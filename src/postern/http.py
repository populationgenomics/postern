"""The HTTP forward-proxy escape hatch: brokered network egress, allowlisted.

Where `GrpcHatch` hands the guest a set of typed methods, `HttpHatch` hands it
*network egress* — but only to destinations you allowlist. The guest sees an
ordinary HTTP proxy: point `HTTP_PROXY`/`HTTPS_PROXY` at it and any stdlib or
third-party client (`urllib`, `requests`, `httpx`, `curl`) works unmodified. The
proxy runs in the trusted host process, parses the guest's (hostile) HTTP,
checks the destination against the allowlist — the capability grant, exactly as
the method set is for gRPC — and only then dials out on the host network.

This closes the loop on postern's empty network namespace *without* reopening
it. The sandbox still has no route off `lo`; the only thing that pierces the
netns is the hatch Unix socket (a filesystem object, not a network object). To
reach it the guest needs a tiny loopback→UDS relay (a dumb byte pump listening
on ``127.0.0.1`` — bwrap's ``loopback_setup()`` already raised ``lo``, so no
capability is needed) with ``HTTP_PROXY`` pointed at it. That relay is the
guest-side counterpart to this host-side proxy; this module is only the trusted
end. Egress is then a single brokered, auditable channel, not a raw interface.

Unlike the gRPC hatch this is **stdlib-only** — no extra to install. Both proxy
modes are supported:

* **absolute-form** (``GET http://host/path``) for plain HTTP — the proxy sees
  and forwards the full request;
* **CONNECT** (``CONNECT host:443``) for HTTPS — the proxy sees only ``host:port``
  and then splices an opaque byte tunnel; it never holds the TLS payload.

    from postern import Sandbox, SandboxProfile
    from postern.http import HttpHatch

    hatch = HttpHatch(allowlist={'api.github.com:443', 'pypi.org'})
    sandbox = Sandbox(SandboxProfile.with_venv('/opt/env'), hatch=hatch)
    sandbox.run_python(guest_code)   # guest's HTTP_PROXY -> loopback -> UDS -> here

Trust model: every byte from the guest is attacker-controlled, so this proxy is
the most security-sensitive surface postern exposes. The allowlist is its whole
job — an entry ``host`` permits any port on that host, ``host:port`` pins the
port. A permitted host is dialled wherever DNS points it, so allowlist names you
control (an SSRF via a hostile-resolving name you allowlisted is your choice to
grant, not the proxy's to second-guess).
"""

from __future__ import annotations

import contextlib
import os
import socket
import tempfile
import threading
import urllib.parse
from collections.abc import Generator, Iterable
from concurrent import futures

_CRLF = b'\r\n'
_HEADER_END = b'\r\n\r\n'
# A request line + headers larger than this is abuse, not a real client: bail
# rather than buffer unboundedly on a hostile connection.
_MAX_HEADER_BYTES = 64 * 1024
# Hop-by-hop headers (RFC 7230 §6.1) a proxy must not forward, plus the proxy
# framing the guest sent us. Everything else is passed through untouched.
_HOP_BY_HOP = frozenset(
    {b'connection', b'proxy-connection', b'keep-alive', b'proxy-authorization', b'te', b'trailer', b'upgrade'}
)


class HttpHatch:
    """Serve a destination-allowlisted HTTP forward proxy over the sandbox UDS.

    Conforms to postern's ``Hatch`` protocol (``socket_path`` + ``accepting()``),
    so it drops into ``Sandbox(hatch=...)`` exactly where ``GrpcHatch`` would.
    Reused across many ``run_python`` calls: the server starts once on first
    :meth:`accepting` and stays up until :meth:`close`.
    """

    # Reached via the shim's loopback→UDS relay + HTTP_PROXY, not a direct dial
    # (see the Hatch protocol and Sandbox.run_python).
    guest_proxy = True

    def __init__(
        self,
        allowlist: Iterable[str],
        *,
        socket_path: str | os.PathLike[str] | None = None,
        max_workers: int = 16,
        connect_timeout: float = 10.0,
    ) -> None:
        """Create a hatch that proxies only to ``allowlist`` destinations.

        Args:
            allowlist: Permitted destinations. ``host`` allows any port on that
                host; ``host:port`` pins the port. This set is the capability
                grant — the security boundary is exactly these entries.
            socket_path: Where to bind the UDS. Defaults to a fresh ``0700``
                temp dir (host-side isolation rests on that dir, per F9).
            max_workers: Concurrent guest connections served at once. A CONNECT
                tunnel occupies one worker for its lifetime, so size this to the
                guest's expected concurrency; excess connections queue.
            connect_timeout: Seconds to wait dialling an upstream destination.
        """
        self._allowed = frozenset(allowlist)
        self._timeout = connect_timeout
        if socket_path is None:
            self._dir: str | None = tempfile.mkdtemp(prefix='postern-http-')
            self._path = os.path.join(self._dir, 'hatch.sock')
        else:
            self._dir = None
            self._path = os.fspath(socket_path)
        self._pool = futures.ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix='postern-http')
        self._srv: socket.socket | None = None
        self._started = False

    @property
    def socket_path(self) -> str:
        return self._path

    def _allowed_dest(self, host: str, port: int) -> bool:
        return f'{host}:{port}' in self._allowed or host in self._allowed

    # -- serving lifecycle (mirrors GrpcHatch) ------------------------------- #
    def start(self) -> None:
        """Start serving (idempotent). Serves until :meth:`close`."""
        if self._started:
            return
        with contextlib.suppress(FileNotFoundError):
            os.unlink(self._path)  # a stale socket from a crashed run would EADDRINUSE
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(self._path)
        srv.listen(128)
        # Deterministic perms, not umask-dependent (F9): the guest runs as a
        # non-root uid so must be able to connect; host-side isolation rests on
        # the 0700 dir above, which keeps other host users off the socket.
        with contextlib.suppress(OSError):
            os.chmod(self._path, 0o666)  # noqa: S103 — intentional; see the comment above
        self._srv = srv
        self._started = True
        threading.Thread(target=self._accept_loop, args=(srv,), daemon=True, name='postern-http-accept').start()

    @contextlib.contextmanager
    def accepting(self) -> Generator[HttpHatch, None, None]:
        """Ensure the hatch is serving for the block; it stays up for reuse."""
        self.start()
        yield self

    def _accept_loop(self, srv: socket.socket) -> None:
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return  # socket closed by close()
            with contextlib.suppress(RuntimeError):  # pool shut down mid-accept
                self._pool.submit(self._serve_conn, conn)

    # -- one guest connection ------------------------------------------------ #
    def _serve_conn(self, conn: socket.socket) -> None:
        # A single hostile connection must never take a pool worker down, so the
        # whole exchange is wrapped: on any error we just drop this connection.
        try:
            head, leftover = self._read_headers(conn)
            if head is None:
                conn.close()
                return
            request_line, _, header_block = head.partition(_CRLF)
            method, _, rest = request_line.decode('latin-1').partition(' ')
            target = rest.rsplit(' ', 1)[0].strip()  # drop the trailing "HTTP/1.1"
            if method.upper() == 'CONNECT':
                self._do_connect(conn, target)
            else:
                self._do_absolute(conn, method, target, header_block, leftover)
        except Exception:  # noqa: BLE001 — hostile input; contain it to this connection
            with contextlib.suppress(OSError):
                conn.close()

    @staticmethod
    def _read_headers(conn: socket.socket) -> tuple[bytes | None, bytes]:
        """Read to end-of-headers; return (header_bytes, bytes_read_past_them)."""
        buf = b''
        while _HEADER_END not in buf:
            chunk = conn.recv(65536)
            if not chunk:
                return (buf or None), b''
            buf += chunk
            if len(buf) > _MAX_HEADER_BYTES:
                return None, b''
        head, _, leftover = buf.partition(_HEADER_END)
        return head, leftover

    def _do_connect(self, conn: socket.socket, target: str) -> None:
        host, port = _split_authority(target, default_port=443)
        if not self._allowed_dest(host, port):
            _refuse(conn, host, port)
            return
        try:
            upstream = socket.create_connection((host, port), timeout=self._timeout)
        except OSError:
            _bad_gateway(conn)
            return
        conn.sendall(b'HTTP/1.1 200 Connection established' + _HEADER_END)
        upstream.settimeout(None)
        _splice(conn, upstream)  # opaque from here — the TLS payload is never inspected

    def _do_absolute(self, conn: socket.socket, method: str, target: str, header_block: bytes, leftover: bytes) -> None:
        parts = urllib.parse.urlsplit(target)
        if parts.scheme != 'http' or not parts.hostname:
            _refuse(conn, parts.hostname or '?', parts.port or 0)  # https must arrive as CONNECT
            return
        host, port = parts.hostname, parts.port or 80
        if not self._allowed_dest(host, port):
            _refuse(conn, host, port)
            return
        path = urllib.parse.urlunsplit(('', '', parts.path or '/', parts.query, ''))
        request_line = f'{method} {path} HTTP/1.1'.encode('latin-1')
        headers = _rewrite_headers(header_block)
        try:
            upstream = socket.create_connection((host, port), timeout=self._timeout)
        except OSError:
            _bad_gateway(conn)
            return
        upstream.settimeout(None)
        upstream.sendall(request_line + _CRLF + headers + _HEADER_END + leftover)
        _splice(conn, upstream)

    def close(self) -> None:
        """Stop serving, drop the socket, and remove the owned temp dir."""
        if self._srv is not None:
            with contextlib.suppress(OSError):
                self._srv.close()
            self._srv = None
        self._started = False
        self._pool.shutdown(wait=False)
        with contextlib.suppress(OSError):
            os.unlink(self._path)
        if self._dir is not None:
            with contextlib.suppress(OSError):
                os.rmdir(self._dir)


def _split_authority(authority: str, *, default_port: int) -> tuple[str, int]:
    """Split ``host:port`` (or bare ``host``) into ``(host, port)``."""
    host, sep, port = authority.rpartition(':')
    if sep and host and port.isdigit():
        return host, int(port)
    return authority, default_port


def _rewrite_headers(header_block: bytes) -> bytes:
    """Drop hop-by-hop headers and force ``Connection: close``.

    Forcing close means the upstream signals end-of-response with EOF, which the
    byte splice propagates back to the guest — no keep-alive bookkeeping, at the
    cost of one connection per request (fine for brokered agent egress).
    """
    kept = [
        line for line in header_block.split(_CRLF) if line and line.split(b':', 1)[0].strip().lower() not in _HOP_BY_HOP
    ]
    kept.append(b'Connection: close')
    return _CRLF.join(kept)


def _refuse(conn: socket.socket, host: str, port: int) -> None:
    body = f'{host}:{port} is not on the hatch allowlist\n'.encode()
    conn.sendall(
        b'HTTP/1.1 403 Forbidden'
        + _CRLF
        + b'Content-Type: text/plain'
        + _CRLF
        + b'Content-Length: '
        + str(len(body)).encode()
        + _CRLF
        + b'Connection: close'
        + _HEADER_END
        + body
    )
    conn.close()


def _bad_gateway(conn: socket.socket) -> None:
    conn.sendall(b'HTTP/1.1 502 Bad Gateway' + _CRLF + b'Connection: close' + _HEADER_END)
    conn.close()


def _pump(src: socket.socket, dst: socket.socket) -> None:
    """Copy ``src`` -> ``dst`` until EOF, then half-close ``dst``'s write side."""
    try:
        while True:
            chunk = src.recv(65536)
            if not chunk:
                break
            dst.sendall(chunk)
    except OSError:
        pass
    finally:
        with contextlib.suppress(OSError):
            dst.shutdown(socket.SHUT_WR)


def _splice(a: socket.socket, b: socket.socket) -> None:
    """Relay bytes both ways between two connected sockets until both close."""
    reverse = threading.Thread(target=_pump, args=(a, b), daemon=True)
    reverse.start()
    _pump(b, a)
    reverse.join()
    for sock in (a, b):
        with contextlib.suppress(OSError):
            sock.close()
