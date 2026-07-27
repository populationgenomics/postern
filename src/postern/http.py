"""The HTTP escape hatch: a programmable HTTP endpoint over the sandbox UDS.

Where `GrpcHatch` grants the guest typed methods, `HttpHatch` gives it an
ordinary HTTP proxy endpoint — but what happens to each request is entirely
**client-defined**. The hatch is the transport (it pierces the empty netns,
speaks the proxy protocol, and streams bodies without buffering); *policy* lives
in a handler you supply. A forwarding proxy with an allowlist is just one thing
you can build with it — the handler may equally rewrite requests, transform a
streaming response event-by-event, route to a different backend, or answer with
a synthetic response and never egress at all.

    handler(request, forward) -> Response | Tunnel

* ``request`` — the parsed proxy request (method, url, host/port, headers, and a
  buffered ``body``; ``is_connect`` for HTTPS tunnels).
* ``forward`` — the egress capability: ``forward(request)`` dials upstream and
  returns a **streaming** `Response` (for HTTP) or a `Tunnel` (for CONNECT).
  Withhold it and nothing leaves the host.
* return a `Response` to send it to the guest (synthetic or forwarded, possibly
  with its ``body`` wrapped/transformed), or a `Tunnel` to splice a CONNECT.

Batteries for the common case ship on top of the core: `allow_hosts` /
`deny_hosts` reproduce a destination allowlist in one line. Stdlib-only — no
extra to install.

    from postern import Sandbox, SandboxProfile
    from postern.http import HttpHatch, allow_hosts

    hatch = HttpHatch(allow_hosts({'api.github.com:443', 'pypi.org'}))
    Sandbox(SandboxProfile.with_venv('/opt/env'), hatch=hatch).run_python(guest_code)

**Streaming / SSE.** ``forward`` returns a lazy `Response.body`, so Server-Sent
Events (and any chunked/close-delimited stream) flow through in real time and a
handler can intervene per message with `sse_events` / `encode_sse`:

    def handler(req, forward):
        resp = forward(req)
        if resp.content_type.startswith('text/event-stream'):
            resp = resp.with_body(encode_sse(edit(e) for e in sse_events(resp.body)))
        return resp

**HTTPS.** A CONNECT tunnel is opaque TLS — the proxy sees only ``host:port``,
so per-message intervention is impossible without terminating TLS (a separate,
opt-in concern). Nothing downgrades https→http on its own. To get plaintext for
a cooperative client, point it at an ``http://`` base URL (e.g.
``ANTHROPIC_BASE_URL``) and have your handler originate TLS upstream; or refuse
CONNECT with a `Response` that says so — see `steer_https_to_http`.

Trust model: every byte from the guest is attacker-controlled, so this is the
most security-sensitive host-side surface. With a bare handler *you* own the
policy; most callers should wrap `allow_hosts`/`deny_hosts`.
"""

from __future__ import annotations

import contextlib
import dataclasses
import os
import socket
import tempfile
import threading
import urllib.parse
from collections.abc import Callable, Generator, Iterable, Iterator
from concurrent import futures

_CRLF = b'\r\n'
_HEADER_END = b'\r\n\r\n'
# A request line + headers larger than this is abuse, not a real client.
_MAX_HEADER_BYTES = 64 * 1024
# A chunked size line (hex size + any chunk-extension) or trailer line this large
# is abuse: cap it so a giant extension can't be buffered to dodge max_body_bytes.
_MAX_CHUNK_LINE = 8 * 1024
# Request bodies are buffered (so a handler can inspect/rewrite them and forward
# recomputes Content-Length); responses stream. Cap the buffered request body.
_DEFAULT_MAX_BODY = 16 * 1024 * 1024
# Hop-by-hop headers (RFC 7230 §6.1) a proxy must not forward.
_HOP_BY_HOP = frozenset(
    {b'connection', b'proxy-connection', b'keep-alive', b'proxy-authorization', b'te', b'trailer', b'upgrade'}
)
# Framing headers we re-derive rather than copy (bodies are re-emitted
# close-delimited, so a stale length/encoding would corrupt the stream).
_FRAMING = frozenset({b'content-length', b'transfer-encoding'})


class _BadRequestError(Exception):
    """A malformed guest request; answered with 400 rather than forwarded."""


# --------------------------------------------------------------------------- #
# Request / Response / Tunnel — the handler's data model                       #
# --------------------------------------------------------------------------- #
@dataclasses.dataclass
class Request:
    """One parsed proxy request handed to the handler."""

    method: str
    target: str  # absolute URL (absolute-form) or "host:port" (CONNECT)
    headers: list[tuple[str, str]]
    host: str
    port: int
    is_connect: bool
    origin_target: str = '/'  # path?query sent upstream in origin-form (HTTP only)
    body: bytes = b''  # buffered request body; a handler may replace it before forwarding

    @property
    def host_port(self) -> str:
        return f'{self.host}:{self.port}'

    def header(self, name: str) -> str | None:
        return _get(self.headers, name)


@dataclasses.dataclass
class Response:
    """A response to send to the guest — synthetic, or returned by ``forward``.

    ``body`` is an iterable of byte chunks, consumed lazily and streamed to the
    guest, so a forwarded SSE/chunked response is never buffered.
    """

    status: int
    reason: str
    headers: list[tuple[str, str]]
    body: Iterable[bytes]

    @property
    def content_type(self) -> str:
        return (_get(self.headers, 'content-type') or '').split(';', 1)[0].strip()

    def with_body(self, body: Iterable[bytes]) -> Response:
        """This response with its body replaced (e.g. a transformed SSE stream)."""
        return dataclasses.replace(self, body=body)

    @classmethod
    def text(cls, status: int, reason: str, text: str) -> Response:
        return cls(status, reason, [('Content-Type', 'text/plain; charset=utf-8')], [text.encode()])

    @classmethod
    def forbidden(cls, message: str) -> Response:
        return cls.text(403, 'Forbidden', message + '\n')

    @classmethod
    def bad_gateway(cls, message: str = 'upstream connection failed') -> Response:
        return cls.text(502, 'Bad Gateway', message + '\n')


@dataclasses.dataclass
class Tunnel:
    """Handler verdict for a CONNECT: splice this upstream socket to the guest."""

    upstream: socket.socket


Forward = Callable[[Request], 'Response | Tunnel']
Handler = Callable[[Request, Forward], 'Response | Tunnel']


# --------------------------------------------------------------------------- #
# Batteries — common handlers built on the core                                #
# --------------------------------------------------------------------------- #
def allow_hosts(allowed: Iterable[str]) -> Handler:
    """Forward only to ``allowed`` destinations (``host`` or ``host:port``)."""
    allowed = frozenset(allowed)

    def handler(req: Request, forward: Forward) -> Response | Tunnel:
        if req.host_port in allowed or req.host in allowed:
            return forward(req)
        return Response.forbidden(f'{req.host_port} is not on the allowlist')

    return handler


def deny_hosts(denied: Iterable[str]) -> Handler:
    """Forward everywhere except ``denied`` destinations (``host`` or ``host:port``)."""
    denied = frozenset(denied)

    def handler(req: Request, forward: Forward) -> Response | Tunnel:
        if req.host_port in denied or req.host in denied:
            return Response.forbidden(f'{req.host_port} is on the denylist')
        return forward(req)

    return handler


def steer_https_to_http(inner: Handler, *, hint: str = '') -> Handler:
    """Wrap ``inner`` to refuse CONNECT with an actionable message.

    Since nothing downgrades https→http on its own, a client hitting an
    intercept-only hatch over HTTPS just fails opaquely. This turns that into a
    clear 405 telling the guest to use an ``http://`` base URL instead, while
    passing plain-HTTP requests through to ``inner``.
    """
    tail = f' {hint}' if hint else ''

    def handler(req: Request, forward: Forward) -> Response | Tunnel:
        if req.is_connect:
            return Response.text(
                405, 'Method Not Allowed', f'HTTPS/CONNECT is not intercepted here; use an http:// base URL.{tail}'
            )
        return inner(req, forward)

    return handler


# --------------------------------------------------------------------------- #
# SSE helpers — per-message intervention on a text/event-stream body           #
# --------------------------------------------------------------------------- #
@dataclasses.dataclass
class SseEvent:
    """One Server-Sent Event (`data` may be multi-line; blank-terminated)."""

    data: str = ''
    event: str | None = None
    id: str | None = None
    retry: int | None = None


def sse_events(body: Iterable[bytes]) -> Iterator[SseEvent]:
    """Parse a streaming ``text/event-stream`` body into events, lazily."""
    buf = ''
    for chunk in body:
        buf += chunk.decode('utf-8', 'replace').replace('\r\n', '\n').replace('\r', '\n')
        while '\n\n' in buf:
            block, buf = buf.split('\n\n', 1)
            event = _parse_sse_block(block)
            if event is not None:
                yield event


def encode_sse(events: Iterable[SseEvent]) -> Iterator[bytes]:
    """Serialise events back into ``text/event-stream`` wire bytes."""
    for ev in events:
        lines = []
        if ev.event is not None:
            lines.append(f'event: {ev.event}')
        if ev.id is not None:
            lines.append(f'id: {ev.id}')
        if ev.retry is not None:
            lines.append(f'retry: {ev.retry}')
        lines.extend(f'data: {line}' for line in ev.data.split('\n'))
        yield ('\n'.join(lines) + '\n\n').encode('utf-8')


def _parse_sse_block(block: str) -> SseEvent | None:
    data: list[str] = []
    event = ident = None
    retry = None
    for line in block.split('\n'):
        if not line or line.startswith(':'):  # blank or comment
            continue
        field, _, value = line.partition(':')
        if value.startswith(' '):
            value = value[1:]
        if field == 'data':
            data.append(value)
        elif field == 'event':
            event = value
        elif field == 'id':
            ident = value
        elif field == 'retry' and value.isdigit():
            retry = int(value)
    if not data and event is None and ident is None and retry is None:
        return None
    return SseEvent('\n'.join(data), event, ident, retry)


# --------------------------------------------------------------------------- #
# The hatch                                                                     #
# --------------------------------------------------------------------------- #
class HttpHatch:
    """Serve a client-defined HTTP endpoint over the sandbox UDS.

    Conforms to postern's ``Hatch`` protocol (``socket_path`` + ``accepting()``),
    so it drops into ``Sandbox(hatch=...)`` where ``GrpcHatch`` would; the guest
    reaches it via the shim's loopback relay + ``HTTP_PROXY``. Reused across many
    ``run_python`` calls: serves once on first :meth:`accepting`, until
    :meth:`close`.
    """

    # Reached via the shim's loopback→UDS relay + HTTP_PROXY, not a direct dial
    # (see the Hatch protocol and Sandbox.run_python).
    guest_proxy = True

    def __init__(
        self,
        handler: Handler,
        *,
        socket_path: str | os.PathLike[str] | None = None,
        max_workers: int = 16,
        connect_timeout: float = 10.0,
        max_body_bytes: int = _DEFAULT_MAX_BODY,
    ) -> None:
        """Create a hatch that runs ``handler`` for each guest request.

        Args:
            handler: ``handler(request, forward) -> Response | Tunnel``. It owns
                all policy — wrap `allow_hosts`/`deny_hosts` for the common case.
            socket_path: Where to bind the UDS. Defaults to a fresh ``0700`` temp
                dir (host-side isolation rests on that dir, per F9).
            max_workers: Concurrent guest connections; a CONNECT tunnel or an
                open SSE stream holds one for its lifetime, so size accordingly.
            connect_timeout: Seconds to wait dialling an upstream destination.
            max_body_bytes: Cap on a buffered request body.
        """
        self._handler = handler
        self._timeout = connect_timeout
        self._max_body = max_body_bytes
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
        # non-root uid so must connect; host-side isolation rests on the 0700 dir.
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
        # A single hostile connection must never take a pool worker down.
        try:
            # Bound the pre-response phase (header + request-body read) so a
            # stalled/slowloris guest cannot pin a pool worker forever; cleared
            # before the (possibly long-lived) forward/stream/tunnel phase.
            conn.settimeout(self._timeout)
            head, leftover = _read_headers(conn)
            if head is None:
                conn.close()
                return
            request = self._parse_request(head, leftover, conn)
            # Clear the deadline for the forward/stream/tunnel phase: a legitimate
            # long download, idle-gapped SSE stream, or CONNECT tunnel must not be
            # killed on a timer. The cost is that a guest which stops *reading* can
            # block conn.sendall (backpressure) and hold this worker + its upstream
            # fd; that is bounded by max_workers and, in the sandbox, by the outer
            # Sandbox.run_python(timeout=...) that kills the guest (and its relay,
            # EOF-ing this conn) — the deliberate backstop rather than a write timer.
            conn.settimeout(None)
            result = self._handler(request, self._make_forward())
            if isinstance(result, Tunnel):
                conn.sendall(b'HTTP/1.1 200 Connection established' + _HEADER_END)
                _splice(conn, result.upstream)  # opaque from here — TLS payload never inspected
            else:
                _write_response(conn, result)
        except _BadRequestError as exc:
            with contextlib.suppress(OSError):
                _write_response(conn, Response.text(400, 'Bad Request', f'{exc}\n'))
        except Exception:  # noqa: BLE001 — hostile input; contain it to this connection
            with contextlib.suppress(OSError):
                conn.close()

    def _parse_request(self, head: bytes, leftover: bytes, conn: socket.socket) -> Request:
        # Any bare CR or LF in the header block (valid HTTP separates only with
        # CRLF) is a request-smuggling / header-injection attempt: a bare-LF
        # inside a header value would survive _parse_headers (which splits on
        # CRLF) and be re-serialized to upstream as a *separate* header line,
        # slipping a Transfer-Encoding/Host/auth past the name-based framing
        # strip. Reject the whole request rather than forward ambiguous framing.
        if b'\n' in head.replace(_CRLF, b'') or b'\r' in head.replace(_CRLF, b''):
            raise _BadRequestError('malformed request: bare CR or LF in headers')
        request_line, _, header_block = head.partition(_CRLF)
        method, _, rest = request_line.decode('latin-1').partition(' ')
        target = rest.rsplit(' ', 1)[0].strip()  # drop the trailing "HTTP/1.1"
        headers = _parse_headers(header_block)
        if method.upper() == 'CONNECT':
            host, port = _split_authority(target, default_port=443)
            return Request(method, target, headers, host, port, is_connect=True)
        parts = urllib.parse.urlsplit(target)
        host = parts.hostname or ''
        port = parts.port or (443 if parts.scheme == 'https' else 80)
        origin = urllib.parse.urlunsplit(('', '', parts.path or '/', parts.query, '')) or '/'
        reader = _SockReader(leftover, conn)
        body = b''.join(_decode_body(reader, headers, allow_eof=False, max_bytes=self._max_body))
        return Request(method, target, headers, host, port, is_connect=False, origin_target=origin, body=body)

    def _make_forward(self) -> Forward:
        def forward(req: Request) -> Response | Tunnel:
            try:
                upstream = socket.create_connection((req.host, req.port), timeout=self._timeout)
            except OSError:
                return Response.bad_gateway()
            upstream.settimeout(None)
            if req.is_connect:
                return Tunnel(upstream)
            # From here upstream must be closed on any failure, or its fd leaks
            # (an allowlisted host that RSTs mid-exchange would otherwise walk
            # the host proxy to EMFILE); the success path hands it to _closing.
            try:
                headers = _forward_request_headers(req.headers, len(req.body))
                upstream.sendall(
                    f'{req.method} {req.origin_target} HTTP/1.1'.encode('latin-1')
                    + _CRLF
                    + _encode_headers(headers)
                    + _HEADER_END
                    + req.body
                )
                head, leftover = _read_headers(upstream)
            except OSError:
                upstream.close()
                return Response.bad_gateway()
            if head is None:
                upstream.close()
                return Response.bad_gateway('no response from upstream')
            status, reason, resp_headers = _parse_status_line(head)
            if status in (204, 304) or 100 <= status < 200:
                upstream.close()
                return Response(status, reason, resp_headers, [])
            reader = _SockReader(leftover, upstream)
            body = _closing(_decode_body(reader, resp_headers, allow_eof=True), upstream)
            return Response(status, reason, resp_headers, body)

        return forward

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


# --------------------------------------------------------------------------- #
# Wire helpers                                                                  #
# --------------------------------------------------------------------------- #
class _SockReader:
    """A small buffered reader over ``initial`` bytes then a stream socket."""

    def __init__(self, initial: bytes, sock: socket.socket) -> None:
        self._buf = bytearray(initial)
        self._sock = sock
        self._eof = False

    def _fill(self) -> bool:
        if self._eof:
            return False
        chunk = self._sock.recv(65536)
        if not chunk:
            self._eof = True
            return False
        self._buf += chunk
        return True

    def read(self, n: int) -> bytes:
        while len(self._buf) < n and self._fill():
            pass
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    def readline(self, limit: int = 0) -> bytes:
        # ``limit`` caps how much is buffered while hunting for the newline, so a
        # line that never terminates (or a giant chunk-extension) can't be
        # accumulated unboundedly — the caller's byte budget only counts what a
        # line *contains*, not what it might grow to mid-read.
        while b'\n' not in self._buf and self._fill():
            if limit and len(self._buf) > limit:
                raise ValueError('line exceeds limit')
        idx = self._buf.find(b'\n')
        if idx < 0:
            out = bytes(self._buf)
            self._buf.clear()
            return out
        out = bytes(self._buf[: idx + 1])
        del self._buf[: idx + 1]
        return out


def _read_headers(sock: socket.socket) -> tuple[bytes | None, bytes]:
    """Read to end-of-headers; return (header_bytes, bytes_read_past_them)."""
    buf = b''
    while _HEADER_END not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            return (buf or None), b''
        buf += chunk
        if len(buf) > _MAX_HEADER_BYTES:
            return None, b''
    head, _, leftover = buf.partition(_HEADER_END)
    return head, leftover


def _decode_body(
    reader: _SockReader, headers: list[tuple[str, str]], *, allow_eof: bool, max_bytes: int = 0
) -> Iterator[bytes]:
    """Yield the decoded message body per its framing headers.

    Handles Transfer-Encoding: chunked and Content-Length; falls back to
    close-delimited only when ``allow_eof`` (responses, never requests — a
    bodyless request has no length and must not block waiting for EOF).
    """
    if 'chunked' in (_get(headers, 'transfer-encoding') or '').lower():
        return _iter_chunked(reader, max_bytes)
    content_length = _get(headers, 'content-length')
    if content_length is not None:
        return _iter_fixed(reader, int(content_length), max_bytes)
    if allow_eof:
        return _iter_until_eof(reader)
    return iter(())


def _iter_chunked(reader: _SockReader, max_bytes: int) -> Iterator[bytes]:
    # ``total`` counts *everything consumed* — size lines, chunk data, and
    # trailers — against max_bytes, not just the declared data. Otherwise a
    # flood of blank/size/trailer lines (each tiny, never data) slips the cap;
    # and the declared size is checked before the read so one huge chunk can't
    # be buffered first (unlike Content-Length, bounded in _iter_fixed).
    # max_bytes==0 means unbounded (the streaming response path).
    total = 0

    def budget(delta: int) -> None:
        nonlocal total
        total += delta
        if max_bytes and total > max_bytes:
            raise ValueError('body exceeds max_body_bytes')

    while True:
        raw = reader.readline(_MAX_CHUNK_LINE)
        if not raw:  # EOF before a size line: truncated. Stop — do NOT spin on b''.
            raise ValueError('truncated chunked body')
        budget(len(raw))
        size_line = raw.strip()
        if not size_line:  # tolerate a stray blank line between chunks
            continue
        size = int(size_line.split(b';', 1)[0], 16)
        if size == 0:
            while True:  # consume any trailers (b'' at EOF ends it)
                trailer = reader.readline(_MAX_CHUNK_LINE)
                budget(len(trailer))
                if not trailer.strip():
                    return
        budget(size)
        yield reader.read(size)
        reader.read(2)  # trailing CRLF


def _iter_fixed(reader: _SockReader, remaining: int, max_bytes: int) -> Iterator[bytes]:
    if max_bytes and remaining > max_bytes:
        raise ValueError('body exceeds max_body_bytes')
    while remaining > 0:
        data = reader.read(min(65536, remaining))
        if not data:
            return
        remaining -= len(data)
        yield data


def _iter_until_eof(reader: _SockReader) -> Iterator[bytes]:
    while True:
        data = reader.read(65536)
        if not data:
            return
        yield data


def _closing(body: Iterator[bytes], sock: socket.socket) -> Iterator[bytes]:
    """Yield from ``body``, closing ``sock`` once the stream is exhausted."""
    try:
        yield from body
    finally:
        with contextlib.suppress(OSError):
            sock.close()


def _write_response(conn: socket.socket, resp: Response) -> None:
    """Write a response to the guest, close-delimited, streaming the body."""
    headers = [(k, v) for k, v in resp.headers if k.lower().encode() not in _HOP_BY_HOP | _FRAMING]
    headers.append(('Connection', 'close'))  # body is re-emitted close-delimited
    conn.sendall(
        f'HTTP/1.1 {resp.status} {resp.reason}'.encode('latin-1') + _CRLF + _encode_headers(headers) + _HEADER_END
    )
    for chunk in resp.body:
        conn.sendall(chunk)
    conn.close()


def _forward_request_headers(headers: list[tuple[str, str]], body_len: int) -> list[tuple[str, str]]:
    kept = [(k, v) for k, v in headers if k.lower().encode() not in _HOP_BY_HOP | _FRAMING]
    if body_len:
        kept.append(('Content-Length', str(body_len)))
    kept.append(('Connection', 'close'))  # so upstream EOFs the (close-delimited) response
    return kept


def _parse_status_line(head: bytes) -> tuple[int, str, list[tuple[str, str]]]:
    status_line, _, block = head.partition(_CRLF)
    parts = status_line.decode('latin-1').split(' ', 2)
    status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 502
    reason = parts[2] if len(parts) > 2 else ''
    return status, reason, _parse_headers(block)


def _parse_headers(block: bytes) -> list[tuple[str, str]]:
    headers = []
    for line in block.split(_CRLF):
        if not line:
            continue
        name, _, value = line.partition(b':')
        headers.append((name.decode('latin-1').strip(), value.decode('latin-1').strip()))
    return headers


def _encode_headers(headers: list[tuple[str, str]]) -> bytes:
    return _CRLF.join(f'{k}: {v}'.encode('latin-1') for k, v in headers)


def _get(headers: list[tuple[str, str]], name: str) -> str | None:
    name = name.lower()
    for key, value in headers:
        if key.lower() == name:
            return value
    return None


def _split_authority(authority: str, *, default_port: int) -> tuple[str, int]:
    host, sep, port = authority.rpartition(':')
    if sep and host and port.isdigit():
        return host, int(port)
    return authority, default_port


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
