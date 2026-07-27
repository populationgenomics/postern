"""The destination-allowlist is the capability gate — test allow vs deny directly.

Exercises the host-side proxy over its UDS, speaking the HTTP proxy protocol a
guest's HTTP_PROXY would (absolute-form and CONNECT). A local origin server
stands in for "the internet"; no bubblewrap needed — this tests the hatch
server, not the sandbox.
"""

import http.server
import importlib.util
import json
import os
import pathlib
import socket
import stat
import threading

import pytest

import postern
from postern.http import HttpHatch


def _load_guest_shim():
    """Load the bound-in shim as a module (it is a standalone script, not part
    of the importable package) so its real relay code can be exercised here."""
    path = pathlib.Path(postern.__file__).with_name('_guest.py')
    spec = importlib.util.spec_from_file_location('postern_guest_shim', path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _Origin(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({'path': self.path, 'host': self.headers.get('Host')}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args, **_kwargs):
        pass


@pytest.fixture
def origin():
    server = http.server.HTTPServer(('127.0.0.1', 0), _Origin)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[0], server.server_address[1]
    try:
        yield f'{host}:{port}'
    finally:
        server.shutdown()


def _proxy_conn(hatch):
    """A raw stream socket to the hatch UDS — the guest's loopback relay carries
    exactly this byte stream through to the host proxy."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(hatch.socket_path)
    return sock


def _http_get(hatch, url, host):
    sock = _proxy_conn(hatch)
    sock.sendall(f'GET {url} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n'.encode())
    raw = b''
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        raw += chunk
    sock.close()
    status = int(raw.split(b' ', 2)[1])
    body = raw.split(b'\r\n\r\n', 1)[1]
    return status, body


def test_allowlisted_destination_is_forwarded(origin):
    hatch = HttpHatch(allowlist={origin})
    with hatch.accepting():
        status, body = _http_get(hatch, f'http://{origin}/data', origin)
    hatch.close()
    assert status == 200
    assert json.loads(body)['path'] == '/data'


def test_unlisted_destination_is_forbidden(origin):
    # A different port on the allowed host is a different destination: denied.
    other = origin.rsplit(':', 1)[0] + ':1'
    hatch = HttpHatch(allowlist={other})
    with hatch.accepting():
        status, body = _http_get(hatch, f'http://{origin}/data', origin)
    hatch.close()
    assert status == 403
    assert b'not on the hatch allowlist' in body


def test_bare_host_entry_allows_any_port(origin):
    host = origin.rsplit(':', 1)[0]
    hatch = HttpHatch(allowlist={host})
    with hatch.accepting():
        status, _ = _http_get(hatch, f'http://{origin}/data', origin)
    hatch.close()
    assert status == 200


def test_connect_tunnel_to_allowed_destination(origin):
    # CONNECT opens an opaque tunnel; speak plain HTTP inside it to prove the
    # HTTPS plumbing without needing a TLS origin.
    hatch = HttpHatch(allowlist={origin})
    with hatch.accepting():
        sock = _proxy_conn(hatch)
        sock.sendall(f'CONNECT {origin} HTTP/1.1\r\nHost: {origin}\r\n\r\n'.encode())
        established = sock.recv(4096)
        assert established.split(b'\r\n', 1)[0] == b'HTTP/1.1 200 Connection established'
        sock.sendall(f'GET /tunnelled HTTP/1.0\r\nHost: {origin}\r\n\r\n'.encode())
        raw = b''
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw += chunk
        sock.close()
    hatch.close()
    assert json.loads(raw.split(b'\r\n\r\n', 1)[1])['path'] == '/tunnelled'


def test_connect_to_unlisted_destination_is_refused_before_tunnel():
    hatch = HttpHatch(allowlist={'example.com:443'})
    with hatch.accepting():
        sock = _proxy_conn(hatch)
        sock.sendall(b'CONNECT 169.254.169.254:443 HTTP/1.1\r\nHost: x\r\n\r\n')
        status_line = sock.recv(4096).split(b'\r\n', 1)[0]
        sock.close()
    hatch.close()
    assert status_line == b'HTTP/1.1 403 Forbidden'


def test_https_in_absolute_form_is_refused(origin):
    # https must arrive as CONNECT; an absolute-form https URL is not proxied.
    hatch = HttpHatch(allowlist={origin})
    with hatch.accepting():
        status, _ = _http_get(hatch, f'https://{origin}/x', origin)
    hatch.close()
    assert status == 403


def test_request_body_is_forwarded(origin):
    # A body read past the header boundary must still reach upstream. Drive a
    # POST with a Content-Length body and confirm the origin sees the path.
    hatch = HttpHatch(allowlist={origin})
    with hatch.accepting():
        sock = _proxy_conn(hatch)
        body = b'{"k": "v"}'
        sock.sendall(
            f'POST http://{origin}/submit HTTP/1.1\r\nHost: {origin}\r\n'.encode()
            + f'Content-Length: {len(body)}\r\nConnection: close\r\n\r\n'.encode()
            + body
        )
        raw = b''
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            raw += chunk
        sock.close()
    hatch.close()
    # The stub origin only implements GET, so a POST yields 501 — but a 501 from
    # the *origin* (not a 403 from the proxy) proves the request was forwarded.
    assert raw.split(b' ', 2)[1] == b'501'


def _tcp_get(proxy_addr, url, host):
    sock = socket.create_connection(proxy_addr, timeout=10)
    sock.sendall(f'GET {url} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n'.encode())
    raw = b''
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        raw += chunk
    sock.close()
    return int(raw.split(b' ', 2)[1]), raw.split(b'\r\n\r\n', 1)[1]


def test_guest_relay_bridges_loopback_to_hatch(origin):
    # The two halves together with the *real* shim code: guest-side loopback
    # relay (postern._guest) -> hatch UDS -> host-side allowlisted proxy.
    guest = _load_guest_shim()
    hatch = HttpHatch(allowlist={origin})
    with hatch.accepting():
        srv = guest._bind_proxy_relay()
        proxy_addr = srv.getsockname()  # what HTTP_PROXY would point at in the guest
        guest._serve_proxy_relay(srv, hatch.socket_path)
        status, body = _tcp_get(proxy_addr, f'http://{origin}/relayed', origin)
        srv.close()
    hatch.close()
    assert status == 200
    assert json.loads(body)['path'] == '/relayed'


def test_guest_relay_denied_destination_still_refused(origin):
    # The relay carries bytes blindly; policy stays host-side — a disallowed
    # destination is refused by the proxy even reached through the relay.
    guest = _load_guest_shim()
    hatch = HttpHatch(allowlist={origin})
    with hatch.accepting():
        srv = guest._bind_proxy_relay()
        proxy_addr = srv.getsockname()
        guest._serve_proxy_relay(srv, hatch.socket_path)
        status, body = _tcp_get(proxy_addr, 'http://169.254.169.254/latest/', '169.254.169.254')
        srv.close()
    hatch.close()
    assert status == 403
    assert b'not on the hatch allowlist' in body


def test_socket_perms_are_deterministic_and_guest_connectable():
    hatch = HttpHatch(allowlist=set())
    with hatch.accepting():
        mode = stat.S_IMODE(os.stat(hatch.socket_path).st_mode)
        assert mode == 0o666  # non-root guest must connect; not umask-dependent
        parent = stat.S_IMODE(os.stat(os.path.dirname(hatch.socket_path)).st_mode)
        assert parent == 0o700  # mkdtemp default keeps other host users out
    hatch.close()


def test_hatch_reused_across_calls(origin):
    hatch = HttpHatch(allowlist={origin})
    with hatch.accepting():
        assert _http_get(hatch, f'http://{origin}/one', origin)[0] == 200
    with hatch.accepting():
        assert _http_get(hatch, f'http://{origin}/two', origin)[0] == 200
    hatch.close()
