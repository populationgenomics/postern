"""The handler is the policy — test the core dispatch plus the shipped batteries.

Exercises the host-side hatch over its UDS, speaking the HTTP proxy protocol a
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
from postern.http import HttpHatch, Response, allow_hosts, deny_hosts, encode_sse, sse_events, steer_https_to_http


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
    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        if self.path == '/sse':
            self._stream_sse()
            return
        body = json.dumps({'path': self.path, 'host': self.headers.get('Host')}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        received = self.rfile.read(length)
        body = json.dumps({'path': self.path, 'received': received.decode()}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)

    def _stream_sse(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Connection', 'close')
        self.end_headers()
        for i in range(3):
            self.wfile.write(f'data: tick-{i}\n\n'.encode())
            self.wfile.flush()

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
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(hatch.socket_path)
    return sock


def _recv_all(sock):
    raw = b''
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        raw += chunk
    sock.close()
    return raw


def _http_get(hatch, url, host):
    sock = _proxy_conn(hatch)
    sock.sendall(f'GET {url} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n'.encode())
    raw = _recv_all(sock)
    return int(raw.split(b' ', 2)[1]), raw.split(b'\r\n\r\n', 1)[1]


# -- batteries: allow / deny ------------------------------------------------- #
def test_allowlisted_destination_is_forwarded(origin):
    hatch = HttpHatch(allow_hosts({origin}))
    with hatch.accepting():
        status, body = _http_get(hatch, f'http://{origin}/data', origin)
    hatch.close()
    assert status == 200
    assert json.loads(body)['path'] == '/data'


def test_unlisted_destination_is_forbidden(origin):
    other = origin.rsplit(':', 1)[0] + ':1'  # different port = different destination
    hatch = HttpHatch(allow_hosts({other}))
    with hatch.accepting():
        status, body = _http_get(hatch, f'http://{origin}/data', origin)
    hatch.close()
    assert status == 403
    assert b'not on the allowlist' in body


def test_bare_host_entry_allows_any_port(origin):
    hatch = HttpHatch(allow_hosts({origin.rsplit(':', 1)[0]}))
    with hatch.accepting():
        status, _ = _http_get(hatch, f'http://{origin}/data', origin)
    hatch.close()
    assert status == 200


def test_deny_hosts_blocks_listed_forwards_rest(origin):
    hatch = HttpHatch(deny_hosts({'169.254.169.254'}))
    with hatch.accepting():
        assert _http_get(hatch, f'http://{origin}/ok', origin)[0] == 200
        blocked, body = _http_get(hatch, 'http://169.254.169.254/latest/', '169.254.169.254')
    hatch.close()
    assert blocked == 403
    assert b'denylist' in body


# -- core: client-defined handler, no forwarding ----------------------------- #
def test_synthetic_response_without_forwarding():
    # A handler need not egress at all — it can answer directly.
    def handler(req, _forward):
        return Response.text(200, 'OK', f'hello {req.host}')

    hatch = HttpHatch(handler)
    with hatch.accepting():
        status, body = _http_get(hatch, 'http://example.com/x', 'example.com')
    hatch.close()
    assert status == 200
    assert body == b'hello example.com'


def test_handler_can_rewrite_request_body(origin):
    def handler(req, forward):
        if req.body:
            req.body = req.body.replace(b'redactme', b'REDACTED')
        return forward(req)

    hatch = HttpHatch(handler)
    with hatch.accepting():
        sock = _proxy_conn(hatch)
        body = b'{"secret": "redactme"}'
        sock.sendall(
            f'POST http://{origin}/submit HTTP/1.1\r\nHost: {origin}\r\n'.encode()
            + f'Content-Length: {len(body)}\r\nConnection: close\r\n\r\n'.encode()
            + body
        )
        raw = _recv_all(sock)
    hatch.close()
    echoed = json.loads(raw.split(b'\r\n\r\n', 1)[1])['received']
    assert 'REDACTED' in echoed
    assert 'redactme' not in echoed


# -- streaming / SSE per-message intervention -------------------------------- #
def test_sse_stream_is_intervened_per_event(origin):
    def handler(req, forward):
        resp = forward(req)
        if resp.content_type == 'text/event-stream':

            def edit(events):
                for ev in events:
                    ev.data = ev.data.upper()
                    yield ev

            return resp.with_body(encode_sse(edit(sse_events(resp.body))))
        return resp

    hatch = HttpHatch(handler)
    with hatch.accepting():
        status, body = _http_get(hatch, f'http://{origin}/sse', origin)
    hatch.close()
    assert status == 200
    assert b'data: TICK-0' in body
    assert b'data: TICK-2' in body
    assert b'tick-' not in body  # every event was transformed


def test_sse_events_roundtrip_parses_multiple():
    raw = b'data: one\n\ndata: two\nevent: tick\n\n'
    events = list(sse_events([raw]))
    assert [e.data for e in events] == ['one', 'two']
    assert events[1].event == 'tick'
    assert b'data: one\n\n' in b''.join(encode_sse(events))


# -- CONNECT (HTTPS tunnel) --------------------------------------------------- #
def test_connect_tunnel_when_handler_forwards(origin):
    hatch = HttpHatch(allow_hosts({origin}))
    with hatch.accepting():
        sock = _proxy_conn(hatch)
        sock.sendall(f'CONNECT {origin} HTTP/1.1\r\nHost: {origin}\r\n\r\n'.encode())
        established = sock.recv(4096)
        assert established.split(b'\r\n', 1)[0] == b'HTTP/1.1 200 Connection established'
        sock.sendall(f'GET /tunnelled HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n'.encode())
        raw = _recv_all(sock)
    hatch.close()
    assert json.loads(raw.split(b'\r\n\r\n', 1)[1])['path'] == '/tunnelled'


def test_connect_refused_when_handler_denies():
    hatch = HttpHatch(allow_hosts({'example.com:443'}))
    with hatch.accepting():
        sock = _proxy_conn(hatch)
        sock.sendall(b'CONNECT 169.254.169.254:443 HTTP/1.1\r\nHost: x\r\n\r\n')
        status_line = sock.recv(4096).split(b'\r\n', 1)[0]
        sock.close()
    hatch.close()
    assert status_line == b'HTTP/1.1 403 Forbidden'


def test_steer_https_to_http_refuses_connect_with_guidance(origin):
    hatch = HttpHatch(steer_https_to_http(allow_hosts({origin}), hint='set ANTHROPIC_BASE_URL'))
    with hatch.accepting():
        # plain HTTP still forwards
        assert _http_get(hatch, f'http://{origin}/ok', origin)[0] == 200
        # CONNECT is refused with an actionable 405
        sock = _proxy_conn(hatch)
        sock.sendall(f'CONNECT {origin} HTTP/1.1\r\nHost: {origin}\r\n\r\n'.encode())
        raw = _recv_all(sock)
    hatch.close()
    assert raw.split(b' ', 2)[1] == b'405'
    assert b'ANTHROPIC_BASE_URL' in raw


# -- guest-side relay end-to-end (real shim code) ---------------------------- #
def _tcp_get(proxy_addr, url, host):
    sock = socket.create_connection(proxy_addr, timeout=10)
    sock.sendall(f'GET {url} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n'.encode())
    raw = _recv_all(sock)
    return int(raw.split(b' ', 2)[1]), raw.split(b'\r\n\r\n', 1)[1]


def test_guest_relay_bridges_loopback_to_hatch(origin):
    guest = _load_guest_shim()
    hatch = HttpHatch(allow_hosts({origin}))
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
    guest = _load_guest_shim()
    hatch = HttpHatch(allow_hosts({origin}))
    with hatch.accepting():
        srv = guest._bind_proxy_relay()
        proxy_addr = srv.getsockname()
        guest._serve_proxy_relay(srv, hatch.socket_path)
        status, body = _tcp_get(proxy_addr, 'http://169.254.169.254/latest/', '169.254.169.254')
        srv.close()
    hatch.close()
    assert status == 403
    assert b'not on the allowlist' in body


# -- lifecycle --------------------------------------------------------------- #
def test_socket_perms_are_deterministic_and_guest_connectable():
    hatch = HttpHatch(allow_hosts(set()))
    with hatch.accepting():
        mode = stat.S_IMODE(os.stat(hatch.socket_path).st_mode)
        assert mode == 0o666  # non-root guest must connect; not umask-dependent
        parent = stat.S_IMODE(os.stat(os.path.dirname(hatch.socket_path)).st_mode)
        assert parent == 0o700  # mkdtemp default keeps other host users out
    hatch.close()


def test_hatch_reused_across_calls(origin):
    hatch = HttpHatch(allow_hosts({origin}))
    with hatch.accepting():
        assert _http_get(hatch, f'http://{origin}/one', origin)[0] == 200
    with hatch.accepting():
        assert _http_get(hatch, f'http://{origin}/two', origin)[0] == 200
    hatch.close()
