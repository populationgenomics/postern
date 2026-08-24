"""The handler is the policy — test the core dispatch plus the shipped batteries.

Exercises the host-side hatch over its UDS, speaking the HTTP proxy protocol a
guest's HTTP_PROXY would (absolute-form and CONNECT). A local origin server
stands in for "the internet"; no bubblewrap needed — this tests the hatch
server, not the sandbox.
"""

import http.server
import importlib.util
import ipaddress
import json
import os
import pathlib
import socket
import stat
import threading
import time

import pytest

import postern
from postern.http import (
    HttpHatch,
    Request,
    Response,
    allow_hosts,
    block_private,
    deny_hosts,
    encode_sse,
    sse_events,
    steer_https_to_http,
)


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


# -- security review: Host pinning + CONNECT canonicalization ---------------- #
def test_host_header_is_pinned_to_the_dialed_authority(origin):
    # A guest that passes the allowlist by dialing an allowed host must not then
    # steer a host-routed front end elsewhere via a spoofed Host header.
    hatch = HttpHatch(allow_hosts({origin}))
    with hatch.accepting():
        sock = _proxy_conn(hatch)
        sock.sendall(f'GET http://{origin}/ HTTP/1.1\r\nHost: attacker.example\r\nConnection: close\r\n\r\n'.encode())
        raw = _recv_all(sock)
    hatch.close()
    body = json.loads(raw.split(b'\r\n\r\n', 1)[1])
    assert body['host'] == origin  # forwarded Host is the policy-checked authority
    assert 'attacker' not in body['host']


def test_duplicate_host_headers_are_all_replaced(origin):
    hatch = HttpHatch(allow_hosts({origin}))
    with hatch.accepting():
        sock = _proxy_conn(hatch)
        sock.sendall(
            f'GET http://{origin}/ HTTP/1.1\r\nHost: a.example\r\nHost: b.example\r\nConnection: close\r\n\r\n'.encode()
        )
        raw = _recv_all(sock)
    hatch.close()
    assert json.loads(raw.split(b'\r\n\r\n', 1)[1])['host'] == origin


def test_missing_host_is_synthesized(origin):
    hatch = HttpHatch(allow_hosts({origin}))
    with hatch.accepting():
        sock = _proxy_conn(hatch)
        sock.sendall(f'GET http://{origin}/ HTTP/1.1\r\nConnection: close\r\n\r\n'.encode())
        raw = _recv_all(sock)
    hatch.close()
    assert json.loads(raw.split(b'\r\n\r\n', 1)[1])['host'] == origin


def test_connect_authority_is_canonicalized_like_absolute_form():
    # A handler sees one canonical req.host on both the absolute-form and CONNECT
    # paths — no case/normalization gap that de-syncs a string-matching handler.
    seen = []

    def handler(req, _forward):
        seen.append(req.host)
        return Response.text(200, 'OK', 'noted')  # don't dial; just record

    hatch = HttpHatch(handler)
    with hatch.accepting():
        _http_get(hatch, 'http://EXAMPLE.COM/', 'x')
        sock = _proxy_conn(hatch)
        sock.sendall(b'CONNECT EXAMPLE.COM:443 HTTP/1.1\r\nHost: x\r\n\r\n')
        _recv_all(sock)
    hatch.close()
    assert set(seen) == {'example.com'}  # both lowercased


def test_set_header_drops_guest_duplicates():
    req = Request('GET', 'http://x/', [('X-Api-Key', 'guest'), ('x-api-key', 'guest2')], 'x', 80, is_connect=False)
    req.set_header('X-Api-Key', 'SECRET')
    values = [v for k, v in req.headers if k.lower() == 'x-api-key']
    assert values == ['SECRET']  # both guest copies (any case) replaced by one


# -- block_private: address-level SSRF/IMDS boundary ------------------------- #
def test_block_private_blocks_internal_allows_global():
    blocked = block_private()
    for ip in (
        '169.254.169.254',  # cloud metadata
        '127.0.0.1',
        '10.0.0.1',
        '172.16.0.1',
        '192.168.1.1',
        '100.64.0.1',  # CGNAT
        '0.0.0.0',  # noqa: S104 — testing that unspecified is blocked
        '::1',
        'fe80::1',
        'fc00::1',  # ULA
    ):
        assert blocked(ipaddress.ip_address(ip)), ip
    for ip in ('8.8.8.8', '1.1.1.1', '93.184.216.34', '2606:4700:4700::1111'):
        assert not blocked(ipaddress.ip_address(ip)), ip


def test_block_overrides_an_allowed_name_on_the_resolved_address(origin):
    # block filters the *resolved* address, so it refuses the loopback origin
    # even though its host:port is on the allowlist — defense in depth a
    # name-based deny_hosts can't provide.
    hatch = HttpHatch(allow_hosts({origin}), block=block_private())
    with hatch.accepting():
        status, body = _http_get(hatch, f'http://{origin}/x', origin)
    hatch.close()
    assert status == 403
    assert b'blocked address' in body


# -- regression: hostile input (adversarial review findings) ----------------- #
def test_bare_lf_header_is_rejected_not_smuggled(origin):
    # A bare LF inside a header value must not be re-serialized upstream as a
    # separate header line (CL.TE request smuggling); reject with 400.
    hatch = HttpHatch(allow_hosts({origin}))
    with hatch.accepting():
        sock = _proxy_conn(hatch)
        sock.sendall(
            f'GET http://{origin}/ HTTP/1.1\r\nHost: {origin}\r\n'.encode()
            + b'X-Foo: x\nTransfer-Encoding: chunked\r\n\r\n'
        )
        raw = _recv_all(sock)
    hatch.close()
    assert raw.split(b' ', 2)[1] == b'400'


def test_truncated_chunked_request_does_not_hang(origin):
    # A chunked request body that EOFs before a size line must not spin the
    # worker at 100% CPU — the connection is torn down promptly.
    hatch = HttpHatch(allow_hosts({origin}))
    with hatch.accepting():
        sock = _proxy_conn(hatch)
        sock.settimeout(4)
        sock.sendall(
            f'POST http://{origin}/x HTTP/1.1\r\nHost: {origin}\r\n'.encode() + b'Transfer-Encoding: chunked\r\n\r\n'
        )
        sock.shutdown(socket.SHUT_WR)  # truncate: no chunk ever arrives
        assert sock.recv(4096) == b''  # server tears the connection down, no hang
        sock.close()
    hatch.close()


def test_chunked_request_body_respects_max_body_bytes(origin):
    # A single oversized declared chunk must be refused up front, not buffered.
    hatch = HttpHatch(allow_hosts({origin}), max_body_bytes=1024)
    with hatch.accepting():
        sock = _proxy_conn(hatch)
        sock.settimeout(4)
        sock.sendall(
            f'POST http://{origin}/x HTTP/1.1\r\nHost: {origin}\r\n'.encode()
            + b'Transfer-Encoding: chunked\r\n\r\n'
            + b'100000\r\n'  # 1 MiB declared chunk >> the 1 KiB cap
        )
        assert sock.recv(4096) == b''  # rejected before the body is read
        sock.close()
    hatch.close()


def test_chunked_extension_line_is_capped(origin):
    # A giant chunk-extension (or endless no-newline padding) must not buffer
    # past the size-line cap to dodge max_body_bytes (the N1 relocation of F3).
    hatch = HttpHatch(allow_hosts({origin}), max_body_bytes=1024)
    with hatch.accepting():
        sock = _proxy_conn(hatch)
        sock.settimeout(4)
        payload = (
            f'POST http://{origin}/x HTTP/1.1\r\nHost: {origin}\r\n'.encode()
            + b'Transfer-Encoding: chunked\r\n\r\n'
            + b'1;'
            + b'a' * 50_000  # chunk-extension far past the 8 KiB line cap, no newline
        )
        # The hatch caps the line and closes mid-send, so the write may break —
        # either a broken pipe or an empty read means rejected-not-buffered.
        try:
            sock.sendall(payload)
            rejected = sock.recv(4096) == b''
        except (BrokenPipeError, ConnectionResetError):
            rejected = True
        sock.close()
    hatch.close()
    assert rejected


def test_oversized_response_chunk_streams_instead_of_buffering():
    # `read(size)` used to materialise the whole *declared* chunk before yielding
    # it, so an upstream chunk header was a host memory lever (64 MiB streamed
    # inside a chunk declared as 4 GiB cost 68 MiB of host RSS while the guest
    # saw only the headers). The bytes that have arrived must reach the guest
    # while the chunk is still open.
    sent = 128 * 1024
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    host_port = f'127.0.0.1:{listener.getsockname()[1]}'
    done = threading.Event()

    def dribbling_origin():
        conn, _ = listener.accept()
        while b'\r\n\r\n' not in conn.recv(65536):
            pass
        conn.sendall(
            b'HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n'
            b'Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n'
            b'ffffffff\r\n'  # declare 4 GiB, then send a fraction of it and stall
        )
        conn.sendall(b'B' * sent)
        done.wait(10)  # hold the chunk open: nothing else is coming
        conn.close()

    threading.Thread(target=dribbling_origin, daemon=True).start()
    hatch = HttpHatch(allow_hosts({host_port}))
    with hatch.accepting():
        sock = _proxy_conn(hatch)
        sock.settimeout(10)
        sock.sendall(f'GET http://{host_port}/big HTTP/1.1\r\nHost: {host_port}\r\n\r\n'.encode())
        body = b''
        while len(body) < sent:  # times out (test failure) if the host buffers
            body += sock.recv(65536)
        sock.close()
    done.set()
    hatch.close()
    listener.close()
    assert body.endswith(b'B' * 1024)


def test_https_absolute_form_is_refused_not_dialled_in_cleartext():
    # `forward` never wraps TLS, so forwarding an `https://` absolute-form target
    # put the request — including a handler's injected credentials — on the wire
    # in plaintext to port 443 of an allowlisted host, at the guest's choosing.
    wire = []
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    host_port = f'127.0.0.1:{listener.getsockname()[1]}'

    def capture():
        try:
            conn, _ = listener.accept()
        except OSError:
            return  # the listener was closed without anything ever dialling it
        conn.settimeout(2)
        try:
            wire.append(conn.recv(65536))
        except TimeoutError:
            wire.append(b'')
        conn.close()

    threading.Thread(target=capture, daemon=True).start()
    inner = allow_hosts({host_port})

    def handler(req, forward):
        req.set_header('Authorization', 'Bearer HOST-ONLY-SECRET')
        return inner(req, forward)

    hatch = HttpHatch(handler)
    with hatch.accepting():
        status, body = _http_get(hatch, f'https://{host_port}/v1/x', host_port)
    hatch.close()
    listener.close()
    assert status == 400
    assert b'CONNECT' in body  # actionable: use CONNECT or an http:// base URL
    assert not wire, 'nothing may be dialled, let alone the credential in cleartext'


@pytest.mark.parametrize('scheme', ['https', 'ftp', 'gopher', ''])
def test_non_http_schemes_are_not_forwarded(scheme):
    # Any non-http scheme is plaintext-dialled garbage at best; a scheme-relative
    # target (`//host/x`) parses a host with no scheme at all, so pin to `http`.
    hatch = HttpHatch(allow_hosts({'x'}))
    target = f'{scheme}://x/y' if scheme else '//x/y'
    with hatch.accepting():
        status, _ = _http_get(hatch, target, 'x')
    hatch.close()
    assert status == 400


def test_hostless_target_is_refused_not_dialled_at_loopback(origin):
    # `http://:PORT/x` (empty authority) and `GET /x` (origin-form) both leave
    # host == '', which matches no entry in a name-based policy *and* which
    # getaddrinfo resolves to loopback — so `deny_hosts` used to wave them
    # through onto the host's own services. Both must be a 400.
    port = int(origin.split(':')[1])
    denied = {'127.0.0.1', 'localhost', '::1', origin}
    hatch = HttpHatch(deny_hosts(denied))
    with hatch.accepting():
        for target in (f'http://:{port}/x', '/x', 'http:///x'):
            status, body = _http_get(hatch, target, 'example.com')
            assert status == 400, target
            assert b'absolute-form' in body, target
    hatch.close()


def test_hostless_connect_authority_is_refused():
    # `CONNECT` with no parsable host used to fall back to the raw authority as
    # the "host" (`:443` → the host ':443') or to an empty one, which dialled
    # loopback:443. No host parsed means malformed.
    hatch = HttpHatch(deny_hosts({'127.0.0.1', 'localhost'}))
    with hatch.accepting():
        for authority in ('', ':443', '/x'):
            sock = _proxy_conn(hatch)
            sock.sendall(f'CONNECT {authority} HTTP/1.1\r\nHost: x\r\n\r\n'.encode())
            raw = _recv_all(sock)
            assert raw.split(b' ', 2)[1] == b'400', authority
    hatch.close()


def test_unparsable_port_is_a_400_not_a_bare_teardown():
    # Reading urlsplit's .port raises ValueError for a non-numeric/out-of-range
    # port; unguarded that escaped as a bare exception and dropped the guest's
    # connection with no answer at all.
    hatch = HttpHatch(allow_hosts(set()))
    with hatch.accepting():
        for target in ('http://x:99999/', 'http://x:notaport/'):
            status, _ = _http_get(hatch, target, 'x')
            assert status == 400, target
    hatch.close()


def test_negative_chunk_size_cannot_credit_the_body_budget(origin):
    # `int(b'-ff', 16)` is a *negative* size: as a budget delta it drove the
    # running total below zero (so max_body_bytes never fired again) and as a
    # read() length it consumed nothing (so the loop continued) — one 17-byte
    # size line bought unbounded host-side buffering, pre-policy. Only 1*HEXDIG
    # is a chunk-size; anything else is rejected outright.
    hatch = HttpHatch(allow_hosts({origin}), max_body_bytes=1024)
    with hatch.accepting():
        sock = _proxy_conn(hatch)
        sock.settimeout(4)
        sock.sendall(
            f'POST http://{origin}/x HTTP/1.1\r\nHost: {origin}\r\n'.encode()
            + b'Transfer-Encoding: chunked\r\n\r\n'
            + b'-ffffffffffffff\r\n'  # negative, and small enough to fit Py_ssize_t
            + b'\r\n'
            + b'400000\r\n'  # 4 MiB, which the credited budget would have waved through
        )
        assert sock.recv(4096) == b''  # rejected, not buffered
        sock.close()
    hatch.close()


@pytest.mark.parametrize('size_field', [b'-1', b'+1', b'0x10', b'1 0', b'f' * 17, b''])
def test_malformed_chunk_size_is_rejected(origin, size_field):
    # Sign, base prefix, embedded whitespace, an absurd digit count, an empty
    # field: none is a chunk-size, and none may reach int(..., 16).
    hatch = HttpHatch(allow_hosts({origin}), max_body_bytes=1024)
    with hatch.accepting():
        sock = _proxy_conn(hatch)
        sock.settimeout(4)
        sock.sendall(
            f'POST http://{origin}/x HTTP/1.1\r\nHost: {origin}\r\n'.encode()
            + b'Transfer-Encoding: chunked\r\n\r\n'
            + size_field
            + b'\r\nquxx\r\n0\r\n\r\n'
        )
        assert sock.recv(4096) == b''
        sock.close()
    hatch.close()


def test_chunk_extension_after_bws_still_parses(origin):
    # Strictness must not break the servers that pad BWS before a chunk-ext.
    hatch = HttpHatch(allow_hosts({origin}))
    with hatch.accepting():
        sock = _proxy_conn(hatch)
        sock.settimeout(4)
        sock.sendall(
            f'POST http://{origin}/x HTTP/1.1\r\nHost: {origin}\r\n'.encode()
            + b'Transfer-Encoding: chunked\r\n\r\n'
            + b'4 ;name=value\r\nbody\r\n0\r\n\r\n'
        )
        raw = _recv_all(sock)
    hatch.close()
    assert json.loads(raw.split(b'\r\n\r\n', 1)[1])['received'] == 'body'


def test_dripping_guest_hits_the_phase_deadline_not_the_per_read_timer():
    # conn.settimeout is a per-recv timer that every arriving byte resets, so a
    # guest dripping one header line per (timeout - eps) held a pool worker
    # indefinitely without ever tripping it — 8s and counting against a 0.5s
    # timeout. The pre-response phase needs an absolute budget.
    hatch = HttpHatch(allow_hosts(set()), connect_timeout=1.0)
    with hatch.accepting():
        sock = _proxy_conn(hatch)
        sock.sendall(b'GET http://x/ HTTP/1.1\r\n')  # no terminating blank line
        start = time.monotonic()
        closed = False
        while time.monotonic() - start < 8:
            time.sleep(0.3)  # comfortably inside the per-recv timer, forever
            try:
                sock.sendall(b'X-Pad: y\r\n')
            except OSError:
                closed = True
                break
            sock.setblocking(False)
            try:
                closed = sock.recv(1) == b''
            except BlockingIOError:
                pass
            finally:
                sock.setblocking(True)
            if closed:
                break
        elapsed = time.monotonic() - start
        sock.close()
    hatch.close()
    assert closed, 'a dripping guest held the worker past the phase deadline'
    assert elapsed < 5, f'torn down late ({elapsed:.1f}s) for a 1.0s budget'


def test_stalled_guest_is_timed_out_not_pinned():
    # A slowloris that sends a partial header then stalls must not hold a worker.
    hatch = HttpHatch(allow_hosts(set()), connect_timeout=0.5)
    with hatch.accepting():
        sock = _proxy_conn(hatch)
        sock.settimeout(4)
        sock.sendall(b'GET http://x/ HTTP/1.1\r\nHost: x\r\n')  # no terminating blank line
        assert sock.recv(4096) == b''  # read times out host-side, connection closed
        sock.close()
    hatch.close()


def test_upstream_reset_after_accept_is_502_not_a_leak():
    # If an allowed upstream accepts then closes before responding, the hatch
    # answers 502 and does not leak the upstream fd (exercises the failure path).
    dead = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dead.bind(('127.0.0.1', 0))
    dead.listen(1)
    dead_hp = f'127.0.0.1:{dead.getsockname()[1]}'

    def slam():
        conn, _ = dead.accept()
        conn.close()  # accept then immediately drop

    threading.Thread(target=slam, daemon=True).start()
    hatch = HttpHatch(allow_hosts({dead_hp}))
    with hatch.accepting():
        status, _ = _http_get(hatch, f'http://{dead_hp}/x', dead_hp)
    hatch.close()
    dead.close()
    assert status == 502


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
