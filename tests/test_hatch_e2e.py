"""End-to-end: sealed sandbox + gRPC hatch + allowlist, all at once.

The rest of the e2e suite covers the *sealed* sandbox (no hatch). This is the
whole postern promise in one run: untrusted guest code, no network and no host
filesystem, reaching the outside world *only* by dialing the bound hatch UDS —
an allowlisted method succeeds, a non-allowlisted one is ``PERMISSION_DENIED``.

Requires Linux + bubblewrap (skipped elsewhere) and grpcio in the guest's
environment. The default profile binds the host ``/usr`` read-only, so grpcio
installed in site-packages is importable by the guest interpreter — no venv or
generated stubs needed. Like ``test_grpc_hatch``, it uses a raw-bytes generic
handler instead of protoc output so it runs anywhere grpcio is installed.
"""

import grpc
import pytest

from postern import Sandbox, SandboxProfile, available
from postern.grpc import GrpcHatch

pytestmark = pytest.mark.skipif(not available(), reason='requires Linux + bubblewrap')

_ALLOWED = '/svc.Echo/Allowed'

# Guest code: dial the hatch, call an allowlisted method (echoes back), then a
# non-allowlisted one (must be refused). Prints outcomes for the host to assert.
_GUEST = """
import os, grpc

channel = grpc.insecure_channel('unix:' + os.environ['POSTERN_HATCH'])

def call(method, payload):
    stub = channel.unary_unary(method, request_serializer=bytes, response_deserializer=bytes)
    return stub(payload, timeout=15)

print('ALLOWED', call('/svc.Echo/Allowed', b'ping').decode())
try:
    call('/svc.Echo/Denied', b'x')
    print('DENIED reached')
except grpc.RpcError as exc:
    print('DENIED', exc.code().name)
"""


def _echo(request, _context):
    return request


def _install_echo(server):
    handler = grpc.method_handlers_generic_handler(
        'svc.Echo',
        {'Allowed': grpc.unary_unary_rpc_method_handler(_echo, request_deserializer=bytes, response_serializer=bytes)},
    )
    server.add_generic_rpc_handlers((handler,))


def test_guest_reaches_allowlisted_method_and_is_denied_the_rest():
    hatch = GrpcHatch(allowlist={_ALLOWED})
    _install_echo(hatch._server)
    result = Sandbox(SandboxProfile(), hatch=hatch).run_python(_GUEST)
    hatch.close()
    assert result.ok, result.stderr
    assert 'ALLOWED ping' in result.stdout  # allowlisted call went through and echoed
    assert 'DENIED PERMISSION_DENIED' in result.stdout  # non-allowlisted call refused
    assert 'DENIED reached' not in result.stdout


def test_guest_has_no_network_but_still_reaches_the_hatch():
    # The hatch works over the bound UDS even though the netns has no route out:
    # proves the socket the guest opens is the hatch, not egress.
    hatch = GrpcHatch(allowlist={_ALLOWED})
    _install_echo(hatch._server)
    code = (
        'import os, socket, grpc\n'
        'try:\n'
        '    socket.create_connection(("1.1.1.1", 443), timeout=3); print("EGRESS")\n'
        'except OSError:\n'
        '    print("no-egress")\n'
        "stub = grpc.insecure_channel('unix:' + os.environ['POSTERN_HATCH'])"
        ".unary_unary('/svc.Echo/Allowed', request_serializer=bytes, response_deserializer=bytes)\n"
        "print('HATCH', stub(b'hi', timeout=15).decode())\n"
    )
    result = Sandbox(SandboxProfile(), hatch=hatch).run_python(code)
    hatch.close()
    assert result.ok, result.stderr
    assert 'no-egress' in result.stdout
    assert 'EGRESS' not in result.stdout
    assert 'HATCH hi' in result.stdout
