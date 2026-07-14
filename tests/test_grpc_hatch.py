"""The method-allowlist is the capability gate — test allow vs deny directly.

Uses raw generic handlers (no generated stubs) so it runs anywhere grpcio is
installed; no bubblewrap needed (this exercises the hatch server, not the sandbox).
"""

import grpc
import pytest

from postern.grpc import GrpcHatch

_ALLOWED = '/svc.Echo/Allowed'
_DENIED = '/svc.Echo/Denied'


def _echo(request, _context):
    return request


def _install_echo(server):
    handler = grpc.method_handlers_generic_handler(
        'svc.Echo',
        {'Allowed': grpc.unary_unary_rpc_method_handler(_echo, request_deserializer=bytes, response_serializer=bytes)},
    )
    server.add_generic_rpc_handlers((handler,))


def _call(channel, method, payload):
    stub = channel.unary_unary(method, request_serializer=bytes, response_deserializer=bytes)
    return stub(payload)


def test_allowlisted_method_passes():
    hatch = GrpcHatch(allowlist={_ALLOWED})
    _install_echo(hatch._server)
    with hatch.accepting(), grpc.insecure_channel(f'unix:{hatch.socket_path}') as channel:
        assert _call(channel, _ALLOWED, b'hi') == b'hi'
    hatch.close()


def test_unlisted_method_is_permission_denied():
    hatch = GrpcHatch(allowlist={_ALLOWED})
    _install_echo(hatch._server)
    with hatch.accepting(), grpc.insecure_channel(f'unix:{hatch.socket_path}') as channel:
        with pytest.raises(grpc.RpcError) as exc:
            _call(channel, _DENIED, b'x')
        assert exc.value.code() == grpc.StatusCode.PERMISSION_DENIED
    hatch.close()


def test_hatch_reused_across_calls():
    # A session makes many run_python calls against one hatch; the server must
    # start once and stay up (a gRPC server cannot be restarted).
    hatch = GrpcHatch(allowlist={_ALLOWED})
    _install_echo(hatch._server)
    with hatch.accepting(), grpc.insecure_channel(f'unix:{hatch.socket_path}') as channel:
        assert _call(channel, _ALLOWED, b'one') == b'one'
    with hatch.accepting(), grpc.insecure_channel(f'unix:{hatch.socket_path}') as channel:
        assert _call(channel, _ALLOWED, b'two') == b'two'
    hatch.close()
