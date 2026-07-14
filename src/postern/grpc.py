"""The gRPC escape hatch: the sandbox's typed doorway to the outside.

A `GrpcHatch` serves host-provided `grpc` servicers over the sandbox's Unix
domain socket, gated by a **method allowlist** — only the exact
``/package.Service/Method`` names you list are reachable; anything else is
`PERMISSION_DENIED`. The servicer runs in the trusted host process; the guest
calls it with the generated stub over ``unix:$POSTERN_HATCH``. The proto is the
typed contract, so arguments and results are typed and language-neutral, and the
allowlist is the capability grant — the security boundary is that method set.

Requires the ``grpc`` extra (``pip install 'postern[grpc]'``). ``import
postern.grpc`` only where you use it; the bare `Sandbox` stays dependency-free.

    from postern import Sandbox, SandboxProfile
    from postern.grpc import GrpcHatch
    import greeter_pb2_grpc

    hatch = GrpcHatch(allowlist={'/greeter.Greeter/SayHello'})
    hatch.add_servicer(greeter_pb2_grpc.add_GreeterServicer_to_server, MyGreeter())
    sandbox = Sandbox(SandboxProfile.with_venv('/opt/env'), hatch=hatch)
    sandbox.run_python(guest_code)   # guest dials unix:$POSTERN_HATCH with the stub
"""

from __future__ import annotations

import contextlib
import os
import tempfile
import typing
from collections.abc import Callable, Generator
from concurrent import futures

import grpc


class _Allowlist(grpc.ServerInterceptor):
    """Reject any method whose full name is not in the allowlist."""

    def __init__(self, allowed: typing.Iterable[str]) -> None:
        self._allowed = frozenset(allowed)

    def intercept_service(
        self,
        continuation: Callable[[grpc.HandlerCallDetails], grpc.RpcMethodHandler | None],
        handler_call_details: grpc.HandlerCallDetails,
    ) -> grpc.RpcMethodHandler | None:
        method = getattr(handler_call_details, 'method', None)
        if method in self._allowed:
            return continuation(handler_call_details)

        def deny(_request: object, context: grpc.ServicerContext) -> typing.NoReturn:
            context.abort(grpc.StatusCode.PERMISSION_DENIED, f'{method} is not on the hatch allowlist')

        # A unary deny handler aborts before any message flows. Streaming methods
        # on the deny path may surface a cardinality mismatch client-side, but the
        # call is still refused; allowed methods keep their real (any-cardinality)
        # handler via ``continuation``.
        return grpc.unary_unary_rpc_method_handler(deny)


class GrpcHatch:
    """Serve allowlisted `grpc` servicers over the sandbox's UDS."""

    def __init__(
        self,
        allowlist: typing.Iterable[str],
        *,
        socket_path: str | os.PathLike[str] | None = None,
        max_workers: int = 8,
    ) -> None:
        if socket_path is None:
            self._dir = tempfile.mkdtemp(prefix='postern-')
            self._path = os.path.join(self._dir, 'hatch.sock')
        else:
            self._dir = None
            self._path = os.fspath(socket_path)
        self._server = grpc.server(
            futures.ThreadPoolExecutor(max_workers=max_workers),
            interceptors=[_Allowlist(allowlist)],
        )
        self._server.add_insecure_port(f'unix:{self._path}')
        self._started = False

    @property
    def socket_path(self) -> str:
        return self._path

    def add_servicer(self, register: Callable[[typing.Any, grpc.Server], None], servicer: object) -> None:
        """Register a servicer via its generated ``add_<Service>Servicer_to_server``."""
        register(servicer, self._server)

    def start(self) -> None:
        """Start serving (idempotent).

        A gRPC server cannot be restarted, so the hatch serves from here until
        :meth:`close` — reused across many calls.
        """
        if not self._started:
            self._server.start()
            self._started = True

    @contextlib.contextmanager
    def accepting(self) -> Generator[GrpcHatch, None, None]:
        """Ensure the hatch is serving for the block.

        It stays up afterwards so a later call can reuse it, and is stopped only
        by :meth:`close`.
        """
        self.start()
        yield self

    def close(self) -> None:
        if self._started:
            self._server.stop(0)
            self._started = False
        with contextlib.suppress(OSError):
            os.unlink(self._path)
        if self._dir is not None:
            with contextlib.suppress(OSError):
                os.rmdir(self._dir)
