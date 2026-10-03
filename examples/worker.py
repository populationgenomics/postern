"""Deployable worker for the Cloud Run recipe (``examples/Dockerfile``).

Binds the curated guest rootfs the Dockerfile builds at ``/opt/guest-root``, so
the guest sees none of the worker's userland, and runs every guest under the C
init the Dockerfile builds at ``/opt/postern-init``. The guest code here is a fixed
smoke-test snippet where a real Job would take it from the caller.

Cloud Run stops a task with SIGTERM to this process, then SIGKILL 10 s later. The
worker passes the SIGTERM on to the guest with :meth:`Process.terminate`, so the
guest's own cleanup runs, and exits with status 143.
"""

from __future__ import annotations

import signal
import sys
import types

import greeter_pb2
import greeter_pb2_grpc

from postern import IsolationError, Sandbox, SandboxProfile
from postern.grpc import GrpcHatch


class Greeter(greeter_pb2_grpc.GreeterServicer):
    def SayHello(self, request, context):
        return greeter_pb2.HelloReply(message=f'Hello, {request.name}!')


_GUEST = """
import os
import grpc
import pandas as pd
import greeter_pb2, greeter_pb2_grpc

channel = grpc.insecure_channel('unix:' + os.environ['POSTERN_HATCH'])
reply = greeter_pb2_grpc.GreeterStub(channel).SayHello(greeter_pb2.HelloRequest(name='sandbox'))
print('HATCH_REPLY:', reply.message)
print('PANDAS:', pd.__version__)
"""

# How long a stopped guest gets to clean up: inside the 10 s Cloud Run allows
# between its SIGTERM and its SIGKILL, with room left for the worker to exit.
_STOP_GRACE_S = 5.0
_STOPPED = 128 + signal.SIGTERM


def _exit_on_sigterm(_signum: int, _frame: types.FrameType | None) -> None:
    raise SystemExit(_STOPPED)


def main() -> int:
    # As the container's PID 1, this process gets no default action for SIGTERM:
    # without a handler, Cloud Run's stop would be ignored until its SIGKILL.
    # Raising unwinds whatever is under way; a launch interrupted that way is
    # discarded, guest and all.
    signal.signal(signal.SIGTERM, _exit_on_sigterm)
    profile = SandboxProfile(rootfs='/opt/guest-root', init='/opt/postern-init')
    # Boot-time gate: a platform that cannot enforce the profile, or an init built
    # from another postern version, fails here rather than on the first request.
    try:
        Sandbox(profile).verify()
    except IsolationError as exc:
        print(f'FATAL: isolation self-test failed, refusing to serve: {exc}', file=sys.stderr)
        return 2

    hatch = GrpcHatch(allowlist={'/greeter.Greeter/SayHello'})
    hatch.add_servicer(greeter_pb2_grpc.add_GreeterServicer_to_server, Greeter())
    try:
        with Sandbox(profile, hatch=hatch) as sandbox, sandbox.start_python(_GUEST) as process:
            # From here a SIGTERM stops the guest gracefully instead, and the
            # worker reports what it printed on its way out.
            signal.signal(signal.SIGTERM, lambda *_: process.terminate(grace=_STOP_GRACE_S))
            result = process.communicate(timeout=120)
    finally:
        hatch.close()
    print(result.stdout)
    print(result.stderr.strip())
    if process.terminated and not result.timed_out:
        return _STOPPED
    return 0 if result.ok else 1


if __name__ == '__main__':
    sys.exit(main())
