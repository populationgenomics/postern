"""Deployable worker for the Cloud Run recipe (``examples/Dockerfile``).

Binds the curated guest rootfs the Dockerfile builds at ``/opt/guest-root``, so
the guest sees none of the worker's userland, and runs every guest under the C
init the Dockerfile builds at ``/opt/postern-init``. The guest code here is a fixed
smoke-test snippet where a real Job would take it from the caller.
"""

from __future__ import annotations

import sys

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


def main() -> int:
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
    result = Sandbox(profile, hatch=hatch).run_python(_GUEST, timeout=120)
    hatch.close()
    print(result.stdout)
    print(result.stderr.strip())
    return 0 if result.ok else 1


if __name__ == '__main__':
    sys.exit(main())
