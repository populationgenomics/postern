"""Deployable worker for the Cloud Run recipe (examples/Dockerfile).

Binds a curated guest rootfs at /opt/guest-root (built by the Dockerfile), so the
guest sees none of the worker's userland. In a real Job the guest code comes
from the agent loop; here it runs a fixed snippet as a smoke test.
"""

from __future__ import annotations

import sys

import greeter_pb2
import greeter_pb2_grpc

from postern import Sandbox, SandboxProfile
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
    hatch = GrpcHatch(allowlist={'/greeter.Greeter/SayHello'})
    hatch.add_servicer(greeter_pb2_grpc.add_GreeterServicer_to_server, Greeter())
    result = Sandbox(SandboxProfile(rootfs='/opt/guest-root'), hatch=hatch).run_python(_GUEST, timeout=120)
    hatch.close()
    print(result.stdout)
    print(result.stderr.strip())
    return 0 if result.ok else 1


if __name__ == '__main__':
    sys.exit(main())
