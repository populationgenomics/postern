"""End-to-end example: a typed host call over the gRPC hatch + pandas, sandboxed.

Run on a Linux host with bubblewrap, using the interpreter of a venv that holds
grpcio + pandas + the generated greeter stubs:

    python -m grpc_tools.protoc -I examples --python_out=<site-packages> \
        --grpc_python_out=<site-packages> examples/greeter.proto
    <venv>/bin/python examples/e2e_greeter.py

The guest, inside the sealed sandbox, dials the hatch, calls the *allowlisted*
SayHello, uses pandas, confirms a non-allowlisted method is denied, and confirms
there is no network. The servicer runs in this trusted host process.
"""

from __future__ import annotations

import pathlib
import sys

import greeter_pb2
import greeter_pb2_grpc

from postern import Sandbox, SandboxProfile
from postern.grpc import GrpcHatch


class Greeter(greeter_pb2_grpc.GreeterServicer):
    def SayHello(self, request, context):
        return greeter_pb2.HelloReply(message=f'Hello, {request.name}!')


_GUEST = """
import os, socket
import pandas as pd
import grpc
import greeter_pb2, greeter_pb2_grpc

channel = grpc.insecure_channel('unix:' + os.environ['POSTERN_HATCH'])
stub = greeter_pb2_grpc.GreeterStub(channel)
print('HATCH_REPLY:', stub.SayHello(greeter_pb2.HelloRequest(name='sandbox')).message)
print('PANDAS_SUM:', int(pd.DataFrame({'x': [1, 2, 3]}).x.sum()))

try:
    forbidden = channel.unary_unary(
        '/greeter.Greeter/Forbidden',
        request_serializer=greeter_pb2.HelloRequest.SerializeToString,
        response_deserializer=greeter_pb2.HelloReply.FromString,
    )
    forbidden(greeter_pb2.HelloRequest(name='x'))
    print('DENY_CHECK: FAIL-allowed')
except grpc.RpcError as e:
    print('DENY_CHECK:', e.code().name)

try:
    socket.create_connection(('1.1.1.1', 443), timeout=3)
    print('NET: EGRESS-bad')
except OSError as e:
    print('NET: no-egress', e.errno)
"""


def main() -> int:
    hatch = GrpcHatch(allowlist={'/greeter.Greeter/SayHello'})
    hatch.add_servicer(greeter_pb2_grpc.add_GreeterServicer_to_server, Greeter())
    sandbox = Sandbox(SandboxProfile.with_venv(pathlib.Path(sys.prefix)), hatch=hatch)
    result = sandbox.run_python(_GUEST, timeout=120)
    hatch.close()
    print('--- guest stdout ---')
    print(result.stdout)
    print('--- guest stderr ---')
    print(result.stderr.strip())
    print('--- returncode', result.returncode)
    return 0 if result.ok else 1


if __name__ == '__main__':
    sys.exit(main())
