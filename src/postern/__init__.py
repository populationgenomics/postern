"""postern — untrusted code in a sealed sandbox with one typed doorway.

Run untrusted Python in an OS-isolated `Sandbox` (bubblewrap: empty network
namespace, surgical filesystem, dropped capabilities, seccomp) whose *only*
interface to the outside is a hatch — host-provided gRPC methods, gated by an
allowlist, that the guest calls with the generated stub. The security boundary
is that method set, not a coarse permission flag.

    from postern import Sandbox, SandboxProfile
    from postern.grpc import GrpcHatch
    import greeter_pb2_grpc

    hatch = GrpcHatch(allowlist={'/greeter.Greeter/SayHello'})
    hatch.add_servicer(greeter_pb2_grpc.add_GreeterServicer_to_server, MyGreeter())

    profile = SandboxProfile.with_venv('/opt/analysis-env')   # pandas, grpcio, stubs
    Sandbox(profile, hatch=hatch).run_python(guest_code)

The bare `Sandbox` has no third-party dependencies and no cloud dependency — it
is a Linux + bubblewrap primitive. The gRPC hatch lives behind the ``grpc``
extra; provider/runtime adapters behind their own.
"""

from __future__ import annotations

import importlib.metadata

from postern._sandbox import ProcResult, Sandbox, SandboxProfile, available

try:
    __version__ = importlib.metadata.version('postern')
except importlib.metadata.PackageNotFoundError:
    # Running from a source tree without an install.
    __version__ = '0.0.0+unknown'

__all__ = ['ProcResult', 'Sandbox', 'SandboxProfile', '__version__', 'available']
