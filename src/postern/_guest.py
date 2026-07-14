"""In-sandbox entrypoint for `Sandbox.run_python`.

Runs *inside* the bubblewrap sandbox, so it is stdlib-only. It applies the
process-count limit (a fork-bomb backstop set here rather than via a fork-time
callback in the host) and then execs the guest code.

The guest reaches the hatch by dialing the bound Unix socket with an ordinary
gRPC channel + the generated stub — that machinery lives in the guest's own
environment, not here. The socket path is exported as ``POSTERN_HATCH``.
"""

import os
import resource
import sys


def main() -> None:
    nproc = int(os.environ.get('POSTERN_NPROC') or 0)
    if nproc:
        resource.setrlimit(resource.RLIMIT_NPROC, (nproc, nproc))
    code = os.environ.get('POSTERN_CODE', '')
    exec(code, {'__name__': '__main__'})  # noqa: S102 — executing guest code is the whole point


if __name__ == '__main__':
    sys.exit(main())
