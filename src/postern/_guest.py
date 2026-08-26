"""In-sandbox entrypoint for `Sandbox.run_python`.

Runs *inside* the bubblewrap sandbox, so it is stdlib-only. It applies the
resource limits and then execs the guest code. Reaching a hatch is the guest's
own business: the socket is a file at ``$POSTERN_HATCH``, dialled with whatever
client library the guest's environment carries.

bwrap launches this shim with ``--as-pid-1``, so it is PID 1 of the guest's PID
namespace and owes that namespace a real init: it forks the guest and reaps it
plus any orphaned descendants that reparent here, and marks *itself* non-dumpable
so a co-uid process the guest spawns cannot read this init's ``/proc/1``.

The host↔shim contract is three environment variables: ``POSTERN_CODE``,
``POSTERN_NPROC`` and ``POSTERN_AS``. ``POSTERN_HATCH`` is set alongside them for
the *guest* to read, not for this module.
"""

import contextlib
import ctypes
import os
import resource
import signal
import sys
import traceback

_PR_SET_DUMPABLE = 4  # linux/prctl.h


def _set_nondumpable() -> None:
    """Clear PR_SET_DUMPABLE so this process's /proc/<pid> is root-owned.

    With the flag off the kernel roots ownership of ``/proc/self`` and gates
    ``ptrace_may_access`` on CAP_SYS_PTRACE, so no same-uid process the guest
    spawns can read this init's memory, environ or maps. Best-effort: the init's
    own environment is already cleared by ``--clearenv``, so a failure here costs
    a layer of defense rather than a secret.
    """
    with contextlib.suppress(OSError):
        ctypes.CDLL(None, use_errno=True).prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0)


def _run_guest() -> None:
    """Apply the resource backstops and execute the guest code in this process."""
    nproc = int(os.environ.get('POSTERN_NPROC') or 0)
    if nproc:
        resource.setrlimit(resource.RLIMIT_NPROC, (nproc, nproc))
    # Per-process, so this bounds one allocation spree rather than the guest's
    # total memory; a cgroup memory.max at the deploy layer is the real bound.
    as_bytes = int(os.environ.get('POSTERN_AS') or 0)
    if as_bytes:
        resource.setrlimit(resource.RLIMIT_AS, (as_bytes, as_bytes))
    code = os.environ.get('POSTERN_CODE', '')
    exec(code, {'__name__': '__main__'})  # noqa: S102 — executing guest code is the whole point


def _init() -> int:
    """Run as PID 1: fork the guest, reap the namespace, return the guest's status."""
    child = os.fork()
    if child == 0:
        # `sys.exit(main())`'s status handling, but via os._exit so the child can
        # never fall back into the parent's reaper loop.
        try:
            _run_guest()
        except SystemExit as exc:
            code = exc.code
            os._exit(code if isinstance(code, int) else (0 if code is None else 1))
        except BaseException:
            traceback.print_exc()
            os._exit(1)
        os._exit(0)
    # PID 1 gets no default signal action, so an unhandled SIGTERM/SIGINT would be
    # dropped rather than reaching the guest.
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda s, _frame, c=child: os.kill(c, s))
    # Reap orphaned descendants reparented here along the way. Anything still
    # alive when PID 1 exits is SIGKILLed by the kernel.
    while True:
        pid, status = os.wait()
        if pid == child:
            if os.WIFEXITED(status):
                return os.WEXITSTATUS(status)
            if os.WIFSIGNALED(status):
                return 128 + os.WTERMSIG(status)
            return 1


def main() -> int:
    if os.getpid() == 1:
        _set_nondumpable()
        return _init()
    # Launched without --as-pid-1: no init role to play, so run the guest here.
    _run_guest()
    return 0


if __name__ == '__main__':
    sys.exit(main())
