"""In-sandbox entrypoint for `Sandbox.run_python`.

Runs *inside* the bubblewrap sandbox, so it is stdlib-only. It applies the
process-count limit (a fork-bomb backstop set here rather than via a fork-time
callback in the host) and then execs the guest code.

The guest reaches the hatch by dialing the bound Unix socket with an ordinary
gRPC channel + the generated stub — that machinery lives in the guest's own
environment, not here. The socket path is exported as ``POSTERN_HATCH``.

bwrap launches this shim with ``--as-pid-1``, so it is PID 1 of the guest's PID
namespace: there is no separate bwrap process whose ``/proc/1`` the guest could
read (closing the PID-1 environ/cmdline/mem exposure — bwrap shares the guest
uid, so a same-uid guest could otherwise read and write it). As PID 1 the shim
owes the namespace a real init, so it forks the guest and reaps it plus any
orphaned descendants that reparent here, and it marks *itself* non-dumpable so
even a co-uid process the guest spawns cannot read this init's ``/proc/1``.
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

    With the dumpable flag off the kernel roots ownership of ``/proc/self`` and
    gates ``ptrace_may_access`` on CAP_SYS_PTRACE, so no same-uid process the
    guest spawns can read this init's memory/environ/maps. Best-effort: a failure
    here is not fatal (the init holds no secrets — its env is ``--clearenv``'d —
    so this is defense in depth, not the load-bearing control).
    """
    with contextlib.suppress(OSError):
        ctypes.CDLL(None, use_errno=True).prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0)


def _run_guest() -> None:
    """Apply the resource backstops and execute the guest code in this process."""
    nproc = int(os.environ.get('POSTERN_NPROC') or 0)
    if nproc:
        resource.setrlimit(resource.RLIMIT_NPROC, (nproc, nproc))
    # Address-space backstop: a partial guard against a memory bomb starving the
    # co-located trusted worker (F3). It is per-process, not a true total-memory
    # bound — a cgroup memory.max set by the worker/deploy is the real fix.
    as_bytes = int(os.environ.get('POSTERN_AS') or 0)
    if as_bytes:
        resource.setrlimit(resource.RLIMIT_AS, (as_bytes, as_bytes))
    code = os.environ.get('POSTERN_CODE', '')
    exec(code, {'__name__': '__main__'})  # noqa: S102 — executing guest code is the whole point


def _init() -> int:
    """Run as PID 1: fork the guest, reap the namespace, return the guest's status."""
    child = os.fork()
    if child == 0:
        # The guest runs here as a normal (dumpable) child; only the init above
        # is hidden. Mirror `sys.exit(main())`'s status handling for the guest's
        # own SystemExit / uncaught exception, but with os._exit so we never fall
        # back into the parent's reaper path.
        try:
            _run_guest()
        except SystemExit as exc:
            code = exc.code
            os._exit(code if isinstance(code, int) else (0 if code is None else 1))
        except BaseException:  # surface the guest traceback, then exit nonzero
            traceback.print_exc()
            os._exit(1)
        os._exit(0)
    # Forward a graceful stop to the guest — PID 1 gets no default signal action,
    # so without this a SIGTERM/SIGINT would be dropped rather than reaching it.
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda s, _frame, c=child: os.kill(c, s))
    # Reap until the guest exits, absorbing any orphaned descendants reparented to
    # PID 1 along the way; leftover processes are SIGKILLed by the kernel when
    # PID 1 exits, so returning on the guest's own exit is sufficient.
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
    # Defensive fallback if the shim is ever launched without --as-pid-1: there is
    # no init role to play, so just run the guest in this process.
    _run_guest()
    return 0


if __name__ == '__main__':
    sys.exit(main())
