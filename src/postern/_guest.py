"""In-sandbox supervisor for `Sandbox.run`, `Sandbox.run_bash` and `Sandbox.run_python`.

Runs *inside* the bubblewrap sandbox, so it is stdlib-only. bwrap launches this
shim as the entrypoint for every run: it applies the resource backstops, forks,
and the child execs whatever ``POSTERN_ARGV`` names — a re-exec of the interpreter
to run ``POSTERN_CODE`` (`Sandbox.run_python`), or an arbitrary program
(`Sandbox.run`, `Sandbox.run_bash`). One fork+exec shape for all three, so a
non-Python entrypoint inherits the same limits across the exec that Python code
gets. Reaching a hatch is the guest's own business: the socket is a file at
``$POSTERN_HATCH``/``$POSTERN_HATCH_<NAME>``, dialled with whatever client library
the guest's environment carries.

bwrap launches this shim with ``--as-pid-1``, so it is PID 1 of the guest's PID
namespace and owes that namespace a real init: it forks the work and reaps it plus
any orphaned descendants that reparent here, and marks *itself* non-dumpable so a
co-uid process the guest spawns cannot read this init's ``/proc/1``.

The host↔shim contract is five environment variables: ``POSTERN_ARGV``,
``POSTERN_CODE``, ``POSTERN_RECODE``, ``POSTERN_NPROC`` and ``POSTERN_AS``. The
``POSTERN_HATCH``/``POSTERN_HATCH_<NAME>`` variables are set alongside them for the
*guest* to read, not for this module.

The supervisor being Python is what makes ``run``/``run_bash`` need an interpreter
in the sandbox even for a non-Python program.
"""

import contextlib
import ctypes
import json
import os
import resource
import signal
import sys
import traceback
from typing import NoReturn

_PR_SET_DUMPABLE = 4  # linux/prctl.h


def _set_nondumpable() -> None:
    """Clear PR_SET_DUMPABLE so this process's /proc/<pid> is root-owned.

    With the flag off the kernel roots ownership of ``/proc/self`` and gates
    ``ptrace_may_access`` on CAP_SYS_PTRACE, so no same-uid process the guest
    spawns can read this init's memory, environ or maps. Best-effort: ``--clearenv``
    already drops the worker's environment, and all ``--setenv`` puts back is the
    guest's own code and its hatch paths, so a failure here costs a layer of defense
    rather than a secret.
    """
    with contextlib.suppress(OSError):
        ctypes.CDLL(None, use_errno=True).prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0)


def _apply_rlimits(*, address_space: bool) -> None:
    """Set the process-count backstop, and optionally the address-space one.

    Applied in the forked child before it execs, so an arbitrary program inherits
    both across the exec rather than having to set them itself.

    Args:
        address_space: Whether to apply ``RLIMIT_AS`` here. False for the
            ``run_python`` re-exec, where :func:`_run_code` applies it once the
            fresh interpreter is up: a bare CPython's *virtual* size at startup can
            far exceed its resident use, so capping before ``execvp`` can abort the
            new interpreter's startup outright. An external program offers no such
            hook, so ``run``/``run_bash`` cap before the exec.
    """
    nproc = int(os.environ.get('POSTERN_NPROC') or 0)
    if nproc:
        resource.setrlimit(resource.RLIMIT_NPROC, (nproc, nproc))
    # Per-process, so this bounds one allocation spree rather than the guest's
    # total memory; a cgroup memory.max at the deploy layer is the real bound.
    as_bytes = int(os.environ.get('POSTERN_AS') or 0)
    if address_space and as_bytes:
        resource.setrlimit(resource.RLIMIT_AS, (as_bytes, as_bytes))


def _run_code() -> int:
    """Execute ``POSTERN_CODE`` in *this* process and return its exit status.

    Reached in the fresh interpreter the supervisor re-execs for ``run_python``,
    and when the shim is launched without ``--as-pid-1`` and so has no init role.
    Mirrors ``sys.exit(main())``'s handling of the guest's own ``SystemExit`` and
    of an uncaught exception.
    """
    _apply_rlimits(address_space=True)
    code = os.environ.get('POSTERN_CODE', '')
    try:
        exec(code, {'__name__': '__main__'})  # noqa: S102 — executing guest code is the whole point
    except SystemExit as exc:
        if isinstance(exc.code, int):
            return exc.code
        if exc.code is None:
            return 0
        print(exc.code, file=sys.stderr)  # CPython prints a non-int sys.exit() arg
        return 1
    except BaseException:
        traceback.print_exc()
        return 1
    return 0


def _exec_work() -> NoReturn:
    """In the forked child: apply the limits, then exec ``POSTERN_ARGV``.

    Every path out ends in ``os._exit``, including a ``setrlimit`` or JSON failure.
    Returning instead would drop this child into PID 1's reaper loop as a second
    supervisor, waiting on siblings it does not own.
    """
    try:
        _apply_rlimits(address_space=not os.environ.get('POSTERN_RECODE'))
        argv = json.loads(os.environ.get('POSTERN_ARGV') or '[]')
    except BaseException:
        traceback.print_exc()
        os._exit(1)
    if not argv:
        os._exit(_run_code())
    try:
        os.execvp(argv[0], argv)  # noqa: S606 — fixed argv from the host, no shell
    except OSError as exc:
        print(f'postern: cannot exec {argv[0]!r}: {exc}', file=sys.stderr)
        os._exit(127)


def _supervise() -> int:
    """Run as PID 1: fork the work, reap the namespace, return the work's status."""
    child = os.fork()
    if child == 0:
        _exec_work()

    # PID 1 gets no default signal action, so an unhandled SIGTERM/SIGINT would be
    # dropped rather than reaching the work. Suppress ProcessLookupError: a signal
    # arriving after the child is reaped must not raise out of the handler.
    def _forward(sig: int, _frame: object, target: int = child) -> None:
        with contextlib.suppress(ProcessLookupError):
            os.kill(target, sig)

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, _forward)
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
        return _supervise()
    # Launched without --as-pid-1, or the re-exec'd interpreter for run_python:
    # no init role to play, so run the code here.
    return _run_code()


if __name__ == '__main__':
    sys.exit(main())
