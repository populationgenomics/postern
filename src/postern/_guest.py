"""In-sandbox supervisor for `Sandbox.run`, `run_python`, and `run_bash`.

Runs *inside* the bubblewrap sandbox, so it is stdlib-only. bwrap launches this
shim as the entrypoint for **every** run; the shim is the universal supervisor.
It applies the resource backstops (a fork-bomb / memory backstop set here rather
than via a fork-time callback in the host) and then execs the actual work —
whatever ``POSTERN_ARGV`` names: a re-exec of this interpreter to run
``POSTERN_CODE`` (``run_python``), or an arbitrary program such as ``bash``
(``run``/``run_bash``). Running the work in a forked child that *execs* is one
shape for all three: the child inherits the supervisor's setup (limits, and —
where wired — the hatch) and hands off to any program.

The guest reaches the hatch by dialing the bound Unix socket; that machinery
lives in the guest's own environment, not here. The socket path is exported as
``POSTERN_HATCH``.

bwrap launches this shim with ``--as-pid-1``, so it is PID 1 of the guest's PID
namespace: there is no separate bwrap process whose ``/proc/1`` the guest could
read (closing the PID-1 environ/cmdline/mem exposure — bwrap shares the guest
uid, so a same-uid guest could otherwise read and write it). As PID 1 the shim
owes the namespace a real init, so it forks the work and reaps it plus any
orphaned descendants that reparent here, and it marks *itself* non-dumpable so
even a co-uid process the guest spawns cannot read this init's ``/proc/1``.

A native (C/Rust) supervisor could replace this Python shim later — it would drop
the Python-in-rootfs requirement for non-Python work (``run``/``run_bash``) — but
the shim keeps the supervisor in the language postern already ships.
"""

import contextlib
import ctypes
import json
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


def _apply_rlimits() -> None:
    """Set the process-count and (optional) address-space backstops.

    Applied in the forked child *before* it execs the work, so an arbitrary
    program (bash, a compiled tool) inherits them across the exec — not just a
    Python guest that would otherwise set them itself.
    """
    nproc = int(os.environ.get('POSTERN_NPROC') or 0)
    if nproc:
        resource.setrlimit(resource.RLIMIT_NPROC, (nproc, nproc))
    # Address-space backstop: a partial guard against a memory bomb starving the
    # co-located trusted worker (F3). It is per-process, not a true total-memory
    # bound — a cgroup memory.max set by the worker/deploy is the real fix.
    as_bytes = int(os.environ.get('POSTERN_AS') or 0)
    if as_bytes:
        resource.setrlimit(resource.RLIMIT_AS, (as_bytes, as_bytes))


def _run_code() -> int:
    """Execute ``POSTERN_CODE`` in *this* process; return its exit status.

    Reached in the fresh process the supervisor re-execs for ``run_python`` (a
    clean interpreter, not the supervisor's), or as the defensive fallback when
    the shim is launched without ``--as-pid-1``. Mirrors ``sys.exit(main())``'s
    handling of the guest's own SystemExit / uncaught exception.
    """
    _apply_rlimits()  # idempotent; covers the no-fork fallback path
    code = os.environ.get('POSTERN_CODE', '')
    try:
        exec(code, {'__name__': '__main__'})  # noqa: S102 — executing guest code is the whole point
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)
    except BaseException:  # surface the guest traceback, then exit nonzero
        traceback.print_exc()
        return 1
    return 0


def _exec_work() -> None:
    """In the forked child: apply the limits, then exec the work. Never returns.

    ``POSTERN_ARGV`` names the work: ``[python, -u, _guest.py]`` re-execs this
    shim to run the code (``run_python``), or an arbitrary argv (``run``,
    ``run_bash``). Running as a normal (dumpable) child, it must not fall back
    into the parent's reaper, so every path ends in ``os._exit``.
    """
    _apply_rlimits()
    try:
        argv = json.loads(os.environ.get('POSTERN_ARGV') or '[]')
    except ValueError:
        argv = []
    if argv:
        try:
            # Replace this image with the work argv — no shell, by design.
            os.execvp(argv[0], argv)  # noqa: S606
        except OSError as exc:
            print(f'postern: cannot exec {argv[0]!r}: {exc}', file=sys.stderr)
            os._exit(127)
    os._exit(_run_code())  # no argv (defensive): run the code in this process


def _supervise() -> int:
    """Run as PID 1: fork the work, reap the namespace, return its status."""
    child = os.fork()
    if child == 0:
        _exec_work()  # never returns
    # Forward a graceful stop to the work — PID 1 gets no default signal action,
    # so without this a SIGTERM/SIGINT would be dropped rather than reaching it.
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda s, _frame, c=child: os.kill(c, s))
    # Reap until the work exits, absorbing any orphaned descendants reparented to
    # PID 1 along the way; leftover processes are SIGKILLed by the kernel when
    # PID 1 exits, so returning on the work's own exit is sufficient.
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
    # Not PID 1: we are the work process the supervisor re-exec'd for run_python
    # (or a defensive fallback launched without --as-pid-1). Run the code here.
    return _run_code()


if __name__ == '__main__':
    sys.exit(main())
