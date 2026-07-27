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


def _apply_rlimits(*, address_space: bool = True) -> None:
    """Set the process-count and (optional) address-space backstops.

    Applied in the forked child *before* it execs the work, so an arbitrary
    program (bash, a compiled tool) inherits them across the exec — not just a
    Python guest that would otherwise set them itself.

    ``address_space`` gates the ``RLIMIT_AS`` backstop. It is deferred for the
    ``run_python`` re-exec (applied later in :func:`_run_code`, once the fresh
    interpreter is up) because a bare CPython's *virtual* size at startup can far
    exceed its resident use — applying the cap before ``execvp``-ing a new
    interpreter can abort its startup outright. An external program has no such
    hook, so ``run``/``run_bash`` apply it before the exec.
    """
    nproc = int(os.environ.get('POSTERN_NPROC') or 0)
    if nproc:
        resource.setrlimit(resource.RLIMIT_NPROC, (nproc, nproc))
    # Address-space backstop: a partial guard against a memory bomb starving the
    # co-located trusted worker (F3). It is per-process, not a true total-memory
    # bound — a cgroup memory.max set by the worker/deploy is the real fix.
    as_bytes = int(os.environ.get('POSTERN_AS') or 0)
    if address_space and as_bytes:
        resource.setrlimit(resource.RLIMIT_AS, (as_bytes, as_bytes))


def _run_code() -> int:
    """Execute ``POSTERN_CODE`` in *this* process; return its exit status.

    Reached in the fresh process the supervisor re-execs for ``run_python`` (a
    clean interpreter, not the supervisor's), or as the defensive fallback when
    the shim is launched without ``--as-pid-1``. Mirrors ``sys.exit(main())``'s
    handling of the guest's own SystemExit / uncaught exception.
    """
    _apply_rlimits(address_space=True)  # AS applied here, post-startup (see _apply_rlimits)
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
    except BaseException:  # surface the guest traceback, then exit nonzero
        traceback.print_exc()
        return 1
    return 0


def _exec_work() -> None:
    """In the forked child: apply the limits, then exec the work. Never returns.

    ``POSTERN_ARGV`` names the work: ``[python, -u, _guest.py]`` re-execs this
    shim to run the code (``run_python``), or an arbitrary argv (``run``,
    ``run_bash``). Running as a normal (dumpable) child, it must not fall back
    into the parent's reaper, so **every** path ends in ``os._exit`` — including
    an unexpected failure (e.g. ``setrlimit`` EPERM), which must exit here rather
    than escape into the parent's PID-1 reaper loop.
    """
    try:
        # AS is deferred to _run_code for the run_python re-exec (POSTERN_RECODE),
        # so the fresh interpreter isn't capped before it finishes starting up.
        _apply_rlimits(address_space=not os.environ.get('POSTERN_RECODE'))
        argv = json.loads(os.environ.get('POSTERN_ARGV') or '[]')
    except BaseException:  # a setrlimit/parse failure must exit, not reach the reaper
        traceback.print_exc()
        os._exit(1)
    if not argv:
        os._exit(_run_code())  # no argv (defensive): run the code in this process
    try:
        # Replace this image with the work argv — no shell, by design.
        os.execvp(argv[0], argv)  # noqa: S606
    except OSError as exc:
        print(f'postern: cannot exec {argv[0]!r}: {exc}', file=sys.stderr)
        os._exit(127)


def _supervise() -> int:
    """Run as PID 1: fork the work, reap the namespace, return its status."""
    child = os.fork()
    if child == 0:
        _exec_work()  # never returns
        os._exit(1)  # belt-and-braces: the child must never fall through

    # Forward a graceful stop to the work — PID 1 gets no default signal action,
    # so without this a SIGTERM/SIGINT would be dropped rather than reaching it.
    # Suppress ProcessLookupError: a signal arriving after the child is reaped
    # must not raise out of the handler during teardown.
    def _forward(_sig: int, _frame: object, _child: int = child) -> None:
        with contextlib.suppress(ProcessLookupError):
            os.kill(_child, _sig)

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, _forward)
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
