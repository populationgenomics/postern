"""A guest run in progress: its output as it arrives, and a way to stop it.

`Sandbox.start`, `Sandbox.start_bash` and `Sandbox.start_python` return a
`Process`; `run`, `run_bash` and `run_python` are those plus
:meth:`Process.communicate`, so there is one launch path.

**Streaming.** :meth:`Process.iter_output` yields ``(stream, bytes)`` chunks as the
guest writes them. Nothing on the way buffers: the guest init never touches the
command's stdio, so its writes land in the pipes this reads.

**Cancellation.** bwrap does not forward signals: SIGTERM to bwrap kills bwrap,
and ``--die-with-parent`` then SIGKILLs the guest with no chance to clean up. So
:meth:`Process.cancel` signals the guest's *init* directly. bwrap reports the
init's host pid on ``--info-fd``, and a pidfd is opened on it at start, so the
signal can only ever reach that process even after its pid is recycled. The init
forwards SIGTERM to the command (the C init to its whole process group); if the
command is still running when ``grace`` expires, bwrap is killed and the kernel
tears the namespace down.
"""

from __future__ import annotations

import contextlib
import json
import os
import selectors
import signal
import subprocess
import threading
import time
import typing

if typing.TYPE_CHECKING:
    from collections.abc import Iterator

    from typing_extensions import Self

    from postern._sandbox import ProcResult

# How long start() waits for bwrap to report the init's pid. bwrap writes it after
# building the namespaces, which takes milliseconds; a launch that fails before then
# closes the pipe, so this bounds only a bwrap that hangs.
_INFO_TIMEOUT_S = 30.0
_READ_SIZE = 65536

# Which of the guest's pipes a chunk of output came from.
Stream = typing.Literal['stdout', 'stderr']


def read_init_pid(info_fd: int, *, timeout: float = _INFO_TIMEOUT_S) -> int | None:
    """The guest init's host pid, from bwrap's ``--info-fd`` JSON, or None.

    Reads only until the JSON object is complete rather than to EOF: whether bwrap
    closes the descriptor after writing is not something to depend on.

    Args:
        info_fd: The read end of the pipe bwrap's ``--info-fd`` writes to.
        timeout: Seconds to wait for the report.

    Returns:
        The pid, or None if bwrap exited (or hung) before reporting one.
    """
    deadline = time.monotonic() + timeout
    buffer = b''
    with selectors.DefaultSelector() as selector:
        selector.register(info_fd, selectors.EVENT_READ)
        while (remaining := deadline - time.monotonic()) > 0:
            if not selector.select(remaining):
                continue
            chunk = os.read(info_fd, 4096)
            if not chunk:
                return None
            buffer += chunk
            try:
                report = json.loads(buffer)
            except ValueError:
                continue  # not complete yet
            pid = report.get('child-pid') if isinstance(report, dict) else None
            return pid if isinstance(pid, int) else None
    return None


def open_pidfd(pid: int | None, popen: subprocess.Popen[bytes]) -> int | None:
    """A pidfd on the init, so a later signal cannot reach a recycled pid.

    Opened while bwrap is still running: bwrap reaps the init only once it exits
    and then exits itself, so a live bwrap means the pid still names the init. One
    opened after bwrap has gone is discarded rather than trusted.
    """
    pidfd_open = getattr(os, 'pidfd_open', None)
    if pid is None or pidfd_open is None:
        return None
    try:
        pidfd = pidfd_open(pid)
    except OSError:
        return None  # already gone
    if popen.poll() is not None:
        os.close(pidfd)
        return None
    return pidfd


class Process:
    """A guest run in progress. Use as a context manager, or call :meth:`close`.

    It owns the run's hatches: they keep serving until the process is closed, which
    :meth:`communicate` does for you.
    """

    def __init__(self, popen: subprocess.Popen[bytes], *, pidfd: int | None, resources: contextlib.ExitStack) -> None:
        self._popen = popen
        self._pidfd = pidfd
        self._resources = resources
        self._lock = threading.Lock()
        self._escalation: threading.Timer | None = None
        self._cancelled = False
        self._open: dict[int, Stream] = {}
        pipes: tuple[tuple[Stream, typing.IO[bytes] | None], ...] = (('stdout', popen.stdout), ('stderr', popen.stderr))
        for name, pipe in pipes:
            if pipe is not None:
                os.set_blocking(pipe.fileno(), False)
                self._open[pipe.fileno()] = name

    @property
    def returncode(self) -> int | None:
        """The exit status once the run has ended, else None. Negative N means bwrap died of signal N."""
        return self._popen.poll()

    @property
    def cancelled(self) -> bool:
        """Whether :meth:`cancel` was called."""
        return self._cancelled

    def iter_output(self) -> Iterator[tuple[Stream, bytes]]:
        """Yield ``(stream, chunk)`` as the guest writes, until both pipes close.

        ``stream`` is ``'stdout'`` or ``'stderr'``: which of the guest's pipes the
        bytes came from, so a caller can keep them apart or interleave them in the
        order they arrived.

        Output consumed here is not returned again by :meth:`communicate`.
        """
        yield from self._pump(deadline=None)

    def _pump(self, *, deadline: float | None) -> Iterator[tuple[Stream, bytes]]:
        """Read whichever pipes are ready until both reach EOF, or raise at ``deadline``.

        Raises:
            subprocess.TimeoutExpired: If ``deadline`` passes with a pipe still open.
        """
        with selectors.DefaultSelector() as selector:
            for fd in self._open:
                selector.register(fd, selectors.EVENT_READ)
            while self._open:
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    raise subprocess.TimeoutExpired(self._popen.args, 0)
                for key, _ in selector.select(remaining):
                    fd = typing.cast('int', key.fd)
                    try:
                        chunk = os.read(fd, _READ_SIZE)
                    except BlockingIOError:
                        continue
                    if chunk:
                        yield self._open[fd], chunk
                    else:
                        selector.unregister(fd)
                        del self._open[fd]

    def cancel(self, *, grace: float = 5.0) -> None:
        """Ask the run to stop: SIGTERM now, and SIGKILL if it outlives ``grace`` seconds.

        Returns at once; keep reading output (or call :meth:`communicate`) to see
        what the command said on its way out. A no-op once the run has ended.

        Args:
            grace: Seconds to allow after SIGTERM before the sandbox is killed. 0
                kills it at once.
        """
        with self._lock:
            if self._popen.poll() is not None or self._cancelled:
                return
            self._cancelled = True
            if self._pidfd is None or grace <= 0:
                self._kill()
                return
            # Linux-only, as pidfds are; without one we never get here.
            send = typing.cast('typing.Callable[[int, int], None]', getattr(signal, 'pidfd_send_signal'))  # noqa: B009
            with contextlib.suppress(ProcessLookupError):
                send(self._pidfd, signal.SIGTERM)
            self._escalation = threading.Timer(grace, self._kill)
            self._escalation.daemon = True
            self._escalation.start()

    def _kill(self) -> None:
        # The init dies with bwrap (--die-with-parent), and the kernel then kills
        # everything left in the namespace.
        if self._popen.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                self._popen.kill()

    def wait(self, timeout: float | None = None) -> int:
        """Wait for the run to end and return its status.

        Raises:
            subprocess.TimeoutExpired: If it is still running after ``timeout``.
        """
        return self._popen.wait(timeout)

    def communicate(self, timeout: float | None = None) -> ProcResult:
        """Read the rest of the output, wait for the run to end, and close it.

        On ``timeout`` the sandbox is killed and the result is status 124 with
        ``[postern] timed out`` appended to stderr, as :meth:`Sandbox.run` reports
        it. Output is decoded as UTF-8, with undecodable bytes replaced.
        """
        from postern._sandbox import ProcResult  # noqa: PLC0415 — _sandbox imports this module

        out, err = bytearray(), bytearray()
        deadline = None if timeout is None else time.monotonic() + timeout
        timed_out = False
        try:
            for name, chunk in self._pump(deadline=deadline):
                (out if name == 'stdout' else err).extend(chunk)
            self._popen.wait(None if deadline is None else max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            timed_out = True
            self._kill()
            for name, chunk in self._pump(deadline=None):
                (out if name == 'stdout' else err).extend(chunk)
            self._popen.wait()
        finally:
            self.close()
        stdout, stderr = out.decode('utf-8', 'replace'), err.decode('utf-8', 'replace')
        if timed_out:
            return ProcResult(124, stdout, stderr + '\n[postern] timed out')
        return ProcResult(typing.cast('int', self._popen.returncode), stdout, stderr)

    def close(self) -> None:
        """Kill the run if it is still going, and release its pipes, pidfd and hatches."""
        self._kill()
        self._popen.wait()
        if self._escalation is not None:
            self._escalation.cancel()
        for pipe in (self._popen.stdout, self._popen.stderr):
            if pipe is not None:
                pipe.close()
        self._open.clear()
        if self._pidfd is not None:
            os.close(self._pidfd)
            self._pidfd = None
        self._resources.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
