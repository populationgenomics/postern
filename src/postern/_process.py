"""A guest run in progress: its output as it arrives, and a way to stop it.

`Sandbox.start`, `Sandbox.start_bash` and `Sandbox.start_python` return a
`Process`; `run`, `run_bash` and `run_python` are those plus
:meth:`Process.communicate`, so there is one launch path. The ``astart*`` variants
return an `AsyncProcess`, the same run for asyncio.

**Streaming.** :meth:`Process.output` yields ``(stream, bytes)`` chunks as the guest
writes them, ``stream`` being ``'stdout'`` or ``'stderr'``. Nothing on the way
buffers: the guest init never touches the command's stdio, so its writes land in
the pipes this reads. It is the *only* way to read output, deliberately: separate
stdout and stderr readers invite draining one while the other's pipe fills and
stalls the guest. A caller who wants one stream can write ``2>&1``.

**Stopping.** bwrap does not forward signals: SIGTERM to bwrap kills bwrap, and
``--die-with-parent`` then SIGKILLs the guest with no chance to clean up. So
:meth:`Process.terminate` signals the guest's *init* directly. bwrap reports the
init's host pid on ``--info-fd``, and a pidfd is opened on it at start, so the
signal can only ever reach that process even after its pid is recycled. The init
forwards SIGTERM to the command (the C init to its whole process group); if the
command is still running when ``grace`` expires, bwrap is killed and the kernel
tears the namespace down.
"""

from __future__ import annotations

import asyncio
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
    import collections.abc

    import typing_extensions

    import postern._sandbox

# How long start() waits for bwrap to report the init's pid. bwrap writes it after
# building the namespaces, which takes milliseconds; a launch that fails before then
# closes the pipe, so this bounds only a bwrap that hangs.
_INFO_TIMEOUT_S = 30.0
_READ_SIZE = 65536
# How long closing a still-running process allows it to stop on SIGTERM before it
# is killed: closing should be prompt, but an interrupted caller is no reason to
# deny the command its cleanup.
_CLOSE_GRACE_S = 1.0
# How long to drain remaining pipe output after kill() on timeout before abandoning.
_POST_KILL_DRAIN_S = 1.0

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
    :meth:`communicate` does for you. One thread reads it (:meth:`output`,
    :meth:`communicate`); :meth:`terminate` and :meth:`kill` are safe from any.
    """

    def __init__(self, popen: subprocess.Popen[bytes], *, pidfd: int | None, resources: contextlib.ExitStack) -> None:
        self._popen = popen
        self._pidfd = pidfd
        self._resources = resources
        self._lock = threading.RLock()
        self._escalation: threading.Timer | None = None
        self._terminated = False
        self._closed = False
        pidfd_open = getattr(os, 'pidfd_open', None)
        self._bwrap_pidfd: int | None = None
        if pidfd_open is not None:
            with contextlib.suppress(OSError):
                self._bwrap_pidfd = pidfd_open(popen.pid)
        self._open: dict[int, Stream] = {}
        pipes: tuple[tuple[Stream, typing.IO[bytes] | None], ...] = (('stdout', popen.stdout), ('stderr', popen.stderr))
        for name, pipe in pipes:
            if pipe is not None:
                os.set_blocking(pipe.fileno(), False)
                self._open[pipe.fileno()] = name

    @property
    def pid(self) -> int:
        """The host pid of the run's bwrap process."""
        return self._popen.pid

    @property
    def returncode(self) -> int | None:
        """The exit status once the run has ended, else None. Negative N means bwrap died of signal N."""
        return self._popen.poll()

    @property
    def terminated(self) -> bool:
        """Whether :meth:`terminate` or :meth:`kill` was called."""
        return self._terminated

    def output(self) -> collections.abc.Iterator[tuple[Stream, bytes]]:
        """Yield ``(stream, chunk)`` as the guest writes, until both pipes close.

        ``stream`` is ``'stdout'`` or ``'stderr'``, the pipe the bytes came from;
        chunks of one stream keep their order, and the two interleave in the order
        they were read. A chunk is whatever one read returned, so it can end
        mid-line or mid-character.

        The loop ends when both pipes close, which is normally when the run ends:
        the init's exit takes everything else in the namespace with it. A command
        that closes its own output ends the loop early, so :meth:`wait` for its
        status. Output read here is not returned again by :meth:`communicate`.
        """
        yield from self._pump(deadline=None)

    def _pump(self, *, deadline: float | None) -> collections.abc.Iterator[tuple[Stream, bytes]]:
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
                if selector.select(remaining):
                    for fd in list(self._open):
                        if fd not in self._open:
                            continue
                        yield from self._read(fd, selector)

    def _read(
        self, fd: int, selector: selectors.BaseSelector | None = None
    ) -> collections.abc.Iterator[tuple[Stream, bytes]]:
        """One non-blocking read of ``fd``: its chunk, or nothing, closing it at EOF."""
        try:
            chunk = os.read(fd, _READ_SIZE)
        except BlockingIOError:
            return
        if chunk:
            yield self._open[fd], chunk
            return
        if selector is not None:
            selector.unregister(fd)
        del self._open[fd]

    def terminate(self, *, grace: float = 5.0) -> None:
        """Ask the run to stop: SIGTERM now, and SIGKILL if it outlives ``grace`` seconds.

        Returns at once; keep reading :meth:`output` (or call :meth:`communicate`)
        to see what the command says on its way out. A no-op once the run has ended
        or been stopped.

        Args:
            grace: Seconds to allow after SIGTERM before the sandbox is killed. 0
                kills it at once.
        """
        with self._lock:
            if self._closed or self._popen.poll() is not None or self._terminated:
                return
            self._terminated = True
            if self._pidfd is None or grace <= 0:
                self._kill()
                return
            # Linux-only, as pidfds are; without one we never get here.
            send = typing.cast(
                'typing.Callable[[int, int], None] | None',
                getattr(signal, 'pidfd_send_signal', None),
            )
            if send is not None:
                with contextlib.suppress(ProcessLookupError):
                    send(self._pidfd, signal.SIGTERM)
            self._escalation = threading.Timer(grace, self._kill)
            self._escalation.daemon = True
            self._escalation.start()

    def kill(self) -> None:
        """Kill the run now, without letting the command clean up."""
        with self._lock:
            self._terminated = True
            self._kill()

    def _kill(self) -> None:
        with self._lock:
            if self._closed:
                return
            send = typing.cast(
                'typing.Callable[[int, int], None] | None',
                getattr(signal, 'pidfd_send_signal', None),
            )
            # SIGKILL the init via its pidfd first. bwrap's --die-with-parent only kills
            # the guest if PR_SET_PDEATHSIG was set before bwrap died. Signalling the init
            # from an ancestor namespace guarantees the init and the entire namespace die.
            if self._pidfd is not None and send is not None:
                with contextlib.suppress(ProcessLookupError):
                    send(self._pidfd, signal.SIGKILL)
            if self._bwrap_pidfd is not None and send is not None:
                with contextlib.suppress(ProcessLookupError):
                    send(self._bwrap_pidfd, signal.SIGKILL)
            elif self._popen.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    self._popen.kill()

    def wait(self, timeout: float | None = None) -> int:
        """Wait for the run to end and return its status.

        Raises:
            subprocess.TimeoutExpired: If it is still running after ``timeout``.
        """
        return self._popen.wait(timeout)

    def communicate(
        self, timeout: float | None = None, *, max_output: int | None = None
    ) -> postern._sandbox.ProcResult:
        """Read the rest of the output, wait for the run to end, and close it.

        On ``timeout`` the sandbox is killed and the result is status 124 with
        ``[postern] timed out`` appended to stderr, as :meth:`Sandbox.run` reports
        it. Output is decoded as UTF-8, with undecodable bytes replaced. If
        ``max_output`` is set, buffered output is capped at that byte count,
        further output discarded, and ``result.truncated`` set.
        """
        out, err = bytearray(), bytearray()
        deadline = None if timeout is None else time.monotonic() + timeout
        timed_out = False
        truncated = False

        def _append(target: bytearray, chunk: bytes) -> None:
            nonlocal truncated
            if max_output is None:
                target.extend(chunk)
                return
            remaining = max_output - (len(out) + len(err))
            if remaining <= 0:
                truncated = True
                return
            if len(chunk) > remaining:
                truncated = True
                target.extend(chunk[:remaining])
            else:
                target.extend(chunk)

        try:
            for name, chunk in self._pump(deadline=deadline):
                _append(out if name == 'stdout' else err, chunk)
            self._popen.wait(None if deadline is None else max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            timed_out = True
            self.kill()
            drain_deadline = time.monotonic() + _POST_KILL_DRAIN_S
            try:
                for name, chunk in self._pump(deadline=drain_deadline):
                    _append(out if name == 'stdout' else err, chunk)
                self._popen.wait(timeout=max(0.0, drain_deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                pass
        finally:
            self.close()
        return _result(self._popen.returncode, out, err, timed_out=timed_out, truncated=truncated)

    def close(self) -> None:
        """Stop the run if it is still going, and release its pipes, pidfd and hatches.

        A run still going is stopped gracefully: SIGTERM, and a kill if it outlives
        a short grace. Its remaining output is discarded meanwhile, so a command
        printing on its way out cannot stall on a full pipe.
        """
        with self._lock:
            if self._closed:
                return
        try:
            if self._popen.poll() is None:
                self.terminate(grace=_CLOSE_GRACE_S)
                try:
                    for _ in self._pump(deadline=time.monotonic() + _CLOSE_GRACE_S + 1):
                        pass
                    self._popen.wait(_CLOSE_GRACE_S + 1)
                except subprocess.TimeoutExpired:
                    self.kill()
            self._popen.wait()
        finally:
            self._release()

    def _release(self) -> None:
        with self._lock:
            self._closed = True
            if self._escalation is not None:
                self._escalation.cancel()
            for pipe in (self._popen.stdout, self._popen.stderr):
                if pipe is not None:
                    pipe.close()
            self._open.clear()
            send = typing.cast(
                'typing.Callable[[int, int], None] | None',
                getattr(signal, 'pidfd_send_signal', None),
            )
            if self._pidfd is not None:
                if send is not None:
                    with contextlib.suppress(OSError):
                        send(self._pidfd, signal.SIGKILL)
                os.close(self._pidfd)
                self._pidfd = None
            if self._bwrap_pidfd is not None:
                if send is not None:
                    with contextlib.suppress(OSError):
                        send(self._bwrap_pidfd, signal.SIGKILL)
                os.close(self._bwrap_pidfd)
                self._bwrap_pidfd = None
            self._resources.close()

    def __enter__(self) -> typing_extensions.Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


class AsyncProcess:
    """The same run as a :class:`Process`, for asyncio: awaited rather than blocked on.

    Use with ``async with``. Output comes from :meth:`output`, an async iterator of
    ``(stream, bytes)``; the run's end from :meth:`wait`, which watches a pidfd on
    bwrap rather than tying up a thread. Cancelling the task that is using it stops
    the run gracefully as the ``async with`` block unwinds.
    """

    def __init__(self, process: Process) -> None:
        self._process = process
        pidfd_open = getattr(os, 'pidfd_open', None)
        self._exit_fd: int | None = None
        if pidfd_open is not None:
            with contextlib.suppress(OSError):
                # bwrap is our own unreaped child, so its pid cannot be recycled yet.
                self._exit_fd = pidfd_open(process.pid)

    @property
    def pid(self) -> int:
        """The host pid of the run's bwrap process."""
        return self._process.pid

    @property
    def returncode(self) -> int | None:
        """The exit status once the run has ended, else None. Negative N means bwrap died of signal N."""
        return self._process.returncode

    @property
    def terminated(self) -> bool:
        """Whether :meth:`terminate` or :meth:`kill` was called."""
        return self._process.terminated

    def terminate(self, *, grace: float = 5.0) -> None:
        """As :meth:`Process.terminate`: SIGTERM now, SIGKILL after ``grace``. Does not block."""
        self._process.terminate(grace=grace)

    def kill(self) -> None:
        """Kill the run now, without letting the command clean up."""
        self._process.kill()

    async def output(self) -> collections.abc.AsyncIterator[tuple[Stream, bytes]]:
        """Yield ``(stream, chunk)`` as the guest writes, until both pipes close. See :meth:`Process.output`."""
        loop = asyncio.get_running_loop()
        process = self._process
        while process._open:  # noqa: SLF001 — the two faces of one run
            fds = list(process._open)  # noqa: SLF001
            ready = loop.create_future()
            for fd in fds:
                loop.add_reader(fd, _settle, ready)
            try:
                await ready
            finally:
                for fd in fds:
                    loop.remove_reader(fd)
            for fd in fds:
                if fd in process._open:  # noqa: SLF001
                    for item in process._read(fd):  # noqa: SLF001
                        yield item

    async def wait(self) -> int:
        """Wait for the run to end and return its status."""
        if self._process.returncode is None:
            if self._exit_fd is None:
                return await asyncio.to_thread(self._process.wait)
            loop = asyncio.get_running_loop()
            exited = loop.create_future()
            loop.add_reader(self._exit_fd, _settle, exited)
            try:
                if self._process.returncode is None:
                    await exited
            finally:
                loop.remove_reader(self._exit_fd)
        return self._process.wait()

    async def communicate(
        self, timeout: float | None = None, *, max_output: int | None = None
    ) -> postern._sandbox.ProcResult:
        """Read the rest of the output, wait for the run to end, and close it. See :meth:`Process.communicate`."""
        out, err = bytearray(), bytearray()
        truncated = False

        def _append(target: bytearray, chunk: bytes) -> None:
            nonlocal truncated
            if max_output is None:
                target.extend(chunk)
                return
            remaining = max_output - (len(out) + len(err))
            if remaining <= 0:
                truncated = True
                return
            if len(chunk) > remaining:
                truncated = True
                target.extend(chunk[:remaining])
            else:
                target.extend(chunk)

        async def collect() -> None:
            async for name, chunk in self.output():
                _append(out if name == 'stdout' else err, chunk)
            await self.wait()

        timed_out = False
        try:
            await asyncio.wait_for(collect(), timeout)
        except asyncio.TimeoutError:
            timed_out = True
            self.kill()
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(collect(), _POST_KILL_DRAIN_S)
        finally:
            await self.aclose()
        return _result(self._process.returncode, out, err, timed_out=timed_out, truncated=truncated)

    async def aclose(self) -> None:
        """Stop the run if it is still going, and release it. See :meth:`Process.close`."""
        try:
            if self._process.returncode is None:
                self.terminate(grace=_CLOSE_GRACE_S)

                async def drain() -> None:
                    async for _ in self.output():
                        pass
                    await self.wait()

                try:
                    await asyncio.wait_for(drain(), _CLOSE_GRACE_S + 1)
                except asyncio.TimeoutError:
                    self.kill()
                    await self.wait()
        finally:
            if self._exit_fd is not None:
                os.close(self._exit_fd)
                self._exit_fd = None
            if self._process.returncode is None:
                self._process.kill()
            await asyncio.shield(asyncio.to_thread(self._process.close))

    async def __aenter__(self) -> typing_extensions.Self:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()


def _settle(future: asyncio.Future[None]) -> None:
    if not future.done():
        future.set_result(None)


def _result(
    returncode: int | None,
    out: bytes | bytearray,
    err: bytes | bytearray,
    *,
    timed_out: bool,
    truncated: bool = False,
) -> postern._sandbox.ProcResult:
    from postern import _sandbox  # noqa: PLC0415 — _sandbox imports this module

    stdout, stderr = bytes(out).decode('utf-8', 'replace'), bytes(err).decode('utf-8', 'replace')
    if truncated:
        stderr = (stderr + '\n' if stderr else '') + '[postern] output truncated'
    if timed_out:
        stderr = (stderr + '\n' if stderr else '\n') + '[postern] timed out'
        return _sandbox.ProcResult(124, stdout, stderr, timed_out=True, truncated=truncated)
    return _sandbox.ProcResult(typing.cast('int', returncode), stdout, stderr, timed_out=False, truncated=truncated)
