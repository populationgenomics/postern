"""Teardown invariants for the stream hatch: nothing outlives its connection.

Each of these is a regression test for a way a hostile guest could make the host
keep something — a subprocess, a slot, a thread, the ability to exit — after its
connection was over. They need no bubblewrap: the guest is only ever a socket
client, and the host side is where all of this happens.

The command under test deliberately leaves a background child holding its stdout.
Nothing exotic — a wrapper that starts a sidecar behaves this way — and the point
is that the hatch must cope with a command it did not write. Liveness of that
child is observed through a **heartbeat file** rather than its pid: when its
parent exits it is reparented to whatever is PID 1 (which, under
``tests/docker/run.sh``, is pytest itself, and does not reap), so a killed child
can linger as a zombie that ``kill(pid, 0)`` still calls alive. A stale heartbeat
is unambiguous. Every test asserts the child *appeared* before asserting it went
away, so none of them can pass by the command having failed to start.
"""

from __future__ import annotations

import contextlib
import pathlib
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator

import pytest

from postern.stream import Process, Stream, StreamHatch, splice_subprocess

_HEARTBEAT_STALE_AFTER = 3.0


def _command(heartbeat: pathlib.Path) -> list[str]:
    """``/bin/sh`` reading stdin to EOF, having left a child holding its stdout.

    POSIX shell only: ``exec -a`` is a bashism that dash — Debian's and Ubuntu's
    ``/bin/sh``, and so CI's — rejects outright, which would make every assertion
    below vacuously true.
    """
    return [
        '/bin/sh',
        '-c',
        f'while : ; do date +%s > {heartbeat} ; sleep 1 ; done &\nexec cat\n',
    ]


def _beating(heartbeat: pathlib.Path) -> bool:
    """Whether the background child is still running."""
    try:
        return time.time() - heartbeat.stat().st_mtime < _HEARTBEAT_STALE_AFTER
    except OSError:
        return False


def _wait_until(pred: Callable[[], bool], timeout: float = 25.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.2)
    return pred()


@pytest.fixture
def heartbeat(tmp_path: pathlib.Path) -> Iterator[pathlib.Path]:
    """A heartbeat path, asserted stale by the end of the test."""
    path = tmp_path / 'heartbeat'
    yield path
    assert _wait_until(lambda: not _beating(path)), 'a background child of the command outlived the test'


def test_teardown_reaches_the_whole_process_group(heartbeat: pathlib.Path) -> None:
    """A background child of the command must not survive the connection."""
    hatch = StreamHatch(splice_subprocess(_command(heartbeat)), name='g', max_conns=2, grace=1.0)
    hatch.start()
    try:
        conn = socket.socket(socket.AF_UNIX)
        conn.connect(hatch.socket_path)
        conn.sendall(b'req\n')
        assert _wait_until(lambda: _beating(heartbeat)), 'the command never started its background child'
        conn.shutdown(socket.SHUT_WR)  # the command exits on EOF; its child does not
        assert _wait_until(lambda: not _beating(heartbeat)), 'teardown reached the command but not its group'
        conn.close()
    finally:
        hatch.close()


def test_a_child_left_behind_does_not_hold_the_connection_open(heartbeat: pathlib.Path) -> None:
    """A child that inherited the guest's socket must not outlive the command.

    The hazard moved rather than went away when the host-side pump did. It used to
    be a *pipe*: a surviving child held the stdout pipe open, so the pump waited for
    an EOF that could never come and the slot never returned. Now the socket itself
    is the command's stdio, so a surviving child holds the *guest's connection*
    open — the guest never reads end-of-stream, and the run hangs until its timeout.
    Either way the fix is the same: teardown signals the process group.
    """
    hatch = StreamHatch(splice_subprocess(_command(heartbeat)), name='p', max_conns=1, grace=1.0)
    hatch.start()
    try:
        conn = socket.socket(socket.AF_UNIX)
        conn.settimeout(25.0)
        conn.connect(hatch.socket_path)
        conn.sendall(b'req\n')
        assert _wait_until(lambda: _beating(heartbeat)), 'the command never started its background child'
        conn.shutdown(socket.SHUT_WR)  # `cat` exits; the background child does not
        # The guest must reach end-of-stream, which needs every inherited copy of
        # this socket closed — the child's included.
        data = b''
        while chunk := conn.recv(65536):
            data += chunk
        assert data == b'req\n'
        conn.close()

        # And the slot must come back, so the next dial is served.
        probe = socket.socket(socket.AF_UNIX)
        probe.settimeout(25.0)
        probe.connect(hatch.socket_path)
        probe.sendall(b'ping\n')
        probe.shutdown(socket.SHUT_WR)
        assert probe.recv(64) == b'ping\n', 'the only slot was never returned'
        probe.close()
    finally:
        hatch.close()


def test_a_verdict_handed_to_a_closing_hatch_is_still_reaped() -> None:
    """A verdict the hatch cannot use must still be disposed of, not abandoned.

    With no splice function there is far less between the handler returning and the
    command being waited, but the window is not empty: a handler that returns while
    `close` is running has its verdict refused by the bookkeeping, and that path has
    to reap what it declines. ``max_conns`` bounds concurrent commands, not
    abandoned ones, so a guest reconnecting in a loop would otherwise grow the
    host's process table without bound.
    """
    started: list[Process] = []
    hatch = StreamHatch(splice_subprocess(['sh', '-c', 'exec sleep 30']), name='r', max_conns=4, grace=0.5)

    def handler(stream: Stream) -> Process:
        verdict = splice_subprocess(['sh', '-c', 'exec sleep 30'])(stream)
        assert isinstance(verdict, Process)
        started.append(verdict)
        hatch._closing = True
        return verdict

    hatch._handler = handler
    hatch.start()
    try:
        # One connection: setting _closing also retires the accept loop, which is
        # exactly the race being simulated, so a second dial would never land.
        conn = socket.socket(socket.AF_UNIX)
        conn.connect(hatch.socket_path)
        conn.close()
        assert _wait_until(lambda: bool(started) and started[0].proc is not None), 'the command never started'
        pid = started[0].proc.pid  # type: ignore[union-attr]
        assert _wait_until(lambda: not _alive(pid)), f'the closing path abandoned pid {pid}'
    finally:
        hatch.close()


def _alive(pid: int) -> bool:
    """Whether ``pid`` is a live (non-zombie) process."""
    stat = pathlib.Path(f'/proc/{pid}/stat')
    if pathlib.Path('/proc/self/stat').exists():
        try:
            return stat.read_text().rpartition(')')[2].split()[0] != 'Z'
        except OSError:
            return False
    out = subprocess.run(
        ['ps', '-o', 'state=', '-p', str(pid)], capture_output=True, text=True, check=False
    ).stdout.strip()
    return bool(out) and not out.startswith('Z')


def test_process_refuses_pipes() -> None:
    """The connection must be the command's stdio; a pipe would go unread."""
    proc = subprocess.Popen(
        [sys.executable, '-c', 'import time; time.sleep(300)'],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        with pytest.raises(ValueError, match=r'requires the connection as the command'):
            Process.from_popen(proc)
    finally:
        with contextlib.suppress(OSError, subprocess.TimeoutExpired):
            proc.kill()
            proc.wait(timeout=30)


def test_close_tears_down_an_in_flight_splice(heartbeat: pathlib.Path) -> None:
    """close() must release what is in flight, not merely stop accepting."""
    hatch = StreamHatch(splice_subprocess(_command(heartbeat)), name='c', max_conns=2, grace=1.0)
    hatch.start()
    conn = socket.socket(socket.AF_UNIX)
    conn.connect(hatch.socket_path)
    conn.sendall(b'req\n')
    assert _wait_until(lambda: _beating(heartbeat)), 'the command never started its background child'
    hatch.close()
    assert _wait_until(lambda: not _beating(heartbeat)), 'close() left a subprocess running'
    # On Linux, closing a listening socket does not wake a thread blocked in
    # accept(), so close() has to shut it down first or leak the accept thread for
    # the life of the process — one per closed hatch.
    assert _wait_until(lambda: not [t for t in threading.enumerate() if t.name.startswith('postern-stream')])
    conn.close()


def test_the_worker_process_can_still_exit(tmp_path: pathlib.Path) -> None:
    """A splice blocked on a stranded pipe must not wedge the whole worker.

    ``ThreadPoolExecutor`` workers have been non-daemon since 3.9 and
    ``shutdown(wait=False)`` does not interrupt one, so a pump this hatch cannot
    unblock is a pump that stops the interpreter from ever exiting.
    """
    src = str(pathlib.Path(__file__).resolve().parent.parent / 'src')
    argv = _command(tmp_path / 'heartbeat')
    script = (
        f'import sys; sys.path.insert(0, {src!r})\n'
        'import socket, time\n'
        'from postern.stream import StreamHatch, splice_subprocess\n'
        f'h = StreamHatch(splice_subprocess({argv!r}), name="x", grace=1.0)\n'
        'h.start()\n'
        'c = socket.socket(socket.AF_UNIX)\n'
        'c.connect(h.socket_path)\n'
        'c.sendall(b"req\\n")\n'
        'time.sleep(1.5)\n'
        'h.close()\n'
    )
    proc = subprocess.Popen([sys.executable, '-c', script])
    try:
        assert proc.wait(timeout=60) == 0, 'the worker did not exit cleanly'
    except subprocess.TimeoutExpired:
        proc.kill()
        pytest.fail('the host worker could not exit with a splice still in flight')
