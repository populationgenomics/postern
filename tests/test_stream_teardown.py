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


def test_a_stranded_pipe_does_not_pin_the_slot(heartbeat: pathlib.Path) -> None:
    """The slot must come back even while something else still holds stdout.

    Before the group kill and the bounded forward pump, ``max_conns`` connections
    of this shape killed the hatch permanently: the slots were not returned even
    once the guest died, because the pump was waiting for an EOF on a pipe a
    surviving child held open.
    """
    hatch = StreamHatch(splice_subprocess(_command(heartbeat)), name='p', max_conns=1, grace=1.0)
    hatch.start()
    try:
        held = socket.socket(socket.AF_UNIX)
        held.connect(hatch.socket_path)
        held.sendall(b'req\n')
        assert _wait_until(lambda: _beating(heartbeat)), 'the command never started its background child'
        held.shutdown(socket.SHUT_WR)  # deliberately never read, never closed

        probe = socket.socket(socket.AF_UNIX)
        probe.settimeout(25.0)
        probe.connect(hatch.socket_path)
        probe.sendall(b'ping\n')
        assert probe.recv(64) == b'ping\n', 'the only slot was never returned'
        probe.close()
        held.close()
    finally:
        hatch.close()


def test_a_verdict_is_reaped_even_when_the_splice_raises() -> None:
    """An exception *after* the handler returned must not abandon its subprocess.

    ``max_conns`` bounds concurrent splices, not abandoned children, so a guest
    reconnecting in a loop grew the host's process table without bound. Closing
    stdout stands in for anything that can raise once the verdict is in hand.

    Observed through ``Popen.poll()`` rather than the heartbeat file the other
    tests use, because that is exact here and a heartbeat is not: these children
    are the worker's own, so ``poll()`` reaps them and cannot report a zombie as
    alive, and an *abandoned* child is precisely one whose ``poll()`` stays
    ``None`` for ever because nobody ever waits it. Asserting how many were
    created is what keeps the test from passing vacuously.

    (A handler that raises *before* returning still owns what it started: the
    hatch never saw the verdict and cannot dispose of it. That is the handler's
    obligation, and why the batteries do nothing between `Popen` and ``return``.)
    """
    created: list[subprocess.Popen[bytes]] = []

    def handler(_stream: Stream) -> Process:
        proc = subprocess.Popen(
            [sys.executable, '-c', 'import time; time.sleep(300)'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        created.append(proc)
        verdict = Process(proc)
        assert proc.stdout is not None
        proc.stdout.close()  # the splice will raise on fileno()
        return verdict

    hatch = StreamHatch(handler, name='raise', max_conns=2, grace=1.0)
    hatch.start()
    try:
        for _ in range(4):
            conn = socket.socket(socket.AF_UNIX)
            conn.connect(hatch.socket_path)
            conn.close()
        assert _wait_until(lambda: len(created) == 4), f'only {len(created)} subprocesses were started'
        assert _wait_until(lambda: all(p.poll() is not None for p in created)), (
            'a failing splice abandoned its subprocess'
        )
    finally:
        hatch.close()
        for proc in created:
            with contextlib.suppress(OSError, subprocess.TimeoutExpired):
                proc.kill()
                proc.wait(timeout=30)


def test_process_requires_both_pipes() -> None:
    """The `Popen` contract is enforced, not asserted downstream."""
    proc = subprocess.Popen(
        [sys.executable, '-c', 'import time; time.sleep(300)'],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        with pytest.raises(ValueError, match='stdin=PIPE and stdout=PIPE'):
            Process(proc)
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
