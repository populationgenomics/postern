"""Regressions from the third review of the stream hatch.

Both of these are about the same thing from two directions: exit observation that
must not reap, and teardown that must not stop at the leader.
"""

from __future__ import annotations

import contextlib
import os
import pathlib
import socket
import subprocess
import sys
import time

import pytest

import postern.stream as stream_module
from postern.stream import Process, StreamHatch, splice_subprocess

_DEADLINE = 25.0


def _wait_until(pred, timeout: float = 20.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.1)
    return pred()


def _beating(path: pathlib.Path, stale_after: float = 2.5) -> bool:
    try:
        return time.time() - path.stat().st_mtime < stale_after
    except OSError:
        return False


def test_a_term_ignoring_group_member_does_not_survive_teardown(tmp_path: pathlib.Path) -> None:
    """Escalation is keyed on the group, not on the leader's exit.

    The leader dies well inside ``grace``, so the old code reaped it and never sent
    the group ``SIGKILL`` — and the member that ignored ``SIGTERM`` went on holding a
    dup of the guest's socket in its own session, outliving the hatch and this
    process. Nothing exotic: a sidecar with a ``SIGTERM`` handler behaves this way.
    """
    heartbeat = tmp_path / 'heartbeat'
    argv = [
        '/bin/sh',
        '-c',
        f'(trap "" TERM; while : ; do date +%s > {heartbeat} ; sleep 0.5 ; done) &\nexec cat\n',
    ]
    hatch = StreamHatch(splice_subprocess(argv), name='esc', max_conns=2, grace=1.0)
    hatch.start()
    conn = socket.socket(socket.AF_UNIX)
    conn.settimeout(_DEADLINE)
    try:
        conn.connect(hatch.socket_path)
        conn.sendall(b'req\n')
        assert conn.recv(64) == b'req\n'
        assert _wait_until(lambda: _beating(heartbeat)), 'the command never started its background child'
        # close() is the path that signals a *live* command, so it is the path where
        # the leader can die inside grace and take the escalation with it.
        hatch.close()
        assert _wait_until(lambda: not _beating(heartbeat)), (
            'a SIGTERM-ignoring member of the command group outlived teardown'
        )
    finally:
        conn.close()
        hatch.close()


def test_the_escalation_test_is_not_vacuous(tmp_path: pathlib.Path) -> None:
    """The command really does leave a member that ignores SIGTERM.

    Without this the test above passes whenever the shell fails to fork the
    subshell, or ``trap`` fails to take, which is the shape of every vacuous test
    this branch has produced.
    """
    heartbeat = tmp_path / 'heartbeat'
    proc = subprocess.Popen(
        [
            '/bin/sh',
            '-c',
            f'(trap "" TERM; while : ; do date +%s > {heartbeat} ; sleep 0.5 ; done) &\nexec cat\n',
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        assert _wait_until(lambda: _beating(heartbeat)), 'the background child never started'
        os.killpg(proc.pid, 15)
        proc.wait(timeout=10)
        time.sleep(1.0)
        assert _beating(heartbeat), 'the background child died on SIGTERM, so the escalation test proves nothing'
    finally:
        with contextlib.suppress(OSError):
            os.killpg(proc.pid, 9)
        with contextlib.suppress(Exception):
            proc.wait(timeout=10)
        assert _wait_until(lambda: not _beating(heartbeat)), 'SIGKILL did not reach the group'


@pytest.mark.skipif(hasattr(os, 'waitid'), reason='the kqueue tier is only reached without os.waitid')
def test_await_command_never_waits_on_a_pid_that_is_no_longer_ours() -> None:
    """``EVFILT_PROC`` registers happily against a recycled pid.

    ``_kq_exited`` documents its precondition — our own child, still unreaped — and
    ``_exited`` enforces it with a ``returncode`` check. ``_await_command`` did not,
    so a `Popen` that something else had already waited (``close()`` racing this
    connection, or a handler adopting a finished process) was registered by raw pid:
    once that pid is recycled the wait succeeds against a stranger and blocks for
    *its* lifetime.
    """
    finished = subprocess.Popen(['/bin/sh', '-c', 'exit 0'], start_new_session=True)
    finished.wait()
    stranger = subprocess.Popen(['/bin/sleep', '5'], start_new_session=True)
    finished.pid = stranger.pid  # what a recycled pid looks like from here
    verdict = Process()
    verdict.proc = finished
    try:
        start = time.monotonic()
        stream_module._await_command(verdict)
        waited = time.monotonic() - start
    finally:
        stranger.kill()
        stranger.wait()
    assert waited < 1.0, f'_await_command waited {waited:.1f}s on a process that is not our child'


def test_grace_still_bounds_the_wait_for_a_command_that_ignores_sigterm() -> None:
    """The non-reaping wait must still be bounded, and must still reap at the end."""
    verdict = Process(
        [sys.executable, '-c', 'import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(300)']
    )
    left, right = socket.socketpair()
    try:
        verdict._attach(right, 0.5)
        start = time.monotonic()
        verdict.dispose(0.5)
        elapsed = time.monotonic() - start
    finally:
        left.close()
        right.close()
    assert verdict.proc is not None
    assert verdict.proc.returncode is not None, 'the command was left unreaped'
    assert elapsed < 10.0, f'teardown took {elapsed:.1f}s for a grace of 0.5'
