"""Exit observation that must not reap, and teardown that must not stop at the leader."""

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

    A group member that ignores ``SIGTERM`` — a sidecar with a handler — survives a
    leader that dies well inside ``grace``, and it holds a dup of the guest's socket
    in its own session.
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

    Without this the test above passes whenever the shell fails to fork the subshell
    or ``trap`` fails to take.
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

    So a `Popen` something else has already waited (``close()`` racing this
    connection, or a handler adopting a finished process) must not be registered by
    raw pid: once that pid is recycled the wait succeeds against a stranger and
    blocks for *its* lifetime.
    """
    finished = subprocess.Popen(['/bin/sh', '-c', 'exit 0'], start_new_session=True)
    finished.wait()
    stranger = subprocess.Popen(['/bin/sleep', '5'], start_new_session=True)
    finished.pid = stranger.pid  # what a recycled pid looks like from here
    verdict = Process()
    verdict._proc = finished
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


# --------------------------------------------------------------------------- #
# from_popen drops the declarative path's defaults; the disclosure is detected  #
# --------------------------------------------------------------------------- #
@pytest.mark.skipif(not pathlib.Path('/proc/self/fd').exists(), reason='the fd-2 check needs /proc')
def test_an_adopted_popen_with_stderr_merged_into_the_guest_socket_is_refused() -> None:
    """stdout *is* the guest's socket, so ``stderr=STDOUT`` hands it host state.

    `_check_stderr` refuses this at construction, but only for a verdict that
    declares its command: ``subprocess`` keeps no record of the ``stderr`` argument
    it was given, so ``proc.stderr`` is ``None`` whether it was ``DEVNULL`` or
    ``STDOUT`` and `from_popen`'s pipe check cannot see the difference.
    """
    leak = 'HOST /srv/secrets/customer-a/repo.git'
    verdicts: list[Process] = []

    def handler(stream) -> Process:
        proc = subprocess.Popen(
            [sys.executable, '-c', f'import sys; sys.stderr.write({leak!r})'],
            stdin=stream.conn.fileno(),
            stdout=stream.conn.fileno(),
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        verdict = Process.from_popen(proc)
        verdicts.append(verdict)
        return verdict

    hatch = StreamHatch(handler, name='fd2', grace=1.0)
    hatch.start()
    try:
        conn = socket.socket(socket.AF_UNIX)
        conn.settimeout(_DEADLINE)
        conn.connect(hatch.socket_path)
        conn.shutdown(socket.SHUT_WR)
        got = b''
        with contextlib.suppress(OSError):
            while chunk := conn.recv(65536):
                got += chunk
        conn.close()
    finally:
        hatch.close()
    assert leak.encode() not in got, 'the guest received the command diagnostics through fd 2'
    assert verdicts, 'the handler never ran'
    assert verdicts[0].proc is not None
    assert verdicts[0].proc.returncode is not None, 'the refused verdict was abandoned unreaped'


def test_a_process_with_no_argv_still_checks_stderr() -> None:
    """``__post_init__`` checks stderr before the argv-None return, not after."""
    with pytest.raises(ValueError, match=r'stderr=subprocess\.STDOUT is not supported'):
        Process(stderr=subprocess.STDOUT)
    with pytest.raises(ValueError, match=r'stderr=subprocess\.PIPE is not supported'):
        Process(stderr=subprocess.PIPE)


# --------------------------------------------------------------------------- #
# A verdict describes one connection                                           #
# --------------------------------------------------------------------------- #
def test_a_reused_verdict_is_refused_without_disturbing_the_first_connection() -> None:
    """A cached verdict must be refused, and connection 1 must not notice.

    ``Process(argv)`` looks like an immutable description, so a handler that returns
    a module-level constant is the obvious mistake. Unrefused, the second connection
    is attached to no command at all and its pool worker parks on the *first*
    connection's command.
    """
    shared = Process(['cat'])
    hatch = StreamHatch(lambda _stream: shared, name='once', max_conns=4, grace=0.5)
    hatch.start()
    try:
        first = socket.socket(socket.AF_UNIX)
        first.settimeout(_DEADLINE)
        first.connect(hatch.socket_path)
        first.sendall(b'mine')
        assert first.recv(16) == b'mine'

        second = socket.socket(socket.AF_UNIX)
        second.settimeout(_DEADLINE)
        second.connect(hatch.socket_path)
        # The refusal a raw stream can express: end-of-stream, promptly.
        assert second.recv(16) == b'', 'the reused verdict was accepted for a second connection'
        second.close()

        # And the first connection is untouched: still spliced, still alive.
        first.sendall(b'still')
        assert first.recv(16) == b'still', "the second connection's refusal disturbed the first"
        assert shared.proc is not None
        assert shared.proc.returncode is None, "the second connection tore down the first's command"
        first.close()
    finally:
        hatch.close()


def test_proc_cannot_be_assigned_to_reach_the_adopted_path() -> None:
    """``v = Process(); v.proc = popen`` must not reach the adopted path.

    That route skips every check in ``from_popen`` and would be accepted holding
    pipes nothing pumps. ``proc`` is read-only, so the bypass does not typecheck;
    assigning the private field behind it still reaches the hatch, which refuses a
    command it was not asked to adopt.
    """
    proc = subprocess.Popen(
        [sys.executable, '-c', 'import time; time.sleep(300)'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        verdict = Process()
        with pytest.raises(AttributeError):
            verdict.proc = proc  # type: ignore[misc]
        verdict._proc = proc  # the private field is not an API, but the hatch still checks
        left, right = socket.socketpair()
        try:
            with pytest.raises(ValueError, match=r'did not come from Process\.from_popen'):
                verdict._attach(right, 0.5)
        finally:
            left.close()
            right.close()
    finally:
        with contextlib.suppress(OSError, subprocess.TimeoutExpired):
            proc.kill()
            proc.wait(timeout=30)


# --------------------------------------------------------------------------- #
# The refusal drain: fast when nothing is queued, still orderly when it is      #
# --------------------------------------------------------------------------- #
def test_a_refusal_does_not_cost_the_whole_grace() -> None:
    """A guest that connects and says nothing must not hold a slot for ``grace``.

    Waiting the full ``grace`` for a *first* byte the guest never sends is a slot it
    takes with nothing but ``connect()``, renewably.
    """
    hatch = StreamHatch(lambda _stream: None, name='fast', max_conns=1, grace=5.0)
    hatch.start()
    try:
        start = time.monotonic()
        for _ in range(2):
            conn = socket.socket(socket.AF_UNIX)
            conn.settimeout(_DEADLINE)
            conn.connect(hatch.socket_path)
            assert conn.recv(16) == b''  # the refusal
            conn.close()
        elapsed = time.monotonic() - start
    finally:
        hatch.close()
    assert elapsed < 2.0, f'two refusals at grace=5.0 took {elapsed:.1f}s'


def test_a_refusal_still_drains_queued_bytes_so_the_guest_reads_eof() -> None:
    """The hard requirement the fast path must not regress.

    Closing an ``AF_UNIX`` socket with bytes unread in its receive queue resets the
    *peer* (``unix_release_sock``), and a client such as git reads a reset as a
    protocol error rather than as "the exchange is over". So a refusal has to consume
    what the guest already sent.
    """
    hatch = StreamHatch(lambda _stream: None, name='orderly', max_conns=1, grace=5.0)
    hatch.start()
    try:
        conn = socket.socket(socket.AF_UNIX)
        conn.settimeout(_DEADLINE)
        conn.connect(hatch.socket_path)
        conn.sendall(b'q' * 8192)  # queued, and nothing on the host will ever read it
        assert conn.recv(16) == b'', 'a refusal with bytes queued did not end in end-of-stream'
        conn.close()
    finally:
        hatch.close()


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='unix_release_sock resets the peer on Linux')
def test_the_drain_is_what_prevents_that_reset(monkeypatch: pytest.MonkeyPatch) -> None:
    """Neuter the drain and the guest above must read a reset instead of EOF.

    Linux-gated because the reset is ``unix_release_sock``'s doing: on darwin the
    same unread queue at last close gives the peer a plain end-of-stream.
    """
    monkeypatch.setattr(stream_module, '_drain', lambda *_args: None)
    hatch = StreamHatch(lambda _stream: None, name='reset', max_conns=1, grace=5.0)
    hatch.start()
    try:
        conn = socket.socket(socket.AF_UNIX)
        conn.settimeout(_DEADLINE)
        conn.connect(hatch.socket_path)
        conn.sendall(b'q' * 8192)
        with pytest.raises(ConnectionResetError):
            conn.recv(65536)
        conn.close()
    finally:
        hatch.close()
