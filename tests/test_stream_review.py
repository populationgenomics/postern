"""Regressions from the review of the stream hatch.

Each test here failed on the reviewed revision and passes now; they are grouped by
the cause rather than by the symptom that found them.
"""

from __future__ import annotations

import contextlib
import errno
import os
import pathlib
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

from postern import Sandbox, SandboxProfile
from postern._sandbox import GUEST_CONNECT
from postern.stream import (
    _REVERSE_THREAD,
    Process,
    Stream,
    StreamHatch,
    git_url,
    splice_subprocess,
    splice_tcp,
)

_MIB = 1 << 20


def _wait_until(pred, timeout: float = 20.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.05)
    return pred()


@contextlib.contextmanager
def _serving(hatch: StreamHatch):
    hatch.start()
    try:
        yield hatch
    finally:
        hatch.close()


def _is_zombie(pid: int) -> bool:
    """Whether ``pid`` is an unreaped zombie — without reaping it.

    Deliberately avoids ``Popen.poll()``/``wait()``: those *are* the reap, so a
    test that calls them cannot observe the leak it is looking for. (That is why
    the reviewed revision's own ``test_process_requires_both_pipes`` missed this.)
    """
    if pathlib.Path('/proc/self/stat').exists():  # Linux: absent pid == fully gone
        try:
            return pathlib.Path(f'/proc/{pid}/stat').read_text().rpartition(')')[2].split()[0] == 'Z'
        except (OSError, IndexError):
            return False
    out = subprocess.run(
        ['ps', '-o', 'state=', '-p', str(pid)], capture_output=True, text=True, check=False
    ).stdout.strip()
    return out.startswith('Z')


def _dial(hatch: StreamHatch, timeout: float = 20.0) -> socket.socket:
    conn = socket.socket(socket.AF_UNIX)
    conn.settimeout(timeout)
    conn.connect(hatch.socket_path)
    return conn


# --------------------------------------------------------------------------- #
# Teardown ownership                                                           #
# --------------------------------------------------------------------------- #
def test_response_survives_a_command_that_closes_stdin_first(tmp_path: Path) -> None:
    """The reverse pump must not half-close the direction the response uses.

    A command that closes stdin and then writes (a request/response filter,
    ``head``, an ``upload-pack`` exiting while the client still writes) used to
    deliver *nothing*: the reverse pump's drain began with ``shutdown(SHUT_WR)``,
    the forward pump's next ``sendall`` took EPIPE, and the guest saw a clean EOF.
    """
    big = tmp_path / 'big'
    big.write_bytes(b'A' * (4 * _MIB))
    argv = ['sh', '-c', f'exec 0</dev/null; exec cat {big}']
    with _serving(StreamHatch(splice_subprocess(argv), name='t', grace=2.0)) as hatch:
        conn = _dial(hatch)
        stop = threading.Event()

        def flood() -> None:
            buf = b'x' * 65536
            while not stop.is_set():
                try:
                    conn.sendall(buf)
                except OSError:
                    return

        threading.Thread(target=flood, daemon=True).start()
        got = 0
        try:
            while chunk := conn.recv(65536):
                got += len(chunk)
        except OSError:
            pass
        stop.set()
        conn.close()
    assert got == 4 * _MIB, f'guest received {got} of {4 * _MIB} bytes'


def test_reverse_pump_threads_do_not_leak() -> None:
    """A guest that holds its write side open in silence must not park a thread.

    ``close()`` does not wake a thread already inside ``recv`` on Linux; only
    ``shutdown`` does. Without it every such connection left a reverse pump parked
    for ever, and ``max_conns`` bounded none of it because the slot was released —
    the same unbounded growth the process reaping exists to prevent.
    """

    def parked() -> int:
        # Both spellings: the pumps are named now, and were bare ``Thread-N``
        # before, so this counts the leak either way rather than passing vacuously
        # against a revision that never set the name.
        return len(
            [
                t
                for t in threading.enumerate()
                if t.is_alive() and (t.name == _REVERSE_THREAD or t.name.startswith('Thread-'))
            ]
        )

    argv = ['sh', '-c', 'echo hi']  # says its piece, exits, never reads stdin
    with _serving(StreamHatch(splice_subprocess(argv), name='l', max_conns=4, grace=0.5)) as hatch:
        held = []
        for _ in range(12):
            conn = _dial(hatch)
            # Read to EOF so the forward direction is over, then hold the socket
            # open and silent: the reverse pump has nothing to end it.
            with contextlib.suppress(OSError):
                while conn.recv(65536):
                    pass
            held.append(conn)
        assert _wait_until(lambda: parked() == 0), f'{parked()} reverse pumps still parked after 12 connections'
        for conn in held:
            conn.close()


def test_upstream_half_close_does_not_cap_the_guest_upload() -> None:
    """An upstream FIN must not turn ``grace`` into a deadline on the upload."""
    payload = 2560 * 1024
    received: list[int] = []
    ready = threading.Event()

    srv = socket.socket()
    srv.bind(('127.0.0.1', 0))
    srv.listen(4)
    port = srv.getsockname()[1]

    def upstream() -> None:
        sock, _ = srv.accept()
        sock.sendall(b'BANNER\n')
        sock.shutdown(socket.SHUT_WR)  # nothing more to say; still listening
        total = 0
        ready.set()
        try:
            while chunk := sock.recv(65536):
                total += len(chunk)
        except OSError:
            pass
        received.append(total)
        sock.close()

    threading.Thread(target=upstream, daemon=True).start()
    try:
        with _serving(StreamHatch(splice_tcp('127.0.0.1', port), name='u', grace=2.0)) as hatch:
            conn = _dial(hatch, timeout=60)
            assert conn.recv(64) == b'BANNER\n'
            ready.wait(10)
            sent = 0
            buf = b'z' * 65536
            while sent < payload:
                # Slower than `grace`, which is the point: the old code closed the
                # socket under the still-running pump after grace expired.
                conn.sendall(buf)
                sent += len(buf)
                time.sleep(0.08)
            conn.shutdown(socket.SHUT_WR)
            assert _wait_until(lambda: bool(received), timeout=30)
            conn.close()
    finally:
        srv.close()
    assert received, 'the upstream never finished reading'
    assert received[0] == sent, f'upstream got {received[0]} of {sent} bytes'


def test_teardown_does_not_raise_valueerror_in_the_reverse_pump() -> None:
    """Join before dispose: stdin must not be closed under a live reverse pump.

    The window, per Leo's recipe: connect, outlast the grace, send one byte. The
    command closes *stdout* so the forward pump ends and teardown begins; teardown
    closed the command's ``BufferedWriter`` while the reverse pump was still parked
    in ``recv``; the next byte from the guest then hit ``write`` on a closed file.
    ``ValueError`` is not an ``OSError``, so the thread died with a traceback and
    skipped its drain — handing the guest the very ECONNRESET the drain prevents.

    (Sending *continuously* instead would park the pump in ``write`` and take the
    EPIPE path, which was always handled. The bug needs an idle pump.)
    """
    seen: list[BaseException] = []
    hook = threading.excepthook

    def record(args) -> None:
        if args.exc_value is not None:
            seen.append(args.exc_value)

    threading.excepthook = record
    try:
        argv = ['sh', '-c', 'echo ack; exec 1>&-; exec sleep 30']
        with _serving(StreamHatch(splice_subprocess(argv), name='v', max_conns=4, grace=2.0)) as hatch:
            for _ in range(10):
                conn = _dial(hatch, timeout=10)
                with contextlib.suppress(OSError):
                    conn.recv(64)  # the ack; stdout is now closed, teardown starts
                time.sleep(0.6)  # let the reap close the command's stdin
                with contextlib.suppress(OSError):
                    conn.sendall(b'x')  # wakes a pump parked in recv
                time.sleep(0.2)
                conn.close()
            time.sleep(2.0)
    finally:
        threading.excepthook = hook
    value_errors = [e for e in seen if isinstance(e, ValueError)]
    assert not value_errors, f'{len(value_errors)} uncaught ValueError(s) in teardown: {value_errors[:3]}'


def test_a_process_verdict_is_reaped_exactly_once() -> None:
    """Two reap passes SIGKILLed a pgid whose leader had already been waited."""
    signalled: list[tuple[int, int]] = []
    real_killpg = os.killpg

    def spy(pgid: int, sig: int) -> None:
        signalled.append((pgid, sig))
        real_killpg(pgid, sig)

    os.killpg = spy
    try:
        with _serving(StreamHatch(splice_subprocess(['cat']), name='k', grace=1.0)) as hatch:
            conn = _dial(hatch)
            conn.sendall(b'ping\n')
            assert conn.recv(64) == b'ping\n'
            conn.shutdown(socket.SHUT_WR)
            with contextlib.suppress(OSError):
                while conn.recv(65536):
                    pass
            conn.close()
            time.sleep(1.0)
    finally:
        os.killpg = real_killpg
    kills = [s for s in signalled if s[1] == signal.SIGKILL]
    assert not kills, f'SIGKILL issued after the group was reaped: {signalled}'


# --------------------------------------------------------------------------- #
# Lifecycle                                                                    #
# --------------------------------------------------------------------------- #
def test_close_is_terminal_and_idempotent() -> None:
    hatch = StreamHatch(splice_subprocess(['cat']), name='c', max_conns=1, grace=0.5)
    hatch.start()
    hatch.close()
    hatch.close()  # must not inflate the slot semaphore
    assert hatch._slots._value <= 1, f'semaphore inflated to {hatch._slots._value}'
    with pytest.raises(RuntimeError, match=r'close\(\) is terminal'):
        hatch.start()
    with pytest.raises(RuntimeError, match=r'close\(\) is terminal'), hatch.accepting():
        pass


def test_close_on_a_never_started_hatch_does_not_inflate_slots() -> None:
    hatch = StreamHatch(splice_subprocess(['cat']), name='n', max_conns=1)
    hatch.close()
    assert hatch._slots._value == 1


def test_a_caller_supplied_socket_path_is_never_unlinked_unbound() -> None:
    """A path this hatch did not bind belongs to whoever did."""
    # Not pytest's tmp_path: sun_path is 108 bytes and pytest's is longer.
    victim = Path(tempfile.mkdtemp(prefix='pv-')) / 's.sock'
    other = socket.socket(socket.AF_UNIX)
    other.bind(str(victim))
    other.listen(1)
    try:
        hatch = StreamHatch(splice_subprocess(['cat']), name='v', socket_path=str(victim))
        hatch.close()  # never started, so it bound nothing
        assert victim.exists(), 'close() unlinked a socket this hatch never bound'
        hatch2 = StreamHatch(splice_subprocess(['cat']), name='v', socket_path=str(victim))
        with pytest.raises(OSError, match='ddress already in use'):
            hatch2.start()
        assert victim.exists(), 'start() unlinked a live socket it did not own'
    finally:
        other.close()


def test_grace_zero_still_reaps() -> None:
    """``grace=0.0`` must still reap: an invariant, not a regression.

    ``wait(timeout=0.0)`` is a single ``WNOHANG`` poll that necessarily loses the
    race against the signal it just sent, which is why the final ``wait()`` is
    untimed. On the reviewed revision this particular path happened to survive
    anyway, because the double dispose it also had reaped on its second pass; the
    discriminating case for the same cause is
    :func:`test_process_contract_rejection_reaps_the_group`, where there is no
    second pass. Kept because the invariant is what matters, not the symptom.

    Driven through ``close()`` rather than by disconnecting: a command that writes
    nothing and ignores stdin EOF holds its slot by design (there is deliberately
    no per-connection lifetime cap), so ``close()`` is what makes the reap run.
    """
    procs: list[subprocess.Popen[bytes]] = []

    def handler(_stream: Stream) -> Process:
        proc = subprocess.Popen(
            [sys.executable, '-c', 'import time; time.sleep(300)'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        procs.append(proc)
        return Process(proc)

    hatch = StreamHatch(handler, name='z', max_conns=6, grace=0.0)
    hatch.start()
    conns = []
    try:
        for _ in range(6):
            conns.append(_dial(hatch))
        assert _wait_until(lambda: len(procs) == 6), f'only {len(procs)} of 6 connections were served'
    finally:
        hatch.close()
        for conn in conns:
            conn.close()
    pids = [p.pid for p in procs]
    assert _wait_until(lambda: not [pid for pid in pids if _is_zombie(pid)], timeout=30), (
        f'unreaped zombies at grace=0.0: {[pid for pid in pids if _is_zombie(pid)]}'
    )


def test_process_contract_rejection_reaps_the_group() -> None:
    """The reject path must collect what it refuses, group included."""
    proc = subprocess.Popen(
        [sys.executable, '-c', 'import time; time.sleep(300)'],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        start_new_session=True,
    )
    with pytest.raises(ValueError, match='stdin=PIPE and stdout=PIPE'):
        Process(proc)
    pid = proc.pid
    assert _wait_until(lambda: not _is_zombie(pid), timeout=15), f'rejected Popen left a zombie: {pid}'
    assert proc.poll() is not None, 'rejected Popen was never waited'


def test_transient_accept_errors_do_not_retire_the_hatch(monkeypatch: pytest.MonkeyPatch) -> None:
    """EMFILE from the embedding worker must not leave the hatch permanently deaf.

    Before, any ``OSError`` from ``accept()`` returned from the loop while
    ``_started`` stayed ``True`` and ``_srv`` stayed live, so ``start()``
    short-circuited for ever and dials piled up in the backlog with no diagnostic.
    """
    hatch = StreamHatch(splice_subprocess(['cat']), name='a', max_conns=2, grace=0.5)
    hatch.start()
    try:
        real_accept = socket.socket.accept
        failures = {'left': 3}

        def flaky(self):
            if failures['left'] > 0 and self is hatch._srv:
                failures['left'] -= 1
                raise OSError(errno.EMFILE, 'Too many open files')
            return real_accept(self)

        monkeypatch.setattr(socket.socket, 'accept', flaky)
        # The loop is already parked inside the *unpatched* accept, so land one
        # dial to release it; the next iteration reaches the patched version.
        _dial(hatch).close()
        assert _wait_until(lambda: failures['left'] == 0, timeout=15), 'accept() was never retried'
        monkeypatch.undo()
        conn = _dial(hatch)
        conn.sendall(b'alive\n')
        assert conn.recv(64) == b'alive\n', 'the hatch never recovered from a transient accept error'
        conn.close()
    finally:
        hatch.close()


# --------------------------------------------------------------------------- #
# splice_subprocess contract                                                   #
# --------------------------------------------------------------------------- #
def test_stderr_pipe_is_refused() -> None:
    with pytest.raises(ValueError, match=r'stderr=subprocess\.PIPE is not supported'):
        splice_subprocess(['cat'], stderr=subprocess.PIPE)


# --------------------------------------------------------------------------- #
# git_url / constants                                                          #
# --------------------------------------------------------------------------- #
def test_git_url_takes_its_interpreter_from_the_profile() -> None:
    profile = SandboxProfile.with_venv('/opt/venv')
    assert git_url('repo', profile=profile) == f'ext::/opt/venv/bin/python {GUEST_CONNECT} /run/postern/repo.sock'
    assert git_url('repo', profile=profile, python='/other/py').startswith('ext::/other/py ')


def test_the_connector_path_has_one_definition() -> None:
    """`stream.py` must not keep its own copy of the guest connector path."""
    source = (Path(__file__).resolve().parent.parent / 'src' / 'postern' / 'stream.py').read_text()
    assert '/run/postern/connect.py' not in source, 'stream.py redefines GUEST_CONNECT'
    assert git_url('x').split()[1] == GUEST_CONNECT


# --------------------------------------------------------------------------- #
# Collision checking                                                           #
# --------------------------------------------------------------------------- #
# Never bound, never created: only the collision arithmetic looks at them.
_FAKE_A = '/nonexistent/postern-test/a.sock'
_FAKE_B = '/nonexistent/postern-test/b.sock'
_FAKE_C = '/nonexistent/postern-test/c.sock'
_FAKE_SAME = '/nonexistent/postern-test/same.sock'


class _FakeHatch:
    def __init__(self, name: str | None, path: str) -> None:
        if name is not None:
            self.guest_name = name
        self.socket_path = path

    def accepting(self):
        raise AssertionError('not launched')


@pytest.mark.parametrize(
    ('hatches', 'expected'),
    [
        ([_FakeHatch(None, _FAKE_A), _FakeHatch('hatch', _FAKE_B)], 'guest socket paths'),
        ([_FakeHatch('a', _FAKE_SAME), _FakeHatch('b', _FAKE_SAME)], 'host socket paths'),
        ([_FakeHatch('repo', _FAKE_A), _FakeHatch('REPO', _FAKE_B)], 'guest environment variables'),
    ],
)
def test_colliding_hatches_are_refused(hatches: list[object], expected: str) -> None:
    with pytest.raises(ValueError, match=expected):
        Sandbox(SandboxProfile(), hatch=hatches)  # type: ignore[arg-type]


def test_a_legitimate_hatch_set_is_still_accepted() -> None:
    sandbox = Sandbox(
        SandboxProfile(),
        hatch=[_FakeHatch(None, _FAKE_A), _FakeHatch('x', _FAKE_B), _FakeHatch('y', _FAKE_C)],  # type: ignore[arg-type]
    )
    _binds, env = sandbox._hatch_wiring()
    assert env == {
        'POSTERN_HATCH': '/run/postern/hatch.sock',
        'POSTERN_HATCH_X': '/run/postern/x.sock',
        'POSTERN_HATCH_Y': '/run/postern/y.sock',
    }


# --------------------------------------------------------------------------- #
# The connector                                                                #
# --------------------------------------------------------------------------- #
_CONNECTOR = str(Path(__file__).resolve().parent.parent / 'src' / 'postern' / '_stream_connect.py')


def test_connector_moves_bulk_bytes_both_ways() -> None:
    """Full duplex through the real connector: the suite had no such coverage.

    ``test_large_payload_streams_without_a_ceiling`` passes only because its client
    is two-threaded, so nothing exercised the connector the sandbox actually binds.
    """
    # 64 MiB, not 8: the deadlock needs enough in flight to fill the socket
    # buffers, both pipe buffers and the command's own queue. 8 MiB clears on a
    # container with generous buffers even on the blocking connector.
    payload = 64 * _MIB
    with _serving(StreamHatch(splice_subprocess(['cat']), name='d', grace=3.0)) as hatch:
        proc = subprocess.Popen(
            [sys.executable, _CONNECTOR, hatch.socket_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        got = bytearray()

        def read() -> None:
            with contextlib.suppress(OSError):
                assert proc.stdout is not None
                while chunk := proc.stdout.read(65536):
                    got.extend(chunk)

        reader = threading.Thread(target=read, daemon=True)
        reader.start()

        def write() -> None:
            # In chunks, not one giant write: the wedge needs the writer to keep
            # coming back for more while every buffer in the cycle is already full.
            with contextlib.suppress(OSError):
                assert proc.stdin is not None
                block = b'Q' * 65536
                for _ in range(payload // 65536):
                    proc.stdin.write(block)
                proc.stdin.flush()
                proc.stdin.close()

        writer = threading.Thread(target=write, daemon=True)
        writer.start()
        writer.join(60)
        reader.join(60)
        proc.kill()
        proc.wait(30)
    assert len(got) == payload, f'{len(got)} of {payload} bytes echoed'


def test_connector_works_when_stdin_is_not_a_pipe() -> None:
    """``epoll_ctl`` rejects regular files and ``/dev/null`` with EPERM.

    The sandbox gives entrypoints ``stdin=DEVNULL``, so an in-guest invocation
    inheriting it silently reported success having moved nothing.
    """
    hatch = StreamHatch(splice_subprocess(['sh', '-c', 'echo HELLO']), name='n', grace=2.0)
    with _serving(hatch), open(os.devnull) as devnull:
        done = subprocess.run(
            [sys.executable, _CONNECTOR, hatch.socket_path],
            stdin=devnull,
            capture_output=True,
            timeout=60,
            check=False,
        )
    assert done.stdout == b'HELLO\n', f'rc={done.returncode} stdout={done.stdout!r} stderr={done.stderr!r}'


def test_connector_reports_a_failure_rather_than_exiting_zero(tmp_path: Path) -> None:
    done = subprocess.run(
        [sys.executable, _CONNECTOR, str(tmp_path / 'nothing-here.sock')],
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert done.returncode != 0
    assert b'cannot reach the hatch' in done.stderr
