"""Stream-hatch regressions, grouped by cause rather than by symptom."""

from __future__ import annotations

import contextlib
import errno
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

import postern.stream as stream_module
from postern import Sandbox, SandboxProfile
from postern._sandbox import GUEST_CONNECT
from postern.stream import (
    Process,
    Stream,
    StreamHatch,
    git_url,
    splice_subprocess,
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

    Avoids ``Popen.poll()``/``wait()``: those *are* the reap, so a test that calls
    them cannot observe the leak it is looking for.
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
    """A command that closes stdin and then writes must still deliver everything.

    The shape: a request/response filter, ``head``, an ``upload-pack`` exiting while
    the client still writes.
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


def test_no_signal_is_ever_sent_to_an_already_reaped_group() -> None:
    """A group may only be signalled while we still hold the leader's pid.

    A group id is valid only while that pid is allocated, so a signal sent after the
    reap can land on a recycled pid — plausibly another connection's command, since
    every verdict mints a session leader. The group *is* signalled on the normal
    path; what must never happen is signalling after the reap, so the observation
    here is the leader's ``returncode`` at the moment of each ``killpg``.
    """
    seen: list[tuple[int, int, int | None]] = []
    verdicts: list[Process] = []
    real_killpg = os.killpg

    def spy(pgid: int, sig: int) -> None:
        live = verdicts[0].proc if verdicts else None
        seen.append((pgid, sig, live.returncode if live is not None else None))
        real_killpg(pgid, sig)

    base = splice_subprocess(['cat'])

    def handler(stream: Stream) -> Process:
        verdict = base(stream)
        assert isinstance(verdict, Process)
        verdicts.append(verdict)
        return verdict

    os.killpg = spy
    try:
        with _serving(StreamHatch(handler, name='k', grace=1.0)) as hatch:
            conn = _dial(hatch)
            conn.sendall(b'ping\n')
            assert conn.recv(64) == b'ping\n'
            conn.shutdown(socket.SHUT_WR)
            with contextlib.suppress(OSError):
                while conn.recv(65536):
                    pass
            conn.close()
            assert _wait_until(lambda: bool(seen), timeout=15), 'the group was never collected'
    finally:
        os.killpg = real_killpg
    after_reap = [entry for entry in seen if entry[2] is not None]
    assert not after_reap, f'signal sent after the leader was reaped: {after_reap}'


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
    """``grace=0.0`` must still reap.

    ``wait(timeout=0.0)`` is a single ``WNOHANG`` poll that necessarily loses the
    race against the signal it just sent, which is why the final ``wait()`` is
    untimed.

    Driven through ``close()`` rather than by disconnecting: a command that writes
    nothing and ignores stdin EOF holds its slot by design (there is no
    per-connection lifetime cap), so ``close()`` is what makes the reap run.
    """
    verdicts: list[Process] = []

    def handler(_stream: Stream) -> Process:
        verdict = Process([sys.executable, '-c', 'import time; time.sleep(300)'])
        verdicts.append(verdict)
        return verdict

    graces: list[float] = []
    real_reap = stream_module._reap

    def spy(proc: subprocess.Popen[bytes], grace: float, pgid: int | None = None) -> None:
        graces.append(grace)
        real_reap(proc, grace, pgid)

    stream_module._reap = spy
    hatch = StreamHatch(handler, name='z', max_conns=6, grace=0.0)
    hatch.start()
    conns = []
    try:
        for _ in range(6):
            conns.append(_dial(hatch))
        assert _wait_until(lambda: sum(v.proc is not None for v in verdicts) == 6), (
            f'only {sum(v.proc is not None for v in verdicts)} of 6 connections were served'
        )
    finally:
        hatch.close()
        stream_module._reap = real_reap
        for conn in conns:
            conn.close()
    # The reap must have run at the hatch's grace, not at the contract-rejection
    # budget; without this the test can pass vacuously.
    assert graces, 'no reap ran at all'
    assert all(g == 0.0 for g in graces), f'grace=0.0 never reached _reap: {graces}'
    pids = [v.proc.pid for v in verdicts if v.proc is not None]
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
    with pytest.raises(ValueError, match=r'requires the connection as the command'):
        Process.from_popen(proc)
    pid = proc.pid
    assert _wait_until(lambda: not _is_zombie(pid), timeout=15), f'rejected Popen left a zombie: {pid}'
    assert proc.poll() is not None, 'rejected Popen was never waited'


def test_transient_accept_errors_do_not_retire_the_hatch(monkeypatch: pytest.MonkeyPatch) -> None:
    """EMFILE from the embedding worker must not leave the hatch permanently deaf.

    Returning from the accept loop leaves ``_started`` true and ``_srv`` live, so
    ``start()`` short-circuits for ever and dials pile up in the backlog with no
    diagnostic.
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
    """Full duplex through the connector the sandbox actually binds in.

    ``test_large_payload_streams_without_a_ceiling`` passes with a two-threaded
    client of its own, so it says nothing about the connector.
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
    inherits it.
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


# --------------------------------------------------------------------------- #
# Disposition: what the kernel says, now that nothing copies                   #
# --------------------------------------------------------------------------- #
@pytest.mark.skipif(sys.platform != 'linux', reason='AF_UNIX close only resets the peer on Linux')
def test_the_kernel_propagates_the_commands_disposition() -> None:
    """EOF when the command finished, a reset when it died mid-request.

    The reason the `Process` path does not drain: for a stream with no framing of its
    own this is the only failure signal there is.
    """

    def outcome(argv: list[str], payload: bytes, *, half_close: bool) -> str:
        with _serving(StreamHatch(splice_subprocess(argv), name='d', grace=1.0)) as hatch:
            conn = _dial(hatch)
            with contextlib.suppress(OSError):
                conn.sendall(payload)
                if half_close:
                    conn.shutdown(socket.SHUT_WR)
            try:
                while conn.recv(65536):
                    pass
            except ConnectionResetError:
                return 'reset'
            except OSError:
                return 'error'
            finally:
                conn.close()
            return 'eof'

    assert outcome(['sh', '-c', 'cat >/dev/null; echo done'], b'x' * 4096, half_close=True) == 'eof'
    # A megabyte the command never reads: the remainder is still queued when its
    # last descriptor closes, which is precisely what the guest needs to be told.
    assert outcome(['sh', '-c', 'echo partial; exit 0'], b'x' * (1 << 20), half_close=False) == 'reset'
    died = ['sh', '-c', 'head -c 100 >/dev/null; echo hi; exit 1']
    assert outcome(died, b'x' * (1 << 20), half_close=False) == 'reset'
