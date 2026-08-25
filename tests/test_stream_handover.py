"""Handover: the command gets ordinary stdio, whatever the handler did to the socket.

A `Process` verdict makes the accepted connection the command's stdin and stdout,
and the child's fds 0 and 1 are ``dup2``s of *one* open file description. Its file
status flags and its socket options are therefore shared with the handler's
``stream.conn``, not copied from it — so anything a handler configures is what the
command runs with.

That is a hazard the host-side pump did not have: with a pump, a non-blocking
socket was the pump's problem. Now it is the command's, and the failure is silent
— the command takes ``EAGAIN``, exits, and the guest reads the truncation as a
clean end-of-stream.

So the invariant these tests pin is not "``O_NONBLOCK`` is cleared", it is **the
child gets ordinary stdio**: one case per shared setting, asserted from inside the
child. :func:`test_the_tests_would_notice_if_normalisation_stopped_happening`
checks they are not vacuous.
"""

from __future__ import annotations

import contextlib
import fcntl
import os
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

import postern.stream as stream_module
from postern.stream import Process, Stream, StreamHatch, splice_subprocess

_DEADLINE = 25.0
_MIB = 1 << 20
_O_ASYNC = getattr(os, 'O_ASYNC', 0)
_F_SETSIG = getattr(fcntl, 'F_SETSIG', None)
_SO_PASSCRED = getattr(socket, 'SO_PASSCRED', None)

# Reports its own fd 0 / fd 1, which is the only place the invariant is observable.
_REPORT = [
    sys.executable,
    '-c',
    r"""
import fcntl, os, socket, sys
fl = fcntl.fcntl(0, fcntl.F_GETFL)
s = socket.socket(fileno=os.dup(0))
def opt(o, n=4):
    try:
        return s.getsockopt(socket.SOL_SOCKET, o, n) if n > 4 else s.getsockopt(socket.SOL_SOCKET, o)
    except OSError:
        return None
out = {
    'fl': fl,
    'fl1': fcntl.fcntl(1, fcntl.F_GETFL),
    'owner': fcntl.fcntl(0, fcntl.F_GETOWN),
    'sig': fcntl.fcntl(0, 11) if hasattr(fcntl, 'F_GETSIG') else 0,
    'rcvtimeo': opt(socket.SO_RCVTIMEO, 32),
    'sndtimeo': opt(socket.SO_SNDTIMEO, 32),
    'rcvlowat': opt(socket.SO_RCVLOWAT),
    'oobinline': opt(socket.SO_OOBINLINE),
    'passcred': opt(socket.SO_PASSCRED) if hasattr(socket, 'SO_PASSCRED') else 0,
    'linger': opt(socket.SO_LINGER, 8),
}
sys.stdout.write(repr(out))
sys.stdout.flush()
""",
]


def _report(tweak, *, argv=None) -> dict:
    """Run a child through the hatch and return what it saw of its own stdio."""
    base = splice_subprocess(argv or _REPORT)

    def handler(stream: Stream) -> Process:
        tweak(stream.conn)
        verdict = base(stream)
        assert isinstance(verdict, Process)
        return verdict

    hatch = StreamHatch(handler, name='h', grace=2.0)
    hatch.start()
    try:
        conn = socket.socket(socket.AF_UNIX)
        conn.settimeout(_DEADLINE)
        conn.connect(hatch.socket_path)
        conn.shutdown(socket.SHUT_WR)
        raw = b''
        with contextlib.suppress(OSError):
            while chunk := conn.recv(65536):
                raw += chunk
        conn.close()
        assert raw, 'the child produced nothing'
        return eval(raw)  # noqa: S307 — our own child's repr()
    finally:
        hatch.close()


def _reaped(verdicts: list[Process]) -> bool:
    """Whether the first verdict's command has been waited (without doing the wait)."""
    if not verdicts or verdicts[0].proc is None:
        return False
    return verdicts[0].proc.returncode is not None


def _timeval(seconds: int) -> bytes:
    return struct.pack('@ll', seconds, 0)


def _set_fl(sock: socket.socket, bit: int) -> None:
    fd = sock.fileno()
    fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) | bit)


# --------------------------------------------------------------------------- #
# One case per shared setting: the child must see the ordinary value            #
# --------------------------------------------------------------------------- #
def test_baseline_is_ordinary_stdio() -> None:
    """What "ordinary" means here, so every case below has something to equal."""
    seen = _report(lambda _conn: None)
    assert not seen['fl'] & os.O_NONBLOCK
    assert not seen['fl'] & _O_ASYNC
    assert not seen['fl'] & os.O_APPEND
    assert not any(seen['rcvtimeo'])
    assert not any(seen['sndtimeo'])
    assert seen['rcvlowat'] == 1
    assert seen['oobinline'] == 0


def test_a_handlers_settimeout_does_not_reach_the_command() -> None:
    """``settimeout`` is the reachable one: CPython implements it as ``O_NONBLOCK``.

    Before normalisation the child saw ``O_NONBLOCK`` on both fd 0 and fd 1 — see
    :func:`test_a_nonblocking_connection_no_longer_truncates_the_response` for what
    that cost.
    """
    seen = _report(lambda conn: conn.settimeout(2.0))
    assert not seen['fl'] & os.O_NONBLOCK, 'the command inherited O_NONBLOCK on stdin'
    assert not seen['fl1'] & os.O_NONBLOCK, 'the command inherited O_NONBLOCK on stdout'


def test_a_handlers_setblocking_false_does_not_reach_the_command() -> None:
    seen = _report(lambda conn: conn.setblocking(False))
    assert not seen['fl'] & os.O_NONBLOCK


@pytest.mark.skipif(not _O_ASYNC, reason='no O_ASYNC on this platform')
def test_o_async_does_not_reach_the_command() -> None:
    """Signal-driven I/O: ordinary stdio has none, and a child with it can get SIGIO.

    Measured inert on ``AF_UNIX`` (no ``SIGIO`` was delivered even with an owner
    set), which is why this asserts the flag rather than a death: the inertness is
    a detail of one kernel's ``AF_UNIX`` path, not a property to depend on.
    """
    seen = _report(lambda conn: _set_fl(conn, _O_ASYNC))
    assert not seen['fl'] & _O_ASYNC
    assert not seen['fl1'] & _O_ASYNC


def test_o_append_does_not_reach_the_command() -> None:
    seen = _report(lambda conn: _set_fl(conn, os.O_APPEND))
    assert not seen['fl'] & os.O_APPEND


def test_a_stale_signal_owner_does_not_reach_the_command() -> None:
    """``F_SETOWN``/``F_SETSIG`` are on the same description, so they are shared too.

    Inert once ``O_ASYNC`` is clear, but zeroed rather than reasoned about: a stale
    owner is the sort of thing that becomes reachable when something else changes.
    """

    def tweak(conn: socket.socket) -> None:
        fcntl.fcntl(conn.fileno(), fcntl.F_SETOWN, os.getpid())
        if _F_SETSIG is not None:
            fcntl.fcntl(conn.fileno(), _F_SETSIG, 34)

    seen = _report(tweak)
    assert seen['owner'] == 0, f'the command inherited signal owner {seen["owner"]}'
    assert seen['sig'] == 0


def test_so_rcvtimeo_does_not_reach_the_command() -> None:
    seen = _report(lambda conn: conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, _timeval(2)))
    assert not any(seen['rcvtimeo']), 'the command inherited a receive timeout'


def test_so_sndtimeo_does_not_reach_the_command() -> None:
    seen = _report(lambda conn: conn.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO, _timeval(2)))
    assert not any(seen['sndtimeo']), 'the command inherited a send timeout'


def test_so_rcvlowat_does_not_reach_the_command() -> None:
    seen = _report(lambda conn: conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVLOWAT, 4096))
    assert seen['rcvlowat'] == 1


def test_so_oobinline_does_not_reach_the_command() -> None:
    seen = _report(lambda conn: conn.setsockopt(socket.SOL_SOCKET, socket.SO_OOBINLINE, 1))
    assert seen['oobinline'] == 0


@pytest.mark.skipif(_SO_PASSCRED is None, reason='SO_PASSCRED is Linux-only')
def test_so_passcred_does_not_reach_the_command() -> None:
    assert _SO_PASSCRED is not None
    seen = _report(lambda conn: conn.setsockopt(socket.SOL_SOCKET, _SO_PASSCRED, 1))
    assert seen['passcred'] == 0


def test_so_linger_is_deliberately_left_alone() -> None:
    """The one exception, and it has to be an exception.

    Close semantics carry the disposition signal — an unread receive queue at
    last-close is what resets the guest, and that reset is the only failure signal
    a stream with no framing of its own has. Normalising ``SO_LINGER`` would change
    what the guest is told about the command, so it is left exactly as found. Pinned
    so that "not normalised" stays a decision rather than becoming an oversight.
    """
    seen = _report(lambda conn: conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0)))
    assert seen['linger'][:4] != b'\x00\x00\x00\x00', 'SO_LINGER was normalised away; see the docstring'


# --------------------------------------------------------------------------- #
# The behaviour behind the two flags that actually bite                         #
# --------------------------------------------------------------------------- #
def test_a_nonblocking_connection_no_longer_truncates_the_response(tmp_path: Path) -> None:
    """The symptom that found all of this: 219264 of 4194304 bytes, reported as EOF.

    A slow reader forces the command to block in ``write``; on a non-blocking
    socket it takes ``EAGAIN`` instead, exits, and the guest sees a clean
    end-of-stream on a truncated response — silent corruption with no diagnostic
    anywhere. Both ``cat`` and CPython lost the tail at exactly the same offset.
    """
    big = tmp_path / 'big'
    big.write_bytes(b'B' * (4 * _MIB))
    base = splice_subprocess(['cat', str(big)])

    def handler(stream: Stream) -> Process:
        stream.conn.settimeout(2.0)  # the defensive thing a handler would do
        verdict = base(stream)
        assert isinstance(verdict, Process)
        return verdict

    hatch = StreamHatch(handler, name='t', grace=3.0)
    hatch.start()
    try:
        conn = socket.socket(socket.AF_UNIX)
        conn.settimeout(_DEADLINE)
        conn.connect(hatch.socket_path)
        conn.shutdown(socket.SHUT_WR)
        got = 0
        with contextlib.suppress(OSError):
            while True:
                time.sleep(0.005)  # a slow guest, so the command has to block
                chunk = conn.recv(4096)
                if not chunk:
                    break
                got += len(chunk)
        conn.close()
    finally:
        hatch.close()
    assert got == 4 * _MIB, f'the command delivered {got} of {4 * _MIB} bytes'


def test_a_receive_timeout_no_longer_breaks_a_slow_request() -> None:
    """``SO_RCVTIMEO`` is the same failure by another route: 8 of 16 bytes echoed.

    A guest that pauses mid-request is ordinary (git does it between phases). With
    an inherited receive timeout the command's ``read`` fails ``EAGAIN`` and it
    exits half way through.
    """
    base = splice_subprocess(['cat'])

    def handler(stream: Stream) -> Process:
        stream.conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, _timeval(1))
        verdict = base(stream)
        assert isinstance(verdict, Process)
        return verdict

    hatch = StreamHatch(handler, name='s', grace=2.0)
    hatch.start()
    try:
        conn = socket.socket(socket.AF_UNIX)
        conn.settimeout(_DEADLINE)
        conn.connect(hatch.socket_path)
        got = b''
        with contextlib.suppress(OSError):
            conn.sendall(b'0123456789')
            time.sleep(2.5)  # longer than the timeout the handler set
            conn.sendall(b'abcdef')
            conn.shutdown(socket.SHUT_WR)
            while chunk := conn.recv(65536):
                got += chunk
        conn.close()
    finally:
        hatch.close()
    assert got == b'0123456789abcdef', f'the command echoed {got!r}'


# --------------------------------------------------------------------------- #
# read_preamble: the flag-free way to bound a handshake read                    #
# --------------------------------------------------------------------------- #
def test_read_preamble_reads_without_disturbing_the_handover() -> None:
    """A handler can consume a preamble and still splice a working stream."""
    seen: list[bytes] = []
    base = splice_subprocess(['cat'])

    def handler(stream: Stream) -> Process:
        seen.append(stream.read_preamble(6, 5.0))
        verdict = base(stream)
        assert isinstance(verdict, Process)
        return verdict

    hatch = StreamHatch(handler, name='p', grace=2.0)
    hatch.start()
    try:
        conn = socket.socket(socket.AF_UNIX)
        conn.settimeout(_DEADLINE)
        conn.connect(hatch.socket_path)

        # Send on a second thread: a stream is genuinely bidirectional, and 100 KiB
        # outgrows a macOS AF_UNIX socket buffer several times over, so a client that
        # wrote everything before reading would wedge on its own buffers.
        def send() -> None:
            with contextlib.suppress(OSError):
                conn.sendall(b'HELLO!' + b'z' * 100000)
                conn.shutdown(socket.SHUT_WR)

        sender = threading.Thread(target=send, daemon=True)
        sender.start()
        got = 0
        with contextlib.suppress(OSError):
            while chunk := conn.recv(65536):
                got += len(chunk)
        sender.join(_DEADLINE)
        conn.close()
    finally:
        hatch.close()
    assert seen == [b'HELLO!']
    assert got == 100000, f'the splice after the preamble delivered {got} of 100000'


def test_read_preamble_is_bounded_and_leaves_the_socket_blocking() -> None:
    """A silent guest costs ``timeout``, not the hatch's life — and no flags change.

    This is the safe form of the pattern that otherwise pins a slot for ever: the
    hatch cannot shut a connection down until its handler returns, so an unbounded
    read here is a slot a guest takes with nothing but ``connect()``.
    """
    elapsed: list[float] = []
    flags: list[int] = []

    def handler(stream: Stream) -> None:
        start = time.monotonic()
        assert stream.read_preamble(16, 0.4) == b''
        elapsed.append(time.monotonic() - start)
        flags.append(fcntl.fcntl(stream.conn.fileno(), fcntl.F_GETFL))
        # No verdict: an implicit None is the refusal.

    hatch = StreamHatch(handler, name='b', grace=1.0)
    hatch.start()
    try:
        conn = socket.socket(socket.AF_UNIX)
        conn.settimeout(_DEADLINE)
        conn.connect(hatch.socket_path)  # and never send anything
        assert conn.recv(64) == b''  # the refusal: end-of-stream, no diagnostic
        conn.close()
    finally:
        hatch.close()
    assert elapsed, 'the handler never ran'
    assert 0.3 < elapsed[0] < 5.0, f'read_preamble was not bounded: {elapsed}'
    assert flags
    assert not flags[0] & os.O_NONBLOCK, 'read_preamble left the socket non-blocking'


# --------------------------------------------------------------------------- #
# The escape hatch: adopted Popens are validated, because they cannot be fixed  #
# --------------------------------------------------------------------------- #
def test_an_adopted_popen_on_an_abnormal_connection_is_refused_and_reaped() -> None:
    """``from_popen`` cannot be normalised after the fact, so it is checked instead.

    Normalising post-spawn is not a fix but a race: measured, half a millisecond of
    delay in the parent between ``Popen`` and the clear took a 4 MiB response down
    to 219 KiB on 10 of 10 attempts. So the hatch refuses the verdict and names the
    cause, which is late but loud — and it must still reap what it refuses, or a
    guest reconnecting in a loop grows the host's process table.
    """
    verdicts: list[Process] = []

    def handler(stream: Stream) -> Process:
        stream.conn.settimeout(2.0)  # abnormal, and the child is already coming
        proc = subprocess.Popen(
            ['cat'],
            stdin=stream.conn.fileno(),
            stdout=stream.conn.fileno(),
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        verdict = Process.from_popen(proc)
        verdicts.append(verdict)
        return verdict

    hatch = StreamHatch(handler, name='a', grace=1.0)
    hatch.start()
    try:
        conn = socket.socket(socket.AF_UNIX)
        conn.settimeout(_DEADLINE)
        conn.connect(hatch.socket_path)
        with contextlib.suppress(OSError):
            conn.recv(64)
        conn.close()
        deadline = time.monotonic() + _DEADLINE
        while time.monotonic() < deadline and not (
            verdicts and verdicts[0].proc is not None and verdicts[0].proc.returncode is not None
        ):
            time.sleep(0.05)
    finally:
        hatch.close()
    assert verdicts, 'the handler never ran'
    proc = verdicts[0].proc
    assert proc is not None
    assert proc.returncode is not None, 'the refused verdict was abandoned unreaped'


def test_an_adopted_popen_on_a_clean_connection_still_works() -> None:
    """The escape hatch has to remain usable, or it is not an escape hatch."""

    def handler(stream: Stream) -> Process:
        proc = subprocess.Popen(
            ['cat'],
            stdin=stream.conn.fileno(),
            stdout=stream.conn.fileno(),
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        return Process.from_popen(proc)

    hatch = StreamHatch(handler, name='k', grace=2.0)
    hatch.start()
    try:
        conn = socket.socket(socket.AF_UNIX)
        conn.settimeout(_DEADLINE)
        conn.connect(hatch.socket_path)
        conn.sendall(b'adopted')
        conn.shutdown(socket.SHUT_WR)
        got = b''
        with contextlib.suppress(OSError):
            while chunk := conn.recv(65536):
                got += chunk
        conn.close()
    finally:
        hatch.close()
    assert got == b'adopted'


def test_stderr_stdout_is_refused_at_both_entry_points() -> None:
    """stdout *is* the guest socket, so merging fd 2 into it is a disclosure.

    Measured before the guard: the guest received ``fatal:
    '/srv/secrets/customer-a/repo.git' does not appear to be a git repository`` —
    verbatim the host-path leak the ``stderr`` argument exists to prevent. ``PIPE``
    (a deadlock) was guarded; ``STDOUT`` (a disclosure) was not.
    """
    for build in (
        lambda: splice_subprocess(['cat'], stderr=subprocess.STDOUT),
        lambda: Process(['cat'], stderr=subprocess.STDOUT),
    ):
        with pytest.raises(ValueError, match=r'stderr=subprocess\.STDOUT is not supported'):
            build()
    for build_pipe in (
        lambda: splice_subprocess(['cat'], stderr=subprocess.PIPE),
        lambda: Process(['cat'], stderr=subprocess.PIPE),
    ):
        with pytest.raises(ValueError, match=r'stderr=subprocess\.PIPE is not supported'):
            build_pipe()


# --------------------------------------------------------------------------- #
# Are the cases above actually testing anything?                               #
# --------------------------------------------------------------------------- #
def test_the_tests_would_notice_if_normalisation_stopped_happening(monkeypatch: pytest.MonkeyPatch) -> None:
    """Neuter the normalisation and the child must see the handler's settings.

    This branch has a track record of tests that passed vacuously, so each case
    above is only worth its line count if it fails without the fix. Rather than
    trusting that, this reintroduces the bug and checks the observation notices —
    for the flag that bites and for one socket option, which between them cover
    both halves of :func:`postern.stream._normalise_stdio`.
    """
    monkeypatch.setattr(stream_module, '_normalise_stdio', lambda _conn: None)
    seen = _report(lambda conn: conn.settimeout(2.0))
    assert seen['fl'] & os.O_NONBLOCK, 'O_NONBLOCK is not reaching the child even unnormalised'
    seen = _report(lambda conn: conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, _timeval(2)))
    assert any(seen['rcvtimeo']), 'SO_RCVTIMEO is not reaching the child even unnormalised'
