"""The `Upstream` verdict: the one path that needs a host-side relay.

A `Process` gets the guest's socket *as* its stdio, so the kernel moves the bytes.
Two sockets are different kernel objects and nothing joins them but a copy, so this
path has a thread per direction — and every teardown question the `Process` path
does not have to answer.
"""

from __future__ import annotations

import contextlib
import socket
import struct
import sys
import threading
import time

import pytest

from postern.stream import _RELAY_THREAD, StreamHatch, Upstream, splice_tcp

_MIB = 1 << 20


def _wait_until(pred, timeout: float = 25.0) -> bool:
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


def _dial(hatch: StreamHatch, timeout: float = 25.0) -> socket.socket:
    conn = socket.socket(socket.AF_UNIX)
    conn.settimeout(timeout)
    conn.connect(hatch.socket_path)
    return conn


class _Upstream:
    """A scriptable TCP upstream: one accepted connection, handed to ``behaviour``."""

    def __init__(self, behaviour) -> None:
        self._srv = socket.socket()
        self._srv.bind(('127.0.0.1', 0))
        self._srv.listen(4)
        self.port = self._srv.getsockname()[1]
        self.received: list[int] = []
        self.ready = threading.Event()
        self._behaviour = behaviour
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self) -> None:
        with contextlib.suppress(OSError):
            sock, _ = self._srv.accept()
            self._behaviour(self, sock)

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self._srv.close()


def _guest_outcome(conn: socket.socket) -> str:
    """Read to the end and report how the stream ended: eof, reset or error."""
    try:
        while conn.recv(65536):
            pass
    except ConnectionResetError:
        return 'reset'
    except OSError:
        return 'error'
    return 'eof'


# --------------------------------------------------------------------------- #
# Disposition: a dead upstream must not look like a finished one               #
# --------------------------------------------------------------------------- #
@pytest.mark.skipif(sys.platform != 'linux', reason='AF_UNIX close only resets the peer on Linux')
def test_a_clean_upstream_fin_gives_the_guest_end_of_stream() -> None:
    """Nothing went wrong, so the guest must not be told anything did.

    The guest is left with unread bytes queued on purpose: that is the reset which
    would be the relay's own teardown artifact, and suppressing it is what the drain
    is for.
    """

    def behaviour(_own: _Upstream, sock: socket.socket) -> None:
        sock.sendall(b'BANNER\n')
        sock.shutdown(socket.SHUT_WR)  # orderly: nothing more to say
        with contextlib.suppress(OSError):
            while sock.recv(65536):
                pass
        sock.close()

    up = _Upstream(behaviour)
    try:
        with _serving(StreamHatch(splice_tcp('127.0.0.1', up.port), name='u', grace=2.0)) as hatch:
            conn = _dial(hatch)
            assert conn.recv(64) == b'BANNER\n'
            assert _guest_outcome(conn) == 'eof'
            conn.close()
    finally:
        up.close()


@pytest.mark.skipif(sys.platform != 'linux', reason='AF_UNIX close only resets the peer on Linux')
def test_an_upstream_that_resets_mid_response_resets_the_guest() -> None:
    """The reset is the only failure signal a stream with no framing of its own has.

    Paired with the clean-FIN test above: together they require the relay to
    distinguish the two endings rather than draining unconditionally, which would
    report a dead upstream as a clean end of stream.
    """

    def behaviour(_own: _Upstream, sock: socket.socket) -> None:
        sock.sendall(b'PARTIAL')
        # Abort rather than close: SO_LINGER 0 makes the close an RST.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        sock.close()

    up = _Upstream(behaviour)
    try:
        with _serving(StreamHatch(splice_tcp('127.0.0.1', up.port), name='u', grace=2.0)) as hatch:
            conn = _dial(hatch)
            assert conn.recv(64) == b'PARTIAL'
            # Keep bytes queued towards the host, so the close has something to
            # deliver the reset with: AF_UNIX has no way to synthesise one.
            with contextlib.suppress(OSError):
                conn.sendall(b'z' * _MIB)
            assert _guest_outcome(conn) == 'reset'
            conn.close()
    finally:
        up.close()


# --------------------------------------------------------------------------- #
# Lifetime and threads                                                         #
# --------------------------------------------------------------------------- #
def test_upstream_half_close_does_not_cap_the_guest_upload() -> None:
    """An upstream FIN must not turn ``grace`` into a deadline on the upload.

    The upstream half-closes after its banner and keeps reading, which is ordinary
    request/response shape. The guest-to-upstream direction has to run to its own
    EOF for the whole body to arrive.
    """
    payload = 2560 * 1024

    def behaviour(own: _Upstream, sock: socket.socket) -> None:
        sock.sendall(b'BANNER\n')
        sock.shutdown(socket.SHUT_WR)
        total = 0
        own.ready.set()
        with contextlib.suppress(OSError):
            while chunk := sock.recv(65536):
                total += len(chunk)
        own.received.append(total)
        sock.close()

    up = _Upstream(behaviour)
    try:
        with _serving(StreamHatch(splice_tcp('127.0.0.1', up.port), name='u', grace=2.0)) as hatch:
            conn = _dial(hatch, timeout=60)
            assert conn.recv(64) == b'BANNER\n'
            up.ready.wait(10)
            sent = 0
            block = b'z' * 65536
            while sent < payload:
                # Deliberately slower than `grace`, so a relay that treated the
                # upstream's FIN as the end of the exchange would truncate this.
                conn.sendall(block)
                sent += len(block)
                time.sleep(0.08)
            conn.shutdown(socket.SHUT_WR)
            assert _wait_until(lambda: bool(up.received), timeout=30)
            conn.close()
    finally:
        up.close()
    assert up.received, 'the upstream never finished reading'
    assert up.received[0] == sent, f'upstream got {up.received[0]} of {sent} bytes'


def test_relay_threads_do_not_leak() -> None:
    """A guest holding its half open in silence must not park a relay thread.

    ``close()`` does not wake a thread already inside ``recv`` on Linux; only
    ``shutdown`` does, and without it such a connection parks a thread for ever
    while ``max_conns`` bounds none of it, the slot having been released.
    """

    def parked() -> int:
        return len([t for t in threading.enumerate() if t.name == _RELAY_THREAD and t.is_alive()])

    def behaviour(_own: _Upstream, sock: socket.socket) -> None:
        sock.sendall(b'hi')
        sock.shutdown(socket.SHUT_WR)
        with contextlib.suppress(OSError):
            while sock.recv(65536):
                pass
        sock.close()

    held = []
    ups = []
    try:
        for _ in range(8):
            up = _Upstream(behaviour)
            ups.append(up)
            hatch = StreamHatch(splice_tcp('127.0.0.1', up.port), name='u', max_conns=2, grace=0.5)
            hatch.start()
            conn = _dial(hatch)
            assert conn.recv(8) == b'hi'
            held.append((hatch, conn))
        for hatch, conn in held:
            hatch.close()
            conn.close()
        assert _wait_until(lambda: parked() == 0), f'{parked()} relay threads still parked'
    finally:
        for up in ups:
            up.close()


def test_the_verdict_is_disposed_of_once() -> None:
    """A closed upstream socket must not be closed twice, nor left open."""
    left, right = socket.socketpair()
    verdict = Upstream(right)
    verdict.dispose(0.5)
    verdict.dispose(0.5)
    assert right.fileno() == -1, 'the upstream socket was not closed'
    left.close()


def test_a_verdict_relays_one_connection_only() -> None:
    """A cached verdict must not be relayed twice; the second claim is refused."""
    left, right = socket.socketpair()
    verdict = Upstream(right)
    try:
        assert verdict._claim() is True
        assert verdict._claim() is False
    finally:
        verdict.dispose(0.5)
        left.close()
