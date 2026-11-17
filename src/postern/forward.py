"""Port forwards: a TCP port inside the guest, served by a handler process on the host.

A `PortForward` names a port in the guest and the *handler* that serves it: a host
process the caller runs, listening on a Unix socket of its own (the handler's
*control socket*). For each launch postern opens a listening TCP socket on that
port inside the guest's network namespace, from the host, and hands it to the
handler over the control socket. The handler accepts the guest's connections on
it directly: no byte passes through postern or through a relay in the guest, and
nothing of postern runs in the guest to serve the port.

    import threading

    from postern import Sandbox
    from postern.forward import HandoffError, PortForward, Receiver

    # The handler, in a process of its own:
    with Receiver('/run/files/control.sock') as receiver:
        while True:
            try:
                handoff = receiver.receive()      # one per launch
            except HandoffError:
                continue                          # one bad control connection, not the receiver
            threading.Thread(target=serve, args=(handoff,)).start()

    def serve(handoff):
        with handoff:
            while (conn := handoff.accept()) is not None:   # None once the launch ends
                ...                                         # an ordinary TCP connection

    # The worker:
    sandbox = Sandbox(profile, forwards=[PortForward(8080, '/run/files/control.sock')])
    sandbox.run(['curl', 'http://127.0.0.1:8080/x'], launch_token=b'launch-17')   # handoff.token

The handler learns a launch has ended when postern closes that launch's control
connection, which it does when the run is closed. A guest's namespace going away
does not close a socket in it, so without that signal a handler would hold every
launch's listener for good.

`Handoff.accept` is for a handler with a thread per launch: it polls the listener
and the control connection, and accepts from the listener once a connection waits
there. A handler on an event loop uses neither: it registers `Handoff.listener`
with its loop to accept connections, and `Handoff.control` to learn the launch
has ended (postern closed it), then closes the handoff.

Trust model
-----------
Every byte on an accepted connection is the guest's: the handler is a server for
untrusted clients, and what it can reach is what the guest can reach. The listener
is the capability. It lives in one launch's namespace, so only that launch's guest
can connect to it, and connections from two launches arrive on two `Handoff`s.

A `Handoff` says which launch a connection came from, not whose: it carries the
guest port, and the token the caller gave the launch (``launch_token`` on
`Sandbox.run` and the other launch methods; empty if it gave none). postern
chooses nothing in it and checks nothing of its meaning, and anything that can
reach the control socket can send any token. So a token names a launch for a handler that
already trusts its control socket: one serving several launches at once can tell
their listeners apart, or look the token up in what the caller registered with it
before the launch. It is not a credential. One control socket grants the same
authority to every launch pointed at it. Where launches differ in what they may
reach (one session's files, say, and another's), give each scope a `Receiver` of
its own, and the handler behind it only that scope's authority.

The control socket is the handler's own: postern connects to it, and anything else
that can reach it can hand the handler listeners too. `Receiver` makes it mode
0600 by default, and its directory should admit only the worker.

Each accepted connection is a descriptor in the handler's process, and the guest
decides how many it opens. Bound the connections served per `Handoff`: a handler
that runs out of descriptors waits, in `accept` and in `receive`, for some to free.

The listener is dual-stack, so a guest connecting to 127.0.0.1 arrives as an IPv6
socket from ``::ffff:127.0.0.1``. The peer address says nothing the listener does
not: every connection on it is that launch's guest.
"""

from __future__ import annotations

import array
import contextlib
import dataclasses
import errno
import os
import select
import socket
import struct
import threading
import time
import typing

from postern import _process

if typing.TYPE_CHECKING:
    # typing_extensions is not a runtime dependency: `typing.Self` is 3.11+ and
    # the floor is 3.10, so the backport must stay behind this guard.
    import typing_extensions

MAX_TOKEN = 256
# What postern sends on a control connection, as one message with the listener: this header (the guest port and the
# token's length), then the token.
_FRAME_HEADER = struct.Struct('>HH')
# How long a control connection may take to deliver its handoff; postern sends it whole on connecting.
_HANDOFF_TIMEOUT_S = 10.0
# Linux's: a peer's shutdown(SHUT_WR), which a hang-up's POLLHUP does not report.
_POLLRDHUP = typing.cast('int', getattr(select, 'POLLRDHUP', 0))
# The pause before accepting again while this process is out of descriptors.
_ACCEPT_RETRY_S = 0.05


class HandoffError(Exception):
    """A control connection did not carry a handoff: refused, and the `Receiver` serves on."""


@dataclasses.dataclass(frozen=True)
class PortForward:
    """Serve ``guest_port`` on the guest's loopback with the handler listening at ``handler``.

    Attributes:
        guest_port: The TCP port, 1 to 65535. Postern opens it from the host, so a
            port below 1024 needs no capability in the guest.
        handler: The handler's control socket, a Unix socket a `Receiver` listens on.
    """

    guest_port: int
    handler: str | os.PathLike[str]

    def __post_init__(self) -> None:
        if isinstance(self.guest_port, bool) or not isinstance(self.guest_port, int):
            raise TypeError(f'PortForward.guest_port must be an int, got {self.guest_port!r}')
        if not 1 <= self.guest_port <= 65535:
            raise ValueError(f'PortForward.guest_port must be 1 to 65535, got {self.guest_port}')


class Handoff:
    """One launch's listener for one forward, as its handler receives it.

    Use it as a context manager, or call :meth:`close`: it holds the listener and
    the launch's control connection.

    Attributes:
        guest_port: The port the guest connects to.
        token: The token the caller gave the launch, as it gave it; empty where it
            gave none. Anything that can reach the control socket can send any
            token: it names the launch for a handler, and proves nothing.
        listener: The listening socket, in the guest's network namespace,
            non-blocking. Readable when a guest connection waits to be accepted.
        control: The launch's control connection. Readable, closed by postern,
            when the launch ends. An event loop watches it for that, and the listener
            for connections, in place of :meth:`accept`.
    """

    def __init__(self, guest_port: int, listener: socket.socket, control: socket.socket, token: bytes = b'') -> None:
        """Hold one launch's ``listener`` and ``control`` connection for ``guest_port``.

        Raises:
            TypeError: If ``token`` is not bytes.
            ValueError: If ``token`` is longer than `MAX_TOKEN`.
        """
        check_token(token)
        self.guest_port = guest_port
        self.token = token
        self.listener = listener
        self.control = control
        # close() frees the descriptors only once no accept() is polling them, so none polls a reused number.
        self._lock = threading.Lock()
        self._waiting = 0
        self._closing = False

    def accept(self) -> socket.socket | None:
        """Wait for the guest's next connection, for a handler with a thread per launch.

        Polls the listener and the control connection, and accepts from the
        listener once a connection waits there. A connection lost between the poll
        and the accept, taken by another thread or reset by the guest, is waited
        past, as is this process running out of descriptors.

        Returns:
            The connection, blocking. None once the launch has ended, or the
            handoff was closed: a connection that arrived and was not yet taken by
            then is closed with the listener.

        Raises:
            ValueError: If a message followed the handoff on the control connection.
        """
        with self._lock:
            if self._closing:
                return None
            self._waiting += 1
        try:
            return self._wait()
        finally:
            with self._lock:
                self._waiting -= 1
                release = self._closing and not self._waiting
            if release:
                self._release()

    def _wait(self) -> socket.socket | None:
        poller = select.poll()
        poller.register(self.listener, select.POLLIN)
        poller.register(self.control, select.POLLIN)
        while True:
            events = dict(poller.poll())
            if self._closing:
                return None
            if self.control.fileno() in events:
                if _more_queued(self.control):
                    raise ValueError('unexpected message on a port forward control connection')
                return None
            connection = self._try_accept()
            if connection is not None:
                return connection

    def _try_accept(self) -> socket.socket | None:
        """The next connection, or None to wait again."""
        try:
            connection, _ = self.listener.accept()
        except (BlockingIOError, ConnectionAbortedError):
            return None  # taken by another thread, or the guest's dial died in the handshake
        except OSError as exc:
            if exc.errno not in (errno.EMFILE, errno.ENFILE):
                raise
            time.sleep(_ACCEPT_RETRY_S)  # out of descriptors here; the guest's dial waits in the backlog
            return None
        connection.setblocking(True)
        return connection

    def close(self) -> None:
        """Close the listener and the control connection, ending any :meth:`accept` waiting on them. Idempotent."""
        with self._lock:
            if self._closing:
                return
            self._closing = True
            # poll() does not wake for a descriptor closed under it; a hang-up on the control connection does.
            with contextlib.suppress(OSError):
                self.control.shutdown(socket.SHUT_RDWR)
            release = not self._waiting
        if release:
            self._release()

    def _release(self) -> None:
        self.listener.close()
        self.control.close()

    def __enter__(self) -> typing_extensions.Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


class Receiver:
    """A handler's control socket: where postern hands it each launch's listener.

    An ``AF_UNIX`` ``SOCK_SEQPACKET`` socket, so a handoff arrives as one message,
    whole or not at all; a stream connection is refused. Binds ``path`` on
    construction and sets its ``mode``, 0600 by default: postern connects as the
    worker, so widen it only for a worker at another uid. The directory it lies in
    decides who may reach it as well. Use it as a context manager, or call
    :meth:`close`, which also removes the socket file.
    """

    def __init__(self, path: str | os.PathLike[str], *, mode: int = 0o600) -> None:
        self.path = os.fspath(path)
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            self._socket.bind(self.path)
            os.chmod(self.path, mode)
            self._socket.listen()
        except BaseException:
            self._socket.close()
            raise

    def receive(self) -> Handoff:
        """Wait for postern's next launch and take its listener.

        Returns:
            The launch's `Handoff`, which the caller now owns.

        Raises:
            HandoffError: If a control connection did not carry exactly one
                listening TCP socket and one whole frame of this format (guest
                port and launch token) within a bounded time, or failed while it
                was read. Only that connection is refused.
            OSError: If the receiver itself cannot accept: closed, say. Running
                out of descriptors is waited out, not raised.
        """
        control = self._accept()
        try:
            control.settimeout(_HANDOFF_TIMEOUT_S)
            handoff = _take(control)
            control.settimeout(None)
        except (ValueError, OSError) as exc:
            control.close()
            raise HandoffError(f'refused a control connection: {exc}') from exc
        except BaseException:
            control.close()
            raise
        return handoff

    def _accept(self) -> socket.socket:
        while True:
            try:
                control, _ = self._socket.accept()
            except ConnectionAbortedError:
                continue
            except OSError as exc:
                if exc.errno not in (errno.EMFILE, errno.ENFILE):
                    raise
                # Out of descriptors, which guests' connections can cause: wait, not end every launch's handoffs.
                time.sleep(_ACCEPT_RETRY_S)
                continue
            return control

    def close(self) -> None:
        """Stop listening and remove the socket file, ending a :meth:`receive` waiting here. Idempotent."""
        if self._socket.fileno() >= 0:
            # close() does not wake a blocked accept(), which keeps the descriptor number it reserved; shutdown does.
            with contextlib.suppress(OSError):
                self._socket.shutdown(socket.SHUT_RDWR)
            self._socket.close()
            os.unlink(self.path)

    def __enter__(self) -> typing_extensions.Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def _take(control: socket.socket) -> Handoff:
    """Read one handoff from ``control``: a guest port, the launch's token and its listener."""
    received, fds, cut = _process.recv_fds(control, _FRAME_HEADER.size + MAX_TOKEN, 1)
    try:
        parsed = None if len(fds) != 1 or cut or _more_queued(control) else _parse(received)
        if parsed is None:
            raise ValueError(f'malformed port forward handoff: {len(received)} bytes with {len(fds)} descriptors')
    except BaseException:
        for fd in fds:
            os.close(fd)
        raise
    port, token = parsed
    try:
        listener = socket.socket(fileno=fds[0])
    except OSError:
        os.close(fds[0])
        raise
    if (
        listener.family not in (socket.AF_INET, socket.AF_INET6)
        or listener.type != socket.SOCK_STREAM
        or listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
    ):
        listener.close()
        raise ValueError('a port forward handoff carried something other than a listening TCP socket')
    listener.setblocking(False)
    return Handoff(port, listener, control, token=token)


def _parse(message: bytes) -> tuple[int, bytes] | None:
    """The guest port and token of a handoff ``message``, or None if it is not one of this format."""
    if len(message) < _FRAME_HEADER.size:
        return None
    port, length = _FRAME_HEADER.unpack_from(message)
    if not 1 <= port <= 65535 or len(message) != _FRAME_HEADER.size + length:
        return None
    return port, message[_FRAME_HEADER.size :]


def check_token(token: bytes) -> None:
    """Raise unless ``token`` is one a launch may carry: bytes, at most `MAX_TOKEN` of them.

    Raises:
        TypeError: If ``token`` is not bytes (a bytearray or memoryview included).
        ValueError: If it is longer than `MAX_TOKEN`.
    """
    if not isinstance(token, bytes):
        raise TypeError(f'a launch token is bytes, got {type(token).__name__}')
    if len(token) > MAX_TOKEN:
        raise ValueError(f'a launch token is at most {MAX_TOKEN} bytes, got {len(token)}')


def _more_queued(control: socket.socket) -> bool:
    """Whether a message waits on ``control`` past the handoff, which postern never sends."""
    poller = select.poll()
    poller.register(control, select.POLLIN | _POLLRDHUP)
    events = sum(revents for _, revents in poller.poll(0))
    if not events & select.POLLIN:
        return False
    if not events & (select.POLLHUP | _POLLRDHUP):
        return True  # the peer can still send, so this is a message: an empty one reads as b'', as a hang-up does
    # Hung up, so the launch has ended. An empty message before the hang-up cannot be told from it, and ends nothing
    # that has not ended; one with bytes in it is refused.
    return bool(control.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT))


def hand_over(forward: PortForward, listener: socket.socket, *, timeout: float, token: bytes = b'') -> socket.socket:
    """Send ``listener`` and the launch's ``token`` to ``forward``'s handler.

    The returned control connection is the launch's to close.

    Raises:
        TypeError: If ``token`` is not bytes.
        ValueError: If ``token`` is longer than `MAX_TOKEN`.
        ConnectionError: If the handler's control socket cannot be reached in
            ``timeout`` seconds.
    """
    check_token(token)
    message = _FRAME_HEADER.pack(forward.guest_port, len(token)) + token
    control = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        control.settimeout(timeout)
        try:
            control.connect(os.fspath(forward.handler))
            control.sendmsg(  # one seqpacket message: sent whole or not at all
                [message],
                [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [listener.fileno()]))],
            )
        except OSError as exc:
            raise ConnectionError(
                f'port forward {forward.guest_port}: cannot hand the listener to {os.fspath(forward.handler)!r}: {exc}'
            ) from exc
        control.settimeout(None)
    except BaseException:
        control.close()
        raise
    return control
