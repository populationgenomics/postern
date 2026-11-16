"""Port forwards: a TCP port inside the guest, served by a handler process on the host.

A `PortForward` names a port in the guest and the *handler* that serves it: a host
process the caller runs, listening on a Unix socket of its own (the handler's
*control socket*). For each launch postern opens a listening TCP socket on that
port inside the guest's network namespace, from the host, and hands it to the
handler over the control socket. The handler accepts the guest's connections on
it directly: no byte passes through postern or through a relay in the guest, and
nothing of postern runs in the guest to serve the port.

    from postern import Sandbox
    from postern.forward import PortForward, Receiver

    # The handler, in a process of its own:
    with Receiver('/run/files/control.sock') as receiver:
        while True:
            handoff = receiver.receive()          # one per launch
            threading.Thread(target=serve, args=(handoff,)).start()

    def serve(handoff):
        with handoff:
            while (conn := handoff.accept()) is not None:   # None once the launch ends
                ...                                         # an ordinary TCP connection

    # The worker:
    sandbox = Sandbox(profile, forwards=[PortForward(8080, '/run/files/control.sock')])
    sandbox.run(['curl', 'http://127.0.0.1:8080/x'])

The handler learns a launch has ended when postern closes that launch's control
connection, which it does when the run is closed. A guest's namespace going away
does not close a socket in it, so without that signal a handler would hold every
launch's listener for good.

Trust model
-----------
Every byte on an accepted connection is the guest's: the handler is a server for
untrusted clients, and what it can reach is what the guest can reach. The listener
is the capability. It lives in one launch's namespace, so only that launch's guest
can connect to it, and a handler serving several launches tells them apart by the
`Handoff` a connection arrived on. The control socket is the handler's own: postern
connects to it, and anything else that can reach that path can hand the handler
listeners too, so its directory should admit only the worker.
"""

from __future__ import annotations

import array
import dataclasses
import os
import select
import socket
import typing

from postern import _process

if typing.TYPE_CHECKING:
    # typing_extensions is not a runtime dependency: `typing.Self` is 3.11+ and
    # the floor is 3.10, so the backport must stay behind this guard.
    import typing_extensions

# What postern sends on a control connection besides the listener: the guest port, in decimal ASCII.
_MAX_MESSAGE = 5
# How long a control connection may take to deliver its handoff; postern sends it whole on connecting.
_HANDOFF_TIMEOUT_S = 10.0


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
        listener: The listening socket, in the guest's network namespace.
        control: The launch's control connection. It turns readable, at end of
            stream, when the launch ends; an event loop can watch it for that.
    """

    def __init__(self, guest_port: int, listener: socket.socket, control: socket.socket) -> None:
        self.guest_port = guest_port
        self.listener = listener
        self.control = control

    def accept(self) -> socket.socket | None:
        """Wait for the guest's next connection.

        Returns:
            The connection, blocking. None once the launch has ended: a connection
            that arrived and was not yet taken by then is closed with the listener.

        Raises:
            ValueError: If postern sent anything more on the control connection.
        """
        poller = select.poll()
        poller.register(self.listener, select.POLLIN)
        poller.register(self.control, select.POLLIN)
        while True:
            ready = {fd for fd, _ in poller.poll()}
            if self.control.fileno() in ready:
                if self.control.recv(1):
                    raise ValueError('unexpected bytes on a port forward control connection')
                return None
            try:
                connection, _ = self.listener.accept()
            except BlockingIOError:
                continue  # taken by another thread accepting on the same listener
            connection.setblocking(True)
            return connection

    def close(self) -> None:
        """Close the listener and the control connection. Idempotent."""
        self.listener.close()
        self.control.close()

    def __enter__(self) -> typing_extensions.Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


class Receiver:
    """A handler's control socket: where postern hands it each launch's listener.

    Binds ``path`` on construction, with the process's umask; the caller decides
    who may reach it through the directory it lies in. Use it as a context
    manager, or call :meth:`close`, which also removes the socket file.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = os.fspath(path)
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self._socket.bind(self.path)
            self._socket.listen()
        except BaseException:
            self._socket.close()
            raise

    def receive(self) -> Handoff:
        """Wait for postern's next launch and take its listener.

        Returns:
            The launch's `Handoff`, which the caller now owns.

        Raises:
            ValueError: If the control connection did not carry exactly one
                listening TCP socket and a guest port.
            TimeoutError: If it carried nothing within a bounded time.
        """
        control, _ = self._socket.accept()
        try:
            control.settimeout(_HANDOFF_TIMEOUT_S)
            handoff = _take(control)
            control.settimeout(None)
            return handoff
        except BaseException:
            control.close()
            raise

    def close(self) -> None:
        """Stop listening and remove the socket file. Idempotent."""
        if self._socket.fileno() >= 0:
            self._socket.close()
            os.unlink(self.path)

    def __enter__(self) -> typing_extensions.Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def _take(control: socket.socket) -> Handoff:
    """Read one handoff from ``control``: a guest port and its listener."""
    message, fds, cut = _process.recv_fds(control, _MAX_MESSAGE, 1)
    if len(fds) != 1 or cut or not message.isdigit() or _more_queued(control):
        for fd in fds:
            os.close(fd)
        raise ValueError(f'malformed port forward handoff: {message!r} with {len(fds)} descriptors')
    listener = socket.socket(fileno=fds[0])
    if (
        listener.family not in (socket.AF_INET, socket.AF_INET6)
        or listener.type != socket.SOCK_STREAM
        or listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
    ):
        listener.close()
        raise ValueError('a port forward handoff carried something other than a listening TCP socket')
    listener.setblocking(False)
    return Handoff(int(message), listener, control)


def _more_queued(control: socket.socket) -> bool:
    """Whether ``control`` holds bytes past the handoff: postern sends nothing more."""
    # Non-blocking for the peek: under a timeout, Python waits for readability before recv whatever its flags.
    timeout = control.gettimeout()
    control.setblocking(False)
    try:
        return bool(control.recv(1, socket.MSG_PEEK))
    except BlockingIOError:
        return False
    finally:
        control.settimeout(timeout)


def hand_over(forward: PortForward, listener: socket.socket, *, timeout: float) -> socket.socket:
    """Send ``listener`` to ``forward``'s handler; the returned control connection is the launch's to close.

    Raises:
        ConnectionError: If the handler's control socket cannot be reached in ``timeout`` seconds.
    """
    control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        control.settimeout(timeout)
        try:
            control.connect(os.fspath(forward.handler))
            control.sendmsg(
                [str(forward.guest_port).encode('ascii')],
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
