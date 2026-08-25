"""In-sandbox connector for a stream hatch: splice this process's stdio to the UDS.

Runs *inside* the sandbox (stdlib-only, no import of the postern package). It is
the guest-side half of `postern.stream.StreamHatch`: a dumb byte pump with no
policy of its own, every decision having been made host-side. Bound in at
``/run/postern/connect.py`` and named by ``$POSTERN_CONNECT`` whenever a stream
hatch is configured; it takes the guest socket path as its one argument:

    git -c protocol.ext.allow=always clone 'ext::python3 /run/postern/connect.py /run/postern/git.sock'

It exists because the protocols a stream hatch carries reach a *byte stream*, not
a socket: git's native wire protocol runs over an ``ext::`` helper's stdin/stdout,
so something has to carry that conversation to the one file descriptor that
pierces the empty netns. Nothing is sent ahead of the payload — no service name,
no repository, no handshake. That is deliberate: the socket already *is* the
capability (the host bound one socket per resource), so there is nothing for the
guest to name and nothing for the host to parse.

Single-threaded on purpose. A two-thread pump aborts under git (``python3 died of
signal 6`` at interpreter shutdown, when one thread is blocked in ``read`` on a
fd git has already torn down); one selector loop over both directions has no such
window. Half-closes propagate: stdin EOF becomes ``shutdown(SHUT_WR)`` on the
socket so the host's subprocess sees a real EOF, and socket EOF retires both
directions so the pump exits rather than blocking on a stdin that will never
close.
"""

import contextlib
import os
import selectors
import signal
import socket
import sys

_CHUNK = 65536


def _selector():
    """A selector that accepts regular files and character devices.

    Not ``DefaultSelector``: on Linux that is ``EpollSelector``, and ``epoll_ctl``
    rejects regular files and ``/dev/null`` with ``EPERM``. Registering stdin then
    raised ``PermissionError`` — an ``OSError`` — which ``main`` swallowed before
    returning 0, so any invocation whose stdin was not a pipe reported success
    having moved nothing. The sandbox hands entrypoints ``stdin=DEVNULL``, so
    ``python3 $POSTERN_CONNECT $SOCK > out.bin`` hit exactly that. Two descriptors
    make ``select``'s ceiling irrelevant.
    """
    for name in ('PollSelector', 'SelectSelector'):
        impl = getattr(selectors, name, None)
        if impl is not None:
            return impl()
    return selectors.DefaultSelector()


class _Half:
    """One direction of the relay: read from ``src``, write to ``dst``.

    Holds its own unsent ``tail``. That is the whole point: a blocking
    ``sendall``/``write`` inside the selector loop stops the *other* direction
    being serviced, and on a full-duplex bulk exchange that deadlocks the entire
    cycle -- the connector parks in send, so the host's forward pump fills the
    socket buffer and blocks, the command's stdout pipe fills, the command stops
    reading stdin, the host's reverse pump stops reading the socket, and the
    connector's send can never complete. 64 MiB through `cat` moved 10 MiB and
    wedged. Only git's mostly half-duplex phases hid it.
    """

    def __init__(self, src, dst, on_eof=None):
        self.src = src
        self.dst = dst
        self.tail = b''
        self.reading = True
        self.on_eof = on_eof

    @property
    def done(self):
        return not self.reading and not self.tail

    def read(self):
        """Take what is available; returns False at end of input."""
        chunk = _read(self.src)
        if chunk:
            self.tail += chunk
            return True
        self.reading = False
        if self.on_eof is not None and not self.tail:
            self.on_eof()
        return False

    def flush(self):
        """Write what we can without blocking; fires ``on_eof`` once drained."""
        if self.tail:
            self.tail = self.tail[_write(self.dst, self.tail) :]
        if not self.tail and not self.reading and self.on_eof is not None:
            self.on_eof()


def _read(src):
    if isinstance(src, int):
        return os.read(src, _CHUNK)
    return src.recv(_CHUNK)


def _write(dst, data):
    if isinstance(dst, int):
        return os.write(dst, data)
    return dst.send(data)


def _pump(sock) -> None:
    """Relay stdin<->``sock`` in one selector loop until both directions retire."""
    sock.setblocking(False)

    def half_close():
        # Our input is done, but the host may still have a pack to send: half-close
        # so its subprocess reads EOF, and keep reading.
        with contextlib.suppress(OSError):
            sock.shutdown(socket.SHUT_WR)

    out = _Half(0, sock, on_eof=half_close)  # stdin -> socket
    back = _Half(sock, 1)  # socket -> stdout
    sel = _selector()
    try:
        while not (out.done and back.done):
            sel_map = _interest(out, back, sock)
            _reregister(sel, sel_map)
            if not sel_map:
                break
            for key, mask in sel.select():
                if key.fileobj is sock and mask & selectors.EVENT_WRITE:
                    out.flush()
                if not mask & selectors.EVENT_READ:
                    continue
                half = out if key.fd == 0 else back
                if half.read() and half is back:
                    # stdout is not portably pollable (git gives us a pipe, a
                    # redirect gives us a file), so drain it here and now.
                    while back.tail:
                        back.flush()
            if not back.reading and back.done and out.reading:
                # The host is finished; nothing more can arrive, so stop waiting on
                # a stdin the client may never close.
                out.reading = False
                out.tail = b''
    finally:
        sel.close()


def _interest(out, back, sock):
    """What we want to hear about next, which is also the backpressure rule.

    stdin is worth reading only while we are not already holding a backlog for the
    socket, and vice versa: whoever has an unsent tail waits for writability
    instead of taking on more.
    """
    wanted = {}
    if out.reading and not out.tail:
        wanted[0] = selectors.EVENT_READ
    if back.reading:
        wanted[sock] = selectors.EVENT_READ
    if out.tail:
        wanted[sock] = wanted.get(sock, 0) | selectors.EVENT_WRITE
    return wanted


def _reregister(sel, wanted) -> None:
    """Make the selector's registrations exactly ``wanted``."""
    for key in list(sel.get_map().values()):
        if key.fileobj not in wanted:
            with contextlib.suppress(KeyError, OSError):
                sel.unregister(key.fileobj)
    for fileobj, events in wanted.items():
        try:
            sel.modify(fileobj, events)
        except KeyError:
            sel.register(fileobj, events)


def main() -> int:
    if len(sys.argv) != 2:
        print('usage: connect.py <socket-path>', file=sys.stderr)
        return 2
    # Die on SIGPIPE like any pipe filter instead of raising: when git tears down
    # the helper it closes our stdout, and a Python traceback on the way out would
    # be mistaken for a protocol error.
    with contextlib.suppress(AttributeError, ValueError):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(sys.argv[1])
    except OSError as exc:
        print(f'connect.py: cannot reach the hatch: {exc}', file=sys.stderr)
        return 1
    try:
        _pump(sock)
    except BrokenPipeError:
        pass  # git tore our stdout down; that is a normal end, not a failure
    except OSError as exc:
        # Not `pass`: swallowing this and returning 0 reported success for a pump
        # that moved nothing, which is how the epoll registration failure above
        # stayed invisible.
        print(f'connect.py: stream failed: {exc}', file=sys.stderr)
        return 1
    finally:
        with contextlib.suppress(OSError):
            sock.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
