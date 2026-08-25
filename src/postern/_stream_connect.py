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


def _write_all(fd, data) -> None:
    """Write every byte of ``data`` to ``fd`` (``os.write`` may write short)."""
    while data:
        data = data[os.write(fd, data) :]


def _pump(sock) -> None:
    """Relay stdin<->``sock`` in one selector loop until both directions retire."""
    sel = selectors.DefaultSelector()
    sel.register(0, selectors.EVENT_READ)
    sel.register(sock, selectors.EVENT_READ)
    while sel.get_map():
        for key, _ in sel.select():
            if key.fileobj not in sel.get_map():
                continue  # retired by the other half of this same ready batch
            if key.fd == 0:
                chunk = os.read(0, _CHUNK)
                if chunk:
                    sock.sendall(chunk)
                else:
                    # Our input is done, but the host may still have a pack to
                    # send: half-close so its subprocess reads EOF, keep reading.
                    sel.unregister(0)
                    with contextlib.suppress(OSError):
                        sock.shutdown(socket.SHUT_WR)
            else:
                chunk = sock.recv(_CHUNK)
                if chunk:
                    _write_all(1, chunk)
                else:
                    # The host is finished; nothing more can arrive, so stop
                    # waiting on a stdin the client may never close.
                    sel.unregister(sock)
                    if 0 in sel.get_map():
                        sel.unregister(0)


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
    except OSError:
        pass  # either end vanished mid-stream; the exit status is the report
    finally:
        with contextlib.suppress(OSError):
            sock.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
