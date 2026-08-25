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

**One blocking thread per direction.** This is the only place in postern that
still copies bytes — the host side hands the socket straight to a command as its
stdio — and a thread each way is the simplest shape that can do it. The selector
loop it replaces had to be non-blocking on the socket and keep an unsent tail per
direction, and still could not poll stdout for write-readiness, because stdout is
not portably pollable: git gives us a pipe, a shell redirect gives us a regular
file, and ``epoll`` refuses the latter outright. So it wrote stdout from inside the
loop and blocked there, coupling the two directions.

Threads decouple them, though honesty requires saying by how much: a guest that
stops reading its own stdout stalls the *command* too, through the socket, so
end-to-end backpressure arrives either way and the coupling was not reachable as a
deadlock. What the rewrite actually buys is half the code, no non-blocking
bookkeeping, and one class of bug that stops existing rather than being fixed —
with no selector there is no ``epoll_ctl`` to reject a regular file or
``/dev/null``, so the silent zero-byte exit that came from registering such a stdin
is now unrepresentable rather than worked around.

Threads were tried before and abandoned because they aborted under git (``python3
died of signal 6``) when a daemon thread sat blocked in ``read`` on a descriptor
git had already torn down and the interpreter then tried to finalise. That is a
shutdown bug rather than an argument about architecture, and the fix is to not
finalise: when the socket direction is done the exchange is over by definition, so
``os._exit`` leaves immediately, with no interpreter teardown for a parked reader
to trip over.

"""

import contextlib
import os
import socket
import sys
import threading

_CHUNK = 65536


def _write_all(fd, data) -> None:
    """Write every byte of ``data`` to ``fd`` (``os.write`` may write short)."""
    while data:
        data = data[os.write(fd, data) :]


def _stdin_to_socket(sock) -> None:
    """Copy stdin -> socket, then half-close so the host's command reads EOF."""
    try:
        while True:
            chunk = os.read(0, _CHUNK)
            if not chunk:
                break
            sock.sendall(chunk)
    except OSError:
        pass  # git tore our stdin down, or the host went away
    finally:
        # Our input is done, but the host may still have a pack to send: half-close
        # rather than close, and let the other direction run to its own end.
        with contextlib.suppress(OSError):
            sock.shutdown(socket.SHUT_WR)


def _socket_to_stdout(sock) -> int:
    """Copy socket -> stdout until the host is finished. Returns an exit status."""
    try:
        while True:
            chunk = sock.recv(_CHUNK)
            if not chunk:
                return 0
            _write_all(1, chunk)
    except BrokenPipeError:
        return 0  # git closed our stdout; a normal end, not a failure
    except OSError as exc:
        print(f'connect.py: stream failed: {exc}', file=sys.stderr)
        return 1


def main() -> int:
    if len(sys.argv) != 2:
        print('usage: connect.py <socket-path>', file=sys.stderr)
        return 2
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(sys.argv[1])
    except OSError as exc:
        print(f'connect.py: cannot reach the hatch: {exc}', file=sys.stderr)
        return 1
    threading.Thread(target=_stdin_to_socket, args=(sock,), daemon=True).start()
    status = _socket_to_stdout(sock)
    # The host has closed its end, so nothing more can arrive and the exchange is
    # over whatever stdin is doing. Leave without finalising the interpreter: the
    # stdin reader may be parked in read() on a descriptor git has already closed,
    # and joining or finalising around that is what used to abort under git.
    sys.stderr.flush()
    os._exit(status)


if __name__ == '__main__':
    sys.exit(main())
