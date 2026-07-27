"""In-sandbox entrypoint for `Sandbox.run_python`.

Runs *inside* the bubblewrap sandbox, so it is stdlib-only. It applies the
process-count limit (a fork-bomb backstop set here rather than via a fork-time
callback in the host) and then execs the guest code.

The guest reaches the hatch by dialing the bound Unix socket with an ordinary
gRPC channel + the generated stub — that machinery lives in the guest's own
environment, not here. The socket path is exported as ``POSTERN_HATCH``.

bwrap launches this shim with ``--as-pid-1``, so it is PID 1 of the guest's PID
namespace: there is no separate bwrap process whose ``/proc/1`` the guest could
read (closing the PID-1 environ/cmdline/mem exposure — bwrap shares the guest
uid, so a same-uid guest could otherwise read and write it). As PID 1 the shim
owes the namespace a real init, so it forks the guest and reaps it plus any
orphaned descendants that reparent here, and it marks *itself* non-dumpable so
even a co-uid process the guest spawns cannot read this init's ``/proc/1``.
"""

import contextlib
import ctypes
import os
import resource
import signal
import socket
import sys
import threading
import traceback
from concurrent import futures

_PR_SET_DUMPABLE = 4  # linux/prctl.h
# Concurrent guest→hatch connections the relay services at once. A CONNECT
# tunnel holds one slot for its lifetime; excess connections queue. Bounds the
# threads a hostile guest can make PID 1 spawn by opening loopback sockets.
_RELAY_MAX_CONNS = 64


def _set_nondumpable() -> None:
    """Clear PR_SET_DUMPABLE so this process's /proc/<pid> is root-owned.

    With the dumpable flag off the kernel roots ownership of ``/proc/self`` and
    gates ``ptrace_may_access`` on CAP_SYS_PTRACE, so no same-uid process the
    guest spawns can read this init's memory/environ/maps. Best-effort: a failure
    here is not fatal (the init holds no secrets — its env is ``--clearenv``'d —
    so this is defense in depth, not the load-bearing control).
    """
    with contextlib.suppress(OSError):
        ctypes.CDLL(None, use_errno=True).prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0)


def _pump(src, dst) -> None:
    """Copy src -> dst until EOF, then half-close dst's write side."""
    try:
        while True:
            chunk = src.recv(65536)
            if not chunk:
                break
            dst.sendall(chunk)
    except OSError:
        pass
    finally:
        with contextlib.suppress(OSError):
            dst.shutdown(socket.SHUT_WR)


def _relay_conn(client, uds_path) -> None:
    """Splice one accepted loopback connection to the hatch UDS, both ways.

    The guest-side counterpart to postern.http.HttpHatch: a dumb byte pump with
    no policy of its own. HTTP_PROXY points the guest's clients at the loopback
    listener; this carries that TCP conversation to the hatch socket — the one
    channel that pierces the empty netns — where the host proxy enforces the
    allowlist. No socat/nc in the rootfs: it is stdlib sockets, nothing more.
    """
    try:
        upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        upstream.connect(uds_path)
    except OSError:
        client.close()
        return
    reverse = threading.Thread(target=_pump, args=(client, upstream), daemon=True)
    reverse.start()
    _pump(upstream, client)
    reverse.join()
    for sock in (client, upstream):
        with contextlib.suppress(OSError):
            sock.close()


def _bind_proxy_relay(host='127.0.0.1'):
    """Bind (but do not yet serve) the loopback listener for the proxy relay.

    Bound before the guest fork so its address is known for HTTP_PROXY; served
    only afterwards, in the parent, so the fork happens single-threaded (no
    relay thread's lock can be held across it) and the guest never inherits a
    live accept loop. bwrap's loopback_setup() already raised ``lo``, so binding
    127.0.0.1 needs no capability.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, 0))
    srv.listen(128)
    return srv


def _prepare_proxy_relay():
    """Pre-fork half of the relay: bind the listener and export the proxy env.

    Returns the bound (not yet serving) listener, or ``None`` when no proxy hatch
    is in play. Runs before the guest fork so HTTP_PROXY can name the port the
    guest's clients will inherit; the accept loop starts later via
    :func:`_serve_proxy_relay`, in the parent, keeping the fork single-threaded.
    """
    uds_path = os.environ.get('POSTERN_PROXY_UDS')
    if not uds_path:
        return None
    srv = _bind_proxy_relay()
    host, port = srv.getsockname()
    proxy = f'http://{host}:{port}'
    for key in ('HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy'):
        os.environ[key] = proxy
    return srv


def _serve_proxy_relay(srv, uds_path) -> None:
    """Run the relay's accept loop over ``srv`` in a daemon thread."""
    pool = futures.ThreadPoolExecutor(max_workers=_RELAY_MAX_CONNS, thread_name_prefix='postern-relay')

    def accept_loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            with contextlib.suppress(RuntimeError):
                pool.submit(_relay_conn, conn, uds_path)

    threading.Thread(target=accept_loop, daemon=True, name='postern-relay-accept').start()


def _run_guest() -> None:
    """Apply the resource backstops and execute the guest code in this process."""
    nproc = int(os.environ.get('POSTERN_NPROC') or 0)
    if nproc:
        resource.setrlimit(resource.RLIMIT_NPROC, (nproc, nproc))
    # Address-space backstop: a partial guard against a memory bomb starving the
    # co-located trusted worker (F3). It is per-process, not a true total-memory
    # bound — a cgroup memory.max set by the worker/deploy is the real fix.
    as_bytes = int(os.environ.get('POSTERN_AS') or 0)
    if as_bytes:
        resource.setrlimit(resource.RLIMIT_AS, (as_bytes, as_bytes))
    code = os.environ.get('POSTERN_CODE', '')
    exec(code, {'__name__': '__main__'})  # noqa: S102 — executing guest code is the whole point


def _guest_child(relay_srv):
    """The forked child: run the guest and exit, never returning to the reaper.

    Runs as a normal (dumpable) process; only the PID-1 init is hidden. It must
    not hold the relay's listening socket, so it drops it first. Mirrors
    `sys.exit(main())`'s status handling for the guest's own SystemExit /
    uncaught exception, but with os._exit so it never falls into the parent path.
    """
    if relay_srv is not None:
        relay_srv.close()
    try:
        _run_guest()
    except SystemExit as exc:
        code = exc.code
        os._exit(code if isinstance(code, int) else (0 if code is None else 1))
    except BaseException:  # surface the guest traceback, then exit nonzero
        traceback.print_exc()
        os._exit(1)
    os._exit(0)


def _init() -> int:
    """Run as PID 1: fork the guest, reap the namespace, return the guest's status."""
    # With an HTTP-proxy hatch the host asks the shim to front the hatch UDS with
    # a loopback→UDS relay: bind + export HTTP_PROXY pre-fork, serve post-fork.
    relay_srv = _prepare_proxy_relay()
    child = os.fork()
    if child == 0:
        _guest_child(relay_srv)
    # Now single-thread past the fork: bring the relay's accept loop up in the
    # parent (PID 1), which is non-dumpable and outlives each guest call.
    if relay_srv is not None:
        _serve_proxy_relay(relay_srv, os.environ['POSTERN_PROXY_UDS'])
    # Forward a graceful stop to the guest — PID 1 gets no default signal action,
    # so without this a SIGTERM/SIGINT would be dropped rather than reaching it.
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda s, _frame, c=child: os.kill(c, s))
    # Reap until the guest exits, absorbing any orphaned descendants reparented to
    # PID 1 along the way; leftover processes are SIGKILLed by the kernel when
    # PID 1 exits, so returning on the guest's own exit is sufficient.
    while True:
        pid, status = os.wait()
        if pid == child:
            if os.WIFEXITED(status):
                return os.WEXITSTATUS(status)
            if os.WIFSIGNALED(status):
                return 128 + os.WTERMSIG(status)
            return 1


def main() -> int:
    if os.getpid() == 1:
        _set_nondumpable()
        return _init()
    # Defensive fallback if the shim is ever launched without --as-pid-1: there is
    # no init role to play, so just run the guest in this process.
    _run_guest()
    return 0


if __name__ == '__main__':
    sys.exit(main())
