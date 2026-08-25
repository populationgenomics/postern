"""The stream hatch: a raw bidirectional byte stream over the sandbox UDS.

Where `GrpcHatch` grants the guest a set of typed methods, `StreamHatch` gives it
**one socket** and nothing else. Per accepted connection a handler you supply
decides what the guest's bytes are spliced to — a host-side subprocess's stdio,
an upstream socket, or nothing.

    handler(stream) -> Process | None

* ``stream`` — the accepted connection (``stream.conn``) and the name of the
  hatch it arrived on (``stream.hatch``).
* return `Process` to hand the connection to a subprocess as its stdin and
  stdout, or ``None`` to refuse (the guest sees EOF).
* the hatch owns the *lifecycle* after the verdict — waiting for the command, then
  terminate-then-kill teardown and reaping the process group. It does not own the
  data path: the socket **is** the command's stdio, so the kernel moves the bytes.

This exists for the protocols that are neither typed RPC nor request/response.
The motivating case is **git**: git's native wire protocol is pkt-line over a raw bidirectional
stream, and `ext::` carries it over a command's stdin/stdout, so a byte pump
reaches a UDS (`postern._stream_connect`, bound into the guest as
``$POSTERN_CONNECT``, is that pump).

    from postern import Sandbox, SandboxProfile
    from postern.stream import StreamHatch, git_url, splice_subprocess

    hatch = StreamHatch(splice_subprocess(['git', 'upload-pack', '/srv/repo.git']), name='repo')
    sandbox = Sandbox(SandboxProfile(), hatch=hatch)
    sandbox.run(['git', '-c', 'protocol.ext.allow=always', 'clone', git_url('repo'), 'work'])

**Why a socket and not a brokered HTTP proxy.** git can be reached through an
HTTP forward proxy with a host-side handler policing each request, and that works.
A bound stream socket is better in four ways, and the first is the whole reason
this module exists:

1. *Capability by descriptor, not policy by parser.* Through a proxy the guest
   names a URL, so "only this one repository" means parsing and validating
   request targets in a handler — a parser sitting in the policy path, fed
   attacker-controlled input. Here the socket **is** the capability: one socket
   per resource makes the wrong resource unrepresentable, and nothing parses
   anything. The service is fixed too — a hatch bound to ``git upload-pack``
   cannot be talked into ``receive-pack``, so read-only is read-only by
   construction rather than by a rule about verbs.
2. *No body buffering, and no copying at all.* A proxy that lets a handler inspect
   request bodies has to buffer them, and therefore has to cap them. Here the
   socket **is** the command's stdin and stdout, so the kernel moves every byte and
   this process is not on the data path: no ceiling, no cap to tune, no pump.

   That is not only simpler, it is more truthful. A pump has to decide when an
   exchange is over and how to end it, and both decisions were wrong in ways the
   kernel gets right for nothing. Draining before close suppresses ``ECONNRESET``
   — correct when the reset would be our own teardown artifact, and wrong when the
   command died mid-request, because then the reset is the only failure signal a
   stream with no framing of its own has. With the socket as stdio the kernel
   propagates the command's disposition exactly: a command that consumed its input
   and exited leaves an empty receive queue and the guest reads end-of-stream,
   while one that died mid-request leaves the remainder queued and the guest reads
   a reset (measured both ways).
3. *No protocol translation.* The host side is "run a subprocess, splice its
   stdio" rather than a bridge that must decode chunked framing and re-emit
   headers to reach the same subprocess.
4. *It works with `Sandbox.run`.* A dial hatch needs no in-guest relay — the
   socket is just a file — so a bare ``git`` entrypoint reaches it, not only a
   `run_python` guest. A proxy has to be fronted by something inside the guest
   that speaks TCP, which a raw entrypoint has no way to start.

Trust model: every byte the guest sends is attacker-controlled, and here those
bytes are handed to a host-side process. The batteries are built so guest input
can only ever be a subprocess's **stdin** — never its argv, env, cwd, or the
destination of a dial, all of which are fixed when the hatch is constructed. That
is the whole reason to prefer a socket per resource over a parser. `Process` also
defaults its subprocess to a scrubbed environment and a discarded stderr, because
both are host state the guest must not read (see `splice_subprocess`). Stdlib-only
— no extra to install.

What the socket itself tells the guest: nothing useful. It arrives at
``/run/postern/<name>.sock``, so the host-side path is not in the environment, and
``SO_PEERCRED`` from inside reads ``(0, 65534, 65534)`` — the host process's pid is
not mapped into the guest's pid namespace and its uid is not mapped into the
guest's user namespace, so both come back as the unmapped placeholders. (The host
*path* is still visible in ``/proc/self/mountinfo``, as every bwrap bind source is,
including the workspace's; that is a pre-existing property of binding anything in,
not of this hatch, and it is an information leak rather than a reachable path.)

An unbounded number of connections buys a hostile guest very little: ``max_conns``
gates *accepting*, so beyond the cap its dials sit in the kernel backlog costing
the host no descriptors, and past the backlog they are simply refused. What it can
do is hold ``max_conns`` slots — and each slot's subprocess — for as long as its
connections live, so size the cap for the workload and rely on the outer
``Sandbox.run(timeout=...)`` as the backstop that EOFs every connection at once.

That backstop is only a backstop if a dead guest actually frees the slot, which
takes two things beyond the EOF: teardown that signals the command's whole
*process group* (a background child it left behind would otherwise keep the
stdout pipe open, so the splice would wait for an EOF that can never come), and a
forward pump that stops waiting on that pipe once the command itself has exited.
Both are here; without them one connection could cost a slot, a subprocess and a
non-exitable worker thread permanently, and ``max_conns`` of them killed the hatch
for the worker's whole life rather than the run's.
"""

from __future__ import annotations

import contextlib
import dataclasses
import errno
import os
import selectors
import signal
import socket
import stat
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Generator, Sequence
from concurrent import futures

from postern._sandbox import (
    GUEST_CONNECT,
    SandboxProfile,
    guest_env_var,
    guest_socket_path,
    validate_guest_name,
)

_CHUNK = 65536
# Concurrent connections a hatch serves at once (see StreamHatch.__init__ for why
# this gates accepting rather than dispatch).
_DEFAULT_MAX_CONNS = 8
# How long to wait for a subprocess to die after terminate(), and for the guest to
# close after we half-close, before forcing the issue.
_DEFAULT_GRACE = 5.0
# Teardown budget for a verdict rejected at construction: enough for SIGTERM to
# land before SIGKILL, since the caller has no handle to reap it later.
_REJECT_GRACE = 0.5
# accept() errnos that mean the listening socket itself is finished, as opposed to
# a transient shortage the loop should ride out.
_FATAL_ACCEPT_ERRNOS = frozenset({errno.EBADF, errno.EINVAL, errno.ENOTSOCK})
# Pause before retrying a transient accept() failure, so an fd shortage in the
# embedding worker cannot turn into a hot spin.
_ACCEPT_RETRY_DELAY = 0.05
# How long to wait when probing whether a socket in the way is still live.
_STALE_PROBE_TIMEOUT = 1.0
# waitid lets us observe an exit without reaping it. Reached through getattr because
# typeshed marks it unavailable on darwin, where CPython in fact provides it; None
# would mean falling back to poll(), which reaps and so forfeits the group signal.
_WAITID = getattr(os, 'waitid', None)
_P_PID = getattr(os, 'P_PID', 0)
_WEXITED = getattr(os, 'WEXITED', 0)
_WNOWAIT = getattr(os, 'WNOWAIT', 0)
# Everything a host-side subprocess gets of the host's environment. The subprocess
# is the thing chewing on guest bytes, so it must not inherit the trusted worker's
# secrets (the same reasoning as _sandbox.bwrap_env).
_MINIMAL_PATH = '/usr/local/bin:/usr/bin:/bin'


# --------------------------------------------------------------------------- #
# Stream / Process — the handler's data model                                  #
# --------------------------------------------------------------------------- #
@dataclasses.dataclass
class Stream:
    """One accepted guest connection handed to the handler.

    ``conn`` is the raw socket. The hatch splices it for you according to the
    verdict you return, so a handler normally never touches it — read from it only
    to consume a preamble, and note that any policy derived from those bytes is a
    parser back in the policy path, which is exactly what one socket per resource
    exists to avoid.

    ``hatch`` is the hatch's guest name, so one handler can serve several hatches
    and still know which capability was dialled.
    """

    conn: socket.socket
    hatch: str


@dataclasses.dataclass
class Process:
    """Handler verdict: this subprocess owns the connection; wait for it and reap it.

    The socket **is** the command's stdin and stdout — ``Popen(argv,
    stdin=stream.conn, stdout=stream.conn)``, because `subprocess` accepts
    anything with a ``fileno()``. The kernel moves the bytes; there is no
    host-side pump, no thread per direction, and nothing in this process on the
    data path at all. Half-close propagates natively: the guest's
    ``shutdown(SHUT_WR)`` is an EOF on the command's stdin, which is how ``git
    upload-pack`` learns the request is over, and the command's exit is the EOF
    the guest reads.

    The hatch's remaining job is lifecycle: wait for the command, then terminate,
    kill and reap its process group.

    A command that would introspect the socket, or hand descriptors back over it
    with ``sendmsg``, could do so — but only by colluding with the guest, and a
    host that splices a command like that has already granted the guest something
    that does not play by the rules. That is the same category as a command that
    writes host state to its stdout, not a new one.
    """

    proc: subprocess.Popen[bytes]
    # The command's process group, captured here and not at teardown: by then
    # ``poll()`` has reaped the leader, so ``getpgid`` on its pid is ESRCH (or
    # worse, a recycled pid) — while the *group* is still alive, and here still
    # holding a descriptor for the guest's socket. ``None`` when the command is not
    # its own group leader, i.e. when a handler built the `Popen` without
    # ``start_new_session=True`` and the group is the worker's own: signalling that
    # would signal the worker.
    pgid: int | None = dataclasses.field(default=None, init=False)
    _disposed: bool = dataclasses.field(default=False, init=False, repr=False)
    _lock: threading.Lock = dataclasses.field(default_factory=threading.Lock, init=False, repr=False)

    def __post_init__(self) -> None:
        # Before the contract check, not after: the check's own reject path has to
        # be able to signal the group it is about to abandon.
        with contextlib.suppress(OSError, AttributeError):
            if os.getpgid(self.proc.pid) == self.proc.pid:
                self.pgid = self.proc.pid
        held = [name for name in ('stdin', 'stdout', 'stderr') if getattr(self.proc, name) is not None]
        if held:
            self.dispose(_REJECT_GRACE)
            raise ValueError(
                f"Process(proc) requires the connection as the command's stdio, but {held} "
                f'{"is" if len(held) == 1 else "are"} a pipe. Nothing pumps a pipe: pass '
                'stdin=stream.conn, stdout=stream.conn and a file or DEVNULL for stderr.'
            )

    def dispose(self, grace: float) -> None:
        """Terminate, kill and reap the command's process group. Idempotent.

        Idempotence is load-bearing rather than tidy: `StreamHatch.close` disposes
        of what is in flight, and the per-connection ``finally`` disposes of what it
        was handed, and both may reach the same verdict. Letting both reap meant the
        second pass signalled a process group whose leader had already been waited —
        a pid the kernel may reuse, and `splice_subprocess` mints a session leader
        per connection, so one connection's stale ``SIGKILL`` could land on another's
        command.
        """
        with self._lock:
            if self._disposed:
                return
            self._disposed = True
        with contextlib.suppress(Exception):
            _reap(self.proc, grace, self.pgid)


Handler = Callable[[Stream], 'Process | None']


# --------------------------------------------------------------------------- #
# Batteries — the common cases built on the core                               #
# --------------------------------------------------------------------------- #
def splice_subprocess(
    argv: Sequence[str],
    *,
    cwd: str | os.PathLike[str] | None = None,
    env: dict[str, str] | None = None,
    stderr: int | None = subprocess.DEVNULL,
) -> Handler:
    r"""Run ``argv`` per connection, with the connection as its stdio.

    The capability is the exact argv, fixed here and unreachable from the guest:
    guest bytes become the command's **stdin** and nothing else, so there is no
    quoting, no injection, and no way to reach a different repository or a
    different service. ``shell=False`` always.

    The socket is handed to the command as fds 0 and 1, so the kernel moves every
    byte and this process is not on the data path. That is why there is no cap on
    payload size to tune and no buffering to configure.

    Args:
        argv: The command, as a list (never a string through a shell).
        env: Environment for the command. The default is a fixed minimal ``PATH``
            (``_MINIMAL_PATH``) — *not* the host's environment, and not even the
            worker's ``PATH``, which routinely names the operator's home directory
            and tool installs and would both leak that to a process fed
            attacker-controlled input and let ambient host state decide which
            binary ``argv[0]`` resolves to. Pass an explicit dict to add what the
            command needs, e.g. ``{'PATH': ..., 'GIT_PROTOCOL': 'version=2'}``.
        cwd: Working directory. Defaults to ``/`` rather than inheriting the
            worker's cwd, so the capability does not depend on where the worker
            happened to be started.
        stderr: Where the command's **fd 2** goes; discarded by default. It must
            not be merged into the stream: a command's diagnostics quote host
            state (``fatal: '/srv/secrets/repo.git' does not appear to be a git
            repository``), so relaying them would hand the guest a map of the host
            filesystem. Point it at a file or an fd to keep them.

            ``subprocess.PIPE`` is refused: nothing reads it, so a command that
            fills the pipe blocks in ``write(2)`` for ever and never exits, pinning
            the connection's slot until :meth:`StreamHatch.close`.

            This covers fd 2 and nothing more. A command that multiplexes its own
            diagnostics onto **stdout** routes around it, and git does: ``git
            upload-archive`` reports exactly the ``does not appear to be a git
            repository`` message above on its pkt-line sideband, host path
            included. Where the command has such a channel, keep the host path out
            of it — pass ``cwd`` and a bare basename in ``argv`` rather than an
            absolute path.

    Note:
        The command's own **stdin grammar** is part of the capability, and is the
        one thing this function cannot check for you. A fixed argv means guest
        bytes never become *this* process's argv — it does not mean they cannot
        become a *downstream* process's argv or a shell command, if the command
        you chose offers that. ``git upload-pack`` does not. ``sqlite3``
        (``.shell``/``.system``/``.import``), ``psql`` (``\!``, ``COPY … FROM
        PROGRAM``), ``mysql`` (``system``), ``ftp``, ``gdb`` and ``ed`` all do, and
        splicing any of them hands the guest host command execution however
        read-only the flags look. Choose a command whose stdin grants nothing
        beyond the capability you meant to grant.
    """
    if stderr == subprocess.PIPE:
        raise ValueError(
            'stderr=subprocess.PIPE is not supported: nothing drains it, so the command deadlocks. '
            'Use DEVNULL (the default), or pass a file/fd to keep the diagnostics.'
        )
    argv = list(argv)
    process_env = dict(env) if env is not None else {'PATH': _MINIMAL_PATH}

    def handler(stream: Stream) -> Process:
        proc = subprocess.Popen(  # noqa: S603 — fixed argv, no shell; guest bytes only ever reach stdin
            argv,
            # The descriptor, not the socket object: `subprocess` accepts anything
            # with a fileno(), but typeshed's _FILE does not admit a socket. Passing
            # the fd is the same call and says what it means — this descriptor
            # becomes the command's 0 and 1, dup'd before the close_fds sweep, and
            # the socket object stays ours to close.
            stdin=stream.conn.fileno(),
            stdout=stream.conn.fileno(),
            stderr=stderr,
            cwd=cwd if cwd is not None else '/',
            env=process_env,
            # Its own process group, so teardown reaps everything the command
            # started and not just the command. Without this a child left behind
            # inherits the guest's socket and keeps the connection open after the
            # command is gone — the guest never sees EOF and the slot never returns.
            start_new_session=True,
        )
        return Process(proc)

    return handler


def git_url(
    name: str = 'stream',
    *,
    profile: SandboxProfile | None = None,
    python: str | None = None,
) -> str:
    """The ``ext::`` URL a guest uses to reach the stream hatch called ``name``.

    git has no unix-socket transport, but `ext::` carries its native protocol over
    an arbitrary command's stdin/stdout, so the bound-in connector reaches the
    hatch. git gates `ext::` behind ``protocol.ext.allow`` because an ``ext::``
    URL is command execution, and hostile fetched content (a submodule URL) could
    smuggle one in. Inside the sandbox that gate protects nothing — the guest is
    already running untrusted code with the connector bound in — so enable it per
    invocation and leave the host's git config alone:

        git -c protocol.ext.allow=always clone <git_url('repo', profile=profile)> work

    The URL passes no ``%s``/``%S``/``%G``, so git sends no service or repository
    line: the host fixed both when it bound the hatch.

    Args:
        name: The hatch to reach.
        profile: The profile the guest will run under. **Pass this.** The
            interpreter is taken from ``profile.python``, which is the same place
            :meth:`Sandbox.run_python` gets it, so the URL cannot disagree with the
            sandbox it runs in. Without it the default is a bare ``python3``
            resolved from the guest ``PATH`` — which is wrong for exactly the
            posture the README recommends, since ``SandboxProfile.with_venv`` sets
            an absolute venv interpreter and does not touch ``PATH``, and a curated
            ``rootfs`` need not carry ``python3`` at all. The failure surfaces
            inside git's helper as ``cannot run python3: No such file or
            directory``, traceable to this default only if you know it exists.
        python: An explicit interpreter, overriding ``profile``.
    """
    validate_guest_name(name)
    interpreter = python or (profile.python if profile is not None else 'python3')
    return f'ext::{interpreter} {GUEST_CONNECT} {guest_socket_path(name)}'


# --------------------------------------------------------------------------- #
# The hatch                                                                     #
# --------------------------------------------------------------------------- #
class StreamHatch:
    """Serve a raw bidirectional stream over the sandbox UDS, per-connection.

    Conforms to postern's ``Hatch`` protocol (``socket_path`` + ``accepting()``),
    so it drops into ``Sandbox(hatch=...)`` where a `GrpcHatch` would. It is a
    **named dial** hatch: the guest reaches it as an ordinary file at
    ``/run/postern/<name>.sock``, exported as ``$POSTERN_HATCH_<NAME>``. Because
    each hatch is named, a sandbox can carry several — one per resource, which is
    the point. Reused across many runs: serves once on first :meth:`accepting`,
    until :meth:`close`.
    """

    # Ask `Sandbox` to bind the in-guest stdio↔UDS connector at $POSTERN_CONNECT:
    # the protocols a stream hatch carries (git's ext:: transport for one) reach a
    # byte stream rather than a socket, so something in-guest has to bridge them.
    guest_connector = True

    def __init__(
        self,
        handler: Handler,
        *,
        name: str = 'stream',
        socket_path: str | os.PathLike[str] | None = None,
        max_conns: int = _DEFAULT_MAX_CONNS,
        backlog: int = 64,
        grace: float = _DEFAULT_GRACE,
    ) -> None:
        """Create a hatch that runs ``handler`` for each guest connection.

        Args:
            handler: ``handler(stream) -> Process | None``. It owns all policy —
                wrap `splice_subprocess` for the common case.
            name: The capability's name in the guest: its socket is bound at
                ``/run/postern/<name>.sock`` and exported as
                ``POSTERN_HATCH_<NAME>``. A Python identifier, because it becomes
                both a path component and an environment variable name.
            socket_path: Where to bind the host-side UDS. Defaults to a fresh
                ``0700`` temp dir (host-side isolation rests on that dir, per F9).
                **The socket itself is chmod'd 0666**, deterministically rather
                than by umask, because the guest runs as an unrelated uid and has
                to be able to connect. So the containing directory is the entire
                host-side access control: pass a path only in a directory no other
                local uid can traverse. A stable path somewhere convenient
                (``/tmp/myservice.sock``) publishes the capability — a host
                ``git upload-pack``, an upstream dial — to every user on the box.
            max_conns: Concurrent connections served. This gates **accepting**,
                not merely dispatch to a worker pool, and the difference matters: a
                stream connection is long-lived by definition (a clone runs for as
                long as it runs), so a queue of already-accepted connections would
                be a queue of host file descriptors — a guest that opens thousands
                walks the host to EMFILE while doing no work. At the cap the
                accept loop simply stops accepting, leaving connections in the
                kernel backlog where they cost the host nothing. The default is
                deliberately small: each served connection can hold a subprocess,
                two pipes, a socket and two threads for its whole lifetime, so
                this is the real bound on what one guest can pin.
            backlog: ``listen`` backlog. Past ``max_conns + backlog`` pending
                connections the kernel refuses the guest's dial, which is the
                correct answer rather than a host-side queue.
            grace: Seconds to wait for a subprocess to exit after ``terminate()``
                before ``kill()``, and for the guest to close after we half-close.
                Bounds teardown; it is not a limit on the stream's lifetime.
        """
        validate_guest_name(name)
        self._handler = handler
        self._name = name
        self._grace = grace
        self._backlog = backlog
        if socket_path is None:
            self._dir: str | None = tempfile.mkdtemp(prefix='postern-stream-')
            self._path = os.path.join(self._dir, 'hatch.sock')
        else:
            self._dir = None
            self._path = os.fspath(socket_path)
        self._pool = futures.ThreadPoolExecutor(max_workers=max_conns, thread_name_prefix='postern-stream')
        self._slots = threading.Semaphore(max_conns)
        self._srv: socket.socket | None = None
        self._started = False
        self._closing = False
        self._closed = False
        self._accepting = False
        self._bound = False
        # Live connections and the verdict behind each, so close() can tear them
        # down rather than merely stop accepting new ones.
        self._lock = threading.Lock()
        self._live: dict[socket.socket, Process | None] = {}

    @property
    def socket_path(self) -> str:
        return self._path

    @property
    def guest_name(self) -> str:
        """This hatch's name in the guest — how `Sandbox` derives socket and env var."""
        return self._name

    @property
    def guest_env_var(self) -> str:
        """The environment variable naming this hatch's socket inside the sandbox."""
        return guest_env_var(self._name)

    # -- serving lifecycle (mirrors GrpcHatch) ------------------------------- #
    def start(self) -> None:
        """Start serving. Idempotent while open; raises once :meth:`close` has run.

        ``close()`` is **terminal**, matching `GrpcHatch`, and that is now
        structural rather than a convention. It used to reset ``_started`` and
        ``_closing`` while leaving the thread pool permanently shut down, so a
        restarted hatch looked alive from every angle — socket bound, listening,
        accept thread running — and served nothing: the first dial's ``submit``
        raised and every later one parked in the backlog until the guest's run
        timed out, with no host-side error anywhere.
        """
        if self._closed:
            raise RuntimeError('this StreamHatch is closed; close() is terminal — construct a new one')
        if self._started:
            return
        self._clear_stale_socket()
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(self._path)
        self._bound = True
        srv.listen(self._backlog)
        # Deterministic perms, not umask-dependent (F9): the guest runs as a
        # non-root uid so must connect; host-side isolation rests on the 0700 dir.
        with contextlib.suppress(OSError):
            os.chmod(self._path, 0o666)  # noqa: S103 — intentional; see the comment above
        self._srv = srv
        self._started = True
        self._accepting = True
        threading.Thread(target=self._accept_loop, args=(srv,), daemon=True, name='postern-stream-accept').start()

    def _clear_stale_socket(self) -> None:
        """Remove a dead socket left where we are about to bind. Nothing else.

        A crashed run leaves its socket file behind and ``bind`` would fail with
        ``EADDRINUSE``, so this has to happen — but the old version unlinked the
        path unconditionally, and a caller-supplied ``socket_path`` is somebody
        else's file until we have bound it. Pointed at a reused or mistyped path
        (the docstring's own ``/tmp/myservice.sock``), constructing a hatch quietly
        deleted a live unrelated service's socket, which then kept accepting on an
        unlinked inode while every new client got ENOENT.

        So: a path under the temp dir this hatch created is ours to clear. Any
        other path is cleared only if it is an ``AF_UNIX`` socket with nobody
        listening — the standard liveness probe, and the only case where removing
        it is unambiguously safe. Anything else is left alone for ``bind`` to
        refuse loudly.
        """
        if self._dir is not None:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(self._path)
            return
        try:
            mode = os.stat(self._path).st_mode
        except OSError:
            return  # nothing there, or not ours to look at
        if not stat.S_ISSOCK(mode):
            return  # a regular file or a directory: let bind() say so
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe.settimeout(_STALE_PROBE_TIMEOUT)
            probe.connect(self._path)
        except ConnectionRefusedError:
            with contextlib.suppress(OSError):
                os.unlink(self._path)  # nobody home: a crashed run's leftover
        except OSError:
            pass  # in doubt (EAGAIN on a full backlog, a timeout): leave it be
        finally:
            probe.close()

    @contextlib.contextmanager
    def accepting(self) -> Generator[StreamHatch, None, None]:
        """Ensure the hatch is serving for the block; it stays up for reuse."""
        self.start()
        yield self

    def _accept_loop(self, srv: socket.socket) -> None:
        while True:
            # Take the slot *before* accepting: an unaccepted connection sits in
            # the kernel backlog and costs the host no descriptor, whereas an
            # accepted-and-queued one costs one for as long as the queue is deep.
            self._slots.acquire()
            if self._closing:
                return
            try:
                conn, _ = srv.accept()
            except OSError as exc:
                if self._closing or exc.errno in _FATAL_ACCEPT_ERRNOS:
                    return  # our own close(), or the socket is genuinely unusable
                # Transient: EMFILE/ENFILE when the *embedding* worker momentarily
                # runs out of descriptors, ECONNABORTED when a dial dies during the
                # handshake, EINTR. Retiring the hatch on one of these left it
                # bound, listening and permanently deaf, with no log line and no
                # recovery short of close().
                self._slots.release()
                time.sleep(_ACCEPT_RETRY_DELAY)
                continue
            try:
                self._pool.submit(self._serve_conn, conn)
            except RuntimeError:  # pool shut down mid-accept
                with contextlib.suppress(OSError):
                    conn.close()
                self._slots.release()
                return

    # -- one guest connection ------------------------------------------------ #
    def _serve_conn(self, conn: socket.socket) -> None:
        # A single hostile connection must never take a pool worker down, and must
        # always give its slot back — otherwise the hatch bleeds capacity.
        verdict: Process | None = None
        try:
            verdict = self._handler(Stream(conn, self._name))
            self._track(conn, verdict)
            if verdict is None:
                # A refusal. A raw stream has no way to say "no", so the guest gets
                # end-of-stream and nothing else — in particular no diagnostic,
                # which on this surface would only ever be host state.
                _drain(conn, self._grace)
            else:
                _await_command(verdict)
        except Exception:  # noqa: BLE001 — hostile input; contain it to this connection
            _drain(conn, self._grace)
        finally:
            # Whatever the verdict was, and however this ended, it must not outlive
            # the connection: an exception raised anywhere above used to abandon a
            # subprocess unreaped, which let a guest reconnecting in a loop grow the
            # host's process table without bound (max_conns bounds concurrent
            # commands, not abandoned children).
            self._untrack(conn)
            _dispose(verdict, self._grace)
            with contextlib.suppress(OSError):
                conn.close()
            self._slots.release()

    # -- live-connection bookkeeping, so close() can mean something ---------- #
    def _track(self, conn: socket.socket, verdict: Process | None) -> None:
        with self._lock:
            if self._closing:
                # close() already ran; do not let a verdict slip past its teardown.
                _dispose(verdict, self._grace)
                raise ConnectionAbortedError('hatch closed')
            self._live[conn] = verdict

    def _untrack(self, conn: socket.socket) -> None:
        with self._lock:
            self._live.pop(conn, None)

    def close(self) -> None:
        """Stop serving, tear down everything in flight, and drop the socket.

        **Terminal and idempotent**: a closed hatch cannot be restarted (see
        :meth:`start`), and closing twice is a no-op rather than a second pass that
        inflates the slot semaphore — two ``close()``es on a ``max_conns=1`` hatch
        used to leave three slots available.

        Every live connection is shut down and the command behind it reaped, because
        nothing else will: ``ThreadPoolExecutor`` workers have been non-daemon since
        3.9 and ``shutdown(wait=False)`` does not interrupt one, so a worker parked
        in ``proc.wait()`` on a command the guest is keeping alive would hold that
        command *and* stop the host worker process from exiting at all.
        """
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._closing = True
            live = list(self._live.items())
            self._live.clear()
            accepting, self._accepting = self._accepting, False
            bound, self._bound = self._bound, False
        if self._srv is not None:
            # shutdown() before close(): on Linux, closing a listening socket
            # another thread is blocked in accept() on does not wake that thread,
            # so the accept loop parked there for the life of the process — one
            # leaked thread and stack per closed hatch.
            with contextlib.suppress(OSError):
                self._srv.shutdown(socket.SHUT_RDWR)
            with contextlib.suppress(OSError):
                self._srv.close()
            self._srv = None
        self._started = False
        if accepting:
            self._slots.release()  # unblock an accept loop parked on the cap
        for conn, verdict in live:
            # The socket first, so a command reading it sees EOF, then the command
            # itself: reaping is what releases the worker parked in proc.wait().
            _unblock(conn)
            _dispose(verdict, self._grace)
        self._pool.shutdown(wait=False)
        if bound:
            # Only what this hatch actually bound. A caller-supplied socket_path
            # that we never bound belongs to whoever did.
            with contextlib.suppress(OSError):
                os.unlink(self._path)
        if self._dir is not None:
            with contextlib.suppress(OSError):
                os.rmdir(self._dir)


# --------------------------------------------------------------------------- #
# Splicing                                                                      #
# --------------------------------------------------------------------------- #
def _dispose(verdict: Process | None, grace: float) -> None:
    """Release whatever a verdict was holding. Idempotent, never raises."""
    if verdict is not None:
        with contextlib.suppress(Exception):
            verdict.dispose(grace)


def _readable(sock_or_fd: socket.socket | int, timeout: float) -> bool:
    """Wait for readability. ``selectors``, never ``select.select``.

    CPython's ``select()`` rejects any descriptor >= ``FD_SETSIZE`` (1024) with
    ``ValueError`` before it reaches the syscall, and the precondition is the
    *embedding* worker's descriptor budget, which a library cannot control — the
    standard reason library code avoids it. A worker above the default soft limit
    would have had its drains silently skipped, so a guest would see the reset the
    drain exists to prevent, with no diagnostic anywhere. ``poll``/``kqueue`` have
    no such ceiling.
    """
    with contextlib.suppress(OSError, ValueError), selectors.DefaultSelector() as sel:
        sel.register(sock_or_fd, selectors.EVENT_READ)
        return bool(sel.select(timeout))
    return False


def _drain(guest: socket.socket, grace: float) -> None:
    """Discard what the guest is still sending, bounded by ``grace``.

    Closing an ``AF_UNIX`` socket while bytes remain unread in its receive queue
    makes the kernel set ``ECONNRESET`` on the *peer* (``unix_release_sock``), so
    the guest's next read fails with a reset instead of reporting end-of-stream —
    and a client such as git reads that as a protocol error, not as "the exchange
    is over". Draining first turns the close into an orderly one. ``grace`` bounds
    it, so a guest that keeps writing forever gives up its slot anyway (at the
    price of the reset it brought on itself).

    Deliberately does **not** touch the write side, and is the only thing this
    module does with the guest's bytes on its own account: it is reached when a
    handler refuses (verdict ``None``), when a handler raises, and after a command
    has exited. In none of those cases is anything else going to read the socket,
    so discarding what is queued is exactly right — and it is the difference
    between the guest reading end-of-stream and the guest reading a reset.

    Waits on readability rather than a socket timeout: ``settimeout`` is
    per-socket, and on the refusal path a handler may have already written to it.
    """
    deadline = time.monotonic() + grace
    with contextlib.suppress(OSError, ValueError):
        while (remaining := deadline - time.monotonic()) > 0:
            if not _readable(guest, remaining):
                return  # the guest has gone quiet; stop waiting on it
            if not guest.recv(_CHUNK):
                return


def _unblock(sock: socket.socket) -> None:
    """Wake anything blocked on ``sock``, and tell its peer we are finished.

    ``close()`` does not do this on Linux — the descriptor goes away but a reader
    already inside the syscall stays there — and here the reader may be a *command*
    holding the same socket as its stdin, which a shutdown gives a clean EOF.
    """
    with contextlib.suppress(OSError):
        sock.shutdown(socket.SHUT_RDWR)


def _await_command(verdict: Process) -> None:
    """Wait for the command that owns the connection. Nothing is copied or drained.

    The command has the socket as fds 0 and 1, so the kernel is the data path and
    this function only waits — which is the whole reason the `Process` path has no
    pump, no thread per direction, and no teardown ordering to get wrong.

    In particular it does **not** drain. The drain exists to suppress a reset that
    is purely our own teardown artifact: nothing went wrong on the wire, we simply
    never read what the guest sent, and the guest should not be told an exchange
    failed when it did not. Here the opposite is true, and the kernel already
    reports it correctly for free: a command that consumed its input and exited
    leaves an empty receive queue, so the guest reads end-of-stream, while a command
    that died mid-request leaves the unread remainder queued, so closing the last
    descriptor resets the guest (``unix_release_sock``). That distinction is the
    only failure signal a stream with no framing of its own has, and draining here
    would erase it — reporting a command that crashed halfway through the request as
    a clean finish.

    Waits **without reaping**, which is what lets teardown still collect the
    command's process group afterwards: reaping releases the leader's pid, and a
    group id is only valid while that pid is allocated, so a plain ``wait()`` here
    would leave :func:`_reap` correctly declining to signal a group it can no
    longer prove is ours — and a child the command left behind would inherit the
    guest's socket and keep the connection open for ever. ``waitid(..., WNOWAIT)``
    reports the exit and leaves the child waitable.
    """
    proc = verdict.proc
    if _WAITID is not None:
        try:
            _WAITID(_P_PID, proc.pid, _WEXITED | _WNOWAIT)
        except OSError:
            proc.wait()  # interrupted, or no such child: fall back
        return
    proc.wait()  # pragma: no cover - waitid is POSIX-wide in practice


def _signal_group(proc: subprocess.Popen[bytes], pgid: int | None, sig: int) -> None:
    """Signal ``pgid`` if there is one; otherwise just ``proc``.

    ``splice_subprocess`` starts the command in its own session, so the command
    *is* its group leader and the group is exactly the command's descendants.
    ``pgid`` is ``None`` for a `Popen` a handler built without
    ``start_new_session=True``: that process shares the worker's own group, and
    signalling that group would signal the worker.
    """
    if pgid is not None:
        with contextlib.suppress(OSError, AttributeError):
            os.killpg(pgid, sig)
            return
    with contextlib.suppress(OSError, ValueError):
        proc.send_signal(sig)


def _exited(proc: subprocess.Popen[bytes]) -> bool:
    """Whether the command has exited — **without reaping it**.

    ``poll()`` reaps, and reaping releases the leader's pid. A process group's id
    stays valid only while that pid is still allocated, which an unreaped zombie
    guarantees and a reaped child does not, so a group kill issued after a ``poll()``
    can land on a recycled pid — and `splice_subprocess` mints a new session leader
    per connection, so the recycled pid is plausibly another connection's command.
    ``waitid(..., WNOWAIT)`` reports the exit and leaves the child waitable.
    """
    if proc.returncode is not None:
        return True
    if _WAITID is None:  # pragma: no cover - waitid is POSIX-wide in practice
        return proc.poll() is not None  # weaker: this reaps, so no group signal follows
    try:
        return _WAITID(_P_PID, proc.pid, _WEXITED | os.WNOHANG | _WNOWAIT) is not None
    except OSError:
        return proc.poll() is not None


def _reap(proc: subprocess.Popen[bytes], grace: float, pgid: int | None = None) -> None:
    """Terminate, then kill, then wait — never leave a child of the host running.

    Signals the process *group*, not the process: a command that leaves a
    background child behind otherwise strands it, and — because that child
    inherited the stdout pipe — strands the splice waiting for EOF on it too, so
    the connection's slot never came back even after the guest died.

    The final ``wait()`` is deliberately untimed. With ``grace=0.0`` every
    ``wait(timeout=grace)`` is a single ``WNOHANG`` poll that necessarily loses the
    race against the signal it just sent, so the killed child stayed an unreaped
    zombie — one per connection, which is the leak this function exists to close.
    It cannot hang: it runs only after ``SIGKILL``, which is not maskable.
    """
    # Signalling the group is only safe while we still hold the leader's pid. If
    # something already waited this Popen, the pid may have been recycled, so the
    # group is no longer provably ours and we signal nothing.
    if proc.returncode is None:
        if not _exited(proc):
            _signal_group(proc, pgid, signal.SIGTERM)
            try:
                proc.wait(timeout=grace)
            except subprocess.TimeoutExpired:
                _signal_group(proc, pgid, signal.SIGKILL)
        elif proc.returncode is None:
            # Exited but not yet reaped: the zombie pins the pid, so the group id is
            # still valid and anything the command started is still in it. The
            # re-check matters because the fallback above reaps, and after a reap
            # the group is no longer provably ours.
            _signal_group(proc, pgid, signal.SIGKILL)
    with contextlib.suppress(Exception):
        proc.wait()
    # stderr as well as the two the splice owns: `splice_subprocess` refuses PIPE,
    # but a handler may build its own Popen, and an unclosed read end leaks until
    # the Popen is garbage collected.
    for pipe in (proc.stdin, proc.stdout, proc.stderr):
        if pipe is not None:
            with contextlib.suppress(OSError, ValueError):
                pipe.close()


# Re-exported for callers that build guest command lines by hand.
__all__ = [
    'Handler',
    'Process',
    'Stream',
    'StreamHatch',
    'git_url',
    'guest_env_var',
    'guest_socket_path',
    'splice_subprocess',
]
