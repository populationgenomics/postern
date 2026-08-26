"""The stream hatch: a raw bidirectional byte stream over the sandbox UDS.

Where `GrpcHatch` grants the guest a set of typed methods, `StreamHatch` gives it
**one socket** and nothing else. Per accepted connection a handler you supply
decides what the guest's bytes are spliced to:

    handler(stream) -> Process | None

* ``stream`` — the accepted connection (``stream.conn``) and the name of the hatch
  it arrived on (``stream.hatch``).
* return ``Process(argv)`` to hand the connection to a subprocess as its stdin and
  stdout, or ``None`` to refuse (the guest sees end-of-stream). The verdict
  *describes* the command and the hatch spawns it, which is what puts the
  connection into ordinary-stdio shape before there is a child to race;
  `Process.from_popen` is the escape hatch, and says what it costs.
* the hatch owns the *lifecycle* after the verdict — waiting for the command, then
  terminate-then-kill teardown and reaping the process group. It does not own the
  data path: the socket **is** the command's stdio, so the kernel moves the bytes.
  No pump, so no payload ceiling to tune and no buffering to configure.

The motivating case is **git**: its native wire protocol is pkt-line over a raw
bidirectional stream, and ``ext::`` carries that over a command's stdin/stdout, so
a byte pump reaches a UDS (`postern._stream_connect`, bound into the guest as
``$POSTERN_CONNECT``, is that pump).

    from postern import Sandbox, SandboxProfile
    from postern.stream import StreamHatch, git_url, splice_subprocess

    hatch = StreamHatch(splice_subprocess(['git', 'upload-pack', '/srv/repo.git']), name='repo')
    sandbox = Sandbox(SandboxProfile(), hatch=hatch)
    sandbox.run(['git', '-c', 'protocol.ext.allow=always', 'clone', git_url('repo'), 'work'])

A dial hatch needs nothing in-guest — the socket is just a file — so a bare ``git``
entrypoint under `Sandbox.run` reaches it, not only a `run_python` guest.
Stdlib-only: no extra to install.

Trust model
-----------
Every byte the guest sends is attacker-controlled, and here those bytes are handed
to a host-side process. The batteries are built so guest input can only ever be a
subprocess's **stdin** — never its argv, env, cwd, or the destination of a dial,
all of which are fixed when the hatch is constructed. One socket per resource makes
the wrong resource unrepresentable and nothing parses anything; the service is
fixed too, so a hatch bound to ``git upload-pack`` cannot be talked into
``receive-pack``. `Process` also defaults its subprocess to a scrubbed environment
and a discarded stderr, both host state the guest must not read (see
`splice_subprocess`).

What the socket itself tells the guest: nothing useful. It arrives at
``/run/postern/<name>.sock``, so the host-side path is not in the environment, and
``SO_PEERCRED`` from inside reads ``(0, 65534, 65534)`` — the host process's pid is
not mapped into the guest's pid namespace and its uid is not mapped into the
guest's user namespace. The host *path* is still visible in
``/proc/self/mountinfo``, as every bwrap bind source is: an information leak rather
than a reachable path.

A hostile guest can hold ``max_conns`` slots — and each slot's subprocess — for as
long as its connections live, so size the cap for the workload and rely on the
outer ``Sandbox.run(timeout=...)`` as the backstop that EOFs every connection at
once.

The kernel reports the command's disposition to the guest exactly: a command that
consumed its input and exited leaves an empty receive queue, so the guest reads
end-of-stream, while one that died mid-request leaves the remainder queued, so the
guest reads a reset. That distinction is the only failure signal a stream with no
framing of its own has.

Teardown and its caveats
------------------------
Linux is the only platform postern sandboxes *on* (bubblewrap), but a `StreamHatch`
is host-side and runs anywhere. Teardown signals the command's process *group*,
because a child the command left behind inherits the guest's socket and would hold
the connection open after the command is gone. Doing that safely means observing
the command's exit **without reaping it**: an unreaped zombie is what proves the
leader's pid — and so the group id captured at spawn — is still ours rather than a
number the kernel has since handed to somebody else.

Three tiers observe the exit, in ``_WAITID``'s order, because no single interface
is portable:

1. ``os.waitid(..., WNOWAIT)``. Always present on Linux. On darwin CPython exposes
   it only from 3.13, and the floor here is 3.10, hence the ``getattr``.
2. ``kqueue``/``EVFILT_PROC``/``NOTE_EXIT`` on macOS and the BSDs. ``EVFILT_PROC``
   reports an immediate ``NOTE_EXIT`` for a pid that does not exist *at all*, so a
   registration only answers the question for a pid we own and have not reaped.
3. ``Popen.poll()``/``wait()``, a floor. These reap, so `_reap` then declines to
   signal a group it can no longer prove is ours, and a background child survives
   holding the guest's socket.

**Caveat 1 — another reaper in the host process voids the group signal.** If
anything else in the embedding process reaps arbitrary children — a supervisor loop
calling ``waitpid(-1)``, ``multiprocessing``, an asyncio child watcher, ``SIGCHLD``
set to ``SIG_IGN`` — teardown silently skips the process-group kill. ``Popen``
synthesises an exit status of 0 on ``ECHILD``, which is indistinguishable from a
clean exit, and signalling on that ambiguity would aim a stale group kill at
another connection's command. What leaks is the command's *children*; the worker
thread and the slot come back.

**Caveat 2 — a grandchild that leaves the process group escapes teardown.** A
shell's ``&`` child stays in the group; a sidecar that calls ``setsid()`` leaves
it, and nothing here reaches it. ``max_conns`` still holds, so the cost is one
leaked process and one leaked descriptor per connection, unbounded across
reconnections. Read "a background child it left behind", wherever this module says
it, as "one that stays in the group".
"""

from __future__ import annotations

import contextlib
import dataclasses
import errno
import fcntl
import os
import select
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

from postern import _sandbox

# Bound as names, not reached through _sandbox: __all__ below re-exports these two.
from postern._sandbox import guest_env_var, guest_socket_path

_CHUNK = 65536
# Concurrent connections a hatch serves at once; gates accepting, not dispatch.
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
# Pause before retrying a transient accept() failure: no hot spin on an fd shortage.
_ACCEPT_RETRY_DELAY = 0.05
# How long to wait when probing whether a socket in the way is still live.
_STALE_PROBE_TIMEOUT = 1.0
# A poll rather than `Popen.wait(timeout=...)` because that reaps, and the reap is
# what invalidates the group id.
_EXIT_POLL = 0.02
# How long `_drain` waits for the *next* byte before calling the receive queue
# empty: a quiet-period test, not a share of `grace`, which caps the whole drain.
_DRAIN_QUIET = 0.1
# The exit-observation tiers; see "Teardown and its caveats" above. waitid through
# getattr: CPython exposes it on darwin only from 3.13, and the floor here is 3.10.
_WAITID = getattr(os, 'waitid', None)
_P_PID = getattr(os, 'P_PID', 0)
_WEXITED = getattr(os, 'WEXITED', 0)
_WNOWAIT = getattr(os, 'WNOWAIT', 0)
# The whole kqueue family through getattr: `select.kevent` and the KQ_* constants
# exist only on the BSDs, so naming one directly is an attribute error on Linux at
# *type-check* time even though the call site can never run there.
_KQUEUE = getattr(select, 'kqueue', None)
_KEVENT = getattr(select, 'kevent', None)
_KQ_FILTER_PROC = getattr(select, 'KQ_FILTER_PROC', None)
_KQ_NOTE_EXIT = getattr(select, 'KQ_NOTE_EXIT', None)
_KQ_EV_ADD = getattr(select, 'KQ_EV_ADD', 0)
_KQ_EV_ONESHOT = getattr(select, 'KQ_EV_ONESHOT', 0)
# File status flags to clear before handing the connection over as a command's
# stdio. They live on the *open file description*, which the child's fds 0 and 1
# are dup2's of, so whatever is set here is what the command runs with.
_HANDOVER_CLEAR_FL = 0
for _name in ('O_NONBLOCK', 'O_ASYNC', 'O_APPEND', 'O_DIRECT', 'O_NOATIME'):
    _HANDOVER_CLEAR_FL |= getattr(os, _name, 0)
# F_SETSIG. Not in the fcntl module on every platform, and only consulted when
# O_ASYNC is set, but zeroed with the owner so no stale signal number survives.
_F_SETSIG = getattr(fcntl, 'F_SETSIG', None)
# Linux-only, hence the getattr; harmless where absent.
_SO_PASSCRED = getattr(socket, 'SO_PASSCRED', None)
# Socket options whose value is a `struct timeval`, whose width differs by platform
# (16 bytes on Linux LP64, 12 on darwin): the length the kernel reports for the
# current value is the length written back, never a hard-coded one.
_TIMEOUT_OPTS = (socket.SO_RCVTIMEO, socket.SO_SNDTIMEO)
_TIMEVAL_MAX = 32
# Everything a host-side subprocess gets of the host's environment: it chews on
# guest bytes, so it must not inherit the worker's secrets (cf. _sandbox.bwrap_env).
_MINIMAL_PATH = '/usr/local/bin:/usr/bin:/bin'


# --------------------------------------------------------------------------- #
# Stream / Process — the handler's data model                                  #
# --------------------------------------------------------------------------- #
@dataclasses.dataclass
class Stream:
    """One accepted guest connection handed to the handler.

    ``conn`` is the raw socket; the hatch splices it according to the verdict you
    return, so a handler normally never touches it. ``hatch`` is the hatch's guest
    name, so one handler can serve several hatches and still know which capability
    was dialled.

    **The socket is handed over, not lent.** A `Process` verdict makes it the
    command's stdin and stdout, so it is normalised at handover — blocking, no
    signal-driven I/O, no socket timeouts — and a handler's settings for those
    properties are undone (:func:`_normalise_stdio` lists what it leaves alone). In
    particular do not reach for :meth:`socket.socket.settimeout` to
    bound a preamble read: CPython implements it by setting ``O_NONBLOCK``, which
    lives on the open file description the command's fds 0 and 1 are dup2's of, so
    it truncates the command's response and the guest reads that as a clean
    end-of-stream. Use :meth:`read_preamble`, which touches no flags.

    Bound that read: the hatch cannot shut a connection down until the handler has
    returned, so a handler that blocks for ever on a guest that connects and sends
    nothing costs a slot for the hatch's whole life.
    """

    conn: socket.socket
    hatch: str

    def read_preamble(self, max_bytes: int, timeout: float) -> bytes:
        """Read up to ``max_bytes``, waiting at most ``timeout`` seconds in total.

        Readiness comes from a selector rather than a socket timeout, so the
        connection's file status flags stay as the command will need them. Returns
        what arrived — short, or empty on timeout or immediate end-of-stream —
        rather than raising: a guest that says nothing is a refusal waiting to be
        made, not an error.
        """
        deadline = time.monotonic() + timeout
        buf = bytearray()
        with contextlib.suppress(OSError, ValueError):
            while len(buf) < max_bytes and (remaining := deadline - time.monotonic()) > 0:
                if not _readable(self.conn, remaining):
                    break
                chunk = self.conn.recv(max_bytes - len(buf))
                if not chunk:
                    break
                buf += chunk
        return bytes(buf)


@dataclasses.dataclass
class Process:
    """Handler verdict: run ``argv`` with the connection as its stdin and stdout.

    **Declarative on purpose.** The verdict describes the command; the hatch spawns
    it. The connection has to be put into ordinary-stdio shape *before* ``Popen``,
    and a verdict that arrives holding an already-spawned `Popen` is too late to
    fix. Owning the spawn also means ``start_new_session=True`` is guaranteed rather
    than remembered, so teardown always has a process group of its own to signal,
    and the pipe/stderr contract is checked in one place.

    The socket **is** the command's stdin and stdout, so the kernel moves the bytes
    and nothing in this process is on the data path. Half-close propagates natively:
    the guest's ``shutdown(SHUT_WR)`` is an EOF on the command's stdin, which is how
    ``git upload-pack`` learns the request is over, and the command's exit is the EOF
    the guest reads. The hatch's remaining job is lifecycle — wait for the command,
    then terminate, kill and reap its process group.

    Args:
        argv: The command, as a list (never a string through a shell).
            ``None`` is reserved for :meth:`from_popen`.
        cwd: Working directory; defaults to ``/``. See `splice_subprocess`.
        env: Environment; defaults to a fixed minimal ``PATH``. See
            `splice_subprocess`, which documents why the worker's own environment
            is not inherited.
        stderr: Where fd 2 goes; discarded by default. ``PIPE`` and ``STDOUT``
            are both refused — see `splice_subprocess`.
    """

    argv: Sequence[str] | None = None
    cwd: str | os.PathLike[str] | None = None
    env: dict[str, str] | None = None
    stderr: int | None = subprocess.DEVNULL

    # Set when the hatch attaches this verdict to a connection, or up front by
    # from_popen. Read-only: a writable field reaches the adopted path with none of
    # :meth:`from_popen`'s validation. ``None`` until the hatch attaches.
    _proc: subprocess.Popen[bytes] | None = dataclasses.field(default=None, init=False, repr=False)
    # The command's process group, captured at spawn and not at teardown: by then
    # the leader may have been reaped, so ``getpgid`` on its pid is ESRCH (and on
    # darwin it is ESRCH for a zombie regardless) while the *group* is still alive
    # holding a descriptor for the guest's socket. ``None`` when the command is not
    # its own group leader — an adopted `Popen` built without
    # ``start_new_session=True``, whose group is the worker's own. Read-only: a
    # writable pgid is a ``killpg`` at an arbitrary group.
    _pgid: int | None = dataclasses.field(default=None, init=False, repr=False)
    # Whether the adopted path was *asked for*. Not the same question as "``proc``
    # is set".
    _adopted: bool = dataclasses.field(default=False, init=False, repr=False)
    # A verdict describes *one* connection's command; see _claim.
    _claimed: bool = dataclasses.field(default=False, init=False, repr=False)
    _disposed: bool = dataclasses.field(default=False, init=False, repr=False)
    _lock: threading.Lock = dataclasses.field(default_factory=threading.Lock, init=False, repr=False)

    @property
    def proc(self) -> subprocess.Popen[bytes] | None:
        """The command, once the hatch has spawned or adopted it. Read-only."""
        return self._proc

    @property
    def pgid(self) -> int | None:
        """The command's process group, captured at spawn. Read-only."""
        return self._pgid

    def __post_init__(self) -> None:
        # Ahead of the argv check, so a Process() with no argv is still checked.
        # An adopted Popen's real fd 2 is not visible here — _attach checks that.
        _check_stderr(self.stderr)
        if self.argv is None:
            return  # from_popen, or a Process() the hatch will refuse at attach
        self.argv = list(self.argv)
        if not self.argv:
            raise ValueError('Process(argv) requires a command')

    @classmethod
    def from_popen(cls, proc: subprocess.Popen[bytes]) -> Process:
        """Adopt a `Popen` you spawned yourself: you own the descriptor hygiene.

        The escape hatch for what ``argv``/``cwd``/``env``/``stderr`` do not cover —
        ``pass_fds``, ``user=``/``group=`` to run a command as a per-tenant uid, an
        rlimit in ``preexec_fn``. The child is already running by the time the hatch
        sees this verdict, so the connection cannot be normalised without racing it;
        the hatch *validates* instead and refuses a connection that is not in
        ordinary-stdio shape, naming the reason. That is loud rather than silently
        corrupt, but it is late — the child may already have died on ``EAGAIN``. Put
        the socket in ordinary shape, or never touch it, before you spawn.

        Spawn with ``stdin=stream.conn.fileno(), stdout=stream.conn.fileno()`` and
        ``start_new_session=True``; without the latter ``pgid`` is ``None`` and
        teardown can only signal the command itself, so a background child it leaves
        behind keeps the guest's connection open.

        **This drops three defaults that are security properties.** A `Popen` you
        built has none of them unless you passed them yourself:

        * ``stderr``. The declarative path defaults to ``DEVNULL`` and *refuses*
          ``STDOUT``, because stdout is the guest's socket and a command's
          diagnostics quote host paths. ``Popen`` inherits fd 2, and
          ``stderr=subprocess.STDOUT`` merges it into the guest's stream. The hatch
          detects that last case where the platform allows (Linux, by comparing the
          child's fd 2 with the connection) and refuses the verdict, but pass
          ``DEVNULL`` or a file.
        * ``env``. The declarative path passes a fixed minimal ``PATH``; ``Popen``
          inherits the worker's entire environment, secrets included, into a process
          whose stdin is attacker-controlled. Pass ``env=`` explicitly.
        * ``cwd``. The declarative path uses ``/``; ``Popen`` inherits the worker's
          working directory, so the capability depends on where the host process was
          started. Pass ``cwd=`` explicitly.

        ``env`` and ``cwd`` are not policed here — owning the hygiene is this
        method's premise. The one that is checked is the one that leaks host state
        *to the guest*.
        """
        verdict = cls()
        verdict._proc = proc
        verdict._adopted = True
        verdict._capture_pgid()
        held = [name for name in ('stdin', 'stdout', 'stderr') if getattr(proc, name) is not None]
        if held:
            # Reap before raising, or a guest reconnecting in a loop grows the
            # host's process table with abandoned children.
            verdict.dispose(_REJECT_GRACE)
            raise ValueError(
                f"Process.from_popen(proc) requires the connection as the command's stdio, but {held} "
                f'{"is" if len(held) == 1 else "are"} a pipe. Nothing pumps a pipe: pass '
                'stdin=stream.conn.fileno(), stdout=stream.conn.fileno() and a file or DEVNULL for stderr.'
            )
        return verdict

    def _capture_pgid(self) -> None:
        """Record the group id while the leader is certainly still alive."""
        if self._proc is None:
            return
        with contextlib.suppress(OSError, AttributeError):
            if os.getpgid(self._proc.pid) == self._proc.pid:
                self._pgid = self._proc.pid

    def _claim(self) -> bool:
        """Take ownership of this verdict for one connection. False if taken.

        A verdict describes *one* connection's command, so the hatch claims one
        before attaching it and refuses one it cannot claim — a handler that caches
        a verdict would otherwise splice a second connection to nothing.
        `StreamHatch._serve_conn` must forget a verdict it could not claim before it
        raises: it is another connection's, and the per-connection ``finally`` would
        tear down that connection's command.
        """
        with self._lock:
            if self._claimed:
                return False
            self._claimed = True
            return True

    def _attach(self, conn: socket.socket, grace: float) -> None:
        """Make ``conn`` this verdict's command's stdio. Called only by the hatch.

        Normalise, then spawn — in that order and with nothing in between.
        """
        if self._adopted:
            merged = _stderr_is_the_connection(self._proc, conn)
            if merged:
                self.dispose(grace)
                raise ValueError(
                    "this verdict's command has the connection as its stderr as well as its stdout "
                    '(stderr=subprocess.STDOUT, or the connection passed for fd 2), so its diagnostics — '
                    'which quote host paths — go straight to the guest. Pass stderr=DEVNULL or a file. '
                    '(Process(argv=...) refuses this at construction; here it can only be detected.)'
                )
            abnormal = _abnormal_stdio(conn)
            if abnormal:
                self.dispose(grace)
                raise ValueError(
                    f'the connection is not in ordinary-stdio shape ({", ".join(abnormal)}), and this '
                    'verdict already spawned its command, so it cannot be normalised without racing '
                    'the child. Leave the connection alone before Popen, or use Process(argv=...) and '
                    'let the hatch spawn it.'
                )
            return
        if self._proc is not None:
            # Not adopted, yet already holding a process: `_proc` assigned behind
            # the property's back, which skips every check in from_popen.
            raise ValueError(
                'this Process already holds a command but did not come from Process.from_popen(popen). '
                'A verdict describes one connection: build a fresh Process per connection, and adopt an '
                'existing Popen only through from_popen, which validates it.'
            )
        if self.argv is None:
            raise ValueError('Process() requires argv, or use Process.from_popen(popen)')
        _normalise_stdio(conn)
        fd = conn.fileno()
        self._proc = subprocess.Popen(  # noqa: S603 — fixed argv, no shell; guest bytes only ever reach stdin
            list(self.argv),
            # The descriptor, not the socket object: typeshed's _FILE does not admit
            # a socket. Same call — the fd becomes the command's 0 and 1, dup'd
            # before the close_fds sweep, and the socket object stays ours to close.
            stdin=fd,
            stdout=fd,
            stderr=self.stderr,
            cwd=self.cwd if self.cwd is not None else '/',
            env=dict(self.env) if self.env is not None else {'PATH': _MINIMAL_PATH},
            # Its own process group, so teardown reaps everything the command
            # started and not just the command.
            start_new_session=True,
        )
        self._capture_pgid()

    def dispose(self, grace: float) -> None:
        """Terminate, kill and reap the command's process group. Idempotent.

        Idempotence is load-bearing: `StreamHatch.close` disposes of what is in
        flight and the per-connection ``finally`` disposes of what it was handed, so
        both may reach the same verdict. A second reaping pass would signal a group
        whose leader had already been waited — a pid the kernel may reuse, and every
        verdict mints a session leader, so the stale ``SIGKILL`` could land on
        another connection's command.

        A verdict that never reached :meth:`_attach` has nothing to reap.
        """
        with self._lock:
            if self._disposed:
                return
            self._disposed = True
        if self._proc is None:
            return
        with contextlib.suppress(Exception):
            _reap(self._proc, grace, self._pgid)


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
    quoting, no injection, and no way to reach a different repository or a different
    service. ``shell=False`` always. The socket is handed to the command as fds 0 and
    1, so the kernel moves every byte and there is no payload cap to tune.

    Args:
        argv: The command, as a list (never a string through a shell).
        env: Environment for the command. The default is a fixed minimal ``PATH``
            (``_MINIMAL_PATH``) — not the host's environment, and not even the
            worker's ``PATH``, which routinely names the operator's home directory
            and tool installs, and would both leak that to a process fed
            attacker-controlled input and let ambient host state decide which binary
            ``argv[0]`` resolves to. Pass an explicit dict to add what the command
            needs, e.g. ``{'PATH': ..., 'GIT_PROTOCOL': 'version=2'}``.
        cwd: Working directory. Defaults to ``/`` rather than inheriting the worker's
            cwd, so the capability does not depend on where the worker was started.
        stderr: Where the command's **fd 2** goes; discarded by default. It must not
            be merged into the stream: a command's diagnostics quote host state
            (``fatal: '/srv/secrets/repo.git' does not appear to be a git
            repository``), so relaying them hands the guest a map of the host
            filesystem. Point it at a file or an fd to keep them.

            ``subprocess.STDOUT`` is refused for that reason, and
            ``subprocess.PIPE`` because nothing reads it, so a command that fills the
            pipe blocks in ``write(2)`` for ever and never exits, pinning the
            connection's slot until :meth:`StreamHatch.close`.

            This covers fd 2 and nothing more. A command that multiplexes its own
            diagnostics onto **stdout** routes around it, and git does: ``git
            upload-archive`` reports the message above on its pkt-line sideband,
            host path included. Where the command has such a channel, keep the host
            path out of it — pass ``cwd`` and a bare basename in ``argv`` rather
            than an absolute path.

    Note:
        The command's own **stdin grammar** is part of the capability, and is the one
        thing this function cannot check for you. A fixed argv means guest bytes
        never become *this* process's argv; it does not mean they cannot become a
        *downstream* process's argv or a shell command, if the command you chose
        offers that. ``git upload-pack`` does not. ``sqlite3``
        (``.shell``/``.system``/``.import``), ``psql`` (``\!``, ``COPY … FROM
        PROGRAM``), ``mysql`` (``system``), ``ftp``, ``gdb`` and ``ed`` all do, and
        splicing any of them hands the guest host command execution however
        read-only the flags look. Choose a command whose stdin grants nothing beyond
        the capability you meant to grant.
    """
    # Eagerly, so a bad stderr fails when the hatch is built rather than on the
    # first connection.
    _check_stderr(stderr)
    argv = list(argv)
    if not argv:
        raise ValueError('splice_subprocess(argv) requires a command')

    def handler(_stream: Stream) -> Process:
        return Process(argv, cwd=cwd, env=env, stderr=stderr)

    return handler


def git_url(
    name: str = 'stream',
    *,
    profile: _sandbox.SandboxProfile | None = None,
    python: str | None = None,
) -> str:
    """The ``ext::`` URL a guest uses to reach the stream hatch called ``name``.

    git has no unix-socket transport, but ``ext::`` carries its native protocol over
    an arbitrary command's stdin/stdout, so the bound-in connector reaches the hatch.
    git gates ``ext::`` behind ``protocol.ext.allow`` because such a URL is command
    execution and hostile fetched content (a submodule URL) could smuggle one in.
    Inside the sandbox that gate protects nothing, so enable it per invocation and
    leave the host's git config alone:

        git -c protocol.ext.allow=always clone <git_url('repo', profile=profile)> work

    The URL passes no ``%s``/``%S``/``%G``, so git sends no service or repository
    line: the host fixed both when it bound the hatch.

    Args:
        name: The hatch to reach.
        profile: The profile the guest will run under; the interpreter comes from
            ``profile.python``, so the URL cannot disagree with the sandbox it runs
            in. Omitting it falls back to a bare ``python3`` off the guest ``PATH``,
            which ``SandboxProfile.with_venv`` does not touch and a curated
            ``rootfs`` need not populate, and git reports that as
            ``cannot run python3: No such file or directory``.
        python: An explicit interpreter, overriding ``profile``.
    """
    _sandbox.validate_guest_name(name)
    interpreter = python or (profile.python if profile is not None else 'python3')
    return f'ext::{interpreter} {_sandbox.GUEST_CONNECT} {guest_socket_path(name)}'


# --------------------------------------------------------------------------- #
# The hatch                                                                     #
# --------------------------------------------------------------------------- #
class StreamHatch:
    """Serve a raw bidirectional stream over the sandbox UDS, per-connection.

    Conforms to postern's ``Hatch`` protocol (``socket_path`` + ``accepting()``), so
    it drops into ``Sandbox(hatch=...)`` where a `GrpcHatch` would. It is a **named
    dial** hatch: the guest reaches it as an ordinary file at
    ``/run/postern/<name>.sock``, exported as ``$POSTERN_HATCH_<NAME>``, so a sandbox
    can carry several — one per resource. Reused across many runs: serves once on
    first :meth:`accepting`, until :meth:`close`.
    """

    # Ask `Sandbox` to bind the in-guest stdio↔UDS connector at $POSTERN_CONNECT:
    # git's ext:: transport and its kind reach a byte stream, not a socket.
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
                ``0700`` temp dir. **The socket itself is chmod'd 0666**,
                deterministically rather than by umask, because the guest runs as an
                unrelated uid and has to be able to connect — so the containing
                directory is the entire host-side access control. Pass a path only in
                a directory no other local uid can traverse: a stable path somewhere
                convenient (``/tmp/myservice.sock``) publishes the capability to
                every user on the box.
            max_conns: Concurrent connections served. Gates **accepting**, not
                dispatch to a worker pool: a stream connection is long-lived by
                definition, so a queue of already-accepted connections would be a
                queue of host file descriptors and a guest that opens thousands
                walks the host to EMFILE while doing no work. At the cap the accept
                loop stops accepting, leaving connections in the kernel backlog
                where they cost the host nothing. The default is small because each
                served connection can hold a subprocess, a socket and a thread for
                its whole lifetime, so this is the real bound on what one guest can
                pin.
            backlog: ``listen`` backlog. Past ``max_conns + backlog`` pending
                connections the kernel refuses the guest's dial, rather than a
                host-side queue absorbing it.
            grace: Seconds to wait for a subprocess to exit after ``terminate()``
                before ``kill()``, and for the guest to close after we half-close.
                Bounds teardown; it is not a limit on the stream's lifetime.
        """
        _sandbox.validate_guest_name(name)
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
        return _sandbox.guest_env_var(self._name)

    # -- serving lifecycle (mirrors GrpcHatch) ------------------------------- #
    def start(self) -> None:
        """Start serving. Idempotent while open; raises once :meth:`close` has run.

        ``close()`` is **terminal**, matching `GrpcHatch`: it shuts the thread pool
        down for good, so construct a new hatch rather than restarting this one.
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
        # The guest runs as an unrelated uid and must be able to connect, and umask
        # would otherwise decide whether it can. Host-side access control is the
        # containing directory (see the socket_path argument), never this mode.
        with contextlib.suppress(OSError):
            os.chmod(self._path, 0o666)  # noqa: S103 — intentional; see the comment above
        self._srv = srv
        self._started = True
        self._accepting = True
        threading.Thread(target=self._accept_loop, args=(srv,), daemon=True, name='postern-stream-accept').start()

    def _clear_stale_socket(self) -> None:
        """Remove a dead socket left where we are about to bind. Nothing else.

        A crashed run leaves its socket file behind and ``bind`` would fail
        ``EADDRINUSE``, but a caller-supplied ``socket_path`` is somebody else's file
        until we have bound it. So a path under the temp dir this hatch created is
        ours to clear; any other path is cleared only if it is an ``AF_UNIX`` socket
        with nobody listening. Anything else is left for ``bind`` to refuse loudly.
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
                # handshake, EINTR. Riding these out rather than retiring the hatch.
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
        # A hostile connection must never take a pool worker down, and must always
        # give its slot back.
        verdict: Process | None = None
        try:
            # Tracked *before* the verdict: a handler is entitled to read a preamble,
            # and until this connection is in _live, close() cannot shut it down.
            self._track(conn, None)
            verdict = self._handler(Stream(conn, self._name))
            if verdict is not None and not verdict._claim():  # noqa: SLF001 — the hatch owns the verdict's lifecycle
                # Another connection's verdict. Forget it *before* raising: the
                # `finally` below would otherwise dispose of that connection's live
                # command. This one takes the refusal path.
                verdict = None
                raise ValueError('a Process verdict is single-use; this one is already attached to a connection')
            if verdict is not None:
                # Inside the try, so a refused verdict is contained to this
                # connection like any other handler failure.
                verdict._attach(conn, self._grace)  # noqa: SLF001 — the hatch owns the verdict's lifecycle
            self._track(conn, verdict)
            if verdict is None:
                # A raw stream has no way to say "no", so a refusal is end-of-stream
                # and nothing else — no diagnostic, which here would be host state.
                _drain(conn, self._grace)
            else:
                _await_command(verdict)
        except Exception:  # noqa: BLE001 — hostile input; contain it to this connection
            _drain(conn, self._grace)
        finally:
            # The verdict must not outlive the connection: an abandoned subprocess
            # lets a guest reconnecting in a loop grow the host's process table.
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
        inflates the slot semaphore.

        Every live connection is shut down and the command behind it reaped, because
        nothing else will: ``ThreadPoolExecutor`` workers are non-daemon and
        ``shutdown(wait=False)`` does not interrupt one, so a worker parked in
        ``proc.wait()`` on a command the guest is keeping alive would hold that
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
            # another thread is blocked in accept() on does not wake that thread.
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
def _check_stderr(stderr: int | None) -> None:
    """Refuse the two ``stderr`` values that cannot work on this surface.

    ``PIPE`` deadlocks: nothing drains it, so a command that fills the 64 KiB pipe
    blocks in ``write(2)`` for ever and never exits, pinning the connection's slot
    until :meth:`StreamHatch.close`. ``STDOUT`` discloses: stdout *is* the guest's
    socket, so merging fd 2 into it relays the command's diagnostics — which quote
    host state — straight to the guest.
    """
    if stderr == subprocess.PIPE:
        raise ValueError(
            'stderr=subprocess.PIPE is not supported: nothing drains it, so the command deadlocks. '
            'Use DEVNULL (the default), or pass a file/fd to keep the diagnostics.'
        )
    if stderr == subprocess.STDOUT:
        raise ValueError(
            'stderr=subprocess.STDOUT is not supported: stdout is the guest socket, so merging fd 2 '
            'into it hands the guest the command diagnostics (host paths included). '
            'Use DEVNULL (the default), or pass a file/fd to keep them host-side.'
        )


def _normalise_stdio(conn: socket.socket) -> None:
    """Put ``conn`` in the shape ordinary (non-pty) stdin/stdout has. Never raises.

    A command's fds 0 and 1 are ``dup2``s of *this* open file description, so its
    file status flags and its socket options are shared, not copied: whatever a
    handler configured on the connection is what the command runs with. Ordinary
    stdio is blocking, has no signal-driven I/O and has no I/O timeouts, so that is
    what the command gets.

    ``SO_LINGER`` is excluded: close semantics carry the disposition signal the
    guest reads. So are ``SO_RCVBUF``/``SO_SNDBUF``, ``SO_MARK``, ``SO_PRIORITY``
    (sizes and routing hints, which a handler that sets them means to set) and
    ``SO_PEEK_OFF`` (``MSG_PEEK`` only, which ordinary stdio never uses).
    """
    fd = conn.fileno()
    with contextlib.suppress(OSError, ValueError):
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        if flags & _HANDOVER_CLEAR_FL:
            fcntl.fcntl(fd, fcntl.F_SETFL, flags & ~_HANDOVER_CLEAR_FL)
    # Zeroed so no stale owner or signal number survives the handover.
    with contextlib.suppress(OSError, ValueError):
        fcntl.fcntl(fd, fcntl.F_SETOWN, 0)
    if _F_SETSIG is not None:
        with contextlib.suppress(OSError, ValueError):
            fcntl.fcntl(fd, _F_SETSIG, 0)
    for opt in _TIMEOUT_OPTS:
        with contextlib.suppress(OSError, ValueError):
            current = conn.getsockopt(socket.SOL_SOCKET, opt, _TIMEVAL_MAX)
            if any(current):
                conn.setsockopt(socket.SOL_SOCKET, opt, bytes(len(current)))
    flag_opts = [(socket.SO_RCVLOWAT, 1), (socket.SO_OOBINLINE, 0)]
    if _SO_PASSCRED is not None:
        flag_opts.append((_SO_PASSCRED, 0))
    for opt, value in flag_opts:
        with contextlib.suppress(OSError, ValueError):
            conn.setsockopt(socket.SOL_SOCKET, opt, value)


def _stderr_is_the_connection(proc: subprocess.Popen[bytes] | None, conn: socket.socket) -> bool:
    """Whether an adopted command's fd 2 is the guest's connection. Never raises.

    ``subprocess`` keeps no record of the ``stderr`` argument it was given, so an
    adopted `Popen` built with ``stderr=subprocess.STDOUT`` is indistinguishable
    from one built with ``DEVNULL`` by inspecting the object — ``proc.stderr`` is
    ``None`` either way. The child is not: on Linux its fd 2 can be stat'd through
    ``/proc``, and an inode matching the connection's means fd 2 goes to the guest.

    Best-effort by construction — ``False`` where there is no ``/proc``, where the
    child has already exited, or on any error. Off Linux, `from_popen`'s docstring
    is the only guard.
    """
    if proc is None:
        return False
    try:
        target = os.fstat(conn.fileno())
        actual = os.stat(f'/proc/{proc.pid}/fd/2')
    except (OSError, ValueError):
        return False
    return (actual.st_dev, actual.st_ino) == (target.st_dev, target.st_ino)


def _abnormal_stdio(conn: socket.socket) -> list[str]:
    """Which of the normalised properties ``conn`` is not in. Never raises.

    Only reached for an adopted `Popen`, where the child is already running and
    normalising would race it, so this reports rather than repairs.
    """
    bad: list[str] = []
    with contextlib.suppress(OSError, ValueError):
        flags = fcntl.fcntl(conn.fileno(), fcntl.F_GETFL)
        for name in ('O_NONBLOCK', 'O_ASYNC', 'O_APPEND', 'O_DIRECT', 'O_NOATIME'):
            bit = getattr(os, name, 0)
            if bit and flags & bit:
                bad.append(name)
    for name, opt in zip(('SO_RCVTIMEO', 'SO_SNDTIMEO'), _TIMEOUT_OPTS, strict=True):
        with contextlib.suppress(OSError, ValueError):
            if any(conn.getsockopt(socket.SOL_SOCKET, opt, _TIMEVAL_MAX)):
                bad.append(name)
    return bad


def _dispose(verdict: Process | None, grace: float) -> None:
    """Release whatever a verdict was holding. Idempotent, never raises."""
    if verdict is not None:
        with contextlib.suppress(Exception):
            verdict.dispose(grace)


def _readable(sock_or_fd: socket.socket | int, timeout: float) -> bool:
    """Wait for readability. ``selectors``, never ``select.select``.

    CPython's ``select()`` rejects any descriptor >= ``FD_SETSIZE`` (1024) with
    ``ValueError`` before it reaches the syscall, and the descriptor budget belongs
    to the embedding worker. ``poll``/``kqueue`` have no such ceiling.
    """
    with contextlib.suppress(OSError, ValueError), selectors.DefaultSelector() as sel:
        sel.register(sock_or_fd, selectors.EVENT_READ)
        return bool(sel.select(timeout))
    return False


def _drain(guest: socket.socket, grace: float) -> None:
    """Discard what the guest is still sending, bounded by ``grace``.

    On Linux, closing an ``AF_UNIX`` socket while bytes remain unread in its receive
    queue makes the kernel set ``ECONNRESET`` on the *peer* (``unix_release_sock``),
    so the guest's next read fails with a reset instead of reporting end-of-stream,
    and a client such as git reads that as a protocol error. Draining first turns the
    close into an orderly one. ``grace`` bounds the whole drain, so a guest that
    keeps writing for ever gives up its slot anyway, at the price of the reset it
    brought on itself.

    Does **not** touch the write side. Reached when a handler refuses, when a
    handler raises, and after a command has exited — in none of those is anything
    else going to read the socket.

    Waits on readability rather than ``settimeout``, which is per-socket and would
    outlive this call. Each wait is only ``_DRAIN_QUIET`` long, because an already
    empty receive queue is the answer rather than a reason to keep waiting.
    """
    deadline = time.monotonic() + grace
    with contextlib.suppress(OSError, ValueError):
        while (remaining := deadline - time.monotonic()) > 0:
            if not _readable(guest, min(_DRAIN_QUIET, remaining)):
                return  # nothing queued: closing now is already orderly
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
    this only waits.

    It does **not** drain. `_drain` suppresses a reset that is purely our own
    teardown artifact; here the reset is signal, since a command that died
    mid-request leaves the unread remainder queued while one that exited cleanly
    leaves an empty queue. Draining would report the former as a clean finish.

    Waits **without reaping**, which is what lets teardown still collect the
    command's process group: a plain ``wait()`` releases the leader's pid, and
    :func:`_reap` then declines to signal a group it can no longer prove is ours.
    """
    proc = verdict.proc
    if proc is None:  # never attached; nothing to wait for
        return
    if proc.returncode is not None:
        # Already waited — by `close()` racing this connection, or by a handler that
        # adopted a finished `Popen`. Without this the kqueue tier below registers
        # EVFILT_PROC on a released pid, and once that pid is recycled the
        # registration succeeds against a stranger. `_exited` guards the same way.
        return
    if _WAITID is not None:
        try:
            _WAITID(_P_PID, proc.pid, _WEXITED | _WNOWAIT)
        except OSError:
            proc.wait()  # interrupted, or no such child: fall back
        return
    if _kq_exited(proc.pid, None) is not None:
        return
    proc.wait()


def _kq_exited(pid: int, timeout: float | None) -> bool | None:
    """Whether ``pid`` has exited, via ``kqueue``, **without reaping it**.

    ``None`` means kqueue cannot answer here (not this platform, or registration
    failed), so the caller falls through to the reaping fallback. ``timeout=None``
    blocks until the exit; ``0`` polls.

    Only ever called with our own unreaped child's pid: ``EVFILT_PROC`` reports an
    immediate ``NOTE_EXIT`` for a pid that does not exist at all, so on any other pid
    a ``True`` here would be meaningless.
    """
    if _KQUEUE is None or _KEVENT is None or _KQ_FILTER_PROC is None or _KQ_NOTE_EXIT is None:
        return None
    try:
        kq = _KQUEUE()
    except OSError:  # only if the platform claims kqueue and then refuses it
        return None
    try:
        event = _KEVENT(
            pid,
            filter=_KQ_FILTER_PROC,
            flags=_KQ_EV_ADD | _KQ_EV_ONESHOT,
            fflags=_KQ_NOTE_EXIT,
        )
        try:
            return bool(kq.control([event], 1, timeout))
        except OSError:
            return None
    finally:
        kq.close()


def _signal_group(proc: subprocess.Popen[bytes], pgid: int | None, sig: int) -> None:
    """Signal ``pgid`` if there is one; otherwise just ``proc``.

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

    ``poll()`` reaps, and reaping releases the leader's pid. A group id stays valid
    only while that pid is allocated, which an unreaped zombie guarantees, so a group
    kill issued after a ``poll()`` can land on a recycled pid — plausibly another
    connection's command, since every verdict mints a session leader.

    What this cannot answer: if another reaper in the host process has already
    collected the status, every tier reports "exited" indistinguishably from a clean
    exit. See "Teardown and its caveats" in the module docstring.
    """
    if proc.returncode is not None:
        return True
    if _WAITID is not None:
        try:
            return _WAITID(_P_PID, proc.pid, _WEXITED | os.WNOHANG | _WNOWAIT) is not None
        except OSError:
            return proc.poll() is not None
    kq = _kq_exited(proc.pid, 0)
    if kq is not None:
        return kq
    return proc.poll() is not None  # weaker: this reaps, so no group signal follows


def _wait_exited(proc: subprocess.Popen[bytes], grace: float) -> None:
    """Wait up to ``grace`` for the command to exit, **without reaping it**.

    ``Popen.wait(timeout=...)`` reaps, which releases the leader's pid and so the
    captured ``pgid`` (see :func:`_exited`), hence a poll on the non-reaping exit
    test. ``grace=0.0`` is a single check.
    """
    deadline = time.monotonic() + grace
    while not _exited(proc):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(_EXIT_POLL, remaining))


def _reap(proc: subprocess.Popen[bytes], grace: float, pgid: int | None = None) -> None:
    """Terminate, then kill, then wait — never leave a child of the host running.

    Signals the process *group*, not the process: a command that leaves a background
    child behind otherwise strands it, and — because that child inherited the guest's
    *socket* — strands the guest too, waiting for an end-of-stream that can never
    come. Two things bound that guarantee, both written up under "Teardown and its
    caveats" in the module docstring: it is skipped entirely if something else in the
    host process reaps arbitrary children, and it does not reach a grandchild that has
    left the group with ``setsid()``.

    ``SIGKILL`` goes to the group whenever the leader is confirmed gone and still
    unreaped, **not** only when the leader outlived ``grace``: a group member that
    ignores ``SIGTERM`` survives while the leader dies inside ``grace``, and it holds
    a dup of the guest's socket.

    The final ``wait()`` is untimed; it cannot hang, because it runs only after
    ``SIGKILL``.
    """
    # Signalling the group is only safe while we still hold the leader's pid: if
    # something already waited this Popen the pid may have been recycled.
    if proc.returncode is None:
        if not _exited(proc):
            _signal_group(proc, pgid, signal.SIGTERM)
            _wait_exited(proc, grace)
        if proc.returncode is None:
            # Either exited and not yet reaped, or still running past `grace`. Either
            # way an unreaped zombie pins the pid, so the group id is still valid.
            # The re-check matters because `_exited`'s last-resort tier reaps.
            _signal_group(proc, pgid, signal.SIGKILL)
    with contextlib.suppress(Exception):
        proc.wait()
    # stderr too: `splice_subprocess` refuses PIPE, but a handler may build its own
    # Popen, and an unclosed read end leaks until the Popen is collected.
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
