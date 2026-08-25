"""The stream hatch: a raw bidirectional byte stream over the sandbox UDS.

Where `GrpcHatch` grants the guest a set of typed methods, `StreamHatch` gives it
**one socket** and nothing else. Per accepted connection a handler you supply
decides what the guest's bytes are spliced to — a host-side subprocess's stdio,
or nothing.

    handler(stream) -> Process | None

* ``stream`` — the accepted connection (``stream.conn``) and the name of the
  hatch it arrived on (``stream.hatch``).
* return ``Process(argv)`` to hand the connection to a subprocess as its stdin
  and stdout, or ``None`` to refuse (the guest sees EOF). The verdict *describes*
  the command and the hatch spawns it, which is what lets the connection be put
  into ordinary-stdio shape before there is a child to race
  (`Process.from_popen` is the escape hatch, and says what it costs).
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
takes teardown that signals the command's whole *process group*: a child the
command left behind inherits the guest's socket, so it holds the connection open
after the command is gone and the guest waits for an end-of-stream that can never
come. Without it one connection could cost a slot, a subprocess and a
non-exitable worker thread permanently, and ``max_conns`` of them killed the hatch
for the worker's whole life rather than the run's.

Teardown and its caveats
------------------------
Linux is the only platform postern sandboxes *on* (bubblewrap), but a
`StreamHatch` is host-side and runs anywhere, so the host half is exercised on
macOS too. Everything in this section follows from one requirement: teardown
signals the command's process *group*, and doing that safely means observing the
command's exit **without reaping it** — an unreaped zombie is what proves the
leader's pid, and so the group id captured at spawn, is still ours rather than a
number the kernel has since handed to somebody else.

**Observing the exit: three tiers.** In ``_WAITID``'s order, and the reason there
is more than one is that no single interface is portable.

1. ``os.waitid(..., WNOWAIT)``. Always present on Linux. On macOS its presence is
   a property of the *build* rather than of the platform, which is why it is
   reached through ``getattr`` and why typeshed's "unavailable on darwin" is not
   simply wrong: measured absent on CPython 3.9.6 (Apple's system interpreter),
   3.10.20, 3.11.12, 3.11.13 and 3.12.13, and present on 3.13.12 — where it is
   also correct end to end (the leader stays a zombie, the captured pgid stays
   addressable, and ``killpg`` reaches a child the command left behind).
2. ``kqueue``/``EVFILT_PROC``/``NOTE_EXIT`` on macOS and the BSDs, measured
   equivalent to tier 1. One sharp edge: ``EVFILT_PROC`` reports an immediate
   ``NOTE_EXIT`` for a pid that does not exist *at all*, so a registration only
   answers the question for a pid we own and have not reaped. `Popen` guarantees
   that here, and `_kq_exited` says so — but it makes the tier unusable for a pid
   whose fate is what you are trying to establish.
3. ``Popen.poll()``/``wait()``. These reap, which frees the leader's pid, so
   `_reap` then declines to signal a group it can no longer prove is ours and a
   background child survives holding the guest's socket. This tier exists only as
   a floor; without tier 2 every macOS interpreter lacking ``os.waitid`` landed on
   it, and ``test_teardown_reaches_the_whole_process_group`` and
   ``test_a_child_left_behind_does_not_hold_the_connection_open`` did not pass
   vacuously there — they *failed*, the second with the guest timing out. The
   suite had only ever been run on Linux.

**Caveat 1 — another reaper in the host process voids the group signal.** If
anything else in the embedding process reaps arbitrary children, teardown
silently skips the process-group kill. The triggers are ordinary: a supervisor
loop calling ``waitpid(-1)``, ``multiprocessing``, an asyncio child watcher, or
``SIGCHLD`` set to ``SIG_IGN``.

The mechanism is an information loss in ``Popen``, not a branch in this module.
Once a third party has collected the status, ``waitid`` raises
``ChildProcessError`` (``ECHILD``); `_await_command` falls back to ``proc.wait()``,
and ``Popen._try_wait`` catches that same ``ECHILD`` and *synthesises a status of
0* — measured: ``wait()`` returned ``0`` in 2.3 ms for a command whose real exit
status was 7, and ``poll()`` likewise returned ``0`` for one that exited 9. So
``returncode`` is ``0``, `_reap`'s outer ``if proc.returncode is None`` is false,
and the whole signalling block is skipped. (On the `close`-first path
`_dispose` runs before anything has set ``returncode``, so `_exited` is reached
instead: ``waitid`` gives ``ECHILD``, its ``poll()`` fallback synthesises 0 again,
and the second ``if proc.returncode is None`` guard fails just the same. Two routes,
one outcome.)

Measured consequence, using ``SIGCHLD=SIG_IGN`` as a race-free stand-in for a
supervisor: without a foreign reaper, ``killpg`` is called once with ``SIGKILL``,
the guest reads end-of-stream immediately, and every group member is a zombie.
With one, ``killpg`` is **never called**, the guest times out after 6 s having
never reached end-of-stream, and two group members are still alive. In both cases
the host's thread count returns to its baseline and no ``postern-stream`` thread
is left behind — this leaks the command's *children*, and it does not hang the
worker or leak a thread, which is the plausible wrong guess about it.

**Declining to signal is the correct response to that ambiguity, not a bug.**
``ECHILD`` is indistinguishable from a clean exit, and signalling anyway would
reintroduce exactly the pid-reuse hazard ``8d8e00f`` closed — *because* the third
party's reap freed the pid, and a freed pid really is reissued (measured: with
``pid_max`` lowered, the reaped pid came back within two wraps of the allocator).
Every verdict mints a session leader, so a stale group kill is plausibly aimed at
another connection's command. This is an information limit, and closing it needs a
different primitive, not a different branch — see *The fix* below.

**Caveat 2 — a grandchild that leaves the process group escapes teardown.** The
guarantee is over the command's process group, which is where a shell's ``&``
child stays. A *correctly daemonising* sidecar calls ``setsid()`` and leaves it,
and nothing here reaches it. Measured on this revision: with a plain ``&`` child
the guest reads end-of-stream, and with a ``setsid()`` child the guest times out
while the escapee keeps a dup of the guest's socket indefinitely. ``max_conns``
still holds — the slot is released — so the cost is one leaked process and one
leaked descriptor per connection, unbounded across reconnections. Read "a
background child it left behind", wherever this module says it, as "one that stays
in the group".

**The fix, deliberately deferred.** Both caveats above are open in this revision
and are to be closed in a follow-up. The shape of it, with the parts that were
measured rather than assumed:

* *Reaper-independent exit observation.* Acquire the handle **at spawn** —
  ``os.pidfd_open(pid)`` on Linux, a ``kqueue`` ``EVFILT_PROC``/``NOTE_EXIT``
  registration on macOS and the BSDs — and wait on that instead of on
  ``waitid``/``wait``. Verified: both still report the exit after a third party
  has reaped the leader (the pidfd becomes readable; the kqueue still delivers
  ``NOTE_EXIT``). At spawn and not at wait time, because once the pid is gone
  ``pidfd_open`` fails ``ESRCH`` and ``EVFILT_PROC`` gives the spurious immediate
  event described in tier 2. That makes "the command exited" and "somebody else
  reaped it" distinguishable, which is what caveat 1 currently cannot tell apart.
* *A group signal that does not go through a pid number.* This is the half a
  pidfd does **not** give for free, and the easy assumption to get wrong: holding
  a pidfd does *not* pin the pid number against reuse — measured, the reaped pid
  was reissued within two wraps of the allocator whether or not a pidfd on it was
  open — so ``killpg(pgid)`` after a foreign reap stays unprovable. What does work
  is ``pidfd_send_signal(fd, sig, NULL, PIDFD_SIGNAL_PROCESS_GROUP)``, which names
  the group through the pidfd rather than through a number: measured, it killed a
  live group member whose leader a third party had already reaped. That flag is
  **Linux 6.9+**, so ``killpg`` plus today's decline has to remain the fallback
  below it — and on macOS and the BSDs there is no equivalent, so caveat 1 stays
  open there even with the kqueue handle in place.
* Caveat 2 is not addressed by either primitive: the escapee is in another group
  by its own choice. The durable answer is to bound the command with a container
  rather than a group — cgroup v2 ``cgroup.kill`` on Linux — which needs
  delegation an unprivileged embedder may not have.
* Secondary, and not a reason on its own: a pidfd or kqueue handle is *pollable*,
  so the per-connection wait would stop needing a thread parked in ``waitid``. At
  ``max_conns=8`` that is eight threads.
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
# Poll interval while waiting for a signalled command to exit. Small, because it
# is pure teardown latency; a poll rather than `Popen.wait(timeout=...)` because
# that reaps, and the reap is what invalidates the group id (see `_wait_exited`).
_EXIT_POLL = 0.02
# How long `_drain` waits for the *next* byte before calling the receive queue
# empty. An empty queue is what makes the last close orderly, so this is a
# quiet-period test and not a share of `grace`, which still caps the whole drain.
_DRAIN_QUIET = 0.1
# Observing the command's exit *without reaping it* is what keeps its pid — and so
# the process group id captured at spawn — provably ours until teardown has
# signalled the group. Three tiers, because no single interface is portable:
# waitid(WNOWAIT), then kqueue/EVFILT_PROC/NOTE_EXIT, then a reaping poll()/wait()
# as the floor. Which platform gets which, what each guarantees, and the two
# caveats that remain open (a third-party reaper in the host process, and a
# grandchild that leaves the group) are in this module's docstring under "Teardown
# and its caveats" — deliberately there and not repeated here, because the reader
# who needs them is not reading a fallback branch. waitid is reached through
# getattr because its presence on macOS is a property of the build.
_WAITID = getattr(os, 'waitid', None)
_P_PID = getattr(os, 'P_PID', 0)
_WEXITED = getattr(os, 'WEXITED', 0)
_WNOWAIT = getattr(os, 'WNOWAIT', 0)
# Every name the kqueue tier touches is reached through getattr, the whole family
# and not just some of it: `select.kevent` and the KQ_* constants exist only on the
# BSDs, so naming them directly is an attribute error on Linux at *type-check* time
# even though the call site can never run there — which is exactly what CI found
# the first time this tier reached it (pyright runs on ubuntu, where the stubs have
# no kevent).
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
# (16 bytes on Linux LP64, 12 on darwin). Never hard-coded: the length the kernel
# reports for the current value is the length written back.
_TIMEOUT_OPTS = (socket.SO_RCVTIMEO, socket.SO_SNDTIMEO)
_TIMEVAL_MAX = 32
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

    **The socket is handed over, not lent.** A `Process` verdict makes it the
    command's stdin and stdout, so it is normalised at handover — blocking, no
    signal-driven I/O, no socket timeouts — and anything a handler configured on
    it is undone. Do not rely on such settings persisting, and in particular do
    not reach for :meth:`socket.socket.settimeout` to bound a preamble read:
    CPython implements it by setting ``O_NONBLOCK``, which lives on the open file
    description the command's fds 0 and 1 are dup2's of, so before normalisation
    it silently truncated the command's response (measured: 219 KiB of 4 MiB
    delivered, and the guest read it as a clean end-of-stream). Use
    :meth:`read_preamble`, which waits on readability and touches no flags.

    Bounding that read matters for more than tidiness: the hatch cannot shut a
    connection down until the handler has returned, so a handler that blocks
    for ever on a guest that connects and sends nothing costs a slot for the
    hatch's whole life. ``max_conns`` of those is a hatch a guest has silenced
    with nothing but ``connect()``.

    ``hatch`` is the hatch's guest name, so one handler can serve several hatches
    and still know which capability was dialled.
    """

    conn: socket.socket
    hatch: str

    def read_preamble(self, max_bytes: int, timeout: float) -> bytes:
        """Read up to ``max_bytes``, waiting at most ``timeout`` seconds in total.

        The flag-free way to consume a preamble: readiness comes from a selector
        rather than from a socket timeout, so the connection's file status flags
        are exactly as the command will need them (see the class docstring, and
        `_drain`, which avoids ``settimeout`` for a related reason). Returns what
        arrived — short, or empty on timeout or immediate end-of-stream — rather
        than raising, because on this surface a guest that says nothing is not an
        error, it is a refusal waiting to be made.
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

    **Declarative on purpose.** The verdict describes the command; the hatch
    spawns it. That inversion is not ergonomics, it is the only way the
    descriptor hygiene can be structural: the connection has to be put into
    ordinary-stdio shape *before* ``Popen``, and a verdict that arrives holding an
    already-spawned `Popen` is too late to fix. Measured — with the normalisation
    sited after ``Popen``, half a millisecond of delay in the parent (one lost
    timeslice) took a 4 MiB response down to 219 KiB on 10 of 10 attempts. Owning
    the spawn also means ``start_new_session=True`` is guaranteed rather than
    remembered, so teardown always has a process group of its own to signal, and
    the pipe/stderr contract is checked in one place instead of being a rule a
    handler has to know.

    The socket **is** the command's stdin and stdout, so the kernel moves the
    bytes: there is no host-side pump, no thread per direction, and nothing in
    this process on the data path at all. Half-close propagates natively — the
    guest's ``shutdown(SHUT_WR)`` is an EOF on the command's stdin, which is how
    ``git upload-pack`` learns the request is over, and the command's exit is the
    EOF the guest reads.

    The hatch's remaining job is lifecycle: wait for the command, then terminate,
    kill and reap its process group.

    A command that would introspect the socket, or hand descriptors back over it
    with ``sendmsg``, could do so — but only by colluding with the guest, and a
    host that splices a command like that has already granted the guest something
    that does not play by the rules. That is the same category as a command that
    writes host state to its stdout, not a new one.

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
    # from_popen. **Read-only**, and that is the point: assigning it was a way to
    # reach the adopted path with none of :meth:`from_popen`'s validation — a
    # `Popen` holding pipes was accepted, nothing pumped them, and the command
    # deadlocked filling one while the guest waited for bytes that never came
    # (measured). A checked-at-the-door field would still have been a door; this
    # makes the bypass unrepresentable, which is the same argument as one socket
    # per resource. Readable because teardown tests and handlers that want the pid
    # need it; ``None`` until the hatch attaches the verdict.
    _proc: subprocess.Popen[bytes] | None = dataclasses.field(default=None, init=False, repr=False)
    # The command's process group, captured at spawn and not at teardown: by then
    # the leader may have been reaped, so ``getpgid`` on its pid is ESRCH (and on
    # darwin it is ESRCH for a zombie regardless) — while the *group* is still
    # alive, and here still holding a descriptor for the guest's socket. ``None``
    # when the command is not its own group leader, i.e. an adopted `Popen` built
    # without ``start_new_session=True``, whose group is the worker's own:
    # signalling that would signal the worker. Read-only for the same reason
    # ``proc`` is: a writable pgid is a ``killpg`` at an arbitrary group.
    _pgid: int | None = dataclasses.field(default=None, init=False, repr=False)
    # Whether this verdict's Popen came through from_popen — i.e. whether the
    # adopted path was *asked for*. "``proc`` is set" is not the same question, and
    # conflating them is what made a reused verdict silently take the adopted
    # branch on its second connection.
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
        # Before the argv check and before from_popen's early return, so it cannot
        # be skipped: `Process(stderr=subprocess.STDOUT)` with no argv used to
        # construct happily, because the only call was past this branch.
        _check_stderr(self.stderr)
        if self.argv is None:
            return  # from_popen, or a Process() the hatch will refuse at attach
        self.argv = list(self.argv)
        if not self.argv:
            raise ValueError('Process(argv) requires a command')

    @classmethod
    def from_popen(cls, proc: subprocess.Popen[bytes]) -> Process:
        """Adopt a `Popen` you spawned yourself: you own the descriptor hygiene.

        The escape hatch for what ``argv``/``cwd``/``env``/``stderr`` do not
        cover — ``pass_fds``, ``user=``/``group=`` to run a command as a
        per-tenant uid, an rlimit in ``preexec_fn``. It cannot give the same
        guarantee the declarative form does: by the time this verdict reaches the
        hatch the child is already running, so the connection cannot be
        normalised without racing it. The hatch therefore *validates* instead —
        a connection that is not in ordinary-stdio shape is refused with the
        reason named, which is loud rather than silently corrupt, but it is late:
        the child may already have died on ``EAGAIN``. So put the socket in
        ordinary shape (or simply never touch it) before you spawn.

        Spawn with ``stdin=stream.conn.fileno(), stdout=stream.conn.fileno()`` and
        ``start_new_session=True``; without the latter ``pgid`` is ``None`` and
        teardown can only signal the command itself, so a background child it
        leaves behind keeps the guest's connection open.

        **What you are also taking on, beyond the descriptors.** ``Process(argv)``
        does not merely spawn for you, it spawns with three defaults that are
        security properties, and a `Popen` you built has none of them unless you
        passed them yourself:

        * ``stderr``. The declarative path defaults to ``DEVNULL`` and *refuses*
          ``STDOUT``, because stdout is the guest's socket and a command's
          diagnostics quote host paths. ``Popen``'s own default is to inherit fd 2,
          and ``stderr=subprocess.STDOUT`` merges it into the guest's stream. The
          hatch detects that last case where the platform allows (Linux, by
          comparing the child's fd 2 with the connection) and refuses the verdict,
          but detection is not the same as a default: pass ``DEVNULL`` or a file.
        * ``env``. The declarative path passes a fixed minimal ``PATH``; ``Popen``
          inherits the worker's entire environment, secrets included, into a
          process whose stdin is attacker-controlled. Pass ``env=`` explicitly.
        * ``cwd``. The declarative path uses ``/``; ``Popen`` inherits the worker's
          working directory, so the capability starts depending on where the host
          process was started. Pass ``cwd=`` explicitly.

        Those two are not policed here — owning the hygiene is this method's whole
        premise, and a check that guessed at intent would be worse than a note. The
        one that is checked is the one that leaks host state *to the guest*.
        """
        verdict = cls()
        verdict._proc = proc
        verdict._adopted = True
        verdict._capture_pgid()
        held = [name for name in ('stdin', 'stdout', 'stderr') if getattr(proc, name) is not None]
        if held:
            # Reap before raising: this path abandons the child otherwise, and a
            # guest reconnecting in a loop then grows the host's process table.
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

        A verdict describes *one* connection's command, and nothing about
        ``Process(argv)`` says so: it looks like an immutable description, so
        caching one — a module-level constant, a dict of verdicts by resource — is
        the obvious idiom. It was also silently wrong. The second connection to
        return the same object found ``proc`` already set, took the adopted branch
        of :meth:`_attach`, and was spliced to *nothing*: its socket went to no
        command, it never reached end-of-stream, and its pool worker parked in
        `_await_command` on the first connection's command until that exited
        (measured). Worse if the second handler had touched the socket, because
        then the adopted branch's refusal disposed the verdict — killing the first
        connection's live command.

        So the hatch claims a verdict before attaching it, and refuses one it
        cannot claim. `StreamHatch._serve_conn` must forget the verdict it could
        not claim before it raises: it is another connection's, and the
        per-connection ``finally`` would otherwise tear down that connection's
        command.
        """
        with self._lock:
            if self._claimed:
                return False
            self._claimed = True
            return True

    def _attach(self, conn: socket.socket, grace: float) -> None:
        """Make ``conn`` this verdict's command's stdio. Called only by the hatch.

        Normalise, then spawn. In that order and with nothing in between, which is
        the property `Process`'s docstring exists to explain.
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
            # Not adopted, yet already holding a process: either a verdict reused
            # across connections (which _claim catches first, so this is the
            # narrower case) or `_proc` assigned behind the property's back, which
            # skips every check in from_popen.
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
            # The descriptor, not the socket object: `subprocess` accepts anything
            # with a fileno(), but typeshed's _FILE does not admit a socket. Passing
            # the fd is the same call and says what it means — this descriptor
            # becomes the command's 0 and 1, dup'd before the close_fds sweep, and
            # the socket object stays ours to close.
            stdin=fd,
            stdout=fd,
            stderr=self.stderr,
            cwd=self.cwd if self.cwd is not None else '/',
            env=dict(self.env) if self.env is not None else {'PATH': _MINIMAL_PATH},
            # Its own process group, so teardown reaps everything the command
            # started and not just the command. Without this a child left behind
            # inherits the guest's socket and keeps the connection open after the
            # command is gone — the guest never sees EOF and the slot never returns.
            start_new_session=True,
        )
        self._capture_pgid()

    def dispose(self, grace: float) -> None:
        """Terminate, kill and reap the command's process group. Idempotent.

        Idempotence is load-bearing rather than tidy: `StreamHatch.close` disposes
        of what is in flight, and the per-connection ``finally`` disposes of what it
        was handed, and both may reach the same verdict. Letting both reap meant the
        second pass signalled a process group whose leader had already been waited —
        a pid the kernel may reuse, and every verdict mints a session leader, so one
        connection's stale ``SIGKILL`` could land on another's command.

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
    # Eagerly, so a bad stderr fails when the hatch is built rather than on the
    # first connection; `Process` checks the same thing for a directly-built verdict.
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
            # Tracked *before* the verdict, not after: a handler is entitled to read
            # a preamble (see `Stream`), and until this connection is in _live,
            # close() cannot shut it down. A hostile guest that connects and sends
            # nothing then parks a pool worker in recv() for ever — max_conns of
            # those deafen the hatch permanently, and because ThreadPoolExecutor
            # workers are non-daemon the host process can no longer exit either.
            self._track(conn, None)
            verdict = self._handler(Stream(conn, self._name))
            if verdict is not None and not verdict._claim():  # noqa: SLF001 — the hatch owns the verdict's lifecycle
                # Another connection's verdict (a handler that caches or shares
                # one). Forget it *before* raising: it is not ours to tear down,
                # and the `finally` below would otherwise dispose of the other
                # connection's live command. This connection gets the refusal
                # path instead — a clean end-of-stream, like any other failure.
                verdict = None
                raise ValueError('a Process verdict is single-use; this one is already attached to a connection')
            if verdict is not None:
                # Normalise-then-spawn, the one place a connection becomes a
                # command's stdio. Inside the try, so a refused verdict is
                # contained to this connection like any other handler failure.
                verdict._attach(conn, self._grace)  # noqa: SLF001 — the hatch owns the verdict's lifecycle
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
def _check_stderr(stderr: int | None) -> None:
    """Refuse the two ``stderr`` values that cannot work on this surface.

    ``PIPE`` deadlocks: nothing drains it, so a command that fills the 64 KiB pipe
    blocks in ``write(2)`` for ever and never exits, pinning the connection's slot
    until :meth:`StreamHatch.close`.

    ``STDOUT`` discloses: stdout *is* the guest's socket, so merging fd 2 into it
    relays the command's diagnostics — which quote host state — straight to the
    guest. Measured: a guest received ``fatal: '/srv/secrets/customer-a/repo.git'
    does not appear to be a git repository``, which is verbatim the disclosure the
    ``stderr`` argument exists to prevent.
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
    stdio is blocking, has no signal-driven I/O and has no I/O timeouts, so that
    is what the command gets — undoing anything the handler set rather than
    forbidding handlers from setting it.

    Enumerated by measurement rather than from the manual: every option below was
    confirmed to reach a child that reports its own fd 0. The three that change
    behaviour are ``O_NONBLOCK`` (a handler's ``settimeout`` — 219 KiB of a 4 MiB
    response delivered, and read by the guest as a clean end-of-stream),
    ``SO_RCVTIMEO`` (the command's read fails ``EAGAIN`` mid-request — 8 of 16
    bytes echoed) and ``SO_SNDTIMEO`` (the same on the way out). The rest reach
    the child but were measured inert on ``AF_UNIX`` — ``O_ASYNC`` delivers no
    ``SIGIO`` even with an owner set, ``SO_RCVLOWAT`` does not gate a stream read,
    ``SO_OOBINLINE`` and ``SO_PASSCRED`` change nothing a plain-reading command
    can see — and are cleared anyway, because their inertness is a detail of one
    kernel's ``AF_UNIX`` implementation and not a property worth depending on.

    Deliberately **not** normalised:

    * ``SO_LINGER`` — close semantics carry the disposition signal (an unread
      receive queue at last-close is what resets the guest, and it is the only
      failure signal a stream with no framing of its own has). Changing how the
      socket closes would change what the guest is told, so this one is left
      exactly as it is found.
    * ``SO_RCVBUF``/``SO_SNDBUF``, ``SO_MARK``, ``SO_PRIORITY`` — sizes and
      routing hints. A pipe has a buffer size too, so these are not surprises,
      and a handler that tunes them presumably means to.
    * ``SO_PEEK_OFF`` — affects ``MSG_PEEK`` only, which ordinary stdio never uses.
    """
    fd = conn.fileno()
    with contextlib.suppress(OSError, ValueError):
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        if flags & _HANDOVER_CLEAR_FL:
            fcntl.fcntl(fd, fcntl.F_SETFL, flags & ~_HANDOVER_CLEAR_FL)
    # Only meaningful while O_ASYNC is set, which it no longer is; zeroed so no
    # stale owner or signal number survives the handover.
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

    The disclosure `_check_stderr` refuses on the declarative path, arriving by the
    one route that check cannot see: ``subprocess`` keeps no record of the
    ``stderr`` argument it was given, so an adopted `Popen` built with
    ``stderr=subprocess.STDOUT`` is indistinguishable from one built with
    ``DEVNULL`` by inspecting the object — ``proc.stderr`` is ``None`` either way.
    The child itself is not indistinguishable, though: on Linux its fd 2 can be
    stat'd through ``/proc``, and if it names the same inode as the connection then
    fd 2 goes to the guest. Measured: the guest received ``HOST
    /srv/secrets/repo.git`` before this check, and the inode comparison identifies
    it.

    Best-effort by construction — ``False`` where there is no ``/proc``, or where
    the child has already exited, or on any error. Linux is the platform postern
    sandboxes on, which is where it matters; elsewhere `from_popen`'s docstring is
    the only guard, and says so.
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
    normalising would race it (see `Process.from_popen`). Reports rather than
    repairs, so the failure is named instead of silent.
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

    ``grace`` caps the whole drain, but each wait is only ``_DRAIN_QUIET`` long,
    because what makes the close orderly is an **empty receive queue** — so a
    queue that is already empty is the answer, not a reason to keep waiting. The
    old shape spent the full ``grace`` on the *first* byte, which a guest that
    connects and says nothing never sends: a refusal therefore cost a slot for
    ``grace`` seconds (measured 9.5 s for two of them at ``grace=5.0``), renewably,
    for nothing but ``connect()``. Draining continues as long as bytes keep
    arriving, which is the case the reset actually depends on.
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
    group id is only reusable once that pid is free, so a plain ``wait()`` here
    would leave :func:`_reap` correctly declining to signal a group it can no
    longer prove is ours — and a child the command left behind would inherit the
    guest's socket and keep the connection open for ever. Both
    ``waitid(..., WNOWAIT)`` and ``kqueue``/``NOTE_EXIT`` report the exit and leave
    the child waitable; see ``_WAITID`` for which platform gets which, and why
    there are two.
    """
    proc = verdict.proc
    if proc is None:  # never attached; nothing to wait for
        return
    if proc.returncode is not None:
        # Already waited — by `close()` racing this connection, or by a handler that
        # adopted a finished `Popen`. Without this the kqueue tier below registers
        # EVFILT_PROC on a *released* pid: harmless while the pid is merely gone
        # (NOTE_EXIT fires immediately, measured), but once it has been recycled the
        # registration succeeds against a stranger and this waits for that process
        # to exit instead — a slot held for a lifetime that is not ours to observe.
        # `_exited` has this guard for the same reason.
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

    Only ever called with our own child's pid, and only while it is unreaped:
    which matters, because ``EVFILT_PROC`` reports an immediate ``NOTE_EXIT`` for a
    pid that does not exist at all (measured), so on any other pid a ``True`` here
    would be meaningless. `Popen` holds the pid until something waits it, so
    within this module "registration says exited" and "our child exited" coincide.
    """
    if _KQUEUE is None or _KEVENT is None or _KQ_FILTER_PROC is None or _KQ_NOTE_EXIT is None:
        return None
    try:
        kq = _KQUEUE()
    except OSError:  # pragma: no cover - only if the platform lies about kqueue
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
    can land on a recycled pid — and every verdict mints a new session leader per
    connection, so the recycled pid is plausibly another connection's command.
    ``waitid(..., WNOWAIT)`` and ``kqueue``/``NOTE_EXIT`` both report the exit and
    leave the child waitable; ``poll()`` is the last resort and reaps.

    Note what this cannot answer: if another reaper in the host process has already
    collected the status, every tier here reports "exited" indistinguishably from a
    clean exit, because ``Popen`` synthesises a status of 0 on ``ECHILD``. See the
    module docstring, "Teardown and its caveats".
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

    ``Popen.wait(timeout=...)`` cannot be used here: it reaps, and reaping releases
    the leader's pid, which is the only thing that keeps the captured ``pgid``
    provably ours (see :func:`_exited`). So this polls the non-reaping exit test
    instead. On the tier-3 platform where ``_exited`` falls back to ``poll()`` this
    reaps exactly as before, and the group signal is skipped exactly as before.

    ``grace=0.0`` is a single check, which is the point of the untimed ``wait()``
    that follows the kill in :func:`_reap`.
    """
    deadline = time.monotonic() + grace
    while not _exited(proc):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(_EXIT_POLL, remaining))


def _reap(proc: subprocess.Popen[bytes], grace: float, pgid: int | None = None) -> None:
    """Terminate, then kill, then wait — never leave a child of the host running.

    Signals the process *group*, not the process: a command that leaves a
    background child behind otherwise strands it, and — because that child
    inherited the guest's *socket* — strands the guest too, waiting for an
    end-of-stream that can never come.

    Two things bound that guarantee, both open in this revision and both written
    up under "Teardown and its caveats" in the module docstring: it is skipped
    entirely if something else in the host process reaps arbitrary children (the
    ``if proc.returncode is None`` below is where that lands, and declining is the
    correct answer to the ambiguity), and it does not reach a grandchild that has
    left the group with ``setsid()``.

    ``SIGKILL`` goes to the group whenever the leader is confirmed gone and still
    unreaped, and **not** only when the leader outlived ``grace``. Keying the
    escalation on the leader's exit was a hole with nothing exotic in it: a group
    member that ignores ``SIGTERM`` (a sidecar with a handler, an installer script)
    survives while the leader dies inside ``grace``, so the old code reaped the
    leader and stopped — and that member kept a dup of the guest's socket, in its
    own session, outliving the connection, the hatch and this process. Measured on
    Linux and macOS with ``sh -c '(trap "" TERM; …) & exec cat'``.

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
            _wait_exited(proc, grace)
        if proc.returncode is None:
            # Either exited and not yet reaped, or still running past `grace`. Both
            # ways the pid is still ours — an unreaped zombie pins it — so the group
            # id is still valid and anything the command started is still in it. The
            # re-check matters because `_exited`'s last-resort tier reaps, and after
            # a reap the group is no longer provably ours.
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
