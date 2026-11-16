"""The hardened isolation core: a bubblewrap-launched sandbox.

`Sandbox` runs a program (or a snippet of Python) under bubblewrap with the
hardened profile: an empty network namespace, a surgical read-only view of the
base system directories plus one writable workspace, `--cap-drop ALL`,
`--new-session` and a seccomp denylist. Every entrypoint runs under the guest's
init, PID 1 of its namespace: the static C init the Linux wheel carries (or the
one ``SandboxProfile.init`` names), which adds the ``RLIMIT_NPROC`` fork-bomb
backstop and reaps the guest's orphans. The guest's only channel to the outside is
whatever `Hatch` the caller binds in.

The base system directories come from the host by default, or from a curated
``rootfs`` directory assembled at image-build time, which hides the host userland
entirely. The Python environment the guest runs against is a read-only bind
(`SandboxProfile.with_venv`): there is no egress to install from at run time.

Linux + bubblewrap + unprivileged user namespaces only. :func:`available`
reports whether the runtime can launch here.
"""

from __future__ import annotations

import asyncio
import collections.abc
import contextlib
import dataclasses
import functools
import json
import os
import pathlib
import queue
import re
import selectors
import shutil
import signal
import tempfile
import threading
import time
import typing

from postern import _process, _seccomp, _workspace

if typing.TYPE_CHECKING:
    # typing_extensions is not a runtime dependency: `typing.Self` is 3.11+ and
    # the floor is 3.10, so the backport must stay behind this guard.
    import typing_extensions

_GUEST_DIR = '/run/postern'
_GUEST_SOCK = f'{_GUEST_DIR}/hatch.sock'  # the unnamed hatch (GrpcHatch) → POSTERN_HATCH
_GUEST_SHIM = f'{_GUEST_DIR}/_guest.py'
_GUEST_INIT = f'{_GUEST_DIR}/init'
_GUEST_STUBS = f'{_GUEST_DIR}/stubs'
_GUEST_WORKSPACE = '/workspace'
_SHIM_SRC = str(pathlib.Path(__file__).with_name('_guest.py'))
# Built into the Linux wheel by setup.py, or by `python -m postern.build_init --in-place`.
_PACKAGED_INIT = pathlib.Path(__file__).with_name('_bin') / 'postern-init'
_PACKAGED_LAUNCH = pathlib.Path(__file__).with_name('_bin') / 'postern-launch'
# Where the launch puts the descriptors bwrap reads, in this order; postern-launch
# closes every one above.
_INFO_SLOT = _process.FIRST_INHERITED
_SECCOMP_SLOT = _INFO_SLOT + 1
# The largest uid or gid: one more is (uid_t)-1, which the set*id calls read as "unchanged".
_MAX_ID = 0xFFFFFFFE
# Where postern._stream_connect is bound for a hatch that sets guest_connector.
GUEST_CONNECT = f'{_GUEST_DIR}/connect.py'
_CONNECT_SRC = str(pathlib.Path(__file__).with_name('_stream_connect.py'))
_SYSTEM_DIRS = ('/usr', '/lib', '/lib64', '/bin', '/sbin')
# A hatch name is both a path component under /run/postern and the tail of an
# environment variable: '/' or '..' would bind the socket elsewhere, and 'a-b' and
# 'a_b' collide on POSTERN_HATCH_A_B while looking distinct.
_GUEST_NAME_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
_SUN_PATH_MAX = 108  # sizeof(struct sockaddr_un.sun_path) on Linux

# bwrap's fresh `--proc /proc` discards the read-only /proc mask the container
# runtime applied. A guest whose kernel uid maps to root then owns root's global
# sysctls (0644) and can write them with no capability and no blocked syscall —
# writing `core_pattern` is arbitrary code execution as root in the initial
# namespace. Each path is re-bound read-only over *itself* with `--ro-bind-try`,
# so a write is EROFS and a path absent on this kernel is skipped rather than
# fatal. Read-only suffices: the info-leak reads (/proc/kcore, keyrings) need
# CAP_SYS_RAWIO or ownership the cap-dropped guest does not have.
_PROC_RO_PATHS = (
    '/proc/sys',
    '/proc/sysrq-trigger',
    '/proc/irq',
    '/proc/bus',
    '/proc/fs',
    '/proc/acpi',
    '/proc/scsi',
    '/proc/kcore',
    '/proc/keys',
    '/proc/latency_stats',
    '/proc/timer_list',
    '/proc/sched_debug',
)


class Hatch(typing.Protocol):
    """What `Sandbox` needs of a hatch: a UDS path and a serving context.

    Two optional attributes steer the wiring; a hatch declaring neither is the
    unnamed singleton.

    * ``guest_name`` — bind at ``/run/postern/<name>.sock`` and export
      ``$POSTERN_HATCH_<NAME>`` rather than the single ``$POSTERN_HATCH``, which is
      what lets one sandbox carry several hatches.
    * ``guest_connector`` — bind `postern._stream_connect` at ``$POSTERN_CONNECT``
      so the guest can splice a command's stdio to the socket.
    """

    @property
    def socket_path(self) -> str: ...

    def accepting(self) -> contextlib.AbstractContextManager[typing.Any]: ...


def validate_guest_name(name: str) -> str:
    """Check a hatch name is usable as a path component and an env-var tail.

    Args:
        name: The candidate hatch name.

    Returns:
        ``name`` unchanged.

    Raises:
        ValueError: If ``name`` is not a Python identifier, or its guest socket
            path would not fit in a ``sockaddr_un`` — a capability the guest could
            never ``connect()`` to.
    """
    if not _GUEST_NAME_RE.match(name):
        raise ValueError(f'hatch name {name!r} must be a Python identifier (letters, digits, underscore)')
    if len(f'{_GUEST_DIR}/{name}.sock') >= _SUN_PATH_MAX:
        raise ValueError(f'hatch name {name!r} is too long: {_GUEST_DIR}/<name>.sock must fit in {_SUN_PATH_MAX} bytes')
    return name


def guest_socket_path(name: str) -> str:
    """Where a hatch named ``name`` is bound inside the sandbox."""
    return f'{_GUEST_DIR}/{validate_guest_name(name)}.sock'


def guest_env_var(name: str) -> str:
    """The environment variable naming a hatch named ``name`` inside the sandbox."""
    return f'POSTERN_HATCH_{validate_guest_name(name).upper()}'


def _guest_name(hatch: Hatch) -> str | None:
    """A named hatch's name, or None for the unnamed singleton."""
    name = getattr(hatch, 'guest_name', None)
    return validate_guest_name(name) if name is not None else None


def _wants_connector(hatch: Hatch) -> bool:
    """Whether ``hatch``'s guest side needs the stdio↔UDS connector bound in."""
    return bool(getattr(hatch, 'guest_connector', False))


def _hatch_paths(hatch: Hatch) -> tuple[str, str]:
    """The ``(guest socket path, guest env var)`` pair for one hatch.

    The single place a hatch's guest-side contract is decided.
    """
    name = _guest_name(hatch)
    if name is None:
        return _GUEST_SOCK, 'POSTERN_HATCH'
    return guest_socket_path(name), guest_env_var(name)


def available() -> bool:
    """Whether a sandbox can launch here (bubblewrap present on the PATH)."""
    return shutil.which('bwrap') is not None


class IsolationError(RuntimeError):
    """A load-bearing control cannot be enforced here.

    Raised by :meth:`Sandbox.verify`, so a worker can refuse to serve rather than
    run untrusted code with weaker isolation than intended; by a launch with no
    guest init or launcher, whose launcher fails before bwrap runs, or on a glibc
    whose ``posix_spawn`` forks; and by a launch that could not hold the guest's
    init by pidfd, without which a stop could not be sure of reaching it.
    """


@dataclasses.dataclass
class SandboxProfile:
    """The hardened bubblewrap profile. Defaults are the secure baseline.

    Attributes:
        workspace: Host directory bound read-write at ``/workspace`` (the guest's
            cwd), persisting for the Sandbox's lifetime. Read, pack or restore it
            through :meth:`Sandbox.accessor` rather than ``os``/``tarfile``
            directly, so a guest-planted symlink or special file is never followed
            out of the tree. ``None`` makes the Sandbox create a private temp dir,
            removed on ``close()``.
        rootfs: A curated base directory whose ``/usr``, ``/lib`` … are bound as
            the guest's system dirs. ``None`` binds the *host's* system dirs,
            exposing the host userland read-only.
        python: The guest's interpreter argv0 (an absolute path when it lives in
            a bound venv): what :meth:`Sandbox.run_python` runs the shim on, and
            what :func:`postern.stream.git_url` runs the connector on.
        ro_binds: Extra ``(host, guest)`` read-only binds beyond the base system
            dirs, mapped to ``--ro-bind-try``: a missing source is skipped
            silently, so use these only for binds the guest can do without.
        required_ro_binds: ``(host, guest)`` read-only binds mapped to
            ``--ro-bind``, so a missing source is a launch failure rather than a
            silent skip that surfaces later as a confusing in-guest ``ENOENT``.
            Use these for a bind the guest cannot run without — e.g. a host
            directory carrying a tool's inputs, or a venv (see :meth:`with_venv`).
        stubs: Importable modules to inject at ``/run/postern/stubs`` (prepended to
            the guest's ``PYTHONPATH``) — a directory, or a list of files, so a
            shared rootfs can carry the heavy base while the per-agent gRPC stubs
            bind in selectively.
        env: Environment for the guest (``--clearenv`` wipes everything first).
        seccomp: Load the syscall denylist.
        rlimit_nproc: Per-run process-count cap (fork-bomb backstop), applied by
            the guest init.
        rlimit_as: Per-process address-space cap in bytes, applied by the guest
            init (by the shim, once its interpreter is up, for
            :meth:`Sandbox.run_python`). ``None`` leaves it unlimited. It bounds one process, not the
            guest's total memory; a cgroup ``memory.max`` at the deploy layer is
            the real bound.
        guest_uid: uid the guest runs as (``--uid``). Defaults to ``65534``
            (nobody), so the guest holds no capabilities inside its user namespace
            and a root host still drops to a non-root real uid if the user
            namespace fails to materialise. A caller-owned ``workspace`` is
            chmod'd sticky world-writable (``0o1777``) at launch so the non-root
            guest can write it while the sticky bit stops it replacing files it
            does not own. ``None`` runs the guest as uid 0 inside the userns.
        guest_gid: gid the guest runs as (``--gid``). Defaults to ``65534``.
            ``None`` leaves the gid unset.
        host_uid: The *real* uid bwrap itself runs as when the worker started as
            root. bwrap maps the guest's ``--uid`` onto its own real uid, so a root
            bwrap gives the guest kernel uid 0, which owns root's files by DAC;
            setting this makes the guest's kernel uid own none of them. Any uid
            works as root, with no ``newuidmap``/``/etc/subuid``; a dedicated uid
            that owns no host file is the tightest mapping. ``None`` (default) does
            not drop, because dropping requires the deploy to make every bind
            source — the workspace *and its parents*, the hatch socket's dir, the
            rootfs, and the files postern binds from its own install (the packaged
            init, ``run_python``'s shim, a stream hatch's connector), which a
            ``0700`` home directory above a virtualenv would hide — reachable by
            ``host_uid``. Ignored when already non-root, but must still be 1 to
            4294967294, as the gid it pairs with must be 0 to 4294967294.
        host_gid: the real gid bwrap runs as, paired with ``host_uid``. ``None``
            reuses ``guest_gid``, and ``None`` for that too keeps root's gid.
        init: Host path to a static guest init built by
            ``python -m postern.build_init``, PID 1 of every run. ``None``
            (default) uses the one the Linux wheel carries; a launch raises
            :class:`IsolationError` when there is none (an editable install
            before ``python -m postern.build_init --in-place``, or a non-Linux
            install). :meth:`Sandbox.run` and :meth:`Sandbox.run_bash`
            need no interpreter in the sandbox; :meth:`Sandbox.run_python` execs
            ``python`` on the shim as the init's child. It is bound in read-only;
            being static, it needs nothing from ``rootfs``. It is only ever
            executed inside the sandbox, never on the host. Must be absolute.
            :meth:`Sandbox.verify` refuses one built from a different postern
            version.
    """

    workspace: pathlib.Path | None = None
    rootfs: pathlib.Path | None = None
    python: str = 'python3'
    ro_binds: list[tuple[str, str]] = dataclasses.field(default_factory=list)
    required_ro_binds: list[tuple[str, str]] = dataclasses.field(default_factory=list)
    stubs: str | os.PathLike[str] | collections.abc.Sequence[str | os.PathLike[str]] | None = None
    env: dict[str, str] = dataclasses.field(default_factory=lambda: {'PATH': '/usr/local/bin:/usr/bin:/bin'})
    seccomp: bool = True
    rlimit_nproc: int = 1024
    rlimit_as: int | None = None
    guest_uid: int | None = 65534
    guest_gid: int | None = 65534
    host_uid: int | None = None
    host_gid: int | None = None
    init: str | os.PathLike[str] | None = None

    @classmethod
    def with_venv(cls, venv: str | pathlib.Path, **kwargs: typing.Any) -> SandboxProfile:  # noqa: ANN401 — passthrough
        """A profile that binds ``venv`` read-only and runs its interpreter.

        The venv is bound at its own path so the interpreter's ``pyvenv.cfg`` /
        ``site.py`` resolution finds its site-packages unchanged. The bind is
        strict (``required_ro_binds``): a missing venv is a launch failure, not a
        ``run_python`` that dies later on an unresolvable interpreter.

        Args:
            venv: The venv root on the host.
            **kwargs: Any other :class:`SandboxProfile` field; ``required_ro_binds``
                is extended rather than replaced.
        """
        path = pathlib.Path(venv).resolve()
        binds = [*kwargs.pop('required_ro_binds', []), (str(path), str(path))]
        return cls(python=str(path / 'bin' / 'python'), required_ro_binds=binds, **kwargs)


def bwrap_env() -> dict[str, str]:
    """Environment for the *bwrap process itself* — scrubbed to PATH alone.

    ``--clearenv``/``--setenv`` define the *guest's* environment and do not touch
    bwrap's own process image. bwrap runs at the guest's uid (``--uid`` applies to
    it too), so any secret it inherited from the worker is a same-uid environ read
    away for a guest that can see bwrap's ``/proc`` entry. ``--as-pid-1`` keeps
    bwrap out of the guest's PID namespace; scrubbing here means that is not the
    only thing standing between the worker's environment and the guest. Only
    ``PATH`` survives, so a bare ``bwrap`` still resolves.
    """
    return {'PATH': os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin')}


def bwrap_credentials(profile: SandboxProfile, euid: int) -> list[str]:
    """``postern-launch`` flags to run bwrap at a non-root real uid (opt-in).

    bwrap maps the guest's ``--uid`` onto its own real uid, so a root bwrap gives
    the guest kernel uid 0, which owns root's files by DAC. A non-root bwrap makes
    a re-exposed root-owned surface unwritable by ownership as well as by the
    ``/proc/sys`` mask. The launcher drops root's supplementary groups too.

    Args:
        profile: The profile whose ``host_uid``/``host_gid`` decide the drop.
        euid: The worker's effective uid; a drop is only possible from 0.

    Returns:
        ``--uid``, and ``--gid`` when there is one, or ``[]`` for no drop. Empty
        unless ``host_uid`` is set and ``euid`` is 0, because an unprivileged
        bwrap must still be able to reach every bind source — the workspace *and
        its parents*, the hatch socket's directory, the rootfs, the init — or the
        launch fails with ``Permission denied``.
    """
    if euid != 0 or profile.host_uid is None:
        return []
    flags = ['--uid', str(profile.host_uid)]
    gid = profile.host_gid if profile.host_gid is not None else profile.guest_gid
    if gid is not None:
        flags += ['--gid', str(gid)]
    return flags


def build_base_argv(profile: SandboxProfile, seccomp_fd: int | None) -> list[str]:
    """The bwrap flags for ``profile`` (excluding the trailing ``-- argv``)."""
    root = str(profile.rootfs) if profile.rootfs is not None else ''
    # --unshare-all makes the user and cgroup namespaces best-effort
    # (--unshare-user-try/--unshare-cgroup-try): without a user namespace bwrap
    # continues silently and the guest runs as real root. Listing them strict makes
    # that a launch failure. --unshare-all still supplies the strict ipc/pid/net/uts.
    argv = ['bwrap', '--unshare-all', '--unshare-user', '--unshare-cgroup']
    argv += ['--new-session', '--cap-drop', 'ALL', '--die-with-parent', '--clearenv']
    # Without --as-pid-1 bwrap stays resident as PID 1 of the guest's namespace,
    # at the guest's own uid, so its /proc/1 (cmdline, maps, mem) is readable from
    # inside. The guest's init is PID 1 instead.
    argv += ['--as-pid-1']
    if profile.guest_uid is not None:
        argv += ['--uid', str(profile.guest_uid)]
    if profile.guest_gid is not None:
        argv += ['--gid', str(profile.guest_gid)]
    for d in _SYSTEM_DIRS:
        # /usr is mandatory; the rest are -try so a path absent on this base
        # (e.g. /lib64) is skipped rather than fatal.
        flag = '--ro-bind' if d == '/usr' else '--ro-bind-try'
        argv += [flag, root + d, d]
    argv += ['--ro-bind-try', root + '/etc/ld.so.cache', '/etc/ld.so.cache']
    argv += _caller_ro_binds(profile)
    argv += ['--proc', '/proc', '--dev', '/dev']
    # Must come after --proc: it re-masks what the fresh procfs re-exposed.
    for path in _PROC_RO_PATHS:
        argv += ['--ro-bind-try', path, path]
    # An in-sandbox mountpoint, not a host path; 1777 is what a non-root guest
    # needs and what a real /tmp has.
    argv += ['--perms', '1777', '--tmpfs', '/tmp']  # noqa: S108
    if profile.workspace is not None:
        argv += ['--bind', str(profile.workspace), _GUEST_WORKSPACE]
    else:
        argv += ['--perms', '1777', '--tmpfs', _GUEST_WORKSPACE]
    argv += ['--chdir', _GUEST_WORKSPACE]
    env = dict(profile.env)
    if profile.stubs is not None:
        argv += _stub_binds(profile.stubs)
        prior = env.get('PYTHONPATH')
        env['PYTHONPATH'] = _GUEST_STUBS if not prior else f'{_GUEST_STUBS}:{prior}'
    for key, val in env.items():
        argv += ['--setenv', key, val]
    if seccomp_fd is not None:
        argv += ['--seccomp', str(seccomp_fd)]
    return argv


def _caller_ro_binds(profile: SandboxProfile) -> list[str]:
    """Bwrap flags for the profile's caller-supplied read-only binds.

    ``ro_binds`` map to ``--ro-bind-try`` (a missing source is skipped);
    ``required_ro_binds`` map to ``--ro-bind`` (a missing source fails the launch).
    """
    argv: list[str] = []
    for host, guest in profile.ro_binds:
        argv += ['--ro-bind-try', host, guest]
    for host, guest in profile.required_ro_binds:
        argv += ['--ro-bind', host, guest]
    return argv


def _stub_binds(
    stubs: str | os.PathLike[str] | collections.abc.Sequence[str | os.PathLike[str]],
) -> list[str]:
    """Bwrap flags injecting importable stubs at ``/run/postern/stubs``.

    A directory is bound whole; a sequence of files is bound each to its basename
    under the stubs dir.
    """
    if isinstance(stubs, (str, os.PathLike)):
        return ['--ro-bind', os.fspath(stubs), _GUEST_STUBS]
    binds: list[str] = []
    for entry in stubs:
        path = os.fspath(entry)
        binds += ['--ro-bind', path, f'{_GUEST_STUBS}/{pathlib.Path(path).name}']
    return binds


_T = typing.TypeVar('_T')

# How long a launch waits for bwrap to report the init's pid. bwrap writes it once
# it has cloned the guest, within milliseconds; one that fails first closes the
# pipe, so this bounds only a bwrap that hangs.
_INFO_TIMEOUT_S = 30.0


class _Job(typing.Generic[_T]):
    """One call run on another thread, and the hand-off of its result.

    The result goes to the caller, or to ``discard`` if the caller stopped waiting
    first, so something the call started is never left without an owner. The call
    itself cannot be interrupted: a ``KeyboardInterrupt`` reaches only the main
    thread.
    """

    def __init__(self, fn: collections.abc.Callable[[], _T], discard: collections.abc.Callable[[_T], None]) -> None:
        self._fn = fn
        self._discard = discard
        self._lock = threading.Lock()
        self._done = threading.Event()
        self._abandoned = False
        self._value: _T | None = None
        self._error: BaseException | None = None

    def run(self) -> None:
        """Run the call, on the thread meant for it. An error in it goes to the caller."""
        try:
            value = self._fn()
        except BaseException as exc:  # noqa: BLE001 — re-raised in the caller
            self._error = exc
            self._done.set()
            return
        with self._lock:
            abandoned = self._abandoned
            self._value = value
            self._done.set()
        if abandoned:
            self._discard(value)

    def result(self) -> _T:
        """Wait for the call, and return its result or raise its error.

        Interrupted while waiting (a ``KeyboardInterrupt``), the result is discarded
        here if it has arrived, or by :meth:`run` when it does. Once this returns,
        the result is the caller's: an interrupt in the few bytecodes before the
        caller has bound it is beyond reach.
        """
        try:
            self._done.wait()
        except BaseException:
            with self._lock:
                self._abandoned = True
                arrived = self._done.is_set() and self._error is None
            if arrived:
                self._discard(typing.cast('_T', self._value))
            raise
        if self._error is not None:
            raise self._error
        return typing.cast('_T', self._value)

    def in_thread(self, name: str) -> _T:
        """Run the call on a new thread of its own and return :meth:`result`."""
        threading.Thread(target=self.run, name=name, daemon=True).start()
        return self.result()


class _Spawner:
    """Spawns every bwrap from one long-lived thread.

    bwrap's ``--die-with-parent`` is ``PR_SET_PDEATHSIG``, which fires when the
    *thread* that created bwrap exits, not the process. Spawned from a caller or
    pool thread, a guest would die when that thread finished.

    Only the spawn belongs here, and whatever must follow it before anything else
    can touch the child: one launch waiting on bwrap would hold up every other.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._queue: queue.SimpleQueue[collections.abc.Callable[[], None]] = queue.SimpleQueue()
        self._thread: threading.Thread | None = None

    def call(self, fn: collections.abc.Callable[[], _T], discard: collections.abc.Callable[[_T], None]) -> _T:
        """Run ``fn`` on the spawning thread and return its result, or raise its error.

        Args:
            fn: The spawn.
            discard: Releases ``fn``'s result if the caller is interrupted before
                receiving it.
        """
        job = _Job(fn, discard)
        with self._lock:
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._serve, name='postern-spawner', daemon=True)
                self._thread.start()
        self._queue.put(job.run)
        return job.result()

    def _serve(self) -> None:
        # Inherited by bwrap and, across its exec, by the guest init. The init is
        # PID 1 of its namespace, so the kernel drops a SIGTERM it has no handler for
        # yet — a Process.terminate() just after start, while the init is still
        # starting up. Blocked, the SIGTERM is held pending until the init takes it.
        # bwrap ignores SIGTERM as a result; postern stops it with SIGKILL, and a
        # cgroup- or group-wide SIGTERM reaches the init directly.
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
        while True:
            self._queue.get()()


# Process-wide, not per Sandbox: the thread must outlive every guest it launched,
# and the only lifetime that does so is the worker process's.
_spawner = _Spawner()


def _read_init_pid(info_fd: int) -> int | None:
    """The guest init's host pid, from bwrap's ``--info-fd`` JSON, or None.

    Reads only until the JSON object is complete rather than to EOF: whether bwrap
    closes the descriptor after writing is not something to depend on.

    Returns:
        The pid, or None if bwrap closed the pipe without reporting one, which it
        does only when it fails before starting the guest.

    Raises:
        IsolationError: If postern-launch reports its own failure there, before
            bwrap ran, or the report is malformed or does not arrive in time.
    """
    deadline = time.monotonic() + _INFO_TIMEOUT_S
    buffer = b''
    with selectors.DefaultSelector() as selector:
        selector.register(info_fd, selectors.EVENT_READ)
        while (remaining := deadline - time.monotonic()) > 0:
            if not selector.select(remaining):
                continue
            chunk = os.read(info_fd, 4096)
            if not chunk:
                if buffer:
                    raise IsolationError(f'bwrap --info-fd report is truncated: {buffer!r}')
                return None
            buffer += chunk
            try:
                report = json.loads(buffer)
            except ValueError:
                continue  # not complete yet
            if isinstance(report, dict) and isinstance(report.get('postern-launch'), str):
                raise IsolationError(f'postern-launch: {report["postern-launch"]}')
            pid = report.get('child-pid') if isinstance(report, dict) else None
            if not isinstance(pid, int):
                raise IsolationError(f'bwrap --info-fd report has no child-pid: {buffer!r}')
            return pid
    raise IsolationError(f'bwrap did not report the guest init within {_INFO_TIMEOUT_S}s')


def _status_field(pid: int | str, field: str) -> int:
    """An integer field (``Pid``, ``PPid``) of ``/proc/<pid>/status``.

    Raises:
        FileNotFoundError: If ``pid`` does not exist in this ``/proc``.
        IsolationError: If the status has no such field.
    """
    for line in pathlib.Path(f'/proc/{pid}/status').read_text().splitlines():
        name, _, value = line.partition(':')
        if name == field:
            return int(value.split()[0])
    raise IsolationError(f'/proc/{pid}/status has no {field} line')


def _hold_init(info_fd: int, bwrap_pid: int) -> int | None:
    """A pidfd on the guest init bwrap reports on ``info_fd``, or None if no init is running.

    The pid is checked to name bwrap's child once the pidfd is open: bwrap reaps
    the init before it exits itself, so by the time the pid is read it may have
    been recycled. The check reads ``/proc`` and then confirms through the pidfd
    that the process is alive; alive, the pid cannot have changed hands in
    between, so the ``/proc`` entry was its. Only the pidfd decides that the init
    has exited: a process alive but not shown as bwrap's child is one this cannot
    vouch for, and fails closed.

    Returns:
        The pidfd, or None if bwrap started no init or it has already exited.

    Raises:
        IsolationError: If bwrap's report is unusable, the pidfd cannot be opened,
            or ``/proc`` does not show the live process as bwrap's child. The
            process is SIGKILLed first: it is the init in all but a pid
            recycled in the moments since bwrap reported it, while it was still
            being set up.
    """
    pid = _read_init_pid(info_fd)
    if pid is None:
        return None
    try:
        pidfd = _process.pidfd_open(pid)
    except ProcessLookupError:
        return None
    except OSError as exc:
        raise IsolationError(f'cannot open a pidfd on the guest init: {exc}') from exc
    try:
        try:
            parent: int | None = _status_field(pid, 'PPid')
        except FileNotFoundError:
            parent = None  # hidden from this /proc (hidepid), or the init has exited
        try:
            _process.pidfd_signal(pidfd, 0)
        except ProcessLookupError:
            os.close(pidfd)
            return None
        if parent != bwrap_pid:
            with contextlib.suppress(ProcessLookupError):
                _process.pidfd_signal(pidfd, signal.SIGKILL)
            shown = 'no such process' if parent is None else f'parent {parent}'
            raise IsolationError(
                f'cannot confirm that pid {pid} is the guest init: /proc shows {shown}, not bwrap ({bwrap_pid})'
            )
    except BaseException:
        os.close(pidfd)
        raise
    return pidfd


def _require_init_control() -> None:
    """Raise unless a guest init can be held and identified here: stopping a run depends on it.

    Raises:
        IsolationError: If pidfds do not work (off Linux, before 5.3, or under a
            seccomp profile blocking ``pidfd_open`` or ``pidfd_send_signal``), or
            ``/proc`` belongs to another pid namespace than this process's, so the
            init's pid could not be checked against it.
    """
    try:
        pidfd = _process.pidfd_open(os.getpid())
        try:
            _process.pidfd_signal(pidfd, 0)
        finally:
            os.close(pidfd)
    except OSError as exc:
        raise IsolationError(f'pidfds are unavailable, so a run could not be reliably stopped: {exc}') from exc
    try:
        shown: int | None = _status_field('self', 'Pid')
    except FileNotFoundError:
        shown = None  # no /proc, or one in which this process does not appear
    if shown != os.getpid():
        raise IsolationError(
            f"/proc does not belong to this process's pid namespace (its self is {shown}, not {os.getpid()}), "
            'so the guest init could not be identified'
        )


def _spawn(cmd: list[str], *, seccomp_fd: int | None, profile: SandboxProfile) -> _process.Launch:
    """Start bwrap and take hold of the guest's init. Not on the caller's thread: see :class:`_Job`.

    ``cmd`` is the bwrap command line, with ``cmd[0]`` bwrap itself and any
    ``--seccomp`` naming :data:`_SECCOMP_SLOT`, where ``seccomp_fd`` lands;
    ``--info-fd`` is added here. On any failure, whatever was started is killed
    before this raises — except an init that could not be held, which only killing
    bwrap can reach: one already past ``--die-with-parent`` dies with it, one not
    yet past it does not. Only descriptor exhaustion gets that far, with pidfds
    known to work.

    Raises:
        IsolationError: If the init cannot be held by a pidfd, and so could not be
            reliably stopped; this install carries no launcher, or it cannot be
            started or reports its own failure; or glibc's ``posix_spawn`` forks.
        ChildProcessError: If something else in this process reaped bwrap.
    """
    _require_init_control()
    _require_spawn_without_fork()
    launcher = _launcher_path()
    env = bwrap_env()
    bwrap = shutil.which(cmd[0], path=env['PATH'])
    if bwrap is None:
        raise RuntimeError(f'{cmd[0]} not found on PATH ({env["PATH"]})')
    info_read, info_write = os.pipe()
    try:
        inherit = (info_write,) if seccomp_fd is None else (info_write, seccomp_fd)
        argv = [
            launcher,
            '--close-from',
            str(_process.FIRST_INHERITED + len(inherit)),
            '--error-fd',
            str(_INFO_SLOT),
            *bwrap_credentials(profile, os.geteuid()),
            '--',
            bwrap,
            '--info-fd',
            str(_INFO_SLOT),
            *cmd[1:],
        ]
        try:
            launch = _spawner.call(
                functools.partial(_process.spawn, launcher, argv, env=env, inherit=inherit),
                _process.Launch.discard,
            )
        except ChildProcessError:
            raise  # the process's own child handling, not the platform's isolation
        except OSError as exc:
            raise IsolationError(f'cannot start {launcher}: {exc}') from exc
        finally:
            os.close(info_write)
        try:
            launch.init_pidfd = _hold_init(info_read, launch.pid)
        except BaseException:
            launch.discard()
            raise
        return launch
    finally:
        os.close(info_read)


def _require_spawn_without_fork() -> None:
    """Raise unless ``posix_spawn`` here never forks, so runs no ``pthread_atfork`` handler.

    glibc's clones with ``CLONE_VM|CLONE_VFORK`` from 2.24; before that it forks
    whenever it has file actions, which every launch does. musl's never forks.

    Raises:
        IsolationError: On glibc older than 2.24.
    """
    try:
        version = os.confstr('CS_GNU_LIBC_VERSION')
    except (ValueError, OSError):
        return  # not glibc
    # Vendors append to the number: 'glibc 2.20-2014.11'.
    match = re.match(r'glibc (\d+)\.(\d+)', version or '')
    if match is not None and (int(match[1]), int(match[2])) < (2, 24):
        raise IsolationError(f'{version} forks inside posix_spawn; postern needs glibc 2.24 or later')


def _check_host_ids(profile: SandboxProfile) -> None:
    """Raise unless ``profile``'s uid drop names a non-root uid and a valid gid, whatever the worker's euid.

    Raises:
        ValueError: If ``host_uid`` is set and not in 1 to 4294967294, or the gid it
            pairs with (``host_gid``, else ``guest_gid``) not in 0 to 4294967294;
            ``-1`` (4294967295) means "unchanged" to ``setresuid``.
    """
    if profile.host_uid is None:
        return
    if not 1 <= profile.host_uid <= _MAX_ID:
        raise ValueError(f'SandboxProfile.host_uid must be a non-root uid, 1 to {_MAX_ID}, got {profile.host_uid!r}')
    gid = profile.host_gid if profile.host_gid is not None else profile.guest_gid
    if gid is not None and not 0 <= gid <= _MAX_ID:
        raise ValueError(f'the gid host_uid drops to must be 0 to {_MAX_ID}, got {gid!r}')


def _launcher_path() -> str:
    """The packaged ``postern-launch``.

    Never a configurable path, unlike the init: it runs on the host as the worker,
    root included, so a path a deployer named would hand that to whoever could
    replace the file.

    Raises:
        IsolationError: If this install carries none.
    """
    if not _PACKAGED_LAUNCH.is_file():
        raise IsolationError(
            f'this postern install carries no bwrap launcher ({_PACKAGED_LAUNCH} is missing), as an editable '
            'install or non-Linux one does not: build one with `python -m postern.build_init --in-place`'
        )
    return str(_PACKAGED_LAUNCH)


def _discard_process(process: _process.Process) -> None:
    process.kill()
    process.close()


def _discard_started(future: asyncio.Future[_process.Process]) -> None:
    """Stop and close a run whose start finished after the task awaiting it was cancelled."""
    if future.cancelled() or future.exception() is not None:
        return  # a start that failed has already released what it started
    process = future.result()
    process.kill()
    # On a thread of its own rather than the loop's executor: a loop shutting down
    # refuses new work, which would leave the hatches serving.
    threading.Thread(target=process.close, name='postern-discard').start()


class Sandbox:
    """A hardened bubblewrap sandbox with optional :class:`Hatch` channels.

    ``hatch`` takes one hatch or a sequence, and defaults to none (no channel is
    opened). At most one *unnamed* hatch, since that one owns a fixed guest socket
    path and environment variable.
    """

    def __init__(
        self,
        profile: SandboxProfile | None = None,
        *,
        hatch: Hatch | collections.abc.Sequence[Hatch] | None = None,
    ) -> None:
        self._profile = profile or SandboxProfile()
        if hatch is None:
            self._hatches: list[Hatch] = []
        elif isinstance(hatch, (list, tuple)):
            self._hatches = list(hatch)
        else:
            self._hatches = [typing.cast('Hatch', hatch)]
        self._check_hatches()
        # Absolute, so the file bound in as PID 1 cannot depend on the worker's cwd.
        if self._profile.init is not None and not os.path.isabs(self._profile.init):
            raise ValueError(f'SandboxProfile.init must be an absolute path, got {os.fspath(self._profile.init)!r}')
        _check_host_ids(self._profile)
        if self._profile.workspace is not None:
            self._workspace = pathlib.Path(self._profile.workspace)
            self._own_workspace = False
            self._workspace.mkdir(parents=True, exist_ok=True)
        else:
            self._workspace = pathlib.Path(tempfile.mkdtemp(prefix='postern-ws-'))
            self._own_workspace = True

    def _check_hatches(self) -> None:
        """Reject a hatch set whose guest sockets, env vars or host paths collide.

        Checked on the *derived* artefacts rather than the names, because distinct
        names still collide once derived, and each collision is a silent capability
        swap: ``GrpcHatch()`` and ``StreamHatch(name='hatch')`` both land on
        ``/run/postern/hatch.sock`` where the later bind shadows the earlier;
        ``.upper()`` collides ``repo`` and ``REPO`` on ``POSTERN_HATCH_REPO``; and
        one ``socket_path`` shared by two hatches aliases whichever ``start()``
        bound last. The unnamed hatch is capped at one for the same reason.

        Raises:
            ValueError: On a second unnamed hatch, or any derived collision.
        """
        if sum(_guest_name(h) is None for h in self._hatches) > 1:
            raise ValueError('a sandbox takes at most one unnamed hatch (e.g. GrpcHatch); name the rest')
        for label, derive in (
            ('guest socket paths', lambda h: _hatch_paths(h)[0]),
            ('guest environment variables', lambda h: _hatch_paths(h)[1]),
            ('host socket paths', lambda h: os.fspath(h.socket_path)),
        ):
            self._reject_duplicates(label, derive)

    def _reject_duplicates(self, label: str, derive: collections.abc.Callable[[Hatch], str]) -> None:
        """Raise if two configured hatches derive the same value."""
        seen: dict[str, list[str]] = {}
        for hatch in self._hatches:
            name = _guest_name(hatch)
            seen.setdefault(derive(hatch), []).append('<unnamed>' if name is None else name)
        clashes = {value: names for value, names in seen.items() if len(names) > 1}
        if clashes:
            detail = '; '.join(f'{value!r} <- {sorted(names)}' for value, names in sorted(clashes.items()))
            raise ValueError(f'hatches must not share {label}: {detail}')

    def _hatch_wiring(self) -> tuple[list[str], dict[str, str]]:
        """The bwrap binds and guest env for every configured hatch (no serving yet)."""
        binds: list[str] = []
        env: dict[str, str] = {}
        for hatch in self._hatches:
            guest_path, env_var = _hatch_paths(hatch)
            binds += ['--bind', hatch.socket_path, guest_path]
            env[env_var] = guest_path
        if any(_wants_connector(h) for h in self._hatches):
            binds += ['--ro-bind', _CONNECT_SRC, GUEST_CONNECT]
            env['POSTERN_CONNECT'] = GUEST_CONNECT
        return binds, env

    @property
    def workspace(self) -> pathlib.Path:
        """The host directory bound read-write at ``/workspace`` (the guest cwd)."""
        return self._workspace

    def accessor(self) -> _workspace.Workspace:
        """A reference-closed :class:`~postern.Workspace` over the workspace.

        Read, pack or restore the guest's workspace through this rather than
        `os`/`tarfile`/`shutil`: every access is confined beneath the workspace, so
        a guest-planted symlink, ``..`` or special file is never followed out of the
        tree. The accessor only needs the directory path, so it outlives the
        Sandbox. Use it as a context manager, or call ``close()``, to release its
        anchor fd.
        """
        return _workspace.Workspace(self._workspace)

    def _start(
        self,
        argv: list[str],
        *,
        resources: contextlib.ExitStack,
        setenv: dict[str, str] | None = None,
        extra_binds: list[str] | None = None,
    ) -> _process.Process:
        """Launch ``argv`` under bwrap and hand back the running :class:`Process`.

        ``resources`` (the hatches' serving contexts) passes to the Process, which
        closes it when the run is closed; on any failure it is closed here. The
        launch runs whole on a thread of its own, through to the Process that owns
        it, so an interrupt cannot leave a guest between the two.
        """
        job = _Job(
            functools.partial(self._launch, argv, setenv=setenv, extra_binds=extra_binds, resources=resources),
            _discard_process,
        )
        try:
            return job.in_thread('postern-start')
        except BaseException:
            resources.close()
            raise

    def _launch(
        self,
        argv: list[str],
        *,
        setenv: dict[str, str] | None,
        extra_binds: list[str] | None,
        resources: contextlib.ExitStack,
    ) -> _process.Process:
        if not available():
            raise RuntimeError('bubblewrap (bwrap) not found on PATH; postern requires Linux + bubblewrap')
        # A non-root guest cannot write a host-owned workspace dir. 1777 rather than
        # 0777 (matching the tmpfs branch): without the sticky bit the guest could
        # unlink a host-written file and recreate it as an escaping symlink. It can
        # still plant one among files it owns, which is what :meth:`accessor` is for.
        if self._profile.guest_uid not in (None, 0):
            with contextlib.suppress(OSError):
                self._workspace.chmod(0o1777)
        seccomp = _seccomp.load_filter() if self._profile.seccomp else None
        launch: _process.Launch | None = None
        try:
            profile = dataclasses.replace(self._profile, workspace=self._workspace)
            cmd = build_base_argv(profile, None if seccomp is None else _SECCOMP_SLOT)
            for key, val in (setenv or {}).items():
                cmd += ['--setenv', key, val]
            cmd += extra_binds or []
            cmd += ['--', *argv]
            launch = _spawn(cmd, seccomp_fd=None if seccomp is None else seccomp.fileno(), profile=self._profile)
            if seccomp is not None:
                seccomp.close()
            return _process.Process(launch, resources=resources)
        except BaseException:
            if launch is not None:
                launch.discard()
            if seccomp is not None:
                seccomp.close()
            raise

    def _init_path(self) -> str:
        """The host path of the guest init: the profile's, else the wheel's.

        Raises:
            IsolationError: If the profile names none and this install carries none.
        """
        if self._profile.init is not None:
            return os.fspath(self._profile.init)
        if not _PACKAGED_INIT.is_file():
            raise IsolationError(
                f'this postern install carries no guest init ({_PACKAGED_INIT} is missing), as an editable install or '
                'non-Linux one does not: build one with `python -m postern.build_init --in-place`'
            )
        return str(_PACKAGED_INIT)

    def _supervised(self, work_argv: list[str], *, code: str | None = None) -> _process.Process:
        """Start ``work_argv`` under the guest's init, with every hatch bound and served.

        The one funnel behind :meth:`run`, :meth:`run_bash` and :meth:`run_python`.
        The init is bwrap's ``--as-pid-1`` entrypoint. It applies the resource
        backstops, forks, and the child execs ``work_argv``.

        Args:
            work_argv: What the init's forked child execs.
            code: ``POSTERN_CODE`` when ``work_argv`` runs the shim
                (:meth:`run_python`); ``None`` for an arbitrary program, which reads
                its own input.

        Returns:
            The running process, which owns the hatches' serving contexts.

        Raises:
            IsolationError: If there is no guest init to launch.
        """
        binds, env = self._hatch_wiring()
        # Under --clearenv, guest code reading os.environ['POSTERN_HATCH'] would
        # raise KeyError with no hatch configured; seed it empty instead.
        env = {'POSTERN_HATCH': '', **env}
        as_bytes = str(self._profile.rlimit_as or 0)
        binds += ['--ro-bind', self._init_path(), _GUEST_INIT]
        if code is not None:
            # The shim applies RLIMIT_AS once its interpreter is up, so the init must not.
            binds += ['--ro-bind', _SHIM_SRC, _GUEST_SHIM]
            env = {'POSTERN_CODE': code, 'POSTERN_AS': as_bytes, **env}
            as_bytes = '0'
        limits = ['--nproc', str(self._profile.rlimit_nproc), '--as', as_bytes]
        entrypoint = [_GUEST_INIT, *limits, '--', *work_argv]
        stack = contextlib.ExitStack()
        try:
            for hatch in self._hatches:
                stack.enter_context(hatch.accepting())
        except BaseException:
            stack.close()
            raise
        return self._start(entrypoint, resources=stack, setenv=env, extra_binds=binds)

    def run(self, argv: list[str], *, timeout: float = 60, max_output: int | None = None) -> _process.ProcResult:
        """Run ``argv`` inside the sandbox and return its result.

        The entrypoint for a program that is not Python. It runs under the same
        guest init as :meth:`run_python`, so ``argv`` inherits ``RLIMIT_NPROC`` and
        ``RLIMIT_AS`` across the exec, has its orphaned descendants reaped, and is
        not PID 1 itself. It needs no interpreter in the sandbox.

        Every configured :class:`Hatch` is bound and served: the socket is a file at
        ``$POSTERN_HATCH``/``$POSTERN_HATCH_<NAME>``, so ``argv`` reaches it with no
        in-guest relay.
        """
        return self.start(argv).communicate(timeout, max_output=max_output)

    def run_bash(
        self, script: str, *, shell: str = 'bash', timeout: float = 60, max_output: int | None = None
    ) -> _process.ProcResult:
        """Run ``script`` inside the sandbox as ``shell -c script``.

        Args:
            script: The script text. It is an argument to ``shell`` in the guest,
                never interpolated into a host command line.
            shell: The shell to run it with. Must exist in the sandbox, which a
                curated ``rootfs`` need not provide.
            timeout: Seconds before the launch is killed.
            max_output: Maximum total bytes of stdout and stderr to buffer. Output
                beyond this is discarded and result.truncated is set.

        Returns:
            The launch's result.
        """
        return self.start_bash(script, shell=shell).communicate(timeout, max_output=max_output)

    def run_python(self, code: str, *, timeout: float = 60, max_output: int | None = None) -> _process.ProcResult:
        """Run untrusted Python ``code`` inside the sandbox.

        The init's child execs ``profile.python`` on the shim to run ``code``, and
        the shim applies ``RLIMIT_AS`` once that interpreter is up.

        Each configured :class:`Hatch` binds its own UDS in. The unnamed hatch
        exports its path as ``POSTERN_HATCH``, a named one as
        ``POSTERN_HATCH_<NAME>``; the client library that dials it comes from the
        guest's bound environment.
        """
        return self.start_python(code).communicate(timeout, max_output=max_output)

    def start(self, argv: list[str]) -> _process.Process:
        """Start ``argv`` in the sandbox, as :meth:`run` does, and return at once.

        The :class:`Process` streams the output as it arrives
        (:meth:`Process.output`) and can be stopped (:meth:`Process.terminate`).
        Use it as a context manager: the run's hatches serve until it is closed.
        """
        return self._supervised(list(argv))

    def start_bash(self, script: str, *, shell: str = 'bash') -> _process.Process:
        """Start ``shell -c script`` in the sandbox, as :meth:`run_bash` does, and return at once."""
        return self._supervised([shell, '-c', script])

    def start_python(self, code: str) -> _process.Process:
        """Start ``code`` in the sandbox, as :meth:`run_python` does, and return at once."""
        return self._supervised([self._profile.python, '-u', _GUEST_SHIM], code=code)

    async def _astart(
        self,
        starter: collections.abc.Callable[..., _process.Process],
        *args: object,
        **kwargs: object,
    ) -> _process.AsyncProcess:
        loop = asyncio.get_running_loop()
        future = loop.run_in_executor(None, functools.partial(starter, *args, **kwargs))
        try:
            process = await asyncio.shield(future)
        except asyncio.CancelledError:
            future.add_done_callback(_discard_started)
            raise
        try:
            return _process.AsyncProcess(process)
        except BaseException:
            process.kill()
            process.close()
            raise

    async def astart(self, argv: list[str]) -> _process.AsyncProcess:
        """Start ``argv`` as :meth:`start` does, for asyncio. Use with ``async with``."""
        return await self._astart(self.start, argv)

    async def astart_bash(self, script: str, *, shell: str = 'bash') -> _process.AsyncProcess:
        """Start ``shell -c script`` as :meth:`start_bash` does, for asyncio."""
        return await self._astart(self.start_bash, script, shell=shell)

    async def astart_python(self, code: str) -> _process.AsyncProcess:
        """Start ``code`` as :meth:`start_python` does, for asyncio."""
        return await self._astart(self.start_python, code)

    def verify(self, *, timeout: float = 30) -> None:
        """Fail fast at startup unless the sandbox actually launches here.

        Every control is already fail-closed on the launch path: the strict
        ``--unshare-*`` flags make bwrap abort if it cannot create the namespaces,
        apply ``--uid`` or drop capabilities, and :func:`_seccomp.load_filter`
        refuses an architecture the filter does not cover. A successful launch is
        therefore the proof, and this triggers one trivial launch so a broken
        platform — no user namespace, gVisor, an uncovered arch — surfaces at
        startup rather than on the first real request.

        The trivial launch is the init's own ``--version``, run inside the sandbox,
        and its answer must be this postern's version, as must the launcher's.

        Raises:
            IsolationError: If ``seccomp`` is disabled in the profile, there is no
                guest init or launcher, the trivial launch fails, or the init or
                the launcher was built from another postern version.
            ChildProcessError: If something else in this process reaped a
                launch's child.
        """
        if not self._profile.seccomp:
            raise IsolationError('seccomp is disabled; refusing to treat this as a hardened sandbox')
        import postern  # noqa: PLC0415 — the package imports this module

        # The launcher is postern's own, and runs on the host as every launch runs it.
        _require_init_control()
        _require_spawn_without_fork()
        launcher = _launcher_path()
        try:
            launch = _process.spawn(launcher, [launcher, '--version'], env=bwrap_env())
        except ChildProcessError:
            raise  # the process's own child handling, not the platform's isolation
        except OSError as exc:
            raise IsolationError(f'cannot start {launcher}: {exc}') from exc
        with _process.Process(launch, resources=contextlib.ExitStack()) as process:
            answer = process.communicate(timeout)
        if not answer.ok:
            raise IsolationError(f'launcher {launcher} failed: {answer.stderr.strip() or answer.returncode}')
        reported = answer.stdout.strip()
        if reported != postern.__version__:
            raise IsolationError(
                f'launcher {launcher} was built from postern {reported}, not {postern.__version__}; '
                'rebuild it with `python -m postern.build_init --in-place`'
            )
        # The init itself, inside the sandbox: it needs nothing from the rootfs (a
        # rootfs need not carry Python), and the init is never executed on the host,
        # which runs only postern's own launcher and bwrap. Running a deployer-supplied
        # binary here, as the worker and with its environment, would hand anything
        # that could swap that file the worker's privileges.
        result = self.run([_GUEST_INIT, '--version'], timeout=timeout)
        if not result.ok:
            raise IsolationError(f'sandbox failed to launch: {result.stderr.strip() or result.returncode}')
        reported = result.stdout.strip()
        if reported != postern.__version__:
            raise IsolationError(
                f'guest init {self._init_path()} was built from postern {reported}, not {postern.__version__}; '
                'rebuild it with `python -m postern.build_init`'
            )

    def close(self) -> None:
        """Remove the workspace if this Sandbox created it (a no-op for a caller-owned path)."""
        if self._own_workspace:
            shutil.rmtree(self._workspace, ignore_errors=True)

    def __enter__(self) -> typing_extensions.Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
