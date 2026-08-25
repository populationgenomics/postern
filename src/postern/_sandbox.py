"""The hardened isolation core: a bubblewrap-launched sandbox.

`Sandbox` runs a program (or a snippet of Python) under bubblewrap with the
hardened profile: an empty network namespace (no egress at all), a surgical
read-only view of the base system directories plus one writable workspace,
`--cap-drop ALL`, `--new-session`, a seccomp denylist, and an `RLIMIT_NPROC`
fork-bomb backstop. The guest's only channel to the outside is whatever
`Hatch` the caller binds in — nothing else is reachable.

The base system directories come from the host by default, or from a curated
``rootfs`` directory (a minimal base assembled at image-build time) — the latter
hides the host's userland entirely. The Python environment the guest runs
against is a read-only bind (`SandboxProfile.with_venv`), never installed at
run time (there is no egress to install from).

Linux + bubblewrap + unprivileged user namespaces only. :func:`available`
reports whether the runtime can launch here.
"""

from __future__ import annotations

import contextlib
import dataclasses
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import typing
from collections.abc import Sequence

from postern import _seccomp
from postern._workspace import Workspace

if typing.TYPE_CHECKING:
    # `typing.Self` is 3.11+, but postern supports 3.10; the backport is
    # type-check-only (guarded here), so the runtime stays dependency-free.
    from typing_extensions import Self

_GUEST_DIR = '/run/postern'
_GUEST_SOCK = f'{_GUEST_DIR}/hatch.sock'  # the unnamed hatch (GrpcHatch) → POSTERN_HATCH
_GUEST_SHIM = f'{_GUEST_DIR}/_guest.py'
_GUEST_STUBS = f'{_GUEST_DIR}/stubs'
_GUEST_WORKSPACE = '/workspace'
_SHIM_SRC = str(pathlib.Path(__file__).with_name('_guest.py'))
# The in-guest stdio↔UDS connector a stream hatch's guest side needs (see
# postern._stream_connect); bound in read-only whenever a hatch asks for it.
GUEST_CONNECT = f'{_GUEST_DIR}/connect.py'
_CONNECT_SRC = str(pathlib.Path(__file__).with_name('_stream_connect.py'))
_SYSTEM_DIRS = ('/usr', '/lib', '/lib64', '/bin', '/sbin')
# A hatch name becomes both a path component under /run/postern and the tail of an
# environment variable, so restrict it to a Python identifier. That is not guest
# input — the host names its own capabilities — but a name with a '/' or '..' would
# bind the socket somewhere unintended, and 'a-b' vs 'a_b' would collide on
# POSTERN_HATCH_A_B while looking distinct. Refuse both at construction.
_GUEST_NAME_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
# sizeof(struct sockaddr_un.sun_path) on Linux. A name whose guest socket path
# does not fit is a capability nothing in the guest can ever connect() to.
_SUN_PATH_MAX = 108

# bwrap's fresh `--proc /proc` is owned by the guest's user namespace and
# discards the read-only /proc mask the container runtime applied. Because bwrap
# runs at the host's real uid (root, under the Cloud Run gen2 posture) the guest's
# kernel uid maps to 0, so it *owns* root's global sysctls (`0644`) and can write
# them with no capability and no blocked syscall — writing `core_pattern` alone
# yields arbitrary code execution as root in the initial namespace (a full host
# escape). Re-mask the sysctl and other sensitive procfs surfaces read-only, as
# every container runtime does. Each is bound read-only over *itself* with
# `--ro-bind-try`, so a write anywhere on the surface is EROFS and a path absent
# on this kernel is skipped rather than fatal (binding /dev/null over a missing
# file can't work — bwrap can't create it on the read-only fresh proc). Read-only
# is sufficient: this is a *write* escape, and the info-leak reads (/proc/kcore,
# keyrings) need CAP_SYS_RAWIO/owner the cap-dropped guest does not have.
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

    Two optional attributes steer the wiring; a hatch that declares neither gets
    the original behaviour, so `GrpcHatch` needs no changes.

    * ``guest_name`` (`StreamHatch`) — this hatch is *named*, so it binds at
      ``/run/postern/<name>.sock`` and exports ``$POSTERN_HATCH_<NAME>`` instead
      of the single unnamed ``$POSTERN_HATCH``. Naming is what lets a sandbox
      carry several hatches at once, which for a stream hatch is the whole point:
      one socket per resource, so the wrong resource is unrepresentable.
    * ``guest_connector`` (`StreamHatch`) — bind `postern._stream_connect` in at
      ``$POSTERN_CONNECT`` so the guest can splice a command's stdio to the
      socket (git's ``ext::`` transport, for one, reaches a byte stream and not a
      socket).

    Everything else is the hatch's own business: `Sandbox` binds the socket, sets
    the environment, and enters ``accepting()``.
    """

    @property
    def socket_path(self) -> str: ...

    def accepting(self) -> contextlib.AbstractContextManager[typing.Any]: ...


def validate_guest_name(name: str) -> str:
    """Check a hatch name is usable as a path component and an env-var tail.

    Raises:
        ValueError: if ``name`` is not a Python identifier (see ``_GUEST_NAME_RE``),
            or is long enough that its guest socket path would not fit in a
            ``sockaddr_un`` (``sun_path`` is 108 bytes on Linux) — which is a
            capability the guest could never ``connect()`` to, and better refused
            here than silently unreachable at run time.
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

    The single place a hatch's guest-side contract is decided, so a new kind of
    hatch is one more case here rather than a branch threaded through `run` and
    `run_python`.
    """
    name = _guest_name(hatch)
    if name is None:
        return _GUEST_SOCK, 'POSTERN_HATCH'
    return guest_socket_path(name), guest_env_var(name)


def available() -> bool:
    """Whether a sandbox can launch here (bubblewrap present on the PATH)."""
    return shutil.which('bwrap') is not None


class IsolationError(RuntimeError):
    """A boot-time isolation self-test found a load-bearing control unenforced.

    Raised by :meth:`Sandbox.verify`. It exists so a worker can *fail closed* at
    startup — refuse to serve — rather than silently run untrusted code with
    weaker isolation than intended (the F1/F5 silent-degradation risk).
    """


@dataclasses.dataclass
class ProcResult:
    """The outcome of one guest run."""

    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


@dataclasses.dataclass
class SandboxProfile:
    """The hardened bubblewrap profile. Defaults are the secure baseline.

    Attributes:
        workspace: Host directory bound read-write at ``/workspace`` (the guest's
            cwd), persisting across calls for the Sandbox's lifetime and readable
            from the host (e.g. to checkpoint). Read/pack/restore it through
            :meth:`Sandbox.accessor` (a reference-closed :class:`~postern.Workspace`)
            rather than ``os``/``tarfile`` directly, so a guest-planted symlink or
            special file is never followed out of the tree. ``None`` makes the
            Sandbox create a private temp dir (removed on ``close()``); pass a path
            to own its location and lifetime.
        rootfs: A curated base directory whose ``/usr``, ``/lib`` … are bound as
            the guest's system dirs. ``None`` binds the *host's* system dirs —
            convenient for dev but exposes the host userland read-only; point at
            a minimal rootfs (assembled at build time) to hide it.
        python: Interpreter argv0 for :meth:`Sandbox.run_python` (an absolute
            path when it lives in a bound venv).
        ro_binds: Extra ``(host, guest)`` read-only binds beyond the base system
            dirs — e.g. a venv (see :meth:`with_venv`).
        stubs: Importable modules to inject at ``/run/postern/stubs`` (added to
            the guest's ``PYTHONPATH``) — a directory, or a list of individual
            files. Lets one shared rootfs carry the heavy base while per-agent
            gRPC stubs are bound in selectively (kept in lockstep with the hatch
            allowlist).
        env: Environment for the guest (``--clearenv`` wipes everything first).
        seccomp: Load the syscall denylist.
        rlimit_nproc: Per-run process-count cap (fork-bomb backstop).
        rlimit_as: Per-process address-space cap in bytes (memory-bomb backstop),
            applied by the guest shim. ``None`` leaves it unlimited. This is a
            *partial* guard — it bounds one process, not the guest's total
            memory; a cgroup ``memory.max`` set by the worker/deploy is the real
            isolation from the co-located trusted worker (F3). Leave it unset for
            legitimately memory-hungry workloads and rely on the cgroup.
        guest_uid: uid the guest runs as (``--uid``). Defaults to ``65534``
            (nobody) so the guest is **non-root inside its user namespace** —
            defusing a seccomp-gap namespace/cap re-acquisition (F2) and, when
            run as root, dropping to a non-root real uid even if the user
            namespace silently fails to materialise (F1's degraded case). The
            guest's ``/workspace`` and ``/tmp`` are made writable to suit; a
            caller-owned ``workspace`` dir is chmod'd *sticky* world-writable
            (``0o1777``) at launch so the non-root guest can use it while the
            sticky bit still stops it unlinking/replacing files it does not own
            (e.g. swapping a host-written file for an escaping symlink). ``None``
            keeps the legacy uid-0-in-userns behaviour.
        guest_gid: gid the guest runs as (``--gid``). Defaults to ``65534``.
            ``None`` leaves the gid unset.
        host_uid: opt-in defense in depth — the *real* uid bwrap runs as when the
            worker started as root. bwrap maps the guest's ``--uid`` to its own
            real uid, so a root bwrap gives the guest **kernel** uid 0, which owns
            root's files by DAC. Setting ``host_uid`` runs bwrap non-root, so the
            guest's kernel uid owns none of root's files (belt to the ``/proc/sys``
            mask's braces). As root any uid works with no ``newuidmap``/
            ``/etc/subuid``; point it at a **dedicated uid that owns no host
            file** for the tightest mapping. ``None`` (default) does not drop —
            the always-on ``/proc/sys`` mask is what closes the escape, and
            dropping requires the deploy to make every bind source (the workspace
            **and its parents**, the hatch socket's dir, the rootfs) reachable by
            ``host_uid``, so it is off unless the operator arranges that. Ignored
            when the worker is already non-root.
        host_gid: the real gid bwrap runs as, paired with ``host_uid``. ``None``
            reuses ``guest_gid``.
    """

    workspace: pathlib.Path | None = None
    rootfs: pathlib.Path | None = None
    python: str = 'python3'
    ro_binds: list[tuple[str, str]] = dataclasses.field(default_factory=list)
    stubs: str | os.PathLike[str] | Sequence[str | os.PathLike[str]] | None = None
    env: dict[str, str] = dataclasses.field(default_factory=lambda: {'PATH': '/usr/local/bin:/usr/bin:/bin'})
    seccomp: bool = True
    rlimit_nproc: int = 1024
    rlimit_as: int | None = None
    guest_uid: int | None = 65534
    guest_gid: int | None = 65534
    host_uid: int | None = None
    host_gid: int | None = None

    @classmethod
    def with_venv(cls, venv: str | pathlib.Path, **kwargs: typing.Any) -> SandboxProfile:  # noqa: ANN401
        """A profile that binds ``venv`` read-only and runs its interpreter.

        The venv is bound at its own path so the interpreter's `pyvenv.cfg` /
        `site.py` resolution finds its site-packages unchanged. Pass ``rootfs``
        through ``kwargs`` to also hide the host userland.
        """
        path = pathlib.Path(venv).resolve()
        binds = [*kwargs.pop('ro_binds', []), (str(path), str(path))]
        return cls(python=str(path / 'bin' / 'python'), ro_binds=binds, **kwargs)


def bwrap_env() -> dict[str, str]:
    """Environment for the *bwrap process itself* — scrubbed to PATH alone.

    ``--clearenv``/``--setenv`` define the *guest's* environment; they do not
    touch bwrap's own process image. bwrap is PID 1 in the guest's PID namespace
    and (because ``--uid`` is applied to it too) runs at the guest's uid, so
    whatever bwrap inherited is readable from inside the jail via
    ``/proc/1/environ`` — a same-uid ``ptrace_may_access`` read that no namespace
    or capability drop prevents. The trusted worker's environment holds the live
    secrets the hatch exists to keep from the guest (session tokens, API keys,
    backend URLs), so bwrap must be exec'd with none of them: postern does not
    trust the worker to have pre-scrubbed its own environment. Only ``PATH``
    survives, so bare ``bwrap`` still resolves.
    """
    return {'PATH': os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin')}


def bwrap_credentials(profile: SandboxProfile, euid: int) -> dict[str, typing.Any]:
    """`Popen` uid/gid kwargs to run bwrap at a non-root real uid (opt-in).

    bwrap maps the guest's ``--uid`` to its own real uid, so a root bwrap gives
    the guest kernel uid 0 — which owns root's files by DAC. Running bwrap at a
    non-root uid instead makes the guest's kernel uid non-root, so a re-exposed
    root-owned surface is unwritable by ownership as well as by the ``/proc/sys``
    mask (defense in depth). ``extra_groups=[]`` drops root's supplementary
    groups too.

    Opt-in via ``host_uid`` because bwrap, now unprivileged, must be able to
    *reach* every bind source: the workspace **and its parent directories**, the
    hatch socket's directory, and the rootfs must be traversable/readable by
    ``host_uid`` (a caller-owned workspace under a ``0700`` home, or the hatch
    socket in a private dir, otherwise fails with ``Permission denied``). Empty
    (no drop) when ``host_uid`` is unset or we are not root — the always-on
    ``/proc/sys`` mask is what closes the escape by default.
    """
    if euid != 0 or profile.host_uid is None:
        return {}
    creds: dict[str, typing.Any] = {'user': profile.host_uid, 'extra_groups': []}
    gid = profile.host_gid if profile.host_gid is not None else profile.guest_gid
    if gid is not None:
        creds['group'] = gid
    return creds


def build_base_argv(profile: SandboxProfile, seccomp_fd: int | None) -> list[str]:
    """The bwrap flags for ``profile`` (excluding the trailing ``-- argv``)."""
    root = str(profile.rootfs) if profile.rootfs is not None else ''
    # --unshare-all leaves the user and cgroup namespaces *best-effort*
    # (--unshare-user-try / --unshare-cgroup-try): if the kernel can't provide a
    # user namespace, bwrap silently continues WITHOUT one and the guest runs as
    # real root (F1's silent degradation). Re-list them strict so a missing
    # namespace is a hard launch failure instead — bwrap's own docs say to use
    # --unshare-user if you rely on it for security. --unshare-all still supplies
    # the strict ipc/pid/net/uts (and any namespace it gains in future versions).
    argv = ['bwrap', '--unshare-all', '--unshare-user', '--unshare-cgroup']
    argv += ['--new-session', '--cap-drop', 'ALL', '--die-with-parent', '--clearenv']
    # --as-pid-1 runs the entrypoint *as* PID 1 of the guest's PID namespace
    # instead of leaving bwrap resident there as a reaper. That removes the one
    # in-namespace process the guest neither owns nor can be denied by uid (bwrap
    # shares the guest uid, so its /proc/1 — cmdline, maps, read/write mem, and
    # historically environ — was reachable). With no separate bwrap PID 1, /proc/1
    # is just the guest's own entrypoint. run_python's shim then acts as a minimal
    # init (fork + reap); a raw run() entrypoint must tolerate being PID 1 itself.
    argv += ['--as-pid-1']
    # Run the guest as a non-root uid/gid (F2): inside the userns it then holds
    # no capabilities to re-gain namespaces through a seccomp gap, and if the
    # userns silently fails to materialise (F1) a root host still drops to a
    # non-root real uid rather than running the guest as real root.
    if profile.guest_uid is not None:
        argv += ['--uid', str(profile.guest_uid)]
    if profile.guest_gid is not None:
        argv += ['--gid', str(profile.guest_gid)]
    for d in _SYSTEM_DIRS:
        # /usr is mandatory (plain --ro-bind); the rest are ``-try`` so a path
        # absent on this base (e.g. /lib64) is skipped, not fatal.
        flag = '--ro-bind' if d == '/usr' else '--ro-bind-try'
        argv += [flag, root + d, d]
    argv += ['--ro-bind-try', root + '/etc/ld.so.cache', '/etc/ld.so.cache']
    for host, guest in profile.ro_binds:
        argv += ['--ro-bind-try', host, guest]
    argv += ['--proc', '/proc', '--dev', '/dev']
    # Re-mask the sensitive procfs surfaces bwrap's fresh --proc re-exposes (see
    # _PROC_RO_PATHS): without this a guest that owns the mapped-root sysctls
    # escapes the host by writing core_pattern.
    for path in _PROC_RO_PATHS:
        argv += ['--ro-bind-try', path, path]
    # '/tmp' is the guest's in-sandbox mountpoint (a fresh tmpfs), not a host
    # path; '--perms 1777' gives it the sticky world-writable mode a non-root
    # guest needs (and that a real /tmp has anyway).
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


def _stub_binds(stubs: str | os.PathLike[str] | Sequence[str | os.PathLike[str]]) -> list[str]:
    """Bwrap flags injecting importable stubs at ``/run/postern/stubs``.

    A directory is bound whole; a sequence of files is bound each to its
    basename under the stubs dir (so a common rootfs can carry the base while
    the per-service stubs are injected selectively).
    """
    if isinstance(stubs, (str, os.PathLike)):
        return ['--ro-bind', os.fspath(stubs), _GUEST_STUBS]
    binds: list[str] = []
    for entry in stubs:
        path = os.fspath(entry)
        binds += ['--ro-bind', path, f'{_GUEST_STUBS}/{pathlib.Path(path).name}']
    return binds


class Sandbox:
    """A hardened bubblewrap sandbox with optional :class:`Hatch` channels.

    ``hatch`` is opt-in and takes one hatch or a sequence: a `GrpcHatch` for typed
    methods, any number of named `StreamHatch`es for raw streams, both, or none
    (no channel is opened). At most one *unnamed* hatch, since that one owns a
    fixed guest socket and environment variable.
    """

    def __init__(self, profile: SandboxProfile | None = None, *, hatch: Hatch | Sequence[Hatch] | None = None) -> None:
        self._profile = profile or SandboxProfile()
        # A sandbox can carry several channels at once — a GrpcHatch for typed
        # methods and a StreamHatch per resource — so ``hatch`` accepts one hatch
        # or a sequence. Each is opt-in: pass none and no channel is opened.
        if hatch is None:
            self._hatches: list[Hatch] = []
        elif isinstance(hatch, (list, tuple)):
            self._hatches = list(hatch)
        else:
            self._hatches = [typing.cast('Hatch', hatch)]
        self._check_hatches()
        # The workspace persists for this Sandbox's lifetime and is bound
        # read-write at /workspace (the guest's cwd). An explicit profile path is
        # caller-owned; otherwise a private temp dir is created here and removed
        # on close(). Either way the host can read it between calls (e.g. to
        # checkpoint) via the ``workspace`` property.
        if self._profile.workspace is not None:
            self._workspace = pathlib.Path(self._profile.workspace)
            self._own_workspace = False
            self._workspace.mkdir(parents=True, exist_ok=True)
        else:
            self._workspace = pathlib.Path(tempfile.mkdtemp(prefix='postern-ws-'))
            self._own_workspace = True

    def _check_hatches(self) -> None:
        """Reject a hatch set whose guest sockets or env vars would collide.

        The unnamed hatch is capped at one because it owns a fixed guest path and
        env var (``POSTERN_HATCH``); a second would silently shadow the first's
        bind. Named hatches are unlimited but must be distinct, for the same
        reason.

        Distinct *names* are not enough: the env var is the name upper-cased, so
        ``repo`` and ``REPO`` bind two different sockets and then collide on
        ``POSTERN_HATCH_REPO``, where the last one silently wins. A guest reading
        the documented variable would land on a capability the host meant to
        expose under the other name — a resource swap in exactly the dimension the
        one-socket-per-resource design exists to make unrepresentable. So check
        the derived env var, not the name.
        """
        if sum(_guest_name(h) is None for h in self._hatches) > 1:
            raise ValueError('a sandbox takes at most one unnamed hatch (e.g. GrpcHatch); name the rest')
        names = [name for h in self._hatches if (name := _guest_name(h)) is not None]
        duplicates = {name for name in names if names.count(name) > 1}
        if duplicates:
            raise ValueError(f'hatch names must be unique; repeated: {sorted(duplicates)}')
        env_vars = [guest_env_var(name) for name in names]
        clashes = {
            var: sorted(n for n in names if guest_env_var(n) == var) for var in env_vars if env_vars.count(var) > 1
        }
        if clashes:
            raise ValueError(f'hatch names must differ by more than case; they collide on {clashes}')

    def _hatch_wiring(self) -> tuple[list[str], dict[str, str]]:
        """The bwrap binds and guest env for every configured hatch (no serving yet).

        Shared by :meth:`run` and :meth:`run_python`, because binding a socket in
        and naming it in the environment is all a hatch needs: the socket is just a
        file, so there is nothing to start inside the guest and no fork ordering to
        respect. That is why a bare ``run`` entrypoint reaches a hatch at all.
        """
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

    def accessor(self) -> Workspace:
        """A reference-closed :class:`~postern.Workspace` over the workspace.

        Read, pack, or restore the guest's workspace through this instead of
        `os`/`tarfile`/`shutil` directly: every access is confined beneath the
        workspace, so a guest-planted symlink, ``..`` or special file is never
        followed out of the tree. Usable while the Sandbox lives and after it
        (the returned accessor only needs the directory path). Use it as a
        context manager, or call ``.close()``, to release its anchor fd.
        """
        return Workspace(self._workspace)

    def _launch(
        self,
        argv: list[str],
        *,
        timeout: float,
        setenv: dict[str, str] | None = None,
        extra_binds: list[str] | None = None,
    ) -> ProcResult:
        if not available():
            raise RuntimeError('bubblewrap (bwrap) not found on PATH; postern requires Linux + bubblewrap')
        # A non-root guest cannot write a workspace dir owned by (and mode-locked
        # to) the host user, so open it up. Use the *sticky* world-writable mode
        # (0o1777), matching the tmpfs branch's `--perms 1777`: without the sticky
        # bit any uid can unlink/replace files it does not own, so the guest could
        # delete a host-written file and recreate it as an escaping symlink among
        # files it does not own. The sticky bit confines each uid to its own
        # entries — defense in depth. It removes a *precondition* for the attack,
        # not the whole fix: the guest can still plant escaping symlinks among
        # files it legitimately owns, which is why the host must read/pack the
        # workspace through the reference-closed accessor (:meth:`accessor`).
        if self._profile.guest_uid not in (None, 0):
            with contextlib.suppress(OSError):
                self._workspace.chmod(0o1777)
        seccomp = _seccomp.load_filter() if self._profile.seccomp else None
        fd = seccomp.fileno() if seccomp is not None else None
        try:
            cmd = build_base_argv(dataclasses.replace(self._profile, workspace=self._workspace), fd)
            for key, val in (setenv or {}).items():
                cmd += ['--setenv', key, val]
            cmd += extra_binds or []
            cmd += ['--', *argv]
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                # Scrub bwrap's own environment: it is PID 1 in the guest's
                # namespace at the guest uid, so an inherited secret would be
                # readable from inside via /proc/1/environ (see bwrap_env).
                env=bwrap_env(),
                pass_fds=(fd,) if fd is not None else (),
                # Run bwrap at a non-root real uid when we are root, so the
                # guest's kernel uid (which bwrap maps --uid onto) is non-root and
                # owns none of root's files (see bwrap_credentials).
                **bwrap_credentials(self._profile, os.geteuid()),
            )
            try:
                out, err = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                out, err = proc.communicate()
                return ProcResult(124, out or '', (err or '') + '\n[postern] timed out')
            return ProcResult(proc.returncode, out or '', err or '')
        finally:
            if seccomp is not None:
                seccomp.close()

    def run(self, argv: list[str], *, timeout: float = 60) -> ProcResult:
        """Run ``argv`` inside the sandbox and return its result.

        The raw primitive for a non-Python entrypoint: it does not set
        ``RLIMIT_NPROC`` (that is :meth:`run_python`'s job, applied by its shim),
        so the entrypoint manages its own limits and must tolerate being PID 1.

        It *does* bind and serve every configured :class:`Hatch`, so a bare
        entrypoint — ``git`` reaching a `StreamHatch`, say — has the same
        capabilities a `run_python` guest would. That works because a hatch needs
        nothing in-guest: the socket is a file at
        ``$POSTERN_HATCH``/``$POSTERN_HATCH_<NAME>``, with no relay to start and so
        no in-guest fork to order it against.
        """
        binds, env = self._hatch_wiring()
        with contextlib.ExitStack() as stack:
            for hatch in self._hatches:
                stack.enter_context(hatch.accepting())
            return self._launch(list(argv), timeout=timeout, setenv=env, extra_binds=binds)

    def run_python(self, code: str, *, timeout: float = 60) -> ProcResult:
        """Run untrusted Python ``code`` inside the sandbox.

        Each configured :class:`Hatch` binds its own UDS in. The unnamed hatch
        (e.g. `GrpcHatch`) exports its path as ``POSTERN_HATCH``, and the guest
        reaches the host's allowlisted gRPC methods by dialing
        ``unix:$POSTERN_HATCH`` with the generated stub (grpcio and the stubs come
        from the bound environment); a *named* hatch (`StreamHatch`) exports
        ``POSTERN_HATCH_<NAME>`` so several can coexist. The guest shim applies
        ``RLIMIT_NPROC`` before running the code.
        """
        binds, env = self._hatch_wiring()
        binds += ['--ro-bind', _SHIM_SRC, _GUEST_SHIM]
        # Pre-seed the variable the shim reads unconditionally, so an absent hatch
        # is an empty string rather than a missing one under --clearenv.
        env = {
            'POSTERN_CODE': code,
            'POSTERN_NPROC': str(self._profile.rlimit_nproc),
            'POSTERN_AS': str(self._profile.rlimit_as or 0),
            'POSTERN_HATCH': '',
            **env,
        }
        argv = [self._profile.python, '-u', _GUEST_SHIM]
        # With no hatches the ExitStack is a no-op and no channel is opened.
        with contextlib.ExitStack() as stack:
            for hatch in self._hatches:
                stack.enter_context(hatch.accepting())
            return self._launch(argv, timeout=timeout, setenv=env, extra_binds=binds)

    def verify(self, *, timeout: float = 30) -> None:
        """Fail fast at startup unless the sandbox actually launches here.

        A boot-time gate: call once against the profile you will serve with, and
        refuse to run untrusted code if it raises. Every control is already
        fail-closed on the launch path — the strict ``--unshare-{user,net,…}``
        flags make bwrap abort if it cannot create the namespaces, apply
        ``--uid`` or drop capabilities (F1/F2/F5), and :func:`_seccomp.load_filter`
        refuses an architecture the filter doesn't cover (F4). So there is nothing
        to *probe* for at runtime (a successful launch is the proof, as in
        Chrome's sandbox): this just triggers one trivial launch so a broken
        platform — no user namespace, gVisor, an uncovered arch — surfaces as an
        :class:`IsolationError` at startup rather than on the first real request.
        """
        if not self._profile.seccomp:
            raise IsolationError('seccomp is disabled; refusing to treat this as a hardened sandbox')
        result = self.run_python('pass', timeout=timeout)
        if not result.ok:
            raise IsolationError(f'sandbox failed to launch: {result.stderr.strip() or result.returncode}')

    def close(self) -> None:
        """Remove the workspace if this Sandbox created it (a no-op for a caller-owned path)."""
        if self._own_workspace:
            shutil.rmtree(self._workspace, ignore_errors=True)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
