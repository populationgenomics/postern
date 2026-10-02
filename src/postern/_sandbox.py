"""The hardened isolation core: a bubblewrap-launched sandbox.

`Sandbox` runs a program (or a snippet of Python) under bubblewrap with the
hardened profile: an empty network namespace, a surgical read-only view of the
base system directories plus one writable workspace, `--cap-drop ALL`,
`--new-session` and a seccomp denylist. Every entrypoint runs under the guest's
init, PID 1 of its namespace, which adds the ``RLIMIT_NPROC`` fork-bomb backstop
and reaps the guest's orphans: the static C init when the profile names one
(``SandboxProfile.init``, the recommended path), the Python shim
(`postern._guest`) otherwise. The guest's only channel to the outside is whatever
`Hatch` the caller binds in.

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
import re
import shutil
import subprocess
import tempfile
import typing

from postern import _process, _seccomp, _workspace

if typing.TYPE_CHECKING:
    import typing_extensions

_GUEST_DIR = '/run/postern'
_GUEST_SOCK = f'{_GUEST_DIR}/hatch.sock'  # the unnamed hatch (GrpcHatch) → POSTERN_HATCH
_GUEST_SHIM = f'{_GUEST_DIR}/_guest.py'
_GUEST_INIT = f'{_GUEST_DIR}/init'
_GUEST_STUBS = f'{_GUEST_DIR}/stubs'
_GUEST_WORKSPACE = '/workspace'
_SHIM_SRC = str(pathlib.Path(__file__).with_name('_guest.py'))
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
    """A boot-time isolation self-test found a load-bearing control unenforced.

    Raised by :meth:`Sandbox.verify`, so a worker can refuse to serve rather than
    run untrusted code with weaker isolation than intended.
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
            cwd), persisting for the Sandbox's lifetime. Read, pack or restore it
            through :meth:`Sandbox.accessor` rather than ``os``/``tarfile``
            directly, so a guest-planted symlink or special file is never followed
            out of the tree. ``None`` makes the Sandbox create a private temp dir,
            removed on ``close()``.
        rootfs: A curated base directory whose ``/usr``, ``/lib`` … are bound as
            the guest's system dirs. ``None`` binds the *host's* system dirs,
            exposing the host userland read-only.
        python: Interpreter argv0 for the in-guest shim (an absolute path when it
            lives in a bound venv). :meth:`Sandbox.run_python` always needs it;
            under the C init (``init``) nothing else does, while the fallback
            Python shim needs it for every entrypoint.
        ro_binds: Extra ``(host, guest)`` read-only binds beyond the base system
            dirs — e.g. a venv (see :meth:`with_venv`).
        stubs: Importable modules to inject at ``/run/postern/stubs`` (prepended to
            the guest's ``PYTHONPATH``) — a directory, or a list of files, so a
            shared rootfs can carry the heavy base while the per-agent gRPC stubs
            bind in selectively.
        env: Environment for the guest (``--clearenv`` wipes everything first).
        seccomp: Load the syscall denylist.
        rlimit_nproc: Per-run process-count cap (fork-bomb backstop), applied by
            the guest shim.
        rlimit_as: Per-process address-space cap in bytes, applied by the guest
            shim. ``None`` leaves it unlimited. It bounds one process, not the
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
            rootfs — reachable by ``host_uid``. Ignored when already non-root.
        host_gid: the real gid bwrap runs as, paired with ``host_uid``. ``None``
            reuses ``guest_gid``.
        init: Host path to the static guest init that
            ``python -m postern.build_init`` builds: the recommended PID 1 of
            every run. Under it :meth:`Sandbox.run` and :meth:`Sandbox.run_bash`
            need no interpreter in the sandbox; :meth:`Sandbox.run_python` execs
            ``python`` on the shim as the init's child. It is bound in read-only;
            being static, it needs nothing from ``rootfs``. It is only ever
            executed inside the sandbox, never on the host. Must be absolute.
            :meth:`Sandbox.verify` refuses one built from a different postern
            version. ``None`` falls
            back to the Python shim as the init, which needs ``python`` for every
            entrypoint and costs an interpreter start on every run.
    """

    workspace: pathlib.Path | None = None
    rootfs: pathlib.Path | None = None
    python: str = 'python3'
    ro_binds: list[tuple[str, str]] = dataclasses.field(default_factory=list)
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
        ``site.py`` resolution finds its site-packages unchanged.

        Args:
            venv: The venv root on the host.
            **kwargs: Any other :class:`SandboxProfile` field; ``ro_binds`` is
                extended rather than replaced.
        """
        path = pathlib.Path(venv).resolve()
        binds = [*kwargs.pop('ro_binds', []), (str(path), str(path))]
        return cls(python=str(path / 'bin' / 'python'), ro_binds=binds, **kwargs)


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


def bwrap_credentials(profile: SandboxProfile, euid: int) -> dict[str, typing.Any]:
    """`Popen` uid/gid kwargs to run bwrap at a non-root real uid (opt-in).

    bwrap maps the guest's ``--uid`` onto its own real uid, so a root bwrap gives
    the guest kernel uid 0, which owns root's files by DAC. A non-root bwrap makes
    a re-exposed root-owned surface unwritable by ownership as well as by the
    ``/proc/sys`` mask. ``extra_groups=[]`` drops root's supplementary groups too.

    Args:
        profile: The profile whose ``host_uid``/``host_gid`` decide the drop.
        euid: The worker's effective uid; a drop is only possible from 0.

    Returns:
        The kwargs to splat into `Popen`, or ``{}`` for no drop. Empty unless
        ``host_uid`` is set and ``euid`` is 0, because an unprivileged bwrap must
        still be able to reach every bind source — the workspace *and its
        parents*, the hatch socket's directory, the rootfs — or the launch fails
        with ``Permission denied``.
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
    # --unshare-all makes the user and cgroup namespaces best-effort
    # (--unshare-user-try/--unshare-cgroup-try): without a user namespace bwrap
    # continues silently and the guest runs as real root. Listing them strict makes
    # that a launch failure. --unshare-all still supplies the strict ipc/pid/net/uts.
    argv = ['bwrap', '--unshare-all', '--unshare-user', '--unshare-cgroup']
    argv += ['--new-session', '--cap-drop', 'ALL', '--die-with-parent', '--clearenv']
    # Without --as-pid-1 bwrap stays resident as PID 1 of the guest's namespace,
    # at the guest's own uid, so its /proc/1 (cmdline, maps, mem) is readable from
    # inside. The guest's init (the C init, or the Python shim) is PID 1 instead.
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
    for host, guest in profile.ro_binds:
        argv += ['--ro-bind-try', host, guest]
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
        closes it when the run is closed; on a failed launch it is closed here.
        """
        if not available():
            resources.close()
            raise RuntimeError('bubblewrap (bwrap) not found on PATH; postern requires Linux + bubblewrap')
        # A non-root guest cannot write a host-owned workspace dir. 1777 rather than
        # 0777 (matching the tmpfs branch): without the sticky bit the guest could
        # unlink a host-written file and recreate it as an escaping symlink. It can
        # still plant one among files it owns, which is what :meth:`accessor` is for.
        if self._profile.guest_uid not in (None, 0):
            with contextlib.suppress(OSError):
                self._workspace.chmod(0o1777)
        seccomp = _seccomp.load_filter() if self._profile.seccomp else None
        fd = seccomp.fileno() if seccomp is not None else None
        # bwrap reports the init's host pid here, which is how cancel() reaches it.
        info_read, info_write = os.pipe()
        try:
            cmd = build_base_argv(dataclasses.replace(self._profile, workspace=self._workspace), fd)
            cmd += ['--info-fd', str(info_write)]
            for key, val in (setenv or {}).items():
                cmd += ['--setenv', key, val]
            cmd += extra_binds or []
            cmd += ['--', *argv]
            # Bytes, decoded by Process. Cast because the credentials splat is Any,
            # which lets the type checker pick Popen's text-mode overload.
            popen = typing.cast(
                'subprocess.Popen[bytes]',
                subprocess.Popen(
                    cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    # Scrub bwrap's own environment: it is PID 1 in the guest's
                    # namespace at the guest uid, so an inherited secret would be
                    # readable from inside via /proc/1/environ (see bwrap_env).
                    env=bwrap_env(),
                    pass_fds=(info_write,) if fd is None else (fd, info_write),
                    # Run bwrap at a non-root real uid when we are root, so the
                    # guest's kernel uid (which bwrap maps --uid onto) is non-root and
                    # owns none of root's files (see bwrap_credentials).
                    **bwrap_credentials(self._profile, os.geteuid()),
                ),
            )
        except BaseException:
            os.close(info_read)
            resources.close()
            raise
        finally:
            os.close(info_write)
            if seccomp is not None:
                seccomp.close()
        try:
            try:
                pidfd = _process.open_pidfd(_process.read_init_pid(info_read), popen)
            finally:
                os.close(info_read)
            return _process.Process(popen, pidfd=pidfd, resources=resources)
        except BaseException:
            with contextlib.suppress(ProcessLookupError):
                popen.kill()
            with contextlib.suppress(Exception):
                popen.wait()
            resources.close()
            raise

    def _supervised(self, work_argv: list[str], *, code: str = '', recode: bool = False) -> _process.Process:
        """Start ``work_argv`` under the guest's init, with every hatch bound and served.

        The one funnel behind :meth:`run`, :meth:`run_bash` and :meth:`run_python`.
        The init is bwrap's ``--as-pid-1`` entrypoint: the C init when the profile
        names one, the Python shim (``postern._guest``) otherwise. It applies the
        resource backstops, forks, and the child execs ``work_argv``.

        Args:
            work_argv: What the shim's forked child execs.
            code: ``POSTERN_CODE`` for the :meth:`run_python` re-exec. Empty for an
                arbitrary program, which reads its own input.
            recode: Whether ``work_argv`` re-execs the shim to run ``code``. It makes
                the shim defer ``RLIMIT_AS`` until the fresh interpreter has started.

        Returns:
            The running process, which owns the hatches' serving contexts.
        """
        binds, env = self._hatch_wiring()
        # Under --clearenv, guest code reading os.environ['POSTERN_HATCH'] would
        # raise KeyError with no hatch configured; seed it empty instead.
        env = {'POSTERN_HATCH': '', **env}
        nproc, as_bytes = str(self._profile.rlimit_nproc), str(self._profile.rlimit_as or 0)
        if self._profile.init is not None:
            # The C init is PID 1 and execs work_argv itself. The shim is only bound
            # when work_argv runs it (run_python), and then it is a plain child that
            # applies RLIMIT_AS once its interpreter is up — so the init must not.
            binds += ['--ro-bind', os.fspath(self._profile.init), _GUEST_INIT]
            if recode:
                binds += ['--ro-bind', _SHIM_SRC, _GUEST_SHIM]
                env = {'POSTERN_CODE': code, 'POSTERN_NPROC': nproc, 'POSTERN_AS': as_bytes, **env}
            limits = ['--nproc', nproc, '--as', '0' if recode else as_bytes]
            entrypoint = [_GUEST_INIT, *limits, '--', *work_argv]
        else:
            binds += ['--ro-bind', _SHIM_SRC, _GUEST_SHIM]
            env = {
                'POSTERN_ARGV': json.dumps(work_argv),
                'POSTERN_CODE': code,
                'POSTERN_RECODE': '1' if recode else '',
                'POSTERN_NPROC': nproc,
                'POSTERN_AS': as_bytes,
                **env,
            }
            entrypoint = [self._profile.python, '-u', _GUEST_SHIM]
        stack = contextlib.ExitStack()
        try:
            for hatch in self._hatches:
                stack.enter_context(hatch.accepting())
        except BaseException:
            stack.close()
            raise
        return self._start(entrypoint, resources=stack, setenv=env, extra_binds=binds)

    def run(self, argv: list[str], *, timeout: float = 60) -> ProcResult:
        """Run ``argv`` inside the sandbox and return its result.

        The entrypoint for a program that is not Python. It runs under the same
        guest init as :meth:`run_python`, so ``argv`` inherits ``RLIMIT_NPROC`` and
        ``RLIMIT_AS`` across the exec, has its orphaned descendants reaped, and is
        not PID 1 itself. Under the C init (``SandboxProfile.init``) it needs no
        interpreter in the sandbox; under the fallback Python shim,
        ``profile.python`` must exist there even when ``argv`` is a compiled
        program.

        Every configured :class:`Hatch` is bound and served: the socket is a file at
        ``$POSTERN_HATCH``/``$POSTERN_HATCH_<NAME>``, so ``argv`` reaches it with no
        in-guest relay.
        """
        return self.start(argv).communicate(timeout)

    def run_bash(self, script: str, *, shell: str = 'bash', timeout: float = 60) -> ProcResult:
        """Run ``script`` inside the sandbox as ``shell -c script``.

        Args:
            script: The script text. It is an argument to ``shell`` in the guest,
                never interpolated into a host command line.
            shell: The shell to run it with. Must exist in the sandbox, which a
                curated ``rootfs`` need not provide.
            timeout: Seconds before the launch is killed.

        Returns:
            The launch's result.
        """
        return self.start_bash(script, shell=shell).communicate(timeout)

    def run_python(self, code: str, *, timeout: float = 60) -> ProcResult:
        """Run untrusted Python ``code`` inside the sandbox.

        The shim's child re-execs ``profile.python`` to run ``code``, so the code
        gets a clean interpreter rather than the supervisor's own process, and
        ``RLIMIT_AS`` is applied once that interpreter is up.

        Each configured :class:`Hatch` binds its own UDS in. The unnamed hatch
        exports its path as ``POSTERN_HATCH``, a named one as
        ``POSTERN_HATCH_<NAME>``; the client library that dials it comes from the
        guest's bound environment.
        """
        return self.start_python(code).communicate(timeout)

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
        return self._supervised([self._profile.python, '-u', _GUEST_SHIM], code=code, recode=True)

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

            def _cleanup(f: asyncio.Future[_process.Process]) -> None:
                if f.cancelled() or f.exception() is not None:
                    return
                with contextlib.suppress(Exception):
                    proc = f.result()
                    proc.kill()
                    proc.close()

            future.add_done_callback(_cleanup)
            raise
        return _process.AsyncProcess(process)

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

        With an init set, the trivial launch is the init's own ``--version``, run
        inside the sandbox, and its answer must be this postern's version.

        Raises:
            IsolationError: If ``seccomp`` is disabled in the profile, the trivial
                launch fails, or the init was built from another postern version.
        """
        if not self._profile.seccomp:
            raise IsolationError('seccomp is disabled; refusing to treat this as a hardened sandbox')
        if self._profile.init is None:
            result = self.run_python('pass', timeout=timeout)
            if not result.ok:
                raise IsolationError(f'sandbox failed to launch: {result.stderr.strip() or result.returncode}')
            return
        # The init itself, inside the sandbox: it needs nothing from the rootfs (under
        # the C init a rootfs need not carry Python), and the init is never executed
        # on the host. The host only ever runs bwrap; running a deployer-supplied
        # binary here, as the worker and with its environment, would hand anything
        # that could swap that file the worker's privileges.
        result = self.run([_GUEST_INIT, '--version'], timeout=timeout)
        if not result.ok:
            raise IsolationError(f'sandbox failed to launch: {result.stderr.strip() or result.returncode}')
        import postern  # noqa: PLC0415 — the package imports this module

        reported = result.stdout.strip()
        if reported != postern.__version__:
            raise IsolationError(
                f'guest init {self._profile.init} was built from postern {reported}, not {postern.__version__}; '
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
