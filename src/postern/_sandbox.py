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
import shutil
import subprocess
import tempfile
import typing
from collections.abc import Sequence

from postern import _seccomp

if typing.TYPE_CHECKING:
    # `typing.Self` is 3.11+, but postern supports 3.10; the backport is
    # type-check-only (guarded here), so the runtime stays dependency-free.
    from typing_extensions import Self

_GUEST_DIR = '/run/postern'
_GUEST_SOCK = f'{_GUEST_DIR}/hatch.sock'
_GUEST_SHIM = f'{_GUEST_DIR}/_guest.py'
_GUEST_STUBS = f'{_GUEST_DIR}/stubs'
_GUEST_WORKSPACE = '/workspace'
_SHIM_SRC = str(pathlib.Path(__file__).with_name('_guest.py'))
_SYSTEM_DIRS = ('/usr', '/lib', '/lib64', '/bin', '/sbin')


class Hatch(typing.Protocol):
    """What `Sandbox` needs of a hatch: a UDS path and a serving context."""

    @property
    def socket_path(self) -> str: ...

    def accepting(self) -> contextlib.AbstractContextManager[typing.Any]: ...


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
            from the host (e.g. to checkpoint). ``None`` makes the Sandbox create
            a private temp dir (removed on ``close()``); pass a path to own its
            location and lifetime.
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
            caller-owned ``workspace`` dir is chmod'd world-writable at launch so
            the non-root guest can use it. ``None`` keeps the legacy uid-0-in-
            userns behaviour.
        guest_gid: gid the guest runs as (``--gid``). Defaults to ``65534``.
            ``None`` leaves the gid unset.
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
    # '/tmp' is the guest's in-sandbox mountpoint (a fresh tmpfs), not a host
    # path; '--perms 1777' gives it the sticky world-writable mode a non-root
    # guest needs (and that a real /tmp has anyway).
    argv += ['--proc', '/proc', '--dev', '/dev', '--perms', '1777', '--tmpfs', '/tmp']  # noqa: S108
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
    """A hardened bubblewrap sandbox with an optional typed :class:`Hatch`."""

    def __init__(self, profile: SandboxProfile | None = None, *, hatch: Hatch | None = None) -> None:
        self._profile = profile or SandboxProfile()
        self._hatch = hatch
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

    @property
    def workspace(self) -> pathlib.Path:
        """The host directory bound read-write at ``/workspace`` (the guest cwd)."""
        return self._workspace

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
        # to) the host user, so open it up. The dir is private to this single-
        # tenant sandbox, so world-writable is immaterial (see F9).
        if self._profile.guest_uid not in (None, 0):
            with contextlib.suppress(OSError):
                self._workspace.chmod(0o777)
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

        The raw primitive: it does not serve the hatch or set ``RLIMIT_NPROC``
        (those are :meth:`run_python`'s job). Use it for a non-Python entrypoint
        that manages its own limits.
        """
        return self._launch(list(argv), timeout=timeout)

    def run_python(self, code: str, *, timeout: float = 60) -> ProcResult:
        """Run untrusted Python ``code`` inside the sandbox.

        With a :class:`Hatch`, the hatch UDS is bound in and its path exported as
        ``POSTERN_HATCH``; the guest reaches the host's allowlisted gRPC methods
        by dialing ``unix:$POSTERN_HATCH`` with the generated stub (grpcio and
        the stubs come from the bound environment). The guest shim applies
        ``RLIMIT_NPROC`` before running the code.
        """
        binds = ['--ro-bind', _SHIM_SRC, _GUEST_SHIM]
        env = {
            'POSTERN_CODE': code,
            'POSTERN_NPROC': str(self._profile.rlimit_nproc),
            'POSTERN_AS': str(self._profile.rlimit_as or 0),
            'POSTERN_HATCH': '',
        }
        argv = [self._profile.python, '-u', _GUEST_SHIM]
        if self._hatch is None:
            return self._launch(argv, timeout=timeout, setenv=env, extra_binds=binds)
        binds += ['--bind', self._hatch.socket_path, _GUEST_SOCK]
        env['POSTERN_HATCH'] = _GUEST_SOCK
        with self._hatch.accepting():
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
