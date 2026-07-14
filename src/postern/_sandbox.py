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
import json
import os
import pathlib
import platform
import shutil
import subprocess
import tempfile
import typing
from collections.abc import Sequence

from postern import _seccomp

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


# A stdlib-only probe run *inside* the sandbox by :meth:`Sandbox.self_test`. It
# reports the guest's uid/gid, its effective capabilities, whether egress is
# denied, and whether re-gaining a user namespace is blocked — the observable
# signals of the isolation controls. It prints one JSON object as its last line.
_SELFTEST_CODE = r"""
import ctypes, json, os, socket
report = {'uid': os.getuid(), 'gid': os.getgid()}
caps = -1
try:
    with open('/proc/self/status') as fh:
        for line in fh:
            if line.startswith('CapEff:'):
                caps = int(line.split()[1], 16)
                break
except OSError:
    pass
report['cap_eff'] = caps
try:
    socket.create_connection(('1.1.1.1', 443), timeout=3).close()
    report['egress'] = True
except OSError:
    report['egress'] = False
libc = ctypes.CDLL(None, use_errno=True)
report['userns_reblocked'] = libc.unshare(0x10000000) != 0  # CLONE_NEWUSER
print(json.dumps(report))
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

    def self_test(self, *, timeout: float = 30) -> dict[str, typing.Any]:
        """Launch an in-sandbox probe and return its isolation report.

        The report has ``uid``/``gid``/``cap_eff`` (effective capabilities, 0 ==
        fully unprivileged), ``egress`` (True if an outbound connection
        succeeded — it must not), and ``userns_reblocked`` (True if the guest was
        refused a fresh user namespace). This only *observes*; :meth:`verify`
        turns the report into a fail-closed gate. Raises :class:`IsolationError`
        if the probe cannot run or emits no report.
        """
        result = self.run_python(_SELFTEST_CODE, timeout=timeout)
        if not result.ok:
            detail = result.stderr.strip() or result.returncode
            raise IsolationError(f'isolation self-test probe failed to run: {detail}')
        try:
            return json.loads(result.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError) as exc:
            raise IsolationError(f'isolation self-test emitted no report (stdout={result.stdout!r})') from exc

    def verify(self) -> None:
        """Fail closed unless every load-bearing isolation control is enforced.

        Intended as a boot-time gate: call once at worker startup against the
        profile you will serve with, and refuse to run untrusted code if it
        raises. It converts the silent-degradation risks (F1: no user namespace /
        real-root guest; F5: open egress; F4: seccomp that is a no-op on this
        architecture) into a hard :class:`IsolationError` at startup instead of a
        weakened sandbox that looks healthy.
        """
        problems: list[str] = []
        if self._profile.seccomp and not _seccomp.arch_is_covered():
            problems.append(
                f'seccomp filter carries no program for this architecture ({platform.machine()!r}); it enforces nothing'
            )
        report = self.self_test()
        if report.get('egress') is not False:
            problems.append('network egress is not denied (the empty netns did not take effect)')
        if self._profile.seccomp and report.get('userns_reblocked') is not True:
            problems.append('guest was able to create a new user namespace (seccomp is not enforcing)')
        guest_uid = self._profile.guest_uid
        if guest_uid not in (None, 0):
            if report.get('uid') != guest_uid:
                problems.append(f'guest runs as uid {report.get("uid")}, not the configured non-root {guest_uid}')
            if report.get('cap_eff') != 0:
                problems.append(f'guest holds effective capabilities (CapEff={report.get("cap_eff")}), expected none')
        if problems:
            raise IsolationError('isolation self-test failed: ' + '; '.join(problems))

    def close(self) -> None:
        """Remove the workspace if this Sandbox created it (a no-op for a caller-owned path)."""
        if self._own_workspace:
            shutil.rmtree(self._workspace, ignore_errors=True)

    def __enter__(self) -> typing.Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
