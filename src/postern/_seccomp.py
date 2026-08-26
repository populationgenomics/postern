"""The seccomp-BPF denylist: a multi-arch backstop.

Defense in depth on top of the empty network namespace and dropped capabilities:
block the syscalls that would let guest code re-gain namespaces, mount, trace,
load code into the kernel, or fake terminal input. It is a denylist (default
allow) — a backstop, not the primary boundary.

``tools/gen_seccomp.py`` compiles the syscall lists below with libseccomp and
commits the result as ``_seccomp.bpf`` next to this module; the runtime only
loads that blob and hands its fd to ``bwrap --seccomp``, so postern itself needs
no libseccomp. The blob is one multi-arch program; on an architecture it does not
cover its default-allow enforces nothing, so :func:`load_filter` refuses to load
it there.

The syscall lists are the source of truth the generator consumes, derived from
Flatpak's policy (``common/flatpak-run.c``). Editing them requires regenerating
the blob — see ``tools/gen_seccomp.sh``.
"""

from __future__ import annotations

import hashlib
import importlib.resources
import json
import platform
import tempfile
import typing

_BPF_RESOURCE = '_seccomp.bpf'
_SPEC_RESOURCE = '_seccomp.spec'

# The ``uname -m`` spellings of the architectures GEN_ARCHES compiles into the blob.
COVERED_ARCHES: frozenset[str] = frozenset(
    {'x86_64', 'amd64', 'i386', 'i486', 'i586', 'i686', 'aarch64', 'arm64', 'armv6l', 'armv7l', 'armv8l', 'arm'}
)


def arch_is_covered(machine: str | None = None) -> bool:
    """Whether the committed filter carries a program for ``machine``.

    Args:
        machine: A ``uname -m`` name; defaults to the host's ``platform.machine()``.

    Returns:
        False if the blob would load here but enforce nothing (default-allow).
    """
    return (machine or platform.machine()).lower() in COVERED_ARCHES


# Blocked with EPERM. Flatpak's main blocklist plus its non-devel additions
# (ptrace, perf_event_open).
BLOCKED_EPERM: tuple[str, ...] = (
    # Re-gaining namespaces / changing the mount or root view (bwrap already set
    # ours up before applying this filter).
    'unshare',
    'setns',
    'mount',
    'umount2',
    'pivot_root',
    'chroot',
    # Kernel keyring.
    'add_key',
    'keyctl',
    'request_key',
    # Tracing / profiling other processes.
    'ptrace',
    'perf_event_open',
    # Scary VM / NUMA memory ops.
    'move_pages',
    'mbind',
    'get_mempolicy',
    'set_mempolicy',
    'migrate_pages',
    # Misc: read the kernel log, load a shared lib by inode, toggle accounting,
    # manipulate quotas.
    'syslog',
    'uselib',
    'acct',
    'quotactl',
    # Kernel modules, eBPF, kexec, reboot, swap. Each also needs a capability the
    # guest lacks; blocked anyway as defense in depth.
    'bpf',
    'init_module',
    'finit_module',
    'delete_module',
    'kexec_load',
    'kexec_file_load',
    'reboot',
    'swapon',
    'swapoff',
    # io_uring performs operations (openat, read, …) as ring entries that never
    # pass back through this syscall filter.
    'io_uring_setup',
    'io_uring_enter',
    'io_uring_register',
)

# clone3 and the new mount API. seccomp cannot inspect clone3's argument struct,
# so it is refused wholesale; ENOSYS (not EPERM) makes glibc fall back to the
# classic clone/mount paths instead of failing hard.
BLOCKED_ENOSYS: tuple[str, ...] = (
    'clone3',
    'open_tree',
    'move_mount',
    'fsopen',
    'fsconfig',
    'fsmount',
    'fspick',
    'mount_setattr',
)

# Argument-filtered rules the generator applies. clone's flags are arg0 on every
# architecture in GEN_ARCHES; ioctl's request is arg1.
CLONE_NEWUSER = 0x10000000  # clone(CLONE_NEWUSER, ...) — the gap unshare/setns alone leave open
TIOCSTI = 0x5412  # fake terminal input (CVE-2017-5226)
TIOCLINUX = 0x541C  # the same via the linux console ioctl

# The libseccomp Arch names the generator compiles into the blob. Here rather
# than in the generator so spec_digest covers them without importing libseccomp.
GEN_ARCHES: tuple[str, ...] = ('X86_64', 'X86', 'X32', 'AARCH64', 'ARM')

# socket and socketpair stay allowed: the guest needs socket(AF_UNIX) to reach the
# hatch UDS, and network isolation is the empty netns's job.


def spec_digest() -> str:
    """A stable digest of the syscall spec the committed blob was built from.

    ``tools/gen_seccomp.py`` records it in ``_seccomp.spec`` and
    ``tests/test_seccomp.py`` compares, so editing a rule list without
    regenerating the blob is caught without a libseccomp dependency. It does not
    prove the blob is what libseccomp would emit today — the regenerate-and-diff
    job in ``.github/workflows/tests.yml`` is what proves that.
    """
    payload = json.dumps(
        {
            'blocked_eperm': list(BLOCKED_EPERM),
            'blocked_enosys': list(BLOCKED_ENOSYS),
            'clone_newuser': CLONE_NEWUSER,
            'tiocsti': TIOCSTI,
            'tioclinux': TIOCLINUX,
            'gen_arches': list(GEN_ARCHES),
        },
        sort_keys=True,
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def manifest() -> dict[str, str]:
    """Build the ``_seccomp.spec`` manifest for the currently committed blob."""
    blob = importlib.resources.files('postern').joinpath(_BPF_RESOURCE).read_bytes()
    return {'source_digest': spec_digest(), 'bpf_sha256': hashlib.sha256(blob).hexdigest()}


def load_filter() -> typing.IO[bytes]:
    """Load the prebuilt BPF denylist into an open temp file positioned at 0.

    Returns:
        An open temp file; the caller passes its fd to ``bwrap --seccomp``, keeps
        it open for the child's lifetime, and closes it.

    Raises:
        RuntimeError: On an architecture the blob does not cover (where it would
            enforce nothing), or if the blob is missing from the install.
    """
    if not arch_is_covered():
        raise RuntimeError(
            f'seccomp filter has no coverage for this architecture ({platform.machine()!r}); refusing to run '
            'untrusted code with an unenforced filter (set SandboxProfile(seccomp=False) to override deliberately)'
        )
    data = importlib.resources.files('postern').joinpath(_BPF_RESOURCE).read_bytes()
    if not data:
        raise RuntimeError(f'seccomp filter {_BPF_RESOURCE!r} is missing or empty; the postern install is broken')
    f = tempfile.TemporaryFile()  # noqa: SIM115 — returned open; caller passes its fd to bwrap and closes it
    f.write(data)
    f.flush()
    f.seek(0)
    return f
