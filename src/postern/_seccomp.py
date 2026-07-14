"""The seccomp-BPF denylist: a maintained, multi-arch backstop.

Defense in depth on top of the empty network namespace and dropped capabilities:
block the syscalls that would let guest code re-gain namespaces, mount, trace,
load code into the kernel, or fake terminal input. It is a denylist (default
allow) — a backstop, not the primary boundary.

The filter is compiled **ahead of time** by ``tools/gen_seccomp.py`` (which uses
libseccomp) and committed as ``_seccomp.bpf`` next to this module. The runtime
only *loads* that blob and hands its fd to ``bwrap --seccomp`` — so installing or
running postern needs no libseccomp, keeping the core dependency-free. The blob
is a single multi-arch program (x86_64, x86, x32, aarch64, arm); on any other
architecture its default-allow makes it a safe no-op.

The syscall lists below are the source of truth the generator consumes; they are
derived from Flatpak's seccomp policy (``common/flatpak-run.c``). Editing them
requires regenerating the blob — see ``tools/gen_seccomp.sh``.
"""

from __future__ import annotations

import importlib.resources
import platform
import tempfile
import typing

_BPF_RESOURCE = '_seccomp.bpf'

# The machine architectures the committed blob actually carries a program for
# (the ``uname -m`` names for ``tools/gen_seccomp._ARCHES``). On anything else
# the filter's default-allow makes it a silent no-op, so a caller that relies on
# the backstop must treat an uncovered arch as fail-closed rather than trusting a
# filter that enforces nothing — see ``Sandbox.verify``.
COVERED_ARCHES: frozenset[str] = frozenset(
    {'x86_64', 'amd64', 'i386', 'i486', 'i586', 'i686', 'aarch64', 'arm64', 'armv6l', 'armv7l', 'armv8l', 'arm'}
)


def arch_is_covered(machine: str | None = None) -> bool:
    """Whether the committed filter carries a program for ``machine``.

    Defaults to the running host's ``platform.machine()``. False means the blob
    would load but enforce nothing here (default-allow no-op).
    """
    return (machine or platform.machine()).lower() in COVERED_ARCHES


# Blocked with EPERM: escape-enabling or dangerous syscalls the guest never
# legitimately needs. (Flatpak's main blocklist plus its non-devel additions —
# ptrace and perf_event_open.)
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
    # Kernel modules, eBPF, kexec, reboot, swap. Redundant with --cap-drop ALL
    # (each needs a capability the guest lacks) but kept as cheap defense in
    # depth — postern blocked these before adopting Flatpak's list.
    'bpf',
    'init_module',
    'finit_module',
    'delete_module',
    'kexec_load',
    'kexec_file_load',
    'reboot',
    'swapon',
    'swapoff',
)

# Blocked with ENOSYS (not EPERM): clone3 and the new mount API. seccomp cannot
# inspect clone3's argument struct, so it is refused wholesale; returning ENOSYS
# (rather than EPERM) lets glibc fall back to the classic clone/mount paths
# instead of treating the call as a hard failure.
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

# Argument-filtered rules (generator applies these). clone's flags are arg0 on
# every architecture postern targets; ioctl's request is arg1.
CLONE_NEWUSER = 0x10000000  # block clone(CLONE_NEWUSER, ...) — the gap unshare/setns alone leave open
TIOCSTI = 0x5412  # fake terminal input (CVE-2017-5226)
TIOCLINUX = 0x541C  # ditto via the linux console ioctl

# Deliberately NOT blocked: socket / socketpair. Network isolation is the empty
# netns's job (no interface, no route); the guest needs socket(AF_UNIX) to reach
# the hatch UDS, so blocking it breaks the hatch while adding nothing.


def load_filter() -> typing.IO[bytes]:
    """Load the prebuilt BPF denylist into an open temp file positioned at 0.

    The caller passes its fd to ``bwrap --seccomp`` and keeps it open for the
    child's lifetime, then closes it. Raises if the blob is missing from the
    install (a packaging error — fail loudly rather than run unfiltered).
    """
    data = importlib.resources.files('postern').joinpath(_BPF_RESOURCE).read_bytes()
    if not data:
        raise RuntimeError(f'seccomp filter {_BPF_RESOURCE!r} is missing or empty; the postern install is broken')
    f = tempfile.TemporaryFile()  # noqa: SIM115 — returned open; caller passes its fd to bwrap and closes it
    f.write(data)
    f.flush()
    f.seek(0)
    return f
