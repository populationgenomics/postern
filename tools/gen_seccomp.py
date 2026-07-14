"""Compile postern's seccomp denylist to a committed multi-arch BPF blob.

Run on Linux with the libseccomp Python bindings (Debian: python3-libseccomp).
``tools/gen_seccomp.sh`` wraps this in a linux/amd64 container so it runs on any
host. The syscall lists come from ``postern._seccomp`` (the source of truth);
this script only turns them into the ``_seccomp.bpf`` the runtime loads.

Generate on amd64 so the full (x86-centric) Flatpak list resolves against the
native syscall table; the secondary architectures added below get whichever of
those syscalls exist there and silently skip the rest.
"""

from __future__ import annotations

import contextlib
import errno
import pathlib
import sys

import seccomp

_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / 'src'))

from postern import _seccomp  # import after sys.path tweak — needs the src path above

_OUT = _ROOT / 'src' / 'postern' / _seccomp._BPF_RESOURCE

# Cover the compat ABIs too (Flatpak does the same) so a blocked syscall cannot
# be reached via a different architecture's syscall table. The native arch of
# the build host is already present; adding it again is a harmless no-op.
_ARCHES = (seccomp.Arch.X86_64, seccomp.Arch.X86, seccomp.Arch.X32, seccomp.Arch.AARCH64, seccomp.Arch.ARM)


def build() -> seccomp.SyscallFilter:
    f = seccomp.SyscallFilter(defaction=seccomp.ALLOW)
    for arch in _ARCHES:
        with contextlib.suppress(ValueError, RuntimeError):
            f.add_arch(arch)  # already present (native) — fine
    for name in _seccomp.BLOCKED_EPERM:
        f.add_rule(seccomp.ERRNO(errno.EPERM), name)
    for name in _seccomp.BLOCKED_ENOSYS:
        f.add_rule(seccomp.ERRNO(errno.ENOSYS), name)
    # clone(CLONE_NEWUSER, ...) — flags is arg0 on every arch here.
    f.add_rule(
        seccomp.ERRNO(errno.EPERM),
        'clone',
        seccomp.Arg(0, seccomp.MASKED_EQ, _seccomp.CLONE_NEWUSER, _seccomp.CLONE_NEWUSER),
    )
    # ioctl request (arg1) TIOCSTI / TIOCLINUX — mask to 32 bits (64-bit callers).
    for request in (_seccomp.TIOCSTI, _seccomp.TIOCLINUX):
        f.add_rule(seccomp.ERRNO(errno.EPERM), 'ioctl', seccomp.Arg(1, seccomp.MASKED_EQ, 0xFFFFFFFF, request))
    return f


def main() -> None:
    f = build()
    with _OUT.open('wb') as out:
        f.export_bpf(out)
    print(f'wrote {_OUT.relative_to(_ROOT)} ({_OUT.stat().st_size} bytes)')


if __name__ == '__main__':
    main()
