import hashlib
import importlib.resources
import json

from postern import _seccomp


def test_load_filter_shape():
    f = _seccomp.load_filter()
    data = f.read()
    f.close()
    assert data  # the committed blob is present and non-empty
    assert len(data) % 8 == 0  # each BPF instruction is 8 bytes


def test_blocklist_covers_escape_syscalls():
    # Namespace/mount escapes plus the tracing, keyring, module and bpf syscalls.
    for name in ('unshare', 'setns', 'mount', 'pivot_root', 'chroot', 'ptrace', 'keyctl', 'bpf', 'init_module'):
        assert name in _seccomp.BLOCKED_EPERM


def test_new_mount_and_clone_apis_return_enosys():
    # ENOSYS (not EPERM) so glibc falls back to the classic paths.
    for name in ('clone3', 'fsopen', 'open_tree', 'move_mount'):
        assert name in _seccomp.BLOCKED_ENOSYS


def test_socket_not_blocked():
    # socket(AF_UNIX) is needed to reach the hatch; network isolation is the
    # empty netns's job, not seccomp's.
    assert 'socket' not in _seccomp.BLOCKED_EPERM
    assert 'socket' not in _seccomp.BLOCKED_ENOSYS


def test_committed_blob_is_not_stale():
    # Drift guard (F4): if the syscall lists change without regenerating the
    # blob, or the blob is hand-edited, the committed manifest no longer matches.
    # Dependency-free — the authoritative regenerate-and-diff runs in CI.
    manifest = json.loads(importlib.resources.files('postern').joinpath(_seccomp._SPEC_RESOURCE).read_text())
    assert manifest['source_digest'] == _seccomp.spec_digest(), (
        'seccomp syscall lists changed without regenerating _seccomp.bpf — run tools/gen_seccomp.sh'
    )
    blob = importlib.resources.files('postern').joinpath(_seccomp._BPF_RESOURCE).read_bytes()
    assert manifest['bpf_sha256'] == hashlib.sha256(blob).hexdigest(), (
        '_seccomp.bpf does not match its manifest — regenerate with tools/gen_seccomp.sh'
    )


def test_arch_is_covered_recognises_supported_and_rejects_others():
    # The blob carries programs for x86 and ARM families; anything else is a
    # default-allow no-op the caller must treat as fail-closed (F4).
    assert _seccomp.arch_is_covered('x86_64')
    assert _seccomp.arch_is_covered('AARCH64')  # case-insensitive
    assert _seccomp.arch_is_covered('armv7l')
    assert not _seccomp.arch_is_covered('mips64')
    assert not _seccomp.arch_is_covered('riscv64')
    assert not _seccomp.arch_is_covered('s390x')
