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
