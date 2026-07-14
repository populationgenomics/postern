import pathlib

from postern._sandbox import SandboxProfile, build_base_argv


def test_hardened_flags_present():
    argv = build_base_argv(SandboxProfile(), seccomp_fd=None)
    for flag in ('--unshare-all', '--new-session', '--cap-drop', 'ALL', '--die-with-parent', '--clearenv'):
        assert flag in argv
    assert argv[argv.index('/usr') - 1] == '--ro-bind'


def test_ephemeral_workspace_is_tmpfs():
    argv = build_base_argv(SandboxProfile(workspace=None), seccomp_fd=None)
    assert '--tmpfs' in argv
    assert '/workspace' in argv
    assert '--bind' not in argv  # no host directory is bound writable


def test_non_root_guest_uid_gid_by_default():
    argv = build_base_argv(SandboxProfile(), seccomp_fd=None)
    assert argv[argv.index('--uid') + 1] == '65534'
    assert argv[argv.index('--gid') + 1] == '65534'


def test_guest_uid_none_leaves_uid_unset():
    argv = build_base_argv(SandboxProfile(guest_uid=None, guest_gid=None), seccomp_fd=None)
    assert '--uid' not in argv
    assert '--gid' not in argv


def test_tmp_and_ephemeral_workspace_are_world_writable():
    # A non-root guest needs a writable /tmp and cwd; --perms 1777 precedes each.
    argv = build_base_argv(SandboxProfile(workspace=None), seccomp_fd=None)
    assert argv[argv.index('/tmp') - 1] == '--tmpfs'  # noqa: S108
    assert argv[argv.index('/tmp') - 2] == '1777'  # noqa: S108
    assert argv[argv.index('/workspace') - 1] == '--tmpfs'
    assert argv[argv.index('/workspace') - 2] == '1777'


def test_bound_workspace(tmp_path):
    argv = build_base_argv(SandboxProfile(workspace=tmp_path), seccomp_fd=None)
    assert '--bind' in argv
    assert str(tmp_path) in argv


def test_seccomp_fd_wired():
    argv = build_base_argv(SandboxProfile(), seccomp_fd=7)
    assert argv[argv.index('--seccomp') + 1] == '7'


def test_no_etc_or_home_bind_by_default():
    argv = build_base_argv(SandboxProfile(), seccomp_fd=None)
    # Only /etc/ld.so.cache is exposed, never /etc wholesale or /home/root.
    assert '/etc' not in argv
    assert '/home' not in argv
    assert '/root' not in argv


def test_rootfs_prefixes_system_dirs():
    argv = build_base_argv(SandboxProfile(rootfs=pathlib.Path('/opt/guest-root')), seccomp_fd=None)
    i = argv.index('/opt/guest-root/usr')
    assert argv[i - 1] == '--ro-bind'  # bound from the rootfs
    assert argv[i + 1] == '/usr'  # mapped to the guest's /usr
    assert '/opt/guest-root/bin' in argv  # the rest of the base too


def test_with_venv_binds_and_sets_python(tmp_path):
    venv = tmp_path / 'env'
    (venv / 'bin').mkdir(parents=True)
    profile = SandboxProfile.with_venv(venv)
    assert profile.python == str(venv.resolve() / 'bin' / 'python')
    argv = build_base_argv(profile, seccomp_fd=None)
    assert str(venv.resolve()) in argv  # the venv is bound read-only


def test_stubs_dir_bound_and_on_pythonpath():
    argv = build_base_argv(SandboxProfile(stubs='/srv/stubs'), seccomp_fd=None)
    i = argv.index('/srv/stubs')
    assert argv[i - 1] == '--ro-bind'
    assert argv[i + 1] == '/run/postern/stubs'
    assert argv[argv.index('PYTHONPATH') + 1] == '/run/postern/stubs'


def test_stubs_files_bound_individually():
    argv = build_base_argv(SandboxProfile(stubs=['/a/greeter_pb2.py', '/a/greeter_pb2_grpc.py']), seccomp_fd=None)
    assert '/run/postern/stubs/greeter_pb2.py' in argv
    assert '/run/postern/stubs/greeter_pb2_grpc.py' in argv
    assert argv[argv.index('PYTHONPATH') + 1] == '/run/postern/stubs'


def test_stubs_pythonpath_prepends_existing():
    profile = SandboxProfile(stubs='/srv/stubs', env={'PATH': '/usr/bin', 'PYTHONPATH': '/extra'})
    argv = build_base_argv(profile, seccomp_fd=None)
    assert argv[argv.index('PYTHONPATH') + 1] == '/run/postern/stubs:/extra'
