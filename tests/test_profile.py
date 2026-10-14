import pathlib

from postern._sandbox import SandboxProfile, build_base_argv, bwrap_credentials


def test_hardened_flags_present():
    argv = build_base_argv(SandboxProfile(), seccomp_fd=None)
    for flag in ('--unshare-all', '--new-session', '--cap-drop', 'ALL', '--die-with-parent', '--clearenv'):
        assert flag in argv
    assert argv[argv.index('/usr') - 1] == '--ro-bind'


def test_user_and_cgroup_namespaces_are_strict():
    # Explicit --unshare-user/--unshare-cgroup upgrade --unshare-all's best-effort
    # -try variants, so a missing user namespace is a launch failure rather than a
    # silent fall-through to a real-root guest.
    argv = build_base_argv(SandboxProfile(), seccomp_fd=None)
    assert '--unshare-user' in argv
    assert '--unshare-cgroup' in argv


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


def test_proc_sysctl_surface_masked_read_only():
    # bwrap's fresh --proc re-exposes /proc/sys writable; a guest whose kernel uid
    # maps to root then owns the global sysctls and escapes by writing
    # core_pattern. The mask must be a read-only self-bind applied *after* --proc.
    argv = build_base_argv(SandboxProfile(), seccomp_fd=None)
    proc_at = argv.index('/proc')
    for path in ('/proc/sys', '/proc/sysrq-trigger', '/proc/kcore'):
        i = argv.index(path)
        assert argv[i - 1] == '--ro-bind-try'
        assert argv[i + 1] == path  # bound over itself, read-only
        assert i > proc_at  # layered on top of the fresh procfs, not before it


def test_bwrap_credentials_no_drop_by_default():
    # host_uid unset: no privilege drop, at either euid.
    assert bwrap_credentials(SandboxProfile(), euid=0) == {}
    assert bwrap_credentials(SandboxProfile(), euid=1000) == {}


def test_bwrap_credentials_opt_in_when_root():
    # host_uid set + we are root: run bwrap non-root, dropping supplementary groups.
    creds = bwrap_credentials(SandboxProfile(host_uid=65534), euid=0)
    assert creds == {'user': 65534, 'group': 65534, 'extra_groups': []}  # gid from guest_gid
    creds = bwrap_credentials(SandboxProfile(host_uid=100000, host_gid=100000, guest_gid=65534), euid=0)
    assert creds == {'user': 100000, 'group': 100000, 'extra_groups': []}  # host_gid wins


def test_bwrap_credentials_ignored_when_not_root():
    # Cannot setuid unless root; bwrap then runs at our (already non-root) uid.
    assert bwrap_credentials(SandboxProfile(host_uid=65534), euid=1000) == {}


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


def test_optional_ro_bind_is_try():
    argv = build_base_argv(SandboxProfile(ro_binds=[('/host/opt', '/opt')]), seccomp_fd=None)
    i = argv.index('/host/opt')
    assert argv[i - 1] == '--ro-bind-try'  # missing source skipped silently
    assert argv[i + 1] == '/opt'


def test_required_ro_bind_is_strict():
    # A required bind maps to --ro-bind, so a missing source fails the launch
    # instead of being skipped and surfacing later as an in-guest ENOENT.
    argv = build_base_argv(SandboxProfile(required_ro_binds=[('/host/tools', '/tools')]), seccomp_fd=None)
    i = argv.index('/host/tools')
    assert argv[i - 1] == '--ro-bind'
    assert argv[i + 1] == '/tools'


def test_with_venv_binds_and_sets_python(tmp_path):
    venv = tmp_path / 'env'
    (venv / 'bin').mkdir(parents=True)
    profile = SandboxProfile.with_venv(venv)
    assert profile.python == str(venv.resolve() / 'bin' / 'python')
    argv = build_base_argv(profile, seccomp_fd=None)
    i = argv.index(str(venv.resolve()))
    assert argv[i - 1] == '--ro-bind'  # strict: a missing venv fails the launch


def test_with_venv_extends_required_ro_binds(tmp_path):
    venv = tmp_path / 'env'
    (venv / 'bin').mkdir(parents=True)
    profile = SandboxProfile.with_venv(venv, required_ro_binds=[('/host/tools', '/tools')])
    assert ('/host/tools', '/tools') in profile.required_ro_binds
    assert (str(venv.resolve()), str(venv.resolve())) in profile.required_ro_binds


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
