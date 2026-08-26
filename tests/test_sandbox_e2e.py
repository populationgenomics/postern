"""End-to-end sandbox tests — require Linux + bubblewrap, skipped elsewhere.

These cover the sealed sandbox: no hatch is configured, so what is under test is
the wall itself. The hatch paths are covered by ``test_hatch_e2e`` and
``test_stream_e2e``.
"""

import pytest

from postern import IsolationError, Sandbox, SandboxProfile, available

pytestmark = pytest.mark.skipif(not available(), reason='requires Linux + bubblewrap')


def test_run_python_sealed():
    result = Sandbox().run_python('print(2 + 2)')
    assert result.ok
    assert result.stdout.strip() == '4'


def test_run_python_propagates_exit_status():
    # The status has to survive the re-exec, the fork and the reap.
    result = Sandbox().run_python('import sys; sys.exit(7)')
    assert result.returncode == 7


def test_run_arbitrary_argv():
    result = Sandbox().run(['echo', 'argv-works'])
    assert result.ok, result.stderr
    assert result.stdout.strip() == 'argv-works'


def test_run_bash():
    result = Sandbox().run_bash('echo supervised')
    assert result.ok, result.stderr
    assert result.stdout.strip() == 'supervised'


def test_run_bash_inherits_rlimit_nproc():
    # The cap is set before the exec, so bash carries it across.
    result = Sandbox(SandboxProfile(rlimit_nproc=8)).run_bash('ulimit -u')
    assert result.ok, result.stderr
    assert result.stdout.strip() == '8'


def test_run_missing_program_is_127():
    result = Sandbox().run(['definitely-not-a-program'])
    assert result.returncode == 127
    assert 'cannot exec' in result.stderr


def test_run_python_address_space_limit_does_not_break_startup():
    # RLIMIT_AS lands after the re-exec'd interpreter is up: a fresh CPython's
    # virtual size at startup would trip a cap applied before the execvp.
    result = Sandbox(SandboxProfile(rlimit_as=1024 * 1024 * 1024)).run_python('print(sum(range(1000)))')
    assert result.ok, result.stderr
    assert result.stdout.strip() == '499500'


def test_seccomp_blocks_unshare():
    # unshare(CLONE_NEWUSER) needs no capability, so --cap-drop ALL would let it
    # through; only the seccomp filter stops it.
    code = (
        'import ctypes\n'
        'libc = ctypes.CDLL(None, use_errno=True)\n'
        'rc = libc.unshare(0x10000000)  # CLONE_NEWUSER\n'
        "print('rc', rc, 'errno', ctypes.get_errno())\n"
    )
    result = Sandbox().run_python(code)
    assert result.ok, result.stderr
    assert 'rc -1 errno 1' in result.stdout  # EPERM


def test_seccomp_disabled_lets_unshare_through():
    # The negative control for the test above: with seccomp off the call succeeds.
    code = "import ctypes\nlibc = ctypes.CDLL(None, use_errno=True)\nprint('rc', libc.unshare(0x10000000))\n"
    result = Sandbox(SandboxProfile(seccomp=False)).run_python(code)
    assert result.ok, result.stderr
    assert 'rc 0' in result.stdout


def test_network_is_denied():
    # A socket can be created (needed for the hatch UDS), but the empty netns
    # has no route, so an outbound connection cannot succeed.
    code = (
        'import socket\n'
        'try:\n'
        '    socket.create_connection(("1.1.1.1", 443), timeout=3); print("CONNECTED")\n'
        'except OSError as e:\n'
        '    print("no-egress", e.errno)\n'
    )
    result = Sandbox().run_python(code)
    assert result.ok
    assert 'CONNECTED' not in result.stdout
    assert 'no-egress' in result.stdout


def test_bwrap_pid1_environ_holds_no_host_secrets(monkeypatch):
    # --clearenv scrubs the guest's environment, not bwrap's own process image, and
    # bwrap runs at the guest uid, so a worker secret it inherited would be a
    # same-uid environ read away. Two controls cover it — bwrap_env scrubbing what
    # bwrap is exec'd with, and --as-pid-1 keeping bwrap out of the guest's PID
    # namespace so /proc/1 is the shim's own non-dumpable init. Either is "clean".
    monkeypatch.setenv('WORKER_SESSION_TOKEN', 'worker-SECRET-should-not-leak')
    code = (
        'try:\n'
        '    data = open("/proc/1/environ", "rb").read()\n'
        '    print("LEAK" if b"SECRET" in data else "clean")\n'
        'except OSError:\n'
        "    print('clean')  # /proc/1 not even readable\n"
    )
    result = Sandbox().run_python(code)
    assert result.ok, result.stderr
    assert result.stdout.strip() == 'clean'


def test_pid1_is_the_guest_entrypoint_not_bwrap():
    # --as-pid-1 runs the shim as PID 1; the shim then forks the work.
    result = Sandbox().run_python('import os; print(os.getpid(), open("/proc/1/comm").read().strip())')
    assert result.ok, result.stderr
    pid, comm = result.stdout.split()
    assert pid != '1'
    assert comm != 'bwrap'


def test_init_pid1_is_non_dumpable():
    # The init marks itself non-dumpable, so the co-uid guest cannot read its
    # /proc/1 memory, environ or maps.
    code = (
        'import os\n'
        'try:\n'
        '    open("/proc/1/environ", "rb").read(); print("READABLE")\n'
        'except OSError as e:\n'
        '    print("blocked", os.strerror(e.errno))\n'
    )
    result = Sandbox().run_python(code)
    assert result.ok, result.stderr
    assert result.stdout.startswith('blocked')


def test_guest_runs_as_non_root_by_default():
    result = Sandbox().run_python('import os; print(os.getuid(), os.getgid())')
    assert result.ok, result.stderr
    assert result.stdout.strip() == '65534 65534'  # nobody, not uid 0 in the userns


def test_verify_passes_on_the_hardened_profile():
    Sandbox().verify()


def test_verify_fails_closed_without_seccomp():
    with pytest.raises(IsolationError, match='seccomp'):
        Sandbox(SandboxProfile(seccomp=False)).verify()


def test_rlimit_as_caps_guest_memory():
    # A 256 MiB address-space cap makes a larger allocation fail inside the guest.
    profile = SandboxProfile(rlimit_as=256 * 1024 * 1024)
    code = (
        'try:\n'
        "    b = bytearray(512 * 1024 * 1024); print('ALLOCATED', len(b))\n"
        'except MemoryError:\n'
        "    print('capped')\n"
    )
    result = Sandbox(profile).run_python(code)
    assert result.ok, result.stderr
    assert 'capped' in result.stdout
    assert 'ALLOCATED' not in result.stdout


def test_host_filesystem_not_visible():
    result = Sandbox().run_python("open('/etc/passwd').read()")
    assert not result.ok  # /etc is not bound into the guest


def test_workspace_is_writable():
    result = Sandbox().run_python("open('/workspace/x', 'w').write('ok'); print(open('/workspace/x').read())")
    assert result.ok
    assert result.stdout.strip() == 'ok'


def test_workspace_persists_across_calls_and_is_host_readable(tmp_path):
    sandbox = Sandbox(SandboxProfile(workspace=tmp_path / 'ws'))
    # cwd is /workspace, so the relative write lands there.
    assert sandbox.run_python("open('note.txt', 'w').write('hello')").ok
    second = sandbox.run_python("print(open('note.txt').read())")
    assert second.ok
    assert second.stdout.strip() == 'hello'
    assert (sandbox.workspace / 'note.txt').read_text() == 'hello'
    sandbox.close()
