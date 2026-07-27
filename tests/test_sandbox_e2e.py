"""End-to-end sandbox tests — require Linux + bubblewrap, skipped elsewhere.

These cover the sealed sandbox (no hatch). The full gRPC-hatch + environment
path is exercised by the standalone example against a real venv on a Linux host.
"""

import pytest

from postern import IsolationError, Sandbox, SandboxProfile, available

pytestmark = pytest.mark.skipif(not available(), reason='requires Linux + bubblewrap')


def test_run_python_sealed():
    result = Sandbox().run_python('print(2 + 2)')
    assert result.ok
    assert result.stdout.strip() == '4'


def test_run_python_propagates_exit_status():
    # The supervisor re-execs a fresh interpreter for the code; its exit status
    # must flow back through the fork+exec+reap chain unchanged.
    result = Sandbox().run_python('import sys; sys.exit(7)')
    assert result.returncode == 7


def test_run_bash_under_supervisor():
    # A non-Python entrypoint runs in the same fork+exec shape as run_python.
    result = Sandbox().run_bash('echo supervised')
    assert result.ok, result.stderr
    assert result.stdout.strip() == 'supervised'


def test_run_arbitrary_argv_under_supervisor():
    result = Sandbox().run(['echo', 'argv-works'])
    assert result.ok, result.stderr
    assert result.stdout.strip() == 'argv-works'


def test_run_bash_inherits_rlimit_nproc():
    # The child applies RLIMIT_NPROC before exec, so bash inherits the cap across
    # the exec — a non-Python entrypoint gets the backstop without managing it.
    result = Sandbox(SandboxProfile(rlimit_nproc=8)).run_bash('ulimit -u')
    assert result.ok, result.stderr
    assert result.stdout.strip() == '8'


def test_run_python_address_space_limit_does_not_break_startup():
    # RLIMIT_AS is applied after the re-exec'd interpreter is up (not before the
    # execvp), so a cap doesn't abort CPython startup — regression guard for the
    # fork+exec model, where a fresh interpreter's virtual size is large.
    result = Sandbox(SandboxProfile(rlimit_as=1024 * 1024 * 1024)).run_python('print(sum(range(1000)))')
    assert result.ok, result.stderr
    assert result.stdout.strip() == '499500'


def test_seccomp_blocks_unshare():
    # unshare(CLONE_NEWUSER) needs no capability, so --cap-drop ALL would let it
    # through; only the seccomp filter stops it. A -1/EPERM proves the committed
    # BPF blob loaded and is enforcing on this kernel/arch.
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
    # The negative control: with seccomp off, the same call succeeds — so the
    # test above is really measuring the filter, not some other layer.
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
    # bwrap is PID 1 in the guest's PID namespace and (because --uid applies to
    # it too) runs at the guest uid, so its /proc/1/environ is a same-uid read
    # from inside the jail. --clearenv only scrubs the *guest's* env, not bwrap's
    # own image, so a secret inherited from the trusted worker would leak here.
    # The launcher must exec bwrap with a scrubbed environment.
    monkeypatch.setenv('WORKER_SESSION_TOKEN', 'worker-SECRET-should-not-leak')
    # No secret must reach the guest via PID 1 — whether because bwrap's env is
    # scrubbed or because --as-pid-1 makes PID 1 the guest's own non-dumpable init
    # (so the read is denied outright). Either outcome is "clean".
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
    # --as-pid-1 runs the shim as PID 1, so there is no separate bwrap process in
    # the namespace for the guest to read; the shim forks the guest (PID 2).
    result = Sandbox().run_python('import os; print(os.getpid(), open("/proc/1/comm").read().strip())')
    assert result.ok, result.stderr
    pid, comm = result.stdout.split()
    assert pid != '1'  # the guest is a child of the init, not PID 1 itself
    assert comm != 'bwrap'  # PID 1 is our entrypoint, not a resident bwrap reaper


def test_init_pid1_is_non_dumpable():
    # The PID 1 init marks itself non-dumpable, so a co-uid guest cannot read its
    # /proc/1 memory/environ/maps even though they share a uid.
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
    assert result.stdout.strip() == '65534 65534'  # nobody, not uid 0 in the userns (F2)


def test_verify_passes_on_the_hardened_profile():
    Sandbox().verify()  # must not raise on a correctly-configured sandbox


def test_verify_fails_closed_without_seccomp():
    # verify() is the "am I fully hardened" gate; a seccomp-disabled profile is
    # not, so it must refuse rather than let the caller serve under it.
    with pytest.raises(IsolationError, match='seccomp'):
        Sandbox(SandboxProfile(seccomp=False)).verify()


def test_rlimit_as_caps_guest_memory():
    # A 256 MiB address-space cap makes a larger allocation fail inside the
    # guest, without killing the co-located worker (F3 backstop).
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
    second = sandbox.run_python("print(open('note.txt').read())")  # a separate sandbox invocation
    assert second.ok
    assert second.stdout.strip() == 'hello'
    # the host sees it too
    assert (sandbox.workspace / 'note.txt').read_text() == 'hello'
    sandbox.close()
