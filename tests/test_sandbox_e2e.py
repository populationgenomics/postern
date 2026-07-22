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
    code = 'data = open("/proc/1/environ", "rb").read()\nprint("LEAK" if b"SECRET" in data else "clean")\n'
    result = Sandbox().run_python(code)
    assert result.ok, result.stderr
    assert result.stdout.strip() == 'clean'


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
