"""End-to-end sandbox tests — require Linux + bubblewrap, skipped elsewhere.

These cover the sealed sandbox (no hatch). The full gRPC-hatch + environment
path is exercised by the standalone example against a real venv on a Linux host.
"""

import pytest

from postern import Sandbox, SandboxProfile, available

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
