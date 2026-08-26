"""End-to-end: sealed sandbox + stream hatch, reached from both entrypoints.

Where ``test_stream_hatch`` covers the hatch, this covers the *wiring*: the socket
arrives inside the jail under its name, a guest with no network reaches it and
nothing else, and a **bare argv** entrypoint gets the capability, not just guest
Python. The clone is a real ``git clone`` inside bubblewrap against a real ``git
upload-pack`` on the host.

Requires Linux + bubblewrap (skipped elsewhere); the git tests additionally need git
on the host, which the default profile binds read-only into the guest.
"""

import os
import shutil
import subprocess

import pytest

from postern import Sandbox, SandboxProfile, available
from postern.stream import StreamHatch, git_url, splice_subprocess

pytestmark = pytest.mark.skipif(not available(), reason='requires Linux + bubblewrap')

requires_git = pytest.mark.skipif(shutil.which('git') is None, reason='requires git')

_GIT_ENV = {
    'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
    'GIT_AUTHOR_NAME': 'postern',
    'GIT_AUTHOR_EMAIL': 'postern@example.invalid',
    'GIT_COMMITTER_NAME': 'postern',
    'GIT_COMMITTER_EMAIL': 'postern@example.invalid',
    'GIT_CONFIG_GLOBAL': '/dev/null',
    'GIT_CONFIG_SYSTEM': '/dev/null',
}

# Guest code: the hatch is a plain file at $POSTERN_HATCH_ECHO, so reaching it is
# connect + sendall + read — no relay, no client library, no protocol.
_GUEST = """
import os, socket
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(os.environ['POSTERN_HATCH_ECHO'])
sock.sendall(b'ping from the guest')
sock.shutdown(socket.SHUT_WR)
chunks = []
while (chunk := sock.recv(65536)):
    chunks.append(chunk)
print('STREAM', b''.join(chunks).decode())
"""


def _git(*args, cwd=None):
    return subprocess.run(['git', *args], cwd=cwd, env=_GIT_ENV, capture_output=True, text=True, check=True)


@pytest.fixture
def origin_repo(tmp_path):
    repo = tmp_path / 'origin'
    repo.mkdir()
    _git('init', '-q', '-b', 'main', cwd=repo)
    (repo / 'hello.txt').write_text('cloned through the hatch\n')
    _git('add', 'hello.txt', cwd=repo)
    _git('commit', '-qm', 'initial', cwd=repo)
    return repo


def test_guest_python_reaches_a_named_stream_hatch():
    hatch = StreamHatch(splice_subprocess(['cat']), name='echo')
    result = Sandbox(SandboxProfile(), hatch=hatch).run_python(_GUEST)
    hatch.close()
    assert result.ok, result.stderr
    assert 'STREAM ping from the guest' in result.stdout


def test_guest_has_no_network_but_still_reaches_the_stream_hatch():
    hatch = StreamHatch(splice_subprocess(['cat']), name='echo')
    code = (
        'import socket\n'
        'try:\n'
        '    socket.create_connection(("1.1.1.1", 443), timeout=3); print("EGRESS")\n'
        'except OSError:\n'
        "    print('no-egress')\n" + _GUEST
    )
    result = Sandbox(SandboxProfile(), hatch=hatch).run_python(code)
    hatch.close()
    assert result.ok, result.stderr
    assert 'no-egress' in result.stdout
    assert 'EGRESS' not in result.stdout
    assert 'STREAM ping from the guest' in result.stdout


@requires_git
def test_bare_argv_entrypoint_clones_through_the_hatch(origin_repo):
    # `git` is the entrypoint: no shim, nothing in-guest to relay through, and the
    # clone works because the hatch is a file the guest opens.
    hatch = StreamHatch(splice_subprocess(['git', 'upload-pack', str(origin_repo)]), name='repo')
    sandbox = Sandbox(SandboxProfile(), hatch=hatch)
    result = sandbox.run(
        [
            'git',
            '-c',
            'protocol.ext.allow=always',
            'clone',
            '-q',
            git_url('repo'),
            '/workspace/clone',
        ],
        timeout=180,
    )
    hatch.close()
    assert result.ok, f'{result.returncode}: {result.stderr}'
    with sandbox.accessor() as workspace:
        assert (workspace / 'clone/hello.txt').read_bytes() == b'cloned through the hatch\n'
    sandbox.close()


@requires_git
@pytest.mark.usefixtures('origin_repo')
def test_a_bare_entrypoint_without_the_hatch_reaches_nothing():
    # The control for the test above: the same argv with no hatch configured has
    # no socket to open, so the clone fails rather than quietly finding a route.
    sandbox = Sandbox(SandboxProfile())
    result = sandbox.run(
        ['git', '-c', 'protocol.ext.allow=always', 'clone', '-q', git_url('repo'), '/workspace/clone'],
        timeout=120,
    )
    sandbox.close()
    assert not result.ok


# Guest code: drive the bound-in connector as a *subprocess*, full duplex, with bulk
# bytes in both directions at once. This exercises `postern._stream_connect`, which
# is what the sandbox binds in and what every real guest (git included) goes
# through; a connector that stops draining its receive side while sending deadlocks
# the whole cycle.
_DUPLEX_GUEST = """
import os, subprocess, sys, threading

payload = %(size)d
connector = os.environ['POSTERN_CONNECT']
sock = os.environ['POSTERN_HATCH_DUPLEX']

proc = subprocess.Popen(
    [sys.executable, connector, sock],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
)
got = bytearray()

def read():
    while True:
        chunk = proc.stdout.read(65536)
        if not chunk:
            break
        got.extend(chunk)

def write():
    block = b'Q' * 65536
    try:
        for _ in range(payload // 65536):
            proc.stdin.write(block)
        proc.stdin.flush()
        proc.stdin.close()
    except OSError:
        pass

reader = threading.Thread(target=read); reader.start()
writer = threading.Thread(target=write); writer.start()
writer.join(180); reader.join(180)
proc.wait(60)
print('ECHOED', len(got), 'OF', payload)
"""


def test_bulk_bytes_move_both_ways_through_the_bound_in_connector() -> None:
    """Full-duplex bulk through the real connector, inside the jail.

    ``cat`` rather than git: git's phases are mostly half-duplex, so a clone passing
    says nothing about the full-duplex case.
    """
    size = 64 * 1024 * 1024
    hatch = StreamHatch(splice_subprocess(['cat']), name='duplex', grace=5.0)
    try:
        sandbox = Sandbox(SandboxProfile(), hatch=hatch)
        try:
            result = sandbox.run_python(_DUPLEX_GUEST % {'size': size}, timeout=300)
        finally:
            sandbox.close()
    finally:
        hatch.close()
    assert result.ok, f'guest failed: rc={result.returncode} {result.stderr[-800:]}'
    assert f'ECHOED {size} OF {size}' in result.stdout, result.stdout[-400:]
