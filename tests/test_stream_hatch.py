"""The socket is the capability — test the core splice plus the shipped batteries.

Exercises the host-side hatch over its UDS, speaking exactly what a guest would:
raw bytes, both directions, nothing else. No bubblewrap needed — this tests the
hatch server, not the sandbox — which means the motivating case (a real ``git
clone`` reaching a real ``git upload-pack`` over the hatch, via the same in-guest
connector the sandbox binds in) is covered here too, on any platform with git.
"""

import contextlib
import os
import pathlib
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time

import pytest

from postern._sandbox import _CONNECT_SRC
from postern.stream import (
    Process,
    Stream,
    StreamHatch,
    git_url,
    splice_subprocess,
)

_DEADLINE = 10.0


@contextlib.contextmanager
def _serving(hatch):
    """Serve ``hatch`` for the block and always close it (it owns a temp dir)."""
    try:
        with hatch.accepting():
            yield hatch
    finally:
        hatch.close()


def _dial(hatch, timeout=_DEADLINE):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect(hatch.socket_path)
    return sock


def _recv_all(sock):
    raw = b''
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        raw += chunk
    sock.close()
    return raw


def _exchange(hatch, payload):
    """Send ``payload``, half-close, and read everything the host sends back.

    Sends on a second thread and reads on this one, because a stream is genuinely
    bidirectional: a test that wrote everything before reading would wedge on its
    own socket buffers as soon as the payload outgrew them (as a real client such
    as git never does, since it interleaves).
    """
    sock = _dial(hatch, timeout=_DEADLINE * 3)

    def send():
        with contextlib.suppress(OSError):
            sock.sendall(payload)
            sock.shutdown(socket.SHUT_WR)

    sender = threading.Thread(target=send, daemon=True)
    sender.start()
    raw = _recv_all(sock)
    sender.join(_DEADLINE)
    return raw


def _until(predicate, deadline=_DEADLINE):
    end = time.monotonic() + deadline
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.02)
    return False


# -- batteries: a subprocess's stdio ---------------------------------------- #
def test_subprocess_stdio_is_spliced_both_ways():
    with _serving(StreamHatch(splice_subprocess(['cat']))) as hatch:
        assert _exchange(hatch, b'round trip') == b'round trip'


def test_large_payload_streams_without_a_ceiling():
    # No body buffering anywhere on this path: 8 MiB through `cat` with no cap
    # configured (a proxy that let a handler inspect bodies would have had to
    # buffer it, and so would have had to cap it).
    payload = os.urandom(8 * 1024 * 1024)
    with _serving(StreamHatch(splice_subprocess(['cat']))) as hatch:
        assert _exchange(hatch, payload) == payload


def test_subprocess_environment_is_scrubbed_not_inherited(monkeypatch):
    # The subprocess is the thing chewing on guest bytes, so it must not inherit
    # the trusted worker's environment (where the secrets the hatch exists to
    # withhold live). PATH survives so a bare argv still resolves.
    monkeypatch.setenv('POSTERN_TEST_SECRET', 'do-not-leak')
    with _serving(StreamHatch(splice_subprocess(['env']))) as hatch:
        received = _exchange(hatch, b'')
    assert b'do-not-leak' not in received
    assert b'PATH=' in received


def test_explicit_environment_is_passed_through():
    handler = splice_subprocess(['env'], env={'MARKER': 'set-by-host'})
    with _serving(StreamHatch(handler)) as hatch:
        assert b'MARKER=set-by-host' in _exchange(hatch, b'')


def test_subprocess_stderr_is_not_merged_into_the_stream():
    # A command's diagnostics quote host paths, so relaying them would map the
    # host filesystem for the guest. Only stdout is the stream.
    handler = splice_subprocess(['sh', '-c', 'echo on-stdout; echo /srv/secret >&2'])
    with _serving(StreamHatch(handler)) as hatch:
        received = _exchange(hatch, b'')
    assert received.strip() == b'on-stdout'
    assert b'/srv/secret' not in received


def test_cwd_is_honoured(tmp_path):
    (tmp_path / 'marker').write_text('here\n')
    handler = splice_subprocess(['cat', 'marker'], cwd=tmp_path)
    with _serving(StreamHatch(handler)) as hatch:
        assert _exchange(hatch, b'') == b'here\n'


# -- core: the handler is the policy ---------------------------------------- #
def test_handler_refusal_closes_with_no_bytes():
    with _serving(StreamHatch(lambda _stream: None)) as hatch:
        assert _exchange(hatch, b'let me in') == b''


def test_handler_sees_the_hatch_name():
    seen = []

    def handler(stream):
        seen.append((stream.hatch, isinstance(stream, Stream)))
        # No verdict: an implicit None is the refusal.

    with _serving(StreamHatch(handler, name='repo_one')) as hatch:
        _exchange(hatch, b'')
    assert seen == [('repo_one', True)]


def test_handler_may_write_a_preamble_on_the_raw_connection():
    # The raw conn is reachable for a banner/preamble, even though policy that
    # parses guest bytes is what a per-resource socket exists to avoid.
    def handler(stream):
        stream.conn.sendall(b'postern/1 ')
        return splice_subprocess(['cat'])(stream)

    with _serving(StreamHatch(handler)) as hatch:
        assert _exchange(hatch, b'body') == b'postern/1 body'


def test_a_raising_handler_does_not_poison_the_hatch():
    calls = []

    def handler(stream):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError('boom')
        return splice_subprocess(['cat'])(stream)

    with _serving(StreamHatch(handler)) as hatch:
        assert _exchange(hatch, b'first') == b''  # contained to its own connection
        assert _exchange(hatch, b'second') == b'second'  # slot was released


# -- resource limits: max_conns gates accepting, not just dispatch ---------- #
def test_max_conns_stops_accepting_rather_than_queueing_fds():
    started = threading.Semaphore(0)
    release = threading.Event()

    def handler(_stream):
        started.release()
        release.wait(_DEADLINE)  # hold the slot, then refuse (implicit None)

    with _serving(StreamHatch(handler, max_conns=1)) as hatch:
        first = _dial(hatch)
        assert started.acquire(timeout=_DEADLINE)  # the one slot is in use
        second = _dial(hatch)  # accepted by the kernel backlog, not by us
        assert not started.acquire(timeout=0.5)  # no second handler runs
        release.set()
        assert started.acquire(timeout=_DEADLINE)  # freed slot picks it up
        first.close()
        second.close()


# -- abrupt guest death ------------------------------------------------------ #
def test_guest_reset_mid_splice_reaps_the_subprocess_and_frees_the_slot():
    procs = []
    base = splice_subprocess(['cat'])

    def handler(stream):
        verdict = base(stream)
        assert isinstance(verdict, Process)
        procs.append(verdict.proc)
        return verdict

    with _serving(StreamHatch(handler, max_conns=1, grace=1.0)) as hatch:
        sock = _dial(hatch)
        sock.sendall(b'half a request')
        assert _until(lambda: bool(procs))
        # RST rather than a clean FIN: the guest was killed, not closed.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        sock.close()
        assert _until(lambda: procs[0].poll() is not None)  # no host process left running
        assert _exchange(hatch, b'after') == b'after'  # the single slot came back


def test_subprocess_that_ignores_stdin_eof_is_terminated_at_teardown():
    # The handler's contract is that the command exits on stdin EOF. One that does
    # not owns its connection for as long as it runs — with the socket as its stdio
    # there is no separate signal to notice, which is deliberate: the old pump
    # guessed the exchange was over when stdout closed, and guessing wrong is what
    # truncated responses. So `close()` is what ends it, via terminate-then-kill.
    procs = []
    base = splice_subprocess(['sh', '-c', 'exec sleep 60'])

    def handler(stream):
        verdict = base(stream)
        assert isinstance(verdict, Process)
        procs.append(verdict.proc)
        return verdict

    hatch = StreamHatch(handler, grace=1.0)
    hatch.start()
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.settimeout(_DEADLINE)
    conn.connect(hatch.socket_path)
    try:
        assert _until(lambda: bool(procs))
        assert procs[0].poll() is None  # still running: nothing has ended it
        hatch.close()
        assert _until(lambda: procs[0].poll() is not None)
        assert procs[0].returncode != 0  # signalled, not a clean exit
    finally:
        conn.close()
        hatch.close()


# -- lifecycle -------------------------------------------------------------- #
def test_socket_perms_are_deterministic_and_guest_connectable():
    hatch = StreamHatch(lambda _stream: None)
    with _serving(hatch):
        mode = stat.S_IMODE(os.stat(hatch.socket_path).st_mode)
        assert mode == 0o666  # non-root guest must connect; not umask-dependent
        parent = stat.S_IMODE(os.stat(os.path.dirname(hatch.socket_path)).st_mode)
        assert parent == 0o700  # mkdtemp default keeps other host users out


def test_hatch_reused_across_calls():
    hatch = StreamHatch(splice_subprocess(['cat']))
    try:
        with hatch.accepting():
            assert _exchange(hatch, b'one') == b'one'
        with hatch.accepting():
            assert _exchange(hatch, b'two') == b'two'
    finally:
        hatch.close()


def test_host_socket_paths_are_unique_per_instance():
    a, b = StreamHatch(lambda _s: None), StreamHatch(lambda _s: None)
    try:
        assert a.socket_path != b.socket_path
    finally:
        a.close()
        b.close()


def test_stale_socket_from_a_crashed_run_is_replaced():
    # tempfile, not pytest's tmp_path: AF_UNIX paths are capped at ~104 bytes and
    # a per-test tmp_path blows through that on macOS.
    path = pathlib.Path(tempfile.mkdtemp()) / 'hatch.sock'
    # What a crashed run actually leaves: a bound socket file with nobody
    # listening. (A *live* socket at a caller-supplied path is deliberately not
    # replaced — see test_a_caller_supplied_socket_path_is_never_unlinked_unbound.)
    stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale.bind(str(path))
    stale.close()
    assert path.exists()
    hatch = StreamHatch(splice_subprocess(['cat']), socket_path=path)
    with _serving(hatch):
        assert _exchange(hatch, b'ok') == b'ok'


# -- names: the capability's identity in the guest -------------------------- #
def test_guest_name_and_env_var_are_derived_from_the_name():
    hatch = StreamHatch(lambda _s: None, name='repo')
    try:
        assert hatch.guest_name == 'repo'
        assert hatch.guest_env_var == 'POSTERN_HATCH_REPO'
    finally:
        hatch.close()


@pytest.mark.parametrize('name', ['', 'has-dash', '../escape', 'a/b', '1st', 'with space'])
def test_unusable_names_are_refused_at_construction(name):
    with pytest.raises(ValueError, match='identifier'):
        StreamHatch(lambda _s: None, name=name)


def test_git_url_names_the_connector_and_the_guest_socket():
    url = git_url('repo')
    assert url.startswith('ext::python3 /run/postern/connect.py /run/postern/repo.sock')
    assert git_url() == 'ext::python3 /run/postern/connect.py /run/postern/stream.sock'


# -- the motivating case: a real clone over the hatch ----------------------- #
_GIT_ENV = {
    'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
    'GIT_AUTHOR_NAME': 'postern',
    'GIT_AUTHOR_EMAIL': 'postern@example.invalid',
    'GIT_COMMITTER_NAME': 'postern',
    'GIT_COMMITTER_EMAIL': 'postern@example.invalid',
    # Ignore whatever the developer's own git config says, so the test is the
    # same everywhere (and so `protocol.ext.allow` is genuinely off by default).
    'GIT_CONFIG_GLOBAL': '/dev/null',
    'GIT_CONFIG_SYSTEM': '/dev/null',
}
_GIT_EXT = ['-c', 'protocol.ext.allow=always']

pytest_git = pytest.mark.skipif(not __import__('shutil').which('git'), reason='requires git')


def _git(*args, cwd=None):
    return subprocess.run(['git', *args], cwd=cwd, env=_GIT_ENV, capture_output=True, text=True, check=True)


@pytest.fixture
def origin_repo(tmp_path):
    """A real repository on the host, standing in for the one resource granted."""
    repo = tmp_path / 'origin'
    repo.mkdir()
    _git('init', '-q', '-b', 'main', cwd=repo)
    (repo / 'hello.txt').write_text('from the hatch\n')
    _git('add', 'hello.txt', cwd=repo)
    _git('commit', '-qm', 'initial', cwd=repo)
    return repo


def _ext_url(hatch):
    """The ``ext::`` URL for a host-side test: the real connector, the real socket."""
    return f'ext::{sys.executable} {pathlib.Path(_CONNECT_SRC).resolve()} {hatch.socket_path}'


@pytest_git
@pytest.mark.parametrize('version', ['0', '2'])
def test_git_clone_succeeds_over_the_hatch(origin_repo, tmp_path, version):
    # The whole point, end to end: git's native pkt-line protocol over a raw
    # bidirectional stream, spliced to a real `git upload-pack`. Both wire
    # protocol versions, since v2 negotiates differently.
    hatch = StreamHatch(splice_subprocess(['git', 'upload-pack', str(origin_repo)]), name='repo')
    dest = tmp_path / f'clone{version}'
    with _serving(hatch):
        _git(*_GIT_EXT, '-c', f'protocol.version={version}', 'clone', '-q', _ext_url(hatch), str(dest))
    assert (dest / 'hello.txt').read_text() == 'from the hatch\n'


@pytest_git
def test_upload_pack_hatch_cannot_be_talked_into_a_push(origin_repo, tmp_path):
    # Read-only by construction: the service is part of the argv the host fixed,
    # so there is no verb for the guest to change and no path to validate.
    hatch = StreamHatch(splice_subprocess(['git', 'upload-pack', str(origin_repo)]), name='repo')
    work = tmp_path / 'work'
    with _serving(hatch):
        url = _ext_url(hatch)
        _git(*_GIT_EXT, 'clone', '-q', url, str(work))
        (work / 'new.txt').write_text('pushed\n')
        _git('add', 'new.txt', cwd=work)
        _git('commit', '-qm', 'second', cwd=work)
        pushed = subprocess.run(
            ['git', *_GIT_EXT, 'push', url, 'main'],
            cwd=work,
            env=_GIT_ENV,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    assert pushed.returncode != 0
    assert not (origin_repo / 'new.txt').exists()  # the origin never took the write


@pytest_git
def test_two_named_hatches_are_two_separate_capabilities(origin_repo, tmp_path):
    # One socket per resource is the security story: a guest holding the socket
    # for `open` has no way to name `closed`, because naming happens host-side.
    closed = tmp_path / 'closed'
    closed.mkdir()
    _git('init', '-q', '-b', 'main', cwd=closed)
    (closed / 'secret.txt').write_text('not for the guest\n')
    _git('add', 'secret.txt', cwd=closed)
    _git('commit', '-qm', 'secret', cwd=closed)

    open_hatch = StreamHatch(splice_subprocess(['git', 'upload-pack', str(origin_repo)]), name='open')
    closed_hatch = StreamHatch(splice_subprocess(['git', 'upload-pack', str(closed)]), name='closed')
    with _serving(open_hatch), _serving(closed_hatch):
        assert open_hatch.socket_path != closed_hatch.socket_path
        _git(*_GIT_EXT, 'clone', '-q', _ext_url(open_hatch), str(tmp_path / 'from-open'))
    assert (tmp_path / 'from-open' / 'hello.txt').exists()
    assert not (tmp_path / 'from-open' / 'secret.txt').exists()


# -- the in-guest connector -------------------------------------------------- #
def test_connector_reports_an_unreachable_hatch_without_a_traceback(tmp_path):
    result = subprocess.run(
        [sys.executable, _CONNECT_SRC, str(tmp_path / 'absent.sock')],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 1
    assert 'cannot reach the hatch' in result.stderr
    assert 'Traceback' not in result.stderr


def test_connector_pumps_stdio_to_the_hatch():
    # The same connector the sandbox binds in, driven as a plain pipe filter.
    with _serving(StreamHatch(splice_subprocess(['cat']))) as hatch:
        result = subprocess.run(
            [sys.executable, _CONNECT_SRC, hatch.socket_path],
            input=b'through the pump',
            capture_output=True,
            timeout=30,
            check=False,
        )
    assert result.returncode == 0
    assert result.stdout == b'through the pump'


# -- verdict types ----------------------------------------------------------- #
def test_verdicts_are_plain_data():
    # The connection is the command's stdio, so a verdict holds no pipes at all.
    left, right = socket.socketpair()
    proc = subprocess.Popen(
        [sys.executable, '-c', 'pass'], stdin=right.fileno(), stdout=right.fileno(), start_new_session=True
    )
    try:
        assert Process(proc).proc is proc
    finally:
        proc.wait(timeout=30)
        left.close()
        right.close()
