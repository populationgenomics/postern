"""The launch path: posix_spawn, postern-launch, and what reaches bwrap and the guest."""

from __future__ import annotations

import ast
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator

import pytest

import postern
from postern import IsolationError, Sandbox, SandboxProfile, _sandbox, available, build_init

pytestmark = pytest.mark.skipif(not available(), reason='requires Linux + bubblewrap')
requires_root = pytest.mark.skipif(os.geteuid() != 0, reason='a uid drop needs root')

_LIST_FDS = 'import os; print(sorted(int(fd) for fd in os.listdir("/proc/self/fd")))'


def _launcher(
    *args: str, pass_fds: tuple[int, ...] = (), launcher: str | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [launcher or str(_sandbox._PACKAGED_LAUNCH), *args],
        capture_output=True,
        text=True,
        check=False,
        pass_fds=pass_fds,
    )


@pytest.fixture(scope='module')
def proc_fallback_launcher(tmp_path_factory: pytest.TempPathFactory) -> str:
    """A launcher built to find close_range unavailable, as before Linux 5.9 or under an old seccomp profile."""
    cc = f'{os.environ.get("CC") or "cc"} -DPOSTERN_TEST_NO_CLOSE_RANGE'
    output = tmp_path_factory.mktemp('fallback') / 'postern-launch'
    return str(build_init.compile_binary(build_init.LAUNCH_SOURCE, output, version=postern.__version__, cc=cc))


@pytest.fixture
def reachable_init() -> Iterator[str]:
    """A copy of the init that a bwrap at another uid can reach: pytest's temp root is 0700."""
    directory = pathlib.Path(tempfile.mkdtemp())
    try:
        directory.chmod(0o755)
        init = directory / 'postern-init'
        shutil.copy(_sandbox._PACKAGED_INIT, init)
        yield str(init)
    finally:
        shutil.rmtree(directory)


def test_launcher_reports_its_version():
    result = _launcher('--version')
    assert (result.returncode, result.stdout.strip()) == (0, postern.__version__)


@pytest.mark.parametrize(
    'args',
    [
        [],
        ['--close-from', '3'],
        ['--close-from', '3', '--'],
        ['--', '/bin/true'],
        ['--close-from', '2', '--', '/bin/true'],
        ['--close-from', '3', '--gid', '65534', '--', '/bin/true'],
        ['--close-from', '3', '--uid', '-1', '--', '/bin/true'],
        ['--close-from', '3', '--uid', '4294967295', '--', '/bin/true'],
        ['--close-from', '3', '--uid', '12x', '--', '/bin/true'],
        ['--close-from', '3', '--bogus', '1', '--', '/bin/true'],
    ],
)
def test_launcher_refuses_a_malformed_command_line(args):
    # Never runs the program: a gid alone would leave root's uid, a close below 3 bwrap's stdio.
    result = _launcher(*args)
    assert result.returncode == 125, result.stderr
    assert 'usage' in result.stderr


def test_launcher_reports_a_failed_exec_as_its_own_status():
    read, write = os.pipe()
    try:
        os.dup2(write, 40)
        result = _launcher('--close-from', '41', '--error-fd', '40', '--', '/nonexistent', pass_fds=(40,))
        os.close(40)
        os.close(write)
        report = os.read(read, 4096)
    finally:
        os.close(read)
    assert result.returncode == 125
    assert 'postern-launch: /nonexistent' in result.stderr
    assert json.loads(report) == {'postern-launch': '/nonexistent: No such file or directory'}


def test_a_launcher_failure_raises_rather_than_reading_as_the_commands_status(monkeypatch):
    monkeypatch.setattr(_sandbox.shutil, 'which', lambda *_args, **_kwargs: '/nonexistent/bwrap')
    with pytest.raises(IsolationError, match='postern-launch: /nonexistent/bwrap: No such file'):
        Sandbox().run(['true'])


def test_a_foreign_reaper_is_named_rather_than_read_as_success(child_prelude):
    script = child_prelude + (
        'import signal\n'
        'from postern import Sandbox\n'
        'signal.signal(signal.SIGCHLD, signal.SIG_IGN)\n'
        'try:\n'
        '    Sandbox().run(["true"])\n'
        'except ChildProcessError as exc:\n'
        '    print(exc)\n'
    )
    worker = subprocess.run([sys.executable, '-c', script], capture_output=True, text=True, check=False)
    assert 'was reaped by something else in this process' in worker.stdout, worker.stderr


@pytest.mark.parametrize(('version', 'refused'), [('glibc 2.17', True), ('glibc 2.23', True), ('glibc 2.24', False)])
def test_a_glibc_whose_posix_spawn_forks_is_refused(monkeypatch, version, refused):
    monkeypatch.setattr(_sandbox.os, 'confstr', lambda _name: version)
    if refused:
        with pytest.raises(IsolationError, match='forks inside posix_spawn'):
            _sandbox._require_spawn_without_fork()
    else:
        _sandbox._require_spawn_without_fork()


@pytest.mark.parametrize('variant', ['close_range', '/proc/self/fd'])
def test_launcher_closes_every_descriptor_from_close_from(variant, proc_fallback_launcher):
    launcher = proc_fallback_launcher if variant == '/proc/self/fd' else None
    read, write = os.pipe()
    try:
        os.dup2(read, 40)
        os.dup2(read, 41)
        result = _launcher(
            '--close-from', '41', '--', sys.executable, '-c', _LIST_FDS, pass_fds=(40, 41), launcher=launcher
        )
    finally:
        for fd in (read, write, 40, 41):
            os.close(fd)
    assert result.returncode == 0, result.stderr
    fds = ast.literal_eval(result.stdout)
    assert 40 in fds
    assert 41 not in fds


@requires_root
def test_launcher_drops_to_the_uid_and_gid_with_no_groups():
    code = 'import os; print(os.getresuid(), os.getresgid(), os.getgroups())'
    result = _launcher('--close-from', '3', '--uid', '65534', '--gid', '65533', '--', sys.executable, '-c', code)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == '(65534, 65534, 65534) (65533, 65533, 65533) []'


def test_a_stray_inheritable_descriptor_does_not_reach_the_guest():
    # A library's descriptor without O_CLOEXEC: posix_spawn passes it on, the launcher closes it.
    read, write = os.pipe()
    try:
        os.dup2(read, 60)  # inheritable
        result = Sandbox().run_python(_LIST_FDS)
    finally:
        for fd in (read, write, 60):
            os.close(fd)
    assert result.ok, result.stderr
    assert 60 not in ast.literal_eval(result.stdout)


def test_a_launch_from_a_worker_with_no_stdio_still_wires_the_guest(tmp_path, child_prelude):
    # With 0-2 closed, the launch's own pipes and the seccomp file take those numbers,
    # the same ones the guest's stdio must land on.
    report = tmp_path / 'report'
    script = child_prelude + (
        'import os\n'
        'for fd in (0, 1, 2):\n'
        '    os.close(fd)\n'
        'from postern import Sandbox\n'
        'result = Sandbox().run_bash("echo out; echo err >&2; exit 3")\n'
        f'pathlib.Path({str(report)!r}).write_text(repr((result.returncode, result.stdout, result.stderr)))\n'
    )
    subprocess.run([sys.executable, '-c', 'import pathlib\n' + script], check=False)
    assert report.read_text() == repr((3, 'out\n', 'err\n'))


@requires_root
def test_host_uid_runs_bwrap_at_that_uid_with_no_groups(reachable_init):
    sandbox = Sandbox(SandboxProfile(host_uid=65534, host_gid=65533, init=reachable_init))
    with sandbox.start_bash('sleep 30') as process:
        status = dict(
            line.split(':', 1) for line in pathlib.Path(f'/proc/{process.pid}/status').read_text().splitlines()
        )
    assert status['Uid'].split() == ['65534'] * 4
    assert status['Gid'].split() == ['65533'] * 4
    assert status['Groups'].split() == []


@pytest.mark.parametrize('host_uid', [None, pytest.param(65534, marks=requires_root)], ids=['no-drop', 'uid-drop'])
def test_a_launch_runs_no_atfork_handler(child_prelude, reachable_init, host_uid):
    # A handler that aborts the child of any real fork, as gRPC's can. The uid drop
    # is what once forced a real fork; posix_spawn never runs the handler.
    script = child_prelude + (
        'import ctypes, json, os\n'
        'from postern import Sandbox, SandboxProfile\n'
        'libc = ctypes.CDLL(None)\n'
        'libc.__register_atfork.argtypes = [ctypes.c_void_p] * 4\n'
        'libc.__register_atfork(None, None, ctypes.cast(libc.abort, ctypes.c_void_p), None)\n'
        f'result = Sandbox(SandboxProfile(host_uid={host_uid!r}, init={reachable_init!r})).run(["true"])\n'
        'pid = os.fork()\n'
        'if pid == 0:\n'
        '    os._exit(0)\n'
        'print(json.dumps([result.returncode, result.stderr, os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])]))\n'
    )
    worker = subprocess.run([sys.executable, '-c', script], capture_output=True, text=True, check=False)
    assert worker.returncode == 0, worker.stderr
    returncode, stderr, forked = json.loads(worker.stdout)
    assert forked == -6  # the handler is armed: a real fork's child dies of SIGABRT
    assert returncode == 0, stderr


def test_verify_refuses_a_launcher_from_another_postern_version(monkeypatch, tmp_path):
    stale = build_init.compile_binary(build_init.LAUNCH_SOURCE, tmp_path / 'postern-launch', version='0.0.0-stale')
    monkeypatch.setattr(_sandbox, '_PACKAGED_LAUNCH', stale)
    with pytest.raises(IsolationError, match=r'launcher .* was built from postern 0\.0\.0-stale'):
        Sandbox().verify()
