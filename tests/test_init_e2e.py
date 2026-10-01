"""The guest init, end to end: the Python shim and the C init, held to one contract.

Each behaviour PID 1 owes the guest runs under both inits, so the C init is
measured against the shim it would replace. Require Linux + bubblewrap, and a C
compiler for the C init (which the session builds once, as a deployer would).
"""

import pathlib
import shutil

import pytest

from postern import Sandbox, SandboxProfile, available
from postern.build_init import build

pytestmark = pytest.mark.skipif(not available(), reason='requires Linux + bubblewrap')


@pytest.fixture(scope='session')
def c_init(tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    if shutil.which('cc') is None:
        pytest.skip('requires a C compiler to build the guest init')
    return build(tmp_path_factory.mktemp('init') / 'postern-init')


@pytest.fixture(params=['shim', 'c'])
def profile(request: pytest.FixtureRequest):
    """A profile factory for the init under test."""
    init = request.getfixturevalue('c_init') if request.param == 'c' else None

    def make(**kwargs) -> SandboxProfile:
        return SandboxProfile(init=init, **kwargs)

    return make


def test_run_python(profile):
    result = Sandbox(profile()).run_python('print(2 + 2)')
    assert result.ok, result.stderr
    assert result.stdout.strip() == '4'


def test_run_bash(profile):
    result = Sandbox(profile()).run_bash('echo supervised')
    assert result.ok, result.stderr
    assert result.stdout.strip() == 'supervised'


def test_exit_status_passes_through(profile):
    sandbox = Sandbox(profile())
    assert sandbox.run_python('import sys; sys.exit(7)').returncode == 7
    assert sandbox.run_bash('exit 9').returncode == 9


def test_death_by_signal_is_128_plus_n(profile):
    assert Sandbox(profile()).run_bash('kill -KILL $$').returncode == 128 + 9


def test_missing_program_is_127(profile):
    result = Sandbox(profile()).run(['definitely-not-a-program'])
    assert result.returncode == 127
    assert 'cannot exec' in result.stderr


def test_rlimit_nproc_carries_across_the_exec(profile):
    result = Sandbox(profile(rlimit_nproc=8)).run_bash('ulimit -u')
    assert result.ok, result.stderr
    assert result.stdout.strip() == '8'


def test_rlimit_as_caps_bash_but_not_python_startup(profile):
    # RLIMIT_AS lands before the exec for a program, after the interpreter is up
    # for run_python: a fresh CPython's virtual size could trip a cap set earlier.
    sandbox = Sandbox(profile(rlimit_as=1024 * 1024 * 1024))
    assert sandbox.run_bash('ulimit -v').stdout.strip() == str(1024 * 1024)  # KiB
    result = sandbox.run_python('print(sum(range(1000)))')
    assert result.ok, result.stderr
    assert result.stdout.strip() == '499500'


def test_pid1_is_the_init_and_is_non_dumpable(profile):
    script = 'echo $$; cat /proc/1/environ >/dev/null 2>&1 && echo READABLE || echo blocked'
    result = Sandbox(profile()).run_bash(script)
    assert result.ok, result.stderr
    pid, verdict = result.stdout.split()
    assert pid != '1'
    assert verdict == 'blocked'


def test_orphans_are_reaped(profile):
    # The backgrounded sleep's parent exits at once, so it reparents to PID 1 and
    # becomes a zombie there unless the init reaps it.
    script = (
        '( sleep 0.1 & ); sleep 0.5; '
        'for f in /proc/[0-9]*/stat; do read -r _ _ state _ < "$f" && [ "$state" = Z ] && echo ZOMBIE; done; '
        'echo done'
    )
    result = Sandbox(profile()).run_bash(script)
    assert result.ok, result.stderr
    assert result.stdout.split() == ['done']


def test_sigterm_to_pid1_reaches_the_command(profile):
    script = 'trap "echo got-TERM; exit 0" TERM; kill -TERM 1; sleep 5 & wait'
    result = Sandbox(profile()).run_bash(script, timeout=10)
    assert result.ok, result.stderr
    assert result.stdout.strip() == 'got-TERM'


def test_c_init_forwards_to_the_whole_process_group(c_init):
    # The shim signals the command alone; the C init signals its process group, so
    # a grandchild hears the TERM too. bash's trap waits for it to finish.
    script = (
        'trap "wait; exit 0" TERM; '
        'sh -c \'trap "echo grandchild-TERM; exit 0" TERM; sleep 5 & wait\' & '
        'sleep 0.3; kill -TERM 1; wait'
    )
    result = Sandbox(SandboxProfile(init=c_init)).run_bash(script, timeout=10)
    assert result.ok, result.stderr
    assert result.stdout.strip() == 'grandchild-TERM'


def test_c_init_needs_no_interpreter_for_run_or_run_bash(c_init):
    # The shim is Python, so under it every entrypoint needs profile.python; the
    # C init execs the command itself.
    sandbox = Sandbox(SandboxProfile(init=c_init, python='/nonexistent/python3'))
    assert sandbox.run_bash('echo no-python-needed').stdout.strip() == 'no-python-needed'
    assert sandbox.run(['echo', 'argv']).stdout.strip() == 'argv'


def test_verify_accepts_the_init_it_was_built_with(c_init):
    Sandbox(SandboxProfile(init=c_init)).verify()


def test_verify_needs_no_interpreter_under_the_c_init(c_init):
    # A rootfs without Python is the point of the C init, so the boot check must
    # not launch run_python to prove isolation.
    Sandbox(SandboxProfile(init=c_init, python='/nonexistent/python3')).verify()
