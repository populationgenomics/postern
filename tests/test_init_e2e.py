"""The guest init, end to end: each behaviour PID 1 owes the guest.

Require Linux + bubblewrap. The init is the one the wheel carries, or in a source
checkout the one ``conftest`` builds for the session.
"""

import pytest

from postern import Sandbox, SandboxProfile, available

pytestmark = pytest.mark.skipif(not available(), reason='requires Linux + bubblewrap')


def test_run_python():
    result = Sandbox(SandboxProfile()).run_python('print(2 + 2)')
    assert result.ok, result.stderr
    assert result.stdout.strip() == '4'


def test_run_bash():
    result = Sandbox(SandboxProfile()).run_bash('echo supervised')
    assert result.ok, result.stderr
    assert result.stdout.strip() == 'supervised'


def test_exit_status_passes_through():
    sandbox = Sandbox(SandboxProfile())
    assert sandbox.run_python('import sys; sys.exit(7)').returncode == 7
    assert sandbox.run_bash('exit 9').returncode == 9


def test_death_by_signal_is_128_plus_n():
    assert Sandbox(SandboxProfile()).run_bash('kill -KILL $$').returncode == 128 + 9


def test_missing_program_is_127():
    result = Sandbox(SandboxProfile()).run(['definitely-not-a-program'])
    assert result.returncode == 127
    assert 'cannot exec' in result.stderr


def test_non_executable_program_is_127_too():
    # Not only a missing program: one that exists but cannot be executed gets the
    # same status, as documented.
    sandbox = Sandbox(SandboxProfile())
    assert sandbox.run_bash('printf "#!/bin/sh\\n" > /workspace/plain; chmod 644 /workspace/plain').ok
    result = sandbox.run(['/workspace/plain'])
    assert result.returncode == 127
    assert 'cannot exec' in result.stderr


def test_rlimit_nproc_carries_across_the_exec():
    result = Sandbox(SandboxProfile(rlimit_nproc=8)).run_bash('ulimit -u')
    assert result.ok, result.stderr
    assert result.stdout.strip() == '8'


def test_rlimit_as_caps_bash_but_not_python_startup():
    # RLIMIT_AS lands before the exec for a program, after the interpreter is up
    # for run_python: a fresh CPython's virtual size could trip a cap set earlier.
    sandbox = Sandbox(SandboxProfile(rlimit_as=1024 * 1024 * 1024))
    assert sandbox.run_bash('ulimit -v').stdout.strip() == str(1024 * 1024)  # KiB
    result = sandbox.run_python('print(sum(range(1000)))')
    assert result.ok, result.stderr
    assert result.stdout.strip() == '499500'


def test_the_work_dies_of_a_broken_pipe():
    # The init resets every disposition before the exec, so a writer to a closed
    # pipe dies of it (141) rather than getting EPIPE and possibly spinning until
    # the timeout.
    result = Sandbox(SandboxProfile()).run_bash('yes | head -1 >/dev/null; echo "${PIPESTATUS[0]}"')
    assert result.ok, result.stderr
    assert result.stdout.strip() == '141'


def test_the_work_starts_with_no_signals_ignored_or_blocked():
    result = Sandbox(SandboxProfile()).run_bash('grep -E "^Sig(Ign|Blk):" /proc/self/status')
    assert result.ok, result.stderr
    fields = dict(line.split(':\t') for line in result.stdout.strip().splitlines())
    assert int(fields['SigBlk'], 16) == 0
    # bash ignores a few job-control signals itself, but neither PIPE (13) nor XFSZ (25).
    ignored = int(fields['SigIgn'], 16)
    assert not ignored & (1 << (13 - 1))
    assert not ignored & (1 << (25 - 1))


def test_pid1_is_the_init_and_is_non_dumpable():
    script = 'echo $$; cat /proc/1/environ >/dev/null 2>&1 && echo READABLE || echo blocked'
    result = Sandbox(SandboxProfile()).run_bash(script)
    assert result.ok, result.stderr
    pid, verdict = result.stdout.split()
    assert pid != '1'
    assert verdict == 'blocked'


def test_orphans_are_reaped():
    # The backgrounded sleep's parent exits at once, so it reparents to PID 1 and
    # becomes a zombie there unless the init reaps it.
    script = (
        '( sleep 0.1 & ); sleep 0.5; '
        'for f in /proc/[0-9]*/stat; do read -r _ _ state _ < "$f" && [ "$state" = Z ] && echo ZOMBIE; done; '
        'echo done'
    )
    result = Sandbox(SandboxProfile()).run_bash(script)
    assert result.ok, result.stderr
    assert result.stdout.split() == ['done']


def test_sigterm_to_pid1_reaches_the_command():
    script = 'trap "echo got-TERM; exit 0" TERM; kill -TERM 1; sleep 5 & wait'
    result = Sandbox(SandboxProfile()).run_bash(script, timeout=10)
    assert result.ok, result.stderr
    assert result.stdout.strip() == 'got-TERM'


def test_init_forwards_to_the_whole_process_group():
    # The init signals the command's process group, so a grandchild hears the TERM
    # too. bash's trap waits for it to finish.
    script = (
        'trap "wait; exit 0" TERM; '
        'sh -c \'trap "echo grandchild-TERM; exit 0" TERM; sleep 5 & wait\' & '
        'sleep 0.3; kill -TERM 1; wait'
    )
    result = Sandbox(SandboxProfile()).run_bash(script, timeout=10)
    assert result.ok, result.stderr
    assert result.stdout.strip() == 'grandchild-TERM'


def test_init_needs_no_interpreter_for_run_or_run_bash():
    # The init execs the command itself; only run_python needs profile.python.
    sandbox = Sandbox(SandboxProfile(python='/nonexistent/python3'))
    assert sandbox.run_bash('echo no-python-needed').stdout.strip() == 'no-python-needed'
    assert sandbox.run(['echo', 'argv']).stdout.strip() == 'argv'


def test_verify_accepts_the_init_it_was_built_with():
    Sandbox(SandboxProfile()).verify()


def test_verify_needs_no_interpreter():
    # A rootfs need not carry Python, so the boot check must not launch run_python
    # to prove isolation.
    Sandbox(SandboxProfile(python='/nonexistent/python3')).verify()
