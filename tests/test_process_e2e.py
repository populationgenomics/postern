"""`Sandbox.start*` and `Process`: output as it arrives, and cancellation.

Require Linux + bubblewrap. Cancellation runs under both guest inits, since each
must turn a SIGTERM from the host into one the command sees.
"""

import pathlib
import shutil
import threading
import time

import pytest

from postern import Process, Sandbox, SandboxProfile, available
from postern.build_init import build

pytestmark = pytest.mark.skipif(not available(), reason='requires Linux + bubblewrap')


@pytest.fixture(scope='session')
def c_init(tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    if shutil.which('cc') is None:
        pytest.skip('requires a C compiler to build the guest init')
    return build(tmp_path_factory.mktemp('init') / 'postern-init')


@pytest.fixture(params=['shim', 'c'])
def sandbox(request: pytest.FixtureRequest) -> Sandbox:
    init = request.getfixturevalue('c_init') if request.param == 'c' else None
    return Sandbox(SandboxProfile(init=init))


def _drain(process: Process) -> tuple[list[tuple[float, str, bytes]], float]:
    started = time.monotonic()
    chunks = [(time.monotonic() - started, stream, data) for stream, data in process.iter_output()]
    return chunks, time.monotonic() - started


def test_output_arrives_while_the_command_runs(sandbox):
    with sandbox.start_bash('for i in 1 2 3; do echo $i; sleep 0.3; done') as process:
        chunks, elapsed = _drain(process)
        assert process.wait() == 0
    assert b''.join(data for _, _, data in chunks) == b'1\n2\n3\n'
    first_at = chunks[0][0]
    assert first_at < 0.3 < elapsed  # the first line came well before the end


def test_streams_are_labelled(sandbox):
    with sandbox.start_bash('echo out; echo err >&2') as process:
        by_stream: dict[str, bytes] = {}
        for stream, data in process.iter_output():
            by_stream[stream] = by_stream.get(stream, b'') + data
    assert by_stream == {'stdout': b'out\n', 'stderr': b'err\n'}


def test_communicate_after_partial_streaming_returns_the_rest(sandbox):
    with sandbox.start_bash('echo first; sleep 0.3; echo second') as process:
        stream, data = next(process.iter_output())
        assert (stream, data) == ('stdout', b'first\n')
        result = process.communicate(timeout=10)
    assert result.ok
    assert result.stdout == 'second\n'


def test_cancel_lets_the_command_clean_up(sandbox):
    script = 'trap "echo cleaning-up; exit 3" TERM; echo ready; sleep 30 & wait'
    with sandbox.start_bash(script) as process:
        assert next(process.iter_output()) == ('stdout', b'ready\n')
        started = time.monotonic()
        process.cancel(grace=5)
        result = process.communicate(timeout=10)
    assert time.monotonic() - started < 2
    assert process.cancelled
    assert result.returncode == 3
    assert result.stdout == 'cleaning-up\n'


def test_cancel_escalates_when_the_command_ignores_sigterm(sandbox):
    script = 'trap "" TERM; echo ready; sleep 30'
    with sandbox.start_bash(script) as process:
        assert next(process.iter_output()) == ('stdout', b'ready\n')
        started = time.monotonic()
        process.cancel(grace=0.5)
        result = process.communicate(timeout=10)
    assert 0.4 < time.monotonic() - started < 3
    assert result.returncode < 0  # bwrap killed; the namespace went with it


def test_cancel_with_no_grace_is_immediate(sandbox):
    with sandbox.start_bash('echo ready; sleep 30') as process:
        assert next(process.iter_output()) == ('stdout', b'ready\n')
        started = time.monotonic()
        process.cancel(grace=0)
        process.communicate(timeout=10)
    assert time.monotonic() - started < 1


def test_cancel_from_another_thread_while_streaming(sandbox):
    # The shape a harness takes: one thread reads, another decides to stop it.
    with sandbox.start_bash('trap "echo bye; exit 0" TERM; while :; do echo tick; sleep 0.1; done') as process:
        threading.Timer(0.5, process.cancel).start()
        output = b''.join(data for _, data in process.iter_output())
        assert process.wait() == 0
    assert output.count(b'tick') >= 2
    assert output.endswith(b'bye\n')


def test_cancel_after_exit_is_a_no_op(sandbox):
    with sandbox.start_bash('exit 5') as process:
        assert process.wait() == 5
        process.cancel()
        assert process.communicate().returncode == 5


def test_closing_a_running_process_stops_it(sandbox):
    with sandbox.start_bash('sleep 30') as process:
        pass
    assert process.returncode is not None


def test_c_init_cancel_reaches_the_whole_process_group(c_init):
    # A pipeline's members are not the command itself; the C init signals its
    # process group, so they stop too and the trap can report it.
    script = 'trap "echo stopped; exit 0" TERM; echo ready; sleep 30 | cat & wait'
    with Sandbox(SandboxProfile(init=c_init)).start_bash(script) as process:
        assert next(process.iter_output()) == ('stdout', b'ready\n')
        process.cancel(grace=5)
        result = process.communicate(timeout=10)
    assert result.returncode == 0
    assert result.stdout == 'stopped\n'
