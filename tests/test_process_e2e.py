"""`Sandbox.start*` and `Process`: output as it arrives, and stopping a run.

Require Linux + bubblewrap. Stopping runs under both guest inits, since each
must turn a SIGTERM from the host into one the command sees.
"""

import asyncio
import contextlib
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
    chunks = [(time.monotonic() - started, stream, data) for stream, data in process.output()]
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
        for stream, data in process.output():
            by_stream[stream] = by_stream.get(stream, b'') + data
    assert by_stream == {'stdout': b'out\n', 'stderr': b'err\n'}


def test_communicate_after_partial_streaming_returns_the_rest(sandbox):
    with sandbox.start_bash('echo first; sleep 0.3; echo second') as process:
        stream, data = next(process.output())
        assert (stream, data) == ('stdout', b'first\n')
        result = process.communicate(timeout=10)
    assert result.ok
    assert result.stdout == 'second\n'


def test_terminate_lets_the_command_clean_up(sandbox):
    script = 'trap "echo cleaning-up; exit 3" TERM; echo ready; sleep 30 & wait'
    with sandbox.start_bash(script) as process:
        assert next(process.output()) == ('stdout', b'ready\n')
        started = time.monotonic()
        process.terminate(grace=5)
        result = process.communicate(timeout=10)
    assert time.monotonic() - started < 2
    assert process.terminated
    assert result.returncode == 3
    assert result.stdout == 'cleaning-up\n'


def test_terminate_escalates_when_the_command_ignores_sigterm(sandbox):
    script = 'trap "" TERM; echo ready; sleep 30'
    with sandbox.start_bash(script) as process:
        assert next(process.output()) == ('stdout', b'ready\n')
        started = time.monotonic()
        process.terminate(grace=0.5)
        result = process.communicate(timeout=10)
    assert 0.4 < time.monotonic() - started < 3
    assert result.returncode < 0  # bwrap killed; the namespace went with it


def test_terminate_with_no_grace_is_immediate(sandbox):
    with sandbox.start_bash('echo ready; sleep 30') as process:
        assert next(process.output()) == ('stdout', b'ready\n')
        started = time.monotonic()
        process.terminate(grace=0)
        process.communicate(timeout=10)
    assert time.monotonic() - started < 1


def test_terminate_from_another_thread_while_streaming(sandbox):
    # The shape a harness takes: one thread reads, another decides to stop it.
    with sandbox.start_bash('trap "echo bye; exit 0" TERM; while :; do echo tick; sleep 0.1; done') as process:
        threading.Timer(0.5, process.terminate).start()
        output = b''.join(data for _, data in process.output())
        assert process.wait() == 0
    assert output.count(b'tick') >= 2
    # The trap ran. Under the C init the running `sleep` got the TERM too, so bash
    # may also report it as Terminated: the whole group heard the signal.
    assert b'bye\n' in output


def test_terminate_after_exit_is_a_no_op(sandbox):
    with sandbox.start_bash('exit 5') as process:
        assert process.wait() == 5
        process.terminate()
        assert process.communicate().returncode == 5


def test_closing_a_running_process_stops_it(sandbox):
    with sandbox.start_bash('sleep 30') as process:
        pass
    assert process.returncode is not None


@pytest.mark.parametrize('how', ['kill', 'close', 'terminate0', 'timeout0'])
def test_stop_right_after_start_kills_guest(sandbox, how):
    process = sandbox.start_bash('sleep 2; echo survived > /workspace/marker; echo done')
    started = time.monotonic()
    if how == 'kill':
        process.kill()
        result = process.communicate(10)
    elif how == 'close':
        process.close()
        result = None
    elif how == 'terminate0':
        process.terminate(grace=0)
        result = process.communicate(10)
    else:
        result = process.communicate(0)
    elapsed = time.monotonic() - started
    max_elapsed = 1.5 if how == 'close' else 0.5
    assert elapsed < max_elapsed
    if result is not None:
        assert 'done' not in result.stdout
    assert not (sandbox.workspace / 'marker').exists()


def test_c_init_cancel_reaches_the_whole_process_group(c_init):
    # A pipeline's members are not the command itself; the C init signals its
    # process group, so they stop too and the trap can report it.
    script = 'trap "echo stopped; exit 0" TERM; echo ready; sleep 30 | cat & wait'
    with Sandbox(SandboxProfile(init=c_init)).start_bash(script) as process:
        assert next(process.output()) == ('stdout', b'ready\n')
        process.terminate(grace=5)
        result = process.communicate(timeout=10)
    assert result.returncode == 0
    assert result.stdout == 'stopped\n'


def test_an_exception_in_the_block_stops_the_run_gracefully(sandbox):
    # Leaving the block with the run still going (here, on an exception) gives the
    # command its SIGTERM and a short grace, not an immediate kill.
    script = 'trap "echo cleaned > /workspace/marker; exit 0" TERM; echo ready; sleep 30 & wait'
    started = {}

    def give_up() -> None:
        with sandbox.start_bash(script) as process:
            started['process'] = process
            assert next(process.output()) == ('stdout', b'ready\n')
            raise RuntimeError('caller gave up')

    with pytest.raises(RuntimeError, match='caller gave up'):
        give_up()
    assert started['process'].returncode == 0
    assert (sandbox.workspace / 'marker').read_text() == 'cleaned\n'


def test_async_output_arrives_while_the_command_runs(sandbox):
    async def main():
        started = time.monotonic()
        arrivals = []
        async with await sandbox.astart_bash('for i in 1 2 3; do echo $i; sleep 0.3; done') as process:
            async for stream, data in process.output():
                arrivals.append((time.monotonic() - started, stream, data))
            return arrivals, await process.wait(), time.monotonic() - started

    arrivals, status, elapsed = asyncio.run(main())
    assert status == 0
    assert b''.join(data for _, _, data in arrivals) == b'1\n2\n3\n'
    assert arrivals[0][0] < 0.5 < elapsed


def test_async_communicate_and_timeout(sandbox):
    async def main():
        async with await sandbox.astart_bash('echo out; echo err >&2; exit 4') as process:
            done = await process.communicate(timeout=10)
        async with await sandbox.astart_bash('echo before; sleep 30') as process:
            slow = await process.communicate(timeout=0.5)
        return done, slow

    done, slow = asyncio.run(main())
    assert (done.returncode, done.stdout, done.stderr) == (4, 'out\n', 'err\n')
    assert slow.returncode == 124
    assert slow.stdout == 'before\n'
    assert slow.stderr.endswith('[postern] timed out')


def test_async_terminate_lets_the_command_clean_up(sandbox):
    async def main():
        script = 'trap "echo cleaning-up; exit 3" TERM; echo ready; sleep 30 & wait'
        async with await sandbox.astart_bash(script) as process:
            output = process.output()
            assert await anext(output) == ('stdout', b'ready\n')
            process.terminate(grace=5)
            rest = b''.join([data async for _, data in output])
            return rest, await process.wait()

    rest, status = asyncio.run(main())
    assert (rest, status) == (b'cleaning-up\n', 3)


def test_cancelling_the_task_stops_the_run_gracefully(sandbox):
    # asyncio cancellation of the task using the process becomes a graceful stop
    # of the guest, as the async with block unwinds.
    async def main():
        script = 'trap "echo cleaned > /workspace/marker; exit 0" TERM; echo ready; sleep 30 & wait'
        ready = asyncio.Event()
        holder = {}

        async def use():
            async with await sandbox.astart_bash(script) as process:
                holder['process'] = process
                async for _ in process.output():
                    ready.set()

        task = asyncio.create_task(use())
        await ready.wait()
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        return holder['process']

    process = asyncio.run(main())
    assert process.returncode == 0
    assert (sandbox.workspace / 'marker').read_text() == 'cleaned\n'
