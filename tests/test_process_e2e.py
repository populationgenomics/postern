"""`Sandbox.start*` and `Process`: output as it arrives, and stopping a run.

Require Linux + bubblewrap. Stopping runs under both guest inits, since each
must turn a SIGTERM from the host into one the command sees.
"""

import asyncio
import contextlib
import os
import pathlib
import select
import shutil
import signal
import threading
import time

import pytest

from postern import IsolationError, Process, Sandbox, SandboxProfile, _process, _sandbox, available
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


def test_cancelling_astart_cleans_up_process(sandbox):
    started = threading.Event()
    orig_start = sandbox.start_bash

    def slow_start(*args, **kwargs):
        started.set()
        time.sleep(0.1)
        return orig_start(*args, **kwargs)

    sandbox.start_bash = slow_start

    async def main():
        task = asyncio.create_task(sandbox.astart_bash('sleep 0.5; echo survived > /workspace/marker'))
        while not started.is_set():
            await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.sleep(0.8)

    asyncio.run(main())
    assert not (sandbox.workspace / 'marker').exists()


# Long enough to be sure the guest is not just slow, short enough to keep the suite quick.
_SURVIVOR = 'sleep 0.5; echo survived > /workspace/marker'


def _assert_no_survivor(sandbox: Sandbox) -> None:
    time.sleep(1.0)
    assert not (sandbox.workspace / 'marker').exists()


def test_a_failed_start_leaves_no_guest(sandbox, monkeypatch):
    # The failure lands once the launch is complete: the guest is running by then.
    resources = contextlib.ExitStack()
    closed = threading.Event()
    resources.callback(closed.set)

    def fail(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError('boom')

    monkeypatch.setattr(_process.Process, '__init__', fail)
    with pytest.raises(RuntimeError, match='boom'):
        sandbox._start(['bash', '-c', _SURVIVOR], resources=resources)
    assert closed.is_set()
    _assert_no_survivor(sandbox)


def test_an_interrupted_start_leaves_no_guest(sandbox, monkeypatch):
    # Ctrl-C while the caller waits on the launcher thread: the launch finishes
    # there, and the result nobody received is discarded.
    real = _sandbox._hold_init

    def slow_hold(*args, **kwargs):
        pidfd = real(*args, **kwargs)
        time.sleep(0.3)
        return pidfd

    def interrupt(*_args: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(_sandbox, '_hold_init', slow_hold)
    previous = signal.signal(signal.SIGALRM, interrupt)
    try:
        signal.setitimer(signal.ITIMER_REAL, 0.1)
        with pytest.raises(KeyboardInterrupt):
            sandbox.start_bash(_SURVIVOR)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
    _assert_no_survivor(sandbox)


def test_no_pidfds_fails_closed_before_launching(sandbox, monkeypatch):
    def refuse(_pid: int) -> int:
        raise PermissionError(1, 'blocked by seccomp')

    monkeypatch.setattr(_process, 'pidfd_open', refuse)
    with pytest.raises(IsolationError, match='pidfds are unavailable'):
        sandbox.start_bash(_SURVIVOR)
    _assert_no_survivor(sandbox)


@pytest.mark.parametrize(
    'report',
    [b'{"child-pid": "1"}', b'[1]', b'{"child-pid"'],
    ids=['not-an-int', 'not-an-object', 'truncated'],
)
def test_an_unusable_init_report_fails_closed(report):
    read, write = os.pipe()
    try:
        os.write(write, report)
        os.close(write)
        write = -1
        with pytest.raises(IsolationError, match='--info-fd report'):
            _sandbox._read_init_pid(read)
    finally:
        os.close(read)
        if write >= 0:
            os.close(write)


def test_no_init_report_means_no_init():
    read, write = os.pipe()
    os.close(write)
    try:
        assert _sandbox._read_init_pid(read) is None
    finally:
        os.close(read)


def test_post_kill_drain_bounds_timeout(sandbox):
    start_t = time.monotonic()
    result = sandbox.start_bash('while true; do echo flood; done').communicate(timeout=0.3)
    elapsed = time.monotonic() - start_t
    assert result.returncode == 124
    assert elapsed < 2.5


def test_async_aclose_does_not_block_event_loop_when_cancelled(sandbox):
    async def main():
        proc = await sandbox.astart_bash('trap "" TERM; sleep 30')

        loop_ticks = 0
        heartbeat_running = True

        async def heartbeat():
            nonlocal loop_ticks
            while heartbeat_running:
                loop_ticks += 1
                await asyncio.sleep(0.01)

        hb_task = asyncio.create_task(heartbeat())

        aclose_task = asyncio.create_task(proc.aclose())
        await asyncio.sleep(0.05)
        aclose_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await aclose_task

        before_ticks = loop_ticks
        await asyncio.sleep(0.05)
        after_ticks = loop_ticks
        heartbeat_running = False
        await hb_task
        assert after_ticks > before_ticks

    asyncio.run(main())


def test_procresult_timed_out_distinguishes_guest_exit_124(sandbox):
    guest_124 = sandbox.run_bash('exit 124')
    assert guest_124.returncode == 124
    assert not guest_124.timed_out
    assert not guest_124.ok
    assert '[postern] timed out' not in guest_124.stderr

    timed_out = sandbox.run_bash('sleep 30', timeout=0.2)
    assert timed_out.returncode == 124
    assert timed_out.timed_out
    assert not timed_out.ok
    assert '[postern] timed out' in timed_out.stderr


def test_communicate_max_output_caps_buffer(sandbox):
    result = sandbox.run_bash('echo "hello world"', max_output=5)
    assert result.returncode == 0
    assert result.stdout == 'hello'
    assert result.truncated
    assert not result.timed_out
    assert '[postern] output truncated' in result.stderr


def test_async_communicate_max_output_caps_buffer(sandbox):
    async def main():
        async with await sandbox.astart_bash('echo "streaming output"') as proc:
            return await proc.communicate(max_output=7)

    result = asyncio.run(main())
    assert result.stdout == 'streami'
    assert result.truncated
    assert not result.timed_out
    assert '[postern] output truncated' in result.stderr


def test_release_kills_init_when_bwrap_already_dead(sandbox):
    proc = sandbox.start_bash('sleep 30')
    assert proc._launch.init_pidfd is not None
    init_pidfd = os.dup(proc._launch.init_pidfd)
    poller = select.poll()
    poller.register(init_pidfd, select.POLLIN)
    try:
        # bwrap dying out-of-band does not kill the guest init immediately
        os.kill(proc._popen.pid, signal.SIGKILL)
        proc._popen.wait()
        assert proc._popen.poll() is not None
        assert poller.poll(0) == []

        # proc.close() must kill the guest init via its pidfd in _release()
        proc.close()
        assert poller.poll(1000) != []
    finally:
        with contextlib.suppress(OSError):
            _process.pidfd_signal(init_pidfd, signal.SIGKILL)
        os.close(init_pidfd)


def test_launch_thread_keeps_bwrap_alive_when_spawner_thread_exits(sandbox):
    proc_box = []

    def worker():
        p = sandbox.start_bash('sleep 0.3; echo ok > /workspace/marker')
        proc_box.append(p)

    t = threading.Thread(target=worker)
    t.start()
    t.join()

    proc = proc_box[0]
    try:
        result = proc.communicate(timeout=2.0)
        assert result.returncode == 0
        assert (sandbox.workspace / 'marker').read_text() == 'ok\n'
    finally:
        proc.close()
