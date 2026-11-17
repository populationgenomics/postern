"""The forward protocol without a sandbox: validation, and what a handler accepts on its control socket."""

from __future__ import annotations

import array
import asyncio
import pathlib
import socket
import stat
import threading
import time
from collections.abc import Awaitable, Callable

import pytest

from postern import Sandbox, SandboxProfile, forward
from postern.forward import Handoff, HandoffError, PortForward, Receiver, hand_over


@pytest.mark.parametrize('port', [0, 65536, -1])
def test_a_port_out_of_range_is_refused(port):
    with pytest.raises(ValueError, match='1 to 65535'):
        PortForward(port, '/x.sock')


@pytest.mark.parametrize('port', [True, '8080', 80.0])
def test_a_port_that_is_not_an_int_is_refused(port):
    with pytest.raises(TypeError):
        PortForward(port, '/x.sock')


def test_forwards_take_only_port_forwards():
    with pytest.raises(TypeError, match='PortForward'):
        Sandbox(forwards=[(8080, '/x.sock')])  # pyright: ignore[reportArgumentType]


def test_a_handoff_delivers_the_listener_and_ends_at_the_launch_end(tmp_path: pathlib.Path):
    with Receiver(tmp_path / 'h.sock') as receiver, socket.create_server(('127.0.0.1', 0)) as listener:
        control = hand_over(PortForward(8080, receiver.path), listener, timeout=5)
        with receiver.receive() as handoff:
            assert handoff.guest_port == 8080
            port = listener.getsockname()[1]
            with socket.create_connection(('127.0.0.1', port), timeout=5) as client:
                accepted = handoff.accept()
                assert accepted is not None
                with accepted:
                    client.sendall(b'x')
                    assert accepted.recv(1) == b'x'
            control.close()
            assert handoff.accept() is None


def _message(port: int, token: bytes = b'', *, length: int | None = None) -> bytes:
    """A hand-over message as postern frames it, with its stated token length open to corruption."""
    stated = len(token) if length is None else length
    return port.to_bytes(2, 'big') + stated.to_bytes(2, 'big') + token


@pytest.mark.parametrize(
    ('message', 'with_listener'),
    [
        (_message(8080), False),
        (b'', True),
        (_message(0), True),
        (_message(8080)[:3], True),
        (_message(8080, b'abc', length=2), True),
        (_message(8080, b'abc', length=4), True),
        (_message(8080, bytes(257)), True),
    ],
    ids=[
        'no-descriptor',
        'empty',
        'port-zero',
        'cut-header',
        'token-longer-than-stated',
        'token-shorter-than-stated',
        'token-past-the-longest',
    ],
)
def test_a_malformed_handoff_is_refused(tmp_path: pathlib.Path, message: bytes, with_listener: bool):
    with (
        Receiver(tmp_path / 'h.sock') as receiver,
        socket.create_server(('127.0.0.1', 0)) as listener,
        socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as control,
    ):
        control.connect(receiver.path)
        fds = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [listener.fileno()]))]
        control.sendmsg([message] if message else [b'\0'], fds if with_listener else [])
        with pytest.raises(HandoffError, match='malformed port forward handoff'):
            receiver.receive()


def test_a_handoff_of_something_other_than_a_listener_is_refused(tmp_path: pathlib.Path):
    with Receiver(tmp_path / 'h.sock') as receiver, socket.socket() as not_listening:
        hand_over(PortForward(8080, receiver.path), not_listening, timeout=5).close()
        with pytest.raises(HandoffError, match='listening TCP socket'):
            receiver.receive()


def test_closing_the_receiver_removes_its_socket(tmp_path: pathlib.Path):
    path = tmp_path / 'h.sock'
    Receiver(path).close()
    assert not path.exists()


def test_a_handoff_with_bytes_past_its_frame_is_refused(tmp_path: pathlib.Path):
    with (
        Receiver(tmp_path / 'h.sock') as receiver,
        socket.create_server(('127.0.0.1', 0)) as listener,
        socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as control,
    ):
        control.connect(receiver.path)
        fds = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [listener.fileno()]))]
        control.sendmsg([_message(8080)], fds)
        control.sendall(b'more')
        with pytest.raises(HandoffError, match='malformed port forward handoff'):
            receiver.receive()


def test_a_handoff_of_a_unix_listener_is_refused(tmp_path: pathlib.Path):
    with Receiver(tmp_path / 'h.sock') as receiver, socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as unix:
        unix.bind(str(tmp_path / 'other.sock'))
        unix.listen()
        hand_over(PortForward(8080, receiver.path), unix, timeout=5).close()
        with pytest.raises(HandoffError, match='listening TCP socket'):
            receiver.receive()


def test_a_silent_control_connection_times_out(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(forward, '_HANDOFF_TIMEOUT_S', 0.2)
    with Receiver(tmp_path / 'h.sock') as receiver, socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as control:
        control.connect(receiver.path)
        with pytest.raises(HandoffError, match='timed out'):
            receiver.receive()


def test_a_receiver_serves_on_after_refusing_a_connection(tmp_path: pathlib.Path):
    with Receiver(tmp_path / 'h.sock') as receiver, socket.create_server(('127.0.0.1', 0)) as listener:
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as bad:
            bad.connect(receiver.path)
            bad.sendall(b'junk')
            with pytest.raises(HandoffError):
                receiver.receive()
        hand_over(PortForward(8080, receiver.path), listener, timeout=5)
        with receiver.receive() as handoff:
            assert handoff.guest_port == 8080


def test_the_control_socket_admits_only_its_owner_by_default(tmp_path: pathlib.Path):
    with Receiver(tmp_path / 'h.sock'):
        assert stat.S_IMODE((tmp_path / 'h.sock').stat().st_mode) == 0o600
    with Receiver(tmp_path / 'w.sock', mode=0o660):
        assert stat.S_IMODE((tmp_path / 'w.sock').stat().st_mode) == 0o660


def test_closing_a_handoff_ends_an_accept_waiting_on_it(tmp_path: pathlib.Path):
    with Receiver(tmp_path / 'h.sock') as receiver, socket.create_server(('127.0.0.1', 0)) as listener:
        control = hand_over(PortForward(8080, receiver.path), listener, timeout=5)
        handoff = receiver.receive()
        result: list[object] = []
        waiter = threading.Thread(target=lambda: result.append(handoff.accept()))
        waiter.start()
        time.sleep(0.2)
        handoff.close()
        waiter.join(5)
        control.close()
        assert not waiter.is_alive()
        assert result == [None]


async def _serve_in_a_loop(
    handoff: Handoff, handle: Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]
) -> None:
    # The event-loop pattern the README shows: the listener into asyncio's server,
    # the control connection's end of stream as the launch's end.
    loop = asyncio.get_running_loop()
    ended = loop.create_future()
    loop.add_reader(handoff.control, lambda: ended.done() or ended.set_result(None))
    server = await asyncio.start_server(handle, sock=handoff.listener)
    try:
        await ended
    finally:
        loop.remove_reader(handoff.control)
        server.close()
        await server.wait_closed()
        handoff.close()


def test_a_handoff_serves_from_an_event_loop(tmp_path: pathlib.Path):
    async def echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b'echo:' + await reader.read(64))
        await writer.drain()
        writer.close()

    async def main() -> bytes:
        with Receiver(tmp_path / 'h.sock') as receiver, socket.create_server(('127.0.0.1', 0)) as listener:
            port = listener.getsockname()[1]
            control = hand_over(PortForward(8080, receiver.path), listener, timeout=5)
            handoff = await asyncio.to_thread(receiver.receive)
            serving = asyncio.create_task(_serve_in_a_loop(handoff, echo))
            reader, writer = await asyncio.open_connection('127.0.0.1', port)
            writer.write(b'hi')
            writer.write_eof()
            reply = await reader.read()
            writer.close()
            control.close()  # the launch ends
            await asyncio.wait_for(serving, 5)
            return reply

    assert asyncio.run(main()) == b'echo:hi'


@pytest.mark.parametrize('token', [b'', b'launch-17', bytes(range(256))], ids=['none', 'text', 'longest-binary'])
def test_a_handoff_carries_the_token_it_was_sent_with(tmp_path: pathlib.Path, token: bytes):
    with Receiver(tmp_path / 'h.sock') as receiver, socket.create_server(('127.0.0.1', 0)) as listener:
        control = hand_over(PortForward(8080, receiver.path), listener, timeout=5, token=token)
        with control, receiver.receive() as handoff:
            assert handoff.token == token
            assert handoff.guest_port == 8080


@pytest.mark.parametrize('with_forwards', [True, False], ids=['forwards', 'no-forwards'])
@pytest.mark.parametrize(
    ('token', 'error'),
    [('launch-17', TypeError), (bytearray(b'launch-17'), TypeError), (bytes(257), ValueError)],
    ids=['str', 'bytearray', 'too-long'],
)
def test_a_launch_refuses_a_bad_token_before_it_starts(
    tmp_path: pathlib.Path, token: object, error: type, with_forwards: bool
):
    forwards = [PortForward(8080, tmp_path / 'never-bound.sock')] if with_forwards else []
    sandbox = Sandbox(SandboxProfile(), forwards=forwards)
    with pytest.raises(error, match='launch token'):
        sandbox.start(['true'], launch_token=token)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ('token', 'error'), [('launch-17', TypeError), (bytes(70000), ValueError)], ids=['str', 'huge']
)
def test_hand_over_refuses_a_bad_token_before_it_connects(tmp_path: pathlib.Path, token: object, error: type):
    with socket.create_server(('127.0.0.1', 0)) as listener, pytest.raises(error, match='launch token'):
        hand_over(PortForward(8080, tmp_path / 'never-bound.sock'), listener, timeout=5, token=token)  # type: ignore[arg-type]


def test_a_handoff_split_over_two_messages_is_refused(tmp_path: pathlib.Path):
    frame = _message(8080, b'launch-17')
    with (
        Receiver(tmp_path / 'h.sock') as receiver,
        socket.create_server(('127.0.0.1', 0)) as listener,
        socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as control,
    ):
        control.connect(receiver.path)
        control.sendmsg([frame[:2]], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [listener.fileno()]))])
        control.sendall(frame[2:])
        with pytest.raises(HandoffError, match='malformed port forward handoff'):
            receiver.receive()


def test_a_stream_connection_cannot_reach_the_control_socket(tmp_path: pathlib.Path):
    with (
        Receiver(tmp_path / 'h.sock') as receiver,
        socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream,
        pytest.raises(OSError, match='Protocol wrong type'),
    ):
        stream.connect(receiver.path)


@pytest.mark.parametrize(
    ('token', 'error'), [('launch-17', TypeError), (bytes(257), ValueError)], ids=['str', 'too-long']
)
def test_a_handoff_refuses_a_bad_token(token: object, error: type):
    with socket.socket() as listener, socket.socket() as control, pytest.raises(error, match='launch token'):
        Handoff(8080, listener, control, token=token)  # type: ignore[arg-type]
