"""The forward protocol without a sandbox: validation, and what a handler accepts on its control socket."""

from __future__ import annotations

import array
import pathlib
import socket

import pytest

from postern import Sandbox, forward
from postern.forward import PortForward, Receiver, hand_over


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


@pytest.mark.parametrize(
    ('message', 'with_listener'),
    [(b'8080', False), (b'port', True), (b'', True)],
    ids=['no-descriptor', 'not-a-port', 'empty'],
)
def test_a_malformed_handoff_is_refused(tmp_path: pathlib.Path, message: bytes, with_listener: bool):
    with (
        Receiver(tmp_path / 'h.sock') as receiver,
        socket.create_server(('127.0.0.1', 0)) as listener,
        socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as control,
    ):
        control.connect(receiver.path)
        fds = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [listener.fileno()]))]
        control.sendmsg([message] if message else [b'\0'], fds if with_listener else [])
        with pytest.raises(ValueError, match='malformed port forward handoff'):
            receiver.receive()


def test_a_handoff_of_something_other_than_a_listener_is_refused(tmp_path: pathlib.Path):
    with Receiver(tmp_path / 'h.sock') as receiver, socket.socket() as not_listening:
        hand_over(PortForward(8080, receiver.path), not_listening, timeout=5).close()
        with pytest.raises(ValueError, match='listening TCP socket'):
            receiver.receive()


def test_closing_the_receiver_removes_its_socket(tmp_path: pathlib.Path):
    path = tmp_path / 'h.sock'
    Receiver(path).close()
    assert not path.exists()


def test_a_handoff_with_bytes_past_the_port_is_refused(tmp_path: pathlib.Path):
    with (
        Receiver(tmp_path / 'h.sock') as receiver,
        socket.create_server(('127.0.0.1', 0)) as listener,
        socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as control,
    ):
        control.connect(receiver.path)
        fds = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [listener.fileno()]))]
        control.sendmsg([b'8080'], fds)
        control.sendall(b'more')
        with pytest.raises(ValueError, match='malformed port forward handoff'):
            receiver.receive()


def test_a_handoff_of_a_unix_listener_is_refused(tmp_path: pathlib.Path):
    with Receiver(tmp_path / 'h.sock') as receiver, socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as unix:
        unix.bind(str(tmp_path / 'other.sock'))
        unix.listen()
        hand_over(PortForward(8080, receiver.path), unix, timeout=5).close()
        with pytest.raises(ValueError, match='listening TCP socket'):
            receiver.receive()


def test_a_silent_control_connection_times_out(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(forward, '_HANDOFF_TIMEOUT_S', 0.2)
    with Receiver(tmp_path / 'h.sock') as receiver, socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as control:
        control.connect(receiver.path)
        with pytest.raises(TimeoutError):
            receiver.receive()
