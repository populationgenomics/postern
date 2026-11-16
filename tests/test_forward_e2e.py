"""End-to-end: a guest's TCP port, opened from the host and served by a handler process.

Requires Linux + bubblewrap (skipped elsewhere). The handler here is a thread
behind a `Receiver`; in production it is any process with a control socket.
"""

from __future__ import annotations

import errno
import pathlib
import socket
import threading
import time
from collections.abc import Callable, Iterator

import pytest

from postern import Sandbox, SandboxProfile, available
from postern.forward import Handoff, PortForward, Receiver

pytestmark = pytest.mark.skipif(not available(), reason='requires Linux + bubblewrap')

# Connects to each port given on argv, sends its name, half-closes, and prints the reply.
_CLIENT = """
import socket, sys
for port in sys.argv[1:]:
    with socket.create_connection(('127.0.0.1', int(port)), timeout=10) as conn:
        conn.sendall(b'hello ' + port.encode())
        conn.shutdown(socket.SHUT_WR)
        reply = b''
        while chunk := conn.recv(4096):
            reply += chunk
        print(reply.decode())
"""


class _Echo:
    """A handler that answers each connection with ``<tag>:<what it read>`` and records its handoffs."""

    def __init__(self, path: pathlib.Path, tag: str) -> None:
        self.receiver = Receiver(path)
        self.tag = tag
        self.handoffs: list[Handoff] = []
        self.ended: list[int] = []
        self._thread = threading.Thread(target=self._receive, daemon=True)
        self._thread.start()

    def _receive(self) -> None:
        while True:
            try:
                handoff = self.receiver.receive()
            except OSError:
                return  # the receiver was closed
            self.handoffs.append(handoff)
            threading.Thread(target=self._serve, args=(handoff,), daemon=True).start()

    def _serve(self, handoff: Handoff) -> None:
        with handoff:
            while (conn := handoff.accept()) is not None:
                with conn:
                    data = b''
                    while chunk := conn.recv(4096):
                        data += chunk
                    conn.sendall(f'{self.tag}:'.encode() + data)
            self.ended.append(handoff.guest_port)


@pytest.fixture
def echo(tmp_path: pathlib.Path) -> Iterator[Callable[[str], _Echo]]:
    handlers: list[_Echo] = []

    def make(tag: str) -> _Echo:
        handler = _Echo(tmp_path / f'{tag}.sock', tag)
        handlers.append(handler)
        return handler

    yield make
    for handler in handlers:
        handler.receiver.close()


def _client(*ports: int) -> list[str]:
    return ['python3', '-c', _CLIENT, *(str(port) for port in ports)]


def test_the_guest_reaches_each_handler_on_its_port(echo):
    files, git = echo('files'), echo('git')
    sandbox = Sandbox(
        SandboxProfile(),
        forwards=[PortForward(8080, files.receiver.path), PortForward(9418, git.receiver.path)],
    )
    result = sandbox.run(_client(8080, 9418), timeout=30)
    assert result.ok, result.stderr
    assert result.stdout.splitlines() == ['files:hello 8080', 'git:hello 9418']


def test_a_port_below_1024_needs_no_capability_in_the_guest(echo):
    handler = echo('web')
    result = Sandbox(SandboxProfile(), forwards=[PortForward(80, handler.receiver.path)]).run(_client(80), timeout=30)
    assert result.ok, result.stderr
    assert result.stdout == 'web:hello 80\n'


def test_each_launch_hands_over_its_own_listener_and_ends_it(echo):
    handler = echo('files')
    sandbox = Sandbox(SandboxProfile(), forwards=[PortForward(8080, handler.receiver.path)])
    for _ in range(2):
        assert sandbox.run(_client(8080), timeout=30).stdout == 'files:hello 8080\n'
    assert len(handler.handoffs) == 2
    first, second = (handoff.listener for handoff in handler.handoffs)
    assert first is not second
    _wait_for(lambda: handler.ended == [8080, 8080])


def test_a_port_busy_on_the_host_is_free_in_the_guest(echo):
    handler = echo('files')
    with socket.create_server(('127.0.0.1', 0)) as host_listener:
        port = host_listener.getsockname()[1]
        sandbox = Sandbox(SandboxProfile(), forwards=[PortForward(port, handler.receiver.path)])
        result = sandbox.run(_client(port), timeout=30)
    assert result.ok, result.stderr
    assert result.stdout == f'files:hello {port}\n'


def test_the_guest_cannot_take_a_forwarded_port(echo):
    handler = echo('files')
    probe = (
        'import socket\n'
        'try:\n'
        '    socket.create_server(("127.0.0.1", 8080))\n'
        '    print("bound")\n'
        'except OSError as exc:\n'
        '    print(exc.errno)\n'
    )
    result = Sandbox(SandboxProfile(), forwards=[PortForward(8080, handler.receiver.path)]).run_python(probe)
    assert result.ok, result.stderr
    assert result.stdout.strip() == str(errno.EADDRINUSE)


def test_ipv6_loopback_reaches_the_handler_too(echo):
    handler = echo('files')
    probe = (
        'import socket\n'
        'try:\n'
        '    conn = socket.create_connection(("::1", 8080), timeout=10)\n'
        'except OSError as exc:\n'
        '    print("no-ipv6", exc)\n'
        'else:\n'
        '    conn.sendall(b"v6"); conn.shutdown(socket.SHUT_WR); print(conn.recv(64).decode())\n'
    )
    result = Sandbox(SandboxProfile(), forwards=[PortForward(8080, handler.receiver.path)]).run_python(probe)
    assert result.ok, result.stderr
    if result.stdout.startswith('no-ipv6'):
        pytest.skip(f'the guest has no IPv6 loopback here: {result.stdout.strip()}')
    assert result.stdout.strip() == 'files:v6'


def test_the_guest_inherits_no_launch_descriptors(echo):
    handler = echo('files')
    listing = 'import os; print(" ".join(sorted(os.listdir("/proc/self/fd"))))'
    result = Sandbox(SandboxProfile(), forwards=[PortForward(8080, handler.receiver.path)]).run(
        ['python3', '-c', listing], timeout=30
    )
    assert result.ok, result.stderr
    extra = set(result.stdout.split()) - {'0', '1', '2'}
    assert len(extra) <= 1, result.stdout  # the listing's own descriptor on /proc/self/fd


def test_the_guest_still_has_no_route_out(echo):
    handler = echo('files')
    probe = (
        'import socket\n'
        'try:\n'
        '    socket.create_connection(("1.1.1.1", 80), timeout=3)\n'
        '    print("reached")\n'
        'except OSError as exc:\n'
        '    print(type(exc).__name__)\n'
    )
    result = Sandbox(SandboxProfile(), forwards=[PortForward(8080, handler.receiver.path)]).run_python(probe)
    assert result.ok, result.stderr
    assert result.stdout.strip() != 'reached'


def test_an_unreachable_handler_fails_the_launch_before_the_guest_runs(tmp_path):
    sandbox = Sandbox(SandboxProfile(), forwards=[PortForward(8080, tmp_path / 'nobody.sock')])
    with pytest.raises(ConnectionError, match=r'nobody\.sock'):
        sandbox.start(['touch', '/workspace/ran'])
    assert not (sandbox.workspace / 'ran').exists()


def test_a_handler_after_an_unreachable_one_is_never_left_holding_a_listener(echo, tmp_path):
    first = echo('files')
    sandbox = Sandbox(
        SandboxProfile(),
        forwards=[PortForward(8080, first.receiver.path), PortForward(8081, tmp_path / 'nobody.sock')],
    )
    with pytest.raises(ConnectionError, match=r'nobody\.sock'):
        sandbox.start(['true'])
    _wait_for(lambda: first.ended == [8080])


def test_a_guest_that_dies_in_setup_reports_bwraps_error(echo):
    handler = echo('files')
    profile = SandboxProfile(required_ro_binds=[('/nonexistent-bind-source', '/x')])
    result = Sandbox(profile, forwards=[PortForward(8080, handler.receiver.path)]).run(['true'], timeout=30)
    assert not result.ok
    assert 'nonexistent-bind-source' in result.stderr


def test_a_guest_port_in_use_by_another_forward_is_refused_up_front(tmp_path):
    with pytest.raises(ValueError, match=r'more than once: \[8080\]'):
        Sandbox(forwards=[PortForward(8080, tmp_path / 'a.sock'), PortForward(8080, tmp_path / 'b.sock')])


def test_verify_proves_the_forwarding_path(echo):
    handler = echo('files')
    Sandbox(SandboxProfile(), forwards=[PortForward(8080, handler.receiver.path)]).verify()
    _wait_for(lambda: handler.ended == [8080])


def test_verify_fails_while_a_handler_is_down(tmp_path):
    with pytest.raises(ConnectionError, match=r'nobody\.sock'):
        Sandbox(SandboxProfile(), forwards=[PortForward(8080, tmp_path / 'nobody.sock')]).verify()


def _wait_for(condition: Callable[[], bool], timeout: float = 10) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > deadline:
            raise AssertionError('condition not met in time')
        time.sleep(0.02)
