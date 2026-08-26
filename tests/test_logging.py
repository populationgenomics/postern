"""What postern's logging promises: a NullHandler, no configuration, no raw guest bytes.

The level split is a security property, not a preference, so it is asserted here
rather than left to a reader of the call sites.
"""

from __future__ import annotations

import contextlib
import logging
import socket
import subprocess
import sys
import time
import typing

import grpc
import pytest

import postern.stream as stream_module
from postern import _log
from postern.grpc import _Allowlist
from postern.stream import Process, StreamHatch, splice_subprocess

_SETTLE = 0.2  # let the pool worker reach its logging call before we assert

# --- the library configures nothing ---------------------------------------- #


def test_package_root_has_exactly_one_null_handler():
    handlers = logging.getLogger('postern').handlers
    assert len(handlers) == 1
    assert isinstance(handlers[0], logging.NullHandler)


@pytest.mark.parametrize('name', ['postern', 'postern.stream', 'postern.grpc', 'postern._workspace'])
def test_library_sets_no_level(name):
    # NOTSET means "inherit"; anything else is the library deciding for the app.
    assert logging.getLogger(name).level == logging.NOTSET


@pytest.mark.parametrize('name', ['postern.stream', 'postern.grpc', 'postern._workspace'])
def test_library_adds_no_handler_below_the_package_root(name):
    assert logging.getLogger(name).handlers == []


# --- guest-controlled bytes are never logged verbatim ---------------------- #


@pytest.mark.parametrize(
    'hostile',
    [
        '/x\nseverity=ERROR fake host line',
        '/x\r\nWARNING: breach',
        '/x\x00y',
        '/x\rERROR',
        '\n\n\n',
    ],
)
def test_safe_renders_a_forging_attempt_on_one_line(hostile):
    rendered = _log.safe(hostile)
    assert '\n' not in rendered
    assert '\r' not in rendered
    assert '\x00' not in rendered


def test_safe_caps_length_and_says_it_did():
    rendered = _log.safe('A' * 5000)
    assert len(rendered) < 300
    assert '5000 total' in rendered


def test_safe_does_not_mark_an_uncapped_value():
    assert _log.safe('short') == "'short'"


def test_safe_handles_bytes_and_none():
    assert '\n' not in _log.safe(b'a\nb')
    assert _log.safe(None) == 'None'


def test_a_denied_grpc_method_is_logged_escaped_and_at_warning(caplog):
    hostile = '/svc/M\nseverity=ERROR forged'
    details = typing.cast(grpc.HandlerCallDetails, _Details(hostile))
    with caplog.at_level(logging.DEBUG, logger='postern.grpc'):
        _Allowlist({'/allowed/M'}).intercept_service(lambda _d: None, details)

    records = [r for r in caplog.records if r.name == 'postern.grpc']
    assert len(records) == 1
    assert records[0].levelno == logging.WARNING, 'an off-allowlist method is host-visible evidence'
    assert '\n' not in records[0].getMessage()
    assert 'forged' in records[0].getMessage(), 'the method must still be identifiable'


# --- the level split ------------------------------------------------------- #


def test_a_handler_that_raises_logs_a_warning_with_the_traceback(caplog):
    hatch = StreamHatch(_exploding, name='boom')
    with caplog.at_level(logging.DEBUG, logger='postern.stream'), hatch.accepting():
        _connect_and_close(hatch)
    hatch.close()

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings, 'a host handler bug must not be indistinguishable from hostile input'
    assert any(r.exc_info is not None for r in warnings), 'the traceback is the point'


def test_a_policy_refusal_is_debug_not_warning(caplog):
    hatch = StreamHatch(_refusing, name='refuse')
    with caplog.at_level(logging.DEBUG, logger='postern.stream'), hatch.accepting():
        _connect_and_close(hatch)
    hatch.close()

    records = [r for r in caplog.records if r.name == 'postern.stream']
    assert records, 'a refusal must leave a trace at DEBUG'
    assert all(r.levelno <= logging.DEBUG for r in records), (
        'a handler refusing by policy is working correctly; at WARNING the guest picks the rate'
    )


def test_a_refusal_logs_nothing_at_the_default_level(caplog):
    # The property that makes an unsuppressed per-event line affordable: with no
    # level configured, a guest driving refusals in a loop emits nothing.
    hatch = StreamHatch(_refusing, name='quiet')
    with caplog.at_level(logging.INFO, logger='postern.stream'), hatch.accepting():
        for _ in range(20):
            _connect_and_close(hatch)
    hatch.close()

    assert [r for r in caplog.records if r.name == 'postern.stream'] == []


def test_the_hatch_name_goes_through_safe(caplog):
    hatch = StreamHatch(_exploding, name='a_b')
    with caplog.at_level(logging.DEBUG, logger='postern.stream'), hatch.accepting():
        _connect_and_close(hatch)
    hatch.close()

    messages = [r.getMessage() for r in caplog.records]
    assert any(repr('a_b') in m for m in messages), 'the name is quoted, so it cannot run into the message'


def test_dispose_failure_is_logged_rather_than_swallowed(caplog, monkeypatch):
    verdict = Process.from_popen(_sleeping_popen())
    monkeypatch.setattr(verdict, 'dispose', _raising)
    with caplog.at_level(logging.DEBUG, logger='postern.stream'):
        stream_module._dispose(verdict, 0.1)

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings, 'a failed dispose leaks a subprocess; that cannot be silent'
    assert warnings[0].exc_info is not None
    _reap_quietly(verdict)


def test_the_happy_path_stays_silent(caplog):
    hatch = StreamHatch(splice_subprocess(['true']), name='ok')
    with caplog.at_level(logging.DEBUG, logger='postern.stream'), hatch.accepting():
        _connect_and_close(hatch)
    hatch.close()

    assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []


# --- helpers --------------------------------------------------------------- #


class _Details:
    """The one attribute `_Allowlist.intercept_service` reads off its argument."""

    def __init__(self, method: str) -> None:
        self.method = method


def _exploding(_stream):
    raise RuntimeError('handler bug')


def _refusing(_stream):
    return None


def _raising(*_args, **_kwargs):
    raise OSError('dispose blew up')


def _connect_and_close(hatch):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(hatch.socket_path)
    sock.close()
    time.sleep(_SETTLE)


def _sleeping_popen():
    return subprocess.Popen(
        [sys.executable, '-c', 'import time; time.sleep(30)'],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def _reap_quietly(verdict):
    with contextlib.suppress(Exception):
        verdict._proc.kill()
        verdict._proc.wait(timeout=5)
