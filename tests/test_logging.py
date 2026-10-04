"""What postern's logging promises: a NullHandler, no configuration, no raw guest bytes.

The level split is a security property, not a preference, so it is asserted here
rather than left to a reader of the call sites.
"""

from __future__ import annotations

import contextlib
import importlib
import logging
import socket
import subprocess
import sys
import threading
import time
import typing

import grpc
import pytest

import postern
import postern.stream as stream_module
from postern import _log, _workspace
from postern.grpc import GrpcHatch, _Allowlist
from postern.stream import Process, StreamHatch, splice_subprocess

_LOOP = 20  # enough refusals that an aggregating implementation would show

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
def test_guest_renders_a_forging_attempt_on_one_line(hostile):
    rendered = str(_log.Guest(hostile))
    assert '\n' not in rendered
    assert '\r' not in rendered
    assert '\x00' not in rendered


def test_guest_caps_length_and_says_it_did():
    rendered = str(_log.Guest('A' * 5000))
    assert len(rendered) < 300
    assert '5000 total' in rendered


def test_guest_caps_an_escape_heavy_value_by_its_rendering():
    # 200 NULs are within the input cap but render four times longer.
    rendered = str(_log.Guest('\x00' * 200))
    assert len(rendered) < 250
    assert '200 total' in rendered


def test_guest_does_not_mark_an_uncapped_value():
    assert str(_log.Guest('short')) == "'short'"


def test_guest_handles_bytes_and_none():
    assert '\n' not in str(_log.Guest(b'a\nb'))
    assert str(_log.Guest(None)) == 'None'


def test_guest_renders_an_exception_as_its_type_and_escaped_message():
    assert str(_log.Guest(ValueError('bad\nline'))) == repr('ValueError: bad\nline')


def test_guest_renders_only_when_the_record_is_formatted():
    class Unrenderable:
        def __repr__(self) -> str:
            raise AssertionError('rendered at a disabled level')

    logging.getLogger('postern.stream').debug('%s', _log.Guest(Unrenderable()))


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


def test_a_handler_that_raises_logs_a_warning_naming_the_exception(caplog):
    handler = _Counted(_exploding)
    hatch = StreamHatch(handler, name='boom')
    with caplog.at_level(logging.DEBUG, logger='postern.stream'), hatch.accepting():
        _drive(hatch, handler)
        _wait_for(lambda: _named(caplog, 'handler raised'), 'the handler-failure WARNING')
    hatch.close()

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING and r.name == 'postern.stream']
    assert warnings, 'a host handler bug must not be indistinguishable from the guest closing cleanly'
    assert 'RuntimeError' in warnings[0].getMessage(), 'the exception type is what identifies the bug'
    assert 'handler bug' in warnings[0].getMessage(), 'and its message'


def test_a_policy_refusal_is_debug_not_warning(caplog):
    handler = _Counted(_refusing)
    hatch = StreamHatch(handler, name='refuse')
    with caplog.at_level(logging.DEBUG, logger='postern.stream'), hatch.accepting():
        _drive(hatch, handler)
        _wait_for(lambda: _named(caplog, 'refused a connection'), 'the refusal DEBUG line')
    hatch.close()

    records = [r for r in caplog.records if r.name == 'postern.stream' and r.levelno != logging.INFO]
    assert records, 'a refusal must leave a trace at DEBUG'
    assert all(r.levelno <= logging.DEBUG for r in records), (
        'a handler refusing by policy is working correctly; at WARNING the guest picks the rate'
    )


def test_the_library_default_level_is_warning():
    # What "the default" actually is, since the library sets nothing: the root's
    # own level. Asserted so the claim below is about a measured number.
    assert logging.getLogger('postern.stream').getEffectiveLevel() == logging.WARNING


def test_a_refusal_emits_nothing_at_the_default_level(caplog):
    # The property that makes an unsuppressed per-event line affordable: a guest
    # driving refusals in a loop produces no record a default-configured host sees.
    handler = _Counted(_refusing)
    hatch = StreamHatch(handler, name='quiet')
    with caplog.at_level(logging.WARNING, logger='postern.stream'), hatch.accepting():
        _drive(hatch, handler, _LOOP)
    hatch.close()

    assert [r for r in caplog.records if r.name == 'postern.stream'] == []


def test_the_same_refusals_are_all_visible_at_debug(caplog):
    # The positive control for the test above: without it, "no records" cannot be
    # told apart from "the connections never reached the handler".
    handler = _Counted(_refusing)
    hatch = StreamHatch(handler, name='loud')
    with caplog.at_level(logging.DEBUG, logger='postern.stream'), hatch.accepting():
        _drive(hatch, handler, _LOOP)
        _wait_for(lambda: _count(caplog, 'refused a connection') == _LOOP, f'all {_LOOP} refusal lines')
    hatch.close()

    assert _count(caplog, 'refused a connection') == _LOOP, 'every refusal gets a line; nothing is aggregated'


def test_dispose_failure_is_logged_rather_than_swallowed(caplog, monkeypatch):
    verdict = Process.from_popen(_sleeping_popen())
    monkeypatch.setattr(verdict, 'dispose', _raising)
    with caplog.at_level(logging.DEBUG, logger='postern.stream'):
        stream_module._dispose(verdict, 0.1)

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings, 'a failed dispose leaks a subprocess; that cannot be silent'
    assert warnings[0].exc_info is not None
    _reap_quietly(verdict)


def test_a_handler_exception_message_cannot_forge_a_log_line(caplog):
    # The handler's exception text is guest-derived, so neither it nor the
    # traceback may reach the record raw.
    handler = _Counted(_forging)
    hatch = StreamHatch(handler, name='forge')
    with caplog.at_level(logging.DEBUG, logger='postern.stream'), hatch.accepting():
        _drive(hatch, handler)
        _wait_for(lambda: _named(caplog, 'handler traceback'), 'the escaped-traceback DEBUG line')
    hatch.close()

    records = [r for r in caplog.records if r.name == 'postern.stream' and r.levelno != logging.INFO]
    assert records
    for record in records:
        assert record.exc_info is None, 'exc_info on a guest-reachable path puts the traceback in raw'
        assert '\n' not in record.getMessage()
        assert '\r' not in record.getMessage()
    assert any('ValueError' in r.getMessage() for r in records), 'the bug must still be identifiable'


def test_closing_with_a_connection_in_flight_is_not_reported_as_a_handler_bug(caplog):
    # _track raises ConnectionAbortedError by design when close() has run. That is
    # teardown, not a handler failure, and a guest picks how many fire per close.
    handler = _Counted(_slow)
    hatch = StreamHatch(handler, name='teardown')
    hatch.start()
    for _ in range(4):
        _connect(hatch)
    with caplog.at_level(logging.DEBUG, logger='postern.stream'):
        _wait_for(lambda: hatch._live or handler._handled._value, 'a connection to reach the handler')
        hatch.close()
        _wait_for(lambda: _named(caplog, 'closed with a connection in flight'), 'the teardown DEBUG line')

    assert [r for r in caplog.records if 'handler raised' in r.getMessage()] == [], (
        'a designed teardown path must not be reported as host evidence'
    )


def test_a_failed_reap_inside_dispose_is_logged(caplog, monkeypatch):
    verdict = Process.from_popen(_sleeping_popen())
    monkeypatch.setattr(stream_module, '_reap', _raising)
    with caplog.at_level(logging.DEBUG, logger='postern.stream'):
        verdict.dispose(0.1)

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING and r.name == 'postern.stream']
    assert warnings, 'a reap that fails leaves an untracked subprocess'
    assert warnings[0].exc_info is not None, 'the failure is host-side, so the traceback is safe and useful'
    _reap_quietly(verdict)


def test_a_failed_wait_in_reap_is_logged(caplog, monkeypatch):
    proc = _sleeping_popen()
    monkeypatch.setattr(proc, 'wait', _raising)
    with caplog.at_level(logging.DEBUG, logger='postern.stream'):
        stream_module._reap(proc, 0.1, None)

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING and r.name == 'postern.stream']
    assert warnings, "an unreaped pid lingers as a zombie for the worker's life"
    proc.kill()


def test_a_workspace_whose_close_fails_is_logged(caplog, tmp_path, monkeypatch):
    workspace = _workspace.Workspace(tmp_path)
    monkeypatch.setattr(workspace, 'close', _raising)
    with caplog.at_level(logging.DEBUG, logger='postern._workspace'):
        workspace.__del__()

    warnings = [r for r in caplog.records if r.name == 'postern._workspace']
    assert warnings, 'a Workspace whose close fails holds a directory fd open'
    assert warnings[0].levelno == logging.WARNING


def test_workspace_del_cannot_raise_even_if_logging_does(tmp_path, monkeypatch):
    # A logging Filter an application installs is entitled to raise, and does so
    # before any handler's handleError net.
    workspace = _workspace.Workspace(tmp_path)
    monkeypatch.setattr(workspace, 'close', _raising)
    logger = logging.getLogger('postern._workspace')
    raising = _RaisingFilter()
    logger.addFilter(raising)
    try:
        workspace.__del__()  # must not raise
    finally:
        logger.removeFilter(raising)


@pytest.mark.parametrize('method', ['start', 'close'])
def test_each_hatch_logs_its_lifecycle_at_info(caplog, method):
    grpc_hatch = GrpcHatch(allowlist=set())
    stream_hatch = StreamHatch(_refusing, name='life')
    with caplog.at_level(logging.INFO, logger='postern'):
        for hatch in (grpc_hatch, stream_hatch):
            hatch.start()
        if method == 'close':
            for hatch in (grpc_hatch, stream_hatch):
                hatch.close()

    infos = [r for r in caplog.records if r.levelno == logging.INFO]
    names = {r.name for r in infos}
    assert names == {'postern.grpc', 'postern.stream'}, 'both hatches log lifecycle, or the README is wrong'
    grpc_hatch.close()
    stream_hatch.close()


def test_reimporting_postern_does_not_stack_null_handlers():
    importlib.reload(postern)
    handlers = logging.getLogger('postern').handlers
    assert len([h for h in handlers if isinstance(h, logging.NullHandler)]) == 1


def test_the_happy_path_stays_silent(caplog):
    handler = _Counted(splice_subprocess(['true']))
    hatch = StreamHatch(handler, name='ok')
    with caplog.at_level(logging.DEBUG, logger='postern.stream'), hatch.accepting():
        _drive(hatch, handler)
    hatch.close()

    assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []


# --- helpers --------------------------------------------------------------- #


def _count(caplog, fragment):
    return len([r for r in caplog.records if fragment in r.getMessage()])


def _named(caplog, fragment):
    return _count(caplog, fragment) > 0


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


def _forging(_stream):
    raise ValueError('rejecting request: BAD\n2026-08-26 10:00:00 WARNING postern.stream: breach contained\n')


def _slow(_stream):
    time.sleep(0.5)


class _RaisingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:  # noqa: ARG002 — raises before it reads the record
        raise RuntimeError('a Filter is entitled to raise')


class _Counted:
    """A handler that lets a test wait for N connections to have been handled.

    The accept loop holds a slot while parked, so the semaphore is not a drain
    signal. Counting the handler's own returns is, and it is what the assertions
    are about.
    """

    def __init__(self, inner):
        self._inner = inner
        self._handled = threading.Semaphore(0)

    def __call__(self, stream):
        try:
            return self._inner(stream)
        finally:
            self._handled.release()

    def wait(self, count, timeout=10.0):
        for i in range(count):
            assert self._handled.acquire(timeout=timeout), f'only {i} of {count} connections reached the handler'


def _connect(hatch):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(hatch.socket_path)
    sock.close()


def _wait_for(predicate, what, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.005)
    raise AssertionError(f'timed out waiting for {what}')


def _drive(hatch, handler, count=1):
    """Open ``count`` connections and return once the handler has seen them all."""
    for _ in range(count):
        _connect(hatch)
    handler.wait(count)


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
