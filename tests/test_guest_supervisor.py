"""The guest shim's exit-status dispatch and rlimit gating — no bubblewrap needed.

Loads the bound-in shim by path and drives `_run_code` and `_apply_rlimits`
directly, so the ``SystemExit``/exception → status mapping is covered on any
platform. The fork+exec supervisor itself, and the ``run``/``run_bash`` wiring
above it, need a real sandbox and are covered in ``test_sandbox_e2e``.
"""

import importlib.util
import pathlib

import pytest

import postern


def _load_shim():
    path = pathlib.Path(postern.__file__).with_name('_guest.py')
    spec = importlib.util.spec_from_file_location('postern_guest_shim', path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def shim(monkeypatch):
    # Unset, so _apply_rlimits is a no-op and cannot touch this process's limits.
    monkeypatch.delenv('POSTERN_NPROC', raising=False)
    monkeypatch.delenv('POSTERN_AS', raising=False)
    return _load_shim()


def test_run_code_success_is_zero(shim, monkeypatch):
    monkeypatch.setenv('POSTERN_CODE', 'result = 2 + 2')
    assert shim._run_code() == 0


def test_run_code_propagates_explicit_exit_status(shim, monkeypatch):
    monkeypatch.setenv('POSTERN_CODE', 'import sys; sys.exit(7)')
    assert shim._run_code() == 7


def test_run_code_sys_exit_none_is_zero(shim, monkeypatch):
    monkeypatch.setenv('POSTERN_CODE', 'import sys; sys.exit()')
    assert shim._run_code() == 0


def test_run_code_uncaught_exception_is_one(shim, monkeypatch, capsys):
    monkeypatch.setenv('POSTERN_CODE', 'raise ValueError("boom")')
    assert shim._run_code() == 1
    assert 'ValueError' in capsys.readouterr().err


def test_run_code_empty_is_zero(shim, monkeypatch):
    monkeypatch.delenv('POSTERN_CODE', raising=False)
    assert shim._run_code() == 0


def test_run_code_string_exit_prints_message(shim, monkeypatch, capsys):
    monkeypatch.setenv('POSTERN_CODE', 'import sys; sys.exit("nope")')
    assert shim._run_code() == 1
    assert 'nope' in capsys.readouterr().err


def test_apply_rlimits_applies_both_when_address_space(shim, monkeypatch):
    calls = []
    monkeypatch.setattr(shim.resource, 'setrlimit', lambda which, _lim: calls.append(which))
    monkeypatch.setenv('POSTERN_NPROC', '32')
    monkeypatch.setenv('POSTERN_AS', str(1024 * 1024))
    shim._apply_rlimits(address_space=True)
    assert shim.resource.RLIMIT_NPROC in calls
    assert shim.resource.RLIMIT_AS in calls


def test_apply_rlimits_defers_address_space(shim, monkeypatch):
    calls = []
    monkeypatch.setattr(shim.resource, 'setrlimit', lambda which, _lim: calls.append(which))
    monkeypatch.setenv('POSTERN_NPROC', '32')
    monkeypatch.setenv('POSTERN_AS', str(1024 * 1024))
    shim._apply_rlimits(address_space=False)
    assert shim.resource.RLIMIT_NPROC in calls
    assert shim.resource.RLIMIT_AS not in calls
