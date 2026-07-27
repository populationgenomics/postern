"""Unit tests for the guest shim's exit-status dispatch (no bubblewrap needed).

Loads the bound-in shim as a module and exercises `_run_code` — the code path
the supervisor re-execs into for run_python — directly, so the SystemExit /
exception -> status mapping is covered on any platform. The fork+exec supervisor
and run_bash/run wiring are exercised end-to-end in test_sandbox_e2e.py (Linux).
"""

import importlib.util
import pathlib

import pytest

import postern


def _load_shim():
    path = pathlib.Path(postern.__file__).with_name('_guest.py')
    spec = importlib.util.spec_from_file_location('postern_guest_shim_supervisor', path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def shim(monkeypatch):
    # Keep the rlimit backstops off so _run_code's _apply_rlimits is a no-op and
    # can't touch the test process's own limits.
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
    assert 'ValueError' in capsys.readouterr().err  # traceback surfaced


def test_run_code_empty_is_zero(shim, monkeypatch):
    monkeypatch.delenv('POSTERN_CODE', raising=False)
    assert shim._run_code() == 0
