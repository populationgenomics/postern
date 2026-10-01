"""`Sandbox.verify` refuses a guest init built from another postern version.

Runs anywhere: the version check comes before any launch, and the "init" here
is a stand-in script that only answers ``--version``.
"""

import pathlib
import stat

import pytest

from postern import IsolationError, Sandbox, SandboxProfile


def _fake_init(tmp_path: pathlib.Path, version: str) -> pathlib.Path:
    init = tmp_path / 'postern-init'
    init.write_text(f'#!/bin/sh\necho {version}\n')
    init.chmod(init.stat().st_mode | stat.S_IXUSR)
    return init


def test_verify_refuses_an_init_from_another_version(tmp_path):
    init = _fake_init(tmp_path, '0.0.1-not-this-one')
    with pytest.raises(IsolationError, match=r'was built from postern 0\.0\.1-not-this-one'):
        Sandbox(SandboxProfile(init=init)).verify()


def test_verify_refuses_an_init_that_cannot_run(tmp_path):
    with pytest.raises(IsolationError, match='cannot run'):
        Sandbox(SandboxProfile(init=tmp_path / 'missing')).verify()
