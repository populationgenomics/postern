"""`Sandbox.verify` and the guest init: the version check, inside the sandbox only.

The init is a deployer-supplied binary, and the host never executes it: the
version check reads the init's own ``--version`` from a run inside the sandbox.
The "inits" here are stand-in scripts that only answer with a version.
"""

import pathlib
import stat

import pytest

from postern import IsolationError, Sandbox, SandboxProfile, available

needs_bwrap = pytest.mark.skipif(not available(), reason='requires Linux + bubblewrap')


def _fake_init(tmp_path: pathlib.Path, version: str, *, marker: pathlib.Path | None = None) -> pathlib.Path:
    init = tmp_path / 'postern-init'
    # A host path a run on the host could write to; inside the sandbox it is not bound.
    leave_marker = f'echo ran > {marker} 2>/dev/null\n' if marker else ''
    init.write_text(f'#!/bin/sh\n{leave_marker}echo {version}\n')
    init.chmod(init.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return init


def test_a_relative_init_path_is_refused():
    # Relative, the file bound in as PID 1 would depend on the worker's cwd.
    with pytest.raises(ValueError, match='must be an absolute path'):
        Sandbox(SandboxProfile(init='postern-init'))


@needs_bwrap
def test_verify_refuses_an_init_from_another_version(tmp_path):
    init = _fake_init(tmp_path, '0.0.1-not-this-one')
    with pytest.raises(IsolationError, match=r'was built from postern 0\.0\.1-not-this-one'):
        Sandbox(SandboxProfile(init=init)).verify()


@needs_bwrap
def test_verify_refuses_an_init_that_cannot_launch(tmp_path):
    with pytest.raises(IsolationError, match='failed to launch'):
        Sandbox(SandboxProfile(init=tmp_path / 'missing')).verify()


@needs_bwrap
def test_verify_never_executes_the_init_on_the_host(tmp_path):
    marker = tmp_path / 'ran-on-the-host'
    init = _fake_init(tmp_path, '0.0.1-not-this-one', marker=marker)
    with pytest.raises(IsolationError, match='was built from postern'):
        Sandbox(SandboxProfile(init=init)).verify()
    assert not marker.exists()
