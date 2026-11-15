"""Session setup: give a source checkout the guest init and launcher a Linux wheel carries."""

from __future__ import annotations

import os
import pathlib
import shutil
from collections.abc import Iterator

import pytest

import postern
from postern import _sandbox, available, build_init


@pytest.fixture(scope='session', autouse=True)
def packaged_bin(tmp_path_factory: pytest.TempPathFactory) -> Iterator[pathlib.Path | None]:
    """The directory of the init and launcher every launch uses: the install's, else one built for the session.

    An editable install has no ``_bin``, so where a sandbox can run this builds
    both, as ``setup.py`` would, and points postern at them. With no compiler it
    builds nothing, and each sandboxed test fails on the missing binaries.
    """
    if _sandbox._PACKAGED_INIT.is_file() and _sandbox._PACKAGED_LAUNCH.is_file():
        yield _sandbox._PACKAGED_INIT.parent
        return
    if not available() or shutil.which(os.environ.get('CC') or 'cc') is None:
        yield None
        return
    built = build_init.compile_binaries(tmp_path_factory.mktemp('bin'), version=postern.__version__)
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(_sandbox, '_PACKAGED_INIT', built / 'postern-init')
        patch.setattr(_sandbox, '_PACKAGED_LAUNCH', built / 'postern-launch')
        yield built


@pytest.fixture
def child_prelude(packaged_bin: pathlib.Path | None) -> str:
    """Python source pointing a child interpreter's postern at :func:`packaged_bin`, which no patch here reaches."""
    if packaged_bin is None:
        return ''
    return (
        'import pathlib\n'
        'from postern import _sandbox\n'
        f'_sandbox._PACKAGED_INIT = pathlib.Path({str(packaged_bin / "postern-init")!r})\n'
        f'_sandbox._PACKAGED_LAUNCH = pathlib.Path({str(packaged_bin / "postern-launch")!r})\n'
    )
