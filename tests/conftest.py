"""Session setup: give a source checkout the static binaries a Linux wheel carries."""

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
    """The directory of the static binaries every launch uses: the install's, else one built for the session.

    A source checkout's ``_bin`` may be missing or older than its C sources, so
    where a sandbox can run this builds them, as ``setup.py`` would, and points
    postern at them. With no compiler it builds nothing, and each sandboxed test
    fails on the missing binaries.
    """
    checkout = pathlib.Path(__file__).resolve().parent.parent / 'src' / 'postern'
    from_wheel = pathlib.Path(postern.__file__).resolve().parent != checkout
    packaged = (_sandbox._PACKAGED_INIT, _sandbox._PACKAGED_LAUNCH, _sandbox._PACKAGED_LISTEN)
    if from_wheel and all(path.is_file() for path in packaged):
        yield _sandbox._PACKAGED_INIT.parent
        return
    if not available() or shutil.which(os.environ.get('CC') or 'cc') is None:
        yield None
        return
    built = build_init.compile_binaries(tmp_path_factory.mktemp('bin'), version=postern.__version__)
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(_sandbox, '_PACKAGED_INIT', built / 'postern-init')
        patch.setattr(_sandbox, '_PACKAGED_LAUNCH', built / 'postern-launch')
        patch.setattr(_sandbox, '_PACKAGED_LISTEN', built / 'postern-listen')
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
        f'_sandbox._PACKAGED_LISTEN = pathlib.Path({str(packaged_bin / "postern-listen")!r})\n'
    )
