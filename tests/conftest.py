"""Session setup: give a source checkout the guest init a Linux wheel carries."""

from __future__ import annotations

import os
import pathlib
import shutil
from collections.abc import Iterator

import pytest

from postern import _sandbox, available, build_init


@pytest.fixture(scope='session', autouse=True)
def packaged_init(tmp_path_factory: pytest.TempPathFactory) -> Iterator[pathlib.Path | None]:
    """The init every default profile launches: the installed wheel's, else one built for the session.

    A source checkout has no ``_bin/postern-init``, so where a sandbox can run this
    builds one, as ``setup.py`` would, and points the default at it. With no
    compiler it builds nothing, and each sandboxed test fails on the missing init.
    """
    if _sandbox._PACKAGED_INIT.is_file():
        yield _sandbox._PACKAGED_INIT
        return
    if not available() or shutil.which(os.environ.get('CC') or 'cc') is None:
        yield None
        return
    built = build_init.build(tmp_path_factory.mktemp('init') / 'postern-init')
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(_sandbox, '_PACKAGED_INIT', built)
        yield built
