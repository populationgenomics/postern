"""Build hooks: compile the static guest init into the Linux wheel.

Everything declarative lives in ``pyproject.toml``. This file adds the one step
setuptools cannot express there: on Linux, ``build_py`` compiles ``_init.c`` into
``postern/_bin/postern-init``, and the wheel is tagged for the platform it was
built on, ``linux_<arch>``, which any local installer accepts. The binary is
static, so it depends on no libc at run time; ``tools/build_wheel.sh`` retags a
release wheel for manylinux and musllinux on that basis. Elsewhere the wheel is
pure and carries no init: a sandbox runs only on Linux.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys

import setuptools
from setuptools.command import bdist_wheel, build_py

_SRC = pathlib.Path(__file__).parent / 'src' / 'postern'
# Where the init lands inside the package; postern._sandbox resolves the same path.
_INIT_IN_PACKAGE = pathlib.Path('postern', '_bin', 'postern-init')


def _builds_init() -> bool:
    return sys.platform.startswith('linux')


def _compile_init(output: pathlib.Path, version: str) -> None:
    # By path: importing the postern package would need postern installed.
    spec = importlib.util.spec_from_file_location('_postern_build_init', _SRC / 'build_init.py')
    if spec is None or spec.loader is None:
        raise RuntimeError(f'cannot load {_SRC / "build_init.py"}')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    output.parent.mkdir(parents=True, exist_ok=True)
    module.compile_init(output, version=version)


class BuildPy(build_py.build_py):
    """``build_py``, plus the compiled init on Linux."""

    def run(self) -> None:
        super().run()
        # An editable install keeps only get_outputs(), so a compiled init would be discarded.
        if _builds_init() and not self.editable_mode:
            _compile_init(pathlib.Path(self.build_lib) / _INIT_IN_PACKAGE, self.distribution.get_version())


class Distribution(setuptools.Distribution):
    """A platform distribution on Linux, so the init lands at the wheel's root, not under ``.data/purelib``."""

    def has_ext_modules(self) -> bool:
        return _builds_init()


class BdistWheel(bdist_wheel.bdist_wheel):
    """A ``py3-none-<platform>`` wheel on Linux, where it carries the init; pure elsewhere."""

    def get_tag(self) -> tuple[str, str, str]:
        python, abi, platform_tag = super().get_tag()
        if not _builds_init():
            return python, abi, platform_tag
        # No Python extension: the init is the wheel's only native file, and any CPython runs it.
        return 'py3', 'none', platform_tag


setuptools.setup(distclass=Distribution, cmdclass={'build_py': BuildPy, 'bdist_wheel': BdistWheel})
