"""Build hooks: compile the static guest init into the Linux wheel.

Everything declarative lives in ``pyproject.toml``. This file adds the one step
setuptools cannot express there: on Linux, ``build_py`` compiles ``_init.c`` into
``postern/_bin/postern-init``, and the wheel is tagged for the platform it was
built on. The binary is static, so it depends on no libc at run time, and the tag
claims both manylinux and musllinux. Elsewhere the wheel is pure and carries no
init: a sandbox runs only on Linux.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import sysconfig

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
    output.chmod(0o755)


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
        if not _builds_init():
            return super().get_tag()
        # The interpreter's platform, not the kernel's: a 32-bit userland can run on a 64-bit kernel.
        arch = sysconfig.get_platform().split('-', 1)[1]
        # The init is the wheel's only native file, and it is statically linked.
        return 'py3', 'none', f'manylinux_2_17_{arch}.manylinux2014_{arch}.musllinux_1_1_{arch}'


setuptools.setup(distclass=Distribution, cmdclass={'build_py': BuildPy, 'bdist_wheel': BdistWheel})
