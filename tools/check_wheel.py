"""Check a built Linux wheel carries a working guest init for its own platform.

    python tools/check_wheel.py dist/postern-X.Y.Z-py3-none-manylinux_2_17_x86_64....whl

Fails unless the wheel is tagged for this machine's architecture, carries
``postern/_bin/postern-init`` with its executable bit recorded, and the binary
reports the wheel's version. Runs the binary on the host, which only CI does: at
run time postern executes the init inside the sandbox alone.
"""

from __future__ import annotations

import pathlib
import stat
import subprocess
import sys
import sysconfig
import tempfile
import zipfile

_MEMBER = 'postern/_bin/postern-init'


def main(path: str) -> None:
    wheel = pathlib.Path(path)
    # A wheel name is name-version-python-abi-platform.
    _, version, python_tag, abi, platform_tag = wheel.stem.split('-')
    arch = sysconfig.get_platform().split('-', 1)[1]
    expected = [f'manylinux_2_17_{arch}', f'manylinux2014_{arch}', f'musllinux_1_1_{arch}']
    if (python_tag, abi) != ('py3', 'none') or platform_tag.split('.') != expected:
        sys.exit(f'{wheel.name}: expected py3-none-{".".join(expected)}')
    with zipfile.ZipFile(wheel) as archive:
        try:
            info = archive.getinfo(_MEMBER)
        except KeyError:
            sys.exit(f'{wheel.name}: no {_MEMBER}')
        mode = info.external_attr >> 16
        if not mode & stat.S_IXUSR:
            sys.exit(f'{wheel.name}: {_MEMBER} has mode {oct(mode)}, not executable')
        with tempfile.TemporaryDirectory() as tmp:
            init = pathlib.Path(archive.extract(info, tmp))
            init.chmod(0o755)
            reported = subprocess.run([init, '--version'], check=True, capture_output=True, text=True).stdout.strip()
    if reported != version:
        sys.exit(f'{wheel.name}: the init reports {reported!r}, not {version!r}')
    print(f'{wheel.name}: ok')


if __name__ == '__main__':
    main(*sys.argv[1:])
