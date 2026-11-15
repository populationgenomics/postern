"""Check built Linux wheels carry a working guest init for the platform they claim.

    python tools/check_wheel.py dist/postern-X.Y.Z-py3-none-manylinux_2_17_x86_64....whl ...

Fails unless each wheel is ``py3-none`` for a single architecture and carries
``postern/_bin/postern-init`` readable and executable by any uid. The binary must
be an ELF for that architecture with no ``PT_INTERP`` (static, so it runs under
any libc, as the manylinux and musllinux tags claim), and must report the wheel's
version. Runs the binary on the host, which only CI does: at run time postern
executes the init inside the sandbox alone.
"""

from __future__ import annotations

import pathlib
import re
import stat
import struct
import subprocess
import sys
import tempfile
import zipfile

_MEMBER = 'postern/_bin/postern-init'
_PLATFORM = re.compile(r'(?:linux|manylinux2014|manylinux_\d+_\d+|musllinux_\d+_\d+)_(?P<arch>\w+)')
# Wheel architecture → (ELF class, e_machine).
_ELF = {'x86_64': (2, 62), 'aarch64': (2, 183), 'i686': (1, 3), 'armv7l': (1, 40)}
_PT_INTERP = 3


def _arch(wheel: pathlib.Path) -> str:
    # A wheel name is name-version-python-abi-platform.
    _, _, python_tag, abi, platform_tags = wheel.stem.split('-')
    if (python_tag, abi) != ('py3', 'none'):
        sys.exit(f'{wheel.name}: expected py3-none, not {python_tag}-{abi}')
    matches = [_PLATFORM.fullmatch(tag) for tag in platform_tags.split('.')]
    arches = {match['arch'] for match in matches if match is not None}
    if None in matches or len(arches) != 1:
        sys.exit(f'{wheel.name}: expected Linux platform tags for one architecture, not {platform_tags}')
    return arches.pop()


def _check_elf(name: str, binary: bytes, arch: str) -> None:
    if arch not in _ELF:
        sys.exit(f'{name}: no ELF expectation for {arch}')
    if binary[:4] != b'\x7fELF' or binary[5] != 1:
        sys.exit(f'{name}: {_MEMBER} is not a little-endian ELF')
    elf_class = binary[4]
    (machine,) = struct.unpack_from('<H', binary, 18)
    if (elf_class, machine) != _ELF[arch]:
        sys.exit(f'{name}: {_MEMBER} is ELF class {elf_class} machine {machine}, not {arch}')
    if elf_class == 2:
        (phoff,) = struct.unpack_from('<Q', binary, 32)
        phentsize, phnum = struct.unpack_from('<HH', binary, 54)
    else:
        (phoff,) = struct.unpack_from('<I', binary, 28)
        phentsize, phnum = struct.unpack_from('<HH', binary, 42)
    for index in range(phnum):
        (p_type,) = struct.unpack_from('<I', binary, phoff + index * phentsize)
        if p_type == _PT_INTERP:
            sys.exit(f'{name}: {_MEMBER} is dynamically linked (it has a PT_INTERP)')


def _check(wheel: pathlib.Path) -> None:
    arch = _arch(wheel)
    version = wheel.stem.split('-')[1]
    with zipfile.ZipFile(wheel) as archive:
        try:
            info = archive.getinfo(_MEMBER)
        except KeyError:
            sys.exit(f'{wheel.name}: no {_MEMBER}')
        mode = info.external_attr >> 16
        # bwrap may run at another uid than the one that installed the wheel (host_uid=).
        if stat.S_IMODE(mode) & 0o555 != 0o555:
            sys.exit(f'{wheel.name}: {_MEMBER} has mode {oct(mode)}, not readable and executable by all')
        _check_elf(wheel.name, archive.read(info), arch)
        with tempfile.TemporaryDirectory() as tmp:
            init = pathlib.Path(archive.extract(info, tmp))
            init.chmod(0o755)
            reported = subprocess.run([init, '--version'], check=True, capture_output=True, text=True).stdout.strip()
    if reported != version:
        sys.exit(f'{wheel.name}: the init reports {reported!r}, not {version!r}')
    print(f'{wheel.name}: ok')


def main(paths: list[str]) -> None:
    if not paths:
        sys.exit('usage: python tools/check_wheel.py WHEEL...')
    for path in paths:
        _check(pathlib.Path(path))


if __name__ == '__main__':
    main(sys.argv[1:])
