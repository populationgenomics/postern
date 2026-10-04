r"""Build postern's guest init into a static binary.

The init (``_init.c``) ships as source inside the package, so the binary a
deployer builds is the one that matches the postern they installed. Build it in
a throwaway stage of the worker image and copy out only the binary, so no
compiler reaches the guest rootfs or the worker:

    FROM python:3.12-slim AS init
    RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \\
        && pip install 'postern==X.Y.Z' && python -m postern.build_init /postern-init
    ...
    COPY --from=init /postern-init /opt/postern-init

then point the profile at it with ``SandboxProfile(init='/opt/postern-init')``.
It is static, so it needs nothing from the guest's rootfs; postern binds it in.

Usage: ``python -m postern.build_init OUTPUT [--cc CC]`` (``CC`` defaults to
``$CC``, then ``cc``).
"""

from __future__ import annotations

import argparse
import os
import pathlib
import subprocess

from postern import __version__

SOURCE = pathlib.Path(__file__).with_name('_init.c')


def build(output: str | os.PathLike[str], *, cc: str | None = None) -> pathlib.Path:
    """Compile the init to ``output`` as a static binary stamped with this postern's version.

    Args:
        output: Where to write the binary.
        cc: The C compiler. Defaults to ``$CC``, then ``cc``.

    Returns:
        The path written.

    Raises:
        subprocess.CalledProcessError: If the compiler fails.
    """
    target = pathlib.Path(output)
    compiler = cc or os.environ.get('CC') or 'cc'
    command = [
        compiler,
        '-static',
        '-O2',
        '-Wall',
        '-Wextra',
        '-Werror',
        f'-DPOSTERN_VERSION="{__version__}"',
        '-o',
        str(target),
        str(SOURCE),
    ]
    subprocess.run(command, check=True)  # noqa: S603 — fixed argv, no shell
    return target


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog='python -m postern.build_init', description="Build postern's guest init into a static binary."
    )
    parser.add_argument('output', help='where to write the static binary')
    parser.add_argument('--cc', help='the C compiler (default: $CC, then cc)')
    args = parser.parse_args(argv)
    print(build(args.output, cc=args.cc))


if __name__ == '__main__':
    main()
