r"""Build postern's guest init into a static binary.

A Linux install already carries the init, built by ``setup.py`` through
:func:`compile_init`, and a profile uses it with no configuration. Build one
yourself only for an editable install or source checkout, which carries none:

    python -m postern.build_init /opt/postern-init

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

SOURCE = pathlib.Path(__file__).with_name('_init.c')


def compile_init(output: str | os.PathLike[str], *, version: str, cc: str | None = None) -> pathlib.Path:
    """Compile the init to ``output`` as a static binary that reports ``version``.

    Imports nothing from postern, so ``setup.py`` can load this module by path
    and build the init into a wheel before postern is installed.

    Args:
        output: Where to write the binary.
        version: What the binary's ``--version`` prints, which
            :meth:`~postern.Sandbox.verify` compares with the installed postern.
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
        f'-DPOSTERN_VERSION="{version}"',
        '-o',
        str(target),
        str(SOURCE),
    ]
    subprocess.run(command, check=True)  # noqa: S603 — fixed argv, no shell
    return target


def build(output: str | os.PathLike[str], *, cc: str | None = None) -> pathlib.Path:
    """Compile the init to ``output``, stamped with the installed postern's version.

    Args:
        output: Where to write the binary.
        cc: The C compiler. Defaults to ``$CC``, then ``cc``.

    Returns:
        The path written.

    Raises:
        subprocess.CalledProcessError: If the compiler fails.
    """
    # Here rather than at module level: compile_init must stay importable without postern.
    from postern import __version__  # noqa: PLC0415

    return compile_init(output, version=__version__, cc=cc)


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
