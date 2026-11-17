r"""Build postern's static binaries: the guest init, the bwrap launcher and the port opener.

A Linux install already carries all three, built by ``setup.py`` through
:func:`compile_binaries`. An editable install or source checkout carries none;
build them into the package, where postern looks for them:

    python -m postern.build_init --in-place

The init alone can also go anywhere, for a profile to name:

    python -m postern.build_init /opt/postern-init

then ``SandboxProfile(init='/opt/postern-init')``. The launcher has no such
option, nor has the port opener: both run on the host as the worker, root
included, so postern runs only its own.

All are static: the init needs nothing from the guest's rootfs, and none needs a
particular libc on the host.

Usage: ``python -m postern.build_init (--in-place | OUTPUT) [--cc CC]``
(``CC`` defaults to ``$CC``, then ``cc``).
"""

from __future__ import annotations

import argparse
import os
import pathlib
import shlex
import subprocess

INIT_SOURCE = pathlib.Path(__file__).with_name('_init.c')
LAUNCH_SOURCE = pathlib.Path(__file__).with_name('_launch.c')
LISTEN_SOURCE = pathlib.Path(__file__).with_name('_listen.c')
# Each binary's file name in a package's ``_bin`` directory, by source.
BINARIES = {INIT_SOURCE: 'postern-init', LAUNCH_SOURCE: 'postern-launch', LISTEN_SOURCE: 'postern-listen'}


def compile_binary(
    source: pathlib.Path, output: str | os.PathLike[str], *, version: str, cc: str | None = None
) -> pathlib.Path:
    """Compile ``source`` to ``output`` as a stripped static binary that reports ``version``.

    Imports nothing from postern, so ``setup.py`` can load this module by path
    and build the binaries into a wheel before postern is installed.

    Args:
        source: The C source, one of :data:`BINARIES`.
        output: Where to write the binary.
        version: What the binary's ``--version`` prints, which
            :meth:`~postern.Sandbox.verify` compares with the installed postern.
        cc: The C compiler command, split like a shell word list (``ccache gcc``).
            Defaults to ``$CC``, then ``cc``.

    Returns:
        The path written, mode 0755.

    Raises:
        subprocess.CalledProcessError: If the compiler fails.
    """
    target = pathlib.Path(output)
    command = [
        *shlex.split(cc or os.environ.get('CC') or 'cc'),
        '-static',
        '-s',
        '-O2',
        '-Wall',
        '-Wextra',
        '-Werror',
        f'-DPOSTERN_VERSION="{version}"',
        '-o',
        str(target),
        str(source),
    ]
    subprocess.run(command, check=True)  # noqa: S603 — fixed argv, no shell
    # Whatever the umask: a bwrap at another uid (host_uid=) must read and exec the init.
    target.chmod(0o755)
    return target


def compile_binaries(directory: str | os.PathLike[str], *, version: str, cc: str | None = None) -> pathlib.Path:
    """Compile every one of :data:`BINARIES` into ``directory``, a package's ``_bin``.

    Args:
        directory: Created if missing, and made mode 0755 either way.
        version: What the binaries' ``--version`` prints.
        cc: As :func:`compile_binary`.

    Returns:
        ``directory``.

    Raises:
        subprocess.CalledProcessError: If the compiler fails.
    """
    target = pathlib.Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    target.chmod(0o755)  # as compile_binary's files: a bwrap at host_uid must traverse to the init
    for source, name in BINARIES.items():
        compile_binary(source, target / name, version=version, cc=cc)
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
    return compile_binary(INIT_SOURCE, output, version=_installed_version(), cc=cc)


def build_in_place(*, cc: str | None = None) -> pathlib.Path:
    """Compile every binary into this package's ``_bin``, where postern looks for them.

    Args:
        cc: As :func:`compile_binary`.

    Returns:
        The ``_bin`` directory.

    Raises:
        subprocess.CalledProcessError: If the compiler fails.
    """
    return compile_binaries(pathlib.Path(__file__).with_name('_bin'), version=_installed_version(), cc=cc)


def _installed_version() -> str:
    # Here rather than at module level: compile_binary must stay importable without postern.
    import postern  # noqa: PLC0415

    return postern.__version__


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog='python -m postern.build_init',
        description="Build postern's static guest init, bwrap launcher and port opener.",
    )
    where = parser.add_mutually_exclusive_group(required=True)
    where.add_argument('output', nargs='?', help='where to write the init alone')
    where.add_argument('--in-place', action='store_true', help="build every binary into this package's _bin")
    parser.add_argument('--cc', help='the C compiler (default: $CC, then cc)')
    args = parser.parse_args(argv)
    print(build_in_place(cc=args.cc) if args.in_place else build(args.output, cc=args.cc))


if __name__ == '__main__':
    main()
