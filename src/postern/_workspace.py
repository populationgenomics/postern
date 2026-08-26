"""Reference-closed access to a sandbox workspace.

The workspace is the one writable surface the untrusted guest and the trusted
host share, and it outlives the sandbox. A guest can plant, among the files it
owns, references that point *outside* the workspace — a symlink to an absolute
host path, ``/workspace/root -> /``, a symlink to ``/proc/self/environ``, a
FIFO. Inside the guest's mount namespace these are inert; the danger is entirely
on the *host* side, where a later read/tar/checkpoint/restore dereferences the
guest-planted reference in the host's own namespace and privileges and becomes a
confused deputy (exfiltrating host data, or writing through the link to a host
path outside the workspace).

`Workspace` is the host-side accessor that makes that impossible by construction.
It is a confined root: a capability to one directory subtree where every path
operation resolves one component at a time with ``O_NOFOLLOW`` relative to a
directory fd, so no symlink, ``..`` or absolute path a guest planted is ever
followed out of the tree, and no path string is re-resolved (TOCTOU-resistant).
It never hands back a dereferenceable host path. The model is Go 1.24's
``os.Root`` and Rust's ``cap-std::Dir``, built here on ``os.open`` with a
``dir_fd`` rather than on ``openat2(RESOLVE_BENEATH)``, which keeps it portable to
macOS and to kernels without ``openat2``.

`WorkspacePath` is a `pathlib`-like facade over the confined root (``ws / 'a/b'``,
``.iterdir()``, ``.open()``, ``.read_bytes()``, ``.walk()``).

Consumers get "read / pack / restore this workspace safely" as an API:

    with Workspace(sandbox.workspace) as ws:
        report = ws.pack_tar(open('snap.tar', 'wb'))   # only regular files + dirs
        ...
        ws.restore_tar(open('snap.tar', 'rb'))          # confined extraction

For consumers wedded to stock ``tarfile``, :func:`reference_closed_filter` plugs
into ``TarFile.extractall(path, filter=...)`` and refuses escaping/link/special
members. :meth:`Workspace.restore_tar` is stronger (it writes through the
confined root) and reports what it neutralized.

Pure stdlib, no third-party dependency, no mount privilege required — so it runs
on an unprivileged host (e.g. a Cloud Run container that cannot mount).
"""

from __future__ import annotations

import contextlib
import dataclasses
import os
import stat
import tarfile
import typing
from pathlib import Path, PurePosixPath

if typing.TYPE_CHECKING:
    from collections.abc import Iterator

    from typing_extensions import Self

# The anchor is host-trusted, so a symlinked prefix reaching it is fine; every
# component below it is opened O_NOFOLLOW.
_CLOEXEC = getattr(os, 'O_CLOEXEC', 0)
_ANCHOR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | _CLOEXEC
_DIR_FLAGS = _ANCHOR_FLAGS | os.O_NOFOLLOW


class WorkspaceError(RuntimeError):
    """A reference-closure violation: an escaping name or a neutralized entry.

    Raised when an operation would follow or create a reference out of the
    workspace (an absolute/``..`` name, an in-tree symlink opened for read/write),
    and when ``on_unsafe='error'`` meets a non-regular entry.
    """


@dataclasses.dataclass
class WorkspaceReport:
    """What a pack/restore neutralized rather than following.

    ``skipped`` is a list of ``(workspace-relative path, reason)`` — symlinks,
    hardlinks, FIFOs, sockets, device nodes, unreadable entries, or escaping member
    names that were dropped instead of dereferenced. It is never truncated, so
    ``ok`` (an empty list) means the whole tree was regular files and directories.
    """

    skipped: list[tuple[str, str]] = dataclasses.field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.skipped

    def _add(self, vpath: str, reason: str) -> None:
        self.skipped.append((vpath, reason))


def _split(rel: object) -> tuple[str, ...]:
    """Normalize a caller path into safe workspace-relative components.

    Args:
        rel: A `WorkspacePath`, a string, or an ``os.PathLike``.

    Returns:
        The path's components, with ``.`` and empty ones dropped.

    Raises:
        WorkspaceError: On an absolute path or any ``..`` component.
    """
    if isinstance(rel, WorkspacePath):
        return rel._parts
    text = os.fspath(rel) if isinstance(rel, os.PathLike) else str(rel)
    pure = PurePosixPath(text)
    if pure.is_absolute() or text.startswith('/'):
        raise WorkspaceError(f'absolute path escapes the workspace: {text!r}')
    parts: list[str] = []
    for comp in pure.parts:
        if comp in ('', '.', '/'):
            continue
        if comp == '..':
            raise WorkspaceError(f'".." escapes the workspace: {text!r}')
        parts.append(comp)
    return tuple(parts)


def _mode_kind(mode: int) -> str:
    """A human label for a non-regular st_mode (for the skip report)."""
    if stat.S_ISLNK(mode):
        return 'symlink'
    if stat.S_ISFIFO(mode):
        return 'fifo'
    if stat.S_ISSOCK(mode):
        return 'socket'
    if stat.S_ISBLK(mode) or stat.S_ISCHR(mode):
        return 'device'
    return 'special'


class Workspace:
    """A reference-closed confined root over one workspace directory.

    Open it on a workspace path (``Workspace(sandbox.workspace)``); use it as a
    context manager so the anchor fd is released, or call :meth:`close`. All
    traversal and IO is confined beneath the anchor by construction — see the
    module docstring.
    """

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self._root = Path(root)
        self._fd: int | None = os.open(self._root, _ANCHOR_FLAGS)

    @property
    def host_root(self) -> Path:
        """The anchor directory on the host: the trusted path the caller handed in.

        Child paths are never exposed this way — `WorkspacePath` raises from
        ``__fspath__`` — because a dereferenceable child path would re-open the
        escape this class exists to close.
        """
        return self._root

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        # Best-effort if the caller never closed: at interpreter teardown `os` may
        # already be gone.
        with contextlib.suppress(Exception):
            self.close()

    # -- confined primitives (parts = normalized tuple, never a path string) --

    def _anchor(self) -> int:
        if self._fd is None:
            raise WorkspaceError('workspace is closed')
        return self._fd

    def _open_dir(self, parts: tuple[str, ...]) -> int:
        """Open the directory at ``parts`` confined beneath the anchor.

        Each component is opened ``O_DIRECTORY | O_NOFOLLOW`` relative to its
        parent's fd, so a symlinked component fails rather than being traversed.

        Returns:
            A directory fd the caller owns and must close.
        """
        fd = os.dup(self._anchor())
        try:
            for comp in parts:
                nxt = os.open(comp, _DIR_FLAGS, dir_fd=fd)
                os.close(fd)
                fd = nxt
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _lstat(self, parts: tuple[str, ...]) -> os.stat_result:
        if not parts:
            return os.fstat(self._anchor())
        parent = self._open_dir(parts[:-1])
        try:
            return os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        finally:
            os.close(parent)

    def _listdir(self, parts: tuple[str, ...]) -> list[str]:
        fd = self._open_dir(parts)
        try:
            return os.listdir(fd)
        finally:
            os.close(fd)

    def _open_read_fd(self, parts: tuple[str, ...]) -> int:
        """Open a regular file for reading, refusing symlinks and specials.

        ``O_NOFOLLOW`` makes a final symlink component fail (``ELOOP``);
        ``O_NONBLOCK`` keeps a FIFO from blocking the open, and the ``S_ISREG``
        check then rejects any non-regular target.
        """
        if not parts:
            raise IsADirectoryError('workspace root is a directory')
        parent = self._open_dir(parts[:-1])
        try:
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | _CLOEXEC, dir_fd=parent)
        finally:
            os.close(parent)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise WorkspaceError(f'{"/".join(parts)!r} is not a regular file ({_mode_kind(st.st_mode)})')
        except BaseException:
            os.close(fd)
            raise
        os.set_blocking(fd, True)  # undo the O_NONBLOCK used to survive opening a FIFO
        return fd

    def _open_write_fd(self, parts: tuple[str, ...]) -> int:
        """Create/truncate a regular file for writing, never through a symlink.

        ``O_NOFOLLOW`` makes writing through an existing symlink at the final
        component fail (``ELOOP``).
        """
        if not parts:
            raise IsADirectoryError('workspace root is a directory')
        parent = self._open_dir(parts[:-1])
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | _CLOEXEC
        try:
            return os.open(parts[-1], flags, 0o600, dir_fd=parent)
        finally:
            os.close(parent)

    def _mkdir(self, parts: tuple[str, ...], *, parents: bool = False, exist_ok: bool = False) -> None:
        if not parts:
            return
        depths = range(len(parts)) if parents else (len(parts) - 1,)
        for depth in depths:
            sub = parts[: depth + 1]
            parent = self._open_dir(sub[:-1])
            try:
                os.mkdir(sub[-1], 0o700, dir_fd=parent)
            except FileExistsError:
                final = depth == len(parts) - 1
                st = os.stat(sub[-1], dir_fd=parent, follow_symlinks=False)
                if not stat.S_ISDIR(st.st_mode):
                    raise WorkspaceError(f'{"/".join(sub)!r} exists and is not a directory') from None
                if final and not exist_ok:
                    raise
            finally:
                os.close(parent)

    def _descendants(self, parts: tuple[str, ...]) -> Iterator[tuple[str, ...]]:
        """Yield every descendant's parts, parents before children, sorted."""
        for name in sorted(self._listdir(parts)):
            child = (*parts, name)
            yield child
            if stat.S_ISDIR(self._lstat(child).st_mode):
                yield from self._descendants(child)

    # -- pathlib-like facade entry points --

    @property
    def root(self) -> WorkspacePath:
        return WorkspacePath(self, ())

    def __truediv__(self, other: object) -> WorkspacePath:
        return WorkspacePath(self, _split(other))

    def iterdir(self) -> Iterator[WorkspacePath]:
        return self.root.iterdir()

    def walk(self) -> Iterator[tuple[WorkspacePath, list[str], list[str]]]:
        return self.root.walk()

    # -- consumers (thin: tar is just one) --

    def pack_tar(
        self,
        fileobj: typing.BinaryIO,
        *,
        on_unsafe: str = 'skip',
        compression: str = '',
        exclude: typing.Callable[[str], bool] | None = None,
    ) -> WorkspaceReport:
        """Write the workspace tree to ``fileobj`` as a tar of regular files+dirs.

        Only regular files and directories are archived, so the result is
        reference-closed: any consumer can extract it anywhere without following a
        reference out of the tree. Symlinks, FIFOs, sockets and device nodes are
        neutralized rather than dereferenced, and so is a hardlink whose link count
        is not fully accounted for inside the workspace — its inode is named
        outside the tree too, the one case a confined open cannot distinguish from
        an ordinary file.

        Args:
            fileobj: Binary stream the archive is written to.
            on_unsafe: ``'skip'`` records a neutralized entry in the report;
                ``'error'`` raises on the first.
            compression: A ``tarfile`` stream suffix (``'gz'``, ``'bz2'``,
                ``'xz'``) or ``''``.
            exclude: Called with each entry's workspace-relative POSIX path; a
                true result skips the entry and, for a directory, its subtree.

        Returns:
            The :class:`WorkspaceReport` audit trail. Nothing is dropped silently.

        Raises:
            WorkspaceError: On the first neutralized entry when
                ``on_unsafe='error'``.
        """
        report = WorkspaceReport()
        entries = [(parts, self._lstat(parts)) for parts in self._descendants(())]
        # Names inside the workspace per multiply-linked inode; fewer than
        # st_nlink means some links lie outside the tree.
        inside: dict[tuple[int, int], int] = {}
        for _parts, st in entries:
            if stat.S_ISREG(st.st_mode) and st.st_nlink > 1:
                key = (st.st_dev, st.st_ino)
                inside[key] = inside.get(key, 0) + 1
        pruned: list[str] = []
        mode = typing.cast('typing.Any', f'w|{compression}' if compression else 'w')
        with tarfile.open(fileobj=fileobj, mode=mode) as tar:
            for parts, st in entries:
                name = '/'.join(parts)
                if any(name == p or name.startswith(p + '/') for p in pruned):
                    continue  # inside an excluded (undescended) directory
                if exclude is not None and exclude(name):
                    pruned.append(name)
                    continue
                if stat.S_ISDIR(st.st_mode):
                    tar.addfile(self._tarinfo(name, st, tarfile.DIRTYPE))
                elif stat.S_ISREG(st.st_mode):
                    key = (st.st_dev, st.st_ino)
                    if st.st_nlink > 1 and inside.get(key, 0) < st.st_nlink:
                        self._flag(report, name, 'hardlink', on_unsafe)
                    else:
                        self._pack_regular(tar, parts, name, report, on_unsafe)
                else:
                    self._flag(report, name, _mode_kind(st.st_mode), on_unsafe)
        return report

    @staticmethod
    def _flag(report: WorkspaceReport, name: str, reason: str, on_unsafe: str) -> None:
        report._add(name, reason)
        if on_unsafe == 'error':
            raise WorkspaceError(f'neutralized {reason} entry {name!r}')

    def _pack_regular(
        self, tar: tarfile.TarFile, parts: tuple[str, ...], name: str, report: WorkspaceReport, on_unsafe: str
    ) -> None:
        try:
            fd = self._open_read_fd(parts)
        except (OSError, WorkspaceError):
            # The entry changed type or vanished since the walk. O_NOFOLLOW means
            # nothing was followed out, so record it and keep going.
            self._flag(report, name, 'unreadable', on_unsafe)
            return
        with os.fdopen(fd, 'rb') as src:
            # Size from the open fd, not the earlier lstat: a concurrent truncation
            # would otherwise desync the tar header from the bytes written.
            tar.addfile(self._tarinfo(name, os.fstat(fd), tarfile.REGTYPE), src)

    @staticmethod
    def _tarinfo(name: str, st: os.stat_result, kind: bytes) -> tarfile.TarInfo:
        info = tarfile.TarInfo(name)
        info.type = kind
        info.mode = stat.S_IMODE(st.st_mode) & ~(stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)
        info.mtime = int(st.st_mtime)
        info.size = st.st_size if kind == tarfile.REGTYPE else 0
        # Normalize the guest's uid out so the archive restores under any host uid.
        info.uid = info.gid = 0
        info.uname = info.gname = ''
        return info

    def restore_tar(
        self,
        fileobj: typing.BinaryIO,
        *,
        on_unsafe: str = 'skip',
        max_entries: int | None = None,
        max_bytes: int | None = None,
    ) -> WorkspaceReport:
        """Extract a tar into the workspace through the confined root.

        Only regular-file and directory members are created, each via an
        ``O_NOFOLLOW`` confined open, so extraction never writes *through* a
        symlink — pre-existing or planted. That is stronger than a stock
        ``extractall`` even with :func:`reference_closed_filter`, which vets members
        but leaves the writes to ``tarfile``.

        Args:
            fileobj: Binary stream the archive is read from.
            on_unsafe: ``'skip'`` records a neutralized member in the report;
                ``'error'`` raises on the first.
            max_entries: Member-count ceiling, or ``None`` for no limit.
            max_bytes: Extracted-byte ceiling, or ``None`` for no limit.

        Returns:
            The :class:`WorkspaceReport` audit trail.

        Raises:
            WorkspaceError: Once ``max_entries`` or ``max_bytes`` is exceeded, and
                on the first neutralized member when ``on_unsafe='error'``.
        """
        report = WorkspaceReport()
        written = [0]
        with tarfile.open(fileobj=fileobj, mode='r|*') as tar:
            for count, member in enumerate(tar, start=1):
                if max_entries is not None and count > max_entries:
                    raise WorkspaceError(f'archive exceeds max_entries={max_entries}')
                self._restore_member(tar, member, report, on_unsafe, max_bytes, written)
        return report

    def _restore_member(
        self,
        tar: tarfile.TarFile,
        member: tarfile.TarInfo,
        report: WorkspaceReport,
        on_unsafe: str,
        max_bytes: int | None,
        written: list[int],
    ) -> None:
        try:
            parts = _split(member.name)
        except WorkspaceError:
            report._add(member.name, 'escaping-name')
            if on_unsafe == 'error':
                raise
            return
        if not parts:
            return
        if member.isdir():
            self._mkdir(parts, parents=True, exist_ok=True)
            return
        if member.isreg():
            self._mkdir(parts[:-1], parents=True, exist_ok=True)
            src = tar.extractfile(member)
            fd = self._open_write_fd(parts)
            with os.fdopen(fd, 'wb') as dst:
                if src is not None:
                    self._copy_capped(src, dst, written, max_bytes)
            return
        kind = 'symlink' if member.issym() else 'hardlink' if member.islnk() else 'special'
        report._add(member.name, kind)
        if on_unsafe == 'error':
            raise WorkspaceError(f'non-regular member {member.name!r} ({kind})')

    @staticmethod
    def _copy_capped(src: typing.IO[bytes], dst: typing.IO[bytes], written: list[int], max_bytes: int | None) -> None:
        while True:
            chunk = src.read(65536)
            if not chunk:
                return
            written[0] += len(chunk)
            if max_bytes is not None and written[0] > max_bytes:
                raise WorkspaceError(f'archive exceeds max_bytes={max_bytes}')
            dst.write(chunk)


@dataclasses.dataclass(frozen=True)
class WorkspacePath:
    """A `pathlib`-like handle to one path within a `Workspace`, confined.

    Join with ``/`` (``ws / 'sub' / 'file'``); read, write and traverse with the
    familiar methods. ``__fspath__`` raises rather than returning a path, so the
    handle cannot be passed to ``open()`` to escape the confined root.
    """

    workspace: Workspace
    _parts: tuple[str, ...]

    def __truediv__(self, other: object) -> WorkspacePath:
        return WorkspacePath(self.workspace, self._parts + _split(other))

    def __str__(self) -> str:
        return '/'.join(self._parts) or '.'

    def __repr__(self) -> str:
        return f'WorkspacePath({str(self)!r})'

    def __fspath__(self) -> str:
        raise TypeError('WorkspacePath is a confined handle with no dereferenceable host path; use its IO methods')

    @property
    def name(self) -> str:
        return self._parts[-1] if self._parts else ''

    def lstat(self) -> os.stat_result:
        return self.workspace._lstat(self._parts)

    def exists(self) -> bool:
        """Whether the path exists, counting a dangling symlink (``lexists``).

        Total rather than raising: a path behind a guest-planted symlinked
        directory (``ELOOP``/``ENOTDIR``) reads as absent.
        """
        try:
            self.workspace._lstat(self._parts)
        except OSError:
            return False
        return True

    def _is(self, predicate: typing.Callable[[int], bool]) -> bool:
        try:
            return predicate(self.workspace._lstat(self._parts).st_mode)
        except OSError:
            return False

    def is_dir(self) -> bool:
        return self._is(stat.S_ISDIR)

    def is_file(self) -> bool:
        return self._is(stat.S_ISREG)

    def is_symlink(self) -> bool:
        return self._is(stat.S_ISLNK)

    def iterdir(self) -> Iterator[WorkspacePath]:
        for name in sorted(self.workspace._listdir(self._parts)):
            yield WorkspacePath(self.workspace, (*self._parts, name))

    def walk(self) -> Iterator[tuple[WorkspacePath, list[str], list[str]]]:
        """Like `pathlib.Path.walk` (never follows symlinks).

        Only real directories go in ``dirnames`` and are descended; symlinks
        (even to directories), FIFOs, sockets and devices go in ``filenames``.
        """
        stack = [self._parts]
        while stack:
            parts = stack.pop()
            dirnames: list[str] = []
            filenames: list[str] = []
            for name in sorted(self.workspace._listdir(parts)):
                if stat.S_ISDIR(self.workspace._lstat((*parts, name)).st_mode):
                    dirnames.append(name)
                else:
                    filenames.append(name)
            yield WorkspacePath(self.workspace, parts), dirnames, filenames
            for name in reversed(dirnames):
                stack.append((*parts, name))

    def open(self, mode: str = 'rb') -> typing.BinaryIO:
        if mode in ('rb', 'r'):
            return typing.cast('typing.BinaryIO', os.fdopen(self.workspace._open_read_fd(self._parts), 'rb'))
        if mode in ('wb', 'w'):
            return typing.cast('typing.BinaryIO', os.fdopen(self.workspace._open_write_fd(self._parts), 'wb'))
        raise ValueError(f'unsupported mode {mode!r}; use rb or wb')

    def read_bytes(self) -> bytes:
        with self.open('rb') as handle:
            return handle.read()

    def read_text(self, encoding: str = 'utf-8') -> str:
        return self.read_bytes().decode(encoding)

    def write_bytes(self, data: bytes) -> int:
        with self.open('wb') as handle:
            return handle.write(data)

    def write_text(self, text: str, encoding: str = 'utf-8') -> int:
        return self.write_bytes(text.encode(encoding))


def reference_closed_filter(member: tarfile.TarInfo, path: str) -> tarfile.TarInfo:
    """A ``TarFile.extractall(filter=...)`` hook that vets members for closure.

    Setuid/setgid/sticky bits are stripped, so the *archive* cannot introduce an
    out-of-tree reference or create one on disk.

    Scope: a filter only vets members, and stock ``extractall`` still does the
    writes — following a symlink that already exists in the destination. Safe only
    into a fresh host-controlled directory; for a workspace a guest may have
    touched, use :meth:`Workspace.restore_tar`, which writes through the confined
    root and reports rather than aborting.

    Args:
        member: The member ``tarfile`` is about to extract.
        path: The destination directory, unused — confinement here is by member
            vetting, not by the destination.

    Returns:
        The member with its setuid/setgid/sticky bits cleared.

    Raises:
        WorkspaceError: On an absolute or ``..`` name, or a symlink, hardlink,
            FIFO, socket or device member. Extraction aborts.
    """
    del path
    _split(member.name)  # raises WorkspaceError on an absolute or ".." name
    if not (member.isreg() or member.isdir()):
        kind = 'symlink' if member.issym() else 'hardlink' if member.islnk() else 'special'
        raise WorkspaceError(f'non-regular member {member.name!r} ({kind})')
    clean = member.replace(deep=False) if hasattr(member, 'replace') else member
    clean.mode = member.mode & ~(stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)
    return clean
