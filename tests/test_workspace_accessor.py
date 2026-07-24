"""Reference-closure tests for the host-side `Workspace` accessor.

These plant, in a workspace directory, exactly the hostile references a guest
could leave behind — a symlink to an absolute host path, a symlink to
``/proc/self/environ``, ``root -> /``, a FIFO — and assert the accessor never
follows one out of the tree nor exposes its target, whether reading, walking,
packing, or restoring. They are OS-filesystem tests (no bubblewrap), so they run
anywhere ``O_NOFOLLOW`` + ``dir_fd`` work (Linux and macOS).
"""

from __future__ import annotations

import io
import os
import tarfile

import pytest

from postern import Workspace, WorkspaceError, reference_closed_filter


@pytest.fixture
def secret(tmp_path):
    """A host file *outside* the workspace that must never be exposed."""
    path = tmp_path / 'host_secret'
    path.write_text('TOP-SECRET-HOST-TOKEN')
    return path


@pytest.fixture
def ws_dir(tmp_path):
    d = tmp_path / 'workspace'
    d.mkdir()
    return d


def _plant_hostile(ws_dir, secret):
    """Plant the canonical booby-traps a guest could leave in a workspace."""
    (ws_dir / 'good.txt').write_text('legitimate guest output')
    sub = ws_dir / 'sub'
    sub.mkdir()
    (sub / 'nested.txt').write_text('nested output')
    os.symlink(str(secret), ws_dir / 'abs_link')  # -> /abs/host/host_secret
    os.symlink('/proc/self/environ', ws_dir / 'environ_link')
    os.symlink('/', ws_dir / 'root')  # /workspace/root -> /
    os.symlink('../../host_secret', ws_dir / 'rel_escape')  # climbs out via ..
    os.symlink('/etc', ws_dir / 'dir_link')  # symlink to a directory
    os.mkfifo(ws_dir / 'fifo')


def test_walk_surfaces_but_never_follows_references(ws_dir, secret):
    _plant_hostile(ws_dir, secret)
    with Workspace(ws_dir) as ws:
        # The dir symlink and root symlink are NOT descended (they'd be dirs if
        # followed); they appear as non-directory entries only.
        assert not (ws / 'root').is_dir()
        assert (ws / 'root').is_symlink()
        assert not (ws / 'dir_link').is_dir()
        # Real nested dir *is* traversed.
        assert (ws / 'sub' / 'nested.txt').read_text() == 'nested output'


@pytest.mark.parametrize('link', ['abs_link', 'environ_link', 'root', 'rel_escape', 'dir_link'])
def test_read_refuses_to_follow_symlink(ws_dir, secret, link):
    _plant_hostile(ws_dir, secret)
    with Workspace(ws_dir) as ws:
        with pytest.raises((OSError, WorkspaceError)) as exc:
            (ws / link).read_bytes()
        # Whatever the failure, the host secret is never in the surfaced bytes.
        assert 'TOP-SECRET' not in str(exc.value)


def test_read_through_dir_symlink_is_blocked(ws_dir, secret):
    _plant_hostile(ws_dir, secret)
    with Workspace(ws_dir) as ws:
        # `root -> /`, so `root/etc/passwd` would escape to the host root.
        with pytest.raises((OSError, WorkspaceError)):
            (ws / 'root' / 'etc' / 'passwd').read_bytes()
        # `dir_link -> /etc`, so `dir_link/passwd` would escape too.
        with pytest.raises((OSError, WorkspaceError)):
            (ws / 'dir_link' / 'passwd').read_bytes()


def test_read_regular_file_still_works(ws_dir, secret):
    _plant_hostile(ws_dir, secret)
    with Workspace(ws_dir) as ws:
        assert (ws / 'good.txt').read_bytes() == b'legitimate guest output'


def test_escaping_virtual_paths_rejected(ws_dir):
    with Workspace(ws_dir) as ws:
        for bad in ['/etc/passwd', '../escape', 'a/../../b', 'sub/../../x']:
            with pytest.raises(WorkspaceError):
                _ = ws / bad


def test_pack_tar_excludes_all_references(ws_dir, secret):
    _plant_hostile(ws_dir, secret)
    buf = io.BytesIO()
    with Workspace(ws_dir) as ws:
        report = ws.pack_tar(buf)
    buf.seek(0)
    with tarfile.open(fileobj=buf) as tar:
        members = tar.getmembers()
        names = {m.name for m in members}
        # Only regular files and dirs — reference-closed by construction.
        assert all(m.isreg() or m.isdir() for m in members), names
        assert 'good.txt' in names
        assert 'sub' in names
        assert 'sub/nested.txt' in names
        # No symlink/fifo entries at all.
        for planted in ('abs_link', 'environ_link', 'root', 'rel_escape', 'dir_link', 'fifo'):
            assert planted not in names
        # And the secret's contents are nowhere in the archive bytes.
        assert b'TOP-SECRET-HOST-TOKEN' not in buf.getvalue()
    # The report is the audit trail of what was neutralized (never silent).
    reasons = dict(report.skipped)
    assert reasons['abs_link'] == 'symlink'
    assert reasons['fifo'] == 'fifo'
    assert not report.ok


def test_pack_tar_on_unsafe_error_raises(ws_dir, secret):
    _plant_hostile(ws_dir, secret)
    with Workspace(ws_dir) as ws, pytest.raises(WorkspaceError):
        ws.pack_tar(io.BytesIO(), on_unsafe='error')


def test_pack_restore_roundtrip(ws_dir, secret, tmp_path):
    _plant_hostile(ws_dir, secret)
    buf = io.BytesIO()
    with Workspace(ws_dir) as ws:
        ws.pack_tar(buf)
    buf.seek(0)
    dest = tmp_path / 'restored'
    dest.mkdir()
    with Workspace(dest) as ws:
        ws.restore_tar(buf)
        assert (ws / 'good.txt').read_bytes() == b'legitimate guest output'
        assert (ws / 'sub' / 'nested.txt').read_text() == 'nested output'
    assert not (dest / 'abs_link').exists()
    assert not (dest / 'fifo').exists()


def _malicious_tar() -> io.BytesIO:
    """A tar crafted to escape on a naive extractall."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w') as tar:
        # absolute-path member
        info = tarfile.TarInfo('/tmp/pwned')  # noqa: S108
        data = b'escaped'
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
        # parent-traversal member
        info = tarfile.TarInfo('../escaped_parent')
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
        # symlink member pointing at the host root
        link = tarfile.TarInfo('link_to_root')
        link.type = tarfile.SYMTYPE
        link.linkname = '/'
        tar.addfile(link)
        # a legitimate file
        good = tarfile.TarInfo('ok.txt')
        good.size = 2
        tar.addfile(good, io.BytesIO(b'hi'))
    buf.seek(0)
    return buf


def test_restore_tar_neutralizes_malicious_members(tmp_path):
    dest = tmp_path / 'restored'
    dest.mkdir()
    with Workspace(dest) as ws:
        report = ws.restore_tar(_malicious_tar())
        assert (ws / 'ok.txt').read_bytes() == b'hi'
    # Nothing escaped the destination.
    assert not (tmp_path / 'escaped_parent').exists()
    assert not os.path.exists('/tmp/pwned')  # noqa: S108
    assert not (dest / 'link_to_root').exists()
    reasons = {name for name, _ in report.skipped}
    assert '/tmp/pwned' in reasons or 'pwned' in str(report.skipped)  # noqa: S108
    assert 'link_to_root' in reasons


def test_restore_tar_will_not_write_through_planted_symlink(tmp_path, secret):
    """A restore must not follow an in-tree symlink to clobber a host file."""
    dest = tmp_path / 'restored'
    dest.mkdir()
    # Pre-existing symlink in the destination (as if left by a prior guest).
    os.symlink(str(secret), dest / 'target')
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w') as tar:
        info = tarfile.TarInfo('target')  # collides with the symlink name
        payload = b'OVERWRITE'
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    buf.seek(0)
    # O_NOFOLLOW makes the confined write fail (ELOOP) rather than follow the link.
    with Workspace(dest) as ws, pytest.raises(OSError, match=r'.'):
        ws.restore_tar(buf, on_unsafe='error')
    # The host secret behind the symlink is untouched.
    assert secret.read_text() == 'TOP-SECRET-HOST-TOKEN'


def test_reference_closed_filter_rejects_links_and_escapes():
    for name in ['/abs', '../up']:
        m = tarfile.TarInfo(name)
        m.size = 0
        with pytest.raises(WorkspaceError):
            reference_closed_filter(m, '/dest')
    sym = tarfile.TarInfo('l')
    sym.type = tarfile.SYMTYPE
    sym.linkname = '/etc'
    with pytest.raises(WorkspaceError):
        reference_closed_filter(sym, '/dest')


def test_reference_closed_filter_passes_regular(tmp_path):
    m = tarfile.TarInfo('sub/ok.txt')
    m.size = 3
    m.mode = 0o4777  # setuid + world-writable
    out = reference_closed_filter(m, str(tmp_path))
    assert out.mode & 0o4000 == 0  # setuid stripped
    assert out.name == 'sub/ok.txt'


def test_reference_closed_filter_used_by_stock_extractall(tmp_path):
    """The filter plugs into stock tarfile.extractall and blocks the escape."""
    dest = tmp_path / 'out'
    dest.mkdir()
    buf = _malicious_tar()
    with tarfile.open(fileobj=buf) as tar, pytest.raises(WorkspaceError):
        tar.extractall(dest, filter=reference_closed_filter)  # noqa: S202


def test_pack_tar_neutralizes_escaping_hardlink(ws_dir, secret):
    # A hardlink inside the workspace to a file OUTSIDE it: the inode is also
    # named outside, so its content is shared out of bounds. pack must not copy
    # it out, and must record the neutralization (never silent).
    os.link(str(secret), ws_dir / 'innocent.txt')  # secret nlink 1 -> 2
    (ws_dir / 'real.txt').write_text('legit')
    buf = io.BytesIO()
    with Workspace(ws_dir) as ws:
        report = ws.pack_tar(buf)
    assert b'TOP-SECRET-HOST-TOKEN' not in buf.getvalue()
    assert dict(report.skipped).get('innocent.txt') == 'hardlink'
    buf.seek(0)
    with tarfile.open(fileobj=buf) as tar:
        names = {m.name for m in tar.getmembers()}
    assert 'real.txt' in names
    assert 'innocent.txt' not in names


def test_pack_tar_keeps_internal_hardlink(ws_dir):
    # Two names inside the workspace for one inode: fully accounted for within
    # the tree, so it is safe and both are packed.
    (ws_dir / 'a.txt').write_text('shared')
    os.link(ws_dir / 'a.txt', ws_dir / 'b.txt')
    buf = io.BytesIO()
    with Workspace(ws_dir) as ws:
        report = ws.pack_tar(buf)
    assert report.ok
    buf.seek(0)
    with tarfile.open(fileobj=buf) as tar:
        names = {m.name for m in tar.getmembers()}
    assert {'a.txt', 'b.txt'} <= names


def test_pack_tar_exclude_prunes_subtree(ws_dir):
    (ws_dir / 'keep.txt').write_text('keep')
    (ws_dir / 'document.md').write_text('doc')
    skills = ws_dir / 'skills'
    skills.mkdir()
    (skills / 'x.py').write_text('code')
    buf = io.BytesIO()
    with Workspace(ws_dir) as ws:
        # Exclude only the dir itself; its children must be pruned too.
        ws.pack_tar(buf, exclude=lambda p: p in ('document.md', 'skills'))
    buf.seek(0)
    with tarfile.open(fileobj=buf) as tar:
        names = {m.name for m in tar.getmembers()}
    assert 'keep.txt' in names
    assert 'document.md' not in names
    assert not any(n == 'skills' or n.startswith('skills/') for n in names)


def test_pack_tar_skips_unreadable_entry_without_aborting(ws_dir, monkeypatch):
    # A concurrent type-swap makes the confined open fail; pack must record it
    # and continue, not abort the whole archive (on_unsafe='skip').
    (ws_dir / 'a.txt').write_text('a')
    (ws_dir / 'b.txt').write_text('b')
    buf = io.BytesIO()
    with Workspace(ws_dir) as ws:
        real_open = ws._open_read_fd

        def flaky(parts):
            if parts == ('a.txt',):
                raise OSError('raced')
            return real_open(parts)

        monkeypatch.setattr(ws, '_open_read_fd', flaky)
        report = ws.pack_tar(buf)
    assert dict(report.skipped).get('a.txt') == 'unreadable'
    buf.seek(0)
    with tarfile.open(fileobj=buf) as tar:
        assert 'b.txt' in {m.name for m in tar.getmembers()}


def _tar_of_files(n, size):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w') as tar:
        for i in range(n):
            info = tarfile.TarInfo(f'f{i}.txt')
            data = b'x' * size
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    buf.seek(0)
    return buf


def test_restore_tar_max_entries(tmp_path):
    dest = tmp_path / 'd'
    dest.mkdir()
    with Workspace(dest) as ws, pytest.raises(WorkspaceError, match='max_entries'):
        ws.restore_tar(_tar_of_files(5, 10), max_entries=3)


def test_restore_tar_max_bytes(tmp_path):
    dest = tmp_path / 'd'
    dest.mkdir()
    with Workspace(dest) as ws, pytest.raises(WorkspaceError, match='max_bytes'):
        ws.restore_tar(_tar_of_files(5, 100), max_bytes=250)  # 500 bytes total


def test_restore_tar_within_caps_ok(tmp_path):
    dest = tmp_path / 'd'
    dest.mkdir()
    with Workspace(dest) as ws:
        report = ws.restore_tar(_tar_of_files(3, 10), max_entries=10, max_bytes=1000)
        assert report.ok
        assert (ws / 'f0.txt').read_bytes() == b'x' * 10
