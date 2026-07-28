"""Sandbox hatch wiring: opt-in, both-channels, and path uniqueness.

Construction-only (no bubblewrap): the normalization + validation live in
__init__, and host-side socket uniqueness is a property of the hatch objects —
neither needs a launch. The end-to-end bind/env wiring is covered on Linux.
"""

import contextlib

import pytest

from postern import Sandbox
from postern._sandbox import _GUEST_PROXY_SOCK, _GUEST_SOCK
from postern.http import HttpHatch, allow_hosts


class _FakeHatch:
    """A minimal Hatch: a dial hatch unless guest_proxy is set."""

    guest_proxy = False

    def __init__(self, path='/tmp/postern-fake.sock'):  # noqa: S108 — not opened, just a path
        self._path = path

    @property
    def socket_path(self):
        return self._path

    @contextlib.contextmanager
    def accepting(self):
        yield self


class _FakeProxyHatch(_FakeHatch):
    guest_proxy = True


def test_no_hatch_opens_no_channel():
    sandbox = Sandbox()
    assert sandbox._hatches == []
    sandbox.close()


def test_single_hatch_is_normalized_to_a_list():
    hatch = _FakeHatch()
    sandbox = Sandbox(hatch=hatch)
    assert sandbox._hatches == [hatch]
    sandbox.close()


def test_dial_and_proxy_hatch_together_are_allowed():
    dial, proxy = _FakeHatch(), _FakeProxyHatch()
    sandbox = Sandbox(hatch=[dial, proxy])
    assert sandbox._hatches == [dial, proxy]
    sandbox.close()


def test_two_proxy_hatches_are_rejected():
    with pytest.raises(ValueError, match='proxy'):
        Sandbox(hatch=[_FakeProxyHatch(), _FakeProxyHatch()])


def test_two_dial_hatches_are_rejected():
    with pytest.raises(ValueError, match='dial'):
        Sandbox(hatch=[_FakeHatch(), _FakeHatch()])


def test_guest_socket_paths_are_distinct():
    # Both channels can be present at once only because they bind different
    # guest paths; a shared path would shadow one bind.
    assert _GUEST_SOCK != _GUEST_PROXY_SOCK


def test_host_socket_paths_are_unique_per_instance():
    # Two concurrent callers each get their own host socket (mkdtemp 0700 dir),
    # so distinct hatch instances never collide on the host.
    a, b = HttpHatch(allow_hosts(set())), HttpHatch(allow_hosts(set()))
    try:
        assert a.socket_path != b.socket_path
    finally:
        a.close()
        b.close()
