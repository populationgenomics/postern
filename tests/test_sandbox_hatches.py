"""Sandbox hatch wiring: opt-in, several at once, and no colliding guest paths.

Construction-only (no bubblewrap): the normalization and validation live in
__init__, and the bind/env derivation is a pure function of the hatch objects —
neither needs a launch. The bwrap end of the same wiring is covered by the e2e
suites.
"""

import contextlib

import pytest

from postern import Sandbox
from postern._sandbox import _GUEST_SOCK, GUEST_CONNECT, guest_env_var, guest_socket_path


class _FakeHatch:
    """A minimal Hatch: the unnamed singleton, bound at POSTERN_HATCH."""

    def __init__(self, path='/tmp/postern-fake.sock'):  # noqa: S108 — not opened, just a path
        self._path = path

    @property
    def socket_path(self):
        return self._path

    @contextlib.contextmanager
    def accepting(self):
        yield self


class _FakeNamedHatch(_FakeHatch):
    """A named hatch, as StreamHatch is: its own guest socket and env var."""

    def __init__(self, name, path=None):
        super().__init__(path or f'/tmp/postern-{name}.sock')  # noqa: S108 — not opened
        self.guest_name = name


class _FakeConnectorHatch(_FakeNamedHatch):
    guest_connector = True


# -- opt-in ------------------------------------------------------------------ #
def test_no_hatch_opens_no_channel():
    sandbox = Sandbox()
    assert sandbox._hatches == []
    binds, env = sandbox._hatch_wiring()
    sandbox.close()
    assert binds == []
    assert env == {}


def test_single_hatch_is_normalized_to_a_list():
    hatch = _FakeHatch()
    sandbox = Sandbox(hatch=hatch)
    assert sandbox._hatches == [hatch]
    sandbox.close()


def test_unnamed_hatch_keeps_the_legacy_socket_and_env_var():
    # GrpcHatch declares no name, so nothing about its wiring changes.
    sandbox = Sandbox(hatch=_FakeHatch())
    binds, env = sandbox._hatch_wiring()
    sandbox.close()
    assert binds == ['--bind', '/tmp/postern-fake.sock', _GUEST_SOCK]  # noqa: S108
    assert env == {'POSTERN_HATCH': _GUEST_SOCK}


def test_two_unnamed_hatches_are_rejected():
    with pytest.raises(ValueError, match='unnamed'):
        Sandbox(hatch=[_FakeHatch(), _FakeHatch()])


# -- named hatches: several of a kind, one socket per resource --------------- #
def test_several_named_hatches_are_allowed():
    # The point of naming: a stream hatch per resource, which a single-hatch
    # sandbox could not express.
    a, b, c = _FakeNamedHatch('repo_a'), _FakeNamedHatch('repo_b'), _FakeNamedHatch('repo_c')
    sandbox = Sandbox(hatch=[a, b, c])
    assert sandbox._hatches == [a, b, c]
    sandbox.close()


def test_named_hatches_coexist_with_the_unnamed_one():
    sandbox = Sandbox(hatch=[_FakeHatch(), _FakeNamedHatch('repo')])
    binds, env = sandbox._hatch_wiring()
    sandbox.close()
    assert env['POSTERN_HATCH'] == _GUEST_SOCK
    assert env['POSTERN_HATCH_REPO'] == guest_socket_path('repo')
    # Every guest path is distinct, or one bind would shadow another.
    bound = [binds[i + 2] for i in range(0, len(binds), 3)]
    assert len(set(bound)) == len(bound)


def test_a_named_hatch_does_not_consume_the_unnamed_slot():
    sandbox = Sandbox(hatch=[_FakeHatch(), _FakeNamedHatch('repo')])
    sandbox.close()  # no ValueError: only the *unnamed* hatch is a singleton


def test_duplicate_hatch_names_are_rejected():
    # Two hatches of the same name collide on every derived artefact at once; the
    # guest socket path is the one reported first because it is the one that would
    # have silently shadowed a bind.
    with pytest.raises(ValueError, match='must not share guest socket paths'):
        Sandbox(hatch=[_FakeNamedHatch('repo'), _FakeNamedHatch('repo')])


def test_env_var_and_socket_are_derived_from_the_name():
    assert guest_env_var('repo') == 'POSTERN_HATCH_REPO'
    assert guest_socket_path('repo') == '/run/postern/repo.sock'


@pytest.mark.parametrize('name', ['has-dash', '../escape', 'a/b', '', '1st', 'with space'])
def test_unusable_hatch_names_are_refused(name):
    # A name is a path component and an env-var tail, so anything that could
    # escape /run/postern or collide after upper-casing is refused outright.
    with pytest.raises(ValueError, match='identifier'):
        Sandbox(hatch=_FakeNamedHatch(name))


# -- the in-guest connector -------------------------------------------------- #
def test_connector_is_bound_only_when_a_hatch_asks_for_it():
    plain = Sandbox(hatch=_FakeNamedHatch('repo'))
    binds, env = plain._hatch_wiring()
    plain.close()
    assert GUEST_CONNECT not in binds
    assert 'POSTERN_CONNECT' not in env

    wanting = Sandbox(hatch=_FakeConnectorHatch('repo'))
    binds, env = wanting._hatch_wiring()
    wanting.close()
    assert env['POSTERN_CONNECT'] == GUEST_CONNECT
    assert binds[-3:] == ['--ro-bind', binds[-2], GUEST_CONNECT]


def test_connector_is_bound_once_for_many_hatches():
    sandbox = Sandbox(hatch=[_FakeConnectorHatch('a'), _FakeConnectorHatch('b')])
    binds, _ = sandbox._hatch_wiring()
    sandbox.close()
    assert binds.count(GUEST_CONNECT) == 1


# -- run() gets the same wiring as run_python() ----------------------------- #
def test_hatch_wiring_is_independent_of_the_entrypoint():
    # run() previously bound no hatch at all; both entrypoints now share one
    # wiring helper, so a bare argv has the same capabilities as guest Python.
    sandbox = Sandbox(hatch=[_FakeNamedHatch('repo'), _FakeHatch()])
    binds, env = sandbox._hatch_wiring()
    sandbox.close()
    assert binds[:3] == ['--bind', '/tmp/postern-repo.sock', guest_socket_path('repo')]  # noqa: S108
    assert set(env) == {'POSTERN_HATCH_REPO', 'POSTERN_HATCH'}
