# Python style

The human-judgement layer for Python in postern. Mechanical formatting and naming are enforced by [ruff]; the select
list and per-file ignores in [`../../pyproject.toml`](../../pyproject.toml) are the source of truth for those and are
not restated here. If something here contradicts ruff, ruff wins and this doc is wrong.

Largely lifted from the [Google Python Style Guide][pyguide] (CC-BY-3.0), cut down to what ruff does not already cover.

## Imports

**Import modules, not symbols.** Use `import x` to bring in a package or module. Use `from x import y` only when `y` is
itself a module (i.e. `x` is the package prefix). Do not use `from x import y` to bring in a class, function, constant,
or other symbol.

Why: at the call site, a qualified reference (`module.Thing`) makes it clear where `Thing` came from. A bare `Thing` is
ambiguous to a reader — and to an AI assistant navigating the code — without scrolling to the import block.

```python
# Good
import dataclasses
import pathlib

path = pathlib.Path('/etc/hostname')


@dataclasses.dataclass
class Record:
    name: str


# Bad — symbols pulled out of their module
from dataclasses import dataclass
from pathlib import Path

path = Path('/etc/hostname')


@dataclass
class Record:
    name: str
```

The cost is a little extra typing at call sites. It's worth it.

### Carved-out exceptions

- Names from `typing` (`Any`, `Protocol`, `TypeVar`, `NoReturn`, …) and from `collections.abc` (`Iterator`, `Iterable`,
  `Mapping`, `Sequence`, `Callable`, …). These are language vocabulary; qualifying them adds noise without clarity.
- `from __future__ import ...` — future-statement syntax, not a normal import.
- The re-exports in [`../../src/postern/__init__.py`](../../src/postern/__init__.py). That file *is* the public API
  surface; naming each exported symbol is its job.
- Tests and examples importing postern's own public API (`from postern import Sandbox`), which reads as the consumer
  code it stands in for.

Anything else — `pathlib.Path`, `dataclasses.dataclass`, `contextlib.contextmanager`, a class from another module in
this package — goes through its module.

### No `TYPE_CHECKING` blocks

Don't use `from typing import TYPE_CHECKING` to gate type-only imports. This is policy, not lint (ruff's `TC` rules are
not selected here). The pattern is a two-tier import structure that almost always papers over a problem better fixed
elsewhere:

- If the import is type-only because of a *circular import*, the abstractions are usually wrong. Restructure.
- If the import is type-only because the module is not installed at run time, that is a real exception — keep the block
  and say why on the line above it. postern has exactly one: `typing_extensions.Self`, a type-check-only backport for
  the 3.10 floor that must not become a runtime dependency of a package whose core has none.

For everything else (`Iterator`, `Sequence` from `collections.abc`), import at module level. The runtime cost is
nothing, and `from __future__ import annotations` means an unused type-only import costs the import and no resolution.

```python
# Good
from collections.abc import Iterator


def lines(source: str) -> Iterator[str]: ...


# Bad — Iterator costs nothing to import; the block is pure noise
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator


def lines(source: str) -> Iterator[str]: ...
```

## Exception handling

Use the built-in exception classes where they fit — `ValueError` for a bad argument value, `TypeError` for a bad type.
Don't use `assert` to validate the arguments of a public API: `assert` is for internal correctness, not for enforcing
correct usage.

Narrow `except` clauses to the exceptions you can actually handle, and never swallow one silently — at minimum re-raise
with context via `raise ... from`. `contextlib.suppress(OSError)` around a best-effort cleanup is fine; a bare
`except Exception: pass` around the operation that was the point is not.

```python
# Good
try:
    return json.loads(path.read_text())
except json.JSONDecodeError as e:
    raise ConfigError(f'invalid JSON in {path}') from e

# Bad — the caller has no way to know the file was invalid
try:
    return json.loads(path.read_text())
except Exception:
    return {}
```

## Mutable global state

Avoid module-level mutable state. A module global that gets mutated at run time is a hidden parameter to every function
in the module — hard to test, hard to reason about under concurrency, surprising when the module is imported twice.

Constants are fine. Caches, registries and pools belong on an explicit object or scoped to a function.

```python
# Good — the caller owns the state
def build_index(records: Iterable[Record]) -> dict[str, Record]:
    return {r.id: r for r in records}


# Bad — every caller now shares this dictionary
_INDEX: dict[str, Record] = {}


def add_to_index(r: Record) -> None:
    _INDEX[r.id] = r
```

## Resource management

Use `with` for anything needing explicit cleanup — files, sockets, subprocesses, locks, directory file descriptors.
Don't rely on garbage collection.

Where an object must outlive the block that created it (a temp file whose fd is handed to a child process, a confined
root held open across calls), give it a `close()` and a context-manager protocol so the *caller* can use `with`, and
say on the line that returns it who is responsible for closing. For a third-party object with neither, wrap it in
`contextlib.closing` rather than calling `.close()` in a `finally`.

## Power features

Avoid metaclasses, monkey-patching, dynamic class creation, `eval`, `exec`, custom `__getattr__`/`__setattr__` magic
and reflective tricks. They exist for library-level use cases; in application code they make things harder to read,
harder to type-check, and harder for tools (including AI assistants) to reason about. Reaching for one usually means an
abstraction is missing or wrong — fix that instead.

Two uses in `_guest.py` are deliberate, and both are the whole point of that module: it `exec`s the untrusted guest
code (carrying `# noqa: S102` and the reason), and it reaches `PR_SET_DUMPABLE` through `ctypes.CDLL(None).prctl`
because a stdlib-only script inside the sandbox has no other route to a `prctl`. A power feature needs justification at
that level or it doesn't go in.

## Docstrings

Google-style, on public APIs that warrant explanation. This is policy, not lint: ruff's `D1xx` rules are disabled, so a
missing docstring won't fail the gate — but the *format* of one that exists is enforced (Google convention), as is the
accuracy expectation from [`general.md`](general.md): an `Args:`/`Returns:`/`Raises:` entry that doesn't match the real
signature and behaviour is a defect.

- **Module**: what the module is for and what to reach for it for.
- **Function/method**: what the caller needs in order to call it correctly. Not a paraphrase of the implementation.
- **Class**: the invariant it maintains, plus behaviour the class name doesn't already imply.

```python
# Good
def guest_socket_path(name: str) -> str:
    """Where a hatch named ``name`` is bound inside the sandbox.

    Args:
        name: The hatch name, which becomes a path component.

    Returns:
        The absolute in-guest socket path.

    Raises:
        ValueError: If ``name`` is not usable as a path component and env-var tail.
    """


# Bad — restates the code, and documents a Raises: the function cannot produce
def guest_socket_path(name: str) -> str:
    """Format the guest dir and the name into a .sock path.

    Raises:
        OSError: If the socket cannot be bound.
    """
```

## Type annotations

Annotations are required on signatures (ruff's `ANN`) and should be *specific*; specificity is the policy part.

- `typing.Any` is banned outright (`ANN401` is selected). If you need it, ask whether a `Protocol`, `TypeVar` or union
  carries more signal. A `noqa: ANN401` needs a reason on the line — passthrough `**kwargs` forwarded to a dataclass
  constructor is the one case in postern.
- Prefer `list[Record]` over bare `list`. The element type carries meaning.
- Prefer the most general type the function actually uses for parameters (`Iterable[T]`, `Sequence[T]`, `Mapping[K, V]`)
  and a concrete `list`/`dict` for return types.
- Don't annotate the obvious, and don't add `# type:` comments inside a function unless pyright is confused. pyright
  runs in `standard` mode at `pythonVersion = "3.10"`, so an annotation that only type-checks on 3.11+ is a failure.

## Function decomposition

A function does one thing. Pyguide's loose target is "under 40 lines"; well above that usually means more than one
thing. Decompose along natural boundaries — parse the input, do the operation, format the output — not at arbitrary
line counts.

Structurally simple but long is fine (a builder appending flags in sequence). Fifty lines of branching where each
branch is a different mode of operation is not; those branches want to be functions.

## Tooling notes

### `from __future__ import annotations`

Use it, on the line after the module docstring. It makes annotations lazily-evaluated strings, which removes ordering
dependencies for forward references, allows `list[int]` and `X | Y` on the 3.10 floor, and keeps an unused type-only
import cheap.

Every module under `src/postern/` has it except `_guest.py` and `_stream_connect.py` — the stdlib-only scripts that run
*inside* the sandbox, exec'd by name and never imported by the package. Test modules that annotate nothing don't need
it; add it when one gains an annotation.

### pytest

`pytest`, not `unittest`. Test functions are top-level or grouped under `Test*` classes, and assertions are bare
`assert` (`S101` is ignored under `tests/**` exactly so that works). Use fixtures (`tmp_path`, `monkeypatch`, `capsys`,
your own) for setup rather than class-level setup methods, and `@pytest.mark.parametrize` rather than N near-identical
functions.

Platform-gated tests skip, they don't pass: `pytest.mark.skipif(not available(), reason='requires Linux + bubblewrap')`
at module scope. A test that silently no-ops on the host that can't run it is worse than one that skips loudly.

```python
# Good
def test_arch_is_covered_rejects_others():
    assert not _seccomp.arch_is_covered('riscv64')


# Bad — unittest style
class ArchTest(unittest.TestCase):
    def test_rejects_others(self):
        self.assertFalse(...)
```

---

*Adapted from the [Google Python Style Guide][pyguide], licensed under [CC-BY-3.0]. Sections covered by [ruff]'s lint
rules have been omitted; the linter config in [`../../pyproject.toml`](../../pyproject.toml) is the source of truth for
those.*

[cc-by-3.0]: https://creativecommons.org/licenses/by/3.0/
[pyguide]: https://google.github.io/styleguide/pyguide.html
[ruff]: https://docs.astral.sh/ruff/
