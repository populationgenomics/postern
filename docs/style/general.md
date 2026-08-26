# Code style — language-agnostic

Principles independent of language; the language layers build on this one
([`python.md`](python.md)). On conflict, the language doc wins for its language. Code properties only —
behavioural directives for an agent working in the repo live in [`../../CLAUDE.md`](../../CLAUDE.md).

## Fail loud; never silently degrade

Raise on missing or malformed data; don't paper over it with `x or []`, `x or {}`, or a bare `if x:` that skips the real
case — that turns a missing input into a silent wrong answer. Validate and fail early.

For a security control the rule is stronger: a control that cannot be enforced must fail *closed*, not proceed
unenforced. `_seccomp.load_filter` refuses to load the filter on an architecture the committed blob does not cover,
because there its default-allow would enforce nothing; `build_base_argv` lists `--unshare-user` explicitly on top of
`--unshare-all` so a kernel that cannot provide a user namespace is a hard launch failure rather than a guest running as
real root. Neither degrades quietly.

## Comments

Default to *no* comment. Add one only for a non-obvious *mechanism* or *constraint* a reader cannot recover from the
code — tersely, one line where possible. The *why* (why this shape was chosen) belongs in the docstring or the commit
message, not inline; never duplicate what a docstring above already states. No history narration ("removed X",
"switched from Y", "is now a…"), no reference to a transient artifact ("this slice", "this PR", "for now", "as X
lands") — name the durable behaviour, not the moment it arrived — no commented-out code, no persuasion: write as if the
current shape always existed. Self-check: a comment that stays true after the code beneath it is rewritten is
describing intent, not mechanism.

```python
# Bad — argues for the code, and the docstring above already says it
seccomp = _seccomp.load_filter()  # we compile the filter ahead of time rather than
# at run time because a libseccomp dependency would defeat the whole point of a
# dependency-free core, which is the property this design exists to preserve ...

# Good — one non-obvious fact
seccomp = _seccomp.load_filter()  # returned open: bwrap needs the fd for the child's lifetime
```

```python
# Bad — restates the rationale, and cites a review finding no document defines
argv += ['--unshare-all', '--unshare-user']  # --unshare-all leaves the user namespace
# best-effort, which is the silent-degradation risk (F1) the review called out in §3;
# re-listing it strict is what turns that into a hard failure.

# Good — the one non-obvious mechanism, terse
argv += ['--unshare-all', '--unshare-user']  # --unshare-all's user ns is best-effort; strict makes a missing one fatal
```

## Reference nothing that does not exist

Every identifier, path, flag, environment variable, and command named in a comment, docstring, or doc must exist, and
no two statements anywhere in the repo may contradict each other. Grep before you name something.

These are all the same defect — prose the reader cannot check and the linter does not:

- A `Raises:` entry for an exception the function cannot raise, or an `Args:` entry whose name or shape no longer
  matches the signature.
- A doc that enumerates a set ("the two e2e test files", "the sole hatch adapter") that has since grown.
- A `# pragma: no cover` on a line that is covered, or a platform claim nobody checked.
- A finding code or section pointer (`F3`, `§7`, "the security review") with no document in the repo defining it.
- Two files describing the same mechanism differently — e.g. one saying the seccomp filter is x86_64-only while another
  says it is a multi-arch blob.

When code changes, the prose describing it is part of the change.
