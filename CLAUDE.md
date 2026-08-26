# postern development notes

postern runs untrusted code in an OS-isolated sandbox. `_sandbox.py`, `_seccomp.py` and `_workspace.py` are the
security boundary: a weakening there is a vulnerability, not a bug. [`CONTEXT.md`](CONTEXT.md) is the domain glossary —
use its names.

## Working norms

Operating directives for Claude (and any agent) in this repo; they counteract default model dispositions.

- **Resist the minimal-diff reflex.** Don't reach for the smallest change that hides the symptom (special-casing,
  papering over root causes). Aim for the correct fix at the right complexity level — not the smallest, not gold-plated.
- **Fail loudly and early.** Raise on a missing expected input or precondition; never fall back to a
  default/placeholder to limp along. A placeholder is an explicit caller input, never a code default. A security
  control that cannot be enforced fails closed.
- **Push back; don't just comply.** When a design, name, or approach seems worse — including a shortcut you're asked to
  take — say so with reasoning, unprompted. The author owns the final call.
- **Offer better alternatives with trade-offs.** When a materially better approach than the proposed one exists,
  present it and the trade-offs — don't just execute the ask.
- **Investigate before producing.** Read the code and verify constraints first. Don't treat a training-pattern
  convention as load-bearing unchecked; don't speculate about what you can read.
- **Explain non-obvious changes first.** For a change whose rationale isn't self-evident, give the why before showing
  or applying the diff.
- **Ask when unsure** rather than assume intent.
- **No intensifiers or emphasis filler.** Drop words and phrases that add emphasis but no information — "that's the
  key", "crucially", "importantly", "the key insight", "it's worth noting". State the point plainly. Applies to all
  prose: chat replies, PR/review comments, commit messages, and docs.

## Code style

@docs/style/general.md
@docs/style/python.md

## Docs

The primary audience for docs is a model reading them as context; humans second. Be terse: state each decision,
mechanism and rationale once — no rhetorical emphasis, no persuasion, no recaps. Every token written is re-paid on
every future read.

Reference nothing that does not exist, and don't leave two statements contradicting each other. When code changes, the
comments, docstrings, `README.md` and `CONTEXT.md` describing it are part of that change.

## Committing

- **Stage explicit paths**, not `git add -A` / `.`. Explicit staging is what stops an untracked scratch file being
  swept into a commit.
- **Pre-commit is the whole static gate** (`.pre-commit-config.yaml`: ruff, ruff-format, markdownlint, yamlfmt,
  pyright, hygiene hooks). Run `uv run pre-commit run --all-files` before committing. Ensure hooks are installed
  (`pre-commit install`) — never bypass with `--no-verify`.
- **Tests before committing**: `uv run --group test pytest`. The bubblewrap e2e tests skip off Linux;
  `tests/docker/run.sh` runs the whole suite in a Linux container.
- **Correct a pushed branch with a new commit on top**, not amend + force-push. PRs squash-merge, so `main` stays
  linear regardless and intermediate fixups vanish on merge. Reserve force-push for rebasing onto `main`.

## `.claude/`

The whole directory is gitignored and stays local — worktrees, `settings.local.json`, agent and skill definitions,
slash commands, transcripts, scratch output. None of it is committed. Configuration meant for everyone working on the
repo goes in a tracked file at the root (`CLAUDE.md`, `pyproject.toml`, `.pre-commit-config.yaml`) where review covers
it; a `.claude/` file is one person's local setup and can change under anyone else's feet.

### Worktrees

Worktrees go in `.claude/worktrees/`, never `../` siblings.

- **New branch** → the Claude Code worktree command.
- **Existing branch** → `git worktree add .claude/worktrees/<name> <branch>` (the command only cuts fresh branches).
