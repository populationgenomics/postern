# PROBE: Pi's loop outside a postern guest, its tools inside

Throwaway. Lives on `pi-probe` and is not meant for `main`.

Ported from two themis-internal prototype branches, which asked whether [Pi](https://pi.dev)
(`@earendil-works/pi-coding-agent`) could replace Managed Agents as themis's harness:

- `proto/pi-loop-outside`: the tool seam, measured with a stub executor and no model. It ran on
  macOS, so every number came from a host subprocess and the guest's own cost was left open.
- `proto/pi-vm`: a Pi session driving a real Analysis on a VM, in the production sandbox image.

The decision memo is `docs/plans/pi-harness-evaluation.md` on themis-internal's
`docs/pi-harness-findings`. This probe keeps only the postern part: Pi's seven built-in tools
routed into a verified guest. It drops everything themis-specific (sheaf, the mirror, git hatches,
agent definitions, the VM launcher). What remains runs in one container against this checkout's
postern.

## The shape

```text
 Pi (model credential) ── index.ts registers read/write/edit/grep/find/ls/bash
        │                  over bash-ops.ts / fs-ops.ts
        │ Unix socket, NDJSON, one request per connection
        ▼
 executor.py (no credential: started with `env -i`)
        │ confines every path to the workspace, clamps timeouts
        ▼
 postern guest: Sandbox.run / run_python, empty netns, uid 65534, seccomp
```

## Running it

Needs Docker. On macOS it runs natively on arm64 in Docker Desktop. The two `--security-opt`s are
the ones `tests/docker/run.sh` uses, for the same reason.

```bash
probes/pi/run.sh              # seam timings against the real guest (no model)
probes/pi/run.sh tools        # Pi's seven tools through the seam (no model)
ANTHROPIC_API_KEY=… probes/pi/run.sh pi --provider anthropic --model claude-sonnet-5-5
```

Type-check the extension against Pi's published types locally with
`cd probes/pi && npm ci && npm run typecheck`.

Pi is pinned at 0.85.1, the version both themis prototypes measured. The findings below are about
0.85.1, and themis already found Pi's surface moving silently between versions.

## What it found (Docker Desktop, arm64, 2026-09-30)

**The guest is cheap, and the seam is still free.** `seam`: a trivial command takes a median
**3.8 ms** in the guest (bwrap launch plus bash; min 3.3, max 5.6) plus **0.3 ms** of socket. That
is the number `pi-loop-outside` could not measure. A file primitive costs about 28 ms, because each
one is a fresh `run_python` and so pays for a Python interpreter start. The six file tools issued 16
of them.

**Streaming and abort are still absent, now confirmed against the guest.** Five lines 200 ms apart
arrive as **1 frame** after 1038 ms. `sleep 5` cancelled at 300 ms returns after **5016 ms**. This is
the postern-side work both themis docs name, and it applies whichever harness sits above postern:
a streaming `run` over the existing stdout pipe, plus a kill on cancel.

**Confinement holds on the trusted side, including against a planted symlink.** `../escaped.txt`,
`/etc/hosts` and a workspace symlink to `/etc/hostname` are all refused by the executor before
reaching the guest. Pi itself passes all three through without complaint.

**New: Pi's `grep` does not run in the guest.** Neither themis prototype caught this. In 0.85.1,
`createGrepTool(cwd, { operations })` only uses the operations for `isDirectory` (on the root) and
`readFile` (for context lines). The search itself runs `ensureTool('rg')`, which **downloads
ripgrep from GitHub at runtime if it is missing**, then **spawns `rg` on the host** against the
resolved path (`dist/core/tools/grep.js`). So in both prototypes grep ran beside the model
credential. On `pi-vm` that meant on the VM's trusted side, not in the guest. The `isDirectory` gate does
confine the search root, and `rg` does not follow symlinks by default, so this is not a read-out
here. It is still a host exec, on a model-chosen pattern and glob, of a binary fetched at runtime.
It is also why the `tools` run spends about 1.5 s wall-clock against about 0.45 s in the guest.
Pi's own Gondolin example avoids it by replacing grep's whole `execute` with a walk-and-match over
the VM's filesystem rather than supplying operations. `find` is fine: it uses `operations.glob`
when one is provided and only falls back to `fd` otherwise.

## Open

- **Route grep into the guest**, the way Gondolin does: a `grep` op the executor runs in the guest,
  and a registered grep tool whose `execute` calls it.
- **File primitives through the `Workspace` accessor** instead of a guest per call. The accessor is
  reference-closed by construction, so it would satisfy the confinement requirement host-side
  without a 28 ms interpreter start. It lacks `mkdir` and `glob` today.
- **Streaming and abort in `Sandbox.run`**, as above.
- **A model-driven run** (`run.sh pi`), timed, as the end-to-end latency number themis is still
  missing.
