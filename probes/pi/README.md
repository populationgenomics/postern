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
 postern guest: Sandbox.run / run_python, empty netns, uid 65534, seccomp,
               its own rootfs (/opt/guest-root: python, bash, git, ripgrep)
```

The guest's rootfs is a separate build stage, bound read-only by postern, as in themis's sandbox
worker image (`themis/services/sandbox_worker/Dockerfile`). Without it postern binds the trusted
side's own system dirs, and the guest can see node, Pi and its extension, and the postern package.
`tools` checks what the guest has: `python3 git rg !node !pi !postern`.

PID 1 of every guest is postern's static C init (`SandboxProfile(init=...)`), built from this
checkout in a throwaway stage so gcc reaches neither the rootfs nor the runtime. `bash` goes
through `Sandbox.run_bash`. On this branch's base (postern PR #11, which puts an init in front of
every run), the Python shim as that init cost each trivial command 18.4 ms against 3.5 ms before;
the C init brings it back to 4.4 ms. File primitives still run Python, as the init's child, and
the seven `tools` calls take 0.40 s against 0.70 s under the shim.

bwrap runs as uid:gid `65532:65532` (`SandboxProfile.host_uid`), as themis's worker does when
`THEMIS_SANDBOX_HOST_UID` is set. Run as root, bwrap gives the guest kernel uid 0: it can change a
root-owned file in the workspace, and every file it creates is root's on the host. As 65532 it
owns only what it creates. To copy files in for the guest to work on, write them as that uid:

```bash
id=$(docker ps -q --filter ancestor=postern-pi-probe)
git -C ~/src/postern archive HEAD |
  docker exec -i -u 65532:65532 "$id" sh -c 'mkdir -p /var/lib/pi-probe/workspace/postern && tar -x -C $_'
```

## Running it

Needs Docker. On macOS it runs natively on arm64 in Docker Desktop. The two `--security-opt`s are
the ones `tests/docker/run.sh` uses, for the same reason.

```bash
probes/pi/run.sh              # seam timings against the real guest (no model)
probes/pi/run.sh tools        # Pi's seven tools through the seam (no model)
ANTHROPIC_API_KEY=… probes/pi/run.sh pi --provider anthropic --model claude-sonnet-5
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

**Confinement holds, including against a planted symlink.** `../escaped.txt`, `/etc/hosts` and a
workspace symlink to `/etc/hostname` are all refused. Pi itself passes all three through without
complaint. The first two are refused lexically, before a guest is launched. The symlink is refused
by a `realpath` inside the guest, so the host never dereferences a link the guest planted.

**New: supplying operations does not keep a tool's paths off the host.** Even with our operations,
Pi's `read` stat-probes the path locally for macOS filename variants, and `write`/`edit` `realpath`
it locally to key their mutation queue. So in both themis prototypes the host looked up whatever
path the model named, and on `pi-vm` the host's workspace was the real one. Two fixes, in layers:

- **Pi's `/workspace` is a decoy.** The guest's `/workspace` lives on the host at
  `/var/lib/pi-probe/workspace`. The `/workspace` Pi sees is an empty directory, so a local probe of
  any workspace path finds nothing, and every file the tools touch exists only on the guest's side
  (`tools` checks this).
- **`confine.ts`** refuses a path outside the workspace before Pi's execute runs, so Pi never
  probes `/etc/hosts` on its own side either. The executor refuses the same paths again; this layer
  exists to protect Pi's host, not to be the boundary.

**New: Pi's `grep` did not run in the guest.** Neither themis prototype caught this. In 0.85.1,
`createGrepTool(cwd, { operations })` only uses the operations for `isDirectory` (on the root) and
`readFile` (for context lines). The search itself runs `ensureTool('rg')`, which **downloads
ripgrep from GitHub at runtime if it is missing**, then **spawns `rg` on the host** against the
resolved path (`dist/core/tools/grep.js`). So in both prototypes grep ran beside the model
credential. On `pi-vm` that meant on the VM's trusted side, not in the guest. The `isDirectory` gate does
confine the search root, and `rg` does not follow symlinks by default, so this is not a read-out
here. It is still a host exec, on a model-chosen pattern and glob, of a binary fetched at runtime.
It is also why the `tools` run took about 1.5 s wall-clock against about 0.45 s in the guest.
Pi's own Gondolin example avoids it by replacing grep's whole `execute` rather than supplying
operations, and so does this probe now (`grep.ts`). A `grep` op walks and matches in the guest, and
the TS side only formats, reproducing Pi's output line for line. The seven calls now take about
0.4 s. `PI_OFFLINE=1` stops Pi fetching rg or fd if anything reaches for them again. `find` was
already fine: it uses `operations.glob` when one is provided and only falls back to `fd` otherwise.
The guest grep uses Python's `re` rather than ripgrep's regex engine and does not read
`.gitignore`. It skips `.git`, `node_modules`, symlinks and binary files.

**New: the tools themis registered reached the model with less guidance than Pi's own.**
`createReadTool` and friends wrap the definition into an `AgentTool`, and the wrapper keeps the
name, description and schema but drops `promptSnippet`, `promptGuidelines` and the renderers. The
extension now registers the `…ToolDefinition` factories. That brings back the edit renderer's
pre-call preview, which reads the target file locally with whatever path the model named, so
`index.ts` renders the edit call as though its arguments were still streaming, which skips the
preview. The diff shown after the call comes from the result, computed in the guest.

**A separate rootfs needs its stdlib precompiled.** The official `python` images strip stdlib
bytecode. While the guest shared the trusted side's `/usr`, the executor's own imports left
`__pycache__` behind for it. A read-only rootfs that has never run Python has none, so each file
primitive recompiled `json`, `pathlib` and the rest: 1.4 s for the seven calls instead of 0.36 s,
with bash unaffected. The guest stage runs `compileall` over the stdlib.

## Open

- **File primitives through the `Workspace` accessor** instead of a guest per call. The accessor is
  reference-closed by construction, so it would satisfy the confinement requirement host-side
  without a 28 ms interpreter start. It lacks `mkdir` and `glob` today.
- **Streaming and abort in `Sandbox.run`**, as above.
- **A model-driven run** (`run.sh pi`), timed, as the end-to-end latency number themis is still
  missing.
