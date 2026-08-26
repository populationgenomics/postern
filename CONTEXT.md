# postern — domain glossary

The shared vocabulary for postern. Reviews and design discussions should use these
names for the domain and structural terms (module, interface, depth, seam,
adapter) for the shape — e.g. "the **Hatch** seam", not "the gRPC service".

The founding metaphor: a *postern* is the small guarded gate through an
otherwise sealed wall. Guest code runs behind a sealed wall (no network, no
filesystem, no capabilities) and reaches the outside world only through the one
gate the host opens.

## Core terms

- **Guest** — the untrusted, host-supplied Python code run inside the sandbox.
  It is the thing the wall exists to contain. It sees only `/workspace`, a
  read-only base system, and the hatch; nothing of the host.

- **Sandbox** — the sealed wall. One bubblewrap-launched process with the
  hardened profile: empty network namespace (no egress), surgical read-only
  filesystem, `--cap-drop ALL`, `--new-session` and a seccomp denylist. Runs a
  guest via `run` (raw argv) or `run_python` (the shim path, which adds the
  `RLIMIT_NPROC` backstop). The security-critical module.

- **SandboxProfile** — the description of a sealed wall: workspace, rootfs,
  interpreter, extra read-only binds, stubs, env, and the seccomp/rlimit knobs.
  Defaults are the secure baseline; `with_venv` is the common variant that binds
  a prepared environment. A profile is a value — no side effects until a Sandbox
  runs it.

- **Hatch** — the gate: the guest's *only* channel to the outside. A `Protocol`
  (`socket_path`, `accepting()`) the Sandbox binds in and nothing else. The
  security boundary is not a permission flag but *what the hatch exposes*. Two
  adapters: `GrpcHatch` and `StreamHatch`.

- **GrpcHatch** — the gRPC adapter of the Hatch seam. Serves host-provided
  servicers over the sandbox's Unix domain socket, gated by a method
  **allowlist**. The servicer runs in the trusted host process; the guest calls
  it with a generated stub over `unix:$POSTERN_HATCH`. Requires the `grpc`
  extra.

- **StreamHatch** — the raw-stream adapter of the Hatch seam. One socket per
  resource; per accepted connection a handler decides whether its bytes are
  spliced to a host-side subprocess's stdio. Named, so a sandbox carries several
  (`$POSTERN_HATCH_<NAME>`). Stdlib-only.

- **Allowlist** — the capability grant. The exact `/package.Service/Method`
  names the guest may call through the hatch; everything else is
  `PERMISSION_DENIED`. Whatever a listed method can reach (a database, a
  credentialed API, a compute backend), the guest reaches only through that
  method's typed shape — never directly.

- **Workspace** — the guest's writable world: one host directory bound
  read-write at `/workspace` (the guest cwd). Persists for the Sandbox's
  lifetime and is readable from the host between runs (the seam a future
  checkpoint/restore **Store** would sit behind). An ephemeral workspace is a
  private temp dir removed on `close()`. The `Workspace` *accessor*
  (`Sandbox.accessor()`) is also the reference-closed host-side handle to that
  directory — see **reference-closure**.

- **Reference-closure** — the invariant that every path the guest can create in
  the workspace resolves, in *any* namespace (including the host's, including
  after the sandbox exits), only to a target within the workspace, or it fails.
  The guest can plant escaping references (a symlink to `/proc/self/environ`,
  `root -> /`, a FIFO) that are inert in the jail but turn the host into a
  confused deputy when it reads/tars/restores the tree. postern enforces closure
  with a **confined root** — `Workspace` (the capability, modelled on Go's
  `os.Root`) and `WorkspacePath` (its `pathlib`-like facade) — which resolves
  every component with `O_NOFOLLOW` and never exposes a dereferenceable host
  path. A sticky world-writable workspace and
  `reference_closed_filter` (for stock `tarfile`) are the supporting defenses.

- **Rootfs** — a curated base directory bound as the guest's `/usr`, `/lib`, …
  *instead of* the host's, hiding the host userland entirely. Assembled at
  image-build time (never a runtime container engine). `None` binds the host's
  own system dirs — convenient for dev, exposes the host userland read-only.

- **Shim** (`_guest.py`) — the in-sandbox entrypoint for `run_python`. Runs
  *inside* the wall, so it is stdlib-only: it applies `RLIMIT_NPROC` and
  `RLIMIT_AS`, then `exec`s the guest code as PID 1's forked child. The host↔shim
  handshake rides three env vars (`POSTERN_CODE`, `POSTERN_NPROC`,
  `POSTERN_AS`).

- **Stubs** — importable modules injected at `/run/postern/stubs` (on the
  guest's `PYTHONPATH`). Lets one shared rootfs carry the heavy base while the
  per-service gRPC stubs are bound in selectively, kept in lockstep with the
  hatch allowlist.

- **Log split** — `WARNING` is evidence about the host (a handler that raised, a
  leaked subprocess, an off-allowlist method); `DEBUG` is everything a guest can
  drive at its own rate. A per-event line on a guest-reachable path is an
  amplifier the guest controls, so which level a site gets is a security decision.
  Guest-derived values reach a record only through `_log.safe` — a handler's
  traceback included, which is why no guest-reachable site uses `exc_info`.

## Layering

The bare **Sandbox** is a Linux + bubblewrap primitive with no third-party and no
cloud dependency. **GrpcHatch** lives behind the `grpc` extra; **StreamHatch** is
stdlib. Consumers inject *policy* — which servicers, which allowlist, which
handler, which profile — not isolation mechanics.
