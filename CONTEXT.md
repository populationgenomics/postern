# postern — domain glossary

The shared vocabulary for postern. Architecture reviews and design discussions
should use these names for the domain, and the `/codebase-design` terms
(module, interface, depth, seam, adapter, leverage, locality) for the structure
— e.g. "the **Hatch** seam", not "the gRPC service".

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
  filesystem, `--cap-drop ALL`, `--new-session`, a seccomp denylist, and an
  `RLIMIT_NPROC` backstop. Runs a guest via `run` (raw argv) or `run_python`
  (the shim path). The security-critical module — the one the design exists to
  protect.

- **SandboxProfile** — the description of a sealed wall: workspace, rootfs,
  interpreter, extra read-only binds, stubs, env, and the seccomp/rlimit knobs.
  Defaults are the secure baseline; `with_venv` is the common variant that binds
  a prepared environment. A profile is a value — no side effects until a Sandbox
  runs it.

- **Hatch** — the gate: the guest's *only* channel to the outside. A `Protocol`
  (`socket_path`, `accepting()`) the Sandbox binds in and nothing else. The
  security boundary is not a permission flag but *the set of methods the hatch
  exposes*. Today the sole adapter is the gRPC hatch.

- **GrpcHatch** — the gRPC adapter of the Hatch seam. Serves host-provided
  servicers over the sandbox's Unix domain socket, gated by a method
  **allowlist**. The servicer runs in the trusted host process; the guest calls
  it with a generated stub over `unix:$POSTERN_HATCH`. Requires the `grpc`
  extra.

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
  `os.Root`) and `WorkspacePath` (its `pathlib`-like facade) — that resolves
  every component with `O_NOFOLLOW` and never exposes a dereferenceable host
  path, so consumers get "read/pack/restore this workspace safely" as an API
  instead of reimplementing confinement. A sticky world-writable workspace and
  `reference_closed_filter` (for stock `tarfile`) are the supporting defenses.

- **Rootfs** — a curated base directory bound as the guest's `/usr`, `/lib`, …
  *instead of* the host's, hiding the host userland entirely. Assembled at
  image-build time (never a runtime container engine). `None` binds the host's
  own system dirs — convenient for dev, exposes the host userland read-only.

- **Shim** (`_guest.py`) — the in-sandbox entrypoint for `run_python`. Runs
  *inside* the wall, so it is stdlib-only: it applies `RLIMIT_NPROC` and then
  `exec`s the guest code. The host↔shim handshake rides three env vars
  (`POSTERN_CODE`, `POSTERN_NPROC`, `POSTERN_HATCH`).

- **Stubs** — importable modules injected at `/run/postern/stubs` (on the
  guest's `PYTHONPATH`). Lets one shared rootfs carry the heavy base while the
  per-service gRPC stubs are bound in selectively, kept in lockstep with the
  hatch allowlist.

## Layering

The bare **Sandbox** is a Linux + bubblewrap primitive with no third-party and
no cloud dependency. The **GrpcHatch** lives behind the `grpc` extra. Consumers
inject *policy* (which servicers, which allowlist, which profile), not isolation
mechanics — the hardened wall is meant to live in one reviewed place.
