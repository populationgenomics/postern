# postern

Run untrusted Python in an OS-isolated sandbox whose **only** exit is a set of
host-defined, typed gRPC methods.

A postern is the small guarded gate through an otherwise sealed wall. That is the
model: guest code runs with no network, no filesystem beyond a workspace, no
capabilities — and reaches the outside world only by calling the specific gRPC
methods the host allowlists. The security boundary is that method set, not a
coarse permission flag.

```python
from postern import Sandbox, SandboxProfile
from postern.grpc import GrpcHatch
import greeter_pb2_grpc

hatch = GrpcHatch(allowlist={'/greeter.Greeter/SayHello'})
hatch.add_servicer(greeter_pb2_grpc.add_GreeterServicer_to_server, MyGreeter())

profile = SandboxProfile.with_venv('/opt/analysis-env')   # pandas, grpcio, stubs
result = Sandbox(profile, hatch=hatch).run_python(guest_code)
# guest dials unix:$POSTERN_HATCH with the generated stub; a non-allowlisted
# method → PERMISSION_DENIED; there is no network.
```

## Why

Coarse sandbox permissions (`--allow-net`, `--allow-read`) are the wrong grain
for untrusted agent/tool code: you rarely want "the network", you want "this one
method that fetches this one resource". postern inverts the default — the guest
gets **nothing** except the host methods you allowlist, each a typed proto shape.
Whatever a method can reach (a database, a credentialed API, a compute backend)
the guest reaches only through that shape, never directly.

This is the design [enclave](https://github.com/populationgenomics/enclave-py)
prototyped over WebAssembly (WASI-compiled CPython). postern delivers the same
"fine-grained function injection is the boundary" promise over a different
substrate — **OS isolation (bubblewrap) + a gRPC-over-UDS hatch** — which means
real CPython with arbitrary third-party packages (no custom toolchain), and
typed, language-neutral arguments/results (proto, `buf breaking`-gateable).

## Isolation

`Sandbox` launches the guest under [bubblewrap](https://github.com/containers/bubblewrap):

- **empty network namespace** — no egress of any kind (a socket can be created
  but has no route). The user and cgroup namespaces are unshared **strictly**
  (`--unshare-user`/`--unshare-cgroup`, not `--unshare-all`'s best-effort `-try`
  variants), so a host that can't provide a user namespace is a hard launch
  failure rather than a silent fall-through to a real-root guest;
- **surgical filesystem** — read-only base system dirs + one writable
  `/workspace`; no `/etc`, `/home`, `/root`, or host application code;
- **`--cap-drop ALL`**, **`--new-session`** (anti terminal-injection),
  **`--die-with-parent`**, **`--clearenv`**;
- **non-root guest** — the guest runs as uid/gid `65534` (`nobody`), so it holds
  no capabilities inside its user namespace, and if the userns fails to
  materialise on a root host it still drops to a non-root real uid
  (`SandboxProfile(guest_uid=None)` restores the legacy uid-0-in-userns);
- a **seccomp denylist** blocking escape-enabling syscalls (`unshare`, `setns`,
  `mount`, `ptrace`, `bpf`, `keyctl`, …). `socket` is deliberately *not* blocked
  — network isolation is the netns's job, and the guest needs `socket(AF_UNIX)`
  for the hatch;
- **`RLIMIT_NPROC`** as a fork-bomb backstop (set inside the guest), and an
  optional **`RLIMIT_AS`** memory backstop (`SandboxProfile(rlimit_as=...)`, off
  by default; a cgroup `memory.max` at the deploy layer is the real isolation).

The hatch UDS is bind-mounted in as the single controlled opening. Because the
RPC rides that socket, the guest's own stdin/stdout/stderr stay free.

**Fail-closed boot check.** The isolation depends on the platform providing a
real userns-enabled kernel; if that silently regresses (no userns, gVisor, an
arch the seccomp blob doesn't cover), the sandbox could weaken without any
error. `Sandbox(profile).verify()` launches an in-sandbox probe and raises
`IsolationError` unless egress is denied, seccomp is enforcing, the guest is
non-root, and the architecture is covered — call it once at worker startup and
refuse to serve if it raises (`examples/worker.py` does this).

## The environment (getting pandas etc. in)

The sandbox has no egress, so packages are provisioned **ahead of time** and
mounted read-only — never `pip install`ed at run time.

- `SandboxProfile.with_venv('/opt/env')` binds a venv read-only (at its own path,
  so its `site.py` resolution works) and runs its interpreter. The venv holds the
  guest's libraries **and** its hatch client (grpcio + the generated stubs).
- `SandboxProfile(rootfs='/opt/guest-root')` binds a curated base directory as the
  guest's system dirs *instead of the host's* — hiding the host userland
  entirely. Build it at image-build time (build-time Docker is fine; only
  *runtime* container engines are excluded): `docker export` a container into a
  dir, or ship a single squashfs/erofs image file mounted read-only via FUSE
  (`squashfuse`, unprivileged, Cloud-Run-compatible) and point `rootfs` at the
  mountpoint. `bwrap --ro-overlay` can stack OCI layer dirs without flattening.

## Requirements

Linux with **bubblewrap** and unprivileged user namespaces (a Cloud Run gen2 Job,
or any such host). `postern.available()` reports whether a sandbox can launch.
The seccomp filter is a prebuilt multi-arch BPF blob (x86_64, x86, x32, aarch64,
arm); on any other architecture its default-allow makes it a safe no-op and the
netns/capability boundary still holds. Not runnable on macOS except against a
Linux target — `import postern` works anywhere, `Sandbox.run*` needs the OS.

**Ubuntu 23.10+ / 24.04** restrict unprivileged user namespaces by default
(`kernel.apparmor_restrict_unprivileged_userns=1`), which bubblewrap needs —
the symptom is `bwrap: setting up uid map: Permission denied` or `loopback:
Failed RTM_NEWADDR`. Lift it with `sudo sysctl -w
kernel.apparmor_restrict_unprivileged_userns=0`, or install an AppArmor profile
that grants bwrap `userns`. Cloud Run gen2 does not have this restriction.

The bare `Sandbox` has **no third-party dependencies and no cloud dependency** —
it is a Linux primitive. The gRPC hatch pulls `grpcio` via the `grpc` extra.

## Install

```bash
pip install postern              # the bare sandbox (no deps)
pip install 'postern[grpc]'      # + the gRPC hatch
```

## Public API

- `Sandbox(profile=None, *, hatch=None)` — `.run(argv)`, `.run_python(code)` → `ProcResult(returncode, stdout, stderr, ok)`; `.verify()` (fail-closed boot check, raises `IsolationError`) and `.self_test()` (the raw isolation report).
- `SandboxProfile(workspace=None, rootfs=None, python='python3', ro_binds=[], stubs=None, env=..., seccomp=True, rlimit_nproc=1024, rlimit_as=None, guest_uid=65534, guest_gid=65534)` and `SandboxProfile.with_venv(venv, **kw)`. `stubs=` injects a dir or list of files at `/run/postern/stubs` (on `PYTHONPATH`) — a shared rootfs carries the heavy base, per-agent stubs bind in selectively.
- `postern.grpc.GrpcHatch(allowlist, *, socket_path=None)` — `.add_servicer(register_fn, servicer)`; `with hatch.accepting(): ...`. (`grpc` extra.)
- `available()` — bubblewrap present?

See `examples/e2e_greeter.py` for an end-to-end run (typed hatch call + pandas,
verified on a Linux host).

## Deploy: bundle the rootfs into the Job image

For a Cloud Run Job you build an image anyway, so bundle the guest rootfs into
it and let postern bind it — no runtime container engine. `examples/Dockerfile`
is the recipe: a multi-stage build that (1) generates the stubs, (2) builds a
minimal guest rootfs (`python:slim` + grpcio + your data libs + the client
stubs), and (3) assembles the worker (bubblewrap + `postern[grpc]` + your
servicer) with the guest rootfs copied to `/opt/guest-root`. The worker
(`examples/worker.py`) binds it with `SandboxProfile(rootfs='/opt/guest-root')`,
so the guest sees only that curated image, never the worker's userland. Cloud
Run gen2 provides the unprivileged user namespaces bubblewrap needs.

## Roadmap

- **Checkpoint/restore** — a `Store` protocol + durable-glob workspace snapshots
  for run-lived state continuity.
- **`overlay=` profile mode** — emit `bwrap --ro-overlay` to stack layers with a
  tmpfs upper, instead of a single `--ro-bind` rootfs.
- **Agent-runtime adapters** — drive the sandbox from Anthropic Managed Agents,
  Google ADK, or MCP (the same sandbox, provider-agnostic).

## License

MIT.
