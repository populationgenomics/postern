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
  `/workspace`; no `/etc`, `/home`, `/root`, or host application code. bwrap's
  fresh `--proc` re-exposes the procfs sysctl surface writable and discards the
  runtime's mask, so `/proc/sys` (and `/proc/sysrq-trigger`, `/proc/irq`,
  `/proc/kcore`, …) are re-masked read-only — without it a guest whose mapped
  kernel uid is root can write `core_pattern`/`modprobe` and gain init-namespace
  root (a full host escape);
- **`--cap-drop ALL`**, **`--new-session`** (anti terminal-injection),
  **`--die-with-parent`**, **`--clearenv`**;
- **`--as-pid-1`** — the guest entrypoint *is* PID 1 of the guest's PID
  namespace, so no resident bwrap process sits there for the guest to read. That
  bwrap shared the guest uid, so its `/proc/1` (cmdline, maps, read/write mem,
  and env) was reachable from inside; with the entrypoint as PID 1 there is no
  such process. `run_python`'s shim then acts as a minimal init — it forks the
  guest, reaps orphaned descendants, propagates the guest's exit status, and
  marks *itself* `PR_SET_DUMPABLE=0` so a co-uid process the guest spawns cannot
  read the init either;
- **non-root guest** — the guest runs as uid/gid `65534` (`nobody`), so it holds
  no capabilities inside its user namespace, and if the userns fails to
  materialise on a root host it still drops to a non-root real uid
  (`SandboxProfile(guest_uid=None)` restores the legacy uid-0-in-userns). bwrap
  maps `--uid` to its *own* real uid, so a root bwrap still gives the guest
  kernel uid 0; `SandboxProfile(host_uid=…)` opts into running bwrap itself
  non-root (defense in depth beyond the `/proc/sys` mask) — off by default
  because the deploy must then make every bind source reachable by that uid;
- a **seccomp denylist** blocking escape-enabling syscalls (`unshare`, `setns`,
  `mount`, `ptrace`, `bpf`, `keyctl`, `io_uring_setup`, …). `socket` is
  deliberately *not* blocked — network isolation is the netns's job, and the
  guest needs `socket(AF_UNIX)`
  for the hatch;
- **`RLIMIT_NPROC`** as a fork-bomb backstop (set inside the guest), and an
  optional **`RLIMIT_AS`** memory backstop (`SandboxProfile(rlimit_as=...)`, off
  by default; a cgroup `memory.max` at the deploy layer is the real isolation).

The hatch UDS is bind-mounted in as the single controlled opening. Because the
RPC rides that socket, the guest's own stdin/stdout/stderr stay free.

**Fail-closed boot check.** Every control is enforced on the launch path: the
strict `--unshare-*` flags make bwrap abort if it can't create the namespaces,
apply `--uid`, or drop capabilities, and the seccomp loader refuses an uncovered
architecture — so a successful launch *is* the proof (no runtime probe, like
Chrome's sandbox). `Sandbox(profile).verify()` just triggers one trivial launch
at startup so a broken platform (no user namespace, gVisor, uncovered arch)
raises `IsolationError` there rather than on the first request. Call it at worker
startup and refuse to serve if it raises (`examples/worker.py` does this).

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
arm); on any other architecture it would be a default-allow no-op, so `Sandbox`
**refuses to launch** there (fail-closed) rather than run with an unenforced
filter — set `SandboxProfile(seccomp=False)` to override deliberately. Not
runnable on macOS except against a Linux target — `import postern` works
anywhere, `Sandbox.run*` needs the OS.

**Ubuntu 23.10+ / 24.04** restrict unprivileged user namespaces by default
(`kernel.apparmor_restrict_unprivileged_userns=1`), which bubblewrap needs —
the symptom is `bwrap: setting up uid map: Permission denied` or `loopback:
Failed RTM_NEWADDR`. Lift it with `sudo sysctl -w
kernel.apparmor_restrict_unprivileged_userns=0`, or install an AppArmor profile
that grants bwrap `userns`. Cloud Run gen2 does not have this restriction.

The bare `Sandbox` has **no third-party dependencies and no cloud dependency** —
it is a Linux primitive. The gRPC hatch pulls `grpcio` via the `grpc` extra; the
stream hatch (below) is stdlib-only.

## Stream hatch

Some protocols are neither typed RPC nor request/response. `StreamHatch` gives
the guest **one socket** and nothing else; per accepted connection a handler
decides what its bytes are spliced to — a host-side subprocess's stdio, or
nothing. The motivating case is git: git's native wire
protocol is pkt-line over a raw bidirectional stream, and `ext::` carries it over
a command's stdin/stdout, so a byte pump reaches the socket.

```python
from postern import Sandbox, SandboxProfile
from postern.stream import StreamHatch, git_url, splice_subprocess

hatch = StreamHatch(splice_subprocess(['git', 'upload-pack', '/srv/repo.git']), name='repo')
profile = SandboxProfile()
sandbox = Sandbox(profile, hatch=hatch)
sandbox.run(['git', '-c', 'protocol.ext.allow=always', 'clone',
             git_url('repo', profile=profile), 'work'])
```

Pass `profile=` to `git_url`: the in-guest interpreter comes from
`profile.python`, the same place `run_python` gets it, so the URL cannot disagree
with the sandbox it runs in. Without it the default is a bare `python3` off the
guest `PATH`, which is wrong for `with_venv` or a curated `rootfs`.

This is the sharpest form of the postern thesis: **the socket is the
capability.** The same access could be brokered through an HTTP forward proxy
with a handler policing each request; a bound stream socket is better in four
ways, and the first is the reason the hatch exists.

- *Capability by descriptor, not policy by parser.* Through a proxy the guest
  names a URL, so "only this one repository" means parsing and validating request
  targets in a handler — a parser in the policy path, fed attacker-controlled
  input. One socket per resource makes the wrong resource unrepresentable, and
  nothing parses anything. The service is fixed too — a hatch bound to `git
  upload-pack` cannot be talked into `receive-pack`, so read-only is read-only by
  construction rather than by a rule about verbs.
- *No body buffering, and no copying at all.* A proxy that lets a handler inspect
  request bodies has to buffer them, and so has to cap them. Here the socket **is**
  the command's stdin and stdout, so the kernel moves every byte and postern is not
  on the data path: no ceiling, no cap, no pump. It also means the kernel
  propagates the command's disposition for free — a command that consumed its
  input and exited gives the guest end-of-stream, one that died mid-request gives
  it a reset, which for a stream with no framing of its own is the only failure
  signal there is.
- *No protocol translation.* The host side is "run a subprocess, splice its
  stdio", not a bridge that decodes framing and re-emits headers to reach the
  same subprocess.
- *It works with `Sandbox.run`.* A hatch needs nothing in-guest — the socket is
  just a file — so a bare `git` entrypoint reaches it, not only a `run_python`
  guest. Both entrypoints bind and serve every configured hatch.

Stream hatches are **named**, so a sandbox carries as many as it has resources:
each binds at `/run/postern/<name>.sock` and is exported as
`$POSTERN_HATCH_<NAME>` (the unnamed `GrpcHatch` keeps `$POSTERN_HATCH`, and
`hatch=` now takes one hatch or a sequence). The in-guest connector that bridges
a command's stdio to the socket is bound in at `$POSTERN_CONNECT` (stdlib-only,
one blocking thread per direction; it leaves with `os._exit` rather than
finalising, because a daemon reader parked on a descriptor git has torn down is
what used to abort under git). git gates `ext::` behind
`protocol.ext.allow` because an `ext::` URL is command execution; inside the
sandbox that gate protects nothing, since the guest is already running untrusted
code, so enable it per invocation with `-c` and leave the host's git config alone.

Guest bytes reach a host-side process only as its **stdin** — never its argv,
env, cwd, or a dial's destination, all fixed when the hatch is constructed.
`splice_subprocess` gives the process a fixed minimal `PATH` and a fixed `cwd`
(not the worker's, which is where the secrets the hatch exists to withhold live
and which would let ambient host state decide what the capability even is), and
discards its stderr, because a command's diagnostics quote host paths.
`max_conns` gates *accepting* rather than dispatch: a stream connection is
long-lived by definition, so a queue of accepted-but-unserved connections would
be a queue of host file descriptors — past the cap, dials wait in the kernel
backlog costing the host nothing.

**Know this before you pick a command.** A fixed argv means guest bytes never
become *that* process's argv. It does not mean they cannot become a *downstream*
process's argv or a shell command, because the command's own **stdin grammar** is
part of the capability and `splice_subprocess` cannot check it for you. `git
upload-pack` grants nothing beyond the repository. `sqlite3` — even
`-readonly` — has `.shell`, so splicing it is host command execution; so are
`psql` (`\!`, `COPY … FROM PROGRAM`), `mysql` (`system`), `redis-cli`, `ftp`,
`gdb` and `ed`. Choose a command whose stdin grants only what you meant to grant.
Relatedly, `stderr=DEVNULL` covers fd 2 and nothing else: a command that
multiplexes diagnostics onto *stdout* routes around it (`git upload-archive`
reports `fatal: '<path>' does not appear to be a git repository` on its pkt-line
sideband), so pass `cwd` and a bare basename rather than an absolute host path.

## Install

```bash
pip install postern              # the bare sandbox + the stream hatch (no deps)
pip install 'postern[grpc]'      # + the gRPC hatch
```

## Public API

- `Sandbox(profile=None, *, hatch=None)` — `.run(argv)`, `.run_python(code)` → `ProcResult(returncode, stdout, stderr, ok)`; `.verify()` (fail-closed boot check, raises `IsolationError`). Both entrypoints bind and serve every configured hatch. `hatch` is opt-in and takes one hatch or a sequence — a `GrpcHatch` (typed methods), any number of named `StreamHatch`es (raw streams), both, or none (no channel opened); at most one *unnamed* hatch, since it owns a fixed guest env var.
- `SandboxProfile(workspace=None, rootfs=None, python='python3', ro_binds=[], stubs=None, env=..., seccomp=True, rlimit_nproc=1024, rlimit_as=None, guest_uid=65534, guest_gid=65534, host_uid=None, host_gid=None)` and `SandboxProfile.with_venv(venv, **kw)`. `host_uid=` opts bwrap into running at a non-root real uid (defense in depth for the sysctl surface; the deploy must make bind sources reachable by it). `stubs=` injects a dir or list of files at `/run/postern/stubs` (on `PYTHONPATH`) — a shared rootfs carries the heavy base, per-agent stubs bind in selectively.
- `postern.grpc.GrpcHatch(allowlist, *, socket_path=None)` — `.add_servicer(register_fn, servicer)`; `with hatch.accepting(): ...`. (`grpc` extra.)
- `postern.stream.StreamHatch(handler, *, name='stream', socket_path=None, max_conns=8, backlog=64, grace=5.0)` — a raw bidirectional byte stream over the sandbox UDS, reached as a plain file at `$POSTERN_HATCH_<NAME>` (so `run()` works, not just `run_python()`). `handler(stream) -> Process | None`: hand the connection to a subprocess as its stdio, or refuse. Battery: `splice_subprocess(argv, *, cwd=None, env=None, stderr=DEVNULL)`; `git_url(name, *, profile=None, python=None)` builds the `ext::` URL for the in-guest connector at `$POSTERN_CONNECT`. `close()` is terminal, as `GrpcHatch`'s is. `splice_subprocess` refuses `stderr=PIPE` (nothing drains it, so the command deadlocks). Named, so several coexist — one socket per resource. Stdlib-only. `with hatch.accepting(): ...`.
- `Sandbox.accessor()` / `postern.Workspace(dir)` — a reference-closed handle to a workspace; `WorkspacePath` is its `pathlib`-like facade. `.pack_tar(f, *, exclude=…)` and `.restore_tar(f, *, max_entries=…, max_bytes=…)` → `WorkspaceReport`; `ws / 'a/b'`, `.iterdir()`, `.walk()`, `.open()`, `.read_bytes()`. `reference_closed_filter` plugs into `tarfile.extractall(filter=...)` (member-vetting only — see below).
- `available()` — bubblewrap present?

## Reading the workspace safely

The workspace is the one writable surface the guest and host share, and it
outlives the sandbox. Nothing stops the guest planting a reference that points
*outside* it — `ln -s /proc/self/environ doc`, `ln -s / root`, a FIFO. Inside the
jail these are inert; the danger is when the **host** later reads, tars, or
restores the tree in its own namespace and privileges and becomes a confused
deputy (exfiltrating its own secrets, or writing through the link to a host path).

postern guarantees the workspace is **reference-closed**: read/pack/restore it
through the host-side accessor and no guest-planted symlink, `..`, or special
file is ever followed out of the tree — by construction, not by consumer
vigilance.

```python
with sandbox.accessor() as ws:                 # or Workspace(some_dir)
    # only regular files + dirs; symlinks/FIFOs and escaping hardlinks are
    # neutralized, and exclude drops paths a checkpoint persists elsewhere
    report = ws.pack_tar(open('snap.tar', 'wb'), exclude=lambda p: p == 'document.md')
    # report.skipped is the audit trail of what was neutralized (never silent)
    ws.restore_tar(open('snap.tar', 'rb'), max_entries=20_000, max_bytes=512 << 20)
    data = (ws / 'out' / 'result.json').read_bytes()
```

Every path resolves one component at a time with `O_NOFOLLOW` relative to a
directory fd (the model is Go's `os.Root` / Rust's `cap-std::Dir`); the accessor
never hands back a dereferenceable host path. It is pure stdlib and needs no
mount privilege, so it runs on an unprivileged host (e.g. a Cloud Run container).
A sticky world-writable workspace (`0o1777`) additionally stops the guest
unlinking host-written files to swap in escaping symlinks. `restore_tar`'s
`max_entries`/`max_bytes` bound a decompression bomb from an untrusted store.

`reference_closed_filter` plugs into stock `TarFile.extractall(filter=...)` for
consumers that keep `tarfile`, but it only **vets members** — stock extraction
still follows a symlink that already exists in the destination, so it is safe
only into a fresh host-controlled directory. To extract into a workspace a guest
may have touched, use `restore_tar`: it writes *through the confined root* (never
through an in-tree symlink, pre-existing or planted) and reports what it
neutralized.

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
  for run-lived state continuity, sitting on the reference-closed `Workspace`
  accessor (`pack_tar`/`restore_tar`) so snapshots are safe by construction.
- **`overlay=` profile mode** — emit `bwrap --ro-overlay` to stack layers with a
  tmpfs upper, instead of a single `--ro-bind` rootfs.
- **Agent-runtime adapters** — drive the sandbox from Anthropic Managed Agents,
  Google ADK, or MCP (the same sandbox, provider-agnostic).

## License

MIT.
