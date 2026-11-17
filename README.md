# postern

Run untrusted Python in an OS-isolated sandbox whose **only** exit is what the
host opens: a set of typed gRPC methods, one raw stream per resource, or a TCP
port served by a host process.

A postern is the small guarded gate through an otherwise sealed wall. That is the
model: guest code runs with no network, no filesystem beyond a workspace, no
capabilities — and reaches the outside world only through the hatches the host
binds in and the ports it forwards. The security boundary is what those expose,
not a coarse permission flag.

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
substrate — OS isolation (bubblewrap) plus a hatch over a Unix socket — so the
guest is real CPython with arbitrary third-party packages, no custom toolchain,
and the arguments and results are typed and language-neutral.

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
- **`--as-pid-1`** — postern's guest init *is* PID 1 of the guest's PID namespace.
  A resident bwrap there would share the guest uid, putting its `/proc/1` (cmdline,
  maps, read/write mem, env) within reach from inside. What the init does with that
  role: see [PID 1 and the resource backstops](#pid-1-and-the-resource-backstops)
  below;
- **non-root guest** — the guest runs as uid/gid `65534` (`nobody`), so it holds
  no capabilities inside its user namespace, and if the userns fails to
  materialise on a root host it still drops to a non-root real uid
  (`SandboxProfile(guest_uid=None)` restores the legacy uid-0-in-userns). bwrap
  maps `--uid` to its *own* real uid, so a root bwrap still gives the guest
  kernel uid 0; `SandboxProfile(host_uid=…)` opts into running bwrap itself
  non-root (defense in depth beyond the `/proc/sys` mask) — off by default
  because the deploy must then make every bind source reachable by that uid,
  including the files postern binds from its own install (the init, `run_python`'s
  shim, a stream hatch's connector), which a `0700` home directory above a
  virtualenv hides;
- a **seccomp denylist** blocking escape-enabling syscalls (`unshare`, `setns`,
  `mount`, `ptrace`, `bpf`, `keyctl`, `io_uring_setup`, …). `socket` is
  deliberately *not* blocked — network isolation is the netns's job, and the guest
  needs `socket(AF_UNIX)` for the hatch.

The hatch UDS is bind-mounted in as the single controlled opening. Because the
RPC rides that socket, the guest's own stdin/stdout/stderr stay free.

### PID 1 and the resource backstops

Everything above is a bwrap flag, so every entrypoint gets it. The rlimits and the
init role are not flags: they come from the guest's **init**, which postern binds in
and makes the entrypoint for **every** run.

The init is a small static C program (`_init.c`, ~190 lines) that the Linux wheels
carry, built for the wheel's architecture and stamped with its version; a profile
uses it with no configuration. It needs nothing from the guest's rootfs, so the only
things that need a Python interpreter in the sandbox are `run_python` and the stream
hatch's `git_url` connector, and a rootfs for `run`/`run_bash` need not carry one. A
bare launch (`run_bash('true')`) costs about 2.9 ms.

The init is a real PID 1. It marks *itself* `PR_SET_DUMPABLE=0` so a co-uid process
the guest spawns cannot read it, forks the work, reaps orphaned descendants that
reparent to it, forwards termination signals to the work's whole *process group*,
and propagates the work's exit status, as 128+N for death by signal N. The forked child applies
**`RLIMIT_NPROC`** (`SandboxProfile(rlimit_nproc=1024)`) as a fork-bomb backstop
and, when set, **`RLIMIT_AS`** (`SandboxProfile(rlimit_as=...)`, off by default; a
cgroup `memory.max` at the deploy layer is the real memory isolation), then `exec`s
the work. Setting the limits before the `exec` is what carries them to a program
that would not set them itself.

What the child execs is the only difference between the entrypoints:

- **`Sandbox.run`** execs the caller's argv, and **`Sandbox.run_bash`** execs
  `shell -c script` (`bash` by default). Neither has to tolerate being PID 1 or
  manage its own limits. A program the init cannot exec is a `returncode` of 127,
  not an exception.
- **`Sandbox.run_python`** execs `profile.python` on the shim, which runs the code
  in that fresh interpreter. `RLIMIT_AS` is applied after the interpreter is up,
  because a bare CPython's *virtual* size at startup can exceed a cap that its
  resident use never approaches, and capping before the `exec` would abort the
  startup.

**Running from a source checkout?** An editable install (`pip install -e`,
`uv sync`) carries neither the init nor the [launcher](#how-bwrap-is-started), and a
launch without them raises `IsolationError`; there is no fallback. Build both into
the package from the source it ships (a C compiler and static libc, e.g. Debian's
`gcc libc6-dev`):

```bash
python -m postern.build_init --in-place
```

A profile can also name an init built elsewhere:

```bash
python -m postern.build_init /opt/postern-init
```

```python
profile = SandboxProfile(rootfs='/opt/guest-root', init='/opt/postern-init')
```

The binary is stamped with the postern version it was built from, and `verify()`
refuses a mismatch. The check reads the init's own `--version` from a run *inside*
the sandbox: postern never executes the init on the host, which runs only its own
launcher and bwrap. `init=` must be an absolute path. Either way postern binds the
init in at `/run/postern/init`.

### How bwrap is started

A worker is usually a threaded server, and starting a child from a threaded
process with `fork` is fragile: the child is a copy of one thread in an address
space the others were using, and every handler a library registered with
`pthread_atfork` runs in it before the `exec`. gRPC's handler, for one, starts a
thread in the child; when the child then closes its inherited descriptors, that
thread finds its epoll descriptor gone and aborts the child
([grpc/grpc#43055](https://github.com/grpc/grpc/issues/43055)).

So postern never forks to start bwrap. It uses `posix_spawn`, which glibc
implements with `clone(CLONE_VM|CLONE_VFORK)` and which runs no atfork handler,
through a small static program the Linux wheels carry next to the init,
`postern-launch` (`_launch.c`). The spawn places stdio, the `--info-fd` pipe and
the seccomp filter at fixed descriptors; the launcher closes every descriptor
above them that a library left without `O_CLOEXEC`, drops to `host_uid`/`host_gid`
with no supplementary groups when the profile asks for it (by number: a static
binary resolving names would load the host's NSS modules), checks the drop cannot
be undone, and execs bwrap. A failure there raises `IsolationError` with the
launcher's reason, which it reports on the `--info-fd` pipe before bwrap starts.
The launcher is never configurable: it runs on the host as the worker, root
included, so postern runs only the copy installed with its own code.

Two things in the embedding process can defeat this. glibc before 2.24 forks
inside `posix_spawn` itself, so a launch refuses to run on one. And postern reaps
bwrap itself, so a process-wide reaper (a `SIGCHLD` set to `SIG_IGN`, a
`waitpid(-1)` loop) makes a run raise `ChildProcessError` rather than report a
status it never saw.

**Fail-closed boot check.** Every control is enforced on the launch path: the
strict `--unshare-*` flags make bwrap abort if it can't create the namespaces,
apply `--uid`, or drop capabilities, and the seccomp loader refuses an uncovered
architecture — so a successful launch *is* the proof, and there is no runtime
probe. `Sandbox(profile).verify()` triggers one trivial launch at startup so a
broken platform (no user namespace, gVisor, uncovered arch) raises
`IsolationError` there rather than on the first request. Call it at worker startup
and refuse to serve if it raises, as `examples/worker.py` does.

### Streaming and stopping a run

`run`, `run_bash` and `run_python` block until the run ends. `start`, `start_bash`
and `start_python` return a `Process` at once, which streams the output as the
guest writes it and can be stopped:

```python
with sandbox.start_bash('make test') as process:
    for stream, chunk in process.output():   # stream is 'stdout' or 'stderr'
        show(stream, chunk)
        if user_pressed_stop():
            process.terminate(grace=5)       # SIGTERM now, SIGKILL after 5 s
status = process.returncode
```

The same run for asyncio comes from `astart`, `astart_bash` and `astart_python`:

```python
async with await sandbox.astart_bash('make test') as process:
    async for stream, chunk in process.output():
        await show(stream, chunk)
    status = await process.wait()
```

- **One way to read output.** `output()` yields `(stream, bytes)` chunks from both
  pipes in the order they arrive; a chunk can end mid-line or mid-character. There
  are deliberately no separate stdout and stderr readers: draining one while the
  other's pipe fills stalls the guest. For a single stream, write `2>&1`.
  `communicate(timeout)` collects whatever `output()` has not into a `ProcResult`,
  which is all `run*` does.
- **Stopping is graceful.** bwrap does not forward signals, so `terminate()`
  signals the guest's init directly, through a pidfd on the host pid bwrap reports
  on `--info-fd` (so a recycled pid is never signalled). The init forwards the
  SIGTERM to the command's whole process group, which can trap it
  and clean up; if it is still running after `grace`, the init is killed through
  the same pidfd and the kernel kills the rest of its namespace with it. A launch
  raises `IsolationError` where pidfds do not work (before Linux 5.3, or under a
  seccomp profile blocking `pidfd_open`) or `/proc` cannot vouch for the init (a
  `/proc` from another pid namespace, `hidepid`), since a stop could not then be
  sure of reaching it. A SIGTERM sent before the init is ready for it is held
  pending until it is, not dropped: bwrap is launched with SIGTERM blocked, and
  the init inherits that. bwrap therefore ignores SIGTERM itself (`pkill -TERM
  bwrap` does nothing); a SIGTERM to the whole cgroup or process group still
  reaches the init, which forwards it. `terminate()` returns at once and is safe
  from another thread, so keep reading to see what the command says on its way
  out. `kill()` skips the grace.
- **Leaving early stops it too.** Leaving the `with` block while the run is still
  going (on an exception, a `break`, or an asyncio task cancellation) terminates it
  with a 1 s grace, discarding its remaining output. Close the `Process` (the
  `with` block does) to release the run's hatches, which serve until then.
- **When the loop ends.** `output()` ends when both pipes close, which is normally
  when the run ends: the init's exit takes everything else in the namespace with
  it, so a backgrounded straggler cannot hold the loop open. A command that closes
  its own output ends the loop early; `wait()` gives the status either way.
- **No threads for asyncio.** `AsyncProcess` reads the non-blocking pipes with loop
  readers and waits for the exit on a pidfd on bwrap. One reader per process:
  `terminate()` and `kill()` are the calls meant to come from elsewhere.

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
  The rootfs needs `profile.python` only for `run_python` and `git_url`.

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

## Port forwards

A tool that speaks HTTP or another TCP protocol, and cannot be pointed at a Unix
socket, reaches the host through a **port forward**: a TCP port on the guest's
loopback, served by a **handler**, a host process the caller runs.

```python
from postern import Sandbox, SandboxProfile
from postern.forward import HandoffError, PortForward, Receiver

# The handler, in a process of its own:
with Receiver('/run/files/control.sock') as receiver:   # mode 0600
    while True:
        try:
            handoff = receiver.receive()                 # one per launch
        except HandoffError:
            continue                                     # one bad control connection
        threading.Thread(target=serve, args=(handoff,)).start()

def serve(handoff):
    with handoff:
        while (conn := handoff.accept()) is not None:    # None once the launch ends
            ...                                          # an ordinary TCP connection

# The worker:
sandbox = Sandbox(SandboxProfile(), forwards=[PortForward(8080, '/run/files/control.sock')])
sandbox.run(['curl', 'http://127.0.0.1:8080/x'])
```

Two network namespaces cannot be joined by a connection: a TCP connection lives in
one. So postern opens the port inside the guest's namespace from the host and
gives the listening socket to the handler, which accepts the guest's connections
on it directly. No byte passes through postern or a relay in the guest. Per launch:

1. bwrap starts with `--block-fd`, which holds the guest before its init, and
   reports the init's pid on `--info-fd` as every launch does.
2. postern runs `postern-listen` (`_listen.c`) through `postern-launch`, so at
   the same uid as bwrap, which owns the guest: `/proc/<pid>/ns` is ptrace-gated,
   and a root worker whose bwrap drops to `host_uid` would otherwise need
   `CAP_SYS_PTRACE`. It opens `/proc/<pid>/ns/net`, confirms through the init's
   pidfd (not yet readable, so not exited) that the pid is still the init's, joins
   the user namespace that owns the guest's network namespace (bwrap nests the guest's own inside it, and
   only the owner's gives the capability to join), joins the network namespace,
   opens one listener per port on the dual-stack wildcard `::` (`0.0.0.0` on a
   kernel without IPv6), and sends them back over a socket pair. So `127.0.0.1`
   and `::1` both reach it. A wildcard rather than a loopback address because
   bwrap reports the pid before it brings loopback up; loopback is the guest's
   only interface either way.
3. postern connects to each handler's control socket and sends its listener
   (`SCM_RIGHTS`), the guest port, and the launch's token, then releases the
   guest. A handler that cannot be reached within 10 s, shared across all of a
   launch's forwards, fails the launch before the guest runs. A guest that dies in bwrap's setup first is reported as
   any launch's is, with bwrap's own error.
4. When the run is closed, postern closes the launch's control connections, which
   the handler sees closed: `Handoff.accept()` returns `None`. A
   namespace that goes away does not close a socket in it, so this is the
   handler's only signal.

`Handoff.accept()`, as above, is for a handler with a thread per launch. It polls
the listener and the control connection, and accepts from the listener once a
connection waits there. A handler on an event loop uses neither: it registers
`handoff.listener` with its loop to accept connections and `handoff.control` to
learn the launch has ended, then closes the handoff. With asyncio:

```python
async def serve(handoff, handle):
    loop = asyncio.get_running_loop()
    ended = loop.create_future()
    # Readable until closed, so the callback can run again once ended is set.
    loop.add_reader(handoff.control, lambda: ended.done() or ended.set_result(None))
    server = await asyncio.start_server(handle, sock=handoff.listener)
    try:
        await ended                       # the launch has ended
    finally:
        loop.remove_reader(handoff.control)
        server.close()
        await server.wait_closed()
        handoff.close()
```

`Receiver.receive()` blocks, so such a handler calls it in a thread
(`await asyncio.to_thread(receiver.receive)`).

The listener lives in one launch's namespace, so only that launch's guest can
connect, and two launches' connections arrive on two `Handoff`s. To say which
launch a `Handoff` is, the caller can give the launch a token, up to 256 bytes,
which every handler receives as `handoff.token`:

```python
sandbox.run(['curl', 'http://127.0.0.1:8080/x'], launch_token=b'session-4/call-17')
```

postern chooses nothing in the token and checks nothing of its meaning, and
anything that can reach a control socket can send any token, so it names a launch for a
handler and proves nothing. A handler serving several launches at once tells their
listeners apart by it, or looks it up in what the caller registered with the
handler before the launch. A `Handoff` says which launch, not whose: one control
socket grants the same authority to every launch pointed at it. Give each scope of
authority (one session's files, say) a `Receiver` of its own. A port
below 1024 needs no capability in the guest: postern-listen binds it as the
namespace's owner. The listener is dual-stack, so a guest's 127.0.0.1 arrives as
`::ffff:127.0.0.1`. The handler is a server for untrusted clients, and the control
socket is its own: anything that can reach it can hand it listeners, so `Receiver`
makes it mode 0600 and its directory should admit only the worker. Each accepted
connection is a descriptor in the handler, and the guest decides how many it opens,
so bound the connections served per `Handoff`.

Like the launcher, postern-listen runs on the host as the worker and is never
configurable. `verify()` checks its version when forwards are configured, and its
trivial launch forwards the ports like any launch: it proves at startup that the
ports open and each handler's control socket takes a connection. Each handler must
be listening by then, and receives one handoff that ends at once, with an empty
token.

## Stream hatch

Some protocols are neither typed RPC nor request/response. `StreamHatch` gives
the guest **one socket** and nothing else; per accepted connection a handler
decides what its bytes are spliced to — a host-side subprocess's stdio, or
nothing. The motivating case is git, whose native wire protocol is pkt-line over
a raw bidirectional stream and whose `ext::` transport carries that over a
command's stdin/stdout.

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
guest `PATH`, which is wrong for `with_venv` or a curated `rootfs`. The connector
is Python, so this needs an interpreter in the rootfs.

**The socket is the capability.** The same access could be brokered through an
HTTP forward proxy with a handler policing each request; a bound stream socket
differs in four ways.

- *Capability by descriptor, not policy by parser.* Through a proxy the guest
  names a URL, so "only this one repository" means validating request targets in
  a handler — a parser in the policy path, fed attacker-controlled input. One
  socket per resource makes the wrong resource unrepresentable. The service is
  fixed too: a hatch bound to `git upload-pack` cannot be talked into
  `receive-pack`.
- *No body buffering, and no copying.* A proxy that inspects request bodies has to
  buffer them, and so has to cap them. Here the socket **is** the command's stdin
  and stdout, so the kernel moves every byte and postern is not on the data path.
  The kernel also propagates the command's disposition: a command that consumed
  its input and exited gives the guest end-of-stream, one that died mid-request
  gives it a reset — the only failure signal a stream with no framing of its own
  has.
- *No protocol translation.* The host side runs a subprocess and splices its
  stdio, rather than decoding framing and re-emitting headers to reach the same
  subprocess.
- *It works with `Sandbox.run`.* A hatch needs nothing in-guest, so a plain `git`
  entrypoint reaches it, not only a `run_python` guest. Every entrypoint binds and
  serves every configured hatch.

Stream hatches are **named**, so a sandbox carries as many as it has resources:
each binds at `/run/postern/<name>.sock` and is exported as
`$POSTERN_HATCH_<NAME>`, while the unnamed `GrpcHatch` keeps `$POSTERN_HATCH`.
`hatch=` takes one hatch or a sequence. The in-guest connector that bridges a
command's stdio to the socket is bound in at `$POSTERN_CONNECT` — stdlib-only,
one blocking thread per direction, leaving with `os._exit` rather than finalising,
because finalising the interpreter around a reader still parked on a descriptor
git has torn down aborts the connector (`python3 died of signal 6`). git gates `ext::` behind `protocol.ext.allow` because an `ext::` URL is
command execution; inside the sandbox that gate protects nothing, since the guest
is already running untrusted code, so enable it per invocation with `-c` and leave
the host's git config alone.

Guest bytes reach a host-side process only as its **stdin** — never its argv,
env, cwd, or a dial's destination, all fixed when the hatch is constructed.
`splice_subprocess` gives the process a fixed minimal `PATH` and a fixed `cwd`
rather than the worker's, so ambient host state cannot decide what the capability
is, and discards its stderr, because a command's diagnostics quote host paths.
`max_conns` gates *accepting* rather than dispatch: a stream connection is
long-lived, so a queue of accepted-but-unserved connections would be a queue of
host file descriptors. Past the cap, dials wait in the kernel backlog.

**Teardown has two known holes.** Per connection the hatch waits for the command
and then signals its whole process *group*, because a child the command left
behind inherits the guest's socket and would otherwise hold the connection open
for ever. Two things bound that:

- *Another reaper in your process voids it.* If the embedding process reaps
  arbitrary children — a supervisor loop calling `waitpid(-1)`, `multiprocessing`,
  an asyncio child watcher, `SIGCHLD` set to `SIG_IGN` — then `Popen` synthesises
  an exit status of `0` on `ECHILD`, which is indistinguishable from a clean exit,
  and the group signal is skipped. Declining is the answer to that ambiguity: the
  foreign reap freed the pid, so signalling anyway could land on a recycled one.
  What leaks is the command's *children*; the worker thread and the slot come
  back. If your host process has its own reaper, keep the outer
  `Sandbox.run(timeout=...)` short.
- *A grandchild that calls `setsid()` escapes it*, because it is no longer in the
  group. A shell's `&` child stays and is collected; a daemonising sidecar does
  not. Prefer a command that does not daemonise.

`postern.stream`'s module docstring covers the mechanism under "Teardown and its
caveats", including which platforms can observe a command's exit without reaping
it (`waitid` on Linux, and on darwin from CPython 3.13; `kqueue` on macOS and the
BSDs) and what a platform with neither loses.

**The command's stdin grammar is part of the capability.** A fixed argv means
guest bytes never become *that* process's argv. It does not stop them becoming a
*downstream* process's argv or a shell command, and `splice_subprocess` cannot
check a grammar for you. `git upload-pack` grants nothing beyond the repository.
`sqlite3` — even `-readonly` — has `.shell`, so splicing it is host command
execution; so are `psql` (`\!`, `COPY … FROM PROGRAM`), `mysql` (`system`),
`redis-cli`, `ftp`, `gdb` and `ed`.

`stderr=DEVNULL` covers fd 2 and nothing else: a command that multiplexes
diagnostics onto *stdout* routes around it (`git upload-archive` reports
`fatal: '<path>' does not appear to be a git repository` on its pkt-line
sideband), so pass `cwd` and a bare basename rather than an absolute host path.

## Logging

postern logs through the stdlib and configures nothing. Each module logs to
`logging.getLogger('postern.<module>')`; the package attaches a `NullHandler` to
`postern` and adds no handler, sets no level and installs no format. Wiring the
sink is the application's job — on Cloud Run, structured stdout is ingested, so a
`logging.basicConfig` (or the app's own JSON formatter) is the whole integration.
There is no `google-cloud-logging` dependency and no OpenTelemetry: tracing is a
separate concern and a separate dependency decision.

```python
logging.getLogger('postern').setLevel(logging.INFO)     # hatch start and stop
logging.getLogger('postern').setLevel(logging.DEBUG)    # every guest-driven event
```

**The level split is a security property.** A guest reaches the hatch, so a
per-event line on a guest-driven path is an amplifier whose rate the guest sets,
for as long as the run lives: until its `timeout` for `run*`, and until the
caller stops it for `start*`.

- **`WARNING`** — evidence about the *host*: a handler that raised, with the
  exception type and message, so a host bug is not indistinguishable from the
  guest's clean end-of-stream; a reap or dispose that failed and therefore leaked
  a subprocess; closing an unclosed `Workspace` failing; `accept()` failing
  transiently because the embedding worker is out of descriptors (bounded at
  `1/_ACCEPT_RETRY_DELAY` = 20 lines/second, and unreachable by the guest). Also a
  gRPC method called that is not on the allowlist: in correct operation the guest
  only calls what the host allowlisted, so it is either a misconfigured allowlist
  or a guest probing the boundary.
- **`INFO`** — a hatch starting and stopping: two lines per hatch per run, for
  both `GrpcHatch` and `StreamHatch`.
- **`DEBUG`** — what a well-behaved guest drives at its own rate: a handler
  refusing by policy (that is the handler working), a connection in flight when
  `close()` runs, and the traceback behind a `WARNING` handler failure.

Nothing is rate-limited or aggregated: every event gets a line.

**A handler failure is the one WARNING a guest can drive.** A handler runs on
guest input, so a handler that raises on malformed input logs once per connection
at the default level. That is deliberate — a host bug that only fires on hostile
input is exactly what you want to see — but it means a handler should refuse by
returning `None` (`DEBUG`) and raise only when something is genuinely wrong.

**Guest-derived values are never interpolated raw, tracebacks included.** A gRPC
method name, and a handler exception's type, message and traceback, are passed to
the log call wrapped in `postern._log.Guest`, which renders them escaped and
length-capped when the record is formatted, so a newline cannot start what reads
like a new host-attributed entry in an aggregated stream. Wrapping is the call
site's job: nothing does it for a value passed bare. Nothing on a guest-reachable
path is handed to `exc_info`; the traceback is wrapped and logged at `DEBUG`
instead.

## Install

```bash
pip install postern              # the bare sandbox + the stream hatch (no deps)
pip install 'postern[grpc]'      # + the gRPC hatch
```

The x86_64 and aarch64 Linux wheels carry the guest init and the bwrap launcher.
Any other install builds from the sdist: on Linux that compiles both and needs a C
compiler and static libc; elsewhere it installs without one, and no sandbox runs
there anyway.

## Public API

- `Sandbox(profile=None, *, hatch=None, forwards=())` — `.run(argv)`, `.run_bash(script, *, shell='bash')`, `.run_python(code)` → `ProcResult(returncode, stdout, stderr, ok)`; `.start(argv)`, `.start_bash(script, *, shell='bash')`, `.start_python(code)` → `Process`, and `await .astart(...)`, `.astart_bash(...)`, `.astart_python(...)` → `AsyncProcess` ([streaming and stopping](#streaming-and-stopping-a-run)); `.verify()` (fail-closed boot check, raises `IsolationError`, as does any launch with no guest init or launcher, whose launcher fails, on a glibc older than 2.24, or where pidfds do not work). All three bind and serve every configured hatch, get the identical bwrap profile, and run under the guest init with the same rlimits and orphan reaping ([above](#pid-1-and-the-resource-backstops)); they differ only in what the init's child execs. `hatch` takes one hatch or a sequence, with at most one *unnamed* hatch since that one owns a fixed guest env var. `forwards` takes `PortForward`s with distinct guest ports, at most 64 ([port forwards](#port-forwards)); every run and start method takes `launch_token=b''`, `bytes` of at most `postern.forward.MAX_TOKEN` (256), which each handler receives with the launch's listener; a sandbox without forwards takes one and sends it nowhere.
- `Process` — `.output()` → iterator of `(stream, bytes)`; `.terminate(*, grace=5.0)`, `.kill()`, `.wait(timeout=None)`, `.communicate(timeout=None)` → `ProcResult`, `.close()`; `.pid`, `.returncode`, `.terminated`; a context manager. `AsyncProcess` is the same run for asyncio: `async for` over `.output()`, `await .wait()`, `await .communicate(timeout=None)`, `await .aclose()`, `async with`.
- `SandboxProfile(workspace=None, rootfs=None, python='python3', ro_binds=[], required_ro_binds=[], stubs=None, env=..., seccomp=True, rlimit_nproc=1024, rlimit_as=None, guest_uid=65534, guest_gid=65534, host_uid=None, host_gid=None, init=None)` and `SandboxProfile.with_venv(venv, **kw)`. `ro_binds=` are `--ro-bind-try` (a missing source is skipped silently); `required_ro_binds=` are `--ro-bind` (a missing source fails the launch), for a bind the guest cannot run without. `host_uid=` runs bwrap itself at a non-root real uid; the deploy must then make every bind source, and the files postern binds from its own install, reachable by it. `init=` names a static C init built by `python -m postern.build_init` ([above](#pid-1-and-the-resource-backstops)); `None` uses the one the Linux wheel carries, and a launch with neither raises `IsolationError`. `verify()` checks the init and the launcher were built from this postern version. `stubs=` injects a dir or list of files at `/run/postern/stubs`, prepended to `PYTHONPATH`. `rlimit_nproc=`/`rlimit_as=` are applied by the guest init, so every entrypoint gets them.
- `postern.grpc.GrpcHatch(allowlist, *, socket_path=None)` — `.add_servicer(register_fn, servicer)`; `with hatch.accepting(): ...`. (`grpc` extra.)
- `postern.stream.StreamHatch(handler, *, name='stream', socket_path=None, max_conns=8, backlog=64, grace=5.0)` — a raw bidirectional byte stream over the sandbox UDS, reached as a plain file at `$POSTERN_HATCH_<NAME>`, so `run()` works and not only `run_python()`. Named, so several coexist: one socket per resource. Stdlib-only. `with hatch.accepting(): ...`, and `close()` is terminal as `GrpcHatch`'s is.
  - `handler(stream) -> Process | None`: return `Process(argv, cwd=None, env=None, stderr=DEVNULL)` to hand the connection to a subprocess as its stdio, or `None` to refuse. The hatch spawns it, so the descriptor is in ordinary-stdio shape (blocking, no signal-driven I/O, no socket timeouts) before there is a child to race.
  - `Process.from_popen(popen)` adopts a subprocess you spawned yourself, for what the declarative form does not cover (`pass_fds`, `user=`, an rlimit). An already-spawned verdict can only be validated, and it has none of the declarative path's `stderr`/`env`/`cwd` defaults.
  - `stderr=PIPE` is refused because nothing drains it and the command would deadlock; `stderr=STDOUT` is refused because stdout is the guest socket, so it would relay host-path diagnostics to the guest. Checked at construction for `Process(argv)`, and by detection for an adopted `Popen` where the platform allows, since `subprocess` keeps no record of the `stderr` it was passed.
  - `Stream.read_preamble(max_bytes, timeout)` bounds a preamble read without touching socket flags. Do not use `settimeout` for that: the command shares the descriptor.
  - `splice_subprocess(argv, *, cwd=None, env=None, stderr=DEVNULL)` is the stock handler; `git_url(name, *, profile=None, python=None)` builds the `ext::` URL for the in-guest connector at `$POSTERN_CONNECT`.
- `postern.forward.PortForward(guest_port, handler)` — serve `guest_port` (1 to 65535) on the guest's loopback with the handler whose control socket is `handler`. `Receiver(path, *, mode=0o600)` binds a handler's control socket, a Unix `SOCK_SEQPACKET` socket so that each handoff is one message: `.receive()` → `Handoff` per launch (raises `HandoffError` for one bad control connection, which the loop should skip), `.close()` removes the socket file. `Handoff` — `.guest_port`; `.token`, the launch's `launch_token` (`b''` if none); `.listener` and `.control`, the sockets an event loop registers (a waiting connection, the launch's end); `.accept()` polls both for a threaded handler → the next connection, or `None` once the launch ends; a context manager. `check_token(token)` raises `TypeError` or `ValueError` unless `token` is `bytes` of at most `MAX_TOKEN` (256): the rule every launch and `Handoff` applies. Stdlib-only.
- `Sandbox.accessor()` / `postern.Workspace(dir)` — a reference-closed handle to a workspace; `WorkspacePath` is its `pathlib`-like facade. `.pack_tar(f, *, exclude=…)` and `.restore_tar(f, *, max_entries=…, max_bytes=…)` → `WorkspaceReport`; `ws / 'a/b'`, `.iterdir()`, `.walk()`, `.open()`, `.read_bytes()`. `reference_closed_filter` plugs into `tarfile.extractall(filter=...)`, member-vetting only — see below.
- `available()` — whether bubblewrap is on the PATH.

## Reading the workspace safely

The workspace is the one writable surface the guest and host share, and it
outlives the sandbox. Nothing stops the guest planting a reference that points
*outside* it — `ln -s /proc/self/environ doc`, `ln -s / root`, a FIFO. Inside the
jail these are inert; the danger is when the **host** later reads, tars, or
restores the tree in its own namespace and privileges and becomes a confused
deputy (exfiltrating its own secrets, or writing through the link to a host path).

postern guarantees the workspace is **reference-closed**: read, pack or restore it
through the host-side accessor and no guest-planted symlink, `..`, or special file
is ever followed out of the tree.

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
never hands back a dereferenceable host path. Pure stdlib, no mount privilege, so
it runs on an unprivileged host such as a Cloud Run container. A sticky
world-writable workspace (`0o1777`) additionally stops the guest unlinking
host-written files to swap in escaping symlinks. `restore_tar`'s
`max_entries`/`max_bytes` bound a decompression bomb from an untrusted store.

`reference_closed_filter` plugs into stock `TarFile.extractall(filter=...)` for
consumers that keep `tarfile`, but it only **vets members** — stock extraction
still follows a symlink that already exists in the destination, so it is safe
only into a fresh host-controlled directory. To extract into a workspace a guest
may have touched, use `restore_tar`: it writes *through the confined root*, never
through an in-tree symlink, and reports what it neutralized.

`examples/e2e_greeter.py` is a runnable end-to-end example: a typed hatch call
plus pandas, on a Linux host.

## Deploy: bundle the rootfs into the Job image

For a Cloud Run Job you build an image anyway, so bundle the guest rootfs into it
and let postern bind it, with no runtime container engine. `examples/Dockerfile`
is the recipe: a three-stage build that generates the stubs, builds a minimal
guest rootfs (`python:3.12-slim` + grpcio + your data libs + the client stubs),
and assembles the worker (bubblewrap + `postern[grpc]` + your servicer) with the
guest rootfs copied to `/opt/guest-root`. `examples/worker.py` binds it with
`SandboxProfile(rootfs='/opt/guest-root')`, so the guest sees only that curated
image. Cloud Run gen2 provides the unprivileged user namespaces bubblewrap needs.

Cloud Run stops a task with SIGTERM to the container's entrypoint, then SIGKILL
10 s later. As the container's PID 1, a worker with no SIGTERM handler ignores
the SIGTERM, so its guests get no chance to clean up before the SIGKILL.
`examples/worker.py` installs one: it passes the stop on to the run with
`terminate()`, so the guest's own cleanup runs, and exits 143.

## Roadmap

Not implemented:

- **Checkpoint/restore** — a `Store` protocol and durable-glob workspace
  snapshots, sitting on the reference-closed `Workspace` accessor
  (`pack_tar`/`restore_tar`).
- **`overlay=` profile mode** — emit `bwrap --ro-overlay` to stack layers with a
  tmpfs upper, instead of a single `--ro-bind` rootfs.
- **Agent-runtime adapters** — drive the same sandbox from Anthropic Managed
  Agents, Google ADK, or MCP.

## License

MIT.
