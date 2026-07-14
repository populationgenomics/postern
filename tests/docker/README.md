# Docker test harness

postern is a Linux + bubblewrap primitive: the bubblewrap-gated e2e tests
(`test_sandbox_e2e.py`, `test_hatch_e2e.py`) `skip` unless `postern.available()`
finds `bwrap` on the PATH. On macOS there is no `bwrap`, so those tests never
run locally. This harness runs the whole suite inside a Linux container instead,
so a macOS/arm64 machine (Docker Desktop) exercises the real isolation path.

## Run

```bash
tests/docker/run.sh                        # whole suite
tests/docker/run.sh tests/test_hatch_e2e.py -v   # trailing args pass to pytest
```

The image (`tests/docker/Dockerfile`) carries only the toolchain — bubblewrap,
grpcio, pytest. The source is bind-mounted read-only at `/repo` and put on
`PYTHONPATH`, so editing a test and re-running needs no rebuild.

## Why the two `--security-opt` flags

Bubblewrap builds the guest's user, network, and mount namespaces from inside
the container. Docker's defaults block exactly that, so `run.sh` relaxes two
things and nothing more — the container still runs unprivileged (no
`--privileged`, no added capabilities):

| Flag | Why |
| --- | --- |
| `seccomp=unconfined` | Docker's default seccomp profile blocks the `unshare()` / `clone()` calls that create the guest's user + network namespaces. |
| `systempaths=unconfined` | Docker masks parts of `/proc` read-only; bubblewrap mounts a fresh `/proc` for the guest and needs those paths unmasked. |

This is the same permissive shape a real target host provides (Cloud Run gen2
allows unprivileged user namespaces out of the box). `--privileged` also works
but grants far more than bubblewrap needs.

## Architecture notes

The seccomp filter is now a prebuilt multi-arch BPF blob (see
`tools/gen_seccomp.py`), so it loads and enforces on aarch64 too:
`test_seccomp_blocks_unshare` proves it on the native arm64 container.

Do **not** run this harness under `--platform linux/amd64` on an Apple Silicon
host. Docker Desktop's x86_64 emulation (Rosetta/QEMU) cannot load *any*
seccomp-BPF filter — `bwrap` fails with `prctl(PR_SET_SECCOMP) reported EINVAL`
even for a trivial allow-all filter. That is an emulation limitation, not a
postern bug. Validate the x86_64 filter on a real x86_64 Linux host (e.g. CI);
validate aarch64 with this harness natively.
