#!/usr/bin/env bash
# Regenerate src/postern/_seccomp.bpf from the syscall lists in
# postern/_seccomp.py, using libseccomp inside a linux/amd64 container (so it
# runs on any host, including macOS/arm64 via Docker Desktop emulation).
#
# Run this whenever BLOCKED_EPERM / BLOCKED_ENOSYS or the arg-filtered rules
# change. The committed .bpf is what ships; installing postern needs no
# libseccomp. Building on amd64 resolves the full x86-centric syscall list; the
# secondary arches (x86, x32, aarch64, arm) get whichever of those exist there.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

docker run --platform linux/amd64 --rm \
  -v "$repo_root":/repo -w /repo \
  debian:12-slim bash -c '
    set -e
    apt-get update -qq >/dev/null
    apt-get install -y -qq python3 python3-seccomp >/dev/null
    python3 tools/gen_seccomp.py
  '
