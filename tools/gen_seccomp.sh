#!/usr/bin/env bash
# Regenerate src/postern/_seccomp.bpf and _seccomp.spec from the syscall lists in
# src/postern/_seccomp.py, using libseccomp inside a linux/amd64 container so it
# runs on any host including macOS/arm64.
#
# Run it whenever BLOCKED_EPERM, BLOCKED_ENOSYS, the arg-filtered rules or
# GEN_ARCHES change. Building on amd64 resolves the x86-centric syscall list; the
# secondary arches get whichever of those syscalls exist there.
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
