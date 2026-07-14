#!/usr/bin/env bash
# Run postern's full test suite — including the bubblewrap-gated e2e tests that
# skip on a non-Linux host — inside a Linux container. Works on macOS/arm64 via
# Docker Desktop (the tests run in the Linux VM); any Docker host works too.
#
#   tests/docker/run.sh                # whole suite
#   tests/docker/run.sh tests/test_hatch_e2e.py -v   # extra args → pytest
#
# The two --security-opt flags are what let bubblewrap build its namespaces
# inside the container, and nothing more:
#   seccomp=unconfined     Docker's default seccomp blocks the unshare()/clone()
#                          that create the guest's user+net namespaces.
#   systempaths=unconfined Docker masks parts of /proc read-only; bwrap mounts a
#                          fresh /proc for the guest and needs those unmasked.
# The container still runs unprivileged (no --privileged, no added caps) — the
# same shape a permissive host like Cloud Run gen2 provides.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
image="postern-test"

docker build -q -t "$image" -f "$repo_root/tests/docker/Dockerfile" "$repo_root/tests/docker" >/dev/null

exec docker run --rm -t \
  --security-opt seccomp=unconfined \
  --security-opt systempaths=unconfined \
  -v "$repo_root":/repo:ro \
  "$image" \
  python -m pytest -q -o cache_dir=/tmp/pytest_cache "${@:-tests}"
