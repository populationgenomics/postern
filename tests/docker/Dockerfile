# Test image for running postern's bubblewrap-gated e2e suite on a non-Linux
# host (e.g. macOS/arm64 via Docker Desktop). It carries only the *toolchain* —
# bubblewrap plus grpcio and pytest; the postern source is mounted at run time
# (PYTHONPATH=/repo/src) so an edit-run loop needs no rebuild.
#
# The container must be launched with unprivileged user namespaces and a
# mountable /proc reachable — see tests/docker/run.sh and README.md for the two
# --security-opt flags this requires. postern's own seccomp filter is x86_64
# only, so on aarch64 it is skipped and the netns + cap-drop boundary is what
# the e2e tests exercise.
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends bubblewrap \
    && rm -rf /var/lib/apt/lists/*

# Toolchain only — no postern here; it is mounted at run time.
RUN pip install --no-cache-dir 'grpcio>=1.60' pytest

WORKDIR /repo
ENV PYTHONPATH=/repo/src PYTHONDONTWRITEBYTECODE=1

# Redirect pytest's cache off the read-only mounted source tree.
CMD ["python", "-m", "pytest", "-q", "-o", "cache_dir=/tmp/pytest_cache", "tests"]
