# Test image for running postern's bubblewrap-gated e2e suite on a non-Linux host
# (e.g. macOS/arm64 via Docker Desktop). It carries only the toolchain —
# bubblewrap, git, grpcio, pytest; the postern source is mounted at run time
# (PYTHONPATH=/repo/src) so an edit-run loop needs no rebuild.
#
# The container needs unprivileged user namespaces and an unmasked /proc — see the
# two --security-opt flags in tests/docker/run.sh and README.md.
FROM python:3.12-slim

# git as well as bubblewrap: the stream-hatch e2e clones a real repository through
# the hatch, with git itself as the sandbox entrypoint.
RUN apt-get update && apt-get install -y --no-install-recommends bubblewrap git gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# Toolchain only — no postern here; it is mounted at run time.
RUN pip install --no-cache-dir 'grpcio>=1.60' pytest

WORKDIR /repo
ENV PYTHONPATH=/repo/src PYTHONDONTWRITEBYTECODE=1

# Redirect pytest's cache off the read-only mounted source tree.
CMD ["python", "-m", "pytest", "-q", "-o", "cache_dir=/tmp/pytest_cache", "tests"]
