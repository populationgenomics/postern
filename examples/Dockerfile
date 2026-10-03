# Cloud Run Job recipe: a worker image that bundles a curated guest rootfs.
#
# You are building an image for the Job anyway, so bundle the sandbox's guest
# filesystem into it. bwrap binds a directory that Docker built at *build* time
# (SandboxProfile(rootfs='/opt/guest-root')) — no runtime container engine.
#
# Four stages: build postern's guest init, generate stubs, build a minimal guest
# rootfs, assemble the worker. Adapt the package/proto names to your service.
#
#   docker build --build-arg POSTERN_VERSION=X.Y.Z -t worker .
#
# The init stage and the worker install the same postern: the init is stamped
# with the version it was built from, and verify() refuses a mismatch.
ARG POSTERN_VERSION

# --- 1. The guest init: postern's static C PID 1, built from the source postern
#        ships. A throwaway stage, so the compiler reaches neither the guest
#        rootfs nor the worker; only the binary is copied out. ---
FROM python:3.12-slim AS init
ARG POSTERN_VERSION
RUN test -n "$POSTERN_VERSION" || { echo 'build with --build-arg POSTERN_VERSION=X.Y.Z' >&2; exit 1; }
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir "postern==${POSTERN_VERSION}" \
    && python -m postern.build_init /postern-init

# --- 2. Generate gRPC stubs from the contract (needed by the worker servicer
#        AND the guest client). ---
FROM python:3.12-slim AS stubs
RUN pip install --no-cache-dir grpcio-tools
WORKDIR /src
COPY greeter.proto .
RUN mkdir -p /stubs && python -m grpc_tools.protoc -I. --python_out=/stubs --grpc_python_out=/stubs greeter.proto

# --- 3. The guest rootfs: a minimal base holding ONLY what the sandboxed code
#        needs — the interpreter, grpcio, data libs, and the client stubs. This
#        stage's whole filesystem becomes the guest's world, so the guest sees
#        none of the worker's userland. The interpreter is here for run_python;
#        a guest that only uses run/run_bash needs none. ---
FROM python:3.12-slim AS guest
RUN pip install --no-cache-dir grpcio protobuf pandas
COPY --from=stubs /stubs /usr/local/lib/python3.12/site-packages/
# Precompile everything the guest can import. The rootfs is read-only to the
# guest, so Python cannot cache bytecode at runtime: any module without a .pyc
# here is recompiled on every run. The official image ships the stdlib without
# bytecode, and while pip compiles what it installs, `uv pip install` does not
# by default — without this, `import pandas` alone costs ~4x per run.
RUN python -m compileall -q /usr/local/lib/python3.12

# --- 4. The worker: bubblewrap + postern + your servicer, plus the guest rootfs
#        and the init, which postern binds read-only at runtime. ---
FROM python:3.12-slim
ARG POSTERN_VERSION
RUN apt-get update && apt-get install -y --no-install-recommends bubblewrap \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir "postern[grpc]==${POSTERN_VERSION}" protobuf
# Stubs for the host-side servicer base classes:
COPY --from=stubs /stubs /usr/local/lib/python3.12/site-packages/
# The guest rootfs (copying '/' preserves the usrmerge symlink layout); postern
# binds /opt/guest-root/{usr,lib,...} via SandboxProfile(rootfs='/opt/guest-root'):
COPY --from=guest / /opt/guest-root
# Static, so it needs nothing from the rootfs; SandboxProfile(init='/opt/postern-init'):
COPY --from=init /postern-init /opt/postern-init
COPY worker.py /app/worker.py
WORKDIR /app
# Cloud Run gen2 provides unprivileged user namespaces (bubblewrap needs them).
# On a self-managed host see the README's Ubuntu 24.04 note.
CMD ["python", "worker.py"]
