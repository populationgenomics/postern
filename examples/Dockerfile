# Cloud Run Job recipe: a worker image that bundles a curated guest rootfs.
#
# You are building an image for the Job anyway, so bundle the sandbox's guest
# filesystem into it. bwrap binds a directory that Docker built at *build* time
# (SandboxProfile(rootfs='/opt/guest-root')) — no runtime container engine.
#
# Three stages: generate stubs, build a minimal guest rootfs, assemble the
# worker. Adapt the package/proto names to your service.

# --- 1. Generate gRPC stubs from the contract (needed by the worker servicer
#        AND the guest client). ---
FROM python:3.12-slim AS stubs
RUN pip install --no-cache-dir grpcio-tools
WORKDIR /src
COPY greeter.proto .
RUN mkdir -p /stubs && python -m grpc_tools.protoc -I. --python_out=/stubs --grpc_python_out=/stubs greeter.proto

# --- 2. The guest rootfs: a minimal base holding ONLY what the sandboxed code
#        needs — the interpreter, grpcio, data libs, and the client stubs. This
#        stage's whole filesystem becomes the guest's world, so the guest sees
#        none of the worker's userland. ---
FROM python:3.12-slim AS guest
RUN pip install --no-cache-dir grpcio protobuf pandas
COPY --from=stubs /stubs /usr/local/lib/python3.12/site-packages/

# --- 3. The worker: bubblewrap + postern + your servicer, plus the guest rootfs
#        copied in for postern to bind read-only at runtime. ---
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends bubblewrap \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir 'postern[grpc]' protobuf
# Stubs for the host-side servicer base classes:
COPY --from=stubs /stubs /usr/local/lib/python3.12/site-packages/
# The guest rootfs (copying '/' preserves the usrmerge symlink layout); postern
# binds /opt/guest-root/{usr,lib,...} via SandboxProfile(rootfs='/opt/guest-root'):
COPY --from=guest / /opt/guest-root
COPY worker.py /app/worker.py
WORKDIR /app
# Cloud Run gen2 provides unprivileged user namespaces (bubblewrap needs them).
# On a self-managed host see the README's Ubuntu 24.04 note.
CMD ["python", "worker.py"]
