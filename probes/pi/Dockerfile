# syntax=docker/dockerfile:1

# PROBE — throwaway, lives on `pi-probe`. Pi, the extension, and this checkout's postern, in one
# Linux image. `run.sh` builds and runs it; build context is the repo ROOT.
#
# The guest's system dirs are this image's (SandboxProfile's default rootfs), so the guest has the
# same bash, python and coreutils the executor does. A real deploy would point `rootfs` at a curated
# tree instead — see examples/Dockerfile.

ARG NODE_IMAGE=node:24-bookworm-slim
ARG PYTHON_IMAGE=python:3.12-slim-bookworm

# --- Pi and the extension's dependencies, from the committed lock. ---
FROM ${NODE_IMAGE} AS pi
WORKDIR /opt/pi-probe
COPY probes/pi/package.json probes/pi/package-lock.json ./
RUN npm ci --ignore-scripts --omit=dev

# --- bubblewrap, postern from this checkout, and a node to run Pi with. ---
FROM ${PYTHON_IMAGE}
RUN apt-get update \
    && apt-get install -y --no-install-recommends bubblewrap \
    && rm -rf /var/lib/apt/lists/*
# Both images are bookworm, so node's dynamic libraries are already here; the binary is all that
# has to cross.
COPY --from=pi /usr/local/bin/node /usr/local/bin/node
COPY pyproject.toml README.md LICENSE /tmp/postern/
COPY src /tmp/postern/src
RUN pip install --no-cache-dir /tmp/postern && rm -rf /tmp/postern
COPY --from=pi /opt/pi-probe/node_modules /opt/pi-probe/node_modules
COPY probes/pi/package.json probes/pi/index.ts probes/pi/bash-ops.ts probes/pi/fs-ops.ts \
    probes/pi/seam.ts probes/pi/tools.ts probes/pi/executor.py probes/pi/entrypoint.sh /opt/pi-probe/
RUN ln -s /opt/pi-probe/node_modules/@earendil-works/pi-coding-agent/dist/bundle/cli.js /usr/local/bin/pi \
    && node --version && pi --version
# Pi's own state — sessions, settings, the models catalog — outside the workspace the tools see.
ENV PI_AGENT_DIR=/var/lib/pi
RUN mkdir -p /var/lib/pi
ENTRYPOINT ["/opt/pi-probe/entrypoint.sh"]
CMD ["seam"]
