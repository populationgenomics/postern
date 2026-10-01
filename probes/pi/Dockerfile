# syntax=docker/dockerfile:1

# PROBE — throwaway, lives on `pi-probe`. Pi, the extension, and this checkout's postern, in one
# Linux image. `run.sh` builds and runs it; build context is the repo ROOT.
#
# The guest gets its own rootfs, assembled at build time in the `guest` stage and bound read-only
# by postern (SandboxProfile(rootfs='/opt/guest-root')), as themis's sandbox worker image does. So
# the guest sees none of the trusted side's userland: not node, not Pi or its extension, not postern.

ARG NODE_IMAGE=node:24-bookworm-slim
ARG PYTHON_IMAGE=python:3.12-slim-bookworm

# --- Pi and the extension's dependencies, from the committed lock. ---
FROM ${NODE_IMAGE} AS pi
WORKDIR /opt/pi-probe
COPY probes/pi/package.json probes/pi/package-lock.json ./
RUN npm ci --ignore-scripts --omit=dev

# --- the guest rootfs: ONLY what the tools need. This stage's whole filesystem becomes the guest's
#     world. Python for the executor's file primitives (stdlib only), bash and coreutils for `bash`,
#     and the git and ripgrep a model reaches for through `bash` without being told to. postern binds
#     the rootfs's /usr, /lib and /bin but not its /etc, so the executor binds the system gitconfig
#     (the identity commits carry) on its own. ---
FROM ${PYTHON_IMAGE} AS guest
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ripgrep \
    && rm -rf /var/lib/apt/lists/* \
    && git config --system user.name 'Pi probe agent' \
    && git config --system user.email 'agent@localhost' \
    && python -m compileall -q "$(python -c 'import sysconfig; print(sysconfig.get_path("stdlib"))')"
# The official image strips the stdlib's bytecode, and the rootfs is read-only to the guest, so
# without this every file primitive recompiles json, pathlib and friends: about 4x per call.

# --- the guest's PID 1: postern's C init, built from this checkout in a throwaway stage, so the
#     compiler reaches neither the guest rootfs nor the runtime. The same checkout is installed
#     below, so the version verify() checks the binary against matches by construction. ---
FROM ${PYTHON_IMAGE} AS init
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml README.md LICENSE /tmp/postern/
COPY src /tmp/postern/src
RUN pip install --no-cache-dir /tmp/postern && python -m postern.build_init /postern-init

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
COPY probes/pi/package.json probes/pi/index.ts probes/pi/bash-ops.ts probes/pi/fs-ops.ts probes/pi/grep.ts probes/pi/confine.ts \
    probes/pi/seam.ts probes/pi/tools.ts probes/pi/executor.py probes/pi/entrypoint.sh /opt/pi-probe/
RUN ln -s /opt/pi-probe/node_modules/@earendil-works/pi-coding-agent/dist/bundle/cli.js /usr/local/bin/pi \
    && node --version && pi --version
# Pi's own state — sessions, settings, the models catalog — outside the workspace the tools see.
ENV PI_AGENT_DIR=/var/lib/pi
# Pi fetches rg and fd from GitHub on first use when they are missing. Nothing here should need
# either, so a tool that still reaches for one fails loudly instead of fetching a host binary.
ENV PI_OFFLINE=1
RUN mkdir -p /var/lib/pi
# Copying '/' preserves the usrmerge symlink layout postern's binds expect.
COPY --from=guest / /opt/guest-root
# Static, so it needs nothing from the rootfs; postern binds it in as the guest's PID 1.
COPY --from=init /postern-init /opt/postern-init
ENTRYPOINT ["/opt/pi-probe/entrypoint.sh"]
CMD ["seam"]
