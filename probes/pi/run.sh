#!/usr/bin/env bash
# PROBE — throwaway, lives on `pi-probe`. Build the probe image and run one mode in it.
#
#   probes/pi/run.sh              # seam timings against the real guest (default)
#   probes/pi/run.sh tools        # Pi's seven tools through the seam
#   ANTHROPIC_API_KEY=… probes/pi/run.sh pi --provider anthropic --model claude-sonnet-5
#
# The two --security-opts are the ones tests/docker/run.sh needs, for the same reason: they let
# bubblewrap build its namespaces inside the container. They loosen the container's confinement of
# the trusted process, not the guest's; the executor's Sandbox.verify() is the thing to read.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
image=postern-pi-probe
docker build -q -f "$root/probes/pi/Dockerfile" -t "$image" "$root" >/dev/null

# -i always, so a driver piping Pi's RPC mode reaches it; -t only with a terminal to give it.
tty=(-i)
[[ -t 0 && -t 1 ]] && tty=(-it)
# Provider keys pass through only if set; Pi reads whichever its --provider needs.
keys=()
for key in ANTHROPIC_API_KEY OPENAI_API_KEY GEMINI_API_KEY OPENROUTER_API_KEY; do
  [[ -n ${!key:-} ]] && keys+=(-e "$key")
done

exec docker run --rm --init ${tty[@]+"${tty[@]}"} \
  --security-opt seccomp=unconfined --security-opt systempaths=unconfined \
  ${keys[@]+"${keys[@]}"} "$image" "$@"
