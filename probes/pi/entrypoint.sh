#!/usr/bin/env bash
# PROBE — throwaway, lives on `pi-probe`. The container's entrypoint: start the executor over a
# verified guest, then run one mode against it.
#
#   seam            the seam, timed, against the real guest (no model)
#   tools           Pi's seven built-in tools through the seam (no model)
#   pi [pi args…]   Pi's TUI with the extension loaded; needs a provider key in the environment
#   <anything else> exec'd as-is, with the executor running
set -euo pipefail

SOCKET=/run/pi-probe/exec.sock
# Two directories, one name. The guest's /workspace is HOST_WORKSPACE, bound in by postern. Pi's
# /workspace is this empty directory: Pi is told the guest's path, and anything Pi's own code does
# with a path locally (stat, realpath, an edit preview) lands here and finds nothing.
WORKSPACE=/workspace
HOST_WORKSPACE=/var/lib/pi-probe/workspace
mkdir -p "$(dirname "$SOCKET")" "$WORKSPACE" "$HOST_WORKSPACE"
chmod 0555 "$WORKSPACE"

# The executor gets none of this environment, so it never holds the model credential Pi does.
env -i PATH="$PATH" PYTHONUNBUFFERED=1 python /opt/pi-probe/executor.py "$SOCKET" "$HOST_WORKSPACE" /opt/guest-root &
executor=$!
until [[ -S $SOCKET ]]; do
  # verify() failing is the executor exiting here: refuse rather than run tools anywhere else.
  kill -0 "$executor" 2>/dev/null || { echo 'entrypoint: the executor exited before serving' >&2; exit 1; }
  sleep 0.05
done

export PI_POSTERN_SOCKET=$SOCKET PI_POSTERN_WORKSPACE=$WORKSPACE
mode=${1:-seam}
[[ $# -gt 0 ]] && shift
case $mode in
  seam) exec node /opt/pi-probe/seam.ts ;;
  tools) exec node /opt/pi-probe/tools.ts ;;
  # Discovery off: the container's dotfiles are not the session's.
  pi) cd "$WORKSPACE" && exec pi --extension /opt/pi-probe --no-skills --no-context-files "$@" ;;
  *) exec "$mode" "$@" ;;
esac
