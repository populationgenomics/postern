#!/usr/bin/env bash
# Build postern's Linux wheel for this machine's architecture into dist/, the way
# an install from the sdist would, then tag it for PyPI and check it.
#
#   tools/build_wheel.sh
#
# setup.py tags the wheel linux_<arch>, which only a local installer accepts. Its
# native files, the init and the launcher, are statically linked, so they run
# under any libc: the wheel can claim manylinux and musllinux.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

# No target: uv builds the sdist, then the wheel from the unpacked sdist.
uv build --out-dir dist
shopt -s nullglob
built=(dist/*-linux_*.whl)
if [ "${#built[@]}" -ne 1 ]; then
  echo "expected one linux_<arch> wheel in dist/, found ${#built[@]}" >&2
  exit 1
fi
platform="${built[0]##*-}"
arch="${platform%.whl}"
arch="${arch#linux_}"
uvx --from 'wheel>=0.40' wheel tags --remove \
  --platform-tag "manylinux_2_17_${arch}.manylinux2014_${arch}.musllinux_1_1_${arch}" "${built[0]}"
python3 tools/check_wheel.py dist/*.whl
