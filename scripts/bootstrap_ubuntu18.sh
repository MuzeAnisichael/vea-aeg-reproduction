#!/usr/bin/env bash
set -euo pipefail

python_bin="${PYTHON_BIN:-python3}"

sudo apt-get update
sudo apt-get install -y \
  build-essential \
  gcc-multilib \
  g++-multilib \
  gdb \
  binutils \
  file \
  patchelf \
  libc6-i386 \
  libc6-dbg \
  radare2

"${python_bin}" -m pip install -U pip setuptools wheel
"${python_bin}" -m pip install -r requirements.txt

echo "VEA-AEG reproduction dependencies installed."

