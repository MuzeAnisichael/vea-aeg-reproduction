#!/usr/bin/env bash
set -euo pipefail

python_bin="${PYTHON_BIN:-python3}"
venv_dir="${VENV_DIR:-.venv}"

sudo apt-get update
sudo apt-get install -y \
  binutils \
  build-essential \
  checksec \
  curl \
  file \
  g++-multilib \
  gcc-multilib \
  gdb \
  git \
  libc6-dbg \
  libc6-i386 \
  patchelf \
  python3-dev \
  python3-pip \
  python3-venv \
  socat \
  tmux \
  wget

if ! command -v r2 >/dev/null 2>&1; then
  if ! sudo apt-get install -y radare2; then
    echo "WARNING: apt could not install radare2. Install radare2 manually before strict runs."
  fi
fi

"${python_bin}" -m venv "${venv_dir}"
# shellcheck source=/dev/null
source "${venv_dir}/bin/activate"
python -m pip install -U pip setuptools wheel
python -m pip install -r requirements.txt
python -m pip install -e .

echo "Ubuntu VEA-AEG environment is ready."
echo "Activate it with: source ${venv_dir}/bin/activate"
