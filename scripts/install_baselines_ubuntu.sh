#!/usr/bin/env bash
set -euo pipefail

tool_root="${TOOL_ROOT:-third_party}"
python_bin="${PYTHON_BIN:-python3}"

mkdir -p "${tool_root}"

clone_if_missing() {
  local url="$1"
  local target="$2"
  if [ -d "${target}/.git" ]; then
    echo "exists: ${target}"
    return 0
  fi
  git clone --depth 1 "${url}" "${target}"
}

install_python_project_if_possible() {
  local target="$1"
  if [ -f "${target}/requirements.txt" ]; then
    "${python_bin}" -m pip install -r "${target}/requirements.txt" || true
  fi
  if [ -f "${target}/setup.py" ] || [ -f "${target}/pyproject.toml" ]; then
    "${python_bin}" -m pip install -e "${target}" || true
  fi
}

clone_if_missing "https://github.com/PIG-007/AEG-ANGR.git" "${tool_root}/AEG-ANGR"
clone_if_missing "https://github.com/ChrisTheCoolHut/Zeratool.git" "${tool_root}/Zeratool"
clone_if_missing "https://github.com/LaiLaK918/bofAEG.git" "${tool_root}/bofAEG"

install_python_project_if_possible "${tool_root}/AEG-ANGR"
install_python_project_if_possible "${tool_root}/Zeratool"
install_python_project_if_possible "${tool_root}/bofAEG"

"${python_bin}" -m pip install zeratool || true

echo "Baseline repositories are in ${tool_root}."
echo "Review configs/baselines.ubuntu.json if a cloned tool uses a different entrypoint."
