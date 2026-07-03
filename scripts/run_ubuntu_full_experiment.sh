#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

if [ -f ".venv/bin/activate" ]; then
  # shellcheck source=/dev/null
  source ".venv/bin/activate"
fi

python -m vea_aeg download-data --manifest data/challenge_manifest.json --data-dir data/challenges
python -m vea_aeg ubuntu-experiment \
  --manifest data/challenge_manifest.json \
  --data-dir data/challenges \
  --out-dir reports \
  --repo-root "${repo_root}" \
  --baseline-config configs/baselines.ubuntu.json \
  --tool-root third_party \
  --baseline-timeout "${BASELINE_TIMEOUT:-900}" \
  --vea-timeout "${VEA_TIMEOUT:-120}" \
  --max-steps "${VEA_MAX_STEPS:-2000}" \
  --input-size "${VEA_INPUT_SIZE:-256}"
