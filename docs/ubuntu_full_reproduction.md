# Ubuntu Full Reproduction Guide

This guide explains how to run the full VEA-AEG reproduction on Ubuntu or an
Ubuntu virtual machine and produce a paper-format result table:

```text
Challenge | NX | PIE | AEGAngr | Zeratool | BofAEG | VEA-AEG
```

The paper did not publish the original VEA-AEG source code, exact command-line
parameters, baseline tool commits, or challenge hashes. This repository
therefore implements an independent reproduction from the paper description and
stores per-challenge JSON details for audit.

## 1. Recommended Environment

Paper environment:

```text
Ubuntu 18.04
Linux kernel 5.4.0
Intel i7-11800H @ 2.30GHz
4GB RAM
```

Practical test environment:

```text
Ubuntu 18.04 / 20.04 / 22.04 x86_64
Python 3.10+
8GB RAM or more
20GB free disk space
```

Required system tools:

```text
gcc/g++ multilib
gdb
binutils
checksec
radare2
patchelf
libc6-i386
libc6-dbg
git
curl/wget
socat
```

Required Python packages are listed in `requirements.txt`.

## 2. Clone The Repository

```bash
git clone https://github.com/MuzeAnisichael/vea-aeg-reproduction.git
cd vea-aeg-reproduction
```

To use the marked version for this update:

```bash
git fetch --tags
git checkout ubuntu-full-flow-v0.1
```

## 3. Install The VEA-AEG Environment

Use the helper script:

```bash
bash scripts/bootstrap_ubuntu.sh
source .venv/bin/activate
```

If Ubuntu 18.04 does not provide Python 3.10 by default, install Python 3.10 and
run:

```bash
PYTHON_BIN=python3.10 bash scripts/bootstrap_ubuntu.sh
source .venv/bin/activate
```

Confirm the core tools:

```bash
r2 -v
python -c "import angr, claripy, pwn, r2pipe; print('python deps ok')"
```

If `apt` cannot install `radare2`, install radare2 manually before strict runs.

## 4. Download Challenge Binaries

The manifest is:

```text
data/challenge_manifest.json
```

Download all public challenge binaries:

```bash
python -m vea_aeg download-data \
  --manifest data/challenge_manifest.json \
  --data-dir data/challenges
```

Public sources:

```text
https://github.com/ctf-wiki/ctf-challenges
https://github.com/LaiLaK918/bofAEG
```

## 5. Install Baseline Tools

The paper compares against:

```text
AEGAngr
Zeratool
BofAEG
```

Install their public repositories:

```bash
bash scripts/install_baselines_ubuntu.sh
```

Default paths:

```text
third_party/AEG-ANGR
third_party/Zeratool
third_party/bofAEG
```

Baseline command templates are stored in:

```text
configs/baselines.ubuntu.json
```

If a cloned tool uses a different entrypoint, edit the corresponding `commands`
array. If no configured command exists, the table records `N/R`.

## 6. Disable ASLR For Paper-Like Local Runs

Before running:

```bash
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

After running:

```bash
echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
```

## 7. Run The Full Experiment

One-command run:

```bash
bash scripts/run_ubuntu_full_experiment.sh
```

Equivalent explicit command:

```bash
python -m vea_aeg ubuntu-experiment \
  --manifest data/challenge_manifest.json \
  --data-dir data/challenges \
  --out-dir reports \
  --repo-root "$PWD" \
  --baseline-config configs/baselines.ubuntu.json \
  --tool-root third_party \
  --baseline-timeout 900 \
  --vea-timeout 120 \
  --max-steps 2000 \
  --input-size 256 \
  --inventory-backend auto
```

Run only the repository VEA-AEG flow:

```bash
python -m vea_aeg ubuntu-experiment \
  --manifest data/challenge_manifest.json \
  --data-dir data/challenges \
  --out-dir reports \
  --repo-root "$PWD" \
  --skip-baselines \
  --inventory-backend auto
```

Skip local payload execution while keeping payload generation:

```bash
python -m vea_aeg ubuntu-experiment \
  --manifest data/challenge_manifest.json \
  --data-dir data/challenges \
  --out-dir reports \
  --repo-root "$PWD" \
  --skip-validate
```

## 8. Output Files

```text
reports/ubuntu_full_experiment_table.md
reports/ubuntu_full_experiment_table.csv
reports/ubuntu_full_experiment_results.json
reports/ubuntu_full_details/<challenge>.json
reports/payloads/<challenge>.payload
```

Meaning:

```text
ubuntu_full_experiment_table.md      paper-format Markdown table
ubuntu_full_experiment_table.csv     paper-format CSV table
ubuntu_full_experiment_results.json  complete structured result set
ubuntu_full_details/*.json           per-challenge stage details
payloads/*.payload                   payloads extracted from symbolic states
```

## 9. Result Values

```text
0.123s        tool completed successfully or found an exploitable state
N/R           not run, not installed, disabled, or command unavailable
T/O           timeout
FAIL          completed but did not find an exploitable result
ERR:<type>    internal exception or external tool error
```

The `VEA-AEG` column runs this repository's implementation:

```text
1. dangerous function location, CFGEmulated, CDG/DDG BackwardSlice, fallback slicing
2. symbolic execution and exploitability classification
3. exploit-plan selection, payload extraction, and optional local validation
```

The `AEGAngr`, `Zeratool`, and `BofAEG` columns are produced by external tools
through `configs/baselines.ubuntu.json`.

## 10. Troubleshooting

If baseline columns show `N/R`:

```text
1. Run bash scripts/install_baselines_ubuntu.sh
2. Check configs/baselines.ubuntu.json entrypoints
3. Run the baseline command manually for one binary
```

If `VEA-AEG` shows `ERR:FileNotFoundError`:

```text
1. Older versions forced radare2 inventory even when --skip-baselines was used
2. Use the current default --inventory-backend auto
3. If you want strict paper-like radare2 inventory, install radare2 and use --inventory-backend radare2
4. If you only want to keep the flow running, use --inventory-backend basic
```

If radare2 fails:

```text
1. Confirm r2 -v works
2. Confirm python -c "import r2pipe" works
3. Install radare2 manually if the Ubuntu package is unavailable
```

If angr is too slow:

```text
1. Lower --max-steps
2. Lower --input-size
3. Lower --vea-timeout
4. Use --skip-baselines for first validation
```

If results differ from the paper:

```text
1. The original VEA-AEG code and exact parameters are not public
2. Public CTF binaries may differ from the authors' local files
3. libc, loader, kernel, angr, radare2, and pwntools versions affect results
4. Inspect reports/ubuntu_full_details/*.json for stage-level causes
```
