# VEA-AEG Reproduction

This repository contains an independent reproduction scaffold for the paper
`VEA-AEG: An Automated Exploit Generation Method Based on Vulnerability
Exploitability Analysis`.

New Ubuntu full-flow entrypoint:

```bash
bash scripts/bootstrap_ubuntu.sh
source .venv/bin/activate
python -m vea_aeg download-data
bash scripts/install_baselines_ubuntu.sh
bash scripts/run_ubuntu_full_experiment.sh
```

When running without baseline tools, keep the VEA-AEG resource inventory backend
on `auto` unless radare2 is installed:

```bash
python -m vea_aeg ubuntu-experiment --skip-baselines --inventory-backend auto
```

Use `--inventory-backend basic` to force the pure Python inventory fallback, or
`--inventory-backend radare2` for strict radare2 inventory.

Main outputs:

```text
reports/ubuntu_full_experiment_table.md
reports/ubuntu_full_experiment_table.csv
reports/ubuntu_full_experiment_results.json
reports/ubuntu_full_details/
reports/payloads/
```

Detailed instructions:
[`docs/ubuntu_full_reproduction.md`](docs/ubuntu_full_reproduction.md) and
[`docs/ubuntu_full_reproduction_zh.md`](docs/ubuntu_full_reproduction_zh.md).

The result table keeps the paper columns:

```text
Challenge | NX | PIE | AEGAngr | Zeratool | BofAEG | VEA-AEG
```

The original VEA-AEG implementation, exact parameters, baseline commits, and
challenge hashes were not published, so this repository records detailed JSON
evidence for every challenge.

# VEA-AEG Reproduction Scaffold

这是 `PAPER.docx` 中 VEA-AEG 方法的复现仓库骨架。目标是把论文中的三个核心算法拆成可运行模块：

- 算法 1：危险函数定位、CFG 构建、可疑路径切片。
- 算法 2：基于符号状态的漏洞可利用性判定。
- 算法 3：栈指针重定向和漏洞利用约束构建。

当前仓库先实现复现框架、CLI、环境脚本、单元测试和本地 toy 样例。完整秒级结果复现还需要论文实验样本、libc 版本、基线工具配置和更精确的阈值参数。

## Safety Scope

本项目仅用于授权的本地 CTF/教学样本和论文复现实验。不要对第三方程序、服务或未经授权的目标运行。

## Environment

论文环境：

- Ubuntu 18.04
- Linux kernel 5.4.0
- Intel Core i7-11800H @ 2.30 GHz
- 4 GB RAM

建议环境：

- Ubuntu 18.04/20.04 x86_64 VM
- Python 3.10+
- 8 GB+ RAM
- `gcc`, `gdb`, `binutils`, `checksec`, `radare2`
- Python packages listed in `requirements.txt`

Install Python packages:

```bash
python3 -m pip install -U pip setuptools wheel
python3 -m pip install -r requirements.txt
```

Ubuntu helper:

```bash
bash scripts/bootstrap_ubuntu18.sh
```

## Quick Start

List the default dangerous function set:

```bash
python3 -m vea_aeg dangerous
```

Build the toy sample:

```bash
cd examples/toy
gcc -fno-stack-protector -no-pie -o vuln64 overflow.c
```

Run static analysis:

```bash
python3 -m vea_aeg analyze examples/toy/vuln64 --json
```

Run unit tests that do not require angr:

```bash
python3 -m unittest discover -s tests
```

## Repository Layout

```text
src/vea_aeg/
  dangerous_functions.py  Dangerous-function list and loading helpers
  static_analysis.py      Algorithm 1 scaffold: PLT, CFG, suspicious slices
  path_optimizer.py       Directed symbolic-execution path pruning helpers
  exploitability.py       Algorithm 2 symbolic-state exploitability rules
  exploit_builder.py      Algorithm 3 planning interface and resource inventory
  cli.py                  Command-line interface
docs/
  reproduction_plan.md    Phased reproduction method
  paper_mapping.md        Paper-to-code mapping
examples/toy/
  overflow.c              Local-only toy binary for smoke tests
scripts/
  bootstrap_ubuntu18.sh   System and Python dependency bootstrap
tests/
  unittest-based tests
```

## Current Status

Implemented:

- Dangerous-function inventory.
- PLT and suspicious callsite discovery scaffold through angr.
- Directed path-pruning helpers.
- Symbolic IP/BP and memory read/write classification helpers.
- radare2-based resource inventory scaffold.
- CLI and tests.

Not yet fully implemented:

- Exact DDG/CDG backward slicing parity with the paper.
- Full exploit payload generation.
- Baseline reproduction for AEGAngr, Zeratool, and BofAEG.
- Paper Table 2 timing reproduction.
