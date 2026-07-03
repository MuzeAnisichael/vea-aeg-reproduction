# Ubuntu 完整复现实验操作说明

本文档指导你在 Ubuntu 系统或 Ubuntu 虚拟机中运行本仓库的完整复现实验，最终生成论文同格式实验表：

```text
Challenge | NX | PIE | AEGAngr | Zeratool | BofAEG | VEA-AEG
```

说明：论文没有公开 VEA-AEG 原始源码、精确参数、基线工具版本和样本 hash。本仓库实现的是基于论文描述的独立复现流程，并为每个样本保存 JSON 明细，方便解释每个结果的来源。

## 1. 环境要求

论文环境：

```text
Ubuntu 18.04
Linux kernel 5.4.0
Intel i7-11800H @ 2.30GHz
4GB RAM
```

建议环境：

```text
Ubuntu 18.04 / 20.04 / 22.04 x86_64
Python 3.10+
8GB 以上内存
20GB 以上可用磁盘
```

需要的系统工具：

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

## 2. 获取代码

```bash
git clone https://github.com/MuzeAnisichael/vea-aeg-reproduction.git
cd vea-aeg-reproduction
```

如果要切到本次更新的标识版本：

```bash
git fetch --tags
git checkout ubuntu-full-flow-v0.1
```

## 3. 安装复现环境

推荐直接执行：

```bash
bash scripts/bootstrap_ubuntu.sh
source .venv/bin/activate
```

如果 Ubuntu 18.04 默认 Python 版本低于 3.10，先安装 Python 3.10，然后执行：

```bash
PYTHON_BIN=python3.10 bash scripts/bootstrap_ubuntu.sh
source .venv/bin/activate
```

检查依赖：

```bash
r2 -v
python -c "import angr, claripy, pwn, r2pipe; print('python deps ok')"
```

如果 `apt` 无法安装 `radare2`，需要手动安装 radare2 后再运行实验。

## 4. 下载实验样本

样本清单：

```text
data/challenge_manifest.json
```

下载命令：

```bash
python -m vea_aeg download-data \
  --manifest data/challenge_manifest.json \
  --data-dir data/challenges
```

公开来源：

```text
https://github.com/ctf-wiki/ctf-challenges
https://github.com/LaiLaK918/bofAEG
```

## 5. 安装三个基线工具

论文对比工具：

```text
AEGAngr
Zeratool
BofAEG
```

执行：

```bash
bash scripts/install_baselines_ubuntu.sh
```

默认会放到：

```text
third_party/AEG-ANGR
third_party/Zeratool
third_party/bofAEG
```

基线命令配置文件：

```text
configs/baselines.ubuntu.json
```

如果某个工具的入口脚本名称和配置不一致，修改该文件里的 `commands`。程序会按顺序尝试命令；如果都不可用，结果表中该工具显示 `N/R`。

## 6. 关闭 ASLR

为了更接近论文中的本地 CTF 复现条件，建议运行实验前关闭 ASLR：

```bash
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

实验结束后恢复：

```bash
echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
```

## 7. 运行完整实验

一键运行：

```bash
bash scripts/run_ubuntu_full_experiment.sh
```

等价的完整命令：

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
  --input-size 256
```

只运行本仓库的 VEA-AEG 流程，不运行三个基线：

```bash
python -m vea_aeg ubuntu-experiment \
  --manifest data/challenge_manifest.json \
  --data-dir data/challenges \
  --out-dir reports \
  --repo-root "$PWD" \
  --skip-baselines
```

生成 payload 但不执行本地验证：

```bash
python -m vea_aeg ubuntu-experiment \
  --manifest data/challenge_manifest.json \
  --data-dir data/challenges \
  --out-dir reports \
  --repo-root "$PWD" \
  --skip-validate
```

## 8. 输出文件

运行后生成：

```text
reports/ubuntu_full_experiment_table.md
reports/ubuntu_full_experiment_table.csv
reports/ubuntu_full_experiment_results.json
reports/ubuntu_full_details/<challenge>.json
reports/payloads/<challenge>.payload
```

含义：

```text
ubuntu_full_experiment_table.md      论文格式 Markdown 表
ubuntu_full_experiment_table.csv     论文格式 CSV 表
ubuntu_full_experiment_results.json  全量结构化结果
ubuntu_full_details/*.json           每个样本的阶段明细
payloads/*.payload                   从符号执行状态中导出的 payload
```

## 9. 结果字段含义

```text
0.123s        工具成功运行或发现可利用状态，耗时 0.123 秒
N/R           not run，工具未安装、被跳过或命令不可用
T/O           timeout，超过配置的超时时间
FAIL          运行完成但没有发现可利用结果
ERR:<type>    内部异常或外部工具错误
```

`VEA-AEG` 列执行本仓库实现的论文流程：

```text
1. Algorithm 1：危险函数定位、CFGEmulated、CDG/DDG BackwardSlice，失败时回退到 CFG 前驱切片
2. Algorithm 2：符号执行、unconstrained state、IP/BP/内存读写可利用性规则
3. Algorithm 3：利用策略选择、payload 导出、本地验证
```

`AEGAngr`、`Zeratool`、`BofAEG` 列由 `configs/baselines.ubuntu.json` 调用外部工具得到。

## 10. 常见问题

如果基线列显示 `N/R`：

```text
1. 先执行 bash scripts/install_baselines_ubuntu.sh
2. 检查 configs/baselines.ubuntu.json 中的入口脚本是否存在
3. 单独运行该工具命令，确认工具本身可以启动
```

如果 radare2 报错：

```text
1. 确认 r2 -v 可运行
2. 确认 python -c "import r2pipe" 可运行
3. 如果 apt 没有 radare2，用源码或发行版安装包手动安装
```

如果 angr 太慢：

```text
1. 降低 --max-steps
2. 降低 --input-size
3. 降低 --vea-timeout
4. 先用 --skip-baselines 验证 VEA-AEG 流程
```

如果结果和论文不同：

```text
1. 论文未公开 VEA-AEG 原始代码和全部实验参数
2. 公开 CTF 样本可能和作者本地样本 hash 不完全一致
3. libc、loader、kernel、angr、radare2、pwntools 版本都会影响耗时和成功率
4. 查看 reports/ubuntu_full_details/*.json 可以定位每个样本失败、超时或成功的阶段
```
