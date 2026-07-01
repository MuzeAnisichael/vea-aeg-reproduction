# Windows Native Flow

Use this path when the goal is to run through the VEA-AEG process, not to
strictly reproduce the paper's Linux timing table.

## What This Can Validate

- The dangerous-function inventory loads.
- The exploitability rules classify simulated symbolic states.
- The planner maps findings to exploit strategies.
- The CLI and report serialization work on Windows.

## What This Does Not Validate

- Linux ELF loader behavior.
- libc, PLT/GOT, syscall, NX, PIE, and ASLR behavior.
- Real payload execution.
- Paper Table 2 timing results.

## Setup

From PowerShell:

```powershell
cd D:\FUXIAN1\vea-aeg-reproduction
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip setuptools wheel
python -m pip install -r requirements.txt
$env:PYTHONPATH = "src"
```

If dependency installation is slow or fails, you can still run the smoke path
without installing optional binary-analysis dependencies:

```powershell
$env:PYTHONPATH = "src"
python -m vea_aeg smoke --json
python -m unittest discover -s tests
```

If `gcc` or `radare2` fail to install, skip them. The Windows flow has a
pure-Python inventory backend:

```powershell
python -m vea_aeg inventory C:\Windows\System32\notepad.exe --backend basic --json
```

The default `inventory` mode is `auto`, so it will use radare2 when present and
fall back to the basic backend when it is not:

```powershell
python -m vea_aeg inventory C:\Windows\System32\notepad.exe --json
```

## Smoke Flow

```powershell
python -m vea_aeg dangerous
python -m vea_aeg smoke --json
python -m vea_aeg inventory C:\Windows\System32\notepad.exe --backend basic --json
python -m vea_aeg plan IP_OVERWRITE --json
python -m vea_aeg plan WRITE_WHAT_WHERE --json
```

This exercises:

1. Paper input concept: dangerous functions.
2. Paper Algorithm 2 concept: symbolic IP and symbolic memory write.
3. Paper Algorithm 3 concept: exploit strategy selection.
4. Report output.

## Upgrade Path

After the Windows smoke flow works, use WSL2/Docker/VM only for the Linux-only
parts: compiling ELF samples, running radare2/gdb/checksec, and verifying
payloads against Linux libc.

## Paper-Format Table on Windows

Download the public challenge binaries listed in `data/challenge_manifest.json`:

```powershell
python -m vea_aeg download-data --json
```

Generate a table with the same columns as the paper:

```powershell
python -m vea_aeg experiment
```

Outputs:

- `reports/windows_basic_experiment_table.md`
- `reports/windows_basic_experiment_table.csv`

The Windows table uses:

- computed ELF `NX` and `PIE` where the binary is available;
- `N/R` for AEGAngr, Zeratool, and BofAEG because those baselines are not run
  in the Windows basic mode;
- local Windows basic-backend runtime in the `VEA-AEG` column.
