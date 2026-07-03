from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import json
import os
import shutil
import subprocess
import time
from typing import Dict, Iterable, List, Optional


DEFAULT_BASELINE_CONFIG = Path("configs/baselines.ubuntu.json")
DEFAULT_TOOL_ROOT = Path("third_party")


@dataclass
class BaselineSpec:
    name: str
    commands: List[List[str]]
    enabled: bool = True
    cwd: Optional[str] = None
    timeout_seconds: float = 900.0
    success_patterns: List[str] = field(
        default_factory=lambda: ["success", "shell", "flag", "payload", "win"]
    )


@dataclass
class BaselineRun:
    name: str
    status: str
    display: str
    elapsed_seconds: float = 0.0
    command: List[str] = field(default_factory=list)
    returncode: Optional[int] = None
    stdout_tail: str = ""
    stderr_tail: str = ""
    notes: List[str] = field(default_factory=list)


def default_baseline_specs(timeout_seconds: float = 900.0) -> List[BaselineSpec]:
    return [
        BaselineSpec(
            name="AEGAngr",
            timeout_seconds=timeout_seconds,
            commands=[
                ["python3", "{tool_root}/AEG-ANGR/aeg.py", "{binary}"],
                ["python3", "{tool_root}/AEG-ANGR/main.py", "{binary}"],
                ["python3", "{tool_root}/AEG-ANGR/AEG.py", "{binary}"],
            ],
        ),
        BaselineSpec(
            name="Zeratool",
            timeout_seconds=timeout_seconds,
            commands=[
                ["zerapwn.py", "{binary}", "--skip_check", "--overflow_only", "--no_win"],
                [
                    "python3",
                    "{tool_root}/Zeratool/bin/zerapwn.py",
                    "{binary}",
                    "--skip_check",
                    "--overflow_only",
                    "--no_win",
                ],
                [
                    "python3",
                    "{tool_root}/Zeratool/zerapwn.py",
                    "{binary}",
                    "--skip_check",
                    "--overflow_only",
                    "--no_win",
                ],
            ],
        ),
        BaselineSpec(
            name="BofAEG",
            timeout_seconds=timeout_seconds,
            commands=[
                ["python3", "{tool_root}/bofAEG/bofAEG.py", "{binary}"],
                ["python3", "{tool_root}/bofAEG/bof_aeg.py", "{binary}"],
                ["python3", "{tool_root}/bofAEG/main.py", "{binary}"],
                ["python3", "{tool_root}/bof_aeg/bofAEG.py", "{binary}"],
            ],
        ),
    ]


def load_baseline_specs(
    path: str | Path | None = DEFAULT_BASELINE_CONFIG,
    *,
    timeout_seconds: float = 900.0,
) -> List[BaselineSpec]:
    config_path = Path(path) if path else DEFAULT_BASELINE_CONFIG
    if not config_path.exists():
        return default_baseline_specs(timeout_seconds)

    raw = json.loads(config_path.read_text(encoding="utf-8"))
    items = raw.get("tools", raw) if isinstance(raw, dict) else raw
    specs: List[BaselineSpec] = []
    for item in items:
        specs.append(
            BaselineSpec(
                name=item["name"],
                commands=[list(command) for command in item.get("commands", [])],
                enabled=bool(item.get("enabled", True)),
                cwd=item.get("cwd"),
                timeout_seconds=float(item.get("timeout_seconds", timeout_seconds)),
                success_patterns=list(
                    item.get(
                        "success_patterns",
                        ["success", "shell", "flag", "payload", "win"],
                    )
                ),
            )
        )
    return specs


def _format_template(value: str, variables: Dict[str, str]) -> str:
    return value.format(**variables)


def _looks_like_path(value: str) -> bool:
    return "/" in value or "\\" in value or value.startswith(".")


def _command_available(command: List[str]) -> bool:
    if not command:
        return False
    executable = command[0]
    if shutil.which(executable) is None and not Path(executable).exists():
        return False
    for arg in command[1:]:
        if _looks_like_path(arg) and not arg.startswith("-"):
            if not Path(arg).exists():
                return False
    return True


def resolve_command(
    spec: BaselineSpec,
    *,
    binary: str | Path,
    repo_root: str | Path,
    tool_root: str | Path = DEFAULT_TOOL_ROOT,
) -> Optional[List[str]]:
    variables = {
        "binary": str(Path(binary).resolve()),
        "challenge": Path(binary).name,
        "repo": str(Path(repo_root).resolve()),
        "tool_root": str((Path(repo_root) / tool_root).resolve()),
        "python": shutil.which("python3") or "python3",
    }
    for template in spec.commands:
        command = [_format_template(part, variables) for part in template]
        if _command_available(command):
            return command
    return None


def _tail(text: str, limit: int = 4000) -> str:
    return text[-limit:] if len(text) > limit else text


def _success_from_output(output: str, patterns: Iterable[str]) -> bool:
    lowered = output.lower()
    return any(pattern.lower() in lowered for pattern in patterns)


def run_baseline(
    spec: BaselineSpec,
    *,
    binary: str | Path,
    repo_root: str | Path,
    tool_root: str | Path = DEFAULT_TOOL_ROOT,
) -> BaselineRun:
    if not spec.enabled:
        return BaselineRun(spec.name, "N/R", "N/R", notes=["disabled in baseline config"])

    command = resolve_command(spec, binary=binary, repo_root=repo_root, tool_root=tool_root)
    if command is None:
        return BaselineRun(
            spec.name,
            "N/R",
            "N/R",
            notes=["no configured command was available on this host"],
        )

    cwd = spec.cwd.format(repo=str(Path(repo_root).resolve())) if spec.cwd else str(Path(repo_root))
    env = os.environ.copy()
    env.setdefault("PWNLIB_NOTERM", "1")

    started = time.perf_counter()
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=spec.timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        elapsed = time.perf_counter() - started
        return BaselineRun(
            spec.name,
            "T/O",
            "T/O",
            elapsed_seconds=elapsed,
            command=command,
            stdout_tail=_tail(exc.stdout or ""),
            stderr_tail=_tail(exc.stderr or ""),
            notes=[f"timeout after {spec.timeout_seconds:.0f}s"],
        )

    elapsed = time.perf_counter() - started
    output = f"{completed.stdout}\n{completed.stderr}"
    success = completed.returncode == 0 or _success_from_output(output, spec.success_patterns)
    status = "OK" if success else f"ERR:{completed.returncode}"
    display = f"{elapsed:.3f}s" if success else status
    return BaselineRun(
        spec.name,
        status,
        display,
        elapsed_seconds=elapsed,
        command=command,
        returncode=completed.returncode,
        stdout_tail=_tail(completed.stdout),
        stderr_tail=_tail(completed.stderr),
    )


def run_baselines(
    specs: Iterable[BaselineSpec],
    *,
    binary: str | Path,
    repo_root: str | Path,
    tool_root: str | Path = DEFAULT_TOOL_ROOT,
) -> Dict[str, BaselineRun]:
    return {
        spec.name: run_baseline(spec, binary=binary, repo_root=repo_root, tool_root=tool_root)
        for spec in specs
    }
