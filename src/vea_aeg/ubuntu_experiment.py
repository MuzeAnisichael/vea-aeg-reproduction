from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
import csv
import json
import subprocess
import time
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .baselines import (
    BaselineRun,
    DEFAULT_BASELINE_CONFIG,
    DEFAULT_TOOL_ROOT,
    load_baseline_specs,
    run_baselines,
)
from .dataset import ChallengeResource, DEFAULT_DATA_DIR, DEFAULT_MANIFEST, load_manifest
from .experiment import ExperimentRow, inspect_elf_nx_pie, markdown_table
from .exploit_builder import ExploitPlan, choose_exploit_plan, inventory_binary
from .exploitability import ExploitabilityFinding, classify_simgr_unconstrained, classify_state
from .report import to_jsonable
from .static_analysis import analyze_static


CONTROL_SYMBOL_NAMES = (
    "win",
    "shell",
    "get_shell",
    "print_flag",
    "flag",
    "winner",
    "system",
)


@dataclass
class SymbolicRunResult:
    findings: List[ExploitabilityFinding] = field(default_factory=list)
    unconstrained_count: int = 0
    steps: int = 0
    timed_out: bool = False
    error: Optional[str] = None
    payload: Optional[bytes] = None
    payload_target: Optional[str] = None


@dataclass
class PayloadValidation:
    status: str
    elapsed_seconds: float = 0.0
    returncode: Optional[int] = None
    stdout_tail: str = ""
    stderr_tail: str = ""
    notes: List[str] = field(default_factory=list)


@dataclass
class VeaRunResult:
    status: str
    display: str
    elapsed_seconds: float
    static_slices: int
    findings: List[ExploitabilityFinding]
    plan: Optional[ExploitPlan]
    payload_path: Optional[str]
    payload_target: Optional[str]
    validation: Optional[PayloadValidation]
    notes: List[str] = field(default_factory=list)


@dataclass
class UbuntuChallengeResult:
    row: ExperimentRow
    vea: Optional[VeaRunResult]
    baselines: Dict[str, BaselineRun]


@dataclass
class UbuntuExperimentOutputs:
    markdown: str
    csv: str
    json: str
    details_dir: str


def _unique_findings(findings: Iterable[ExploitabilityFinding]) -> List[ExploitabilityFinding]:
    seen = set()
    result: List[ExploitabilityFinding] = []
    for finding in findings:
        key = (finding.rule, finding.vulnerability_type, finding.evidence)
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)
    return result


def _state_addr(state) -> Optional[int]:
    addr = getattr(state, "addr", None)
    try:
        return int(addr) if addr is not None else None
    except TypeError:
        return None


def _prioritize_states(simgr, suspicious_addresses: Sequence[int], *, max_active: int) -> None:
    active = list(getattr(simgr, "active", []))
    if not active:
        return
    suspicious = set(suspicious_addresses)
    active.sort(key=lambda state: 0 if _state_addr(state) in suspicious else 1)
    simgr.stashes["active"] = active[:max_active]
    if len(active) > max_active:
        simgr.stashes.setdefault("deferred", []).extend(active[max_active:])


def _reactivate_deferred(simgr) -> None:
    if getattr(simgr, "active", []):
        return
    deferred = simgr.stashes.get("deferred", [])
    if deferred:
        simgr.stashes["active"] = [deferred.pop()]


def _find_control_target(project) -> Tuple[Optional[int], Optional[str]]:
    main_object = project.loader.main_object
    for name in CONTROL_SYMBOL_NAMES:
        symbol = main_object.get_symbol(name)
        if symbol is not None and getattr(symbol, "rebased_addr", None):
            return int(symbol.rebased_addr), name
    return None, None


def _try_extract_payload(project, state, input_bv) -> Tuple[Optional[bytes], Optional[str]]:
    ip = getattr(state.regs, "ip", None)
    if ip is None or not state.solver.symbolic(ip):
        return None, None

    target, target_name = _find_control_target(project)
    if target is not None:
        try:
            state.solver.add(ip == target)
        except Exception:
            return None, None
    try:
        return state.solver.eval(input_bv, cast_to=bytes), target_name or "symbolic-ip"
    except Exception:
        return None, None


def run_symbolic_flow(
    binary: str | Path,
    suspicious_addresses: Sequence[int],
    *,
    input_size: int = 256,
    timeout_seconds: float = 120.0,
    max_steps: int = 2000,
    max_active: int = 8,
) -> SymbolicRunResult:
    try:
        import angr  # type: ignore
        import claripy  # type: ignore
    except ImportError as exc:
        return SymbolicRunResult(error=f"missing dependency: {exc}")

    started = time.monotonic()
    try:
        project = angr.Project(str(binary), auto_load_libs=False)
        input_bv = claripy.BVS("stdin_bytes", input_size * 8)
        stdin = angr.SimFileStream(name="stdin", content=input_bv, has_end=True)
        state = project.factory.full_init_state(args=[str(binary)], stdin=stdin)
        state.options.add(angr.options.TRACK_ACTION_HISTORY)
        state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
        state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
        simgr = project.factory.simulation_manager(state, save_unconstrained=True)
    except Exception as exc:
        return SymbolicRunResult(error=f"initialization failed: {type(exc).__name__}: {exc}")

    findings: List[ExploitabilityFinding] = []
    payload: Optional[bytes] = None
    payload_target: Optional[str] = None
    steps = 0
    timed_out = False

    while steps < max_steps:
        if time.monotonic() - started > timeout_seconds:
            timed_out = True
            break
        _reactivate_deferred(simgr)
        if not getattr(simgr, "active", []):
            break
        try:
            simgr.step()
        except Exception as exc:
            return SymbolicRunResult(
                findings=_unique_findings(findings),
                unconstrained_count=len(getattr(simgr, "unconstrained", [])),
                steps=steps,
                error=f"step failed: {type(exc).__name__}: {exc}",
            )
        steps += 1

        if suspicious_addresses:
            _prioritize_states(simgr, suspicious_addresses, max_active=max_active)

        for active_state in getattr(simgr, "active", []):
            findings.extend(classify_state(active_state))

        unconstrained = list(getattr(simgr, "unconstrained", []))
        if unconstrained:
            findings.extend(classify_simgr_unconstrained(simgr))
            for unconstrained_state in unconstrained:
                payload, payload_target = _try_extract_payload(
                    project,
                    unconstrained_state,
                    input_bv,
                )
                if payload:
                    break
            break

    return SymbolicRunResult(
        findings=_unique_findings(findings),
        unconstrained_count=len(getattr(simgr, "unconstrained", [])),
        steps=steps,
        timed_out=timed_out,
        payload=payload,
        payload_target=payload_target,
    )


def _tail_bytes(data: bytes, limit: int = 4000) -> str:
    return data[-limit:].decode("utf-8", errors="replace")


def validate_payload(
    binary: str | Path,
    payload: bytes,
    *,
    timeout_seconds: float = 5.0,
) -> PayloadValidation:
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            [str(Path(binary).resolve())],
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        elapsed = time.perf_counter() - started
        return PayloadValidation(
            status="T/O",
            elapsed_seconds=elapsed,
            stdout_tail=_tail_bytes(exc.stdout or b""),
            stderr_tail=_tail_bytes(exc.stderr or b""),
            notes=[f"payload execution timed out after {timeout_seconds:.0f}s"],
        )
    except OSError as exc:
        elapsed = time.perf_counter() - started
        return PayloadValidation(
            status=f"ERR:{type(exc).__name__}",
            elapsed_seconds=elapsed,
            notes=[str(exc)],
        )

    elapsed = time.perf_counter() - started
    output = f"{_tail_bytes(completed.stdout)}\n{_tail_bytes(completed.stderr)}".lower()
    markers = ("flag", "shell", "win", "success", "$", "#")
    status = "OK" if completed.returncode == 0 or any(marker in output for marker in markers) else "FAIL"
    return PayloadValidation(
        status=status,
        elapsed_seconds=elapsed,
        returncode=completed.returncode,
        stdout_tail=_tail_bytes(completed.stdout),
        stderr_tail=_tail_bytes(completed.stderr),
    )


def _choose_best_finding(findings: Sequence[ExploitabilityFinding]) -> Optional[ExploitabilityFinding]:
    exploitable = [finding for finding in findings if finding.exploitable]
    if exploitable:
        return exploitable[0]
    return findings[0] if findings else None


def run_vea_aeg_full(
    binary: str | Path,
    *,
    out_dir: str | Path,
    cfg_kind: str = "emulated",
    slice_depth: int = 64,
    inventory_backend: str = "auto",
    input_size: int = 256,
    timeout_seconds: float = 120.0,
    max_steps: int = 2000,
    max_active: int = 8,
    skip_validate: bool = False,
) -> VeaRunResult:
    binary_path = Path(binary)
    started = time.perf_counter()
    payload_path: Optional[Path] = None
    notes: List[str] = []

    try:
        static_report = analyze_static(
            binary_path,
            cfg_kind=cfg_kind,
            slice_depth=slice_depth,
            prefer_exact_slice=True,
        )
        suspicious_addresses = sorted(
            {
                address
                for suspicious_slice in static_report.suspicious_slices
                for address in suspicious_slice.addresses
            }
        )
        if not suspicious_addresses:
            suspicious_addresses = [static_report.entry]
            notes.append("no dangerous-function slice found; started symbolic search at entry")

        inventory = inventory_binary(binary_path, backend=inventory_backend)
        notes.extend(inventory.notes)
        symbolic = run_symbolic_flow(
            binary_path,
            suspicious_addresses,
            input_size=input_size,
            timeout_seconds=timeout_seconds,
            max_steps=max_steps,
            max_active=max_active,
        )
        if symbolic.error:
            notes.append(symbolic.error)
        if symbolic.timed_out:
            notes.append("symbolic execution timed out")

        finding = _choose_best_finding(symbolic.findings)
        plan = choose_exploit_plan(finding, inventory) if finding else None

        validation: Optional[PayloadValidation] = None
        if symbolic.payload:
            payload_dir = Path(out_dir) / "payloads"
            payload_dir.mkdir(parents=True, exist_ok=True)
            payload_path = payload_dir / f"{binary_path.name}.payload"
            payload_path.write_bytes(symbolic.payload)
            if not skip_validate:
                validation = validate_payload(binary_path, symbolic.payload)

        elapsed = time.perf_counter() - started
        success = bool(finding and finding.exploitable)
        if symbolic.payload and validation and validation.status == "OK":
            status = "OK"
        elif success:
            status = "EXPLOITABLE"
        elif symbolic.timed_out:
            status = "T/O"
        else:
            status = "FAIL"
        display = f"{elapsed:.3f}s" if status in {"OK", "EXPLOITABLE"} else status
        return VeaRunResult(
            status=status,
            display=display,
            elapsed_seconds=elapsed,
            static_slices=len(static_report.suspicious_slices),
            findings=symbolic.findings,
            plan=plan,
            payload_path=str(payload_path) if payload_path else None,
            payload_target=symbolic.payload_target,
            validation=validation,
            notes=notes,
        )
    except Exception as exc:
        elapsed = time.perf_counter() - started
        return VeaRunResult(
            status=f"ERR:{type(exc).__name__}",
            display=f"ERR:{type(exc).__name__}",
            elapsed_seconds=elapsed,
            static_slices=0,
            findings=[],
            plan=None,
            payload_path=None,
            payload_target=None,
            validation=None,
            notes=[str(exc)],
        )


def _baseline_display(baselines: Dict[str, BaselineRun], name: str) -> str:
    result = baselines.get(name)
    return result.display if result else "N/R"


def run_ubuntu_challenge(
    resource: ChallengeResource,
    *,
    data_dir: str | Path,
    out_dir: str | Path,
    repo_root: str | Path,
    baseline_config: str | Path | None,
    tool_root: str | Path,
    skip_baselines: bool,
    baseline_timeout: float,
    vea_timeout: float,
    max_steps: int,
    input_size: int,
    inventory_backend: str,
    skip_validate: bool,
) -> UbuntuChallengeResult:
    binary = Path(data_dir) / resource.name
    if not binary.exists():
        row = ExperimentRow(resource.name, "N/A", "N/A", "N/R", "N/R", "N/R", "N/A")
        return UbuntuChallengeResult(row=row, vea=None, baselines={})

    try:
        binary.chmod(binary.stat().st_mode | 0o111)
    except OSError:
        pass

    nx, pie = inspect_elf_nx_pie(binary)
    if skip_baselines:
        baselines = {
            name: BaselineRun(name, "N/R", "N/R", notes=["--skip-baselines"])
            for name in ("AEGAngr", "Zeratool", "BofAEG")
        }
    else:
        specs = load_baseline_specs(baseline_config, timeout_seconds=baseline_timeout)
        baselines = run_baselines(specs, binary=binary, repo_root=repo_root, tool_root=tool_root)

    vea = run_vea_aeg_full(
        binary,
        out_dir=out_dir,
        timeout_seconds=vea_timeout,
        max_steps=max_steps,
        input_size=input_size,
        inventory_backend=inventory_backend,
        skip_validate=skip_validate,
    )
    row = ExperimentRow(
        resource.name,
        nx,
        pie,
        _baseline_display(baselines, "AEGAngr"),
        _baseline_display(baselines, "Zeratool"),
        _baseline_display(baselines, "BofAEG"),
        vea.display,
    )
    return UbuntuChallengeResult(row=row, vea=vea, baselines=baselines)


def _write_details(result: UbuntuChallengeResult, details_dir: Path) -> None:
    details_dir.mkdir(parents=True, exist_ok=True)
    path = details_dir / f"{result.row.Challenge}.json"
    path.write_text(json.dumps(to_jsonable(result), indent=2, sort_keys=True), encoding="utf-8")


def write_ubuntu_outputs(
    results: List[UbuntuChallengeResult],
    *,
    out_dir: str | Path,
) -> UbuntuExperimentOutputs:
    target = Path(out_dir)
    target.mkdir(parents=True, exist_ok=True)
    details_dir = target / "ubuntu_full_details"
    for result in results:
        _write_details(result, details_dir)

    rows = [result.row for result in results]
    markdown_path = target / "ubuntu_full_experiment_table.md"
    csv_path = target / "ubuntu_full_experiment_table.csv"
    json_path = target / "ubuntu_full_experiment_results.json"

    markdown_path.write_text(markdown_table(rows), encoding="utf-8")
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["Challenge", "NX", "PIE", "AEGAngr", "Zeratool", "BofAEG", "VEA_AEG"],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))
    json_path.write_text(json.dumps(to_jsonable(results), indent=2, sort_keys=True), encoding="utf-8")
    return UbuntuExperimentOutputs(
        markdown=str(markdown_path),
        csv=str(csv_path),
        json=str(json_path),
        details_dir=str(details_dir),
    )


def run_ubuntu_experiment(
    resources: Iterable[ChallengeResource],
    *,
    data_dir: str | Path = DEFAULT_DATA_DIR,
    out_dir: str | Path = "reports",
    repo_root: str | Path = ".",
    baseline_config: str | Path | None = DEFAULT_BASELINE_CONFIG,
    tool_root: str | Path = DEFAULT_TOOL_ROOT,
    skip_baselines: bool = False,
    baseline_timeout: float = 900.0,
    vea_timeout: float = 120.0,
    max_steps: int = 2000,
    input_size: int = 256,
    inventory_backend: str = "auto",
    skip_validate: bool = False,
) -> Tuple[List[UbuntuChallengeResult], UbuntuExperimentOutputs]:
    results = [
        run_ubuntu_challenge(
            resource,
            data_dir=data_dir,
            out_dir=out_dir,
            repo_root=repo_root,
            baseline_config=baseline_config,
            tool_root=tool_root,
            skip_baselines=skip_baselines,
            baseline_timeout=baseline_timeout,
            vea_timeout=vea_timeout,
            max_steps=max_steps,
            input_size=input_size,
            inventory_backend=inventory_backend,
            skip_validate=skip_validate,
        )
        for resource in resources
    ]
    outputs = write_ubuntu_outputs(results, out_dir=out_dir)
    return results, outputs


def run_manifest_ubuntu_experiment(
    manifest: str | Path = DEFAULT_MANIFEST,
    *,
    data_dir: str | Path = DEFAULT_DATA_DIR,
    out_dir: str | Path = "reports",
    repo_root: str | Path = ".",
    baseline_config: str | Path | None = DEFAULT_BASELINE_CONFIG,
    tool_root: str | Path = DEFAULT_TOOL_ROOT,
    skip_baselines: bool = False,
    baseline_timeout: float = 900.0,
    vea_timeout: float = 120.0,
    max_steps: int = 2000,
    input_size: int = 256,
    inventory_backend: str = "auto",
    skip_validate: bool = False,
) -> Tuple[List[UbuntuChallengeResult], UbuntuExperimentOutputs]:
    return run_ubuntu_experiment(
        load_manifest(manifest),
        data_dir=data_dir,
        out_dir=out_dir,
        repo_root=repo_root,
        baseline_config=baseline_config,
        tool_root=tool_root,
        skip_baselines=skip_baselines,
        baseline_timeout=baseline_timeout,
        vea_timeout=vea_timeout,
        max_steps=max_steps,
        input_size=input_size,
        inventory_backend=inventory_backend,
        skip_validate=skip_validate,
    )
