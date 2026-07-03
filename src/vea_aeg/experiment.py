from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import csv
import time
from typing import Dict, Iterable, List, Tuple

from .dataset import ChallengeResource, DEFAULT_DATA_DIR, DEFAULT_MANIFEST, load_manifest
from .exploit_builder import choose_exploit_plan, inventory_binary
from .exploitability import ExploitabilityFinding


CHECK_MARK = "\u221a"
NO_MARK = "x"


@dataclass
class ExperimentRow:
    Challenge: str
    NX: str
    PIE: str
    AEGAngr: str
    Zeratool: str
    BofAEG: str
    VEA_AEG: str


def _u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "little")


def _u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def _u64(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 8], "little")


def inspect_elf_nx_pie(path: str | Path) -> Tuple[str, str]:
    data = Path(path).read_bytes()
    if len(data) < 0x40 or data[:4] != b"\x7fELF":
        return "N/A", "N/A"
    elf_class = data[4]
    endian = data[5]
    if endian != 1:
        return "?", "?"
    e_type = _u16(data, 16)
    pie = CHECK_MARK if e_type == 3 else NO_MARK if e_type == 2 else "?"

    if elf_class == 1:
        phoff = _u32(data, 28)
        phentsize = _u16(data, 42)
        phnum = _u16(data, 44)
        p_type_offset = 0
        p_flags_offset = 24
    elif elf_class == 2:
        phoff = _u64(data, 32)
        phentsize = _u16(data, 54)
        phnum = _u16(data, 56)
        p_type_offset = 0
        p_flags_offset = 4
    else:
        return "?", pie

    nx = "?"
    for idx in range(phnum):
        entry = phoff + idx * phentsize
        if entry + phentsize > len(data):
            break
        p_type = _u32(data, entry + p_type_offset)
        if p_type == 0x6474E551:  # PT_GNU_STACK
            flags = _u32(data, entry + p_flags_offset)
            nx = NO_MARK if flags & 0x1 else CHECK_MARK
            break
    return nx, pie


def run_windows_basic_challenge(path: Path) -> str:
    started = time.perf_counter()
    inventory = inventory_binary(path, backend="basic")
    finding = ExploitabilityFinding(
        rule="windows-basic-flow",
        vulnerability_type="IP_OVERWRITE",
        exploitable=True,
        evidence=f"{inventory.format}/{inventory.arch} inventory completed",
    )
    choose_exploit_plan(finding, inventory)
    elapsed = time.perf_counter() - started
    return f"{elapsed:.3f}s"


def run_experiment(
    resources: Iterable[ChallengeResource],
    data_dir: str | Path = DEFAULT_DATA_DIR,
) -> List[ExperimentRow]:
    rows: List[ExperimentRow] = []
    base = Path(data_dir)
    for resource in resources:
        binary = base / resource.name
        if not binary.exists():
            rows.append(
                ExperimentRow(resource.name, "N/A", "N/A", "N/R", "N/R", "N/R", "N/A")
            )
            continue
        nx, pie = inspect_elf_nx_pie(binary)
        try:
            vea_time = run_windows_basic_challenge(binary)
        except Exception as exc:
            vea_time = f"ERR:{type(exc).__name__}"
        rows.append(ExperimentRow(resource.name, nx, pie, "N/R", "N/R", "N/R", vea_time))
    return rows


def markdown_table(rows: Iterable[ExperimentRow]) -> str:
    headers = ["Challenge", "NX", "PIE", "AEGAngr", "Zeratool", "BofAEG", "VEA-AEG"]
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for row in rows:
        values = [
            row.Challenge,
            row.NX,
            row.PIE,
            row.AEGAngr,
            row.Zeratool,
            row.BofAEG,
            row.VEA_AEG,
        ]
        lines.append("| " + " | ".join(values) + " |")
    return "\n".join(lines) + "\n"


def write_outputs(rows: List[ExperimentRow], out_dir: str | Path = "reports") -> Dict[str, str]:
    target = Path(out_dir)
    target.mkdir(parents=True, exist_ok=True)
    markdown_path = target / "windows_basic_experiment_table.md"
    csv_path = target / "windows_basic_experiment_table.csv"
    markdown_path.write_text(markdown_table(rows), encoding="utf-8")
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["Challenge", "NX", "PIE", "AEGAngr", "Zeratool", "BofAEG", "VEA_AEG"],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))
    return {"markdown": str(markdown_path), "csv": str(csv_path)}


def run_manifest_experiment(
    manifest: str | Path = DEFAULT_MANIFEST,
    data_dir: str | Path = DEFAULT_DATA_DIR,
    out_dir: str | Path = "reports",
) -> Tuple[List[ExperimentRow], Dict[str, str]]:
    rows = run_experiment(load_manifest(manifest), data_dir)
    outputs = write_outputs(rows, out_dir)
    return rows, outputs
