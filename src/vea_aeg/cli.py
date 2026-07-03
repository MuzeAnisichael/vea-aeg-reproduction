from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from .dangerous_functions import (
    DEFAULT_DANGEROUS_FUNCTIONS,
    load_dangerous_functions,
    parse_dangerous_functions,
)
from .dataset import DEFAULT_DATA_DIR, DEFAULT_MANIFEST, download_manifest, load_manifest
from .errors import ReproductionDependencyError
from .experiment import markdown_table, run_manifest_experiment
from .exploit_builder import choose_exploit_plan, inventory_binary
from .report import dumps_json
from .smoke import run_smoke_flow
from .static_analysis import analyze_static
from .ubuntu_experiment import run_manifest_ubuntu_experiment


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vea-aeg")
    subparsers = parser.add_subparsers(dest="command", required=True)

    dangerous = subparsers.add_parser("dangerous", help="print default dangerous functions")
    dangerous.add_argument("--json", action="store_true")

    inventory = subparsers.add_parser("inventory", help="collect binary inventory")
    inventory.add_argument("binary", type=Path)
    inventory.add_argument(
        "--backend",
        choices=("auto", "radare2", "basic"),
        default="auto",
        help="auto falls back to a pure-Python basic backend when radare2 is unavailable",
    )
    inventory.add_argument("--json", action="store_true")

    analyze = subparsers.add_parser("analyze", help="run static VEA-AEG analysis scaffold")
    analyze.add_argument("binary", type=Path)
    analyze.add_argument("--dangerous", help="comma-separated dangerous function names")
    analyze.add_argument("--dangerous-file", type=Path, help="newline-separated dangerous names")
    analyze.add_argument("--cfg-kind", choices=("emulated", "fast"), default="emulated")
    analyze.add_argument("--slice-depth", type=int, default=64)
    analyze.add_argument("--json", action="store_true")

    plan = subparsers.add_parser("plan", help="choose an exploit strategy from a finding type")
    plan.add_argument("finding_type", help="example: IP_OVERWRITE, WRITE_WHAT_WHERE")
    plan.add_argument("--binary", type=Path, help="optional binary for resource inventory")
    plan.add_argument("--json", action="store_true")

    smoke = subparsers.add_parser(
        "smoke",
        help="run a Windows-friendly flow test without angr, radare2, or Linux ELF execution",
    )
    smoke.add_argument("--json", action="store_true")

    download_data = subparsers.add_parser("download-data", help="download public CTF resources")
    download_data.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    download_data.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    download_data.add_argument("--force", action="store_true")
    download_data.add_argument("--json", action="store_true")

    experiment = subparsers.add_parser(
        "experiment",
        help="generate a paper-format result table using the Windows basic backend",
    )
    experiment.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    experiment.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    experiment.add_argument("--out-dir", type=Path, default=Path("reports"))
    experiment.add_argument("--json", action="store_true")

    ubuntu_experiment = subparsers.add_parser(
        "ubuntu-experiment",
        help="run the Ubuntu paper-flow reproduction with VEA-AEG and baseline tool timings",
    )
    ubuntu_experiment.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    ubuntu_experiment.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    ubuntu_experiment.add_argument("--out-dir", type=Path, default=Path("reports"))
    ubuntu_experiment.add_argument("--repo-root", type=Path, default=Path("."))
    ubuntu_experiment.add_argument(
        "--baseline-config",
        type=Path,
        default=Path("configs/baselines.ubuntu.json"),
    )
    ubuntu_experiment.add_argument("--tool-root", type=Path, default=Path("third_party"))
    ubuntu_experiment.add_argument("--skip-baselines", action="store_true")
    ubuntu_experiment.add_argument("--skip-validate", action="store_true")
    ubuntu_experiment.add_argument("--baseline-timeout", type=float, default=900.0)
    ubuntu_experiment.add_argument("--vea-timeout", type=float, default=120.0)
    ubuntu_experiment.add_argument("--max-steps", type=int, default=2000)
    ubuntu_experiment.add_argument("--input-size", type=int, default=256)
    ubuntu_experiment.add_argument("--json", action="store_true")

    return parser


def _print_or_json(value, as_json: bool) -> None:
    if as_json:
        print(dumps_json(value))
    elif isinstance(value, (list, tuple)):
        for item in value:
            print(item)
    else:
        print(value)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "dangerous":
            _print_or_json(DEFAULT_DANGEROUS_FUNCTIONS, args.json)
            return 0

        if args.command == "inventory":
            report = inventory_binary(args.binary, backend=args.backend)
            _print_or_json(report if args.json else dumps_json(report), args.json)
            return 0

        if args.command == "analyze":
            dangerous_functions = load_dangerous_functions(args.dangerous_file)
            if args.dangerous:
                dangerous_functions = parse_dangerous_functions(args.dangerous)
            report = analyze_static(
                args.binary,
                dangerous_functions=dangerous_functions,
                cfg_kind=args.cfg_kind,
                slice_depth=args.slice_depth,
            )
            _print_or_json(report if args.json else dumps_json(report), args.json)
            return 0

        if args.command == "plan":
            from .exploitability import ExploitabilityFinding

            inventory = inventory_binary(args.binary) if args.binary else None
            finding = ExploitabilityFinding(
                rule="manual",
                vulnerability_type=args.finding_type,
                exploitable=args.finding_type not in {"ARBITRARY_READ", "WRITE_X_WHERE"},
                evidence="provided from CLI",
            )
            result = choose_exploit_plan(finding, inventory)
            _print_or_json(result if args.json else dumps_json(result), args.json)
            return 0

        if args.command == "smoke":
            result = run_smoke_flow()
            _print_or_json(result if args.json else dumps_json(result), args.json)
            return 0

        if args.command == "download-data":
            result = download_manifest(
                load_manifest(args.manifest),
                args.data_dir,
                force=args.force,
            )
            _print_or_json(result if args.json else dumps_json(result), args.json)
            return 0

        if args.command == "experiment":
            rows, outputs = run_manifest_experiment(args.manifest, args.data_dir, args.out_dir)
            if args.json:
                _print_or_json({"rows": rows, "outputs": outputs}, True)
            else:
                print(markdown_table(rows))
                print(f"wrote: {outputs['markdown']}")
                print(f"wrote: {outputs['csv']}")
            return 0

        if args.command == "ubuntu-experiment":
            results, outputs = run_manifest_ubuntu_experiment(
                args.manifest,
                data_dir=args.data_dir,
                out_dir=args.out_dir,
                repo_root=args.repo_root,
                baseline_config=args.baseline_config,
                tool_root=args.tool_root,
                skip_baselines=args.skip_baselines,
                baseline_timeout=args.baseline_timeout,
                vea_timeout=args.vea_timeout,
                max_steps=args.max_steps,
                input_size=args.input_size,
                skip_validate=args.skip_validate,
            )
            rows = [result.row for result in results]
            if args.json:
                _print_or_json({"results": results, "outputs": outputs}, True)
            else:
                print(markdown_table(rows))
                print(f"wrote: {outputs.markdown}")
                print(f"wrote: {outputs.csv}")
                print(f"wrote: {outputs.json}")
                print(f"wrote: {outputs.details_dir}")
            return 0
    except ReproductionDependencyError as exc:
        parser.exit(2, f"dependency error: {exc}\n")

    parser.error(f"unknown command: {args.command}")
    return 2
