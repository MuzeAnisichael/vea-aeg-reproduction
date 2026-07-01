from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from .dangerous_functions import (
    DEFAULT_DANGEROUS_FUNCTIONS,
    load_dangerous_functions,
    parse_dangerous_functions,
)
from .errors import ReproductionDependencyError
from .exploit_builder import choose_exploit_plan, inventory_binary
from .report import dumps_json
from .smoke import run_smoke_flow
from .static_analysis import analyze_static


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vea-aeg")
    subparsers = parser.add_subparsers(dest="command", required=True)

    dangerous = subparsers.add_parser("dangerous", help="print default dangerous functions")
    dangerous.add_argument("--json", action="store_true")

    inventory = subparsers.add_parser("inventory", help="collect radare2 binary inventory")
    inventory.add_argument("binary", type=Path)
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
            report = inventory_binary(args.binary)
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
    except ReproductionDependencyError as exc:
        parser.exit(2, f"dependency error: {exc}\n")

    parser.error(f"unknown command: {args.command}")
    return 2
