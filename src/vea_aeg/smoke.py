from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace
from typing import List

from .dangerous_functions import DEFAULT_DANGEROUS_FUNCTIONS
from .exploit_builder import choose_exploit_plan
from .exploitability import classify_memory_action, classify_register_control


class MockSymbolicValue:
    def __init__(self, symbolic: bool):
        self.symbolic = symbolic


@dataclass
class SmokeReport:
    goal: str
    os_mode: str
    dangerous_functions_count: int
    simulated_findings: List[object]
    exploit_plans: List[object]
    next_real_steps: List[str]


def build_mock_state(*, symbolic_ip: bool = True, symbolic_bp: bool = False):
    return SimpleNamespace(
        regs=SimpleNamespace(
            eip=MockSymbolicValue(symbolic_ip),
            ebp=MockSymbolicValue(symbolic_bp),
        )
    )


def build_mock_memory_write(*, symbolic_data: bool = True):
    return SimpleNamespace(
        type="mem",
        action="write",
        data=MockSymbolicValue(symbolic_data),
        address=MockSymbolicValue(False),
    )


def run_smoke_flow() -> SmokeReport:
    """Run the reproduction pipeline without binary-analysis dependencies.

    This is a Windows-friendly smoke test. It exercises the same internal
    decision path as the real flow but uses mock symbolic states instead of
    executing Linux ELF binaries.
    """

    state = build_mock_state(symbolic_ip=True)
    write_action = build_mock_memory_write(symbolic_data=True)
    findings = classify_register_control(state) + classify_memory_action(write_action)
    plans = [choose_exploit_plan(finding) for finding in findings]
    return SmokeReport(
        goal="exercise VEA-AEG pipeline without strict paper-result reproduction",
        os_mode="windows-native-safe-smoke",
        dangerous_functions_count=len(DEFAULT_DANGEROUS_FUNCTIONS),
        simulated_findings=findings,
        exploit_plans=plans,
        next_real_steps=[
            "install optional binary-analysis packages",
            "compile or collect an authorized local toy binary",
            "replace mock state with angr state exploration",
            "replace strategy planning with verified local exploit generation",
        ],
    )

