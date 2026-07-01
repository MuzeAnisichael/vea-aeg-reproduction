from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set

from .dangerous_functions import DEFAULT_DANGEROUS_FUNCTIONS
from .errors import ReproductionDependencyError


@dataclass(frozen=True)
class DangerousCallSite:
    function: str
    plt_address: int
    callsite_address: int


@dataclass
class SuspiciousSlice:
    callsite: DangerousCallSite
    addresses: Set[int] = field(default_factory=set)
    notes: List[str] = field(default_factory=list)


@dataclass
class StaticAnalysisReport:
    binary: str
    arch: str
    entry: int
    plt_entries: Dict[str, int]
    dangerous_callsites: List[DangerousCallSite]
    suspicious_slices: List[SuspiciousSlice]


def _require_angr():
    try:
        import angr  # type: ignore
    except ImportError as exc:
        raise ReproductionDependencyError(
            "angr is required for static analysis. Install with: "
            "python3 -m pip install -r requirements.txt"
        ) from exc
    return angr


def load_project(binary_path: str | Path, *, auto_load_libs: bool = False):
    angr = _require_angr()
    return angr.Project(str(binary_path), auto_load_libs=auto_load_libs)


def extract_plt_entries(project) -> Dict[str, int]:
    plt = getattr(project.loader.main_object, "plt", {}) or {}
    return {name: int(addr) for name, addr in plt.items()}


def build_cfg(project, *, cfg_kind: str = "emulated"):
    if cfg_kind == "fast":
        return project.analyses.CFGFast(normalize=True)
    if cfg_kind == "emulated":
        return project.analyses.CFGEmulated(keep_state=True, normalize=True)
    raise ValueError(f"unsupported cfg_kind: {cfg_kind}")


def find_dangerous_callsites(
    project,
    cfg,
    dangerous_functions: Sequence[str] = DEFAULT_DANGEROUS_FUNCTIONS,
) -> List[DangerousCallSite]:
    plt_entries = extract_plt_entries(project)
    callsites: List[DangerousCallSite] = []
    for function in dangerous_functions:
        plt_address = plt_entries.get(function)
        if plt_address is None:
            continue
        plt_node = cfg.model.get_any_node(plt_address)
        if plt_node is None:
            continue
        for predecessor in cfg.graph.predecessors(plt_node):
            addr = getattr(predecessor, "addr", None)
            if addr is not None:
                callsites.append(
                    DangerousCallSite(
                        function=function,
                        plt_address=int(plt_address),
                        callsite_address=int(addr),
                    )
                )
    return callsites


def approximate_backward_slice(cfg, callsite_address: int, *, max_depth: int = 64) -> Set[int]:
    """Approximate Algorithm 1 when full DDG/CDG slicing is too expensive.

    The paper uses CFG + CDG + DDG and angr BackwardSlice. This fallback walks
    CFG predecessors from the dangerous callsite and keeps a bounded address set
    that can guide symbolic execution. It is intentionally conservative.
    """

    start = cfg.model.get_any_node(callsite_address)
    if start is None:
        return set()

    visited = set()
    frontier = [(start, 0)]
    while frontier:
        node, depth = frontier.pop()
        addr = getattr(node, "addr", None)
        if addr is None or addr in visited:
            continue
        visited.add(int(addr))
        if depth >= max_depth:
            continue
        for predecessor in cfg.graph.predecessors(node):
            frontier.append((predecessor, depth + 1))
    return visited


def analyze_static(
    binary_path: str | Path,
    *,
    dangerous_functions: Optional[Iterable[str]] = None,
    cfg_kind: str = "emulated",
    slice_depth: int = 64,
) -> StaticAnalysisReport:
    binary = Path(binary_path)
    project = load_project(binary)
    cfg = build_cfg(project, cfg_kind=cfg_kind)
    functions = tuple(dangerous_functions or DEFAULT_DANGEROUS_FUNCTIONS)
    callsites = find_dangerous_callsites(project, cfg, functions)
    slices = [
        SuspiciousSlice(
            callsite=callsite,
            addresses=approximate_backward_slice(cfg, callsite.callsite_address, max_depth=slice_depth),
            notes=["bounded CFG-predecessor slice; replace with CDG/DDG BackwardSlice for parity"],
        )
        for callsite in callsites
    ]
    return StaticAnalysisReport(
        binary=str(binary),
        arch=project.arch.name,
        entry=int(project.entry),
        plt_entries=extract_plt_entries(project),
        dangerous_callsites=callsites,
        suspicious_slices=slices,
    )

