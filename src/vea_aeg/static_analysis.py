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


def exact_backward_slice(project, cfg, callsite_address: int) -> tuple[Set[int], str]:
    """Try the paper-style CDG/DDG BackwardSlice.

    angr's DDG and BackwardSlice APIs are version-sensitive, so this function
    keeps extraction defensive and reports a fallback reason to the caller.
    """

    target = cfg.model.get_any_node(callsite_address)
    if target is None:
        return set(), "no CFG node for target callsite"

    cdg = project.analyses.CDG(cfg)
    ddg = project.analyses.DDG(cfg)
    backward_slice = project.analyses.BackwardSlice(
        cfg,
        cdg=cdg,
        ddg=ddg,
        targets=[(target, -1)],
    )

    addresses: Set[int] = set()
    for attr_name in ("runs_in_slice", "chosen_statements"):
        value = getattr(backward_slice, attr_name, None)
        if not value:
            continue
        items = value.keys() if hasattr(value, "keys") else value
        for item in items:
            node = item[0] if isinstance(item, tuple) and item else item
            addr = getattr(node, "addr", None)
            if addr is not None:
                addresses.add(int(addr))

    if not addresses:
        return set(), "BackwardSlice produced no extractable addresses"
    return addresses, "CDG/DDG BackwardSlice"


def build_suspicious_slice(
    project,
    cfg,
    callsite_address: int,
    *,
    max_depth: int = 64,
    prefer_exact_slice: bool = False,
) -> SuspiciousSlice:
    if prefer_exact_slice:
        try:
            exact_addresses, exact_note = exact_backward_slice(project, cfg, callsite_address)
            if exact_addresses:
                callsite = DangerousCallSite("", 0, callsite_address)
                return SuspiciousSlice(callsite=callsite, addresses=exact_addresses, notes=[exact_note])
            fallback_note = exact_note
        except Exception as exc:
            fallback_note = f"CDG/DDG BackwardSlice unavailable: {type(exc).__name__}: {exc}"
    else:
        fallback_note = "bounded CFG-predecessor slice"

    callsite = DangerousCallSite("", 0, callsite_address)
    return SuspiciousSlice(
        callsite=callsite,
        addresses=approximate_backward_slice(cfg, callsite_address, max_depth=max_depth),
        notes=[fallback_note, "bounded CFG-predecessor fallback"],
    )


def analyze_static(
    binary_path: str | Path,
    *,
    dangerous_functions: Optional[Iterable[str]] = None,
    cfg_kind: str = "emulated",
    slice_depth: int = 64,
    prefer_exact_slice: bool = False,
) -> StaticAnalysisReport:
    binary = Path(binary_path)
    project = load_project(binary)
    cfg = build_cfg(project, cfg_kind=cfg_kind)
    functions = tuple(dangerous_functions or DEFAULT_DANGEROUS_FUNCTIONS)
    callsites = find_dangerous_callsites(project, cfg, functions)
    slices = []
    for callsite in callsites:
        suspicious_slice = build_suspicious_slice(
            project,
            cfg,
            callsite.callsite_address,
            max_depth=slice_depth,
            prefer_exact_slice=prefer_exact_slice,
        )
        suspicious_slice.callsite = callsite
        slices.append(suspicious_slice)
    return StaticAnalysisReport(
        binary=str(binary),
        arch=project.arch.name,
        entry=int(project.entry),
        plt_entries=extract_plt_entries(project),
        dangerous_callsites=callsites,
        suspicious_slices=slices,
    )
