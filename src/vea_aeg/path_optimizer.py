from __future__ import annotations

from dataclasses import dataclass
from time import monotonic
from typing import Iterable, Set


@dataclass
class PathOptimizerConfig:
    suspicious_addresses: Set[int]
    max_active: int = 1
    timeout_seconds: float = 120.0
    keep_unknown_addresses: bool = True


def state_address(state) -> int | None:
    addr = getattr(state, "addr", None)
    if addr is None:
        return None
    try:
        return int(addr)
    except TypeError:
        return None


def should_keep_state(state, suspicious_addresses: Iterable[int], *, keep_unknown: bool = True) -> bool:
    addr = state_address(state)
    if addr is None:
        return keep_unknown
    return addr in set(suspicious_addresses)


def rebalance_stashes(simgr, *, max_active: int = 1):
    """Move surplus active states into angr's deferred stash.

    This mirrors the paper's delayed-exploration idea without hiding discarded
    states. Deferred states can later be reactivated when active is exhausted.
    """

    active = list(getattr(simgr, "active", []))
    if len(active) <= max_active:
        return simgr
    simgr.stashes.setdefault("deferred", [])
    simgr.stashes["active"] = active[:max_active]
    simgr.stashes["deferred"].extend(active[max_active:])
    return simgr


def reactivate_deferred_if_needed(simgr):
    if getattr(simgr, "active", []):
        return simgr
    deferred = simgr.stashes.get("deferred", [])
    if deferred:
        simgr.stashes["active"] = [deferred.pop()]
    return simgr


def explore_with_suspicious_slice(simgr, config: PathOptimizerConfig):
    start = monotonic()
    while getattr(simgr, "active", []) and monotonic() - start < config.timeout_seconds:
        simgr.step()
        kept = []
        for state in getattr(simgr, "active", []):
            if should_keep_state(
                state,
                config.suspicious_addresses,
                keep_unknown=config.keep_unknown_addresses,
            ):
                kept.append(state)
            else:
                simgr.stashes.setdefault("pruned", []).append(state)
        simgr.stashes["active"] = kept
        rebalance_stashes(simgr, max_active=config.max_active)
        reactivate_deferred_if_needed(simgr)
    return simgr

