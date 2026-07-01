from __future__ import annotations

from pathlib import Path
from typing import Iterable, Tuple

DEFAULT_DANGEROUS_FUNCTIONS: Tuple[str, ...] = (
    "gets",
    "fgets",
    "scanf",
    "__isoc99_scanf",
    "strcpy",
    "strncpy",
    "strcat",
    "sprintf",
    "vsprintf",
    "read",
    "recv",
    "memcpy",
    "memmove",
)


def normalize_function_names(names: Iterable[str]) -> Tuple[str, ...]:
    cleaned = []
    seen = set()
    for name in names:
        item = name.strip()
        if not item or item.startswith("#"):
            continue
        if item not in seen:
            cleaned.append(item)
            seen.add(item)
    return tuple(cleaned)


def parse_dangerous_functions(raw: str | None) -> Tuple[str, ...]:
    if raw is None or not raw.strip():
        return DEFAULT_DANGEROUS_FUNCTIONS
    return normalize_function_names(raw.replace(";", ",").split(","))


def load_dangerous_functions(path: str | Path | None) -> Tuple[str, ...]:
    if path is None:
        return DEFAULT_DANGEROUS_FUNCTIONS
    text = Path(path).read_text(encoding="utf-8")
    return normalize_function_names(text.splitlines())

