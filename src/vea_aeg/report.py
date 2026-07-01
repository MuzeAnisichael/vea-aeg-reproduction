from __future__ import annotations

from dataclasses import asdict, is_dataclass
import json
from typing import Any


def to_jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return to_jsonable(asdict(value))
    if isinstance(value, set):
        return sorted(value)
    if isinstance(value, dict):
        return {key: to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_jsonable(item) for item in value]
    return value


def dumps_json(value: Any) -> str:
    return json.dumps(to_jsonable(value), indent=2, sort_keys=True)

