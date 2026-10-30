"""Value-free JSON shape helpers shared by the shape report scripts."""

from __future__ import annotations

import json
import math
from typing import Any


def shape(value: Any) -> dict[str, Any]:
    """Describe a JSON value without including any of its contents."""
    if value is None:
        return {"type": "null"}
    if isinstance(value, bool):
        return {"type": "boolean"}
    if isinstance(value, int):
        return {"type": "integer"}
    if isinstance(value, float):
        return {"type": "number", "finite": math.isfinite(value)}
    if isinstance(value, str):
        return {"type": "string"}
    if isinstance(value, list):
        shapes: dict[str, dict[str, Any]] = {}
        for item in value:
            descriptor = shape(item)
            shapes[json.dumps(descriptor, sort_keys=True)] = descriptor
        return {
            "type": "array",
            "length": len(value),
            "items": list(shapes.values()),
        }
    if isinstance(value, dict):
        return {
            "type": "object",
            "keys": {key: shape(child) for key, child in value.items()},
        }
    return {"type": type(value).__name__}
