"""DAS-04-003 Python reference for canonical JSON used by cadence runtime.

This module is the test/CI-side reference. The canonical Go implementation
lives at ``cadence-core/internal/canonicaljson/``; both MUST produce the
same byte sequence for the same input so that hash chains match across
languages.

Rules:
    - object keys sorted lexicographically (UTF-8 codepoint order)
    - strings escaped with the JSON spec subset (no \\u for non-ASCII unless
      necessary)
    - integers serialised without trailing ``.0``
    - floats serialised with ``repr``-equivalent shortest round-trip form
    - no insignificant whitespace
"""

from __future__ import annotations

import json
import math
from typing import Any


def canonicalize(value: Any) -> bytes:
    return _encode(value).encode("utf-8")


def _encode(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise ValueError("NaN/Infinity not allowed in canonical JSON")
        # int-valued floats serialise without trailing .0 to match Go.
        if value.is_integer():
            return str(int(value))
        return repr(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_encode(v) for v in value) + "]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: kv[0])
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _encode(v) for k, v in items) + "}"
    raise TypeError(f"cannot canonicalize {type(value).__name__}")
