"""Canonical JSON implementation following RFC 8785 (JSON Canonicalization Scheme - JCS).

RFC 8785 guarantees a unique, deterministic byte representation of JSON data,
which is critical for generating stable Merkle tree leaf hashes, digital
signatures, and AEAD Associated Authenticated Data (AAD).

Numeric values are formatted according to ECMAScript 6 (ES6) Section 7.1.12.1
"ToString Applied to the Number Type" as mandated by RFC 8785 Section 3.2.2.3:
- Negative zero (-0.0) is serialized as 0
- Floats with integral value (e.g. 100.0) serialize without decimal point or trailing zero ("100")
- Numbers whose exponent in scientific notation is in [-6, 20] are serialized in fixed-point notation
- Exponential notation uses lowercase 'e' and no leading zeros in the exponent (e.g. 1e-7, 1e+21)
- Object keys are sorted lexicographically by UTF-16 code units
- Whitespace between separators is eliminated
"""

from __future__ import annotations

import hashlib
import json
import math
from datetime import date, datetime
from typing import Any


def format_es6_number(val: float | int) -> str:
    """Format a number according to RFC 8785 Section 3.2.2.3 / ES6 Number.toString().

    Rules:
    - Zero (including -0.0) is serialized as "0".
    - NaN and Infinity raise ValueError.
    - Integers are represented in standard base-10 with no leading zeros.
    - Floats are formatted according to the ES6 7.1.12.1 ToString algorithm:
      - Integers represented as floats (e.g. 100.0) serialize as "100" without decimal point.
      - Numbers in range [1e-6, 1e21) use fixed-point notation with minimal digits.
      - Exponential notation uses lowercase 'e', with '+' or '-' sign and no leading zeros in exponent.

    Args:
        val: Numeric value (float or int).

    Returns:
        Formatted string representation.

    Raises:
        ValueError: If val is NaN or Infinite.
    """
    fvalue = float(val)

    if math.isnan(fvalue) or math.isinf(fvalue):
        raise ValueError(f"Out of range float values are not JSON compliant: {val}")

    # Zero is a special case: -0.0 and +0.0 both serialize to "0"
    if fvalue == 0:
        return "0"

    # Start from Python's shortest round-tripping float representation
    py_double = str(fvalue)
    if "n" in py_double:
        raise ValueError(f"Invalid JSON number: {py_double}")

    # Preserve negative sign
    py_sign = ""
    if py_double.startswith("-"):
        py_sign = "-"
        py_double = py_double[1:]

    # Parse exponent if present
    py_exp_str = ""
    py_exp_val = 0
    q = py_double.find("e")
    if q > 0:
        py_exp_str = py_double[q:]
        # Suppress leading zeros on exponents (e.g., e-07 -> e-7)
        if len(py_exp_str) > 2 and py_exp_str[2] == "0":
            py_exp_str = py_exp_str[:2] + py_exp_str[3:]
        py_double = py_double[:q]
        py_exp_val = int(py_exp_str[1:])

    # Split into integer part and decimal part
    py_first = py_double
    py_dot = ""
    py_last = ""
    q = py_double.find(".")
    if q > 0:
        py_dot = "."
        py_first = py_double[:q]
        py_last = py_double[q + 1 :]

    # Remove trailing .0 from Python float representation
    if py_last == "0":
        py_dot = ""
        py_last = ""

    # Check ES6 fixed-point thresholds
    if 0 < py_exp_val < 21:
        # Integers / fixed-point shown as-is up to 21 digits
        py_first += py_last
        py_last = ""
        py_dot = ""
        py_exp_str = ""
        q = py_exp_val - len(py_first)
        while q >= 0:
            q -= 1
            py_first += "0"
    elif -7 < py_exp_val < 0:
        # Small numbers shown as 0.xxx down to 1e-6
        py_last = py_first + py_last
        py_first = "0"
        py_dot = "."
        py_exp_str = ""
        q = py_exp_val
        while q < -1:
            q += 1
            py_last = "0" + py_last

    return py_sign + py_first + py_dot + py_last + py_exp_str


def _json_default(obj: Any) -> Any:
    """Format non-standard JSON types into deterministic representations."""
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, bytes):
        return obj.hex()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def _serialize(obj: Any, seen: set[int] | None = None) -> str:
    """Recursively serialize Python data into canonical JSON per RFC 8785."""
    if seen is None:
        seen = set()

    if obj is None:
        return "null"
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, int):
        return str(obj)
    if isinstance(obj, float):
        return format_es6_number(obj)
    if isinstance(obj, str):
        return json.dumps(obj, ensure_ascii=False)
    if isinstance(obj, (list, tuple)):
        obj_id = id(obj)
        if obj_id in seen:
            raise ValueError("Circular reference detected")
        seen.add(obj_id)
        try:
            return "[" + ",".join(_serialize(item, seen) for item in obj) + "]"
        finally:
            seen.remove(obj_id)
    if isinstance(obj, dict):
        obj_id = id(obj)
        if obj_id in seen:
            raise ValueError("Circular reference detected")
        seen.add(obj_id)
        try:
            # RFC 8785 Section 3.2.3: Dictionary keys sorted by UTF-16 code units
            sorted_keys = sorted(obj.keys(), key=lambda k: k.encode("utf-16-be"))
            items = []
            for k in sorted_keys:
                if not isinstance(k, str):
                    raise TypeError(f"Keys must be strings, got {type(k).__name__}")
                key_str = json.dumps(k, ensure_ascii=False)
                val_str = _serialize(obj[k], seen)
                items.append(f"{key_str}:{val_str}")
            return "{" + ",".join(items) + "}"
        finally:
            seen.remove(obj_id)

    # Process custom types through default handler
    return _serialize(_json_default(obj), seen)


class CanonicalJSONEncoder(json.JSONEncoder):
    """Custom JSONEncoder subclass that implements RFC 8785 canonical serialization."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=_json_default,
            *args,  # noqa: B026  (kept for JSONEncoder signature compatibility)
            **kwargs,
        )

    def encode(self, o: Any) -> str:
        return _serialize(o)


def canonical_json(data: Any) -> bytes:
    """Serialize Python data into canonical JSON bytes according to RFC 8785.

    Rules applied:
    - UTF-8 encoding without Byte Order Mark (BOM)
    - Deterministic key ordering (lexicographical by UTF-16 code units)
    - Minimal whitespace (no whitespace between separators: ',' and ':')
    - ES6 Number.toString() float formatting
    - Standard JSON escaping

    Args:
        data: Python object to serialize (dict, list, str, int, float, bool, None).

    Returns:
        Canonical JSON byte string.

    Raises:
        TypeError: If an object inside `data` cannot be serialized.
        ValueError: If circular references or NaN/Infinite floats are present.
    """
    return _serialize(data).encode("utf-8")


canonical_json_encode = canonical_json


def canonical_json_hash(data: Any) -> str:
    """Compute the SHA-256 hex digest of the canonical JSON representation of data.

    Args:
        data: Python object to serialize and hash.

    Returns:
        Hex-encoded SHA-256 digest string.
    """
    return hashlib.sha256(canonical_json(data)).hexdigest()


def canonical_hash(data: Any) -> bytes:
    """Compute the SHA-256 raw bytes digest of the canonical JSON representation of data.

    Args:
        data: Python object to serialize and hash.

    Returns:
        Raw bytes SHA-256 digest (32 bytes).
    """
    return hashlib.sha256(canonical_json(data)).digest()
