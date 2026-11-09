"""RFC 8785 (JSON Canonicalization Scheme) for Mandate.

Sorted by UTF-16 code units, ECMAScript number serialization, minimal string
escaping. Non-finite numbers, non-string keys, lone surrogates and integers
outside the IEEE-754 safe range are rejected.
"""
from __future__ import annotations

import math
from decimal import Decimal

MAX_SAFE_INTEGER = 2 ** 53 - 1


def _utf16_key(text: str) -> tuple[int, ...]:
    try:
        data = text.encode("utf-16-be")
    except UnicodeEncodeError as exc:
        raise ValueError("invalid UTF-16 key") from exc
    return tuple(int.from_bytes(data[i:i + 2], "big")
                 for i in range(0, len(data), 2))


def _escape(text: str) -> str:
    out = ['"']
    for ch in text:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\r":
            out.append("\\r")
        elif code < 0x20:
            out.append("\\u%04x" % code)
        elif 0xD800 <= code <= 0xDFFF:
            raise ValueError("lone surrogate")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _number(value) -> str:
    if isinstance(value, bool):
        raise TypeError("bool is not a number")
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise ValueError("integer exceeds IEEE-754 safe range")
        return str(value)
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("non-finite number")
    if number == 0:
        return "0"
    sign = "-" if number < 0 else ""
    decimal = Decimal(repr(abs(number)))
    digits = list(decimal.as_tuple().digits)
    exponent = decimal.as_tuple().exponent
    while len(digits) > 1 and digits[-1] == 0:
        digits.pop()
        exponent += 1
    count = len(digits)
    position = exponent + count
    text = "".join(str(d) for d in digits)
    if count <= position <= 21:
        rendered = text + "0" * (position - count)
    elif 0 < position <= 21:
        rendered = text[:position] + "." + text[position:]
    elif -6 < position <= 0:
        rendered = "0." + "0" * (-position) + text
    else:
        exp = position - 1
        mantissa = text[0] + ("." + text[1:] if count > 1 else "")
        rendered = mantissa + "e" + ("+" if exp >= 0 else "-") + str(abs(exp))
    return sign + rendered


def canonicalize(value) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _escape(value)
    if isinstance(value, (int, float)):
        return _number(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonicalize(item) for item in value) + "]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise TypeError("object keys must be strings")
        keys = sorted(value.keys(), key=_utf16_key)
        return "{" + ",".join(
            _escape(key) + ":" + canonicalize(value[key]) for key in keys) + "}"
    raise TypeError("unsupported type: %r" % type(value))
