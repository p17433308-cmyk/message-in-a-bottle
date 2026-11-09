"""Minimal Protocol Buffers wire-format reader (zero dependencies).

Enough to pull fields out of Chromium's ServiceWorkerRegistrationData records
without a .proto or the protobuf runtime. Returns a {field_number: [values]}
map where values are ints (varint/fixed) or bytes (length-delimited).
"""
from __future__ import annotations


def _varint(buf: bytes, i: int) -> tuple[int, int]:
    shift = 0
    result = 0
    while i < len(buf):
        b = buf[i]
        result |= (b & 0x7F) << shift
        i += 1
        if not (b & 0x80):
            return result, i
        shift += 7
    raise ValueError("truncated varint")


def parse(buf: bytes) -> dict[int, list]:
    """Parse one protobuf message into {field: [values]}."""
    out: dict[int, list] = {}
    i = 0
    n = len(buf)
    while i < n:
        try:
            tag, i = _varint(buf, i)
        except ValueError:
            break
        field = tag >> 3
        wire = tag & 0x7
        if wire == 0:               # varint
            try:
                val, i = _varint(buf, i)
            except ValueError:
                break
        elif wire == 2:             # length-delimited
            try:
                ln, i = _varint(buf, i)
            except ValueError:
                break
            if i + ln > n:
                break
            val = buf[i:i + ln]
            i += ln
        elif wire == 5:             # 32-bit
            if i + 4 > n:
                break
            val = int.from_bytes(buf[i:i + 4], "little")
            i += 4
        elif wire == 1:             # 64-bit
            if i + 8 > n:
                break
            val = int.from_bytes(buf[i:i + 8], "little")
            i += 8
        else:
            break
        out.setdefault(field, []).append(val)
    return out


def as_str(v) -> str:
    if isinstance(v, bytes):
        return v.decode("utf-8", "replace")
    return str(v)
