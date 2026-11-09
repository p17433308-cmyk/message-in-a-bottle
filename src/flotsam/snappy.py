"""Pure-Python Snappy (raw block) decompressor — zero dependencies.

LevelDB compresses SSTable blocks with raw Snappy (no stream framing). This lets
FLOTSAM read COMPACTED LevelDBs (long-lived real profiles), not just the
write-ahead log. Format: a varint uncompressed length, then a sequence of
literal and copy elements. Reference: the Snappy format description.
"""
from __future__ import annotations


class SnappyError(Exception):
    pass


def _varint(data: bytes, i: int) -> tuple[int, int]:
    shift = result = 0
    while i < len(data):
        b = data[i]; i += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, i
        shift += 7
    raise SnappyError("truncated length varint")


def decompress(data: bytes) -> bytes:
    exp_len, i = _varint(data, 0)
    out = bytearray()
    n = len(data)
    while i < n:
        tag = data[i]; i += 1
        kind = tag & 0x03
        if kind == 0:                        # literal
            length = (tag >> 2) + 1
            if length > 60:
                extra = length - 60
                if i + extra > n:
                    raise SnappyError("truncated literal length")
                length = int.from_bytes(data[i:i + extra], "little") + 1
                i += extra
            if i + length > n:
                raise SnappyError("truncated literal")
            out += data[i:i + length]
            i += length
        else:
            if kind == 1:                    # copy, 1-byte offset
                length = ((tag >> 2) & 0x07) + 4
                if i >= n:
                    raise SnappyError("truncated copy1")
                offset = ((tag >> 5) << 8) | data[i]
                i += 1
            elif kind == 2:                  # copy, 2-byte offset
                length = (tag >> 2) + 1
                if i + 2 > n:
                    raise SnappyError("truncated copy2")
                offset = int.from_bytes(data[i:i + 2], "little")
                i += 2
            else:                            # kind == 3, copy, 4-byte offset
                length = (tag >> 2) + 1
                if i + 4 > n:
                    raise SnappyError("truncated copy4")
                offset = int.from_bytes(data[i:i + 4], "little")
                i += 4
            if offset == 0 or offset > len(out):
                raise SnappyError("bad copy offset")
            start = len(out) - offset
            for j in range(length):          # byte-wise (overlap is valid)
                out.append(out[start + j])
    if len(out) != exp_len:
        raise SnappyError(f"length mismatch: got {len(out)} want {exp_len}")
    return bytes(out)


def try_decompress(data: bytes):
    try:
        return decompress(data)
    except Exception:  # noqa: BLE001
        return None
