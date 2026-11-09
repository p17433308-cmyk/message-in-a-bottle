"""A small, zero-dependency LevelDB reader.

Enough of the format to recover the LIVE key/value set from a Chromium LevelDB
(the Service Worker / IndexedDB stores): it reads the write-ahead `.log` files
and the `.ldb` SSTables, orders every record by sequence number, and applies
deletions (tombstones) so unregistered / stale records do not leak into results.

Scope: uncompressed SSTable blocks are parsed; Snappy-compressed blocks are
skipped (the optional `snappy` module would be needed) — but the WAL `.log`,
which holds everything until a compaction, is uncompressed and fully parsed, so
live profiles read correctly. This is a big step up from scanning raw bytes.

References: LevelDB log_format.h, table/format.{h,cc}, block.cc.
"""
from __future__ import annotations

import os
import struct

_BLOCK = 32768
_TABLE_MAGIC = 0xdb4775248b80fb57


def _varint(buf: bytes, i: int) -> tuple[int, int]:
    shift = result = 0
    while i < len(buf):
        b = buf[i]; i += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, i
        shift += 7
    raise ValueError("truncated varint")


# ---- write-ahead log (.log) ------------------------------------------------

def _parse_batch(batch: bytes, ops: list) -> None:
    if len(batch) < 12:
        return
    seq = int.from_bytes(batch[0:8], "little")
    count = int.from_bytes(batch[8:12], "little")
    i = 12
    for c in range(count):
        if i >= len(batch):
            break
        rtype = batch[i]; i += 1
        try:
            klen, i = _varint(batch, i)
        except ValueError:
            break
        key = batch[i:i + klen]; i += klen
        if rtype == 1:            # value
            vlen, i = _varint(batch, i)
            val = batch[i:i + vlen]; i += vlen
            ops.append((seq + c, 1, key, val))
        elif rtype == 0:          # deletion (tombstone)
            ops.append((seq + c, 0, key, b""))
        else:
            break


def read_log(path: str) -> list:
    data = open(path, "rb").read()
    ops: list = []
    pos = 0
    frag = b""
    while pos + 7 <= len(data):
        if _BLOCK - (pos % _BLOCK) < 7:      # trailer padding -> next block
            pos += _BLOCK - (pos % _BLOCK)
            continue
        length = int.from_bytes(data[pos + 4:pos + 6], "little")
        rtype = data[pos + 6]
        pos += 7
        chunk = data[pos:pos + length]; pos += length
        if rtype == 1:            # FULL
            _parse_batch(chunk, ops); frag = b""
        elif rtype == 2:          # FIRST
            frag = chunk
        elif rtype in (3, 4):     # MIDDLE / LAST
            frag += chunk
            if rtype == 4:
                _parse_batch(frag, ops); frag = b""
        elif length == 0:
            pos += (_BLOCK - (pos % _BLOCK)) % _BLOCK
    return ops


# ---- SSTable (.ldb) --------------------------------------------------------

def _iter_block(block: bytes):
    if len(block) < 4:
        return
    num_restarts = struct.unpack_from("<I", block, len(block) - 4)[0]
    entries_end = len(block) - 4 * (num_restarts + 1)
    i = 0
    key = b""
    while i < entries_end:
        shared, i = _varint(block, i)
        nonshared, i = _varint(block, i)
        vlen, i = _varint(block, i)
        delta = block[i:i + nonshared]; i += nonshared
        key = key[:shared] + delta
        val = block[i:i + vlen]; i += vlen
        yield key, val


def _read_block(data: bytes, off: int, size: int):
    if off + size + 1 > len(data):
        return None
    comp = data[off + size]            # 1-byte compression type after block data
    if comp != 0:                      # 0 = none; others (snappy/zstd) unsupported
        return None
    return data[off:off + size]


def read_ldb(path: str) -> list:
    data = open(path, "rb").read()
    if len(data) < 48:
        return []
    if struct.unpack_from("<Q", data, len(data) - 8)[0] != _TABLE_MAGIC:
        return []
    footer = data[-48:]
    i = 0
    _mi_off, i = _varint(footer, i); _mi_size, i = _varint(footer, i)
    idx_off, i = _varint(footer, i); idx_size, i = _varint(footer, i)
    index_block = _read_block(data, idx_off, idx_size)
    if index_block is None:
        return []
    ops: list = []
    for ikey, handle in _iter_block(index_block):
        j = 0
        h_off, j = _varint(handle, j); h_size, j = _varint(handle, j)
        db = _read_block(data, h_off, h_size)
        if db is None:
            continue
        for internal_key, val in _iter_block(db):
            if len(internal_key) < 8:
                continue
            user_key = internal_key[:-8]
            trailer = int.from_bytes(internal_key[-8:], "little")
            seq = trailer >> 8
            ktype = trailer & 0xFF
            ops.append((seq, 1 if ktype == 1 else 0, user_key, val))
    return ops


# ---- merge -----------------------------------------------------------------

def live_pairs(db_dir: str) -> dict:
    """Return the live {user_key: value} map for a LevelDB directory."""
    if not os.path.isdir(db_dir):
        return {}
    ops: list = []
    for name in sorted(os.listdir(db_dir)):
        p = os.path.join(db_dir, name)
        try:
            if name.endswith(".log"):
                ops += read_log(p)
            elif name.endswith(".ldb") or name.endswith(".sst"):
                ops += read_ldb(p)
        except Exception:  # noqa: BLE001  (one bad table must not kill the read)
            continue
    latest: dict[bytes, tuple] = {}
    for seq, ktype, key, val in ops:
        cur = latest.get(key)
        if cur is None or seq >= cur[0]:
            latest[key] = (seq, ktype, val)
    return {k: v[2] for k, v in latest.items() if v[1] == 1}
