"""IndexedDB abuse scanning — the sibling channel (ACM 2021).

IndexedDB is the other origin-scoped, persistent store an attacker can stash
code/config in, and it is also a LevelDB on disk
(`IndexedDB/<scheme>_<host>_<port>.indexeddb.leveldb`). We reuse the LevelDB
reader to pull live values and expose their text to the hunting rules, so the
same signatures that catch Cache-Storage payloads catch IndexedDB ones.

Object-store values use Blink's serialization; we don't deserialize it, we scan
the readable text (UTF-8 and UTF-16) for IOCs — a hunting lens, not a decoder.
"""
from __future__ import annotations

import os

from .leveldb import live_pairs

_MAX_VALUE = 1 << 20   # ignore absurdly large blobs


def _origin_from_dirname(name: str) -> str:
    base = name
    for suf in (".indexeddb.leveldb", ".leveldb"):
        if base.endswith(suf):
            base = base[: -len(suf)]
            break
    parts = base.split("_")
    if len(parts) < 3:
        return ""
    scheme, port = parts[0], parts[-1]
    host = "_".join(parts[1:-1])
    if port in ("0", "80", "443"):
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def _texts(value: bytes):
    # Printable UTF-8 run, plus a UTF-16-LE decode (JS strings are often UTF-16).
    out = []
    try:
        t8 = value.decode("utf-8", "ignore")
        if sum(c.isprintable() for c in t8) > 8:
            out.append(t8)
    except Exception:  # noqa: BLE001
        pass
    try:
        t16 = value.decode("utf-16-le", "ignore")
        if sum(c.isprintable() for c in t16) > 8:
            out.append(t16)
    except Exception:  # noqa: BLE001
        pass
    return out


def extract_values(profile_dir: str) -> list[tuple]:
    """Return [(origin, text)] for live IndexedDB values with readable text."""
    base = os.path.join(profile_dir, "IndexedDB")
    results: list[tuple] = []
    if not os.path.isdir(base):
        return results
    for name in sorted(os.listdir(base)):
        d = os.path.join(base, name)
        if not (os.path.isdir(d) and name.endswith(".leveldb")):
            continue
        origin = _origin_from_dirname(name)
        try:
            pairs = live_pairs(d)
        except Exception:  # noqa: BLE001
            continue
        for _k, v in pairs.items():
            if not v or len(v) > _MAX_VALUE:
                continue
            for t in _texts(v):
                results.append((origin, t))
    return results
