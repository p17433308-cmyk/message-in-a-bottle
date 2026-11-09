"""Service Worker registration recovery + sibling-channel presence.

The *persistence* in a service-worker attack lives in the registration, not the
cache: `Service Worker/Database` (a LevelDB) maps each origin to its registered
worker script, scope, and updateViaCache policy. Correlating a suspicious cached
payload with an ACTIVE registration is the difference between "a weird file" and
"a live, origin-wide persistence mechanism."

We do not ship a full LevelDB+protobuf parser (that is a project of its own).
Instead we scan the LevelDB table/log bytes for the registration strings, which
are stored as UTF-8 and survive compaction. This recovers origin + script_url +
scope reliably enough for correlation; we flag it as heuristic.

We also note the sibling abuse channels (ACM 2021): IndexedDB and Push.
"""
from __future__ import annotations

import os
import re
from urllib.parse import urlparse

from .models import Registration

_URL_RE = re.compile(rb"https?://[A-Za-z0-9\-._~:/%?#\[\]@!$&'()*+,;=]+")


def _origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}" if p.scheme and p.netloc else ""


def _db_blob(profile_dir: str, rel: str) -> bytes:
    d = os.path.join(profile_dir, rel)
    if not os.path.isdir(d):
        return b""
    out = bytearray()
    for name in sorted(os.listdir(d)):
        if name.endswith((".ldb", ".log")) or name in ("CURRENT", "MANIFEST"):
            try:
                out += open(os.path.join(d, name), "rb").read()
            except OSError:
                continue
    return bytes(out)


def scan_registrations(profile_dir: str) -> list[Registration]:
    blob = _db_blob(profile_dir, os.path.join("Service Worker", "Database"))
    if not blob:
        return []
    urls = {m.group(0).decode("utf-8", "replace") for m in _URL_RE.finditer(blob)}
    by_origin: dict[str, list[str]] = {}
    for u in urls:
        o = _origin(u)
        if o:
            by_origin.setdefault(o, []).append(u)

    regs: list[Registration] = []
    for origin, us in sorted(by_origin.items()):
        scripts = [u for u in us if u.lower().rstrip("/").endswith(".js")
                   or re.search(r"(sw|service.?worker|worker)\b", u, re.I)]
        script = sorted(scripts, key=len)[0] if scripts else ""
        # Scope = shortest same-origin path URL seen (often the registration scope).
        paths = sorted((u for u in us if u != script), key=len)
        scope = paths[0] if paths else origin + "/"
        regs.append(Registration(origin=origin, scope=scope, script_url=script,
                                  update_via_cache=""))
    return regs


def side_channels(profile_dir: str) -> dict:
    """Light presence check for the sibling abuse channels."""
    out = {"indexeddb_origins": [], "push_present": False}
    idb = os.path.join(profile_dir, "IndexedDB")
    if os.path.isdir(idb):
        out["indexeddb_origins"] = sorted(
            n for n in os.listdir(idb) if n.endswith(".leveldb"))
    # GCM/push store hints.
    for cand in ("GCM Store", "Platform Notifications"):
        if os.path.exists(os.path.join(profile_dir, cand)):
            out["push_present"] = True
    return out
