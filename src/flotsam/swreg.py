"""Service Worker registration recovery + sibling-channel presence.

The persistence in a service-worker attack lives in the registration, not the
cache: `Service Worker/Database` (a LevelDB) maps each origin to its registered
worker script, scope, and updateViaCache policy. Correlating a suspicious cached
payload with an ACTIVE registration is the difference between "a weird file" and
"a live, origin-wide persistence mechanism."

We now parse the LevelDB properly (see leveldb.py): only LIVE records survive —
unregistered/stale workers are tombstoned and excluded — and each registration
value is a ServiceWorkerRegistrationData protobuf we decode for scope, script,
and updateViaCache. A raw-byte scan remains as a fallback for Snappy-compacted
databases we cannot fully decode.
"""
from __future__ import annotations

import os
import re

from .models import Registration
from .leveldb import live_pairs
from . import proto

# ServiceWorkerRegistrationData field numbers (service_worker_database.proto).
_F_SCOPE = 2
_F_SCRIPT = 3
_F_UVC = 12  # update_via_cache (enum); best-effort
_UVC = {0: "imports", 1: "all", 2: "none"}
_URL_RE = re.compile(rb"https?://[A-Za-z0-9\-._~:/%?#\[\]@!$&'()*+,;=]+")


def _from_leveldb(db_dir: str) -> list[Registration]:
    regs: list[Registration] = []
    for key, value in live_pairs(db_dir).items():
        if not key.startswith(b"REG:"):
            continue
        origin = key[4:].split(b"\x00")[0].decode("utf-8", "replace")
        f = proto.parse(value)
        scope = proto.as_str(f[_F_SCOPE][0]) if _F_SCOPE in f else ""
        script = proto.as_str(f[_F_SCRIPT][0]) if _F_SCRIPT in f else ""
        uvc = ""
        if _F_UVC in f and isinstance(f[_F_UVC][0], int):
            uvc = _UVC.get(f[_F_UVC][0], "")
        regs.append(Registration(origin=origin or _origin(script or scope),
                                 scope=scope, script_url=script, update_via_cache=uvc))
    return regs


def _origin(url: str) -> str:
    from urllib.parse import urlparse
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}" if p.scheme and p.netloc else ""


def _raw_fallback(db_dir: str) -> list[Registration]:
    """Byte-scan fallback when the LevelDB can't be decoded (e.g. Snappy)."""
    blob = b""
    for name in sorted(os.listdir(db_dir)):
        if name.endswith((".ldb", ".log", ".sst")):
            try:
                blob += open(os.path.join(db_dir, name), "rb").read()
            except OSError:
                continue
    urls = {m.group(0).decode("utf-8", "replace") for m in _URL_RE.finditer(blob)}
    by_origin: dict[str, list[str]] = {}
    for u in urls:
        o = _origin(u)
        if o:
            by_origin.setdefault(o, []).append(u)
    regs: list[Registration] = []
    for origin, us in sorted(by_origin.items()):
        scripts = [u for u in us if u.lower().rstrip("/").endswith(".js")]
        script = sorted(scripts, key=len)[0] if scripts else ""
        scope = sorted((u for u in us if u != script), key=len)
        regs.append(Registration(origin=origin, scope=scope[0] if scope else origin + "/",
                                 script_url=script, update_via_cache=""))
    return regs


def scan_registrations(profile_dir: str) -> list[Registration]:
    db = os.path.join(profile_dir, "Service Worker", "Database")
    if not os.path.isdir(db):
        return []
    regs = _from_leveldb(db)
    if regs:
        return regs
    return _raw_fallback(db)


def side_channels(profile_dir: str) -> dict:
    out = {"indexeddb_origins": [], "push_present": False}
    idb = os.path.join(profile_dir, "IndexedDB")
    if os.path.isdir(idb):
        out["indexeddb_origins"] = sorted(
            n for n in os.listdir(idb) if n.endswith(".leveldb"))
    for cand in ("GCM Store", "Platform Notifications"):
        if os.path.exists(os.path.join(profile_dir, cand)):
            out["push_present"] = True
    return out
