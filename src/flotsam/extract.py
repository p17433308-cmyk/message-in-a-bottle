"""Deep extraction: turn a real Chromium profile's Service Worker Cache Storage
into a FLOTSAM Inventory (with fully-decoded response bodies), using the native
Simple Cache reader. Zero external dependencies.
"""
from __future__ import annotations

import hashlib
import math
import os
import time
from collections import Counter
from urllib.parse import urlparse

from .models import Inventory, OriginStore, CacheBucket, CacheEntry
from .simplecache import parse_entry, parse_meta, decompress, SimpleCacheError
from .swreg import scan_registrations

_DEFAULT_PORT = {"http": 80, "https": 443, "ws": 80, "wss": 443, "ftp": 21, "file": 0}


def _origin_of(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}" if p.scheme and p.netloc else ""


def _origin_identifier_hashes(origin: str) -> list[str]:
    """Chromium names the CacheStorage dir SHA1('<scheme>_<host>_<port>').
    Default ports have used both the real value and 0, so we offer both."""
    p = urlparse(origin)
    scheme, host = p.scheme, (p.hostname or "")
    if not scheme or not host:
        return []
    port = p.port if p.port is not None else _DEFAULT_PORT.get(scheme, 0)
    ids = {f"{scheme}_{host}_{port}", f"{scheme}_{host}_0"}
    return [hashlib.sha1(s.encode()).hexdigest() for s in ids]


def _entropy(b: bytes) -> float:
    if not b:
        return 0.0
    counts = Counter(b)
    n = len(b)
    return round(-sum((c / n) * math.log2(c / n) for c in counts.values()), 3)


def _index_membership(origin_dir: str) -> tuple[set, str]:
    """Return (set-of-strings-in-index, index_format). Works for the legacy text
    index and best-effort for the protobuf index by scanning for GUID strings."""
    for cand in ("index.txt", "index"):
        p = os.path.join(origin_dir, cand)
        if os.path.isfile(p):
            try:
                raw = open(p, "rb").read()
            except OSError:
                continue
            printable = sum(1 for c in raw if 32 <= c < 127 or c in (9, 10, 13))
            fmt = "text" if raw and printable / len(raw) > 0.9 else "protobuf"
            # Membership = GUID substring present in the index bytes (works for
            # both text and protobuf, since GUIDs are stored as ASCII).
            return {raw.decode("latin-1")}, fmt
    # index-dir/the-real-index (Simple Cache index) also lists entries.
    idx_dir = os.path.join(origin_dir, "index-dir")
    if os.path.isdir(idx_dir):
        return {"<index-dir-present>"}, "protobuf"
    return set(), "unknown"


def _guid_in_index(guid: str, index_blob: set, fmt: str) -> bool:
    if fmt == "unknown" or not index_blob:
        return True  # cannot tell; do not raise a false orphan alarm
    blob = next(iter(index_blob))
    if blob == "<index-dir-present>":
        return True  # Simple-Cache index present but not name-mapped here
    return guid in blob


def read_cache_dir(cache_dir: str) -> list[CacheEntry]:
    # Chromium may split one entry across `_0`/`_1` files that share the key, so
    # we key by URL and keep the richest (longest-body) parse per URL.
    best: dict[str, CacheEntry] = {}
    for name in sorted(os.listdir(cache_dir)):
        path = os.path.join(cache_dir, name)
        if not os.path.isfile(path) or name.startswith("index"):
            continue
        try:
            with open(path, "rb") as fh:
                data = fh.read()
            e = parse_entry(data)
        except (SimpleCacheError, OSError):
            continue

        status, headers = parse_meta(e.meta)
        enc = headers.get("content-encoding", "")
        mime = headers.get("content-type", "").split(";")[0].strip().lower()
        decoded_body, ok = decompress(e.body, enc)
        if not mime:
            mime = _sniff(decoded_body)
        text = decoded_body.decode("utf-8", "replace")
        entry = CacheEntry(
            request_url=e.url, response_mime=mime, response_status=status,
            content_encoding=enc, size=len(decoded_body),
            body_sha256=hashlib.sha256(decoded_body).hexdigest(),
            body_preview=text[:512], body_text=text,
            body_entropy=_entropy(decoded_body),
            crc_ok=e.body_crc_ok, decoded=ok, mtime=os.path.getmtime(path))
        # When `_0`/`_1` siblings both parse to the same URL, prefer the one
        # whose body is actual text/content (the other is a binary side-stream).
        prev = best.get(e.url)
        if prev is None or _text_score(entry) > _text_score(prev):
            best[e.url] = entry
    return list(best.values())


def _text_score(e: CacheEntry) -> tuple:
    t = e.body_text
    if not t:
        return (0.0, 0)
    printable = sum(1 for c in t if c.isprintable() or c in "\n\t\r")
    return (printable / len(t), len(t))


def _sniff(body: bytes) -> str:
    head = body[:64].lstrip()
    if head[:15].lower() == b"<!doctype html>" or head[:5].lower() == b"<html":
        return "text/html"
    if head[:2] == b"\xff\xd8":
        return "image/jpeg"
    if head[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    return "application/octet-stream"


def deep_extract(profile_dir: str) -> Inventory:
    base = os.path.join(profile_dir, "Service Worker", "CacheStorage")
    inv = Inventory(profile=profile_dir, extracted_at=time.time())
    # Correlate with actual Service Worker registrations (persistence proof).
    inv.registrations = scan_registrations(profile_dir)
    if not os.path.isdir(base):
        return inv
    for origin_hash in sorted(os.listdir(base)):
        odir = os.path.join(base, origin_hash)
        if not os.path.isdir(odir):
            continue
        index_blob, fmt = _index_membership(odir)
        store = OriginStore(origin=f"(hash:{origin_hash})", origin_hash=origin_hash)
        for guid in sorted(os.listdir(odir)):
            cdir = os.path.join(odir, guid)
            if not os.path.isdir(cdir) or guid == "index-dir":
                continue
            store.caches.append(CacheBucket(
                name=guid, guid=guid,
                in_index=_guid_in_index(guid, index_blob, fmt),
                index_format=fmt, mtime=os.path.getmtime(cdir),
                entries=read_cache_dir(cdir)))
        inv.origins.append(store)

    # Map each opaque origin-hash directory back to its real origin by hashing
    # candidate origins (from registrations + cached entry URLs) and matching.
    candidates = {r.origin for r in inv.registrations if r.origin}
    for store in inv.origins:
        for c in store.caches:
            for e in c.entries:
                o = _origin_of(e.request_url)
                if o:
                    candidates.add(o)
    hash_to_origin: dict[str, str] = {}
    for o in candidates:
        for h in _origin_identifier_hashes(o):
            hash_to_origin[h] = o
    for store in inv.origins:
        real = hash_to_origin.get(store.origin_hash)
        if real:
            store.origin = real
    return inv
