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

from .models import Inventory, OriginStore, CacheBucket, CacheEntry
from .simplecache import parse_entry, parse_meta, decompress, SimpleCacheError
from .swreg import scan_registrations


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
    entries: list[CacheEntry] = []
    for name in sorted(os.listdir(cache_dir)):
        path = os.path.join(cache_dir, name)
        if not os.path.isfile(path) or name.startswith("index"):
            continue
        try:
            with open(path, "rb") as fh:
                data = fh.read()
            e = parse_entry(data)
        except (SimpleCacheError, OSError):
            continue  # not a single-file Simple Cache entry (or multi-file)

        status, headers = parse_meta(e.meta)
        enc = headers.get("content-encoding", "")
        mime = headers.get("content-type", "").split(";")[0].strip().lower()
        decoded_body, ok = decompress(e.body, enc)
        if not mime:
            mime = _sniff(decoded_body)
        text = decoded_body.decode("utf-8", "replace")
        entries.append(CacheEntry(
            request_url=e.url, response_mime=mime, response_status=status,
            content_encoding=enc, size=len(decoded_body),
            body_sha256=hashlib.sha256(decoded_body).hexdigest(),
            body_preview=text[:512], body_text=text,
            body_entropy=_entropy(decoded_body),
            crc_ok=e.body_crc_ok, decoded=ok, mtime=os.path.getmtime(path)))
    return entries


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
    return inv
