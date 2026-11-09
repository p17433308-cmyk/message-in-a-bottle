"""Deep extraction: turn a real Chromium profile's Service Worker Cache Storage
into a FLOTSAM Inventory (with response bodies), using the native Simple Cache
reader. Zero external dependencies.
"""
from __future__ import annotations

import math
import os
import time
from collections import Counter

from .models import Inventory, OriginStore, CacheBucket, CacheEntry
from .simplecache import parse_entry, sniff_mime, SimpleCacheError


def _entropy(b: bytes) -> float:
    if not b:
        return 0.0
    counts = Counter(b)
    n = len(b)
    return round(-sum((c / n) * math.log2(c / n) for c in counts.values()), 3)


def _nonzero(b: bytes) -> float:
    return 0.0 if not b else round(1.0 - b.count(0) / len(b), 4)


def read_cache_dir(cache_dir: str) -> list[CacheEntry]:
    """Parse every Simple Cache entry file in one cache directory."""
    entries: list[CacheEntry] = []
    for name in sorted(os.listdir(cache_dir)):
        path = os.path.join(cache_dir, name)
        if not os.path.isfile(path):
            continue
        if name in ("index", "the-real-index") or name.startswith("index"):
            continue
        try:
            with open(path, "rb") as fh:
                data = fh.read()
            e = parse_entry(data)
        except (SimpleCacheError, OSError):
            continue
        import hashlib
        mime = sniff_mime(e.meta, e.body)
        preview = e.body[:512].decode("utf-8", "replace")
        entries.append(CacheEntry(
            request_url=e.url, response_mime=mime, response_status=200,
            size=len(e.body),
            body_sha256=hashlib.sha256(e.body).hexdigest(),
            body_preview=preview, body_entropy=_entropy(e.body),
            mtime=os.path.getmtime(path)))
    return entries


def deep_extract(profile_dir: str) -> Inventory:
    base = os.path.join(profile_dir, "Service Worker", "CacheStorage")
    inv = Inventory(profile=profile_dir, extracted_at=time.time())
    if not os.path.isdir(base):
        return inv
    for origin_hash in sorted(os.listdir(base)):
        odir = os.path.join(base, origin_hash)
        if not os.path.isdir(odir):
            continue
        indexed: set[str] = set()
        idx = os.path.join(odir, "index.txt")
        if os.path.exists(idx):
            try:
                indexed = set(open(idx, encoding="utf-8", errors="ignore").read().split())
            except OSError:
                pass
        store = OriginStore(origin=f"(hash:{origin_hash})", origin_hash=origin_hash)
        for guid in sorted(os.listdir(odir)):
            cdir = os.path.join(odir, guid)
            if not os.path.isdir(cdir):
                continue
            store.caches.append(CacheBucket(
                name=guid, guid=guid,
                in_index=(guid in indexed) if indexed else True,
                mtime=os.path.getmtime(cdir),
                entries=read_cache_dir(cdir)))
        inv.origins.append(store)
    return inv
