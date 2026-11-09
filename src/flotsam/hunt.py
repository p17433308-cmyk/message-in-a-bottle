"""The abuse-hunting engine.

Walks an Inventory of Service Worker Cache Storage and emits Findings for the
indicators that academic work ties to Cache-Storage abuse. Each rule maps to a
concrete, defensible statement an analyst can act on. This is a hunting lens,
not a parser — it answers "did an attacker hide something here?", not "what is
cached?".
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from .models import (
    Inventory, Finding, HuntResult, Severity, Verdict, max_severity,
)

_SCRIPT_MIMES = {
    "application/javascript", "text/javascript", "application/x-javascript",
    "application/ecmascript", "text/ecmascript", "application/wasm",
}
_MARKUP_MIMES = {"text/html", "application/xhtml+xml"}

# Signatures seen in cached payloads / webshells / loaders.
_PAYLOAD_SIGS = [
    (re.compile(r"\beval\s*\("), "eval() in cached body"),
    (re.compile(r"\bFunction\s*\(\s*['\"]"), "Function() constructor from string"),
    (re.compile(r"\batob\s*\("), "base64 decode (atob) in cached body"),
    (re.compile(r"importScripts\s*\("), "importScripts() — SW pulling extra code"),
    (re.compile(r"(?:[A-Za-z0-9+/]{120,}={0,2})"), "long base64 blob"),
    (re.compile(r"\bWebSocket\s*\(|\bnew\s+EventSource\b"), "live channel (WS/SSE) in cached code"),
    (re.compile(r"navigator\.sendBeacon|fetch\([^)]*(?:collect|exfil|log)"), "exfil-style beacon"),
]


def _origin_of(url: str) -> str:
    try:
        p = urlparse(url)
        if p.scheme and p.netloc:
            return f"{p.scheme}://{p.netloc}"
    except Exception:  # noqa: BLE001
        pass
    return ""


def hunt(inv: Inventory) -> HuntResult:
    findings: list[Finding] = []
    n_origins = n_caches = n_entries = 0

    for store in inv.origins:
        n_origins += 1
        own_origin = store.origin
        for cache in store.caches:
            n_caches += 1

            # Rule R1: orphaned cache (present on disk but not in the index).
            # CacheStorage deletes unindexed caches on init, so an orphan that is
            # still present suggests very recent planting or index tampering.
            if not cache.in_index:
                findings.append(Finding(
                    "orphaned-cache", Severity.HIGH, own_origin, cache.name, "",
                    "cache present on disk but absent from CacheStorage index — "
                    "recently planted or index tampered (CacheStorage normally "
                    "deletes unindexed caches on startup)"))

            for e in cache.entries:
                n_entries += 1
                mime = (e.response_mime or "").split(";")[0].strip().lower()
                body = e.body_preview or ""
                ent_origin = _origin_of(e.request_url)

                # Rule R2: executable content cached (context only). Caching same-
                # origin JS/HTML is normal PWA behaviour, so this is INFO on its
                # own — it becomes dangerous combined with R1/R3/R4/R5 below.
                if mime in _SCRIPT_MIMES or mime in _MARKUP_MIMES:
                    findings.append(Finding(
                        "cached-executable", Severity.INFO, own_origin, cache.name, e.request_url,
                        f"executable content ({mime}) stored in Cache Storage — "
                        "normal for a PWA, but it is what a service worker can "
                        "serve origin-wide; review alongside other findings"))

                # Rule R3: cross-origin payload staged under victim origin.
                if ent_origin and own_origin and ent_origin != own_origin:
                    findings.append(Finding(
                        "cross-origin-entry", Severity.HIGH, own_origin, cache.name, e.request_url,
                        f"response from a DIFFERENT origin ({ent_origin}) cached "
                        f"under {own_origin} — classic cross-origin payload staging"))

                # Rule R4: payload signatures in the body.
                for rx, why in _PAYLOAD_SIGS:
                    if rx.search(body):
                        findings.append(Finding(
                            "payload-signature", Severity.HIGH, own_origin, cache.name, e.request_url,
                            f"suspicious pattern in cached body: {why}"))
                        break

                # Rule R5: obfuscation — high-entropy text body.
                if (mime.startswith("text/") or mime in _SCRIPT_MIMES) and e.body_entropy >= 5.3:
                    findings.append(Finding(
                        "obfuscated-body", Severity.MEDIUM, own_origin, cache.name, e.request_url,
                        f"text/script body has high entropy ({e.body_entropy:.2f} "
                        "bits/byte) — likely packed/obfuscated"))

    verdict = Verdict.CLEAN
    top = max_severity(findings)
    if top in (Severity.CRITICAL, Severity.HIGH):
        verdict = Verdict.COMPROMISED
    elif top in (Severity.MEDIUM, Severity.LOW):
        verdict = Verdict.SUSPICIOUS

    stats = {
        "origins": n_origins, "caches": n_caches, "entries": n_entries,
        "findings": len(findings),
        "top_severity": top.value if top else "none",
    }
    return HuntResult(verdict, findings, stats)
