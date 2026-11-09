"""The abuse-hunting engine.

Walks an Inventory of Service Worker Cache Storage and emits weighted Findings
for the indicators academic work ties to Cache-Storage abuse, correlates them
with actual Service Worker registrations (proof of live persistence), applies a
CDN allowlist to cut false positives, and builds a timeline that flags recently
planted entries. A hunting lens, not a parser.
"""
from __future__ import annotations

from collections import Counter
from statistics import median
from urllib.parse import urlparse

from .models import (
    Inventory, Finding, HuntResult, Severity, Verdict,
    SEVERITY_WEIGHT, max_severity,
)
from .rules import default_rules, Rule

# Reputable public CDNs: cross-origin caching from these is normal, so down-rank.
_CDN_ALLOWLIST = {
    "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "ajax.googleapis.com",
    "fonts.googleapis.com", "fonts.gstatic.com", "www.gstatic.com",
    "unpkg.com", "code.jquery.com", "stackpath.bootstrapcdn.com",
    "maxcdn.bootstrapcdn.com", "cdn.skypack.dev", "esm.sh", "jsdelivr.net",
    "d3js.org", "polyfill.io",
}
_SCRIPT_MIMES = {
    "application/javascript", "text/javascript", "application/x-javascript",
    "application/ecmascript", "text/ecmascript", "application/wasm",
}
_MARKUP_MIMES = {"text/html", "application/xhtml+xml"}
_RECENT_GAP = 3600.0   # seconds a "newer" entry must lead the baseline to flag


def _host(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except Exception:  # noqa: BLE001
        return ""


def _origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}" if p.scheme and p.netloc else ""


def hunt(inv: Inventory, rules: list[Rule] | None = None) -> HuntResult:
    rules = rules or default_rules()
    findings: list[Finding] = []
    n_origins = n_caches = n_entries = 0
    all_mtimes: list[float] = []

    reg_origins = {r.origin for r in inv.registrations if r.origin}
    reg_scripts = {r.script_url for r in inv.registrations if r.script_url}
    reg_by_origin = {r.origin: r for r in inv.registrations}

    def add(rule, sev, origin, cache, url, detail):
        findings.append(Finding(rule, sev, origin, cache, url, detail,
                                weight=SEVERITY_WEIGHT[sev]))

    for store in inv.origins:
        n_origins += 1
        own = store.origin
        # Infer the store's true origin once, from the modal origin of ALL its
        # entries (the registering origin dominates a legit profile). Used only
        # when `own` is an opaque hash (deep extract).
        if own and not own.startswith("(hash:"):
            store_origin = own
        else:
            ens = [_origin(x.request_url) for c in store.caches
                   for x in c.entries if _origin(x.request_url)]
            store_origin = Counter(ens).most_common(1)[0][0] if ens else own
        for cache in store.caches:
            n_caches += 1
            if not cache.in_index:
                add("orphaned-cache", Severity.HIGH, own, cache.name, "",
                    "cache present on disk but absent from the CacheStorage index "
                    f"(index format: {cache.index_format}) — recently planted or "
                    "index tampered")
            base_origin = store_origin
            for e in cache.entries:
                n_entries += 1
                if e.mtime:
                    all_mtimes.append(e.mtime)
                mime = (e.response_mime or "").split(";")[0].strip().lower()
                text = e.body_text or e.body_preview or ""
                ent_origin = _origin(e.request_url)
                ent_host = _host(e.request_url)

                # R0: CRC mismatch = corruption or tampering.
                if e.crc_ok is False:
                    add("crc-mismatch", Severity.MEDIUM, own, cache.name, e.request_url,
                        "stored Simple Cache CRC32 does not match the body — "
                        "corruption or post-write tampering")

                # R1: executable content (INFO context unless combined).
                if mime in _SCRIPT_MIMES or mime in _MARKUP_MIMES:
                    add("cached-executable", Severity.INFO, own, cache.name, e.request_url,
                        f"executable content ({mime}) in Cache Storage — normal for "
                        "a PWA, risky combined with other findings")

                # R2: cross-origin staging, down-ranked for reputable CDNs.
                if ent_origin and base_origin and ent_origin != base_origin:
                    if ent_host in _CDN_ALLOWLIST or any(
                            ent_host.endswith("." + d) for d in _CDN_ALLOWLIST):
                        add("cross-origin-cdn", Severity.LOW, own, cache.name, e.request_url,
                            f"cross-origin entry from a reputable CDN ({ent_host}) — "
                            "usually benign; verify integrity")
                    else:
                        add("cross-origin-entry", Severity.HIGH, own, cache.name, e.request_url,
                            f"response from a different origin ({ent_origin}) cached "
                            f"under {base_origin} — cross-origin payload staging")

                # R3: payload signatures over the FULL decoded body.
                if text:
                    for rule in rules:
                        if rule.pattern.search(text):
                            findings.append(Finding(
                                rule.name, rule.severity, own, cache.name, e.request_url,
                                rule.description, weight=rule.weight))

                # R4: obfuscation — high entropy on DECODED text/script only.
                if (mime.startswith("text/") or mime in _SCRIPT_MIMES) and e.decoded \
                        and e.body_entropy >= 5.6:
                    add("obfuscated-body", Severity.MEDIUM, own, cache.name, e.request_url,
                        f"decoded text/script body entropy {e.body_entropy:.2f} "
                        "bits/byte — likely packed/obfuscated")

                # R5: the cached resource IS a registered worker script.
                if e.request_url and e.request_url in reg_scripts:
                    add("registered-script-cached", Severity.HIGH, own, cache.name,
                        e.request_url,
                        "this cached resource is a REGISTERED service-worker script — "
                        "if tampered, it re-runs on every visit, origin-wide")

                # R6: payload lives under an origin with an ACTIVE registration.
                if ent_origin in reg_origins and (mime in _SCRIPT_MIMES):
                    r = reg_by_origin.get(ent_origin)
                    scope = r.scope if r else ent_origin
                    add("active-persistence", Severity.HIGH, own, cache.name, e.request_url,
                        f"origin {ent_origin} has an ACTIVE service-worker "
                        f"registration (scope {scope}); cached code here is live "
                        "persistence, not a dead file")

    # Sibling channel: scan live IndexedDB values with the same rules.
    n_idb = 0
    seen_idb: set = set()
    for origin, text in inv.idb_values:
        if not text:
            continue
        n_idb += 1
        for rule in rules:
            key = (rule.name, origin)
            if key in seen_idb:
                continue
            if rule.pattern.search(text):
                seen_idb.add(key)
                findings.append(Finding(
                    f"idb:{rule.name}", rule.severity, origin or "(indexeddb)",
                    "IndexedDB", "", f"IndexedDB value — {rule.description}",
                    weight=rule.weight))

    # Timeline: flag entries much newer than the install baseline.
    timeline: list[dict] = []
    if all_mtimes:
        base = median(all_mtimes)
        newest = max(all_mtimes)
        for store in inv.origins:
            for cache in store.caches:
                for e in cache.entries:
                    recent = bool(e.mtime) and (e.mtime - base) > _RECENT_GAP
                    timeline.append({"mtime": e.mtime, "url": e.request_url,
                                     "cache": cache.name, "recently_planted": recent})
                    if recent and (e.response_mime.split("/")[0] in ("text", "application")):
                        add("recently-planted", Severity.MEDIUM, store.origin,
                            cache.name, e.request_url,
                            f"entry written {int(e.mtime - base)}s after the cache "
                            "baseline — out of step with the rest of the profile")
        timeline.sort(key=lambda d: d["mtime"])

    # Weighted scoring + verdict.
    score = sum(f.weight for f in findings)
    top = max_severity(findings)
    if top in (Severity.CRITICAL, Severity.HIGH) or score >= 10:
        verdict = Verdict.COMPROMISED
    elif top in (Severity.MEDIUM, Severity.LOW) or score >= 3:
        verdict = Verdict.SUSPICIOUS
    else:
        verdict = Verdict.CLEAN

    stats = {
        "origins": n_origins, "caches": n_caches, "entries": n_entries,
        "registrations": len(inv.registrations), "idb_values": n_idb,
        "findings": len(findings), "risk_score": score,
        "top_severity": top.value if top else "none",
    }
    return HuntResult(verdict, findings, stats, timeline)
