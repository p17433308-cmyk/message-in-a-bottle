# Novelty & Prior-Art Delta

Pre-emptive answer to "what's new vs. existing work?"

## The existing body of work

| Work | Establishes | Does NOT do |
|------|-------------|-------------|
| SecWeb 2020, *The Remote on the Local* | XSS can tamper the Cache; it's origin-wide; injected content survives SW reinstall (persistence). | No detection/forensic tooling. |
| ACM 2021, *The Service Worker Hiding in Your Browser* | Cache + IndexedDB + push as attack channels; SW runs attacker code later. | Attack research, not IR. |
| JSLess 2019 | SW as fileless, memory-resident botnet node (theft, DDoS). | Demonstrates the threat; no defender tooling. |
| MarioNet 2018 | Browser-based persistent computation; mitigations. | Not cache-storage forensics. |
| ccl_chromium_reader (CCL) | Parses Chromium Simple Cache / Cache Storage on disk. | General parser; no abuse detection or hunting logic. |
| ChromeCacheView / Axiom / KAPE | Parse the HTTP cache and browser artifacts. | Not the Cache Storage API; no SW-abuse lens. |

## Our delta (one line)
> The attack is proven in academia and the parsing exists in `ccl_chromium_reader`,
> but **no open tool turns that into a practitioner hunting workflow**. FLOTSAM is
> the first open abuse-detection lens for Service Worker Cache Storage: it flags
> orphaned caches, cross-origin staging, payload signatures and obfuscation, and
> produces an IR verdict + report.

## Defensible contributions
1. **Registration-correlated detection** — FLOTSAM joins Cache Storage entries to
   the actual Service Worker **registration** (origin → script, scope,
   updateViaCache) by parsing the `Service Worker/Database` **LevelDB properly**
   (write-ahead log + SSTables, sequence-ordered, **tombstone-aware** so
   unregistered/stale workers are excluded) and decoding the registration
   **protobuf**. It also reverses Chromium's CacheStorage **origin-hash**
   (`SHA1("<scheme>_<host>_<port>")`) to attribute findings to the real origin.
   That turns "a suspicious file" into "a payload served by a LIVE, origin-wide
   worker." No open tool does this correlation — and it is all zero-dependency.
2. **A low-false-positive, extensible ruleset** — full-body (not preview) signature
   scanning after decompression, a CDN allowlist, weighted scoring, and
   user-loadable YARA-style rules.
3. **A reproducible inventory format + native zero-dependency parser** so hunts are
   offline, auditable, and shareable as teaching/evidence packs — no `ccl` install.
4. **Timeline + tamper signals** — CRC32 verification and baseline-relative planting
   detection, which the parsing-only prior art does not provide.

5. **Sibling-channel coverage** — the same rules hunt **IndexedDB** values (also a
   LevelDB), so the talk covers two of the three documented abuse channels
   (Cache Storage + IndexedDB), not one. A pure-Python **Snappy** + LevelDB stack
   means compacted, long-lived real profiles parse too — not just fresh ones.

## What we explicitly do NOT claim
- Not the first to parse Cache Storage (ccl does). FLOTSAM's contribution is the
  abuse-detection + correlation layer, and it is self-contained (its own Simple
  Cache, LevelDB and Snappy readers).
- No claim of intent from a single indicator; findings are for analyst review.
- IndexedDB object-store values are scanned as text for IOCs, not fully
  deserialized (Blink SSV); Firefox/Safari are future work.
