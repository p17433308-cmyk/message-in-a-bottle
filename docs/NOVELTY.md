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

## Three defensible contributions
1. **An abuse-detection ruleset** for Cache Storage, tuned to be low-false-positive
   (caching your own JS is normal; cross-origin/orphaned/obfuscated is not).
2. **A reproducible inventory format** so hunts are offline, auditable, and shareable
   as teaching/ evidence packs.
3. **The first open hunting tool (FLOTSAM)** bridging a documented-but-ignored attack
   to day-to-day IR.

## What we explicitly do NOT claim
- Not the first to parse Cache Storage (ccl does). We depend on it for body extraction.
- No claim of intent from a single indicator; findings are for analyst review.
