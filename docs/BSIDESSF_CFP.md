# BSidesSF 2027 — CFP Submission (Project 2)
## Message in a Bottle: Hunting Attacker Payloads in the Service Worker Cache

**Conference:** BSidesSF 2027 · Pier 27, SF · April 3–4, 2027
**Track:** DFIR / Blue Team (offense crossover)
**Tool release:** FLOTSAM (open-source, Apache-2.0)

---

## Submission A — Presentation (45 minutes)

### Title
Message in a Bottle: Hunting Attacker Payloads in the Service Worker Cache

### Session Abstract (≤300 chars)
The browser's Service Worker Cache is persistent, origin-wide, runs offline, and
is almost never examined in incident response. Academics showed it can hide
fileless malware and XSS persistence; attackers know. This talk shows defenders
how to hunt it, and releases an open tool.

### Session Content

#### Thesis / Takeaway
Service Worker Cache Storage is a persistence and payload-staging surface that
sits in plain sight: it survives reloads, is reachable from the whole origin, and
no mainstream DFIR workflow inspects it. Attendees learn where it lives on disk,
what abuse looks like, and leave with an open-source tool (FLOTSAM) that triages
a browser profile and flags the indicators of abuse.

#### Intended Audience
Incident responders, threat hunters, blue-team analysts, and the web-attack crowd
curious how far a service-worker foothold can go. Comfort with browser internals
helps but is not required.

#### Outline (45 minutes)
1. (0–4) Cold open: a reloaded, "cleaned" page that still serves attacker code
   from Cache Storage. The hook.
2. (4–11) Service worker + Cache API primer: lifecycle, origin-wide reach, offline
   serving, and why "close the tab" does not help.
3. (11–18) The documented attacks: Cache tampering via XSS persistence (SecWeb
   2020), the IndexedDB/push channels (ACM 2021), fileless memory-resident malware
   (JSLess 2019). Why practitioners still don't look.
4. (18–26) Where it lives on disk: the `Service Worker/CacheStorage/` tree, the
   index (text vs protobuf), Simple Cache backend, and what "not in the index"
   means forensically.
5. (26–34) FLOTSAM: an abuse-hunting lens, not a dumper. The rules — orphaned
   caches, cross-origin entries, payload signatures, obfuscated bodies — and why
   each is defensible and low-false-positive (caching your own JS is normal).
6. (34–40) Live hunt: a benign PWA profile vs a compromised one; FLOTSAM reaches
   COMPROMISED and explains why. IR report output.
7. (40–44) Remediation + the takeaway: unregister/purge correctly, fix the vector,
   preserve evidence first. Tool + rules released.
8. (44–45) Q&A.

#### Novelty
Prior tooling parses Chromium caches (ccl_chromium_reader) but none triages Cache
Storage for ABUSE. The attack is proven in academia but absent from practitioner
workflows and tooling. FLOTSAM is the first open hunting lens for it.

#### What this is not
Not a cache dumper (that exists). Not a claim to decrypt or defeat anything. Full
body extraction is delegated to ccl_chromium_reader; FLOTSAM adds the detection
layer. Original, unpublished; BSidesSF premiere.

---

## Submission B — Workshop (120 minutes)
**Title:** Washed Ashore — Hands-on Service Worker Cache Threat Hunting

Laptop-only, Python 3.9+. Attendees get inventory packs (benign + several
compromised profiles), run FLOTSAM, write and defend verdicts, then craft their
own malicious inventory to prove they understand the abuse model. 7 blocks:
setup, SW/Cache primer, hunt-by-hand, the rules, the traps (false positives:
legit PWAs), build-your-own-payload, field kit + report.

## Logistics
- Vendor pitch? No. Open-source tool release.
- AV: projector/HDMI; terminal + live hunt (recorded fallback ready).
- Prior venues: none — premiere.
