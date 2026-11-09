# Message in a Bottle 🏴‍☠️
### FLOTSAM — hunting attacker payloads in the browser's Service Worker Cache

> *Wreck debris washes ashore long after the ship is gone. So does an attacker's
> payload — hiding in the one persistent, origin-wide, offline-capable browser
> store that incident responders almost never open: Service Worker Cache Storage.*

**Built for BSidesSF 2027 (Pier 27, Apr 3–4).** DFIR / offense crossover.

---

## The problem

The Service Worker **Cache API** is persistent storage that survives reloads,
runs offline, and is reachable from the whole origin. Academic work has shown it
can be abused for XSS persistence, cross-origin payload staging, and fileless,
memory-resident malware (SecWeb 2020; ACM 2021; JSLess 2019). But practitioners
don't look there, and **no open DFIR tool triages it for abuse**. General cache
tools (ChromeCacheView, Axiom, KAPE) parse the HTTP cache, not Cache Storage.

## What FLOTSAM is (and is not)

FLOTSAM ships its own **zero-dependency native reader** for Chromium's Simple
Cache format (`flotsam inventory --deep`), so it parses real Service Worker Cache
Storage entry bodies off disk with pure stdlib — no `ccl` install required. Its
value over a plain dumper is the **hunting lens**: it flags the signs of abuse
and times them:

| Rule | Signal |
|------|--------|
| `active-persistence` | cached code under an origin with an **active Service Worker registration** (live persistence, not a dead file) |
| `registered-script-cached` | the cached resource **is** a registered worker script — tamper it and it re-runs origin-wide |
| `orphaned-cache` | cache on disk but absent from the CacheStorage index (planted / index-tampered) |
| `cross-origin-entry` | a response from another origin cached under the victim origin (reputable CDNs down-ranked via allowlist) |
| `dynamic-eval` / `base64-decode` / `import-scripts` / `live-channel` / `exfil-beacon` / `keylogger` / `formjacker` / `crypto-miner` / … | extensible **YARA-style rules** scanned over the **full decoded body** |
| `obfuscated-body` | high-entropy decoded text/script (packed/obfuscated) |
| `crc-mismatch` | stored Simple Cache CRC32 ≠ body — corruption or post-write tampering |
| `recently-planted` | entry written well after the cache baseline (timeline anomaly) |

Verdicts: `CLEAN` · `SUSPICIOUS` · `COMPROMISED`, from a **weighted risk score** (not just max severity).

**Also:** parses the `Service Worker/Database` **LevelDB** for real registrations
(write-ahead log + SSTables, sequence-ordered and **tombstone-aware**, protobuf
decoded) and reverses Chromium's CacheStorage **origin-hash** to attribute
findings to the real origin; decompresses gzip/deflate (brotli if available)
before analysis; verifies CRC32; builds a timeline; notes sibling channels
(IndexedDB / Push); and loads custom rules with `--rules yourrules.json`.
Entirely zero-dependency (pure stdlib).

## Quick start

```bash
python3 tests/test_hunt.py
PYTHONPATH=src python3 -m flotsam.cli hunt --inventory samples/compromised.json
PYTHONPATH=src python3 -m flotsam.cli simulate --out /tmp/inv.json
PYTHONPATH=src python3 -m flotsam.cli hunt --inventory /tmp/inv.json --json
PYTHONPATH=src python3 -m flotsam.cli report --inventory samples/compromised.json
# Structural inventory of a real Chromium profile (no body parsing):
PYTHONPATH=src python3 -m flotsam.cli inventory --profile "~/Library/Application Support/Google/Chrome/Default"
```

All hunting runs on an extracted **inventory JSON**, so it is reproducible
offline and safe to demo without a live browser.

## Scope honesty

- FLOTSAM triages **structure + extracted bodies**; full response-body extraction
  from the Simple Cache format is delegated to `ccl_chromium_reader`, not
  reinvented. Our contribution is the abuse-detection lens.
- Findings flag indicators for analyst review — not proof of intent on their own.

## License
Apache-2.0. For authorized incident response, research, and education.
