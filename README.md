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
| `orphaned-cache` | cache on disk but absent from the CacheStorage index (planted / index-tampered) |
| `cross-origin-entry` | a response from another origin cached under the victim origin |
| `payload-signature` | `eval` / `atob` / `Function()` / `importScripts` / base64 blob / WS-SSE / beacon |
| `obfuscated-body` | high-entropy text/script body (packed/obfuscated) |
| `cached-executable` | JS/HTML cached (INFO context; dangerous combined with the above) |

Verdicts: `CLEAN` · `SUSPICIOUS` · `COMPROMISED`.

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
