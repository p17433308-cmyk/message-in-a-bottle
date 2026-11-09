"""FLOTSAM — Forensic Lookup Of Tampered Service-worker Artifacts & Malware.

Wreck debris washes ashore long after the ship is gone. So does an attacker's
payload: the browser's Service Worker Cache Storage is persistent, origin-wide,
runs offline, and is almost never examined in incident response.

Academic work (SecWeb 2020; ACM 2021; JSLess 2019) has shown Cache Storage can
be abused for XSS persistence, cross-origin payload staging, and fileless,
memory-resident malware. Yet no open DFIR tool triages it for ABUSE.

FLOTSAM is not another cache dumper (ccl_chromium_reader already parses Chromium
caches). It is a hunting lens: it inventories Service Worker Cache Storage and
flags the signs an attacker left behind — cached executable payloads, cross-
origin persistence, orphaned caches, obfuscated bodies — and times them.

All analysis runs on an extracted cache inventory (JSON), so it is reproducible
offline and safe to demo without a live browser.
"""

__version__ = "0.2.0"
__all__ = ["__version__"]
