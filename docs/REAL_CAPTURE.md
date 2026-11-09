# Verified Real Capture — end-to-end against a live Chrome

This is the proof that FLOTSAM works on **genuine browser artifacts**, not just
fixtures: a real Chrome registers a malicious service worker that stages a
cross-origin payload in Cache Storage, Chrome writes the real on-disk Simple
Cache + registration LevelDB, and FLOTSAM parses and hunts it.

## Reproduce

```bash
scripts/real_capture.sh
```

It serves a victim PWA on `localhost:8000` and an attacker origin on
`127.0.0.1:8001`, launches headless Chrome with a throwaway profile, lets the
service worker install and cache the cross-origin payload, stops Chrome so it
flushes, then runs `flotsam inventory --deep` + `flotsam hunt` on the real
profile.

- Victim/attacker app: `demo/victim/` (index.html, app.js, **sw.js**), `demo/attacker/payload.js`
- The service worker (`demo/victim/sw.js`) fetches `http://127.0.0.1:8001/payload.js`
  (CORS-enabled) and `cache.put`s it into a `sync-tmp` cache — exactly what an
  injected worker would do.

## Verified result (real Chrome, macOS, 2026-11-09)

```
Scanned: 1 origins, 2 caches, 4 entries, 1 SW registrations
VERDICT: COMPROMISED  (risk score 25, 6 findings, top=high)
  [HIGH] cross-origin-entry      http://127.0.0.1:8001/payload.js cached under http://localhost:8000
  [MED ] base64-decode           atob() in cached body
  [HIGH] live-channel            WebSocket C2 in cached code
  [HIGH] exfil-beacon            sendBeacon/fetch exfil in cached code
  [HIGH] registered-script-cached http://localhost:8000/sw.js is the live registered worker
```

Every finding is recovered from real on-disk bytes: the cross-origin URL and the
payload signatures from the Simple Cache entry body, and the registration from
the `Service Worker/Database` LevelDB.

## Format note (useful for the talk)

Chromium's `SimpleFileHeader` and `SimpleFileEOF` structs both lead with a
`uint64`, so the compiler pads `sizeof()` to an 8-byte multiple: the **on-disk
records are 24 bytes**, not the 20 bytes of their field contents. Missing this
silently shifts every offset. FLOTSAM accounts for it, finds the response body
as the first inter-EOF segment after the key, and prefers the text-bearing file
when an entry is split across `_0`/`_1`.

## Scope honesty
This validates parsing + hunting against real artifacts. FLOTSAM focuses on the
single-file response-body case (the common one for Cache Storage); exotic
sparse/multi-stream entries are out of scope and are skipped, not mis-parsed.
