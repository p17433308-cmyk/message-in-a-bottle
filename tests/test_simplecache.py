"""Byte-accurate round-trip test for the native Simple Cache reader.

We synthesize a Simple Cache entry file exactly per the documented on-disk
format, then prove the reader recovers the key/URL, body, and MIME. This
validates the parser against the real format without needing a live browser.
"""
import sys, pathlib, struct, zlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from flotsam.simplecache import (
    parse_entry, sniff_mime, INITIAL_MAGIC, FINAL_MAGIC, HEADER, EOF,
)


def build_entry(key: bytes, body: bytes, meta: bytes) -> bytes:
    """Produce a valid Simple Cache file: header|key|stream1|EOF1|stream0|EOF0."""
    out = bytearray()
    out += HEADER.pack(INITIAL_MAGIC, 5, len(key), 0)
    out += key
    out += body                                   # stream 1 = body
    out += EOF.pack(FINAL_MAGIC, 0, zlib.crc32(body) & 0xffffffff, len(body))
    out += meta                                   # stream 0 = metadata
    out += EOF.pack(FINAL_MAGIC, 0, zlib.crc32(meta) & 0xffffffff, len(meta))
    return bytes(out)


def test_roundtrip_basic():
    key = b"_dk_https://victim.example https://victim.example https://evil.tld/p.js"
    body = b"var p=atob('AAAA');eval(p);"
    meta = b"\x00\x00HTTP/1.1 200 OK\x00Content-Type: application/javascript\x00"
    blob = build_entry(key, body, meta)
    e = parse_entry(blob)
    assert e.url == "https://evil.tld/p.js", e.url
    assert e.body == body, e.body
    assert sniff_mime(e.meta, e.body) == "application/javascript"


def test_roundtrip_html_sniff():
    key = b"https://x.example/index.html"
    body = b"<!DOCTYPE html><title>ok</title>"
    meta = b"garbage-without-content-type"
    e = parse_entry(build_entry(key, body, meta))
    assert e.url == "https://x.example/index.html"
    assert sniff_mime(e.meta, e.body) == "text/html"


def test_rejects_bad_magic():
    blob = bytearray(build_entry(b"k", b"b", b"m"))
    blob[0] ^= 0xFF
    try:
        parse_entry(bytes(blob))
    except Exception:
        return
    raise AssertionError("should have rejected bad magic")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn(); print(f"ok  {name}")
    print("all simplecache tests passed")
