"""Byte-accurate round-trip test for the native Simple Cache reader + helpers."""
import sys, pathlib, zlib, gzip
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from flotsam.simplecache import (
    parse_entry, parse_meta, decompress, INITIAL_MAGIC, FINAL_MAGIC,
    HEADER, EOF, FLAG_HAS_CRC32,
)


def build_entry(key: bytes, body: bytes, meta: bytes, with_crc=True) -> bytes:
    out = bytearray()
    out += HEADER.pack(INITIAL_MAGIC, 5, len(key), 0) + b"\x00\x00\x00\x00"  # 24B
    out += key + body
    flags = FLAG_HAS_CRC32 if with_crc else 0
    out += EOF.pack(FINAL_MAGIC, flags, zlib.crc32(body) & 0xffffffff, len(body))
    out += b"\x00\x00\x00\x00"                                              # 24B
    out += meta
    out += EOF.pack(FINAL_MAGIC, 0, zlib.crc32(meta) & 0xffffffff, len(meta))
    out += b"\x00\x00\x00\x00"
    return bytes(out)


def test_roundtrip_and_crc_ok():
    key = b"_dk_https://victim.example https://victim.example https://evil.tld/p.js"
    body = b"var p=atob('AAAA');eval(p);"
    meta = b"\x00HTTP/1.1 200 OK\x00Content-Type: application/javascript\x00"
    e = parse_entry(build_entry(key, body, meta))
    assert e.url == "https://evil.tld/p.js", e.url
    assert e.body == body
    assert e.body_crc_ok is True
    status, headers = parse_meta(e.meta)
    assert status == 200, status
    assert headers.get("content-type") == "application/javascript"


def test_crc_ok_on_clean_body():
    e = parse_entry(build_entry(b"https://x/a.js", b"console.log(1)", b"m"))
    assert e.body_crc_ok is True


def test_crc_not_asserted_on_corruption():
    blob = bytearray(build_entry(b"https://x/a.js", b"hello world body", b"m"))
    blob[24 + len(b"https://x/a.js") + 1] ^= 0xFF  # corrupt one body byte
    e = parse_entry(bytes(blob))
    assert e.body_crc_ok is not True  # unknown, not a false "verified"


def test_decompress_gzip():
    raw = b"console.log('ok')" * 50
    data, ok = decompress(gzip.compress(raw), "gzip")
    assert ok and data == raw


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
