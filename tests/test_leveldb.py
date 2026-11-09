"""Tests for the LevelDB reader, protobuf parser, and SW registration parse."""
import sys, pathlib, os, tempfile, struct
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from flotsam.leveldb import read_log, live_pairs
from flotsam import proto
from flotsam.extract import _origin_identifier_hashes
from flotsam.swreg import scan_registrations


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _batch(seq: int, recs: list) -> bytes:
    b = struct.pack("<QI", seq, len(recs))
    for rtype, key, val in recs:
        b += bytes([rtype]) + _varint(len(key)) + key
        if rtype == 1:
            b += _varint(len(val)) + val
    return b


def _log_record(batch: bytes) -> bytes:
    return b"\x00\x00\x00\x00" + struct.pack("<H", len(batch)) + b"\x01" + batch


def test_log_put_and_tombstone():
    with tempfile.TemporaryDirectory() as d:
        log = _log_record(_batch(1, [(1, b"REG:https://a", b"val1")]))
        log += _log_record(_batch(2, [(1, b"REG:https://b", b"val2")]))
        log += _log_record(_batch(3, [(0, b"REG:https://b", b"")]))  # delete b
        open(os.path.join(d, "000003.log"), "wb").write(log)
        live = live_pairs(d)
        assert b"REG:https://a" in live
        assert b"REG:https://b" not in live, "tombstoned record must be excluded"


def _pbfield(num: int, val: bytes) -> bytes:
    return bytes([num << 3 | 2]) + _varint(len(val)) + val


def test_proto_parse_strings():
    msg = _pbfield(2, b"https://x/sc/") + _pbfield(3, b"https://x/sw.js")
    f = proto.parse(msg)
    assert proto.as_str(f[2][0]) == "https://x/sc/"
    assert proto.as_str(f[3][0]) == "https://x/sw.js"


def test_origin_hash_known_value():
    hashes = _origin_identifier_hashes("http://localhost:8000")
    assert "d9771a1d5c0593755eedd039d9d681b859f87dc1" in hashes


def test_scan_registrations_from_leveldb():
    with tempfile.TemporaryDirectory() as prof:
        db = os.path.join(prof, "Service Worker", "Database")
        os.makedirs(db)
        val = _pbfield(2, b"https://bank.example/") + _pbfield(3, b"https://bank.example/sw.js")
        key = b"REG:https://bank.example\x001"
        open(os.path.join(db, "000003.log"), "wb").write(_log_record(_batch(1, [(1, key, val)])))
        regs = scan_registrations(prof)
        assert any(r.origin == "https://bank.example"
                   and r.script_url == "https://bank.example/sw.js" for r in regs), regs


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn(); print(f"ok  {name}")
    print("all leveldb tests passed")
