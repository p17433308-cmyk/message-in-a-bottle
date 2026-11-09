"""Native, zero-dependency reader for Chromium's Simple Cache entry format.

Used by Service Worker Cache Storage and the HTTP cache. We recover, per entry:
the cache key (request URL), the response body (stream 1), the response metadata
(stream 0 — status line + headers), and whether the stored CRC32 verifies (a
tamper / corruption signal).

Format reference: net/disk_cache/simple/simple_entry_format.h

  SimpleFileHeader { u64 initial_magic; u32 version; u32 key_length; u32 key_hash; }
  <key bytes>
  <stream 1 data>            (HTTP response BODY, possibly content-encoded)
  SimpleFileEOF              (for stream 1; carries crc32 + size)
  <stream 0 data>            (HTTP response METADATA: status line + headers)
  [optional 32-byte key SHA-256 if FLAG_HAS_KEY_SHA256]
  SimpleFileEOF              (for stream 0)

  SimpleFileEOF { u64 final_magic; u32 flags; u32 data_crc32; i32 stream_size; }

Little-endian. Streams are located by parsing the two EOF trailers from the end
of the file. Single-file entries (the common case for Cache Storage bodies) are
fully supported; multi-file/sparse entries are out of scope (defer to
ccl_chromium_reader) and are skipped rather than mis-parsed.
"""
from __future__ import annotations

import gzip
import re
import struct
import zlib
from dataclasses import dataclass

INITIAL_MAGIC = 0xfcfb6d1ba7725c30
FINAL_MAGIC = 0xf4fa6f45970d41d8
HEADER = struct.Struct("<QIII")   # magic, version, key_length, key_hash   (20 bytes)
EOF = struct.Struct("<QIIi")      # final_magic, flags, crc32, stream_size  (20 bytes)
FLAG_HAS_CRC32 = 1
FLAG_HAS_KEY_SHA256 = 2

try:
    import brotli  # optional; not in stdlib
    _HAVE_BROTLI = True
except Exception:  # noqa: BLE001
    _HAVE_BROTLI = False


class SimpleCacheError(Exception):
    pass


@dataclass
class SimpleEntry:
    key: str
    url: str
    body: bytes            # stream 1 as stored (possibly compressed)
    meta: bytes            # stream 0
    body_crc_ok: object = None   # True/False if CRC present, else None


def _url_from_key(key: str) -> str:
    toks = [t for t in key.split() if t.startswith("http://") or t.startswith("https://")]
    return toks[-1] if toks else key


def parse_entry(data: bytes) -> SimpleEntry:
    if len(data) < HEADER.size + EOF.size:
        raise SimpleCacheError("file too small")
    magic, version, key_len, key_hash = HEADER.unpack_from(data, 0)
    if magic != INITIAL_MAGIC:
        raise SimpleCacheError(f"bad initial magic 0x{magic:x}")
    if HEADER.size + key_len > len(data):
        raise SimpleCacheError("key length overruns file")
    key = data[HEADER.size:HEADER.size + key_len].decode("utf-8", "replace")

    m0, flags0, _crc0, s0 = EOF.unpack(data[-EOF.size:])
    if m0 != FINAL_MAGIC:
        raise SimpleCacheError("bad final magic for stream 0")
    sha_len = 32 if (flags0 & FLAG_HAS_KEY_SHA256) else 0
    stream0_end = len(data) - EOF.size - sha_len
    stream0_start = stream0_end - s0
    if stream0_start < 0:
        raise SimpleCacheError("stream 0 underruns file")
    meta = data[stream0_start:stream0_end]

    eof1_start = stream0_start - EOF.size
    if eof1_start < HEADER.size + key_len:
        raise SimpleCacheError("stream 1 trailer underruns file")
    m1, flags1, crc1, s1 = EOF.unpack(data[eof1_start:eof1_start + EOF.size])
    if m1 != FINAL_MAGIC:
        raise SimpleCacheError("bad final magic for stream 1")
    body_start = HEADER.size + key_len
    body = data[body_start:body_start + s1]

    crc_ok = None
    if flags1 & FLAG_HAS_CRC32:
        crc_ok = ((zlib.crc32(body) & 0xffffffff) == (crc1 & 0xffffffff))

    return SimpleEntry(key=key, url=_url_from_key(key), body=body, meta=meta,
                       body_crc_ok=crc_ok)


_STATUS_RE = re.compile(rb"HTTP/\d\.\d\s+(\d{3})")


def parse_meta(meta: bytes) -> tuple[int, dict]:
    """Best-effort (status, headers) from the stream-0 metadata blob.

    Chromium serializes HttpResponseInfo; the status line and headers survive as
    a NUL-separated ASCII block, which we scan rather than fully unpickle.
    """
    status = 0
    m = _STATUS_RE.search(meta)
    if m:
        try:
            status = int(m.group(1))
        except ValueError:
            status = 0
    headers: dict[str, str] = {}
    for part in meta.split(b"\x00"):
        if b":" in part and part[:1].isalpha():
            try:
                k, v = part.split(b":", 1)
                hk = k.decode("ascii", "ignore").strip().lower()
                if 1 <= len(hk) <= 40 and all(c.isprintable() for c in hk):
                    headers[hk] = v.decode("ascii", "ignore").strip()
            except Exception:  # noqa: BLE001
                continue
    return status, headers


def decompress(body: bytes, content_encoding: str) -> tuple[bytes, bool]:
    """Decode a possibly content-encoded body. Returns (data, decoded_ok)."""
    enc = (content_encoding or "").lower().strip()
    try:
        if enc in ("gzip", "x-gzip"):
            return gzip.decompress(body), True
        if enc == "deflate":
            try:
                return zlib.decompress(body), True
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS), True
        if enc == "br":
            if _HAVE_BROTLI:
                return brotli.decompress(body), True
            return body, False  # brotli not available; flag as undecoded
    except Exception:  # noqa: BLE001
        return body, False
    return body, True  # identity / unknown-but-plaintext
