"""Native, zero-dependency reader for Chromium's Simple Cache entry format.

Used by Service Worker Cache Storage (content/browser/cache_storage) and the
HTTP cache. We implement enough of the on-disk format to recover, per entry:
the cache key (request URL), the response body (stream 1), and a best-effort
MIME/status sniff from the response-metadata blob (stream 0).

Format reference: net/disk_cache/simple/simple_entry_format.h

  SimpleFileHeader { u64 initial_magic; u32 version; u32 key_length; u32 key_hash; }
  <key bytes>                 (key_length)
  <stream 1 data>            (the HTTP response BODY)
  SimpleFileEOF              (for stream 1)
  <stream 0 data>            (the HTTP response METADATA)
  [optional 32-byte key SHA-256 if FLAG_HAS_KEY_SHA256]
  SimpleFileEOF              (for stream 0)

  SimpleFileEOF { u64 final_magic; u32 flags; u32 data_crc32; i32 stream_size; }

All integers are little-endian. We parse the two EOF trailers from the end of
the file to locate the stream boundaries, which avoids guessing stream sizes.

This is a deliberately small, auditable reader. For edge cases (sparse entries,
multi-file entries) defer to ccl_chromium_reader; those are rare for Cache
Storage response bodies.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

INITIAL_MAGIC = 0xfcfb6d1ba7725c30
FINAL_MAGIC = 0xf4fa6f45970d41d8
HEADER = struct.Struct("<QIII")   # magic, version, key_length, key_hash   (20 bytes)
EOF = struct.Struct("<QIIi")      # final_magic, flags, crc32, stream_size  (20 bytes)
FLAG_HAS_KEY_SHA256 = 2


class SimpleCacheError(Exception):
    pass


@dataclass
class SimpleEntry:
    key: str            # raw cache key (contains the request URL)
    url: str            # best-effort request URL parsed from the key
    body: bytes         # stream 1 (response body)
    meta: bytes         # stream 0 (serialized response metadata)


def _url_from_key(key: str) -> str:
    # CacheStorage keys look like "_dk_<top-origin> <frame-origin> <request-url>".
    # The request URL is the last whitespace-separated http(s) token.
    toks = [t for t in key.split() if t.startswith("http://") or t.startswith("https://")]
    if toks:
        return toks[-1]
    return key


def parse_entry(data: bytes) -> SimpleEntry:
    if len(data) < HEADER.size + EOF.size:
        raise SimpleCacheError("file too small")
    magic, version, key_len, key_hash = HEADER.unpack_from(data, 0)
    if magic != INITIAL_MAGIC:
        raise SimpleCacheError(f"bad initial magic 0x{magic:x}")
    if HEADER.size + key_len > len(data):
        raise SimpleCacheError("key length overruns file")
    key = data[HEADER.size:HEADER.size + key_len].decode("utf-8", "replace")

    # EOF0 is the last 20 bytes.
    eof0 = data[-EOF.size:]
    m0, flags0, _crc0, s0 = EOF.unpack(eof0)
    if m0 != FINAL_MAGIC:
        raise SimpleCacheError("bad final magic for stream 0")
    sha_len = 32 if (flags0 & FLAG_HAS_KEY_SHA256) else 0
    stream0_end = len(data) - EOF.size - sha_len
    stream0_start = stream0_end - s0
    if stream0_start < 0:
        raise SimpleCacheError("stream 0 underruns file")
    meta = data[stream0_start:stream0_end]

    # EOF1 sits immediately before stream 0 data.
    eof1_start = stream0_start - EOF.size
    if eof1_start < HEADER.size + key_len:
        raise SimpleCacheError("stream 1 trailer underruns file")
    m1, _flags1, _crc1, s1 = EOF.unpack(data[eof1_start:eof1_start + EOF.size])
    if m1 != FINAL_MAGIC:
        raise SimpleCacheError("bad final magic for stream 1")
    body_start = HEADER.size + key_len
    body = data[body_start:body_start + s1]

    return SimpleEntry(key=key, url=_url_from_key(key), body=body, meta=meta)


def sniff_mime(meta: bytes, body: bytes) -> str:
    """Best-effort MIME: look for a Content-Type token in the metadata blob,
    else sniff from the body's first bytes."""
    low = meta.lower()
    idx = low.find(b"content-type")
    if idx != -1:
        tail = meta[idx + len(b"content-type"):idx + len(b"content-type") + 128]
        tail = tail.lstrip(b": \x00")
        val = bytes(c for c in _until_ctrl(tail)).decode("ascii", "replace").strip()
        if val:
            return val.split(";")[0].strip().lower()
    head = body[:256].lstrip()
    if head[:15].lower() == b"<!doctype html>" or head[:5].lower() == b"<html":
        return "text/html"
    if head[:2] == b"\xff\xd8":
        return "image/jpeg"
    if head[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    return "application/octet-stream"


def _until_ctrl(b: bytes) -> bytes:
    out = bytearray()
    for c in b:
        if c in (0x00, 0x0a, 0x0d):
            break
        out.append(c)
    return bytes(out)
