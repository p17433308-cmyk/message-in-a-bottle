"""Data models for FLOTSAM Service Worker Cache triage."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional
import json


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_ORDER = {s: i for i, s in enumerate(
    [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL])}

# Points each severity contributes to an entry's weighted risk score.
SEVERITY_WEIGHT = {
    Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 3,
    Severity.HIGH: 6, Severity.CRITICAL: 10,
}


class Verdict(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    COMPROMISED = "compromised"


@dataclass
class CacheEntry:
    request_url: str = ""
    response_mime: str = ""
    response_status: int = 0
    content_encoding: str = ""      # as stored (gzip/br/deflate/"")
    size: int = 0                   # decoded body size
    body_sha256: str = ""
    body_preview: str = ""          # first bytes decoded, for display only
    body_text: str = ""             # FULL decoded text for signature scanning
    body_entropy: float = 0.0       # bits/byte of the DECODED body
    crc_ok: Optional[bool] = None   # Simple Cache CRC32 verified? None=unknown
    decoded: bool = True            # was the body successfully decompressed?
    mtime: float = 0.0


@dataclass
class CacheBucket:
    name: str = ""
    guid: str = ""
    in_index: bool = True
    index_format: str = "unknown"   # text | protobuf | unknown
    mtime: float = 0.0
    entries: list[CacheEntry] = field(default_factory=list)


@dataclass
class Registration:
    """A registered Service Worker (from Service Worker/Database LevelDB)."""
    origin: str = ""
    scope: str = ""
    script_url: str = ""
    update_via_cache: str = ""      # all | imports | none


@dataclass
class OriginStore:
    origin: str = ""
    origin_hash: str = ""
    caches: list[CacheBucket] = field(default_factory=list)


@dataclass
class Inventory:
    profile: str = ""
    extracted_at: float = 0.0
    origins: list[OriginStore] = field(default_factory=list)
    registrations: list[Registration] = field(default_factory=list)
    idb_values: list = field(default_factory=list)   # [(origin, text)] IndexedDB


@dataclass
class Finding:
    rule: str
    severity: Severity
    origin: str
    cache: str
    request_url: str
    detail: str
    weight: int = 0

    def as_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class HuntResult:
    verdict: Verdict
    findings: list[Finding] = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    timeline: list[dict] = field(default_factory=list)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps({
            "verdict": self.verdict.value,
            "stats": self.stats,
            "timeline": self.timeline,
            "findings": [f.as_dict() for f in self.findings],
        }, indent=indent)


def max_severity(findings: list[Finding]) -> Optional[Severity]:
    if not findings:
        return None
    return max((f.severity for f in findings), key=lambda s: _ORDER[s])


def severity_rank(s: Severity) -> int:
    return _ORDER[s]
