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


class Verdict(str, Enum):
    CLEAN = "clean"             # nothing notable
    SUSPICIOUS = "suspicious"   # indicators worth a human look
    COMPROMISED = "compromised" # strong abuse indicators


@dataclass
class CacheEntry:
    request_url: str = ""
    response_mime: str = ""
    response_status: int = 200
    size: int = 0
    body_sha256: str = ""
    body_preview: str = ""      # first bytes decoded, for signature matching
    body_entropy: float = 0.0   # bits/byte
    mtime: float = 0.0


@dataclass
class CacheBucket:
    name: str = ""
    guid: str = ""
    in_index: bool = True       # referenced by CacheStorage index?
    mtime: float = 0.0
    entries: list[CacheEntry] = field(default_factory=list)


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


@dataclass
class Finding:
    rule: str
    severity: Severity
    origin: str
    cache: str
    request_url: str
    detail: str

    def as_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class HuntResult:
    verdict: Verdict
    findings: list[Finding] = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps({
            "verdict": self.verdict.value,
            "stats": self.stats,
            "findings": [f.as_dict() for f in self.findings],
        }, indent=indent)


def max_severity(findings: list[Finding]) -> Optional[Severity]:
    if not findings:
        return None
    return max((f.severity for f in findings), key=lambda s: _ORDER[s])


def severity_rank(s: Severity) -> int:
    return _ORDER[s]
