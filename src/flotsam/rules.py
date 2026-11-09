"""Extensible payload-signature rules.

Rules are data, not code, so analysts can extend them without touching FLOTSAM.
A rule set is a list of {name, pattern, severity, weight, description}. Load the
built-ins with default_rules(), or merge a user file (JSON) with load_rules().

This is deliberately YARA-flavoured but regex-based and dependency-free.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

from .models import Severity


@dataclass
class Rule:
    name: str
    pattern: "re.Pattern"
    severity: Severity
    weight: int
    description: str


_DEFAULTS = [
    ("dynamic-eval", r"\beval\s*\(", Severity.HIGH, 6,
     "eval() in cached body — dynamic code execution"),
    ("function-ctor", r"\bFunction\s*\(\s*['\"]", Severity.HIGH, 6,
     "Function() constructor built from a string"),
    ("base64-decode", r"\batob\s*\(", Severity.MEDIUM, 3,
     "base64 decode (atob) — common payload unpacking"),
    ("import-scripts", r"importScripts\s*\(", Severity.HIGH, 6,
     "importScripts() — a service worker pulling in extra code"),
    ("long-base64", r"[A-Za-z0-9+/]{200,}={0,2}", Severity.MEDIUM, 3,
     "long base64 blob — likely an embedded payload"),
    ("live-channel", r"\bnew\s+WebSocket\s*\(|\bnew\s+EventSource\s*\(", Severity.HIGH, 5,
     "live channel (WebSocket/SSE) opened from cached code — possible C2"),
    ("exfil-beacon", r"navigator\.sendBeacon\s*\(|fetch\([^)]*(?:collect|exfil|/log)",
     Severity.HIGH, 5, "exfil-style beacon/fetch in cached code"),
    ("keylogger", r"addEventListener\s*\(\s*['\"]key(down|press|up)['\"]",
     Severity.MEDIUM, 3, "keyboard event hook in cached code"),
    ("formjacker", r"addEventListener\s*\(\s*['\"]submit['\"]|\.elements\[",
     Severity.MEDIUM, 3, "form-submission hook — possible formjacking"),
    ("crypto-miner", r"\bCryptonight\b|coinhive|\bhashrate\b|new\s+Worker\([^)]*miner",
     Severity.HIGH, 5, "cryptomining markers"),
    ("obfuscator-io", r"_0x[a-f0-9]{4,}\b", Severity.MEDIUM, 2,
     "obfuscator.io-style hex identifiers"),
    ("wasm-instantiate", r"WebAssembly\.(instantiate|compile)\s*\(", Severity.LOW, 1,
     "WebAssembly instantiation from cached bytes"),
]


def default_rules() -> list[Rule]:
    return [Rule(n, re.compile(p, re.I), s, w, d) for (n, p, s, w, d) in _DEFAULTS]


def load_rules(path: str | None = None) -> list[Rule]:
    """Built-ins, optionally merged with a user JSON rule file."""
    rules = default_rules()
    if not path:
        return rules
    with open(path, "r", encoding="utf-8") as fh:
        for r in json.load(fh):
            rules.append(Rule(
                r["name"], re.compile(r["pattern"], re.I),
                Severity(r.get("severity", "medium")),
                int(r.get("weight", 3)), r.get("description", r["name"])))
    return rules
