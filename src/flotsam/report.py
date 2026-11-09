"""Markdown IR report from a hunt result."""
from __future__ import annotations

from datetime import datetime, timezone

from .models import HuntResult

_VERDICT_TEXT = {
    "clean": "No Service-Worker Cache-Storage abuse indicators were found.",
    "suspicious": "Indicators were found that warrant analyst review; none are, "
                  "on their own, conclusive of compromise.",
    "compromised": "Strong indicators of Cache-Storage abuse were found. Treat "
                   "the affected origin(s) as a live persistence mechanism: a "
                   "service worker can keep serving cached payloads origin-wide "
                   "even after the originating page or injection is gone.",
}


def to_markdown(res: HuntResult, case_id: str = "UNASSIGNED", examiner: str = "") -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out: list[str] = []
    a = out.append
    a("# Service Worker Cache Storage — Hunt Report")
    a("")
    a(f"- **Case ID:** {case_id}")
    a(f"- **Examiner:** {examiner or 'n/a'}")
    a(f"- **Generated:** {now}")
    a(f"- **Tool:** FLOTSAM (Service Worker Cache abuse hunting)")
    a("")
    a("## Summary")
    a(f"**Verdict: {res.verdict.value.upper()}**")
    a("")
    a(_VERDICT_TEXT.get(res.verdict.value, ""))
    a("")
    s = res.stats
    a(f"Scanned {s.get('origins',0)} origin(s), {s.get('caches',0)} cache(s), "
      f"{s.get('entries',0)} entr(y/ies); {s.get('findings',0)} finding(s), "
      f"top severity {s.get('top_severity','none')}.")
    a("")
    a("## Findings")
    if not res.findings:
        a("_None._")
    else:
        for i, f in enumerate(res.findings, 1):
            a(f"### {i}. [{f.severity.value.upper()}] {f.rule}")
            a(f"- Origin: `{f.origin}`")
            a(f"- Cache: `{f.cache}`")
            if f.request_url:
                a(f"- Entry: `{f.request_url}`")
            a(f"- Detail: {f.detail}")
            a("")
    a("## Remediation")
    a("- Unregister the service worker and purge Cache Storage for the affected "
      "origin; a page reload alone does not remove it.")
    a("- Fix the original injection vector (XSS/compromised script); set "
      "`updateViaCache: 'none'` and enforce integrity on cached executable assets.")
    a("- Preserve the profile's `Service Worker/` tree as evidence before purging.")
    a("")
    a("## Limitations")
    a("- FLOTSAM triages structure and extracted bodies; full response-body "
      "extraction is delegated to ccl_chromium_reader. Findings flag indicators "
      "for analyst review, not proof of intent on their own.")
    return "\n".join(out) + "\n"
