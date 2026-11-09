"""FLOTSAM command-line interface.

    flotsam hunt --inventory samples/compromised.json
    flotsam hunt --inventory samples/compromised.json --json
    flotsam simulate --out /tmp/inv.json && flotsam hunt --inventory /tmp/inv.json
    flotsam inventory --profile "~/Library/Application Support/Google/Chrome/Default"
    flotsam report --inventory samples/compromised.json --out report.md
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .inventory import load_json, from_profile, make_sim
from .hunt import hunt
from .rules import load_rules
from .report import to_markdown

_MARK = {"clean": "\N{LARGE GREEN CIRCLE} CLEAN",
         "suspicious": "\N{LARGE YELLOW CIRCLE} SUSPICIOUS",
         "compromised": "\N{SKULL AND CROSSBONES} COMPROMISED"}
_SEV = {"critical": "CRIT", "high": "HIGH", "medium": "MED ", "low": "LOW ", "info": "INFO"}


def cmd_hunt(args) -> int:
    res = hunt(load_json(args.inventory), rules=load_rules(args.rules or None))
    if args.json:
        print(res.to_json())
        return 0
    print(f"\n  FLOTSAM v{__version__} — Service Worker Cache hunt")
    print("  " + "-" * 56)
    s = res.stats
    print(f"  Scanned: {s['origins']} origins, {s['caches']} caches, "
          f"{s['entries']} entries, {s.get('registrations',0)} SW registrations")
    print(f"  VERDICT: {_MARK.get(res.verdict.value, res.verdict.value)}  "
          f"(risk score {s.get('risk_score',0)}, {s['findings']} findings, "
          f"top={s['top_severity']})")
    planted = sum(1 for t in res.timeline if t.get("recently_planted"))
    if planted:
        print(f"  Timeline: {planted} entr(y/ies) planted after the cache baseline")
    if res.findings:
        print("  Findings:")
        for f in res.findings:
            print(f"    [{_SEV.get(f.severity.value, f.severity.value)}] {f.rule}: "
                  f"{f.origin} / {f.cache}")
            if f.request_url:
                print(f"           {f.request_url}")
            print(f"           {f.detail}")
    print()
    return 0 if res.verdict.value == "clean" else 1


def cmd_simulate(args) -> int:
    path = make_sim(args.out)
    print(f"wrote simulated inventory -> {path}")
    return 0


def cmd_inventory(args) -> int:
    profile = os.path.expanduser(args.profile)
    if args.deep:
        from .extract import deep_extract
        inv = deep_extract(profile)
    else:
        inv = from_profile(profile)
    out = {
        "profile": inv.profile,
        "origins": [{
            "origin": o.origin, "origin_hash": o.origin_hash,
            "caches": [{"name": c.name, "guid": c.guid, "in_index": c.in_index,
                        "mtime": c.mtime,
                        "entries": [{
                            "request_url": e.request_url, "response_mime": e.response_mime,
                            "response_status": e.response_status,
                            "content_encoding": e.content_encoding, "size": e.size,
                            "body_sha256": e.body_sha256, "body_preview": e.body_preview,
                            "body_text": e.body_text, "body_entropy": e.body_entropy,
                            "crc_ok": e.crc_ok, "decoded": e.decoded, "mtime": e.mtime,
                        } for e in c.entries]} for c in o.caches],
        } for o in inv.origins],
        "registrations": [{"origin": r.origin, "scope": r.scope,
                           "script_url": r.script_url,
                           "update_via_cache": r.update_via_cache}
                          for r in inv.registrations],
    }
    text = json.dumps(out, indent=2)
    if args.out:
        open(args.out, "w", encoding="utf-8").write(text)
        print(f"wrote structural inventory -> {args.out}")
    else:
        print(text)
    return 0


def cmd_report(args) -> int:
    res = hunt(load_json(args.inventory))
    md = to_markdown(res, case_id=args.case_id, examiner=args.examiner)
    if args.out:
        open(args.out, "w", encoding="utf-8").write(md)
        print(f"wrote report -> {args.out}")
    else:
        print(md)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="flotsam", description=__doc__.splitlines()[0])
    p.add_argument("--version", action="version", version=f"flotsam {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    h = sub.add_parser("hunt", help="hunt an inventory for Cache-Storage abuse")
    h.add_argument("--inventory", required=True)
    h.add_argument("--rules", default="", help="optional extra YARA-style rules JSON")
    h.add_argument("--json", action="store_true")
    h.set_defaults(func=cmd_hunt)

    s = sub.add_parser("simulate", help="write a synthetic inventory for demo")
    s.add_argument("--out", default="/tmp/flotsam_sim.json")
    s.set_defaults(func=cmd_simulate)

    i = sub.add_parser("inventory", help="inventory a live Chromium profile (--deep parses bodies)")
    i.add_argument("--profile", required=True)
    i.add_argument("--deep", action="store_true",
                   help="parse Simple Cache entry bodies (native reader, zero deps)")
    i.add_argument("--out", default="")
    i.set_defaults(func=cmd_inventory)

    r = sub.add_parser("report", help="Markdown IR report from an inventory")
    r.add_argument("--inventory", required=True)
    r.add_argument("--case-id", default="UNASSIGNED")
    r.add_argument("--examiner", default="")
    r.add_argument("--out", default="")
    r.set_defaults(func=cmd_report)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv if argv is not None else sys.argv[1:])
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
