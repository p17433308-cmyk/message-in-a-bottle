"""Tests for the FLOTSAM hunting engine."""
import sys, pathlib, json, tempfile, os
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from flotsam.inventory import load_json, make_sim
from flotsam.hunt import hunt
from flotsam.models import Verdict, Severity
from flotsam.report import to_markdown

SAMPLES = pathlib.Path(__file__).resolve().parents[1] / "samples"


def test_clean_is_clean():
    res = hunt(load_json(str(SAMPLES / "clean.json")))
    assert res.verdict is Verdict.CLEAN, res.stats
    # Only INFO context findings allowed on a clean profile.
    assert all(f.severity is Severity.INFO for f in res.findings), \
        [f.rule for f in res.findings]


def test_compromised_is_flagged():
    res = hunt(load_json(str(SAMPLES / "compromised.json")))
    assert res.verdict is Verdict.COMPROMISED, res.stats
    rules = {f.rule for f in res.findings}
    for expected in {"orphaned-cache", "cross-origin-entry", "payload-signature"}:
        assert expected in rules, rules


def test_payload_signatures_fire():
    res = hunt(load_json(str(SAMPLES / "compromised.json")))
    sigs = [f for f in res.findings if f.rule == "payload-signature"]
    assert sigs, "expected atob/eval/WebSocket to trigger"


def test_simulate_roundtrip():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "inv.json")
        make_sim(p)
        res = hunt(load_json(p))
        assert res.verdict is Verdict.COMPROMISED


def test_report_renders():
    res = hunt(load_json(str(SAMPLES / "compromised.json")))
    md = to_markdown(res, case_id="IR-7", examiner="Analyst")
    for m in ["# Service Worker Cache Storage", "IR-7", "COMPROMISED", "## Remediation"]:
        assert m in md, m


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn(); print(f"ok  {name}")
    print("all flotsam tests passed")
