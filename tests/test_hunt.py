"""Tests for the FLOTSAM hunting engine, rules, and scoring."""
import sys, pathlib, tempfile, os, json
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from flotsam.inventory import load_json, make_sim
from flotsam.hunt import hunt
from flotsam.rules import default_rules, load_rules
from flotsam.models import Verdict, Severity
from flotsam.report import to_markdown

SAMPLES = pathlib.Path(__file__).resolve().parents[1] / "samples"


def test_clean_is_clean():
    res = hunt(load_json(str(SAMPLES / "clean.json")))
    assert res.verdict is Verdict.CLEAN, res.stats
    assert all(f.severity is Severity.INFO for f in res.findings), \
        [(f.rule, f.severity.value) for f in res.findings]


def test_compromised_is_flagged():
    res = hunt(load_json(str(SAMPLES / "compromised.json")))
    assert res.verdict is Verdict.COMPROMISED, res.stats
    rules = {f.rule for f in res.findings}
    assert "orphaned-cache" in rules, rules
    assert "cross-origin-entry" in rules, rules
    # payload signatures now have specific names
    assert {"dynamic-eval", "base64-decode", "live-channel"} & rules, rules


def test_risk_score_accumulates():
    res = hunt(load_json(str(SAMPLES / "compromised.json")))
    assert res.stats["risk_score"] >= 10, res.stats


def test_registration_correlation():
    res = hunt(load_json(str(SAMPLES / "compromised.json")))
    rules = {f.rule for f in res.findings}
    # bank.example/main.js is both cached and a registered worker script
    assert "registered-script-cached" in rules, rules


def test_custom_rule_loads():
    with tempfile.TemporaryDirectory() as d:
        rp = os.path.join(d, "rules.json")
        json.dump([{"name": "my-ioc", "pattern": "SECRET_MARKER",
                    "severity": "critical", "weight": 10,
                    "description": "test IOC"}], open(rp, "w"))
        rules = load_rules(rp)
        assert any(r.name == "my-ioc" for r in rules)
        assert len(rules) == len(default_rules()) + 1


def test_simulate_roundtrip():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "inv.json")
        make_sim(p)
        res = hunt(load_json(p))
        assert res.verdict is Verdict.COMPROMISED


def test_report_renders():
    res = hunt(load_json(str(SAMPLES / "compromised.json")))
    md = to_markdown(res, case_id="IR-7", examiner="Analyst")
    for m in ["# Service Worker Cache Storage", "IR-7", "COMPROMISED",
              "## Remediation", "risk score"]:
        assert m in md, m


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn(); print(f"ok  {name}")
    print("all flotsam tests passed")
