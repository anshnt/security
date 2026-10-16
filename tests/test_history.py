"""Scan history store: record / list / get / diff / trend / retention / schema versions, the engine hook and the
"changes since previous scan" section of the HTML report."""

from __future__ import annotations

import datetime as dt
import json
import sqlite3
import threading
from pathlib import Path

import pytest

from aegis.core import history as H
from aegis.core.config import Config
from aegis.core.models import Category, CheckResult, CheckStatus, Finding, ScanResult, Severity
from aegis.core.report import is_aegis_report, render_html, render_text, write_report
from aegis.core.scoring import security_score


@pytest.fixture
def cfg():
    return Config()


def finding(n: int, sev: Severity = Severity.HIGH, loc: str = "", rule: str = "AEG-T-%d") -> Finding:
    return Finding(rule % n, f"Title {n}", sev, Category.MALWARE, location=loc or f"/tmp/file{n}.exe", scanner="files",
                   mitre=["T1204"], description="secret description", evidence={"token": "SHOULD-NOT-BE-STORED"})


def scan(findings=(), profile="quick", started="2026-10-01T10:00:00", host="host-a", scanners=("files",), **kw) -> ScanResult:
    r = ScanResult(profile=profile, started=started, finished=started, host={"hostname": host, "admin": True},
                   scanners=list(scanners), stats={"duration_s": 1.5})
    for f in findings:
        r.add(f)
    for k, v in kw.items():
        setattr(r, k, v)
    return r


# --------------------------------------------------------------------------- record / list / get

def test_record_list_and_get_roundtrip(cfg):
    r = scan([finding(1, Severity.CRITICAL), finding(2, Severity.LOW)])
    r.checks.append(CheckResult("C1", "Firewall on", CheckStatus.FAIL, "off"))
    r.errors.append("scanner x: boom")
    sid = H.record(r, cfg)
    assert sid == 1

    rows = H.list_scans(cfg)
    assert len(rows) == 1
    s = rows[0]
    score, grade = security_score(r)
    assert (s.id, s.profile, s.host, s.score, s.grade) == (1, "quick", "host-a", score, grade)
    assert s.counts == r.counts() and s.finding_count == 2 and s.scanners == ["files"]
    assert s.started == "2026-10-01T10:00:00" and s.new_findings is None
    assert s.to_dict()["counts"]["critical"] == 1

    back = H.get_scan(cfg, sid)
    assert isinstance(back, ScanResult)
    assert back.profile == "quick" and back.host["hostname"] == "host-a" and back.scanners == ["files"]
    assert {f.fingerprint for f in back.findings} == {f.fingerprint for f in r.findings}
    got = {f.rule_id: f for f in back.findings}["AEG-T-1"]
    assert (got.severity, got.category, got.title, got.location, got.scanner) == (
        Severity.CRITICAL, Category.MALWARE, "Title 1", "/tmp/file1.exe", "files")
    assert got.mitre == ["T1204"]
    assert back.errors == ["scanner x: boom"]
    assert [(c.check_id, c.status) for c in back.checks] == [("C1", CheckStatus.FAIL)]
    assert security_score(back)[0] == score  # checks are stored, so the score reproduces
    assert back.stats["history_id"] == 1 and back.stats["duration_s"] == 1.5


def test_findings_are_stored_slim_without_evidence(cfg):
    H.record(scan([finding(1)]), cfg)
    raw = sqlite3.connect(str(H.history_path(cfg)))
    dump = "\n".join(str(r) for t in ("scans", "findings") for r in raw.execute(f"SELECT * FROM {t}"))
    raw.close()
    assert "SHOULD-NOT-BE-STORED" not in dump and "secret description" not in dump
    back = H.get_scan(cfg, 1).findings[0]
    assert back.evidence == {} and back.description == ""


def test_get_scan_missing_returns_none(cfg):
    assert H.get_scan(cfg, 999) is None
    assert H.get_summary(cfg, 999) is None


def test_list_scans_newest_first_limit_and_filters(cfg):
    for i, (prof, host) in enumerate([("quick", "a"), ("full", "a"), ("quick", "b"), ("quick", "a")]):
        H.record(scan(profile=prof, host=host, started=f"2026-10-0{i + 1}T10:00:00"), cfg)
    assert [s.id for s in H.list_scans(cfg)] == [4, 3, 2, 1]
    assert [s.id for s in H.list_scans(cfg, limit=2)] == [4, 3]
    assert [s.id for s in H.list_scans(cfg, profile="quick")] == [4, 3, 1]
    assert [s.id for s in H.list_scans(cfg, profile="quick", host="a")] == [4, 1]


def test_record_never_raises(cfg, monkeypatch):
    def boom(config):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(H, "_connect", boom)
    assert H.record(scan([finding(1)]), cfg) is None
    r = scan([finding(1)])
    assert H.record_and_compare(r, cfg) is None  # and the scan result is left usable
    assert "new_findings" not in r.stats


def test_concurrent_recording(cfg):
    errors = []

    def worker(k):
        try:
            for i in range(5):
                assert H.record(scan([finding(k * 10 + i)], started=f"2026-10-01T10:0{k}:0{i}"), cfg) is not None
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(k,)) for k in range(4)]
    [t.start() for t in threads]
    [t.join(60) for t in threads]
    assert not errors
    assert H.scan_count(cfg) == 20


# --------------------------------------------------------------------------- diff

def test_diff_new_resolved_persisting_and_score_change():
    old = scan([finding(1), finding(2, Severity.MEDIUM), finding(3, Severity.LOW)])
    new = scan([finding(2, Severity.MEDIUM), finding(3, Severity.LOW), finding(4, Severity.CRITICAL)])
    d = H.diff(old, new)
    assert [f.rule_id for f in d["new"]] == ["AEG-T-4"]
    assert [f.rule_id for f in d["resolved"]] == ["AEG-T-1"]
    assert sorted(f.rule_id for f in d["persisting"]) == ["AEG-T-2", "AEG-T-3"]
    assert d["escalated"] == []
    assert d["score_change"] == security_score(new)[0] - security_score(old)[0] < 0
    assert set(d) == {"new", "resolved", "persisting", "escalated", "score_change"}


def test_diff_orders_by_severity_and_flags_escalation():
    old = scan([finding(1, Severity.MEDIUM)])
    new = scan([finding(1, Severity.HIGH), finding(2, Severity.LOW), finding(3, Severity.CRITICAL)])
    d = H.diff(old, new)
    assert [f.rule_id for f in d["new"]] == ["AEG-T-3", "AEG-T-2"]
    assert [f.rule_id for f in d["escalated"]] == ["AEG-T-1"]
    assert d["persisting"][0].severity == Severity.HIGH  # the *new* scan's finding


def test_diff_ignores_volatile_pid_suffix():
    old = scan([finding(1, loc=r"C:\Users\x\AppData\evil.exe (pid 4242)")])
    new = scan([finding(1, loc=r"C:\Users\x\AppData\evil.exe (pid 9)")])
    assert old.findings[0].fingerprint != new.findings[0].fingerprint  # fingerprints differ ...
    d = H.diff(old, new)
    assert d["new"] == [] and d["resolved"] == [] and len(d["persisting"]) == 1  # ... the history key does not
    assert H.match_key(finding(1, loc="x [PID: 12, 13]")) == H.match_key(finding(1, loc="x"))


def test_diff_identical_scans_and_empty():
    r = scan([finding(1)])
    d = H.diff(r, scan([finding(1)]))
    assert d["new"] == d["resolved"] == [] and d["score_change"] == 0
    assert H.diff(scan(), scan())["persisting"] == []


# --------------------------------------------------------------------------- comparable scans / trend

def test_latest_comparable_matches_profile_and_respects_before(cfg):
    H.record(scan([finding(1)], profile="quick", started="2026-10-01T10:00:00"), cfg)  # 1
    H.record(scan([finding(2)], profile="full", started="2026-10-02T10:00:00"), cfg)  # 2
    H.record(scan([finding(3)], profile="quick", started="2026-10-03T10:00:00"), cfg)  # 3

    prev = H.latest_comparable(cfg, "quick")
    assert prev is not None and prev.findings[0].rule_id == "AEG-T-3" and prev.stats["history_id"] == 3
    assert H.latest_comparable(cfg, "quick", before=3).findings[0].rule_id == "AEG-T-1"  # by scan id
    assert H.latest_comparable(cfg, "quick", before="2026-10-03T10:00:00").stats["history_id"] == 1  # by timestamp
    assert H.latest_comparable(cfg, "quick", before=scan(started="2026-10-03T10:00:00")).stats["history_id"] == 1
    assert H.latest_comparable(cfg, "quick", before=1) is None
    assert H.latest_comparable(cfg, "audit") is None
    assert H.latest_comparable(cfg, "full").stats["history_id"] == 2


def test_latest_comparable_host_and_custom_scanner_set(cfg):
    H.record(scan(profile="quick", host="a", started="2026-10-01T10:00:00"), cfg)
    H.record(scan(profile="quick", host="b", started="2026-10-02T10:00:00"), cfg)
    assert H.latest_comparable(cfg, "quick", host="a").stats["history_id"] == 1
    assert H.latest_comparable(cfg, "quick").stats["history_id"] == 2
    H.record(scan(profile="custom", scanners=("files",), started="2026-10-03T10:00:00"), cfg)
    H.record(scan(profile="custom", scanners=("files", "secrets"), started="2026-10-04T10:00:00"), cfg)
    assert H.latest_comparable(cfg, "custom", scanners=["files"]).stats["history_id"] == 3
    assert H.latest_comparable(cfg, "custom", scanners=["secrets", "files"]).stats["history_id"] == 4
    assert H.latest_comparable(cfg, "custom", scanners=["eventlog"]) is None


def test_trend_and_recent_scores(cfg):
    now = dt.datetime(2026, 10, 16, 12, 0, 0)
    plan = [("quick", 200, 0), ("quick", 40, 2), ("full", 10, 4), ("quick", 3, 1), ("quick", 1, 3)]  # (profile, days ago, highs)
    for prof, days, highs in plan:
        started = (now - dt.timedelta(days=days)).isoformat(timespec="seconds")
        H.record(scan([finding(i) for i in range(highs)], profile=prof, started=started), cfg)
    t = H.trend(cfg, days=90, now=now)
    assert [d for d, _s in t] == [(now - dt.timedelta(days=x)).strftime("%Y-%m-%d") for x in (40, 10, 3, 1)]
    assert all(isinstance(s, int) for _d, s in t)
    assert [s for _d, s in H.trend(cfg, profile="quick", days=90, now=now)] == [76, 88, 64]  # 2, 1, 3 high findings
    assert H.trend(cfg, days=5, now=now) == [t[2], t[3]]
    assert len(H.trend(cfg, days=365, now=now)) == 5

    assert [sc for _d, sc in H.recent_scores(cfg, "quick", limit=3)] == [76, 88, 64]  # last 3 quick scans, oldest first
    assert [sc for _d, sc in H.recent_scores(cfg, "quick", limit=2)] == [88, 64]
    assert [sc for _d, sc in H.recent_scores(cfg, limit=20)] == [100, 76, 55, 88, 64]  # every profile, insertion order


# --------------------------------------------------------------------------- retention / schema

def test_retention_keeps_newest_and_removes_orphan_findings(cfg, monkeypatch):
    monkeypatch.setattr(H, "MAX_SCANS", 5)
    for i in range(8):
        H.record(scan([finding(i)], started=f"2026-10-0{i + 1}T10:00:00"), cfg)
    assert [s.id for s in H.list_scans(cfg, limit=50)] == [8, 7, 6, 5, 4]
    raw = sqlite3.connect(str(H.history_path(cfg)))
    assert raw.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 5
    assert raw.execute("SELECT COUNT(*) FROM findings WHERE scan_id NOT IN (SELECT id FROM scans)").fetchone()[0] == 0
    raw.close()
    assert H.get_scan(cfg, 1) is None and H.get_scan(cfg, 8) is not None


def test_retention_default_is_500_and_explicit_keep(cfg):
    assert H.MAX_SCANS == 500
    for i in range(6):
        H.record(scan(started=f"2026-10-0{i + 1}T10:00:00"), cfg, keep=3)
    assert H.scan_count(cfg) == 3


def test_schema_version_table_on_fresh_db(cfg):
    assert H.schema_version(cfg) == H.target_version() == 1
    raw = sqlite3.connect(str(H.history_path(cfg)))
    assert raw.execute("SELECT version FROM schema_version").fetchall() == [(1,)]
    tables = {r[0] for r in raw.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"scans", "findings", "schema_version"} <= tables
    raw.close()


def test_migration_to_a_newer_schema_preserves_data(cfg, monkeypatch):
    H.record(scan([finding(1)]), cfg)
    migrations = dict(H._MIGRATIONS)
    migrations[2] = ("ALTER TABLE scans ADD COLUMN note TEXT NOT NULL DEFAULT 'migrated'",
                     "CREATE INDEX idx_scans_host ON scans(host)")
    monkeypatch.setattr(H, "_MIGRATIONS", migrations)
    assert H.target_version() == 2
    assert H.schema_version(cfg) == 2  # opening upgrades
    assert H.schema_version(cfg) == 2  # and re-opening does not re-apply
    raw = sqlite3.connect(str(H.history_path(cfg)))
    assert raw.execute("SELECT version FROM schema_version ORDER BY version").fetchall() == [(1,), (2,)]
    assert raw.execute("SELECT note FROM scans").fetchall() == [("migrated",)]
    raw.close()
    assert len(H.get_scan(cfg, 1).findings) == 1  # old data still readable
    assert H.record(scan([finding(2)]), cfg) == 2


def test_failed_migration_rolls_back(cfg, monkeypatch):
    H.record(scan(), cfg)
    bad = dict(H._MIGRATIONS)
    bad[2] = ("ALTER TABLE scans ADD COLUMN ok_col TEXT", "THIS IS NOT SQL")
    monkeypatch.setattr(H, "_MIGRATIONS", bad)
    with pytest.raises(sqlite3.Error):
        H.schema_version(cfg)
    good = dict(H._MIGRATIONS)
    good[2] = ("ALTER TABLE scans ADD COLUMN ok_col TEXT",)
    monkeypatch.setattr(H, "_MIGRATIONS", good)
    assert H.schema_version(cfg) == 2  # nothing half-applied: the same migration now succeeds


def test_database_from_a_newer_aegis_is_used_as_is(cfg):
    H.record(scan(), cfg)
    raw = sqlite3.connect(str(H.history_path(cfg)))
    raw.execute("INSERT INTO schema_version(version, applied) VALUES (99, 'future')")
    raw.commit()
    raw.close()
    assert H.schema_version(cfg) == 99
    assert H.record(scan([finding(1)]), cfg) == 2 and H.scan_count(cfg) == 2


def test_corrupt_database_is_moved_aside(cfg):
    path = H.history_path(cfg)
    path.write_bytes(b"this is definitely not an sqlite database" * 20)
    assert H.record(scan([finding(1)]), cfg) == 1
    assert H.scan_count(cfg) == 1
    assert list(path.parent.glob("history.sqlite.corrupt-*"))


# --------------------------------------------------------------------------- engine hook

def test_record_and_compare_sets_stats_and_history_block(cfg):
    first = scan([finding(1), finding(2)], started="2026-10-01T10:00:00")
    assert H.record_and_compare(first, cfg) is None  # no baseline yet
    assert "new_findings" not in first.stats and first.stats["history"]["scan_id"] == 1
    assert "previous" not in first.stats["history"] and first.stats["history"]["trend"][0][0] == "2026-10-01T10:00:00"

    second = scan([finding(2), finding(3, Severity.CRITICAL)], started="2026-10-02T10:00:00")
    d = H.record_and_compare(second, cfg)
    assert [f.rule_id for f in d["new"]] == ["AEG-T-3"]
    assert (second.stats["new_findings"], second.stats["resolved_findings"]) == (1, 1)
    assert second.stats["score_change"] == d["score_change"] < 0
    h = second.stats["history"]
    assert h["previous"]["id"] == 1 and h["previous"]["started"] == "2026-10-01T10:00:00" and h["previous"]["grade"]
    assert [x["rule_id"] for x in h["new"]] == ["AEG-T-3"] and [x["rule_id"] for x in h["resolved"]] == ["AEG-T-1"]
    assert set(h["new"][0]) == {"fingerprint", "rule_id", "severity", "category", "title", "location"}
    assert len(h["trend"]) == 2
    json.dumps(second.stats, default=str)  # stays JSON-serialisable

    s = H.list_scans(cfg)[0]
    assert (s.new_findings, s.resolved_findings, s.score_change) == (1, 1, d["score_change"])
    assert "history" not in json.loads(sqlite3.connect(str(H.history_path(cfg))).execute("SELECT stats_json FROM scans WHERE id=2").fetchone()[0])


def test_cancelled_scans_are_not_recorded(cfg):
    r = scan([finding(1)], errors=["scan cancelled by user"])
    assert H.record_and_compare(r, cfg) is None
    assert H.scan_count(cfg) == 0 and "history" not in r.stats


def test_custom_profile_compares_only_identical_scanner_sets(cfg):
    H.record_and_compare(scan([finding(1)], profile="custom", scanners=("files",), started="2026-10-01T10:00:00"), cfg)
    other = scan([finding(1)], profile="custom", scanners=("secrets",), started="2026-10-02T10:00:00")
    H.record_and_compare(other, cfg)
    assert "new_findings" not in other.stats
    same = scan([finding(1), finding(2)], profile="custom", scanners=("files",), started="2026-10-03T10:00:00")
    H.record_and_compare(same, cfg)
    assert same.stats["new_findings"] == 1 and same.stats["history"]["previous"]["id"] == 1


def test_dashboard_data_and_compare_latest(cfg):
    assert H.dashboard_data(cfg)["latest"] is None and H.dashboard_data(cfg)["points"] == []
    assert H.compare_latest(cfg) is None
    H.record_and_compare(scan([finding(1)], started="2026-10-01T10:00:00"), cfg)
    data = H.dashboard_data(cfg)
    assert data["new"] is None and len(data["points"]) == 1 and data["profile"] == "quick"
    assert H.compare_latest(cfg) is None  # only one scan so far
    H.record_and_compare(scan([finding(1), finding(2), finding(3)], started="2026-10-02T10:00:00"), cfg)
    H.record_and_compare(scan([finding(4)], profile="full", started="2026-10-03T10:00:00"), cfg)
    data = H.dashboard_data(cfg)  # newest scan is a first "full" scan: no baseline for it
    assert data["profile"] == "full" and data["new"] is None
    cmp_ = H.compare_latest(cfg, profile="quick")
    assert cmp_["old"].id == 1 and cmp_["new"].id == 2 and len(cmp_["diff"]["new"]) == 2
    text = H.render_diff_text(cmp_["diff"])
    assert "New: 2" in text and "Title 2" in text and "Score change:" in text


def test_scan_engine_records_history_and_reports_changes(tmp_path, eicar_bytes):
    from aegis.core.engine import ScanEngine, last_scan

    root = tmp_path / "scanme"
    root.mkdir()
    (root / "a.com").write_bytes(eicar_bytes)
    eng = ScanEngine()
    eng.config.use_windows_defender_engine = False

    r1 = eng.scan("custom", ["files"], paths=[root])
    assert H.scan_count(eng.config) == 1 and "new_findings" not in r1.stats

    r2 = eng.scan("custom", ["files"], paths=[root])
    assert (r2.stats["new_findings"], r2.stats["resolved_findings"]) == (0, 0)

    (root / "b.com").write_bytes(eicar_bytes + b" ")
    r3 = eng.scan("custom", ["files"], paths=[root])
    new = r3.stats["history"]["new"]  # 1 finding, or 2 when yara-python adds its own EICAR rule match
    assert r3.stats["new_findings"] == len(new) >= 1 and all(n["location"].endswith("b.com") for n in new)
    assert any(n["severity"] == "critical" for n in new)

    (root / "a.com").unlink()
    r4 = eng.scan("custom", ["files"], paths=[root])
    assert (r4.stats["new_findings"], r4.stats["resolved_findings"]) == (0, 1)

    assert [s.new_findings for s in H.list_scans(eng.config)] == [0, len(new), 0, None]
    saved = last_scan(eng.config)
    assert saved.stats["new_findings"] == 0 and saved.stats["history"]["previous"]["id"] == 3  # persisted in last_scan.json


def test_scan_engine_survives_a_broken_history(tmp_path, monkeypatch, eicar_bytes):
    from aegis.core.engine import ScanEngine

    (tmp_path / "a.com").write_bytes(eicar_bytes)
    monkeypatch.setattr(H, "record_and_compare", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("history is down")))
    eng = ScanEngine()
    eng.config.use_windows_defender_engine = False
    res = eng.scan("custom", ["files"], paths=[tmp_path])
    assert res.findings and (eng.config.home / "last_scan.json").exists()


# --------------------------------------------------------------------------- report: changes + sparkline

def _two_scans(cfg):
    a = scan([finding(1), finding(2, Severity.MEDIUM)], started="2026-10-01T10:00:00")
    H.record_and_compare(a, cfg)
    b = scan([finding(2, Severity.MEDIUM), finding(3, Severity.CRITICAL, loc="C:\\x\\<b>evil</b>.exe")], started="2026-10-02T10:00:00")
    H.record_and_compare(b, cfg)
    return b


def test_html_report_has_changes_section_and_sparkline(cfg):
    b = _two_scans(cfg)
    out = render_html(b)
    assert 'id="changes"' in out and "Changes since previous scan" in out
    assert "<svg" in out and "<polyline" in out and "Score trend over the last 2 scans" in out
    assert "Title 3" in out and "Title 1" in out  # new and resolved lists
    assert "&lt;b&gt;evil&lt;/b&gt;" in out and "<b>evil</b>" not in out  # escaped
    assert is_aegis_report(out.encode(), "html")  # still recognised (and trusted) as Aegis' own report


def test_html_report_without_history_has_no_section():
    out = render_html(scan([finding(1)]))
    assert 'id="changes"' not in out and "<svg" not in out


def test_html_report_history_parameter_overrides_stats(cfg):
    r = scan([finding(1)])
    hist = {"previous": {"started": "2026-09-01T00:00:00", "profile": "quick", "score": 90, "grade": "A"},
            "new": [{"severity": "high", "title": "Injected <script>alert(1)</script>", "location": "x"}], "resolved": [],
            "score_change": -12, "trend": [["2026-09-01", 90], ["2026-09-02", 78], ["2026-09-03", 66]]}
    out = render_html(r, history=hist)
    assert "Injected &lt;script&gt;" in out and "<script>alert(1)" not in out
    assert out.lower().count("<script") == 1  # only the report's own filter script
    assert "-12" in out and is_aegis_report(out.encode(), "html")


def test_html_report_survives_malformed_history():
    for bad in ({"previous": "nope", "trend": "nope"}, {"previous": {}, "new": "x", "resolved": [1, None], "trend": [[1]]},
                {"trend": [["d", "not a number"], ["d", 50]]}, "garbage", 5):
        out = render_html(scan([finding(1)]), history=bad)  # type: ignore[arg-type]
        assert "<html" in out


def test_trend_only_section_and_text_report(cfg):
    r = scan([finding(1)])
    r.stats["history"] = {"trend": [["2026-10-01", 80], ["2026-10-02", 85]]}
    out = render_html(r)
    assert "<svg" in out and "Compared with" not in out
    b = _two_scans(cfg)
    assert "Since the previous quick scan: 1 new, 1 resolved" in render_text(b)


def test_write_report_html_uses_stored_history(cfg, tmp_path):
    b = _two_scans(cfg)
    p = write_report(b, tmp_path / "r.html")
    assert "Changes since previous scan" in Path(p).read_text(encoding="utf-8")
    j = json.loads(write_report(b, tmp_path / "r.json").read_text(encoding="utf-8"))
    assert j["stats"]["new_findings"] == 1 and is_aegis_report(Path(tmp_path / "r.json").read_bytes(), "json")
