"""Unit tests for aegis.scanners.software: version compare, PUP matching, vulnerable-software rules, inventory."""

import datetime as dt
import json

import pytest

from aegis.core.config import Config
from aegis.core.models import CheckResult, CheckStatus, Finding, Severity
from aegis.core.signatures import SignatureDB
from aegis.scanners import software as sw
from aegis.scanners.base import ScanContext

TODAY = dt.date(2026, 10, 15)


def entry(name, version="", **kw):
    return sw._entry(name, version, **kw)


@pytest.fixture(scope="module")
def rules():
    return sw.load_vuln_rules()


def findings_for(rules, name, version="", platform="windows", pups=()):
    return list(sw.analyse_inventory([entry(name, version)], pups, rules, TODAY, platform))


# ---------------------------------------------------------------- versions
@pytest.mark.parametrize("text,expected", [
    ("24.09", (24, 9)), ("8.0.4010.7", (8, 0, 4010, 7)), ("7.12 (64-bit)", (7, 12)), ("1.1.1w", (1, 1, 1)),
    ("v3.0.21", (3, 0, 21)), ("release 0.78", (0, 78)), ("128.0.1 ESR", (128, 0, 1)), ("", None), (None, None),
    ("no digits", None), ("5.17.11 (31580)", (5, 17, 11)),
])
def test_parse_version(text, expected):
    assert sw.parse_version(text) == expected


@pytest.mark.parametrize("a,b,expected", [
    ("7.12", "7.13", -1), ("7.13", "7.13", 0), ("7.13.0", "7.13", 0), ("7.13.1", "7.13", 1),
    ("24.08", "24.09", -1), ("24.9", "24.09", 0), ("8.0.4010.7", "8.0.4010.7", 0), ("9", "10", -1),
    ("3.0.20", "3.0.21", -1), ("1.10", "1.9", 1), ("", "1.0", None), ("abc", "1", None),
])
def test_compare_versions(a, b, expected):
    assert sw.compare_versions(a, b) == expected


# ---------------------------------------------------------------- PUP
def test_pup_matching_whole_word():
    m = sw.compile_pup_matcher(["onelaunch", "driver booster", "conduit", "snap.do"])
    assert sw.match_pup("OneLaunch", m) == "onelaunch"
    assert sw.match_pup("IObit Driver Booster 11", m) == "driver booster"
    assert sw.match_pup("Search Protect by Conduit", m) == "conduit"
    assert sw.match_pup("Snap.do", m) == "snap.do"
    assert sw.match_pup("Microsoft Visual C++ 2015 Redistributable", m) is None
    assert sw.match_pup("Conduits Pro", m) is None  # whole-word only
    assert sw.match_pup("anything", None) is None


def test_pup_finding_has_uninstall_string_but_no_remediation():
    e = entry("OneLaunch 5.1", "5.1", publisher="OneLaunch Tech", uninstall='"C:\\x\\unins000.exe" /SILENT')
    f = next(sw.analyse_inventory([e], ["onelaunch"], {"rules": []}, TODAY, "windows"))
    assert f.rule_id == "AEG-SW-PUP" and f.severity == Severity.MEDIUM and f.category == "pup"
    assert f.remediation is None
    assert f.evidence["uninstall_string"] == '"C:\\x\\unins000.exe" /SILENT'
    assert f.recommendation and f.location == "software:OneLaunch 5.1"
    json.dumps(f.to_dict())


def test_pup_uses_bundled_signatures(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path))
    sigs = SignatureDB(Config())
    assert sigs.pup_names
    m = sw.compile_pup_matcher(sigs.pup_names)
    assert sw.match_pup("OneLaunch", m)


# ---------------------------------------------------------------- vulnerable software
def test_rules_file_is_valid(rules):
    ids = [r["id"] for r in rules["rules"]]
    assert len(ids) == len(set(ids)) and len(ids) >= 20
    raw = json.loads(sw.VULN_RULES_FILE.read_text())
    assert len(raw["rules"]) == len(rules["rules"])  # every regex compiled
    for r in rules["rules"]:
        assert r["advice"] and ("max_vulnerable_version" in r or "fixed_version" in r or "exact_versions" in r)


@pytest.mark.parametrize("name,version,rule_id,sev", [
    ("WinRAR 7.12 (64-bit)", "7.12.0", "AEG-SW-VULN", Severity.HIGH),
    ("WinRAR 7.13 (64-bit)", "7.13.0", None, None),
    ("WinRAR 6.24", "6.24", "AEG-SW-VULN", Severity.HIGH),
    ("7-Zip 24.08 (x64)", "24.08", "AEG-SW-VULN", Severity.MEDIUM),
    ("7-Zip 24.09 (x64)", "24.09", None, None),
    ("7-Zip 23.01", "23.01", "AEG-SW-VULN", Severity.MEDIUM),
    ("Adobe Flash Player 32 NPAPI", "32.0.0.465", "AEG-SW-EOL", Severity.HIGH),
    ("Microsoft Silverlight", "5.1.50918.0", "AEG-SW-EOL", Severity.MEDIUM),
    ("QuickTime 7", "7.79.80.95", "AEG-SW-EOL", Severity.HIGH),
    ("Java(TM) 6 Update 45", "6.0.450", "AEG-SW-EOL", Severity.HIGH),
    ("Java 7 Update 80", "7.0.800", "AEG-SW-EOL", Severity.HIGH),
    ("Java SE Development Kit 7 Update 79 (64-bit)", "", "AEG-SW-EOL", Severity.HIGH),
    ("Java 8 Update 361 (64-bit)", "8.0.3610.9", "AEG-SW-VULN", Severity.MEDIUM),
    ("Java 8 Update 401 (64-bit)", "8.0.4010.7", None, None),
    ("Java 8 Update 471", "8.0.4710.9", None, None),
    ("Java SE Development Kit 17.0.1 (64-bit)", "17.0.1.0", None, None),
    ("Eclipse Temurin JDK with Hotspot 21.0.2+13 (x64)", "21.0.2.13", None, None),
    ("Python 2.7.18", "2.7.18150", "AEG-SW-EOL", Severity.MEDIUM),
    ("Python 3.12.4 (64-bit)", "3.12.4150.0", None, None),
    ("PuTTY release 0.78 (64-bit)", "0.78.0.0", "AEG-SW-VULN", Severity.MEDIUM),
    ("PuTTY release 0.81 (64-bit)", "0.81.0.0", None, None),
    ("VLC media player", "3.0.20", "AEG-SW-VULN", Severity.MEDIUM),
    ("VLC media player", "3.0.21", None, None),
    ("Notepad++ (64-bit x64)", "8.8.1", "AEG-SW-VULN", Severity.MEDIUM),
    ("Notepad++ (64-bit x64)", "8.8.2", None, None),
    ("Adobe Reader XI (11.0.23)", "11.0.23", "AEG-SW-EOL", Severity.HIGH),
    ("Adobe Reader 9.5.5 - English", "9.5.5", "AEG-SW-EOL", Severity.HIGH),
    ("Adobe Acrobat Reader DC", "25.001.20531", None, None),
    ("Microsoft Office Professional Plus 2010", "14.0.7015.1000", "AEG-SW-EOL", Severity.HIGH),
    ("Microsoft Office Standard 2013", "15.0.4569.1506", "AEG-SW-EOL", Severity.HIGH),
    ("Microsoft Office Professional Plus 2016", "16.0.4266.1001", "AEG-SW-EOL", Severity.MEDIUM),
    ("Microsoft Office Professional 2019 - en-us", "16.0.10417.20083", "AEG-SW-EOL", Severity.MEDIUM),
    ("Microsoft Office LTSC Professional Plus 2021 - en-us", "16.0.14332.20000", "AEG-SW-EOL", Severity.MEDIUM),
    ("Microsoft Office Proof (English) 2010", "14.0.4763.1000", None, None),
    ("Microsoft 365 Apps for enterprise - en-us", "16.0.18227.20162", None, None),
    ("Zoom Workplace (64-bit)", "5.17.11 (31580)", "AEG-SW-VULN", Severity.MEDIUM),
    ("Zoom Workplace (64-bit)", "6.2.5 (47003)", None, None),
    ("Zoom Outlook Plugin", "5.0", None, None),
    ("Google Chrome", "129.0.6668.90", "AEG-SW-VULN", Severity.MEDIUM),
    ("Google Chrome", "141.0.7390.55", None, None),
    ("Microsoft Edge", "128.0.2739.42", "AEG-SW-VULN", Severity.MEDIUM),
    ("Microsoft Edge WebView2 Runtime", "128.0.0.1", None, None),
    ("Mozilla Firefox (x64 en-US)", "115.5.0", "AEG-SW-VULN", Severity.MEDIUM),
    ("Mozilla Firefox (x64 en-US)", "128.0", None, None),
    ("Mozilla Maintenance Service", "100.0", None, None),
    ("OpenSSL 1.1.1w Light (64-bit)", "1.1.1w", "AEG-SW-EOL", Severity.MEDIUM),
    ("OpenSSL 3.2.1 (64-bit)", "3.2.1", None, None),
    ("TeamViewer", "15.5.3", "AEG-SW-VULN", Severity.MEDIUM),
    ("TeamViewer", "15.58.4", None, None),
    ("CCleaner", "5.33.6162", "AEG-SW-VULN", Severity.HIGH),
    ("CCleaner", "6.20.11000", None, None),
    ("Internet Explorer 11", "11.0", "AEG-SW-EOL", Severity.LOW),
])
def test_vulnerable_software_rules(rules, name, version, rule_id, sev):
    got = [f for f in findings_for(rules, name, version)
           if f.rule_id in ("AEG-SW-VULN", "AEG-SW-EOL")]
    if rule_id is None:
        assert not got, [g.title for g in got]
        return
    assert len(got) == 1, [g.title for g in got]
    assert got[0].rule_id == rule_id and got[0].severity == sev and got[0].category == "vulnerability"
    assert got[0].recommendation


def test_rule_eol_date_is_respected(rules):
    old = dt.date(2026, 10, 1)
    e = entry("Microsoft Office LTSC Professional Plus 2021", "16.0")
    assert not [f for f in sw.analyse_inventory([e], [], rules, old, "windows") if f.rule_id == "AEG-SW-EOL"]
    assert [f for f in sw.analyse_inventory([e], [], rules, TODAY, "windows") if f.rule_id == "AEG-SW-EOL"]


def test_version_rules_skip_linux_distro_packages(rules):
    assert not findings_for(rules, "openssl", "1.1.1f-1ubuntu2.19", platform="linux")
    assert not findings_for(rules, "vlc", "3.0.9", platform="linux")


def test_vuln_finding_content(rules):
    f = findings_for(rules, "WinRAR 7.12 (64-bit)", "7.12.0")[0]
    assert "CVE-2025-8088" in f.evidence["cve"] and f.evidence["fixed_version"] == "7.13"
    assert f.remediation is None
    assert f.mitre
    json.dumps(f.to_dict())


def test_bad_rule_is_dropped(tmp_path):
    p = tmp_path / "r.json"
    p.write_text(json.dumps({"rules": [{"id": "bad", "name_regex": "(", "max_vulnerable_version": "any", "severity": "low"},
                                       {"id": "ok", "name_regex": "x", "max_vulnerable_version": "any", "severity": "low"}]}))
    loaded = sw.load_vuln_rules(p)
    assert [r["id"] for r in loaded["rules"]] == ["ok"]
    assert sw.load_vuln_rules(tmp_path / "missing.json") == {"rules": [], "remote_access_software": []}


# ---------------------------------------------------------------- remote access inventory
def test_remote_access_inventory_is_info_only(rules):
    fs = findings_for(rules, "AnyDesk", "9.0.1")
    r = [f for f in fs if f.rule_id == "AEG-SW-REMOTE"]
    assert len(r) == 1 and r[0].severity == Severity.INFO
    assert not findings_for(rules, "Notepad", "1.0")


# ---------------------------------------------------------------- inventory parsing
def test_uninstall_entry_parsing():
    good = sw.entry_from_uninstall_values({"DisplayName": "WinRAR 7.12", "DisplayVersion": "7.12.0", "Publisher": "win.rar GmbH",
                                           "InstallLocation": "C:\\Program Files\\WinRAR", "UninstallString": "u.exe",
                                           "InstallDate": "20250101"}, "HKLM")
    assert good["name"] == "WinRAR 7.12" and good["publisher"] == "win.rar GmbH" and good["install_date"] == "20250101"
    assert sw.entry_from_uninstall_values({"DisplayName": "Foo", "SystemComponent": 1}) is None
    assert sw.entry_from_uninstall_values({"DisplayName": "Security Update for Windows (KB5000000)"}) is None
    assert sw.entry_from_uninstall_values({"DisplayName": "Hotfix X", "ReleaseType": "Hotfix"}) is None
    assert sw.entry_from_uninstall_values({"DisplayName": "Sub", "ParentKeyName": "Parent"}) is None
    assert sw.entry_from_uninstall_values({"UninstallString": "x"}) is None
    q = sw.entry_from_uninstall_values({"DisplayName": "App", "UninstallString": "u", "QuietUninstallString": "q /S"})
    assert q["uninstall_string"] == "q /S"


def test_windows_inventory_dedup(monkeypatch):
    def fake_walk(hive, key, view64=True):
        yield key + "\\A", {"DisplayName": "App One", "DisplayVersion": "1.0"}
        yield key + "\\B", {"DisplayName": "Hidden", "SystemComponent": 1}
        if hive == "HKLM":
            yield key + "\\C", {"DisplayName": "App One", "DisplayVersion": "1.0"}  # same in 32-bit view

    monkeypatch.setattr(sw, "reg_walk_values", fake_walk)
    inv = sw.collect_windows_inventory()
    assert [e["name"] for e in inv] == ["App One"]


def test_macos_inventory(tmp_path):
    import plistlib

    app = tmp_path / "Foo.app" / "Contents"
    app.mkdir(parents=True)
    (app / "Info.plist").write_bytes(plistlib.dumps({"CFBundleName": "Foo", "CFBundleShortVersionString": "2.3.4",
                                                     "CFBundleIdentifier": "com.example.foo"}))
    inv = sw.collect_macos_inventory([str(tmp_path)])
    assert inv[0]["name"] == "Foo" and inv[0]["version"] == "2.3.4"


def test_linux_inventory_parsing(monkeypatch):
    out = "bash\t5.2\tUbuntu Devs\tii \nghost\t1.0\tx\trc \nopenssl\t3.0.13\tUbuntu\tii \n"
    monkeypatch.setattr(sw, "run", lambda cmd, timeout=60, input_text=None: (0, out, ""))
    inv = sw.collect_linux_inventory()
    assert [e["name"] for e in inv] == ["bash", "openssl"]


# ---------------------------------------------------------------- scanner on this platform
def test_scanner_runs_with_mock_inventory(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path))
    cfg = Config()
    ctx = ScanContext(config=cfg, signatures=SignatureDB(cfg))
    monkeypatch.setattr(sw, "OS_NAME", "windows")
    monkeypatch.setattr(sw, "collect_inventory", lambda: [entry("OneLaunch", "1"), entry("WinRAR 7.12", "7.12"),
                                                           entry("AnyDesk", "9"), entry("Good App", "1")])
    items = list(sw.SoftwareScanner().run(ctx))
    findings = [i for i in items if isinstance(i, Finding)]
    checks = {i.check_id: i for i in items if isinstance(i, CheckResult)}
    assert {f.rule_id for f in findings} == {"AEG-SW-PUP", "AEG-SW-VULN", "AEG-SW-REMOTE"}
    assert checks["AEG-SW-INVENTORY"].status == CheckStatus.PASS
    assert checks["AEG-SW-PUP"].status == CheckStatus.FAIL and checks["AEG-SW-VULN"].status == CheckStatus.FAIL
    assert ctx.stats["software_installed"] == 4 and len(ctx.options["software_inventory"]) == 4


def test_scanner_runs_for_real_on_linux(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path))
    cfg = Config()
    ctx = ScanContext(config=cfg, signatures=SignatureDB(cfg))
    items = list(sw.SoftwareScanner().run(ctx))  # must not raise even without dpkg/rpm
    assert all(isinstance(i, (Finding, CheckResult)) for i in items)
    assert sw.SoftwareScanner.name == "software"
