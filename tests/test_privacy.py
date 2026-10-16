"""Unit tests for aegis.scanners.privacy: FILETIME and path decoding, the ConsentStore collector (fake registry), the
Windows and macOS classifiers, the TCC reader (real sqlite files in both layouts) and the scanner flow (platform facts are
mocked, so everything runs on any OS)."""

import datetime as dt
import json
import os
import sqlite3
import struct
import sys
from contextlib import closing

import pytest

from aegis.core.models import Category, CheckResult, CheckStatus, Finding, Severity
from aegis.scanners import privacy
from aegis.scanners.base import REGISTRY, load_all

UTC = dt.timezone.utc
NOW = dt.datetime(2026, 10, 16, 12, 0, tzinfo=UTC)
CONSENT = privacy.CONSENT_KEY
CAMERA = privacy.WINDOWS_BY_KEY["webcam"]
MIC = privacy.WINDOWS_BY_KEY["microphone"]
LOCATION = privacy.WINDOWS_BY_KEY["location"]


def ft(when: dt.datetime) -> int:
    """FILETIME (what a REG_QWORD holds) of an aware datetime."""
    delta = when - dt.datetime(1601, 1, 1, tzinfo=UTC)
    return (delta.days * 86400 + delta.seconds) * 10_000_000 + delta.microseconds * 10


def ago(**kw) -> dt.datetime:
    return NOW - dt.timedelta(**kw)


def rules(findings):
    return [f.rule_id for f in findings]


def split(out):
    out = list(out)
    return [x for x in out if isinstance(x, Finding)], [x for x in out if isinstance(x, CheckResult)]


# ---------------------------------------------------------------- FILETIME
def test_filetime_to_datetime_known_values():
    t = dt.datetime(2026, 10, 14, 10, 30, 15, tzinfo=UTC)
    assert privacy.filetime_to_datetime(ft(t)) == t
    assert privacy.filetime_to_datetime(ft(t)).tzinfo is not None
    assert privacy.filetime_to_datetime(struct.pack("<Q", ft(t))) == t  # REG_BINARY holding the same 8 bytes
    assert privacy.filetime_to_datetime(bytearray(struct.pack("<Q", ft(t)))) == t
    assert privacy.filetime_to_datetime(ft(t) + 7) == t  # sub-second noise is dropped, not an error
    assert privacy.filetime_to_datetime(116444736000000000) is None  # 1970-01-01 is before the supported range
    assert privacy.filetime_to_datetime(132539328000000000) == dt.datetime(2021, 1, 1, tzinfo=UTC)


@pytest.mark.parametrize("value", [
    0, None, -5, -ft(NOW), 1, 123456789,  # zero, missing, negative, 1601
    2 ** 64 - 1, 2 ** 63, 10 ** 30,  # far beyond the year 2100 / overflow
    b"", b"\x00" * 8, b"\xff" * 8, b"\x01\x02\x03",  # raw bytes: empty, zero, absurd, too short
    True, "not a number", "", [], {}, float("nan"), float("inf"),
])
def test_filetime_absurd_values_give_none(value):
    assert privacy.filetime_to_datetime(value) is None


def test_filetime_range_edges():
    assert privacy.filetime_to_datetime(ft(dt.datetime(2000, 1, 1, tzinfo=UTC))) == dt.datetime(2000, 1, 1, tzinfo=UTC)
    assert privacy.filetime_to_datetime(ft(dt.datetime(1999, 12, 31, 23, 59, tzinfo=UTC))) is None
    assert privacy.filetime_to_datetime(ft(dt.datetime(2099, 12, 31, tzinfo=UTC))) is not None
    assert privacy.filetime_to_datetime(ft(dt.datetime(2100, 1, 1, tzinfo=UTC))) is None


def test_unix_to_datetime():
    assert privacy.unix_to_datetime(1_760_000_000) == dt.datetime.fromtimestamp(1_760_000_000, tz=UTC)
    for bad in (0, None, -1, "x", True, 10 ** 20, 1):
        assert privacy.unix_to_datetime(bad) is None


# ---------------------------------------------------------------- path decoding / location helpers
@pytest.mark.parametrize("name,path", [
    ("C:#Program Files#Zoom#bin#Zoom.exe", "C:\\Program Files\\Zoom\\bin\\Zoom.exe"),
    ("C:#Users#bob#AppData#Local#Temp#x.exe", "C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe"),
    ("##server#share#tool.exe", "\\\\server\\share\\tool.exe"),
    ("  D:#a.exe  ", "D:\\a.exe"),
    ("NoSeparators.exe", "NoSeparators.exe"),
    ("", ""),
])
def test_decode_nonpackaged_name(name, path):
    assert privacy.decode_nonpackaged_name(name) == path


@pytest.mark.parametrize("path,staging", [
    ("C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe", True),
    ("C:\\Users\\bob\\AppData\\Local\\Temp\\a\\b\\x.exe", True),
    ("c:\\users\\bob\\appdata\\local\\temp\\x.exe", True),  # case-insensitive
    ("C:/Users/bob/AppData/Local/Temp/x.exe", True),  # forward slashes
    ("C:\\Windows\\Temp\\x.exe", True),
    ("C:\\Users\\bob\\Downloads\\setup.exe", True),
    ("C:\\Users\\bob\\Downloads\\portable\\app.exe", True),
    ("C:\\Users\\Public\\x.exe", True),
    ("C:\\Users\\Public\\Documents\\x.exe", True),
    ("C:\\$Recycle.Bin\\S-1-5-21-1\\x.exe", True),
    ("C:\\ProgramData\\x.exe", True),
    ("D:\\ProgramData\\x.exe", True),
    ("C:\\Users\\bob\\AppData\\Roaming\\x.exe", True),
    ("C:\\Users\\bob\\AppData\\Local\\x.exe", True),
    ("\\\\?\\C:\\Users\\bob\\AppData\\Local\\x.exe", True),
    # a file one level deeper is an install folder, not the staging root
    ("C:\\ProgramData\\Vendor\\x.exe", False),
    ("C:\\Users\\bob\\AppData\\Roaming\\Zoom\\bin\\Zoom.exe", False),
    ("C:\\Users\\bob\\AppData\\Local\\Programs\\Foo\\foo.exe", False),
    ("C:\\Users\\bob\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe", False),
    ("C:\\Program Files\\Zoom\\bin\\Zoom.exe", False),
    ("C:\\Windows\\System32\\rundll32.exe", False),
    ("C:\\Users\\bob\\Desktop\\x.exe", False),
    ("C:\\Users\\bob\\MyDownloads\\x.exe", False),  # only a folder literally named Downloads counts
    ("", False),
])
def test_staging_location(path, staging):
    assert bool(privacy.staging_location(path)) is staging


@pytest.mark.parametrize("path,versioned", [
    ("C:\\Users\\bob\\AppData\\Local\\Discord\\app-1.0.9035\\Discord.exe", True),
    ("C:\\Users\\bob\\AppData\\Local\\slack\\app-4.36.140\\slack.exe", True),
    ("C:\\Users\\bob\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe", True),
    ("C:\\Program Files\\Foo\\1.2.3.4\\foo.exe", True),
    ("C:\\Program Files (x86)\\Google\\Chrome\\Application\\131.0.6778.86\\chrome.exe", True),
    ("C:\\Program Files\\Foo\\v2.0.1\\foo.exe", True),
    ("C:\\Program Files\\WindowsApps\\Microsoft.WindowsCamera_2022.2404.2.0_x64__8wekyb3d8bbwe\\WindowsCamera.exe", True),
    ("/opt/homebrew/Cellar/foo/1.2.3/bin/foo", True),
    ("C:\\Program Files\\Zoom\\bin\\Zoom.exe", False),
    ("C:\\Program Files\\OldApp\\old.exe", False),
    ("C:\\Program Files\\Python312\\python.exe", False),
    ("C:\\Tools\\7zip\\7z.exe", False),
    ("C:\\Tools\\1.exe", False),  # the file name is never a version folder
    ("C:\\Tools\\3\\x.exe", False),  # a bare number has no dot: not a version
])
def test_is_versioned_path(path, versioned):
    assert privacy.is_versioned_path(path) is versioned


# ---------------------------------------------------------------- fake registry + collector
class FakeRegistry:
    """In-memory stand-in for reg_subkeys / reg_values (the keys are case-insensitive like the real registry)."""

    def __init__(self):
        self.keys = {}  # (hive, lower path) -> (path as written, values)
        self.fail_on = set()  # paths whose enumeration raises

    def add(self, hive, path, **values):
        parts = path.split("\\")
        for i in range(1, len(parts) + 1):
            sub = "\\".join(parts[:i])
            self.keys.setdefault((hive, sub.lower()), (sub, {}))
        self.keys[(hive, path.lower())][1].update(values)

    def app(self, hive, cap, name, start=None, stop=None, packaged=False, **extra):
        values = dict(extra)
        values.setdefault("Value", "Allow")
        if start is not None:
            values["LastUsedTimeStart"] = start if isinstance(start, (int, bytes)) else ft(start)
        if stop is not None:
            values["LastUsedTimeStop"] = stop if isinstance(stop, (int, bytes)) else ft(stop)
        self.add(hive, f"{CONSENT}\\{cap}\\" + ("" if packaged else "NonPackaged\\") + name, **values)

    def subkeys(self, hive, key, view64=True):
        if key in self.fail_on:
            raise OSError("access denied")
        prefix = key.lower() + "\\"
        return [orig.rsplit("\\", 1)[-1] for (h, low), (orig, _v) in self.keys.items()
                if h == hive and low.startswith(prefix) and "\\" not in low[len(prefix):]]

    def values(self, hive, key, view64=True):
        return dict(self.keys.get((hive, key.lower()), ("", {}))[1])

    def install(self, monkeypatch):
        monkeypatch.setattr(privacy, "reg_subkeys", self.subkeys)
        monkeypatch.setattr(privacy, "reg_values", self.values)


def collect(reg, cap="webcam", exists=lambda p: True):
    return privacy.collect_usage(cap, reg.subkeys, reg.values, exists)


def test_collector_reads_packaged_and_desktop_apps_from_both_hives():
    reg = FakeRegistry()
    reg.app("HKCU", "webcam", "Microsoft.WindowsCamera_8wekyb3d8bbwe", ago(days=2), ago(days=2, minutes=-5), packaged=True)
    reg.app("HKCU", "webcam", "C:#Program Files#Zoom#bin#Zoom.exe", ago(hours=3), ago(hours=2))
    reg.app("HKLM", "webcam", "C:#Windows#System32#svchost.exe", ago(days=9), ago(days=9, minutes=-1))
    reg.add("HKCU", f"{CONSENT}\\webcam", Value="Allow")  # the capability key itself is not an app
    recs = {r.app: r for r in collect(reg)}
    assert set(recs) == {"Microsoft.WindowsCamera_8wekyb3d8bbwe", "C:\\Program Files\\Zoom\\bin\\Zoom.exe",
                         "C:\\Windows\\System32\\svchost.exe"}  # NonPackaged itself is never reported as an app
    store = recs["Microsoft.WindowsCamera_8wekyb3d8bbwe"]
    assert store.packaged and store.exists is None and store.hive == "HKCU" and store.permission == "Allow"
    assert store.name == "Microsoft.WindowsCamera_8wekyb3d8bbwe"
    zoom = recs["C:\\Program Files\\Zoom\\bin\\Zoom.exe"]
    assert not zoom.packaged and zoom.exists is True and zoom.name == "Zoom.exe" and zoom.hive == "HKCU"
    assert zoom.last_start == ago(hours=3) and zoom.last_stop == ago(hours=2) and not zoom.in_use
    assert zoom.last_used == ago(hours=2) and zoom.used
    assert zoom.key == f"{CONSENT}\\webcam\\NonPackaged\\C:#Program Files#Zoom#bin#Zoom.exe"
    assert recs["C:\\Windows\\System32\\svchost.exe"].hive == "HKLM"


def test_collector_in_use_now_and_missing_values():
    reg = FakeRegistry()
    reg.app("HKCU", "webcam", "C:#Tools#live.exe", ago(minutes=5), 0)  # stop == 0: in use right now
    reg.app("HKCU", "webcam", "C:#Tools#nostop.exe", ago(minutes=5))  # no stop value at all: not "in use"
    reg.app("HKCU", "webcam", "C:#Tools#never.exe")  # permission granted, never used
    reg.app("HKCU", "webcam", "C:#Tools#zero.exe", 0, 0)  # both zero: never used
    reg.app("HKCU", "webcam", "C:#Tools#stoponly.exe", None, 0)  # a stop of 0 without a start is not a session
    reg.app("HKCU", "webcam", "C:#Tools#garbage.exe", 2 ** 64 - 1, 2 ** 64 - 1)
    reg.app("HKCU", "webcam", "C:#Tools#bytes.exe", struct.pack("<Q", ft(ago(hours=1))), b"\x00" * 8)
    recs = {r.name: r for r in collect(reg)}
    assert recs["live.exe"].in_use and recs["live.exe"].last_stop is None and recs["live.exe"].last_start == ago(minutes=5)
    assert not recs["nostop.exe"].in_use and recs["nostop.exe"].last_stop is None and recs["nostop.exe"].used
    assert not recs["never.exe"].used and recs["never.exe"].last_used is None
    assert not recs["zero.exe"].used and not recs["zero.exe"].in_use
    assert not recs["stoponly.exe"].in_use and not recs["stoponly.exe"].used
    assert not recs["garbage.exe"].used and not recs["garbage.exe"].in_use  # absurd times are ignored
    assert recs["bytes.exe"].in_use and recs["bytes.exe"].last_start == ago(hours=1)


def test_collector_value_names_are_case_insensitive_and_permission_is_kept():
    reg = FakeRegistry()
    reg.add("HKCU", f"{CONSENT}\\webcam\\NonPackaged\\C:#T#a.exe", value="Deny", lastusedtimestart=ft(ago(days=1)),
            LASTUSEDTIMESTOP=ft(ago(days=1)) + 1000)
    (r,) = collect(reg)
    assert r.permission == "Deny" and r.last_start == ago(days=1) and r.last_stop is not None


def test_collector_path_exists_is_injectable_and_skips_unc_and_odd_names():
    reg = FakeRegistry()
    reg.app("HKCU", "webcam", "C:#here#a.exe", ago(days=1), ago(days=1))
    reg.app("HKCU", "webcam", "C:#gone#b.exe", ago(days=1), ago(days=1))
    reg.app("HKCU", "webcam", "##srv#share#c.exe", ago(days=1), ago(days=1))
    reg.app("HKCU", "webcam", "weird-name", ago(days=1), ago(days=1))
    asked = []

    def exists(path):
        asked.append(path)
        return "gone" not in path

    recs = {r.app: r for r in collect(reg, exists=exists)}
    assert recs["C:\\here\\a.exe"].exists is True and recs["C:\\gone\\b.exe"].exists is False
    assert recs["\\\\srv\\share\\c.exe"].exists is None and recs["weird-name"].exists is None
    assert sorted(asked) == ["C:\\gone\\b.exe", "C:\\here\\a.exe"]  # the network path was never touched

    def boom(path):
        raise OSError("device not ready")

    assert all(r.exists is None for r in collect(reg, exists=boom))


def test_collector_without_any_keys_and_other_capability():
    reg = FakeRegistry()
    assert collect(reg) == []
    reg.app("HKCU", "microphone", "C:#a#a.exe", ago(days=1), ago(days=1))
    assert collect(reg, "webcam") == [] and len(collect(reg, "microphone")) == 1
    assert collect(reg, "microphone")[0].capability == "microphone"


def test_read_switches():
    reg = FakeRegistry()
    reg.add("HKCU", f"{CONSENT}\\webcam", Value="Allow")
    reg.add("HKLM", f"{CONSENT}\\webcam", Value="Deny")
    reg.add("HKCU", f"{CONSENT}\\microphone", Value=5)  # not a string: ignored
    assert privacy.read_switches("webcam", reg.values) == {"HKCU": "Allow", "HKLM": "Deny"}
    assert privacy.read_switches("microphone", reg.values) == {}
    assert privacy.read_switches("location", reg.values) == {}


def rec(path, cap="webcam", days=1, in_use=False, exists=True, packaged=False, hive="HKCU", value="Allow", used=True):
    start = ago(days=days) if used else None
    stop = None if in_use or not used else start + dt.timedelta(minutes=30)
    return privacy.UsageRecord(cap, hive, path, packaged, "key", value, start, stop, in_use and used, exists)


def test_dedupe_records_keeps_the_most_recent_per_app_and_capability():
    a_old = rec("C:\\Tools\\a.exe", days=5, hive="HKLM")
    a_new = rec("c:\\tools\\A.EXE", days=1, hive="HKCU")
    b = rec("C:\\Tools\\b.exe", days=3)
    b_mic = rec("C:\\Tools\\b.exe", cap="microphone", days=3)
    c_old = rec("C:\\Tools\\c.exe", days=20)
    c_live = rec("C:\\Tools\\c.exe", days=30, in_use=True, hive="HKLM")  # in use beats a newer finished session
    got = privacy.dedupe_records([a_old, b, a_new, b_mic, c_old, c_live])
    assert got == [a_new, b, b_mic, c_live]


def test_recent_usage_window_and_order():
    recs = [rec("C:\\a.exe", days=29), rec("C:\\b.exe", days=31), rec("C:\\c.exe", days=1), rec("C:\\d.exe", used=False),
            rec("C:\\e.exe", days=90, in_use=True), rec("C:\\f.exe", days=0)]
    got = privacy.recent_usage(recs, NOW)
    # 31 days old and never used drop out; a session still in use counts whatever its start time, and comes first
    assert [r.app for r in got] == ["C:\\e.exe", "C:\\f.exe", "C:\\c.exe", "C:\\a.exe"]
    assert [r.app for r in privacy.recent_usage(recs, NOW, days=2)] == ["C:\\e.exe", "C:\\f.exe", "C:\\c.exe"]


# ---------------------------------------------------------------- Windows classifier
def verdict(path, cap="webcam", **kw):
    return privacy.classify_usage(rec(path, cap, **kw))


@pytest.mark.parametrize("name", sorted(privacy.HIGH_RISK_HOSTS))
def test_script_hosts_are_high(name):
    sev, reasons, mitre = verdict(f"C:\\Windows\\System32\\{name}")
    assert sev == Severity.HIGH and "script host" in reasons[0] and mitre == ["T1125"]
    assert verdict(f"C:\\Windows\\System32\\{name.upper()}")[0] == Severity.HIGH  # case-insensitive


@pytest.mark.parametrize("path", [
    "C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "C:\\Program Files\\PowerShell\\7\\pwsh.exe"])
def test_shells_are_medium(path):
    sev, reasons, _m = verdict(path)
    assert sev == Severity.MEDIUM and "command shell" in reasons[0]


@pytest.mark.parametrize("path", [
    "C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe", "C:\\Windows\\Temp\\x.exe", "C:\\Users\\bob\\Downloads\\x.exe",
    "C:\\Users\\Public\\x.exe", "C:\\$Recycle.Bin\\S-1-5-21-1\\x.exe", "C:\\ProgramData\\x.exe",
    "C:\\Users\\bob\\AppData\\Roaming\\x.exe", "C:\\Users\\bob\\AppData\\Local\\x.exe"])
def test_staging_locations_are_medium(path):
    sev, reasons, _m = verdict(path)
    assert sev == Severity.MEDIUM and "folder any program can write to" in reasons[0]


@pytest.mark.parametrize("path", [
    "C:\\Program Files\\Zoom\\bin\\Zoom.exe",
    "C:\\Users\\bob\\AppData\\Roaming\\Zoom\\bin\\Zoom.exe",
    "C:\\Program Files (x86)\\Microsoft\\Teams\\current\\Teams.exe",
    "C:\\Users\\bob\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe",
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files\\obs-studio\\bin\\64bit\\obs64.exe",
    "C:\\Users\\bob\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe",
    "C:\\Users\\bob\\AppData\\Local\\Discord\\app-1.0.9035\\Discord.exe",
    "C:\\ProgramData\\Vendor\\helper.exe",
    "C:\\Windows\\System32\\svchost.exe",
])
def test_normal_installs_are_not_flagged(path):
    assert verdict(path) is None
    assert verdict(path, in_use=True) is None  # being in use does not make a normal program suspicious
    assert verdict(path, "microphone") is None and verdict(path, "graphicsCaptureProgrammatic") is None


def test_store_apps_are_never_flagged():
    assert verdict("Microsoft.WindowsCamera_8wekyb3d8bbwe", packaged=True, exists=None) is None
    assert verdict("rundll32.exe", packaged=True, exists=None, in_use=True) is None


def test_programs_without_a_recorded_use_are_not_flagged():
    assert verdict("C:\\Windows\\System32\\rundll32.exe", used=False) is None
    assert verdict("C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe", used=False, exists=False) is None


@pytest.mark.parametrize("path,start_sev,live_sev", [
    ("C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe", Severity.MEDIUM, Severity.HIGH),  # staging MEDIUM -> HIGH
    ("C:\\Windows\\System32\\cmd.exe", Severity.MEDIUM, Severity.HIGH),  # shell MEDIUM -> HIGH
    ("C:\\Windows\\System32\\mshta.exe", Severity.HIGH, Severity.CRITICAL),  # LOLBin HIGH -> CRITICAL
    ("C:\\Users\\Public\\rundll32.exe", Severity.HIGH, Severity.CRITICAL),  # LOLBin in staging: still one level only
    ("C:\\Users\\bob\\Downloads\\powershell.exe", Severity.MEDIUM, Severity.HIGH),
])
def test_in_use_now_raises_one_level(path, start_sev, live_sev):
    idle = verdict(path)
    live = verdict(path, in_use=True)
    assert idle[0] == start_sev and live[0] == live_sev
    assert "right now" in live[1][-1] and not any("right now" in r for r in idle[1])


def test_deleted_staging_program_keeps_severity_and_says_why():
    path = "C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe"
    sev, reasons, _m = verdict(path, exists=False)
    assert sev == Severity.MEDIUM and "the program was deleted after using the device" in reasons
    sev, reasons, _m = verdict(path, exists=False, in_use=True)
    assert sev == Severity.HIGH and "the program was deleted after using the device" in reasons
    # still there: no deletion reason
    assert "the program was deleted after using the device" not in verdict(path, exists=True)[1]
    # unknown (None) is not "deleted"
    assert "the program was deleted after using the device" not in verdict(path, exists=None)[1]
    # a versioned folder inside a staging folder is still staging
    assert verdict("C:\\Users\\bob\\AppData\\Local\\Temp\\app-1.2.3\\x.exe", exists=False)[0] == Severity.MEDIUM


def test_deleted_lolbin_outside_staging_keeps_its_severity_without_the_deletion_reason():
    sev, reasons, _m = verdict("C:\\Windows\\System32\\rundll32.exe", exists=False)
    assert sev == Severity.HIGH and not any("deleted" in r for r in reasons)


def test_deleted_program_elsewhere_is_info_only():
    sev, reasons, mitre = verdict("C:\\Program Files\\OldApp\\old.exe", exists=False)
    assert sev == Severity.INFO and reasons == ["the program no longer exists on disk"] and mitre == ["T1125"]
    # in use now does not raise an INFO
    assert verdict("C:\\Program Files\\OldApp\\old.exe", exists=False, in_use=True)[0] == Severity.INFO
    assert verdict("C:\\Program Files\\OldApp\\old.exe", exists=None) is None  # unknown is not missing


@pytest.mark.parametrize("path", [
    "C:\\Users\\bob\\AppData\\Local\\Discord\\app-1.0.9035\\Discord.exe",
    "C:\\Users\\bob\\AppData\\Local\\slack\\app-4.36.140\\slack.exe",
    "C:\\Users\\bob\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe",
    "C:\\Program Files\\Foo\\1.2.3.4\\foo.exe",
    "C:\\Program Files (x86)\\Google\\Chrome\\Application\\131.0.6778.86\\chrome.exe",
])
def test_deleted_programs_in_versioned_folders_are_ignored(path):
    assert verdict(path, exists=False) is None


@pytest.mark.parametrize("cap,mitre", [
    ("webcam", ["T1125"]), ("microphone", ["T1123"]), ("graphicsCaptureProgrammatic", ["T1113"]),
    ("graphicsCaptureWithoutBorder", ["T1113"]), ("location", [])])
def test_mitre_follows_the_capability(cap, mitre):
    assert verdict("C:\\Windows\\System32\\mshta.exe", cap)[2] == mitre
    assert verdict("C:\\Program Files\\OldApp\\old.exe", cap, exists=False)[2] == mitre


def test_every_capability_mitre_id_is_well_formed():
    import re

    for cap in privacy.WINDOWS_CAPABILITIES + privacy.MAC_CAPABILITIES:
        assert all(re.fullmatch(r"T1\d{3}(?:\.\d{3})?", m) for m in cap.mitre), cap.key
        assert cap.tag and cap.phrase and cap.abuse


# ---------------------------------------------------------------- Windows findings, remediation, review
def finding_for(path, cap=CAMERA, **kw):
    r = rec(path, cap.key, **kw)
    return privacy.usage_finding(cap, r, privacy.classify_usage(r))


def test_usage_finding_carries_everything_the_report_needs():
    path = "C:\\Users\\bob\\AppData\\Local\\Temp\\evil.exe"
    f = finding_for(path, in_use=True)
    assert f.rule_id == "AEG-PRIV-CAMERA" and f.severity == Severity.HIGH and f.category == Category.PRIVACY
    assert f.location == path and f.mitre == ["T1125"]
    assert "evil.exe" in f.title and "camera" in f.title and "right now" in f.title
    assert path in f.description and "Why this is suspicious" in f.description and "Temp folder" in f.description
    assert "stalkerware" in f.description and "right now" in f.description
    ev = f.evidence
    assert ev["capability"] == "webcam" and ev["app"] == path and ev["hive"] == "HKCU" and ev["packaged"] is False
    assert ev["in_use_now"] is True and ev["exists_on_disk"] is True and ev["last_used_stop"] is None
    assert dt.datetime.fromisoformat(ev["last_used_start"]) == ago(days=1)
    assert ev["reasons"] and ev["permission"] == "Allow"
    assert "Settings > Privacy & security > Camera" in f.recommendation
    assert "Let desktop apps access your camera" in f.recommendation
    assert f.remediation.action == "quarantine_file" and f.remediation.params == {"path": path}
    json.dumps(f.to_dict())


def test_usage_finding_idle_session_shows_start_and_stop():
    f = finding_for("C:\\Windows\\System32\\mshta.exe")
    ev = f.evidence
    assert dt.datetime.fromisoformat(ev["last_used_stop"]) - dt.datetime.fromisoformat(ev["last_used_start"]) == \
        dt.timedelta(minutes=30)
    assert ev["in_use_now"] is False and "from 2026-10-15 12:00 UTC to 2026-10-15 12:30 UTC" in f.description
    assert "right now" not in f.title and "script host" in f.title


@pytest.mark.parametrize("cap,pane", [(MIC, "Microphone"), (LOCATION, "Location")])
def test_recommendation_names_the_settings_page_of_the_capability(cap, pane):
    f = finding_for("C:\\Users\\Public\\x.exe", cap)
    assert f"Settings > Privacy & security > {pane}" in f.recommendation
    assert f"Let desktop apps access your {cap.key if cap.key != 'webcam' else 'camera'}" in f.recommendation
    assert f.rule_id == f"AEG-PRIV-{cap.tag}"


def test_screen_capture_findings_have_their_own_rule_ids_and_no_toggle_hint():
    for key, rule in (("graphicsCaptureProgrammatic", "AEG-PRIV-SCREEN"),
                      ("graphicsCaptureWithoutBorder", "AEG-PRIV-SCREEN-BORDERLESS")):
        f = finding_for("C:\\Users\\Public\\x.exe", privacy.WINDOWS_BY_KEY[key])
        assert f.rule_id == rule and f.mitre == ["T1113"] and "Let desktop apps" not in f.recommendation
    # one program using both screen-capture capabilities must not collapse into a single fingerprint
    a = finding_for("C:\\Users\\Public\\x.exe", privacy.WINDOWS_BY_KEY["graphicsCaptureProgrammatic"])
    b = finding_for("C:\\Users\\Public\\x.exe", privacy.WINDOWS_BY_KEY["graphicsCaptureWithoutBorder"])
    c = finding_for("C:\\Users\\Public\\x.exe", CAMERA)
    assert len({a.fingerprint, b.fingerprint, c.fingerprint}) == 3


def test_deleted_program_finding_texts():
    gone = finding_for("C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe", exists=False)
    assert "deleted after using the device" in gone.description and gone.remediation is None
    assert "file is gone" in gone.recommendation
    info = finding_for("C:\\Program Files\\OldApp\\old.exe", exists=False)
    assert info.severity == Severity.INFO and "no longer on disk" in info.title and info.remediation is None
    assert "malware also deletes itself" in info.description


@pytest.mark.parametrize("path,exists,fix", [
    ("C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe", True, True),  # staging, still there
    ("C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe", False, False),  # nothing to move
    ("C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe", None, False),  # unknown: do not guess
    ("C:\\Users\\bob\\Music\\mshta.exe", True, True),  # a script host copied somewhere user-writable
    ("C:\\Windows\\System32\\rundll32.exe", True, False),  # genuine Windows binary: never quarantined
    ("C:\\Windows\\SysWOW64\\cmd.exe", True, False),
    ("C:\\Program Files\\PowerShell\\7\\pwsh.exe", True, False),
    ("C:\\Program Files (x86)\\Microsoft Visual Studio\\MSBuild\\Current\\Bin\\MSBuild.exe", True, False),
    ("C:\\Windows\\Temp\\x.exe", True, True),  # the Windows Temp folder is staging, not a system tree
])
def test_remediation_only_when_it_is_safe(path, exists, fix):
    r = rec(path, exists=exists)
    f = privacy.usage_finding(CAMERA, r, privacy.classify_usage(r))
    assert (f.remediation is not None) is fix
    if fix:
        assert f.remediation.action == "quarantine_file" and f.remediation.params["path"] == path


def test_protected_system_binary_gets_a_hint_about_the_launcher_instead_of_a_fix():
    f = finding_for("C:\\Windows\\System32\\rundll32.exe")
    assert f.remediation is None and "genuine Windows component" in f.recommendation


def review(records, switches=None, cap=CAMERA):
    return privacy.review_usage(cap, records, switches, NOW)


def test_review_no_data_is_skip():
    check, findings = review([], {})
    assert check.status == CheckStatus.SKIP and findings == []
    assert check.check_id == "AEG-PRIV-CAMERA" and check.category == Category.PRIVACY


def test_review_only_the_global_switch_is_a_pass_with_the_setting_in_the_detail():
    check, findings = review([], {"HKCU": "Deny", "HKLM": "Allow"})
    assert check.status == CheckStatus.PASS and findings == []
    assert "your account: Deny" in check.detail and "this PC: Allow" in check.detail and "switched off" in check.detail
    check, _ = review([rec("C:\\Program Files\\Zoom\\bin\\Zoom.exe")], {"HKCU": "Allow"})
    assert "your account: Allow" in check.detail and "switched off" not in check.detail
    check, _ = review([rec("C:\\Program Files\\Zoom\\bin\\Zoom.exe")], {})
    assert "No global on/off setting" in check.detail


def test_review_clean_machine_passes_and_inventories():
    recs = [rec("C:\\Program Files\\Zoom\\bin\\Zoom.exe", days=1), rec("Microsoft.WindowsCamera_8wekyb3d8bbwe", days=3,
                                                                         packaged=True, exists=None)]
    check, findings = review(recs, {"HKCU": "Allow"})
    assert check.status == CheckStatus.PASS and "2 apps used the camera in the last 30 days" in check.detail
    assert rules(findings) == ["AEG-PRIV-CAMERA-INVENTORY"]


def test_review_flags_fail_the_check_and_lists_names():
    recs = [rec("C:\\Program Files\\Zoom\\bin\\Zoom.exe"), rec("C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe"),
            rec("C:\\Windows\\System32\\mshta.exe", days=4)]
    check, findings = review(recs, {"HKCU": "Allow"})
    assert check.status == CheckStatus.FAIL and "2 suspicious program(s)" in check.detail
    assert "x.exe" in check.detail and "mshta.exe" in check.detail and "Zoom.exe" not in check.detail
    assert sorted(f.severity.name for f in findings) == ["HIGH", "INFO", "MEDIUM"]  # + the inventory


def test_review_old_deleted_programs_alone_do_not_fail_the_check():
    check, findings = review([rec("C:\\Program Files\\OldApp\\old.exe", days=60, exists=False)])
    assert check.status == CheckStatus.PASS and "1 program(s) that no longer exist" in check.detail
    assert [f.severity for f in findings] == [Severity.INFO] and findings[0].rule_id == "AEG-PRIV-CAMERA"
    # 60 days ago is outside the inventory window
    assert "AEG-PRIV-CAMERA-INVENTORY" not in rules(findings)


def test_review_inventory_title_location_and_evidence():
    recs = [rec("C:\\Program Files\\Zoom\\bin\\Zoom.exe", days=1), rec("C:\\Program Files\\Teams\\Teams.exe", days=2),
            rec("C:\\Program Files\\Old\\old.exe", days=45)]
    check, findings = review(recs)
    (inv,) = [f for f in findings if f.rule_id.endswith("-INVENTORY")]
    assert inv.title == "2 apps used the camera in the last 30 days" and inv.severity == Severity.INFO
    assert inv.location == f"HKCU\\{CONSENT}\\webcam" and inv.category == Category.PRIVACY and inv.mitre == ["T1125"]
    assert inv.evidence["total"] == 2 and inv.evidence["capability"] == "webcam"
    assert [a["app"] for a in inv.evidence["apps"]] == ["C:\\Program Files\\Zoom\\bin\\Zoom.exe",
                                                       "C:\\Program Files\\Teams\\Teams.exe"]  # newest first
    assert set(inv.evidence["apps"][0]) == {"app", "last_used", "in_use_now"}
    assert inv.evidence["apps"][0]["in_use_now"] is False
    assert dt.datetime.fromisoformat(inv.evidence["apps"][0]["last_used"]) == ago(days=1) + dt.timedelta(minutes=30)
    one = review([recs[0]])[1][0]
    assert one.title == "1 app used the camera in the last 30 days"
    mic = review([rec("C:\\a\\a.exe", "microphone")], cap=MIC)[1][0]
    assert mic.title == "1 app used the microphone in the last 30 days" and mic.location.endswith("\\microphone")
    loc = review([rec("C:\\a\\a.exe", "location")], cap=LOCATION)[1][0]
    assert loc.title == "1 app used your location in the last 30 days" and loc.mitre == []
    assert len({x.fingerprint for x in (inv, mic, loc)}) == 3


def test_review_inventory_is_capped_at_50_and_counts_everything():
    recs = [privacy.UsageRecord("webcam", "HKCU", f"C:\\Program Files\\App{i:02d}\\app.exe", False, "k", "Allow",
                                NOW - dt.timedelta(hours=i + 1), NOW - dt.timedelta(hours=i + 1) + dt.timedelta(minutes=1),
                                False, True) for i in range(60)]
    (inv,) = [f for f in review(recs)[1] if f.rule_id.endswith("-INVENTORY")]
    assert inv.title == "60 apps used the camera in the last 30 days" and inv.evidence["total"] == 60
    assert len(inv.evidence["apps"]) == 50
    assert inv.evidence["apps"][0]["app"].endswith("App00\\app.exe") and inv.evidence["apps"][-1]["app"].endswith("App49\\app.exe")


def test_review_inventory_marks_in_use_now_and_skips_never_used():
    recs = [rec("C:\\Program Files\\Live\\live.exe", days=0, in_use=True), rec("C:\\Program Files\\N\\n.exe", used=False)]
    (inv,) = review(recs)[1]
    assert inv.evidence["total"] == 1 and inv.evidence["apps"][0]["in_use_now"] is True


def test_review_dedupes_the_same_program_across_hives():
    path = "C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe"
    recs = [rec(path, hive="HKCU", days=3), rec(path, hive="HKLM", days=1)]
    check, findings = review(recs)
    bad = [f for f in findings if f.severity >= Severity.MEDIUM]
    assert len(bad) == 1 and bad[0].evidence["hive"] == "HKLM"
    assert [f for f in findings if f.rule_id.endswith("-INVENTORY")][0].evidence["total"] == 1


def test_review_caps_the_no_longer_on_disk_notes():
    recs = [rec(f"C:\\Program Files\\Old{i}\\old.exe", days=40, exists=False) for i in range(privacy.MAX_INFO_FINDINGS + 10)]
    check, findings = review(recs)
    assert len(findings) == privacy.MAX_INFO_FINDINGS
    assert f"{privacy.MAX_INFO_FINDINGS + 10} program(s) that no longer exist" in check.detail


# ---------------------------------------------------------------- scanner on (mocked) Windows
def windows_registry():
    reg = FakeRegistry()
    # camera: a normal call app, a Store app, a live program in Temp, a script host
    reg.add("HKCU", f"{CONSENT}\\webcam", Value="Allow")
    reg.add("HKLM", f"{CONSENT}\\webcam", Value="Allow")
    reg.app("HKCU", "webcam", "C:#Program Files#Zoom#bin#Zoom.exe", ago(days=1), ago(days=1, hours=-1))
    reg.app("HKCU", "webcam", "Microsoft.WindowsCamera_8wekyb3d8bbwe", ago(days=2), ago(days=2, minutes=-5), packaged=True)
    reg.app("HKCU", "webcam", "C:#Users#bob#AppData#Local#Temp#spy.exe", ago(minutes=20), 0)
    reg.app("HKCU", "webcam", "C:#Windows#System32#mshta.exe", ago(days=3), ago(days=3, minutes=-2))
    # microphone: only the global switch
    reg.add("HKCU", f"{CONSENT}\\microphone", Value="Deny")
    # location: nothing at all; screen capture: borderless capture by a Downloads program, other key absent
    reg.app("HKCU", "graphicsCaptureWithoutBorder", "C:#Users#bob#Downloads#grab.exe", ago(days=4), ago(days=4, minutes=-1))
    return reg


@pytest.fixture
def win(monkeypatch):
    monkeypatch.setattr(privacy, "IS_WINDOWS", True)
    monkeypatch.setattr(privacy, "IS_MAC", False)
    monkeypatch.setattr(privacy, "_utcnow", lambda: NOW)
    monkeypatch.setattr(privacy, "_path_exists", lambda p: "spy.exe" not in p)
    reg = windows_registry()
    reg.install(monkeypatch)
    return reg


def test_scanner_windows_flow(ctx, win):
    out = list(privacy.PrivacyScanner().run(ctx))
    findings, checks = split(out)
    by_id = {c.check_id: c for c in checks}
    assert set(by_id) == {"AEG-PRIV-CAMERA", "AEG-PRIV-MICROPHONE", "AEG-PRIV-LOCATION", "AEG-PRIV-SCREEN-BORDERLESS"}
    assert by_id["AEG-PRIV-CAMERA"].status == CheckStatus.FAIL
    assert "spy.exe" in by_id["AEG-PRIV-CAMERA"].detail and "mshta.exe" in by_id["AEG-PRIV-CAMERA"].detail
    assert by_id["AEG-PRIV-MICROPHONE"].status == CheckStatus.PASS and "switched off" in by_id["AEG-PRIV-MICROPHONE"].detail
    assert by_id["AEG-PRIV-LOCATION"].status == CheckStatus.SKIP  # reviewed, nothing recorded
    assert by_id["AEG-PRIV-SCREEN-BORDERLESS"].status == CheckStatus.FAIL
    assert all(c.category == Category.PRIVACY for c in checks)
    assert "AEG-PRIV-SCREEN" not in by_id  # optional capability whose key does not exist is not reported at all

    spy = [f for f in findings if f.location.endswith("spy.exe")][0]
    assert spy.rule_id == "AEG-PRIV-CAMERA" and spy.severity == Severity.HIGH  # Temp (MEDIUM) + in use now
    assert spy.evidence["in_use_now"] is True and spy.evidence["exists_on_disk"] is False
    assert "the program was deleted after using the device" in spy.evidence["reasons"] and spy.remediation is None
    mshta = [f for f in findings if f.location.endswith("mshta.exe")][0]
    assert mshta.severity == Severity.HIGH and mshta.remediation is None  # genuine System32 binary: no quarantine
    grab = [f for f in findings if f.location.endswith("grab.exe")][0]
    assert grab.rule_id == "AEG-PRIV-SCREEN-BORDERLESS" and grab.severity == Severity.MEDIUM and grab.mitre == ["T1113"]
    assert grab.remediation.action == "quarantine_file"
    assert not [f for f in findings if "Zoom" in f.location or "WindowsCamera" in f.location and f.severity != Severity.INFO]

    inv = {f.rule_id: f for f in findings if f.rule_id.endswith("-INVENTORY")}
    assert set(inv) == {"AEG-PRIV-CAMERA-INVENTORY", "AEG-PRIV-SCREEN-BORDERLESS-INVENTORY"}
    cam = inv["AEG-PRIV-CAMERA-INVENTORY"]
    assert cam.title == "4 apps used the camera in the last 30 days" and cam.severity == Severity.INFO
    assert cam.location == f"HKCU\\{CONSENT}\\webcam"
    assert cam.evidence["apps"][0]["app"].endswith("spy.exe") and cam.evidence["apps"][0]["in_use_now"] is True
    assert "AEG-PRIV-MICROPHONE-INVENTORY" not in inv  # no records, no inventory
    assert ctx.stats["privacy_records"] == 5 and ctx.stats["privacy_flagged"] == 3
    json.dumps([x.to_dict() for x in out])


def test_scanner_windows_inventory_fingerprints_are_stable_between_scans(ctx, win, monkeypatch):
    def inventories():
        return {f.rule_id: f for f in privacy.PrivacyScanner().run(ctx) if isinstance(f, Finding)
                and f.rule_id.endswith("-INVENTORY")}

    first = inventories()
    win.app("HKCU", "webcam", "C:#Program Files#Teams#Teams.exe", ago(hours=1), ago(minutes=30))  # one more app, new times
    second = inventories()
    assert second["AEG-PRIV-CAMERA-INVENTORY"].title != first["AEG-PRIV-CAMERA-INVENTORY"].title
    for rule, f in first.items():
        assert second[rule].fingerprint == f.fingerprint and second[rule].location == f.location


def test_scanner_windows_error_in_one_capability_does_not_kill_the_scan(ctx, win):
    win.fail_on.add(f"{CONSENT}\\microphone")
    win.add("HKCU", f"{CONSENT}\\microphone", Value="Allow")
    out = list(privacy.PrivacyScanner().run(ctx))
    findings, checks = split(out)
    by_id = {c.check_id: c for c in checks}
    assert by_id["AEG-PRIV-MICROPHONE"].status == CheckStatus.ERROR and "OSError" in by_id["AEG-PRIV-MICROPHONE"].detail
    assert by_id["AEG-PRIV-CAMERA"].status == CheckStatus.FAIL and by_id["AEG-PRIV-LOCATION"].status == CheckStatus.SKIP
    assert any(f.rule_id == "AEG-PRIV-CAMERA" for f in findings)


def test_scanner_never_raises_out_of_run(ctx, win, monkeypatch):
    monkeypatch.setattr(privacy, "WINDOWS_CAPABILITIES", None)  # makes the Windows flow itself blow up
    out = list(privacy.PrivacyScanner().run(ctx))
    assert [(c.check_id, c.status) for c in out] == [("AEG-PRIV-ERROR", CheckStatus.ERROR)]


def test_scanner_respects_cancel(ctx, win):
    ctx.cancel.set()
    assert list(privacy.PrivacyScanner().run(ctx)) == []


def test_scanner_optional_screen_capture_checks_appear_when_the_key_exists(ctx, win):
    win.add("HKCU", f"{CONSENT}\\graphicsCaptureProgrammatic", Value="Allow")
    checks = [c for c in privacy.PrivacyScanner().run(ctx) if isinstance(c, CheckResult)]
    by_id = {c.check_id: c for c in checks}
    assert by_id["AEG-PRIV-SCREEN"].status == CheckStatus.PASS and "Allow" in by_id["AEG-PRIV-SCREEN"].detail


# ---------------------------------------------------------------- scanner on Linux
def test_scanner_linux_is_one_clean_skip(ctx, monkeypatch):
    monkeypatch.setattr(privacy, "IS_WINDOWS", False)
    monkeypatch.setattr(privacy, "IS_MAC", False)
    out = list(privacy.PrivacyScanner().run(ctx))
    assert len(out) == 1 and isinstance(out[0], CheckResult)
    assert out[0].status == CheckStatus.SKIP and out[0].category == Category.PRIVACY
    assert "no system-wide record" in out[0].detail and out[0].check_id == "AEG-PRIV-LINUX"
    json.dumps(out[0].to_dict())


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="exercises the real platform flags of a Linux host")
def test_scanner_runs_for_real_on_linux(ctx):
    out = list(privacy.PrivacyScanner().run(ctx))
    assert [c.status for c in out] == [CheckStatus.SKIP]


# ---------------------------------------------------------------- macOS: TCC database
NEW_SCHEMA = (
    "CREATE TABLE access (service TEXT NOT NULL, client TEXT NOT NULL, client_type INTEGER NOT NULL, "
    "auth_value INTEGER NOT NULL, auth_reason INTEGER NOT NULL, auth_version INTEGER NOT NULL, csreq BLOB, policy_id INTEGER, "
    "indirect_object_identifier_type INTEGER, indirect_object_identifier TEXT NOT NULL DEFAULT 'UNUSED', "
    "indirect_object_code_identity BLOB, flags INTEGER, last_modified INTEGER NOT NULL DEFAULT 0, "
    "PRIMARY KEY (service, client, client_type, indirect_object_identifier))")
OLD_SCHEMA = (
    "CREATE TABLE access (service TEXT NOT NULL, client TEXT NOT NULL, client_type INTEGER NOT NULL, allowed INTEGER NOT NULL, "
    "prompt_count INTEGER NOT NULL, csreq BLOB, policy_id INTEGER, indirect_object_identifier_type INTEGER, "
    "indirect_object_identifier TEXT, indirect_object_code_identity BLOB, flags INTEGER, "
    "last_modified INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (service, client, client_type, indirect_object_identifier))")
CAM, MICS, SCR = "kTCCServiceCamera", "kTCCServiceMicrophone", "kTCCServiceScreenCapture"
ACC, LISTEN, POST = "kTCCServiceAccessibility", "kTCCServiceListenEvent", "kTCCServicePostEvent"
T1 = 1_760_000_000  # 2025-10-09
T2 = 1_770_000_000
T3 = 1_780_000_000


def make_tcc_db(path, schema, rows):
    """A real TCC.db. rows: (service, client, client_type, allowed, last_modified)."""
    with closing(sqlite3.connect(str(path))) as con:
        con.execute(NEW_SCHEMA if schema == "new" else OLD_SCHEMA)
        for service, client, ctype, allowed, mod in rows:
            if schema == "new":
                con.execute("INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version, "
                            "last_modified) VALUES (?,?,?,?,?,?,?)", (service, client, ctype, 2 if allowed else 0, 4, 1, mod))
            else:
                con.execute("INSERT INTO access (service, client, client_type, allowed, prompt_count, last_modified) "
                            "VALUES (?,?,?,?,?,?)", (service, client, ctype, 1 if allowed else 0, 1, mod))
        con.commit()
    return path


USER_ROWS = [
    (CAM, "us.zoom.xos", 0, True, T1),
    (CAM, "/private/tmp/cam", 1, True, T2),
    (MICS, "/usr/bin/python3", 1, True, T3),
    (MICS, "com.denied.app", 0, False, T1),
    (CAM, "/Applications/Old.app/Contents/MacOS/Old", 1, False, T1),  # denied path: never checked on disk
    ("kTCCServiceAddressBook", "com.some.app", 0, True, T1),  # not a reviewed service
]


@pytest.mark.parametrize("schema", ["new", "old"])
def test_tcc_reader_handles_both_schema_layouts(tmp_path, schema):
    db = make_tcc_db(tmp_path / "TCC.db", schema, USER_ROWS)
    checked = []

    def exists(p):
        checked.append(p)
        return p != "/private/tmp/cam"

    entries = privacy.read_tcc_entries("user", str(db), exists)
    assert len(entries) == 5  # the AddressBook row is not a reviewed service
    by = {(e.service, e.client): e for e in entries}
    zoom = by[(CAM, "us.zoom.xos")]
    assert zoom.allowed and zoom.client_type == 0 and zoom.exists is None and zoom.db == "user"
    assert zoom.last_modified == dt.datetime.fromtimestamp(T1, tz=UTC) and zoom.name == "us.zoom.xos"
    tmp = by[(CAM, "/private/tmp/cam")]
    assert tmp.allowed and tmp.client_type == 1 and tmp.exists is False and tmp.name == "cam"
    assert by[(MICS, "/usr/bin/python3")].exists is True and by[(MICS, "/usr/bin/python3")].name == "python3"
    assert not by[(MICS, "com.denied.app")].allowed
    assert not by[(CAM, "/Applications/Old.app/Contents/MacOS/Old")].allowed
    assert sorted(checked) == ["/private/tmp/cam", "/usr/bin/python3"]  # only allowed programs given by path hit the disk


def test_tcc_auth_value_semantics_follow_the_schema(tmp_path):
    new = make_tcc_db(tmp_path / "new.db", "new", [(CAM, "a", 0, True, T1), (CAM, "b", 0, False, T1)])
    with closing(sqlite3.connect(str(new))) as con:  # 3 = limited, 1 = unknown: neither is "allowed" in the new layout
        con.execute("INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version, last_modified) "
                    "VALUES (?,?,0,3,0,1,?)", (CAM, "limited", T1))
        con.execute("INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version, last_modified) "
                    "VALUES (?,?,0,1,0,1,?)", (CAM, "unknown", T1))
        con.commit()
    got = {e.client: e.allowed for e in privacy.read_tcc_entries("user", str(new), lambda p: True)}
    assert got == {"a": True, "b": False, "limited": False, "unknown": False}
    old = make_tcc_db(tmp_path / "old.db", "old", [(CAM, "a", 0, True, T1)])
    with closing(sqlite3.connect(str(old))) as con:  # 2 would be "allowed" in the new layout but is not in the old one
        con.execute("INSERT INTO access (service, client, client_type, allowed, prompt_count, last_modified) "
                    "VALUES (?,?,0,2,0,?)", (CAM, "two", T1))
        con.commit()
    got = {e.client: e.allowed for e in privacy.read_tcc_entries("user", str(old), lambda p: True)}
    assert got == {"a": True, "two": False}


def test_tcc_client_type_is_inferred_when_missing(tmp_path):
    db = tmp_path / "TCC.db"
    with closing(sqlite3.connect(str(db))) as con:  # a layout without client_type and last_modified
        con.execute("CREATE TABLE access (service TEXT, client TEXT, auth_value INTEGER)")
        con.execute("INSERT INTO access VALUES (?,?,2)", (CAM, "/tmp/x"))
        con.execute("INSERT INTO access VALUES (?,?,2)", (CAM, "com.vendor.app"))
        con.execute("INSERT INTO access VALUES (?,'',2)", (CAM,))  # empty client: ignored
        con.commit()
    got = {e.client: (e.client_type, e.last_modified) for e in privacy.read_tcc_entries("user", str(db), lambda p: True)}
    assert got == {"/tmp/x": (1, None), "com.vendor.app": (0, None)}


def test_tcc_database_is_opened_read_only_and_never_modified(tmp_path, monkeypatch):
    folder = tmp_path / "tcc"
    folder.mkdir()
    db = make_tcc_db(folder / "TCC.db", "new", USER_ROWS)
    before = db.read_bytes()
    calls = []
    real = sqlite3.connect

    def spy(*args, **kw):
        calls.append((args, kw))
        return real(*args, **kw)

    monkeypatch.setattr(privacy.sqlite3, "connect", spy)
    assert privacy.read_tcc_rows(str(db))
    assert len(calls) == 1 and calls[0][1].get("uri") is True and calls[0][0][0].startswith("file:")
    assert calls[0][0][0].endswith("?mode=ro")
    assert db.read_bytes() == before
    assert [p.name for p in folder.iterdir()] == ["TCC.db"]  # no journal / copy left behind


def test_tcc_path_with_spaces_and_special_characters(tmp_path):
    folder = tmp_path / "Application Support" / "com.apple.TCC #1 %41 & it's+"  # legal on every OS, hostile to URIs
    folder.mkdir(parents=True)
    db = make_tcc_db(folder / "TCC.db", "new", USER_ROWS)
    assert len(privacy.read_tcc_rows(str(db))) == 5


def test_tcc_errors_become_typed_exceptions(tmp_path, monkeypatch):
    with pytest.raises(privacy.TccMissingError):
        privacy.read_tcc_rows(str(tmp_path / "nope.db"))
    junk = tmp_path / "junk.db"
    junk.write_bytes(b"this is not a sqlite database" * 50)
    with pytest.raises(privacy.TccAccessError):
        privacy.read_tcc_rows(str(junk))
    empty = tmp_path / "empty.db"
    with closing(sqlite3.connect(str(empty))) as con:
        con.execute("CREATE TABLE other (x INTEGER)")
        con.commit()
    with pytest.raises(privacy.TccSchemaError, match="no 'access' table"):
        privacy.read_tcc_rows(str(empty))
    odd = tmp_path / "odd.db"
    with closing(sqlite3.connect(str(odd))) as con:
        con.execute("CREATE TABLE access (service TEXT, client TEXT, client_type INTEGER)")
        con.commit()
    with pytest.raises(privacy.TccSchemaError, match="auth_value nor an allowed"):
        privacy.read_tcc_rows(str(odd))

    good = make_tcc_db(tmp_path / "TCC.db", "new", USER_ROWS)
    real_stat = os.stat

    def deny(path, *a, **kw):
        if str(path) == str(good):
            raise PermissionError(1, "Operation not permitted")
        return real_stat(path, *a, **kw)

    monkeypatch.setattr(privacy.os, "stat", deny)
    with pytest.raises(privacy.TccAccessError, match="PermissionError"):
        privacy.read_tcc_rows(str(good))


def test_tcc_sqlite_open_failure_is_an_access_error_without_a_copy_attempt(tmp_path, monkeypatch):
    db = make_tcc_db(tmp_path / "TCC.db", "new", USER_ROWS)
    calls = []

    def blocked(path, readonly=True):
        calls.append(readonly)
        raise sqlite3.OperationalError("unable to open database file")

    monkeypatch.setattr(privacy, "_read_access_table", blocked)
    with pytest.raises(privacy.TccAccessError, match="unable to open database file"):
        privacy.read_tcc_rows(str(db))
    assert calls == [True]


@pytest.mark.parametrize("message", ["database is locked", "database table is locked",
                                     "attempt to write a readonly database"])
def test_locked_tcc_database_falls_back_to_a_private_copy(tmp_path, monkeypatch, message):
    db = make_tcc_db(tmp_path / "TCC.db", "new", USER_ROWS)
    real = privacy._read_access_table
    calls = []

    def flaky(path, readonly=True):
        calls.append((path, readonly))
        if readonly:
            raise sqlite3.OperationalError(message)
        assert os.path.abspath(path) != os.path.abspath(str(db))  # the copy, never the original, is opened read-write
        return real(path, readonly=False)

    monkeypatch.setattr(privacy, "_read_access_table", flaky)
    rows = privacy.read_tcc_rows(str(db))
    assert len(rows) == 5 and [c[1] for c in calls] == [True, False]
    assert not os.path.exists(calls[1][0])  # the temporary copy is removed again

    def no_copy(path):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(privacy, "_read_copy", no_copy)
    with pytest.raises(privacy.TccAccessError, match="locked"):
        privacy.read_tcc_rows(str(db))


@pytest.mark.skipif(sys.platform.startswith("win"), reason="byte-range locks differ on Windows; the fallback is covered above")
def test_really_locked_tcc_database_is_read_from_a_copy(tmp_path, monkeypatch):
    db = make_tcc_db(tmp_path / "TCC.db", "new", USER_ROWS)
    monkeypatch.setattr(privacy, "TCC_TIMEOUT_S", 0.05)
    copies = []
    real_copy = privacy._read_copy
    monkeypatch.setattr(privacy, "_read_copy", lambda path: copies.append(path) or real_copy(path))
    holder = sqlite3.connect(str(db), timeout=0.05, isolation_level=None)
    holder.execute("BEGIN EXCLUSIVE")
    try:
        rows = privacy.read_tcc_rows(str(db))
    finally:
        holder.execute("ROLLBACK")
        holder.close()
    assert len(rows) == 5 and copies == [str(db)]  # the read-only open hit the lock, so the copy was used


# ---------------------------------------------------------------- macOS classifier
def entry(service, client, ctype=1, allowed=True, exists=True, mod=T1, db="user"):
    return privacy.TccEntry(service, client, ctype, allowed, privacy.unix_to_datetime(mod), db, exists)


@pytest.mark.parametrize("path", [
    "/tmp/helper", "/private/tmp/helper", "/var/folders/zz/abc/T/helper", "/private/var/folders/zz/abc/T/helper",
    "/Users/bob/Downloads/tool", "/Users/bob/Downloads/sub/tool", "/Users/Shared/tool", "/Users/bob/.hidden/tool",
    "/Users/bob/Library/.cache/x/tool", "/USERS/BOB/DOWNLOADS/TOOL",
])
def test_mac_staging_locations_are_flagged_by_severity_of_the_service(path):
    for service, sev in ((CAM, Severity.MEDIUM), (MICS, Severity.MEDIUM), (SCR, Severity.HIGH), (ACC, Severity.HIGH),
                         (LISTEN, Severity.HIGH), (POST, Severity.HIGH)):
        got = privacy.classify_tcc(entry(service, path))
        assert got is not None and got[0] == sev, (service, path)
        assert "it runs from" in got[1][0]


@pytest.mark.parametrize("name", ["osascript", "python", "python3", "python3.11", "Python", "perl", "perl5.34", "ruby", "bash",
                                  "sh", "zsh", "node"])
def test_mac_script_interpreters_are_flagged_even_in_normal_places(name):
    got = privacy.classify_tcc(entry(ACC, f"/usr/bin/{name}"))
    assert got is not None and got[0] == Severity.HIGH and "script interpreter" in got[1][0]
    assert privacy.classify_tcc(entry(CAM, f"/usr/local/bin/{name}"))[0] == Severity.MEDIUM


@pytest.mark.parametrize("path", [
    "/Applications/zoom.us.app/Contents/MacOS/zoom.us", "/System/Applications/FaceTime.app/Contents/MacOS/FaceTime",
    "/usr/local/bin/ffmpeg", "/Users/bob/Applications/Tool.app/Contents/MacOS/Tool", "/Users/bob/Desktop/mytool",
    "/Users/bob/Downloads", "/opt/homebrew/bin/obs", "/Users/bob/Library/Application Support/Foo/foo",
    "/Users/bob/Projects/.gitignore",  # a hidden *file* is not a hidden directory
    "/usr/bin/pythonista", "/usr/bin/nodejs-helper", "/usr/bin/shellcheck",
])
def test_mac_normal_programs_are_not_flagged(path):
    assert privacy.classify_tcc(entry(ACC, path)) is None
    assert privacy.classify_tcc(entry(CAM, path)) is None


def test_mac_bundle_ids_and_denied_entries_are_inventory_only():
    assert privacy.classify_tcc(entry(ACC, "com.evil.keylogger", ctype=0, exists=None)) is None
    assert privacy.classify_tcc(entry(CAM, "/tmp/x", allowed=False)) is None
    assert privacy.classify_tcc(entry("kTCCServiceAddressBook", "/tmp/x")) is None


def test_mac_missing_path_is_info_unless_it_was_in_a_staging_folder():
    got = privacy.classify_tcc(entry(CAM, "/Applications/Old.app/Contents/MacOS/Old", exists=False))
    assert got == (Severity.INFO, ["the program no longer exists on disk"], ["T1125"])
    got = privacy.classify_tcc(entry(LISTEN, "/private/tmp/x", exists=False))
    assert got[0] == Severity.HIGH and "the program was deleted after it was given access" in got[1]
    assert got[2] == ["T1056.001"]
    # a versioned folder (Homebrew Cellar, updaters) is ignored like on Windows
    assert privacy.classify_tcc(entry(CAM, "/opt/homebrew/Cellar/foo/1.2.3/bin/foo", exists=False)) is None
    assert privacy.classify_tcc(entry(CAM, "/Applications/Old.app/Contents/MacOS/Old", exists=None)) is None


@pytest.mark.parametrize("service,mitre", [
    (CAM, ["T1125"]), (MICS, ["T1123"]), (SCR, ["T1113"]), (ACC, ["T1056.001"]), (LISTEN, ["T1056.001"]), (POST, [])])
def test_mac_mitre_per_service(service, mitre):
    assert privacy.classify_tcc(entry(service, "/tmp/x"))[2] == mitre


def test_mac_finding_and_remediation():
    cap = privacy.MAC_BY_KEY[ACC]
    e = entry(ACC, "/private/tmp/helper", mod=T2)
    f = privacy.tcc_finding(cap, e, privacy.classify_tcc(e))
    assert f.rule_id == "AEG-PRIV-ACCESSIBILITY" and f.severity == Severity.HIGH and f.category == Category.PRIVACY
    assert f.location == "/private/tmp/helper" and f.mitre == ["T1056.001"] and "helper" in f.title
    assert f.evidence["capability"] == ACC and f.evidence["app"] == "/private/tmp/helper" and f.evidence["database"] == "user"
    assert f.evidence["exists_on_disk"] is True and f.evidence["client_type"] == "path"
    assert dt.datetime.fromisoformat(f.evidence["permission_last_modified"]) == dt.datetime.fromtimestamp(T2, tz=UTC)
    assert "Privacy & Security > Accessibility" in f.recommendation and "keyloggers" in f.description
    assert f.remediation.action == "quarantine_file" and f.remediation.params == {"path": "/private/tmp/helper"}
    json.dumps(f.to_dict())
    # system interpreters / installed apps are never quarantined; missing files cannot be
    for path, exists, fix in (("/usr/bin/python3", True, False), ("/bin/bash", True, False),
                              ("/Users/bob/Downloads/python3", True, True), ("/tmp/x", False, False), ("/tmp/x", None, False),
                              ("/Users/bob/.hidden/node", True, True)):
        e = entry(ACC, path, exists=exists)
        assert (privacy.tcc_finding(cap, e, privacy.classify_tcc(e)).remediation is not None) is fix, path
    info = entry(CAM, "/Applications/Old.app/Contents/MacOS/Old", exists=False)
    fi = privacy.tcc_finding(privacy.MAC_BY_KEY[CAM], info, privacy.classify_tcc(info))
    assert fi.severity == Severity.INFO and fi.remediation is None and "no longer on disk" in fi.title


def test_review_tcc_inventory_and_check():
    cap = privacy.MAC_BY_KEY[CAM]
    entries = [entry(CAM, "us.zoom.xos", ctype=0, exists=None, mod=T1), entry(CAM, "/private/tmp/cam", mod=T2),
               entry(CAM, "com.denied.app", ctype=0, allowed=False, exists=None), entry(MICS, "/tmp/mic")]
    check, findings = privacy.review_tcc(cap, entries)
    assert check.status == CheckStatus.FAIL and check.check_id == "AEG-PRIV-CAMERA" and "cam" in check.detail
    assert "2 apps are allowed to use the camera" in check.detail
    (inv,) = [f for f in findings if f.rule_id.endswith("-INVENTORY")]
    assert inv.title == "2 apps are allowed to use the camera" and inv.severity == Severity.INFO
    assert inv.location == f"TCC.db / {CAM}" and inv.evidence["total"] == 2
    assert [a["app"] for a in inv.evidence["apps"]] == ["/private/tmp/cam", "us.zoom.xos"]  # most recently changed first
    assert inv.evidence["apps"][0]["client_type"] == "path" and inv.evidence["apps"][1]["client_type"] == "bundle id"
    assert [f.rule_id for f in findings].count("AEG-PRIV-CAMERA") == 1
    # clean service, and one with nothing at all
    ok, fs = privacy.review_tcc(cap, [entries[0]], skipped=["system"])
    assert ok.status == CheckStatus.PASS and "Not examined: the system database" in ok.detail
    assert [f.rule_id for f in fs] == ["AEG-PRIV-CAMERA-INVENTORY"]
    assert fs[0].title == "1 app is allowed to use the camera"
    none, fs = privacy.review_tcc(cap, [])
    assert none.status == CheckStatus.PASS and fs == []


def test_review_tcc_dedupes_user_and_system_entries():
    cap = privacy.MAC_BY_KEY[SCR]
    entries = [entry(SCR, "/private/tmp/rec", mod=T1, db="user"), entry(SCR, "/private/tmp/rec", mod=T3, db="system")]
    check, findings = privacy.review_tcc(cap, entries)
    bad = [f for f in findings if f.severity >= Severity.MEDIUM]
    assert len(bad) == 1 and bad[0].evidence["database"] == "system" and bad[0].severity == Severity.HIGH
    assert [f for f in findings if f.rule_id.endswith("-INVENTORY")][0].evidence["total"] == 1


# ---------------------------------------------------------------- scanner on (mocked) macOS
@pytest.fixture
def mac(tmp_path, monkeypatch):
    monkeypatch.setattr(privacy, "IS_WINDOWS", False)
    monkeypatch.setattr(privacy, "IS_MAC", True)
    (tmp_path / "user").mkdir()
    (tmp_path / "system").mkdir()
    user = make_tcc_db(tmp_path / "user" / "TCC.db", "new", USER_ROWS)
    system = make_tcc_db(tmp_path / "system" / "TCC.db", "old", [
        (ACC, "/Users/Shared/remote", 1, True, T3), (ACC, "com.apple.Terminal", 0, True, T1),
        (LISTEN, "/usr/bin/osascript", 1, True, T2), (SCR, "us.zoom.xos", 0, True, T1),
        (CAM, "/private/tmp/cam", 1, True, T1)])  # also in the user database
    monkeypatch.setattr(privacy, "tcc_database_paths", lambda: [("user", str(user)), ("system", str(system))])
    monkeypatch.setattr(privacy, "_path_exists", lambda p: p != "/private/tmp/cam")
    return user, system


def test_scanner_macos_flow(ctx, mac):
    out = list(privacy.PrivacyScanner().run(ctx))
    findings, checks = split(out)
    by_id = {c.check_id: c for c in checks}
    assert set(by_id) == {"AEG-PRIV-CAMERA", "AEG-PRIV-MICROPHONE", "AEG-PRIV-SCREEN", "AEG-PRIV-ACCESSIBILITY",
                          "AEG-PRIV-INPUT-MONITORING", "AEG-PRIV-SYNTHETIC-INPUT"}
    assert by_id["AEG-PRIV-CAMERA"].status == CheckStatus.FAIL and by_id["AEG-PRIV-MICROPHONE"].status == CheckStatus.FAIL
    assert by_id["AEG-PRIV-SCREEN"].status == CheckStatus.PASS and by_id["AEG-PRIV-SYNTHETIC-INPUT"].status == CheckStatus.PASS
    assert by_id["AEG-PRIV-ACCESSIBILITY"].status == CheckStatus.FAIL
    assert by_id["AEG-PRIV-INPUT-MONITORING"].status == CheckStatus.FAIL
    sev = {(f.rule_id, f.location): f.severity for f in findings if not f.rule_id.endswith("-INVENTORY")}
    assert sev == {("AEG-PRIV-CAMERA", "/private/tmp/cam"): Severity.MEDIUM,  # missing, but it sat in /private/tmp
                   ("AEG-PRIV-MICROPHONE", "/usr/bin/python3"): Severity.MEDIUM,
                   ("AEG-PRIV-ACCESSIBILITY", "/Users/Shared/remote"): Severity.HIGH,
                   ("AEG-PRIV-INPUT-MONITORING", "/usr/bin/osascript"): Severity.HIGH}
    cam = [f for f in findings if f.location == "/private/tmp/cam"][0]
    assert "the program was deleted after it was given access" in cam.evidence["reasons"] and cam.remediation is None
    inv = {f.rule_id: f for f in findings if f.rule_id.endswith("-INVENTORY")}
    assert inv["AEG-PRIV-CAMERA-INVENTORY"].title == "2 apps are allowed to use the camera"
    assert inv["AEG-PRIV-ACCESSIBILITY-INVENTORY"].title == "2 apps are allowed to use Accessibility (control of the computer)"
    assert inv["AEG-PRIV-SCREEN-INVENTORY"].evidence["apps"][0]["client_type"] == "bundle id"
    assert "AEG-PRIV-SYNTHETIC-INPUT-INVENTORY" not in inv  # nobody has that permission
    assert all(c.category == Category.PRIVACY for c in checks)
    assert ctx.stats["privacy_records"] == 10 and ctx.stats["privacy_flagged"] == 4
    json.dumps([x.to_dict() for x in out])


def test_scanner_macos_permission_error_is_a_skip_that_explains_full_disk_access(ctx, mac, monkeypatch):
    def blocked(path, readonly=True):
        raise sqlite3.OperationalError("unable to open database file")

    monkeypatch.setattr(privacy, "_read_access_table", blocked)
    out = list(privacy.PrivacyScanner().run(ctx))
    assert all(isinstance(x, CheckResult) for x in out)  # nothing else is emitted
    assert [(c.check_id, c.status) for c in out] == [("AEG-PRIV-TCC-USER", CheckStatus.SKIP),
                                                     ("AEG-PRIV-TCC-SYSTEM", CheckStatus.SKIP)]
    for c in out:
        assert "Full Disk Access" in c.detail and "run the scan again" in c.detail and "unable to open" in c.detail


def test_scanner_macos_one_unreadable_database_still_reports_the_other(ctx, mac, monkeypatch):
    user, system = mac
    real = privacy._read_access_table

    def only_user(path, readonly=True):
        if str(path) == str(system):
            raise PermissionError(1, "Operation not permitted")
        return real(path, readonly)

    monkeypatch.setattr(privacy, "_read_access_table", only_user)
    findings, checks = split(privacy.PrivacyScanner().run(ctx))
    by_id = {c.check_id: c for c in checks}
    assert by_id["AEG-PRIV-TCC-SYSTEM"].status == CheckStatus.SKIP and "Full Disk Access" in by_id["AEG-PRIV-TCC-SYSTEM"].detail
    assert "AEG-PRIV-TCC-USER" not in by_id
    assert by_id["AEG-PRIV-CAMERA"].status == CheckStatus.FAIL and "Not examined: the system database" in by_id["AEG-PRIV-CAMERA"].detail
    assert "AEG-PRIV-ACCESSIBILITY" in by_id  # reviewed (nothing found in the readable database)


def test_scanner_macos_missing_and_odd_databases_skip_without_the_permission_advice(ctx, mac, tmp_path, monkeypatch):
    odd = tmp_path / "odd.db"
    with closing(sqlite3.connect(str(odd))) as con:
        con.execute("CREATE TABLE other (x INTEGER)")
        con.commit()
    monkeypatch.setattr(privacy, "tcc_database_paths", lambda: [("user", str(tmp_path / "missing.db")), ("system", str(odd))])
    out = list(privacy.PrivacyScanner().run(ctx))
    assert [(c.check_id, c.status) for c in out] == [("AEG-PRIV-TCC-USER", CheckStatus.SKIP),
                                                     ("AEG-PRIV-TCC-SYSTEM", CheckStatus.SKIP)]
    assert "was not found" in out[0].detail and "unknown layout" in out[1].detail
    assert not any("Full Disk Access" in c.detail for c in out)


def test_scanner_macos_unexpected_error_is_an_error_check(ctx, mac, monkeypatch):
    def boom(path, readonly=True):
        raise RuntimeError("boom")

    monkeypatch.setattr(privacy, "_read_access_table", boom)
    out = list(privacy.PrivacyScanner().run(ctx))
    assert [c.status for c in out] == [CheckStatus.ERROR, CheckStatus.ERROR] and "RuntimeError" in out[0].detail


def test_tcc_database_paths_point_at_the_user_and_system_databases(monkeypatch):
    monkeypatch.setenv("HOME", "/Users/bob")
    monkeypatch.setenv("USERPROFILE", "C:\\Users\\bob")
    (u_label, u_path), (s_label, s_path) = privacy.tcc_database_paths()
    assert (u_label, s_label) == ("user", "system")
    assert u_path.replace("\\", "/").endswith("/Library/Application Support/com.apple.TCC/TCC.db") and "~" not in u_path
    assert s_path == "/Library/Application Support/com.apple.TCC/TCC.db"


# ---------------------------------------------------------------- registration
def test_scanner_registered_and_in_the_full_profile():
    from aegis.core.engine import PROFILES

    load_all()
    cls = REGISTRY["privacy"]
    assert cls.name == "privacy" and cls.title == "Camera, microphone & screen access review" and cls.description
    assert set(cls.platforms) == {"windows", "linux", "darwin"} and cls().supported()
    assert PROFILES["full"][-1] == "privacy" and PROFILES["full"].count("privacy") == 1
    assert "privacy" not in PROFILES["quick"] and "privacy" not in PROFILES["audit"]
