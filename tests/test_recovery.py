"""Unit tests for aegis.scanners.recovery: timestamp parsing, the Windows PowerShell facts and registry readers (canned JSON
and a fake registry), File History / OneDrive / Google Drive / Dropbox detection (fake registry + temporary folders), the
macOS tmutil / defaults parsers, Linux tool detection (temporary home and root folders), the readiness grade and the scanner
flow. Every command runner, registry reader and folder is injected or monkeypatched, so everything runs on any OS."""

import datetime as dt
import json
import os
from pathlib import Path

import pytest

from aegis.core.models import Category, CheckResult, CheckStatus, Finding, Severity
from aegis.scanners import recovery as rc
from aegis.scanners.base import REGISTRY, load_all

UTC = dt.timezone.utc
NOW = dt.datetime(2026, 10, 16, 12, 0, tzinfo=UTC)
CV = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"


def ago(**kw) -> dt.datetime:
    return NOW - dt.timedelta(**kw)


def zulu(when: dt.datetime) -> str:
    """What the PowerShell script prints: ``ToUniversalTime().ToString('o')``."""
    return when.strftime("%Y-%m-%dT%H:%M:%S.") + "0000000Z"


def wall(when: dt.datetime, fmt: str) -> str:
    """Local wall-clock text of an instant, the way Time Machine, Timeshift and snapper name their backups."""
    return when.astimezone().strftime(fmt)


def ft(when: dt.datetime) -> int:
    delta = when - dt.datetime(1601, 1, 1, tzinfo=UTC)
    return (delta.days * 86400 + delta.seconds) * 10_000_000


def rules(findings):
    return [f.rule_id for f in findings]


def split(out):
    out = list(out)
    return [x for x in out if isinstance(x, Finding)], [x for x in out if isinstance(x, CheckResult)]


class FakeReg:
    """Dict-backed stand-in for reg_read / reg_values / reg_subkeys (case-insensitive, like the real registry)."""

    def __init__(self):
        self.keys = {}  # (hive, lower path) -> (path as written, {value: data})

    def add(self, hive, path, values=None, **kw):
        parts = path.split("\\")
        for i in range(1, len(parts) + 1):
            sub = "\\".join(parts[:i])
            self.keys.setdefault((hive.upper(), sub.lower()), (sub, {}))
        self.keys[(hive.upper(), path.lower())][1].update(values or {})
        self.keys[(hive.upper(), path.lower())][1].update(kw)
        return self

    def read(self, hive, key, value, view64=True):
        vals = self.keys.get((hive.upper(), key.lower()), ("", {}))[1]
        return next((v for k, v in vals.items() if k.lower() == value.lower()), None)

    def values(self, hive, key, view64=True):
        return dict(self.keys.get((hive.upper(), key.lower()), ("", {}))[1])

    def subkeys(self, hive, key, view64=True):
        prefix = key.lower() + "\\"
        return [orig.rsplit("\\", 1)[-1] for (h, low), (orig, _v) in self.keys.items()
                if h == hive.upper() and low.startswith(prefix) and "\\" not in low[len(prefix):]]

    def install(self, monkeypatch):
        monkeypatch.setattr(rc, "reg_read", self.read)
        monkeypatch.setattr(rc, "reg_values", self.values)
        monkeypatch.setattr(rc, "reg_subkeys", self.subkeys)
        return self


class FakeRun:
    """Command runner: the first (prefix, (rc, out, err)) whose prefix starts the command answers; everything else is
    'not found' (return code -1, like platform.run for a missing binary). Every call is recorded."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.calls = []

    def __call__(self, cmd, timeout=60, input_text=None):
        self.calls.append((list(cmd), timeout))
        for prefix, result in self.answers:
            if list(cmd[:len(prefix)]) == list(prefix):
                return result
        return -1, "", f"not found: {cmd[0]}"

    @property
    def commands(self):
        return [c for c, _t in self.calls]


class FakePS:
    def __init__(self, data):
        self.data = data
        self.calls = []

    def __call__(self, script, timeout=90):
        self.calls.append((script, timeout))
        return self.data


# ---------------------------------------------------------------- timestamps
def test_parse_timestamp_zones_and_fractions():
    assert rc.parse_timestamp("2026-10-14T08:00:00.1234567Z") == dt.datetime(2026, 10, 14, 8, 0, 0, 123456, tzinfo=UTC)
    assert rc.parse_timestamp("2026-10-14T08:00:00Z") == dt.datetime(2026, 10, 14, 8, tzinfo=UTC)
    assert rc.parse_timestamp("2026-10-14 08:00:00 +0200") == dt.datetime(2026, 10, 14, 6, tzinfo=UTC)
    assert rc.parse_timestamp("2026-10-14T08:00:00+02:00") == dt.datetime(2026, 10, 14, 6, tzinfo=UTC)
    assert rc.parse_timestamp("2026-10-14T08:00:00-05:30") == dt.datetime(2026, 10, 14, 13, 30, tzinfo=UTC)
    assert rc.parse_timestamp("2026-10-14 08:00:00 +0000") == dt.datetime(2026, 10, 14, 8, tzinfo=UTC)
    assert rc.parse_timestamp("  2026-10-14T08:00:00Z  ").tzinfo is not None


def test_parse_timestamp_without_zone_is_local_time():
    got = rc.parse_timestamp("2026-10-14T08:30:00")
    assert got == dt.datetime(2026, 10, 14, 8, 30).astimezone(UTC) and got.tzinfo is not None


@pytest.mark.parametrize("value", [None, "", "x", 5, b"2026-10-14T08:00:00Z", "2026-13-14T08:00:00Z", "2026-10-32T08:00:00Z",
                                   "2026-10-14T25:00:00Z", "1999-12-31T23:59:59Z", "2100-01-01T00:00:00Z", "2026-10-14",
                                   "'2026-10-14T08:00:00Z'"])
def test_parse_timestamp_rejects_garbage_and_absurd_years(value):
    assert rc.parse_timestamp(value) is None


def test_filetime_and_registry_time():
    when = dt.datetime(2026, 10, 14, 8, 0, tzinfo=UTC)
    assert rc.filetime_to_datetime(ft(when)) == when
    assert rc.filetime_to_datetime(ft(when).to_bytes(8, "little")) == when
    assert rc.filetime_to_datetime(bytearray(ft(when).to_bytes(8, "little"))) == when
    for bad in (0, -1, None, True, b"", b"\x01\x02", 2 ** 64 - 1, "x", float("nan"), [], 116444736000000000):
        assert rc.filetime_to_datetime(bad) is None
    assert rc.parse_registry_time(ft(when)) == when
    assert rc.parse_registry_time(str(ft(when))) == when  # REG_SZ holding the number
    assert rc.parse_registry_time("2026-10-14T08:00:00Z") == when
    assert rc.parse_registry_time("not a time") is None and rc.parse_registry_time(None) is None


def test_small_helpers():
    assert rc._int(True) == 1 and rc._int("0x10") == 16 and rc._int(" 7 ") == 7 and rc._int(b"1") is None
    assert rc._int(None) is None and rc._int("x") is None and rc._int([]) is None
    assert rc._when(None, NOW) == "at an unknown time"
    assert rc._when(NOW, NOW) == "2026-10-16 (today)" and rc._when(ago(days=1), NOW) == "2026-10-15 (1 day ago)"
    assert rc._when(NOW + dt.timedelta(days=3), NOW) == "2026-10-19 (today)"  # a clock that runs ahead is not "-3 days"
    assert rc._short("a  b\n c" * 40, 30).endswith("...") and len(rc._short("a  b\n c" * 40, 30)) == 30
    assert rc.newest_of() is None and rc.newest_of(None, ago(days=1), ago(days=2)) == ago(days=1)
    assert rc._get({"Foo": 1}, "foo") == 1 and rc._get({"Foo": 1}, "bar") is None
    assert rc._mtime(Path("/definitely/not/here")) is None


# ---------------------------------------------------------------- Windows: PowerShell facts
GOOD_FACTS = {"os": {"caption": "Microsoft Windows 11 Pro", "product_type": 1}, "drive": "C:",
              "restore": {"supported": True, "count": 3, "newest": zulu(ago(days=4)), "newest_name": "Windows Update"},
              "shadow": {"count": 2, "total": 5, "newest": zulu(ago(days=2))}}


def test_parse_windows_facts_full_answer():
    f = rc.parse_windows_facts(GOOD_FACTS)
    assert f.available and f.drive == "C:" and f.product_type == 1 and f.restore_supported
    assert f.restore_count == 3 and f.restore_newest == ago(days=4) and f.restore_error == ""
    assert f.shadow_count == 2 and f.shadow_newest == ago(days=2) and f.shadow_error == ""


def test_parse_windows_facts_access_denied_and_odd_input():
    f = rc.parse_windows_facts({"drive": "d:\\", "restore": {"supported": True, "error": "Access is denied."},
                                "shadow": {"error": "Access denied "}})
    assert f.available and f.drive == "D:" and f.restore_count is None and f.restore_error == "Access is denied."
    assert f.shadow_count is None and f.shadow_error == "Access denied"
    for junk in (None, {}, [], "text", 5):
        f = rc.parse_windows_facts(junk)
        assert not f.available and f.restore_count is None and f.drive == "C:"
    f = rc.parse_windows_facts({"drive": "network", "os": "x", "restore": [1], "shadow": {"count": "many"}})
    assert f.drive == "C:" and f.product_type is None and f.restore_count is None and f.shadow_count is None
    assert rc.parse_windows_facts({"restore": {"supported": False}}).restore_supported is False


def test_collect_windows_facts_is_one_powershell_call_with_a_timeout():
    ps = FakePS(GOOD_FACTS)
    facts = rc.collect_windows_facts(ps)
    assert facts.restore_count == 3 and len(ps.calls) == 1
    script, timeout = ps.calls[0]
    assert timeout == rc.PS_TIMEOUT_S and "ConvertTo-Json" in script
    assert "Get-ComputerRestorePoint" in script and "Win32_ShadowCopy" in script
    assert not rc.collect_windows_facts(FakePS(None)).available


def test_powershell_script_is_read_only():
    low = rc._PS_FACTS.lower()
    for verb in ("checkpoint-computer", "enable-computerrestore", "disable-computerrestore", "restore-computer", "vssadmin",
                 "remove-", "delete", "resize", "set-", "new-", "wmic", "diskshadow"):
        assert verb not in low, verb


# ---------------------------------------------------------------- Windows: registry switch and server SKU
SR = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore"
SR_POLICY = r"SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore"


def test_system_restore_setting_from_registry():
    def setting(*sets):
        reg = FakeReg()
        for key, name, value in sets:
            reg.add("HKLM", key, {name: value})
        return rc.read_system_restore_setting(reg.read)

    assert setting() == rc.SystemRestoreSetting(None, "")
    assert setting((SR, "RPSessionInterval", 1)) == rc.SystemRestoreSetting(True, "")
    assert setting((SR, "RPSessionInterval", 0)) == rc.SystemRestoreSetting(False, "local setting")
    assert setting((SR, "DisableSR", 1)) == rc.SystemRestoreSetting(False, "local setting")
    assert setting((SR, "DisableSR", 0), (SR, "RPSessionInterval", 1)).enabled is True
    pol = setting((SR_POLICY, "DisableSR", 1), (SR, "RPSessionInterval", 1))
    assert pol == rc.SystemRestoreSetting(False, "group policy")  # the policy wins over a local "on"
    assert setting((SR, "RPSessionInterval", "0")).enabled is False  # REG_SZ numbers are read too


@pytest.mark.parametrize("values,product_type,server", [
    ({"InstallationType": "Server"}, None, True),
    ({"InstallationType": "Server Core"}, None, True),
    ({"EditionID": "ServerStandard"}, None, True),
    ({"ProductName": "Windows Server 2022 Datacenter"}, None, True),
    ({"InstallationType": "Client", "EditionID": "Professional", "ProductName": "Windows 11 Pro"}, 1, False),
    ({}, 3, True), ({}, 2, True), ({}, 1, False), ({}, None, False),
])
def test_is_windows_server(values, product_type, server):
    reg = FakeReg().add("HKLM", CV, values)
    facts = rc.WindowsFacts(available=True, product_type=product_type) if product_type is not None else None
    assert rc.is_windows_server(facts, reg.read) is server


# ---------------------------------------------------------------- Windows: restore point assessment
def facts_for(restore=None, shadow=None, restore_err="", shadow_err="", restore_new=None, shadow_new=None, **kw):
    return rc.WindowsFacts(available=True, restore_count=restore, restore_newest=restore_new, restore_error=restore_err,
                           shadow_count=shadow, shadow_newest=shadow_new, shadow_error=shadow_err, **kw)


ON, OFF = rc.SystemRestoreSetting(True), rc.SystemRestoreSetting(False, "local setting")
UNSET = rc.SystemRestoreSetting()


def test_protection_off_is_medium_with_exact_steps_and_no_remediation():
    layer, findings = rc.assess_restore(facts_for(0, 0), OFF, True, False, NOW)
    (f,) = findings
    assert f.rule_id == "AEG-RECOVERY-RESTORE-OFF" and f.severity == Severity.MEDIUM
    assert f.category == Category.RANSOMWARE and f.mitre == ["T1490"] and f.location == "System Protection (C:)"
    assert "turned off" in f.title and f.remediation is None
    for needle in ("Enable-ComputerRestore -Drive \"C:\\\"", "Checkpoint-Computer", "Create a restore point", "System Protection",
                   "Max Usage"):
        assert needle in f.recommendation
    assert "ransomware" in f.description.lower() and "Good looks like" in f.description
    assert f.evidence["system_protection"] is False and f.evidence["protection_setting_source"] == "local setting"
    assert layer.state == rc.MISSING and layer.severity == Severity.MEDIUM and layer_status(layer) == CheckStatus.FAIL


def layer_status(layer):
    return rc.layer_check(layer).status


def test_protection_off_by_group_policy_says_so():
    _, (f,) = rc.assess_restore(facts_for(0, 0), rc.SystemRestoreSetting(False, "group policy"), True, False, NOW)
    assert "Group Policy" in f.description and "Turn off System Restore" in f.recommendation and f.remediation is None
    assert f.evidence["protection_setting_source"] == "group policy"


def test_protection_off_is_reported_without_administrator_rights():
    layer, findings = rc.assess_restore(facts_for(None, None, "Access is denied.", "Access denied"), OFF, False, False, NOW)
    assert rules(findings) == ["AEG-RECOVERY-RESTORE-OFF"] and layer.state == rc.MISSING


def test_drive_letter_comes_from_the_facts():
    _, (f,) = rc.assess_restore(facts_for(0, 0, drive="D:"), OFF, True, False, NOW)
    assert f.location == "System Protection (D:)" and 'Enable-ComputerRestore -Drive "D:\\"' in f.recommendation


def test_recent_restore_point_and_shadow_copies_are_ok():
    layer, findings = rc.assess_restore(facts_for(3, 2, restore_new=ago(days=4), shadow_new=ago(days=2)), ON, True, False, NOW)
    assert findings == [] and layer.state == rc.OK and layer.newest == ago(days=2)
    assert "3 restore points" in layer.detail and "2 shadow copies" in layer.detail and "2 days ago" in layer.detail
    assert layer_status(layer) == CheckStatus.PASS


@pytest.mark.parametrize("age,stale", [(0, False), (29, False), (30, False), (31, True), (45, True), (400, True)])
def test_restore_point_age_threshold(age, stale):
    layer, findings = rc.assess_restore(facts_for(1, 0, restore_new=ago(days=age)), ON, True, False, NOW)
    assert (layer.state == rc.STALE) is stale and bool(findings) is stale
    if stale:
        (f,) = findings
        assert f.rule_id == "AEG-RECOVERY-RESTORE-STALE" and f.severity == Severity.LOW and f.mitre == ["T1490"]
        assert f"{age} days old" in f.title and f.remediation is None and "Checkpoint-Computer" in f.recommendation
        assert layer_status(layer) == CheckStatus.WARN


def test_the_newest_of_restore_points_and_shadow_copies_counts():
    layer, findings = rc.assess_restore(facts_for(2, 1, restore_new=ago(days=90), shadow_new=ago(days=3)), ON, True, False, NOW)
    assert findings == [] and layer.state == rc.OK and layer.newest == ago(days=3)


def test_nothing_at_all_as_administrator_is_medium():
    layer, findings = rc.assess_restore(facts_for(0, 0), ON, True, False, NOW)
    (f,) = findings
    assert f.rule_id == "AEG-RECOVERY-RESTORE-NONE" and f.severity == Severity.MEDIUM and f.mitre == ["T1490"]
    assert "No restore point" in f.title and "vssadmin delete shadows" in f.description and "Checkpoint-Computer" in f.recommendation
    assert f.evidence["restore_points"] == 0 and f.evidence["shadow_copies"] == 0 and f.evidence["checked_as_administrator"]
    assert layer.state == rc.MISSING and layer_status(layer) == CheckStatus.FAIL
    # protection that the registry does not mention is still reported when both lists are empty
    assert rules(rc.assess_restore(facts_for(0, 0), UNSET, True, False, NOW)[1]) == ["AEG-RECOVERY-RESTORE-NONE"]


def test_one_empty_readable_source_is_enough_to_report_none():
    layer, findings = rc.assess_restore(facts_for(0, None, shadow_err="WMI broke"), ON, True, False, NOW)
    assert rules(findings) == ["AEG-RECOVERY-RESTORE-NONE"] and layer.state == rc.MISSING
    assert findings[0].evidence["shadow_copies_not_checked"] is True


def test_without_administrator_rights_an_empty_answer_is_not_a_problem():
    for restore, shadow, r_err, s_err in ((0, 0, "", ""), (None, None, "Access is denied.", "Access denied"),
                                          (None, 0, "Access is denied.", "")):
        layer, findings = rc.assess_restore(facts_for(restore, shadow, r_err, s_err), ON, False, False, NOW)
        assert findings == [] and layer.state == rc.UNKNOWN
        assert "Not checked without administrator rights" in layer.detail and "switched on" in layer.detail
        assert layer_status(layer) == CheckStatus.SKIP
    layer, _ = rc.assess_restore(facts_for(0, 0), UNSET, False, False, NOW)
    assert "switched on" not in layer.detail


def test_restore_points_found_without_administrator_rights_still_count():
    layer, findings = rc.assess_restore(facts_for(2, 0, restore_new=ago(days=5)), ON, False, False, NOW)
    assert findings == [] and layer.state == rc.OK
    assert "shadow copies not checked without administrator rights" in layer.detail
    layer, findings = rc.assess_restore(facts_for(2, 0, restore_new=ago(days=50)), ON, False, False, NOW)
    assert layer.state == rc.STALE and rules(findings) == ["AEG-RECOVERY-RESTORE-STALE"]


def test_one_unreadable_source_is_named_in_the_detail():
    layer, findings = rc.assess_restore(facts_for(None, 2, "Access denied", shadow_new=ago(days=3)), ON, True, False, NOW)
    assert findings == [] and layer.state == rc.OK and "restore points could not be read" in layer.detail
    layer, _ = rc.assess_restore(facts_for(None, 2, "Access denied", shadow_new=ago(days=3)), ON, False, False, NOW)
    assert "restore points not checked without administrator rights" in layer.detail


def test_restore_point_with_an_unparsable_date_is_still_a_restore_point():
    layer, findings = rc.assess_restore(facts_for(1, 0), ON, True, False, NOW)
    assert findings == [] and layer.state == rc.OK and layer.newest is None and "unknown time" in layer.detail


def test_administrator_read_errors_are_unknown_not_a_finding():
    layer, findings = rc.assess_restore(facts_for(None, None, "The WMI service is not running", "Provider load failure"),
                                        ON, True, False, NOW)
    assert findings == [] and layer.state == rc.UNKNOWN and "could not be read" in layer.detail
    assert "WMI service" in layer.detail
    layer, findings = rc.assess_restore(rc.WindowsFacts(), UNSET, True, False, NOW)  # PowerShell gave nothing
    assert findings == [] and layer.state == rc.UNKNOWN and "PowerShell returned no data" in layer.detail


def test_server_editions_are_skipped_with_an_explanation():
    for setting in (ON, OFF, UNSET):
        layer, findings = rc.assess_restore(facts_for(0, 0), setting, True, True, NOW)
        assert findings == [] and layer.state == rc.NA and "Windows Server" in layer.detail
        assert "Windows Server Backup" in layer.detail and layer_status(layer) == CheckStatus.SKIP


def test_missing_system_restore_command_is_skipped_unless_the_registry_says_off():
    facts = facts_for(restore_supported=False)
    layer, findings = rc.assess_restore(facts, UNSET, True, False, NOW)
    assert findings == [] and layer.state == rc.NA and "Get-ComputerRestorePoint" in layer.detail
    assert rules(rc.assess_restore(facts, OFF, True, False, NOW)[1]) == ["AEG-RECOVERY-RESTORE-OFF"]


def test_check_windows_restore_runs_ps_once_and_shares_the_server_flag():
    ps = FakePS(dict(GOOD_FACTS, os={"product_type": 3}))
    reg = FakeReg().add("HKLM", SR, RPSessionInterval=1)
    shared = {}
    layers, findings = rc.check_windows_restore(True, NOW, ps, reg.read, shared)
    assert len(ps.calls) == 1 and shared["server"] is True and isinstance(shared["facts"], rc.WindowsFacts)
    assert [l.state for l in layers] == [rc.NA] and findings == []

    ps = FakePS(GOOD_FACTS)
    layers, findings = rc.check_windows_restore(True, NOW, ps, reg.read, shared)
    assert shared["server"] is False and layers[0].state == rc.OK

    def boom(script, timeout=90):
        raise OSError("powershell.exe is blocked")

    layers, findings = rc.check_windows_restore(False, NOW, boom, FakeReg().add("HKLM", SR, RPSessionInterval=0).read)
    assert rules(findings) == ["AEG-RECOVERY-RESTORE-OFF"]  # the registry part survives a dead PowerShell


# ---------------------------------------------------------------- Windows: File History
FH = r"Software\Microsoft\Windows\CurrentVersion\FileHistory"
FH_POLICY = r"SOFTWARE\Policies\Microsoft\Windows\FileHistory"


def detect_fh(values=None, policy=None):
    reg = FakeReg()
    if values is not None:
        reg.add("HKCU", FH, values)
    if policy is not None:
        reg.add("HKLM", FH_POLICY, Disabled=policy)
    return rc.detect_file_history(reg.values, reg.read)


def test_file_history_detection():
    assert detect_fh() == rc.FileHistoryState()
    s = detect_fh({"ProtectedUpToTime": ft(ago(days=3))})
    assert s.configured and s.last_backup == ago(days=3) and s.enabled is None and not s.policy_disabled
    assert detect_fh({"ProtectedUpToTime": ft(ago(days=3)).to_bytes(8, "little")}).last_backup == ago(days=3)
    assert detect_fh({"protecteduptotime": zulu(ago(days=3))}).last_backup == ago(days=3)  # names are case-insensitive
    assert detect_fh({"ProvisionedTime": ft(ago(days=90))}).configured
    s = detect_fh({"Enabled": 0, "ProtectedUpToTime": ft(ago(days=3))})
    assert s.enabled is False and s.configured
    assert detect_fh({"Enabled": 1}).enabled is True
    assert detect_fh({"ProtectedUpToTime": "garbage"}).configured is False
    assert detect_fh({}, policy=1).policy_disabled and not detect_fh({}, policy=0).policy_disabled


def test_file_history_layer_states():
    L = lambda **kw: rc.file_history_layer(rc.FileHistoryState(**kw), NOW)  # noqa: E731
    assert L(policy_disabled=True, configured=True).state == rc.MISSING and "Group Policy" in L(policy_disabled=True).detail
    off = L(configured=True, enabled=False, last_backup=ago(days=5))
    assert off.state == rc.MISSING and "turned off" in off.detail and "5 days ago" in off.detail
    ok = L(configured=True, last_backup=ago(days=7))
    assert ok.state == rc.OK and "last backup" in ok.detail and ok.newest == ago(days=7)
    assert L(configured=True, last_backup=ago(days=30)).state == rc.OK and L(configured=True, last_backup=ago(days=31)).state == rc.STALE
    stale = L(configured=True, last_backup=ago(days=100))
    assert stale.state == rc.STALE and "100 days" in stale.hint
    unknown_time = L(configured=True, enabled=True)
    assert unknown_time.state == rc.OK and "did not report" in unknown_time.detail
    assert L().state == rc.MISSING and "not set up" in L().detail
    assert rc.file_history_layer(rc.FileHistoryState(), NOW, server=True).state == rc.NA


# ---------------------------------------------------------------- Windows: OneDrive, Google Drive, Dropbox
ONEDRIVE = r"Software\Microsoft\OneDrive\Accounts"
SHELL = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
ENV = {"USERPROFILE": r"C:\Users\bob"}


def onedrive(reg, env=ENV):
    return rc.detect_onedrive(reg.values, reg.subkeys, env)


def test_onedrive_known_folder_move_values():
    reg = FakeReg().add("HKCU", ONEDRIVE + r"\Personal", UserEmail="bob@example.com", KfmFoldersProtectedNow=3,
                        UserFolder=r"C:\Users\bob\OneDrive")
    p = onedrive(reg)
    assert p.name == "OneDrive" and p.covers_known_folders and "Known Folder Move" in p.detail
    assert p.evidence["kfm_folders_protected_now"] == 3 and p.evidence["signed_in"] is True
    assert "bob@example.com" not in json.dumps(p.evidence) + p.detail  # the address itself is never reported


def test_onedrive_signed_in_without_folder_backup_is_partial():
    reg = FakeReg().add("HKCU", ONEDRIVE + r"\Business1", UserEmail="bob@corp.example", KfmFoldersProtectedNow=0)
    p = onedrive(reg)
    assert p.name == "OneDrive" and not p.covers_known_folders and "not backed up to it" in p.detail
    assert p.evidence["folders_redirected_into_onedrive"] == []
    assert onedrive(FakeReg().add("HKCU", ONEDRIVE + r"\Personal", UserEmail="  ")) is None  # an empty account is no account


def test_onedrive_folders_redirected_through_shell_folders():
    reg = FakeReg().add("HKCU", SHELL, {"Desktop": r"%USERPROFILE%\OneDrive\Desktop",
                                        "{F42EE2D3-909F-4907-8871-4C22FC0BF756}": r"%USERPROFILE%\OneDrive - Contoso\Documents",
                                        "My Pictures": r"C:\Users\bob\Pictures"})
    p = onedrive(reg)
    assert p.covers_known_folders and p.evidence["folders_redirected_into_onedrive"] == ["Desktop", "Documents"]
    assert "Desktop, Documents" in p.detail
    plain = FakeReg().add("HKCU", SHELL, {"Desktop": r"%USERPROFILE%\Desktop", "Personal": r"%USERPROFILE%\Documents"})
    assert onedrive(plain) is None


def test_onedrive_redirect_by_account_folder_and_lookalikes():
    reg = FakeReg().add("HKCU", ONEDRIVE + r"\Personal", UserFolder=r"D:\Cloud\MyDrive")
    reg.add("HKCU", SHELL, {"Personal": r"D:\Cloud\MyDrive\Documents"})
    p = onedrive(reg)
    assert p and p.evidence["folders_redirected_into_onedrive"] == ["Documents"]
    for path in (r"C:\Users\bob\OneDriveBackup\Documents", r"C:\Users\bob\NotOneDrive\Desktop", r"C:\Users\bob\Documents\OneDrivers"):
        assert onedrive(FakeReg().add("HKCU", SHELL, {"Desktop": path})) is None, path
    assert onedrive(FakeReg()) is None
    assert rc._expand("%userprofile%\\x\\%MISSING%", {"USERPROFILE": "C:\\u"}) == "C:\\u\\x\\%MISSING%"


def test_google_drive_and_dropbox_are_found_by_folder_file_or_registry(tmp_path):
    home = tmp_path / "home"
    local, roaming = tmp_path / "Local", tmp_path / "Roaming"
    env = {"LOCALAPPDATA": str(local), "APPDATA": str(roaming)}
    empty = FakeReg()
    assert rc.detect_sync_clients(home, env, values=empty.values, subkeys=empty.subkeys) == []

    (home / "Dropbox").mkdir(parents=True)
    got = rc.detect_sync_clients(home, env, values=empty.values, subkeys=empty.subkeys)
    assert [p.name for p in got] == ["Dropbox"] and got[0].evidence["paths"] == [str(home / "Dropbox")]

    (local / "Google" / "DriveFS").mkdir(parents=True)
    got = rc.detect_sync_clients(home, env, values=empty.values, subkeys=empty.subkeys)
    assert [p.name for p in got] == ["Dropbox", "Google Drive"] and all(not p.covers_known_folders for p in got)

    (home / "Dropbox").rmdir()
    (roaming / "Dropbox").mkdir(parents=True)
    (roaming / "Dropbox" / "info.json").write_text("{}")
    assert [p.name for p in rc.detect_sync_clients(home, env, values=empty.values, subkeys=empty.subkeys)] == ["Dropbox",
                                                                                                              "Google Drive"]

    only_reg = FakeReg().add("HKCU", r"Software\Dropbox\ks", Version=1)
    got = rc.detect_sync_clients(tmp_path / "nobody", {"LOCALAPPDATA": str(tmp_path / "x"), "APPDATA": str(tmp_path / "y")},
                                 values=only_reg.values, subkeys=only_reg.subkeys)
    assert [p.name for p in got] == ["Dropbox"] and got[0].evidence["registry_key"] == r"HKCU\Software\Dropbox"
    drive_reg = FakeReg().add("HKCU", r"Software\Google\DriveFS", Share=1)
    got = rc.detect_sync_clients(tmp_path / "nobody", {"LOCALAPPDATA": str(tmp_path / "x"), "APPDATA": str(tmp_path / "y")},
                                 values=drive_reg.values, subkeys=drive_reg.subkeys)
    assert [p.name for p in got] == ["Google Drive"]


def test_sync_client_paths_are_checked_with_the_injected_exists():
    asked = []

    def exists(path):
        asked.append(path)
        return path.endswith("info.json") and "Roaming" in path

    empty = FakeReg()
    got = rc.detect_sync_clients(Path("/nobody"), {"LOCALAPPDATA": "/L", "APPDATA": "/Roaming"}, exists,
                                 empty.values, empty.subkeys)
    assert [p.name for p in got] == ["Dropbox"] and len(asked) == 6


# ---------------------------------------------------------------- Windows: personal files assessment
KFM = rc.CloudProvider("OneDrive", "OneDrive folder backup (Known Folder Move) is protecting Desktop", True, {"signed_in": True})
DROPBOX = rc.CloudProvider("Dropbox", "Dropbox desktop client found", False, {"paths": ["C:\\Users\\bob\\Dropbox"]})
FH_GOOD = rc.FileHistoryState(configured=True, last_backup=ago(days=2))
FH_OLD = rc.FileHistoryState(configured=True, last_backup=ago(days=60))
FH_NONE = rc.FileHistoryState()


def test_file_history_alone_is_a_pass_with_no_finding():
    (backup, cloud), findings = rc.assess_windows_files(FH_GOOD, [], NOW)
    assert findings == [] and backup.state == rc.OK and cloud.state == rc.MISSING and cloud.severity is None
    assert layer_status(backup) == CheckStatus.PASS and layer_status(cloud) == CheckStatus.WARN


def test_cloud_sync_alone_counts_and_explains_version_history():
    (backup, cloud), findings = rc.assess_windows_files(FH_NONE, [KFM], NOW)
    assert findings == [] and cloud.state == rc.OK and backup.state == rc.MISSING
    assert "Known Folder Move" in cloud.detail and "earlier versions" in cloud.detail and "inside its folders" in cloud.detail


def test_google_drive_and_dropbox_count_as_a_backup_with_a_note():
    (_, cloud), findings = rc.assess_windows_files(FH_NONE, [DROPBOX], NOW)
    assert findings == [] and cloud.state == rc.OK and "Dropbox desktop client found" in cloud.detail
    assert "only protects what is inside its folders" in cloud.detail


def test_no_backup_at_all_is_medium():
    (backup, cloud), findings = rc.assess_windows_files(FH_NONE, [], NOW)
    (f,) = findings
    assert f.rule_id == "AEG-RECOVERY-FILES-NONE" and f.severity == Severity.MEDIUM and f.mitre == ["T1486"]
    assert f.title == "Your personal files are not backed up" and f.category == Category.RANSOMWARE
    assert f.location == "Personal files backup" and f.remediation is None
    for needle in ("OneDrive", "File History", "Google Drive", "Dropbox", "version history", "Manage backup"):
        assert needle in f.description + f.recommendation, needle
    assert f.evidence["file_history_configured"] is False and f.evidence["cloud"] == []
    assert backup.severity == Severity.MEDIUM and layer_status(backup) == CheckStatus.FAIL
    assert layer_status(cloud) == CheckStatus.WARN  # one finding costs one failed check, not two


def test_file_history_turned_off_by_policy_and_no_cloud_is_medium():
    fh = rc.FileHistoryState(policy_disabled=True, configured=True)
    assert rules(rc.assess_windows_files(fh, [], NOW)[1]) == ["AEG-RECOVERY-FILES-NONE"]
    off = rc.FileHistoryState(configured=True, enabled=False, last_backup=ago(days=2))
    assert rules(rc.assess_windows_files(off, [], NOW)[1]) == ["AEG-RECOVERY-FILES-NONE"]


def test_stale_file_history_without_cloud_is_low():
    (backup, cloud), (f,) = rc.assess_windows_files(FH_OLD, [], NOW)
    assert f.rule_id == "AEG-RECOVERY-FILES-STALE" and f.severity == Severity.LOW and f.mitre == ["T1486"]
    assert "60 days" in f.title and "Run now" in f.recommendation and f.remediation is None
    assert backup.state == rc.STALE and layer_status(backup) == CheckStatus.WARN
    assert rc.assess_windows_files(FH_OLD, [KFM], NOW)[1] == []  # cloud versioning covers the gap


def test_server_never_gets_a_personal_files_finding():
    (backup, cloud), findings = rc.assess_windows_files(FH_NONE, [], NOW, server=True)
    assert findings == [] and backup.state == rc.NA and cloud.state == rc.NA
    assert layer_status(backup) == CheckStatus.SKIP
    (_, cloud), findings = rc.assess_windows_files(FH_NONE, [KFM], NOW, server=True)
    assert findings == [] and cloud.state == rc.OK
    assert rc.assess_windows_files(FH_OLD, [], NOW, server=True)[1] == []


def test_check_windows_files_end_to_end_with_fakes(tmp_path):
    reg = FakeReg().add("HKCU", FH, ProtectedUpToTime=ft(ago(days=1)))
    reg.add("HKCU", ONEDRIVE + r"\Personal", UserEmail="a@b.example", KfmFoldersProtectedNow=1)
    (tmp_path / "Dropbox").mkdir()
    env = {"LOCALAPPDATA": str(tmp_path / "L"), "APPDATA": str(tmp_path / "A")}
    (backup, cloud), findings = rc.check_windows_files(NOW, False, reg.read, reg.values, reg.subkeys, home=tmp_path, env=env)
    assert findings == [] and backup.state == rc.OK and cloud.state == rc.OK
    assert "OneDrive" in cloud.detail and "Dropbox" in cloud.detail
    empty = FakeReg()
    (backup, cloud), findings = rc.check_windows_files(NOW, False, empty.read, empty.values, empty.subkeys,
                                                       home=tmp_path / "x", env=env)
    assert rules(findings) == ["AEG-RECOVERY-FILES-NONE"]


# ---------------------------------------------------------------- macOS: tmutil and defaults parsers
TM_ID = "6D5F6B64-0000-4000-8000-000000000001"
DEST_OUT = f"""====================================================
Name          : Backup Drive
Kind          : Local
Mount Point   : /Volumes/Backup Drive
ID            : {TM_ID}
====================================================
"""
DEST_TWO = DEST_OUT + """Name          : Time Capsule
Kind          : Network
URL           : smb://capsule.local/Backups
ID            : 3C0C1C42-0000-4000-8000-000000000002
====================================================
"""
NO_DEST = "tmutil: No destinations configured.\n"
FDA_ERR = ("tmutil: latestbackup requires Full Disk Access privileges. To allow this operation, select Full Disk Access in the "
           "Privacy tab of Security & Privacy preferences and add Terminal to the list of allowed applications.\n")


def tm_path(when, apfs=False):
    stamp = wall(when, "%Y-%m-%d-%H%M%S")
    if apfs:
        return f"/Volumes/Backup Drive/{stamp}.backup/{stamp}.backup\n"
    return f"/Volumes/Backup Drive/Backups.backupdb/MacBook Pro/{stamp}\n"


def tm_defaults(dates, auto=1):
    snaps = ",\n".join(f'                "{d.strftime("%Y-%m-%d %H:%M:%S")} +0000"' for d in dates)
    return f"""{{
    AutoBackup = {auto};
    Destinations =     (
                {{
            BytesAvailable = 123456;
            DestinationID = "{TM_ID}";
            LastKnownVolumeName = "Backup Drive";
            SnapshotDates =             (
{snaps}
            );
        }}
    );
    LastConfigurationTraceDate = "2020-01-01 00:00:00 +0000";
    LastDestinationID = "{TM_ID}";
    PreferencesVersion = 6;
}}
"""


def test_parse_tmutil_destinations():
    (d,) = rc.parse_tmutil_destinations(DEST_OUT)
    assert d == {"Name": "Backup Drive", "Kind": "Local", "Mount Point": "/Volumes/Backup Drive", "ID": TM_ID}
    two = rc.parse_tmutil_destinations(DEST_TWO)
    assert [x["Name"] for x in two] == ["Backup Drive", "Time Capsule"] and two[1]["URL"] == "smb://capsule.local/Backups"
    assert rc.parse_tmutil_destinations(NO_DEST) == [] and rc.parse_tmutil_destinations("") == []
    assert rc.parse_tmutil_destinations(None) == []


def test_parse_tmutil_latest():
    when = ago(days=3)
    for apfs in (False, True):
        got, problem = rc.parse_tmutil_latest(0, tm_path(when, apfs), "")
        assert problem == "" and abs((got - when).total_seconds()) < 1
    assert rc.parse_tmutil_latest(1, "", FDA_ERR) == (None, "fda")
    assert rc.parse_tmutil_latest(0, FDA_ERR, "") == (None, "fda")
    assert rc.parse_tmutil_latest(1, "", "tmutil: No backups found for host.\n") == (None, "none")
    assert rc.parse_tmutil_latest(0, "tmutil: No backups found for host.\n", "") == (None, "none")
    assert rc.parse_tmutil_latest(1, "", "tmutil: Failed to mount backup destination\n") == (None, "unreachable")
    assert rc.parse_tmutil_latest(1, "", "The backup disk could not be found.") == (None, "unreachable")
    assert rc.parse_tmutil_latest(-1, "", "not found: tmutil") == (None, "error")
    assert rc.parse_tmutil_latest(-1, "", "timeout after 15s: tmutil") == (None, "error")
    assert rc.parse_tmutil_latest(0, "", "") == (None, "error")
    assert rc.parse_tmutil_latest(0, "/Volumes/X/2026-13-45-999999\n", "") == (None, "error")


def test_parse_timemachine_defaults():
    dates = [ago(days=20), ago(days=3), ago(days=10)]
    prefs = rc.parse_timemachine_defaults(tm_defaults(dates))
    assert prefs.auto_backup is True and prefs.destination_ids == [TM_ID] and prefs.last_destination_id == TM_ID
    assert sorted(prefs.snapshot_dates) == sorted(dates)  # LastConfigurationTraceDate is not a backup date
    assert rc.parse_timemachine_defaults(tm_defaults([], auto=0)).auto_backup is False
    empty = rc.parse_timemachine_defaults("")
    assert empty.auto_backup is None and empty.destination_ids == [] and empty.snapshot_dates == []
    assert rc.parse_timemachine_defaults("{\n    AutoBackup = 1;\n}\n").destination_ids == []


def test_time_machine_state():
    dest = [{"Name": "Backup Drive", "ID": TM_ID}]
    prefs = rc.TimeMachinePrefs(True, [TM_ID], TM_ID, [])
    S = lambda d, p, latest=None, problem="": rc.time_machine_state(d, p, latest, problem, NOW)  # noqa: E731
    assert S([], rc.TimeMachinePrefs()).status == "none"
    assert S([], None).status == "none" and S(None, rc.TimeMachinePrefs()).status == "none"
    assert S(None, None).status == "unavailable"
    assert S(dest, prefs, ago(days=1)).status == "ok" and S(dest, prefs, ago(days=1)).destinations == ["Backup Drive"]
    assert S(dest, prefs, ago(days=14)).status == "ok" and S(dest, prefs, ago(days=15)).status == "stale"
    assert S([], prefs, ago(days=1)).status == "ok"  # configured according to the preferences only
    assert S(dest, prefs, None, "none").status == "never"
    unknown = S(dest, prefs, None, "fda")
    assert unknown.status == "unknown" and unknown.problem == "fda"
    assert S(dest, None, None, "").problem == "error"
    rescued = rc.TimeMachinePrefs(True, [TM_ID], TM_ID, [ago(days=2), ago(days=40)])
    assert S(dest, rescued, None, "fda").status == "ok"  # the snapshot dates answer even without Full Disk Access
    assert S(dest, rescued, ago(days=30), "").last_backup == ago(days=2)


def test_time_machine_not_configured_is_medium():
    state = rc.TimeMachineState("none")
    layer, (f,) = rc.assess_time_machine(state, NOW)
    assert f.rule_id == "AEG-RECOVERY-TM-NONE" and f.severity == Severity.MEDIUM and f.mitre == ["T1486"]
    assert f.title == "Time Machine is not set up" and f.category == Category.RANSOMWARE and f.remediation is None
    assert "System Settings > General > Time Machine" in f.recommendation and "Back Up Now" in f.recommendation
    assert layer.state == rc.MISSING and layer_status(layer) == CheckStatus.FAIL


def test_time_machine_never_completed_and_icloud_note():
    state = rc.TimeMachineState("never", ["Backup Drive"], problem="none")
    icloud = rc.CloudProvider("iCloud Drive (Desktop & Documents)", "iCloud Drive is syncing Desktop and Documents", True)
    layer, (f,) = rc.assess_time_machine(state, NOW, [icloud])
    assert f.rule_id == "AEG-RECOVERY-TM-NONE" and "never completed" in f.title and "Backup Drive" in f.description
    assert "iCloud Drive is syncing Desktop & Documents" in f.description and f.evidence["icloud_desktop_and_documents"] is True
    assert layer.state == rc.MISSING


@pytest.mark.parametrize("age,rule", [(1, None), (14, None), (15, "AEG-RECOVERY-TM-STALE"), (60, "AEG-RECOVERY-TM-STALE")])
def test_time_machine_age_threshold(age, rule):
    state = rc.time_machine_state([{"Name": "D", "ID": "1"}], None, ago(days=age), "", NOW)
    layer, findings = rc.assess_time_machine(state, NOW)
    assert rules(findings) == ([rule] if rule else [])
    if rule:
        (f,) = findings
        assert f.severity == Severity.LOW and f.mitre == ["T1486"] and f"{age} days old" in f.title
        assert layer.state == rc.STALE and layer_status(layer) == CheckStatus.WARN
    else:
        assert layer.state == rc.OK and layer_status(layer) == CheckStatus.PASS and "last backup" in layer.detail


def test_time_machine_without_full_disk_access_is_a_skip_with_the_hint():
    state = rc.TimeMachineState("unknown", ["Backup Drive"], problem="fda")
    layer, findings = rc.assess_time_machine(state, NOW)
    assert findings == [] and layer.state == rc.UNKNOWN and layer_status(layer) == CheckStatus.SKIP
    assert "Full Disk Access" in layer.detail and "Privacy & Security" in layer.detail
    layer, findings = rc.assess_time_machine(rc.TimeMachineState("unknown", ["D"], problem="unreachable"), NOW)
    assert findings == [] and "not connected" in layer.detail
    layer, findings = rc.assess_time_machine(rc.TimeMachineState("unavailable"), NOW)
    assert findings == [] and layer.state == rc.UNKNOWN and "tmutil" in layer.detail


def test_time_machine_automatic_backups_off_is_mentioned():
    state = rc.TimeMachineState("ok", ["D"], ago(days=1), auto_backup=False)
    assert "Automatic backups are switched off" in rc.assess_time_machine(state, NOW)[0].detail
    state = rc.TimeMachineState("stale", ["D"], ago(days=20), auto_backup=False)
    (f,) = rc.assess_time_machine(state, NOW)[1]
    assert "automatic backups are off" in f.description and "Automatic backups are switched off" in f.description


def tm_runner(dest=(0, DEST_OUT, ""), prefs=(0, "", ""), latest=(0, "", "")):
    return FakeRun((["tmutil", "destinationinfo"], dest), (["defaults", "read", rc.TIME_MACHINE_PLIST], prefs),
                   (["tmutil", "latestbackup"], latest))


def collect_tm(runner, providers=()):
    (layer,), findings = rc.collect_time_machine(NOW, runner, providers)
    return layer, findings


def test_collect_time_machine_configured_and_recent():
    runner = tm_runner(latest=(0, tm_path(ago(days=2)), ""))
    layer, findings = collect_tm(runner)
    assert findings == [] and layer.state == rc.OK
    assert runner.commands == [["tmutil", "destinationinfo"], ["defaults", "read", rc.TIME_MACHINE_PLIST],
                               ["tmutil", "latestbackup"]]
    assert all(timeout == rc.CMD_TIMEOUT_S for _c, timeout in runner.calls)


def test_collect_time_machine_not_configured_runs_no_latestbackup():
    runner = tm_runner(dest=(1, "", NO_DEST), prefs=(1, "", "The domain/default pair of (/Library/Preferences/com.apple.TimeMachine, "
                                                          "AutoBackup) does not exist"))
    layer, findings = collect_tm(runner)
    assert rules(findings) == ["AEG-RECOVERY-TM-NONE"] and layer.state == rc.MISSING
    assert ["tmutil", "latestbackup"] not in runner.commands
    layer, findings = collect_tm(tm_runner(dest=(0, NO_DEST, ""), prefs=(0, "{\n    AutoBackup = 1;\n}\n", "")))
    assert rules(findings) == ["AEG-RECOVERY-TM-NONE"]


def test_collect_time_machine_full_disk_access_error_is_skipped_unless_preferences_answer():
    layer, findings = collect_tm(tm_runner(latest=(1, "", FDA_ERR)))
    assert findings == [] and layer.state == rc.UNKNOWN and "Full Disk Access" in layer.detail
    layer, findings = collect_tm(tm_runner(prefs=(0, tm_defaults([ago(days=1)]), ""), latest=(1, "", FDA_ERR)))
    assert findings == [] and layer.state == rc.OK  # SnapshotDates in the preferences need no Full Disk Access
    layer, findings = collect_tm(tm_runner(prefs=(0, tm_defaults([ago(days=40)]), ""), latest=(1, "", FDA_ERR)))
    assert rules(findings) == ["AEG-RECOVERY-TM-STALE"]


def test_collect_time_machine_old_backup_and_never_backed_up():
    layer, findings = collect_tm(tm_runner(latest=(0, tm_path(ago(days=20), apfs=True), "")))
    assert rules(findings) == ["AEG-RECOVERY-TM-STALE"] and layer.state == rc.STALE
    layer, findings = collect_tm(tm_runner(latest=(1, "", "tmutil: No backups found for host.")))
    assert rules(findings) == ["AEG-RECOVERY-TM-NONE"] and "never completed" in findings[0].title


def test_collect_time_machine_tmutil_missing_is_a_skip_not_a_finding():
    layer, findings = collect_tm(FakeRun())  # every binary "not found"
    assert findings == [] and layer.state == rc.UNKNOWN
    layer, findings = collect_tm(tm_runner(dest=(1, "", "tmutil: some other failure"), prefs=(-1, "", "not found: defaults")))
    assert findings == [] and layer.state == rc.UNKNOWN  # a failing tmutil is never read as "not configured"


def test_detect_mac_cloud(tmp_path):
    assert rc.detect_mac_cloud(tmp_path) == []
    docs = tmp_path / "Library" / "Mobile Documents" / "com~apple~CloudDocs"
    docs.mkdir(parents=True)
    assert rc.detect_mac_cloud(tmp_path) == []  # iCloud Drive without Desktop & Documents is not a backup of them
    (docs / "Desktop").mkdir()
    (docs / "Documents").mkdir()
    (p,) = rc.detect_mac_cloud(tmp_path)
    assert p.name.startswith("iCloud") and p.covers_known_folders and p.evidence["folders"] == ["Desktop", "Documents"]
    storage = tmp_path / "Library" / "CloudStorage"
    for name in ("OneDrive-Personal", "OneDrive-Contoso", "GoogleDrive-bob@example.com", "Dropbox", "Box-Box"):
        (storage / name).mkdir(parents=True)
    names = [p.name for p in rc.detect_mac_cloud(tmp_path)]
    assert names == ["iCloud Drive (Desktop & Documents)", "OneDrive", "Google Drive", "Dropbox"]  # one entry per service
    assert rc.detect_mac_cloud(tmp_path)[1].evidence["path"] == str(storage / "OneDrive-Contoso")
    legacy = tmp_path / "other"
    (legacy / "Dropbox").mkdir(parents=True)
    assert [p.name for p in rc.detect_mac_cloud(legacy)] == ["Dropbox"]


def test_detect_mac_cloud_survives_an_unreadable_folder(tmp_path, monkeypatch):
    (tmp_path / "Library" / "CloudStorage" / "Dropbox").mkdir(parents=True)
    (tmp_path / "Google Drive").mkdir()

    def denied(self):
        raise PermissionError("Operation not permitted")

    monkeypatch.setattr(Path, "iterdir", denied)
    assert [p.name for p in rc.detect_mac_cloud(tmp_path)] == ["Google Drive"]


# ---------------------------------------------------------------- Linux: tools
def snapshot_dirs(root, rel, ages):
    base = root / rel
    for a in ages:
        (base / wall(ago(days=a), "%Y-%m-%d_%H-%M-%S")).mkdir(parents=True)
    return base


def timeshift_conf(root, **schedule):
    (root / "etc" / "timeshift").mkdir(parents=True)
    conf = {"backup_device_uuid": "abc", **{f"schedule_{k}": v for k, v in schedule.items()}}
    (root / "etc" / "timeshift" / "timeshift.json").write_text(json.dumps(conf))


def test_timeshift_with_snapshots(tmp_path):
    timeshift_conf(tmp_path, daily="true", weekly="false", boot="true")
    snapshot_dirs(tmp_path, "run/timeshift/backup/timeshift/snapshots", [9, 2, 30])
    t = rc.detect_timeshift(tmp_path)
    assert t.name == "Timeshift" and t.kind == "snapshot" and t.known
    assert abs((t.last - ago(days=2)).total_seconds()) < 1
    assert "daily, boot" in t.detail and "weekly" not in t.detail


def test_timeshift_snapshot_locations_and_odd_names(tmp_path):
    timeshift_conf(tmp_path)
    base = snapshot_dirs(tmp_path, "media/bob/BackupDisk/timeshift/snapshots", [5])
    (base / ".sync").mkdir()
    (base / "info.json").write_text("{}")
    (base / "2026-13-45_99-99-99").mkdir()
    t = rc.detect_timeshift(tmp_path)
    assert abs((t.last - ago(days=5)).total_seconds()) < 1 and "no schedule" in t.detail
    snapshot_dirs(tmp_path, "run/timeshift/1234/backup/timeshift-btrfs/snapshots", [1])
    assert abs((rc.detect_timeshift(tmp_path).last - ago(days=1)).total_seconds()) < 1


def test_timeshift_configured_but_snapshots_not_visible_is_unknown(tmp_path):
    timeshift_conf(tmp_path, daily="true")
    t = rc.detect_timeshift(tmp_path)
    assert t.last is None and t.known is False and "sudo timeshift --list" in t.detail
    (tmp_path / "timeshift" / "snapshots").mkdir(parents=True)  # the folder is readable and empty: no snapshot yet
    t = rc.detect_timeshift(tmp_path)
    assert t.last is None and t.known is True and "no snapshot yet" in t.detail


def test_timeshift_absent_or_unreadable_config(tmp_path):
    assert rc.detect_timeshift(tmp_path) is None
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "timeshift.json").write_text("not json at all")  # old location, broken file: still configured
    assert rc.detect_timeshift(tmp_path).known is False


SNAPPER_LIST = """ # | Type   | Pre # | Date                | User | Cleanup  | Description | Userdata
---+--------+-------+---------------------+------+----------+-------------+---------
0  | single |       |                     | root |          | current     |
1* | single |       | {old} | root | number   | first root filesystem |
2  | single |       | {new} | root | timeline | timeline    |
"""


def snapper_root(tmp_path, *names):
    configs = tmp_path / "etc" / "snapper" / "configs"
    configs.mkdir(parents=True)
    for n in names:
        (configs / n).write_text("SUBVOLUME=/")
    return tmp_path


def test_snapper_reads_the_newest_snapshot(tmp_path):
    root = snapper_root(tmp_path, "root")
    out = SNAPPER_LIST.format(old=wall(ago(days=40), "%Y-%m-%d %H:%M:%S"), new=wall(ago(days=1), "%Y-%m-%d %H:%M:%S"))
    runner = FakeRun((["snapper", "-c", "root", "--iso", "list"], (0, out, "")))
    t = rc.detect_snapper(root, runner)
    assert t.name == "snapper" and t.known and abs((t.last - ago(days=1)).total_seconds()) < 1
    assert runner.calls == [(["snapper", "-c", "root", "--iso", "list"], rc.CMD_TIMEOUT_S)]


def test_snapper_needing_root_is_unknown_and_unconfigured_is_none(tmp_path):
    root = snapper_root(tmp_path, "root", "home")
    runner = FakeRun((["snapper"], (1, "", "No permissions.")))
    t = rc.detect_snapper(root, runner)
    assert t.known is False and t.last is None and "sudo snapper list" in t.detail and len(runner.calls) == 1
    assert rc.detect_snapper(tmp_path / "empty", runner) is None
    assert rc.detect_snapper(snapper_root(tmp_path / "e2"), runner) is None  # configs folder without configurations
    t = rc.detect_snapper(root, FakeRun())  # snapper binary not installed
    assert t.known is False
    t = rc.detect_snapper(root, FakeRun((["snapper"], (0, SNAPPER_LIST.split("1*")[0], ""))))
    assert t.known and t.last is None and "no snapshot yet" in t.detail


def test_snapper_looks_at_every_configuration(tmp_path):
    root = snapper_root(tmp_path, "root", "home")
    old = SNAPPER_LIST.format(old=wall(ago(days=60), "%Y-%m-%d %H:%M:%S"), new=wall(ago(days=50), "%Y-%m-%d %H:%M:%S"))
    new = SNAPPER_LIST.format(old=wall(ago(days=60), "%Y-%m-%d %H:%M:%S"), new=wall(ago(days=3), "%Y-%m-%d %H:%M:%S"))
    runner = FakeRun((["snapper", "-c", "home"], (0, new, "")), (["snapper", "-c", "root"], (0, old, "")))
    assert abs((rc.detect_snapper(root, runner).last - ago(days=3)).total_seconds()) < 1


def test_zfs_newest_snapshot():
    epoch = int(ago(days=2).timestamp())
    runner = FakeRun((["zfs", "list"], (0, f"{epoch}\n{epoch - 86400}\n", "")))
    t = rc.detect_zfs(runner)
    assert t.name == "ZFS" and t.last == ago(days=2)
    assert runner.commands == [["zfs", "list", "-H", "-p", "-t", "snapshot", "-o", "creation", "-S", "creation"]]
    assert rc.detect_zfs(FakeRun()) is None  # no zfs binary
    assert rc.detect_zfs(FakeRun((["zfs"], (0, "", "")))) is None  # a pool without snapshots is not a snapshot tool in use
    assert rc.detect_zfs(FakeRun((["zfs"], (1, "", "cannot open: permission denied")))) is None
    assert rc.detect_zfs(FakeRun((["zfs"], (0, "garbage\n", "")))) is None
    assert rc.detect_zfs(FakeRun((["zfs"], (0, "99999999999999999999\n", "")))) is None


def test_btrfs_newest_snapshot():
    out = (f"ID 257 gen 20 cgen 20 parent 5 top level 5 otime {wall(ago(days=9), '%Y-%m-%d %H:%M:%S')} path .snapshots/1/snapshot\n"
           f"ID 258 gen 90 cgen 90 parent 5 top level 5 otime {wall(ago(days=1), '%Y-%m-%d %H:%M:%S')} path .snapshots/2/snapshot\n")
    runner = FakeRun((["btrfs", "subvolume", "list", "-s", "/"], (0, out, "")))
    t = rc.detect_btrfs(runner)
    assert t.name == "Btrfs" and abs((t.last - ago(days=1)).total_seconds()) < 1
    assert rc.detect_btrfs(FakeRun((["btrfs"], (1, "", "ERROR: can't perform the search - Operation not permitted")))) is None
    assert rc.detect_btrfs(FakeRun((["btrfs"], (0, "", "")))) is None and rc.detect_btrfs(FakeRun()) is None


def test_restic_cache(tmp_path):
    assert rc.detect_restic(tmp_path) is None
    cache = tmp_path / ".cache" / "restic"
    cache.mkdir(parents=True)
    (cache / "CACHEDIR.TAG").write_text("Signature: 8a477f597d28d172789f06886806bc55")
    assert rc.detect_restic(tmp_path) is None  # a cache folder without a repository
    for name, age in (("0a1b2c", 12), ("3d4e5f", 3)):
        (cache / name).mkdir()
        os.utime(cache / name, (ago(days=age).timestamp(),) * 2)
    t = rc.detect_restic(tmp_path)
    assert t.name == "restic" and t.kind == "backup" and t.known and t.last == ago(days=3)


def test_borg_cache_and_security_folders(tmp_path):
    assert rc.detect_borg(tmp_path) is None
    repo = tmp_path / ".cache" / "borg" / "aabbcc"
    repo.mkdir(parents=True)
    (repo / "chunks").write_text("x")
    (repo / "files").write_text("x")
    os.utime(repo / "chunks", (ago(days=8).timestamp(),) * 2)
    os.utime(repo / "files", (ago(days=2).timestamp(),) * 2)
    os.utime(repo, (ago(days=20).timestamp(),) * 2)
    t = rc.detect_borg(tmp_path)
    assert t.name == "BorgBackup" and t.known and t.last == ago(days=2)

    only_config = tmp_path / "other"
    (only_config / ".config" / "borg" / "security" / "aabbcc").mkdir(parents=True)
    t = rc.detect_borg(only_config)
    assert t.known is False and t.last is None and "unknown" in t.detail
    (tmp_path / "third" / ".config" / "borg" / "security").mkdir(parents=True)
    assert rc.detect_borg(tmp_path / "third") is None


def test_deja_dup_last_backup_setting():
    stamp = ago(days=4).strftime("%Y-%m-%dT%H:%M:%SZ")
    runner = FakeRun((["gsettings", "get", "org.gnome.DejaDup", "last-backup"], (0, f"'{stamp}'\n", "")))
    t = rc.detect_dejadup(runner)
    assert t.name == "Deja Dup" and t.kind == "backup" and t.last == ago(days=4)
    assert runner.calls == [(["gsettings", "get", "org.gnome.DejaDup", "last-backup"], rc.CMD_TIMEOUT_S)]
    assert rc.detect_dejadup(FakeRun((["gsettings"], (0, "''\n", "")))) is None  # installed, never ran
    assert rc.detect_dejadup(FakeRun((["gsettings"], (1, "", "No such schema 'org.gnome.DejaDup'")))) is None
    assert rc.detect_dejadup(FakeRun()) is None


def test_a_crashing_detector_becomes_an_unknown_tool_not_an_error():
    def boom():
        raise PermissionError("denied")

    t = rc._safe_detect("Timeshift", "snapshot", boom)
    assert t.name == "Timeshift" and t.known is False and "PermissionError" in t.detail
    assert rc._safe_detect("x", "backup", lambda: None) is None


# ---------------------------------------------------------------- Linux: layers and findings
def tool(name, kind="backup", days=None, known=True, detail=""):
    return rc.ToolState(name, kind, ago(days=days) if days is not None else None, known, detail)


def test_tools_layer_states():
    L = lambda key, *tools: rc.tools_layer(key, tools, NOW, "none found", "do it")  # noqa: E731
    none = L(rc.BACKUP)
    assert none.state == rc.MISSING and none.detail == "none found" and none.hint == "do it"
    ok = L(rc.BACKUP, tool("restic", days=3), tool("BorgBackup", days=90))
    assert ok.state == rc.OK and ok.newest == ago(days=3) and "restic: newest" in ok.detail and "BorgBackup" in ok.detail
    stale = L(rc.BACKUP, tool("restic", days=45))
    assert stale.state == rc.STALE and stale.severity == Severity.LOW and "45 days" in stale.hint
    assert L(rc.BACKUP, tool("restic", days=30)).state == rc.OK and L(rc.BACKUP, tool("restic", days=31)).state == rc.STALE
    unknown = L(rc.RESTORE, tool("Timeshift", "snapshot", known=False, detail="is set up, but unreadable"))
    assert unknown.state == rc.UNKNOWN and "Timeshift is set up, but unreadable" in unknown.detail
    assert L(rc.RESTORE, tool("snapper", "snapshot", days=100), tool("Timeshift", "snapshot", known=False)).state == rc.UNKNOWN
    assert L(rc.RESTORE, tool("snapper", "snapshot", days=2), tool("Timeshift", "snapshot", known=False)).state == rc.OK
    empty = L(rc.RESTORE, tool("Timeshift", "snapshot", detail="is set up but has no snapshot yet"))
    assert empty.state == rc.MISSING
    assert L(rc.RESTORE, tool("ZFS", "snapshot", days=1)).counts_as_backup and not L(rc.RESTORE).newest
    assert not rc.Layer(rc.RESTORE, rc.OK).counts_as_backup and rc.Layer(rc.CLOUD, rc.OK).counts_as_backup


def test_check_linux_without_any_tool_is_low(tmp_path):
    layers, findings = rc.check_linux(NOW, FakeRun(), tmp_path / "root", tmp_path / "home")
    assert [l.key for l in layers] == [rc.RESTORE, rc.BACKUP, rc.CLOUD]
    assert [l.state for l in layers] == [rc.MISSING, rc.MISSING, rc.NA]
    (f,) = findings
    assert f.rule_id == "AEG-RECOVERY-LINUX-NONE" and f.severity == Severity.LOW and f.category == Category.RANSOMWARE
    assert f.mitre == ["T1486", "T1490"] and f.location == "recovery:linux" and f.remediation is None
    assert "Servers are often backed up from outside" in f.description and "restic init" in f.recommendation
    assert "borg init" in f.recommendation and "Deja Dup" in f.recommendation
    assert f.evidence["tools"] == [] and "restic" in f.evidence["checked"]


def test_check_linux_with_a_recent_backup_has_no_finding(tmp_path):
    home = tmp_path / "home"
    (home / ".cache" / "restic" / "abc").mkdir(parents=True)
    os.utime(home / ".cache" / "restic" / "abc", (ago(days=1).timestamp(),) * 2)
    layers, findings = rc.check_linux(NOW, FakeRun(), tmp_path / "root", home)
    assert findings == [] and layers[1].state == rc.OK and layers[0].state == rc.MISSING


def test_check_linux_stale_backups_are_low(tmp_path):
    home = tmp_path / "home"
    (home / ".cache" / "restic" / "abc").mkdir(parents=True)
    os.utime(home / ".cache" / "restic" / "abc", (ago(days=75).timestamp(),) * 2)
    layers, (f,) = rc.check_linux(NOW, FakeRun(), tmp_path / "root", home)
    assert f.rule_id == "AEG-RECOVERY-LINUX-STALE" and f.severity == Severity.LOW and f.mitre == ["T1486", "T1490"]
    assert "75 days old" in f.title and layers[1].state == rc.STALE and f.evidence["tools"][0]["tool"] == "restic"


def test_check_linux_unknown_snapshots_are_not_a_finding(tmp_path):
    root = tmp_path / "root"
    timeshift_conf(root, daily="true")
    layers, findings = rc.check_linux(NOW, FakeRun(), root, tmp_path / "home")
    assert findings == [] and layers[0].state == rc.UNKNOWN and layers[1].state == rc.MISSING
    assert layer_status(layers[0]) == CheckStatus.SKIP and layer_status(layers[1]) == CheckStatus.WARN
    # unknown next to an old backup is still not enough to report anything
    home = tmp_path / "home"
    (home / ".cache" / "restic" / "abc").mkdir(parents=True)
    os.utime(home / ".cache" / "restic" / "abc", (ago(days=75).timestamp(),) * 2)
    assert rc.check_linux(NOW, FakeRun(), root, home)[1] == []


def test_check_linux_one_detector_failing_keeps_the_rest(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".cache" / "restic" / "abc").mkdir(parents=True)
    os.utime(home / ".cache" / "restic" / "abc", (ago(days=1).timestamp(),) * 2)

    def boom(root=None):
        raise RuntimeError("config exploded")

    monkeypatch.setattr(rc, "detect_timeshift", boom)
    layers, findings = rc.check_linux(NOW, FakeRun(), tmp_path / "root", home)
    assert layers[0].state == rc.UNKNOWN and "RuntimeError" in layers[0].detail and layers[1].state == rc.OK
    assert findings == []


# ---------------------------------------------------------------- grade and summary
def L(key, state, **kw):
    return rc.Layer(key, state, f"{key} is {state}", **kw)


@pytest.mark.parametrize("layers,grade", [
    ([L(rc.RESTORE, rc.OK), L(rc.BACKUP, rc.OK), L(rc.CLOUD, rc.OK)], "Good"),
    ([L(rc.RESTORE, rc.MISSING), L(rc.BACKUP, rc.OK), L(rc.CLOUD, rc.OK)], "Good"),
    ([L(rc.RESTORE, rc.OK), L(rc.BACKUP, rc.MISSING), L(rc.CLOUD, rc.OK)], "Good"),
    ([L(rc.RESTORE, rc.OK), L(rc.BACKUP, rc.OK), L(rc.CLOUD, rc.MISSING)], "Good"),
    ([L(rc.RESTORE, rc.MISSING), L(rc.BACKUP, rc.OK), L(rc.CLOUD, rc.MISSING)], "Fair"),
    ([L(rc.RESTORE, rc.UNKNOWN), L(rc.BACKUP, rc.MISSING), L(rc.CLOUD, rc.OK)], "Fair"),
    ([L(rc.RESTORE, rc.NA), L(rc.BACKUP, rc.OK), L(rc.CLOUD, rc.NA)], "Fair"),
    ([L(rc.RESTORE, rc.OK), L(rc.BACKUP, rc.MISSING), L(rc.CLOUD, rc.MISSING)], "Weak"),  # restore points alone are not a backup
    ([L(rc.RESTORE, rc.MISSING), L(rc.BACKUP, rc.MISSING), L(rc.CLOUD, rc.MISSING)], "Weak"),
    ([L(rc.RESTORE, rc.UNKNOWN), L(rc.BACKUP, rc.MISSING), L(rc.CLOUD, rc.MISSING)], "Weak"),
    ([L(rc.RESTORE, rc.OK), L(rc.BACKUP, rc.STALE), L(rc.CLOUD, rc.MISSING)], "Weak"),
    ([L(rc.RESTORE, rc.NA), L(rc.BACKUP, rc.UNKNOWN), L(rc.CLOUD, rc.MISSING)], "Unknown"),  # Time Machine without Full Disk Access
    ([L(rc.RESTORE, rc.OK), L(rc.BACKUP, rc.UNKNOWN), L(rc.CLOUD, rc.MISSING)], "Unknown"),
    ([L(rc.RESTORE, rc.NA), L(rc.BACKUP, rc.NA), L(rc.CLOUD, rc.NA)], "Unknown"),  # a server
    ([L(rc.RESTORE, rc.UNKNOWN), L(rc.BACKUP, rc.UNKNOWN), L(rc.CLOUD, rc.UNKNOWN)], "Unknown"),
    ([], "Unknown"),
    ([L(rc.RESTORE, rc.OK, covers_files=True), L(rc.BACKUP, rc.MISSING), L(rc.CLOUD, rc.NA)], "Fair"),  # Linux snapshots of data
    ([L(rc.RESTORE, rc.UNKNOWN, covers_files=True), L(rc.BACKUP, rc.MISSING), L(rc.CLOUD, rc.NA)], "Unknown"),
])
def test_readiness_grade(layers, grade):
    got, verdict = rc.readiness_grade(layers + [rc.offline_layer()])
    assert got == grade and verdict and len(verdict) > 40


def test_offline_layer_never_changes_the_grade_and_is_never_verified():
    off = rc.offline_layer()
    assert off.state == rc.UNKNOWN and "Not verified" in off.detail and layer_status(off) == CheckStatus.SKIP
    base = [L(rc.RESTORE, rc.OK), L(rc.BACKUP, rc.OK)]
    assert rc.readiness_grade(base)[0] == rc.readiness_grade(base + [off])[0] == "Good"
    assert rc.readiness_grade([L(rc.BACKUP, rc.OK), rc.Layer(rc.OFFLINE, rc.OK)])[0] == "Fair"


def test_verdict_texts_name_the_layers():
    good = rc.readiness_grade([L(rc.RESTORE, rc.OK), L(rc.BACKUP, rc.OK)])[1]
    assert "2 independent ways" in good and "restore points and a file backup" in good and "disconnected" in good
    fair = rc.readiness_grade([L(rc.RESTORE, rc.MISSING), L(rc.BACKUP, rc.OK), L(rc.CLOUD, rc.MISSING)])[1]
    assert "(a file backup)" in fair and "for example cloud sync with version history" in fair
    weak = rc.readiness_grade([L(rc.RESTORE, rc.OK), L(rc.BACKUP, rc.MISSING)])[1]
    assert "deletes them" in weak and "same disk" in weak
    unknown = rc.readiness_grade([L(rc.BACKUP, rc.UNKNOWN)])[1]
    assert "Full Disk Access" in unknown and "administrator" in unknown


def test_summary_finding_lists_every_layer():
    layers = [rc.offline_layer(), L(rc.CLOUD, rc.MISSING, hint="turn on OneDrive"), L(rc.RESTORE, rc.OK, newest=ago(days=2)),
              L(rc.BACKUP, rc.OK)]
    f = rc.summary_finding(layers)
    assert f.rule_id == "AEG-RECOVERY-SUMMARY" and f.title == "Ransomware recovery readiness: Good"
    assert f.severity == Severity.INFO and f.category == Category.RANSOMWARE and f.location == "recovery:summary"
    assert f.mitre == ["T1486"] and f.remediation is None and f.description and f.recommendation
    assert f.evidence["grade"] == "Good" and f.evidence["healthy_layers"] == 2
    assert [e["layer"] for e in f.evidence["layers"]] == ["Restore points & snapshots", "File backup",
                                                          "Cloud sync with version history", "Offline or off-site copy"]
    assert [e["state"] for e in f.evidence["layers"]] == ["ok", "ok", "missing", "unknown"]
    assert f.evidence["layers"][0]["newest"] == _iso(ago(days=2)) and f.evidence["layers"][1]["newest"] is None
    assert "turn on OneDrive" in f.recommendation and "keep one backup disconnected" in f.recommendation
    assert "Test a restore" in f.recommendation and "no scanner can see" in f.description
    assert f.fingerprint == rc.summary_finding(layers).fingerprint  # stable across runs


def _iso(when):
    return when.isoformat(timespec="seconds")


def test_summary_note_only_below_good():
    layers = [L(rc.BACKUP, rc.MISSING)]
    assert "servers note" in rc.summary_finding(layers, "servers note").description
    assert "servers note" not in rc.summary_finding([L(rc.BACKUP, rc.OK), L(rc.CLOUD, rc.OK)], "servers note").description


def test_layer_check_statuses():
    C = rc.layer_check
    assert C(L(rc.RESTORE, rc.OK)).status == CheckStatus.PASS
    assert C(L(rc.RESTORE, rc.UNKNOWN)).status == CheckStatus.SKIP and C(L(rc.RESTORE, rc.NA)).status == CheckStatus.SKIP
    assert C(L(rc.RESTORE, rc.STALE, severity=Severity.LOW)).status == CheckStatus.WARN
    assert C(L(rc.RESTORE, rc.MISSING)).status == CheckStatus.WARN
    assert C(L(rc.RESTORE, rc.MISSING, severity=Severity.MEDIUM)).status == CheckStatus.FAIL
    assert C(L(rc.RESTORE, rc.UNKNOWN, error=True)).status == CheckStatus.ERROR
    c = C(L(rc.BACKUP, rc.OK))
    assert c.check_id == "AEG-RECOVERY-BACKUP" and c.title == "File backup" and c.category == Category.RANSOMWARE
    assert c.detail == "backup is ok"


# ---------------------------------------------------------------- scanner flow
def test_scanner_is_registered_and_in_the_profiles():
    from aegis.core.engine import PROFILES

    load_all()
    cls = REGISTRY["recovery"]
    assert cls.name == "recovery" and set(cls.platforms) == {"windows", "linux", "darwin"} and cls().supported()
    assert cls.title == "Backup & ransomware recovery readiness" and cls.description and cls.needs_admin_for_full_results
    assert PROFILES["full"][-1] == "recovery" and PROFILES["full"].count("recovery") == 1
    assert PROFILES["audit"][-1] == "recovery" and PROFILES["audit"].count("recovery") == 1
    assert "recovery" not in PROFILES["quick"]


def windows_world(monkeypatch, tmp_path, facts=None, reg=None):
    """Everything the Windows flow reads, replaced by fakes (the user's folders and %VARIABLES% point into tmp_path)."""
    monkeypatch.setattr(rc, "IS_WINDOWS", True)
    monkeypatch.setattr(rc, "IS_MAC", False)
    ps = FakePS(facts)
    monkeypatch.setattr(rc, "powershell_json", ps)
    reg = (reg or FakeReg()).install(monkeypatch)
    monkeypatch.setattr(rc, "user_home", lambda: tmp_path / "home")
    for var, sub in (("LOCALAPPDATA", "Local"), ("APPDATA", "Roaming"), ("USERPROFILE", "home")):
        monkeypatch.setenv(var, str(tmp_path / sub))
    return ps, reg


def test_run_windows_everything_in_place(ctx, tmp_path, monkeypatch):
    reg = FakeReg().add("HKLM", SR, RPSessionInterval=1).add("HKCU", FH, ProtectedUpToTime=ft(ago(days=2)))
    reg.add("HKCU", ONEDRIVE + r"\Personal", UserEmail="a@b.example", KfmFoldersProtectedNow=7)
    ps, _ = windows_world(monkeypatch, tmp_path, GOOD_FACTS, reg)
    ctx.is_admin = True
    messages = []
    ctx.progress = lambda scanner, msg: messages.append((scanner, msg))
    findings, checks = split(rc.RecoveryScanner().run(ctx))
    assert [(c.check_id, c.status) for c in checks] == [
        ("AEG-RECOVERY-RESTORE", CheckStatus.PASS), ("AEG-RECOVERY-BACKUP", CheckStatus.PASS),
        ("AEG-RECOVERY-CLOUD", CheckStatus.PASS), ("AEG-RECOVERY-OFFLINE", CheckStatus.SKIP)]
    assert rules(findings) == ["AEG-RECOVERY-SUMMARY"] and findings[0].title == "Ransomware recovery readiness: Good"
    assert len(ps.calls) == 1 and ps.calls[0][1] == rc.PS_TIMEOUT_S
    assert [m for s, m in messages if m.startswith("checking")] == ["checking System Restore and shadow copies",
                                                                    "checking File History and cloud sync"]
    assert ctx.stats["recovery_layers_ok"] == 3


def test_run_windows_standard_user_with_nothing_set_up(ctx, tmp_path, monkeypatch):
    denied = {"drive": "C:", "restore": {"supported": True, "error": "Access is denied."},
              "shadow": {"error": "Access denied"}}
    windows_world(monkeypatch, tmp_path, denied, FakeReg().add("HKLM", SR, RPSessionInterval=1))
    ctx.is_admin = False
    out = list(rc.RecoveryScanner().run(ctx))
    findings, checks = split(out)
    assert [(c.check_id, c.status) for c in checks] == [
        ("AEG-RECOVERY-RESTORE", CheckStatus.SKIP), ("AEG-RECOVERY-BACKUP", CheckStatus.FAIL),
        ("AEG-RECOVERY-CLOUD", CheckStatus.WARN), ("AEG-RECOVERY-OFFLINE", CheckStatus.SKIP)]
    assert "Not checked without administrator rights" in checks[0].detail
    assert rules(findings) == ["AEG-RECOVERY-FILES-NONE", "AEG-RECOVERY-SUMMARY"]
    assert findings[0].severity == Severity.MEDIUM and findings[1].title == "Ransomware recovery readiness: Weak"
    assert isinstance(out[-1], Finding) and out[-1].rule_id == "AEG-RECOVERY-SUMMARY"  # the summary comes last


def test_run_windows_protection_off_and_server(ctx, tmp_path, monkeypatch):
    reg = FakeReg().add("HKLM", SR, RPSessionInterval=0)
    windows_world(monkeypatch, tmp_path, {"drive": "C:", "restore": {"supported": True, "count": 0},
                                          "shadow": {"count": 0}}, reg)
    ctx.is_admin = True
    findings, checks = split(rc.RecoveryScanner().run(ctx))
    assert rules(findings) == ["AEG-RECOVERY-RESTORE-OFF", "AEG-RECOVERY-FILES-NONE", "AEG-RECOVERY-SUMMARY"]
    assert checks[0].status == CheckStatus.FAIL and checks[1].status == CheckStatus.FAIL

    reg = FakeReg().add("HKLM", CV, InstallationType="Server", EditionID="ServerStandard")
    windows_world(monkeypatch, tmp_path, dict(GOOD_FACTS, os={"product_type": 3}), reg)
    findings, checks = split(rc.RecoveryScanner().run(ctx))
    assert rules(findings) == ["AEG-RECOVERY-SUMMARY"] and findings[0].title.endswith("Unknown")
    assert [c.status for c in checks] == [CheckStatus.SKIP] * 4


def test_run_windows_without_powershell_still_reports_the_registry_part(ctx, tmp_path, monkeypatch):
    windows_world(monkeypatch, tmp_path, None, FakeReg().add("HKLM", SR, RPSessionInterval=0))
    ctx.is_admin = False
    findings, checks = split(rc.RecoveryScanner().run(ctx))
    assert "AEG-RECOVERY-RESTORE-OFF" in rules(findings) and len(checks) == 4


MAC_PLIST = ["defaults", "read", rc.TIME_MACHINE_PLIST]


def mac_world(monkeypatch, tmp_path, runner):
    monkeypatch.setattr(rc, "IS_WINDOWS", False)
    monkeypatch.setattr(rc, "IS_MAC", True)
    monkeypatch.setattr(rc, "run", runner)
    monkeypatch.setattr(rc, "user_home", lambda: tmp_path / "home")
    return runner


def test_run_macos_time_machine_and_icloud(ctx, tmp_path, monkeypatch):
    docs = tmp_path / "home" / "Library" / "Mobile Documents" / "com~apple~CloudDocs"
    (docs / "Desktop").mkdir(parents=True)
    runner = mac_world(monkeypatch, tmp_path, tm_runner(latest=(0, tm_path(ago(days=1)), "")))
    findings, checks = split(rc.RecoveryScanner().run(ctx))
    assert [(c.check_id, c.status) for c in checks] == [
        ("AEG-RECOVERY-RESTORE", CheckStatus.SKIP), ("AEG-RECOVERY-BACKUP", CheckStatus.PASS),
        ("AEG-RECOVERY-CLOUD", CheckStatus.PASS), ("AEG-RECOVERY-OFFLINE", CheckStatus.SKIP)]
    assert rules(findings) == ["AEG-RECOVERY-SUMMARY"] and findings[0].title.endswith("Good")  # Time Machine + iCloud
    assert [c for c in runner.commands] == [["tmutil", "destinationinfo"], MAC_PLIST, ["tmutil", "latestbackup"]]


def test_run_macos_not_configured_and_without_full_disk_access(ctx, tmp_path, monkeypatch):
    mac_world(monkeypatch, tmp_path, tm_runner(dest=(0, NO_DEST, ""), prefs=(1, "", "... does not exist")))
    findings, checks = split(rc.RecoveryScanner().run(ctx))
    assert rules(findings) == ["AEG-RECOVERY-TM-NONE", "AEG-RECOVERY-SUMMARY"] and findings[1].title.endswith("Weak")
    assert checks[1].status == CheckStatus.FAIL and checks[2].status == CheckStatus.WARN

    mac_world(monkeypatch, tmp_path, tm_runner(latest=(1, "", FDA_ERR)))
    findings, checks = split(rc.RecoveryScanner().run(ctx))
    assert rules(findings) == ["AEG-RECOVERY-SUMMARY"] and findings[0].title.endswith("Unknown")
    assert checks[1].status == CheckStatus.SKIP and "Full Disk Access" in checks[1].detail


def test_run_linux(ctx, tmp_path, monkeypatch):
    monkeypatch.setattr(rc, "IS_WINDOWS", False)
    monkeypatch.setattr(rc, "IS_MAC", False)
    root, home = tmp_path / "root", tmp_path / "home"
    timeshift_conf(root, daily="true")
    snapshot_dirs(root, "run/timeshift/backup/timeshift/snapshots", [1])
    (home / ".cache" / "restic" / "abc").mkdir(parents=True)
    os.utime(home / ".cache" / "restic" / "abc", (ago(days=2).timestamp(),) * 2)
    runner = FakeRun()
    monkeypatch.setattr(rc, "run", runner)
    monkeypatch.setattr(rc, "user_home", lambda: home)
    monkeypatch.setattr(rc, "LINUX_ROOT", root)
    findings, checks = split(rc.RecoveryScanner().run(ctx))
    assert [(c.check_id, c.status) for c in checks] == [
        ("AEG-RECOVERY-RESTORE", CheckStatus.PASS), ("AEG-RECOVERY-BACKUP", CheckStatus.PASS),
        ("AEG-RECOVERY-CLOUD", CheckStatus.SKIP), ("AEG-RECOVERY-OFFLINE", CheckStatus.SKIP)]
    assert rules(findings) == ["AEG-RECOVERY-SUMMARY"] and findings[0].title.endswith("Good")
    assert {tuple(c[:2]) for c in runner.commands} == {("zfs", "list"), ("btrfs", "subvolume"), ("gsettings", "get")}
    assert all(timeout == rc.CMD_TIMEOUT_S for _c, timeout in runner.calls)


def test_run_linux_nothing_found_adds_the_server_note(ctx, tmp_path, monkeypatch):
    monkeypatch.setattr(rc, "IS_WINDOWS", False)
    monkeypatch.setattr(rc, "IS_MAC", False)
    monkeypatch.setattr(rc, "run", FakeRun())
    monkeypatch.setattr(rc, "user_home", lambda: tmp_path / "home")
    monkeypatch.setattr(rc, "LINUX_ROOT", tmp_path / "root")
    findings, checks = split(rc.RecoveryScanner().run(ctx))
    assert rules(findings) == ["AEG-RECOVERY-LINUX-NONE", "AEG-RECOVERY-SUMMARY"]
    assert findings[1].title.endswith("Weak") and "taken from outside the machine" in findings[1].description
    assert [c.status for c in checks] == [CheckStatus.WARN, CheckStatus.WARN, CheckStatus.SKIP, CheckStatus.SKIP]


def test_one_failing_part_does_not_stop_the_others(ctx, tmp_path, monkeypatch):
    windows_world(monkeypatch, tmp_path, GOOD_FACTS, FakeReg().add("HKLM", SR, RPSessionInterval=1))
    ctx.is_admin = True

    def boom(*a, **k):
        raise RuntimeError("registry exploded")

    monkeypatch.setattr(rc, "check_windows_files", boom)
    findings, checks = split(rc.RecoveryScanner().run(ctx))
    by_id = {c.check_id: c for c in checks}
    assert by_id["AEG-RECOVERY-RESTORE"].status == CheckStatus.PASS
    assert by_id["AEG-RECOVERY-BACKUP"].status == CheckStatus.ERROR and "registry exploded" in by_id["AEG-RECOVERY-BACKUP"].detail
    assert by_id["AEG-RECOVERY-CLOUD"].status == CheckStatus.ERROR and len(checks) == 4
    assert rules(findings) == ["AEG-RECOVERY-SUMMARY"] and findings[0].title.endswith("Unknown")


def test_a_failure_of_the_whole_scan_becomes_one_error_check(ctx, monkeypatch):
    def boom(*a, **k):
        raise ValueError("no clock")

    monkeypatch.setattr(rc, "IS_WINDOWS", False)
    monkeypatch.setattr(rc, "IS_MAC", False)
    monkeypatch.setattr(rc, "linux_parts", boom)
    (check,) = list(rc.RecoveryScanner().run(ctx))
    assert isinstance(check, CheckResult) and check.check_id == "AEG-RECOVERY-ERROR" and check.status == CheckStatus.ERROR
    assert "ValueError: no clock" in check.detail


def test_cancelled_scan_still_emits_a_summary(ctx, tmp_path, monkeypatch):
    monkeypatch.setattr(rc, "IS_WINDOWS", False)
    monkeypatch.setattr(rc, "IS_MAC", False)
    runner = FakeRun()
    monkeypatch.setattr(rc, "run", runner)
    ctx.cancel.set()
    findings, checks = split(rc.RecoveryScanner().run(ctx))
    assert runner.calls == [] and rules(findings) == ["AEG-RECOVERY-SUMMARY"] and findings[0].title.endswith("Unknown")
    assert [c.check_id for c in checks] == ["AEG-RECOVERY-OFFLINE"]


def test_every_finding_is_complete_read_only_and_uses_current_attack_ids(ctx, tmp_path, monkeypatch):
    seen = []
    windows_world(monkeypatch, tmp_path, {"drive": "C:", "restore": {"supported": True, "count": 0}, "shadow": {"count": 0}},
                  FakeReg().add("HKLM", SR, RPSessionInterval=0))
    ctx.is_admin = True
    seen += split(rc.RecoveryScanner().run(ctx))[0]
    mac_world(monkeypatch, tmp_path, tm_runner(dest=(0, NO_DEST, ""), prefs=(1, "", "does not exist")))
    seen += split(rc.RecoveryScanner().run(ctx))[0]
    mac_world(monkeypatch, tmp_path, tm_runner(prefs=(0, tm_defaults([ago(days=40)]), "")))
    seen += split(rc.RecoveryScanner().run(ctx))[0]
    monkeypatch.setattr(rc, "IS_MAC", False)
    monkeypatch.setattr(rc, "run", FakeRun())
    monkeypatch.setattr(rc, "LINUX_ROOT", tmp_path / "root")
    monkeypatch.setattr(rc, "user_home", lambda: tmp_path / "home")
    seen += split(rc.RecoveryScanner().run(ctx))[0]
    assert {"AEG-RECOVERY-RESTORE-OFF", "AEG-RECOVERY-FILES-NONE", "AEG-RECOVERY-TM-NONE", "AEG-RECOVERY-TM-STALE",
            "AEG-RECOVERY-LINUX-NONE", "AEG-RECOVERY-SUMMARY"} <= set(rules(seen))
    for f in seen:
        assert f.rule_id.startswith("AEG-RECOVERY-") and f.category == Category.RANSOMWARE, f.rule_id
        assert f.title and f.description and f.location and f.evidence and f.recommendation and f.mitre, f.rule_id
        assert set(f.mitre) <= {"T1486", "T1490"}, f.rule_id
        assert f.remediation is None, f.rule_id  # read-only: no automatic fix
        assert f.severity <= Severity.MEDIUM
        json.dumps(f.to_dict())


def test_engine_runs_the_scanner_end_to_end(tmp_path, monkeypatch):
    from aegis.core.engine import ScanEngine

    monkeypatch.setattr(rc, "IS_WINDOWS", False)
    monkeypatch.setattr(rc, "IS_MAC", False)
    monkeypatch.setattr(rc, "run", FakeRun())
    monkeypatch.setattr(rc, "user_home", lambda: tmp_path / "home")
    monkeypatch.setattr(rc, "LINUX_ROOT", tmp_path / "root")
    result = ScanEngine().scan(profile="custom", scanners=["recovery"])
    assert result.errors == [] and result.scanners == ["recovery"]
    assert {c.check_id for c in result.checks} == {"AEG-RECOVERY-RESTORE", "AEG-RECOVERY-BACKUP", "AEG-RECOVERY-CLOUD",
                                                   "AEG-RECOVERY-OFFLINE"}
    assert {f.rule_id for f in result.findings} == {"AEG-RECOVERY-LINUX-NONE", "AEG-RECOVERY-SUMMARY"}
    assert all(f.scanner == "recovery" for f in result.findings)
    assert json.loads(result.to_json())["scanners"] == ["recovery"]
