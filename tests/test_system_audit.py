"""Unit tests for aegis.scanners.system_audit decision logic (mocked registry / PowerShell facts)."""

import datetime as dt
import os
import stat

import pytest

from aegis.core.config import Config
from aegis.core.models import CheckResult, CheckStatus, Finding, Severity
from aegis.core.signatures import SignatureDB
from aegis.scanners import system_audit as sa
from aegis.scanners.base import ScanContext

TODAY = dt.date(2026, 10, 15)
CV = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"


class FakeReg:
    """Dict-backed registry: keys are (hive, key, value) in any case."""

    def __init__(self, values=None, subkeys=None, valuemaps=None):
        self.values = {(h.upper(), k.lower(), v.lower()): d for (h, k, v), d in (values or {}).items()}
        self.subkeys = {(h.upper(), k.lower()): s for (h, k), s in (subkeys or {}).items()}
        self.valuemaps = {(h.upper(), k.lower()): m for (h, k), m in (valuemaps or {}).items()}

    def read(self, hive, key, value, view64=True):
        return self.values.get((hive.upper(), key.lower(), value.lower()))

    def subkeys_of(self, hive, key, view64=True):
        return list(self.subkeys.get((hive.upper(), key.lower()), []))

    def values_of(self, hive, key, view64=True):
        return dict(self.valuemaps.get((hive.upper(), key.lower()), {}))


@pytest.fixture
def reg(monkeypatch):
    def install(values=None, subkeys=None, valuemaps=None):
        fake = FakeReg(values, subkeys, valuemaps)
        monkeypatch.setattr(sa, "reg_read", fake.read)
        monkeypatch.setattr(sa, "reg_subkeys", fake.subkeys_of)
        monkeypatch.setattr(sa, "reg_values", fake.values_of)
        return fake

    install()
    return install


def env(facts=None, admin=False):
    return sa.AuditEnv(today=TODAY, is_admin=admin, facts=facts or {})


def by_key(checks):
    return {c.key: c for c in checks}


# ---------------------------------------------------------------- OS support table
@pytest.mark.parametrize("build,edition,expect_status,expect_sev", [
    (19045, "Professional", "eol", Severity.HIGH),      # Windows 10 22H2: ended 2025-10-14
    (19044, "Core", "eol", Severity.HIGH),
    (10240, "Professional", "eol", Severity.HIGH),
    (7601, "Professional", "eol", Severity.CRITICAL),   # Windows 7
    (9600, "Professional", "eol", Severity.CRITICAL),   # Windows 8.1
    (9200, "Core", "eol", Severity.CRITICAL),           # Windows 8
    (22000, "Professional", "eol", Severity.HIGH),      # 11 21H2
    (22621, "Core", "eol", Severity.HIGH),              # 22H2
    (22631, "Professional", "eol", Severity.HIGH),      # 23H2 Pro ended 2025-11-11
    (22631, "Enterprise", "ending_soon", Severity.LOW),  # Ent/Edu until 2026-11-10 (26 days)
    (26100, "Core", "eol", Severity.HIGH),              # 24H2 Home ended 2026-10-13
    (26100, "Enterprise", "supported", None),           # Ent/Edu until 2027-10-12
    (26200, "Professional", "supported", None),         # 25H2
    (26200, "Core", "supported", None),
    (26300, "Professional", "supported", None),
    (30000, "Professional", "supported", None),         # newer than the table
])
def test_os_support_matrix(build, edition, expect_status, expect_sev):
    r = sa.evaluate_os_support(build, edition, today=TODAY)
    assert r.status == expect_status, r.detail
    assert r.severity == expect_sev


def test_os_support_dates_and_detail():
    r = sa.evaluate_os_support(19045, "Professional", today=TODAY, display_version="22H2")
    assert r.eol == dt.date(2025, 10, 14) and r.days_left == -366
    assert "ESU" in r.recommendation and "Windows 11" in r.recommendation
    r11 = sa.evaluate_os_support(26100, "Enterprise", today=TODAY)
    assert r11.eol == dt.date(2027, 10, 12)
    assert "Enterprise/Education" in r11.detail
    # one day before / after the boundary
    assert sa.evaluate_os_support(26100, "Core", today=dt.date(2026, 10, 13)).status == "ending_soon"
    assert sa.evaluate_os_support(26100, "Core", today=dt.date(2026, 10, 14)).status == "eol"


def test_os_support_ltsc_and_server():
    ltsc = sa.evaluate_os_support(19044, "EnterpriseS", today=TODAY)
    assert ltsc.status == "ending_soon" and ltsc.eol == dt.date(2027, 1, 12)  # 89 days away
    assert sa.evaluate_os_support(17763, "EnterpriseS", today=TODAY).status == "supported"  # LTSC 2019 -> 2029
    iot = sa.evaluate_os_support(19044, "IoTEnterpriseS", today=TODAY)
    assert iot.eol == dt.date(2032, 1, 13)
    s = sa.evaluate_os_support(9600, "ServerStandard", today=TODAY, installation_type="Server")
    assert s.status == "eol" and s.severity == Severity.HIGH and "2012 R2" in s.name
    assert sa.evaluate_os_support(20348, "ServerStandard", today=TODAY, installation_type="Server").status == "supported"


def test_check_os_support_registry(reg):
    reg({("HKLM", CV, "CurrentBuild"): "19045", ("HKLM", CV, "EditionID"): "Professional",
         ("HKLM", CV, "DisplayVersion"): "22H2", ("HKLM", CV, "UBR"): 5011})
    (c,) = sa.check_os_support(env())
    assert c.ok is False and c.severity == Severity.HIGH and c.status == CheckStatus.FAIL
    f = c.to_finding()
    assert f.rule_id == "AEG-AUDIT-OS-SUPPORT" and "Windows 10" in f.title and f.evidence["end_of_support"] == "2025-10-14"

    reg({("HKLM", CV, "CurrentBuild"): "26200", ("HKLM", CV, "EditionID"): "Core", ("HKLM", CV, "DisplayVersion"): "25H2"})
    (c,) = sa.check_os_support(env())
    assert c.ok is True and c.status == CheckStatus.PASS

    reg()
    (c,) = sa.check_os_support(env())
    assert c.ok is None and c.status == CheckStatus.SKIP


# ---------------------------------------------------------------- antivirus
def test_decode_product_state():
    assert sa.decode_product_state(397568) == (True, True)    # 0x061100 Defender on, current
    assert sa.decode_product_state(397584) == (True, False)   # 0x061110 on, outdated
    assert sa.decode_product_state(393472) == (False, True)   # 0x060100 off
    assert sa.decode_product_state(266240) == (True, True)    # 0x041000
    assert sa.decode_product_state(None) == (False, False)


MP_OK = {"AMServiceEnabled": True, "AntivirusEnabled": True, "RealTimeProtectionEnabled": True,
         "BehaviorMonitorEnabled": True, "IsTamperProtected": True, "AntivirusSignatureAge": 1, "QuickScanAge": 2,
         "AMRunningMode": "Normal"}


def av_facts(products=(), mp=None):
    f = {"av": [{"name": n, "state": s} for n, s in products]}
    if mp is not None:
        f["mp"] = mp
    return f


def test_av_healthy_defender():
    c = by_key(sa.check_antivirus(env(av_facts([("Windows Defender", 397568)], MP_OK))))
    assert all(x.ok in (True,) for x in c.values())


def test_av_no_active_av_is_critical():
    c = by_key(sa.check_antivirus(env(av_facts([("Windows Defender", 393472)], dict(MP_OK, RealTimeProtectionEnabled=False)))))
    assert c["AV-ACTIVE"].ok is False and c["AV-ACTIVE"].severity == Severity.CRITICAL
    assert "real-time" in c["AV-ACTIVE"].title.lower()
    assert c["AV-ACTIVE"].remediation.action == "run_command"
    c = by_key(sa.check_antivirus(env(av_facts([("Acme AV", 393472)]))))
    assert c["AV-ACTIVE"].severity == Severity.CRITICAL and c["AV-ACTIVE"].title == "No active antivirus"


def test_av_third_party_active_defender_passive_is_fine():
    mp = dict(MP_OK, RealTimeProtectionEnabled=False, AMRunningMode="Passive", IsTamperProtected=False)
    c = by_key(sa.check_antivirus(env(av_facts([("Windows Defender", 393472), ("Contoso Antivirus", 266240)], mp))))
    assert c["AV-ACTIVE"].ok is True
    assert c["AV-TAMPER"].ok is None  # skipped: defender not primary


def test_av_stale_signatures_and_tamper():
    mp = dict(MP_OK, AntivirusSignatureAge=8, IsTamperProtected=False)
    c = by_key(sa.check_antivirus(env(av_facts([("Windows Defender", 397568)], mp))))
    assert c["AV-SIGNATURES"].ok is False and c["AV-SIGNATURES"].severity == Severity.MEDIUM
    assert c["AV-TAMPER"].ok is False and c["AV-TAMPER"].severity == Severity.LOW
    c = by_key(sa.check_antivirus(env(av_facts([("Windows Defender", 397568)], dict(MP_OK, AntivirusSignatureAge=7)))))
    assert c["AV-SIGNATURES"].ok is True  # 7 days is the limit
    # third party reporting outdated definitions
    c = by_key(sa.check_antivirus(env(av_facts([("Contoso Antivirus", 266256)]))))
    assert c["AV-SIGNATURES"].ok is False


def test_av_unavailable_is_skip():
    c = sa.check_antivirus(env({}))
    assert all(x.ok is None for x in c)


# ---------------------------------------------------------------- Defender preferences
@pytest.mark.parametrize("kind,value,expected", [
    ("path", "C:\\", True), ("path", "C:", True), ("path", "D:\\*", True), ("path", "C:\\Users", True),
    ("path", r"C:\Users\bob\AppData\Local\Temp", True), ("path", r"C:\Users\bob\Downloads", True),
    ("path", r"C:\Users\bob\AppData\Roaming\Foo", True), ("path", "%TEMP%", True), ("path", r"C:\Windows\Temp\x", True),
    ("path", r"C:\Dev\MyProject", False), ("path", r"C:\Program Files\Vendor\App", False),
    ("process", "powershell.exe", True), ("process", r"C:\Windows\System32\cmd.exe", True),
    ("process", r"C:\Users\bob\AppData\Roaming\x\evil.exe", True), ("process", "mybuildtool.exe", False),
    ("extension", "exe", True), ("extension", ".dll", True), ("extension", "*.ps1", True), ("extension", "log", False),
])
def test_classify_exclusion(kind, value, expected):
    assert bool(sa.classify_exclusion(kind, value)) is expected


def pref(**kw):
    base = {"ExclusionPath": [], "ExclusionProcess": [], "ExclusionExtension": [], "PUAProtection": 1,
            "EnableControlledFolderAccess": 1, "MAPSReporting": 2}
    base.update(kw)
    return base


def test_exclusions_suspicious_is_high(reg):
    facts = av_facts([("Windows Defender", 397568)], MP_OK)
    facts["pref"] = pref(ExclusionPath=["C:\\", r"C:\Dev\Proj"], ExclusionExtension=["exe"])
    c = by_key(sa.check_defender_prefs(env(facts)))
    ex = c["DEFENDER-EXCLUSIONS"]
    assert ex.ok is False and ex.severity == Severity.HIGH
    assert {b["value"] for b in ex.evidence["suspicious"]} == {"C:\\", "exe"}


def test_exclusions_not_admin_is_skip(reg):
    facts = av_facts([("Windows Defender", 397568)], MP_OK)
    na = "N/A: Must be an administrator to view exclusions"
    facts["pref"] = pref(ExclusionPath=[na], ExclusionProcess=[na], ExclusionExtension=[na])
    c = by_key(sa.check_defender_prefs(env(facts)))
    assert c["DEFENDER-EXCLUSIONS"].ok is None and c["DEFENDER-EXCLUSIONS"].status == CheckStatus.SKIP


def test_exclusions_registry_fallback(reg):
    reg(valuemaps={("HKLM", r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"): {"C:\\": 0}})
    facts = av_facts([("Windows Defender", 397568)], MP_OK)
    na = "N/A: Must be an administrator to view exclusions"
    facts["pref"] = pref(ExclusionPath=[na])
    c = by_key(sa.check_defender_prefs(env(facts)))
    assert c["DEFENDER-EXCLUSIONS"].ok is False


def test_defender_pua_cfa_maps(reg):
    facts = av_facts([("Windows Defender", 397568)], MP_OK)
    facts["pref"] = pref(PUAProtection=0, EnableControlledFolderAccess=0, MAPSReporting=0)
    c = by_key(sa.check_defender_prefs(env(facts)))
    for k in ("DEFENDER-PUA", "DEFENDER-CFA", "DEFENDER-CLOUD"):
        assert c[k].ok is False and c[k].severity == Severity.LOW
    assert c["DEFENDER-PUA"].remediation.params["command"].startswith("Set-MpPreference")
    assert c["DEFENDER-CFA"].remediation is None  # may block legitimate apps -> manual
    facts["pref"] = pref()
    c = by_key(sa.check_defender_prefs(env(facts)))
    assert all(c[k].ok for k in ("DEFENDER-PUA", "DEFENDER-CFA", "DEFENDER-CLOUD"))
    # third-party AV primary -> these are skipped
    facts = av_facts([("Contoso", 266240)], dict(MP_OK, AMRunningMode="Passive", RealTimeProtectionEnabled=False))
    facts["pref"] = pref(PUAProtection=0)
    c = by_key(sa.check_defender_prefs(env(facts)))
    assert c["DEFENDER-PUA"].ok is None


# ---------------------------------------------------------------- firewall / UAC
FWL = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
FWP = r"SOFTWARE\Policies\Microsoft\WindowsFirewall"


def test_firewall(reg):
    (c,) = sa.check_firewall(env())
    assert c.ok is True
    reg({("HKLM", FWL + r"\PublicProfile", "EnableFirewall"): 0, ("HKLM", FWL + r"\DomainProfile", "EnableFirewall"): 1})
    (c,) = sa.check_firewall(env())
    assert c.ok is False and c.severity == Severity.HIGH
    assert c.remediation.params["command"] == ["netsh", "advfirewall", "set", "allprofiles", "state", "on"]
    assert c.evidence["profiles_off"][0]["profile"] == "Public"
    # group policy forces it off -> no auto fix
    reg({("HKLM", FWP + r"\StandardProfile", "EnableFirewall"): 0})
    (c,) = sa.check_firewall(env())
    assert c.ok is False and c.remediation is None
    # a third-party firewall is registered and active
    (c,) = sa.check_firewall(env({"fw": [{"name": "Contoso Firewall", "state": 266240}]}))
    assert c.ok is True
    # policy overrides local off
    reg({("HKLM", FWL + r"\PublicProfile", "EnableFirewall"): 0, ("HKLM", FWP + r"\PublicProfile", "EnableFirewall"): 1})
    (c,) = sa.check_firewall(env())
    assert c.ok is True


def test_uac(reg):
    assert all(c.ok for c in sa.check_uac(env()))
    sysk = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    reg({("HKLM", sysk, "EnableLUA"): 0, ("HKLM", sysk, "ConsentPromptBehaviorAdmin"): 0, ("HKLM", sysk, "PromptOnSecureDesktop"): 0})
    c = by_key(sa.check_uac(env()))
    assert (c["UAC-DISABLED"].severity, c["UAC-NOPROMPT"].severity, c["UAC-NOSECUREDESKTOP"].severity) == (
        Severity.HIGH, Severity.MEDIUM, Severity.LOW)
    assert c["UAC-DISABLED"].remediation.action == "set_registry_value"
    assert c["UAC-DISABLED"].remediation.params["data"] == 1 and c["UAC-DISABLED"].remediation.params["value"] == "EnableLUA"


# ---------------------------------------------------------------- SMB / RDP
def test_smb(reg):
    srv = r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    c = by_key(sa.check_smb(env()))
    assert c["SMB1-SERVER"].ok is None  # not determinable without admin
    assert c["SMB1-CLIENT"].ok is True
    reg({("HKLM", srv, "SMB1"): 1, ("HKLM", r"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start"): 2})
    c = by_key(sa.check_smb(env()))
    assert c["SMB1-SERVER"].ok is False and c["SMB1-SERVER"].severity == Severity.HIGH
    assert c["SMB1-CLIENT"].ok is False and c["SMB1-CLIENT"].severity == Severity.HIGH
    reg({("HKLM", srv, "SMB1"): 0, ("HKLM", r"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start"): 4})
    c = by_key(sa.check_smb(env()))
    assert c["SMB1-SERVER"].ok is True and c["SMB1-CLIENT"].ok is True
    reg()
    assert by_key(sa.check_smb(env({"smb1_server": True})))["SMB1-SERVER"].ok is False


def test_rdp(reg):
    ts = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
    c = by_key(sa.check_rdp(env()))
    assert c["RDP-ENABLED"].ok is True
    reg({("HKLM", ts, "fDenyTSConnections"): 0, ("HKLM", ts + r"\WinStations\RDP-Tcp", "UserAuthentication"): 1})
    c = by_key(sa.check_rdp(env()))
    assert c["RDP-ENABLED"].ok is False and c["RDP-ENABLED"].severity == Severity.MEDIUM and c["RDP-NLA"].ok is True
    reg({("HKLM", ts, "fDenyTSConnections"): 0, ("HKLM", ts + r"\WinStations\RDP-Tcp", "UserAuthentication"): 0})
    c = by_key(sa.check_rdp(env()))
    assert c["RDP-NLA"].ok is False and c["RDP-NLA"].severity == Severity.HIGH
    assert c["RDP-NLA"].remediation.params["data"] == 1


# ---------------------------------------------------------------- BitLocker / boot
def test_bitlocker():
    assert sa.check_bitlocker(env())[0].ok is None
    assert sa.check_bitlocker(env({"bitlocker": {"status": 1, "drive": "C:"}}))[0].ok is True
    c = sa.check_bitlocker(env({"bitlocker": {"status": 0, "drive": "C:"}}))[0]
    assert c.ok is False and c.severity == Severity.MEDIUM


def test_secure_boot_and_dg(reg):
    sb = r"SYSTEM\CurrentControlSet\Control\SecureBoot\State"
    reg({("HKLM", sb, "UEFISecureBootEnabled"): 0})
    c = by_key(sa.check_secure_boot(env()))
    assert c["SECURE-BOOT"].ok is False and c["SECURE-BOOT"].severity == Severity.LOW
    reg()
    assert by_key(sa.check_secure_boot(env()))["SECURE-BOOT"].severity == Severity.INFO
    reg({("HKLM", sb, "UEFISecureBootEnabled"): 1})
    c = by_key(sa.check_secure_boot(env({"dg": {"vbs": 2, "running": [1, 2]}, "tpm": {"enabled": True, "spec": "2.0"}})))
    assert c["SECURE-BOOT"].ok and c["VBS"].ok and c["HVCI"].ok and c["CREDGUARD"].ok and c["TPM"].ok
    c = by_key(sa.check_secure_boot(env({"dg": {"vbs": 0, "running": []}})))
    assert c["HVCI"].ok is False and c["HVCI"].severity == Severity.INFO


# ---------------------------------------------------------------- Windows Update
def test_windows_update_age(reg):
    def run_age(days):
        last = (TODAY - dt.timedelta(days=days)).isoformat() + "T10:11:12.1234567Z"
        return by_key(sa.check_windows_update(env({"wu_last": last, "wu_title": "KB123"})))["WU-STALE"]

    assert run_age(10).ok is True
    assert run_age(45).ok is True
    c = run_age(46)
    assert c.ok is False and c.severity == Severity.MEDIUM
    c = run_age(90)
    assert c.ok is False and c.severity == Severity.MEDIUM
    c = run_age(91)
    assert c.ok is False and c.severity == Severity.HIGH
    assert by_key(sa.check_windows_update(env()))["WU-STALE"].ok is None


def test_windows_update_service_and_reboot(reg):
    reg({("HKLM", r"SYSTEM\CurrentControlSet\Services\wuauserv", "Start"): 4,
         ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate"): 1},
        subkeys={("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"): ["RebootRequired"]})
    c = by_key(sa.check_windows_update(env()))
    assert c["WU-SERVICE-DISABLED"].ok is False and c["WU-SERVICE-DISABLED"].severity == Severity.HIGH
    assert c["WU-AUTO-OFF"].ok is False
    assert c["WU-REBOOT-PENDING"].ok is False and c["WU-REBOOT-PENDING"].severity == Severity.LOW


# ---------------------------------------------------------------- credentials
def test_credential_checks(reg):
    lsa = r"SYSTEM\CurrentControlSet\Control\Lsa"
    wl = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    reg({("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential"): 1,
         ("HKLM", lsa, "NoLMHash"): 0, ("HKLM", lsa, "LmCompatibilityLevel"): 1,
         ("HKLM", wl, "DefaultPassword"): "hunter2-secret", ("HKLM", wl, "AutoAdminLogon"): "1"})
    facts = {"users": [
        {"name": "Guest", "sid": "S-1-5-21-1-2-3-501", "enabled": True, "pwreq": False, "never_expires": True},
        {"name": "bob", "sid": "S-1-5-21-1-2-3-1001", "enabled": True, "pwreq": False, "never_expires": True},
        {"name": "alice", "sid": "S-1-5-21-1-2-3-1002", "enabled": False, "pwreq": False, "never_expires": True},
    ], "user": "PC\\bob", "in_admins": True}
    c = by_key(sa.check_credentials(env(facts)))
    assert c["WDIGEST"].severity == Severity.HIGH and c["WDIGEST"].ok is False
    assert c["WDIGEST"].remediation.params["data"] == 0
    assert c["LSA-PPL"].ok is False and c["LSA-PPL"].severity == Severity.LOW
    assert c["NOLMHASH"].severity == Severity.MEDIUM and c["LMCOMPAT"].severity == Severity.MEDIUM
    assert c["GUEST"].ok is False and c["GUEST"].severity == Severity.MEDIUM
    assert c["ACCOUNT-NOPASSWORD"].evidence["accounts"] == ["bob"]  # Guest/disabled excluded
    assert c["ADMIN-USER"].ok is False and c["ADMIN-USER"].severity == Severity.LOW
    ap = c["AUTOLOGON-PASSWORD"]
    assert ap.ok is False and ap.severity == Severity.HIGH
    assert "hunter2" not in repr(ap.evidence) and "hunter2" not in ap.description and ap.remediation is None
    assert "hunter2" not in repr(ap.to_finding().to_dict())


def test_credentials_clean(reg):
    lsa = r"SYSTEM\CurrentControlSet\Control\Lsa"
    reg({("HKLM", lsa, "RunAsPPL"): 1, ("HKLM", lsa, "LmCompatibilityLevel"): 5})
    facts = {"users": [{"name": "bob", "sid": "S-1-5-21-1-2-3-1001", "enabled": True, "pwreq": True, "never_expires": False},
                       {"name": "Guest", "sid": "S-1-5-21-1-2-3-501", "enabled": False, "pwreq": False, "never_expires": True}],
             "user": "PC\\bob", "in_admins": False}
    assert all(c.ok for c in sa.check_credentials(env(facts)))


# ---------------------------------------------------------------- hygiene / office
def test_hygiene(reg):
    expl = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    reg({("HKCU", expl, "HideFileExt"): 1,
         ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen"): 0})
    c = by_key(sa.check_hygiene(env({"remote_registry": "Running", "ps2": "Enabled"}, admin=True)))
    assert c["HIDE-FILE-EXT"].ok is False and c["HIDE-FILE-EXT"].remediation.params["hive"] == "HKCU"
    assert c["HIDE-FILE-EXT"].remediation.params["data"] == 0
    assert c["SMARTSCREEN"].severity == Severity.MEDIUM and c["SMARTSCREEN"].ok is False
    assert c["AUTORUN"].ok is False and c["AUTORUN"].severity == Severity.LOW
    assert c["WSH"].severity == Severity.INFO and c["WSH"].ok is False
    assert c["PS2-ENGINE"].ok is False and c["REMOTE-REGISTRY"].remediation.action == "disable_service"
    assert c["LLMNR"].ok is False and c["PS-SCRIPTBLOCK-LOG"].ok is False


def test_hygiene_good(reg):
    explorer_pol = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    reg({("HKLM", explorer_pol, "NoDriveTypeAutoRun"): 255,
         ("HKLM", r"SOFTWARE\Microsoft\Windows Script Host\Settings", "Enabled"): 0,
         ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging"): 1,
         ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast"): 0})
    c = by_key(sa.check_hygiene(env({"remote_registry": "Stopped", "ps2": "Disabled"}, admin=True)))
    assert all(c[k].ok for k in ("AUTORUN", "WSH", "PS2-ENGINE", "PS-SCRIPTBLOCK-LOG", "LLMNR", "REMOTE-REGISTRY",
                                 "SMARTSCREEN", "HIDE-FILE-EXT"))


def test_office_macros(reg):
    assert all(c.ok is None for c in sa.check_office(env()))  # Office not installed
    reg(values={("HKCU", r"Software\Microsoft\Office\16.0\Word\Security", "VBAWarnings"): 1,
                ("HKCU", r"Software\Microsoft\Office\16.0\Excel\Security", "blockcontentexecutionfrominternet"): 0},
        subkeys={("HKLM", r"SOFTWARE\Microsoft\Office"): ["ClickToRun"]})
    c = by_key(sa.check_office(env()))
    assert c["OFFICE-MACROS"].ok is False and c["OFFICE-MACROS"].severity == Severity.HIGH
    assert c["OFFICE-MACROS"].remediation.params["data"] == 2
    assert c["OFFICE-INTERNET-MACROS"].ok is False and c["OFFICE-INTERNET-MACROS"].severity == Severity.MEDIUM
    reg(subkeys={("HKLM", r"SOFTWARE\Microsoft\Office"): ["16.0"]})
    assert all(c.ok for c in sa.check_office(env()))


# ---------------------------------------------------------------- emission contract
def test_every_check_yields_result_and_failures_yield_findings(reg):
    reg({("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuild"): "19045"})
    items = list(sa.run_checks(env(), sa.WINDOWS_CHECKS))
    results = [i for i in items if isinstance(i, CheckResult)]
    findings = [i for i in items if isinstance(i, Finding)]
    assert len(results) > 30
    ids = {r.check_id for r in results}
    for f in findings:
        assert f.rule_id in ids and f.rule_id.startswith("AEG-AUDIT-")
        assert f.recommendation and f.title and f.location and f.category == "system"
    assert any(f.rule_id == "AEG-AUDIT-OS-SUPPORT" for f in findings)


def test_exception_in_check_becomes_error_result():
    def boom(_env):
        raise RuntimeError("kaput")

    out = list(sa.run_checks(env(), [boom, lambda e: [sa.passed("X-OK", "ok")]]))
    assert out[0].status == CheckStatus.ERROR and "kaput" in out[0].detail
    assert out[1].status == CheckStatus.PASS


def test_findings_are_json_serialisable(reg):
    import json

    reg({("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuild"): "7601"})
    for item in sa.run_checks(env(), sa.WINDOWS_CHECKS):
        if isinstance(item, Finding):
            json.dumps(item.to_dict())


# ---------------------------------------------------------------- Linux
def test_parse_sshd_config_first_wins_and_match():
    cfg = sa.parse_sshd_config("PermitRootLogin no\nPermitRootLogin yes\nPasswordAuthentication yes\n"
                               "Match User bob\n  PermitRootLogin yes\n  X11Forwarding yes\n")
    assert cfg["permitrootlogin"] == "no" and cfg["passwordauthentication"] == "yes" and "x11forwarding" not in cfg
    inc = sa.parse_sshd_config("Include conf.d/*.conf\nPermitRootLogin yes\n",
                               include_reader=lambda pat: ["PermitRootLogin prohibit-password\n"])
    assert inc["permitrootlogin"] == "prohibit-password"
    assert sa.parse_sshd_config("PermitRootLogin=yes\n")["permitrootlogin"] == "yes"


def test_linux_ssh_checks(monkeypatch):
    monkeypatch.setattr(sa, "_read_text", lambda p, limit=0: "PermitRootLogin yes\nPasswordAuthentication yes\n")
    monkeypatch.setattr(sa, "_sshd_running", lambda: True)
    c = by_key(sa.check_linux_ssh(env()))
    assert c["SSH-ROOT-LOGIN"].ok is False and c["SSH-ROOT-LOGIN"].severity == Severity.HIGH
    assert c["SSH-PASSWORD-AUTH"].ok is False and c["SSH-PASSWORD-AUTH"].severity == Severity.MEDIUM
    monkeypatch.setattr(sa, "_sshd_running", lambda: False)
    c = by_key(sa.check_linux_ssh(env()))
    assert c["SSH-ROOT-LOGIN"].severity == Severity.MEDIUM  # downgraded: not running
    monkeypatch.setattr(sa, "_read_text", lambda p, limit=0: "PermitRootLogin no\nPasswordAuthentication no\n")
    assert all(x.ok for x in sa.check_linux_ssh(env()))
    monkeypatch.setattr(sa, "_read_text", lambda p, limit=0: None)
    assert all(x.ok is None for x in sa.check_linux_ssh(env()))


def test_find_nopasswd_all():
    text = ("# comment\nDefaults env_reset\nroot ALL=(ALL:ALL) ALL\nbob ALL=(ALL) NOPASSWD: ALL\n"
            "%wheel ALL=(ALL:ALL) NOPASSWD:ALL\nalice ALL=(ALL) NOPASSWD: /usr/bin/apt\nroot ALL=(ALL) NOPASSWD: ALL\n")
    hits = sa.find_nopasswd_all([("/etc/sudoers", text)])
    assert [h["principal"] for h in hits] == ["bob", "%wheel"]


posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits (chmod) don't exist on Windows")


@posix_only
def test_find_world_writable(tmp_path):
    d = tmp_path / "etc"
    (d / "sub").mkdir(parents=True)
    f1, f2, sticky = d / "bad.conf", d / "sub" / "ok.conf", d / "tmpdir"
    f1.write_text("x"), f2.write_text("y")
    sticky.mkdir()
    os.chmod(f1, 0o666)
    os.chmod(f2, 0o644)
    os.chmod(sticky, 0o1777)
    (d / "link").symlink_to(f1)
    assert sa.find_world_writable(str(d)) == [str(f1)]
    assert sa.find_world_writable(str(tmp_path / "missing")) is None


@posix_only
def test_suid_detection(tmp_path):
    bad = tmp_path / "backdoor"
    bad.write_text("#!/bin/sh\n")
    os.chmod(bad, 0o4755)
    plain = tmp_path / "plain"
    plain.write_text("x")
    paths, timed_out = sa.find_suid([str(tmp_path)], 5)
    assert paths == [str(bad)] and not timed_out
    unknown, suspicious = sa.classify_suid(["/usr/bin/sudo", "/usr/bin/weirdtool", "/tmp/x/backdoor", "/home/u/.local/su"])
    assert unknown == ["/usr/bin/weirdtool"]
    assert suspicious == ["/tmp/x/backdoor", "/home/u/.local/su"]


def test_linux_firewall_logic(monkeypatch):
    monkeypatch.setattr(sa.shutil, "which", lambda n: "/usr/sbin/" + n if n in ("ufw",) else None)

    def fake_run(cmd, timeout=60, input_text=None):
        if cmd[:2] == ["ufw", "status"]:
            return 0, "Status: active\n", ""
        return 1, "inactive", ""

    monkeypatch.setattr(sa, "run", fake_run)
    assert sa.check_linux_firewall(env())[0].ok is True

    def inactive(cmd, timeout=60, input_text=None):
        return (0, "Status: inactive\n", "") if cmd[:2] == ["ufw", "status"] else (1, "inactive", "")

    monkeypatch.setattr(sa, "run", inactive)
    c = sa.check_linux_firewall(env())[0]
    assert c.ok is False and c.severity == Severity.MEDIUM

    monkeypatch.setattr(sa.shutil, "which", lambda n: None)
    monkeypatch.setattr(sa, "run", lambda cmd, timeout=60, input_text=None: (-1, "", "nf"))
    assert sa.check_linux_firewall(env(admin=False))[0].ok is None
    assert sa.check_linux_firewall(env(admin=True))[0].ok is False


def test_linux_file_checks_with_mocks(monkeypatch, tmp_path):
    files = {"/etc/ld.so.preload": "/lib/evil.so\n", "/proc/sys/kernel/randomize_va_space": "0\n",
             "/etc/sudoers": "bob ALL=(ALL) NOPASSWD: ALL\n"}
    monkeypatch.setattr(sa, "_read_text", lambda p, limit=0: files.get(p))
    monkeypatch.setattr(sa.glob, "glob", lambda pat: [])
    c = by_key(sa.check_linux_files(env()))
    assert c["LINUX-LD-PRELOAD"].ok is False and c["LINUX-LD-PRELOAD"].severity == Severity.HIGH
    assert c["LINUX-SUDO-NOPASSWD"].ok is False
    assert "LINUX-ASLR" not in c  # ASLR is audited by check_linux_kernel (AEG-AUDIT-KERNEL-ASLR)
    files["/etc/ld.so.preload"] = "# nothing\n"
    c = by_key(sa.check_linux_files(env()))
    assert c["LINUX-LD-PRELOAD"].ok is True


# ---------------------------------------------------------------- macOS
def test_macos_checks(monkeypatch):
    outputs = {
        "csrutil": (0, "System Integrity Protection status: disabled.", ""),
        "spctl": (0, "assessments enabled", ""),
        "fdesetup": (0, "FileVault is Off.", ""),
        "socketfilterfw": (0, "Firewall is disabled. (State = 0)", ""),
        "defaults": (0, "0\n", ""),
    }
    monkeypatch.setattr(sa, "run", lambda cmd, timeout=60, input_text=None: outputs[os.path.basename(cmd[0])])
    c = by_key(sa.check_macos(env()))
    assert c["MAC-SIP"].ok is False and c["MAC-SIP"].severity == Severity.HIGH
    assert c["MAC-GATEKEEPER"].ok is True
    assert c["MAC-FILEVAULT"].ok is False and c["MAC-FIREWALL"].ok is False and c["MAC-AUTO-UPDATES"].ok is False
    outputs.update({"csrutil": (0, "System Integrity Protection status: enabled.", ""),
                    "fdesetup": (0, "FileVault is On.", ""), "socketfilterfw": (0, "Firewall is enabled. (State = 1)", ""),
                    "defaults": (0, "1\n", "")})
    assert all(x.ok for x in sa.check_macos(env()))
    monkeypatch.setattr(sa, "run", lambda cmd, timeout=60, input_text=None: (-1, "", "nf"))
    assert all(x.ok is None for x in sa.check_macos(env()))


# ---------------------------------------------------------------- real scanner run (Linux CI)
def test_scanner_runs_on_this_platform(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path))
    cfg = Config()
    ctx = ScanContext(config=cfg, signatures=SignatureDB(cfg))
    items = list(sa.SystemAuditScanner().run(ctx))
    assert any(isinstance(i, CheckResult) for i in items)
    for i in items:
        if isinstance(i, CheckResult):
            assert i.status in (CheckStatus.PASS, CheckStatus.FAIL, CheckStatus.WARN, CheckStatus.SKIP, CheckStatus.ERROR)
            assert i.status != CheckStatus.ERROR, i
    assert sa.SystemAuditScanner.name == "system_audit"
    from aegis.scanners.base import REGISTRY
    assert REGISTRY["system_audit"] is sa.SystemAuditScanner


# ---------------------------------------------------------------- exploit protection
def _by_key(checks):
    return {c.key: c for c in checks}


def test_exploit_protection_defaults_pass():
    facts = {"mitig": {"dep": "NOTSET", "bottomup": "NOTSET", "highentropy": "NOTSET", "forcereloc": "NOTSET",
                       "cfg": "NOTSET", "sehop": "NOTSET"}, "dep_policy": 2}
    checks = _by_key(sa.check_exploit_protection(env(facts)))
    assert set(checks) == {"EXPLOIT-DEP", "EXPLOIT-ASLR", "EXPLOIT-CFG", "EXPLOIT-SEHOP"}
    assert all(c.ok is True for c in checks.values())
    assert "OptIn" in checks["EXPLOIT-DEP"].detail and all(c.to_finding() is None for c in checks.values())


def test_exploit_protection_flags_explicitly_disabled_mitigations():
    facts = {"mitig": {"dep": "NOTSET", "bottomup": "OFF", "highentropy": "NOTSET", "forcereloc": "NOTSET",
                       "cfg": "OFF", "sehop": "OFF"}, "dep_policy": 0}
    checks = _by_key(sa.check_exploit_protection(env(facts)))
    dep = checks["EXPLOIT-DEP"].to_finding()
    assert dep.severity == Severity.HIGH and "AlwaysOff" in dep.description and dep.remediation is None  # BitLocker caution
    assert "BitLocker" in dep.recommendation and dep.evidence["dep_support_policy"] == "AlwaysOff"
    aslr = checks["EXPLOIT-ASLR"].to_finding()
    assert aslr.severity == Severity.MEDIUM and aslr.description.startswith("Bottom-up ASLR is switched off")
    assert aslr.remediation.params["command"] == "Set-ProcessMitigation -System -Enable BottomUp,HighEntropy"
    for key, flag in (("EXPLOIT-CFG", "CFG"), ("EXPLOIT-SEHOP", "SEHOP")):
        f = checks[key].to_finding()
        assert f.severity == Severity.MEDIUM and f.remediation.params["powershell"] is True
        assert f.remediation.params["command"] == f"Set-ProcessMitigation -System -Enable {flag}"
        assert f.mitre == ["T1685"] and f.rule_id == "AEG-AUDIT-" + key


def test_exploit_protection_dep_off_via_mitigation_and_aslr_wording():
    facts = {"mitig": {"dep": "OFF", "bottomup": "OFF", "highentropy": "OFF", "cfg": "ON", "sehop": "ON", "forcereloc": "ON"}}
    checks = _by_key(sa.check_exploit_protection(env(facts)))
    assert checks["EXPLOIT-DEP"].ok is False and "exploit protection setting OFF" in checks["EXPLOIT-DEP"].description
    assert checks["EXPLOIT-ASLR"].description.startswith("Bottom-up ASLR and high-entropy ASLR are switched off")
    assert checks["EXPLOIT-CFG"].ok is True and checks["EXPLOIT-CFG"].detail == "Explicitly on."


def test_exploit_protection_unavailable_is_skipped_and_partial_facts_work():
    checks = sa.check_exploit_protection(env({}))
    assert len(checks) == 1 and checks[0].ok is None and checks[0].status == CheckStatus.SKIP
    only_policy = _by_key(sa.check_exploit_protection(env({"dep_policy": 3})))
    assert only_policy["EXPLOIT-DEP"].ok is True and "OptOut" in only_policy["EXPLOIT-DEP"].detail
    assert all(c.ok is True for c in only_policy.values())


# ---------------------------------------------------------------- Secure Boot 2023 certificates
SB_STATE = r"SYSTEM\CurrentControlSet\Control\SecureBoot\State"
SB_SERVICING = r"SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"


def _sb_certs(reg, **servicing):
    values = {("HKLM", SB_STATE, "UEFISecureBootEnabled"): 1}
    values.update({("HKLM", SB_SERVICING, k): v for k, v in servicing.items()})
    reg(values)
    checks = sa.check_secure_boot_certs(env())
    assert len(checks) == 1 and checks[0].key == "SECURE-BOOT-CERTS"
    return checks[0]


def test_secure_boot_certs_updated_passes(reg):
    c = _sb_certs(reg, UEFICA2023Status="Updated", UEFICA2023Error=0, WindowsUEFICA2023Capable=2)
    assert c.ok is True and c.to_finding() is None


def test_secure_boot_certs_states(reg):
    c = _sb_certs(reg, UEFICA2023Status="NotStarted")
    assert c.ok is False and c.severity == Severity.MEDIUM and "2011" in c.title
    f = c.to_finding()
    assert f.remediation is None and "BitLocker" in f.recommendation and f.mitre == ["T1542.003"]
    assert "Microsoft Corporation KEK CA 2011" in f.description and f.evidence["UEFICA2023Status"] == "NotStarted"
    c = _sb_certs(reg, UEFICA2023Status="InProgress")
    assert c.ok is False and c.severity == Severity.LOW and "Restart" in c.recommendation
    c = _sb_certs(reg, UEFICA2023Status="InProgress", UEFICA2023Error=0x80070005, UEFICA2023ErrorEvent=1796)
    assert c.severity == Severity.MEDIUM and "0x80070005" in c.description and "event 1796" in c.description
    c = _sb_certs(reg)  # not reported at all: older update level
    assert c.ok is False and c.severity == Severity.LOW and "unknown" in c.title


def test_secure_boot_certs_capable_is_not_used_for_status(reg):
    # Microsoft: WindowsUEFICA2023Capable is reference only; a device can report 2 without the update being complete
    c = _sb_certs(reg, UEFICA2023Status="NotStarted", WindowsUEFICA2023Capable=2)
    assert c.ok is False and c.evidence["WindowsUEFICA2023Capable"] == 2


def test_secure_boot_certs_skipped_without_secure_boot(reg):
    reg({("HKLM", SB_STATE, "UEFISecureBootEnabled"): 0, ("HKLM", SB_SERVICING, "UEFICA2023Status"): "NotStarted"})
    checks = sa.check_secure_boot_certs(env())
    assert checks[0].ok is None and checks[0].status == CheckStatus.SKIP


def test_secure_boot_expiry_wording_follows_the_date():
    assert "expires on 2026-10-19" in sa._expiry_text(dt.date(2026, 10, 1))
    assert "Microsoft Windows Production PCA 2011 expired on 2026-10-19" in sa._expiry_text(dt.date(2026, 10, 20))
    assert "Microsoft Corporation KEK CA 2011 expired on 2026-06-24" in sa._expiry_text(dt.date(2026, 10, 1))


# ---------------------------------------------------------------- automatic screen lock
POLICIES_SYSTEM = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
SS_USER = r"Control Panel\Desktop"
SS_POLICY = r"Software\Policies\Microsoft\Windows\Control Panel\Desktop"


def _lock_win(reg, machine=None, user=None, policy=None, facts=None):
    values = {("HKLM", POLICIES_SYSTEM, "InactivityTimeoutSecs"): machine} if machine is not None else {}
    values.update({("HKCU", SS_USER, k): v for k, v in (user or {}).items()})
    values.update({("HKCU", SS_POLICY, k): v for k, v in (policy or {}).items()})
    reg(values)
    checks = sa._screen_lock_windows(env(facts))
    assert len(checks) == 1 and checks[0].key == "SCREENLOCK"
    return checks[0]


SAVER = {"ScreenSaveActive": "1", "ScreenSaverIsSecure": "1", "ScreenSaveTimeOut": "600", "SCRNSAVE.EXE": "scrnsave.scr"}


@pytest.mark.parametrize("secs", [1, 300, 899, 900])
def test_windows_machine_inactivity_limit_within_15_minutes_passes(reg, secs):
    c = _lock_win(reg, machine=secs)
    assert c.ok is True and c.status == CheckStatus.PASS and c.to_finding() is None
    assert "machine inactivity limit" in c.detail and c.evidence["InactivityTimeoutSecs"] == secs


def test_windows_nothing_configured_is_low_with_a_registry_fix(reg):
    c = _lock_win(reg)
    assert c.ok is False and c.severity == Severity.LOW and c.status == CheckStatus.WARN
    f = c.to_finding()
    assert f.rule_id == "AEG-AUDIT-SCREENLOCK" and f.title == "PC does not lock itself when left idle" and f.mitre == []
    assert f.remediation.action == "set_registry_value"
    assert f.remediation.params == {"hive": "HKLM", "key": POLICIES_SYSTEM, "value": "InactivityTimeoutSecs", "data": 900}
    assert isinstance(f.remediation.params["data"], int)  # reg_set_value stores an int as REG_DWORD
    assert f.location == "HKLM\\" + POLICIES_SYSTEM + "\\InactivityTimeoutSecs"
    assert "sleep" in f.description and "idle timeout" in f.description and "no machine inactivity limit" in f.description
    assert "screen saver is off" in f.description and "900 seconds" in f.recommendation


@pytest.mark.parametrize("secs,minutes", [(901, 16), (1800, 30), (3600, 60)])
def test_windows_limit_above_15_minutes_names_the_actual_minutes(reg, secs, minutes):
    c = _lock_win(reg, machine=secs)
    f = c.to_finding()
    assert c.ok is False and c.severity == Severity.LOW and f"waits {minutes} minutes" in f.title
    assert f"locks the screen only after {minutes} minutes" in f.description and f.remediation.params["data"] == 900


def test_windows_zero_limit_means_not_set(reg):
    assert "does not lock itself" in _lock_win(reg, machine=0).to_finding().title


def test_windows_password_protected_screen_saver_passes(reg):
    c = _lock_win(reg, user=SAVER)
    assert c.ok is True and "10 minute(s)" in c.detail and "screen saver" in c.detail
    assert c.evidence["ScreenSaveTimeOut"] == 600 and c.evidence["ScreenSaver"] == "scrnsave.scr"
    assert _lock_win(reg, user=dict(SAVER, ScreenSaveTimeOut="900")).ok is True
    assert _lock_win(reg, machine=7200, user=SAVER).ok is True  # the screen saver locks sooner than the machine limit


@pytest.mark.parametrize("change,reason", [
    ({"ScreenSaveActive": "0"}, "screen saver is off"),
    ({"SCRNSAVE.EXE": ""}, "no screen saver is selected"),
    ({"ScreenSaverIsSecure": "0"}, "does not ask for a password"),
    ({"ScreenSaveTimeOut": "0"}, "no timeout"),
    ({"ScreenSaveTimeOut": "1200"}, "starts after 20 minutes"),
])
def test_windows_weak_screen_saver_is_low(reg, change, reason):
    c = _lock_win(reg, user=dict(SAVER, **change))
    assert c.ok is False and c.severity == Severity.LOW and reason in c.description


def test_windows_policy_key_wins_over_the_users_screen_saver(reg):
    assert _lock_win(reg, user=SAVER, policy={"ScreenSaverIsSecure": "0"}).ok is False
    assert _lock_win(reg, user=dict(SAVER, ScreenSaveTimeOut="3000"), policy={"ScreenSaveTimeOut": "300"}).ok is True
    assert _lock_win(reg, user=dict(SAVER, ScreenSaveActive="0"), policy={"ScreenSaveActive": "1"}).ok is True
    assert _lock_win(reg, policy=SAVER).ok is True


def test_windows_system_account_has_no_user_settings(reg):
    system = {"user": "NT AUTHORITY\\SYSTEM"}
    c = _lock_win(reg, user=SAVER, facts=system)
    assert c.ok is None and c.status == CheckStatus.SKIP and "SYSTEM" in c.detail
    assert _lock_win(reg, machine=600, facts=system).ok is True


def test_screen_lock_dispatches_by_platform(reg, monkeypatch):
    reg({("HKLM", POLICIES_SYSTEM, "InactivityTimeoutSecs"): 600})
    monkeypatch.setattr(sa, "IS_WINDOWS", True)
    assert sa.check_screen_lock(env())[0].ok is True
    monkeypatch.setattr(sa, "IS_WINDOWS", False)
    monkeypatch.setattr(sa, "IS_MAC", True)
    monkeypatch.setattr(sa, "run", lambda cmd, timeout=60, input_text=None: (0, "", "screenLock is off\n"))
    c = sa.check_screen_lock(env())[0]
    assert c.ok is False and c.to_finding().title == "Mac does not lock itself when left idle"
    monkeypatch.setattr(sa, "IS_MAC", False)
    for name in ("DISPLAY", "WAYLAND_DISPLAY", "XDG_CURRENT_DESKTOP"):
        monkeypatch.delenv(name, raising=False)
    assert sa.check_screen_lock(env())[0].ok is None


def test_screen_lock_is_registered_for_every_platform():
    for checks in (sa.WINDOWS_CHECKS, sa.LINUX_CHECKS, sa.MAC_CHECKS):
        assert sa.check_screen_lock in checks


def test_screen_lock_rows_reach_the_report_as_result_and_finding(reg):
    reg()
    items = list(sa.run_checks(env(), [sa._screen_lock_windows]))
    assert [type(i).__name__ for i in items] == ["CheckResult", "Finding"]
    assert items[0].check_id == "AEG-AUDIT-SCREENLOCK" and items[0].status == CheckStatus.WARN
    assert items[1].severity == Severity.LOW and items[1].category == "system" and items[1].recommendation


@pytest.mark.skipif(not sa.IS_WINDOWS, reason="reads the real registry")
def test_windows_screen_lock_reads_the_real_registry():
    checks = sa._screen_lock_windows(sa.AuditEnv(today=TODAY, facts={}))
    assert len(checks) == 1 and checks[0].key == "SCREENLOCK"
    c = checks[0]
    assert c.ok in (True, False, None) and c.status in (CheckStatus.PASS, CheckStatus.WARN, CheckStatus.SKIP)
    assert set(c.evidence) >= {"InactivityTimeoutSecs", "ScreenSaveActive", "ScreenSaverIsSecure", "ScreenSaveTimeOut"}
    f = c.to_finding()
    if f:
        assert f.remediation.action == "set_registry_value" and f.remediation.params["data"] == 900
    items = list(sa.run_checks(sa.AuditEnv(today=TODAY, facts={}), [sa.check_screen_lock]))
    assert items and not any(isinstance(i, CheckResult) and i.status == CheckStatus.ERROR for i in items)


# ---- macOS
@pytest.mark.parametrize("text,expected", [
    ("2026-10-15 09:00:00.123 sysadminctl[512:4096] screenLock delay is 300 seconds\n", (True, 300)),
    ("screenLock delay is 5 seconds", (True, 5)),
    ("screenLock delay is 1 second", (True, 1)),
    ("screenLock delay is immediate", (True, 0)),
    ("sysadminctl[512:4096] screenLock is off\n", (False, None)),
    ("SCREENLOCK IS OFF", (False, None)),
    ("screenLock delay is 5 minutes", (True, 300)),
    ("", (None, None)),
    ("Usage: sysadminctl -screenLock status", (None, None)),
])
def test_parse_mac_screen_lock(text, expected):
    assert sa.parse_mac_screen_lock(text) == expected


def _mac_lock(monkeypatch, out="", err="", rc=0, admin=False):
    monkeypatch.setattr(sa, "run", lambda cmd, timeout=60, input_text=None: (rc, out, err))
    checks = sa._screen_lock_macos(env(admin=admin))
    assert len(checks) == 1 and checks[0].key == "SCREENLOCK"
    return checks[0]


def test_macos_screen_lock_states(monkeypatch):
    assert _mac_lock(monkeypatch, err="screenLock delay is 300 seconds\n").ok is True  # sysadminctl writes to stderr
    assert _mac_lock(monkeypatch, out="screenLock delay is immediate").ok is True
    assert _mac_lock(monkeypatch, err="screenLock delay is 900 seconds").ok is True
    off = _mac_lock(monkeypatch, err="screenLock is off")
    assert off.ok is False and off.severity == Severity.LOW and off.to_finding().remediation is None
    assert off.to_finding().title == "Mac does not lock itself when left idle"
    assert "sysadminctl -screenLock immediate" in off.to_finding().recommendation
    slow = _mac_lock(monkeypatch, err="screenLock delay is 1800 seconds")
    f = slow.to_finding()
    assert slow.ok is False and "waits 30 minutes" in f.title and f.evidence["delay_seconds"] == 1800
    assert "screen saver starts or the display turns off" in f.description and "sleep" in f.description


def test_macos_screen_lock_unknown_output_or_missing_tool_is_a_skip(monkeypatch):
    for kwargs in ({"out": "something new from a future macOS"}, {"rc": -1, "err": "not found: sysadminctl"}, {}):
        c = _mac_lock(monkeypatch, **kwargs)
        assert c.ok is None and c.status == CheckStatus.SKIP and c.to_finding() is None
    root = _mac_lock(monkeypatch, err="screenLock is off", admin=True)
    assert root.ok is None and "normal user" in root.detail


# ---- Linux desktops
class FakeDesktop:
    """Answers gsettings / kreadconfig from a dict and records every call; sets up the session environment."""

    def __init__(self, monkeypatch, answers, tools=("gsettings",), desktop="GNOME", display=":0"):
        self.calls = []
        self.answers = answers
        for name in ("DISPLAY", "WAYLAND_DISPLAY", "XDG_CURRENT_DESKTOP", "DESKTOP_SESSION"):
            monkeypatch.delenv(name, raising=False)
        if display:
            monkeypatch.setenv("DISPLAY", display)
        if desktop:
            monkeypatch.setenv("XDG_CURRENT_DESKTOP", desktop)
        monkeypatch.setattr(sa.shutil, "which", lambda n: "/usr/bin/" + n if n in tools else None)
        monkeypatch.setattr(sa, "run", self.run)

    def run(self, cmd, timeout=60, input_text=None):
        self.calls.append(list(cmd))
        if cmd[0] == "gsettings":
            key = tuple(cmd[2:4])  # (schema, key)
        else:
            key = (cmd[0], cmd[cmd.index("--key") + 1])
        out = self.answers.get(key)
        return (0, out + "\n", "") if out is not None else (1, "", "No such schema")


def _lock_linux(admin=False):
    checks = sa._screen_lock_linux(env(admin=admin))
    assert len(checks) == 1 and checks[0].key == "SCREENLOCK"
    return checks[0]


GNOME_SCREENSAVER, GNOME_SESSION = "org.gnome.desktop.screensaver", "org.gnome.desktop.session"


def gnome_answers(lock="true", idle="uint32 300", delay="uint32 0"):
    return {(GNOME_SCREENSAVER, "lock-enabled"): lock, (GNOME_SESSION, "idle-delay"): idle,
            (GNOME_SCREENSAVER, "lock-delay"): delay}


def test_gnome_screen_lock_passes_within_15_minutes(monkeypatch):
    fake = FakeDesktop(monkeypatch, gnome_answers())
    c = _lock_linux()
    assert c.ok is True and "5 minute(s)" in c.detail and c.evidence["idle_seconds"] == 300
    assert ["gsettings", "get", GNOME_SESSION, "idle-delay"] in fake.calls
    FakeDesktop(monkeypatch, gnome_answers(idle="uint32 900"))
    assert _lock_linux().ok is True


@pytest.mark.parametrize("answers,title,reason", [
    (gnome_answers(lock="false"), "does not lock itself", "switched off"),
    (gnome_answers(idle="uint32 0"), "does not lock itself", "never goes idle"),
    (gnome_answers(idle="uint32 1800"), "waits 30 minutes", "after 30 minutes"),
    (gnome_answers(idle="uint32 600", delay="uint32 400"), "waits 17 minutes", "after 17 minutes"),  # 1000 s in total
    (gnome_answers(lock="false", idle="uint32 0"), "does not lock itself", "switched off"),
])
def test_gnome_weak_screen_lock_is_low(monkeypatch, answers, title, reason):
    FakeDesktop(monkeypatch, answers)
    c = _lock_linux()
    f = c.to_finding()
    assert c.ok is False and c.severity == Severity.LOW and f.rule_id == "AEG-AUDIT-SCREENLOCK" and title in f.title
    assert reason in f.description and f.remediation is None and f.mitre == []
    assert "gsettings set org.gnome.desktop.screensaver lock-enabled true" in f.recommendation
    assert "gsettings set org.gnome.desktop.session idle-delay 300" in f.recommendation
    assert "sleep" in f.description


def test_gnome_family_desktops_use_the_gnome_schema(monkeypatch):
    for desktop in ("ubuntu:GNOME", "Budgie:GNOME", "Unity", "Pantheon", "GNOME-Flashback:GNOME"):
        FakeDesktop(monkeypatch, gnome_answers(), desktop=desktop)
        assert _lock_linux().ok is True, desktop


def test_cinnamon_and_mate_use_their_own_schemas_and_units(monkeypatch):
    cin = {("org.cinnamon.desktop.screensaver", "lock-enabled"): "true",
           ("org.cinnamon.desktop.session", "idle-delay"): "uint32 600",
           ("org.cinnamon.desktop.screensaver", "lock-delay"): "uint32 0"}
    fake = FakeDesktop(monkeypatch, cin, desktop="X-Cinnamon")
    c = _lock_linux()
    assert c.ok is True and ["gsettings", "get", "org.cinnamon.desktop.session", "idle-delay"] in fake.calls
    assert not any("org.gnome" in " ".join(call) for call in fake.calls)
    mate = {("org.mate.screensaver", "lock-enabled"): "true", ("org.mate.session", "idle-delay"): "5",
            ("org.mate.screensaver", "lock-delay"): "0", ("org.mate.screensaver", "idle-activation-enabled"): "true"}
    FakeDesktop(monkeypatch, mate, desktop="MATE")
    ok = _lock_linux()
    assert ok.ok is True and ok.evidence["idle_seconds"] == 300  # MATE counts minutes
    FakeDesktop(monkeypatch, {**mate, ("org.mate.session", "idle-delay"): "20"}, desktop="MATE")
    slow = _lock_linux()
    assert slow.ok is False and "waits 20 minutes" in slow.to_finding().title
    assert "gsettings set org.mate.session idle-delay 5" in slow.to_finding().recommendation
    FakeDesktop(monkeypatch, {**mate, ("org.mate.screensaver", "idle-activation-enabled"): "false"}, desktop="MATE")
    assert _lock_linux().ok is False


def _kde(timeout="5", auto="true"):
    return {("kreadconfig5", "Autolock"): auto, ("kreadconfig5", "Timeout"): timeout,
            ("kreadconfig6", "Autolock"): auto, ("kreadconfig6", "Timeout"): timeout}


def _kde_lock(monkeypatch, answers, tools=("kreadconfig5",), desktop="KDE"):
    fake = FakeDesktop(monkeypatch, answers, tools=tools, desktop=desktop)
    return _lock_linux(), fake


def test_kde_screen_locker(monkeypatch):
    c, fake = _kde_lock(monkeypatch, _kde())
    assert c.ok is True and c.evidence["timeout_minutes"] == 5 and c.evidence["tool"] == "kreadconfig5"
    assert fake.calls[0][:7] == ["kreadconfig5", "--file", "kscreenlockerrc", "--group", "Daemon", "--key", "Autolock"]
    assert "--default" in fake.calls[0]  # the defaults are Autolock=true and Timeout=5 minutes
    assert _kde_lock(monkeypatch, _kde(timeout="15"))[0].ok is True
    slow, _ = _kde_lock(monkeypatch, _kde(timeout="30"))
    f = slow.to_finding()
    assert slow.ok is False and "waits 30 minutes" in f.title and "kwriteconfig5 --file kscreenlockerrc" in f.recommendation
    off, _ = _kde_lock(monkeypatch, _kde(auto="false"))
    assert off.ok is False and "does not lock itself" in off.to_finding().title and "switched off" in off.to_finding().description
    both, _ = _kde_lock(monkeypatch, _kde(), tools=("kreadconfig5", "kreadconfig6"))
    assert both.evidence["tool"] == "kreadconfig6"  # Plasma 6 first
    assert _kde_lock(monkeypatch, _kde(), tools=("kreadconfig6",), desktop="plasma")[0].to_finding() is None


def test_linux_screen_lock_is_skipped_when_it_cannot_be_judged(monkeypatch):
    FakeDesktop(monkeypatch, gnome_answers(), display=None, desktop=None)
    c = _lock_linux()
    assert c.ok is None and c.status == CheckStatus.SKIP and "No desktop session" in c.detail
    FakeDesktop(monkeypatch, gnome_answers(), desktop="XFCE")
    c = _lock_linux()
    assert c.ok is None and "XFCE" in c.detail and "not supported" in c.detail
    FakeDesktop(monkeypatch, gnome_answers(), display=None, desktop="XFCE")
    assert "not supported" in _lock_linux().detail  # XDG_CURRENT_DESKTOP alone counts as a graphical session
    FakeDesktop(monkeypatch, gnome_answers(), tools=())
    assert "gsettings is not installed" in _lock_linux().detail
    FakeDesktop(monkeypatch, {}, desktop="GNOME")  # schema missing: gsettings exits 1
    assert "did not return" in _lock_linux().detail
    FakeDesktop(monkeypatch, {}, tools=(), desktop="KDE")
    assert "kreadconfig5 / kreadconfig6 is not installed" in _lock_linux().detail
    FakeDesktop(monkeypatch, {}, tools=("kreadconfig5",), desktop="KDE")
    assert "did not return" in _lock_linux().detail
    FakeDesktop(monkeypatch, gnome_answers())
    root = _lock_linux(admin=True)
    assert root.ok is None and "desktop user" in root.detail


def test_session_without_a_desktop_name_uses_desktop_session(monkeypatch):
    FakeDesktop(monkeypatch, gnome_answers(), desktop=None)
    monkeypatch.setenv("DESKTOP_SESSION", "gnome-xorg")
    assert _lock_linux().ok is True
