"""Tests for aegis.scanners.processes decision logic and a live run on Linux."""

import os
import time

import pytest

from aegis.core.config import Config
from aegis.core.models import CheckResult, Finding, Severity
from aegis.core.signatures import SignatureDB
from aegis.scanners import processes as pr
from aegis.scanners.base import ScanContext
from aegis.scanners.processes import ProcInfo

SYS = r"C:\Windows\System32"


def P(pid, name, exe="", cmdline="", parent="", ppid=1, **kw):
    return ProcInfo(pid=pid, name=name, ppid=ppid, exe=exe, cmdline=cmdline or exe, parent_name=parent, **kw)


def rules(findings):
    return [f.rule_id for f in findings]


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path / "home"))
    cfg = Config()
    return ScanContext(cfg, SignatureDB(cfg))


# --------------------------------------------------------------------------- masquerading

def test_edit_distance():
    assert pr.edit_distance("svchost", "svchost") == 0
    assert pr.edit_distance("svch0st", "svchost") == 1
    assert pr.edit_distance("scvhost", "svchost") == 1  # transposition counts once
    assert pr.edit_distance("lsasss", "lsass") == 1
    assert pr.edit_distance("abc", "xyz") == 3


@pytest.mark.parametrize("name,target", [
    ("svch0st.exe", "svchost.exe"), ("scvhost.exe", "svchost.exe"), ("lsasss.exe", "lsass.exe"),
    ("expl0rer.exe", "explorer.exe"), ("csrs.exe", None), ("svchosts.exe", "svchost.exe"),
    ("runtimebrokr.exe", "runtimebroker.exe"), ("svchost.exe", None), ("chrome.exe", None), ("notepad.exe", None),
    ("taskhost.exe", None), ("service.exe", None), ("dwn.exe", None), ("python.exe", None), ("spoolsv.exe", None),
])
def test_typosquat_target(name, target):
    assert pr.typosquat_target(name) == target


def test_masquerade_wrong_directory_is_high():
    f = pr.masquerade_findings([P(10, "svchost.exe", r"C:\Users\bob\AppData\Local\Temp\svchost.exe", parent="services.exe")])
    assert rules(f) == ["AEG-PROC-MASQ"]
    assert f[0].severity == Severity.HIGH
    assert f[0].remediation.action == "kill_process"
    assert f[0].remediation.params["pid"] == 10 and f[0].remediation.params["quarantine"] is True
    assert "T1036.005" in f[0].mitre


def test_masquerade_legit_locations_not_flagged():
    procs = [
        P(1, "svchost.exe", SYS + r"\svchost.exe", parent="services.exe"),
        P(2, "explorer.exe", r"C:\Windows\explorer.exe"),
        P(3, "rundll32.exe", r"C:\Windows\SysWOW64\rundll32.exe"),
        P(4, "MsMpEng.exe", r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2301.6-0\MsMpEng.exe"),
        P(5, "lsass.exe", SYS + r"\lsass.exe", parent="wininit.exe"),
        P(6, "dwm.exe", SYS + r"\dwm.exe"),
        P(7, "services.exe", SYS + r"\services.exe", parent="wininit.exe"),
        P(8, "explorer.exe", r"D:\Windows\explorer.exe"),  # non-C: system drive is fine
    ]
    assert pr.masquerade_findings(procs) == []


def test_masquerade_ignores_non_windows_paths_and_unknown_exe():
    procs = [P(1, "svchost.exe", ""), P(2, "dwm.exe", "/opt/wine/bin/wine64-preloader")]
    assert pr.masquerade_findings(procs) == []


def test_msmpeng_wrong_dir_high():
    f = pr.masquerade_findings([P(1, "MsMpEng.exe", r"C:\Users\Public\MsMpEng.exe")])
    assert rules(f) == ["AEG-PROC-MASQ"]


def test_typosquat_flagged_high_but_vendor_dirs_allowed():
    f = pr.masquerade_findings([P(1, "scvhost.exe", r"C:\Users\bob\AppData\Roaming\scvhost.exe")])
    assert rules(f) == ["AEG-PROC-TYPOSQUAT"] and f[0].severity == Severity.HIGH
    assert f[0].evidence["imitates"] == "svchost.exe"
    assert pr.masquerade_findings([P(2, "scvhost.exe", r"C:\Program Files\Vendor\scvhost.exe")]) == []
    assert rules(pr.masquerade_findings([P(3, "svch0st.exe", "")])) == ["AEG-PROC-TYPOSQUAT"]


def test_wrong_parent_is_medium():
    f = pr.masquerade_findings([P(1, "svchost.exe", SYS + r"\svchost.exe", parent="cmd.exe")])
    assert rules(f) == ["AEG-PROC-PARENT"] and f[0].severity == Severity.MEDIUM
    f = pr.masquerade_findings([P(2, "lsass.exe", SYS + r"\lsass.exe", parent="explorer.exe")])
    assert rules(f) == ["AEG-PROC-PARENT"]
    # unknown parent (exited / PID reuse) is not an indicator
    assert pr.masquerade_findings([P(3, "svchost.exe", SYS + r"\svchost.exe", parent="")]) == []


def test_multiple_lsass_high():
    good = P(1, "lsass.exe", SYS + r"\lsass.exe", parent="wininit.exe")
    fake = P(2, "lsass.exe", r"C:\Temp\lsass.exe", parent="cmd.exe")
    f = pr.masquerade_findings([good, fake])
    multi = [x for x in f if x.rule_id == "AEG-PROC-MULTI-LSASS"]
    assert len(multi) == 2 and all(x.severity == Severity.HIGH for x in multi)
    assert multi[0].remediation is None  # the genuine one is never offered for termination
    assert multi[1].remediation.action == "kill_process"
    assert "AEG-PROC-MASQ" in rules(f)


def test_skip_set_respected():
    p = P(10, "svchost.exe", r"C:\Temp\svchost.exe")
    assert pr.masquerade_findings([p], skip={10}) == []


# --------------------------------------------------------------------------- chains

def test_office_spawning_shell_is_high():
    f = pr.chain_findings([P(5, "powershell.exe", SYS + r"\WindowsPowerShell\v1.0\powershell.exe", parent="WINWORD.EXE",
                             parent_cmdline="winword.exe /n x.docx")])
    assert rules(f) == ["AEG-PROC-CHAIN"] and f[0].severity == Severity.HIGH
    assert f[0].remediation.params["quarantine"] is False  # never quarantine powershell.exe itself


@pytest.mark.parametrize("parent,child", [("EXCEL.EXE", "cmd.exe"), ("Outlook.exe", "wscript.exe"), ("AcroRd32.exe", "mshta.exe"),
                                          ("powerpnt.exe", "regsvr32.exe"), ("Acrobat.exe", "certutil.exe")])
def test_chain_variants(parent, child):
    assert rules(pr.chain_findings([P(5, child, SYS + "\\" + child, parent=parent)])) == ["AEG-PROC-CHAIN"]


def test_wmiprvse_chain_medium_and_browsers_ignored():
    f = pr.chain_findings([P(1, "powershell.exe", parent="WmiPrvSE.exe")])
    assert f and f[0].severity == Severity.MEDIUM
    assert pr.chain_findings([P(2, "cmd.exe", parent="chrome.exe"), P(3, "cmd.exe", parent="explorer.exe"),
                              P(4, "notepad.exe", parent="WINWORD.EXE")]) == []


def test_office_rundll32_system_dll_not_flagged():
    p = P(1, "rundll32.exe", SYS + r"\rundll32.exe", cmdline=r"C:\Windows\System32\rundll32.exe printui.dll,PrintUIEntry /in", parent="WINWORD.EXE")
    assert pr.chain_findings([p]) == []
    p = P(2, "rundll32.exe", SYS + r"\rundll32.exe", cmdline=r"rundll32.exe C:\Users\a\AppData\Local\Temp\x.dll,Run", parent="WINWORD.EXE")
    assert rules(pr.chain_findings([p])) == ["AEG-PROC-CHAIN"]


# --------------------------------------------------------------------------- command lines

def test_cmdline_findings_and_dedupe():
    enc = r"powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgA"
    procs = [P(1, "powershell.exe", SYS + r"\WindowsPowerShell\v1.0\powershell.exe", cmdline=enc),
             P(2, "powershell.exe", SYS + r"\WindowsPowerShell\v1.0\powershell.exe", cmdline=enc),
             P(3, "chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe",
               cmdline=r'"C:\Program Files\Google\Chrome\Application\chrome.exe" --no-startup-window'),
             P(4, "powershell.exe", cmdline=r"powershell.exe -NoProfile -File C:\Scripts\backup.ps1")]
    f = pr.cmdline_findings(procs)
    assert rules(f) == ["AEG-CMD-PS-ENC-STEALTH"]  # identical command lines are reported once
    assert f[0].severity == Severity.HIGH and f[0].remediation.action == "kill_process"


def test_cmdline_management_agent_encoded_command_ignored():
    enc = r"powershell.exe -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgA"
    assert pr.cmdline_findings([P(1, "powershell.exe", cmdline=enc, parent="CcmExec.exe")]) == []
    assert rules(pr.cmdline_findings([P(2, "powershell.exe", cmdline=enc, parent="explorer.exe")])) == ["AEG-CMD-PS-ENC"]


def test_cmdline_low_severity_not_reported():
    p = P(1, "powershell.exe", cmdline=r"powershell.exe -version 2 -c Get-Date")
    assert pr.cmdline_findings([p]) == []
    assert rules(pr.cmdline_findings([p], min_sev=Severity.LOW)) == ["AEG-CMD-PS-DOWNGRADE"]


# --------------------------------------------------------------------------- miners / remote tools / deleted

def test_miner_by_name_and_cmdline():
    f, pids = pr.miner_findings([P(1, "xmrig.exe", r"C:\Users\bob\AppData\Local\Temp\xmrig.exe"),
                                 P(2, "svc.exe", cmdline="svc.exe -o stratum+tcp://pool:3333 -u w"),
                                 P(3, "notepad.exe")])
    assert pids == {1, 2} and rules(f) == ["AEG-PROC-MINER"] * 2
    assert all(x.severity == Severity.HIGH for x in f)
    assert f[0].remediation.params["quarantine"] is True
    # miner process is not double-reported by the generic command-line rule
    assert pr.cmdline_findings([P(2, "svc.exe", cmdline="svc.exe -o stratum+tcp://pool:3333 -u w")], miner_pids={2}) == []


def test_high_cpu_requires_user_writable_path_and_duration():
    now = time.time()
    hot = dict(cpu_now=95.0, cpu_avg=90.0, create_time=now - 3600)
    f, _ = pr.miner_findings([P(1, "a.exe", r"C:\Users\bob\AppData\Roaming\a.exe", **hot)])
    assert rules(f) == ["AEG-PROC-HIGHCPU"] and f[0].severity == Severity.MEDIUM
    f, _ = pr.miner_findings([P(2, "a.exe", r"C:\Program Files\Foo\a.exe", **hot)])
    assert f == []
    f, _ = pr.miner_findings([P(3, "a.exe", r"C:\Users\bob\AppData\Roaming\a.exe", cpu_now=95, cpu_avg=90, create_time=now - 10)])
    assert f == []


@pytest.mark.parametrize("name,exe,tool,sev", [
    ("AnyDesk.exe", r"C:\Program Files (x86)\AnyDesk\AnyDesk.exe", "AnyDesk", Severity.LOW),
    ("AnyDesk.exe", r"C:\Users\bob\Downloads\AnyDesk.exe", "AnyDesk", Severity.MEDIUM),
    ("TeamViewer.exe", r"C:\Program Files\TeamViewer\TeamViewer.exe", "TeamViewer", Severity.LOW),
    ("ScreenConnect.ClientService.exe", r"C:\Program Files (x86)\ScreenConnect Client\ScreenConnect.ClientService.exe",
     "ScreenConnect / ConnectWise Control", Severity.LOW),
    ("AteraAgent.exe", r"C:\Program Files\ATERA Networks\AteraAgent\AteraAgent.exe", "Atera agent", Severity.LOW),
    ("rustdesk.exe", "", "RustDesk", Severity.LOW),
    ("AmmyyAdmin.exe", r"C:\Program Files\Ammyy\AmmyyAdmin.exe", "Ammyy Admin", Severity.MEDIUM),
    ("client32.exe", r"C:\Program Files\NetSupport\NetSupport Manager\client32.exe", "NetSupport Manager client", Severity.MEDIUM),
    ("LogMeIn.exe", r"C:\Program Files\LogMeIn\x86\LogMeIn.exe", "LogMeIn", Severity.LOW),
])
def test_remote_access_tools(name, exe, tool, sev):
    f = pr.remote_access_findings([P(1, name, exe)])
    assert len(f) == 1 and f[0].rule_id == "AEG-PROC-REMOTE"
    assert f[0].evidence["tool"] == tool and f[0].severity == sev
    assert "scam" in f[0].description.lower() or "scam" in f[0].recommendation.lower() or "unsolicited" in f[0].recommendation.lower()


def test_client32_generic_name_ignored_in_system_dir():
    assert pr.remote_access_findings([P(1, "client32.exe", r"C:\Program Files\Novell\client32.exe")]) == []


def test_deleted_exe_logic():
    assert pr.deleted_exe_suspicious("/memfd:x") == Severity.HIGH
    assert pr.deleted_exe_suspicious("/tmp/x") == Severity.MEDIUM
    assert pr.deleted_exe_suspicious("/usr/sbin/sshd") is None  # package upgrade, normal
    p = P(1, "x", "/tmp/.x/payload", exe_deleted=True)
    f = pr.deleted_exe_findings([p])
    assert rules(f) == ["AEG-PROC-DELETED"] and f[0].severity == Severity.MEDIUM
    assert pr.deleted_exe_findings([P(2, "sshd", "/usr/sbin/sshd", exe_deleted=True)]) == []


# --------------------------------------------------------------------------- location / authenticode

def test_location_severity_matrix():
    S = Severity
    assert pr.location_severity(0, "NotSigned") is None
    assert pr.location_severity(2, None) == S.MEDIUM
    assert pr.location_severity(1, None) == S.LOW
    assert pr.location_severity(2, "NotSigned") == S.HIGH
    assert pr.location_severity(1, "NotSigned") == S.MEDIUM
    assert pr.location_severity(1, "Valid") is None
    assert pr.location_severity(2, "Valid") == S.LOW
    assert pr.location_severity(1, "HashMismatch") == S.HIGH


def test_parse_authenticode_and_location_findings():
    data = [{"Path": r"C:\Users\bob\AppData\Local\Temp\a.exe", "Status": "NotSigned", "Signer": ""},
            {"Path": r"C:\Users\bob\AppData\Roaming\Foo\b.exe", "Status": "Valid", "Signer": "CN=Foo Inc"}]
    sigs = pr.parse_authenticode(data)
    assert pr.parse_authenticode({"Path": "C:\\x.exe", "Status": "Valid"})  # single object (not a list)
    procs = [P(1, "a.exe", data[0]["Path"]), P(2, "b.exe", data[1]["Path"]), P(3, "c.exe", r"C:\Program Files\X\c.exe")]
    f = pr.location_findings(procs, sigs)
    assert len(f) == 1 and f[0].severity == Severity.HIGH and f[0].evidence["signature"] == "NotSigned"
    assert f[0].location.endswith("(pid 1)")


def test_location_findings_dedupe_by_path():
    path = "/tmp/.x/a"
    f = pr.location_findings([P(1, "a", path), P(2, "a", path)])
    assert len(f) == 1


def test_scan_candidates_orders_and_limits():
    procs = [P(1, "a", "/tmp/a"), P(2, "b", "/usr/bin/b"), P(3, "c", "/opt/app/c"), P(4, "d", "/tmp/a"),
             P(5, "e", r"C:\Windows\System32\e.exe"), P(6, "f", r"C:\Users\x\Downloads\f.exe")]
    c = pr.scan_candidates(procs, set(), deep=False, limit=10)
    paths = [p for p, _ in c]
    assert "/usr/bin/b" not in paths and r"C:\Windows\System32\e.exe" not in paths
    assert dict(c)["/tmp/a"] == [1, 4]
    assert pr.scan_candidates(procs, set(), deep=False, limit=1)[0][0] in ("/tmp/a", r"C:\Users\x\Downloads\f.exe")


def test_retag_file_findings():
    f = Finding("AEG-SIG-HASH", "Known malware: X", Severity.CRITICAL, "malware", location="/tmp/a")
    out = pr.retag_file_findings([f], "/tmp/a", [7, 9])
    assert out[0].location == "/tmp/a (pid 7)" and out[0].evidence["pids"] == [7, 9]
    assert out[0].remediation.action == "kill_process" and out[0].remediation.params["quarantine"] is True


# --------------------------------------------------------------------------- self exclusion & live run

def test_excluded_pids_covers_self_parent_children():
    me, parent = os.getpid(), os.getppid()
    procs = [P(me, "python", ppid=parent), P(parent, "bash"), P(me + 1000, "powershell", ppid=me),
             P(me + 2000, "child", ppid=me + 1000), P(me + 3000, "other", ppid=1)]
    ex = pr.excluded_pids(procs)
    assert {me, parent, me + 1000, me + 2000} <= ex and (me + 3000) not in ex


def test_collect_processes_live():
    procs = pr.collect_processes(sample_cpu=False)
    assert procs and any(p.pid == os.getpid() for p in procs)
    mine = next(p for p in procs if p.pid == os.getpid())
    assert mine.name and mine.cmdline


def test_scanner_runs_on_linux_without_exceptions(ctx):
    out = list(pr.ProcessScanner().run(ctx))
    assert out
    assert all(isinstance(o, (Finding, CheckResult)) for o in out)
    checks = {o.check_id: o.status for o in out if isinstance(o, CheckResult)}
    assert {"AEG-PROC-CHK-MASQ", "AEG-PROC-CHK-CHAIN", "AEG-PROC-CHK-CMD", "AEG-PROC-CHK-MINER"} <= set(checks)
    # Aegis' own test process must never be reported
    me = os.getpid()
    for f in out:
        if isinstance(f, Finding) and f.rule_id.startswith("AEG-PROC") or isinstance(f, Finding) and f.rule_id.startswith("AEG-CMD"):
            assert f.evidence.get("pid") != me
    assert ctx.stats.get("processes_examined", 0) > 0


def test_scanner_metadata():
    from aegis.scanners.base import REGISTRY
    assert REGISTRY["processes"] is pr.ProcessScanner
    assert pr.ProcessScanner.name == "processes" and set(pr.ProcessScanner.platforms) == {"windows", "linux", "darwin"}
