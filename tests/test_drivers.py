"""Unit tests for aegis.scanners.drivers: BYOVD matching, signature/location logic, posture checks (all mocked)."""

import hashlib
import json

import pytest

from aegis.core import fileanalysis as fa
from aegis.core.models import CheckResult, CheckStatus, Finding, Severity
from aegis.scanners import drivers as dr
from aegis.scanners.base import REGISTRY, load_all

WIN = r"C:\Windows"
SHA_A = "a" * 64
SHA_B = "b" * 64


def drv(name="foo", path=r"C:\Windows\System32\drivers\foo.sys", state="Stopped", sig="Valid", sha="", exists=True, signer="",
        start=3):
    return dr.DriverInfo(name=name, path=path, raw_path=path, state=state, sig_status=sig, sha256=sha, exists=exists,
                         signer=signer, start=start)


def analyse(drivers, vuln=None, sigs=None):
    return dr.analyse_drivers(drivers, vuln or {}, sigs, windir=WIN)


def rules(findings):
    return [f.rule_id for f in findings]


class FakeSigs:
    def __init__(self, hashes):
        self.hashes = hashes

    def lookup_hash(self, *hs):
        return next((self.hashes[h.lower()] for h in hs if h and h.lower() in self.hashes), None)


# ---------------------------------------------------------------- known names
@pytest.mark.parametrize("name", [
    "RTCore64.sys", "rtcore64.SYS", "dbutil_2_3.sys", "DBUTIL_2_5.sys", "gdrv.sys", "AsIO3.sys", "procexp152.sys",
    "iqvw64e.sys", "cpuz141.sys", "cpuz_x64.sys", "WinRing0x64.sys", "asrdrv103.sys", "mhyprot2.sys", "kprocesshacker.sys",
    r"C:\Windows\System32\drivers\RTCore64.sys", "/tmp/x/gdrv.sys", "TrueSight.sys", "zamguard64.sys", "aswArPot.sys",
])
def test_known_abusable_names_match(name):
    m = dr.match_known_driver(name)
    assert m and m[0] and m[1]


@pytest.mark.parametrize("name", ["ntfs.sys", "tcpip.sys", "cpuz.exe", "myrtcore64.sys.txt", "", "dbutil.dll", "asioX.sys"])
def test_normal_names_do_not_match(name):
    assert dr.match_known_driver(name) is None


# ---------------------------------------------------------------- paths
@pytest.mark.parametrize("raw,name,expected", [
    (r"\SystemRoot\System32\drivers\acpi.sys", "acpi", r"C:\Windows\System32\drivers\acpi.sys"),
    (r"System32\drivers\foo.sys", "foo", r"C:\Windows\System32\drivers\foo.sys"),
    (r"\??\C:\Users\bob\AppData\Local\Temp\evil.sys", "evil", r"C:\Users\bob\AppData\Local\Temp\evil.sys"),
    (r"%SystemRoot%\system32\DRIVERS\bar.sys", "bar", r"C:\Windows\system32\DRIVERS\bar.sys"),
    ('"C:\\Program Files\\Vendor\\v.sys" /flag', "v", r"C:\Program Files\Vendor\v.sys"),
    (r"\\?\C:\Tools\x.sys", "x", r"C:\Tools\x.sys"),
    ("", "noimage", r"C:\Windows\System32\drivers\noimage.sys"),
    ("bare.sys", "bare", r"C:\Windows\System32\drivers\bare.sys"),
    ("", "", ""),
])
def test_normalize_driver_path(raw, name, expected):
    assert dr.normalize_driver_path(raw, name, WIN) == expected


@pytest.mark.parametrize("path,cls", [
    (r"C:\Windows\System32\drivers\x.sys", "standard"),
    (r"C:\Windows\System32\DriverStore\FileRepository\nv\nv.sys", "standard"),
    (r"C:\Windows\System32\ntoskrnl.exe", "standard"),
    (r"C:\Program Files\Vendor\x.sys", "vendor"),
    (r"C:\Program Files (x86)\Vendor\x.sys", "vendor"),
    (r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MpKslDrv.sys", "vendor"),
    (r"C:\Users\bob\AppData\Local\Temp\evil.sys", "userwritable"),
    (r"C:\Users\bob\Downloads\gdrv.sys", "userwritable"),
    (r"C:\Users\Public\x.sys", "userwritable"),
    (r"D:\Tools\drv.sys", "other"),
    (r"C:\Windows\drv.sys", "other"),
    ("", "other"),
])
def test_driver_location_class(path, cls):
    assert dr.driver_location_class(path, WIN) == cls


# ---------------------------------------------------------------- hash list
def test_load_vulnerable_hashes_formats(tmp_path):
    f = tmp_path / "vulnerable_drivers.txt"
    f.write_text("# comment\n" + SHA_A.upper() + "\tLOLDrivers.VulnDriver: RTCore64.sys [CVE-2019-16098]\n"
                 + SHA_B + ",LOLDrivers.MalDriver: bad.sys\n" + "short\tnope\n" + "\n" + "c" * 64 + "\n", encoding="utf-8")
    got = dr.load_vulnerable_driver_hashes(base=f)
    assert got[SHA_A] == "LOLDrivers.VulnDriver: RTCore64.sys [CVE-2019-16098]"
    assert got[SHA_B] == "LOLDrivers.MalDriver: bad.sys" and got["c" * 64] == "Vulnerable driver" and len(got) == 3


def test_missing_hash_file_is_fine_and_extra_dirs_merge(tmp_path):
    assert dr.load_vulnerable_driver_hashes(base=tmp_path / "nope.txt") == {}
    (tmp_path / "vulnerable_drivers.txt").write_text(f"{SHA_A}\tfrom extra dir\n")
    got = dr.load_vulnerable_driver_hashes([tmp_path], base=tmp_path / "nope.txt")
    assert got == {SHA_A: "from extra dir"}


def test_bundled_hash_list_if_present_is_well_formed():
    got = dr.load_vulnerable_driver_hashes()
    if dr.VULN_DRIVERS_FILE.exists():
        assert len(got) > 100
    assert all(len(h) == 64 for h in got)


# ---------------------------------------------------------------- analysis
def test_hash_match_vulnerable_is_high_with_disable_fix():
    d = drv("RTCore64", r"C:\Windows\System32\drivers\RTCore64.sys", state="Running", sha=SHA_A, signer="CN=MSI")
    f = analyse([d], {SHA_A: "LOLDrivers.VulnDriver: RTCore64.sys [CVE-2019-16098,CVE-2019-16099]"})
    assert rules(f) == ["AEG-DRV-VULN"]  # one finding: the name/other rules would only repeat it
    x = f[0]
    assert x.severity == Severity.HIGH and x.category == "vulnerability" and "BYOVD" in x.description
    assert x.evidence["cves"] == ["CVE-2019-16098", "CVE-2019-16099"] and x.evidence["running"] is True
    assert x.remediation.action == "disable_service" and x.remediation.params == {"name": "RTCore64"}
    assert "T1068" in x.mitre and x.location.endswith("RTCore64.sys")
    json.dumps(x.to_dict())


def test_hash_match_malicious_driver_is_critical():
    f = analyse([drv("mimidrv", sha=SHA_B)], {SHA_B: "LOLDrivers.MalDriver: mimidrv.sys"})
    assert f[0].severity == Severity.CRITICAL and f[0].category == "malware" and f[0].title.startswith("Malicious kernel driver")
    f2 = analyse([drv("x", sha=SHA_A)], {}, FakeSigs({SHA_A: "Rootkit.Test"}))
    assert f2[0].severity == Severity.CRITICAL and "Rootkit.Test" in f2[0].description


def test_known_name_alone_is_medium_without_fix():
    f = analyse([drv("gdrv", r"C:\Windows\System32\drivers\gdrv.sys")])
    assert rules(f) == ["AEG-DRV-ABUSABLE"] and f[0].severity == Severity.MEDIUM and f[0].remediation is None
    assert "CVE-2018-19320" in f[0].description and f[0].title == "Known abusable driver present: gdrv.sys"
    # vendor install location, still MEDIUM
    assert analyse([drv("RTCore64", r"C:\Program Files (x86)\MSI Afterburner\RTCore64.sys")])[0].severity == Severity.MEDIUM


def test_known_name_in_user_writable_folder_or_unsigned_and_loaded_is_high():
    f = analyse([drv("gdrv", r"C:\Users\bob\Downloads\gdrv.sys", state="Running")])
    assert f[0].rule_id == "AEG-DRV-ABUSABLE" and f[0].severity == Severity.HIGH and f[0].remediation.action == "disable_service"
    assert "user-writable" in f[0].description
    f2 = analyse([drv("dbutil_2_3", r"C:\Windows\System32\drivers\dbutil_2_3.sys", state="Running", sig="NotSigned")])
    assert "AEG-DRV-ABUSABLE" in rules(f2) and [x for x in f2 if x.rule_id == "AEG-DRV-ABUSABLE"][0].severity == Severity.HIGH


def test_renamed_file_caught_through_service_name():
    f = analyse([drv("RTCore64", r"C:\Windows\System32\drivers\totally_innocent.sys")])
    assert rules(f) == ["AEG-DRV-ABUSABLE"]


def test_procexp_driver_only_flagged_outside_sysinternals():
    ok1 = drv("PROCEXP152", r"C:\Windows\System32\drivers\PROCEXP152.SYS", signer="CN=Microsoft Corporation")
    ok2 = drv("PROCEXP152", r"C:\Tools\Sysinternals\procexp152.sys", sig="Valid")
    assert analyse([ok1]) == [] and analyse([ok2]) == []
    bad = analyse([drv("PROCEXP152", r"C:\Users\bob\Downloads\procexp152.sys")])
    assert rules(bad) == ["AEG-DRV-ABUSABLE"] and bad[0].severity == Severity.HIGH
    bad2 = analyse([drv("PROCEXP152", r"D:\stuff\procexp152.sys")])
    assert rules(bad2) == ["AEG-DRV-ABUSABLE"] and bad2[0].severity == Severity.MEDIUM


@pytest.mark.parametrize("sig,state,sev", [
    ("NotSigned", "Stopped", Severity.MEDIUM), ("NotSigned", "Running", Severity.HIGH), ("HashMismatch", "Stopped", Severity.HIGH),
    ("NotTrusted", "Running", Severity.MEDIUM), ("UnknownError", "Stopped", Severity.MEDIUM),
])
def test_signature_problems(sig, state, sev):
    f = analyse([drv("foo", state=state, sig=sig)])
    assert rules(f) == ["AEG-DRV-UNSIGNED"] and f[0].severity == sev
    assert (f[0].remediation is not None) == (sev >= Severity.HIGH)
    assert "T1553.002" in f[0].mitre


def test_valid_unchecked_or_missing_files_produce_nothing():
    assert analyse([drv(sig="Valid"), drv(sig=""), drv(sig="NotSigned", exists=False),
                    drv("ok", r"C:\Program Files\V\v.sys", sig="Valid")]) == []


def test_location_findings():
    temp = analyse([drv("evil", r"C:\Users\bob\AppData\Local\Temp\evil.sys", state="Running", sig="Valid")])
    assert rules(temp) == ["AEG-DRV-LOCATION"] and temp[0].severity == Severity.HIGH
    appdata = analyse([drv("e2", r"C:\Users\bob\AppData\Roaming\Foo\e2.sys", sig="Valid")])
    assert appdata[0].severity == Severity.MEDIUM and appdata[0].remediation is None
    stale = analyse([drv("gone", r"C:\Users\bob\AppData\Local\Temp\gone.sys", sig="", exists=False)])
    assert stale[0].severity == Severity.LOW and "leftover" in stale[0].description
    # unusual-but-not-writable folder: only noteworthy when loaded
    assert analyse([drv("t", r"D:\Tools\t.sys", sig="Valid", state="Stopped")]) == []
    loaded = analyse([drv("t", r"D:\Tools\t.sys", sig="Valid", state="Running")])
    assert loaded[0].rule_id == "AEG-DRV-LOCATION" and loaded[0].severity == Severity.LOW


def test_unsigned_in_temp_gives_both_findings():
    f = analyse([drv("evil", r"C:\Windows\Temp\evil.sys", state="Running", sig="NotSigned")])
    assert set(rules(f)) == {"AEG-DRV-UNSIGNED", "AEG-DRV-LOCATION"} and all(x.severity == Severity.HIGH for x in f)


# ---------------------------------------------------------------- posture
def test_decode_ci_options_and_boot_options():
    assert dr.decode_ci_options(None) == {}
    ci = dr.decode_ci_options(0x1 | 0x2 | 0x400)
    assert ci["enabled"] and ci["testsign"] and ci["hvci"] and not ci["debug"] and not ci["umci"]
    assert dr.decode_ci_options(0x80)["debug"]
    b = dr.parse_boot_options(" NOEXECUTE=OPTIN  TESTSIGNING  DEBUG")
    assert b == {"testsign": True, "nointegrity": False, "debug": True}
    assert dr.parse_boot_options("DISABLE_INTEGRITY_CHECKS")["nointegrity"] and dr.parse_boot_options("")["testsign"] is False
    assert dr.parse_boot_options("NODEBUG")["debug"] is False


@pytest.mark.parametrize("value,build,hvci,status", [
    (1, 19045, False, CheckStatus.PASS), (0, 22631, True, CheckStatus.FAIL), (None, 22631, False, CheckStatus.PASS),
    (None, 22621, False, CheckStatus.PASS), (None, 19045, True, CheckStatus.PASS), (None, 19045, False, CheckStatus.WARN),
    (None, None, False, CheckStatus.WARN),
])
def test_blocklist_status(value, build, hvci, status):
    assert dr.blocklist_status(value, build, hvci)[0] == status


def checks_by_id(checks):
    return {c.check_id: c for c in checks}


def test_posture_all_good():
    checks, findings = dr.posture_results(0x1 | 0x400, "NOEXECUTE=OPTIN", 1, 1, 1, 22631)
    c = checks_by_id(checks)
    assert findings == [] and {x.status for x in checks} == {CheckStatus.PASS}
    assert set(c) == {"AEG-DRV-HVCI", "AEG-DRV-BLOCKLIST", "AEG-DRV-TESTSIGN", "AEG-DRV-KDEBUG", "AEG-DRV-SECUREBOOT"}


def test_posture_all_bad():
    checks, findings = dr.posture_results(0x1 | 0x2 | 0x80, "TESTSIGNING DEBUG", 0, 0, 0, 19045)
    c = checks_by_id(checks)
    assert c["AEG-DRV-HVCI"].status == CheckStatus.WARN and c["AEG-DRV-BLOCKLIST"].status == CheckStatus.FAIL
    assert c["AEG-DRV-TESTSIGN"].status == CheckStatus.FAIL and c["AEG-DRV-KDEBUG"].status == CheckStatus.WARN
    assert c["AEG-DRV-SECUREBOOT"].status == CheckStatus.WARN
    by = {f.rule_id: f for f in findings}
    assert set(by) == {"AEG-DRV-HVCI", "AEG-DRV-BLOCKLIST", "AEG-DRV-TESTSIGN", "AEG-DRV-KDEBUG", "AEG-DRV-SECUREBOOT"}
    assert by["AEG-DRV-TESTSIGN"].severity == Severity.HIGH and by["AEG-DRV-TESTSIGN"].remediation is None
    assert by["AEG-DRV-BLOCKLIST"].severity == Severity.MEDIUM
    rem = by["AEG-DRV-BLOCKLIST"].remediation
    assert rem.action == "set_registry_value" and rem.params == {
        "hive": "HKLM", "key": r"SYSTEM\CurrentControlSet\Control\CI\Config", "value": "VulnerableDriverBlocklistEnable", "data": 1}
    assert by["AEG-DRV-HVCI"].remediation is None  # enabling HVCI blindly can stop a PC booting
    for f in findings:
        json.dumps(f.to_dict())


def test_posture_without_ntdll_falls_back_to_registry_and_boot_string():
    checks, findings = dr.posture_results(None, "TESTSIGNING", None, 1, None, 19045)
    c = checks_by_id(checks)
    assert c["AEG-DRV-HVCI"].status == CheckStatus.PASS  # registry says enabled
    assert c["AEG-DRV-TESTSIGN"].status == CheckStatus.FAIL
    assert c["AEG-DRV-SECUREBOOT"].status == CheckStatus.SKIP
    assert c["AEG-DRV-BLOCKLIST"].status == CheckStatus.PASS  # on because HVCI is on


def test_hvci_enabled_but_not_running_message():
    checks, findings = dr.posture_results(0x1, "", 1, 1, 1, 22631)
    c = checks_by_id(checks)["AEG-DRV-HVCI"]
    assert c.status == CheckStatus.WARN and "not active" in c.detail


# ---------------------------------------------------------------- collection helpers
def test_drivers_from_registry_and_cim_merge():
    def walk(hive, key, view64=True):
        yield key + r"\acpi", {"Type": 1, "Start": 0, "ImagePath": r"\SystemRoot\System32\drivers\ACPI.sys", "DisplayName": "ACPI"}
        yield key + r"\Spooler", {"Type": 16, "Start": 2, "ImagePath": r"C:\Windows\System32\spoolsv.exe"}  # a service, not a driver
        yield key + r"\ntfs", {"Type": 2, "Start": 1}  # file-system driver, no ImagePath
        yield key + r"\RTCore64", {"Type": "1", "Start": 3, "ImagePath": r"\??\C:\Users\bob\AppData\Local\Temp\RTCore64.sys"}

    got = dr.drivers_from_registry(walk, WIN)
    assert set(got) == {"acpi", "ntfs", "rtcore64"}
    assert got["acpi"].path == r"C:\Windows\System32\drivers\ACPI.sys" and got["acpi"].start == 0
    assert got["ntfs"].path == r"C:\Windows\System32\drivers\ntfs.sys"
    dr.merge_cim_drivers(got, [{"Name": "ACPI", "State": "Running", "Description": "Microsoft ACPI Driver", "StartMode": "Boot"},
                               {"Name": "NewOne", "PathName": r"C:\Windows\System32\drivers\new.sys", "State": "Stopped",
                                "StartMode": "Manual"}], WIN)
    assert got["acpi"].running and got["acpi"].description == "Microsoft ACPI Driver"
    assert got["newone"].path == r"C:\Windows\System32\drivers\new.sys" and got["newone"].start == 3
    dr.merge_cim_drivers(got, {"Name": "ntfs", "State": "Running"}, WIN)  # single dict (PowerShell collapses one-element lists)
    assert got["ntfs"].running
    dr.merge_cim_drivers(got, None)
    dr.merge_cim_drivers(got, [{"no": "name"}, "junk"])


def test_signature_script_is_one_batched_call():
    paths = [r"C:\Windows\System32\drivers\a.sys", r"C:\Users\O'Neil\x.sys"]
    s = dr.build_signature_script(paths)
    assert s.count("Get-AuthenticodeSignature") == 1 and "-LiteralPath $p" in s
    assert "O''Neil" in s and '"' not in s and "ToString()" in s and s.count("ConvertTo-Json") == 1
    assert [i.rule_id for i in fa.content_indicators(s.encode(), "script") if i.score > 0] == []
    assert [i.rule_id for i in fa.content_indicators(dr.CIM_SCRIPT.encode(), "script") if i.score > 0] == []


def test_chunk_paths_only_splits_when_needed():
    paths = [f"C:\\Windows\\System32\\drivers\\driver{i:04d}.sys" for i in range(300)]
    assert len(dr.chunk_paths(paths)) == 1
    chunks = dr.chunk_paths(paths, limit=2000)
    assert len(chunks) > 3 and sum(len(c) for c in chunks) == 300 and all(chunks)
    assert dr.chunk_paths([]) == []


def test_apply_signatures_case_insensitive_and_single_dict():
    d1 = drv("a", r"C:\Windows\System32\drivers\a.sys", sig="")
    d2 = drv("b", r"C:\Windows\System32\drivers\b.sys", sig="")
    n = dr.apply_signatures([d1, d2], [{"Path": r"c:\windows\system32\DRIVERS\A.SYS", "Status": "Valid", "Signer": "CN=Microsoft",
                                        "Company": "Microsoft", "Description": "A driver", "Version": "10.0"}])
    assert n == 1 and d1.sig_status == "Valid" and d1.company == "Microsoft" and d2.sig_status == ""
    assert dr.apply_signatures([d2], {"Path": d2.path, "Status": "NotSigned"}) == 1 and d2.sig_status == "NotSigned"
    assert dr.apply_signatures([d2], None) == 0


# ---------------------------------------------------------------- scanner end to end (everything mocked)
def test_scanner_end_to_end(monkeypatch, ctx, tmp_path):
    evil = tmp_path / "RTCore64.sys"
    evil.write_bytes(b"MZ-not-really-a-driver-but-has-a-hash")
    good = tmp_path / "good.sys"
    good.write_bytes(b"another file")
    (ctx.config.signatures_dir / "vulnerable_drivers.txt").write_text(
        hashlib.sha256(evil.read_bytes()).hexdigest() + "\tLOLDrivers.VulnDriver: RTCore64.sys [CVE-2019-16098]\n")

    def walk(hive, key, view64=True):
        yield key + r"\RTCore64", {"Type": 1, "Start": 3, "ImagePath": str(evil)}
        yield key + r"\good", {"Type": 1, "Start": 3, "ImagePath": str(good)}
        yield key + r"\ghost", {"Type": 1, "Start": 3, "ImagePath": str(tmp_path / "ghost.sys")}

    def ps(script, timeout=90):
        if "Win32_SystemDriver" in script:
            return [{"Name": "RTCore64", "State": "Running", "StartMode": "Manual"}]
        return [{"Path": str(good), "Status": "NotSigned", "Signer": "", "Company": "", "Description": "", "Version": ""},
                {"Path": str(evil), "Status": "Valid", "Signer": "CN=MICRO-STAR", "Company": "MSI", "Description": "d", "Version": "1"}]

    monkeypatch.setattr(dr, "IS_WINDOWS", True)
    monkeypatch.setattr(dr, "reg_walk_values", walk)
    monkeypatch.setattr(dr, "powershell_json", ps)
    monkeypatch.setattr(dr, "reg_read", lambda *a, **k: None)
    monkeypatch.setattr(dr, "code_integrity_options", lambda: 0x1)
    monkeypatch.setattr(dr, "windows_build", lambda: 19045)
    out = list(dr.DriverScanner().run(ctx))
    findings = [x for x in out if isinstance(x, Finding)]
    checks = checks_by_id([x for x in out if isinstance(x, CheckResult)])
    vuln = [f for f in findings if f.rule_id == "AEG-DRV-VULN"]
    assert len(vuln) == 1 and vuln[0].severity == Severity.HIGH and vuln[0].evidence["cves"] == ["CVE-2019-16098"]
    assert vuln[0].evidence["running"] is True and vuln[0].remediation.params == {"name": "RTCore64"}
    unsigned = [f for f in findings if f.rule_id == "AEG-DRV-UNSIGNED"]
    assert len(unsigned) == 1 and unsigned[0].evidence["service"] == "good"
    assert checks["AEG-DRV-VULN"].status == CheckStatus.FAIL and checks["AEG-DRV-SIGNED"].status == CheckStatus.FAIL
    assert checks["AEG-DRV-INVENTORY"].status == CheckStatus.PASS and "3 kernel driver" in checks["AEG-DRV-INVENTORY"].detail
    assert "AEG-DRV-HVCI" in checks and "AEG-DRV-BLOCKLIST" in checks
    assert ctx.stats["drivers_inspected"] == 3
    json.dumps([x.to_dict() for x in out])


def test_scanner_when_powershell_fails_and_no_drivers(monkeypatch, ctx):
    monkeypatch.setattr(dr, "IS_WINDOWS", True)
    monkeypatch.setattr(dr, "reg_walk_values", lambda *a, **k: iter(()))
    monkeypatch.setattr(dr, "powershell_json", lambda *a, **k: None)
    monkeypatch.setattr(dr, "reg_read", lambda *a, **k: None)
    monkeypatch.setattr(dr, "code_integrity_options", lambda: None)
    monkeypatch.setattr(dr, "windows_build", lambda: None)
    out = list(dr.DriverScanner().run(ctx))
    inv = [x for x in out if isinstance(x, CheckResult) and x.check_id == "AEG-DRV-INVENTORY"]
    assert inv and inv[0].status == CheckStatus.SKIP


def test_scanner_non_windows_skips_and_is_registered(ctx):
    out = list(dr.DriverScanner().run(ctx))  # the test host is not Windows
    assert len(out) == 1 and out[0].status == CheckStatus.SKIP
    load_all()
    assert REGISTRY["drivers"].platforms == ("windows",)
