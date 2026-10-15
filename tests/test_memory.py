"""Tests for aegis.scanners.memory. The pure logic (process selection, self-exclusion, watchdog, findings) always runs;
tests that need a real YARA engine are skipped when yara-python is missing."""

import os
import subprocess
import sys
import time
import uuid

import pytest

from aegis.core.models import CheckResult, CheckStatus, Finding, Severity
from aegis.scanners import memory as mem
from aegis.scanners.base import REGISTRY, load_all


def P(pid, name="x.exe", exe=r"C:\Program Files\App\x.exe", ppid=1, created=0.0, cmdline="x"):
    return mem.ProcRec(pid=pid, name=name, exe=exe, ppid=ppid, create_time=created, cmdline=cmdline)


class _Inst:
    def __init__(self, offset):
        self.offset = offset


class _Str:
    def __init__(self, identifier, offsets):
        self.identifier, self.instances = identifier, [_Inst(o) for o in offsets]


class FakeMatch:
    def __init__(self, rule="Test_Rule", meta=None, strings=("$a",), namespace="default", tags=(), offsets=(0x1000,)):
        self.rule, self.namespace, self.tags = rule, namespace, list(tags)
        self.meta = {"description": "Test detection", "severity": "high", "scope": "memory"} if meta is None else meta
        self.strings = [_Str(s, offsets) for s in strings]


class FakeRules:
    """Stands in for compiled YARA rules: records calls, returns scripted results per pid."""

    def __init__(self, script=None, delay=0.0):
        self.script = script or {}
        self.calls = []
        self.delay = delay

    def match(self, **kw):
        self.calls.append(kw)
        if self.delay:
            time.sleep(self.delay)
        r = self.script.get(kw.get("pid"), [])
        if isinstance(r, Exception):
            raise r
        return r


DEADLINE = lambda: time.monotonic() + 60  # noqa: E731


# ---------------------------------------------------------------- process selection
def test_own_pids_self_children_parent_and_frozen_duplicates():
    me = os.getpid()
    procs = [P(10, "shell"), P(me, "python", exe="/usr/bin/python3", ppid=10), P(me + 1, "child", ppid=me), P(me + 2, "grandchild", ppid=me + 1),
             P(50, "other"), P(51, "aegis.exe", exe=r"C:\Aegis\aegis.exe", ppid=1)]
    ex = mem.own_pids(procs, me=me, my_exe="/usr/bin/python3", frozen=False)
    assert ex == {me, me + 1, me + 2}  # parent shell and unrelated processes are NOT excluded
    boot = [P(20, "aegis.exe", exe=r"C:\Aegis\aegis.exe", ppid=1), P(me, "aegis.exe", exe=r"C:\Aegis\aegis.exe", ppid=20),
            P(60, "aegis.exe", exe=r"C:\Aegis\aegis.exe", ppid=1), P(61, "notepad.exe", exe=r"C:\Windows\notepad.exe")]
    ex2 = mem.own_pids(boot, me=me, my_exe=r"C:\Aegis\aegis.exe", frozen=True)
    assert ex2 == {me, 20, 60}  # PyInstaller bootloader parent + other copies of our exe


def test_select_processes_filters_and_orders():
    exclude = {100}
    procs = [P(100, "aegis"), P(4, "System", exe=""), P(5, "Registry", exe="", cmdline=""), P(300, "MsMpEng.exe", exe=r"C:\ProgramData\Microsoft\x\MsMpEng.exe"),
             P(301, "kthreadd", exe="", cmdline=""), P(400, "app.exe", created=5.0), P(401, "evil.exe", exe=r"C:\Users\bob\AppData\Local\Temp\evil.exe", created=1.0),
             P(402, "powershell.exe", exe=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", created=9.0),
             P(403, "hollow.exe", exe="", cmdline="hollow.exe", created=2.0), P(404, "new.exe", exe=r"C:\Program Files\N\new.exe", created=50.0)]
    chosen, st = mem.select_processes(procs, exclude, 100)
    order = [p.pid for p in chosen]
    assert order[0] == 401  # drop-location binary first
    assert 100 not in order and 300 not in order and 4 not in order and 5 not in order and 301 not in order
    assert order.index(402) < order.index(404)  # script host before ordinary programs
    assert order.index(404) < order.index(400)  # newest first within equal priority
    assert st["self"] == 1 and st["skipped_names"] >= 2 and st["kernel"] >= 1
    capped, st2 = mem.select_processes(procs, exclude, 2)
    assert len(capped) == 2 and st2["capped"] == len(order) - 2


# ---------------------------------------------------------------- scan_pid watchdog
def test_scan_pid_classifies_errors():
    ok = mem.scan_pid(FakeRules({7: ["m"]}), 7, 2)
    assert ok == ("ok", ["m"])
    assert mem.scan_pid(FakeRules({8: OSError("access denied")}), 8, 2)[0] == "denied"
    assert mem.scan_pid(FakeRules({9: RuntimeError("scanning timed out")}), 9, 2)[0] == "timeout"
    assert mem.scan_pid(FakeRules({10: RuntimeError("could not attach to process")}), 10, 2)[0] == "denied"
    assert mem.scan_pid(FakeRules({11: ValueError("weird")}), 11, 2)[0] == "error"


def test_scan_pid_never_hangs_the_scan():
    t0 = time.monotonic()
    status, payload = mem.scan_pid(FakeRules(delay=3.0), 1234, timeout=0.2, grace=0.2)
    assert status == "hung" and payload is None
    assert time.monotonic() - t0 < 1.5  # returned after timeout+grace, not after the 3 s native call


# ---------------------------------------------------------------- scan_processes
def test_scan_processes_never_scans_excluded_or_own_pid(monkeypatch):
    me = os.getpid()
    marker = "AEGIS_" + "MEM_" + uuid.uuid4().hex  # a harmless marker living in this very process's memory
    assert marker in locals().values()
    rules = FakeRules({me: [FakeMatch("Marker")], 2000: [FakeMatch("Marker")]})
    res = mem.scan_processes(rules, [P(me, "pytest"), P(2000, "child"), P(2001, "ok")], DEADLINE(), 5, exclude={2000})
    assert [c["pid"] for c in rules.calls] == [2001]  # own pid and the excluded pid were never handed to yara
    assert res.findings == [] and res.skipped_self == 2 and res.scanned == 1


def test_scan_processes_findings_counters_and_remediation():
    rules = FakeRules({
        1: [FakeMatch("Cobalt_Strike_Beacon", {"description": "Cobalt Strike beacon in memory", "severity": "critical",
                                               "mitre": "T1055, T1071", "author": "t", "scope": "memory"})],
        2: OSError("access denied"), 3: RuntimeError("scanning timed out"), 4: ValueError("boom"),
        5: [FakeMatch("File_Only", {"scope": "file", "severity": "high"})],
        6: [FakeMatch("Low_Rule", {"description": "just info", "severity": "low", "scope": "memory"})],
        7: [FakeMatch("No_Meta", {"scope": "memory"})]})
    procs = [P(1, "evil.exe", exe=r"C:\Users\bob\AppData\Local\Temp\evil.exe"), P(2, "a.exe"), P(3, "b.exe"), P(4, "c.exe"),
             P(5, "d.exe"), P(6, "e.exe"), P(7, "f.exe", exe=r"C:\Program Files\F\f.exe")]
    res = mem.scan_processes(rules, procs, DEADLINE(), 5)
    assert res.denied == 1 and res.timeouts == 1 and res.errors == 1 and res.scanned == 4 and res.first_error.startswith("ValueError")
    by = {f.rule_id: f for f in res.findings}
    assert set(by) == {"AEG-MEM-Cobalt_Strike_Beacon", "AEG-MEM-Low_Rule", "AEG-MEM-No_Meta"}  # the scope=file rule is ignored
    assert res.ignored_generic == 0  # file-scoped matches are not even counted as "generic"
    c = by["AEG-MEM-Cobalt_Strike_Beacon"]
    assert c.severity == Severity.CRITICAL and c.category == "malware" and c.mitre == ["T1055", "T1071"]
    assert c.evidence["pid"] == 1 and c.evidence["rule"] == "Cobalt_Strike_Beacon" and c.evidence["exe"].endswith("evil.exe")
    assert c.evidence["matched_strings"] == ["$a"] and c.location == r"C:\Users\bob\AppData\Local\Temp\evil.exe (pid 1)"
    assert c.evidence["corroboration"] == "memory-scoped rule" and c.evidence["scope"] == "memory"
    assert c.remediation.action == "kill_process" and c.remediation.params == {"pid": 1, "path": r"C:\Users\bob\AppData\Local\Temp\evil.exe", "quarantine": True}
    assert by["AEG-MEM-Low_Rule"].remediation is None  # LOW: informational only
    nm = by["AEG-MEM-No_Meta"]
    assert nm.severity == Severity.HIGH and nm.remediation.params["quarantine"] is False  # vendor path: kill, never quarantine
    assert nm.mitre == ["T1055"]
    import json

    json.dumps([f.to_dict() for f in res.findings])


def test_generic_rules_need_corroboration():
    """File-oriented (untagged) rules match *text* held by browsers/editors/terminals; they only count in executable memory or
    inside an already suspicious process."""
    generic = {"description": "Mimikatz strings", "severity": "critical"}
    rules = FakeRules({10: [FakeMatch("Mimi", dict(generic))], 11: [FakeMatch("Mimi", dict(generic))], 12: [FakeMatch("Mimi", dict(generic))],
                       13: [FakeMatch("Mimi", dict(generic))]})
    procs = [P(10, "chrome.exe", exe=r"C:\Program Files\Google\Chrome\Application\chrome.exe"),   # text in a data buffer
             P(11, "installer.exe", exe=r"C:\Program Files\Vendor\installer.exe"),                    # match in code
             P(12, "dropped.exe", exe=r"C:\Users\bob\Downloads\dropped.exe"),                        # suspicious process
             P(13, "rundll32.exe", exe=r"C:\Windows\System32\rundll32.exe")]                          # script/LOLBin host
    code_pids = {11}
    res = mem.scan_processes(rules, procs, DEADLINE(), 5, region_exec=lambda pid, addrs: pid in code_pids)
    by_pid = {f.evidence["pid"]: f for f in res.findings}
    assert set(by_pid) == {11, 12, 13} and res.ignored_generic == 1  # chrome's text match ignored, but counted
    assert by_pid[11].evidence["corroboration"] == "match is in executable memory"
    assert by_pid[12].evidence["corroboration"] == "the process itself is suspicious" and by_pid[12].evidence["scope"] == "generic"
    assert all(f.severity == Severity.HIGH for f in by_pid.values())  # a generic rule never reaches CRITICAL
    assert mem.match_verdict(P(10, "chrome.exe"), FakeMatch("M", {"severity": "critical"}), lambda pid, a: None) is None
    assert mem.match_verdict(P(10, "chrome.exe"), FakeMatch("M", {"severity": "critical", "scope": "any"}), lambda pid, a: None) == ("memory-scoped rule", Severity.CRITICAL)
    assert mem.match_verdict(P(10, "chrome.exe"), FakeMatch("M", {"severity": "critical", "scope": "file"}), lambda pid, a: True) is None
    assert mem.match_verdict(P(10, "chrome.exe"), FakeMatch("M", {"severity": "critical"}), None) is None  # no region lookup available
    assert mem.match_verdict(P(10, "x.exe", exe=""), FakeMatch("M", {"severity": "low"}), None)[1] == Severity.LOW  # unknown image => suspicious


def test_match_addresses_handles_new_and_legacy_formats():
    m = FakeMatch(strings=("$a", "$b"), offsets=(0x10, 0x20))
    assert mem.match_addresses(m) == [0x10, 0x20, 0x10, 0x20]

    class Legacy:
        strings = [(0x500, "$x", b"data"), (0x600, "$y", b"d")]

    assert mem.match_addresses(Legacy()) == [0x500, 0x600]
    assert mem.match_addresses(object()) == []
    assert len(mem.match_addresses(FakeMatch(strings=("$a",), offsets=tuple(range(100))), limit=5)) == 5


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads /proc/<pid>/maps")
def test_addresses_in_executable_memory_on_linux():
    maps = open("/proc/self/maps").read().splitlines()
    exec_lo = next(int(l.split()[0].split("-")[0], 16) for l in maps if "x" in l.split()[1])
    data_lo = next(int(l.split()[0].split("-")[0], 16) for l in maps if l.split()[1].startswith("rw-"))
    pid = os.getpid()
    assert mem.addresses_in_executable_memory(pid, [exec_lo + 8]) is True
    assert mem.addresses_in_executable_memory(pid, [data_lo + 8]) is False
    assert mem.addresses_in_executable_memory(pid, [data_lo + 8, exec_lo + 8]) is True
    assert mem.addresses_in_executable_memory(pid, [1]) is None  # unmapped address: unknown
    assert mem.addresses_in_executable_memory(pid, []) is None
    assert mem.addresses_in_executable_memory(2 ** 22 + 1234567, [0x1000]) is None  # no such process


def test_scan_processes_respects_deadline_cancel_and_hang():
    rules = FakeRules()
    res = mem.scan_processes(rules, [P(1), P(2)], time.monotonic() - 1, 5)
    assert res.out_of_time and rules.calls == [] and res.scanned == 0
    res = mem.scan_processes(rules, [P(1), P(2)], DEADLINE(), 5, cancelled=lambda: True)
    assert rules.calls == []
    slow = FakeRules(delay=2.0)
    t0 = time.monotonic()
    res = mem.scan_processes(slow, [P(1), P(2), P(3)], DEADLINE(), 0.2, grace=0.2)
    assert res.hung and len(slow.calls) == 1 and time.monotonic() - t0 < 1.5  # stops after the first stuck scan


# ---------------------------------------------------------------- RWX heuristic
def test_rwx_finding_rules():
    regions = [(0x1000000, 65536, 0x40), (0x2000000, 4096, 0x80)]
    f = mem.rwx_finding(P(9, "notepad.exe", exe=r"C:\Windows\notepad.exe"), regions)
    assert f.rule_id == "AEG-MEM-RWX" and f.severity == Severity.MEDIUM and f.evidence["regions"] == 2 and f.evidence["total_bytes"] == 69632
    assert f.evidence["first_regions"][0]["protect"] == "0x40" and f.remediation.params["quarantine"] is False and "T1055" in f.mitre
    assert mem.rwx_finding(P(9, "chrome.exe"), regions) is None  # JIT host
    assert mem.rwx_finding(P(9, "java.exe"), regions) is None
    assert mem.rwx_finding(P(9, "notepad.exe"), []) is None


def test_private_exec_regions_unavailable_off_windows():
    if not mem.IS_WINDOWS:
        assert mem.private_exec_regions(os.getpid()) is None


# ---------------------------------------------------------------- scanner
def ctx_with(ctx, rules):
    ctx.signatures.yara_rules = rules
    ctx.options.update({"memory_budget_s": 20, "memory_proc_timeout_s": 2})
    return ctx


def fake_procs(monkeypatch, procs):
    monkeypatch.setattr(mem, "list_processes", lambda: list(procs))


def test_scanner_end_to_end_with_fake_rules(monkeypatch, ctx):
    me = os.getpid()
    fake_procs(monkeypatch, [P(me, "pytest", exe="/usr/bin/python3"), P(4001, "evil.exe", exe=r"C:\Users\bob\Downloads\evil.exe"), P(4002, "ok.exe"),
                             P(4003, "denied.exe")])
    monkeypatch.setattr(mem, "HAVE_YARA", True)
    rules = FakeRules({4001: [FakeMatch("Meterpreter_Stager", {"description": "Meterpreter stager", "severity": "high", "scope": "memory"})],
                       4003: OSError("access denied")})
    out = list(mem.MemoryScanner().run(ctx_with(ctx, rules)))
    findings = [x for x in out if isinstance(x, Finding)]
    checks = {c.check_id: c for c in out if isinstance(c, CheckResult)}
    assert [f.rule_id for f in findings] == ["AEG-MEM-Meterpreter_Stager"]
    assert findings[0].evidence["pid"] == 4001
    assert me not in [c["pid"] for c in rules.calls]  # Aegis itself was never scanned
    y = checks["AEG-MEM-YARA"]
    assert y.status == CheckStatus.FAIL and "Scanned the memory of 2 of 4" in y.detail
    assert "1 process(es) could not be read" in y.detail and "1 Aegis process(es) skipped" in y.detail
    assert checks["AEG-MEM-RWX"].status == CheckStatus.SKIP  # not Windows
    assert ctx.stats["memory_processes_scanned"] == 2


def test_scanner_clean_run_and_access_hint(monkeypatch, ctx):
    fake_procs(monkeypatch, [P(5001, "a.exe"), P(5002, "b.exe")])
    monkeypatch.setattr(mem, "HAVE_YARA", True)
    ctx.is_admin = False
    out = list(mem.MemoryScanner().run(ctx_with(ctx, FakeRules())))
    y = [c for c in out if isinstance(c, CheckResult) and c.check_id == "AEG-MEM-YARA"][0]
    assert y.status == CheckStatus.PASS and "Administrator" in y.detail
    assert [x for x in out if isinstance(x, Finding)] == []


def test_scanner_skips_without_yara_or_rules(monkeypatch, ctx):
    fake_procs(monkeypatch, [P(5001, "a.exe")])
    monkeypatch.setattr(mem, "HAVE_YARA", False)
    out = list(mem.MemoryScanner().run(ctx_with(ctx, FakeRules())))
    y = [c for c in out if c.check_id == "AEG-MEM-YARA"][0]
    assert y.status == CheckStatus.SKIP and "yara-python" in y.detail
    monkeypatch.setattr(mem, "HAVE_YARA", True)
    out = list(mem.MemoryScanner().run(ctx_with(ctx, None)))
    y = [c for c in out if c.check_id == "AEG-MEM-YARA"][0]
    assert y.status == CheckStatus.SKIP and "No YARA rules" in y.detail


def test_scanner_hang_is_reported_not_fatal(monkeypatch, ctx):
    fake_procs(monkeypatch, [P(6001, "a.exe"), P(6002, "b.exe"), P(6003, "c.exe")])
    monkeypatch.setattr(mem, "HAVE_YARA", True)
    rules = FakeRules(delay=2.0)
    c = ctx_with(ctx, rules)
    c.options.update({"memory_proc_timeout_s": 0.2, "memory_watchdog_grace_s": 0.2})
    t0 = time.monotonic()
    out = list(mem.MemoryScanner().run(c))
    y = [x for x in out if isinstance(x, CheckResult) and x.check_id == "AEG-MEM-YARA"][0]
    assert y.status == CheckStatus.ERROR and "stopped responding" in y.detail
    assert len(rules.calls) == 1 and time.monotonic() - t0 < 1.5  # aborted after the first stuck scan


def test_scanner_time_budget_is_reported(monkeypatch, ctx):
    fake_procs(monkeypatch, [P(6001, "a.exe"), P(6002, "b.exe")])
    monkeypatch.setattr(mem, "HAVE_YARA", True)
    rules = FakeRules()
    c = ctx_with(ctx, rules)
    c.options["memory_budget_s"] = 0.0000001
    out = list(mem.MemoryScanner().run(c))
    y = [x for x in out if isinstance(x, CheckResult) and x.check_id == "AEG-MEM-YARA"][0]
    assert rules.calls == [] and y.status == CheckStatus.WARN and "time budget" in y.detail


def test_scanner_windows_rwx_flow(monkeypatch, ctx):
    fake_procs(monkeypatch, [P(7001, "notepad.exe", exe=r"C:\Windows\notepad.exe"), P(7002, "chrome.exe"), P(7003, "calc.exe", exe=r"C:\Windows\calc.exe")])
    monkeypatch.setattr(mem, "HAVE_YARA", False)
    monkeypatch.setattr(mem, "IS_WINDOWS", True)
    monkeypatch.setattr(mem, "private_exec_regions", lambda pid: {7001: [(0x10000, 8192, 0x40)], 7003: []}.get(pid))
    out = list(mem.MemoryScanner().run(ctx_with(ctx, FakeRules())))
    f = [x for x in out if isinstance(x, Finding)]
    assert [x.rule_id for x in f] == ["AEG-MEM-RWX"] and f[0].evidence["pid"] == 7001
    rwx = [c for c in out if isinstance(c, CheckResult) and c.check_id == "AEG-MEM-RWX"][0]
    assert rwx.status == CheckStatus.FAIL and "Examined 2" in rwx.detail  # chrome is a JIT host and not examined


def test_scanner_registered():
    load_all()
    cls = REGISTRY["memory"]
    assert set(cls.platforms) == {"windows", "linux", "darwin"} and cls.title and cls.description


# ---------------------------------------------------------------- real YARA engine
def need_yara():
    return pytest.importorskip("yara", reason="yara-python is not installed")


def test_real_yara_marker_in_own_memory_is_not_scanned_or_flagged(ctx):
    y = need_yara()
    marker = "AEGIS" + "_OWN_MEM_" + uuid.uuid4().hex  # exists only in this process's memory (plus the rule source below)
    rules = y.compile(source='rule Own_Marker { strings: $m = "%s" ascii wide condition: $m }' % marker)

    class Spy:
        def __init__(self, r):
            self.r, self.pids = r, []

        def match(self, **kw):
            self.pids.append(kw.get("pid"))
            return self.r.match(**kw)

    spy = Spy(rules)
    me = os.getpid()
    res = mem.scan_processes(spy, [P(me, "pytest", exe=sys.executable)], DEADLINE(), 5)
    assert spy.pids == [] and res.findings == [] and res.skipped_self == 1  # the marker IS in our memory, but we never look
    assert marker in repr(marker)
    # full scanner run: the filter keeps our pid out as well; use a process list that holds only us plus a sentinel
    monkey_list = [P(me, "pytest", exe=sys.executable)]
    chosen, st = mem.select_processes(monkey_list, mem.own_pids(monkey_list), 10)
    assert chosen == [] and st["self"] == 1


def test_real_yara_scans_a_foreign_process(ctx):
    y = need_yara()
    marker = "AEGIS" + "_CHILD_MEM_" + uuid.uuid4().hex
    scoped = y.compile(source='rule Child_Marker { meta: description = "marker in child memory" severity = "high" scope = "memory" '
                              'strings: $m = "%s" ascii wide condition: $m }' % marker)
    generic = y.compile(source='rule Child_Generic { meta: description = "generic marker" severity = "critical" '
                               'strings: $m = "%s" ascii wide condition: $m }' % marker)
    code = "import sys,time; m=sys.argv[1]; print('ready', flush=True); time.sleep(60)"
    child = subprocess.Popen([sys.executable, "-I", "-c", code, marker], stdout=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == "ready"
        proc = P(child.pid, "python", exe=sys.executable)
        res = mem.scan_processes(scoped, [proc], DEADLINE(), 20)  # the child is not 'us': it is scanned for real
        if res.denied or res.errors:
            pytest.skip("this environment does not allow reading other processes' memory: " + (res.first_error or "access denied"))
        assert [f.rule_id for f in res.findings] == ["AEG-MEM-Child_Marker"]
        f = res.findings[0]
        assert f.evidence["pid"] == child.pid and f.evidence["rule"] == "Child_Marker" and f.remediation.action == "kill_process"
        assert f.remediation.params["pid"] == child.pid and f.evidence["matched_strings"] == ["$m"]
        # the same text matched by an untagged rule sits in a data buffer (argv / heap / stack): ignored, but counted
        res2 = mem.scan_processes(generic, [proc], DEADLINE(), 20)
        assert res2.findings == [] and res2.ignored_generic == 1
    finally:
        child.kill()
        child.wait(timeout=10)
