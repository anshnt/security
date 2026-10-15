"""Tests for the real-time protection engine, notifications and the GUI shell.

All tests use temp dirs and short intervals; nothing touches the real home
folder or suspends real processes."""

from __future__ import annotations

import json
import os
import struct
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from aegis.core.config import Config
from aegis.core.models import Category, Finding, Remediation, Severity
from aegis.realtime import monitor as M
from aegis.realtime import notify as N


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path / "aegis_home"))
    c = Config()
    c.notifications = False
    return c


def wait_for(pred, timeout=6.0, step=0.05):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(step)
    return pred()


def make_monitor(cfg, **kw):
    events = []
    kw.setdefault("components", ("files",))
    mon = M.RealtimeMonitor(cfg, SimpleNamespace(), on_event=events.append, **kw)
    mon.ransomware.suspend_enabled = False  # never suspend real processes in tests
    return mon, events


# --------------------------------------------------------------------------- watchers

def test_parse_notify_buffer_roundtrip():
    def rec(action, name, last):
        raw = name.encode("utf-16-le")
        body = struct.pack("<III", 0 if last else 12 + len(raw) + (-(12 + len(raw)) % 4), action, len(raw)) + raw
        return body + b"\x00" * ((-len(body)) % 4)

    buf = rec(4, "old.txt", False) + rec(5, "new.txt", True)
    assert M.parse_notify_buffer(buf, len(buf)) == [(4, "old.txt"), (5, "new.txt")]
    assert M.parse_notify_buffer(b"", 0) == []


def test_polling_watcher_diff(tmp_path):
    events = []
    w = M.PollingWatcher([(tmp_path, True)], lambda k, p, o: events.append((k, Path(p).name, o and Path(o).name)))
    w.poll_once()  # baseline: no events for pre-existing state
    assert events == []
    f = tmp_path / "a.txt"
    f.write_text("one")
    w.poll_once()
    assert ("created", "a.txt", None) in events
    f.write_text("one two three")
    w.poll_once()
    assert ("modified", "a.txt", None) in events
    os.rename(f, tmp_path / "b.txt")
    w.poll_once()
    assert ("renamed", "b.txt", "a.txt") in events
    (tmp_path / "b.txt").unlink()
    w.poll_once()
    assert ("deleted", "b.txt", None) in events


def test_polling_watcher_non_recursive_and_skip_dirs(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "node_modules").mkdir()
    events = []
    w = M.PollingWatcher([(tmp_path, False)], lambda k, p, o: events.append(Path(p).name))
    w.poll_once()
    (tmp_path / "sub" / "x.txt").write_text("x")
    (tmp_path / "top.txt").write_text("x")
    w.poll_once()
    assert events == ["top.txt"]
    events.clear()
    w2 = M.PollingWatcher([(tmp_path, True)], lambda k, p, o: events.append(Path(p).name))
    w2.poll_once()
    (tmp_path / "node_modules" / "y.js").write_text("y")
    w2.poll_once()
    assert "y.js" not in events


def test_file_guard_debounce_and_scan(cfg, tmp_path, monkeypatch):
    import aegis.scanners.files as F

    scanned = []
    monkeypatch.setattr(F, "scan_file", lambda ctx, p, cache=None: scanned.append(Path(p).name) or [])
    watch = tmp_path / "watch"
    watch.mkdir()
    mon, _ = make_monitor(cfg, watch_specs=[(watch, True)], stable_secs=1.0)
    g = mon.files
    f = watch / "setup.exe"
    f.write_bytes(b"MZ" + b"\0" * 100)
    g.queue(str(f))
    t = time.monotonic()
    assert g.process_pending(now=t) == 0  # first sight records the signature
    assert g.process_pending(now=t + 0.5) == 0  # stable, but not for long enough
    f.write_bytes(b"MZ" + b"\0" * 200)  # still being written -> timer resets
    assert g.process_pending(now=t + 1.2) == 0
    assert g.process_pending(now=t + 1.3) == 0
    assert g.process_pending(now=t + 2.6) == 1
    assert scanned == ["setup.exe"]
    g.queue(str(f))  # same unchanged version is not rescanned
    g.process_pending(now=t + 3)
    g.process_pending(now=t + 5)
    assert scanned == ["setup.exe"]


def test_polling_monitor_detects_new_file_and_scans(cfg, tmp_path, monkeypatch):
    import aegis.scanners.files as F

    scanned = []
    monkeypatch.setattr(F, "scan_file", lambda ctx, p, cache=None: scanned.append(Path(p).name) or [])
    watch = tmp_path / "watch"
    watch.mkdir()
    mon, _ = make_monitor(cfg, watch_specs=[(watch, True)], backend="poll", poll_interval=0.1, stable_secs=0.3)
    mon.start()
    try:
        assert mon.running
        time.sleep(0.4)  # let the baseline snapshot happen
        (watch / "dropper.exe").write_bytes(b"MZ" + b"A" * 300)
        assert wait_for(lambda: "dropper.exe" in scanned), "new file was not scanned"
        assert mon.stats["files_scanned"] >= 1
    finally:
        mon.stop()
    assert not mon.running
    assert wait_for(lambda: not any(t.is_alive() for t in mon._threads), 3)


def test_file_guard_auto_quarantine_and_event(cfg, tmp_path, monkeypatch):
    import aegis.scanners.files as F
    from aegis.core.quarantine import Quarantine

    watch = tmp_path / "watch"
    watch.mkdir()

    def fake_scan(ctx, p, cache=None):
        return [Finding("AEG-SIG-HASH", "Known malware: Test.Sample", Severity.CRITICAL, Category.MALWARE, "x", str(p),
                        {}, "q", Remediation("quarantine_file", {"path": str(p)}))]

    monkeypatch.setattr(F, "scan_file", fake_scan)
    cfg.auto_quarantine = True
    cfg.auto_quarantine_min_severity = "high"
    mon, events = make_monitor(cfg, watch_specs=[(watch, True)], backend="poll", poll_interval=0.1, stable_secs=0.3)
    mon.start()
    try:
        time.sleep(0.3)
        victim = watch / "evil.exe"
        victim.write_bytes(b"MZ" + b"B" * 400)
        assert wait_for(lambda: events), "no event emitted"
    finally:
        mon.stop()
    assert not victim.exists()
    assert len(Quarantine(cfg).list()) == 1
    ev = events[0]
    assert ev.title.startswith("Blocked:")
    assert "quarantined" in ev.evidence["auto_remediation"]
    lines = (cfg.logs_dir / "realtime_events.jsonl").read_text(encoding="utf-8").splitlines()
    assert json.loads(lines[-1])["rule_id"] == "AEG-SIG-HASH"


def test_emit_dedup_allowlist_and_callback_errors(cfg):
    got = []

    def bad_cb(f):
        got.append(f)
        raise RuntimeError("boom")

    mon = M.RealtimeMonitor(cfg, SimpleNamespace(), on_event=bad_cb, components=())
    f = Finding("AEG-T", "t", Severity.HIGH, Category.MALWARE, location="/x")
    assert mon.emit(f) is True
    assert mon.emit(f) is False  # de-duplicated
    assert mon.emit(f, force=True) is True
    other = Finding("AEG-T", "t", Severity.HIGH, Category.MALWARE, location="/y")
    cfg.allowlist_fingerprints.append(other.fingerprint)
    assert mon.emit(other) is False
    assert len(got) == 2


# --------------------------------------------------------------------------- ransomware: canaries

def test_canary_files_are_plausible(tmp_path):
    d = M.build_canary_bytes("docx", "abc123")
    zf = zipfile.ZipFile(__import__("io").BytesIO(d))
    assert "word/document.xml" in zf.namelist() and zf.testzip() is None
    x = M.build_canary_bytes("xlsx", "abc123")
    assert "xl/workbook.xml" in zipfile.ZipFile(__import__("io").BytesIO(x)).namelist()
    p = M.build_canary_bytes("pdf", "abc123")
    assert p.startswith(b"%PDF-1.4") and p.rstrip().endswith(b"%%EOF")
    # xref offsets point at the objects
    startxref = int(p.split(b"startxref\n")[1].split(b"\n")[0])
    assert p[startxref:startxref + 4] == b"xref"
    assert len(d) > 1500 and len(p) > 1500


def test_canary_deploy_idempotent_and_detection(cfg, tmp_path):
    docs = tmp_path / "Documents"
    docs.mkdir()
    state = tmp_path / "canaries.json"
    cm = M.CanaryManager(cfg, [docs], state)
    created = cm.deploy()
    assert len(created) == 3
    assert sorted(Path(p).suffix for p in created) == [".docx", ".pdf", ".xlsx"]
    assert all(Path(p).name.startswith("~$aegis-canary-") for p in created)
    assert cm.deploy() == []
    cm2 = M.CanaryManager(cfg, [docs], state)  # state survives restarts
    assert cm2.deploy() == [] and len(cm2.paths()) == 3

    docx = next(p for p in created if p.endswith(".docx"))
    # created events (our own writes) and pure touches are ignored
    assert cm.check_event("created", docx) is None
    st = os.stat(docx)
    os.utime(docx, ns=(st.st_atime_ns, st.st_mtime_ns + 5_000_000_000))
    assert cm.check_event("modified", docx) is None
    # real modification
    with open(docx, "ab") as fh:
        fh.write(b"ENCRYPTED")
    hit = cm.check_event("modified", docx)
    assert hit and hit.kind == "modified"
    assert cm.check_event("modified", docx) is None  # already tripped

    pdf = next(p for p in created if p.endswith(".pdf"))
    os.remove(pdf)
    assert [h.kind for h in cm.poll()] == ["deleted"]

    xlsx = next(p for p in created if p.endswith(".xlsx"))
    hit = cm.check_event("renamed", xlsx + ".locked", xlsx)
    assert hit and hit.kind == "renamed"
    assert cm.is_canary(docx) and not cm.is_canary(str(tmp_path / "other.docx"))

    assert cm.remove_canaries() >= 1
    assert cm.paths() == []


def test_canary_modified_while_protection_off(cfg, tmp_path):
    docs = tmp_path / "Documents"
    docs.mkdir()
    state = tmp_path / "c.json"
    cm = M.CanaryManager(cfg, [docs], state)
    created = cm.deploy()
    with open(created[0], "ab") as fh:
        fh.write(b"tampered")
    cm2 = M.CanaryManager(cfg, [docs], state)
    cm2.deploy()
    assert [h.kind for h in cm2.startup_hits] == ["modified"]


def test_ransomware_guard_canary_event(cfg, tmp_path):
    docs = tmp_path / "Documents"
    docs.mkdir()
    mon, events = make_monitor(cfg, components=("ransomware",), canary_dirs=[docs])
    mon.ransomware.interval = 0.1
    mon.ransomware.canaries.state_path = tmp_path / "state.json"
    mon.start()
    try:
        canary = next(Path(p) for p in mon.ransomware.canaries.paths() if p.endswith(".docx"))
        # Rewrite in place (as ransomware does). Opening a *hidden* file with "wb"
        # (CREATE_ALWAYS) is refused by Windows, so use r+b and truncate.
        with open(canary, "r+b") as fh:
            fh.write(b"\x00garbage-encrypted-content" * 50)
            fh.truncate()
        assert wait_for(lambda: any(e.rule_id == "AEG-RANSOM-CANARY" for e in events))
    finally:
        mon.stop()
    ev = next(e for e in events if e.rule_id == "AEG-RANSOM-CANARY")
    assert ev.severity == Severity.CRITICAL and ev.category == Category.RANSOMWARE
    assert ev.evidence["action"] == "modified"


# --------------------------------------------------------------------------- ransomware: bursts

def test_classify_event_indicators():
    assert {"ransom-ext", "ext-appended"} <= set(M.classify_event("/d/a.docx.locked", "renamed", "/d/a.docx"))
    assert "random-ext" in M.classify_event("/d/a.docx.k3x9a2", "created")
    assert "ext-changed" in M.classify_event("/d/a.xyzzyq", "renamed", "/d/a.pdf")
    assert "ransom-note" in M.classify_event("/d/HOW_TO_DECRYPT_FILES.txt", "created")
    assert M.classify_event("/d/report.docx", "modified") == ()
    assert M.classify_event("/d/report.docx", "renamed", "/d/draft.docx") == ()
    assert M.classify_event("/d/README.md", "created") == ()


def test_sample_flags(tmp_path):
    bad_docx = tmp_path / "a.docx"
    bad_docx.write_bytes(os.urandom(4096))
    assert "bad-magic" in M.sample_flags(str(bad_docx))
    enc_txt = tmp_path / "b.txt"
    enc_txt.write_bytes(os.urandom(8192))
    assert "high-entropy" in M.sample_flags(str(enc_txt))
    ok_txt = tmp_path / "c.txt"
    ok_txt.write_text("hello world, this is an ordinary note. " * 50)
    assert M.sample_flags(str(ok_txt)) == ()
    good_pdf = tmp_path / "d.pdf"
    good_pdf.write_bytes(M.build_canary_bytes("pdf", "zz"))
    assert M.sample_flags(str(good_pdf)) == ()


def test_burst_detector_triggers_on_encrypting_rename():
    b = M.BurstDetector(window=10, threshold=30)
    t = 1000.0
    for i in range(40):
        new, old = f"/u/Documents/f{i}.docx.locked", f"/u/Documents/f{i}.docx"
        b.add(new, M.classify_event(new, "renamed", old), now=t + i * 0.1)
    info = b.check(now=t + 4)
    assert info and info.total == 40 and info.suspicious == 40
    assert "ransom-ext" in info.reasons
    assert b.check(now=t + 60) is None  # window slid past everything


def test_burst_detector_ignores_ordinary_bulk_changes():
    b = M.BurstDetector(window=10, threshold=30)
    t = 500.0
    for i in range(300):  # a build or git checkout touching hundreds of normal files
        b.add(f"/u/proj/src/f{i}.py", M.classify_event(f"/u/proj/src/f{i}.py", "modified"), now=t + i * 0.01)
    assert b.check(now=t + 3) is None


def test_burst_detector_counts_unique_files_and_notes():
    b = M.BurstDetector(window=10, threshold=30)
    t = 0.0
    for i in range(100):  # one huge file modified over and over is not a burst
        b.add("/u/big.vhd", (), now=t + i * 0.05)
    assert b.check(now=t + 5) is None
    # ransom note plus sizeable burst of suspicious files below the volume threshold
    for i in range(16):
        p = f"/u/d/f{i}.jpg.k3x9a2"
        b.add(p, M.classify_event(p, "created"), now=t + 6)
    b.add("/u/d/HOW_TO_DECRYPT.txt", M.classify_event("/u/d/HOW_TO_DECRYPT.txt", "created"), now=t + 6.5)
    info = b.check(now=t + 7)
    assert info and info.notes == 1


def test_ransomware_guard_burst_event(cfg, tmp_path):
    mon, events = make_monitor(cfg, components=(), canary_dirs=[])
    g = mon.ransomware
    for i in range(40):
        g.on_fs_event("renamed", f"/u/Documents/f{i}.docx.locked", f"/u/Documents/f{i}.docx")
    g.tick()
    burst = [e for e in events if e.rule_id == "AEG-RANSOM-BURST"]
    assert len(burst) == 1 and burst[0].severity == Severity.CRITICAL
    assert burst[0].evidence["files_changed"] == 40
    g.tick()  # detector was reset + cooldown: no duplicate
    assert len([e for e in events if e.rule_id == "AEG-RANSOM-BURST"]) == 1


def test_ransomware_burst_fires_right_after_boot(cfg, monkeypatch):
    """time.monotonic() counts from boot; the burst cooldown must not swallow the
    first burst on a freshly started machine (e.g. ransomware launched at logon)."""
    monkeypatch.setattr(M.time, "monotonic", lambda: 5.0)
    mon, events = make_monitor(cfg, components=(), canary_dirs=[])
    g = mon.ransomware
    for i in range(40):
        g.on_fs_event("renamed", f"/u/Documents/f{i}.docx.locked", f"/u/Documents/f{i}.docx")
    g.tick()
    assert [e.rule_id for e in events].count("AEG-RANSOM-BURST") == 1


def test_io_tracker_deltas_and_window():
    t = M.IOTracker()
    t.feed({1: 0, 2: 100}, now=0)
    t.feed({1: 5_000_000, 2: 150, 3: 10}, now=1)
    t.feed({1: 9_000_000, 2: 150, 3: 10}, now=2)
    tot = t.totals(window_s=10, now=3)
    assert tot[1] == 9_000_000 and tot[2] == 50 and 3 not in tot  # pid 3 first seen: no delta
    assert t.totals(window_s=1.5, now=3) == {1: 4_000_000}  # only the newest sample falls in the window


def test_protected_processes():
    assert M.is_protected_process(os.getpid(), "python", sys.executable)
    assert M.is_protected_process(4, "System", "")
    assert M.is_protected_process(4242, "lsass.exe", "/tmp/whatever/lsass.exe")
    assert M.is_protected_process(4242, "thing", "")  # unidentifiable -> never touch
    assert not M.is_protected_process(2**22 + 7, "evil.exe", "/tmp/xyz/evil.exe")


# --------------------------------------------------------------------------- process guard

def _info(tmp_path, **kw):
    d = {"pid": 2**22 + 11, "name": "evil.exe", "exe": str(tmp_path / "evil.exe"), "cmdline": ["evil.exe", "--evil"],
         "ppid": 1, "parent_name": "cmd.exe", "create_time": 1.0}
    d.update(kw)
    return d


def test_process_guard_evaluate_and_kill_switch(cfg, tmp_path, monkeypatch):
    mon, events = make_monitor(cfg, components=())

    def analyse(cmd):
        return [("AEG-PROC-EVIL", "Evil command line", Severity.CRITICAL, ["T1059"], "evil")] if "evil" in cmd else \
            [("AEG-PROC-LOW", "meh", Severity.LOW, [], "x")]

    pg = M.ProcessGuard(mon, analyse_fn=analyse, scan_fn=lambda ctx, p: [])
    info = _info(tmp_path)
    findings = pg.evaluate(info)
    assert [f.rule_id for f in findings] == ["AEG-PROC-EVIL"]
    assert findings[0].evidence["pid"] == info["pid"] and findings[0].remediation.action == "kill_process"
    assert pg.evaluate(_info(tmp_path, cmdline=["calc.exe"])) == []  # LOW is below the reporting bar

    assert not pg.should_kill(info, findings)  # kill switch is off by default
    cfg.realtime_kill_malicious_processes = True
    assert pg.should_kill(info, findings)
    assert not pg.should_kill(_info(tmp_path, name="lsass.exe"), findings)
    assert not pg.should_kill(_info(tmp_path, exe=""), findings)
    high_heur = [Finding("AEG-H-PACKED", "Packed", Severity.HIGH, Category.SUSPICIOUS)]
    assert not pg.should_kill(info, high_heur)  # HIGH from a heuristic is not enough
    high_sig = [Finding("AEG-SIG-HASH", "Known", Severity.HIGH, Category.MALWARE)]
    assert pg.should_kill(info, high_sig)

    calls = []
    import aegis.core.remediation as R

    monkeypatch.setattr(R, "apply_remediation", lambda f, c: calls.append(f.remediation) or (True, "terminated"))
    pg.handle(info)
    assert calls and calls[0].action == "kill_process" and calls[0].params["pid"] == info["pid"]
    assert events and events[0].title.startswith("Blocked:")


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="uses sh double-fork")
def test_process_guard_sees_new_process(cfg, tmp_path):
    mon, _ = make_monitor(cfg, components=())
    pg = M.ProcessGuard(mon)
    seen = []
    pg.handle = lambda info: seen.append(info) or []  # type: ignore[assignment]
    pg.seed()
    found = False
    for _ in range(3):  # retry: other processes on a busy CI box may race with us
        # orphaned grandchild so it is not our own child (those are deliberately skipped)
        subprocess.run(["sh", "-c", "sleep 6 >/dev/null 2>&1 &"], check=True)
        found = wait_for(lambda: (pg.poll_once() or True) and any(i["name"] == "sleep" for i in seen), 3)
        if found:
            break
    assert found
    assert next(i for i in seen if i["name"] == "sleep")["cmdline"][0] == "sleep"


def test_process_guard_rereads_empty_cmdline(cfg, monkeypatch):
    """A process sampled mid-exec can report an empty cmdline; it must be re-read
    on a later poll rather than evaluated once without command-line analysis."""
    import psutil

    mon, _ = make_monitor(cfg, components=())
    pg = M.ProcessGuard(mon)
    seen = []
    pg.handle = lambda info: seen.append(info) or []  # type: ignore[assignment]
    pg.seed()
    fake_pid = 2**22 + 99
    reads = {"n": 0}

    def fake_info(pid):
        if pid != fake_pid:
            return None
        reads["n"] += 1
        cmd = [] if reads["n"] == 1 else ["evil.exe", "-enc", "AAAA"]
        return {"pid": pid, "create_time": 1.0, "name": "evil.exe", "ppid": 1, "exe": "/tmp/evil.exe",
                "cmdline": cmd, "username": "u", "parent_name": "", "parent_exe": "", "parent_cmdline": ""}

    monkeypatch.setattr(pg, "_info", fake_info)
    monkeypatch.setattr(psutil, "pids", lambda: [fake_pid])
    pg.poll_once()
    assert seen == []  # empty cmdline: deferred
    pg.poll_once()
    assert len(seen) == 1 and seen[0]["cmdline"] == ["evil.exe", "-enc", "AAAA"]
    pg.poll_once()
    assert len(seen) == 1  # evaluated exactly once


# --------------------------------------------------------------------------- persistence guard

def test_persistence_guard_diff_and_hosts(cfg, tmp_path):
    mon, events = make_monitor(cfg, components=())
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n")
    entries = [{"name": "OneDrive", "location": r"HKCU\Run", "command": r"C:\OD\OneDrive.exe"}]
    g = M.PersistenceGuard(mon, collect_fn=lambda: list(entries), hosts_path=hosts)
    assert g.tick() == []  # baseline
    assert g.tick() == []  # nothing changed

    entries.append({"name": "Updater", "location": r"HKCU\Run", "command": "powershell -enc AAAA"})
    new = g.tick()
    assert len(new) == 1 and new[0].rule_id == "AEG-RT-AUTORUN"
    assert new[0].severity >= Severity.MEDIUM and new[0].category == Category.PERSISTENCE
    assert new[0].evidence["name"] == "Updater"
    assert g.tick() == []  # reported once

    hosts.write_text("127.0.0.1 localhost\n6.6.6.6 www.mybank.example\n")
    ch = g.tick()
    assert len(ch) == 1 and ch[0].rule_id == "AEG-RT-HOSTS"
    assert ch[0].remediation.action == "restore_hosts"
    assert ch[0].remediation.params["remove_lines"] == ["6.6.6.6 www.mybank.example"]
    assert ch[0].severity >= Severity.MEDIUM
    assert {e.rule_id for e in events} == {"AEG-RT-AUTORUN", "AEG-RT-HOSTS"}


def test_persistence_guard_object_entries_and_missing_collector(cfg, tmp_path):
    mon, _ = make_monitor(cfg, components=())
    e1 = SimpleNamespace(kind="run-key", name="A", location="HKLM\\Run", command="a.exe")
    pool = [e1]
    g = M.PersistenceGuard(mon, collect_fn=lambda: pool, hosts_path=tmp_path / "nohosts")
    g.tick()
    pool.append(SimpleNamespace(kind="task", name="B", location="\\Tasks\\B", command="b.exe",
                                remediation=Remediation("disable_task", {"name": "B"})))
    out = g.tick()
    assert len(out) == 1 and out[0].remediation.action == "disable_task"

    def boom():
        raise RuntimeError("collector broke")

    g2 = M.PersistenceGuard(mon, collect_fn=boom, hosts_path=tmp_path / "nohosts")
    assert g2.tick() == []  # failures are swallowed


def test_persistence_guard_with_scanner_entry_format(cfg, tmp_path):
    """Entries in the persistence scanner's own dict format (remediation lives in meta)."""
    from aegis.scanners.persistence import make_entry

    mon, _ = make_monitor(cfg, components=())
    rem = {"action": "delete_registry_value", "description": "Delete the autorun value 'Evil'",
           "params": {"hive": "HKCU", "key": r"Software\Microsoft\Windows\CurrentVersion\Run", "value": "Evil", "view64": True}}
    pool = []
    g = M.PersistenceGuard(mon, collect_fn=lambda: list(pool), hosts_path=tmp_path / "nohosts")
    assert g.tick() == []
    pool.append(make_entry("registry_run", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "Evil",
                           r"C:\Users\x\AppData\Local\Temp\evil.exe", remediation=rem))
    out = g.tick()
    assert len(out) == 1 and out[0].remediation.action == "delete_registry_value"
    assert out[0].remediation.params["value"] == "Evil"
    assert out[0].evidence["kind"] == "registry_run" and out[0].evidence["name"] == "Evil"


# --------------------------------------------------------------------------- notifications

def test_notify_rate_limiting(monkeypatch):
    sent = []
    monkeypatch.setattr(N, "_deliver", lambda t, m, s: sent.append((t, m, s)) or True)
    monkeypatch.setattr(N, "ASYNC", False)
    now = [100.0]
    monkeypatch.setattr(N, "_clock", lambda: now[0])
    N.reset_rate_limit()
    assert N.notify("Threat", "one", "high") is True
    assert N.notify("Threat", "two", "high") is False  # same title inside 5s
    assert N.notify("Other", "three", Severity.MEDIUM) is True  # different title is independent
    now[0] += N.RATE_LIMIT_S + 0.1
    assert N.notify("Threat", "four", "critical") is True
    assert [s[1] for s in sent] == ["one", "three", "four"]
    assert sent[1][2] == "medium"  # Severity enum normalised
    N.reset_rate_limit()


def test_notify_linux_uses_notify_send(monkeypatch):
    calls = []
    monkeypatch.setattr(N, "IS_WINDOWS", False)
    monkeypatch.setattr(N, "IS_MAC", False)
    monkeypatch.setattr(N, "IS_LINUX", True)
    monkeypatch.setattr(N.shutil, "which", lambda n: "/usr/bin/notify-send")
    monkeypatch.setattr(N, "run", lambda cmd, timeout=60, **k: calls.append(cmd) or (0, "", ""))
    assert N._deliver("Title", "Body", "critical")
    assert calls[0][0] == "/usr/bin/notify-send" and "critical" in calls[0] and calls[0][-2:] == ["Title", "Body"]


def test_notify_windows_toast_script(monkeypatch):
    xml = N.build_toast_xml("A & <B> 'q'", "path\\to\\file", "critical")
    root = ET.fromstring(xml)  # must be well-formed despite hostile text
    texts = [t.text for t in root.iter("text")]
    assert texts == ["A & <B> 'q'", "path\\to\\file"]
    assert root.get("scenario") == "reminder"
    script = N.build_toast_script("it's", "msg", "info")
    assert N.TOAST_APP_ID in script and "it''s" not in script.replace("&apos;", "") or "&apos;" in script
    calls = []
    monkeypatch.setattr(N, "IS_WINDOWS", True)
    monkeypatch.setattr(N, "run", lambda cmd, timeout=60, **k: calls.append(cmd) or (0, "", ""))
    assert N._deliver("T", "M", "high")
    assert "-EncodedCommand" in calls[0]


# --------------------------------------------------------------------------- monitor lifecycle

def test_monitor_start_stop_idempotent(cfg, tmp_path):
    watch = tmp_path / "w"
    watch.mkdir()
    mon, _ = make_monitor(cfg, components=("files", "persistence"), watch_specs=[(watch, True)], backend="poll",
                          poll_interval=0.1)
    mon.persistence.hosts_path = tmp_path / "nohosts"
    mon.persistence.collect_fn = lambda: []
    assert not mon.running
    mon.start()
    mon.start()  # second start is a no-op
    assert mon.running
    st = mon.status()
    assert st["running"] and str(watch) in st["watched"]
    mon.stop()
    mon.stop()
    assert not mon.running


def test_run_forever_stops_from_other_thread(cfg, tmp_path):
    mon, _ = make_monitor(cfg, components=(), watch_specs=[])
    t = threading.Thread(target=mon.run_forever, daemon=True)
    t.start()
    assert wait_for(lambda: mon.running)
    mon.stop()
    t.join(3)
    assert not t.is_alive()


def test_default_watch_specs_exist_on_this_os():
    specs = M.default_watch_specs()
    assert all(isinstance(p, Path) and p.is_dir() for p, _ in specs)


# --------------------------------------------------------------------------- GUI (mock toolkit)

def test_gui_module_imports_without_tkinter():
    import aegis.ui.gui as gui

    assert callable(gui.launch_gui)
    assert gui.fmt_time("2025-01-02T03:04:05").startswith("02 Jan 2025")
    assert gui.human_size(1536) == "1.5 KB"


def test_gui_builds_all_pages_with_mock_toolkit(cfg):
    from aegis.ui import gui

    tk, ttk, fd, mb, root = (MagicMock() for _ in range(5))
    app = gui.GuiApp(tk, ttk, fd, mb, root, config=cfg)
    assert set(app.pages) == {"dashboard", "scan", "protection", "quarantine", "tools", "settings"}
    for key in app.pages:
        app.show(key)
        assert app.current == key
    root.title.assert_called_with("Aegis Security Suite")
    root.minsize.assert_called_with(1100, 700)
    # posted callbacks run on the "UI thread" via the bridge
    seen = []
    app.ui.post(seen.append, 1)
    assert app.ui.drain() >= 1 and seen == [1]
    # live findings reach the results table once, de-duplicated
    f = Finding("AEG-T", "Test", Severity.HIGH, Category.MALWARE, location="/x")
    scan = app.pages["scan"]
    scan.add_finding(f)
    scan.add_finding(f)
    assert list(scan.findings) == [f.fingerprint]
    prot = app.pages["protection"]
    prot.add_event(f)
    app.pages["dashboard"].gauge.set(87, "B")
    assert app.pages["dashboard"].gauge.canvas.create_arc.called


def test_gui_save_config_keeps_env_secrets_off_disk(cfg, monkeypatch):
    from aegis.ui import gui

    monkeypatch.setenv("AEGIS_VT_API_KEY", "env-secret")
    cfg.virustotal_api_key = "env-secret"
    app = gui.GuiApp(*(MagicMock() for _ in range(5)), config=cfg)
    app.save_config()
    assert "env-secret" not in cfg.path.read_text(encoding="utf-8")
    assert cfg.virustotal_api_key == "env-secret"  # in-memory value restored
