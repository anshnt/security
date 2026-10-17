"""Tests for aegis.realtime.credcanary: planting realistic decoys only where no application lives, retiring a decoy a
real application moved in with, matching event 4663 paths, judging readers (Aegis itself, Defender, Windows Search,
processes that are gone, Windows binaries), the guard lifecycle with a fake event source, Aegis's scanners skipping the
decoys, the monitor wiring, a real inotify watch on Linux and, on Windows CI only, a real audited read named by event
4663."""

import base64
import collections
import json
import os
import sqlite3
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from aegis.core.models import Severity
from aegis.core.platform import IS_WINDOWS, system_binary_dirs, windows_dir
from aegis.realtime import credcanary as cc

EVENT_4663 = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>
<Provider Name="Microsoft-Windows-Security-Auditing" Guid="{{54849625-5478-4994-a5ba-3e3b0328c30d}}"/>
<EventID>{id}</EventID><TimeCreated SystemTime="2026-10-17T08:15:02.1234567Z"/><EventRecordID>91822</EventRecordID>
<Channel>Security</Channel><Computer>PC</Computer></System><EventData>
<Data Name="SubjectUserSid">S-1-5-21-1-2-3-1001</Data><Data Name="SubjectUserName">alice</Data>
<Data Name="SubjectDomainName">PC</Data><Data Name="SubjectLogonId">0x2c7f1</Data>
<Data Name="ObjectServer">Security</Data><Data Name="ObjectType">File</Data><Data Name="ObjectName">{path}</Data>
<Data Name="HandleId">0x4d8</Data><Data Name="AccessList">%%4416</Data><Data Name="AccessMask">{mask}</Data>
<Data Name="ProcessId">0x1a2c</Data><Data Name="ProcessName">C:\\Users\\alice\\AppData\\Local\\Temp\\upd.exe</Data>
<Data Name="ResourceAttributes"></Data></EventData></Event>"""


def spots(home: Path):
    return [cc.Spot("browser", "Kometa browser profile", str(home / "Kometa"), cc._CHROMIUM_WIN),
            cc.Spot("browser", "Chromium browser profile", str(home / "Chromium"), cc._CHROMIUM_WIN),
            cc.Spot("wallet", "Electrum wallet", str(home / "Electrum"), ("wallets/default_wallet",))]


def decoyset(tmp_path):
    return cc.DecoySet(tmp_path / "state.json", lambda: spots(tmp_path / "home"))


class FakeMonitor:
    def __init__(self, tmp_path=None, enabled=True):
        self.config = SimpleNamespace(realtime_credential_canary=enabled, home=tmp_path)
        self.stats = collections.Counter()
        self.emitted = []
        self.threads = []

    def emit(self, finding, source=""):
        self.emitted.append((source, finding))
        return True

    def spawn(self, name, target):
        t = threading.Thread(target=target, name=name, daemon=True)
        t.start()
        self.threads.append(t)
        return t


class FakeSource:
    def __init__(self, fail=False):
        self.prepared = []
        self.fail = fail
        self.on_access = None
        self.ready = threading.Event()

    def prepare(self, paths):
        if self.fail:
            raise OSError("could not put an audit entry on 1 decoy file(s)")
        self.prepared = list(paths)

    def run(self, stop, on_access):
        self.on_access = on_access
        self.ready.set()
        stop.wait()


def guard_with_decoys(tmp_path, monkeypatch, running="upd.exe"):
    ds = decoyset(tmp_path)
    ds.deploy()
    mon = FakeMonitor(tmp_path)
    monkeypatch.setattr(cc, "running_name", lambda pid, exe: running)
    return cc.CredentialCanaryGuard(mon, FakeSource(), ds), mon, ds


# =========================================================================== decoys
def test_deploy_plants_realistic_decoys_once(tmp_path):
    ds = decoyset(tmp_path)
    files = ds.deploy()
    assert [os.path.relpath(p, tmp_path / "home") for p in files] == [
        os.path.join("Kometa", "User Data", "Local State"), os.path.join("Kometa", "User Data", "Default", "Login Data"),
        os.path.join("Kometa", "User Data", "Default", "Network", "Cookies"),
        os.path.join("Electrum", "wallets", "default_wallet")]
    local_state, login, cookies, wallet = files
    key = json.loads(Path(local_state).read_text())["os_crypt"]["encrypted_key"]
    assert base64.b64decode(key).startswith(b"DPAPI")
    con = sqlite3.connect(login)
    (user, pw), = con.execute("SELECT username_value, password_value FROM logins").fetchall()
    con.close()
    assert user.endswith("@example.com") and pw.startswith(b"v10")  # reserved domain: never a real person's account
    con = sqlite3.connect(cookies)
    assert con.execute("SELECT host_key FROM cookies").fetchall() == [(".example.com",)]
    con.close()
    assert base64.b64decode(Path(wallet).read_bytes()).startswith(b"BIE1")  # Electrum's encrypted-wallet format
    assert not (tmp_path / "home" / "Chromium").exists()  # one browser and one wallet decoy

    stamps = {p: os.stat(p).st_mtime_ns for p in files}
    again = cc.DecoySet(tmp_path / "state.json", lambda: spots(tmp_path / "home"))  # state survives a restart
    assert again.spots == ds.spots and again.deploy() == files
    assert {p: os.stat(p).st_mtime_ns for p in files} == stamps  # nothing rewritten


def test_an_existing_application_folder_is_never_used(tmp_path):
    real = tmp_path / "home" / "Kometa"
    (real / "User Data").mkdir(parents=True)  # a real Kometa install
    files = decoyset(tmp_path).deploy()
    assert any("Chromium" in p for p in files) and not any("Kometa" in p for p in files)
    assert os.listdir(real / "User Data") == []


def test_a_decoy_is_retired_when_a_real_application_moves_in(tmp_path):
    ds = decoyset(tmp_path)
    ds.deploy()
    app = tmp_path / "home" / "Kometa" / "Application"
    app.mkdir()
    (app / "kometa.exe").write_bytes(b"MZ")
    assert cc.foreign_entries(ds.spots[0]) == [os.path.normcase("Application"),
                                                os.path.normcase(os.path.join("Application", "kometa.exe"))]
    files = ds.deploy()
    assert not (tmp_path / "home" / "Kometa" / "User Data").exists() and (app / "kometa.exe").exists()
    assert any("Chromium" in p for p in files)


def test_missing_decoys_are_recreated(tmp_path):
    ds = decoyset(tmp_path)
    local_state, login, _cookies, wallet = ds.deploy()
    os.remove(login)
    os.remove(wallet)
    os.rmdir(os.path.dirname(wallet))
    os.rmdir(os.path.dirname(os.path.dirname(wallet)))  # the user deleted the whole Electrum folder
    files = ds.deploy()
    assert all(os.path.exists(p) for p in files) and login in files and wallet in files


def test_remove_deletes_only_what_aegis_created(tmp_path):
    ds = decoyset(tmp_path)
    ds.deploy()
    other = tmp_path / "home" / "Electrum" / "wallets" / "my_wallet"
    other.write_text("not ours")
    assert ds.remove() == 4
    assert not (tmp_path / "home" / "Kometa").exists() and other.exists()
    assert os.listdir(tmp_path / "home" / "Electrum" / "wallets") == ["my_wallet"]
    assert cc.DecoySet(tmp_path / "state.json").spots == []


def test_lookup_matches_the_paths_event_4663_reports(tmp_path):
    ds = decoyset(tmp_path)
    login = ds.deploy()[1]
    assert ds.lookup(login).kind == "browser" and ds.lookup(str(tmp_path / "elsewhere")) is None
    if IS_WINDOWS:
        assert ds.lookup(login.upper()).kind == "browser"
        assert ds.lookup("\\Device\\HarddiskVolume3" + login[2:]).kind == "browser"


def test_candidate_spots_per_platform(tmp_path):
    found = cc.candidate_spots(home=tmp_path)
    if IS_WINDOWS:
        assert [os.path.relpath(s.root, tmp_path) for s in found] == [
            os.path.join("AppData", "Local", "Kometa"), os.path.join("AppData", "Local", "Chromium"),
            os.path.join("AppData", "Roaming", "Electrum"), os.path.join("AppData", "Roaming", "Ethereum")]
    elif sys.platform.startswith("linux"):
        assert [os.path.relpath(s.root, tmp_path) for s in found] == [os.path.join(".config", "chromium"), ".electrum",
                                                                        ".ethereum"]
    else:
        assert found == []  # no reliable user-mode read signal: nothing is planted
    keystore = next((s for s in found if s.label == "Ethereum keystore"), None)
    if keystore:
        name = keystore.files[0].split("/")[-1]
        assert name.startswith("UTC--") and len(name.rsplit("--", 1)[-1]) == 40
        assert json.loads(cc._decoy_bytes(name))["address"] == name.rsplit("--", 1)[-1]


# =========================================================================== events and readers
def test_event_4663_names_path_process_and_user():
    a = cc.access_from_event_xml(EVENT_4663.format(id=4663, path="C:\\x\\Login Data", mask="0x1"))
    assert a == cc.Access("C:\\x\\Login Data", 0x1A2C, "C:\\Users\\alice\\AppData\\Local\\Temp\\upd.exe", "PC\\alice")
    assert cc.access_from_event_xml(EVENT_4663.format(id=4663, path="C:\\x", mask="0x2")) is None  # a write
    assert cc.access_from_event_xml(EVENT_4663.format(id=4656, path="C:\\x", mask="0x1")) is None
    assert cc.access_from_event_xml("not xml") is None


def test_parse_inotify_reads_every_event_in_the_buffer():
    buf = struct.pack("=iIII", 3, 0x20, 0, 0) + struct.pack("=iIII", 4, 0x20, 0, 16) + b"name".ljust(16, b"\0")
    buf += struct.pack("=iIII", 3, 0x8000, 0, 0)
    assert cc.parse_inotify(buf) == [(3, 0x20), (4, 0x20), (3, 0x8000)]


@pytest.mark.skipif(not IS_WINDOWS, reason="Windows image paths")
def test_defender_and_windows_search_are_trusted_by_folder_not_by_name(monkeypatch, tmp_path):
    monkeypatch.setenv("ProgramData", r"C:\ProgramData")
    monkeypatch.setenv("ProgramFiles", r"C:\Program Files")
    assert cc.trusted_reader(r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe")
    assert cc.trusted_reader(str(windows_dir() / "System32" / "SearchProtocolHost.exe"))
    assert not cc.trusted_reader(str(tmp_path / "MsMpEng.exe")) and not cc.trusted_reader("")
    assert not cc.trusted_reader(str(windows_dir() / "System32" / "rundll32.exe"))


def test_a_decoy_read_by_another_program_is_high_with_kill_and_quarantine(tmp_path, monkeypatch):
    guard, mon, ds = guard_with_decoys(tmp_path, monkeypatch)
    exe = str(tmp_path / "Temp" / "upd.exe")
    f = guard.on_access(cc.Access(ds.spots[0].paths()[1], 4242, exe, "PC\\alice"))
    assert f is not None and mon.emitted == [("credential-canary", f)] and mon.stats["credential_canary_alerts"] == 1
    assert f.rule_id == "AEG-RT-CREDCANARY" and f.severity == Severity.HIGH and f.location == exe
    assert f.title == "Infostealer: upd.exe read a decoy Kometa browser profile"
    assert "'Login Data'" in f.description and "upd.exe (pid 4242" in f.description and "sign out" in f.recommendation
    assert f.remediation.action == "kill_process" and f.remediation.params == {"pid": 4242, "path": exe, "quarantine": True}
    assert f.mitre == ["T1555.003", "T1539"]
    assert f.evidence["decoy_kind"] == "browser" and f.evidence["user"] == "PC\\alice" and f.evidence["still_running"]
    wallet = guard.on_access(cc.Access(ds.spots[1].paths()[0], 4242, exe))
    assert wallet.mitre == ["T1005"] and "crypto wallets" in wallet.description


def test_aegis_itself_other_files_and_a_switched_off_guard_are_ignored(tmp_path, monkeypatch):
    guard, mon, ds = guard_with_decoys(tmp_path, monkeypatch)
    login = ds.spots[0].paths()[1]
    assert guard.on_access(cc.Access(login, os.getpid(), sys.executable)) is None
    assert guard.on_access(cc.Access(str(tmp_path / "notes.txt"), 4242, "x.exe")) is None
    monkeypatch.setattr(cc, "trusted_reader", lambda exe: exe == "defender.exe")
    assert guard.on_access(cc.Access(login, 4242, "defender.exe")) is None
    mon.config.realtime_credential_canary = False
    assert guard.on_access(cc.Access(login, 4242, "x.exe")) is None
    assert mon.emitted == []


def test_the_offered_fix_depends_on_what_read_the_decoy(tmp_path):
    spot = spots(tmp_path)[0]
    path = spot.paths()[1]
    gone = tmp_path / "gone.exe"
    gone.write_bytes(b"MZ")
    f = cc.access_finding(cc.Access(path, 4242, str(gone)), spot, None)  # exited: its file can still be quarantined
    assert f.remediation.action == "quarantine_file" and f.remediation.params == {"path": str(gone)}
    assert f.title == "Infostealer: gone.exe read a decoy Kometa browser profile" and not f.evidence["still_running"]
    assert cc.access_finding(cc.Access(path, 4242, str(tmp_path / "deleted.exe")), spot, None).remediation is None
    hollowed = str(Path(system_binary_dirs()[0]) / "AppLaunch.exe")  # a Windows binary a stealer was injected into
    f = cc.access_finding(cc.Access(path, 4242, hollowed), spot, "AppLaunch.exe")
    assert f.remediation.action == "kill_process" and f.remediation.params["quarantine"] is False
    assert cc.access_finding(cc.Access(path, 4242, "C:\\Windows\\explorer.exe"), spot, "explorer.exe").remediation is None
    linux = cc.access_finding(cc.Access(path), spot, None)  # inotify: nobody named
    assert linux.remediation is None and linux.location == spot.root and "Linux does not tell" in linux.description
    assert linux.title == "Infostealer: a decoy Kometa browser profile was opened"


def test_a_real_application_opening_its_new_folder_retires_the_decoy(tmp_path, monkeypatch):
    guard, mon, ds = guard_with_decoys(tmp_path, monkeypatch)
    (tmp_path / "home" / "Electrum" / "config").write_text("{}")  # Electrum was just installed and started
    wallet = ds.spots[1].paths()[0]
    assert guard.on_access(cc.Access(wallet, 4242, "electrum.exe")) is None and mon.emitted == []
    assert not os.path.exists(wallet) and [s.kind for s in cc.DecoySet(tmp_path / "state.json").spots] == ["browser"]


# =========================================================================== guard lifecycle
def test_guard_start_plants_prepares_and_follows_the_source(tmp_path, monkeypatch):
    monkeypatch.setattr(cc, "running_name", lambda pid, exe: "upd.exe")
    mon, src, ds = FakeMonitor(tmp_path), FakeSource(), decoyset(tmp_path)
    guard = cc.CredentialCanaryGuard(mon, src, ds)
    stop = threading.Event()
    try:
        assert len(guard.start(stop)) == 1 and src.ready.wait(3)
        assert src.prepared == [p for s in ds.spots for p in s.paths()] and guard.state == "watching 4 decoy files"
        src.on_access(cc.Access(src.prepared[1], 4242, "upd.exe"))
        src.on_access(cc.Access(str(tmp_path / "notes.txt"), 1, "x"))  # not a decoy
        assert [f.rule_id for _, f in mon.emitted] == ["AEG-RT-CREDCANARY"]
    finally:
        stop.set()
        for t in mon.threads:
            t.join(3)
    assert guard.remove() == 4 and not any(os.path.exists(p) for p in src.prepared)


def test_guard_does_not_start_when_off_unsupported_or_unprotectable(tmp_path, monkeypatch):
    stop = threading.Event()
    off = cc.CredentialCanaryGuard(FakeMonitor(tmp_path, enabled=False), FakeSource(), decoyset(tmp_path))
    assert off.start(stop) == [] and off.state == "off"
    monkeypatch.setattr(cc, "unavailable_reason", lambda: "needs administrator rights")
    plain = cc.CredentialCanaryGuard(FakeMonitor(tmp_path), None, decoyset(tmp_path))
    assert plain.start(stop) == [] and plain.state == "not running: needs administrator rights"
    assert not (tmp_path / "home").exists()  # nothing planted when nothing could watch it
    broken = cc.CredentialCanaryGuard(FakeMonitor(tmp_path), FakeSource(fail=True), decoyset(tmp_path))
    assert broken.start(stop) == [] and broken.state.startswith("not running: could not put an audit entry")


def test_state_reports_reads_the_source_cannot_see(tmp_path):
    src = FakeSource()
    guard = cc.CredentialCanaryGuard(FakeMonitor(tmp_path), src, decoyset(tmp_path))
    guard.state = "watching 4 decoy files"
    assert guard.state == "watching 4 decoy files"
    src.problem = "Windows does not log file reads"
    assert guard.state == "watching 4 decoy files, but Windows does not log file reads"
    guard.state = "not running: needs administrator rights"
    assert guard.state == "not running: needs administrator rights"  # the problem only qualifies a running guard


def test_unavailable_reason_per_platform(monkeypatch):
    monkeypatch.setattr(cc, "IS_WINDOWS", True)
    assert "administrator" in cc.unavailable_reason(admin=False) and cc.unavailable_reason(admin=True) is None
    monkeypatch.setattr(cc, "IS_WINDOWS", False)
    monkeypatch.setattr(cc, "IS_LINUX", True)
    assert cc.unavailable_reason() is None
    monkeypatch.setattr(cc, "IS_LINUX", False)
    assert "Endpoint Security" in cc.unavailable_reason()


# =========================================================================== Aegis's scanners skip the decoys
def register(home: Path, *roots):
    (home / cc.STATE_NAME).write_text(json.dumps({"spots": [
        {"kind": "browser", "label": "x", "root": str(r), "files": ["Local State"]} for r in roots]}))


def test_scanners_skip_the_decoy_folders(tmp_path, aegis_home, monkeypatch):
    from aegis.core.config import Config
    from aegis.scanners import browser, files, secrets
    from aegis.scanners.base import ScanContext

    monkeypatch.delenv("ProgramData", raising=False)
    decoy, real = tmp_path / "scan" / "Kometa", tmp_path / "scan" / "Documents"
    for d in (decoy, real):
        d.mkdir(parents=True)
        (d / "file.txt").write_text("x")
    home = tmp_path / "user"
    chromium = home / ".config" / "chromium"
    if IS_WINDOWS:
        monkeypatch.setenv("APPDATA", str(tmp_path / "roaming"))
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
        electrum = tmp_path / "roaming" / "Electrum"
    else:
        electrum = home / ".electrum"
    (electrum / "wallets").mkdir(parents=True)
    (electrum / "wallets" / "default_wallet").write_text("x")
    ctx = ScanContext(config=Config.load(), signatures=None)
    assert len(list(files.iter_files([tmp_path / "scan"], ctx))) == 2
    assert chromium in [r.base for r in browser.chromium_browser_roots("linux", home=home, env={})]
    assert secrets.known_wallet_locations(home) == [electrum / "wallets" / "default_wallet"]

    register(aegis_home, decoy, chromium, electrum)
    assert cc.decoy_roots() == [str(decoy), str(chromium), str(electrum)] and cc.is_decoy(decoy / "file.txt")
    assert list(files.iter_files([tmp_path / "scan"], ctx)) == [real / "file.txt"]
    assert chromium not in [r.base for r in browser.chromium_browser_roots("linux", home=home, env={})]
    assert secrets.known_wallet_locations(home) == []


@pytest.mark.skipif(not IS_WINDOWS, reason="the elevated monitor's state lives in %ProgramData%\\Aegis on Windows")
def test_decoys_of_the_elevated_monitor_are_seen_by_a_user_mode_scan(tmp_path, monkeypatch):
    pd = tmp_path / "ProgramData"
    (pd / "Aegis").mkdir(parents=True)
    monkeypatch.setenv("ProgramData", str(pd))
    register(pd / "Aegis", tmp_path / "Kometa")
    assert cc.decoy_roots() == [str(tmp_path / "Kometa")]


# =========================================================================== monitor wiring
def test_the_monitor_runs_the_credential_canary(tmp_path, monkeypatch):
    from aegis.core.config import Config
    from aegis.realtime import monitor as M

    assert "credential_canary" in M.ALL_COMPONENTS and Config().realtime_credential_canary is True
    cfg = Config()
    cfg.notifications = False
    mon = M.RealtimeMonitor(cfg, SimpleNamespace(), components=("credential_canary",))
    src = FakeSource()
    mon.credentials.source, mon.credentials.decoys = src, decoyset(tmp_path)
    mon.start()
    try:
        assert src.ready.wait(3) and mon.status()["credential_canary"] == "watching 4 decoy files"
        from aegis.core.doctor import read_heartbeat

        deadline = time.monotonic() + 3
        while not (read_heartbeat(cfg) or {}).get("guards") and time.monotonic() < deadline:
            time.sleep(0.05)
        assert read_heartbeat(cfg)["guards"] == {"credential_canary": "watching 4 decoy files"}  # for aegis doctor
    finally:
        mon.stop(timeout=3.0)
    assert mon.remove_canaries() == 4 and not any(os.path.exists(p) for p in src.prepared)


# =========================================================================== real platform tests
@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="inotify is Linux only")
def test_real_inotify_reports_opens_but_not_stat(tmp_path):
    p = tmp_path / "Login Data"
    p.write_bytes(b"decoy")
    src = cc.InotifySource()
    src.prepare([str(p)])
    got, stop = [], threading.Event()
    t = threading.Thread(target=src.run, args=(stop, got.append), daemon=True)
    t.start()
    try:
        os.stat(p)
        time.sleep(0.5)
        assert got == []
        p.read_bytes()
        deadline = time.monotonic() + 5
        while not got and time.monotonic() < deadline:
            time.sleep(0.05)
        assert got and got[0] == cc.Access(str(p))
    finally:
        stop.set()
        t.join(3)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows event log")
def test_real_event_subscription_keeps_delivering_after_quiet_spells():
    """The Security log needs admin; the Application log does not, and the pull subscription is the same. EvtNext called
    again after a drain fails with ERROR_INVALID_OPERATION, which once ended the subscription before any event came."""
    got, stop = [], threading.Event()
    query = "*[System[Provider[@Name='Windows Error Reporting'] and (EventID=999)]]"
    t = threading.Thread(target=cc.follow_events, args=("Application", query, stop, got.append), daemon=True)
    t.start()
    try:
        time.sleep(3.5)  # several empty wake-ups first
        assert t.is_alive()
        subprocess.run(["powershell", "-NoProfile", "-Command", "Write-EventLog -LogName Application -Source "
                        "'Windows Error Reporting' -EventId 999 -Message 'Aegis test event'"], check=True, timeout=60)
        deadline = time.monotonic() + 10
        while not got and time.monotonic() < deadline:
            time.sleep(0.1)
        assert got and "<EventID" in got[0] and "999" in got[0]
    finally:
        stop.set()
        t.join(3)


@pytest.mark.skipif(sys.platform != "win32" or not os.environ.get("CI"),
                    reason="turns on file-system auditing and reads the Security log; Windows CI only")
def test_real_windows_audit_names_the_process_that_read_a_decoy(tmp_path):
    from aegis.core.platform import is_admin
    from aegis.protect import harden

    if not is_admin():
        pytest.skip("needs administrator rights")
    before = harden._auditpol_get(harden.FILE_SYSTEM_GUID)
    assert before is not None
    assert harden._auditpol_set(harden.FILE_SYSTEM_GUID, before | 1)[0]
    tmp_path = tmp_path.resolve()  # runners set TEMP with an 8.3 short name (RUNNER~1); %LOCALAPPDATA% is the long form
    mon, ds = FakeMonitor(tmp_path), decoyset(tmp_path)
    guard = cc.CredentialCanaryGuard(mon, cc.WindowsAuditSource(), ds)
    stop = threading.Event()
    try:
        assert guard.start(stop) and guard.state == "watching 4 decoy files"
        login = ds.spots[0].paths()[1]
        time.sleep(3)  # the subscription only sees events logged after it started
        with open(login, "rb") as fh:  # Aegis's own read: audited, but never an alert
            fh.read()
        child = subprocess.run([sys.executable, "-c", "import os, sys; os.stat(sys.argv[1]); "
                                "open(sys.argv[1], 'rb').read(); print(os.getpid())", login],
                               capture_output=True, text=True, check=True)
        pid = int(child.stdout)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not any(f.evidence["pid"] == pid for _, f in mon.emitted):
            time.sleep(0.2)
        hits = [f for _, f in mon.emitted if f.evidence["pid"] == pid]
        assert hits, f"no alert for pid {pid}; state {guard.state}; emitted {mon.emitted}"
        f = hits[0]
        assert f.rule_id == "AEG-RT-CREDCANARY" and f.severity == Severity.HIGH
        assert os.path.basename(f.evidence["exe"]).lower().startswith("python")
        assert os.path.normcase(f.evidence["decoy"]) == os.path.normcase(login)
        assert not any(f.evidence["pid"] == os.getpid() for _, f in mon.emitted)
    finally:
        stop.set()
        for t in mon.threads:
            t.join(5)
        guard.remove()
        harden._auditpol_set(harden.FILE_SYSTEM_GUID, before)
