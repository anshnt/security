"""Tests for aegis.protect.undo: every backup kind is produced by the REAL writers (core/remediation.py's
``_backup`` users, webguard's hosts backups, harden journals), listed, and undone. Windows-only kinds run against
the dict-backed fakes of tests/_protect_fakes.py, so this passes on Linux and Windows CI."""

import base64
import datetime as dt
import json
import zipfile
from pathlib import Path

import pytest

from aegis.core import remediation as rem
from aegis.core.config import Config
from aegis.core.models import Finding, Severity
from aegis.protect import harden, undo
from aegis.protect import webguard as wg
from tests._protect_fakes import FakeWindows

FINDING = Finding("AEG-TEST", "t", Severity.LOW, "system")
KEY = r"SOFTWARE\Policies\Aegis\Test"
TASK_XML = ('<?xml version="1.0" encoding="UTF-16"?>\r\n<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
            '<Settings><Enabled>true</Enabled></Settings></Task>')
SC_QC = (
    "[SC] QueryServiceConfig SUCCESS\n\nSERVICE_NAME: Spooler\n        TYPE               : 110  WIN32_OWN_PROCESS  (interactive)\n"
    "        START_TYPE         : {start}\n        ERROR_CONTROL      : 1   NORMAL\n"
    "        BINARY_PATH_NAME   : C:\\Windows\\System32\\spoolsv.exe\n        LOAD_ORDER_GROUP   : SpoolerGroup\n"
    "        TAG                : 0\n        DISPLAY_NAME       : Print Spooler\n        DEPENDENCIES       : RPCSS\n"
    "                           : http\n        SERVICE_START_NAME : LocalSystem\n")


@pytest.fixture
def cfg():
    return Config.load()


@pytest.fixture
def win(monkeypatch):
    w = FakeWindows().install(monkeypatch, undo_module=undo)
    # the remediation writers use the same fake registry, so their backups and undo see one world
    monkeypatch.setattr(rem, "reg_read", w.reg.read)
    monkeypatch.setattr(rem, "reg_set_value", w.reg.set_value)
    monkeypatch.setattr(rem, "reg_delete_value", w.reg.delete_value)
    # web-protection helpers: Linux-flavoured, admin, no real DNS flush
    monkeypatch.setattr(wg, "IS_WINDOWS", False)
    monkeypatch.setattr(wg, "IS_MAC", False)
    monkeypatch.setattr(wg, "is_admin", lambda: w.admin)
    monkeypatch.setattr(wg, "run", lambda *a, **k: (0, "", ""))
    monkeypatch.setattr(wg, "_which", lambda n: None)
    return w


def only(cfg, kind):
    found = [e for e in undo.list_backups(cfg) if e["kind"] == kind]
    assert len(found) == 1, found
    return found[0]


def last(cfg, kind):
    return next(e for e in undo.list_backups(cfg) if e["kind"] == kind)


def set_value(cfg, value, data, hive="HKLM"):
    return rem.set_registry_value(cfg, {"hive": hive, "key": KEY, "value": value, "data": data}, FINDING)


# =========================================================================== listing
def test_list_backups_covers_every_kind_and_ignores_noise(win, cfg, tmp_path, monkeypatch):
    set_value(cfg, "V", 1)
    rem.delete_registry_value(cfg, {"hive": "HKLM", "key": KEY, "value": "V"}, FINDING)
    monkeypatch.setattr(rem, "run", lambda argv, timeout=60, input_text=None:
                        (0, TASK_XML if argv[:2] == ["schtasks", "/Query"] else SC_QC.format(start="2   AUTO_START")
                         if argv[:2] == ["sc", "qc"] else "OK", ""))
    rem.disable_task(cfg, {"name": r"\Aegis\Test"}, FINDING)
    rem.disable_service(cfg, {"name": "Spooler"}, FINDING)
    p = tmp_path / "hosts"
    p.write_text("127.0.0.1 localhost\n10.0.0.1 evil.example\n", encoding="utf-8")
    rem.restore_hosts(cfg, {"path": str(p), "remove_lines": ["10.0.0.1 evil.example"]}, FINDING)
    folder = tmp_path / "ext"
    folder.mkdir()
    (folder / "a.js").write_text("x")
    rem.remove_path(cfg, {"path": str(folder)}, FINDING)
    monkeypatch.setattr(wg, "hosts_path", lambda: p)
    wg.enable_web_protection(cfg, type("S", (), {"bad_domains": {"bad.example"}})(), hosts_file=p)
    harden.apply(["windows.llmnr"], cfg, env=win.env())
    # noise that must never show up as a backup
    (cfg.backups_dir / "notes.txt").write_text("hi")
    (cfg.backups_dir / "registry-notastamp.json").write_text("{}")
    (cfg.backups_dir / undo.UNDO_LOG).write_text('{"entries": []}')
    (cfg.backups_dir / "registry-20250101-000000-000001.json").write_text("{not json")

    entries = undo.list_backups(cfg)
    kinds = {e["kind"] for e in entries}
    assert kinds == {"registry", "task", "service", "hosts", "removed", "webhosts", "harden"}
    assert not [e for e in entries if e["id"].startswith(("notes", "undo-log", "registry-notastamp"))]
    broken = next(e for e in entries if e["id"] == "registry-20250101-000000-000001")
    assert broken["undoable"] is False and "unreadable" in broken["summary"]
    good = [e for e in entries if e is not broken]
    assert all(e["undoable"] and e["summary"] and e["undone"] is None for e in good)
    for e in entries:
        assert set(e) >= {"id", "kind", "timestamp", "path", "size", "summary", "undoable", "undone"}
        dt.datetime.fromisoformat(e["timestamp"])
        assert Path(e["path"]).exists()
    stamps = [e["timestamp"] for e in entries]
    assert stamps == sorted(stamps, reverse=True)  # newest first
    regs = [e for e in entries if e["kind"] == "registry" and e is not broken]
    assert any("deleted" in e["summary"] for e in regs) and any("changed" in e["summary"] for e in regs)
    assert "Spooler" in only(cfg, "service")["summary"] and "auto" in only(cfg, "service")["summary"]
    assert r"\Aegis\Test" in only(cfg, "task")["summary"]
    assert "ext" in only(cfg, "removed")["summary"] and "1 file" in only(cfg, "removed")["summary"]
    assert "web protection" in only(cfg, "webhosts")["summary"] and "applied" in only(cfg, "harden")["summary"]
    assert [e["kind"] for e in undo.list_backups(cfg, kinds=["harden"])] == ["harden"]


def test_list_backups_empty_and_unreadable_dir(cfg):
    assert undo.list_backups(cfg) == []


# =========================================================================== registry
def test_undo_set_registry_value_that_did_not_exist_deletes_it(win, cfg):
    set_value(cfg, "V", 1)
    assert win.reg.get("HKLM", KEY, "V") == 1
    e = only(cfg, "registry")
    assert "previous value: absent" in e["summary"]
    r = undo.undo(cfg, e["id"])
    assert r["ok"] and r["changed"] and win.reg.get("HKLM", KEY, "V") is None
    assert r["details"]["backup_id"] == e["id"] and r["details"]["kind"] == "registry" and r["results"]


def test_undo_set_registry_value_restores_previous_data_and_type(win, cfg):
    win.reg.put("HKLM", KEY, "Num", 5)
    win.reg.put("HKLM", KEY, "Txt", "old text")
    set_value(cfg, "Num", 1)
    set_value(cfg, "Txt", "new text")
    for e in [x for x in undo.list_backups(cfg)]:
        assert undo.undo(cfg, e["id"])["ok"]
    assert win.reg.get("HKLM", KEY, "Num") == 5 and win.reg.get("HKLM", KEY, "Txt") == "old text"


def test_undo_delete_registry_value_puts_it_back(win, cfg):
    win.reg.put("HKLM", KEY, "Run", r"C:\evil.exe")
    win.reg.put("HKLM", KEY, "Multi", ["a", "b"])
    for v in ("Run", "Multi"):
        rem.delete_registry_value(cfg, {"hive": "HKLM", "key": KEY, "value": v}, FINDING)
        assert win.reg.get("HKLM", KEY, v) is None
    for e in undo.list_backups(cfg):
        assert "deleted" in e["summary"] and undo.undo(cfg, e["id"])["ok"]
    assert win.reg.get("HKLM", KEY, "Run") == r"C:\evil.exe" and win.reg.get("HKLM", KEY, "Multi") == ["a", "b"]


def test_undo_delete_of_a_value_that_never_existed_is_a_no_op(win, cfg):
    with pytest.raises(OSError):  # the remediation itself fails, but its backup was written first
        rem.delete_registry_value(cfg, {"hive": "HKLM", "key": KEY, "value": "Ghost"}, FINDING)
    r = undo.undo(cfg, only(cfg, "registry")["id"])
    assert r["ok"] and not r["changed"] and "did not exist" in r["message"]
    assert win.reg.get("HKLM", KEY, "Ghost") is None


def test_undo_refuses_binary_registry_data(win, cfg):
    (cfg.backups_dir / "registry-20260101-000000-000001.json").write_text(
        json.dumps({"hive": "HKLM", "key": KEY, "value": "Blob", "data": "b'\\x01\\x02'", "view64": True}))
    r = undo.undo(cfg, "registry-20260101-000000-000001")
    assert r["ok"] is False and "binary" in r["message"]


def test_registry_undo_privileges(win, cfg):
    win.reg.put("HKLM", KEY, "M", 5)
    win.reg.put("HKCU", KEY, "U", 5)
    set_value(cfg, "M", 1)
    set_value(cfg, "U", 1, hive="HKCU")
    win.admin = False
    hklm = next(e for e in undo.list_backups(cfg) if "HKLM" in e["summary"])
    hkcu = next(e for e in undo.list_backups(cfg) if "HKCU" in e["summary"])
    r = undo.undo(cfg, hklm["id"])
    assert r["ok"] is False and r["details"]["needs_admin"] and "Administrator rights are required" in r["message"]
    assert win.reg.get("HKLM", KEY, "M") == 1
    assert undo.undo(cfg, hklm["id"], dry_run=True)["ok"] and win.reg.get("HKLM", KEY, "M") == 1  # preview needs no rights
    assert undo.undo(cfg, hkcu["id"])["ok"] and win.reg.get("HKCU", KEY, "U") == 5  # HKCU never needs elevation


def test_registry_undo_failure_is_reported_and_not_marked_done(win, cfg):
    win.reg.put("HKLM", KEY, "V", 5)
    set_value(cfg, "V", 1)
    win.reg.fail_on = (KEY.lower(), "v")
    e = only(cfg, "registry")
    r = undo.undo(cfg, e["id"])
    assert r["ok"] is False and "could not restore" in r["message"]
    assert only(cfg, "registry")["undone"] is None
    win.reg.fail_on = None
    assert undo.undo(cfg, e["id"])["ok"]


# =========================================================================== scheduled task
class RunLog:
    def __init__(self, rc=0, out=""):
        self.calls, self.rc, self.out = [], rc, out
        self.xml_bytes = None

    def __call__(self, argv, timeout=60, input_text=None):
        argv = list(argv)
        self.calls.append(argv)
        if argv[:2] == ["schtasks", "/Create"]:
            self.xml_bytes = Path(argv[argv.index("/XML") + 1]).read_bytes()  # the file only exists during the call
        return self.rc, self.out, ""


def make_task_backup(cfg, monkeypatch, name=r"\Aegis\Test"):
    monkeypatch.setattr(rem, "run", lambda argv, timeout=60, input_text=None:
                        (0, TASK_XML if argv[:2] == ["schtasks", "/Query"] else "SUCCESS", ""))
    rem.disable_task(cfg, {"name": name}, FINDING)


def test_undo_task_recreates_it_from_the_saved_xml(win, cfg, monkeypatch):
    make_task_backup(cfg, monkeypatch)
    log = RunLog(out="SUCCESS: The scheduled task was successfully created.")
    monkeypatch.setattr(undo, "run", log)
    r = undo.undo(cfg, only(cfg, "task")["id"])
    assert r["ok"] and r["changed"]
    create = log.calls[0]
    assert create[:4] == ["schtasks", "/Create", "/TN", r"\Aegis\Test"] and create[-1] == "/F" and "/XML" in create
    assert log.xml_bytes[:2] in (b"\xff\xfe", b"\xfe\xff")  # UTF-16 with BOM, as schtasks exported it
    assert log.xml_bytes.decode("utf-16") == TASK_XML


def test_undo_task_failure_privileges_and_validation(win, cfg, monkeypatch):
    make_task_backup(cfg, monkeypatch)
    e = only(cfg, "task")
    monkeypatch.setattr(undo, "run", RunLog(rc=1, out="ERROR: Access is denied."))
    r = undo.undo(cfg, e["id"])
    assert r["ok"] is False and "Access is denied" in r["message"] and only(cfg, "task")["undone"] is None
    win.admin = False
    log = RunLog()
    monkeypatch.setattr(undo, "run", log)
    r = undo.undo(cfg, e["id"])
    assert r["ok"] is False and "Administrator rights are required" in r["message"] and not log.calls
    dry = undo.undo(cfg, e["id"], dry_run=True)
    assert dry["ok"] and not log.calls and "dry run" in dry["message"]
    for bad_name in ("", "x\x00y", "a|b"):
        (cfg.backups_dir / "task-20260101-000000-000009.json").write_text(json.dumps({"name": bad_name, "xml": TASK_XML}))
        assert undo.undo(cfg, "task-20260101-000000-000009", dry_run=True)["ok"] is False
    (cfg.backups_dir / "task-20260101-000000-000009.json").write_text(json.dumps({"name": "ok", "xml": "<nope/>"}))
    assert undo.undo(cfg, "task-20260101-000000-000009", dry_run=True)["ok"] is False


# =========================================================================== service
@pytest.mark.parametrize("start,expected", [
    ("2   AUTO_START", "auto"), ("3   DEMAND_START", "demand"), ("2   AUTO_START  (DELAYED)", "delayed-auto"),
    ("0   BOOT_START", "boot"), ("1   SYSTEM_START", "system"),
])
def test_undo_service_restores_the_start_type(win, cfg, monkeypatch, start, expected):
    monkeypatch.setattr(rem, "run", lambda argv, timeout=60, input_text=None: (0, SC_QC.format(start=start) if argv[:2] == ["sc", "qc"] else "", ""))
    rem.disable_service(cfg, {"name": "Spooler"}, FINDING)
    log = RunLog()
    monkeypatch.setattr(undo, "run", log)
    r = undo.undo(cfg, only(cfg, "service")["id"])
    assert r["ok"] and r["changed"] and log.calls == [["sc", "config", "Spooler", "start=", expected]]
    assert "sc start Spooler" in r["message"]  # the start type is restored, the service is not started behind your back


def test_service_start_type_parsing_is_locale_independent():
    german = SC_QC.format(start="3   DEMAND_START").replace("START_TYPE", "STARTART").replace("TYPE   ", "TYP    ")
    assert undo._parse_service_start(german) == ("demand", "demand")
    assert undo._parse_service_start("garbage") is None
    assert undo._parse_service_start(SC_QC.format(start="9   WHATEVER")) is None


def test_undo_service_edge_cases(win, cfg, monkeypatch):
    monkeypatch.setattr(rem, "run", lambda argv, timeout=60, input_text=None: (0, SC_QC.format(start="4   DISABLED") if argv[:2] == ["sc", "qc"] else "", ""))
    rem.disable_service(cfg, {"name": "Spooler"}, FINDING)
    log = RunLog()
    monkeypatch.setattr(undo, "run", log)
    r = undo.undo(cfg, only(cfg, "service")["id"])
    assert r["ok"] and not r["changed"] and "already disabled" in r["message"] and not log.calls
    for payload in ({"name": "bad;name", "query": SC_QC.format(start="2   AUTO_START")},
                    {"name": "Spooler", "query": "no start type here"}):
        (cfg.backups_dir / "service-20260101-000000-000007.json").write_text(json.dumps(payload))
        assert undo.undo(cfg, "service-20260101-000000-000007")["ok"] is False
    (cfg.backups_dir / "service-20260101-000000-000007.json").write_text(json.dumps({"name": "Spooler", "query": SC_QC.format(start="2   AUTO_START")}))
    win.admin = False
    assert "Administrator" in undo.undo(cfg, "service-20260101-000000-000007")["message"]
    assert undo.undo(cfg, "service-20260101-000000-000007", dry_run=True)["ok"] and not log.calls


# =========================================================================== hosts (remediation) and web protection
def neutralised_hosts(cfg, tmp_path, monkeypatch, original="127.0.0.1 localhost\n10.0.0.1 evil.example\n# mine\n"):
    p = tmp_path / "hosts"
    p.write_bytes(original.encode("utf-8"))
    rem.restore_hosts(cfg, {"path": str(p), "remove_lines": ["10.0.0.1 evil.example"]}, FINDING)
    monkeypatch.setattr(wg, "hosts_path", lambda: p)
    return p


def test_undo_hosts_restores_content_and_is_itself_undoable(win, cfg, tmp_path, monkeypatch):
    original = "127.0.0.1 localhost\n10.0.0.1 evil.example\n# mine\n"
    p = neutralised_hosts(cfg, tmp_path, monkeypatch, original)
    assert "# disabled by Aegis: 10.0.0.1 evil.example" in p.read_text()
    neutralised_bytes = p.read_bytes()
    r = undo.undo(cfg, only(cfg, "hosts")["id"])
    assert r["ok"] and r["changed"], r
    assert p.read_bytes().replace(b"\r\n", b"\n") == original.encode()
    snap = only(cfg, "webhosts")  # the pre-undo file was saved first
    assert "undo" in snap["summary"] and undo.undo(cfg, snap["id"])["ok"]
    assert p.read_bytes() == neutralised_bytes


def test_undo_hosts_keeps_the_files_own_line_endings(win, cfg, tmp_path, monkeypatch):
    p = neutralised_hosts(cfg, tmp_path, monkeypatch)
    p.write_bytes(p.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))  # the file is CRLF now (Windows)
    assert undo.undo(cfg, only(cfg, "hosts")["id"])["ok"]
    data = p.read_bytes()
    assert data.count(b"\r\n") == 3 and b"\n" not in data.replace(b"\r\n", b"")


def test_undo_hosts_refuses_other_files_and_needs_admin(win, cfg, tmp_path, monkeypatch):
    p = neutralised_hosts(cfg, tmp_path, monkeypatch)
    other = tmp_path / "elsewhere"
    other.write_text("keep me")
    monkeypatch.setattr(wg, "hosts_path", lambda: other)
    r = undo.undo(cfg, only(cfg, "hosts")["id"])
    assert r["ok"] is False and "not this system's hosts file" in r["message"] and other.read_text() == "keep me"
    monkeypatch.setattr(wg, "hosts_path", lambda: p)
    win.admin = False
    before = p.read_bytes()
    r = undo.undo(cfg, only(cfg, "hosts")["id"])
    assert r["ok"] is False and "Administrator" in r["message"] and p.read_bytes() == before
    assert undo.undo(cfg, only(cfg, "hosts")["id"], dry_run=True)["ok"] and p.read_bytes() == before


def test_undo_webhosts_restores_the_file_byte_for_byte(win, cfg, tmp_path, monkeypatch):
    original = b"\xef\xbb\xbf127.0.0.1 localhost\r\n10.0.0.5 nas.home\r\n# caf\xe9\r\n"
    p = tmp_path / "hosts"
    p.write_bytes(original)
    monkeypatch.setattr(wg, "hosts_path", lambda: p)
    wg.enable_web_protection(cfg, type("S", (), {"bad_domains": {"bad.example"}})(), hosts_file=p)
    assert wg.BLOCK_BEGIN.encode() in p.read_bytes()
    e = only(cfg, "webhosts")
    r = undo.undo(cfg, e["id"])
    assert r["ok"] and r["changed"] and p.read_bytes() == original
    again = undo.undo(cfg, e["id"], force=True)
    assert again["ok"] and not again["changed"] and "already matches" in again["message"]


def test_undo_webhosts_damaged_or_foreign_backup(win, cfg, tmp_path, monkeypatch):
    p = tmp_path / "hosts"
    p.write_bytes(b"x\n")
    monkeypatch.setattr(wg, "hosts_path", lambda: p)
    name = "webhosts-20260101-000000-000003"
    (cfg.backups_dir / f"{name}.json").write_text(json.dumps({"path": str(p), "content_b64": "!!!not base64!!!"}))
    assert "damaged" in undo.undo(cfg, name)["message"]
    (cfg.backups_dir / f"{name}.json").write_text(json.dumps({"path": str(tmp_path / "other"), "content_b64": base64.b64encode(b"y").decode()}))
    r = undo.undo(cfg, name)
    assert r["ok"] is False and "not this system's hosts file" in r["message"] and p.read_bytes() == b"x\n"


# =========================================================================== removed (zip)
def archived_folder(cfg, tmp_path):
    folder = tmp_path / "BadExt"
    (folder / "sub").mkdir(parents=True)
    (folder / "manifest.json").write_text("{}")
    (folder / "sub" / "bg.js").write_text("evil()")
    rem.remove_path(cfg, {"path": str(folder)}, FINDING)
    assert not folder.exists()
    return folder


def test_undo_removed_needs_a_destination_and_extracts_there(cfg, tmp_path):
    archived_folder(cfg, tmp_path)
    e = only(cfg, "removed")
    assert e["undoable"] and "BadExt" in e["summary"] and "2 file" in e["summary"]
    r = undo.undo(cfg, e["id"])
    assert r["ok"] is False and r["details"]["needs_destination"] and "restore_to" in r["message"]
    dest = tmp_path / "restored"
    dry = undo.undo(cfg, e["id"], dry_run=True, restore_to=str(dest))
    assert dry["ok"] and not dest.exists()
    r = undo.undo(cfg, e["id"], restore_to=str(dest))
    assert r["ok"] and r["changed"] and (dest / "manifest.json").read_text() == "{}" and (dest / "sub" / "bg.js").exists()
    busy = undo.undo(cfg, e["id"], restore_to=str(dest), force=True)  # destination now holds files
    assert busy["ok"] is False and "not empty" in busy["message"]


def test_undo_removed_refuses_zip_slip(cfg, tmp_path):
    z = cfg.backups_dir / "removed-evil-20260101-000000.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("../escaped.txt", "x")
    dest = tmp_path / "dest"
    r = undo.undo(cfg, z.stem, restore_to=str(dest))
    assert r["ok"] is False and "outside the destination" in r["message"]
    assert not (tmp_path / "escaped.txt").exists() and not dest.exists()


# =========================================================================== harden journals via undo
def test_undo_harden_dry_run_and_platform_guard(win, cfg):
    harden.apply(["windows.llmnr"], cfg, env=win.env())
    e = only(cfg, "harden")
    dry = undo.undo(cfg, e["id"], dry_run=True)
    assert dry["ok"] and not dry["changed"] and "dry run" in dry["message"]
    assert win.reg.get("HKLM", r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast") == 0
    doc = json.loads(Path(e["path"]).read_text())
    doc["platform"] = "darwin"
    foreign = cfg.backups_dir / "harden-20260101-000000-000005.json"
    foreign.write_text(json.dumps(doc))
    entry = next(x for x in undo.list_backups(cfg) if x["id"] == foreign.stem)
    assert entry["undoable"] is False
    r = undo.undo(cfg, foreign.stem)
    assert r["ok"] is False and "cannot be undone here" in r["message"]


def test_undo_harden_needs_admin_for_machine_wide_changes(win, cfg):
    harden.apply(["windows.llmnr"], cfg, env=win.env())
    win.admin = False
    r = undo.undo(cfg, only(cfg, "harden")["id"])
    assert r["ok"] is False and "Administrator rights are required" in r["message"]
    assert win.reg.get("HKLM", r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast") == 0


# =========================================================================== resolution / bookkeeping / safety
def test_backup_id_resolution(win, cfg):
    set_value(cfg, "A", 1)
    set_value(cfg, "B", 1)
    a, b = sorted(undo.list_backups(cfg), key=lambda e: e["id"])
    assert undo._resolve(cfg, a["id"])[0]["id"] == a["id"]
    assert undo._resolve(cfg, a["id"] + ".json")[0]["id"] == a["id"]
    assert undo._resolve(cfg, str(Path(cfg.backups_dir) / (a["id"] + ".json")))[0]["id"] == a["id"]  # a pasted path works
    entry, err = undo._resolve(cfg, "registry-")
    assert entry is None and "matches 2 backups" in err
    assert undo._resolve(cfg, "nope")[1].startswith("no backup named")
    assert "no backup id" in undo._resolve(cfg, "")[1]
    newest = max(undo.list_backups(cfg), key=lambda e: (e["timestamp"], e["id"]))
    assert undo._resolve(cfg, "latest")[0]["id"] == newest["id"]
    assert undo.undo(cfg, "../../etc/passwd")["ok"] is False  # never resolves outside the backups directory


def test_latest_skips_undone_and_the_undo_snapshots(win, cfg, tmp_path, monkeypatch):
    win.reg.put("HKLM", KEY, "A", 5)
    set_value(cfg, "A", 1)
    assert undo.undo(cfg, "latest")["ok"] and win.reg.get("HKLM", KEY, "A") == 5
    assert undo.undo(cfg, "latest")["ok"] is False and "nothing left to undo" in undo.undo(cfg, "latest")["message"]
    p = neutralised_hosts(cfg, tmp_path, monkeypatch)
    assert undo.undo(cfg, "latest")["ok"]  # the hosts backup (not the snapshot the undo itself just wrote)
    assert undo._resolve(cfg, "latest")[0] is None  # only the undo's own hosts snapshot is left: never offered
    assert "nothing left to undo" in undo.undo(cfg, "latest")["message"] and p.exists()


def test_already_undone_needs_force(win, cfg):
    win.reg.put("HKLM", KEY, "A", 5)
    set_value(cfg, "A", 1)
    e = only(cfg, "registry")
    assert undo.undo(cfg, e["id"])["ok"]
    stamp = only(cfg, "registry")["undone"]
    assert stamp
    again = undo.undo(cfg, e["id"])
    assert again["ok"] is False and again["details"]["already_undone"] and stamp in again["message"]
    win.reg.put("HKLM", KEY, "A", 99)
    assert undo.undo(cfg, e["id"], dry_run=True)["ok"] and win.reg.get("HKLM", KEY, "A") == 99  # a preview is always allowed
    assert undo.undo(cfg, e["id"], force=True)["ok"] and win.reg.get("HKLM", KEY, "A") == 5


def test_windows_only_kinds_are_refused_elsewhere(win, cfg, monkeypatch):
    set_value(cfg, "A", 1)
    make_task_backup(cfg, monkeypatch)
    monkeypatch.setattr(undo, "IS_WINDOWS", False)
    for e in undo.list_backups(cfg):
        assert e["undoable"] is False
        r = undo.undo(cfg, e["id"])
        assert r["ok"] is False and "only be restored on Windows" in r["message"]
    assert win.reg.get("HKLM", KEY, "A") == 1


def test_undo_never_raises_on_garbage(win, cfg, monkeypatch):
    (cfg.backups_dir / "registry-20260101-000000-000001.json").write_text("{not json")
    (cfg.backups_dir / "hosts-20260101-000000-000002.json").write_text(json.dumps(["a", "list"]))
    (cfg.backups_dir / "webhosts-20260101-000000-000003.json").write_text(json.dumps({"path": 5, "content_b64": None}))
    (cfg.backups_dir / "mystery-20260101-000000-000004.json").write_text("{}")
    for e in undo.list_backups(cfg):
        r = undo.undo(cfg, e["id"])
        assert set(r) >= {"ok", "changed", "message", "details"} and r["ok"] is False
    monkeypatch.setattr(undo, "list_backups", lambda *a, **k: 1 / 0)
    r = undo.undo(cfg, "latest")
    assert r["ok"] is False and "undo failed" in r["message"]


def test_remediation_backup_payloads_are_what_undo_expects(win, cfg, monkeypatch, tmp_path):
    """Guards the contract with core/remediation.py: if a backup's payload shape changes, this fails loudly."""
    set_value(cfg, "V", 1)
    doc = json.loads(Path(only(cfg, "registry")["path"]).read_text())
    assert set(doc) == {"hive", "key", "value", "data"}  # set_registry_value: no view64
    rem.delete_registry_value(cfg, {"hive": "HKLM", "key": KEY, "value": "V"}, FINDING)
    deleted = next(json.loads(Path(e["path"]).read_text()) for e in undo.list_backups(cfg) if "view64" in Path(e["path"]).read_text())
    assert set(deleted) == {"hive", "key", "value", "data", "view64"}
    make_task_backup(cfg, monkeypatch)
    assert set(json.loads(Path(only(cfg, "task")["path"]).read_text())) == {"name", "xml"}
    monkeypatch.setattr(rem, "run", lambda *a, **k: (0, SC_QC.format(start="2   AUTO_START"), ""))
    rem.disable_service(cfg, {"name": "Spooler"}, FINDING)
    assert set(json.loads(Path(only(cfg, "service")["path"]).read_text())) == {"name", "query"}
    neutralised_hosts(cfg, tmp_path, monkeypatch)
    assert set(json.loads(Path(only(cfg, "hosts")["path"]).read_text())) == {"path", "content"}
