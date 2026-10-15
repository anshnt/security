"""Unit tests for aegis.scanners.usb: drive classification, autorun parsing, worm patterns on a fake USB tree, USBSTOR and
AutoRun policy logic (platform-specific facts are mocked)."""

import datetime as dt
import json
import os
import struct
import time
from types import SimpleNamespace

import pytest

from aegis.core.models import CheckResult, CheckStatus, Finding, Severity
from aegis.scanners import usb
from aegis.scanners.base import REGISTRY, load_all


def lnk_bytes(command="cmd.exe /c start \"\" \"evil.exe\" & start Photos"):
    """Header of a shortcut file followed by a UTF-16 argument string (what real LNK files contain)."""
    return b"L\x00\x00\x00\x01\x14\x02\x00" + b"\0" * 60 + command.encode("utf-16-le")


def rules(findings):
    return [f.rule_id for f in findings]


@pytest.fixture
def win_attrs(monkeypatch):
    """Pretend these names carry the Windows hidden attribute (the test host is not Windows)."""
    hidden = set()
    monkeypatch.setattr(usb, "attributes_of", lambda name, st: (name in hidden, False))
    return hidden


# ---------------------------------------------------------------- drive discovery
@pytest.mark.parametrize("dev,disk", [("/dev/sdb1", "sdb"), ("/dev/sdb", "sdb"), ("/dev/mmcblk0p1", "mmcblk0"),
                                      ("/dev/nvme0n1p2", "nvme0n1"), ("/dev/sdaa12", "sdaa"), ("/dev/vdb1", "vdb"), ("", "")])
def test_linux_disk_of(dev, disk):
    assert usb.linux_disk_of(dev) == disk


@pytest.mark.skipif(os.name == "nt", reason="Linux /sys/block layout (and unprivileged symlinks)")
def test_linux_block_removable(tmp_path):
    for name, flag in (("sdb", "1"), ("sda", "0")):
        d = tmp_path / "block" / name
        d.mkdir(parents=True)
        (d / "removable").write_text(flag + "\n")
    real = tmp_path / "devices" / "usb1" / "sdc"
    real.mkdir(parents=True)
    (real / "removable").write_text("0\n")
    os.symlink(real, tmp_path / "block" / "sdc")
    base = str(tmp_path / "block")
    assert usb.linux_block_removable("/dev/sdb1", base) is True
    assert usb.linux_block_removable("/dev/sda1", base) is False
    assert usb.linux_block_removable("/dev/sdc1", base) is True  # fixed flag but on a USB bus
    assert usb.linux_block_removable("/dev/sdz1", base) is None


def P(mountpoint, device="", fstype="", opts=""):
    return SimpleNamespace(mountpoint=mountpoint, device=device, fstype=fstype, opts=opts)


def test_classify_partition_windows():
    c = usb.classify_partition
    assert c(P("E:\\", "E:\\", "FAT32", "rw,removable"), "windows").mountpoint == "E:\\"
    assert c(P("D:\\", "D:\\", "CDFS", "ro,cdrom"), "windows") is None
    assert c(P("C:\\", "C:\\", "NTFS", "rw,fixed"), "windows") is None
    ext = c(P("F:\\", "F:\\", "NTFS", "rw,fixed"), "windows", usb_letters=["f"])
    assert ext and ext.reason == "USB disk"
    assert c(P("", "", "", "rw,removable"), "windows") is None


def test_classify_partition_linux_and_mac():
    c = usb.classify_partition
    yes = lambda dev: True  # noqa: E731
    no = lambda dev: False  # noqa: E731
    assert c(P("/mnt/stick", "/dev/sdb1", "vfat", "rw"), "linux", block_removable=yes)
    assert c(P("/", "/dev/sda1", "ext4", "rw"), "linux", block_removable=no) is None
    assert c(P("/media/bob/STICK", "/dev/mapper/x", "ext4", "rw"), "linux", block_removable=no).reason == "mounted under /media"
    assert c(P("/run/media/bob/X", "/dev/sdc1", "exfat", "rw"), "linux", block_removable=no)
    assert c(P("/snap/core/1", "/dev/loop1", "squashfs", "ro"), "linux", block_removable=yes) is None
    assert c(P("/Volumes/STICK", "/dev/disk4s1", "msdos", ""), "darwin")
    assert c(P("/Volumes/Macintosh HD", "/dev/disk1s1", "apfs", ""), "darwin") is None
    assert c(P("/System/Volumes/Data", "/dev/disk1s2", "apfs", ""), "darwin") is None


def test_find_removable_drives_with_injected_partitions():
    parts = [P("C:\\", "C:\\", "NTFS", "rw,fixed"), P("E:\\", "E:\\", "FAT32", "rw,removable"),
             P("E:\\", "E:\\", "FAT32", "rw,removable")]
    drives = usb.find_removable_drives("windows", parts)
    assert [d.mountpoint for d in drives] == ["E:\\"]
    assert usb.find_removable_drives("linux", []) == []


def test_attributes_of():
    st = SimpleNamespace(st_file_attributes=0x2 | 0x4)
    assert usb.attributes_of("x.exe", st) == (True, True)
    assert usb.attributes_of("x.exe", SimpleNamespace(st_file_attributes=0x20)) == (False, False)
    assert usb.attributes_of(".hidden", SimpleNamespace()) == (True, False)  # POSIX: leading dot
    assert usb.attributes_of("visible", SimpleNamespace()) == (False, False)


# ---------------------------------------------------------------- autorun.inf
def test_parse_autorun():
    p = usb.parse_autorun("[AutoRun]\r\nopen=setup.exe /auto\r\nICON=disk.ico\r\nlabel=My Stick\r\n"
                          "shell\\open\\command=wscript x.vbs\r\n[Content]\r\nMusicFiles=true\r\n; comment\r\njunk line\r\n")
    assert p["commands"] == [("open", "setup.exe /auto"), ("shell\\open\\command", "wscript x.vbs")]
    assert p["icon"] == "disk.ico" and p["label"] == "My Stick"
    q = usb.parse_autorun("[autorun]\nicon=a.ico\nlabel=X\n")
    assert q["commands"] == [] and q["icon"] == "a.ico"
    assert usb.parse_autorun("")["commands"] == [] and usb.parse_autorun("\x00\x00garbage")["commands"] == []
    amd = usb.parse_autorun("[autorun.amd64]\nopen=setup64.exe\n")
    assert amd["commands"] == [("open", "setup64.exe")]


def entry(name, hidden=False, is_dir=False, size=10):
    return usb.Entry(name, "/x/" + name, is_dir, hidden, False, size)


def test_evaluate_autorun_severities():
    lower = {"setup.exe": entry("setup.exe"), "evil.exe": entry("evil.exe", hidden=True)}
    ev = usb.evaluate_autorun
    sev, _r, d = ev(usb.parse_autorun("[autorun]\nopen=setup.exe\n"), "E:\\", lower)
    assert sev == Severity.MEDIUM and d[0]["target_on_drive"] is True
    assert ev(usb.parse_autorun("[autorun]\nopen=cmd /c start x.vbs\n"), "E:\\", lower)[0] == Severity.HIGH
    sev, reasons, d = ev(usb.parse_autorun("[autorun]\nopen=evil.exe\n"), "E:\\", lower)
    assert sev == Severity.HIGH and d[0]["target_hidden"] and any("hidden" in r for r in reasons)
    assert ev(usb.parse_autorun("[autorun]\nshellexecute=http://bad.example/x\n"), "E:\\", lower)[0] == Severity.HIGH
    assert ev(usb.parse_autorun("[autorun]\nopen=launch.scr\n"), "E:\\", lower)[0] == Severity.HIGH
    assert ev(usb.parse_autorun("[autorun]\nicon=a.ico\n"), "E:\\", lower)[0] == Severity.INFO


# ---------------------------------------------------------------- worm patterns on a fake drive
def build_infected_drive(root, hidden):
    (root / "autorun.inf").write_text("[autorun]\nopen=cmd /c start evil.exe\nicon=%systemroot%\\system32\\shell32.dll,4\n")
    (root / "evil.exe").write_bytes(b"MZ" + b"\0" * 200)
    (root / "Photos").mkdir()
    (root / "Photos" / "holiday.jpg").write_bytes(b"\xff\xd8\xff")
    (root / "Photos.lnk").write_bytes(lnk_bytes())
    (root / "Docs").mkdir()
    (root / "Docs.exe").write_bytes(b"MZ" + b"\0" * 100)
    (root / "New Folder.exe").write_bytes(b"MZ" + b"\0" * 100)
    (root / "RECYCLER" / "S-1-5-21").mkdir(parents=True)
    (root / "RECYCLER" / "S-1-5-21" / "svchost.exe").write_bytes(b"MZ" + b"\0" * 100)
    (root / "notes.txt").write_text("hello")
    hidden.update({"evil.exe", "Photos"})


def level(root, is_root=True):
    return usb.analyse_level(str(root), usb.read_entries(str(root)), is_root, "E:\\")


def test_analyse_level_finds_each_worm_artifact(tmp_path, win_attrs):
    build_infected_drive(tmp_path, win_attrs)
    f = level(tmp_path)
    by = {}
    for x in f:
        by.setdefault(x.rule_id, []).append(x)
    assert set(by) == {"AEG-USB-AUTORUN", "AEG-USB-HIDDENEXE", "AEG-USB-LNKWORM", "AEG-USB-FOLDEREXE", "AEG-USB-RECYCLER"}

    auto = by["AEG-USB-AUTORUN"][0]
    assert auto.severity == Severity.HIGH and auto.remediation.action == "quarantine_file" and "T1091" in auto.mitre
    assert auto.evidence["commands"][0]["target"].endswith("evil.exe") or "evil.exe" in auto.evidence["commands"][0]["command"]

    hid = by["AEG-USB-HIDDENEXE"][0]
    assert hid.severity == Severity.HIGH and hid.location.endswith("evil.exe") and hid.remediation.params["path"] == hid.location

    worm = by["AEG-USB-LNKWORM"][0]
    assert worm.severity == Severity.HIGH and worm.location.endswith("Photos.lnk")
    assert worm.evidence["hidden_folder"].endswith("Photos") and any("cmd" in s for s in worm.evidence["shortcut_strings"])
    assert "shortcut virus" in worm.description

    names = {x.title for x in by["AEG-USB-FOLDEREXE"]}
    assert names == {"Program disguised as a folder: Docs.exe", "Program disguised as a folder: New Folder.exe"}
    assert all(x.severity == Severity.HIGH for x in by["AEG-USB-FOLDEREXE"])
    rec = by["AEG-USB-RECYCLER"][0]
    assert rec.severity == Severity.HIGH and rec.evidence["programs"][0].endswith("svchost.exe")
    for x in f:
        json.dumps(x.to_dict())


def test_unhide_fix_only_on_windows(tmp_path, win_attrs, monkeypatch):
    (tmp_path / "Photos").mkdir()
    (tmp_path / "Photos.lnk").write_bytes(lnk_bytes())
    win_attrs.add("Photos")
    monkeypatch.setattr(usb, "IS_WINDOWS", False)
    assert level(tmp_path)[0].remediation is None
    monkeypatch.setattr(usb, "IS_WINDOWS", True)
    w = level(tmp_path)[0]
    assert w.remediation.action == "run_command"
    assert w.remediation.params["command"][:4] == ["attrib", "-h", "-s", "-r"] and w.remediation.params["command"][4].endswith("Photos")


def test_benign_drive_has_no_findings(tmp_path, win_attrs):
    (tmp_path / "Photos").mkdir()
    (tmp_path / "Photos" / "a.jpg").write_bytes(b"\xff\xd8")
    (tmp_path / "readme.txt").write_text("hi")
    (tmp_path / "report.docx").write_bytes(b"PK\x03\x04")
    (tmp_path / "Setup.exe").write_bytes(b"MZ" + b"\0" * 50)  # an installer: no folder of that name, normal name
    (tmp_path / "shortcut.lnk").write_bytes(lnk_bytes("C:\\Program Files\\Foo\\foo.exe"))  # plain shortcut
    (tmp_path / "autorun.inf").write_text("[autorun]\nicon=a.ico\nlabel=Photos\n")
    f = level(tmp_path)
    assert rules(f) == ["AEG-USB-AUTORUN-INFO"] and f[0].severity == Severity.INFO


def test_lnk_without_hidden_twin_is_flagged_medium_only_when_it_runs_a_shell(tmp_path, win_attrs):
    (tmp_path / "invoice.lnk").write_bytes(lnk_bytes("cmd.exe /c powershell -w hidden calc"))
    f = level(tmp_path)
    assert rules(f) == ["AEG-USB-LNK"] and f[0].severity == Severity.MEDIUM


def test_hidden_dll_and_apple_double_stubs(tmp_path, win_attrs):
    (tmp_path / "helper.dll").write_bytes(b"MZ" + b"\0" * 50)
    (tmp_path / "._setup.exe").write_bytes(b"\0" * 10)  # macOS metadata stub
    win_attrs.add("helper.dll")
    win_attrs.add("._setup.exe")
    f = level(tmp_path)
    assert [x.title for x in f] == ["Hidden program on a removable drive: helper.dll"] and f[0].severity == Severity.MEDIUM


def test_hidden_items_at_depth_are_found_by_walk(tmp_path, win_attrs):
    root = tmp_path / "drive"
    sub = root / "Work"
    sub.mkdir(parents=True)
    (sub / "run.vbs").write_text("MsgBox 1")
    win_attrs.add("run.vbs")
    seen = [(os.path.basename(d), depth) for d, _e, depth in usb.walk_drive(str(root), 2, time.monotonic() + 30)]
    assert seen == [("drive", 0), ("Work", 1)]
    assert len(list(usb.walk_drive(str(root), 0, time.monotonic() + 30))) == 1  # depth limit
    assert list(usb.walk_drive(str(root), 2, time.monotonic() - 1)) == []  # deadline
    f = usb.analyse_level(str(sub), usb.read_entries(str(sub)), False, "E:\\")
    assert rules(f) == ["AEG-USB-HIDDENEXE"]


# ---------------------------------------------------------------- scan_drive / scanner
def test_scan_drive_uses_scan_file_on_programs(ctx, tmp_path, eicar_bytes):
    (tmp_path / "setup.exe").write_bytes(eicar_bytes)
    (tmp_path / "readme.txt").write_text("hello")
    findings = list(usb.scan_drive(ctx, usb.RemovableDrive(str(tmp_path)), time.monotonic() + 60))
    detect = [f for f in findings if f.location == str(tmp_path / "setup.exe")]
    assert detect and detect[0].evidence["removable_drive"] == str(tmp_path)
    assert any(f.rule_id == "AEG-USB-PROGRAMS" for f in findings)  # INFO inventory of the root programs
    assert ctx.stats["usb_files_scanned"] == 1


def test_scanner_end_to_end_infected_and_clean(ctx, tmp_path, win_attrs):
    bad = tmp_path / "bad"
    good = tmp_path / "good"
    bad.mkdir()
    good.mkdir()
    build_infected_drive(bad, win_attrs)
    (good / "doc.txt").write_text("fine")
    ctx.options["usb_roots"] = [str(bad), str(good), str(tmp_path / "missing")]
    out = list(usb.UsbScanner().run(ctx))
    findings = [x for x in out if isinstance(x, Finding)]
    checks = [x for x in out if isinstance(x, CheckResult)]
    assert {"AEG-USB-AUTORUN", "AEG-USB-LNKWORM", "AEG-USB-HIDDENEXE"} <= set(rules(findings))
    drive_checks = [c for c in checks if c.check_id.startswith("AEG-USB-DRIVE-")]
    assert len(drive_checks) == 2
    status = {c.title: c.status for c in drive_checks}
    assert status[f"Removable drive {bad}"] == CheckStatus.FAIL and status[f"Removable drive {good}"] == CheckStatus.PASS
    assert checks[0].check_id == "AEG-USB-AUTORUN"
    if os.name != "nt":
        assert checks[0].status == CheckStatus.SKIP  # the AutoRun policy is a Windows registry check
    assert ctx.stats["usb_drives"] == 2
    json.dumps([x.to_dict() for x in out])


def test_scanner_no_drives(ctx, monkeypatch):
    monkeypatch.setattr(usb, "find_removable_drives", lambda *a, **k: [])
    out = list(usb.UsbScanner().run(ctx))
    c = [x for x in out if isinstance(x, CheckResult) and x.check_id == "AEG-USB-DRIVES"][0]
    assert c.status == CheckStatus.PASS and "No USB" in c.detail


def test_scanner_survives_drive_discovery_failure(ctx, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("psutil exploded")

    monkeypatch.setattr(usb, "find_removable_drives", boom)
    out = list(usb.UsbScanner().run(ctx))
    assert any(isinstance(x, CheckResult) and x.check_id == "AEG-USB-DRIVES" for x in out)


# ---------------------------------------------------------------- USBSTOR history
def ft(when: dt.datetime) -> bytes:
    delta = when - dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
    return struct.pack("<Q", int(delta.total_seconds() * 10_000_000))


def test_filetime_conversion():
    t = dt.datetime(2026, 10, 14, 10, 30, tzinfo=dt.timezone.utc)
    assert usb.filetime_to_str(ft(t)) == "2026-10-14 10:30 UTC"
    assert usb.filetime_to_str(int.from_bytes(ft(t), "little")) == "2026-10-14 10:30 UTC"
    assert usb.filetime_to_str(b"") == "" and usb.filetime_to_str(None) == "" and usb.filetime_to_str(0) == ""
    assert usb.filetime_to_str(b"\xff" * 8) == ""  # out of range


def test_parse_usbstor_device():
    t1 = dt.datetime(2025, 3, 1, 8, 0, tzinfo=dt.timezone.utc)
    t2 = dt.datetime(2026, 10, 1, 9, 15, tzinfo=dt.timezone.utc)
    d = usb.parse_usbstor_device("Disk&Ven_SanDisk&Prod_Ultra_USB_3.0&Rev_1.00", "4C530001230605115334&0",
                                 {"FriendlyName": "SanDisk Ultra USB 3.0 USB Device"},
                                 {"0065": ft(t1), "0066": ft(t2)})
    assert d["vendor"] == "SanDisk" and d["product"] == "Ultra USB 3.0" and d["revision"] == "1.00"
    assert d["serial"] == "4C530001230605115334" and d["name"] == "SanDisk Ultra USB 3.0 USB Device"
    assert d["first_install"] == "2025-03-01 08:00 UTC" and d["last_connected"] == "2026-10-01 09:15 UTC" and d["last_removed"] == ""
    odd = usb.parse_usbstor_device("Weird", "ABC", {})
    assert odd["product"] == "Weird" and odd["serial"] == "ABC"


def test_collect_usbstor_sorted_by_last_connected():
    older = dt.datetime(2025, 1, 1, tzinfo=dt.timezone.utc)
    newer = dt.datetime(2026, 9, 1, tzinfo=dt.timezone.utc)
    tree = {usb.USBSTOR_KEY: ["Disk&Ven_A&Prod_Old&Rev_1", "Disk&Ven_B&Prod_New&Rev_2"],
            usb.USBSTOR_KEY + r"\Disk&Ven_A&Prod_Old&Rev_1": ["111&0"], usb.USBSTOR_KEY + r"\Disk&Ven_B&Prod_New&Rev_2": ["222&0"]}
    times = {usb.USBSTOR_KEY + r"\Disk&Ven_A&Prod_Old&Rev_1\111&0\Properties\{83da6326-97a6-4088-9453-a1923f573b29}\0066": ft(older),
             usb.USBSTOR_KEY + r"\Disk&Ven_B&Prod_New&Rev_2\222&0\Properties\{83da6326-97a6-4088-9453-a1923f573b29}\0066": ft(newer)}
    got = usb.collect_usbstor(lambda h, k, v=True: tree.get(k, []), lambda h, k, v=True: {"FriendlyName": "dev"},
                              lambda h, k, name, v=True: times.get(k))
    assert [d["product"] for d in got] == ["New", "Old"] and got[0]["last_connected"].startswith("2026-09-01")


# ---------------------------------------------------------------- policy
@pytest.mark.parametrize("hklm,hkcu,na_m,na_u,dis,autorun_off,autoplay_off", [
    (None, None, None, None, None, False, False),
    (255, None, None, None, None, True, True),
    (0x91, None, None, None, None, False, False),  # the Windows default mask does not cover removable drives
    (0x95, None, None, None, None, True, True),
    (None, 0x04, None, None, None, True, True),
    (None, None, 1, None, None, True, False),  # NoAutorun blocks autorun.inf but AutoPlay prompts remain
    (None, None, None, 1, 1, True, True),
    (None, None, None, None, 1, False, True),
])
def test_evaluate_autorun_policy(hklm, hkcu, na_m, na_u, dis, autorun_off, autoplay_off):
    p = usb.evaluate_autorun_policy(hklm, hkcu, na_m, na_u, dis)
    assert p["autorun_disabled"] is autorun_off and p["autoplay_disabled"] is autoplay_off


def test_policy_results_and_fix():
    checks, findings = usb.policy_results(usb.evaluate_autorun_policy(None, None, None, None, None))
    assert {c.check_id: c.status for c in checks} == {"AEG-USB-AUTORUN": CheckStatus.WARN, "AEG-USB-AUTOPLAY": CheckStatus.WARN}
    f = findings[0]
    assert f.rule_id == "AEG-USB-POLICY" and f.severity == Severity.LOW
    assert f.remediation.action == "set_registry_value" and f.remediation.params == {
        "hive": "HKLM", "key": usb.EXPLORER_POLICY_KEY, "value": "NoDriveTypeAutoRun", "data": 255}
    checks, findings = usb.policy_results(usb.evaluate_autorun_policy(255, None, None, None, None))
    assert findings == [] and {c.status for c in checks} == {CheckStatus.PASS}


def test_scanner_windows_flow_with_mocks(ctx, monkeypatch, tmp_path):
    monkeypatch.setattr(usb, "IS_WINDOWS", True)
    monkeypatch.setattr(usb, "reg_read", lambda *a, **k: None)
    monkeypatch.setattr(usb, "collect_usbstor", lambda: [{"vendor": "SanDisk", "product": "Ultra", "serial": "1", "name": "SanDisk",
                                                         "last_connected": "2026-10-01 09:15 UTC", "first_install": "",
                                                         "last_removed": "", "revision": ""}])
    monkeypatch.setattr(usb, "find_removable_drives", lambda *a, **k: [])
    out = list(usb.UsbScanner().run(ctx))
    ids = {x.check_id if isinstance(x, CheckResult) else x.rule_id for x in out}
    assert {"AEG-USB-AUTORUN", "AEG-USB-AUTOPLAY", "AEG-USB-POLICY", "AEG-USB-HISTORY", "AEG-USB-DRIVES"} <= ids
    hist = [x for x in out if isinstance(x, Finding) and x.rule_id == "AEG-USB-HISTORY"][0]
    assert hist.severity == Severity.INFO and hist.evidence["total"] == 1


def test_scanner_registered():
    load_all()
    cls = REGISTRY["usb"]
    assert set(cls.platforms) == {"windows", "linux", "darwin"} and cls.title and cls.description
