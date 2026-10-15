"""Removable-media risk review (USB sticks, SD cards, external drives).

* **Currently mounted removable drives** (psutil: the ``removable`` mount option on Windows, ``/sys/block/*/removable`` or
  ``/media`` mounts on Linux, ``/Volumes`` on macOS; on Windows USB *hard disks* that report as fixed disks are added via
  ``Get-Disk`` BusType USB) are inspected for the artefacts USB worms leave behind:
  - ``autorun.inf`` that launches something (T1091),
  - hidden / system executables and scripts,
  - **shortcut-virus** pattern: hidden folders replaced by ``.lnk`` files of the same name that start a hidden program,
  - programs masquerading as folders (``Photos.exe`` beside a ``Photos`` folder, ``New Folder.exe`` ...),
  - executables inside ``RECYCLER`` / ``System Volume Information`` style hiding places,
  and every program/script/shortcut found near the root is run through ``aegis.scanners.files.scan_file``.
* **USBSTOR history** (``HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR``) is reported as an INFO inventory of every USB
  storage device this PC has seen (vendor, product, serial, first/last connection).
* **AutoRun / AutoPlay policy** (``NoAutorun``, ``NoDriveTypeAutoRun``, ``DisableAutoplay``) is checked and can be tightened.

Listing, classification, autorun parsing and USBSTOR parsing are pure functions unit-tested on any OS.
"""

from __future__ import annotations

import datetime as dt
import logging
import os
import re
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

from aegis.core import cmdline as cl
from aegis.core import fileanalysis as fa
from aegis.core.models import Category, CheckResult, CheckStatus, Finding, Remediation, Severity
from aegis.core.platform import IS_MAC, IS_WINDOWS, as_list, powershell_json, reg_read, reg_subkeys, reg_values
from aegis.scanners.base import Emitted, ScanContext, Scanner, register
from aegis.scanners.files import scan_file

log = logging.getLogger("aegis.usb")

RUNNABLE_EXTS = {"exe", "scr", "com", "pif", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "ps1", "jar",
                 "cpl", "msi"}
HIDEABLE_EXTS = RUNNABLE_EXTS | {"dll", "lnk"}
MAX_DEPTH = 2
MAX_DEPTH_DEEP = 4
MAX_ENTRIES_PER_DIR = 3000
MAX_ENTRIES_PER_DRIVE = 30000
MAX_SCAN_FILES = 60
MAX_SCAN_FILES_DEEP = 250
MAX_FINDINGS_PER_RULE = 15
HIDING_DIRS = {"recycler", "system volume information", "$recycle.bin", "recycled"}

FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_SYSTEM = 0x4

# =========================================================================== drive discovery


@dataclass
class RemovableDrive:
    mountpoint: str
    device: str = ""
    fstype: str = ""
    reason: str = ""  # how we decided it is removable


def linux_disk_of(device: str) -> str:
    """'/dev/sdb1' -> 'sdb', '/dev/mmcblk0p1' -> 'mmcblk0', '/dev/nvme0n1p2' -> 'nvme0n1'."""
    dev = os.path.basename(device or "")
    m = re.match(r"^(nvme\d+n\d+|mmcblk\d+|loop\d+)p\d+$", dev)
    if m:
        return m.group(1)
    m = re.match(r"^((?:sd|vd|hd|xvd)[a-z]+)\d+$", dev)
    return m.group(1) if m else dev


def linux_block_removable(device: str, sys_block: str = "/sys/block") -> Optional[bool]:
    """True if /sys says the underlying disk is removable or sits on a USB bus; None if unknown."""
    disk = linux_disk_of(device)
    if not disk:
        return None
    base = os.path.join(sys_block, disk)
    try:
        with open(os.path.join(base, "removable"), "r", encoding="ascii", errors="replace") as fh:
            if fh.read().strip() == "1":
                return True
    except OSError:
        return None
    try:
        return "/usb" in os.path.realpath(base)
    except OSError:
        return False


def classify_partition(part: Any, platform: str, usb_letters: Sequence[str] = (),
                       block_removable=linux_block_removable) -> Optional[RemovableDrive]:
    """Decide whether a psutil partition record is a removable drive. ``part`` needs mountpoint/device/fstype/opts."""
    mp = str(getattr(part, "mountpoint", "") or "")
    dev = str(getattr(part, "device", "") or "")
    fstype = str(getattr(part, "fstype", "") or "")
    opts = str(getattr(part, "opts", "") or "").lower()
    if not mp:
        return None
    if platform == "windows":
        if "cdrom" in opts:
            return None
        letter = mp[:1].upper()
        if "removable" in opts:
            return RemovableDrive(mp, dev, fstype, "removable drive")
        if letter in {x.upper() for x in usb_letters}:
            return RemovableDrive(mp, dev, fstype, "USB disk")
        return None
    if platform == "darwin":
        if mp.startswith("/Volumes/") and not re.match(r"^/Volumes/(Macintosh HD|Preboot|Recovery|Update|VM|xarts|iSCPreboot|Hardware)", mp):
            return RemovableDrive(mp, dev, fstype, "external volume")
        return None
    # linux
    if fstype in ("squashfs", "tmpfs", "overlay", "proc", "sysfs", "devtmpfs", "ramfs", "iso9660", "udf"):
        return None
    flag = block_removable(dev) if dev.startswith("/dev/") else None
    if flag:
        return RemovableDrive(mp, dev, fstype, "removable / USB disk")
    if mp.startswith(("/media/", "/run/media/")):
        return RemovableDrive(mp, dev, fstype, "mounted under /media")
    return None


def usb_drive_letters() -> List[str]:
    """Drive letters of USB-attached disks (also USB hard disks that Windows reports as 'fixed')."""
    if not IS_WINDOWS:
        return []
    data = powershell_json(
        "Get-Disk | Where-Object { $_.BusType -eq 'USB' } | Get-Partition | Where-Object { $_.DriveLetter } | "
        "ForEach-Object { [string]$_.DriveLetter } | ConvertTo-Json -Compress", timeout=45)
    return [str(x) for x in as_list(data) if isinstance(x, str) and len(x) == 1]


def find_removable_drives(platform: Optional[str] = None, partitions: Optional[Sequence[Any]] = None) -> List[RemovableDrive]:
    platform = platform or ("windows" if IS_WINDOWS else "darwin" if IS_MAC else "linux")
    if partitions is None:
        try:
            import psutil

            partitions = psutil.disk_partitions(all=False)
        except Exception as exc:
            log.debug("disk_partitions failed: %s", exc)
            return []
    letters = usb_drive_letters() if platform == "windows" and IS_WINDOWS else []
    out: List[RemovableDrive] = []
    seen = set()
    for p in partitions:
        d = classify_partition(p, platform, letters)
        if d and d.mountpoint not in seen:
            seen.add(d.mountpoint)
            out.append(d)
    return out


# =========================================================================== directory listing


@dataclass
class Entry:
    name: str
    path: str
    is_dir: bool = False
    hidden: bool = False
    system: bool = False
    size: int = 0

    @property
    def ext(self) -> str:
        return self.name.rsplit(".", 1)[-1].lower() if "." in self.name else ""

    @property
    def stem(self) -> str:
        return self.name.rsplit(".", 1)[0] if "." in self.name else self.name

    @property
    def concealed(self) -> bool:
        return self.hidden or self.system


def attributes_of(name: str, st: Any) -> Tuple[bool, bool]:
    """(hidden, system) from Windows file attributes, or the leading-dot convention elsewhere."""
    attrs = getattr(st, "st_file_attributes", None)
    if attrs is not None:
        return bool(attrs & FILE_ATTRIBUTE_HIDDEN), bool(attrs & FILE_ATTRIBUTE_SYSTEM)
    return name.startswith("."), False


def read_entries(directory: str, limit: int = MAX_ENTRIES_PER_DIR) -> List[Entry]:
    out: List[Entry] = []
    try:
        with os.scandir(directory) as it:
            for e in it:
                if len(out) >= limit:
                    break
                try:
                    st = e.stat(follow_symlinks=False)
                    is_dir = e.is_dir(follow_symlinks=False)
                except OSError:
                    continue
                hidden, system = attributes_of(e.name, st)
                out.append(Entry(e.name, e.path, is_dir, hidden, system, 0 if is_dir else st.st_size))
    except OSError:
        pass
    return out


# =========================================================================== analysis helpers (pure)

_INTERPRETER = re.compile(r"(?i)\b(cmd(?:\.exe)?\s+/[ck]|%comspec%|wscript|cscript|mshta|powershell|pwsh|rundll32|regsvr32|"
                          r"certutil|bitsadmin|msiexec)\b")
_FOLDERISH_EXE = re.compile(r"(?i)^(new folder|documents?|my documents|pictures?|my pictures|photos?|music|videos?|downloads?|"
                            r"desktop|backup|files?|data|work|school|usb|drive|removable disk|disk|folder|images?|"
                            r"my videos|my music|private|secret|hidden)(?:[ _-]?\(?\d+\)?)?\.(?:exe|scr|com|pif)$")


def parse_autorun(text: str) -> Dict[str, Any]:
    """Parse an autorun.inf (tolerant of the garbage real worms write). Returns
    {'commands': [(key, value)], 'icon': str, 'label': str, 'action': str, 'sections': [...]}."""
    sections: Dict[str, Dict[str, str]] = {}
    cur = ""
    for raw in (text or "").replace("\x00", "").splitlines():
        line = raw.strip()
        if not line or line.startswith((";", "#")):
            continue
        if line.startswith("[") and "]" in line:
            cur = line[1:line.index("]")].strip().lower()
            sections.setdefault(cur, {})
            continue
        if "=" in line and cur:
            k, v = line.split("=", 1)
            sections[cur].setdefault(k.strip().lower(), v.strip())
    commands: List[Tuple[str, str]] = []
    icon = label = action = ""
    for name, kv in sections.items():
        if not name.startswith("autorun"):
            continue
        for k, v in kv.items():
            if k in ("open", "shellexecute") or (k.startswith("shell\\") and k.endswith("\\command")):
                if v:
                    commands.append((k, v))
            elif k == "icon":
                icon = icon or v
            elif k == "label":
                label = label or v
            elif k == "action":
                action = action or v
    return {"commands": commands, "icon": icon, "label": label, "action": action, "sections": sorted(sections)}


def evaluate_autorun(parsed: Dict[str, Any], root: str, entries_by_lower: Dict[str, Entry]) -> Tuple[Severity, List[str], List[Dict[str, Any]]]:
    """(severity, reasons, per-command details) for a parsed autorun.inf."""
    if not parsed["commands"]:
        return Severity.INFO, [], []
    sev = Severity.MEDIUM
    reasons: List[str] = []
    details: List[Dict[str, Any]] = []
    for key, cmd in parsed["commands"]:
        hits = cl.analyse_command_line(cmd)
        target = cl.extract_executable(cmd) or ""
        base = re.split(r"[\\/]", target)[-1].lower() if target else ""
        ent = entries_by_lower.get(base) if base else None
        d = {"key": key, "command": cmd[:300], "target": target, "target_on_drive": bool(ent),
             "target_hidden": bool(ent and ent.concealed), "analysis": [h[0] for h in hits]}
        details.append(d)
        if hits:
            sev = max(sev, max(h[2] for h in hits))
            reasons.append("the command is suspicious: " + hits[0][1])
        if _INTERPRETER.search(cmd):
            sev = max(sev, Severity.HIGH)
            reasons.append("it starts a script interpreter / shell instead of a normal program")
        if re.match(r"(?i)^\s*(?:https?|ftp)://", cmd):
            sev = max(sev, Severity.HIGH)
            reasons.append("it opens a web address automatically")
        if ent and ent.concealed:
            sev = max(sev, Severity.HIGH)
            reasons.append("the program it launches is a hidden file on the drive")
        if cmd.lower().endswith((".lnk", ".vbs", ".js", ".bat", ".cmd", ".scr", ".pif")) or ".vbs" in cmd.lower():
            sev = max(sev, Severity.HIGH)
            reasons.append("it launches a script/shortcut/screensaver file")
    return sev, list(dict.fromkeys(reasons)), details


def lnk_summary(data: bytes) -> Tuple[List[Any], List[str]]:
    """(indicators, readable command strings) of a shortcut file."""
    inds = fa.lnk_indicators(data) + [i for i in fa.content_indicators(data, "lnk") if i.score > 0]
    flat = data.replace(b"\x00", b"")
    strings = [m.decode("latin-1") for m in re.findall(rb"[ -~]{8,}", flat)]
    interesting = [s for s in strings if re.search(r"(?i)\b(cmd|start|wscript|cscript|powershell|rundll32|\.exe|\.vbs|\.js|\.bat)\b", s)]
    return inds, interesting[:6]


def _read_head(path: str, n: int = 262144) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(n)
    except OSError:
        return b""


def _quarantine(path: str, desc: str = "Move the file to quarantine") -> Remediation:
    return Remediation("quarantine_file", {"path": path}, desc)


def _unhide_fix(path: str) -> Optional[Remediation]:
    if not IS_WINDOWS:
        return None
    return Remediation("run_command", {"command": ["attrib", "-h", "-s", "-r", path]},
                       "Make the hidden folder visible again (attrib -h -s -r); nothing is deleted")


def analyse_level(dirpath: str, entries: Sequence[Entry], is_root: bool, drive_label: str = "") -> List[Finding]:
    """Findings for one directory level of a removable drive (no antivirus scanning here)."""
    out: List[Finding] = []
    lower = {e.name.lower(): e for e in entries}
    where = f"on the removable drive {drive_label}" if drive_label else "on a removable drive"

    # ---- autorun.inf (root only)
    if is_root and "autorun.inf" in lower and not lower["autorun.inf"].is_dir:
        e = lower["autorun.inf"]
        text = _read_head(e.path, 32768).decode("latin-1", "replace")
        parsed = parse_autorun(text)
        sev, reasons, details = evaluate_autorun(parsed, dirpath, lower)
        if parsed["commands"]:
            out.append(Finding(
                "AEG-USB-AUTORUN", "autorun.inf on a removable drive launches a program", sev, Category.SUSPICIOUS,
                f"The file {e.path} tells Windows to run: {parsed['commands'][0][1][:150]}. USB worms have used autorun.inf "
                "for decades to start themselves when a drive is plugged in. Modern Windows no longer auto-runs it from "
                "USB sticks, but it still shows the command in the AutoPlay menu, and older PCs run it automatically."
                + (" Flagged because " + "; ".join(reasons) + "." if reasons else ""),
                e.path, {"commands": details, "icon": parsed["icon"], "label": parsed["label"], "action": parsed["action"]},
                "Do not open programs from this drive. Delete autorun.inf (quarantine it) and scan the drive; if you "
                "created it yourself for an installer, it is safe to keep.",
                _quarantine(e.path, "Move autorun.inf to quarantine"), mitre=["T1091", "T1547"]))
        else:
            out.append(Finding(
                "AEG-USB-AUTORUN-INFO", "autorun.inf present on a removable drive (icon/label only)", Severity.INFO,
                Category.SUSPICIOUS,
                f"{e.path} exists but only sets a drive icon/label - it does not launch anything.", e.path,
                {"icon": parsed["icon"], "label": parsed["label"]}, "No action needed.", mitre=["T1091"]))

    # ---- hidden / system programs and scripts
    # (macOS writes hidden "._name" AppleDouble stubs next to files on FAT/exFAT drives; they are not programs)
    hidden_exes = [e for e in entries if not e.is_dir and e.concealed and e.ext in HIDEABLE_EXTS
                   and not (e.name.startswith("._") and not e.system)]
    for e in hidden_exes[:MAX_FINDINGS_PER_RULE]:
        sev = Severity.MEDIUM if e.ext in ("lnk", "dll") else Severity.HIGH
        out.append(Finding(
            "AEG-USB-HIDDENEXE", f"Hidden program on a removable drive: {e.name}", sev, Category.SUSPICIOUS,
            f"{e.path} is a hidden{'/system' if e.system else ''} {e.ext.upper()} file {where}. Legitimate USB drives rarely "
            "contain hidden programs; USB worms hide their own copies so you do not notice them.",
            e.path, {"hidden": e.hidden, "system": e.system, "size": e.size, "extension": e.ext},
            "Do not run it. Quarantine the file and scan the drive; show hidden files in Explorer to see what else is there.",
            _quarantine(e.path), mitre=["T1091", "T1564.001"]))

    # ---- shortcut-virus pattern: hidden folder + same-named .lnk
    for d in entries:
        if not (d.is_dir and d.concealed) or d.name.lower() in HIDING_DIRS:
            continue
        twin = lower.get(d.name.lower() + ".lnk")
        if not twin or twin.is_dir:
            continue
        data = _read_head(twin.path, 65536)
        _inds, strings = lnk_summary(data)
        out.append(Finding(
            "AEG-USB-LNKWORM", f"Shortcut virus pattern: folder '{d.name}' is hidden and replaced by a shortcut", Severity.HIGH,
            Category.SUSPICIOUS,
            f"The folder '{d.name}' {where} has been hidden, and a shortcut called '{twin.name}' with the same name takes its "
            "place. This is the signature of the 'shortcut virus': clicking the shortcut starts the malware (and then "
            "opens your folder so you notice nothing), while your real files are hidden but still intact.",
            twin.path, {"hidden_folder": d.path, "shortcut": twin.path, "shortcut_size": twin.size, "shortcut_strings": strings},
            "Do not click the shortcuts. Make the hidden folders visible again (the fix below does that without deleting "
            "anything), delete the .lnk files and the hidden program, and run a full scan. Copy your files off the drive and "
            "reformat it if malware keeps coming back.",
            _unhide_fix(d.path), mitre=["T1091", "T1564.001", "T1204.002"]))
    # ---- shortcuts that start interpreters
    twinned = {d.name.lower() + ".lnk" for d in entries if d.is_dir and d.concealed}
    for e in entries:
        if e.is_dir or e.ext != "lnk" or e.name.lower() in twinned:
            continue
        inds, strings = lnk_summary(_read_head(e.path, 65536))
        if any(i.severity >= Severity.MEDIUM for i in inds):
            out.append(Finding(
                "AEG-USB-LNK", f"Shortcut on a removable drive starts a command interpreter: {e.name}", Severity.MEDIUM,
                Category.SUSPICIOUS,
                f"The shortcut {e.path} runs cmd/PowerShell/a script engine instead of opening a normal file or program. "
                "Shortcuts are a common way to disguise malware on USB drives and in downloads.",
                e.path, {"indicators": [i.title for i in inds], "strings": strings},
                "Do not open the shortcut; quarantine it and scan the drive.", _quarantine(e.path), mitre=["T1204.002", "T1091"]))

    # ---- programs masquerading as folders
    folder_names = {d.name.lower() for d in entries if d.is_dir}
    for e in entries:
        if e.is_dir or e.ext not in ("exe", "scr", "com", "pif"):
            continue
        twin_dir = e.stem.lower() in folder_names
        if twin_dir or _FOLDERISH_EXE.match(e.name):
            out.append(Finding(
                "AEG-USB-FOLDEREXE", f"Program disguised as a folder: {e.name}", Severity.HIGH, Category.SUSPICIOUS,
                f"{e.path} is a program named like a folder or common user folder"
                + (f" and sits next to a real folder called '{e.stem}'" if twin_dir else "")
                + ". USB worms copy themselves as 'Photos.exe', 'Documents.exe' ... with a folder icon so that a double-click "
                  "on the 'folder' runs the malware.",
                e.path, {"matches_folder": twin_dir, "size": e.size},
                "Do not double-click it. Quarantine it, then open the real folder instead; scan the drive.",
                _quarantine(e.path), mitre=["T1036.005", "T1091"]))

    # ---- hiding places used by old worms
    if is_root:
        for d in entries:
            if d.is_dir and d.name.lower() in ("recycler", "recycled"):
                bad = _executables_under(d.path)
                if bad:
                    out.append(Finding(
                        "AEG-USB-RECYCLER", "Programs hidden inside a fake RECYCLER folder on a removable drive", Severity.HIGH,
                        Category.SUSPICIOUS,
                        f"The folder {d.path} contains {len(bad)} program(s). The RECYCLER folder is an old Windows Recycle Bin "
                        "location that USB worms abuse as a hiding place; modern Windows only uses $RECYCLE.BIN.",
                        d.path, {"programs": bad[:10]}, "Quarantine the programs and scan the drive.",
                        _quarantine(bad[0]) if bad else None, mitre=["T1091", "T1564.001"]))
    return out


def _executables_under(directory: str, depth: int = 3, limit: int = 20) -> List[str]:
    found: List[str] = []

    def walk(d: str, level: int) -> None:
        for e in read_entries(d, 500):
            if len(found) >= limit:
                return
            if e.is_dir:
                if level < depth:
                    walk(e.path, level + 1)
            elif e.ext in RUNNABLE_EXTS | {"dll"} and not re.match(r"^\$[RI]", e.name):
                found.append(e.path)

    walk(directory, 0)
    return found


# =========================================================================== drive scan


def walk_drive(root: str, max_depth: int, deadline: float) -> Iterator[Tuple[str, List[Entry], int]]:
    """Breadth-first (dirpath, entries, depth) over a drive with entry / depth / time caps. Special hiding dirs are
    analysed by ``analyse_level`` themselves and are not descended into here."""
    total = 0
    queue: List[Tuple[str, int]] = [(root, 0)]
    while queue:
        if time.monotonic() > deadline or total >= MAX_ENTRIES_PER_DRIVE:
            return
        path, depth = queue.pop(0)
        entries = read_entries(path)
        total += len(entries)
        yield path, entries, depth
        if depth < max_depth:
            for e in entries:
                if e.is_dir and e.name.lower() not in HIDING_DIRS and not e.name.startswith("$"):
                    queue.append((e.path, depth + 1))


def scan_drive(ctx: ScanContext, drive: RemovableDrive, deadline: float) -> Iterator[Finding]:
    max_depth = MAX_DEPTH_DEEP if ctx.deep else MAX_DEPTH
    cap = MAX_SCAN_FILES_DEEP if ctx.deep else MAX_SCAN_FILES
    label = drive.mountpoint
    to_scan: List[str] = []
    programs: List[Entry] = []
    counts: Dict[str, int] = {}
    for dirpath, entries, depth in walk_drive(drive.mountpoint, max_depth, deadline):
        if ctx.cancelled:
            return
        ctx.bump("usb_entries", len(entries))
        for f in analyse_level(dirpath, entries, depth == 0, label):
            counts[f.rule_id] = counts.get(f.rule_id, 0) + 1
            if counts[f.rule_id] <= MAX_FINDINGS_PER_RULE:
                yield f
        for e in entries:
            if not e.is_dir and e.ext in RUNNABLE_EXTS | {"lnk", "dll"} and depth <= 1:
                to_scan.append(e.path)
                if depth == 0 and e.ext in RUNNABLE_EXTS:
                    programs.append(e)
    scanned = 0
    for p in to_scan[:cap]:
        if ctx.cancelled or time.monotonic() > deadline:
            break
        scanned += 1
        try:
            for f in scan_file(ctx, Path(p)):
                f.evidence.setdefault("removable_drive", label)
                yield f
        except Exception as exc:  # pragma: no cover - defensive
            log.debug("scan_file failed for %s: %s", p, exc)
    ctx.bump("usb_files_scanned", scanned)
    if programs:
        yield Finding(
            "AEG-USB-PROGRAMS", f"Programs stored in the root of removable drive {label}", Severity.INFO, Category.SUSPICIOUS,
            f"{len(programs)} program/script file(s) sit in the top folder of {label}. That is normal for portable apps and "
            "installers, but worth knowing because anything started from a USB stick runs with your privileges.",
            label, {"programs": [e.name for e in programs][:25]}, "Only run programs from a drive you trust.", mitre=["T1091"])


# =========================================================================== USBSTOR history

USBSTOR_KEY = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
_PROP_GUID = "{83da6326-97a6-4088-9453-a1923f573b29}"
_DEV_RX = re.compile(r"(?i)^(?P<cls>[^&]+)&Ven_(?P<ven>[^&]*)&Prod_(?P<prod>[^&]*)(?:&Rev_(?P<rev>.*))?$")


def filetime_to_str(v: Any) -> str:
    """Registry FILETIME (8 raw bytes or int, 100 ns since 1601-01-01 UTC) -> 'YYYY-MM-DD HH:MM UTC'."""
    try:
        if isinstance(v, (bytes, bytearray)):
            if len(v) < 8:
                return ""
            ft = struct.unpack("<Q", bytes(v[:8]))[0]
        else:
            ft = int(v)
        if ft <= 0:
            return ""
        t = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(microseconds=ft // 10)
        return t.strftime("%Y-%m-%d %H:%M UTC")
    except (TypeError, ValueError, OverflowError, struct.error):
        return ""


def parse_usbstor_device(devkey: str, instance: str, values: Dict[str, Any], times: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    m = _DEV_RX.match(devkey)
    ven = (m.group("ven") if m else "").replace("_", " ").strip()
    prod = (m.group("prod") if m else devkey).replace("_", " ").strip()
    name = str(values.get("FriendlyName") or values.get("DeviceDesc") or "").split(";")[-1].strip()
    t = times or {}
    return {"vendor": ven, "product": prod, "revision": (m.group("rev") if m and m.group("rev") else ""),
            "serial": instance.rsplit("&", 1)[0] if instance.endswith(("&0", "&1")) else instance,
            "name": name or f"{ven} {prod}".strip(), "first_install": filetime_to_str(t.get("0065") or t.get("0064")),
            "last_connected": filetime_to_str(t.get("0066")), "last_removed": filetime_to_str(t.get("0067"))}


def collect_usbstor(subkeys=None, values=None, read=None) -> List[Dict[str, str]]:
    """USB storage devices ever connected (Windows registry). The three accessors are injectable for tests."""
    subkeys = subkeys or reg_subkeys
    values = values or reg_values
    read = read or reg_read
    out: List[Dict[str, str]] = []
    for dev in subkeys("HKLM", USBSTOR_KEY):
        for inst in subkeys("HKLM", f"{USBSTOR_KEY}\\{dev}"):
            base = f"{USBSTOR_KEY}\\{dev}\\{inst}"
            times = {}
            for code in ("0064", "0065", "0066", "0067"):
                v = read("HKLM", f"{base}\\Properties\\{_PROP_GUID}\\{code}", "")
                if v is not None:
                    times[code] = v
            out.append(parse_usbstor_device(dev, inst, values("HKLM", base) or {}, times))
    out.sort(key=lambda d: d["last_connected"], reverse=True)
    return out


# =========================================================================== AutoRun / AutoPlay policy

EXPLORER_POLICY_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
AUTOPLAY_HANDLERS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers"
DRIVE_REMOVABLE_BIT = 0x04


def _to_int(v: Any) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def evaluate_autorun_policy(hklm_no_type: Optional[int], hkcu_no_type: Optional[int], hklm_no_autorun: Optional[int],
                            hkcu_no_autorun: Optional[int], disable_autoplay: Optional[int]) -> Dict[str, Any]:
    """Interpret the AutoRun / AutoPlay policy values. 'autorun' = autorun.inf commands, 'autoplay' = the AutoPlay prompt."""
    no_autorun = bool(hklm_no_autorun == 1 or hkcu_no_autorun == 1)
    mask = 0
    for v in (hklm_no_type, hkcu_no_type):
        if v is not None:
            mask |= v
    removable_blocked = bool(mask & DRIVE_REMOVABLE_BIT)
    return {"autorun_disabled": no_autorun or removable_blocked, "autoplay_disabled": disable_autoplay == 1 or removable_blocked,
            "no_drive_type_mask": mask, "no_autorun": no_autorun, "disable_autoplay": disable_autoplay == 1}


def policy_results(pol: Dict[str, Any]) -> Tuple[List[CheckResult], List[Finding]]:
    checks: List[CheckResult] = []
    findings: List[Finding] = []
    checks.append(CheckResult(
        "AEG-USB-AUTORUN", "AutoRun is disabled for removable drives", CheckStatus.PASS if pol["autorun_disabled"] else CheckStatus.WARN,
        "autorun.inf commands are blocked by policy." if pol["autorun_disabled"] else
        "No policy blocks autorun.inf commands (Windows 7 and later already ignore them on USB sticks, but not on all drive types).",
        Category.SYSTEM))
    checks.append(CheckResult(
        "AEG-USB-AUTOPLAY", "AutoPlay is disabled for removable drives", CheckStatus.PASS if pol["autoplay_disabled"] else CheckStatus.WARN,
        "AutoPlay does not start anything automatically for removable drives." if pol["autoplay_disabled"] else
        "AutoPlay is enabled: plugging in a drive offers to run its content.", Category.SYSTEM))
    if not (pol["autorun_disabled"] and pol["autoplay_disabled"]):
        findings.append(Finding(
            "AEG-USB-POLICY", "AutoRun/AutoPlay is not restricted for removable drives", Severity.LOW, Category.SYSTEM,
            "Windows can offer to open or run content automatically when a USB drive is plugged in. Disabling AutoRun and "
            "AutoPlay for removable drives is a standard hardening step (CIS, Microsoft security baselines) that removes "
            "the plug-in-and-infect path used by USB worms and malicious 'dropped' drives.",
            "Windows AutoRun/AutoPlay policy",
            {"NoDriveTypeAutoRun": pol["no_drive_type_mask"], "NoAutorun": pol["no_autorun"],
             "DisableAutoplay": pol["disable_autoplay"]},
            "Turn off AutoPlay (Settings > Bluetooth & devices > AutoPlay) and/or apply the fix below, which sets the "
            "'Turn off AutoPlay' policy for all drives (value 255).",
            Remediation("set_registry_value", {"hive": "HKLM", "key": EXPLORER_POLICY_KEY, "value": "NoDriveTypeAutoRun", "data": 255},
                        "Turn off AutoRun/AutoPlay for all drive types (NoDriveTypeAutoRun = 255)"),
            mitre=["T1091"]))
    return checks, findings


def read_autorun_policy() -> Dict[str, Any]:
    r = lambda hive, key, val: _to_int(reg_read(hive, key, val))  # noqa: E731
    return evaluate_autorun_policy(
        r("HKLM", EXPLORER_POLICY_KEY, "NoDriveTypeAutoRun"), r("HKCU", EXPLORER_POLICY_KEY, "NoDriveTypeAutoRun"),
        r("HKLM", EXPLORER_POLICY_KEY, "NoAutorun"), r("HKCU", EXPLORER_POLICY_KEY, "NoAutorun"),
        r("HKCU", AUTOPLAY_HANDLERS_KEY, "DisableAutoplay"))


# =========================================================================== scanner


@register
class UsbScanner(Scanner):
    name = "usb"
    title = "Removable media review"
    description = ("Checks plugged-in USB/removable drives for autorun.inf, hidden programs and shortcut-virus patterns, "
                   "lists USB storage history and reviews the AutoRun/AutoPlay policy.")
    platforms = ("windows", "linux", "darwin")

    def run(self, ctx: ScanContext) -> Iterator[Emitted]:
        # ---- policy (Windows)
        if IS_WINDOWS:
            try:
                checks, findings = policy_results(read_autorun_policy())
                yield from checks
                yield from findings
            except Exception as exc:  # pragma: no cover - defensive
                yield CheckResult("AEG-USB-AUTORUN", "AutoRun policy", CheckStatus.ERROR, f"{type(exc).__name__}: {exc}", Category.SYSTEM)
        else:
            yield CheckResult("AEG-USB-AUTORUN", "AutoRun is disabled for removable drives", CheckStatus.SKIP,
                              "The Windows AutoRun/AutoPlay policy does not apply on this OS.", Category.SYSTEM)

        # ---- drives
        custom = ctx.options.get("usb_roots")
        try:
            drives = [RemovableDrive(str(p), reason="selected") for p in custom if os.path.isdir(str(p))] if custom \
                else find_removable_drives()
        except Exception as exc:
            log.debug("drive discovery failed: %s", exc)
            drives = []
        budget = float(ctx.options.get("usb_budget_s", 60) or 60)
        deadline = time.monotonic() + budget
        if not drives:
            yield CheckResult("AEG-USB-DRIVES", "Removable drives plugged in", CheckStatus.PASS,
                              "No USB/removable drive is currently connected.", Category.SUSPICIOUS)
        bad = 0
        for d in drives:
            if ctx.cancelled:
                return
            ctx.report(self.name, f"scanning removable drive {d.mountpoint}")
            ctx.bump("usb_drives")
            n = 0
            try:
                for f in scan_drive(ctx, d, deadline):
                    if f.severity >= Severity.MEDIUM:
                        n += 1
                    yield f
            except Exception as exc:
                log.warning("usb drive %s failed: %s", d.mountpoint, exc, exc_info=True)
                yield CheckResult("AEG-USB-DRIVES", f"Removable drive {d.mountpoint}", CheckStatus.ERROR,
                                  f"{type(exc).__name__}: {exc}", Category.SUSPICIOUS)
                continue
            bad += n
            yield CheckResult("AEG-USB-DRIVE-" + (re.sub(r"[^A-Za-z0-9]+", "", d.mountpoint) or "ROOT"),
                              f"Removable drive {d.mountpoint}", CheckStatus.FAIL if n else CheckStatus.PASS,
                              (f"{n} suspicious item(s) found." if n else "No suspicious items found.") + f" ({d.reason})",
                              Category.SUSPICIOUS)

        # ---- USBSTOR inventory (Windows only)
        if IS_WINDOWS:
            try:
                devices = collect_usbstor()
            except Exception as exc:  # pragma: no cover - defensive
                yield CheckResult("AEG-USB-HISTORY", "USB storage history", CheckStatus.ERROR, f"{type(exc).__name__}: {exc}",
                                  Category.PRIVACY)
                return
            yield CheckResult("AEG-USB-HISTORY", "USB storage history", CheckStatus.PASS,
                              f"{len(devices)} USB storage device(s) have been connected to this PC.", Category.PRIVACY)
            if devices:
                yield Finding(
                    "AEG-USB-HISTORY", f"{len(devices)} USB storage device(s) have been connected to this PC", Severity.INFO,
                    Category.PRIVACY,
                    "Windows remembers every USB storage device that was ever plugged in (name, serial number, first and last "
                    "connection). This is an inventory only - useful to check that nobody connected a device you do not know.",
                    "HKLM\\" + USBSTOR_KEY, {"devices": devices[:50], "total": len(devices)},
                    "Review the list; devices you do not recognise may be worth investigating.", mitre=["T1091", "T1052.001"])
