"""Camera, microphone & screen access review.

Spyware, remote-access trojans and stalkerware watch their victims through the webcam, the microphone, the screen and
keyboard monitoring. The operating system records which programs used those capabilities; this scanner reviews that
record and reports programs that should never be using them.

* **Windows**: the CapabilityAccessManager ConsentStore (``HKCU`` and ``HKLM``) lists, for the camera, microphone,
  location and (when present) the screen-capture capabilities, every Store app and every desktop program that asked for
  access, with the time of its last use (``LastUsedTimeStart`` / ``LastUsedTimeStop``, FILETIME). A stop time of 0 with a
  start time means the program is using the device right now. Reported are
  - script hosts and system utilities that have no business using a camera or microphone (rundll32, mshta, wscript,
    msbuild ... HIGH; PowerShell / cmd MEDIUM),
  - programs running from user-writable staging folders (Temp, Downloads, Public, the Recycle Bin, the root of
    ProgramData / AppData\\Roaming / AppData\\Local) (MEDIUM),
  - either of the above while the device is in use right now (one level higher), and programs that deleted themselves
    after using the device,
  and every capability gets an INFO inventory of the apps that used it in the last 30 days.
* **macOS**: the TCC privacy database (user and system) lists the programs that are allowed to use the camera, microphone,
  screen recording, Accessibility, Input Monitoring and synthetic input. Allowed programs that live in temporary / hidden
  folders or are script interpreters are reported. Reading the database needs Full Disk Access.
* **Linux** keeps no system-wide record of device use, so the scanner only says that there is nothing to review.

FILETIME conversion, path decoding, the registry collector, the TCC reader and both classifiers are pure functions with
injectable readers, unit-tested on any OS.
"""

from __future__ import annotations

import datetime as dt
import logging
import os
import re
import shutil
import sqlite3
import struct
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

from aegis.core.models import Category, CheckResult, CheckStatus, Finding, Remediation, Severity
from aegis.core.platform import IS_MAC, IS_WINDOWS, reg_subkeys, reg_values
from aegis.scanners.base import Emitted, ScanContext, Scanner, register

log = logging.getLogger("aegis.privacy")

RECENT_DAYS = 30
MAX_INVENTORY = 50
MAX_INFO_FINDINGS = 15  # "no longer on disk" notes per capability; they are background noise by nature

Verdict = Tuple[Severity, List[str], List[str]]  # (severity, reasons, MITRE ids)


@dataclass(frozen=True)
class Capability:
    key: str  # ConsentStore sub-key (Windows) or TCC service name (macOS)
    tag: str  # suffix of the AEG-PRIV-* rule id
    phrase: str  # reads after "used" / "allowed to use"
    abuse: str  # how malware abuses it (goes into the description)
    mitre: Tuple[str, ...] = ()
    pane: str = ""  # Settings page where access can be switched off
    toggle: str = ""  # Windows: the switch for desktop programs on that page
    optional: bool = False  # Windows: only reviewed when the key exists
    flag_severity: Severity = Severity.MEDIUM  # macOS: severity of a suspicious program


_SPY = "Spyware, remote-access trojans (RATs) and stalkerware "

WINDOWS_CAPABILITIES: Tuple[Capability, ...] = (
    Capability("webcam", "CAMERA", "the camera",
               _SPY + "secretly switch on the camera to watch and photograph people.",
               ("T1125",), "Camera", "Let desktop apps access your camera"),
    Capability("microphone", "MICROPHONE", "the microphone",
               _SPY + "secretly record conversations and the room through the microphone.",
               ("T1123",), "Microphone", "Let desktop apps access your microphone"),
    Capability("location", "LOCATION", "your location",
               _SPY + "read the device location to track where its owner is.",
               (), "Location", "Let desktop apps access your location"),  # no ATT&CK technique mapped on purpose
    Capability("graphicsCaptureProgrammatic", "SCREEN", "screen capture",
               _SPY + "capture the screen without the user picking a window, to steal what is shown on it (messages, "
                      "banking pages, documents).", ("T1113",), optional=True),
    Capability("graphicsCaptureWithoutBorder", "SCREEN-BORDERLESS", "borderless screen capture",
               _SPY + "capture the screen without the visible border Windows draws around a window that is being "
                      "captured, so the user does not notice.", ("T1113",), optional=True),
)

MAC_CAPABILITIES: Tuple[Capability, ...] = (
    Capability("kTCCServiceCamera", "CAMERA", "the camera",
               _SPY + "secretly switch on the camera to watch and photograph people.", ("T1125",), "Camera"),
    Capability("kTCCServiceMicrophone", "MICROPHONE", "the microphone",
               _SPY + "secretly record conversations and the room through the microphone.", ("T1123",), "Microphone"),
    Capability("kTCCServiceScreenCapture", "SCREEN", "screen recording",
               _SPY + "record the screen to steal what is shown on it (messages, banking pages, documents).",
               ("T1113",), "Screen & System Audio Recording", flag_severity=Severity.HIGH),
    Capability("kTCCServiceAccessibility", "ACCESSIBILITY", "Accessibility (control of the computer)",
               "A program with Accessibility access can read what is on screen and what is typed, and click and type "
               "for the user, which is how keyloggers and remote-control malware work on a Mac.",
               ("T1056.001",), "Accessibility", flag_severity=Severity.HIGH),
    Capability("kTCCServiceListenEvent", "INPUT-MONITORING", "Input Monitoring (keyboard capture)",
               "Input Monitoring lets a program see every key that is pressed, in every app, which is the basis of "
               "keyloggers.", ("T1056.001",), "Input Monitoring", flag_severity=Severity.HIGH),
    Capability("kTCCServicePostEvent", "SYNTHETIC-INPUT", "synthetic keyboard and mouse input",
               "A program that may post synthetic input can press keys and click as if it were the user, which remote-"
               "control malware uses.", (), "", flag_severity=Severity.HIGH),  # no ATT&CK technique mapped on purpose
)
WINDOWS_BY_KEY = {c.key: c for c in WINDOWS_CAPABILITIES}
MAC_BY_KEY = {c.key: c for c in MAC_CAPABILITIES}


# =========================================================================== helpers (pure)

_EPOCH_1601 = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
_SANE_FROM = dt.datetime(2000, 1, 1, tzinfo=dt.timezone.utc)
_SANE_TO = dt.datetime(2100, 1, 1, tzinfo=dt.timezone.utc)
_MIN_TIME = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _sane(when: dt.datetime) -> Optional[dt.datetime]:
    return when if _SANE_FROM <= when < _SANE_TO else None


def _filetime_int(value: Any) -> Optional[int]:
    """FILETIME as an integer: REG_QWORD ints and 8 raw bytes are accepted; anything else gives None."""
    try:
        if value is None or isinstance(value, bool):
            return None
        if isinstance(value, (bytes, bytearray)):
            if len(value) < 8:
                return None
            return struct.unpack("<Q", bytes(value[:8]))[0]
        return int(value)
    except (TypeError, ValueError, OverflowError, struct.error):
        return None


def filetime_to_datetime(value: Any) -> Optional[dt.datetime]:
    """Registry FILETIME (100 ns since 1601-01-01 UTC; REG_QWORD int or 8 raw bytes) -> aware UTC datetime.
    0, missing, malformed and absurd values (outside 2000-2100) give None."""
    ft = _filetime_int(value)
    if ft is None or ft <= 0:
        return None
    try:
        return _sane(_EPOCH_1601 + dt.timedelta(microseconds=ft // 10))
    except OverflowError:
        return None


def unix_to_datetime(value: Any) -> Optional[dt.datetime]:
    """Unix seconds -> aware UTC datetime (None for 0, missing and absurd values)."""
    try:
        if value is None or isinstance(value, bool) or float(value) <= 0:
            return None
        return _sane(dt.datetime.fromtimestamp(float(value), tz=dt.timezone.utc))
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _iso(when: Optional[dt.datetime]) -> Optional[str]:
    return when.isoformat(timespec="seconds") if when else None


def _fmt(when: Optional[dt.datetime]) -> str:
    return when.strftime("%Y-%m-%d %H:%M UTC") if when else "an unknown time"


def _basename(path: str) -> str:
    return re.split(r"[\\/]", (path or "").rstrip("\\/"))[-1]


def _plural(n: int, one: str, many: str) -> str:
    return one if n == 1 else many


def decode_nonpackaged_name(name: str) -> str:
    """'C:#Program Files#Zoom#bin#Zoom.exe' -> 'C:\\Program Files\\Zoom\\bin\\Zoom.exe'. A registry key name cannot hold a
    backslash, so the ConsentStore writes '#' for every path separator."""
    return (name or "").strip().replace("#", "\\")


def _winpath(path: str) -> str:
    """Lower-case Windows path with backslashes and no \\\\?\\ prefix, for comparisons."""
    p = (path or "").strip().strip('"').replace("/", "\\").lower()
    return p[4:] if p.startswith("\\\\?\\") else p


# Windows programs that have no business using a camera or microphone
HIGH_RISK_HOSTS = frozenset({"rundll32.exe", "regsvr32.exe", "mshta.exe", "wscript.exe", "cscript.exe", "msbuild.exe",
                             "installutil.exe", "regasm.exe", "regsvcs.exe"})
SHELL_HOSTS = frozenset({"powershell.exe", "pwsh.exe", "cmd.exe"})

_STAGING_DIRS = (
    ("\\appdata\\local\\temp\\", "a Temp folder"),
    ("\\windows\\temp\\", "the Windows Temp folder"),
    ("\\downloads\\", "a Downloads folder"),
    ("\\users\\public\\", "the shared Public profile"),
    ("\\$recycle.bin\\", "the Recycle Bin"),
)
_STAGING_ROOTS = (  # programs sitting directly in these folders (the parent IS the folder)
    (re.compile(r"^[a-z]:\\programdata\\[^\\]+$"), "the top level of ProgramData"),
    (re.compile(r"\\appdata\\roaming\\[^\\]+$"), "the top level of AppData\\Roaming"),
    (re.compile(r"\\appdata\\local\\[^\\]+$"), "the top level of AppData\\Local"),
)
_PROTECTED_WIN = re.compile(r"^[a-z]:\\(?:windows|program files(?: \(x86\))?)\\")
_VERSION_SEGMENT = re.compile(r"^(?:app-|v)?\d+(?:\.\d+)+(?:[-+_.].*)?$")
_UPDATER_SEGMENTS = frozenset({"current", "windowsapps"})  # folders auto-updaters replace wholesale


def staging_location(path: str) -> str:
    """Description of the user-writable staging folder a Windows program runs from ('' if it is not in one)."""
    p = _winpath(path)
    for needle, label in _STAGING_DIRS:
        if needle in p:
            return label
    for rx, label in _STAGING_ROOTS:
        if rx.search(p):
            return label
    return ""


def is_versioned_path(path: str) -> bool:
    """True if a folder of the path is a version number (``1.2.3.4``, ``app-1.2.3``) or an updater folder (``current``):
    auto-updaters delete these, so a missing program there is normal."""
    segments = [s for s in re.split(r"[\\/]", (path or "").lower())[:-1] if s]
    return any(s in _UPDATER_SEGMENTS or _VERSION_SEGMENT.match(s) for s in segments)


def _path_exists(path: str) -> bool:
    return os.path.exists(path)


def _dedupe(items: Sequence[Any], key, rank) -> List[Any]:
    best: Dict[Any, Any] = {}
    for it in items:
        k = key(it)
        if k not in best or rank(it) > rank(best[k]):
            best[k] = it
    return list(best.values())


# =========================================================================== Windows: ConsentStore

CONSENT_KEY = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
NONPACKAGED = "NonPackaged"
WINDOWS_HIVES = ("HKCU", "HKLM")


@dataclass
class UsageRecord:
    """One ConsentStore entry: a Store app or desktop program and its last use of one capability."""

    capability: str
    hive: str
    app: str  # Store package family name, or the full path of the desktop program
    packaged: bool = False
    key: str = ""  # registry key (below the hive) the record came from
    permission: str = ""  # "Allow" / "Deny" / ""
    last_start: Optional[dt.datetime] = None
    last_stop: Optional[dt.datetime] = None
    in_use: bool = False  # start time set and stop time 0: the device is in use right now
    exists: Optional[bool] = None  # does the program still exist on disk? None = unknown (Store apps, UNC paths)

    @property
    def last_used(self) -> Optional[dt.datetime]:
        times = [t for t in (self.last_start, self.last_stop) if t]
        return max(times) if times else None

    @property
    def used(self) -> bool:
        return self.in_use or self.last_used is not None

    @property
    def name(self) -> str:
        return self.app if self.packaged else (_basename(self.app) or self.app)

    def rank(self) -> Tuple[bool, dt.datetime]:
        return self.in_use, self.last_used or _MIN_TIME


def _value(values: Dict[str, Any], name: str) -> Any:
    if name in values:
        return values[name]
    low = name.lower()
    for k, v in values.items():
        if str(k).lower() == low:
            return v
    return None


def _exists_or_none(path_exists, path: str) -> Optional[bool]:
    if not re.match(r"^[A-Za-z]:\\", path):  # UNC and odd names: never touch the network or guess
        return None
    try:
        return bool(path_exists(path))
    except (OSError, ValueError):
        return None


def make_record(capability: str, hive: str, key: str, app: str, packaged: bool, values: Dict[str, Any],
                exists: Optional[bool] = None) -> UsageRecord:
    start_raw = _filetime_int(_value(values, "LastUsedTimeStart"))
    stop_raw = _filetime_int(_value(values, "LastUsedTimeStop"))
    start = filetime_to_datetime(start_raw)
    perm = _value(values, "Value")
    return UsageRecord(capability, hive, app, packaged, key, perm if isinstance(perm, str) else "", start,
                       filetime_to_datetime(stop_raw), start is not None and stop_raw == 0, exists)


def collect_usage(capability: str, subkeys=None, values=None, path_exists=None,
                  hives: Sequence[str] = WINDOWS_HIVES) -> List[UsageRecord]:
    """Every Store app (direct subkeys) and desktop program (``NonPackaged`` subkeys) under one ConsentStore capability, for
    each hive. The registry readers and the path-exists check are injectable for tests."""
    subkeys = subkeys or reg_subkeys
    values = values or reg_values
    path_exists = path_exists or _path_exists
    base = f"{CONSENT_KEY}\\{capability}"
    out: List[UsageRecord] = []
    for hive in hives:
        for sub in subkeys(hive, base) or []:
            if sub.lower() == NONPACKAGED.lower():
                continue
            key = f"{base}\\{sub}"
            out.append(make_record(capability, hive, key, sub, True, values(hive, key) or {}))
        for sub in subkeys(hive, f"{base}\\{NONPACKAGED}") or []:
            key = f"{base}\\{NONPACKAGED}\\{sub}"
            app = decode_nonpackaged_name(sub)
            out.append(make_record(capability, hive, key, app, False, values(hive, key) or {},
                                   _exists_or_none(path_exists, app)))
    return out


def read_switches(capability: str, values=None, hives: Sequence[str] = WINDOWS_HIVES) -> Dict[str, str]:
    """The global Allow/Deny ``Value`` on the capability key itself, per hive (HKCU = this user, HKLM = this device)."""
    values = values or reg_values
    out: Dict[str, str] = {}
    for hive in hives:
        v = _value(values(hive, f"{CONSENT_KEY}\\{capability}") or {}, "Value")
        if isinstance(v, str) and v:
            out[hive] = v
    return out


def dedupe_records(records: Sequence[UsageRecord]) -> List[UsageRecord]:
    """One record per program and capability (the same program can appear under HKCU and HKLM); the most recent wins."""
    return _dedupe(records, lambda r: (r.capability, r.app.lower()), UsageRecord.rank)


def recent_usage(records: Sequence[UsageRecord], now: Optional[dt.datetime] = None,
                 days: int = RECENT_DAYS) -> List[UsageRecord]:
    """Records of programs that used the device within the last ``days`` days (or are using it now), newest first."""
    cutoff = (now or _utcnow()) - dt.timedelta(days=days)
    out = [r for r in records if r.in_use or (r.last_used is not None and r.last_used >= cutoff)]
    return sorted(out, key=UsageRecord.rank, reverse=True)


def is_protected_path(path: str) -> bool:
    """Windows and Program Files: files there are never quarantined automatically."""
    return bool(_PROTECTED_WIN.match(_winpath(path)))


def classify_usage(rec: UsageRecord) -> Optional[Verdict]:
    """(severity, reasons, MITRE ids) for a program that used a capability, or None if it looks normal.

    HIGH: script hosts / LOLBins (rundll32, mshta, wscript ...); MEDIUM: PowerShell / cmd and programs in user-writable
    staging folders; one level higher while the device is in use right now. A program that no longer exists is INFO,
    unless it sat in a staging folder (then the staging severity stays and the deletion is added as a reason). Store apps and
    programs without a recorded use are never flagged."""
    if rec.packaged or not rec.used:
        return None
    cap = WINDOWS_BY_KEY.get(rec.capability)
    mitre = list(cap.mitre) if cap else []
    phrase = cap.phrase if cap else "a device"
    name = rec.name
    sev: Optional[Severity] = None
    reasons: List[str] = []
    if name.lower() in HIGH_RISK_HOSTS:
        sev = Severity.HIGH
        reasons.append(f"{name} is a script host / system utility that has no business using {phrase}")
    elif name.lower() in SHELL_HOSTS:
        sev = Severity.MEDIUM
        reasons.append(f"{name} is a command shell that has no business using {phrase}")
    where = staging_location(rec.app)
    if where:
        sev = max(sev or Severity.MEDIUM, Severity.MEDIUM)
        reasons.append(f"it runs from {where}, a folder any program can write to and that malware favours, not from "
                       "a normal install folder")
    if sev is not None:
        if rec.in_use:
            sev = Severity(min(int(sev) + 1, int(Severity.CRITICAL)))
            reasons.append(f"Windows shows it using {phrase} right now")
        if where and rec.exists is False:
            reasons.append("the program was deleted after using the device")
        return sev, reasons, mitre
    if rec.exists is False and not is_versioned_path(rec.app):
        return Severity.INFO, ["the program no longer exists on disk"], mitre
    return None


def _quarantine_fix(path: str, name: str) -> Remediation:
    return Remediation("quarantine_file", {"path": path}, f"Move {name} to quarantine (it can be restored)")


def usage_remediation(rec: UsageRecord) -> Optional[Remediation]:
    """Quarantine for a flagged program that still exists, but never for genuine Windows / Program Files binaries (a
    script host there is not the problem; whatever started it is)."""
    if rec.exists is not True or rec.packaged:
        return None
    if not staging_location(rec.app) and is_protected_path(rec.app):
        return None
    return _quarantine_fix(rec.app, rec.name)


def _usage_sentence(cap: Capability, rec: UsageRecord) -> str:
    if rec.in_use:
        return f"Windows still lists it as using {cap.phrase} right now (started {_fmt(rec.last_start)})"
    if rec.last_start and rec.last_stop:
        return f"it last used {cap.phrase} from {_fmt(rec.last_start)} to {_fmt(rec.last_stop)}"
    return f"it last used {cap.phrase} around {_fmt(rec.last_used)}"


def usage_evidence(rec: UsageRecord) -> Dict[str, Any]:
    return {"capability": rec.capability, "app": rec.app, "hive": rec.hive, "packaged": rec.packaged,
            "permission": rec.permission or None, "last_used_start": _iso(rec.last_start),
            "last_used_stop": _iso(rec.last_stop), "in_use_now": rec.in_use, "exists_on_disk": rec.exists}


def _switch_off_hint(cap: Capability) -> str:
    if not cap.pane:
        return ""
    return (f" To stop desktop programs from using {cap.phrase} at all, open Settings > Privacy & security > {cap.pane} "
            f"and turn off '{cap.toggle}'.")


def usage_finding(cap: Capability, rec: UsageRecord, verdict: Verdict) -> Finding:
    sev, reasons, mitre = verdict
    name = rec.name
    low = name.lower()
    title = f"{name} appears to be using {cap.phrase} right now" if rec.in_use else f"{name} used {cap.phrase}"
    if sev == Severity.INFO:
        title += " (program no longer on disk)"
        desc = (f"Windows recorded that {rec.app} used {cap.phrase}: {_usage_sentence(cap, rec)}. The program no longer "
                "exists on disk, so it was uninstalled or deleted since. That is normal for software you removed "
                "yourself, but malware also deletes itself once it has finished spying, so check that you remember "
                "installing it.")
        rec_text = ("If you remember installing and later removing this program, no action is needed. If not, run a full "
                    "Aegis scan and review startup entries and scheduled tasks for what may have started it.")
    else:
        title += (" (script host / system utility)" if low in HIGH_RISK_HOSTS or low in SHELL_HOSTS
                  else " (runs from a user-writable folder)")
        desc = (f"Windows recorded that {rec.app} used {cap.phrase}: {_usage_sentence(cap, rec)}. Why this is suspicious: "
                f"{'; '.join(reasons)}. {cap.abuse} Genuine programs that use {cap.phrase} run from their own install "
                "folder; they are not script hosts or files dropped into temporary folders.")
        if rec.permission.lower() == "deny":
            desc += " Access is currently set to Deny for this program."
        if rec.exists is False:
            rec_text = ("The file is gone, so you cannot inspect it. Check that you recognise the program, look at recently "
                        "installed software, and run a full Aegis scan and review startup entries and scheduled tasks "
                        "for what may have started it.")
        elif rec.exists is True and not staging_location(rec.app) and is_protected_path(rec.app):
            rec_text = (f"{name} is a genuine Windows component here; the request comes from whatever started it (a "
                        "script, a shortcut or a malicious DLL). Review startup entries and scheduled tasks, check "
                        "Task Manager for what is running it, and run a full Aegis scan.")
        else:
            rec_text = (f"Check whether you recognise {name}: look at the file's properties (Details and Digital Signatures "
                        "tabs) or search for its name online, and look for it in Task Manager. If you did not install "
                        "it or cannot verify it, quarantine it (the fix below), run a full Aegis scan and treat the PC "
                        "as possibly compromised.")
        rec_text += _switch_off_hint(cap)
    return Finding(
        rule_id=f"AEG-PRIV-{cap.tag}", title=title, severity=sev, category=Category.PRIVACY, description=desc,
        location=rec.app, evidence={**usage_evidence(rec), "reasons": reasons}, recommendation=rec_text,
        remediation=usage_remediation(rec) if sev >= Severity.MEDIUM else None, mitre=mitre)


def _inventory_key(cap: Capability) -> str:
    return f"HKCU\\{CONSENT_KEY}\\{cap.key}"


def inventory_finding(cap: Capability, recent: Sequence[UsageRecord]) -> Finding:
    """INFO list of the programs that used the capability in the last 30 days (newest first, at most 50)."""
    n = len(recent)
    apps = [{"app": r.app, "last_used": _iso(r.last_used), "in_use_now": r.in_use} for r in recent[:MAX_INVENTORY]]
    return Finding(
        rule_id=f"AEG-PRIV-{cap.tag}-INVENTORY",
        title=f"{n} {_plural(n, 'app', 'apps')} used {cap.phrase} in the last {RECENT_DAYS} days",
        severity=Severity.INFO, category=Category.PRIVACY,
        description=(f"Windows remembers which Store apps and desktop programs used {cap.phrase} and when. This is an "
                     "inventory only (newest first) - useful to check that you recognise every program on the list."),
        location=_inventory_key(cap),
        evidence={"capability": cap.key, "apps": apps, "total": n, "window_days": RECENT_DAYS},
        recommendation="Review the list; a program you do not recognise may be worth investigating.", mitre=list(cap.mitre))


def _check(cap: Capability, status: str, detail: str, title: Optional[str] = None) -> CheckResult:
    return CheckResult(f"AEG-PRIV-{cap.tag}", title or f"Apps that used {cap.phrase}", status, detail, Category.PRIVACY)


def _switch_text(switches: Dict[str, str]) -> str:
    if not switches:
        return "No global on/off setting is recorded."
    parts = [f"{label}: {switches[h]}" for h, label in (("HKCU", "your account"), ("HKLM", "this PC")) if h in switches]
    off = any(v.lower() == "deny" for v in switches.values())
    return "Windows access setting - " + ", ".join(parts) + (" (access is switched off)." if off else ".")


def review_usage(cap: Capability, records: Sequence[UsageRecord], switches: Optional[Dict[str, str]] = None,
                 now: Optional[dt.datetime] = None) -> Tuple[CheckResult, List[Finding]]:
    """Check result and findings for one Windows capability."""
    switches = switches or {}
    records = dedupe_records(records)
    if not records and not switches:
        return _check(cap, CheckStatus.SKIP, f"Windows has no record of {cap.phrase} being used on this PC."), []
    findings: List[Finding] = []
    flagged: List[UsageRecord] = []
    gone = 0
    for rec in sorted(records, key=UsageRecord.rank, reverse=True):
        verdict = classify_usage(rec)
        if verdict is None:
            continue
        if verdict[0] >= Severity.MEDIUM:
            flagged.append(rec)
        else:
            gone += 1
            if gone > MAX_INFO_FINDINGS:
                continue
        findings.append(usage_finding(cap, rec, verdict))
    recent = recent_usage(records, now)
    if recent:
        findings.append(inventory_finding(cap, recent))
    seen = f"{len(recent)} {_plural(len(recent), 'app', 'apps')} used {cap.phrase} in the last {RECENT_DAYS} days"
    note = f" {gone} program(s) that no longer exist were also listed." if gone else ""
    if flagged:
        names = ", ".join(r.name for r in flagged[:5]) + (", ..." if len(flagged) > 5 else "")
        detail = f"{len(flagged)} suspicious program(s): {names}. {seen}.{note} {_switch_text(switches)}"
        return _check(cap, CheckStatus.FAIL, detail), findings
    detail = f"No suspicious program used {cap.phrase}; {seen}.{note} {_switch_text(switches)}"
    return _check(cap, CheckStatus.PASS, detail), findings


# =========================================================================== macOS: TCC database

TCC_USER_DB = "~/Library/Application Support/com.apple.TCC/TCC.db"
TCC_SYSTEM_DB = "/Library/Application Support/com.apple.TCC/TCC.db"
TCC_TIMEOUT_S = 1.0  # how long sqlite waits for a lock before the file is copied instead
_LOCK_HINTS = ("locked", "busy", "readonly")  # "readonly": a write-ahead log that needs a writable -shm file

_MAC_STAGING_PREFIXES = (
    ("/tmp/", "a temporary folder"),
    ("/private/tmp/", "a temporary folder"),
    ("/var/folders/", "a temporary folder"),
    ("/private/var/folders/", "a temporary folder"),
    ("/users/shared/", "the shared Users folder"),
)
_MAC_DOWNLOADS = re.compile(r"^/users/[^/]+/downloads/")
_MAC_INTERPRETER = re.compile(r"^(?:osascript|python[\d.]*|perl[\d.]*|ruby[\d.]*|bash|sh|zsh|node)$")
_MAC_PROTECTED = ("/usr/", "/bin/", "/sbin/", "/system/", "/library/", "/applications/", "/opt/", "/private/etc/")


class TccError(Exception):
    """The TCC database could not be read."""


class TccAccessError(TccError):
    """Permission or sqlite error: macOS blocks the file without Full Disk Access."""


class TccMissingError(TccError):
    """The database file does not exist."""


class TccSchemaError(TccError):
    """The ``access`` table has an unknown layout."""


@dataclass
class TccEntry:
    service: str
    client: str  # bundle id or absolute path
    client_type: int  # 0 = bundle id, 1 = absolute path
    allowed: bool
    last_modified: Optional[dt.datetime] = None
    db: str = "user"
    exists: Optional[bool] = None  # only checked for allowed programs given by path

    @property
    def name(self) -> str:
        return (_basename(self.client) or self.client) if self.client_type == 1 else self.client


def tcc_database_paths() -> List[Tuple[str, str]]:
    return [("user", os.path.expanduser(TCC_USER_DB)), ("system", TCC_SYSTEM_DB)]


def _read_access_table(path: str, readonly: bool = True) -> List[Tuple[str, str, Any, bool, Any]]:
    """(service, client, client_type, allowed, last_modified) rows of the services we review. Handles both layouts:
    ``auth_value`` (2 = allowed, macOS 11+) and the older ``allowed`` (1 = allowed)."""
    if readonly:
        con = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True, timeout=TCC_TIMEOUT_S)
    else:
        con = sqlite3.connect(path, timeout=TCC_TIMEOUT_S)
    try:
        cols = {str(r[1]).lower() for r in con.execute("PRAGMA table_info(access)")}
        if not cols:
            raise TccSchemaError("the database has no 'access' table")
        if "auth_value" in cols:
            auth, allowed_value = "auth_value", 2
        elif "allowed" in cols:
            auth, allowed_value = "allowed", 1
        else:
            raise TccSchemaError("the 'access' table has neither an auth_value nor an allowed column")
        ctype = "client_type" if "client_type" in cols else "NULL"
        modified = "last_modified" if "last_modified" in cols else "NULL"
        marks = ",".join("?" for _ in MAC_CAPABILITIES)
        rows = con.execute(f"SELECT service, client, {ctype}, {auth}, {modified} FROM access WHERE service IN ({marks})",
                           [c.key for c in MAC_CAPABILITIES]).fetchall()
        return [(r[0], r[1], r[2], r[3] == allowed_value, r[4]) for r in rows]
    finally:
        con.close()


def _read_copy(path: str) -> List[Tuple[str, str, Any, bool, Any]]:
    """Read a private copy of a locked database (including its write-ahead log, so recent changes are not lost)."""
    with tempfile.TemporaryDirectory(prefix="aegis-tcc-") as tmp:
        dst = os.path.join(tmp, "TCC.db")
        shutil.copyfile(path, dst)
        for suffix in ("-wal", "-shm"):
            if os.path.exists(path + suffix):
                try:
                    shutil.copyfile(path + suffix, dst + suffix)
                except OSError:
                    pass
        return _read_access_table(dst, readonly=False)


def read_tcc_rows(path: str) -> List[Tuple[str, str, Any, bool, Any]]:
    """Rows of one TCC.db, opened read-only (a copy is read when the file is locked). Raises TccError subclasses."""
    try:
        os.stat(path)
    except FileNotFoundError as exc:
        raise TccMissingError(f"{path} does not exist") from exc
    except OSError as exc:
        raise TccAccessError(f"{type(exc).__name__}: {exc}") from exc
    try:
        return _read_access_table(path)
    except TccError:
        raise
    except sqlite3.OperationalError as exc:
        if not any(h in str(exc).lower() for h in _LOCK_HINTS):
            raise TccAccessError(f"sqlite: {exc}") from exc
    except (sqlite3.Error, OSError) as exc:
        raise TccAccessError(f"{type(exc).__name__}: {exc}") from exc
    try:
        return _read_copy(path)
    except TccError:
        raise
    except (sqlite3.Error, OSError) as exc:
        raise TccAccessError(f"the database is locked and a copy could not be read ({type(exc).__name__}: {exc})") from exc


def read_tcc_entries(label: str, path: str, path_exists=None) -> List[TccEntry]:
    """Entries of one TCC.db for the reviewed services (denied ones included, ``allowed`` says which)."""
    path_exists = path_exists or _path_exists
    out: List[TccEntry] = []
    for service, client, ctype, allowed, modified in read_tcc_rows(path):
        client = str(client or "")
        if not client:
            continue
        kind = ctype if isinstance(ctype, int) and ctype in (0, 1) else (1 if client.startswith("/") else 0)
        exists = None
        if kind == 1 and allowed:
            try:
                exists = bool(path_exists(client))
            except (OSError, ValueError):
                exists = None
        out.append(TccEntry(str(service), client, kind, allowed, unix_to_datetime(modified), label, exists))
    return out


def mac_staging_location(path: str) -> str:
    """Description of the temporary / shared / hidden folder a macOS program lives in ('' if it is not in one)."""
    low = (path or "").lower()
    for prefix, label in _MAC_STAGING_PREFIXES:
        if low.startswith(prefix):
            return label
    if _MAC_DOWNLOADS.match(low):
        return "the Downloads folder"
    segments = [s for s in (path or "").split("/")[:-1] if s]
    if any(s.startswith(".") and s not in (".", "..") for s in segments):
        return "a hidden folder"
    return ""


def classify_tcc(entry: TccEntry) -> Optional[Verdict]:
    """(severity, reasons, MITRE ids) for an allowed TCC entry, or None. Only programs given by path are judged (bundle
    ids are inventory only): a program in a temporary / shared / hidden folder or a script interpreter is HIGH for
    Accessibility, Input Monitoring, synthetic input and screen recording and MEDIUM for camera and microphone; a path that
    no longer exists is INFO unless it was in such a folder (then the severity stays and the deletion is added)."""
    cap = MAC_BY_KEY.get(entry.service)
    if cap is None or not entry.allowed or entry.client_type != 1:
        return None
    name = _basename(entry.client)
    reasons: List[str] = []
    where = mac_staging_location(entry.client)
    if where:
        reasons.append(f"it runs from {where}, a folder that malware favours, not from an Applications folder")
    if _MAC_INTERPRETER.match(name.lower()):
        reasons.append(f"{name} is a script interpreter, so any script run through it inherits this permission")
    if reasons:
        if where and entry.exists is False:
            reasons.append("the program was deleted after it was given access")
        return cap.flag_severity, reasons, list(cap.mitre)
    if entry.exists is False and not is_versioned_path(entry.client):
        return Severity.INFO, ["the program no longer exists on disk"], list(cap.mitre)
    return None


def tcc_remediation(entry: TccEntry) -> Optional[Remediation]:
    """Quarantine for a flagged program that still exists and is not a system interpreter or an installed application."""
    if entry.exists is not True or entry.client_type != 1:
        return None
    if not mac_staging_location(entry.client) and entry.client.lower().startswith(_MAC_PROTECTED):
        return None
    return _quarantine_fix(entry.client, entry.name)


def dedupe_tcc(entries: Sequence[TccEntry]) -> List[TccEntry]:
    """One entry per program and service (the user and system databases can both list it); the newest wins."""
    return _dedupe(entries, lambda e: (e.service, e.client.lower()), lambda e: e.last_modified or _MIN_TIME)


def tcc_finding(cap: Capability, entry: TccEntry, verdict: Verdict) -> Finding:
    sev, reasons, mitre = verdict
    name = entry.name
    when = f", last changed {_fmt(entry.last_modified)}" if entry.last_modified else ""
    ev = {"capability": entry.service, "app": entry.client, "client_type": "path", "allowed": entry.allowed,
          "permission_last_modified": _iso(entry.last_modified), "exists_on_disk": entry.exists,
          "database": entry.db, "reasons": reasons}
    if sev == Severity.INFO:
        title = f"{name} is allowed to use {cap.phrase} (program no longer on disk)"
        desc = (f"The macOS privacy database lists {entry.client} as allowed to use {cap.phrase}{when}, but the program no "
                "longer exists on disk. That is normal for software you removed yourself, but malware also deletes itself "
                "after it has been given access, so check that you remember installing it.")
        rec_text = ("If you remember installing and later removing this program, no action is needed. If not, review "
                    "login items and launch agents for what may have started it.")
    else:
        title = f"{name} is allowed to use {cap.phrase}" + (" (script interpreter)" if _MAC_INTERPRETER.match(name.lower())
                                                           else " (runs from a temporary or hidden folder)")
        desc = (f"The macOS privacy database lists {entry.client} as allowed to use {cap.phrase}{when}. Why this is "
                f"suspicious: {'; '.join(reasons)}. {cap.abuse} Genuine apps that need this permission are installed in "
                "Applications and identified by their bundle id; they are not interpreters or files in temporary or "
                "hidden folders.")
        if entry.exists is False:
            rec_text = ("The file is gone, so you cannot inspect it. Review login items and launch agents for what may "
                        "have started it, and run a full Aegis scan.")
        else:
            rec_text = (f"Check whether you recognise {name} and where it came from. If you did not set it up, quarantine "
                        "it (the fix below, if offered) and run a full Aegis scan.")
        rec_text += (f" Then open System Settings > Privacy & Security > {cap.pane} and remove it from the list."
                     if cap.pane else " Then review System Settings > Privacy & Security and remove its entry.")
    return Finding(
        rule_id=f"AEG-PRIV-{cap.tag}", title=title, severity=sev, category=Category.PRIVACY, description=desc,
        location=entry.client, evidence=ev, recommendation=rec_text,
        remediation=tcc_remediation(entry) if sev >= Severity.MEDIUM else None, mitre=mitre)


def tcc_inventory_finding(cap: Capability, allowed: Sequence[TccEntry]) -> Finding:
    n = len(allowed)
    ordered = sorted(allowed, key=lambda e: e.last_modified or _MIN_TIME, reverse=True)
    apps = [{"app": e.client, "client_type": "path" if e.client_type == 1 else "bundle id",
             "last_modified": _iso(e.last_modified), "database": e.db} for e in ordered[:MAX_INVENTORY]]
    return Finding(
        rule_id=f"AEG-PRIV-{cap.tag}-INVENTORY",
        title=f"{n} {_plural(n, 'app is', 'apps are')} allowed to use {cap.phrase}", severity=Severity.INFO,
        category=Category.PRIVACY,
        description=(f"The macOS privacy database (TCC) lists the apps that were given access to {cap.phrase}. This is an "
                     "inventory only (most recently changed first) - useful to check that you recognise every app."),
        location=f"TCC.db / {cap.key}", evidence={"capability": cap.key, "apps": apps, "total": n},
        recommendation=f"Review the list in System Settings > Privacy & Security{' > ' + cap.pane if cap.pane else ''}; "
                       "remove apps you do not recognise.", mitre=list(cap.mitre))


def review_tcc(cap: Capability, entries: Sequence[TccEntry],
               skipped: Sequence[str] = ()) -> Tuple[CheckResult, List[Finding]]:
    """Check result and findings for one macOS service."""
    allowed = dedupe_tcc([e for e in entries if e.service == cap.key and e.allowed])
    findings: List[Finding] = []
    flagged: List[TccEntry] = []
    gone = 0
    for entry in allowed:
        verdict = classify_tcc(entry)
        if verdict is None:
            continue
        if verdict[0] >= Severity.MEDIUM:
            flagged.append(entry)
        else:
            gone += 1
            if gone > MAX_INFO_FINDINGS:
                continue
        findings.append(tcc_finding(cap, entry, verdict))
    if allowed:
        findings.append(tcc_inventory_finding(cap, allowed))
    title = f"Apps allowed to use {cap.phrase}"
    seen = f"{len(allowed)} {_plural(len(allowed), 'app is', 'apps are')} allowed to use {cap.phrase}"
    note = (f" {gone} program(s) that no longer exist were also listed." if gone else "") + \
           (f" Not examined: the {' and '.join(skipped)} database." if skipped else "")
    if flagged:
        names = ", ".join(e.name for e in flagged[:5]) + (", ..." if len(flagged) > 5 else "")
        detail = f"{len(flagged)} suspicious program(s): {names}. {seen}.{note}"
        return _check(cap, CheckStatus.FAIL, detail, title), findings
    detail = f"No suspicious program is allowed to use {cap.phrase}; {seen}.{note}"
    return _check(cap, CheckStatus.PASS, detail, title), findings


def _tcc_skip_detail(label: str, path: str, exc: TccError) -> str:
    if isinstance(exc, TccMissingError):
        return f"The {label} privacy database was not found ({exc})."
    if isinstance(exc, TccSchemaError):
        return f"The {label} privacy database ({path}) has an unknown layout: {exc}."
    return (f"Could not read the {label} privacy database ({path}): {exc}. macOS only lets programs with Full Disk Access read "
            "it: open System Settings > Privacy & Security > Full Disk Access, add your terminal (or the Aegis app), "
            "then run the scan again.")


# =========================================================================== scanner

LINUX_NOTE = ("Linux keeps no system-wide record of which programs used the camera, microphone or screen, so there is "
              "nothing to review. To see what holds the camera open right now, run 'fuser -v /dev/video*'; desktop "
              "sandboxes (Flatpak, Snap) ask for permission through their own portals.")


@register
class PrivacyScanner(Scanner):
    name = "privacy"
    title = "Camera, microphone & screen access review"
    description = ("Reviews the OS record of which programs used the camera, microphone, location and screen (Windows "
                   "ConsentStore, macOS TCC database) and flags script hosts, programs in temporary folders and other apps "
                   "that should never be using them")
    platforms = ("windows", "linux", "darwin")

    def run(self, ctx: ScanContext) -> Iterator[Emitted]:
        try:
            if IS_WINDOWS:
                yield from self._run_windows(ctx)
            elif IS_MAC:
                yield from self._run_macos(ctx)
            else:
                yield CheckResult("AEG-PRIV-LINUX", self.title, CheckStatus.SKIP, LINUX_NOTE, Category.PRIVACY)
        except Exception as exc:  # never raise out of run()
            log.warning("privacy scan failed: %s", exc, exc_info=True)
            yield CheckResult("AEG-PRIV-ERROR", self.title, CheckStatus.ERROR, f"{type(exc).__name__}: {exc}", Category.PRIVACY)

    def _run_windows(self, ctx: ScanContext) -> Iterator[Emitted]:
        for cap in WINDOWS_CAPABILITIES:
            if ctx.cancelled:
                return
            ctx.report(self.name, f"reviewing programs that used {cap.phrase}")
            try:
                records = collect_usage(cap.key)
                switches = read_switches(cap.key)
                if cap.optional and not records and not switches:
                    continue
                check, findings = review_usage(cap, records, switches)
            except Exception as exc:
                log.warning("privacy review of %s failed: %s", cap.key, exc, exc_info=True)
                yield _check(cap, CheckStatus.ERROR, f"{type(exc).__name__}: {exc}")
                continue
            ctx.bump("privacy_records", len(records))
            ctx.bump("privacy_flagged", sum(1 for f in findings if f.severity >= Severity.MEDIUM))
            yield check
            yield from findings

    def _run_macos(self, ctx: ScanContext) -> Iterator[Emitted]:
        entries: List[TccEntry] = []
        readable: List[str] = []
        skipped: List[str] = []
        for label, path in tcc_database_paths():
            if ctx.cancelled:
                return
            ctx.report(self.name, f"reading the {label} privacy database")
            try:
                entries += read_tcc_entries(label, path)
                readable.append(label)
            except TccError as exc:
                skipped.append(label)
                yield CheckResult(f"AEG-PRIV-TCC-{label.upper()}", f"macOS privacy database ({label})", CheckStatus.SKIP,
                                  _tcc_skip_detail(label, path, exc), Category.PRIVACY)
            except Exception as exc:
                skipped.append(label)
                log.warning("reading %s failed: %s", path, exc, exc_info=True)
                yield CheckResult(f"AEG-PRIV-TCC-{label.upper()}", f"macOS privacy database ({label})", CheckStatus.ERROR,
                                  f"{type(exc).__name__}: {exc}", Category.PRIVACY)
        if not readable:
            return
        ctx.bump("privacy_records", len(entries))
        for cap in MAC_CAPABILITIES:
            if ctx.cancelled:
                return
            try:
                check, findings = review_tcc(cap, entries, skipped)
            except Exception as exc:
                log.warning("privacy review of %s failed: %s", cap.key, exc, exc_info=True)
                yield _check(cap, CheckStatus.ERROR, f"{type(exc).__name__}: {exc}", f"Apps allowed to use {cap.phrase}")
                continue
            ctx.bump("privacy_flagged", sum(1 for f in findings if f.severity >= Severity.MEDIUM))
            yield check
            yield from findings
