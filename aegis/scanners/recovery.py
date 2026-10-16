"""Backup & ransomware recovery readiness.

Ransomware is survivable when there is a recent backup the attacker could not reach. This scanner does not look for
malware; it answers one question: if every file on this computer were encrypted today, could you get them back? It reviews
four recovery layers and grades the whole:

* **restore points** - Windows System Restore / Volume Shadow Copies of the system drive (System Protection switch in the
  registry, newest restore point and shadow copy from ONE batched PowerShell call); Linux snapshots (Timeshift, snapper,
  ZFS, Btrfs). Windows needs administrator rights to list restore points and shadow copies: without them the layer says
  "not checked" instead of reporting a problem. Windows Server has no System Restore and is skipped.
* **file backup** - Windows File History (``HKCU`` FileHistory key: on/off, group policy, last backup), macOS Time Machine
  (``tmutil destinationinfo`` / ``tmutil latestbackup`` / ``defaults read com.apple.TimeMachine``; the snapshot dates in the
  preferences answer even when ``tmutil`` needs Full Disk Access), Linux restic / BorgBackup / Deja Dup.
* **cloud sync with version history** - OneDrive (Known Folder Move values and Desktop / Documents / Pictures redirected into
  the OneDrive folder), Google Drive and Dropbox desktop clients, macOS iCloud Drive "Desktop & Documents". These services
  keep earlier versions of a file, so files can be restored as they were before the attack; a client only protects what is
  inside its folders, which the result says.
* **offline / off-site copy** - the copy ransomware cannot reach. No scanner can verify it, so it is always reported as not
  verified.

One INFO finding "Ransomware recovery readiness: <grade>" lists every layer; MEDIUM / LOW findings are raised for a switched-
off or empty restore layer, personal files without any backup, an unconfigured Time Machine and Linux hosts without any tool,
and for backups older than 30 days (Time Machine: 14). Deleting shadow copies (``vssadmin delete shadows``) is already
reported by the event-log scanner and the Sigma rules, so only what exists now is examined here.

The scanner is read-only: it never creates, deletes or resizes a restore point, shadow copy or backup and offers no
automatic fix (undoing "turn System Protection on" would delete every restore point), only the exact steps to take.

Every external command goes through an injectable runner (``platform.run`` / ``powershell_json``) with a timeout; registry
readers, home / root folders and the clock are injectable too, so the parsers and the grading are unit-tested on any OS.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple

from aegis.core.models import Category, CheckResult, CheckStatus, Finding, Severity
from aegis.core.platform import IS_MAC, IS_WINDOWS, powershell_json, reg_read, reg_subkeys, reg_values, run, user_home
from aegis.scanners.base import Emitted, ScanContext, Scanner, register

log = logging.getLogger("aegis.recovery")

STALE_DAYS = 30  # a restore point / File History / Linux backup older than this is reported (LOW)
TIME_MACHINE_STALE_DAYS = 14
CMD_TIMEOUT_S = 15
PS_TIMEOUT_S = 90
MAX_SNAPPER_CONFIGS = 5

# ATT&CK: T1490 Inhibit System Recovery (no restore points / shadow copies to go back to), T1486 Data Encrypted for Impact
MITRE_RESTORE = ["T1490"]
MITRE_BACKUP = ["T1486"]

# =========================================================================== layers

RESTORE, BACKUP, CLOUD, OFFLINE = "restore", "backup", "cloud", "offline"
LAYER_ORDER = (RESTORE, BACKUP, CLOUD, OFFLINE)
LAYER_TITLES = {RESTORE: "Restore points & snapshots", BACKUP: "File backup", CLOUD: "Cloud sync with version history",
                OFFLINE: "Offline or off-site copy"}
_LAYER_NAMES = {RESTORE: "restore points", BACKUP: "a file backup", CLOUD: "cloud sync with version history"}

OK, STALE, MISSING, UNKNOWN, NA = "ok", "stale", "missing", "unknown", "n/a"


@dataclass
class Layer:
    """State of one recovery layer: ``state`` is ok (in place and recent), stale (in place but old), missing (not found
    or switched off), unknown (could not be checked) or n/a (does not apply to this system)."""

    key: str
    state: str
    detail: str = ""
    newest: Optional[dt.datetime] = None
    severity: Optional[Severity] = None  # of the finding raised for this layer, if any
    hint: str = ""  # short next step for the summary when the layer is missing or stale
    covers_files: Optional[bool] = None  # can this layer bring personal files back? (default: file backup and cloud only)
    error: bool = False  # the check itself failed

    @property
    def title(self) -> str:
        return LAYER_TITLES[self.key]

    @property
    def counts_as_backup(self) -> bool:
        return self.key in (BACKUP, CLOUD) if self.covers_files is None else self.covers_files


def layer_check(layer: Layer) -> CheckResult:
    """CheckResult of a layer: PASS when in place, SKIP when unknown / not applicable, FAIL when it raised a MEDIUM or higher
    finding, WARN otherwise."""
    if layer.error:
        status = CheckStatus.ERROR
    elif layer.state == OK:
        status = CheckStatus.PASS
    elif layer.state in (UNKNOWN, NA):
        status = CheckStatus.SKIP
    else:
        status = CheckStatus.FAIL if layer.severity is not None and layer.severity >= Severity.MEDIUM else CheckStatus.WARN
    return CheckResult(f"AEG-RECOVERY-{layer.key.upper()}", layer.title, status, layer.detail, Category.RANSOMWARE)


def offline_layer() -> Layer:
    return Layer(OFFLINE, UNKNOWN,
                 "Not verified - no scanner can see it. An offline or off-site copy (a drive you unplug after the backup, "
                 "a backup server or cloud bucket the computer cannot delete from) is the copy ransomware cannot reach.",
                 hint="keep one backup disconnected or off-site")


# =========================================================================== helpers (pure)

_SANE_FROM = dt.datetime(2000, 1, 1, tzinfo=dt.timezone.utc)
_SANE_TO = dt.datetime(2100, 1, 1, tzinfo=dt.timezone.utc)
_EPOCH_1601 = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
_TIMESTAMP = re.compile(
    r"^\s*(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,](\d+))?\s*(Z|[+-]\d{2}(?::?\d{2})?)?\s*$", re.I)
_SPACED_DATE = re.compile(r"\b(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})\b")


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _sane(when: dt.datetime) -> Optional[dt.datetime]:
    return when if _SANE_FROM <= when < _SANE_TO else None


def _local(*parts: int) -> Optional[dt.datetime]:
    """Aware UTC datetime of a local wall-clock time given as (year, month, day, hour, minute, second)."""
    try:
        return _sane(dt.datetime(*parts).astimezone(dt.timezone.utc))
    except (ValueError, OverflowError, OSError):
        return None


def _iso(when: Optional[dt.datetime]) -> Optional[str]:
    return when.isoformat(timespec="seconds") if when else None


def _age_days(when: dt.datetime, now: dt.datetime) -> int:
    return max(0, (now - when).days)


def _when(when: Optional[dt.datetime], now: dt.datetime) -> str:
    """'2026-10-14 (3 days ago)'."""
    if when is None:
        return "at an unknown time"
    days = _age_days(when, now)
    ago = "today" if days == 0 else "1 day ago" if days == 1 else f"{days} days ago"
    return f"{when.strftime('%Y-%m-%d')} ({ago})"


def _plural(n: int, one: str, many: str) -> str:
    return one if n == 1 else many


def _int(value: Any) -> Optional[int]:
    if value is None or isinstance(value, (bytes, bytearray)):
        return None
    if isinstance(value, bool):
        return int(value)
    try:
        return int(value)
    except (TypeError, ValueError):
        try:
            return int(str(value).strip(), 0)
        except (TypeError, ValueError):
            return None


def _get(values: Mapping[str, Any], name: str) -> Any:
    """Registry value by name, ignoring case."""
    if name in values:
        return values[name]
    low = name.lower()
    for key, val in values.items():
        if str(key).lower() == low:
            return val
    return None


def parse_timestamp(value: Any) -> Optional[dt.datetime]:
    """ISO-8601 style text ('2026-10-14T08:00:00.1234567Z', '2026-10-14 08:00:00 +0200', or a local time without a zone)
    -> aware UTC datetime. Anything else and absurd years (outside 2000-2100) give None."""
    m = _TIMESTAMP.match(value) if isinstance(value, str) else None
    if not m:
        return None
    parts = [int(g) for g in m.groups()[:6]]
    zone = m.group(8)
    if zone is None:
        return _local(*parts)
    try:
        when = dt.datetime(*parts, int((m.group(7) or "0")[:6].ljust(6, "0")))
        if zone.upper() != "Z":
            digits = zone[1:].replace(":", "")
            offset = dt.timedelta(hours=int(digits[:2]), minutes=int(digits[2:4] or 0))
            when -= -offset if zone[0] == "-" else offset  # wall time minus its offset from UTC is UTC
        return _sane(when.replace(tzinfo=dt.timezone.utc))
    except (ValueError, OverflowError):
        return None


def filetime_to_datetime(value: Any) -> Optional[dt.datetime]:
    """Registry FILETIME (100 ns since 1601 UTC; REG_QWORD int or 8 raw bytes) -> aware UTC datetime, None if absurd."""
    try:
        if isinstance(value, (bytes, bytearray)):
            if len(value) < 8:
                return None
            value = int.from_bytes(bytes(value[:8]), "little")
        if value is None or isinstance(value, bool):
            return None
        ft = int(value)
        return _sane(_EPOCH_1601 + dt.timedelta(microseconds=ft // 10)) if ft > 0 else None
    except (TypeError, ValueError, OverflowError):
        return None


def parse_registry_time(value: Any) -> Optional[dt.datetime]:
    """A time stored in the registry as FILETIME (int / bytes) or as ISO text."""
    if isinstance(value, str):
        return parse_timestamp(value) or (filetime_to_datetime(value) if value.strip().isdigit() else None)
    return filetime_to_datetime(value)


def newest_of(*times: Optional[dt.datetime]) -> Optional[dt.datetime]:
    known = [t for t in times if t is not None]
    return max(known) if known else None


def _text(out: str, err: str) -> str:
    return f"{out or ''}\n{err or ''}".strip()


# =========================================================================== readiness grade and summary


def readiness_grade(layers: Sequence[Layer]) -> Tuple[str, str]:
    """(grade, plain-English verdict). Good = a working backup layer plus at least one more working layer; Fair = one working
    backup layer; Weak = no working backup layer (restore points alone do not count: ransomware deletes them and they live
    on the same disk); Unknown = a backup layer could not be checked, or nothing could be judged."""
    judged = [l for l in layers if l.key != OFFLINE]
    healthy = [l for l in judged if l.state == OK]
    protecting = [l for l in healthy if l.counts_as_backup]
    names = " and ".join(_LAYER_NAMES[l.key] for l in healthy)
    lacking = {l.key for l in judged if l.state in (MISSING, STALE)}
    missing = [_LAYER_NAMES[k] for k in (BACKUP, CLOUD, RESTORE) if k in lacking]
    if protecting:
        if len(healthy) >= 2:
            return "Good", (f"You have {len(healthy)} independent ways to get files back ({names}), so one of them failing or "
                            "being wiped by an attack does not leave you without a copy. Try a restore now and then, and keep "
                            "one copy disconnected from this computer - Aegis cannot verify that one.")
        extra = f" (for example {missing[0]})" if missing else ""
        return "Fair", (f"One recovery layer is working ({names}). That is a start, but a single layer can fail or be reached "
                        f"by the same attack. Add a second, different layer{extra} and keep one copy disconnected from this "
                        "computer.")
    if any(l.counts_as_backup and l.state == UNKNOWN for l in judged) \
            or not any(l.state in (OK, STALE, MISSING) for l in judged):
        return "Unknown", ("Aegis could not check enough to judge whether you could recover from ransomware. See the skipped "
                           "checks of this scan for what was missing (administrator rights on Windows, Full Disk Access on "
                           "macOS), or verify your backups by hand.")
    only = (" Restore points exist, but ransomware routinely deletes them and they sit on the same disk as your files."
            if healthy else "")
    return "Weak", ("No up-to-date file backup or cloud copy was found, so if ransomware encrypted this computer today you "
                    f"could not count on getting your files back without paying.{only} The findings of this scan list "
                    "the exact steps.")


def summary_finding(layers: Sequence[Layer], note: str = "") -> Finding:
    """The one INFO finding that lists every recovery layer with its state and a plain-English verdict (``note`` is added
    to the description unless the grade is Good)."""
    ordered = sorted(layers, key=lambda l: LAYER_ORDER.index(l.key))
    grade, verdict = readiness_grade(ordered)
    todo = [l.hint for l in ordered if l.hint and (l.state in (MISSING, STALE) or l.key == OFFLINE)]
    rec = ("Next steps: " + "; ".join(todo) + "." if todo else "Nothing more to set up.") + \
          (" Test a restore of one file now and then - a backup you have never restored from is a hope, not a plan."
           if grade in ("Good", "Fair") else "")
    return Finding(
        rule_id="AEG-RECOVERY-SUMMARY", title=f"Ransomware recovery readiness: {grade}", severity=Severity.INFO,
        category=Category.RANSOMWARE,
        description=(f"{verdict} Good = two or more independent recovery layers including a working backup; Fair = one "
                     "working backup layer; Weak = none found; Unknown = could not be checked. Ransomware encrypts every "
                     "backup it can reach, so a copy that is disconnected or off-site is what finally decides the outcome, "
                     "and no scanner can see whether you have one." + (f" {note}" if note and grade != "Good" else "")),
        location="recovery:summary",
        evidence={"grade": grade, "healthy_layers": sum(1 for l in ordered if l.state == OK and l.key != OFFLINE),
                  "layers": [{"layer": l.title, "state": l.state, "detail": l.detail, "newest": _iso(l.newest)}
                             for l in ordered]},
        recommendation=rec, mitre=list(MITRE_BACKUP))


# =========================================================================== Windows: PowerShell facts

_PS_FACTS = r"""
$ErrorActionPreference='SilentlyContinue'
$r=[ordered]@{}
try{$o=Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop;$r['os']=[pscustomobject]@{caption=[string]$o.Caption;product_type=[int]$o.ProductType}}catch{}
$r['drive']=[string]$env:SystemDrive
$rs=[ordered]@{supported=[bool](Get-Command Get-ComputerRestorePoint -ErrorAction SilentlyContinue)}
if($rs['supported']){try{$p=@(Get-ComputerRestorePoint -ErrorAction Stop);$rs['count']=$p.Count;if($p.Count -gt 0){$n=$p|Sort-Object SequenceNumber -Descending|Select-Object -First 1;$rs['newest']=[Management.ManagementDateTimeConverter]::ToDateTime([string]$n.CreationTime).ToUniversalTime().ToString('o');$rs['newest_name']=[string]$n.Description}}catch{$rs['error']=[string]$_.Exception.Message}}
$r['restore']=[pscustomobject]$rs
$sid='';try{$sid=[string](Get-CimInstance -ClassName Win32_Volume -Filter "DriveLetter='$env:SystemDrive'" -ErrorAction Stop).DeviceID}catch{}
try{$all=@(Get-CimInstance -ClassName Win32_ShadowCopy -ErrorAction Stop);$mine=@($all|Where-Object{(-not $sid) -or ($_.VolumeName -eq $sid)});$sh=[ordered]@{count=$mine.Count;total=$all.Count};if($mine.Count -gt 0){$sh['newest']=($mine|Sort-Object InstallDate -Descending|Select-Object -First 1).InstallDate.ToUniversalTime().ToString('o')};$r['shadow']=[pscustomobject]$sh}catch{$r['shadow']=[pscustomobject]@{error=[string]$_.Exception.Message}}
$r|ConvertTo-Json -Depth 4 -Compress
"""


@dataclass
class WindowsFacts:
    """What the batched PowerShell call reported about restore points and shadow copies."""

    available: bool = False  # PowerShell answered
    drive: str = "C:"
    product_type: Optional[int] = None  # Win32_OperatingSystem.ProductType: 1 workstation, 2 domain controller, 3 server
    restore_supported: bool = True
    restore_count: Optional[int] = None
    restore_newest: Optional[dt.datetime] = None
    restore_error: str = ""
    shadow_count: Optional[int] = None
    shadow_newest: Optional[dt.datetime] = None
    shadow_error: str = ""


def parse_windows_facts(data: Any) -> WindowsFacts:
    """Facts from the PowerShell JSON; anything missing or malformed stays at its 'not known' default."""
    facts = WindowsFacts()
    if not isinstance(data, dict) or not data:
        return facts
    facts.available = True
    drive = str(data.get("drive") or "").strip().rstrip("\\")
    if re.fullmatch(r"[A-Za-z]:", drive):
        facts.drive = drive.upper()
    os_info = data.get("os")
    if isinstance(os_info, dict):
        facts.product_type = _int(os_info.get("product_type"))
    restore = data.get("restore")
    if isinstance(restore, dict):
        facts.restore_supported = restore.get("supported") is not False
        facts.restore_count = _int(restore.get("count"))
        facts.restore_newest = parse_timestamp(restore.get("newest"))
        facts.restore_error = str(restore.get("error") or "").strip()
    shadow = data.get("shadow")
    if isinstance(shadow, dict):
        facts.shadow_count = _int(shadow.get("count"))
        facts.shadow_newest = parse_timestamp(shadow.get("newest"))
        facts.shadow_error = str(shadow.get("error") or "").strip()
    return facts


def collect_windows_facts(ps_runner: Optional[Callable[..., Any]] = None) -> WindowsFacts:
    """One batched PowerShell call for restore points, shadow copies of the system drive and the OS product type."""
    ps_runner = ps_runner or powershell_json
    return parse_windows_facts(ps_runner(_PS_FACTS, timeout=PS_TIMEOUT_S))


# =========================================================================== Windows: System Restore / shadow copies

SYSTEM_RESTORE_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore"
SYSTEM_RESTORE_POLICY_KEY = r"SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore"
WINDOWS_VERSION_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"


@dataclass
class SystemRestoreSetting:
    enabled: Optional[bool] = None  # None = the registry does not say
    source: str = ""  # "group policy" | "local setting" when enabled is False


def read_system_restore_setting(read: Optional[Callable[..., Any]] = None) -> SystemRestoreSetting:
    """System Protection switch: ``DisableSR`` set by Group Policy or locally, or ``RPSessionInterval`` = 0, mean off;
    ``RPSessionInterval`` >= 1 means on; a missing value means the registry does not say."""
    read = read or reg_read
    if _int(read("HKLM", SYSTEM_RESTORE_POLICY_KEY, "DisableSR")) == 1:
        return SystemRestoreSetting(False, "group policy")
    if _int(read("HKLM", SYSTEM_RESTORE_KEY, "DisableSR")) == 1:
        return SystemRestoreSetting(False, "local setting")
    interval = _int(read("HKLM", SYSTEM_RESTORE_KEY, "RPSessionInterval"))
    if interval is None:
        return SystemRestoreSetting()
    return SystemRestoreSetting(False, "local setting") if interval == 0 else SystemRestoreSetting(True)


def is_windows_server(facts: Optional[WindowsFacts] = None, read: Optional[Callable[..., Any]] = None) -> bool:
    """True for a Windows Server SKU (registry InstallationType / EditionID / ProductName, or ProductType 2 / 3)."""
    read = read or reg_read
    install = str(read("HKLM", WINDOWS_VERSION_KEY, "InstallationType") or "").lower()
    edition = str(read("HKLM", WINDOWS_VERSION_KEY, "EditionID") or "").lower()
    product = str(read("HKLM", WINDOWS_VERSION_KEY, "ProductName") or "").lower()
    if install.startswith("server") or "server" in edition or "server" in product:
        return True
    return bool(facts and facts.product_type in (2, 3))


def _readable_count(count: Optional[int], error: str, admin: bool) -> Optional[int]:
    """Count a source reported, or None when it cannot be trusted: failed, or empty without administrator rights (Windows
    may answer an unprivileged query with an empty list instead of 'access denied')."""
    if count is None or error or (count == 0 and not admin):
        return None
    return count


def _short(text: str, limit: int = 120) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= limit else text[:limit - 3] + "..."


def _enable_cmd(drive: str) -> str:
    return f'Enable-ComputerRestore -Drive "{drive}\\"'


_CHECKPOINT_CMD = 'Checkpoint-Computer -Description "Manual restore point" -RestorePointType MODIFY_SETTINGS'


def restore_finding(rule: str, title: str, severity: Severity, desc: str, rec: str, drive: str,
                    evidence: Dict[str, Any]) -> Finding:
    return Finding(rule_id=f"AEG-RECOVERY-RESTORE-{rule}", title=title, severity=severity, category=Category.RANSOMWARE,
                   description=desc, location=f"System Protection ({drive})", evidence=evidence, recommendation=rec,
                   mitre=list(MITRE_RESTORE))


def assess_restore(facts: WindowsFacts, setting: SystemRestoreSetting, admin: bool, server: bool,
                   now: dt.datetime) -> Tuple[Layer, List[Finding]]:
    """The restore-point layer and its finding (if any) from the PowerShell facts and the registry switch."""
    drive = facts.drive
    if server:
        return Layer(RESTORE, NA, "Windows Server has no System Restore (it is a client feature). Servers are normally "
                                  "protected with Windows Server Backup, shadow copies on the data volumes or a third-party "
                                  "backup agent; check those separately."), []
    if facts.available and not facts.restore_supported and setting.enabled is not False:
        return Layer(RESTORE, NA, "System Restore is not available on this Windows installation "
                                  "(Get-ComputerRestorePoint is missing)."), []
    restore = _readable_count(facts.restore_count, facts.restore_error, admin)
    shadow = _readable_count(facts.shadow_count, facts.shadow_error, admin)
    newest = newest_of(facts.restore_newest if restore else None, facts.shadow_newest if shadow else None)
    ev: Dict[str, Any] = {
        "system_drive": drive, "system_protection": setting.enabled, "protection_setting_source": setting.source or None,
        "restore_points": restore, "newest_restore_point": _iso(facts.restore_newest if restore else None),
        "shadow_copies": shadow, "newest_shadow_copy": _iso(facts.shadow_newest if shadow else None),
        "restore_points_not_checked": restore is None, "shadow_copies_not_checked": shadow is None,
        "checked_as_administrator": admin}
    hint_on = f"turn on System Protection for {drive} (Start > 'Create a restore point' > Configure)"

    if setting.enabled is False:
        policy = setting.source == "group policy"
        how = "switched off by Group Policy" if policy else "turned off in the system settings"
        desc = (f"System Protection is {how} for {drive}, so Windows makes no restore points and keeps no shadow copies of "
                "the drive. Restore points are the one recovery layer built into the PC: after a bad update, a faulty driver "
                "or some malware they let you roll Windows back, and many PCs can also bring back earlier versions of files. "
                "Ransomware often tries to delete them, but a PC with none leaves nothing to go back to at all. Good looks "
                "like: System Protection on for the system drive, with a restore point from the last 30 days. Restore "
                "points live on the same disk, so they complement a real backup and never replace it.")
        steps = (f"Open Start, type 'Create a restore point', and on the System Protection tab select drive {drive}, click "
                 "Configure, choose 'Turn on system protection', set Max Usage to about 5-10% and click OK. Then click "
                 f"Create to make the first restore point. From an elevated PowerShell the same is: {_enable_cmd(drive)} "
                 f"and then {_CHECKPOINT_CMD} (Windows creates at most one restore point per 24 hours).")
        rec = (("A Group Policy turns System Protection off (Computer Configuration > Administrative Templates > System > "
                "System Restore > Turn off System Restore). Ask your IT administrator to change it, or on a PC you manage "
                "yourself set that policy to Not configured in gpedit.msc. Then: ") + steps) if policy else steps
        layer = Layer(RESTORE, MISSING, f"System Protection is {how} for {drive}; no restore points are made.",
                      severity=Severity.MEDIUM, hint=hint_on)
        return layer, [restore_finding("OFF", "System Protection (System Restore) is turned off", Severity.MEDIUM, desc, rec,
                                       drive, ev)]

    points = (restore or 0) + (shadow or 0)
    if points > 0:
        pieces = []
        if restore is not None:
            pieces.append(f"{restore} restore {_plural(restore, 'point', 'points')}"
                          + (f", newest {_when(facts.restore_newest, now)}" if restore else ""))
        if shadow is not None:
            pieces.append(f"{shadow} shadow {_plural(shadow, 'copy', 'copies')}"
                          + (f", newest {_when(facts.shadow_newest, now)}" if shadow else ""))
        if restore is None:
            pieces.append("restore points not checked without administrator rights" if not admin
                          else "restore points could not be read")
        if shadow is None:
            pieces.append("shadow copies not checked without administrator rights" if not admin
                          else "shadow copies could not be read")
        detail = f"Drive {drive}: " + "; ".join(pieces) + "."
        if newest is None or _age_days(newest, now) <= STALE_DAYS:
            return Layer(RESTORE, OK, detail, newest), []
        days = _age_days(newest, now)
        desc = (f"The newest restore point or shadow copy of {drive} is from {_when(newest, now)}. Windows normally creates "
                "one before major updates and driver installs, so a month without a new one suggests that automatic restore "
                "points are failing, most often because the disk-space limit on the System Protection tab is too small. An "
                "old restore point only brings back an old state of Windows and of any file it covers; ransomware that "
                "strikes today would find little recent to roll back to. Good looks like: a restore point from the last "
                f"{STALE_DAYS} days.")
        rec = ("Create a fresh restore point (Start > 'Create a restore point' > Create, or in an elevated PowerShell: "
               f"{_CHECKPOINT_CMD}) and raise Max Usage under System Protection > Configure to about 5-10% of the disk so "
               "restore points are not squeezed out.")
        layer = Layer(RESTORE, STALE, detail, newest, Severity.LOW,
                      f"create a fresh restore point (the newest is {days} days old)")
        return layer, [restore_finding("STALE", f"The newest restore point is {days} days old", Severity.LOW, desc, rec,
                                       drive, ev)]

    if restore is not None or shadow is not None:  # every source that could be read is empty
        state = "on" if setting.enabled else "not reported as off"
        desc = (f"System Protection is {state} for {drive}, yet Windows holds no restore point and no shadow copy of it. If "
                "ransomware or a bad update hits this PC there is nothing on the PC to roll back to. Windows normally "
                "creates a restore point before major updates, so an empty list usually means the disk-space limit is too "
                "small, the drive was reset, or the restore points were deleted - which is exactly what ransomware does "
                f"on purpose (vssadmin delete shadows). Good looks like: at least one restore point from the last {STALE_DAYS} "
                "days.")
        rec = (f"Create one now: Start > 'Create a restore point' > Create, or in an elevated PowerShell: {_CHECKPOINT_CMD}. "
               f"Then check that the System Protection tab shows Protection 'On' for {drive}; if it shows 'Off', select the "
               f"drive, click Configure and turn it on (or run {_enable_cmd(drive)}), with Max Usage at about 5-10%. If "
               "you did not delete the restore points yourself, treat this as a warning sign and run a full Aegis scan.")
        layer = Layer(RESTORE, MISSING, f"System Protection reports no restore point or shadow copy for {drive}.",
                      severity=Severity.MEDIUM, hint=f"create a restore point (in an elevated PowerShell: {_CHECKPOINT_CMD})")
        return layer, [restore_finding("NONE", "No restore point or shadow copy exists on the system drive", Severity.MEDIUM,
                                       desc, rec, drive, ev)]

    if not admin:
        detail = ("Not checked without administrator rights: Windows only lets administrators list restore points and "
                  "shadow copies. Run Aegis as Administrator for a definitive answer.")
        if setting.enabled:
            detail += " System Protection is switched on according to the registry."
    else:
        why = facts.restore_error or facts.shadow_error
        detail = ("Restore points and shadow copies could not be read" + (f" ({_short(why)})" if why else
                                                                          " (PowerShell returned no data)") + ".")
    return Layer(RESTORE, UNKNOWN, detail), []


def check_windows_restore(admin: bool, now: dt.datetime, ps_runner: Optional[Callable[..., Any]] = None,
                          read: Optional[Callable[..., Any]] = None,
                          shared: Optional[Dict[str, Any]] = None) -> Tuple[List[Layer], List[Finding]]:
    """Collect the PowerShell facts and the registry switch, then assess the restore-point layer."""
    shared = shared if shared is not None else {}
    try:
        facts = collect_windows_facts(ps_runner)
    except Exception as exc:  # PowerShell missing or crashed: the registry part still works
        log.warning("PowerShell restore point query failed: %s", exc)
        facts = WindowsFacts()
    shared["facts"] = facts
    server = is_windows_server(facts, read)
    shared["server"] = server
    layer, findings = assess_restore(facts, read_system_restore_setting(read), admin, server, now)
    return [layer], findings


# =========================================================================== Windows: File History

FILE_HISTORY_KEY = r"Software\Microsoft\Windows\CurrentVersion\FileHistory"
FILE_HISTORY_POLICY_KEY = r"SOFTWARE\Policies\Microsoft\Windows\FileHistory"


@dataclass
class FileHistoryState:
    configured: bool = False  # File History has been set up for this user
    enabled: Optional[bool] = None  # explicit on / off value, if the registry has one
    policy_disabled: bool = False  # switched off by Group Policy
    last_backup: Optional[dt.datetime] = None  # ProtectedUpToTime


def detect_file_history(values: Optional[Callable[..., Dict[str, Any]]] = None,
                        read: Optional[Callable[..., Any]] = None) -> FileHistoryState:
    """File History state from ``HKCU\\...\\FileHistory`` (``ProtectedUpToTime`` = newest backup, ``ProvisionedTime`` and
    ``Enabled`` = set up / on) and the ``Disabled`` Group Policy. Best effort: the key only exists once it was configured."""
    values = values or reg_values
    read = read or reg_read
    vals = values("HKCU", FILE_HISTORY_KEY) or {}
    state = FileHistoryState()
    state.policy_disabled = _int(read("HKLM", FILE_HISTORY_POLICY_KEY, "Disabled")) == 1
    state.last_backup = parse_registry_time(_get(vals, "ProtectedUpToTime"))
    enabled = _int(_get(vals, "Enabled"))
    state.enabled = None if enabled is None else enabled != 0
    state.configured = bool(state.last_backup or state.enabled is not None or _get(vals, "ProvisionedTime") is not None)
    return state


# =========================================================================== Windows: cloud sync clients

ONEDRIVE_ACCOUNTS_KEY = r"Software\Microsoft\OneDrive\Accounts"
USER_SHELL_FOLDERS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
KNOWN_FOLDERS = (("Desktop", ("Desktop",)),
                 ("Documents", ("Personal", "{F42EE2D3-909F-4907-8871-4C22FC0BF756}")),
                 ("Pictures", ("My Pictures", "{0DDD015D-B06C-45D5-8C4C-F59713854639}")))
_ONEDRIVE_SEGMENT = re.compile(r"(?:^|\\)onedrive(?: - [^\\]*)?(?:\\|$)", re.I)

CLOUD_NOTE = ("Services with version history keep earlier versions of a file, so after an attack you can restore the files "
              "as they were before they were encrypted. A sync client only protects what is inside its folders, so make "
              "sure your important files live there.")


@dataclass
class CloudProvider:
    name: str
    detail: str
    covers_known_folders: bool = False  # Desktop / Documents / Pictures are inside it
    evidence: Dict[str, Any] = field(default_factory=dict)


def _expand(path: str, env: Mapping[str, str]) -> str:
    """Expand %NAME% (case-insensitive) with the given environment; unknown names are left as they are."""
    lower = {str(k).lower(): str(v) for k, v in env.items()}
    return re.sub(r"%([^%]+)%", lambda m: lower.get(m.group(1).lower(), m.group(0)), path)


def _in_onedrive(path: str, roots: Sequence[str]) -> bool:
    p = path.replace("/", "\\").rstrip("\\").lower()
    if any(p == r.replace("/", "\\").rstrip("\\").lower() or p.startswith(r.replace("/", "\\").rstrip("\\").lower() + "\\")
           for r in roots if r):
        return True
    return bool(_ONEDRIVE_SEGMENT.search(p))


def detect_onedrive(values: Optional[Callable[..., Dict[str, Any]]] = None, subkeys: Optional[Callable[..., List[str]]] = None,
                    env: Optional[Mapping[str, str]] = None) -> Optional[CloudProvider]:
    """OneDrive: an account is signed in (``UserEmail``), Known Folder Move reports protected folders
    (``KfmFoldersProtectedNow``) or the Desktop / Documents / Pictures shell folders point into the OneDrive folder."""
    values = values or reg_values
    subkeys = subkeys or reg_subkeys
    env = os.environ if env is None else env
    signed_in, kfm, roots = False, 0, []
    for sub in subkeys("HKCU", ONEDRIVE_ACCOUNTS_KEY) or []:
        vals = values("HKCU", f"{ONEDRIVE_ACCOUNTS_KEY}\\{sub}") or {}
        signed_in = signed_in or bool(str(_get(vals, "UserEmail") or "").strip())
        kfm |= max(_int(_get(vals, "KfmFoldersProtectedNow")) or 0, 0)
        folder = _get(vals, "UserFolder")
        if isinstance(folder, str) and folder.strip():
            roots.append(_expand(folder.strip(), env))
    shell = values("HKCU", USER_SHELL_FOLDERS_KEY) or {}
    redirected: List[str] = []
    for label, names in KNOWN_FOLDERS:
        for name in names:
            raw = _get(shell, name)
            if isinstance(raw, str) and _in_onedrive(_expand(raw.strip(), env), roots):
                redirected.append(label)
                break
    if not (signed_in or kfm or redirected):
        return None
    ev = {"signed_in": signed_in, "kfm_folders_protected_now": kfm or None, "folders_redirected_into_onedrive": redirected}
    if redirected or kfm:
        which = ", ".join(redirected) if redirected else "your known folders"
        return CloudProvider("OneDrive", f"OneDrive folder backup (Known Folder Move) is protecting {which}", True, ev)
    return CloudProvider("OneDrive", "OneDrive is signed in, but Desktop, Documents and Pictures are not backed up to it "
                                     "(only files saved inside the OneDrive folder are protected)", False, ev)


def detect_sync_clients(home: Optional[Path] = None, env: Optional[Mapping[str, str]] = None,
                        path_exists: Optional[Callable[[str], bool]] = None,
                        values: Optional[Callable[..., Dict[str, Any]]] = None,
                        subkeys: Optional[Callable[..., List[str]]] = None) -> List[CloudProvider]:
    """Google Drive and Dropbox desktop clients: their folder in the user profile, their app-data folder / ``info.json`` or
    their ``HKCU\\Software`` key. A client counts as present, not as proof that any given folder is synced."""
    home = home or user_home()
    env = os.environ if env is None else env
    exists = path_exists or os.path.exists
    values = values or reg_values
    subkeys = subkeys or reg_subkeys
    local = str(env.get("LOCALAPPDATA") or home / "AppData" / "Local")
    roaming = str(env.get("APPDATA") or home / "AppData" / "Roaming")

    def registry_present(key: str) -> bool:
        return bool(values("HKCU", key) or subkeys("HKCU", key))

    out: List[CloudProvider] = []
    candidates = (
        ("Dropbox", [str(home / "Dropbox"), os.path.join(local, "Dropbox", "info.json"),
                     os.path.join(roaming, "Dropbox", "info.json")], r"Software\Dropbox"),
        ("Google Drive", [str(home / "Google Drive"), str(home / "My Drive"), os.path.join(local, "Google", "DriveFS")],
         r"Software\Google\DriveFS"),
    )
    for name, paths, key in candidates:
        found = [p for p in paths if exists(p)]
        in_registry = registry_present(key)
        if found or in_registry:
            out.append(CloudProvider(name, f"{name} desktop client found", False,
                                     {"paths": found, "registry_key": f"HKCU\\{key}" if in_registry else None}))
    return out


def file_history_layer(fh: FileHistoryState, now: dt.datetime, server: bool = False) -> Layer:
    hint = "turn on File History (Control Panel > File History) with an external drive"
    if fh.policy_disabled:
        return Layer(BACKUP, MISSING, "File History is switched off by Group Policy.", hint=hint)
    if fh.enabled is False:
        extra = f" (its last backup was {_when(fh.last_backup, now)})" if fh.last_backup else ""
        return Layer(BACKUP, MISSING, f"File History is turned off{extra}.", fh.last_backup, hint=hint)
    if fh.last_backup is not None:
        days = _age_days(fh.last_backup, now)
        if days > STALE_DAYS:
            return Layer(BACKUP, STALE, f"File History last backed up {_when(fh.last_backup, now)}.", fh.last_backup,
                         hint=f"reconnect the File History drive and run a backup (the last was {days} days ago)")
        return Layer(BACKUP, OK, f"File History is on; last backup {_when(fh.last_backup, now)}.", fh.last_backup)
    if fh.configured:
        return Layer(BACKUP, OK, "File History is set up; Windows did not report when it last ran.")
    if server:
        return Layer(BACKUP, NA, "File History is a Windows client feature; servers are backed up with Windows Server Backup "
                                 "or a third-party agent - check that separately.")
    return Layer(BACKUP, MISSING, "File History is not set up.", hint=hint)


def assess_windows_files(fh: FileHistoryState, providers: Sequence[CloudProvider], now: dt.datetime,
                         server: bool = False) -> Tuple[List[Layer], List[Finding]]:
    """The file-backup and cloud layers and the one finding about personal files (none / stale File History)."""
    backup = file_history_layer(fh, now, server)
    if providers:
        cloud = Layer(CLOUD, OK, "; ".join(p.detail for p in providers) + ". " + CLOUD_NOTE)
    elif server:
        cloud = Layer(CLOUD, NA, "No cloud sync client found; on a server this is normal (back it up with a server backup "
                                 "agent).")
    else:
        cloud = Layer(CLOUD, MISSING, "No OneDrive, Google Drive or Dropbox client found.",
                      hint="turn on OneDrive folder backup (OneDrive icon > Settings > Sync and backup > Manage backup)")
    ev = {"file_history_configured": fh.configured, "file_history_enabled": fh.enabled,
          "file_history_disabled_by_policy": fh.policy_disabled, "file_history_last_backup": _iso(fh.last_backup),
          "cloud": [{"service": p.name, "covers_known_folders": p.covers_known_folders, **p.evidence} for p in providers]}
    if backup.state == OK or cloud.state == OK or server:
        return [backup, cloud], []
    if backup.state == STALE:
        days = _age_days(fh.last_backup, now) if fh.last_backup else 0
        backup.severity = Severity.LOW
        desc = (f"File History last backed up {_when(fh.last_backup, now)} and no cloud sync with version history was found, "
                "so your newest documents and photos are not covered. Backups only help for what they contain: anything "
                "created or changed since the last run is lost if ransomware encrypts it. Good looks like: File History "
                f"running with a backup from the last {STALE_DAYS} days, or a cloud service with version history.")
        rec = ("Reconnect the File History drive (or network share) and run a backup: Control Panel > System and Security > "
               "File History > Run now. If the drive has failed or was replaced, pick a new one under 'Select drive'. A "
               "cloud service such as OneDrive (OneDrive icon > Settings > Sync and backup > Manage backup) closes the gap "
               "without a drive.")
        return [backup, cloud], [Finding(
            rule_id="AEG-RECOVERY-FILES-STALE", title=f"File History has not backed up for {days} days", severity=Severity.LOW,
            category=Category.RANSOMWARE, description=desc, location="File History", evidence=ev, recommendation=rec,
            mitre=list(MITRE_BACKUP))]
    backup.severity = Severity.MEDIUM
    desc = ("Aegis found no File History backup and no cloud sync with version history (OneDrive folder backup, Google Drive "
            "or Dropbox). Your documents, photos and desktop exist only on this computer, so if ransomware encrypts them or "
            "the disk fails they are gone unless you pay. Good looks like: File History or Windows Backup / OneDrive folder "
            "backup running, plus - ideally - a copy on a drive that is unplugged after the backup. Cloud sync with version "
            "history (OneDrive, Google Drive, Dropbox) helps because these services keep earlier versions of a file, so you "
            "can restore files as they were before the ransomware encrypted them.")
    rec = ("Pick at least one. (1) OneDrive: sign in, click the OneDrive cloud icon in the taskbar > Settings (gear) > Sync and "
           "backup > Manage backup > turn on Desktop, Documents and Pictures; OneDrive keeps versions and can restore the whole "
           "OneDrive to an earlier date. (2) File History: connect an external drive, then Control Panel > System and "
           "Security > File History > Turn on. (3) Google Drive or Dropbox: install the desktop app and keep your important "
           "folders inside its folder. Also keep one copy on a drive that is disconnected when not in use, because "
           "ransomware encrypts backup drives that stay plugged in.")
    return [backup, cloud], [Finding(
        rule_id="AEG-RECOVERY-FILES-NONE", title="Your personal files are not backed up", severity=Severity.MEDIUM,
        category=Category.RANSOMWARE, description=desc, location="Personal files backup", evidence=ev, recommendation=rec,
        mitre=list(MITRE_BACKUP))]


def check_windows_files(now: dt.datetime, server: bool = False, read: Optional[Callable[..., Any]] = None,
                        values: Optional[Callable[..., Dict[str, Any]]] = None,
                        subkeys: Optional[Callable[..., List[str]]] = None, path_exists: Optional[Callable[[str], bool]] = None,
                        env: Optional[Mapping[str, str]] = None,
                        home: Optional[Path] = None) -> Tuple[List[Layer], List[Finding]]:
    """File History, OneDrive / Google Drive / Dropbox detection and the personal-files assessment."""
    fh = detect_file_history(values, read)
    providers: List[CloudProvider] = []
    onedrive = detect_onedrive(values, subkeys, env)
    if onedrive:
        providers.append(onedrive)
    providers += detect_sync_clients(home, env, path_exists, values, subkeys)
    return assess_windows_files(fh, providers, now, server)


# =========================================================================== macOS: Time Machine and iCloud

TIME_MACHINE_PLIST = "/Library/Preferences/com.apple.TimeMachine"
_BACKUP_NAME = re.compile(r"(\d{4})-(\d{2})-(\d{2})-(\d{2})(\d{2})(\d{2})")
_SNAPSHOT_DATES = re.compile(r"SnapshotDates\s*=\s*\((.*?)\)\s*;", re.S)
_QUOTED_DATE = re.compile(r'"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4})"')
FDA_HINT = ("macOS only lets programs with Full Disk Access read the Time Machine backup list: open System Settings > "
            "Privacy & Security > Full Disk Access, add your terminal (or the Aegis app), then run the scan again.")


@dataclass
class TimeMachinePrefs:
    auto_backup: Optional[bool] = None
    destination_ids: List[str] = field(default_factory=list)
    last_destination_id: str = ""
    snapshot_dates: List[dt.datetime] = field(default_factory=list)


def parse_tmutil_destinations(text: str) -> List[Dict[str, str]]:
    """Backup destinations from ``tmutil destinationinfo`` (blocks of 'Key : value' lines between '====' rules)."""
    blocks: List[Dict[str, str]] = []
    cur: Dict[str, str] = {}
    for line in (text or "").splitlines():
        s = line.strip()
        if s and set(s) == {"="}:
            if cur:
                blocks.append(cur)
            cur = {}
            continue
        m = re.match(r"^([A-Za-z][A-Za-z ]*?)\s*:\s*(.*)$", s)
        if m:
            cur[m.group(1).strip()] = m.group(2).strip()
    if cur:
        blocks.append(cur)
    return [b for b in blocks if b.get("ID") or b.get("Name")]


def parse_tmutil_latest(rc: int, out: str, err: str) -> Tuple[Optional[dt.datetime], str]:
    """(time of the latest backup, problem) from ``tmutil latestbackup``. The time comes from the backup folder name
    (``2026-10-10-123456``, local time). problem is '' | 'fda' (needs Full Disk Access) | 'none' (no backup exists yet) |
    'unreachable' (backup disk not available) | 'error'."""
    low = _text(out, err).lower()
    if "full disk access" in low:
        return None, "fda"
    if "no backups found" in low:
        return None, "none"
    if rc != 0:
        gone = rc > 0 and re.search(r"mount|could not be found|unavailable|not available|no such|offline|not connected", low)
        return None, "unreachable" if gone else "error"
    matches = _BACKUP_NAME.findall(out or "")
    when = _local(*(int(g) for g in matches[-1])) if matches else None
    return (when, "") if when else (None, "error")


def parse_timemachine_defaults(text: str) -> TimeMachinePrefs:
    """``defaults read /Library/Preferences/com.apple.TimeMachine``: AutoBackup, the destination ids and the snapshot dates
    (the preferences are readable without Full Disk Access)."""
    prefs = TimeMachinePrefs()
    m = re.search(r"\bAutoBackup\s*=\s*(\d)", text or "")
    if m:
        prefs.auto_backup = m.group(1) != "0"
    prefs.destination_ids = re.findall(r'\bDestinationID\s*=\s*"?([0-9A-Za-z-]+)"?\s*;', text or "")
    m = re.search(r'\bLastDestinationID\s*=\s*"?([0-9A-Za-z-]+)"?\s*;', text or "")
    if m:
        prefs.last_destination_id = m.group(1)
    for block in _SNAPSHOT_DATES.findall(text or ""):
        for stamp in _QUOTED_DATE.findall(block):
            when = parse_timestamp(stamp)
            if when:
                prefs.snapshot_dates.append(when)
    return prefs


@dataclass
class TimeMachineState:
    status: str  # none | never | ok | stale | unknown | unavailable
    destinations: List[str] = field(default_factory=list)
    last_backup: Optional[dt.datetime] = None
    auto_backup: Optional[bool] = None
    problem: str = ""  # why the latest backup is unknown: fda | unreachable | error | ''


def time_machine_state(destinations: Optional[List[Dict[str, str]]], prefs: Optional[TimeMachinePrefs],
                       latest: Optional[dt.datetime], problem: str, now: dt.datetime) -> TimeMachineState:
    """Combine tmutil and the preferences (None = that source could not be run / read) into one state."""
    names = [d.get("Name") or d.get("ID") or "?" for d in destinations or []]
    if destinations is None and prefs is None:
        return TimeMachineState("unavailable", problem=problem)
    configured = bool(names) or bool(prefs and (prefs.destination_ids or prefs.last_destination_id))
    auto = prefs.auto_backup if prefs else None
    if not configured:
        return TimeMachineState("none", names, None, auto)
    last = newest_of(latest, *(prefs.snapshot_dates if prefs else []))
    if last is not None:
        stale = _age_days(last, now) > TIME_MACHINE_STALE_DAYS
        return TimeMachineState("stale" if stale else "ok", names, last, auto)
    if problem == "none":
        return TimeMachineState("never", names, None, auto, problem)
    return TimeMachineState("unknown", names, None, auto, problem or "error")


def assess_time_machine(state: TimeMachineState, now: dt.datetime,
                        providers: Sequence[CloudProvider] = ()) -> Tuple[Layer, List[Finding]]:
    where = "Time Machine"
    hint = "set up Time Machine (System Settings > General > Time Machine > Add Backup Disk)"
    icloud = [p for p in providers if p.name.startswith("iCloud")]
    ev = {"destinations": state.destinations, "last_backup": _iso(state.last_backup), "auto_backup": state.auto_backup,
          "icloud_desktop_and_documents": bool(icloud)}
    note = (" iCloud Drive is syncing Desktop & Documents, which keeps versions of those files, but everything outside them "
            "is not covered." if icloud else "")
    if state.status == "unavailable":
        return Layer(BACKUP, UNKNOWN, "Time Machine could not be queried (tmutil is not available)."), []
    if state.status in ("none", "never"):
        never = state.status == "never"
        title = "Time Machine is set up but has never completed a backup" if never else "Time Machine is not set up"
        desc = ((f"Time Machine has a backup disk ({', '.join(state.destinations) or 'configured'}) but no backup has ever "
                 "finished, so the Mac has no copy of your files. " if never else
                 "No Time Machine backup disk is configured, so this Mac has no built-in backup of your files. ")
                + "If ransomware encrypts the files, or the disk fails, they are gone unless you pay. Good looks like: Time "
                  f"Machine backing up automatically to a disk or network share with a backup from the last "
                  f"{TIME_MACHINE_STALE_DAYS} days, ideally alternating two disks so one is always disconnected." + note)
        rec = ("Connect an external drive and open System Settings > General > Time Machine > Add Backup Disk (macOS 12 and "
               "earlier: System Preferences > Time Machine > Select Backup Disk), choose the drive, keep 'Encrypt Backup' on and "
               "click Back Up Now. Eject the drive when it is not backing up, or alternate two drives, because ransomware "
               "encrypts a backup disk that stays connected.")
        layer = Layer(BACKUP, MISSING, ("Time Machine has never completed a backup." if never
                                        else "Time Machine is not set up (no backup destination)."),
                      severity=Severity.MEDIUM, hint=hint)
        return layer, [Finding(rule_id="AEG-RECOVERY-TM-NONE", title=title, severity=Severity.MEDIUM,
                               category=Category.RANSOMWARE, description=desc, location=where, evidence=ev,
                               recommendation=rec, mitre=list(MITRE_BACKUP))]
    if state.status == "unknown":
        reasons = {"fda": FDA_HINT, "unreachable": "the backup disk is not connected or not reachable right now, so the date "
                                                   "of the last backup is unknown."}
        why = reasons.get(state.problem, "tmutil returned no usable answer.")
        return Layer(BACKUP, UNKNOWN, "Time Machine is set up but the latest backup could not be read: " + why), []
    auto = "" if state.auto_backup in (None, True) else " Automatic backups are switched off."
    if state.status == "ok":
        return Layer(BACKUP, OK, f"Time Machine: last backup {_when(state.last_backup, now)}.{auto}", state.last_backup), []
    days = _age_days(state.last_backup, now) if state.last_backup else 0
    desc = (f"The latest Time Machine backup is from {_when(state.last_backup, now)}. Ransomware that strikes today can only be "
            "undone back to that date, and everything created since is lost. Backups go stale when the backup disk is not "
            f"connected, is full, or automatic backups are off. Good looks like: a backup from the last {TIME_MACHINE_STALE_DAYS} "
            f"days.{auto}{note}")
    rec = ("Connect the backup disk (or join the network share) and choose Back Up Now from the Time Machine menu or System "
           "Settings > General > Time Machine. If the disk is full or no longer works, choose a new one under Add Backup "
           "Disk; turn 'Back Up Automatically' on if it is off.")
    layer = Layer(BACKUP, STALE, f"Time Machine: last backup {_when(state.last_backup, now)}.{auto}", state.last_backup,
                  Severity.LOW, f"run a Time Machine backup (the last was {days} days ago)")
    return layer, [Finding(rule_id="AEG-RECOVERY-TM-STALE", title=f"The latest Time Machine backup is {days} days old",
                           severity=Severity.LOW, category=Category.RANSOMWARE, description=desc, location=where, evidence=ev,
                           recommendation=rec, mitre=list(MITRE_BACKUP))]


def detect_mac_cloud(home: Optional[Path] = None) -> List[CloudProvider]:
    """iCloud Drive "Desktop & Documents" and the OneDrive / Google Drive / Dropbox folders under ~/Library/CloudStorage
    (or, for older installs, Dropbox / Google Drive in the home folder)."""
    home = home or user_home()
    out: List[CloudProvider] = []
    icloud = home / "Library" / "Mobile Documents" / "com~apple~CloudDocs"
    synced = [n for n in ("Desktop", "Documents") if (icloud / n).is_dir()]
    if synced:
        out.append(CloudProvider("iCloud Drive (Desktop & Documents)",
                                 f"iCloud Drive is syncing {' and '.join(synced)}", True, {"folders": synced}))
    storage = home / "Library" / "CloudStorage"
    try:
        entries = sorted(p for p in storage.iterdir() if p.is_dir()) if storage.is_dir() else []
    except OSError:
        entries = []
    for name, prefix, legacy in (("OneDrive", "onedrive", None), ("Google Drive", "googledrive", home / "Google Drive"),
                                 ("Dropbox", "dropbox", home / "Dropbox")):
        found = next((p for p in entries if p.name.lower().startswith(prefix)), None) or \
            (legacy if legacy is not None and legacy.is_dir() else None)
        if found is not None:
            out.append(CloudProvider(name, f"{name} folder found", False, {"path": str(found)}))
    return out


def cloud_layer(providers: Sequence[CloudProvider], missing_hint: str, none_text: str) -> Layer:
    if not providers:
        return Layer(CLOUD, MISSING, none_text, hint=missing_hint)
    return Layer(CLOUD, OK, "; ".join(p.detail for p in providers) + ". " + CLOUD_NOTE)


def collect_time_machine(now: dt.datetime, runner: Optional[Callable[..., Tuple[int, str, str]]] = None,
                         providers: Sequence[CloudProvider] = ()) -> Tuple[List[Layer], List[Finding]]:
    """Run ``tmutil`` and read the Time Machine preferences, then assess Time Machine."""
    runner = runner or run
    destinations: Optional[List[Dict[str, str]]] = None  # None = tmutil could not tell
    rc, out, err = runner(["tmutil", "destinationinfo"], timeout=CMD_TIMEOUT_S)
    if rc == 0 or "no destinations" in _text(out, err).lower():
        destinations = parse_tmutil_destinations(out)
    prefs: Optional[TimeMachinePrefs] = None
    rc, out, err = runner(["defaults", "read", TIME_MACHINE_PLIST], timeout=CMD_TIMEOUT_S)
    if rc == 0 and out.strip():
        prefs = parse_timemachine_defaults(out)
    elif "does not exist" in _text(out, err).lower():
        prefs = TimeMachinePrefs()  # this Mac has no Time Machine preferences at all
    latest, problem = None, ""
    if destinations or (prefs and (prefs.destination_ids or prefs.last_destination_id)):
        rc, out, err = runner(["tmutil", "latestbackup"], timeout=CMD_TIMEOUT_S)
        latest, problem = parse_tmutil_latest(rc, out, err)
    layer, findings = assess_time_machine(time_machine_state(destinations, prefs, latest, problem, now), now, providers)
    return [layer], findings


# =========================================================================== Linux: snapshot and backup tools

TIMESHIFT_SNAPSHOT_GLOBS = (
    "timeshift/snapshots", "timeshift-btrfs/snapshots",
    "run/timeshift/backup/timeshift/snapshots", "run/timeshift/backup/timeshift-btrfs/snapshots",
    "run/timeshift/*/backup/timeshift/snapshots", "run/timeshift/*/backup/timeshift-btrfs/snapshots",
    "media/*/*/timeshift/snapshots", "run/media/*/*/timeshift/snapshots", "mnt/*/timeshift/snapshots",
    "mnt/timeshift/snapshots",
)
_TIMESHIFT_NAME = re.compile(r"^(\d{4})-(\d{2})-(\d{2})_(\d{2})-(\d{2})-(\d{2})")
_TIMESHIFT_SCHEDULES = ("monthly", "weekly", "daily", "hourly", "boot")


@dataclass
class ToolState:
    """A snapshot or backup tool that is in use on this machine."""

    name: str
    kind: str  # "snapshot" | "backup"
    last: Optional[dt.datetime] = None  # newest snapshot / backup, None if there is none or it could not be read
    known: bool = True  # False: the tool is set up but its newest run could not be read (root, unmounted disk ...)
    detail: str = ""


def _mtime(path: Path) -> Optional[dt.datetime]:
    try:
        return _sane(dt.datetime.fromtimestamp(path.stat().st_mtime, tz=dt.timezone.utc))
    except (OSError, OverflowError, ValueError):
        return None


def _spaced_dates(text: str) -> List[dt.datetime]:
    return [w for w in (_local(*(int(g) for g in m)) for m in _SPACED_DATE.findall(text or "")) if w]


def detect_timeshift(root: Optional[Path] = None) -> Optional[ToolState]:
    """Timeshift: ``/etc/timeshift/timeshift.json`` is the configuration; snapshots are folders named
    ``YYYY-MM-DD_HH-MM-SS`` on the backup device, which is only visible while it is mounted."""
    root = root or LINUX_ROOT
    cfg = next((p for p in (root / "etc" / "timeshift" / "timeshift.json", root / "etc" / "timeshift.json") if p.is_file()),
               None)
    if cfg is None:
        return None
    schedule: List[str] = []
    try:
        data = json.loads(cfg.read_text(encoding="utf-8", errors="replace"))
        schedule = [s for s in _TIMESHIFT_SCHEDULES if str(data.get(f"schedule_{s}", "")).lower() == "true"]
    except (OSError, ValueError, AttributeError):
        pass
    note = f" (schedule: {', '.join(schedule)})" if schedule else " (no schedule is switched on)"
    folders = [d for pattern in TIMESHIFT_SNAPSHOT_GLOBS for d in root.glob(pattern) if d.is_dir()]
    dates: List[dt.datetime] = []
    for folder in folders:
        for child in folder.iterdir():
            m = _TIMESHIFT_NAME.match(child.name)
            when = _local(*(int(g) for g in m.groups())) if m else None
            if when:
                dates.append(when)
    if dates:
        return ToolState("Timeshift", "snapshot", max(dates), True, note)
    if folders:
        return ToolState("Timeshift", "snapshot", None, True, "is set up but has no snapshot yet" + note)
    return ToolState("Timeshift", "snapshot", None, False, "is set up, but its snapshot folder is not mounted or not readable "
                                                           "(list the snapshots with: sudo timeshift --list)" + note)


def detect_snapper(root: Optional[Path] = None, runner: Optional[Callable[..., Tuple[int, str, str]]] = None
                   ) -> Optional[ToolState]:
    """snapper: configurations in ``/etc/snapper/configs``; ``snapper list`` needs root unless the user is allowed."""
    root = root or LINUX_ROOT
    runner = runner or run
    try:
        configs = sorted(p.name for p in (root / "etc" / "snapper" / "configs").iterdir())
    except OSError:
        return None
    if not configs:
        return None
    dates: List[dt.datetime] = []
    for name in configs[:MAX_SNAPPER_CONFIGS]:
        rc, out, err = runner(["snapper", "-c", name, "--iso", "list"], timeout=CMD_TIMEOUT_S)
        if rc != 0:
            return ToolState("snapper", "snapshot", None, False, "is configured, but its snapshot list needs root "
                                                                 "(run: sudo snapper list)")
        dates += _spaced_dates(out)
    if dates:
        return ToolState("snapper", "snapshot", max(dates))
    return ToolState("snapper", "snapshot", None, True, "is configured but has no snapshot yet")


def detect_zfs(runner: Optional[Callable[..., Tuple[int, str, str]]] = None) -> Optional[ToolState]:
    """ZFS: creation time (epoch seconds) of the newest snapshot of any dataset."""
    runner = runner or run
    rc, out, err = runner(["zfs", "list", "-H", "-p", "-t", "snapshot", "-o", "creation", "-S", "creation"],
                          timeout=CMD_TIMEOUT_S)
    first = next((ln.strip() for ln in (out or "").splitlines() if ln.strip()), "") if rc == 0 else ""
    when = None
    if first.isdigit():
        try:
            when = _sane(dt.datetime.fromtimestamp(int(first), tz=dt.timezone.utc))
        except (OverflowError, OSError, ValueError):
            when = None
    return ToolState("ZFS", "snapshot", when) if when else None


def detect_btrfs(runner: Optional[Callable[..., Tuple[int, str, str]]] = None) -> Optional[ToolState]:
    """Btrfs: ``otime`` of the newest snapshot subvolume of ``/`` (root only; silently absent otherwise)."""
    runner = runner or run
    rc, out, err = runner(["btrfs", "subvolume", "list", "-s", "/"], timeout=CMD_TIMEOUT_S)
    dates = _spaced_dates(out) if rc == 0 else []
    return ToolState("Btrfs", "snapshot", max(dates)) if dates else None


def detect_restic(home: Optional[Path] = None) -> Optional[ToolState]:
    """restic: every repository it used leaves a folder in ``~/.cache/restic`` that is touched on each run."""
    home = home or user_home()
    cache = home / ".cache" / "restic"
    try:
        repos = [p for p in cache.iterdir() if p.is_dir()]
    except OSError:
        return None
    times = [t for t in (_mtime(p) for p in repos) if t]
    if not repos:
        return None
    return ToolState("restic", "backup", max(times) if times else None, bool(times), "" if times else "cache has no date")


def detect_borg(home: Optional[Path] = None) -> Optional[ToolState]:
    """BorgBackup: a cache folder per repository (``~/.cache/borg/<id>``) whose files change on every ``borg create``;
    ``~/.config/borg/security`` alone proves a repository was used but not when."""
    home = home or user_home()
    times: List[dt.datetime] = []
    try:
        for repo in (home / ".cache" / "borg").iterdir():
            if repo.is_dir():
                times += [t for t in [_mtime(repo)] + [_mtime(c) for c in repo.iterdir()] if t]
    except OSError:
        pass
    if times:
        return ToolState("BorgBackup", "backup", max(times))
    try:
        if any((home / ".config" / "borg" / "security").iterdir()):
            return ToolState("BorgBackup", "backup", None, False, "was used, but the time of its last backup is unknown")
    except OSError:
        pass
    return None


def detect_dejadup(runner: Optional[Callable[..., Tuple[int, str, str]]] = None) -> Optional[ToolState]:
    """Deja Dup (GNOME Backups): ``gsettings get org.gnome.DejaDup last-backup`` is empty until the first backup."""
    runner = runner or run
    rc, out, err = runner(["gsettings", "get", "org.gnome.DejaDup", "last-backup"], timeout=CMD_TIMEOUT_S)
    if rc != 0:
        return None
    when = parse_timestamp((out or "").strip().strip("'\""))
    return ToolState("Deja Dup", "backup", when) if when else None


def _safe_detect(name: str, kind: str, fn: Callable[[], Optional[ToolState]]) -> Optional[ToolState]:
    try:
        return fn()
    except Exception as exc:  # one broken detector must not hide the others
        log.warning("detecting %s failed: %s", name, exc, exc_info=True)
        return ToolState(name, kind, None, False, f"could not be checked ({type(exc).__name__})")


def tools_layer(key: str, tools: Sequence[ToolState], now: dt.datetime, none_text: str, hint: str) -> Layer:
    """Layer state from the tools found: ok / stale by the newest run, unknown if a tool's run could not be read and nothing
    recent was seen, missing when nothing (usable) was found."""
    covers = True if key == RESTORE else None
    if not tools:
        return Layer(key, MISSING, none_text, hint=hint, covers_files=covers)
    seen = [t for t in tools if t.last is not None]
    parts = [f"{t.name}: newest {_when(t.last, now)}{t.detail}" if t.last else f"{t.name} {t.detail}".strip() for t in tools]
    detail = "; ".join(parts) + "."
    newest = newest_of(*(t.last for t in tools))
    if newest is not None and _age_days(newest, now) <= STALE_DAYS:
        return Layer(key, OK, detail, newest, covers_files=covers)
    if any(not t.known for t in tools):
        return Layer(key, UNKNOWN, detail, newest, covers_files=covers)
    if seen:
        return Layer(key, STALE, detail, newest, Severity.LOW, f"run a fresh backup or snapshot (the newest is "
                     f"{_age_days(newest, now)} days old)", covers)
    return Layer(key, MISSING, detail, None, hint=hint, covers_files=covers)


LINUX_ROOT = Path("/")  # tests point this at a temporary folder
LINUX_SERVER_NOTE = ("On servers the backups are often taken from outside the machine (a backup server, provider or hypervisor "
                     "snapshots), which Aegis cannot see.")
LINUX_RESTORE_NONE = "No snapshot tool found (checked Timeshift, snapper, ZFS and Btrfs)."
LINUX_BACKUP_NONE = "No backup tool found (checked restic, BorgBackup and Deja Dup)."
LINUX_RESTORE_HINT = "set up Timeshift or snapper for system snapshots"
LINUX_BACKUP_HINT = "set up restic, BorgBackup or Deja Dup to back up your files"


def linux_findings(restore: Layer, backup: Layer, tools: Sequence[ToolState], now: dt.datetime) -> List[Finding]:
    ev = {"tools": [{"tool": t.name, "kind": t.kind, "newest": _iso(t.last), "readable": t.known} for t in tools],
          "checked": ["Timeshift", "snapper", "ZFS", "Btrfs", "restic", "BorgBackup", "Deja Dup"]}
    layers = (restore, backup)
    if all(l.state == MISSING for l in layers):
        desc = ("Aegis found no sign of Timeshift, snapper, ZFS or Btrfs snapshots, restic, BorgBackup or Deja Dup for this "
                "user, so if ransomware encrypted this machine's data (or its disk failed) there is nothing local to "
                "restore from. Servers are often backed up from outside - a backup server that pulls the data, "
                "provider or hypervisor snapshots, a managed database - and desktop backups may run as root or as another "
                "user; Aegis cannot see those, which is why this is only a LOW finding. Good looks like: automatic backups "
                "of your home folder and important data to another machine, drive or cloud bucket, kept for several weeks, "
                "with at least one copy the computer cannot delete or overwrite (an offline drive, an object-lock bucket "
                "or an append-only repository).")
        rec = ("Desktop: open 'Backups' (Deja Dup) and turn on automatic backups to an external drive or cloud account, and "
               "install Timeshift for system snapshots. Command line: restic init --repo /path/to/backup-drive/restic && "
               "restic -r /path/to/backup-drive/restic backup ~ (or borg init --encryption=repokey /path/to/repo && borg "
               "create /path/to/repo::{now} ~), then run it daily from a systemd timer or cron and test a restore with "
               "restic restore latest --target /tmp/restore-test. Server: confirm where its backups are taken and that the "
               "backup target cannot be wiped from this machine.")
        return [Finding(rule_id="AEG-RECOVERY-LINUX-NONE", title="No backup or snapshot tool found", severity=Severity.LOW,
                        category=Category.RANSOMWARE, description=desc, location="recovery:linux", evidence=ev,
                        recommendation=rec, mitre=MITRE_BACKUP + MITRE_RESTORE)]
    if all(l.state in (STALE, MISSING, NA) for l in layers) and any(l.state == STALE for l in layers):
        newest = newest_of(restore.newest, backup.newest)
        days = _age_days(newest, now) if newest else 0
        desc = (f"The newest backup or snapshot Aegis could find is from {_when(newest, now)}. Ransomware that strikes today "
                "can only be undone back to that date, and everything created since is lost. Backups go stale when the "
                "backup drive is not connected, the schedule stopped, or the job fails silently. Good looks like: a backup "
                f"or snapshot from the last {STALE_DAYS} days, with failures that someone notices.")
        rec = ("Run the backup now and check its schedule: restic snapshots / borg list show what exists, 'systemctl list-timers' "
               "shows whether a timer still fires, and the Deja Dup 'Backups' settings show its schedule. Reconnect or "
               "mount the backup drive if it is not available.")
        return [Finding(rule_id="AEG-RECOVERY-LINUX-STALE", title=f"The newest backup or snapshot is {days} days old",
                        severity=Severity.LOW, category=Category.RANSOMWARE, description=desc, location="recovery:linux",
                        evidence=ev, recommendation=rec, mitre=MITRE_BACKUP + MITRE_RESTORE)]
    return []


def check_linux(now: dt.datetime, runner: Optional[Callable[..., Tuple[int, str, str]]] = None, root: Optional[Path] = None,
                home: Optional[Path] = None) -> Tuple[List[Layer], List[Finding]]:
    """Detect snapshot and backup tools (no root needed where possible) and assess both layers."""
    snapshot_detectors = (("Timeshift", lambda: detect_timeshift(root)), ("snapper", lambda: detect_snapper(root, runner)),
                          ("ZFS", lambda: detect_zfs(runner)), ("Btrfs", lambda: detect_btrfs(runner)))
    backup_detectors = (("restic", lambda: detect_restic(home)), ("BorgBackup", lambda: detect_borg(home)),
                        ("Deja Dup", lambda: detect_dejadup(runner)))
    snapshots = [t for t in (_safe_detect(n, "snapshot", fn) for n, fn in snapshot_detectors) if t]
    backups = [t for t in (_safe_detect(n, "backup", fn) for n, fn in backup_detectors) if t]
    restore = tools_layer(RESTORE, snapshots, now, LINUX_RESTORE_NONE, LINUX_RESTORE_HINT)
    backup = tools_layer(BACKUP, backups, now, LINUX_BACKUP_NONE, LINUX_BACKUP_HINT)
    cloud = Layer(CLOUD, NA, "Cloud sync clients are not checked on Linux.")
    return [restore, backup, cloud], linux_findings(restore, backup, snapshots + backups, now)


# =========================================================================== scanner

Part = Tuple[str, Tuple[str, ...], Callable[[], Tuple[List[Layer], List[Finding]]]]


def windows_parts(admin: bool, now: dt.datetime, ps_runner: Optional[Callable[..., Any]] = None) -> List[Part]:
    shared: Dict[str, Any] = {}

    def restore() -> Tuple[List[Layer], List[Finding]]:
        return check_windows_restore(admin, now, ps_runner, shared=shared)

    def files() -> Tuple[List[Layer], List[Finding]]:
        server = shared["server"] if "server" in shared else is_windows_server()
        return check_windows_files(now, server)

    return [("System Restore and shadow copies", (RESTORE,), restore), ("File History and cloud sync", (BACKUP, CLOUD), files)]


def macos_parts(now: dt.datetime, runner: Optional[Callable[..., Tuple[int, str, str]]] = None,
                home: Optional[Path] = None) -> List[Part]:
    shared: Dict[str, Any] = {"providers": []}

    def cloud() -> Tuple[List[Layer], List[Finding]]:
        providers = detect_mac_cloud(home)
        shared["providers"] = providers
        return [cloud_layer(providers, "turn on iCloud Drive 'Desktop & Documents Folders' (System Settings > [your name] > "
                                       "iCloud > iCloud Drive) or another cloud sync with version history",
                            "No iCloud Drive Desktop & Documents sync, OneDrive, Google Drive or Dropbox folder found.")], []

    def time_machine() -> Tuple[List[Layer], List[Finding]]:
        return collect_time_machine(now, runner, shared["providers"])

    restore = Layer(RESTORE, NA, "macOS keeps its local restore points (Time Machine snapshots) as part of Time Machine; "
                                 "see the file backup result.")
    return [("iCloud and cloud sync folders", (CLOUD,), cloud), ("Time Machine", (BACKUP,), time_machine),
            ("restore points", (RESTORE,), lambda: ([restore], []))]


def linux_parts(now: dt.datetime, runner: Optional[Callable[..., Tuple[int, str, str]]] = None,
                root: Optional[Path] = None, home: Optional[Path] = None) -> List[Part]:
    return [("snapshot and backup tools", (RESTORE, BACKUP, CLOUD), lambda: check_linux(now, runner, root, home))]


def run_parts(parts: Sequence[Part], cancel: Optional[Callable[[], bool]] = None,
              report: Optional[Callable[[str], None]] = None) -> Tuple[List[Layer], List[Finding]]:
    """Run every part; one that raises becomes an ERROR layer for each of its layers and never stops the others."""
    layers: List[Layer] = []
    findings: List[Finding] = []
    for label, keys, fn in parts:
        if cancel and cancel():
            break
        if report:
            report(f"checking {label}")
        try:
            got_layers, got_findings = fn()
        except Exception as exc:
            log.warning("recovery check %s failed: %s", label, exc, exc_info=True)
            layers += [Layer(k, UNKNOWN, f"{type(exc).__name__}: {exc}", error=True) for k in keys]
            continue
        layers += got_layers
        findings += got_findings
    return layers, findings


@register
class RecoveryScanner(Scanner):
    name = "recovery"
    title = "Backup & ransomware recovery readiness"
    description = ("Checks whether you could recover from ransomware today: System Restore and shadow copies, File History, "
                   "OneDrive / Google Drive / Dropbox, Time Machine and Linux snapshot and backup tools, with a readiness "
                   "grade (read-only)")
    platforms = ("windows", "linux", "darwin")
    needs_admin_for_full_results = True

    def run(self, ctx: ScanContext) -> Iterator[Emitted]:
        try:
            now = _utcnow()
            if IS_WINDOWS:
                parts = windows_parts(ctx.is_admin, now)
            elif IS_MAC:
                parts = macos_parts(now)
            else:
                parts = linux_parts(now)
            layers, findings = run_parts(parts, lambda: ctx.cancelled, lambda msg: ctx.report(self.name, msg))
            layers.append(offline_layer())
            ordered = sorted(layers, key=lambda l: LAYER_ORDER.index(l.key))
            for layer in ordered:
                yield layer_check(layer)
            yield from findings
            ctx.bump("recovery_layers_ok", sum(1 for l in ordered if l.state == OK))
            yield summary_finding(ordered, "" if IS_WINDOWS or IS_MAC else LINUX_SERVER_NOTE)
        except Exception as exc:  # never raise out of run()
            log.warning("recovery scan failed: %s", exc, exc_info=True)
            yield CheckResult("AEG-RECOVERY-ERROR", self.title, CheckStatus.ERROR, f"{type(exc).__name__}: {exc}",
                              Category.RANSOMWARE)
