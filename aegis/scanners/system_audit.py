"""System hardening audit (Microsoft Secure Score / CIS quick-check style).

Every check yields a `CheckResult` (pass, fail, warn, skip or error) and every
failed check additionally yields a `Finding` with a plain-English
recommendation and, where a fix is safe and reversible, a `Remediation`.

Status mapping: a failed check of MEDIUM severity or above is `FAIL`; LOW / INFO
items are `WARN`; checks that could not be evaluated (not admin, feature not
present) are `SKIP`; unexpected exceptions become `ERROR` and never abort the
audit.

Design notes
------------
* Registry is preferred for Windows settings (locale independent). Everything
  that needs WMI/Defender cmdlets is collected in ONE batched PowerShell call
  returning JSON (`collect_windows_facts`) to keep the audit fast.
* Every check function is pure with respect to its inputs: it takes an
  `AuditEnv` (today's date, admin flag, PowerShell facts) and returns a list of
  `Check` objects. Registry helpers are looked up at call time so unit tests can
  monkeypatch `aegis.scanners.system_audit.reg_read` etc.
* The Windows end-of-support table lives in `WINDOWS_CLIENT_RELEASES` /
  `WINDOWS_SERVER_RELEASES` / `WINDOWS_LTSC_EOL` below - update those when
  Microsoft publishes new lifecycle dates.
"""

from __future__ import annotations

import datetime as dt
import fnmatch
import glob
import logging
import os
import re
import shutil
import stat as statmod
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from aegis.core.models import Category, CheckResult, CheckStatus, Finding, Remediation, Severity
from aegis.core.platform import (
    IS_LINUX,
    IS_MAC,
    IS_WINDOWS,
    as_list,
    powershell_json,
    reg_read,
    reg_subkeys,
    reg_values,
    run,
)
from aegis.scanners.base import Emitted, ScanContext, Scanner, register

log = logging.getLogger("aegis.system_audit")

RULE_PREFIX = "AEG-AUDIT-"

# =========================================================================== OS support data
# One row per Windows client feature release:
#   (first build, display name, family, end of servicing Home/Pro, end of servicing Enterprise/Education)
# A build maps to the row with the largest first-build <= the actual build.
D = dt.date
WINDOWS_CLIENT_RELEASES: List[Tuple[int, str, str, dt.date, dt.date]] = [
    (2600, "Windows XP", "xp", D(2014, 4, 8), D(2014, 4, 8)),
    (6000, "Windows Vista", "vista", D(2017, 4, 11), D(2017, 4, 11)),
    (7600, "Windows 7", "win7", D(2020, 1, 14), D(2020, 1, 14)),
    (9200, "Windows 8", "win8", D(2016, 1, 12), D(2016, 1, 12)),
    (9600, "Windows 8.1", "win8", D(2023, 1, 10), D(2023, 1, 10)),
    (10240, "Windows 10 1507", "win10", D(2017, 5, 9), D(2017, 5, 9)),
    (10586, "Windows 10 1511", "win10", D(2017, 10, 10), D(2017, 10, 10)),
    (14393, "Windows 10 1607", "win10", D(2018, 4, 10), D(2019, 4, 9)),
    (15063, "Windows 10 1703", "win10", D(2018, 10, 9), D(2019, 10, 8)),
    (16299, "Windows 10 1709", "win10", D(2019, 4, 9), D(2020, 10, 13)),
    (17134, "Windows 10 1803", "win10", D(2019, 11, 12), D(2021, 5, 11)),
    (17763, "Windows 10 1809", "win10", D(2020, 11, 10), D(2021, 5, 11)),
    (18362, "Windows 10 1903", "win10", D(2020, 12, 8), D(2020, 12, 8)),
    (18363, "Windows 10 1909", "win10", D(2021, 5, 11), D(2022, 5, 10)),
    (19041, "Windows 10 2004", "win10", D(2021, 12, 14), D(2021, 12, 14)),
    (19042, "Windows 10 20H2", "win10", D(2022, 5, 10), D(2023, 5, 9)),
    (19043, "Windows 10 21H1", "win10", D(2022, 12, 13), D(2022, 12, 13)),
    (19044, "Windows 10 21H2", "win10", D(2023, 6, 13), D(2024, 6, 11)),
    (19045, "Windows 10 22H2", "win10", D(2025, 10, 14), D(2025, 10, 14)),
    (22000, "Windows 11 21H2", "win11", D(2023, 10, 10), D(2024, 10, 8)),
    (22621, "Windows 11 22H2", "win11", D(2024, 10, 8), D(2025, 10, 14)),
    (22631, "Windows 11 23H2", "win11", D(2025, 11, 11), D(2026, 11, 10)),
    (26100, "Windows 11 24H2", "win11", D(2026, 10, 13), D(2027, 10, 12)),
    (26200, "Windows 11 25H2", "win11", D(2027, 10, 12), D(2028, 10, 10)),
]
# Builds at or above this are newer than the table above: treat as supported.
NEWER_THAN_TABLE_BUILD = 27000

# Long-term servicing channel editions (EditionID EnterpriseS / IoTEnterpriseS): (build, iot) -> end of support.
WINDOWS_LTSC_EOL: Dict[Tuple[int, bool], dt.date] = {
    (10240, False): D(2025, 10, 14),  # Enterprise 2015 LTSB
    (14393, False): D(2026, 10, 13),  # Enterprise 2016 LTSB
    (14393, True): D(2026, 10, 13),
    (17763, False): D(2029, 1, 9),  # Enterprise 2019 LTSC
    (17763, True): D(2029, 1, 9),
    (19044, False): D(2027, 1, 12),  # Enterprise 2021 LTSC
    (19044, True): D(2032, 1, 13),  # IoT Enterprise 2021 LTSC
    (26100, False): D(2029, 10, 9),  # Enterprise 2024 LTSC
    (26100, True): D(2034, 10, 10),  # IoT Enterprise 2024 LTSC
}

# (first build, display name, end of support)
WINDOWS_SERVER_RELEASES: List[Tuple[int, str, dt.date]] = [
    (3790, "Windows Server 2003", D(2015, 7, 14)),
    (6000, "Windows Server 2008", D(2020, 1, 14)),
    (7600, "Windows Server 2008 R2", D(2020, 1, 14)),
    (9200, "Windows Server 2012", D(2023, 10, 10)),
    (9600, "Windows Server 2012 R2", D(2023, 10, 10)),
    (14393, "Windows Server 2016", D(2027, 1, 12)),
    (17763, "Windows Server 2019", D(2029, 1, 9)),
    (20348, "Windows Server 2022", D(2031, 10, 14)),
    (26100, "Windows Server 2025", D(2034, 10, 10)),
]
del D

ENDING_SOON_DAYS = 120  # warn this many days before end of support

# Windows Update staleness thresholds (days since last successful non-definition install)
WU_STALE_MEDIUM_DAYS = 45
WU_STALE_HIGH_DAYS = 90
DEFENDER_SIGNATURE_MAX_AGE_DAYS = 7


# =========================================================================== check model
@dataclass
class Check:
    """Outcome of one check before it is turned into CheckResult (+ Finding)."""

    key: str  # suffix of the rule id, e.g. "UAC-DISABLED"
    title: str
    ok: Optional[bool]  # True = pass, False = fail, None = skipped / not applicable
    detail: str = ""
    severity: Severity = Severity.LOW
    description: str = ""
    recommendation: str = ""
    location: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: Optional[Remediation] = None
    mitre: List[str] = field(default_factory=list)
    category: str = Category.SYSTEM
    error: bool = False  # ok is None because evaluation failed (CheckStatus.ERROR)

    @property
    def check_id(self) -> str:
        return RULE_PREFIX + self.key

    @property
    def status(self) -> str:
        if self.ok is True:
            return CheckStatus.PASS
        if self.ok is None:
            return CheckStatus.ERROR if self.error else CheckStatus.SKIP
        return CheckStatus.FAIL if self.severity >= Severity.MEDIUM else CheckStatus.WARN

    def to_result(self) -> CheckResult:
        return CheckResult(check_id=self.check_id, title=self.title, status=self.status,
                           detail=self.detail or self.description, category=self.category)

    def to_finding(self) -> Optional[Finding]:
        if self.ok is not False:
            return None
        return Finding(
            rule_id=self.check_id,
            title=self.title,
            severity=self.severity,
            category=self.category,
            description=self.description or self.detail,
            location=self.location or self.title,
            evidence=self.evidence,
            recommendation=self.recommendation,
            remediation=self.remediation,
            mitre=list(self.mitre),
        )


def passed(key: str, title: str, detail: str = "", **kw: Any) -> Check:
    return Check(key=key, title=title, ok=True, detail=detail, **kw)


def skipped(key: str, title: str, detail: str) -> Check:
    return Check(key=key, title=title, ok=None, detail=detail)


def failed(key: str, title: str, severity: Severity, description: str, recommendation: str, location: str,
           evidence: Optional[Dict[str, Any]] = None, remediation: Optional[Remediation] = None,
           mitre: Optional[Sequence[str]] = None, category: str = Category.SYSTEM) -> Check:
    return Check(key=key, title=title, ok=False, detail=description, severity=severity, description=description,
                 recommendation=recommendation, location=location, evidence=evidence or {},
                 remediation=remediation, mitre=list(mitre or []), category=category)


def set_reg(key: str, value: str, data: Any, description: str, hive: str = "HKLM") -> Remediation:
    return Remediation("set_registry_value", {"hive": hive, "key": key, "value": value, "data": data}, description)


def run_cmd(command: Sequence[str], description: str) -> Remediation:
    return Remediation("run_command", {"command": list(command), "powershell": False}, description)


def run_ps(script: str, description: str) -> Remediation:
    return Remediation("run_command", {"command": script, "powershell": True}, description)


@dataclass
class AuditEnv:
    today: dt.date
    is_admin: bool = False
    facts: Dict[str, Any] = field(default_factory=dict)  # batched PowerShell results (Windows)
    deep: bool = False


# =========================================================================== small helpers
def to_int(value: Any) -> Optional[int]:
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


def rd(hive: str, key: str, value: str) -> Any:
    return reg_read(hive, key, value)


def rd_int(hive: str, key: str, value: str) -> Optional[int]:
    return to_int(reg_read(hive, key, value))


def parse_iso_date(text: Any) -> Optional[dt.date]:
    """Date part of an ISO-8601 timestamp (PowerShell 'o' format has 7 fractional digits)."""
    if not text:
        return None
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})", str(text))
    if not m:
        return None
    try:
        return dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return None


def hkey(hive: str, key: str, value: str = "") -> str:
    return f"{hive}\\{key}" + (f"\\{value}" if value else "")


# =========================================================================== PowerShell facts (Windows)
_PS_FACTS = r"""
$ErrorActionPreference='SilentlyContinue'
$r=[ordered]@{}
try{$r['av']=@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object {[pscustomobject]@{name=[string]$_.displayName;state=[int64]$_.productState;exe=[string]$_.pathToSignedProductExe}})}catch{}
try{$r['fw']=@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName FirewallProduct | ForEach-Object {[pscustomobject]@{name=[string]$_.displayName;state=[int64]$_.productState}})}catch{}
try{$m=Get-MpComputerStatus; if($m){$r['mp']=[pscustomobject]@{AMServiceEnabled=[bool]$m.AMServiceEnabled;AntivirusEnabled=[bool]$m.AntivirusEnabled;RealTimeProtectionEnabled=[bool]$m.RealTimeProtectionEnabled;BehaviorMonitorEnabled=[bool]$m.BehaviorMonitorEnabled;IsTamperProtected=[bool]$m.IsTamperProtected;AntivirusSignatureAge=[int64]$m.AntivirusSignatureAge;QuickScanAge=[int64]$m.QuickScanAge;AMRunningMode=[string]$m.AMRunningMode}}}catch{}
try{$p=Get-MpPreference; if($p){$r['pref']=[pscustomobject]@{ExclusionPath=@($p.ExclusionPath|Where-Object{$_});ExclusionProcess=@($p.ExclusionProcess|Where-Object{$_});ExclusionExtension=@($p.ExclusionExtension|Where-Object{$_});PUAProtection=[int]$p.PUAProtection;EnableControlledFolderAccess=[int]$p.EnableControlledFolderAccess;MAPSReporting=[int]$p.MAPSReporting}}}catch{}
try{$s=New-Object -ComObject Microsoft.Update.Session;$se=$s.CreateUpdateSearcher();$n=$se.GetTotalHistoryCount();if($n -gt 0){$h=@($se.QueryHistory(0,[Math]::Min($n,300))|Where-Object{$_.ResultCode -eq 2 -and $_.Title -notmatch 'Definition|Security Intelligence|Malicious Software Removal|Defender Antivirus'}|Sort-Object Date -Descending|Select-Object -First 1);if($h.Count -gt 0){$r['wu_last']=$h[0].Date.ToUniversalTime().ToString('o');$r['wu_title']=[string]$h[0].Title}}}catch{}
if(-not $r['wu_last']){try{$hf=Get-HotFix|Where-Object{$_.InstalledOn}|Sort-Object InstalledOn -Descending|Select-Object -First 1;if($hf){$r['wu_last']=$hf.InstalledOn.ToUniversalTime().ToString('o');$r['wu_title']=[string]$hf.HotFixID}}catch{}}
try{$r['users']=@(Get-LocalUser|ForEach-Object{[pscustomobject]@{name=[string]$_.Name;sid=[string]$_.SID.Value;enabled=[bool]$_.Enabled;pwreq=[bool]$_.PasswordRequired;never_expires=($null -eq $_.PasswordExpires)}})}catch{}
try{$id=[Security.Principal.WindowsIdentity]::GetCurrent();$r['user']=[string]$id.Name;$r['in_admins']=[bool]($id.Groups|Where-Object{$_.Value -eq 'S-1-5-32-544'})}catch{}
try{$v=Get-CimInstance -Namespace root/cimv2/security/microsoftvolumeencryption -ClassName Win32_EncryptableVolume -Filter "DriveLetter='$env:SystemDrive'" -ErrorAction Stop;if($v){$r['bitlocker']=[pscustomobject]@{status=[int]$v.ProtectionStatus;drive=[string]$env:SystemDrive}}}catch{}
try{$dg=Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop;if($dg){$r['dg']=[pscustomobject]@{vbs=[int]$dg.VirtualizationBasedSecurityStatus;running=@($dg.SecurityServicesRunning|ForEach-Object{[int]$_})}}}catch{}
try{$t=Get-CimInstance -Namespace root/cimv2/security/microsofttpm -ClassName Win32_Tpm -ErrorAction Stop;if($t){$r['tpm']=[pscustomobject]@{enabled=[bool]$t.IsEnabled_InitialValue;spec=[string]$t.SpecVersion}}}catch{}
try{$sv=Get-Service RemoteRegistry;if($sv){$r['remote_registry']=[string]$sv.Status}}catch{}
try{$c=Get-SmbServerConfiguration;if($c){$r['smb1_server']=[bool]$c.EnableSMB1Protocol}}catch{}
if($admin){try{$f=Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root;if($f){$r['ps2']=[string]$f.State}}catch{}}
$r|ConvertTo-Json -Depth 5 -Compress
"""


def collect_windows_facts(admin: bool) -> Dict[str, Any]:
    """One batched PowerShell call for everything that registry cannot answer."""
    script = f"$admin={'$true' if admin else '$false'};" + _PS_FACTS
    data = powershell_json(script, timeout=150)
    return data if isinstance(data, dict) else {}


# =========================================================================== OS support
@dataclass
class OSSupport:
    name: str
    family: str  # xp|vista|win7|win8|win10|win11|server|unknown
    build: int
    eol: Optional[dt.date]
    status: str  # supported | ending_soon | eol | unknown
    days_left: Optional[int]
    severity: Optional[Severity]
    detail: str
    recommendation: str = ""


def _is_ent_edu(edition: str) -> bool:
    e = edition.lower()
    return "enterprise" in e or "education" in e


def evaluate_os_support(build: int, edition: str = "", today: Optional[dt.date] = None, installation_type: str = "",
                        product_name: str = "", display_version: str = "", ubr: Optional[int] = None) -> OSSupport:
    """Map a Windows build number to its release name and end-of-support date and
    compare with `today`. Pure function so it can be tested with injected dates."""
    today = today or dt.date.today()
    ed_l = (edition or "").lower()
    server = installation_type.lower() == "server" or "server" in ed_l or "server" in product_name.lower()
    build_txt = f"{build}.{ubr}" if ubr is not None else str(build)

    name = ""
    family = "unknown"
    eol: Optional[dt.date] = None
    notes: List[str] = []

    if server:
        row = None
        for first, nm, end in WINDOWS_SERVER_RELEASES:
            if build >= first:
                row = (nm, end)
        if row:
            name, eol = row
            family = "server"
            if build >= 26100 and build >= NEWER_THAN_TABLE_BUILD + 1000:
                eol = None
    else:
        row_c = None
        for first, nm, fam, e_pro, e_ent in WINDOWS_CLIENT_RELEASES:
            if build >= first:
                row_c = (first, nm, fam, e_pro, e_ent)
        if row_c:
            first, name, family, e_pro, e_ent = row_c
            eol = e_ent if _is_ent_edu(edition) else e_pro
            if _is_ent_edu(edition) and e_ent != e_pro:
                notes.append(f"Enterprise/Education editions are serviced until {e_ent.isoformat()} "
                             f"(Home/Pro: {e_pro.isoformat()}).")
            # Long-term servicing channel editions follow their own lifecycle.
            if ed_l.startswith(("enterprises", "iotenterprises")):
                iot = ed_l.startswith("iot")
                ltsc = WINDOWS_LTSC_EOL.get((first, iot)) or WINDOWS_LTSC_EOL.get((build, iot))
                if ltsc:
                    eol = ltsc
                    notes.append("Long-Term Servicing Channel edition: lifecycle is longer than the "
                                 "regular release.")
            if build >= NEWER_THAN_TABLE_BUILD:
                eol = None
                name = f"Windows 11 (build {build}, newer than this audit knows)"
                notes.append("Release is newer than Aegis' lifecycle table; assuming it is supported.")

    if display_version and name and family in ("win10", "win11") and display_version.lower() not in name.lower():
        name = f"{name} ({display_version})"

    if not name or (eol is None and family == "unknown"):
        return OSSupport(name or f"Windows build {build}", family, build, None, "unknown", None, None,
                         f"Could not map build {build_txt} to a known Windows release.")
    if eol is None:
        return OSSupport(name, family, build, None, "supported", None, None,
                         f"{name} (build {build_txt}) - " + " ".join(notes))

    days_left = (eol - today).days
    note_txt = (" " + " ".join(notes)) if notes else ""
    if days_left >= 0 and days_left > ENDING_SOON_DAYS:
        return OSSupport(name, family, build, eol, "supported", days_left, None,
                         f"{name} (build {build_txt}) is supported until {eol.isoformat()} "
                         f"({days_left} days).{note_txt}")
    if days_left >= 0:
        return OSSupport(
            name, family, build, eol, "ending_soon", days_left, Severity.LOW,
            f"{name} (build {build_txt}) stops receiving security updates on {eol.isoformat()} "
            f"({days_left} days from now).{note_txt}",
            "Plan the upgrade now: open Settings > Windows Update and install the newest Windows 11 feature "
            "update (or move to a newer release) before support ends.")

    # past end of support
    ago = -days_left
    sev = Severity.CRITICAL if family in ("xp", "vista", "win7", "win8") else Severity.HIGH
    if family == "win10":
        rec = ("Upgrade to Windows 11 (Settings > Windows Update shows whether your PC is eligible). If the PC "
               "cannot run Windows 11, replace it or switch to a supported OS; organisations can still buy "
               "Extended Security Updates (ESU) for Windows 10 for up to three years after end of support. "
               "Until then keep the PC off risky tasks (web browsing, email, remote access).")
        detail = (f"{name} (build {build_txt}) reached end of support on {eol.isoformat()} ({ago} days ago): it no "
                  f"longer receives free security updates unless the device is enrolled in ESU.{note_txt}")
    elif family == "win11":
        rec = (f"Open Settings > Windows Update and install the latest Windows 11 feature update "
               f"(currently 25H2 or newer). {name} no longer receives security fixes.")
        detail = (f"{name} (build {build_txt}) reached end of servicing on {eol.isoformat()} ({ago} days ago); "
                  f"it no longer receives security updates.{note_txt}")
    elif family == "server":
        rec = ("Upgrade to a supported Windows Server release, or enrol in Extended Security Updates (ESU) "
               "where Microsoft offers them for this version.")
        detail = f"{name} reached end of support on {eol.isoformat()} ({ago} days ago).{note_txt}"
    else:
        rec = ("This version of Windows has been unsupported for years and has known, unpatched, widely exploited "
               "vulnerabilities. Back up your files and move to a supported version of Windows (or Linux) "
               "immediately; do not use it for internet-facing tasks.")
        detail = f"{name} reached end of support on {eol.isoformat()} ({ago} days ago).{note_txt}"
    return OSSupport(name, family, build, eol, "eol", days_left, sev, detail, rec)


def check_os_support(env: AuditEnv) -> List[Check]:
    key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    build = to_int(rd("HKLM", key, "CurrentBuild")) or to_int(rd("HKLM", key, "CurrentBuildNumber"))
    if not build:
        return [skipped("OS-SUPPORT", "Operating system is still supported", "Could not read Windows build number.")]
    res = evaluate_os_support(
        build,
        edition=str(rd("HKLM", key, "EditionID") or ""),
        today=env.today,
        installation_type=str(rd("HKLM", key, "InstallationType") or ""),
        product_name=str(rd("HKLM", key, "ProductName") or ""),
        display_version=str(rd("HKLM", key, "DisplayVersion") or rd("HKLM", key, "ReleaseId") or ""),
        ubr=to_int(rd("HKLM", key, "UBR")),
    )
    title = "Operating system is still supported"
    ev = {"name": res.name, "build": res.build, "end_of_support": res.eol.isoformat() if res.eol else None,
          "days_left": res.days_left}
    if res.status == "unknown":
        return [skipped("OS-SUPPORT", title, res.detail)]
    if res.status == "supported":
        return [passed("OS-SUPPORT", title, res.detail)]
    ttl = (f"{res.name} is no longer supported" if res.status == "eol"
           else f"{res.name} support ends soon")
    return [failed("OS-SUPPORT", ttl, res.severity or Severity.LOW, res.detail, res.recommendation,
                   location=f"{res.name} (build {res.build})", evidence=ev, mitre=["T1190"])]


# =========================================================================== antivirus
def decode_product_state(state: Any) -> Tuple[bool, bool]:
    """Decode SecurityCenter2 productState -> (enabled, definitions_up_to_date).

    Bit 0x1000 = product on (0x2000 snoozed, 0x3000 expired); bit 0x10 = signatures out of date.
    e.g. 0x061100 (Defender on, current), 0x061110 (on, out of date), 0x060100 (off).
    """
    s = to_int(state)
    if s is None:
        return False, False
    enabled = bool(s & 0x1000) and not (s & 0x2000)
    up_to_date = not (s & 0x10)
    return enabled, up_to_date


def is_defender_name(name: str) -> bool:
    n = (name or "").lower()
    return "windows defender" in n or "microsoft defender" in n


@dataclass
class AVState:
    products: List[Dict[str, Any]]  # name, enabled, up_to_date, is_defender
    mp: Optional[Dict[str, Any]]
    third_party_active: List[Dict[str, Any]]
    defender_active: bool  # Defender real-time protection really on
    defender_primary: bool  # Defender is the product protecting the PC (no active 3rd party)
    passive: bool


def build_av_state(facts: Dict[str, Any]) -> Optional[AVState]:
    prods = []
    for p in as_list(facts.get("av")):
        if not isinstance(p, dict):
            continue
        enabled, uptodate = decode_product_state(p.get("state"))
        name = str(p.get("name") or "Unknown")
        prods.append({"name": name, "enabled": enabled, "up_to_date": uptodate, "is_defender": is_defender_name(name),
                      "state": to_int(p.get("state"))})
    mp = facts.get("mp") if isinstance(facts.get("mp"), dict) else None
    if not prods and not mp:
        return None
    if mp:
        defender_active = bool(mp.get("AntivirusEnabled") and mp.get("RealTimeProtectionEnabled"))
    else:
        defender_active = any(p["enabled"] and p["is_defender"] for p in prods)
    third = [p for p in prods if p["enabled"] and not p["is_defender"]]
    passive = bool(mp and "passive" in str(mp.get("AMRunningMode", "")).lower())
    return AVState(prods, mp, third, defender_active, defender_active and not third and not passive, passive)


def check_antivirus(env: AuditEnv) -> List[Check]:
    st = build_av_state(env.facts)
    t_active, t_sigs, t_tamper, t_beh = ("Antivirus protection is active", "Antivirus definitions are up to date",
                                         "Defender tamper protection is on", "Defender behaviour monitoring is on")
    if st is None:
        msg = "Security Center and Defender status were unavailable (Windows Server or restricted session)."
        return [skipped("AV-ACTIVE", t_active, msg), skipped("AV-SIGNATURES", t_sigs, msg),
                skipped("AV-TAMPER", t_tamper, msg)]
    out: List[Check] = []
    loc = "Windows Security / antivirus"
    names = [p["name"] for p in st.products]
    ev: Dict[str, Any] = {"registered_products": names, "defender_realtime": st.defender_active}

    # ---- active protection
    if st.third_party_active or st.defender_active:
        who = ", ".join(p["name"] for p in st.third_party_active) or "Microsoft Defender"
        out.append(passed("AV-ACTIVE", t_active, f"Protected by {who}."))
    else:
        only_defender = bool(st.mp) and all(p["is_defender"] for p in st.products)
        if only_defender:
            title = "Microsoft Defender real-time protection is turned off"
            why = ("Microsoft Defender is installed but real-time protection is switched off and no other "
                   "antivirus is active, so malware can run without being blocked.")
        else:
            title, why = "No active antivirus", "Every registered antivirus product is switched off or expired."
        fix = run_ps("Set-MpPreference -DisableRealtimeMonitoring $false",
                     "Turn Microsoft Defender real-time protection back on") if st.mp else None
        out.append(failed(
            "AV-ACTIVE", title, Severity.CRITICAL, why,
            "Open Windows Security > Virus & threat protection > Manage settings and turn on Real-time protection "
            "(or open your antivirus program and re-enable protection). If it turns itself off or cannot be "
            "turned on, treat the PC as possibly infected: run an offline scan (Defender Offline) and Aegis' full scan.",
            loc, ev, fix, ["T1562.001"]))

    # ---- definitions
    stale: List[Tuple[str, str]] = []
    if st.defender_primary and st.mp and to_int(st.mp.get("AntivirusSignatureAge")) is not None:
        age = to_int(st.mp.get("AntivirusSignatureAge")) or 0
        if age > DEFENDER_SIGNATURE_MAX_AGE_DAYS:
            stale.append(("Microsoft Defender", f"signatures are {age} days old"))
    for p in st.third_party_active:
        if not p["up_to_date"]:
            stale.append((p["name"], "reports out-of-date definitions"))
    if not (st.third_party_active or st.defender_active):
        out.append(skipped("AV-SIGNATURES", t_sigs, "No active antivirus to check."))
    elif stale:
        who, why = stale[0]
        fix = run_ps("Update-MpSignature", "Download the latest Microsoft Defender definitions") \
            if who == "Microsoft Defender" else None
        out.append(failed(
            "AV-SIGNATURES", f"Antivirus definitions are out of date ({who})", Severity.MEDIUM,
            f"{who}: {why}. Old definitions miss new malware.",
            "Open Windows Security > Virus & threat protection > Protection updates > Check for updates "
            "(or update your antivirus). Make sure the PC is online and Windows Update is not blocked.",
            f"antivirus:{who}", {"stale": [{"product": a, "reason": b} for a, b in stale]}, fix, ["T1562.001"]))
    else:
        out.append(passed("AV-SIGNATURES", t_sigs, "Definitions are current."))

    # ---- tamper protection / behaviour monitoring (only meaningful when Defender is the primary AV)
    if not st.defender_primary or not st.mp:
        why = "Microsoft Defender is not the active antivirus." if st.mp or st.third_party_active else \
            "Defender status unavailable."
        out.append(skipped("AV-TAMPER", t_tamper, why))
        out.append(skipped("AV-BEHAVIOR", t_beh, why))
        return out
    if st.mp.get("IsTamperProtected") is False:
        out.append(failed(
            "AV-TAMPER", "Defender tamper protection is off", Severity.LOW,
            "Tamper protection stops malware (and scripts) from switching off Defender or adding exclusions.",
            "Open Windows Security > Virus & threat protection > Manage settings and turn on Tamper Protection.",
            "Microsoft Defender tamper protection", {"IsTamperProtected": False}, None, ["T1562.001"]))
    else:
        out.append(passed("AV-TAMPER", t_tamper))
    if st.mp.get("BehaviorMonitorEnabled") is False:
        out.append(failed(
            "AV-BEHAVIOR", "Defender behaviour monitoring is off", Severity.LOW,
            "Behaviour monitoring catches malware that is not yet in the signature database.",
            "Enable real-time protection in Windows Security; behaviour monitoring turns on with it.",
            "Microsoft Defender behaviour monitoring", {"BehaviorMonitorEnabled": False},
            run_ps("Set-MpPreference -DisableBehaviorMonitoring $false", "Turn on Defender behaviour monitoring"),
            ["T1562.001"]))
    else:
        out.append(passed("AV-BEHAVIOR", t_beh))
    qage = to_int(st.mp.get("QuickScanAge"))
    if qage is not None and (qage > 30):
        never = qage >= 4294967295
        out.append(failed(
            "AV-SCAN-AGE", "No recent antivirus scan", Severity.INFO,
            "Defender has " + ("never completed a quick scan." if never else f"not completed a quick scan for {qage} days."),
            "Run a scan from Windows Security > Virus & threat protection > Quick scan (or run Aegis).",
            "Microsoft Defender scan history", {"QuickScanAge": qage}, None))
    return out


# =========================================================================== Defender preferences
_BROAD_PROCESSES = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
                    "rundll32.exe", "regsvr32.exe", "wmic.exe", "certutil.exe", "bitsadmin.exe", "msbuild.exe",
                    "python.exe", "pythonw.exe", "node.exe", "java.exe", "javaw.exe", "explorer.exe", "svchost.exe"}
_BROAD_EXTENSIONS = {"exe", "dll", "ps1", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "hta", "scr", "com", "msi",
                     "lnk", "jar", "sys", "docm", "xlsm", "pptm", "py", "*", "tmp", "dat", "bin"}
_DRIVE_ROOT = re.compile(r"^[a-z]:\\?\*?$")
# Folders malware drops into and excludes; matched against the lower-cased path with a trailing backslash.
_RISKY_FRAGMENTS = ("\\appdata\\local\\temp\\", "\\appdata\\roaming\\", "\\temp\\", "\\tmp\\",
                    "\\downloads\\", "\\users\\public\\", "\\windows\\temp\\", "\\perflogs\\",
                    "\\$recycle.bin\\")
_RISKY_EXACT_ENDS = ("\\appdata", "\\appdata\\local", "\\appdata\\locallow", "\\appdata\\roaming")
_WHOLE_SYSTEM_DIRS = {"c:\\users", "%userprofile%", "c:\\windows", "c:\\windows\\system32", "%systemroot%", "%windir%",
                      "c:\\program files", "c:\\program files (x86)", "c:\\programdata", "%programdata%",
                      "%systemdrive%\\users", "%programfiles%", "%localappdata%"}
_RISKY_REASON = "excludes a folder malware commonly runs from (temp/AppData/Downloads/Public)"


def classify_exclusion(kind: str, value: str) -> Optional[str]:
    """Return why a Defender exclusion is dangerous, or None if it looks ordinary.
    kind is 'path', 'process' or 'extension'."""
    v = (value or "").strip().strip('"').lower()
    if not v:
        return None
    if kind == "extension":
        ext = "*" if v in ("*", ".*", "*.*") else v.lstrip("*.")
        return f"excludes every .{ext} file from scanning" if ext in _BROAD_EXTENSIONS else None
    p = v.replace("/", "\\")
    if kind == "process":
        base = p.rsplit("\\", 1)[-1]
        if base in _BROAD_PROCESSES:
            return f"excludes the scripting/system process {base} from scanning"
        if p in ("*", "*.exe"):
            return "excludes all processes from scanning"
        if any(frag in p for frag in _RISKY_FRAGMENTS) or p.startswith(("%temp%", "%tmp%", "%appdata%")):
            return "excludes a program running from a user-writable folder"
        return None
    # path
    stripped = p.rstrip("\\*")
    if _DRIVE_ROOT.match(p) or stripped in ("", "c:", "%systemdrive%"):
        return "excludes an entire drive from scanning"
    if stripped in _WHOLE_SYSTEM_DIRS:
        return "excludes a whole system or user-profile folder from scanning"
    if stripped.startswith(("%temp%", "%tmp%", "%appdata%", "%public%", "%userprofile%\\downloads",
                            "%localappdata%\\temp")):
        return _RISKY_REASON
    if stripped.endswith(_RISKY_EXACT_ENDS) or any(frag in stripped + "\\" for frag in _RISKY_FRAGMENTS):
        return _RISKY_REASON
    if p.endswith(("\\*.exe", "\\*.dll", "\\*.ps1")) or p in ("*.exe", "*.dll", "*.ps1"):
        return "excludes all programs/scripts in a folder"
    return None


def collect_exclusions(pref: Optional[Dict[str, Any]]) -> Tuple[Dict[str, List[str]], bool]:
    """Merge Get-MpPreference exclusions with registry fallbacks.
    Returns ({kind: [values]}, hidden) - hidden=True when non-admin PowerShell redacted them
    and the registry fallback could not recover them."""
    kinds = {"path": "ExclusionPath", "process": "ExclusionProcess", "extension": "ExclusionExtension"}
    reg_names = {"path": "Paths", "process": "Processes", "extension": "Extensions"}
    out: Dict[str, List[str]] = {k: [] for k in kinds}
    redacted = False
    for kind, prop in kinds.items():
        for v in as_list((pref or {}).get(prop)):
            if isinstance(v, str) and v.upper().startswith("N/A"):
                redacted = True
            elif v:
                out[kind].append(str(v))
        for base in (r"SOFTWARE\Microsoft\Windows Defender\Exclusions", r"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions"):
            try:
                for name in reg_values("HKLM", f"{base}\\{reg_names[kind]}"):
                    if name and name not in out[kind]:
                        out[kind].append(name)
            except Exception:
                pass
    recovered = any(out[k] for k in out)
    return out, redacted and not recovered


def check_defender_prefs(env: AuditEnv) -> List[Check]:
    out: List[Check] = []
    pref = env.facts.get("pref") if isinstance(env.facts.get("pref"), dict) else None
    t_ex = "No dangerous Defender exclusions"
    excl, hidden = collect_exclusions(pref)
    if pref is None and not any(excl.values()):
        out.append(skipped("DEFENDER-EXCLUSIONS", t_ex, "Defender preferences unavailable."))
    elif hidden:
        out.append(skipped("DEFENDER-EXCLUSIONS", t_ex,
                           "Windows hides Defender exclusions from non-administrators - re-run Aegis as Administrator."))
    else:
        bad: List[Dict[str, str]] = []
        for kind, vals in excl.items():
            for v in vals:
                why = classify_exclusion(kind, v)
                if why:
                    bad.append({"type": kind, "value": v, "reason": why})
        total = sum(len(v) for v in excl.values())
        if bad:
            out.append(failed(
                "DEFENDER-EXCLUSIONS", "Suspicious Microsoft Defender exclusions", Severity.HIGH,
                f"{len(bad)} of {total} Microsoft Defender exclusion(s) hide whole drives, user-writable folders, "
                "scripting programs or executable file types from scanning. Malware routinely adds such exclusions "
                "so it can run undetected.",
                "If you did not add these yourself, assume compromise: run a full scan, then remove each entry in "
                "Windows Security > Virus & threat protection > Manage settings > Exclusions (or PowerShell: "
                "Remove-MpPreference -ExclusionPath '<path>'). Keep only exclusions you recognise and need "
                "(for example a specific developer folder).",
                "Microsoft Defender exclusions", {"suspicious": bad, "total_exclusions": total}, None, ["T1562.001"]))
        else:
            out.append(passed("DEFENDER-EXCLUSIONS", t_ex, f"{total} exclusion(s) configured, none look dangerous."))

    st = build_av_state(env.facts)
    primary = bool(st and st.defender_primary)
    t_pua, t_cfa, t_maps = ("PUA (adware) protection is on", "Controlled folder access (ransomware protection) is on",
                            "Cloud-delivered protection is on")
    if not pref or not primary:
        why = "Microsoft Defender is not the active antivirus." if pref else "Defender preferences unavailable."
        return out + [skipped("DEFENDER-PUA", t_pua, why), skipped("DEFENDER-CFA", t_cfa, why),
                      skipped("DEFENDER-CLOUD", t_maps, why)]
    pua = to_int(pref.get("PUAProtection"))
    if pua == 0:
        out.append(failed(
            "DEFENDER-PUA", "Defender blocking of unwanted apps (PUA) is off", Severity.LOW,
            "Potentially unwanted applications (adware, bundled toolbars, fake optimisers) are not blocked.",
            "Windows Security > App & browser control > Reputation-based protection > Potentially unwanted app "
            "blocking > turn on.", "Microsoft Defender PUA protection", {"PUAProtection": pua},
            run_ps("Set-MpPreference -PUAProtection Enabled", "Turn on Defender PUA protection")))
    else:
        out.append(passed("DEFENDER-PUA", t_pua))
    cfa = to_int(pref.get("EnableControlledFolderAccess"))
    if cfa is not None and cfa not in (1, 3):
        out.append(failed(
            "DEFENDER-CFA", "Controlled folder access (ransomware protection) is off", Severity.LOW,
            "Controlled folder access stops untrusted programs from changing files in Documents, Pictures, Desktop "
            "and other protected folders - the main defence against ransomware encrypting your files.",
            "Windows Security > Virus & threat protection > Ransomware protection > turn on Controlled folder access "
            "(try 'audit mode' first if you worry about blocked apps).", "Microsoft Defender controlled folder access",
            {"EnableControlledFolderAccess": cfa}, None, ["T1486"], Category.RANSOMWARE))
    else:
        out.append(passed("DEFENDER-CFA", t_cfa))
    maps = to_int(pref.get("MAPSReporting"))
    if maps == 0:
        out.append(failed(
            "DEFENDER-CLOUD", "Defender cloud-delivered protection is off", Severity.LOW,
            "Cloud protection gives Defender near-instant verdicts on brand-new malware.",
            "Windows Security > Virus & threat protection > Manage settings > Cloud-delivered protection > On.",
            "Microsoft Defender cloud protection", {"MAPSReporting": maps},
            run_ps("Set-MpPreference -MAPSReporting Advanced", "Turn on Defender cloud-delivered protection")))
    else:
        out.append(passed("DEFENDER-CLOUD", t_maps))
    return out


# =========================================================================== firewall
_FW_PROFILES = (("Domain", "DomainProfile"), ("Private", "StandardProfile"), ("Public", "PublicProfile"))
_FW_LOCAL = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
_FW_POLICY = r"SOFTWARE\Policies\Microsoft\WindowsFirewall"


def check_firewall(env: AuditEnv) -> List[Check]:
    title = "Windows Firewall is on for all network profiles"
    off: List[Dict[str, Any]] = []
    policy_forced = False
    for label, sub in _FW_PROFILES:
        pol = rd_int("HKLM", f"{_FW_POLICY}\\{sub}", "EnableFirewall")
        loc = rd_int("HKLM", f"{_FW_LOCAL}\\{sub}", "EnableFirewall")
        eff = pol if pol is not None else loc
        if eff is None:
            eff = 1  # default is on
        if eff == 0:
            off.append({"profile": label, "source": "group policy" if pol is not None else "local setting"})
            policy_forced = policy_forced or pol is not None
    if not off:
        return [passed("FIREWALL", title)]
    # a third-party firewall legitimately replaces Windows Firewall
    third = []
    for p in as_list(env.facts.get("fw")):
        if isinstance(p, dict) and "windows" not in str(p.get("name", "")).lower():
            enabled, _ = decode_product_state(p.get("state"))
            if enabled:
                third.append(str(p.get("name")))
    if third:
        return [passed("FIREWALL", title, f"Windows Firewall is off but {', '.join(third)} is the active firewall.")]
    names = ", ".join(o["profile"] for o in off)
    fix = None if policy_forced else run_cmd(["netsh", "advfirewall", "set", "allprofiles", "state", "on"],
                                             "Turn Windows Defender Firewall on for all profiles")
    return [failed(
        "FIREWALL", "Windows Firewall is turned off", Severity.HIGH,
        f"Windows Firewall is off for the {names} network profile(s). Anything on the network (or internet, on "
        "public Wi-Fi) can connect to services on this PC.",
        "Open Windows Security > Firewall & network protection and turn the firewall on for every profile "
        "(or run: netsh advfirewall set allprofiles state on). If you use a third-party firewall, make sure it is running.",
        "Windows Defender Firewall", {"profiles_off": off}, fix, ["T1562.004"])]


# =========================================================================== UAC
_UAC_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"


def check_uac(env: AuditEnv) -> List[Check]:
    out: List[Check] = []
    loc = hkey("HKLM", _UAC_KEY)
    lua = rd_int("HKLM", _UAC_KEY, "EnableLUA")
    if lua == 0:
        out.append(failed(
            "UAC-DISABLED", "User Account Control (UAC) is turned off", Severity.HIGH,
            "With UAC disabled every program you start runs with full administrator rights, so malware gets "
            "complete control with no prompt.", "Re-enable UAC (Control Panel > User Accounts > Change User Account "
            "Control settings) and restart the PC.", loc + "\\EnableLUA", {"EnableLUA": 0},
            set_reg(_UAC_KEY, "EnableLUA", 1, "Turn User Account Control on (restart required)"), ["T1548.002"]))
    else:
        out.append(passed("UAC-DISABLED", "User Account Control (UAC) is on"))
    consent = rd_int("HKLM", _UAC_KEY, "ConsentPromptBehaviorAdmin")
    if consent == 0:
        out.append(failed(
            "UAC-NOPROMPT", "UAC elevates administrators silently", Severity.MEDIUM,
            "Administrators are elevated without any prompt (ConsentPromptBehaviorAdmin=0), which defeats UAC.",
            "Set the UAC slider to 'Notify me only when apps try to make changes' or higher.",
            loc + "\\ConsentPromptBehaviorAdmin", {"ConsentPromptBehaviorAdmin": 0},
            set_reg(_UAC_KEY, "ConsentPromptBehaviorAdmin", 5, "Restore the default UAC prompt for administrators"),
            ["T1548.002"]))
    else:
        out.append(passed("UAC-NOPROMPT", "UAC prompts administrators before elevating"))
    secure = rd_int("HKLM", _UAC_KEY, "PromptOnSecureDesktop")
    if secure == 0:
        out.append(failed(
            "UAC-NOSECUREDESKTOP", "UAC prompt does not use the secure desktop", Severity.LOW,
            "UAC prompts are shown on your normal desktop where other programs can click 'Yes' for you.",
            "Set the UAC slider to the default level (the screen dims during the prompt).",
            loc + "\\PromptOnSecureDesktop", {"PromptOnSecureDesktop": 0},
            set_reg(_UAC_KEY, "PromptOnSecureDesktop", 1, "Show UAC prompts on the secure desktop"), ["T1548.002"]))
    else:
        out.append(passed("UAC-NOSECUREDESKTOP", "UAC prompts use the secure desktop"))
    return out


# =========================================================================== SMB / RDP
def check_smb(env: AuditEnv) -> List[Check]:
    out: List[Check] = []
    srv_key = r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    reg_srv = rd_int("HKLM", srv_key, "SMB1")
    live = env.facts.get("smb1_server")
    t = "SMBv1 server is disabled"
    enabled: Optional[bool]
    if reg_srv == 1:
        enabled = True
    elif reg_srv == 0:
        enabled = False
    elif isinstance(live, bool):
        enabled = live
    else:
        enabled = None
    if enabled is True:
        out.append(failed(
            "SMB1-SERVER", "SMBv1 file-sharing server is enabled", Severity.HIGH,
            "SMBv1 is an obsolete protocol exploited by WannaCry/NotPetya (EternalBlue). It should be off on every PC.",
            "Turn off 'SMB 1.0/CIFS File Sharing Support' in Windows Features, or run in an admin PowerShell: "
            "Set-SmbServerConfiguration -EnableSMB1Protocol $false", hkey("HKLM", srv_key, "SMB1"),
            {"SMB1": reg_srv, "Get-SmbServerConfiguration": live},
            set_reg(srv_key, "SMB1", 0, "Disable the SMBv1 server (takes effect after restart)"), ["T1210"]))
    elif enabled is False:
        out.append(passed("SMB1-SERVER", t))
    else:
        out.append(skipped("SMB1-SERVER", t, "Not explicitly configured; run Aegis as Administrator for a definitive answer "
                           "(SMBv1 is off by default on Windows 10 1709+ fresh installs)."))
    cl_key = r"SYSTEM\CurrentControlSet\Services\mrxsmb10"
    start = rd_int("HKLM", cl_key, "Start")
    if start is not None and start != 4:
        out.append(failed(
            "SMB1-CLIENT", "SMBv1 client is enabled", Severity.HIGH,
            "The SMBv1 client driver (mrxsmb10) is active, allowing this PC to talk to servers using the broken SMBv1 protocol.",
            "Turn off 'SMB 1.0/CIFS Client' in Windows Features (Control Panel > Programs > Turn Windows features on or off).",
            hkey("HKLM", cl_key, "Start"), {"mrxsmb10_Start": start},
            set_reg(cl_key, "Start", 4, "Disable the SMBv1 client driver (restart required)"), ["T1210"]))
    else:
        out.append(passed("SMB1-CLIENT", "SMBv1 client is disabled"))
    return out


_TS = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
_TS_POL = r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"


def check_rdp(env: AuditEnv) -> List[Check]:
    deny = rd_int("HKLM", _TS_POL, "fDenyTSConnections")
    deny_src = "policy"
    if deny is None:
        deny = rd_int("HKLM", _TS, "fDenyTSConnections")
        deny_src = "local"
    if deny is None or deny != 0:
        return [passed("RDP-ENABLED", "Remote Desktop is disabled"), passed("RDP-NLA", "RDP requires Network Level Authentication",
                                                                          "Remote Desktop is off.")]
    out = [failed(
        "RDP-ENABLED", "Remote Desktop (RDP) is enabled", Severity.MEDIUM,
        "Remote Desktop accepts logins over the network. Exposed RDP is the #1 entry point for ransomware gangs "
        "(brute-forced or leaked passwords).",
        "If you do not use Remote Desktop, turn it off: Settings > System > Remote Desktop > Off. If you need it, "
        "never expose port 3389 to the internet - use a VPN, keep NLA on and use strong unique passwords/MFA.",
        hkey("HKLM", _TS, "fDenyTSConnections"), {"fDenyTSConnections": 0, "source": deny_src}, None, ["T1021.001"])]
    nla_key = _TS + r"\WinStations\RDP-Tcp"
    nla_pol = rd_int("HKLM", _TS_POL, "UserAuthentication")
    nla = nla_pol if nla_pol is not None else rd_int("HKLM", nla_key, "UserAuthentication")
    if nla == 0:
        out.append(failed(
            "RDP-NLA", "Remote Desktop does not require Network Level Authentication", Severity.HIGH,
            "Without NLA anyone who can reach the PC gets a Windows login screen (and pre-authentication attack "
            "surface such as BlueKeep) before proving who they are.",
            "Settings > System > Remote Desktop > Advanced settings > require Network Level Authentication.",
            hkey("HKLM", nla_key, "UserAuthentication"), {"UserAuthentication": 0},
            None if nla_pol is not None else set_reg(nla_key, "UserAuthentication", 1,
                                                    "Require Network Level Authentication for RDP"), ["T1021.001"]))
    else:
        out.append(passed("RDP-NLA", "RDP requires Network Level Authentication"))
    return out


# =========================================================================== disk / boot security
def check_bitlocker(env: AuditEnv) -> List[Check]:
    title = "System drive is encrypted (BitLocker / Device Encryption)"
    bl = env.facts.get("bitlocker")
    if not isinstance(bl, dict):
        return [skipped("BITLOCKER-OFF", title, "Needs Administrator rights (or BitLocker is not supported on this edition).")]
    status = to_int(bl.get("status"))
    if status == 1:
        return [passed("BITLOCKER-OFF", title, f"Drive {bl.get('drive', '')} is protected.")]
    if status == 0:
        return [failed(
            "BITLOCKER-OFF", "System drive is not encrypted", Severity.MEDIUM,
            "If the PC is lost or stolen, anyone can read the files on the drive (including saved passwords "
            "and browser sessions) by removing the disk.",
            "Settings > Privacy & security > Device encryption (or Control Panel > BitLocker Drive Encryption) > Turn on. "
            "Save the recovery key to your Microsoft account or print it first.",
            f"Drive {bl.get('drive', 'C:')}", {"ProtectionStatus": status}, None, ["T1005"])]
    return [skipped("BITLOCKER-OFF", title, "Protection status could not be determined.")]


def check_secure_boot(env: AuditEnv) -> List[Check]:
    out: List[Check] = []
    sb = rd_int("HKLM", r"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled")
    t = "Secure Boot is enabled"
    if sb == 1:
        out.append(passed("SECURE-BOOT", t))
    elif sb == 0:
        out.append(failed(
            "SECURE-BOOT", "Secure Boot is disabled", Severity.LOW,
            "Secure Boot stops bootkits and unsigned boot loaders from starting before Windows.",
            "Enter the UEFI/BIOS setup and enable Secure Boot (the disk must use GPT/UEFI boot; Windows 11 requires it).",
            "UEFI Secure Boot", {"UEFISecureBootEnabled": 0}, None, ["T1542.003"]))
    else:
        out.append(failed(
            "SECURE-BOOT", "Secure Boot is not available (legacy BIOS boot)", Severity.INFO,
            "This PC boots in legacy BIOS/CSM mode or the firmware does not expose Secure Boot.",
            "If your hardware supports UEFI, convert to GPT (MBR2GPT) and enable Secure Boot.",
            "UEFI Secure Boot", {}, None))
    tpm = env.facts.get("tpm")
    if isinstance(tpm, dict):
        out.append(passed("TPM", "TPM is present and enabled", f"TPM spec {tpm.get('spec', '?')}")
                   if tpm.get("enabled") else
                   failed("TPM", "TPM is present but disabled", Severity.INFO,
                          "A TPM protects encryption keys and enables Windows 11 security features.",
                          "Enable the TPM (fTPM / PTT) in your UEFI/BIOS settings.", "TPM", dict(tpm), None))
    else:
        out.append(skipped("TPM", "TPM is present and enabled",
                           "Needs Administrator rights, or no TPM is available."))
    dg = env.facts.get("dg")
    if not isinstance(dg, dict):
        out += [skipped("VBS", "Virtualization-based security is running", "Device Guard status unavailable."),
                skipped("HVCI", "Memory integrity (HVCI) is on", "Device Guard status unavailable."),
                skipped("CREDGUARD", "Credential Guard is running", "Device Guard status unavailable.")]
        return out
    running = {to_int(x) for x in as_list(dg.get("running"))}
    vbs = to_int(dg.get("vbs"))
    out.append(passed("VBS", "Virtualization-based security is running") if vbs == 2 else failed(
        "VBS", "Virtualization-based security is not running", Severity.INFO,
        "VBS isolates sensitive parts of Windows from the rest of the system.",
        "Windows Security > Device security > Core isolation > turn on Memory integrity.",
        "Virtualization-based security", {"VirtualizationBasedSecurityStatus": vbs}, None))
    out.append(passed("HVCI", "Memory integrity (HVCI) is on") if 2 in running else failed(
        "HVCI", "Memory integrity (core isolation) is off", Severity.INFO,
        "Memory integrity blocks vulnerable or malicious kernel drivers.",
        "Windows Security > Device security > Core isolation details > Memory integrity > On "
        "(incompatible drivers will be listed).", "Memory integrity (HVCI)", {"running": sorted(x for x in running if x is not None)}, None))
    out.append(passed("CREDGUARD", "Credential Guard is running") if 1 in running else failed(
        "CREDGUARD", "Credential Guard is not running", Severity.INFO,
        "Credential Guard protects domain credentials from credential-dumping tools such as Mimikatz "
        "(mainly relevant for work/domain PCs).", "Enable Credential Guard via Group Policy or Windows Security on Enterprise/Education editions.",
        "Credential Guard", {"running": sorted(x for x in running if x is not None)}, None, ["T1003"]))
    return out


# =========================================================================== Windows Update
_WU_AU = r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
_CBS = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing"
_WU_POLICY_AU = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"


def check_windows_update(env: AuditEnv) -> List[Check]:
    out: List[Check] = []
    start = rd_int("HKLM", r"SYSTEM\CurrentControlSet\Services\wuauserv", "Start")
    if start == 4:
        out.append(failed(
            "WU-SERVICE-DISABLED", "The Windows Update service is disabled", Severity.HIGH,
            "The Windows Update service (wuauserv) is set to Disabled, so security patches cannot be installed. "
            "Malware and 'update blocker' tools do this on purpose.",
            "Set the service to Manual: services.msc > Windows Update > Startup type > Manual, then run Windows Update.",
            hkey("HKLM", r"SYSTEM\CurrentControlSet\Services\wuauserv", "Start"), {"Start": 4},
            run_cmd(["sc.exe", "config", "wuauserv", "start=", "demand"], "Set the Windows Update service back to Manual"),
            ["T1562.001"]))
    else:
        out.append(passed("WU-SERVICE-DISABLED", "The Windows Update service is not disabled"))

    noauto = rd_int("HKLM", _WU_POLICY_AU, "NoAutoUpdate")
    if noauto == 1:
        out.append(failed(
            "WU-AUTO-OFF", "Automatic Windows updates are disabled by policy", Severity.MEDIUM,
            "A policy (NoAutoUpdate=1) stops Windows from installing updates automatically.",
            "Ask your IT administrator, or remove the policy: delete HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU\\NoAutoUpdate.",
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoUpdate", {"NoAutoUpdate": 1}, None))
    else:
        out.append(passed("WU-AUTO-OFF", "Automatic Windows updates are not disabled by policy"))

    last = parse_iso_date(env.facts.get("wu_last"))
    t = "Windows updates were installed recently"
    if last is None:
        out.append(skipped("WU-STALE", t, "Could not read the update history."))
    else:
        age = (env.today - last).days
        ev = {"last_update": last.isoformat(), "days_ago": age, "update": env.facts.get("wu_title")}
        if age > WU_STALE_HIGH_DAYS or age > WU_STALE_MEDIUM_DAYS:
            sev = Severity.HIGH if age > WU_STALE_HIGH_DAYS else Severity.MEDIUM
            out.append(failed(
                "WU-STALE", f"No Windows update installed for {age} days", sev,
                f"The last successful Windows update was installed on {last.isoformat()} ({age} days ago). "
                "Missing monthly security updates leaves known vulnerabilities open.",
                "Open Settings > Windows Update > Check for updates, install everything and restart. If updates fail, "
                "run the Windows Update troubleshooter (Settings > System > Troubleshoot).",
                "Windows Update history", ev, None, ["T1190"]))
        else:
            out.append(passed("WU-STALE", t, f"Last update {age} day(s) ago."))

    reboot: List[str] = []
    try:
        if "RebootRequired" in reg_subkeys("HKLM", _WU_AU):
            reboot.append("Windows Update: RebootRequired")
        if "RebootPending" in reg_subkeys("HKLM", _CBS):
            reboot.append("Component Based Servicing: RebootPending")
    except Exception:
        pass
    if reboot:
        out.append(failed(
            "WU-REBOOT-PENDING", "A restart is pending to finish updates", Severity.LOW,
            "Installed updates only protect you after the PC restarts.",
            "Save your work and restart the PC (Start > Power > Update and restart).",
            "Windows pending reboot", {"markers": reboot}, None))
    else:
        out.append(passed("WU-REBOOT-PENDING", "No restart is pending"))
    return out


# =========================================================================== credential hygiene
_LSA = r"SYSTEM\CurrentControlSet\Control\Lsa"
_WINLOGON = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
_BUILTIN_SKIP = {"defaultaccount", "wdagutilityaccount", "guest"}


def check_credentials(env: AuditEnv) -> List[Check]:
    out: List[Check] = []
    wd_key = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
    if rd_int("HKLM", wd_key, "UseLogonCredential") == 1:
        out.append(failed(
            "WDIGEST", "WDigest stores your password in memory in clear text", Severity.HIGH,
            "UseLogonCredential=1 makes Windows keep plaintext passwords in LSASS memory where Mimikatz and other "
            "credential stealers can read them. Attackers set this flag after breaking in.",
            "Set it back to 0 (or delete the value). If you did not set it yourself, treat the PC as compromised and "
            "change your passwords from a clean device.", hkey("HKLM", wd_key, "UseLogonCredential"),
            {"UseLogonCredential": 1}, set_reg(wd_key, "UseLogonCredential", 0, "Stop WDigest caching plaintext passwords"),
            ["T1003.001", "T1112"]))
    else:
        out.append(passed("WDIGEST", "WDigest plaintext credential caching is off"))

    ppl = rd_int("HKLM", _LSA, "RunAsPPL")
    if ppl in (1, 2):
        out.append(passed("LSA-PPL", "LSA protection (RunAsPPL) is on"))
    else:
        out.append(failed(
            "LSA-PPL", "LSA protection is not enabled", Severity.LOW,
            "Running the Local Security Authority as a protected process blocks credential-dumping tools from reading logon secrets.",
            "Windows Security > Device security > Core isolation > Local Security Authority protection > On, then restart. "
            "(Some older security drivers are incompatible - check Event Viewer after enabling.)",
            hkey("HKLM", _LSA, "RunAsPPL"), {"RunAsPPL": ppl}, None, ["T1003.001"]))

    if rd_int("HKLM", _LSA, "NoLMHash") == 0:
        out.append(failed(
            "NOLMHASH", "Windows stores weak LM password hashes", Severity.MEDIUM,
            "NoLMHash=0 makes Windows save an easily-cracked LM hash of every password you set.",
            "Enable the policy 'Network security: Do not store LAN Manager hash value on next password change' and "
            "change your passwords.", hkey("HKLM", _LSA, "NoLMHash"), {"NoLMHash": 0},
            set_reg(_LSA, "NoLMHash", 1, "Stop storing LM hashes (applies on next password change)"), ["T1003.002"]))
    else:
        out.append(passed("NOLMHASH", "LM password hashes are not stored"))

    lm = rd_int("HKLM", _LSA, "LmCompatibilityLevel")
    if lm is not None and lm < 3:
        out.append(failed(
            "LMCOMPAT", "Legacy LM/NTLMv1 authentication is allowed", Severity.MEDIUM,
            f"LmCompatibilityLevel is {lm}: this PC may send weak LM/NTLMv1 responses that can be cracked or relayed in seconds.",
            "Set 'Network security: LAN Manager authentication level' to 'Send NTLMv2 response only' (3) or higher.",
            hkey("HKLM", _LSA, "LmCompatibilityLevel"), {"LmCompatibilityLevel": lm},
            set_reg(_LSA, "LmCompatibilityLevel", 3, "Require NTLMv2 for outgoing authentication"), ["T1557.001"]))
    else:
        out.append(passed("LMCOMPAT", "NTLMv2 is used for authentication"))

    users = [u for u in as_list(env.facts.get("users")) if isinstance(u, dict)]
    t_guest = "Guest account is disabled"
    if not users:
        out.append(skipped("GUEST", t_guest, "Local user list unavailable."))
        out.append(skipped("ACCOUNT-NOPASSWORD", "All accounts require a password", "Local user list unavailable."))
        out.append(skipped("ACCOUNT-NOEXPIRE", "Account passwords expire", "Local user list unavailable."))
    else:
        guests = [u for u in users if str(u.get("sid", "")).endswith("-501") and u.get("enabled")]
        if guests:
            out.append(failed(
                "GUEST", "The built-in Guest account is enabled", Severity.MEDIUM,
                "The Guest account allows anonymous local logins and is a common foothold for attackers.",
                "Disable it: Computer Management > Local Users and Groups > Users > Guest > Account is disabled.",
                "Local account: Guest", {"account": guests[0].get("name")},
                run_ps("Get-LocalUser | Where-Object { $_.SID.Value -like 'S-1-5-21-*-501' } | Disable-LocalUser",
                       "Disable the built-in Guest account"), ["T1078.001"]))
        else:
            out.append(passed("GUEST", t_guest))
        nopw = sorted(str(u.get("name")) for u in users if u.get("enabled") and u.get("pwreq") is False
                      and str(u.get("name", "")).lower() not in _BUILTIN_SKIP)
        if nopw:
            out.append(failed(
                "ACCOUNT-NOPASSWORD", "Accounts that do not require a password", Severity.LOW,
                f"{len(nopw)} enabled local account(s) are not required to have a password: {', '.join(nopw)}.",
                "Give each account a password (or PIN/Windows Hello): Settings > Accounts > Sign-in options.",
                "Local accounts: " + ", ".join(nopw), {"accounts": nopw}, None, ["T1078.003"]))
        else:
            out.append(passed("ACCOUNT-NOPASSWORD", "All accounts require a password"))
        noexp = sorted(str(u.get("name")) for u in users if u.get("enabled") and u.get("never_expires")
                       and str(u.get("name", "")).lower() not in _BUILTIN_SKIP)
        if noexp:
            out.append(failed(
                "ACCOUNT-NOEXPIRE", "Account passwords never expire", Severity.LOW,
                f"Password never expires for: {', '.join(noexp)}. (Fine for a unique, strong password; risky if it "
                "was ever reused or leaked.)",
                "Use a long unique password or passphrase (check it with `aegis check-password`) and enable MFA/Windows "
                "Hello. For shared or business PCs, enforce a password-expiry policy.",
                "Local accounts: " + ", ".join(noexp), {"accounts": noexp}, None))
        else:
            out.append(passed("ACCOUNT-NOEXPIRE", "Account passwords expire"))

    user = str(env.facts.get("user") or "")
    if env.facts.get("in_admins") is True and "system" not in user.lower():
        out.append(failed(
            "ADMIN-USER", "You are signed in with an administrator account", Severity.LOW,
            f"{user or 'The current user'} is a member of the local Administrators group. Day-to-day use as an "
            "administrator means malware you run can change system settings after a single UAC click.",
            "Create a Standard user account for daily use and keep the administrator account for installs "
            "(Settings > Accounts > Other users).", f"User: {user}", {"user": user}, None, ["T1078.003"]))
    elif "in_admins" in env.facts:
        out.append(passed("ADMIN-USER", "Daily-use account is a standard user"))
    else:
        out.append(skipped("ADMIN-USER", "Daily-use account is a standard user", "Group membership unavailable."))

    # auto-logon
    pw = rd("HKLM", _WINLOGON, "DefaultPassword")
    auto = str(rd("HKLM", _WINLOGON, "AutoAdminLogon") or "0")
    if pw not in (None, ""):
        out.append(failed(
            "AUTOLOGON-PASSWORD", "A Windows login password is stored in plain text (auto-logon)", Severity.HIGH,
            "The Winlogon registry key contains DefaultPassword in clear text; any local user or malware can read it.",
            "Turn off automatic sign-in (run netplwiz > tick 'Users must enter a user name and password') and change "
            "that account's password because it has been exposed. Aegis does not show the password.",
            hkey("HKLM", _WINLOGON, "DefaultPassword"),
            {"DefaultUserName": str(rd("HKLM", _WINLOGON, "DefaultUserName") or ""), "password": "****(hidden)"},
            None, ["T1552.002"]))
    elif auto == "1":
        out.append(failed(
            "AUTOLOGON", "Windows signs in automatically without a password", Severity.LOW,
            "Auto-logon is enabled, so anyone with physical access to the PC gets into your account.",
            "Turn it off with netplwiz (tick 'Users must enter a user name and password to use this computer').",
            hkey("HKLM", _WINLOGON, "AutoAdminLogon"), {"AutoAdminLogon": 1},
            set_reg(_WINLOGON, "AutoAdminLogon", "0", "Turn off automatic sign-in"), ["T1078"]))
    else:
        out.append(passed("AUTOLOGON-PASSWORD", "No auto-logon password is stored"))
    return out


# =========================================================================== misc hygiene
_EXPLORER_POL = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"


def check_hygiene(env: AuditEnv) -> List[Check]:
    out: List[Check] = []
    # AutoRun / AutoPlay
    nd = rd_int("HKLM", _EXPLORER_POL, "NoDriveTypeAutoRun")
    nd_u = rd_int("HKCU", _EXPLORER_POL, "NoDriveTypeAutoRun")
    if nd == 255 or nd_u == 255:
        out.append(passed("AUTORUN", "AutoRun is disabled for all drive types"))
    else:
        out.append(failed(
            "AUTORUN", "AutoRun is not fully disabled", Severity.LOW,
            "NoDriveTypeAutoRun is not 255, so USB sticks and discs may launch programs automatically (a classic worm "
            "and malware-USB spreading route).",
            "Settings > Bluetooth & devices > AutoPlay > turn 'Use AutoPlay for all media and devices' Off.",
            hkey("HKLM", _EXPLORER_POL, "NoDriveTypeAutoRun"), {"NoDriveTypeAutoRun": nd},
            set_reg(_EXPLORER_POL, "NoDriveTypeAutoRun", 255, "Disable AutoRun on all drive types"), ["T1091"]))

    wsh_key = r"SOFTWARE\Microsoft\Windows Script Host\Settings"
    if rd_int("HKLM", wsh_key, "Enabled") == 0 or rd_int("HKCU", wsh_key, "Enabled") == 0:
        out.append(passed("WSH", "Windows Script Host is disabled"))
    else:
        out.append(failed(
            "WSH", "Windows Script Host (.vbs/.js) is enabled", Severity.INFO,
            "Malware e-mail attachments commonly use .vbs/.js/.wsf scripts that run through Windows Script Host. "
            "Most users never need it.",
            "Optional hardening: set HKLM\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings\\Enabled=0 "
            "(this can break old login scripts and some installers).", hkey("HKLM", wsh_key, "Enabled"), {}, None,
            ["T1059.005"]))

    # PowerShell v2
    ps2 = env.facts.get("ps2")
    ps2_reg = rd("HKLM", r"SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine", "PowerShellVersion")
    ps2_on: Optional[bool] = None
    if isinstance(ps2, str) and ps2:
        ps2_on = ps2.lower() == "enabled"
    elif isinstance(ps2_reg, str) and ps2_reg.startswith("2") and env.is_admin is False:
        ps2_on = None  # registry key exists even when the feature is removed on some builds
    if ps2_on is True:
        out.append(failed(
            "PS2-ENGINE", "The legacy PowerShell 2.0 engine is installed", Severity.LOW,
            "PowerShell 2.0 has no AMSI or script-block logging; attackers downgrade to it (powershell -version 2) to "
            "evade detection.", "Turn off the feature 'Windows PowerShell 2.0' in Windows Features, or run in an admin "
            "PowerShell: Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root",
            "Windows feature: PowerShell 2.0", {"state": ps2},
            run_ps("Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart",
                   "Remove the legacy PowerShell 2.0 engine"), ["T1059.001", "T1562.001"]))
    elif ps2_on is False:
        out.append(passed("PS2-ENGINE", "The legacy PowerShell 2.0 engine is not installed"))
    else:
        out.append(skipped("PS2-ENGINE", "The legacy PowerShell 2.0 engine is not installed",
                           "Needs Administrator rights to read optional-feature state."))

    sbl_key = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    if rd_int("HKLM", sbl_key, "EnableScriptBlockLogging") == 1 or rd_int("HKCU", sbl_key, "EnableScriptBlockLogging") == 1:
        out.append(passed("PS-SCRIPTBLOCK-LOG", "PowerShell script block logging is on"))
    else:
        out.append(failed(
            "PS-SCRIPTBLOCK-LOG", "PowerShell script block logging is off", Severity.LOW,
            "Without script block logging, malicious PowerShell leaves no record of what it ran (Event ID 4104).",
            "Enable it via Group Policy: Administrative Templates > Windows PowerShell > Turn on PowerShell Script Block Logging.",
            hkey("HKLM", sbl_key, "EnableScriptBlockLogging"), {},
            set_reg(sbl_key, "EnableScriptBlockLogging", 1, "Turn on PowerShell script block logging"), ["T1059.001"]))

    llmnr_key = r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    if rd_int("HKLM", llmnr_key, "EnableMulticast") == 0:
        out.append(passed("LLMNR", "LLMNR name resolution is disabled"))
    else:
        out.append(failed(
            "LLMNR", "LLMNR is enabled", Severity.LOW,
            "Link-Local Multicast Name Resolution lets any device on the network answer name lookups - attackers "
            "use Responder-style spoofing to capture password hashes.",
            "Disable it: Group Policy > Computer Configuration > Administrative Templates > Network > DNS Client > "
            "Turn off multicast name resolution = Enabled.", hkey("HKLM", llmnr_key, "EnableMulticast"), {},
            set_reg(llmnr_key, "EnableMulticast", 0, "Turn off LLMNR"), ["T1557.001"]))

    rr = env.facts.get("remote_registry")
    t_rr = "Remote Registry service is not running"
    if rr is None:
        out.append(skipped("REMOTE-REGISTRY", t_rr, "Service state unavailable."))
    elif str(rr).lower() == "running":
        out.append(failed(
            "REMOTE-REGISTRY", "The Remote Registry service is running", Severity.LOW,
            "Remote Registry lets other computers read and change this PC's registry over the network.",
            "Stop and disable it: services.msc > Remote Registry > Startup type: Disabled.",
            "Service: RemoteRegistry", {"status": rr},
            Remediation("disable_service", {"name": "RemoteRegistry"}, "Stop and disable the Remote Registry service"),
            ["T1021"]))
    else:
        out.append(passed("REMOTE-REGISTRY", t_rr))

    # SmartScreen
    ss_pol_key = r"SOFTWARE\Policies\Microsoft\Windows\System"
    ss_exp_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
    pol = rd_int("HKLM", ss_pol_key, "EnableSmartScreen")
    exp = str(rd("HKLM", ss_exp_key, "SmartScreenEnabled") or "")
    if pol == 0:
        out.append(failed(
            "SMARTSCREEN", "Windows SmartScreen is disabled by policy", Severity.MEDIUM,
            "SmartScreen warns before you run unrecognised downloads and visit known phishing/malware sites.",
            "Windows Security > App & browser control > Reputation-based protection > turn SmartScreen on.",
            hkey("HKLM", ss_pol_key, "EnableSmartScreen"), {"EnableSmartScreen": 0},
            set_reg(ss_pol_key, "EnableSmartScreen", 1, "Turn SmartScreen back on"), ["T1204.002"]))
    elif exp.lower() == "off":
        out.append(failed(
            "SMARTSCREEN", "Windows SmartScreen is turned off", Severity.MEDIUM,
            "SmartScreen warns before you run unrecognised downloads and visit known phishing/malware sites.",
            "Windows Security > App & browser control > Reputation-based protection > turn SmartScreen on.",
            hkey("HKLM", ss_exp_key, "SmartScreenEnabled"), {"SmartScreenEnabled": exp},
            set_reg(ss_exp_key, "SmartScreenEnabled", "Warn", "Turn SmartScreen on (warn mode)"), ["T1204.002"]))
    else:
        out.append(passed("SMARTSCREEN", "Windows SmartScreen is on"))

    adv = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    if rd_int("HKCU", adv, "HideFileExt") == 1:
        out.append(failed(
            "HIDE-FILE-EXT", "File extensions are hidden in File Explorer", Severity.LOW,
            "Hidden extensions let 'invoice.pdf.exe' look like a PDF - the most common trick for disguising malware.",
            "File Explorer > View > Show > File name extensions.", hkey("HKCU", adv, "HideFileExt"),
            {"HideFileExt": 1}, set_reg(adv, "HideFileExt", 0, "Show file extensions in Explorer", hive="HKCU"),
            ["T1036.007"]))
    else:
        out.append(passed("HIDE-FILE-EXT", "File extensions are visible in File Explorer"))
    return out


# =========================================================================== Office macros
_OFFICE_APPS = ("Word", "Excel", "PowerPoint")
_OFFICE_VERSIONS = ("16.0", "15.0")


def _office_present() -> bool:
    try:
        for hive in ("HKLM", "HKCU"):
            subs = {s.lower() for s in reg_subkeys(hive, r"SOFTWARE\Microsoft\Office" if hive == "HKLM"
                                                  else r"Software\Microsoft\Office")}
            if subs & {"16.0", "15.0", "14.0", "clicktorun"}:
                return True
    except Exception:
        pass
    return False


def check_office(env: AuditEnv) -> List[Check]:
    t1, t2 = "Office macros are not set to 'enable all'", "Office blocks macros in files from the internet"
    if not _office_present():
        return [skipped("OFFICE-MACROS", t1, "Microsoft Office does not appear to be installed."),
                skipped("OFFICE-INTERNET-MACROS", t2, "Microsoft Office does not appear to be installed.")]
    out: List[Check] = []
    bad_macro: List[Dict[str, Any]] = []
    bad_net: List[Dict[str, Any]] = []
    first_macro_fix: Optional[Remediation] = None
    for ver in _OFFICE_VERSIONS:
        for app in _OFFICE_APPS:
            for hive, base in (("HKCU", f"Software\\Policies\\Microsoft\\Office\\{ver}\\{app}\\Security"),
                               ("HKCU", f"Software\\Microsoft\\Office\\{ver}\\{app}\\Security"),
                               ("HKLM", f"SOFTWARE\\Policies\\Microsoft\\Office\\{ver}\\{app}\\Security")):
                vba = rd_int(hive, base, "VBAWarnings")
                if vba == 1:
                    bad_macro.append({"app": app, "version": ver, "key": hkey(hive, base, "VBAWarnings")})
                    if first_macro_fix is None and "Policies" not in base:
                        first_macro_fix = set_reg(base, "VBAWarnings", 2,
                                                  f"Make {app} warn before running macros", hive=hive)
                if rd_int(hive, base, "blockcontentexecutionfrominternet") == 0:
                    bad_net.append({"app": app, "version": ver, "key": hkey(hive, base, "blockcontentexecutionfrominternet")})
    if bad_macro:
        apps = ", ".join(sorted({b["app"] for b in bad_macro}))
        out.append(failed(
            "OFFICE-MACROS", "Office is set to run ALL macros without asking", Severity.HIGH,
            f"{apps} is configured to enable all macros (VBAWarnings=1). Malicious Word/Excel macros are among the "
            "most common ways ransomware and infostealers get in.",
            "In each Office app: File > Options > Trust Center > Trust Center Settings > Macro Settings > choose "
            "'Disable all macros with notification' (or stricter).", "Office macro security",
            {"settings": bad_macro}, first_macro_fix, ["T1566.001", "T1204.002"]))
    else:
        out.append(passed("OFFICE-MACROS", t1))
    if bad_net:
        out.append(failed(
            "OFFICE-INTERNET-MACROS", "Office allows macros in files downloaded from the internet", Severity.MEDIUM,
            "The 'Block macros from running in Office files from the Internet' protection is explicitly turned off.",
            "Remove the setting or set it to 1: File > Options > Trust Center > Macro Settings, or Group Policy "
            "'Block macros from running in Office files from the Internet' = Enabled.", "Office macro security",
            {"settings": bad_net}, None, ["T1566.001", "T1204.002"]))
    else:
        out.append(passed("OFFICE-INTERNET-MACROS", t2))
    return out


# =========================================================================== Linux checks
KNOWN_SUID = {
    "passwd", "su", "sudo", "sudoedit", "mount", "umount", "ping", "ping6", "chsh", "chfn", "gpasswd", "newgrp",
    "pkexec", "fusermount", "fusermount3", "ssh-keysign", "dbus-daemon-launch-helper", "polkit-agent-helper-1",
    "xorg.wrap", "crontab", "at", "unix_chkpwd", "mount.nfs", "mount.cifs", "ntfs-3g", "chage", "expiry", "newuidmap",
    "newgidmap", "snap-confine", "pam_extrausers_chkpwd", "traceroute6.iputils", "arping", "mtr-packet", "bwrap",
    "ksu", "doas", "userhelper", "mount.ecryptfs_private", "umount.ecryptfs_private", "staprun", "pppd", "chrome-sandbox",
    "vmware-user-suid-wrapper", "authbind-helper", "ubuntu-core-launcher", "wall", "write", "ssh-agent", "locate",
    "plocate", "unix2_chkpwd", "pt_chown", "utempter", "lockdev", "dotlockfile", "fping", "traceroute", "ping4",
    "sg", "Xorg", "X", "screen", "ssh-sk-helper", "cockpit-session", "nvidia-modprobe", "exim4", "procmail",
    "abrt-action-install-debuginfo-to-abrt-cache", "mandb", "kismet_capture", "pmmgr", "firejail",
}
SUID_ROOTS = ["/usr", "/bin", "/sbin", "/opt", "/home", "/root", "/tmp", "/var/tmp", "/dev/shm", "/srv"]
SUID_USER_WRITABLE = ("/tmp", "/var/tmp", "/dev/shm", "/home", "/root", "/srv")
SKIP_WALK = {"/proc", "/sys", "/dev", "/run", "/snap", "/var/lib/docker", "/var/lib/containerd"}


def _read_text(path: str, limit: int = 1_000_000) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(limit)
    except OSError:
        return None


def parse_sshd_config(text: str, include_reader: Optional[Callable[[str], List[str]]] = None,
                      _depth: int = 0) -> Dict[str, str]:
    """Effective sshd settings (first occurrence wins, 'Match' blocks ignored, Include expanded)."""
    cfg: Dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"\s+|\s*=\s*", line, maxsplit=1)
        if len(parts) < 2:
            continue
        key, val = parts[0].lower(), parts[1].strip().strip('"')
        if key == "match":
            break  # everything after is conditional
        if key == "include" and include_reader and _depth < 3:
            for sub in include_reader(val):
                for k, v in parse_sshd_config(sub, include_reader, _depth + 1).items():
                    cfg.setdefault(k, v)
            continue
        cfg.setdefault(key, val.lower() if key not in ("authorizedkeysfile",) else val)
    return cfg


def _sshd_include_reader(pattern: str) -> List[str]:
    if not os.path.isabs(pattern):
        pattern = os.path.join("/etc/ssh", pattern)
    out = []
    for p in sorted(glob.glob(pattern)):
        t = _read_text(p)
        if t is not None:
            out.append(t)
    return out


def _sshd_running() -> bool:
    for svc in ("ssh", "sshd"):
        rc, out, _ = run(["systemctl", "is-active", svc], timeout=10)
        if rc == 0 and out.strip() == "active":
            return True
    try:
        import psutil

        return any((p.info.get("name") or "") == "sshd" for p in psutil.process_iter(["name"]))
    except Exception:
        return False


def check_linux_firewall(env: AuditEnv) -> List[Check]:
    title = "A host firewall is active"
    active: List[str] = []
    queried = False
    if shutil.which("ufw"):
        rc, out, _ = run(["ufw", "status"], timeout=15)
        if rc == 0:
            queried = True
            if "status: active" in out.lower():
                active.append("ufw")
    for svc in ("ufw", "firewalld"):
        if svc in active:
            continue
        rc, out, _ = run(["systemctl", "is-active", svc], timeout=10)
        if rc == 0 and out.strip() == "active":
            active.append(svc)
    if not active and shutil.which("nft"):
        rc, out, _ = run(["nft", "list", "ruleset"], timeout=15)
        if rc == 0:
            queried = True
            if re.search(r"policy\s+drop|\bdrop\b|\breject\b", out):
                active.append("nftables")
    if not active and shutil.which("iptables"):
        rc, out, _ = run(["iptables", "-S"], timeout=15)
        if rc == 0:
            queried = True
            if re.search(r"-P\s+INPUT\s+(DROP|REJECT)", out) or re.search(r"^-A INPUT .*-j (DROP|REJECT)", out, re.M):
                active.append("iptables")
    if active:
        return [passed("LINUX-FIREWALL", title, "Active: " + ", ".join(active))]
    if queried or env.is_admin:
        return [failed(
            "LINUX-FIREWALL", "No host firewall is active", Severity.MEDIUM,
            "No active firewall rules (ufw, firewalld, nftables or iptables) were found, so every listening "
            "service is reachable from the network.",
            "Install and enable a firewall, for example: sudo apt install ufw && sudo ufw default deny incoming && "
            "sudo ufw allow ssh && sudo ufw enable", "Host firewall", {}, None, ["T1562.004"])]
    return [skipped("LINUX-FIREWALL", title, "Needs root to read firewall rules; re-run with sudo.")]


def check_linux_ssh(env: AuditEnv) -> List[Check]:
    path = "/etc/ssh/sshd_config"
    text = _read_text(path)
    t1, t2 = "SSH root login is not permitted", "SSH password authentication is disabled"
    if text is None:
        return [skipped("SSH-ROOT-LOGIN", t1, "sshd is not installed or its configuration is unreadable."),
                skipped("SSH-PASSWORD-AUTH", t2, "sshd is not installed or its configuration is unreadable.")]
    cfg = parse_sshd_config(text, _sshd_include_reader)
    running = _sshd_running()
    out: List[Check] = []
    note = "" if running else " (the SSH server is installed but not currently running)"

    def sev(base: Severity) -> Severity:
        return base if running else Severity(max(int(base) - 1, int(Severity.LOW)))

    if cfg.get("permitrootlogin") in ("yes",):
        out.append(failed(
            "SSH-ROOT-LOGIN", "SSH allows direct root login", sev(Severity.HIGH),
            "PermitRootLogin yes lets attackers brute-force the root account directly over SSH" + note + ".",
            "Edit /etc/ssh/sshd_config: set 'PermitRootLogin no' (or 'prohibit-password'), then sudo systemctl reload ssh.",
            path, {"PermitRootLogin": "yes", "sshd_running": running}, None, ["T1021.004", "T1110"]))
    else:
        out.append(passed("SSH-ROOT-LOGIN", t1))
    if cfg.get("permitemptypasswords") == "yes":
        out.append(failed(
            "SSH-EMPTY-PASSWORDS", "SSH allows accounts with empty passwords", sev(Severity.HIGH),
            "PermitEmptyPasswords yes lets anyone log in to accounts with a blank password" + note + ".",
            "Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config and reload sshd.", path,
            {"PermitEmptyPasswords": "yes"}, None, ["T1110"]))
    pw = cfg.get("passwordauthentication", "yes")  # OpenSSH default is yes
    if pw == "yes":
        out.append(failed(
            "SSH-PASSWORD-AUTH", "SSH accepts password logins", sev(Severity.MEDIUM),
            "Password authentication is enabled for SSH" + note + ": it is exposed to credential stuffing and brute-force attacks.",
            "Use SSH keys and set 'PasswordAuthentication no' in /etc/ssh/sshd_config (make sure your key works first), "
            "then sudo systemctl reload ssh.", path,
            {"PasswordAuthentication": pw, "explicit": "passwordauthentication" in cfg, "sshd_running": running},
            None, ["T1110"]))
    else:
        out.append(passed("SSH-PASSWORD-AUTH", t2))
    return out


def check_linux_updates(env: AuditEnv) -> List[Check]:
    out: List[Check] = []
    t = "Automatic security updates are enabled"
    enabled: Optional[bool] = None
    how = ""
    if os.path.exists("/usr/bin/apt") or shutil.which("apt-get"):
        conf = (_read_text("/etc/apt/apt.conf.d/20auto-upgrades") or "") + (_read_text("/etc/apt/apt.conf.d/10periodic") or "")
        m = re.search(r'APT::Periodic::Unattended-Upgrade\s+"?(\d+)"?', conf)
        rc, _, _ = run(["dpkg", "-s", "unattended-upgrades"], timeout=15)
        enabled = bool(m and m.group(1) != "0" and rc == 0)
        how = "unattended-upgrades"
    elif shutil.which("dnf") or shutil.which("yum"):
        for unit in ("dnf-automatic-install.timer", "dnf-automatic.timer", "yum-cron.service", "dnf5-automatic.timer"):
            rc, out_t, _ = run(["systemctl", "is-enabled", unit], timeout=10)
            if rc == 0 and out_t.strip() == "enabled":
                enabled, how = True, unit
                break
        else:
            enabled = False
    if enabled is None:
        out.append(skipped("LINUX-AUTO-UPDATES", t, "Unsupported package manager."))
    elif enabled:
        out.append(passed("LINUX-AUTO-UPDATES", t, how))
    else:
        out.append(failed(
            "LINUX-AUTO-UPDATES", "Automatic security updates are not enabled", Severity.LOW,
            "This system does not install security updates automatically.",
            "Debian/Ubuntu: sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades. "
            "Fedora/RHEL: sudo dnf install dnf-automatic && sudo systemctl enable --now dnf-automatic-install.timer",
            "Automatic updates", {"mechanism": how or "none"}, None))

    t2 = "No pending security updates"
    if shutil.which("apt"):
        rc, so, _ = run(["env", "LC_ALL=C", "apt", "list", "--upgradable"], timeout=40)
        if rc != 0:
            out.append(skipped("LINUX-PENDING-UPDATES", t2, "Could not query apt."))
        else:
            lines = [l for l in so.splitlines() if re.match(r"^\S+/\S+\s+\S+\s+\S+\s+\[.*\]$", l)]
            sec = [l.split("/")[0] for l in lines if "-security" in l.split()[0]]
            if sec:
                out.append(failed(
                    "LINUX-PENDING-UPDATES", f"{len(sec)} security update(s) waiting to be installed", Severity.MEDIUM,
                    f"{len(sec)} of {len(lines)} pending package updates are security fixes.",
                    "Run: sudo apt update && sudo apt upgrade", "apt", {"security_updates": sec[:50],
                                                                          "total_upgradable": len(lines)},
                    None, ["T1190"]))
            else:
                out.append(passed("LINUX-PENDING-UPDATES", t2, f"{len(lines)} other update(s) pending." if lines else ""))
    else:
        out.append(skipped("LINUX-PENDING-UPDATES", t2, "apt not available."))
    return out


def check_linux_files(env: AuditEnv) -> List[Check]:
    out: List[Check] = []
    # /etc/shadow
    t = "/etc/shadow is not readable by other users"
    try:
        st = os.stat("/etc/shadow")
        mode = statmod.S_IMODE(st.st_mode)
        if mode & 0o007 or mode & 0o020:
            out.append(failed(
                "LINUX-SHADOW-PERMS", "/etc/shadow has unsafe permissions", Severity.HIGH,
                f"/etc/shadow is mode {mode:04o}; password hashes are exposed to local users.",
                "Run: sudo chown root:shadow /etc/shadow && sudo chmod 640 /etc/shadow", "/etc/shadow",
                {"mode": f"{mode:04o}"}, run_cmd(["chmod", "640", "/etc/shadow"], "Restrict /etc/shadow to root and the shadow group"),
                ["T1003.008"]))
        else:
            out.append(passed("LINUX-SHADOW-PERMS", t, f"mode {mode:04o}"))
    except OSError:
        out.append(skipped("LINUX-SHADOW-PERMS", t, "/etc/shadow not found."))

    # sudoers NOPASSWD ALL
    t = "No passwordless sudo for regular users"
    texts: List[Tuple[str, str]] = []
    main = _read_text("/etc/sudoers")
    if main is not None:
        texts.append(("/etc/sudoers", main))
    for p in sorted(glob.glob("/etc/sudoers.d/*")):
        tx = _read_text(p)
        if tx is not None:
            texts.append((p, tx))
    if not texts:
        out.append(skipped("LINUX-SUDO-NOPASSWD", t, "sudoers not readable (needs root) or sudo not installed."))
    else:
        hits = find_nopasswd_all(texts)
        if hits:
            out.append(failed(
                "LINUX-SUDO-NOPASSWD", "Passwordless sudo (NOPASSWD: ALL) is configured", Severity.MEDIUM,
                "These users/groups can become root without a password, so any program running as them (or anyone "
                "at their unlocked session) owns the machine.",
                "Remove the NOPASSWD rule with `sudo visudo -f <file>` unless it is needed for automation.",
                hits[0]["file"], {"entries": hits[:20]}, None, ["T1548.003"]))
        else:
            out.append(passed("LINUX-SUDO-NOPASSWD", t))

    # world-writable files in /etc (shallow)
    ww = find_world_writable("/etc", max_depth=3, limit=20000)
    t = "No world-writable files in /etc"
    if ww is None:
        out.append(skipped("LINUX-ETC-WORLD-WRITABLE", t, "/etc not readable."))
    elif ww:
        critical = {"passwd", "shadow", "group", "gshadow", "sudoers", "ld.so.preload", "crontab", "profile",
                    "bash.bashrc", "hosts", "resolv.conf", "fstab", "environment"}
        sev = Severity.HIGH if any(os.path.basename(p) in critical for p in ww) else Severity.MEDIUM
        out.append(failed(
            "LINUX-ETC-WORLD-WRITABLE", "World-writable configuration files in /etc", sev,
            f"{len(ww)} file(s)/folder(s) under /etc can be modified by any local user - a direct path to root.",
            "Fix permissions, e.g. sudo chmod o-w <path>. If you did not create these, investigate how they changed.",
            ww[0], {"paths": ww[:30], "count": len(ww)}, None, ["T1222.002", "T1068"]))
    else:
        out.append(passed("LINUX-ETC-WORLD-WRITABLE", t))

    # ASLR
    t = "Address space layout randomisation (ASLR) is fully enabled"
    val = (_read_text("/proc/sys/kernel/randomize_va_space") or "").strip()
    if not val:
        out.append(skipped("LINUX-ASLR", t, "Kernel setting unreadable."))
    elif val == "2":
        out.append(passed("LINUX-ASLR", t))
    else:
        out.append(failed(
            "LINUX-ASLR", "ASLR is not fully enabled", Severity.MEDIUM,
            f"kernel.randomize_va_space is {val}; memory-corruption exploits become far easier.",
            "Run: sudo sysctl -w kernel.randomize_va_space=2 and persist it in /etc/sysctl.d/.",
            "/proc/sys/kernel/randomize_va_space", {"value": val},
            run_cmd(["sysctl", "-w", "kernel.randomize_va_space=2"], "Enable full ASLR"), ["T1068"]))

    # ld.so.preload
    t = "/etc/ld.so.preload is empty"
    pre = _read_text("/etc/ld.so.preload")
    if pre is None:
        out.append(passed("LINUX-LD-PRELOAD", t, "File does not exist."))
    else:
        entries = [l.strip() for l in pre.splitlines() if l.strip() and not l.strip().startswith("#")]
        if entries:
            out.append(failed(
                "LINUX-LD-PRELOAD", "/etc/ld.so.preload loads libraries into every program", Severity.HIGH,
                "Entries in /etc/ld.so.preload are injected into every process - the classic way user-space rootkits hide.",
                "Check each listed library (dpkg -S <path>). If it is not part of software you installed, treat the "
                "machine as compromised: back up data and reinstall.", "/etc/ld.so.preload", {"entries": entries[:20]},
                None, ["T1574.006"]))
        else:
            out.append(passed("LINUX-LD-PRELOAD", t))
    return out


def find_nopasswd_all(texts: Iterable[Tuple[str, str]]) -> List[Dict[str, str]]:
    rx = re.compile(r"^\s*(\S+)\s+\S+\s*=\s*(?:\([^)]*\)\s*)?(?:\w+:\s*)*NOPASSWD:\s*ALL\s*(?:#.*)?$")
    hits = []
    for fname, text in texts:
        for line in text.splitlines():
            if line.lstrip().startswith(("#", "Defaults")):
                continue
            m = rx.match(line)
            if m and m.group(1) not in ("root", "%root"):
                hits.append({"file": fname, "principal": m.group(1), "rule": line.strip()})
    return hits


def find_world_writable(root: str, max_depth: int = 3, limit: int = 20000) -> Optional[List[str]]:
    if not os.path.isdir(root):
        return None
    found: List[str] = []
    seen = 0
    base_depth = root.rstrip("/").count("/")
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        if dirpath.count("/") - base_depth >= max_depth:
            dirnames[:] = []
        for name in list(dirnames) + filenames:
            seen += 1
            if seen > limit:
                return found
            p = os.path.join(dirpath, name)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if statmod.S_ISLNK(st.st_mode):
                continue
            mode = st.st_mode
            if mode & 0o002:
                if statmod.S_ISDIR(mode) and mode & 0o1000:
                    continue  # sticky directory (like /tmp) is fine
                found.append(p)
    return found


def find_suid(roots: Sequence[str], budget_s: float) -> Tuple[List[str], bool]:
    """Walk roots looking for set-uid regular files. Returns (paths, timed_out)."""
    deadline = time.monotonic() + budget_s
    out: List[str] = []
    for root in roots:
        if not os.path.isdir(root) or root in SKIP_WALK:
            continue
        try:
            root_dev = os.stat(root).st_dev
        except OSError:
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            if time.monotonic() > deadline:
                return out, True
            keep = []
            for d in dirnames:
                full = os.path.join(dirpath, d)
                if full in SKIP_WALK or d in ("node_modules", ".git", ".cache", "proc"):
                    continue
                try:
                    if os.lstat(full).st_dev != root_dev:
                        continue
                except OSError:
                    continue
                keep.append(d)
            dirnames[:] = keep
            for name in filenames:
                p = os.path.join(dirpath, name)
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                if statmod.S_ISREG(st.st_mode) and st.st_mode & statmod.S_ISUID:
                    out.append(p)
    return out, False


def classify_suid(paths: Iterable[str]) -> Tuple[List[str], List[str]]:
    """(unknown binaries in system dirs, set-uid files in user-writable locations)."""
    unknown, suspicious = [], []
    for p in paths:
        if p.startswith(SUID_USER_WRITABLE):
            suspicious.append(p)
        elif os.path.basename(p) not in KNOWN_SUID:
            unknown.append(p)
    return unknown, suspicious


def check_linux_suid(env: AuditEnv) -> List[Check]:
    paths, timed_out = find_suid(SUID_ROOTS, 30.0 if env.deep else 10.0)
    unknown, suspicious = classify_suid(paths)
    note = " (scan stopped early at the time limit)" if timed_out else ""
    out: List[Check] = []
    t1, t2 = "No set-uid programs in user-writable folders", "No unfamiliar set-uid programs"
    if suspicious:
        out.append(failed(
            "LINUX-SUID-WRITABLE", "Set-uid programs in user-writable locations", Severity.HIGH,
            "Programs with the set-uid bit in /tmp, /home or similar folders run as their owner (often root) - a "
            "common privilege-escalation backdoor.",
            "Inspect each file; remove the set-uid bit with `chmod u-s <file>` or delete it if unknown.",
            suspicious[0], {"paths": suspicious[:30]}, None, ["T1548.001"]))
    else:
        out.append(passed("LINUX-SUID-WRITABLE", t1, note.strip()))
    if unknown:
        out.append(failed(
            "LINUX-SUID-UNKNOWN", "Unfamiliar set-uid programs", Severity.LOW,
            f"{len(unknown)} set-uid program(s) are not on Aegis' list of well-known ones{note}. Many are legitimate "
            "(distribution-specific helpers) but each is a potential privilege-escalation target.",
            "Check each with `dpkg -S <path>` or `rpm -qf <path>`; remove the set-uid bit from anything you do not need.",
            unknown[0], {"paths": unknown[:40], "count": len(unknown)}, None, ["T1548.001"]))
    else:
        out.append(passed("LINUX-SUID-UNKNOWN", t2, note.strip()))
    return out


# =========================================================================== macOS checks
def _mac_cmd(cmd: Sequence[str]) -> Optional[str]:
    rc, out, err = run(cmd, timeout=20)
    return (out + err) if rc >= 0 else None


def check_macos(env: AuditEnv) -> List[Check]:
    out: List[Check] = []
    txt = _mac_cmd(["csrutil", "status"])
    t = "System Integrity Protection (SIP) is enabled"
    if txt is None:
        out.append(skipped("MAC-SIP", t, "csrutil unavailable."))
    elif "enabled" in txt.lower() and "disabled" not in txt.lower():
        out.append(passed("MAC-SIP", t))
    else:
        out.append(failed(
            "MAC-SIP", "System Integrity Protection is disabled", Severity.HIGH,
            "SIP stops even root from modifying protected system files; with it off, malware can persist deep in macOS.",
            "Boot into Recovery (hold power / Cmd-R), open Terminal and run: csrutil enable", "csrutil status",
            {"output": txt.strip()[:200]}, None, ["T1553"]))
    txt = _mac_cmd(["spctl", "--status"])
    t = "Gatekeeper is enabled"
    if txt is None:
        out.append(skipped("MAC-GATEKEEPER", t, "spctl unavailable."))
    elif "assessments enabled" in txt.lower():
        out.append(passed("MAC-GATEKEEPER", t))
    else:
        out.append(failed(
            "MAC-GATEKEEPER", "Gatekeeper is disabled", Severity.HIGH,
            "Gatekeeper blocks unsigned/unnotarised apps from running. It is currently off.",
            "Run: sudo spctl --master-enable", "spctl --status", {"output": txt.strip()[:200]},
            run_cmd(["spctl", "--master-enable"], "Turn Gatekeeper on"), ["T1553.001"]))
    txt = _mac_cmd(["fdesetup", "status"])
    t = "FileVault disk encryption is on"
    if txt is None:
        out.append(skipped("MAC-FILEVAULT", t, "fdesetup unavailable."))
    elif re.search(r"filevault is on", txt, re.I):
        out.append(passed("MAC-FILEVAULT", t))
    else:
        out.append(failed(
            "MAC-FILEVAULT", "FileVault disk encryption is off", Severity.MEDIUM,
            "If the Mac is lost or stolen its disk can be read by anyone.",
            "System Settings > Privacy & Security > FileVault > Turn On. Store the recovery key safely.",
            "fdesetup status", {"output": txt.strip()[:200]}, None, ["T1005"]))
    txt = _mac_cmd(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
    t = "The macOS firewall is on"
    if txt is None:
        out.append(skipped("MAC-FIREWALL", t, "socketfilterfw unavailable."))
    else:
        m = re.search(r"State\s*=\s*(\d)", txt)
        if (m and m.group(1) in ("1", "2")) or "enabled" in txt.lower() and "disabled" not in txt.lower():
            out.append(passed("MAC-FIREWALL", t))
        else:
            out.append(failed(
                "MAC-FIREWALL", "The macOS application firewall is off", Severity.MEDIUM,
                "Incoming connections to apps are not filtered.",
                "System Settings > Network > Firewall > On.", "socketfilterfw --getglobalstate",
                {"output": txt.strip()[:200]},
                run_cmd(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "on"],
                        "Turn the macOS firewall on"), ["T1562.004"]))
    txt = _mac_cmd(["defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"])
    t = "Automatic update checks are on"
    if txt is None or "does not exist" in (txt or "").lower():
        out.append(skipped("MAC-AUTO-UPDATES", t, "Preference not set or unreadable (default is on)."))
    elif txt.strip() == "1":
        out.append(passed("MAC-AUTO-UPDATES", t))
    else:
        out.append(failed(
            "MAC-AUTO-UPDATES", "Automatic macOS update checks are off", Severity.MEDIUM,
            "The Mac does not check for security updates by itself.",
            "System Settings > General > Software Update > Automatic updates > turn on.",
            "com.apple.SoftwareUpdate", {"AutomaticCheckEnabled": txt.strip()[:20]}, None, ["T1190"]))
    return out


# =========================================================================== scanner
WINDOWS_CHECKS: List[Callable[[AuditEnv], List[Check]]] = [
    check_os_support, check_antivirus, check_defender_prefs, check_firewall, check_uac, check_smb, check_rdp,
    check_bitlocker, check_secure_boot, check_windows_update, check_credentials, check_hygiene, check_office,
]
LINUX_CHECKS: List[Callable[[AuditEnv], List[Check]]] = [
    check_linux_firewall, check_linux_ssh, check_linux_updates, check_linux_files, check_linux_suid,
]
MAC_CHECKS: List[Callable[[AuditEnv], List[Check]]] = [check_macos]


def run_checks(env: AuditEnv, checks: Sequence[Callable[[AuditEnv], List[Check]]],
               cancel: Optional[Callable[[], bool]] = None) -> Iterator[Emitted]:
    """Run check groups, converting any exception into an ERROR CheckResult."""
    for fn in checks:
        if cancel and cancel():
            return
        try:
            results = fn(env)
        except Exception as exc:  # one broken check must never abort the audit
            log.warning("check %s failed: %s", fn.__name__, exc, exc_info=True)
            yield CheckResult(check_id=RULE_PREFIX + fn.__name__.replace("check_", "").upper().replace("_", "-"),
                              title=f"Check '{fn.__name__}' could not run", status=CheckStatus.ERROR,
                              detail=f"{type(exc).__name__}: {exc}", category=Category.SYSTEM)
            continue
        for c in results:
            yield c.to_result()
            f = c.to_finding()
            if f:
                yield f


@register
class SystemAuditScanner(Scanner):
    name = "system_audit"
    title = "System hardening audit"
    description = ("Checks antivirus, firewall, updates, UAC, encryption, RDP/SMB exposure, credential hygiene, "
                   "Office macros and OS end-of-support (CIS / Secure Score style).")
    platforms = ("windows", "linux", "darwin")
    needs_admin_for_full_results = True

    def run(self, ctx: ScanContext) -> Iterator[Emitted]:
        env = AuditEnv(today=dt.date.today(), is_admin=ctx.is_admin, deep=ctx.deep)
        if IS_WINDOWS:
            ctx.report(self.name, "collecting Windows security state")
            try:
                env.facts = collect_windows_facts(ctx.is_admin)
            except Exception as exc:
                log.warning("PowerShell fact collection failed: %s", exc)
            if not env.facts:
                yield CheckResult(check_id=RULE_PREFIX + "POWERSHELL", title="PowerShell security queries",
                                  status=CheckStatus.WARN,
                                  detail="PowerShell returned no data; Defender/update/account checks will be skipped.",
                                  category=Category.SYSTEM)
            checks = WINDOWS_CHECKS
        elif IS_MAC:
            checks = MAC_CHECKS
        else:
            checks = LINUX_CHECKS
        ctx.report(self.name, "evaluating hardening checks")
        yield from run_checks(env, checks, cancel=lambda: ctx.cancelled)
