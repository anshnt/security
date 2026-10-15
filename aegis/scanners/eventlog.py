"""Windows event-log threat hunting (a single-endpoint, Sigma-style "hunt").

Reads the last 14 days of the local event logs with ONE batched PowerShell
``Get-WinEvent -FilterHashtable`` call per log (capped counts, JSON output) and
looks for the behaviour attackers leave behind:

* Security 1102 / System 104        - audit / event log cleared
* Security 4720 / 4722 / 4732       - new local user, re-enabled built-in account, added to Administrators
* Security 4625 + 4624              - password-guessing bursts, and whether one *succeeded* (RDP/SMB)
* Security 4697 / System 7045       - new service (user-writable image path, LOLBin command lines, drivers)
* Security 4698                     - new scheduled task with a suspicious command
* Security 4688 / Sysmon 1          - process creation command lines (needs auditing; see below)
* Defender 1116-1119, 5001/5007/5010/5012 - threats detected / protection switched off or weakened
* PowerShell 4104                   - script blocks that contain malicious content
* WMI-Activity 5861                 - permanent WMI event subscriptions (fileless persistence)
* Sysmon 3 / 7 / 11                 - outbound LOLBin connections, DLL side-loading, dropped executables

Everything is locale independent: events are identified by EventID and fields
are read from the event XML ``<Data Name=...>`` elements (never from the
localised message text).

The parsing and detection logic is pure (functions over plain event dicts, see
``make_event``) so it is unit-tested on any OS; only ``collect_log`` talks to
PowerShell. Windows audit policies that are off (process-creation auditing,
PowerShell script-block logging) are reported as visibility gaps with a fix.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import logging
import os
import re
import time
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

from aegis.core.models import Category, CheckResult, CheckStatus, Finding, Remediation, Severity
from aegis.core.platform import IS_WINDOWS, as_list, powershell_json, reg_read
from aegis.scanners.base import Emitted, ScanContext, Scanner, register

log = logging.getLogger("aegis.eventlog")

LOOKBACK_DAYS = 14
MAX_FINDINGS_PER_DETECTOR = 25
BRUTE_THRESHOLD = 10  # failed logons from one source inside BRUTE_WINDOW_S
BRUTE_WINDOW_S = 600
SUCCESS_WINDOW_S = 3600  # a success this long after the last failure still counts as "after the burst"

# =========================================================================== query description


@dataclass(frozen=True)
class Group:
    """One Get-WinEvent query inside a log's batched PowerShell call."""

    ids: Tuple[int, ...]
    cap: int
    kind: str = "xml"  # xml: ship event XML | logon_ok: 4624 prefilter on logon type | sbl: PowerShell 4104 fields


@dataclass(frozen=True)
class LogSpec:
    key: str
    name: str  # Get-WinEvent -LogName
    groups: Tuple[Group, ...]
    admin_only: bool = False
    timeout: int = 180
    optional: bool = False  # the log legitimately may not exist (Sysmon)
    av_query: bool = False  # also ask Security Center which antivirus products are registered


LOG_SPECS: Tuple[LogSpec, ...] = (
    LogSpec("security", "Security", (
        Group((1102, 4719, 4720, 4722, 4732, 4697, 4698), 1500),
        Group((4625,), 4000),
        Group((4624,), 1500, "logon_ok"),
        Group((4688,), 3000),
    ), admin_only=True, timeout=240),
    LogSpec("system", "System", (Group((104, 7045), 800),)),
    LogSpec("defender", "Microsoft-Windows-Windows Defender/Operational",
            (Group((1116, 1117, 1118, 1119, 5001, 5007, 5010, 5012), 800),), av_query=True),
    LogSpec("powershell", "Microsoft-Windows-PowerShell/Operational", (Group((4104,), 1500, "sbl"),)),
    LogSpec("wmi", "Microsoft-Windows-WMI-Activity/Operational", (Group((5861,), 300),)),
    LogSpec("sysmon", "Microsoft-Windows-Sysmon/Operational", (
        Group((1,), 3000), Group((3,), 2500), Group((7,), 1500), Group((11,), 2500),
    ), optional=True),
)


def _ps_quote(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def build_query_script(spec: LogSpec, days: int = LOOKBACK_DAYS) -> str:
    """The single PowerShell script that reads one log. Output is one JSON object
    ``{Events:[{I,X}|{I,L,T,D}], Errors:[..], Info:{..}, Av:[..]}``. Errors carry
    exception type names / FullyQualifiedErrorIds (never localised text)."""
    log_q = _ps_quote(spec.name)
    parts = [
        "$ErrorActionPreference='Stop'",
        f"$start=(Get-Date).AddDays(-{int(days)})",
        "$ev=New-Object System.Collections.Generic.List[object]",
        "$er=New-Object System.Collections.Generic.List[string]",
        "$info=@{Enabled=$null;Records=$null;MaxBytes=$null;FileBytes=$null;Oldest=$null}",
        f"try {{ $li=Get-WinEvent -ListLog {log_q}; $info.Enabled=$li.IsEnabled; $info.Records=$li.RecordCount; "
        f"$info.MaxBytes=$li.MaximumSizeInBytes; $info.FileBytes=$li.FileSize }} "
        f"catch {{ $er.Add('list|'+$_.Exception.GetType().Name) }}",
        f"try {{ $o=Get-WinEvent -LogName {log_q} -Oldest -MaxEvents 1; "
        f"if($o){{ $info.Oldest=$o.TimeCreated.ToUniversalTime().ToString('o') }} }} catch {{ }}",
    ]
    for g in spec.groups:
        ids = ",".join(str(i) for i in g.ids)
        flt = f"@{{LogName={log_q};Id=@({ids});StartTime=$start"
        if g.kind == "logon_ok":
            flt += ";Data=@('3','10')"  # server-side prefilter: network / remote-interactive logons
        flt += "}"
        base = f"Get-WinEvent -FilterHashtable {flt} -ErrorAction Stop"
        if g.kind == "logon_ok":
            # 4624 property 8 is LogonType (Properties are positional => locale independent)
            pipeline = (f"{base} | Where-Object {{ $t=$_.Properties[8].Value -as [int]; $t -eq 3 -or $t -eq 10 }} "
                        f"| Select-Object -First {g.cap}")
        else:
            pipeline = f"{base} -MaxEvents {g.cap}"
        if g.kind == "sbl":
            proj = ("ForEach-Object { $p=$_.Properties; $t=[string]$p[2].Value; "
                    "if($t.Length -gt 20000){$t=$t.Substring(0,20000)}; "
                    "$ev.Add([pscustomobject]@{I=$_.Id;L=($_.Level -as [int]);T=$_.TimeCreated.ToUniversalTime().ToString('o');"
                    "D=[pscustomobject]@{MessageNumber=[string]$p[0].Value;MessageTotal=[string]$p[1].Value;"
                    "ScriptBlockText=$t;ScriptBlockId=[string]$p[3].Value;Path=[string]$p[4].Value}}) }")
        else:
            proj = "ForEach-Object { $ev.Add([pscustomobject]@{I=$_.Id;X=$_.ToXml()}) }"
        parts.append(f"try {{ {pipeline} | {proj} }} "
                     f"catch {{ $er.Add(($_.FullyQualifiedErrorId+'|'+$_.Exception.GetType().Name)) }}")
    if spec.av_query:
        parts.append("$av=@(); try { $av=@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct "
                     "-ErrorAction Stop | ForEach-Object { [string]$_.displayName }) } catch { }")
    else:
        parts.append("$av=@()")
    parts.append("[pscustomobject]@{Events=$ev.ToArray();Errors=$er.ToArray();Info=$info;Av=$av} "
                 "| ConvertTo-Json -Depth 6 -Compress")
    return "; ".join(parts)


# =========================================================================== event parsing (pure)

_TS_RX = re.compile(r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,](\d+))?")


def parse_time(value: Any) -> Optional[float]:
    """Epoch seconds (UTC) from an event timestamp such as ``2026-10-14T10:22:11.1234567Z``."""
    if isinstance(value, (int, float)):
        return float(value)
    m = _TS_RX.search(str(value or ""))
    if not m:
        return None
    y, mo, d, h, mi, s = (int(x) for x in m.groups()[:6])
    try:
        base = dt.datetime(y, mo, d, h, mi, s, tzinfo=dt.timezone.utc).timestamp()
    except ValueError:
        return None
    return base + (float("0." + m.group(7)) if m.group(7) else 0.0)


def fmt_time(ts: Optional[float]) -> str:
    if ts is None:
        return "unknown time"
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_event_xml(xml: str) -> Optional[Dict[str, Any]]:
    """Parse the XML of one event into a normalised dict:
    ``{id, log, ts, time, provider, computer, level, user_sid, data}``. ``data`` maps
    EventData ``<Data Name=..>`` (and UserData leaf element) names to text."""
    try:
        root = ET.fromstring(xml)
    except (ET.ParseError, ValueError):
        return None
    ev: Dict[str, Any] = {"id": 0, "log": "", "ts": None, "time": "", "provider": "", "computer": "", "level": None,
                          "user_sid": "", "data": {}}
    data: Dict[str, str] = {}
    idx = 0
    for el in root:
        tag = _local(el.tag)
        if tag == "System":
            for s in el:
                st = _local(s.tag)
                if st == "EventID":
                    try:
                        ev["id"] = int((s.text or "0").strip())
                    except ValueError:
                        ev["id"] = 0
                elif st == "Provider":
                    ev["provider"] = s.attrib.get("Name", "")
                elif st == "TimeCreated":
                    ev["time"] = s.attrib.get("SystemTime", "")
                    ev["ts"] = parse_time(ev["time"])
                elif st == "Computer":
                    ev["computer"] = (s.text or "").strip()
                elif st == "Level":
                    try:
                        ev["level"] = int((s.text or "").strip())
                    except ValueError:
                        pass
                elif st == "Channel":
                    ev["log"] = (s.text or "").strip()
                elif st == "Security":
                    ev["user_sid"] = s.attrib.get("UserID", "")
        elif tag in ("EventData", "UserData"):
            for node in el.iter():
                nt = _local(node.tag)
                if node is el:
                    continue
                if nt == "Data":
                    name = node.attrib.get("Name") or f"Data{idx}"
                    data[name] = (node.text or "").strip() if len(node) == 0 else data.get(name, "")
                    idx += 1
                elif nt != "Binary" and len(node) == 0 and tag == "UserData":
                    data[nt] = (node.text or "").strip()
    ev["data"] = data
    return ev


def make_event(event_id: int, log: str = "Security", when: Any = None, provider: str = "", computer: str = "",
               level: Optional[int] = None, user_sid: str = "", **data: Any) -> Dict[str, Any]:
    """Build a normalised event dict (used by the parser, the tests and any caller that has events
    from another source, e.g. an EVTX exporter)."""
    ts = parse_time(when) if when is not None else None
    return {"id": int(event_id), "log": log, "ts": ts, "time": (when if isinstance(when, str) else fmt_time(ts)),
            "provider": provider, "computer": computer, "level": level, "user_sid": user_sid,
            "data": {k: ("" if v is None else str(v)) for k, v in data.items()}}


def normalize_record(rec: Dict[str, Any], log_name: str) -> Optional[Dict[str, Any]]:
    """Convert one JSON record from ``build_query_script`` into a normalised event dict."""
    if not isinstance(rec, dict):
        return None
    if rec.get("X"):
        ev = parse_event_xml(str(rec["X"]))
        if ev is None:
            return None
        if rec.get("I") and not ev["id"]:
            ev["id"] = int(rec["I"])
    else:
        ts = parse_time(rec.get("T"))
        d = rec.get("D") if isinstance(rec.get("D"), dict) else {}
        ev = {"id": int(rec.get("I") or 0), "log": log_name, "ts": ts, "time": rec.get("T") or "", "provider": "",
              "computer": "", "level": rec.get("L"), "user_sid": "", "data": {k: ("" if v is None else str(v)) for k, v in d.items()}}
    ev["log"] = log_name  # the channel as we asked for it (stable key for the detectors)
    return ev


# =========================================================================== helpers

def _d(ev: Dict[str, Any], *names: str, default: str = "") -> str:
    data = ev.get("data") or {}
    for n in names:
        v = data.get(n)
        if v not in (None, ""):
            return str(v)
    return default


def _who(ev: Dict[str, Any], prefix: str = "Subject") -> str:
    user, dom = _d(ev, prefix + "UserName"), _d(ev, prefix + "DomainName")
    if user and dom and dom != "-":
        return f"{dom}\\{user}"
    return user or "unknown"


def _is_system_actor(ev: Dict[str, Any]) -> bool:
    sid, user = _d(ev, "SubjectUserSid"), _d(ev, "SubjectUserName")
    return sid == "S-1-5-18" or user.upper() == "SYSTEM" or user.endswith("$")


def _base(path: str) -> str:
    return re.split(r"[\\/]", (path or "").strip().strip('"'))[-1].lower()


def _clip(text: str, n: int = 500) -> str:
    text = text or ""
    return text if len(text) <= n else text[:n] + "..."


def _cmdline():
    try:
        from aegis.core import cmdline as cl  # imported lazily: shared module owned by another component

        return cl
    except Exception:  # pragma: no cover - module missing
        return None


def _analyse_cmd(cmd: str) -> List[Tuple[str, str, Severity, List[str], str]]:
    cl = _cmdline()
    if not cl or not cmd:
        return []
    try:
        return list(cl.analyse_command_line(cmd))
    except Exception as exc:  # pragma: no cover - defensive
        log.debug("analyse_command_line failed: %s", exc)
        return []


def _path_risk(path: str) -> int:
    cl = _cmdline()
    if not cl or not path:
        return 0
    try:
        return int(cl.path_risk(path))
    except Exception:  # pragma: no cover
        return 0


def _exe_of(cmd: str) -> str:
    cl = _cmdline()
    if not cl or not cmd:
        return ""
    try:
        return cl.extract_executable(cmd) or ""
    except Exception:  # pragma: no cover
        return ""


def classify_ip(ip: str) -> str:
    """'external' (public Internet), 'internal' (private/link-local/CGNAT), 'local' (loopback) or 'unknown'."""
    ip = (ip or "").strip().strip("[]").split("%")[0]
    if ip in ("", "-"):
        return "unknown"
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped:
        addr = mapped
    if addr.is_loopback:
        return "local"
    return "external" if addr.is_global else "internal"


def _loc(ev: Dict[str, Any], what: str = "") -> str:
    base = f"{ev.get('log', '?')} log, event {ev.get('id')} at {fmt_time(ev.get('ts'))}"
    return f"{base} ({what})" if what else base


def _finding(rule: str, title: str, sev: Severity, cat: str, desc: str, ev: Dict[str, Any], rec: str,
             evidence: Optional[Dict[str, Any]] = None, mitre: Optional[List[str]] = None,
             remediation: Optional[Remediation] = None, what: str = "", location: str = "") -> Finding:
    e = {"source": "eventlog", "log": ev.get("log"), "event_id": ev.get("id"), "time": fmt_time(ev.get("ts"))}
    e.update(evidence or {})
    return Finding(rule, title, sev, cat, desc, location or _loc(ev, what), e, rec, remediation, mitre=mitre or [])


def _top(findings: List[Finding], n: int = MAX_FINDINGS_PER_DETECTOR) -> List[Finding]:
    findings.sort(key=lambda f: -int(f.severity))
    return findings[:n]


def _events(events: Sequence[Dict[str, Any]], *ids: int, log: Optional[str] = None) -> List[Dict[str, Any]]:
    out = [e for e in events if e.get("id") in ids and (log is None or e.get("log") == log)]
    out.sort(key=lambda e: e.get("ts") or 0)
    return out


# =========================================================================== 1. log cleared (1102 / 104)

def detect_log_cleared(events: Sequence[Dict[str, Any]]) -> List[Finding]:
    out: List[Finding] = []
    for ev in _events(events, 1102, 104):
        if ev["id"] == 1102 and ev["log"] != "Security":
            continue
        if ev["id"] == 104 and ev["log"] != "System":
            continue
        channel = _d(ev, "Channel") or ("Security" if ev["id"] == 1102 else "an event log")
        who = _who(ev)
        important = channel.lower() in ("security", "system", "microsoft-windows-powershell/operational",
                                        "windows powershell", "microsoft-windows-sysmon/operational",
                                        "microsoft-windows-windows defender/operational")
        sev = Severity.HIGH if important else Severity.MEDIUM
        out.append(_finding(
            "AEG-EVT-CLEARED", f"The {channel} event log was cleared", sev, Category.SUSPICIOUS,
            f"Windows recorded that the {channel} event log was erased by {who}. The event log is the black-box "
            "recorder of your PC; clearing it is a standard way for an intruder to hide what they did, and "
            "ordinary users and programs almost never do it.",
            ev, "If you (or your IT department) did not clear this log on purpose, treat the PC as possibly "
                "compromised: review the other findings from around that time, change your passwords from a "
                "different device and run a full scan. Consider forwarding logs to another machine so they cannot "
                "be erased locally.",
            {"cleared_by": who, "channel": channel, "user_sid": _d(ev, "SubjectUserSid")}, ["T1685.005"]))
    return _top(out)


# =========================================================================== 2. accounts (4720 / 4722 / 4732)

_BUILTIN_RIDS = {"500": "Administrator", "501": "Guest", "503": "DefaultAccount"}
_EXPECTED_NEW_USERS = ("defaultuser", "wdagutilityaccount", "defaultaccount")
_GROUPS = {
    "S-1-5-32-544": ("Administrators", Severity.MEDIUM),
    "S-1-5-32-555": ("Remote Desktop Users", Severity.MEDIUM),
    "S-1-5-32-551": ("Backup Operators", Severity.LOW),
    "S-1-5-32-580": ("Remote Management Users", Severity.LOW),
}


def detect_account_changes(events: Sequence[Dict[str, Any]]) -> List[Finding]:
    out: List[Finding] = []
    created = _events(events, 4720, log="Security")
    adds = [e for e in _events(events, 4732, log="Security") if _d(e, "TargetSid") in _GROUPS]
    enables = _events(events, 4722, log="Security")
    used_adds: set = set()

    for ev in created:
        name, sid = _d(ev, "TargetUserName"), _d(ev, "TargetSid")
        if name.lower().startswith(_EXPECTED_NEW_USERS):
            continue
        hidden = name.endswith("$")
        admin_add = next((a for a in adds if _d(a, "TargetSid") == "S-1-5-32-544" and _d(a, "MemberSid") == sid
                          and 0 <= (a["ts"] or 0) - (ev["ts"] or 0) <= 86400), None)
        by = _who(ev)
        if admin_add:
            used_adds.add(id(admin_add))
            gap = int((admin_add["ts"] or 0) - (ev["ts"] or 0))
            out.append(_finding(
                "AEG-EVT-NEWADMIN", f"New local administrator account '{name}' was created", Severity.HIGH,
                Category.PERSISTENCE,
                f"A new local account called '{name}' was created by {by} and "
                f"{'within ' + str(gap // 60) + ' minute(s) ' if gap >= 60 else 'immediately '}added to the "
                "Administrators group. Creating a hidden or extra administrator account is one of the most common "
                "ways an intruder keeps access to a PC after the first break-in."
                + (" The name ends in '$', which hides the account from the normal user list." if hidden else ""),
                ev, f"If you did not create '{name}', remove it (Settings > Accounts, or an elevated 'net user {name} "
                    "/delete') and change the passwords of all other accounts, then run a full scan. "
                    "Check Remote Desktop and scheduled tasks for other backdoors.",
                {"account": name, "account_sid": sid, "created_by": by, "added_by": _who(admin_add),
                 "added_to_admins_at": fmt_time(admin_add["ts"]), "hidden_name": hidden}, ["T1136.001", "T1098"],
                what=f"account {name}"))
            continue
        system_actor = _is_system_actor(ev)
        sev = Severity.HIGH if hidden else (Severity.LOW if system_actor else Severity.MEDIUM)
        out.append(_finding(
            "AEG-EVT-NEWUSER", f"New local user account '{name}' was created", sev, Category.PERSISTENCE,
            f"A new local account called '{name}' was created by {by}. New accounts are normal when you set up the "
            "PC or add a family member, but attackers also create accounts as a back door."
            + (" The name ends in '$', which hides the account from the normal user list." if hidden else ""),
            ev, f"If you did not create '{name}' (or approve an installer/IT tool doing it), disable or delete the "
                "account and change your passwords.",
            {"account": name, "account_sid": sid, "created_by": by, "hidden_name": hidden}, ["T1136.001"],
            what=f"account {name}"))

    for ev in adds:
        if id(ev) in used_adds:
            continue
        group, base_sev = _GROUPS[_d(ev, "TargetSid")]
        msid, mname = _d(ev, "MemberSid"), _d(ev, "MemberName", default="")
        if msid.endswith("-512") and _is_system_actor(ev):
            continue  # domain join adds "Domain Admins" to local Administrators
        member = mname if mname and mname != "-" else msid
        sev = Severity.LOW if _is_system_actor(ev) else base_sev
        by = _who(ev)
        out.append(_finding(
            "AEG-EVT-GROUPADD", f"'{member}' was added to the local {group} group", sev, Category.PERSISTENCE,
            f"{by} added '{member}' to the {group} group. Members of this group can "
            + ("take complete control of the PC." if group == "Administrators" else
               "log in remotely or access data they otherwise could not.")
            + " Unexpected additions are a typical privilege-escalation / persistence step.",
            ev, f"Open 'lusrmgr.msc' (or 'net localgroup {group}') and remove '{member}' unless you recognise it.",
            {"member": member, "member_sid": msid, "group": group, "added_by": by},
            ["T1098", "T1078.003"] if group != "Remote Desktop Users" else ["T1098", "T1021.001"],
            what=f"{member} -> {group}"))

    for ev in enables:
        sid, name = _d(ev, "TargetSid"), _d(ev, "TargetUserName")
        rid = sid.rsplit("-", 1)[-1] if sid.startswith("S-1-5-21-") else ""
        if rid in _BUILTIN_RIDS:
            out.append(_finding(
                "AEG-EVT-BUILTIN-ENABLED", f"The built-in {_BUILTIN_RIDS[rid]} account was enabled", Severity.MEDIUM,
                Category.PERSISTENCE,
                f"{_who(ev)} switched on the built-in '{name or _BUILTIN_RIDS[rid]}' account, which is disabled by "
                "default because its name is well known and it is a favourite target for password guessing. "
                "Attackers re-enable it to get a quiet way back in.",
                ev, "Disable the account again unless you enabled it deliberately ('net user "
                    f"{name or _BUILTIN_RIDS[rid]} /active:no') and make sure it has a strong, unique password.",
                {"account": name, "account_sid": sid, "enabled_by": _who(ev)}, ["T1078.001"],
                what=f"account {name}"))
            continue
        if any(c["ts"] and ev["ts"] and 0 <= ev["ts"] - c["ts"] <= 600 and _d(c, "TargetSid") == sid for c in created):
            continue  # enabling right after creation is the normal flow
        if name.lower().startswith(_EXPECTED_NEW_USERS):
            continue
        out.append(_finding(
            "AEG-EVT-USER-ENABLED", f"Local account '{name}' was re-enabled", Severity.LOW, Category.PERSISTENCE,
            f"{_who(ev)} re-enabled the previously disabled account '{name}'. This is normal when you reactivate a "
            "user on purpose, but attackers also wake up old accounts because nobody is watching them.",
            ev, f"Confirm you expected '{name}' to be active; if not, disable it and reset its password.",
            {"account": name, "account_sid": sid, "enabled_by": _who(ev)}, ["T1078"], what=f"account {name}"))
    return _top(out)


# =========================================================================== 3. password guessing (4625 / 4624)

def _logon_type(ev: Dict[str, Any]) -> int:
    try:
        return int(_d(ev, "LogonType", default="0"))
    except ValueError:
        return 0


def _source_key(ev: Dict[str, Any]) -> Tuple[str, str]:
    ip = _d(ev, "IpAddress")
    if ip and ip not in ("-", "::1", "127.0.0.1"):
        return ip, ip
    ws = _d(ev, "WorkstationName")
    return (f"ws:{ws}", "") if ws and ws != "-" else ("unknown", "")


def find_bursts(times: Sequence[float], threshold: int, window: float) -> Optional[Tuple[int, float, float]]:
    """Sliding-window burst finder over sorted timestamps. Returns (events_in_bursts, first_ts, last_ts) covering
    every window that reaches ``threshold`` events, else None."""
    if len(times) < threshold:
        return None
    marked: set = set()
    lo = 0
    for hi in range(len(times)):
        while times[hi] - times[lo] > window:
            lo += 1
        if hi - lo + 1 >= threshold:
            marked.update(range(lo, hi + 1))
    if not marked:
        return None
    first, last = min(marked), max(marked)
    return len(marked), times[first], times[last]


def _block_ip_remediation(ip: str) -> Optional[Remediation]:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return Remediation(
        "run_command",
        {"command": ["netsh", "advfirewall", "firewall", "add", "rule", f"name=Aegis block {addr}", "dir=in",
                     "action=block", f"remoteip={addr}"]},
        f"Add a Windows Firewall rule that blocks inbound traffic from {addr} (remove it later in "
        "'Windows Defender Firewall with Advanced Security')")


def detect_logon_attacks(events: Sequence[Dict[str, Any]], signatures: Any = None, threshold: int = BRUTE_THRESHOLD,
                         window: float = BRUTE_WINDOW_S) -> List[Finding]:
    fails = [e for e in _events(events, 4625, log="Security") if e.get("ts")]
    succ = [e for e in _events(events, 4624, log="Security") if e.get("ts") and _logon_type(e) in (3, 10)
            and not _d(e, "TargetUserName").endswith("$") and _d(e, "TargetUserName").upper() != "ANONYMOUS LOGON"]
    out: List[Finding] = []
    by_src: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    ip_of: Dict[str, str] = {}
    for e in fails:
        key, ip = _source_key(e)
        by_src[key].append(e)
        ip_of[key] = ip
    handled_success: set = set()

    def is_bad_ip(ip: str) -> bool:
        try:
            return bool(signatures and ip and signatures.is_bad_ip(ip))
        except Exception:
            return False

    for key, evs in by_src.items():
        times = [e["ts"] for e in evs]
        burst = find_bursts(times, threshold, window)
        if not burst:
            continue
        count, first, last = burst
        ip = ip_of[key]
        kind = classify_ip(ip) if ip else "unknown"
        in_burst = [e for e in evs if first <= e["ts"] <= last]
        users = sorted({_d(e, "TargetUserName") for e in in_burst if _d(e, "TargetUserName")})
        types = sorted({_logon_type(e) for e in in_burst})
        wins = [s for s in succ if ip and _source_key(s)[0] == ip and first <= s["ts"] <= last + SUCCESS_WINDOW_S]
        service = "Remote Desktop" if 10 in types or 3 in types else "Windows sign-in"
        spray = len(users) >= 5
        src_label = ip or key
        mitre = ["T1110.003" if spray else "T1110.001", "T1021.001"]
        evid = {"source": src_label, "source_kind": kind, "failed_attempts": count, "first_attempt": fmt_time(first),
                "last_attempt": fmt_time(last), "accounts_tried": users[:15], "logon_types": types,
                "password_spraying": spray, "known_bad_ip": is_bad_ip(ip)}
        rem = _block_ip_remediation(ip) if kind == "external" else None
        if wins:
            w = wins[0]
            handled_success.add(id(w))
            sev = Severity.CRITICAL if is_bad_ip(ip) else (Severity.HIGH if kind == "external" else Severity.MEDIUM)
            evid.update({"successful_account": _d(w, "TargetUserName"), "success_logon_type": _logon_type(w),
                         "success_time": fmt_time(w["ts"])})
            out.append(_finding(
                "AEG-EVT-BRUTE-SUCCESS",
                f"Password guessing from {src_label} probably succeeded ({_d(w, 'TargetUserName')})", sev,
                Category.NETWORK,
                f"{count} failed sign-in attempts from {src_label} ({kind} address) between {fmt_time(first)} and "
                f"{fmt_time(last)} were followed by a SUCCESSFUL {service.lower()} sign-in as "
                f"'{_d(w, 'TargetUserName')}' at {fmt_time(w['ts'])}. That pattern - many wrong passwords and then "
                "a right one - is how attackers break into PCs whose Remote Desktop or file sharing is reachable "
                "from the network."
                + (" The source address is on a known-malicious list." if is_bad_ip(ip) else ""),
                w, "Treat this as a likely intrusion. Change the password of that account (and any account "
                   "that shares it) from a different device, sign out remote sessions, run a full scan and review "
                   "new accounts, services and scheduled tasks. Do not expose Remote Desktop to the Internet - use a "
                   "VPN and enable Network Level Authentication and account lockout.",
                evid, mitre + ["T1078"], rem, what=f"from {src_label}",
                location=f"{service} sign-in from {src_label} after password guessing"))
        else:
            sev = Severity.MEDIUM if kind == "external" else Severity.LOW
            out.append(_finding(
                "AEG-EVT-BRUTE",
                f"{'Internet' if kind == 'external' else 'Network'} password guessing against this PC from {src_label}",
                sev, Category.NETWORK,
                f"{count} failed sign-in attempts from {src_label} ({kind} address) between {fmt_time(first)} and "
                f"{fmt_time(last)}, trying {len(users)} account name(s)"
                + (" (password spraying: many accounts, few passwords)" if spray else "") + ". "
                + ("Because the address is on the public Internet, this PC accepts sign-in attempts from the "
                   "outside - usually Remote Desktop or file sharing that is exposed through the router or firewall."
                   if kind == "external" else "Someone or something on your network is trying passwords against this PC."),
                in_burst[-1], "No attempt succeeded in the logs reviewed. Close the exposure: disable Remote Desktop "
                              "if you do not need it, or put it behind a VPN; block the address; use long unique "
                              "passwords and an account lockout policy.",
                evid, mitre, rem, what=f"from {src_label}",
                location=f"Failed sign-ins from {src_label}"))

    # Successful network/RDP logons from the public Internet that were not part of a burst.
    seen_ips: set = set()
    for s in succ:
        if id(s) in handled_success:
            continue
        key, ip = _source_key(s)
        if not ip or classify_ip(ip) != "external" or ip in seen_ips:
            continue
        seen_ips.add(ip)
        rdp = _logon_type(s) == 10
        sev = Severity.CRITICAL if is_bad_ip(ip) else Severity.MEDIUM
        out.append(_finding(
            "AEG-EVT-EXTERNAL-LOGON",
            f"{'Remote Desktop' if rdp else 'Network'} sign-in from Internet address {ip}", sev, Category.NETWORK,
            f"'{_d(s, 'TargetUserName')}' signed in to this PC from the public Internet address {ip} at "
            f"{fmt_time(s['ts'])} (logon type {_logon_type(s)}). That is expected if you connected to your own PC "
            "from outside your home or office, but it also means the PC is reachable from the Internet - which "
            "attackers constantly scan for."
            + (" The address is on a known-malicious list." if is_bad_ip(ip) else ""),
            s, "If this was not you, change the account's password immediately and run a full scan. Prefer a VPN "
               "over exposing Remote Desktop / file sharing directly.",
            {"source": ip, "account": _d(s, "TargetUserName"), "logon_type": _logon_type(s),
             "known_bad_ip": is_bad_ip(ip)}, ["T1021.001", "T1078"], _block_ip_remediation(ip), what=f"from {ip}",
            location=f"{'RDP' if rdp else 'Network'} sign-in from {ip}"))
    return _top(out)


# =========================================================================== 4. services (4697 / 7045)

_SERVICE_INTERPRETER = re.compile(
    r"(?i)(%comspec%|\bcmd(?:\.exe)?\"?\s+/[ck]\b|\b(?:powershell|pwsh)(?:\.exe)?\b|\bmshta(?:\.exe)?\b|"
    r"\bw(?:script|cscript)(?:\.exe)?\b|\brundll32(?:\.exe)?\b|\bregsvr32(?:\.exe)?\b)")
_REMOTE_EXEC = re.compile(r"(?i)\\\\(?:127\.0\.0\.1|localhost|\.)\\(?:[a-z]\$|admin\$)|\\\\[^\\\s]+\\(?:[a-z]\$|admin\$)\\")


def _service_fields(ev: Dict[str, Any]) -> Tuple[str, str, str, str]:
    if ev["id"] == 4697:
        return (_d(ev, "ServiceName"), _d(ev, "ServiceFileName"), _d(ev, "ServiceAccount"), _who(ev))
    return (_d(ev, "ServiceName"), _d(ev, "ImagePath"), _d(ev, "AccountName"), "")


def detect_service_installs(events: Sequence[Dict[str, Any]]) -> List[Finding]:
    out: List[Finding] = []
    seen: set = set()
    try:
        from aegis.scanners.drivers import match_known_driver  # sibling module, optional
    except Exception:  # pragma: no cover
        match_known_driver = None  # type: ignore[assignment]
    for ev in _events(events, 4697, 7045):
        if (ev["id"] == 4697 and ev["log"] != "Security") or (ev["id"] == 7045 and ev["log"] != "System"):
            continue
        name, image, account, who = _service_fields(ev)
        if not image:
            continue
        key = (name.lower(), image.lower())
        if key in seen:
            continue
        seen.add(key)
        exe = _exe_of(image) or image
        risk = _path_risk(exe)
        hits = _analyse_cmd(image)
        reasons: List[str] = []
        sev = max((h[2] for h in hits), default=Severity.INFO)
        mitre = ["T1543.003"]
        for h in hits:
            reasons.append(h[1])
            mitre += h[3]
        is_driver = exe.lower().endswith(".sys")
        if risk:
            reasons.append(f"program is in a user-writable folder ({'a typical malware drop location' if risk == 2 else 'AppData/ProgramData'})")
            sev = max(sev, Severity.MEDIUM if risk == 2 else Severity.LOW)
        if _SERVICE_INTERPRETER.search(image):
            reasons.append("the service is a script interpreter / command shell, not a normal program")
            sev = max(sev, Severity.MEDIUM)
            if risk or hits:
                sev = max(sev, Severity.HIGH)
        if _REMOTE_EXEC.search(image):
            reasons.append("runs from a remote administrative share (remote-execution tool pattern)")
            sev = max(sev, Severity.HIGH)
            mitre += ["T1021.002", "T1569.002"]
        if name.upper() in ("PSEXESVC", "PAEXEC", "REMCOM_SVC", "CSEXECSVC"):
            reasons.append("PsExec-style remote execution service")
            sev = max(sev, Severity.MEDIUM)
            mitre += ["T1569.002", "T1021.002"]
        if is_driver:
            mitre += ["T1068"]
            if risk:
                reasons.append("a kernel driver loaded from a user-writable folder (BYOVD technique)")
                sev = max(sev, Severity.HIGH)
            known = match_known_driver(_base(exe)) if match_known_driver else None
            if known:
                reasons.append(f"known abusable driver: {known[0]}")
                sev = max(sev, Severity.MEDIUM)
        if sev <= Severity.INFO or not reasons:
            continue
        rem = None
        if sev >= Severity.MEDIUM and name:
            rem = Remediation("disable_service", {"name": name}, f"Stop and disable the service '{name}' (backed up first)")
        kind = "driver" if is_driver else "service"
        out.append(_finding(
            "AEG-EVT-SVCINSTALL", f"Suspicious new {kind} installed: {name or exe}", sev, Category.PERSISTENCE,
            f"A new Windows {kind} named '{name}' was installed at {fmt_time(ev['ts'])}"
            + (f" by {who}" if who and who != "unknown" else "") + f" running: {_clip(image, 200)}. "
            "Services start automatically with full privileges, which makes them a favourite way to stay on a PC "
            "(and to run code as SYSTEM). Flagged because " + "; ".join(dict.fromkeys(reasons)) + ".",
            ev, "If you did not install software that needs this service, disable it, delete its file and run a "
                "full scan. Legitimate installers use Program Files or System32, not Temp/AppData/Downloads.",
            {"service": name, "image_path": _clip(image, 800), "account": account, "installed_by": who,
             "reasons": list(dict.fromkeys(reasons)), "matched": [h[0] for h in hits]},
            sorted(set(mitre)), rem, what=name))
    return _top(out)


# =========================================================================== 5. scheduled tasks (4698)

_TASK_NS = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"


def parse_task_xml(xml: str) -> Dict[str, Any]:
    """Pull actions / principal / triggers out of a Task Scheduler definition. Never raises."""
    info: Dict[str, Any] = {"actions": [], "user": "", "run_level": "", "triggers": [], "hidden": False}
    if not xml or "<!DOCTYPE" in xml or "<!ENTITY" in xml:  # no DTDs / entity tricks from untrusted text
        return info
    try:
        root = ET.fromstring(xml)
    except (ET.ParseError, ValueError):
        return info
    for el in root.iter():
        t = _local(el.tag)
        if t == "Exec":
            cmd = args = wd = ""
            for c in el:
                ct = _local(c.tag)
                if ct == "Command":
                    cmd = (c.text or "").strip()
                elif ct == "Arguments":
                    args = (c.text or "").strip()
                elif ct == "WorkingDirectory":
                    wd = (c.text or "").strip()
            info["actions"].append({"command": cmd, "arguments": args, "workdir": wd})
        elif t == "Principal":
            for c in el:
                ct = _local(c.tag)
                if ct in ("UserId", "GroupId") and not info["user"]:
                    info["user"] = (c.text or "").strip()
                elif ct == "RunLevel":
                    info["run_level"] = (c.text or "").strip()
        elif t == "Hidden":
            info["hidden"] = (el.text or "").strip().lower() == "true"
        elif t.endswith("Trigger"):
            info["triggers"].append(t)
    return info


def detect_task_creations(events: Sequence[Dict[str, Any]]) -> List[Finding]:
    out: List[Finding] = []
    seen: set = set()
    for ev in _events(events, 4698, log="Security"):
        tname = _d(ev, "TaskName")
        info = parse_task_xml(_d(ev, "TaskContent"))
        for act in info["actions"] or [{"command": "", "arguments": "", "workdir": ""}]:
            cmd = (act["command"] + " " + act["arguments"]).strip()
            if not cmd:
                continue
            key = (tname.lower(), cmd.lower())
            if key in seen:
                continue
            seen.add(key)
            hits = _analyse_cmd(cmd)
            exe = _exe_of(cmd) or act["command"]
            risk = _path_risk(exe)
            sev = max((h[2] for h in hits), default=Severity.INFO)
            reasons = [h[1] for h in hits]
            mitre = ["T1053.005"] + [m for h in hits for m in h[3]]
            if risk:
                reasons.append("runs a program from a user-writable folder")
                sev = max(sev, Severity.MEDIUM if risk == 2 else Severity.LOW)
            if _SERVICE_INTERPRETER.search(cmd) and (info["run_level"] == "HighestAvailable" or info["user"].upper() in
                                                     ("S-1-5-18", "SYSTEM", "NT AUTHORITY\\SYSTEM")) and (risk or hits):
                reasons.append("runs an interpreter with the highest privileges")
                sev = max(sev, Severity.HIGH)
            if sev <= Severity.INFO:
                continue
            rem = Remediation("disable_task", {"name": tname}, f"Disable the scheduled task {tname} (exported to backups first)") \
                if tname and sev >= Severity.MEDIUM else None
            out.append(_finding(
                "AEG-EVT-TASKCREATE", f"Suspicious scheduled task created: {tname or '(unnamed)'}", sev,
                Category.PERSISTENCE,
                f"A scheduled task '{tname}' was created at {fmt_time(ev['ts'])} by {_who(ev)} to run: "
                f"{_clip(cmd, 250)}. Scheduled tasks re-run a program at logon, at a set time or at boot, so malware "
                "uses them to survive reboots. Flagged because " + "; ".join(dict.fromkeys(reasons)) + ".",
                ev, "If you did not create or install something that adds this task, disable and delete it, delete the "
                    "program it runs and scan the PC.",
                {"task": tname, "command": _clip(cmd, 800), "run_as": info["user"], "run_level": info["run_level"],
                 "triggers": info["triggers"], "hidden": info["hidden"], "created_by": _who(ev),
                 "reasons": list(dict.fromkeys(reasons)), "matched": [h[0] for h in hits]},
                sorted(set(mitre)), rem, what=tname))
    return _top(out)


# =========================================================================== 6. process creation (4688 / Sysmon 1)

_OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe", "onenote.exe",
           "visio.exe", "eqnedt32.exe", "acrord32.exe", "foxitreader.exe"}
_CHILD_SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
                 "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msbuild.exe", "installutil.exe", "wmic.exe",
                 "cmstp.exe", "forfiles.exe"}
_SERVER_PARENTS = {"w3wp.exe", "httpd.exe", "nginx.exe", "tomcat9.exe", "tomcat8.exe", "php-cgi.exe", "sqlservr.exe"}
_CHAIN_RULES: List[Tuple[set, set, Severity, str, List[str], str]] = [
    (_OFFICE, _CHILD_SHELLS, Severity.HIGH, "Document/e-mail program started a command shell or script engine",
     ["T1204.002", "T1059"], "Office documents and PDF readers do not normally launch shells. This is what a malicious macro or exploit does."),
    ({"wmiprvse.exe"}, {"cmd.exe", "powershell.exe", "pwsh.exe", "rundll32.exe", "mshta.exe", "wscript.exe", "cscript.exe"},
     Severity.HIGH, "Command started through WMI", ["T1047"], "Running commands via WMI is a common lateral-movement and fileless-malware technique."),
    (_SERVER_PARENTS, {"cmd.exe", "powershell.exe", "pwsh.exe", "whoami.exe", "net.exe", "net1.exe"}, Severity.HIGH,
     "Web/database server started a command shell", ["T1505.003", "T1190"], "A web or database server spawning a shell usually means a web shell or exploit."),
]


def _proc_fields(ev: Dict[str, Any]) -> Tuple[str, str, str, str, str]:
    """(image, command line, parent image, user, sha256/md5 string)"""
    if ev["log"] == "Security":
        return (_d(ev, "NewProcessName"), _d(ev, "CommandLine"), _d(ev, "ParentProcessName"), _who(ev), "")
    return (_d(ev, "Image"), _d(ev, "CommandLine"), _d(ev, "ParentImage"), _d(ev, "User"), _d(ev, "Hashes"))


def parse_hashes(text: str) -> Dict[str, str]:
    """Sysmon ``Hashes`` field (``SHA256=...,MD5=...``) -> {algorithm: lowercase hex}."""
    out: Dict[str, str] = {}
    for part in re.split(r"[,;]", text or ""):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().upper()] = v.strip().lower()
    return out


def detect_process_creation(events: Sequence[Dict[str, Any]], signatures: Any = None) -> List[Finding]:
    """4688 (needs command-line auditing) and Sysmon 1: LOLBin / attack command lines, bad parent->child
    chains, and (Sysmon) hashes of known malware."""
    out: List[Finding] = []
    seen: set = set()
    for ev in events:
        if not ((ev.get("id") == 4688 and ev.get("log") == "Security") or
                (ev.get("id") == 1 and ev.get("log") == "Sysmon")):
            continue
        image, cmd, parent, user, hashes = _proc_fields(ev)
        pbase, ibase = _base(parent), _base(image)
        reasons: List[str] = []
        mitre: List[str] = []
        sev = Severity.INFO
        matched: List[str] = []
        # known-malware hash (Sysmon only)
        threat = None
        if hashes and signatures is not None:
            h = parse_hashes(hashes)
            try:
                threat = signatures.lookup_hash(h.get("SHA256"), h.get("MD5"))
            except Exception:
                threat = None
        if threat:
            out.append(_finding(
                "AEG-EVT-PROC-KNOWN", f"Known malware was executed: {threat}", Severity.CRITICAL, Category.MALWARE,
                f"Sysmon recorded {image} starting at {fmt_time(ev['ts'])}, and its hash matches the malware sample "
                f"'{threat}' in the Aegis threat database.", ev,
                "Isolate the PC from the network, run a full scan, and change passwords from another device.",
                {"image": image, "command_line": _clip(cmd), "hashes": hashes, "user": user, "threat": threat},
                ["T1204"], what=ibase))
            continue
        for sets, kids, csev, ctitle, cmitre, cwhy in _CHAIN_RULES:
            if pbase in sets and ibase in kids:
                reasons.append(ctitle)
                sev = max(sev, csev)
                mitre += cmitre
                matched.append("chain:" + pbase + ">" + ibase)
        for rid, title, hsev, hmitre, snippet in _analyse_cmd(cmd):
            reasons.append(title)
            sev = max(sev, hsev)
            mitre += hmitre
            matched.append(rid)
        if sev <= Severity.INFO:
            continue
        key = (tuple(matched), cmd.lower()[:300])
        if key in seen:
            continue
        seen.add(key)
        out.append(_finding(
            "AEG-EVT-PROC", f"Suspicious command was run: {reasons[0]}", sev, Category.SUSPICIOUS,
            f"At {fmt_time(ev['ts'])} {ibase or 'a program'} was started"
            + (f" by {parent and _base(parent)}" if parent else "") + (f" as {user}" if user else "")
            + f" with the command line: {_clip(cmd, 250)}. Flagged because " + "; ".join(dict.fromkeys(reasons)) + ". "
            "Attack tools and malware scripts leave exactly these command lines behind.",
            ev, "If you or an administrator did not run this, treat it as a possible compromise: check the processes "
                "and persistence scans, change passwords from another device and run a full scan.",
            {"image": image, "parent": parent, "command_line": _clip(cmd, 1200), "user": user,
             "matched": matched, "reasons": list(dict.fromkeys(reasons))}, sorted(set(mitre)), what=ibase))
    return _top(out, 40)


# =========================================================================== 7. Microsoft Defender

_DEF_SEVERITY_ID = {"1": Severity.LOW, "2": Severity.MEDIUM, "4": Severity.HIGH, "5": Severity.HIGH}
_DEF_SEVERITY_NAME = {"1": "Low", "2": "Moderate", "4": "High", "5": "Severe"}
_DEF_ACTION_ALLOWED = {"6"}  # user / admin chose "Allow" for this threat


def _defender_path(raw: str) -> str:
    p = raw or ""
    p = re.sub(r"^(?:containerfile|file|webfile|process|regkey|amsi|behavior)[:_]+", "", p, flags=re.I)
    return p.split("->")[0].strip().strip("_")


_DEF_WEAKEN = re.compile(
    r"(?i)(\\Exclusions\\(?:Paths|Extensions|Processes|IpAddresses)\\[^=]+|DisableAntiSpyware|DisableAntiVirus|"
    r"DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableIOAVProtection|DisableOnAccessProtection|"
    r"DisableScanOnRealtimeEnable|DisableScriptScanning|DisableRoutinelyTakingAction|TamperProtection\s*=\s*(?:0x)?0\b|"
    r"SpynetReporting\s*=\s*(?:0x)?0\b|DisableBlockAtFirstSeen)")


def detect_defender_events(events: Sequence[Dict[str, Any]], av_products: Sequence[str] = ()) -> List[Finding]:
    out: List[Finding] = []
    defender = [e for e in events if e.get("log") == "Defender"]
    detections = _events(defender, 1116)
    actions = _events(defender, 1117)
    failures = _events(defender, 1118, 1119)

    def keys(ev: Dict[str, Any]) -> List[str]:
        ks = []
        if _d(ev, "Detection ID"):
            ks.append("d:" + _d(ev, "Detection ID").lower())
        ks.append("t:" + _d(ev, "Threat ID") + "|" + _defender_path(_d(ev, "Path")).lower())
        return ks

    resolved: Dict[str, Dict[str, Any]] = {}
    for a in actions:
        for k in keys(a):
            resolved[k] = a
    failed = set()
    for f in failures:
        failed.update(keys(f))
    emitted: set = set()
    for ev in detections:
        threat = _d(ev, "Threat Name") or "unknown threat"
        path = _defender_path(_d(ev, "Path"))
        sid = _d(ev, "Severity ID")
        action = next((resolved[k] for k in keys(ev) if k in resolved), None)
        is_failed = any(k in failed for k in keys(ev))
        allowed = bool(action and _d(action, "Action ID") in _DEF_ACTION_ALLOWED)
        sev_base = _DEF_SEVERITY_ID.get(sid, Severity.MEDIUM)
        if "eicar" in threat.lower():
            sev, state = Severity.INFO, "test file"
        elif allowed:
            sev, state = Severity.HIGH, "allowed to run"
        elif is_failed or action is None:
            sev, state = (Severity.HIGH if sev_base >= Severity.HIGH else Severity.MEDIUM), \
                ("could not be removed" if is_failed else "no clean-up recorded")
        else:
            sev, state = (Severity.MEDIUM if sev_base >= Severity.HIGH else Severity.LOW), "removed"
        dedupe = (threat, path.lower())
        if dedupe in emitted:
            continue
        emitted.add(dedupe)
        rem = None
        if sev >= Severity.HIGH and state != "removed" and path and re.match(r"^[A-Za-z]:\\", path) and os.path.isfile(path):
            rem = Remediation("quarantine_file", {"path": path}, "Move the file to Aegis quarantine")
        sevname = _DEF_SEVERITY_NAME.get(sid, "")
        out.append(_finding(
            "AEG-EVT-DEF-DETECT", f"Microsoft Defender detected {threat} ({state})", sev, Category.MALWARE,
            f"Microsoft Defender flagged {threat}" + (f" ({sevname} severity)" if sevname else "")
            + (f" in {path}" if path else "") + f" at {fmt_time(ev['ts'])}; outcome: {state}. "
            + ("Defender cleaned it up, but the file had to arrive somehow - the download, e-mail or USB drive it "
               "came from is worth identifying." if state == "removed" else
               "The threat may still be on the PC." if state != "test file" else "This is the harmless antivirus test file."),
            ev, ("Run a full scan and a Microsoft Defender Offline scan. " if state != "test file" else "")
                + ("If this was an information stealer or remote-access trojan, change your passwords from a clean device "
                   "and review browser extensions and saved sessions." if state != "test file" else
                   "Nothing to do - it only proves protection works."),
            {"threat": threat, "path": path, "severity_name": sevname, "outcome": state,
             "detected_user": _d(ev, "Detection User"), "process": _d(ev, "Process Name"),
             "category": _d(ev, "Category Name")}, ["T1204"], rem, location=path or f"defender:{threat}",
            what=threat))

    other_av = [a for a in av_products if a and "defender" not in a.lower() and "windows" not in a.lower()]
    for ev in _events(defender, 5001, 5010, 5012):
        what = {5001: "real-time protection", 5010: "scanning for malware and unwanted software",
                5012: "scanning for viruses"}[ev["id"]]
        sev = Severity.LOW if other_av else Severity.MEDIUM
        out.append(_finding(
            "AEG-EVT-DEF-OFF", f"Microsoft Defender {what} was turned off", sev, Category.SYSTEM,
            f"Microsoft Defender's {what} was disabled at {fmt_time(ev['ts'])}."
            + (f" You have another antivirus registered ({', '.join(other_av)}), which normally switches Defender off "
               "on purpose, so this is probably harmless." if other_av else
               " Nothing else is protecting this PC, and malware commonly switches antivirus off before it starts work."),
            ev, "Re-enable it in Windows Security > Virus & threat protection unless you deliberately installed other "
                "security software. If it keeps switching off, run a full scan.",
            {"protection": what, "other_antivirus": other_av}, ["T1685"], what=what))
    for ev in _events(defender, 5007):
        new, old = _d(ev, "New Value"), _d(ev, "Old Value")
        m = _DEF_WEAKEN.search(new)
        if not m:
            continue
        token = m.group(1)
        excl = "\\exclusions\\" in token.lower()
        what = "an exclusion was added" if excl else "a protection setting was weakened"
        out.append(_finding(
            "AEG-EVT-DEF-TAMPER",
            "Microsoft Defender exclusion added" if excl else "Microsoft Defender setting weakened",
            Severity.HIGH if not other_av else Severity.MEDIUM, Category.SYSTEM,
            f"At {fmt_time(ev['ts'])} Defender's configuration changed and {what}: {_clip(new, 250)}. "
            "Attackers add folders or programs to Defender's exclusion list so their malware is never scanned.",
            ev, "Open Windows Security > Virus & threat protection > Manage settings > Exclusions and remove anything "
                "you do not recognise; run a full scan.",
            {"new_value": _clip(new, 400), "old_value": _clip(old, 400)}, ["T1685"], what=_clip(token, 60)))
    return _top(out)


# =========================================================================== 8. PowerShell script blocks (4104)

def reassemble_script_blocks(events: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Join multi-part 4104 events by ScriptBlockId -> [{id, text, ts, level, path}]."""
    parts: Dict[str, Dict[str, Any]] = {}
    for ev in _events(events, 4104):
        bid = _d(ev, "ScriptBlockId") or f"anon-{id(ev)}"
        slot = parts.setdefault(bid, {"parts": {}, "ts": ev["ts"], "level": ev.get("level"), "path": _d(ev, "Path"),
                                      "ev": ev})
        try:
            num = int(_d(ev, "MessageNumber", default="1"))
        except ValueError:
            num = 1
        slot["parts"][num] = _d(ev, "ScriptBlockText")
    out = []
    for bid, slot in parts.items():
        text = "".join(slot["parts"][n] for n in sorted(slot["parts"]))
        out.append({"id": bid, "text": text, "ts": slot["ts"], "level": slot["level"], "path": slot["path"],
                    "ev": slot["ev"]})
    return out


def detect_powershell(events: Sequence[Dict[str, Any]]) -> List[Finding]:
    try:
        from aegis.core import fileanalysis as fa
    except Exception:  # pragma: no cover
        return []
    out: List[Finding] = []
    seen: set = set()
    for blk in reassemble_script_blocks([e for e in events if e.get("log") == "PowerShell"]):
        text = blk["text"]
        if len(text) < 20:
            continue
        digest = hashlib.sha1(text.encode("utf-8", "replace")).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        inds = [i for i in fa.content_indicators(text.encode("utf-8", "replace"), "script") if i.score > 0]
        if not inds:
            continue
        score = sum(i.score for i in inds)
        sev = max([i.severity for i in inds] + [fa.score_to_severity(score) or Severity.LOW])
        if sev < Severity.MEDIUM and score < 30:
            continue
        top = max(inds, key=lambda i: i.score)
        ev = blk["ev"]
        out.append(_finding(
            "AEG-EVT-PSBLOCK", f"Malicious-looking PowerShell was run: {top.title}", sev, Category.SUSPICIOUS,
            f"PowerShell script-block logging recorded code run at {fmt_time(blk['ts'])} that "
            + "; ".join(sorted({i.title.lower() for i in inds}))
            + ". Attackers use PowerShell because it is built into Windows and can run entirely in memory, so "
              "these logs are often the only trace left.",
            ev, "If you did not run this script (or an admin tool/installer you trust did), assume the PC is "
                "compromised: check the processes and persistence scans, change passwords from another device and "
                "run a full scan.",
            {"script_block_id": blk["id"], "script_path": blk["path"], "length": len(text), "powershell_flagged": blk["level"] == 3,
             "indicators": [{"id": i.rule_id, "title": i.title, "detail": _clip(i.detail, 160), "score": i.score} for i in inds],
             "excerpt": _clip(text.strip().replace("\r", ""), 400)},
            sorted({"T1059.001"} | {m for i in inds for m in i.mitre}), what=top.rule_id,
            location=f"PowerShell log, script block {blk['id']} at {fmt_time(blk['ts'])}"))
    return _top(out)


# =========================================================================== 9. WMI permanent subscriptions (5861)

_WMI_BENIGN = ("scm event log consumer", "scm event log filter", "bvtfilter", "bvtconsumer", "tslogonevents", "tslogonfilter")
_WMI_NAME = re.compile(r'Name\s*=\s*"([^"]+)"', re.I)


def detect_wmi_subscriptions(events: Sequence[Dict[str, Any]]) -> List[Finding]:
    out: List[Finding] = []
    for ev in _events(events, 5861, log="WMI"):
        consumer = _d(ev, "CONSUMER", "Consumer")
        filt = _d(ev, "ESS", "Ess")
        cause = _d(ev, "PossibleCause", default="Permanent")
        namespace = _d(ev, "Namespace")
        low = (consumer + " " + filt).lower()
        if any(b in low for b in _WMI_BENIGN):
            continue
        m = _WMI_NAME.search(consumer)
        cname = m.group(1) if m else ""
        active = "commandlineeventconsumer" in consumer.lower() or "activescripteventconsumer" in consumer.lower()
        kind = consumer.split(".")[0] if "." in consumer else (consumer[:40] or "unknown consumer")
        out.append(_finding(
            "AEG-EVT-WMISUB", f"Permanent WMI event subscription created ({kind})",
            Severity.HIGH if active else Severity.MEDIUM, Category.PERSISTENCE,
            f"A permanent WMI event subscription was registered at {fmt_time(ev['ts'])} in {namespace or 'root/subscription'}: "
            f"when '{_clip(filt, 160)}' happens, Windows runs {kind}{' ' + repr(cname) if cname else ''}. "
            "Permanent WMI subscriptions run code without any file in a startup folder or registry Run key, which is "
            "why fileless malware (and some legitimate management software) uses them.",
            ev, "If you do not use software that registers WMI subscriptions (some monitoring and management agents "
                "do), remove it: the persistence scan lists the live subscription and can remove it.",
            {"consumer": _clip(consumer, 400), "filter": _clip(filt, 400), "namespace": namespace, "type": cause,
             "consumer_name": cname}, ["T1546.003"],
            Remediation("remove_wmi_subscription", {"name": cname}, f"Remove the WMI subscription '{cname}'")
            if cname and active else None, what=cname or kind))
    return _top(out)


# =========================================================================== 10. audit-policy tampering (4719)

def detect_audit_policy_changes(events: Sequence[Dict[str, Any]]) -> List[Finding]:
    out: List[Finding] = []
    for ev in _events(events, 4719, log="Security"):
        if _is_system_actor(ev):
            continue  # policy refresh by SYSTEM / group policy
        out.append(_finding(
            "AEG-EVT-AUDITPOL", "Windows audit policy was changed", Severity.LOW, Category.SYSTEM,
            f"{_who(ev)} changed the system audit policy at {fmt_time(ev['ts'])}. Switching auditing off is a way for an "
            "intruder to stop Windows recording what they do.", ev,
            "If you or your IT team did not change auditing, review the other findings from around that time.",
            {"changed_by": _who(ev), "subcategory_guid": _d(ev, "SubcategoryGuid"),
             "changes": _d(ev, "AuditPolicyChanges")}, ["T1685.001"], what="audit policy"))
    return _top(out, 10)


# =========================================================================== 11. Sysmon (only if installed)

_NET_LOLBINS = {"mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe", "wscript.exe", "cscript.exe", "msbuild.exe",
                "installutil.exe", "regasm.exe", "regsvcs.exe", "odbcconf.exe", "cmstp.exe", "hh.exe", "wmic.exe",
                "msiexec.exe", "mavinject.exe"}
_SYSTEM_PROCS = {"svchost.exe", "explorer.exe", "winlogon.exe", "services.exe", "spoolsv.exe", "lsass.exe", "csrss.exe",
                 "dwm.exe", "taskhostw.exe", "runtimebroker.exe", "searchindexer.exe"}
_DROP_EXTS = {"exe", "dll", "scr", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "hta", "wsf", "jar", "cpl", "msi", "lnk", "com", "pif"}
_SCRIPT_DROP = {"exe", "dll", "scr", "vbs", "vbe", "js", "jse", "hta", "wsf", "ps1", "bat", "cmd", "jar", "cpl", "com", "pif"}


def detect_sysmon(events: Sequence[Dict[str, Any]], signatures: Any = None) -> List[Finding]:
    sysmon = [e for e in events if e.get("log") == "Sysmon"]
    if not sysmon:
        return []
    try:
        from aegis.scanners.sideload import system_dll_names  # sibling module, optional
        sysdlls = system_dll_names()
    except Exception:  # pragma: no cover
        sysdlls = set()
    out: List[Finding] = []
    out += detect_process_creation(sysmon, signatures)
    seen: set = set()

    def bad_ip(ip: str) -> bool:
        try:
            return bool(signatures and ip and signatures.is_bad_ip(ip))
        except Exception:
            return False

    for ev in _events(sysmon, 3):
        image, dest = _d(ev, "Image"), _d(ev, "DestinationIp")
        if _d(ev, "Initiated").lower() == "false" or classify_ip(dest) != "external":
            continue
        ibase = _base(image)
        key = ("net", ibase, dest)
        if key in seen:
            continue
        bad = bad_ip(dest)
        risk = _path_risk(image)
        if bad:
            sev, why = Severity.HIGH, "the destination is on a known-malicious IP list"
        elif ibase in _NET_LOLBINS:
            sev, why = Severity.MEDIUM, f"{ibase} is a Windows tool that attackers use to download and run payloads"
        elif risk == 2:
            sev, why = Severity.LOW, "the program runs from a temporary/download folder"
        else:
            continue
        seen.add(key)
        out.append(_finding(
            "AEG-EVT-SYSMON-NET", f"{ibase or 'A program'} connected to {dest}", sev, Category.NETWORK,
            f"Sysmon recorded {image} opening a connection to {dest}:{_d(ev, 'DestinationPort')} "
            f"({_d(ev, 'DestinationHostname') or 'no host name'}) at {fmt_time(ev['ts'])}; flagged because {why}.",
            ev, "Check whether you know the program. Run the network and processes scans for more context.",
            {"image": image, "destination": dest, "port": _d(ev, "DestinationPort"),
             "host": _d(ev, "DestinationHostname"), "user": _d(ev, "User"), "known_bad_ip": bad},
            ["T1071", "T1218"] if ibase in _NET_LOLBINS else ["T1071"], what=f"{ibase}->{dest}"))

    for ev in _events(sysmon, 7):
        image, loaded = _d(ev, "Image"), _d(ev, "ImageLoaded")
        lbase = _base(loaded)
        if _d(ev, "Signed").lower() != "false":
            continue
        risk = _path_risk(loaded)
        sysname = lbase in sysdlls
        outside = not re.search(r"(?i)\\windows\\(?:system32|syswow64|winsxs)\\", loaded)
        key = ("dll", lbase, loaded.lower())
        if key in seen:
            continue
        if sysname and outside and risk:
            sev, why = Severity.MEDIUM, f"an unsigned DLL named like the Windows file {lbase} was loaded from {loaded.rsplit(chr(92), 1)[0]}"
        elif risk == 2 and _base(image) in _SYSTEM_PROCS:
            sev, why = Severity.MEDIUM, "a Windows system process loaded an unsigned DLL from a temporary/download folder"
        else:
            continue
        seen.add(key)
        out.append(_finding(
            "AEG-EVT-SYSMON-DLL", f"Unsigned DLL loaded from an unusual place: {lbase}", sev, Category.SUSPICIOUS,
            f"Sysmon recorded {image} loading {loaded} at {fmt_time(ev['ts'])} - {why}. Attackers plant a DLL "
            "with a familiar name next to a trusted program so Windows loads theirs instead (DLL side-loading).",
            ev, "Run the 'sideload' scan and check where the DLL came from; quarantine it if unexpected.",
            {"image": image, "image_loaded": loaded, "signature": _d(ev, "Signature"),
             "hashes": _d(ev, "Hashes")}, ["T1574.001"], what=lbase))

    for ev in _events(sysmon, 11):
        image, target = _d(ev, "Image"), _d(ev, "TargetFilename")
        ext = target.rsplit(".", 1)[-1].lower() if "." in _base(target) else ""
        if ext not in _DROP_EXTS:
            continue
        ibase = _base(image)
        low = target.lower()
        key = ("file", low)
        if key in seen:
            continue
        sev, why, mitre = Severity.INFO, "", ["T1105"]
        if "\\start menu\\programs\\startup\\" in low:
            sev, why, mitre = Severity.MEDIUM, "it was placed in a Windows Startup folder so it runs at every logon", ["T1547.001"]
        elif ibase in _OFFICE and ext in _SCRIPT_DROP and _path_risk(target):
            sev, why, mitre = Severity.HIGH, f"{ibase} dropped an executable/script - what a malicious document does", ["T1204.002", "T1566.001"]
        elif ibase in ("mshta.exe", "wscript.exe", "cscript.exe", "certutil.exe", "bitsadmin.exe", "powershell.exe",
                       "pwsh.exe") and ext in ("exe", "dll", "scr", "cpl") and _path_risk(target) == 2:
            sev, why = Severity.MEDIUM, f"{ibase} wrote an executable into a temporary/download folder"
        if sev <= Severity.INFO:
            continue
        seen.add(key)
        out.append(_finding(
            "AEG-EVT-SYSMON-DROP", f"{ibase or 'A program'} created {_base(target)}", sev, Category.SUSPICIOUS,
            f"Sysmon recorded {image} creating {target} at {fmt_time(ev['ts'])}; flagged because {why}.",
            ev, "If the file still exists, scan it (Aegis 'files' scan) and delete it unless you know why it is there.",
            {"image": image, "target": target}, mitre, what=_base(target)))
    return _top(out, 40)


# =========================================================================== orchestration

def analyse_all(logs: Dict[str, Sequence[Dict[str, Any]]], signatures: Any = None,
                av_products: Sequence[str] = ()) -> List[Finding]:
    """Run every detector over events grouped by LogSpec.key (pure; used by the scanner and the tests)."""
    sec = list(logs.get("security", []))
    syslog = list(logs.get("system", []))
    out: List[Finding] = []
    out += detect_log_cleared(sec + syslog)
    out += detect_account_changes(sec)
    out += detect_logon_attacks(sec, signatures)
    out += detect_service_installs(sec + syslog)
    out += detect_task_creations(sec)
    out += detect_process_creation(sec, signatures)
    out += detect_audit_policy_changes(sec)
    out += detect_defender_events(list(logs.get("defender", [])), av_products)
    out += detect_powershell(list(logs.get("powershell", [])))
    out += detect_wmi_subscriptions(list(logs.get("wmi", [])))
    out += detect_sysmon(list(logs.get("sysmon", [])), signatures)
    return out


# --------------------------------------------------------------------------- audit / logging visibility

_AUDIT_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
_SBL_KEY = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
_MODLOG_KEY = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
# subcategory GUID "Process Creation" - locale independent
_PROC_AUDIT_FIX = ["auditpol", "/set", "/subcategory:{0CCE922B-69AE-11D9-BED3-505054503030}", "/success:enable"]


def _reg_on(hive: str, key: str, value: str) -> Optional[bool]:
    try:
        v = reg_read(hive, key, value)
    except Exception:
        return None
    if v is None:
        return None
    try:
        return int(v) == 1
    except (TypeError, ValueError):
        return None


def visibility_checks(proc_events_seen: Optional[bool], security_log_readable: bool,
                      info: Optional[Dict[str, Any]] = None, now: Optional[float] = None
                      ) -> Tuple[List[CheckResult], List[Finding]]:
    """Which telemetry is missing? ``proc_events_seen`` is None when the Security log could not be read."""
    checks: List[CheckResult] = []
    findings: List[Finding] = []

    def gap(check_id: str, title: str, detail: str, rule: str, ftitle: str, fdesc: str, rec: str,
            rem: Optional[Remediation], mitre: Optional[List[str]] = None, sev: Severity = Severity.INFO) -> None:
        checks.append(CheckResult(check_id, title, CheckStatus.WARN, detail, Category.SYSTEM))
        findings.append(Finding(rule, ftitle, sev, Category.SYSTEM, fdesc, "Windows audit policy",
                                {"source": "eventlog"}, rec, rem, mitre=mitre or ["T1685.001"]))

    # process-creation auditing (4688)
    if proc_events_seen is None:
        checks.append(CheckResult("AEG-EVT-AUDIT-PROC", "Process-creation auditing (event 4688)", CheckStatus.SKIP,
                                  "The Security log could not be read (run Aegis as Administrator).", Category.SYSTEM))
    elif proc_events_seen:
        checks.append(CheckResult("AEG-EVT-AUDIT-PROC", "Process-creation auditing (event 4688)", CheckStatus.PASS,
                                  "Windows is recording every program that starts.", Category.SYSTEM))
    else:
        gap("AEG-EVT-AUDIT-PROC", "Process-creation auditing (event 4688)",
            "Windows is NOT recording which programs start, so Aegis cannot review past commands.",
            "AEG-EVT-AUDIT-PROC", "Process-creation auditing is off",
            "Windows is not logging program launches (event 4688). Without it, there is no after-the-fact record of "
            "which programs and commands ran, which is the single most useful source for investigating an infection.",
            "Turn on 'Audit Process Creation' (Success). The fix below does that; it adds modest log volume.",
            Remediation("run_command", {"command": list(_PROC_AUDIT_FIX)},
                        "Enable 'Audit Process Creation' (Success) with auditpol"))
    # command line in 4688
    cmd_on = _reg_on("HKLM", _AUDIT_KEY, "ProcessCreationIncludeCmdLine_Enabled")
    if cmd_on:
        checks.append(CheckResult("AEG-EVT-AUDIT-CMDLINE", "Command lines in process-creation events", CheckStatus.PASS,
                                  "Command lines are included in event 4688.", Category.SYSTEM))
    else:
        gap("AEG-EVT-AUDIT-CMDLINE", "Command lines in process-creation events",
            "Event 4688 does not include command lines, so malicious arguments are invisible.",
            "AEG-EVT-AUDIT-CMDLINE", "Command lines are not recorded in process-creation events",
            "Even with process auditing on, Windows omits the command line unless 'Include command line in process "
            "creation events' is enabled. The program name alone rarely reveals an attack (powershell.exe is "
            "normal; its arguments are not).",
            "Enable 'Include command line in process creation events' (Group Policy > Administrative Templates > "
            "System > Audit Process Creation). The fix below sets that policy.",
            Remediation("set_registry_value", {"hive": "HKLM", "key": _AUDIT_KEY,
                                               "value": "ProcessCreationIncludeCmdLine_Enabled", "data": 1},
                        "Include command lines in process-creation events"))
    # PowerShell script block logging
    sbl = _reg_on("HKLM", _SBL_KEY, "EnableScriptBlockLogging")
    if sbl is None:
        sbl = _reg_on("HKCU", _SBL_KEY, "EnableScriptBlockLogging")
    if sbl:
        checks.append(CheckResult("AEG-EVT-AUDIT-PSLOG", "PowerShell script-block logging", CheckStatus.PASS,
                                  "PowerShell script blocks are logged (event 4104).", Category.SYSTEM))
    else:
        gap("AEG-EVT-AUDIT-PSLOG", "PowerShell script-block logging",
            "PowerShell script-block logging is off; only PowerShell's own 'suspicious' warnings are recorded.",
            "AEG-EVT-AUDIT-PSLOG", "PowerShell script-block logging is off",
            "PowerShell is the most abused built-in Windows tool. Script-block logging records the code that actually "
            "runs - even when it was obfuscated or downloaded straight into memory - and is the best way to see what "
            "an attacker ran.",
            "Turn on 'Script Block Logging' (Group Policy > Administrative Templates > Windows Components > Windows "
            "PowerShell). The fix below sets that policy; logging is lightweight.",
            Remediation("set_registry_value", {"hive": "HKLM", "key": _SBL_KEY, "value": "EnableScriptBlockLogging", "data": 1},
                        "Enable PowerShell script-block logging"))
    mod = _reg_on("HKLM", _MODLOG_KEY, "EnableModuleLogging")
    checks.append(CheckResult("AEG-EVT-AUDIT-MODLOG", "PowerShell module logging",
                              CheckStatus.PASS if mod else CheckStatus.WARN,
                              "PowerShell module logging is enabled." if mod else
                              "PowerShell module logging is off (optional extra; script-block logging matters more).",
                              Category.SYSTEM))
    # Security log history
    if info and security_log_readable:
        oldest = parse_time(info.get("Oldest"))
        now = now if now is not None else dt.datetime.now(dt.timezone.utc).timestamp()
        try:
            maxb, fileb = float(info.get("MaxBytes") or 0), float(info.get("FileBytes") or 0)
        except (TypeError, ValueError):
            maxb = fileb = 0.0
        if oldest:
            days = max(0.0, (now - oldest) / 86400)
            wrapped = maxb > 0 and fileb >= 0.95 * maxb
            if wrapped and days < 7:
                checks.append(CheckResult(
                    "AEG-EVT-LOGSIZE", "Security log history", CheckStatus.WARN,
                    f"The Security log only goes back {days:.1f} day(s) and is full, so older evidence is overwritten "
                    f"(size limit {maxb / 1048576:.0f} MB).", Category.SYSTEM))
                findings.append(Finding(
                    "AEG-EVT-LOGSIZE", "Security event log is too small to keep a week of history", Severity.INFO,
                    Category.SYSTEM,
                    f"The Security log is full and only reaches back {days:.1f} day(s). Attack evidence older than that "
                    "is overwritten before anyone looks.", "Windows Security log",
                    {"source": "eventlog", "history_days": round(days, 1), "max_size_mb": round(maxb / 1048576)},
                    "Increase the Security log size to at least 256 MB (Event Viewer > Windows Logs > Security > "
                    "Properties > Maximum log size).",
                    Remediation("run_command", {"command": ["wevtutil", "sl", "Security", "/ms:268435456"]},
                                "Set the Security log maximum size to 256 MB"), mitre=["T1685.005"]))
            else:
                checks.append(CheckResult("AEG-EVT-LOGSIZE", "Security log history", CheckStatus.PASS,
                                          f"The Security log covers {days:.1f} day(s).", Category.SYSTEM))
    return checks, findings


# --------------------------------------------------------------------------- collection

@dataclass
class LogData:
    spec: LogSpec
    events: List[Dict[str, Any]]
    ok: bool = True
    problem: str = ""  # '' | 'no_access' | 'missing' | 'error'
    info: Optional[Dict[str, Any]] = None
    av: Optional[List[str]] = None


def classify_errors(errors: Sequence[str]) -> str:
    """Map PowerShell exception names / FullyQualifiedErrorIds to '', 'no_access', 'missing' or 'error'."""
    worst = ""
    for e in errors:
        low = str(e).lower()
        if "nomatchingevents" in low:
            continue
        if "unauthorized" in low or "accessdenied" in low or "access is denied" in low:
            return "no_access"
        if "nomatchinglogs" in low or "notfound" in low or "eventlognotfound" in low:
            worst = worst or "missing"
        elif low.startswith("list|") and not worst:
            worst = "missing"
        else:
            worst = "error"
    return worst


def collect_log(spec: LogSpec, days: int = LOOKBACK_DAYS) -> LogData:
    """Run the batched query for one log and normalise the result. Never raises."""
    try:
        data = powershell_json(build_query_script(spec, days), timeout=spec.timeout)
    except Exception as exc:  # pragma: no cover - defensive
        log.debug("event query for %s failed: %s", spec.name, exc)
        data = None
    if not isinstance(data, dict):
        return LogData(spec, [], False, "error")
    events = [e for e in (normalize_record(r, _CHANNEL_KEY.get(spec.key, spec.name))
                          for r in as_list(data.get("Events"))) if e]
    errors = [str(x) for x in as_list(data.get("Errors"))]
    info = data.get("Info") if isinstance(data.get("Info"), dict) else None
    problem = classify_errors(errors)
    if events:
        problem = ""
    elif info and info.get("Enabled") is False and not problem:
        problem = "missing"
    return LogData(spec, events, not problem, problem, info, [str(a) for a in as_list(data.get("Av")) if a])


# detectors address events by a short channel key rather than the long LogName
_CHANNEL_KEY = {"security": "Security", "system": "System", "defender": "Defender", "powershell": "PowerShell",
                "wmi": "WMI", "sysmon": "Sysmon"}


def _read_check(ld: LogData, n_events: int) -> CheckResult:
    spec = ld.spec
    cid = f"AEG-EVT-LOG-{spec.key.upper()}"
    title = f"Event log hunt: {spec.name}"
    if ld.problem == "no_access":
        return CheckResult(cid, title, CheckStatus.SKIP,
                           "Access denied - run Aegis as Administrator to review this log.", Category.SUSPICIOUS)
    if ld.problem == "missing":
        why = "Sysmon is not installed." if spec.optional else "The log does not exist or is disabled."
        return CheckResult(cid, title, CheckStatus.SKIP, why, Category.SUSPICIOUS)
    if ld.problem:
        return CheckResult(cid, title, CheckStatus.ERROR, "The event log could not be read.", Category.SUSPICIOUS)
    return CheckResult(cid, title, CheckStatus.PASS,
                       f"Reviewed {n_events} relevant event(s) from the last {LOOKBACK_DAYS} days.", Category.SUSPICIOUS)


@register
class EventLogScanner(Scanner):
    name = "eventlog"
    title = "Event log threat hunting"
    description = ("Hunts the last 14 days of Windows event logs: cleared logs, new admin accounts, password-guessing "
                   "that succeeded, new services/tasks, Defender detections, malicious PowerShell, WMI persistence.")
    platforms = ("windows",)
    needs_admin_for_full_results = True

    def run(self, ctx: ScanContext) -> Iterator[Emitted]:
        if not IS_WINDOWS:
            yield CheckResult("AEG-EVT-ENV", "Event log hunting", CheckStatus.SKIP,
                              "Windows event logs are only available on Windows.", Category.SUSPICIOUS)
            return
        days = int(ctx.options.get("eventlog_days", LOOKBACK_DAYS) or LOOKBACK_DAYS)
        budget = float(ctx.options.get("eventlog_budget_s", 600) or 600)  # all logs together; each query also has its own timeout
        started = time.monotonic()
        logs: Dict[str, List[Dict[str, Any]]] = {}
        datas: Dict[str, LogData] = {}
        for spec in LOG_SPECS:
            if ctx.cancelled:
                return
            if spec.admin_only and not ctx.is_admin:
                ld = LogData(spec, [], False, "no_access")
            elif time.monotonic() - started > budget:
                ld = LogData(spec, [], False, "error")
                log.warning("event log budget exhausted, skipping %s", spec.name)
            else:
                ctx.report(self.name, f"reading the {spec.name} log")
                try:
                    ld = collect_log(spec, days)
                except Exception as exc:  # pragma: no cover - defensive
                    log.warning("event log %s failed: %s", spec.name, exc)
                    ld = LogData(spec, [], False, "error")
            datas[spec.key] = ld
            logs[spec.key] = ld.events
            ctx.bump("eventlog_events", len(ld.events))
            yield _read_check(ld, len(ld.events))
        try:
            findings = analyse_all(logs, ctx.signatures, datas["defender"].av or [])
        except Exception as exc:  # pragma: no cover - defensive
            log.warning("event analysis failed: %s", exc, exc_info=True)
            yield CheckResult("AEG-EVT-ANALYSE", "Event log analysis", CheckStatus.ERROR,
                              f"{type(exc).__name__}: {exc}", Category.SUSPICIOUS)
            findings = []
        for f in findings:
            if ctx.cancelled:
                return
            yield f
        sec = datas["security"]
        proc_seen: Optional[bool] = None
        if sec.ok and not sec.problem:
            proc_seen = any(e["id"] == 4688 for e in sec.events)
        try:
            checks, gaps = visibility_checks(proc_seen, sec.ok, sec.info)
        except Exception as exc:  # pragma: no cover - defensive
            yield CheckResult("AEG-EVT-AUDIT", "Audit policy review", CheckStatus.ERROR, f"{type(exc).__name__}: {exc}",
                              Category.SYSTEM)
            return
        yield from checks
        yield from gaps
        sm = datas["sysmon"]
        if sm.problem == "missing":
            yield CheckResult("AEG-EVT-SYSMON", "Sysmon (deep process/network telemetry)", CheckStatus.SKIP,
                              "Not installed. Microsoft Sysinternals Sysmon with a community config adds detailed "
                              "process, network and file telemetry that this hunt can use.", Category.SYSTEM)
