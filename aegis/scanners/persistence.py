"""Persistence scanner - an Autoruns-style inventory with suspicion analysis.

``collect_entries()`` returns every autostart entry as a plain dict
``{"type","location","name","command","path","enabled", "meta"}`` (used by
``aegis persistence --list`` and the real-time persistence-diff monitor).
``assess_entry()`` decides - purely from the entry - why it is suspicious, so
decisions are unit-testable on any OS. The scanner only *reports* suspicious
entries (plus scan_file hits on their targets).

Windows: Run/RunOnce keys, Winlogon, IFEO/SilentProcessExit, accessibility
backdoors, AppInit/AppCert DLLs, LSA packages, BootExecute, Startup folders,
scheduled tasks (XML) and tasks hidden from Task Scheduler (TaskCache entries
without a security descriptor), services & drivers, WMI event subscriptions,
COM hijacks, Office add-ins, Active Setup, logon scripts, screensavers.
Linux/macOS: cron, systemd, rc.local, shell rc files, ld.so.preload, ssh keys,
udev, XDG autostart, launchd, PAM rules and modules, update-motd scripts, systemd
generators and at jobs; macOS also periodic scripts, emond rules, authorization
plugins, login/logout hooks and the login items of Background Task Management
(``sfltool dumpbtm``, root only). On macOS the code signature of every launch agent,
daemon and login item program outside the system folders is checked with ``codesign``.
"""

from __future__ import annotations

import functools
import hashlib
import itertools
import logging
import os
import platform
import plistlib
import posixpath
import re
import shutil
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import unquote

from aegis.core import cmdline as cl
from aegis.core.models import Category, CheckResult, CheckStatus, Finding, Remediation, Severity
from aegis.core.platform import (IS_MAC, IS_WINDOWS, as_list, is_admin, powershell_json, reg_read, reg_subkeys,
                                 reg_values, run, user_home, windows_dir)
from aegis.scanners.base import ScanContext, Scanner, register

log = logging.getLogger("aegis.persistence")

MAX_TEXT = 128 * 1024
MAX_SCANNED_TARGETS = 300
MAX_SCANNED_TARGETS_DEEP = 800

Entry = Dict[str, Any]


def make_entry(type_: str, location: str, name: str, command: str, path: Optional[str] = None, enabled: bool = True,
               **meta: Any) -> Entry:
    """*path* None = derive it from the command line; "" = deliberately no target."""
    if path is None:
        path = (cl.extract_executable(command) or "") if command else ''
    return {"type": type_, "location": location, "name": name, "command": command, "path": path,
            "enabled": enabled, "meta": meta}


def entry_key(e: Entry) -> Tuple[str, str, str, str]:
    """Identity of an entry for diffing (type, location, name, command)."""
    return (e["type"], e["location"].lower(), e["name"].lower(), e["command"])


def diff_entries(old: Iterable[Entry], new: Iterable[Entry]) -> Tuple[List[Entry], List[Entry]]:
    """(added, removed) between two inventories - used by the real-time monitor."""
    o = {entry_key(e): e for e in old}
    n = {entry_key(e): e for e in new}
    return [n[k] for k in n if k not in o], [o[k] for k in o if k not in n]


# --------------------------------------------------------------------------- heuristics

_GUID_RE = re.compile(r"\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?")
_VOWELS = set("aeiouy")


def looks_random(name: str) -> bool:
    """Heuristic for machine-generated names (hex blobs, consonant soup, digit/letter salad)."""
    core = re.sub(r"\.[A-Za-z0-9]{1,4}$", "", name.strip())
    core = _GUID_RE.sub("", core)
    core = re.sub(r"S-1-5-21-[\d-]+", "", core)
    core = re.sub(r"[\s_\-.{}()]", "", core)
    if len(core) < 6:
        return False
    low = core.lower()
    if re.fullmatch(r"[0-9a-f]{8,}", low) and re.search(r"\d", low) and re.search(r"[a-f]", low):
        return True
    letters = [c for c in low if c.isalpha()]
    if len(letters) >= 7:
        vowels = sum(c in _VOWELS for c in letters)
        ratio = vowels / len(letters)
        run = best = 0
        for c in low:
            if c.isalpha() and c not in _VOWELS:
                run += 1
                best = max(best, run)
            else:
                run = 0
        # Windows' own names are vowel-poor abbreviations (dnsrslvr, appmgmts, wmpnscfg), so
        # consonant soup alone needs a long name; callers also skip Windows/Program Files targets.
        if len(letters) >= 10 and (ratio < 0.10 or (ratio < 0.20 and best >= 6)):
            return True
    if len(low) >= 8:
        trans = sum(1 for a, b in zip(low, low[1:]) if a.isdigit() != b.isdigit())
        if trans >= 5:
            return True
    return False


def startup_approved_enabled(data: Any) -> bool:
    """StartupApproved binary value: first byte 0x02/0x06 = enabled, 0x03/0x07 = disabled."""
    if isinstance(data, (bytes, bytearray)) and data:
        return data[0] % 2 == 0
    return True


# --------------------------------------------------------------------------- reasons

@dataclass
class Reason:
    severity: Severity
    text: str
    kind: str = "meta"  # cmd | location | missing | random | script | scan | signature | meta | modifier
    mitre: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"severity": self.severity.name.lower(), "text": self.text, "kind": self.kind, "mitre": self.mitre}


def _meta_reasons(e: Entry) -> List[Reason]:
    out = []
    for r in e.get("meta", {}).get("reasons", []):
        out.append(Reason(Severity.parse(r["severity"]), r["text"], r.get("kind", "meta"), list(r.get("mitre", []))))
    return out


def meta_reason(severity: Severity, text: str, mitre: Optional[List[str]] = None, kind: str = "meta") -> Dict[str, Any]:
    return {"severity": severity.name, "text": text, "mitre": mitre or [], "kind": kind}


# --------------------------------------------------------------------------- target resolution

def _search_dirs() -> List[str]:
    w = str(windows_dir()) if IS_WINDOWS else r"C:\Windows"
    dirs = [w + r"\System32", w, w + r"\SysWOW64"]
    dirs += [d for d in os.environ.get("PATH", "").split(os.pathsep) if d]
    return dirs


def target_exists(path: str) -> bool:
    """Does the autostart target exist? Resolves bare names against System32/PATH."""
    if not path:
        return True
    p = cl.clean_path(path)
    try:
        if os.path.exists(p):
            return True
        if "\\" not in p and "/" not in p:
            names = [p] if os.path.splitext(p)[1] else [p, p + ".exe", p + ".dll"]
            return any(os.path.exists(os.path.join(d, n)) for d in _search_dirs() for n in names)
    except OSError:
        return True
    return False


def _is_unc_or_unknown(path: str) -> bool:
    return path.startswith("\\\\") or "%" in path or "$" in path or not path.strip()


_INTERPRETERS = {"wscript", "cscript", "mshta", "powershell", "pwsh", "cmd", "rundll32", "regsvr32", "python", "python3",
                 "pythonw", "node", "perl", "ruby", "bash", "sh", "zsh", "dash", "osascript", "java"}


def _stem(path: str) -> str:
    b = cl.basename(path).lower()
    return b[:-4] if b.endswith(".exe") else b


def is_os_path(path: str) -> bool:
    if cl.is_windows_style(path):
        return cl.is_in_windir(path)
    return path.startswith(("/usr/", "/bin/", "/sbin/", "/lib", "/System/", "/snap/", "/opt/microsoft/"))


# macOS folders only Apple writes to (sealed system volume, SIP): programs there are not code-signature checked or judged by name
MAC_SYSTEM_DIRS = ("/System/", "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/libexec/")
# where a normal user (or a process running as one) can drop a program
_MAC_USER_WRITABLE = re.compile(r"^(?:~/Library/|/Users/[^/]+/Library/|/Users/Shared/|/tmp/|/private/tmp/|/var/tmp/|"
                                r"/private/var/tmp/|/var/folders/|/private/var/folders/)")


def mac_user_writable(path: str) -> bool:
    return bool(_MAC_USER_WRITABLE.match(path.strip().strip('"')))


# --------------------------------------------------------------------------- assessment

TYPE_INFO: Dict[str, Tuple[str, str, List[str]]] = {
    # type: (rule id, label, MITRE)
    "registry_run": ("AEG-PERS-RUN", "Registry autorun entry", ["T1547.001"]),
    "winlogon": ("AEG-PERS-WINLOGON", "Winlogon autostart value", ["T1547.004"]),
    "ifeo": ("AEG-PERS-IFEO", "Image File Execution Options hijack", ["T1546.012"]),
    "silentprocessexit": ("AEG-PERS-IFEO", "SilentProcessExit monitor", ["T1546.012"]),
    "accessibility": ("AEG-PERS-ACCESS", "Accessibility-feature backdoor", ["T1546.008"]),
    "appinit": ("AEG-PERS-APPINIT", "AppInit_DLLs injection", ["T1546.010"]),
    "appcert": ("AEG-PERS-APPCERT", "AppCertDlls injection", ["T1546.009"]),
    "lsa": ("AEG-PERS-LSA", "LSA package", ["T1547.002", "T1547.005"]),
    "bootexecute": ("AEG-PERS-BOOTEXEC", "Session Manager boot-time execution", ["T1547.001"]),
    "startup_folder": ("AEG-PERS-STARTUP", "Startup folder item", ["T1547.001"]),
    "scheduled_task": ("AEG-PERS-TASK", "Scheduled task", ["T1053.005"]),
    "service": ("AEG-PERS-SERVICE", "Service/driver", ["T1543.003"]),
    "wmi_subscription": ("AEG-PERS-WMI", "WMI event subscription", ["T1546.003"]),
    "com_hijack": ("AEG-PERS-COM", "COM object hijack", ["T1546.015"]),
    "office_addin": ("AEG-PERS-OFFICE", "Office add-in / startup file", ["T1137"]),
    "active_setup": ("AEG-PERS-ACTIVESETUP", "Active Setup StubPath", ["T1547.014"]),
    "logon_script": ("AEG-PERS-LOGONSCRIPT", "Logon script", ["T1037.001"]),
    "cmd_autorun": ("AEG-PERS-CMDAUTORUN", "Command Processor AutoRun", ["T1546"]),
    "screensaver": ("AEG-PERS-SCREENSAVER", "Screensaver program", ["T1546.002"]),
    "dll_hook": ("AEG-PERS-DLLHOOK", "System DLL hook (netsh/time provider/print monitor)", ["T1546.007", "T1547.003", "T1547.010"]),
    "cron": ("AEG-PERS-CRON", "Cron job", ["T1053.003"]),
    "cron_script": ("AEG-PERS-CRON", "Cron script", ["T1053.003"]),
    "systemd": ("AEG-PERS-SYSTEMD", "systemd unit", ["T1543.002"]),
    "rc_local": ("AEG-PERS-RCLOCAL", "rc.local startup script", ["T1037.004"]),
    "shell_rc": ("AEG-PERS-SHELLRC", "Shell startup file", ["T1546.004"]),
    "ld_preload": ("AEG-PERS-LDPRELOAD", "/etc/ld.so.preload library", ["T1574.006"]),
    "ssh_key": ("AEG-PERS-SSHKEYS", "SSH authorized key", ["T1098.004"]),
    "udev": ("AEG-PERS-UDEV", "udev RUN rule", ["T1546.017"]),
    "xdg_autostart": ("AEG-PERS-XDG", "Desktop autostart entry", ["T1547.013"]),
    "launchd": ("AEG-PERS-LAUNCHD", "launchd job", ["T1543.001", "T1543.004"]),
    "pam": ("AEG-PERS-PAM", "PAM rule or module", ["T1556.003"]),
    "motd": ("AEG-PERS-MOTD", "update-motd script", ["T1037"]),
    "systemd_generator": ("AEG-PERS-GENERATOR", "systemd generator", ["T1543.002"]),
    "at_job": ("AEG-PERS-ATJOB", "at job", ["T1053.002"]),
    "periodic": ("AEG-PERS-PERIODIC", "macOS periodic script", ["T1053.003"]),
    "emond": ("AEG-PERS-EMOND", "emond rule", ["T1546.014"]),
    "auth_plugin": ("AEG-PERS-AUTHPLUGIN", "macOS authorization plugin", ["T1556"]),
    "login_hook": ("AEG-PERS-LOGINHOOK", "macOS login/logout hook", ["T1037.002"]),
    "btm": ("AEG-PERS-BTM", "Login item / background task", ["T1547.015"]),
}
TEXT_TYPES = {"cron_script", "rc_local", "shell_rc", "motd", "at_job", "periodic"}
# btm: the Background Task Management database keeps the records of apps that were uninstalled long ago
NO_MISSING_CHECK = TEXT_TYPES | {"ifeo", "silentprocessexit", "wmi_subscription", "ssh_key", "ld_preload", "winlogon",
                                 "lsa", "bootexecute", "dll_hook", "com_hijack", "btm"}
NO_RANDOM_CHECK = TEXT_TYPES | {"ssh_key", "ld_preload", "lsa", "winlogon", "bootexecute", "ifeo", "silentprocessexit",
                                "accessibility", "appinit", "appcert", "cron", "udev"}

_MAC_SUSPICIOUS = re.compile(
    r"\bosascript\s+-e\b|\bcurl\s+-[a-zA-Z]*s\b[^\n]*\|\s*(?:ba|z)?sh\b|\bbase64\s+(?:-d|-D|--decode)\b|"
    r"\bpython[\d.]*\s+-c\s|\bperl\s+-e\s|\bopenssl\s+enc\b", re.I)


def logical_lines(text: str) -> List[str]:
    """Join backslash-continued lines and drop comments/blank lines."""
    out, buf = [], ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        line = (buf + line).strip()
        buf = ""
        if line and not line.startswith("#"):
            out.append(line)
    if buf.strip():
        out.append(buf.strip())
    return out


def analyse_script_text(text: str, min_sev: Severity = Severity.MEDIUM) -> List[Tuple[str, str, Severity, List[str], str]]:
    hits, seen = [], set()
    for line in logical_lines(text[:MAX_TEXT]):
        for h in cl.analyse_command_line(line):
            key = (h[0], h[4])
            if h[2] >= min_sev and key not in seen:
                seen.add(key)
                hits.append(h)
    return hits


def assess_entry(e: Entry, sig_status: Optional[str] = None, scan_findings: Sequence[Finding] = (),
                 exists: Callable[[str], bool] = target_exists) -> List[Reason]:
    """Why (if at all) is this autostart entry suspicious? Pure given its inputs."""
    if not e.get("enabled", True):
        return []
    typ, command, path, name = e["type"], e.get("command") or "", e.get("path") or "", e.get("name") or ""
    meta = e.get("meta", {})
    reasons: List[Reason] = list(_meta_reasons(e))
    microsoft = bool(meta.get("microsoft")) and bool(path) and cl.is_windows_style(path) and cl.is_in_windir(path)

    # 1. command-line / script-content patterns
    hits = []
    if typ in TEXT_TYPES:
        hits = analyse_script_text(meta.get("text", ""))
    elif command:
        hits = [h for h in cl.analyse_command_line(command) if h[2] >= Severity.MEDIUM]
        if meta.get("mac") and not hits and _MAC_SUSPICIOUS.search(command):
            hits = [("AEG-CMD-MAC", "Launch job runs a download/encoded/inline-script command", Severity.MEDIUM, ["T1059.002"],
                     command[:160])]
    for rid, title, sev, mitre, matched in hits[:4]:
        reasons.append(Reason(sev, f"{title}: {matched[:120]}", "cmd", mitre))

    # 2. where does it run from / is it there / is it signed
    if path and typ not in TEXT_TYPES:
        risk = cl.path_risk(path)
        if risk > 0 and not microsoft:
            sev = None
            try:
                from aegis.scanners.processes import location_severity

                sev = location_severity(risk, sig_status)
            except Exception:  # pragma: no cover
                sev = Severity.MEDIUM if risk >= 2 else Severity.LOW
            if sev is not None:
                note = f" (Authenticode: {sig_status})" if sig_status else ""
                reasons.append(Reason(sev, f"runs from a user-writable location: {cl.dirname(path)}{note}", "location",
                                      ["T1036", "T1204.002"]))
        svc_ok = typ != "service" or (meta.get("start") in (0, 1, 2) and not cl.is_in_windir(path))
        if (typ not in NO_MISSING_CHECK and svc_ok and not _is_unc_or_unknown(path) and not microsoft
                and not exists(path) and (cl.is_windows_style(path) or path.startswith("/"))):
            reasons.append(Reason(Severity.LOW, f"target file is missing: {path}", "missing"))

    # 3. interpreter running a script from a user-writable place / remote
    host = cl.first_program_name(command) if command else ""
    if command and typ not in TEXT_TYPES and host in _INTERPRETERS:
        script = cl.script_target(command)
        if script and cl.path_risk(script) > 0 and not microsoft:
            reasons.append(Reason(Severity.MEDIUM, f"script interpreter runs a script from a user-writable location: {script}",
                                  "script", ["T1059"]))
    if host in ("wscript", "cscript", "mshta") and typ in ("registry_run", "startup_folder") and not any(
            r.kind == "script" for r in reasons):
        reasons.append(Reason(Severity.LOW, f"autostart launches a script host ({host})", "script", ["T1059.005"]))

    # 4. random-looking names
    trusted_dir = bool(path) and (cl.is_in_windir(path) or cl.is_in_program_files(path)
                                  or (bool(meta.get("mac")) and path.startswith(MAC_SYSTEM_DIRS)))
    if typ not in NO_RANDOM_CHECK and not microsoft and not trusted_dir:
        leaf = name.rsplit("\\", 1)[-1] if typ == "scheduled_task" else name
        cands = [cl.basename(path)] if path else []
        if typ in ("registry_run", "service", "startup_folder", "scheduled_task"):
            cands.append(leaf)
        if any(c and looks_random(c) for c in cands):
            reasons.append(Reason(Severity.LOW, "name looks randomly generated", "random", ["T1036"]))

    # 5. content-scan verdict on the target
    for f in scan_findings:
        reasons.append(Reason(f.severity, f"target flagged by scanner: {f.title}", "scan", list(f.mitre)))

    # 6. weak modifiers only count when something else is already wrong
    if reasons:
        for m in meta.get("modifiers", []):
            reasons.append(Reason(Severity.INFO, m, "modifier"))
    return reasons


def combined_severity(reasons: Sequence[Reason]) -> Severity:
    """Highest reason severity, +1 (max HIGH) when two independent kinds of evidence stack."""
    real = [r for r in reasons if r.severity > Severity.INFO]
    if not real:
        return Severity.INFO
    top = max(r.severity for r in real)
    # A LOW content-heuristic hint on the target (e.g. high-entropy sections, common in Go/packed
    # but legitimate binaries) is too weak to stack: it must not turn an unsigned binary in
    # ProgramData into HIGH. Location + random name (classic dropper pattern) still stacks.
    kinds = {r.kind for r in real if r.kind not in ("missing", "modifier")
             and not (r.kind == "scan" and r.severity <= Severity.LOW)}
    if top < Severity.HIGH and len(kinds) >= 2:
        return Severity(int(top) + 1)
    # Modifiers (highest privileges, hidden, boot trigger, repetition) lift weak evidence to MEDIUM.
    # They push MEDIUM to HIGH only when they show stealth (a hidden task) or stack up: an unsigned
    # vendor agent under ProgramData that merely runs elevated is worth a look, not "very likely
    # malicious" (seen with GitHub's own runner agents on real Windows).
    mods = [r for r in reasons if r.kind == "modifier"]
    if kinds and mods:
        if top <= Severity.LOW:
            return Severity.MEDIUM
        stealthy = any("hidden" in r.text.lower() for r in mods)
        if top == Severity.MEDIUM and (stealthy or len(mods) >= 2):
            return Severity.HIGH
    return top


def display_location(e: Entry) -> str:
    t, loc, name = e["type"], e["location"], e["name"]
    if t == "scheduled_task":
        return f"Task {name}"
    if t == "service":
        return f"Service {name}"
    if t == "wmi_subscription":
        return f"WMI {name}"
    if t in ("registry_run", "winlogon", "ifeo", "silentprocessexit", "appinit", "appcert", "lsa", "bootexecute",
             "active_setup", "logon_script", "cmd_autorun", "screensaver", "dll_hook", "com_hijack", "office_addin") \
            and loc.upper().startswith("HK"):
        return f"{loc}\\{name}" if name else loc
    if t == "startup_folder":
        return e.get("meta", {}).get("shortcut") or e.get("path") or loc
    return f"{loc} [{name}]" if name and name not in loc else loc


def finding_for_entry(e: Entry, reasons: Sequence[Reason]) -> Optional[Finding]:
    sev = combined_severity(reasons)
    if sev <= Severity.INFO:
        return None
    rule, label, mitre = TYPE_INFO.get(e["type"], ("AEG-PERS-GENERIC", "Autostart entry", []))
    mitre = list(e.get("meta", {}).get("mitre") or mitre)  # an entry knows better than its type (a btm agent is not a login item)
    real = sorted((r for r in reasons if r.severity > Severity.INFO), key=lambda r: -int(r.severity))
    mods = [r.text for r in reasons if r.kind == "modifier"]
    all_mitre = list(dict.fromkeys(mitre + [m for r in real for m in r.mitre]))
    top = real[0]
    desc = "; ".join(r.text for r in real[:5]) + (f". Also: {', '.join(mods)}" if mods else "")
    rem = None
    rd = e.get("meta", {}).get("remediation")
    if rd:
        rem = Remediation(rd["action"], dict(rd["params"]), rd.get("description", ""))
    rec = ("Verify that you installed this item. If not, remove it (Aegis can disable/delete it) and scan the target file."
           if sev >= Severity.MEDIUM else
           "Stale or unusual autostart item - remove it if you no longer use the program.")
    cat = Category.PERSISTENCE
    if sev >= Severity.HIGH and any(r.kind == "scan" for r in real):
        cat = Category.MALWARE
    return Finding(
        rule, f"{label}: {e['name'] or cl.basename(e.get('path') or '') or e['location']} - {top.text.split(':')[0][:70]}",
        sev, cat, desc, display_location(e),
        {"type": e["type"], "name": e["name"], "command": (e.get("command") or "")[:1000], "path": e.get("path", ""),
         "location": e["location"], "reasons": [r.to_dict() for r in real], "enabled": e.get("enabled", True),
         **{k: v for k, v in e.get("meta", {}).items()
            if k in ("author", "hidden", "run_level", "user", "triggers", "start", "svc_type", "filter_query", "item_type",
                     "developer", "team_id", "identifier", "disposition", "signer", "signature")}},
        rec, rem, scanner="persistence", mitre=all_mitre)


# --------------------------------------------------------------------------- Windows: registry

RUN_KEYS: List[Tuple[str, str]] = [
    (r"Software\Microsoft\Windows\CurrentVersion\Run", "Run"),
    (r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce"),
    (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "Policies\\Explorer\\Run"),
    (r"Software\Microsoft\Windows\CurrentVersion\RunServices", "RunServices"),
    (r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce", "RunServicesOnce"),
]
APPROVED_KEYS = {"Run": "Run", "RunOnce": "Run", "Policies\\Explorer\\Run": "Run"}
APPROVED_BASE = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved"


def _run_remediation(hive: str, key: str, name: str, view64: bool) -> Dict[str, Any]:
    return {"action": "delete_registry_value", "params": {"hive": hive, "key": key, "value": name, "view64": view64},
            "description": f"Delete the autorun value {name!r}"}


def collect_run_keys() -> List[Entry]:
    out: List[Entry] = []
    seen: Set[Tuple[str, str, str, str]] = set()
    for hive in ("HKLM", "HKCU"):
        for view64 in ((True, False) if hive == "HKLM" else (True,)):
            tag = "" if view64 else " (32-bit view)"
            for key, label in RUN_KEYS:
                approved: Dict[str, Any] = {}
                if label in APPROVED_KEYS:
                    for ak in ("Run", "Run32"):
                        approved.update(reg_values(hive, f"{APPROVED_BASE}\\{ak}", view64))
                values = reg_values(hive, key, view64)
                for name, data in values.items():
                    if not name or not isinstance(data, str) or not data.strip():
                        continue
                    ident = (hive, key.lower(), name.lower(), data)
                    if ident in seen:
                        continue
                    seen.add(ident)
                    out.append(make_entry("registry_run", f"{hive}\\{key}{tag}", name, data.strip(),
                                          enabled=startup_approved_enabled(approved.get(name)),
                                          remediation=_run_remediation(hive, key, name, view64), label=label))
            # RunOnceEx has numbered subkeys holding the commands
            rox = r"Software\Microsoft\Windows\CurrentVersion\RunOnceEx"
            for sub in reg_subkeys(hive, rox, view64):
                for name, data in reg_values(hive, f"{rox}\\{sub}", view64).items():
                    if isinstance(data, str) and data.strip() and name.lower() != "title":
                        out.append(make_entry("registry_run", f"{hive}\\{rox}\\{sub}{tag}", name, data.strip(),
                                              remediation=_run_remediation(hive, f"{rox}\\{sub}", name, view64)))
        # legacy Load / Run values under Windows NT\CurrentVersion\Windows
        key = r"Software\Microsoft\Windows NT\CurrentVersion\Windows"
        for name in ("Load", "Run"):
            data = reg_read(hive, key, name)
            if isinstance(data, str) and data.strip():
                out.append(make_entry("registry_run", f"{hive}\\{key}", name, data.strip(),
                                      remediation=_run_remediation(hive, key, name, True)))
    return out


# ---- Winlogon

WINLOGON_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"


def winlogon_reasons(values: Dict[str, Any], hive: str = "HKLM") -> List[Tuple[str, str, Dict[str, Any]]]:
    """(value name, data, reason dict) for each abnormal Winlogon value."""
    out: List[Tuple[str, str, Dict[str, Any]]] = []
    mitre = ["T1547.004"]
    shell = values.get("Shell")
    if isinstance(shell, str) and shell.strip():
        s = shell.strip().strip('"')
        if s.lower() != "explorer.exe" and not (cl.basename(s).lower() == "explorer.exe" and cl.is_in_windir(s)):
            out.append(("Shell", shell, meta_reason(Severity.HIGH, f"Winlogon Shell is '{shell}' instead of explorer.exe", mitre)))
    ui = values.get("Userinit")
    if isinstance(ui, str) and ui.strip():
        items = [x.strip().strip('"') for x in ui.split(",") if x.strip()]
        bad = [x for x in items if cl.basename(x).lower() != "userinit.exe" or not cl.is_in_system32(cl.clean_path(x))]
        if bad:
            out.append(("Userinit", ui, meta_reason(Severity.HIGH, f"Winlogon Userinit launches additional program(s): {', '.join(bad)}", mitre)))
    for name, sev, text in (("Taskman", Severity.HIGH, "Winlogon Taskman replaces Task Manager with another program"),
                            ("GinaDLL", Severity.HIGH, "Custom GINA DLL loaded by Winlogon"),
                            ("AppSetup", Severity.MEDIUM, "Winlogon AppSetup launches a program at logon")):
        v = values.get(name)
        if isinstance(v, str) and v.strip():
            out.append((name, v, meta_reason(sev, f"{text}: {v}", mitre)))
    uih = values.get("UIHost")
    if isinstance(uih, str) and uih.strip() and uih.strip().lower() != "logonui.exe":
        out.append(("UIHost", uih, meta_reason(Severity.HIGH, f"Winlogon UIHost replaced: {uih}", mitre)))
    return out


def collect_winlogon() -> List[Entry]:
    out: List[Entry] = []
    for hive, key in (("HKLM", WINLOGON_KEY), ("HKCU", WINLOGON_KEY.replace("SOFTWARE", "Software", 1))):
        vals = reg_values(hive, key)
        for name, data, reason in winlogon_reasons(vals, hive):
            rem = {"action": "delete_registry_value", "params": {"hive": hive, "key": key, "value": name, "view64": True},
                   "description": f"Delete the Winlogon {name} override"}
            if hive == "HKLM" and name == "Shell":
                rem = {"action": "set_registry_value", "params": {"hive": hive, "key": key, "value": name, "data": "explorer.exe"},
                       "description": "Restore the default shell (explorer.exe)"}
            elif hive == "HKLM" and name == "Userinit":
                rem = {"action": "set_registry_value",
                       "params": {"hive": hive, "key": key, "value": name,
                                  "data": str(windows_dir() / "system32" / "userinit.exe") + ","},
                       "description": "Restore the default Userinit value"}
            out.append(make_entry("winlogon", f"{hive}\\{key}", name, data, reasons=[reason], remediation=rem))
    return out


# ---- IFEO / SilentProcessExit / accessibility

IFEO_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
SPE_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit"
ACCESSIBILITY_EXES = {"sethc.exe", "utilman.exe", "osk.exe", "narrator.exe", "magnify.exe", "displayswitch.exe",
                      "atbroker.exe"}
LEGIT_DEBUGGERS = {"vsjitdebugger.exe", "drwtsn32.exe", "drwatson.exe", "procexp.exe", "procexp64.exe", "windbg.exe",
                   "cdb.exe", "ntsd.exe"}
SECURITY_TARGETS = {"taskmgr.exe", "regedit.exe", "msconfig.exe", "cmd.exe", "powershell.exe", "mmc.exe", "procexp.exe",
                    "procexp64.exe", "procmon.exe", "procmon64.exe", "autoruns.exe", "autoruns64.exe", "msmpeng.exe",
                    "mpcmdrun.exe", "nissrv.exe", "msseces.exe", "mbam.exe", "mbamservice.exe", "avp.exe", "avgui.exe",
                    "avastui.exe", "avastsvc.exe", "ekrn.exe", "egui.exe", "bdagent.exe", "mcshield.exe", "wireshark.exe",
                    "tcpview.exe", "sysmon.exe", "sysmon64.exe", "securityhealthservice.exe", "mpdefendercoreservice.exe"}


def ifeo_reason(exe_name: str, debugger: str) -> Optional[Dict[str, Any]]:
    """Reason dict for an IFEO Debugger value, or None if it is a known-benign debugger setup."""
    target = exe_name.lower()
    dbg_exe = cl.basename(cl.extract_executable(debugger) or debugger).lower()
    mitre = ["T1546.012"]
    if target in ACCESSIBILITY_EXES:
        return meta_reason(Severity.CRITICAL,
                           f"IFEO Debugger on accessibility binary {exe_name} runs '{debugger}' at the logon screen as SYSTEM "
                           "(sticky-keys style backdoor)", ["T1546.008", "T1546.012"])
    if dbg_exe in LEGIT_DEBUGGERS and not cl.path_risk(cl.extract_executable(debugger) or ""):
        if dbg_exe in ("procexp.exe", "procexp64.exe") and target != "taskmgr.exe":
            pass
        else:
            return None
    if target in SECURITY_TARGETS:
        return meta_reason(Severity.HIGH, f"IFEO Debugger hijacks security/admin tool {exe_name}: '{debugger}' "
                                          "(commonly used to block or replace it)", mitre)
    return meta_reason(Severity.MEDIUM, f"IFEO Debugger for {exe_name} launches '{debugger}' instead of the program", mitre)


def collect_ifeo() -> List[Entry]:
    out: List[Entry] = []
    for view64 in (True, False):
        tag = "" if view64 else " (32-bit view)"
        for sub in reg_subkeys("HKLM", IFEO_KEY, view64):
            vals = reg_values("HKLM", f"{IFEO_KEY}\\{sub}", view64)
            dbg = vals.get("Debugger")
            if isinstance(dbg, str) and dbg.strip():
                reason = ifeo_reason(sub, dbg)
                typ = "accessibility" if sub.lower() in ACCESSIBILITY_EXES else "ifeo"
                out.append(make_entry(typ, f"HKLM\\{IFEO_KEY}\\{sub}{tag}", "Debugger", dbg,
                                      reasons=[reason] if reason else [], image=sub,
                                      remediation={"action": "delete_registry_value",
                                                   "params": {"hive": "HKLM", "key": f"{IFEO_KEY}\\{sub}", "value": "Debugger",
                                                              "view64": view64},
                                                   "description": f"Remove the Debugger hijack on {sub}"}))
        for sub in reg_subkeys("HKLM", SPE_KEY, view64):
            vals = reg_values("HKLM", f"{SPE_KEY}\\{sub}", view64)
            mon = vals.get("MonitorProcess")
            if isinstance(mon, str) and mon.strip():
                out.append(make_entry("silentprocessexit", f"HKLM\\{SPE_KEY}\\{sub}{tag}", "MonitorProcess", mon,
                                      reasons=[meta_reason(Severity.HIGH, f"SilentProcessExit launches '{mon}' whenever {sub} exits "
                                                                         "(stealthy persistence / LSASS dumping)", ["T1546.012"])],
                                      remediation={"action": "delete_registry_value",
                                                   "params": {"hive": "HKLM", "key": f"{SPE_KEY}\\{sub}",
                                                              "value": "MonitorProcess", "view64": view64},
                                                   "description": "Remove the SilentProcessExit monitor"}))
    return out


def file_identical_to(path: Path, refs: Sequence[Path]) -> Optional[Path]:
    """If *path* is a byte-for-byte copy of one of *refs* (e.g. sethc.exe replaced by cmd.exe), return that ref."""
    try:
        size = path.stat().st_size
    except OSError:
        return None
    digest = None
    for r in refs:
        try:
            if r.stat().st_size != size:
                continue
            if digest is None:
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if hashlib.sha256(r.read_bytes()).hexdigest() == digest:
                return r
        except OSError:
            continue
    return None


def collect_accessibility_files(sys32: Optional[Path] = None) -> List[Entry]:
    sys32 = sys32 or windows_dir() / "System32"
    refs = [sys32 / "cmd.exe", sys32 / "WindowsPowerShell" / "v1.0" / "powershell.exe", sys32 / "mshta.exe",
            sys32 / "wscript.exe", sys32 / "cscript.exe", sys32 / "regedit.exe"]
    out: List[Entry] = []
    for n in sorted(ACCESSIBILITY_EXES):
        p = sys32 / n
        ref = file_identical_to(p, refs) if p.exists() else None
        if ref:
            out.append(make_entry(
                "accessibility", str(p), n, str(p), path=str(p),
                reasons=[meta_reason(Severity.CRITICAL, f"{n} has been replaced with a copy of {ref.name} - anyone at the "
                                                        "logon screen can get a SYSTEM shell", ["T1546.008"])]))
    return out


# ---- AppInit / AppCert / LSA / BootExecute / DLL hooks

def collect_appinit() -> List[Entry]:
    out: List[Entry] = []
    for view64 in (True, False):
        key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
        vals = reg_values("HKLM", key, view64)
        dlls = vals.get("AppInit_DLLs")
        load = vals.get("LoadAppInit_DLLs")
        if isinstance(dlls, str) and dlls.strip():
            enabled = bool(load) and int(load) == 1 if isinstance(load, int) else False
            for dll in [d for d in re.split(r"[,\s]+", dlls.strip()) if d]:
                out.append(make_entry(
                    "appinit", f"HKLM\\{key}" + ("" if view64 else " (32-bit view)"), "AppInit_DLLs", dll, path=dll,
                    enabled=enabled,
                    reasons=[meta_reason(Severity.HIGH, f"AppInit_DLLs injects {dll} into every process that loads user32.dll",
                                         ["T1546.010"])],
                    remediation={"action": "set_registry_value",
                                 "params": {"hive": "HKLM", "key": key, "value": "AppInit_DLLs", "data": ""},
                                 "description": "Clear AppInit_DLLs"}))
    key = r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls"
    for name, data in reg_values("HKLM", key).items():
        if isinstance(data, str) and data.strip():
            out.append(make_entry("appcert", f"HKLM\\{key}", name, data, path=data,
                                  reasons=[meta_reason(Severity.HIGH, f"AppCertDlls loads {data} into every process that calls CreateProcess",
                                                       ["T1546.009"])],
                                  remediation={"action": "delete_registry_value",
                                               "params": {"hive": "HKLM", "key": key, "value": name, "view64": True},
                                               "description": "Delete the AppCertDlls value"}))
    return out


LSA_KEY = r"SYSTEM\CurrentControlSet\Control\Lsa"
LSA_DEFAULTS: Dict[str, Set[str]] = {
    "Authentication Packages": {"msv1_0"},
    "Security Packages": {"kerberos", "msv1_0", "schannel", "wdigest", "tspkg", "pku2u", "cloudap", "negoexts",
                          "livessp", "credssp", "negoextender", "", '""'},
    "Notification Packages": {"scecli", "rassfm", "kdcsvc"},
}


def lsa_reasons(value_name: str, data: Any, exists_in_system32: Callable[[str], bool]) -> List[Tuple[str, Dict[str, Any]]]:
    allowed = LSA_DEFAULTS.get(value_name, set())
    items: List[str] = [str(x) for x in (data if isinstance(data, list) else re.split(r"[,\0]", str(data or "")))]
    out = []
    for raw in items:
        pkg = raw.strip().strip('"')
        low = re.sub(r"\.dll$", "", pkg.lower())
        if low in allowed or not pkg:
            continue
        sev = Severity.HIGH if ("mimi" in low or not exists_in_system32(pkg)) else Severity.MEDIUM
        out.append((pkg, meta_reason(sev, f"Non-default LSA {value_name[:-1].lower()} '{pkg}' is loaded into lsass.exe "
                                          "(credential-theft implants such as mimilib use this)", ["T1547.002", "T1547.005"])))
    return out


def collect_lsa() -> List[Entry]:
    out: List[Entry] = []
    sys32 = windows_dir() / "System32"

    def exists32(pkg: str) -> bool:
        return (sys32 / (pkg if pkg.lower().endswith(".dll") else pkg + ".dll")).exists()

    for vname in LSA_DEFAULTS:
        data = reg_read("HKLM", LSA_KEY, vname)
        if data is None:
            continue
        for pkg, reason in lsa_reasons(vname, data, exists32):
            out.append(make_entry("lsa", f"HKLM\\{LSA_KEY}", vname, pkg, path=str(sys32 / (pkg if pkg.lower().endswith('.dll') else pkg + '.dll')),
                                  reasons=[reason]))
    return out


# 'autocheck autochk *' plus the standard autochk switches (/q /v /k:C /p /r /x ...) Windows itself sets.
BOOT_DEFAULT = re.compile(r"^autocheck\s+autochk(?:\s+/[a-z]+(?::\S+)?)*\s+\*$", re.I)


def collect_bootexecute() -> List[Entry]:
    out: List[Entry] = []
    key = r"SYSTEM\CurrentControlSet\Control\Session Manager"
    for vname in ("BootExecute", "SetupExecute", "PlatformExecute", "Execute", "S0InitialCommand"):
        data = reg_read("HKLM", key, vname)
        items = data if isinstance(data, list) else ([data] if isinstance(data, str) else [])
        for it in items:
            it = str(it).strip()
            if it and not BOOT_DEFAULT.match(it):
                out.append(make_entry("bootexecute", f"HKLM\\{key}", vname, it,
                                      reasons=[meta_reason(Severity.HIGH, f"Session Manager runs '{it}' before Windows starts "
                                                                          "(only 'autocheck autochk *' is normal)", ["T1547.001"])]))
    return out


def collect_dll_hooks() -> List[Entry]:
    """netsh helper DLLs, W32Time providers, print monitors outside System32."""
    out: List[Entry] = []
    def add(loc: str, name: str, dll: str, what: str) -> None:
        if not dll:
            return
        full = cl.clean_path(dll)
        if "\\" not in full:
            return  # bare name = resolved from System32
        if cl.is_in_system32(full):
            return
        out.append(make_entry("dll_hook", loc, name, dll, path=full,
                              reasons=[meta_reason(Severity.MEDIUM, f"{what} loads a DLL from outside System32: {dll}", ["T1546.007"])]))

    for name, data in reg_values("HKLM", r"SOFTWARE\Microsoft\NetSh").items():
        if isinstance(data, str):
            add(r"HKLM\SOFTWARE\Microsoft\NetSh", name, data, "netsh helper")
    tp = r"SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders"
    for sub in reg_subkeys("HKLM", tp):
        d = reg_read("HKLM", f"{tp}\\{sub}", "DllName")
        if isinstance(d, str):
            add(f"HKLM\\{tp}\\{sub}", "DllName", d, "Time provider")
    pm = r"SYSTEM\CurrentControlSet\Control\Print\Monitors"
    for sub in reg_subkeys("HKLM", pm):
        d = reg_read("HKLM", f"{pm}\\{sub}", "Driver")
        if isinstance(d, str):
            add(f"HKLM\\{pm}\\{sub}", "Driver", d, "Print monitor")
    return out


# ---- misc registry persistence

def collect_misc_registry() -> List[Entry]:
    out: List[Entry] = []
    # Active Setup
    base = r"SOFTWARE\Microsoft\Active Setup\Installed Components"
    for view64 in (True, False):
        for sub in reg_subkeys("HKLM", base, view64):
            stub = reg_read("HKLM", f"{base}\\{sub}", "StubPath", view64)
            if isinstance(stub, str) and stub.strip():
                out.append(make_entry("active_setup", f"HKLM\\{base}\\{sub}" + ("" if view64 else " (32-bit view)"),
                                      "StubPath", stub.strip(),
                                      remediation={"action": "delete_registry_value",
                                                   "params": {"hive": "HKLM", "key": f"{base}\\{sub}", "value": "StubPath",
                                                              "view64": view64},
                                                   "description": "Delete the Active Setup StubPath"}))
    # logon script, cmd AutoRun, screensaver, Office 'Test\Special\Perf'
    v = reg_read("HKCU", "Environment", "UserInitMprLogonScript")
    if isinstance(v, str) and v.strip():
        out.append(make_entry("logon_script", r"HKCU\Environment", "UserInitMprLogonScript", v.strip(),
                              reasons=[meta_reason(Severity.MEDIUM, "A per-user logon script is configured via the registry", ["T1037.001"])],
                              remediation={"action": "delete_registry_value",
                                           "params": {"hive": "HKCU", "key": "Environment", "value": "UserInitMprLogonScript",
                                                      "view64": True}, "description": "Delete the logon script value"}))
    for hive in ("HKLM", "HKCU"):
        key = r"Software\Microsoft\Command Processor"
        v = reg_read(hive, key, "AutoRun")
        if isinstance(v, str) and v.strip() and not re.search(r"conda_hook|clink|condabin", v, re.I):
            out.append(make_entry("cmd_autorun", f"{hive}\\{key}", "AutoRun", v.strip(),
                                  reasons=[meta_reason(Severity.LOW, "cmd.exe runs this command every time it starts", ["T1546"])],
                                  remediation={"action": "delete_registry_value",
                                               "params": {"hive": hive, "key": key, "value": "AutoRun", "view64": True},
                                               "description": "Delete the cmd.exe AutoRun value"}))
    scr = reg_read("HKCU", r"Control Panel\Desktop", "SCRNSAVE.EXE")
    if isinstance(scr, str) and scr.strip() and not cl.is_in_system32(cl.clean_path(scr)) and "\\" in scr:
        out.append(make_entry("screensaver", r"HKCU\Control Panel\Desktop", "SCRNSAVE.EXE", scr.strip(),
                              reasons=[meta_reason(Severity.MEDIUM, "Screensaver program is outside System32 (screensavers are plain executables)",
                                                   ["T1546.002"])],
                              remediation={"action": "delete_registry_value",
                                           "params": {"hive": "HKCU", "key": r"Control Panel\Desktop", "value": "SCRNSAVE.EXE",
                                                      "view64": True}, "description": "Remove the custom screensaver"}))
    perf = reg_values("HKCU", r"Software\Microsoft\Office test\Special\Perf").get("")
    if isinstance(perf, str) and perf.strip():
        out.append(make_entry("office_addin", r"HKCU\Software\Microsoft\Office test\Special\Perf", "(Default)", perf.strip(),
                              path=perf.strip(),
                              reasons=[meta_reason(Severity.HIGH, "Office 'test\\Special\\Perf' key loads a DLL into every Office app", ["T1137.002"])],
                              remediation={"action": "delete_registry_value",
                                           "params": {"hive": "HKCU", "key": r"Software\Microsoft\Office test\Special\Perf",
                                                      "value": "", "view64": True}, "description": "Remove the Office Perf DLL"}))
    return out


def collect_office_addins() -> List[Entry]:
    out: List[Entry] = []
    for app in ("Word", "Excel", "Outlook", "PowerPoint"):
        base = f"Software\\Microsoft\\Office\\{app}\\Addins"
        for sub in reg_subkeys("HKCU", base):
            vals = reg_values("HKCU", f"{base}\\{sub}")
            manifest = vals.get("Manifest")
            if isinstance(manifest, str) and manifest.strip():
                target = manifest.split("|")[0].replace("file:///", "").replace("/", "\\")
                out.append(make_entry("office_addin", f"HKCU\\{base}\\{sub}", sub, target, path=target,
                                      enabled=vals.get("LoadBehavior", 3) in (3, 2, 9, 16)))
    appdata = os.environ.get("APPDATA")
    if appdata:
        for app, folder, exts in (("Word", "Microsoft\\Word\\STARTUP", (".dot", ".dotm", ".wll")),
                                  ("Excel", "Microsoft\\Excel\\XLSTART", (".xla", ".xlam", ".xll", ".xlsm"))):
            d = Path(appdata) / folder
            try:
                for f in d.iterdir():
                    if f.is_file() and f.suffix.lower() in exts:
                        out.append(make_entry("office_addin", str(d), f.name, str(f), path=str(f),
                                              reasons=[meta_reason(Severity.LOW, f"{app} auto-loads this macro-capable file at startup", ["T1137.001", "T1137.006"])],
                                              remediation={"action": "quarantine_file", "params": {"path": str(f)},
                                                           "description": "Quarantine the startup add-in file"}))
            except OSError:
                continue
    return out


def collect_com_hijacks() -> List[Entry]:
    """HKCU CLSID registrations that override HKLM or point into user-writable folders."""
    out: List[Entry] = []
    base = r"Software\Classes\CLSID"
    for clsid in reg_subkeys("HKCU", base):
        for srv in ("InprocServer32", "LocalServer32"):
            vals = reg_values("HKCU", f"{base}\\{clsid}\\{srv}")
            target = vals.get("")
            if not isinstance(target, str) or not target.strip():
                continue
            hk = reg_values("HKLM", f"Software\\Classes\\CLSID\\{clsid}\\{srv}").get("")
            reasons = []
            if isinstance(hk, str) and hk.strip() and cl.norm_win(hk) != cl.norm_win(target):
                reasons.append(meta_reason(Severity.MEDIUM, f"Per-user COM registration overrides the system one ({hk})", ["T1546.015"]))
            out.append(make_entry("com_hijack", f"HKCU\\{base}\\{clsid}\\{srv}", clsid, target.strip(), reasons=reasons,
                                  remediation={"action": "delete_registry_value",
                                               "params": {"hive": "HKCU", "key": f"{base}\\{clsid}\\{srv}", "value": "", "view64": True},
                                               "description": "Remove the per-user COM registration"}))
    return out


# --------------------------------------------------------------------------- Windows: startup folders

def startup_dirs() -> List[Path]:
    dirs = []
    appdata = os.environ.get("APPDATA")
    if appdata:
        dirs.append(Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
    pd = os.environ.get("ProgramData")
    if pd:
        dirs.append(Path(pd) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "StartUp")
    return dirs


EXEC_EXTS = {".exe", ".scr", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".ps1", ".jar", ".dll",
             ".com", ".pif", ".msi", ".cpl"}


def parse_lnk_json(data: Any) -> Dict[str, Tuple[str, str]]:
    """{normalised lnk path: (target, arguments)} from the PowerShell CreateShortcut batch."""
    out: Dict[str, Tuple[str, str]] = {}
    for row in as_list(data):
        if isinstance(row, dict) and row.get("Path"):
            out[str(row["Path"]).lower()] = (str(row.get("Target") or ""), str(row.get("Args") or ""))
    return out


def resolve_lnks(paths: Sequence[str]) -> Dict[str, Tuple[str, str]]:
    if not paths or not IS_WINDOWS:
        return {}
    arr = ",".join("'" + p.replace("'", "''") + "'" for p in paths)
    script = (f"$sh=New-Object -ComObject WScript.Shell; @({arr}) | ForEach-Object {{ try {{ $l=$sh.CreateShortcut($_); "
              "[pscustomobject]@{Path=$_;Target=$l.TargetPath;Args=$l.Arguments} } catch {} } | ConvertTo-Json -Compress")
    try:
        return parse_lnk_json(powershell_json(script))
    except Exception:  # pragma: no cover
        return {}


def collect_startup_folders(dirs: Optional[Sequence[Path]] = None,
                            lnk_resolver: Callable[[Sequence[str]], Dict[str, Tuple[str, str]]] = resolve_lnks) -> List[Entry]:
    files: List[Tuple[Path, Path]] = []
    for d in (dirs if dirs is not None else startup_dirs()):
        try:
            for f in sorted(d.iterdir()):
                if f.is_file() and f.name.lower() != "desktop.ini":
                    files.append((d, f))
        except OSError:
            continue
    lnk_targets = lnk_resolver([str(f) for _, f in files if f.suffix.lower() == ".lnk"])
    out: List[Entry] = []
    for d, f in files:
        ext = f.suffix.lower()
        rem = {"action": "quarantine_file", "params": {"path": str(f)}, "description": "Quarantine the startup item"}
        reasons = []
        if ext == ".lnk":
            target, args = lnk_targets.get(str(f).lower(), ("", ""))
            command = f'"{target}" {args}'.strip() if target else str(f)
            out.append(make_entry("startup_folder", str(d), f.name, command, path=target or str(f), remediation=rem, shortcut=str(f)))
        elif ext in EXEC_EXTS:
            reasons.append(meta_reason(Severity.MEDIUM, f"{ext} file placed directly in the Startup folder (programs normally use shortcuts)", ["T1547.001"]))
            out.append(make_entry("startup_folder", str(d), f.name, str(f), path=str(f), reasons=reasons, remediation=rem))
        elif ext == ".url":
            try:
                m = re.search(r"^URL=(.+)$", f.read_text(errors="replace"), re.M)
            except OSError:
                m = None
            url = m.group(1).strip() if m else ""
            if url and not re.match(r"https?://", url, re.I):
                out.append(make_entry("startup_folder", str(d), f.name, url, path=url if not url.lower().startswith("file:") else "",
                                      remediation=rem))
    return out


# --------------------------------------------------------------------------- Windows: scheduled tasks

_XML_DECL = re.compile(r"^\s*<\?xml[^>]*\?>", re.I)


def decode_task_xml(data: bytes) -> str:
    """Task Scheduler XML is usually UTF-16 LE with BOM, but UTF-8 occurs too."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = data.decode("utf-16", errors="replace")
    elif data[:3] == b"\xef\xbb\xbf":
        text = data[3:].decode("utf-8", errors="replace")
    else:
        try:
            text = data.decode("utf-8")
            if "\x00" in text:
                raise UnicodeDecodeError("utf-8", b"", 0, 1, "nul")
        except UnicodeDecodeError:
            text = data.decode("utf-16-le" if data[1:2] == b"\x00" else "utf-16-be", errors="replace")
    return _XML_DECL.sub("", text.lstrip("\ufeff"), count=1)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child(el: Optional[ET.Element], name: str) -> Optional[ET.Element]:
    if el is None:
        return None
    for c in el:
        if _local(c.tag) == name:
            return c
    return None


def _text(el: Optional[ET.Element], name: str) -> str:
    c = _child(el, name)
    return (c.text or "").strip() if c is not None and c.text else ""


def iso_duration_minutes(value: str) -> Optional[float]:
    m = re.fullmatch(r"P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?", (value or "").strip())
    if not m or not any(m.groups()):
        return None
    d, h, mi, s = (int(x or 0) for x in m.groups())
    return d * 1440 + h * 60 + mi + s / 60.0


def parse_task_xml(data: bytes) -> Dict[str, Any]:
    """Parse Task Scheduler XML into {author, uri, hidden, enabled, run_level, user, triggers, repetition_min, actions[]}."""
    root = ET.fromstring(decode_task_xml(data))
    reg = _child(root, "RegistrationInfo")
    settings = _child(root, "Settings")
    princ = _child(_child(root, "Principals"), "Principal")
    info: Dict[str, Any] = {
        "author": _text(reg, "Author"), "uri": _text(reg, "URI"), "description": _text(reg, "Description"),
        "hidden": _text(settings, "Hidden").lower() == "true",
        "enabled": _text(settings, "Enabled").lower() != "false",
        "run_level": _text(princ, "RunLevel"), "user": _text(princ, "UserId") or _text(princ, "GroupId"),
        "logon_type": _text(princ, "LogonType"), "triggers": [], "repetition_min": None, "actions": [],
    }
    triggers = _child(root, "Triggers")
    if triggers is not None:
        for t in triggers:
            info["triggers"].append(_local(t.tag))
            if _text(t, "Enabled").lower() == "false":
                continue
            rep = _child(t, "Repetition")
            mins = iso_duration_minutes(_text(rep, "Interval")) if rep is not None else None
            if mins is not None and (info["repetition_min"] is None or mins < info["repetition_min"]):
                info["repetition_min"] = mins
    actions = _child(root, "Actions")
    if actions is not None:
        for a in actions:
            kind = _local(a.tag)
            if kind == "Exec":
                info["actions"].append({"kind": "Exec", "command": _text(a, "Command"), "arguments": _text(a, "Arguments"),
                                        "workdir": _text(a, "WorkingDirectory")})
            elif kind == "ComHandler":
                info["actions"].append({"kind": "ComHandler", "clsid": _text(a, "ClassId")})
    return info


def task_entries(name: str, location: str, info: Dict[str, Any]) -> List[Entry]:
    """Entries for one parsed task (one per Exec action)."""
    out: List[Entry] = []
    author = info.get("author", "")
    microsoft = name.lower().startswith("\\microsoft\\") or author.lower().startswith("microsoft") or author.startswith("$(@%SystemRoot%")
    modifiers = []
    if info.get("hidden") and not microsoft:
        modifiers.append("task is hidden")
    if "highest" in (info.get("run_level") or "").lower() and not microsoft:
        modifiers.append("runs with highest privileges")
    rep = info.get("repetition_min")
    if rep is not None and rep <= 30 and not microsoft:
        modifiers.append(f"repeats every {rep:g} minutes")
    for a in info.get("actions", []):
        if a["kind"] != "Exec" or not a["command"]:
            continue
        cmd_str = a["command"].strip()
        command = (f'"{cmd_str}"' if " " in cmd_str and not cmd_str.startswith('"') else cmd_str)
        if a["arguments"]:
            command += " " + a["arguments"]
        exe = cl.clean_path(cmd_str)
        bare = "\\" not in exe and "/" not in exe
        if bare and a.get("workdir") and os.path.splitext(exe)[1].lower() in (".exe", ".bat", ".cmd", ".vbs", ".js", ".ps1"):
            wd = cl.clean_path(a["workdir"]).rstrip("\\")
            exe = wd + "\\" + exe if wd else exe
        out.append(make_entry("scheduled_task", location, name, command, path=exe, enabled=info.get("enabled", True),
                              author=author, hidden=info.get("hidden", False), run_level=info.get("run_level", ""),
                              user=info.get("user", ""), triggers=info.get("triggers", []), microsoft=microsoft,
                              modifiers=modifiers,
                              remediation={"action": "disable_task", "params": {"name": name},
                                           "description": f"Disable the scheduled task {name}"}))
    return out


def collect_tasks(tasks_dir: Optional[Path] = None) -> List[Entry]:
    tasks_dir = tasks_dir or windows_dir() / "System32" / "Tasks"
    out: List[Entry] = []
    if not tasks_dir.is_dir():
        return out
    for dirpath, _dirs, files in os.walk(tasks_dir, onerror=lambda e: None):
        for fn in files:
            full = Path(dirpath) / fn
            try:
                data = full.read_bytes()
                if len(data) > 2 * 1024 * 1024:
                    continue
                info = parse_task_xml(data)
            except (OSError, ET.ParseError, ValueError) as exc:
                log.debug("cannot parse task %s: %s", full, exc)
                continue
            rel = "\\" + str(full.relative_to(tasks_dir)).replace("/", "\\")
            out.extend(task_entries(rel, str(full), info))
    return out


# --------------------------------------------------------------------------- Windows: hidden scheduled tasks

TASKCACHE_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache"
MAX_TASKCACHE_KEYS = 20000
MAX_TASKCACHE_DEPTH = 32
# Task paths (lower case) that ship without an SD value on a clean Windows install. The Task Scheduler service gives every
# task it registers a security descriptor and none of the public hunting guides (Microsoft's Tarrask analysis, Qualys,
# Binary Defense, Velociraptor) names a built-in task without one, so nothing is allow-listed. Add a path here only after
# confirming it on a clean image; a single finding can also be allow-listed by its fingerprint.
SDLESS_TASK_ALLOWLIST: Set[str] = set()


@dataclass
class TaskKey:
    """One task key under TaskCache\\Tree (a key that has an Id value; folder keys have none)."""

    path: str  # Task Scheduler path, e.g. \Microsoft\Windows\Foo\Bar
    task_id: str  # GUID, also the name of the key under TaskCache\Tasks
    has_sd: bool
    sd_empty: bool = False
    index: Optional[int] = None

    @property
    def registry_key(self) -> str:
        return f"HKLM\\{TASKCACHE_KEY}\\Tree{self.path}"


def collect_task_cache(subkeys: Optional[Callable[[str], List[str]]] = None,
                       values: Optional[Callable[[str], Dict[str, Any]]] = None,
                       limit: int = MAX_TASKCACHE_KEYS) -> Tuple[List[TaskKey], bool]:
    """(task keys, truncated) from TaskCache\\Tree. Folders are subkeys, a task is a key with an Id value. Raises OSError
    when the tree cannot be read (every Windows install has hundreds of tasks), so a read failure never looks like a clean
    machine. Value names are matched case-insensitively."""
    subkeys = subkeys or (lambda key: reg_subkeys("HKLM", key))
    values = values or (lambda key: reg_values("HKLM", key))
    root = TASKCACHE_KEY + "\\Tree"
    first = subkeys(root)
    if not first:
        raise OSError(f"HKLM\\{root} could not be read")
    stack: List[Tuple[str, int]] = [(name, 1) for name in reversed(first)]
    tasks: List[TaskKey] = []
    visited = 0
    truncated = False
    while stack:
        rel, depth = stack.pop()
        if visited >= limit:
            truncated = True
            break
        visited += 1
        key = f"{root}\\{rel}"
        vals = {str(k).lower(): v for k, v in values(key).items()}
        task_id = vals.get("id")
        if isinstance(task_id, str) and task_id.strip():
            index = vals.get("index")
            tasks.append(TaskKey("\\" + rel, task_id.strip(), "sd" in vals, "sd" in vals and not vals["sd"],
                                 index if isinstance(index, int) and not isinstance(index, bool) else None))
        if depth < MAX_TASKCACHE_DEPTH:
            stack.extend((f"{rel}\\{sub}", depth + 1) for sub in reversed(subkeys(key)))
    if not tasks:
        raise OSError(f"HKLM\\{root} holds no readable task keys")
    tasks.sort(key=lambda t: t.path.lower())
    return tasks, truncated


INDEX_ZERO_REASON = "its Index value is 0"


def hidden_task_reasons(t: TaskKey, xml_present: bool = False) -> List[str]:
    """Why a task key is hidden from Task Scheduler / schtasks / Get-ScheduledTask while it keeps running: no (or an empty)
    SD value (the Tarrask technique) or an Index of 0 (documented by Qualys; a missing Index is normal and not reported).
    An Index of 0 counts only for a task outside \\Microsoft\\ whose task file exists: Windows Server 2025 keeps dozens of
    built-in Microsoft tasks with Index 0 and no task file, stale cache entries that are not a sign of tampering."""
    out: List[str] = []
    if t.path.lower() not in SDLESS_TASK_ALLOWLIST:
        if not t.has_sd:
            out.append("it has no SD (security descriptor) value")
        elif t.sd_empty:
            out.append("its SD (security descriptor) value is empty")
    if t.index == 0 and xml_present and not t.path.lower().startswith("\\microsoft\\"):
        out.append(INDEX_ZERO_REASON)
    return out


_ACTION_EXEC = 0x6666
_MAX_ACTION_STRING = 64 * 1024


def _read_bstr(data: bytes, pos: int) -> Optional[Tuple[str, int]]:
    """(text, next position) of the length-prefixed UTF-16LE string at *pos* (DWORD byte count, then the characters)."""
    if pos < 0 or pos + 4 > len(data):
        return None
    size = int.from_bytes(data[pos:pos + 4], "little")
    if size % 2 or size > _MAX_ACTION_STRING or pos + 4 + size > len(data):
        return None
    return data[pos + 4:pos + 4 + size].decode("utf-16-le", errors="replace").rstrip("\x00"), pos + 4 + size


def extract_utf16_strings(blob: Any, limit: int = 24) -> List[str]:
    """Readable strings of a binary registry value that stores text as length-prefixed UTF-16LE (the Task Scheduler's
    layout), found at any byte offset: 3+ printable characters with at least one letter or digit, in order, without repeats.
    Best effort for values whose structure is not parsed (COM handler actions, other Windows builds)."""
    if not isinstance(blob, (bytes, bytearray)):
        return []
    data = bytes(blob)
    out: List[str] = []
    i = 0
    while i + 4 < len(data):
        got = _read_bstr(data, i)
        text = got[0].strip() if got else ""
        if got and len(text) >= 3 and text.isprintable() and any(c.isalnum() for c in text):
            if text not in out:
                out.append(text)
            i = got[1]
        else:
            i += 1
    return out[:limit]


def parse_task_actions(blob: Any) -> List[Dict[str, str]]:
    """Exec actions of a TaskCache\\Tasks\\{Id} Actions value: a WORD version, a length-prefixed context string, then
    actions that each start with a WORD magic. Exec (0x6666) carries id, command, arguments and working-directory strings
    and, from version 3, a WORD of flags. [] when the layout is not recognised; other action kinds (COM handler, e-mail,
    message box) end the parse."""
    if not isinstance(blob, (bytes, bytearray)) or len(blob) < 6:
        return []
    data = bytes(blob)
    version = int.from_bytes(data[:2], "little")
    got = _read_bstr(data, 2)  # context: the principal the actions run as
    if got is None:
        return []
    pos = got[1]
    out: List[Dict[str, str]] = []
    while pos + 2 <= len(data) and int.from_bytes(data[pos:pos + 2], "little") == _ACTION_EXEC:
        pos += 2
        fields: List[str] = []  # id, command, arguments, working directory
        for _ in range(4):
            got = _read_bstr(data, pos)
            if got is None:
                return out
            fields.append(got[0])
            pos = got[1]
        if version >= 3:
            pos += 2
        out.append({"kind": "Exec", "command": fields[1], "arguments": fields[2], "workdir": fields[3]})
    return out


def describe_task_actions(blob: Any) -> Tuple[str, List[str]]:
    """(command, readable strings) of an Actions value: the first Exec action as 'command arguments', else the first
    program-looking string."""
    strings = extract_utf16_strings(blob)
    for a in parse_task_actions(blob):
        if a["command"].strip():
            return f"{a['command'].strip()} {a['arguments'].strip()}".strip()[:500], strings
    for s in strings:
        if re.search(r"\.(?:exe|bat|cmd|com|ps1|vbs|js|hta|scr|dll|msi)\b", s, re.I) or ("\\" in s and ":" in s):
            return s[:500], strings
    return "", strings


def task_xml_path(task_path: str) -> str:
    return f"{windows_dir()}\\System32\\Tasks{task_path}"


def hidden_task_findings(tasks: Sequence[TaskKey], read_actions: Optional[Callable[[str], Any]] = None,
                         xml_exists: Optional[Callable[[str], bool]] = None) -> List[Finding]:
    """A finding for every task that Task Scheduler cannot list but Windows still runs: HIGH for a missing or empty SD,
    MEDIUM when the only sign is an Index of 0. No automatic fix: restoring an SD or deleting the keys blindly would destroy
    the evidence of a compromise."""
    read_actions = read_actions or (lambda tid: None if "\\" in tid or "/" in tid else
                                    reg_read("HKLM", f"{TASKCACHE_KEY}\\Tasks\\{tid}", "Actions"))
    xml_exists = xml_exists or os.path.isfile
    out: List[Finding] = []
    for t in tasks:
        if t.has_sd and not t.sd_empty and t.index != 0:
            continue  # the common case: no file system access
        xml = task_xml_path(t.path)
        try:
            xml_present = bool(xml_exists(xml))
        except OSError:
            xml_present = False
        reasons = hidden_task_reasons(t, xml_present)
        if not reasons:
            continue
        command, strings = describe_task_actions(read_actions(t.task_id))
        tasks_key = f"HKLM\\{TASKCACHE_KEY}\\Tasks\\{t.task_id}"
        out.append(Finding(
            "AEG-PERS-TASK-HIDDEN", f"Hidden scheduled task: {t.path}",
            Severity.MEDIUM if reasons == [INDEX_ZERO_REASON] else Severity.HIGH, Category.PERSISTENCE,
            f"The scheduled task {t.path} is registered in the Task Scheduler cache but {' and '.join(reasons)}. That keeps it "
            "out of Task Scheduler, 'schtasks /query' and Get-ScheduledTask while Windows still runs it - a technique used by "
            "the Tarrask malware (HAFNIUM) and other attackers to hide persistence. Tasks registered normally have a security "
            "descriptor and, when they have an Index, one above zero."
            + (f" It runs: {command}." if command else " Its command could not be read.")
            + (" Its task file exists." if xml_present else " Its task file under System32\\Tasks is missing."),
            t.registry_key,
            {"task": t.path, "task_id": t.task_id, "registry_key": t.registry_key, "tasks_key": tasks_key, "problems": reasons,
             "has_sd": t.has_sd, "index": t.index, "command": command, "action_strings": strings[:8], "xml_file": xml,
             "xml_file_exists": xml_present},
            "Treat this as a likely compromise and run a full scan. Inspect it with: reg query \"" + t.registry_key + "\" /s and "
            "reg query \"" + tasks_key + "\" /v Actions, then check the program it starts. To remove it, first export both keys "
            "(reg export), then delete the Tree key, the Tasks key and the task file (this normally needs SYSTEM rights, for "
            "example from a SYSTEM shell) and restart Windows so the Task Scheduler drops its in-memory copy. Aegis does not fix "
            "this automatically.",
            None, scanner="persistence", mitre=["T1053.005", "T1564"]))
    return out


# --------------------------------------------------------------------------- Windows: services

SERVICES_KEY = r"SYSTEM\CurrentControlSet\Services"
KNOWN_ATTACK_SERVICES = {"psexesvc": "PsExec service", "paexec": "PAExec service", "remcom": "RemCom service",
                         "csexecsvc": "Cobalt/Csexec service", "winexesvc": "winexe service", "hacktool": "hack tool"}
_SVC_TYPES = {0x1, 0x2, 0x10, 0x20, 0x50, 0x60}


def service_reasons(name: str, svc_type: int, imagepath: str, service_dll: str, start: int) -> List[Dict[str, Any]]:
    out = []
    low = name.lower()
    if low in KNOWN_ATTACK_SERVICES:
        out.append(meta_reason(Severity.MEDIUM, f"{KNOWN_ATTACK_SERVICES[low]} is installed - used by admins but also for lateral movement", ["T1569.002", "T1021.002"]))
    target = service_dll or cl.extract_executable(imagepath) or ""
    is_driver = bool(svc_type & 0x3)
    if is_driver and target and cl.path_risk(target) > 0:
        out.append(meta_reason(Severity.HIGH, f"Kernel driver loaded from a user-writable location: {target}", ["T1543.003", "T1014"]))
    if service_dll and cl.is_windows_style(service_dll):
        d = cl.clean_path(service_dll)
        if not (cl.is_in_windir(d) or cl.is_in_program_files(d)) and cl.path_risk(d) == 0:
            out.append(meta_reason(Severity.MEDIUM, f"svchost-hosted service DLL outside Windows/Program Files: {service_dll}", ["T1543.003", "T1574.011"]))
    return out


def collect_services() -> List[Entry]:
    out: List[Entry] = []
    for sub, vals in _walk_services():
        entry = service_entry(sub, vals, reg_values("HKLM", f"{SERVICES_KEY}\\{sub}\\Parameters")
                              if "svchost" in str(vals.get("ImagePath", "")).lower() else {})
        if entry:
            out.append(entry)
    return out


def _walk_services() -> Iterable[Tuple[str, Dict[str, Any]]]:
    for sub in reg_subkeys("HKLM", SERVICES_KEY):
        yield sub, reg_values("HKLM", f"{SERVICES_KEY}\\{sub}")


def service_entry(name: str, vals: Dict[str, Any], params: Dict[str, Any]) -> Optional[Entry]:
    image = vals.get("ImagePath")
    stype = vals.get("Type")
    if not isinstance(image, str) or not image.strip() or not isinstance(stype, int):
        return None
    if (stype & ~0x100) not in _SVC_TYPES:
        return None
    start = vals.get("Start") if isinstance(vals.get("Start"), int) else 3
    dll = params.get("ServiceDll") if isinstance(params.get("ServiceDll"), str) else ""
    dll = cl.clean_path(dll) if dll else ""
    path = dll or (cl.extract_executable(image) or "")
    return make_entry("service", f"HKLM\\{SERVICES_KEY}\\{name}", name, image.strip(), path=path, enabled=start != 4,
                      svc_type=stype, start=start, user=str(vals.get("ObjectName") or ""), display=str(vals.get("DisplayName") or ""),
                      reasons=service_reasons(name, stype, image, dll, start),
                      remediation={"action": "disable_service", "params": {"name": name},
                                   "description": f"Stop and disable the service {name}"})


# --------------------------------------------------------------------------- Windows: WMI

WMI_SCRIPT = (
    "$f=@(Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -ErrorAction SilentlyContinue | "
    "ForEach-Object { [pscustomobject]@{Name=$_.Name;Query=$_.Query;EventNamespace=$_.EventNamespace} });"
    "$c=@(Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue | "
    "ForEach-Object { [pscustomobject]@{Name=$_.Name;Class=$_.CimClass.CimClassName;CommandLineTemplate=$_.CommandLineTemplate;"
    "ExecutablePath=$_.ExecutablePath;ScriptText=$_.ScriptText;ScriptingEngine=$_.ScriptingEngine;ScriptFileName=$_.ScriptFileName} });"
    "$b=@(Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | "
    "ForEach-Object { [pscustomobject]@{Filter=$_.Filter.Name;Consumer=$_.Consumer.Name} });"
    "[pscustomobject]@{Filters=$f;Consumers=$c;Bindings=$b} | ConvertTo-Json -Depth 4 -Compress")

_WMI_BENIGN = {"scm event log consumer", "scm event log filter"}


def wmi_entries(data: Any) -> List[Entry]:
    """Entries from the root/subscription JSON; command/script consumers are HIGH."""
    out: List[Entry] = []
    if not isinstance(data, dict):
        return out
    filters = {str(f.get("Name")): f for f in as_list(data.get("Filters")) if isinstance(f, dict)}
    bindings = [b for b in as_list(data.get("Bindings")) if isinstance(b, dict)]
    for c in as_list(data.get("Consumers")):
        if not isinstance(c, dict):
            continue
        name = str(c.get("Name") or "")
        cls = str(c.get("Class") or "")
        if name.lower() in _WMI_BENIGN or cls == "NTEventLogEventConsumer":
            continue
        bound = [str(b.get("Filter")) for b in bindings if str(b.get("Consumer")) == name]
        queries = [str(filters.get(f, {}).get("Query") or "") for f in bound]
        if cls == "CommandLineEventConsumer":
            command = str(c.get("CommandLineTemplate") or c.get("ExecutablePath") or "")
            sev, text = Severity.HIGH, f"WMI CommandLineEventConsumer executes: {command[:150]}"
        elif cls == "ActiveScriptEventConsumer":
            command = str(c.get("ScriptFileName") or c.get("ScriptText") or "")[:300]
            sev, text = Severity.HIGH, f"WMI ActiveScriptEventConsumer runs {c.get('ScriptingEngine') or 'script'} code: {command[:120]}"
        else:
            command = cls
            sev, text = Severity.LOW, f"Unusual WMI event consumer ({cls})"
        out.append(make_entry("wmi_subscription", "root\\subscription", name, command,
                              path=None if cls == "CommandLineEventConsumer" else "",
                              reasons=[meta_reason(sev, text, ["T1546.003"])], filter_query="; ".join(q for q in queries if q)[:400],
                              filters=bound,
                              remediation={"action": "remove_wmi_subscription", "params": {"name": name},
                                           "description": f"Remove WMI subscription objects named {name}"}))
    return out


def collect_wmi() -> List[Entry]:
    return wmi_entries(powershell_json(WMI_SCRIPT, timeout=60))


# --------------------------------------------------------------------------- Linux / macOS

@dataclass
class LinuxPaths:
    etc: Path = Path("/etc")
    spool: Tuple[Path, ...] = (Path("/var/spool/cron"), Path("/var/spool/cron/crontabs"))
    homes: Tuple[Path, ...] = ()
    root: Optional[Path] = None  # where absolute locations (/usr/lib, /var/spool ...) live; default: the parent of etc

    def __post_init__(self) -> None:
        if not self.homes:
            self.homes = tuple(discover_homes())
        if self.root is None:
            self.root = Path("/") if self.etc == Path("/etc") else self.etc.parent

    @property
    def is_real(self) -> bool:
        return self.root is None or self.root == Path("/")

    def at(self, logical: str) -> Path:
        """Where an absolute location such as /usr/lib/security lives in this tree (itself on a real system)."""
        if logical == "/etc" or logical.startswith("/etc/"):
            return self.etc / logical[5:]
        return (self.root or Path("/")) / logical.lstrip("/")


def discover_homes() -> List[Path]:
    homes: List[Path] = []
    try:
        homes.append(user_home())
    except Exception:
        pass
    for base in ("/home", "/Users"):
        try:
            homes += [p for p in Path(base).iterdir() if p.is_dir()]
        except OSError:
            pass
    if Path("/root").is_dir():
        homes.append(Path("/root"))
    seen, out = set(), []
    for h in homes:
        if str(h) not in seen:
            seen.add(str(h))
            out.append(h)
    return out


def _read_text(path: Path, limit: int = MAX_TEXT) -> Optional[str]:
    try:
        if path.is_symlink() and not path.exists():
            return None
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            return fh.read(limit)
    except OSError:
        return None


_CRON_SPECIAL = {"@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight", "@hourly"}
_ENV_LINE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=")


def parse_crontab(text: str, system: bool = False) -> List[Tuple[str, str, str]]:
    """Parse a crontab; returns (schedule, user, command). *system* = /etc/crontab format with a user column."""
    out = []
    for line in logical_lines(text):
        if _ENV_LINE.match(line) and not line.split(None, 1)[0].startswith("@"):
            continue
        if line.startswith("@"):
            parts = line.split(None, 2 if system else 1)
            if parts[0].lower() not in _CRON_SPECIAL:
                continue
            if system and len(parts) == 3:
                out.append((parts[0], parts[1], parts[2]))
            elif not system and len(parts) == 2:
                out.append((parts[0], "", parts[1]))
        else:
            parts = line.split(None, 6 if system else 5)
            need = 7 if system else 6
            if (len(parts) < need or not re.search(r"[\d*?]", parts[0])
                    or not all(re.fullmatch(r"[0-9*/,\-?A-Za-z]+", x) for x in parts[:5])):
                continue
            out.append((" ".join(parts[:5]), parts[5] if system else "", parts[need - 1]))
    return out


_ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=\S*$")
_WRAPPERS = {"sudo", "nohup", "exec", "env", "nice", "ionice", "flock", "timeout", "setsid", "time", "chronic", "run-parts"}


def posix_target(command: str) -> str:
    """Best-effort program path of a shell command (skips env assignments, cd x &&, nohup/nice/flock ...)."""
    for segment in re.split(r"&&|;|\|\||\|", command):
        toks = segment.strip().split()
        i = 0
        while i < len(toks):
            t = toks[i].strip("\"'")
            if _ENV_ASSIGN.match(t) or t in ("cd", "export", "test", "[", "!"):
                i += 2 if t == "cd" else 1
                continue
            if t in _WRAPPERS:
                i += 1
                while i < len(toks) and (toks[i].startswith("-") or re.match(r"^\d+[smhd]?$", toks[i])):
                    i += 1
                continue
            if t.startswith(("/", "./", "~")):
                return os.path.expanduser(t)
            break
    return ""


def collect_cron(paths: LinuxPaths) -> List[Entry]:
    out: List[Entry] = []
    files: List[Tuple[Path, bool]] = [(paths.etc / "crontab", True)]
    cron_d = paths.etc / "cron.d"
    try:
        files += [(p, True) for p in sorted(cron_d.iterdir()) if p.is_file()]
    except OSError:
        pass
    for sp in paths.spool:
        try:
            files += [(p, False) for p in sorted(sp.iterdir()) if p.is_file()]
        except OSError:
            pass
    for f, system in files:
        text = _read_text(f)
        if text is None:
            continue
        for sched, user, command in parse_crontab(text, system):
            out.append(make_entry("cron", str(f), f"{sched} {user}".strip(), command, path=posix_target(command)))
    for period in ("hourly", "daily", "weekly", "monthly"):
        d = paths.etc / f"cron.{period}"
        try:
            for p in sorted(d.iterdir()):
                if p.is_file() and not p.is_symlink():
                    text = _read_text(p)
                    if text is not None:
                        out.append(make_entry("cron_script", str(d), p.name, "sha1:" + hashlib.sha1(text.encode("utf-8", "replace")).hexdigest(),
                                              path=str(p), text=text))
        except OSError:
            pass
    return out


_EXEC_DIRECTIVES = ("ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecReload", "ExecCondition")


def parse_unit_exec(text: str) -> List[Tuple[str, str]]:
    """(directive, command) for Exec* lines of a systemd unit (modifier prefixes stripped)."""
    out = []
    section = ""
    for line in logical_lines(text):
        if line.startswith("[") and line.endswith("]"):
            section = line.strip("[]")
            continue
        if section != "Service" or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        if key not in _EXEC_DIRECTIVES:
            continue
        val = val.strip().lstrip("@-:+!").strip()
        if val:
            out.append((key, val))
    return out


def collect_systemd(paths: LinuxPaths) -> List[Entry]:
    out: List[Entry] = []
    roots = [paths.etc / "systemd" / "system"] + [h / ".config" / "systemd" / "user" for h in paths.homes]
    for root in roots:
        for dirpath, dirnames, files in os.walk(root, followlinks=False):
            for fn in files:
                if not fn.endswith(".service"):
                    continue
                f = Path(dirpath) / fn
                if f.is_symlink():  # enablement symlinks / masked units
                    continue
                text = _read_text(f)
                if text is None:
                    continue
                for directive, command in parse_unit_exec(text):
                    out.append(make_entry("systemd", str(f), f"{fn} {directive}", command, path=posix_target(command)))
    return out


def collect_rc_local(paths: LinuxPaths) -> List[Entry]:
    out = []
    for f in (paths.etc / "rc.local", paths.etc / "rc.d" / "rc.local"):
        text = _read_text(f)
        if text is not None and logical_lines(text):
            out.append(make_entry("rc_local", str(f), f.name, "sha1:" + hashlib.sha1(text.encode("utf-8", "replace")).hexdigest(),
                                  path=str(f), text=text))
    return out


SHELL_RC_NAMES = (".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zprofile", ".zshenv", ".bash_logout")


def collect_shell_rc(paths: LinuxPaths) -> List[Entry]:
    out = []
    files = [paths.etc / "profile", paths.etc / "bash.bashrc", paths.etc / "bashrc", paths.etc / "zsh" / "zshrc",
             paths.etc / "zshrc", paths.etc / "environment"]
    try:
        files += sorted((paths.etc / "profile.d").iterdir())
    except OSError:
        pass
    for h in paths.homes:
        files += [h / n for n in SHELL_RC_NAMES]
    for f in files:
        try:
            if not f.is_file():
                continue
        except OSError:  # another user's home that this account cannot enter (is_file re-raises EACCES before Python 3.13)
            continue
        text = _read_text(f)
        if text is None:
            continue
        out.append(make_entry("shell_rc", str(f.parent), f.name, "sha1:" + hashlib.sha1(text.encode("utf-8", "replace")).hexdigest(),
                              path=str(f), text=text))
    return out


LD_PRELOAD_ALLOW = ("gtk3-nocsd", "libfakeroot", "libfakechroot", "libeatmydata", "libhugetlbfs", "libgtk3-nocsd")


def collect_ld_preload(paths: LinuxPaths) -> List[Entry]:
    f = paths.etc / "ld.so.preload"
    text = _read_text(f)
    out = []
    if text is None:
        return out
    for line in logical_lines(text):
        for lib in line.split():
            allowed = any(a in lib for a in LD_PRELOAD_ALLOW)
            reasons = [] if allowed else [meta_reason(
                Severity.HIGH, f"{lib} is force-loaded into every process via /etc/ld.so.preload (userland rootkit technique)", ["T1574.006"])]
            out.append(make_entry("ld_preload", str(f), lib, lib, path=lib, reasons=reasons))
    return out


_KEY_TYPES = r"(?:ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-nistp\d+|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)"
_KEY_LINE = re.compile(rf"^(?P<opts>.*?)\s*(?P<type>{_KEY_TYPES})\s+(?P<blob>[A-Za-z0-9+/=]+)\s*(?P<comment>.*)$")


def parse_authorized_keys(text: str) -> List[Dict[str, str]]:
    out = []
    for line in logical_lines(text):
        m = _KEY_LINE.match(line)
        if m:
            out.append({"options": m.group("opts").strip(), "type": m.group("type"), "blob": m.group("blob"),
                        "comment": m.group("comment").strip()})
    return out


def _forced_command(options: str) -> str:
    m = re.search(r'command="((?:[^"\\]|\\.)*)"', options)
    return m.group(1).replace('\\"', '"') if m else ""


def collect_ssh_keys(paths: LinuxPaths, many: int = 8) -> List[Entry]:
    out = []
    for h in paths.homes:
        f = h / ".ssh" / "authorized_keys"
        text = _read_text(f)
        if text is None:
            continue
        keys = parse_authorized_keys(text)
        for i, k in enumerate(keys):
            fp = hashlib.sha256(k["blob"].encode()).hexdigest()[:16]
            forced = _forced_command(k["options"])
            reasons = []
            if forced:
                reasons.append(meta_reason(Severity.LOW, f"key has a forced command: {forced[:100]}", ["T1098.004"]))
            if i == 0 and len(keys) > many:
                reasons.append(meta_reason(Severity.LOW, f"unusually many authorized keys ({len(keys)})", ["T1098.004"]))
            out.append(make_entry("ssh_key", str(f), k["comment"] or f"{k['type']}:{fp}", forced or f"{k['type']} {fp}",
                                  path="", reasons=reasons, fingerprint=fp))
    return out


_UDEV_RUN = re.compile(r'\bRUN(?:\{[^}]*\})?\s*\+?=\s*"([^"]+)"')


def parse_udev_rules(text: str) -> List[str]:
    return [m.group(1) for line in logical_lines(text) for m in _UDEV_RUN.finditer(line)]


def collect_udev(paths: LinuxPaths) -> List[Entry]:
    out = []
    for d in (paths.etc / "udev" / "rules.d",):
        try:
            for f in sorted(d.iterdir()):
                if f.suffix == ".rules":
                    text = _read_text(f)
                    for cmd in parse_udev_rules(text or ""):
                        out.append(make_entry("udev", str(f), f.name, cmd, path=posix_target(cmd) or ""))
        except OSError:
            pass
    return out


def parse_desktop_entry(text: str) -> Dict[str, str]:
    d: Dict[str, str] = {}
    section = ""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("["):
            section = line
        elif "=" in line and section == "[Desktop Entry]" and not line.startswith("#"):
            k, _, v = line.partition("=")
            d.setdefault(k.strip(), v.strip())
    return d


def collect_xdg_autostart(paths: LinuxPaths) -> List[Entry]:
    out = []
    dirs = [paths.etc / "xdg" / "autostart"] + [h / ".config" / "autostart" for h in paths.homes]
    for d in dirs:
        try:
            for f in sorted(d.iterdir()):
                if f.suffix != ".desktop":
                    continue
                text = _read_text(f)
                if not text:
                    continue
                de = parse_desktop_entry(text)
                exe = re.sub(r"\s%[a-zA-Z]", "", de.get("Exec", "")).strip()
                if not exe:
                    continue
                enabled = de.get("Hidden", "").lower() != "true" and de.get("X-GNOME-Autostart-enabled", "true").lower() != "false"
                out.append(make_entry("xdg_autostart", str(d), f.name, exe, path=posix_target(exe), enabled=enabled))
        except OSError:
            pass
    return out


# --------------------------------------------------------------------------- Linux / macOS: PAM, motd, generators, at

MAX_DIR_ENTRIES = 1000
MAX_PAM_MODULES = 500


def _dir_files(d: Path) -> List[Path]:
    """Files (and dangling links) directly inside *d*, sorted and capped; [] when it is missing or unreadable."""
    try:
        return sorted(p for p in itertools.islice(d.iterdir(), MAX_DIR_ENTRIES) if not p.is_dir())
    except OSError:
        return []


def _text_digest(text: str) -> str:
    return "sha1:" + hashlib.sha1(text.encode("utf-8", "replace")).hexdigest()


def _is_exec(p: Path) -> bool:
    try:
        return bool(p.stat().st_mode & 0o111)
    except OSError:
        return False


def _is_mask(p: Path) -> bool:
    """A symlink to /dev/null: how systemd (and run-parts users) switch a file off without deleting it."""
    try:
        return p.is_symlink() and os.readlink(p) == "/dev/null"
    except OSError:
        return False


def _join_args(args: Sequence[str]) -> str:
    return " ".join(f'"{a}"' if " " in a else a for a in args)


def _script_entries(files: Iterable[Path], type_: str, require_exec: bool = True) -> List[Entry]:
    """Script files whose *content* is judged (TEXT_TYPES); a file that is not executable is listed but not run."""
    out = []
    for f in files:
        text = None if _is_mask(f) else _read_text(f)
        if text is not None:
            out.append(make_entry(type_, str(f.parent), f.name, _text_digest(text), path=str(f),
                                  enabled=_is_exec(f) or not require_exec, text=text))
    return out


def collect_motd(paths: LinuxPaths) -> List[Entry]:
    """/etc/update-motd.d: run-parts executes these as root on every SSH/console login (pam_motd)."""
    return _script_entries(_dir_files(paths.etc / "update-motd.d"), "motd")


GENERATOR_DIRS = tuple(f"{base}/{kind}-generators" for kind in ("system", "user")
                       for base in ("/etc/systemd", "/usr/local/lib/systemd", "/run/systemd"))


def collect_generators(paths: LinuxPaths) -> List[Entry]:
    """systemd generators outside the distribution directories (/usr/lib, /lib are package-owned and not listed).

    systemd runs every executable in these directories as root, before any unit, and lets it write units at will;
    distributions do not ship anything there, so every entry is at least LOW. A symlink to /dev/null is a mask."""
    out = []
    for logical in GENERATOR_DIRS:
        d = paths.at(logical)
        for f in _dir_files(d):
            if _is_mask(f):
                continue
            target = os.path.realpath(f) if f.is_symlink() else str(f)
            reasons = [meta_reason(Severity.LOW, f"systemd generator in {logical}: it runs as root before any service starts and "
                                                 "can create units; distributions do not ship generators here", ["T1543.002"])]
            out.append(make_entry("systemd_generator", str(d), f.name, str(f), path=target, enabled=_is_exec(f), reasons=reasons))
    return out


AT_SPOOLS = ("/var/spool/cron/atjobs", "/var/spool/at", "/var/spool/atjobs", "/usr/lib/cron/jobs")


def collect_at_jobs(paths: LinuxPaths) -> List[Entry]:
    """Pending at(1) jobs: each file is a shell script that atd runs once (Linux spools; macOS /usr/lib/cron/jobs)."""
    out: List[Entry] = []
    seen: Set[str] = set()
    for logical in AT_SPOOLS:
        d = paths.at(logical)
        real = os.path.realpath(d)
        if real not in seen:
            seen.add(real)
            out += _script_entries((f for f in _dir_files(d) if f.name != ".SEQ"), "at_job", require_exec=False)
    return out


# PAM ------------------------------------------------------------------------

@dataclass
class PamRule:
    stack: str  # auth | account | password | session; "*" for an @include of a whole file
    control: str  # required | requisite | sufficient | optional | include | substack | [value=action ...] | @include
    module: str  # module name or path; for include/substack/@include the pam.d file to pull in
    args: str
    service: str  # the /etc/pam.d file the line is in
    dash: bool = False  # `-session ...`: do not log a missing module


_PAM_RULE = re.compile(r"^(?P<dash>-)?(?P<stack>auth|account|password|session)\s+(?P<control>\[[^\]]*\]|\S+)\s+(?P<module>\S+)"
                       r"\s*(?P<args>.*)$", re.I)


def parse_pam_conf(text: str, service: str = "") -> List[PamRule]:
    """Rules of one /etc/pam.d file: ``[-]type control module [args]`` (control may be ``[success=1 default=ignore]``)
    and Debian's ``@include name``. Comments and blank lines are dropped, backslash continuations joined."""
    out = []
    for line in logical_lines(text):
        line = re.split(r"\s#", line, maxsplit=1)[0].strip()
        if line.startswith("@include"):
            parts = line.split()
            if len(parts) >= 2:
                out.append(PamRule("*", "@include", parts[1], "", service))
            continue
        m = _PAM_RULE.match(line)
        if m:
            out.append(PamRule(m.group("stack").lower(), m.group("control"), m.group("module"), " ".join(m.group("args").split()),
                               service, bool(m.group("dash"))))
    return out


# What `required`, `requisite`, `sufficient` and `optional` mean as [value=action] tables (pam.conf(5)).
_PAM_SIMPLE: Dict[str, Dict[str, str]] = {
    "required": {"success": "ok", "new_authtok_reqd": "ok", "ignore": "ignore", "default": "bad"},
    "requisite": {"success": "ok", "new_authtok_reqd": "ok", "ignore": "ignore", "default": "die"},
    "sufficient": {"success": "done", "new_authtok_reqd": "done", "default": "ignore"},
    "optional": {"success": "ok", "new_authtok_reqd": "ok", "default": "ignore"},
}
# Modules that never check a credential and succeed for any ordinary login attempt (gates, environment, bookkeeping).
_PAM_NEUTRAL = frozenset({
    "pam_env", "pam_faildelay", "pam_nologin", "pam_limits", "pam_keyinit", "pam_umask", "pam_motd", "pam_mail", "pam_lastlog",
    "pam_lastlog2", "pam_loginuid", "pam_selinux", "pam_systemd", "pam_succeed_if", "pam_access", "pam_time", "pam_securetty",
    "pam_shells", "pam_listfile", "pam_group", "pam_cap", "pam_namespace", "pam_xauth", "pam_echo", "pam_warn", "pam_issue",
    "pam_tty_audit", "pam_localuser", "pam_usertype", "pam_faillock", "pam_tally", "pam_tally2", "pam_gnome_keyring",
    "pam_kwallet", "pam_kwallet5", "pam_ecryptfs", "pam_mount", "pam_console", "pam_sepermit", "pam_launchd", "pam_uwtmp"})
# Interactive login services whose auth stack must be able to say no (autologin, greeter and system-services stacks
# legitimately consist of pam_permit.so alone, Arch's system-services even has `auth sufficient pam_permit.so`).
PAM_LOGIN_SERVICES = ("common-auth", "system-auth", "password-auth", "sshd", "sudo", "sudo-i", "login", "su", "su-l", "other",
                      "system-login", "system-local-login", "system-remote-login")


def _pam_stem(module: str) -> str:
    """pam_unix for pam_unix.so, /lib/security/pam_unix.so and pam_unix.so.2 alike."""
    return re.sub(r"\.so(?:\.\d+)*$", "", cl.basename(module).lower())


def pam_control_actions(control: str) -> Dict[str, str]:
    """{return code: action} of a simple or ``[value=action ...]`` control; "default" covers every other code."""
    c = control.strip()
    if not c.startswith("["):
        return _PAM_SIMPLE.get(c.lower(), _PAM_SIMPLE["required"])
    acts = {k.lower(): v.lower() for k, _, v in (tok.partition("=") for tok in c.strip("[]").split()) if v}
    acts.setdefault("default", "bad")
    return acts


def pam_stack(service: str, stack: str, load: Callable[[str], Optional[List[PamRule]]], depth: int = 0) -> List[Any]:
    """The *stack* rules that apply to *service*: ``@include`` and ``include`` inlined, ``substack`` kept as a nested list."""
    out: List[Any] = []
    for r in load(service) or []:
        control = r.control.lower()
        if r.control == "@include" or (r.stack == stack and control in ("include", "substack")):
            if depth < 8:  # include loops
                sub = pam_stack(r.module, stack, load, depth + 1)
                if control == "substack":
                    out.append(sub)
                else:
                    out += sub
        elif r.stack == stack:
            out.append(r)
    return out


def pam_stack_passes(items: Sequence[Any], trace: List[PamRule]) -> bool:
    """Replay a stack (from pam_stack) as Linux-PAM evaluates it for someone who knows no credential.

    pam_permit.so and the modules in _PAM_NEUTRAL succeed, every other module fails. Returns True when the stack still
    lets that person in; the pam_permit.so rules that contributed to the success are appended to *trace*."""
    impression, status = "undef", "fail"
    i = 0
    while i < len(items):
        item = items[i]
        i += 1
        rule: Optional[PamRule] = None
        if isinstance(item, list):  # a substack counts as one `required` module
            retval, acts = ("success" if pam_stack_passes(item, trace) else "auth_err"), _PAM_SIMPLE["required"]
        else:
            rule, stem = item, _pam_stem(item.module)
            retval = "success" if stem == "pam_permit" or stem in _PAM_NEUTRAL else "auth_err"
            acts = pam_control_actions(item.control)
        action = acts.get(retval, acts["default"])
        if action == "ignore":
            continue
        if action == "reset":
            impression, status = "undef", "fail"
        elif action in ("bad", "die"):
            if impression != "neg":
                impression, status = "neg", "fail"
            if action == "die":
                return False
        elif action in ("ok", "done") or action.isdigit():  # a number is ok plus skipping that many modules
            if impression == "undef" or (impression == "pos" and status == "success"):
                impression, status = "pos", retval
                if rule is not None and _pam_stem(rule.module) == "pam_permit":
                    trace.append(rule)
            if action == "done" and impression == "pos":
                return status == "success"
            if action.isdigit():
                i += int(action)
    return impression == "pos" and status == "success"


def pam_bypass_rules(services: Dict[str, List[PamRule]]) -> Dict[int, Tuple[PamRule, Set[str]]]:
    """pam_permit.so lines that let anyone through the auth stack of a login service: {id(rule): (rule, services)}.

    pam_permit.so always succeeds, so its presence proves nothing: every Debian/Ubuntu common-auth ends in
    ``auth required pam_permit.so``, Arch's system-auth has ``auth optional pam_permit.so``. What matters is whether the
    stack can still say no. Each service in PAM_LOGIN_SERVICES is therefore replayed (pam_stack_passes) for someone who
    knows no credential, with the real control semantics (bracket actions, jumps, done/die, includes, substack).
    Debian's ``[success=1 default=ignore] pam_unix.so`` / ``requisite pam_deny.so`` / ``required pam_permit.so`` fails at
    pam_deny, Red Hat's ``sufficient pam_unix.so`` ... ``required pam_deny.so`` fails at pam_deny, Arch's ends in
    ``[default=die] pam_faillock.so authfail``: none of the defaults is reported. A pam_permit.so line is reported only
    when the replay *succeeds* and that line contributed to it: ``auth sufficient pam_permit.so`` anywhere before the real
    modules, or a stack whose last word is ``pam_permit.so`` with nothing that can fail after the credential check
    (``sufficient pam_unix.so`` followed by ``required pam_permit.so``, ``optional pam_unix.so`` ...)."""

    def load(name: str) -> Optional[List[PamRule]]:
        return services.get(posixpath.basename(name))

    found: Dict[int, Tuple[PamRule, Set[str]]] = {}
    for service in PAM_LOGIN_SERVICES:
        trace: List[PamRule] = []
        if service in services and pam_stack_passes(pam_stack(service, "auth", load), trace):
            for r in trace:
                found.setdefault(id(r), (r, set()))[1].add(service)
    return found


# Where a module can sit without raising a question: /lib*/security, /usr/lib*/security, /lib/*/security,
# /usr/lib/*/security, macOS /usr/lib/pam and the immutable Nix/Guix stores that NixOS writes into pam.d.
_PAM_STD_DIR = re.compile(r"^(?:/usr)?/lib(?:32|64|x32)?(?:/[^/]+)?/security$|^/usr/lib/pam$"
                          r"|^/(?:nix|gnu)/store/[^/]+/lib/security$|^/run/current-system/sw/lib/security$")
_PAM_EXEC_OPTIONS = ("debug", "expose_authtok", "seteuid", "quiet", "quiet_log", "stdout")


def pam_exec_command(args: str) -> str:
    """The program (and its arguments) a pam_exec.so line runs: the arguments minus pam_exec's own options."""
    toks = args.split()
    while toks and (toks[0] in _PAM_EXEC_OPTIONS or toks[0].startswith(("log=", "type="))):
        toks.pop(0)
    return " ".join(toks)


def risky_unix_path(path: str, real: Optional[Path] = None) -> bool:
    """A place a root-run program should not live: temp dirs, hidden dirs, home folders, anything world-writable.

    *real* is where the path is on disk (differs from *path* only in a test tree); its mode is checked too."""
    if path.startswith("~") or cl.path_risk(path) > 0 or path.startswith(("/home/", "/root/", "/Users/")):
        return True
    if re.search(r"/\.[^/.]", path):
        return True
    for p in (real, real.parent if real else None):
        try:
            if p is not None and p.stat().st_mode & 0o002:
                return True
        except OSError:
            pass
    return False


@functools.lru_cache(maxsize=1)
def _package_tool() -> Optional[str]:
    """"dpkg" or "rpm" when that tool is installed and its database answers (probed once with the tool's own binary)."""
    for tool in ("dpkg", "rpm"):
        exe = shutil.which(tool)
        if exe and _query_owned(tool, exe, [exe]):
            return tool
    return None


def _path_variants(path: str) -> Set[str]:
    """The spellings a package database may know a file under (/lib vs /usr/lib on merged-/usr systems, symlinks)."""
    out = {path, os.path.realpath(path)}
    for p in list(out):
        if p.startswith("/usr/") and p[4:].startswith(("/lib", "/bin", "/sbin")):
            out.add(p[4:])
        elif p.startswith(("/lib", "/bin", "/sbin")):
            out.add("/usr" + p)
    return out


def _query_owned(tool: str, exe: str, files: Sequence[str]) -> Optional[Set[str]]:
    """Subset of *files* that *tool* says belong to a package (one batched query); None when it cannot answer."""
    variants = {f: _path_variants(f) for f in files}
    flat = sorted(set().union(*variants.values()))
    if tool == "dpkg":
        rc, out, _err = run([exe, "-S", "--"] + flat, timeout=20)
        if rc not in (0, 1):  # 1 = some paths are not owned
            return None
        lines = [ln for ln in out.splitlines() if ": /" in ln and not ln.startswith("diversion")]
        found = {"/" + ln.rpartition(": /")[2] for ln in lines}
    else:
        rc, out, _err = run([exe, "-qf", "--qf", "%{NAME}\\n", "--"] + flat, timeout=20)
        if rc == -1 or not out.strip():
            return None
        found = set(flat) - set(re.findall(r"^file (.+) is not owned by any package$", out, re.M))
    return {f for f, names in variants.items() if names & found}


_OWNED_CACHE: Dict[Tuple[str, int], bool] = {}


def package_owned(files: Sequence[str]) -> Optional[Set[str]]:
    """Which of *files* are installed by a dpkg/rpm package. One batched query for the files not asked about before
    (the real-time guard polls); None - the check is skipped silently - without a usable dpkg or rpm."""
    tool = _package_tool()
    exe = shutil.which(tool) if tool else None
    if not tool or not exe:
        return None

    def key(f: str) -> Tuple[str, int]:
        try:
            return f, os.stat(f).st_mtime_ns
        except OSError:
            return f, 0

    todo = [f for f in files if key(f) not in _OWNED_CACHE]
    if todo:
        found = _query_owned(tool, exe, todo)
        if found is None:
            return None
        for f in todo:
            _OWNED_CACHE[key(f)] = f in found
    return {f for f in files if _OWNED_CACHE.get(key(f))}


def pam_module_files(paths: LinuxPaths) -> List[Path]:
    """Module files (*.so) of the standard PAM module directories, every real directory once (capped)."""
    dirs: List[Path] = []
    for base in ("/lib", "/usr/lib"):
        dirs += [paths.at(f"{base}{suffix}/security") for suffix in ("", "32", "64", "x32")]
        try:
            dirs += sorted(paths.at(base).glob("*/security"))
        except OSError:
            pass
    dirs.append(paths.at("/usr/lib/pam"))
    seen: Set[str] = set()
    out: List[Path] = []
    for d in dirs:
        real = os.path.realpath(d)
        if real not in seen and d.is_dir():
            seen.add(real)
            out += [f for f in _dir_files(d) if re.search(r"\.so(?:\.\d+)*$", f.name)]
    return out[:MAX_PAM_MODULES]


# Homebrew PAM modules that macOS users add on purpose by absolute path: pam_reattach (Touch ID inside tmux / screen) and
# pam_watchid (Apple Watch for sudo). Still reported, at LOW, because the Homebrew prefix is writable by its owner.
KNOWN_EXTRA_PAM_MODULES = frozenset({"pam_reattach", "pam_watchid"})


def collect_pam(paths: LinuxPaths, owned: Optional[Callable[[Sequence[str]], Optional[Set[str]]]] = None) -> List[Entry]:
    """PAM backdoors: a rule or module that runs code or decides logins for every sshd/login/su/sudo session.

    Listed (and judged) are only the notable lines of /etc/pam.d, not the whole configuration:
    * ``pam_exec.so`` - runs a program on every login; the program is recorded. HIGH when it sits in a temp, hidden, home
      or world-writable location, MEDIUM otherwise (the stock Debian, Ubuntu, Fedora and Arch login stacks do not use it).
    * a module given by absolute path outside the standard module directories (_PAM_STD_DIR): MEDIUM, HIGH in such a place.
    * a ``pam_permit.so`` line that lets anyone through the auth stack of a login service: HIGH (see pam_bypass_rules).
    * a module file in the standard directories that no package owns: MEDIUM when a PAM rule loads it, else LOW. Needs
      dpkg or rpm; *owned* (default: package_owned, only on a real root) returns the owned subset or None to skip the check."""
    out: List[Entry] = []
    services: Dict[str, List[PamRule]] = {}
    files: Dict[str, Path] = {}
    for f in _dir_files(paths.etc / "pam.d"):
        text = _read_text(f)
        if text is not None:
            services[f.name], files[f.name] = parse_pam_conf(text, f.name), f
    bypass = pam_bypass_rules(services)
    referenced: Dict[str, Set[str]] = {}
    for service, rules in services.items():
        seen: Dict[str, int] = {}
        for r in rules:
            if r.stack == "*" or r.control.lower() in ("include", "substack"):
                continue
            stem = _pam_stem(r.module)
            referenced.setdefault(stem, set()).add(service)
            reasons: List[Dict[str, Any]] = []
            command, path = f"{r.control} {r.module} {r.args}".strip(), ""
            if r.module.startswith("/"):
                path = r.module
                if not _PAM_STD_DIR.match(posixpath.dirname(posixpath.normpath(r.module))):
                    known = stem in KNOWN_EXTRA_PAM_MODULES
                    sev = (Severity.HIGH if risky_unix_path(r.module, paths.at(r.module))
                           else Severity.LOW if known else Severity.MEDIUM)
                    reasons.append(meta_reason(sev, f"{r.module} is loaded by the {r.stack} stack of {service} from outside the "
                                                    "standard PAM module directories"
                                                    + (" (a known Homebrew module: check that you installed it)" if known else ""),
                                               ["T1556.003"]))
            if stem == "pam_exec":
                command = pam_exec_command(r.args)
                path = posix_target(command)
                where = [t for t in command.split() if t.startswith(("/", "~", "./"))]
                risky = any(risky_unix_path(t, paths.at(t) if t.startswith("/") else None) for t in where)
                note = " (hands it the user's password: expose_authtok)" if "expose_authtok" in r.args.split() else ""
                reasons.append(meta_reason(
                    Severity.HIGH if risky else Severity.MEDIUM,
                    f"pam_exec.so runs {command[:100] or 'a program'} in the {r.stack} stack of {service}{note}"
                    + (", from a temporary, hidden, home or world-writable location" if risky else ""), ["T1556.003"]))
            if id(r) in bypass:
                names = ", ".join(sorted(bypass[id(r)][1]))
                reasons.append(meta_reason(Severity.HIGH, f"pam_permit.so lets anyone pass the auth stack of {names}: nothing "
                                                          "after it can reject a wrong password", ["T1556.003"]))
            if reasons:
                base = f"{r.stack} {posixpath.basename(r.module)}"
                seen[base] = seen.get(base, 0) + 1
                out.append(make_entry("pam", str(files[service]), base if seen[base] == 1 else f"{base} #{seen[base]}", command,
                                      path=path, reasons=reasons, rule=f"{r.stack} {r.control} {r.module} {r.args}".strip()))
    modules = pam_module_files(paths)
    if owned is None:  # a test tree has no package database of its own
        owned = package_owned if paths.is_real else (lambda _files: None)
    owners = owned([str(f) for f in modules]) if modules else None
    if owners is not None:
        for f in modules:
            if str(f) in owners:
                continue
            users = referenced.get(_pam_stem(f.name))
            text = (f"{f.name} is used by the PAM stack of {', '.join(sorted(users))} but no package installed it" if users else
                    f"{f.name} sits in a PAM module directory but no package installed it")
            out.append(make_entry("pam", str(f.parent), f.name, str(f), path=str(f),
                                  reasons=[meta_reason(Severity.MEDIUM if users else Severity.LOW, text, ["T1556.003"])]))
    return out


def parse_launchd_plist(data: bytes) -> Dict[str, Any]:
    pl = plistlib.loads(data)
    args = pl.get("ProgramArguments") or ([pl["Program"]] if pl.get("Program") else [])
    return {"label": pl.get("Label", ""), "args": [str(a) for a in args], "run_at_load": bool(pl.get("RunAtLoad")),
            "keep_alive": bool(pl.get("KeepAlive")), "disabled": bool(pl.get("Disabled")),
            "watch": bool(pl.get("WatchPaths") or pl.get("QueueDirectories") or pl.get("StartInterval") or pl.get("StartCalendarInterval"))}


def launchd_dirs() -> List[Path]:
    dirs = [Path("/Library/LaunchAgents"), Path("/Library/LaunchDaemons")]
    dirs += [h / "Library" / "LaunchAgents" for h in discover_homes()]
    return dirs


def launchd_program(args: Sequence[str]) -> Tuple[str, str]:
    """(command line, target) of a launchd job's program arguments; the target is the script when an interpreter runs one."""
    path = args[0]
    if _stem(path) in _INTERPRETERS and len(args) > 1 and not args[1].startswith("-"):
        path = args[1]
    return _join_args(args), path


def collect_launchd(dirs: Optional[Sequence[Path]] = None) -> List[Entry]:
    out = []
    for d in (dirs if dirs is not None else launchd_dirs()):
        try:
            files = sorted(d.glob("*.plist"))
        except OSError:
            continue
        for f in files:
            try:
                info = parse_launchd_plist(f.read_bytes())
            except Exception as exc:
                log.debug("bad plist %s: %s", f, exc)
                continue
            args = info["args"]
            if not args:
                continue
            command, path = launchd_program(args)
            out.append(make_entry("launchd", str(d), f.name, command, path=path, enabled=not info["disabled"], mac=True,
                                  label=info["label"]))
    return out


PERIODIC_DIRS = ("/etc/periodic", "/usr/local/etc/periodic")
PERIODIC_LOCAL = ("/etc/daily.local", "/etc/weekly.local", "/etc/monthly.local")


def collect_periodic(paths: LinuxPaths) -> List[Entry]:
    """macOS periodic(8) scripts: launchd runs everything in /etc/periodic/{daily,weekly,monthly} (and the same folders
    under /usr/local/etc/periodic) as root, and the stock 999.local scripts run /etc/{daily,weekly,monthly}.local.
    The stock scripts are only inventoried; like any script their content is judged."""
    out: List[Entry] = []
    for logical in PERIODIC_DIRS:
        try:
            subdirs = sorted(p for p in itertools.islice(paths.at(logical).iterdir(), MAX_DIR_ENTRIES) if p.is_dir())
        except OSError:
            continue
        for d in subdirs:
            out += _script_entries(_dir_files(d), "periodic")
    return out + _script_entries([paths.at(p) for p in PERIODIC_LOCAL if paths.at(p).is_file()], "periodic", require_exec=False)


def parse_emond_rules(data: bytes) -> List[Dict[str, Any]]:
    """The RunCommand actions of an emond rules plist (a list of rules, each with eventTypes and actions)."""
    pl = plistlib.loads(data)
    out = []
    for rule in pl if isinstance(pl, list) else []:
        if not isinstance(rule, dict):
            continue
        for act in rule.get("actions") or []:
            if isinstance(act, dict) and str(act.get("type", "")).lower() == "runcommand" and act.get("command"):
                out.append({"rule": str(rule.get("name", "")), "enabled": rule.get("enabled", True) is not False,
                            "events": [str(e) for e in rule.get("eventTypes") or []], "user": str(act.get("user", "")),
                            "args": [str(act["command"])] + [str(a) for a in act.get("arguments") or []]})
    return out


def collect_emond(paths: LinuxPaths) -> List[Entry]:
    """macOS emond (removed in macOS 13, shipped without rules before): each enabled RunCommand rule in
    /etc/emond.d/rules runs a command as root on a system event, and a file in /private/var/db/emondClients is what
    wakes emond up. Both are unusual, so an enabled rule is MEDIUM and a client file LOW."""
    out: List[Entry] = []
    rules = paths.at("/etc/emond.d/rules")
    try:
        plists = sorted(rules.glob("*.plist"))
    except OSError:
        plists = []
    for f in plists:
        try:
            actions = parse_emond_rules(f.read_bytes())
        except Exception as exc:
            log.debug("bad emond rules %s: %s", f, exc)
            continue
        seen: Dict[str, int] = {}
        for a in actions:
            name = a["rule"] or f.stem
            seen[name] = seen.get(name, 0) + 1
            reasons = [meta_reason(Severity.MEDIUM, f"emond rule {name!r} runs a command as {a['user'] or 'root'} on "
                                                    f"{', '.join(a['events'])[:80] or 'system events'}", ["T1546.014"])]
            out.append(make_entry("emond", str(f), name if seen[name] == 1 else f"{name} #{seen[name]}", _join_args(a["args"]),
                                  path=a["args"][0], enabled=a["enabled"], reasons=reasons))
    clients = paths.at("/private/var/db/emondClients")
    for f in _dir_files(clients):
        if not f.name.startswith("."):
            why = f"{f.name} in emondClients wakes the emond daemon, which modern macOS does not use"
            reasons = [meta_reason(Severity.LOW, why, ["T1546.014"])]
            out.append(make_entry("emond", str(clients), f.name, "", path="", reasons=reasons))
    return out


def _bundle_executable(bundle: Path) -> str:
    """The Mach-O a .bundle loads (CFBundleExecutable, else Contents/MacOS/<name>); the bundle itself when neither exists."""
    macos = bundle / "Contents" / "MacOS"
    try:
        name = plistlib.loads((bundle / "Contents" / "Info.plist").read_bytes()).get("CFBundleExecutable")
        if name and (macos / str(name)).is_file():
            return str(macos / str(name))
    except Exception:
        pass
    return str(macos / bundle.stem) if (macos / bundle.stem).is_file() else str(bundle)


def collect_auth_plugins(paths: LinuxPaths) -> List[Entry]:
    """macOS authorization plugins (/Library/Security/SecurityAgentPlugins/*.bundle): code loaded into the login window
    and every authorization prompt. Listed only; Apple's and the known vendors' (Jamf Connect, NoMAD Login ...) are
    not suspicious in themselves, so just the usual location and content checks apply."""
    d = paths.at("/Library/Security/SecurityAgentPlugins")
    try:
        bundles = sorted(p for p in itertools.islice(d.iterdir(), MAX_DIR_ENTRIES) if p.suffix == ".bundle")
    except OSError:
        return []
    out = []
    for b in bundles:
        exe = _bundle_executable(b)
        out.append(make_entry("auth_plugin", str(d), b.name, exe, path=exe))
    return out


def collect_login_hooks(paths: LinuxPaths) -> List[Entry]:
    """macOS login/logout hooks: ``defaults write com.apple.loginwindow LoginHook /path/script`` runs the script as root at
    every login (LogoutHook: at logout). Deprecated since macOS 10.11, so any hook is at least LOW."""
    out: List[Entry] = []
    plists = [paths.at("/Library/Preferences/com.apple.loginwindow.plist")]
    plists += [h / "Library" / "Preferences" / "com.apple.loginwindow.plist" for h in paths.homes]
    for f in plists:
        try:
            pl = plistlib.loads(f.read_bytes())
        except Exception:
            continue
        for key in ("LoginHook", "LogoutHook"):
            hook = pl.get(key) if isinstance(pl, dict) else None
            if isinstance(hook, str) and hook.strip():
                out.append(make_entry("login_hook", str(f), key, hook.strip(), reasons=[meta_reason(
                    Severity.LOW, f"{key} {hook.strip()[:100]} runs as root at every {key[:-4].lower()}; hooks are deprecated "
                                  "since macOS 10.11", ["T1037.002"])]))
    return out


# --------------------------------------------------------------------------- macOS: login items (Background Task Management)

BTM_TIMEOUT = 30
MAX_BTM_BYTES = 8 * 1024 * 1024
MAX_BTM_RECORDS = 3000
BTM_JUDGED = ("login item", "agent", "daemon")  # app and developer records only group the items an app registers
BTM_MITRE = {"login item": ["T1547.015"], "agent": ["T1543.001"], "daemon": ["T1543.004"], "app": ["T1547.015"],
             "developer": ["T1547.015"], "unknown": ["T1547.015"]}

_BTM_UID = re.compile(r"^\s*Records\s+for\s+UID\s+(-?\d+)", re.I)
_BTM_ITEM = re.compile(r"^\s*#\d+:\s*$")
_BTM_EMBEDDED = re.compile(r"^\s*#\d+:\s*(\S.*)$")
_BTM_FIELD = re.compile(r"^\s*([A-Za-z][A-Za-z0-9 ./()-]{0,40}?):(?:\s+(\S.*?))?\s*$")
_BTM_KEYS = {"uuid": "uuid", "name": "name", "developer name": "developer", "team identifier": "team_id", "type": "type",
             "disposition": "disposition", "identifier": "identifier", "url": "url", "executable path": "executable",
             "parent identifier": "parent"}
_BTM_NONE = {"", "(null)", "null", "none", "unknown", "unknown developer", "n/a", "-"}
_BTM_ID_PREFIX = re.compile(r"^\d+\.")  # legacy items are identified as "<type code>.<launchd label>", e.g. 16.com.vendor.daemon


@dataclass
class BtmRecord:
    """One item of ``sfltool dumpbtm``. A value the dump does not have (or prints as '(null)') is ''."""

    uid: str = ""
    uuid: str = ""
    name: str = ""
    developer: str = ""
    team_id: str = ""
    type_text: str = ""
    kind: str = "unknown"  # login item | agent | daemon | app | developer | unknown
    disposition: str = ""
    enabled: Optional[bool] = None  # None: the dump does not say
    allowed: Optional[bool] = None
    visible: Optional[bool] = None
    identifier: str = ""
    url: str = ""
    executable: str = ""
    parent: str = ""
    embedded: List[str] = field(default_factory=list)


def parse_btm_disposition(text: str) -> Tuple[Optional[bool], Optional[bool], Optional[bool]]:
    """(enabled, allowed, visible) of ``[enabled, allowed, visible, notified] (0xf)``. The words win; without them the bits
    (enabled 0x1, allowed 0x2, visible 0x4, notified 0x8) do; None when the text says neither."""
    m = re.search(r"\[([^\]]*)\]", text)
    words = {w.strip().lower() for w in m.group(1).split(",")} if m else set()
    h = re.search(r"\(0x([0-9a-fA-F]+)\)", text)
    bits = int(h.group(1), 16) if h else None

    def flag(on: str, off: str, bit: int) -> Optional[bool]:
        if on in words:
            return True
        if off in words:
            return False
        return None if bits is None else bool(bits & bit)

    return flag("enabled", "disabled", 0x1), flag("allowed", "disallowed", 0x2), flag("visible", "hidden", 0x4)


def btm_kind(type_text: str, url: str = "") -> str:
    """"login item", "agent", "daemon", "app", "developer" or "unknown" from ``login item (0x4)``, ``legacy daemon (0x10010)``,
    ``legacy agent/daemon`` (the folder of the plist decides) ... Falls back to the type bits when the words are new."""
    t = type_text.lower()
    if "developer" in t:
        return "developer"
    if "login item" in t:
        return "login item"
    if "daemon" in t and "agent" in t:
        return "daemon" if "/launchdaemons/" in url.lower() else "agent"
    if "daemon" in t:
        return "daemon"
    if "agent" in t:
        return "agent"
    if re.search(r"\bapp\b", t):
        return "app"
    m = re.search(r"\(0x([0-9a-f]+)\)", t)
    bits = int(m.group(1), 16) if m else 0
    return next((kind for bit, kind in ((0x20, "developer"), (0x10, "daemon"), (0x8, "agent"), (0x4, "login item"), (0x2, "app"))
                 if bits & bit), "unknown")


def parse_btm_dump(text: str) -> List[BtmRecord]:
    """The items of ``sfltool dumpbtm``: ``Records for UID <n> : <uuid>`` headers, each followed by ``#<n>:`` items made of
    ``Key: value`` lines. Unknown keys and lines are ignored; ``#<n>: <identifier>`` lines inside an item are embedded items."""
    raw: List[Tuple[str, Dict[str, str], List[str]]] = []
    uid = ""
    cur: Optional[Tuple[str, Dict[str, str], List[str]]] = None
    for line in text.splitlines():
        m = _BTM_UID.match(line)
        if m:
            uid, cur = m.group(1), None
        elif _BTM_ITEM.match(line):
            cur = (uid, {}, [])
            raw.append(cur)
            if len(raw) >= MAX_BTM_RECORDS:
                break
        elif cur is not None:
            m = _BTM_EMBEDDED.match(line)
            if m:
                cur[2].append(m.group(1).strip())
                continue
            m = _BTM_FIELD.match(line)
            key = _BTM_KEYS.get(m.group(1).strip().lower()) if m else None
            if m and key and key not in cur[1]:
                cur[1][key] = (m.group(2) or "").strip()
    out: List[BtmRecord] = []
    for uid, fields, embedded in raw:
        f = {k: ("" if v.lower() in _BTM_NONE else v) for k, v in fields.items()}
        rec = BtmRecord(uid=uid, uuid=f.get("uuid", ""), name=f.get("name", ""), developer=f.get("developer", ""),
                        team_id=f.get("team_id", ""), type_text=f.get("type", ""), disposition=f.get("disposition", ""),
                        identifier=f.get("identifier", ""), url=f.get("url", ""), executable=f.get("executable", ""),
                        parent=f.get("parent", ""), embedded=embedded)
        rec.kind = btm_kind(rec.type_text, rec.url)
        rec.enabled, rec.allowed, rec.visible = parse_btm_disposition(rec.disposition)
        out.append(rec)
    return out


def btm_is_apple(rec: BtmRecord, *paths: str) -> bool:
    """Apple's own item: a com.apple. identifier (or parent app), Apple as the developer or Apple's own signing identity, or
    a file in /System (only Apple can write there). Spoofing the label alone does not hide a program from the path checks."""
    return (_BTM_ID_PREFIX.sub("", rec.identifier).startswith("com.apple.")
            or _BTM_ID_PREFIX.sub("", rec.parent).startswith("com.apple.")
            or rec.team_id.lower() in ("apple", "software signing")
            or rec.developer.lower() in ("apple", "apple inc.", "apple inc")
            or any(p.startswith("/System/") for p in paths))


def _btm_path(text: str) -> str:
    """The local path of a ``file://`` URL (percent-decoded, no trailing slash) or of an absolute path; '' for anything else."""
    t = text.strip()
    if t.lower().startswith("file://"):
        t = unquote(t[7:])
        if t.lower().startswith("localhost/"):
            t = t[9:]
    return (t.rstrip("/") or "/") if t.startswith("/") else ""


def btm_item_path(rec: BtmRecord, by_ident: Dict[str, BtmRecord], depth: int = 0) -> str:
    """Where the item lives: its URL, or a URL relative to the app that holds it (the record named as its parent)."""
    if rec.url.lower().startswith("file://") or rec.url.startswith("/"):
        return _btm_path(rec.url)
    parent = (by_ident.get(rec.parent) or by_ident.get(_BTM_ID_PREFIX.sub("", rec.parent))) if rec.parent else None
    if rec.url and parent is not None and parent is not rec and depth < 4:
        base = btm_item_path(parent, by_ident, depth + 1)
        return f"{base}/{unquote(rec.url).strip('/')}" if base else ""
    return ""


def btm_program(rec: BtmRecord, by_ident: Dict[str, BtmRecord], paths: LinuxPaths) -> Tuple[str, str]:
    """(command, target) of a record: its Executable Path, else the program its launchd plist starts, else the item itself
    (an app or helper bundle). A plist that cannot be read has no target: the plist is not the program."""
    exe = _btm_path(rec.executable)
    if exe:
        return _join_args([exe]), exe
    item = btm_item_path(rec, by_ident)
    if item.endswith(".plist"):
        try:
            args = parse_launchd_plist(paths.at(item).read_bytes())["args"]
        except Exception as exc:
            log.debug("bad plist %s: %s", item, exc)
            args = []
        return launchd_program(args) if args else (_join_args([item]), "")
    return (_join_args([item]) if item else ""), item


def btm_reasons(rec: BtmRecord, apple: bool) -> List[Dict[str, Any]]:
    """What the record itself gives away about an autostart item: no developer the system can identify, or a program that is
    allowed to run in the background but hidden from the user's list. Apple's own items are never judged this way."""
    if apple or rec.kind not in BTM_JUDGED:
        return []
    mitre = BTM_MITRE[rec.kind]
    out = []
    if not rec.team_id:
        out.append(meta_reason(Severity.LOW, "not signed by an identified developer: the item has no Team Identifier", mitre,
                               "signature"))
    if rec.enabled and rec.allowed and rec.visible is False:
        out.append(meta_reason(Severity.LOW, "hidden from System Settings > Login Items: it is allowed to run in the background "
                                             "without being listed there", mitre))
    return out


BTM_DB_DIR = Path("/private/var/db/com.apple.backgroundtaskmanagement")
_BTM_CACHE: Dict[str, Any] = {}


def _btm_db_stamp() -> Optional[Tuple[Tuple[str, int, int], ...]]:
    try:
        return tuple(sorted((p.name, p.stat().st_size, p.stat().st_mtime_ns) for p in BTM_DB_DIR.iterdir()))
    except OSError:
        return None


def cached_btm_dump() -> Tuple[Optional[str], str]:
    """read_btm_dump, run again only when the Background Task Management database changed: the real-time persistence guard
    collects every 30 seconds and the dump takes a second or more."""
    stamp = _btm_db_stamp()
    if stamp is not None and _BTM_CACHE.get("stamp") == stamp:
        return _BTM_CACHE["result"]
    result = read_btm_dump()
    if stamp is not None and result[0] is not None:
        _BTM_CACHE.update(stamp=stamp, result=result)
    return result


def read_btm_dump(admin: Optional[bool] = None, runner: Optional[Callable[..., Tuple[int, str, str]]] = None,
                  version: Optional[str] = None) -> Tuple[Optional[str], str]:
    """(dump, "") from ``sfltool dumpbtm``, or (None, why it was skipped): the command needs root and macOS 13 or newer.
    Any other failure as root raises, so it is reported as an error and not as a quiet gap."""
    if not (is_admin() if admin is None else admin):
        return None, "login items (Background Task Management) were not read: sfltool dumpbtm needs root, run Aegis with sudo"
    ver = platform.mac_ver()[0] if version is None else version
    m = re.match(r"(\d+)", ver)
    if m and int(m.group(1)) < 13:
        return None, f"login items (Background Task Management) were not read: macOS {ver} has no sfltool dumpbtm (needs 13)"
    rc, out, err = (runner or run)(["sfltool", "dumpbtm"], timeout=BTM_TIMEOUT)
    if rc != 0:
        if err.startswith("not found"):
            return None, "login items (Background Task Management) were not read: sfltool is not installed"
        raise RuntimeError(f"sfltool dumpbtm failed (exit {rc}): {(err or out).strip()[:300]}")
    return out[:MAX_BTM_BYTES], ""


def collect_btm(paths: LinuxPaths, notes: Optional[List[str]] = None,
                dump: Optional[Callable[[], Tuple[Optional[str], str]]] = None) -> List[Entry]:
    """Login items and background tasks (macOS 13+, ``sfltool dumpbtm``, root only): every record of the dump is an entry.
    When the dump cannot be read the reason goes to *notes* and nothing is returned; a dump that is read but not
    understood raises. Records of an identified developer or of Apple pass; see btm_reasons for what is judged."""
    text, why = (dump or cached_btm_dump)()
    if text is None:
        if notes is not None:
            notes.append(why)
        return []
    records = parse_btm_dump(text)
    if not records and not any(_BTM_UID.match(line) for line in text.splitlines()):
        raise ValueError(f"sfltool dumpbtm printed {len(text)} bytes without a 'Records for UID' section: output not recognised")
    if not records and re.search(r"^\s*UUID:", text, re.M):
        raise ValueError(f"sfltool dumpbtm printed {len(text)} bytes with items but no '#<n>:' record could be read: "
                         "output not recognised")
    by_ident = {r.identifier: r for r in records if r.identifier}
    for r in records:
        if r.identifier:
            by_ident.setdefault(_BTM_ID_PREFIX.sub("", r.identifier), r)
    out: List[Entry] = []
    seen: Dict[Tuple[str, str], int] = {}
    for rec in records:
        command, path = btm_program(rec, by_ident, paths)
        apple = btm_is_apple(rec, path, btm_item_path(rec, by_ident))
        location = f"Background Task Management (UID {rec.uid}, {rec.kind})"
        name = rec.name or _BTM_ID_PREFIX.sub("", rec.identifier) or rec.uuid
        key = (location, name)
        seen[key] = seen.get(key, 0) + 1
        plist = btm_item_path(rec, by_ident) if "legacy" in rec.type_text.lower() else ""
        out.append(make_entry("btm", location, name if seen[key] == 1 else f"{name} #{seen[key]}", command, path=path,
                              plist=plist if plist.endswith(".plist") else "",
                              enabled=rec.enabled is not False and rec.allowed is not False, mac=True, apple=apple, uid=rec.uid,
                              uuid=rec.uuid, identifier=rec.identifier, item_type=rec.kind, developer=rec.developer,
                              team_id=rec.team_id, disposition=rec.disposition, visible=rec.visible, url=rec.url,
                              parent=rec.parent, mitre=BTM_MITRE[rec.kind], reasons=btm_reasons(rec, apple)))
    return out


# --------------------------------------------------------------------------- macOS: code signatures of autostart programs

MAX_CODESIGN_BINARIES = 60
CODESIGN_TIMEOUT = 10
CODESIGN_BUDGET_S = 120.0  # wall clock for all the codesign runs of one scan
_MACHO_MAGIC = {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
                b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"}  # thin, fat and fat64
_CODESIGN_INVALID = ("sealed resource", "invalid signature", "have been modified", "failed strict validation",
                     "invalid or unsupported format", "file modified")
_APPLE_SIGNERS = ("Software Signing", "Apple Mac OS Application Signing")  # Apple's own identities, only Apple holds them


@dataclass
class CodeSignature:
    """What ``codesign`` says about one program. status: signed | adhoc | unsigned | invalid | unknown | script (a script
    cannot carry a signature, so codesign is not run on it)."""

    status: str
    signer: str = ""  # first Authority, "ad-hoc" or "unsigned"
    team_id: str = ""
    identifier: str = ""
    hardened: bool = False  # hardened runtime
    detail: str = ""

    @property
    def apple(self) -> bool:
        return self.signer in _APPLE_SIGNERS


def parse_codesign_display(text: str) -> Dict[str, Any]:
    """The facts in the stderr of ``codesign -dv --verbose=2``: Authority lines, TeamIdentifier, Identifier, ad-hoc and the
    hardened runtime flag (``CodeDirectory v=20500 size=... flags=0x10000(runtime) ...``)."""
    flags: List[str] = []
    for m in re.finditer(r"^CodeDirectory\b.*?\bflags=0x[0-9a-fA-F]+\(([^)]*)\)", text, re.M):
        flags += [f.strip() for f in m.group(1).split(",")]
    team = re.search(r"^TeamIdentifier=(.*)$", text, re.M)
    ident = re.search(r"^Identifier=(.*)$", text, re.M)
    team_id = team.group(1).strip() if team else ""
    return {"authorities": [a.strip() for a in re.findall(r"^Authority=(.*)$", text, re.M)],
            "team_id": "" if team_id.lower() == "not set" else team_id, "identifier": ident.group(1).strip() if ident else "",
            "adhoc": "adhoc" in flags or bool(re.search(r"^Signature=adhoc\b", text, re.M)), "runtime": "runtime" in flags}


def parse_codesign_verify(rc: int, text: str) -> Tuple[str, str]:
    """(valid | unsigned | invalid | unknown, detail) from the exit code and output of ``codesign --verify --strict``."""
    first = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")
    detail = first.split(": ", 1)[1] if first.startswith("/") and ": " in first else first  # codesign leads with the path
    low = text.lower()
    if rc == 0:
        return "valid", ""
    if "not signed at all" in low:
        return "unsigned", detail
    if rc > 0 and any(p in low for p in _CODESIGN_INVALID):
        return "invalid", detail
    return "unknown", detail or f"codesign exited with {rc}"


def inspect_signature(path: str, runner: Optional[Callable[..., Tuple[int, str, str]]] = None) -> CodeSignature:
    """Verify (``codesign --verify --strict``) and describe (``codesign -dv --verbose=2``) one program or bundle: two runs,
    one when the verification already says it is not signed."""
    runner = runner or run
    rc, out, err = runner(["codesign", "--verify", "--strict", path], timeout=CODESIGN_TIMEOUT)
    status, detail = parse_codesign_verify(rc, out + err)
    if status == "unsigned":
        return CodeSignature("unsigned", "unsigned", detail=detail)
    if status == "unknown" and rc < 0:
        return CodeSignature("unknown", detail=detail)
    rc, out, err = runner(["codesign", "-dv", "--verbose=2", path], timeout=CODESIGN_TIMEOUT)
    text = out + err  # codesign describes on stderr
    if rc != 0:
        shown, why = parse_codesign_verify(rc, text)
        return CodeSignature("unsigned", "unsigned", detail=why) if shown == "unsigned" else CodeSignature("unknown", detail=why)
    d = parse_codesign_display(text)
    signer = "ad-hoc" if d["adhoc"] else (d["authorities"][0] if d["authorities"] else "")
    if status in ("invalid", "unknown"):
        return CodeSignature(status, signer, d["team_id"], d["identifier"], d["runtime"], detail)
    return CodeSignature("adhoc" if d["adhoc"] else "signed", signer, d["team_id"], d["identifier"], d["runtime"])


def codesign_target_kind(path: str) -> str:
    """"missing", "code" (a bundle, or a file with a Mach-O header) or "script" (any other file: scripts cannot be signed)."""
    try:
        if os.path.isdir(path):
            return "code"
        with open(path, "rb") as fh:
            return "code" if fh.read(4) in _MACHO_MAGIC else "script"
    except PermissionError:
        return "code"  # codesign may still be allowed to read it
    except OSError:
        return "missing"


def review_signatures(entries: Sequence[Entry], runner: Optional[Callable[..., Tuple[int, str, str]]] = None,
                      kind: Optional[Callable[[str], str]] = None, limit: int = MAX_CODESIGN_BINARIES,
                      clock: Callable[[], float] = time.monotonic) -> Tuple[Dict[str, CodeSignature], List[str]]:
    """Code signature of the program of every active launchd and btm entry outside the system folders. codesign runs for at
    most *limit* programs (user-writable places first) and for CODESIGN_BUDGET_S seconds; a script (the target of an
    interpreter) is only told apart. Returns ({program: signature}, notes on what could not be checked)."""
    kind = kind or codesign_target_kind
    candidates = dict.fromkeys(
        e["path"] for e in entries if e["type"] in ("launchd", "btm") and e.get("enabled", True)
        and (e.get("path") or "").startswith("/") and not e["path"].startswith(MAC_SYSTEM_DIRS))
    sigs: Dict[str, CodeSignature] = {}
    unknown: List[str] = []
    checked = left = 0
    started = clock()
    out_of_time = False
    for path in sorted(candidates, key=lambda p: (not mac_user_writable(p), p)):
        what = kind(path)
        if what == "script":
            sigs[path] = CodeSignature("script", detail="a script has no code signature")
        elif what == "code":
            out_of_time = out_of_time or clock() - started > CODESIGN_BUDGET_S
            if checked >= limit or out_of_time:
                left += 1
                continue
            sigs[path] = inspect_signature(path, runner)
            checked += 1
            if sigs[path].status == "unknown":
                unknown.append(f"{cl.basename(path)}: {sigs[path].detail}")
    notes = []
    if left:
        notes.append(f"code signatures: {checked} of {checked + left} programs checked, {left} not checked "
                     f"({'time budget' if out_of_time else f'limit of {limit}'} reached)")
    if unknown:
        notes.append(f"code signatures: {len(unknown)} program(s) could not be verified, e.g. {unknown[0][:120]}")
    return sigs, notes


_HOMEBREW = re.compile(r"^(?:/opt/homebrew|/usr/local)/(?:Cellar|opt|Caskroom)/")


def signature_reasons(sig: CodeSignature, path: str) -> List[Dict[str, Any]]:
    """What a program's code signature says against its autostart entry: an invalid signature is MEDIUM, an unsigned or ad-hoc
    signed program MEDIUM in a user-writable place and LOW elsewhere. Apple and identified developers pass. A script cannot be
    signed, so it only counts in a user-writable place (and not when the path heuristics already say so)."""
    writable = mac_user_writable(path)
    if sig.status == "invalid":
        return [meta_reason(Severity.MEDIUM, f"invalid code signature: {sig.detail or 'verification failed'}", ["T1553.002"],
                            "signature")]
    if sig.status == "adhoc" and _HOMEBREW.match(path):
        return []  # Homebrew ad-hoc signs every bottle it installs on Apple silicon; that is how it ships
    if sig.status in ("unsigned", "adhoc"):
        what = "not code-signed" if sig.status == "unsigned" else "only ad-hoc signed"
        where = " in a user-writable location" if writable else ""
        return [meta_reason(Severity.MEDIUM if writable else Severity.LOW, f"autostart program is {what}{where}: {path}",
                            ["T1553.002"], "signature")]
    if sig.status == "script" and writable and cl.path_risk(path) <= 0:
        return [meta_reason(Severity.MEDIUM, f"autostart runs an unsigned script from a user-writable location: {path}",
                            ["T1059"], "script")]
    return []


def apply_signatures(entries: Sequence[Entry], sigs: Dict[str, CodeSignature]) -> None:
    """Record each program's signature in its entries (evidence: signature, signer, team_id) and add the reasons it gives."""
    for e in entries:
        sig = sigs.get(e.get("path") or "") if e["type"] in ("launchd", "btm") else None
        if sig is None:
            continue
        meta = e["meta"]
        meta["signature"] = sig.status
        if sig.status not in ("script", "unknown"):
            meta["signer"] = sig.signer
            meta["hardened_runtime"] = sig.hardened
        if sig.team_id and not meta.get("team_id"):
            meta["team_id"] = sig.team_id  # a btm record already names the team it was registered with
        reasons = signature_reasons(sig, e["path"])
        if reasons:
            meta["reasons"] = list(meta.get("reasons", [])) + reasons


# --------------------------------------------------------------------------- collection

def _safe(collector: Callable[[], List[Entry]], name: str, errors: List[str]) -> List[Entry]:
    try:
        return collector()
    except Exception as exc:
        log.debug("collector %s failed", name, exc_info=True)
        errors.append(f"{name}: {type(exc).__name__}: {exc}")
        return []


def collect_all(errors: Optional[List[str]] = None, linux_paths: Optional[LinuxPaths] = None,
                notes: Optional[List[str]] = None) -> List[Entry]:
    """Every entry on this machine. *errors* collects what failed; *notes* what was left out on purpose (e.g. root-only data)."""
    errors = errors if errors is not None else []
    out: List[Entry] = []
    if IS_WINDOWS:
        for name, fn in (("run_keys", collect_run_keys), ("winlogon", collect_winlogon), ("ifeo", collect_ifeo),
                         ("accessibility", collect_accessibility_files), ("appinit", collect_appinit), ("lsa", collect_lsa),
                         ("bootexecute", collect_bootexecute), ("dll_hooks", collect_dll_hooks),
                         ("misc_registry", collect_misc_registry), ("office", collect_office_addins),
                         ("com", collect_com_hijacks), ("startup_folders", collect_startup_folders),
                         ("tasks", collect_tasks), ("services", collect_services), ("wmi", collect_wmi)):
            out += _safe(fn, name, errors)
    else:
        lp = linux_paths or LinuxPaths()
        for name, fn in (("cron", collect_cron), ("systemd", collect_systemd), ("rc_local", collect_rc_local),
                         ("shell_rc", collect_shell_rc), ("ld_preload", collect_ld_preload), ("ssh_keys", collect_ssh_keys),
                         ("udev", collect_udev), ("xdg", collect_xdg_autostart), ("pam", collect_pam), ("motd", collect_motd),
                         ("generators", collect_generators), ("at_jobs", collect_at_jobs)):
            out += _safe(lambda fn=fn: fn(lp), name, errors)
        if IS_MAC:
            launchd = _safe(collect_launchd, "launchd", errors)
            out += launchd
            for name, fn in (("periodic", collect_periodic), ("emond", collect_emond), ("auth_plugins", collect_auth_plugins),
                             ("login_hooks", collect_login_hooks)):
                out += _safe(lambda fn=fn: fn(lp), name, errors)
            out += without_listed_plists(_safe(lambda: collect_btm(lp, notes), "btm", errors), launchd)
    return out


def without_listed_plists(btm: List[Entry], launchd: Sequence[Entry]) -> List[Entry]:
    """BTM entries minus the legacy items whose plist the launchd collector already listed: Background Task Management
    lists every LaunchAgent / LaunchDaemon plist again, and one item should give one finding, not two."""
    listed = {os.path.normcase(os.path.join(e["location"], e["name"])) for e in launchd}
    return [e for e in btm if not (e["meta"].get("plist") and os.path.normcase(e["meta"]["plist"]) in listed)]


def collect_entries() -> List[Entry]:
    """Every autostart entry on this machine (inventory; includes benign and disabled ones)."""
    return collect_all()


# --------------------------------------------------------------------------- scanner

def _scan_target_ok(path: str, deep: bool) -> bool:
    if not path or _is_unc_or_unknown(path):
        return False
    if is_os_path(path):
        return False
    if not deep and (cl.is_in_program_files(path) if cl.is_windows_style(path) else path.startswith(("/opt/", "/Applications/"))):
        return False
    try:
        return os.path.isfile(cl.clean_path(path))
    except OSError:
        return False


@register
class PersistenceScanner(Scanner):
    name = "persistence"
    title = "Autostart / persistence"
    description = ("Autoruns-style analysis: Run keys, tasks (also hidden ones), services, WMI, IFEO, Winlogon, startup folders, "
                   "cron, systemd, launchd, PAM, update-motd, systemd generators, at jobs, macOS periodic/emond/login hooks "
                   "and login items, code signatures of macOS launch agents and daemons")
    platforms = ("windows", "linux", "darwin")

    @staticmethod
    def _hidden_tasks(admin: bool, collect: Callable[[], Tuple[List[TaskKey], bool]],
                      review: Callable[[Sequence[TaskKey]], List[Finding]]):
        def check(status: str, detail: str) -> CheckResult:
            return CheckResult("AEG-PERS-CHK-HIDDEN-TASKS", "No hidden scheduled tasks", status, detail, Category.PERSISTENCE,
                               "persistence")

        if not admin:
            yield check(CheckStatus.SKIP, "Needs administrator rights to read the Task Scheduler registry cache; "
                                          "run Aegis as Administrator.")
            return
        try:
            tasks, truncated = collect()
            hidden = review(tasks)
            yield from hidden
            note = f" (stopped after {MAX_TASKCACHE_KEYS} registry keys)" if truncated else ""
            if hidden:
                yield check(CheckStatus.FAIL, f"{len(hidden)} of {len(tasks)} registered tasks are hidden from Task Scheduler{note}")
            else:
                yield check(CheckStatus.WARN if truncated else CheckStatus.PASS,
                            f"{len(tasks)} registered tasks reviewed, none hidden{note}")
        except Exception as exc:
            yield check(CheckStatus.ERROR, f"{type(exc).__name__}: {exc}")

    def run(self, ctx: ScanContext):
        from aegis.scanners.files import scan_file
        from aegis.scanners.processes import authenticode_batch

        errors: List[str] = []
        notes: List[str] = []
        ctx.report(self.name, "collecting autostart entries")
        entries = collect_all(errors, notes=notes)
        ctx.bump("persistence_entries", len(entries))
        for msg in errors:
            yield CheckResult("AEG-PERS-CHK-COLLECT", "Autostart collection", CheckStatus.ERROR, msg, Category.PERSISTENCE, self.name)

        active = [e for e in entries if e.get("enabled", True)]
        if IS_MAC:
            ctx.report(self.name, "checking the code signatures of launch agents, daemons and login items")
            try:
                mac_sigs, sig_notes = review_signatures(active)
                apply_signatures(active, mac_sigs)
                notes += sig_notes
            except Exception as exc:
                log.debug("code signature review failed", exc_info=True)
                yield CheckResult("AEG-PERS-CHK-CODESIGN", "Code signatures of autostart programs", CheckStatus.ERROR,
                                  f"{type(exc).__name__}: {exc}", Category.PERSISTENCE, self.name)
        # signatures for user-writable targets (one batch)
        sigs: Dict[str, Tuple[str, str]] = {}
        if IS_WINDOWS:
            risky = list(dict.fromkeys(cl.clean_path(e["path"]) for e in active if e.get("path") and cl.path_risk(e["path"]) > 0
                                       and os.path.isfile(cl.clean_path(e["path"]))))
            try:
                sigs = authenticode_batch(risky)
            except Exception as exc:  # pragma: no cover
                log.debug("authenticode failed: %s", exc)

        # content-scan existing, non-OS targets (deduplicated, capped)
        limit = int(ctx.options.get("persistence_scan_limit", MAX_SCANNED_TARGETS_DEEP if ctx.deep else MAX_SCANNED_TARGETS))
        targets: Dict[str, List[Entry]] = {}
        for e in active:
            cands = [e.get("path", "")]
            if e["type"] not in TEXT_TYPES:
                st = cl.script_target(e.get("command") or "") if e.get("command") else None
                if st:
                    cands.append(st)
            for c in cands:
                if _scan_target_ok(c, ctx.deep):
                    targets.setdefault(cl.clean_path(c), []).append(e)
        scan_hits: Dict[str, List[Finding]] = {}
        file_findings: List[Finding] = []
        ordered = sorted(targets, key=lambda p: (-cl.path_risk(p), p))[:limit]
        for p in ordered:
            if ctx.cancelled:
                break
            ctx.report(self.name, f"scanning {p}")
            try:
                fs = scan_file(ctx, Path(p))
            except Exception as exc:
                log.debug("scan_file(%s) failed: %s", p, exc)
                continue
            if fs:
                for f in fs:
                    f.scanner = self.name
                    f.evidence = dict(f.evidence, autostart=[display_location(e) for e in targets[p]][:5])
                scan_hits[p] = fs
                file_findings += fs

        flagged = 0
        for e in active:
            if ctx.cancelled:
                break
            try:
                path = e.get("path", "")
                key = cl.norm_win(path) if path and cl.is_windows_style(path) else path
                status = sigs.get(key, (None, ""))[0] if sigs else None
                hits = list(scan_hits.get(cl.clean_path(path), [])) if path else []
                st = cl.script_target(e["command"]) if e.get("command") and e["type"] not in TEXT_TYPES else None
                if st:
                    hits += scan_hits.get(cl.clean_path(st), [])
                if e["type"] in TEXT_TYPES and path:
                    hits += scan_hits.get(path, [])
                f = finding_for_entry(e, assess_entry(e, status, hits))
            except Exception as exc:
                log.debug("assess failed for %s: %s", e.get("name"), exc, exc_info=True)
                continue
            if f:
                flagged += 1
                yield f
        yield from file_findings
        detail = f"{flagged} suspicious of {len(entries)} entries" if flagged else f"{len(entries)} entries reviewed"
        yield CheckResult("AEG-PERS-CHK-AUTOSTART", "No suspicious autostart entries",
                          CheckStatus.FAIL if flagged else CheckStatus.PASS,
                          detail + (f" ({'; '.join(notes)})" if notes else ""), Category.PERSISTENCE, self.name)
        if IS_WINDOWS and not ctx.cancelled:
            ctx.report(self.name, "checking the Task Scheduler registry cache")
            yield from self._hidden_tasks(ctx.is_admin, collect_task_cache, hidden_task_findings)
