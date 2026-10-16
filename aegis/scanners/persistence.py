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
udev, XDG autostart, launchd.
"""

from __future__ import annotations

import hashlib
import logging
import os
import plistlib
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from aegis.core import cmdline as cl
from aegis.core.models import Category, CheckResult, CheckStatus, Finding, Remediation, Severity
from aegis.core.platform import (IS_MAC, IS_WINDOWS, as_list, powershell_json, reg_read, reg_subkeys,
                                 reg_values, user_home, windows_dir)
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
    kind: str = "meta"  # cmd | location | missing | random | script | scan | meta | modifier
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
}
TEXT_TYPES = {"cron_script", "rc_local", "shell_rc"}
NO_MISSING_CHECK = TEXT_TYPES | {"ifeo", "silentprocessexit", "wmi_subscription", "ssh_key", "ld_preload", "winlogon",
                                 "lsa", "bootexecute", "dll_hook", "com_hijack"}
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
    trusted_dir = bool(path) and (cl.is_in_windir(path) or cl.is_in_program_files(path))
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
         **{k: v for k, v in e.get("meta", {}).items() if k in ("author", "hidden", "run_level", "user", "triggers", "start", "svc_type", "filter_query")}},
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

    def __post_init__(self) -> None:
        if not self.homes:
            self.homes = tuple(discover_homes())


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
            command = " ".join(f'"{a}"' if " " in a else a for a in args)
            path = args[0]
            if _stem(path) in _INTERPRETERS and len(args) > 1 and not args[1].startswith("-"):
                path = args[1]
            out.append(make_entry("launchd", str(d), f.name, command, path=path, enabled=not info["disabled"], mac=True,
                                  label=info["label"]))
    return out


# --------------------------------------------------------------------------- collection

def _safe(collector: Callable[[], List[Entry]], name: str, errors: List[str]) -> List[Entry]:
    try:
        return collector()
    except Exception as exc:
        log.debug("collector %s failed", name, exc_info=True)
        errors.append(f"{name}: {type(exc).__name__}: {exc}")
        return []


def collect_all(errors: Optional[List[str]] = None, linux_paths: Optional[LinuxPaths] = None) -> List[Entry]:
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
                         ("udev", collect_udev), ("xdg", collect_xdg_autostart)):
            out += _safe(lambda fn=fn: fn(lp), name, errors)
        if IS_MAC:
            out += _safe(collect_launchd, "launchd", errors)
    return out


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
    description = "Autoruns-style analysis: Run keys, tasks (also hidden ones), services, WMI, IFEO, Winlogon, startup folders, cron, systemd, launchd"
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
        ctx.report(self.name, "collecting autostart entries")
        entries = collect_all(errors)
        ctx.bump("persistence_entries", len(entries))
        for msg in errors:
            yield CheckResult("AEG-PERS-CHK-COLLECT", "Autostart collection", CheckStatus.ERROR, msg, Category.PERSISTENCE, self.name)

        active = [e for e in entries if e.get("enabled", True)]
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
        yield CheckResult("AEG-PERS-CHK-AUTOSTART", "No suspicious autostart entries",
                          CheckStatus.FAIL if flagged else CheckStatus.PASS,
                          f"{flagged} suspicious of {len(entries)} entries" if flagged else f"{len(entries)} entries reviewed",
                          Category.PERSISTENCE, self.name)
        if IS_WINDOWS and not ctx.cancelled:
            ctx.report(self.name, "checking the Task Scheduler registry cache")
            yield from self._hidden_tasks(ctx.is_admin, collect_task_cache, hidden_task_findings)
