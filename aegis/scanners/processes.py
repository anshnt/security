"""Process scanner (Process Explorer-style triage).

Detects, for every running process:
  * system-process masquerading (wrong directory, typosquatted name, wrong
    parent, duplicate lsass),
  * suspicious parent -> child chains (Office/PDF reader spawning a shell ...),
  * LOLBin / malicious command lines (``aegis.core.cmdline``),
  * binaries running from user-writable drop locations (+ signature/rule scan
    of the executable and, on Windows, an Authenticode check),
  * executables deleted from disk while still running,
  * crypto-miners and unwanted remote-access tools.

Data collection (``collect_processes``) is separated from the decision logic
(``masquerade_findings``, ``chain_findings`` ...) so the latter can be unit
tested with synthetic ``ProcInfo`` records on any OS.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

from aegis.core import cmdline as cl
from aegis.core.models import Category, CheckResult, CheckStatus, Finding, Remediation, Severity
from aegis.core.platform import IS_WINDOWS, powershell_json, as_list
from aegis.scanners.base import ScanContext, Scanner, register

log = logging.getLogger("aegis.processes")

MAX_SCANNED_EXES = 200
MAX_SCANNED_EXES_DEEP = 600


# --------------------------------------------------------------------------- data model

@dataclass
class ProcInfo:
    pid: int
    name: str
    ppid: int = 0
    exe: str = ""
    cmdline: str = ""
    username: str = ""
    create_time: float = 0.0
    cpu_now: float = 0.0  # % of one core in the sampling window
    cpu_avg: float = 0.0  # % of one core averaged over the process lifetime
    parent_name: str = ""  # resolved only when the parent really is the parent
    parent_cmdline: str = ""
    parent_exe: str = ""
    exe_deleted: bool = False

    @property
    def lname(self) -> str:
        return (self.name or "").lower()

    @property
    def label(self) -> str:
        return f"{self.exe or self.name} (pid {self.pid})"

    def age(self, now: Optional[float] = None) -> float:
        return max(0.0, (now or time.time()) - self.create_time) if self.create_time else 0.0


def _join_cmdline(parts: Optional[Sequence[str]]) -> str:
    if not parts:
        return ""
    if IS_WINDOWS:
        return subprocess.list2cmdline(list(parts))
    return " ".join(parts)


def collect_processes(sample_cpu: bool = True) -> List[ProcInfo]:
    """Snapshot of all processes via psutil (tolerates AccessDenied/NoSuchProcess)."""
    import psutil

    entries: List[Tuple["psutil.Process", ProcInfo]] = []
    for p in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]):
        try:
            i = p.info
            exe = i.get("exe") or ""
            info = ProcInfo(
                pid=i["pid"], ppid=i.get("ppid") or 0, name=i.get("name") or "", exe=exe,
                cmdline=_join_cmdline(i.get("cmdline")), username=i.get("username") or "",
                create_time=i.get("create_time") or 0.0)
            if exe and not IS_WINDOWS:
                try:
                    link = os.readlink(f"/proc/{info.pid}/exe")
                    info.exe_deleted = link.endswith(" (deleted)") or link.startswith("/memfd:")
                    if info.exe_deleted:
                        info.exe = link.replace(" (deleted)", "")
                except OSError:
                    info.exe_deleted = not os.path.exists(exe)
            if sample_cpu:
                p.cpu_percent(None)
            entries.append((p, info))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception as exc:  # pragma: no cover - defensive
            log.debug("process enumeration error: %s", exc)
    if sample_cpu:
        time.sleep(0.6)
    now = time.time()
    by_pid = {i.pid: i for _, i in entries}
    for p, info in entries:
        try:
            if sample_cpu:
                info.cpu_now = p.cpu_percent(None)
            t = p.cpu_times()
            life = max(now - info.create_time, 1.0) if info.create_time else 0.0
            info.cpu_avg = ((t.user + t.system) / life * 100.0) if life else 0.0
        except Exception:
            pass
        parent = by_pid.get(info.ppid)
        # PID reuse guard: a real parent started before its child
        if parent and parent.pid != info.pid and (not parent.create_time or not info.create_time
                                                   or parent.create_time <= info.create_time + 1.0):
            info.parent_name, info.parent_cmdline, info.parent_exe = parent.name, parent.cmdline, parent.exe
    return [i for _, i in entries]


def excluded_pids(procs: Sequence[ProcInfo]) -> Set[int]:
    """Aegis's own process, its parent and all of our descendants are never flagged."""
    me = os.getpid()
    ex: Set[int] = {me, os.getppid(), 0}
    children: Dict[int, List[int]] = {}
    for p in procs:
        children.setdefault(p.ppid, []).append(p.pid)
    stack = [me]
    while stack:
        cur = stack.pop()
        for c in children.get(cur, []):
            if c not in ex:
                ex.add(c)
                stack.append(c)
    return ex


# --------------------------------------------------------------------------- helpers

def strip_drive(n: str) -> str:
    return re.sub(r"^[a-z]:", "", n)


def safe_to_quarantine(exe: str) -> bool:
    """Only quarantine binaries in user-writable drop locations - never OS or vendor files."""
    if not exe or cl.is_in_windir(exe) or cl.is_in_program_files(exe):
        return False
    return cl.path_risk(exe) > 0


def kill_remediation(p: ProcInfo, desc: str = "Terminate the process") -> Remediation:
    q = safe_to_quarantine(p.exe)
    return Remediation("kill_process", {"pid": p.pid, "path": p.exe, "quarantine": q},
                       desc + (" and quarantine its executable" if q else ""))


def _finding(rule: str, title: str, sev: Severity, p: ProcInfo, description: str, recommendation: str,
             evidence: Optional[dict] = None, mitre: Optional[List[str]] = None,
             category: str = Category.PROCESS, remediation: Optional[Remediation] = None) -> Finding:
    ev = {"pid": p.pid, "name": p.name, "exe": p.exe, "cmdline": p.cmdline[:1000], "parent": p.parent_name,
          "user": p.username}
    ev.update(evidence or {})
    return Finding(rule, title, sev, category, description, p.label, ev, recommendation, remediation,
                   scanner="processes", mitre=mitre or [])


# --------------------------------------------------------------------------- masquerading

@dataclass(frozen=True)
class ProcSpec:
    dirs: Tuple[str, ...] = (r"\windows\system32",)  # exact directories (drive stripped, lower case)
    dir_prefixes: Tuple[str, ...] = ()
    parents: Tuple[str, ...] = ()  # allowed parent names when the parent is known
    singleton: bool = False


_SYS32 = (r"\windows\system32",)
_SYS32_WOW = (r"\windows\system32", r"\windows\syswow64")
SYSTEM_PROCS: Dict[str, ProcSpec] = {
    "svchost.exe": ProcSpec(_SYS32, parents=("services.exe",)),
    "lsass.exe": ProcSpec(_SYS32, parents=("wininit.exe",), singleton=True),
    "csrss.exe": ProcSpec(_SYS32),
    "wininit.exe": ProcSpec(_SYS32, singleton=True),
    "winlogon.exe": ProcSpec(_SYS32),
    "services.exe": ProcSpec(_SYS32, parents=("wininit.exe",), singleton=True),
    "smss.exe": ProcSpec(_SYS32),
    "explorer.exe": ProcSpec((r"\windows", r"\windows\syswow64")),
    "spoolsv.exe": ProcSpec(_SYS32),
    "taskhostw.exe": ProcSpec(_SYS32),
    "dllhost.exe": ProcSpec(_SYS32_WOW),
    "conhost.exe": ProcSpec(_SYS32_WOW),
    "rundll32.exe": ProcSpec(_SYS32_WOW),
    "lsm.exe": ProcSpec(_SYS32, singleton=True),
    "runtimebroker.exe": ProcSpec(_SYS32),
    "sihost.exe": ProcSpec(_SYS32),
    "ctfmon.exe": ProcSpec(_SYS32),
    "fontdrvhost.exe": ProcSpec(_SYS32),
    "dwm.exe": ProcSpec(_SYS32),
    "audiodg.exe": ProcSpec(_SYS32),
    "searchindexer.exe": ProcSpec(_SYS32),
    "msmpeng.exe": ProcSpec((), dir_prefixes=(
        r"\programdata\microsoft\windows defender\platform", r"\program files\windows defender",
        r"\program files (x86)\windows defender", r"\program files\microsoft security client",
        r"\program files\windows defender advanced threat protection")),
}

# Legit names that sit within edit distance of a system name.
LEGIT_LOOKALIKES = {"taskhost.exe", "taskhostex.exe", "service.exe", "explore.exe", "dllhst3g.exe", "csrs.exe",
                    "conhost64.exe", "sihost64.exe", "svchost64.exe"}


def edit_distance(a: str, b: str) -> int:
    """Optimal-string-alignment (Damerau-Levenshtein) distance: a transposition counts as 1."""
    la, lb = len(a), len(b)
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[la][lb]


def typosquat_target(name: str) -> Optional[str]:
    """Return the system process name *name* is a typosquat of, else None."""
    n = name.lower()
    if n in SYSTEM_PROCS or n in LEGIT_LOOKALIKES:
        return None
    stem, dot, ext = n.rpartition(".")
    if not dot:
        stem, ext = n, ""
    if ext not in ("exe", "", "scr", "com", "dll"):
        return None
    best: Optional[Tuple[int, str]] = None
    for target in SYSTEM_PROCS:
        tstem = target[:-4]
        if len(tstem) < 5:
            continue  # smss/dwm/lsm are too short for fuzzy matching
        dist = edit_distance(stem, tstem)
        limit = 2 if len(tstem) >= 9 else 1
        if 0 < dist <= limit and (best is None or dist < best[0]):
            best = (dist, target)
    return best[1] if best else None


def dir_allowed(exe: str, spec: ProcSpec) -> bool:
    d = strip_drive(cl.norm_win(cl.dirname(exe)))
    if d in spec.dirs:
        return True
    return any(d == p or d.startswith(p + "\\") for p in spec.dir_prefixes)


def _expected_desc(spec: ProcSpec) -> str:
    dirs = list(spec.dirs) + list(spec.dir_prefixes)
    return " or ".join("%SystemDrive%" + d for d in dirs) or "its install directory"


def masquerade_findings(procs: Sequence[ProcInfo], skip: Optional[Set[int]] = None) -> List[Finding]:
    skip = skip or set()
    out: List[Finding] = []
    lsass_like: Dict[str, List[ProcInfo]] = {}
    for p in procs:
        if p.pid in skip or not p.name:
            continue
        n = p.lname
        spec = SYSTEM_PROCS.get(n)
        win_exe = bool(p.exe) and cl.is_windows_style(p.exe)
        if spec:
            if spec.singleton and (win_exe or not p.exe):
                lsass_like.setdefault(n, []).append(p)
            if win_exe and not dir_allowed(p.exe, spec):
                out.append(_finding(
                    "AEG-PROC-MASQ", f"System process name '{p.name}' running from the wrong location", Severity.HIGH, p,
                    f"'{p.name}' is a core Windows process that only runs from {_expected_desc(spec)}. "
                    f"This copy runs from '{cl.dirname(p.exe)}', a classic malware masquerading technique.",
                    "Terminate the process and quarantine the file; run a full scan.",
                    {"expected_dirs": list(spec.dirs) or list(spec.dir_prefixes)}, ["T1036.005"],
                    Category.MALWARE, kill_remediation(p)))
            if spec.parents and p.parent_name and p.parent_name.lower() not in spec.parents:
                out.append(_finding(
                    "AEG-PROC-PARENT", f"'{p.name}' started by an unexpected parent ({p.parent_name})", Severity.MEDIUM, p,
                    f"'{p.name}' is normally started by {' / '.join(spec.parents)}. Its parent here is "
                    f"'{p.parent_name}', which can indicate process spoofing or injection.",
                    "Inspect the parent process and the image path; terminate if unexpected.",
                    {"expected_parents": list(spec.parents)}, ["T1036.005", "T1134.004"]))
            continue
        target = typosquat_target(p.name)
        if target and not (p.exe and (cl.is_in_program_files(p.exe) or cl.is_in_windir(p.exe))):
            out.append(_finding(
                "AEG-PROC-TYPOSQUAT", f"Process name '{p.name}' imitates Windows process '{target}'", Severity.HIGH, p,
                f"The name differs from the genuine '{target}' by only one or two characters - a typical "
                "disguise used by malware to hide in the process list.",
                "Terminate the process and quarantine the file; run a full scan.",
                {"imitates": target}, ["T1036.005"], Category.MALWARE, kill_remediation(p)))
    for n, plist in lsass_like.items():
        if n == "lsass.exe" and len(plist) > 1:
            pids = [x.pid for x in plist]
            for p in plist:
                out.append(_finding(
                    "AEG-PROC-MULTI-LSASS", "Multiple lsass.exe processes are running", Severity.HIGH, p,
                    "Windows runs exactly one lsass.exe. Additional instances are a well-known malware trick.",
                    "Terminate the imposter(s) - the genuine lsass.exe is a child of wininit.exe in System32.",
                    {"all_lsass_pids": pids}, ["T1036.005", "T1003.001"], Category.MALWARE,
                    None if (p.exe and dir_allowed(p.exe, SYSTEM_PROCS[n]) and p.parent_name.lower() == "wininit.exe")
                    else kill_remediation(p)))
    return out


# --------------------------------------------------------------------------- parent -> child chains

OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe", "visio.exe",
                  "onenote.exe", "eqnedt32.exe", "wordpad.exe"}
PDF_PARENTS = {"acrord32.exe", "acrord64.exe", "acrobat.exe", "acrocef.exe"}
SCRIPT_CHILDREN = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
                   "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msbuild.exe", "installutil.exe", "wmic.exe",
                   "forfiles.exe"}
WMI_CHILDREN = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
SERVER_PARENTS = {"w3wp.exe", "sqlservr.exe", "httpd.exe", "tomcat9.exe", "tomcat8.exe", "php-cgi.exe", "nginx.exe"}
SERVER_CHILDREN = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "certutil.exe",
                   "bitsadmin.exe"}


def _rundll32_is_system(p: ProcInfo) -> bool:
    """Office/Acrobat legitimately launch rundll32 for system DLLs (printui, shell32 ...)."""
    if p.lname != "rundll32.exe":
        return False
    if cl.analyse_command_line(p.cmdline):
        return False
    target = cl.extract_executable(p.cmdline) or ""
    return not target or cl.basename(target).lower() == "rundll32.exe" or cl.is_in_windir(target) or "\\" not in target


def chain_findings(procs: Sequence[ProcInfo], skip: Optional[Set[int]] = None) -> List[Finding]:
    skip = skip or set()
    out: List[Finding] = []
    for p in procs:
        if p.pid in skip or not p.parent_name:
            continue
        par, child = p.parent_name.lower(), p.lname
        sev: Optional[Severity] = None
        why = ""
        if par in OFFICE_PARENTS | PDF_PARENTS and child in SCRIPT_CHILDREN:
            if _rundll32_is_system(p):
                continue
            sev, why = Severity.HIGH, "Document applications should never launch shells or script hosts - this is how malicious macros, exploits and phishing attachments execute code."
        elif par == "wmiprvse.exe" and child in WMI_CHILDREN:
            sev, why = Severity.MEDIUM, "WMI provider host spawned a script host/shell - typical of WMI-based lateral movement (can also be a management tool)."
        elif par in SERVER_PARENTS and child in SERVER_CHILDREN:
            sev, why = Severity.MEDIUM, "A server process spawned a command interpreter - typical of a web shell or SQL xp_cmdshell abuse (can also be a legitimate job)."
        if sev is None:
            continue
        out.append(_finding(
            "AEG-PROC-CHAIN", f"Suspicious process chain: {p.parent_name} -> {p.name}", sev, p, why,
            "Check what the document/server was doing; terminate the child process if unexpected and scan the source file.",
            {"parent_cmdline": p.parent_cmdline[:500]}, ["T1204.002", "T1059"], Category.SUSPICIOUS,
            kill_remediation(p) if sev >= Severity.HIGH else None))
    return out


# --------------------------------------------------------------------------- command lines

BENIGN_ENC_PARENTS = {"wsmprovhost.exe", "ccmexec.exe", "ccmsetup.exe", "healthservice.exe", "code.exe", "devenv.exe",
                      "windowsterminal.exe", "microsoft.management.services.intunewindowsagent.exe",
                      "agentexecutor.exe", "vmtoolsd.exe", "azurearcsetup.exe", "himds.exe"}


def cmdline_findings(procs: Sequence[ProcInfo], skip: Optional[Set[int]] = None,
                     miner_pids: Optional[Set[int]] = None, min_sev: Severity = Severity.MEDIUM) -> List[Finding]:
    skip = skip or set()
    miner_pids = miner_pids or set()
    out: List[Finding] = []
    seen: Set[Tuple[str, str]] = set()
    for p in procs:
        if p.pid in skip or not p.cmdline:
            continue
        for rid, title, sev, mitre, matched in cl.analyse_command_line(p.cmdline):
            if sev < min_sev or (rid == "AEG-CMD-MINER" and p.pid in miner_pids):
                continue
            if rid == "AEG-CMD-PS-ENC" and p.parent_name.lower() in BENIGN_ENC_PARENTS:
                continue  # management agents legitimately use -EncodedCommand
            key = (rid, hashlib.sha1(p.cmdline.encode("utf-8", "replace")).hexdigest())
            if key in seen:
                continue
            seen.add(key)
            out.append(_finding(
                rid, title, sev, p,
                f"The command line of '{p.name}' matches a known attack technique: {matched[:160]}",
                "Verify who started this process. If you did not run it, terminate it and scan the system.",
                {"matched": matched}, mitre, Category.SUSPICIOUS if sev < Severity.HIGH else Category.MALWARE,
                kill_remediation(p) if sev >= Severity.HIGH else None))
    return out


# --------------------------------------------------------------------------- miners / remote access / deleted

MINER_NAMES = {"xmrig", "xmrigdaemon", "xmr-stak", "nbminer", "t-rex", "trex", "phoenixminer", "lolminer", "cpuminer",
               "cpuminer-multi", "minerd", "ethminer", "gminer", "teamredminer", "bfgminer", "cgminer", "ccminer",
               "kawpowminer", "srbminer", "srbminer-multi", "nanominer", "minergate", "minergate-cli", "xmr-stak-cpu",
               "claymore", "nicehashminer", "excavator", "rigel", "wildrig", "kryptex"}
_STRATUM_RE = re.compile(r"stratum(?:\+(?:tcp|ssl|tls))?://|--donate-level|\bcryptonight\b|\brandomx\b", re.I)


def miner_reason(p: ProcInfo) -> Optional[str]:
    stem = p.lname.rsplit(".", 1)[0] if p.lname.endswith(".exe") else p.lname
    if stem in MINER_NAMES:
        return f"process name '{p.name}' is a known cryptocurrency miner"
    if p.cmdline and _STRATUM_RE.search(p.cmdline):
        return "command line contains a mining-pool (stratum) URL or miner option"
    exe_stem = cl.basename(p.exe).lower().rsplit(".", 1)[0] if p.exe else ""
    if exe_stem in MINER_NAMES:
        return f"executable '{cl.basename(p.exe)}' is a known cryptocurrency miner"
    return None


def sustained_high_cpu(p: ProcInfo) -> bool:
    return p.cpu_now >= 70.0 and p.cpu_avg >= 40.0 and p.age() >= 300.0


def miner_findings(procs: Sequence[ProcInfo], skip: Optional[Set[int]] = None) -> Tuple[List[Finding], Set[int]]:
    skip = skip or set()
    out: List[Finding] = []
    pids: Set[int] = set()
    for p in procs:
        if p.pid in skip:
            continue
        reason = miner_reason(p)
        if reason:
            pids.add(p.pid)
            extra = " It is also using a lot of CPU." if sustained_high_cpu(p) else ""
            out.append(_finding(
                "AEG-PROC-MINER", "Cryptocurrency miner running", Severity.HIGH, p,
                f"{reason}.{extra} Miners hijack your CPU/GPU and electricity and are often installed by malware.",
                "Terminate the process, remove its autostart entry and quarantine the executable.",
                {"cpu_now": round(p.cpu_now, 1), "cpu_avg": round(p.cpu_avg, 1)}, ["T1496"], Category.MALWARE,
                kill_remediation(p)))
        elif sustained_high_cpu(p) and p.exe and cl.path_risk(p.exe) >= 1 and not cl.is_in_windir(p.exe):
            out.append(_finding(
                "AEG-PROC-HIGHCPU", "Sustained high CPU from a program in a user-writable folder", Severity.MEDIUM, p,
                "A binary in a user-writable location has been using most of a CPU core for minutes - a common "
                "sign of a hidden cryptocurrency miner.",
                "Identify the program; if you do not recognise it, terminate it and scan it.",
                {"cpu_now": round(p.cpu_now, 1), "cpu_avg": round(p.cpu_avg, 1)}, ["T1496"]))
    return out, pids


# (stem patterns, display name, severity)
REMOTE_TOOLS: List[Tuple[Tuple[str, ...], str, Severity]] = [
    (("anydesk",), "AnyDesk", Severity.LOW),
    (("teamviewer", "teamviewer_service", "tv_w32", "tv_x64", "teamviewerd"), "TeamViewer", Severity.LOW),
    (("screenconnect.clientservice", "screenconnect.windowsclient", "connectwisecontrol.client"), "ScreenConnect / ConnectWise Control", Severity.LOW),
    (("ateraagent",), "Atera agent", Severity.LOW),
    (("srservice", "srmanager", "splashtopstreamer", "srfeature"), "Splashtop", Severity.LOW),
    (("rustdesk",), "RustDesk", Severity.LOW),
    (("ultraviewer_desktop", "ultraviewer_service", "ultraviewer"), "UltraViewer", Severity.LOW),
    (("ammyyadmin", "aa_v3", "ammyy"), "Ammyy Admin", Severity.MEDIUM),
    (("supremo", "supremoservice"), "Supremo", Severity.LOW),
    (("logmein", "lmiguardiansvc", "lmiignition"), "LogMeIn", Severity.LOW),
    (("rutserv", "rfusclient"), "Remote Utilities host", Severity.LOW),
    (("todesk", "todesk_service"), "ToDesk", Severity.LOW),
]


def remote_tool(p: ProcInfo) -> Optional[Tuple[str, Severity]]:
    stem = p.lname[:-4] if p.lname.endswith(".exe") else p.lname
    if stem == "client32":  # NetSupport Manager client - generic name, require context
        if "netsupport" in p.exe.lower() or cl.path_risk(p.exe) > 0:
            return "NetSupport Manager client", Severity.MEDIUM
        return None
    for stems, display, sev in REMOTE_TOOLS:
        if any(stem == s or (len(s) >= 6 and stem.startswith(s)) for s in stems):
            if p.exe and cl.path_risk(p.exe) >= 2:  # portable copy in Downloads/Temp - the scam pattern
                sev = Severity(min(int(sev) + 1, int(Severity.HIGH)))
            return display, sev
    return None


def remote_access_findings(procs: Sequence[ProcInfo], skip: Optional[Set[int]] = None) -> List[Finding]:
    skip = skip or set()
    out: List[Finding] = []
    seen: Set[str] = set()
    for p in procs:
        if p.pid in skip:
            continue
        hit = remote_tool(p)
        if not hit or hit[0] in seen:
            continue
        seen.add(hit[0])
        display, sev = hit
        out.append(_finding(
            "AEG-PROC-REMOTE", f"Remote-access tool running: {display}", sev, p,
            f"{display} allows another person to see and control this computer. It is legitimate when you "
            "installed it, but is the most common tool used in tech-support scams and by intruders.",
            "If you did not install or start it yourself, or someone phoned you and asked you to install it, "
            "close it, uninstall it and change your passwords. Never give remote access to unsolicited callers.",
            {"tool": display}, ["T1219"], Category.SUSPICIOUS))
    return out


def deleted_exe_suspicious(exe: str) -> Optional[Severity]:
    """Deleted-while-running is only interesting for temp / memfd / hidden locations;
    daemons running a binary replaced by a package upgrade are normal."""
    if not exe:
        return None
    if exe.startswith("/memfd:") or exe.startswith("/dev/shm/"):
        return Severity.HIGH
    if cl.path_risk(exe) >= 1:
        return Severity.MEDIUM
    if exe.startswith(("/usr/", "/bin/", "/sbin/", "/lib", "/opt/", "/snap/", "/var/lib/", "/System/", "/Applications/")):
        return None
    return Severity.MEDIUM


def deleted_exe_findings(procs: Sequence[ProcInfo], skip: Optional[Set[int]] = None) -> List[Finding]:
    skip = skip or set()
    out: List[Finding] = []
    for p in procs:
        if p.pid in skip or not p.exe_deleted:
            continue
        sev = deleted_exe_suspicious(p.exe)
        if sev is None:
            continue
        out.append(_finding(
            "AEG-PROC-DELETED", "Process running from a deleted executable", sev, p,
            "The program file was deleted (or lives only in memory) while the process keeps running - malware does "
            "this to avoid file-based detection.",
            "Dump or inspect the process if you need forensics, then terminate it and look for how it was started.",
            {}, ["T1070.004", "T1620"], Category.SUSPICIOUS, kill_remediation(p)))
    return out


# --------------------------------------------------------------------------- authenticode / location

_AUTHENTICODE_CHUNK = 100


def parse_authenticode(data) -> Dict[str, Tuple[str, str]]:
    """{normalised path: (status, signer subject)} from ConvertTo-Json output."""
    out: Dict[str, Tuple[str, str]] = {}
    for row in as_list(data):
        if not isinstance(row, dict) or not row.get("Path"):
            continue
        out[cl.norm_win(str(row["Path"]))] = (str(row.get("Status") or ""), str(row.get("Signer") or ""))
    return out


def authenticode_batch(paths: Sequence[str]) -> Dict[str, Tuple[str, str]]:
    """Windows only: Get-AuthenticodeSignature for many files in one PowerShell call per chunk."""
    result: Dict[str, Tuple[str, str]] = {}
    if not IS_WINDOWS or not paths:
        return result
    uniq = list(dict.fromkeys(paths))
    for i in range(0, len(uniq), _AUTHENTICODE_CHUNK):
        chunk = uniq[i:i + _AUTHENTICODE_CHUNK]
        arr = ",".join("'" + p.replace("'", "''") + "'" for p in chunk)
        script = (f"$paths=@({arr});"
                  "$paths | ForEach-Object { $s=Get-AuthenticodeSignature -LiteralPath $_ -ErrorAction SilentlyContinue;"
                  " [pscustomobject]@{Path=$_;Status=[string]$s.Status;Signer=[string]$s.SignerCertificate.Subject} }"
                  " | ConvertTo-Json -Compress")
        try:
            result.update(parse_authenticode(powershell_json(script, timeout=120)))
        except Exception as exc:  # pragma: no cover
            log.debug("authenticode batch failed: %s", exc)
    return result


def location_severity(risk: int, sig_status: Optional[str]) -> Optional[Severity]:
    """Severity for a process running from a user-writable folder, boosted by signature state.
    Returns None when the finding should be dropped (validly signed app in an AppData app folder)."""
    if risk <= 0:
        return None
    base = Severity.MEDIUM if risk >= 2 else Severity.LOW
    st = (sig_status or "").lower()
    if st == "valid":
        return Severity.LOW if risk >= 2 else None
    if st in ("hashmismatch", "nottrusted", "invalid"):
        return Severity.HIGH
    if st == "notsigned":
        return Severity(min(int(base) + 1, int(Severity.HIGH)))
    return base


def location_findings(procs: Sequence[ProcInfo], sigs: Optional[Dict[str, Tuple[str, str]]] = None,
                      skip: Optional[Set[int]] = None) -> List[Finding]:
    skip = skip or set()
    sigs = sigs or {}
    out: List[Finding] = []
    seen: Set[str] = set()
    for p in procs:
        if p.pid in skip or not p.exe or p.exe_deleted:
            continue
        risk = cl.path_risk(p.exe)
        key = cl.norm_win(p.exe) if cl.is_windows_style(p.exe) else p.exe
        if key in seen:
            continue
        status, signer = sigs.get(cl.norm_win(p.exe), (None, ""))
        sev = location_severity(risk, status)
        if sev is None:
            continue
        seen.add(key)
        out.append(_finding(
            "AEG-PROC-LOCATION", "Program running from a user-writable folder", sev, p,
            f"'{cl.basename(p.exe)}' runs from '{cl.dirname(p.exe)}'. Malware and droppers favour Temp, Downloads, "
            "Public and AppData because no admin rights are needed to write there."
            + (f" Authenticode status: {status}." if status else ""),
            "Confirm you recognise the program. If not, terminate it and quarantine the file.",
            {"signature": status or "unchecked", "signer": signer, "path_risk": risk}, ["T1036", "T1204.002"],
            Category.SUSPICIOUS, kill_remediation(p) if sev >= Severity.MEDIUM else None))
    return out


def scan_candidates(procs: Sequence[ProcInfo], skip: Set[int], deep: bool, limit: int) -> List[Tuple[str, List[int]]]:
    """Unique executable paths worth content-scanning, riskiest first, capped at *limit*."""
    by_path: Dict[str, List[int]] = {}
    risk: Dict[str, int] = {}
    for p in procs:
        if p.pid in skip or not p.exe or p.exe_deleted or not p.exe.strip():
            continue
        r = cl.path_risk(p.exe)
        in_os = cl.is_in_windir(p.exe) if cl.is_windows_style(p.exe) else p.exe.startswith(
            ("/usr/", "/bin/", "/sbin/", "/lib", "/System/", "/snap/"))
        if r == 0 and (in_os or (not deep and (cl.is_in_program_files(p.exe) if cl.is_windows_style(p.exe)
                                              else p.exe.startswith(("/opt/", "/Applications/"))))):
            continue
        by_path.setdefault(p.exe, []).append(p.pid)
        risk[p.exe] = r
    ordered = sorted(by_path, key=lambda x: (-risk[x], x))
    return [(x, by_path[x]) for x in ordered[:limit]]


def retag_file_findings(findings: Iterable[Finding], path: str, pids: List[int]) -> List[Finding]:
    out = []
    for f in findings:
        f.location = f"{path} (pid {pids[0]})"
        f.evidence = dict(f.evidence, pids=pids, running=True)
        f.scanner = "processes"
        if f.severity >= Severity.HIGH:
            q = safe_to_quarantine(path) or f.rule_id.startswith(("AEG-SIG", "YARA", "AEG-VT", "AEG-DEFENDER"))
            f.remediation = Remediation("kill_process", {"pid": pids[0], "path": path, "quarantine": q},
                                        "Terminate the process" + (" and quarantine the file" if q else ""))
        out.append(f)
    return out


# --------------------------------------------------------------------------- scanner

@register
class ProcessScanner(Scanner):
    name = "processes"
    title = "Running processes"
    description = "Masquerading, suspicious chains, LOLBin command lines, miners, remote-access tools, unsigned binaries"
    platforms = ("windows", "linux", "darwin")

    def run(self, ctx: ScanContext):
        from aegis.scanners.files import scan_file

        try:
            procs = collect_processes()
        except Exception as exc:
            yield CheckResult("AEG-PROC-CHK-ENUM", "Enumerate running processes", CheckStatus.ERROR, str(exc),
                              Category.PROCESS, self.name)
            return
        ctx.bump("processes_examined", len(procs))
        ctx.report(self.name, f"analysing {len(procs)} processes")
        skip = excluded_pids(procs)

        def section(check_id: str, title: str, fn):
            try:
                found = fn()
            except Exception as exc:  # one broken analysis must not abort the rest
                log.exception("process analysis %s failed", check_id)
                return [CheckResult(check_id, title, CheckStatus.ERROR, f"{type(exc).__name__}: {exc}",
                                    Category.PROCESS, self.name)]
            res: list = list(found)
            res.append(CheckResult(check_id, title, CheckStatus.FAIL if found else CheckStatus.PASS,
                                   f"{len(found)} issue(s)" if found else "no issues found", Category.PROCESS, self.name))
            return res

        yield from section("AEG-PROC-CHK-MASQ", "No masquerading system processes", lambda: masquerade_findings(procs, skip))
        yield from section("AEG-PROC-CHK-CHAIN", "No suspicious parent/child process chains", lambda: chain_findings(procs, skip))
        miner: Tuple[List[Finding], Set[int]] = ([], set())
        try:
            miner = miner_findings(procs, skip)
        except Exception as exc:
            log.debug("miner analysis failed: %s", exc)
        yield from miner[0]
        yield CheckResult("AEG-PROC-CHK-MINER", "No cryptocurrency miners running",
                          CheckStatus.FAIL if miner[0] else CheckStatus.PASS, "", Category.PROCESS, self.name)
        yield from section("AEG-PROC-CHK-CMD", "No malicious command lines",
                           lambda: cmdline_findings(procs, skip, miner[1]))
        yield from section("AEG-PROC-CHK-DELETED", "No processes running from deleted files",
                           lambda: deleted_exe_findings(procs, skip))
        yield from section("AEG-PROC-CHK-REMOTE", "No remote-access tools running",
                           lambda: remote_access_findings(procs, skip))

        # ---- binaries in user-writable locations + content scan of running executables
        if ctx.cancelled:
            return
        try:
            risky = [p.exe for p in procs if p.pid not in skip and p.exe and cl.path_risk(p.exe) > 0]
            sigs = authenticode_batch(risky) if IS_WINDOWS else {}
            loc = location_findings(procs, sigs, skip)
        except Exception as exc:
            log.debug("location analysis failed: %s", exc)
            loc = []
        yield from loc
        limit = int(ctx.options.get("proc_scan_limit", MAX_SCANNED_EXES_DEEP if ctx.deep else MAX_SCANNED_EXES))
        file_hits = 0
        for path, pids in scan_candidates(procs, skip, ctx.deep, limit):
            if ctx.cancelled:
                break
            ctx.report(self.name, f"scanning {path}")
            try:
                fs = scan_file(ctx, Path(path))
            except Exception as exc:
                log.debug("scan_file failed for %s: %s", path, exc)
                continue
            if fs:
                tagged = retag_file_findings(fs, path, pids)
                file_hits += len(tagged)
                yield from tagged
        ctx.bump("process_images_scanned", min(limit, len(procs)))
        bad = file_hits or any(f.severity >= Severity.MEDIUM for f in loc)
        yield CheckResult("AEG-PROC-CHK-IMAGES", "Running executables are clean", CheckStatus.FAIL if bad else CheckStatus.PASS,
                          "", Category.PROCESS, self.name)
