"""In-memory threat hunting.

* **YARA over live process memory** (needs the optional ``yara-python``; without it a SKIP result is reported): the memory
  of running, user-accessible processes is scanned with the signature database's compiled YARA rules through
  ``rules.match(pid=..., timeout=...)``. This finds fileless malware, injected payloads and decrypted/unpacked malware
  that never touches the disk in a recognisable form.
* **Unbacked executable memory** (Windows, best effort): private ``PAGE_EXECUTE_READWRITE`` regions - memory that is
  writable *and* executable yet not backed by any file - in processes that are not JIT hosts (browsers, Java, .NET ...)
  are a classic sign of injected shellcode. Reported at MEDIUM with a clear caveat because security software can create
  the same regions.

False-positive control (important for memory scanning, because browsers, editors, terminals and AI tools hold arbitrary
*text* in memory, including the text of malware rules): a rule whose metadata says ``scope = "file"`` is ignored, a rule
tagged ``scope = "memory"`` (or ``any``) is trusted and reported at its own severity, and an untagged ("generic") rule is only
reported - at most HIGH - when the matched bytes lie in *executable* memory (code, not data) or the process is itself
suspicious (runs from a drop location, has no image path, or is a script/LOLBin host). Other generic matches are counted and
mentioned in the check result but not turned into findings.

Safety: Aegis never scans itself, its parent/children or its other instances; security products (whose memory legitimately
holds malware signatures) are skipped; every process has its own timeout (run in a watchdog thread), the whole scan has a
time budget (``ctx.options['memory_budget_s']``, default 60 s), the number of processes is capped
(``memory_max_procs``, default 150 / 400 in deep scans; per-process limit ``memory_proc_timeout_s``) and access-denied processes are simply counted.
"""

from __future__ import annotations

import logging
import os
import re
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Sequence, Set, Tuple

from aegis.core import cmdline as cl
from aegis.core.models import Category, CheckResult, CheckStatus, Finding, Remediation, Severity
from aegis.core.platform import IS_WINDOWS
from aegis.core.signatures import HAVE_YARA
from aegis.scanners.base import Emitted, ScanContext, Scanner, register

log = logging.getLogger("aegis.memory")

DEFAULT_BUDGET_S = 60
DEFAULT_PROC_TIMEOUT_S = 15
DEFAULT_MAX_PROCS = 150
DEFAULT_MAX_PROCS_DEEP = 400
WATCHDOG_GRACE_S = 5.0

# Processes that are never scanned: kernel/OS pseudo-processes and security products (their memory legitimately holds
# malware signatures, which would match string rules).
_SKIP_NAMES = {
    "system", "idle", "registry", "memory compression", "secure system", "vmmem", "system idle process", "smss.exe", "csrss.exe",
    "wininit.exe", "msmpeng.exe", "nissrv.exe", "mssense.exe", "senseir.exe", "sensecncproxy.exe", "msmpsvc.exe", "avp.exe",
    "avpui.exe", "avastsvc.exe", "avastui.exe", "avgsvc.exe", "avgui.exe", "ekrn.exe", "egui.exe", "mbamservice.exe", "mbam.exe",
    "mcshield.exe", "mcuicnt.exe", "bdagent.exe", "vsserv.exe", "savservice.exe", "sophosfilescanner.exe", "sophosui.exe",
    "sophoshealth.exe", "csfalconservice.exe", "csfalconcontainer.exe", "cylancesvc.exe", "sentinelagent.exe",
    "sentinelstaticengine.exe", "wrsa.exe", "ccsvchst.exe", "tmbmsrv.exe", "tmccsf.exe", "pccntmon.exe", "a2service.exe",
    "hmpalert.exe", "ntrtscan.exe", "elastic-agent.exe", "elastic-endpoint.exe", "carbonblack.exe", "cb.exe", "clamd", "freshclam",
    "falcon-sensor", "wazuh-agentd", "ossec-agentd",
}

# Processes that legitimately JIT-compile code (they own RWX private memory): not reported by the RWX heuristic.
_JIT_HOSTS = {
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe", "iexplore.exe", "msedgewebview2.exe",
    "code.exe", "teams.exe", "ms-teams.exe", "slack.exe", "discord.exe", "spotify.exe", "whatsapp.exe", "signal.exe", "notion.exe",
    "obsidian.exe", "figma.exe", "postman.exe", "1password.exe", "bitwarden.exe", "zoom.exe", "skype.exe", "steamwebhelper.exe",
    "steam.exe", "epicgameslauncher.exe", "java.exe", "javaw.exe", "node.exe", "dotnet.exe", "python.exe", "pythonw.exe",
    "pwsh.exe", "powershell.exe", "powershell_ise.exe", "mono.exe", "devenv.exe", "rider64.exe", "idea64.exe", "pycharm64.exe",
    "studio64.exe", "unity.exe", "godot.exe", "ue4editor.exe", "unrealeditor.exe", "blender.exe", "obs64.exe", "electron.exe",
    "cursor.exe", "windsurf.exe", "claude.exe", "msbuild.exe", "vbcscompiler.exe", "w3wp.exe", "sqlservr.exe", "mmc.exe",
    "chrome", "firefox", "java", "node", "python", "python3", "code", "dotnet",
}

# Runtimes whose JIT compilers legitimately create private executable memory. Detected from the
# modules a process has loaded, which also covers apps not named in _JIT_HOSTS - e.g. .NET Core
# apps launched via a native apphost exe (no CLR header), Azure/GitHub agents, Electron/CEF apps.
_JIT_RUNTIME_MODULES = {
    "clr.dll", "coreclr.dll", "clrjit.dll", "mscorwks.dll", "mscorsvr.dll", "mrt100_app.dll",  # .NET
    "jvm.dll", "libjvm.so",  # Java
    "libcef.dll", "node.dll", "v8.dll", "v8_libbase.dll", "libnode.dll",  # V8 / Chromium Embedded / Electron
    "mono-2.0-bdwgc.dll", "mono-2.0-sgen.dll", "monosgen-2.0.dll", "libmonosgen-2.0.so",  # Mono / Unity
    "lua51.dll", "luajit.dll",  # LuaJIT
}


def loads_jit_runtime(pid: int) -> bool:
    """True when the process has a JIT runtime loaded (best effort; False if modules can't be read)."""
    try:
        import psutil

        maps = psutil.Process(pid).memory_maps(grouped=True)
    except Exception:
        return False
    for m in maps:
        name = re.split(r"[\\/]", getattr(m, "path", "") or "")[-1].lower()
        if name in _JIT_RUNTIME_MODULES:
            return True
    return False


_PRIORITY_NAMES = {"powershell.exe": 3, "pwsh.exe": 3, "wscript.exe": 4, "cscript.exe": 4, "mshta.exe": 4, "rundll32.exe": 3,
                   "regsvr32.exe": 3, "cmd.exe": 2, "msbuild.exe": 2, "installutil.exe": 3, "regasm.exe": 3, "regsvcs.exe": 3,
                   "explorer.exe": 2, "svchost.exe": 2, "notepad.exe": 3, "spoolsv.exe": 2, "winlogon.exe": 1, "taskhostw.exe": 2,
                   "wmiprvse.exe": 2, "dllhost.exe": 3, "searchindexer.exe": 1, "runtimebroker.exe": 1}

MEMORY_SCOPES = {"memory", "any", "all", "both", "process"}  # YARA meta "scope" values that mark a rule as written for memory
_EXEC_PROTECT = {0x10, 0x20, 0x40, 0x80}  # PAGE_EXECUTE*
_SUSPICIOUS_HOSTS = {"wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "installutil.exe", "regasm.exe",
                     "regsvcs.exe", "msbuild.exe", "dllhost.exe", "notepad.exe"}
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000

# =========================================================================== process list


@dataclass
class ProcRec:
    pid: int
    name: str = ""
    exe: str = ""
    ppid: int = 0
    create_time: float = 0.0
    username: str = ""
    cmdline: str = ""

    @property
    def lname(self) -> str:
        return (self.name or os.path.basename(self.exe) or "").lower()

    @property
    def label(self) -> str:
        return f"{self.exe or self.name} (pid {self.pid})"


def list_processes() -> List[ProcRec]:
    """Snapshot via psutil; processes that vanish or deny access to some fields are still listed with what we got."""
    out: List[ProcRec] = []
    try:
        import psutil
    except Exception:  # pragma: no cover - psutil is a hard dependency
        return out
    for p in psutil.process_iter(["pid", "ppid", "name", "exe", "create_time", "username", "cmdline"]):
        try:
            i = p.info
            out.append(ProcRec(pid=i["pid"], name=i.get("name") or "", exe=i.get("exe") or "", ppid=i.get("ppid") or 0,
                               create_time=i.get("create_time") or 0.0, username=i.get("username") or "",
                               cmdline=" ".join(i.get("cmdline") or [])[:300]))
        except Exception:
            continue
    return out


def own_pids(procs: Sequence[ProcRec], me: Optional[int] = None, my_exe: Optional[str] = None,
             frozen: Optional[bool] = None) -> Set[int]:
    """Processes that are Aegis: this process, everything it started, its parent when that is the PyInstaller bootloader /
    another copy of our executable, and (frozen builds) every process running our executable."""
    me = os.getpid() if me is None else me
    frozen = bool(getattr(sys, "frozen", False)) if frozen is None else frozen
    my_exe = (sys.executable if my_exe is None else my_exe) or ""
    ex: Set[int] = {me}
    children: Dict[int, List[int]] = {}
    by_pid: Dict[int, ProcRec] = {}
    for p in procs:
        children.setdefault(p.ppid, []).append(p.pid)
        by_pid[p.pid] = p
    stack = [me]
    while stack:
        for c in children.get(stack.pop(), []):
            if c not in ex:
                ex.add(c)
                stack.append(c)
    mine = by_pid.get(me)
    parent = by_pid.get(mine.ppid) if mine else None
    if parent and (parent.lname.startswith("aegis") or (my_exe and parent.exe and os.path.normcase(parent.exe) == os.path.normcase(my_exe))):
        ex.add(parent.pid)
    if frozen and my_exe:
        key = os.path.normcase(my_exe)
        ex.update(p.pid for p in procs if p.exe and os.path.normcase(p.exe) == key)
    return ex


def priority(p: ProcRec) -> Tuple[int, float]:
    """Higher = scanned earlier: drop-location binaries, script hosts / injection targets, then the newest processes."""
    score = _PRIORITY_NAMES.get(p.lname, 0)
    risk = cl.path_risk(p.exe) if p.exe else 0
    score += {2: 6, 1: 3}.get(risk, 0)
    if not p.exe:
        score += 1  # unknown image path: hollowed / protected / short-lived
    return score, p.create_time


def select_processes(procs: Sequence[ProcRec], exclude: Set[int], max_procs: int) -> Tuple[List[ProcRec], Dict[str, int]]:
    """Choose which processes to scan. Returns (ordered list, counters of what was skipped and why)."""
    stats = {"total": len(procs), "self": 0, "skipped_names": 0, "kernel": 0, "capped": 0}
    cand: List[ProcRec] = []
    for p in procs:
        if p.pid in exclude:
            stats["self"] += 1
        elif (p.pid <= 4 and not p.exe) or p.lname in _SKIP_NAMES or (p.pid == 1 and not IS_WINDOWS):
            stats["skipped_names"] += 1
        elif not p.exe and not p.cmdline:
            stats["kernel"] += 1  # kernel threads / zombies have nothing to scan
        else:
            cand.append(p)
    cand.sort(key=priority, reverse=True)
    stats["capped"] = max(0, len(cand) - max_procs)
    return cand[:max_procs], stats


# =========================================================================== YARA scanning


def scan_pid(rules: Any, pid: int, timeout: float, grace: float = WATCHDOG_GRACE_S) -> Tuple[str, Any]:
    """Scan one process in a watchdog thread. Returns ('ok', matches) | ('denied'|'timeout'|'error', message) | ('hung', None).
    A scan that does not come back within ``timeout + grace`` seconds is abandoned (the thread is a daemon)."""
    box: Dict[str, Any] = {}

    def work() -> None:
        try:
            box["matches"] = rules.match(pid=pid, timeout=int(max(1, timeout)))
        except Exception as exc:  # yara.Error / TimeoutError / OSError ...
            box["error"] = exc

    t = threading.Thread(target=work, name=f"aegis-mem-{pid}", daemon=True)
    t.start()
    t.join(timeout + grace)
    if t.is_alive():
        return "hung", None
    if "error" in box:
        exc = box["error"]
        msg = f"{type(exc).__name__}: {exc}"
        low = msg.lower()
        if "timeout" in low or "timed out" in low:
            return "timeout", msg
        if any(k in low for k in ("attach", "access", "denied", "permission", "could not open", "not permitted", "no such process")):
            return "denied", msg
        return "error", msg
    return "ok", box.get("matches") or []


def _sev(meta: Dict[str, Any]) -> Severity:
    raw = str(meta.get("severity", "")).strip().lower()
    return Severity.parse(raw) if raw in ("info", "low", "medium", "high", "critical") else Severity.HIGH


def safe_to_quarantine(exe: str) -> bool:
    """Only drop-location binaries are quarantined with the process - never OS or vendor files."""
    if not exe or cl.is_in_windir(exe) or cl.is_in_program_files(exe):
        return False
    return cl.path_risk(exe) > 0


def rule_scope(meta: Dict[str, Any]) -> str:
    return str(meta.get("scope", "")).strip().lower()


def match_addresses(m: Any, limit: int = 16) -> List[int]:
    """Virtual addresses of the matched strings (yara-python >= 4.3 ``StringMatch.instances`` or the legacy tuples)."""
    out: List[int] = []
    try:
        for s in getattr(m, "strings", None) or []:
            instances = getattr(s, "instances", None)
            if instances is not None:
                out += [int(i.offset) for i in instances]
            elif isinstance(s, (tuple, list)) and s and isinstance(s[0], int):
                out.append(int(s[0]))
            if len(out) >= limit:
                break
    except Exception:
        pass
    return out[:limit]


def addresses_in_executable_memory(pid: int, addresses: Sequence[int]) -> Optional[bool]:
    """True if any address lies in an executable memory region of the process, False if none does, None if it cannot be
    determined (unsupported OS / no access). Linux reads /proc/<pid>/maps, Windows uses VirtualQueryEx."""
    if not addresses:
        return None
    try:
        if IS_WINDOWS:
            return _windows_any_executable(pid, addresses)
        if sys.platform.startswith("linux"):
            with open(f"/proc/{pid}/maps", "r", encoding="ascii", errors="replace") as fh:
                ranges = []
                for line in fh:
                    parts = line.split()
                    if len(parts) >= 2 and "-" in parts[0]:
                        lo, hi = (int(x, 16) for x in parts[0].split("-", 1))
                        ranges.append((lo, hi, "x" in parts[1]))
            known = False
            for a in addresses:
                for lo, hi, ex in ranges:
                    if lo <= a < hi:
                        known = True
                        if ex:
                            return True
            return False if known else None
    except Exception as exc:
        log.debug("region lookup failed for %s: %s", pid, exc)
    return None


def _windows_any_executable(pid: int, addresses: Sequence[int]) -> Optional[bool]:  # pragma: no cover - Windows only
    import ctypes
    from ctypes import wintypes

    class MBI(ctypes.Structure):
        _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p), ("AllocationProtect", wintypes.DWORD),
                    ("PartitionId", wintypes.WORD), ("RegionSize", ctypes.c_size_t), ("State", wintypes.DWORD),
                    ("Protect", wintypes.DWORD), ("Type", wintypes.DWORD)]

    k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(MBI), ctypes.c_size_t]
    k32.VirtualQueryEx.restype = ctypes.c_size_t
    h = k32.OpenProcess(0x0400, False, pid) or k32.OpenProcess(0x1000, False, pid)
    if not h:
        return None
    try:
        known = False
        for a in addresses:
            mbi = MBI()
            if k32.VirtualQueryEx(h, ctypes.c_void_p(a), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                known = True
                if mbi.State == MEM_COMMIT and (int(mbi.Protect) & 0xFF) in _EXEC_PROTECT:
                    return True
        return False if known else None
    finally:
        k32.CloseHandle(h)


def is_suspicious_process(p: ProcRec) -> bool:
    """A process that is itself worth a second look: runs from a malware drop location, has no image path, or is a script / LOLBin host."""
    if p.lname in _SUSPICIOUS_HOSTS:
        return True
    if not p.exe:
        return True
    return cl.path_risk(p.exe) > 0


def match_verdict(p: ProcRec, m: Any, region_exec=addresses_in_executable_memory) -> Optional[Tuple[str, Severity]]:
    """Decide whether a YARA memory match becomes a finding. Returns (corroboration, severity) or None to ignore it."""
    meta = dict(getattr(m, "meta", {}) or {})
    scope = rule_scope(meta)
    if scope == "file":
        return None
    sev = _sev(meta)
    if scope in MEMORY_SCOPES:
        return "memory-scoped rule", sev
    # generic (untagged) rule: needs corroboration that this is not just text sitting in a data buffer
    capped = min(sev, Severity.HIGH)
    try:
        ex = region_exec(p.pid, match_addresses(m)) if region_exec else None
    except Exception:
        ex = None
    if ex:
        return "match is in executable memory", capped
    if is_suspicious_process(p):
        return "the process itself is suspicious", capped
    return None


def match_finding(p: ProcRec, m: Any, corroboration: str = "memory-scoped rule", severity: Optional[Severity] = None) -> Finding:
    """Finding for one YARA match object (``rule``, ``meta``, ``namespace``, ``tags``, ``strings``)."""
    meta = dict(getattr(m, "meta", {}) or {})
    rule = str(getattr(m, "rule", "") or "unknown")
    sev = severity if severity is not None else _sev(meta)
    desc = str(meta.get("description") or rule)
    try:
        strings = sorted({str(getattr(s, "identifier", s)) for s in (getattr(m, "strings", None) or [])})[:8]
    except Exception:
        strings = []
    q = safe_to_quarantine(p.exe)
    mitre = [x.strip() for x in str(meta.get("mitre", "")).replace(";", ",").split(",") if x.strip()]
    rem = Remediation("kill_process", {"pid": p.pid, "path": p.exe, "quarantine": q},
                      "Terminate the process" + (" and quarantine its executable" if q else "")) if sev >= Severity.MEDIUM else None
    return Finding(
        f"AEG-MEM-{re.sub(r'[^A-Za-z0-9_]+', '_', rule)}", f"In-memory detection: {desc} ({p.name or os.path.basename(p.exe) or 'process'})",
        sev, Category.MALWARE,
        f"The running process {p.name or p.exe} (pid {p.pid}) contains in its memory a pattern matching the YARA rule "
        f"'{rule}': {desc}. Corroboration: {corroboration}. Memory scanning finds malware that never exists as a normal file - "
        "code injected into another program, or payloads that unpack themselves only when running. Security tools and analysis "
        "tools can contain such patterns legitimately, so check the process before acting.",
        p.label,
        {"pid": p.pid, "process": p.name, "exe": p.exe, "user": p.username, "rule": rule, "namespace": str(getattr(m, "namespace", "")),
         "tags": list(getattr(m, "tags", []) or []), "matched_strings": strings, "author": str(meta.get("author", "")),
         "reference": str(meta.get("reference", "")), "corroboration": corroboration, "scope": rule_scope(meta) or "generic",
         "source": "process memory"},
        "If you do not recognise this process, terminate it (the fix below does that) and run a full scan; change your passwords "
        "afterwards from a clean device if it handled credentials. If it is a security or analysis tool you use, ignore this.",
        rem, mitre=mitre or ["T1055"])


@dataclass
class MemResult:
    findings: List[Finding] = field(default_factory=list)
    scanned: int = 0
    denied: int = 0
    timeouts: int = 0
    errors: int = 0
    hung: bool = False
    out_of_time: bool = False
    skipped_self: int = 0
    first_error: str = ""
    ignored_generic: int = 0
    seen_pids: List[int] = field(default_factory=list)


def scan_processes(rules: Any, procs: Sequence[ProcRec], deadline: float, proc_timeout: float, cancelled=lambda: False,
                   grace: float = WATCHDOG_GRACE_S, exclude: Optional[Set[int]] = None,
                   region_exec=addresses_in_executable_memory) -> MemResult:
    """YARA-scan the given processes (already filtered/ordered). ``exclude`` pids are never passed to ``rules.match`` - a last
    line of defence that guarantees Aegis does not scan itself even if a caller forgets to filter."""
    res = MemResult()
    me = os.getpid()
    banned = set(exclude or ()) | {me}
    for p in procs:
        if cancelled():
            break
        if p.pid in banned:
            res.skipped_self += 1
            continue
        if time.monotonic() > deadline:
            res.out_of_time = True
            break
        status, payload = scan_pid(rules, p.pid, min(proc_timeout, max(1.0, deadline - time.monotonic())), grace)
        res.seen_pids.append(p.pid)
        if status == "ok":
            res.scanned += 1
            for m in payload:
                verdict = match_verdict(p, m, region_exec)
                if verdict is None:
                    if rule_scope(dict(getattr(m, "meta", {}) or {})) != "file":
                        res.ignored_generic += 1
                    continue
                res.findings.append(match_finding(p, m, verdict[0], verdict[1]))
        elif status == "denied":
            res.denied += 1
        elif status == "timeout":
            res.timeouts += 1
        elif status == "hung":
            res.hung = True
            res.errors += 1
            break  # a stuck native scan thread cannot be killed: do not pile up more
        else:
            res.errors += 1
            res.first_error = res.first_error or str(payload)
    return res


# =========================================================================== unbacked executable memory (Windows)


def private_exec_regions(pid: int, max_loops: int = 200000) -> Optional[List[Tuple[int, int, int]]]:
    """Private committed RWX regions (base, size, protection) of a process via ``VirtualQueryEx``; None when unavailable
    (non-Windows, or the process cannot be opened)."""
    if not IS_WINDOWS:
        return None
    try:
        import ctypes
        from ctypes import wintypes

        class MBI(ctypes.Structure):
            _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p), ("AllocationProtect", wintypes.DWORD),
                        ("PartitionId", wintypes.WORD), ("RegionSize", ctypes.c_size_t), ("State", wintypes.DWORD),
                        ("Protect", wintypes.DWORD), ("Type", wintypes.DWORD)]

        k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        k32.OpenProcess.restype = wintypes.HANDLE
        k32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(MBI), ctypes.c_size_t]
        k32.VirtualQueryEx.restype = ctypes.c_size_t
        h = k32.OpenProcess(0x0400, False, pid) or k32.OpenProcess(0x1000, False, pid)  # QUERY_INFORMATION, else LIMITED
        if not h:
            return None
        out: List[Tuple[int, int, int]] = []
        try:
            addr = 0
            mbi = MBI()
            for _ in range(max_loops):
                if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                    break
                base, size = int(mbi.BaseAddress or 0), int(mbi.RegionSize)
                if mbi.State == MEM_COMMIT and mbi.Type == MEM_PRIVATE and mbi.Protect in (PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY):
                    out.append((base, size, int(mbi.Protect)))
                nxt = base + size
                if size == 0 or nxt <= addr or nxt > 0x7FFFFFFFFFFF:
                    break
                addr = nxt
        finally:
            k32.CloseHandle(h)
        return out
    except Exception as exc:
        log.debug("VirtualQueryEx failed for %s: %s", pid, exc)
        return None


def rwx_finding(p: ProcRec, regions: Sequence[Tuple[int, int, int]]) -> Optional[Finding]:
    """MEDIUM finding when a non-JIT process holds private writable+executable memory."""
    if not regions or p.lname in _JIT_HOSTS:
        return None
    total = sum(r[1] for r in regions)
    q = safe_to_quarantine(p.exe)
    return Finding(
        "AEG-MEM-RWX", f"Unbacked executable memory in {p.name or os.path.basename(p.exe) or 'a process'}", Severity.MEDIUM, Category.SUSPICIOUS,
        f"The process {p.name or p.exe} (pid {p.pid}) has {len(regions)} memory region(s) ({total // 1024} KB) that are both writable "
        "and executable and are not backed by any file. Normal programs rarely do this; malware that injects shellcode or "
        "unpacks itself in memory does. This is a heuristic: security software that hooks programs, and some software that "
        "generates code at run time, can produce the same pattern.",
        p.label, {"pid": p.pid, "process": p.name, "exe": p.exe, "regions": len(regions), "total_bytes": total,
                  "first_regions": [{"base": hex(b), "size": s, "protect": hex(pr)} for b, s, pr in regions[:5]], "source": "process memory"},
        "Check whether you know this program and whether security software is installed that injects into processes. If neither "
        "applies, scan with YARA (this scanner) / a full scan, and consider terminating and quarantining the program.",
        Remediation("kill_process", {"pid": p.pid, "path": p.exe, "quarantine": q},
                    "Terminate the process" + (" and quarantine its executable" if q else "")),
        mitre=["T1055", "T1620"])


# =========================================================================== scanner


@register
class MemoryScanner(Scanner):
    name = "memory"
    title = "In-memory threat hunting"
    description = ("Scans the memory of running processes with YARA rules (fileless / injected malware) and flags "
                   "unbacked writable+executable memory on Windows.")
    platforms = ("windows", "linux", "darwin")
    needs_admin_for_full_results = True

    def run(self, ctx: ScanContext) -> Iterator[Emitted]:
        budget = float(ctx.options.get("memory_budget_s", DEFAULT_BUDGET_S) or DEFAULT_BUDGET_S)
        proc_timeout = float(ctx.options.get("memory_proc_timeout_s", DEFAULT_PROC_TIMEOUT_S) or DEFAULT_PROC_TIMEOUT_S)
        max_procs = int(ctx.options.get("memory_max_procs", DEFAULT_MAX_PROCS_DEEP if ctx.deep else DEFAULT_MAX_PROCS) or DEFAULT_MAX_PROCS)
        deadline = time.monotonic() + budget
        try:
            procs = list_processes()
        except Exception as exc:  # pragma: no cover - defensive
            yield CheckResult("AEG-MEM-YARA", "In-memory YARA scan", CheckStatus.ERROR, f"{type(exc).__name__}: {exc}", Category.MALWARE)
            return
        chosen, st = select_processes(procs, own_pids(procs), max_procs)
        ctx.bump("memory_processes_listed", st["total"])
        note = ("" if ctx.is_admin else " Run Aegis as Administrator/root to include system and other users' processes.")

        rules = ctx.signatures.yara_rules
        # ---- YARA over process memory
        if not HAVE_YARA:
            yield CheckResult("AEG-MEM-YARA", "In-memory YARA scan", CheckStatus.SKIP,
                              "yara-python is not installed (pip install yara-python); memory scanning needs it.", Category.MALWARE)
        elif rules is None:
            yield CheckResult("AEG-MEM-YARA", "In-memory YARA scan", CheckStatus.SKIP,
                              "No YARA rules are loaded (run 'aegis update' to download the rule set).", Category.MALWARE)
        else:
            ctx.report(self.name, f"scanning memory of up to {len(chosen)} process(es)")
            grace = float(ctx.options.get("memory_watchdog_grace_s", WATCHDOG_GRACE_S))
            res = scan_processes(rules, chosen, deadline, proc_timeout, cancelled=lambda: ctx.cancelled, grace=grace)
            ctx.bump("memory_processes_scanned", res.scanned)
            for f in res.findings:
                yield f
            problems: List[str] = []
            if res.denied:
                problems.append(f"{res.denied} process(es) could not be read (access denied)")
            if res.timeouts:
                problems.append(f"{res.timeouts} scan(s) timed out")
            if res.errors and not res.hung:
                problems.append(f"{res.errors} scan error(s) ({res.first_error[:80]})")
            if res.hung:
                problems.append("a scan stopped responding and the memory scan was aborted")
            if res.out_of_time:
                problems.append(f"the {int(budget)} s time budget was reached")
            if st["capped"]:
                problems.append(f"{st['capped']} lower-priority process(es) were not scanned (limit {max_procs})")
            if res.ignored_generic:
                problems.append(f"{res.ignored_generic} generic pattern match(es) in ordinary data memory were ignored (typically text shown "
                                "by a browser, editor or terminal)")
            detail = f"Scanned the memory of {res.scanned} of {st['total']} process(es)" + \
                (f" ({res.skipped_self + st['self']} Aegis process(es) skipped)" if (res.skipped_self + st['self']) else "") + \
                ("; " + "; ".join(problems) if problems else "") + "."
            if res.findings:
                status = CheckStatus.FAIL
            elif res.hung or (res.errors and not res.scanned):
                status = CheckStatus.ERROR if not res.scanned else CheckStatus.WARN
            elif problems and res.scanned == 0:
                status = CheckStatus.WARN
            else:
                status = CheckStatus.PASS
            yield CheckResult("AEG-MEM-YARA", "No malware patterns in process memory (YARA)", status,
                              detail + ("" if status == CheckStatus.FAIL else note), Category.MALWARE)
        # ---- unbacked executable memory (Windows only)
        if not IS_WINDOWS:
            yield CheckResult("AEG-MEM-RWX", "No unbacked executable memory", CheckStatus.SKIP,
                              "The unbacked-executable-memory heuristic is only available on Windows.", Category.SUSPICIOUS)
            return
        flagged = 0
        checked = 0
        out_of_time = False
        for p in chosen:
            if ctx.cancelled:
                break
            if time.monotonic() > deadline:
                out_of_time = True
                break
            if p.pid == os.getpid() or p.lname in _JIT_HOSTS:
                continue
            regions = private_exec_regions(p.pid)
            if regions is None:
                continue
            checked += 1
            if regions and loads_jit_runtime(p.pid):  # .NET / Java / V8 JIT code is expected, not injection
                ctx.bump("memory_rwx_jit_skipped")
                continue
            f = rwx_finding(p, regions)
            if f:
                flagged += 1
                yield f
        yield CheckResult("AEG-MEM-RWX", "No unbacked executable memory in processes", CheckStatus.FAIL if flagged else CheckStatus.PASS,
                          f"Examined {checked} process(es); {flagged} with writable+executable private memory"
                          + ("; time budget reached" if out_of_time else "") + ".", Category.SUSPICIOUS)
