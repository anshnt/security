"""DLL side-loading / search-order-hijack heuristics.

Windows loads a program's DLLs from the program's *own folder* before the system folder, so malware plants a fake
``version.dll`` / ``winhttp.dll`` / ``dbghelp.dll`` ... next to a legitimate, signed executable. The trusted
executable then loads the attacker's code under its good name (T1574.001; used by APT groups and most modern
loaders).

The scanner walks user-writable locations (AppData, ProgramData, Temp, Downloads, Public, Desktop) to a limited depth
and looks at every folder that contains both an EXE and a DLL:

* an **unsigned DLL** named like a Windows system DLL (or one the EXE statically imports) sitting next to an EXE,
* strengthened when a *signed* EXE actually imports that DLL name, the DLL is high-entropy (packed/encrypted payload)
  or forwards its exports to the real system DLL (the classic "proxy DLL" trick), or the folder is a malware drop
  location (Temp, Downloads, Public ...),
* candidates are also run through ``aegis.scanners.files.scan_file`` (hashes, YARA, PE heuristics).

False positives are kept low by skipping well-known application trees (Microsoft, Google, Mozilla, Discord, Slack,
Zoom, Teams, JetBrains, game launchers, Docker, Python/Node ...) and by requiring unsigned + suspicious name or location.
Parsing uses a small dependency-free PE reader; the scoring (``evaluate_dir``) is pure and unit-tested on any OS.
Limitation: a signature *directory* is treated as "signed" (the chain is not verified, to keep the scan fast).
"""

from __future__ import annotations

import functools
import hashlib
import logging
import math
import os
import re
import struct
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Sequence, Set, Tuple

from aegis.core import cmdline as cl
from aegis.core.models import Category, CheckResult, CheckStatus, Finding, Remediation, Severity
from aegis.core.platform import IS_WINDOWS, suspicious_dirs, user_home, windows_dir
from aegis.scanners.base import Emitted, ScanContext, Scanner, register
from aegis.scanners.files import scan_file

log = logging.getLogger("aegis.sideload")

MAX_DEPTH = 4
MAX_DIRS = 8000
MAX_EXES_PER_DIR = 12
MAX_DLLS_PER_DIR = 40
MAX_CANDIDATES_SCANNED = 40
MAX_FINDINGS = 60
EXE_READ_LIMIT = 24 * 1024 * 1024
DLL_READ_LIMIT = 16 * 1024 * 1024
HIGH_ENTROPY = 7.2
VERY_HIGH_ENTROPY = 7.6

# DLLs that are *not* KnownDLLs (so a copy next to the EXE wins the search order) and are classic hijack targets.
HIJACKABLE_DLLS = frozenset({
    "version.dll", "winhttp.dll", "wininet.dll", "dbghelp.dll", "cryptbase.dll", "cryptsp.dll", "wtsapi32.dll",
    "dwmapi.dll", "d3d9.dll", "mscms.dll", "ncrypt.dll", "profapi.dll", "userenv.dll", "wlbsctrl.dll", "secur32.dll",
    "lpk.dll", "usp10.dll", "msimg32.dll", "uxtheme.dll", "propsys.dll", "iphlpapi.dll", "winmm.dll", "wsock32.dll",
    "mpr.dll", "ntmarta.dll", "netapi32.dll", "samcli.dll", "sspicli.dll", "urlmon.dll", "wldp.dll", "dxgi.dll",
    "d3d11.dll", "dinput8.dll", "xinput1_3.dll", "xinput1_4.dll", "xinput9_1_0.dll", "opengl32.dll", "apphelp.dll",
    "bcrypt.dll", "dnsapi.dll", "rasapi32.dll", "shfolder.dll", "cscapi.dll", "oleacc.dll", "mswsock.dll",
    "credui.dll", "winsta.dll", "netutils.dll", "wkscli.dll", "logoncli.dll", "rstrtmgr.dll", "srvcli.dll",
    "slc.dll", "devobj.dll", "msasn1.dll", "ntshrui.dll", "hid.dll", "pdh.dll", "powrprof.dll", "dpapi.dll",
})

# Windows files commonly *shipped by apps in their own folder*; unsigned copies are still suspicious next to a signed EXE
# but they carry less weight than the hijack list above.
EXTRA_SYSTEM_DLLS = frozenset({
    "msvcp140.dll", "vcruntime140.dll", "msvcr100.dll", "msvcr120.dll", "mfc140u.dll", "msi.dll", "mscoree.dll",
    "wintrust.dll", "crypt32.dll", "dnsapi.dll", "normaliz.dll", "winspool.drv", "comctl32.dll", "gdiplus.dll",
    "ws2_32.dll", "wldap32.dll", "psapi.dll", "setupapi.dll", "shell32.dll", "kernel32.dll", "user32.dll",
    "advapi32.dll", "ole32.dll", "oleaut32.dll", "shlwapi.dll", "ntdll.dll", "msvcrt.dll", "rpcrt4.dll",
})

# Directory trees of well-known applications (matched on whole path components, case-insensitive).
_BENIGN_DIR_RX = re.compile(
    r"\\(?:microsoft|google|mozilla|discord|slack|zoom|teams|microsoft teams|jetbrains|steam|steamapps|steamlibrary|"
    r"epic games|epicgames|epic|docker|docker desktop|nodejs|node_modules|npm|site-packages|virtualenvs|\.venv|venv|"
    r"anaconda\d*|miniconda\d*|windowsapps|packages|package cache|spotify|whatsapp|dropbox|onedrive|"
    r"bravesoftware|vivaldi|opera software|github desktop|githubdesktop|gitkraken|postman|figma|1password|"
    r"bitwarden|telegram desktop|obsidian|code|vscode|cursor|riot games|battle\.net|blizzard entertainment|ubisoft|"
    r"gog galaxy|ea games|\.minecraft|roblox|overwolf|obs-studio|unityhub|\.cargo|\.rustup|\.nuget|\.gradle|\.m2|"
    r"jdk[\w.\-]*|python\d*(?:\.\d+)*|pythoncore[\w.\-]*)\\", re.I)


def is_benign_dir(path: str) -> bool:
    return bool(_BENIGN_DIR_RX.search(path.replace("/", "\\").rstrip("\\") + "\\"))


@functools.lru_cache(maxsize=1)
def system_dll_names() -> frozenset:
    """Lower-case file names of Windows system DLLs (System32 + SysWOW64 listing on Windows, a curated list elsewhere)."""
    names: Set[str] = set(HIJACKABLE_DLLS) | set(EXTRA_SYSTEM_DLLS)
    if IS_WINDOWS:
        for sub in ("System32", "SysWOW64"):
            try:
                with os.scandir(windows_dir() / sub) as it:
                    for e in it:
                        if e.name.lower().endswith(".dll"):
                            names.add(e.name.lower())
            except OSError:
                continue
    return frozenset(names)


# =========================================================================== light PE reader

@dataclass
class PELight:
    ok: bool = False
    is_dll: bool = False
    signed: bool = False  # an Authenticode signature directory is present (chain NOT verified)
    imports: Set[str] = field(default_factory=set)  # lower-case DLL names (static + delay-load)
    forwarders: List[str] = field(default_factory=list)  # export forwarder strings such as "version_orig.GetFileVersionInfoA"


def _cstr(data: bytes, off: Optional[int], limit: int = 160) -> str:
    if off is None or off < 0 or off >= len(data):
        return ""
    end = data.find(b"\x00", off, off + limit)
    return data[off:end if end >= 0 else off + limit].decode("latin-1", "replace")


def parse_pe_light(data: bytes) -> PELight:
    """Header, signature directory, import names and export forwarders only (no entropy, no function names). Never raises."""
    info = PELight()
    try:
        if data[:2] != b"MZ" or len(data) < 0x40:
            return info
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if pe + 24 > len(data) or data[pe:pe + 4] != b"PE\x00\x00":
            return info
        coff = pe + 4
        _machine, nsec, _ts, _, _, opt_size, chars = struct.unpack_from("<HHIIIHH", data, coff)
        opt = coff + 20
        is64 = struct.unpack_from("<H", data, opt)[0] == 0x20B
        dd = opt + (112 if is64 else 96)
        ndd = struct.unpack_from("<I", data, dd - 4)[0]
        dirs = [struct.unpack_from("<II", data, dd + 8 * i) for i in range(min(ndd, 16))]
        secs: List[Tuple[int, int, int]] = []
        so = opt + opt_size
        for i in range(min(nsec, 96)):
            o = so + 40 * i
            if o + 40 > len(data):
                break
            vsize, va, rsize, rptr = struct.unpack_from("<IIII", data, o + 8)
            secs.append((va, max(vsize, rsize), rptr))

        def off(rva: int) -> Optional[int]:
            for va, size, ptr in secs:
                if va <= rva < va + size and ptr:
                    return rva - va + ptr
            return None

        info.ok = True
        info.is_dll = bool(chars & 0x2000)
        info.signed = len(dirs) > 4 and dirs[4][0] > 0 and dirs[4][1] > 0
        # static imports
        if len(dirs) > 1 and dirs[1][0]:
            o = off(dirs[1][0])
            for _ in range(256):
                if o is None or o + 20 > len(data) or not any(data[o:o + 20]):
                    break
                name_rva = struct.unpack_from("<I", data, o + 12)[0]
                nm = _cstr(data, off(name_rva)).lower()
                if nm:
                    info.imports.add(nm)
                o += 20
        # delay-load imports
        if len(dirs) > 13 and dirs[13][0]:
            o = off(dirs[13][0])
            for _ in range(128):
                if o is None or o + 32 > len(data) or not any(data[o:o + 32]):
                    break
                name_rva = struct.unpack_from("<I", data, o + 4)[0]
                nm = _cstr(data, off(name_rva)).lower()
                if nm:
                    info.imports.add(nm)
                o += 32
        # export forwarders (functions whose RVA points back inside the export directory)
        if dirs and dirs[0][0] and dirs[0][1]:
            exp_rva, exp_size = dirs[0]
            o = off(exp_rva)
            if o is not None and o + 40 <= len(data):
                nfunc = struct.unpack_from("<I", data, o + 20)[0]
                table = off(struct.unpack_from("<I", data, o + 28)[0])
                if table is not None:
                    for i in range(min(nfunc, 600)):
                        if table + 4 * i + 4 > len(data):
                            break
                        rva = struct.unpack_from("<I", data, table + 4 * i)[0]
                        if exp_rva <= rva < exp_rva + exp_size:
                            s = _cstr(data, off(rva))
                            if "." in s:
                                info.forwarders.append(s)
                                if len(info.forwarders) >= 50:
                                    break
    except (struct.error, IndexError, ValueError, OverflowError):
        pass
    return info


def sample_entropy(data: bytes, cap: int = 4 * 1024 * 1024) -> float:
    """Shannon entropy (bits/byte) of the data; large inputs are sampled head+tail."""
    if not data:
        return 0.0
    if len(data) > cap:
        data = data[: cap // 2] + data[-cap // 2:]
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


# =========================================================================== analysis (pure)

@dataclass
class PEFile:
    path: str
    name: str  # lower-case file name
    size: int = 0
    signed: bool = False
    is_dll: bool = False
    imports: Set[str] = field(default_factory=set)
    forwarders: List[str] = field(default_factory=list)
    entropy: float = 0.0
    mtime: float = 0.0


@dataclass
class Candidate:
    dll: PEFile
    hosts: List[PEFile]  # EXEs in the folder that import the DLL's name
    exes: List[PEFile]  # every PE EXE in the folder
    score: int
    reasons: List[str]
    loc_risk: int

    @property
    def severity(self) -> Optional[Severity]:
        return score_severity(self.score)


def score_severity(score: int) -> Optional[Severity]:
    if score >= 70:
        return Severity.HIGH
    if score >= 45:
        return Severity.MEDIUM
    if score >= 30:
        return Severity.LOW
    return None


def evaluate_dir(exes: Sequence[PEFile], dlls: Sequence[PEFile], sysnames: Iterable[str] = (), loc_risk: int = 0) -> List[Candidate]:
    """Score every unsigned DLL in one folder against the EXEs next to it. Only returns candidates with a reportable score."""
    sysnames = set(sysnames) | set(HIJACKABLE_DLLS)
    pe_exes = [e for e in exes if not e.is_dll]
    if not pe_exes:
        return []
    out: List[Candidate] = []
    for dll in dlls:
        if not dll.is_dll or dll.signed:
            continue  # signed DLLs are assumed legitimate (limitation: signature chain is not verified)
        name = dll.name
        primary = name in HIJACKABLE_DLLS
        sysname = name in sysnames
        hosts = [e for e in pe_exes if name in e.imports]
        signed_hosts = [e for e in hosts if e.signed]
        any_signed_exe = any(e.signed for e in pe_exes)
        high_ent = dll.entropy >= HIGH_ENTROPY and dll.size > 8 * 1024
        proxy = len(dll.forwarders) >= 3
        # The DLL must be interesting by *name* (system-style) - or be an imported custom-named DLL that also looks
        # like a payload (high entropy / proxy exports): an ordinary unsigned plug-in DLL is not reported.
        if not (sysname or (hosts and (high_ent or proxy))):
            continue
        # ... and a trusted-looking host (signed EXE) or an inherently suspicious DLL must be present.
        if not (any_signed_exe or high_ent or proxy):
            continue
        score = 0
        reasons: List[str] = []
        if primary:
            score += 20
            reasons.append(f"{name} is a Windows DLL name that attackers routinely impersonate")
        elif sysname:
            score += 12
            reasons.append(f"{name} has the same name as a Windows system DLL")
        else:
            score += 8
            reasons.append(f"{name} is an unsigned DLL that the program loads from its own folder")
        if signed_hosts:
            score += 25
            reasons.append(f"the signed program {signed_hosts[0].name} imports {name}, so Windows will load this copy instead of the system one"
                           if sysname else f"the signed program {signed_hosts[0].name} loads this unsigned DLL")
        elif hosts:
            score += 12
            reasons.append(f"{hosts[0].name} imports {name}")
        if loc_risk >= 2:
            score += 15
            reasons.append("the folder is a typical malware drop location (Temp, Downloads, Public)")
        elif loc_risk == 1:
            score += 8
            reasons.append("the folder is user-writable (AppData / ProgramData)")
        if dll.entropy >= VERY_HIGH_ENTROPY and dll.size > 8 * 1024:
            score += 25
            reasons.append(f"the DLL is almost random data (entropy {dll.entropy:.1f}), typical of an encrypted or packed payload")
        elif high_ent:
            score += 18
            reasons.append(f"the DLL has high entropy ({dll.entropy:.1f}), typical of a packed payload")
        if proxy:
            score += 20
            reasons.append(f"it forwards {len(dll.forwarders)} exports to another DLL (a 'proxy DLL' that passes calls to the real one)")
        out.append(Candidate(dll, hosts, list(pe_exes), score, reasons, loc_risk))
    return out


def candidate_finding(c: Candidate, sha256: str = "", scan_findings: Sequence[Finding] = ()) -> Finding:
    sev = c.severity or Severity.LOW
    flagged = [f for f in scan_findings if f.severity >= Severity.MEDIUM]
    if any(f.severity >= Severity.HIGH for f in scan_findings):
        sev = max(sev, Severity.HIGH)
    host = (c.hosts or c.exes)[0]
    folder = os.path.dirname(c.dll.path)
    rem = Remediation("quarantine_file", {"path": c.dll.path}, f"Move {c.dll.name} to quarantine (it can be restored)") \
        if sev >= Severity.MEDIUM else None
    return Finding(
        "AEG-SIDELOAD-DLL", f"Possible DLL side-loading: unsigned {c.dll.name} next to {host.name}", sev, Category.SUSPICIOUS,
        f"The folder {folder} contains the program {host.name}"
        + (" (digitally signed)" if host.signed else "") + f" and an unsigned file called {c.dll.name}. "
        "Windows programs load DLLs from their own folder before the system folder, so an attacker can plant a fake DLL "
        "next to a trusted program and have it run under the trusted program's good name (DLL side-loading). "
        "Why this was flagged: " + "; ".join(c.reasons) + ". This is a heuristic - some legitimate software and game mods ship "
        "such files.",
        c.dll.path,
        {"dll": c.dll.path, "dll_name": c.dll.name, "sha256": sha256, "size": c.dll.size, "entropy": round(c.dll.entropy, 2),
         "host_executables": [e.name for e in (c.hosts or c.exes)][:6], "host_signed": host.signed,
         "host_imports_dll": bool(c.hosts), "forwarded_exports": c.dll.forwarders[:5], "score": c.score,
         "reasons": c.reasons, "file_scan_findings": [f.rule_id for f in flagged]},
        f"Do not run {host.name} until you know where this folder came from. If you did not install this software, "
        f"quarantine {c.dll.name} (and the program) and run a full scan. If you did install it, reinstall from the vendor's "
        "website - the vendor's DLL should be digitally signed.",
        rem, mitre=["T1574.001", "T1036"])


# =========================================================================== collection

def read_pe_file(path: str, is_exe: bool) -> Optional[PEFile]:
    """Parse one file into a PEFile (None if unreadable or not a PE)."""
    try:
        st = os.stat(path)
        with open(path, "rb") as fh:
            data = fh.read(EXE_READ_LIMIT if is_exe else DLL_READ_LIMIT)
    except OSError:
        return None
    light = parse_pe_light(data)
    if not light.ok:
        return None
    return PEFile(path=path, name=os.path.basename(path).lower(), size=st.st_size, signed=light.signed, is_dll=light.is_dll,
                  imports=light.imports, forwarders=light.forwarders,
                  entropy=0.0 if is_exe else sample_entropy(data), mtime=st.st_mtime)


def _hash(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def default_roots() -> List[Path]:
    """User-writable locations where side-loading payloads are staged."""
    roots: List[Path] = list(suspicious_dirs())
    home = user_home()
    roots += [home / "Desktop", home / "Documents"] if IS_WINDOWS else [home / "Desktop"]
    out: List[Path] = []
    seen: Set[str] = set()
    for r in roots:
        try:
            if not r.is_dir():
                continue
            key = str(r.resolve()).lower()
        except OSError:
            continue
        if key not in seen:
            seen.add(key)
            out.append(r)
    # drop roots that live inside another root (e.g. %TEMP% inside %LOCALAPPDATA%) so folders are walked once
    keys = [str(r.resolve()).lower().rstrip("\\/") for r in out]

    def inside(child: str, parent: str) -> bool:
        return child != parent and (child.startswith(parent + "/") or child.startswith(parent + "\\"))

    return [r for r, k in zip(out, keys) if not any(inside(k, o) for o in keys)]


def iter_pair_dirs(roots: Iterable[Path], deadline: float, max_depth: int = MAX_DEPTH, max_dirs: int = MAX_DIRS,
                   cancelled=lambda: False) -> Iterator[Tuple[str, List[str], int]]:
    """Yield (folder, file names, loc_risk) for folders holding both an .exe and a .dll, skipping well-known app trees."""
    visited = 0
    for root in roots:
        root_s = str(root)
        base_depth = root_s.rstrip("\\/").count(os.sep)
        for dirpath, dirnames, filenames in os.walk(root_s, onerror=lambda e: None, followlinks=False):
            if cancelled() or time.monotonic() > deadline or visited >= max_dirs:
                return
            visited += 1
            depth = dirpath.rstrip("\\/").count(os.sep) - base_depth
            if depth >= max_depth:
                dirnames[:] = []
            if is_benign_dir(dirpath):
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in dirnames if not is_benign_dir(os.path.join(dirpath, d))]
            lows = [f.lower() for f in filenames]
            if any(f.endswith(".exe") for f in lows) and any(f.endswith(".dll") for f in lows):
                yield dirpath, filenames, cl.path_risk(os.path.join(dirpath, "x.dll"))


def analyse_folder(dirpath: str, filenames: Sequence[str], loc_risk: int, sysnames: Iterable[str]) -> List[Candidate]:
    """Read the PE files of one folder and score its DLLs."""
    exes: List[PEFile] = []
    for fn in [f for f in filenames if f.lower().endswith(".exe")][:MAX_EXES_PER_DIR]:
        pf = read_pe_file(os.path.join(dirpath, fn), True)
        if pf and not pf.is_dll:
            exes.append(pf)
    if not exes:
        return []
    wanted = set(sysnames) | set(HIJACKABLE_DLLS)
    for e in exes:
        wanted |= e.imports
    dlls: List[PEFile] = []
    for fn in [f for f in filenames if f.lower().endswith(".dll") and f.lower() in wanted][:MAX_DLLS_PER_DIR]:
        pf = read_pe_file(os.path.join(dirpath, fn), False)
        if pf and pf.is_dll:
            dlls.append(pf)
    return evaluate_dir(exes, dlls, sysnames, loc_risk)


def _roots_for(ctx: ScanContext) -> List[Path]:
    custom = ctx.options.get("sideload_roots")
    if custom:
        return [Path(p) for p in custom if Path(p).is_dir()]
    roots = default_roots()
    # explicit folders from the command line (but never whole drives)
    for p in ctx.paths:
        try:
            if p.is_dir() and len(p.resolve().parts) > 2 and all(str(p.resolve()).lower() != str(r.resolve()).lower() for r in roots):
                roots.append(p)
        except OSError:
            continue
    return roots


@register
class SideloadScanner(Scanner):
    name = "sideload"
    title = "DLL side-loading hunt"
    description = ("Finds unsigned DLLs named like Windows system DLLs (version.dll, winhttp.dll, dbghelp.dll ...) planted next "
                   "to legitimate signed programs in user-writable folders.")
    platforms = ("windows", "linux", "darwin")

    def run(self, ctx: ScanContext) -> Iterator[Emitted]:
        roots = _roots_for(ctx)
        if not roots:
            yield CheckResult("AEG-SIDELOAD-SCAN", "DLL side-loading hunt", CheckStatus.SKIP,
                              "No user-writable program folders to examine.", Category.SUSPICIOUS)
            return
        budget = float(ctx.options.get("sideload_budget_s", 45) or 45)
        deadline = time.monotonic() + budget
        sysnames = system_dll_names()
        folders = 0
        emitted: List[Finding] = []
        scanned = 0
        ctx.report(self.name, "looking for DLL side-loading in " + ", ".join(str(r) for r in roots[:4]))
        try:
            for dirpath, files, loc_risk in iter_pair_dirs(roots, deadline, cancelled=lambda: ctx.cancelled):
                folders += 1
                ctx.bump("sideload_folders")
                try:
                    cands = analyse_folder(dirpath, files, loc_risk, sysnames)
                except Exception as exc:  # one odd folder must not stop the hunt
                    log.debug("sideload: %s failed: %s", dirpath, exc)
                    continue
                for c in cands:
                    if len(emitted) >= MAX_FINDINGS:
                        break
                    sub: List[Finding] = []
                    if scanned < MAX_CANDIDATES_SCANNED and c.score >= 20:
                        scanned += 1
                        try:
                            sub = scan_file(ctx, Path(c.dll.path))
                        except Exception as exc:  # pragma: no cover - defensive
                            log.debug("scan_file failed for %s: %s", c.dll.path, exc)
                        if sub:
                            c.score += 25
                            c.reasons.append("the file scanner also flags it (" + sub[0].title + ")")
                    if c.severity is not None:
                        f = candidate_finding(c, _hash(c.dll.path), sub)
                        emitted.append(f)
                        yield f
                    for s in sub:
                        yield s
        except Exception as exc:  # pragma: no cover - defensive
            log.warning("sideload scan failed: %s", exc, exc_info=True)
            yield CheckResult("AEG-SIDELOAD-SCAN", "DLL side-loading hunt", CheckStatus.ERROR, f"{type(exc).__name__}: {exc}",
                              Category.SUSPICIOUS)
            return
        bad = [f for f in emitted if f.severity >= Severity.MEDIUM]
        timed_out = time.monotonic() > deadline
        yield CheckResult(
            "AEG-SIDELOAD-SCAN", "No DLL side-loading candidates in user-writable folders",
            CheckStatus.FAIL if bad else (CheckStatus.WARN if emitted else CheckStatus.PASS),
            f"{folders} folder(s) with programs and DLLs examined; {len(emitted)} candidate(s)"
            + (" (time budget reached - results are partial)" if timed_out else "") + ".", Category.SUSPICIOUS)
