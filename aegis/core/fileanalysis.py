"""Static file analysis: type detection, entropy, a dependency-free PE parser
and heuristics for executables, scripts, Office documents, shortcuts and more."""

from __future__ import annotations

import math
import re
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from aegis.core.atoms import Prefiltered
from aegis.core.models import Severity

EXEC_EXTS = {"exe", "dll", "scr", "com", "pif", "cpl", "sys", "ocx", "drv", "efi", "msi", "msp", "appx", "msix"}
SCRIPT_EXTS = {"ps1", "psm1", "psd1", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "sh", "py",
               "pl", "php", "jsp", "asp", "aspx", "rb", "applescript", "scpt", "reg", "inf", "sct", "xsl", "xll"}
OFFICE_EXTS = {"doc", "docx", "docm", "dot", "dotm", "xls", "xlsx", "xlsm", "xlsb", "xlam", "xla", "ppt", "pptx",
               "pptm", "ppam", "rtf", "one", "pub"}
ARCHIVE_EXTS = {"zip", "jar", "rar", "7z", "gz", "tgz", "cab", "iso", "img", "vhd", "vhdx", "apk", "xpi", "crx"}
DECOY_EXTS = {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "gif", "txt", "mp3", "mp4", "avi", "zip",
              "rtf", "ppt", "pptx", "csv", "html", "htm"}
RISKY_EXTS = EXEC_EXTS | SCRIPT_EXTS | OFFICE_EXTS | ARCHIVE_EXTS | {"lnk", "url", "pdf", "html", "htm", "svg",
                                                                      "elf", "so", "dylib", "bin", "jar", "chm"}
RTLO = "\u202e"


@dataclass
class Indicator:
    rule_id: str
    title: str
    severity: Severity
    score: int  # contribution to the heuristic score (0-100)
    detail: str = ""
    mitre: List[str] = field(default_factory=list)


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def classify(head: bytes, ext: str) -> str:
    if head[:2] == b"MZ":
        return "pe"
    if head[:4] == b"\x7fELF":
        return "elf"
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xcf"):
        return "macho" if ext != "class" else "other"
    if head[:4] == b"L\x00\x00\x00" and head[4:8] == b"\x01\x14\x02\x00":
        return "lnk"
    if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "office" if ext not in ("msi", "msp") else "pe"
    if head[:4] == b"PK\x03\x04":
        if ext in OFFICE_EXTS:
            return "office"
        return "archive"
    if head[:5] == b"{\\rtf":
        return "office"
    if head[:5] == b"%PDF-":
        return "pdf"
    if head[:4] in (b"Rar!", b"7z\xbc\xaf") or head[:2] == b"\x1f\x8b" or head[:4] == b"MSCF":
        return "archive"
    if ext in ("iso", "img", "vhd", "vhdx"):
        return "archive"
    if ext in SCRIPT_EXTS or head[:2] == b"#!":
        return "script"
    if ext in ("lnk",):
        return "lnk"
    if _looks_text(head):
        return "text"
    return "other"


def _looks_text(b: bytes) -> bool:
    if not b:
        return False
    if b[:2] in (b"\xff\xfe", b"\xfe\xff") or b[:3] == b"\xef\xbb\xbf":
        return True
    sample = b[:4096]
    nontext = sum(1 for c in sample if c < 9 or (13 < c < 32))
    return nontext / len(sample) < 0.05


# ===================================================================== PE parser

@dataclass
class PESection:
    name: str
    vsize: int
    raw_size: int
    raw_ptr: int
    characteristics: int
    entropy: float = 0.0

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & 0x20000000)

    @property
    def writable(self) -> bool:
        return bool(self.characteristics & 0x80000000)


@dataclass
class PEInfo:
    machine: int = 0
    timestamp: int = 0
    is_dll: bool = False
    is_64: bool = False
    subsystem: int = 0
    entry_point: int = 0
    sections: List[PESection] = field(default_factory=list)
    imports: Dict[str, List[str]] = field(default_factory=dict)
    has_signature: bool = False
    has_dotnet: bool = False
    overlay_size: int = 0
    error: str = ""

    @property
    def import_names(self) -> List[str]:
        return [f for funcs in self.imports.values() for f in funcs]


def _rva_to_offset(rva: int, sections: List[PESection]) -> Optional[int]:
    for s in sections:
        size = max(s.vsize, s.raw_size)
        if s.raw_ptr and s.vsize >= 0 and rva >= _sec_va(s) and rva < _sec_va(s) + size:
            return rva - _sec_va(s) + s.raw_ptr
    return None


def _sec_va(s: PESection) -> int:
    return getattr(s, "_va", 0)


def parse_pe(data: bytes) -> PEInfo:
    """Parse enough of a PE image for heuristics. Robust against truncated or
    malformed files: on any inconsistency it records `error` and returns what it has."""
    info = PEInfo()
    try:
        if data[:2] != b"MZ" or len(data) < 0x40:
            info.error = "not a PE"
            return info
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            info.error = "bad PE header"
            return info
        coff = e_lfanew + 4
        info.machine, nsec, info.timestamp, _, _, opt_size, chars = struct.unpack_from("<HHIIIHH", data, coff)
        info.is_dll = bool(chars & 0x2000)
        opt = coff + 20
        magic = struct.unpack_from("<H", data, opt)[0]
        info.is_64 = magic == 0x20B
        info.entry_point = struct.unpack_from("<I", data, opt + 16)[0]
        info.subsystem = struct.unpack_from("<H", data, opt + 68)[0]
        dd_off = opt + (112 if info.is_64 else 96)
        ndd = struct.unpack_from("<I", data, dd_off - 4)[0]
        dirs = []
        for i in range(min(ndd, 16)):
            dirs.append(struct.unpack_from("<II", data, dd_off + i * 8))
        sec_off = opt + opt_size
        max_end = 0
        for i in range(min(nsec, 96)):
            o = sec_off + i * 40
            if o + 40 > len(data):
                break
            name = data[o:o + 8].rstrip(b"\x00").decode("latin-1")
            vsize, va, raw_size, raw_ptr = struct.unpack_from("<IIII", data, o + 8)
            ch = struct.unpack_from("<I", data, o + 36)[0]
            s = PESection(name, vsize, raw_size, raw_ptr, ch)
            s._va = va  # type: ignore[attr-defined]
            if raw_ptr and raw_size:
                s.entropy = round(entropy(data[raw_ptr:raw_ptr + min(raw_size, 4 * 1024 * 1024)]), 3)
                max_end = max(max_end, raw_ptr + raw_size)
            info.sections.append(s)
        # Security directory (index 4) is a *file offset*, not an RVA.
        if len(dirs) > 4:
            sec_ptr, sec_size = dirs[4]
            info.has_signature = sec_size > 0 and sec_ptr > 0
            if info.has_signature:
                max_end = max(max_end, sec_ptr + sec_size)
        if len(dirs) > 14:
            info.has_dotnet = dirs[14][1] > 0
        if max_end and len(data) > max_end:
            info.overlay_size = len(data) - max_end
        if len(dirs) > 1 and dirs[1][0]:
            info.imports = _parse_imports(data, dirs[1][0], info)
    except (struct.error, IndexError, ValueError) as exc:
        info.error = f"malformed PE: {exc}"
    return info


def _read_cstr(data: bytes, off: int, limit: int = 256) -> str:
    end = data.find(b"\x00", off, off + limit)
    if end < 0:
        end = off + limit
    return data[off:end].decode("latin-1", "replace")


def _parse_imports(data: bytes, rva: int, info: PEInfo) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    off = _rva_to_offset(rva, info.sections)
    if off is None:
        return out
    thunk_size = 8 if info.is_64 else 4
    ord_flag = 1 << 63 if info.is_64 else 1 << 31
    for _ in range(512):  # descriptors
        if off + 20 > len(data):
            break
        oft, _, _, name_rva, ft = struct.unpack_from("<IIIII", data, off)
        if not (oft or name_rva or ft):
            break
        off += 20
        noff = _rva_to_offset(name_rva, info.sections)
        if noff is None:
            continue
        dll = _read_cstr(data, noff).lower()
        funcs: List[str] = []
        toff = _rva_to_offset(oft or ft, info.sections)
        if toff is not None:
            for _ in range(4096):
                if toff + thunk_size > len(data):
                    break
                val = struct.unpack_from("<Q" if info.is_64 else "<I", data, toff)[0]
                toff += thunk_size
                if not val:
                    break
                if val & ord_flag:
                    funcs.append(f"ord{val & 0xFFFF}")
                    continue
                hoff = _rva_to_offset(val & 0x7FFFFFFF, info.sections)
                if hoff is not None:
                    funcs.append(_read_cstr(data, hoff + 2))
        out[dll] = funcs
    return out


# ===================================================================== heuristics

# Import combinations that are strongly associated with specific malicious capabilities.
_IMPORT_COMBOS: List[Tuple[str, str, Tuple[str, ...], int, List[str]]] = [
    ("AEG-H-PE-INJECT", "Process injection capability", ("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"), 30, ["T1055"]),
    ("AEG-H-PE-HOLLOW", "Process hollowing capability", ("NtUnmapViewOfSection", "SetThreadContext", "ResumeThread"), 35, ["T1055.012"]),
    ("AEG-H-PE-APC", "APC injection capability", ("QueueUserAPC", "OpenThread", "VirtualAllocEx"), 25, ["T1055.004"]),
    ("AEG-H-PE-KEYLOG", "Keylogging capability", ("SetWindowsHookExA|SetWindowsHookExW", "GetAsyncKeyState|GetKeyState|GetKeyboardState", "GetForegroundWindow"), 25, ["T1056.001"]),
    ("AEG-H-PE-CREDDUMP", "LSASS memory access capability", ("MiniDumpWriteDump", "OpenProcess"), 30, ["T1003.001"]),
    ("AEG-H-PE-SCREEN", "Screen capture + upload capability", ("BitBlt", "GetDC", "InternetOpenA|InternetOpenW|WinHttpOpen"), 15, ["T1113"]),
    ("AEG-H-PE-RANSOM", "File-encryption + enumeration capability", ("CryptEncrypt|BCryptEncrypt", "FindFirstFileW|FindFirstFileExW", "MoveFileExW|MoveFileW"), 20, ["T1486"]),
    ("AEG-H-PE-ANTIDBG", "Anti-debugging / evasion", ("IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"), 10, ["T1622"]),
    ("AEG-H-PE-DOWNLOADER", "Download-and-execute capability", ("URLDownloadToFileA|URLDownloadToFileW", "ShellExecuteA|ShellExecuteW|WinExec|CreateProcessA|CreateProcessW"), 20, ["T1105"]),
]

_PACKER_SECTIONS = {
    "upx0": "UPX", "upx1": "UPX", "upx2": "UPX", ".aspack": "ASPack", ".adata": "ASPack", ".mpress1": "MPRESS",
    ".mpress2": "MPRESS", ".petite": "Petite", ".nsp0": "NsPack", ".nsp1": "NsPack", ".themida": "Themida",
    ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".enigma1": "Enigma", ".packed": "generic", "pec2": "PECompact",
    ".pelock": "PELock", ".yp": "Y0da", ".perplex": "Perplex", ".spack": "SimplePack", ".winlice": "WinLicense",
}


def _has(names: set, spec: str) -> bool:
    return any(alt in names for alt in spec.split("|"))


def pe_indicators(info: PEInfo, size: int) -> List[Indicator]:
    out: List[Indicator] = []
    if info.error:
        if "malformed" in info.error:
            out.append(Indicator("AEG-H-PE-MALFORMED", "Malformed PE structure", Severity.LOW, 10, info.error))
        return out
    names = set(info.import_names)
    for rid, title, req, score, mitre in _IMPORT_COMBOS:
        if all(_has(names, r) for r in req):
            out.append(Indicator(rid, title, Severity.MEDIUM, score, ", ".join(req), mitre))

    for s in info.sections:
        packer = _PACKER_SECTIONS.get(s.name.lower())
        if packer:
            out.append(Indicator("AEG-H-PE-PACKER", f"Packed with {packer}", Severity.LOW, 15, f"section {s.name}", ["T1027.002"]))
            break
    # Skip resources (compressed icons/images) and COFF long-name sections ("/19", "/32"): the
    # compressed DWARF debug data Go/MinGW binaries carry - high entropy there is normal.
    high_ent = [s for s in info.sections if s.entropy > 7.2 and s.raw_size > 4096
                and s.name.lower() != ".rsrc" and not s.name.startswith("/")]
    if high_ent:
        out.append(Indicator("AEG-H-PE-ENTROPY", "High-entropy (packed/encrypted) sections", Severity.LOW, 15,
                             ", ".join(f"{s.name}={s.entropy}" for s in high_ent), ["T1027.002"]))
    wx = [s.name for s in info.sections if s.executable and s.writable]
    if wx:
        out.append(Indicator("AEG-H-PE-WX", "Writable + executable section", Severity.LOW, 10, ", ".join(wx), ["T1027"]))
    if info.imports is not None and len(names) <= 5 and not info.has_dotnet and size > 20_000:
        out.append(Indicator("AEG-H-PE-FEWIMPORTS", "Very small import table (runtime API resolution)", Severity.LOW, 10,
                             f"{len(names)} imports", ["T1027"]))
    if info.timestamp > 0:
        import time

        if info.timestamp > time.time() + 86400 * 2:
            out.append(Indicator("AEG-H-PE-FUTURETS", "Compile timestamp in the future", Severity.LOW, 5, str(info.timestamp)))
    if info.overlay_size > 1024 * 1024 and not info.has_signature:
        out.append(Indicator("AEG-H-PE-OVERLAY", "Large unsigned overlay (embedded payload)", Severity.LOW, 10,
                             f"{info.overlay_size} bytes"))
    if not info.has_signature:
        out.append(Indicator("AEG-H-PE-UNSIGNED", "No Authenticode signature", Severity.INFO, 5))
    return out


def name_indicators(path: Path, kind: str) -> List[Indicator]:
    out: List[Indicator] = []
    name = path.name
    if RTLO in name:
        out.append(Indicator("AEG-H-NAME-RTLO", "Right-to-left override character in file name", Severity.HIGH, 60,
                             repr(name), ["T1036.002"]))
    parts = name.lower().split(".")
    if len(parts) >= 3:
        last, prev = parts[-1], parts[-2]
        if last in EXEC_EXTS | SCRIPT_EXTS | {"lnk"} and prev in DECOY_EXTS:
            out.append(Indicator("AEG-H-NAME-DOUBLEEXT", "Double extension disguising an executable", Severity.HIGH, 50,
                                 name, ["T1036.007"]))
    if re.search(r"\s{6,}\.(exe|scr|bat|cmd|js|vbs)$", name, re.I):
        out.append(Indicator("AEG-H-NAME-PADDING", "Whitespace-padded name hiding the real extension", Severity.HIGH, 45,
                             name, ["T1036"]))
    ext = parts[-1] if len(parts) > 1 else ""
    if kind == "pe" and ext and ext not in EXEC_EXTS and ext not in ("tmp", "bin", "dat", "", "mui", "node", "pyd",
                                                                     "winmd", "ax", "tlb", "mun", "acm", "tsp", "rll", "ime",
                                                                     "fon", "old", "bak", "mzz", "api", "xpi", "aex",
                                                                     "8bi", "8bf", "vst", "vst3", "ppi", "bpl", "flt", "dlx",
                                                                     "plugin", "manifest", "lic", "crx", "spl"):
        if ext in DECOY_EXTS:
            out.append(Indicator("AEG-H-NAME-MISMATCH", f"Windows executable disguised as .{ext}", Severity.HIGH, 50,
                                 name, ["T1036.008"]))
    return out


_SCRIPT_PATTERNS: List[Tuple[str, str, str, int, List[str]]] = [
    ("AEG-H-SCR-ENCCMD", "Encoded PowerShell command", r"(?i)-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{40,}", 35, ["T1059.001", "T1027"]),
    ("AEG-H-SCR-CRADLE", "PowerShell download-and-execute cradle",
     # the web cmdlet must actually fetch something (URL or variable): bare alias lists such as
     # syntax-highlighter keyword tables ("iex ... irm ise iwmi iwr") are not cradles
     r"(?i)\b(iex|invoke-expression)\b[\s(]+.{0,80}(downloadstring|downloaddata|net\.webclient|"
     r"\b(?:invoke-webrequest|invoke-restmethod|iwr|irm)\b\s*(?:-uri\s+)?\(?\s*['\"]?(?:https?://|\$))",
     40, ["T1059.001", "T1105"]),
    ("AEG-H-SCR-CRADLE2", "PowerShell download-and-execute cradle",
     r"(?i)\b(downloadstring|invoke-webrequest|iwr|irm|invoke-restmethod)\b[^|\n]{0,200}\|\s*(iex|invoke-expression)\b",
     40, ["T1059.001", "T1105"]),
    ("AEG-H-SCR-AMSI", "AMSI bypass attempt", r"(?i)(amsiInitFailed|AmsiScanBuffer|amsi\.dll|System\.Management\.Automation\.AmsiUtils)", 45, ["T1685"]),
    ("AEG-H-SCR-DEFENDER", "Disables Microsoft Defender",
     r"(?i)(Set-MpPreference\s+.{0,60}-Disable(RealtimeMonitoring|BehaviorMonitoring|IOAVProtection|ScriptScanning)\s+(\$true|1)|DisableAntiSpyware)", 45, ["T1685"]),
    # Only *broad* exclusions are malicious-looking; excluding a dev/build folder is routine.
    ("AEG-H-SCR-DEFENDER-EXCL", "Adds a broad Microsoft Defender exclusion",
     r"(?im)Add-MpPreference\b[^\n]{0,80}?-Exclusion(?:Path|Process|Extension)\s+[\"']?(?:"
     r"[A-Za-z]:\\?(?=[\"'\s,;]|$)"                                   # whole drive
     r"|\$env:(?:TEMP|TMP|APPDATA|LOCALAPPDATA|USERPROFILE|PUBLIC|ProgramData|SystemDrive|windir)\b"
     r"|%(?:TEMP|TMP|APPDATA|LOCALAPPDATA|USERPROFILE|PUBLIC|ProgramData|SystemDrive)%"
     r"|[A-Za-z]:\\(?:Users|ProgramData|Windows\\Temp|Temp)\\?(?=[\"'\s,;]|$)"   # profile/data roots
     r"|[^\n\"',;]*\\(?:AppData|Temp|Downloads|Public)(?:\\[^\n\"',;]*)?(?=[\"'\s,;]|$)"
     r"|\.?(?:exe|dll|ps1|bat|cmd|vbs|js|scr|hta)(?=[\"'\s,;]|$)"         # whole executable types
     r"|(?:powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32)(?:\.exe)?(?=[\"'\s,;]|$))",
     45, ["T1685"]),
    ("AEG-H-SCR-SHADOW", "Deletes volume shadow copies / backups (ransomware)",
     r"(?i)(vssadmin(\.exe)?\s+delete\s+shadows|wmic(\.exe)?\s+shadowcopy\s+delete|wbadmin(\.exe)?\s+delete\s+(catalog|systemstatebackup)|bcdedit(\.exe)?\s+/set\s+\{?default\}?\s+recoveryenabled\s+no|Win32_ShadowCopy.{0,40}Delete)", 60, ["T1490"]),
    ("AEG-H-SCR-LOLBIN-DL", "LOLBin used to download a payload",
     r"(?i)(certutil(\.exe)?\s+.{0,40}-urlcache.{0,40}http|bitsadmin(\.exe)?\s+/transfer|mshta(\.exe)?\s+https?://|regsvr32(\.exe)?\s+.{0,30}/i:\s*https?://|curl(\.exe)?\s+.{0,80}-o\s+.{0,80}\.(exe|dll|ps1|bat))", 40, ["T1105", "T1218"]),
    ("AEG-H-SCR-HIDDEN", "Hidden-window execution with policy bypass",
     r"(?i)-w(indowstyle)?\s+h(idden)?\b.{0,120}-(ep|exec|executionpolicy)\s+bypass|-(ep|exec|executionpolicy)\s+bypass.{0,120}-w(indowstyle)?\s+h(idden)?\b", 25, ["T1564.003"]),
    ("AEG-H-SCR-REFLECT", "In-memory .NET assembly loading", r"(?i)\[(System\.)?Reflection\.Assembly\]::Load\s*\(", 25, ["T1620"]),
    ("AEG-H-SCR-VBSHELL", "Script launches shell from the web",
     r"(?i)(WScript\.Shell|Shell\.Application).{0,300}(http|\.Run|ShellExecute).{0,200}(powershell|cmd|mshta|http)", 25, ["T1059.005"]),
    ("AEG-H-SCR-OBFJS", "Obfuscated JavaScript/VBScript", r"(?i)(eval\s*\(\s*(unescape|atob|String\.fromCharCode)|Execute\s*\(\s*(Chr|StrReverse)|ExecuteGlobal)", 25, ["T1027"]),
    ("AEG-H-SCR-CLIPPER", "Clipboard hijack of crypto addresses", r"(?i)(Get-Clipboard|clipboardData|GetClipboardData).{0,400}(bc1|0x[a-f0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})", 30, ["T1115"]),
    ("AEG-H-SCR-PERSIST", "Script installs persistence",
     r"(?i)(schtasks(\.exe)?\s+/create|New-ScheduledTask|reg(\.exe)?\s+add\s+.{0,80}\\CurrentVersion\\Run|New-ItemProperty.{0,120}CurrentVersion\\Run|Start Menu\\Programs\\Startup)", 15, ["T1547.001", "T1053.005"]),
    ("AEG-H-SCR-CREDS", "Credential theft tooling",
     r"(?i)(sekurlsa::|lsadump::|Invoke-Mimikatz|procdump.{0,30}lsass|comsvcs(\.dll)?.{0,20}MiniDump)", 60, ["T1003.001"]),
    ("AEG-H-SCR-FIREWALL", "Disables the firewall", r"(?i)(netsh\s+(adv)?firewall\s+set\s+\w*\s*(state\s+off|opmode\s+disable)|Set-NetFirewallProfile.{0,60}-Enabled\s+(False|0))", 35, ["T1686"]),
    ("AEG-H-SCR-LINUX-DROPPER", "Shell download-and-execute",
     r"(?i)(curl|wget)\s+[^|;\n]{0,200}\|\s*(ba|z|da)?sh\b|(curl|wget)[^;\n]{0,200};\s*chmod\s+\+x", 20, ["T1105"]),
    ("AEG-H-SCR-REVSHELL", "Reverse shell", r"(/dev/tcp/\d{1,3}(\.\d{1,3}){3}/\d+|nc(at)?\s+(-e|-c)\s+/bin/(ba)?sh|socket\.socket.{0,200}subprocess.{0,80}/bin/(ba)?sh|New-Object\s+System\.Net\.Sockets\.TCPClient.{0,300}GetStream)", 55, ["T1059"]),
    ("AEG-H-SCR-MINER", "Cryptocurrency miner configuration", r"(?i)(stratum\+(tcp|ssl)://|\"donate-level\"|xmrig|minexmr|nicehash|--cpu-max-threads-hint)", 40, ["T1496"]),
    ("AEG-H-SCR-WEBSHELL", "Web shell", r"(?i)(eval\s*\(\s*(base64_decode|gzinflate|str_rot13)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)|assert\s*\(\s*\$_(POST|REQUEST)|system\s*\(\s*\$_(GET|POST|REQUEST)\[)", 60, ["T1505.003"]),
]
_COMPILED_SCRIPT = [(rid, t, Prefiltered(re.compile(p.encode("utf-8"), re.S)), s, m) for rid, t, p, s, m in _SCRIPT_PATTERNS]


def content_indicators(data: bytes, kind: str, lowered: Optional[bytes] = None) -> List[Indicator]:
    """Regex heuristics applied to scripts, text, shortcuts and documents.
    ``lowered`` (= data.lower()) may be passed to share the atom-prefilter copy."""
    out: List[Indicator] = []
    sample = data
    if data[:2] == b"\xff\xfe":
        try:
            sample = data.decode("utf-16-le", "replace").encode("utf-8")
        except Exception:
            pass
    elif kind == "lnk":
        # LNK argument strings are UTF-16; flatten so regexes see them.
        sample = data + data.replace(b"\x00", b"")
    low = lowered if (sample is data and lowered is not None) else sample.lower()
    for rid, title, rx, score, mitre in _COMPILED_SCRIPT:
        m = rx.search(sample, low)
        if m:
            sev = Severity.HIGH if score >= 45 else Severity.MEDIUM if score >= 25 else Severity.LOW
            out.append(Indicator(rid, title, sev, score, m.group(0)[:120].decode("utf-8", "replace"), mitre))
    return out


def lnk_indicators(data: bytes) -> List[Indicator]:
    flat = data.replace(b"\x00", b"").lower()
    out = []
    if any(x in flat for x in (b"powershell", b"cmd.exe /c", b"cmd /c", b"mshta", b"wscript", b"cscript", b"rundll32",
                               b"regsvr32", b"certutil", b"bitsadmin", b"conhost --headless")):
        out.append(Indicator("AEG-H-LNK-LOLBIN", "Shortcut launches a script interpreter / LOLBin", Severity.MEDIUM, 35,
                             "", ["T1204.002", "T1547.009"]))
    if len(data) > 200_000:
        out.append(Indicator("AEG-H-LNK-SIZE", "Oversized shortcut (embedded payload)", Severity.MEDIUM, 25, f"{len(data)} bytes"))
    return out


def office_indicators(path: Path, data: bytes) -> List[Indicator]:
    out: List[Indicator] = []
    if data[:4] == b"PK\x03\x04":
        try:
            with zipfile.ZipFile(path) as z:
                names = [n.lower() for n in z.namelist()]
                if any(n.endswith("vbaproject.bin") for n in names):
                    out.append(Indicator("AEG-H-DOC-MACRO", "Document contains VBA macros", Severity.LOW, 20, "", ["T1137", "T1204.002"]))
                    for n in z.namelist():
                        if n.lower().endswith("vbaproject.bin"):
                            out += _vba_indicators(z.read(n)[:5_000_000])
                for n in z.namelist():
                    if n.lower().endswith(".rels") and z.getinfo(n).file_size < 1_000_000:
                        rel = z.read(n)
                        if re.search(rb'TargetMode="External"', rel) and re.search(rb'(attachedTemplate|oleObject|frame)', rel, re.I) \
                                and re.search(rb'Target="(https?|file|\\\\)', rel, re.I):
                            out.append(Indicator("AEG-H-DOC-REMOTE", "Remote template / OLE object injection", Severity.HIGH, 50,
                                                 n, ["T1221"]))
                            break
                if any(n.endswith((".exe", ".scr", ".dll", ".js", ".vbs", ".hta")) for n in names):
                    out.append(Indicator("AEG-H-DOC-EMBEDEXE", "Document embeds an executable/script", Severity.HIGH, 45, "", ["T1027.009"]))
        except (zipfile.BadZipFile, OSError, KeyError):
            pass
    elif data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        if b"VBA" in data or b"_VBA_PROJECT" in data.replace(b"\x00", b""):
            out.append(Indicator("AEG-H-DOC-MACRO", "Document contains VBA macros", Severity.LOW, 20, "", ["T1137"]))
            out += _vba_indicators(data)
        if b"Equation.3" in data or b"EQNEDT32" in data.upper():
            out.append(Indicator("AEG-H-DOC-EQNEDT", "Equation Editor object (CVE-2017-11882 exploit vector)", Severity.HIGH, 50, "", ["T1203"]))
    elif data[:5] == b"{\\rtf":
        low = data.lower()
        if b"\\objdata" in low and (b"equation.3" in low or b"0002ce02" in low or b"package" in low):
            out.append(Indicator("AEG-H-RTF-EXPLOIT", "RTF with embedded OLE exploit object", Severity.HIGH, 55, "", ["T1203"]))
    return out


def _vba_indicators(blob: bytes) -> List[Indicator]:
    """VBA source is usually compressed, but keywords survive often enough in
    the p-code/identifier tables for a useful heuristic."""
    flat = blob.replace(b"\x00", b"")
    auto = re.search(rb"(?i)(AutoOpen|Auto_Open|Document_Open|Workbook_Open|AutoExec|Document_Close)", flat)
    bad = re.search(rb"(?i)(Shell|WScript\.Shell|CreateObject|URLDownloadToFile|MSXML2\.XMLHTTP|Powershell|ADODB\.Stream|CallByName|VirtualAlloc|RtlMoveMemory)", flat)
    if auto and bad:
        return [Indicator("AEG-H-DOC-AUTOEXEC", "Auto-executing macro that spawns code / downloads",
                          Severity.HIGH, 50, f"{auto.group(0).decode()} + {bad.group(0).decode()}", ["T1204.002", "T1059.005"])]
    return []


def pdf_indicators(data: bytes) -> List[Indicator]:
    out = []
    if re.search(rb"/(JavaScript|JS)\b", data) and re.search(rb"/(OpenAction|AA)\b", data):
        out.append(Indicator("AEG-H-PDF-AUTOJS", "PDF runs JavaScript on open", Severity.MEDIUM, 30, "", ["T1204.002"]))
    if re.search(rb"/Launch\b", data):
        out.append(Indicator("AEG-H-PDF-LAUNCH", "PDF /Launch action (runs external program)", Severity.HIGH, 45, "", ["T1204.002"]))
    if re.search(rb"/EmbeddedFile\b", data) and re.search(rb"\.(exe|scr|js|vbs|hta|bat)\)", data, re.I):
        out.append(Indicator("AEG-H-PDF-EMBEDEXE", "PDF embeds an executable", Severity.HIGH, 45, "", ["T1027.009"]))
    return out


def ransom_note_indicators(path: Path, data: bytes) -> List[Indicator]:
    name = path.name.lower()
    if not re.search(r"(decrypt|restore|recover|readme|how.?to|!!|ransom|_files|instruction)", name):
        return []
    low = data[:200_000].lower()
    hits = sum(1 for k in (b"bitcoin", b"btc", b"decrypt", b"encrypted", b"tor browser", b".onion", b"private key",
                           b"your files", b"monero", b"ransom") if k in low)
    if hits >= 4:
        return [Indicator("AEG-H-RANSOMNOTE", "Ransomware ransom note", Severity.CRITICAL, 90, path.name, ["T1486"])]
    return []


def score_to_severity(score: int) -> Optional[Severity]:
    if score >= 80:
        return Severity.HIGH
    if score >= 50:
        return Severity.MEDIUM
    if score >= 30:
        return Severity.LOW
    return None
