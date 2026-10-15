"""Shared command-line analysis used by the process, persistence and real-time
scanners.

* ``extract_executable`` - which program (or DLL for rundll32/regsvr32) does a
  command line really run? Handles quoting, unquoted paths with spaces,
  ``%ENV%`` variables, ``\\??\\`` / ``\\SystemRoot\\`` prefixes.
* ``analyse_command_line`` - LOLBin abuse / suspicious pattern detection with
  precompiled regexes. Rules are deliberately specific (benign admin and
  installer command lines must not trigger them).
* Windows path predicates (``path_risk`` ...) that work on *strings*, so the
  decision logic is unit-testable on any OS.

Nothing here touches the OS except optional ``os.path.exists`` probing.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Pattern, Tuple

from aegis.core.models import Severity

Hit = Tuple[str, str, Severity, List[str], str]  # (rule_id, title, severity, mitre, matched)

MAX_ANALYSE_LEN = 8192

# --------------------------------------------------------------------------- path helpers

_WIN_DEFAULTS: Dict[str, str] = {
    "SYSTEMROOT": r"C:\Windows",
    "WINDIR": r"C:\Windows",
    "SYSTEMDRIVE": "C:",
    "PROGRAMFILES": r"C:\Program Files",
    "PROGRAMFILES(X86)": r"C:\Program Files (x86)",
    "PROGRAMW6432": r"C:\Program Files",
    "PROGRAMDATA": r"C:\ProgramData",
    "COMSPEC": r"C:\Windows\System32\cmd.exe",
    "COMMONPROGRAMFILES": r"C:\Program Files\Common Files",
}

_ENV_RE = re.compile(r"%([^%\s]+)%")
_WIN_STYLE_RE = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\|%|\\\?\?\\|\\SystemRoot\\|system32\\|syswow64\\)", re.I)
_EXE_EXTS = ("exe", "com", "bat", "cmd", "scr", "pif", "dll", "sys", "cpl", "ocx", "msi", "msc", "ps1", "vbs", "vbe",
             "js", "jse", "wsf", "wsh", "hta", "jar", "lnk", "drv", "sct", "ax")
_PATH_EXT_RE = re.compile(r"^(.+?\.(?:" + "|".join(_EXE_EXTS) + r"))(?=$|[\s\"',;|&<>])", re.I)
_SWITCH_RE = re.compile(r"^[/-]")


def is_windows_style(path: str) -> bool:
    """True if the string looks like a Windows path/command (drive, UNC, %VAR%, \\??\\...)."""
    return bool(_WIN_STYLE_RE.match(path.strip().lstrip('"'))) or "\\" in path.split(" ")[0]


def expand_env(text: str) -> str:
    """Expand ``%VAR%`` (case-insensitive; sane defaults for core Windows vars on any OS)."""
    if "%" not in text:
        return text
    env = {k.upper(): v for k, v in os.environ.items()}

    def sub(m: "re.Match[str]") -> str:
        name = m.group(1).upper()
        return env.get(name) or _WIN_DEFAULTS.get(name) or m.group(0)

    return _ENV_RE.sub(sub, text)


def clean_path(path: str) -> str:
    """Strip quotes / NT prefixes, expand %VARS%, resolve \\SystemRoot\\ and bare system32\\."""
    p = path.strip().strip('"').strip("'").strip()
    p = expand_env(p)
    low = p.lower()
    if low.startswith("\\??\\"):
        p = p[4:]
    elif low.startswith("\\\\?\\") and not low.startswith("\\\\?\\unc\\"):
        p = p[4:]
    low = p.lower()
    root = expand_env("%SystemRoot%")
    if low.startswith("\\systemroot\\"):
        p = root + p[11:]
    elif low.startswith(("system32\\", "syswow64\\")):
        p = root + "\\" + p
    return p


def basename(path: str) -> str:
    return re.split(r"[\\/]", path.strip().strip('"'))[-1]


def dirname(path: str) -> str:
    parts = re.split(r"[\\/]", path.strip().strip('"'))
    return "\\".join(parts[:-1]) if len(parts) > 1 else ""


def norm_win(path: str) -> str:
    """Lower-case, backslash-separated, NT-prefix-free form for comparisons."""
    p = clean_path(path).replace("/", "\\").lower()
    return p


# Directories that are user-writable but home to many legitimate programs.
_BENIGN_USER_DIRS = (
    "\\appdata\\local\\programs\\", "\\appdata\\local\\microsoft\\", "\\appdata\\roaming\\microsoft\\",
    "\\programdata\\microsoft\\", "\\appdata\\local\\google\\", "\\appdata\\local\\mozilla\\",
    "\\appdata\\local\\discord\\", "\\appdata\\local\\slack\\", "\\appdata\\local\\zoom\\",
    "\\appdata\\roaming\\zoom\\", "\\appdata\\local\\packages\\", "\\programdata\\package cache\\",
    "\\appdata\\local\\github", "\\appdata\\local\\jetbrains\\", "\\appdata\\local\\spotify",
    "\\appdata\\roaming\\spotify", "\\appdata\\local\\whatsapp", "\\appdata\\local\\1password",
    "\\appdata\\local\\bravesoftware\\", "\\appdata\\local\\vivaldi\\", "\\appdata\\local\\teams",
    "\\appdata\\local\\temp\\_mei", "\\programdata\\chocolatey\\", "\\appdata\\local\\temp\\chocolatey",
    "\\programdata\\docker", "\\programdata\\microsoft\\windows defender\\",
)
_HIGH_RISK_WIN = re.compile(
    r"^[a-z]:\\(?:users\\[^\\]+\\(?:appdata\\local\\temp\\|appdata\\roaming\\[^\\]+\.(?:exe|dll|scr|bat|vbs|js|ps1)$|"
    r"downloads\\|desktop\\[^\\]+\.(?:exe|scr|bat|vbs|js|ps1)$|appdata\\locallow\\)|"
    r"users\\public\\|windows\\temp\\|\$recycle\.bin\\|perflogs\\|programdata\\[^\\]+\.(?:exe|dll|scr|bat|vbs|js|ps1)$|"
    r"temp\\|tmp\\|windows\\tasks\\|windows\\debug\\|windows\\fonts\\|windows\\help\\|windows\\inf\\.+\.exe$)")
_LOW_RISK_WIN = re.compile(r"^[a-z]:\\(?:users\\[^\\]+\\appdata\\|programdata\\|users\\[^\\]+\\(?:documents|music|pictures|videos)\\)")


def path_risk(path: str) -> int:
    """0 = not in a user-writable drop location, 1 = user-writable application
    dir (AppData\\...), 2 = classic malware drop location (Temp, Downloads,
    Public, Recycle Bin, ...). Works on Windows-style strings on any OS; POSIX
    paths are rated /tmp,/var/tmp,/dev/shm = 2, ~/.cache,~/.local = 1."""
    if not path:
        return 0
    if is_windows_style(path):
        n = norm_win(path)
        if any(b in n for b in _BENIGN_USER_DIRS):
            return 0
        if _HIGH_RISK_WIN.match(n):
            return 2
        if _LOW_RISK_WIN.match(n):
            return 1
        return 0
    p = path.strip().strip('"')
    if p.startswith(("/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "/private/tmp/", "/private/var/tmp/",
                     "/Users/Shared/", "/Library/Caches/")):
        return 2
    if "/." in p and not p.startswith(("/usr/", "/opt/", "/bin/", "/etc/")):
        # hidden directory/file inside a user's home or a world-writable area
        if re.search(r"/\.[^/]+/", p) and re.match(r"^(?:/home/|/root/|/Users/)", p):
            return 1
    return 0


def is_in_windir(path: str) -> bool:
    n = norm_win(path)
    return bool(re.match(r"^[a-z]:\\windows\\", n))


def is_in_system32(path: str) -> bool:
    return bool(re.match(r"^[a-z]:\\windows\\(?:system32|syswow64)\\", norm_win(path)))


def is_in_program_files(path: str) -> bool:
    return bool(re.match(r"^[a-z]:\\program files(?: \(x86\))?\\", norm_win(path)))


# --------------------------------------------------------------------------- tokenising

def split_command_line(cmd: str) -> List[str]:
    """Split a command line into tokens honouring double quotes (Windows rules,
    simplified; quotes are removed)."""
    tokens: List[str] = []
    cur: List[str] = []
    in_q = False
    started = False
    for ch in cmd.strip():
        if ch == '"':
            in_q = not in_q
            started = True
        elif ch.isspace() and not in_q:
            if started:
                tokens.append("".join(cur))
                cur, started = [], False
        else:
            cur.append(ch)
            started = True
    if started:
        tokens.append("".join(cur))
    return tokens


def _first_program(cmd: str) -> Tuple[str, str]:
    """Return (program, rest_of_command_line) for a raw command line."""
    s = cmd.strip()
    if not s:
        return "", ""
    if s[0] == '"':
        end = s.find('"', 1)
        if end == -1:
            inner, rest = s[1:], ""
        else:
            inner, rest = s[1:end], s[end + 1:]
        # `"C:\x y\z.exe -arg"` (quote swallowed the args)
        m = _PATH_EXT_RE.match(inner) if is_windows_style(inner) else None
        if m and len(m.group(1)) < len(inner):
            rest = inner[len(m.group(1)):] + " " + rest
            inner = m.group(1)
        return inner, rest.strip()
    if s[0] == "'":
        end = s.find("'", 1)
        if end > 0:
            return s[1:end], s[end + 1:].strip()
    if is_windows_style(s):
        m = _PATH_EXT_RE.match(s)
        if m:
            return m.group(1), s[m.end():].strip()
        # progressive existence probe for `C:\Program Files\Foo\foo -x` without extension
        words = s.split(" ")
        for i in range(len(words), 0, -1):
            cand = clean_path(" ".join(words[:i]))
            if i > 1 and (os.path.exists(cand) or os.path.exists(cand + ".exe")):
                return " ".join(words[:i]), " ".join(words[i:])
        return words[0], " ".join(words[1:])
    parts = s.split(None, 1)
    return parts[0], parts[1] if len(parts) > 1 else ""


_DLL_HOSTS = {"rundll32", "rundll32.exe"}
_REGSVR_HOSTS = {"regsvr32", "regsvr32.exe"}
_URLISH = re.compile(r"^(?:https?|ftps?|javascript|vbscript|file):", re.I)


def _rundll32_target(rest: str) -> Optional[str]:
    rest = rest.strip()
    while rest[:1] in ("/", "-") and rest:  # rundll32 has few switches (/d) - skip them
        parts = rest.split(None, 1)
        rest = parts[1] if len(parts) > 1 else ""
    if not rest or _URLISH.match(rest.lstrip('"')):
        return None
    if rest[0] == '"':
        end = rest.find('"', 1)
        chunk = rest[1:end] if end > 0 else rest[1:]
        if "," in chunk and not chunk.lower().endswith(tuple("." + e for e in _EXE_EXTS)):
            chunk = chunk.rsplit(",", 1)[0]
    else:
        if "," not in rest.split(None, 1)[0] and "," not in rest:
            # `rundll32 foo.dll` (no entry point) - take first token
            chunk = rest.split(None, 1)[0]
        else:
            chunk = rest.split(",", 1)[0]
    chunk = chunk.strip().strip('"')
    if not chunk or ":" in chunk[2:] or _URLISH.match(chunk):
        return None
    return clean_path(chunk)


def _regsvr32_target(rest: str) -> Optional[str]:
    s = rest.strip()
    while s and s[0] in "/-":
        parts = s.split(None, 1)
        s = parts[1] if len(parts) > 1 else ""
    if not s:
        return None
    if s[0] == '"':
        end = s.find('"', 1)
        chunk = s[1:end] if end > 0 else s[1:]
    else:
        m = _PATH_EXT_RE.match(s) if is_windows_style(s) else None
        chunk = m.group(1) if m else s.split(None, 1)[0]
    if _URLISH.match(chunk):
        return None
    return clean_path(chunk)


def extract_executable(cmd: str) -> Optional[str]:
    """Path of the program a command line runs.

    ``rundll32``/``regsvr32`` return the DLL they load when one is present. The
    result has quotes removed, ``%VARS%`` expanded, and NT prefixes resolved."""
    if not cmd or not cmd.strip():
        return None
    program, rest = _first_program(cmd)
    if not program:
        return None
    exe = clean_path(program) if is_windows_style(program) or "%" in program else os.path.expandvars(program.strip('"'))
    name = basename(exe).lower()
    if name in _DLL_HOSTS:
        dll = _rundll32_target(rest)
        return dll or exe
    if name in _REGSVR_HOSTS:
        dll = _regsvr32_target(rest)
        return dll or exe
    return exe or None


def first_program_name(cmd: str) -> str:
    """Lower-case program name (no directory, no .exe) of the first token of a command line."""
    program, _ = _first_program(cmd)
    n = basename(program).lower() if program else ""
    return n[:-4] if n.endswith(".exe") else n


def script_target(cmd: str) -> Optional[str]:
    """For script hosts (wscript/cscript/mshta/powershell -File/cmd /c script/
    python/node/bash/java -jar) return the script file the command runs."""
    program, rest = _first_program(cmd)
    if not program:
        return None
    name = basename(program).lower()
    name = name[:-4] if name.endswith(".exe") else name
    toks = split_command_line(rest)
    if name in ("wscript", "cscript", "mshta"):
        for t in toks:
            if t.startswith(("/", "-")):
                continue
            return None if _URLISH.match(t) else clean_path(t)
        return None
    if name in ("powershell", "pwsh"):
        for i, t in enumerate(toks):
            if t.lower() in ("-file", "/file", "-f") and i + 1 < len(toks):
                return clean_path(toks[i + 1])
        for t in toks:
            if t.lower().endswith(".ps1"):
                return clean_path(t.lstrip("&").strip("'"))
        return None
    if name == "cmd":
        m = re.search(r"/[ck]\s+(.*)$", rest, re.I | re.S)
        if not m:
            return None
        inner = m.group(1).strip()
        if inner.startswith('"') and inner.endswith('"') and inner.count('"') > 2:
            inner = inner[1:-1]
        prog, _ = _first_program(inner)
        if prog and prog.lower().endswith((".bat", ".cmd", ".vbs", ".js", ".ps1", ".exe", ".hta", ".lnk")):
            return clean_path(prog)
        return None
    if name in ("python", "python3", "pythonw", "py", "node", "perl", "ruby", "bash", "sh", "zsh", "dash"):
        for t in toks:
            if not t.startswith("-"):
                return t
        return None
    if name == "java":
        for i, t in enumerate(toks):
            if t == "-jar" and i + 1 < len(toks):
                return toks[i + 1]
    return None


# --------------------------------------------------------------------------- detection rules

# user-writable drop locations as they appear (unexpanded or expanded) in command lines
_UW = (r"(?:%(?:temp|tmp|appdata|public)%|\\appdata\\(?:local\\temp\\|roaming\\(?!microsoft\\)|locallow\\)|"
       r"\\users\\public\\|\\windows\\temp\\|\\(?:temp|tmp)\\|\\downloads\\|\\\$recycle\.bin\\|\\perflogs\\|"
       r"\\programdata\\[^\\\s\"']{1,40}\.(?:exe|dll|bat|ps1|vbs|js|hta)\b)")
_PS = r"(?:powershell|pwsh)(?:\.exe)?"
_SHELL = r"(?:/bin/|/usr/bin/)?(?:ba|z|da|k)?sh"
_ENC_FLAG = r"[-/](?:" + "|".join(["ec"] + ["encodedcommand"[:i] for i in range(1, 15)]) + r")"
_B64 = r"[\"']?[A-Za-z0-9+/=]{20,}"
_SUSP_HOSTS = (r"(?:https?://\d{1,3}(?:\.\d{1,3}){3}|pastebin|transfer\.sh|ngrok|duckdns|no-ip|ddns|discordapp|"
               r"anonfiles|file\.io|temp\.sh|termbin|hastebin|ix\.io|sprunge|githubusercontent\.com/[^/\s]+/[^/\s]+/raw)")
_LOLBIN_NAMES = (r"(?:cmd|powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|curl|wget|"
                 r"msiexec|installutil|regasm|regsvcs|msbuild)")


def _p(template: str) -> Pattern[str]:
    t = (template.replace("@UW@", _UW).replace("@PS@", _PS).replace("@SHELL@", _SHELL)
         .replace("@ENC@", _ENC_FLAG).replace("@B64@", _B64).replace("@SUSP@", _SUSP_HOSTS)
         .replace("@LOL@", _LOLBIN_NAMES))
    return re.compile(t, re.I | re.S)


@dataclass(frozen=True)
class Rule:
    suffix: str
    title: str
    severity: Severity
    mitre: Tuple[str, ...]
    pattern: Pattern[str]
    supersedes: Tuple[str, ...] = ()
    guard: Optional[Callable[[str], bool]] = None

    @property
    def rule_id(self) -> str:
        return "AEG-CMD-" + self.suffix


S = Severity

RULES: List[Rule] = [
    # ---------------------------------------------------------------- PowerShell
    Rule("PS-ENC-STEALTH", "PowerShell with encoded command and evasion flags", S.HIGH, ("T1059.001", "T1027.010"),
         _p(r"\b@PS@\"?(?=\s)(?=.*\s@ENC@\s+@B64@)(?=.*(?:\s[-/]w(?:in\w*)?\s+h(?:idden)?\b|\s[-/]nop(?:r\w*)?\b|"
            r"\s[-/](?:ep|exec\w*)\s+(?:bypass|unrestricted)|\s[-/]noni(?:n\w*)?\b))"), supersedes=("AEG-CMD-PS-ENC",)),
    Rule("PS-ENC", "PowerShell with Base64-encoded command", S.MEDIUM, ("T1059.001", "T1027.010"),
         _p(r"\b@PS@\"?(?=\s)(?=.*\s@ENC@\s+@B64@)")),
    Rule("PS-CRADLE", "PowerShell download cradle (download and execute in memory)", S.HIGH, ("T1059.001", "T1105"),
         _p(r"(?:\biex\b|invoke-expression)[\s\S]{0,300}?(?:downloadstring|downloadfile|invoke-webrequest|\biwr\b|"
            r"invoke-restmethod|\birm\b|net\.webclient|system\.net\.webclient)|"
            r"(?:downloadstring|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|net\.webclient)[\s\S]{0,300}?"
            r"(?:\|\s*iex\b|\|\s*invoke-expression|\biex\b\s*[(\"'$]|invoke-expression)")),
    Rule("PS-INMEM", "PowerShell decodes and executes a Base64/compressed payload in memory", S.HIGH,
         ("T1059.001", "T1027", "T1620"),
         _p(r"frombase64string[\s\S]{0,400}?(?:gzipstream|deflatestream|\biex\b|invoke-expression|assembly\]::load|\.invoke\()|"
            r"(?:\biex\b|invoke-expression)[\s\S]{0,400}?frombase64string|"
            r"assembly\]::load\(\s*\[?(?:convert|system\.convert)\]?::frombase64string")),
    Rule("PS-DOWNLOAD", "PowerShell downloads a file from a URL", S.MEDIUM, ("T1105", "T1059.001"),
         _p(r"\b@PS@\"?(?=\s)(?=.*https?://)(?=.*(?:\.downloadfile\(|\.downloaddata\(|start-bitstransfer|"
            r"(?:invoke-webrequest|\biwr\b)[^|;]*-out(?:file)?\b))"), supersedes=()),
    Rule("PS-AMSI", "AMSI bypass attempt", S.HIGH, ("T1562.001",),
         _p(r"amsiinitfailed|amsiutils|amsicontext|amsiscanbuffer|\[ref\]\.assembly\.gettype\([^)]*amsi")),
    Rule("PS-REVSHELL", "PowerShell reverse shell (TCPClient + stream execution)", S.CRITICAL, ("T1059.001", "T1095"),
         _p(r"tcpclient[\s\S]{0,500}?getstream[\s\S]{0,500}?(?:\biex\b|invoke-expression|\.read\(|streamwriter|\|\s*out-string)")),
    Rule("PS-SHELLCODE", "PowerShell shellcode injection pattern (VirtualAlloc + CreateThread)", S.HIGH, ("T1055", "T1059.001"),
         _p(r"virtualalloc[\s\S]{0,400}?(?:createthread|memmove|marshal\]::copy)|"
            r"createthread[\s\S]{0,400}?virtualalloc")),
    Rule("PS-OFFSEC", "Known offensive PowerShell tooling in command line", S.HIGH, ("T1059.001", "T1003"),
         _p(r"\b(?:invoke-(?:mimikatz|shellcode|reflectivepeinjection|kerberoast|dcsync|tokenmanipulation|psinject|"
            r"wmiexec|smbexec|inveigh|bloodhound)|sharphound|rubeus|powerview|powersploit|get-gpppassword|"
            r"invoke-powershelltcp|invoke-obfuscation)\b")),
    Rule("PS-HIDDEN-BYPASS-UW", "Hidden PowerShell with execution-policy bypass running a script from a user-writable folder",
         S.MEDIUM, ("T1059.001", "T1564.003"),
         _p(r"\b@PS@\"?(?=\s)(?=.*\s[-/]w(?:in\w*)?\s+h(?:idden)?\b)(?=.*\s[-/](?:ep|exec\w*)\s+bypass)(?=.*@UW@[^\n]*?\.ps1)"),
         supersedes=("AEG-CMD-PS-FILE-UW",)),
    Rule("PS-FILE-UW", "PowerShell script run from a user-writable folder", S.LOW, ("T1059.001",),
         _p(r"\b@PS@\"?(?=\s)(?=.*\s[-/](?:file|f)\s+[\"']?[^\n]*?@UW@[^\n]*?\.ps1\b)")),
    Rule("PS-DOWNGRADE", "PowerShell version 2 downgrade", S.LOW, ("T1059.001",),
         _p(r"\b@PS@\"?\s(?:.*\s)?[-/]v(?:ersion)?\s+2(?:\.0)?(?=\s|$)")),
    # ---------------------------------------------------------------- credential theft
    Rule("MIMIKATZ", "Mimikatz-style credential dumping command", S.CRITICAL, ("T1003.001",),
         _p(r"\bmimikatz\b|sekurlsa::|lsadump::|kerberos::(?:ptt|golden)|privilege::debug|token::elevate")),
    Rule("COMSVCS-DUMP", "LSASS memory dump via comsvcs.dll MiniDump", S.CRITICAL, ("T1003.001",),
         _p(r"comsvcs(?:\.dll)?[\s\"']*,[\s\"']*(?:#+\s*24|minidump)")),
    Rule("LSASS-DUMP", "LSASS memory dump via dump tool", S.HIGH, ("T1003.001",),
         _p(r"\b(?:procdump(?:64)?|sqldumper|dumpert|nanodump|pssdump)(?:\.exe)?\b[^\n]*\blsass|"
            r"minidumpwritedump[^\n]*lsass|lsass[^\n]*minidumpwritedump")),
    Rule("HIVE-SAVE", "Registry credential hive export (SAM/SECURITY/SYSTEM)", S.HIGH, ("T1003.002",),
         _p(r"\breg(?:\.exe)?\"?\s+save\s+\"?hk(?:lm|ey_local_machine)\\(?:sam|security|system)\b")),
    Rule("NTDS", "Active Directory database (NTDS.dit) extraction", S.HIGH, ("T1003.003",),
         _p(r"\bntds\.dit\b|\bntdsutil(?:\.exe)?\b[^\n]*(?:\bifm\b|create\s+full)")),
    Rule("WDIGEST", "WDigest plaintext credential caching enabled", S.HIGH, ("T1003.001",),
         _p(r"\breg(?:\.exe)?\s+add\b[^\n]*wdigest[^\n]*uselogoncredential[^\n]*/d\s+(?:1|0x1)\b")),
    # ---------------------------------------------------------------- LOLBins
    Rule("MSHTA-REMOTE", "mshta executing remote or inline script", S.HIGH, ("T1218.005",),
         _p(r"\bmshta(?:\.exe)?\"?\s+(?:[-/]\S+\s+)*[\"']?(?:https?:|ftps?:|javascript:|vbscript:|\\\\)")),
    Rule("RUNDLL32-SCRIPT", "rundll32 executing inline JavaScript/VBScript", S.HIGH, ("T1218.011",),
         _p(r"\brundll32(?:\.exe)?\"?\s+(?:[-/]\S+\s+)*[\"']?(?:javascript|vbscript):|mshtml\s*,\s*runhtmlapplication")),
    Rule("RUNDLL32-URL", "rundll32 url.dll launching a program or remote file", S.MEDIUM, ("T1218.011",),
         _p(r"url\.dll\s*,\s*(?:fileprotocolhandler|openurl\w?|ftpprotocolhandler)\s+[\"']?"
            r"(?:file:|\\\\|[^\s\"']*\.(?:exe|hta|vbs|vbe|js|jse|bat|cmd|scr|ps1|msi|dll|wsf)\b)")),
    Rule("RUNDLL32-SHELLEXEC", "rundll32 ShellExec_RunDLL launching an interpreter or remote file", S.MEDIUM, ("T1218.011",),
         _p(r"shell32(?:\.dll)?\s*,\s*shellexec_rundll\w*\s+[\"']?(?:[^|&\n]*?\b(?:cmd|powershell|pwsh|mshta|wscript|cscript|"
            r"rundll32|regsvr32|certutil|bitsadmin)(?:\.exe)?\b|https?://|\\\\)")),
    Rule("RUNDLL32-LOLEXPORT", "rundll32 proxy-execution export commonly abused by malware", S.MEDIUM, ("T1218.011",),
         _p(r"\brundll32(?:\.exe)?\"?\s+(?:[-/]\S+\s+)*[\"']?(?:pcwutl(?:\.dll)?\s*,\s*launchapplication|"
            r"desk\.cpl\s*,\s*installscreensaver|zipfldr(?:\.dll)?\s*,\s*routethecall|"
            r"syssetup(?:\.dll)?\s*,\s*setupinfobjectinstallaction|(?:ie)?advpack(?:\.dll)?\s*,\s*(?:launchinfsection\w*|registerocx)"
            r"(?=[^\n]*(?:@UW@|https?://)))")),
    Rule("RUNDLL32-NONDLL", "rundll32 loading a file that is not a DLL", S.HIGH, ("T1218.011", "T1036.008"),
         _p(r"\brundll32(?:\.exe)?\"?\s+(?:[-/]\S+\s+)*[\"']?[^\n,\"']*\.(?:png|jpe?g|gif|bmp|txt|dat|tmp|db|bin|ini|log|pdf|docx?|xlsx?|bak|mp3|csv)"
            r"[\"']?\s*,")),
    Rule("BARE-HOST", "Process-injection host launched without arguments (rundll32/regsvr32/svchost)", S.HIGH,
         ("T1055", "T1036.005"),
         _p(r"^\s*(?:\"[^\"]*(?:rundll32|regsvr32|svchost)(?:\.exe)?\"|\S*(?:rundll32|regsvr32|svchost)(?:\.exe)?)\s*$")),
    Rule("REGSVR32-SQUIBLEE", "regsvr32 loading a remote scriptlet (Squiblydoo)", S.HIGH, ("T1218.010",),
         _p(r"\bregsvr32(?:\.exe)?\"?(?=\s)(?=[^\n]*(?:https?://|ftps?://))|"
            r"\bregsvr32(?:\.exe)?\"?(?=\s)(?=[^\n]*\s[-/]i(?::|=|\s))(?=[^\n]*scrobj)")),
    Rule("REGSVR32-UW", "regsvr32 registering a DLL from a user-writable folder", S.MEDIUM, ("T1218.010",),
         _p(r"\bregsvr32(?:\.exe)?\"?(?=\s)(?=[^\n]*@UW@)")),
    Rule("CERTUTIL-URL", "certutil downloading a file", S.HIGH, ("T1105", "T1218"),
         _p(r"\bcertutil(?:\.exe)?\b(?=[^\n]*[-/](?:urlcache|verifyctl))(?=[^\n]*(?:https?://|ftps?://|\\\\))")),
    Rule("CERTUTIL-DECODE", "certutil decoding a file (payload staging)", S.MEDIUM, ("T1140",),
         _p(r"\bcertutil(?:\.exe)?\b[^\n]*?\s[-/](?:decode|decodehex)\b")),
    Rule("BITSADMIN-URL", "bitsadmin transferring a file from a URL", S.HIGH, ("T1197", "T1105"),
         _p(r"\bbitsadmin(?:\.exe)?\b(?=[^\n]*[/-](?:transfer|addfile)\b)(?=[^\n]*(?:https?://|ftps?://))"),
         supersedes=("AEG-CMD-BITSADMIN",)),
    Rule("BITSADMIN-NOTIFY", "bitsadmin job with a notify command (persistence/execution)", S.HIGH, ("T1197",),
         _p(r"\bbitsadmin(?:\.exe)?\b[^\n]*[/-]setnotifycmdline\b")),
    Rule("BITSADMIN", "bitsadmin /transfer", S.MEDIUM, ("T1197",),
         _p(r"\bbitsadmin(?:\.exe)?\b[^\n]*[/-]transfer\b")),
    Rule("WMIC-PROCCREATE-HIGH", "WMIC process creation of an interpreter, remote node or dropped file", S.HIGH,
         ("T1047",),
         _p(r"\bwmic(?:\.exe)?\b(?=[^\n]*\bprocess\s+call\s+create\b)(?=[^\n]*(?:[/-]node:|@LOL@|https?://|@UW@))"),
         supersedes=("AEG-CMD-WMIC-PROCCREATE",)),
    Rule("WMIC-PROCCREATE", "WMIC process call create", S.MEDIUM, ("T1047",),
         _p(r"\bwmic(?:\.exe)?\b[^\n]*?\bprocess\s+call\s+create\b")),
    Rule("WMIC-XSL", "WMIC loading a remote XSL stylesheet", S.HIGH, ("T1220",),
         _p(r"\bwmic(?:\.exe)?\b[^\n]*[/-]format:\s*[\"']?(?:https?://|\\\\|[^\s\"']+\.xsl)")),
    Rule("MSIEXEC-REMOTE-QUIET", "Silent msiexec install from a URL", S.HIGH, ("T1218.007",),
         _p(r"\bmsiexec(?:\.exe)?\"?(?=\s)(?=[^\n]*https?://)(?=[^\n]*\s[/-](?:q[nbrf]?\+?|quiet|passive)(?:\s|$))"),
         supersedes=("AEG-CMD-MSIEXEC-REMOTE",)),
    Rule("MSIEXEC-REMOTE", "msiexec installing a package from a URL", S.MEDIUM, ("T1218.007",),
         _p(r"\bmsiexec(?:\.exe)?\"?(?=\s)(?=[^\n]*\s[/-](?:i|package|a|y|z|jm?u?)(?:\s|$))(?=[^\n]*https?://)")),
    Rule("CMSTP", "cmstp executing an INF profile silently", S.HIGH, ("T1218.003",),
         _p(r"\bcmstp(?:\.exe)?\"?(?=\s)(?=[^\n]*\s[/-](?:s|au|ni)(?:\s|$))(?=[^\n]*\.inf)")),
    Rule("INSTALLUTIL", "InstallUtil used to run code (LogToConsole=false)", S.HIGH, ("T1218.004",),
         _p(r"\binstallutil(?:\.exe)?\b(?=[^\n]*[-/]logtoconsole\s*=\s*false)")),
    Rule("INSTALLUTIL-UW", "InstallUtil running an assembly from a user-writable folder", S.MEDIUM, ("T1218.004",),
         _p(r"\binstallutil(?:\.exe)?\b(?=[^\n]*[-/]u\b)(?=[^\n]*@UW@)")),
    Rule("REGASM-UW", "regasm/regsvcs loading an assembly from a user-writable folder", S.MEDIUM, ("T1218.009",),
         _p(r"\b(?:regasm|regsvcs)(?:\.exe)?\b(?=[^\n]*@UW@)")),
    Rule("MSBUILD-UW", "MSBuild project run from a user-writable folder with a non-project extension", S.MEDIUM,
         ("T1127.001",),
         _p(r"\bmsbuild(?:\.exe)?\b(?=[^\n]*@UW@)(?=[^\n]*\.(?:xml|tmp|txt|png|jpe?g|dat|xsl)\b)")),
    Rule("ODBCCONF-REGSVR", "odbcconf loading a DLL via REGSVR", S.HIGH, ("T1218.008",),
         _p(r"\bodbcconf(?:\.exe)?\b(?=[^\n]*[/-]a\s*\{?\s*regsvr)")),
    Rule("ODBCCONF-RSP", "odbcconf response file execution", S.MEDIUM, ("T1218.008",),
         _p(r"\bodbcconf(?:\.exe)?\b[^\n]*[/-]f\s+\S+\.rsp")),
    Rule("FORFILES", "forfiles proxy-executing an interpreter or LOLBin", S.MEDIUM, ("T1202",),
         _p(r"\bforfiles(?:\.exe)?\b[^\n]*?\s[/-]c\s+[\"']?(?:cmd(?:\.exe)?\s+/[ck]\s+)?"
            r"(?:powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|curl|wget|msiexec)\b")),
    Rule("CONHOST-HEADLESS", "conhost --headless launching an interpreter", S.MEDIUM, ("T1202",),
         _p(r"\bconhost(?:\.exe)?\"?\s+(?:0x\w+\s+)?--headless\s+[\"']?(?:cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|curl)")),
    Rule("CONTROL-CPL-UW", "control.exe loading a CPL/DLL from a user-writable folder", S.MEDIUM, ("T1218.002",),
         _p(r"\bcontrol\.exe\"?\s+[^\n]*@UW@[^\n]*\.(?:cpl|dll|dat|tmp)\b")),
    Rule("MAVINJECT", "mavinject DLL injection", S.HIGH, ("T1218.013", "T1055"),
         _p(r"\bmavinject(?:32)?(?:\.exe)?\s+\d+\s+/injectrunning")),
    Rule("DESKTOPIMG", "desktopimgdownldr used to download a file", S.MEDIUM, ("T1105",),
         _p(r"\bdesktopimgdownldr(?:\.exe)?\b[^\n]*lockscreenurl:\s*https?://")),
    Rule("CURL-WIN-DROP", "curl downloading an executable or script into a user-writable folder", S.MEDIUM, ("T1105",),
         _p(r"\bcurl(?:\.exe)?\b(?=[^\n]*https?://)[^\n]*?(?:\s-o|\s--output)\s+[\"']?[^\n]*?@UW@[^\s\"']*\.(?:exe|dll|ps1|bat|cmd|vbs|js|hta|scr|msi|jar)\b")),
    Rule("SCRIPTHOST-UW", "Windows Script Host / mshta running a script from a user-writable folder", S.MEDIUM,
         ("T1059.005", "T1218.005"),
         _p(r"\b(?:wscript|cscript|mshta)(?:\.exe)?\"?\s+(?:[-/]{1,2}\S+\s+)*[\"']?[^|&\n]*?@UW@[^|&\n]*?\.(?:vbs|vbe|js|jse|wsf|wsh|hta|sct)\b")),
    Rule("SCRIPTHOST-ENGINE", "Windows Script Host forced to run a disguised script via //E:", S.MEDIUM, ("T1059.005", "T1036.008"),
         _p(r"\b(?:wscript|cscript)(?:\.exe)?\"?\s[^\n]*//e:(?:vbscript|jscript)\s+[^\n]*\.(?:txt|tmp|dat|png|jpe?g|log|ini|bin|db|csv|pdf|docx?|bak)\b")),
    # ---------------------------------------------------------------- impact / defence evasion
    Rule("RECOVERY-DESTROY", "Backup/shadow-copy destruction (ransomware behaviour)", S.HIGH, ("T1490",),
         _p(r"\bvssadmin(?:\.exe)?\"?\s+(?:delete\s+shadows|resize\s+shadowstorage[^\n]*maxsize\s*=\s*(?:401mb|unbounded))|"
            r"\bwbadmin(?:\.exe)?\"?\s+delete\s+(?:catalog|systemstatebackup|backup)|"
            r"\bbcdedit(?:\.exe)?\b[^\n]*(?:recoveryenabled\s+(?:no|off|false)|bootstatuspolicy\s+ignoreallfailures)|"
            r"\bwmic(?:\.exe)?\b[^\n]*\bshadowcopy\b[^\n]*\bdelete\b|"
            r"win32_shadowcopy[\s\S]{0,200}?(?:\.delete\(|remove-wmiobject|remove-ciminstance|\bdelete\b)")),
    Rule("SAFEBOOT", "Boot configuration forced into safe mode", S.MEDIUM, ("T1562.009",),
         _p(r"\bbcdedit(?:\.exe)?\b[^\n]*\s/set\s+(?:\{\w+\}\s+)?safeboot\b")),
    Rule("EVENTLOG-CLEAR-CORE", "Windows Security/System event log cleared", S.HIGH, ("T1070.001",),
         _p(r"\bwevtutil(?:\.exe)?\"?\s+(?:cl|clear-log)\s+[\"']?(?:security|system|windows\s+powershell|microsoft-windows-powershell)|"
            r"\bfor\b[^\n]*\bwevtutil\b[^\n]*\b(?:cl|clear-log)\b"), supersedes=("AEG-CMD-EVENTLOG-CLEAR",)),
    Rule("EVENTLOG-CLEAR", "Windows event log cleared", S.MEDIUM, ("T1070.001",),
         _p(r"\bwevtutil(?:\.exe)?\"?\s+(?:cl|clear-log)\b|\b(?:clear|remove)-eventlog\b")),
    Rule("USN-DELETE", "NTFS change journal deleted", S.HIGH, ("T1070",),
         _p(r"\bfsutil(?:\.exe)?\"?\s+usn\s+deletejournal")),
    Rule("DEFENDER-TAMPER", "Windows Defender protection disabled or exclusions added", S.HIGH, ("T1562.001",),
         _p(r"\b(?:set|add)-mppreference\b[^\n]*(?:-disable(?:realtimemonitoring|behaviormonitoring|ioavprotection|scriptscanning|"
            r"blockatfirstseen|intrusionpreventionsystem|archivescanning|emailscanning|privacymode)\s+[$]?(?:true|1)\b|"
            r"-exclusion(?:path|extension|process)\s)|"
            r"\breg(?:\.exe)?\s+add\b[^\n]*(?:disableantispyware|disablerealtimemonitoring|disableantivirus|disablebehaviormonitoring|"
            r"disableioavprotection|disableonaccessprotection)[^\n]*/d\s+(?:1|0x1)\b|"
            r"\buninstall-windowsfeature\s+windows-defender|\bdism\b[^\n]*disable-feature[^\n]*windows-defender")),
    Rule("SECURITY-SERVICE-STOP", "Security service stopped or disabled from the command line", S.HIGH, ("T1562.001",),
         _p(r"\b(?:sc|net1?)(?:\.exe)?\"?\s+(?:stop|config|delete|pause)\s+(?:windefend|wdnissvc|sense|wdfilter|wdboot|"
            r"mpssvc|securityhealthservice|wscsvc|sedsvc)\b")),
    Rule("AV-KILL", "Antivirus/EDR process killed via taskkill", S.HIGH, ("T1562.001",),
         _p(r"\btaskkill(?:\.exe)?\b[^\n]*[/-]im\s+[\"']?(?:msmpeng|nissrv|mssense|msseces|msascui|msascuil|avp|avgui|avgsvc|"
            r"avastui|avastsvc|ashserv|ekrn|egui|mbam|mbamservice|mcshield|mcuicnt|bdagent|vsserv|savservice|sophosui|"
            r"sophosfilescanner|csfalconservice|cylancesvc|sentinelagent|sentinelstaticengine|wrsa|ccsvchst|nsmdtr|tmbmsrv|"
            r"tmccsf|pccntmon|a2service|hmpalert|ntrtscan)(?:\.exe)?")),
    Rule("FIREWALL-OFF", "Windows Firewall disabled from the command line", S.MEDIUM, ("T1562.004",),
         _p(r"\bnetsh(?:\.exe)?\b[^\n]*(?:advfirewall\s+set\s+\w+profile\s+state\s+off|firewall\s+set\s+opmode\s+(?:mode=)?disable)")),
    Rule("REG-RUN-HIGH", "reg.exe adding an autorun entry that launches an interpreter or user-writable file", S.HIGH,
         ("T1547.001",),
         _p(r"\breg(?:\.exe)?\"?\s+add\s+\"?hk(?:cu|lm|ey_current_user|ey_local_machine)\\software\\(?:wow6432node\\)?microsoft\\"
            r"windows(?:\s+nt)?\\currentversion\\(?:run|runonce|runservices|policies\\explorer\\run|winlogon)\b"
            r"(?=[^\n]*(?:@UW@|https?://|powershell|mshta|wscript|cscript|rundll32|regsvr32|cmd(?:\.exe)?\s+/c))"),
         supersedes=("AEG-CMD-REG-RUN",)),
    Rule("REG-RUN", "reg.exe adding an autorun/Winlogon registry value", S.MEDIUM, ("T1547.001",),
         _p(r"\breg(?:\.exe)?\"?\s+add\s+\"?hk(?:cu|lm|ey_current_user|ey_local_machine)\\software\\(?:wow6432node\\)?microsoft\\"
            r"windows(?:\s+nt)?\\currentversion\\(?:run|runonce|runservices|policies\\explorer\\run|winlogon)\b")),
    Rule("REG-IFEO", "Image File Execution Options debugger/monitor hijack via reg.exe", S.HIGH, ("T1546.012",),
         _p(r"\breg(?:\.exe)?\"?\s+add\s+[^\n]*(?:image\s+file\s+execution\s+options|silentprocessexit)[^\n]*\s/v\s+(?:debugger|globalflag|monitorprocess)")),
    Rule("REG-UAC-HIJACK", "UAC-bypass registry hijack (ms-settings/mscfile shell\\open\\command)", S.HIGH, ("T1548.002",),
         _p(r"\breg(?:\.exe)?\"?\s+add\s+\"?hk(?:cu|ey_current_user)\\software\\classes\\(?:ms-settings|mscfile|exefile|folder|ms-windows-store)\\shell\\open\\command")),
    Rule("REG-WEAKEN", "Security features weakened via reg.exe", S.MEDIUM, ("T1112", "T1548.002"),
         _p(r"\breg(?:\.exe)?\"?\s+add\b[^\n]*(?:(?:disabletaskmgr|disableregistrytools|disablecmd)[^\n]*/d\s+(?:1|0x1)\b|"
            r"(?:enablelua|consentpromptbehavioradmin)[^\n]*/d\s+(?:0|0x0)\b)")),
    Rule("RDP-ENABLE", "Remote Desktop enabled via reg.exe", S.MEDIUM, ("T1021.001",),
         _p(r"\breg(?:\.exe)?\"?\s+add\b[^\n]*fdenytsconnections[^\n]*/d\s+(?:0|0x0)\b")),
    # ---------------------------------------------------------------- persistence / lateral movement
    Rule("SCHTASKS-HIGH", "Scheduled task created to run a remote/obfuscated payload", S.HIGH, ("T1053.005",),
         _p(r"\bschtasks(?:\.exe)?\"?(?=\s)(?=[^\n]*[/-]create\b)(?=[^\n]*[/-]tr\s+[^\n]*(?:https?://|javascript:|"
            r"@PS@[^\n]*\s@ENC@\s+@B64@|mshta|regsvr32[^\n]*scrobj|rundll32[^\n]*javascript))"),
         supersedes=("AEG-CMD-SCHTASKS-UW",)),
    Rule("SCHTASKS-UW", "Scheduled task created to run a file from a user-writable folder", S.MEDIUM, ("T1053.005",),
         _p(r"\bschtasks(?:\.exe)?\"?(?=\s)(?=[^\n]*[/-]create\b)(?=[^\n]*[/-]tr\s+[^\n]*@UW@)")),
    Rule("SC-CREATE", "Service created/reconfigured to run an interpreter or user-writable file", S.MEDIUM, ("T1543.003",),
         _p(r"\bsc(?:\.exe)?\"?\s+(?:\\\\\S+\s+)?(?:create|config)\s+\S+\s+[^\n]*?binpath=\s*[\"']?[^\n]*?"
            r"(?:@UW@|cmd(?:\.exe)?\s+/[ck]|%comspec%|@PS@|mshta|wscript|cscript|rundll32)")),
    Rule("PIPE-IMPERSONATE", "Named-pipe impersonation one-liner (getsystem style)", S.HIGH, ("T1134.001",),
         _p(r"(?:\bcmd(?:\.exe)?|%comspec%)\s+/c\s+echo\s+\S+\s*>\s*\\\\\.\\pipe\\")),
    Rule("NET-USER-ADMIN", "User added to the local Administrators group", S.HIGH, ("T1098", "T1136.001"),
         _p(r"\bnet1?(?:\.exe)?\"?\s+localgroup\s+administrators?\s+\S+\s+/add\b")),
    Rule("NET-USER-ADD", "Local user account created from the command line", S.MEDIUM, ("T1136.001",),
         _p(r"\bnet1?(?:\.exe)?\"?\s+user\s+(?:(?!/add)\S+\s+){1,2}/add\b")),
    Rule("NET-USER-ENABLE", "Built-in Administrator/Guest account enabled", S.MEDIUM, ("T1078.001",),
         _p(r"\bnet1?(?:\.exe)?\"?\s+user\s+(?:administrator|guest)\s+/active:yes")),
    # ---------------------------------------------------------------- crypto-mining
    Rule("MINER", "Cryptocurrency miner command line", S.HIGH, ("T1496",),
         _p(r"stratum(?:\+(?:tcp|ssl|tls))?://\S+|--donate-level\b|\b(?:xmrig|cpuminer|minerd|nbminer|lolminer|phoenixminer)\b(?=[^\n]*(?:-o\s|--url|--pool|stratum|-a\s|--algo))")),
    # ---------------------------------------------------------------- Linux / macOS
    Rule("LINUX-REVSHELL", "Reverse shell via /dev/tcp or equivalent", S.CRITICAL, ("T1059.004", "T1095"),
         _p(r">&\s*/dev/(?:tcp|udp)/[^\s/]+/\d+|\bexec\s+\d+\s*<>\s*/dev/tcp/[^\s/]+/\d+[^\n]*\bsh\s+-i|"
            r"/bin/(?:ba)?sh\s+-i\s+<&\d|\bmkfifo\s+\S+[^\n]*?\b(?:nc|ncat|netcat|telnet)\b")),
    Rule("LINUX-NC-EXEC", "netcat/ncat with command execution (-e/-c/--exec)", S.HIGH, ("T1059.004", "T1095"),
         _p(r"\b(?:nc|ncat|netcat)(?:\.\w+)?\s+(?:[^\n]*?\s)?-[a-z]*e\s+/?\S*sh\b|"
            r"\b(?:nc|ncat|netcat)(?:\.\w+)?\b[^\n]*\s--(?:sh-)?exec\s+\S*sh\b|"
            r"\b(?:nc|ncat|netcat)(?:\.\w+)?\b[^\n]*\s-c\s+[\"']?(?:/bin/)?(?:ba)?sh\b")),
    Rule("LINUX-SCRIPT-REVSHELL", "Scripting-language reverse shell one-liner", S.HIGH, ("T1059.006", "T1095"),
         _p(r"\bpython[\d.]*\s+[^\n]*-c\s[^\n]*(?:\bsocket\b[^\n]*\.connect\([^\n]*(?:dup2|pty\.spawn|subprocess|/bin/(?:ba)?sh)|"
            r"(?:dup2|pty\.spawn|subprocess)[^\n]*\bsocket\b[^\n]*connect)|"
            r"\bperl\s+[^\n]*-e\s+[^\n]*\bsocket\b[^\n]*\b(?:exec|open\s*\(\s*STDIN)|"
            r"\bruby\s+-rsocket\s+-e|"
            r"\bphp\s+-r\s+[^\n]*fsockopen[^\n]*(?:exec|passthru|system|/bin/(?:ba)?sh)|"
            r"\bsocat\b[^\n]*(?:tcp|tcp4|openssl)[:\-]\S+[^\n]*\bexec:[^\n]*sh")),
    Rule("LINUX-B64-SHELL", "Base64-decoded payload piped into a shell", S.HIGH, ("T1027", "T1059.004"),
         _p(r"\bbase64\s+(?:-d|-D|--decode)\b[^\n]*\|\s*(?:sudo\s+)?@SHELL@\b|"
            r"\beval\s*[\"']?\$\(\s*(?:echo|printf)[^\n]*base64\s+(?:-d|-D|--decode)")),
    Rule("LINUX-CURL-PIPE-SUSP", "Download piped into a shell from a suspicious host", S.HIGH, ("T1105", "T1059.004"),
         _p(r"\b(?:curl|wget)\b(?=[^\n]*@SUSP@)[^\n|]*\|\s*(?:sudo\s+(?:-\w+\s+)*)?@SHELL@\b"),
         supersedes=("AEG-CMD-LINUX-CURL-PIPE",)),
    Rule("LINUX-CURL-PIPE", "Download piped directly into a shell", S.MEDIUM, ("T1105", "T1059.004"),
         _p(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+(?:-\w+\s+)*)?@SHELL@\b|"
            r"\b(?:ba|z)?sh\s+<\(\s*(?:curl|wget)\b|-c\s+[\"']?\$\(\s*(?:curl|wget)\b")),
    Rule("LINUX-DROP-EXEC", "Payload downloaded into a temp directory and executed", S.HIGH, ("T1105", "T1059.004"),
         _p(r"\b(?:curl|wget)\b[^\n;&|]*?(?:\s-o|\s-O|--output|--output-document)[= ]\s*(?:/tmp|/var/tmp|/dev/shm)/\S+[^\n]*?"
            r"\bchmod\s+(?:[ugoa]*\+[rwx]*x|[0-7]{3,4})|"
            r"\bcd\s+(?:/tmp|/var/tmp|/dev/shm)\s*;[^\n]*?\b(?:wget|curl)\b[^\n]*?(?:chmod\s+\S+|\./\S+)")),
    Rule("LINUX-CRON-INJECT", "Cron entry injected from a download or encoded payload", S.HIGH, ("T1053.003",),
         _p(r"\b(?:curl|wget)\b[^\n]*\|\s*crontab\b|"
            r"\bcrontab\s+-l\s*;\s*echo\s+[^\n]*(?:curl|wget|base64|/tmp/|/dev/shm|\|\s*(?:ba)?sh)[^\n]*\|\s*crontab\s+-")),
    Rule("LINUX-LDPRELOAD", "LD_PRELOAD / ld.so.preload pointing at a temp-directory library", S.HIGH, ("T1574.006",),
         _p(r"\bld_preload\s*=\s*\S*(?:/tmp/|/dev/shm/|/var/tmp/)\S+|"
            r"echo\s+\S*(?:/tmp/|/dev/shm/|/var/tmp/)\S+\.so\s*>>?\s*/etc/ld\.so\.preload")),
]

_RULE_BY_ID: Dict[str, Rule] = {r.rule_id: r for r in RULES}


def _normalise(cmd: str) -> str:
    """Undo trivial cmd.exe / PowerShell obfuscation (^ and ` escapes) and bound length."""
    s = cmd[:MAX_ANALYSE_LEN]
    if "^" in s:
        s = re.sub(r"\^(?=[A-Za-z0-9])", "", s)
    if "`" in s:
        s = re.sub(r"`(?=[A-Za-z])", "", s)
    return s


def analyse_command_line(cmd: str) -> List[Hit]:
    """Return (rule_id, title, severity, mitre, matched) for every suspicious
    pattern in *cmd*, most severe first. Benign command lines return []."""
    if not cmd or len(cmd) < 4:
        return []
    s = _normalise(cmd)
    matched: Dict[str, Tuple[Rule, str]] = {}
    for rule in RULES:
        m = rule.pattern.search(s)
        if not m:
            continue
        if rule.guard and not rule.guard(s):
            continue
        snippet = s[m.start(): m.start() + 200].strip()
        matched[rule.rule_id] = (rule, snippet)
    for rid, (rule, _) in list(matched.items()):
        for sup in rule.supersedes:
            matched.pop(sup, None)
    hits: List[Hit] = [(r.rule_id, r.title, r.severity, list(r.mitre), snip) for r, snip in matched.values()]
    hits.sort(key=lambda h: (-int(h[2]), h[0]))
    return hits


def max_severity(hits: List[Hit]) -> Severity:
    return max((h[2] for h in hits), default=Severity.INFO)
