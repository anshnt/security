"""Recent activity traces: what was run on this PC and which sites it contacted.

Many 2025-2026 infections start with the user being tricked into running a command: a fake CAPTCHA / "verify you are
human" page (ClickFix) puts a PowerShell or mshta command on the clipboard and tells the user to press Win+R, Ctrl+V and
Enter (the macOS variants say "paste into Terminal"). Windows and the shells keep a record of what was run, and the system
keeps a record of which sites were contacted. This scanner reads those records:

* **Run dialog history** (Windows) - the commands typed into Win+R (``RunMRU``, most recent first). A command that downloads
  or hides code (PowerShell with an encoded / hidden / download-and-run command, mshta, curl or certutil through cmd,
  rundll32 / regsvr32 / msiexec on a web address, ``conhost --headless``, ``finger user@host``) is HIGH; one that also
  carries the harmless sentence the fake-CAPTCHA pages append after a ``#`` ("I am not a robot", "reCAPTCHA Verification ID")
  is CRITICAL; any other command the shared command-line analysers rate MEDIUM or more is MEDIUM. Ordinary commands (notepad,
  cmd, a URL, a folder, a network share) are not reported. The entry is never offered for deletion as a fix: clearing the
  record does not undo what ran.
* **PowerShell history** (PSReadLine; also pwsh on Linux and macOS) - the last 5,000 lines of every history file are searched
  for download-and-run cradles, encoded commands, AMSI / Defender tampering, credential-dumping one-liners and the same
  ClickFix patterns. One finding per file with a few masked example lines. Installers from a short list of well-known hosts
  (Chocolatey, Scoop, uv, rustup ...) are ignored.
* **Unix shell history** (bash, zsh, fish on Linux and macOS) - only strong patterns, because developers run ``curl | sh``
  all the time: a download piped into a shell from a raw IP address, a known-malicious domain or a file-sharing / paste /
  tunnel service, ``base64 -d | sh``, fake password prompts (``osascript`` ``display dialog`` with ``hidden answer``),
  quarantine stripping followed by running a file from /tmp or Downloads, and drop-and-run from /tmp. One finding per file.
* **DNS cache** (Windows) - every cached name and address is checked against the malicious-domain and malicious-IP feeds that
  ``aegis update`` downloads. Without a feed the check says so instead of reporting a clean result.
* **Browser history** (Chrome, Edge, Brave, Vivaldi, Opera, Chromium, Firefox ...) - the last 30 days are checked against the
  same feeds, from a private copy of the history database (the original is locked while the browser runs). Findings carry
  the domain, a visit count and at most three example addresses without query strings, never the browsing history itself.

These files are private. Nothing here prints, stores or reports a whole history: findings carry only the matching entries,
capped, with passwords, tokens and encoded payloads masked. Every decision is a pure function (classifiers, parsers, path
discovery with injectable roots) unit-tested on any OS; each check emits its own CheckResult and one failing check never
stops the others.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import logging
import os
import re
import shutil
import sqlite3
import tempfile
import time
import urllib.parse
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple

from aegis.core import cmdline as cl
from aegis.core import fileanalysis as fa
from aegis.core import platform as plat
from aegis.core.alerts import redact
from aegis.core.models import Category, CheckResult, CheckStatus, Finding, Severity
from aegis.core.platform import IS_WINDOWS, OS_NAME, as_list, powershell_json, reg_values, user_home
from aegis.scanners.apptamper import mask_secrets
from aegis.scanners.base import Emitted, ScanContext, Scanner, register
from aegis.scanners.browser import (chromium_browser_roots, chromium_profile_label, chromium_profiles,
                                    firefox_browser_roots, firefox_profiles)
from aegis.scanners.privacy import filetime_to_datetime

log = logging.getLogger("aegis.traces")

MAX_HISTORY_LINES = 5000  # only the most recent lines of a history file are read
MAX_TAIL_BYTES = 4 * 1024 * 1024  # ... and never more than this much of its end
MAX_HISTORY_FILE = 64 * 1024 * 1024  # a larger file is not a command history; it is skipped unread
MAX_HISTORY_FILES = 12
MAX_EXAMPLES = 10  # masked example lines per history finding
COMMAND_CHARS = 400  # a command shown in a finding is cut to this length (after masking)
MASK_INPUT_CHARS = 20_000  # a longer command is cut before masking (a finding never shows more than the first few hundred)
BROWSER_DAYS = 30
BROWSER_ROW_LIMIT = 50_000  # rows read per browser profile, newest first
BROWSER_BUDGET_S = 60.0
MAX_BROWSER_EXAMPLES = 3
MAX_SITE_FINDINGS = 100
MAX_DNS_FINDINGS = 100
UPDATE_HINT = "Run `aegis update` to download the malicious-domain and malicious-IP feeds, then scan again."

RUNMRU_KEY = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"

RUN_TITLE = "Run dialog history has no pasted malicious commands"
PS_TITLE = "PowerShell history has no download-and-run or tampering commands"
SHELL_TITLE = "Shell history has no download-and-run or fake-prompt commands"
DNS_TITLE = "DNS cache has no known-malicious domains"
BROWSER_TITLE = "Browser history has no known-malicious sites"

# =========================================================================== shared helpers


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _fmt(when: Optional[dt.datetime]) -> str:
    return when.strftime("%Y-%m-%d %H:%M UTC") if when else "an unknown time"


def _iso(when: Optional[dt.datetime]) -> Optional[str]:
    return when.isoformat(timespec="seconds") if when else None


def _plural(n: int, one: str, many: str) -> str:
    return one if n == 1 else many


def _status(flagged: int) -> str:
    return CheckStatus.FAIL if flagged else CheckStatus.PASS


def _short_hash(text: str) -> str:
    return hashlib.sha1(text.strip().encode("utf-8", "replace")).hexdigest()[:8]


_EPOCH_1601 = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
_EPOCH_1970 = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
_SANE_FROM = dt.datetime(2000, 1, 1, tzinfo=dt.timezone.utc)
_SANE_TO = dt.datetime(2100, 1, 1, tzinfo=dt.timezone.utc)


def _micros_to_datetime(epoch: dt.datetime, value: Any) -> Optional[dt.datetime]:
    try:
        if value is None or isinstance(value, bool):
            return None
        when = epoch + dt.timedelta(microseconds=int(value))
    except (TypeError, ValueError, OverflowError):
        return None
    return when if _SANE_FROM <= when < _SANE_TO else None


def webkit_to_datetime(value: Any) -> Optional[dt.datetime]:
    """Chromium time (microseconds since 1601-01-01 UTC) -> aware UTC datetime; 0, missing and absurd values give None."""
    return _micros_to_datetime(_EPOCH_1601, value)


def unix_micros_to_datetime(value: Any) -> Optional[dt.datetime]:
    """Firefox time (microseconds since 1970-01-01 UTC) -> aware UTC datetime; 0, missing and absurd values give None."""
    return _micros_to_datetime(_EPOCH_1970, value)


def unix_to_datetime(value: Any) -> Optional[dt.datetime]:
    """Unix seconds (bash / zsh / fish history time stamps) -> aware UTC datetime; absurd values give None."""
    try:
        if value is None or isinstance(value, bool):
            return None
        when = _EPOCH_1970 + dt.timedelta(seconds=int(value))
    except (TypeError, ValueError, OverflowError):
        return None
    return when if _SANE_FROM <= when < _SANE_TO else None


def datetime_to_webkit(when: dt.datetime) -> int:
    return int((when - _EPOCH_1601).total_seconds()) * 1_000_000


def datetime_to_unix_micros(when: dt.datetime) -> int:
    return int((when - _EPOCH_1970).total_seconds()) * 1_000_000


# =========================================================================== masking

# every spelling PowerShell accepts for -EncodedCommand: -e, -en ... -encodedcommand and -ec
_ENC_SWITCH = r"[-/](?:" + "|".join(["ec"] + ["encodedcommand"[:i] for i in range(1, 15)]) + r")"
_B64_ENC = re.compile(r"(?i)(\s" + _ENC_SWITCH + r"\s+[\"']?)[A-Za-z0-9+/=]{16,}")
_B64_RUN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")
_CMD_MASKS: Tuple[Tuple["re.Pattern[str]", Any], ...] = (
    (re.compile(r"(?i)(authorization\s*[:=]\s*(?:bearer|basic|token|digest)\s+)[^\s'\"]+"), r"\1***"),
    (re.compile(r"(?i)(\s--?(?:password|passwd|pwd|pass|passphrase|token|secret|api-?key|auth|access-?key|client-?secret)"
                r"(?:\s+|=|:))(?!-)[^\s'\"]+"), r"\1***"),
    (re.compile(r"(?i)\b(password|passwd|pwd|passphrase|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)"
                r"(\s*[=:]\s*)(['\"]?)[^\s'\";&|]+"), r"\1\2\3***"),
    (re.compile(r"(?i)([?&](?:token|access_token|auth|key|api_?key|sig|signature|password|secret|code)=)[^&\s'\"]+"),
     r"\1***"),
)


def _mask_encoded_value(m: "re.Match[str]") -> str:
    return m.group(1) + f"<base64 {len(m.group(0)) - len(m.group(1))} chars>"


def _mask_base64_run(m: "re.Match[str]") -> str:
    run = m.group(0)
    # a long path or identifier is not a payload: payloads mix cases and hardly ever contain several slashes
    if run.count("/") > 2 or run.islower() or run.isupper():
        return run
    return f"<base64 {len(run)} chars>"


def mask_command(text: str, limit: int = COMMAND_CHARS) -> str:
    """One-line form of a command that is safe to show: passwords, tokens, credentials in URLs, webhook and bot URLs and
    encoded payloads are masked FIRST, then the text is cut to ``limit`` characters (so a secret is never half-cut)."""
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", str(text or "")[:MASK_INPUT_CHARS])  # only the start is ever shown
    text = re.sub(r"\s+", " ", text).strip()
    text = _B64_ENC.sub(_mask_encoded_value, text)
    for rx, repl in _CMD_MASKS:
        text = rx.sub(repl, text)
    text = _B64_RUN.sub(_mask_base64_run, text)
    text = redact(mask_secrets(text))
    return text if len(text) <= limit else text[:limit - 3] + "..."


def strip_url(url: str, max_path: int = 120) -> str:
    """``scheme://host[:port]/path`` of a URL: no credentials, query string or fragment (browser history is private)."""
    try:
        parts = urllib.parse.urlsplit(url.strip())
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return ""
    if not host or parts.scheme.lower() not in ("http", "https", "ftp"):
        return ""
    if ":" in host:
        host = f"[{host}]"
    path = parts.path[:max_path] + ("..." if len(parts.path) > max_path else "")
    return f"{parts.scheme.lower()}://{host}{':' + str(port) if port else ''}{path}"


# =========================================================================== well-known installer hosts

# Developers legitimately run ``iwr ... | iex`` / ``irm ... | iex`` for these installers; a download-and-run command whose
# every address is on this list is not reported. Entries without a path name a host whose address (and sub-domains)
# the project controls; entries with a path name a folder on a host anyone can publish to (GitHub raw content), so only
# that owner / repository counts.
TRUSTED_INSTALLER_HOSTS: Tuple[str, ...] = (
    "community.chocolatey.org", "chocolatey.org",  # Chocolatey install.ps1
    "get.scoop.sh",  # Scoop
    "astral.sh",  # uv / ruff installers
    "aka.ms",  # Microsoft short links (install-powershell.ps1, winget ...)
    "dot.net",  # dotnet-install.ps1
    "deno.land", "bun.sh",  # Deno, Bun
    "rustup.rs", "sh.rustup.rs",  # rustup
    "get.docker.com",  # Docker convenience script
    "install.python-poetry.org",  # Poetry
)
TRUSTED_INSTALLER_PATHS: Tuple[str, ...] = (
    "raw.githubusercontent.com/powershell/powershell/",  # install-powershell.ps1
    "raw.githubusercontent.com/scoopinstaller/",  # Scoop installer
    "raw.githubusercontent.com/homebrew/install/",  # Homebrew
    "raw.githubusercontent.com/ohmyzsh/ohmyzsh/",  # Oh My Zsh
    "raw.githubusercontent.com/nvm-sh/nvm/",  # nvm
)

_LABEL = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
# the PowerShell commands and .NET calls that fetch something from the web
_FETCH_CALL = re.compile(r"(?i)(?<![\w.-])(?:iwr|irm|wget|curl|invoke-webrequest|invoke-restmethod|start-bitstransfer)"
                         r"(?:\.exe)?(?![\w-])|\bdownload(?:string|file|data)\b")
_ADDRESS_ARG = re.compile(r"(?i)^(?:(?:https?|ftp)://\S+|(?P<host>" + _LABEL + r"(?:\." + _LABEL + r")+)(?P<path>/\S*)?)$")


def is_trusted_installer(host: str, path: str = "") -> bool:
    """True for a host (or sub-domain of one) on the installer allow-list, or a folder on the path-qualified list."""
    host = (host or "").lower().strip(".")
    if not host:
        return False
    if any(host == h or host.endswith("." + h) for h in TRUSTED_INSTALLER_HOSTS):
        return True
    full = host + "/" + (path or "").lstrip("/").lower()
    return any(full.startswith(p) for p in TRUSTED_INSTALLER_PATHS)


def _address_argument(rest: str) -> Optional[Tuple[str, str]]:
    """``(host, path)`` of the address a fetch command is given: the first argument after its switches, written as a URL
    or as a scheme-less address (``get.scoop.sh``). None for a variable, an expression or anything else."""
    for token in re.split(r"[\s'\"`(),;|]+", rest[:400]):
        if not token or token.startswith("-"):
            continue  # a switch (-UseBasicParsing, -Uri ...)
        m = _ADDRESS_ARG.match(token)
        if not m:
            return None
        if m.group("host"):
            return m.group("host").lower(), m.group("path") or ""
        try:
            parts = urllib.parse.urlsplit(token)
            return (parts.hostname or "").lower(), parts.path
        except ValueError:
            return None
    return None


def fetch_addresses(text: str) -> List[Optional[Tuple[str, str]]]:
    """One entry per web-fetching call in a command (``iwr``, ``irm``, ``Invoke-WebRequest``, ``DownloadString`` ...): the
    ``(host, path)`` it is given, or None when its argument is not a literal address (``irm $url``)."""
    return [_address_argument(text[m.end():]) for m in _FETCH_CALL.finditer(text)]


def downloads_only_from_trusted(text: str) -> bool:
    """True when the command fetches from the web and EVERY fetching call is given a literal address on the installer
    allow-list. A call that fetches from a variable (``irm $url``) vouches for nothing, and a trusted address elsewhere in
    the line (a comment, a decoy) does not help it."""
    calls = fetch_addresses(text)
    return bool(calls) and all(c is not None and is_trusted_installer(*c) for c in calls)


# =========================================================================== command classification (Windows / PowerShell)


@dataclass(frozen=True)
class Signal:
    """One thing a command line does that makes it suspicious."""

    key: str
    label: str
    severity: Severity
    mitre: Tuple[str, ...] = ()
    clickfix: bool = False  # one of the ClickFix patterns of this module (the others come from the shared analysers)


@dataclass
class CommandVerdict:
    severity: Severity
    signals: List[Signal] = field(default_factory=list)
    lure: str = ""  # the comment text that looks like a fake-CAPTCHA lure ('' if none)

    @property
    def keys(self) -> List[str]:
        return [s.key for s in self.signals]

    @property
    def reasons(self) -> List[str]:
        out = [s.label for s in self.signals]
        if self.lure:
            out.insert(0, "a # comment with the wording fake CAPTCHA pages add")
        return out

    @property
    def mitre(self) -> List[str]:
        ids: List[str] = []
        if self.lure or any(s.clickfix for s in self.signals):
            ids.append("T1204.004")
        for s in self.signals:
            ids.extend(s.mitre)
        return list(dict.fromkeys(ids))


_PS = r"\b(?:powershell|pwsh)(?:\.exe)?\b"
_HIDDEN_SWITCH = r"[-/]w(?:in\w*)?\s+[\"']?h(?:idden)?\b"
_PS_WEB = (r"\bi(?:wr|rm)\b|\binvoke-(?:webrequest|restmethod)\b|\bdownload(?:string|file|data)\b|\bnet\.webclient\b|"
           r"\bstart-bitstransfer\b|\biex\b|\binvoke-expression\b")
_WEB_ADDRESS = r"(?:https?://|ftps?://)"
_UNC_SHARE = r"\\\\[\w.$-]+\\[\w$]"
_CMD_START = r"(?:^|[\s\"'&|;(])"

# (key, label, severity, severity in a history file, MITRE ids, pattern). Several patterns can share a key. A history severity
# of INFO means "not reported from a history file": a lone ``powershell -c "irm https://api..."``, ``curl url -o file`` or
# ``powershell -w hidden -File x.ps1`` is routine there (download-and-run is caught by the shared cradle rules, hidden plus
# bypass switches by the stealth rule), while in the Run dialog none of them is.
_CLICKFIX: Tuple[Tuple[str, str, Severity, Optional[Severity], Tuple[str, ...], "re.Pattern[str]"], ...] = tuple(
    (key, label, sev, hist, mitre, re.compile(pattern, re.I)) for key, label, sev, hist, mitre, pattern in (
        ("encoded", "PowerShell started with a Base64-encoded command", Severity.HIGH, None, ("T1059.001", "T1027.010"),
         _PS + r"[^\n]*?\s" + _ENC_SWITCH + r"\s+[\"']?[A-Za-z0-9+/=]{20,}"),
        ("hidden-stealth", "PowerShell started with a hidden window and no-profile / bypass / inline-command switches",
         Severity.HIGH, None, ("T1059.001", "T1564.003"),
         _PS + r"(?=[^\n]*\s" + _HIDDEN_SWITCH + r")(?=[^\n]*(?:\s[-/]nop(?:r\w*)?\b|"
         r"\s[-/](?:ep|exec\w*)\s+(?:bypass|unrestricted)\b|\s[-/]noni(?:n\w*)?\b|\s[-/]c(?:o\w*)?\s+\S|"
         r"\s" + _ENC_SWITCH + r"\s))"),
        ("hidden", "PowerShell started with a hidden window", Severity.MEDIUM, Severity.INFO, ("T1059.001", "T1564.003"),
         _PS + r"(?=[^\n]*\s" + _HIDDEN_SWITCH + r")"),
        ("ps-web", "PowerShell downloading or running code from the web", Severity.HIGH, Severity.INFO,
         ("T1059.001", "T1105"), _PS + r"[^\n]*?(?:" + _PS_WEB + r")"),
        # ... in a history file only together with what a pasted ClickFix command adds: no-profile / bypass switches or a
        # second step that starts what was fetched
        ("ps-web", "PowerShell downloading or running code from the web", Severity.HIGH, None, ("T1059.001", "T1105"),
         _PS + r"(?=[^\n]*(?:" + _PS_WEB + r"))(?=[^\n]*(?:\s[-/]nop(?:r\w*)?\b|"
         r"\s[-/](?:ep|exec\w*)\s+(?:bypass|unrestricted)\b|\s[-/]noni(?:n\w*)?\b|\bstart-process\b|\binvoke-item\b|"
         r"&\s*[\$'\"(]|\|\s*(?:cmd|powershell|pwsh)\b|\bcmd(?:\.exe)?\s+/c\b))"),
        ("mshta-url", "mshta opening a remote address or inline script", Severity.HIGH, None, ("T1218.005",),
         r"\bmshta(?:\.exe)?\b[^\n]*?(?:" + _WEB_ADDRESS + r"|javascript:|vbscript:|" + _UNC_SHARE + r")"),
        ("download-tool", "file download through cmd with curl, wget, certutil or bitsadmin", Severity.HIGH, None,
         ("T1105", "T1059.003"),
         r"\bcmd(?:\.exe)?\b[^\n]*?\s/[ck]\b[^\n]*?\b(?:curl|wget|certutil|bitsadmin)(?:\.exe)?\b[^\n]*?" + _WEB_ADDRESS),
        ("download-tool", "file download through curl or wget written to disk or piped on", Severity.HIGH, Severity.INFO,
         ("T1105",),
         _CMD_START + r"(?:curl|wget)(?:\.exe)?\s(?=[^\n]*" + _WEB_ADDRESS + r")(?=[^\n]*(?:\s-[a-z]*o\b|\s--output\b|"
         r"\|\s*\S|&&|\s&\s|;))"),
        ("rundll32-remote", "rundll32 loading something from a web address or network share", Severity.HIGH, None,
         ("T1218.011",), r"\brundll32(?:\.exe)?\b[^\n]*?(?:" + _WEB_ADDRESS + r"|" + _UNC_SHARE + r")"),
        ("regsvr32-remote", "regsvr32 loading something from a web address or network share", Severity.HIGH, None,
         ("T1218.010",), r"\bregsvr32(?:\.exe)?\b[^\n]*?(?:" + _WEB_ADDRESS + r"|" + _UNC_SHARE + r")"),
        ("conhost-headless", "conhost --headless hiding a command window", Severity.HIGH, None, ("T1202",),
         r"\bconhost(?:\.exe)?\b[^\n]*?--headless\b"),
        ("msiexec-remote", "msiexec installing a package from the web", Severity.HIGH, None, ("T1218.007",),
         r"\bmsiexec(?:\.exe)?\b[^\n]*?\s[/-](?:i|package|a|y|z|jm?u?)\s*[\"']?(?:" + _WEB_ADDRESS + r"|" + _UNC_SHARE + r")"),
        ("finger", "finger fetching text from a remote host (a 2025 ClickFix delivery trick)", Severity.HIGH, None,
         ("T1105",), _CMD_START + r"finger(?:\.exe)?\s+[\"']?[\w.$-]*@[\w.-]+"),
    ))

# the shared analysers' rules that mean "this command downloads or starts code": kept at their own severity in the Run dialog
# (any other hit there is MEDIUM); PowerShell history additionally keeps the rules for tampering and credential theft
_RUN_EXEC = frozenset("AEG-CMD-" + r for r in (
    "PS-ENC-STEALTH", "PS-ENC", "PS-CRADLE", "PS-INMEM", "PS-REVSHELL", "PS-SHELLCODE", "MSHTA-REMOTE", "RUNDLL32-SCRIPT",
    "REGSVR32-SQUIBLEE", "CERTUTIL-URL", "BITSADMIN-URL", "MSIEXEC-REMOTE-QUIET", "CURL-WIN-DROP"))
_HISTORY_RULES = _RUN_EXEC | frozenset("AEG-CMD-" + r for r in (
    "PS-AMSI", "PS-OFFSEC", "MIMIKATZ", "COMSVCS-DUMP", "LSASS-DUMP", "HIVE-SAVE", "NTDS", "WDIGEST", "DEFENDER-TAMPER"))
_RULE_KEY = {
    "AEG-CMD-PS-CRADLE": "cradle", "AEG-H-SCR-CRADLE": "cradle", "AEG-H-SCR-CRADLE2": "cradle",
    "AEG-CMD-PS-ENC": "encoded", "AEG-CMD-PS-ENC-STEALTH": "encoded",
    "AEG-CMD-MSHTA-REMOTE": "mshta-url", "AEG-CMD-REGSVR32-SQUIBLEE": "regsvr32-remote",
    "AEG-CMD-MSIEXEC-REMOTE-QUIET": "msiexec-remote", "AEG-CMD-CONHOST-HEADLESS": "conhost-headless",
    "AEG-CMD-PS-DOWNLOAD": "ps-web", "AEG-CMD-PS-OFFSEC": "offsec",
    "AEG-CMD-CERTUTIL-URL": "download-tool", "AEG-CMD-BITSADMIN-URL": "download-tool", "AEG-CMD-CURL-WIN-DROP": "download-tool",
    "AEG-CMD-PS-AMSI": "amsi", "AEG-H-SCR-AMSI": "amsi",
    "AEG-CMD-DEFENDER-TAMPER": "defender", "AEG-H-SCR-DEFENDER": "defender", "AEG-H-SCR-DEFENDER-EXCL": "defender",
    "AEG-CMD-MIMIKATZ": "credentials", "AEG-CMD-COMSVCS-DUMP": "credentials", "AEG-CMD-LSASS-DUMP": "credentials",
    "AEG-CMD-HIVE-SAVE": "credentials", "AEG-CMD-NTDS": "credentials", "AEG-CMD-WDIGEST": "credentials",
    "AEG-H-SCR-CREDS": "credentials",
}
# content_indicators() scores a cradle MEDIUM, the command-line analyser HIGH; both mean the same thing here
_INDICATOR_SEVERITY = {"AEG-H-SCR-CRADLE": Severity.HIGH, "AEG-H-SCR-CRADLE2": Severity.HIGH}
_HISTORY_INDICATORS = frozenset(_INDICATOR_SEVERITY) | frozenset(
    {"AEG-H-SCR-AMSI", "AEG-H-SCR-DEFENDER", "AEG-H-SCR-DEFENDER-EXCL", "AEG-H-SCR-CREDS"})
# the command-line analyser flags every Defender exclusion; routine ones (a build folder) are not tampering, so only the
# "disable" forms of its rule count here and exclusions are judged by the content analyser, which knows broad from narrow
_DEFENDER_DISABLE = re.compile(r"(?i)\b(?:set|add)-mppreference\b[^\n]*-disable|\breg(?:\.exe)?\s+add\b|"
                               r"\buninstall-windowsfeature\b|\bdism\b")

_COMMENT_START = re.compile(r"(?i)(?:^|[\s&;|)\"'])(?:#|rem(?=\s))")
_LURE_WORDS = re.compile(r"(?i)\bnot\s+a\s+(?:robot|bot)\b|\b(?:i\s+am|i'm|you\s+are|you're)\s+human\b|"
                         r"\b(?:human|bot)\s+(?:verif|check)|verif(?:y|ication|ied|ying)|\bre?captcha\b|\bcloudflare\b|"
                         r"\bray\s*id\b|\bturnstile\b")


def _clean(text: str) -> str:
    """The command as the analysers should see it: whitespace runs collapsed (so padding cannot push a payload past the
    analysis limit), bounded, cmd ``^`` and PowerShell backtick escapes undone (``p^owershell`` is still PowerShell)."""
    s = re.sub(r"\s+", " ", re.sub(r"[\x00-\x1f\x7f]+", " ", str(text or "")))[:cl.MAX_ANALYSE_LEN]
    if "^" in s:
        s = re.sub(r"\^(?=[A-Za-z0-9])", "", s)
    if "`" in s:
        s = re.sub(r"`(?=[A-Za-z])", "", s)
    return s.strip()


def find_lure(text: str) -> str:
    """Comment text of a fake-CAPTCHA lure ('' if none). The fake pages append a ``#`` comment such as ``# I am not a robot -
    reCAPTCHA Verification ID: 1234`` so the Run box shows a harmless sentence; the comment is the evidence, not the words
    alone (``https://site/#verification`` and a file called verification.txt are ordinary)."""
    first = len(text) - len(text.lstrip())
    starts = [m.start() for m in _COMMENT_START.finditer(text) if m.start() > first]  # a comment needs a command before it
    if not starts:
        return ""
    lure = _LURE_WORDS.search(text, starts[0])
    if lure is None:
        return ""
    return text[max(s for s in starts if s <= lure.start()):].strip()  # the comment the lure words sit in


def clickfix_signals(text: str, history: bool = False) -> List[Signal]:
    """The ClickFix patterns of this module found in ``text`` (a PowerShell command in the Run box or a history file)."""
    out: List[Signal] = []
    for key, label, sev, hist, mitre, rx in _CLICKFIX:
        if history and hist is not None:
            if hist <= Severity.INFO:
                continue
            sev = hist
        if rx.search(text):
            out.append(Signal(key, label, sev, mitre, True))
    return out


def analyser_signals(text: str, history: bool = False) -> List[Signal]:
    """What the shared analysers (``aegis.core.cmdline`` / ``aegis.core.fileanalysis``) make of ``text``.

    Run dialog: every hit of MEDIUM or more; the rules that download or start code keep their severity, any other hit is
    MEDIUM. History file: only download-and-run, encoded, tampering and credential-theft rules, at their own severity
    (a history is full of ordinary administration, which must not be reported)."""
    out: List[Signal] = []
    for rule_id, title, sev, mitre, _matched in cl.analyse_command_line(text):
        if sev < Severity.MEDIUM:
            continue
        if history:
            if rule_id not in _HISTORY_RULES:
                continue
            if rule_id == "AEG-CMD-DEFENDER-TAMPER" and not _DEFENDER_DISABLE.search(text):
                continue
        elif rule_id not in _RUN_EXEC:
            sev = Severity.MEDIUM
        out.append(Signal(_RULE_KEY.get(rule_id, rule_id), title, sev, tuple(mitre)))
    if history:
        for ind in fa.content_indicators(text.encode("utf-8", "replace"), "script"):
            if ind.rule_id in _HISTORY_INDICATORS:
                out.append(Signal(_RULE_KEY[ind.rule_id], ind.title, _INDICATOR_SEVERITY.get(ind.rule_id, ind.severity),
                                  tuple(ind.mitre)))
    return out


def _merge_signals(signals: Iterable[Signal]) -> List[Signal]:
    """One signal per key (the most severe, with every MITRE id seen), most severe first."""
    best: Dict[str, Signal] = {}
    for s in signals:
        cur = best.get(s.key)
        if cur is None:
            best[s.key] = s
            continue
        top = s if s.severity > cur.severity else cur
        best[s.key] = Signal(top.key, top.label, top.severity, tuple(dict.fromkeys(top.mitre + (cur if top is s else s).mitre)),
                             s.clickfix or cur.clickfix)
    if "hidden-stealth" in best:
        best.pop("hidden", None)  # the stricter signal already says it
    if "cradle" in best and "ps-web" in best:  # one signal for "downloads and runs code": the cradle rule absorbs the pattern
        del best["ps-web"]
        c = best["cradle"]
        best["cradle"] = Signal(c.key, c.label, c.severity, c.mitre, True)
    return sorted(best.values(), key=lambda s: (-int(s.severity), s.key))


def classify_command(command: str, history: bool = False) -> Optional[CommandVerdict]:
    """Verdict on one Windows / PowerShell command line, or None when it looks ordinary.

    * a fake-CAPTCHA lure comment together with any signal is CRITICAL; a lure with nothing else is HIGH;
    * otherwise the most severe signal decides: download-and-run, encoded or hidden-and-bypassing PowerShell, mshta /
      rundll32 / regsvr32 / msiexec on a web address, curl / certutil / bitsadmin downloads, ``conhost --headless`` and
      ``finger user@host`` are HIGH; the shared analysers' other hits are MEDIUM (Run dialog) or keep their own severity
      (history);
    * a command whose every web address is a well-known installer (``irm https://astral.sh/uv/install.ps1 | iex``) loses its
      download-and-run signals, unless it also carries a lure."""
    text = _clean(command)
    if len(text) < 4:
        return None
    lure = find_lure(text)
    signals = clickfix_signals(text, history) + analyser_signals(text, history)
    if signals and not lure and downloads_only_from_trusted(text):
        signals = [s for s in signals if s.key not in ("cradle", "ps-web")]
    signals = _merge_signals(signals)
    if lure:
        return CommandVerdict(Severity.CRITICAL if signals else Severity.HIGH, signals, lure)
    if signals:
        return CommandVerdict(max(s.severity for s in signals), signals)
    return None


def classify_run_command(command: str) -> Optional[CommandVerdict]:
    """Verdict on a command typed into the Windows Run dialog (see ``classify_command``)."""
    return classify_command(command, history=False)


def classify_powershell_line(line: str) -> Optional[CommandVerdict]:
    """Verdict on one line of a PowerShell history file (see ``classify_command``)."""
    return classify_command(line, history=True)


# =========================================================================== 1. Run dialog history (Windows)


@dataclass
class RunEntry:
    name: str  # registry value name (a, b, c ...)
    command: str
    position: int  # 1 = the most recent command


def _value_text(value: Any) -> str:
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        for enc in ("utf-16-le", "utf-8"):
            try:
                return raw.decode(enc).rstrip("\x00")
            except UnicodeDecodeError:
                continue
        return ""
    return value if isinstance(value, str) else ""


def parse_runmru(values: Mapping[str, Any]) -> List[RunEntry]:
    """Run dialog commands from the ``RunMRU`` values, most recent first. ``MRUList`` is the order of the value names
    (``"bca"``: b is the most recent); every command ends with a literal ``\\1``. Values that ``MRUList`` does not name are
    appended after the listed ones."""
    named: Dict[str, str] = {}
    order = ""
    for name, data in values.items():
        if str(name).lower() == "mrulist":
            order = _value_text(data).strip().lower()
        elif re.fullmatch(r"[A-Za-z]", str(name)):
            named[str(name).lower()] = _value_text(data)
    names = [n for n in dict.fromkeys(order) if n in named]
    names += sorted(n for n in named if n not in names)
    out: List[RunEntry] = []
    for name in names:
        command = re.sub(r"\\1$", "", named[name].rstrip("\x00 \t\r\n")).strip()
        if command:
            out.append(RunEntry(name, command, len(out) + 1))
    return out


def read_runmru() -> Dict[str, Any]:
    return reg_values("HKCU", RUNMRU_KEY)


def read_runmru_last_write() -> Optional[dt.datetime]:
    """When the RunMRU key was last written, i.e. when the most recent Run command was run (Windows records no time for
    the others). None where it cannot be read."""
    winreg = plat.winreg
    if not IS_WINDOWS or winreg is None:
        return None
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUNMRU_KEY, 0, winreg.KEY_READ) as key:
            return filetime_to_datetime(winreg.QueryInfoKey(key)[2])
    except OSError:
        return None


_RUN_TITLES = {
    "lure": "A fake-CAPTCHA (ClickFix) command was run from the Windows Run dialog",
    "lure-only": "A command with fake human-verification text was run from the Windows Run dialog",
    "high": "A download or hidden-execution command was run from the Windows Run dialog",
    "medium": "An unusual command was run from the Windows Run dialog",
}

RUN_RECOMMENDATION = (
    "If you did not deliberately type this command yourself, assume it ran: a web page (a fake CAPTCHA, 'verify you are "
    "human' or 'fix this error' page) or a message tricked you into pasting it. Disconnect this PC from the network, run a "
    "full Aegis scan (and a second opinion scan from another product), and from a different, clean device change the "
    "passwords of your important accounts (email, banking, work, crypto exchanges), sign out of all sessions and turn on "
    "two-factor authentication - information stealers copy browser passwords, cookies and wallets within seconds. Deleting "
    "the Run entry is not a fix and does not remove anything that ran. If you only want to clear the record afterwards: "
    "open regedit, go to HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU and delete the "
    "value named in this finding (or all values to clear the whole list).")
RUN_RECOMMENDATION_MEDIUM = (
    "If you typed this command yourself you can ignore this finding. If you did not, or a web page or a message told you to "
    "paste it, assume it ran: disconnect this PC from the network, run a full Aegis scan, and from a different, clean device "
    "change the passwords of your important accounts and sign out of all sessions. To clear the record afterwards, open "
    "regedit, go to HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU and delete the value "
    "named in this finding; that only hides the entry.")


def run_finding(entry: RunEntry, verdict: CommandVerdict, last_write: Optional[dt.datetime] = None) -> Finding:
    """Finding for one flagged Run dialog command. The location holds the registry value and a short hash of the command,
    so it stays the same between scans and a different command in the same slot is a different finding."""
    command = mask_command(entry.command)
    lure = mask_command(verdict.lure, 160) if verdict.lure else ""
    where = f"HKCU\\{RUNMRU_KEY}\\{entry.name}#{_short_hash(entry.command)}"
    if verdict.lure and verdict.signals:
        tier = "lure"
    elif verdict.lure:
        tier = "lure-only"
    else:
        tier = "high" if verdict.severity >= Severity.HIGH else "medium"
    slot = ("the most recent command in the history" if entry.position == 1
            else f"command number {entry.position} in the history (1 is the most recent)")
    when = ""
    if entry.position == 1 and last_write:
        when = f" Windows records when the list last changed, which is when this command was run: {_fmt(last_write)}."
    elif entry.position != 1:
        when = " Windows records no time for individual Run commands."
    if tier == "medium":
        why = ("Administrators sometimes type commands like this, but attackers also get people to run them: fake 'fix this "
               "problem' pages and messages tell people to press Win+R, paste a command and press Enter.")
    else:
        why = ("Fake 'verify you are human' pages (ClickFix) copy a command like this to the clipboard and tell people to press "
               "Win+R, Ctrl+V and Enter; the command downloads and starts malware, usually an information stealer or a "
               "remote-access trojan"
               + (", and the text after the # is added so the Run box shows a harmless sentence" if verdict.lure else "")
               + ". No genuine CAPTCHA ever asks you to run a command.")
    description = (
        f"The Windows Run dialog (Win+R) remembers the commands typed into it. Entry '{entry.name}' of {RUNMRU_KEY} is "
        f"{slot}: {command}. What stands out: " + "; ".join(verdict.reasons) + f".{when} " + why)
    return Finding(
        rule_id="AEG-TRACE-RUNMRU", title=_RUN_TITLES[tier], severity=verdict.severity, category=Category.SUSPICIOUS,
        description=description, location=where,
        evidence={"value_name": entry.name, "position": entry.position, "command": command, "reasons": verdict.reasons,
                  "lure_text": lure or None, "last_registry_write": _iso(last_write) if entry.position == 1 else None},
        recommendation=RUN_RECOMMENDATION if verdict.severity >= Severity.HIGH else RUN_RECOMMENDATION_MEDIUM,
        remediation=None, mitre=list(dict.fromkeys(["T1204.004"] + verdict.mitre)))


def check_run_history(ctx: ScanContext) -> Iterator[Emitted]:
    if not IS_WINDOWS:
        yield CheckResult("AEG-TRACE-RUNMRU", RUN_TITLE, CheckStatus.SKIP,
                          "The Run dialog (Win+R) exists on Windows only.", Category.SUSPICIOUS)
        return
    entries = parse_runmru(read_runmru())
    ctx.bump("traces_run_entries", len(entries))
    if not entries:
        yield CheckResult("AEG-TRACE-RUNMRU", RUN_TITLE, CheckStatus.PASS, "The Run dialog history is empty.",
                          Category.SUSPICIOUS)
        return
    last_write: Optional[dt.datetime] = None
    flagged = 0
    for entry in entries:
        if ctx.cancelled:
            return
        verdict = classify_run_command(entry.command)
        if verdict is None:
            continue
        if not flagged:
            last_write = read_runmru_last_write()
        flagged += 1
        yield run_finding(entry, verdict, last_write)
    ctx.bump("traces_flagged", flagged)
    yield CheckResult("AEG-TRACE-RUNMRU", RUN_TITLE, _status(flagged),
                      f"{len(entries)} Run dialog {_plural(len(entries), 'command', 'commands')} examined: {flagged} "
                      "suspicious." if flagged else
                      f"{len(entries)} Run dialog {_plural(len(entries), 'command', 'commands')} examined; none looks like a "
                      "pasted download-and-run command.", Category.SUSPICIOUS)


# =========================================================================== history files: reading and parsing


@dataclass
class HistoryEntry:
    command: str
    when: Optional[dt.datetime] = None


@dataclass
class TailRead:
    lines: List[str] = field(default_factory=list)
    size: int = 0
    truncated: bool = False  # older lines were not read
    error: str = ""  # why the file was skipped ('' when it was read)


def read_history_tail(path: Path, max_lines: Optional[int] = None, max_bytes: Optional[int] = None,
                      max_file: Optional[int] = None) -> TailRead:
    """The last ``max_lines`` lines (default ``MAX_HISTORY_LINES``) of a history file, reading at most ``max_bytes``
    (``MAX_TAIL_BYTES``) from its end. A file larger than ``max_file`` (``MAX_HISTORY_FILE``) is not a command history and
    is not read at all."""
    max_lines = MAX_HISTORY_LINES if max_lines is None else max_lines
    max_bytes = MAX_TAIL_BYTES if max_bytes is None else max_bytes
    max_file = MAX_HISTORY_FILE if max_file is None else max_file
    try:
        size = path.stat().st_size
        if size > max_file:
            return TailRead(size=size, error=f"larger than {max_file // (1024 * 1024)} MB, so not read")
        with open(path, "rb") as fh:
            bom = fh.read(2)
            base = 2 if bom in (b"\xff\xfe", b"\xfe\xff") else 0  # UTF-16 files start with a byte order mark
            start = max(base, size - max_bytes)
            if base:
                start -= start % 2  # stay on a character boundary
            fh.seek(start)
            data = fh.read(max_bytes)
    except OSError as exc:
        return TailRead(error=f"could not be read ({exc.strerror or type(exc).__name__})")
    if base:
        text = data[:len(data) - len(data) % 2].decode("utf-16-le" if bom == b"\xff\xfe" else "utf-16-be", "replace")
    else:
        text = data.decode("utf-8", "replace").lstrip("﻿")
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    cut = start > base
    if cut and lines:
        lines = lines[1:]  # the first line of a tail read is cut in the middle
    if lines and lines[-1] == "":
        lines.pop()
    return TailRead(lines[-max_lines:], size, cut or len(lines) > max_lines)


def _join_lines(parts: Sequence[str]) -> str:
    """One line from the lines of a multi-line command: a ``;`` between commands, a space after a trailing operator."""
    out = ""
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if not out:
            out = part
        elif out.endswith(("|", "&&", "||", "&", "(", "{", ",")):
            out += " " + part
        else:
            out += " ; " + part
    return out


def parse_psreadline(lines: Sequence[str]) -> List[HistoryEntry]:
    """PSReadLine history (``ConsoleHost_history.txt``): one command per line; a multi-line command has a backtick at the end
    of each line but the last. PSReadLine keeps no time stamps."""
    out: List[HistoryEntry] = []
    pending: List[str] = []
    for raw in lines:
        line = raw.rstrip("\r\n")
        if line.endswith("`") and not line.endswith("``"):
            pending.append(line[:-1])
            continue
        if pending:
            pending.append(line)
            line = " ".join(p.strip() for p in pending if p.strip())
            pending = []
        line = line.strip()
        if line:
            out.append(HistoryEntry(line))
    if pending:
        line = " ".join(p.strip() for p in pending if p.strip())
        if line:
            out.append(HistoryEntry(line))
    return out


def _ends_with_continuation(line: str) -> bool:
    return (len(line) - len(line.rstrip("\\"))) % 2 == 1


def parse_bash_history(lines: Sequence[str]) -> List[HistoryEntry]:
    """``~/.bash_history``: one command per line, optionally preceded by a ``#<unix time>`` line (HISTTIMEFORMAT); a line
    ending in a backslash continues on the next one."""
    out: List[HistoryEntry] = []
    when: Optional[dt.datetime] = None
    parts: List[str] = []
    for raw in lines:
        line = raw.rstrip("\r\n")
        if not parts:
            stamp = re.fullmatch(r"#(\d{9,11})", line.strip())
            if stamp:
                when = unix_to_datetime(int(stamp.group(1)))
                continue
        if _ends_with_continuation(line):
            parts.append(line[:-1])
            continue
        parts.append(line)
        command = " ".join(p.strip() for p in parts if p.strip())
        parts = []
        if command:
            out.append(HistoryEntry(command, when))
        when = None
    if parts:
        command = " ".join(p.strip() for p in parts if p.strip())
        if command:
            out.append(HistoryEntry(command, when))
    return out


_ZSH_EXTENDED = re.compile(r"^: (\d+):\d+;(.*)$")


def parse_zsh_history(lines: Sequence[str]) -> List[HistoryEntry]:
    """``~/.zsh_history``: plain commands or the extended format ``: 1700000000:0;command``; a multi-line command is stored
    with a backslash at the end of each line but the last."""
    out: List[HistoryEntry] = []
    when: Optional[dt.datetime] = None
    parts: List[str] = []
    for raw in lines:
        line = raw.rstrip("\r\n")
        if not parts:
            m = _ZSH_EXTENDED.match(line)
            if m:
                when, line = unix_to_datetime(int(m.group(1))), m.group(2)
            else:
                when = None
        if _ends_with_continuation(line):
            parts.append(line[:-1])
            continue
        parts.append(line)
        command = " ".join(p.strip() for p in parts if p.strip())
        parts = []
        if command:
            out.append(HistoryEntry(command, when))
        when = None
    if parts:
        command = " ".join(p.strip() for p in parts if p.strip())
        if command:
            out.append(HistoryEntry(command, when))
    return out


def _fish_unescape(text: str) -> str:
    out: List[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text):
            nxt = text[i + 1]
            if nxt == "n":
                out.append("\n")
                i += 2
                continue
            if nxt == "\\":
                out.append("\\")
                i += 2
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def parse_fish_history(lines: Sequence[str]) -> List[HistoryEntry]:
    """``~/.local/share/fish/fish_history`` (a small YAML dialect): ``- cmd: <command>`` then ``  when: <unix time>``; a
    newline inside a command is written ``\\n`` and a backslash ``\\\\``."""
    out: List[HistoryEntry] = []
    command: Optional[str] = None
    when: Optional[dt.datetime] = None

    def flush() -> None:
        if command is not None:
            joined = _join_lines(command.split("\n"))
            if joined:
                out.append(HistoryEntry(joined, when))

    for raw in lines:
        line = raw.rstrip("\r\n")
        if line.startswith("- cmd:"):
            flush()
            command = _fish_unescape(line[len("- cmd:"):].strip())
            when = None
        elif command is not None and line.strip().startswith("when:"):
            stamp = line.strip()[len("when:"):].strip()
            when = unix_to_datetime(int(stamp)) if stamp.isdigit() else None
    flush()
    return out


def powershell_history_files(platform: Optional[str] = None, home: Optional[Path] = None,
                             env: Optional[Mapping[str, str]] = None) -> List[Path]:
    """PSReadLine history files of the current user: ``%APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine`` on Windows
    (Windows PowerShell and pwsh share it) and ``~/.local/share/powershell/PSReadLine`` on Linux and macOS. Besides
    ``ConsoleHost_history.txt`` the folder holds one file per host (``Visual Studio Code Host_history.txt`` ...)."""
    platform = platform or OS_NAME
    home = home or user_home()
    env = os.environ if env is None else env
    if platform == "windows":
        appdata = Path(env.get("APPDATA") or (home / "AppData" / "Roaming"))
        folder = appdata / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine"
    else:
        folder = Path(env.get("XDG_DATA_HOME") or (home / ".local" / "share")) / "powershell" / "PSReadLine"
    try:
        files = [p for p in folder.glob("*_history.txt") if p.is_file()] if folder.is_dir() else []
    except OSError:
        return []
    files.sort(key=lambda p: (p.name.lower() != "consolehost_history.txt", p.name.lower()))
    return files[:MAX_HISTORY_FILES]


def unix_history_files(home: Optional[Path] = None, env: Optional[Mapping[str, str]] = None) -> List[Tuple[str, Path]]:
    """``(shell, path)`` of the bash, zsh and fish history files of the current user that exist."""
    home = home or user_home()
    env = os.environ if env is None else env
    candidates: List[Tuple[str, Path]] = [("bash", home / ".bash_history")]
    if env.get("ZDOTDIR"):
        candidates.append(("zsh", Path(env["ZDOTDIR"]) / ".zsh_history"))
    candidates.append(("zsh", home / ".zsh_history"))
    if env.get("XDG_DATA_HOME"):
        candidates.append(("fish", Path(env["XDG_DATA_HOME"]) / "fish" / "fish_history"))
    candidates.append(("fish", home / ".local" / "share" / "fish" / "fish_history"))
    out: List[Tuple[str, Path]] = []
    seen = set()
    for shell, path in candidates:
        try:
            key = os.path.normcase(os.path.realpath(path))
            if key not in seen and path.is_file():
                seen.add(key)
                out.append((shell, path))
        except OSError:
            continue
    return out


UNIX_PARSERS: Dict[str, Callable[[Sequence[str]], List[HistoryEntry]]] = {
    "bash": parse_bash_history, "zsh": parse_zsh_history, "fish": parse_fish_history}


# =========================================================================== 3. Unix shell history classification

# Services that give anyone an anonymous download address (file hosts, paste sites, tunnels, dynamic DNS): malware delivery
# favours them and a genuine installer is never published there.
FREE_HOSTING: Tuple[str, ...] = (
    "pastebin.com", "paste.ee", "hastebin.com", "rentry.co", "justpaste.it", "termbin.com", "ix.io", "sprunge.us", "0x0.st",
    "transfer.sh", "temp.sh", "file.io", "bashupload.com", "tmpfiles.org", "anonfiles.com", "bayfiles.com", "gofile.io",
    "pixeldrain.com", "catbox.moe", "cdn.discordapp.com", "media.discordapp.net",
    "ngrok.io", "ngrok.app", "ngrok.dev", "ngrok-free.app", "ngrok-free.dev", "trycloudflare.com", "serveo.net",
    "localhost.run", "lhr.life", "loca.lt", "pagekite.me", "duckdns.org", "ddns.net", "hopto.org", "zapto.org",
)

_ARGS = r"(?:\"[^\"\n]*\"|'[^'\n]*'|[^|;&\n\"'])*"
_SH = r"(?:(?:ba|z|da|k|c)?sh)"
_SUDO = r"(?:sudo\s+(?:-\S+\s+)*)?"
_FETCH_PIPE = re.compile(
    r"\b(?:curl|wget)\b(?P<args>" + _ARGS + r")\|\s*" + _SUDO + r"(?:env\s+\S+=\S+\s+)*" + _SH + r"\b", re.I)
_FETCH_SUBST = re.compile(
    r"(?:\b" + _SH + r"\b(?:\s+-\S+)*|\bsource|\beval|(?<![\w.])\.)\s+[\"']?(?:<\(|\$\()\s*(?:curl|wget)\b"
    r"(?P<args>[^)\n]*)\)", re.I)
_B64_SHELL = re.compile(
    r"\bbase64\s+(?:-d|-D|--decode)\b[^\n]*?\|\s*" + _SUDO + _SH + r"\b|"
    r"(?:\beval|\b" + _SH + r"\s+-c)\s+[\"']?\$\(\s*(?:echo|printf)\b[^\n)]*\|\s*base64\s+(?:-d|-D|--decode)\b", re.I)
_OSA_PROMPT = re.compile(r"\bosascript\b(?=[^\n]*display\s+dialog)(?=[^\n]*hidden\s+answer)", re.I)
_DROP_DIRS = (r"(?:/private)?/(?:tmp|var/tmp|dev/shm)|/var/folders/[^\s/]+/[^\s/]+/[A-Za-z]|~/Downloads|\$HOME/Downloads|"
              r"\$\{HOME\}/Downloads|/Users/[^/\s]+/Downloads|/home/[^/\s]+/Downloads")
_XATTR_STRIP = re.compile(
    r"\bxattr\b[^\n;&|]*?(?:\s-[A-Za-z]*c[A-Za-z]*\b|\s-[A-Za-z]*d[A-Za-z]*\s+com\.apple\.quarantine\b)[^\n]*?"
    r"(?:;|&&|\|\||\|)\s*" + _SUDO + r"(?:(?:open|nohup|exec|env)\s+(?:-\S+\s+)*)*[\"']?"
    r"(?P<path>(?:" + _DROP_DIRS + r")/[^\s;&|\"']+)", re.I)
_CHMOD_MODE = r"(?:[ugoa]*\+[rwxs]*x[rwxs]*|[0-7]?[0-7][0-7][0-7])"
_DROP_RUN = re.compile(
    r"\bchmod\s+(?:-\w+\s+)*" + _CHMOD_MODE + r"\s+[\"']?(?P<p>(?:/tmp|/var/tmp|/dev/shm|/private/tmp)/[^\s;&|\"']+)[\"']?[^\n]*?"
    r"(?:;|&&|\|\|)\s*" + _SUDO + r"(?:(?:nohup|setsid|exec)\s+)*[\"']?(?P=p)(?![\w./-])|"
    r"\bcd\s+(?:/tmp|/var/tmp|/dev/shm)\b[^\n]*?\bchmod\s+(?:-\w+\s+)*" + _CHMOD_MODE + r"\s+(?:\./)?(?P<n>[\w.-]+)[^\n]*?"
    r"(?:;|&&|\|\|)\s*" + _SUDO + r"\./(?P=n)(?![\w./-])", re.I)

_UNIX_MITRE_FETCH = ("T1105", "T1059.004", "T1204.004")


def _host_of_token(token: str) -> str:
    """Host of a command-line argument that is a URL or a scheme-less address (``get.docker.com/x``); '' for anything else."""
    token = token.strip("\"'")
    if token.startswith("--") and "=" in token:
        token = token.split("=", 1)[1].strip("\"'")
    if token.startswith("-"):
        return ""
    if "://" in token:
        try:
            return (urllib.parse.urlsplit(token).hostname or "").lower()
        except ValueError:
            return ""
    m = re.match(r"^(?:\[([0-9a-f:]+)\]|([a-z0-9-]+(?:\.[a-z0-9-]+)+))(?::\d+)?(?:/|$)", token, re.I)
    return (m.group(1) or m.group(2)).lower() if m else ""


def fetch_hosts(args: str) -> List[str]:
    """Hosts a curl / wget argument string downloads from (URLs and scheme-less addresses; options are skipped)."""
    hosts: List[str] = []
    for token in re.findall(r"\"[^\"]*\"|'[^']*'|\S+", args):
        host = _host_of_token(token)
        if host and host not in hosts:
            hosts.append(host)
    return hosts


def _internal_ip(ip: "ipaddress._BaseAddress") -> bool:
    """Loopback, private (LAN), link-local and other non-Internet addresses: a local development server, not an attacker's."""
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast or ip.is_reserved)


def _numeric_ipv4(host: str) -> str:
    """The dotted address of an IPv4 address written as one decimal or hex number (``1572395042``, ``0x5db8d822``), which
    curl accepts and which hides an IP address from a reader; '' for anything else."""
    try:
        if re.fullmatch(r"[0-9]{8,10}", host):
            return str(ipaddress.IPv4Address(int(host)))
        if re.fullmatch(r"0x[0-9a-f]{8}", host):
            return str(ipaddress.IPv4Address(int(host, 16)))
    except ValueError:
        pass
    return ""


def classify_fetch_host(host: str, is_bad_domain: Optional[Callable[[str], bool]] = None) -> Optional[Tuple[str, Severity]]:
    """``(description, severity)`` when a host is a poor place to run a downloaded script from, else None: a known-malicious
    domain (CRITICAL), a public IP address, or a free file / paste / tunnel service (HIGH)."""
    host = host.lower().strip(".")
    host = _numeric_ipv4(host) or host
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        return (f"a raw IP address ({host})", Severity.HIGH) if not _internal_ip(ip) else None
    if is_bad_domain is not None and is_bad_domain(host):
        return f"a known-malicious domain ({host})", Severity.CRITICAL
    for service in FREE_HOSTING:
        if host == service or host.endswith("." + service):
            return f"a free file-sharing, paste or tunnel service ({service})", Severity.HIGH
    return None


def classify_unix_command(command: str, is_bad_domain: Optional[Callable[[str], bool]] = None) -> Optional[CommandVerdict]:
    """Verdict on one bash / zsh / fish command, or None. Only strong patterns count (developers run ``curl | sh`` installers
    from well-known sites all day):

    * a ``curl`` / ``wget`` download piped into a shell (also ``bash <(curl ...)``, ``sh -c "$(curl ...)"``, ``source <(...)``)
      whose host is a known-malicious domain (CRITICAL), a public IP address or a free file / paste / tunnel service (HIGH);
    * ``base64 -d | sh`` (HIGH);
    * ``osascript`` showing a ``display dialog`` with a ``hidden answer`` - the fake password prompt of AMOS / Atomic
      Stealer (HIGH);
    * ``xattr`` removing the quarantine flag followed by running a file from /tmp (HIGH) or Downloads (MEDIUM);
    * ``chmod +x /tmp/x && /tmp/x`` drop-and-run (MEDIUM; HIGH when the same line downloads the file)."""
    text = re.sub(r"\s+", " ", re.sub(r"[\x00-\x1f\x7f]+", " ", str(command or "")))[:cl.MAX_ANALYSE_LEN].strip()
    if len(text) < 4:
        return None
    signals: List[Signal] = []
    for rx in (_FETCH_PIPE, _FETCH_SUBST):
        for m in rx.finditer(text):
            for host in fetch_hosts(m.group("args")):
                verdict = classify_fetch_host(host, is_bad_domain)
                if verdict:
                    what, sev = verdict
                    key = "fetch-exec-bad-domain" if sev == Severity.CRITICAL else "fetch-exec"
                    signals.append(Signal(key, f"a script downloaded and run straight from {what}", sev, _UNIX_MITRE_FETCH))
    if _B64_SHELL.search(text):
        signals.append(Signal("b64-exec", "a Base64 blob decoded and run in a shell", Severity.HIGH,
                              ("T1140", "T1059.004", "T1204.004")))
    if _OSA_PROMPT.search(text):
        signals.append(Signal("osascript-prompt", "a fake password dialog with a hidden answer field (Atomic Stealer style)",
                              Severity.HIGH, ("T1056.002", "T1059.002")))
    m = _XATTR_STRIP.search(text)
    if m:
        tmp = bool(re.match(r"(?i)(?:/private)?/(?:tmp|var/tmp|dev/shm)/|/var/folders/", m.group("path")))
        signals.append(Signal("quarantine-strip-exec", "the macOS quarantine flag removed and the file run from "
                              + ("a temporary folder" if tmp else "Downloads"), Severity.HIGH if tmp else Severity.MEDIUM,
                              ("T1553.001", "T1059.004")))
    low = text.lower()
    # the shared rule "payload downloaded into a temp directory and executed"; it needs chmod and a download tool, so the
    # (comparatively slow) analyser only runs for lines that have both
    download_drop = ("chmod" in low and ("curl" in low or "wget" in low)
                     and any(h[0] == "AEG-CMD-LINUX-DROP-EXEC" for h in cl.analyse_command_line(text)))
    if download_drop or _DROP_RUN.search(text):
        signals.append(Signal("drop-exec", "a file downloaded into /tmp and run" if download_drop
                              else "a file in /tmp made executable and run", Severity.HIGH if download_drop
                              else Severity.MEDIUM, ("T1105", "T1059.004")))
    signals = _merge_signals(signals)
    return CommandVerdict(max(s.severity for s in signals), signals) if signals else None


# =========================================================================== 2 + 3. history scanning and findings


@dataclass
class HistoryHit:
    command: str  # masked
    severity: Severity
    reasons: List[str]
    keys: List[str]
    mitre: List[str]
    when: Optional[dt.datetime] = None
    count: int = 1
    index: int = 0  # position of the last occurrence in the file (larger = newer)


@dataclass
class HistoryScan:
    examined: int = 0
    occurrences: int = 0
    cancelled: bool = False
    by_command: Dict[str, HistoryHit] = field(default_factory=dict)

    @property
    def hits(self) -> List[HistoryHit]:
        """Distinct flagged commands: most severe first, then newest first."""
        return sorted(self.by_command.values(), key=lambda h: (-int(h.severity), -h.index))

    @property
    def severity(self) -> Severity:
        return max((h.severity for h in self.by_command.values()), default=Severity.INFO)


def scan_history(entries: Iterable[HistoryEntry], classify: Callable[[str], Optional[CommandVerdict]],
                 should_stop: Optional[Callable[[], bool]] = None) -> HistoryScan:
    """Classify every command of a history and keep the flagged ones, masked and de-duplicated (the same command run ten
    times is one hit seen ten times). The rest of the history is dropped immediately."""
    scan = HistoryScan()
    for index, entry in enumerate(entries):
        if should_stop and index % 200 == 0 and should_stop():
            scan.cancelled = True
            break
        scan.examined += 1
        if len(entry.command) < 4:
            continue
        verdict = classify(entry.command)
        if verdict is None:
            continue
        scan.occurrences += 1
        masked = mask_command(entry.command)
        hit = scan.by_command.get(masked)
        if hit is None:
            scan.by_command[masked] = HistoryHit(masked, verdict.severity, verdict.reasons, verdict.keys, verdict.mitre,
                                                 entry.when, 1, index)
        else:
            hit.count += 1
            hit.index = index
            if entry.when and (hit.when is None or entry.when > hit.when):
                hit.when = entry.when
    return scan


def _history_evidence(path: Path, scan: HistoryScan, lines: int, truncated: bool) -> Dict[str, Any]:
    hits = scan.hits
    categories: Dict[str, int] = {}
    for hit in hits:
        for reason in hit.reasons:
            categories[reason] = categories.get(reason, 0) + 1
    return {
        "file": str(path), "lines_examined": lines, "older_lines_not_read": truncated,
        "flagged_commands": len(hits), "flagged_occurrences": scan.occurrences, "patterns": categories,
        "examples": [{"command": h.command, "severity": h.severity.name.lower(), "reasons": h.reasons,
                      "when": _iso(h.when), "times_seen": h.count} for h in hits[:MAX_EXAMPLES]],
        "examples_shown": min(len(hits), MAX_EXAMPLES)}


def _history_summary(scan: HistoryScan, lines: int) -> str:
    hits = scan.hits
    n = len(hits)
    patterns: List[str] = []
    for hit in hits:
        for reason in hit.reasons:
            if reason not in patterns:
                patterns.append(reason)
    newest = max((h.when for h in hits if h.when), default=None)
    seen = f" (seen {scan.occurrences} times in all)" if scan.occurrences != n else ""
    text = (f"{n} distinct {_plural(n, 'command', 'commands')} among the last {lines} lines "
            f"{_plural(n, 'matches', 'match')} known attack patterns{seen}: " + "; ".join(patterns[:5])
            + ("; ..." if len(patterns) > 5 else "") + ".")
    if newest:
        text += f" The most recent one was run around {_fmt(newest)}."
    if n > MAX_EXAMPLES:
        text += f" The {MAX_EXAMPLES} most serious are listed in the evidence."
    return text


def powershell_history_finding(path: Path, scan: HistoryScan, lines: int, truncated: bool = False) -> Finding:
    mitre = list(dict.fromkeys(m for h in scan.hits for m in h.mitre))
    return Finding(
        rule_id="AEG-TRACE-PSHISTORY", title=f"Suspicious commands found in the PowerShell history ({path.name})",
        severity=scan.severity, category=Category.SUSPICIOUS,
        description=f"PowerShell keeps a plain-text record of the commands typed into its console in {path}. "
                    + _history_summary(scan, lines) + " These are the commands attackers get people to paste from fake "
                    "'verify you are human' or 'fix this error' pages, and the ones malware runs to fetch its next stage, "
                    "switch off or blind Microsoft Defender and steal passwords. Developers and administrators run similar "
                    "commands for good reasons (installers from well-known sites are ignored), so the question is whether "
                    "you ran each of them yourself.",
        location=str(path), evidence=_history_evidence(path, scan, lines, truncated),
        recommendation="Read the example commands in the evidence. If you ran them on purpose (for example to install a tool "
                       "you trust) no action is needed. If you do not remember them, or you pasted a command from a web page "
                       "or a message, assume it ran: disconnect this PC from the network, run a full Aegis scan, and from a "
                       "different, clean device change the passwords of your important accounts and sign out of all "
                       "sessions. Deleting the history file only hides the record.",
        remediation=None, mitre=mitre or ["T1059.001"])


def shell_history_finding(shell: str, path: Path, scan: HistoryScan, lines: int, truncated: bool = False) -> Finding:
    mitre = list(dict.fromkeys(m for h in scan.hits for m in h.mitre))
    return Finding(
        rule_id="AEG-TRACE-SHELLHISTORY", title=f"Suspicious commands found in the {shell} history ({path.name})",
        severity=scan.severity, category=Category.SUSPICIOUS,
        description=f"{path} is the {shell} command history of this account. "
                    + _history_summary(scan, lines) + " Only strong patterns are reported: a download piped straight into a "
                    "shell from an IP address, a known-malicious domain or a file-sharing / tunnel service, a Base64 blob "
                    "decoded into a shell, a fake password dialog, quarantine flags stripped from a file that is then run, "
                    "or a file dropped into /tmp and run. Fake 'verify you are human' and 'fix this' pages tell people to "
                    "paste exactly such commands into a terminal, and information stealers for macOS (AMOS / Atomic "
                    "Stealer) are installed this way.",
        location=str(path), evidence=_history_evidence(path, scan, lines, truncated),
        recommendation="Read the example commands in the evidence. If you ran them on purpose, no action is needed. If you do "
                       "not remember them, or you pasted a command from a web page or a message, assume it ran: disconnect "
                       "this computer from the network, run a full Aegis scan, check what the command installed (launch "
                       "agents, cron jobs, files in /tmp and Downloads), and from a different, clean device change the "
                       "passwords of your important accounts and sign out of all sessions. On a Mac also check Keychain "
                       "and crypto-wallet apps. Deleting the history file only hides the record.",
        remediation=None, mitre=mitre or ["T1059.004"])


def check_powershell_history(ctx: ScanContext) -> Iterator[Emitted]:
    files = powershell_history_files()
    if not files:
        yield CheckResult("AEG-TRACE-PSHISTORY", PS_TITLE, CheckStatus.SKIP,
                          "No PowerShell command history found (PSReadLine has not saved any).", Category.SUSPICIOUS)
        return
    flagged = lines_total = 0
    notes: List[str] = []
    for path in files:
        if ctx.cancelled:
            return
        ctx.report("traces", "reading a PowerShell history file")
        tail = read_history_tail(path)
        if tail.error:
            notes.append(f"{path.name} {tail.error}")
            continue
        scan = scan_history(parse_psreadline(tail.lines), classify_powershell_line, lambda: ctx.cancelled)
        if scan.cancelled:
            return
        lines_total += len(tail.lines)
        ctx.bump("traces_history_lines", len(tail.lines))
        if scan.hits:
            flagged += 1
            yield powershell_history_finding(path, scan, len(tail.lines), tail.truncated)
    ctx.bump("traces_flagged", flagged)
    detail = (f"{len(files)} history {_plural(len(files), 'file', 'files')}, {lines_total} recent lines examined: "
              + (f"suspicious commands in {flagged} {_plural(flagged, 'file', 'files')}." if flagged
                 else "no download-and-run, encoded or tampering commands."))
    if notes:
        detail += " Skipped: " + "; ".join(notes) + "."
    yield CheckResult("AEG-TRACE-PSHISTORY", PS_TITLE, _status(flagged), detail, Category.SUSPICIOUS)


def check_shell_history(ctx: ScanContext) -> Iterator[Emitted]:
    if IS_WINDOWS:
        yield CheckResult("AEG-TRACE-SHELLHISTORY", SHELL_TITLE, CheckStatus.SKIP,
                          "bash, zsh and fish history is reviewed on Linux and macOS (PowerShell history is a separate check).",
                          Category.SUSPICIOUS)
        return
    files = unix_history_files()
    if not files:
        yield CheckResult("AEG-TRACE-SHELLHISTORY", SHELL_TITLE, CheckStatus.SKIP,
                          "No bash, zsh or fish history file found.", Category.SUSPICIOUS)
        return
    sigs = ctx.signatures
    feed = _feed_loaded(sigs)

    def classify(command: str) -> Optional[CommandVerdict]:
        return classify_unix_command(command, sigs.is_bad_domain if feed else None)

    flagged = lines_total = 0
    notes: List[str] = []
    for shell, path in files:
        if ctx.cancelled:
            return
        ctx.report("traces", f"reading the {shell} history")
        tail = read_history_tail(path)
        if tail.error:
            notes.append(f"{path.name} {tail.error}")
            continue
        scan = scan_history(UNIX_PARSERS[shell](tail.lines), classify, lambda: ctx.cancelled)
        if scan.cancelled:
            return
        lines_total += len(tail.lines)
        ctx.bump("traces_history_lines", len(tail.lines))
        if scan.hits:
            flagged += 1
            yield shell_history_finding(shell, path, scan, len(tail.lines), tail.truncated)
    ctx.bump("traces_flagged", flagged)
    detail = (f"{len(files)} history {_plural(len(files), 'file', 'files')}, {lines_total} recent lines examined: "
              + (f"suspicious commands in {flagged} {_plural(flagged, 'file', 'files')}." if flagged
                 else "no strong download-and-run or fake-prompt pattern."))
    if not feed:
        detail += " Matching against known-malicious domains is off because no threat feed is loaded (`aegis update`)."
    if notes:
        detail += " Skipped: " + "; ".join(notes) + "."
    yield CheckResult("AEG-TRACE-SHELLHISTORY", SHELL_TITLE, _status(flagged), detail, Category.SUSPICIOUS)


# =========================================================================== 4. DNS cache (Windows)

# Get-DnsClientCache gives locale-independent, typed records as JSON. `ipconfig /displaydns` prints translated labels
# ("Record Name", "Record Type", ...) and a layout that differs between Windows releases, which makes parsing it fragile.
# -InputObject @(...) keeps a single record an array and an empty cache `[]`, so an empty cache and a failure differ.
DNS_SCRIPT = ("try { ConvertTo-Json -Compress -InputObject @(Get-DnsClientCache -ErrorAction Stop | "
              "Select-Object Entry,Name,Data,Type) } catch { exit 1 }")
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV"}
NON_WINDOWS_DNS_NOTE = ("There is no system-wide DNS cache that can be listed reliably on this OS (systemd-resolved, "
                        "mDNSResponder and local resolvers keep it in memory and do not expose it).")


@dataclass
class DnsRecord:
    entry: str  # the name that was looked up
    name: str  # the record's own name
    data: str
    rtype: str  # "A", "AAAA", "CNAME" ... or the number as text


def _domain(value: Any) -> str:
    """A cached name as a plain lower-case domain; '' for empty names, IP addresses and reverse-lookup names."""
    text = str(value or "").strip().strip(".").lower()
    if not text or text.endswith((".in-addr.arpa", ".ip6.arpa")) or " " in text:
        return ""
    try:
        ipaddress.ip_address(text)
        return ""
    except ValueError:
        return text


def _ip(value: Any) -> str:
    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError:
        return ""


def parse_dns_cache(rows: Any) -> List[DnsRecord]:
    """DnsRecord list from the ``Get-DnsClientCache | ConvertTo-Json`` result (a list of dicts, or one dict)."""
    out: List[DnsRecord] = []
    for row in as_list(rows):
        if not isinstance(row, dict):
            continue
        low = {str(k).lower(): v for k, v in row.items()}
        raw_type = low.get("type")
        rtype = DNS_TYPES.get(raw_type, str(raw_type)) if isinstance(raw_type, int) and not isinstance(raw_type, bool) \
            else str(raw_type or "").upper()
        out.append(DnsRecord(str(low.get("entry") or ""), str(low.get("name") or ""), str(low.get("data") or ""), rtype))
    return out


def _feed_loaded(sigs: Any) -> bool:
    return bool(getattr(sigs, "bad_domains", None))


@dataclass
class DnsHit:
    domain: str
    listed_domain: bool = False  # the domain itself is on the malicious-domain feed
    ips: List[str] = field(default_factory=list)  # addresses on the malicious-IP feed it resolves to
    looked_up_as: List[str] = field(default_factory=list)  # for a CNAME target: the names that led to it


def find_dns_hits(records: Sequence[DnsRecord], sigs: Any) -> List[DnsHit]:
    """Cached names on the malicious-domain feed and names that resolve to an address on the malicious-IP feed (one hit per
    domain). A CNAME target is checked as a domain too."""
    hits: Dict[str, DnsHit] = {}

    def hit(domain: str) -> DnsHit:
        return hits.setdefault(domain, DnsHit(domain))

    seen: Dict[str, bool] = {}
    for rec in records:
        names = [n for n in dict.fromkeys((_domain(rec.entry), _domain(rec.name))) if n]
        targets = [_domain(rec.data)] if rec.rtype == "CNAME" else []
        for domain in names + [t for t in targets if t]:
            if domain not in seen:
                seen[domain] = bool(sigs.is_bad_domain(domain))
            if seen[domain]:
                h = hit(domain)
                h.listed_domain = True
                if domain in targets and rec.entry and _domain(rec.entry) != domain:
                    q = _domain(rec.entry)
                    if q and q not in h.looked_up_as:
                        h.looked_up_as.append(q)
        if rec.rtype in ("A", "AAAA"):
            ip = _ip(rec.data)
            if ip and sigs.is_bad_ip(ip):
                for domain in names[:1]:
                    h = hit(domain)
                    if ip not in h.ips:
                        h.ips.append(ip)
    return sorted(hits.values(), key=lambda h: (not h.listed_domain, h.domain))


def dns_finding(hit: DnsHit) -> Finding:
    if hit.listed_domain:
        title = f"This PC recently contacted a known-malicious domain: {hit.domain}"
        why = f"{hit.domain} is on the malicious-domain feed (URLhaus and other lists downloaded by `aegis update`)"
    else:
        title = f"This PC recently contacted a known-malicious server: {hit.domain} ({hit.ips[0]})"
        why = f"{hit.domain} resolves to {hit.ips[0]}, an address on the malicious-IP feed"
    if hit.listed_domain and hit.ips:
        why += f", and to {', '.join(hit.ips[:3])}, which is on the malicious-IP feed"
    via = f" It was reached through {', '.join(hit.looked_up_as[:3])}." if hit.looked_up_as else ""
    return Finding(
        rule_id="AEG-TRACE-DNS", title=title, severity=Severity.HIGH, category=Category.NETWORK,
        description=f"The Windows DNS cache, which remembers the names this PC looked up in the last minutes or hours, holds an "
                    f"entry for {hit.domain}. {why}.{via} A DNS lookup shows that a program or a web page tried to reach the "
                    "address; the cache does not show which program did it or whether a connection followed. Malware uses "
                    "such domains to download its next stage and to receive commands, and phishing and drive-by pages use "
                    "them too.",
        location=f"dns-cache:{hit.domain}",
        evidence={"domain": hit.domain, "on_domain_feed": hit.listed_domain, "malicious_ips": hit.ips[:5],
                  "looked_up_as": hit.looked_up_as[:5]},
        recommendation="Find out which program made the request: look in Task Manager and Resource Monitor > Network (or "
                       "Process Explorer) for connections you do not recognise, check the Aegis network scanner results, "
                       "and your firewall or router logs. If it was a web page you opened by mistake and nothing was "
                       "downloaded, a full scan is enough; if a program you do not recognise did it, treat the PC as "
                       "compromised: run a full Aegis scan and change your important passwords from a clean device. "
                       "`aegis protect web` blocks known-malicious domains from now on.",
        remediation=None, mitre=["T1071"] if hit.listed_domain else ["T1071", "T1568"])


def check_dns_cache(ctx: ScanContext) -> Iterator[Emitted]:
    if not IS_WINDOWS:
        yield CheckResult("AEG-TRACE-DNS", DNS_TITLE, CheckStatus.SKIP, NON_WINDOWS_DNS_NOTE, Category.NETWORK)
        return
    sigs = ctx.signatures
    if not _feed_loaded(sigs):
        yield CheckResult("AEG-TRACE-DNS", DNS_TITLE, CheckStatus.SKIP,
                          "No malicious-domain feed is loaded, so cached names cannot be checked. " + UPDATE_HINT,
                          Category.NETWORK)
        return
    rows = powershell_json(DNS_SCRIPT, timeout=60)
    if rows is None:
        yield CheckResult("AEG-TRACE-DNS", DNS_TITLE, CheckStatus.SKIP,
                          "The DNS cache could not be read (Get-DnsClientCache failed or PowerShell is unavailable).",
                          Category.NETWORK)
        return
    records = parse_dns_cache(rows)
    ctx.bump("traces_dns_entries", len(records))
    hits = find_dns_hits(records, sigs)
    for hit in hits[:MAX_DNS_FINDINGS]:
        if ctx.cancelled:
            return
        yield dns_finding(hit)
    ctx.bump("traces_flagged", len(hits))
    detail = (f"{len(records)} cached DNS {_plural(len(records), 'record', 'records')} checked: {len(hits)} known-malicious "
              f"{_plural(len(hits), 'domain or server', 'domains or servers')}." if hits else
              f"{len(records)} cached DNS {_plural(len(records), 'record', 'records')} checked; none is on a threat feed.")
    if len(hits) > MAX_DNS_FINDINGS:
        detail += f" Only the first {MAX_DNS_FINDINGS} are reported."
    yield CheckResult("AEG-TRACE-DNS", DNS_TITLE, _status(len(hits)), detail, Category.NETWORK)


# =========================================================================== 5. Browser history


@dataclass(frozen=True)
class BrowserProfile:
    browser: str  # "Google Chrome"
    family: str  # "chromium" | "firefox"
    label: str  # "Default", "Profile 1 (Work)" or a Firefox profile name
    path: Path  # the profile folder

    @property
    def history(self) -> Path:
        return self.path / ("places.sqlite" if self.family == "firefox" else "History")


def discover_browser_profiles(os_name: Optional[str] = None, home: Optional[Path] = None,
                              env: Optional[Dict[str, str]] = None) -> List[BrowserProfile]:
    """Every browser profile on this PC, found with the browser scanner's own discovery (so a browser it knows about is
    covered here too)."""
    os_name = os_name or OS_NAME
    out: List[BrowserProfile] = []
    seen = set()

    def add(profile: BrowserProfile) -> None:
        key = os.path.normcase(str(profile.path))
        if key not in seen:
            seen.add(key)
            out.append(profile)

    for root in chromium_browser_roots(os_name, home, env):
        try:
            for path in chromium_profiles(root.base):
                add(BrowserProfile(root.name, "chromium", chromium_profile_label(root.base, path), path))
        except OSError:
            continue
    for root in firefox_browser_roots(os_name, home, env):
        try:
            for name, path in firefox_profiles(root.base):
                add(BrowserProfile(root.name, "firefox", name, path))
        except OSError:
            continue
    return out


@dataclass
class HistoryRow:
    url: str
    when: Optional[dt.datetime]
    visits: int = 1


class HistoryReadError(Exception):
    """A browser history database could not be read."""


CHROMIUM_QUERY = ("SELECT url, last_visit_time, visit_count FROM urls WHERE last_visit_time >= ? "
                  "ORDER BY last_visit_time DESC LIMIT ?")
FIREFOX_QUERY = ("SELECT url, last_visit_date, visit_count FROM moz_places WHERE last_visit_date >= ? "
                 "ORDER BY last_visit_date DESC LIMIT ?")


def _copy_database(path: Path, folder: str) -> str:
    """Copy a (locked) history database and its write-ahead log into ``folder``; returns the copy's path."""
    dst = os.path.join(folder, "history.db")
    shutil.copyfile(path, dst)
    wal = Path(str(path) + "-wal")
    if wal.exists():
        try:
            shutil.copyfile(wal, dst + "-wal")
        except OSError:
            pass  # the main file is still readable; only the newest visits can be missing
    return dst


def _query_copy(copy: str, query: str, params: Tuple[int, int]) -> List[Tuple[Any, ...]]:
    """Run ``query`` on the private copy, opened read-only. Some SQLite builds cannot open a copy that comes with a
    write-ahead log read-only; the copy (never the original) is then opened normally with writes switched off."""
    uri = Path(copy).resolve().as_uri() + "?mode=ro"
    try:
        with closing(sqlite3.connect(uri, uri=True, timeout=3)) as con:
            con.execute("PRAGMA query_only = ON")
            return con.execute(query, params).fetchall()
    except sqlite3.OperationalError:
        with closing(sqlite3.connect(copy, timeout=3)) as con:
            con.execute("PRAGMA query_only = ON")
            return con.execute(query, params).fetchall()


def read_history_rows(profile: BrowserProfile, since: dt.datetime, limit: int = BROWSER_ROW_LIMIT) -> List[HistoryRow]:
    """Visits of the last days from a profile's history, newest first, from a private read-only copy of the database.
    Raises HistoryReadError (never an sqlite or OS error) when the file is missing, locked or not a history database."""
    source = profile.history
    if not source.is_file():
        raise HistoryReadError("no history file")
    firefox = profile.family == "firefox"
    query = FIREFOX_QUERY if firefox else CHROMIUM_QUERY
    cutoff = datetime_to_unix_micros(since) if firefox else datetime_to_webkit(since)
    convert = unix_micros_to_datetime if firefox else webkit_to_datetime
    try:
        with tempfile.TemporaryDirectory(prefix="aegis-hist-") as folder:
            rows = _query_copy(_copy_database(source, folder), query, (cutoff, limit))
    except PermissionError as exc:
        raise HistoryReadError("the file is locked (close the browser and scan again)") from exc
    except OSError as exc:
        raise HistoryReadError(f"could not be copied ({exc.strerror or type(exc).__name__})") from exc
    except sqlite3.Error as exc:
        raise HistoryReadError("not a readable history database") from exc
    out: List[HistoryRow] = []
    for url, stamp, visits in rows:
        if isinstance(url, str) and url.lower().startswith(("http://", "https://", "ftp://")):
            out.append(HistoryRow(url, convert(stamp), visits if isinstance(visits, int) and visits > 0 else 1))
    return out


@dataclass
class SiteHit:
    domain: str  # the blocklist entry that matched (or the IP address)
    urls: int = 0
    visits: int = 0
    last_visit: Optional[dt.datetime] = None
    examples: List[str] = field(default_factory=list)  # query-free addresses, newest first


def match_bad_host(host: str, sigs: Any) -> Optional[str]:
    """The malicious-feed entry a visited host matches: the listed domain (``evil.example`` for ``a.evil.example``), the IP
    address itself, or None for a host that is on no feed."""
    host = (host or "").lower().strip(".")
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not sigs.is_bad_domain(host):
            return None
        listed = getattr(sigs, "bad_domains", None) or ()
        candidate = host
        while candidate:
            if candidate in listed:
                return candidate
            if "." not in candidate:
                break
            candidate = candidate.split(".", 1)[1]
        return host
    return host if sigs.is_bad_ip(host) else None


def find_bad_sites(rows: Iterable[HistoryRow], sigs: Any) -> Tuple[int, Dict[str, SiteHit]]:
    """``(rows examined, {matched domain: SiteHit})`` for the visits whose host is on a malicious-domain / IP feed."""
    hits: Dict[str, SiteHit] = {}
    verdicts: Dict[str, Optional[str]] = {}
    examined = 0
    for row in rows:
        examined += 1
        try:
            host = (urllib.parse.urlsplit(row.url).hostname or "").lower()
        except ValueError:
            continue
        if host not in verdicts:
            verdicts[host] = match_bad_host(host, sigs)
        domain = verdicts[host]
        if not domain:
            continue
        hit = hits.setdefault(domain, SiteHit(domain))
        hit.urls += 1
        hit.visits += row.visits
        if row.when and (hit.last_visit is None or row.when > hit.last_visit):
            hit.last_visit = row.when
        example = strip_url(row.url)
        if example and example not in hit.examples and len(hit.examples) < MAX_BROWSER_EXAMPLES:
            hit.examples.append(example)
    return examined, hits


def site_finding(profile: BrowserProfile, hit: SiteHit, days: int = BROWSER_DAYS) -> Finding:
    when = f", most recently {_fmt(hit.last_visit)}" if hit.last_visit else ""
    return Finding(
        rule_id="AEG-TRACE-BROWSER", title=f"Browser visited a known-malicious site: {hit.domain}", severity=Severity.HIGH,
        category=Category.BROWSER,
        description=f"The history of {profile.browser} (profile {profile.label}) shows {hit.visits} "
                    f"{_plural(hit.visits, 'visit', 'visits')} to {hit.domain} in the last {days} days{when}. That "
                    "domain is on a malware / phishing blocklist (URLhaus and the other feeds downloaded by `aegis update`): "
                    "such sites serve malware downloads, fake software and CAPTCHA pages that make you paste a command, "
                    "and phishing pages that steal passwords. Visiting one does not by itself mean the PC is infected - what "
                    "matters is what happened on the page.",
        location=f"{profile.path}#{hit.domain}",
        evidence={"browser": profile.browser, "profile": profile.label, "profile_path": str(profile.path),
                  "domain": hit.domain, "visit_count": hit.visits, "urls_visited": hit.urls,
                  "last_visit": _iso(hit.last_visit), "example_urls": hit.examples, "window_days": days},
        recommendation="Think back to what you did there. If you downloaded or ran a file, pasted a command the page told "
                       "you to run, or typed a password or payment details, treat the PC as compromised: run a full Aegis "
                       "scan, check the Downloads folder and recently installed programs, and change the passwords you used "
                       "from a different, clean device. If you only landed on the page (an ad or a redirect) and nothing "
                       "was downloaded or entered, a full scan is enough. `aegis protect web` blocks known-malicious "
                       "domains from now on.",
        remediation=None, mitre=["T1189", "T1566.002"])


def check_browser_history(ctx: ScanContext) -> Iterator[Emitted]:
    sigs = ctx.signatures
    if not _feed_loaded(sigs):  # without a feed nothing could match, so the history is not even opened
        yield CheckResult("AEG-TRACE-BROWSER", BROWSER_TITLE, CheckStatus.SKIP,
                          "No malicious-domain feed is loaded, so browser history cannot be checked. " + UPDATE_HINT,
                          Category.BROWSER)
        return
    profiles = discover_browser_profiles()
    if not profiles:
        yield CheckResult("AEG-TRACE-BROWSER", BROWSER_TITLE, CheckStatus.SKIP, "No browser profile found.", Category.BROWSER)
        return
    budget = float(ctx.options.get("traces_browser_budget_s", BROWSER_BUDGET_S) or BROWSER_BUDGET_S)
    deadline = time.monotonic() + budget
    since = _utcnow() - dt.timedelta(days=BROWSER_DAYS)
    read = rows_total = flagged = 0
    notes: List[str] = []
    for index, profile in enumerate(profiles):
        if ctx.cancelled:
            return
        if time.monotonic() > deadline:
            notes.append(f"time budget of {budget:.0f} s reached, {len(profiles) - index} profile(s) not examined")
            break
        ctx.report("traces", f"reading the {profile.browser} history")
        try:
            rows = read_history_rows(profile, since)
        except HistoryReadError as exc:
            notes.append(f"{profile.browser} [{profile.label}]: {exc}")
            continue
        read += 1
        examined, hits = find_bad_sites(rows, sigs)
        rows_total += examined
        ctx.bump("traces_browser_rows", examined)
        for hit in sorted(hits.values(), key=lambda h: h.domain):
            if flagged >= MAX_SITE_FINDINGS:
                break
            flagged += 1
            yield site_finding(profile, hit)
    ctx.bump("traces_flagged", flagged)
    detail = (f"{read} of {len(profiles)} browser {_plural(len(profiles), 'profile', 'profiles')} read, {rows_total} "
              f"{_plural(rows_total, 'address', 'addresses')} visited in the last {BROWSER_DAYS} days checked: "
              + (f"{flagged} known-malicious {_plural(flagged, 'site', 'sites')}." if flagged else "none is on a threat feed."))
    if notes:
        detail += " " + "; ".join(notes) + "."
    yield CheckResult("AEG-TRACE-BROWSER", BROWSER_TITLE, _status(flagged), detail, Category.BROWSER)


# =========================================================================== scanner

_CHECKS: Tuple[Tuple[str, str, str, Callable[[ScanContext], Iterator[Emitted]], str], ...] = (
    ("AEG-TRACE-RUNMRU", RUN_TITLE, "reading the Run dialog history", check_run_history, Category.SUSPICIOUS),
    ("AEG-TRACE-PSHISTORY", PS_TITLE, "reading the PowerShell history", check_powershell_history, Category.SUSPICIOUS),
    ("AEG-TRACE-SHELLHISTORY", SHELL_TITLE, "reading the shell history", check_shell_history, Category.SUSPICIOUS),
    ("AEG-TRACE-DNS", DNS_TITLE, "checking the DNS cache", check_dns_cache, Category.NETWORK),
    ("AEG-TRACE-BROWSER", BROWSER_TITLE, "checking the browser history", check_browser_history, Category.BROWSER),
)


@register
class TracesScanner(Scanner):
    name = "traces"
    title = "Recent activity traces"
    description = ("Reads what was run and contacted: the Run dialog history (ClickFix fake-CAPTCHA commands), PowerShell and "
                   "shell command history, the Windows DNS cache and browser history, and reports download-and-run commands "
                   "and contacts with known-malicious domains.")
    platforms = ("windows", "linux", "darwin")

    def run(self, ctx: ScanContext) -> Iterator[Emitted]:
        for check_id, title, progress, check, category in _CHECKS:
            if ctx.cancelled:
                return
            ctx.report(self.name, progress)
            try:
                yield from check(ctx)
            except Exception as exc:  # one failing check must not stop the others
                log.warning("traces check %s failed: %s", check_id, type(exc).__name__, exc_info=True)
                yield CheckResult(check_id, title, CheckStatus.ERROR, f"{type(exc).__name__}: {exc}", category)
