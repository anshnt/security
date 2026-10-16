"""Application tampering and session theft.

Infostealers and browser hijackers rarely drop a new program: they modify software that is already trusted and
already running. This scanner looks for the traces that leaves behind:

* **Discord client injection** - token stealers (Blank Grabber, Pysilon, Luna and many more) persist by rewriting
  ``discord_desktop_core/index.js``, whose genuine content is the single line ``module.exports = require('./core.asar');``.
  A file with extra ``require`` lines for a known client mod (BetterDiscord, Vencord ...) is reported as INFO; any other
  change is HIGH, and CRITICAL when the added code carries stealer indicators (webhook URLs, token access, hooks on
  login/billing requests, outbound requests, ``eval``, base64 blobs). The fix restores the genuine line.
* **Electron / Node runtime abuse** (Windows) - a persistent ``ELECTRON_RUN_AS_NODE`` turns every Electron app into a plain
  Node.js interpreter that runs scripts under a signed binary's name, and ``NODE_OPTIONS`` with ``--require`` / ``--import`` /
  ``--loader`` / ``--inspect`` injects code into every Node and Electron process.
* **Browser shortcut hijacking** (Windows) - ``.lnk`` files on the desktop, Start Menu, taskbar and Quick Launch are parsed
  (``aegis.core.lnk``): browser shortcuts that load an extension, open a remote-debugging port, set a proxy or weaken web
  security, force a start page, or that are named like a browser but start something else.
* **Browsers running with cookie-theft switches** (all OSes) - ``browser_cmdline_risk`` classifies a browser command line:
  remote debugging on the user's real profile (HIGH when headless / hidden), and ``--load-extension`` from a user-writable
  folder. Separate automation profiles (Puppeteer, Playwright, Selenium) are not flagged.
* **Crypto-wallet app tampering** - the ``resources/app.asar`` of Exodus, Atomic Wallet and Ledger Live is searched for
  exfiltration endpoints no wallet ships (Discord webhooks, Telegram bot API), and flagged when it is much newer than the
  wallet's executable (a swapped asar).

Every decision is a pure function (classifiers, path discovery with injectable roots) unit-tested on any OS; each check
emits its own CheckResult and one failing check never stops the others.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple, Union

from aegis.core import cmdline as cl
from aegis.core.lnk import LnkInfo, read_lnk
from aegis.core.models import Category, CheckResult, CheckStatus, Finding, Remediation, Severity
from aegis.core.platform import IS_WINDOWS, OS_NAME, reg_values, user_home
from aegis.scanners.base import Emitted, ScanContext, Scanner, register

log = logging.getLogger("aegis.apptamper")

GENUINE_INDEX_JS = "module.exports = require('./core.asar');"
MAX_DISCORD_FILES = 40
MAX_DISCORD_READ = 2 * 1024 * 1024
MAX_STATEMENT_ANALYSIS = 16 * 1024  # genuine / mod-only files are tiny; anything larger is modified by definition
MAX_SHORTCUTS = 1500
MAX_SHORTCUT_DEPTH = 3
ASAR_MAX_BYTES = 400 * 1024 * 1024
ASAR_CHUNK = 4 * 1024 * 1024
ASAR_OVERLAP = 1024
ASAR_NEWER_DAYS = 3.0
EXCERPT_CHARS = 300
EXCERPT_SCAN = 20000  # only this much of a large file is collapsed and masked to build a 300 character excerpt

# =========================================================================== shared helpers

_MASKS: Tuple[Tuple["re.Pattern[str]", Union[str, Callable[["re.Match[str]"], str]]], ...] = (
    (re.compile(r"(?i)(discord(?:app)?\.com/api(?:/v\d+)?/webhooks/\d+/)[\w-]+"), r"\1***"),
    (re.compile(r"(?i)(api\.telegram\.org/bot)[\w:-]+"), r"\1***"),
    (re.compile(r"(?i)(hooks\.slack\.com/services/)[\w/]+"), r"\1***"),
    (re.compile(r"[\w-]{23,28}\.[\w-]{6,7}\.[\w-]{27,}"), "<token>"),
    (re.compile(r"(?i)(://)[^/\s:@]+:[^/\s@]+@"), r"\1***@"),
    (re.compile(r"[A-Za-z0-9+/]{120,}={0,2}"), lambda m: f"<base64 {len(m.group(0))} chars>"),
)


def mask_secrets(text: str) -> str:
    """Hide webhook / bot tokens, Discord tokens, credentials in URLs and long base64 blobs (before any truncation)."""
    for rx, repl in _MASKS:
        text = rx.sub(repl, text)
    return text


def _excerpt(text: str, limit: int = EXCERPT_CHARS) -> str:
    """Whitespace-collapsed, secret-masked start of ``text``, at most ``limit`` characters (masking happens first)."""
    text = mask_secrets(re.sub(r"\s+", " ", text[:EXCERPT_SCAN]).strip())
    return text if len(text) <= limit else text[:limit - 3] + "..."


def _quarantine(path: str, desc: str) -> Remediation:
    return Remediation("quarantine_file", {"path": path}, desc)


def _iso(ts: float) -> str:
    try:
        return dt.datetime.fromtimestamp(ts).isoformat(timespec="seconds")
    except (OverflowError, OSError, ValueError):
        return ""


def _norm_path(path: str) -> str:
    """Lower-case, forward-slash, quote- and trailing-slash-free form for comparisons on any OS."""
    return path.strip().strip("\"'").replace("\\", "/").lower().rstrip("/")


def _status(flagged: int) -> str:
    return CheckStatus.FAIL if flagged else CheckStatus.PASS


# =========================================================================== 2. Discord client injection

CLIENT_MODS = {"betterdiscord": "BetterDiscord", "replugged": "Replugged", "powercord": "Powercord", "vencord": "Vencord",
               "equicord": "Equicord", "shelter": "Shelter"}

_GENUINE_STMT = re.compile(r"""module\s*\.\s*exports\s*=\s*require\s*\(\s*(['"])\./core\.asar\1\s*\)\s*;?""")
_REQUIRE_STMT = re.compile(r"""require\s*\(\s*(?:"((?:[^"\\\n]|\\.)*)"|'((?:[^'\\\n]|\\.)*)')\s*\)\s*;?""")
_WEBHOOK_URL = re.compile(r"(?i)discord(?:app)?\.com/api(?:/v\d+)?/webhooks/\d+/[\w-]+")
_TELEGRAM_BOT = re.compile(r"(?i)api\.telegram\.org/bot")
_TOKEN_ACCESS = re.compile(
    r"""(?i)localStorage|\bgetToken\b|webpackChunkdiscord_app|\btokens?\b\s*[:=]|['"]tokens?['"]|\.tokens?\b""")
_REQUEST_HOOK = re.compile(r"(?i)webRequest|onBeforeRequest|onCompleted|onBeforeSendHeaders|webContents")
_SENSITIVE_ENDPOINT = re.compile(r"(?i)users/@me|/auth/login|/login\b|billing|payment[-_]sources|/mfa/")
_NET_CALL = re.compile(r"""(?i)\bhttps?\s*\.\s*(?:request|get)\s*\(|\bfetch\s*\(|XMLHttpRequest|\bnet\s*\.\s*request\s*\(|"""
                       r"""\brequire\s*\(\s*['"](?:node:)?https?['"]\s*\)|\baxios\b""")
_URL_HOST = re.compile(r"(?i)(?:https?|wss?)://([A-Za-z0-9.\-]+|\[[0-9a-f:]+\])")
_HOST_PROP = re.compile(r"""(?i)\bhost(?:name)?\s*:\s*['"]([A-Za-z0-9.\-]+)['"]""")
_EVAL_CALL = re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(")
_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{150,}={0,2}")
_OWN_HOSTS = ("discord.com", "discordapp.com", "discord.gg", "discordapp.net", "discord.media", "localhost", "127.0.0.1")


@dataclass
class DiscordVerdict:
    status: str  # "genuine" | "mod" | "tampered"
    severity: Severity = Severity.INFO
    mods: List[str] = field(default_factory=list)
    mod_paths: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    hosts: List[str] = field(default_factory=list)
    excerpt: str = ""


def _strip_js_comments(text: str) -> str:
    """Remove // and /* */ comments outside string literals (a small state machine; regex literals are not modelled)."""
    out: List[str] = []
    i, n, quote = 0, len(text), ""
    while i < n:
        ch = text[i]
        if quote:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == quote or (ch == "\n" and quote != "`"):
                quote = ""
        elif ch in "'\"`":
            quote = ch
            out.append(ch)
        elif ch == "/" and text.startswith("//", i):
            end = text.find("\n", i)
            if end < 0:
                break
            i = end
            continue
        elif ch == "/" and text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end < 0:
                break
            out.append(" ")
            i = end + 2
            continue
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def _external_hosts(text: str) -> List[str]:
    found = [m.group(1).lower() for m in _URL_HOST.finditer(text)] + [m.group(1).lower() for m in _HOST_PROP.finditer(text)]
    own = tuple(_OWN_HOSTS)
    return sorted({h for h in found if not any(h == o or h.endswith("." + o) for o in own)})[:8]


def discord_stealer_indicators(text: str) -> Tuple[List[str], List[str]]:
    """(human-readable indicators, external hosts contacted) found in modified Discord client code."""
    ind: List[str] = []
    if _WEBHOOK_URL.search(text):
        ind.append("hard-coded Discord webhook URL")
    if _TELEGRAM_BOT.search(text):
        ind.append("Telegram bot API URL")
    if _TOKEN_ACCESS.search(text):
        ind.append("reads tokens / localStorage")
    if _REQUEST_HOOK.search(text) and _SENSITIVE_ENDPOINT.search(text):
        ind.append("hooks web requests on login / billing / users/@me endpoints")
    hosts: List[str] = []
    if _NET_CALL.search(text):
        hosts = _external_hosts(text)
        if hosts:
            ind.append("sends data to an external server (" + ", ".join(hosts[:3]) + ")")
    if _EVAL_CALL.search(text):
        ind.append("eval() / new Function()")
    blob = _BASE64_BLOB.search(text)
    if blob:
        ind.append(f"long base64 blob ({len(blob.group(0))} characters)")
    return ind, hosts


def classify_discord_index(content: Union[str, bytes]) -> DiscordVerdict:
    """Classify the content of ``discord_desktop_core/index.js``.

    * ``genuine`` - exactly the ``module.exports = require('./core.asar');`` line (whitespace / quote style may vary);
    * ``mod`` - that line plus only ``require("<path>")`` lines whose path names a known client mod (INFO);
    * ``tampered`` - anything else: HIGH, CRITICAL when the code carries stealer indicators."""
    text = content.decode("utf-8", "replace") if isinstance(content, (bytes, bytearray)) else str(content)
    text = text.lstrip("\ufeff")
    if len(text) <= MAX_STATEMENT_ANALYSIS:
        code = _strip_js_comments(text)
        genuine = len(_GENUINE_STMT.findall(code))
        rest = _GENUINE_STMT.sub("", code)
        required: List[str] = []

        def take(m: "re.Match[str]") -> str:
            required.append(m.group(1) if m.group(1) is not None else m.group(2))
            return ""

        leftover = _REQUIRE_STMT.sub(take, rest).strip(" \t\r\n;")
        if genuine == 1 and not leftover:
            if not required:
                return DiscordVerdict("genuine")
            names = [CLIENT_MODS[k] for k in CLIENT_MODS if any(k in r.lower() for r in required)]
            if all(any(k in r.lower() for k in CLIENT_MODS) and not re.match(r"(?i)^(?:https?|ftp|data):", r.strip())
                   for r in required):
                return DiscordVerdict("mod", Severity.INFO, mods=names, mod_paths=[r[:200] for r in required[:5]])
    indicators, hosts = discord_stealer_indicators(text)
    return DiscordVerdict("tampered", Severity.CRITICAL if indicators else Severity.HIGH, indicators=indicators,
                          hosts=hosts, excerpt=_excerpt(_GENUINE_STMT.sub("", text)))


# (label, folder under %LOCALAPPDATA%) / (label, folder under the config root on macOS and Linux)
DISCORD_WINDOWS_CLIENTS = (("Discord", "Discord"), ("Discord PTB", "DiscordPTB"), ("Discord Canary", "DiscordCanary"),
                           ("Discord Development", "DiscordDevelopment"))
DISCORD_UNIX_CLIENTS = (("Discord", "discord"), ("Discord PTB", "discordptb"), ("Discord Canary", "discordcanary"))


def discord_index_files(platform: Optional[str] = None, home: Optional[Path] = None,
                        local_appdata: Optional[Path] = None) -> List[Tuple[str, Path]]:
    """``(client label, index.js path)`` for every installed Discord client (roots injectable for tests)."""
    platform = platform or OS_NAME
    home = home or user_home()
    roots: List[Tuple[str, Path, str]] = []  # (label, client folder, glob below it)
    if platform == "windows":
        base = local_appdata or Path(os.environ.get("LOCALAPPDATA") or (home / "AppData" / "Local"))
        for label, folder in DISCORD_WINDOWS_CLIENTS:
            roots.append((label, base / folder, "app-*/modules/discord_desktop_core-*/discord_desktop_core/index.js"))
    else:
        unix_glob = "*/modules/discord_desktop_core/index.js"
        if platform == "darwin":
            config = home / "Library" / "Application Support"
            for label, folder in DISCORD_UNIX_CLIENTS:
                roots.append((label, config / folder, unix_glob))
        else:
            config = home / ".config"
            for label, folder in DISCORD_UNIX_CLIENTS:
                roots.append((label, config / folder, unix_glob))
            roots.append(("Discord", home / ".var" / "app" / "com.discordapp.Discord" / "config" / "discord", unix_glob))
            roots.append(("Discord", home / "snap" / "discord" / "current" / ".config" / "discord", unix_glob))
    out: List[Tuple[str, Path]] = []
    seen = set()
    for label, folder, pattern in roots:
        try:
            if not folder.is_dir():
                continue
            for p in sorted(folder.glob(pattern)):
                key = os.path.normcase(str(p))
                if key not in seen and p.is_file():
                    seen.add(key)
                    out.append((label, p))
        except OSError:
            continue
    return out[:MAX_DISCORD_FILES]


def find_discord_files() -> List[Tuple[str, Path]]:
    return discord_index_files()


def _read_head(path: Path, limit: int) -> Optional[bytes]:
    """The first ``limit`` bytes of a file, or None when it cannot be read (an unreadable file is not a modified one)."""
    try:
        with open(path, "rb") as fh:
            return fh.read(limit)
    except OSError:
        return None


def discord_finding(client: str, path: Path, verdict: DiscordVerdict, data: bytes, size: int) -> Optional[Finding]:
    if verdict.status == "genuine":
        return None
    ev: Dict[str, Any] = {"client": client, "size": size, "sha256": hashlib.sha256(data).hexdigest() if len(data) == size else ""}
    if verdict.status == "mod":
        ev.update(mods=verdict.mods, required_paths=verdict.mod_paths)
        return Finding(
            rule_id="AEG-TAMPER-DISCORD-MOD", title="Discord client mod installed", severity=Severity.INFO,
            category=Category.SUSPICIOUS,
            description=f"{client} loads {', '.join(verdict.mods)} from {path}. Client mods are not malware, but they run "
                        "third-party code inside Discord with access to your account and session, and they are against "
                        "Discord's terms of service. Token stealers use the same file, so it is worth knowing it was changed.",
            location=str(path), evidence=ev,
            recommendation="No action is needed if you installed the mod yourself. If you do not recognise it, uninstall it "
                           "with the mod's installer (or reinstall Discord), change your Discord password and enable two-factor "
                           "authentication.", mitre=["T1554", "T1539"])
    ev.update(indicators=verdict.indicators, external_hosts=verdict.hosts, excerpt=verdict.excerpt)
    critical = verdict.severity >= Severity.CRITICAL
    return Finding(
        rule_id="AEG-TAMPER-DISCORD", title="Discord client code was modified (possible token-stealer injection)",
        severity=verdict.severity, category=Category.MALWARE if critical else Category.SUSPICIOUS,
        description=f"{path} is the entry point Discord loads every time it starts. Its genuine content is the single line "
                    "module.exports = require('./core.asar'); but it has been changed ("
                    + (f"{size} bytes" if size else "empty") + "). Information stealers such as Blank Grabber, Pysilon and Luna "
                    "rewrite this file so their code runs inside Discord on every launch and steals the login token, which "
                    "gives an attacker your account without the password or two-factor code, plus saved payment details."
                    + (" The added code contains stealer indicators: " + "; ".join(verdict.indicators) + "." if critical else ""),
        location=str(path), evidence=ev,
        recommendation="Quit Discord completely (also from the system tray), then restore the original file with the fix below. "
                       "Change your Discord password now - that invalidates every token that was stolen - and enable "
                       "two-factor authentication. Run a full Aegis scan: a stealer was running on this PC, so browser "
                       "passwords, sessions and crypto wallets may be exposed too.",
        remediation=Remediation("restore_file_content", {"path": str(path), "content": GENUINE_INDEX_JS},
                                "Rewrite index.js with its genuine one-line content (the current file is backed up; "
                                "`aegis undo` restores it)"),
        mitre=["T1554", "T1539"])


def check_discord(ctx: ScanContext) -> Iterator[Emitted]:
    title = "Discord client files are unmodified"
    files = find_discord_files()
    if not files:
        yield CheckResult("AEG-TAMPER-DISCORD", title, CheckStatus.SKIP, "Discord is not installed.", Category.SUSPICIOUS)
        return
    genuine = mods = bad = unreadable = 0
    for client, path in files:
        if ctx.cancelled:
            return
        ctx.bump("tamper_discord_files")
        try:
            size = path.stat().st_size
        except OSError:
            size = -1
        data = _read_head(path, MAX_DISCORD_READ) if size >= 0 else None
        if data is None:
            unreadable += 1
            continue
        verdict = classify_discord_index(data)
        finding = discord_finding(client, path, verdict, data, size)
        if verdict.status == "genuine":
            genuine += 1
        elif verdict.status == "mod":
            mods += 1
        else:
            bad += 1
        if finding:
            yield finding
    detail = f"{len(files)} Discord core file(s) checked: {genuine} genuine, {mods} with a client mod, {bad} modified"
    detail += f", {unreadable} could not be read." if unreadable else "."
    yield CheckResult("AEG-TAMPER-DISCORD", title, _status(bad), detail, Category.SUSPICIOUS)


# =========================================================================== 3. Electron / Node environment abuse

ENV_SCOPES = (("user", "HKCU", "Environment"),
              ("machine", "HKLM", r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"))
_NODE_INJECT_FLAGS = {"-r": "--require", "--require": "--require", "--import": "--import", "--loader": "--loader",
                      "--experimental-loader": "--experimental-loader", "--inspect": "--inspect",
                      "--inspect-brk": "--inspect", "--inspect-wait": "--inspect"}
_NODE_FLAGS_WITH_VALUE = {"--require", "--import", "--loader", "--experimental-loader"}


@dataclass
class EnvIssue:
    rule_id: str
    name: str  # the variable as stored in the registry
    value: str
    flags: List[str] = field(default_factory=list)


def node_options_flags(value: str) -> List[str]:
    """Code-injecting options in a NODE_OPTIONS string, as written (``--require C:\\x\\evil.js``)."""
    tokens = cl.split_command_line(value)
    found: List[str] = []
    i = 0
    while i < len(tokens):
        name, sep, val = tokens[i].partition("=")
        canon = _NODE_INJECT_FLAGS.get(name.lower())
        if canon:
            arg = val
            if not sep and canon in _NODE_FLAGS_WITH_VALUE and i + 1 < len(tokens):
                arg = tokens[i + 1]
                i += 1
            found.append(f"{name} {arg}".strip())
        i += 1
    return found


def classify_node_environment(values: Mapping[str, Any]) -> List[EnvIssue]:
    """Abuse of ELECTRON_RUN_AS_NODE / NODE_OPTIONS in a ``{name: value}`` environment (names are case-insensitive)."""
    issues: List[EnvIssue] = []
    for name, raw in values.items():
        text = "" if raw is None else str(raw)
        key = str(name).upper()
        if key == "ELECTRON_RUN_AS_NODE" and text.strip():
            issues.append(EnvIssue("AEG-TAMPER-ELECTRON-NODE", str(name), text.strip()))
        elif key == "NODE_OPTIONS":
            flags = node_options_flags(text)
            if flags:
                issues.append(EnvIssue("AEG-TAMPER-NODE-OPTIONS", str(name), text.strip(), flags))
    return issues


def env_findings(scope: str, hive: str, key: str, values: Mapping[str, Any]) -> List[Finding]:
    out: List[Finding] = []
    for issue in classify_node_environment(values):
        where = f"{hive}\\{key}\\{issue.name}"
        fix = Remediation("delete_registry_value", {"hive": hive, "key": key, "value": issue.name, "view64": True},
                          f"Delete the {scope} environment variable {issue.name} ({where}); sign out and back in afterwards")
        if issue.rule_id == "AEG-TAMPER-ELECTRON-NODE":
            out.append(Finding(
                rule_id=issue.rule_id, title=f"ELECTRON_RUN_AS_NODE is set permanently in the {scope} environment",
                severity=Severity.HIGH, category=Category.PERSISTENCE,
                description=f"The {scope} environment variable ELECTRON_RUN_AS_NODE is set to '{issue.value[:40]}' in {where}. "
                            "With it, every Electron application (Teams, Slack, VS Code, Discord ...) starts as a plain "
                            "Node.js interpreter instead of its normal window, so a script given on the command line runs "
                            "under the name of a signed, trusted program. Attackers use this to proxy-execute malicious "
                            "scripts through legitimate binaries and slip past allow-lists. It is meant to be set for a "
                            "single command, never permanently.",
                location=where, evidence={"scope": scope, "variable": issue.name, "value": issue.value[:200]},
                recommendation="Delete the variable (Aegis can do it) and sign out and back in so running programs pick up the "
                               "change. If you did not set it yourself, find what created it: review startup entries and "
                               "scheduled tasks and run a full scan.",
                remediation=fix, mitre=["T1218.015"]))
        else:
            out.append(Finding(
                rule_id=issue.rule_id, title=f"NODE_OPTIONS injects code into every Node.js and Electron process ({scope})",
                severity=Severity.HIGH, category=Category.PERSISTENCE,
                description=f"The {scope} environment variable NODE_OPTIONS in {where} contains {', '.join(issue.flags[:4])}. "
                            "Node.js reads this variable at start-up, so the named module (or inspector) is loaded into every "
                            "Node.js and Electron process on the PC - VS Code, Teams, Slack, Discord and any developer tool. "
                            "Malware uses it to run code inside trusted applications and to read their data.",
                location=where,
                evidence={"scope": scope, "variable": issue.name, "value": issue.value[:300], "flags": issue.flags[:8]},
                recommendation="If you did not configure this yourself, delete the variable (Aegis can do it), sign out and back "
                               "in, then check the file it loads and run a full scan. Developers who set it on purpose should "
                               "pass it to a single command instead of storing it permanently.",
                remediation=fix, mitre=["T1574"]))
    return out


def read_environment_values() -> Dict[str, Dict[str, Any]]:
    return {scope: reg_values(hive, key) for scope, hive, key in ENV_SCOPES}


def check_environment(ctx: ScanContext) -> Iterator[Emitted]:
    title = "Electron / Node.js environment variables are not abused"
    if not IS_WINDOWS:
        yield CheckResult("AEG-TAMPER-ENV", title, CheckStatus.SKIP,
                          "The persistent Windows environment (registry) does not apply on this OS.", Category.PERSISTENCE)
        return
    env = read_environment_values()
    flagged = 0
    for scope, hive, key in ENV_SCOPES:
        values = env.get(scope) or {}
        ctx.bump("tamper_env_values", len(values))
        for f in env_findings(scope, hive, key, values):
            flagged += 1
            yield f
    yield CheckResult("AEG-TAMPER-ENV", title, _status(flagged),
                      f"{flagged} abusive variable(s) found." if flagged else
                      "Neither ELECTRON_RUN_AS_NODE nor a code-injecting NODE_OPTIONS is set.", Category.PERSISTENCE)


# =========================================================================== browser knowledge shared by 4 and 5

# lower-case process / executable names (without ".exe") -> browser
BROWSER_NAMES = {
    "chrome": "Chrome", "google chrome": "Chrome", "google-chrome": "Chrome", "google-chrome-stable": "Chrome",
    "google-chrome-beta": "Chrome", "google-chrome-unstable": "Chrome", "chrome_proxy": "Chrome",
    "msedge": "Edge", "microsoft edge": "Edge", "microsoft-edge": "Edge", "microsoft-edge-stable": "Edge",
    "microsoft-edge-beta": "Edge", "microsoft-edge-dev": "Edge", "msedge_proxy": "Edge",
    "firefox": "Firefox", "firefox-bin": "Firefox", "firefox-esr": "Firefox",
    "brave": "Brave", "brave-browser": "Brave", "brave-browser-stable": "Brave", "brave browser": "Brave",
    "vivaldi": "Vivaldi", "vivaldi-bin": "Vivaldi", "vivaldi-stable": "Vivaldi",
    "opera": "Opera", "iexplore": "Internet Explorer",
    "chromium": "Chromium", "chromium-browser": "Chromium",
}
_PATH_QUALIFIED = {"launcher": ("opera", "Opera"), "browser": ("yandex", "Yandex Browser")}


def browser_of_name(name: str, path: str = "") -> Optional[str]:
    """Browser a program name belongs to (``launcher`` only inside an Opera folder, ``browser`` only inside a Yandex one)."""
    base = cl.basename(name or "").lower()
    if base.endswith(".exe"):
        base = base[:-4]
    if base in BROWSER_NAMES:
        return BROWSER_NAMES[base]
    need = _PATH_QUALIFIED.get(base)
    if need and need[0] in (path or name or "").lower():
        return need[1]
    return None


def _argv(cmdline: Union[str, Sequence[str], None]) -> List[str]:
    if cmdline is None:
        return []
    if isinstance(cmdline, str):
        return cl.split_command_line(cmdline)
    return [str(t) for t in cmdline]


def _switch(token: str) -> Tuple[str, str]:
    """``('load-extension', 'C:\\x')`` for ``--load-extension=C:\\x``; ``('', token)`` for a plain argument. Chromium accepts
    ``--x``, ``-x`` and (on Windows) ``/x``; the name is returned lower-case without the prefix."""
    if not token or token[0] not in "-/":
        return "", token
    name, _, value = token.partition("=")
    return name.lstrip("-/").lower(), value


def _switch_value(tokens: Sequence[str], i: int) -> str:
    """Value of the switch at ``tokens[i]``: after ``=``, or the next token (``--user-data-dir C:\\x``)."""
    value = _switch(tokens[i])[1]
    if value or "=" in tokens[i]:
        return value
    if i + 1 < len(tokens) and tokens[i + 1] and not tokens[i + 1].startswith("-"):
        return tokens[i + 1]
    return ""


# =========================================================================== 4. Browser shortcut hijacking

LNK_RULES = {
    "load_extension": ("AEG-TAMPER-LNK-EXTENSION", Severity.HIGH, ["T1547.009", "T1176.001"]),
    "remote_debugging": ("AEG-TAMPER-LNK-DEBUG", Severity.HIGH, ["T1547.009", "T1539"]),
    "traffic": ("AEG-TAMPER-LNK-TRAFFIC", Severity.HIGH, ["T1547.009", "T1557"]),
    "masquerade": ("AEG-TAMPER-LNK-MASQUERADE", Severity.HIGH, ["T1547.009", "T1036"]),
    "start_page": ("AEG-TAMPER-LNK-STARTPAGE", Severity.MEDIUM, ["T1547.009"]),
}
_RULE_ORDER = ("load_extension", "remote_debugging", "traffic", "masquerade", "start_page")
_TRAFFIC_SWITCHES = {"proxy-server", "proxy-pac-url", "host-resolver-rules", "disable-web-security", "ignore-certificate-errors"}
_SWITCHES_TAKING_VALUE = {"p", "profile", "profile-directory"}  # Firefox "-P <name>", "-profile <dir>"
_URL_ARG = re.compile(r"(?i)^(?:https?|ftp)://\S+$")
_DOMAIN_ARG = re.compile(r"(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24})(?::\d{1,5})?(?:[/?#]\S*)?$")
_FILE_EXTENSIONS = frozenset(
    "exe lnk bat cmd scr dll msi ps1 vbs vbe js jse wsf hta jar txt log ini cfg conf json xml yml yaml csv html htm xhtml "
    "mht mhtml url pdf doc docx xls xlsx ppt pptx rtf md png jpg jpeg gif bmp ico svg webp zip rar 7z tar gz bz2 iso img crx xpi "
    "pak dat db sqlite default".split())
_MASQUERADE_NAMES: Tuple[Tuple["re.Pattern[str]", str, Tuple[str, ...]], ...] = (
    (re.compile(r"(?i)^(?:google )?chrome(?: (?:beta|dev|canary))?$"), "Chrome", ("chrome.exe", "chrome_proxy.exe")),
    (re.compile(r"(?i)^(?:microsoft )?edge(?: (?:beta|dev|canary))?$"), "Edge", ("msedge.exe", "msedge_proxy.exe")),
    (re.compile(r"(?i)^(?:mozilla )?firefox(?: (?:esr|nightly|beta|developer edition))?$"), "Firefox", ("firefox.exe",)),
    (re.compile(r"(?i)^brave(?: browser)?(?: (?:beta|nightly))?$"), "Brave", ("brave.exe",)),
    (re.compile(r"(?i)^opera(?: (?:gx|air|one|neon|beta|developer|stable|crypto|browser))*$"), "Opera",
     ("opera.exe", "launcher.exe")),
    (re.compile(r"(?i)^vivaldi$"), "Vivaldi", ("vivaldi.exe",)),
    (re.compile(r"(?i)^chromium$"), "Chromium", ("chromium.exe", "chrome.exe")),
    (re.compile(r"(?i)^internet explorer$"), "Internet Explorer", ("iexplore.exe",)),
    (re.compile(r"(?i)^yandex(?: browser)?$"), "Yandex Browser", ("browser.exe",)),
)


@dataclass
class ShortcutIssue:
    kind: str  # key of LNK_RULES
    detail: str  # the offending switch / address / target
    switches: List[str] = field(default_factory=list)

    @property
    def rule_id(self) -> str:
        return LNK_RULES[self.kind][0]

    @property
    def severity(self) -> Severity:
        return LNK_RULES[self.kind][1]

    @property
    def mitre(self) -> List[str]:
        return list(LNK_RULES[self.kind][2])


def classify_browser_args(arguments: str) -> List[ShortcutIssue]:
    """Risky parts of a browser shortcut's argument string. Harmless switches (``--profile-directory``, ``--app-id``,
    ``--app=<url>``, ``--new-window``, private-window flags, Firefox ``-P`` ...) are ignored."""
    tokens = cl.split_command_line(arguments or "")
    ext: List[str] = []
    debug: List[str] = []
    traffic: List[str] = []
    pages: List[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        name, _value = _switch(tok)
        if name:
            if name == "load-extension":
                ext.append(tok)
            elif name in ("remote-debugging-port", "remote-debugging-pipe"):
                debug.append(tok)
            elif name in _TRAFFIC_SWITCHES or name.startswith("ignore-certificate-errors-"):
                traffic.append(tok)
            elif name in _SWITCHES_TAKING_VALUE and "=" not in tok:
                i += 1  # "-P <profile>": the next token is a profile name, not an address
        elif _URL_ARG.match(tok) or _is_bare_domain(tok):
            pages.append(tok)
        i += 1
    issues: List[ShortcutIssue] = []
    if ext:
        issues.append(ShortcutIssue("load_extension", ext[0], ext))
    if debug:
        issues.append(ShortcutIssue("remote_debugging", debug[0], debug))
    if traffic:
        issues.append(ShortcutIssue("traffic", traffic[0], traffic))
    if pages:
        issues.append(ShortcutIssue("start_page", pages[0], pages))
    return issues


def _is_bare_domain(token: str) -> bool:
    m = _DOMAIN_ARG.match(token)
    return bool(m) and m.group(1).lower() not in _FILE_EXTENSIONS and "\\" not in token


def browser_of_target(target: str) -> Optional[str]:
    """Browser a shortcut target (an executable path) starts, by base name."""
    return browser_of_name(cl.basename(target), target) if target else None


def _lnk_stem(file_name: str) -> str:
    stem = file_name[:-4] if file_name.lower().endswith(".lnk") else file_name
    stem = re.sub(r"(?i)\s*-\s*shortcut$", "", stem.strip())
    return re.sub(r"\s*\(\d+\)$", "", stem).strip()


def masquerade_issue(file_name: str, target: str) -> Optional[ShortcutIssue]:
    """A shortcut named like a browser (``Google Chrome.lnk``) whose resolved target is not that browser's executable."""
    target = (target or "").strip()
    if not target or target.lower().startswith(("shell:", "::{")):
        return None  # unresolved or a shell object: no evidence either way
    stem = _lnk_stem(file_name)
    base = cl.basename(target).lower()
    for rx, browser, exes in _MASQUERADE_NAMES:
        if not rx.match(stem):
            continue
        if base in exes and (base != "launcher.exe" or "opera" in target.lower()) and \
                (base != "browser.exe" or "yandex" in target.lower()):
            return None
        return ShortcutIssue("masquerade", target, [base])
    return None


def classify_shortcut(file_name: str, info: LnkInfo) -> List[ShortcutIssue]:
    """All issues of one parsed shortcut, most serious first (see ``LNK_RULES``)."""
    target = cl.expand_env(info.target_path or "")
    issues: List[ShortcutIssue] = []
    if browser_of_target(target):
        issues.extend(classify_browser_args(info.arguments))
    masq = masquerade_issue(file_name, target)
    if masq:
        issues.append(masq)
    issues.sort(key=lambda i: _RULE_ORDER.index(i.kind))
    return issues


def shortcut_locations(env: Optional[Mapping[str, str]] = None, home: Optional[Path] = None) -> List[Tuple[Path, int]]:
    """``(folder, max depth)`` of every place browser shortcuts live: desktops, Start Menu, taskbar pins, Quick Launch."""
    env = os.environ if env is None else env
    home = home or user_home()
    appdata = Path(env.get("APPDATA") or (home / "AppData" / "Roaming"))
    program_data = Path(env.get("ProgramData") or r"C:\ProgramData")
    public = Path(env.get("PUBLIC") or r"C:\Users\Public")
    quick = appdata / "Microsoft" / "Internet Explorer" / "Quick Launch"
    cands: List[Tuple[Path, int]] = [(home / "Desktop", 0)]
    for var in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial"):
        if env.get(var):
            cands.append((Path(env[var]) / "Desktop", 0))
    cands += [(public / "Desktop", 0),
              (appdata / "Microsoft" / "Windows" / "Start Menu" / "Programs", MAX_SHORTCUT_DEPTH),
              (program_data / "Microsoft" / "Windows" / "Start Menu" / "Programs", MAX_SHORTCUT_DEPTH),
              (quick, 0), (quick / "User Pinned" / "TaskBar", 0), (quick / "User Pinned" / "StartMenu", 0)]
    out: List[Tuple[Path, int]] = []
    seen = set()
    for p, depth in cands:
        key = os.path.normcase(str(p))
        if key not in seen:
            seen.add(key)
            out.append((p, depth))
    return out


def collect_shortcut_files(locations: Sequence[Tuple[Path, int]], limit: int = MAX_SHORTCUTS) -> List[Path]:
    """The ``.lnk`` files in ``locations`` (never following links; at most ``limit`` files)."""
    found: List[Path] = []

    def walk(directory: str, depth: int) -> None:
        try:
            with os.scandir(directory) as it:
                entries = sorted(it, key=lambda e: e.name.lower())
        except OSError:
            return
        for e in entries:
            if len(found) >= limit:
                return
            try:
                if e.is_file(follow_symlinks=False) and e.name.lower().endswith(".lnk"):
                    found.append(Path(e.path))
                elif depth > 0 and e.is_dir(follow_symlinks=False):
                    walk(e.path, depth - 1)
            except OSError:
                continue

    for folder, depth in locations:
        walk(str(folder), depth)
    return found


def find_shortcut_files() -> List[Path]:
    return collect_shortcut_files(shortcut_locations())


_LNK_WHY = {
    "load_extension": ("Browser shortcut force-loads an extension",
                       "The shortcut starts {browser} with {detail}, which makes the browser load an unpacked extension from "
                       "disk every time it is started this way - without the Web Store's vetting or the usual consent "
                       "prompts. Browser hijackers (ChromeLoader and others) use it to inject ads, redirect searches and "
                       "steal data."),
    "remote_debugging": ("Browser shortcut opens a remote-debugging channel",
                         "The shortcut starts {browser} with {detail}. That opens a control channel that any program on the PC "
                         "can use to read every cookie and logged-in session of the profile, which bypasses Chrome's "
                         "app-bound cookie encryption; stealers rewrite shortcuts this way to harvest sessions."),
    "traffic": ("Browser shortcut reroutes traffic or weakens browser security",
                "The shortcut starts {browser} with {detail}. That sends the browser's traffic through a proxy, PAC script or "
                "DNS override chosen by the shortcut, or switches off certificate / web-security protection, which allows "
                "interception of everything you do in the browser."),
    "start_page": ("Browser shortcut opens a forced start page",
                   "The shortcut starts {browser} with the address {detail}, so every launch through it opens that page. "
                   "Hijackers and adware set this to monetise traffic or lure you to phishing pages."),
    "masquerade": ("Shortcut disguised as a browser",
                   "The shortcut is named like a web browser but its target is {detail}, not the browser. Malware replaces "
                   "browser shortcuts so that clicking the familiar icon starts the malware (often followed by opening the "
                   "real browser so nothing looks wrong)."),
}


def shortcut_finding(path: Path, info: LnkInfo, issues: Sequence[ShortcutIssue]) -> Finding:
    top = issues[0]
    target = cl.expand_env(info.target_path or "")
    browser = browser_of_target(target) or "the browser"
    title_base, why = _LNK_WHY[top.kind]
    detail = mask_secrets(top.detail) if top.kind != "masquerade" else (cl.basename(top.detail) or top.detail)
    extra = list(issues[1:])
    description = f"{path}: " + why.format(browser=browser, detail=detail[:200])
    if extra:
        description += " It also has: " + "; ".join(_LNK_WHY[i.kind][0].lower() for i in extra) + "."
    mitre = list(dict.fromkeys(m for i in issues for m in i.mitre))
    return Finding(
        rule_id=top.rule_id, title=f"{title_base}: {path.name}", severity=max(i.severity for i in issues),
        category=Category.BROWSER, description=description, location=str(path),
        evidence={"shortcut": path.name, "target": target, "arguments": mask_secrets(info.arguments)[:500],
                  "working_dir": info.working_dir, "icon": info.icon_location, "browser": browser_of_target(target) or "",
                  "issues": [{"kind": i.kind, "detail": mask_secrets(i.detail)[:200], "severity": i.severity.name.lower()}
                             for i in issues]},
        recommendation="Quarantine the shortcut (Aegis can do it; it stays restorable from quarantine), then re-pin or re-create "
                       "the browser shortcut from the browser's own install folder or the Start Menu. Check installed programs "
                       "and startup entries for whatever changed it, and run a full scan.",
        remediation=_quarantine(str(path), "Move the shortcut to quarantine (restorable); re-pin the browser afterwards"),
        mitre=mitre)


def check_shortcuts(ctx: ScanContext) -> Iterator[Emitted]:
    title = "Browser shortcuts are not hijacked"
    if not IS_WINDOWS:
        yield CheckResult("AEG-TAMPER-SHORTCUTS", title, CheckStatus.SKIP,
                          "Windows desktop / Start Menu shortcuts do not apply on this OS.", Category.BROWSER)
        return
    files = find_shortcut_files()
    parsed = flagged = 0
    for path in files:
        if ctx.cancelled:
            return
        info = read_lnk(str(path))
        if info is None:
            continue
        parsed += 1
        issues = classify_shortcut(path.name, info)
        if issues:
            flagged += 1
            yield shortcut_finding(path, info, issues)
    ctx.bump("tamper_shortcuts", parsed)
    yield CheckResult("AEG-TAMPER-SHORTCUTS", title, _status(flagged),
                      f"{parsed} shortcut(s) read ({len(files)} found): {flagged} suspicious." if files else
                      "No shortcuts found in the desktop, Start Menu, taskbar or Quick Launch folders.", Category.BROWSER)


# =========================================================================== 5. Browsers running with cookie-theft switches

# the browser's own user-data folders (matched as path suffixes, lower-case, forward slashes)
DEFAULT_PROFILE_DIRS = (
    # Windows (under %LOCALAPPDATA% / %APPDATA%)
    "/google/chrome/user data", "/google/chrome beta/user data", "/google/chrome dev/user data", "/google/chrome sxs/user data",
    "/microsoft/edge/user data", "/microsoft/edge beta/user data", "/microsoft/edge dev/user data",
    "/microsoft/edge sxs/user data", "/bravesoftware/brave-browser/user data", "/bravesoftware/brave-browser-beta/user data",
    "/vivaldi/user data", "/chromium/user data", "/yandex/yandexbrowser/user data", "/opera software/opera stable",
    "/opera software/opera gx stable", "/opera software/opera next", "/opera software/opera developer",
    # Linux
    "/.config/google-chrome", "/.config/google-chrome-beta", "/.config/google-chrome-unstable", "/.config/chromium",
    "/.config/microsoft-edge", "/.config/microsoft-edge-beta", "/.config/microsoft-edge-dev",
    "/.config/bravesoftware/brave-browser", "/.config/vivaldi", "/.config/opera", "/.config/yandex-browser",
    "/snap/chromium/common/chromium",
    # macOS
    "/library/application support/google/chrome", "/library/application support/google/chrome beta",
    "/library/application support/microsoft edge", "/library/application support/bravesoftware/brave-browser",
    "/library/application support/vivaldi", "/library/application support/chromium",
    "/library/application support/com.operasoftware.opera", "/library/application support/yandex/yandexbrowser",
)
_FIREFOX_PROFILE_ROOT = re.compile(r"/(?:mozilla/firefox/profiles|\.mozilla/firefox|application support/firefox/profiles)(?:/|$)")
# profile folders named by test-automation tools (Puppeteer, Playwright, chromedriver, geckodriver, Lighthouse ...)
_AUTOMATION_PROFILE = re.compile(
    r"(?:puppeteer|playwright)[\w-]*profile|scoped_dir|selenium|webdriver|chromedriver|/karma-|/cypress|testcafe|/wdio|"
    r"rust_mozprofile|/lighthouse\.|chrome-launcher|/\.org\.chromium\.")
_TEMP_DIR = re.compile(r"/(?:tmp|temp|var/tmp|dev/shm|var/folders)(?:/|$)|/appdata/local/temp(?:/|$)")
_DROP_LOCATION = re.compile(
    r"/(?:appdata|temp|tmp|downloads|programdata|users/public|var/folders|dev/shm)/"
    r"|%(?:temp|tmp|appdata|localappdata|programdata)%")


def is_default_profile_dir(path: str) -> bool:
    """True when ``path`` is a browser's own default user-data / profile folder (or a profile inside it)."""
    p = _norm_path(path)
    p = re.sub(r"/(?:default|profile \d+)$", "", p)
    return any(p.endswith(s) for s in DEFAULT_PROFILE_DIRS) or bool(_FIREFOX_PROFILE_ROOT.search(p + "/"))


def browser_profile(tokens: Sequence[str]) -> Tuple[str, str]:
    """``(kind, user_data_dir)`` of the profile a browser command line uses. ``kind`` is ``default`` (no ``--user-data-dir`` /
    ``-profile``, or the browser's own folder), ``automation`` (a folder named by Puppeteer / Playwright / Selenium /
    Lighthouse ...), ``temp`` (any other folder under a temp directory) or ``custom`` (any other separate folder)."""
    udd = ""
    for i, tok in enumerate(tokens):
        name, _ = _switch(tok)
        if name in ("user-data-dir", "profile"):
            udd = _switch_value(tokens, i)
            if udd:
                break
    if not udd:
        return "default", ""
    if is_default_profile_dir(udd):
        return "default", udd
    norm = _norm_path(udd) + "/"
    if _AUTOMATION_PROFILE.search(norm):
        return "automation", udd
    if _TEMP_DIR.search(norm):
        return "temp", udd
    return "custom", udd


def _stealth_markers(tokens: Sequence[str]) -> List[str]:
    """Signs that the browser was started so the user does not see it: headless, an off-screen window, silent launch."""
    out: List[str] = []
    for tok in tokens:
        name, value = _switch(tok)
        if name == "headless" and value.lower() not in ("false", "0", "no"):
            out.append("headless")
        elif name == "silent-launch":
            out.append("silent-launch")
        elif name == "window-position":
            m = re.match(r"^\s*(-?\d+)\s*,\s*(-?\d+)\s*$", value)
            if m:
                x, y = int(m.group(1)), int(m.group(2))
                # a monitor to the left of / above the main one gives one negative value; both negative and far away,
                # or an extreme value (the -32000 convention), is a window parked out of sight
                if min(x, y) <= -10000 or (x < 0 and y < 0 and min(x, y) <= -1000):
                    out.append(f"off-screen window position ({x},{y})")
    return list(dict.fromkeys(out))


def _in_drop_location(path: str) -> bool:
    return bool(_DROP_LOCATION.search("/" + _norm_path(path).lstrip("/") + "/"))


@dataclass
class BrowserRisk:
    rule_id: str
    severity: Severity
    title: str
    reason: str
    browser: str
    profile: str  # "default" | "automation" | "temp" | "custom"
    user_data_dir: str = ""
    switches: List[str] = field(default_factory=list)
    stealth: List[str] = field(default_factory=list)
    mitre: List[str] = field(default_factory=list)


def browser_main_process(name: str, cmdline: Union[str, Sequence[str], None], exe: str = "") -> Optional[str]:
    """The browser a process is, or None. Child processes (renderer, GPU, utility: ``--type=`` / ``-contentproc``) are not
    the browser itself and return None."""
    argv = _argv(cmdline)
    browser = browser_of_name(name, exe or (argv[0] if argv else ""))
    if not browser:
        return None
    for tok in argv:
        low = tok.lower()
        if low.startswith("--type=") or low in ("-contentproc", "--contentproc"):
            return None
    return browser


def browser_cmdline_risk(name: str, cmdline: Union[str, Sequence[str], None], exe: str = "") -> Optional[BrowserRisk]:
    """Classify a running browser's command line (pure; reused by the real-time process guard).

    * remote debugging (``--remote-debugging-port`` / ``-pipe``) on the user's REAL profile is HIGH when the browser is also
      hidden (headless, off-screen window, ``--silent-launch``) and MEDIUM otherwise - cookie theft that bypasses Chrome's
      app-bound encryption.
    * hidden remote debugging on an unnamed profile in a temp folder is MEDIUM: since Chrome 136 refuses remote debugging on
      the default profile, stealers copy the profile into Temp and start the copy headless. Profiles named by automation
      tools and any other ``--user-data-dir`` are test automation and return None.
    * ``--load-extension=`` from a Temp / AppData / Downloads / ProgramData folder is HIGH unless the browser uses a separate
      automation profile (then MEDIUM); from anywhere else MEDIUM.

    Returns None for non-browsers, browser child processes and harmless command lines."""
    browser = browser_main_process(name, cmdline, exe)
    if not browser:
        return None
    tokens = _argv(cmdline)
    kind, udd = browser_profile(tokens)
    debug = [t for t in tokens if _switch(t)[0] in ("remote-debugging-port", "remote-debugging-pipe")]
    ext = [(t, _switch_value(tokens, i)) for i, t in enumerate(tokens) if _switch(t)[0] == "load-extension"]
    candidates: List[BrowserRisk] = []
    if debug and kind == "temp":
        stealth = _stealth_markers(tokens)
        if stealth:
            candidates.append(BrowserRisk(
                "AEG-TAMPER-BROWSER-DEBUG", Severity.MEDIUM,
                "Hidden browser with remote debugging on a profile in a temporary folder",
                f"{browser} was started hidden ({', '.join(stealth)}) with {debug[0]} on a profile in a temporary folder "
                f"({udd}). Since Chrome 136 blocks remote debugging on the normal profile, information stealers copy the "
                "profile (with its cookies and sessions) into a temp folder and start the copy this way to read every "
                "cookie. Test tools do the same with an empty profile, but they normally name the folder after themselves "
                "(Puppeteer, Playwright, chromedriver ...); this one has no such name.",
                browser, kind, udd, debug, stealth, ["T1539", "T1185"]))
    if debug and kind == "default":
        stealth = _stealth_markers(tokens)
        if stealth:
            how = "headless" if "headless" in stealth else "with a hidden window"
            title = ("Browser started headless with remote debugging on your real profile (cookie theft)" if how == "headless"
                     else "Browser started with a hidden window and remote debugging on your real profile (cookie theft)")
            reason = (f"{browser} was started {how} ({', '.join(stealth)}) with {debug[0]} on your normal profile. A "
                      "remote-debugging port lets any program on this PC read every cookie and logged-in session of the "
                      "profile and drive the browser - information stealers start the browser hidden this way to take over "
                      "accounts without a password or two-factor code, bypassing Chrome's app-bound cookie encryption. "
                      "Legitimate test tools use a separate temporary profile instead.")
            sev = Severity.HIGH
        else:
            title = "Browser running with remote debugging on your real profile"
            reason = (f"{browser} is running with {debug[0]} on your normal profile. Any program on this PC can use the "
                      "remote-debugging port to read every cookie and logged-in session of the profile. Developers sometimes "
                      "do this on purpose, but legitimate test tools use a separate --user-data-dir.")
            sev = Severity.MEDIUM
        candidates.append(BrowserRisk("AEG-TAMPER-BROWSER-DEBUG", sev, title, reason, browser, kind, udd, debug, stealth,
                                      ["T1539", "T1185"]))
    if ext:
        risky = any(_in_drop_location(p) for _t, v in ext for p in v.split(",") if p)
        high = risky and kind not in ("automation", "temp")
        where = "a temporary or user-writable folder" if risky else "a folder on disk"
        reason = (f"{browser} was started with {ext[0][0]}, which loads an unpacked extension from {where} without the Web "
                  "Store's vetting or the usual consent prompts. Hijackers and stealers launch the browser this way to inject "
                  "code into every page you visit."
                  + (" It uses a separate temporary profile, so this may be a test run." if kind in ("automation", "temp")
                     else ""))
        title = ("Browser launched with an extension loaded from a user-writable folder" if high
                 else "Browser launched with an unpacked extension (--load-extension)")
        candidates.append(BrowserRisk("AEG-TAMPER-BROWSER-EXT", Severity.HIGH if high else Severity.MEDIUM, title, reason,
                                      browser, kind, udd, [t for t, _v in ext], [], ["T1176.001"]))
    if not candidates:
        return None
    candidates.sort(key=lambda r: -int(r.severity))  # stable: debugging first on a tie
    best = candidates[0]
    best.switches = list(dict.fromkeys(s for c in candidates for s in c.switches))
    return best


@dataclass
class BrowserProc:
    pid: int
    name: str
    exe: str = ""
    argv: List[str] = field(default_factory=list)
    username: str = ""
    create_time: float = 0.0


def collect_browser_processes() -> List[BrowserProc]:
    """Running browser main processes (psutil; tolerates AccessDenied / NoSuchProcess / zombies)."""
    import psutil

    out: List[BrowserProc] = []
    for p in psutil.process_iter(["pid", "name", "exe", "cmdline", "username", "create_time"]):
        try:
            i = p.info
            name = i.get("name") or ""
            argv = [str(a) for a in (i.get("cmdline") or [])]
            exe = i.get("exe") or ""
            if browser_main_process(name, argv, exe):
                out.append(BrowserProc(i["pid"], name, exe, argv, i.get("username") or "", i.get("create_time") or 0.0))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception as exc:  # pragma: no cover - defensive
            log.debug("browser process enumeration error: %s", exc)
    return out


def browser_process_finding(proc: BrowserProc, risk: BrowserRisk) -> Finding:
    label = f"{proc.exe or proc.name} (pid {proc.pid})"
    cmd = mask_secrets(" ".join(proc.argv))
    ev: Dict[str, Any] = {"pid": proc.pid, "name": proc.name, "exe": proc.exe, "cmdline": cmd[:1000], "user": proc.username,
                          "browser": risk.browser, "profile": risk.profile, "user_data_dir": risk.user_data_dir,
                          "switches": [mask_secrets(s) for s in risk.switches], "hidden_by": risk.stealth}
    if proc.create_time:
        ev["started"] = _iso(proc.create_time)
    if risk.rule_id == "AEG-TAMPER-BROWSER-DEBUG":
        rec = ("Close the browser (Aegis can terminate it) and find out what launched it: check the parent process, startup "
               "entries and recent downloads, then run a full scan. Treat the sessions in this profile as exposed: sign out of "
               "important accounts on all devices, change passwords and enable two-factor authentication or passkeys. "
               "Developers: use a separate --user-data-dir for remote debugging.")
    else:
        rec = ("If you did not start the browser this way yourself, close it (Aegis can terminate it), remove the extension "
               "folder it points to after checking what it is, find what launched the browser and run a full scan.")
    return Finding(
        rule_id=risk.rule_id, title=risk.title, severity=risk.severity, category=Category.BROWSER,
        description=risk.reason, location=label, evidence=ev, recommendation=rec,
        remediation=Remediation("kill_process", {"pid": proc.pid, "path": proc.exe, "quarantine": False},
                                "Terminate the browser process (the browser itself is not touched or quarantined)"),
        mitre=risk.mitre)


def check_browser_processes(ctx: ScanContext) -> Iterator[Emitted]:
    title = "Running browsers have no cookie-theft switches"
    procs = collect_browser_processes()
    flagged = 0
    for proc in procs:
        if ctx.cancelled:
            return
        risk = browser_cmdline_risk(proc.name, proc.argv, proc.exe)
        if risk:
            flagged += 1
            yield browser_process_finding(proc, risk)
    ctx.bump("tamper_browser_procs", len(procs))
    yield CheckResult("AEG-TAMPER-BROWSER-PROC", title, _status(flagged),
                      f"{len(procs)} browser process(es) examined: {flagged} with risky switches.", Category.BROWSER)


# =========================================================================== 6. Desktop crypto-wallet tampering


@dataclass(frozen=True)
class WalletApp:
    name: str
    # globs per platform; {LOCALAPPDATA} and {HOME} are replaced, anything else is absolute
    asar_globs: Dict[str, Tuple[str, ...]]
    # executable relative to the install root (the folder that contains ``resources`` / ``Contents/Resources``)
    exes: Dict[str, Tuple[str, ...]]


WALLET_APPS: Tuple[WalletApp, ...] = (
    WalletApp(
        "Exodus",
        {"windows": ("{LOCALAPPDATA}/exodus/app-*/resources/app.asar",),
         "darwin": ("/Applications/Exodus.app/Contents/Resources/app.asar",
                    "{HOME}/Applications/Exodus.app/Contents/Resources/app.asar"),
         "linux": ("{HOME}/.local/share/exodus*/resources/app.asar", "/opt/exodus*/resources/app.asar")},
        {"windows": ("Exodus.exe",), "darwin": ("MacOS/Exodus",), "linux": ("Exodus", "exodus")}),
    WalletApp(
        "Atomic Wallet",
        {"windows": ("{LOCALAPPDATA}/Programs/atomic/resources/app.asar",),
         "darwin": ("/Applications/Atomic Wallet.app/Contents/Resources/app.asar",
                    "{HOME}/Applications/Atomic Wallet.app/Contents/Resources/app.asar")},
        {"windows": ("Atomic Wallet.exe",), "darwin": ("MacOS/Atomic Wallet",)}),
    WalletApp(
        "Ledger Live",
        {"windows": ("{LOCALAPPDATA}/Programs/ledger-live-desktop/resources/app.asar",),
         "darwin": ("/Applications/Ledger Live.app/Contents/Resources/app.asar",
                    "{HOME}/Applications/Ledger Live.app/Contents/Resources/app.asar")},
        {"windows": ("Ledger Live.exe",), "darwin": ("MacOS/Ledger Live",)}),
)


@dataclass
class WalletInstall:
    wallet: str
    asar: Path
    exe: Optional[Path] = None


def _glob_pattern(pattern: str) -> List[Path]:
    parts = Path(pattern).parts
    for i, part in enumerate(parts):
        if any(c in part for c in "*?["):
            anchor = Path(*parts[:i]) if i else Path(".")
            return sorted(anchor.glob("/".join(parts[i:]))) if anchor.is_dir() else []
    p = Path(pattern)
    return [p] if p.exists() else []


def find_wallet_installs(platform: Optional[str] = None, home: Optional[Path] = None,
                         local_appdata: Optional[Path] = None) -> List[WalletInstall]:
    """Every installed Exodus / Atomic Wallet / Ledger Live ``app.asar`` with its main executable (roots injectable)."""
    platform = platform or OS_NAME
    home = home or user_home()
    local = local_appdata or Path(os.environ.get("LOCALAPPDATA") or (home / "AppData" / "Local"))
    out: List[WalletInstall] = []
    seen = set()
    for app in WALLET_APPS:
        for template in app.asar_globs.get(platform, ()):
            pattern = template.replace("{LOCALAPPDATA}", local.as_posix()).replace("{HOME}", home.as_posix())
            try:
                matches = _glob_pattern(pattern)
            except OSError:
                continue
            for asar in matches:
                key = os.path.normcase(str(asar))
                if key in seen or not asar.is_file():
                    continue
                seen.add(key)
                root = asar.parent.parent
                exe = next((root / rel for rel in app.exes.get(platform, ()) if (root / rel).is_file()), None)
                out.append(WalletInstall(app.name, asar, exe))
    return out


def find_wallets() -> List[WalletInstall]:
    return find_wallet_installs()


# marker name, lower-case needle used to locate candidates cheaply, regex confirming a real exfiltration endpoint
ASAR_MARKERS: Tuple[Tuple[str, bytes, "re.Pattern[bytes]"], ...] = (
    ("Discord webhook URL", b"/webhooks/",
     re.compile(rb"(?i)discord(?:app)?\.com/api(?:/v\d+)?/webhooks/\d{5,}/[\w-]{10,}")),
    ("Telegram bot API URL", b"api.telegram.org/bot", re.compile(rb"(?i)api\.telegram\.org/bot[\w:-]{0,60}")),
)


@dataclass
class MarkerHit:
    name: str
    offset: int
    excerpt: str


@dataclass
class AsarSearch:
    hits: List[MarkerHit] = field(default_factory=list)
    bytes_read: int = 0
    complete: bool = True  # False when the size cap or a cancel stopped the search before the end of the file


def search_asar_markers(path: Union[str, Path], max_bytes: int = ASAR_MAX_BYTES, chunk_size: int = ASAR_CHUNK,
                        overlap: int = ASAR_OVERLAP, should_stop: Optional[Callable[[], bool]] = None) -> AsarSearch:
    """Stream ``path`` in chunks (with ``overlap`` bytes carried over so a marker cannot hide on a boundary) looking for
    exfiltration endpoints; stops after the first chunk that has hits or after ``max_bytes``."""
    res = AsarSearch()
    carry = b""
    base = 0  # absolute offset of the first byte of ``carry + chunk``
    with open(path, "rb") as fh:
        while True:
            if res.bytes_read >= max_bytes:
                res.complete = not fh.read(1)  # exactly at the cap is still a complete search
                break
            if should_stop and should_stop():
                res.complete = False
                break
            buf = fh.read(min(chunk_size, max_bytes - res.bytes_read))
            if not buf:
                break
            res.bytes_read += len(buf)
            data = carry + buf
            lowered = data.lower()
            for name, needle, rx in ASAR_MARKERS:
                pos = lowered.find(needle)
                while pos >= 0:
                    m = rx.search(data, max(0, pos - 48), min(len(data), pos + 320))
                    if m:
                        window = data[max(0, m.start() - 40):m.end() + 40].decode("latin-1")
                        res.hits.append(MarkerHit(name, base + m.start(), _excerpt(window, 200)))
                        break
                    pos = lowered.find(needle, pos + 1)
            if res.hits:
                break
            carry = data[-overlap:] if overlap else b""
            base += len(data) - len(carry)
    return res


def asar_swapped_after_install(asar_mtime: float, exe_mtime: float, days: float = ASAR_NEWER_DAYS) -> bool:
    """True when app.asar is more than ``days`` newer than the wallet's executable (installers keep build timestamps, so a
    much newer asar means it was replaced afterwards)."""
    return asar_mtime - exe_mtime > days * 86400


def wallet_findings(inst: WalletInstall, search: Optional[AsarSearch], asar_mtime: float, size: int,
                    exe_mtime: Optional[float]) -> List[Finding]:
    ev: Dict[str, Any] = {"wallet": inst.wallet, "asar": str(inst.asar), "size": size, "modified": _iso(asar_mtime)}
    if exe_mtime is not None:
        ev["executable"] = str(inst.exe)
        ev["executable_modified"] = _iso(exe_mtime)
    if search and search.hits:
        ev.update(markers=sorted({h.name for h in search.hits}), offset=search.hits[0].offset,
                  excerpt=search.hits[0].excerpt, bytes_searched=search.bytes_read)
        return [Finding(
            rule_id="AEG-TAMPER-WALLET", title=f"{inst.wallet} wallet app was tampered with (it contains data-theft code)",
            severity=Severity.CRITICAL, category=Category.MALWARE,
            description=f"The application archive {inst.asar} of {inst.wallet} contains "
                        + " and ".join(sorted({h.name for h in search.hits})) + ". A wallet never ships these: stealers "
                        "('wallet injectors') replace app.asar with a copy that sends the wallet password and recovery "
                        "phrase to the attacker's Discord or Telegram the next time you type them, which lets them empty "
                        "the wallet.",
            location=str(inst.asar), evidence=ev,
            recommendation=f"Do not open {inst.wallet} or type your password or recovery phrase on this PC. From a clean device, "
                           "move the funds to a new wallet with a new recovery phrase (the old one must be treated as "
                           "stolen), then uninstall the wallet, delete its folder and reinstall it from the official website. "
                           "Run a full Aegis scan: a stealer was running here, so browser passwords, sessions and other "
                           "wallets may be exposed too.",
            remediation=None, mitre=["T1554", "T1567"])]
    if exe_mtime is not None and asar_swapped_after_install(asar_mtime, exe_mtime):
        days = (asar_mtime - exe_mtime) / 86400
        ev["days_newer"] = round(days, 1)
        return [Finding(
            rule_id="AEG-TAMPER-WALLET-CHANGED", title=f"Wallet app code changed after it was installed: {inst.wallet}",
            severity=Severity.MEDIUM, category=Category.SUSPICIOUS,
            description=f"{inst.asar} was modified {days:.0f} days after the {inst.wallet} program file next to it. Installers "
                        "and updates write both together, so a much newer app.asar means the application code was replaced "
                        "afterwards. Wallet-injecting malware does exactly that; no known data-theft address was found in "
                        "the file, so this can also be a manual repack or an unusual update.",
            location=str(inst.asar), evidence=ev,
            recommendation=f"If you did not patch {inst.wallet} yourself, treat it as suspicious: do not enter your password or "
                           "recovery phrase until you have uninstalled it and reinstalled the current version from the "
                           "official website, and run a full scan.",
            mitre=["T1554"])]
    return []


def check_wallets(ctx: ScanContext) -> Iterator[Emitted]:
    title = "Desktop crypto-wallet apps are untampered"
    installs = find_wallets()
    if not installs:
        yield CheckResult("AEG-TAMPER-WALLET", title, CheckStatus.SKIP,
                          "No Exodus, Atomic Wallet or Ledger Live installation found.", Category.SUSPICIOUS)
        return
    deadline = time.monotonic() + float(ctx.options.get("tamper_wallet_budget_s", 120) or 120)
    flagged = 0
    notes: List[str] = []
    for inst in installs:
        if ctx.cancelled:
            return
        ctx.report("apptamper", f"searching {inst.wallet} app.asar")
        ctx.bump("tamper_wallets")
        try:
            st = inst.asar.stat()
            exe_mtime = inst.exe.stat().st_mtime if inst.exe else None
        except OSError:
            continue
        try:
            search = search_asar_markers(inst.asar, should_stop=lambda: ctx.cancelled or time.monotonic() > deadline)
        except OSError as exc:  # unreadable archive: say so, keep checking the other wallets
            notes.append(f"{inst.wallet}: app.asar could not be read ({exc.strerror or type(exc).__name__})")
            search = AsarSearch(complete=False)
        if not search.complete and not search.hits and search.bytes_read:
            notes.append(f"{inst.wallet}: only the first {search.bytes_read // (1024 * 1024)} MB searched")
        for f in wallet_findings(inst, search, st.st_mtime, st.st_size, exe_mtime):
            flagged += 1
            yield f
    names = ", ".join(sorted({i.wallet for i in installs}))
    detail = f"{len(installs)} wallet app archive(s) checked ({names}): {flagged} suspicious."
    if notes:
        detail += " " + "; ".join(notes)
    yield CheckResult("AEG-TAMPER-WALLET", title, _status(flagged), detail, Category.SUSPICIOUS)


# =========================================================================== scanner

_CHECKS: Tuple[Tuple[str, str, str, Callable[[ScanContext], Iterator[Emitted]], str], ...] = (
    ("AEG-TAMPER-DISCORD", "Discord client files are unmodified", "checking Discord client files", check_discord,
     Category.SUSPICIOUS),
    ("AEG-TAMPER-ENV", "Electron / Node.js environment variables are not abused", "checking Electron / Node environment",
     check_environment, Category.PERSISTENCE),
    ("AEG-TAMPER-SHORTCUTS", "Browser shortcuts are not hijacked", "checking browser shortcuts", check_shortcuts,
     Category.BROWSER),
    ("AEG-TAMPER-BROWSER-PROC", "Running browsers have no cookie-theft switches", "checking running browsers",
     check_browser_processes, Category.BROWSER),
    ("AEG-TAMPER-WALLET", "Desktop crypto-wallet apps are untampered", "checking crypto-wallet apps", check_wallets,
     Category.SUSPICIOUS),
)


@register
class AppTamperScanner(Scanner):
    name = "apptamper"
    title = "Application tampering & session theft"
    description = ("Detects Discord client injection (token stealers), Electron/Node runtime abuse, hijacked browser "
                   "shortcuts, browsers running with cookie-theft switches and tampered crypto-wallet apps.")
    platforms = ("windows", "linux", "darwin")

    def run(self, ctx: ScanContext) -> Iterator[Emitted]:
        for check_id, title, progress, check, category in _CHECKS:
            if ctx.cancelled:
                return
            ctx.report(self.name, progress)
            try:
                yield from check(ctx)
            except Exception as exc:  # one failing check must not stop the others
                log.warning("apptamper check %s failed: %s", check_id, exc, exc_info=True)
                yield CheckResult(check_id, title, CheckStatus.ERROR, f"{type(exc).__name__}: {exc}", category)
