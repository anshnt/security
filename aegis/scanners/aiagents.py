"""AI coding agents and MCP servers: the newest way onto a developer's machine.

AI assistants (Claude Code / Desktop, Cursor, VS Code + Copilot, Windsurf, Gemini CLI, Codex CLI, Cline) start MCP servers,
run hooks and follow instruction files with the user's rights. Every check here is read-only:

* **MCP servers** from each app's config (user level and, in project folders, ``.mcp.json`` / ``.vscode/mcp.json`` /
  ``.cursor/mcp.json`` ...). A server whose package is on OSV's malicious list is CRITICAL (``postmark-mcp`` was the first
  one caught in the wild, MAL-2025-47604); a pinned version with known vulnerabilities is MEDIUM; a launch command that
  downloads and runs code or starts from Temp / Downloads is HIGH; a remote server over plain ``http://`` or on a raw IP /
  tunnel host is MEDIUM; API tokens written into the config (an infostealer favourite) are MEDIUM, masked; packages fetched
  unpinned on every start (how a "rug pull" update reaches you) are one LOW summary.
* **Agent permissions**: Claude Code ``bypassPermissions`` mode and ``enableAllProjectMcpServers`` (any cloned repository's
  ``.mcp.json`` starts without asking), VS Code ``chat.tools.global.autoApprove``, Codex ``approval_policy = "never"`` with
  ``sandbox_mode = "danger-full-access"``, Gemini CLI YOLO mode and trusted servers: a prompt injection in a web page,
  issue or file then becomes code execution without a prompt (MEDIUM).
* **Hooks and helper commands** (Claude Code ``hooks`` / ``statusLine`` / ``apiKeyHelper``, Codex ``notify`` / ``hooks``):
  npm worms have planted hooks into AI tools, so a download-and-run or encoded command is HIGH.
* **Instruction files and skills** (``AGENTS.md``, ``CLAUDE.md``, ``.cursorrules``, ``.github/copilot-instructions.md``,
  ``SKILL.md`` ...): invisible Unicode that the AI reads but people do not see ("Rules File Backdoor"): tag characters
  that spell hidden text (decoded in the evidence) and long runs of variation selectors that encode a payload are HIGH,
  bidirectional controls and zero-width characters inside plain text are MEDIUM. A skill that tells the agent to download
  and run code from an unknown host (the ClawHavoc marketplace campaign) is HIGH.
* **Local AI servers**: Ollama listening on every interface (no authentication) and versions before 0.17.1 (CVE-2026-7482,
  memory leak of keys and prompts), and MCP servers bound to 0.0.0.0 ("NeighborJack").

Readers, the clock-free parsers and the decisions take plain data, so everything is unit-tested on any OS.
"""

from __future__ import annotations

import json
import logging
import os
import re
import socket
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple

from aegis.core.models import Category, CheckResult, CheckStatus, Finding, Severity
from aegis.core.platform import IS_MAC, IS_WINDOWS, user_home
from aegis.scanners.base import Emitted, ScanContext, Scanner, register
from aegis.scanners.privacy import staging_location

log = logging.getLogger("aegis.aiagents")

MAX_CONFIG = 2 * 1024 * 1024
MAX_TEXT = 512 * 1024
MAX_FINDINGS_PER_KIND = 25
OLLAMA_FIXED = (0, 17, 1)  # CVE-2026-7482 fixed in 0.17.1
MITRE_SUPPLY = ["T1195.002"]
MITRE_EXEC = ["T1059"]

# =========================================================================== config locations
# (app, format, path): format "mcp" = a JSON file whose mcpServers / servers hold MCP servers
JSON_MCP_KEYS = ("mcpServers", "servers")


def _app_data(home: Path, env: Mapping[str, str]) -> Path:
    if IS_WINDOWS:
        return Path(env.get("APPDATA") or home / "AppData" / "Roaming")
    return home / "Library" / "Application Support" if IS_MAC else Path(env.get("XDG_CONFIG_HOME") or home / ".config")


def user_config_files(home: Path, env: Mapping[str, str]) -> List[Tuple[str, str, Path]]:
    app_data = _app_data(home, env)
    files = [("Claude Desktop", "mcp", app_data / "Claude" / "claude_desktop_config.json"),
             ("Claude Code", "claude-json", home / ".claude.json"),
             ("Claude Code", "claude-settings", home / ".claude" / "settings.json"),
             ("Cursor", "mcp", home / ".cursor" / "mcp.json"),
             ("Windsurf", "mcp", home / ".codeium" / "windsurf" / "mcp_config.json"),
             ("GitHub Copilot CLI", "mcp", home / ".copilot" / "mcp-config.json"),
             ("Gemini CLI", "gemini-settings", home / ".gemini" / "settings.json"),
             ("Codex CLI", "codex-toml", home / ".codex" / "config.toml")]
    for editor in ("Code", "Code - Insiders", "VSCodium", "Cursor", "Windsurf"):
        user = app_data / editor / "User"
        files += [(editor if editor != "Code" else "VS Code", "mcp", user / "mcp.json"),
                  (editor if editor != "Code" else "VS Code", "vscode-settings", user / "settings.json"),
                  ("Cline", "mcp", user / "globalStorage" / "saoudrizwan.claude-dev" / "settings" / "cline_mcp_settings.json")]
    return files


PROJECT_CONFIGS = ((".mcp.json", "mcp"), (".vscode/mcp.json", "mcp"), (".cursor/mcp.json", "mcp"),
                   (".gemini/settings.json", "gemini-settings"), (".claude/settings.json", "claude-settings"),
                   (".claude/settings.local.json", "claude-settings"), (".codex/config.toml", "codex-toml"))

INSTRUCTION_NAMES = frozenset({"agents.md", "claude.md", "gemini.md", ".cursorrules", ".windsurfrules", ".clinerules",
                               "copilot-instructions.md", "skill.md"})
INSTRUCTION_DIRS = (".cursor/rules", ".claude/commands", ".claude/agents", ".github/instructions", ".github/prompts",
                    ".clinerules", ".windsurf/rules")
# bulky folders inside agent homes and projects that hold no instructions (session logs, caches, dependencies)
_SKIP_AGENT_DIRS = frozenset({"node_modules", ".git", "__pycache__", ".venv", "venv", "projects", "file-history",
                              "shell-snapshots", "backups", "telemetry", "session-env", "paste-cache", "sessions", "jobs",
                              "downloads", "uploads", "todos", "statsig", "logs"})
SKILL_SCRIPT_EXT = (".sh", ".bash", ".zsh", ".ps1", ".psm1", ".bat", ".cmd", ".py", ".js", ".mjs", ".ts")


def user_instruction_roots(home: Path) -> List[Path]:
    return [home / ".claude", home / ".codex", home / ".gemini", home / ".cursor", home / ".copilot"]


# =========================================================================== parsing
@dataclass
class McpServer:
    app: str
    name: str
    source: str
    command: str = ""
    args: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    trusted: bool = False
    project: str = ""  # Claude Code per-project servers in ~/.claude.json

    @property
    def command_line(self) -> str:
        return " ".join([self.command] + [str(a) for a in self.args]).strip()

    @property
    def label(self) -> str:
        return f"{self.app} MCP server '{self.name}'"


@dataclass
class AgentConfig:
    app: str
    path: str
    kind: str
    scope: str  # user | project
    servers: List[McpServer] = field(default_factory=list)
    settings: Dict[str, Any] = field(default_factory=dict)
    text: str = ""


def load_json_text(text: str) -> Any:
    from aegis.scanners.supplychain import load_jsonc  # comments and trailing commas (VS Code style files)

    try:
        return json.loads(text)
    except ValueError:
        return load_jsonc(text)


def _str_map(value: Any) -> Dict[str, str]:
    return {str(k): str(v) for k, v in value.items()} if isinstance(value, dict) else {}


def _servers(app: str, source: str, table: Any, project: str = "") -> List[McpServer]:
    out: List[McpServer] = []
    if not isinstance(table, dict):
        return out
    for name, spec in table.items():
        if not isinstance(spec, dict):
            continue
        args = spec.get("args") or []
        if isinstance(args, str):
            args = args.split()
        cmd = spec.get("command") or ""
        if isinstance(cmd, dict):  # Zed-style {"path": ..., "args": [...]}
            args, cmd = cmd.get("args") or [], cmd.get("path") or ""
        out.append(McpServer(app, str(name), source, str(cmd), [str(a) for a in args if a is not None],
                             _str_map(spec.get("env")), str(spec.get("url") or spec.get("serverUrl") or spec.get("httpUrl") or ""),
                             _str_map(spec.get("headers")), bool(spec.get("trust")), project))
    return out


def parse_config(app: str, kind: str, path: str, text: str, scope: str = "user") -> Optional[AgentConfig]:
    """One agent configuration file -> servers + the settings the checks need. None when unparseable."""
    cfg = AgentConfig(app, path, kind, scope, text=text)
    if kind == "codex-toml":
        try:
            import tomllib  # Python 3.11+
        except ImportError:  # pragma: no cover - older Pythons skip Codex config
            return None
        try:
            doc = tomllib.loads(text)
        except Exception:
            return None
        cfg.servers = _servers(app, path, doc.get("mcp_servers"))
        cfg.settings = {k: doc.get(k) for k in ("approval_policy", "sandbox_mode", "notify", "hooks") if k in doc}
        return cfg
    doc = load_json_text(text)
    if not isinstance(doc, dict):
        return None
    if kind == "claude-json":
        cfg.servers = _servers(app, path, doc.get("mcpServers"))
        for proj, pdoc in (doc.get("projects") or {}).items() if isinstance(doc.get("projects"), dict) else ():
            if isinstance(pdoc, dict):
                cfg.servers += _servers(app, path, pdoc.get("mcpServers"), project=str(proj))
    elif kind == "vscode-settings":
        mcp = doc.get("mcp")
        cfg.servers = _servers(app, path, mcp.get("servers")) if isinstance(mcp, dict) else []
        cfg.settings = {k: doc.get(k) for k in ("chat.tools.global.autoApprove", "chat.tools.autoApprove") if k in doc}
    else:
        for key in JSON_MCP_KEYS:
            cfg.servers += _servers(app, path, doc.get(key))
        if kind == "claude-settings":
            perms = doc.get("permissions") if isinstance(doc.get("permissions"), dict) else {}
            cfg.settings = {"defaultMode": perms.get("defaultMode"), "hooks": doc.get("hooks"),
                            **{k: doc.get(k) for k in ("skipDangerousModePermissionPrompt", "enableAllProjectMcpServers",
                                                        "statusLine", "apiKeyHelper") if k in doc}}
        elif kind == "gemini-settings":
            general = doc.get("general") if isinstance(doc.get("general"), dict) else {}
            cfg.settings = {"defaultApprovalMode": general.get("defaultApprovalMode") or doc.get("defaultApprovalMode")}
    return cfg


# =========================================================================== MCP server checks
_WRAPPERS = {"cmd", "cmd.exe"}
_LAUNCHERS = {"npx": "npm", "npx.cmd": "npm", "bunx": "npm", "pnpx": "npm", "uvx": "PyPI", "uvx.exe": "PyPI"}
_TWO_WORD = {("pnpm", "dlx"): "npm", ("yarn", "dlx"): "npm", ("npm", "exec"): "npm", ("bun", "x"): "npm",
             ("pipx", "run"): "PyPI", ("uv", "tool"): "PyPI"}
_NPM_VALUE_OPTS = {"-p", "--package", "-c", "--call", "--registry", "--cache", "--userconfig"}
_UV_VALUE_OPTS = {"--from", "--with", "-p", "--python", "--index", "--index-url", "--extra-index-url", "--with-requirements"}


def _base(cmd: str) -> str:
    return re.split(r"[\\/]", cmd.strip().strip('"'))[-1].lower()


def package_spec(command: str, args: Sequence[str]) -> Optional[Tuple[str, str, str]]:
    """(ecosystem, name, version or '') of the package a launcher fetches: npx / bunx / pnpm dlx / yarn dlx (npm),
    uvx / pipx run (PyPI). ``cmd /c npx ...`` is unwrapped. None for anything else."""
    words = [command] + list(args)
    if words and _base(words[0]) in _WRAPPERS and len(words) > 2 and words[1].lower() in ("/c", "/k"):
        words = words[2:]
    if not words:
        return None
    first, eco = _base(words[0]), None
    rest = words[1:]
    if first in _LAUNCHERS:
        eco = _LAUNCHERS[first]
    elif len(words) > 1 and (first.removesuffix(".cmd").removesuffix(".exe"), words[1].lower()) in _TWO_WORD:
        eco = _TWO_WORD[(first.removesuffix(".cmd").removesuffix(".exe"), words[1].lower())]
        rest = words[2:] if words[1].lower() != "tool" else (words[3:] if len(words) > 2 and words[2] == "run" else [])
    if eco is None:
        return None
    value_opts = _NPM_VALUE_OPTS if eco == "npm" else _UV_VALUE_OPTS
    spec, i = "", 0
    while i < len(rest):
        a = rest[i]
        if a in ("-p", "--package", "--from") and i + 1 < len(rest):
            spec = rest[i + 1]
            break
        if a.startswith(("--package=", "--from=")):
            spec = a.split("=", 1)[1]
            break
        if a.startswith("-"):
            i += 2 if a in value_opts else 1
            continue
        spec = a
        break
    if not spec or spec.startswith((".", "/", "\\", "http:", "https:", "git+", "github:", "file:")) or re.match(r"^[A-Za-z]:", spec):
        return None
    if eco == "npm":
        at = spec.rfind("@")
        name, version = (spec[:at], spec[at + 1:]) if at > 0 else (spec, "")
    else:
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(?:==|@)\s*([A-Za-z0-9._+!-]+)$", spec)
        name, version = (m.group(1), m.group(2)) if m else (re.split(r"[<>=!~@\[ ]", spec)[0], "")
    if version.lower() in ("latest", "next", "*"):
        version = ""
    return (eco, name, version) if name else None


_HTTP_LOCAL = re.compile(r"^(?:localhost|127\.\d+\.\d+\.\d+|\[?::1\]?)$", re.I)
_RAW_IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _finding(rule: str, title: str, sev: Severity, desc: str, location: str, evidence: Dict[str, Any], rec: str,
             mitre: Sequence[str], category: str = Category.SUSPICIOUS) -> Finding:
    return Finding(rule, title, sev, category, desc, location, evidence, rec, None, "", list(mitre))


# reasons from supplychain.analyze_command that a vendor's "curl https://vendor/install.sh | sh" line never has
_STRONG_REASONS = ("decodes base64", "hidden or encoded PowerShell", "raw IP address", "webhook / paste / tunnel",
                   "Shai-Hulud")
# paste and anonymous file hosts: where the ClawHavoc skills fetched their "setup" scripts (glot.io among them)
_PASTE_HOSTS = re.compile(r"\b(?:glot\.io|pastebin\.com|paste\.ee|rentry\.(?:co|org)|hastebin\.\w+|dpaste\.\w+|"
                          r"termbin\.com|0x0\.st|transfer\.sh|bashupload\.com|file\.io|temp\.sh|paste\.rs)/", re.I)
_PLAIN_HTTP_FETCH = re.compile(r"\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^|;&\n]*\bhttp://", re.I)


def command_risk(cmd: str, strict: bool = False) -> Tuple[Optional[Severity], List[str]]:
    """HIGH verdicts only: download-and-run, encoded or hidden PowerShell, known attack command lines. Installers from
    well-known hosts are not flagged. ``strict`` (skill text, where vendors document ``curl https://... | sh`` installs)
    also needs a signal such installers never have: decoding, hidden PowerShell, a raw IP, a paste / tunnel host or a
    plain-HTTP download."""
    from aegis.core.cmdline import analyse_command_line
    from aegis.scanners.supplychain import analyze_command
    from aegis.scanners.traces import downloads_only_from_trusted

    if not cmd.strip():
        return None, []
    sev, reasons = analyze_command(cmd)
    hits = [h for h in analyse_command_line(cmd) if h[2] >= Severity.HIGH]
    if (sev is None or sev < Severity.HIGH) and not hits:
        return None, []
    if downloads_only_from_trusted(cmd) and not any(h[2] >= Severity.CRITICAL for h in hits):
        return None, []
    if strict and not any(h[2] >= Severity.CRITICAL for h in hits) and not _PLAIN_HTTP_FETCH.search(cmd) \
            and not _PASTE_HOSTS.search(cmd) and not any(k in r for r in reasons for k in _STRONG_REASONS):
        return None, []
    if _PASTE_HOSTS.search(cmd):
        reasons = reasons + ["fetches from a paste / anonymous file host"]
    worst = max([sev or Severity.INFO] + [h[2] for h in hits])
    return worst, list(dict.fromkeys(reasons + [h[1] for h in hits]))[:5]


def server_findings(s: McpServer) -> List[Finding]:
    out: List[Finding] = []
    loc = f"{s.source} :: {s.name}" + (f" (project {s.project})" if s.project else "")
    ev = {"app": s.app, "server": s.name, "config": s.source, "command": s.command_line[:500], "url": s.url}
    if s.command:
        sev, reasons = command_risk(s.command_line)
        if sev:
            out.append(_finding(
                "AEG-AI-MCP-CMD", f"{s.label} starts with a download-and-run command", max(sev, Severity.HIGH),
                f"Every time {s.app} starts, it runs: {s.command_line[:200]}. Reasons: {'; '.join(reasons)}. MCP servers run "
                "with your rights, so this is how a poisoned config or repository gets code onto the machine.",
                loc, {**ev, "reasons": reasons}, "Remove the server from the config unless you added it on purpose, and "
                "scan the machine.", MITRE_EXEC))
        staged = staging_location(s.command)
        if staged:
            out.append(_finding(
                "AEG-AI-MCP-STAGED", f"{s.label} runs a program from {staged}", Severity.HIGH,
                f"The server's program is {s.command}, in {staged}. Real MCP servers are installed packages; malware drops "
                "itself in such folders and registers as an MCP server to be started by the AI app.",
                loc, ev, "Remove the server entry and scan the program.", MITRE_EXEC))
    if s.url:
        u = urllib.parse.urlsplit(s.url)
        host = (u.hostname or "").lower()
        from aegis.scanners.supplychain import _RX

        if u.scheme == "http" and host and not _HTTP_LOCAL.match(host):
            out.append(_finding(
                "AEG-AI-MCP-HTTP", f"{s.label} talks to a remote server over plain HTTP", Severity.MEDIUM,
                f"{s.url} is not encrypted: anyone on the network path can read the tokens and data the AI sends to it, "
                "and change the tool descriptions and results it gets back (tool poisoning).",
                loc, ev, "Use the https:// address of the server, or remove it.", ["T1557"], Category.NETWORK))
        elif (_RAW_IP.match(host) and not host.startswith(("10.", "127.", "192.168."))) or _RX["exfil_host"].search(s.url):
            out.append(_finding(
                "AEG-AI-MCP-HOST", f"{s.label} points at a raw IP address or tunnel host", Severity.MEDIUM,
                f"{s.url} is a bare IP address or a tunnel / webhook service, where legitimate MCP providers do not run. "
                "Tool descriptions from such a server can carry hidden instructions for the AI.",
                loc, ev, "Remove the server unless you know who runs it.", MITRE_SUPPLY, Category.NETWORK))
    return out


def token_findings(cfg: AgentConfig) -> List[Finding]:
    """API tokens written into an MCP / agent config (masked). Capped at MEDIUM: putting them there is how many servers
    are documented, but these files are among the first an infostealer copies."""
    from aegis.scanners.secrets import scan_tokens

    hits = scan_tokens(cfg.text)
    if not hits:
        return []
    kinds = sorted({h.evidence.get("type", h.rule) for h in hits})
    return [_finding(
        "AEG-AI-CONFIG-TOKEN", f"{cfg.app} config stores API tokens in plain text ({', '.join(kinds)})",
        min(max(h.severity for h in hits), Severity.MEDIUM),
        f"{cfg.path} contains {', '.join(kinds)} in plain text. AI-agent and MCP configs are on infostealers' target "
        "lists (the 2026 ClawHavoc campaign went after LLM API keys), and the file is readable by every program you run.",
        cfg.path, {"types": kinds, "matches": [m for h in hits for m in h.evidence.get("matches", [])][:10]},
        "Reference the token from an environment variable or the app's secret input (for example ${env:GITHUB_TOKEN} or "
        "${input:token}) instead of writing it into the file, and rotate tokens that were stored there.",
        ["T1552.001"], Category.PRIVACY)]


def osv_findings(pkgs: Mapping[Tuple[str, str, str], List[McpServer]], results: Mapping[Any, List[str]]) -> List[Finding]:
    out: List[Finding] = []
    for (eco, name, version), servers in pkgs.items():
        ids = [] if results is None else results.get((eco, name, version), [])
        mal = [i for i in ids if i.startswith("MAL-")]
        names = ", ".join(sorted({f"{s.app}: {s.name}" for s in servers}))
        ev = {"ecosystem": eco, "package": name, "version": version or "latest (unpinned)", "advisories": ids[:20],
              "servers": names, "configs": sorted({s.source for s in servers})}
        if mal:
            out.append(_finding(
                "AEG-AI-MCP-MALICIOUS", f"MCP server package {name} is known malware", Severity.CRITICAL,
                f"{names} runs the {eco} package {name}, which OSV lists as malicious ({', '.join(mal)}). Malicious MCP "
                "servers read the data the AI handles and can copy every e-mail, file or secret that passes through them.",
                servers[0].source, ev, "Remove the server from every config now, rotate any token it was given, and run a "
                "full scan.", MITRE_SUPPLY, Category.MALWARE))
        elif ids and version:
            out.append(_finding(
                "AEG-AI-MCP-VULN", f"MCP server package {name} {version} has known vulnerabilities", Severity.MEDIUM,
                f"{names} pins {eco} {name} {version}, which is affected by {', '.join(ids[:5])}.",
                servers[0].source, ev, f"Update the pinned version of {name} to a fixed release.", MITRE_SUPPLY,
                Category.VULNERABILITY))
    return out


def unpinned_finding(pkgs: Mapping[Tuple[str, str, str], List[McpServer]]) -> Optional[Finding]:
    loose = sorted({f"{name} ({s.app})" for (eco, name, version), servers in pkgs.items() if not version for s in servers})
    if not loose:
        return None
    return _finding(
        "AEG-AI-MCP-UNPINNED", f"{len(loose)} MCP server(s) download the latest package version on every start", Severity.LOW,
        "These servers are started with npx / uvx and no version, so whatever the package owner (or someone who steals "
        "their account) publishes next runs on this machine automatically. That is how postmark-mcp turned malicious in "
        "an update after a dozen clean releases: " + "; ".join(loose[:15]) + ("; ..." if len(loose) > 15 else ""),
        "MCP server packages", {"servers": loose[:50]}, "Pin a version you have reviewed (npx -y package@1.2.3, "
        "uvx package==1.2.3) and update it on purpose.", MITRE_SUPPLY, Category.VULNERABILITY)


# =========================================================================== agent permission settings and hooks
def _hook_commands(hooks: Any) -> List[str]:
    """Command strings from a Claude Code / Codex hooks table: {Event: [{matcher, hooks: [{type, command}]}]}."""
    out: List[str] = []
    if not isinstance(hooks, dict):
        return out
    for groups in hooks.values():
        for group in groups if isinstance(groups, list) else []:
            if not isinstance(group, dict):
                continue
            for h in group.get("hooks") or [group]:
                if isinstance(h, dict):
                    for key in ("command", "commandWindows"):
                        if isinstance(h.get(key), str):
                            out.append(h[key])
    return out


def settings_findings(cfg: AgentConfig) -> List[Finding]:
    out: List[Finding] = []
    st = cfg.settings
    loc = cfg.path

    def perm(rule: str, title: str, desc: str, rec: str, sev: Severity = Severity.MEDIUM) -> None:
        out.append(_finding(rule, title, sev, desc + " A prompt injection hidden in a web page, issue, e-mail or file the "
                            "agent reads can then run commands on this machine without anyone confirming.",
                            loc, {"app": cfg.app, "config": cfg.path, "scope": cfg.scope}, rec, MITRE_EXEC, Category.SYSTEM))

    if cfg.kind == "claude-settings":
        if st.get("defaultMode") == "bypassPermissions" and cfg.scope == "user":  # ignored in project files
            perm("AEG-AI-AGENT-AUTOAPPROVE", "Claude Code starts every session with all permission prompts off",
                 "permissions.defaultMode is bypassPermissions" + (" and the warning before that mode is switched off"
                                                                    if st.get("skipDangerousModePermissionPrompt") else "") + ".",
                 "Remove defaultMode (or use acceptEdits) and enable bypass mode only inside a container or VM.")
        if st.get("enableAllProjectMcpServers") is True:
            perm("AEG-AI-MCP-AUTOTRUST", "Claude Code starts every project's MCP servers without asking"
                 + (" (set by the project itself)" if cfg.scope == "project" else ""),
                 "enableAllProjectMcpServers is true, so the .mcp.json of any repository you open launches its servers "
                 "(arbitrary commands) without a prompt.", "Set enableAllProjectMcpServers to false and approve servers per "
                 "project with enabledMcpjsonServers.", Severity.HIGH if cfg.scope == "project" else Severity.MEDIUM)
        cmds = _hook_commands(st.get("hooks"))
        for key in ("statusLine", "apiKeyHelper"):
            v = st.get(key)
            cmds += [v] if isinstance(v, str) else ([v["command"]] if isinstance(v, dict) and isinstance(v.get("command"), str) else [])
        out += _command_findings(cfg, cmds)
    elif cfg.kind == "vscode-settings":
        if any(v is True for v in st.values()):
            perm("AEG-AI-AGENT-AUTOAPPROVE", f"{cfg.app} approves every agent tool call automatically",
                 "chat.tools.global.autoApprove (or the older chat.tools.autoApprove) is true in the user settings.",
                 "Turn the setting off; approve tools per session (/autoApprove) only when you trust what the agent reads.")
    elif cfg.kind == "codex-toml":
        if st.get("approval_policy") == "never" and st.get("sandbox_mode") == "danger-full-access":
            perm("AEG-AI-AGENT-AUTOAPPROVE", "Codex runs commands without approval and without a sandbox",
                 'approval_policy = "never" together with sandbox_mode = "danger-full-access".',
                 'Use approval_policy = "on-request" or sandbox_mode = "workspace-write".')
        notify = st.get("notify")
        out += _command_findings(cfg, ([" ".join(map(str, notify))] if isinstance(notify, list) else [])
                                 + _hook_commands(st.get("hooks")))
    elif cfg.kind == "gemini-settings":
        if str(st.get("defaultApprovalMode") or "").lower() == "yolo":
            perm("AEG-AI-AGENT-AUTOAPPROVE", "Gemini CLI approves every tool call automatically (YOLO mode)",
                 "defaultApprovalMode is yolo.", "Use the default approval mode.")
        trusted = [s.name for s in cfg.servers if s.trusted]
        if trusted:
            perm("AEG-AI-MCP-TRUSTED", f"Gemini CLI runs tools of {len(trusted)} MCP server(s) without confirmation",
                 f"trust is true for: {', '.join(trusted[:10])}.", "Remove trust: true unless you wrote the server.",
                 Severity.LOW)
    return out


def _command_findings(cfg: AgentConfig, commands: Sequence[str]) -> List[Finding]:
    out: List[Finding] = []
    for cmd in commands:
        sev, reasons = command_risk(cmd)
        if sev:
            out.append(_finding(
                "AEG-AI-HOOK", f"{cfg.app} runs a suspicious hook command", max(sev, Severity.HIGH),
                f"{cfg.path} makes {cfg.app} run: {cmd[:200]}. Reasons: {'; '.join(reasons)}. npm worms have planted such "
                "hooks into AI coding tools so that every session runs their code.",
                f"{cfg.path} :: hook", {"app": cfg.app, "config": cfg.path, "command": cmd[:500], "reasons": reasons},
                "Delete the hook unless you wrote it, then scan the machine.", MITRE_EXEC + ["T1546"]))
    return out


# =========================================================================== hidden Unicode in instruction files
BIDI_CONTROLS = frozenset({0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069})
ZERO_WIDTH = frozenset({0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF, 0x180E})
VS_RUN_MIN = 16  # supplementary variation selectors (U+E0100..E01EF) used to smuggle bytes ("invisible code")
ZERO_WIDTH_MIN = 3


@dataclass
class Hidden:
    tag_text: str = ""
    tag_chars: int = 0
    variation_selectors: int = 0
    bidi: int = 0
    zero_width: int = 0

    @property
    def severity(self) -> Optional[Severity]:
        if self.tag_chars or self.variation_selectors >= VS_RUN_MIN:
            return Severity.HIGH
        if self.bidi or self.zero_width >= ZERO_WIDTH_MIN:
            return Severity.MEDIUM
        return None


_ANY_HIDDEN = re.compile("[\U000E0000-\U000E007F\U000E0100-\U000E01EF\u202A-\u202E\u2066-\u2069"
                         "\u200B-\u200D\u2060-\u2064\uFEFF\u180E]")
# lines worth the full command analysis: something that fetches, decodes or starts an interpreter
_COMMAND_HINT = re.compile(r"curl|wget|\biwr\b|\birm\b|invoke-|powershell|pwsh|base64|certutil|bitsadmin|mshta|"
                           r"https?://|\biex\b|\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b", re.I)


def _plain(ch: str) -> bool:
    return ch.isascii()


def hidden_unicode(text: str) -> Hidden:
    """Count characters an AI model reads but an editor does not show. Zero-width characters only count between plain
    ASCII text (emoji sequences and Persian / Indic joiners use them legitimately); a leading BOM is ignored."""
    h = Hidden()
    if not _ANY_HIDDEN.search(text):
        return h
    tag: List[str] = []
    for i, ch in enumerate(text):
        o = ord(ch)
        if 0xE0000 <= o <= 0xE007F:
            h.tag_chars += 1
            if 0x20 <= o - 0xE0000 < 0x7F:
                tag.append(chr(o - 0xE0000))
        elif 0xE0100 <= o <= 0xE01EF:
            h.variation_selectors += 1
        elif o in BIDI_CONTROLS:
            h.bidi += 1
        elif o in ZERO_WIDTH and not (o == 0xFEFF and i == 0):
            before = text[i - 1] if i else " "
            after = text[i + 1] if i + 1 < len(text) else " "
            if _plain(before) and (_plain(after) or ord(after) in ZERO_WIDTH):
                h.zero_width += 1
    h.tag_text = "".join(tag)
    return h


def instruction_findings(path: str, text: str, kind: str) -> List[Finding]:
    out: List[Finding] = []
    h = hidden_unicode(text)
    sev = h.severity
    if sev:
        parts = []
        if h.tag_chars:
            parts.append(f"{h.tag_chars} Unicode tag characters that spell hidden text")
        if h.variation_selectors >= VS_RUN_MIN:
            parts.append(f"{h.variation_selectors} invisible variation selectors (an encoded payload)")
        if h.bidi:
            parts.append(f"{h.bidi} bidirectional control characters that reorder what you see")
        if h.zero_width >= ZERO_WIDTH_MIN:
            parts.append(f"{h.zero_width} zero-width characters inside the text")
        out.append(_finding(
            "AEG-AI-HIDDEN-TEXT", f"AI {kind} file contains invisible instructions", sev,
            f"{path} has {'; '.join(parts)}. AI coding assistants read these characters but editors and code review do not "
            "show them (the 'Rules File Backdoor' technique), so the file can tell the AI to add backdoors or leak secrets "
            "while looking harmless." + (f" Hidden text: \"{h.tag_text[:300]}\"" if h.tag_text else ""),
            path, {"tag_characters": h.tag_chars, "hidden_text": h.tag_text[:1000], "variation_selectors": h.variation_selectors,
                   "bidi_controls": h.bidi, "zero_width": h.zero_width},
            "Open the file in an editor that shows invisible characters (VS Code highlights them), remove them, and find "
            "out where the file came from before letting an AI agent use it again.", ["T1195.002", "T1027"]))
    if kind == "skill":
        for line in text.splitlines():
            if not _COMMAND_HINT.search(line):
                continue
            sev2, reasons = command_risk(line, strict=True)
            if sev2:
                out.append(_finding(
                    "AEG-AI-SKILL-CMD", "AI agent skill tells the agent to download and run code", max(sev2, Severity.HIGH),
                    f"{path} contains: {line.strip()[:200]}. Reasons: {'; '.join(reasons)}. Malicious skills on agent "
                    "marketplaces (the 2026 ClawHavoc campaign) hid infostealer installers in exactly such 'setup' steps.",
                    path, {"line": line.strip()[:500], "reasons": reasons}, "Delete the skill unless you wrote it; if the "
                    "agent already ran it, treat the machine as compromised and rotate your API keys.", MITRE_SUPPLY + MITRE_EXEC))
                break
    return out


def _read(path: Path, limit: int = MAX_TEXT) -> Optional[str]:
    try:
        if not path.is_file() or path.stat().st_size > limit:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def instruction_kind(path: Path) -> str:
    name = path.name.lower()
    if name == "skill.md" or ("skills" in (p.lower() for p in path.parts) and path.suffix.lower() in SKILL_SCRIPT_EXT):
        return "skill"
    return "instruction"


def find_instruction_files(base: Path, depth: int = 3, limit: int = 400) -> List[Path]:
    """AI instruction / rules / skill files under one folder (a user's agent folder or a project)."""
    out: List[Path] = []
    base_parts = len(base.parts)
    try:
        for dirpath, dirnames, filenames in os.walk(base):
            cur = Path(dirpath)
            rel = cur.relative_to(base).as_posix() if cur != base else ""
            in_rules_dir = any(rel == d or rel.startswith(d + "/") for d in INSTRUCTION_DIRS)
            in_skill = "skills" in [p.lower() for p in cur.parts[base_parts:]]
            for fn in filenames:
                low = fn.lower()
                if (low in INSTRUCTION_NAMES or (in_rules_dir and low.endswith((".md", ".mdc")))
                        or (in_skill and low.endswith(SKILL_SCRIPT_EXT))):
                    out.append(cur / fn)
                    if len(out) >= limit:
                        return out
            if len(cur.parts) - base_parts >= depth:
                dirnames[:] = []
            else:
                dirnames[:] = [d for d in dirnames if d.lower() not in _SKIP_AGENT_DIRS]
    except OSError:
        pass
    return out


# =========================================================================== local AI servers
_MCP_PROC = re.compile(r"(?:^|[\\/\s@_-])(?:mcp|fastmcp|mcp-server|server-[\w-]+-mcp)(?:$|[\\/\s@_.-])|modelcontextprotocol", re.I)


def version_tuple(text: str) -> Optional[Tuple[int, ...]]:
    m = re.match(r"^\s*v?(\d+)\.(\d+)(?:\.(\d+))?", text or "")
    return tuple(int(x or 0) for x in m.groups()) if m else None


def listener_findings(listeners: Sequence[Tuple[str, int, str, str, int]], ollama_version: str = "",
                      ollama_env_host: str = "") -> List[Finding]:
    """``listeners``: (bound address, port, process name, command line, pid) of listening sockets."""
    out: List[Finding] = []
    exposed = lambda addr: addr in ("0.0.0.0", "::", "", "*")  # noqa: E731
    ollama_all = any(p == 11434 and exposed(a) for a, p, *_ in listeners)
    ollama_any = any(p == 11434 for _a, p, *_ in listeners)
    ver = version_tuple(ollama_version)
    if ollama_any and ver and ver < OLLAMA_FIXED:
        out.append(_finding(
            "AEG-AI-OLLAMA-CVE", f"Ollama {ollama_version} leaks memory to anyone who can reach it (CVE-2026-7482)",
            Severity.HIGH if ollama_all else Severity.MEDIUM,
            f"Ollama before 0.17.1 has a heap out-of-bounds read in its model loader: a few unauthenticated HTTP requests "
            f"leak process memory, including API keys and prompts.{' It also listens on every network interface.' if ollama_all else ''}",
            "ollama", {"version": ollama_version, "listens_on_all_interfaces": ollama_all},
            "Update Ollama to 0.17.1 or later.", ["T1190"], Category.VULNERABILITY))
    if ollama_all or (not ollama_any and ollama_env_host.split(":")[0] in ("0.0.0.0", "::", "[::]")):
        out.append(_finding(
            "AEG-AI-OLLAMA-EXPOSED", "Ollama accepts connections from the whole network without a password", Severity.MEDIUM,
            ("Ollama listens on port 11434 on every interface" if ollama_all else
             f"OLLAMA_HOST is {ollama_env_host}, so Ollama listens on every interface when it starts")
            + ". Its API has no authentication: anyone on the same Wi-Fi (or the internet, behind a forwarded port) can use "
            "your GPU, read and delete models and reach the vulnerable model loader. Scans in 2026 found over 10,000 such servers.",
            "0.0.0.0:11434", {"env_OLLAMA_HOST": ollama_env_host}, "Bind Ollama to 127.0.0.1 (unset OLLAMA_HOST or set it to "
            "127.0.0.1:11434) and put an authenticating reverse proxy in front if other devices need it.", ["T1133"],
            Category.NETWORK))
    seen = set()
    for addr, port, name, cmdline, pid in listeners:
        if not exposed(addr) or port == 11434 or port in seen or not _MCP_PROC.search(cmdline or ""):
            continue
        seen.add(port)
        out.append(_finding(
            "AEG-AI-MCP-EXPOSED", f"An MCP server listens on every network interface (port {port})", Severity.MEDIUM,
            f"{name or 'A process'} (pid {pid}) runs {cmdline[:160]} and accepts connections from the whole network. Most "
            "MCP servers have no authentication, and many expose file or command tools, so anyone on the same network can "
            "use them ('NeighborJack').", f"0.0.0.0:{port}", {"port": port, "process": name, "pid": pid,
                                                              "command": cmdline[:500]},
            "Bind the server to 127.0.0.1 (most accept a --host option) or stop it.", ["T1133"], Category.NETWORK))
    return out


def collect_listeners() -> List[Tuple[str, int, str, str, int]]:
    out: List[Tuple[str, int, str, str, int]] = []
    try:
        import psutil

        for c in psutil.net_connections(kind="tcp"):
            if c.status != psutil.CONN_LISTEN or not c.laddr:
                continue
            name = cmdline = ""
            if c.pid:
                try:
                    p = psutil.Process(c.pid)
                    name, cmdline = p.name(), " ".join(p.cmdline())
                except Exception:
                    pass
            out.append((c.laddr.ip, c.laddr.port, name, cmdline, c.pid or 0))
    except Exception as exc:
        log.debug("listening sockets unavailable: %s", exc)
    return out


def ollama_version(timeout: float = 2.0) -> str:
    """Version from the local Ollama API (loopback only, no proxy). '' when it does not answer."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open("http://127.0.0.1:11434/api/version", timeout=timeout) as resp:
            doc = json.loads(resp.read(4096).decode("utf-8", "replace"))
        return str(doc.get("version") or "") if isinstance(doc, dict) else ""
    except (OSError, ValueError, socket.timeout):
        return ""


# =========================================================================== scanner
def project_dirs(ctx: ScanContext, max_seconds: float = 20.0) -> List[Path]:
    """Project folders (they hold a dependency file or a .git folder) under the user's developer folders."""
    from aegis.scanners.supplychain import SKIP_DIRS, resolve_roots

    roots = resolve_roots(ctx.paths or [], include_defaults=True)
    out: List[Path] = []
    t0 = time.monotonic()
    for root in roots:
        base = len(root.parts)
        for dirpath, dirnames, filenames in os.walk(root):
            if time.monotonic() - t0 > max_seconds or ctx.cancelled or len(out) >= 400:
                return out
            cur = Path(dirpath)
            names = set(dirnames) | set(filenames)
            if names & {".git", "package.json", "pyproject.toml", ".mcp.json", "AGENTS.md", "CLAUDE.md", ".cursorrules",
                        ".vscode", ".cursor", ".claude", "Cargo.toml", "go.mod"}:
                out.append(cur)
            if len(cur.parts) - base >= 5:
                dirnames[:] = []
            else:
                dirnames[:] = [d for d in dirnames if not d.startswith(".") and d.lower() not in SKIP_DIRS]
    return out


def collect_configs(home: Path, env: Mapping[str, str], projects: Sequence[Path]) -> List[AgentConfig]:
    out: List[AgentConfig] = []
    seen = set()
    candidates = [(app, kind, p, "user") for app, kind, p in user_config_files(home, env)]
    for proj in projects:
        candidates += [("project", kind, proj / rel, "project") for rel, kind in PROJECT_CONFIGS]
    for app, kind, path, scope in candidates:
        key = os.path.normcase(str(path))
        if key in seen:
            continue
        seen.add(key)
        text = _read(path, MAX_CONFIG)
        if text is None:
            continue
        if app == "project":
            app = {"mcp": "MCP", "gemini-settings": "Gemini CLI", "claude-settings": "Claude Code",
                   "codex-toml": "Codex CLI"}[kind] + " (project)"
        cfg = parse_config(app, kind, str(path), text, scope)
        if cfg is not None:
            out.append(cfg)
    return out


@register
class AIAgentsScanner(Scanner):
    name = "aiagents"
    title = "AI agents & MCP servers"
    description = "MCP servers, agent auto-approve modes, hooks, hidden instructions in AI rules/skills, exposed Ollama"

    def run(self, ctx: ScanContext) -> Iterator[Emitted]:
        home, env = user_home(), dict(os.environ)
        ctx.report(self.name, "finding AI agent configurations")
        projects = project_dirs(ctx)
        configs = collect_configs(home, env, projects)
        servers = [s for c in configs for s in c.servers]
        ctx.bump("ai_configs", len(configs))
        ctx.bump("mcp_servers", len(servers))
        for cfg in configs:
            yield from settings_findings(cfg)
            yield from token_findings(cfg)
        for s in servers:
            yield from server_findings(s)
        pkgs: Dict[Tuple[str, str, str], List[McpServer]] = {}
        for s in servers:
            spec = package_spec(s.command, s.args)
            if spec:
                pkgs.setdefault(spec, []).append(s)
        if pkgs and not ctx.cancelled:
            yield from self._osv(ctx, pkgs)
        f = unpinned_finding(pkgs)
        if f:
            yield f
        ctx.report(self.name, "checking AI instruction files and skills for hidden text")
        files: List[Path] = []
        for base in user_instruction_roots(home) + list(projects):
            files += find_instruction_files(base, depth=8 if base in user_instruction_roots(home) else 3)
        hidden = 0
        for path in dict.fromkeys(files):
            if ctx.cancelled:
                break
            text = _read(path)
            if text is not None:
                found = instruction_findings(str(path), text, instruction_kind(path))
                hidden += sum(f.rule_id == "AEG-AI-HIDDEN-TEXT" for f in found)
                yield from found[:MAX_FINDINGS_PER_KIND]
        ctx.bump("ai_instruction_files", len(files))
        yield CheckResult("AI-HIDDEN-TEXT", "AI instruction files and skills carry no hidden instructions",
                          CheckStatus.FAIL if hidden else CheckStatus.PASS,
                          f"{len(files)} instruction / skill file(s) checked", Category.SUSPICIOUS)
        ctx.report(self.name, "checking local AI servers")
        listeners = collect_listeners()
        version = ollama_version() if any(p == 11434 for _a, p, *_ in listeners) else ""
        yield from listener_findings(listeners, version, env.get("OLLAMA_HOST", ""))

    def _osv(self, ctx: ScanContext, pkgs: Dict[Tuple[str, str, str], List[McpServer]]) -> List[Finding]:
        from aegis.scanners.supplychain import _make_client
        from aegis.tools.osv import Pkg, norm_name

        client = _make_client(ctx)
        query = {spec: Pkg(spec[0], norm_name(spec[0], spec[1]), spec[2]) for spec in pkgs}
        try:
            res = client.query(list(query.values()), deadline=time.monotonic() + 30)
            client.save()
        except Exception as exc:
            log.debug("OSV lookup for MCP packages failed: %s", exc)
            return []
        return osv_findings(pkgs, {spec: res.get(pkg, []) for spec, pkg in query.items()})
