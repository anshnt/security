"""IDE extension scanner for the VS Code family (VS Code, Insiders, VSCodium, Cursor, Windsurf, Positron, Trae,
Kiro and the remote "-server" folders).

Malicious IDE extensions are a developer-targeted supply-chain channel (credential and wallet stealers, backdoors
delivered as themes, formatters or AI helpers). For every installed extension this scanner:

* looks the id (``publisher.name``) up in the blocklist built from Microsoft's list of extensions removed from the
  VS Code Marketplace (``aegis/data/malicious_ide_extensions.txt`` plus the copy refreshed by
  ``aegis.tools.ide_blocklist.update_ide_blocklist``): Malware -> CRITICAL, Impersonation / Typo-squatting -> HIGH,
  Untrustworthy -> MEDIUM;
* reads ``package.json`` (publisher, version, activationEvents, contributes, main) and, for extensions that are not
  from a well-known publisher, inspects the entry-point JavaScript: an extension that activates on ``*`` (or one with
  no marketplace metadata, i.e. a sideloaded VSIX) whose code is obfuscated AND uses child_process / eval, talks to raw
  IP addresses or carries a hard-coded Discord / Telegram webhook is reported (MEDIUM). Minified bundles alone are
  common and are not reported.

Well-known publishers installed from the Marketplace (e.g. ms-python.python, esbenp.prettier-vscode) are never run
through the code heuristics. JetBrains plugins are not covered.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

from aegis.core.models import Category, CheckResult, CheckStatus, Finding, Remediation, Severity
from aegis.core.platform import user_home
from aegis.scanners.base import Emitted, ScanContext, Scanner, register
from aegis.tools import ide_blocklist

log = logging.getLogger("aegis.ide")

# (display name, folder relative to the user's home). Windows uses the same layout under %USERPROFILE%.
IDE_EXTENSION_DIRS: Sequence[Tuple[str, str]] = (
    ("VS Code", ".vscode/extensions"),
    ("VS Code Insiders", ".vscode-insiders/extensions"),
    ("VSCodium", ".vscode-oss/extensions"),
    ("VSCodium", ".vscodium/extensions"),
    ("Cursor", ".cursor/extensions"),
    ("Windsurf", ".windsurf/extensions"),
    ("Positron", ".positron/extensions"),
    ("Trae", ".trae/extensions"),
    ("Kiro", ".kiro/extensions"),
    ("VS Code Server", ".vscode-server/extensions"),
    ("Cursor Server", ".cursor-server/extensions"),
    ("Windsurf Server", ".windsurf-server/extensions"),
)

# Publisher ids of well-known vendors. Only honoured for extensions with Marketplace install metadata.
TRUSTED_PUBLISHERS = frozenset({
    "microsoft", "ms-python", "ms-vscode", "ms-vscode-remote", "ms-dotnettools", "ms-toolsai", "ms-azuretools",
    "ms-kubernetes-tools", "ms-playwright", "ms-edgedevtools", "ms-windows-ai-studio", "github", "redhat", "golang",
    "rust-lang", "vscjava", "dbaeumer", "esbenp", "eamodio", "hashicorp", "streetsidesoftware", "formulahendry",
    "pkief", "christian-kohler", "bradlc", "yzhang", "ritwickdey", "hediet", "gruntfuggly", "editorconfig",
    "visualstudioexptteam", "oracle", "sonarsource", "docker", "eclipse-cdt", "llvm-vs-code-extensions", "vue",
    "svelte", "ms-ceintl", "tamasfe", "usernamehw", "anthropic", "openai", "continue",
})

CATEGORY_SEVERITY = {"malware": Severity.CRITICAL, "impersonation": Severity.HIGH, "untrustworthy": Severity.MEDIUM}
SOURCE_URL = ide_blocklist.SOURCE_PAGE
MAX_CODE_HEAD = 3 * 1024 * 1024
MAX_CODE_TAIL = 1024 * 1024
MAX_EXTENSIONS_PER_DIR = 800

_PRIVATE_V4 = re.compile(rb"^(?:0|10|127|169\.254|172\.(?:1[6-9]|2\d|3[01])|192\.168|22[4-9]|23\d|24\d|25[0-5])\.")
_IP_URL = re.compile(rb"(?:https?|wss?|ftp)://(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
_HEX_IDENT = re.compile(rb"\b_0x[0-9a-fA-F]{3,6}\b")
_CHILD_PROCESS = re.compile(rb"""require\(\s*['"](?:node:)?child_process['"]\s*\)|from\s+['"](?:node:)?child_process['"]|\bchild_process\b""")
_EVAL = re.compile(rb"\beval\s*\(|\bnew\s+Function\s*\(|\bvm\.runIn\w+\(")
_PACKER = re.compile(rb"\beval\(function\(p,a,c,k,e,[dr]\)")
_JSFUCK = re.compile(rb"\[\]\[\(!\[\]\+\[\]\)\[\+\[\]\]\+")
_EVAL_DECODE = re.compile(rb"\b(?:eval|Function)\s*\(\s*(?:atob|Buffer\.from|unescape|decodeURIComponent)\b")
_WEBHOOK = re.compile(rb"discord(?:app)?\.com/api/webhooks/\d{5,}/[\w-]{20,}|api\.telegram\.org/bot\d{6,}:[\w-]{30,}",
                      re.I)
_CRED_TOKENS = (b"Login Data", b"Local State", b"wallet.dat", b"id_rsa", b".git-credentials", b".npmrc",
                b"logins.json", b"key4.db", b"Exodus", b"MetaMask", b"credentials.json", b"Web Data")


@dataclass
class Ext:
    ide: str
    folder: Path
    ext_id: str  # lower-case "publisher.name"
    publisher: str = ""
    name: str = ""
    version: str = ""
    display_name: str = ""
    main: str = ""
    browser: str = ""
    activation: List[str] = field(default_factory=list)
    contributes: List[str] = field(default_factory=list)
    gallery: bool = False  # installed from a marketplace (has marketplace metadata)
    source: str = ""
    installed: Optional[int] = None
    publisher_display: str = ""

    @property
    def activates_always(self) -> bool:
        return "*" in self.activation

    @property
    def trusted_publisher(self) -> bool:
        return self.gallery and self.publisher.lower() in TRUSTED_PUBLISHERS


@dataclass
class CodeSignals:
    obfuscated: bool = False
    child_process: bool = False
    eval_use: bool = False
    raw_ips: List[str] = field(default_factory=list)
    webhooks: List[str] = field(default_factory=list)
    cred_tokens: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)

    @property
    def strong_network(self) -> bool:
        return bool(self.raw_ips or self.webhooks)

    @property
    def risky(self) -> bool:
        return ((self.obfuscated and (self.child_process or self.eval_use or self.strong_network))
                or (self.strong_network and (self.child_process or len(self.cred_tokens) >= 2)))


# --------------------------------------------------------------------------- reading extensions
def _load_json(path: Path, limit: int = 2 * 1024 * 1024) -> Any:
    try:
        if path.stat().st_size > limit:
            return None
        return json.loads(path.read_bytes().decode("utf-8", errors="replace").lstrip("﻿"))
    except (OSError, ValueError, RecursionError):
        return None


def extension_dirs(ctx: Optional[ScanContext] = None, home: Optional[Path] = None) -> List[Tuple[str, Path]]:
    """Existing extension folders of the supported IDEs (deduplicated)."""
    opt = ctx.options.get("ide_extension_dirs") if ctx is not None else None
    cands: List[Tuple[str, Path]] = []
    if isinstance(opt, (list, tuple)) and opt:
        cands = [("IDE", Path(str(p))) for p in opt]
    else:
        home = home or user_home()
        cands = [(name, home / rel) for name, rel in IDE_EXTENSION_DIRS]
        env = os.environ.get("VSCODE_EXTENSIONS")
        if env:
            cands.append(("VS Code", Path(env)))
    out: List[Tuple[str, Path]] = []
    seen = set()
    for name, p in cands:
        try:
            if not p.is_dir():
                continue
            key = os.path.normcase(str(p.resolve()))
        except OSError:
            continue
        if key not in seen:
            seen.add(key)
            out.append((name, p))
    return out


def read_extensions(ide: str, ext_dir: Path) -> List[Ext]:
    """Every installed (non-obsolete) extension of one extensions folder."""
    registry: Dict[str, Dict[str, Any]] = {}
    doc = _load_json(ext_dir / "extensions.json")
    for entry in doc if isinstance(doc, list) else []:
        if not isinstance(entry, dict):
            continue
        rel = entry.get("relativeLocation")
        if not isinstance(rel, str):
            loc = entry.get("location") if isinstance(entry.get("location"), dict) else {}
            rel = Path(str(loc.get("fsPath") or loc.get("path") or "")).name
        if rel:
            registry[rel.lower()] = entry
    obsolete = _load_json(ext_dir / ".obsolete")
    obsolete_keys = {k.lower() for k in obsolete} if isinstance(obsolete, dict) else set()

    out: List[Ext] = []
    try:
        folders = sorted(p for p in ext_dir.iterdir() if p.is_dir() and not p.name.startswith("."))
    except OSError:
        return out
    for folder in folders[:MAX_EXTENSIONS_PER_DIR]:
        if folder.name.lower() in obsolete_keys:
            continue
        manifest = _load_json(folder / "package.json")
        if not isinstance(manifest, dict):
            continue
        entry = registry.get(folder.name.lower(), {})
        ident = entry.get("identifier") if isinstance(entry.get("identifier"), dict) else {}
        meta = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else {}
        old_meta = manifest.get("__metadata") if isinstance(manifest.get("__metadata"), dict) else {}
        meta = {**old_meta, **meta}
        publisher = str(manifest.get("publisher") or "")
        name = str(manifest.get("name") or "")
        ext_id = str(ident.get("id") or "").lower() or (f"{publisher}.{name}".lower() if publisher and name else "")
        if not ext_id:
            m = re.match(r"^(.+?)-\d+(?:\.\d+)+", folder.name)
            ext_id = (m.group(1) if m else folder.name).lower()
        source = str(meta.get("source") or "")
        gallery = source == "gallery" or bool(meta.get("publisherId") and meta.get("id")) or \
            bool(ident.get("uuid") and source != "vsix")
        contributes = manifest.get("contributes") if isinstance(manifest.get("contributes"), dict) else {}
        events = manifest.get("activationEvents")
        out.append(Ext(
            ide=ide, folder=folder, ext_id=ext_id, publisher=publisher or ext_id.split(".")[0], name=name,
            version=str(manifest.get("version") or entry.get("version") or ""),
            display_name=str(manifest.get("displayName") or ""), main=str(manifest.get("main") or ""),
            browser=str(manifest.get("browser") or ""),
            activation=[e for e in events if isinstance(e, str)] if isinstance(events, list) else [],
            contributes=sorted(str(k) for k in contributes), gallery=gallery, source=source,
            installed=meta.get("installedTimestamp") if isinstance(meta.get("installedTimestamp"), int) else None,
            publisher_display=str(meta.get("publisherDisplayName") or "")))
    return out


# --------------------------------------------------------------------------- code heuristics
def _entry_files(ext: Ext) -> List[Path]:
    files: List[Path] = []
    for rel in (ext.main, ext.browser):
        if not rel:
            continue
        parts = [p for p in re.split(r"[\\/]+", rel) if p and p != "."]
        if not parts or ".." in parts or any(":" in p for p in parts):
            continue
        p = ext.folder.joinpath(*parts)
        for cand in (p, p.with_name(p.name + ".js")):
            try:
                if cand.is_file():
                    files.append(cand)
                    break
            except OSError:
                continue
    return files


def _read_head_tail(path: Path) -> bytes:
    try:
        size = path.stat().st_size
        with open(path, "rb") as fh:
            head = fh.read(MAX_CODE_HEAD)
            if size > MAX_CODE_HEAD + MAX_CODE_TAIL:
                fh.seek(max(size - MAX_CODE_TAIL, MAX_CODE_HEAD))
                return head + b"\n" + fh.read(MAX_CODE_TAIL)
            return head + (fh.read(MAX_CODE_TAIL) if size > MAX_CODE_HEAD else b"")
    except OSError:
        return b""


def analyze_code(data: bytes) -> CodeSignals:
    """Signals in extension JavaScript (bytes). Minified code alone is not a signal."""
    sig = CodeSignals()
    # Only fingerprints of real obfuscators count. Hex escapes and String.fromCharCode are NOT used: webpack bundles
    # of ordinary libraries (markdown renderers, parsers, unicode tables) contain thousands of both.
    hex_idents = len(_HEX_IDENT.findall(data))
    if hex_idents >= 30:
        sig.obfuscated = True
        sig.reasons.append(f"obfuscator-style identifiers ({hex_idents} _0x names)")
    if _PACKER.search(data):
        sig.obfuscated = True
        sig.reasons.append("packed with the eval(function(p,a,c,k,e,d)) packer")
    if _JSFUCK.search(data):
        sig.obfuscated = True
        sig.reasons.append("JSFuck-style encoding")
    if _EVAL_DECODE.search(data):
        sig.obfuscated = True
        sig.reasons.append("evaluates decoded data (eval of base64/unescaped text)")
    sig.child_process = bool(_CHILD_PROCESS.search(data))
    sig.eval_use = bool(_EVAL.search(data))
    if sig.child_process:
        sig.reasons.append("uses child_process")
    if sig.eval_use:
        sig.reasons.append("uses eval / new Function")
    ips = []
    for m in _IP_URL.finditer(data):
        ip = m.group(1)
        if _PRIVATE_V4.match(ip) or any(int(x) > 255 for x in ip.split(b".")):
            continue
        ips.append(ip.decode())
    sig.raw_ips = sorted(set(ips))[:8]
    if sig.raw_ips:
        sig.reasons.append("connects to raw public IP addresses (" + ", ".join(sig.raw_ips[:3]) + ")")
    sig.webhooks = sorted({m.group(0).decode("utf-8", "replace").split("/")[0].lower() + "/..." for m in _WEBHOOK.finditer(data)})[:4]
    if sig.webhooks:
        sig.reasons.append("hard-coded Discord/Telegram webhook or bot credentials")
    sig.cred_tokens = [t.decode() for t in _CRED_TOKENS if t in data]
    if len(sig.cred_tokens) >= 2:
        sig.reasons.append("references browser/wallet/credential stores (" + ", ".join(sig.cred_tokens[:4]) + ")")
    return sig


# --------------------------------------------------------------------------- findings
def _base_evidence(ext: Ext) -> Dict[str, Any]:
    ev: Dict[str, Any] = {"extension": ext.ext_id, "version": ext.version, "ide": ext.ide, "folder": str(ext.folder),
                          "publisher": ext.publisher, "display_name": ext.display_name,
                          "marketplace_install": ext.gallery, "activation_events": ext.activation[:10],
                          "contributes": ext.contributes[:12], "main": ext.main}
    if ext.installed:
        ev["installed_ms"] = ext.installed
    return {k: v for k, v in ev.items() if v not in ("", [], None)}


def _remediation(ext: Ext) -> Remediation:
    return Remediation("remove_path", {"path": str(ext.folder)},
                       f"Archive and remove the extension folder {ext.folder.name} (close {ext.ide} first)")


def blocklist_finding(ext: Ext, category: str, removed: str) -> Finding:
    sev = CATEGORY_SEVERITY.get(category, Severity.HIGH)
    label = f"{ext.display_name or ext.ext_id} ({ext.ext_id} {ext.version})".strip()
    why = {
        "malware": "Microsoft removed it from the VS Code Marketplace as malware",
        "impersonation": "Microsoft removed it from the VS Code Marketplace for impersonating another extension or publisher",
        "untrustworthy": "Microsoft removed it from the VS Code Marketplace as untrustworthy",
    }.get(category, "Microsoft removed it from the VS Code Marketplace")
    ev = _base_evidence(ext)
    ev.update(blocklist_category=category, removed=removed, source=SOURCE_URL)
    rec = (f"Close {ext.ide}, uninstall the extension (Extensions view > gear icon > Uninstall) or let Aegis archive and "
           "remove its folder, then restart the IDE. ")
    if category == "malware":
        rec += ("Treat the machine as exposed: an IDE extension runs with your user's full rights, so rotate tokens and "
                "keys reachable from this account (GitHub, npm, cloud, SSH, .env files), review recent commits and "
                "shell start-up files for changes you did not make, and run a full Aegis scan.")
    else:
        rec += "Reinstall the genuine extension from its verified publisher if you still need it."
    return Finding(
        rule_id="AEG-IDE-BLOCKLIST", title=f"Removed/malicious {ext.ide} extension installed: {label}",
        severity=sev, category=Category.MALWARE if category == "malware" else Category.SUSPICIOUS,
        description=f"The installed extension {ext.ext_id} is on the removed-extension list: {why}"
                    + (f" on {removed}" if removed else "") + ". IDE extensions run with the user's rights and can read "
                    "source code, environment variables and stored credentials.",
        location=str(ext.folder), evidence=ev, recommendation=rec, remediation=_remediation(ext),
        mitre=["T1195.002", "T1176.002"])


def code_finding(ext: Ext, sig: CodeSignals, sideloaded: bool) -> Finding:
    ev = _base_evidence(ext)
    ev.update(signals=sig.reasons, raw_ips=sig.raw_ips, webhooks=sig.webhooks, credential_store_refs=sig.cred_tokens[:6])
    if sideloaded:
        rule, title = "AEG-IDE-SIDELOAD-RISKY", f"Sideloaded {ext.ide} extension with risky code: {ext.ext_id}"
        why = ("it was not installed from a marketplace (a sideloaded VSIX, so nothing vets it) and its code is "
               "suspicious")
    else:
        rule, title = "AEG-IDE-SUSPICIOUS-CODE", f"{ext.ide} extension that activates on '*' with suspicious code: {ext.ext_id}"
        why = "it activates on every start-up ('*') and its code is suspicious"
    return Finding(
        rule_id=rule, title=title, severity=Severity.MEDIUM, category=Category.SUSPICIOUS,
        description=f"{ext.ext_id} {ext.version}: {why}: " + "; ".join(sig.reasons[:6]) + ". Legitimate extensions "
                    "rarely combine obfuscated code with process execution, raw-IP connections or hard-coded webhooks.",
        location=str(ext.folder), evidence=ev,
        recommendation=f"Check who published {ext.ext_id} and why you installed it. If you do not recognise it or cannot "
                       "verify the publisher, uninstall it and rotate credentials that were reachable from the IDE.",
        remediation=_remediation(ext), mitre=["T1195.002", "T1176.002"])


def classify_extension(ext: Ext, blocklist: Dict[str, Tuple[str, str]]) -> List[Finding]:
    """Findings for one installed extension (blocklist first, then code heuristics)."""
    hit = blocklist.get(ext.ext_id)
    if hit:
        return [blocklist_finding(ext, hit[0], hit[1])]
    if ext.trusted_publisher:
        return []
    sideloaded = not ext.gallery
    if ext.gallery and not ext.activates_always:
        return []
    data = b"\n".join(_read_head_tail(p) for p in _entry_files(ext))
    if not data:
        return []
    sig = analyze_code(data)
    if sig.risky:
        return [code_finding(ext, sig, sideloaded)]
    return []


def _blocklist_date(directory: Optional[Path]) -> str:
    """'Retrieved YYYY-MM-DD' stamp of the newest blocklist copy (empty if unknown)."""
    newest = ""
    paths = [ide_blocklist.PACKAGE_DATA / ide_blocklist.FILENAME]
    if directory is not None:
        paths.append(Path(directory) / ide_blocklist.FILENAME)
    for p in paths:
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as fh:
                head = fh.read(4096)
        except OSError:
            continue
        m = re.search(r"Retrieved (\d{4}-\d{2}-\d{2})", head)
        if m and m.group(1) > newest:
            newest = m.group(1)
    return newest


def scan_extensions(ctx: ScanContext, dirs: Optional[Sequence[Tuple[str, Path]]] = None) -> Iterator[Emitted]:
    title = "IDE extensions checked against the removed/malicious extension list"
    try:
        sigdir: Optional[Path] = Path(ctx.config.signatures_dir)
    except Exception:
        sigdir = None
    blocklist = ide_blocklist.load_blocklist(sigdir)
    dirs = list(dirs) if dirs is not None else extension_dirs(ctx)
    if not dirs:
        yield CheckResult("AEG-IDE-EXTENSIONS", title, CheckStatus.SKIP,
                          "no VS Code-family extension folders found", category=Category.SUSPICIOUS)
        return
    deadline = time.monotonic() + float(ctx.options.get("ide_max_seconds", 45))
    total, flagged = 0, 0
    for ide, d in dirs:
        ctx.report("ide", f"reading {d}")
        try:
            exts = read_extensions(ide, d)
        except Exception as exc:
            log.debug("could not read extensions in %s: %s", d, exc)
            continue
        for ext in exts:
            if ctx.cancelled:
                return
            total += 1
            ctx.bump("ide_extensions")
            try:
                if time.monotonic() > deadline:  # budget exhausted: only the (cheap) blocklist lookup still runs
                    found = [blocklist_finding(ext, *blocklist[ext.ext_id])] if ext.ext_id in blocklist else []
                else:
                    found = classify_extension(ext, blocklist)
            except Exception as exc:  # one hostile extension must not stop the scan
                log.debug("could not analyse %s: %s", ext.ext_id, exc)
                continue
            for f in found:
                flagged += 1
                yield f
    stamp = _blocklist_date(sigdir)
    detail = (f"{total} extension(s) in {len(dirs)} IDE folder(s) checked against {len(blocklist)} listed ids"
              + (f" (list dated {stamp})" if stamp else ""))
    if not blocklist:
        yield CheckResult("AEG-IDE-EXTENSIONS", title, CheckStatus.WARN, "the extension blocklist is empty or missing; "
                          + detail, category=Category.SUSPICIOUS)
    elif flagged:
        yield CheckResult("AEG-IDE-EXTENSIONS", title, CheckStatus.FAIL, f"{flagged} extension(s) flagged; " + detail,
                          category=Category.SUSPICIOUS)
    else:
        yield CheckResult("AEG-IDE-EXTENSIONS", title, CheckStatus.PASS, detail, category=Category.SUSPICIOUS)


@register
class IdeExtensionScanner(Scanner):
    name = "ide"
    title = "IDE extensions (VS Code, Cursor, Windsurf, VSCodium)"
    description = ("Checks installed VS Code-family extensions against Microsoft's removed-extension list and flags "
                   "always-active or sideloaded extensions with obfuscated, process-spawning or webhook-exfiltrating code")
    platforms = ("windows", "linux", "darwin")

    def run(self, ctx: ScanContext) -> Iterator[Emitted]:
        try:
            yield from scan_extensions(ctx)
        except Exception as exc:  # never raise out of run()
            log.warning("ide scan failed: %s", exc, exc_info=True)
            yield CheckResult("AEG-IDE-ERROR", "IDE extension scan", CheckStatus.ERROR, f"{type(exc).__name__}: {exc}",
                              category=Category.SUSPICIOUS)
