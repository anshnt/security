"""Software supply-chain scanner for developer machines.

Finds local project dependency manifests and lockfiles (under the scan paths, or the usual
developer folders when none are given), reads them with the parsers in ``aegis.tools.lockfiles`` and:

* asks OSV.dev (https://api.osv.dev, no key needed) about every pinned package version - known
  vulnerabilities and, via ``MAL-*`` advisories of the OpenSSF malicious-packages dataset, known
  *malicious* packages. Answers are cached for 24 h (``<data>/osv_cache.json``) so repeat and
  offline scans keep working; with no network the scan says "offline - results from cache only".
* runs offline heuristics: risky npm install scripts (curl/wget/PowerShell/base64/eval/child_process/
  ``node -e``/``bun x``), typosquats of popular npm and PyPI packages, the Shai-Hulud worm family
  (workflow files, payload hashes and file layout, trufflehog in install hooks, the SHA1HULUD runner)
  and VS Code ``tasks.json`` files that run a download-and-execute command when a folder is opened.

Secrets in ``.npmrc`` / ``.pypirc`` are the secrets scanner's job and are not duplicated here.

Severity notes: ``MAL-*`` matches and worm IOCs are CRITICAL (active threat). Ordinary vulnerable-package
findings are capped at HIGH even when OSV rates them CRITICAL (the OSV rating stays in the evidence)
because a CRITICAL finding forces the whole-machine score to F, which is reserved for active threats.

Public helper: ``scan_project(path, ctx=None) -> List[Finding]`` (for ``aegis check-project PATH``).
Options read from ``ctx.options``: ``supplychain_online`` (default True), ``supplychain_default_dirs``
(True), ``supplychain_max_depth`` (6), ``supplychain_max_seconds`` (60), ``supplychain_max_entries``
(300000), ``supplychain_cache_ttl_hours`` (24), ``supplychain_osv_seconds`` (120).
"""

from __future__ import annotations

import functools
import hashlib
import json
import logging
import os
import re
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Set, Tuple

from aegis.core.config import PACKAGE_DATA
from aegis.core.models import Category, CheckResult, CheckStatus, Finding, Remediation, Severity
from aegis.core.platform import IS_WINDOWS, env_path, user_home
from aegis.scanners.base import Emitted, ScanContext, Scanner, register
from aegis.tools import lockfiles as lf
from aegis.tools.osv import OsvClient, Pkg, VulnInfo, fixed_key, norm_name, pick_fixed, version_key

log = logging.getLogger("aegis.supplychain")

POPULAR_FILE = PACKAGE_DATA / "popular_packages.json"

# --------------------------------------------------------------------------- tunables
SKIP_DIRS = frozenset({
    "node_modules", "bower_components", "jspm_packages", "venv", "env", "virtualenv", "site-packages",
    "dist-packages", "__pycache__", "cache", "vendor", "target", "build", "dist", "out", "obj", "bin", "pods",
    "carthage", "deriveddata", "appdata", "library", "$recycle.bin", "system volume information", "windows",
    "program files", "program files (x86)", "programdata", "onedrivetemp", "temp", "tmp",
})
DEV_DIR_NAMES = ("source", "src", "repos", "projects", "code", "dev", "git", "workspace", "workspaces", "work",
                 "github", "gitlab", "developer", "Documents", "Desktop", "Downloads")
MAX_VULN_FINDINGS_PER_PROJECT = 25
MAX_MAL_FINDINGS_PER_PROJECT = 100
MAX_INSTALLED_PACKAGES_READ = 300
MAX_TEXT_READ = 512 * 1024
VULN_SEVERITY_CAP = Severity.HIGH  # see module docstring

INSTALL_HOOKS = ("preinstall", "install", "postinstall")
ROOT_ONLY_HOOKS = ("prepare", "prepublish", "preprepare", "postprepare")

# Hashes published by incident responders (file content, SHA-256). Sources:
#   StepSecurity / Wiz (bundle.js, Sept 2025); Datadog Security Labs and Palo Alto Unit 42 (Shai-Hulud 2.0, Nov 2025)
KNOWN_WORM_SHA256 = {
    "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09": "Shai-Hulud (Sept 2025) bundle.js",
    "a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a": "Shai-Hulud 2.0 (Nov 2025) setup_bun.js",
    "62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0": "Shai-Hulud 2.0 (Nov 2025) bun_environment.js",
    "f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068": "Shai-Hulud 2.0 (Nov 2025) bun_environment.js",
    "cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd": "Shai-Hulud 2.0 (Nov 2025) bun_environment.js",
}
WORM_REFERENCES = [
    "https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised",
    "https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack",
    "https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/",
    "https://unit42.paloaltonetworks.com/npm-supply-chain-attack/",
]
_WORM_BUNDLE_MARKERS = (b"shai-hulud", b"webhook.site", b"trufflehog")


# --------------------------------------------------------------------------- small helpers
def _ev(**kw: Any) -> Dict[str, Any]:
    return {k: v for k, v in kw.items() if v not in (None, "", [], {})}


def _short(text: str, n: int = 400) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[: n - 3] + "..."


def _read_text(path: Path, limit: int = MAX_TEXT_READ) -> Optional[str]:
    try:
        with open(path, "rb") as fh:
            return fh.read(limit).decode("utf-8", errors="replace").lstrip("\ufeff")
    except OSError:
        return None


def _sha256_file(path: Path, limit: int = 64 * 1024 * 1024) -> Optional[str]:
    try:
        if path.stat().st_size > limit:
            return None
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _safe_join(base: Path, rel: str) -> Optional[Path]:
    """base/rel when rel stays inside base (lockfile paths are untrusted text)."""
    parts = [p for p in re.split(r"[\\/]+", rel) if p]
    if not parts or any(p in ("..", ".") or ":" in p for p in parts):
        return None
    return base.joinpath(*parts)


def _safe_token(s: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9@/_.:+~^-]{1,214}", s))


# --------------------------------------------------------------------------- popular packages / typosquats
@dataclass
class Popular:
    npm: List[str] = field(default_factory=list)
    pypi: List[str] = field(default_factory=list)
    npm_known: Set[str] = field(default_factory=set)
    pypi_known: Set[str] = field(default_factory=set)
    scopes: Set[str] = field(default_factory=set)
    skeleton: Dict[str, str] = field(default_factory=dict)


_FALLBACK_NPM = ["react", "react-dom", "lodash", "express", "axios", "chalk", "commander", "debug", "typescript",
                 "webpack", "eslint", "prettier", "jest", "moment", "uuid", "yargs", "semver", "glob", "rimraf"]
_FALLBACK_PYPI = ["requests", "numpy", "pandas", "django", "flask", "boto3", "urllib3", "setuptools", "pytest",
                  "cryptography", "pyyaml", "pillow", "sqlalchemy", "jinja2", "click", "certifi", "idna"]


def _strip_sep(s: str) -> str:
    return re.sub(r"[-_.]", "", s)


def _skeleton(s: str) -> str:
    """Visual skeleton: separators dropped, 0->o, 1->l, rn->m, vv->w (all lower case)."""
    s = _strip_sep(s.lower()).replace("rn", "m").replace("vv", "w")
    return s.translate(str.maketrans({"0": "o", "1": "l", "|": "l"}))


@functools.lru_cache(maxsize=1)
def popular() -> Popular:
    data: Dict[str, Any] = {}
    try:
        data = json.loads(POPULAR_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        log.debug("popular package list unavailable (%s); using a minimal built-in list", exc)

    def names(key: str, fallback: Sequence[str]) -> List[str]:
        v = data.get(key)
        return [str(x).lower() for x in v if isinstance(x, str)] if isinstance(v, list) and v else list(fallback)

    pop = Popular(npm=names("npm", _FALLBACK_NPM), pypi=[norm_name("PyPI", n) for n in names("pypi", _FALLBACK_PYPI)])
    pop.npm_known = set(pop.npm) | set(names("npm_legit", ()))
    pop.pypi_known = set(pop.pypi) | {norm_name("PyPI", n) for n in names("pypi_legit", ())}
    pop.scopes = set(names("npm_scopes", ("@angular", "@babel", "@types")))
    pop.skeleton = {n: _skeleton(n) for n in pop.npm + pop.pypi}
    return pop


def is_popular(ecosystem: str, name: str) -> bool:
    """Well-known package (never a typosquat suspect; its own install scripts are trusted)."""
    pop = popular()
    if ecosystem == lf.NPM:
        return name.lower() in pop.npm_known
    if ecosystem == lf.PYPI:
        return norm_name(ecosystem, name) in pop.pypi_known
    return False


def _dl1(a: str, b: str) -> bool:
    """True when the (Damerau) edit distance between a and b is exactly 1."""
    if a == b:
        return False
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        diffs = [i for i in range(la) if a[i] != b[i]]
        if len(diffs) == 1:
            return True
        return (len(diffs) == 2 and diffs[1] == diffs[0] + 1 and a[diffs[0]] == b[diffs[1]]
                and a[diffs[1]] == b[diffs[0]])
    s, l = (a, b) if la < lb else (b, a)
    i = 0
    while i < len(s) and s[i] == l[i]:
        i += 1
    return s[i:] == l[i + 1:]


def typosquat_of(ecosystem: str, name: str) -> Optional[Tuple[str, str]]:
    """(popular package it imitates, reason) or None. Only unknown names are suspects."""
    pop = popular()
    low = name.strip().lower()
    if ecosystem == lf.NPM:
        if low.startswith("@"):  # scoped: only the scope can imitate a popular scope
            scope = low.partition("/")[0]
            if scope in pop.scopes or "/" not in low:
                return None
            for s in sorted(pop.scopes):
                if len(s) >= 6 and _dl1(scope, s):
                    return s, "the scope differs from the popular scope by one character"
            return None
        norm, targets, known = low, pop.npm, pop.npm_known
    elif ecosystem == lf.PYPI:
        norm, targets, known = norm_name(ecosystem, name), pop.pypi, pop.pypi_known
    else:
        return None
    if len(norm) < 4 or norm in known or not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", norm):
        return None
    skel = _skeleton(norm)
    for t in targets:
        if len(t) < 5 or t == norm:
            continue
        if _dl1(norm, t):
            return t, "one character added, removed, changed or swapped"
        if pop.skeleton.get(t) == skel:
            return t, "same name apart from look-alike characters or separators"
    return None


# --------------------------------------------------------------------------- command analysis
_RX = {
    "download": re.compile(r"\b(?:curl|wget)\b|\b(?:invoke-webrequest|invoke-restmethod|iwr|irm)\b|"
                           r"\bcertutil(?:\.exe)?\b[^&|;\n]*-urlcache|\bbitsadmin\b|\bstart-bitstransfer\b", re.I),
    "pipe_shell": re.compile(r"(?<!\|)\|(?!\|)\s*(?:sudo\s+)?(?:(?:ba|z|da|k|c)?sh|iex|invoke-expression|cmd(?:\.exe)?|"
                             r"node|python3?|perl|ruby)(?![\w.-])", re.I),
    "powershell": re.compile(r"\b(?:powershell|pwsh)(?:\.exe)?\b", re.I),
    "ps_enc_hidden": re.compile(r"(?:^|\s)[-/](?:e|ec|enc|encodedcommand)\b|[-/]w(?:indowstyle)?\s+hidden", re.I),
    "iex": re.compile(r"\b(?:iex|invoke-expression)\b", re.I),
    "encoded": re.compile(r"\bbase64\s+(?:-d\b|-D\b|--decode\b|-w\b)|\|\s*base64\b|\batob\s*\(|\bfrombase64string\b|"
                          r"['\"]base64['\"]|\bcertutil\b[^&|;\n]*-decode|\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){7,}", re.I),
    "eval": re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(|\bvm\.run\w*\(", re.I),
    "child_process": re.compile(r"\bchild_process\b|\bexecSync\s*\(|\bspawnSync\s*\(", re.I),
    "runtime_fetch": re.compile(r"\bbun\s+x\b|\bbunx\b|\bdeno\s+run\s+(?:-\S+\s+)*https?://|"
                                r"\bnpx\s+(?:-\S+\s+)*(?:https?://|github:|git\+)", re.I),
    "raw_ip_url": re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}(?![\d.])"),
    "exfil_host": re.compile(r"discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot|webhook\.site|requestbin|"
                             r"pipedream\.net|ngrok(?:-free)?\.(?:io|app|dev)|pastebin\.com/raw|transfer\.sh|"
                             r"trycloudflare\.com|interact\.sh|oast\.(?:pro|live|site|online|fun|me)", re.I),
    "worm": re.compile(r"trufflehog|shai-?hulud|sha1-?hulud|setup_bun\.js|bun_environment\.js", re.I),
}
_NODE_E = re.compile(r"""\bnode(?:js)?(?:\.exe)?\s+(?:-e|--eval|-p|--print)\s+"""
                     r"""(?:(?P<q>["'])(?P<code>.*?)(?<!\\)(?P=q)|(?P<bare>\S+))""", re.S | re.I)
_NODE_E_RISK = re.compile(r"child_process|\bexec|\bspawn|\beval\b|new\s+Function|\bfetch\s*\(|\bdns\b|XMLHttpRequest|"
                          r"\batob\b|base64|writeFile|appendFile|\bunlink|\brm(?:Sync)?\s*\(|homedir|\.ssh|\.npmrc|"
                          r"\.aws|hostname|userInfo|\bnpm_token|github_token", re.I)
_REQUIRE_NON_RELATIVE = re.compile(r"require\(\s*['\"](?!\.{1,2}/)")


def _private_ip(url: str) -> bool:
    """Loopback / private / link-local addresses are normal in development scripts."""
    m = re.match(r"https?://(\d+)\.(\d+)\.(\d+)\.(\d+)", url)
    if not m:
        return True
    a, b = int(m.group(1)), int(m.group(2))
    return (a in (0, 10, 127) or (a == 169 and b == 254) or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)
            or a >= 224 or any(int(x) > 255 for x in m.groups()))


def _node_e_split(cmd: str) -> Tuple[str, bool]:
    """Remove harmless ``node -e`` snippets (prints a message, requires a relative file, enforces a package
    manager ...) from `cmd`; report whether a risky one remains."""
    risky = False

    def repl(m: "re.Match[str]") -> str:
        nonlocal risky
        code = m.group("code") if m.group("code") is not None else (m.group("bare") or "")
        if _NODE_E_RISK.search(code) or _REQUIRE_NON_RELATIVE.search(code):
            risky = True
            return m.group(0)
        return " "

    return _NODE_E.sub(repl, cmd), risky


def analyze_command(cmd: str) -> Tuple[Optional[Severity], List[str]]:
    """Rate a lifecycle-script / task command line. None = nothing notable.
    CRITICAL: Shai-Hulud tooling. HIGH: download-and-execute, encoded payload execution, hidden/encoded PowerShell,
    raw-IP or exfil endpoints combined with download/exec. MEDIUM: any single risky capability."""
    if not cmd or not isinstance(cmd, str):
        return None, []
    text, node_e = _node_e_split(cmd)
    hit = {k: bool(rx.search(text)) for k, rx in _RX.items()}
    hit["ps_enc_hidden"] = hit["powershell"] and hit["ps_enc_hidden"]  # '-e' alone (node -e) is not PowerShell
    hit["raw_ip_url"] = any(not _private_ip(m) for m in _RX["raw_ip_url"].findall(text))
    if hit["worm"]:
        return Severity.CRITICAL, ["references Shai-Hulud worm tooling (trufflehog / setup_bun.js / bun_environment.js)"]
    reasons: List[str] = []
    labels = [("download", "downloads data with curl/wget/PowerShell"), ("pipe_shell", "pipes output into a shell or interpreter"),
              ("powershell", "starts PowerShell"), ("ps_enc_hidden", "uses hidden or encoded PowerShell options"),
              ("iex", "uses Invoke-Expression"), ("encoded", "decodes base64 or hex-escaped data"),
              ("eval", "evaluates dynamic code (eval / new Function)"), ("child_process", "spawns processes from JavaScript"),
              ("runtime_fetch", "fetches and runs a remote package or script (bun x / npx URL / deno run URL)"),
              ("raw_ip_url", "contacts a raw IP address"), ("exfil_host", "contacts a webhook / paste / tunnel service")]
    for key, label in labels:
        if hit[key]:
            reasons.append(label)
    if node_e:
        reasons.append("runs inline code with node -e")
    if not reasons:
        return None, []
    run_like = hit["pipe_shell"] or hit["iex"] or hit["eval"] or hit["child_process"] or node_e
    sev = Severity.MEDIUM
    if ((hit["download"] and run_like) or (hit["encoded"] and (run_like or hit["powershell"]))
            or (hit["powershell"] and hit["ps_enc_hidden"])
            or ((hit["raw_ip_url"] or hit["exfil_host"]) and (hit["download"] or run_like or hit["powershell"]))):
        sev = Severity.HIGH
    return sev, reasons


# --------------------------------------------------------------------------- JSONC (tasks.json)
def load_jsonc(text: str) -> Any:
    """Parse JSON with comments and trailing commas (VS Code settings files). None on failure."""
    out: List[str] = []
    i, n, in_str = 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
        elif c == '"':
            in_str = True
            out.append(c)
            i += 1
        elif c == "/" and text[i + 1:i + 2] == "/":
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif c == "/" and text[i + 1:i + 2] == "*":
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            out.append(c)
            i += 1
    stripped = "".join(out)
    # drop trailing commas (outside strings)
    res: List[str] = []
    in_str = False
    k, m = 0, len(stripped)
    while k < m:
        c = stripped[k]
        if in_str:
            res.append(c)
            if c == "\\" and k + 1 < m:
                res.append(stripped[k + 1])
                k += 2
                continue
            if c == '"':
                in_str = False
        elif c == '"':
            in_str = True
            res.append(c)
        elif c == ",":
            j = k + 1
            while j < m and stripped[j] in " \t\r\n":
                j += 1
            if j < m and stripped[j] in "}]":
                k += 1
                continue
            res.append(c)
        else:
            res.append(c)
        k += 1
    try:
        return json.loads("".join(res))
    except (ValueError, RecursionError):
        return None


# --------------------------------------------------------------------------- discovery
@dataclass
class Budget:
    max_depth: int = 6
    max_seconds: float = 60.0
    max_entries: int = 300_000
    max_projects: int = 400


@dataclass
class Discovery:
    projects: Dict[Path, List[Path]] = field(default_factory=dict)
    workflow_dirs: List[Path] = field(default_factory=list)
    vscode_dirs: List[Path] = field(default_factory=list)
    entries: int = 0
    truncated: bool = False
    seconds: float = 0.0


def _norm_key(p: Path) -> str:
    try:
        p = p.resolve()
    except OSError:
        pass
    return os.path.normcase(str(p))


def _is_fs_root(p: Path) -> bool:
    try:
        return p.parent == p or (IS_WINDOWS and len(p.parts) == 1)
    except Exception:
        return False


def _temp_roots() -> Set[str]:
    cands = [tempfile.gettempdir(), "/tmp", "/var/tmp", "/dev/shm", "/private/tmp"]
    for var in ("TEMP", "TMP"):
        v = os.environ.get(var)
        if v:
            cands.append(v)
    if IS_WINDOWS:
        cands.append(str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Temp"))
    return {os.path.normcase(os.path.normpath(c)) for c in cands}


def default_roots(home: Optional[Path] = None) -> List[Path]:
    """Usual developer folders under the user's home (only those that exist)."""
    home = home or user_home()
    names: List[str] = []
    for n in DEV_DIR_NAMES:
        names += [n, n.title()]
    cands = [home / n for n in dict.fromkeys(names)]
    cands.append(home / "source" / "repos")
    cands.append(home / "go" / "src")
    try:
        for od in sorted(home.glob("OneDrive*")):
            cands += [od / "Documents", od / "Desktop"]
    except OSError:
        pass
    userprofile = env_path("USERPROFILE") if IS_WINDOWS else None
    if userprofile and userprofile != home:
        cands.append(userprofile / "source" / "repos")
    return [c for c in cands if _isdir(c)]


def _isdir(p: Path) -> bool:
    try:
        return p.is_dir()
    except OSError:
        return False


def resolve_roots(paths: Sequence[Path], include_defaults: bool = True, home: Optional[Path] = None) -> List[Path]:
    """Scan roots: explicit non-root, non-temp paths; drive/filesystem roots are replaced by the dev folders
    under them; plus the user's default developer folders. Nested roots are collapsed."""
    temps = _temp_roots()
    roots: List[Path] = []
    for p in paths:
        p = Path(p)
        if _is_fs_root(p):
            for n in ("dev", "src", "source", "repos", "projects", "code", "git", "workspace", "work"):
                for cand in (p / n, p / n.title()):
                    if _isdir(cand):
                        roots.append(cand)
        elif os.path.normcase(os.path.normpath(str(p))) in temps:
            continue
        elif _isdir(p):
            roots.append(p)
    if include_defaults:
        roots += default_roots(home)
    seen: Dict[str, Path] = {}
    for r in roots:
        seen.setdefault(_norm_key(r), r)
    keys = sorted(seen, key=len)
    kept: List[str] = []
    for k in keys:  # drop roots nested inside an already-kept root
        if not any(k == a or k.startswith(a.rstrip(os.sep) + os.sep) for a in kept):
            kept.append(k)
    return [seen[k] for k in kept]


def discover(roots: Sequence[Path], budget: Budget, cancelled: Callable[[], bool] = lambda: False) -> Discovery:
    """Walk the roots (depth/time/entry budgets) collecting dependency files per directory."""
    d = Discovery()
    t0 = time.monotonic()
    visited: Set[str] = set()
    for root in roots:
        base = len(Path(root).parts)
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            d.entries += len(dirnames) + len(filenames)
            if d.entries > budget.max_entries or time.monotonic() - t0 > budget.max_seconds or cancelled():
                d.truncated = True
                break
            cur = Path(dirpath)
            key = os.path.normcase(dirpath)
            if key in visited:
                dirnames[:] = []
                continue
            visited.add(key)
            if "pyvenv.cfg" in filenames:  # a virtual environment: nothing of the user's is in there
                dirnames[:] = []
                continue
            found = [cur / fn for fn in filenames if lf.classify(fn, cur.name)]
            if found and len(d.projects) < budget.max_projects:
                d.projects[cur] = found
            if ".github" in dirnames and _isdir(cur / ".github" / "workflows"):
                d.workflow_dirs.append(cur)
            if ".vscode" in dirnames and (cur / ".vscode" / "tasks.json").is_file():
                d.vscode_dirs.append(cur)
            if len(cur.parts) - base >= budget.max_depth:
                dirnames[:] = []
            else:
                dirnames[:] = [n for n in dirnames if not n.startswith(".") and n.lower() not in SKIP_DIRS
                               and not n.lower().endswith((".egg-info", ".dist-info"))]
        else:
            continue
        break  # budget hit
    d.seconds = round(time.monotonic() - t0, 2)
    return d


# --------------------------------------------------------------------------- project model
@dataclass
class Use:
    """One package version used by a project (merged across its lockfiles)."""

    dep: lf.Dep
    files: List[str] = field(default_factory=list)

    @property
    def pkg(self) -> Pkg:
        return Pkg(self.dep.ecosystem, norm_name(self.dep.ecosystem, self.dep.name), self.dep.version)


@dataclass
class Project:
    path: Path
    files: List[Path]
    uses: Dict[str, Use] = field(default_factory=dict)  # by Dep.key
    declared: List[lf.Dep] = field(default_factory=list)  # package.json / requirements / pyproject entries
    meta: Dict[str, Any] = field(default_factory=dict)  # package.json metadata
    package_json: Optional[Path] = None
    lock_files: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


def load_project(path: Path, files: Sequence[Path]) -> Project:
    proj = Project(path, list(files))
    parsed = [lf.parse_file(f) for f in sorted(files, key=lambda p: p.name.lower())]
    has_gomod = any(p.kind == "go.mod" and p.deps for p in parsed)
    lock_ecos: Set[str] = set()
    for p in parsed:
        if p.error:
            proj.errors.append(f"{Path(p.path).name}: {p.error}")
        if p.kind == "package.json":
            proj.package_json = Path(p.path)
            proj.meta = p.meta
        if p.kind in lf.LOCK_KINDS and p.deps:
            proj.lock_files.append(p.path)
            lock_ecos.update(d.ecosystem for d in p.deps)
    declared_names: Dict[str, Set[str]] = {}
    for p in parsed:
        if p.kind == "go.sum" and has_gomod:
            continue
        for dep in p.deps:
            if p.kind in ("package.json", "pyproject") or (p.kind == "requirements" and not dep.version):
                proj.declared.append(dep)
                declared_names.setdefault(dep.ecosystem, set()).add(
                    norm_name(dep.ecosystem, dep.name))
            if not dep.version:
                continue
            if p.kind in ("package.json", "pyproject") and dep.ecosystem in lock_ecos:
                continue  # the lockfile has the resolved version
            use = proj.uses.get(dep.key)
            if use is None:
                proj.uses[dep.key] = Use(dep, [p.path])
            else:
                if p.path not in use.files:
                    use.files.append(p.path)
                use.dep.direct = use.dep.direct or dep.direct
                use.dep.dev = use.dep.dev and dep.dev
                use.dep.install_script = use.dep.install_script or dep.install_script
    # direct-dependency marking for lockfiles that do not record it (yarn, pnpm, npm v1, poetry ...)
    for use in proj.uses.values():
        if norm_name(use.dep.ecosystem, use.dep.name) in declared_names.get(use.dep.ecosystem, ()):
            use.dep.direct = True
    for dep in proj.declared:  # declared-only names (ranges) still need name checks
        dep.direct = True
    return proj


# --------------------------------------------------------------------------- finding helpers
def _finding(rule: str, title: str, sev: Severity, category: str, description: str, location: str,
             evidence: Dict[str, Any], recommendation: str, mitre: Sequence[str],
             remediation: Optional[Remediation] = None) -> Finding:
    return Finding(rule_id=rule, title=title, severity=sev, category=category, description=description,
                   location=location, evidence=evidence, recommendation=recommendation, remediation=remediation,
                   mitre=list(mitre))


_COMPROMISE_STEPS = (
    "Do not run npm/pip/build commands in this project until it is clean. Remove or replace the package, delete "
    "node_modules / virtual environments and reinstall from a verified lockfile (pin to a version published before "
    "the compromise). Treat this computer and every credential reachable from it as exposed: from a different, clean "
    "device rotate npm, GitHub, cloud (AWS/Azure/GCP), SSH and CI tokens and revoke active sessions. Check for "
    "persistence and spread: new scheduled tasks / Run keys / cron or systemd user units / shell start-up files, "
    "unfamiliar GitHub Actions workflows, repositories, branches or self-hosted runners in your GitHub account, and "
    "recently published packages under your npm account. Then run a full Aegis scan.")


def _location(file: str, eco: str, name: str, version: str) -> str:
    return f"{file}#{eco}/{name}@{version}"


# --------------------------------------------------------------------------- local (offline) checks
def check_worm_files(pkg_dir: Path, scripts: Dict[str, str], where: str = "") -> List[Finding]:
    """Shai-Hulud payload files in a package/project folder: known SHA-256, marker strings, or the file layout."""
    out: List[Finding] = []
    hooks = " ".join(scripts.get(h, "") for h in INSTALL_HOOKS).lower()
    for fname in ("bundle.js", "setup_bun.js", "bun_environment.js"):
        p = pkg_dir / fname
        try:
            if not p.is_file():
                continue
            size = p.stat().st_size
        except OSError:
            continue
        digest = _sha256_file(p)
        reasons: List[str] = []
        sev = None
        if digest and digest in KNOWN_WORM_SHA256:
            sev, reasons = Severity.CRITICAL, [f"SHA-256 matches {KNOWN_WORM_SHA256[digest]}"]
        elif fname == "bundle.js" and "bundle.js" in hooks:
            head = b""
            try:
                with open(p, "rb") as fh:
                    head = fh.read(8 * 1024 * 1024).lower()
            except OSError:
                pass
            found = [m.decode() for m in _WORM_BUNDLE_MARKERS if m in head]
            if len(found) >= 2:
                sev, reasons = Severity.CRITICAL, [f"install hook runs bundle.js containing {', '.join(found)}"]
            elif size >= 1024 * 1024:
                sev, reasons = Severity.MEDIUM, ["install hook runs a large bundled script (bundle.js) - the Shai-Hulud "
                                                 "payload had this shape; verify the package source"]
        elif fname == "setup_bun.js" and "setup_bun.js" in hooks and (pkg_dir / "bun_environment.js").is_file():
            sev, reasons = Severity.CRITICAL, ["preinstall runs setup_bun.js next to bun_environment.js (Shai-Hulud 2.0 layout)"]
        if sev is None:
            continue
        out.append(_finding(
            "AEG-SC-SHAIHULUD",
            f"Shai-Hulud npm worm payload: {fname}" if sev == Severity.CRITICAL else f"Possible Shai-Hulud-style payload: {fname}",
            sev,
            Category.MALWARE if sev == Severity.CRITICAL else Category.SUSPICIOUS,
            "A file matching the Shai-Hulud self-replicating npm worm was found. The worm steals GitHub, npm and cloud "
            "credentials at install time and republishes the victim's own packages with the payload added. "
            + "; ".join(reasons) + ".",
            str(p), _ev(file=str(p), sha256=digest, size=size, reasons=reasons, package_dir=str(pkg_dir), where=where,
                        references=WORM_REFERENCES),
            _COMPROMISE_STEPS, ["T1195.002", "T1552.001"],
            Remediation("quarantine_file", {"path": str(p)}, f"Quarantine {fname}") if sev == Severity.CRITICAL else None))
    return out


def check_scripts(package_json_path: str, name: str, version: str, scripts: Dict[str, str],
                  own_project: bool, trusted: bool) -> List[Finding]:
    """Findings for risky lifecycle scripts of a package.json (the project's own or an installed package's)."""
    out: List[Finding] = []
    hooks = INSTALL_HOOKS + (ROOT_ONLY_HOOKS if own_project else ())
    for hook in hooks:
        cmd = scripts.get(hook)
        if not cmd:
            continue
        sev, reasons = analyze_command(cmd)
        if sev is None or (trusted and sev != Severity.CRITICAL):
            continue
        label = f"{name}@{version}" if version else name
        if sev == Severity.CRITICAL:
            out.append(_finding(
                "AEG-SC-SHAIHULUD", f"Shai-Hulud tooling in {hook} script of {label}", sev, Category.MALWARE,
                f"The {hook} script references Shai-Hulud worm tooling ({_short(cmd, 160)}). Running it steals "
                "developer credentials and spreads to the packages you publish.",
                f"{package_json_path}#scripts.{hook}",
                _ev(file=package_json_path, package=name, version=version, hook=hook, command=_short(cmd),
                    reasons=reasons, references=WORM_REFERENCES),
                _COMPROMISE_STEPS, ["T1195.002", "T1552.001"]))
            continue
        where = "this project's package.json" if own_project else f"the installed package {label}"
        out.append(_finding(
            "AEG-SC-INSTALLSCRIPT", f"Suspicious {hook} script in {label}", sev, Category.SUSPICIOUS,
            f"The {hook} script of {where} runs automatically on npm install and " + "; ".join(reasons)
            + f". Command: {_short(cmd, 200)}. Legitimate packages normally run a local helper or node-gyp; "
            "download-and-run install hooks are the standard delivery method of malicious npm packages and of "
            "repositories sent to developers as 'coding tests'.",
            f"{package_json_path}#scripts.{hook}",
            _ev(file=package_json_path, package=name, version=version, hook=hook, command=_short(cmd),
                reasons=reasons, own_project=own_project),
            "Do not run npm install / npm ci for this project until you have read the script. Inspect what it "
            "downloads, and use `npm install --ignore-scripts` to install without running lifecycle scripts. If the "
            "code came from an unsolicited message or an unknown repository, delete it and treat any machine that "
            "already ran it as compromised (rotate credentials).",
            ["T1195.001", "T1195.002", "T1059"]))
    return out


def check_typosquats(proj: Project) -> List[Finding]:
    out: List[Finding] = []
    seen: Set[Tuple[str, str]] = set()
    cands: List[Tuple[lf.Dep, str]] = [(d, d.file) for d in proj.declared]
    cands += [(u.dep, u.files[0] if u.files else "") for u in proj.uses.values() if u.dep.direct]
    for dep, file in cands:
        if dep.ecosystem not in (lf.NPM, lf.PYPI):
            continue
        key = (dep.ecosystem, norm_name(dep.ecosystem, dep.name))
        if key in seen:
            continue
        hit = typosquat_of(dep.ecosystem, dep.name)
        if not hit:
            continue
        seen.add(key)
        target, why = hit
        out.append(_finding(
            "AEG-SC-TYPOSQUAT", f"Possible typosquat: {dep.ecosystem} package '{dep.name}' resembles '{target}'",
            Severity.MEDIUM, Category.SUSPICIOUS,
            f"The dependency '{dep.name}' is not a well-known package but its name is very close to the popular "
            f"package '{target}' ({why}). Look-alike names are a common way to get a credential stealer installed "
            "through a simple typing mistake.",
            f"{file}#{dep.name}" if file else f"{proj.path}#{dep.name}",
            _ev(ecosystem=dep.ecosystem, package=dep.name, resembles=target, reason=why, file=file,
                project=str(proj.path), spec=dep.spec),
            f"Check the spelling in {Path(file).name if file else 'the manifest'}: if you meant '{target}', replace it. "
            "If the package is intentional, verify its publisher, source repository and download history on the "
            "registry before installing, and install with scripts disabled until you have.",
            ["T1195.001"]))
    return out


def _installed_candidates(proj: Project) -> List[Tuple[Path, str, str]]:
    """(package dir, name, expected version) of installed packages worth reading: those the lockfile flags as
    having install scripts, or - without a npm lockfile - the direct dependencies."""
    nm = proj.path / "node_modules"
    if not _isdir(nm):
        return []
    out: List[Tuple[Path, str, str]] = []
    has_npm_lock = any(u.dep.ecosystem == lf.NPM and u.dep.path for u in proj.uses.values()) or \
        any(u.dep.ecosystem == lf.NPM and not u.dep.manifest for u in proj.uses.values())
    for use in proj.uses.values():
        d = use.dep
        if d.ecosystem != lf.NPM:
            continue
        if d.install_script and d.path:
            p = _safe_join(proj.path, d.path)
        elif d.install_script:
            p = _safe_join(nm, d.name)
        elif not has_npm_lock and d.direct:
            p = _safe_join(nm, d.name)
        else:
            continue
        if p is not None:
            out.append((p, d.name, d.version))
    if not has_npm_lock:
        for d in proj.declared:
            if d.ecosystem == lf.NPM and (p := _safe_join(nm, d.name)) is not None:
                out.append((p, d.name, ""))
    seen, uniq = set(), []
    for item in out:
        if str(item[0]) not in seen:
            seen.add(str(item[0]))
            uniq.append(item)
    return uniq[:MAX_INSTALLED_PACKAGES_READ]


def local_findings(proj: Project) -> Iterator[Finding]:
    """Everything that needs no network for one project."""
    scripts = proj.meta.get("scripts", {}) if proj.meta else {}
    yield from check_worm_files(proj.path, scripts, where="project folder")
    if proj.package_json is not None and scripts:
        yield from check_scripts(str(proj.package_json), proj.meta.get("name") or proj.path.name,
                                 proj.meta.get("version", ""), scripts, own_project=True, trusted=False)
    for pkg_dir, name, version in _installed_candidates(proj):
        text = _read_text(pkg_dir / "package.json", 1024 * 1024)
        if text is None:
            continue
        _, meta = lf.parse_package_json(text, str(pkg_dir / "package.json"))
        pscripts = meta.get("scripts", {})
        if not pscripts:
            continue
        real_name = meta.get("name") or name
        real_version = meta.get("version") or version
        yield from check_worm_files(pkg_dir, pscripts, where=f"installed package {real_name}")
        yield from check_scripts(str(pkg_dir / "package.json"), real_name, real_version, pscripts, own_project=False,
                                 trusted=is_popular(lf.NPM, real_name))
    yield from check_typosquats(proj)


def check_workflows(project_dir: Path) -> List[Finding]:
    """Shai-Hulud GitHub Actions workflows (both waves) in <project>/.github/workflows."""
    out: List[Finding] = []
    wf_dir = project_dir / ".github" / "workflows"
    try:
        entries = sorted((e for e in os.scandir(wf_dir) if e.is_file()), key=lambda e: e.name)[:200]
    except OSError:
        return out
    for entry in entries:
        name = entry.name.lower()
        if not name.endswith((".yml", ".yaml")):
            continue
        p = Path(entry.path)
        text = _read_text(p, 256 * 1024) or ""
        low = text.lower()
        reasons: List[str] = []
        if re.match(r"^shai-?hulud", name):
            reasons.append("workflow file name is the Shai-Hulud workflow")
        if "webhook.site" in low and "tojson(secrets)" in low:
            reasons.append("sends all repository secrets (toJSON(secrets)) to webhook.site")
        if "sha1hulud" in low:
            reasons.append("references the SHA1HULUD self-hosted runner used by Shai-Hulud 2.0")
        if re.match(r"^formatter_\d{6,}\.ya?ml$", name) and "secrets" in low:
            reasons.append("matches the formatter_<digits>.yml secrets-exfiltration workflow of Shai-Hulud 2.0")
        sev = Severity.CRITICAL if reasons else None
        if sev is None and name in ("discussion.yaml", "discussion.yml") and "self-hosted" in low and \
                re.search(r"run:.*\$\{\{\s*github\.event\.discussion\.body", low):
            sev, reasons = Severity.HIGH, ["discussion workflow on a self-hosted runner that executes the discussion "
                                           "body (command-injection backdoor used by Shai-Hulud 2.0)"]
        if sev is None:
            continue
        out.append(_finding(
            "AEG-SC-SHAIHULUD", f"Shai-Hulud GitHub Actions workflow: {entry.name}", sev,
            Category.MALWARE if sev == Severity.CRITICAL else Category.SUSPICIOUS,
            "This workflow matches the persistence / exfiltration workflows dropped by the Shai-Hulud npm worm into "
            "repositories of infected developers: " + "; ".join(reasons) + ".",
            str(p), _ev(file=str(p), repository=str(project_dir), reasons=reasons, references=WORM_REFERENCES),
            "Delete the workflow (and any 'shai-hulud' branch) from the repository on GitHub as well as locally, "
            "remove unknown self-hosted runners in the repository settings, and rotate every secret that repository "
            "or this machine could reach. " + _COMPROMISE_STEPS,
            ["T1195.002", "T1567", "T1552.001"],
            Remediation("quarantine_file", {"path": str(p)}, "Quarantine the workflow file")))
    return out


def check_vscode_tasks(project_dir: Path) -> List[Finding]:
    """.vscode/tasks.json entries that run on folder open and download-and-execute (malicious repositories sent
    to developers, e.g. the 'Contagious Interview' campaign documented by Jamf Threat Labs, Jan 2026)."""
    path = project_dir / ".vscode" / "tasks.json"
    text = _read_text(path, 512 * 1024)
    doc = load_jsonc(text) if text else None
    tasks = doc.get("tasks") if isinstance(doc, dict) else None
    out: List[Finding] = []
    if not isinstance(tasks, list):
        return out

    def command_text(obj: Any) -> str:
        if not isinstance(obj, dict):
            return ""
        parts: List[str] = []
        cmd = obj.get("command")
        if isinstance(cmd, str):
            parts.append(cmd)
        elif isinstance(cmd, dict) and isinstance(cmd.get("value"), str):
            parts.append(cmd["value"])
        for a in obj.get("args") or []:
            if isinstance(a, str):
                parts.append(a)
            elif isinstance(a, dict) and isinstance(a.get("value"), str):
                parts.append(a["value"])
        return " ".join(parts)

    for t in tasks:
        if not isinstance(t, dict):
            continue
        opts = t.get("runOptions")
        if not (isinstance(opts, dict) and str(opts.get("runOn", "")).lower() == "folderopen"):
            continue
        cmds = [command_text(t)] + [command_text(t.get(k)) for k in ("windows", "linux", "osx")]
        full = " ; ".join(c for c in cmds if c)
        sev, reasons = analyze_command(full)
        if sev is None:
            continue
        out.append(_finding(
            "AEG-SC-VSCODE-TASK", f"VS Code task runs a risky command when the folder is opened: {t.get('label', '?')}",
            Severity.HIGH if sev >= Severity.HIGH else Severity.MEDIUM, Category.SUSPICIOUS,
            "A task with runOptions.runOn = folderOpen in .vscode/tasks.json executes automatically (after a single "
            "'trust this folder' prompt) every time the folder is opened, and it " + "; ".join(reasons) + ". "
            "Malicious repositories use this to install malware on developers who open them. Command: "
            + _short(full, 220),
            str(path), _ev(file=str(path), label=str(t.get("label", "")), command=_short(full), reasons=reasons),
            "Do not trust this folder in VS Code. Read the task and the files it fetches; if the repository came from "
            "an unknown party delete it. If you already trusted it, treat the machine as compromised and rotate "
            "credentials.",
            ["T1195.002", "T1059"]))
    return out


def check_home_iocs(home: Optional[Path] = None) -> List[Finding]:
    """Shai-Hulud 2.0 leaves a GitHub Actions self-hosted runner named SHA1HULUD in ~/.dev-env."""
    home = home or user_home()
    d = home / ".dev-env"
    if not _isdir(d):
        return []
    runner = (_read_text(d / ".runner", 64 * 1024) or "").upper()
    layout = any((d / n).exists() for n in ("config.sh", "run.sh", "config.cmd", "run.cmd")) and \
        ((d / "bin").exists() or any(d.glob("actions-runner*")))
    if "SHA1HULUD" in runner:
        sev, why = Severity.CRITICAL, "the runner registered here is named SHA1HULUD"
    elif layout:
        sev, why = Severity.HIGH, "it contains a GitHub Actions runner installation, the layout Shai-Hulud 2.0 uses"
    else:
        return []
    return [_finding(
        "AEG-SC-SHAIHULUD", "Shai-Hulud 2.0 self-hosted runner backdoor in ~/.dev-env", sev, Category.MALWARE,
        f"The folder {d} looks like the GitHub self-hosted runner the Shai-Hulud 2.0 npm worm installs so attackers "
        f"can run commands on the machine later: {why}.", str(d), _ev(path=str(d), reasons=[why], references=WORM_REFERENCES),
        "Stop the runner process, remove the runner in each GitHub repository's Settings > Actions > Runners, delete the "
        "folder, then rotate all credentials. " + _COMPROMISE_STEPS, ["T1195.002", "T1021"])]


# --------------------------------------------------------------------------- OSV-backed findings
_SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "": 0}
_UPGRADE = {
    lf.NPM: "npm install {name}@{ver}", lf.PYPI: 'pip install --upgrade "{name}>={ver}"',
    lf.CRATES: "cargo update -p {name}", lf.GO: "go get {name}@v{ver}", lf.RUBYGEMS: "bundle update {name}",
    lf.PACKAGIST: "composer update {name}", lf.NUGET: "dotnet add package {name} --version {ver}",
}


def _osv_url(vid: str) -> str:
    return f"https://osv.dev/{vid}"


def _in_project(proj: Project) -> str:
    """' in <folder>' for a title, so the same package in two projects does not read as one finding listed twice."""
    name = proj.path.name or str(proj.path)
    return f" in {name}" if name else ""


def _malicious_finding(proj: Project, use: Use, infos: List[VulnInfo]) -> Finding:
    d = use.dep
    mal = [i for i in infos if i.malicious]
    file = use.files[0] if use.files else str(proj.path)
    ids = [i.id for i in mal]
    summaries = [i.summary for i in mal if i.summary][:3]
    return _finding(
        "AEG-SC-MALPKG", f"Known malicious package {d.ecosystem}/{d.name}@{d.version}{_in_project(proj)}", Severity.CRITICAL,
        Category.MALWARE,
        f"OSV.dev lists {d.ecosystem} package {d.name} {d.version} as malicious ({', '.join(ids)}). "
        + (summaries[0] + ". " if summaries else "")
        + "Installing or running it (including its install scripts) may already have executed attacker code, typically "
        "to steal tokens, SSH keys, browser data and cloud credentials.",
        _location(file, d.ecosystem, d.name, d.version),
        _ev(ecosystem=d.ecosystem, package=d.name, version=d.version, advisories=ids, summaries=summaries,
            file=file, files=use.files, project=str(proj.path), direct=d.direct, dev=d.dev,
            references=[_osv_url(i) for i in ids][:5]),
        _COMPROMISE_STEPS, ["T1195.001", "T1195.002"])


def _vuln_finding(proj: Project, use: Use, infos: List[VulnInfo]) -> Optional[Finding]:
    d = use.dep
    infos = sorted(infos, key=lambda i: (-_SEV_ORDER.get(i.severity or "MEDIUM", 2), i.id))
    if not infos:
        return None
    raw = max((i.severity or "MEDIUM" for i in infos), key=lambda s: _SEV_ORDER.get(s, 2))
    sev = min(Severity[raw], VULN_SEVERITY_CAP)
    key = fixed_key(d.ecosystem, d.name)
    best_fix, no_fix, per_adv = "", [], {}
    candidates: List[str] = []
    for i in infos:
        fx = i.fixed.get(key, [])
        if fx:
            per_adv[i.id] = fx[:6]
            pick = pick_fixed(d.version, fx)
            if pick:
                candidates.append(pick)
        else:
            no_fix.append(i.id)
    if candidates:
        best_fix = max(candidates, key=version_key)
    file = use.files[0] if use.files else str(proj.path)
    top = infos[0]
    cmd = ""
    if best_fix and _safe_token(d.name) and _safe_token(best_fix):
        cmd = _UPGRADE.get(d.ecosystem, "").format(name=d.name, ver=best_fix)
    n = len(infos)
    rec = (f"Update {d.name} to {best_fix} or later" if best_fix else
           f"No fixed version is listed for {d.name} {d.version}; check the advisories for workarounds or replace the package")
    if no_fix and best_fix:
        rec += f" (no fix is listed yet for {', '.join(no_fix[:5])})"
    rec += (f" - e.g. `{cmd}`" if cmd else "") + ". Then regenerate and commit the lockfile."
    return _finding(
        "AEG-SC-VULN",
        f"Vulnerable {d.ecosystem} package {d.name}@{d.version}{_in_project(proj)}: {n} known "
        f"advisor{'y' if n == 1 else 'ies'} ({sev.name.lower()})",
        sev, Category.VULNERABILITY,
        f"{d.name} {d.version} is affected by {n} published advisor{'y' if n == 1 else 'ies'}. Most severe: {top.id}"
        + (f" - {top.summary}" if top.summary else "") + ".",
        _location(file, d.ecosystem, d.name, d.version),
        _ev(ecosystem=d.ecosystem, package=d.name, version=d.version, osv_severity=raw, advisory_count=n,
            advisories=[_ev(id=i.id, severity=i.severity or "unknown", cvss=i.score, summary=i.summary,
                            aliases=i.aliases[:4]) for i in infos[:12]],
            fixed_in=best_fix, fixed_by_advisory=per_adv, no_fix_listed=no_fix[:12], file=file, files=use.files,
            project=str(proj.path), direct=d.direct, dev=d.dev, references=[_osv_url(i.id) for i in infos[:3]]),
        rec, ["T1195.001"])


def osv_findings(projects: Sequence[Project], results: Dict[Pkg, List[str]],
                 details: Dict[str, VulnInfo]) -> Iterator[Finding]:
    """Per project: one finding per vulnerable package (capped), one CRITICAL finding per malicious package."""
    for proj in projects:
        mals: List[Finding] = []
        vulns: List[Tuple[Tuple[int, int, str], Finding]] = []
        for use in proj.uses.values():
            ids = results.get(use.pkg)
            if not ids:
                continue
            infos = [details[i] for i in ids if i in details and not details[i].withdrawn]
            if not infos:
                continue
            if any(i.malicious for i in infos):
                mals.append(_malicious_finding(proj, use, infos))
                continue
            f = _vuln_finding(proj, use, infos)
            if f is not None:
                vulns.append(((-int(f.severity), 0 if use.dep.direct else 1, use.dep.name.lower()), f))
        for f in mals[:MAX_MAL_FINDINGS_PER_PROJECT]:
            yield f
        if len(mals) > MAX_MAL_FINDINGS_PER_PROJECT:
            yield _overflow(proj, "malicious", [f for f in mals[MAX_MAL_FINDINGS_PER_PROJECT:]], Severity.CRITICAL)
        vulns.sort(key=lambda t: t[0])
        for _, f in vulns[:MAX_VULN_FINDINGS_PER_PROJECT]:
            yield f
        rest = [f for _, f in vulns[MAX_VULN_FINDINGS_PER_PROJECT:]]
        if rest:
            yield _overflow(proj, "vulnerable", rest, max(f.severity for f in rest))


def _overflow(proj: Project, kind: str, rest: List[Finding], sev: Severity) -> Finding:
    by_sev: Dict[str, int] = {}
    for f in rest:
        by_sev[f.severity.name.lower()] = by_sev.get(f.severity.name.lower(), 0) + 1
    pkgs = [f"{f.evidence.get('ecosystem')}/{f.evidence.get('package')}@{f.evidence.get('version')} ({f.severity.name.lower()})"
            for f in rest]
    return _finding(
        "AEG-SC-VULN-MORE" if kind == "vulnerable" else "AEG-SC-MALPKG-MORE",
        f"{len(rest)} more {kind} package{'s' if len(rest) != 1 else ''} in {proj.path.name or proj.path}",
        sev, Category.VULNERABILITY if kind == "vulnerable" else Category.MALWARE,
        f"To keep the report readable only the {MAX_VULN_FINDINGS_PER_PROJECT if kind == 'vulnerable' else MAX_MAL_FINDINGS_PER_PROJECT} "
        f"worst {kind} packages of this project are listed individually; the remaining {len(rest)} are summarised here.",
        f"{proj.path}#more-{kind}",
        _ev(project=str(proj.path), omitted=len(rest), by_severity=by_sev, packages=pkgs[:150],
            packages_truncated=max(0, len(pkgs) - 150)),
        "Update the listed packages (start with direct dependencies) and rescan.", ["T1195.001"])


# --------------------------------------------------------------------------- orchestration
def _budget(ctx: ScanContext, **defaults: Any) -> Budget:
    o = ctx.options
    b = Budget(**defaults)
    try:
        b.max_depth = int(o.get("supplychain_max_depth", b.max_depth))
        b.max_seconds = float(o.get("supplychain_max_seconds", b.max_seconds))
        b.max_entries = int(o.get("supplychain_max_entries", b.max_entries))
    except (TypeError, ValueError):
        pass
    return b


def _make_client(ctx: ScanContext) -> OsvClient:
    try:
        ttl = float(ctx.options.get("supplychain_cache_ttl_hours", 24)) * 3600
    except (TypeError, ValueError):
        ttl = 24 * 3600
    online = bool(ctx.options.get("supplychain_online", True))
    try:
        cache = Path(ctx.config.home) / "osv_cache.json"
    except Exception:
        cache = None
    return OsvClient(cache, ttl=ttl, online=online)


def _guarded(fn: Callable[..., Sequence[Finding]], *args: Any) -> List[Finding]:
    """Run one check; an unexpected error (hostile file, RecursionError ...) loses that check, not the scan."""
    try:
        return list(fn(*args))
    except Exception as exc:
        log.debug("supply-chain check %s failed: %s", getattr(fn, "__name__", "check"), exc)
        return []


def _scan(ctx: ScanContext, roots: Sequence[Path], budget: Budget, single_files: Sequence[Path] = (),
          home_iocs: bool = True) -> Iterator[Emitted]:
    name = SupplyChainScanner.name
    ctx.report(name, "looking for dependency manifests and lockfiles")
    disc = discover(roots, budget, lambda: ctx.cancelled)
    for f in single_files:
        disc.projects.setdefault(f.parent, [])
        if f not in disc.projects[f.parent]:
            disc.projects[f.parent].append(f)
    ctx.bump("supplychain_projects", len(disc.projects))

    if home_iocs:
        yield from _guarded(check_home_iocs)
    for d in disc.workflow_dirs:
        yield from _guarded(check_workflows, d)
    for d in disc.vscode_dirs:
        yield from _guarded(check_vscode_tasks, d)

    projects: List[Project] = []
    for path, files in sorted(disc.projects.items(), key=lambda kv: str(kv[0]).lower()):
        if ctx.cancelled:
            return
        ctx.report(name, f"reading {path}")
        try:
            proj = load_project(path, files)
        except Exception as exc:  # one pathological project must not stop the scan
            log.debug("could not load project %s: %s", path, exc)
            continue
        projects.append(proj)
        yield from _guarded(lambda p=proj: list(local_findings(p)))

    pkgs: List[Pkg] = []
    for proj in projects:
        pkgs.extend(u.pkg for u in proj.uses.values())
    unique = list(dict.fromkeys(pkgs))
    ctx.bump("supplychain_packages", len(unique))
    bad_files = [e for p in projects for e in p.errors]
    detail = (f"{len(projects)} project(s), {len(unique)} pinned package version(s) in "
              f"{sum(len(p.files) for p in projects)} file(s); scanned {disc.entries} entries in {disc.seconds}s"
              + ("; stopped early (time/size budget)" if disc.truncated else "")
              + (f"; {len(bad_files)} file(s) could not be read or parsed ({'; '.join(bad_files[:3])})" if bad_files else ""))
    if projects:
        yield CheckResult("AEG-SC-PROJECTS", "Dependency manifests and lockfiles found",
                          CheckStatus.WARN if (disc.truncated or bad_files) else CheckStatus.PASS, detail,
                          category=Category.VULNERABILITY)
    else:
        yield CheckResult("AEG-SC-PROJECTS", "Dependency manifests and lockfiles found",
                          CheckStatus.WARN if disc.truncated else CheckStatus.SKIP,
                          ("stopped early (time/size budget) before finding any dependency files under "
                           if disc.truncated else "no dependency files found under ")
                          + (", ".join(str(r) for r in roots) or "any scan path"), category=Category.VULNERABILITY)

    if not unique:
        yield CheckResult("AEG-SC-OSV", "OSV.dev vulnerability and malicious-package lookup", CheckStatus.SKIP,
                          "no pinned dependency versions to look up", category=Category.VULNERABILITY)
        return
    ctx.report(name, f"checking {len(unique)} package versions against OSV.dev")
    client = _make_client(ctx)
    try:
        osv_budget = float(ctx.options.get("supplychain_osv_seconds", 120))
    except (TypeError, ValueError):
        osv_budget = 120.0
    deadline = time.monotonic() + osv_budget
    stop = lambda: ctx.cancelled  # noqa: E731
    results = client.query(unique, deadline=deadline, should_stop=stop)
    ids = [i for v in results.values() for i in v]
    details = client.details(ids, deadline=deadline, should_stop=stop) if ids else {}
    yield from osv_findings(projects, results, details)
    n_hit = sum(1 for v in results.values() if v)
    ctx.bump("supplychain_vulnerable_packages", n_hit)

    title = "OSV.dev vulnerability and malicious-package lookup"
    st = client.stats
    incomplete = sum(1 for v in details.values() if not v.complete)
    note = (f"; details of {incomplete} advisor{'y' if incomplete == 1 else 'ies'} unavailable, "
            "so some severities are defaults") if incomplete else ""
    if client.offline:
        yield CheckResult("AEG-SC-OSV", title, CheckStatus.WARN,
                          f"offline - results from cache only ({client.error or 'network unavailable'}); "
                          f"{len(results)} of {len(unique)} package versions answered from cache"
                          + (" (cached data may be older than 24 h)" if client.used_stale else "")
                          + (f", {len(client.unchecked)} not checked" if client.unchecked else "") + note,
                          category=Category.VULNERABILITY)
    elif client.truncated or client.unchecked:
        yield CheckResult("AEG-SC-OSV", title, CheckStatus.WARN,
                          f"{len(client.unchecked)} of {len(unique)} package versions could not be checked "
                          "(time budget or cancellation)" + note, category=Category.VULNERABILITY)
    else:
        yield CheckResult("AEG-SC-OSV", title, CheckStatus.WARN if incomplete else CheckStatus.PASS,
                          f"{len(unique)} package versions checked ({st['cache_hits']} from cache, "
                          f"{n_hit} with advisories)" + note, category=Category.VULNERABILITY)


@register
class SupplyChainScanner(Scanner):
    name = "supplychain"
    title = "Software supply chain (dependencies, install scripts, worms)"
    description = ("Reads npm/PyPI/Cargo/Go/Ruby/PHP/NuGet lockfiles in developer folders, checks them against OSV.dev "
                   "for known vulnerabilities and malicious packages, and flags risky install scripts, typosquats and "
                   "Shai-Hulud worm indicators")
    platforms = ("windows", "linux", "darwin")

    def run(self, ctx: ScanContext) -> Iterator[Emitted]:
        roots = resolve_roots(ctx.paths, include_defaults=bool(ctx.options.get("supplychain_default_dirs", True)))
        try:
            yield from _scan(ctx, roots, _budget(ctx))
        except Exception as exc:  # never raise out of run() for the whole scanner
            log.warning("supplychain scan failed: %s", exc, exc_info=True)
            yield CheckResult("AEG-SC-ERROR", "Supply-chain scan", CheckStatus.ERROR, f"{type(exc).__name__}: {exc}",
                              category=Category.VULNERABILITY)


# --------------------------------------------------------------------------- public helpers
def scan_project_results(path: Any, ctx: Optional[ScanContext] = None) -> Tuple[List[Finding], List[CheckResult]]:
    """Scan one project folder (or a single manifest/lockfile) and return (findings, checks).
    Uses the same logic as the scanner but only looks at `path` (no default developer folders)."""
    if ctx is None:
        from aegis.core.config import Config
        from aegis.core.signatures import SignatureDB

        cfg = Config.load()
        ctx = ScanContext(config=cfg, signatures=SignatureDB(cfg))
    p = Path(path)
    findings: List[Finding] = []
    checks: List[CheckResult] = []
    single: List[Path] = []
    if p.is_file():
        single, root = [p], p.parent
        budget = Budget(max_depth=0)
    else:
        root, budget = p, _budget(ctx, max_depth=8)
    try:
        for item in _scan(ctx, [root] if p.is_dir() else [], budget, single_files=single, home_iocs=False):
            (checks if isinstance(item, CheckResult) else findings).append(item)  # type: ignore[arg-type]
    except Exception as exc:
        log.warning("project scan failed: %s", exc, exc_info=True)
        checks.append(CheckResult("AEG-SC-ERROR", "Supply-chain scan", CheckStatus.ERROR, f"{type(exc).__name__}: {exc}",
                                  category=Category.VULNERABILITY))
    for f in findings:
        f.scanner = f.scanner or SupplyChainScanner.name
    for c in checks:
        c.scanner = c.scanner or SupplyChainScanner.name
    return findings, checks


def scan_project(path: Any, ctx: Optional[ScanContext] = None) -> List[Finding]:
    """Findings for one project folder or manifest (for ``aegis check-project PATH``)."""
    return scan_project_results(path, ctx)[0]
