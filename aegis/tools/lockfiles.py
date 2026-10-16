"""Dependency manifest and lockfile parsers (stdlib only, tolerant of malformed input).

Every parser takes the file text and returns a list of :class:`Dep`; none of them raises on bad
input (they return what could be read). Supported files:

========================= ===============================================================
npm                       package-lock.json (v1/v2/v3), npm-shrinkwrap.json, yarn.lock
                          (classic v1 and Berry), pnpm-lock.yaml (v5-v9, line parser),
                          package.json (declared ranges; exact pins carry a version)
PyPI                      requirements*.txt (``==`` pins and declared names), poetry.lock,
                          Pipfile.lock, uv.lock, pyproject.toml (declared names only)
crates.io                 Cargo.lock (registry packages only)
Go                        go.mod (preferred), go.sum
RubyGems                  Gemfile.lock
Packagist                 composer.lock
NuGet                     packages.lock.json
========================= ===============================================================

Ecosystem names are OSV's. Packages that do not come from a public registry (git, path, file,
workspace and link dependencies) are skipped because OSV cannot answer for them.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

log = logging.getLogger("aegis.lockfiles")

MAX_LOCKFILE_BYTES = 48 * 1024 * 1024
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_DEPS_PER_FILE = 60000

NPM, PYPI, CRATES, GO, RUBYGEMS, PACKAGIST, NUGET = "npm", "PyPI", "crates.io", "Go", "RubyGems", "Packagist", "NuGet"


@dataclass
class Dep:
    ecosystem: str
    name: str
    version: str = ""  # exact version, "" when only a range is known
    file: str = ""
    spec: str = ""  # declared version range (manifests)
    direct: bool = False  # known to be a direct dependency of the project
    dev: bool = False
    install_script: bool = False  # npm lockfile hasInstallScript / pnpm requiresBuild
    path: str = ""  # npm: install location inside the lockfile (node_modules/a/node_modules/b)
    manifest: bool = False  # declared in a manifest (not resolved by a lockfile)

    @property
    def key(self) -> str:
        return f"{self.ecosystem}/{self.name}@{self.version}"


# --------------------------------------------------------------------------- classification
_REQ_NAME = re.compile(r"^(?:[\w.-]*requirements[\w.-]*|constraints[\w.-]*)\.txt$", re.I)

_BY_NAME = {
    "package-lock.json": "package-lock", "npm-shrinkwrap.json": "package-lock", "yarn.lock": "yarn",
    "pnpm-lock.yaml": "pnpm", "package.json": "package.json", "poetry.lock": "poetry", "pipfile.lock": "pipfile-lock",
    "uv.lock": "uv", "cargo.lock": "cargo", "go.mod": "go.mod", "go.sum": "go.sum", "gemfile.lock": "gemfile-lock",
    "composer.lock": "composer-lock", "packages.lock.json": "nuget-lock", "pyproject.toml": "pyproject",
}
LOCK_KINDS = {"package-lock", "yarn", "pnpm", "poetry", "pipfile-lock", "uv", "cargo", "go.sum", "gemfile-lock",
              "composer-lock", "nuget-lock"}


def classify(filename: str, parent_name: str = "") -> Optional[str]:
    """File name -> parser kind (None = not a dependency file). `parent_name` lets
    ``requirements/base.txt`` style layouts through."""
    low = filename.lower()
    kind = _BY_NAME.get(low)
    if kind:
        return kind
    if _REQ_NAME.match(filename):
        return "requirements"
    if low.endswith(".txt") and parent_name.lower() in ("requirements", "reqs"):
        return "requirements"
    return None


# --------------------------------------------------------------------------- helpers
_SEMVERISH = re.compile(r"^\d+\.\d+\.\d+")
_EXACT_RANGE = re.compile(r"^=?\s*v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?)$")
_NON_REGISTRY_SPEC = ("git", "github:", "gitlab:", "bitbucket:", "file:", "link:", "workspace:", "http:", "https:",
                      "portal:", "patch:", "./", "../", "/", "~/")


def _json(text: str) -> Any:
    try:
        return json.loads(text)
    except (ValueError, RecursionError):  # malformed, or nested deeply enough to exhaust the parser
        return None


def _is_registry_url(resolved: Any) -> bool:
    """True for http(s) tarball URLs of a package registry; False for git/file specs and GitHub tarballs."""
    if not isinstance(resolved, str):
        return False
    low = resolved.lower()
    if not low.startswith(("http://", "https://")):
        return False
    return "codeload.github.com" not in low and not re.match(r"^https?://(?:www\.)?github\.com/", low)


def _unquote(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        return s[1:-1]
    return s


# --------------------------------------------------------------------------- npm
def parse_package_lock(text: str, file: str = "") -> List[Dep]:
    """package-lock.json / npm-shrinkwrap.json, lockfileVersion 1, 2 and 3."""
    doc = _json(text)
    if not isinstance(doc, dict):
        return []
    out: List[Dep] = []
    packages = doc.get("packages")
    if isinstance(packages, dict):  # v2 / v3 (v2 also keeps the legacy "dependencies" tree: ignored)
        root = packages.get("") if isinstance(packages.get(""), dict) else {}
        direct: set = set()
        for k in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            if isinstance(root.get(k), dict):
                direct.update(root[k])
        for key, meta in packages.items():
            if not key or not isinstance(meta, dict) or meta.get("link"):
                continue
            idx = key.rfind("node_modules/")
            if idx < 0:  # workspace member, not an installed registry package
                continue
            path_name = key[idx + len("node_modules/"):]
            real = meta.get("name") if isinstance(meta.get("name"), str) and meta.get("name") else path_name
            version = meta.get("version")
            if not isinstance(version, str) or not _SEMVERISH.match(version):
                continue
            resolved = meta.get("resolved")
            if resolved is not None and not _is_registry_url(resolved):
                continue
            out.append(Dep(NPM, real, version, file, direct=key.count("node_modules/") == 1 and path_name in direct,
                           dev=meta.get("dev") is True, install_script=bool(meta.get("hasInstallScript")), path=key))
            if len(out) >= MAX_DEPS_PER_FILE:
                break
        return out
    tree = doc.get("dependencies")  # v1
    if isinstance(tree, dict):
        stack: List[Tuple[str, Dict[str, Any], int]] = [("", tree, 0)]
        while stack and len(out) < MAX_DEPS_PER_FILE:
            prefix, level, depth = stack.pop()
            for name, meta in level.items():
                if not isinstance(meta, dict):
                    continue
                version = meta.get("version")
                real = name
                if isinstance(version, str) and version.startswith("npm:"):
                    m = re.match(r"^npm:(@?[^@]+)@(.+)$", version)
                    if m:
                        real, version = m.group(1), m.group(2)
                path = f"{prefix}node_modules/{name}"
                sub = meta.get("dependencies")
                if isinstance(sub, dict) and depth < 40:
                    stack.append((path + "/", sub, depth + 1))
                resolved = meta.get("resolved")
                if not isinstance(version, str) or not _SEMVERISH.match(version) or \
                        (resolved is not None and not _is_registry_url(resolved)):
                    continue
                out.append(Dep(NPM, real, version, file, dev=meta.get("dev") is True, path=path))
    return out


def _split_quoted_csv(header: str) -> List[str]:
    parts, cur, quote = [], "", ""
    for ch in header:
        if quote:
            if ch == quote:
                quote = ""
            else:
                cur += ch
        elif ch in "\"'":
            quote = ch
        elif ch == ",":
            parts.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur.strip())
    return [p for p in parts if p]


def _yarn_descriptor_name(desc: str) -> str:
    at = desc.find("@", 1)
    name = desc[:at] if at > 0 else desc
    m = re.match(r"^(@?[^@]+)@npm:(@?[^@]+)@", desc)  # alias: "x@npm:real@^1"
    return m.group(2) if m else name


def parse_yarn_lock(text: str, file: str = "") -> List[Dep]:
    """yarn.lock - classic (v1) and Berry (v2+) formats."""
    out: List[Dep] = []
    berry = bool(re.search(r"^__metadata:", text, re.M)) or "\n  resolution: " in text
    cur: Optional[Dict[str, Any]] = None

    def flush() -> None:
        nonlocal cur
        if cur is None:
            return
        c, cur = cur, None
        version = c.get("version", "")
        name = c.get("name", "")
        if berry:
            res = c.get("resolution", "")
            if "@npm:" in res:
                name, _, ver = res.rpartition("@npm:")
                version = ver or version
            else:
                return  # workspace / patch / link / git / file protocol
        else:
            if any(m in d for d in c.get("descs", []) for m in ("github:", "git+", "file:", "link:", "http:", "https:", "git@")):
                return
            res = c.get("resolved", "")
            if res and (res.startswith(("git", "file:")) or "codeload.github.com" in res):
                return
        if name and isinstance(version, str) and _SEMVERISH.match(version):
            out.append(Dep(NPM, name, version, file))

    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw[0].isspace():  # block header
            flush()
            header = raw.rstrip()
            if header.endswith(":"):
                header = header[:-1]
            if header.startswith("__metadata"):
                continue
            descs = _split_quoted_csv(header)
            if descs:
                cur = {"descs": descs, "name": _yarn_descriptor_name(descs[0])}
            continue
        if cur is not None and raw.startswith("  ") and not raw.startswith("    "):
            m = re.match(r"^  ([A-Za-z]+):?\s+(.*)$", raw.rstrip())
            if m and m.group(1) in ("version", "resolved", "resolution"):
                cur[m.group(1)] = _unquote(m.group(2))
    flush()
    return out[:MAX_DEPS_PER_FILE]


_PNPM_V5 = re.compile(r"^/?((?:@[^/]+/)?[^/@]+)/(\d[^/_()\s]*)")
_PNPM_V6 = re.compile(r"^/?((?:@[^/@]+/)?[^/@]+)@(\d[^()_\s]*)")


def parse_pnpm_lock(text: str, file: str = "") -> List[Dep]:
    """pnpm-lock.yaml (lockfile v5 through v9) with a small indentation-based reader, no YAML library."""
    out: List[Dep] = []
    section = ""
    cur: Optional[Dep] = None
    skip = False

    def flush() -> None:
        nonlocal cur
        if cur is not None and not skip:
            out.append(cur)
        cur = None

    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        stripped = raw.strip()
        if indent == 0:
            flush()
            section = stripped.rstrip(":").strip() if stripped.endswith(":") else ""
            continue
        if section != "packages":
            continue
        if indent == 2 and stripped.endswith(":"):
            flush()
            key = _unquote(stripped[:-1])
            m = _PNPM_V6.match(key) if "@" in key.lstrip("/")[1:] else _PNPM_V5.match(key)
            if m is None:
                m = _PNPM_V5.match(key) or _PNPM_V6.match(key)
            cur, skip = (Dep(NPM, m.group(1), m.group(2), file), False) if m else (None, True)
            continue
        if cur is not None and indent >= 4:
            if stripped.startswith("requiresBuild:") and "true" in stripped:
                cur.install_script = True
            elif stripped.startswith("dev:") and "true" in stripped:
                cur.dev = True
            elif stripped.startswith("resolution:") and re.search(r"directory:|type:\s*git|repo:", stripped):
                skip = True
    flush()
    return out[:MAX_DEPS_PER_FILE]


def parse_package_json(text: str, file: str = "") -> Tuple[List[Dep], Dict[str, Any]]:
    """package.json -> (declared dependencies, metadata {name, version, scripts, private}).
    Exact pins ("1.2.3", "=1.2.3") carry a version; ranges only a spec."""
    doc = _json(text)
    if not isinstance(doc, dict):
        return [], {}
    deps: List[Dep] = []
    for field_name, dev in (("dependencies", False), ("optionalDependencies", False), ("devDependencies", True)):
        table = doc.get(field_name)
        if not isinstance(table, dict):
            continue
        for name, spec in table.items():
            if not isinstance(name, str) or not isinstance(spec, str):
                continue
            real, version, s = name, "", spec.strip()
            m = re.match(r"^npm:(@?[^@]+)@(.+)$", s)
            if m:  # alias
                real, s = m.group(1), m.group(2).strip()
            if not s.lower().startswith(_NON_REGISTRY_SPEC):
                m = _EXACT_RANGE.match(s)
                if m:
                    version = m.group(1)
            deps.append(Dep(NPM, real, version, file, spec=s, direct=True, dev=dev, manifest=True))
    scripts = doc.get("scripts") if isinstance(doc.get("scripts"), dict) else {}
    meta = {"name": doc.get("name") if isinstance(doc.get("name"), str) else "",
            "version": doc.get("version") if isinstance(doc.get("version"), str) else "",
            "private": bool(doc.get("private")),
            "scripts": {k: v for k, v in scripts.items() if isinstance(k, str) and isinstance(v, str)}}
    return deps, meta


# --------------------------------------------------------------------------- Python
_REQ_LINE = re.compile(r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(\[[^\]]*\])?\s*(.*)$")
_PIN = re.compile(r"^(===?)\s*([A-Za-z0-9_.!+-]+)\s*$")


def parse_requirements(text: str, file: str = "") -> List[Dep]:
    """requirements*.txt: ``name==1.2.3`` pins yield exact versions; every other requirement is
    still reported (declared name + spec) so name-based checks can see it."""
    out: List[Dep] = []
    joined: List[str] = []
    buf = ""
    for raw in text.splitlines():  # join backslash continuations (hash lists)
        line = raw.rstrip()
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        joined.append(buf + line)
        buf = ""
    if buf:
        joined.append(buf)
    dev = bool(re.search(r"dev|test|lint|doc|ci", Path(file).name, re.I)) if file else False
    for line in joined:
        line = re.sub(r"(^|\s)#.*$", "", line).strip()
        if not line or line.startswith("-") or "://" in line or line.startswith(("git+", ".", "/")):
            continue
        line = line.split(";", 1)[0].strip()  # environment markers
        m = _REQ_LINE.match(line)
        if not m:
            continue
        name, rest = m.group(1), m.group(3).strip()
        if rest.startswith("@"):  # direct URL reference
            continue
        rest = re.sub(r"--hash=\S+", "", rest).strip()
        pin = _PIN.match(rest)
        version = pin.group(2) if pin and "*" not in pin.group(2) else ""
        out.append(Dep(PYPI, name, version, file, spec=rest, direct=True, dev=dev, manifest=not version))
    return out[:MAX_DEPS_PER_FILE]


def _toml_str(val: str) -> str:
    val = val.strip()
    m = re.match(r'^"((?:[^"\\]|\\.)*)"', val) or re.match(r"^'([^']*)'", val)
    return m.group(1) if m else val


def _toml_packages(text: str) -> List[Dict[str, Any]]:
    """Top-level keys of every ``[[package]]`` table (enough for poetry.lock, uv.lock, Cargo.lock)."""
    pkgs: List[Dict[str, Any]] = []
    cur: Optional[Dict[str, Any]] = None
    sub = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] == "#":
            continue
        if line.startswith("[["):
            hdr = line.strip("[] \t")
            if hdr == "package":
                cur = {}
                pkgs.append(cur)
                sub = ""
            else:
                sub = hdr
            continue
        if line.startswith("["):
            hdr = line.strip("[] \t")
            if hdr.startswith("package."):
                sub = hdr[len("package."):]
            else:
                cur, sub = None, ""
            continue
        if cur is None:
            continue
        m = re.match(r'^([A-Za-z0-9_.-]+|"[^"]+")\s*=\s*(.*)$', line)
        if not m:
            continue
        key, val = m.group(1).strip('"'), m.group(2).strip()
        if sub == "":
            if key in ("name", "version", "category"):
                cur[key] = _toml_str(val)
            elif key == "source":
                cur["source"] = val
            elif key == "groups":
                cur["groups"] = re.findall(r'"([^"]+)"', val)
        elif sub == "source" and key == "type":
            cur["source_type"] = _toml_str(val)
    return pkgs


def parse_poetry_lock(text: str, file: str = "") -> List[Dep]:
    out: List[Dep] = []
    for p in _toml_packages(text):
        name, version = p.get("name", ""), p.get("version", "")
        if not name or not version or p.get("source_type") in ("git", "directory", "file", "url"):
            continue
        groups = p.get("groups")
        dev = p.get("category") == "dev" or bool(groups and "main" not in groups)
        out.append(Dep(PYPI, name, version, file, dev=dev))
    return out[:MAX_DEPS_PER_FILE]


def parse_uv_lock(text: str, file: str = "") -> List[Dep]:
    out: List[Dep] = []
    for p in _toml_packages(text):
        name, version, source = p.get("name", ""), p.get("version", ""), p.get("source", "")
        if not name or not version or not re.search(r"\bregistry\s*=", source):
            continue  # editable / virtual / git / path / url sources
        out.append(Dep(PYPI, name, version, file))
    return out[:MAX_DEPS_PER_FILE]


def parse_cargo_lock(text: str, file: str = "") -> List[Dep]:
    out: List[Dep] = []
    for p in _toml_packages(text):
        name, version = p.get("name", ""), p.get("version", "")
        src = _toml_str(p.get("source", ""))
        if not name or not version:
            continue
        if src.startswith("registry+https://github.com/rust-lang/crates.io-index") or \
                src.startswith("sparse+https://index.crates.io"):
            out.append(Dep(CRATES, name, version, file))
    return out[:MAX_DEPS_PER_FILE]


def parse_pipfile_lock(text: str, file: str = "") -> List[Dep]:
    doc = _json(text)
    out: List[Dep] = []
    if not isinstance(doc, dict):
        return out
    for section, dev in (("default", False), ("develop", True)):
        table = doc.get(section)
        if not isinstance(table, dict):
            continue
        for name, meta in table.items():
            if not isinstance(meta, dict) or any(k in meta for k in ("git", "path", "file", "editable")):
                continue
            version = str(meta.get("version", "")).lstrip("=").strip()
            if version and "*" not in version:
                out.append(Dep(PYPI, name, version, file, dev=dev))
    return out[:MAX_DEPS_PER_FILE]


def parse_pyproject(text: str, file: str = "") -> List[Dep]:
    """pyproject.toml: declared dependency names (PEP 621, PEP 735 and Poetry). Used for name checks only."""
    out: List[Dep] = []
    table = ""
    array_open = False

    def add_requirements(chunk: str, dev: bool) -> None:
        for dq, sq in re.findall(r'"([^"]*)"|\'([^\']*)\'', chunk):
            req = (dq or sq).split(";", 1)[0].strip()
            m = _REQ_LINE.match(req)
            if m and not m.group(3).strip().startswith("@"):
                rest = m.group(3).strip()
                pin = _PIN.match(rest)
                out.append(Dep(PYPI, m.group(1), pin.group(2) if pin and "*" not in pin.group(2) else "", file,
                               spec=rest, direct=True, dev=dev, manifest=True))

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not array_open and line.startswith("["):
            table = line.strip("[] \t").lower()
            continue
        dev = "dev" in table or "group" in table
        if table == "project" or table.startswith("project.optional-dependencies") or table == "dependency-groups":
            if array_open:
                add_requirements(line, dev)
                array_open = "]" not in re.sub(r'"[^"]*"|\'[^\']*\'', "", line)
                continue
            m = re.match(r"^([\w.-]+)\s*=\s*\[(.*)$", line)
            if m and (table != "project" or m.group(1) == "dependencies"):
                add_requirements(m.group(2), dev)
                array_open = "]" not in re.sub(r'"[^"]*"|\'[^\']*\'', "", m.group(2))
        elif table.startswith("tool.poetry") and table.endswith("dependencies"):
            m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*(.*)$", line)
            if m and m.group(1).lower() != "python":
                out.append(Dep(PYPI, m.group(1), "", file, spec=_toml_str(m.group(2)), direct=True,
                               dev=dev, manifest=True))
    return out[:MAX_DEPS_PER_FILE]


# --------------------------------------------------------------------------- other ecosystems
def parse_go_mod(text: str, file: str = "") -> List[Dep]:
    out: List[Dep] = []
    block = ""
    for raw in text.splitlines():
        indirect = "// indirect" in raw
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if block:
            if line == ")":
                block = ""
            elif block == "require":
                parts = line.split()
                if len(parts) >= 2 and re.match(r"^v\d", parts[1]):
                    out.append(Dep(GO, parts[0], parts[1].lstrip("v"), file, direct=not indirect))
            continue
        m = re.match(r"^(require|replace|exclude|retract|tool|godebug|ignore)\s*\($", line)
        if m:
            block = m.group(1)
            continue
        if line.startswith("require "):
            parts = line[len("require "):].split()
            if len(parts) >= 2 and re.match(r"^v\d", parts[1]):
                out.append(Dep(GO, parts[0], parts[1].lstrip("v"), file, direct=not indirect))
    return out[:MAX_DEPS_PER_FILE]


def parse_go_sum(text: str, file: str = "") -> List[Dep]:
    out: List[Dep] = []
    seen = set()
    for raw in text.splitlines():
        parts = raw.split()
        if len(parts) < 3 or parts[1].endswith("/go.mod") or not re.match(r"^v\d", parts[1]):
            continue
        key = (parts[0], parts[1])
        if key not in seen:
            seen.add(key)
            out.append(Dep(GO, parts[0], parts[1].lstrip("v"), file))
    return out[:MAX_DEPS_PER_FILE]


def parse_gemfile_lock(text: str, file: str = "") -> List[Dep]:
    out: List[Dep] = []
    section, in_specs = "", False
    for raw in text.splitlines():
        if not raw.strip():
            in_specs = False
            continue
        if not raw[0].isspace():
            section, in_specs = raw.strip(), False
            continue
        if section != "GEM":
            continue
        if raw.strip() == "specs:":
            in_specs = True
            continue
        if in_specs:
            m = re.match(r"^ {4}([A-Za-z0-9_.-]+) \(([^)]+)\)\s*$", raw)
            if m:
                version = m.group(2).split("-", 1)[0]  # drop platform suffix (x86_64-linux)
                if re.match(r"^\d", version):
                    out.append(Dep(RUBYGEMS, m.group(1), version, file))
    return out[:MAX_DEPS_PER_FILE]


def parse_composer_lock(text: str, file: str = "") -> List[Dep]:
    doc = _json(text)
    out: List[Dep] = []
    if not isinstance(doc, dict):
        return out
    for section, dev in (("packages", False), ("packages-dev", True)):
        for p in doc.get(section) or []:
            if not isinstance(p, dict) or not isinstance(p.get("name"), str):
                continue
            version = str(p.get("version", "")).lstrip("v")
            if re.match(r"^\d", version) and "dev" not in version:
                out.append(Dep(PACKAGIST, p["name"], version, file, dev=dev))
    return out[:MAX_DEPS_PER_FILE]


def parse_nuget_lock(text: str, file: str = "") -> List[Dep]:
    doc = _json(text)
    out: List[Dep] = []
    if not isinstance(doc, dict) or not isinstance(doc.get("dependencies"), dict):
        return out
    seen = set()
    for _tfm, table in doc["dependencies"].items():
        if not isinstance(table, dict):
            continue
        for name, meta in table.items():
            if not isinstance(meta, dict) or str(meta.get("type", "")).lower() == "project":
                continue
            version = str(meta.get("resolved", "")).strip()
            if version and (name, version) not in seen:
                seen.add((name, version))
                out.append(Dep(NUGET, name, version, file, direct=str(meta.get("type", "")).lower() == "direct"))
    return out[:MAX_DEPS_PER_FILE]


# --------------------------------------------------------------------------- dispatch
_TEXT_PARSERS: Dict[str, Callable[[str, str], List[Dep]]] = {
    "package-lock": parse_package_lock, "yarn": parse_yarn_lock, "pnpm": parse_pnpm_lock,
    "requirements": parse_requirements, "poetry": parse_poetry_lock, "pipfile-lock": parse_pipfile_lock,
    "uv": parse_uv_lock, "cargo": parse_cargo_lock, "go.mod": parse_go_mod, "go.sum": parse_go_sum,
    "gemfile-lock": parse_gemfile_lock, "composer-lock": parse_composer_lock, "nuget-lock": parse_nuget_lock,
    "pyproject": parse_pyproject,
}


@dataclass
class ParsedFile:
    path: str
    kind: str
    deps: List[Dep] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)
    error: str = ""


def parse_text(kind: str, text: str, file: str = "") -> ParsedFile:
    """Parse already-loaded text of a known kind. Never raises."""
    res = ParsedFile(file, kind)
    try:
        if kind == "package.json":
            res.deps, res.meta = parse_package_json(text, file)
        else:
            fn = _TEXT_PARSERS.get(kind)
            if fn is None:
                res.error = f"unknown file kind {kind}"
            else:
                res.deps = fn(text, file)
    except Exception as exc:  # a parser bug or pathological input must not abort a scan
        res.error = f"{type(exc).__name__}: {exc}"
        log.debug("parse failed for %s: %s", file, exc)
    return res


def read_text(path: Path, limit: int) -> Optional[str]:
    try:
        if path.stat().st_size > limit:
            return None
        return path.read_bytes().decode("utf-8", errors="replace")
    except OSError:
        return None


def parse_file(path: Path) -> ParsedFile:
    """Classify, read and parse one dependency file."""
    kind = classify(path.name, path.parent.name)
    if kind is None:
        return ParsedFile(str(path), "", error="not a dependency file")
    limit = MAX_MANIFEST_BYTES if kind in ("package.json", "requirements", "pyproject", "go.mod") else MAX_LOCKFILE_BYTES
    text = read_text(path, limit)
    if text is None:
        return ParsedFile(str(path), kind, error="unreadable or too large")
    return parse_text(kind, text.lstrip("﻿"), str(path))
