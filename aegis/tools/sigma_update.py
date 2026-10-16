"""SigmaHQ rule updater.

Downloads the official SigmaHQ release package (default ``sigma_core.zip`` - the high / critical
rules that are least prone to false positives), keeps only the ``rules/windows/**`` YAML files and
installs them into ``<signatures_dir>/sigma`` for the Sigma engine (``aegis.core.sigma``).

Licensing: the SigmaHQ rule collection is published under the Detection Rule License (DRL) 1.1
(https://github.com/SigmaHQ/Detection-Rule-License). Rules are downloaded at the user's request and
copied unmodified (author attribution intact, a ``NOTICE.txt`` is written next to them); they are NOT
vendored into the Aegis repository. Rules written for Aegis itself live in ``aegis/data/sigma``.

Safety, in the same spirit as ``aegis.tools.updater``: the download is size-limited, zip members are
sanitised (no path traversal, only ``rules/windows/**/*.yml|yaml``), at least ``MIN_RULES`` rules must
parse with the Sigma engine, and the new tree is swapped in with directory renames so a failed or
truncated update leaves the previously installed rules untouched. The directory
``<signatures_dir>/sigma`` is managed by this module and replaced as a whole - put your own rules in
``<signatures_dir>/sigma_custom`` (also loaded by the engine).

Network errors never raise; ``update_sigma_rules`` returns ``{"sigma": {"ok", "count", "error", ...}}``
so the caller can merge it into the result of ``aegis.tools.updater.update_signatures``.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import io
import json
import logging
import os
import re
import shutil
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

from aegis import __version__
from aegis.core import sigma

log = logging.getLogger("aegis.sigma_update")

FEED_NAME = "sigma"
USER_AGENT = "Aegis-Security-Suite/" + __version__
RELEASE_BASE = "https://github.com/SigmaHQ/sigma/releases/latest/download/"
# Verified release assets (github.com/SigmaHQ/sigma/releases): core = high+critical, core+ adds medium,
# core++ adds low and emerging threats, all = every rule (largest, noisiest).
PACKAGES: Dict[str, str] = {"core": "sigma_core.zip", "core+": "sigma_core+.zip", "core++": "sigma_core++.zip",
                            "all": "sigma_all_rules.zip"}
DEFAULT_PACKAGE = "core"
RULES_RE = re.compile(r"(?:^|/)rules/windows/(.+\.ya?ml)$", re.I)
SAFE_PART = re.compile(r"^[\w][\w .+()\-]*$")

MIN_RULES = 500  # a package that parses to fewer rules is truncated or not a Sigma package
TIMEOUT = 120
MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024
MAX_MEMBER_BYTES = sigma.MAX_RULE_FILE_BYTES
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_MEMBERS = 20000
DIR_NAME = "sigma"
MANIFEST = "manifest.json"
NOTICE = """The rules in this directory are from the SigmaHQ project (https://github.com/SigmaHQ/sigma) and are
licensed under the Detection Rule License (DRL) 1.1: https://github.com/SigmaHQ/Detection-Rule-License

They were downloaded by Aegis Security Suite ('aegis update') and are used unmodified; each rule keeps its
author attribution. This directory is replaced on every update - put your own rules in ../sigma_custom.
"""


def _say(progress: Optional[Callable[..., None]], msg: str) -> None:
    log.info("%s: %s", FEED_NAME, msg)
    if progress:
        try:
            progress(FEED_NAME, msg)
        except TypeError:  # single-argument callback
            try:
                progress(f"{FEED_NAME}: {msg}")
            except Exception:
                pass
        except Exception:
            pass


def _download(url: str, timeout: float = TIMEOUT) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read(MAX_DOWNLOAD_BYTES + 1)
    if len(data) > MAX_DOWNLOAD_BYTES:
        raise ValueError("download exceeds size limit")
    return data


def resolve_package(config: Any = None, package: Optional[str] = None) -> str:
    """Package name from the argument, ``config.sigma_package`` or ``AEGIS_SIGMA_PACKAGE`` (default ``core``)."""
    name = (package or getattr(config, "sigma_package", "") or os.environ.get("AEGIS_SIGMA_PACKAGE", "")
            or DEFAULT_PACKAGE)
    return str(name).strip().lower()


def package_url(package: str) -> str:
    if package not in PACKAGES:
        raise ValueError(f"unknown Sigma package '{package}' (choose from {', '.join(PACKAGES)})")
    return RELEASE_BASE + PACKAGES[package]


def _safe_relative(match_path: str) -> Optional[Tuple[str, ...]]:
    parts = tuple(p for p in match_path.replace("\\", "/").split("/") if p)
    if not parts or any(p in (".", "..") or not SAFE_PART.match(p) for p in parts):
        return None
    return parts


def extract_rules(raw: bytes, dest: Path) -> Dict[str, Any]:
    """Write the ``rules/windows/**`` YAML files of a Sigma release zip into ``dest`` (created). Returns
    ``{"files": n, "bytes": n, "version": str}``. Raises ValueError for anything that is not a usable archive."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile as exc:
        raise ValueError(f"download is not a zip archive: {exc}")
    infos = zf.infolist()
    if len(infos) > MAX_MEMBERS:
        raise ValueError(f"archive has too many members ({len(infos)})")
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    files = total = 0
    version = ""
    for info in infos:
        name = info.filename.replace("\\", "/")
        if name.lower().endswith("version.txt") and name.count("/") <= 1 and not version and info.file_size < 4096:
            version = " ".join(zf.read(info).decode("utf-8", "replace").split())[:200]
        if info.is_dir():
            continue
        m = RULES_RE.search(name)
        if not m or info.file_size > MAX_MEMBER_BYTES:
            continue
        parts = _safe_relative(m.group(1))
        if parts is None:
            continue
        total += info.file_size
        if total > MAX_TOTAL_BYTES:
            raise ValueError("archive expands beyond the size limit")
        target = dest.joinpath(*parts)
        if root not in target.resolve().parents:
            continue  # belt and braces against path tricks
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(zf.read(info))
        files += 1
    if not files:
        raise ValueError("archive contains no rules/windows YAML files")
    return {"files": files, "bytes": total, "version": version}


def validate_rules(directory: Path, minimum: Optional[int] = None) -> Dict[str, int]:
    """Parse every rule in ``directory`` with the Sigma engine; raises ValueError if fewer than ``minimum`` parse."""
    need = MIN_RULES if minimum is None else minimum
    rules = skipped = unsupported = 0
    for path in sigma.iter_rule_files(directory):
        r, s = sigma.load_rule_file(path)
        rules += len(r)
        skipped += len(s)
        unsupported += sum(1 for x in s if x.kind == "unsupported")
    if rules < need:
        raise ValueError(f"only {rules} rules parsed (expected at least {need}); the package looks invalid")
    return {"rules": rules, "skipped": skipped, "unsupported": unsupported}


def _replace_dir(src: Path, dst: Path, attempts: int = 4) -> None:
    """os.replace with a few retries: on Windows a virus scanner can briefly hold a freshly written directory."""
    for i in range(attempts):
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if i == attempts - 1:
                raise
            time.sleep(0.25 * (i + 1))


def install_sigma_package(raw: bytes, signatures_dir: Path, source: str = "", package: str = "",
                          minimum: Optional[int] = None) -> Dict[str, Any]:
    """Validate a Sigma release zip and atomically install it as ``<signatures_dir>/sigma``. Any failure leaves the
    previously installed rules in place (and raises)."""
    signatures_dir = Path(signatures_dir)
    signatures_dir.mkdir(parents=True, exist_ok=True)
    target = signatures_dir / DIR_NAME
    staging = Path(tempfile.mkdtemp(prefix=".sigma-new-", dir=str(signatures_dir)))
    backup = signatures_dir / f".sigma-old-{os.getpid()}-{int(time.time() * 1000)}"
    try:
        extracted = extract_rules(raw, staging)
        stats = validate_rules(staging, minimum)
        digest = hashlib.sha256(raw).hexdigest()
        manifest = {"source": source, "package": package, "sha256": digest, "bytes": len(raw),
                    "rules": stats["rules"], "unsupported": stats["unsupported"], "files": extracted["files"],
                    "release": extracted["version"],
                    "updated": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "license": "DRL-1.1"}
        (staging / MANIFEST).write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        (staging / "NOTICE.txt").write_text(NOTICE, encoding="utf-8")
        had_old = target.exists()
        try:
            if had_old:
                _replace_dir(target, backup)
            _replace_dir(staging, target)
        except BaseException:
            if had_old and backup.exists() and not target.exists():
                try:
                    _replace_dir(backup, target)  # put the previous rules back
                except OSError:  # pragma: no cover - nothing more we can do
                    log.error("could not restore the previous Sigma rules from %s", backup)
            raise
        return {"count": stats["rules"], "unsupported": stats["unsupported"], "files": extracted["files"],
                "bytes": len(raw), "sha256": digest, "release": extracted["version"], "path": str(target)}
    finally:
        shutil.rmtree(staging, ignore_errors=True)
        if target.exists():
            shutil.rmtree(backup, ignore_errors=True)


def installed_manifest(config: Any) -> Dict[str, Any]:
    """The manifest of the installed SigmaHQ rules ({} if none)."""
    try:
        return json.loads((Path(config.signatures_dir) / DIR_NAME / MANIFEST).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def update_sigma_rules(config: Any, progress: Optional[Callable[..., None]] = None,
                       package: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    """Download and install the SigmaHQ Windows rules. Never raises.

    Returns ``{"sigma": {"ok": bool, "count": int, "error": str, ...}}`` (extra keys: ``bytes``, ``sha256``,
    ``source``, ``package``, ``unsupported``, ``release``; ``skipped: True`` when PyYAML is missing)."""
    def fail(msg: str, **extra: Any) -> Dict[str, Dict[str, Any]]:
        out: Dict[str, Any] = {"ok": False, "count": 0, "error": msg}
        out.update(extra)
        return {FEED_NAME: out}

    if not sigma.available():
        return fail("PyYAML not installed; skipped (pip install pyyaml)", skipped=True)
    pkg = resolve_package(config, package)
    try:
        url = package_url(pkg)
    except ValueError as exc:
        return fail(str(exc))
    _say(progress, f"downloading the SigmaHQ '{pkg}' Windows rule package")
    try:
        raw = _download(url)
    except urllib.error.HTTPError as exc:
        _say(progress, f"failed: HTTP {exc.code}; previous rules kept")
        return fail(f"HTTP {exc.code}", source=url, package=pkg)
    except Exception as exc:
        _say(progress, f"failed: {exc}; previous rules kept")
        return fail(f"{type(exc).__name__}: {exc}", source=url, package=pkg)
    try:
        info = install_sigma_package(raw, Path(config.signatures_dir), source=url, package=pkg)
    except Exception as exc:
        _say(progress, f"failed: {exc}; previous rules kept")
        return fail(f"{type(exc).__name__}: {exc}", source=url, package=pkg)
    _say(progress, f"updated ({info['count']} rules, {info['unsupported']} unsupported)")
    return {FEED_NAME: {"ok": True, "count": info["count"], "error": "", "bytes": info["bytes"],
                        "sha256": info["sha256"], "source": url, "package": pkg, "unsupported": info["unsupported"],
                        "release": info["release"]}}
