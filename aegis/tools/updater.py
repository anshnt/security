"""Signature / threat-feed updater.

Downloads public abuse.ch and community feeds into ``config.signatures_dir``.
Each feed is validated before it replaces the previous copy (temp file +
``os.replace``), so a failed or truncated download never destroys a working
database. Results and timestamps are recorded in ``update_state.json``."""

from __future__ import annotations

import datetime as dt
import hashlib
import io
import ipaddress
import json
import logging
import os
import re
import tempfile
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

log = logging.getLogger("aegis.updater")

USER_AGENT = "Aegis-Security-Suite/1.0"
TIMEOUT = 60
MAX_BYTES = 64 * 1024 * 1024  # refuse absurdly large downloads
STATE_FILE = "update_state.json"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_EXT_ID = re.compile(r"^[a-p]{32}$")
_HOSTNAME = re.compile(r"^(?=.{4,253}$)([a-z0-9_-]{1,63}\.)+[a-z0-9-]{2,63}$")

YARA_FORGE_API = "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest"
YARA_FORGE_FALLBACK = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip"


# --------------------------------------------------------------------------- validators

def _data_lines(text: str) -> List[str]:
    return [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith(("#", ";", "//"))]


def _valid_sha256(text: str) -> int:
    return sum(1 for ln in _data_lines(text) if _SHA256.match(ln.split()[0].lower()))


def _valid_ip(text: str) -> int:
    n = 0
    for ln in _data_lines(text):
        try:
            ipaddress.ip_address(ln.split(",")[0].split()[0])
            n += 1
        except ValueError:
            pass
    return n


def _valid_hosts(text: str) -> int:
    n = 0
    for ln in _data_lines(text):
        parts = ln.split()
        if len(parts) >= 2 and parts[0] in ("127.0.0.1", "0.0.0.0") and _HOSTNAME.match(parts[1].lower()):
            n += 1
    return n


def _valid_ext_ids(text: str) -> int:
    return sum(1 for ln in _data_lines(text) if _EXT_ID.match(ln.split()[0].lower()))


@dataclass
class Feed:
    name: str
    url: str
    filename: str
    validate: Callable[[str], int]  # returns number of valid entries
    min_count: int
    auth: bool = True  # send Auth-Key when configured (abuse.ch)
    description: str = ""
    max_shrink: float = 0.0  # reject if new count < max_shrink * previous count (0 = off)


FEEDS: List[Feed] = [
    Feed("malwarebazaar", "https://bazaar.abuse.ch/export/txt/sha256/recent/", "malwarebazaar_recent.txt",
         _valid_sha256, 100, description="MalwareBazaar recent malware SHA-256 hashes"),
    Feed("feodo", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "feodo_ipblocklist.txt",
         _valid_ip, 1, description="Feodo Tracker botnet C2 IP blocklist"),
    Feed("urlhaus", "https://urlhaus.abuse.ch/downloads/hostfile/", "urlhaus_hosts.txt",
         _valid_hosts, 10, description="URLhaus malware-distribution hosts"),
    Feed("malicious_extensions", "https://codeberg.org/palant/malicious-extensions-list/raw/branch/main/list.txt",
         "malicious_extensions.txt", _valid_ext_ids, 20, auth=False, max_shrink=0.5,
         description="Known malicious browser extension IDs (Wladimir Palant)"),
]


# --------------------------------------------------------------------------- plumbing

def _request(url: str, headers: Optional[Dict[str, str]] = None, timeout: float = TIMEOUT) -> bytes:
    hdrs = {"User-Agent": USER_AGENT}
    hdrs.update(headers or {})
    req = urllib.request.Request(url, headers=hdrs)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("download exceeds size limit")
    return data


def atomic_write(path: Path, data: bytes) -> None:
    """Write via a temp file in the same directory, then replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _load_state(directory: Path) -> Dict[str, Any]:
    try:
        return json.loads((directory / STATE_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _count_existing(feed: Feed, directory: Path) -> int:
    try:
        return feed.validate((directory / feed.filename).read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return 0


def _say(progress: Optional[Callable[..., None]], name: str, msg: str) -> None:
    log.info("%s: %s", name, msg)
    if progress:
        try:
            progress(name, msg)
        except TypeError:  # single-argument callback
            try:
                progress(f"{name}: {msg}")
            except Exception:
                pass
        except Exception:
            pass


# --------------------------------------------------------------------------- feed updates

def update_feed(feed: Feed, directory: Path, auth_key: str = "") -> Dict[str, Any]:
    """Download + validate + atomically install one text feed."""
    headers = {"Auth-Key": auth_key} if (auth_key and feed.auth) else {}
    raw = _request(feed.url, headers)
    text = raw.decode("utf-8", errors="replace")
    count = feed.validate(text)
    if count < feed.min_count:
        raise ValueError(f"feed looks invalid: only {count} valid entries (expected at least {feed.min_count})")
    if feed.max_shrink:
        prev = _count_existing(feed, directory)
        if prev and count < prev * feed.max_shrink:
            raise ValueError(f"feed shrank suspiciously ({prev} -> {count}); keeping previous copy")
    atomic_write(directory / feed.filename, raw)
    return {"count": count, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def _have_yara() -> bool:
    try:
        import yara  # type: ignore  # noqa: F401

        return True
    except Exception:
        return False


def _resolve_yara_forge_url(auth_token: str = "") -> str:
    """Latest release asset 'yara-forge-rules-core.zip' via the GitHub API;
    falls back to the stable /releases/latest/download/ redirect."""
    headers = {"Accept": "application/vnd.github+json"}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    try:
        doc = json.loads(_request(YARA_FORGE_API, headers, timeout=30).decode("utf-8", "replace"))
        for asset in doc.get("assets", []):
            name = str(asset.get("name", "")).lower()
            if name.startswith("yara-forge-rules-core") and name.endswith(".zip"):
                return str(asset["browser_download_url"])
    except Exception as exc:
        log.info("GitHub API lookup for YARA Forge failed (%s); using fallback URL", exc)
    return YARA_FORGE_FALLBACK


def update_yara_forge(directory: Path) -> Dict[str, Any]:
    """Install the YARA Forge 'core' ruleset into <directory>/yara/ (needs yara-python)."""
    import yara  # type: ignore

    url = _resolve_yara_forge_url(os.environ.get("GITHUB_TOKEN", ""))
    raw = _request(url, timeout=180)
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile as exc:
        raise ValueError(f"download is not a zip archive: {exc}")
    members = [i for i in zf.infolist() if i.filename.lower().endswith((".yar", ".yara")) and not i.is_dir()]
    if not members:
        raise ValueError("archive contains no .yar files")
    dest = directory / "yara"
    dest.mkdir(parents=True, exist_ok=True)
    total_rules = 0
    installed: List[str] = []
    for info in members:
        if info.file_size > 64 * 1024 * 1024:
            continue
        data = zf.read(info)
        # Validate by compiling a temp copy first; never install a broken ruleset.
        fd, tmp = tempfile.mkstemp(suffix=".yar", dir=str(dest))
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            yara.compile(filepath=tmp)
        except Exception as exc:
            log.warning("skipping YARA file %s: %s", info.filename, exc)
            continue
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        name = "yara-forge-" + re.sub(r"[^A-Za-z0-9._-]", "_", Path(info.filename).name)  # basename only: no zip-slip
        atomic_write(dest / name, data)
        installed.append(name)
        total_rules += len(re.findall(rb"^\s*(?:(?:private|global)\s+)*rule\s+\w+", data, re.M))
    if not installed:
        raise ValueError("no YARA file in the archive compiled successfully")
    return {"count": total_rules, "files": installed, "source": url, "bytes": len(raw)}


def update_signatures(config: Any, progress: Optional[Callable[..., None]] = None) -> Dict[str, Dict[str, Any]]:
    """Refresh every feed. Returns ``{feed: {"ok": bool, "count": int, "error": str}}``.
    Failures never raise and never remove the previously installed copy."""
    directory = Path(config.signatures_dir)
    auth_key = getattr(config, "abusech_auth_key", "") or ""
    state = _load_state(directory)
    state.setdefault("feeds", {})
    results: Dict[str, Dict[str, Any]] = {}

    def record(name: str, ok: bool, count: int = 0, error: str = "", **extra: Any) -> None:
        results[name] = {"ok": ok, "count": count, "error": error}
        results[name].update({k: v for k, v in extra.items() if k == "skipped"})
        entry = state["feeds"].setdefault(name, {})
        entry["last_attempt"] = _now()
        entry["ok"] = ok
        if ok:
            entry.update({"updated": entry["last_attempt"], "count": count, "error": "", **{
                k: v for k, v in extra.items() if k in ("bytes", "sha256", "files", "source")}})
        else:
            entry["error"] = error

    for feed in FEEDS:
        _say(progress, feed.name, f"downloading {feed.description}")
        try:
            info = update_feed(feed, directory, auth_key)
            record(feed.name, True, info["count"], bytes=info["bytes"], sha256=info["sha256"])
            _say(progress, feed.name, f"updated ({info['count']} entries)")
        except urllib.error.HTTPError as exc:
            hint = " (an abuse.ch Auth-Key is required: set abusech_auth_key)" if exc.code in (401, 403) and feed.auth else ""
            record(feed.name, False, error=f"HTTP {exc.code}{hint}")
            _say(progress, feed.name, f"failed: HTTP {exc.code}{hint}; previous copy kept")
        except Exception as exc:
            record(feed.name, False, error=f"{type(exc).__name__}: {exc}")
            _say(progress, feed.name, f"failed: {exc}; previous copy kept")

    if _have_yara():
        _say(progress, "yara_forge", "downloading YARA Forge core ruleset")
        try:
            info = update_yara_forge(directory)
            record("yara_forge", True, info["count"], bytes=info["bytes"], files=info["files"], source=info["source"])
            _say(progress, "yara_forge", f"updated ({info['count']} rules)")
        except Exception as exc:
            record("yara_forge", False, error=f"{type(exc).__name__}: {exc}")
            _say(progress, "yara_forge", f"failed: {exc}; previous copy kept")
    else:
        record("yara_forge", False, error="yara-python not installed; skipped (pip install yara-python)", skipped=True)

    state["last_run"] = _now()
    state["any_updated"] = any(r["ok"] for r in results.values())
    try:
        atomic_write(directory / STATE_FILE, json.dumps(state, indent=2).encode("utf-8"))
    except OSError as exc:
        log.warning("could not write %s: %s", STATE_FILE, exc)
    return results
