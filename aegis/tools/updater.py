"""Signature / threat-feed updater.

Downloads public abuse.ch and community feeds into ``config.signatures_dir``.
Each feed is validated before it replaces the previous copy (temp file +
``os.replace``), so a failed or truncated download never destroys a working
database. Results and timestamps are recorded in ``update_state.json``.

abuse.ch (MalwareBazaar, URLhaus, Feodo) asks users to register for a free
Auth-Key (config ``abusech_auth_key`` / env ``AEGIS_ABUSECH_KEY``), which is sent
when set, and its terms restrict free use to non-commercial purposes - commercial
deployments may need a subscription. See docs/FEEDS.md."""

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

from aegis import __version__

log = logging.getLogger("aegis.updater")

USER_AGENT = "Aegis-Security-Suite/" + __version__
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


_DRIVER_LINE = re.compile(r"^[0-9a-f]{64}\t\S")


def _valid_driver_lines(text: str) -> int:
    return sum(1 for line in text.splitlines() if _DRIVER_LINE.match(line))


def loldrivers_to_tsv(raw: bytes) -> bytes:
    """LOLDrivers drivers.json -> ``sha256<TAB>label`` lines (the format of
    aegis/data/vulnerable_drivers.txt that the drivers scanner loads)."""
    doc = json.loads(raw.decode("utf-8", "replace"))
    rows: Dict[str, str] = {}

    def clean(v: Any) -> str:
        return re.sub(r"[\t\r\n]+", " ", str(v)).strip()

    for e in doc if isinstance(doc, list) else []:
        if not isinstance(e, dict):
            continue
        cat = "MalDriver" if str(e.get("Category", "")).lower() == "malicious" else "VulnDriver"
        cves = e.get("CVE") or e.get("CVEs") or []
        cves = [clean(c) for c in ([cves] if isinstance(cves, str) else cves) if re.fullmatch(r"CVE-\d{4}-\d{4,7}", clean(c))]
        tag = (e.get("Tags") or [""])[0] if isinstance(e.get("Tags"), list) else ""
        for smp in e.get("KnownVulnerableSamples") or []:
            if not isinstance(smp, dict):
                continue
            h = str(smp.get("SHA256") or "").strip().lower()
            if not _SHA256.match(h):
                continue
            cand = [clean(x) for x in (smp.get("OriginalFilename"), smp.get("Filename"), tag) if x]
            name = next((c for c in cand if c.lower().endswith(".sys")), cand[0] if cand else "unknown.sys")
            rows.setdefault(h, f"LOLDrivers.{cat}: {name}" + (f" [{','.join(cves[:3])}]" if cves else ""))
    return ("\n".join(f"{h}\t{rows[h]}" for h in sorted(rows)) + "\n").encode("utf-8")


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
    transform: Optional[Callable[[bytes], bytes]] = None  # convert the download before validation
    allow_empty: bool = False  # a currently-empty feed is OK: keep the previous copy, report 0


FEEDS: List[Feed] = [
    Feed("malwarebazaar", "https://bazaar.abuse.ch/export/txt/sha256/recent/", "malwarebazaar_recent.txt",
         _valid_sha256, 100, description="MalwareBazaar recent malware SHA-256 hashes"),
    # Feodo Tracker has published (near-)empty datasets since 2026-03 (docs/FEEDS.md); an empty
    # list is not an error - the previous copy is kept.
    Feed("feodo", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "feodo_ipblocklist.txt",
         _valid_ip, 1, description="Feodo Tracker botnet C2 IP blocklist", allow_empty=True),
    Feed("urlhaus", "https://urlhaus.abuse.ch/downloads/hostfile/", "urlhaus_hosts.txt",
         _valid_hosts, 10, description="URLhaus malware-distribution hosts"),
    Feed("malicious_extensions", "https://codeberg.org/palant/malicious-extensions-list/raw/branch/main/list.txt",
         "malicious_extensions.txt", _valid_ext_ids, 20, auth=False, max_shrink=0.5,
         description="Known malicious browser extension IDs (Wladimir Palant)"),
    Feed("loldrivers", "https://www.loldrivers.io/api/drivers.json", "vulnerable_drivers.txt",
         _valid_driver_lines, 500, auth=False, max_shrink=0.5, transform=loldrivers_to_tsv,
         description="LOLDrivers vulnerable/malicious Windows driver hashes (BYOVD, Apache-2.0)"),
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
    if feed.transform:
        raw = feed.transform(raw)
    text = raw.decode("utf-8", errors="replace")
    count = feed.validate(text)
    if count == 0 and feed.allow_empty:
        return {"count": 0, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                "note": "feed is currently empty upstream; previous copy kept"}
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

    # The /releases/latest/download/ redirect is the verified, keyless path (the API is
    # rate-limited and blocked on some networks), so try it first.
    url = YARA_FORGE_FALLBACK
    try:
        raw = _request(url, timeout=180)
    except Exception as exc:
        log.info("direct YARA Forge download failed (%s); asking the GitHub API", exc)
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

    # Malicious VS Code-family extensions (Microsoft Marketplace removed-packages list).
    try:
        from aegis.tools.ide_blocklist import update_ide_blocklist

        r = update_ide_blocklist(config, progress)
        record("ide_blocklist", bool(r.get("ok")), int(r.get("count") or 0), str(r.get("error") or ""))
    except Exception as exc:
        record("ide_blocklist", False, error=f"{type(exc).__name__}: {exc}")

    # SigmaHQ community detection rules (needs PyYAML; DRL 1.1 licence, see aegis/tools/sigma_update.py).
    try:
        from aegis.core import sigma as _sigma
        from aegis.tools.sigma_update import update_sigma_rules

        if _sigma.available():
            for name, r in update_sigma_rules(config, progress).items():
                record(name, bool(r.get("ok")), int(r.get("count") or 0), str(r.get("error") or ""))
        else:
            record("sigma", False, error="PyYAML not installed; skipped (pip install pyyaml)", skipped=True)
    except Exception as exc:
        record("sigma", False, error=f"{type(exc).__name__}: {exc}")

    state["last_run"] = _now()
    state["any_updated"] = any(r["ok"] for r in results.values())
    try:
        atomic_write(directory / STATE_FILE, json.dumps(state, indent=2).encode("utf-8"))
    except OSError as exc:
        log.warning("could not write %s: %s", STATE_FILE, exc)
    return results
