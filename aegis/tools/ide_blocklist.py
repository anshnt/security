"""Malicious IDE-extension blocklist: parser, loader and updater.

Source (primary): Microsoft's list of extensions removed from the VS Code Marketplace,
https://github.com/microsoft/vsmarketplace/blob/main/RemovedPackages.md (fetched from the raw
URL below). It is a Markdown table ``| Extension Identifier | Removal Date | Type |``; the type
column uses Microsoft's own vocabulary (Malware, Impersonation, Untrustworthy, Spam, ...).

Aegis keeps only the security-relevant rows and maps them to three categories:

* ``malware``        - Type contains "Malware" or is "Potentially malicious"
* ``impersonation``  - "Impersonation" or "Typo-squatting"
* ``untrustworthy``  - "Untrustworthy"

Spam, copyright, owner/publisher-requested and deprecated removals are not security signals and
are dropped. The result is written as ``id<TAB>category<TAB>YYYY-MM-DD`` lines (``#`` comments
allowed) to ``<signatures_dir>/malicious_ide_extensions.txt``; the scanner reads that file in
addition to the copy bundled in ``aegis/data``.

The updater validates the download (table header present, ids well-formed, minimum counts, no
suspicious shrinkage) and installs it atomically, so a failed or truncated download never
destroys a working list. It never raises on network errors.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import logging
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from aegis import __version__
from aegis.core.config import PACKAGE_DATA
from aegis.tools.updater import atomic_write

log = logging.getLogger("aegis.ide_blocklist")

SOURCE_PAGE = "https://github.com/microsoft/vsmarketplace/blob/main/RemovedPackages.md"
SOURCE_RAW = "https://raw.githubusercontent.com/microsoft/vsmarketplace/main/RemovedPackages.md"
FILENAME = "malicious_ide_extensions.txt"
USER_AGENT = "Aegis-Security-Suite/" + __version__
TIMEOUT = 60
MAX_BYTES = 8 * 1024 * 1024
MIN_ROWS = 500  # the real table has > 2,000 rows
MIN_MALWARE = 100
MAX_SHRINK = 0.5

CATEGORIES = ("malware", "impersonation", "untrustworthy")
_RANK = {c: i for i, c in enumerate(CATEGORIES)}  # lower index = stronger

_EXT_ID = re.compile(r"^[a-z0-9][a-z0-9_-]*\.[a-z0-9][a-z0-9._-]*$", re.I)
_DATE = re.compile(r"^(\d{1,2})/(\d{1,2})/(\d{4})$")


@dataclass(frozen=True)
class Entry:
    ext_id: str  # lower-case "publisher.name"
    category: str  # one of CATEGORIES
    removed: str  # ISO date or ""
    ms_type: str = ""  # Microsoft's original wording


def classify_type(ms_type: str) -> Optional[str]:
    """Microsoft removal type -> Aegis category (None = not a security signal)."""
    t = (ms_type or "").strip().lower()
    if "malware" in t or "potentially malicious" in t:
        return "malware"
    if "impersonation" in t or "typo-squatting" in t or "typosquatting" in t:
        return "impersonation"
    if "untrustworthy" in t:
        return "untrustworthy"
    return None


def _iso_date(text: str) -> str:
    m = _DATE.match((text or "").strip())
    if not m:
        return ""
    month, day, year = (int(x) for x in m.groups())
    try:
        return dt.date(year, month, day).isoformat()
    except ValueError:
        return ""


def parse_removed_packages(markdown: str) -> Tuple[List[Entry], int]:
    """Parse RemovedPackages.md. Returns (entries kept, number of table rows seen).
    Duplicate ids keep the strongest category and the latest removal date."""
    best: Dict[str, Entry] = {}
    rows = 0
    for line in markdown.splitlines():
        if not line.lstrip().startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 3:
            continue
        ext_id, removed, ms_type = cells[0], cells[1], cells[2]
        if not _EXT_ID.match(ext_id):  # header row, separator row, junk
            continue
        rows += 1
        cat = classify_type(ms_type)
        if not cat:
            continue
        entry = Entry(ext_id.lower(), cat, _iso_date(removed), ms_type)
        old = best.get(entry.ext_id)
        if old is None:
            best[entry.ext_id] = entry
        else:
            stronger = _RANK[entry.category] < _RANK[old.category]
            same_newer = entry.category == old.category and entry.removed > old.removed
            if stronger or same_newer:
                best[entry.ext_id] = entry
    return sorted(best.values(), key=lambda e: e.ext_id), rows


def render_blocklist(entries: Iterable[Entry], retrieved: Optional[str] = None) -> str:
    entries = list(entries)
    retrieved = retrieved or dt.date.today().isoformat()
    counts = {c: sum(1 for e in entries if e.category == c) for c in CATEGORIES}
    head = [
        "# Malicious / removed VS Code Marketplace extension ids (VS Code, VSCodium, Cursor, Windsurf ...).",
        f"# Source: Microsoft, {SOURCE_PAGE}",
        f"# Raw:    {SOURCE_RAW}",
        f"# Retrieved {retrieved}; {len(entries)} ids (" + ", ".join(f"{counts[c]} {c}" for c in CATEGORIES) + ").",
        "# Only the types Malware / Potentially malicious (malware), Impersonation / Typo-squatting (impersonation)",
        "# and Untrustworthy are kept; Spam, copyright, owner-requested and deprecated removals are not listed.",
        "# Format: <publisher.name><TAB><category><TAB><removal date, ISO>. Ids are case-insensitive.",
        "# Refresh with aegis.tools.ide_blocklist.update_ide_blocklist(config).",
    ]
    body = [f"{e.ext_id}\t{e.category}\t{e.removed}" for e in entries]
    return "\n".join(head + body) + "\n"


def parse_blocklist(text: str) -> Dict[str, Tuple[str, str]]:
    """Blocklist file text -> {id_lower: (category, removal_date)}. Tolerates plain id-per-line files."""
    out: Dict[str, Tuple[str, str]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t") if "\t" in line else line.split()
        ext_id = parts[0].strip().lower()
        if not _EXT_ID.match(ext_id):
            continue
        cat = parts[1].strip().lower() if len(parts) > 1 else "malware"
        if cat not in CATEGORIES:
            cat = "malware"
        removed = parts[2].strip() if len(parts) > 2 else ""
        old = out.get(ext_id)
        if old is None or _RANK[cat] < _RANK[old[0]]:
            out[ext_id] = (cat, removed)
    return out


def load_blocklist(signatures_dir: Optional[Path] = None) -> Dict[str, Tuple[str, str]]:
    """Packaged list merged with the user's updated copy (the updated copy wins on conflicts)."""
    merged: Dict[str, Tuple[str, str]] = {}
    paths = [PACKAGE_DATA / FILENAME]
    if signatures_dir is not None:
        paths.append(Path(signatures_dir) / FILENAME)
    for p in paths:
        try:
            merged.update(parse_blocklist(p.read_text(encoding="utf-8", errors="replace")))
        except OSError:
            continue
    return merged


def _download(url: str = SOURCE_RAW, timeout: float = TIMEOUT) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    resp = urllib.request.urlopen(req, timeout=timeout)
    try:
        data = resp.read(MAX_BYTES + 1)
    finally:
        close = getattr(resp, "close", None)
        if close:
            close()
    if len(data) > MAX_BYTES:
        raise ValueError("download exceeds size limit")
    return data


def update_ide_blocklist(config: Any, progress: Optional[Callable[..., None]] = None) -> Dict[str, Any]:
    """Download Microsoft's removed-extensions list and install the parsed blocklist into
    ``config.signatures_dir``. Returns ``{"ok": bool, "count": int, "error": str, "source": str, ...}``;
    never raises and never replaces a working list with a broken one."""
    result: Dict[str, Any] = {"ok": False, "count": 0, "error": "", "source": SOURCE_PAGE}

    def say(msg: str) -> None:
        log.info("ide_blocklist: %s", msg)
        if progress:
            try:
                progress("ide_blocklist", msg)
            except TypeError:
                try:
                    progress(f"ide_blocklist: {msg}")
                except Exception:
                    pass
            except Exception:
                pass

    try:
        directory = Path(config.signatures_dir)
        say("downloading Microsoft VS Marketplace removed-packages list")
        raw = _download()
        text = raw.decode("utf-8", errors="replace")
        if "Extension Identifier" not in text:
            raise ValueError("unexpected document: table header 'Extension Identifier' not found")
        entries, rows = parse_removed_packages(text)
        malware = sum(1 for e in entries if e.category == "malware")
        if rows < MIN_ROWS or malware < MIN_MALWARE:
            raise ValueError(f"list looks invalid: {rows} rows / {malware} malware entries "
                             f"(expected at least {MIN_ROWS} / {MIN_MALWARE})")
        target = directory / FILENAME
        try:
            previous = len(parse_blocklist(target.read_text(encoding="utf-8", errors="replace")))
        except OSError:
            previous = 0
        if previous and len(entries) < previous * MAX_SHRINK:
            raise ValueError(f"list shrank suspiciously ({previous} -> {len(entries)}); keeping previous copy")
        out = render_blocklist(entries).encode("utf-8")
        atomic_write(target, out)
        result.update(ok=True, count=len(entries), malware=malware, rows=rows, bytes=len(raw),
                      sha256=hashlib.sha256(raw).hexdigest(), path=str(target))
        say(f"updated ({len(entries)} ids, {malware} malware)")
    except urllib.error.HTTPError as exc:
        result["error"] = f"HTTP {exc.code}"
        say(f"failed: {result['error']}; previous copy kept")
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        say(f"failed: {exc}; previous copy kept")
    return result
