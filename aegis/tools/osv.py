"""OSV.dev client for the supply-chain scanner: batched vulnerability / malicious-package lookups
with an on-disk cache and graceful offline behaviour.

API (verified without a key): ``POST https://api.osv.dev/v1/querybatch`` (<= 1000 queries per call,
returns only advisory ids) and ``GET https://api.osv.dev/v1/vulns/{id}`` (full advisory, fetched only
for ids that need details). Known-malicious packages show up as ``MAL-*`` advisories from the
OpenSSF malicious-packages dataset, so they are recognisable from the id alone.

Only ecosystem, package name and version are sent - no paths, host names or other personal data.

Cache: ``<config.home>/osv_cache.json`` holds per-package id lists and per-advisory summaries with a
timestamp. Entries younger than the TTL (default 24 h) are used without touching the network; when
the network is unavailable older entries (up to 30 days) are used as a fallback and ``offline`` is
set so the caller can say "results from cache only". Nothing here raises on network errors.
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, NamedTuple, Optional, Set

from aegis import __version__

log = logging.getLogger("aegis.osv")

OSV_API = "https://api.osv.dev/v1"
QUERYBATCH_URL = OSV_API + "/querybatch"
VULN_URL = OSV_API + "/vulns/"
MAX_BATCH = 1000
MAX_PAGES = 8  # follow-up pages for queries that return a next_page_token
CACHE_FILE = "osv_cache.json"
CACHE_VERSION = 1
DEFAULT_TTL = 24 * 3600
STALE_LIMIT = 30 * 86400  # entries older than this are dropped even for offline use
MAX_RESPONSE = 64 * 1024 * 1024
USER_AGENT = "Aegis-Security-Suite/" + __version__

_ID_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{2,120}$")
_MALWARE_SUMMARY = re.compile(r"^\s*(malicious\s+(code|package)|embedded\s+malicious\s+code|malware)\b", re.I)


class Pkg(NamedTuple):
    """One package version to look up. ``ecosystem`` uses OSV's names: npm, PyPI, crates.io, Go,
    RubyGems, Packagist, NuGet."""

    ecosystem: str
    name: str
    version: str

    @property
    def key(self) -> str:
        return f"{self.ecosystem}/{self.name}@{self.version}"


def norm_name(ecosystem: str, name: str) -> str:
    """Name as sent to OSV: PEP 503 normalisation for PyPI, lower case for npm and Packagist (their registries are
    case-insensitive), unchanged elsewhere (Go module paths and NuGet ids are case-sensitive in OSV)."""
    n = name.strip()
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", n.lower())
    if ecosystem in ("npm", "Packagist"):
        return n.lower()
    return n


def fixed_key(ecosystem: str, name: str) -> str:
    """Case-insensitive key of VulnInfo.fixed: ``<ecosystem>/<normalised lower-case name>``."""
    return f"{ecosystem}/{norm_name(ecosystem, name).lower()}"


@dataclass
class VulnInfo:
    id: str
    summary: str = ""
    severity: str = ""  # CRITICAL | HIGH | MEDIUM | LOW | "" (unknown)
    score: Optional[float] = None  # CVSS base score when it could be derived
    severity_source: str = ""  # database | cvss3 | cvss2 | cvss4-estimate | affected | malware | default
    aliases: List[str] = field(default_factory=list)
    malicious: bool = False
    withdrawn: bool = False
    fixed: Dict[str, List[str]] = field(default_factory=dict)  # fixed_key(ecosystem, name) -> fixed versions
    published: str = ""
    modified: str = ""
    complete: bool = True  # False = placeholder because the advisory could not be fetched

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "VulnInfo":
        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in d.items() if k in known})


# --------------------------------------------------------------------------- CVSS
_V3_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_V3_AC = {"L": 0.77, "H": 0.44}
_V3_UI = {"N": 0.85, "R": 0.62}
_V3_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(x: float) -> float:
    i = int(round(x * 100000))
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector: str) -> Optional[float]:
    """CVSS v3.0/v3.1 base score from a vector string, None if it cannot be parsed."""
    try:
        parts = dict(p.split(":", 1) for p in vector.strip().split("/") if ":" in p)
        scope_changed = parts["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[parts["PR"]]
        iss = 1 - (1 - _V3_CIA[parts["C"]]) * (1 - _V3_CIA[parts["I"]]) * (1 - _V3_CIA[parts["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
        expl = 8.22 * _V3_AV[parts["AV"]] * _V3_AC[parts["AC"]] * pr * _V3_UI[parts["UI"]]
        if impact <= 0:
            return 0.0
        total = 1.08 * (impact + expl) if scope_changed else impact + expl
        return _roundup(min(total, 10.0))
    except (KeyError, ValueError):
        return None


def cvss2_score(vector: str) -> Optional[float]:
    """CVSS v2 base score from a vector string, None if it cannot be parsed."""
    try:
        parts = dict(p.split(":", 1) for p in vector.strip().strip("()").split("/") if ":" in p)
        av = {"L": 0.395, "A": 0.646, "N": 1.0}[parts["AV"]]
        ac = {"H": 0.35, "M": 0.61, "L": 0.71}[parts["AC"]]
        au = {"M": 0.45, "S": 0.56, "N": 0.704}[parts["Au"]]
        cia = {"N": 0.0, "P": 0.275, "C": 0.660}
        impact = 10.41 * (1 - (1 - cia[parts["C"]]) * (1 - cia[parts["I"]]) * (1 - cia[parts["A"]]))
        expl = 20 * av * ac * au
        f = 0 if impact == 0 else 1.176
        return round(((0.6 * impact) + (0.4 * expl) - 1.5) * f, 1)
    except (KeyError, ValueError):
        return None


def cvss4_band(vector: str) -> Optional[str]:
    """Coarse severity band for a CVSS v4 vector. The v4 score needs lookup tables Aegis does not
    carry, so this is an estimate from exploitability and the vulnerable-system impact metrics."""
    try:
        parts = dict(p.split(":", 1) for p in vector.strip().split("/") if ":" in p)
        high = sum(1 for k in ("VC", "VI", "VA") if parts.get(k) == "H")
        easy = parts["AV"] == "N" and parts.get("AT", "N") == "N" and parts.get("PR", "N") == "N"
        if high == 3 and easy:
            return "CRITICAL"
        if high >= 2 or (high >= 1 and easy):
            return "HIGH"
        if high or any(parts.get(k) == "L" for k in ("VC", "VI", "VA")):
            return "MEDIUM"
        return "LOW"
    except KeyError:
        return None


def severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _label(value: Any) -> str:
    v = str(value or "").strip().upper()
    if v == "MODERATE":
        return "MEDIUM"
    return v if v in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else ""


def version_key(version: str) -> List[Any]:
    """Generic, ecosystem-agnostic version sort key (numbers numerically, text lexically)."""
    parts = re.findall(r"\d+|[A-Za-z]+", version)
    return [(0, int(p)) if p.isdigit() else (-1, p.lower()) for p in parts]


_vkey = version_key


def pick_fixed(installed: str, fixed_versions: Iterable[str]) -> str:
    """The smallest fixed version above `installed` (best effort; falls back to the largest listed)."""
    cands = sorted({v for v in fixed_versions if v}, key=_vkey)
    if not cands:
        return ""
    try:
        above = [v for v in cands if _vkey(v) > _vkey(installed)]
    except TypeError:
        above = []
    return above[0] if above else cands[-1]


def parse_vuln(doc: Dict[str, Any]) -> VulnInfo:
    """Reduce a full OSV advisory document to the fields Aegis needs."""
    vid = str(doc.get("id", ""))
    db = doc.get("database_specific") if isinstance(doc.get("database_specific"), dict) else {}
    info = VulnInfo(
        id=vid,
        summary=str(doc.get("summary") or "").strip()[:300],
        aliases=[str(a) for a in (doc.get("aliases") or []) if isinstance(a, str)][:12],
        withdrawn=bool(doc.get("withdrawn")),
        published=str(doc.get("published") or ""),
        modified=str(doc.get("modified") or ""),
    )
    cwes = db.get("cwe_ids") if isinstance(db.get("cwe_ids"), list) else []
    info.malicious = (vid.startswith("MAL-") or "CWE-506" in cwes or bool(_MALWARE_SUMMARY.match(info.summary)))

    affected = [a for a in (doc.get("affected") or []) if isinstance(a, dict)]
    for a in affected[:60]:
        pkg = a.get("package") if isinstance(a.get("package"), dict) else {}
        eco, name = str(pkg.get("ecosystem") or ""), str(pkg.get("name") or "")
        if not eco or not name:
            continue
        key = fixed_key(eco.split(":")[0], name)
        for rng in a.get("ranges") or []:
            if not isinstance(rng, dict) or rng.get("type") == "GIT":
                continue
            for ev in rng.get("events") or []:
                if isinstance(ev, dict) and ev.get("fixed"):
                    lst = info.fixed.setdefault(key, [])
                    if str(ev["fixed"]) not in lst:
                        lst.append(str(ev["fixed"]))

    # severity: malware > database label > CVSS vectors > per-package label > default
    if info.malicious:
        info.severity, info.severity_source = "CRITICAL", "malware"
        return info
    label = _label(db.get("severity"))
    if label:
        info.severity, info.severity_source = label, "database"
    scored: Optional[float] = None
    band = ""
    for sev in doc.get("severity") or []:
        if not isinstance(sev, dict):
            continue
        stype, vec = str(sev.get("type", "")), str(sev.get("score", ""))
        if stype in ("CVSS_V3",) or vec.startswith("CVSS:3"):
            s = cvss3_score(vec)
            if s is not None and (scored is None or s > scored):
                scored = s
        elif stype == "CVSS_V2" or vec.startswith("AV:"):
            s = cvss2_score(vec)
            if s is not None and scored is None:
                scored = s
        elif stype == "CVSS_V4" or vec.startswith("CVSS:4"):
            band = cvss4_band(vec) or band
        else:
            try:  # some databases put a bare number there
                scored = float(vec) if scored is None else scored
            except ValueError:
                pass
    if scored is not None:
        info.score = scored
        if not info.severity:
            info.severity, info.severity_source = severity_from_score(scored), "cvss3"
    if not info.severity and band:
        info.severity, info.severity_source = band, "cvss4-estimate"
    if not info.severity:
        for a in affected:
            for src in (a.get("database_specific"), a.get("ecosystem_specific")):
                lab = _label(src.get("severity")) if isinstance(src, dict) else ""
                if lab:
                    info.severity, info.severity_source = lab, "affected"
                    break
            if info.severity:
                break
    return info


# --------------------------------------------------------------------------- client
class OsvClient:
    """Cached, batched OSV lookups.

    ``query(pkgs)`` -> ``{Pkg: [advisory ids]}`` for every package that could be checked (fresh cache,
    network, or stale cache as a last resort); the rest are in ``unchecked``.
    ``details(ids)`` -> ``{id: VulnInfo}``.
    After use: ``offline`` (the network was off or failed), ``error`` (why), ``used_stale``,
    ``truncated`` (a deadline/cancel stopped lookups early) and ``stats``.
    """

    def __init__(self, cache_path: Optional[Path] = None, ttl: float = DEFAULT_TTL, online: bool = True,
                 timeout: float = 25.0, clock: Callable[[], float] = time.time, max_detail_fetches: int = 600,
                 workers: int = 6):
        self.cache_path = Path(cache_path) if cache_path else None
        self.ttl = float(ttl)
        self.timeout = timeout
        self.clock = clock
        self.max_detail_fetches = max_detail_fetches
        self.workers = max(1, workers)
        self.offline = not online
        self.error = "network lookups disabled" if not online else ""
        self.used_stale = False
        self.truncated = False
        self.unchecked: Set[Pkg] = set()
        self.stats: Dict[str, int] = {"packages": 0, "cache_hits": 0, "network_batches": 0, "stale_used": 0,
                                      "detail_fetches": 0, "detail_cache_hits": 0}
        self._lock = threading.Lock()
        self._dirty = False
        self._cache = self._load()

    # ---- cache -----------------------------------------------------------------------------
    def _load(self) -> Dict[str, Any]:
        empty: Dict[str, Any] = {"version": CACHE_VERSION, "queries": {}, "vulns": {}}
        if not self.cache_path:
            return empty
        try:
            doc = json.loads(self.cache_path.read_text(encoding="utf-8"))
            if (isinstance(doc, dict) and doc.get("version") == CACHE_VERSION and isinstance(doc.get("queries"), dict)
                    and isinstance(doc.get("vulns"), dict)):
                return doc
        except (OSError, ValueError):
            pass
        return empty

    def save(self) -> None:
        """Persist the cache (atomic, drops entries older than the stale limit). Never raises."""
        if not self.cache_path or not self._dirty:
            return
        now = self.clock()
        for table in ("queries", "vulns"):
            self._cache[table] = {k: v for k, v in self._cache[table].items()
                                  if isinstance(v, dict) and now - float(v.get("t", 0)) < STALE_LIMIT}
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix=self.cache_path.name + ".", suffix=".tmp", dir=str(self.cache_path.parent))
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(self._cache, fh, separators=(",", ":"))
                os.replace(tmp, self.cache_path)
            except BaseException:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
            self._dirty = False
        except OSError as exc:
            log.debug("could not write OSV cache: %s", exc)

    def _fresh(self, entry: Any) -> bool:
        if not isinstance(entry, dict):
            return False
        age = self.clock() - float(entry.get("t", 0))
        return -3600 <= age < self.ttl  # tolerate small clock skew, reject timestamps far in the future

    def _usable_stale(self, entry: Any) -> bool:
        return isinstance(entry, dict) and 0 <= self.clock() - float(entry.get("t", 0)) < STALE_LIMIT

    # ---- network ---------------------------------------------------------------------------
    def _go_offline(self, exc: BaseException) -> None:
        with self._lock:
            if not self.offline:
                self.offline = True
                self.error = f"{type(exc).__name__}: {exc}"[:200]
                log.info("OSV unreachable (%s); using cached data only", self.error)

    def _http_json(self, url: str, payload: Optional[Dict[str, Any]] = None) -> Any:
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method="POST" if data is not None else "GET")
        resp = urllib.request.urlopen(req, timeout=self.timeout)
        try:
            raw = resp.read(MAX_RESPONSE + 1)
        finally:
            close = getattr(resp, "close", None)
            if close:
                close()
        if len(raw) > MAX_RESPONSE:
            raise ValueError("response too large")
        return json.loads(raw.decode("utf-8", "replace"))

    def _query_chunk(self, chunk: List[Pkg]) -> List[List[str]]:
        """One or more querybatch calls for <= MAX_BATCH packages (follows pagination tokens)."""
        queries = [{"package": {"name": p.name, "ecosystem": p.ecosystem}, "version": p.version} for p in chunk]
        out: List[List[str]] = [[] for _ in chunk]
        pending = list(range(len(chunk)))
        tokens: Dict[int, str] = {}
        for page in range(MAX_PAGES):
            batch = []
            for i in pending:
                q = dict(queries[i])
                if i in tokens:
                    q["page_token"] = tokens[i]
                batch.append(q)
            doc = self._http_json(QUERYBATCH_URL, {"queries": batch})
            results = doc.get("results") if isinstance(doc, dict) else None
            if not isinstance(results, list) or len(results) != len(batch):
                raise ValueError("unexpected querybatch response shape")
            self.stats["network_batches"] += 1
            next_pending: List[int] = []
            for idx, res in zip(pending, results):
                res = res if isinstance(res, dict) else {}
                for v in res.get("vulns") or []:
                    vid = v.get("id") if isinstance(v, dict) else None
                    if isinstance(vid, str) and _ID_OK.match(vid) and vid not in out[idx]:
                        out[idx].append(vid)
                tok = res.get("next_page_token")
                if tok:
                    tokens[idx] = str(tok)
                    next_pending.append(idx)
            pending = next_pending
            if not pending:
                break
        return out

    # ---- public API -------------------------------------------------------------------------
    def query(self, pkgs: Iterable[Pkg], deadline: Optional[float] = None,
              should_stop: Optional[Callable[[], bool]] = None) -> Dict[Pkg, List[str]]:
        uniq = list(dict.fromkeys(p for p in pkgs if p.name and p.version))
        self.stats["packages"] += len(uniq)
        result: Dict[Pkg, List[str]] = {}
        todo: List[Pkg] = []
        for p in uniq:
            entry = self._cache["queries"].get(p.key)
            if self._fresh(entry):
                result[p] = list(entry.get("ids", []))
                self.stats["cache_hits"] += 1
            else:
                todo.append(p)
        now = self.clock()
        for i in range(0, len(todo), MAX_BATCH):
            if self.offline:
                break
            if (should_stop and should_stop()) or (deadline is not None and time.monotonic() > deadline):
                self.truncated = True
                break
            chunk = todo[i:i + MAX_BATCH]
            try:
                ids_per_pkg = self._query_chunk(chunk)
            except Exception as exc:  # network down, HTTP error, bad JSON ...
                self._go_offline(exc)
                break
            for p, ids in zip(chunk, ids_per_pkg):
                result[p] = ids
                self._cache["queries"][p.key] = {"t": now, "ids": ids}
            self._dirty = True
        for p in todo:  # stale fallback for whatever the network did not answer
            if p in result:
                continue
            entry = self._cache["queries"].get(p.key)
            if self._usable_stale(entry):
                result[p] = list(entry.get("ids", []))
                self.stats["stale_used"] += 1
                self.used_stale = True
            else:
                self.unchecked.add(p)
        self.save()
        return result

    def details(self, ids: Iterable[str], deadline: Optional[float] = None,
                should_stop: Optional[Callable[[], bool]] = None) -> Dict[str, VulnInfo]:
        out: Dict[str, VulnInfo] = {}
        todo: List[str] = []
        for vid in dict.fromkeys(i for i in ids if isinstance(i, str) and _ID_OK.match(i)):
            entry = self._cache["vulns"].get(vid)
            if self._fresh(entry) and isinstance(entry.get("v"), dict):
                out[vid] = VulnInfo.from_dict(entry["v"])
                self.stats["detail_cache_hits"] += 1
            else:
                todo.append(vid)
        # malicious-package advisories first: they matter most if the budget runs out
        todo.sort(key=lambda v: (not v.startswith("MAL-"), v))
        todo_fetch = todo[:self.max_detail_fetches]
        now = self.clock()

        def fetch(vid: str) -> Optional[VulnInfo]:
            if self.offline or (should_stop and should_stop()) or (deadline is not None and time.monotonic() > deadline):
                return None
            try:
                doc = self._http_json(VULN_URL + urllib.parse.quote(vid, safe=""))
            except urllib.error.HTTPError as exc:
                if exc.code in (404, 410):  # unknown / gone: not an outage
                    return None
                self._go_offline(exc)
                return None
            except Exception as exc:
                self._go_offline(exc)
                return None
            if not isinstance(doc, dict) or not doc.get("id"):
                return None
            self.stats["detail_fetches"] += 1
            return parse_vuln(doc)

        if todo_fetch and not self.offline:
            if len(todo_fetch) > 2 and self.workers > 1:
                with ThreadPoolExecutor(max_workers=self.workers) as pool:
                    fetched = list(pool.map(fetch, todo_fetch))
            else:
                fetched = [fetch(v) for v in todo_fetch]
            for vid, info in zip(todo_fetch, fetched):
                if info is not None:
                    out[vid] = info
                    self._cache["vulns"][vid] = {"t": now, "v": info.to_dict()}
                    self._dirty = True
        for vid in todo:
            if vid in out:
                continue
            entry = self._cache["vulns"].get(vid)
            if self._usable_stale(entry) and isinstance(entry.get("v"), dict):
                out[vid] = VulnInfo.from_dict(entry["v"])
                self.used_stale = True
            else:  # placeholder: keep the id, infer what the id itself tells us
                mal = vid.startswith("MAL-")
                out[vid] = VulnInfo(id=vid, malicious=mal, severity="CRITICAL" if mal else "",
                                    severity_source="malware" if mal else "", complete=False)
        self.save()
        return out
