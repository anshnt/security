"""Scan history: a small SQLite store that makes Aegis useful over time.

Every finished scan is recorded in ``<data>/history.sqlite`` (profile, times, score, grade,
severity counts, host, scanners and one row per finding with its fingerprint, rule id,
severity, category, title and location). On top of that this module answers the questions
people actually ask:

* what changed since the last scan?   -> :func:`diff`, :func:`latest_comparable`
* is my score getting better or worse? -> :func:`trend`, :func:`recent_scores`
* what did we scan last Tuesday?       -> :func:`list_scans`, :func:`get_scan`

Design notes
* Findings are stored *slim* (no evidence, descriptions or remediation): the history is a
  change log, not a second copy of the scan reports, and evidence can contain sensitive
  strings. ``get_scan`` therefore returns findings with empty description/evidence.
* The schema is versioned through a ``schema_version`` table and a list of numbered
  migrations (:data:`_MIGRATIONS`); adding a column later is one new entry. A database written
  by a *newer* Aegis is used as-is (additive migrations keep older code working).
* Retention: only the newest :data:`MAX_SCANS` scans are kept.
* Nothing here may break a scan: :func:`record` and :func:`record_and_compare` never raise.
* Findings are matched across scans by fingerprint, after stripping volatile ``(pid 1234)``
  suffixes, so a process finding does not look "new" after every reboot.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import json
import logging
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple, Union

from aegis.core.models import CheckResult, Finding, ScanResult, Severity
from aegis.core.scoring import security_score

log = logging.getLogger("aegis.history")

DB_NAME = "history.sqlite"
MAX_SCANS = 500
CANCELLED_MARK = "scan cancelled by user"  # ScanEngine.scan appends this to result.errors
SPARKLINE_POINTS = 20
MAX_LISTED_CHANGES = 200  # new/resolved entries copied into result.stats["history"]

# --------------------------------------------------------------------------- schema / migrations

_MIGRATIONS: Dict[int, Tuple[str, ...]] = {
    1: (
        """CREATE TABLE scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            profile TEXT NOT NULL,
            started TEXT NOT NULL,
            finished TEXT NOT NULL DEFAULT '',
            recorded_at TEXT NOT NULL,
            host TEXT NOT NULL DEFAULT '',
            score INTEGER NOT NULL,
            grade TEXT NOT NULL,
            critical INTEGER NOT NULL DEFAULT 0,
            high INTEGER NOT NULL DEFAULT 0,
            medium INTEGER NOT NULL DEFAULT 0,
            low INTEGER NOT NULL DEFAULT 0,
            info INTEGER NOT NULL DEFAULT 0,
            finding_count INTEGER NOT NULL DEFAULT 0,
            scanners TEXT NOT NULL DEFAULT '[]',
            host_json TEXT NOT NULL DEFAULT '{}',
            stats_json TEXT NOT NULL DEFAULT '{}',
            errors_json TEXT NOT NULL DEFAULT '[]',
            checks_json TEXT NOT NULL DEFAULT '[]'
        )""",
        "CREATE INDEX idx_scans_profile ON scans(profile, id)",
        """CREATE TABLE findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            fingerprint TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            severity INTEGER NOT NULL,
            category TEXT NOT NULL DEFAULT '',
            title TEXT NOT NULL DEFAULT '',
            location TEXT NOT NULL DEFAULT '',
            scanner TEXT NOT NULL DEFAULT '',
            mitre TEXT NOT NULL DEFAULT ''
        )""",
        "CREATE INDEX idx_findings_scan ON findings(scan_id)",
        "CREATE INDEX idx_findings_fp ON findings(fingerprint)",
    ),
}


def target_version() -> int:
    """Schema version this code writes."""
    return max(_MIGRATIONS)


def history_path(config: Any) -> Path:
    return Path(config.home) / DB_NAME


def _now_iso() -> str:
    return dt.datetime.now().isoformat(timespec="seconds")


def _current_version(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
    return int(row[0] or 0)


def _migrate(conn: sqlite3.Connection) -> int:
    """Create / upgrade the schema; returns the resulting version."""
    conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL, applied TEXT NOT NULL)")
    current = _current_version(conn)
    if current > target_version():
        log.warning("history database is schema v%d but this Aegis writes v%d; using it as-is", current, target_version())
        return current
    for version in sorted(_MIGRATIONS):
        if version <= current:
            continue
        conn.execute("BEGIN IMMEDIATE")
        try:
            # another process may have migrated while we waited for the write lock
            if _current_version(conn) >= version:
                conn.execute("COMMIT")
                continue
            for stmt in _MIGRATIONS[version]:
                conn.execute(stmt)
            conn.execute("INSERT INTO schema_version(version, applied) VALUES (?, ?)", (version, _now_iso()))
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        current = version
    return current


def _looks_corrupt(exc: Exception) -> bool:
    msg = str(exc).lower()
    return any(s in msg for s in ("not a database", "malformed", "corrupt", "encrypted"))


def _open(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), timeout=15, isolation_level=None)  # autocommit; we manage BEGIN/COMMIT
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        _migrate(conn)
        return conn
    except Exception:
        conn.close()
        raise


@contextlib.contextmanager
def _connect(config: Any) -> Iterator[sqlite3.Connection]:
    path = history_path(config)
    try:
        conn = _open(path)
    except sqlite3.DatabaseError as exc:
        if not _looks_corrupt(exc) or not path.exists():
            raise
        # A damaged history must not disable history for good: move it aside and start fresh.
        aside = path.with_name(f"{path.name}.corrupt-{dt.datetime.now():%Y%m%d%H%M%S}")
        log.warning("history database is damaged (%s); moved to %s", exc, aside.name)
        path.replace(aside)
        conn = _open(path)
    try:
        yield conn
    finally:
        conn.close()


def schema_version(config: Any) -> int:
    """Schema version recorded in the database on disk (creates/migrates it if needed)."""
    with _connect(config) as conn:
        return _current_version(conn)


def scan_count(config: Any) -> int:
    with _connect(config) as conn:
        return int(conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0])


# --------------------------------------------------------------------------- summaries

@dataclass
class ScanSummary:
    """One row of the history list (no findings)."""

    id: int
    profile: str
    started: str
    finished: str
    host: str
    score: int
    grade: str
    counts: Dict[str, int] = field(default_factory=dict)
    finding_count: int = 0
    scanners: List[str] = field(default_factory=list)
    new_findings: Optional[int] = None  # vs the previous comparable scan (None: no baseline)
    resolved_findings: Optional[int] = None
    score_change: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "profile": self.profile, "started": self.started, "finished": self.finished,
            "host": self.host, "score": self.score, "grade": self.grade, "counts": dict(self.counts),
            "finding_count": self.finding_count, "scanners": list(self.scanners),
            "new_findings": self.new_findings, "resolved_findings": self.resolved_findings,
            "score_change": self.score_change,
        }


def _json_load(text: Any, default: Any) -> Any:
    try:
        value = json.loads(text) if text else default
    except (TypeError, ValueError):
        return default
    return value if isinstance(value, type(default)) else default


def _summary(row: sqlite3.Row) -> ScanSummary:
    stats = _json_load(row["stats_json"], {})
    nf, rf, sc = stats.get("new_findings"), stats.get("resolved_findings"), stats.get("score_change")
    return ScanSummary(
        id=int(row["id"]), profile=row["profile"], started=row["started"], finished=row["finished"],
        host=row["host"], score=int(row["score"]), grade=row["grade"],
        counts={s: int(row[s]) for s in ("critical", "high", "medium", "low", "info")},
        finding_count=int(row["finding_count"]), scanners=_json_load(row["scanners"], []),
        new_findings=nf if isinstance(nf, int) else None, resolved_findings=rf if isinstance(rf, int) else None,
        score_change=sc if isinstance(sc, int) else None)


# --------------------------------------------------------------------------- recording

def _hostname(result: ScanResult) -> str:
    return str((result.host or {}).get("hostname", "") or "")


def record(result: ScanResult, config: Any, keep: Optional[int] = None) -> Optional[int]:
    """Store ``result``; returns the new scan id, or None if it could not be stored.

    Never raises. Prunes the history to the newest ``keep`` scans (default :data:`MAX_SCANS`)."""
    try:
        keep = MAX_SCANS if keep is None else keep
        score, grade = security_score(result)
        counts = result.counts()
        stats = {k: v for k, v in (result.stats or {}).items() if k != "history"}
        stats_json = json.dumps(stats, default=str)
        if len(stats_json) > 64 * 1024:  # a runaway scanner stat must not bloat the database
            stats_json = "{}"
        checks_json = json.dumps([[c.check_id, c.status, c.category, c.scanner, c.title[:160]] for c in result.checks])
        rows = [(f.fingerprint, f.rule_id, int(f.severity), f.category, f.title[:300], f.location[:1000], f.scanner,
                 " ".join(f.mitre)) for f in result.findings]
        with _connect(config) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                cur = conn.execute(
                    "INSERT INTO scans(profile, started, finished, recorded_at, host, score, grade, critical, high, "
                    "medium, low, info, finding_count, scanners, host_json, stats_json, errors_json, checks_json) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (result.profile, result.started or _now_iso(), result.finished or "", _now_iso(), _hostname(result),
                     score, grade, counts["critical"], counts["high"], counts["medium"], counts["low"], counts["info"],
                     len(result.findings), json.dumps(list(result.scanners)), json.dumps(result.host or {}, default=str),
                     stats_json, json.dumps(list(result.errors), default=str), checks_json))
                scan_id = int(cur.lastrowid)
                conn.executemany(
                    "INSERT INTO findings(scan_id, fingerprint, rule_id, severity, category, title, location, scanner, "
                    "mitre) VALUES (?,?,?,?,?,?,?,?,?)", [(scan_id, *r) for r in rows])
                _prune(conn, keep)
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
        return scan_id
    except Exception as exc:
        log.warning("could not record scan history: %s", exc)
        return None


def _prune(conn: sqlite3.Connection, keep: int) -> None:
    keep = max(1, int(keep))
    cutoff = conn.execute("SELECT id FROM scans ORDER BY id DESC LIMIT 1 OFFSET ?", (keep,)).fetchone()
    if cutoff is not None:
        conn.execute("DELETE FROM scans WHERE id <= ?", (int(cutoff[0]),))
        conn.execute("DELETE FROM findings WHERE scan_id NOT IN (SELECT id FROM scans)")  # if FKs are not enforced


# --------------------------------------------------------------------------- reading

def list_scans(config: Any, limit: int = 50, profile: Optional[str] = None, host: Optional[str] = None) -> List[ScanSummary]:
    """Newest-first scan summaries."""
    where, args = _filters(profile=profile, host=host)
    with _connect(config) as conn:
        rows = conn.execute(f"SELECT * FROM scans{where} ORDER BY id DESC LIMIT ?", [*args, max(1, int(limit))]).fetchall()
        return [_summary(r) for r in rows]


def get_summary(config: Any, scan_id: int) -> Optional[ScanSummary]:
    with _connect(config) as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (int(scan_id),)).fetchone()
        return _summary(row) if row is not None else None


def _filters(profile: Optional[str] = None, host: Optional[str] = None, before: Union[None, int, str, ScanResult] = None,
             since: Optional[str] = None) -> Tuple[str, List[Any]]:
    clauses: List[str] = []
    args: List[Any] = []
    if profile:
        clauses.append("profile = ?")
        args.append(profile)
    if host:
        clauses.append("host = ?")
        args.append(host)
    if before is not None:
        if isinstance(before, int):
            clauses.append("id < ?")
            args.append(before)
        else:
            clauses.append("started < ?")
            args.append(before.started if isinstance(before, ScanResult) else str(before))
    if since:
        clauses.append("started >= ?")
        args.append(since)
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", args


def _load_result(conn: sqlite3.Connection, row: sqlite3.Row) -> ScanResult:
    findings = [
        Finding(rule_id=r["rule_id"], title=r["title"], severity=Severity(int(r["severity"])), category=r["category"],
                location=r["location"], scanner=r["scanner"], mitre=r["mitre"].split() if r["mitre"] else [])
        for r in conn.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY id", (row["id"],)).fetchall()]
    checks: List[CheckResult] = []
    for c in _json_load(row["checks_json"], []):
        try:
            checks.append(CheckResult(check_id=c[0], title=c[4], status=c[1], category=c[2], scanner=c[3]))
        except (IndexError, TypeError):
            continue
    stats = _json_load(row["stats_json"], {})
    stats["history_id"] = int(row["id"])
    return ScanResult(profile=row["profile"], started=row["started"], finished=row["finished"],
                      host=_json_load(row["host_json"], {}), scanners=_json_load(row["scanners"], []),
                      findings=findings, checks=checks, stats=stats, errors=_json_load(row["errors_json"], []))


def get_scan(config: Any, scan_id: int) -> Optional[ScanResult]:
    """Rebuild a recorded scan as a :class:`ScanResult` (findings carry no description/evidence);
    None if there is no such scan."""
    with _connect(config) as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (int(scan_id),)).fetchone()
        return _load_result(conn, row) if row is not None else None


def latest_comparable(config: Any, profile: str, before: Union[None, int, str, ScanResult] = None,
                      host: Optional[str] = None, scanners: Optional[Sequence[str]] = None) -> Optional[ScanResult]:
    """The most recent earlier scan of the same ``profile`` (optionally the same ``host``), or None.

    ``before`` bounds the search: a scan id (``id < before``), an ISO timestamp / ScanResult (``started < ...``)
    or None for "the latest scan". ``scanners``, when given, must match the earlier scan's scanner set exactly
    (used for the free-form "custom" profile, whose scanner set is chosen per run)."""
    where, args = _filters(profile=profile, host=host, before=before)
    with _connect(config) as conn:
        want = sorted(scanners) if scanners is not None else None
        for row in conn.execute(f"SELECT * FROM scans{where} ORDER BY id DESC LIMIT 50", args).fetchall():
            if want is not None and sorted(_json_load(row["scanners"], [])) != want:
                continue
            return _load_result(conn, row)
    return None


def recent_scores(config: Any, profile: Optional[str] = None, limit: int = SPARKLINE_POINTS,
                  host: Optional[str] = None) -> List[Tuple[str, int]]:
    """Scores of the last ``limit`` scans, oldest first: ``[(started, score), ...]``."""
    where, args = _filters(profile=profile, host=host)
    with _connect(config) as conn:
        rows = conn.execute(f"SELECT started, score FROM scans{where} ORDER BY id DESC LIMIT ?",
                            [*args, max(1, int(limit))]).fetchall()
    return [(r["started"], int(r["score"])) for r in reversed(rows)]


def trend(config: Any, profile: Optional[str] = None, days: int = 90, host: Optional[str] = None,
          now: Optional[dt.datetime] = None) -> List[Tuple[str, int]]:
    """``[(date, score), ...]`` oldest first for the scans of the last ``days`` days (one point per scan;
    ``date`` is ``YYYY-MM-DD``). ``profile=None`` mixes every profile."""
    now = now or dt.datetime.now()
    since = (now - dt.timedelta(days=max(0, int(days)))).isoformat(timespec="seconds")
    where, args = _filters(profile=profile, host=host, since=since)
    with _connect(config) as conn:
        rows = conn.execute(f"SELECT started, score FROM scans{where} ORDER BY id", args).fetchall()
    return [(str(r["started"])[:10], int(r["score"])) for r in rows]


# --------------------------------------------------------------------------- diff

_PID_SUFFIX = re.compile(r"\s*[(\[]\s*pids?\s*[:=]?\s*\d+(?:\s*,\s*\d+)*\s*[)\]]", re.IGNORECASE)


def match_key(f: Finding) -> str:
    """Identity of a finding across scans: rule + location without volatile ``(pid N)`` suffixes."""
    return f"{f.rule_id}|{_PID_SUFFIX.sub('', f.location)}".lower()


def _sorted(findings: Sequence[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: (-int(f.severity), f.category, f.title, f.location))


def diff(old: ScanResult, new: ScanResult) -> Dict[str, Any]:
    """What changed between two scans.

    Returns ``{"new": [...], "resolved": [...], "persisting": [...], "escalated": [...], "score_change": int}``.
    ``new`` and ``persisting`` hold the findings of ``new``; ``resolved`` holds findings of ``old`` that are gone;
    ``escalated`` is the subset of ``persisting`` whose severity rose. ``score_change`` is new minus old score."""
    old_by = {match_key(f): f for f in old.findings}
    new_by = {match_key(f): f for f in new.findings}
    new_f = [f for k, f in new_by.items() if k not in old_by]
    resolved = [f for k, f in old_by.items() if k not in new_by]
    persisting = [f for k, f in new_by.items() if k in old_by]
    escalated = [f for f in persisting if f.severity > old_by[match_key(f)].severity]
    return {
        "new": _sorted(new_f), "resolved": _sorted(resolved), "persisting": _sorted(persisting),
        "escalated": _sorted(escalated), "score_change": security_score(new)[0] - security_score(old)[0],
    }


def compact(f: Finding) -> Dict[str, str]:
    """Small JSON-safe description of a finding (no evidence) for stats / reports / alerts."""
    return {"fingerprint": f.fingerprint, "rule_id": f.rule_id, "severity": f.severity.name.lower(),
            "category": f.category, "title": f.title[:200], "location": f.location[:300]}


def compare_latest(config: Any, profile: Optional[str] = None, host: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Diff the newest scan against the one before it of the same profile (what ``aegis history --diff`` shows).

    Returns ``{"old": ScanSummary, "new": ScanSummary, "diff": {...}}`` or None if there is nothing to compare."""
    with _connect(config) as conn:
        where, args = _filters(profile=profile, host=host)
        row = conn.execute(f"SELECT * FROM scans{where} ORDER BY id DESC LIMIT 1", args).fetchone()
        if row is None:
            return None
        newest = _load_result(conn, row)
        new_summary = _summary(row)
    old = latest_comparable(config, newest.profile, before=int(row["id"]), host=_hostname(newest) or None,
                            scanners=newest.scanners if newest.profile == "custom" else None)
    if old is None:
        return None
    old_id = old.stats.get("history_id")
    return {"old": get_summary(config, old_id) if old_id is not None else None, "new": new_summary,
            "diff": diff(old, newest)}


def render_diff_text(d: Dict[str, Any], limit: int = 25) -> str:
    """Plain-text rendering of a :func:`diff` result."""
    lines = [f"New: {len(d['new'])}   Resolved: {len(d['resolved'])}   Persisting: {len(d['persisting'])}   "
             f"Score change: {d['score_change']:+d}"]
    for key, title in (("new", "New findings"), ("resolved", "Resolved findings")):
        items = d[key]
        if not items:
            continue
        lines.append("")
        lines.append(f"{title} ({len(items)})")
        for f in items[:limit]:
            lines.append(f"  [{f.severity.name:<8}] {f.title}" + (f"  -  {f.location}" if f.location else ""))
        if len(items) > limit:
            lines.append(f"  ...and {len(items) - limit} more")
    return "\n".join(lines)


# --------------------------------------------------------------------------- engine hook / dashboard

def record_and_compare(result: ScanResult, config: Any) -> Optional[Dict[str, Any]]:
    """Called by ``ScanEngine`` after every scan.

    Finds the previous comparable scan, stores ``new_findings`` / ``resolved_findings`` / ``score_change`` and a
    compact ``history`` block (previous scan, new + resolved findings, score trend) in ``result.stats``, then records
    the scan. Returns the :func:`diff` (None when there is no baseline, or the scan was cancelled and so not
    recorded). Never raises."""
    try:
        if CANCELLED_MARK in (result.errors or []):
            return None  # a partial scan would report bogus "resolved" findings and skew the trend
        host = _hostname(result) or None
        try:
            previous = latest_comparable(config, result.profile, host=host,
                                         scanners=result.scanners if result.profile == "custom" else None)
        except Exception as exc:
            log.debug("previous scan lookup failed: %s", exc)
            previous = None
        d: Optional[Dict[str, Any]] = None
        if previous is not None:
            d = diff(previous, result)
            result.stats["new_findings"] = len(d["new"])
            result.stats["resolved_findings"] = len(d["resolved"])
            result.stats["score_change"] = d["score_change"]
        scan_id = record(result, config)
        block: Dict[str, Any] = {"scan_id": scan_id}
        if previous is not None and d is not None:
            prev_score, prev_grade = security_score(previous)
            block["previous"] = {"id": previous.stats.get("history_id"), "started": previous.started,
                                 "profile": previous.profile, "score": prev_score, "grade": prev_grade}
            block["new"] = [compact(f) for f in d["new"][:MAX_LISTED_CHANGES]]
            block["resolved"] = [compact(f) for f in d["resolved"][:MAX_LISTED_CHANGES]]
            block["escalated"] = len(d["escalated"])
            block["score_change"] = d["score_change"]
        if scan_id is not None:
            try:
                block["trend"] = [[s, v] for s, v in recent_scores(config, result.profile, SPARKLINE_POINTS, host=host)]
            except Exception as exc:
                log.debug("trend lookup failed: %s", exc)
        result.stats["history"] = block
        return d
    except Exception as exc:
        log.warning("scan history failed: %s", exc)
        return None


def dashboard_data(config: Any, limit: int = SPARKLINE_POINTS) -> Dict[str, Any]:
    """Everything the GUI dashboard needs: ``{"profile", "points", "latest", "new", "resolved", "score_change"}``.

    ``points`` are ``[(started, score), ...]`` (oldest first) for the last ``limit`` scans of the profile of the
    most recent scan; ``new`` / ``resolved`` / ``score_change`` compare that scan with the previous comparable one
    (None when there was no baseline)."""
    out: Dict[str, Any] = {"profile": "", "points": [], "latest": None, "new": None, "resolved": None, "score_change": None}
    latest = list_scans(config, limit=1)
    if not latest:
        return out
    s = latest[0]
    out.update(profile=s.profile, latest=s, new=s.new_findings, resolved=s.resolved_findings,
               score_change=s.score_change, points=recent_scores(config, s.profile, limit, host=s.host or None))
    return out
