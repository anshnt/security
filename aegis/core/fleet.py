"""Fleet overview: one page (or JSON / CSV) for the scan results of many computers.

Scheduled scans on several PCs can write their JSON results to a shared folder
(``aegis scan full --report \\\\server\\share\\%COMPUTERNAME%.json``). This module reads such a folder and answers
"which machines need attention, and what is wrong across the fleet?":

* :func:`load_results`  -> find the JSON files, keep only real Aegis scan results   (the only part that does I/O)
* :func:`build_fleet`   -> newest result per host, trend, new findings, stale hosts, issues shared by many hosts
* :func:`render_html`, :func:`render_json`, :func:`render_csv`, :func:`render_text`, :func:`write_fleet`

Design notes
* Result files are untrusted data. A file must carry the generator marker and parse as a :class:`ScanResult`;
  anything else is skipped and counted. Nothing from a file is ever executed, and the score is recomputed from the
  findings instead of trusting the stored number.
* Loaded results are slimmed down (no evidence or descriptions), so a few thousand files stay small in memory.
* Results of one host are matched by host name (case-insensitive). "Previous" means the most recent earlier result
  of the same profile (and, for ``custom``, the same scanners), like :func:`aegis.core.history.latest_comparable`,
  so a quick scan is never compared with a full one. Findings are matched with :func:`history.match_key`.
* The HTML and JSON outputs are recognised by :func:`aegis.core.report.is_aegis_report` (:func:`is_fleet_html`,
  :func:`is_fleet_json`), so a saved fleet report that quotes malicious strings is not flagged by the file scanner.
  Both validators are strict: the HTML must be the fixed page frame around allow-listed markup, the JSON must have
  exactly the keys written here.
"""

from __future__ import annotations

import csv
import datetime as _dt
import glob
import html
import io
import json
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

from aegis.core.history import SPARKLINE_POINTS, match_key
from aegis.core.models import GENERATOR, CheckStatus, Finding, Remediation, ScanResult, Severity
from aegis.core.report import _SEV_COLORS, _short, _sparkline, action_plan
from aegis.core.scoring import security_score

MAX_FILE_BYTES = 64 * 1024 * 1024  # larger files are skipped unread
MAX_FILES = 5000  # files examined per run
MAX_SKIPPED_LISTED = 200  # skipped files named in the JSON output (the count is always complete)
MAX_HOST_FINDINGS = 25  # findings listed per host
MAX_COMMON_ISSUES = 50
SCHEMA_VERSION = 1
FLEET_FORMATS = ("html", "json", "csv")
_SEVERITIES = tuple(s.name.lower() for s in sorted(Severity, reverse=True))  # critical ... info
_GLOB_CHARS = re.compile(r"[*?\[]")


# --------------------------------------------------------------------------- loading

@dataclass
class LoadReport:
    """What :func:`load_results` found: the valid results and why the other files were left out."""

    results: List[ScanResult] = field(default_factory=list)
    skipped: List[Tuple[str, str]] = field(default_factory=list)  # (path, reason)
    missing: List[str] = field(default_factory=list)  # PATH arguments that do not exist
    limit_reached: bool = False  # more than MAX_FILES candidates: the rest were not read


def _clean(text: Any, limit: int = 200) -> str:
    """Printable one-line text: control characters (terminal escapes, newlines, bidi overrides) become spaces."""
    return "".join(ch if ch.isprintable() else " " for ch in str(text)).strip()[:limit]


def _naive(t: _dt.datetime) -> _dt.datetime:
    """``t`` without a time zone: aware times are converted to UTC, naive ones (what Aegis writes) are kept."""
    return t.astimezone(_dt.timezone.utc).replace(tzinfo=None) if t.tzinfo is not None else t


def parse_time(text: str) -> Optional[_dt.datetime]:
    """ISO timestamp as a naive datetime (see :func:`_naive`); None if it cannot be read."""
    s = str(text).strip()
    if s[-1:] in ("Z", "z"):
        s = s[:-1] + "+00:00"
    try:
        return _naive(_dt.datetime.fromisoformat(s))
    except (ValueError, OverflowError):
        return None


def _problem(r: ScanResult) -> str:
    """Why ``r`` cannot be used (a wrong type anywhere that later code relies on), or ''."""
    if not isinstance(r.profile, str) or not isinstance(r.started, str) or not isinstance(r.host, dict):
        return "fields are missing or have the wrong type"
    if not isinstance(r.scanners, list) or not all(isinstance(s, str) for s in r.scanners):
        return "fields are missing or have the wrong type"
    if parse_time(r.started) is None:
        return "no valid scan time"
    for f in r.findings:
        if not all(isinstance(v, str) for v in (f.rule_id, f.title, f.category, f.location, f.recommendation)):
            return "fields are missing or have the wrong type"
    return ""


def _slim(r: ScanResult) -> ScanResult:
    """The parts of ``r`` the overview uses. Evidence and descriptions can hold sensitive strings and a lot of data."""
    host = {"hostname": _clean(r.host.get("hostname") or "", 253), "os": _clean(r.host.get("os") or "", 40),
            "platform": _clean(r.host.get("platform") or "", 200), "admin": bool(r.host.get("admin"))}
    findings = [Finding(rule_id=f.rule_id, title=_clean(f.title, 300), severity=f.severity, category=f.category,
                        location=f.location, recommendation=_clean(f.recommendation, 600),
                        remediation=Remediation(str(f.remediation.action)[:60]) if f.remediation else None, timestamp="")
                for f in r.findings]
    return ScanResult(profile=_clean(r.profile, 40) or "custom", started=r.started.strip(), host=host,
                      scanners=list(r.scanners), findings=findings,
                      checks=[c for c in r.checks if c.status == CheckStatus.FAIL])  # all the score looks at


def parse_result(data: bytes) -> ScanResult:
    """Validate ``data`` as the JSON of an Aegis scan result and return it slimmed down.

    Raises :class:`ValueError` (the message is a short reason that never quotes the file) for anything else."""
    try:
        text = data.decode("utf-16") if data[:2] in (b"\xff\xfe", b"\xfe\xff") else data.decode("utf-8-sig")
        d = json.loads(text)
    except (ValueError, RecursionError, MemoryError):
        raise ValueError("not valid JSON") from None
    if not isinstance(d, dict) or d.get("generator") != GENERATOR or not isinstance(d.get("findings"), list) \
            or "score" not in d or "scanners" not in d:  # the markers is_aegis_report checks
        raise ValueError("not an Aegis scan result")
    try:
        r = ScanResult.from_dict(d)
    except Exception:
        raise ValueError("fields are missing or have the wrong type") from None
    reason = _problem(r)
    if reason:
        raise ValueError(reason)
    return _slim(r)


def _read_file(path: str) -> bytes:
    """The file's bytes; ValueError with a reason if it is not a readable regular file of acceptable size."""
    try:
        st = os.stat(path)
        if not stat.S_ISREG(st.st_mode):  # a named pipe or device would block
            raise ValueError("not a regular file")
        if st.st_size > MAX_FILE_BYTES:
            raise ValueError(f"larger than {MAX_FILE_BYTES // (1024 * 1024)} MB")
        with open(path, "rb") as fh:
            data = fh.read(MAX_FILE_BYTES + 1)
    except OSError:
        raise ValueError("cannot be read") from None
    if len(data) > MAX_FILE_BYTES:
        raise ValueError(f"larger than {MAX_FILE_BYTES // (1024 * 1024)} MB")
    return data


def _json_files(folder: str, recursive: bool) -> Iterator[str]:
    """``*.json`` files of ``folder`` in a stable order (sub-folders only when ``recursive``; links to folders are not followed)."""
    stack = [folder]
    while stack:
        try:
            with os.scandir(stack.pop()) as it:
                entries = sorted(it, key=lambda e: e.name.lower())
        except OSError:
            continue
        subdirs: List[str] = []
        for e in entries:
            try:
                if e.is_dir(follow_symlinks=False):
                    subdirs.append(e.path)
                elif e.name.lower().endswith(".json"):
                    yield e.path
            except OSError:
                continue
        if recursive:
            stack.extend(reversed(subdirs))


def discover_files(paths: Sequence[str], recursive: bool = False, limit: int = MAX_FILES) -> Tuple[List[str], List[str], bool]:
    """Files to examine for the given PATH arguments: ``(files, missing, limit_reached)``.

    A file argument is always examined; a folder contributes its ``*.json`` files. An argument that does not exist
    but has wildcards (``\\\\server\\share\\*.json``, which cmd.exe does not expand) is globbed. Each file is listed once."""
    files: List[str] = []
    missing: List[str] = []
    seen = set()
    for raw in paths:
        raw = str(raw)
        targets = [raw]
        if not os.path.exists(raw) and _GLOB_CHARS.search(raw):
            targets = sorted(glob.glob(raw)) or [raw]
        for target in targets:
            if os.path.isdir(target):
                found: Iterator[str] = _json_files(target, recursive)
            elif os.path.exists(target):
                found = iter([target])
            else:
                missing.append(raw)
                continue
            for path in found:
                key = os.path.normcase(os.path.abspath(path))
                if key in seen:
                    continue
                if len(files) >= limit:
                    return files, missing, True
                seen.add(key)
                files.append(path)
    return files, missing, False


def load_results(paths: Sequence[str], recursive: bool = False, limit: int = MAX_FILES) -> LoadReport:
    """Read every candidate file under ``paths`` (see :func:`discover_files`); never raises for a bad file.

    Each valid result carries ``stats["source_file"]``."""
    files, missing, reached = discover_files(paths, recursive, limit)
    report = LoadReport(missing=missing, limit_reached=reached)
    for path in files:
        try:
            r = parse_result(_read_file(path))
        except ValueError as exc:
            report.skipped.append((path, str(exc)))
            continue
        r.stats["source_file"] = path
        report.results.append(r)
    return report


# --------------------------------------------------------------------------- aggregation

@dataclass
class HostSummary:
    """The newest result of one host, with what changed since its previous comparable result."""

    hostname: str
    os: str
    platform: str
    admin: bool
    last_scan: str  # ISO time of the newest result
    profile: str
    score: int
    grade: str
    counts: Dict[str, int]  # critical ... info
    new_findings: Optional[int]  # at/above the minimum severity, vs the previous comparable result (None: no baseline)
    score_change: Optional[int]
    previous_scan: Optional[str]
    stale: bool
    age_days: int
    scans: int  # results found for this host (any profile)
    trend: List[Tuple[str, int]]  # (date, score) of the comparable results, oldest first
    findings_total: int  # findings at/above the minimum severity
    findings: List[Dict[str, Any]]  # the worst MAX_HOST_FINDINGS of them
    actions: List[Dict[str, Any]]  # "What to do first": the top items of report.action_plan
    source: str

    def worst(self) -> str:
        """Highest severity with findings (info is not a concern), or 'clean'."""
        return next((s for s in _SEVERITIES[:-1] if self.counts.get(s)), "clean")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hostname": self.hostname, "os": self.os, "platform": self.platform, "admin": self.admin,
            "last_scan": self.last_scan, "profile": self.profile, "score": self.score, "grade": self.grade,
            "counts": dict(self.counts), "new_findings": self.new_findings, "score_change": self.score_change,
            "previous_scan": self.previous_scan, "stale": self.stale, "age_days": self.age_days, "scans": self.scans,
            "trend": [{"date": d, "score": s} for d, s in self.trend], "findings_total": self.findings_total,
            "findings": [dict(f) for f in self.findings], "actions": [dict(a) for a in self.actions],
            "source": self.source,
        }


@dataclass
class CommonIssue:
    """One rule that fired on at least one host, across the fleet."""

    rule_id: str
    title: str  # of the worst instance
    severity: str
    hosts: int
    host_names: List[str]
    findings: int  # instances over all hosts
    variants: int  # other distinct titles under this rule
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        return {"rule_id": self.rule_id, "title": self.title, "severity": self.severity, "hosts": self.hosts,
                "host_names": list(self.host_names), "findings": self.findings, "variants": self.variants,
                "recommendation": self.recommendation}


@dataclass
class Fleet:
    generated: str
    since_days: Optional[int]
    min_severity: Severity
    hosts: List[HostSummary]  # worst first
    common_issues: List[CommonIssue]
    totals: Dict[str, Any]
    skipped: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "generator": GENERATOR, "report": "fleet", "schema": SCHEMA_VERSION, "generated": self.generated,
            "since_days": self.since_days, "min_severity": self.min_severity.name.lower(), "totals": dict(self.totals),
            "hosts": [h.to_dict() for h in self.hosts], "common_issues": [c.to_dict() for c in self.common_issues],
            "skipped": dict(self.skipped),
        }


def _hostname(r: ScanResult) -> str:
    name = _clean((r.host or {}).get("hostname") or "", 253)
    if name:
        return name
    src = (r.stats or {}).get("source_file")  # no host name in the result: the file is usually named after the PC
    return _clean(Path(str(src)).stem, 253) or "unknown" if src else "unknown"


def _comparable(a: ScanResult, b: ScanResult) -> bool:
    return a.profile == b.profile and (a.profile != "custom" or sorted(a.scanners) == sorted(b.scanners))


def _finding_order(f: Finding) -> Tuple[int, str, str]:
    return -int(f.severity), f.title.lower(), f.location.lower()


def _host_summary(entries: List[Tuple[_dt.datetime, ScanResult]], now: _dt.datetime, since_days: Optional[int],
                  min_severity: Severity) -> HostSummary:
    when, newest = entries[-1]
    series = [(t, r) for t, r in entries if _comparable(r, newest)]
    previous = series[-2][1] if len(series) > 1 else None
    score, grade = security_score(newest)
    shown = sorted((f for f in newest.findings if f.severity >= min_severity), key=_finding_order)
    new_keys = {match_key(f) for f in newest.findings} - {match_key(f) for f in previous.findings} \
        if previous is not None else set()
    plan = action_plan(newest, limit=3, min_severity=max(min_severity, Severity.LOW))
    age = now - when
    src = str(newest.stats.get("source_file", ""))
    return HostSummary(
        hostname=_hostname(newest), os=_clean(newest.host.get("os") or "", 40),
        platform=_clean(newest.host.get("platform") or "", 200),
        admin=bool(newest.host.get("admin")), last_scan=when.isoformat(timespec="seconds"), profile=newest.profile,
        score=score, grade=grade, counts=newest.counts(),
        new_findings=sum(1 for f in shown if match_key(f) in new_keys) if previous is not None else None,
        score_change=score - security_score(previous)[0] if previous is not None else None,
        previous_scan=series[-2][0].isoformat(timespec="seconds") if previous is not None else None,
        stale=since_days is not None and age > _dt.timedelta(days=since_days), age_days=max(0, age.days),
        scans=len(entries), trend=[(t.strftime("%Y-%m-%d"), security_score(r)[0]) for t, r in series[-SPARKLINE_POINTS:]],
        findings_total=len(shown),
        findings=[{"rule_id": f.rule_id, "severity": f.severity.name.lower(), "title": f.title,
                   "location": f.location[:500], "fingerprint": f.fingerprint, "new": match_key(f) in new_keys}
                  for f in shown[:MAX_HOST_FINDINGS]],
        actions=[{"rule_id": p["rule_id"], "severity": p["severity"], "title": p["title"], "count": p["count"],
                  "locations": [x[:500] for x in p["locations"]], "recommendation": p["recommendation"], "fix": p["fix"]}
                 for p in plan],
        source=src)


def _common_issues(newest: List[ScanResult], min_severity: Severity) -> Tuple[List[CommonIssue], int]:
    groups: Dict[str, List[Tuple[Finding, str]]] = {}
    for r in newest:
        name = _hostname(r)
        for f in r.findings:
            if f.severity >= min_severity:
                groups.setdefault(f.rule_id, []).append((f, name))
    issues: List[CommonIssue] = []
    for rule_id, items in groups.items():
        items.sort(key=lambda it: (_finding_order(it[0]), it[1].lower()))  # worst instance first
        worst = items[0][0]
        names = sorted({n for _f, n in items}, key=str.lower)
        issues.append(CommonIssue(
            rule_id=rule_id, title=worst.title, severity=worst.severity.name.lower(), hosts=len(names), host_names=names,
            findings=len(items), variants=len({f.title for f, _n in items}) - 1,
            recommendation=next((f.recommendation for f, _n in items if f.recommendation), "")))
    issues.sort(key=lambda c: (-int(Severity[c.severity.upper()]), -c.hosts, -c.findings, c.title.lower(), c.rule_id))
    return issues[:MAX_COMMON_ISSUES], len(issues)


def build_fleet(results: Sequence[ScanResult], now: Optional[_dt.datetime] = None, since_days: Optional[int] = None,
                min_severity: Severity = Severity.MEDIUM, load: Optional[LoadReport] = None) -> Fleet:
    """Aggregate scan results of many hosts.

    The newest result of each host (by ``started``) is the host's row; older results of the same host only feed its
    score trend and the "new since previous scan" / score-change numbers. A host whose newest result is more than
    ``since_days`` old is marked stale (and stays in every list). ``min_severity`` limits the findings that are listed,
    counted as new, and grouped into common issues. ``load`` adds the skipped-file information of :func:`load_results`.
    Results without a readable ``started`` time are ignored."""
    now = _naive(now or _dt.datetime.now())
    by_host: Dict[str, List[Tuple[_dt.datetime, ScanResult]]] = {}
    for r in results:
        when = parse_time(r.started)
        if when is not None:
            by_host.setdefault(_hostname(r).lower(), []).append((when, r))
    duplicates = 0
    hosts: List[HostSummary] = []
    newest: List[ScanResult] = []
    for entries in by_host.values():
        entries.sort(key=lambda e: (e[0], str(e[1].stats.get("source_file", "")), e[1].profile))
        unique: List[Tuple[_dt.datetime, ScanResult]] = []
        seen = set()
        for when, r in entries:  # the same scan found twice (a copy in another folder) must not become "previous"
            if (when, r.profile) in seen:
                duplicates += 1
                continue
            seen.add((when, r.profile))
            unique.append((when, r))
        hosts.append(_host_summary(unique, now, since_days, min_severity))
        newest.append(unique[-1][1])
    hosts.sort(key=lambda h: (-h.counts["critical"], -h.counts["high"], -h.counts["medium"], h.score, h.hostname.lower()))
    issues, kinds = _common_issues(newest, min_severity)
    scores = [h.score for h in hosts]
    load = load or LoadReport()
    totals = {
        "hosts": len(hosts), "needing_attention": sum(1 for h in hosts if h.counts["critical"] or h.counts["high"]),
        "stale": sum(1 for h in hosts if h.stale),
        "average_score": round(sum(scores) / len(scores), 1) if scores else None,
        "results": sum(len(e) for e in by_host.values()) - duplicates, "duplicates": duplicates, "issue_kinds": kinds,
    }
    skipped = {"count": len(load.skipped),
               "files": [{"file": p, "reason": why} for p, why in load.skipped[:MAX_SKIPPED_LISTED]],
               "paths_not_found": list(load.missing), "limit_reached": load.limit_reached}
    return Fleet(generated=now.isoformat(timespec="seconds"), since_days=since_days, min_severity=min_severity,
                 hosts=hosts, common_issues=issues, totals=totals, skipped=skipped)


def exceeds(fleet: Fleet, level: Severity) -> bool:
    """True if the newest result of any host has a finding at/above ``level`` (the ``--fail-on`` test)."""
    return any(h.counts.get(s.name.lower(), 0) for h in fleet.hosts for s in Severity if s >= level)


def skipped_note(fleet: Fleet) -> str:
    """The sentence about files that were left out ('' when none were)."""
    n = fleet.skipped["count"]
    parts = []
    if n:
        parts.append(f"Skipped {n} files that are not Aegis scan results." if n != 1
                     else "Skipped 1 file that is not an Aegis scan result.")
    if fleet.skipped["limit_reached"]:
        parts.append(f"Stopped after reading {MAX_FILES:,} files; more were present.")
    return " ".join(parts)


# --------------------------------------------------------------------------- JSON / CSV / text

def render_json(fleet: Fleet) -> str:
    return json.dumps(fleet.to_dict(), indent=2, default=str)


def _csv_text(value: Any) -> str:
    """Text for a spreadsheet cell: a leading =, +, - or @ would be run as a formula by Excel."""
    s = str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def _blank(value: Any) -> Any:
    return "" if value is None else value


def render_csv(fleet: Fleet) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["hostname", "platform", "last_scan", "profile", "score", "grade", "critical", "high", "medium", "low",
                "new_findings", "score_change", "stale"])
    for h in fleet.hosts:
        w.writerow([_csv_text(h.hostname), _csv_text(h.platform), h.last_scan, _csv_text(h.profile), h.score, h.grade,
                    h.counts["critical"], h.counts["high"], h.counts["medium"], h.counts["low"], _blank(h.new_findings),
                    _blank(h.score_change), "yes" if h.stale else "no"])
    return buf.getvalue()


def render_text(fleet: Fleet, limit: int = 20) -> str:
    """Console summary: the numbers, the hosts that need attention first, and the most common issues."""
    t = fleet.totals
    avg = "n/a" if t["average_score"] is None else t["average_score"]
    lines = [f"Fleet: {t['hosts']} host{'s' if t['hosts'] != 1 else ''}, {t['needing_attention']} need attention "
             f"(critical or high findings), average score {avg}"
             + (f", {t['stale']} with no scan in the last {fleet.since_days} days" if fleet.since_days is not None else "")]
    note = skipped_note(fleet)
    if note:
        lines.append(note)
    lines += ["", f"{'HOST':<24} {'LAST SCAN':<16} {'SCORE':>7} {'CRIT':>5} {'HIGH':>5} {'MED':>4} {'NEW':>4} {'CHANGE':>6}"]
    for h in fleet.hosts[:limit]:
        new = "-" if h.new_findings is None else str(h.new_findings)
        chg = "-" if h.score_change is None else f"{h.score_change:+d}"
        lines.append(f"{_clean(h.hostname, 24):<24} {h.last_scan[:16].replace('T', ' '):<16} {f'{h.score} {h.grade}':>7} "
                     f"{h.counts['critical']:>5} {h.counts['high']:>5} {h.counts['medium']:>4} {new:>4} {chg:>6}"
                     + ("  STALE" if h.stale else ""))
    if len(fleet.hosts) > limit:
        lines.append(f"...and {len(fleet.hosts) - limit} more hosts")
    if fleet.common_issues:
        lines += ["", "Most common issues:"]
        for c in fleet.common_issues[:5]:
            lines.append(f"  {c.severity.upper():<8} {_clean(c.title, 90)}  ({c.hosts} of {t['hosts']} hosts)")
    return "\n".join(lines)


# --------------------------------------------------------------------------- HTML

_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--fg:#1d2329;--muted:#5f6b76;--line:#e3e7eb;--code:#f0f2f5}
@media (prefers-color-scheme: dark){:root{--bg:#0f1317;--card:#171c21;--fg:#e6eaee;--muted:#98a4b0;--line:#27303a;--code:#1f262d}}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg)}
main{max-width:1100px;margin:0 auto;padding:24px 16px}
h1{margin:0 0 4px;font-size:24px}h2{margin:0 0 12px;font-size:18px}h3{margin:14px 0 6px;font-size:15px}.sub{color:var(--muted)}
.tiles{display:flex;gap:12px;flex-wrap:wrap;margin:20px 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 16px;min-width:130px}
.tile .n{font-size:26px;font-weight:700}.tile .l{color:var(--muted);font-size:13px}
section{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin:16px 0}
.tw{overflow-x:auto}table{width:100%;border-collapse:collapse}
th{text-align:left;font-size:13px;color:var(--muted);padding:6px 8px;border-bottom:1px solid var(--line);white-space:nowrap}
#hosts td:first-child{white-space:nowrap}#hosts th{cursor:pointer}
th[aria-sort=ascending]::after{content:" \\25B2"}th[aria-sort=descending]::after{content:" \\25BC"}
td{padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}td.r,th.r{text-align:right}
a{color:inherit;font-weight:600}.meta{color:var(--muted);font-size:12px}.cnt{color:var(--muted);font-weight:600}
.badge{color:#fff;font-size:11px;font-weight:700;padding:2px 8px;border-radius:4px;display:inline-block;min-width:70px;text-align:center}
.num{color:#fff;font-size:12px;font-weight:700;padding:1px 7px;border-radius:10px;display:inline-block;min-width:26px;text-align:center}
.pill{font-size:11px;font-weight:700;padding:2px 8px;border-radius:10px;color:#fff;background:#9aa5b1;white-space:nowrap}
.stale{background:#6c757d;margin-left:6px}.g-A,.g-B{background:#2f9e44}.g-C{background:#f59f00;color:#222}.g-D,.g-F{background:#e03131}
.ok{background:#2f9e44}.new{background:#e03131;margin-left:6px}.up{color:#2f9e44}.down{color:#e03131}
.bad{color:#e03131}.good{color:#2f9e44}@SEV@
details.host{border:1px solid var(--line);border-radius:8px;margin:8px 0;overflow:hidden}
details.host summary{cursor:pointer;padding:10px 12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
details.host .body{padding:0 14px 12px;border-top:1px solid var(--line)}
ul.list,ol.list{list-style:none;padding:0;margin:0}.list li{padding:6px 0;border-bottom:1px solid var(--line)}
.list li:last-child{border-bottom:0}
.list .badge{margin-right:6px;font-size:10px;min-width:58px}.list code{display:block;margin-top:2px;color:var(--muted)}
.list p{margin:4px 0 0}code{background:var(--code);border-radius:4px;font-size:13px;padding:1px 4px;word-break:break-all}
.trend{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-top:14px;color:var(--muted);font-size:13px}
footer{color:var(--muted);font-size:12px;text-align:center;margin:24px 0}
""".replace("@SEV@", "".join(f".b-{k}{{background:{v}}}" for k, v in _SEV_COLORS.items()) + ".b-medium{color:#222}")

_SCRIPT = """<script>
(function(){
  var t=document.getElementById('hosts'); if(!t) return;
  var body=t.tBodies[0], last=-1, asc=true;
  t.tHead.addEventListener('click',function(ev){
    var th=ev.target.closest('th'); if(!th) return;
    var i=th.cellIndex, num=th.dataset.t==='n';
    asc=(i===last)?!asc:!num; last=i;
    function val(r){var v=r.cells[i].dataset.v; return num?(v===''?-Infinity:parseFloat(v)):v;}
    var rows=Array.prototype.slice.call(body.rows);
    rows.sort(function(a,b){var x=val(a),y=val(b); return (x<y?-1:x>y?1:0)*(asc?1:-1);});
    rows.forEach(function(r){body.appendChild(r);});
    Array.prototype.forEach.call(t.tHead.rows[0].cells,function(c){c.removeAttribute('aria-sort');});
    th.setAttribute('aria-sort',asc?'ascending':'descending');
  });
  function show(){var d=document.getElementById(location.hash.slice(1)); if(d&&d.tagName==='DETAILS') d.open=true;}
  window.addEventListener('hashchange',show); show();
})();
</script>"""

_HEAD = ('<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
         '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
         '<meta name="generator" content="Aegis Security Suite">\n<meta name="aegis-report" content="fleet">\n'
         f"<title>Aegis Fleet Overview</title>\n<style>{_CSS}</style></head><body><main>\n")
_TAIL = f"\n</main>\n{_SCRIPT}</body></html>"


def _age(days: int) -> str:
    return "today" if days < 1 else "1 day ago" if days == 1 else f"{days} days ago"


def _badge(sev: str) -> str:
    return f'<span class="badge b-{sev}">{sev.upper()}</span>'


def _count_cell(n: int, sev: str) -> str:
    inner = f'<span class="num b-{sev}">{n}</span>' if n else '<span class="meta">0</span>'
    return f'<td class="r" data-v="{n}">{inner}</td>'


def _tiles(fleet: Fleet) -> str:
    t = fleet.totals
    avg = t["average_score"]
    given = fleet.since_days is not None
    stale = str(t["stale"]) if given else "n/a"
    stale_label = f"Stale (no scan in {fleet.since_days} days)" if given else "Stale (no --since given)"
    tiles = [("Hosts", str(t["hosts"]), ""),
             ("Need attention", str(t["needing_attention"]), "bad" if t["needing_attention"] else "good"),
             ("Average score", "n/a" if avg is None else f"{avg:g}", ""),
             (stale_label, stale, "bad" if t["stale"] else "")]
    return '<div class="tiles">' + "".join(
        f'<div class="tile"><div class="n {c}">{html.escape(v)}</div><div class="l">{html.escape(lab)}</div></div>'
        for lab, v, c in tiles) + "</div>"


def _host_row(i: int, h: HostSummary) -> str:
    e = html.escape
    chg = "" if h.score_change is None else f"{h.score_change:+d}"
    chg_cls = "meta" if not h.score_change else "up" if h.score_change > 0 else "down"
    return (
        f'<tr><td data-v="{e(h.hostname.lower())}"><a href="#h{i}">{e(_short(h.hostname, 40))}</a>'
        + ('<span class="pill stale">stale</span>' if h.stale else "") + "</td>"
        f'<td data-v="{e(h.platform.lower())}" title="{e(h.platform)}">{e(_short(h.platform or h.os, 36))}</td>'
        f'<td data-v="{e(h.last_scan)}">{e(h.last_scan[:10])}<div class="meta">{e(h.profile)} &middot; {_age(h.age_days)}</div></td>'
        f'<td class="r" data-v="{h.score}"><span class="pill g-{e(h.grade)}">{h.score} &middot; {e(h.grade)}</span></td>'
        + _count_cell(h.counts["critical"], "critical") + _count_cell(h.counts["high"], "high")
        + _count_cell(h.counts["medium"], "medium")
        + f'<td class="r" data-v="{"" if h.new_findings is None else h.new_findings}">'
          f'{"-" if h.new_findings is None else h.new_findings}</td>'
        f'<td class="r {chg_cls}" data-v="{chg}">{e(chg) or "-"}</td>'
        f'<td data-v="{int(h.admin)}">{"yes" if h.admin else "no"}</td></tr>')


def _hosts_table(fleet: Fleet) -> str:
    cols = [("Host", "s", ""), ("Platform", "s", ""), ("Last scan", "s", ""), ("Score", "n", "r"), ("Critical", "n", "r"),
            ("High", "n", "r"), ("Medium", "n", "r"), ("New since previous", "n", "r"), ("Score change", "n", "r"),
            ("Admin", "s", "")]
    head = "".join(f'<th class="{c}" data-t="{t}">{n}</th>' for n, t, c in cols)
    rows = "\n".join(_host_row(i, h) for i, h in enumerate(fleet.hosts))
    return (f'<section><h2>Hosts</h2><p class="meta">Worst first; click a heading to sort. New and score change compare the '
            f'latest scan with the previous scan of the same kind.</p><div class="tw"><table id="hosts"><thead><tr>{head}</tr></thead>'
            f"<tbody>\n{rows}\n</tbody></table></div></section>")


def _common_section(fleet: Fleet) -> str:
    e = html.escape
    if not fleet.common_issues:
        return (f'<section><h2>Most common issues across the fleet</h2><p>No findings at {e(fleet.min_severity.name.lower())} '
                "or above on any host.</p></section>")
    rows = []
    for c in fleet.common_issues:
        names = ", ".join(_short(n, 30) for n in c.host_names[:5]) + (f" and {c.hosts - 5} more" if c.hosts > 5 else "")
        similar = f' <span class="cnt">(+ {c.variants} similar)</span>' if c.variants else ""
        rows.append(
            f'<tr><td>{_badge(c.severity)}</td><td><b>{e(c.title)}</b>{similar}<div class="meta">rule {e(c.rule_id)}</div></td>'
            f'<td>{c.hosts} of {fleet.totals["hosts"]}<div class="meta">{e(names)}</div></td>'
            f"<td>{e(c.recommendation)}</td></tr>")
    rest = fleet.totals["issue_kinds"] - len(fleet.common_issues)
    tail = f'<p class="meta">{rest} more kind(s) of issue are in the JSON output.</p>' if rest > 0 else ""
    return ('<section><h2>Most common issues across the fleet</h2><div class="tw"><table><thead><tr><th>Severity</th><th>Issue</th>'
            f'<th>Hosts</th><th>What to do</th></tr></thead><tbody>\n{chr(10).join(rows)}\n</tbody></table></div>{tail}</section>')


def _host_details(i: int, h: HostSummary, min_severity: Severity) -> str:
    e = html.escape
    worst = h.worst()
    head = _badge(worst) if worst != "clean" else '<span class="pill ok">CLEAN</span>'
    out = [f'<details class="host" id="h{i}"><summary>{head}<b>{e(_short(h.hostname, 60))}</b>'
           f'<span class="meta">score {h.score} ({e(h.grade)}) &middot; {h.counts["critical"]} critical, {h.counts["high"]} high, '
           f'{h.counts["medium"]} medium &middot; {e(h.last_scan[:10])} ({e(h.profile)})</span></summary><div class="body">']
    trend = h.trend
    if len(trend) >= 2:
        out.append(f'<div class="trend">{_sparkline(trend)}<span>Score over the last {len(trend)} {e(h.profile)} scans '
                   f"({e(trend[0][0])} to {e(trend[-1][0])}): {trend[0][1]} &rarr; {trend[-1][1]}</span></div>")
    if h.actions:
        items = []
        for n, a in enumerate(h.actions, 1):
            count = f' <span class="cnt">&times; {a["count"]}</span>' if a["count"] > 1 else ""
            fix = f'<p class="meta">On this PC: <code>{e(a["fix"])}</code></p>' if a["fix"] else ""
            items.append(f'<li>{_badge(a["severity"])}<b>{n}. {e(a["title"])}</b>{count}'
                         + (f'<p>{e(a["recommendation"])}</p>' if a["recommendation"] else "") + f"{fix}</li>")
        out.append(f'<h3>What to do first</h3><ol class="list">{"".join(items)}</ol>')
    level = e(min_severity.name.lower())
    if h.findings:
        items = [f'<li>{_badge(f["severity"])}{e(f["title"])}'
                 + (' <span class="pill new">NEW</span>' if f["new"] else "")
                 + (f'<code>{e(_short(f["location"], 160))}</code>' if f["location"] else "") + "</li>" for f in h.findings]
        more = f'<p class="meta">...and {h.findings_total - len(h.findings)} more.</p>' if h.findings_total > len(h.findings) else ""
        out.append(f'<h3>Findings ({level} and above: {h.findings_total})</h3><ul class="list">{"".join(items)}</ul>{more}')
    else:
        out.append(f'<h3>Findings</h3><p class="meta">None at {level} or above.</p>')
    out.append(f'<p class="meta">{h.scans} scan result{"s" if h.scans != 1 else ""} found for this host'
               f' &middot; {e(_short(h.os or h.platform, 60))} &middot; admin: {"yes" if h.admin else "no"}</p></div></details>')
    return "".join(out)


def render_html(fleet: Fleet) -> str:
    """Self-contained overview page: the same look as the scan report, everything HTML-escaped, one inline script."""
    e = html.escape
    t = fleet.totals
    n, dup = t["results"], t["duplicates"]
    notes = [f"Generated {e(fleet.generated.replace('T', ' '))} from {n} scan result{'s' if n != 1 else ''}"
             + (f" ({dup} duplicate{'s' if dup != 1 else ''} ignored)" if dup else "") + "."]
    note = skipped_note(fleet)
    if note:
        notes.append(e(note))
    body = [f'<header><h1>Aegis Fleet Overview</h1><div class="sub">{" ".join(notes)}</div></header>', _tiles(fleet),
            _hosts_table(fleet), _common_section(fleet),
            '<section><h2>Host details</h2>' + "\n".join(_host_details(i, h, fleet.min_severity) for i, h in enumerate(fleet.hosts))
            + "</section>",
            f'<footer>Generated by Aegis Security Suite. Scores are recomputed from the findings in each result.</footer>']
    return _HEAD + "\n".join(body) + _TAIL


# --------------------------------------------------------------------------- writing

def write_fleet(fleet: Fleet, path: "str | Path", fmt: str = "") -> Path:
    """Write the overview as html, json or csv (by ``fmt`` or the file extension; no extension means html).

    The file is written next to the target and moved into place, so a reader (a browser on a share) never sees a
    half-written report. Line endings are LF on every OS."""
    p = Path(path)
    fmt = (fmt or p.suffix.lstrip(".") or "html").lower()
    fmt = "html" if fmt == "htm" else fmt
    renderers = {"html": render_html, "json": render_json, "csv": render_csv}
    if fmt not in renderers:
        raise ValueError(f"unsupported fleet report format {fmt!r} ({', '.join(FLEET_FORMATS)})")
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(f".{p.name}.{os.getpid()}.tmp")
    try:
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(renderers[fmt](fleet))
        os.replace(tmp, p)
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass
    return p


# --------------------------------------------------------------------------- recognising our own output

_TOKEN = re.compile(r"<[^<>]*>")
_TAG = re.compile(r'<(/?)([a-z][a-z0-9]*)((?:\s+[A-Za-z][A-Za-z0-9:-]*="[^"<>]*")*)\s*(/?)>\Z')
_ATTR = re.compile(r'\s+([A-Za-z][A-Za-z0-9:-]*)="([^"<>]*)"')
_TAGS = frozenset("a b circle code details div footer h1 h2 h3 header li line ol p polyline section small span summary svg table "
                  "tbody td th thead title tr ul".split())
_VOID = frozenset(("line", "polyline", "circle"))
_ATTRS = frozenset("class id href title role colspan scope data-v data-t aria-label aria-sort style viewBox width height x1 y1 "
                   "x2 y2 fill stroke stroke-width stroke-linejoin stroke-dasharray points cx cy r".split())
_HREF = re.compile(r"#[A-Za-z0-9_-]+\Z")
_STYLE = re.compile(r"[a-z-]+:[#a-z0-9(),.% -]+(?:;[a-z-]+:[#a-z0-9(),.% -]+)*;?\Z")


def is_fleet_html(data: bytes) -> bool:
    """True if ``data`` is a page written by :func:`render_html`: the fixed frame (head, style, script) around a body
    that uses only the tags and attributes this module emits, with links only to anchors on the same page. Quoted
    text in the body is escaped, so it cannot contain markup."""
    try:
        text = data.decode("utf-8").rstrip()
    except UnicodeDecodeError:
        return False
    if not text.startswith(_HEAD) or not text.endswith(_TAIL):
        return False
    body = text[len(_HEAD):len(text) - len(_TAIL)]
    for token in _TOKEN.findall(body):
        m = _TAG.match(token)
        if not m or m.group(2) not in _TAGS:
            return False
        closing, name, attrs, selfclose = m.groups()
        if (closing and attrs) or (selfclose and (closing or name not in _VOID)):
            return False
        for key, value in _ATTR.findall(attrs):
            if key not in _ATTRS or (key == "href" and not _HREF.match(value)) or \
                    (key == "style" and (not _STYLE.match(value) or "url(" in value)):
                return False
    rest = _TOKEN.sub("", body)
    return "<" not in rest and ">" not in rest


_HOST_SCHEMA: Dict[str, Any] = {
    "hostname": "s", "os": "s", "platform": "s", "admin": "b", "last_scan": "s", "profile": "s", "score": "i", "grade": "s",
    "counts": {s: "i" for s in _SEVERITIES}, "new_findings": "?i", "score_change": "?i", "previous_scan": "?s", "stale": "b",
    "age_days": "i", "scans": "i", "trend": [{"date": "s", "score": "i"}], "findings_total": "i",
    "findings": [{"rule_id": "s", "severity": "s", "title": "s", "location": "s", "fingerprint": "s", "new": "b"}],
    "actions": [{"rule_id": "s", "severity": "s", "title": "s", "count": "i", "locations": ["s"], "recommendation": "s",
                 "fix": "s"}],
    "source": "s",
}
_JSON_SCHEMA: Dict[str, Any] = {
    "generator": "s", "report": "s", "schema": "i", "generated": "s", "since_days": "?i", "min_severity": "s",
    "totals": {"hosts": "i", "needing_attention": "i", "stale": "i", "average_score": "?n", "results": "i", "duplicates": "i",
               "issue_kinds": "i"},
    "hosts": [_HOST_SCHEMA],
    "common_issues": [{"rule_id": "s", "title": "s", "severity": "s", "hosts": "i", "host_names": ["s"], "findings": "i",
                       "variants": "i", "recommendation": "s"}],
    "skipped": {"count": "i", "files": [{"file": "s", "reason": "s"}], "paths_not_found": ["s"], "limit_reached": "b"},
}


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


_LEAF = {
    "s": lambda v: isinstance(v, str), "b": lambda v: isinstance(v, bool), "i": _is_int,
    "n": lambda v: _is_int(v) or isinstance(v, float), "?i": lambda v: v is None or _is_int(v),
    "?s": lambda v: v is None or isinstance(v, str), "?n": lambda v: v is None or _is_int(v) or isinstance(v, float),
}


def _matches(value: Any, schema: Any) -> bool:
    if isinstance(schema, dict):
        return isinstance(value, dict) and set(value) == set(schema) and all(_matches(value[k], s) for k, s in schema.items())
    if isinstance(schema, list):
        return isinstance(value, list) and all(_matches(v, schema[0]) for v in value)
    return bool(_LEAF[schema](value))


def is_fleet_json(d: Any) -> bool:
    """True if the parsed JSON ``d`` has exactly the structure :func:`render_json` writes (same keys, same value types
    at every level); the strings in it are free text, as in the scan result."""
    return (_matches(d, _JSON_SCHEMA) and d["generator"] == GENERATOR and d["report"] == "fleet"
            and d["schema"] == SCHEMA_VERSION and d["min_severity"] in _SEVERITIES)
