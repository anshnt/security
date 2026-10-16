"""Report rendering: coloured console text, self-contained HTML, JSON, CSV and SARIF."""

from __future__ import annotations

import csv
import datetime as _dt
import html
import io
import json
import os
import re
import urllib.parse
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Dict, List, Optional, Tuple

from aegis import __app_name__, __version__
from aegis.core.models import CheckStatus, Finding, ScanResult, Severity
from aegis.core.scoring import grade_for, security_score

_ANSI = {
    Severity.CRITICAL: "\033[1;97;41m",
    Severity.HIGH: "\033[1;91m",
    Severity.MEDIUM: "\033[1;93m",
    Severity.LOW: "\033[96m",
    Severity.INFO: "\033[37m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_GREEN = "\033[1;92m"


def _c(text: str, code: str, color: bool) -> str:
    return f"{code}{text}{_RESET}" if color else text


def render_text(result: ScanResult, color: bool = False, verbose: bool = False, min_severity: Severity = Severity.LOW) -> str:
    score, grade = security_score(result)
    out: List[str] = []
    w = out.append
    w(_c(f"{__app_name__} {__version__} - {result.profile} scan report", _BOLD, color))
    w(f"Host: {result.host.get('hostname', '?')} ({result.host.get('platform', '')})   "
      f"Admin: {'yes' if result.host.get('admin') else 'no'}   Started: {result.started}   Duration: {result.stats.get('duration_s', '?')}s")
    w(f"Scanners: {', '.join(result.scanners)}")
    grade_color = _GREEN if grade in ("A", "B") else _ANSI[Severity.MEDIUM] if grade == "C" else _ANSI[Severity.HIGH]
    w("")
    w("Security score: " + _c(f"{score}/100 (grade {grade})", grade_color, color))
    counts = result.counts()
    w("Findings: " + "  ".join(_c(f"{k.upper()} {v}", _ANSI[Severity[k.upper()]], color) for k, v in counts.items() if k != "info")
      + f"  INFO {counts['info']}")
    if isinstance(result.stats.get("new_findings"), int):
        sc = result.stats.get("score_change")
        w(f"Since the previous {result.profile} scan: {result.stats['new_findings']} new, "
          f"{result.stats.get('resolved_findings', 0)} resolved" + (f", score {sc:+d}" if isinstance(sc, int) else ""))
    if not result.host.get("admin"):
        w(_c("Note: not running as Administrator/root - some checks were limited.", _DIM, color))
    w("")

    shown = [f for f in result.sorted_findings() if f.severity >= min_severity]
    plan = action_plan(result, limit=3, min_severity=max(min_severity, Severity.LOW))
    if len({f.rule_id for f in shown}) > 1 and plan:
        w(_c("What to do first:", _BOLD, color))
        for i, p in enumerate(plan, 1):
            sev = Severity[p["severity"].upper()]
            fix = p["fix"] if p["fix"] and len(p["fix"]) <= 80 else ("aegis fix" if p["fix"] else "")
            count = f" (x{p['count']})" if p["count"] > 1 else ""
            w(f"  {i}. {_c(p['severity'].upper(), _ANSI[sev], color)} {p['title']}{count}" + (f"  ->  {fix}" if fix else ""))
        w("")
    if not shown:
        w(_c("No threats or issues found at this severity level.", _GREEN, color))
    for f in shown:
        tag = _c(f" {f.severity.name:<8} ", _ANSI[f.severity], color)
        w(f"{tag} {f.title}  {_c('[' + f.fingerprint + ']', _DIM, color)}")
        if f.location:
            w(f"           at: {f.location}")
        if verbose and f.description:
            w(f"           {f.description}")
        if f.recommendation:
            w(f"           fix: {f.recommendation}" + ("  (auto-fix available)" if f.remediation else ""))
        if verbose and f.evidence:
            w("           evidence: " + json.dumps(f.evidence, default=str)[:400])
        if verbose and f.mitre:
            w("           MITRE ATT&CK: " + ", ".join(f.mitre))
    if result.checks:
        passed = sum(1 for c in result.checks if c.status == CheckStatus.PASS)
        failed = [c for c in result.checks if c.status in (CheckStatus.FAIL, CheckStatus.WARN)]
        w("")
        w(f"Hardening checks: {passed}/{len(result.checks)} passed, {len(failed)} need attention")
        if verbose:
            for c in result.checks:
                mark = {"pass": _c("PASS", _GREEN, color), "fail": _c("FAIL", _ANSI[Severity.HIGH], color),
                        "warn": _c("WARN", _ANSI[Severity.MEDIUM], color)}.get(c.status, c.status.upper())
                w(f"  [{mark}] {c.title}" + (f" - {c.detail}" if c.detail else ""))
    if result.errors:
        w("")
        w("Errors:")
        for e in result.errors:
            w(f"  - {e}")
    if result.stats.get("saved_to"):
        w("")
        w(_c(f"Full JSON results: {result.stats['saved_to']}", _DIM, color))
    return "\n".join(out)


_REPORT_SCRIPT = """<script>
(function(){
  var sev='all', q=document.getElementById('q');
  function apply(){
    var t=(q&&q.value||'').toLowerCase().trim(), shown=0;
    document.querySelectorAll('details.finding').forEach(function(d){
      var ok=(sev==='all'||d.dataset.sev===sev)&&(!t||d.textContent.toLowerCase().indexOf(t)>=0);
      d.style.display=ok?'':'none'; if(ok) shown++;
    });
    var c=document.getElementById('shown'); if(c) c.textContent=shown;
  }
  document.getElementById('filters').addEventListener('click',function(ev){
    var b=ev.target.closest('button'); if(!b) return;
    document.querySelectorAll('#filters button').forEach(function(x){x.classList.toggle('on',x===b)});
    sev=b.dataset.f; apply();
  });
  if(q) q.addEventListener('input',apply);
})();
</script>"""

_SEV_COLORS = {"critical": "#b3261e", "high": "#e8590c", "medium": "#f2c94c", "low": "#4dabf7", "info": "#9aa5b1"}


_HISTORY_CSS = """
.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px}
h3{margin:0 0 8px;font-size:15px}.chg{list-style:none;padding:0;margin:0}
.chg li{padding:6px 0;border-bottom:1px solid var(--line)}.chg .badge{margin-right:6px;font-size:10px;min-width:58px;display:inline-block}
.chg code{display:block;margin-top:2px;color:var(--muted)}.up{color:#2f9e44}.down{color:#e03131}
.trend{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-top:14px;color:var(--muted);font-size:13px}
"""


def _as_dicts(value: Any) -> List[Dict[str, Any]]:
    return [x for x in value if isinstance(x, dict)] if isinstance(value, list) else []


def _clean_trend(value: Any) -> List[Tuple[str, int]]:
    out: List[Tuple[str, int]] = []
    for item in value if isinstance(value, list) else []:
        try:
            out.append((str(item[0]), max(0, min(100, int(item[1])))))
        except (TypeError, ValueError, IndexError, KeyError):
            continue
    return out


def _sparkline(points: List[Tuple[str, int]]) -> str:
    """Inline SVG line of the scores (oldest first). Every value is an int or escaped text."""
    if len(points) < 2:
        return ""
    w, h, pad = 260, 56, 6
    n = len(points)
    xs = [pad + i * (w - 2 * pad) / (n - 1) for i in range(n)]
    ys = [h - pad - (v / 100.0) * (h - 2 * pad) for _d, v in points]
    line = " ".join(f"{x:.1f},{y:.1f}" for x, y in zip(xs, ys))
    last = points[-1][1]
    ring = "#2f9e44" if grade_for(last) in ("A", "B") else "#f59f00" if grade_for(last) == "C" else "#e03131"
    y90 = h - pad - 0.9 * (h - 2 * pad)
    label = f"Score trend over the last {n} scans: {points[0][1]} to {last}"
    return (f'<svg viewBox="0 0 {w} {h}" width="{w}" height="{h}" role="img" aria-label="{html.escape(label)}">'
            f"<title>{html.escape(label)}</title>"
            f'<line x1="{pad}" y1="{y90:.1f}" x2="{w - pad}" y2="{y90:.1f}" style="stroke:var(--line)" stroke-dasharray="3 3"/>'
            f'<polyline fill="none" stroke="#4c8dff" stroke-width="2" stroke-linejoin="round" points="{line}"/>'
            f'<circle cx="{xs[-1]:.1f}" cy="{ys[-1]:.1f}" r="4" fill="{ring}"/></svg>')


def _change_items(items: List[Dict[str, Any]], limit: int = 50) -> str:
    e = html.escape
    rows = []
    for x in items[:limit]:
        sev = str(x.get("severity", "info")).lower()
        sev = sev if sev in _SEV_COLORS else "info"
        loc = str(x.get("location", ""))
        ink = ";color:#222" if sev == "medium" else ""
        rows.append(f'<li><span class="badge sev-{sev}" style="background:{_SEV_COLORS[sev]}{ink}">{sev.upper()}</span>'
                    f'{e(str(x.get("title", "")))}' + (f"<code>{e(loc)}</code>" if loc else "") + "</li>")
    if len(items) > limit:
        rows.append(f'<li class="meta">...and {len(items) - limit} more</li>')
    return "".join(rows) or '<li class="meta">None</li>'


def _render_changes(h: Optional[Dict[str, Any]]) -> str:
    """"Changes since previous scan" section + score trend sparkline; '' when there is nothing to show."""
    if not isinstance(h, dict):
        return ""
    e = html.escape
    prev = h.get("previous") if isinstance(h.get("previous"), dict) else None
    trend = _clean_trend(h.get("trend"))[-20:]
    if prev is None and len(trend) < 2:
        return ""
    out = ['<section id="changes"><h2>Changes since previous scan</h2>']
    if prev is not None:
        new, resolved = _as_dicts(h.get("new")), _as_dicts(h.get("resolved"))
        try:
            change = int(h.get("score_change"))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            change = None
        out.append(f'<div class="sub">Compared with the {e(str(prev.get("profile", "")))} scan of {e(str(prev.get("started", "")))}'
                   f' (score {e(str(prev.get("score", "?")))}, grade {e(str(prev.get("grade", "?")))})</div>')
        tiles = [("New", len(new), "#e03131" if new else "#2f9e44"), ("Resolved", len(resolved), "#2f9e44")]
        if change is not None:
            tiles.append(("Score change", f"{change:+d}", "#2f9e44" if change > 0 else "#e03131" if change < 0 else "#9aa5b1"))
        out.append('<div class="tiles">' + "".join(
            f'<div class="tile"><div class="n" style="color:{c}">{e(str(v))}</div><div class="l">{lab}</div></div>'
            for lab, v, c in tiles) + "</div>")
        out.append(f'<div class="cols"><div><h3>New ({len(new)})</h3><ul class="chg">{_change_items(new)}</ul></div>'
                   f'<div><h3>Resolved ({len(resolved)})</h3><ul class="chg">{_change_items(resolved)}</ul></div></div>')
    if len(trend) >= 2:
        out.append(f'<div class="trend">{_sparkline(trend)}<span>Score over the last {len(trend)} scans '
                   f'({e(trend[0][0][:10])} to {e(trend[-1][0][:10])}): {trend[0][1]} &rarr; {trend[-1][1]}</span></div>')
    out.append("</section>")
    return "".join(out)


MAX_PLAN_IDS = 6


def action_plan(result: ScanResult, limit: int = 6, min_severity: Severity = Severity.LOW) -> List[Dict[str, Any]]:
    """The few things to do first: findings grouped by rule, worst severity first, then by how many there are.

    Each item: ``rule_id``, ``severity``, ``title`` (of the worst finding, "+ N similar" when titles differ), ``count``,
    ``locations`` (up to 3), ``recommendation``, ``fixable`` (how many have an automatic fix), ``fingerprints`` (of
    those) and ``fix`` (the command that applies those fixes, or "")."""
    groups: Dict[str, List[Finding]] = {}
    for f in result.sorted_findings():
        if f.severity >= min_severity:
            groups.setdefault(f.rule_id, []).append(f)
    ordered = sorted(groups.values(), key=lambda fs: (-int(fs[0].severity), -len(fs), fs[0].title.lower()))
    plan: List[Dict[str, Any]] = []
    for fs in ordered[:limit]:
        top = fs[0]
        titles = {f.title for f in fs}
        fixable = [f for f in fs if f.remediation]
        fix = ""
        if fixable:  # by id, so only this group is touched; for many, the interactive fix asks about each one
            fix = "aegis fix " + " ".join(f"--id {f.fingerprint}" for f in fixable) if len(fixable) <= MAX_PLAN_IDS \
                else "aegis fix"
        plan.append({
            "rule_id": top.rule_id,
            "fingerprints": [f.fingerprint for f in fixable],
            "severity": top.severity.name.lower(),
            "title": top.title + (f" (+ {len(titles) - 1} similar)" if len(titles) > 1 else ""),
            "count": len(fs),
            "locations": [f.location for f in fs if f.location][:3],
            "recommendation": next((f.recommendation for f in fs if f.recommendation), ""),
            "fixable": len(fixable),
            "fix": fix,
        })
    return plan


def _render_plan(plan: List[Dict[str, Any]], total_groups: int) -> str:
    if not plan:
        return ""
    e = html.escape
    items = []
    for i, p in enumerate(plan, 1):
        where = "".join(f"<code>{e(_short(loc, 110))}</code>" for loc in p["locations"])
        more = f" and {p['count'] - len(p['locations'])} more" if p["count"] > len(p["locations"]) else ""
        how = " - it asks about each one" if p["fix"] == "aegis fix" else ""
        fix = (f'<p class="fix"><b>Fix automatically</b> ({p["fixable"]} of {p["count"]}): <code>{e(p["fix"])}</code>{how}</p>'
               if p["fix"] else "")
        items.append(f"""<li><span class="badge" style="background:{_SEV_COLORS[p['severity']]}">{p['severity'].upper()}</span>
  <div><b>{i}. {e(p['title'])}</b>{f' <span class="cnt">&times; {p["count"]}</span>' if p['count'] > 1 else ''}
  <div class="where">{where}{e(more)}</div>
  {f'<p>{e(p["recommendation"])}</p>' if p['recommendation'] else ''}{fix}</div></li>""")
    rest = f'<p class="meta">{total_groups - len(plan)} more kind(s) of issue are listed under Findings.</p>' \
        if total_groups > len(plan) else ""
    return f'<section class="plan"><h2>What to do first</h2><ol>{"".join(items)}</ol>{rest}</section>'


def _short(text: str, n: int) -> str:
    return text if len(text) <= n else text[:n // 2 - 1] + "\u2026" + text[-(n // 2 - 1):]


def render_html(result: ScanResult, history: Optional[Dict[str, Any]] = None) -> str:
    """Self-contained HTML report. ``history`` (default: ``result.stats["history"]``, filled in by the scan engine)
    adds the "Changes since previous scan" section and the score sparkline."""
    d = result.to_dict()
    changes = _render_changes(history if history is not None else (result.stats or {}).get("history"))
    score, grade = d["score"], d["grade"]
    e = html.escape
    ring = "#2f9e44" if grade in ("A", "B") else "#f59f00" if grade == "C" else "#e03131"
    rows = []
    for f in d["findings"]:
        sev = f["severity"]
        evidence = e(json.dumps(f["evidence"], indent=2, default=str)) if f["evidence"] else ""
        mitre = ", ".join(
            f'<a href="https://attack.mitre.org/techniques/{e(m.replace(".", "/"))}/" target="_blank" rel="noopener">{e(m)}</a>'
            for m in f["mitre"])
        rows.append(f"""
<details class="finding sev-{sev}" data-sev="{sev}" data-cat="{e(f['category'])}">
  <summary><span class="badge" style="background:{_SEV_COLORS[sev]}">{sev.upper()}</span>
    <span class="title">{e(f['title'])}{f'<small class="where">{e(_short(f["location"], 120))}</small>' if f['location'] else ''}</span><span class="cat">{e(f['category'])}</span></summary>
  <div class="body">
    {f'<p class="loc"><b>Location:</b> <code>{e(f["location"])}</code></p>' if f['location'] else ''}
    {f'<p>{e(f["description"])}</p>' if f['description'] else ''}
    {f'<p class="rec"><b>Recommendation:</b> {e(f["recommendation"])}</p>' if f['recommendation'] else ''}
    {f'<p><b>Auto-fix:</b> <code>aegis fix --id {e(f["fingerprint"])}</code></p>' if f['remediation'] else ''}
    {f'<p><b>MITRE ATT&amp;CK:</b> {mitre}</p>' if mitre else ''}
    {f'<pre>{evidence}</pre>' if evidence else ''}
    <p class="meta">rule {e(f['rule_id'])} &middot; scanner {e(f['scanner'])} &middot; id {e(f['fingerprint'])}</p>
  </div>
</details>""")
    checks = []
    for c in d["checks"]:
        st = c["status"]
        checks.append(f'<tr class="st-{e(st)}"><td><span class="pill pill-{e(st)}">{e(st.upper())}</span></td>'
                      f'<td>{e(c["title"])}</td><td>{e(c["detail"])}</td></tr>')
    counts = d["counts"]
    tiles = "".join(
        f'<div class="tile"><div class="n" style="color:{_SEV_COLORS[k]}">{v}</div><div class="l">{k}</div></div>'
        for k, v in sorted(counts.items(), key=lambda kv: -Severity[kv[0].upper()]))
    host = d["host"]
    plan = _render_plan(action_plan(result), len({f.rule_id for f in result.findings if f.severity >= Severity.LOW}))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="generator" content="Aegis Security Suite">
<title>Aegis Scan Report</title>
<style>
:root{{--bg:#f6f7f9;--card:#fff;--fg:#1d2329;--muted:#5f6b76;--line:#e3e7eb;--code:#f0f2f5}}
@media (prefers-color-scheme: dark){{:root{{--bg:#0f1317;--card:#171c21;--fg:#e6eaee;--muted:#98a4b0;--line:#27303a;--code:#1f262d}}}}
*{{box-sizing:border-box}}body{{margin:0;font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg)}}
main{{max-width:1100px;margin:0 auto;padding:24px 16px}}
header{{display:flex;gap:24px;align-items:center;flex-wrap:wrap}}
.gauge{{width:140px;height:140px;border-radius:50%;display:grid;place-items:center;
background:conic-gradient({ring} calc({score}*1%),var(--line) 0)}}
.gauge div{{width:112px;height:112px;border-radius:50%;background:var(--bg);display:grid;place-items:center;text-align:center}}
.gauge b{{font-size:34px;line-height:1}}.gauge span{{color:var(--muted);font-size:13px}}
h1{{margin:0 0 4px;font-size:24px}}.sub{{color:var(--muted)}}
.tiles{{display:flex;gap:12px;flex-wrap:wrap;margin:20px 0}}
.tile{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 16px;min-width:96px}}
.tile .n{{font-size:26px;font-weight:700}}.tile .l{{color:var(--muted);text-transform:capitalize;font-size:13px}}
section{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin:16px 0}}
h2{{margin:0 0 12px;font-size:18px}}
.filters{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}}
.filters button{{border:1px solid var(--line);background:var(--bg);color:var(--fg);border-radius:20px;padding:4px 12px;cursor:pointer}}
.filters button.on{{background:var(--fg);color:var(--bg)}}
details.finding{{border:1px solid var(--line);border-radius:8px;margin:8px 0;overflow:hidden}}
details.finding summary{{cursor:pointer;padding:10px 12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}}
.badge{{color:#fff;font-size:11px;font-weight:700;padding:2px 8px;border-radius:4px;min-width:70px;text-align:center}}
.sev-medium .badge{{color:#222}}
.title{{font-weight:600;flex:1;min-width:0}}.cat{{color:var(--muted);font-size:13px}}
.where{{display:block;font-weight:400;color:var(--muted);font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.plan ol{{list-style:none;padding:0;margin:0}}.plan li{{display:flex;gap:12px;align-items:flex-start;padding:10px 0;border-bottom:1px solid var(--line)}}
.plan li:last-child{{border-bottom:0}}.plan li>div{{min-width:0;flex:1}}.plan p{{margin:6px 0 0}}.plan .where code{{display:block;margin-top:2px}}
.cnt{{color:var(--muted);font-weight:600}}.fix code{{word-break:break-all}}
#q{{flex:1;min-width:180px;border:1px solid var(--line);background:var(--bg);color:var(--fg);border-radius:20px;padding:4px 12px}}
.body{{padding:0 14px 12px;border-top:1px solid var(--line)}}
code,pre{{background:var(--code);border-radius:4px;font-size:13px}}code{{padding:1px 4px;word-break:break-all}}
pre{{padding:10px;overflow:auto;max-height:300px}}.meta{{color:var(--muted);font-size:12px}}
table{{width:100%;border-collapse:collapse}}td{{padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}}
.pill{{font-size:11px;font-weight:700;padding:2px 8px;border-radius:10px;color:#fff;background:#9aa5b1}}
.pill-pass{{background:#2f9e44}}.pill-fail{{background:#e03131}}.pill-warn{{background:#f59f00}}
footer{{color:var(--muted);font-size:12px;text-align:center;margin:24px 0}}
@media print{{details.finding{{break-inside:avoid}} details.finding[open] summary ~ *{{display:block}} .filters{{display:none}}}}
{_HISTORY_CSS}</style></head><body><main>
<header>
  <div class="gauge"><div><b>{score}</b><span>grade {grade}</span></div></div>
  <div><h1>Aegis Security Report</h1>
  <div class="sub">{e(str(host.get('hostname', '')))} &middot; {e(str(host.get('platform', '')))} &middot; {e(d['profile'])} scan &middot; {e(d['started'])}
  &middot; {e(str(d['stats'].get('duration_s', '?')))}s &middot; admin: {'yes' if host.get('admin') else 'no'}</div>
  <div class="sub">Scanners: {e(', '.join(d['scanners']))}</div></div>
</header>
<div class="tiles">{tiles}</div>
{changes}
{plan}
<section><h2>Findings (<span id="shown">{len(d['findings'])}</span> of {len(d['findings'])})</h2>
<div class="filters" id="filters"><button class="on" data-f="all">All</button>
<button data-f="critical">Critical</button><button data-f="high">High</button><button data-f="medium">Medium</button>
<button data-f="low">Low</button><button data-f="info">Info</button>
<input id="q" type="search" placeholder="Search title, path, rule..." aria-label="Search findings"></div>
{''.join(rows) or '<p>No threats or issues found.</p>'}
</section>
{f'<section><h2>Hardening checks</h2><table>{"".join(checks)}</table></section>' if checks else ''}
{'<section><h2>Errors</h2><ul>' + ''.join(f'<li>{e(x)}</li>' for x in d['errors']) + '</ul></section>' if d['errors'] else ''}
<footer>Generated by {e(__app_name__)} {e(__version__)}. Findings marked "suspicious" are heuristic and may be false positives - verify before deleting.</footer>
</main>
{_REPORT_SCRIPT}</body></html>"""


def render_csv(result: ScanResult) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["severity", "category", "title", "location", "rule_id", "scanner", "recommendation", "mitre", "fingerprint"])
    for f in result.sorted_findings():
        w.writerow([f.severity.name, f.category, f.title, f.location, f.rule_id, f.scanner, f.recommendation,
                    " ".join(f.mitre), f.fingerprint])
    return buf.getvalue()


# --------------------------------------------------------------------------- SARIF 2.1.0
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
PROJECT_URL = "https://github.com/anshnt/security"
RULES_DOC_URL = PROJECT_URL + "/blob/main/docs/RULES.md"
_SARIF_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
                Severity.LOW: "note", Severity.INFO: "note"}
# GitHub code scanning reads `security-severity` (0.1-10) to label alerts critical / high / medium / low.
_SECURITY_SEVERITY = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5", Severity.LOW: "3.0"}
_WIN_ABS = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\[^\\/]+[\\/][^\\/]+)")
_PATH_SPLIT = re.compile(r"[!#]")


def _is_windows_path(p: str) -> bool:
    return bool(_WIN_ABS.match(p))


def _is_file_path(p: str) -> bool:
    return _is_windows_path(p) or (p.startswith("/") and not p.startswith("//"))


def finding_file(f: Finding) -> Optional[str]:
    """The file a finding points at, or None for registry keys, processes, settings, URLs...

    Locations can carry a suffix: ``archive.zip!member.exe`` (archive member) or ``package.json#scripts.postinstall``
    (a key inside the file); the file itself is the part before it."""
    for key in ("file", "path"):
        v = f.evidence.get(key) if isinstance(f.evidence, dict) else None
        if isinstance(v, str) and _is_file_path(v):
            return v
    loc = (f.location or "").strip()
    if not _is_file_path(loc):
        return None
    if _PATH_SPLIT.search(loc) and not os.path.exists(loc):
        head = _PATH_SPLIT.split(loc, 1)[0]
        if head and _is_file_path(head):
            return head
    return loc


def _finding_line(f: Finding) -> Optional[int]:
    ev = f.evidence if isinstance(f.evidence, dict) else {}
    line = ev.get("line")
    if isinstance(line, int) and not isinstance(line, bool) and line > 0:
        return line
    for v in ev.values():  # e.g. secrets: {"keys": [{"kind": ..., "line": 12}]}
        if isinstance(v, list) and v and isinstance(v[0], dict):
            ln = v[0].get("line")
            if isinstance(ln, int) and not isinstance(ln, bool) and ln > 0:
                return ln
    return None


def _file_uri(path: str) -> str:
    pure = PureWindowsPath(path) if _is_windows_path(path) else PurePosixPath(path)
    return pure.as_uri()


def _relative_uri(path: str, base: Optional[str]) -> Optional[str]:
    """`path` relative to `base` as a URI reference ('src/package.json'), or None when it is outside `base`."""
    if not base:
        return None
    win = _is_windows_path(path)
    if win != _is_windows_path(base):
        return None
    pure_cls = PureWindowsPath if win else PurePosixPath
    try:
        rel = pure_cls(path).relative_to(pure_cls(base))  # PureWindowsPath compares case-insensitively
    except ValueError:
        return None
    parts = rel.parts
    return "/".join(urllib.parse.quote(x) for x in parts) if parts else None


def _utc(stamp: str) -> Optional[str]:
    try:
        t = _dt.datetime.fromisoformat(stamp)
    except (TypeError, ValueError):
        return None
    return t.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _rule_help(f: Finding) -> Dict[str, str]:
    text = f.recommendation or f.description or f.title
    md = [text]
    if f.mitre:
        links = ", ".join(f"[{t}](https://attack.mitre.org/techniques/{t.replace('.', '/')}/)" for t in f.mitre)
        md.append(f"MITRE ATT&CK: {links}")
    return {"text": text, "markdown": "\n\n".join(md)}


def render_sarif(result: ScanResult, base_dir: "str | Path | None" = None) -> str:
    """SARIF 2.1.0 for code-scanning dashboards (GitHub code scanning, Azure DevOps, VS Code SARIF viewer).

    Findings on files get an artifact location, relative to ``base_dir`` when they are inside it (so a CI upload
    of `aegis check-project` lines up with the repository), otherwise a ``file://`` URI. Registry keys, processes
    and settings become logical locations. Rule metadata carries the highest severity seen for the rule, the
    category and MITRE ATT&CK tags. Checks that errored are reported as tool notifications."""
    base = str(base_dir) if base_dir else None
    if base and not _is_file_path(base):
        base = os.path.abspath(base)
    findings = result.sorted_findings()
    rules: List[Dict[str, Any]] = []
    index: Dict[str, int] = {}
    worst: Dict[str, Severity] = {}
    for f in findings:
        if f.rule_id not in index:
            index[f.rule_id] = len(rules)
            worst[f.rule_id] = f.severity
            rules.append({
                "id": f.rule_id,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description or f.title},
                "help": _rule_help(f),
                "helpUri": RULES_DOC_URL,
                "properties": {"tags": [], "category": f.category},
            })
        rule = rules[index[f.rule_id]]
        worst[f.rule_id] = max(worst[f.rule_id], f.severity)
        tags = rule["properties"]["tags"]
        for t in ["security", f.category] + [f"external/mitre-attack/{m}" for m in f.mitre]:
            if t and t not in tags:
                tags.append(t)
    for rid, i in index.items():
        sev = worst[rid]
        rules[i]["defaultConfiguration"] = {"level": _SARIF_LEVEL[sev]}
        rules[i]["properties"]["severity"] = sev.name.lower()
        if sev in _SECURITY_SEVERITY:
            rules[i]["properties"]["security-severity"] = _SECURITY_SEVERITY[sev]

    used_base = False
    results: List[Dict[str, Any]] = []
    for f in findings:
        message = f.title if not f.description else f"{f.title}. {f.description}"
        res: Dict[str, Any] = {
            "ruleId": f.rule_id,
            "ruleIndex": index[f.rule_id],
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": message},
            "partialFingerprints": {"aegisFingerprint/v1": f.fingerprint},
            "properties": {"severity": f.severity.name.lower(), "category": f.category, "scanner": f.scanner,
                           "mitre": list(f.mitre), "location": f.location, "recommendation": f.recommendation,
                           "evidence": f.evidence},
        }
        path = finding_file(f)
        if path:
            rel = _relative_uri(path, base)
            art: Dict[str, Any] = {"uri": rel, "uriBaseId": "SRCROOT"} if rel else {"uri": _file_uri(path)}
            used_base = used_base or bool(rel)
            phys: Dict[str, Any] = {"artifactLocation": art}
            line = _finding_line(f)
            if line:
                phys["region"] = {"startLine": line}
            loc: Dict[str, Any] = {"physicalLocation": phys}
            if f.location and f.location != path:
                loc["logicalLocations"] = [{"fullyQualifiedName": f.location, "kind": "member"}]
            res["locations"] = [loc]
        elif f.location:
            res["locations"] = [{"logicalLocations": [{"fullyQualifiedName": f.location, "kind": "resource"}]}]
        results.append(res)

    score, grade = security_score(result)
    invocation: Dict[str, Any] = {"executionSuccessful": True}
    start, end = _utc(result.started), _utc(result.finished)
    if start:
        invocation["startTimeUtc"] = start
    if end:
        invocation["endTimeUtc"] = end
    notes = [{"level": "error", "message": {"text": f"{c.title}: {c.detail}" if c.detail else c.title},
              "descriptor": {"id": c.check_id}} for c in result.checks if c.status == CheckStatus.ERROR]
    if notes:
        invocation["toolExecutionNotifications"] = notes
    run: Dict[str, Any] = {
        "tool": {"driver": {"name": __app_name__, "version": __version__, "semanticVersion": __version__,
                            "informationUri": PROJECT_URL, "rules": rules}},
        "automationDetails": {"id": f"aegis/{result.profile}/"},
        "invocations": [invocation],
        "results": results,
        "properties": {"profile": result.profile, "scanners": list(result.scanners), "score": score, "grade": grade,
                       "counts": result.counts()},
    }
    if used_base and base:
        root = _file_uri(base)
        run["originalUriBaseIds"] = {"SRCROOT": {"uri": root if root.endswith("/") else root + "/"}}
    doc = {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}
    return json.dumps(doc, indent=2, default=str, ensure_ascii=False)


def _is_aegis_sarif(data: bytes) -> bool:
    if b'"version": "2.1.0"' not in data[:400] or SARIF_SCHEMA.encode() not in data[:400]:
        return False
    try:
        d = json.loads(data.decode("utf-8"))
    except ValueError:
        return False
    if not isinstance(d, dict) or d.get("version") != "2.1.0" or not isinstance(d.get("runs"), list) or len(d["runs"]) != 1:
        return False
    run = d["runs"][0]
    driver = run.get("tool", {}).get("driver", {}) if isinstance(run, dict) else {}
    return isinstance(driver, dict) and driver.get("name") == __app_name__ and isinstance(run.get("results"), list)


REPORT_FORMATS = ("html", "json", "csv", "txt", "sarif")


def write_report(result: ScanResult, path: "str | Path", fmt: str = "", base_dir: "str | Path | None" = None) -> Path:
    p = Path(path)
    fmt = (fmt or p.suffix.lstrip(".") or "html").lower()
    renderers: Dict[str, object] = {
        "html": render_html, "htm": render_html, "json": lambda r: r.to_json(), "csv": render_csv,
        "txt": lambda r: render_text(r, color=False, verbose=True, min_severity=Severity.INFO),
        "sarif": lambda r: render_sarif(r, base_dir),
    }
    if fmt not in renderers:
        raise ValueError(f"unsupported report format {fmt!r} ({', '.join(REPORT_FORMATS)})")
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8", newline="\n") as fh:  # identical bytes on every OS
        fh.write(renderers[fmt](result))  # type: ignore[operator]
    return p


def finding_by_fingerprint(result: ScanResult, fp: str) -> Finding:
    for f in result.findings:
        if f.fingerprint.startswith(fp.lower()):
            return f
    raise KeyError(fp)


def is_aegis_report(data: bytes, ext: str) -> bool:
    """True if `data` is a report Aegis itself wrote. Reports quote the malicious
    strings they found as evidence, so without this a saved report would be
    flagged by the next scan. Validation is strict so the generator marker alone
    cannot be used to smuggle malicious HTML/JSON past the scanner."""
    if len(data) > 64 * 1024 * 1024:
        return False
    data = data.replace(b"\r\n", b"\n")  # tolerate reports re-saved with Windows line endings
    if ext == "sarif":
        return _is_aegis_sarif(data)
    if ext == "json":
        if b'"generator": "Aegis Security Suite"' not in data[:200]:
            return _is_aegis_sarif(data)  # results.sarif.json
        try:
            d = json.loads(data.decode("utf-8"))
        except ValueError:
            return False
        return isinstance(d, dict) and d.get("generator") == "Aegis Security Suite" and \
            isinstance(d.get("findings"), list) and "score" in d and "scanners" in d
    if ext in ("html", "htm"):
        if b'<meta name="generator" content="Aegis Security Suite">' not in data[:1024]:
            return False
        low = data.lower()
        # Everything Aegis renders is HTML-escaped: the only active content is its own filter script.
        if low.count(b"<script") != 1 or _REPORT_SCRIPT.encode() not in data:
            return False
        return not any(t in low for t in (b"<iframe", b"<form", b"<object", b"<embed", b" onload=", b" onerror=",
                                          b"javascript:", b"http-equiv"))
    if ext == "csv":
        return data.startswith(b"severity,category,title,location,rule_id,scanner,recommendation,mitre,fingerprint")
    return False
