"""Report rendering: coloured console text, self-contained HTML, JSON and CSV."""

from __future__ import annotations

import csv
import html
import io
import json
from pathlib import Path
from typing import Dict, List

from aegis import __app_name__, __version__
from aegis.core.models import CheckStatus, Finding, ScanResult, Severity
from aegis.core.scoring import security_score

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
    if not result.host.get("admin"):
        w(_c("Note: not running as Administrator/root - some checks were limited.", _DIM, color))
    w("")

    shown = [f for f in result.sorted_findings() if f.severity >= min_severity]
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
document.getElementById('filters').addEventListener('click',function(ev){
  var b=ev.target.closest('button'); if(!b) return;
  document.querySelectorAll('#filters button').forEach(function(x){x.classList.toggle('on',x===b)});
  var f=b.dataset.f;
  document.querySelectorAll('details.finding').forEach(function(d){d.style.display=(f==='all'||d.dataset.sev===f)?'':'none'});
});
</script>"""

_SEV_COLORS = {"critical": "#b3261e", "high": "#e8590c", "medium": "#f2c94c", "low": "#4dabf7", "info": "#9aa5b1"}


def render_html(result: ScanResult) -> str:
    d = result.to_dict()
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
    <span class="title">{e(f['title'])}</span><span class="cat">{e(f['category'])}</span></summary>
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
.title{{font-weight:600;flex:1}}.cat{{color:var(--muted);font-size:13px}}
.body{{padding:0 14px 12px;border-top:1px solid var(--line)}}
code,pre{{background:var(--code);border-radius:4px;font-size:13px}}code{{padding:1px 4px;word-break:break-all}}
pre{{padding:10px;overflow:auto;max-height:300px}}.meta{{color:var(--muted);font-size:12px}}
table{{width:100%;border-collapse:collapse}}td{{padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}}
.pill{{font-size:11px;font-weight:700;padding:2px 8px;border-radius:10px;color:#fff;background:#9aa5b1}}
.pill-pass{{background:#2f9e44}}.pill-fail{{background:#e03131}}.pill-warn{{background:#f59f00}}
footer{{color:var(--muted);font-size:12px;text-align:center;margin:24px 0}}
@media print{{details.finding{{break-inside:avoid}} details.finding[open] summary ~ *{{display:block}} .filters{{display:none}}}}
</style></head><body><main>
<header>
  <div class="gauge"><div><b>{score}</b><span>grade {grade}</span></div></div>
  <div><h1>Aegis Security Report</h1>
  <div class="sub">{e(str(host.get('hostname', '')))} &middot; {e(str(host.get('platform', '')))} &middot; {e(d['profile'])} scan &middot; {e(d['started'])}
  &middot; {e(str(d['stats'].get('duration_s', '?')))}s &middot; admin: {'yes' if host.get('admin') else 'no'}</div>
  <div class="sub">Scanners: {e(', '.join(d['scanners']))}</div></div>
</header>
<div class="tiles">{tiles}</div>
<section><h2>Findings ({len(d['findings'])})</h2>
<div class="filters" id="filters"><button class="on" data-f="all">All</button>
<button data-f="critical">Critical</button><button data-f="high">High</button><button data-f="medium">Medium</button>
<button data-f="low">Low</button><button data-f="info">Info</button></div>
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


def write_report(result: ScanResult, path: "str | Path", fmt: str = "") -> Path:
    p = Path(path)
    fmt = (fmt or p.suffix.lstrip(".") or "html").lower()
    renderers: Dict[str, object] = {
        "html": render_html, "htm": render_html, "json": lambda r: r.to_json(), "csv": render_csv,
        "txt": lambda r: render_text(r, color=False, verbose=True, min_severity=Severity.INFO),
    }
    if fmt not in renderers:
        raise ValueError(f"unsupported report format {fmt!r} (html, json, csv, txt)")
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
    if ext == "json":
        if b'"generator": "Aegis Security Suite"' not in data[:200]:
            return False
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
