"""HTML / text report usability: the "What to do first" action plan, locations on finding rows, the search box,
and that the report is still recognised as Aegis's own output by the file scanner."""

import re

from aegis.core.models import Finding, Remediation, ScanResult, Severity
from aegis.core.report import MAX_PLAN_IDS, action_plan, is_aegis_report, render_html, render_text


def _f(rule, title, sev, loc, fix=True, rec="Quarantine it."):
    return Finding(rule, title, sev, "malware", "desc", loc, {}, rec,
                   Remediation("quarantine_file", {"path": loc}) if fix else None)


def _result(*fs):
    r = ScanResult(profile="quick", host={"hostname": "h"})
    for f in fs:
        r.add(f)
    return r


def test_plan_groups_by_rule_and_orders_by_severity_then_count():
    r = _result(_f("R-HIGH", "Bad script", Severity.HIGH, "/a"), _f("R-HIGH", "Bad script", Severity.HIGH, "/b"),
                _f("R-HIGH", "Bad script", Severity.HIGH, "/c"), _f("R-CRIT", "Known malware", Severity.CRITICAL, "/x"),
                _f("R-HIGH2", "Other", Severity.HIGH, "/d"), _f("R-INFO", "Inventory", Severity.INFO, "/i"))
    plan = action_plan(r)
    assert [(p["title"], p["count"]) for p in plan] == [("Known malware", 1), ("Bad script", 3), ("Other", 1)]
    assert plan[1]["locations"] == ["/a", "/b", "/c"] and plan[1]["recommendation"] == "Quarantine it."
    assert plan[1]["fix"] == "aegis fix " + " ".join(f"--id {f.fingerprint}" for f in r.findings if f.rule_id == "R-HIGH")
    assert all(p["severity"] != "info" for p in plan)  # inventories are not actions
    assert len(action_plan(r, limit=1)) == 1


def test_plan_titles_fixability_and_many_fixes():
    r = _result(_f("R", "Update available for Chrome", Severity.MEDIUM, "u:1"),
                _f("R", "Update available for Edge", Severity.MEDIUM, "u:2", fix=False),
                *(_f("M", "Mimikatz", Severity.CRITICAL, f"/m{i}") for i in range(MAX_PLAN_IDS + 1)))
    plan = {p["title"].split(" (")[0]: p for p in action_plan(r)}
    upd = plan["Update available for Chrome"]
    assert upd["title"].endswith("(+ 1 similar)") and upd["fixable"] == 1 and upd["fix"].count("--id") == 1
    many = plan["Mimikatz"]
    assert many["fixable"] == MAX_PLAN_IDS + 1 and many["fix"] == "aegis fix"  # never a severity-wide fix for one group
    nofix = action_plan(_result(_f("N", "Setting", Severity.LOW, "x", fix=False)))
    assert nofix[0]["fix"] == "" and nofix[0]["fixable"] == 0


def test_html_has_plan_locations_search_and_stays_recognisable():
    r = _result(_f("R-CRIT", "Known malware", Severity.CRITICAL, "C:\\Users\\bob\\Downloads\\evil.exe"),
                _f("R-HIGH", "Bad <script>", Severity.HIGH, "/very/" + "long/" * 40 + "path.ps1"))
    html = render_html(r)
    assert "What to do first" in html and html.index("What to do first") < html.index('id="filters"')
    assert '<input id="q" type="search"' in html and 'id="shown">2</span> of 2' in html
    assert 'class="where">C:\\Users\\bob\\Downloads\\evil.exe</small>' in html
    assert "\u2026" in html and "Bad &lt;script&gt;" in html and "Bad <script>" not in html  # shortened + escaped
    assert html.lower().count("<script") == 1 and is_aegis_report(html.encode("utf-8"), "html")
    assert "What to do first" not in render_html(_result())


def test_text_report_shows_the_plan_only_when_it_helps():
    r = _result(_f("R-CRIT", "Known malware", Severity.CRITICAL, "/x"), _f("R-HIGH", "Bad script", Severity.HIGH, "/a"))
    text = render_text(r)
    assert "What to do first:" in text and re.search(r"1\. CRITICAL Known malware\s+->\s+aegis fix --id \w+", text)
    assert text.index("What to do first:") < text.index("at: /x")
    single = render_text(_result(_f("R-CRIT", "Known malware", Severity.CRITICAL, "/x")))
    assert "What to do first:" not in single  # one kind of issue: the list itself is the plan
