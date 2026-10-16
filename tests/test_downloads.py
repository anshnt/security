"""Tests for aegis.scanners.downloads: the folder walk (depth, age, entry cap, links, cancel, time budget), the feed checker, the
finding builder, the scanner over a temporary Downloads / Desktop tree (origins injected, so it runs the same on Linux and
Windows), the Windows Attachment Manager policy audit through a monkeypatched registry reader, and an end-to-end run that
records a genuine origin on the file system (an alternate data stream on Windows, an extended attribute on Linux) and lets the
scanner read it back. Nothing here reads the real Downloads folder except the one test that says so."""

import json
import os
import re
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from aegis.core import provenance as prov
from aegis.core.models import Category, CheckResult, CheckStatus, Finding, Remediation, Severity
from aegis.core.provenance import Origin
from aegis.scanners import downloads as dl
from aegis.scanners.base import REGISTRY, load_all

IP = "45.9.148.10"  # a public address (the documentation ranges count as private)
RLO = "\u202e"
POLICY_RULES = {"AEG-DL-MOTW-OFF", "AEG-DL-AVSCAN-OFF"}


def split(out):
    out = list(out)
    return [x for x in out if isinstance(x, Finding)], [x for x in out if isinstance(x, CheckResult)]


def reviewed(findings):
    """The findings of the folder review (the policy findings are Windows registry audits)."""
    return [f for f in findings if f.rule_id not in POLICY_RULES]


def make(folder, name, age_days=1.0, size=64):
    path = Path(folder) / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"MZ" + b"\0" * size)
    stamp = time.time() - age_days * 86400
    os.utime(path, (stamp, stamp))
    return path


def zone(host_url="", referrer_url=""):
    return Origin(3, host_url, referrer_url, "", "zone.identifier")


@pytest.fixture
def home(tmp_path, monkeypatch):
    folder = tmp_path / "home"
    (folder / "Downloads").mkdir(parents=True)
    monkeypatch.setattr(dl, "user_home", lambda: folder)
    monkeypatch.setattr(dl, "IS_WINDOWS", False)
    return folder


@pytest.fixture
def origins(monkeypatch):
    """Stand-in for read_origin: {file name: Origin}; every other file has no recorded origin."""
    table = {}
    monkeypatch.setattr(dl, "read_origin", lambda path: table.get(Path(path).name))
    return table


def checks_by_id(checks):
    return {c.check_id: c for c in checks}


# =========================================================================== types
def test_risky_types_cover_the_requested_list():
    wanted = ("exe msi msix msixbundle appx appxbundle appinstaller scr com pif cpl bat cmd ps1 psm1 vbs vbe js jse wsf wsh hta "
              "lnk url library-ms search-ms iso img vhd vhdx dmg pkg mpkg sh run appimage deb rpm jar zip rar 7z docm xlsm pptm "
              "one chm reg application").split()
    assert set(wanted) == dl.RISKY_EXTS and len(wanted) == len(dl.RISKY_EXTS)
    for harmless in ("txt", "pdf", "png", "docx", "xlsx", "mp4", "py", "gz", "json", "html"):
        assert harmless not in dl.RISKY_EXTS


def test_every_type_the_classifier_reasons_about_is_reviewed():
    assert (prov.SMUGGLED_EXTS | prov.SHARE_EXTS | prov.DISGUISED_EXTS | prov.EXECUTABLE_EXTS) <= dl.RISKY_EXTS


@pytest.mark.parametrize("ext,kind", [("exe", "program or installer"), ("ps1", "script"), ("lnk", "shortcut"),
                                      ("iso", "disk image or archive"), ("docm", "file"), ("", "file")])
def test_file_kind(ext, kind):
    assert dl.file_kind(ext) == kind


# =========================================================================== folder walk
def walk(roots, since=0.0, deadline=None, cancelled=lambda: False, **kw):
    return dl.walk_downloads(roots, since, time.monotonic() + 60 if deadline is None else deadline, cancelled, **kw)


def names(w):
    return sorted(p.name for p, _ in w.files)


def test_walk_depth_age_and_type(tmp_path):
    root = tmp_path / "Downloads"
    make(root, "top.exe")
    make(root, "level1/one.msi")
    make(root, "level1/level2/two.zip")
    make(root, "level1/level2/level3/three.exe")  # too deep
    make(root, "old.exe", age_days=200)
    make(root, "notes.txt")
    make(root, "photo.JPG")
    make(root, "UPPER.EXE")
    since = time.time() - 90 * 86400
    w = walk([root], since)
    assert names(w) == ["UPPER.EXE", "one.msi", "top.exe", "two.zip"]
    assert w.notes == [] and w.entries >= 9
    assert names(walk([root], 0.0)) == ["UPPER.EXE", "old.exe", "one.msi", "top.exe", "two.zip"]


def test_walk_reports_every_root_and_skips_unreadable_ones(tmp_path):
    downloads, desktop = tmp_path / "Downloads", tmp_path / "Desktop"
    make(downloads, "a.exe")
    make(desktop, "b.lnk")
    assert names(walk([downloads, desktop])) == ["a.exe", "b.lnk"]
    assert names(walk([tmp_path / "missing", downloads])) == ["a.exe"]
    assert names(walk([downloads / "a.exe"])) == []  # a file is not a folder


def test_walk_never_follows_links(tmp_path):
    root, elsewhere = tmp_path / "Downloads", tmp_path / "elsewhere"
    make(elsewhere, "inside.exe")
    root.mkdir()
    make(root, "real.exe")
    try:
        os.symlink(elsewhere / "inside.exe", root / "link.exe")
        os.symlink(elsewhere, root / "linked-folder", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("this account cannot create symbolic links")
    assert names(walk([root])) == ["real.exe"]


def test_walk_stops_at_the_entry_cap_with_the_top_level_first(tmp_path):
    root = tmp_path / "Downloads"
    for n in range(6):
        make(root, f"top{n}.exe")
    for n in range(20):
        make(root, f"sub/deep{n}.exe")
    w = walk([root], max_entries=7)  # the six files and the sub-folder, and not one entry more
    assert w.entries == 7 and len(w.files) == 6 and all(name.startswith("top") for name in names(w))  # breadth first
    assert w.notes and "limit of 7 entries" in w.notes[0]
    assert walk([root], max_entries=27).notes == [] and walk([root], max_entries=1000).entries == 27


def test_walk_stops_when_the_budget_is_spent_or_the_scan_is_cancelled(tmp_path):
    root = tmp_path / "Downloads"
    make(root, "a.exe")
    late = walk([root], deadline=time.monotonic() - 1)
    assert late.files == [] and "time budget" in late.notes[0]
    gone = walk([root], cancelled=lambda: True)
    assert gone.files == [] and gone.notes == []


# =========================================================================== feed
def test_feed_checker_needs_a_feed():
    assert dl.feed_checker(SimpleNamespace(bad_domains=set(), bad_ips=set(), bad_networks=[])) is None
    assert dl.feed_checker(SimpleNamespace()) is None


def test_feed_checker_looks_up_domains_and_addresses(ctx):
    ctx.signatures.bad_domains.update({"evil.example", "203.0.113.9"})
    ctx.signatures.bad_ips.add("198.51.100.7")
    is_bad = dl.feed_checker(ctx.signatures)
    assert is_bad("evil.example") and is_bad("cdn.evil.example") and not is_bad("good.example") and not is_bad("notevil.example")
    assert is_bad("198.51.100.7") and is_bad("203.0.113.9")  # the URLhaus list names servers by address
    assert not is_bad("198.51.100.8")
    assert not is_bad("2606:4700:4700::1111")
    only_ips = SimpleNamespace(bad_domains=set(), bad_ips={"198.51.100.7"}, bad_networks=[],
                               is_bad_ip=lambda ip: ip == "198.51.100.7", is_bad_domain=lambda d: False)
    assert dl.feed_checker(only_ips)("198.51.100.7")


# =========================================================================== finding builder
def stat_of(path):
    return os.stat(path)


def test_finding_for_a_high_reason_offers_quarantine(tmp_path):
    f = make(tmp_path, "Invoice.pdf.exe")
    o = Origin(3, "https://cdn.example/x/Invoice.pdf.exe?X-Amz-Signature=SECRETSIG#frag",
               "https://page.example/dl?session=SECRETSESSION", "", "zone.identifier")
    finding = dl.download_finding(f, stat_of(f), o, prov.classify_download(f.name, o))
    assert finding.rule_id == "AEG-DL-DECEPTIVE" and finding.severity == Severity.HIGH and finding.category == Category.SUSPICIOUS
    assert finding.scanner == "downloads" and finding.location == str(f) and finding.title.endswith("Invoice.pdf.exe")
    assert finding.remediation == Remediation("quarantine_file", {"path": str(f)},
                                              "Move the file to quarantine (it can be restored)")
    assert finding.mitre == ["T1036.007"]
    ev = finding.evidence
    assert ev["path"] == str(f) and ev["file"] == "Invoice.pdf.exe"
    assert ev["origin_source"] == "zone.identifier" and ev["zone"] == 3
    assert ev["host_url"] == "https://cdn.example/x/Invoice.pdf.exe" and ev["referrer_url"] == "https://page.example/dl"
    assert ev["agent"] == "" and ev["size"] == 66 and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d", ev["modified"])
    assert ev["rules"] == ["AEG-DL-DECEPTIVE"] and len(ev["reasons"]) == 1
    blob = json.dumps(finding.to_dict())
    assert "SECRETSIG" not in blob and "SECRETSESSION" not in blob
    for phrase in ("not proof", "double extension", "Windows marked it"):
        assert phrase in finding.description
    assert "https://cdn.example/x/Invoice.pdf.exe" in finding.description
    assert "Quarantine" in finding.recommendation and "restored" in finding.recommendation


def test_finding_for_lower_severities_has_no_fix_and_merges_the_reasons(tmp_path):
    f = make(tmp_path, "tool.exe")
    o = Origin(None, f"http://{IP}/tool.exe", "", "Safari", "quarantine")
    finding = dl.download_finding(f, stat_of(f), o, prov.classify_download(f.name, o))
    assert (finding.rule_id, finding.severity) == ("AEG-DL-RAWIP", Severity.MEDIUM) and finding.remediation is None
    assert finding.evidence["rules"] == ["AEG-DL-RAWIP", "AEG-DL-INSECURE"] and finding.evidence["agent"] == "Safari"
    assert finding.mitre == ["T1105"] and "by Safari" in finding.description and "macOS" in finding.description
    assert "bare IP address" in finding.description and "plain http://" in finding.description
    assert finding.recommendation.startswith("Run it only if")


@pytest.mark.parametrize("host_url,rule,severity", [
    ("https://dl.evil.example/a.exe", "AEG-DL-BADSOURCE", Severity.HIGH),
    ("blob:https://page.example/uuid", "AEG-DL-SMUGGLED", Severity.MEDIUM),
    ("\\\\evil.example@SSL\\DavWWWRoot\\a.exe", "AEG-DL-WEBDAV", Severity.MEDIUM),
    (f"https://{IP}/a.exe", "AEG-DL-RAWIP", Severity.MEDIUM),
    ("https://pastebin.com/a.exe", "AEG-DL-FILEHOST", Severity.LOW),
    ("http://vendor.example/a.exe", "AEG-DL-INSECURE", Severity.LOW),
])
def test_every_rule_gets_its_own_title(tmp_path, host_url, rule, severity):
    f = make(tmp_path, "a.exe")
    o = zone(host_url)
    reasons = prov.classify_download(f.name, o, lambda host: host == "dl.evil.example")
    finding = dl.download_finding(f, stat_of(f), o, reasons)
    assert (finding.rule_id, finding.severity) == (rule, severity) and finding.title.endswith("a.exe")
    assert finding.title != dl._title("AEG-DL-OTHER", "a.exe")
    assert (finding.remediation is not None) is (severity >= Severity.HIGH)


def test_finding_for_a_name_without_an_origin(tmp_path):
    f = make(tmp_path, "scan.pdf.js")
    finding = dl.download_finding(f, stat_of(f), None, prov.classify_download(f.name, None))
    assert finding.evidence["origin_source"] == "" and finding.evidence["host_url"] == "" and finding.evidence["zone"] is None
    assert "no recorded origin" in finding.description


def test_a_direction_override_in_a_name_cannot_flip_the_report(tmp_path):
    try:
        f = make(tmp_path, "invoice_" + RLO + "fdp.exe")
    except OSError:
        pytest.skip("this file system rejects the name")
    finding = dl.download_finding(f, stat_of(f), None, prov.classify_download(f.name, None))
    assert finding.rule_id == "AEG-DL-DECEPTIVE"
    for shown in (finding.title, finding.description, finding.location, finding.evidence["file"]):
        assert RLO not in shown and "<U+202E>" in shown
    assert RLO in finding.evidence["path"] and RLO in finding.remediation.params["path"]  # the fix still names the real file
    assert finding.mitre == ["T1036.002"]


# =========================================================================== provenance check wording
def test_provenance_check_wording():
    ok = dl.provenance_check(3, 2, 0, [], [], True)
    assert (ok.check_id, ok.title, ok.status, ok.scanner) == (
        "AEG-DL-CHK-PROVENANCE", "Downloaded programs come from safe places", CheckStatus.PASS, "downloads")
    assert ok.detail == "3 risky downloads reviewed, 2 with a recorded origin."
    assert dl.provenance_check(1, 1, 0, [], [], True).detail == "1 risky download reviewed, 1 with a recorded origin."
    assert dl.provenance_check(0, 0, 0, [], [], True).detail == "0 risky downloads reviewed, 0 with a recorded origin."
    bad = dl.provenance_check(9, 4, 7, ["a.exe", "b.exe", "c.exe", "d.exe", "e.exe"], ["the limit was reached"], False)
    assert bad.status == CheckStatus.FAIL and "7 look suspicious: a.exe, b.exe, c.exe, d.exe, e.exe, ..." in bad.detail
    assert "no threat feed is loaded" in bad.detail and bad.detail.endswith("The limit was reached.")
    one = dl.provenance_check(2, 1, 1, ["a.exe"], [], True)
    assert "1 looks suspicious: a.exe." in one.detail and "..." not in one.detail


# =========================================================================== scanner over a Downloads tree
def fake_world(home, origins):
    downloads, desktop = home / "Downloads", home / "Desktop"
    make(downloads, "setup.exe")  # known-malicious host
    origins["setup.exe"] = zone("https://dl.evil.example/files/setup.exe?token=SECRETTOKEN",
                                "https://landing.example/page?id=SECRETID")
    make(downloads, "Invoice.pdf.exe")  # deceptive name, no origin
    make(downloads, "game.iso")
    origins["game.iso"] = zone("blob:https://warez.example/6f0e1d2c-aaaa-bbbb-cccc-123456789abc", "https://warez.example/")
    make(downloads, "cli.exe")
    origins["cli.exe"] = zone(f"https://{IP}/cli.exe")
    make(downloads, "dropper.js")
    origins["dropper.js"] = zone("https://pastebin.com/raw/abcd1234", "https://pastebin.com/abcd1234")
    make(downloads, "legacy.msi")
    origins["legacy.msi"] = zone("http://vendor.example/legacy.msi", "http://vendor.example/")
    make(downloads, "share.lnk")
    origins["share.lnk"] = zone("\\\\evil2.example@SSL\\DavWWWRoot\\share.lnk")
    make(downloads, "clean.exe")
    origins["clean.exe"] = zone("https://vendor.example/clean.exe", "https://vendor.example/download")
    make(downloads, "notes.txt")
    origins["notes.txt"] = zone(f"http://{IP}/notes.txt")  # not a risky type: never read
    make(downloads, "old.exe", age_days=200)
    origins["old.exe"] = zone(f"http://{IP}/old.exe")  # too old
    make(downloads, "pack/nested/deep.zip")
    origins["deep.zip"] = zone("blob:https://warez.example/x")  # two levels down: reviewed
    make(downloads, "pack/nested/level3/too-deep.exe")
    origins["too-deep.exe"] = zone(f"http://{IP}/too-deep.exe")  # three levels down: not reviewed
    make(desktop, "App.lnk")  # a shortcut with no origin
    return downloads, desktop


def test_scanner_reports_one_finding_per_risky_download(ctx, home, origins):
    ctx.signatures.bad_domains.add("evil.example")
    fake_world(home, origins)
    findings, checks = split(dl.DownloadsScanner().run(ctx))
    got = {Path(f.evidence["path"]).name: (f.rule_id, f.severity.name) for f in findings}
    assert got == {
        "setup.exe": ("AEG-DL-BADSOURCE", "HIGH"),
        "Invoice.pdf.exe": ("AEG-DL-DECEPTIVE", "HIGH"),
        "game.iso": ("AEG-DL-SMUGGLED", "MEDIUM"),
        "deep.zip": ("AEG-DL-SMUGGLED", "MEDIUM"),
        "cli.exe": ("AEG-DL-RAWIP", "MEDIUM"),
        "share.lnk": ("AEG-DL-WEBDAV", "MEDIUM"),
        "dropper.js": ("AEG-DL-FILEHOST", "LOW"),
        "legacy.msi": ("AEG-DL-INSECURE", "LOW"),
    }
    assert len(findings) == 8
    for f in findings:
        assert f.title and f.description and f.location and f.evidence and f.recommendation and f.mitre, f.rule_id
        assert f.scanner == "downloads" and f.category == Category.SUSPICIOUS and f.location == f.evidence["path"]
        assert (f.remediation is not None) is (f.severity == Severity.HIGH)
        if f.remediation:
            assert f.remediation.action == "quarantine_file" and f.remediation.params == {"path": f.evidence["path"]}
        for key in ("path", "file", "origin_source", "zone", "host_url", "referrer_url", "agent", "modified"):
            assert key in f.evidence
        json.dumps(f.to_dict())
    assert len({f.fingerprint for f in findings}) == 8
    blob = json.dumps([f.to_dict() for f in findings] + [c.to_dict() for c in checks])
    assert "SECRETTOKEN" not in blob and "SECRETID" not in blob
    (check,) = checks
    assert check.check_id == "AEG-DL-CHK-PROVENANCE" and check.status == CheckStatus.FAIL and check.scanner == "downloads"
    assert "10 risky downloads reviewed, 8 with a recorded origin" in check.detail and "8 look suspicious" in check.detail
    assert (ctx.stats["downloads_reviewed"], ctx.stats["downloads_with_origin"], ctx.stats["downloads_flagged"]) == (10, 8, 8)


def test_scanner_passes_when_everything_comes_from_safe_places(ctx, home, origins):
    ctx.signatures.bad_domains.add("evil.example")
    make(home / "Downloads", "installer.exe")
    origins["installer.exe"] = zone("https://vendor.example/installer.exe", "https://vendor.example/")
    make(home / "Downloads", "bundle.zip")
    origins["bundle.zip"] = zone("https://github.com/o/r/releases/download/v1/bundle.zip", "https://github.com/o/r/releases")
    make(home / "Downloads", "setup-1.2.3.exe")  # no recorded origin
    make(home / "Downloads", "readme.txt")
    findings, checks = split(dl.DownloadsScanner().run(ctx))
    assert findings == []
    (check,) = checks
    assert check.status == CheckStatus.PASS and check.detail == "3 risky downloads reviewed, 2 with a recorded origin."


def test_scanner_says_so_when_no_threat_feed_is_loaded(ctx, home, origins):
    make(home / "Downloads", "a.exe")
    origins["a.exe"] = zone("https://vendor.example/a.exe")
    (check,) = split(dl.DownloadsScanner().run(ctx))[1]
    assert check.status == CheckStatus.PASS and "no threat feed is loaded" in check.detail and "aegis update" in check.detail
    ctx.signatures.bad_domains.add("evil.example")
    (check,) = split(dl.DownloadsScanner().run(ctx))[1]
    assert "no threat feed" not in check.detail
    only_ips = SimpleNamespace(bad_domains=set(), bad_ips={IP}, bad_networks=[], is_bad_ip=lambda ip: ip == IP,
                               is_bad_domain=lambda d: False)
    ctx.signatures = only_ips
    origins["a.exe"] = zone(f"https://{IP}/a.exe")
    findings, (check,) = split(dl.DownloadsScanner().run(ctx))
    assert [f.rule_id for f in findings] == ["AEG-DL-BADSOURCE"]
    assert "no threat feed" not in check.detail  # an IP feed alone is a feed


def test_scanner_skips_without_a_downloads_folder(ctx, tmp_path, monkeypatch):
    empty = tmp_path / "empty-home"
    empty.mkdir()
    monkeypatch.setattr(dl, "user_home", lambda: empty)
    monkeypatch.setattr(dl, "IS_WINDOWS", False)
    findings, (check,) = split(dl.DownloadsScanner().run(ctx))
    assert findings == [] and check.status == CheckStatus.SKIP and "no Downloads folder" in check.detail
    assert check.check_id == "AEG-DL-CHK-PROVENANCE"


def test_scanner_reviews_the_desktop_when_there_is_no_downloads_folder(ctx, tmp_path, monkeypatch, origins):
    desktop_only = tmp_path / "home2"
    make(desktop_only / "Desktop", "setup.exe")
    origins["setup.exe"] = zone(f"https://{IP}/setup.exe")
    monkeypatch.setattr(dl, "user_home", lambda: desktop_only)
    monkeypatch.setattr(dl, "IS_WINDOWS", False)
    findings, (check,) = split(dl.DownloadsScanner().run(ctx))
    assert [f.rule_id for f in findings] == ["AEG-DL-RAWIP"] and check.status == CheckStatus.FAIL


def test_the_days_option_sets_the_window(ctx, home, origins):
    make(home / "Downloads", "week.exe", age_days=8)
    make(home / "Downloads", "quarter.exe", age_days=100)
    for name in ("week.exe", "quarter.exe"):
        origins[name] = zone(f"https://{IP}/{name}")
    default = split(dl.DownloadsScanner().run(ctx))[0]
    assert [Path(f.evidence["path"]).name for f in default] == ["week.exe"]
    ctx.options["downloads_days"] = 7
    assert split(dl.DownloadsScanner().run(ctx))[0] == []
    ctx.options["downloads_days"] = 120
    wide = split(dl.DownloadsScanner().run(ctx))[0]
    assert sorted(Path(f.evidence["path"]).name for f in wide) == ["quarter.exe", "week.exe"]
    ctx.options["downloads_days"] = 0  # 0 or None mean the default, as for the other scanners
    assert len(split(dl.DownloadsScanner().run(ctx))[0]) == 1


def test_the_budget_option_is_honoured(ctx, home, origins):
    make(home / "Downloads", "a.exe")
    origins["a.exe"] = zone(f"https://{IP}/a.exe")
    ctx.options["downloads_budget_s"] = -1  # a budget that is already spent
    findings, (check,) = split(dl.DownloadsScanner().run(ctx))
    assert findings == [] and "time budget was reached" in check.detail and "0 risky downloads reviewed" in check.detail


def test_the_budget_also_ends_the_origin_reading(ctx, home, monkeypatch):
    clock = {"now": 0.0}
    monkeypatch.setattr(dl, "time", SimpleNamespace(monotonic=lambda: clock["now"], time=time.time))
    for name in ("a.exe", "b.exe", "c.exe"):
        make(home / "Downloads", name)

    def slow_read(path):
        clock["now"] += 100.0  # the first read uses up the budget
        return zone(f"https://{IP}/x.exe")

    monkeypatch.setattr(dl, "read_origin", slow_read)
    ctx.options["downloads_budget_s"] = 50
    findings, (check,) = split(dl.DownloadsScanner().run(ctx))
    assert len(findings) == 1 and "1 risky download reviewed" in check.detail
    assert "remaining files were not examined" in check.detail


def test_findings_are_capped_but_the_check_counts_them_all(ctx, home, monkeypatch):
    monkeypatch.setattr(dl, "MAX_FINDINGS", 2)
    for n in range(5):
        make(home / "Downloads", f"doc{n}.pdf.exe")
    findings, (check,) = split(dl.DownloadsScanner().run(ctx))
    assert len(findings) == 2 and check.status == CheckStatus.FAIL
    assert "5 look suspicious" in check.detail and "Only the first 2 findings are reported" in check.detail
    assert ctx.stats["downloads_flagged"] == 5


def test_a_failing_origin_read_does_not_stop_the_review(ctx, home, monkeypatch):
    make(home / "Downloads", "a.pdf.exe")
    make(home / "Downloads", "b.pdf.exe")

    def boom(path):
        raise RuntimeError("file system exploded")

    monkeypatch.setattr(dl, "read_origin", boom)
    findings, (check,) = split(dl.DownloadsScanner().run(ctx))
    assert sorted(f.rule_id for f in findings) == ["AEG-DL-DECEPTIVE"] * 2 and check.status == CheckStatus.FAIL


def test_a_crash_in_the_review_becomes_an_error_check(ctx, home, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("walk exploded")

    monkeypatch.setattr(dl, "walk_downloads", boom)
    findings, (check,) = split(dl.DownloadsScanner().run(ctx))
    assert findings == [] and check.status == CheckStatus.ERROR and "RuntimeError: walk exploded" in check.detail
    assert check.check_id == "AEG-DL-CHK-PROVENANCE" and check.category == Category.SUSPICIOUS and check.scanner == "downloads"


def test_scanner_stops_when_cancelled(ctx, home, origins, monkeypatch):
    fake_world(home, origins)
    ctx.progress = lambda scanner, msg: ctx.cancel.set() if msg.startswith("listing") else None
    assert list(dl.DownloadsScanner().run(ctx)) == []  # no half-finished check result either

    ctx.cancel.clear()
    ctx.progress = None
    for stale in list((home / "Downloads").rglob("*")):
        if stale.is_file():
            stale.unlink()
    make(home / "Downloads", "a.exe")
    make(home / "Downloads", "b.exe")
    calls = []

    def read_then_cancel(path):
        calls.append(path)
        ctx.cancel.set()
        return zone(f"https://{IP}/a.exe")

    monkeypatch.setattr(dl, "read_origin", read_then_cancel)
    out = list(dl.DownloadsScanner().run(ctx))
    assert len(calls) == 1 and len(out) == 1 and isinstance(out[0], Finding)  # the file read before the cancel, no check result


def test_scanner_reports_progress(ctx, home, origins):
    make(home / "Downloads", "a.exe")
    messages = []
    ctx.progress = lambda scanner, msg: messages.append((scanner, msg))
    list(dl.DownloadsScanner().run(ctx))
    assert ("downloads", "reviewing where recent downloads came from") in messages
    assert ("downloads", "listing recent downloads") in messages


def test_scanner_never_reads_file_content(ctx, home, origins, monkeypatch):
    f = make(home / "Downloads", "a.pdf.exe")
    origins["a.pdf.exe"] = zone(f"https://{IP}/a.exe")
    real_open = open

    def guarded_open(file, *args, **kwargs):
        assert Path(str(file)) != f, "the file itself must not be opened"
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr("builtins.open", guarded_open)
    findings, _ = split(dl.DownloadsScanner().run(ctx))
    assert [x.rule_id for x in findings] == ["AEG-DL-DECEPTIVE"]


def test_findings_are_stable_between_scans(ctx, home, origins):
    ctx.signatures.bad_domains.add("evil.example")
    fake_world(home, origins)
    fingerprints = lambda: sorted(f.fingerprint for f in split(dl.DownloadsScanner().run(ctx))[0])  # noqa: E731
    assert fingerprints() == fingerprints() and len(set(fingerprints())) == 8


# =========================================================================== Windows Attachment Manager policy
def fake_registry(values):
    """reg_read stand-in: ``{(hive, value name): data}``; everything else is missing."""
    def read(hive, key, value, view64=True):
        if key == dl.SHELL_FOLDERS_KEY:
            return None  # Downloads and Desktop stay where the test put them
        assert key == dl.ATTACHMENTS_KEY
        return values.get((hive, value))
    return read


def run_windows(ctx, monkeypatch, values):
    monkeypatch.setattr(dl, "IS_WINDOWS", True)
    monkeypatch.setattr(dl, "reg_read", fake_registry(values))
    return split(dl.DownloadsScanner().run(ctx))


def test_policy_read_normalises_the_values(monkeypatch):
    values = {("HKCU", "SaveZoneInformation"): 1, ("HKLM", "SaveZoneInformation"): "2", ("HKLM", "ScanWithAntiVirus"): "junk"}
    assert dl.read_attachment_policy(fake_registry(values)) == {
        "HKCU": {"SaveZoneInformation": 1, "ScanWithAntiVirus": None},
        "HKLM": {"SaveZoneInformation": 2, "ScanWithAntiVirus": None}}
    monkeypatch.setattr(dl, "reg_read", fake_registry(values))
    assert dl.read_attachment_policy()["HKCU"]["SaveZoneInformation"] == 1  # the module's own reader by default


def test_mark_of_the_web_switched_off_for_this_user(ctx, home, monkeypatch):
    findings, checks = run_windows(ctx, monkeypatch, {("HKCU", "SaveZoneInformation"): 1})
    (f,) = findings
    assert (f.rule_id, f.severity, f.category, f.scanner) == ("AEG-DL-MOTW-OFF", Severity.MEDIUM, Category.SYSTEM, "downloads")
    assert f.mitre == ["T1553.005"] and "HKCU" in f.title and f.location == f"HKCU\\{dl.ATTACHMENTS_KEY}\\SaveZoneInformation"
    assert f.evidence == {"hive": "HKCU", "key": dl.ATTACHMENTS_KEY, "value": "SaveZoneInformation", "data": 1}
    assert f.remediation.action == "set_registry_value"
    assert f.remediation.params == {"hive": "HKCU", "key": dl.ATTACHMENTS_KEY, "value": "SaveZoneInformation", "data": 2}
    assert "SmartScreen" in f.description and "Protected View" in f.description and f.recommendation
    status = {c.check_id: c for c in checks}
    assert status["AEG-DL-CHK-MOTW"].status == CheckStatus.FAIL and "HKCU" in status["AEG-DL-CHK-MOTW"].detail
    assert status["AEG-DL-CHK-MOTW"].title == "Windows marks downloaded files"
    assert status["AEG-DL-CHK-PROVENANCE"].status == CheckStatus.PASS
    assert [c.check_id for c in checks] == ["AEG-DL-CHK-PROVENANCE", "AEG-DL-CHK-MOTW"]


def test_mark_of_the_web_switched_off_for_the_machine_and_the_user(ctx, home, monkeypatch):
    findings, checks = run_windows(ctx, monkeypatch, {("HKCU", "SaveZoneInformation"): 1, ("HKLM", "SaveZoneInformation"): 1})
    assert [(f.rule_id, f.evidence["hive"]) for f in findings] == [("AEG-DL-MOTW-OFF", "HKCU"), ("AEG-DL-MOTW-OFF", "HKLM")]
    assert len({f.fingerprint for f in findings}) == 2
    assert [f.remediation.params["hive"] for f in findings] == ["HKCU", "HKLM"]
    assert all(f.remediation.params["data"] == 2 for f in findings)
    assert "HKCU and HKLM" in {c.check_id: c for c in checks}["AEG-DL-CHK-MOTW"].detail


def test_antivirus_scan_of_attachments_switched_off(ctx, home, monkeypatch):
    findings, checks = run_windows(ctx, monkeypatch, {("HKLM", "ScanWithAntiVirus"): 1})
    (f,) = findings
    assert (f.rule_id, f.severity, f.mitre, f.remediation) == ("AEG-DL-AVSCAN-OFF", Severity.LOW, ["T1685"], None)
    assert f.location.endswith("\\ScanWithAntiVirus") and f.evidence["hive"] == "HKLM" and f.evidence["data"] == 1
    assert {c.check_id: c for c in checks}["AEG-DL-CHK-MOTW"].status == CheckStatus.PASS  # it is about SaveZoneInformation only


@pytest.mark.parametrize("values", [
    {},
    {("HKCU", "SaveZoneInformation"): 2, ("HKLM", "SaveZoneInformation"): 2},
    {("HKCU", "SaveZoneInformation"): 0, ("HKLM", "ScanWithAntiVirus"): 3, ("HKCU", "ScanWithAntiVirus"): 2},
    {("HKCU", "SaveZoneInformation"): "not a number"},
])
def test_policy_in_order_is_clean(ctx, home, monkeypatch, values):
    findings, checks = run_windows(ctx, monkeypatch, values)
    assert findings == []
    assert {c.check_id: c.status for c in checks}["AEG-DL-CHK-MOTW"] == CheckStatus.PASS


def test_the_policy_check_only_exists_on_windows(ctx, home, monkeypatch):
    monkeypatch.setattr(dl, "IS_WINDOWS", False)
    monkeypatch.setattr(dl, "reg_read", lambda *a, **k: pytest.fail("the registry must not be read off Windows"))
    _, checks = split(dl.DownloadsScanner().run(ctx))
    assert [c.check_id for c in checks] == ["AEG-DL-CHK-PROVENANCE"]


def test_a_registry_failure_is_an_error_check_and_the_review_still_ran(ctx, home, monkeypatch, origins):
    make(home / "Downloads", "a.pdf.exe")
    monkeypatch.setattr(dl, "IS_WINDOWS", True)

    def boom(*a, **k):
        raise OSError("registry unavailable")

    monkeypatch.setattr(dl, "reg_read", boom)
    findings, checks = split(dl.DownloadsScanner().run(ctx))
    status = {c.check_id: c for c in checks}
    assert status["AEG-DL-CHK-MOTW"].status == CheckStatus.ERROR and "registry unavailable" in status["AEG-DL-CHK-MOTW"].detail
    assert status["AEG-DL-CHK-MOTW"].category == Category.SYSTEM and status["AEG-DL-CHK-PROVENANCE"].status == CheckStatus.FAIL
    assert [f.rule_id for f in findings] == ["AEG-DL-DECEPTIVE"]


def test_the_fix_is_accepted_by_the_remediation_engine(ctx, home, monkeypatch):
    """The fix params must fit core.remediation.set_registry_value: it backs up the old value and writes the new one."""
    from aegis.core import remediation as R

    findings, _ = run_windows(ctx, monkeypatch, {("HKCU", "SaveZoneInformation"): 1})
    written = []
    monkeypatch.setattr(R, "IS_WINDOWS", True)
    monkeypatch.setattr(R, "reg_read", lambda hive, key, value, view64=True: 1)
    monkeypatch.setattr(R, "reg_set_value", lambda hive, key, value, data, *a, **k: written.append((hive, key, value, data)))
    ok, message = R.apply_remediation(findings[0], ctx.config)
    assert ok, message
    assert written == [("HKCU", dl.ATTACHMENTS_KEY, "SaveZoneInformation", 2)]
    assert list(ctx.config.backups_dir.glob("registry-*.json"))


# =========================================================================== registration and wiring
def test_scanner_registered_and_in_the_quick_and_full_profiles():
    from aegis.core.engine import PROFILES

    load_all()
    cls = REGISTRY["downloads"]
    assert cls.name == "downloads" and cls.title == "Download origin review" and cls.description
    assert set(cls.platforms) == {"windows", "linux", "darwin"} and cls().supported()
    assert PROFILES["quick"].count("downloads") == 1 and PROFILES["full"].count("downloads") == 1
    assert "downloads" not in PROFILES["audit"] and PROFILES["custom"] == []
    assert PROFILES["quick"][-1] == "downloads" and PROFILES["full"][-1] == "downloads"


def test_cli_help_names_the_scanner():
    from aegis.cli import build_parser

    scan_parser = build_parser()._subparsers._group_actions[0].choices["scan"]
    scan = next(a for a in scan_parser._actions if "--scanners" in a.option_strings)
    assert "downloads" in scan.help


def test_engine_runs_the_scanner(tmp_path, home, origins):
    from aegis.core.engine import ScanEngine

    make(home / "Downloads", "Invoice.pdf.exe")
    make(home / "Downloads", "tool.exe")
    origins["tool.exe"] = zone(f"https://{IP}/tool.exe")
    res = ScanEngine().scan("custom", ["downloads"], paths=[tmp_path])
    assert res.scanners == ["downloads"] and res.errors == []
    assert sorted((f.rule_id, f.scanner) for f in res.findings) == [
        ("AEG-DL-DECEPTIVE", "downloads"), ("AEG-DL-RAWIP", "downloads")]
    assert {c.check_id: c.status for c in res.checks if c.scanner == "downloads"} == {"AEG-DL-CHK-PROVENANCE": CheckStatus.FAIL}
    json.loads(res.to_json())


def test_moved_downloads_and_desktop_folders_are_reviewed_once(ctx, tmp_path, monkeypatch, origins):
    """Explorer's User Shell Folders can move Downloads (another drive) and the Desktop (OneDrive folder backup)."""
    home = tmp_path / "home3"
    moved_dl, onedrive_desktop = tmp_path / "D" / "Downloads", home / "OneDrive" / "Desktop"
    make(moved_dl, "setup.exe")
    make(onedrive_desktop, "tool.exe")
    make(home / "Downloads", "old.exe")
    for name in ("setup.exe", "tool.exe", "old.exe"):
        origins[name] = zone(f"https://{IP}/{name}")
    monkeypatch.setenv("AEGIS_TEST_ONEDRIVE", str(home / "OneDrive"))
    values = {dl.DOWNLOADS_FOLDER_ID: str(moved_dl), "Desktop": "%AEGIS_TEST_ONEDRIVE%" + os.sep + "Desktop"}

    def read(hive, key, value, view64=True):
        assert hive == "HKCU" and key == dl.SHELL_FOLDERS_KEY
        return values.get(value)

    assert dl.shell_folders(read) == [moved_dl, onedrive_desktop]
    monkeypatch.setattr(dl, "user_home", lambda: home)
    monkeypatch.setattr(dl, "IS_WINDOWS", True)
    monkeypatch.setattr(dl, "shell_folders", lambda: [moved_dl, onedrive_desktop, home / "Downloads"])
    monkeypatch.setattr(dl, "reg_read", lambda *a, **k: None)
    assert dl.download_roots() == [home / "Downloads", moved_dl, onedrive_desktop]  # no Desktop under home: skipped
    findings = reviewed(split(dl.DownloadsScanner().run(ctx))[0])
    assert sorted(Path(f.evidence["path"]).name for f in findings) == ["old.exe", "setup.exe", "tool.exe"]


def test_a_folder_inside_another_root_is_not_reported_twice(ctx, home, monkeypatch, origins):
    make(home / "Downloads" / "sub", "dup.exe")
    origins["dup.exe"] = zone(f"https://{IP}/dup.exe")
    walk = dl.walk_downloads([home / "Downloads", home / "Downloads" / "sub"], 0, time.monotonic() + 30, lambda: False)
    assert [p.name for p, _ in walk.files] == ["dup.exe"]


def test_engine_skips_cleanly_without_a_downloads_folder(tmp_path, monkeypatch):
    from aegis.core.engine import ScanEngine

    empty = tmp_path / "nohome"
    empty.mkdir()
    monkeypatch.setattr(dl, "user_home", lambda: empty)
    monkeypatch.setattr(dl, "IS_WINDOWS", False)
    res = ScanEngine().scan("custom", ["downloads"], paths=[tmp_path])
    assert res.errors == [] and res.findings == []
    assert [(c.check_id, c.status) for c in res.checks] == [("AEG-DL-CHK-PROVENANCE", CheckStatus.SKIP)]


def test_attack_ids_used_are_current_and_well_formed():
    """The ATT&CK ids these modules emit (checked against the v20 enterprise matrix); retired ids are caught globally by
    tests/test_core.py::test_no_retired_attack_technique_ids."""
    current = {"T1027.006", "T1036", "T1036.002", "T1036.007", "T1105", "T1204.002", "T1553.005", "T1685"}
    used = set()
    for module in (prov, dl):
        used |= set(re.findall(r"(?<![\w.])T1\d{3}(?:\.\d{3})?(?![.\d])", Path(module.__file__).read_text(encoding="utf-8")))
    assert used == current, used ^ current


def test_the_sources_are_plain_ascii():
    """Direction controls and invisible padding are written as escapes, so no source line can hide its own meaning."""
    for module in (prov, dl):
        text = Path(module.__file__).read_text(encoding="utf-8")
        assert text.isascii(), [(n, line) for n, line in enumerate(text.splitlines(), 1) if not line.isascii()]


# =========================================================================== real operating system
def write_real_origin(path, host_url, referrer_url):
    """Record an origin the way the OS does: an alternate data stream (Windows) or user.xdg.* attributes (Linux)."""
    if sys.platform == "win32":
        text = f"[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl={referrer_url}\r\nHostUrl={host_url}\r\n"
        try:
            with open(str(path) + ":Zone.Identifier", "w", encoding="utf-8", newline="") as fh:
                fh.write(text)
        except OSError as exc:
            pytest.skip(f"this file system keeps no alternate data streams ({exc})")
    elif sys.platform.startswith("linux") and hasattr(os, "setxattr"):
        try:
            os.setxattr(path, "user.xdg.origin.url", host_url.encode())
            os.setxattr(path, "user.xdg.referrer.url", referrer_url.encode())
        except OSError as exc:
            pytest.skip(f"this file system keeps no user extended attributes ({exc})")
    else:
        pytest.skip("no way to record a download origin on this platform")


def test_scanner_reads_a_real_recorded_origin(ctx, home):
    downloads = home / "Downloads"
    bad = make(downloads, "setup.exe")
    write_real_origin(bad, f"http://{IP}/dl/setup.exe?token=SECRETTOKEN#frag", "https://free-software.example/page?uid=SECRETUID")
    make(downloads, "Invoice.pdf.exe")  # no origin
    good = make(downloads, "clean.exe")
    write_real_origin(good, "https://vendor.example/clean.exe", "https://vendor.example/download")
    findings, checks = split(dl.DownloadsScanner().run(ctx))
    found = {Path(f.evidence["path"]).name: f for f in reviewed(findings)}
    assert sorted(found) == ["Invoice.pdf.exe", "setup.exe"]
    f = found["setup.exe"]
    assert f.rule_id == "AEG-DL-RAWIP" and f.severity == Severity.MEDIUM
    assert f.evidence["origin_source"] == ("zone.identifier" if sys.platform == "win32" else "xattr")
    assert f.evidence["host_url"] == f"http://{IP}/dl/setup.exe"
    assert f.evidence["referrer_url"] == "https://free-software.example/page"
    assert f.evidence["zone"] == (3 if sys.platform == "win32" else None)
    assert found["Invoice.pdf.exe"].rule_id == "AEG-DL-DECEPTIVE" and found["Invoice.pdf.exe"].evidence["origin_source"] == ""
    assert "SECRET" not in json.dumps([x.to_dict() for x in findings] + [c.to_dict() for c in checks])
    provenance = checks_by_id(checks)["AEG-DL-CHK-PROVENANCE"]
    assert provenance.status == CheckStatus.FAIL and "3 risky downloads reviewed, 2 with a recorded origin" in provenance.detail


def test_scanner_runs_for_real_on_this_machine(ctx):
    """No monkeypatching: whatever this machine has in its Downloads folder, the scan finishes without an ERROR."""
    out = list(dl.DownloadsScanner().run(ctx))
    findings, checks = split(out)
    ids = [c.check_id for c in checks]
    assert ids[0] == "AEG-DL-CHK-PROVENANCE" and ids == (["AEG-DL-CHK-PROVENANCE", "AEG-DL-CHK-MOTW"] if sys.platform == "win32"
                                                         else ["AEG-DL-CHK-PROVENANCE"])
    assert all(c.status != CheckStatus.ERROR for c in checks), [(c.check_id, c.detail) for c in checks]
    json.dumps([x.to_dict() for x in out])
