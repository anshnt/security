"""Software updater: package-manager output parsers, collection with fake runners, risk rating, findings,
the software-scanner integration and the `aegis apps` command. No real package manager is run."""

import json

import pytest

from aegis.core.models import CheckResult, CheckStatus, Finding, Severity
from aegis.tools import appupdates as au
from aegis.tools.appupdates import Update

def _row(widths, *cols):
    return "".join(c.ljust(w) for c, w in zip(cols, widths)) + cols[-1]


_W = (39, 36, 17, 17)
_W2 = (17, 19, 8, 10)
WINGET = (
    "   - \r   \\ \r   | \r                                                                                                    \r"
    + _row(_W, "Name", "Id", "Version", "Available", "Source") + "\n" + "-" * 114 + "\n"
    + _row(_W, "Microsoft Edge", "Microsoft.Edge", "129.0.2792.65", "130.0.2849.46", "winget") + "\n"
    + _row(_W, "7-Zip 23.01 (x64)", "7zip.7zip", "23.01", "24.08", "winget") + "\n"
    + _row(_W, "Python 3.11.4 (64-bit)", "Python.Python.3.11", "3.11.4", "3.11.9", "winget") + "\n"
    + _row(_W, "Some Very Long Application Name Tha\u2026", "Vendor.SomeVeryLongApplicationNa\u2026", "1.0", "2.0", "winget") + "\n"
    + _row(_W, "Contoso Widget", "Contoso.Widget", "Unknown", "5.1.2", "winget") + "\n"
    + "5 upgrades available.\n"
    "\n"
    "The following packages have an upgrade available, but require explicit targeting for upgrade:\n"
    + _row(_W2, "Name", "Id", "Version", "Available", "Source") + "\n" + "-" * 60 + "\n"
    + _row(_W2, "Mozilla Firefox", "Mozilla.Firefox", "130.0", "131.0.3", "winget") + "\n"
)

WINGET_DE = (
    _row((16, 21, 10, 11), "Name", "ID", "Version", "Verfügbar", "Quelle") + "\n" + "-" * 62 + "\n"
    + _row((16, 21, 10, 11), "Notepad++", "Notepad++.Notepad++", "8.6.2", "8.7.1", "winget") + "\n"
    + "1 Aktualisierungen verfügbar.\n"
)

APT = """WARNING: apt does not have a stable CLI interface. Use with caution in scripts.

Listing...
curl/noble-security 8.5.0-2ubuntu10.16 amd64 [upgradable from: 8.5.0-2ubuntu10.15]
libcurl4t64/noble-updates,noble-security 8.5.0-2ubuntu10.16 amd64 [upgradable from: 8.5.0-2ubuntu10.15]
tzdata/noble-updates 2026e-0ubuntu0.24.04.1 all [upgradable from: 2026c-0ubuntu0.24.04.1]
openssl/bookworm-security 3.0.15-1~deb12u1 amd64 [upgradable from: 3.0.14-1~deb12u2]
"""

DNF = """
firefox.x86_64                     131.0-1.fc40                     updates
kernel-core.x86_64                 6.11.3-200.fc40                  updates
tzdata.noarch                      2024b-1.fc40                     updates
Obsoleting Packages
python3-foo.noarch                 1.0-1.fc40                       updates
"""

DNF_SEC = """FEDORA-2024-1a2b3c4d5e Important/Sec.  firefox-131.0-1.fc40.x86_64
FEDORA-2024-aaaaaaaaaa Moderate/Sec.   kernel-core-6.11.3-200.fc40.x86_64
FEDORA-2024-bbbbbbbbbb bugfix          tzdata-2024b-1.fc40.noarch
"""

BREW = json.dumps({
    "formulae": [{"name": "openssl@3", "installed_versions": ["3.3.1"], "current_version": "3.3.2", "pinned": False},
                 {"name": "jq", "installed_versions": ["1.7"], "current_version": "1.7.1", "pinned": True}],
    "casks": [{"name": "firefox", "installed_versions": "130.0", "current_version": "131.0.3"}],
})


# --------------------------------------------------------------------------- parsers
def test_winget_table_both_tables_truncation_and_unknown():
    ups = au.parse_winget_table(WINGET)
    by = {u.id: u for u in ups}
    assert list(by) == ["Microsoft.Edge", "7zip.7zip", "Python.Python.3.11", "Vendor.SomeVeryLongApplicationNa…",
                        "Contoso.Widget", "Mozilla.Firefox"]
    edge = by["Microsoft.Edge"]
    assert (edge.name, edge.installed, edge.available, edge.source, edge.explicit) == \
        ("Microsoft Edge", "129.0.2792.65", "130.0.2849.46", "winget", False)
    assert by["7zip.7zip"].name == "7-Zip 23.01 (x64)"
    assert by["Vendor.SomeVeryLongApplicationNa…"].truncated and not edge.truncated
    assert by["Contoso.Widget"].installed == "Unknown"
    assert by["Mozilla.Firefox"].explicit and by["Mozilla.Firefox"].available == "131.0.3"


def test_winget_rows_padded_off_by_one_are_not_split():
    header = _row(_W, "Name", "Id", "Version", "Available", "Source")
    row = _row((38, 36, 17, 17), "Some Product With A Long Display Na", "Vendor.ProductWithLongIdentifier",
               "1.2.3", "1.2.4", "winget")  # one character short of the header's columns
    ups = au.parse_winget_table(header + "\n" + "-" * 114 + "\n" + row + "\n")
    assert [(u.name, u.id, u.installed, u.available) for u in ups] == [
        ("Some Product With A Long Display Na", "Vendor.ProductWithLongIdentifier", "1.2.3", "1.2.4")]


def test_winget_localised_header_and_garbage():
    ups = au.parse_winget_table(WINGET_DE)
    assert [(u.id, u.available) for u in ups] == [("Notepad++.Notepad++", "8.7.1")]
    assert au.parse_winget_table("") == []
    assert au.parse_winget_table("No installed package found matching input criteria.\n") == []
    assert au.parse_winget_table("-" * 40 + "\n" + "x" * 50) == []  # a rule without a header


def test_apt_upgradable_and_security_pockets():
    ups = au.parse_apt_upgradable(APT)
    assert [(u.name, u.security) for u in ups] == [("curl", True), ("libcurl4t64", True), ("tzdata", False),
                                                   ("openssl", True)]
    assert ups[0].installed == "8.5.0-2ubuntu10.15" and ups[0].available == "8.5.0-2ubuntu10.16"


def test_dnf_check_update_with_security_list():
    sec = au.parse_dnf_security(DNF_SEC)
    assert sec == ["firefox", "kernel-core"]
    ups = au.parse_dnf_check_update(DNF, sec)
    assert [(u.name, u.available, u.security) for u in ups] == [
        ("firefox", "131.0-1.fc40", True), ("kernel-core", "6.11.3-200.fc40", True), ("tzdata", "2024b-1.fc40", False)]


def test_checkupdates_and_brew():
    ups = au.parse_checkupdates("linux 6.6.1.arch1-1 -> 6.6.2.arch1-1\nfirefox 130.0-1 -> 131.0.3-1\njunk line\n")
    assert [(u.name, u.installed, u.available) for u in ups] == [("linux", "6.6.1.arch1-1", "6.6.2.arch1-1"),
                                                                 ("firefox", "130.0-1", "131.0.3-1")]
    b = au.parse_brew_outdated(BREW)
    assert [(u.name, u.installed, u.available, u.explicit, u.cask) for u in b] == [
        ("openssl@3", "3.3.1", "3.3.2", False, False), ("jq", "1.7", "1.7.1", True, False),
        ("firefox", "130.0", "131.0.3", False, True)]
    assert au.parse_brew_outdated("not json") == [] and au.parse_brew_outdated("[1, 2]") == []


# --------------------------------------------------------------------------- collection
class FakeRunner:
    def __init__(self, table):
        self.table = table
        self.calls = []

    def __call__(self, cmd, timeout=60, input_text=None):
        self.calls.append(list(cmd))
        key = next((k for k in self.table if k in " ".join(cmd)), None)
        return self.table[key] if key else (-1, "", f"not found: {cmd[0]}")


def which_of(*tools):
    return lambda name: f"/usr/bin/{name}" if name in tools else None


def test_collect_windows_winget():
    r = FakeRunner({"winget upgrade": (0, WINGET, "")})
    src, ups, problem = au.collect_updates(r, which_of("winget"), "windows")
    assert src == "winget" and len(ups) == 6 and problem == ""
    assert r.calls[0][:2] == ["winget", "upgrade"] and "--accept-source-agreements" in r.calls[0]


@pytest.mark.parametrize("rc", [0x8A150014, -1978335212, 0x8A15002B])
def test_collect_winget_nothing_to_upgrade_codes(rc):
    r = FakeRunner({"winget upgrade": (rc, "Keine installierten Pakete gefunden.\n", "")})
    assert au.collect_updates(r, which_of("winget"), "windows") == ("winget", [], "")


def test_collect_winget_missing_or_failing():
    src, ups, problem = au.collect_updates(FakeRunner({}), which_of(), "windows")
    assert src == "" and "App Installer" in problem
    r = FakeRunner({"winget upgrade": (1, "", "Failed in attempting to update the source: winget")})
    src, ups, problem = au.collect_updates(r, which_of("winget"), "windows")
    assert src == "winget" and ups == [] and "winget failed" in problem


def test_collect_linux_variants():
    r = FakeRunner({"apt list": (0, APT, "WARNING: apt does not have a stable CLI interface")})
    src, ups, problem = au.collect_updates(r, which_of("apt", "dnf"), "linux")
    assert src == "apt" and len(ups) == 4 and not problem and r.calls[0][:2] == ["env", "LC_ALL=C"]
    r = FakeRunner({"check-update": (100, DNF, ""), "updateinfo": (0, DNF_SEC, "")})
    src, ups, problem = au.collect_updates(r, which_of("dnf"), "linux")
    assert src == "dnf" and [u.security for u in ups] == [True, True, False]
    r = FakeRunner({"check-update": (0, "", "")})
    assert au.collect_updates(r, which_of("dnf"), "linux") == ("dnf", [], "")
    assert len(r.calls) == 1  # no security query when nothing is pending
    r = FakeRunner({"check-update": (1, "", "Error: Failed to download metadata")})
    assert "dnf failed" in au.collect_updates(r, which_of("dnf"), "linux")[2]
    r = FakeRunner({"checkupdates": (2, "", "")})
    assert au.collect_updates(r, which_of("checkupdates"), "linux") == ("pacman", [], "")
    assert au.collect_updates(FakeRunner({}), which_of(), "linux")[0] == ""


def test_collect_macos_brew():
    r = FakeRunner({"brew outdated": (0, BREW, "")})
    src, ups, problem = au.collect_updates(r, which_of("brew"), "darwin")
    assert src == "brew" and len(ups) == 3 and "HOMEBREW_NO_AUTO_UPDATE=1" in r.calls[0]
    assert "Homebrew" in au.collect_updates(FakeRunner({}), which_of(), "darwin")[2]
    assert au.collect_updates(FakeRunner({}), which_of(), "plan9")[2]


# --------------------------------------------------------------------------- risk, commands, findings
@pytest.mark.parametrize("name, ident, label", [
    ("Google Chrome", "Google.Chrome", "web browser"),
    ("Microsoft Edge WebView2 Runtime", "Microsoft.EdgeWebView2Runtime", "web browser"),
    ("7-Zip 23.01 (x64)", "7zip.7zip", "archive tool"),
    ("Adobe Acrobat Reader (64-bit)", "Adobe.Acrobat.Reader.64-bit", "document reader"),
    ("Eclipse Temurin JDK", "EclipseAdoptium.Temurin.21.JDK", "runtime"),
    ("Microsoft .NET Desktop Runtime 8.0.8", "Microsoft.DotNet.DesktopRuntime.8", "runtime"),
    ("Zoom Workplace", "Zoom.Zoom", "communication app"),
    ("PuTTY release 0.80 (64-bit)", "PuTTY.PuTTY", "remote access / file transfer tool"),
    ("VLC media player", "VideoLAN.VLC", "media player"),
    ("Notepad++ (64-bit x64)", "Notepad++.Notepad++", "developer / admin tool"),
    ("sudo", "sudo", "developer / admin tool"),
    ("ZoomIt", "Microsoft.Sysinternals.ZoomIt", None),
    ("Microsoft Visual C++ 2015-2022 Redistributable", "Microsoft.VCRedist.2015+.x64", None),
    ("tzdata", "tzdata", None),
    ("Operator Console", "Contoso.OperatorConsole", None),
])
def test_risk_label(name, ident, label):
    assert au.risk_label(Update(name, ident, "1", "2", "winget")) == label


def test_upgrade_commands():
    assert au.upgrade_command(Update("Edge", "Microsoft.Edge", "1", "2", "winget"))[:5] == \
        ["winget", "upgrade", "--id", "Microsoft.Edge", "--exact"]
    assert au.upgrade_command(Update("x…", "Vendor.X…", "1", "2", "winget")) is None
    assert au.upgrade_command(Update("curl", "curl", "1", "2", "apt")) == ["apt-get", "install", "--only-upgrade", "-y", "curl"]
    assert au.upgrade_command(Update("firefox", "firefox", "", "2", "dnf")) == ["dnf", "upgrade", "-y", "firefox"]
    assert au.upgrade_command(Update("firefox", "firefox", "1", "2", "brew", cask=True)) == ["brew", "upgrade", "--cask", "firefox"]
    assert au.upgrade_command(Update("linux", "linux", "1", "2", "pacman")) is None


def test_findings_per_app_for_winget():
    fs = au.update_findings("winget", au.parse_winget_table(WINGET))
    per_app = [f for f in fs if f.rule_id == "AEG-SW-UPDATE"]
    assert [f.location for f in per_app] == ["updates:winget:Microsoft.Edge", "updates:winget:7zip.7zip",
                                             "updates:winget:Python.Python.3.11", "updates:winget:Mozilla.Firefox"]
    edge = per_app[0]
    assert edge.severity == Severity.MEDIUM and edge.category == "vulnerability" and "T1203" in edge.mitre
    assert edge.remediation.action == "run_command" and edge.remediation.params["timeout"] == au.UPGRADE_TIMEOUT_S
    assert edge.remediation.params["command"][:4] == ["winget", "upgrade", "--id", "Microsoft.Edge"]
    summary = [f for f in fs if f.rule_id == "AEG-SW-UPDATES"]
    assert len(summary) == 1 and summary[0].severity == Severity.LOW and summary[0].evidence["count"] == 2
    assert summary[0].title.startswith("2 other installed app(s)") and summary[0].location == "updates:winget"


def test_findings_cap_and_fingerprint_stability():
    many = [Update(f"Firefox {i}", f"Mozilla.Firefox.{i}", "1", "2", "winget") for i in range(au.MAX_APP_FINDINGS + 5)]
    fs = au.update_findings("winget", many)
    assert sum(f.rule_id == "AEG-SW-UPDATE" for f in fs) == au.MAX_APP_FINDINGS
    assert [f.evidence["count"] for f in fs if f.rule_id == "AEG-SW-UPDATES"] == [5]
    a = au.update_findings("winget", [Update("Chrome", "Google.Chrome", "1", "2", "winget")])[0]
    b = au.update_findings("winget", [Update("Chrome", "Google.Chrome", "2", "3", "winget")])[0]
    assert a.fingerprint == b.fingerprint


def test_linux_findings_are_one_summary():
    fs = au.update_findings("apt", au.parse_apt_upgradable(APT))
    assert len(fs) == 1
    f = fs[0]
    assert f.rule_id == "AEG-SW-UPDATES" and f.severity == Severity.MEDIUM
    assert f.title == "4 installed package(s) have updates available (3 security)"
    assert f.evidence["notable"] == ["curl", "libcurl", "openssl"] and f.evidence["security_updates"] == 3
    assert [u["name"] for u in f.evidence["updates"]][:3] == ["curl", "libcurl4t64", "openssl"]  # security first
    plain = au.update_findings("pacman", [Update("tzdata", "tzdata", "1", "2", "pacman")])
    assert plain[0].severity == Severity.LOW and "pacman -Syu" in plain[0].recommendation
    assert au.update_findings("apt", []) == []


# --------------------------------------------------------------------------- software scanner integration
def _scan(monkeypatch, ctx, collected):
    from aegis.scanners import software as sw

    monkeypatch.setattr(sw, "collect_inventory", lambda: [{"name": "Good App", "version": "1", "publisher": "x",
                                                           "install_location": "", "uninstall": "", "source": "HKLM"}])
    monkeypatch.setattr(au, "collect_updates", lambda: collected)
    items = list(sw.SoftwareScanner().run(ctx))
    upd = [i for i in items if isinstance(i, CheckResult) and i.check_id == "AEG-SW-UPDATES"]
    return [i for i in items if isinstance(i, Finding)], upd[0] if upd else None


def test_scanner_reports_updates(monkeypatch, ctx):
    fs, check = _scan(monkeypatch, ctx, ("winget", au.parse_winget_table(WINGET), ""))
    assert check.status == CheckStatus.FAIL and "6 update(s) available from winget, 4 for high-risk apps" in check.detail
    assert sum(f.rule_id == "AEG-SW-UPDATE" for f in fs) == 4 and ctx.stats["software_updates_available"] == 6


def test_scanner_update_statuses(monkeypatch, ctx):
    _fs, check = _scan(monkeypatch, ctx, ("apt", [Update("tzdata", "tzdata", "1", "2", "apt")], ""))
    assert check.status == CheckStatus.WARN
    _fs, check = _scan(monkeypatch, ctx, ("apt", [], ""))
    assert check.status == CheckStatus.PASS and "No pending updates" in check.detail
    _fs, check = _scan(monkeypatch, ctx, ("", [], "winget (App Installer) is not available"))
    assert check.status == CheckStatus.SKIP
    _fs, check = _scan(monkeypatch, ctx, ("winget", [], "winget failed (exit 1)"))
    assert check.status == CheckStatus.WARN
    ctx.options["software_updates"] = False
    _fs, check = _scan(monkeypatch, ctx, ("apt", [], ""))
    assert check is None


def test_run_command_remediation_honours_timeout(monkeypatch, aegis_home):
    from aegis.core import remediation as rem
    from aegis.core.config import Config

    seen = {}

    def fake_run(cmd, timeout=60, input_text=None):
        seen["timeout"] = timeout
        return 0, "ok", ""

    monkeypatch.setattr(rem, "run", fake_run)
    f = au.update_findings("winget", [Update("Chrome", "Google.Chrome", "1", "2", "winget")])[0]
    ok, _msg = rem.apply_remediation(f, Config.load())
    assert ok and seen["timeout"] == au.UPGRADE_TIMEOUT_S


# --------------------------------------------------------------------------- aegis apps
@pytest.fixture
def apps_cli(monkeypatch, aegis_home):
    from aegis import cli
    from aegis.core import platform

    calls = []
    monkeypatch.setattr(au, "collect_updates", lambda: ("winget", au.parse_winget_table(WINGET), ""))
    monkeypatch.setattr(platform, "run", lambda cmd, timeout=60, input_text=None: (calls.append((cmd, timeout)) or (0, "", "")))
    return cli, calls


def test_apps_list_text_and_json(apps_cli, capsys):
    cli, _calls = apps_cli
    assert cli.main(["apps"]) == 1
    out = capsys.readouterr().out
    assert "Microsoft.Edge" in out and "[web browser]" in out and "pinned" in out and "6 update(s) available" in out
    assert cli.main(["apps", "list", "--json"]) == 1
    doc = json.loads(capsys.readouterr().out)
    assert doc["source"] == "winget" and {u["risk"] for u in doc["updates"]} >= {"web browser", None}


def test_apps_upgrade_selected_all_and_errors(apps_cli, monkeypatch, capsys):
    cli, calls = apps_cli
    assert cli.main(["apps", "upgrade", "microsoft.edge", "-y"]) == 0
    assert calls[-1][0][:4] == ["winget", "upgrade", "--id", "Microsoft.Edge"] and calls[-1][1] == au.UPGRADE_TIMEOUT_S
    calls.clear()
    assert cli.main(["apps", "upgrade", "--all", "-y"]) == 2  # the truncated ID cannot be targeted
    upgraded = [c[0][3] for c in calls]
    assert "Mozilla.Firefox" not in upgraded and len(upgraded) == 4  # pinned excluded, truncated skipped
    assert "truncated" in capsys.readouterr().out
    assert cli.main(["apps", "upgrade", "nope.nope", "-y"]) == 2
    assert cli.main(["apps", "upgrade"]) == 2
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")
    calls.clear()
    assert cli.main(["apps", "upgrade", "7zip.7zip"]) == 0 and calls == []
    monkeypatch.setattr(au, "collect_updates", lambda: ("pacman", [Update("linux", "linux", "1", "2", "pacman")], ""))
    assert cli.main(["apps", "upgrade", "linux", "-y"]) == 2 and "pacman -Syu" in capsys.readouterr().out
    monkeypatch.setattr(au, "collect_updates", lambda: ("", [], "winget (App Installer) is not available"))
    assert cli.main(["apps"]) == 2
