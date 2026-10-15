"""Browser scanner tests using fake Chrome / Firefox profile trees."""

import json
import sqlite3
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

from aegis.core.models import CheckStatus, Finding, Severity
from aegis.scanners import browser as br

BAD_ID = "a" * 32
STORE_ID = "b" * 32
BROAD_STORE_ID = "c" * 32
UNPACKED_ID = "d" * 32
REG_ID = "e" * 32
REG_BROAD_ID = "f" * 32
UBLOCK_ID = "cjpalhdlnbpafiamejdnhcphjbkeiagm"
STORE_URL = "https://clients2.google.com/service/update2/crx"


class FakeSigs:
    def __init__(self, bad_ext=(), bad_domains=(), pup=()):
        self.bad_extensions = set(bad_ext)
        self.bad_domains = set(bad_domains)
        self.pup_names = list(pup)

    def is_bad_domain(self, d):
        d = d.lower().strip(".")
        return any(d == b or d.endswith("." + b) for b in self.bad_domains)


@pytest.fixture(autouse=True)
def _unmanaged(monkeypatch):
    monkeypatch.setattr(br, "is_managed_pc", lambda: False)


def write_json(p: Path, obj):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


def add_extension(profile: Path, ext_id: str, manifest: dict, version="1.0_0"):
    d = profile / "Extensions" / ext_id / version
    write_json(d / "manifest.json", manifest)
    return d


def make_chrome(tmp_path: Path, prefs=None, ext_settings=None, secure=None) -> Path:
    base = tmp_path / "User Data"
    prof = base / "Default"
    prof.mkdir(parents=True)
    p = dict(prefs or {})
    if ext_settings is not None:
        p.setdefault("extensions", {})["settings"] = ext_settings
    write_json(prof / "Preferences", p)
    write_json(prof / "Secure Preferences", secure or {})
    return base


def scan(base: Path, sigs=None, managed=False):
    prof = br.chromium_profiles(base)[0]
    return list(br.scan_chromium_profile(base, prof, "chrome", "Google Chrome", sigs or FakeSigs(), managed))


def findings_of(items):
    return [i for i in items if isinstance(i, Finding)]


def by_rule(items, rule):
    return [f for f in findings_of(items) if f.rule_id == rule]


# --------------------------------------------------------------------------- discovery

def test_chromium_profiles_exclude_guest_and_system(tmp_path):
    base = tmp_path / "ud"
    for name in ("Default", "Profile 1", "Profile 12", "Guest Profile", "System Profile", "Crashpad", "Profile X"):
        (base / name).mkdir(parents=True)
        write_json(base / name / "Preferences", {})
    names = [p.name for p in br.chromium_profiles(base)]
    assert names == ["Default", "Profile 1", "Profile 12"]


def test_chromium_profiles_opera_style_and_missing(tmp_path):
    base = tmp_path / "Opera Stable"
    write_json(base / "Preferences", {})
    assert br.chromium_profiles(base) == [base]
    assert br.chromium_profiles(tmp_path / "nothing") == []


def test_profile_label_uses_local_state(tmp_path):
    base = tmp_path / "ud"
    (base / "Profile 1").mkdir(parents=True)
    write_json(base / "Local State", {"profile": {"info_cache": {"Profile 1": {"name": "Work"}}}})
    assert br.chromium_profile_label(base, base / "Profile 1") == "Profile 1 (Work)"


def test_browser_roots_windows_paths(tmp_path):
    env = {"LOCALAPPDATA": r"C:\Users\x\AppData\Local", "APPDATA": r"C:\Users\x\AppData\Roaming"}
    roots = {r.key + ":" + r.name: r.base for r in br.chromium_browser_roots("windows", tmp_path, env)}
    assert "Chrome" in str(roots["chrome:Google Chrome"]) and "User Data" in str(roots["chrome:Google Chrome"])
    keys = {r.key for r in br.chromium_browser_roots("windows", tmp_path, env)}
    assert {"chrome", "edge", "brave", "vivaldi", "opera", "operagx", "chromium", "yandex"} <= keys
    ff = {r.key for r in br.firefox_browser_roots("windows", tmp_path, env)}
    assert ff == {"firefox", "librewolf", "waterfox"}


def test_firefox_profiles_ini(tmp_path):
    base = tmp_path / "ff"
    (base / "Profiles" / "abc.default-release").mkdir(parents=True)
    abs_prof = tmp_path / "elsewhere"
    abs_prof.mkdir()
    (base / "profiles.ini").write_text(
        "[Profile0]\nName=default-release\nIsRelative=1\nPath=Profiles/abc.default-release\nDefault=1\n\n"
        f"[Profile1]\nName=abs\nIsRelative=0\nPath={abs_prof}\n\n[General]\nStartWithLastProfile=1\n")
    got = br.firefox_profiles(base)
    assert [n for n, _ in got] == ["default-release", "abs"]
    assert got[1][1] == abs_prof


# --------------------------------------------------------------------------- extension logic

def test_store_extension_with_modest_permissions_is_clean(tmp_path):
    base = make_chrome(tmp_path, ext_settings={
        STORE_ID: {"location": 1, "from_webstore": True, "state": 1, "path": f"{STORE_ID}/1.0_0"}})
    add_extension(base / "Default", STORE_ID, {
        "name": "Tab Counter", "version": "1.0", "manifest_version": 3, "update_url": STORE_URL,
        "permissions": ["storage", "activeTab"], "host_permissions": ["https://example.com/*"]}, "1.0_0")
    items = scan(base)
    assert findings_of(items) == []
    ext_check = [c for c in items if getattr(c, "check_id", "").endswith(".extensions")][0]
    assert ext_check.status == CheckStatus.PASS


def test_bad_extension_is_critical_with_remediation(tmp_path):
    base = make_chrome(tmp_path, ext_settings={BAD_ID: {"location": 1, "from_webstore": True, "state": 1,
                                                        "path": f"{BAD_ID}/2.0_0"}})
    d = add_extension(base / "Default", BAD_ID, {"name": "Fast Video Downloader", "version": "2.0", "update_url": STORE_URL,
                                                 "permissions": ["tabs"]}, "2.0_0")
    items = scan(base, FakeSigs(bad_ext={BAD_ID}))
    f = by_rule(items, "AEG-BRW-EXT-BAD")
    assert len(f) == 1 and f[0].severity == Severity.CRITICAL
    assert f[0].remediation.action == "remove_path"
    assert f[0].remediation.params["path"] == str(d.parent)  # Extensions/<id>
    assert f[0].evidence["id"] == BAD_ID
    ext_check = [c for c in items if getattr(c, "check_id", "").endswith(".extensions")][0]
    assert ext_check.status == CheckStatus.FAIL


def test_unknown_store_extension_with_dangerous_combo_is_low_review(tmp_path):
    base = make_chrome(tmp_path, ext_settings={BROAD_STORE_ID: {"location": 1, "from_webstore": True, "state": 1,
                                                                "path": f"{BROAD_STORE_ID}/1.0_0"}})
    add_extension(base / "Default", BROAD_STORE_ID, {
        "name": "Super Helper", "version": "1.0", "update_url": STORE_URL, "manifest_version": 2,
        "permissions": ["webRequest", "cookies", "<all_urls>"]})
    f = by_rule(scan(base), "AEG-BRW-EXT-REVIEW")
    assert len(f) == 1 and f[0].severity == Severity.LOW and f[0].remediation is None


def test_allowlisted_id_and_name_are_not_flagged(tmp_path):
    base = make_chrome(tmp_path, ext_settings={
        UBLOCK_ID: {"location": 1, "from_webstore": True, "state": 1, "path": f"{UBLOCK_ID}/1.0_0"},
        BROAD_STORE_ID: {"location": 1, "from_webstore": True, "state": 1, "path": f"{BROAD_STORE_ID}/1.0_0"}})
    broad = {"update_url": STORE_URL, "manifest_version": 2, "permissions": ["webRequest", "webRequestBlocking", "cookies", "<all_urls>", "proxy"]}
    add_extension(base / "Default", UBLOCK_ID, dict(broad, name="uBlock Origin", version="1.0"))
    add_extension(base / "Default", BROAD_STORE_ID, dict(broad, name="Bitwarden Password Manager", version="1.0"))
    assert findings_of(scan(base)) == []


def test_unpacked_extension_with_broad_permissions_is_high_without_remediation(tmp_path):
    unpacked = tmp_path / "devext"
    write_json(unpacked / "manifest.json", {"name": "Dev", "version": "0.1", "permissions": ["webRequest", "<all_urls>"]})
    base = make_chrome(tmp_path, ext_settings={UNPACKED_ID: {"location": 4, "state": 1, "path": str(unpacked)}})
    f = by_rule(scan(base), "AEG-BRW-EXT-SIDELOAD")
    assert len(f) == 1 and f[0].severity == Severity.HIGH
    assert f[0].remediation is None  # never delete a developer's folder


def test_registry_installed_extensions(tmp_path):
    base = make_chrome(tmp_path, ext_settings={
        REG_BROAD_ID: {"location": 3, "state": 1, "path": f"{REG_BROAD_ID}/1.0_0"},
        REG_ID: {"location": 3, "state": 1, "path": f"{REG_ID}/1.0_0"}})
    add_extension(base / "Default", REG_BROAD_ID, {"name": "Coupon Finder", "version": "1.0",
                                                   "permissions": ["tabs", "webRequest", "*://*/*"]})
    add_extension(base / "Default", REG_ID, {"name": "Weather", "version": "1.0", "permissions": ["storage"]})
    sev = {f.evidence["id"]: f for f in by_rule(scan(base), "AEG-BRW-EXT-SIDELOAD")}
    assert sev[REG_BROAD_ID].severity == Severity.HIGH
    assert sev[REG_BROAD_ID].remediation.action == "remove_path"
    assert sev[REG_ID].severity == Severity.MEDIUM


def test_default_installed_external_extension_is_ignored(tmp_path):
    base = make_chrome(tmp_path, ext_settings={REG_ID: {"location": 2, "state": 1, "was_installed_by_default": True,
                                                        "from_webstore": True, "path": f"{REG_ID}/1.0_0"}})
    add_extension(base / "Default", REG_ID, {"name": "Bundled", "version": "1.0", "update_url": STORE_URL,
                                             "permissions": ["storage"]})
    assert findings_of(scan(base)) == []


def test_disabled_sideload_is_downgraded(tmp_path):
    base = make_chrome(tmp_path, ext_settings={REG_ID: {"location": 3, "state": 0, "disable_reasons": 1,
                                                        "path": f"{REG_ID}/1.0_0"}})
    add_extension(base / "Default", REG_ID, {"name": "Weather", "version": "1.0", "permissions": ["storage"]})
    f = by_rule(scan(base), "AEG-BRW-EXT-SIDELOAD")
    assert f and f[0].severity == Severity.LOW


def test_orphan_folder_only_matters_for_bad_ids(tmp_path):
    base = make_chrome(tmp_path, ext_settings={STORE_ID: {"location": 1, "from_webstore": True, "state": 1,
                                                          "path": f"{STORE_ID}/1.0_0"}})
    add_extension(base / "Default", STORE_ID, {"name": "Ok", "version": "1.0", "update_url": STORE_URL})
    add_extension(base / "Default", REG_ID, {"name": "Leftover", "version": "1.0", "permissions": ["<all_urls>", "webRequest"]})
    add_extension(base / "Default", BAD_ID, {"name": "Leftover bad", "version": "1.0"})
    items = scan(base, FakeSigs(bad_ext={BAD_ID}))
    rules = {(f.rule_id, f.evidence["id"]) for f in findings_of(items)}
    assert rules == {("AEG-BRW-EXT-BAD", BAD_ID)}


def test_localized_name_resolution(tmp_path):
    vdir = tmp_path / "ext" / "1.0_0"
    write_json(vdir / "manifest.json", {"name": "__MSG_appName__", "default_locale": "de"})
    write_json(vdir / "_locales" / "de" / "messages.json", {"appName": {"message": "Mein Tool"}})
    write_json(vdir / "_locales" / "en" / "messages.json", {"appName": {"message": "My Tool"}})
    assert br.resolve_ext_name({"name": "__MSG_appName__", "default_locale": "de"}, vdir) == "Mein Tool"
    assert br.resolve_ext_name({"name": "__MSG_appName__"}, vdir) == "My Tool"
    assert br.resolve_ext_name({"name": "Plain"}, vdir) == "Plain"


def test_is_broad_host():
    for p in ("<all_urls>", "*://*/*", "http://*/*", "https://*/*", "*://*/"):
        assert br.is_broad_host(p), p
    for p in ("https://example.com/*", "https://*.example.com/*", "https://mail.google.com/*", "file:///*"):
        assert not br.is_broad_host(p), p


def test_secure_preferences_extension_settings_are_merged(tmp_path):
    base = make_chrome(tmp_path, secure={"extensions": {"settings": {
        REG_ID: {"location": 3, "state": 1, "path": f"{REG_ID}/1.0_0"}}}})
    add_extension(base / "Default", REG_ID, {"name": "Weather", "version": "1.0", "permissions": ["storage"]})
    assert by_rule(scan(base), "AEG-BRW-EXT-SIDELOAD")


def test_extension_update_url_on_bad_domain(tmp_path):
    base = make_chrome(tmp_path, ext_settings={STORE_ID: {"location": 1, "state": 1, "path": f"{STORE_ID}/1.0_0"}})
    add_extension(base / "Default", STORE_ID, {"name": "X", "version": "1.0", "update_url": "https://evil.example.net/u.xml"})
    f = by_rule(scan(base, FakeSigs(bad_domains={"evil.example.net"})), "AEG-BRW-EXT-BADHOST")
    assert f and f[0].severity == Severity.CRITICAL


# --------------------------------------------------------------------------- prefs

def test_search_hijack_levels(tmp_path):
    def run(url):
        base = make_chrome(tmp_path / url.split("/")[2], prefs={"default_search_provider_data": {"template_url_data": {"url": url}}})
        return by_rule(scan(base), "AEG-BRW-HIJACK-SEARCH")

    assert run("https://www.google.com/search?q={searchTerms}") == []
    assert run("https://duckduckgo.com/?q={searchTerms}") == []
    assert run("https://www.google.de/search?q={searchTerms}") == []
    hij = run("https://search.safefinder.com/?q={searchTerms}")
    assert hij and hij[0].severity == Severity.HIGH
    aff = run("https://search.yahoo.com/yhs/search?hspart=xyz&hsimp=yhs-001&p={searchTerms}")
    assert aff and aff[0].severity == Severity.HIGH
    unk = run("https://lookup.example.org/find?q={searchTerms}")
    assert unk and unk[0].severity == Severity.MEDIUM
    assert run("https://www.ask.com/web?q={searchTerms}")[0].severity == Severity.HIGH
    # google look-alike on a high-abuse TLD is not a known engine
    assert run("https://google.tk/search?q={searchTerms}")


def test_search_check_result_fails_on_hijack(tmp_path):
    base = make_chrome(tmp_path, prefs={"default_search_provider_data": {"template_url_data": {"url": "https://search.safefinder.com/?q={searchTerms}"}}})
    items = scan(base)
    c = [i for i in items if getattr(i, "check_id", "").endswith(".search")][0]
    assert c.status == CheckStatus.FAIL


def test_homepage_and_startup_hijack(tmp_path):
    base = make_chrome(tmp_path, prefs={
        "homepage": "https://www.searchbaron.com/?src=hp", "homepage_is_newtabpage": False,
        "session": {"restore_on_startup": 4, "startup_urls": ["https://example.com/", "https://search.mystart.com/"]}})
    items = scan(base)
    assert by_rule(items, "AEG-BRW-HIJACK-HOME")[0].severity == Severity.MEDIUM
    s = by_rule(items, "AEG-BRW-HIJACK-STARTUP")
    assert s and "mystart" in s[0].evidence["urls"][0]


def test_normal_homepage_not_flagged(tmp_path):
    base = make_chrome(tmp_path, prefs={"homepage": "https://intranet.corp.example/", "homepage_is_newtabpage": False,
                                        "session": {"restore_on_startup": 5, "startup_urls": ["https://search.mystart.com/"]}})
    assert findings_of(scan(base)) == []  # startup URLs ignored unless restore_on_startup == 4


def test_safe_browsing(tmp_path):
    off = scan(make_chrome(tmp_path / "a", prefs={"safebrowsing": {"enabled": False}}))
    f = by_rule(off, "AEG-BRW-SAFEBROWSING")
    assert f and f[0].severity == Severity.MEDIUM
    assert [c for c in off if getattr(c, "check_id", "").endswith(".safebrowsing")][0].status == CheckStatus.FAIL
    enh = scan(make_chrome(tmp_path / "b", prefs={"safebrowsing": {"enabled": True, "enhanced": True}}))
    c = [c for c in enh if getattr(c, "check_id", "").endswith(".safebrowsing")][0]
    assert c.status == CheckStatus.PASS and "enhanced" in c.detail
    default = scan(make_chrome(tmp_path / "c"))
    assert [c for c in default if getattr(c, "check_id", "").endswith(".safebrowsing")][0].status == CheckStatus.PASS


def test_notifications(tmp_path):
    notif = {"profile": {"content_settings": {"exceptions": {"notifications": {
        "https://mail.google.com:443,*": {"setting": 1},
        "https://win-prize.example.com:443,*": {"setting": 1},
        "https://blocked.example.org:443,*": {"setting": 2},
        "https://malware.example.net:443,*": {"setting": 1}}}}}}
    items = scan(make_chrome(tmp_path, prefs=notif), FakeSigs(bad_domains={"malware.example.net"}))
    bad = by_rule(items, "AEG-BRW-NOTIF-BAD")
    low = by_rule(items, "AEG-BRW-NOTIF")
    assert bad and bad[0].severity == Severity.HIGH and bad[0].evidence["sites"] == ["malware.example.net"]
    assert low and low[0].severity == Severity.LOW and low[0].evidence["sites"] == ["win-prize.example.com"]


def test_notifications_list_is_capped(tmp_path):
    exc = {f"https://s{i}.example.com:443,*": {"setting": 1} for i in range(60)}
    items = scan(make_chrome(tmp_path, prefs={"profile": {"content_settings": {"exceptions": {"notifications": exc}}}}))
    f = by_rule(items, "AEG-BRW-NOTIF")[0]
    assert len(f.evidence["sites"]) == 25 and f.evidence["total"] == 60


def test_proxy(tmp_path):
    f = by_rule(scan(make_chrome(tmp_path, prefs={"proxy": {"mode": "fixed_servers", "server": "10.1.1.1:8080"}})), "AEG-BRW-PROXY")
    assert f and f[0].severity == Severity.MEDIUM
    assert not by_rule(scan(make_chrome(tmp_path / "x", prefs={"proxy": {"mode": "system"}})), "AEG-BRW-PROXY")
    assert by_rule(scan(make_chrome(tmp_path / "y", prefs={"proxy": {"mode": "pac_script", "pac_url": "http://x/p.pac"}})), "AEG-BRW-PROXY")


def test_saved_passwords_are_counted_not_read(tmp_path):
    base = make_chrome(tmp_path)
    db = base / "Default" / "Login Data"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE logins (origin_url TEXT, username_value TEXT, password_value BLOB)")
    for i in range(3):
        conn.execute("INSERT INTO logins VALUES (?,?,?)", (f"https://s{i}.example/", f"user{i}", b"SECRET-SENTINEL"))
    conn.commit()
    conn.close()
    items = scan(base)
    f = by_rule(items, "AEG-BRW-PWSTORE")
    assert len(f) == 1 and f[0].severity == Severity.LOW and f[0].evidence["saved_logins"] == 3
    blob = json.dumps([x.to_dict() for x in findings_of(items)])
    assert "SECRET-SENTINEL" not in blob and "user0" not in blob and "s0.example" not in blob
    assert db.exists()  # original untouched


def test_no_saved_passwords_no_finding(tmp_path):
    base = make_chrome(tmp_path)
    conn = sqlite3.connect(base / "Default" / "Login Data")
    conn.execute("CREATE TABLE logins (origin_url TEXT, password_value BLOB)")
    conn.commit()
    conn.close()
    assert not by_rule(scan(base), "AEG-BRW-PWSTORE")


# --------------------------------------------------------------------------- policies

def test_linux_policy_forcelist_unmanaged_high_managed_info(tmp_path):
    pol = tmp_path / "managed"
    write_json(pol / "x.json", {"ExtensionInstallForcelist": [f"{STORE_ID};https://clients2.google.com/service/update2/crx"],
                                "HomepageLocation": "https://search.safefinder.com/",
                                "DefaultSearchProviderSearchURL": "https://www.google.com/search?q={searchTerms}",
                                "RestoreOnStartupURLs": ["https://example.com/"],
                                "ProxyMode": "fixed_servers", "ProxyServer": "1.2.3.4:80"})
    entries = br.read_file_chromium_policies("chrome", [str(pol)])
    kinds = sorted({e.kind for e in entries})
    assert kinds == ["ext", "home", "proxy", "search", "startup"]
    unmanaged = br.analyse_policies(entries, FakeSigs(), managed=False)
    ext = [f for f in unmanaged if f.rule_id == "AEG-BRW-POLICY-EXT"]
    assert ext and ext[0].severity == Severity.HIGH
    hij = [f for f in unmanaged if f.rule_id == "AEG-BRW-POLICY-HIJACK"]
    assert any(f.severity == Severity.HIGH and "safefinder" in f.description for f in hij)  # known hijacker homepage
    assert any(f.severity == Severity.LOW for f in hij)  # google search policy: low
    assert any(f.severity == Severity.MEDIUM for f in hij)  # startup URL / proxy
    managed = br.analyse_policies(entries, FakeSigs(), managed=True)
    assert all(f.severity == Severity.INFO for f in managed)


def test_policy_forcelist_with_bad_extension_is_critical(tmp_path):
    entries = [br.PolicyEntry("chrome", "ext", "ExtensionInstallForcelist", f"{BAD_ID};https://x/u.xml", "src", ext_id=BAD_ID)]
    f = br.analyse_policies(entries, FakeSigs(bad_ext={BAD_ID}), managed=True)
    assert f[0].severity == Severity.CRITICAL


def test_windows_policy_registry_with_remediation(monkeypatch):
    base = r"SOFTWARE\Policies\Google\Chrome"
    values = {
        ("HKLM", base): {"HomepageLocation": "https://search.safefinder.com/", "Unrelated": 1},
        ("HKLM", base + r"\ExtensionInstallForcelist"): {"1": f"{STORE_ID};https://clients2.google.com/service/update2/crx"},
        ("HKCU", base + r"\RestoreOnStartupURLs"): {"1": "https://search.mystart.com/"},
    }
    monkeypatch.setattr(br, "reg_values", lambda hive, key, view64=True: dict(values.get((hive, key), {})))
    monkeypatch.setattr(br, "reg_subkeys", lambda hive, key, view64=True: (
        [k.rsplit("\\", 1)[1] for (h, k) in values if h == hive and k.startswith(key + "\\")] if key == base else []))
    monkeypatch.setattr(br, "IS_WINDOWS", True)
    entries = br.read_windows_chromium_policies("chrome", r"Google\Chrome")
    assert {e.name for e in entries} == {"HomepageLocation", "ExtensionInstallForcelist", "RestoreOnStartupURLs"}
    findings = br.analyse_policies(entries, FakeSigs(), managed=False)
    rems = {f.remediation.params["value"]: f.remediation.params for f in findings if f.remediation}
    assert rems["HomepageLocation"]["hive"] == "HKLM" and rems["HomepageLocation"]["key"] == base
    assert rems["1"]["key"].endswith("ExtensionInstallForcelist") or rems["1"]["key"].endswith("RestoreOnStartupURLs")
    ext = [f for f in findings if f.rule_id == "AEG-BRW-POLICY-EXT"][0]
    assert ext.severity == Severity.HIGH and ext.remediation.action == "delete_registry_value"


def test_registry_extension_scan(monkeypatch):
    root = r"SOFTWARE\Google\Chrome\Extensions"
    subs = {("HKLM", root, True): [REG_ID, UBLOCK_ID, "not-an-id"], ("HKCU", root, True): [BAD_ID]}
    vals = {("HKLM", f"{root}\\{REG_ID}"): {"update_url": "https://evil.example/u.xml"},
            ("HKLM", f"{root}\\{UBLOCK_ID}"): {"update_url": STORE_URL},
            ("HKCU", f"{root}\\{BAD_ID}"): {"path": r"C:\x.crx", "version": "1.0"}}
    monkeypatch.setattr(br, "IS_WINDOWS", True)
    monkeypatch.setattr(br, "reg_subkeys", lambda hive, key, view64=True: subs.get((hive, key, view64), []))
    monkeypatch.setattr(br, "reg_values", lambda hive, key, view64=True: vals.get((hive, key), {}))
    out = br.scan_registry_extensions(FakeSigs(bad_ext={BAD_ID}), managed=False)
    got = {f.evidence["extension_id"]: f for f in out}
    assert set(got) == {REG_ID, BAD_ID}
    assert got[BAD_ID].severity == Severity.CRITICAL and got[REG_ID].severity == Severity.MEDIUM
    assert got[REG_ID].remediation.params["value"] == "update_url"
    assert got[BAD_ID].remediation.params["value"] == "path"


def test_firefox_policies_json(tmp_path):
    p = tmp_path / "policies.json"
    write_json(p, {"policies": {"Extensions": {"Install": ["https://evil.example/x.xpi"]},
                                "Homepage": {"URL": "https://search.safefinder.com/", "Additional": ["https://example.com"]},
                                "Proxy": {"Mode": "manual", "HTTPProxy": "1.2.3.4:8080"}}})
    entries = br.read_firefox_policies_json([p])
    assert {e.kind for e in entries} == {"ext", "home", "startup", "proxy"}
    fs = br.analyse_policies(entries, FakeSigs(), managed=False)
    assert any(f.rule_id == "AEG-BRW-POLICY-EXT" and f.severity == Severity.HIGH for f in fs)


# --------------------------------------------------------------------------- Firefox

def lz4_literal_block(data: bytes) -> bytes:
    """Encode data as a literal-only LZ4 block (valid LZ4)."""
    n = len(data)
    out = bytearray()
    if n < 15:
        out.append(n << 4)
    else:
        out.append(15 << 4)
        rest = n - 15
        while rest >= 255:
            out.append(255)
            rest -= 255
        out.append(rest)
    return bytes(out) + data


def write_mozlz4(path: Path, obj):
    raw = json.dumps(obj).encode()
    path.write_bytes(b"mozLz40\0" + struct.pack("<I", len(raw)) + lz4_literal_block(raw))


def test_lz4_with_match_sequence():
    # "abcabcabcabc": literals "abc" then a match of length 9 at offset 3, then 5 literal-free end
    block = bytes([0x35]) + b"abc" + bytes([3, 0]) + bytes([0x10]) + b"Z"
    # token 0x35: 3 literals, match len 5+4=9 -> "abc" + 9 copied chars; final token 0x10: 1 literal "Z"
    assert br.lz4_block_decompress(block) == b"abc" + b"abcabcabc" + b"Z"


def make_firefox(tmp_path: Path, prefs="", user_js=None, addons=None, logins=0):
    base = tmp_path / "Firefox"
    prof = base / "Profiles" / "x.default-release"
    prof.mkdir(parents=True)
    (base / "profiles.ini").write_text("[Profile0]\nName=default-release\nIsRelative=1\nPath=Profiles/x.default-release\n")
    (prof / "prefs.js").write_text(prefs)
    if user_js is not None:
        (prof / "user.js").write_text(user_js)
    write_json(prof / "extensions.json", {"addons": addons or []})
    if logins:
        write_json(prof / "logins.json", {"logins": [{"id": i, "encryptedPassword": "AAAA"} for i in range(logins)]})
    return base, prof


def scan_ff(prof, sigs=None):
    return list(br.scan_firefox_profile("default-release", prof, "firefox", "Mozilla Firefox", sigs or FakeSigs(), False))


def addon(id_, name, **kw):
    d = {"id": id_, "type": "extension", "active": True, "userDisabled": False, "location": "app-profile", "signedState": 2,
         "defaultLocale": {"name": name}, "version": "1.0", "sourceURI": "https://addons.mozilla.org/firefox/downloads/file/1/x.xpi",
         "userPermissions": {"permissions": ["storage"], "origins": []}}
    d.update(kw)
    return d


def test_firefox_extensions(tmp_path):
    broad = {"permissions": ["webRequest", "webRequestBlocking", "cookies"], "origins": ["<all_urls>"]}
    base, prof = make_firefox(tmp_path, addons=[
        addon("ok@example.com", "Tab Tool"),
        addon("unsigned@example.com", "Shady", signedState=0, sourceURI="", userPermissions=broad),
        addon("sys@mozilla.org", "System", location="app-builtin", signedState=3),
        addon("theme@x", "A theme", type="theme", signedState=0),
        addon("amo-broad@example.com", "Amo Broad", userPermissions=broad),
    ])
    items = scan_ff(prof)
    side = by_rule(items, "AEG-BRW-EXT-SIDELOAD")
    assert [f.evidence["id"] for f in side] == ["unsigned@example.com"] and side[0].severity == Severity.HIGH
    rev = by_rule(items, "AEG-BRW-EXT-REVIEW")
    assert [f.evidence["id"] for f in rev] == ["amo-broad@example.com"]
    assert not any(f.evidence.get("id") == "ok@example.com" for f in findings_of(items))


def test_firefox_prefs_and_userjs(tmp_path):
    prefs = ('user_pref("browser.startup.homepage", "https://search.safefinder.com/");\n'
             'user_pref("network.proxy.type", 2);\nuser_pref("network.proxy.autoconfig_url", "http://evil/p.pac");\n'
             'user_pref("browser.safebrowsing.malware.enabled", false);\n'
             'user_pref("xpinstall.signatures.required", false);\n')
    base, prof = make_firefox(tmp_path, prefs=prefs, user_js='user_pref("browser.startup.homepage", "https://www.searchbaron.com/");\n',
                              logins=4)
    items = scan_ff(prof)
    assert by_rule(items, "AEG-BRW-HIJACK-HOME")[0].evidence["source"].startswith("user.js")
    assert by_rule(items, "AEG-BRW-PROXY")[0].severity == Severity.MEDIUM
    assert by_rule(items, "AEG-BRW-SAFEBROWSING")[0].severity == Severity.MEDIUM
    assert by_rule(items, "AEG-BRW-FF-SIGREQ")[0].severity == Severity.HIGH
    assert by_rule(items, "AEG-BRW-FF-USERJS")
    assert by_rule(items, "AEG-BRW-PWSTORE")[0].evidence["saved_logins"] == 4
    assert "AEG-BRW-SECRET" not in json.dumps([f.to_dict() for f in findings_of(items)])
    checks = {c.check_id.rsplit(".", 1)[1]: c.status for c in items if not isinstance(c, Finding)}
    assert checks["safebrowsing"] == CheckStatus.FAIL and checks["search"] == CheckStatus.FAIL


def test_firefox_clean_profile_has_no_findings(tmp_path):
    base, prof = make_firefox(tmp_path, prefs='user_pref("browser.startup.homepage", "about:home");\n'
                                              'user_pref("network.proxy.type", 5);\n')
    items = scan_ff(prof)
    assert findings_of(items) == []
    assert {c.status for c in items} == {CheckStatus.PASS}


def test_firefox_default_search_engine_from_mozlz4(tmp_path):
    base, prof = make_firefox(tmp_path)
    write_mozlz4(prof / "search.json.mozlz4", {"metaData": {"defaultEngineId": "evil-id"}, "engines": [
        {"id": "google@search.mozilla.org", "_name": "Google", "_isAppProvided": True,
         "_urls": [{"template": "https://www.google.com/search?q={searchTerms}"}]},
        {"id": "evil-id", "_name": "Fast Search", "_isAppProvided": False,
         "_urls": [{"template": "https://search.safefinder.com/?q={searchTerms}"}]}]})
    f = by_rule(scan_ff(prof), "AEG-BRW-HIJACK-SEARCH")
    assert f and f[0].severity == Severity.HIGH
    write_mozlz4(prof / "search.json.mozlz4", {"metaData": {"defaultEngineId": "google@search.mozilla.org"}, "engines": [
        {"id": "google@search.mozilla.org", "_name": "Google", "_isAppProvided": True,
         "_urls": [{"template": "https://www.google.com/search?q={searchTerms}"}]}]})
    assert not by_rule(scan_ff(prof), "AEG-BRW-HIJACK-SEARCH")


def test_parse_user_prefs(tmp_path):
    p = tmp_path / "prefs.js"
    p.write_text('// comment\nuser_pref("a.b", true);\nuser_pref("c", 5);\nuser_pref("d", "str\\"q");\nuser_pref("e", false);\n')
    assert br.parse_user_prefs(p) == {"a.b": True, "c": 5, "d": 'str"q', "e": False}


# --------------------------------------------------------------------------- whole scanner

def test_scanner_end_to_end(tmp_path, monkeypatch):
    from aegis.scanners.base import ScanContext

    base = make_chrome(tmp_path / "chrome", prefs={"safebrowsing": {"enabled": False}},
                       ext_settings={BAD_ID: {"location": 1, "from_webstore": True, "state": 1, "path": f"{BAD_ID}/1.0_0"}})
    add_extension(base / "Default", BAD_ID, {"name": "Evil", "version": "1.0"})
    ffbase, _prof = make_firefox(tmp_path / "ff")

    class Fake(br.BrowserScanner):
        def chromium_roots(self):
            return [br.BrowserRoot("chrome", "Google Chrome", base, "chromium"),
                    br.BrowserRoot("edge", "Microsoft Edge", tmp_path / "missing", "chromium")]

        def firefox_roots(self):
            return [br.BrowserRoot("firefox", "Mozilla Firefox", ffbase, "firefox")]

    monkeypatch.setattr(br, "read_file_chromium_policies", lambda *a, **k: [])
    monkeypatch.setattr(br, "firefox_policy_files", lambda: [])
    ctx = ScanContext(config=SimpleNamespace(), signatures=FakeSigs(bad_ext={BAD_ID}))
    items = list(Fake().run(ctx))
    rules = {f.rule_id for f in findings_of(items)}
    assert {"AEG-BRW-EXT-BAD", "AEG-BRW-SAFEBROWSING"} <= rules
    ids = {c.check_id for c in items if not isinstance(c, Finding)}
    assert "browser.chrome.default.extensions" in ids and "browser.chrome.default.safebrowsing" in ids
    assert "browser.chrome.policy" in ids and "browser.firefox.default-release.extensions" in ids
    assert all(f.scanner == "browser" and f.category == "browser" for f in findings_of(items))
    json.dumps([f.to_dict() for f in findings_of(items)])  # evidence is JSON-serialisable


def test_scanner_survives_corrupt_profile(tmp_path, monkeypatch):
    from aegis.scanners.base import ScanContext

    base = tmp_path / "ud"
    (base / "Default").mkdir(parents=True)
    (base / "Default" / "Preferences").write_text("{not json")

    class Fake(br.BrowserScanner):
        def chromium_roots(self):
            return [br.BrowserRoot("chrome", "Google Chrome", base, "chromium")]

        def firefox_roots(self):
            return []

    monkeypatch.setattr(br, "read_file_chromium_policies", lambda *a, **k: [])
    items = list(Fake().run(ScanContext(config=SimpleNamespace(), signatures=FakeSigs())))
    assert findings_of(items) == []


def test_scanner_registered():
    from aegis.scanners.base import REGISTRY

    assert REGISTRY["browser"] is br.BrowserScanner
    assert br.BrowserScanner().supported()
