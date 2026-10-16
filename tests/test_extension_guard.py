"""Tests for aegis.realtime.extensions: baseline, new extensions in Chromium and Firefox profiles (read from real profile
files with the browser scanner's parsers), verdicts reused from the browser scanner, the cheap re-read rule, a profile
created after the baseline, switching the guard off and on, and the wiring into the real-time monitor."""

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from aegis.core.models import Severity
from aegis.realtime import extensions as ext
from aegis.realtime import monitor as M
from aegis.scanners import browser as br

STORE_URL = "https://clients2.google.com/service/update2/crx"
STORE_ID = "aaaabbbbccccddddeeeeffffgggghhhh"
OTHER_ID = "bbbbccccddddeeeeffffgggghhhhiiii"
BAD_ID = "ccccddddeeeeffffgggghhhhiiiijjjj"
UNPACKED_ID = "ddddeeeeffffgggghhhhiiiijjjjkkkk"


class FakeSigs:
    def __init__(self, bad_ext=()):
        self.bad_extensions = set(bad_ext)
        self.pup_names = []

    def is_bad_domain(self, d):
        return False


class FakeMonitor:
    def __init__(self, sigs=None, enabled=True):
        self.config = SimpleNamespace(realtime_extension_guard=enabled)
        self.signatures = sigs or FakeSigs()
        self.emitted = []

    def emit(self, finding, source=""):
        self.emitted.append((source, finding))
        return True


@pytest.fixture(autouse=True)
def _unmanaged(monkeypatch):
    monkeypatch.setattr(br, "is_managed_pc", lambda: False)


def write_json(p: Path, obj):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


def touch_later(p: Path):
    """Move the modification time on, as a browser saving its Preferences seconds later would."""
    st = p.stat()
    os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns + 5_000_000_000))


class Chrome:
    """A Chromium user-data folder with a Default profile whose extensions can be added the way Chrome records them."""

    def __init__(self, tmp_path: Path, name="User Data"):
        self.base = tmp_path / name
        self.profile = self.base / "Default"
        self.settings = {}
        self.save()

    def save(self):
        write_json(self.profile / "Preferences", {"extensions": {"settings": self.settings}})
        write_json(self.profile / "Secure Preferences", {})
        touch_later(self.profile / "Preferences")

    def add(self, ext_id, manifest, location=1, from_webstore=True, path=None):
        if path is None:
            d = self.profile / "Extensions" / ext_id / "1.0_0"
            write_json(d / "manifest.json", manifest)
            path = f"{ext_id}/1.0_0"
        self.settings[ext_id] = {"location": location, "from_webstore": from_webstore, "state": 1, "path": str(path)}
        self.save()

    def root(self):
        return br.BrowserRoot("chrome", "Google Chrome", self.base, "chromium")


def store_manifest(name, perms=("storage",)):
    return {"name": name, "version": "1.0", "manifest_version": 3, "update_url": STORE_URL, "permissions": list(perms)}


def guard_for(roots, sigs=None, enabled=True):
    mon = FakeMonitor(sigs, enabled)
    return ext.ExtensionGuard(mon, roots=lambda: roots), mon


def test_baseline_is_silent_and_a_new_store_extension_is_a_low_event(tmp_path):
    chrome = Chrome(tmp_path)
    chrome.add(STORE_ID, store_manifest("Tab Counter"))
    guard, mon = guard_for([chrome.root()])
    assert guard.tick() == [] and mon.emitted == []  # what is installed already was not installed just now
    assert guard.tick() == []
    chrome.add(OTHER_ID, store_manifest("Dark Reader", ("storage", "tabs")))
    (f,) = guard.tick()
    assert f.rule_id == "AEG-RT-EXTENSION" and f.severity == Severity.LOW and f.scanner == "realtime"
    assert f.title == "New browser extension: Dark Reader (Google Chrome)"
    assert f.evidence["id"] == OTHER_ID and f.evidence["source"] == "extension-guard" and f.mitre == ["T1176"]
    assert f.remediation is None and "Default" in f.description
    assert mon.emitted == [("extension-guard", f)]
    assert guard.tick() == []  # reported once


def test_new_sideloaded_or_malicious_extensions_get_the_browser_scanners_verdict(tmp_path):
    chrome = Chrome(tmp_path)
    guard, mon = guard_for([chrome.root()], FakeSigs(bad_ext={BAD_ID}))
    guard.tick()
    unpacked = tmp_path / "devext"
    write_json(unpacked / "manifest.json", {"name": "Helper", "version": "0.1", "permissions": ["webRequest", "<all_urls>"]})
    chrome.add(UNPACKED_ID, {}, location=4, from_webstore=False, path=unpacked)
    chrome.add(BAD_ID, store_manifest("Fast Video Downloader", ("tabs",)))
    found = {f.evidence["id"]: f for f in guard.tick()}
    side, bad = found[UNPACKED_ID], found[BAD_ID]
    assert side.rule_id == "AEG-BRW-EXT-SIDELOAD" and side.severity == Severity.HIGH
    assert side.title == "New extension - Sideloaded browser extension: Helper" and side.scanner == "realtime"
    assert side.evidence["source"] == "extension-guard"
    assert bad.rule_id == "AEG-BRW-EXT-BAD" and bad.severity == Severity.CRITICAL
    assert bad.remediation is not None and bad.remediation.action == "remove_path"
    assert all(src == "extension-guard" for src, _ in mon.emitted) and len(mon.emitted) == 2


def test_allow_listed_extensions_stay_low_even_with_broad_access(tmp_path):
    chrome = Chrome(tmp_path)
    guard, _ = guard_for([chrome.root()])
    guard.tick()
    chrome.add(STORE_ID, store_manifest("Bitwarden Password Manager", ("webRequest", "webRequestBlocking", "cookies",
                                                                       "<all_urls>")))
    (f,) = guard.tick()
    assert f.rule_id == "AEG-RT-EXTENSION" and f.severity == Severity.LOW


def test_an_unchanged_profile_is_not_read_again(tmp_path, monkeypatch):
    chrome = Chrome(tmp_path)
    chrome.add(STORE_ID, store_manifest("Tab Counter"))
    reads = []
    real = br.collect_chromium_extensions
    monkeypatch.setattr(br, "collect_chromium_extensions", lambda *a, **k: reads.append(a[0]) or real(*a, **k))
    guard, _ = guard_for([chrome.root()])
    guard.tick()
    guard.tick()
    guard.tick()
    assert len(reads) == 1
    chrome.add(OTHER_ID, store_manifest("Dark Reader"))
    assert len(guard.tick()) == 1 and len(reads) == 2


def test_a_profile_created_after_the_baseline_reports_its_extensions(tmp_path):
    first = Chrome(tmp_path)
    second = Chrome(tmp_path, "Edge Data")
    second.profile.joinpath("Preferences").unlink()  # not a profile yet
    second.profile.joinpath("Secure Preferences").unlink()
    edge = br.BrowserRoot("edge", "Microsoft Edge", second.base, "chromium")
    guard, _ = guard_for([first.root(), edge])
    guard.tick()
    second.add(STORE_ID, store_manifest("Coupon Finder"))
    (f,) = guard.tick()
    assert f.evidence["browser"] == "Microsoft Edge" and f.evidence["id"] == STORE_ID


def test_firefox_extensions_are_watched_too(tmp_path):
    base = tmp_path / "firefox"
    prof = base / "Profiles" / "abc.default-release"
    write_json(prof / "extensions.json", {"addons": []})
    root = br.BrowserRoot("firefox", "Mozilla Firefox", base, "firefox")
    guard, _ = guard_for([root])
    guard.tick()
    write_json(prof / "extensions.json", {"addons": [{
        "id": "helper@example.org", "type": "extension", "location": "app-profile", "active": True, "version": "2.1",
        "defaultLocale": {"name": "Page Helper"}, "userPermissions": {"permissions": ["tabs"], "origins": []},
        "signedState": 2, "sourceURI": "https://addons.mozilla.org/firefox/downloads/file/1/helper.xpi"}]})
    touch_later(prof / "extensions.json")
    (f,) = guard.tick()  # signed and from addons.mozilla.org: judged with the Firefox rules, not the Chromium ones
    assert f.rule_id == "AEG-RT-EXTENSION" and "Page Helper" in f.title and "Firefox" in f.title
    write_json(prof / "extensions.json", {"addons": [{
        "id": "helper@example.org", "type": "extension", "location": "app-profile", "active": True, "version": "2.1",
        "defaultLocale": {"name": "Page Helper"}, "userPermissions": {"permissions": ["tabs"], "origins": []},
        "signedState": 2, "sourceURI": "https://addons.mozilla.org/firefox/downloads/file/1/helper.xpi"}, {
        "id": "rogue@example.net", "type": "extension", "location": "app-profile", "active": True, "version": "0.1",
        "defaultLocale": {"name": "Rogue"}, "userPermissions": {"permissions": ["webRequest"], "origins": ["<all_urls>"]},
        "signedState": 0, "sourceURI": "file:///C:/Users/x/AppData/Local/Temp/rogue.xpi"}]})
    touch_later(prof / "extensions.json")
    (rogue,) = guard.tick()
    assert rogue.evidence["id"] == "rogue@example.net" and rogue.severity >= Severity.MEDIUM
    assert rogue.title.startswith("New extension - ")


def test_switching_the_guard_off_and_on_takes_a_fresh_baseline(tmp_path):
    chrome = Chrome(tmp_path)
    guard, mon = guard_for([chrome.root()])
    guard.tick()
    mon.config.realtime_extension_guard = False
    chrome.add(STORE_ID, store_manifest("Installed while the guard was off"))
    assert guard.tick() == []
    mon.config.realtime_extension_guard = True
    assert guard.tick() == []  # a new baseline, not a late alarm
    chrome.add(OTHER_ID, store_manifest("Dark Reader"))
    assert [f.evidence["id"] for f in guard.tick()] == [OTHER_ID]


def test_a_broken_profile_or_a_failing_verdict_never_stops_the_guard(tmp_path, monkeypatch):
    chrome = Chrome(tmp_path)
    guard, _ = guard_for([chrome.root(), br.BrowserRoot("chrome", "Ghost", tmp_path / "missing", "chromium")])
    guard.tick()
    (chrome.profile / "Preferences").write_text("{not json", encoding="utf-8")
    touch_later(chrome.profile / "Preferences")
    assert guard.tick() == []
    chrome.add(STORE_ID, store_manifest("Tab Counter"))
    monkeypatch.setattr(br, "classify_extension", lambda *a, **k: 1 / 0)
    assert guard.tick() == []  # logged, not raised


def test_user_homes_lists_other_users_only_with_admin_rights():
    assert ext.user_homes(admin=False) == [Path.home()]
    homes = ext.user_homes(admin=True)
    assert homes[0] == Path.home() and len(homes) == len({os.path.normcase(str(h)) for h in homes})


def test_browser_roots_of_another_user_follow_from_that_home(tmp_path):
    other = tmp_path / "alice"
    roots = ext.browser_roots([other])
    assert roots and all(str(r.base).startswith(str(other)) for r in roots)


def test_the_monitor_runs_the_extension_guard():
    assert "extensions" in M.ALL_COMPONENTS
    from aegis.core.config import Config

    assert Config().realtime_extension_guard is True
    mon = M.RealtimeMonitor.__new__(M.RealtimeMonitor)  # attribute check without starting threads
    mon.config = Config()
    guard = ext.ExtensionGuard(mon)
    assert guard.enabled() is True
