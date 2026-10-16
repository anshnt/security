"""Tests for the macOS login item collector (Background Task Management, ``sfltool dumpbtm``) and the code-signature review of
launch agents, daemons and login items (``codesign``). The tools' output is canned (tests/macos_samples.py), so everything
but the last section runs on any OS; that section runs the real tools and only runs on a Mac."""

import os
import plistlib
import re
import subprocess
import sys
from collections import Counter

import pytest

from aegis.core.models import CheckResult, CheckStatus, Finding, Severity
from aegis.scanners import persistence as ps
from tests import macos_samples as ms

S = Severity

# ATT&CK ids that v20 revoked (see tests/test_core.py::test_no_retired_attack_technique_ids)
RETIRED = {"T1562", "T1562.001", "T1562.002", "T1562.004", "T1562.006", "T1562.009", "T1070.001", "T1574.002", "T1656"}
posix_only = pytest.mark.skipif(os.name == "nt", reason="runs the POSIX collectors over a fake root")


@pytest.fixture
def tree(tmp_path):
    etc = tmp_path / "etc"
    home = tmp_path / "home" / "bob"
    etc.mkdir()
    home.mkdir(parents=True)
    return ps.LinuxPaths(etc=etc, spool=(tmp_path / "spool",), homes=(home,))


def collect(tree, dump=ms.BTM_DUMP):
    notes = []
    entries = ps.collect_btm(tree, notes, dump=lambda: (dump, ""))
    assert notes == []
    return entries


@pytest.fixture
def btm(tree):
    """The sample dump as entries, keyed by (uid, item type, name)."""
    return {(e["meta"]["uid"], e["meta"]["item_type"], e["name"]): e for e in collect(tree)}


def mini(name="Item", kind="login item", team="A1B2C3D4E5", disposition="[enabled, allowed, visible, notified] (0xf)",
         identifier="4.com.vendor.item", url="file:///Applications/Item.app/", uid="501"):
    """A dump with one record."""
    return (f"Records for UID {uid} : X\n #1:\n Name: {name}\n Developer Name: Vendor\n Team Identifier: {team}\n"
            f" Type: {kind}\n Disposition: {disposition}\n Identifier: {identifier}\n URL: {url}\n")


def judge(e, exists=lambda _p: True):
    return ps.assess_entry(e, None, (), exists)


def verdict(e, **kw):
    return ps.combined_severity(judge(e, **kw))


def texts(e):
    return [r.text for r in judge(e)]


def finding(e):
    return ps.finding_for_entry(e, judge(e))


# --------------------------------------------------------------------------- parsing sfltool dumpbtm

def test_every_record_of_the_dump_is_parsed():
    recs = ps.parse_btm_dump(ms.BTM_DUMP)
    assert len(recs) == 14
    assert Counter(r.uid for r in recs) == {"501": 8, "502": 1, "0": 5}
    assert Counter(r.kind for r in recs) == {"developer": 1, "agent": 5, "login item": 3, "app": 2, "daemon": 3}
    google = recs[0]
    assert (google.kind, google.team_id, google.developer, google.url, google.identifier) == (
        "developer", "EQHXZ8M8AV", "Google LLC", "", "")
    assert google.embedded == ["8.com.google.keystone.agent", "8.com.google.keystone.xpcservice"]
    keystone = recs[1]
    assert keystone.name == "GoogleSoftwareUpdateAgent" and keystone.type_text == "legacy agent (0x10008)"
    assert keystone.identifier == "8.com.google.keystone.agent" and keystone.parent == "Google LLC"
    assert keystone.url == "file:///Users/bob/Library/LaunchAgents/com.google.keystone.agent.plist"
    assert keystone.executable.endswith("/GoogleSoftwareUpdate.bundle/Contents/MacOS/GoogleSoftwareUpdateAgent")
    assert keystone.embedded == []  # "#1: <id>" lines only belong to the item they are in
    assert (keystone.enabled, keystone.allowed, keystone.visible) == (True, True, True)


def test_null_values_and_dispositions_of_the_sample():
    recs = {(r.uid, r.name, r.kind): r for r in ps.parse_btm_dump(ms.BTM_DUMP)}
    unsigned = recs[("501", "sysupdated", "agent")]
    assert unsigned.team_id == "" and unsigned.developer == ""  # "(null)"
    assert unsigned.executable == "/Users/bob/Library/Application Support/SysUpdate/sysupdated"
    apple = recs[("501", "AirPlayXPCHelper", "agent")]
    assert apple.developer == "Apple Inc." and apple.team_id == "" and apple.visible is False
    assert (apple.enabled, apple.allowed) == (True, True)
    off = [r for r in recs.values() if r.enabled is False]
    assert [(r.uid, r.identifier) for r in off] == [("501", "8.com.dropbox.DropboxMacUpdate.agent")]


@pytest.mark.parametrize("text,expected", [
    ("[enabled, allowed, visible, notified] (0xf)", (True, True, True)),
    ("[enabled, allowed, hidden, notified] (0xb)", (True, True, False)),
    ("[disabled, allowed, visible, notified] (0xe)", (False, True, True)),
    ("[enabled, disallowed, visible, not notified] (0x5)", (True, False, True)),
    ("[enabled, allowed, notified] (0xb)", (True, True, False)),  # no word for visibility: the bit says hidden
    ("[enabled, allowed, visible, notified] (0xb)", (True, True, True)),  # the words win over the bits
    ("(0x3)", (True, True, False)),
    ("(0x0)", (False, False, False)),
    ("[enabled, allowed]", (True, True, None)),
    ("", (None, None, None)),
    ("something new", (None, None, None)),
])
def test_disposition(text, expected):
    assert ps.parse_btm_disposition(text) == expected


@pytest.mark.parametrize("type_text,url,kind", [
    ("login item (0x4)", "", "login item"), ("agent (0x8)", "", "agent"), ("daemon (0x10)", "", "daemon"),
    ("app (0x2)", "", "app"), ("developer (0x20)", "", "developer"),
    ("legacy agent (0x10008)", "", "agent"), ("legacy daemon (0x10010)", "", "daemon"),
    ("curated legacy daemon (0x90010)", "", "daemon"),
    ("legacy agent/daemon", "file:///Library/LaunchDaemons/com.x.plist", "daemon"),
    ("legacy agent/daemon", "file:///Library/LaunchAgents/com.x.plist", "agent"),
    ("legacy agent/daemon", "", "agent"),
    ("(0x20)", "", "developer"), ("(0x10010)", "", "daemon"), ("(0x10008)", "", "agent"), ("(0x4)", "", "login item"),
    ("quicklook (0x40)", "", "unknown"), ("", "", "unknown"),
])
def test_item_kind(type_text, url, kind):
    assert ps.btm_kind(type_text, url) == kind


def test_the_parser_is_tolerant():
    ugly = ("noise before anything\r\n"
            "  records for uid -2 : X\r\n"
            "#1:  \r\n"
            "  name:   Odd   \r\n"
            "TEAM IDENTIFIER: (NULL)\r\n"
            "  Type: login item (0x4)\r\n"
            "  Disposition: [enabled, allowed, visible, notified] (0xf)\r\n"
            "  URL: file://localhost/Applications/Odd%20One.app/\r\n"
            "  Some Future Key: with: colons\r\n"
            "  continuation without a key\r\n"
            "  Name: ignored second name\r\n")
    (rec,) = ps.parse_btm_dump(ugly)
    assert (rec.uid, rec.name, rec.team_id, rec.kind) == ("-2", "Odd", "", "login item")
    assert ps.btm_item_path(rec, {}) == "/Applications/Odd One.app"
    assert ps.parse_btm_dump("") == [] and ps.parse_btm_dump("Records for UID 501 : X\n Items:\n") == []
    big = "Records for UID 1 : X\n" + "#1:\n Name: x\n" * (ps.MAX_BTM_RECORDS + 50)
    assert len(ps.parse_btm_dump(big)) == ps.MAX_BTM_RECORDS


# --------------------------------------------------------------------------- the collector

def test_every_record_becomes_an_entry(btm):
    assert len(btm) == 14 and {e["type"] for e in btm.values()} == {"btm"}
    for e in btm.values():
        assert {"type", "location", "name", "command", "path", "enabled"} <= set(e) and e["meta"]["mac"] is True
        assert e["location"] == f"Background Task Management (UID {e['meta']['uid']}, {e['meta']['item_type']})"
        assert e["meta"]["mitre"] and all(re.fullmatch(r"T\d{4}(\.\d{3})?", t) and t not in RETIRED for t in e["meta"]["mitre"])
    assert ps.TYPE_INFO["btm"] == ("AEG-PERS-BTM", "Login item / background task", ["T1547.015"])
    assert ps.display_location(btm[("501", "agent", "sysupdated")]) == (
        "Background Task Management (UID 501, agent) [sysupdated]")
    assert btm[("501", "agent", "Dropbox")]["enabled"] is False
    assert btm[("501", "login item", "Dropbox")]["enabled"] is True and ("502", "login item", "Dropbox") in btm


def test_mitre_follows_the_kind_of_item(btm):
    mitre = {kind: e["meta"]["mitre"] for (_u, kind, _n), e in btm.items()}
    assert mitre == {"developer": ["T1547.015"], "agent": ["T1543.001"], "login item": ["T1547.015"], "app": ["T1547.015"],
                     "daemon": ["T1543.004"]}


def test_commands_and_targets(btm):
    sys_ = btm[("501", "agent", "sysupdated")]
    assert sys_["path"] == "/Users/bob/Library/Application Support/SysUpdate/sysupdated"
    assert sys_["command"] == '"/Users/bob/Library/Application Support/SysUpdate/sysupdated"'
    assert btm[("0", "daemon", "com.example.tool")]["path"] == "/Library/PrivilegedHelperTools/com.example.tool"
    assert btm[("501", "login item", "Dropbox")]["path"] == "/Applications/Dropbox.app"  # file:// URL, no trailing slash
    assert btm[("501", "app", "Acme Sync")]["path"] == "/Applications/Acme Sync.app"  # %20 decoded
    assert btm[("501", "developer", "Google LLC")]["path"] == "" and btm[("501", "developer", "Google LLC")]["command"] == ""
    helper = btm[("501", "login item", "Acme Sync Helper")]  # URL relative to the parent app
    assert helper["path"] == "/Applications/Acme Sync.app/Contents/Library/LoginItems/AcmeSyncHelper.app"
    agent = btm[("0", "agent", "Backup Helper")]  # a plist that is not on this machine: no program to judge
    assert agent["path"] == "" and agent["command"].endswith("/Contents/Library/LaunchAgents/com.example.backup.agent.plist\"")


def test_the_program_of_a_legacy_item_comes_from_its_plist(tree):
    dump = """Records for UID 501 : X
 #1:
       Name: Plain
       Team Identifier: A1B2C3D4E5
       Type: legacy agent (0x10008)
       Disposition: [enabled, allowed, visible, notified] (0xf)
       Identifier: 8.com.plain.agent
       URL: file:///Users/bob/Library/LaunchAgents/com.plain.agent.plist
 #2:
       Name: Scripted
       Team Identifier: A1B2C3D4E5
       Type: legacy agent (0x10008)
       Disposition: [enabled, allowed, visible, notified] (0xf)
       Identifier: 8.com.scripted.agent
       URL: file:///Users/bob/Library/LaunchAgents/com.scripted.agent.plist
 #3:
       Name: Broken
       Team Identifier: A1B2C3D4E5
       Type: legacy agent (0x10008)
       Disposition: [enabled, allowed, visible, notified] (0xf)
       Identifier: 8.com.broken.agent
       URL: file:///Users/bob/Library/LaunchAgents/com.broken.agent.plist
"""
    agents = tree.at("/Users/bob/Library/LaunchAgents")
    agents.mkdir(parents=True)
    (agents / "com.plain.agent.plist").write_bytes(plistlib.dumps({"Label": "com.plain.agent", "ProgramArguments": [
        "/Applications/Plain App.app/Contents/MacOS/plain", "--background"]}))
    (agents / "com.scripted.agent.plist").write_bytes(plistlib.dumps({"Label": "x", "ProgramArguments": [
        "/bin/bash", "/Users/bob/Library/Application Support/x/run.sh"]}))
    (agents / "com.broken.agent.plist").write_text("not a plist")
    rows = {e["name"]: e for e in collect(tree, dump)}
    assert rows["Plain"]["path"] == "/Applications/Plain App.app/Contents/MacOS/plain"
    assert rows["Plain"]["command"] == '"/Applications/Plain App.app/Contents/MacOS/plain" --background'
    assert rows["Scripted"]["path"] == "/Users/bob/Library/Application Support/x/run.sh"  # the script, not the interpreter
    assert rows["Scripted"]["command"].startswith('/bin/bash "/Users/bob/Library/Application Support/x/run.sh"')
    assert rows["Broken"]["path"] == "" and rows["Broken"]["command"].endswith("/LaunchAgents/com.broken.agent.plist")


def test_records_with_the_same_name_stay_apart(tree):
    dump = "Records for UID 501 : X\n" + "".join(
        f" #{i}:\n Name: Same\n Type: login item (0x4)\n Team Identifier: A1B2C3D4E5\n URL: file:///Applications/S{i}.app/\n"
        for i in (1, 2, 3))
    assert [e["name"] for e in collect(tree, dump)] == ["Same", "Same #2", "Same #3"]


# --------------------------------------------------------------------------- judging the records

def test_apple_items_are_never_flagged(btm):
    for key in (("501", "agent", "AirPlayXPCHelper"), ("0", "daemon", "xprotectd")):
        e = btm[key]
        assert e["meta"]["apple"] is True and e["meta"]["visible"] is False and e["meta"]["team_id"] == ""
        assert judge(e) == [] and finding(e) is None
    apple = [k for k, e in btm.items() if e["meta"]["apple"]]
    assert apple == [("501", "agent", "AirPlayXPCHelper"), ("0", "daemon", "xprotectd")]


def test_identified_developers_are_not_flagged(btm):
    for key in (("501", "agent", "GoogleSoftwareUpdateAgent"), ("501", "login item", "Dropbox"), ("502", "login item", "Dropbox"),
                ("0", "daemon", "com.microsoft.autoupdate.helper")):
        assert judge(btm[key]) == [] and verdict(btm[key]) == S.INFO, key
    # nothing is missing from the point of view of a stale record: the database outlives the app
    assert verdict(btm[("0", "daemon", "com.microsoft.autoupdate.helper")], exists=lambda _p: False) == S.INFO
    assert judge(btm[("501", "agent", "Dropbox")]) == []  # switched off in System Settings: nothing runs


def test_no_team_identifier_is_low(btm):
    for key, mitre in ((("501", "agent", "sysupdated"), "T1543.001"), (("0", "daemon", "com.example.tool"), "T1543.004")):
        e = btm[key]
        assert verdict(e) == S.LOW and texts(e)[0].startswith("not signed by an identified developer")
        f = finding(e)
        assert f.rule_id == "AEG-PERS-BTM" and f.severity == S.LOW and f.mitre == [mitre]
        assert f.title.startswith("Login item / background task: ") and f.title.endswith("not signed by an identified developer")
        assert f.evidence["item_type"] == key[1] and f.evidence["team_id"] == ""
        assert f.evidence["identifier"].startswith(("8.", "16."))
    f = finding(btm[("501", "agent", "sysupdated")])
    assert f.location == "Background Task Management (UID 501, agent) [sysupdated]"
    assert f.evidence["path"].endswith("/SysUpdate/sysupdated") and "enabled, allowed, visible" in f.evidence["disposition"]


def test_hidden_but_enabled_is_low(btm):
    e = btm[("501", "login item", "Acme Sync Helper")]
    assert e["meta"]["team_id"] == "A1B2C3D4E5" and e["meta"]["visible"] is False
    assert verdict(e) == S.LOW and len(judge(e)) == 1 and texts(e)[0].startswith("hidden from System Settings > Login Items")
    f = finding(e)
    assert f.severity == S.LOW and f.mitre == ["T1547.015"] and f.title.endswith("hidden from System Settings > Login Items")


def test_a_hidden_item_that_does_not_run_is_not_reported(tree):
    for words in ("[disabled, allowed, hidden, notified] (0xa)", "[enabled, disallowed, hidden, notified] (0x9)"):
        (off,) = collect(tree, mini(disposition=words))
        assert off["enabled"] is False and judge(off) == [], words
    (on,) = collect(tree, mini(disposition="[enabled, allowed, hidden, notified] (0xb)"))
    assert on["enabled"] is True and verdict(on) == S.LOW
    (unknown,) = collect(tree, mini(disposition=""))  # a dump that says nothing about visibility says nothing against the item
    assert unknown["enabled"] is True and judge(unknown) == []


def test_apps_and_developers_are_inventoried_not_judged(btm):
    for key in (("501", "app", "Acme Sync"), ("0", "app", "Example Backup"), ("501", "developer", "Google LLC")):
        assert judge(btm[key]) == [] and finding(btm[key]) is None
    assert btm[("0", "app", "Example Backup")]["meta"]["team_id"] == ""  # unsigned, but only a container for its helpers
    assert verdict(btm[("0", "agent", "Backup Helper")]) == S.LOW  # the helper it registers is judged


def test_location_heuristics_still_apply_to_every_record(tree):
    def dump(identifier, team, path):
        return (f"Records for UID 501 : X\n #1:\n Name: Item\n Team Identifier: {team}\n Type: legacy agent (0x10008)\n"
                f" Disposition: [enabled, allowed, visible, notified] (0xf)\n Identifier: {identifier}\n"
                f" Executable Path: {path}\n")

    for path in ("/tmp/.x/payload", "/private/var/tmp/payload", "/Users/Shared/Library/payload"):
        (e,) = collect(tree, dump("8.com.evil.agent", "(null)", path))
        assert verdict(e) >= S.MEDIUM and any(r.kind == "location" for r in judge(e)), path
    # an identified developer in /tmp is still a program in /tmp; so is an item that only claims to be Apple's
    (signed,) = collect(tree, dump("8.com.vendor.agent", "A1B2C3D4E5", "/tmp/.x/payload"))
    assert verdict(signed) == S.MEDIUM and all(r.kind == "location" for r in judge(signed))
    (spoof,) = collect(tree, dump("8.com.apple.fake", "(null)", "/tmp/.x/payload"))
    assert spoof["meta"]["apple"] is True and verdict(spoof) >= S.MEDIUM
    assert all("identified developer" not in t for t in texts(spoof))
    (genuine,) = collect(tree, dump("8.com.apple.real", "(null)", "/System/Library/CoreServices/real"))
    assert judge(genuine) == []
    # only Apple can write to /System, so a file there is Apple's whatever the item calls itself
    (by_path,) = collect(tree, dump("8.com.nothing.agent", "(null)", "/System/Library/CoreServices/other"))
    assert by_path["meta"]["apple"] is True and judge(by_path) == []


def test_findings_of_the_sample_are_distinct(btm):
    findings = [f for e in btm.values() if (f := finding(e))]
    assert sorted(f.evidence["name"] for f in findings) == ["Acme Sync Helper", "Backup Helper", "com.example.tool", "sysupdated"]
    assert len({f.fingerprint for f in findings}) == 4 and {f.severity for f in findings} == {S.LOW}
    assert {tuple(f.mitre) for f in findings} == {("T1543.001",), ("T1543.004",), ("T1547.015",)}


# --------------------------------------------------------------------------- reading the dump

class FakeSfltool:
    def __init__(self, rc=0, out=ms.BTM_DUMP, err=""):
        self.calls, self.result = [], (rc, out, err)

    def __call__(self, cmd, timeout=60, input_text=None):
        self.calls.append((list(cmd), timeout))
        return self.result


def test_the_dump_is_skipped_without_root():
    fake = FakeSfltool()
    text, why = ps.read_btm_dump(admin=False, runner=fake, version="14.6")
    assert text is None and "sfltool dumpbtm needs root" in why and why.startswith("login items (Background Task Management)")
    assert fake.calls == []  # not even tried: a normal user must not wait for it


def test_the_dump_needs_macos_13():
    fake = FakeSfltool()
    text, why = ps.read_btm_dump(admin=True, runner=fake, version="12.7.6")
    assert text is None and "macOS 12.7.6" in why and fake.calls == []
    assert ps.read_btm_dump(admin=True, runner=fake, version="13.0")[0] == ms.BTM_DUMP
    assert ps.read_btm_dump(admin=True, runner=fake, version="")[0] == ms.BTM_DUMP  # unknown version: try


def test_the_dump_is_read_once_with_a_timeout():
    fake = FakeSfltool()
    assert ps.read_btm_dump(admin=True, runner=fake, version="15.0") == (ms.BTM_DUMP, "")
    assert fake.calls == [(["sfltool", "dumpbtm"], ps.BTM_TIMEOUT)]
    huge = FakeSfltool(out="x" * (ps.MAX_BTM_BYTES + 10))
    assert ps.read_btm_dump(admin=True, runner=huge, version="15.0")[0] == "x" * ps.MAX_BTM_BYTES


def test_a_missing_tool_is_a_note_and_any_other_failure_is_an_error():
    text, why = ps.read_btm_dump(admin=True, runner=FakeSfltool(-1, "", "not found: sfltool"), version="14.0")
    assert text is None and "sfltool is not installed" in why
    with pytest.raises(RuntimeError, match=r"sfltool dumpbtm failed \(exit 1\): Operation not permitted"):
        ps.read_btm_dump(admin=True, runner=FakeSfltool(1, "", "Operation not permitted\n"), version="14.0")
    with pytest.raises(RuntimeError, match="timeout after 30s"):
        ps.read_btm_dump(admin=True, runner=FakeSfltool(-1, "", "timeout after 30s: sfltool"), version="14.0")


def test_collect_btm_notes_a_skip_and_raises_on_output_it_cannot_read(tree):
    notes = []
    assert ps.collect_btm(tree, notes, dump=lambda: (None, "because")) == [] and notes == ["because"]
    assert ps.collect_btm(tree, None, dump=lambda: (None, "because")) == []
    for bad in ("", "sfltool: something new on stderr\n", "\n\n"):
        with pytest.raises(ValueError, match="without a 'Records for UID' section"):
            ps.collect_btm(tree, notes, dump=lambda b=bad: (b, ""))
    assert ps.collect_btm(tree, notes, dump=lambda: ("========\n Records for UID 501 : X\n========\n Items:\n", "")) == []
    with pytest.raises(ValueError, match="no '#<n>:' record could be read"):  # items under a marker this parser does not know
        ps.collect_btm(tree, notes, dump=lambda: ("Records for UID 501 : X\n Item 1\n   UUID: A\n   Name: B\n", ""))


@posix_only
def test_collect_all_reads_login_items_on_a_mac(tree, monkeypatch):
    monkeypatch.setattr(ps, "IS_WINDOWS", False)
    monkeypatch.setattr(ps, "IS_MAC", True)
    monkeypatch.setattr(ps, "collect_launchd", lambda dirs=None: [])
    monkeypatch.setattr(ps, "read_btm_dump", lambda: (ms.BTM_DUMP, ""))
    errors, notes = [], []
    entries = ps.collect_all(errors, linux_paths=tree, notes=notes)
    assert errors == [] and notes == [] and len([e for e in entries if e["type"] == "btm"]) == 14
    monkeypatch.setattr(ps, "read_btm_dump", lambda: (None, "needs root"))
    entries = ps.collect_all(errors, linux_paths=tree, notes=notes)
    assert errors == [] and notes == ["needs root"] and not [e for e in entries if e["type"] == "btm"]
    monkeypatch.setattr(ps, "read_btm_dump", lambda: (_ for _ in ()).throw(RuntimeError("sfltool dumpbtm failed (exit 1): boom")))
    ps.collect_all(errors, linux_paths=tree, notes=notes)
    assert errors == ["btm: RuntimeError: sfltool dumpbtm failed (exit 1): boom"]  # visible, not swallowed
    monkeypatch.setattr(ps, "IS_MAC", False)
    errors.clear()
    notes.clear()
    assert not [e for e in ps.collect_all(errors, linux_paths=tree, notes=notes) if e["type"] == "btm"] and notes == []


# --------------------------------------------------------------------------- reading codesign output

def test_codesign_display_developer_id():
    d = ps.parse_codesign_display(ms.CODESIGN_DEVELOPER_ID)
    assert d["authorities"] == ["Developer ID Application: Dropbox, Inc. (G7HH3F8CAK)", "Developer ID Certification Authority",
                                "Apple Root CA"]
    assert (d["team_id"], d["identifier"], d["adhoc"], d["runtime"]) == ("G7HH3F8CAK", "com.getdropbox.dropbox", False, True)


def test_codesign_display_apple_adhoc_and_nothing():
    d = ps.parse_codesign_display(ms.CODESIGN_APPLE)
    assert d["authorities"][0] == "Software Signing" and d["team_id"] == "" and not d["adhoc"] and not d["runtime"]
    d = ps.parse_codesign_display(ms.CODESIGN_ADHOC)
    assert d["authorities"] == [] and d["team_id"] == "" and d["adhoc"] is True and not d["runtime"]
    d = ps.parse_codesign_display(ms.CODESIGN_ADHOC.replace("Signature=adhoc\n", ""))
    assert d["adhoc"] is True  # the flag alone says it too
    d = ps.parse_codesign_display("")
    assert d == {"authorities": [], "team_id": "", "identifier": "", "adhoc": False, "runtime": False}
    assert ps.parse_codesign_display("CodeDirectory v=20500 flags=0x12000(library-validation,runtime)\n")["runtime"] is True


@pytest.mark.parametrize("rc,text,expected", [
    (0, "", ("valid", "")),
    (*ms.CODESIGN_VERIFY_UNSIGNED, ("unsigned", "code object is not signed at all")),
    (*ms.CODESIGN_VERIFY_SEALED, ("invalid", "a sealed resource is missing or invalid")),
    (*ms.CODESIGN_VERIFY_BADSIG, ("invalid", "invalid signature (code or signature have been modified)")),
    (1, "/x: main executable failed strict validation\n", ("invalid", "main executable failed strict validation")),
    (1, "/x: No such file or directory\n", ("unknown", "No such file or directory")),
    (-1, "timeout after 10s: codesign", ("unknown", "timeout after 10s: codesign")),
    (3, "", ("unknown", "codesign exited with 3")),
])
def test_codesign_verify(rc, text, expected):
    assert ps.parse_codesign_verify(rc, text) == expected


class FakeCodesign:
    """Answers codesign from {path: (verify (rc, text), describe text)} and records every call."""

    def __init__(self, table=None, rc_describe=0):
        self.table, self.calls, self.rc_describe = {} if table is None else table, [], rc_describe

    def __call__(self, cmd, timeout=60, input_text=None):
        self.calls.append((list(cmd), timeout))
        verify, describe = self.table[cmd[-1]]
        if cmd[1] == "--verify":
            return verify[0], "", verify[1]
        return (self.rc_describe, "", describe)


DEVELOPER_ID = (ms.CODESIGN_VERIFY_OK, ms.CODESIGN_DEVELOPER_ID)
APPLE = (ms.CODESIGN_VERIFY_OK, ms.CODESIGN_APPLE)
ADHOC = (ms.CODESIGN_VERIFY_OK, ms.CODESIGN_ADHOC)
UNSIGNED = (ms.CODESIGN_VERIFY_UNSIGNED, "")
INVALID = (ms.CODESIGN_VERIFY_SEALED, ms.CODESIGN_DEVELOPER_ID)  # signed by a developer, then modified


def test_inspect_signature_of_the_five_kinds_of_program():
    fake = FakeCodesign({"/dev": DEVELOPER_ID, "/apple": APPLE, "/adhoc": ADHOC, "/none": UNSIGNED, "/bad": INVALID})
    dev = ps.inspect_signature("/dev", fake)
    assert (dev.status, dev.signer, dev.team_id, dev.identifier, dev.hardened, dev.apple) == (
        "signed", "Developer ID Application: Dropbox, Inc. (G7HH3F8CAK)", "G7HH3F8CAK", "com.getdropbox.dropbox", True, False)
    apple = ps.inspect_signature("/apple", fake)
    assert (apple.status, apple.signer, apple.team_id, apple.apple) == ("signed", "Software Signing", "", True)
    adhoc = ps.inspect_signature("/adhoc", fake)
    assert (adhoc.status, adhoc.signer, adhoc.team_id, adhoc.apple) == ("adhoc", "ad-hoc", "", False)
    none = ps.inspect_signature("/none", fake)
    assert (none.status, none.signer, none.team_id) == ("unsigned", "unsigned", "")
    assert none.detail == "code object is not signed at all"
    bad = ps.inspect_signature("/bad", fake)
    assert (bad.status, bad.team_id, bad.detail) == ("invalid", "G7HH3F8CAK", "a sealed resource is missing or invalid")
    verify = ["codesign", "--verify", "--strict"]
    describe = ["codesign", "-dv", "--verbose=2"]
    assert [c for c, _t in fake.calls if c[-1] == "/dev"] == [verify + ["/dev"], describe + ["/dev"]]
    assert len([c for c, _t in fake.calls if c[-1] == "/none"]) == 1  # unsigned: nothing more to ask
    assert {t for _c, t in fake.calls} == {ps.CODESIGN_TIMEOUT}


def test_inspect_signature_when_codesign_cannot_answer():
    class Gone:
        def __call__(self, cmd, timeout=60, input_text=None):
            return -1, "", "timeout after 10s: codesign"

    sig = ps.inspect_signature("/x", Gone())
    assert sig.status == "unknown" and sig.detail == "timeout after 10s: codesign" and sig.signer == ""
    fake = FakeCodesign({"/x": ((1, "/x: No such file or directory\n"), "/x: No such file or directory\n")}, rc_describe=1)
    sig = ps.inspect_signature("/x", fake)
    assert sig.status == "unknown" and sig.detail == "No such file or directory"
    fake = FakeCodesign({"/x": ((0, ""), "/x: code object is not signed at all\n")}, rc_describe=1)
    assert ps.inspect_signature("/x", fake).status == "unsigned"  # the second opinion wins when verify had nothing to say
    fake = FakeCodesign({"/x": ((1, "/x: strange failure\n"), ms.CODESIGN_ADHOC)})
    sig = ps.inspect_signature("/x", fake)
    assert (sig.status, sig.signer, sig.detail) == ("unknown", "ad-hoc", "strange failure")


# --------------------------------------------------------------------------- what a signature means for an entry

def launchd_entry(program, *args, name="com.x.plist", where="/Users/bob/Library/LaunchAgents"):
    command, path = ps.launchd_program([program, *args])
    return ps.make_entry("launchd", where, name, command, path=path, mac=True, label=name[:-6])


def reasons_of(sig, path):
    return [(r["severity"], r["kind"], r["text"], r["mitre"]) for r in ps.signature_reasons(sig, path)]


@pytest.mark.parametrize("path,writable", [
    ("/Users/bob/Library/Application Support/x/agent", True), ("~/Library/Application Support/x/agent", True),
    ("/Users/Shared/agent", True), ("/tmp/agent", True), ("/private/tmp/agent", True), ("/private/var/folders/zz/T/agent", True),
    ("/var/folders/zz/T/agent", True), ("/var/tmp/agent", True),
    ("/Library/PrivilegedHelperTools/agent", False), ("/Applications/Foo.app/Contents/MacOS/foo", False),
    ("/usr/local/bin/agent", False), ("/opt/homebrew/bin/agent", False), ("/Users/bob/bin/agent", False),
    ("/Library/Application Support/x/agent", False)])
def test_user_writable_locations(path, writable):
    assert ps.mac_user_writable(path) is writable


def test_signature_reasons():
    unsigned, adhoc = ps.CodeSignature("unsigned", "unsigned"), ps.CodeSignature("adhoc", "ad-hoc")
    home, system = "/Users/bob/Library/Application Support/Foo/foo", "/Library/PrivilegedHelperTools/foo"
    sev, kind, text, mitre = reasons_of(unsigned, home)[0]
    assert (sev, kind, mitre) == ("MEDIUM", "signature", ["T1553.002"])
    assert text == f"autostart program is not code-signed in a user-writable location: {home}"
    sev, kind, text, _m = reasons_of(unsigned, system)[0]
    assert sev == "LOW" and "user-writable" not in text and text.endswith(system)
    assert reasons_of(adhoc, home)[0][0] == "MEDIUM" and "only ad-hoc signed in a user-writable" in reasons_of(adhoc, home)[0][2]
    assert reasons_of(adhoc, "/opt/homebrew/bin/foo")[0][0] == "LOW"
    bad = ps.CodeSignature("invalid", "Developer ID Application: X (A1B2C3D4E5)", "A1B2C3D4E5",
                           detail="a sealed resource is missing")
    for path in (home, system):
        assert reasons_of(bad, path) == [
            ("MEDIUM", "signature", "invalid code signature: a sealed resource is missing", ["T1553.002"])]
    assert reasons_of(ps.CodeSignature("invalid"), system)[0][2] == "invalid code signature: verification failed"


def test_identified_developers_and_apple_are_not_flagged():
    dev = ps.CodeSignature("signed", "Developer ID Application: Dropbox, Inc. (G7HH3F8CAK)", "G7HH3F8CAK")
    apple = ps.CodeSignature("signed", "Software Signing")
    for sig in (dev, apple, ps.CodeSignature("signed", ""), ps.CodeSignature("unknown", detail="x")):
        for path in ("/Users/bob/Library/Application Support/Foo/foo", "/Library/PrivilegedHelperTools/foo", "/tmp/foo"):
            assert ps.signature_reasons(sig, path) == []


def test_a_script_cannot_be_signed_so_it_only_counts_in_user_writable_places():
    script = ps.CodeSignature("script")
    home = "/Users/bob/Library/Application Support/x/run.sh"
    ((sev, kind, text, mitre),) = reasons_of(script, home)
    assert (sev, kind, mitre) == ("MEDIUM", "script", ["T1059"]) and text.startswith("autostart runs an unsigned script")
    for path in ("/usr/local/bin/backup.sh", "/Library/Scripts/backup.sh", "/Users/bob/bin/backup.sh"):
        assert reasons_of(script, path) == []
    assert reasons_of(script, "/tmp/run.sh") == []  # the script heuristic of assess_entry already says so


def test_the_signature_is_recorded_in_the_entry_and_the_finding():
    e = launchd_entry("/Users/bob/Library/Application Support/SysUpdate/sysupdated")
    other = launchd_entry("/Applications/Dropbox.app/Contents/MacOS/Dropbox", name="com.dropbox.plist")
    skipped = launchd_entry("/Library/PrivilegedHelperTools/other", name="com.other.plist")
    dropbox = ps.CodeSignature("signed", "Developer ID Application: Dropbox, Inc. (G7HH3F8CAK)", "G7HH3F8CAK", hardened=True)
    ps.apply_signatures([e, other, skipped], {
        e["path"]: ps.CodeSignature("unsigned", "unsigned", detail="code object is not signed at all"), other["path"]: dropbox})
    assert e["meta"]["signature"] == "unsigned" and e["meta"]["signer"] == "unsigned" and "team_id" not in e["meta"]
    assert other["meta"]["signer"].startswith("Developer ID Application") and other["meta"]["team_id"] == "G7HH3F8CAK"
    assert other["meta"]["hardened_runtime"] is True and "signature" not in skipped["meta"]
    assert judge(other) == [] and verdict(other) == S.INFO
    f = finding(e)
    assert f.rule_id == "AEG-PERS-LAUNCHD" and f.severity == S.MEDIUM and "T1553.002" in f.mitre
    assert f.evidence["signer"] == "unsigned" and f.evidence["signature"] == "unsigned"
    assert f.title.endswith("autostart program is not code-signed in a user-writable location")
    signed_team = launchd_entry("/Users/bob/Library/x/z")
    ps.apply_signatures([signed_team], {signed_team["path"]: ps.CodeSignature("signed", "Developer ID Application: X (T)", "T")})
    assert signed_team["meta"]["team_id"] == "T" and verdict(signed_team) == S.INFO  # even in ~/Library
    recorded = ps.make_entry("btm", "x", "y", "/Users/bob/Library/x/y", path="/Users/bob/Library/x/y", team_id="A1B2C3D4E5")
    ps.apply_signatures([recorded], {recorded["path"]: ps.CodeSignature("signed", "Developer ID Application: X (T)", "T")})
    assert recorded["meta"]["team_id"] == "A1B2C3D4E5"  # the team a btm record names is kept


def test_signature_stacks_with_other_evidence_but_not_with_itself(btm):
    unsigned = btm[("501", "agent", "sysupdated")]
    assert verdict(unsigned) == S.LOW  # "no Team Identifier" alone
    ps.apply_signatures([unsigned], {unsigned["path"]: ps.CodeSignature("unsigned", "unsigned")})
    assert verdict(unsigned) == S.MEDIUM and len(judge(unsigned)) == 2  # the same evidence twice is still one kind
    hidden = dict(unsigned, meta=dict(unsigned["meta"]))
    hidden_reason = ps.meta_reason(S.LOW, "hidden from System Settings > Login Items")
    hidden["meta"]["reasons"] = list(unsigned["meta"]["reasons"]) + [hidden_reason]
    assert verdict(hidden) == S.HIGH  # unsigned, in a user-writable place and hiding from the list


# --------------------------------------------------------------------------- which programs are checked

def code(_path):
    return "code"


def app(n):
    return f"/Applications/App{n:02d}.app/Contents/MacOS/App{n:02d}"


def entries_for(*paths, type_="launchd", **kw):
    return [ps.make_entry(type_, "/Library/LaunchDaemons", f"{i}.plist", p, path=p, mac=True, **kw) for i, p in enumerate(paths)]


def test_system_programs_are_not_checked():
    system = ["/System/Library/CoreServices/foo", "/usr/bin/true", "/usr/sbin/cron", "/bin/sh", "/sbin/launchd",
              "/usr/libexec/xpcd"]
    fake = FakeCodesign({"/usr/local/bin/mine": ADHOC, "/usr/lib/other": ADHOC})
    sigs, notes = ps.review_signatures(entries_for(*system, "/usr/local/bin/mine", "/usr/lib/other"), fake, code)
    assert sorted(sigs) == ["/usr/lib/other", "/usr/local/bin/mine"] and notes == []  # /usr/lib and /usr/local are not exempt
    assert not [c for c, _t in fake.calls if c[-1] in system]


def test_only_launchd_and_btm_entries_that_are_enabled_and_absolute_are_checked():
    fake = FakeCodesign({"/Applications/A.app": DEVELOPER_ID, "/Applications/B.app": DEVELOPER_ID})
    entries = (entries_for("/Applications/A.app") + entries_for("/Applications/B.app", type_="btm")
               + entries_for("/Applications/C.app", type_="cron") + entries_for("relative/path", "")
               + [ps.make_entry("launchd", "x", "off", "/Applications/D.app", path="/Applications/D.app", enabled=False),
                  ps.make_entry("btm", "x", "none", "", path="")])
    sigs, notes = ps.review_signatures(entries, fake, code)
    assert sorted(sigs) == ["/Applications/A.app", "/Applications/B.app"] and notes == []


def test_a_program_is_checked_once_however_many_entries_start_it():
    fake = FakeCodesign({"/Applications/A.app": DEVELOPER_ID})
    sigs, _n = ps.review_signatures(entries_for("/Applications/A.app", "/Applications/A.app") +
                                    entries_for("/Applications/A.app", type_="btm"), fake, code)
    assert len(sigs) == 1 and len(fake.calls) == 2


def test_the_budget_is_60_programs_and_the_rest_is_noted():
    paths = [app(n) for n in range(61)]
    fake = FakeCodesign({p: DEVELOPER_ID for p in paths})
    sigs, notes = ps.review_signatures(entries_for(*paths), fake, code)
    assert ps.MAX_CODESIGN_BINARIES == 60 and len(sigs) == 60 and app(60) not in sigs and app(0) in sigs
    assert len(fake.calls) == 120  # a verification and a description each
    assert notes == ["code signatures: 60 of 61 programs checked, 1 not checked (limit of 60 reached)"]
    sigs, notes = ps.review_signatures(entries_for(*paths[:60]), FakeCodesign({p: DEVELOPER_ID for p in paths}), code)
    assert len(sigs) == 60 and notes == []
    fake = FakeCodesign({p: DEVELOPER_ID for p in paths})
    sigs, notes = ps.review_signatures(entries_for(*paths), fake, code, limit=5)
    assert len(sigs) == 5 and "5 of 61" in notes[0] and "56 not checked" in notes[0]


def test_user_writable_programs_are_checked_first():
    exposed = [f"/Users/bob/Library/Application Support/Z{n:02d}/agent" for n in range(3)] + ["/tmp/zz", "/Users/Shared/zz"]
    paths = [app(n) for n in range(58)] + exposed
    fake = FakeCodesign({p: DEVELOPER_ID for p in paths})
    sigs, notes = ps.review_signatures(entries_for(*paths), fake, code)
    assert len(sigs) == 60 and set(exposed) <= set(sigs) and app(57) not in sigs and app(55) not in sigs
    assert "60 of 63" in notes[0]


def test_scripts_are_told_apart_and_do_not_use_the_budget():
    script, binary = "/Users/bob/Library/Application Support/x/run.sh", "/Applications/A.app"
    fake = FakeCodesign({binary: DEVELOPER_ID})
    sigs, notes = ps.review_signatures(entries_for(script, binary, "/Applications/Gone.app"), fake,
                                       lambda p: {script: "script", "/Applications/Gone.app": "missing"}.get(p, "code"))
    assert sorted(sigs) == [binary, script] and sigs[script].status == "script" and notes == []
    assert [c[-1] for c, _t in fake.calls] == [binary, binary]  # codesign never saw the script or the missing file
    many = [f"/Users/bob/Library/s{n}.sh" for n in range(70)]
    sigs, notes = ps.review_signatures(entries_for(*many), FakeCodesign(), lambda _p: "script")
    assert len(sigs) == 70 and notes == []


def test_the_interpreter_is_not_checked_its_script_is():
    entries = [launchd_entry("/bin/bash", "/Users/bob/Library/Application Support/x/run.sh", name="com.sh.plist"),
               launchd_entry("/usr/local/bin/python3", "/Users/bob/Library/y.py", name="com.py.plist"),
               launchd_entry("/opt/homebrew/bin/node", "/Users/bob/Library/Application Support/z/app.js", name="com.js.plist"),
               launchd_entry("/usr/bin/osascript", "/Users/bob/Library/Scripts/run.scpt", name="com.osa.plist")]
    assert [e["path"] for e in entries] == [
        "/Users/bob/Library/Application Support/x/run.sh", "/Users/bob/Library/y.py",
        "/Users/bob/Library/Application Support/z/app.js", "/Users/bob/Library/Scripts/run.scpt"]
    fake = FakeCodesign()
    sigs, notes = ps.review_signatures(entries, fake, lambda _p: "script")
    assert sorted(sigs) == sorted(e["path"] for e in entries) and notes == [] and fake.calls == []
    ps.apply_signatures(entries, sigs)
    for e in entries:
        assert e["meta"]["signature"] == "script" and "signer" not in e["meta"]
        assert verdict(e) == S.MEDIUM and texts(e)[0].startswith("autostart runs an unsigned script from a user-writable")
    # a script in a place only an administrator writes to cannot be signed either, and is not a reason
    safe = launchd_entry("/bin/bash", "/Library/Scripts/backup.sh", name="com.backup.plist", where="/Library/LaunchDaemons")
    ps.apply_signatures([safe], ps.review_signatures([safe], fake, lambda _p: "script")[0])
    assert safe["path"] == "/Library/Scripts/backup.sh" and judge(safe) == []


def test_a_time_budget_stops_the_checks():
    paths = [app(n) for n in range(10)]
    fake = FakeCodesign({p: DEVELOPER_ID for p in paths})
    ticks = iter([0.0, 1.0, 2.0, 3.0, ps.CODESIGN_BUDGET_S + 5, 500, 600, 700, 800, 900, 1000, 1100])
    sigs, notes = ps.review_signatures(entries_for(*paths), fake, code, clock=lambda: next(ticks))
    assert 0 < len(sigs) < 10 and len(fake.calls) == 2 * len(sigs)
    assert notes == [f"code signatures: {len(sigs)} of 10 programs checked, {10 - len(sigs)} not checked (time budget reached)"]


def test_programs_that_cannot_be_verified_are_noted():
    class Flaky(FakeCodesign):
        def __call__(self, cmd, timeout=60, input_text=None):
            if cmd[-1] == app(1):
                return -1, "", "timeout after 10s: codesign"
            return super().__call__(cmd, timeout, input_text)

    paths = [app(0), app(1), app(2)]
    sigs, notes = ps.review_signatures(entries_for(*paths), Flaky({p: DEVELOPER_ID for p in paths}), code)
    assert sigs[app(1)].status == "unknown" and sigs[app(0)].status == "signed"
    assert notes == ["code signatures: 1 program(s) could not be verified, e.g. App01: timeout after 10s: codesign"]
    entry = entries_for(app(1))[0]
    ps.apply_signatures([entry], sigs)
    assert entry["meta"]["signature"] == "unknown" and "signer" not in entry["meta"] and judge(entry) == []


def test_target_kind_of_real_files(tmp_path):
    macho = tmp_path / "tool"
    macho.write_bytes(b"\xcf\xfa\xed\xfe" + b"\0" * 28)
    fat = tmp_path / "fat"
    fat.write_bytes(b"\xca\xfe\xba\xbe" + b"\0" * 28)
    script = tmp_path / "run.sh"
    script.write_text("#!/bin/sh\ntrue\n")
    empty = tmp_path / "empty"
    empty.write_bytes(b"")
    bundle = tmp_path / "Foo.app"
    bundle.mkdir()
    assert [ps.codesign_target_kind(str(p)) for p in (macho, fat, script, empty, bundle, tmp_path / "gone")] == [
        "code", "code", "script", "script", "code", "missing"]


# --------------------------------------------------------------------------- the scanner end to end

class Answers(dict):
    """codesign answers by path; a program that is not listed is signed by a developer."""

    def __missing__(self, key):
        return DEVELOPER_ID


@pytest.fixture
def fake_mac(monkeypatch):
    """The persistence scanner on a pretend Mac: collect_all, codesign and the file kinds are canned."""
    monkeypatch.setattr(ps, "IS_WINDOWS", False)
    monkeypatch.setattr(ps, "IS_MAC", True)
    monkeypatch.setattr(ps, "codesign_target_kind", code)


def scan(ctx):
    out = list(ps.PersistenceScanner().run(ctx))
    return [o for o in out if isinstance(o, Finding)], [o for o in out if isinstance(o, CheckResult)]


def test_the_scanner_reviews_login_items_and_launch_agents(fake_mac, monkeypatch, ctx, tree):
    sysupdated = "/Users/bob/Library/Application Support/SysUpdate/sysupdated"
    launch = [launchd_entry(sysupdated, "--daemon", name="com.sysupdate.helper.plist"),
              launchd_entry("/Applications/Dropbox.app/Contents/MacOS/Dropbox", name="com.dropbox.plist"),
              launchd_entry("/Library/Homebrew/mine", name="homebrew.mine.plist", where="/Library/LaunchDaemons")]
    monkeypatch.setattr(ps, "collect_all", lambda errors=None, linux_paths=None, notes=None: (
        launch + ps.collect_btm(tree, notes, dump=lambda: (ms.BTM_DUMP, ""))))
    tampered = (ms.CODESIGN_VERIFY_SEALED, ms.CODESIGN_ADHOC)
    fake = FakeCodesign(Answers({sysupdated: UNSIGNED, "/Library/Homebrew/mine": ADHOC,
                                 "/Library/PrivilegedHelperTools/com.example.tool": tampered}))
    monkeypatch.setattr(ps, "run", fake)
    findings, checks = scan(ctx)
    # a launchd plist whose program is not on this machine is also reported as missing: look at the signature reasons only
    launchd = {f.evidence["name"]: f for f in findings if f.rule_id == "AEG-PERS-LAUNCHD"}
    sig = {name: [r for r in f.evidence["reasons"] if r["kind"] in ("signature", "script")] for name, f in launchd.items()}
    assert sorted(n for n, r in sig.items() if r) == ["com.sysupdate.helper.plist", "homebrew.mine.plist"]
    assert launchd["com.sysupdate.helper.plist"].severity == S.MEDIUM
    assert launchd["com.sysupdate.helper.plist"].evidence["signer"] == "unsigned"
    assert launchd["homebrew.mine.plist"].severity == S.LOW and launchd["homebrew.mine.plist"].evidence["signer"] == "ad-hoc"
    assert launchd["com.dropbox.plist"].evidence["reasons"] and not sig["com.dropbox.plist"]  # only "target file is missing"
    btm = {f.evidence["name"]: f for f in findings if f.rule_id == "AEG-PERS-BTM"}
    assert sorted(btm) == ["Acme Sync Helper", "Backup Helper", "com.example.tool", "sysupdated"]
    assert {n: btm[n].severity for n in btm} == {"Acme Sync Helper": S.LOW, "Backup Helper": S.LOW,
                                                 "com.example.tool": S.MEDIUM, "sysupdated": S.MEDIUM}
    assert btm["com.example.tool"].evidence["signature"] == "invalid" and btm["com.example.tool"].mitre[0] == "T1543.004"
    assert btm["sysupdated"].evidence["signer"] == "unsigned" and btm["sysupdated"].evidence["team_id"] == ""
    assert btm["Acme Sync Helper"].evidence["team_id"] == "A1B2C3D4E5" and btm["Acme Sync Helper"].mitre == ["T1547.015"]
    assert checks[-1].check_id == "AEG-PERS-CHK-AUTOSTART" and checks[-1].status == CheckStatus.FAIL
    assert not [c for c in checks if c.status == CheckStatus.ERROR]
    assert {c[0][0] for c in fake.calls} == {"codesign"} and len(fake.calls) <= 2 * ps.MAX_CODESIGN_BINARIES


def test_the_check_detail_carries_the_notes(fake_mac, monkeypatch, ctx):
    skip = "login items (Background Task Management) were not read: sfltool dumpbtm needs root, run Aegis with sudo"
    monkeypatch.setattr(ps, "collect_all", lambda errors=None, linux_paths=None, notes=None: (
        notes.append(skip) or entries_for(*[app(n) for n in range(63)], type_="btm")))
    monkeypatch.setattr(ps, "run", FakeCodesign(Answers()))
    findings, checks = scan(ctx)
    assert findings == [] and checks[-1].status == CheckStatus.PASS
    assert checks[-1].detail == (f"63 entries reviewed ({skip}; code signatures: 60 of 63 programs checked, 3 not checked "
                                 "(limit of 60 reached))")


def test_a_failing_review_is_an_error_check(fake_mac, monkeypatch, ctx):
    monkeypatch.setattr(ps, "collect_all", lambda errors=None, linux_paths=None, notes=None: entries_for(app(0), type_="btm"))
    monkeypatch.setattr(ps, "review_signatures", lambda entries: (_ for _ in ()).throw(KeyError("boom")))
    findings, checks = scan(ctx)
    errors = [c for c in checks if c.status == CheckStatus.ERROR]
    assert [(c.check_id, c.detail) for c in errors] == [("AEG-PERS-CHK-CODESIGN", "KeyError: 'boom'")]
    assert checks[-1].check_id == "AEG-PERS-CHK-AUTOSTART"  # the rest of the review still ran


@posix_only
def test_a_collector_error_is_an_error_check(fake_mac, monkeypatch, ctx, tree):
    monkeypatch.setattr(ps, "collect_launchd", lambda dirs=None: [])
    monkeypatch.setattr(ps, "read_btm_dump", lambda: ("sfltool: command line changed\n", ""))
    monkeypatch.setattr(ps, "LinuxPaths", lambda: tree)
    findings, checks = scan(ctx)
    errors = [c for c in checks if c.status == CheckStatus.ERROR]
    assert len(errors) == 1 and errors[0].check_id == "AEG-PERS-CHK-COLLECT"
    assert errors[0].detail.startswith("btm: ValueError: sfltool dumpbtm printed") and "not recognised" in errors[0].detail


def test_nothing_changes_off_the_mac(monkeypatch, ctx):
    monkeypatch.setattr(ps, "IS_WINDOWS", False)
    monkeypatch.setattr(ps, "IS_MAC", False)
    called = []
    monkeypatch.setattr(ps, "review_signatures", lambda entries: called.append(entries))
    monkeypatch.setattr(ps, "collect_all", lambda errors=None, linux_paths=None, notes=None: entries_for(app(0), type_="btm"))
    findings, checks = scan(ctx)
    assert called == [] and checks[-1].detail == "1 entries reviewed"


# --------------------------------------------------------------------------- the real tools (macOS only)

mac_only = pytest.mark.skipif(sys.platform != "darwin", reason="runs sfltool and codesign on a real Mac")


@mac_only
def test_real_btm_collector_skips_quietly_as_a_user_and_reads_the_dump_as_root():
    notes = []
    entries = ps.collect_btm(ps.LinuxPaths(), notes)
    if os.geteuid() != 0:
        assert entries == [] and len(notes) == 1 and "needs root" in notes[0]
        return
    assert len(notes) <= 1 and (entries or notes), "root read neither login items nor a reason for skipping"
    for e in entries:
        assert e["type"] == "btm" and {"type", "location", "name", "command", "path", "enabled", "meta"} <= set(e)
        assert e["location"].startswith("Background Task Management (UID ") and e["meta"]["item_type"] in ps.BTM_MITRE
        assert isinstance(e["enabled"], bool) and isinstance(judge(e), list)


@mac_only
def test_real_codesign_output_of_an_apple_app_is_understood():
    candidates = ["/System/Applications/Calculator.app", "/Applications/Safari.app",
                  "/System/Cryptexes/App/System/Applications/Safari.app"]
    path = next((p for p in candidates if os.path.isdir(p)), None)
    assert path, f"none of {candidates} exists on this Mac"
    sig = ps.inspect_signature(path)
    assert sig.status == "signed" and sig.apple and sig.signer in ps._APPLE_SIGNERS, sig
    assert sig.identifier.startswith("com.apple.")
    raw = subprocess.run(["codesign", "-dv", "--verbose=2", path], capture_output=True, text=True, timeout=30).stderr
    parsed = ps.parse_codesign_display(raw)
    assert parsed["authorities"][0] == sig.signer and parsed["authorities"][-1] == "Apple Root CA"
    assert parsed["team_id"] == "" and not parsed["adhoc"]  # Apple's own software has no Team Identifier
    assert ps.codesign_target_kind(path) == "code" and ps.codesign_target_kind("/usr/bin/true") == "code"
    assert ps.codesign_target_kind("/etc/hosts") == "script" and ps.codesign_target_kind("/nonexistent/x") == "missing"
    unsigned = subprocess.run(["codesign", "--verify", "--strict", "/etc/hosts"], capture_output=True, text=True, timeout=30)
    assert ps.parse_codesign_verify(unsigned.returncode, unsigned.stdout + unsigned.stderr)[0] == "unsigned"


@mac_only
def test_real_launch_agents_review_runs_without_errors():
    entries = [e for e in ps.collect_launchd() + ps.collect_btm(ps.LinuxPaths(), []) if e.get("enabled", True)]
    sigs, _notes = ps.review_signatures(entries)
    assert len([s for s in sigs.values() if s.status != "script"]) <= ps.MAX_CODESIGN_BINARIES
    assert {s.status for s in sigs.values()} <= {"signed", "adhoc", "unsigned", "invalid", "unknown", "script"}
    ps.apply_signatures(entries, sigs)
    for e in entries:
        for r in judge(e):
            assert r.text and isinstance(r.severity, Severity)


# ---- review adjustments: one finding per legacy item, Homebrew bottles, the dump cache

def test_a_legacy_item_whose_plist_launchd_listed_is_not_reported_twice():
    launchd = [ps.make_entry("launchd", "/Users/alice/Library/LaunchAgents", "com.evil.updater.plist", "/tmp/x", path="/tmp/x")]
    same = ps.make_entry("btm", "Background Task Management (UID 501, agent)", "updater", "/tmp/x", path="/tmp/x",
                         plist="/Users/alice/Library/LaunchAgents/com.evil.updater.plist")
    elsewhere = ps.make_entry("btm", "Background Task Management (UID 501, agent)", "helper", "/opt/h", path="/opt/h",
                              plist="/Library/Application Support/Vendor/com.vendor.helper.plist")
    login_item = ps.make_entry("btm", "Background Task Management (UID 501, login item)", "Dropbox", "/Applications/Dropbox.app",
                               path="/Applications/Dropbox.app", plist="")
    assert ps.without_listed_plists([same, elsewhere, login_item], launchd) == [elsewhere, login_item]
    assert ps.without_listed_plists([same], []) == [same]  # the launchd collector failed or did not see it: keep it


@pytest.mark.parametrize("path,flagged", [
    ("/opt/homebrew/Cellar/postgresql@16/16.4/bin/postgres", False),  # Homebrew ad-hoc signs every bottle on Apple silicon
    ("/opt/homebrew/opt/redis/bin/redis-server", False),
    ("/usr/local/Cellar/nginx/1.27.0/bin/nginx", False),
    ("/opt/homebrew/bin-not-brew/evil", True),
    ("/Users/alice/Library/Application Support/x/agent", True),
    ("/usr/local/bin/tool", True),
])
def test_ad_hoc_signed_homebrew_bottles_are_not_flagged(path, flagged):
    assert bool(ps.signature_reasons(ps.CodeSignature("adhoc", "ad-hoc"), path)) is flagged
    assert ps.signature_reasons(ps.CodeSignature("unsigned", "unsigned"), path)  # unsigned is never normal


def test_the_btm_dump_is_run_again_only_when_its_database_changed(monkeypatch, tmp_path):
    db = tmp_path / "com.apple.backgroundtaskmanagement"
    db.mkdir()
    (db / "BackgroundItems-v13.btm").write_bytes(b"x")
    monkeypatch.setattr(ps, "BTM_DB_DIR", db)
    monkeypatch.setattr(ps, "_BTM_CACHE", {})
    calls = []
    monkeypatch.setattr(ps, "read_btm_dump", lambda: calls.append(1) or ("dump text", ""))
    assert ps.cached_btm_dump() == ("dump text", "") and ps.cached_btm_dump() == ("dump text", "")
    assert len(calls) == 1
    (db / "BackgroundItems-v13.btm").write_bytes(b"changed")
    ps.cached_btm_dump()
    assert len(calls) == 2
    monkeypatch.setattr(ps, "read_btm_dump", lambda: calls.append(1) or (None, "needs root"))
    (db / "BackgroundItems-v13.btm").write_bytes(b"changed again")
    assert ps.cached_btm_dump() == (None, "needs root") and ps.cached_btm_dump() == (None, "needs root")
    assert len(calls) == 4  # a skip is never cached: running with sudo later must read the dump
