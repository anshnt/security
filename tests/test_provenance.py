"""Tests for aegis.core.provenance: the Zone.Identifier, quarantine and kMDItemWhereFroms parsers (including garbage input),
the origin readers of every platform (the OS calls are stand-ins, so every branch runs on Linux and Windows), address helpers,
file-name deception (positive and negative names) and every classifier rule. Real OS tests write a genuine alternate data
stream on Windows and a genuine ``user.xdg.origin.url`` attribute on Linux and read them back through ``read_origin``."""

import os
import plistlib
import re
import subprocess
import sys
from pathlib import Path

import pytest

from aegis.core import provenance as prov
from aegis.core.models import Severity
from aegis.core.provenance import Origin

IP = "45.9.148.10"  # a public address (the documentation ranges count as private)
RLO = "\u202e"


def origin(host_url="", referrer_url="", zone=3, agent="", source="zone.identifier"):
    return Origin(zone, host_url, referrer_url, agent, source)


def rule_ids(reasons):
    return [r.rule_id for r in reasons]


def bad_hosts(*hosts):
    listed = {h.lower() for h in hosts}
    return lambda host: any(host == h or host.endswith("." + h) for h in listed)


# =========================================================================== Zone.Identifier
def test_zone_identifier_full_record():
    text = ("\ufeff[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://downloads.example/get\r\n"
            "HostUrl=https://cdn.example/files/setup.exe?token=abc\r\n")
    o = prov.parse_zone_identifier(text)
    assert o == Origin(3, "https://cdn.example/files/setup.exe?token=abc", "https://downloads.example/get", "", "zone.identifier")


@pytest.mark.parametrize("text", [
    "[zonetransfer]\nzoneid=3\nhosturl=https://cdn.example/a.exe\nreferrerurl=https://page.example/",  # lower case, LF
    "[ZONETRANSFER]\r\nZONEID=3\r\nHOSTURL=https://cdn.example/a.exe\r\nREFERRERURL=https://page.example/\r\n",
    "ZoneId=3\r\nHostUrl=https://cdn.example/a.exe\r\nReferrerUrl=https://page.example/",  # no section header
    "\ufeff\n\n; comment\n[ZoneTransfer]\n  ZoneId = 3  \n  HostUrl = https://cdn.example/a.exe  \n"
    "  ReferrerUrl = https://page.example/ \n# another\n",
    "[ZoneTransfer]\x00\nZoneId=3\x00\nHostUrl=https://cdn.example/a.exe\x00\nReferrerUrl=https://page.example/\n",
])
def test_zone_identifier_is_tolerant(text):
    o = prov.parse_zone_identifier(text)
    assert (o.zone, o.host_url, o.referrer_url, o.source) == (3, "https://cdn.example/a.exe", "https://page.example/",
                                                              "zone.identifier")


def test_zone_identifier_partial_and_foreign_sections():
    assert prov.parse_zone_identifier("[ZoneTransfer]\nZoneId=3\n") == Origin(3, "", "", "", "zone.identifier")
    assert prov.parse_zone_identifier("[ZoneTransfer]\nHostUrl=about:internet\n").zone is None
    other = prov.parse_zone_identifier("[Other]\nHostUrl=https://wrong.example/\n[ZoneTransfer]\nZoneId=3\n[Tail]\nZoneId=1")
    assert (other.zone, other.host_url) == (3, "")  # keys of other sections do not count
    first = prov.parse_zone_identifier("[ZoneTransfer]\nZoneId=3\nZoneId=1\n")
    assert first.zone == 3  # the first value wins
    junk_zone = prov.parse_zone_identifier("[ZoneTransfer]\nZoneId=abc\nHostUrl=https://x.example/a.exe\n")
    assert junk_zone.zone is None and junk_zone.host_url == "https://x.example/a.exe"


@pytest.mark.parametrize("text", ["", "   \n\n", "random text without equals", "[ZoneTransfer]", "ZoneId=abc",
                                  "[Other]\nZoneId=3", "\x00\x01\x02", None, 5, "=\n=\n["])
def test_zone_identifier_garbage_gives_none(text):
    assert prov.parse_zone_identifier(text) is None


def test_zone_identifier_caps_a_huge_address():
    o = prov.parse_zone_identifier("[ZoneTransfer]\nHostUrl=https://x.example/" + "a" * 10000)
    assert len(o.host_url) == prov.MAX_URL_CHARS


def test_decode_handles_utf8_bom_and_utf16():
    text = "[ZoneTransfer]\r\nZoneId=3\r\n"
    assert prov._decode(b"\xef\xbb\xbf" + text.encode()) == text
    assert prov._decode(text.encode("utf-16")) == text  # with a BOM
    assert prov._decode(b"\xff\xfe" + text.encode("utf-16-le")) == text
    assert prov._decode(b"\xfe\xff" + text.encode("utf-16-be")) == text
    assert prov._decode(b"[ZoneTransfer]\x80\x81\r\nZoneId=3").startswith("[ZoneTransfer]")  # undecodable bytes are replaced


# =========================================================================== macOS records
@pytest.mark.parametrize("value,agent", [
    ("0083;65a1b2c3;Safari;7E1C6F2A-0000-4C5B-9D9D-ABCDEF123456", "Safari"),
    ("0081;5f2d5a1c;Google Chrome;ABCD", "Google Chrome"),
    ("0181;5f2d5a1c;curl;", "curl"),
    ("0083;65a1b2c3;Sa\x00fa\x1fri;U", "Safari"),
    ("0083;65a1b2c3;;U", ""),
    ("0083;65a1b2c3", ""),
    ("0083", ""),
    ("", ""),
    (None, ""),
    ("garbage", ""),
])
def test_parse_quarantine(value, agent):
    assert prov.parse_quarantine(value) == agent


def test_parse_quarantine_caps_the_name():
    assert len(prov.parse_quarantine("0083;65a1b2c3;" + "A" * 500 + ";U")) == 80


@pytest.mark.parametrize("fmt", [plistlib.FMT_BINARY, plistlib.FMT_XML])
def test_parse_where_froms(fmt):
    data = plistlib.dumps(["https://dl.example/app.dmg?sig=1", "https://dl.example/"], fmt=fmt)
    assert prov.parse_where_froms(data) == ["https://dl.example/app.dmg?sig=1", "https://dl.example/"]


def test_parse_where_froms_keeps_positions_and_drops_non_text():
    blank_first = plistlib.dumps(["", "https://page.example/"], fmt=plistlib.FMT_BINARY)
    assert prov.parse_where_froms(blank_first) == ["", "https://page.example/"]
    mixed = plistlib.dumps(["https://a.example/", 7, None], fmt=plistlib.FMT_BINARY)
    assert prov.parse_where_froms(mixed) == ["https://a.example/", "", ""]


@pytest.mark.parametrize("data", [
    b"", b"garbage", b"bplist00", b"bplist00\x00\x01\x02\x03", None, "text", 12,
    plistlib.dumps({"a": "b"}, fmt=plistlib.FMT_BINARY), plistlib.dumps("https://x.example/", fmt=plistlib.FMT_BINARY),
    plistlib.dumps([1, 2], fmt=plistlib.FMT_BINARY), plistlib.dumps([], fmt=plistlib.FMT_BINARY),
    plistlib.dumps(["https://x.example/"], fmt=plistlib.FMT_BINARY)[:-6],  # truncated
    b"<?xml version='1.0'?><plist><array><string>unterminated",
])
def test_parse_where_froms_garbage_gives_nothing(data):
    assert prov.parse_where_froms(data) == []


# =========================================================================== readers of each platform
@pytest.fixture
def platform(monkeypatch):
    def pick(windows=False, mac=False):
        monkeypatch.setattr(prov, "IS_WINDOWS", windows)
        monkeypatch.setattr(prov, "IS_MAC", mac)
    return pick


def test_read_origin_windows_branch(platform, monkeypatch):
    platform(windows=True)
    text = "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://page.example/\r\nHostUrl=https://cdn.example/a.exe\r\n"
    seen = []

    def stream(path):
        seen.append(str(path))
        return b"\xef\xbb\xbf" + text.encode()

    monkeypatch.setattr(prov, "_read_stream", stream)
    o = prov.read_origin(Path("C:/Users/bob/Downloads/a.exe"))
    assert seen == [str(Path("C:/Users/bob/Downloads/a.exe"))]
    assert (o.zone, o.host_url, o.referrer_url, o.source) == (
        3, "https://cdn.example/a.exe", "https://page.example/", "zone.identifier")
    monkeypatch.setattr(prov, "_read_stream", lambda p: text.encode("utf-16"))  # an editor that saved the stream as UTF-16
    assert prov.read_origin("a.exe").zone == 3
    for missing in (None, b""):
        monkeypatch.setattr(prov, "_read_stream", lambda p, m=missing: m)
        assert prov.read_origin("a.exe") is None
    monkeypatch.setattr(prov, "_read_stream", lambda p: b"not a zone record")
    assert prov.read_origin("a.exe") is None


def test_read_origin_linux_branch(platform, monkeypatch):
    platform()
    attrs = {"user.xdg.origin.url": b"https://cdn.example/a.run", "user.xdg.referrer.url": b"https://page.example/\x00"}
    asked = []
    monkeypatch.setattr(prov, "_getxattr", lambda path, name: asked.append(name) or attrs.get(name))
    o = prov.read_origin("/home/bob/Downloads/a.run")
    assert o == Origin(None, "https://cdn.example/a.run", "https://page.example/", "", "xattr")
    assert asked == ["user.xdg.origin.url", "user.xdg.referrer.url"]
    attrs.pop("user.xdg.origin.url")
    assert prov.read_origin("x").referrer_url == "https://page.example/" and prov.read_origin("x").host_url == ""
    attrs.clear()
    assert prov.read_origin("x") is None


def test_read_origin_macos_branch(platform, monkeypatch):
    platform(mac=True)
    froms = plistlib.dumps(["https://dl.example/app.dmg", "https://dl.example/"], fmt=plistlib.FMT_BINARY)
    attrs = {"com.apple.quarantine": b"0083;65a1b2c3;Safari;UUID", "com.apple.metadata:kMDItemWhereFroms": froms}
    monkeypatch.setattr(prov, "_getxattr", lambda path, name: attrs.get(name))
    assert prov.read_origin("/Users/bob/Downloads/app.dmg") == Origin(None, "https://dl.example/app.dmg", "https://dl.example/",
                                                                      "Safari", "quarantine")
    del attrs["com.apple.quarantine"]  # where-froms alone (the app does not set the quarantine flag)
    o = prov.read_origin("x")
    assert (o.source, o.agent, o.host_url) == ("xattr", "", "https://dl.example/app.dmg")
    attrs["com.apple.quarantine"] = b"0083;65a1b2c3;Safari;UUID"
    del attrs["com.apple.metadata:kMDItemWhereFroms"]
    o = prov.read_origin("x")
    assert (o.source, o.agent, o.host_url, o.referrer_url) == ("quarantine", "Safari", "", "")
    attrs["com.apple.metadata:kMDItemWhereFroms"] = b"garbage"
    assert prov.read_origin("x").host_url == ""
    attrs.clear()
    assert prov.read_origin("x") is None


def test_read_origin_never_raises(platform, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("file system exploded")

    for windows, mac, name in ((True, False, "_read_stream"), (False, True, "_getxattr"), (False, False, "_getxattr")):
        platform(windows=windows, mac=mac)
        monkeypatch.setattr(prov, name, boom)
        assert prov.read_origin("anything") is None
    assert prov.read_origin(None) is None


def test_getxattr_dispatch_and_failures(platform, monkeypatch):
    platform(mac=True)
    monkeypatch.setattr(prov, "_mac_getxattr", lambda path, name: b"mac:" + name.encode())
    assert prov._getxattr("f", "a") == b"mac:a"
    monkeypatch.setattr(prov, "_mac_getxattr", lambda path, name: (_ for _ in ()).throw(OSError("no libc")))
    assert prov._getxattr("f", "a") is None
    platform()
    monkeypatch.setattr(os, "getxattr", lambda path, name: b"x" * (prov.MAX_ATTR_BYTES + 10), raising=False)
    assert len(prov._getxattr("f", "a")) == prov.MAX_ATTR_BYTES

    def enodata(path, name):
        raise OSError(61, "No data available")

    monkeypatch.setattr(os, "getxattr", enodata, raising=False)
    assert prov._getxattr("f", "a") is None
    monkeypatch.delattr(os, "getxattr", raising=False)  # Windows has no getxattr
    assert prov._getxattr("f", "a") is None


def test_attr_text_decodes_and_trims(monkeypatch):
    monkeypatch.setattr(prov, "_getxattr", lambda path, name: b"  https://x.example/\x00\n")
    assert prov._attr_text("f", "n") == "https://x.example/"
    monkeypatch.setattr(prov, "_getxattr", lambda path, name: b"a" * 5000)
    assert len(prov._attr_text("f", "n")) == prov.MAX_URL_CHARS
    monkeypatch.setattr(prov, "_getxattr", lambda path, name: None)
    assert prov._attr_text("f", "n") == ""


# ----- real operating-system records
@pytest.mark.skipif(sys.platform != "win32", reason="alternate data streams exist on NTFS only")
def test_real_zone_identifier_stream_is_read_back(tmp_path):
    f = tmp_path / "file.exe"
    f.write_bytes(b"MZ" + b"\0" * 64)
    assert prov.read_origin(f) is None  # no stream yet
    text = "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://page.example/dl\r\nHostUrl=https://cdn.example/file.exe?sig=1\r\n"
    try:
        with open(str(f) + ":Zone.Identifier", "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
    except OSError as exc:
        pytest.skip(f"this file system keeps no alternate data streams ({exc})")
    o = prov.read_origin(f)
    assert o == Origin(3, "https://cdn.example/file.exe?sig=1", "https://page.example/dl", "", "zone.identifier")
    assert prov.read_origin(str(f)) == o
    assert prov.origin_evidence(o)["host_url"] == "https://cdn.example/file.exe"
    assert prov.read_origin(tmp_path / "missing.exe") is None


@pytest.mark.skipif(not sys.platform.startswith("linux") or not hasattr(os, "setxattr"), reason="needs Linux extended attributes")
def test_real_xdg_origin_attributes_are_read_back(tmp_path):
    f = tmp_path / "setup.run"
    f.write_bytes(b"#!/bin/sh\n")
    assert prov.read_origin(f) is None  # nothing recorded yet
    try:
        os.setxattr(f, "user.xdg.origin.url", b"https://cdn.example/setup.run?sig=1")
        os.setxattr(f, "user.xdg.referrer.url", b"https://page.example/dl")
    except OSError as exc:  # tmpfs mounted without user xattrs, NFS, some container file systems
        pytest.skip(f"this file system keeps no user extended attributes ({exc})")
    o = prov.read_origin(f)
    assert o == Origin(None, "https://cdn.example/setup.run?sig=1", "https://page.example/dl", "", "xattr")
    only_url = tmp_path / "only.run"
    only_url.write_bytes(b"x")
    os.setxattr(only_url, "user.xdg.origin.url", b"http://45.9.148.10/only.run")
    assert prov.read_origin(only_url).referrer_url == ""
    assert prov.read_origin(tmp_path / "missing.run") is None
    assert prov.read_origin(tmp_path) is None  # a folder has no origin


@pytest.mark.skipif(sys.platform != "darwin", reason="needs the macOS quarantine attributes")
def test_real_macos_quarantine_and_where_froms_are_read_back(tmp_path):
    f = tmp_path / "app.dmg"
    f.write_bytes(b"x" * 16)
    froms = plistlib.dumps(["https://dl.example/app.dmg", "https://dl.example/"], fmt=plistlib.FMT_BINARY).hex()
    try:
        subprocess.run(["xattr", "-w", "com.apple.quarantine", "0083;65a1b2c3;Safari;7E1C6F2A", str(f)], check=True, timeout=20)
        subprocess.run(["xattr", "-w", "-x", "com.apple.metadata:kMDItemWhereFroms", froms, str(f)], check=True, timeout=20)
    except (OSError, subprocess.SubprocessError) as exc:
        pytest.skip(f"xattr is not usable here ({exc})")
    o = prov.read_origin(f)
    assert o == Origin(None, "https://dl.example/app.dmg", "https://dl.example/", "Safari", "quarantine")
    assert prov.read_origin(tmp_path / "missing.dmg") is None


# =========================================================================== addresses
@pytest.mark.parametrize("url,host", [
    ("https://CDN.Example.com/a/b.exe?x=1#f", "cdn.example.com"),
    ("http://user:pw@host.example:8080/a", "host.example"),
    ("https://[2606:4700:4700::1111]/a.exe", "2606:4700:4700::1111"),
    ("blob:https://evil.example/6f0e1d2c-aaaa-bbbb-cccc-123456789abc", "evil.example"),
    ("BLOB:http://45.9.148.10/uuid", "45.9.148.10"),
    ("data:text/html;base64,PGh0bWw+", ""),
    ("about:internet", ""),
    ("file:///C:/Users/bob/a.exe", ""),
    ("file://share.example/folder/a.exe", "share.example"),
    ("file://evil.example@SSL/DavWWWRoot/a.js", "evil.example"),
    ("file://evil.example@8080/DavWWWRoot/a.js", "evil.example"),
    ("\\\\evil.example@SSL\\DavWWWRoot\\a.lnk", "evil.example"),
    ("\\\\fileserver\\share\\a.exe", "fileserver"),
    ("", ""), (None, ""), ("not a url", ""), ("http://[::1", ""), ("C:\\Users\\bob\\a.exe", ""),
])
def test_url_host(url, host):
    assert prov.url_host(url) == host


@pytest.mark.parametrize("url,scheme", [
    ("https://x.example/", "https"), ("HTTP://x.example/", "http"), ("blob:https://x.example/u", "blob"), ("data:,x", "data"),
    ("file:///C:/a.exe", "file"), ("\\\\host\\share", "unc"), ("C:\\a.exe", ""), ("", ""), (None, ""), ("no scheme", ""),
])
def test_url_scheme(url, scheme):
    assert prov.url_scheme(url) == scheme


@pytest.mark.parametrize("url,remote", [
    ("\\\\evil.example@SSL\\DavWWWRoot\\invoice.lnk", True),
    ("\\\\evil.example\\share\\a.exe", True),
    ("file://evil.example/share/a.exe", True),
    ("file://evil.example@SSL/DavWWWRoot/a.exe", True),
    ("https://evil.example/DavWWWRoot/a.exe", True),
    ("file:///C:/Users/bob/a.exe", False),
    ("file://localhost/C$/a.exe", False),
    ("\\\\localhost\\c$\\a.exe", False),
    ("https://evil.example/a.exe", False),
    ("", False), (None, False),
])
def test_is_remote_share(url, remote):
    assert prov.is_remote_share(url) is remote


def test_safe_url_removes_query_fragment_and_credentials():
    assert prov.safe_url("https://u:pw@cdn.example/a/b.exe?X-Amz-Signature=SECRET&t=1#frag") == "https://cdn.example/a/b.exe"
    assert prov.safe_url("HTTP://Host.Example:8080/p?x=1") == "http://host.example:8080/p"
    assert prov.safe_url("ftp://ftp.example/pub/a.zip?x=1") == "ftp://ftp.example/pub/a.zip"
    assert prov.safe_url("https://[2606:4700::1111]/a?q=1") == "https://[2606:4700::1111]/a"
    assert prov.safe_url("blob:https://page.example/6f0e1d2c?x=1#y") == "blob:https://page.example/6f0e1d2c"
    assert prov.safe_url("blob:data:text/html,SECRET") == "blob:data:"
    assert prov.safe_url("blob:") == "blob:"
    assert prov.safe_url("data:text/html;base64," + "QUJD" * 5000) == "data:"
    assert prov.safe_url("file://user:pw@evil.example/share/a.exe?token=SECRET#x") == "file://evil.example/share/a.exe"
    assert prov.safe_url("\\\\evil.example@SSL\\DavWWWRoot\\a.lnk?x=SECRET") == "\\\\evil.example@SSL\\DavWWWRoot\\a.lnk"
    assert prov.safe_url("about:internet") == "" and prov.safe_url("") == "" and prov.safe_url(None) == ""
    assert prov.safe_url("javascript:alert(1)") == ""
    long_path = prov.safe_url("https://cdn.example/" + "a" * 400 + "?t=SECRET")
    assert long_path.endswith("...") and len(long_path) < 200 and "SECRET" not in long_path
    assert len(prov.safe_url("file://evil.example/" + "a" * 400)) < 200


def test_origin_evidence_never_carries_tokens():
    o = origin("https://cdn.example/a.exe?sig=SECRET1#frag", "https://page.example/dl?session=SECRET2", agent="Safari",
               source="quarantine", zone=None)
    ev = prov.origin_evidence(o)
    assert ev == {"origin_source": "quarantine", "zone": None, "host_url": "https://cdn.example/a.exe",
                  "referrer_url": "https://page.example/dl", "agent": "Safari"}
    assert "SECRET" not in str(prov.origin_evidence(origin("blob:https://x.example/u?sig=SECRET1", "data:text/html,SECRET2")))


def test_visible_spells_out_direction_controls():
    assert prov.visible("invoice_" + RLO + "fdp.exe") == "invoice_<U+202E>fdp.exe"
    assert prov.visible("a\u2066b\u2069") == "a<U+2066>b<U+2069>"
    assert prov.visible("plain name.exe") == "plain name.exe"


# =========================================================================== file names
@pytest.mark.parametrize("name,ext", [
    ("setup.exe", "exe"), ("Setup.EXE", "exe"), ("archive.tar.gz", "gz"), ("noextension", ""), ("", ""),
    ("trailing.exe   ", "exe"), ("report.docx      .exe", "exe"), ("x.library-ms", "library-ms"), ("x.exe\u200b\u3164", "exe"),
    (".hidden", "hidden"), ("x.exe\u202e", "exe"), ("x.ex\u202ee", "exe"),
])
def test_file_ext(name, ext):
    assert prov.file_ext(name) == ext


@pytest.mark.parametrize("name,mitre", [
    ("invoice.pdf.exe", "T1036.007"),
    ("photo.jpg.scr", "T1036.007"),
    ("Invoice.PDF.EXE", "T1036.007"),
    ("report.docx      .exe", "T1036.007"),  # blanks push the real extension out of view
    ("report.docx\u00a0\u00a0\u00a0\u00a0\u00a0\u00a0.exe", "T1036.007"),
    ("report.docx\u3164\u3164\u3164\u3164\u3164.exe", "T1036.007"),
    ("scan.pdf.js", "T1036.007"), ("notes.txt.lnk", "T1036.007"), ("movie.mp4.cmd", "T1036.007"), ("sheet.xlsx.msi", "T1036.007"),
    ("holiday.png.url", "T1036.007"), ("report.pdf.exe   ", "T1036.007"),
    ("invoice_" + RLO + "fdp.exe", "T1036.002"),
    ("photo\u202dgnp.scr", "T1036.002"),
    ("a\u2066b.exe", "T1036.002"),
    ("setup          .exe", "T1036"),  # padded, but with no fake extension
])
def test_deceptive_names_are_flagged_high(name, mitre):
    reasons = prov.deceptive_name(name)
    assert reasons and all(r.severity == Severity.HIGH and r.rule_id == "AEG-DL-DECEPTIVE" for r in reasons)
    assert mitre in {m for r in reasons for m in r.mitre}


@pytest.mark.parametrize("name", [
    "setup.1.2.3.exe", "archive.tar.gz", "invoice.pdf", "report.docx", "my.report.v2.exe", "photo.jpg", "installer.exe",
    "app.min.js", "jquery-3.7.1.min.js", "setup (1).exe", "readme.txt", "notes.pdf.zip", "backup.sql.gz",
    "python-3.12.4-amd64.exe", "Firefox Setup 128.0.exe", "node-v20.11.0-x64.msi", "report.final.pdf", "tool.exe.config",
    "a b c.exe", "", "exe", ".exe", "doc.pdf.exe.bak", "invoice.pdf.docx",
    "setup    .exe",  # four blanks are not padding
    "hello\u200fworld.exe", "\u200e\u0635\u0648\u0631\u0629.jpg",  # direction marks in genuine Arabic and Hebrew names
])
def test_ordinary_names_are_not_flagged(name):
    assert prov.deceptive_name(name) == []


def test_double_extension_reason_names_both_extensions():
    (reason,) = prov.deceptive_name("invoice.pdf.exe")
    assert ".pdf" in reason.text and ".exe" in reason.text
    (padded,) = prov.deceptive_name("report.docx      .exe")
    assert "blanks" in padded.text
    (bidi,) = prov.deceptive_name("x" + RLO + "y.txt")  # not executable, but the name itself is built to mislead
    assert "U+202E" in bidi.text


def test_name_with_both_tricks_gives_both_reasons():
    reasons = prov.deceptive_name("invoice.pdf" + RLO + ".exe")
    assert sorted(m for r in reasons for m in r.mitre) == ["T1036.002", "T1036.007"]


# =========================================================================== classifier: origin
def test_no_origin_means_no_origin_reasons():
    assert prov.classify_origin("setup.exe", None, bad_hosts("evil.example")) == []
    assert prov.classify_origin("setup.exe", Origin()) == []
    assert prov.classify_origin("setup.exe", origin("about:internet", "")) == []


def test_bad_source_from_the_download_address():
    reasons = prov.classify_origin("anything.bin", origin("https://dl.evil.example/a/b.bin?t=1"), bad_hosts("evil.example"))
    assert rule_ids(reasons) == ["AEG-DL-BADSOURCE"] and reasons[0].severity == Severity.HIGH
    assert "dl.evil.example" in reasons[0].text and set(reasons[0].mitre) == {"T1204.002", "T1105"}
    assert prov.classify_origin("a.exe", origin("https://good.example/a.exe"), bad_hosts("evil.example")) == []


def test_bad_source_from_the_referring_page_and_without_a_feed():
    listed = bad_hosts("evil.example")
    reasons = prov.classify_origin("a.exe", origin("https://github.com/x/a.exe", "https://evil.example/landing"), listed)
    assert rule_ids(reasons) == ["AEG-DL-BADSOURCE"] and "page that offered it" in reasons[0].text
    both = prov.classify_origin("a.exe", origin("https://evil.example/a.exe", "https://evil.example/landing"), listed)
    assert len(both) == 1  # one host, one reason
    two = prov.classify_origin("a.exe", origin("https://one.example/a.exe", "https://two.example/"),
                               bad_hosts("one.example", "two.example"))
    assert len(two) == 2
    assert prov.classify_origin("a.exe", origin("https://evil.example/a.exe", "https://evil.example/")) == []  # no feed loaded
    assert prov.classify_origin("a.exe", origin("https://evil.example/a.exe"), None) == []


def test_bad_source_applies_to_blob_and_raw_ip_addresses_too():
    listed = bad_hosts("evil.example", IP)
    assert "AEG-DL-BADSOURCE" in rule_ids(prov.classify_origin("a.iso", origin("blob:https://evil.example/uuid"), listed))
    assert "AEG-DL-BADSOURCE" in rule_ids(prov.classify_origin("a.exe", origin(f"http://{IP}/a.exe"), listed))


@pytest.mark.parametrize("name", ["a.iso", "a.img", "a.vhd", "a.vhdx", "a.zip", "a.rar", "a.7z", "a.exe", "a.msi", "a.js",
                                  "a.hta", "a.lnk", "a.ps1", "a.scr", "a.dmg", "a.url"])
@pytest.mark.parametrize("address", ["blob:https://page.example/6f0e1d2c-aaaa-bbbb-cccc-123456789abc",
                                     "data:application/zip;base64,UEsDBA==", "BLOB:https://page.example/x"])
def test_html_smuggling_for_containers_and_programs(name, address):
    reasons = prov.classify_origin(name, origin(address, "https://page.example/"))
    assert rule_ids(reasons) == ["AEG-DL-SMUGGLED"] and reasons[0].severity == Severity.MEDIUM
    assert "T1027.006" in reasons[0].mitre


@pytest.mark.parametrize("name,address", [
    ("report.docx", "blob:https://docs.example/u"),  # a web app exporting a document
    ("notes.txt", "data:text/plain,hello"),
    ("photo.png", "blob:https://photos.example/u"),
    ("macro.docm", "blob:https://docs.example/u"),
    ("setup.exe", "https://blob.example/setup.exe"),  # only the scheme counts
])
def test_blob_downloads_of_other_types_are_not_smuggling(name, address):
    assert "AEG-DL-SMUGGLED" not in rule_ids(prov.classify_origin(name, origin(address)))


@pytest.mark.parametrize("address", [f"http://{IP}/a.exe", f"https://{IP}:8443/dl/a.exe?x=1",
                                     "https://[2606:4700:4700::1111]/a.exe", "blob:http://45.9.148.10/uuid"])
def test_raw_ip_for_programs_and_scripts(address):
    reasons = prov.classify_origin("a.exe", origin(address))
    assert "AEG-DL-RAWIP" in rule_ids(reasons)
    rawip = next(r for r in reasons if r.rule_id == "AEG-DL-RAWIP")
    assert rawip.severity == Severity.MEDIUM and rawip.mitre == ("T1105",)


@pytest.mark.parametrize("name", ["a.exe", "a.msi", "a.ps1", "a.js", "a.bat", "a.sh", "a.deb", "a.appimage"])
def test_raw_ip_applies_to_every_executable_type(name):
    assert "AEG-DL-RAWIP" in rule_ids(prov.classify_origin(name, origin(f"https://{IP}/x")))


@pytest.mark.parametrize("name,host_url,referrer", [
    ("a.zip", f"https://{IP}/a.zip", ""),  # only programs and scripts
    ("a.exe", "https://192.168.1.20/a.exe", ""),  # a server on the local network
    ("a.exe", "https://10.0.0.5/a.exe", ""),
    ("a.exe", "https://127.0.0.1:8000/a.exe", ""),
    ("a.exe", "https://[::1]/a.exe", ""),
    ("a.exe", "https://example.com/a.exe", ""),
    ("a.exe", "https://999.1.1.1/a.exe", ""),
    ("a.exe", "https://" + IP + ".example.com/a.exe", ""),
])
def test_raw_ip_not_reported(name, host_url, referrer):
    assert "AEG-DL-RAWIP" not in rule_ids(prov.classify_origin(name, origin(host_url, referrer)))


def test_raw_ip_falls_back_to_the_referring_page():
    assert "AEG-DL-RAWIP" in rule_ids(prov.classify_origin("a.exe", origin("about:internet", f"http://{IP}/landing")))
    named_host = origin("https://cdn.example/a.exe", f"http://{IP}/landing")
    assert "AEG-DL-RAWIP" not in rule_ids(prov.classify_origin("a.exe", named_host))


@pytest.mark.parametrize("host", [
    "pastebin.com", "paste.ee", "rentry.co", "transfer.sh", "gofile.io", "catbox.moe", "files.catbox.moe", "anonfiles.com",
    "mediafire.com", "mega.nz", "cdn.discordapp.com", "media.discordapp.net", "bit.ly", "tinyurl.com", "is.gd", "t.ly", "temp.sh",
    "0x0.st", "file.io", "workupload.com", "pixeldrain.com", "download1234.mediafire.com", "WWW.PASTEBIN.COM"])
def test_file_hosts_for_programs_are_low(host):
    reasons = prov.classify_origin("update.exe", origin(f"https://{host}/get/update.exe"))
    assert rule_ids(reasons) == ["AEG-DL-FILEHOST"] and reasons[0].severity == Severity.LOW
    assert reasons[0].mitre == ("T1105",)


def test_every_listed_file_host_matches_itself():
    for entry in prov.FILE_HOSTS:
        assert "AEG-DL-FILEHOST" in rule_ids(prov.classify_origin("a.exe", origin(f"https://{entry}/a.exe"))), entry
        assert "AEG-DL-FILEHOST" in rule_ids(prov.classify_origin("a.exe", origin(f"https://sub.{entry}/a.exe"))), entry


@pytest.mark.parametrize("host", ["evilpastebin.com", "pastebin.com.evil.example", "notmega.nz", "mega.nz.example.org", "xbit.ly",
                                  "discordapp.com", "cdn.discordapp.com.evil.example", "example.com", "catbox.moe.evil.example",
                                  "pastebin-com.example", "my-tinyurl.com"])
def test_file_host_matching_is_by_domain_suffix_not_substring(host):
    assert "AEG-DL-FILEHOST" not in rule_ids(prov.classify_origin("update.exe", origin(f"https://{host}/update.exe")))


def test_file_host_is_for_programs_and_falls_back_to_the_referrer():
    assert prov.classify_origin("photos.zip", origin("https://mega.nz/file/x")) == []
    assert prov.classify_origin("notes.pdf", origin("https://pastebin.com/raw/x")) == []
    assert rule_ids(prov.classify_origin("a.exe", origin("blob:https://mega.nz/uuid"))) == ["AEG-DL-SMUGGLED", "AEG-DL-FILEHOST"]
    assert "AEG-DL-FILEHOST" in rule_ids(prov.classify_origin("a.exe", origin("data:application/octet-stream;base64,TVo=",
                                                                              "https://rentry.co/abc")))


@pytest.mark.parametrize("name", ["a.exe", "a.msi", "a.bat", "a.ps1", "a.vbs", "a.jar", "a.pkg", "a.rpm", "a.run"])
def test_plain_http_for_programs_is_low(name):
    reasons = prov.classify_origin(name, origin("http://downloads.example/get/" + name))
    assert rule_ids(reasons) == ["AEG-DL-INSECURE"] and reasons[0].severity == Severity.LOW


@pytest.mark.parametrize("name,host_url", [
    ("a.exe", "https://downloads.example/a.exe"),
    ("a.zip", "http://downloads.example/a.zip"),
    ("notes.pdf", "http://downloads.example/notes.pdf"),
    ("a.exe", "http://localhost:8000/a.exe"),
    ("a.exe", "http://127.0.0.1/a.exe"),
    ("a.exe", "http://192.168.1.5/a.exe"),
    ("a.exe", "ftp://downloads.example/a.exe"),
])
def test_http_not_reported(name, host_url):
    assert "AEG-DL-INSECURE" not in rule_ids(prov.classify_origin(name, origin(host_url)))


@pytest.mark.parametrize("name", ["invoice.lnk", "a.exe", "a.js", "a.ps1", "a.hta", "a.url", "a.search-ms", "a.library-ms"])
@pytest.mark.parametrize("address", ["\\\\evil.example@SSL\\DavWWWRoot\\folder\\x", "file://evil.example/share/x",
                                     "file://evil.example@SSL/DavWWWRoot/x", "https://evil.example/DavWWWRoot/x"])
def test_webdav_delivery(name, address):
    reasons = prov.classify_origin(name, origin(address))
    assert rule_ids(reasons) == ["AEG-DL-WEBDAV"] and reasons[0].severity == Severity.MEDIUM
    assert "evil.example" in reasons[0].text and reasons[0].mitre == ("T1105",)


@pytest.mark.parametrize("name,host_url", [
    ("a.exe", "file:///C:/Users/bob/Downloads/a.exe"),
    ("a.exe", "file://localhost/C$/a.exe"),
    ("a.exe", "\\\\localhost\\c$\\a.exe"),
    ("a.zip", "\\\\evil.example@SSL\\DavWWWRoot\\a.zip"),  # a container is not what WebDAV delivery drops
    ("macro.docm", "file://evil.example/share/macro.docm"),
    ("a.exe", "https://evil.example/a.exe"),
])
def test_webdav_not_reported(name, host_url):
    assert "AEG-DL-WEBDAV" not in rule_ids(prov.classify_origin(name, origin(host_url)))


def test_webdav_referrer_counts_too():
    o = origin("about:internet", "file://evil.example@SSL/DavWWWRoot/")
    assert rule_ids(prov.classify_origin("a.lnk", o)) == ["AEG-DL-WEBDAV"]


def test_reasons_are_sorted_strongest_first_and_stable():
    o = origin(f"http://{IP}/a.exe", "https://evil.example/landing")
    reasons = prov.classify_origin("a.exe", o, bad_hosts("evil.example"))
    assert rule_ids(reasons) == ["AEG-DL-BADSOURCE", "AEG-DL-RAWIP", "AEG-DL-INSECURE"]
    assert [r.severity for r in reasons] == [Severity.HIGH, Severity.MEDIUM, Severity.LOW]


def test_classify_download_adds_the_name_and_puts_the_strongest_first():
    o = origin(f"http://{IP}/invoice.pdf.exe", "https://evil.example/landing")
    reasons = prov.classify_download("invoice.pdf.exe", o, bad_hosts("evil.example"))
    assert rule_ids(reasons) == ["AEG-DL-BADSOURCE", "AEG-DL-DECEPTIVE", "AEG-DL-RAWIP", "AEG-DL-INSECURE"]  # origin first
    assert rule_ids(prov.classify_download("invoice.pdf.exe", None)) == ["AEG-DL-DECEPTIVE"]  # a name needs no origin
    blob = origin("blob:https://x.example/u")
    assert rule_ids(prov.classify_download("invoice.pdf.exe", blob)) == ["AEG-DL-DECEPTIVE", "AEG-DL-SMUGGLED"]
    assert prov.classify_download("setup.exe", origin("https://vendor.example/setup.exe", "https://vendor.example/")) == []
    assert prov.classify_download("setup.exe", None) == []


def test_every_reason_carries_attack_ids_and_text():
    samples = [prov.classify_download("a.exe", origin(f"http://{IP}/a.exe", "https://evil.example/"), bad_hosts("evil.example")),
               prov.classify_download("a.iso", origin("blob:https://pastebin.com/u")),
               prov.classify_download("a.exe", origin("https://mega.nz/a.exe")),
               prov.classify_download("a.lnk", origin("\\\\h@SSL\\DavWWWRoot\\a.lnk")),
               prov.classify_download("a.pdf.exe", None), prov.classify_download("a" + RLO + "b.exe", None),
               prov.classify_download("a      .exe", None)]
    for reasons in samples:
        assert reasons
        for r in reasons:
            assert r.text and r.mitre and all(re.fullmatch(r"T1\d{3}(\.\d{3})?", m) for m in r.mitre), r


def test_file_type_groups_are_consistent():
    assert prov.PROGRAM_EXTS.isdisjoint(prov.SCRIPT_EXTS)
    assert prov.EXECUTABLE_EXTS == prov.PROGRAM_EXTS | prov.SCRIPT_EXTS
    assert {"iso", "img", "vhd", "vhdx", "zip", "rar", "7z", "exe", "msi", "js", "hta", "lnk"} <= prov.SMUGGLED_EXTS
    assert prov.DISGUISED_EXTS <= prov.EXECUTABLE_EXTS | prov.SHORTCUT_EXTS
    assert prov.DISGUISED_EXTS.isdisjoint(prov.DECOY_EXTS)
    assert all(h == h.lower() and "/" not in h for h in prov.FILE_HOSTS)
