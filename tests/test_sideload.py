"""Unit tests for aegis.scanners.sideload: light PE parsing, scoring of EXE/DLL pairs, folder walking and the scanner
(synthetic but well-formed PE files are built on the fly)."""

import json
import os
import struct
from pathlib import Path

import pytest

from aegis.core.models import CheckResult, CheckStatus, Finding, Severity
from aegis.scanners import sideload as sl
from aegis.scanners.base import REGISTRY, load_all


# ---------------------------------------------------------------- synthetic PE builder
def build_pe(imports=(), dll=False, signed=False, forwarders=(), padding=b""):
    """A minimal well-formed PE32+ with one .rdata section holding an import table (DLL names only), optional export
    forwarders and an optional (fake) Authenticode signature directory."""
    sec = bytearray(b"\0" * ((len(imports) + 1) * 20))
    for i, name in enumerate(imports):
        rva = 0x1000 + len(sec)
        sec += name.encode() + b"\0"
        struct.pack_into("<IIIII", sec, i * 20, 0, 0, 0, rva, 0)
    exp_rva = exp_size = 0
    if forwarders:
        while len(sec) % 4:
            sec += b"\0"
        exp_off = len(sec)
        exp_rva = 0x1000 + exp_off
        sec += b"\0" * (40 + 4 * len(forwarders))
        rvas = []
        for f in forwarders:
            rvas.append(0x1000 + len(sec))
            sec += f.encode() + b"\0"
        exp_size = len(sec) - exp_off
        struct.pack_into("<I", sec, exp_off + 20, len(forwarders))  # NumberOfFunctions
        struct.pack_into("<I", sec, exp_off + 28, 0x1000 + exp_off + 40)  # AddressOfFunctions
        for i, r in enumerate(rvas):
            struct.pack_into("<I", sec, exp_off + 40 + 4 * i, r)
    sec += padding
    raw = bytes(sec) + b"\0" * (-len(sec) % 0x200)

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0x5F000000, 0, 0, 0xF0, 0x2022 if dll else 0x0022)
    opt = bytearray(0xF0)
    struct.pack_into("<H", opt, 0, 0x20B)
    struct.pack_into("<Q", opt, 24, 0x140000000)
    struct.pack_into("<II", opt, 32, 0x1000, 0x200)
    struct.pack_into("<I", opt, 56, 0x2000 + len(raw))
    struct.pack_into("<I", opt, 60, 0x200)
    struct.pack_into("<H", opt, 68, 3)
    struct.pack_into("<I", opt, 108, 16)
    if exp_rva:
        struct.pack_into("<II", opt, 112, exp_rva, exp_size)
    struct.pack_into("<II", opt, 112 + 8, 0x1000, (len(imports) + 1) * 20)
    cert_off = 0x200 + len(raw)
    if signed:
        struct.pack_into("<II", opt, 112 + 8 * 4, cert_off, 0x200)
    shdr = struct.pack("<8sIIIIIIHHI", b".rdata", len(sec), 0x1000, len(raw), 0x200, 0, 0, 0, 0, 0x40000040)
    head = bytes(dos) + b"PE\0\0" + coff + bytes(opt) + shdr
    head += b"\0" * (0x200 - len(head))
    out = head + raw
    if signed:
        out += b"\x30" * 0x200
    return out


def write(dirpath: Path, name: str, data: bytes) -> str:
    p = dirpath / name
    p.write_bytes(data)
    return str(p)


def pef(name, signed=False, dll=False, imports=(), forwarders=(), entropy=0.0, size=50_000, path=None):
    return sl.PEFile(path=path or f"/tmp/x/{name}", name=name.lower(), size=size, signed=signed, is_dll=dll,
                     imports={i.lower() for i in imports}, forwarders=list(forwarders), entropy=entropy)


# ---------------------------------------------------------------- light parser
def test_parse_pe_light_imports_signature_exports():
    exe = sl.parse_pe_light(build_pe(imports=["KERNEL32.dll", "version.dll"], signed=True))
    assert exe.ok and not exe.is_dll and exe.signed and exe.imports == {"kernel32.dll", "version.dll"}
    dll = sl.parse_pe_light(build_pe(dll=True, forwarders=["version_orig.GetFileVersionInfoA", "version_orig.VerQueryValueW",
                                                           "version_orig.GetFileVersionSizeW"]))
    assert dll.ok and dll.is_dll and not dll.signed and len(dll.forwarders) == 3
    assert dll.forwarders[0] == "version_orig.GetFileVersionInfoA"


def test_parse_pe_light_never_raises_on_junk():
    for blob in (b"", b"MZ", b"MZ" + b"\0" * 100, os.urandom(4096), b"\x7fELF" + b"\0" * 64,
                 build_pe(imports=["a.dll"])[:300], build_pe(imports=["a.dll"])[:0x1a0]):
        info = sl.parse_pe_light(blob)
        assert isinstance(info, sl.PELight)
    assert not sl.parse_pe_light(b"MZ" + b"\0" * 100).ok


def test_sample_entropy():
    assert sl.sample_entropy(b"") == 0.0 and sl.sample_entropy(b"\0" * 1000) == 0.0
    assert sl.sample_entropy(os.urandom(50_000)) > 7.9
    assert 0.9 < sl.sample_entropy(b"ab" * 1000) < 1.1
    assert sl.sample_entropy(os.urandom(10_000_000)) > 7.9  # large inputs are sampled


# ---------------------------------------------------------------- scoring (pure)
SYS = {"version.dll", "winhttp.dll", "kernel32.dll"}


def test_signed_host_importing_hijackable_dll_in_drop_location():
    host = pef("updater.exe", signed=True, imports=["version.dll", "kernel32.dll"])
    c = sl.evaluate_dir([host], [pef("version.dll", dll=True)], SYS, loc_risk=2)
    assert len(c) == 1 and c[0].score == 20 + 25 + 15 and c[0].severity == Severity.MEDIUM
    assert c[0].hosts == [host] and any("imports version.dll" in r for r in c[0].reasons)


def test_entropy_and_proxy_exports_raise_severity():
    host = pef("updater.exe", signed=True, imports=["version.dll"])
    hi = sl.evaluate_dir([host], [pef("version.dll", dll=True, entropy=7.9)], SYS, 2)[0]
    assert hi.severity == Severity.HIGH and any("random data" in r for r in hi.reasons)
    proxy = sl.evaluate_dir([host], [pef("version.dll", dll=True, forwarders=["a.X", "a.Y", "a.Z"])], SYS, 1)[0]
    assert proxy.score == 20 + 25 + 8 + 20 and proxy.severity == Severity.HIGH and any("proxy" in r for r in proxy.reasons)


def test_signed_dll_and_unrelated_unsigned_files_are_ignored():
    host = pef("app.exe", signed=True, imports=["version.dll", "plugin.dll"])
    assert sl.evaluate_dir([host], [pef("version.dll", dll=True, signed=True)], SYS, 2) == []  # Microsoft-style signed copy
    # custom-named plug-in imported by the EXE but ordinary entropy: not reported
    assert sl.evaluate_dir([host], [pef("plugin.dll", dll=True, entropy=5.1)], SYS, 2) == []
    # a DLL that nothing imports and that has no system name
    assert sl.evaluate_dir([host], [pef("random.dll", dll=True, entropy=7.9)], SYS, 2) == []
    # no exe at all
    assert sl.evaluate_dir([], [pef("version.dll", dll=True)], SYS, 2) == []


def test_unsigned_host_needs_a_suspicious_dll():
    unsigned_exe = pef("tool.exe", signed=False, imports=["version.dll"])
    assert sl.evaluate_dir([unsigned_exe], [pef("version.dll", dll=True, entropy=5.0)], SYS, 2) == []
    got = sl.evaluate_dir([unsigned_exe], [pef("version.dll", dll=True, entropy=7.9)], SYS, 2)
    assert got and got[0].severity >= Severity.MEDIUM


def test_name_only_match_is_low_in_drop_dirs_and_silent_in_user_dirs():
    host = pef("app.exe", signed=True, imports=["kernel32.dll"])  # does not import the DLL
    dll = pef("winhttp.dll", dll=True)
    assert sl.evaluate_dir([host], [dll], SYS, 2)[0].severity == Severity.LOW  # 20 + 15
    assert sl.evaluate_dir([host], [dll], SYS, 1)[0].severity is None  # 28 - below the reporting threshold
    assert sl.evaluate_dir([host], [dll], SYS, 0)[0].severity is None


def test_custom_named_payload_dll_next_to_signed_host():
    host = pef("vendor.exe", signed=True, imports=["libcef.dll", "kernel32.dll"])
    got = sl.evaluate_dir([host], [pef("libcef.dll", dll=True, entropy=7.9)], SYS, 2)
    assert got and got[0].severity == Severity.HIGH and got[0].score == 8 + 25 + 15 + 25


@pytest.mark.parametrize("path,benign", [
    (r"C:\Users\bob\AppData\Local\Google\Chrome\Application", True),
    (r"C:\Users\bob\AppData\Local\Microsoft\Teams\current", True),
    (r"C:\Users\bob\AppData\Local\Discord\app-1.0.9", True),
    (r"C:\Users\bob\AppData\Roaming\Zoom\bin", True),
    (r"C:\Users\bob\AppData\Local\JetBrains\Toolbox", True),
    (r"D:\SteamLibrary\steamapps\common\Game", True),
    (r"C:\Program Files (x86)\Steam\bin", True),
    (r"C:\Users\bob\AppData\Local\Programs\Python\Python312\Lib\site-packages\foo", True),
    (r"C:\Users\bob\AppData\Roaming\npm\node_modules\x", True),
    (r"C:\ProgramData\Docker\config", True),
    (r"C:\Users\bob\AppData\Roaming\Mozilla\Firefox", True),
    (r"C:\Users\bob\AppData\Local\Epic Games\Launcher", True),
    ("/home/bob/.local/share/Steam/ubuntu12_32", True),
    (r"C:\Users\bob\AppData\Roaming\Foo", False),
    (r"C:\Users\bob\Downloads\installer", False),
    (r"C:\ProgramData\Updater", False),
    (r"C:\Users\bob\AppData\Local\Temp\abc123", False),
    (r"C:\Users\Public\codewords", False),  # 'code' only as a whole path component is benign
])
def test_is_benign_dir(path, benign):
    assert sl.is_benign_dir(path) is benign


def test_system_dll_names_contains_hijack_list():
    names = sl.system_dll_names()
    assert {"version.dll", "winhttp.dll", "wininet.dll", "dbghelp.dll", "cryptbase.dll", "wtsapi32.dll", "dwmapi.dll",
            "d3d9.dll", "mscms.dll", "ncrypt.dll", "profapi.dll", "userenv.dll", "wlbsctrl.dll", "secur32.dll"} <= names
    assert "notepad.exe" not in names


# ---------------------------------------------------------------- folder analysis with real files
def make_trojan_folder(base: Path, name="Updater", dll_payload=True, host_signed=True, dll_signed=False):
    folder = base / name
    folder.mkdir()
    write(folder, "updater.exe", build_pe(imports=["KERNEL32.dll", "VERSION.dll"], signed=host_signed))
    write(folder, "version.dll", build_pe(dll=True, signed=dll_signed, padding=os.urandom(30_000) if dll_payload else b"\0" * 100))
    return folder


def test_analyse_folder_finds_signed_host_plus_unsigned_proxy(tmp_path):
    folder = make_trojan_folder(tmp_path)
    cands = sl.analyse_folder(str(folder), sorted(os.listdir(folder)), 2, sl.system_dll_names())
    assert len(cands) == 1
    c = cands[0]
    assert c.dll.name == "version.dll" and c.hosts[0].name == "updater.exe" and c.hosts[0].signed
    assert c.dll.entropy > 7.5 and c.severity == Severity.HIGH
    f = sl.candidate_finding(c, sha256="ab" * 32)
    assert f.rule_id == "AEG-SIDELOAD-DLL" and f.severity == Severity.HIGH and f.category == "suspicious"
    assert f.location == str(folder / "version.dll") and f.remediation.action == "quarantine_file"
    assert "T1574.001" in f.mitre and f.evidence["host_imports_dll"] is True and f.evidence["sha256"] == "ab" * 32
    assert "updater.exe" in f.title and f.recommendation
    json.dumps(f.to_dict())


def test_analyse_folder_benign_variants(tmp_path):
    assert sl.analyse_folder(*_folder_args(make_trojan_folder(tmp_path, "a", dll_signed=True))) == []  # signed DLL
    f2 = make_trojan_folder(tmp_path, "b", dll_payload=False, host_signed=False)  # unsigned host, plain DLL
    assert sl.analyse_folder(*_folder_args(f2)) == []
    other = tmp_path / "c"
    other.mkdir()
    write(other, "tool.exe", build_pe(imports=["kernel32.dll"], signed=True))
    write(other, "helper.dll", build_pe(dll=True, padding=os.urandom(20_000)))  # random DLL nobody imports
    write(other, "notapeexe.dll", b"this is not a PE")
    assert sl.analyse_folder(*_folder_args(other)) == []


def _folder_args(folder, loc=2):
    return str(folder), sorted(os.listdir(folder)), loc, sl.system_dll_names()


def test_iter_pair_dirs_skips_benign_and_non_pairs(tmp_path):
    make_trojan_folder(tmp_path, "Bad")
    google = tmp_path / "Google"
    google.mkdir()
    make_trojan_folder(google, "Chrome")
    (tmp_path / "OnlyExe").mkdir()
    write(tmp_path / "OnlyExe", "a.exe", build_pe())
    deep = tmp_path / "d1" / "d2" / "d3" / "d4" / "d5"
    deep.mkdir(parents=True)
    write(deep, "a.exe", build_pe())
    write(deep, "b.dll", build_pe(dll=True))
    import time

    found = [d for d, _f, _r in sl.iter_pair_dirs([tmp_path], time.monotonic() + 30)]
    assert found == [str(tmp_path / "Bad")]
    assert [d for d, _f, _r in sl.iter_pair_dirs([tmp_path], time.monotonic() - 1)] == []  # deadline respected
    assert [d for d, _f, _r in sl.iter_pair_dirs([tmp_path], time.monotonic() + 30, max_depth=9)].count(str(deep)) == 1


# ---------------------------------------------------------------- scanner
def test_scanner_reports_and_quarantine_remediation(ctx, tmp_path):
    make_trojan_folder(tmp_path, "Roaming1")
    ctx.options["sideload_roots"] = [str(tmp_path)]
    out = list(sl.SideloadScanner().run(ctx))
    findings = [x for x in out if isinstance(x, Finding)]
    checks = [x for x in out if isinstance(x, CheckResult)]
    side = [f for f in findings if f.rule_id == "AEG-SIDELOAD-DLL"]
    assert len(side) == 1 and side[0].severity >= Severity.MEDIUM
    assert checks[-1].check_id == "AEG-SIDELOAD-SCAN" and checks[-1].status == CheckStatus.FAIL
    assert ctx.stats["sideload_folders"] == 1


def test_scanner_includes_file_scan_hits(ctx, tmp_path):
    folder = make_trojan_folder(tmp_path, "App")
    import hashlib

    dll = (folder / "version.dll").read_bytes()
    ctx.signatures.hashes[hashlib.sha256(dll).hexdigest()] = "Trojan.SideLoader.Test"
    ctx.options["sideload_roots"] = [str(tmp_path)]
    out = [x for x in sl.SideloadScanner().run(ctx) if isinstance(x, Finding)]
    rules = {f.rule_id for f in out}
    assert {"AEG-SIDELOAD-DLL", "AEG-SIG-HASH"} <= rules
    assert [f for f in out if f.rule_id == "AEG-SIDELOAD-DLL"][0].evidence["file_scan_findings"] == ["AEG-SIG-HASH"]


def test_scanner_clean_folder_and_missing_roots(ctx, tmp_path):
    other = tmp_path / "Good"
    other.mkdir()
    write(other, "app.exe", build_pe(imports=["kernel32.dll"], signed=True))
    write(other, "version.dll", build_pe(dll=True, signed=True))
    ctx.options["sideload_roots"] = [str(tmp_path)]
    out = list(sl.SideloadScanner().run(ctx))
    assert [x for x in out if isinstance(x, Finding)] == []
    assert out[-1].status == CheckStatus.PASS
    ctx.options["sideload_roots"] = [str(tmp_path / "does-not-exist")]
    ctx.paths = []
    # no valid custom roots -> falls back to the default user-writable folders and never raises
    list(sl.SideloadScanner().run(ctx))


def test_scanner_registered_all_platforms():
    load_all()
    cls = REGISTRY["sideload"]
    assert set(cls.platforms) == {"windows", "linux", "darwin"} and cls.title
