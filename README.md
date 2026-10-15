# 🛡️ Aegis Security Suite

**An open-source antivirus, anti-malware, threat-detection and security-audit toolkit for Windows (with
Linux and macOS support).** It scans files, processes, autostarts, browsers, network, system
configuration, installed software and exposed secrets. It also provides real-time protection, ransomware
canaries, one-click remediation with quarantine and backups, and HTML security reports with a 0–100
score. Use it from the command line or the desktop GUI.

> Aegis is user-mode software (no kernel driver). Use it **alongside** Microsoft Defender or another
> real-time AV as your hunting, cleanup and hardening layer. See [docs/COMPARISON.md](docs/COMPARISON.md)
> for how it compares with Defender, Malwarebytes, Bitdefender/Norton/Kaspersky/ESET, Sysinternals,
> AdwCleaner and ClamAV.

---

## Features

| Area | What Aegis does |
|---|---|
| **Malware scanning** | Matches SHA-256/MD5 hashes against threat feeds (MalwareBazaar), runs YARA (YARA Forge) and the dependency-free Aegis-Lite rule engine. Static heuristics cover PE files (injection, keylogging, LSASS dumping, packers, entropy, unsigned overlays), scripts (PowerShell cradles, AMSI bypass, Defender tampering, LOLBins, reverse shells, miners, webshells), Office/RTF/PDF/LNK, HTML smuggling, ClickFix fake-CAPTCHA lures and ransom notes. Nested ZIPs are inspected and encrypted archives flagged. Microsoft Defender and VirusTotal can give a second opinion, and a scan cache speeds up repeat scans |
| **Processes** | Detects masquerading system processes and typosquats (`svch0st.exe`), Office spawning PowerShell, LOLBin command lines, executables running from Temp/Downloads, deleted-on-disk binaries, crypto-miners and remote-access tools used in tech-support scams. Checks Authenticode signatures |
| **Persistence** | Autoruns-style review of Run keys, Winlogon, IFEO and accessibility backdoors, AppInit/AppCert, LSA packages, Startup folders, scheduled tasks (XML), services and drivers, WMI subscriptions and COM hijacks. On Linux/macOS: cron, systemd, rc files, `ld.so.preload`, LaunchAgents |
| **Browsers** | Chrome, Edge, Brave, Vivaldi, Opera, Firefox and more. Checks extensions against known-malicious IDs, scores permission risk and flags sideloading. Detects search/homepage hijacks, forced-install policies, proxy settings, disabled Safe Browsing and notification spam, and counts saved passwords exposed to infostealers |
| **Network** | Connections to known botnet C2 IPs (Feodo Tracker), RAT/miner ports, risky listeners (RDP/SMB/VNC/WinRM), hosts-file hijacks, proxy and DNS hijacks, rogue root certificates (Superfish-style), open Wi-Fi and exposed SMB shares |
| **Hardening audit** | Antivirus/Defender status and malicious exclusions, firewall, UAC, SMBv1, RDP/NLA, BitLocker, Secure Boot, **OS end-of-support** (Windows 10 EOL, Windows 11 release lifecycles), Windows Update age, WDigest/LSA/LM hashes, Guest/admin accounts, AutoRun, SmartScreen, hidden extensions, Office macro policy, LLMNR, PowerShell logging. Includes Linux and macOS checks |
| **Software** | PUP/adware/scareware detection (AdwCleaner-style) and vulnerable/EOL software (WinRAR CVE-2025-8088, 7-Zip CVE-2025-0411, PuTTY CVE-2024-31497, Flash, old browsers, Office EOL, and more) |
| **Secrets** | Plaintext passwords files, crypto seed phrases, wallet files, cloud/API tokens, unencrypted SSH keys, saved RDP/FileZilla credentials, unattend.xml passwords. All values are masked in reports |
| **Real-time protection** | A file guard (scan on write, auto-quarantine), a process guard (new-process analysis, optional kill), a ransomware guard (hidden canary files plus mass-modification detection that suspends the culprit), a persistence guard (alerts on new autoruns and hosts changes) and desktop notifications |
| **Tools** | Phishing/URL checker (lookalike domains, homoglyphs, brand impersonation, URLhaus, optional Google Safe Browsing), password strength and breach check (HIBP k-anonymity), deep file analysis, file integrity monitoring, threat-intel updater |
| **Remediation** | Quarantine/restore, kill process, remove registry autoruns, disable tasks/services, remove WMI persistence, clean hosts file, apply hardening fixes. Every change is backed up |
| **Reporting** | Security score and grade, HTML/JSON/CSV/TXT reports, MITRE ATT&CK mapping, scripting exit codes |

## Quick start (Windows)

### Option A: packaged executable

1. Download `aegis-windows` from the GitHub Actions artifacts or the Releases page, or build it with
   `scripts\build_windows.ps1`.
2. Open **PowerShell as Administrator**:

```powershell
.\aegis.exe update            # fetch latest threat intelligence
.\aegis.exe scan quick        # ~1-2 min: processes, autoruns, downloads/desktop/temp, browsers, network
.\aegis.exe scan full --report html   # everything + all drives, writes an HTML report
.\aegis.exe fix               # review & apply fixes interactively
.\aegis-gui.exe               # desktop app
```

3. Optional: run `scripts\install_windows.ps1` as Administrator. It installs Aegis to
   `C:\Program Files\Aegis` and creates scheduled tasks for real-time protection at logon, a daily quick
   scan and signature updates every 6 hours.

### Option B: from source (Python 3.9+)

```powershell
git clone https://github.com/anshnt/security.git
cd security
python -m pip install -e .[yara]     # yara is optional
python -m aegis update
python -m aegis scan quick
```

On Linux/macOS, use the same commands (`sudo` for full coverage), or run `scripts/install_linux.sh`.

## Command reference

```
aegis scan [quick|full|audit|custom] [--path P] [--scanners a,b] [--deep] [--cloud]
           [--report out.html|html|json|csv] [--fix | --auto-fix high] [--json] [-v]
aegis audit                          hardening + software + network + browser review
aegis fix [--id ID] [-y --min-severity high]   apply fixes from the last scan
aegis allow --id ID | --hash SHA256 | --path P suppress false positives
aegis quarantine list|restore|delete|add ...
aegis monitor [--auto-quarantine] [--kill]     real-time protection (foreground)
aegis update                         MalwareBazaar, Feodo C2 IPs, URLhaus, malicious extensions, YARA Forge
aegis check-file FILE [--cloud]      deep static analysis (+ Defender + VirusTotal)
aegis check-url URL                  phishing / malicious URL verdict
aegis check-password                 strength + breach check (k-anonymity)
aegis autoruns [--json]              list every autostart entry
aegis integrity baseline|check       file integrity monitoring
aegis report out.html                render the last scan
aegis info | config show | config set KEY VALUE
aegis gui | install-service | uninstall-service
```

Exit codes: `0` means clean, `1` means findings at or above `--fail-on` (default `high`), `2` means an error.

### Configuration

`aegis config show` prints all settings. Useful ones:

| Setting | Purpose |
|---|---|
| `virustotal_api_key` / env `AEGIS_VT_API_KEY` | Hash reputation for suspicious files (`--cloud`) |
| `abusech_auth_key` / env `AEGIS_ABUSECH_KEY` | abuse.ch Auth-Key (if feeds require it) |
| `google_safebrowsing_api_key` / env `AEGIS_GSB_API_KEY` | Safe Browsing in the URL checker |
| `auto_quarantine`, `auto_quarantine_min_severity` | Automatic quarantine on scans and realtime |
| `realtime_kill_malicious_processes` | Let the process guard terminate confirmed malware |
| `exclusions` | Path prefixes or globs to skip (`;`-separated with `config set`) |

## What runs where

| Scanner | Windows | Linux | macOS | Needs admin for full results |
|---|---|---|---|---|
| files | ✅ | ✅ | ✅ | for protected folders |
| processes | ✅ | ✅ | ✅ | to see other users' processes |
| persistence | ✅ | ✅ | ✅ | services, all tasks |
| browser | ✅ | ✅ | ✅ | – |
| network | ✅ | ✅ | ✅ | process names of connections |
| system_audit | ✅ | ✅ | ✅ | BitLocker, Defender exclusions |
| software | ✅ | ✅ | ✅ | – |
| secrets | ✅ | ✅ | ✅ | – |

## Testing

```
pip install -e .[dev]
pytest -q
```

The test suite builds malware-like samples at runtime, using EICAR and synthetic PE/script/document
files, so the repository never contains live malware. CI runs on Ubuntu and Windows and builds the
Windows executables.

## Documentation

* [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md): requirements, system requirements, threat coverage
* [docs/COMPARISON.md](docs/COMPARISON.md): comparison with commercial and free tools, and the roadmap
* [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): how the engine works
* [docs/RULES.md](docs/RULES.md): writing your own detection rules

## Disclaimer

No security product detects everything. Heuristic findings are labelled *suspicious* and explain their
reasoning, so verify them before deleting files. Licensed under MIT.
