# Requirements & planning

## 1. Product requirements

| # | Requirement | Module |
|---|---|---|
| R1 | Detect known malware by hash (SHA-256/MD5), with feeds that update automatically | `core/signatures.py`, `tools/updater.py` |
| R2 | Detect malicious content by rules (YARA plus the dependency-free Aegis-Lite engine) | `core/rules.py`, `data/rules`, `data/yara` |
| R3 | Detect unknown threats with static heuristics (PE, scripts, documents, shortcuts, archives, ransom notes) | `core/fileanalysis.py` |
| R4 | Find malicious or suspicious running processes and kill them on request | `scanners/processes.py` |
| R5 | Enumerate and judge every autostart mechanism, Autoruns-style | `scanners/persistence.py` |
| R6 | Audit browsers: malicious or risky extensions, hijacks, policies, Safe Browsing, saved-credential exposure | `scanners/browser.py` |
| R7 | Detect network threats: C2 connections, risky listeners, hosts/proxy/DNS hijack, rogue root CAs, open Wi-Fi, shares | `scanners/network.py` |
| R8 | Audit OS hardening and support status, and offer one-click fixes | `scanners/system_audit.py` |
| R9 | Detect PUPs/adware and vulnerable or end-of-life software | `scanners/software.py` |
| R10 | Find exposed secrets (keys, seed phrases, plaintext passwords) | `scanners/secrets.py` |
| R11 | Real-time protection: new files, new processes, ransomware behaviour, persistence changes | `realtime/` |
| R12 | Quarantine with restore; remediation with backups | `core/quarantine.py`, `core/remediation.py` |
| R13 | Reports: security score, HTML/JSON/CSV/TXT, MITRE ATT&CK mapping | `core/report.py`, `core/scoring.py` |
| R14 | Utilities: URL/phishing checker, password breach check, file deep-analysis, integrity monitoring | `tools/` |
| R15 | Interfaces: CLI with exit codes, desktop GUI, scheduled tasks / services | `cli.py`, `ui/gui.py`, `core/service.py` |
| R16 | Privacy: no telemetry. Cloud lookups are opt-in and send hashes only; passwords use k-anonymity | all modules |
| R17 | Safety: low false-positive rate, never delete without quarantine/backup, allow-listing | engine, config |

## 2. System requirements

| | Minimum | Recommended |
|---|---|---|
| OS | Windows 10 22H2 / Windows 11, Server 2016+ (also Linux, macOS 12+) | Windows 11 24H2/25H2 |
| Runtime | Packaged `aegis.exe` (no Python needed), **or** Python 3.9+ | Python 3.12 |
| Privileges | Standard user (limited checks) | **Administrator**: needed for services, tasks, other users' processes, BitLocker, Defender exclusions, HKLM fixes |
| RAM / CPU | 200 MB / any x64 or ARM64 | 4 GB+ for full scans of large drives |
| Disk | 60 MB + signature feeds (~30 MB) + quarantine | SSD |
| Network | Optional (updates, VirusTotal, HIBP, Safe Browsing) | Allow `*.abuse.ch`, `codeberg.org`, `api.github.com`, `api.pwnedpasswords.com`, `www.virustotal.com` |

### Dependencies

* **Required:** `psutil`
* **Optional:** `yara-python` (native YARA engine plus the YARA Forge community rules)
* **Build:** `pyinstaller`, `pytest`
* **Built into Windows and used when present:** PowerShell 5.1+, `schtasks`, `netsh`, Microsoft Defender
  `MpCmdRun.exe`, WMI/CIM

## 3. Threat model / tool types covered

| Threat class | Examples | How Aegis covers it |
|---|---|---|
| Commodity malware / trojans | AsyncRAT, Remcos, njRAT, Quasar | Hashes, rules, YARA, process and network checks |
| Infostealers | Lumma, RedLine, Vidar, AMOS (mac), Discord grabbers | Stealer rules, ClickFix lure detection, secrets exposure |
| Ransomware | LockBit-style payloads, notes, shadow-copy wipers | Rules, ransom-note detection, canaries, burst detection |
| Cryptojackers | XMRig, NBMiner | Rules, process/CPU heuristics, stratum ports |
| Post-exploitation | Cobalt Strike, Meterpreter, Mimikatz, PowerSploit | Rules, LOLBin command-line analysis, LSASS-dump heuristics |
| Living-off-the-land | certutil, mshta, rundll32, regsvr32, bitsadmin, WMI | `core/cmdline.py` patterns used by processes, persistence and realtime |
| Persistence | Run keys, tasks, services, WMI subscriptions, IFEO/accessibility backdoors, COM hijack | Persistence scanner plus realtime diff |
| Adware / PUP / browser hijackers | OneLaunch, Wave Browser, ChromeLoader, forced extensions, search hijacks | Software and browser scanners |
| Phishing | Lookalike domains, HTML smuggling, credential-harvest pages | URL checker, HTML rules |
| Misconfiguration | No AV, firewall off, SMBv1, RDP without NLA, UAC off, EOL OS, WDigest | System audit |
| Vulnerable software | WinRAR CVE-2025-8088, 7-Zip CVE-2025-0411, PuTTY CVE-2024-31497, Flash, Office EOL | Software scanner |
| Credential exposure | Seed phrases, API keys, SSH keys, saved passwords | Secrets and browser scanners |
| Network attacks | C2 beacons, MITM roots, proxy/DNS hijack, open Wi-Fi | Network scanner |
| Linux/macOS | LD_PRELOAD rootkits, cron/systemd/LaunchAgent persistence, Mirai, webshells | Persistence, rules, audit |

## 4. Non-functional requirements

* **Performance:** a quick scan should finish in under 2 minutes on a typical PC. The clean-file cache
  makes repeat scans faster, file scanning is multi-threaded, and the realtime guards stay under 2% CPU.
* **Robustness:** a failing check never aborts a scan; it is reported in `errors`. Corrupt files never
  crash the parser.
* **Locale independence:** checks read registry values, XML or JSON rather than localised console text.
* **Reversibility:** every fix writes a backup to `<data>/backups`, and quarantined files can be restored.
* **Testability:** decision logic is separated from data collection, so the unit tests run on Linux CI
  with mocked Windows APIs, and a Windows CI job runs the real thing.
