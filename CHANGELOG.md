# Changelog

## [1.1.0] - 2026-10-16

### Detection
- **Sigma rule engine.** Aegis evaluates the community standard for detection rules against Windows event
  logs and, in real time, against every new process. It ships 20 bundled rules, and `aegis update` adds
  1,100+ SigmaHQ Windows rules. Value parsing and condition logic were cross-checked against pySigma.
- **Supply-chain scanner (`supplychain`) and `aegis check-project`.** Aegis parses lockfiles from npm, yarn,
  pnpm, pip, poetry, uv, Pipfile, Cargo, Go, Ruby, PHP and NuGet. It flags known-malicious packages
  (OSV.dev MAL advisories) as CRITICAL and lists vulnerable versions with their fixed version. It also flags
  install-script droppers, typosquats of popular packages, Shai-Hulud worm indicators and auto-run VS Code
  tasks.
- **IDE extension scanner (`ide`).** Covers VS Code, VSCodium, Cursor and Windsurf, using Microsoft's
  2,000+ entry removed-extensions list plus code heuristics validated against 61 popular extensions.
- **ASR rule state in the hardening audit.** The audit now reports Attack Surface Reduction rule state.

### Protection
- **`aegis protect web`.** Blocks malicious domains through a managed, byte-exact reversible hosts-file
  block.
- **`aegis protect ips`.** Blocks botnet C2 IPs with Windows Firewall, nftables or iptables. The rules are
  refreshed after every update.
- **`aegis harden`.** Applies 22 reviewed hardening actions in recommended or strict profiles, including
  19 ASR rules whose GUIDs were verified against Microsoft's reference. It writes an undo journal before
  any change.
- **`aegis undo`.** Reverts any remediation backup, hardening run or protection change.

### Insight
- **Scan history.** Every scan is recorded, with "new since last scan", resolved items, score trend, an
  HTML report section, the `aegis history` command and a dashboard chart.
- **Alerts.** Slack, Teams, Discord, generic webhook and email (SMTP) alerts, sent for new findings and
  real-time events. They are batched and rate-limited, and secrets are masked.
- **`aegis doctor`.** A self-check of privileges, signature freshness, data-folder permissions (with a safe
  ACL fix on Windows), YARA and Sigma availability, services and the real-time monitor heartbeat.

### Performance
- **Literal-atom prefiltering.** File scans run about 4.5x faster with identical findings, and a property
  test proves the prefilter never hides a match.
- **Multi-process deep and full scans.** Scans use all CPU cores, 2.7x faster on 4 cores. If the worker pool
  fails, scanning falls back to threads.

### Fixes
- **Security fix: exclusion matching.** Scan exclusions, including Aegis's own data folder, matched by plain
  string prefix, so a sibling folder such as `...\AegisUpdate` was silently skipped. Malware could use this
  to evade scans. Exclusions now end at a path separator.
- **False positives.** Removed false positives found by real-Windows CI and real-world corpora: the
  PowerShell cradle heuristic on syntax-highlighter alias lists, the Linux rootkit rule on setuptools'
  `hide_file()`, and narrow Defender exclusions treated as "disabling Defender".
- **Credentials on disk.** `config.json` is written owner-only on Linux and macOS, and `aegis config show`
  masks every secret, including webhooks and the SMTP password.

## [1.0.0] - 2026-10-15

First release of Aegis Security Suite: an open-source anti-malware, threat-detection and security-audit
toolkit for Windows, with Linux and macOS support.

### Scanners
- **files**: hash signatures (MalwareBazaar), YARA (YARA Forge) and the dependency-free Aegis-Lite rule
  engine with 78 rules, 60 of them for 2025–2026 threats. Static heuristics for PE files, scripts,
  Office/PDF/RTF/LNK and HTML smuggling, archive inspection, and Microsoft Defender / VirusTotal second
  opinions.
- **processes**: masquerading, typosquats, malicious parent-child chains, LOLBin command lines, miners and
  remote-access tools.
- **persistence**: Autoruns-style review of 25+ autostart locations, including accessibility backdoors,
  WMI, COM hijacks, tasks and services.
- **browser**: malicious and sideloaded extensions, search and homepage hijacks, forced-install policies,
  Safe Browsing, notification spam.
- **network**: C2 IP matches, risky listeners, hosts/proxy/DNS hijacks, rogue root CAs, open Wi-Fi, SMB
  shares.
- **system_audit**: AV/Defender (including malicious exclusions), firewall, UAC, SMBv1, RDP/NLA,
  BitLocker, OS end-of-support, updates, credential hygiene, Office macros, plus Linux and macOS checks.
- **software**: PUP/adware and vulnerable or end-of-life software.
- **secrets**: exposed passwords, API keys, private keys, seed phrases and wallets. Values are always masked.
- **eventlog, drivers, sideload, usb, email, memory**: threat hunting across Windows event logs, BYOVD
  drivers (2,198 LOLDrivers hashes), DLL side-loading, removable media, email attachments and spoofing,
  and YARA scans of process memory.

### Protection, tools and interfaces
- Real-time protection: a file guard, a process guard, a ransomware guard (canaries plus burst
  detection that suspends the culprit) and a persistence guard, with desktop notifications.
- Quarantine with restore, and one-click remediation that backs up everything it changes.
- Tools: phishing URL checker, password breach check (HIBP k-anonymity), deep file analysis, file
  integrity monitoring, threat-intel updater (6 feeds).
- CLI with scripting exit codes, a desktop GUI, scheduled tasks or systemd units, and HTML/JSON/CSV/TXT
  reports with a security score and MITRE ATT&CK v20 mapping.

### Quality
- About 1,170 tests. CI runs on Ubuntu and Windows and also runs the packaged `aegis.exe` end to end on a
  live Windows machine.
- The real-Windows runs found and fixed false positives on built-in Windows components: .NET's
  `SMSvcHost.exe`, the default BootExecute value, Microsoft service names, user-store root CAs, and
  Aegis's own unpacked rule files.
