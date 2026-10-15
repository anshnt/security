# Changelog

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
