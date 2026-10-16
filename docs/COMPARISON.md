# Aegis vs. the market

This is how Aegis's features line up against the tools people usually install on Windows PCs. It aims to
be honest, because a security tool that overstates what it does is a risk in itself.

**Legend:** ✅ yes · 🟡 partial / limited · ❌ no · 💲 paid tier only

## 1. Feature matrix

| Capability | **Aegis** | MS Defender | Malwarebytes | Bitdefender / Norton / Kaspersky / ESET | Sysinternals (Autoruns, ProcExp) | AdwCleaner | ClamAV |
|---|---|---|---|---|---|---|---|
| On-demand malware scan (hash signatures) | ✅ | ✅ | ✅ | ✅ | 🟡 (VT lookup) | 🟡 | ✅ |
| YARA rule support | ✅ (yara-python + YARA Forge feed) | ❌ | ❌ | ❌ (internal) | ❌ | ❌ | ✅ |
| Dependency-free rule engine (works without native libs) | ✅ Aegis-Lite | – | – | – | – | – | ❌ |
| Static PE heuristics (injection/keylogger/packer/entropy imports) | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | 🟡 |
| Script heuristics (PowerShell cradles, AMSI bypass, LOLBins, ClickFix lures) | ✅ | ✅ (AMSI) | ✅ | ✅ | ❌ | ❌ | 🟡 |
| Office/PDF/RTF/LNK/HTML-smuggling analysis | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | 🟡 |
| Archive inspection (nested ZIP, encrypted-archive flagging, zip bombs) | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ |
| Second-opinion engines (Defender MpCmdRun + VirusTotal) | ✅ | – | ❌ | ❌ | 🟡 VT | ❌ | ❌ |
| Process analysis (masquerading, typosquats, parent/child chains, miners, RATs) | ✅ | ✅ (behaviour) | ✅ | ✅ | 🟡 manual | ❌ | ❌ |
| Autostart / persistence audit (Run keys, tasks, services, WMI, IFEO, LSA, COM) | ✅ | 🟡 | 🟡 | 🟡 | ✅ (manual review) | 🟡 | ❌ |
| Hidden scheduled tasks (Tarrask: security descriptor removed, `Index` 0), with the command they run | ✅ | 🟡 (Defender for Endpoint 💲) | ❌ | 🟡 EDR 💲 | ❌ (lists only what Task Scheduler shows) | ❌ | ❌ |
| Linux PAM backdoor / motd / generator persistence (`pam_exec`, `pam_permit`, unpackaged PAM modules, `update-motd.d`, systemd generators, at jobs) | ✅ | 🟡 (Defender for Endpoint 💲) | ❌ | 🟡 EDR 💲 | ❌ | ❌ | ❌ |
| macOS login hooks, emond rules, periodic scripts, authorization plugins | ✅ | 🟡 (Defender for Endpoint 💲) | 🟡 | 🟡 EDR 💲 | ❌ | ❌ | ❌ |
| macOS login items (Background Task Management), code-signature check of launch agents/daemons, XProtect freshness | ✅ | 🟡 (Defender for Endpoint 💲) | 🟡 | 🟡 EDR 💲 | ❌ | ❌ | ❌ |
| Browser extension risk scoring + known-malicious extension IDs | ✅ | ❌ | 🟡 Browser Guard | 🟡 | ❌ | 🟡 | ❌ |
| Browser hijack detection (search/homepage/policy/proxy/notification spam) | ✅ | ❌ | ✅ | 🟡 | ❌ | ✅ | ❌ |
| PUP / adware / scareware detection | ✅ | 🟡 (PUA opt-in) | ✅ | ✅ | ❌ | ✅ | ❌ |
| Network exposure (C2 IP feeds, risky ports, hosts/proxy/DNS hijack, rogue root CAs) | ✅ | 🟡 | 🟡 | ✅ 💲 | 🟡 TCPView | ❌ | ❌ |
| Inbound firewall rule review (programs in user folders, allow-all rules, RDP/SMB/SSH open on public networks, stale rules) | ✅ | ❌ | ❌ | 🟡 (own firewall 💲) | ❌ | ❌ | ❌ |
| Windows hardening audit (Defender, firewall, UAC, SMBv1, RDP/NLA, BitLocker, LSA, WDigest, OS EOL...) | ✅ | 🟡 (Security Center) | ❌ | 🟡 vulnerability scan 💲 | ❌ | ❌ | ❌ |
| Secure Boot 2011 → 2023 certificate update status | ✅ | 🟡 (event log / Windows Security) | ❌ | ❌ | ❌ | ❌ | ❌ |
| Vulnerable / end-of-life software detection | ✅ | 🟡 (Defender for Endpoint 💲) | ❌ | 🟡 💲 | ❌ | ❌ | ❌ |
| Software updater (pending app updates, one-command upgrade via winget / apt / dnf / brew) | ✅ | ❌ | ❌ | ✅ 💲 | ❌ | ❌ | ❌ |
| Windows event-log threat hunting (log clearing, new admins, RDP brute force, Defender tampering, malicious script blocks) | ✅ | 🟡 (Defender for Endpoint 💲) | ❌ | 🟡 EDR 💲 | ❌ | ❌ | ❌ |
| Vulnerable / malicious driver detection (BYOVD, LOLDrivers) + driver blocklist & HVCI checks | ✅ | 🟡 (blocklist only) | ❌ | 🟡 | ❌ | ❌ | ❌ |
| DLL side-loading detection | ✅ heuristic | ✅ | 🟡 | ✅ | ❌ | ❌ | ❌ |
| Process memory scanning (YARA) | ✅ user-mode | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| Email attachment & sender-spoofing analysis (.eml, Outlook cache, Thunderbird) | ✅ | 🟡 | ❌ | ✅ 💲 | ❌ | ❌ | 🟡 |
| USB / removable-media threats (autorun, shortcut virus) | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| Sigma rules (community detection standard) on event logs + live processes | ✅ | ❌ | ❌ | 🟡 EDR 💲 | ❌ | ❌ | ❌ |
| Software supply chain: malicious/vulnerable dependencies in local projects, malicious IDE extensions | ✅ (OSV.dev, Microsoft list) | ❌ | ❌ | 🟡 | ❌ | ❌ | ❌ |
| AI coding agents and MCP servers (malicious MCP packages, auto-approve modes, hidden instructions in rules files and skills) | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Router port forwards (UPnP) and risky inbound firewall rules | ✅ | ❌ | ❌ | 🟡 home-network scan 💲 | ❌ | ❌ | ❌ |
| Web protection (malicious-domain blocking) + C2 IP firewall blocking | ✅ hosts/firewall | ✅ SmartScreen / Network Protection | ✅ 💲 | ✅ | ❌ | ❌ | ❌ |
| One-command hardening incl. ASR rules, with full undo | ✅ | 🟡 (manual / Intune 💲) | ❌ | 🟡 | ❌ | ❌ | ❌ |
| Scan history, "new since last scan", alerts to Slack/Teams/Discord/email | ✅ | 🟡 (Defender for Endpoint 💲) | 🟡 💲 | 🟡 💲 | ❌ | ❌ | ❌ |
| Multi-PC overview built from scan results, no server needed (`aegis fleet`) | ✅ | 🟡 (Defender for Endpoint portal 💲) | 🟡 (cloud console 💲) | 🟡 (cloud console 💲) | ❌ | ❌ | ❌ |
| Exposed secrets / seed phrases / plaintext credentials on disk | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Infostealer persistence in trusted apps (Discord injection, wallet-app swaps, Electron/Node env abuse) | ✅ | 🟡 (signatures) | 🟡 | 🟡 | ❌ | ❌ | ❌ |
| Hijacked browser shortcuts + browsers launched for cookie theft (remote debugging) | ✅ | 🟡 | ✅ | 🟡 | ❌ | ✅ (shortcuts) | ❌ |
| Webcam / microphone / screen-capture access review (spyware, stalkerware) | ✅ (OS usage record) | ❌ | 🟡 💲 | ✅ 💲 (webcam protection) | ❌ | ❌ | ❌ |
| ClickFix / fake-CAPTCHA traces (Run dialog, PowerShell and shell history), malicious domains in DNS cache and browser history | ✅ | 🟡 (behaviour blocking) | 🟡 Browser Guard | 🟡 EDR 💲 | ❌ | ❌ | ❌ |
| Clipboard guard: warns about (and clears) ClickFix commands a web page copies | ✅ | 🟡 (blocks the command when it runs) | 🟡 Browser Guard | 🟡 | ❌ | ❌ | ❌ |
| Real-time alert when a browser extension is installed (sideloaded / malicious / adware rated at once) | ✅ | ❌ | 🟡 Browser Guard | 🟡 | ❌ | ❌ | ❌ |
| Download origin review (Mark-of-the-Web / macOS quarantine / xattr): known-bad and raw-IP sources, HTML smuggling, WebDAV delivery, deceptive file names | ✅ | 🟡 (SmartScreen reputation at download time) | 🟡 (web protection) | 🟡 (web protection) | 🟡 Streams (manual) | ❌ | ❌ |
| Remote-access tool review (AnyDesk, TeamViewer, ScreenConnect, RustDesk, NetSupport, MeshAgent ...): who connected and when from the tool's own logs, unattended-access passwords, self-hosted relays, portable copies | ✅ | ❌ | 🟡 (flags some tools as riskware) | 🟡 (flags some tools as riskware) | 🟡 Autoruns (services only) | ❌ | ❌ |
| Ransomware recovery readiness (restore points, File History, cloud versioning, Time Machine) with a grade | ✅ | 🟡 (CFA, OneDrive prompt) | ❌ | 🟡 (own backup 💲) | ❌ | ❌ | ❌ |
| Exploit-protection audit (DEP, ASLR, CFG, SEHOP switched off) | ✅ | 🟡 (settings page) | ✅ 💲 (exploit protection) | ✅ | ❌ | ❌ | ❌ |
| Linux kernel hardening & hidden kernel module check (sysctls, rootkit LKMs, module-list cross-check, taint, AppArmor / SELinux) | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Automatic screen-lock audit (idle lock on Windows, macOS and Linux desktops) | ✅ | 🟡 (Defender for Endpoint 💲) | ❌ | ❌ | ❌ | ❌ | ❌ |
| Saved Wi-Fi review (WEP, auto-joined open networks, hidden networks) | ✅ | ❌ | ❌ | ✅ (Wi-Fi inspector) | ❌ | ❌ | ❌ |
| Phishing / malicious URL checker | ✅ (offline heuristics + URLhaus + optional Safe Browsing) | ✅ SmartScreen | ✅ 💲 | ✅ | ❌ | ❌ | ❌ |
| Password breach check (HIBP k-anonymity) | ✅ | ✅ (Edge) | ❌ | ✅ 💲 | ❌ | ❌ | ❌ |
| Crypto clipboard hijacker (clipper) guard that restores the copied address | ✅ | 🟡 (signatures) | 🟡 (signatures) | 🟡 | ❌ | ❌ | ❌ |
| Real-time file protection | ✅ user-mode | ✅ kernel | ✅ 💲 | ✅ | ❌ | ❌ | 🟡 (clamonacc, Linux) |
| Ransomware protection | ✅ canaries + burst detection + suspend culprit | ✅ CFA | ✅ 💲 | ✅ | ❌ | ❌ | ❌ |
| Persistence change alerts | ✅ | 🟡 | 🟡 | 🟡 | ❌ | ❌ | ❌ |
| File integrity monitoring | ✅ | ❌ | ❌ | 🟡 | ❌ | ❌ | ❌ |
| Quarantine with restore | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | 🟡 |
| One-click / scripted remediation with backups | ✅ | 🟡 | ✅ | ✅ | 🟡 delete | ✅ | ❌ |
| Security score + HTML/JSON/CSV reports, MITRE ATT&CK mapping | ✅ | 🟡 | 🟡 | 🟡 | ❌ | 🟡 log | ❌ |
| SARIF output for GitHub code scanning and other SARIF tools | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| CLI + exit codes for automation / RMM | ✅ | 🟡 PowerShell | 🟡 💲 | 🟡 💲 | ✅ | ❌ | ✅ |
| Open source, auditable, no telemetry | ✅ | ❌ | ❌ | ❌ | ❌ (free, closed) | ❌ | ✅ |
| Linux / macOS support | 🟡 best-effort | 🟡 💲 | ✅ (mac) | ✅ | ❌ | ❌ | ✅ |
| Kernel driver / minifilter, exploit mitigation, kernel-level memory protection | ❌ (roadmap) | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| Cloud ML / global telemetry network | ❌ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| Price | Free | Free (built in) | Free / 💲 | 💲 | Free | Free | Free |

## 2. Where Aegis is stronger

1. **Breadth in one tool.** Aegis combines an AV scanner, Autoruns-style persistence review, AdwCleaner-style
   browser and PUP cleanup, a CIS-style hardening audit and vulnerable-software checks in a single
   command (`aegis scan full`). Doing the same otherwise takes four or five products.
2. **Transparency.** Every detection says *why* it fired: the rule id, the indicators with their scores,
   MITRE ATT&CK techniques and the evidence. Rules are plain JSON or YARA that you can read and extend.
   Commercial engines are black boxes.
3. **Configuration and exposure, not just malware.** Most infections on home PCs exploit weak configuration:
   an end-of-life OS, RDP without NLA, disabled UAC, SMBv1, malicious Defender exclusions, browser policy
   hijacks, unpatched WinRAR or 7-Zip. Consumer AVs largely ignore these.
4. **Exposed secrets.** Aegis finds plaintext seed phrases, API keys, unencrypted SSH keys and saved RDP or
   FileZilla passwords. Those files are exactly what infostealers grab first.
5. **It complements your existing AV.** Aegis can ask Microsoft Defender's engine and VirusTotal for a
   second opinion. It runs fine alongside any installed AV and doesn't fight it for kernel hooks.
6. **Automation-friendly.** The JSON output, CSV export, exit codes, scheduled-task installer and silent
   modes make it easy to use from RMM tools, CI jobs or fleet scripts.

## 3. Where commercial products are still ahead (and our plan)

| Gap | Why it matters | Roadmap |
|---|---|---|
| Kernel-mode file-system minifilter | Blocks a file *before* it executes; Aegis's user-mode guard reacts within about 1–2 s of the write | Rust/C minifilter driver (needs an EV code-signing certificate and Microsoft attestation signing) |
| AMSI provider | Inspects de-obfuscated PowerShell, VBA and JS in memory | COM AMSI provider DLL that feeds the existing rule engine |
| ETW-based behaviour monitoring | Precise process, registry and network telemetry without polling | ETW consumer (Microsoft-Windows-Kernel-Process / Threat-Intelligence where permitted) |
| Kernel-assisted memory scanning | Aegis already YARA-scans process memory from user mode; a driver could also see protected processes and catch payloads the moment they unpack | Pair the existing memory scanner with the minifilter/ETW work above |
| Cloud reputation / ML at scale | Zero-day detection through prevalence and ML | Optional self-hosted reputation server; MalwareBazaar, ThreatFox and URLhaus integration |
| Exploit mitigation / web filtering | Stops drive-by and phishing at the network layer | DNS-level blocklist (hosts or local resolver) driven by URLhaus |
| Independent lab certification (AV-TEST, AV-Comparatives) | Third-party proof of detection rates | Not applicable until the engine ships a kernel component |

**Recommendation:** keep Microsoft Defender (or another real-time AV) enabled and run Aegis alongside it as
your auditing, hunting, cleanup and hardening layer, with its real-time guards switched on. Aegis's own
audit will warn you if no real-time antivirus is active.
