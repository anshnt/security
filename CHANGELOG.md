# Changelog

## [Unreleased]

### Detection
- **Remote-access tool review (`remoteaccess`, part of the full scan).** For the victim of a tech-support scam: can someone
  get in without clicking Accept, and who connected, and when? Reads what AnyDesk, TeamViewer, ScreenConnect / ConnectWise
  Control, RustDesk, Splashtop, Atera, NetSupport and MeshAgent keep on disk, for every user profile the scan may read.
  Read-only: the logs are evidence and nothing is deleted. Running programs are still reported by the process scanner.
  - **Who connected, and when (`AEG-RA-INCOMING`):** the tool's own log: AnyDesk `connection_trace.txt` (with whether a person
    clicked Accept or a stored password or token let the session in) and the request and address lines of `ad.trace` /
    `ad_svc.trace`, TeamViewer `Connections_incoming.txt`, RustDesk server logs. Count, first and last time, remote IDs and
    addresses and the last 10 sessions. MEDIUM; LOW when every session is older than 90 days.
  - **Unattended access (`AEG-RA-UNATTENDED`, MEDIUM):** an AnyDesk unattended-access password, a TeamViewer permanent
    password or account assignment, a RustDesk permanent password, an Access-mode ScreenConnect client, or an Atera,
    Splashtop, NetSupport or MeshAgent installation (naming the Atera account or MeshCentral group that manages the PC).
  - **Relay servers (`AEG-RA-RELAY`):** HIGH for a bare IP address, a dynamic-DNS name (duckdns.org, ddns.net, no-ip,
    hopto.org ...), a host on the threat feed or a NetSupport `GatewayAddress` (the hallmark of NetSupport RAT campaigns, with
    the flags that hide the client from its user); MEDIUM for any other self-hosted RustDesk, ScreenConnect or MeshCentral
    server. A vendor's own cloud is not reported.
  - **Portable copies (`AEG-RA-PORTABLE`):** `AnyDesk.exe`, `TeamViewerQS*.exe`, `rustdesk*.exe`, `ScreenConnect*.exe` and
    others in the top level of Downloads, Desktop and Temp (MEDIUM; LOW when older than 90 days and not running). A RustDesk
    copy that names its server in its file name also gets the relay finding.
  - **Secrets stay out:** passwords, hashes, salts, tokens, session ids and keys are shown as "set" or "not set" and never
    copied. Logs in UTF-8 (with or without a byte order mark) and UTF-16 are read; large traces from their last 4 MB.
  - The check `AEG-RA-CHK` ("Remote access tools reviewed") passes, fails with a summary per tool, or skips and names where
    it looked; profiles the scan may not read are named. ATT&CK ids are T1219.002 (Remote Desktop Software), T1133 and T1078.

### App
- **Fleet overview in the GUI** (Tools > Fleet overview): pick the folder with your PCs' scan results, build the overview
  and open the HTML report, without the command line.

## [1.4.0] - 2026-10-16

### Detection
- **Download origin review (`downloads`, part of the quick and full scans).**
  - **Where downloads came from:** reads the origin the system keeps with a file (Windows Mark-of-the-Web, macOS
    quarantine and `kMDItemWhereFroms`, the `user.xdg.origin.url` attribute on Linux) for the risky files in Downloads and
    on the Desktop, and reports one finding per file.
  - **HIGH:** the source is on the malicious-domain or malicious-IP feed, or the file name is deceptive (right-to-left
    override, `invoice.pdf.exe`). HIGH findings offer to quarantine the file.
  - **MEDIUM:** a `blob:` or `data:` address (HTML smuggling), a WebDAV or network share, or a bare IP address.
  - **LOW:** paste, anonymous file-sharing and short-link hosts, and plain `http://` downloads.
  - **Windows policy:** reports `SaveZoneInformation = 1` (Windows no longer marks downloads) with a fix that sets it back
    to 2, and `ScanWithAntiVirus = 1`.
  - Addresses are shown without query strings, and the content of a file is never read.
- **Linux kernel hardening and integrity in the audit (`AEG-AUDIT-KERNEL-*`).** Read-only checks of `/proc` and `/sys`.
  - **Weak kernel settings:** ASLR off (HIGH) or without heap randomisation, `kptr_restrict`, `dmesg_restrict`, Yama
    `ptrace_scope`, unprivileged eBPF (MEDIUM), `fs.protected_symlinks` / `hardlinks` (MEDIUM), `protected_fifos` /
    `regular`, `suid_dumpable` and Magic SysRq. One finding per weak setting group; the fix sets the value now and writes
    it to `/etc/sysctl.d/61-aegis-kernel.conf`, and the ASLR fix reuses the undoable `aegis harden` action.
  - **Rootkit modules:** known Linux rootkit module names (Diamorphine, Reptile, Suterusu, Adore-ng, KoviD and others)
    in `/proc/modules` or `/sys/module` are HIGH.
  - **Hidden modules:** a loadable module that `/sys/module` has but `/proc/modules` does not list is HIGH. Built-in
    modules are ignored, and both sources are read twice so a module that loads during the scan is not reported.
  - **Kernel taint:** an out-of-tree (O) or unsigned (E) taint flag that no module in `/proc/modules` explains is LOW
    (unloading a VirtualBox or DKMS driver leaves the same flag until the next reboot).
    Listed unsigned or out-of-tree modules (NVIDIA, VirtualBox, ZFS, DKMS) are recorded, not flagged.
  - **Access control:** no AppArmor or SELinux, or SELinux in permissive mode, is LOW. The kernel lockdown mode is recorded.
  - **Containers:** skipped, because `/proc/sys` and `/sys` belong to the host.
- **Automatic screen lock in the audit (`AEG-AUDIT-SCREENLOCK`, LOW).** Windows (machine inactivity limit or a
  password-protected screen saver, honouring the Group Policy values; the fix sets `InactivityTimeoutSecs` to 900),
  macOS (`sysadminctl -screenLock status`) and Linux desktops (GNOME, Cinnamon, MATE through gsettings, KDE Plasma through
  kreadconfig). Reports a screen that never locks or only after more than 15 minutes.
- **More Linux and macOS persistence locations (`persistence`).** All of them appear in `aegis autoruns`, in the real-time
  persistence guard and in the scan results; nothing is changed or deleted.
  - **PAM backdoors (Linux):** `pam_exec.so` lines (the program is recorded; high when it sits in a temporary, hidden, home
    or world-writable location), modules loaded by absolute path from outside the standard module directories, module files
    that no dpkg/rpm package owns, and `pam_permit.so` lines that let anyone through the auth stack of sshd, login, su or
    sudo. The default files of Debian, Ubuntu, Fedora/RHEL (authselect) and Arch raise nothing: the auth stacks are
    replayed the way PAM evaluates them, and only a stack that still succeeds for a wrong password is reported.
  - **`update-motd.d` scripts:** run as root on every login; their content is judged like cron scripts.
  - **systemd generators** in `/etc`, `/usr/local/lib` and `/run`: run as root before any service; the distribution
    directories are not reported.
  - **at jobs** (`/var/spool/cron/atjobs`, `/var/spool/at`, macOS `/usr/lib/cron/jobs`): script content is judged.
  - **macOS:** periodic scripts (the stock ones are listed but not flagged), emond rules, authorization plugins and
    login/logout hooks.

- **Hidden scheduled tasks (Tarrask technique, `persistence`, needs administrator rights).** Reads the Task Scheduler
  cache in the registry and reports a task that Task Scheduler, `schtasks` and `Get-ScheduledTask` cannot list while
  Windows still runs it: a missing or empty security descriptor (HIGH), or `Index` 0 on a non-Microsoft task whose task
  file exists (MEDIUM). The command the task runs is decoded from its binary `Actions` value. Stale Microsoft cache
  entries (`Index` 0 with no task file, 26 of them on Windows Server 2025) are not reported. No automatic fix: deleting
  the keys blindly would destroy the evidence.
- **Inbound firewall rule review (`network`).** Windows: enabled allow rules for programs in user-writable folders (HIGH;
  MEDIUM for Downloads and Desktop, where the Windows firewall prompt creates them), rules that allow everything from
  anywhere (MEDIUM), RDP / SMB / WinRM / SSH open to any address on public networks (MEDIUM) and rules for programs that
  no longer exist (LOW). Linux: the same exposure checks for `ufw`.
- **Secure Boot certificate update (`system_audit`).** The Microsoft 2011 Secure Boot certificates expire from June 2026;
  reports whether Windows has moved this PC to the 2023 certificates (`UEFICA2023Status`): not started or failed is
  MEDIUM, in progress LOW. Skipped when Secure Boot is off.

### Real-time protection
- **Real-time file guard:** alerts for a file now carry where it was downloaded from, when the system recorded it.
- **Clipboard guard.** Warns when a web page copies a ClickFix / fake-CAPTCHA command (PowerShell download-and-run,
  `mshta`, `curl | sh`, the "I am not a robot" lure) and empties the clipboard when the command carries the lure text.
  The text is only checked in memory and never stored. Windows reads the clipboard sequence number, macOS and Linux use
  `pbpaste`, `wl-paste`, `xclip` or `xsel`. Settings: `realtime_clipboard_guard`, `realtime_clear_malicious_clipboard`;
  also on the GUI Protection page.

### Reports
- **`aegis fleet PATH...`** builds one HTML, JSON or CSV overview from the scan results of many PCs (folders of JSON
  reports, `--recursive`, `--since DAYS`, `--min-severity`, `--fail-on` for scripts). A host's row is its current state:
  the most recent result of each scanner, so a narrow follow-up scan does not hide what a full scan found.

### Changes
- **ASLR on Linux** is now reported by the kernel check as `AEG-AUDIT-KERNEL-ASLR` (HIGH when off, LOW when the heap is
  not randomised) instead of `AEG-AUDIT-LINUX-ASLR`, so the same setting is not reported twice.

### Fixes
- **Persistence on Linux as a normal user:** another user's home that this account cannot enter no longer stops the
  shell start-up file review with a permission error (found by the new real-Ubuntu CI run).


## [1.3.0] - 2026-10-16

### Detection
- **Recent-activity traces (`traces`).**
  - **Run dialog:** finds commands pasted by ClickFix / fake-CAPTCHA attacks, including the "I am not a robot" lure.
  - **Command history:** finds download-and-run and Defender-tampering lines in PowerShell history, and strong
    attack patterns in bash, zsh and fish history (`curl | sh` from raw IPs or paste sites, `base64 -d | sh`, fake
    macOS password dialogs).
  - **Network traces:** checks the Windows DNS cache and the last 30 days of browser history against the
    malicious-domain feeds.
  - Developer installers from well-known hosts are not flagged.
- **Ransomware recovery readiness (`recovery`, part of `aegis audit`).**
  - **Recovery layers checked:** System Restore and shadow copies, File History, OneDrive folder backup, Google Drive,
    Dropbox, Time Machine, and Linux snapshot and backup tools.
  - **Result:** a Good / Fair / Weak grade with exact steps for each gap. Read-only.
- **Exploit protection in the hardening audit.** Reports DEP, ASLR, Control Flow Guard and SEHOP when they were
  explicitly switched off system-wide. ASLR, CFG and SEHOP have a fix that turns them back on.
- **Saved Wi-Fi networks.** Reviews every saved network, not only the current one: WEP, open networks the device
  joins automatically ("evil twin" risk), WPA/TKIP and hidden networks that are joined automatically. The fix switches
  the network to "connect manually"; nothing is deleted and no keys are read.

### Reports and app
- **"What to do first".**
  - **Grouping:** findings are grouped by kind, worst first.
  - **Fix commands:** each group has the exact command that fixes it.
  - **Where it appears:** the HTML report, the console report and the desktop dashboard, which has a Fix button per
    group.
- **HTML report:** every finding shows its location, and a search box filters findings by any text.

## [1.2.0] - 2026-10-16

### Detection
- **App tampering and session theft (`apptamper`).**
  - **Discord client injection** by token stealers: one-click restore of the genuine file, with undo.
  - **Electron and Node code injection** through `ELECTRON_RUN_AS_NODE` and `NODE_OPTIONS`.
  - **Hijacked browser shortcuts**, read by a new built-in `.lnk` parser. Covers forced extensions, remote-debugging
    ports, proxies, forced start pages, and shortcuts disguised as a browser.
  - **Browsers started hidden with remote debugging** to steal cookies, including the copied-profile variant used
    since Chrome 136. The real-time process guard also checks every new browser process for this.
  - **Exodus, Atomic Wallet and Ledger Live** apps whose code was swapped or that contain exfiltration endpoints.
- **Privacy and spyware review (`privacy`).** Reads the operating system's own record of which programs used the
  camera, microphone, location and screen capture (Windows), or hold camera, microphone, screen-recording,
  Accessibility and Input Monitoring permissions (macOS). Flags script hosts, programs in Temp, Downloads or hidden
  folders, programs that deleted themselves afterwards, and anything recording right now. Each device also gets an
  inventory of the apps that used it.
- **Software updater.** The software audit lists pending app updates from winget, apt, dnf, pacman or Homebrew, and
  flags outdated browsers, archivers, PDF readers, runtimes, communication and remote-access tools, and servers.
  `aegis apps upgrade` and the GUI's App updates tab install them through the package manager.

### Reporting
- **SARIF 2.1.0 output** (`--report out.sarif`, `aegis report out.sarif`, GUI export) for GitHub code scanning and
  other SARIF viewers. The output validates against the official schema. `check-project` writes paths relative to
  the project, and the README shows a GitHub Actions upload step.

### Fixes
- **Memory scanner false positives.** The "unbacked executable memory" check no longer flags .NET, Java, V8, Mono and
  LuaJIT processes, which compile code into such memory by design. Real-Windows CI showed seven of these false
  positives; it now skips exactly those seven.
- **Memory scanner ordering.** The check now runs before the YARA memory scan with its own time budget. Previously a
  slow YARA pass could leave it no time at all, and YARA now scans the processes it flags first.
- **`--scanners` help** lists every scanner, with a test so it cannot go stale.

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
