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
| **Persistence** | Autoruns-style review of Run keys, Winlogon, IFEO and accessibility backdoors, AppInit/AppCert, LSA packages, Startup folders, scheduled tasks (XML), services and drivers, WMI subscriptions and COM hijacks. On Linux/macOS: cron, systemd units and generators, rc files, `ld.so.preload`, udev, XDG autostart, PAM backdoors (`pam_exec`, `pam_permit`, modules outside the standard directories or not owned by a package), `update-motd.d` scripts, at jobs, LaunchAgents/Daemons, and on macOS periodic scripts, emond rules, authorization plugins, login/logout hooks, Background Task Management login items and the code signatures of launch agents and daemons |
| **Browsers** | Chrome, Edge, Brave, Vivaldi, Opera, Firefox and more. Checks extensions against known-malicious IDs, scores permission risk and flags sideloading. Detects search/homepage hijacks, forced-install policies, proxy settings, disabled Safe Browsing and notification spam, and counts saved passwords exposed to infostealers |
| **Network** | Connections to known botnet C2 IPs (Feodo Tracker), RAT/miner ports, risky listeners (RDP/SMB/VNC/WinRM), hosts-file hijacks, proxy and DNS hijacks, rogue root certificates (Superfish-style), open Wi-Fi and exposed SMB shares |
| **Network exposure** | Asks your router (UPnP) which ports it forwards from the internet and to which device: RDP, SMB, SSH, VNC, databases or the Docker API forwarded to this PC, and ports opened for programs running from Temp or Downloads, are flagged, and carrier-grade NAT is recognised. Flags the Docker Engine API exposed without TLS, and Redis, MongoDB, Elasticsearch, Memcached and SQL servers listening on all interfaces. Inbound firewall rules for script hosts, LOLBins and fake system processes are flagged by the network scanner |
| **Hardening audit** | Antivirus/Defender status and malicious exclusions, firewall, UAC, SMBv1, RDP/NLA, BitLocker, Secure Boot, **OS end-of-support** (Windows 10 EOL, Windows 11 release lifecycles), Windows Update age, WDigest/LSA/LM hashes, Guest/admin accounts, AutoRun, SmartScreen, hidden extensions, Office macro policy, LLMNR, PowerShell logging, and whether the screen **locks by itself when idle** (Windows, macOS, Linux desktops). Includes Linux and macOS checks, among them how old the XProtect definitions are |
| **Linux kernel hardening** | Reads `/proc` and `/sys` (read-only, nothing is loaded into the kernel): weak sysctls (ASLR, `kptr_restrict`, `dmesg_restrict`, Yama `ptrace_scope`, unprivileged eBPF, protected links and FIFOs, `suid_dumpable`, Magic SysRq), **known rootkit kernel modules** (Diamorphine, Reptile, Suterusu, Adore-ng, KoviD and others), **modules hidden from the module list** (loadable in `/sys/module` but missing from `/proc/modules`), kernel taint that no listed module explains, and whether AppArmor or SELinux is active or only permissive. Unsigned and out-of-tree modules that are listed (NVIDIA, VirtualBox, ZFS, DKMS) are recorded, not flagged. Skipped inside containers, whose kernel belongs to the host. Sysctl fixes set the value now and keep it in `/etc/sysctl.d/` |
| **Software** | PUP/adware/scareware detection (AdwCleaner-style) and vulnerable/EOL software (WinRAR CVE-2025-8088, 7-Zip CVE-2025-0411, PuTTY CVE-2024-31497, Flash, old browsers, Office EOL, and more). A **software updater** lists pending app updates from winget, apt, dnf or Homebrew, flags outdated browsers, archivers, PDF readers, runtimes and remote-access tools, and upgrades them with `aegis apps upgrade` |
| **Secrets** | Plaintext passwords files, crypto seed phrases, wallet files, cloud/API tokens, unencrypted SSH keys, saved RDP/FileZilla credentials, unattend.xml passwords. All values are masked in reports |
| **Real-time protection** | A file guard (scan on write, auto-quarantine), a process guard (new-process analysis, optional kill), a ransomware guard (hidden canary files plus mass-modification detection that suspends the culprit), a persistence guard (alerts on new autoruns and hosts changes), a clipboard guard (warns when a fake CAPTCHA page copies a ClickFix command, and empties the clipboard when it carries the lure; catches crypto "clipper" malware swapping a copied wallet address for the attacker's, names the program and puts your address back; text is only checked in memory), an extension guard (reports each browser extension added to Chrome, Edge, Brave, Firefox and others, rated with the browser scanner's rules, so a sideloaded or malicious one pops up at once) and desktop notifications |
| **App tampering & session theft** | Detects Discord client injection by token stealers (with a one-click restore of the genuine file), `ELECTRON_RUN_AS_NODE` / `NODE_OPTIONS` code injection, hijacked browser shortcuts (forced extensions, remote-debugging ports, proxies, forced start pages, shortcuts disguised as a browser), browsers started hidden with remote debugging to steal cookies (also caught in real time), and Exodus / Atomic / Ledger Live wallet apps whose code was swapped |
| **Recent-activity traces** | Finds the fingerprints of ClickFix / fake-CAPTCHA attacks: commands pasted into the Run dialog (Win+R) with the "I am not a robot" lure, download-and-run and Defender-tampering lines in PowerShell history, `curl \| sh` from raw IPs or paste sites, `base64 -d \| sh` and fake password dialogs in bash / zsh / fish history, plus known-malicious domains in the Windows DNS cache and in browser history (Chrome, Edge, Brave, Vivaldi, Opera, Firefox; last 30 days). Developer installers from well-known hosts are not flagged; evidence is masked and URLs lose their query strings |
| **Download origins** | Reviews where the risky files in Downloads and on the Desktop came from, using the record the system keeps with a download: the Windows Mark-of-the-Web (`Zone.Identifier`), the macOS quarantine record and `kMDItemWhereFroms`, or the `user.xdg.origin.url` attribute that Chrome, `wget --xattr` and `curl --xattr` write on Linux. Flags known-malicious sources (HIGH), `blob:` / `data:` addresses built by the page itself (HTML smuggling), WebDAV shares and raw IP addresses (MEDIUM), paste and file-sharing hosts and plain `http://` (LOW), and deceptive names (right-to-left override, `invoice.pdf.exe`; HIGH). On Windows it also reports the policy that stops Windows marking downloads (`SaveZoneInformation`) with a one-click fix. The real-time file guard adds the origin to its alerts. Addresses lose their query strings; nothing is read from the file |
| **Remote-access tools** | Answers what a tech-support-scam victim asks afterwards: can someone get in without my clicking Accept, and who connected, and when? Reads what AnyDesk (`connection_trace.txt`, `ad.trace`, unattended-access password), TeamViewer (`Connections_incoming.txt`, permanent password, account assignment), ScreenConnect / ConnectWise Control (relay host, Access or Support client), RustDesk (permanent password, self-hosted servers, logs), Splashtop, Atera (the account that manages the PC), NetSupport (`client32.ini` gateway) and MeshAgent (`MeshAgent.msh`) keep on disk, for every user profile it may read. Reports the tool's own incoming connections (MEDIUM, LOW when older than 90 days), unattended access (MEDIUM), relays on a bare IP address, a dynamic-DNS name, the threat feed or a NetSupport gateway (HIGH) or on any other self-hosted server (MEDIUM), and portable copies in Downloads, Desktop and Temp (MEDIUM). Passwords, hashes, keys and session ids are only ever shown as "set" or "not set"; logs are evidence and are never deleted. Running tools are reported by the process scanner |
| **Ransomware recovery readiness** | Answers "could I get my files back today?": System Restore and shadow copies, File History, OneDrive folder backup, Google Drive and Dropbox, Time Machine, and Linux snapshot and backup tools (Timeshift, snapper, ZFS, Btrfs, restic, Borg, Deja Dup), graded Good / Fair / Weak with exact steps. Read-only; part of `aegis audit` |
| **Privacy / spyware** | Reviews the operating system's own record of which programs used the camera, microphone, location and screen capture (Windows ConsentStore) or hold camera, microphone, screen-recording, Accessibility and Input Monitoring permissions (macOS TCC). Flags script hosts, programs in Temp/Downloads/hidden folders, programs that deleted themselves afterwards, and anything recording right now, plus an inventory of every app that used each device |
| **Threat hunting** | Windows event-log hunting (log clearing, new admins, RDP password-guessing success, suspicious service/task installs, Defender tampering, malicious PowerShell script blocks), vulnerable/abused kernel drivers (BYOVD) + Microsoft driver blocklist & memory-integrity checks, DLL side-loading, risky USB drives, malicious email attachments & spoofed senders, YARA memory scanning |
| **Sigma detection** | The community detection-rule standard: 20 bundled rules plus 1,100+ SigmaHQ Windows rules via `aegis update`. Rules are evaluated against Windows event logs and, in real time, against every new process. The engine was cross-checked against the reference pySigma implementation |
| **Supply-chain protection** | Reads lockfiles of every major ecosystem (npm/yarn/pnpm, pip/poetry/uv/Pipfile, Cargo, Go, Ruby, PHP, NuGet) and checks them against OSV.dev for **known-malicious packages** (CRITICAL) and vulnerable versions, with the exact fixed version. Also flags install-script droppers, typosquats, Shai-Hulud worm indicators, auto-run VS Code tasks, and malicious VS Code / Cursor / Windsurf extensions (Microsoft's removed-extensions list) |
| **Protection & hardening** | `aegis protect web` sinks malicious domains via a managed hosts-file block. `aegis protect ips` blocks botnet C2 IPs in the firewall. `aegis harden` applies a reviewed profile: Defender PUA/cloud/network protection, Attack Surface Reduction rules, SMBv1, LLMNR, WDigest, LSA protection, process-command-line auditing, Office macro blocking. Every change is journaled and reversible with `aegis undo` |
| **History & alerts** | Every scan is recorded: "new since last scan", resolved items and score trend in reports and the dashboard. Optional alerts to Slack, Microsoft Teams, Discord, any webhook or email (new findings only, rate-limited, secrets masked). `aegis doctor` self-checks privileges, signature freshness, data-folder permissions and services |
| **Tools** | Phishing/URL checker (lookalike domains, homoglyphs, brand impersonation, URLhaus, optional Google Safe Browsing), password strength and breach check (HIBP k-anonymity), deep file analysis, file integrity monitoring, threat-intel updater |
| **Remediation** | Quarantine/restore, kill process, remove registry autoruns, disable tasks/services, remove WMI persistence, clean hosts file, apply hardening fixes. Every change is backed up |
| **Reporting** | Security score and grade, HTML/JSON/CSV/TXT reports, **SARIF 2.1.0** for GitHub code scanning and other SARIF viewers, MITRE ATT&CK mapping, scripting exit codes |

## Quick start (Windows)

### Option A: packaged executable

1. Download `aegis-<version>-windows-x64.zip` from the
   [Releases page](https://github.com/anshnt/security/releases) and check it against `SHA256SUMS.txt`.
   You can also build it yourself with `scripts\build_windows.ps1`. The executables are not code-signed,
   so SmartScreen may warn on first run.
2. Extract the zip, then open **PowerShell as Administrator** in that folder:

```powershell
.\aegis.exe update            # fetch latest threat intelligence
.\aegis.exe scan quick        # ~1-2 min: processes, autoruns, downloads/desktop/temp, download origins, browsers, network
.\aegis.exe scan full --report html   # everything + all drives, writes an HTML report
.\aegis.exe fix               # review & apply fixes interactively
.\aegis-gui.exe               # desktop app
```

3. Optional: run `install_windows.ps1` (in the zip, or `scripts\` in the source tree) as Administrator. It installs Aegis to
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
           [--report out.html|html|json|csv|sarif] [--fix | --auto-fix high] [--json] [-v]
aegis audit                          hardening + software + network + browser review
aegis fix [--id ID] [-y --min-severity high]   apply fixes from the last scan
aegis allow --id ID | --hash SHA256 | --path P suppress false positives
aegis quarantine list|restore|delete|add ...
aegis monitor [--auto-quarantine] [--kill]     real-time protection (foreground)
aegis update                         MalwareBazaar, Feodo C2 IPs, URLhaus, malicious extensions, LOLDrivers,
                                     YARA Forge, SigmaHQ rules, malicious IDE extensions
aegis check-project PATH [--offline] malicious / vulnerable dependencies, install-script droppers, typosquats
aegis apps [list | upgrade ID... | upgrade --all] [-y]   pending app updates (winget / apt / dnf / brew)
aegis protect web|ips on|off|status  malicious-domain blocklist / C2 IP firewall blocking
aegis harden [--profile recommended|strict] [--apply] [--list]   reviewed hardening, plan first
aegis undo [list|latest|ID]          revert any fix, hardening run or protection change
aegis history [list|show ID|diff|trend]   past scans and what changed
aegis doctor [--fix]                 self-check of the installation
aegis alert status|test              Slack / Teams / Discord / webhook / email alerts
aegis sigma list | sigma test RULE EVENTS.json
aegis check-file FILE [--cloud]      deep static analysis (+ Defender + VirusTotal)
aegis check-url URL                  phishing / malicious URL verdict
aegis check-password                 strength + breach check (k-anonymity)
aegis autoruns [--json]              list every autostart entry
aegis integrity baseline|check       file integrity monitoring
aegis report out.html|out.sarif [--source-root DIR]   render the last scan
aegis fleet PATH... [-o fleet.html|json|csv] [--since DAYS] [--recursive]   one overview of many PCs' scans
aegis info | config show | config set KEY VALUE
aegis gui | install-service | uninstall-service
```

Exit codes: `0` means clean, `1` means findings at or above `--fail-on` (default `high`), `2` means an error.

### Supply-chain checks in CI (GitHub code scanning)

`aegis check-project` writes SARIF with file locations relative to the project, so its findings show up as
code-scanning alerts on the right files:

```yaml
# job needs: permissions: { contents: read, security-events: write }
- run: pip install git+https://github.com/anshnt/security
- run: aegis check-project . --report aegis.sarif --fail-on critical
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: aegis.sarif
    category: aegis-supply-chain
```

### One overview of many PCs (`aegis fleet`)

For a small office, a school or a family, let each PC's scheduled scan write its JSON result to a shared folder, then
build one page from that folder:

```powershell
# on every PC (scheduled task):
aegis scan full --quiet --report "\\server\share\aegis\$env:COMPUTERNAME-$(Get-Date -Format yyyy-MM-dd).json"
# on the admin PC:
aegis fleet \\server\share\aegis -o fleet.html --since 7
```

The page lists every PC worst first (score and grade, critical / high / medium counts, new findings and score change
since its previous scan, admin or not), the issues that show up on the most PCs, and for each PC what to do first.
Only the newest result of each PC is shown; keep the older files in the folder to get its score trend. `--since 7`
marks PCs with no scan in the last 7 days as stale. Use `-o fleet.json` or `-o fleet.csv` for other tools, and
`--recursive` to search sub-folders. Files that are not Aegis scan results are skipped and counted. Exit code `1`
means some PC has findings at or above `--fail-on` (default `high`), `2` that no scan result was found.

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
| eventlog | ✅ | – | – | ✅ Security log |
| drivers | ✅ | – | – | some driver files |
| sideload | ✅ | ✅ | ✅ | – |
| usb | ✅ | ✅ | ✅ | device history |
| email | ✅ | ✅ | ✅ | – |
| memory | ✅ | ✅ | ✅ | other users' processes |
| supplychain | ✅ | ✅ | ✅ | – |
| ide | ✅ | ✅ | ✅ | – |
| privacy | ✅ | – | ✅ (needs Full Disk Access) | – |
| apptamper | ✅ | ✅ | ✅ | other users' processes |
| recovery | ✅ | ✅ | ✅ | restore points / shadow copies (Windows), Full Disk Access (macOS) |
| traces | ✅ | ✅ | ✅ | – |
| downloads | ✅ | ✅ | ✅ | to change the HKLM attachment policy |
| remoteaccess | ✅ | ✅ | ✅ | other users' profiles |
| exposure | ✅ | ✅ | ✅ | – |

The `full` profile runs every scanner. A threat-hunting pass on its own:
`aegis scan custom --scanners eventlog,drivers,sideload,usb,email,memory`.

## Testing

```
pip install -e .[dev]
pytest -q
```

The suite (about 1,170 tests) builds malware-like samples at runtime, using EICAR and synthetic
PE/script/document/email files, so the repository never contains live malware. CI runs it on Ubuntu
and Windows, builds the Windows executables, and then runs the packaged `aegis.exe` end to end on a
live Windows machine (audit, quick scan and threat-hunting scanners), failing on any internal scanner
error. The HTML/JSON reports from that run are uploaded as a build artifact.

## Documentation

* [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md): requirements, system requirements, threat coverage
* [docs/COMPARISON.md](docs/COMPARISON.md): comparison with commercial and free tools, and the roadmap
* [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): how the engine works
* [docs/RULES.md](docs/RULES.md): writing your own detection rules
* [docs/THREAT_LANDSCAPE.md](docs/THREAT_LANDSCAPE.md): sourced 2025–2026 threat briefing and how Aegis maps to it

## Disclaimer

No security product detects everything. Heuristic findings are labelled *suspicious* and explain their
reasoning, so verify them before deleting files. Licensed under MIT.
