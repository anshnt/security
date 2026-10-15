# Endpoint threat landscape brief (Windows home/SMB), as of 2026-10-15

Purpose: give Aegis contributors a sourced picture of what is actually hitting consumer and SMB Windows PCs
in 2025-2026, which defensive advances change the picture, and where Aegis's detection and audit logic
should follow. It is defensive research. It describes behaviours to detect and contains no payloads.

## 0. How to read this brief (method and confidence)

Research was done on 2026-10-15 with web search and page fetches. Every claim carries a source URL and a
confidence tag.

| Tag | Meaning |
|---|---|
| **[P]** | The page itself was opened and read (vendor, researcher or news article). Numbers are as stated there. |
| **[S]** | Taken from a search-result summary of the page. The page was not opened (blocked, binary, or not fetched). Treat numbers as approximate. |
| **[I]** | Inference by the author of this brief, not a claim made by a source. |

Known limits of this pass:

* Several primary reports could not be read: the ESET H1 2026 PDF (binary, unreadable by the fetch tool), the
  GuidePoint Q2 2026 ransomware post and the Dark Reading Vidar article (HTTP 403), the Intrinsec "New Vidar"
  PDF, the Recorded Future 2025 infrastructure report and the Microsoft Digital Defense Report 2025. Where this
  brief quotes them, it does so through secondary coverage and tags the claim **[S]**.
* Vendor counts of "most active" families differ because they measure different things (leak-site claims,
  sandbox uploads, C2 servers, marketplace listings, telemetry). Rankings below are therefore ranges, not facts.
* Several well-known statistics are repeated with the wrong year. The ESET "517% ClickFix growth" is the H1 2025
  figure, while the H1 2026 figure is 108% (see 2.1). The Microsoft "47% of initial access is ClickFix"
  figure comes from the 2025 report, not 2026. A claim that malicious browser extensions reached "millions of
  users" was not supported by any source found (the largest single extension count was about 70,000 Chrome plus
  10,000 Edge users).
* Nothing here was run or detonated. No indicator in this document has been validated against Aegis.

## 1. Executive summary

1. **User-run commands are now the main front door.** Microsoft's 2025 Digital Defense Report is reported to put
   ClickFix at 47% of initial-access cases handled by Defender Experts, ahead of phishing at 35% **[S]**
   ([Intel 471](https://www.intel471.com/blog/clickfix-tricking-users-into-installing-infostealers)).
   ESET measured a further 108% rise in ClickFix detections from H2 2025 to H1 2026, and the technique now
   spreads to browser extensions (CrashFix), AI-themed help pages and OAuth consent theft (ConsentFix) **[P]**
   ([Help Net Security on ESET H1 2026](https://www.helpnetsecurity.com/2026/07/08/eset-ai-threat-trends-report/)).
   The lure moves around whatever defenders watch: Run dialog, then Windows Terminal (Win+X, I), then the Explorer
   address bar (FileFix), and in October 2026 payloads pre-planted in the browser cache.
2. **The infostealer market was shaken up by takedowns but not reduced.** Lumma (May 2025) and Rhadamanthys
   (November 2025) were disrupted. Vidar 2.0 took the top spot on Russian Market by November 2025 **[S]**, Lumma
   recovered through new loaders **[S]**, and StealC, ACR Stealer and others stayed active. Flashpoint counts about
   1.7 billion stolen credentials from 7.4 million infected devices in H1 2026, up 27% on H2 2025, with Vidar, StealC
   and Lumma on top **[P]** ([Infosecurity Magazine](https://www.infosecurity-magazine.com/news/infostealers-17-billion/)).
3. **Stolen credentials feed ransomware, and ransomware crews kill the security tools first.** ESET tracks
   more than 100 EDR killers, over 60 of them BYOVD variants abusing more than 40 vulnerable drivers **[P]**
   ([Help Net Security](https://www.helpnetsecurity.com/2026/07/08/eset-ai-threat-trends-report/)). The top Q2 2026
   ransomware groups (Qilin, Akira, The Gentlemen, DragonForce, LockBit 5.0) mostly enter through edge devices and
   VPN accounts, but also through fake IT-support contact on Microsoft Teams that ends with AnyDesk or Quick Assist
   **[P]** ([Dragos](https://www.dragos.com/blog/dragos-industrial-ransomware-analysis-q2-2026)).
4. **"Legitimate software" is the payload carrier.** Signed RMM installers (MSP360, ScreenConnect, SimpleHelp),
   legitimate runtimes (Node.js, Deno, Python), signed Microsoft or Canon binaries used for DLL side-loading,
   MSBuild, finger.exe and 7-Zip all appear in 2026 intrusion chains. File-reputation and signature checks alone
   miss these.
5. **AI branding is the new lure.** Fake Claude, ChatGPT and Copilot installers, sponsored-search Custom GPTs that
   lead to ClickFix pages, malicious agent "skills", and fake AI coding tool installers are all documented in 2026.
6. **Defensive advances help, but each has a gap.** Chrome's Device Bound Session Credentials (Chrome 146,
   Windows, April 2026) blunt cookie replay but not password or key theft. Windows 10 consumer ESU was quietly
   extended to 2027-10-12. Smart App Control, Quick Machine Recovery and the Microsoft driver blocklist exist but
   are partial or inconsistently enabled.

## 2. Initial access and delivery techniques

### 2.1 ClickFix and its variants (fake CAPTCHA, fake fixes)

* **Scale.** 47% of Microsoft Defender Experts initial-access cases in the 2025 reporting year **[S]**
  ([Intel 471](https://www.intel471.com/blog/clickfix-tricking-users-into-installing-infostealers)). ESET: detections
  +108% between H2 2025 and H1 2026 **[P]**
  ([Help Net Security](https://www.helpnetsecurity.com/2026/07/08/eset-ai-threat-trends-report/)).
* **Variants named by ESET [P]:** AI-fix (fake AI troubleshooting pages), CrashFix (a malicious extension crashes
  the browser, then offers a fake fix), ConsentFix (theft of Microsoft OAuth authorisation codes).
* **Windows Terminal instead of Run.** Microsoft saw a February 2026 campaign telling users to press Win+X then I
  and paste into Windows Terminal, which evades detections written for the Run dialog. One chain ended with Lumma
  injected into `chrome.exe` and `msedge.exe` via `QueueUserAPC()`, used renamed 7-Zip, scheduled tasks and Defender
  exclusions. A second chain used a batch file, VBScript, `MSBuild.exe` and blockchain RPC lookups ("EtherHiding")
  **[P]** ([The Hacker News](https://thehackernews.com/2026/03/microsoft-reveals-clickfix-campaign.html)).
* **Browser-cache smuggling (disclosed 2026-10-03).** Compromised sites pre-load a script into the browser cache,
  disguised as a PNG. The pasted command is short (it avoids the Run dialog's roughly 260 character limit) and only
  searches the browser profile for cache files named `f_*`, matches one by byte size, copies it to `%TEMP%\t.vbs` and
  runs it with `wscript.exe`. Later stages use WMI recon, PowerShell, in-memory .NET and injection into `timeout.exe`
  **[P]** ([The Hacker News](https://thehackernews.com/2026/10/clickfix-smuggles-payloads-through.html);
  also [Infosecurity Magazine](https://www.infosecurity-magazine.com/news/clickfix-vbscript-browser-cache/) **[S]**).
* **FileFix.** The lure opens a File Explorer window and puts a command on the clipboard disguised as a file path;
  the victim pastes it into the address bar. There is no downloaded file, so Mark-of-the-Web never applies. Seen
  delivering RATs and stealers since 2025 **[S]**
  ([Intel 471](https://www.intel471.com/blog/threat-hunting-case-study-filefix)). No distinct 2026 variant was
  confirmed in this pass.
* **Detection signals documented by defenders [P]**
  ([glueckkanja](https://www.glueckkanja.com/en/posts/2026-09-21-clickfix-prevent-detect)):
  * Registry writes by `explorer.exe` to `...\Explorer\RunMRU` with a checkmark emoji, non-Latin Unicode mixed with
    `powershell`, `mshta`, `curl`, `msiexec`, `-w h`, `-eC`, `iex`, `irm`, `iwr`, `DownloadString`, `FromBase64String`.
  * Process lineage `WindowsTerminal.exe` to `pwsh.exe` to `powershell.exe` running `iex(irm ...)` hidden.
  * Microsoft Defender for Endpoint has had ClickFix alerts since Q2 2025, but cloud alerts can lag by over a minute.
  * Microsoft's own advice: a CAPTCHA never asks you to paste commands; consider restricting the Run dialog; enable
    cloud, web and network protection, application control and PowerShell script-block logging **[P]**
    ([The Hacker News](https://thehackernews.com/2026/10/clickfix-smuggles-payloads-through.html)).

### 2.2 Malvertising, SEO poisoning and fake installers

* **Fake VPN clients (Microsoft, March 2026).** SEO-poisoned pages for "Pulse VPN download" and other VPN brands
  serve a ZIP with an MSI signed by a (since revoked) certificate. DLL side-loading (`dwmapi.dll`) loads a Hyrax
  infostealer variant, shows a fake sign-in dialog to capture VPN credentials, then redirects to the real vendor
  site. Persistence via `RunOnce` **[P]**
  ([Microsoft](https://www.microsoft.com/en-us/security/blog/2026/03/12/storm-2561-uses-seo-poisoning-to-distribute-fake-vpn-clients-for-credential-theft/)).
* **Fake software sites to ScreenConnect to AsyncRAT (Kaspersky, July 2026).** More than 90 domains in 10
  languages impersonating OBS Studio, DS4Windows, Bandicam and others. A signed Microsoft `install.exe` side-loads a
  rogue `install.res.1033.dll`, which installs ScreenConnect. A script then adds Defender exclusions, disables UAC
  prompts, drops files in `C:\Users\Public`, runs AsyncRAT by process hollowing and persists with a scheduled task
  every two minutes **[P]**
  ([The Hacker News](https://thehackernews.com/2026/07/seo-poisoned-software-sites-abuse.html)).
* **Fake YouTube software downloads** are a documented Vidar delivery chain **[S]**
  ([Intrinsec report](https://www.intrinsec.com/wp-content/uploads/2026/04/TLP_CLEAR-20260424-New_Vidar.pdf), via
  [Dark Reading](https://www.darkreading.com/vulnerabilities-threats/vidar-top-chaotic-infostealer-market)).
* **Paid search placement** above legitimate results for utility, security and browser downloads is described
  as a general delivery route, not tied to one named ad campaign **[S]**.
* **Fake browser updates.** SocGholish/FakeUpdates injects update prompts into compromised, mostly WordPress,
  sites. Operation Endgame actioned its infrastructure in June 2026 (14,971 infected websites remediated), alongside
  Amadey and StealC. Totals reported: 326 servers, 142 domains, 27 million stolen logins recovered, and Microsoft
  linked over 140,000 infected computers to SocGholish and Amadey **[P]**
  ([Security Affairs](https://securityaffairs.com/194173/cyber-crime/europol-disrupts-stealc-and-amadey-malware-infrastructure-in-operation-endgame.html);
  [Spamhaus](https://www.spamhaus.org/endgame-socgholish) **[S]**). Advice to ordinary users: install updates only
  through system settings or official stores.

### 2.3 Trojanized AI tools, fake AI installers and AI-themed lures

* **Fake Claude site (April 2026).** A look-alike download page served a working copy of the app while a PlugX chain
  ran in the background; the installer folder was misspelled "Cluade" **[S]**
  ([Malwarebytes](https://www.malwarebytes.com/blog/scams/2026/04/fake-claude-site-installs-malware-that-gives-attackers-access-to-your-computer)).
* **Fake ChatGPT/Claude installers on GitHub and SourceForge, promoted by hijacked YouTube channels (May 2026).**
  The user is told to paste a command. The chain installs Scoop and WinGet, uses them to install the legitimate Deno
  runtime, then runs the DinDoor backdoor and a Deno-based RAT in memory. The RAT steals from 50+ wallet extensions,
  streams the screen through a silently launched Edge using the Chrome DevTools Protocol and WebRTC, and persists with a
  Run key **[P]**
  ([Help Net Security](https://www.helpnetsecurity.com/2026/05/27/deno-rat-malware-fake-chatgpt-claude-installers/)).
* **Custom GPT to ClickFix to RAT (Huntress, late September 2026).** A sponsored Google result led to a Custom GPT
  named "Plus 5.6", then a Google Sites page with a fake Cloudflare CAPTCHA, then an MSI that side-loads a rogue DLL
  through a Canon-signed binary, unpacks a loader hidden in a WAV file, bypasses AMSI, unhooks `ntdll.dll`, and
  resolves C2 over DNS-over-HTTPS. At least 40 victims **[P]**
  ([The Hacker News](https://thehackernews.com/2026/09/attackers-abuse-chatgpt-custom-gpts-to.html)).
* **Malicious agent skills.** ESET analysed nearly 900,000 AI skills: over 25,000 suspicious and over 3,000
  malicious **[P]** ([Help Net Security](https://www.helpnetsecurity.com/2026/07/08/eset-ai-threat-trends-report/)).
  The ClawHub/OpenClaw cases found hundreds of malicious skills, mostly delivering Atomic macOS Stealer, with counts
  that vary by audit (341 initially, over 824 later, 1,184 by Antiy) **[S]**
  ([The Hacker News](https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html),
  [Dark Reading](https://www.darkreading.com/cyber-risk/malicious-openclaw-skills-clawhub-threaten-ai-supply-chain)).
  Relevance for Windows home users is mainly developers and power users who run agent frameworks with full user
  permissions.

### 2.4 Malicious browser extensions

* **CrashFix (January 2026).** A cloned uBlock Origin Lite named "NexShield" was promoted by a malicious ad and
  installed from the Chrome Web Store. It waits 60 minutes, then floods runtime ports until the browser crashes. On
  restart a fake warning tells the user to paste a command that abuses `finger.exe`. The next stage is ModeloRAT, a
  Python RAT with Run-key persistence, delivered mainly to domain-joined machines, tied to KongTuke (a traffic
  distribution service whose access is sold to ransomware groups) **[P]**
  ([The Hacker News](https://thehackernews.com/2026/01/crashfix-chrome-extension-delivers.html);
  [Huntress](https://www.huntress.com/blog/malicious-browser-extention-crashfix-kongtuke) **[S]**).
* **August 2026 cluster.** 18 Chrome and 1 Edge extensions linked to one campaign stole crypto and browsing data and
  injected ClickFix lures; the most popular had about 70,000 Chrome and 10,000 Edge users **[S]**
  ([BleepingComputer](https://www.bleepingcomputer.com/news/security/chrome-web-store-extensions-caught-stealing-crypto-browser-data/)).
* **January 2026 cluster.** Five extensions posing as Workday, NetSuite and SAP SuccessFactors tools performed
  session hijacking **[S]** ([Arete](https://areteir.com/resources/malicious-chrome-extensions-enterprise-threats)).

### 2.5 Signed-driver abuse and EDR killers (BYOVD)

* ESET (March 2026): nearly 90 EDR killers, 54 using BYOVD against 35 signed vulnerable drivers. Developers include
  closed ransomware groups (DeadLock, Warlock), forks of public proofs of concept, and commercial sellers. Other
  categories: script-based killers (`taskkill`, `net stop`, `sc delete`, Safe Mode), anti-rootkit utilities (GMER,
  HRSword, PC Hunter) and driverless tools that block EDR outbound traffic **[P]**
  ([The Hacker News](https://thehackernews.com/2026/03/54-edr-killers-use-byovd-to-exploit-34.html)).
* Later ESET numbers: over 100 EDR killers, over 60 BYOVD variants, over 40 drivers, new variants weekly **[P]**
  ([Help Net Security](https://www.helpnetsecurity.com/2026/07/08/eset-ai-threat-trends-report/)).
* Reynolds ransomware bundles the EDR killer and encryptor in one binary **[P]**
  ([The Hacker News](https://thehackernews.com/2026/03/54-edr-killers-use-byovd-to-exploit-34.html)). Qilin, The
  Gentlemen and DragonForce use EDR killers routinely; DragonForce also exploited a zero-day in a Huawei driver
  **[P]** ([Dragos](https://www.dragos.com/blog/dragos-industrial-ransomware-analysis-q2-2026)).
* Blocking one driver does not stop the technique, because operators rotate to another **[P]** (THN above).
  Reports recommend the Microsoft vulnerable driver blocklist, HVCI and App Control, and note the blocklist is not
  always on, especially on older systems without HVCI **[S]**.

### 2.6 RMM tool abuse

* **Phishing delivers a signed RMM installer (Microsoft, 2026-09-29).** July 2026 campaigns used a legitimately signed
  MSP360 installer under lure filenames (meeting invites, Zoom/Meet, Acrobat updates, tax and DHL themes). It
  installs services, Run keys and an inbound UDP 48678 firewall rule, then pulls ScreenConnect with `msiexec /qn` as a
  second channel and runs credential-theft tools such as browser password viewers. The MSP360 signing certificate was
  revoked **[P]**
  ([Microsoft](https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/)).
* **Fake IT support over Teams.** Attackers pose as internal IT on Microsoft Teams and guide victims into AnyDesk or
  Quick Assist sessions **[P]** ([Dragos](https://www.dragos.com/blog/dragos-industrial-ransomware-analysis-q2-2026)).
* **Server-side:** DragonForce exploited SimpleHelp to reach managed service providers and their customers **[P]**
  (Dragos, same link). CISA advisory AA25-163A covers SimpleHelp exploitation **[S]**.
* Recommended controls from Microsoft: approve RMM tools and enforce MFA on them, block unapproved RMMs with App
  Control or AppLocker publisher rules, and hunt for multiple RMM tools on one host.

### 2.7 MSIX, LNK and archive-borne delivery

* **LNK in ZIP is active in 2026.** Microsoft's June 2026 "photo ZIP" case: a phishing relay through Calendly, a
  fresh `photo-*.cfd` domain behind a Turnstile challenge, then `photo-<digits>.zip` holding `IMG-<digits>.png.lnk`
  (about 2 KB). The shortcut runs an obfuscated PowerShell stage, a user-profile `node.exe` runs the TonRAT implant,
  and persistence uses both `HKCU\Run` and `HKCU\RunOnce`. Removing only one entry leaves the implant running **[P]**
  ([Microsoft](https://www.microsoft.com/en-us/security/blog/2026/06/25/photo-zip-campaign-targeting-hospitality-industry-delivers-node-js-implant-persistent-access/)).
  Other 2026 LNK reports: a USB-spread LNK clipper (CryptoBandits) **[S]**
  ([The Hacker News](https://thehackernews.com/2026/06/microsoft-details-windows-clipper.html)) and spear-phishing ZIPs
  with LNK and BAT loaders **[S]** ([Seqrite](https://www.seqrite.com/blog/operation-covert-access-weaponized-lnk-based-spear-phishing-targeting-argentinas-judicial-sector-to-deploy-a-covert-rat/)).
* **MSIX abuse is established but this pass found no clearly 2026 campaign.** Background: signed MSIX packages
  posing as Zoom, Teams or Grammarly used by FIN7, Zloader and FakeBat; Microsoft disabled the `ms-appinstaller`
  protocol handler in early 2024 **[S]**
  ([Red Canary](https://redcanary.com/blog/threat-intelligence/msix-installers/),
  [Malwarebytes](https://www.malwarebytes.com/blog/news/2024/01/microsoft-disables-ms-appinstaller-after-malicious-use),
  [eSentire](https://www.esentire.com/blog/fakebat-continues-signed-msix-app-package-abuse)). MSI is the more
  common 2026 wrapper in the cases above (Storm-2561, Custom GPT, ScreenConnect).
* **Signed-by-stolen-certificate** is a recurring enabler: the Storm-2561 and MSP360 certificates were later
  revoked **[P]** (Microsoft links above).

## 3. Prevalent malware families on consumer and SMB Windows

### 3.1 Infostealers

| Family | 2025-2026 status | Source |
|---|---|---|
| **Vidar (2.0, June 2025)** | Rewritten in C, multithreaded, per-build morphing. Reported as most-used stealer on Russian Market since November 2025. Steals via app-bound-encryption bypass by launching the browser with debugging and injecting to read keys from memory. Targets Chrome, Edge, Opera, Vivaldi, Firefox, crypto wallet extensions, MSAL cache, FileZilla, WinSCP, Steam, Telegram, Discord. C2 dead-drops via Telegram bots and Steam profiles. | [Trend Micro](https://www.trendmicro.com/en_gb/research/25/j/soc-agentic-siem/how-vidar-stealer-2-upgrades-infostealer-capabilities.html) **[P]**; ranking via [Dark Reading](https://www.darkreading.com/vulnerabilities-threats/vidar-top-chaotic-infostealer-market) **[S]** |
| **Lumma (LummaC2)** | Disrupted May 2025, back within weeks, new browser fingerprinting from October 2025, CastleLoader distribution reported February 2026. Still among the top three in Flashpoint's H1 2026 data. | [Trend Micro](https://www.trendmicro.com/en_us/research/25/k/lumma-stealer-browser-fingerprinting.html), [CyberInsider](https://cyberinsider.com/lummastealer-returns-using-castleloader-to-bypass-detection/) **[S]**; [Infosecurity](https://www.infosecurity-magazine.com/news/infostealers-17-billion/) **[P]** |
| **StealC (v2, March 2025)** | RC4 C2, MSI and PowerShell delivery. Part of the June 2026 Endgame action but still top three in H1 2026 data. | [Security Affairs](https://securityaffairs.com/194173/cyber-crime/europol-disrupts-stealc-and-amadey-malware-infrastructure-in-operation-endgame.html) **[P]** |
| **Rhadamanthys** | 1,025 servers seized in Endgame 3.0 (10-13 November 2025). Operator reportedly had access to over 100,000 crypto wallets. | [The Register](https://www.theregister.com/2025/11/13/rhadamanthys_takedown/), [Help Net Security](https://www.helpnetsecurity.com/2025/11/13/rhadamanthys-infostealer-operation-disrupted/) **[S]** |
| **ACR Stealer, Amadey, Hyrax, RedLine remnants** | ASEC's early 2026 data lists LummaC2, ACRStealer, StealC and Vidar as the dominant active families **[S]** (via search summary of [Gridinsoft](https://blog.gridinsoft.com/infostealer-malware-top/)). Amadey is also a loader and was in the June 2026 action. Hyrax was the payload in the Storm-2561 fake VPN case. | see links |

Market-level numbers: about 1.7 billion credentials and 7.4 million infected devices in H1 2026 **[P]**
([Infosecurity](https://www.infosecurity-magazine.com/news/infostealers-17-billion/)). Note that the user asked about
"Acreed"; no source on a stealer of that name was found, so it is not covered here.

### 3.2 Loaders

* **CastleLoader.** Delivered by ClickFix pages and fake GitHub repositories. Observed delivering NetSupport RAT,
  WarmCookie, DeerStealer, RedLine, StealC, SectopRAT, HijackLoader, Rhadamanthys and Remcos **[S]**
  ([PolySwarm](https://blog.polyswarm.io/castleloader),
  [SC World](https://www.scworld.com/brief/malware-loader-castleloader-targets-devices-via-fake-github-clickfix-phishing)).
* **HijackLoader** is a modular second-stage loader delivered by other loaders **[S]**
  ([ANY.RUN](https://any.run/malware-trends/hijackloader/)).
* **SocGholish/FakeUpdates and Amadey**: see 2.2. Latrodectus was not covered by any source found.
* **Custom side-loading loaders** in the Custom GPT, Storm-2561 and Kaspersky cases: legitimate signed binary plus a
  malicious DLL in the same folder **[P]**.

### 3.3 Remote access trojans

* Recorded Future's 2025 C2 validation data: AsyncRAT and QuasarRAT lead, DcRAT and Remcos gaining share **[S]**
  ([Recorded Future](https://assets.recordedfuture.com/insikt-report-pdfs/2026/cta-2026-0319.pdf)).
* Sandbox uploads, week of 20-26 July 2026: AsyncRAT 214, XWorm 205, Remcos 158, with Vidar the top stealer. These
  are submissions, not infections **[S]**
  ([Cybersecurity News](https://cybersecuritynews.com/top-10-malware-used-by-hackers/)).
* ESET telemetry: DcRat is the most distributed AsyncRAT fork at 24% of fork infections, then VenomRAT at 8% **[S]**
  ([CyberScoop](https://cyberscoop.com/asyncrat-malware-variants-eset/)). VenomRAT was part of the November 2025
  Endgame action.
* Newer RATs seen in cases above: DinDoor and a Deno RAT, TonRAT (Node.js), ModeloRAT (Python), PlugX, plus
  commercial RMM tools used as RATs (ScreenConnect, MSP360, NetSupport).
* Trend: **interpreter-based implants** (Node.js, Deno, Python) running from the user profile, which are not
  flagged by PE-oriented static analysis **[I]**.

### 3.4 Ransomware groups and their initial access

Q2 2026 claims (Dragos, leak-site counts) **[P]**
([Dragos](https://www.dragos.com/blog/dragos-industrial-ransomware-analysis-q2-2026)):

| Rank | Group | Q2 claims | Q1 claims |
|---|---|---|---|
| 1 | Qilin | 140 | 198 |
| 2 | Akira | 129 | 100 |
| 3 | The Gentlemen | 125 | 83 |
| 4 | DragonForce | 76 | 45 |
| 5 | LockBit 5.0 | 62 | 71 |
| 6 | Inc Ransom | 50 | 52 |
| 7 | Deadlock | 45 | new |
| 8 | Safepay | 36 | 19 |

Other rankings disagree on the order at the top: one source says The Gentlemen overtook Qilin in June 2026
([Dexpose](https://www.dexpose.io/ransomware-groups/)), another counts 91 active groups in Q2, up from 68 in Q1
([Brandefense](https://brandefense.io/blog/top-5-ransomware-groups-q2-2026/)) **[S]**.

Initial access seen by group **[P]** (Dragos): Qilin through internet-facing appliances, a Check Point VPN bypass and
stolen credentials; Akira through VPN devices and a legacy VPN account without MFA, with several days of credential
theft and backup destruction before encryption; The Gentlemen through Fortinet and Cisco edge devices; DragonForce
through SimpleHelp; fake IT-support contact on Teams leading to AnyDesk or Quick Assist across groups.

Why this matters to home and SMB PCs: browser-stored credentials are harvested first (Qilin), and infostealer logs are
a recognised access source. Estimates of how often victims appear in stealer logs range from about one in five Qilin
victims to over half of 2024-2025 victims, but these come from vendor blogs and should be treated as indicative only
**[S]** ([CYFIRMA](https://www.cyfirma.com/research/the-convergence-of-infostealers-and-ransomware-from-credential-harvesting-to-rapid-extortion-chains/)).
Chainalysis (quoted by ESET coverage): 28% of ransomware victims paid in 2025, median ransom up 368% to nearly
$60,000, total payments $820 million **[P]**
([Help Net Security](https://www.helpnetsecurity.com/2026/07/08/eset-ai-threat-trends-report/)).

## 4. Defensive advances that change the picture

| Advance | What it does | Limits and status | Source |
|---|---|---|---|
| **Device Bound Session Credentials (Chrome 146, Windows, April 2026)** | Binds the session to a TPM-held key and issues short-lived cookies, so a stolen cookie cannot be renewed off the device. | Only sites that add DBSC endpoints benefit. No software-key fallback yet for PCs without suitable hardware. Does not stop theft of passwords, tokens, wallet files, or in-session abuse by malware. Already-stolen cookies are unaffected. | [Help Net Security](https://www.helpnetsecurity.com/2026/04/10/google-chrome-device-bound-session-credentials) **[P]**, [Google](https://blog.google/security/protecting-cookies-with-device-bound-session-credentials/) |
| **Windows 10 consumer ESU extended to 2027-10-12** | Enrolled personal PCs get security fixes for another year. Enrol via Windows Backup (no extra cost), 1,000 Microsoft Rewards points, or $30. Requires 22H2 and a Microsoft account with admin rights. | The change appeared quietly in documentation and an editor's note. Commercial ESU runs to 2028-10-10 **[S]**. | [Help Net Security](https://www.helpnetsecurity.com/2026/06/26/microsoft-windows-10-free-security-updates-esu-program/) **[P]** |
| **Microsoft Edge scareware blocker** | On-device ML detects full-screen fake alerts, exits full screen, stops audio. | Default state is reported inconsistently by sources. Edge-only. Not a ClickFix paste blocker. | [Microsoft Support](https://support.microsoft.com/en-us/edge/prevent-online-scams-with-the-scareware-blocker-in-microsoft-edge) **[S]** |
| **Defender ClickFix behaviour alerts** | Behaviour-based alerts since Q2 2025. | Cloud alerts can lag by over a minute. Gaps for Terminal and Explorer launch surfaces were documented in 2026. | [glueckkanja](https://www.glueckkanja.com/en/posts/2026-09-21-clickfix-prevent-detect) **[P]** |
| **Quick Machine Recovery** | Fixes unbootable PCs through WinRE and Windows Update without reimaging (build 26100.4770 or later, default on for Home). | Resilience feature, not prevention. | [Neowin](https://www.neowin.net/news/windows-11-quick-machine-recovery-will-help-restore-pcs-that-cannot-boot/) **[S]** |
| **Smart App Control** | Reputation-based blocking of unknown executables. Insider tests in July 2026 let users toggle it without a clean install. | Preview changes, not confirmed GA. | [IT-Connect](https://www.it-connect.fr/microsoft-ameliore-quick-machine-recovery-et-simplifie-lactivation-de-smart-app-control/) **[S]** |
| **Administrator Protection** | Just-in-time admin tokens to reduce silent elevation. | Status is unclear: one third-party source says the October 2025 rollout was reverted and the feature disabled from retail and Insider channels in June 2026. Not confirmed against Microsoft. Do not assume it is on. | [Petri](https://petri.com/windows-11-enable-administrator-protection-settings/) **[S]** |
| **Microsoft vulnerable driver blocklist, HVCI, App Control** | Prevent known vulnerable drivers from loading. | Attackers rotate to unlisted drivers; a June 2026 case used a driver on no public blocklist **[S]**. | [The Hacker News](https://thehackernews.com/2026/03/54-edr-killers-use-byovd-to-exploit-34.html) **[P]** |
| **Law-enforcement disruption (Endgame)** | Rhadamanthys (Nov 2025), SocGholish/Amadey/StealC (June 2026), recovered stolen-credential sets shared with victim-notification services such as Have I Been Pwned. | Operators recover within weeks to months (Lumma). | links in 2.2 and 3.1 |

Not confirmed in this pass: any Windows feature that warns on pasted commands in the Run dialog, and a native
Sysmon in Windows 11.

## 5. Gap analysis against Aegis

This section compares the threats above with what the repository contains today. The repo review was a keyword and
file-listing check (`aegis/data/rules/core.json`, `aegis/core/cmdline.py`, scanners, `tests/`), not a full code
audit, so each "gap" should be confirmed before work starts.

### 5.1 Already covered (per the repo)

* ClickFix/fake-CAPTCHA lure detection in HTML (`AEG-FAKE-CAPTCHA`), PowerShell download-and-execute cradles,
  encoded PowerShell, LOLBin command lines, Defender-exclusion and Defender-tamper command patterns, shadow-copy and
  backup deletion, Run-key persistence with script payloads (`aegis/core/cmdline.py`).
* A browser scanner with malicious extension IDs (173 entries), forced-install policy and sideload checks.
* A process scanner that already names AnyDesk and ScreenConnect (at LOW severity) and treats `windowsterminal.exe`
  as a known host.
* Hardening checks for Defender tamper protection, HVCI and Credential Guard (INFO severity), LSA protection, UAC,
  and an OS end-of-support table.

### 5.2 Gaps and recommended additions, in priority order

| # | Gap | Evidence in this brief | Suggested Aegis change |
|---|---|---|---|
| 1 | **Run-dialog and launch-surface history is not inspected after the fact.** A keyword search found no `RunMRU` handling. | 2.1 (RunMRU hunting) | New persistence/forensics check: read `HKCU\...\Explorer\RunMRU` and flag the documented patterns (emoji prefix, `-w h`, `iex`, `irm`, base64, `mshta`, `bitsadmin`). Also review `TypedPaths` for FileFix **[I]**. Reuse `cmdline.py` patterns. |
| 2 | **Process lineage for new ClickFix launch surfaces.** | 2.1 (Terminal chain, `finger.exe`, `wscript t.vbs`) | In the realtime process guard, add rules: `WindowsTerminal.exe` spawning hidden PowerShell with `iex(irm`, `finger.exe` network use, `wscript.exe` running a script from `%TEMP%` copied from a browser cache path, `MSBuild.exe` run from `AppData`. |
| 3 | **Browser-cache script smuggling.** | 2.1 (cache smuggling) | File scanner heuristic: script content (VBScript/PowerShell) inside browser cache entries named `f_*`, or `t.vbs` in `%TEMP%` created shortly after a browser write. |
| 4 | **RMM abuse is LOW severity and has no context.** | 2.6 | Raise severity when an RMM service or Run key appears that is not in an allow-list the user sets, when two or more RMM products are present, when MSP360/Faronics/PDQ/SimpleHelp/NetSupport are added, or when an inbound UDP 48678 firewall rule exists. Add to `aegis allow` flow. |
| 5 | **No BYOVD-aware audit.** Audit has HVCI at INFO only; no check of the Microsoft vulnerable driver blocklist setting. | 2.5 | Add a system-audit check for the blocklist policy state and raise HVCI to LOW/MEDIUM when the blocklist is off. Add installed-driver hash matching against a public vulnerable-driver list (list not researched in this pass). Flag newly installed kernel drivers from user-writable paths in the persistence guard. |
| 6 | **Signed-binary DLL side-loading is not modelled.** Only a browser-scanner hit on "sideload" exists. | 2.2, 2.3 | File/process heuristic: signed legitimate EXE plus unsigned or differently signed DLL of an unexpected name in the same user-writable or fake vendor folder (for example a "Pulse Secure" folder under Common Files, `install.res.1033.dll`, `ceiinfolog.dll` next to `COTFileReadApp.exe`). |
| 7 | **Interpreter-based implants.** Node.js, Deno, Python running from user profile paths with a Run/RunOnce entry. | 2.3, 2.7, 3.3 | Process and persistence rule: `node.exe`/`deno.exe`/`pythonw.exe` under `AppData` or `ProgramData` with a random-name script argument or a Run entry; Edge/Chrome launched with `--remote-debugging-port` by a non-browser parent; new Scoop/WinGet bootstrap followed by Deno. |
| 8 | **LNK-in-archive and double-extension shortcuts.** | 2.7 | File scanner: `*.png.lnk`/`*.pdf.lnk` double extensions, small LNKs whose target is `cmd`/`powershell`/`mshta`, LNK inside ZIP in Downloads, USB-root LNK clones. |
| 9 | **Browser extension intelligence is a static list.** | 2.4 | Add lookalike detection for clones of popular extensions (for example uBlock Origin Lite) installed from a different publisher or ID, extensions requesting broad host access with `runtime` port loops (hard to see statically, so flag recent installs plus browser crash events), and add the CrashFix extension ID to the feed. |
| 10 | **Fake AI tool and brand lookalikes.** | 2.3 | `aegis check-url`: add AI brand tokens (claude, chatgpt, openai, copilot, gemini, deepseek) to lookalike and typosquat logic; flag sponsored-GPT and Google Sites hosts that ask users to run commands. Flag install folders with misspelled vendor names. |
| 11 | **Windows 10 messaging is out of date for consumers.** `system_audit.py` says only organisations can buy ESU and uses 22H2's 2025-10-14 date as final. | 4 (ESU extended to 2027-10-12) | Detect ESU enrolment if feasible; otherwise change the text to say consumer ESU exists until 2027-10-12 (Windows Backup, Rewards points or $30), and keep the severity but soften the recommendation. Update `tests/test_system_audit.py` if messaging is asserted. |
| 12 | **Infostealer exposure guidance does not mention session-binding or token theft.** | 4 (DBSC), 3.1 | In the browser audit, report Chrome version (146+ on Windows gets DBSC where supported by sites), count saved passwords (exists), and recommend revoking sessions and rotating credentials after any stealer detection. |
| 13 | **Second-stage tool theft.** Credential viewers and in-memory stealers named in the RMM and Kaspersky chains. | 2.6 | Add file and process names (browser password viewers, `DefenderControl.exe`-style fake Windows names) to rules. Names from vendor reports are weak indicators and should score low alone. |

Housekeeping found while reading the repo (outside the scope of this research, flagged for the maintainers):
`README.md` and `docs/REQUIREMENTS.md` describe a network scanner (`aegis/scanners/network.py`: C2 IPs, risky
listeners, hosts/proxy/DNS hijack, rogue roots), but `aegis/scanners/` contains no `network.py` and
`aegis.scanners.REGISTRY` exports no such module. Either the file was not committed or the docs are ahead of the
code.

### 5.3 What Aegis cannot do and should say plainly

* Aegis is user-mode. EDR killers and BYOVD operate in the kernel and can blind a user-mode guard. The honest
  recommendation in `docs/COMPARISON.md` (run beside Defender or another real-time AV) stays correct, and the
  hardening audit should push HVCI, the driver blocklist and Tamper Protection.
* Cloud reputation, prevalence and ML (used by Smart App Control and EDR-class products) are out of reach for an
  offline, no-telemetry tool, so zero-day loaders with fresh certificates will be missed. Behavioural rules in
  section 5.2 are the practical substitute.

## 6. Source list

Primary or vendor pages read in full: Microsoft Security Blog
([Storm-2561](https://www.microsoft.com/en-us/security/blog/2026/03/12/storm-2561-uses-seo-poisoning-to-distribute-fake-vpn-clients-for-credential-theft/),
[RMM abuse](https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/),
[photo ZIP](https://www.microsoft.com/en-us/security/blog/2026/06/25/photo-zip-campaign-targeting-hospitality-industry-delivers-node-js-implant-persistent-access/)),
[Trend Micro on Vidar 2.0](https://www.trendmicro.com/en_gb/research/25/j/soc-agentic-siem/how-vidar-stealer-2-upgrades-infostealer-capabilities.html),
[Dragos Q2 2026](https://www.dragos.com/blog/dragos-industrial-ransomware-analysis-q2-2026),
[glueckkanja](https://www.glueckkanja.com/en/posts/2026-09-21-clickfix-prevent-detect).

News coverage of primary research read in full: The Hacker News
([ClickFix cache](https://thehackernews.com/2026/10/clickfix-smuggles-payloads-through.html),
[Terminal ClickFix](https://thehackernews.com/2026/03/microsoft-reveals-clickfix-campaign.html),
[EDR killers](https://thehackernews.com/2026/03/54-edr-killers-use-byovd-to-exploit-34.html),
[Custom GPT](https://thehackernews.com/2026/09/attackers-abuse-chatgpt-custom-gpts-to.html),
[CrashFix](https://thehackernews.com/2026/01/crashfix-chrome-extension-delivers.html),
[SEO to ScreenConnect](https://thehackernews.com/2026/07/seo-poisoned-software-sites-abuse.html)), Help Net Security
([ESET H1 2026](https://www.helpnetsecurity.com/2026/07/08/eset-ai-threat-trends-report/),
[Deno RAT](https://www.helpnetsecurity.com/2026/05/27/deno-rat-malware-fake-chatgpt-claude-installers/),
[DBSC](https://www.helpnetsecurity.com/2026/04/10/google-chrome-device-bound-session-credentials),
[Windows 10 ESU](https://www.helpnetsecurity.com/2026/06/26/microsoft-windows-10-free-security-updates-esu-program/)),
[Infosecurity Magazine on Flashpoint](https://www.infosecurity-magazine.com/news/infostealers-17-billion/),
[Security Affairs on Endgame](https://securityaffairs.com/194173/cyber-crime/europol-disrupts-stealc-and-amadey-malware-infrastructure-in-operation-endgame.html).

Sources used through search summaries only (verify before quoting): the ESET H1 2026 PDF, GuidePoint Q2 2026,
Brandefense, Dark Reading, Intrinsec, Recorded Future, Intel 471, Red Canary, PolySwarm, Malwarebytes, Huntress,
BleepingComputer, Trend Micro Lumma reports, Snyk, CYFIRMA, Petri, IT-Connect, Neowin, Microsoft Edge support.
