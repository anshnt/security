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
* Sections 7 to 10 are a second research pass (also 2026-10-15) that adds primary-source reads, live feed data and the
  detection content shipped in `aegis/data/rules/threats_2026.json`. In sections 7 to 10 **[P]** also covers data
  downloaded and parsed that day (MITRE ATT&CK STIX, the abuse.ch and CISA feeds, the LOLDrivers catalogue). Items that
  contradict or refine sections 1 to 6 are listed in 7.1 rather than silently rewritten. The second pass could not read
  the full Red Canary, Sophos, CrowdStrike, Microsoft Digital Defense Report and ESET PDFs, so their figures stay **[S]**.

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
7. **Payloads now ride on GitHub.** On 2026-10-15, 18,354 of the 27,371 online URLs in the URLhaus dump (67%) were
   `raw.githubusercontent.com` links, mostly ZIPs tagged SmartLoader or LuaJIT-loader from fake repositories offering game
   cheats, mod menus and developer or AI tools **[P]** (7.2). Domain reputation cannot block this; file and behaviour
   rules can.
8. **MITRE ATT&CK renumbered the defence-evasion techniques.** The current release (v20.0, 2026-10-13) has no active
   `T1562.*` or `T1574.002`; they map to `T1685`, `T1686`, `T1688` and `T1574.001`, and the old Defense Evasion tactic is
   split into Stealth and Defense Impairment **[P]** (7.3). Several Aegis modules still cite the retired ids.

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
| **Microsoft vulnerable driver blocklist, HVCI, App Control** | Prevent known vulnerable drivers from loading. | Attackers rotate to unlisted drivers; a June 2026 case used a driver on no public blocklist **[S]**. Microsoft's own page says the list is on by default since the Windows 11 2022 update and enforced with memory integrity, Smart App Control or S mode **[P]** (7.1, 7.7). | [The Hacker News](https://thehackernews.com/2026/03/54-edr-killers-use-byovd-to-exploit-34.html) **[P]** |
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
| 5 | **No BYOVD-aware audit.** Audit has HVCI at INFO only; no check of the Microsoft vulnerable driver blocklist setting. | 2.5 | Add a system-audit check for the blocklist policy state and raise HVCI to LOW/MEDIUM when the blocklist is off. Add installed-driver hash matching against a public vulnerable-driver list (researched in the second pass: LOLDrivers, bundled as `aegis/data/vulnerable_drivers.txt` with 2,198 SHA-256 hashes; see 7.6 and `docs/FEEDS.md`). Flag newly installed kernel drivers from user-writable paths in the persistence guard. |
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

## 7. Second research pass (2026-10-15): primary-source additions, corrections and Aegis coverage

Scope: Microsoft, Red Canary, Elastic, Malwarebytes, Hexastrike, CISA and Singapore CSA pages were opened; the MITRE
ATT&CK STIX bundle, the CISA KEV, LOLDrivers and abuse.ch feeds were downloaded and parsed; Microsoft Learn pages for
the driver blocklist, ASR rules, memory integrity, Smart App Control, Pluton and security baselines were read. Tags are
as in section 0. Defensive research only: command lines are described, not reproduced as working one-liners.

### 7.1 Confirmations and corrections to sections 1 to 6

| Topic | Earlier text | What the second pass found | Source |
|---|---|---|---|
| Vulnerable driver blocklist default state | "Not always on, especially on older systems" **[S]** (2.5, section 4) | Microsoft Learn (page metadata updated 2026-10-08): enabled by default on all devices since the Windows 11 2022 update, switchable in Windows Security, and also enforced when memory integrity, Smart App Control or S mode is on (except Windows Server 2016). Updated quarterly and through monthly Windows updates; the downloadable list usually holds more entries than the in-box one because Microsoft holds back blocks that would break working software. The ASR rule for vulnerable signed drivers stops one being written to disk but does not stop one already present. **[P]** | [Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules) |
| CrashFix | Extension "NexShield", waits 60 minutes, tied to KongTuke (2.4) | Consistent. Microsoft's own post adds: the extension impersonates uBlock Origin Lite, extension id `cpcdkmjddocikjdkbbeiaafnpdbdafmi`, tracking domain `nexsnield[.]com`, a renamed copy of `finger.exe` saved as `ct.exe`, a bundled WinPython running `modes.py` with `pythonw.exe` (ModeloRAT), a Run-key entry, and a scheduled task named `SoftwareProtection` that fires every five minutes; a second chain used `udp.pyw` and `run.exe`. The payload is delivered selectively to domain-joined machines. **[P]** | [Microsoft](https://www.microsoft.com/en-us/security/blog/2026/02/05/clickfix-variant-crashfix-deploying-python-rat-trojan/) |
| Warning on pasted commands | "Not confirmed in this pass: any Windows feature that warns on pasted commands" (section 4) | Microsoft's 2025 ClickFix guidance lists Group Policy to remove the Run dialog and Run menu entry and a setting to warn on multi-line paste in Windows Terminal, plus App Control to restrict native binaries launched from Run. Whether these stop real campaigns was not tested. **[P]** | [Microsoft](https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/) |
| DNS-based ClickFix | Not in 2.1 | February 2026: the pasted command queries an attacker-chosen DNS server with `nslookup`, filters the `Name:` answer and runs it through `cmd`; the later stage fetches a ZIP holding a Python runtime and scripts (reported as ModeloRAT with startup-shortcut persistence). Microsoft is said to describe DNS as a lightweight staging channel. **[S]** (search summaries of Microsoft's post; the Microsoft page itself was not located) | [The Hacker News](https://thehackernews.com/2026/02/microsoft-discloses-dns-based-clickfix.html) |
| `network.py` housekeeping note (5.2) | "`aegis/scanners/` contains no `network.py`" | The file exists in the tree on 2026-10-15 (alongside new `drivers.py`, `sideload.py`, `eventlog.py`, `usb.py`). The note in 5.2 is stale. **[P]** (directory listing) | repository |
| ClickFix rank in Red Canary data | Not in 2.1 | The techniques page lists Malicious Copy and Paste (T1204.004) at rank 8 of the top ten; a search summary of the report says ninth. Unresolved. Another summary says six of the ten top threats relate to paste-and-run. **[P]** / **[S]** | [Red Canary](https://redcanary.com/threat-detection-report/techniques/) |
| Ransomware payment rate | Chainalysis: 28% of victims paid in 2025 (3.4) | ESET H1 2026 coverage gives a 14 to 28% range for the share of victims paying. The two are compatible as a range. **[S]** | [Intelligent CIO](https://www.intelligentcio.com/africa/2026/07/29/eset-report-highlights-ai-driven-threats-and-growth-in-qr-code-phishing/) |

### 7.2 What is attacking PCs: additions

**Red Canary 2026 Threat Detection Report (2025 data), top threats by share of customers affected [P]**
([threats](https://redcanary.com/threat-detection-report/threats/), [techniques](https://redcanary.com/threat-detection-report/techniques/)):
Amber Albatross 11.1%, JustAskJacky 7.4%, Tampered Chef 6.1%, NetSupport Manager 4.5%, LummaC2 3.7%, Scarlet Goldfinch 3.3%,
KongTuke 3.1%, SocGholish 2.3%, MintsLoader 2.0%, Rhadamanthys 1.6%. Top techniques: Cloud Accounts (T1078.004), PowerShell,
Windows Command Shell, Data From Cloud Storage, Ingress Tool Transfer, Email Forwarding Rule, WMI, Malicious Copy and Paste,
Email Hiding Rules, Obfuscated Files or Information. The point for Aegis: three of the top four threats are consumer-style
"utility" installers rather than classic malware, and the report counts them separately from PUPs.

| Threat | What Red Canary documents **[P]** | Aegis rule |
|---|---|---|
| **Amber Albatross** ([page](https://redcanary.com/threat-detection-report/threats/amber-albatross/)) | Active since January 2024. A Pyarmor-obfuscated PyInstaller executable with stealer-like recon, installed by PUP "app store" and masquerading PDF-tool installers (signed with rotating certificates). Needs the arguments `--safetorun` and `--channel=<hex>`. Queries WMI for hypervisor and manufacturer data, reads the Chrome enrollment-token registry value, later stages moved from C++ to Go. | `AEG-T26-PUP-AMBER-ALBATROSS` |
| **JustAskJacky** ([page](https://redcanary.com/threat-detection-report/threats/justaskjacky/)) | Trojan posing as an AI chatbot or manual reader (lure names such as GoAskBobby, CheckWithGilbert, ManualReaderPro). Signed InnoSetup installer; `node.exe` runs a GUID-named, Obfuscator.io-protected JavaScript file from a user folder; a scheduled task imported from XML starts it; the beacon receives Base64/XOR code that is run with `eval()` and never written to disk. | `AEG-T26-JUSTASKJACKY-INSTALLER`, `AEG-T26-NODE-TASK-IMPLANT` |
| **Tampered Chef** ([page](https://redcanary.com/threat-detection-report/threats/tampered-chef/)) | Electron/Node.js apps (a recipe viewer, then a calendar app) whose JavaScript arrives hidden in invisible characters inside otherwise normal API data; commands stop Chrome, restart it on attacker pages and change the search engine. Signed with `CROWN SKY LLC` and `Global Tech Allies ltd`. Runs without admin rights. | `AEG-T26-JS-ZEROWIDTH-DECODE` |
| **KongTuke** ([page](https://redcanary.com/threat-detection-report/threats/kongtuke/)) | Traffic-distribution system on compromised WordPress sites: fake Chrome update (2024), fake CAPTCHA (January 2025), FileFix (April 2025), `finger.exe` lures (November to December 2025). Linked to Rhysida and Interlock ransomware; payloads include Lumma, MintsLoader and WARMCOOKIE. Hunt: `explorer.exe` starting `cmd.exe` with both `start` and `exit` in the command line. | `AEG-T26-CF-FINGER-PIPE`, `AEG-T26-CF-FIX-LURE` |

**SmartLoader / "FakeGit": payloads hosted on GitHub.** Live URLhaus data on 2026-10-15 **[P]**: 18,354 of 27,371 online URLs
(67%) are `raw.githubusercontent.com` links and 2,423 more are `github.com`; the leading tags are SmartLoader (19,465),
LuaJIT-loader (18,055), zip (14,891), CoinMiner (1,595), FakeCaptcha (1,119) and seopoisoning (1,098). Sample paths are ZIPs in
repositories advertising game cheats, mod menus and AI or developer tools. Hexastrike's April 2026 analysis
([Hexastrike](https://hexastrike.com/resources/blog/threat-intelligence/cloned-loaded-and-stolen-how-109-fake-github-repositories-delivered-smartloader-and-stealc/)) **[P]**:
each ZIP holds a one-line `.bat`/`.cmd` launcher, a renamed unsigned LuaJIT executable (names such as loader, selector, unit,
load, compiler, util, luajit, boot), sometimes `lua51.dll`, and a one-line obfuscated Lua payload saved as `.txt` or `.log`. The Lua stage
uses FFI to hide its console, resolves its C2 from a Polygon smart contract through `eth_call`, fetches further Lua from GitHub,
fingerprints the host and loads StealC in memory. Persistence is two daily scheduled tasks with decoy names that point into
`%LOCALAPPDATA%`, one running a cached copy and one re-fetching the payload. The same article's title counts 109 repositories **[S]**
(title only); secondary coverage cites 7,600 repositories (Island, July 2026) and 17,610 (Apiiro via BleepingComputer, 8 October 2026)
**[S]**, both via aggregators and unverified. Aegis rules: `AEG-T26-SMARTLOADER-LAUNCHER`, `AEG-T26-SMARTLOADER-LUA-STAGE`,
`AEG-T26-SMARTLOADER-SCHTASK`; the file scanner already opens ZIP members, so the launcher is seen inside the archive.

**Commodity family mix, MalwareBazaar last 48 hours (2026-10-13 to 10-15) [P]:** 1,021 samples; 289 unclassified, Mirai 205, Formbook 101,
AgentTesla 51, Remcos 51, GuLoader 26, XWorm 23, DCRat 22, AMOS 21, AsyncRAT 19. This is a sample-submission view, not infections,
but it shows that the long tail of RATs and stealers named in 3.1 and 3.3 is still the bulk of what arrives.

**Other sector reports [P]/[S]:**

| Report | Finding | Tag | Source |
|---|---|---|---|
| Mandiant M-Trends 2026 | Initial infection vectors in 2025: exploits 32% (sixth year first), voice phishing 11%, prior compromise 10% (30% in ransomware intrusions, up from 15%), email phishing 6%. Median hand-off from initial access to a secondary group 22 seconds (over 8 hours in 2022). Recommends treating routine malware alerts as high priority and extending log retention beyond 90 days. Credential stealer QUIETVAULT searches machines for local AI command-line tools. | **[P]** | [Google Cloud](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026) |
| Mandiant M-Trends 2026 | Global median dwell time 14 days (11 in the prior year); credential stealers 9% of malware families. | **[S]** | [Help Net Security](https://helpnetsecurity.com/2026/03/24/mandiant-m-trends-2026-report/) |
| Sophos Active Adversary Report 2026 | 661 cases (November 2024 to October 2025): 67% identity-rooted; brute force 15.6% against exploitation 16%; median dwell time 3 days; 3.4 hours to reach the AD server; 88% of ransomware payloads deployed outside business hours. | **[S]** | [Sophos](https://www.sophos.com/en-us/press/press-releases/sophos-active-adversary-report-2026-identity-attacks-dominate-as-threat-groups-proliferate) |
| CrowdStrike Global Threat Report 2026 | Average eCrime breakout time 29 minutes, fastest 27 seconds; AI-enabled attacks up 89%; 281 tracked adversaries; one summary cites 82% of detections malware-free (single secondary source). | **[S]** | [CrowdStrike](https://www.crowdstrike.com/en-us/resources/infographics/crowdstrike-2026-global-threat-report-highlights/) |
| Microsoft Digital Defense Report 2025 | Extortion and ransomware at least 52% of attacks with a known motive; identity attacks up 32% in H1 2025, over 97% password attacks; infostealers described as first-stage access tools. | **[S]** | [The Record](https://therecord.media/microsoft-warns-of-surge-identity-hacks-passwords) |
| ESET Threat Report H1 2026 | ClickFix detections +108% (H2 2025 to H1 2026); QR codes in about 11% of detected phishing emails; more than 100 EDR killers, over 60 using BYOVD. | **[S]** | [Intelligent CIO](https://www.intelligentcio.com/africa/2026/07/29/eset-report-highlights-ai-driven-threats-and-growth-in-qr-code-phishing/) |
| CISA AA24-109A (Akira, revised 2025-11-13) | Note file names `akira_readme.txt`, `fn.txt` and `akiranew.txt`; extensions `.akira`, `.powerranges`, `.akiranew`, `.aki`; shadow-copy removal through PowerShell WMI and `vssadmin`; LSASS dumping with the `comsvcs.dll` MiniDump export; `esentutl` against browser credential stores; abused drivers (Zemana-based PowerTool, POORTRY); remote tools AnyDesk, LogMeIn, RustDesk; entry through VPNs without MFA and Veeam, SonicWall and Cisco flaws. | **[P]** | [CISA](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a) |

### 7.3 MITRE ATT&CK v19/v20 renumbering: retired ids still used in the repository

Parsed from the ATT&CK Enterprise STIX bundle (version 20.0, released 2026-10-13; v19.0 is dated 2026-04-28 in the STIX
index) **[P]**. The updates page covers only v19.2 to v20.0 and does not describe the change, so the version that introduced it is **[I]**.

| Retired id (revoked) | Replacement |
|---|---|
| T1562 Impair Defenses, T1562.001 Disable or Modify Tools, T1562.006 Indicator Blocking | **T1685** Disable or Modify Tools |
| T1562.002 Disable Windows Event Logging | T1685.001 Disable or Modify Windows Event Log |
| T1562.003 Impair Command History Logging | T1690 Prevent Command History Logging |
| T1562.004 Disable or Modify System Firewall | T1686 (Windows host firewall is T1686.003) |
| T1562.009 Safe Mode Boot | **T1688** Safe Mode Boot |
| T1562.010 Downgrade Attack | T1689 Downgrade Attack |
| T1070.001 Clear Windows Event Logs | T1685.005 Clear Windows Event Logs |
| T1574.002 DLL Side-Loading | T1574.001 DLL (merged) |
| Tactic TA0005 Defense Evasion | TA0005 now named **Stealth**; new tactic TA0112 **Defense Impairment** |

Relevant ids that are active in the v20.0 bundle: T1204.004 Malicious Copy and Paste, T1684 Social Engineering and the T1685 to T1690
family (no introduction version stated). The v20 updates page lists T1696 Anti-Automation Evasion (with CAPTCHA sub-techniques),
T1697 Steal Application Specific Passwords and the AI techniques T1698 to T1700 as new in v20 **[P]**. The 60 rules in `threats_2026.json` use only ids that are active in v20.0 (checked by script),
and `tests/test_threat_rules.py` rejects the retired ones.

Repository files that still cite retired ids (counted 2026-10-15; not edited here): `T1562.001` 17 times, `T1562.004` 5,
`T1562.009` 1, `T1070.001` 2, in `aegis/scanners/system_audit.py`, `browser.py`, `network.py`,
`aegis/core/cmdline.py` and `aegis/core/fileanalysis.py`; `aegis/scanners/sideload.py` cites `T1574.002` in its docstring. The
retired pages still resolve on attack.mitre.org as revoked, so nothing breaks, but reports will show stale ids.

### 7.4 Browser credential and session theft

* **App-bound encryption (ABE) bypass, mechanics [P]** ([Elastic Security Labs](https://www.elastic.co/security-labs/katz-and-mouse-game)).
  Encrypted values carry a `v20` prefix. StealC and Vidar run an embedded helper that starts the browser on a hidden desktop and
  reads cookies from the memory of its network-service process using signature patterns borrowed from ChromeKatz ("CookieMonster").
  MetaStealer impersonates the SYSTEM token and calls the Chrome elevation service through COM to decrypt the
  `app_bound_encrypted_key` from Local State; Phemedrone launches the browser with a remote debugging port and an off-screen window and
  calls `Network.getAllCookies`; XenoStealer injects code to call the same decrypt method; Lumma copies `chrome.dll` out of a running
  browser and scans it. Elastic's detection ideas: rare processes opening the browser Cookies file, non-browser processes using the
  debugging port, the browser started with the default profile by an unusual parent, unsigned code in the browser's application
  folder, and registry access to the elevation-service class id `{708860E0-F641-4611-8895-7D867DD3675B}`.
  Aegis coverage: file rules `AEG-T26-STEALER-ABE-BYPASS` and `AEG-T26-STEALER-CDP-COOKIES` (static strings only; the runtime
  behaviours need process telemetry, see 7.9).
* **Remus (Lumma-style key theft with EtherHiding C2)** is reported to use a refined ABE bypass **[S]**
  ([GBHackers](https://gbhackers.com/remus-infostealer-adopts-lumma/)).
* **Extension plus native messaging (Malwarebytes, June 2026) [P]** ([Malwarebytes](https://www.malwarebytes.com/blog/news/2026/06/malware-steals-chrome-session-cookies-to-take-over-your-accounts)):
  an attachment disguised with a double extension (a script posing as a PDF) installs a Chrome extension through PowerShell and edits
  Chrome policy so the install looks administrator-managed; the extension collects cookies and tabs and uses a registered native-messaging host
  that launches PowerShell. The page does not mention ABE or Device Bound Session Credentials. Aegis rules: `AEG-T26-EXT-FORCELIST-SCRIPT`,
  `AEG-T26-NATIVEMSG-SCRIPT-HOST`, `AEG-T26-EXT-COOKIE-POLLING`, `AEG-T26-EXT-MANIFEST-COOKIES-NATIVE` (low severity, audit signal).
* **More extension clusters [S]:** 108 Chrome extensions on shared C2 with about 20,000 users (April 2026, Socket) and the January
  2026 Workday/NetSuite lookalikes that polled cookies every 60 seconds ([The Hacker News](https://thehackernews.com/2026/01/five-malicious-chrome-extensions.html)).
* **Fake verification pages [P]** ([Malwarebytes, July 2026](https://www.malwarebytes.com/blog/threat-intel/2026/07/fake-google-and-cloudflare-verification-pages-spread-multiple-malware-families)):
  fake Google reCAPTCHA, Google Meet, Google sign-in and Cloudflare pages hosted on `pages.dev`, compromised sites and an R2 bucket. The
  pasted command is an `iex(irm <raw IP:port/path>)` one-liner; stage one creates `C:\ProgramData\Zooms` and calls a `/dl-callback`
  endpoint; payloads include StealC (through the ResiLoader DLL side-loading chain with an `AtLorenBase` marker and an OPSWAT driver
  abused to kill security processes), Amatera, Remus, NetSupport and CastleLoader. Aegis rules: `AEG-T26-CF-IEX-IRM-RAWIP`,
  `AEG-T26-CF-STAGE1-PROGRAMDATA`, `AEG-T26-LOADER-RESILOADER`, `AEG-T26-UAC-BYPASS-CMSTPLUA`.

### 7.5 Developer supply chain (npm, PyPI, agent skills)

* **Shai-Hulud (September 2025) [P]** ([CISA alert](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem)):
  a self-replicating worm compromised more than 500 npm packages; it harvested GitHub tokens and cloud keys, sent them to an
  actor-controlled endpoint and to a public repository named Shai-Hulud, and republished other packages using the victim's npm identity.
  CISA advises pinning to versions from before 2025-09-16, rotating all developer credentials, phishing-resistant MFA on GitHub and npm,
  blocking `webhook.site` and enabling secret scanning. The alert does not mention a postinstall hook; that detail is in vendor reports not read here.
* **2025 to 2026 waves.** Shai-Hulud 2.0 (November 2025) reached 796 unique packages with over 20 million weekly downloads **[S]**
  ([Cloud Security Alliance note](https://labs.cloudsecurityalliance.org/research/csa-research-note-shai-hulud-megalodon-supply-chain-cascade/));
  Singapore CSA advisory AD-2026-009 describes a 2026 variant ("ChainDrop") touching more than 1,300 package versions, including keyv, cacheable and
  flat-cache releases, with three named network indicators and a GitHub repository description marker **[P]**
  ([CSA Singapore](https://www.csa.gov.sg/alerts-and-advisories/advisories/ad-2026-009/)). A May 2026 "Mini Shai-Hulud" wave abusing GitHub
  Actions with forged provenance is reported by one source only **[S]**.
* **Aegis rules:** `AEG-T26-NPM-INSTALL-HOOK-DOWNLOAD`, `AEG-T26-NPM-WORM-CREDENTIAL-SWEEP`, `AEG-T26-NPM-CHAINDROP-IOC`, `AEG-T26-PYPI-SETUP-EXEC`.
  **Gap:** Aegis does not enumerate installed packages or lockfiles. The OSV query API (`POST https://api.osv.dev/v1/query`) answered HTTP 200 without a key and
  OpenSSF's malicious-packages reports are published in OSV format (Apache-2.0) **[P]**; a developer-tools scanner could check `package-lock.json`, `yarn.lock`,
  `pnpm-lock.yaml` and `pip` metadata against it. Not built.

### 7.6 Evasion, persistence and credential theft defenders should detect: what Aegis covers

| Technique | 2026 evidence | Aegis detection (rule ids are `AEG-T26-...` unless noted) | Honest limit |
|---|---|---|---|
| BYOVD / vulnerable driver abuse | ESET: nearly 90 EDR killers (March) rising to over 100 (H1 report), over 60 BYOVD **[P]/[S]**; LOLDrivers: 702 entries (578 vulnerable, 124 malicious), 2,407 samples, 2,198 unique SHA-256 **[P]** | `BYOVD-SC-CREATE` (loader command, pattern copied from LOLDrivers entries); hash list `aegis/data/vulnerable_drivers.txt` consumed by `aegis/scanners/drivers.py` (verified: 2,198 hashes load); `EDR-KILLER-SCRIPT`; `SAFEMODE-REBOOT` | A driver already running can kill user-mode Aegis first. Hash lists only know published drivers. The Microsoft blocklist uses Authenticode hashes, not file SHA-256 (see `docs/FEEDS.md`). |
| EDR / AV killers | ESET categories: BYOVD tools, anti-rootkit utilities, driverless tools, script-based killers **[P]** | `EDR-KILLER-SCRIPT` (three or more named security products plus taskkill/sc/net stop) | Binary killers are not detected by strings. |
| DLL side-loading | ResiLoader `ssh-add.exe` plus `msys-*.dll`, Canon- and Microsoft-signed hosts (this document, 2.2 and 2.3) **[P]** | `LOADER-RESILOADER`; module `aegis/scanners/sideload.py` (other agent) | Rules only see a marker string; the heuristic needs the folder context. |
| LOLBins in paste-and-run | `finger`, `nslookup`, `mshta`, `curl`, `msiexec`, `SyncAppvPublishingServer`, MSBuild **[P]/[S]** | `CF-FINGER-PIPE`, `CF-NSLOOKUP-STAGER`, `CF-MSHTA-REMOTE`, `CF-APPV-VBS`, `MSBUILD-INLINE-TASK`, `LNK-LOLBIN-REMOTE`, `PS-DOWNLOAD-IEX-HIDDEN` | Only content on disk. A command pasted into Run never touches a file; RunMRU and script-block logs are the artefacts (gap 1 in 5.2). |
| ClickFix lure pages | See 2.1 | `CF-FIX-LURE`, `CF-TERMINAL-LURE`, `CF-FILEFIX-LURE` (plus existing `AEG-FAKE-CAPTCHA`) | Needs the page saved to disk or in a scanned cache. |
| AMSI / ETW tampering | Custom GPT chain bypasses AMSI and unhooks `ntdll.dll` (2.3) **[P]** | `AMSI-BYPASS`, `ETW-TAMPER-SCRIPT` | In-memory unhooking by a compiled loader is invisible to string rules. |
| Defender exclusions and disabling | Added in Terminal and SEO-poisoning chains (2.1, 2.2) **[P]** | `DEFENDER-EXCL-BROAD`, `DEFENDER-EXCL-REG`, `DEFENDER-DISABLE`; live check in `aegis/core/cmdline.py` (`DEFENDER-TAMPER`) and `eventlog.py` | Tamper Protection already blocks most of these on managed Defender. |
| Scheduled-task and Run-key persistence | Two-minute and five-minute tasks, masqueraded names, Run and RunOnce pairs **[P]** | `SCHTASK-FREQUENT-USERDIR`, `RUNKEY-INTERPRETER`, `NODE-TASK-IMPLANT`, `PYRAT-MODELORAT`, `SMARTLOADER-SCHTASK` | Live registry/task inspection is in `persistence.py`; these rules cover scripts before they run. |
| WMI persistence | ASR rule exists; `eventlog.py` reads WMI-Activity 5861 | `WMI-EVENT-PERSIST` | Script on disk only. |
| COM hijacking and UAC bypass | ICMLuaUtil elevation in ResiLoader **[P]**; class hijacks (T1546.015) | `COM-HIJACK-REG`, `UAC-BYPASS-REG-HIJACK`, `UAC-BYPASS-CMSTPLUA`, `UAC-DISABLE` | Static strings; legitimate installers register per-user COM classes too (medium severity). |
| BITS jobs | Long-standing | `BITS-NOTIFY-PERSIST` | Low volume. |
| Token / cookie / session theft | ABE bypasses, extension cookie polling, OAuth consent theft (ConsentFix) **[P]/[S]** | `STEALER-ABE-BYPASS`, `STEALER-CDP-COOKIES`, `STEALER-VIDAR-DEADDROP`, `STEALER-TELEGRAM-EXFIL`, `EXT-*` | OAuth consent theft and help-desk vishing leave no file. Revoking sessions is the remedy. |
| Interpreter-based implants | Node.js, Deno, Python, Lua loaders (2.3, 3.3, 7.2) **[P]** | `NODE-TASK-IMPLANT`, `PYRAT-MODELORAT`, `SMARTLOADER-*`, `ETHERHIDING-JS`, `JS-ZEROWIDTH-DECODE` | The interpreters are legitimate software; the rules key on launch patterns. |
| Ransomware preparation | Akira removes shadow copies (CISA) and destroys backups (Dragos) **[P]**; Qilin shadow-copy deletion comes from a single vendor blog **[S]** | `RANSOM-INHIBIT-RECOVERY`, `RANSOM-NOTE-DOUBLE-EXTORT` (plus existing `AEG-RANSOM-GENERIC`) | The note rule matches generic extortion wording, not named families. |
| Miners | URLhaus tags 1,595 CoinMiner URLs on 2026-10-15 **[P]** | `MINER-WALLET-POOL` | Needs the wallet, a known pool or miner flags. |
| Web shells | ASR rule covers Exchange servers only **[P]** | `WEBSHELL-PHP-DYNAMIC`, `WEBSHELL-ASPX-PROCESS` (plus existing `AEG-WEBSHELL-CHINA-CHOPPER`) | Mostly relevant to people running local web servers. |
| OneNote, LNK, HTA, WSH delivery | Photo-ZIP LNK (2.7); OneNote embedded-file blocks since 2023 **[S]** | `ONENOTE-EMBEDDED-SCRIPT`, `LNK-PS-ENCODED-DOWNLOAD`, `HTA-DOWNLOADER`, `WSH-DOWNLOADER` | MSIX packages are ZIPs and scanned as archives, but no MSIX-specific rule was written (no verified 2026 campaign, see 2.7). |
| Developer supply chain | 7.5 | `NPM-*`, `PYPI-SETUP-EXEC` | Lockfile/package enumeration not built. |

### 7.7 Defensive technologies and standards worth supporting

| Item | Verified facts | Relevance to Aegis |
|---|---|---|
| **Sigma** | SigmaHQ holds more than 3,000 rules in generic, threat-hunting, emerging-threat, compliance and placeholder sets; rules are under Detection Rule License 1.1, the specification and logo are public domain; `sigma-cli` is the official converter **[P]** ([README](https://raw.githubusercontent.com/SigmaHQ/sigma/master/README.md), [LICENSE](https://raw.githubusercontent.com/SigmaHQ/sigma/master/LICENSE)) | Aegis has no log-event rule engine, so Sigma is a reference format. Mapping `threats_2026.json` titles to Sigma rule ids for SIEM users, and writing the process-lineage rules in 7.9 as Sigma first, is the cheap path **[I]**. |
| **YARA / YARA-X** | The YARA-X README says its goal is to replace YARA; YARA stays maintained for fixes and minor features, new modules go to YARA-X **[P]** ([README](https://raw.githubusercontent.com/VirusTotal/yara-x/main/README.md)). Search summaries report YARA-X 1.x releases through at least 1.19 and YARA 4.5.8 on 2026-07-28 **[S]**; the 1.0 date is not confirmed. | Aegis uses optional `yara-python` (classic YARA). Keep it, and note a future YARA-X backend as a follow-up **[I]**. YARA Forge core (5,145 rules, built 2026-10-11) and YARAhub sets are in `docs/FEEDS.md`. |
| **Microsoft vulnerable driver blocklist** | Default on since the Windows 11 2022 update; enforced with HVCI, Smart App Control or S mode; quarterly updates; downloadable XML with 1,713 deny rules (1,702 hash rules) and policy version 10.0.29545.0 **[P]** | The posture check lives in `drivers.py` (reads `VulnerableDriverBlocklistEnable`). |
| **LOLDrivers** | Apache-2.0 catalogue with Sigma, YARA, Sysmon, WDAC and ClamAV exports; JSON and CSV APIs **[P]** | Source of `vulnerable_drivers.txt`. |
| **ASR rules** | Work on any edition with Defender Antivirus including Windows 11 Home, configurable by PowerShell or Group Policy; only three are "standard protection" (vulnerable signed drivers, LSASS credential theft, WMI persistence). One newer rule blocks copies of System32 tools (or files with their names) running from other folders; whether it stops a renamed copy such as the `finger.exe` to `ct.exe` trick was not tested **[P]** for the rule text | A hardening-audit item: read the configured rule ids and actions and recommend the Block-mode set below **[I]**. |
| **Memory integrity (HVCI)** | Windows Security > Device security > Core isolation; from Windows 11 22H2 a warning shows when it is off; state readable through `Win32_DeviceGuard` (`SecurityServicesRunning` containing 2); incompatible drivers can block enabling it **[P]** ([Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity)) | Already checked by `system_audit.py` and `drivers.py`. |
| **Smart App Control** | Evaluation mode, then enforcement; blocks unknown unsigned code and PUA; state shown under Windows Security > App and browser control **[P]** ([Microsoft Learn](https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/overview), page dated 2026-09-30) | Report state as INFO. How to read its state programmatically was not verified in this pass. |
| **Pluton** | Security processor on listed AMD Ryzen 6000 to 9000, Intel Core Ultra 200V and Series 3, and Qualcomm Snapdragon X parts; can act as the TPM; firmware updated through Windows Update **[P]** ([Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/hardware-security/pluton/microsoft-pluton-security-processor), page dated 2026-05-27) | `system_audit.py` already reports TPM presence; Pluton is not distinguished. Low value. |
| **Windows security baselines** | Written for well-managed organisations where users are not administrators; delivered by GPO or Intune, Pro editions and up **[P]** ([Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines)) | Home users cannot apply them, so Aegis's hardening audit is the substitute. |
| **Passkeys on Windows 11** | Third-party passkey managers through a new API from the November 2025 update (1Password and Bitwarden first) **[S]**; sources disagree on cross-device sync. | Recommendation text only; not verified. |
| **CISA KEV** | 1,746 entries on 2026-10-15; BOD 26-04 (2026-06-10) replaces BOD 22-01 and sets timelines from exposure, KEV status, automatability and impact **[P]** | `aegis/data/kev_software_hints.json` (generated). |
| **Not researched** | SBOM formats, OpenSSF Scorecard scoring, Sysmon/ETW telemetry sources, WDAC authoring. The Scorecard and EPSS APIs were only checked for reachability (`docs/FEEDS.md`). | |

Recommended ASR Block-mode set for a home PC with cloud protection on **[I]**, from the rules in Microsoft's reference: vulnerable signed drivers
(`56a863a9-875e-4185-98a7-b882c64b5ce5`), LSASS (`9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2`), WMI persistence
(`e6db77e5-3df2-4cf1-b95a-636979351e5b`), obfuscated scripts (`5beb7efe-fd9a-4556-801d-275e5ffc04cc`), script launching downloaded content
(`d3e037e1-3eb8-44c8-a917-57927947596d`), untrusted executables by prevalence and age (`01443614-cd74-433a-b99e-2ecdc07bfc25`, audit first),
copied system tools (`c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb`), Safe Mode reboot (`33ddedf1-c6e0-47cb-833e-de6133960387`), ransomware advanced
protection (`c1db55ab-c21a-4637-bb3f-a12568109d35`), Office child processes (`d4f940ab-401b-4efc-aadc-ad5f3c50688a`) and executable email
content (`be9ba2d9-53ea-4cdc-84e5-9b1eeee46550`). Source: [Microsoft Learn ASR reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference) **[P]**
(page dated 2026-09-09). Several rules need cloud protection or AMSI and some only alert at high cloud-protection levels.

## 8. Detection content shipped in this pass

`aegis/data/rules/threats_2026.json` holds 60 Aegis-Lite rules (ids `AEG-T26-*`; 42 high, 17 medium, 1 low; none critical because a file
indicator alone is not a confirmed active threat). Each carries ATT&CK ids active in v20.0 and reference URLs. `tests/test_threat_rules.py`
builds a harmless synthetic sample for every rule at runtime, checks the rule applies to that file type, runs benign samples (an admin
PowerShell script, an installer batch file, a package.json, official installer one-liners, a web-extension manifest and others) and
checks that nothing matches them.

| Group | Rule ids (suffix after `AEG-T26-`) |
|---|---|
| ClickFix and paste-and-run | `CF-FIX-LURE`, `CF-TERMINAL-LURE`, `CF-FILEFIX-LURE`, `CF-FINGER-PIPE`, `CF-NSLOOKUP-STAGER`, `CF-APPV-VBS`, `CF-IEX-IRM-RAWIP`, `CF-MSHTA-REMOTE`, `CF-STAGE1-PROGRAMDATA` |
| Stealers, loaders, interpreter implants | `STEALER-ABE-BYPASS`, `STEALER-CDP-COOKIES`, `STEALER-VIDAR-DEADDROP`, `STEALER-TELEGRAM-EXFIL`, `PUP-AMBER-ALBATROSS`, `JUSTASKJACKY-INSTALLER`, `NODE-TASK-IMPLANT`, `PYRAT-MODELORAT`, `LOADER-RESILOADER`, `ETHERHIDING-JS`, `JS-ZEROWIDTH-DECODE` |
| SmartLoader / FakeGit | `SMARTLOADER-LAUNCHER`, `SMARTLOADER-LUA-STAGE`, `SMARTLOADER-SCHTASK` |
| Browser extensions | `EXT-CRASHFIX-IOC`, `EXT-COOKIE-POLLING`, `EXT-MANIFEST-COOKIES-NATIVE`, `EXT-FORCELIST-SCRIPT`, `NATIVEMSG-SCRIPT-HOST` |
| Evasion and persistence | `DEFENDER-EXCL-BROAD`, `DEFENDER-EXCL-REG`, `DEFENDER-DISABLE`, `AMSI-BYPASS`, `ETW-TAMPER-SCRIPT`, `SCHTASK-FREQUENT-USERDIR`, `RUNKEY-INTERPRETER`, `WMI-EVENT-PERSIST`, `COM-HIJACK-REG`, `UAC-BYPASS-REG-HIJACK`, `UAC-BYPASS-CMSTPLUA`, `BITS-NOTIFY-PERSIST`, `UAC-DISABLE`, `SAFEMODE-REBOOT`, `PS-DOWNLOAD-IEX-HIDDEN` |
| EDR killers, ransomware, miners | `EDR-KILLER-SCRIPT`, `BYOVD-SC-CREATE`, `RANSOM-INHIBIT-RECOVERY`, `RANSOM-NOTE-DOUBLE-EXTORT`, `MINER-WALLET-POOL` |
| Shortcuts, HTA, script hosts, MSBuild | `LNK-PS-ENCODED-DOWNLOAD`, `LNK-LOLBIN-REMOTE`, `HTA-DOWNLOADER`, `WSH-DOWNLOADER`, `MSBUILD-INLINE-TASK` |
| Developer supply chain | `NPM-INSTALL-HOOK-DOWNLOAD`, `NPM-WORM-CREDENTIAL-SWEEP`, `NPM-CHAINDROP-IOC`, `PYPI-SETUP-EXEC` |
| Web shells and documents | `WEBSHELL-PHP-DYNAMIC`, `WEBSHELL-ASPX-PROCESS`, `ONENOTE-EMBEDDED-SCRIPT` |

Other data files: `aegis/data/vulnerable_drivers.txt` (2,198 hashes) and `aegis/data/kev_software_hints.json` (eleven product groups); see `docs/FEEDS.md`.

Indicators left out on purpose because they could not be verified: crypto-wallet extension ids (only MetaMask, Binance Chain Wallet and Ronin could
be matched against published YARA rules, and the existing core rule already covers MetaMask, so no wallet-id rule was written), hashes quoted in vendor
posts (not re-verified), and IP addresses and short-lived domains from campaign write-ups. Named domains and ids appear only where a primary source lists them (CrashFix, ResiLoader, the CSA npm advisory).

## 9. Honest gaps and recommended next steps (second pass)

| # | Gap | Why it matters | Suggested change |
|---|---|---|---|
| G1 | **Aegis-Lite sees bytes, not behaviour.** | ClickFix commands, ABE bypasses, DevTools-port abuse and process injection happen at run time. | Add realtime process-lineage rules (Sigma-style): `explorer.exe` to `cmd.exe` with `start` and `exit`; `WindowsTerminal.exe` to hidden PowerShell with `iex(irm`; the browser started with a debugging port or off-screen window by a non-browser parent; any network use of `finger.exe`; `wscript.exe` on a script in Temp copied from a browser cache path. |
| G2 | **Rule engine cost.** `Rule.match` searches every string of every applicable rule. | Measured on 2026-10-15: the 60 new rules cost about 2 to 3 seconds per MB of text; adding them to the 18 core rules made text scans roughly 2.5 times slower. | In `aegis/core/rules.py` evaluate strings lazily and stop as soon as the condition cannot be met. Benchmarked at about 2.6 times faster with identical results on all positive samples. The scanner already limits `text` files to under 1 MB. |
| G3 | **Rule files flag themselves.** | `aegis/data/rules/core.json` already matches 10 of its own 18 rules, and `threats_2026.json` matches 12 of its own 60 (plus two core rules), because descriptions and patterns contain indicator text. A scan of the install folder or a checkout produces false alarms. | Skip rule files in the file scanner. `files.py` already skips Aegis's own JSON/HTML reports through `is_aegis_report`; a matching check for rule files (a JSON array whose objects have `strings` and `condition`) and for `tests/` would do. |
| G4 | **Retired ATT&CK ids in existing modules** (7.3). | Reports show stale ids. | Replace `T1562.001/.004/.009`, `T1070.001`, `T1574.002` with the ids in 7.3. |
| G5 | **Package and lockfile checks** (7.5). | Developers are the target of the 2025 to 2026 npm and PyPI waves. | A developer-tools scanner that reads lockfiles and queries OSV. |
| G6 | **Images and messages are out of scope.** | ESET: QR codes in about 11% of phishing emails **[S]**; vishing is the second most common initial vector in M-Trends 2026 **[P]**; ConsentFix steals OAuth codes. | Say so in the UI; link to account-recovery steps (revoke sessions, rotate passwords, review OAuth consents). |
| G7 | **Feed fragility.** | abuse.ch documents an Auth-Key requirement and restricts commercial use; Feodo is dormant; the YARA Forge API URL can be blocked. | See `docs/FEEDS.md`, section 5. |
| G8 | **Kernel-level and in-memory threats stay out of reach** (as in 5.3). | EDR killers, unhooking and reflective loading defeat a user-mode scanner. | Keep the advice to run beside Defender with memory integrity, the driver blocklist and Tamper Protection on. |
| G9 | **No MSIX or ISO/VHD content inspection.** | MSIX is a ZIP and is scanned, but no rule targets it; ISO and VHD images are not unpacked. | Add rules only when a verified 2026 campaign justifies them. |

## 10. Sources read in the second pass

Opened in full unless marked: [Microsoft CrashFix post](https://www.microsoft.com/en-us/security/blog/2026/02/05/clickfix-variant-crashfix-deploying-python-rat-trojan/),
[Microsoft ClickFix guidance](https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/),
[Malwarebytes verification pages](https://www.malwarebytes.com/blog/threat-intel/2026/07/fake-google-and-cloudflare-verification-pages-spread-multiple-malware-families),
[Malwarebytes cookie theft](https://www.malwarebytes.com/blog/news/2026/06/malware-steals-chrome-session-cookies-to-take-over-your-accounts),
[The Hacker News ClickFix expansion](https://thehackernews.com/2026/01/clickfix-attacks-expand-using-fake.html),
[Red Canary threats and techniques pages](https://redcanary.com/threat-detection-report/threats/) and four threat pages (Amber Albatross, JustAskJacky, Tampered Chef, KongTuke),
[Elastic Katz and Mouse](https://www.elastic.co/security-labs/katz-and-mouse-game),
[Hexastrike SmartLoader analysis](https://hexastrike.com/resources/blog/threat-intelligence/cloned-loaded-and-stolen-how-109-fake-github-repositories-delivered-smartloader-and-stealc/),
[CISA npm alert](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem),
[CSA Singapore AD-2026-009](https://www.csa.gov.sg/alerts-and-advisories/advisories/ad-2026-009/),
[CISA AA24-109A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a),
[CISA BOD 26-04](https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk),
[Google Cloud M-Trends 2026](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026),
[Microsoft driver blocklist](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules),
[ASR rules reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference),
Microsoft Learn pages on memory integrity, Smart App Control, Pluton and security baselines (links in 7.7),
[LOLDrivers](https://www.loldrivers.io/) (site, README, licence and `drivers.json`),
[MITRE ATT&CK STIX data](https://github.com/mitre-attack/attack-stix-data) (index and Enterprise bundle),
[SigmaHQ](https://github.com/SigmaHQ/sigma) and [YARA-X](https://github.com/VirusTotal/yara-x) READMEs, and the feeds listed in `docs/FEEDS.md`.

Search summaries only (tagged **[S]** above): CrowdStrike, Sophos, Microsoft Digital Defense Report 2025, ESET H1 2026, SecurityWeek and Help Net Security on
M-Trends, The Hacker News on the nslookup variant and the January 2026 extension cluster, Cloud Security Alliance on Shai-Hulud 2.0, GBHackers on Remus,
Trend Micro and others on SmartLoader, and Windows passkey coverage.
