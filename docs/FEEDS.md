# Free threat-intelligence feeds for Aegis (verified 2026-10-15)

This page lists public feeds Aegis could download, which of them were actually reachable, what they contain, and
under what terms. It was produced by requesting every URL with `curl` (through the sandbox's egress proxy) on
**2026-10-15** and reading the formats from the downloaded files. Nothing was run against Aegis.

Confidence tags follow `docs/THREAT_LANDSCAPE.md`: **[P]** = observed directly (a response, a file or a licence page
that was opened), **[S]** = taken from a search summary, **[I]** = inference, not confirmed. "HTTP 200" means the
unauthenticated request returned the data, not an error page, unless noted.

## 1. Summary of recommendations

| Priority | Feed | Why | Caveat |
|---|---|---|---|
| 1 | **LOLDrivers** `drivers.json` | Only maintained public list of vulnerable/abused Windows drivers; feeds `aegis/data/vulnerable_drivers.txt` | 33 MB; Apache-2.0 **[P]** |
| 2 | **CISA KEV** JSON | Prioritise outdated software that is actively exploited; feeds `aegis/data/kev_software_hints.json` | Public-domain status is **[I]** (US Government work) |
| 3 | **YARA Forge core** (already used) | 5,145 curated YARA rules in one file | Mixed per-rule licences, some "NO LICENSE SET" **[P]** |
| 4 | **Neo23x0 signature-base** `hash-iocs.txt`, `c2-iocs.txt` | Curated, low-noise IOCs, DRL 1.1 **[P]** | Hash file mixes MD5/SHA1/SHA256, `;`-separated |
| 5 | **abuse.ch ThreatFox** (`ip-port`, domains, hashes) | Current C2 indicators with malware family | Auth-Key and fair-use terms, see section 4 |
| 6 | **abuse.ch URLhaus** `text_online` / hostfile | Live malware-download URLs for `check-url` | Same terms as above |
| 7 | **IPsum** level 3+ | Aggregated bad-IP reputation, public domain **[P]** | Noisy; use only for `check-url`/network context, never auto-block |
| 8 | **Phishing.Database** active domains | MIT **[P]**; domain phishing list for `check-url` | 11 MB, large false-positive surface on shared hosts |
| 9 | **YARAhub** (`yaraify-rules.zip`) | 1,419 community rules | Licence varies per rule including non-commercial; filter to CC0/CC-BY |
| Skip | Feodo Tracker, SSLBL IP list, SSLBL JA3 list | Dormant or deprecated, see section 3 | Updater still has Feodo; it will yield almost nothing |

## 2. Verified and usable

All rows returned HTTP 200 on 2026-10-15 **[P]** unless the notes say otherwise.

| Feed | URL | Size / entries seen | Format | Licence / terms | Update cadence | Notes |
|---|---|---|---|---|---|---|
| LOLDrivers (JSON) | https://www.loldrivers.io/api/drivers.json | 33.3 MB; 702 entries (578 vulnerable, 124 malicious), 2,407 samples, 2,198 unique SHA-256 | JSON array; per entry `Category`, `Tags`, `CVE`, `Commands`, `Resources`, `KnownVulnerableSamples[]` with `SHA256`, `SHA1`, `MD5`, `Authentihash`, `OriginalFilename`, `Company` | Apache-2.0 (repository `LICENSE` read) **[P]** | Community, continuous; 197 entries (Jan 2023) to 702 (Oct 2026) per the site | Also `https://www.loldrivers.io/api/drivers.csv` (HTTP 200). 105 samples have no SHA-256. Used to build `aegis/data/vulnerable_drivers.txt`. |
| CISA KEV (JSON) | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | 1.79 MB; `catalogVersion` 2026.10.15, 1,746 entries | JSON with `vulnerabilities[]`: `cveID`, `vendorProject`, `product`, `dateAdded`, `dueDate`, `knownRansomwareCampaignUse`, `forensicTriage`, `cwes`, `notes` | US Government work; explicit licence text not read **[I]** | Several times a week; the catalogue was released 2026-10-15 17:00 UTC | CSV twin: `https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv` (1.06 MB). BOD 26-04 (issued 2026-06-10) revokes BOD 19-02 and BOD 22-01 and keeps KEV as the basis for patch deadlines **[P]**. The catalogue page on `www.cisa.gov` itself returned HTTP 403 through the proxy; the JSON feed was unaffected. |
| MalwareBazaar recent hashes | https://bazaar.abuse.ch/export/txt/sha256/recent/ | 68 KB; 1,028 SHA-256 (about 48 h of samples) | Text, one SHA-256 per line, `#` header | abuse.ch terms, section 4 | Rolling; header showed 2026-10-15 16:46 UTC | CSV with family: `https://bazaar.abuse.ch/export/csv/recent/` (470 KB, 1,021 rows with `signature`, `file_name`, `file_type_guess`). Already used by the updater. |
| MalwareBazaar batches | https://datalake.abuse.ch/malware-bazaar/hourly/ and `/daily/` | index pages 42 KB / 513 KB | Directory listings of ZIPs; archives use the password `infected` per the FAQ | abuse.ch terms | Hourly / daily | Samples, not just hashes: do not download into a user's machine. |
| MalwareBazaar code-signing blocklist | https://bazaar.abuse.ch/export/csv/cscb/ | 103 KB | CSV of abused code-signing certificates | abuse.ch terms | Every 5 minutes per the FAQ **[P]** | Useful for the signature check in the file scanner (certificate thumbprints). Not yet wired anywhere. |
| ThreatFox, recent IOCs | https://threatfox.abuse.ch/export/csv/recent/ , https://threatfox.abuse.ch/export/json/recent/ , https://threatfox.abuse.ch/export/csv/ip-port/recent/ | CSV 1.96 MB (8,592 rows: 3,476 ip:port, 2,191 url, 1,996 domain, 617 sha256 and others); JSON 5.4 MB; ip-port 780 KB | CSV with `ioc_value`, `ioc_type`, `threat_type`, `malware_printable`, `confidence_level`, `first_seen_utc`; JSON keyed by IOC id | abuse.ch terms; IOCs older than 6 months are expired from exports since 2025-05-01 **[P]** | Every 5 minutes | The unauthenticated URLs worked, but the export page says an Auth-Key is required for all datasets and gives a keyed URL pattern. See section 4. The CSV contained rows with 2021 dates despite the expiry rule; the reason is unexplained. |
| URLhaus, online URLs | https://urlhaus.abuse.ch/downloads/text_online/ | 2.76 MB; 27,371 URLs | Text, one URL per line | abuse.ch terms | Dumps every 5 minutes per the API page **[P]** | Full (not only online) list `https://urlhaus.abuse.ch/downloads/text/` is 4.57 MB; CSV `csv_online` 7.4 MB with `threat`, `tags`, `url_status`. Observed composition on 2026-10-15 **[P]**: 18,354 of the 27,371 URLs (67%) are `raw.githubusercontent.com` links and another 2,423 are `github.com`; the dominant tags are SmartLoader (19,465), LuaJIT-loader (18,055), zip (14,891), CoinMiner (1,595), elf (1,502), FakeCaptcha (1,119) and seopoisoning (1,098). So this feed currently measures the SmartLoader/FakeGit campaign (section 7.2 of `docs/THREAT_LANDSCAPE.md`) more than anything else, and a naive URL blocklist match would be mostly GitHub paths. |
| URLhaus host file | https://urlhaus.abuse.ch/downloads/hostfile/ | 12 KB; 413 hosts | hosts format (`127.0.0.1 domain`) | abuse.ch terms | Not stated | Already used by the updater. |
| SSLBL certificate blocklist | https://sslbl.abuse.ch/blacklist/sslblacklist.csv | 827 KB | CSV `Listingdate,SHA1,Listingreason` | abuse.ch terms | Header showed 2026-10-14 | SHA-1 fingerprints of C2 TLS certificates (reasons such as Vidar C&C). Needs network capture to use; low value for a file scanner. |
| YARA Forge (core / extended / full) | https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip (also `-extended`, `-full`) | core 1.75 MB zip, one 7.9 MB `.yar` with 5,145 rules (YARA-Forge 0.9.1, built 2026-10-11); extended 3.57 MB; full 4.02 MB | YARA; imports `pe`, `hash`, `dotnet` | Per-rule licence in `license_url`; the sources mix Apache, DRL, GPL and "NO LICENSE SET" **[P]** | Roughly weekly (build date 2026-10-11) | The updater's `api.github.com` release lookup returned HTTP 403 in this sandbox, so only the `releases/latest/download/` fallback was verified. Compiling 5,145 rules needs yara-python and takes noticeable time. |
| YARAhub / YARAify | https://yaraify.abuse.ch/yarahub/yaraify-rules.zip | 1.28 MB zip; 1,419 `.yar` files | YARA with `yarahub_license`, `yarahub_rule_sharing_tlp` | Per rule: 1,152 CC0, 146 CC BY 4.0, 28 CC BY-SA 4.0, 54 CC BY-NC-SA, 35 CC BY-NC, 4 CC BY-NC-ND; TLP:WHITE for 1,417 **[P]** | Not stated | Quality is uneven (some rules target a single submitted sample). Keep only CC0 and CC BY if the rules are redistributed. `https://yaraify-api.abuse.ch/download/yaraify-rules.zip` returned an HTML page, not a zip, so do not use it. |
| Neo23x0 signature-base | https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/hash-iocs.txt | 470 KB; 3,245 entries | Text `HASH;comment`, MD5, SHA-1 or SHA-256 per line | Detection Rule License (DRL) 1.1 (`LICENSE` read): free use with attribution retained **[P]** | Maintained continuously | Same repository: `iocs/c2-iocs.txt` (44 KB, domains and IPs), `iocs/filename-iocs.txt` (140 KB), `yara/*.yar`. |
| Elastic protections-artifacts | https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/ (directory) | file reachable (HTTP 200 for a sample rule) | YARA, plus EQL behaviour rules | **Elastic License 2.0** (`LICENSE.txt` read) **[P]** | Continuous | Not an OSI open-source licence: do not bundle in an open-source release. At most offer an opt-in download with the licence shown to the user. |
| SigmaHQ rules | https://raw.githubusercontent.com/SigmaHQ/sigma/master/README.md (repo root) | README says more than 3,000 rules | Sigma YAML | Rules under DRL 1.1; specification and logo public domain (`LICENSE` read) **[P]** | Continuous | Sigma describes log events; Aegis has no event-log rule engine, so Sigma is reference material for rule authoring and for the realtime monitor, not a download target. The GitHub release API returned HTTP 403 here, so the packaged-release URL was not verified. |
| IPsum | https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt | 2.0 MB; 123,241 IPs, of which 18,892 appear on 3 or more source lists | Text `IP<TAB>count` | Unlicense / public domain (`LICENSE` read) **[P]** | Daily (header: 2026-10-15 03:00 +0200) | Use level 3 or higher only; level 1 to 2 is noise. Context for `check-url`, never a reason to quarantine a file. |
| Spamhaus DROP | https://www.spamhaus.org/drop/drop.txt and https://www.spamhaus.org/drop/drop_v4.json | 46.7 KB; 1,680 CIDR blocks; JSON 102 KB | Text `CIDR ; SBLnnn` / NDJSON | Free regardless of business type; **credit to Spamhaus and the date/copyright text must stay with the file**; do not fetch more than once an hour (the page also says once a day) **[P]** | Header `Expires` 2 h ahead | The page says the text format will eventually be replaced by JSON. Netblocks of hijacked or criminal-run networks: good for `check-url` and the network scanner. |
| Emerging Threats block IPs | https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt | 29 KB | Text, one IP/CIDR per line | Not read **[I]** | Not stated | Compiled from Spamhaus, DShield and abuse.ch per its header; adds little beyond DROP. |
| Phishing.Database | https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt | 11 MB | Text, one domain per line | MIT (`LICENSE` read) **[P]** | Continuous | Large; contains compromised legitimate hosts (free hosting subdomains), so match whole hostnames only. |
| Phishing Army | https://phishing.army/download/phishing_army_blocklist.txt | 3.5 MB; 158,596 entries per its header | Text, domains | Not read **[I]** | Header showed 2026-10-15 16:01 UTC | Aggregates PhishTank, OpenPhish, CERT.PL and others. |
| OpenPhish community feed | https://openphish.com/feed.txt | 16 KB | Text, URLs | The terms page was not read; the homepage fetch did not state the terms **[I]** | Not stated | Many entries were free-hosting subdomains. Check the terms before bundling. |
| PhishTank | https://data.phishtank.com/data/online-valid.csv | 12 MB | CSV `phish_id,url,verified,online,target` | Not read **[I]** | Not stated | The unauthenticated download worked today; PhishTank has changed registration rules before. |
| Palant malicious extensions list | https://codeberg.org/palant/malicious-extensions-list/raw/branch/main/list.txt | 5.9 KB; 164 extension IDs | Text, one 32-character ID per line | Not read **[I]** | Maintained by hand | Already used by the updater for `aegis/data/malicious_extensions.txt`. |
| Microsoft vulnerable driver blocklist | https://aka.ms/VulnerableDriverBlockList | 334 KB zip (redirects to the Download Center) | ZIP with `DriverPolicy_Enforced.xml` (App Control XML), a legacy `.p7b` and a `.cip`; the XML held 1,713 `Deny` rules (1,702 are Authenticode hashes, 162 are file-name rules), policy version 10.0.29545.0 **[P]** | Microsoft; Learn page says the list is updated quarterly and shipped with Windows updates **[P]** | Quarterly | Hashes are **Authenticode** hashes, not file SHA-256, so they cannot be matched against a plain file hash. LOLDrivers records an `Authentihash` per sample, which can be compared once Aegis computes the Authenticode hash. Windows 11 2022 update and later enforce the list by default when memory integrity, Smart App Control or S mode is on **[P]**. |
| MITRE ATT&CK STIX | https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json | 55 MB, version 20.0 (2026-10-13) | STIX 2.1 JSON | MITRE terms of use; not read in full **[I]** | Twice a year plus patches | Used to validate the technique ids in `threats_2026.json`. Do not ship to users; 55 MB. See `docs/THREAT_LANDSCAPE.md` section 7.3 for the v19/v20 renumbering. |
| OSV npm / PyPI dumps | https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip , `.../PyPI/all.zip` | 218 MB / 36 MB | ZIP of OSV JSON (includes `MAL-` malicious-package advisories from OpenSSF) | The `ossf/malicious-packages` repository is Apache-2.0 (`LICENSE` read) **[P]**; OSV data licence not read **[I]** | Continuous | Too large to bundle. For installed-package checks use the query API instead (next row). |
| OSV query API | `POST https://api.osv.dev/v1/query` | HTTP 200, 23.8 KB response for one lodash version | JSON | See above | Live | Works without a key. Suitable for developer-tool audits (npm, PyPI packages found on disk). |
| OpenSSF Scorecard API | https://api.securityscorecards.dev/projects/github.com/psf/requests | 8 KB | JSON, per-check scores | Not read **[I]** | Weekly per the project (not verified) | Optional signal for developer-tool risk. |
| FIRST EPSS | https://api.first.org/data/v1/epss?cve=CVE-2024-3400 ; daily file https://epss.empiricalsecurity.com/epss_scores-current.csv.gz | API HTTP 200; file 2.7 MB | JSON / gzip CSV | Not read **[I]** | Daily (response date 2026-10-15) | Orders KEV entries by exploitation probability; KEV alone is enough for Aegis. |
| NVD CVE API | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-3400 | HTTP 200, 14 KB | JSON | US Government data **[I]** | Live | Rate limited without an API key (not tested). |
| Tor bulk exit list | https://check.torproject.org/torbulkexitlist | 17 KB | Text, IPs | Not read **[I]** | Live | Informational only. A Tor exit is not malicious by itself. |

## 3. Reachable but not recommended

| Feed | URL | Observation | Reason |
|---|---|---|---|
| Feodo Tracker blocklists | https://feodotracker.abuse.ch/downloads/ipblocklist.txt , `ipblocklist_recommended.txt`, `ipblocklist.json` | `ipblocklist.txt` last updated 2026-03-04 and only 565 bytes; the recommended list had 1 entry; JSON entries show `last_online` 2026-03-07; the project page banner says the datasets are currently empty **[P]** | Botnet C2 infrastructure it tracks (Dridex, Emotet, TrickBot, QakBot, BazarLoader) has been disrupted. Licence stated on the page: CC0 **[P]**. The updater's `min_count` of 1 will be met by a few stale entries. |
| SSLBL IP blacklist | https://sslbl.abuse.ch/blacklist/sslipblacklist.csv | Header: "This list has been deprecated on 2025-01-03" **[P]** | Deprecated. |
| SSLBL JA3 list | https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv | Last updated 2021-08-03 **[P]** | Stale. |
| blocklist.de all attacks | https://lists.blocklist.de/lists/all.txt | 379 KB of IPs (SSH, mail and web attack sources) | Attack sources, not malware infrastructure; dynamic and residential addresses churn, so false positives on a user PC. |
| yaraify download API | https://yaraify-api.abuse.ch/download/yaraify-rules.zip | HTTP 200 but HTML, not a zip **[P]** | Use the `yaraify.abuse.ch/yarahub/` path instead. |

## 4. Terms that matter before Aegis downloads anything

* **abuse.ch (URLhaus, ThreatFox, MalwareBazaar, YARAhub, SSLBL).** The unauthenticated export URLs above returned
  live data, but the URLhaus and ThreatFox pages say downloads need a free **Auth-Key** from https://auth.abuse.ch/ **[P]**,
  and the MalwareBazaar API returned HTTP 401 without a key (`https://mb-api.abuse.ch/api/v1/`; ThreatFox and URLhaus API
  hosts also returned 401). Expect the keyless URLs to be withdrawn. The Terms of Use (https://abuse.ch/terms-of-use/)
  say access is for **not-for-profit purposes within usage limits**, forbid high-volume automated harvesting, and say
  commercial users may need a paid subscription managed by Spamhaus **[P]**. The Feodo Tracker page, by contrast, states
  CC0 **[P]**; none of the other pages read stated a licence. Treat the abuse.ch feeds as personal/non-commercial,
  fetch no more often than the updater already does, and add an optional `abuse_ch_auth_key` setting. The updater already
  has an `auth` flag on its `Feed` dataclass.
* **Spamhaus DROP.** Free for all users, attribution required, and the date/copyright header must stay with the data.
  Do not fetch more than once per hour; one hour is the safe floor given the page's conflicting once-a-day statement.
* **YARA rule sets.** Licences are per rule. YARA Forge records each rule's `license_url`; YARAhub records
  `yarahub_license`. A scanner that redistributes rules (rather than downloading them to the user's machine) must carry
  the attribution or filter by licence.
* **Elastic protections-artifacts** are under the Elastic License 2.0 and should not ship inside Aegis.
* **LOLDrivers** is Apache-2.0: redistribution of the derived hash list is fine with attribution (done in
  `vulnerable_drivers.txt` through the label prefix and this document).

## 5. What Aegis should add to `aegis/tools/updater.py`

The updater (owned by another agent, not edited here) currently pulls MalwareBazaar recent hashes, Feodo, URLhaus host
file, the Palant extension list and YARA Forge core. Recommended changes, in order:

1. **Add LOLDrivers.** Download `drivers.json` (33 MB, inside the updater's 64 MB `MAX_BYTES` cap), take every
   `KnownVulnerableSamples[].SHA256` that matches `^[0-9a-f]{64}$`, and write `vulnerable_drivers.txt` as
   `sha256<TAB>label`. The bundled file was generated exactly this way (2,198 unique hashes; 318 are tagged malicious
   rather than merely vulnerable). Validator: at least 500 hashes; reject if the new count is below 80% of the old one
   (`max_shrink=0.8`). Cadence: weekly.
2. **Add CISA KEV.** Download the JSON, validate `catalogVersion` and `count >= 1000`, and regenerate
   `kev_software_hints.json` (script logic: group `vulnerabilities[]` by `vendorProject`/`product`, keep the newest
   eight). Cadence: daily is fine (1.8 MB).
3. **Drop or demote Feodo.** Keep the entry only if a `min_count` of 1 is acceptable; otherwise remove it so a dormant
   feed does not look like protection. Consider replacing it with ThreatFox ip:port filtered to
   `threat_type == botnet_cc`.
4. **Add ThreatFox** (`csv/ip-port/recent`, plus `domain` and `sha256_hash` rows of the main CSV) with the Auth-Key
   mechanism. Filter to `confidence_level >= 75` and to Windows-relevant families if possible. 8.6k rows per pull.
5. **Add signature-base `hash-iocs.txt` and `c2-iocs.txt`.** Parse `HASH;comment` for 32/40/64 hex characters; the
   existing `SignatureDB` already reads `hash<TAB>name`, so convert `;` to a tab. DRL 1.1 requires keeping attribution.
6. **Add URLhaus `text_online`** (27k URLs) only if `check-url` should match full URLs; the host file already covers
   domains. Prefer hostnames to full URLs to keep the memory footprint small.
7. **Optional, for `check-url`:** Phishing.Database (MIT) filtered to hostnames; IPsum level 3+; Spamhaus DROP.
8. **YARA sets:** keep YARA Forge core. If YARAhub is added, filter on `yarahub_license` in {`CC0 1.0`, `CC BY 4.0`}.
9. **Fix the YARA Forge lookup.** `api.github.com` calls can be blocked (HTTP 403 here); make the
   `releases/latest/download/` URL the primary and the API the fallback, since the direct URL was verified working.
10. **Do not add:** Elastic artifacts (licence), blocklist.de (false positives), SSLBL IP/JA3 (deprecated/stale).

Core-engine note: a larger rule set makes every scan slower because `Rule.match` evaluates every string of every
applicable rule. Evaluating the strings lazily and returning as soon as the condition cannot be met was benchmarked at
about 2.6x faster on text with identical results; see the hand-off report.

## 6. Data files produced in this pass

| File | Content | How it was made |
|---|---|---|
| `aegis/data/vulnerable_drivers.txt` | 2,198 SHA-256 hashes, one per line, `sha256<TAB>label` (no comment lines). Label prefix `LOLDrivers.VulnDriver:` or `LOLDrivers.MalDriver:` then the driver file name and up to three CVE ids. | LOLDrivers `drivers.json` snapshot of 2026-10-15 (Apache-2.0). Presence on disk is a risk finding, not proof of compromise: these are legitimately signed drivers that attackers load deliberately. |
| `aegis/data/kev_software_hints.json` | Eleven product groups (Chrome, Edge, Firefox, Acrobat, WinRAR, 7-Zip, Notepad++, Office/Outlook, Java, WPS Office, Windows) with the eight newest KEV entries each, totals and last-added dates, and plain advice. | Generated from the KEV catalogue `2026.10.15`; every CVE id comes from the feed, none was typed by hand. KEV has no version ranges, so this is prioritisation, not a version check. |

## 7. Not verified

* Licences marked **[I]** above were not read. Do not bundle those feeds' data until the terms are confirmed.
* The OpenPhish and PhishTank terms, EPSS terms, OSV data licence and Scorecard data terms were not read.
* The GitHub release API and packaged Sigma release could not be fetched from this sandbox (HTTP 403 through the proxy);
  this does not imply they fail from a normal network.
* Update cadences stated by the sites (5 minutes, hourly) are intervals the operators publish; real freshness was only
  observed from file headers on one day.
