# Architecture

```
                        ┌──────────────┐   ┌──────────────┐   ┌───────────────────┐
  user / RMM / tasks ──▶│  aegis.cli   │   │ aegis.ui.gui │   │ Scheduled tasks / │
                        └──────┬───────┘   └──────┬───────┘   │ systemd (service) │
                               │                  │           └─────────┬─────────┘
                               ▼                  ▼                     ▼
                        ┌─────────────────────────────────┐    ┌──────────────────┐
                        │        core.engine.ScanEngine   │    │ realtime.monitor │
                        │ profiles · allow-list · scoring │    │ file / process / │
                        └───┬──────────────┬──────────────┘    │ ransomware /     │
                            │ ScanContext  │                   │ persistence guard│
          ┌─────────────────┼──────────────┼────────────┐      └────────┬─────────┘
          ▼                 ▼              ▼            ▼               │
   scanners.files   scanners.processes  .persistence  .browser ...     │ reuses scan_file,
   (hash · rules ·   (cmdline analysis   (Autoruns)   .network          │ cmdline analysis,
    YARA · heur.)     masquerade, RATs)               .system_audit     │ collect_entries
          │                                           .software .secrets│
          ▼                                                             ▼
   core.signatures ◀── tools.updater (abuse.ch, Codeberg, YARA Forge)   notify (toasts)
   core.rules (Aegis-Lite)   core.fileanalysis (PE parser, heuristics)
          │
          ▼
   Findings / CheckResults ─▶ core.report (HTML/JSON/CSV/TXT) ─▶ core.remediation ─▶ core.quarantine
```

## Key concepts

* **Finding**: a threat or problem, carrying a severity, category, evidence, recommendation, MITRE
  techniques and an optional machine-actionable `Remediation`. Its `fingerprint` (a hash of rule id and
  location) is used for de-duplication, `aegis fix --id` and allow-listing.
* **CheckResult**: a pass/fail hardening check. The report lists all of them, so passing checks are
  visible as well.
* **Scanner**: a plugin that registers itself with `@register` and yields findings and checks from
  `run(ctx)`. To add one, drop a module into `aegis/scanners/` and list it in `base.load_all()`.
* **Profiles** (`core/engine.py`): `quick` runs processes, persistence, hot-spot files, browser, network and
  downloads. `full` adds every drive, system audit, software, secrets and the threat-hunting scanners (eventlog,
  drivers, sideload, usb, email, memory, supplychain, ide, privacy, apptamper, recovery, traces, remoteaccess). `audit` runs
  configuration checks only (system audit, software and updates, network, browser, recovery readiness).
* **Action plan** (`core/report.py: action_plan`): groups findings by rule, worst first, with the fix command for
  each group. The HTML and console reports and the desktop dashboard all show it.
* **Signatures** (`core/signatures.py`): bundled data in `aegis/data` is merged with downloaded feeds in
  `<data>/signatures`. If a feed update fails, the previous file is kept.
* **Data directory**: `%ProgramData%\Aegis` when running as admin, `%LOCALAPPDATA%\Aegis` otherwise
  (`~/.local/share/aegis` on Linux). Override it with `AEGIS_HOME`. It holds `config.json`, `signatures/`,
  `quarantine/`, `backups/`, `reports/`, `logs/` and `scan_cache.sqlite`.

## Detection pipeline for a file

1. Stat the file. Skip it if it's excluded, unchanged since the last clean scan (cache), or not a risky
   type (quick mode).
2. Compute SHA-256/MD5 and look them up in the hash DB. A hit is a CRITICAL detection and the pipeline
   stops here.
3. Classify the file by magic bytes and extension (pe, elf, macho, script, office, pdf, lnk, archive, text).
4. Run the Aegis-Lite rules that apply to the type, then the YARA rules if `yara-python` is installed.
5. Run the heuristics for the type. Indicator scores are summed and mapped to a severity; strong
   single indicators (RTLO, double extension, shadow-copy deletion) raise it.
6. Recurse into ZIP-family archives, with depth, member-count and bomb-ratio limits.
7. If the result is only "suspicious", ask Microsoft Defender (MpCmdRun) and, when enabled, VirusTotal.

## Safety principles

* Nothing is deleted outright. Files go to an XOR-obfuscated quarantine, and registry, task, hosts and
  service changes are backed up to JSON first.
* Fixes run only on request (`--fix`, `fix`, GUI button) unless auto-quarantine is enabled explicitly.
* Heuristic detections are labelled "Suspicious" and explain their indicators, so the user stays in control.
