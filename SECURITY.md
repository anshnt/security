# Security policy

## Reporting a vulnerability

Please report vulnerabilities in Aegis privately via GitHub's "Report a vulnerability"
(Security Advisories) on this repository rather than opening a public issue. Include
the version (`aegis --version`), OS, and reproduction steps. We aim to respond within 7 days.

## False positives / missed detections

Open an issue with the SHA-256 of the file (never attach live malware), the rule id shown in the
finding (e.g. `AEG-HEUR`, `AEG-PROC-MASQ`) and the finding's evidence block from the JSON report.

## Design guarantees

* No telemetry. Network access happens only for `aegis update`, opt-in VirusTotal / Safe Browsing
  lookups (hashes / URLs only), and the password breach check (k-anonymity: only the first 5
  characters of the SHA-1 leave the machine).
* Secrets found by the secrets scanner are masked in every report.
* Every remediation is reversible: quarantine can be restored and registry/task/hosts changes
  are backed up to `<data>/backups` as JSON.
