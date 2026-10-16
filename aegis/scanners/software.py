"""Installed-software inventory: PUP/adware detection, vulnerable & end-of-life
software, and remote-access-tool inventory.

* Windows: HKLM / HKLM-WOW6432Node / HKCU Uninstall keys.
* Linux: dpkg-query or rpm (best effort).  macOS: /Applications/*.app Info.plist.

Vulnerable-software rules live in `aegis/data/vulnerable_software.json` (see its
`_comment` for the schema). Auto-uninstalling is deliberately NOT offered
because an uninstall string is arbitrary third-party code; the finding carries
the uninstall command as evidence instead.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import plistlib
import re
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from aegis.core.config import PACKAGE_DATA
from aegis.core.models import Category, CheckResult, CheckStatus, Finding, Severity
from aegis.core.platform import IS_LINUX, IS_MAC, IS_WINDOWS, OS_NAME, reg_walk_values, run
from aegis.scanners.base import Emitted, ScanContext, Scanner, register

log = logging.getLogger("aegis.software")

VULN_RULES_FILE = PACKAGE_DATA / "vulnerable_software.json"

UNINSTALL_KEYS = [
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", True, "HKLM"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", False, "HKLM-WOW6432"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Uninstall", True, "HKCU"),
]

_UPDATE_NAME = re.compile(r"^(security update|update for|hotfix|cumulative update)\b|\(kb\d{6,8}\)", re.I)


# =========================================================================== version helpers
_VER_RX = re.compile(r"\d+(?:\.\d+)*")


def parse_version(text: Any) -> Optional[Tuple[int, ...]]:
    """First dotted-number run in `text` as a tuple: '7.12 (64-bit)' -> (7, 12), '8.0.4010.7' ->
    (8, 0, 4010, 7), '1.1.1w' -> (1, 1, 1), 'v24.09' -> (24, 9). None if there are no digits."""
    if text is None:
        return None
    m = _VER_RX.search(str(text))
    if not m:
        return None
    return tuple(int(p) for p in m.group(0).split("."))


def compare_versions(a: Any, b: Any) -> Optional[int]:
    """-1/0/1 like cmp(); None if either side has no parsable version. Missing trailing parts count as 0."""
    va, vb = parse_version(a), parse_version(b)
    if va is None or vb is None:
        return None
    n = max(len(va), len(vb))
    va += (0,) * (n - len(va))
    vb += (0,) * (n - len(vb))
    return (va > vb) - (va < vb)


# =========================================================================== inventory
def _entry(name: str, version: str = "", publisher: str = "", location: str = "", uninstall: str = "",
           date: str = "", source: str = "") -> Dict[str, str]:
    return {"name": name.strip(), "version": str(version or "").strip(), "publisher": str(publisher or "").strip(),
            "install_location": str(location or "").strip(), "uninstall_string": str(uninstall or "").strip(),
            "install_date": str(date or "").strip(), "source": source}


def entry_from_uninstall_values(vals: Dict[str, Any], source: str = "") -> Optional[Dict[str, str]]:
    """Convert one Uninstall-key's values into an inventory entry (None for noise)."""
    name = str(vals.get("DisplayName") or "").strip()
    if not name:
        return None
    if vals.get("SystemComponent") == 1 or vals.get("ParentKeyName") or vals.get("ParentDisplayName"):
        return None  # hidden components and patches
    if str(vals.get("ReleaseType", "")).lower() in ("update", "hotfix", "security update", "update rollup", "service pack"):
        return None
    if _UPDATE_NAME.search(name):
        return None
    uninstall = vals.get("QuietUninstallString") or vals.get("UninstallString") or ""
    return _entry(name, vals.get("DisplayVersion", ""), vals.get("Publisher", ""), vals.get("InstallLocation", ""),
                  uninstall, vals.get("InstallDate", ""), source)


def collect_windows_inventory() -> List[Dict[str, str]]:
    items: Dict[Tuple[str, str], Dict[str, str]] = {}
    for hive, key, view64, label in UNINSTALL_KEYS:
        for _path, vals in reg_walk_values(hive, key, view64):
            e = entry_from_uninstall_values(vals, label)
            if e:
                items.setdefault((e["name"].lower(), e["version"]), e)
    return list(items.values())


def collect_linux_inventory() -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    rc, so, _ = run(["dpkg-query", "-W", "-f", "${Package}\t${Version}\t${Maintainer}\t${db:Status-Abbrev}\n"], timeout=60)
    if rc == 0:
        for line in so.splitlines():
            parts = line.split("\t")
            if len(parts) >= 4 and parts[3].startswith("ii"):
                out.append(_entry(parts[0], parts[1], parts[2], source="dpkg"))
        return out
    rc, so, _ = run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n"], timeout=60)
    if rc == 0:
        for line in so.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2 and parts[0] != "gpg-pubkey":
                out.append(_entry(parts[0], parts[1], parts[2] if len(parts) > 2 else "", source="rpm"))
    return out


def collect_macos_inventory(app_dirs: Sequence[str] = ("/Applications", "~/Applications")) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    for d in app_dirs:
        base = Path(d).expanduser()
        if not base.is_dir():
            continue
        try:
            apps = sorted(base.glob("*.app")) + sorted(base.glob("*/*.app"))
        except OSError:
            continue
        for app in apps:
            plist = app / "Contents" / "Info.plist"
            try:
                with plist.open("rb") as fh:
                    info = plistlib.load(fh)
            except Exception:
                continue
            name = info.get("CFBundleDisplayName") or info.get("CFBundleName") or app.stem
            out.append(_entry(str(name), info.get("CFBundleShortVersionString") or info.get("CFBundleVersion") or "",
                              info.get("CFBundleIdentifier", ""), str(app), "", "", "app"))
    return out


def collect_inventory() -> List[Dict[str, str]]:
    if IS_WINDOWS:
        return collect_windows_inventory()
    if IS_MAC:
        return collect_macos_inventory()
    return collect_linux_inventory()


# =========================================================================== PUP matching
def compile_pup_matcher(pup_names: Iterable[str]) -> Optional["re.Pattern[str]"]:
    names = sorted({n.strip().lower() for n in pup_names if n and n.strip()}, key=len, reverse=True)
    if not names:
        return None
    alt = "|".join(re.escape(n) for n in names)
    return re.compile(r"(?<![a-z0-9])(" + alt + r")(?![a-z0-9])", re.I)


def match_pup(name: str, matcher: Optional["re.Pattern[str]"]) -> Optional[str]:
    """Return the PUP signature found in an installed program's display name (whole-word,
    case-insensitive), or None."""
    if not matcher or not name:
        return None
    m = matcher.search(name)
    return m.group(1).lower() if m else None


def pup_finding(entry: Dict[str, str], signature: str) -> Finding:
    name = entry["name"]
    uninstall = entry.get("uninstall_string", "")
    how = ("Open Settings > Apps > Installed apps, find '" + name + "' and choose Uninstall. ")
    if uninstall:
        how += f"(The uninstall command registered by the program is shown in the details; Aegis does not run it automatically.) "
    how += ("Afterwards reset your browsers' home page/search engine, remove unknown extensions "
            "(Aegis' browser scan lists them) and run a full scan. For stubborn adware, run Malwarebytes AdwCleaner.")
    return Finding(
        rule_id="AEG-SW-PUP",
        title=f"Potentially unwanted program: {name}",
        severity=Severity.MEDIUM,
        category=Category.PUP,
        description=(f"'{name}' matches the potentially-unwanted-program signature '{signature}'. Programs like this "
                     "are bundled with free downloads and typically show ads, hijack the browser home page or search "
                     "engine, track browsing or push 'fix your PC' scareware."),
        location=f"software:{name}",
        evidence={"name": name, "version": entry.get("version", ""), "publisher": entry.get("publisher", ""),
                  "install_location": entry.get("install_location", ""),
                  "uninstall_string": uninstall, "install_date": entry.get("install_date", ""),
                  "matched_signature": signature},
        recommendation=how,
        mitre=["T1176", "T1189"],
    )


# =========================================================================== vulnerable software rules
def load_vuln_rules(path: Path = VULN_RULES_FILE) -> Dict[str, Any]:
    """Load and validate the rules file. Rules with broken regexes are dropped (and logged)."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        log.warning("could not load %s: %s", path, exc)
        return {"rules": [], "remote_access_software": []}
    good = []
    for r in raw.get("rules", []):
        try:
            r["_rx"] = re.compile(r["name_regex"], re.I)
            r["_ex"] = re.compile(r["exclude_regex"], re.I) if r.get("exclude_regex") else None
            r["_vn"] = re.compile(r["version_from_name"], re.I) if r.get("version_from_name") else None
            r["_sev"] = Severity.parse(r.get("severity", "medium"))
            good.append(r)
        except Exception as exc:
            log.warning("bad vulnerable-software rule %s: %s", r.get("id"), exc)
    return {"rules": good, "remote_access_software": raw.get("remote_access_software", [])}


def _rule_version(rule: Dict[str, Any], entry: Dict[str, str]) -> str:
    """Version used for comparison: from the display name if the rule says so, else DisplayVersion,
    else the first dotted number in the name."""
    if rule.get("_vn"):
        m = rule["_vn"].search(entry["name"])
        if m:
            return m.group(1)
    if entry.get("version"):
        return entry["version"]
    m = re.search(r"\d+(?:\.\d+)+", entry["name"])
    return m.group(0) if m else ""


def match_vuln_rule(rule: Dict[str, Any], entry: Dict[str, str], today: Optional[dt.date] = None,
                    platform: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Return match details if `entry` is affected by `rule`, else None."""
    today = today or dt.date.today()
    platform = platform or OS_NAME
    if platform not in rule.get("platforms", ["windows", "darwin"]):
        return None
    name = entry.get("name", "")
    if not rule["_rx"].search(name):
        return None
    if rule.get("_ex") and rule["_ex"].search(name):
        return None
    if rule.get("eol_date"):
        try:
            if today < dt.date.fromisoformat(rule["eol_date"]):
                return None
        except ValueError:
            pass
    version = _rule_version(rule, entry)
    if rule.get("exact_versions"):
        if any(compare_versions(version, v) == 0 for v in rule["exact_versions"]):
            return {"version": version, "reason": "exact affected build"}
        return None
    if rule.get("max_vulnerable_version") == "any":
        return {"version": version, "reason": "all versions affected / end of life"}
    if rule.get("fixed_version"):
        c = compare_versions(version, rule["fixed_version"])
        if c is not None and c < 0:
            return {"version": version, "reason": f"older than fixed version {rule['fixed_version']}"}
        return None
    if rule.get("max_vulnerable_version"):
        c = compare_versions(version, rule["max_vulnerable_version"])
        if c is not None and c <= 0:
            return {"version": version, "reason": f"at or below {rule['max_vulnerable_version']}"}
    return None


def vuln_finding(rule: Dict[str, Any], entry: Dict[str, str], match: Dict[str, Any]) -> Finding:
    name = entry["name"]
    version = match.get("version") or entry.get("version") or ""
    eol = bool(rule.get("eol"))
    cves = rule.get("cve")
    if isinstance(cves, list):
        cves = ", ".join(cves)
    shown = entry.get("version", "")
    if not shown or shown in name or rule.get("_vn"):
        shown = ""
    if rule.get("title"):
        title = f"{rule['title']} ({version})" if version else rule["title"]
    else:
        title = ("Unsupported software: " if eol else "Vulnerable software: ") + name + (f" {shown}" if shown else "")
    return Finding(
        rule_id="AEG-SW-EOL" if eol else "AEG-SW-VULN",
        title=title,
        severity=rule["_sev"],
        category=Category.VULNERABILITY,
        description=(f"{name} {version}".strip() + f" - {match['reason']}. " + (f"Reference: {cves}." if cves else "")),
        location=f"software:{name} {entry.get('version', '')}".strip(),
        evidence={"name": name, "version": entry.get("version", ""), "detected_version": version,
                  "rule": rule.get("id"), "cve": cves or "", "fixed_version": rule.get("fixed_version", ""),
                  "publisher": entry.get("publisher", ""), "install_location": entry.get("install_location", ""),
                  "uninstall_string": entry.get("uninstall_string", ""), "reference": rule.get("reference", "")},
        recommendation=rule.get("advice", "Update or uninstall this software."),
        mitre=["T1203", "T1190"] if not eol else ["T1203"],
    )


def find_remote_access(inventory: Sequence[Dict[str, str]], names: Sequence[str]) -> List[Tuple[Dict[str, str], str]]:
    matcher = compile_pup_matcher(names)
    out = []
    for e in inventory:
        sig = match_pup(e["name"], matcher)
        if sig:
            out.append((e, sig))
    return out


def remote_access_finding(entry: Dict[str, str], sig: str) -> Finding:
    return Finding(
        rule_id="AEG-SW-REMOTE",
        title=f"Remote access software installed: {entry['name']}",
        severity=Severity.INFO,
        category=Category.SYSTEM,
        description=(f"{entry['name']} lets someone control this PC remotely. That is fine if you installed it, but "
                     "remote-access tools are also what tech-support scammers and ransomware crews ask victims to install."),
        location=f"software:{entry['name']}",
        evidence={"name": entry["name"], "version": entry.get("version", ""), "publisher": entry.get("publisher", ""),
                  "install_location": entry.get("install_location", ""), "matched": sig},
        recommendation=("If you do not recognise this program or did not install it yourself, uninstall it now and "
                        "change your passwords. If you use it, keep it updated, protect it with a strong unique password "
                        "and 2FA, and close it when not needed. (The processes scanner reports it if it is running.)"),
        mitre=["T1219.002"],
    )


# =========================================================================== analysis pipeline
def analyse_inventory(inventory: Sequence[Dict[str, str]], pup_names: Iterable[str], rules: Dict[str, Any],
                      today: Optional[dt.date] = None, platform: Optional[str] = None) -> Iterator[Finding]:
    """Pure function used by the scanner and the tests."""
    today = today or dt.date.today()
    matcher = compile_pup_matcher(pup_names)
    remote_matcher = compile_pup_matcher(rules.get("remote_access_software", []))
    seen_remote = set()
    for e in inventory:
        sig = match_pup(e["name"], matcher)
        if sig:
            yield pup_finding(e, sig)
        for rule in rules.get("rules", []):
            m = match_vuln_rule(rule, e, today, platform)
            if m:
                yield vuln_finding(rule, e, m)
        rs = match_pup(e["name"], remote_matcher)
        if rs and e["name"].lower() not in seen_remote:
            seen_remote.add(e["name"].lower())
            yield remote_access_finding(e, rs)


@register
class SoftwareScanner(Scanner):
    name = "software"
    title = "Installed software audit"
    description = ("Inventories installed programs; flags adware/PUPs, vulnerable or end-of-life software and "
                   "installed remote-access tools.")
    platforms = ("windows", "linux", "darwin")

    def run(self, ctx: ScanContext) -> Iterator[Emitted]:
        ctx.report(self.name, "reading installed programs")
        try:
            inventory = collect_inventory()
        except Exception as exc:
            log.warning("inventory failed: %s", exc)
            yield CheckResult("AEG-SW-INVENTORY", "Installed software inventory", CheckStatus.ERROR,
                              f"{type(exc).__name__}: {exc}", Category.SYSTEM)
            return
        ctx.bump("software_installed", len(inventory))
        ctx.options["software_inventory"] = inventory
        if not inventory:
            yield CheckResult("AEG-SW-INVENTORY", "Installed software inventory", CheckStatus.SKIP,
                              "No installed programs could be listed on this system.", Category.SYSTEM)
            return
        yield CheckResult("AEG-SW-INVENTORY", "Installed software inventory", CheckStatus.PASS,
                          f"{len(inventory)} installed program(s) found.", Category.SYSTEM)

        rules = load_vuln_rules()
        counts = {"pup": 0, "vuln": 0, "remote": 0}
        for f in analyse_inventory(inventory, ctx.signatures.pup_names, rules, dt.date.today(), OS_NAME):
            if ctx.cancelled:
                return
            counts["pup" if f.rule_id == "AEG-SW-PUP" else "remote" if f.rule_id == "AEG-SW-REMOTE" else "vuln"] += 1
            yield f

        def result(check_id: str, title: str, n: int, bad: str) -> CheckResult:
            status = CheckStatus.PASS if n == 0 else (CheckStatus.WARN if check_id == "AEG-SW-REMOTE" else CheckStatus.FAIL)
            return CheckResult(check_id, title, status, "None found." if n == 0 else bad.format(n=n),
                               Category.PUP if check_id == "AEG-SW-PUP" else Category.VULNERABILITY
                               if check_id == "AEG-SW-VULN" else Category.SYSTEM)

        yield result("AEG-SW-PUP", "No adware / potentially unwanted programs installed", counts["pup"],
                     "{n} potentially unwanted program(s) found.")
        yield result("AEG-SW-VULN", "No vulnerable or end-of-life software installed", counts["vuln"],
                     "{n} vulnerable or unsupported program(s) found.")
        yield result("AEG-SW-REMOTE", "No remote-access software installed", counts["remote"],
                     "{n} remote-access program(s) installed (inventory only).")
        if ctx.options.get("software_updates", True) and not ctx.cancelled:
            yield from self._updates(ctx)

    def _updates(self, ctx: ScanContext) -> Iterator[Emitted]:
        from aegis.tools import appupdates

        ctx.report(self.name, "checking for app updates")
        title = "Installed apps are up to date"
        try:
            source, updates, problem = appupdates.collect_updates()
        except Exception as exc:  # pragma: no cover - defensive
            yield CheckResult("AEG-SW-UPDATES", title, CheckStatus.ERROR, f"{type(exc).__name__}: {exc}", Category.VULNERABILITY)
            return
        if problem:
            # a package manager that fails (offline, source outage) is not an Aegis error: warn and move on
            yield CheckResult("AEG-SW-UPDATES", title, CheckStatus.SKIP if not source else CheckStatus.WARN, problem,
                              Category.VULNERABILITY)
            return
        ctx.bump("software_updates_available", len(updates))
        findings = appupdates.update_findings(source, updates)
        yield from findings
        risky = sum(1 for f in findings if f.rule_id == "AEG-SW-UPDATE")
        yield CheckResult("AEG-SW-UPDATES", title, CheckStatus.FAIL if risky else CheckStatus.WARN if updates else CheckStatus.PASS,
                          (f"{len(updates)} update(s) available from {source}" + (f", {risky} for high-risk apps" if risky else "")
                           + ".") if updates else f"No pending updates reported by {source}.", Category.VULNERABILITY)
