"""Download provenance: where the risky files in Downloads and on the Desktop came from.

Browsers record where a download came from and the operating system keeps it with the file (see ``aegis.core.provenance``:
the Windows Mark-of-the-Web, the macOS quarantine record and ``kMDItemWhereFroms``, the ``user.xdg.origin.url`` attribute on
Linux). Most infections that start with a download can be recognised by where it came from, before anyone looks inside the
file. This scanner reviews the current user's Downloads folder and Desktop (the top level and two sub-levels, at most
5,000 entries, files modified in the last 90 days) for files of a risky type - programs, installers, scripts, shortcuts, disk
images, archives and macro documents - and reports one finding per file, the strongest reason first:

* **HIGH** - the download address (or the page that offered the file) is on the malicious-domain or malicious-IP feed
  (``AEG-DL-BADSOURCE``); the file name is built to mislead: a right-to-left override or another direction-control character,
  or a program dressed as a document with a double extension such as ``invoice.pdf.exe`` (``AEG-DL-DECEPTIVE``). A HIGH
  finding offers to quarantine the file.
* **MEDIUM** - a ``blob:`` or ``data:`` download address, meaning the web page built the file itself in JavaScript (HTML
  smuggling, ``AEG-DL-SMUGGLED``); a program or script fetched from a WebDAV or network share (``AEG-DL-WEBDAV``) or from a bare
  IP address (``AEG-DL-RAWIP``).
* **LOW** - a program or script from a paste, anonymous file-sharing or short-link host (``AEG-DL-FILEHOST``) or over plain
  http:// (``AEG-DL-INSECURE``). These are weak signals on their own: legitimate files are shared this way too.

On Windows the scanner also audits the Attachment Manager policy: ``SaveZoneInformation = 1`` (HKCU or HKLM) stops Windows
marking downloads, so SmartScreen and Office Protected View no longer apply and the origin of a download cannot be read
(``AEG-DL-MOTW-OFF``, MEDIUM, with a fix that sets it back to 2); ``ScanWithAntiVirus = 1`` stops Windows asking the antivirus
to scan attachments (``AEG-DL-AVSCAN-OFF``, LOW).

An origin is a clue, not a verdict: findings say so, carry the addresses without query strings, and never read the content of
a file. A file with no recorded origin (copied from a USB stick, extracted by a tool that drops the record, saved by Firefox
on Linux) is counted but not reported. Reading and classifying origins is in ``aegis.core.provenance``; the folder walk, the
finding builders and the policy audit here are pure functions with injectable readers, unit-tested on any OS.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple

from aegis.core import provenance as prov
from aegis.core.models import Category, CheckResult, CheckStatus, Finding, Remediation, Severity
from aegis.core.platform import IS_WINDOWS, reg_read, user_home
from aegis.core.provenance import Origin, Reason, classify_download, file_ext, origin_evidence, read_origin, visible
from aegis.scanners.base import Emitted, ScanContext, Scanner, register

log = logging.getLogger("aegis.downloads")

DEFAULT_DAYS = 90
MAX_DEPTH = 2  # sub-levels reviewed below the top of Downloads and of the Desktop
MAX_ENTRIES = 5000  # directory entries looked at, all folders together
MAX_FINDINGS = 200
BUDGET_S = 30.0
MAX_NAMES = 5  # file names listed in a failing check result

# programs, installers, scripts, shortcuts, disk images, archives and macro documents
RISKY_EXTS = frozenset({
    "exe", "msi", "msix", "msixbundle", "appx", "appxbundle", "appinstaller", "scr", "com", "pif", "cpl", "bat", "cmd", "ps1",
    "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "lnk", "url", "library-ms", "search-ms", "iso", "img", "vhd", "vhdx",
    "dmg", "pkg", "mpkg", "sh", "run", "appimage", "deb", "rpm", "jar", "zip", "rar", "7z", "docm", "xlsm", "pptm", "one", "chm",
    "reg", "application",
})

PROVENANCE_ID = "AEG-DL-CHK-PROVENANCE"
PROVENANCE_TITLE = "Downloaded programs come from safe places"
MOTW_ID = "AEG-DL-CHK-MOTW"
MOTW_TITLE = "Windows marks downloaded files"
UPDATE_HINT = "Matching against known-malicious domains is off because no threat feed is loaded (`aegis update`)."

ATTACHMENTS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Policies\Attachments"
SHELL_FOLDERS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
DOWNLOADS_FOLDER_ID = "{374DE290-123F-4565-9164-39C4925E467B}"  # the Downloads known folder

DISCLAIMER = ("These are signals about where the file came from and how it is named, not proof that it is malicious: legitimate "
              "software is sometimes distributed this way. Aegis has not examined what the file does; a scan of the file does "
              "that.")
SOURCE_NOTES = {
    prov.SOURCE_ZONE: "Windows marked it as downloaded (Mark-of-the-Web)",
    prov.SOURCE_QUARANTINE: "macOS marked it as downloaded (quarantine record)",
    prov.SOURCE_XATTR: "its extended attributes record where it was downloaded from",
}
RECOMMEND_HIGH = ("Do not open or run this file unless you are sure where it came from. Quarantine it (the fix below moves it to "
                  "the Aegis quarantine, from where it can be restored) and run a full Aegis scan. If it was already opened, "
                  "treat the PC as compromised: scan, review the persistence results and change your important passwords "
                  "from a clean device.")
RECOMMEND_OTHER = ("Run it only if you chose to download it from a source you trust. Prefer the vendor's own website to mirrors "
                   "and file-sharing links, and check the file with `aegis scan --path <file>` or a hash lookup (VirusTotal) "
                   "before running it.")


# =========================================================================== helpers (pure)


def _plural(n: int, one: str, many: str) -> str:
    return one if n == 1 else many


def _iso(timestamp: float) -> str:
    try:
        return dt.datetime.fromtimestamp(timestamp).isoformat(timespec="seconds")
    except (OverflowError, OSError, ValueError):
        return ""


def _to_int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def file_kind(ext: str) -> str:
    if ext in prov.PROGRAM_EXTS:
        return "program or installer"
    if ext in prov.SCRIPT_EXTS:
        return "script"
    if ext in prov.SHORTCUT_EXTS:
        return "shortcut"
    if ext in prov.CONTAINER_EXTS:
        return "disk image or archive"
    return "file"


def shell_folders(read: Optional[Callable[..., Any]] = None) -> List[Path]:
    """Where Explorer keeps this user's Downloads folder and Desktop when they were moved (OneDrive folder backup moves the
    Desktop, users move Downloads to another drive): the ``User Shell Folders`` values, with %VARIABLES% expanded."""
    read = read or reg_read
    out: List[Path] = []
    for name in (DOWNLOADS_FOLDER_ID, "Desktop"):
        try:
            value = read("HKCU", SHELL_FOLDERS_KEY, name)
        except Exception:  # an unreadable value leaves the default folders
            continue
        if isinstance(value, str) and value.strip():
            env = {k.lower(): v for k, v in os.environ.items()}  # REG_EXPAND_SZ: %USERPROFILE%\\Downloads
            out.append(Path(re.sub(r"%([^%]+)%", lambda m: env.get(m.group(1).lower(), m.group(0)), value.strip())))
    return out


def download_roots() -> List[Path]:
    """The folders downloads land in: the user's Downloads folder and Desktop (on Windows also where Explorer has moved
    them), those that exist, each once."""
    home = user_home()
    candidates = [home / "Downloads", home / "Desktop"] + (shell_folders() if IS_WINDOWS else [])
    out: List[Path] = []
    seen = set()
    for folder in candidates:
        key = os.path.normcase(os.path.abspath(str(folder)))
        if key not in seen and folder.is_dir():
            seen.add(key)
            out.append(folder)
    return out


def feed_checker(sigs: Any) -> Optional[Callable[[str], bool]]:
    """Whether a host is on the malicious-domain or malicious-IP feed, or None when no feed is loaded (so that a scan without
    one says so instead of reporting a clean result). A raw IP address is looked up in both feeds: the URLhaus host list names
    many servers by address."""
    if not any(getattr(sigs, feed, None) for feed in ("bad_domains", "bad_ips", "bad_networks")):
        return None

    def is_bad(host: str) -> bool:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return bool(sigs.is_bad_domain(host))
        return host in (getattr(sigs, "bad_domains", None) or ()) or bool(sigs.is_bad_ip(host))

    return is_bad


# =========================================================================== folder walk


@dataclass
class Walk:
    files: List[Tuple[Path, os.stat_result]] = field(default_factory=list)  # risky type, modified recently
    entries: int = 0
    notes: List[str] = field(default_factory=list)  # why the walk stopped early


def walk_downloads(roots: Sequence[Path], since: float, deadline: float, cancelled: Callable[[], bool],
                   max_entries: int = MAX_ENTRIES) -> Walk:
    """Risky files modified since ``since`` (a timestamp) in the roots and ``MAX_DEPTH`` levels below them, breadth first so
    the top of every folder is seen before the cap or the time budget ends the walk. Links are never followed."""
    walk = Walk()
    seen = set()
    queue: List[Tuple[Path, int]] = [(root, 0) for root in roots]
    index = 0
    while index < len(queue):
        folder, depth = queue[index]
        index += 1
        try:
            with os.scandir(folder) as entries:
                for entry in entries:
                    if cancelled():
                        return walk
                    if walk.entries >= max_entries:
                        walk.notes.append(f"the limit of {max_entries} entries was reached, the rest was not examined")
                        return walk
                    if time.monotonic() > deadline:
                        walk.notes.append("the time budget was reached, the rest was not examined")
                        return walk
                    walk.entries += 1
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            if depth < MAX_DEPTH:
                                queue.append((Path(entry.path), depth + 1))
                        elif entry.is_file(follow_symlinks=False) and file_ext(entry.name) in RISKY_EXTS:
                            st = entry.stat(follow_symlinks=False)
                            key = os.path.normcase(os.path.abspath(entry.path))
                            if st.st_mtime >= since and key not in seen:  # a root can lie inside another
                                seen.add(key)
                                walk.files.append((Path(entry.path), st))
                    except OSError:
                        continue
        except OSError:  # a folder that cannot be listed is skipped
            continue
    return walk


# =========================================================================== findings


def _title(rule_id: str, name: str) -> str:
    return {
        prov.BADSOURCE: f"Download came from a known-malicious site: {name}",
        prov.DECEPTIVE: f"Download with a deceptive file name: {name}",
        prov.SMUGGLED: f"File was built by a web page (HTML smuggling): {name}",
        prov.WEBDAV: f"File came from a WebDAV or network share: {name}",
        prov.RAWIP: f"Program downloaded from a bare IP address: {name}",
        prov.FILEHOST: f"Program downloaded from a file-sharing or paste site: {name}",
        prov.INSECURE: f"Program downloaded over unencrypted http: {name}",
    }.get(rule_id, f"Download with a doubtful origin: {name}")


def _origin_sentence(ev: Dict[str, Any]) -> str:
    if not ev["origin_source"]:
        return "It has no recorded origin."
    bits = [SOURCE_NOTES.get(ev["origin_source"], "its origin is recorded")]
    if ev["agent"]:
        bits.append(f"by {ev['agent']}")
    if ev["host_url"]:
        bits.append(f"download address {ev['host_url']}")
    if ev["referrer_url"]:
        bits.append(f"page that offered it {ev['referrer_url']}")
    return "Origin record: " + ", ".join(bits) + "."


def download_finding(path: Path, st: os.stat_result, origin: Optional[Origin], reasons: Sequence[Reason]) -> Finding:
    """One finding for a file: the strongest reason sets the rule id and the severity, every reason is explained."""
    top = reasons[0]
    name = visible(path.name)
    modified = _iso(st.st_mtime)
    ev = origin_evidence(origin or Origin())
    mitre: List[str] = []
    for reason in reasons:
        mitre += [m for m in reason.mitre if m not in mitre]
    description = (f"{name} is a {file_kind(file_ext(path.name))} last modified {modified[:10] or 'at an unknown time'}. "
                   f"{_origin_sentence(ev)} It was flagged because {'; '.join(r.text for r in reasons)}. {DISCLAIMER}")
    high = top.severity >= Severity.HIGH
    return Finding(
        rule_id=top.rule_id, title=_title(top.rule_id, name), severity=top.severity, category=Category.SUSPICIOUS,
        description=description, location=visible(str(path)),
        evidence={"path": str(path), "file": name, "size": st.st_size, "modified": modified, **ev,
                  "rules": [r.rule_id for r in reasons], "reasons": [r.text for r in reasons]},
        recommendation=RECOMMEND_HIGH if high else RECOMMEND_OTHER,
        remediation=Remediation("quarantine_file", {"path": str(path)}, "Move the file to quarantine (it can be restored)")
        if high else None,
        scanner="downloads", mitre=mitre)


def provenance_check(reviewed: int, with_origin: int, flagged: int, names: Sequence[str], notes: Sequence[str],
                     feed: bool) -> CheckResult:
    detail = f"{reviewed} risky {_plural(reviewed, 'download', 'downloads')} reviewed, {with_origin} with a recorded origin"
    if flagged:
        detail += (f"; {flagged} {_plural(flagged, 'looks', 'look')} suspicious: {', '.join(names[:MAX_NAMES])}"
                   + (", ..." if flagged > MAX_NAMES else ""))
    detail += "."
    if not feed:
        detail += " " + UPDATE_HINT
    if notes:
        detail += " " + "; ".join(n[0].upper() + n[1:] for n in notes) + "."
    return CheckResult(PROVENANCE_ID, PROVENANCE_TITLE, CheckStatus.FAIL if flagged else CheckStatus.PASS, detail,
                       Category.SUSPICIOUS, "downloads")


def review_downloads(ctx: ScanContext) -> Iterator[Emitted]:
    roots = download_roots()
    if not roots:
        yield CheckResult(PROVENANCE_ID, PROVENANCE_TITLE, CheckStatus.SKIP, "There is no Downloads folder or Desktop to review.",
                          Category.SUSPICIOUS, "downloads")
        return
    days = int(ctx.options.get("downloads_days", DEFAULT_DAYS) or DEFAULT_DAYS)
    deadline = time.monotonic() + float(ctx.options.get("downloads_budget_s", BUDGET_S) or BUDGET_S)
    ctx.report("downloads", "listing recent downloads")
    walk = walk_downloads(roots, time.time() - days * 86400, deadline, lambda: ctx.cancelled)
    ctx.bump("downloads_entries", walk.entries)
    if ctx.cancelled:
        return
    is_bad = feed_checker(ctx.signatures)
    reviewed = with_origin = flagged = 0
    names: List[str] = []
    notes = list(walk.notes)
    for path, st in walk.files:
        if ctx.cancelled:
            return
        if time.monotonic() > deadline:
            notes.append("the time budget was reached, the remaining files were not examined")
            break
        reviewed += 1
        try:
            origin = read_origin(path)
        except Exception as exc:  # read_origin does not raise; a stand-in might
            log.debug("could not read the origin of %s: %s", path, exc)
            origin = None
        if origin is not None:
            with_origin += 1
        reasons = classify_download(path.name, origin, is_bad)
        if not reasons:
            continue
        flagged += 1
        if len(names) < MAX_NAMES:
            names.append(visible(path.name))
        if flagged <= MAX_FINDINGS:
            yield download_finding(path, st, origin, reasons)
    if flagged > MAX_FINDINGS:
        notes.append(f"only the first {MAX_FINDINGS} findings are reported")
    ctx.bump("downloads_reviewed", reviewed)
    ctx.bump("downloads_with_origin", with_origin)
    ctx.bump("downloads_flagged", flagged)
    yield provenance_check(reviewed, with_origin, flagged, names, notes, is_bad is not None)


# =========================================================================== Attachment Manager policy (Windows)

POLICY_VALUES = ("SaveZoneInformation", "ScanWithAntiVirus")
POLICY_HIVES = ("HKCU", "HKLM")


def read_attachment_policy(read: Optional[Callable[..., Any]] = None) -> Dict[str, Dict[str, Optional[int]]]:
    """``{hive: {value name: data}}`` of the Attachment Manager policy; the reader is injectable for tests."""
    read = read or reg_read
    return {hive: {value: _to_int(read(hive, ATTACHMENTS_KEY, value)) for value in POLICY_VALUES} for hive in POLICY_HIVES}


def _policy_finding(rule_id: str, hive: str, value: str, title: str, severity: Severity, description: str,
                    recommendation: str, remediation: Optional[Remediation], mitre: List[str]) -> Finding:
    return Finding(
        rule_id=rule_id, title=title, severity=severity, category=Category.SYSTEM, description=description,
        location=f"{hive}\\{ATTACHMENTS_KEY}\\{value}",
        evidence={"hive": hive, "key": ATTACHMENTS_KEY, "value": value, "data": 1}, recommendation=recommendation,
        remediation=remediation, scanner="downloads", mitre=mitre)


def policy_findings(policy: Dict[str, Dict[str, Optional[int]]]) -> List[Finding]:
    out: List[Finding] = []
    for hive in POLICY_HIVES:
        values = policy.get(hive) or {}
        scope = "this user" if hive == "HKCU" else "every user of this PC"
        if values.get("SaveZoneInformation") == 1:
            fix = Remediation("set_registry_value",
                              {"hive": hive, "key": ATTACHMENTS_KEY, "value": "SaveZoneInformation", "data": 2},
                              "Make Windows mark downloaded files again (SaveZoneInformation = 2)")
            out.append(_policy_finding(
                "AEG-DL-MOTW-OFF", hive, "SaveZoneInformation", f"Windows is set not to mark downloaded files ({hive})",
                Severity.MEDIUM,
                f"The Attachment Manager policy SaveZoneInformation is 1 for {scope}. Windows then stops writing the "
                "Mark-of-the-Web on files that come from the internet or from e-mail, so SmartScreen, Office Protected View and "
                "the \"this file came from another computer\" prompt no longer apply to them, and the origin of a download can "
                "no longer be read. Tuning scripts set it to silence the prompts, and malware sets it to avoid them.",
                "Turn the Mark-of-the-Web back on with the fix below (it sets SaveZoneInformation to 2, which preserves zone "
                "information). If a Group Policy enforces the value (\"Do not preserve zone information in file attachments\"), "
                "ask whoever manages this PC. Changing HKLM needs administrator rights.", fix, ["T1553.005"]))
        if values.get("ScanWithAntiVirus") == 1:
            out.append(_policy_finding(
                "AEG-DL-AVSCAN-OFF", hive, "ScanWithAntiVirus",
                f"Windows is set not to ask the antivirus to scan attachments ({hive})", Severity.LOW,
                f"The Attachment Manager policy ScanWithAntiVirus is 1 for {scope}: when a downloaded or e-mailed file is "
                "opened, Windows no longer asks the installed antivirus to scan it. Real-time protection may still catch the "
                "file, but one safety net is switched off.",
                "Set the policy \"Notify antivirus programs when opening attachments\" (Group Policy, Attachment Manager) to "
                "Enabled, or delete the ScanWithAntiVirus value if a tuning script or program you do not know added it.",
                None, ["T1685"]))
    return out


def motw_check(policy: Dict[str, Dict[str, Optional[int]]]) -> CheckResult:
    off = [hive for hive in POLICY_HIVES if (policy.get(hive) or {}).get("SaveZoneInformation") == 1]
    if off:
        detail = (f"The policy SaveZoneInformation is 1 in {' and '.join(off)}: Windows does not mark new downloads, so "
                  "SmartScreen and Office Protected View do not apply to them and their origin cannot be reviewed.")
        return CheckResult(MOTW_ID, MOTW_TITLE, CheckStatus.FAIL, detail, Category.SYSTEM, "downloads")
    return CheckResult(MOTW_ID, MOTW_TITLE, CheckStatus.PASS,
                       "No policy stops Windows from marking downloaded files with their origin (Mark-of-the-Web).",
                       Category.SYSTEM, "downloads")


# =========================================================================== scanner


@register
class DownloadsScanner(Scanner):
    name = "downloads"
    title = "Download origin review"
    description = ("Reviews where recent downloads in Downloads and on the Desktop came from (Mark-of-the-Web, macOS quarantine, "
                   "xattr origin): known-malicious or raw-IP sources, HTML smuggling, WebDAV delivery, file-hosting sites, "
                   "deceptive file names, and the Windows policy that stops downloads being marked.")
    platforms = ("windows", "linux", "darwin")

    def run(self, ctx: ScanContext) -> Iterator[Emitted]:
        ctx.report(self.name, "reviewing where recent downloads came from")
        try:
            yield from review_downloads(ctx)
        except Exception as exc:  # never raise out of run()
            log.warning("download review failed: %s", exc, exc_info=True)
            yield CheckResult(PROVENANCE_ID, PROVENANCE_TITLE, CheckStatus.ERROR, f"{type(exc).__name__}: {exc}",
                              Category.SUSPICIOUS, self.name)
        if not IS_WINDOWS or ctx.cancelled:
            return
        ctx.report(self.name, "checking whether Windows marks downloads")
        try:
            policy = read_attachment_policy()
            yield motw_check(policy)
            yield from policy_findings(policy)
        except Exception as exc:
            log.warning("attachment policy audit failed: %s", exc, exc_info=True)
            yield CheckResult(MOTW_ID, MOTW_TITLE, CheckStatus.ERROR, f"{type(exc).__name__}: {exc}", Category.SYSTEM, self.name)
