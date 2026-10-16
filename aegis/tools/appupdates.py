"""Software updater: which installed apps have updates waiting, and one-command upgrades.

Unpatched browsers, archivers, PDF readers, runtimes and remote-access tools are the usual way in for exploits, so
the software audit lists pending updates and rates them. The data comes from the system's own package manager:

* Windows: ``winget upgrade`` (App Installer). Its output is a fixed-width table; columns are located from the header
  line and the dashed rule under it, so localised headers parse too. A second table lists pinned packages that need
  explicit targeting; those are kept and marked ``explicit``.
* Linux: ``apt list --upgradable`` (``-security`` pockets marked as security updates), ``dnf check-update`` (+ ``dnf
  updateinfo list --security``) or Arch's ``checkupdates``.
* macOS: ``brew outdated --json=v2`` (formulae and casks).

Parsers are pure functions unit-tested on any OS; :func:`collect_updates` takes injectable ``runner`` / ``which``.
Upgrades run the package manager itself (``winget upgrade --id X --exact --silent``, ``apt-get install
--only-upgrade``, ``dnf upgrade``, ``brew upgrade``) - Aegis never downloads installers on its own.
"""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import asdict, dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from aegis.core.models import Category, Finding, Remediation, Severity
from aegis.core.platform import IS_LINUX, IS_MAC, IS_WINDOWS, run

Runner = Callable[..., Tuple[int, str, str]]

WINGET_LIST = ["winget", "upgrade", "--include-unknown", "--accept-source-agreements", "--disable-interactivity"]
# APPINSTALLER_CLI_ERROR_NO_APPLICATIONS_FOUND / _UPDATE_NOT_APPLICABLE: "nothing to upgrade", not a failure
WINGET_NOTHING_CODES = {0x8A150014, 0x8A15002B}
UPGRADE_TIMEOUT_S = 1800
LIST_TIMEOUT_S = 180
MAX_APP_FINDINGS = 25
MAX_EVIDENCE = 200


@dataclass
class Update:
    name: str
    id: str
    installed: str
    available: str
    source: str  # winget | apt | dnf | pacman | brew
    security: bool = False  # the package manager marks it as a security update
    explicit: bool = False  # winget: pinned, upgrades only when targeted explicitly
    cask: bool = False  # brew cask (app) rather than a formula

    @property
    def truncated(self) -> bool:
        return "…" in self.id or "…" in self.name

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# =========================================================================== parsers

def _clean_lines(text: str) -> List[str]:
    # winget draws a spinner with carriage returns before the table; keep what is left after the last one
    return [ln.split("\r")[-1].rstrip() for ln in (text or "").splitlines()]


def _is_rule(line: str) -> bool:
    s = line.strip()
    return len(s) >= 10 and set(s) <= {"-", "─"}


def _looks_like_version(v: str) -> bool:
    return bool(v) and bool(re.search(r"\d", v)) and " " not in v.strip()


def _columns(row: str, starts: Sequence[int]) -> List[str]:
    """Cut a fixed-width row at the header's column starts. A cut that lands inside a word (a row padded one or two
    characters off) moves left to the nearest space, so names and IDs are not split."""
    cuts = [0]
    for b in starts[1:]:
        b = min(b, len(row))
        k = b
        while b - k < 2 and k - 1 > cuts[-1] and k < len(row) and row[k - 1] != " " and row[k] != " ":
            k -= 1  # step back over at most two characters while the cut would split a word
        cuts.append(k if k >= len(row) or row[k - 1] == " " or row[k] == " " else b)
    cuts.append(len(row))
    return [row[a:b].strip() for a, b in zip(cuts, cuts[1:])]


def parse_winget_table(text: str) -> List[Update]:
    """Rows of every table in ``winget upgrade`` output. The first table holds normal upgrades, later ones hold
    pinned packages that need explicit targeting."""
    lines = _clean_lines(text)
    out: List[Update] = []
    table = -1
    i = 0
    while i < len(lines):
        if not (_is_rule(lines[i]) and i > 0 and lines[i - 1].strip()):
            i += 1
            continue
        header = lines[i - 1]
        starts = [m.start() for m in re.finditer(r"\S+", header)]
        i += 1
        if len(starts) < 4:
            continue
        table += 1
        while i < len(lines) and lines[i].strip() and not _is_rule(lines[i]):
            row = lines[i]
            i += 1
            if len(row) <= starts[3]:
                continue
            cols = _columns(row, starts)
            name, ident, installed, available = cols[0], cols[1], cols[2], cols[3]
            source = cols[4] if len(cols) > 4 else ""
            if not name or not ident or " " in ident or not _looks_like_version(available):
                continue
            out.append(Update(name, ident, installed, available, source or "winget", explicit=table > 0))
    return out


_APT = re.compile(r"^(?P<name>[^/\s]+)/(?P<suites>\S+)\s+(?P<new>\S+)\s+\S+\s+\[upgradable from:\s*(?P<old>[^\]]+)\]")


def parse_apt_upgradable(text: str) -> List[Update]:
    out: List[Update] = []
    for ln in _clean_lines(text):
        m = _APT.match(ln.strip())
        if m:
            security = any(s.endswith("-security") or "/updates" in s for s in m.group("suites").split(","))
            out.append(Update(m.group("name"), m.group("name"), m.group("old").strip(), m.group("new"), "apt",
                              security=security))
    return out


def parse_dnf_check_update(text: str, security_names: Sequence[str] = ()) -> List[Update]:
    sec = {s.lower() for s in security_names}
    out: List[Update] = []
    for ln in _clean_lines(text):
        s = ln.strip()
        if not s:
            continue
        if s.lower().startswith(("obsoleting", "security:", "last metadata")):
            if s.lower().startswith("obsoleting"):
                break
            continue
        parts = s.split()
        if len(parts) != 3 or "." not in parts[0] or not _looks_like_version(parts[1]):
            continue
        name = parts[0].rsplit(".", 1)[0]
        out.append(Update(name, name, "", parts[1], "dnf", security=name.lower() in sec))
    return out


def parse_dnf_security(text: str) -> List[str]:
    """Package names from ``dnf updateinfo list --security`` ("ADVISORY  Important/Sec.  name-ver-rel.arch")."""
    names: List[str] = []
    for ln in _clean_lines(text):
        parts = ln.split()
        if len(parts) >= 3 and "/sec" in parts[1].lower():
            nevra = parts[-1].rsplit(".", 1)[0]  # drop .arch
            bits = nevra.rsplit("-", 2)
            if len(bits) == 3:
                names.append(bits[0])
    return names


def parse_checkupdates(text: str) -> List[Update]:
    out: List[Update] = []
    for ln in _clean_lines(text):
        m = re.match(r"^(\S+)\s+(\S+)\s+->\s+(\S+)$", ln.strip())
        if m:
            out.append(Update(m.group(1), m.group(1), m.group(2), m.group(3), "pacman"))
    return out


def parse_brew_outdated(text: str) -> List[Update]:
    try:
        doc = json.loads(text or "{}")
    except ValueError:
        return []
    if not isinstance(doc, dict):
        return []
    out: List[Update] = []
    for kind in ("formulae", "casks"):
        for item in doc.get(kind) or []:
            if not isinstance(item, dict) or not item.get("name"):
                continue
            inst = item.get("installed_versions") or []
            inst_s = ", ".join(map(str, inst)) if isinstance(inst, list) else str(inst)
            out.append(Update(str(item["name"]), str(item["name"]), inst_s, str(item.get("current_version") or ""),
                              "brew", explicit=bool(item.get("pinned")), cask=kind == "casks"))
    return out


# =========================================================================== collection

def collect_updates(runner: Runner = run, which: Callable[[str], Optional[str]] = shutil.which,
                    platform: Optional[str] = None) -> Tuple[str, List[Update], str]:
    """(source, updates, problem). ``source`` is "" when no supported package manager exists; ``problem`` explains
    a failure or why nothing could be checked."""
    plat = platform or ("windows" if IS_WINDOWS else "linux" if IS_LINUX else "darwin" if IS_MAC else "other")
    if plat == "windows":
        if not which("winget"):
            return "", [], ("winget (App Installer) is not available for this account, so pending app updates cannot "
                            "be listed. Install 'App Installer' from the Microsoft Store.")
        rc, out, err = runner(WINGET_LIST, timeout=LIST_TIMEOUT_S)
        updates = parse_winget_table(out)
        nothing = (rc & 0xFFFFFFFF) in WINGET_NOTHING_CODES or bool(re.search(r"(?i)no (installed package|available upgrade|applicable upgrade)", out))
        if rc != 0 and not updates and not nothing:
            return "winget", [], f"winget failed (exit {rc}): {(err or out).strip()[:200]}"
        return "winget", updates, ""
    if plat == "linux":
        if which("apt"):
            rc, out, err = runner(["env", "LC_ALL=C", "apt", "list", "--upgradable"], timeout=LIST_TIMEOUT_S)
            if rc != 0 and not out:
                return "apt", [], f"apt failed: {err.strip()[:200]}"
            return "apt", parse_apt_upgradable(out), ""
        if which("dnf"):
            rc, out, err = runner(["env", "LC_ALL=C", "dnf", "-q", "check-update"], timeout=LIST_TIMEOUT_S)
            if rc not in (0, 100):
                return "dnf", [], f"dnf failed (exit {rc}): {err.strip()[:200]}"
            sec: List[str] = []
            if rc == 100:
                _rc, sout, _err = runner(["env", "LC_ALL=C", "dnf", "-q", "updateinfo", "list", "--security"],
                                         timeout=LIST_TIMEOUT_S)
                sec = parse_dnf_security(sout)
            return "dnf", parse_dnf_check_update(out, sec), ""
        if which("checkupdates"):
            rc, out, err = runner(["checkupdates"], timeout=LIST_TIMEOUT_S)
            if rc not in (0, 2):
                return "pacman", [], f"checkupdates failed (exit {rc}): {err.strip()[:200]}"
            return "pacman", parse_checkupdates(out), ""
        return "", [], "No supported package manager (apt, dnf, checkupdates) was found."
    if plat == "darwin":
        if not which("brew"):
            return "", [], "Homebrew is not installed; App Store and macOS updates are listed by Software Update."
        rc, out, err = runner(["env", "HOMEBREW_NO_AUTO_UPDATE=1", "brew", "outdated", "--json=v2"], timeout=LIST_TIMEOUT_S)
        if rc != 0 and not out.strip():
            return "brew", [], f"brew failed (exit {rc}): {err.strip()[:200]}"
        return "brew", parse_brew_outdated(out), ""
    return "", [], "App update checks are not supported on this OS."


# =========================================================================== risk + commands

# Apps that parse untrusted content or face the network: an outdated copy is a common exploitation route.
HIGH_RISK = [
    ("web browser", r"chrome|chromium|firefox|microsoft\.?edge|\bedge\b|\bbrave\b|\bopera\b|vivaldi|tor ?browser|waterfox|"
                    r"librewolf|thorium|yandex"),
    ("archive tool", r"7-?zip|winrar|peazip|bandizip|winzip|xz-utils|\bxz\b"),
    ("document reader", r"acrobat|adobe reader|foxit|sumatra|libreoffice|openoffice|microsoft office|onlyoffice"),
    ("runtime", r"\bjava\b|\bjre\b|\bjdk\b|temurin|corretto|openjdk|dotnet|\.net (desktop )?runtime|aspnetcore|"
                r"\bpython\b|python3|node\.?js|\bnodejs\b|openssl|libssl|powershell"),
    ("communication app", r"\bzoom\b|\bteams\b|slack|discord|telegram|whatsapp|\bsignal\b|skype|webex|thunderbird"),
    ("remote access / file transfer tool", r"anydesk|teamviewer|rustdesk|vnc|putty|winscp|filezilla|mremoteng|openvpn|"
                                           r"wireguard|forticlient|globalprotect|anyconnect|secure client|openssh|"
                                           r"\bssh\b|openssh-(server|client)"),
    ("media player", r"\bvlc\b|mpc-hc|k-lite|itunes|quicktime"),
    ("server", r"mysql|mariadb|postgres|mongodb|\bredis\b|elasticsearch|tomcat|nginx|apache2|\bhttpd\b|"
               r"apache http server|jenkins|grafana|openssh-server|samba|vsftpd|filezilla server|exim|postfix"),
    ("developer / admin tool", r"notepad\+\+|visual studio code|vscode|\bgit\b|git\.git|docker|virtualbox|vmware|"
                               r"wireshark|keepass|bitwarden|1password|\bsudo\b|polkit|glibc|libc6|curl|libcurl|"
                               r"linux-image|\bkernel\b|systemd|\bbash\b"),
]
_HIGH_RISK_RX = [(label, re.compile(rx, re.I)) for label, rx in HIGH_RISK]


def risk_match(u: Update) -> Optional[Tuple[str, str]]:
    """(category label, matched product name) for a high-risk app, else None."""
    hay = f"{u.name} {u.id}"
    for label, rx in _HIGH_RISK_RX:
        m = rx.search(hay)
        if m:
            return label, m.group(0).strip().lower()
    return None


def risk_label(u: Update) -> Optional[str]:
    m = risk_match(u)
    return m[0] if m else None


def upgrade_command(u: Update) -> Optional[List[str]]:
    """The package-manager command that installs this update, or None when it cannot be targeted safely."""
    if u.truncated:
        return None
    if u.source == "winget":
        return ["winget", "upgrade", "--id", u.id, "--exact", "--silent", "--accept-package-agreements",
                "--accept-source-agreements", "--disable-interactivity"]
    if u.source == "apt":
        return ["apt-get", "install", "--only-upgrade", "-y", u.id]
    if u.source == "dnf":
        return ["dnf", "upgrade", "-y", u.id]
    if u.source == "brew":
        return ["brew", "upgrade"] + (["--cask"] if u.cask else []) + [u.id]
    return None  # pacman: partial upgrades are unsupported, the whole system must be updated (pacman -Syu)


def _manual_hint(source: str) -> str:
    return {"winget": "winget upgrade --all", "apt": "sudo apt update && sudo apt upgrade", "dnf": "sudo dnf upgrade",
            "pacman": "sudo pacman -Syu", "brew": "brew upgrade"}.get(source, "your package manager")


PER_APP_SOURCES = ("winget", "brew")  # one package = one app; Linux distros split apps into many packages


def _notable(updates: Sequence[Update], limit: int = 8) -> List[str]:
    names: List[str] = []
    for u in sorted(updates, key=lambda x: (not x.security, x.name.lower())):
        m = risk_match(u)
        if m:
            family = m[1] if u.source in ("apt", "dnf", "pacman") else u.name
            if family not in names:
                names.append(family)
        if len(names) >= limit:
            break
    return names


def update_findings(source: str, updates: Sequence[Update]) -> List[Finding]:
    """Findings for pending updates.

    winget / brew: one MEDIUM finding per outdated high-risk app (capped) plus one summary for everything else.
    apt / dnf / pacman: a single summary (MEDIUM when security updates are pending) naming the notable packages.
    Locations are ``updates:<source>[:<id>]`` so a finding keeps its fingerprint when the next version comes out."""
    out: List[Finding] = []
    rest: List[Update] = []
    for u in updates:
        label = risk_label(u) if source in PER_APP_SOURCES else None
        if not label or len(out) >= MAX_APP_FINDINGS:
            rest.append(u)
            continue
        cmd = upgrade_command(u)
        sec = " The package manager marks it as a security update." if u.security else ""
        frm = f" {u.installed}" if u.installed and u.installed.lower() != "unknown" else ""
        out.append(Finding(
            "AEG-SW-UPDATE", f"Update available for {u.name}: {u.available}", Severity.MEDIUM, Category.VULNERABILITY,
            f"{u.name}{frm} is out of date; version {u.available} is available from {source}. As a {label}, it handles "
            f"untrusted files or network data, and exploits for fixed bugs are often published soon after a release."
            + sec,
            f"updates:{source}:{u.id}", u.to_dict(),
            f"Install the update ({' '.join(cmd) if cmd else _manual_hint(source)}), or use `aegis apps upgrade "
            f"{u.id}`. Restart the app afterwards so the new version is the one running.",
            Remediation("run_command", {"command": cmd, "timeout": UPGRADE_TIMEOUT_S}, f"Update {u.name} to {u.available}")
            if cmd else None,
            mitre=["T1190", "T1203"]))
    if rest:
        security = [u for u in rest if u.security]
        sev = Severity.MEDIUM if security else Severity.LOW
        noun = "app(s)" if source in PER_APP_SOURCES else "package(s)"
        what = f"{len(rest)} other installed {noun}" if out else f"{len(rest)} installed {noun}"
        sec_txt = f", {len(security)} of them security updates," if security else ""
        notable = _notable(rest)
        note = f" Notable: {', '.join(notable)}." if notable else ""
        out.append(Finding(
            "AEG-SW-UPDATES", f"{what} have updates available" + (f" ({len(security)} security)" if security else ""),
            sev, Category.VULNERABILITY,
            f"{what}{sec_txt} can be updated with {source}. Keeping software current closes known vulnerabilities."
            + note,
            f"updates:{source}", {"source": source, "count": len(rest), "security_updates": len(security),
                                  "notable": notable,
                                  "updates": [u.to_dict() for u in sorted(rest, key=lambda x: (not x.security, x.name.lower()))
                                              [:MAX_EVIDENCE]]},
            f"Run `{_manual_hint(source)}` (or `aegis apps upgrade --all`) to install them.",
            mitre=["T1190"]))
    return out
