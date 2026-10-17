"""Self-check ("doctor"): is Aegis itself set up so that it actually protects this machine?

``doctor(config)`` returns a list of :class:`DoctorCheck` (a ``CheckResult`` plus ``severity``, plain-English ``fix``
text and an optional ``fix_id`` that :func:`apply_fixes` knows how to apply):

  DOC-ADMIN     running with administrator / root rights
  DOC-RUNTIME   packaged build or Python version
  DOC-DATADIR   data folder exists and is writable
  DOC-ACL       standard users cannot tamper with config.json (allow-list), signatures or quarantine
  DOC-SIGS      signature freshness (update_state.json): warn > 3 days, fail > 14 days
  DOC-YARA      yara-python available            DOC-YARA-RULES  rules loaded
  DOC-PYYAML    PyYAML available (Sigma rules)
  DOC-SERVICE   scheduled tasks / systemd units installed
  DOC-MONITOR   real-time monitor alive (heartbeat file written every 30 s by the monitor)
  DOC-AV        Microsoft Defender / other antivirus active (Windows)
  DOC-DISK      free disk space for the quarantine
  DOC-HISTORY   scan history database      DOC-SCANAGE  how long ago the last scan ran
  DOC-ALERTS    alert channels configured and valid

Why the ACL check matters: the allow-list lives in ``config.json``. If a standard user (or malware running as one)
can write that file, malware can simply allow-list itself. On Windows the data folder is %ProgramData%\\Aegis when
Aegis runs elevated; the ACL it inherits from %ProgramData% often lets *Users* create files in it, which is enough to
plant signature-override rules. The fix is a safe ACL: Administrators + SYSTEM full control, Users read & execute.

Everything is best effort and locale independent: ACLs are read through PowerShell ``Get-Acl`` with SIDs (falling
back to parsing ``icacls`` output), services through ``schtasks`` / ``systemctl`` exit codes. A check that crashes is
reported as an ERROR result - ``doctor()`` itself never raises.
"""

from __future__ import annotations

import datetime as dt
import importlib.util
import json
import logging
import os
import re
import shutil
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from aegis import __app_name__, __version__
from aegis.core.models import CheckResult, CheckStatus
from aegis.core.platform import IS_LINUX, IS_MAC, IS_WINDOWS, as_list, is_admin, powershell_json, run

log = logging.getLogger("aegis.doctor")

HEARTBEAT_FILE = "monitor.heartbeat"
HEARTBEAT_INTERVAL_S = 30.0
HEARTBEAT_STALE_S = 90.0  # three missed beats

SIG_WARN_DAYS = 3
SIG_FAIL_DAYS = 14
SCAN_WARN_DAYS = 7
DISK_FAIL_MB = 200
DISK_WARN_MB = 1024


@dataclass
class DoctorCheck(CheckResult):
    """A ``CheckResult`` with the information a self-check needs on top."""

    severity: str = "info"  # impact if the check fails: info | low | medium | high
    fix: str = ""  # plain-English remedy
    fix_id: str = ""  # "acl" | "perms" | "update" when `apply_fixes` can do it automatically ("" = manual)


def _chk(check_id: str, title: str, status: str, detail: str = "", severity: str = "info", fix: str = "",
         fix_id: str = "") -> DoctorCheck:
    return DoctorCheck(check_id=check_id, title=title, status=status, detail=detail, scanner="doctor",
                       severity=severity, fix=fix, fix_id=fix_id)


# =========================================================================== heartbeat (written by the monitor)

def heartbeat_path(config: Any) -> Path:
    return Path(config.home) / HEARTBEAT_FILE


def write_heartbeat(config: Any, started: Optional[float] = None, components: Sequence[str] = (),
                    guards: Optional[Dict[str, str]] = None) -> bool:
    """Called by the real-time monitor every 30 s, with the state of guards that can be degraded (``guards``). Atomic
    where the OS allows it. Never raises."""
    path = heartbeat_path(config)
    data = json.dumps({"pid": os.getpid(), "time": time.time(), "started": started, "components": list(components),
                       "guards": dict(guards or {}), "version": __version__})
    try:
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(data, encoding="utf-8")
        os.replace(tmp, path)
        return True
    except OSError:
        try:  # e.g. Windows sharing violation while a reader has the file open
            path.write_text(data, encoding="utf-8")
            return True
        except OSError as exc:
            log.debug("could not write heartbeat: %s", exc)
            return False


def clear_heartbeat(config: Any) -> None:
    """Remove the heartbeat on a clean stop - but only our own, never another process's."""
    path = heartbeat_path(config)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if int(data.get("pid", -1)) != os.getpid():
            return
        path.unlink()
    except (OSError, ValueError, TypeError):
        pass


def read_heartbeat(config: Any) -> Optional[Dict[str, Any]]:
    path = heartbeat_path(config)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError
    except OSError:
        return None
    except ValueError:
        data = {}
    if not isinstance(data.get("time"), (int, float)):
        try:
            data["time"] = path.stat().st_mtime
        except OSError:
            return None
    return data


# =========================================================================== ACL analysis

# Well-known SIDs. Standard (non-admin) principals must not be able to modify Aegis' data.
STANDARD_SIDS = {
    "S-1-1-0": "Everyone", "S-1-5-11": "Authenticated Users", "S-1-5-32-545": "Users", "S-1-5-4": "Interactive",
    "S-1-5-32-546": "Guests", "S-1-5-32-547": "Power Users", "S-1-5-7": "Anonymous", "S-1-5-2": "Network",
    "S-1-5-32-554": "Pre-Windows 2000 Compatible Access",
}
TRUSTED_SIDS = {"S-1-5-18": "SYSTEM", "S-1-5-32-544": "Administrators", "S-1-3-0": "CREATOR OWNER", "S-1-5-19": "LOCAL SERVICE",
                "S-1-5-20": "NETWORK SERVICE", "S-1-3-4": "OWNER RIGHTS"}
TRUSTED_INSTALLER_PREFIX = "S-1-5-80-"
_DOMAIN_STANDARD_RIDS = ("513", "514", "515")  # Domain Users / Guests / Computers

# English principal names as printed by icacls -> SID. Localised names cannot be mapped (best effort).
_NAME_TO_SID = {
    "everyone": "S-1-1-0", "nt authority\\authenticated users": "S-1-5-11", "builtin\\users": "S-1-5-32-545",
    "nt authority\\interactive": "S-1-5-4", "builtin\\guests": "S-1-5-32-546", "builtin\\power users": "S-1-5-32-547",
    "nt authority\\anonymous logon": "S-1-5-7", "nt authority\\network": "S-1-5-2",
    "nt authority\\system": "S-1-5-18", "builtin\\administrators": "S-1-5-32-544", "creator owner": "S-1-3-0",
    "nt authority\\local service": "S-1-5-19", "nt authority\\network service": "S-1-5-20",
    "nt service\\trustedinstaller": TRUSTED_INSTALLER_PREFIX + "956008885-3418522649-1831038044-1853292631-2271478464",
}

# FileSystemRights bits that let a principal change a file or folder (or gain that ability)
_FS_WRITE_BITS = 0x2 | 0x4 | 0x40 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000
# icacls rights tokens with the same meaning (F full, M modify, W write, D delete, WD/AD create/append, DC delete
# child, DE delete, WDAC change permissions, WO take ownership, GW/GA generic write/all, MA maximum allowed)
_ICACLS_WRITE = {"F", "M", "W", "D", "WD", "AD", "DC", "DE", "WDAC", "WO", "GW", "GA", "MA"}
_ICACLS_STRONG = {"F", "M", "D", "DC", "DE", "WDAC", "WO", "GA", "MA"}
_ICACLS_READ = {"F", "M", "R", "RX", "RD", "GR", "GA", "MA"}
_FS_STRONG_BITS = 0x40 | 0x10000 | 0x40000 | 0x80000 | 0x10000000
_ICACLS_ACE = re.compile(r"^\s*(?P<who>.+?):(?P<perms>(?:\([^()]*\))+)\s*$")


@dataclass
class AclEntry:
    who: str
    sid: str = ""
    allow: bool = True
    write: bool = False  # any way to modify the object (create/append/delete/change permissions ...)
    inherit_only: bool = False  # applies to children only, not to the object itself
    strong: bool = False  # delete / change permissions / take ownership / full control (more than "create files")
    read: bool = False  # can read the object's contents

    @property
    def standard_user(self) -> bool:
        sid = self.sid or _NAME_TO_SID.get(self.who.lower(), "")
        if sid in STANDARD_SIDS:
            return True
        if sid.startswith("S-1-5-21-") and sid.rsplit("-", 1)[-1] in _DOMAIN_STANDARD_RIDS:
            return True
        low = self.who.lower()
        return not sid and low.rsplit("\\", 1)[-1] in ("domain users", "domain guests", "domain computers")

    @property
    def key(self) -> str:
        return (self.sid or self.who).lower()


def _strip_icacls_path(line: str, path: str) -> str:
    """Remove the leading path from the first icacls output line (the principal follows it)."""
    low = line.lower()
    for prefix in (path, '"' + path + '"'):
        if path and low.startswith(prefix.lower()):
            return line[len(prefix):]
    # Unknown path: take the first split whose remainder is "<principal>:(perms)" with a recognisable principal.
    for m in re.finditer(r"\s+", line):
        rest = line[m.end():]
        ace = _ICACLS_ACE.match(rest)
        if ace:
            who = ace.group("who").strip().lower()
            if who in _NAME_TO_SID or who.rsplit("\\", 1)[-1] in ("domain users", "domain guests", "domain computers"):
                return rest
    return line


def parse_icacls(text: str, path: str = "") -> List[AclEntry]:
    """Parse the output of ``icacls <path>``.

    The first line is ``<path> <principal>:<perms>``; following lines are indented ``<principal>:<perms>``; a
    summary line ("Successfully processed ...", localised) ends the output. Rights are ``(F)``, ``(M)``, ``(RX)``,
    ``(R)``, ``(W)``, ``(D)`` or specific comma lists such as ``(RD,WD,AD)``; flags ``(I)``, ``(OI)``, ``(CI)``,
    ``(IO)``, ``(NP)`` and ``(DENY)`` may precede them. Pass ``path`` so the first line can be split reliably."""
    entries: List[AclEntry] = []
    first = True
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if first:
            first = False
            line = _strip_icacls_path(line, path)
        m = _ICACLS_ACE.match(line)
        if not m:
            continue
        who, groups = m.group("who").strip(), re.findall(r"\(([^()]*)\)", m.group("perms"))
        flags = {g.upper() for g in groups if g.upper() in ("I", "OI", "CI", "IO", "NP")}
        deny = any(g.upper() == "DENY" for g in groups)
        rights = {t.strip().upper() for g in groups if g.upper() not in flags | {"DENY"} for t in g.split(",")}
        entries.append(AclEntry(who=who, sid=_NAME_TO_SID.get(who.lower(), ""), allow=not deny,
                                write=bool(rights & _ICACLS_WRITE), inherit_only="IO" in flags,
                                strong=bool(rights & _ICACLS_STRONG), read=bool(rights & _ICACLS_READ)))
    return entries


def parse_acl_json(items: Any) -> List[AclEntry]:
    """Parse the ``acl`` array produced by the PowerShell script: dicts with sid, name, type, rights, inherit_only."""
    entries: List[AclEntry] = []
    for it in as_list(items):
        if not isinstance(it, dict):
            continue
        try:
            rights = int(it.get("rights", 0))
        except (TypeError, ValueError):
            rights = 0
        entries.append(AclEntry(who=str(it.get("name") or it.get("sid") or "?"), sid=str(it.get("sid") or ""),
                                allow=str(it.get("type", "Allow")).lower() != "deny",
                                write=bool(rights & _FS_WRITE_BITS), inherit_only=bool(it.get("inherit_only")),
                                strong=bool(rights & _FS_STRONG_BITS), read=bool(rights & 0x1)))
    return entries


def write_exposure(entries: Sequence[AclEntry], strong_only: bool = False) -> List[str]:
    """Standard-user principals that can modify the object (explicit deny entries are honoured).

    ``strong_only`` ignores plain "create files / append" rights - used for the data folder itself, where Windows'
    default ProgramData ACL hands Users exactly that, which cannot touch an existing config.json."""
    def hit(e: AclEntry) -> bool:
        return e.strong if strong_only else e.write

    denied = {e.key for e in entries if not e.allow and hit(e)}
    return sorted({e.who for e in entries if e.allow and hit(e) and not e.inherit_only and e.standard_user
                   and e.key not in denied})


def read_exposure(entries: Sequence[AclEntry]) -> List[str]:
    """Standard-user principals that can read the object (used for files that hold credentials)."""
    denied = {e.key for e in entries if not e.allow and e.read}
    return sorted({e.who for e in entries if e.allow and e.read and not e.inherit_only and e.standard_user
                   and e.key not in denied})


def _ps_quote(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def _acl_script(paths: Sequence[Path]) -> str:
    plist = ",".join(_ps_quote(str(p)) for p in paths)
    return (
        "$ErrorActionPreference='SilentlyContinue';$r=@();"
        f"foreach($p in @({plist}))" "{"
        "$e=@();try{$a=Get-Acl -LiteralPath $p -ErrorAction Stop;foreach($x in $a.Access){$sid='';"
        "try{$sid=$x.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value}catch{$sid=''};"
        "$e+=[pscustomobject]@{sid=[string]$sid;name=[string]$x.IdentityReference;type=[string]$x.AccessControlType;"
        "rights=[int64]$x.FileSystemRights;inherit_only=[bool](([int]$x.PropagationFlags -band 2) -ne 0)}};"
        "$r+=[pscustomobject]@{path=$p;ok=$true;acl=$e}}catch{$r+=[pscustomobject]@{path=$p;ok=$false}}};"
        "ConvertTo-Json -InputObject $r -Depth 5 -Compress")


def _windows_acls(paths: Sequence[Path]) -> Dict[str, Optional[List[AclEntry]]]:
    """path -> ACL entries (None when unreadable). PowerShell Get-Acl with SIDs first (locale independent),
    ``icacls`` parsing as the fallback."""
    out: Dict[str, Optional[List[AclEntry]]] = {str(p): None for p in paths}
    data = powershell_json(_acl_script(paths))
    for item in as_list(data):
        if isinstance(item, dict) and item.get("ok") and str(item.get("path")) in out:
            out[str(item["path"])] = parse_acl_json(item.get("acl"))
    for p in paths:
        if out[str(p)] is None:
            rc, text, _err = run([shutil.which("icacls") or "icacls", str(p)], timeout=30)
            if rc == 0 and text.strip():
                out[str(p)] = parse_icacls(text, str(p))
    return out


def _acl_targets(config: Any) -> List[Path]:
    sig = Path(config.signatures_dir)
    cands = [Path(config.path), sig, sig / "rules", sig / "yara", Path(config.quarantine_dir), Path(config.home)]
    seen, out = set(), []
    for p in cands:
        if p.exists() and str(p) not in seen:
            seen.add(str(p))
            out.append(p)
    return out


def _acl_label(config: Any, p: Path) -> str:
    home = Path(config.home)
    if p == home:
        return "data folder"
    try:
        return str(p.relative_to(home)).replace("\\", "/")
    except ValueError:
        return str(p)


def _secret_config_fields(config: Any) -> List[str]:
    from aegis.core.alerts import SECRET_FIELDS

    names = list(SECRET_FIELDS) + ["virustotal_api_key", "abusech_auth_key", "google_safebrowsing_api_key"]
    return [n for n in names if str(getattr(config, n, "") or "").strip()]


def check_acl(config: Any) -> DoctorCheck:
    title = "Only administrators can change Aegis' settings, allow-list and signatures"
    if IS_WINDOWS:
        targets = _acl_targets(config)
        acls = _windows_acls(targets)
        readable = {p: e for p, e in acls.items() if e is not None}
        if not readable:
            return _chk("DOC-ACL", title, CheckStatus.SKIP, "Could not read the folder permissions (PowerShell and icacls "
                        "were unavailable or access was denied).", "low")
        exposed: Dict[str, List[str]] = {}
        home = Path(config.home)
        for p in targets:
            entries = readable.get(str(p))
            if entries is None:
                continue
            who = write_exposure(entries, strong_only=(p == home))
            if who:
                exposed[_acl_label(config, p)] = who
        if exposed:
            lines = "; ".join(f"{k}: {', '.join(v)}" for k, v in exposed.items())
            return _chk(
                "DOC-ACL", title, CheckStatus.FAIL,
                f"Standard users can write to: {lines}. Malware running without administrator rights could add itself to "
                f"the allow-list (config.json) or plant detection-override rules in the signatures folder. ({config.home})",
                "medium",
                f"Run `aegis doctor --fix` as Administrator. It gives Administrators and SYSTEM full control and Users "
                f"read & execute only on {config.home} (icacls, inheritance removed).", "acl")
        secrets = _secret_config_fields(config)
        cfg_entries = readable.get(str(Path(config.path)))
        readers = read_exposure(cfg_entries) if (secrets and cfg_entries) else []
        if readers:
            return _chk("DOC-ACL", title, CheckStatus.WARN,
                        f"config.json holds credentials ({', '.join(secrets)}) and can be read by: {', '.join(readers)}.", "low",
                        "Run `aegis doctor --fix` as Administrator: it restricts config.json to Administrators and SYSTEM. "
                        "Setting AEGIS_SMTP_PASSWORD keeps the SMTP password off disk.", "acl")
        place = "per-user" if _is_user_profile(Path(config.home)) else "machine-wide"
        return _chk("DOC-ACL", title, CheckStatus.PASS, f"No standard-user write access found ({place} data folder {config.home}).")
    if IS_MAC or IS_LINUX or os.name == "posix":
        return _check_posix_perms(config, title)
    return _chk("DOC-ACL", title, CheckStatus.SKIP, "Permission check is not available on this OS.")


def _is_user_profile(p: Path) -> bool:
    la = os.environ.get("LOCALAPPDATA") or ""
    if not la:
        return False
    return os.path.normcase(str(p)).startswith(os.path.normcase(la).rstrip("\\/") + os.sep)


def _check_posix_perms(config: Any, title: str) -> DoctorCheck:
    problems = posix_permission_problems(config)
    secrets = _secret_config_fields(config)
    unsafe = [p for p in problems if p[2] != "readable"]
    leaky = [p for p in problems if p[2] == "readable"]
    if unsafe:
        lines = "; ".join(f"{_acl_label(config, p)} ({why})" for p, _m, why in unsafe)
        return _chk("DOC-ACL", title, CheckStatus.FAIL,
                    f"Other users could change Aegis' data: {lines}. A local attacker could add malware to the allow-list "
                    f"or override detection rules. ({config.home})", "medium",
                    "Run `aegis doctor --fix` (removes group/other write permission), or: chmod -R go-w " + str(config.home), "perms")
    if leaky:
        return _chk("DOC-ACL", title, CheckStatus.WARN,
                    "config.json contains credentials (" + ", ".join(secrets) + ") and is readable by other users.", "low",
                    f"Run `aegis doctor --fix` or: chmod 600 {config.path}", "perms")
    return _chk("DOC-ACL", title, CheckStatus.PASS, f"Data folder permissions look safe ({config.home}).")


def posix_permission_problems(config: Any) -> List[Tuple[Path, int, str]]:
    """[(path, mode, why)] where why is 'group/other writable', 'owned by uid N' or 'readable' (secrets in config.json)."""
    out: List[Tuple[Path, int, str]] = []
    secrets = bool(_secret_config_fields(config))
    me = os.geteuid() if hasattr(os, "geteuid") else 0
    for p in _acl_targets(config):
        try:
            st = os.stat(p)
        except OSError:
            continue
        mode = st.st_mode & 0o777
        if mode & 0o022:
            out.append((p, mode, "group/other writable"))
        elif st.st_uid not in (me, 0):
            out.append((p, mode, f"owned by uid {st.st_uid}"))
        elif secrets and p == Path(config.path) and mode & 0o044:
            out.append((p, mode, "readable"))
    return out


# --------------------------------------------------------------------------- applying a safe ACL

_PROTECTED_DIR_ENVS = ("SystemRoot", "WINDIR", "ProgramData", "ProgramFiles", "ProgramFiles(x86)", "USERPROFILE", "PUBLIC",
                       "APPDATA", "LOCALAPPDATA", "TEMP", "TMP", "SystemDrive", "HOMEDRIVE")


def _norm_path(p: Any) -> str:
    return os.path.normcase(os.path.abspath(str(p))).rstrip("\\/")


def _safe_acl_target(path: Path) -> Tuple[bool, str]:
    """Refuse to rewrite the ACL of anything that is not clearly Aegis' own data folder (a recursive
    permission reset on a drive root, %ProgramData% or C:\\Users would be catastrophic)."""
    norm = _norm_path(path)
    if not os.path.splitdrive(norm)[1].strip("\\/"):
        return False, "refusing to change the permissions of a drive root"
    for var in _PROTECTED_DIR_ENVS:
        val = os.environ.get(var)
        if not val:
            continue
        prot = _norm_path(val)
        if prot == norm or prot.startswith(norm + os.sep) or prot.startswith(norm + "\\"):
            return False, f"refusing to change the permissions of %{var}% or a folder that contains it"
    looks_like_aegis = (path / "config.json").exists() or (path / "signatures").exists() or (path / "quarantine").exists() \
        or path.name.lower().startswith("aegis")
    if not looks_like_aegis:
        return False, "this folder does not look like an Aegis data folder"
    return True, ""


def apply_safe_acl(path: Path, runner: Optional[Callable[..., Tuple[int, str, str]]] = None,
                   lock_config: bool = False) -> Tuple[bool, str]:
    """Windows: Administrators + SYSTEM full control, Users read & execute, inheritance from the parent removed.

    With ``lock_config`` (the config holds webhook URLs / an SMTP password) config.json is additionally restricted to
    Administrators + SYSTEM so other users cannot read those credentials.

    Uses SIDs (``*S-1-5-18`` ...) so it works on every Windows language. Order matters: grant first, then drop
    inherited entries, then re-inherit below - the folder is never left without a usable ACL."""
    if not IS_WINDOWS:
        return False, "the ACL fix only applies to Windows"
    runner = runner or run
    if not is_admin():
        return False, "run Aegis as Administrator to change folder permissions"
    ok, why = _safe_acl_target(path)
    if not ok:
        return False, why
    icacls = shutil.which("icacls") or "icacls"
    p = str(path)
    steps: List[Tuple[str, List[str], bool]] = [
        ("grant Administrators + SYSTEM full control, Users read & execute",
         [icacls, p, "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX"], True),
        ("remove explicit entries of broad groups",
         [icacls, p, "/remove:g", "*S-1-5-11", "*S-1-1-0", "*S-1-5-4", "*S-1-5-32-547"], False),
        ("stop inheriting permissions from the parent folder", [icacls, p, "/inheritance:r"], True),
        ("re-apply inheritance to everything inside", [icacls, p + "\\*", "/reset", "/T", "/C", "/Q"], False),
    ]
    cfg_file = path / "config.json"
    if lock_config and cfg_file.exists():  # after the reset above, which would re-inherit "Users: read"
        steps += [("keep credentials in config.json private", [icacls, str(cfg_file), "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F"], False),
                  ("stop config.json inheriting 'Users: read'", [icacls, str(cfg_file), "/inheritance:r"], False)]
    notes: List[str] = []
    for label, cmd, required in steps:
        rc, out, err = runner(cmd, timeout=120)
        if rc != 0:
            if required:
                return False, f"could not {label}: {(err or out).strip()[:200]}"
            notes.append(f"{label}: skipped ({(err or out).strip()[:80]})")
    return True, f"permissions on {p} hardened" + (f" ({'; '.join(notes)})" if notes else "")


def apply_posix_perms(config: Any) -> Tuple[bool, str]:
    """POSIX fix: strip group/other write everywhere and make config.json owner-only when it holds credentials."""
    changed: List[str] = []
    try:
        for p, mode, why in posix_permission_problems(config):
            if why == "readable":
                os.chmod(p, 0o600)
            elif "writable" in why:
                os.chmod(p, mode & ~0o022)
            else:
                continue  # wrong owner: only root could chown, and guessing the right owner is unsafe
            changed.append(_acl_label(config, p))
        return True, ("fixed permissions on " + ", ".join(changed)) if changed else "nothing to change"
    except OSError as exc:
        return False, f"could not change permissions: {exc}"


# =========================================================================== individual checks

def check_admin(config: Any) -> DoctorCheck:
    title = "Running with administrator rights"
    if is_admin():
        return _chk("DOC-ADMIN", title, CheckStatus.PASS, "Aegis is running as " + ("Administrator." if IS_WINDOWS else "root."))
    how = "Right-click Aegis and choose 'Run as administrator'." if IS_WINDOWS else "Run Aegis with sudo."
    return _chk("DOC-ADMIN", title, CheckStatus.WARN,
                "Not elevated: services, drivers, firewall and other users' processes cannot be fully checked, and the "
                "data folder is per-user instead of machine-wide.", "low", how)


def check_runtime(config: Any) -> DoctorCheck:
    title = "Python runtime"
    bits = "64-bit" if sys.maxsize > 2 ** 32 else "32-bit"
    py = ".".join(str(x) for x in sys.version_info[:3])
    if getattr(sys, "frozen", False):
        return _chk("DOC-RUNTIME", title, CheckStatus.PASS, f"{__app_name__} {__version__}: packaged executable "
                    f"(bundled Python {py}, {bits}).")
    if sys.version_info < (3, 9):
        return _chk("DOC-RUNTIME", title, CheckStatus.FAIL, f"Python {py} is too old for {__app_name__} {__version__}.", "high",
                    "Install Python 3.9 or newer.")
    return _chk("DOC-RUNTIME", title, CheckStatus.PASS, f"{__app_name__} {__version__} running from source on Python {py} "
                f"({bits}, {sys.executable}).")


def check_datadir(config: Any) -> DoctorCheck:
    title = "Data folder is writable"
    home = Path(config.home)
    probe = home / f".doctor-{os.getpid()}.tmp"
    try:
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
    except OSError as exc:
        return _chk("DOC-DATADIR", title, CheckStatus.FAIL, f"Aegis cannot write to {home}: {exc}. Scan history, quarantine, "
                    "signature updates and settings will not be saved.", "high",
                    "Fix the folder permissions, run Aegis as Administrator, or point AEGIS_HOME at a folder you own.")
    return _chk("DOC-DATADIR", title, CheckStatus.PASS, f"{home}")


def _parse_ts(value: Any) -> Optional[dt.datetime]:
    try:
        t = dt.datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    return t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)


def check_signatures(config: Any, now: Optional[float] = None) -> DoctorCheck:
    from aegis.core.config import shared_signatures_dir

    title = "Threat signatures are up to date"
    now_dt = dt.datetime.fromtimestamp(now if now is not None else time.time(), dt.timezone.utc)
    dirs = [Path(config.signatures_dir)]
    shared = shared_signatures_dir()
    if shared and shared not in dirs:
        dirs.append(shared)
    newest: Optional[dt.datetime] = None
    failed: List[str] = []
    seen_state = False
    for d in dirs:
        try:
            state = json.loads((d / "update_state.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(state, dict):
            continue
        seen_state = True
        feeds = state.get("feeds") if isinstance(state.get("feeds"), dict) else {}
        for name, info in feeds.items():
            if not isinstance(info, dict):
                continue
            t = _parse_ts(info.get("updated"))
            if t and (newest is None or t > newest):
                newest = t
            if info.get("ok") is False and info.get("error") and "skipped" not in str(info.get("error")):
                failed.append(str(name))
    fix = ("Run `aegis update` (or Tools > Signature update). `aegis install-service` schedules an update every 6 hours."
           + (" If it keeps failing, add your free abuse.ch Auth-Key (abusech_auth_key)." if failed else ""))
    if newest is None:
        why = "were never downloaded" if not seen_state else "have never been downloaded successfully"
        return _chk("DOC-SIGS", title, CheckStatus.WARN, f"Fresh threat feeds {why}; only the signatures bundled with Aegis are "
                    "in use." + (f" Failing feeds: {', '.join(sorted(set(failed)))}." if failed else ""), "medium", fix, "update")
    age = (now_dt - newest).total_seconds() / 86400.0
    detail = f"Last successful update {age:.1f} day(s) ago ({newest:%Y-%m-%d %H:%M} UTC)."
    if failed:
        detail += f" Feeds that failed on the last run: {', '.join(sorted(set(failed)))}."
    if age > SIG_FAIL_DAYS:
        return _chk("DOC-SIGS", title, CheckStatus.FAIL, detail + " New malware families will be missed.", "high", fix, "update")
    if age > SIG_WARN_DAYS:
        return _chk("DOC-SIGS", title, CheckStatus.WARN, detail, "medium", fix, "update")
    return _chk("DOC-SIGS", title, CheckStatus.PASS, detail)


def _yara_info() -> Tuple[bool, str]:
    try:
        from aegis.core import signatures

        if not signatures.HAVE_YARA:
            return False, ""
        return True, str(getattr(signatures.yara, "__version__", "") or "")
    except Exception:
        return False, ""


def _have_module(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def check_yara_engine(config: Any) -> DoctorCheck:
    title = "YARA engine (yara-python)"
    ok, ver = _yara_info()
    if ok:
        return _chk("DOC-YARA", title, CheckStatus.PASS, f"yara-python {ver}".strip())
    return _chk("DOC-YARA", title, CheckStatus.WARN, "yara-python is not installed, so only Aegis' built-in rule engine runs "
                "(community YARA rules from `aegis update` are not used).", "low", "Run: pip install yara-python")


def check_pyyaml(config: Any) -> DoctorCheck:
    title = "PyYAML (Sigma rules)"
    if _have_module("yaml"):
        return _chk("DOC-PYYAML", title, CheckStatus.PASS, "PyYAML is installed.")
    return _chk("DOC-PYYAML", title, CheckStatus.WARN, "PyYAML is missing, so Sigma rule files (YAML) cannot be loaded.", "low",
                "Run: pip install pyyaml")


def _signature_db(config: Any) -> Any:
    from aegis.core.signatures import SignatureDB

    return SignatureDB(config)


def check_yara_rules(config: Any, signatures: Any = None) -> DoctorCheck:
    title = "Detection rules are loaded"
    db = signatures if signatures is not None else _signature_db(config)
    have, _ver = _yara_info()
    lite = len(getattr(db, "rules", []) or [])
    files = int(getattr(db, "yara_count", 0) or 0)
    if not have:
        return _chk("DOC-YARA-RULES", title, CheckStatus.PASS if lite else CheckStatus.WARN,
                    f"{lite} built-in content rule(s); YARA rules are inactive without yara-python.", "low" if not lite else "info",
                    "" if lite else "Reinstall Aegis: the bundled rule files are missing.")
    n_rules = 0
    try:
        n_rules = sum(1 for _ in db.yara_rules) if getattr(db, "yara_rules", None) is not None else 0
    except Exception:
        n_rules = 0
    if files == 0:
        return _chk("DOC-YARA-RULES", title, CheckStatus.FAIL, "No YARA rule file could be loaded even though yara-python is "
                    "installed (a compile error or missing data folder).", "medium",
                    "Run `aegis update`; if it persists run `aegis info` and check the log for 'skipping YARA file'.")
    return _chk("DOC-YARA-RULES", title, CheckStatus.PASS,
                f"{files} YARA rule file(s)" + (f" with {n_rules} rule(s)" if n_rules else "") + f" and {lite} built-in content rule(s).")


def check_service(config: Any) -> DoctorCheck:
    from aegis.core import service

    title = "Background protection is installed"
    fix = "Run `aegis install-service` (as Administrator on Windows) to register real-time protection, a daily quick scan and signature updates."
    states: Dict[str, bool] = {}
    note = ""
    if IS_WINDOWS:
        for name in service.ALL_TASKS:
            rc, out, _err = run(["schtasks", "/Query", "/TN", name, "/XML"], timeout=30)
            m = re.search(r"<Settings>.*?<Enabled>\s*(true|false)\s*</Enabled>", out, re.S | re.I) if rc == 0 else None
            states[name] = rc == 0 and not (m and m.group(1).lower() == "false")
    elif IS_LINUX:
        udir = service.systemd_user_dir()
        units = ("aegis-monitor.service", "aegis-scan.timer", "aegis-update.timer")
        bus_ok = False
        if shutil.which("systemctl"):
            for u in units:
                rc, out, err = run(["systemctl", "--user", "is-enabled", u], timeout=15)
                if rc == 0:
                    states[u], bus_ok = True, True
                else:
                    states[u] = False
                    bus_ok = bus_ok or "failed to connect" not in (err + out).lower()
        if not bus_ok:  # no user session bus (container, ssh without linger): fall back to unit files
            states = {u: (udir / u).exists() for u in units}
            if any(states.values()):
                note = " (unit files found; systemd state could not be queried)"
    else:
        return _chk("DOC-SERVICE", title, CheckStatus.SKIP, "Scheduled protection is only supported on Windows and Linux.")
    missing = [n for n, ok in states.items() if not ok]
    if not missing:
        return _chk("DOC-SERVICE", title, CheckStatus.PASS, "Installed and enabled: " + ", ".join(states) + note)
    if len(missing) == len(states):
        return _chk("DOC-SERVICE", title, CheckStatus.WARN, "No scheduled protection is installed: Aegis only protects while "
                    "you run it by hand.", "medium", fix)
    return _chk("DOC-SERVICE", title, CheckStatus.WARN, "Missing or disabled: " + ", ".join(missing) + note, "medium", fix)


def check_monitor(config: Any, now: Optional[float] = None) -> DoctorCheck:
    title = "Real-time monitor is running"
    fix = "Start it with `aegis monitor` (or turn it on in the app's Protection page); `aegis install-service` starts it at every logon."
    hb = read_heartbeat(config)
    if hb is None:
        return _chk("DOC-MONITOR", title, CheckStatus.WARN, "No heartbeat found: real-time protection is not running.", "medium", fix)
    age = (now if now is not None else time.time()) - float(hb["time"])
    pid = hb.get("pid")
    alive = True
    if isinstance(pid, int):
        try:
            import psutil

            alive = psutil.pid_exists(pid)
        except Exception:
            alive = True
    if age > HEARTBEAT_STALE_S or not alive:
        why = "its process is gone" if not alive else f"the last heartbeat was {int(age)} s ago"
        return _chk("DOC-MONITOR", title, CheckStatus.FAIL, f"The real-time monitor stopped unexpectedly ({why}).", "high", fix)
    comps = ", ".join(hb.get("components") or []) or "all guards"
    return _chk("DOC-MONITOR", title, CheckStatus.PASS, f"Running (pid {pid}, heartbeat {max(0, int(age))} s ago; {comps}).")


def check_credential_canary(config: Any, now: Optional[float] = None) -> DoctorCheck:
    """Whether the running monitor's credential canary is watching its decoys, from the heartbeat."""
    title = "Credential canary is watching its decoys"
    hb = read_heartbeat(config)
    if hb is None or (now if now is not None else time.time()) - float(hb["time"]) > HEARTBEAT_STALE_S:
        return _chk("DOC-CREDCANARY", title, CheckStatus.SKIP, "Real-time protection is not running.")
    state = (hb.get("guards") or {}).get("credential_canary") if isinstance(hb.get("guards"), dict) else None
    if not state:
        return _chk("DOC-CREDCANARY", title, CheckStatus.SKIP, "The running monitor does not report it (an older version, "
                    "or the guard is not one of its components).")
    if state == "off":
        return _chk("DOC-CREDCANARY", title, CheckStatus.SKIP, "Switched off (setting realtime_credential_canary).")
    if "nothing about file reads" in state:
        return _chk("DOC-CREDCANARY", title, CheckStatus.SKIP, f"Not available here: {state.split(': ', 1)[-1]}.")
    if state.startswith("watching") and ", but " not in state:
        return _chk("DOC-CREDCANARY", title, CheckStatus.PASS, state[0].upper() + state[1:] + ".")
    if "file_audit" in state:
        fix = "Run `aegis harden --only windows.file_audit --apply` as administrator."
    elif "administrator" in state:
        fix = "Start real-time protection with administrator rights: `aegis install-service` from an elevated prompt."
    else:
        fix = "See logs/aegis.log in Aegis' data folder for why it could not start, then restart real-time protection."
    return _chk("DOC-CREDCANARY", title, CheckStatus.WARN, f"Infostealers reading the decoys would go unnoticed: {state}.",
                "low", fix)


_PS_AV = r"""
$ErrorActionPreference='SilentlyContinue'
$r=[ordered]@{}
try{$r['av']=@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object {[pscustomobject]@{name=[string]$_.displayName;state=[int64]$_.productState;exe=[string]$_.pathToSignedProductExe}})}catch{}
try{$m=Get-MpComputerStatus; if($m){$r['mp']=[pscustomobject]@{AMServiceEnabled=[bool]$m.AMServiceEnabled;AntivirusEnabled=[bool]$m.AntivirusEnabled;RealTimeProtectionEnabled=[bool]$m.RealTimeProtectionEnabled;BehaviorMonitorEnabled=[bool]$m.BehaviorMonitorEnabled;IsTamperProtected=[bool]$m.IsTamperProtected;AntivirusSignatureAge=[int64]$m.AntivirusSignatureAge;QuickScanAge=[int64]$m.QuickScanAge;AMRunningMode=[string]$m.AMRunningMode}}}catch{}
$r|ConvertTo-Json -Depth 5 -Compress
"""


def check_antivirus(config: Any) -> DoctorCheck:
    title = "An antivirus product is active"
    if not IS_WINDOWS:
        return _chk("DOC-AV", title, CheckStatus.SKIP, "Only checked on Windows (Security Center / Microsoft Defender).")
    facts = powershell_json(_PS_AV, timeout=60)
    from aegis.scanners import system_audit

    state = system_audit.build_av_state(facts) if isinstance(facts, dict) else None
    if state is None:
        return _chk("DOC-AV", title, CheckStatus.SKIP, "Windows Security Center did not report any antivirus status (Windows "
                    "Server or a restricted session).")
    active = [p["name"] for p in state.third_party_active] + (["Microsoft Defender"] if state.defender_active else [])
    if not active:
        return _chk("DOC-AV", title, CheckStatus.FAIL, "No antivirus real-time protection is active. Aegis complements a "
                    "traditional antivirus; it does not replace one.", "high",
                    "Open Windows Security > Virus & threat protection and turn on real-time protection, or install and enable a trusted antivirus.")
    stale = [p["name"] for p in state.products if p.get("enabled") and not p.get("up_to_date", True)]
    age = None
    if state.mp:
        try:
            age = int(state.mp.get("AntivirusSignatureAge"))
        except (TypeError, ValueError):
            age = None
    if stale or (age is not None and age > 7):
        what = ", ".join(stale) or "Microsoft Defender"
        return _chk("DOC-AV", title, CheckStatus.WARN, f"Active: {', '.join(active)}, but {what} has out-of-date definitions"
                    + (f" ({age} days old)." if age is not None and age > 7 else "."), "medium",
                    "Open Windows Security > Virus & threat protection > Check for updates (or update the antivirus).")
    return _chk("DOC-AV", title, CheckStatus.PASS, "Active: " + ", ".join(active) + ".")


def _dir_size(path: Path, limit: int = 50_000) -> int:
    total = n = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            n += 1
            if n > limit:
                return total
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total


def _fmt_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.0f} B"


def check_disk(config: Any) -> DoctorCheck:
    title = "Enough disk space for the quarantine"
    qdir = Path(config.quarantine_dir)
    usage = shutil.disk_usage(qdir)
    free_mb = usage.free / (1024 * 1024)
    held = _fmt_size(_dir_size(qdir))
    detail = f"{_fmt_size(usage.free)} free ({usage.free * 100 // max(1, usage.total)}% of the volume); the quarantine holds {held}."
    fix = f"Free some disk space on the volume that holds {qdir}, or move the data folder with AEGIS_HOME."
    if free_mb < DISK_FAIL_MB:
        return _chk("DOC-DISK", title, CheckStatus.FAIL, detail + " Quarantining files may fail.", "high", fix)
    if free_mb < DISK_WARN_MB or usage.free * 20 < usage.total:
        return _chk("DOC-DISK", title, CheckStatus.WARN, detail, "low", fix)
    return _chk("DOC-DISK", title, CheckStatus.PASS, detail)


def check_history(config: Any) -> DoctorCheck:
    from aegis.core import history

    title = "Scan history is working"
    n = history.scan_count(config)
    return _chk("DOC-HISTORY", title, CheckStatus.PASS,
                f"{n} scan(s) recorded (database schema v{history.schema_version(config)}, {_fmt_size(history.history_path(config).stat().st_size)}).")


def _parse_local(stamp: str) -> Optional[dt.datetime]:
    """Scan timestamps are naive local ISO strings; tolerate aware ones by converting to local time."""
    try:
        t = dt.datetime.fromisoformat(stamp)
    except (TypeError, ValueError):
        return None
    return t.astimezone().replace(tzinfo=None) if t.tzinfo else t


def check_last_scan(config: Any, now: Optional[float] = None) -> DoctorCheck:
    from aegis.core import history

    title = "A scan ran recently"
    fix = "Run `aegis scan quick` now; `aegis install-service` schedules a daily quick scan."
    latest = history.list_scans(config, limit=1)
    stamp = (latest[0].finished or latest[0].started) if latest else ""
    if not stamp:
        try:
            from aegis.core.engine import last_scan

            r = last_scan(config)
            stamp = (r.finished or r.started) if r else ""
        except Exception:
            stamp = ""
    t = _parse_local(stamp) if stamp else None
    if t is None:
        return _chk("DOC-SCANAGE", title, CheckStatus.WARN, "No scan has been recorded yet.", "medium", fix)
    age = ((dt.datetime.fromtimestamp(now) if now is not None else dt.datetime.now()) - t).total_seconds() / 86400.0
    if age > SCAN_WARN_DAYS:
        return _chk("DOC-SCANAGE", title, CheckStatus.WARN, f"The last scan was {age:.0f} day(s) ago ({stamp}).", "low", fix)
    return _chk("DOC-SCANAGE", title, CheckStatus.PASS, f"The last scan finished {max(0.0, age):.1f} day(s) ago ({stamp}).")


def check_alerts(config: Any) -> DoctorCheck:
    from aegis.core import alerts

    title = "Alert channels"
    channels = alerts.configured_channels(config)
    problems = alerts.validate_config(config)
    if problems:
        return _chk("DOC-ALERTS", title, CheckStatus.FAIL, " ".join(problems), "low",
                    "Correct the alert settings (Settings > Alerts, or `aegis config set`) and run an alert test.")
    if not channels:
        return _chk("DOC-ALERTS", title, CheckStatus.SKIP, "No alert channel is configured (optional): Aegis will only "
                    "notify on this machine.", "info", "To get notified elsewhere set a Slack, Teams, Discord, webhook or email channel.")
    mode = "new findings" if alerts.alert_mode(config) == "new" else "all findings"
    return _chk("DOC-ALERTS", title, CheckStatus.PASS,
                f"Channels: {', '.join(channels)}; alerting on {mode} of severity {alerts.min_severity(config).name.lower()} or higher.")


# =========================================================================== orchestration

def doctor(config: Any = None, signatures: Any = None, now: Optional[float] = None) -> List[DoctorCheck]:
    """Run every check. Returns the results in display order; never raises."""
    if config is None:
        from aegis.core.config import Config

        config = Config.load()
    plan: List[Tuple[str, str, Callable[[], DoctorCheck]]] = [
        ("DOC-ADMIN", "Running with administrator rights", lambda: check_admin(config)),
        ("DOC-RUNTIME", "Python runtime", lambda: check_runtime(config)),
        ("DOC-DATADIR", "Data folder is writable", lambda: check_datadir(config)),
        ("DOC-ACL", "Only administrators can change Aegis' settings", lambda: check_acl(config)),
        ("DOC-SIGS", "Threat signatures are up to date", lambda: check_signatures(config, now)),
        ("DOC-YARA", "YARA engine (yara-python)", lambda: check_yara_engine(config)),
        ("DOC-YARA-RULES", "Detection rules are loaded", lambda: check_yara_rules(config, signatures)),
        ("DOC-PYYAML", "PyYAML (Sigma rules)", lambda: check_pyyaml(config)),
        ("DOC-SERVICE", "Background protection is installed", lambda: check_service(config)),
        ("DOC-MONITOR", "Real-time monitor is running", lambda: check_monitor(config, now)),
        ("DOC-CREDCANARY", "Credential canary is watching its decoys", lambda: check_credential_canary(config, now)),
        ("DOC-AV", "An antivirus product is active", lambda: check_antivirus(config)),
        ("DOC-DISK", "Enough disk space for the quarantine", lambda: check_disk(config)),
        ("DOC-HISTORY", "Scan history is working", lambda: check_history(config)),
        ("DOC-SCANAGE", "A scan ran recently", lambda: check_last_scan(config, now)),
        ("DOC-ALERTS", "Alert channels", lambda: check_alerts(config)),
    ]
    out: List[DoctorCheck] = []
    for check_id, title, fn in plan:
        try:
            out.append(fn())
        except Exception as exc:  # a broken check must not hide the others
            log.debug("doctor check %s crashed", check_id, exc_info=True)
            out.append(_chk(check_id, title, CheckStatus.ERROR, f"The check itself failed: {type(exc).__name__}: {exc}", "low"))
    return out


def summarize(results: Sequence[CheckResult]) -> Dict[str, int]:
    counts = {s: 0 for s in (CheckStatus.PASS, CheckStatus.WARN, CheckStatus.FAIL, CheckStatus.SKIP, CheckStatus.ERROR)}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    return counts


def has_failures(results: Sequence[CheckResult]) -> bool:
    """True when any check FAILED (the suggested non-zero exit status for `aegis doctor`)."""
    return any(r.status == CheckStatus.FAIL for r in results)


def render_doctor(results: Sequence[DoctorCheck], color: bool = False) -> str:
    """Plain-text report: one line per check, the fix under every check that needs attention."""
    marks = {CheckStatus.PASS: ("PASS", "\033[1;92m"), CheckStatus.WARN: ("WARN", "\033[1;93m"),
             CheckStatus.FAIL: ("FAIL", "\033[1;91m"), CheckStatus.SKIP: ("SKIP", "\033[2m"),
             CheckStatus.ERROR: ("ERR ", "\033[1;91m")}
    lines = [f"{__app_name__} {__version__} - self-check", ""]
    for r in results:
        label, code = marks.get(r.status, (r.status.upper(), ""))
        tag = f"{code}{label}\033[0m" if color and code else label
        lines.append(f"[{tag}] {r.title}" + (f" ({r.severity})" if r.status in (CheckStatus.FAIL, CheckStatus.WARN) and r.severity != "info" else ""))
        if r.detail:
            lines.append(f"       {r.detail}")
        if r.status in (CheckStatus.FAIL, CheckStatus.WARN, CheckStatus.ERROR) and getattr(r, "fix", ""):
            lines.append(f"       Fix: {r.fix}" + ("   [automatic: aegis doctor --fix]" if getattr(r, "fix_id", "") else ""))
    c = summarize(results)
    lines += ["", f"{c[CheckStatus.PASS]} passed, {c[CheckStatus.WARN]} warning(s), {c[CheckStatus.FAIL]} failed, "
                  f"{c[CheckStatus.SKIP]} skipped" + (f", {c[CheckStatus.ERROR]} error(s)" if c[CheckStatus.ERROR] else "")]
    return "\n".join(lines)


def _run_update(config: Any) -> Tuple[bool, str]:
    from aegis.tools.updater import update_signatures

    res = update_signatures(config)
    good = [k for k, v in res.items() if v.get("ok")]
    bad = {k: v.get("error", "") for k, v in res.items() if not v.get("ok") and not v.get("skipped")}
    msg = f"{len(good)} feed(s) updated" + (f"; failed: {', '.join(bad)}" if bad else "")
    return bool(good), msg


def apply_fixes(config: Any, results: Optional[Sequence[DoctorCheck]] = None,
                only: Optional[Sequence[str]] = None) -> List[Tuple[str, bool, str]]:
    """Apply the automatic fixes of failing/warning checks (``fix_id`` acl, perms, update).

    Returns ``[(fix_id, ok, message)]``. ``only`` restricts the fix ids. Never raises."""
    results = list(results) if results is not None else doctor(config)
    actions: Dict[str, Callable[[], Tuple[bool, str]]] = {
        "acl": lambda: apply_safe_acl(Path(config.home), lock_config=bool(_secret_config_fields(config))),
        "perms": lambda: apply_posix_perms(config),
        "update": lambda: _run_update(config),
    }
    done: List[Tuple[str, bool, str]] = []
    for r in results:
        fid = getattr(r, "fix_id", "")
        if not fid or r.status not in (CheckStatus.FAIL, CheckStatus.WARN) or fid not in actions:
            continue
        if only is not None and fid not in only:
            continue
        if any(d[0] == fid for d in done):
            continue
        try:
            ok, msg = actions[fid]()
        except Exception as exc:
            ok, msg = False, f"{type(exc).__name__}: {exc}"
        done.append((fid, ok, msg))
    return done
