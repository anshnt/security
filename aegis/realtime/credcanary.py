"""Credential canary: decoy browser and wallet files that only an infostealer reads.

Infostealers (RedLine, LummaC2, Vidar, StealC, Rhadamanthys, ...) all do the same thing on a new victim: sweep the
browser profile folders and desktop-wallet folders for saved passwords, cookies, the key that decrypts them, and wallet
files, then send everything off within seconds. arXiv 2609.30070 ("A Data-Driven Analysis of Infostealer Malware
Victims") points to that runtime access to credential stores as a high-fidelity signal across these families. Normal
programs never open another application's password database, so a decoy that nothing legitimate uses turns the sweep
itself into an alarm, independent of how the stealer was packed or delivered.

Decoys (one browser profile and one wallet, planted only where the application folder does not exist yet, so a real
browser or wallet never loads them):

* a Chromium-style profile: ``Local State`` (with an ``os_crypt`` key), ``Default/Login Data`` and ``Cookies`` (real
  SQLite databases with one fake row each, on reserved ``example.com`` names). Windows: ``%LOCALAPPDATA%\\Kometa\\User
  Data`` (on LummaC2's browser list, and a browser almost nobody installs), else ``%LOCALAPPDATA%\\Chromium\\User Data``.
  Linux: ``~/.config/chromium``;
* an Electrum wallet (``wallets/default_wallet``, encrypted-wallet format), else an Ethereum keystore file. Electrum is on
  the wallet lists of LummaC2 and Vidar; RedLine's sweep also searches the application-data folders generically.

When a real application is later installed into a decoy's folder (anything appears there that Aegis did not create), the
decoy is retired instead of raising an alarm, and the next start plants it at the next candidate location.

Who read it:

* Windows: every decoy file gets an audit entry (SACL) for successful ``ReadData`` by Everyone, and the guard subscribes
  to Security event 4663, which names the process (pid and image path). That needs administrator rights (setting a SACL
  needs SeSecurityPrivilege; reading the Security log needs admin) and the "Audit File System" policy, which
  ``aegis harden --only windows.file_audit --apply`` turns on (undo with ``aegis undo``). Only objects carrying a SACL are
  logged, so the Security log hardly grows. Attribute reads (Explorer listing the folder, ``stat``) are not audited.
  Microsoft Defender and Windows Search are recognised by their image folders, which only administrators can write; the
  decoys are also flagged "not content indexed". A read by any other process except Aegis itself is HIGH, offering to
  terminate the process and quarantine its file.
* Linux: inotify ``IN_OPEN`` watches on the decoy files are reliable in user mode, but inotify does not say *who*
  opened a file (fanotify does, and needs root), so the alert cannot name or stop the program. Backup tools that copy
  all of ``~/.config`` also open the decoys. Desktop indexers (tracker, baloo) skip hidden folders.
* macOS: nothing reliable in user mode. FSEvents and kqueue report changes, not reads, and access times are not
  dependable; seeing opens needs an Endpoint Security system extension (entitlement, root, notarised app). The guard
  does not plant decoys there.

Aegis's own scanners skip the decoy folders (``decoy_roots``), so a scan never trips the alarm or reports a decoy as a
real browser profile or wallet.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import secrets
import select
import sqlite3
import struct
import threading
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Tuple

from aegis.core.models import Category, Finding, Remediation, Severity
from aegis.core.platform import (
    IS_LINUX,
    IS_WINDOWS,
    env_path,
    is_admin,
    is_under,
    normalize_path,
    system_binary_dirs,
    user_home,
    windows_dir,
)

if TYPE_CHECKING:  # pragma: no cover
    from aegis.realtime.monitor import RealtimeMonitor

log = logging.getLogger("aegis.realtime.credcanary")

RULE_ID = "AEG-RT-CREDCANARY"
STATE_NAME = "credential_canaries.json"
FILE_READ_DATA = 0x1
AUDIT_SDDL = "S:(AU;SA;0x1;;;WD)"  # audit successful ReadData by Everyone
MITRE = {"browser": ["T1555.003", "T1539"], "wallet": ["T1005"]}
WHAT = {"browser": "saved browser passwords, session cookies and the key that decrypts them", "wallet": "crypto wallets"}

_CHROMIUM_WIN = ("User Data/Local State", "User Data/Default/Login Data", "User Data/Default/Network/Cookies")
_CHROMIUM_NIX = ("Local State", "Default/Login Data", "Default/Cookies")


# =========================================================================== decoy locations and contents

@dataclass(frozen=True)
class Spot:
    kind: str  # browser | wallet
    label: str  # what a stealer believes it found
    root: str  # the application folder: Aegis only plants into one that does not exist yet
    files: Tuple[str, ...]  # decoy files, "/"-separated and relative to root

    def paths(self) -> List[str]:
        return [os.path.join(self.root, *rel.split("/")) for rel in self.files]


def _keystore_name() -> str:
    stamp = time.strftime("%Y-%m-%dT%H-%M-%S", time.gmtime(time.time() - 400 * 86400))
    return f"UTC--{stamp}.{secrets.randbelow(10**9):09d}Z--{secrets.token_hex(20)}"


def candidate_spots(home: Optional[Path] = None) -> List[Spot]:
    """Decoy locations in order of preference; per kind, the first whose folder does not exist yet is used."""
    base = home or user_home()
    if IS_WINDOWS:
        local = (env_path("LOCALAPPDATA") if home is None else None) or base / "AppData" / "Local"
        roaming = (env_path("APPDATA") if home is None else None) or base / "AppData" / "Roaming"
        return [Spot("browser", "Kometa browser profile", str(local / "Kometa"), _CHROMIUM_WIN),
                Spot("browser", "Chromium browser profile", str(local / "Chromium"), _CHROMIUM_WIN),
                Spot("wallet", "Electrum wallet", str(roaming / "Electrum"), ("wallets/default_wallet",)),
                Spot("wallet", "Ethereum keystore", str(roaming / "Ethereum"), (f"keystore/{_keystore_name()}",))]
    if IS_LINUX:
        return [Spot("browser", "Chromium browser profile", str(base / ".config" / "chromium"), _CHROMIUM_NIX),
                Spot("wallet", "Electrum wallet", str(base / ".electrum"), ("wallets/default_wallet",)),
                Spot("wallet", "Ethereum keystore", str(base / ".ethereum"), (f"keystore/{_keystore_name()}",))]
    return []


def _chrome_time(offset_s: float = 0.0) -> int:
    return int((time.time() + offset_s + 11644473600) * 1_000_000)  # microseconds since 1601


def _write_sqlite(path: str, name: str) -> None:
    token = secrets.token_hex(5)
    conn = sqlite3.connect(path)
    try:
        if name == "Login Data":
            conn.execute("CREATE TABLE logins (origin_url VARCHAR NOT NULL, action_url VARCHAR, username_element VARCHAR, "
                         "username_value VARCHAR, password_element VARCHAR, password_value BLOB, signon_realm VARCHAR NOT "
                         "NULL, date_created INTEGER NOT NULL, blacklisted_by_user INTEGER NOT NULL, scheme INTEGER NOT "
                         "NULL, times_used INTEGER)")
            conn.execute("INSERT INTO logins VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                         ("https://login.example.com/", "https://login.example.com/session", "email",
                          f"{token}@example.com", "password", b"v10" + secrets.token_bytes(28),
                          "https://login.example.com/", _chrome_time(-200 * 86400), 0, 0, 7))
        else:
            conn.execute("CREATE TABLE cookies (creation_utc INTEGER NOT NULL, host_key TEXT NOT NULL, name TEXT NOT NULL, "
                         "value TEXT NOT NULL, encrypted_value BLOB NOT NULL, path TEXT NOT NULL, expires_utc INTEGER NOT "
                         "NULL, is_secure INTEGER NOT NULL, is_httponly INTEGER NOT NULL, last_access_utc INTEGER NOT NULL, "
                         "has_expires INTEGER NOT NULL, is_persistent INTEGER NOT NULL, samesite INTEGER NOT NULL)")
            conn.execute("INSERT INTO cookies VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                         (_chrome_time(-30 * 86400), ".example.com", "session_id", "", b"v10" + secrets.token_bytes(48),
                          "/", _chrome_time(335 * 86400), 1, 1, _chrome_time(-86400), 1, 1, 1))
        conn.commit()
    finally:
        conn.close()


def _decoy_bytes(name: str) -> bytes:
    if name == "Local State":
        key = base64.b64encode(b"DPAPI" + secrets.token_bytes(230)).decode()
        return json.dumps({"os_crypt": {"encrypted_key": key},
                           "profile": {"info_cache": {"Default": {"name": "Person 1"}}, "last_used": "Default"}}).encode()
    if name == "default_wallet":  # Electrum's encrypted wallet file: base64 of b"BIE1" + key + ciphertext + MAC
        return base64.b64encode(b"BIE1" + secrets.token_bytes(1040))
    address = name.rsplit("--", 1)[-1]
    return json.dumps({"address": address, "crypto": {
        "cipher": "aes-128-ctr", "ciphertext": secrets.token_hex(32), "cipherparams": {"iv": secrets.token_hex(16)},
        "kdf": "scrypt", "kdfparams": {"dklen": 32, "n": 262144, "p": 1, "r": 8, "salt": secrets.token_hex(32)},
        "mac": secrets.token_hex(32)}, "id": str(uuid.uuid4()), "version": 3}).encode()


def write_decoy(path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    name = os.path.basename(path)
    if name in ("Login Data", "Cookies"):
        _write_sqlite(path, name)
    else:
        with open(path, "wb") as fh:
            fh.write(_decoy_bytes(name))
    if not IS_WINDOWS:
        os.chmod(path, 0o600)  # what the browser uses for these files


def _our_entries(spot: Spot) -> set:
    ours = set()
    for rel in spot.files:
        parts = rel.split("/")
        ours.update(os.path.normcase(os.path.join(*parts[:i])) for i in range(1, len(parts) + 1))
    return ours


def foreign_entries(spot: Spot) -> List[str]:
    """Files or folders under the decoy's folder that Aegis did not create: a real application was installed there.
    Only lists folders, so it never opens (or trips) a decoy."""
    ours, out = _our_entries(spot), []
    for dirpath, dirnames, filenames in os.walk(spot.root):
        for n in dirnames + filenames:
            rel = os.path.normcase(os.path.relpath(os.path.join(dirpath, n), spot.root))
            if rel not in ours:
                out.append(rel)
    return out


def _remove_spot(spot: Spot) -> int:
    """Delete the decoy files and the folders Aegis created for them; a folder that holds anything else stays."""
    n = 0
    dirs = set()
    root = os.path.normpath(spot.root)
    for p in spot.paths():
        try:
            os.remove(p)
            n += 1
        except FileNotFoundError:
            pass
        except OSError as exc:
            log.debug("cannot remove decoy %s: %s", p, exc)
        d = os.path.dirname(os.path.normpath(p))
        while len(d) >= len(root):
            dirs.add(d)
            d = os.path.dirname(d)
    for d in sorted(dirs, key=len, reverse=True):
        try:
            os.rmdir(d)
        except OSError:
            pass
    return n


_DEVICE = re.compile(r"^\\device\\[^\\]+", re.I)


def _tail(path: str) -> str:
    """A path without its drive, so C:\\x and \\Device\\HarddiskVolume3\\x (both appear in event 4663) compare equal."""
    p = os.path.normcase(str(path))
    if p.startswith("\\\\?\\"):
        p = p[4:]
    if len(p) > 1 and p[1] == ":":
        return p[2:]
    return _DEVICE.sub("", p)


class DecoySet:
    """The planted decoys, remembered in a small JSON file in Aegis's data folder."""

    def __init__(self, state_path: Path, candidates: Optional[Callable[[], List[Spot]]] = None):
        self.state_path = Path(state_path)
        self.candidates = candidates or candidate_spots
        self.spots: List[Spot] = []
        self._lock = threading.RLock()
        try:
            raw = json.loads(self.state_path.read_text(encoding="utf-8"))
            self.spots = [Spot(s["kind"], s["label"], s["root"], tuple(s["files"])) for s in raw["spots"]]
        except (OSError, ValueError, KeyError, TypeError):
            pass

    def _save(self) -> None:
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            self.state_path.write_text(json.dumps({"spots": [asdict(s) for s in self.spots]}, indent=1), encoding="utf-8")
        except OSError as exc:
            log.debug("cannot save the credential canary state: %s", exc)

    def deploy(self) -> List[str]:
        """Keep each planted decoy that is still Aegis's alone (recreating missing files), retire one a real application
        moved in with, and plant one browser and one wallet decoy where none is. Returns every decoy file."""
        with self._lock:
            kept: List[Spot] = []
            for s in self.spots:
                if not os.path.isdir(s.root):
                    continue  # removed by the user: planted afresh below
                if foreign_entries(s):
                    log.info("credential canary: an application now uses %s; retiring the decoy there", s.root)
                    _remove_spot(s)
                    continue
                for p in s.paths():
                    if not os.path.exists(p):
                        write_decoy(p)
                kept.append(s)
            kinds = {s.kind for s in kept}
            for c in self.candidates():
                if c.kind in kinds or os.path.lexists(c.root):
                    continue
                try:
                    for p in c.paths():
                        write_decoy(p)
                except (OSError, sqlite3.Error) as exc:
                    log.debug("cannot plant a decoy in %s: %s", c.root, exc)
                    _remove_spot(c)
                    continue
                kept.append(c)
                kinds.add(c.kind)
            self.spots = kept
            self._save()
            return [p for s in kept for p in s.paths()]

    def lookup(self, path: str) -> Optional[Spot]:
        t = _tail(path)
        with self._lock:
            return next((s for s in self.spots if any(_tail(p) == t for p in s.paths())), None)

    def retire(self, spot: Spot) -> None:
        with self._lock:
            _remove_spot(spot)
            self.spots = [s for s in self.spots if s != spot]
            self._save()

    def remove(self) -> int:
        with self._lock:
            n = sum(_remove_spot(s) for s in self.spots)
            self.spots = []
            self._save()
        return n


def decoy_roots() -> List[str]:
    """Folders holding credential decoys, for Aegis's scanners to skip: reading a decoy raises the alarm. Read from this
    process's data folder and, on Windows, from %ProgramData%\\Aegis, where the elevated monitor keeps its state."""
    from aegis.core.config import data_home

    homes = [data_home()]
    pd = os.environ.get("ProgramData") if IS_WINDOWS else None
    if pd:
        homes.append(Path(pd) / "Aegis")
    out: List[str] = []
    for h in homes:
        try:
            raw = json.loads((h / STATE_NAME).read_text(encoding="utf-8"))
            out += [str(s["root"]) for s in raw["spots"]]
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return list(dict.fromkeys(out))


def is_decoy(path: "str | Path", roots: Optional[List[str]] = None) -> bool:
    roots = decoy_roots() if roots is None else roots
    return bool(roots) and is_under(str(path), [Path(r) for r in roots])


# =========================================================================== access events

@dataclass
class Access:
    path: str
    pid: int = 0  # 0 = the platform does not say who
    exe: str = ""
    user: str = ""


def access_from_event_xml(xml: str) -> Optional[Access]:
    """The read reported by one Security event 4663 (data names are not localised)."""
    from aegis.scanners.eventlog import parse_event_xml

    ev = parse_event_xml(xml)
    if not ev or ev.get("id") != 4663:
        return None
    d = ev["data"]

    def num(key: str) -> int:
        try:
            return int(d.get(key) or "0", 0)
        except ValueError:
            return 0

    mask = num("AccessMask")
    if mask and not mask & FILE_READ_DATA:
        return None
    user = "\\".join(x for x in (d.get("SubjectDomainName"), d.get("SubjectUserName")) if x)
    return Access(d.get("ObjectName") or "", num("ProcessId"), d.get("ProcessName") or "", user)


def trusted_reader(exe: str) -> bool:
    """Microsoft Defender and Windows Search read the files they scan or index. Their image folders are writable only by
    administrators, so a stealer cannot pass for them by name."""
    if not exe:
        return False
    pd, pf = env_path("ProgramData", r"C:\ProgramData"), env_path("ProgramFiles", r"C:\Program Files")
    if pd and pf and is_under(exe, [pd / "Microsoft" / "Windows Defender", pf / "Windows Defender",
                                    pf / "Windows Defender Advanced Threat Protection"]):
        return True
    sys32 = windows_dir() / "System32"
    return normalize_path(exe) in {normalize_path(str(sys32 / n)) for n in
                                   ("SearchProtocolHost.exe", "SearchIndexer.exe", "SearchFilterHost.exe")}


def running_name(pid: int, exe: str) -> Optional[str]:
    """The name of the process when that pid is still the program that read the decoy (pid reuse checked)."""
    try:
        import psutil

        p = psutil.Process(pid)
        if exe and os.path.normcase(p.exe()) != os.path.normcase(exe):
            return None
        return p.name()
    except Exception:
        return None


def access_finding(a: Access, spot: Spot, running: Optional[str]) -> Finding:
    from aegis.realtime.monitor import PROTECTED_NAMES, _own_ancestors

    exe = a.exe
    name = running or os.path.basename(exe) or ("System" if a.pid == 4 else "")
    critical = a.pid in (0, 4) or name.lower() in PROTECTED_NAMES or a.pid in _own_ancestors()
    system_bin = bool(exe) and is_under(exe, [Path(p) for p in system_binary_dirs()])
    rem = None
    if running and not critical:  # a hollowed AppLaunch.exe / RegAsm.exe is stopped, but Windows files are not quarantined
        rem = Remediation("kill_process", {"pid": a.pid, "path": exe, "quarantine": not system_bin},
                          f"Terminate {name} (pid {a.pid})" + ("" if system_bin else " and quarantine it"))
    elif exe and not critical and not system_bin and os.path.isfile(exe):
        rem = Remediation("quarantine_file", {"path": exe}, f"Quarantine {os.path.basename(exe)}")
    if name:
        who = f"{name} (pid {a.pid}{', ' + exe if exe else ''})"
        title = f"Infostealer: {name} read a decoy {spot.label}"
    else:
        who = f"A program (pid {a.pid})" if a.pid else "A program"
        title = f"Infostealer: a decoy {spot.label} was opened"
    desc = (f"Aegis keeps a decoy {spot.label} in {spot.root} that no real program uses. {who} opened its "
            f"'{os.path.basename(a.path)}' file. That is what infostealers (RedLine, LummaC2, Vidar, StealC, Rhadamanthys) "
            f"do when they sweep a PC for {WHAT[spot.kind]}.")
    if not a.pid and not exe:
        desc += (" Linux does not tell an unprivileged program who opened a file, so the program cannot be named or stopped "
                 "here. Backup or sync tools that copy all of ~/.config open it too; if one just ran, it is the likely reader.")
    rec = ("Treat this PC as compromised: terminate and quarantine the program, disconnect from the network and run a full "
           "scan. Then, from a different, clean device, change the passwords saved in your browsers, sign out of every "
           "session (stolen cookies get past passwords and two-factor sign-in) and move crypto funds to a new wallet.")
    ev = {"decoy": a.path, "decoy_kind": spot.kind, "decoy_folder": spot.root, "pid": a.pid, "process": name, "exe": exe,
          "user": a.user, "still_running": bool(running), "source": "credential-canary"}
    return Finding(RULE_ID, title, Severity.HIGH, Category.MALWARE, desc, exe or spot.root, ev, rec, rem, "realtime",
                   list(MITRE[spot.kind]))


# =========================================================================== platform sources

def unavailable_reason(admin: Optional[bool] = None) -> Optional[str]:
    if IS_WINDOWS:
        if is_admin() if admin is None else admin:
            return None
        return "needs administrator rights (to put audit entries on the decoys and read the Security log)"
    if IS_LINUX:
        return None
    return "this system tells user-mode programs nothing about file reads (macOS needs an Endpoint Security extension)"


def _set_not_indexed(path: str) -> None:
    import ctypes

    k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    k32.GetFileAttributesW.restype = ctypes.c_uint32
    attrs = k32.GetFileAttributesW(str(path))
    if attrs != 0xFFFFFFFF:
        k32.SetFileAttributesW(str(path), (attrs & ~0x80) | 0x2000)  # not NORMAL; NOT_CONTENT_INDEXED


def _enable_privilege(name: str) -> bool:
    import ctypes
    from ctypes import wintypes

    adv = ctypes.WinDLL("advapi32", use_last_error=True)  # type: ignore[attr-defined]
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]

    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Luid", LUID), ("Attributes", wintypes.DWORD)]

    k32.GetCurrentProcess.restype = wintypes.HANDLE
    adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    adv.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(LUID)]
    adv.AdjustTokenPrivileges.argtypes = [wintypes.HANDLE, wintypes.BOOL, ctypes.c_void_p, wintypes.DWORD,
                                          ctypes.c_void_p, ctypes.c_void_p]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    token = wintypes.HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(), 0x20 | 0x8, ctypes.byref(token)):  # ADJUST_PRIVILEGES | QUERY
        return False
    try:
        luid = LUID()
        if not adv.LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
            return False
        tp = TOKEN_PRIVILEGES(1, luid, 0x2)  # SE_PRIVILEGE_ENABLED
        ok = adv.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None)
        return bool(ok) and ctypes.get_last_error() != 1300  # ERROR_NOT_ALL_ASSIGNED: the token lacks it
    finally:
        k32.CloseHandle(token)


def set_audit_sacl(path: str) -> bool:
    """Audit successful ReadData on one file (needs SeSecurityPrivilege, which administrators hold)."""
    import ctypes
    from ctypes import wintypes

    adv = ctypes.WinDLL("advapi32", use_last_error=True)  # type: ignore[attr-defined]
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    if not _enable_privilege("SeSecurityPrivilege"):
        return False
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    adv.GetSecurityDescriptorSacl.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL),
                                              ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)]
    adv.SetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p,
                                          ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    adv.SetNamedSecurityInfoW.restype = wintypes.DWORD
    k32.LocalFree.argtypes = [ctypes.c_void_p]
    sd = ctypes.c_void_p()
    if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(AUDIT_SDDL, 1, ctypes.byref(sd), None):
        return False
    try:
        present, defaulted, sacl = wintypes.BOOL(), wintypes.BOOL(), ctypes.c_void_p()
        if not adv.GetSecurityDescriptorSacl(sd, ctypes.byref(present), ctypes.byref(sacl), ctypes.byref(defaulted)):
            return False
        return adv.SetNamedSecurityInfoW(str(path), 1, 0x8, None, None, None, sacl) == 0  # SE_FILE_OBJECT, SACL_SECURITY_INFORMATION
    finally:
        k32.LocalFree(sd)


class WindowsAuditSource:
    """Security event 4663 for the decoys' audit entries, pushed by an EvtSubscribe subscription (no log polling)."""

    QUERY = "*[System[(EventID=4663)]]"

    def prepare(self, paths: List[str]) -> None:
        bad = []
        for p in paths:
            for target in (os.path.dirname(p), p):
                _set_not_indexed(target)
            if not set_audit_sacl(p):
                bad.append(p)
        if bad:
            raise OSError(f"could not put an audit entry on {len(bad)} decoy file(s)")

    def run(self, stop: threading.Event, on_access: Callable[[Access], None]) -> None:
        try:
            from aegis.protect import harden

            pol = harden._auditpol_get(harden.FILE_SYSTEM_GUID)
            if pol is not None and not pol & 1:
                log.warning("credential canary: Windows does not audit file-system access, so reads of the decoys are not "
                            "logged. Turn it on with: aegis harden --only windows.file_audit --apply")
        except Exception:
            log.debug("could not read the File System audit policy", exc_info=True)
        while not stop.is_set():
            try:
                self._follow(stop, on_access)
            except OSError as exc:
                log.warning("credential canary cannot read the Security log (%s); retrying in 30s", exc)
                stop.wait(30)

    def _follow(self, stop: threading.Event, on_access: Callable[[Access], None]) -> None:
        import ctypes
        from ctypes import wintypes

        w = ctypes.WinDLL("wevtapi", use_last_error=True)  # type: ignore[attr-defined]
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
        H = wintypes.HANDLE
        w.EvtSubscribe.argtypes = [H, H, wintypes.LPCWSTR, wintypes.LPCWSTR, H, ctypes.c_void_p, ctypes.c_void_p,
                                   wintypes.DWORD]
        w.EvtSubscribe.restype = H
        w.EvtNext.argtypes = [H, wintypes.DWORD, ctypes.POINTER(H), wintypes.DWORD, wintypes.DWORD,
                              ctypes.POINTER(wintypes.DWORD)]
        w.EvtRender.argtypes = [H, H, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD),
                                ctypes.POINTER(wintypes.DWORD)]
        w.EvtClose.argtypes = [H]
        k32.CreateEventW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
        k32.CreateEventW.restype = H
        k32.WaitForSingleObject.argtypes = [H, wintypes.DWORD]
        k32.ResetEvent.argtypes = [H]
        k32.CloseHandle.argtypes = [H]

        signal = k32.CreateEventW(None, True, True, None)  # manual reset, initially set
        sub = w.EvtSubscribe(None, signal, "Security", self.QUERY, None, None, None, 1)  # EvtSubscribeToFutureEvents
        if not sub:
            k32.CloseHandle(signal)
            raise OSError(ctypes.get_last_error(), "EvtSubscribe failed")
        handles = (H * 16)()
        got, used, count = wintypes.DWORD(), wintypes.DWORD(), wintypes.DWORD()
        try:
            while not stop.is_set():
                k32.WaitForSingleObject(signal, 1000)
                k32.ResetEvent(signal)  # before draining, so an event arriving meanwhile sets it again
                while w.EvtNext(sub, 16, handles, 0, 0, ctypes.byref(got)):
                    for i in range(got.value):
                        try:
                            w.EvtRender(None, handles[i], 1, 0, None, ctypes.byref(used), ctypes.byref(count))  # size
                            buf = ctypes.create_unicode_buffer(used.value // 2 + 1)
                            ok = w.EvtRender(None, handles[i], 1, ctypes.sizeof(buf), buf, ctypes.byref(used),
                                             ctypes.byref(count))  # EvtRenderEventXml
                        finally:
                            w.EvtClose(handles[i])
                        a = access_from_event_xml(buf.value) if ok else None
                        if a:
                            on_access(a)
                err = ctypes.get_last_error()
                if err not in (259, 1460):  # ERROR_NO_MORE_ITEMS, ERROR_TIMEOUT: drained
                    raise OSError(err, "EvtNext failed")
        finally:
            w.EvtClose(sub)
            k32.CloseHandle(signal)


_INOTIFY_EVENT = struct.Struct("=iIII")  # wd, mask, cookie, len; then len bytes of name


def parse_inotify(buf: bytes) -> List[Tuple[int, int]]:
    """(watch descriptor, mask) of each struct inotify_event in a read() buffer."""
    out, off = [], 0
    while off + _INOTIFY_EVENT.size <= len(buf):
        wd, mask, _cookie, n = _INOTIFY_EVENT.unpack_from(buf, off)
        out.append((wd, mask))
        off += _INOTIFY_EVENT.size + n
    return out


class InotifySource:
    """IN_OPEN on each decoy file (Linux, no privileges). inotify does not report the opening process."""

    IN_OPEN = 0x20

    def __init__(self) -> None:
        import ctypes
        import ctypes.util

        self._libc = ctypes.CDLL(ctypes.util.find_library("c") or None, use_errno=True)
        self.fd = self._libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), "inotify_init1 failed")
        self.watches: Dict[int, str] = {}

    def prepare(self, paths: List[str]) -> None:
        for p in paths:
            wd = self._libc.inotify_add_watch(self.fd, os.fsencode(p), self.IN_OPEN)
            if wd < 0:
                raise OSError(f"cannot watch {p}")
            self.watches[wd] = p

    def run(self, stop: threading.Event, on_access: Callable[[Access], None]) -> None:
        try:
            while not stop.is_set():
                if not select.select([self.fd], [], [], 1.0)[0]:
                    continue
                try:
                    buf = os.read(self.fd, 65536)
                except BlockingIOError:
                    continue
                for wd, mask in parse_inotify(buf):
                    path = self.watches.get(wd)
                    if path and mask & self.IN_OPEN:
                        on_access(Access(path))
        finally:
            os.close(self.fd)


# =========================================================================== guard

class CredentialCanaryGuard:
    def __init__(self, monitor: "RealtimeMonitor", source: Any = None, decoys: Optional[DecoySet] = None):
        self.monitor = monitor
        self.source = source  # WindowsAuditSource / InotifySource, or a fake with prepare(paths) and run(stop, on_access)
        self.decoys = decoys
        self.state = "not started"

    def enabled(self) -> bool:
        return bool(getattr(self.monitor.config, "realtime_credential_canary", True))

    def _decoyset(self) -> DecoySet:
        if self.decoys is None:
            self.decoys = DecoySet(self.monitor.config.home / STATE_NAME)
        return self.decoys

    def start(self, stop: threading.Event) -> List[threading.Thread]:
        if not self.enabled():
            self.state = "off"
            return []
        if self.source is None:
            reason = unavailable_reason()
            if reason is None:
                try:
                    self.source = WindowsAuditSource() if IS_WINDOWS else InotifySource()
                except (OSError, AttributeError) as exc:
                    reason = f"inotify is unavailable ({exc})"
            if reason:
                self.state = f"not running: {reason}"
                log.warning("credential canary not started: %s", reason)
                return []
        try:
            files = self._decoyset().deploy()
            self.source.prepare(files)
        except Exception as exc:
            self.state = f"not running: {exc}"
            log.warning("credential canary not started: %s", exc)
            return []
        self.state = f"watching {len(files)} decoy files" if files else "not running: no free decoy location"
        if not files:
            return []
        return [self.monitor.spawn("credential-canary", lambda: self.source.run(stop, self._safe_access))]

    def _safe_access(self, access: Access) -> None:
        try:
            self.on_access(access)
        except Exception:
            log.exception("credential canary failed on %s", access.path)

    def on_access(self, a: Access) -> Optional[Finding]:
        """Judge one read of a file: an alert when it is a decoy and the reader is not Aegis, Defender or Windows Search.
        The setting is read every time, so switching the guard off in the app applies at once."""
        if not self.enabled() or self.decoys is None:
            return None
        spot = self.decoys.lookup(a.path)
        if spot is None or a.pid == os.getpid() or trusted_reader(a.exe):
            return None
        if foreign_entries(spot):  # a real application moved into the folder and opened what it took for its data
            log.warning("credential canary: %s was installed into %s; retiring that decoy", a.exe or "an application",
                        spot.root)
            self.decoys.retire(spot)
            return None
        f = access_finding(a, spot, running_name(a.pid, a.exe) if a.pid else None)
        self.monitor.stats["credential_canary_alerts"] += 1
        self.monitor.emit(f, "credential-canary")
        return f

    def remove(self) -> int:
        return self._decoyset().remove()
