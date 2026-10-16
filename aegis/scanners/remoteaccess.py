"""Remote-access tool review: which tools can reach this PC, how, and who used them.

Tech-support scammers ask their victims to install a remote-access program (AnyDesk, TeamViewer, ScreenConnect, RustDesk ...),
control the PC, and often set a permanent "unattended access" password so they can come back later. The same programs are used
legitimately by IT providers and by people who help their relatives, so this scanner does not call them malware. It answers the
questions a victim has afterwards: *can someone get in without me clicking Accept, and who connected, and when?*

Running programs are reported by the process scanner (``AEG-PROC-REMOTE``). This scanner reads what the tools leave on disk and
in the registry: their configuration and their own connection logs, for every user profile it may read (what it may not read is
named in the check result). Nothing is changed or deleted and no finding offers a fix: the logs are evidence.

* **AnyDesk**: ``connection_trace.txt`` (incoming sessions with the way each was accepted, a person clicking Accept or a stored
  password or token), ``ad.trace`` / ``ad_svc.trace`` (incoming session requests and the addresses "Logged in from", the last
  4 MB), and ``system.conf`` / ``service.conf`` / ``user.conf`` (unattended-access password set, access list).
* **TeamViewer**: ``Connections_incoming.txt`` (tab-separated: remote ID, name, start, end, local user, type, session id), the
  registry (``SecurityPasswordAES`` permanent password set, ``Always_Online``, ``OwningManagerAccountName`` account the device is
  assigned to), and the Linux ``global.conf`` and macOS preferences file.
* **ScreenConnect / ConnectWise Control**: the client's service command line (``?e=Access&y=Guest&h=<relay>&p=<port>&s=..&k=..``)
  and ``system.config``: relay host and port, and whether it is an Access (unattended) or a Support (attended) client.
* **RustDesk**: ``RustDesk.toml`` (permanent password set) and ``RustDesk2.toml`` (self-hosted ``custom-rendezvous-server`` /
  ``relay-server`` / ``api-server``, key set), the server logs, and a server named in the file name of a portable copy.
* **Atera** (the account that manages the PC), **Splashtop Streamer**, **NetSupport** (``client32.ini``: the gateway the client
  phones home to, a hallmark of NetSupport RAT campaigns, and whether it hides from the user) and **MeshAgent**
  (``MeshAgent.msh``: the MeshCentral server).
* **Portable copies** of these programs in Downloads, on the Desktop and in Temp, the way scam sessions start.

One finding per tool and installation, evidence merged across the profiles that hold it:

* ``AEG-RA-INCOMING`` - the tool's own log lists incoming connections (MEDIUM; LOW when every one is older than 90 days).
* ``AEG-RA-UNATTENDED`` - unattended access is set up (MEDIUM): a permanent password, an Access-mode ScreenConnect client, an
  Atera, Splashtop, NetSupport or MeshAgent installation.
* ``AEG-RA-RELAY`` - the tool connects through a server somebody runs: HIGH for a bare IP address, a dynamic-DNS name, a host on
  the threat feed or a NetSupport gateway, MEDIUM for any other self-hosted server. A vendor's own cloud is not reported.
* ``AEG-RA-PORTABLE`` - a portable copy sits in Downloads, Desktop or Temp (MEDIUM; LOW when it is older than 90 days and not
  running).
* ``AEG-RA-CHK`` - the check result: PASS, FAIL with a summary, or SKIP naming the places looked at.

Passwords, password hashes and salts, tokens, session ids and keys found in a configuration are reported as "set" or "not set"
and never copied: the parsers drop the value the moment they read it. The parsers (log, configuration, registry values), the
host classifier and the finding builders are pure functions; the collectors read through an injectable ``Env`` (profiles,
Program Files, registry, running processes), so the whole scanner is unit-tested on any OS with a fake tree.
"""

from __future__ import annotations

import codecs
import datetime as dt
import ipaddress
import logging
import os
import plistlib
import re
import stat
import tempfile
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple

from aegis.core.models import Category, CheckResult, CheckStatus, Finding, Severity
from aegis.core.platform import OS_NAME, reg_read, reg_subkeys, reg_values, system_drive, user_home, windows_dir
from aegis.core.provenance import visible
from aegis.scanners.base import Emitted, ScanContext, Scanner, register
from aegis.scanners.downloads import UPDATE_HINT, feed_checker
from aegis.scanners.persistence import discover_homes

log = logging.getLogger("aegis.remoteaccess")

CHECK_ID = "AEG-RA-CHK"
CHECK_TITLE = "Remote access tools reviewed"
RECENT_DAYS = 90
MAX_LOG_BYTES = 2 * 1024 * 1024  # the end of a connection log
MAX_TRACE_BYTES = 4 * 1024 * 1024  # the end of an AnyDesk trace, which can be tens of megabytes
MAX_CONFIG_BYTES = 256 * 1024
MAX_EVENTS = 5000  # sessions kept from one file
MAX_IDS = 20  # distinct remote IDs and addresses listed in a finding
MAX_RECENT = 10  # sessions listed in a finding
MAX_PATHS = 6
MAX_LISTING = 20000  # entries looked at in one folder
MAX_WALK = 60000  # entries looked at in the whole walk for NetSupport and MeshAgent
MAX_NAME = 80

TRACE_FILES = 4  # AnyDesk traces read per folder, newest first
RUSTDESK_LOGS = 3

# per tool, for the finding text: how to end a session, how to remove unattended access, how to uninstall (the wording of the
# menus differs between versions)
HOW: Dict[str, Tuple[str, str, str]] = {
    "anydesk": (
        "use the Disconnect button in the AnyDesk window, or right-click the AnyDesk icon near the clock and choose Exit",
        "open AnyDesk, then the menu > Settings > Security, and switch off unattended access (remove its password)",
        "uninstall AnyDesk (Windows: Settings > Apps > Installed apps)"),
    "teamviewer": (
        "use the Close button of the small control window, or exit TeamViewer from its icon near the clock",
        "open TeamViewer > Extras > Options > Security and clear \"Personal password (for unattended access)\", and untick "
        "\"Start TeamViewer with Windows\" under General; if the device is assigned to a TeamViewer account, remove it "
        "from that account's device list",
        "uninstall TeamViewer (Windows: Settings > Apps > Installed apps)"),
    "screenconnect": (
        "stop the \"ScreenConnect Client\" service (Windows: Services, or Task Manager > Services); the client has no "
        "window to end a session from",
        "an Access-mode client has no setting on this PC that turns unattended access off: it has to be uninstalled",
        "uninstall \"ScreenConnect Client (...)\" in Settings > Apps > Installed apps"),
    "rustdesk": (
        "use the Disconnect button in the RustDesk window, or exit RustDesk from its icon near the clock",
        "open RustDesk > Settings > Security and clear the permanent password (or choose the one-time password option)",
        "uninstall RustDesk (Windows: Settings > Apps > Installed apps)"),
    "atera": (
        "stop the \"AteraAgent\" service (Windows: Services)",
        "the agent belongs to the account that installed it: only uninstalling it, or that account's owner, removes it",
        "uninstall \"Atera Agent\" in Settings > Apps > Installed apps"),
    "splashtop": (
        "stop the \"Splashtop Remote Service\" (Windows: Services)",
        "the streamer belongs to the Splashtop account it was deployed from: only uninstalling it, or that account's owner, "
        "removes it",
        "uninstall \"Splashtop Streamer\" in Settings > Apps > Installed apps"),
    "netsupport": (
        "stop the NetSupport client process (Windows: Task Manager > Details, client32.exe)",
        "the client has no setting that turns control off: the program and its client32.ini have to be removed",
        "remove the folder that holds client32.ini after stopping the program (it often has no uninstaller); Aegis's "
        "persistence review lists what starts it"),
    "meshagent": (
        "stop the \"Mesh Agent\" service (Windows: Services; Linux: systemctl stop meshagent)",
        "the agent belongs to the MeshCentral group it joined: only uninstalling it, or that server's owner, removes it",
        "uninstall \"Mesh Agent\" (Windows: Settings > Apps > Installed apps; its folder holds MeshAgent.exe and MeshAgent.msh)"),
}
SCAM = ("If someone phoned or messaged you and asked you to install it, it is a scam: disconnect this PC from the internet now, "
        "uninstall the program, change your passwords (e-mail first, then banking) from another device and contact your bank.")
KEEP_FILES = "Keep its log and configuration files: they are evidence of what happened, and Aegis never deletes them."

# vendors' own clouds: a relay on these names is a specific company's instance, not a server somebody else runs
SCREENCONNECT_CLOUD = ("screenconnect.com", "connectwise.com", "myconnectwise.net", "connectwisecontrol.com")
RUSTDESK_CLOUD = ("rustdesk.com",)

# dynamic-DNS providers: a name anyone can point at their own PC or a rented server in minutes
DYNAMIC_DNS = (
    "duckdns.org", "ddns.net", "no-ip.com", "no-ip.org", "no-ip.biz", "no-ip.info", "noip.com", "hopto.org", "zapto.org",
    "servehttp.com", "myftp.org", "serveftp.com", "sytes.net", "redirectme.net", "myvnc.com", "publicvm.com", "ddnsking.com",
    "dynu.com", "dynu.net", "freeddns.org", "dyndns.org", "dyndns.biz", "3utilities.com", "bounceme.net", "servebeer.com",
    "gotdns.ch", "ignorelist.com", "chickenkiller.com", "strangled.net", "webhop.me", "serveminecraft.net",
)

PROCESS_STEMS: Dict[str, Tuple[str, ...]] = {
    "anydesk": ("anydesk",),
    "teamviewer": ("teamviewer", "teamviewer_service", "tv_w32", "tv_x64", "teamviewerd"),
    "screenconnect": ("screenconnect.clientservice", "screenconnect.windowsclient", "connectwisecontrol.client"),
    "rustdesk": ("rustdesk",),
    "splashtop": ("srservice", "srmanager", "splashtopstreamer", "srfeature"),
    "atera": ("ateraagent",),
    "meshagent": ("meshagent",),
    "netsupport": ("client32",),
}

# file names of remote-access programs: (pattern, tool); a copy of one of these in Downloads / Desktop / Temp is a portable copy
PORTABLE_NAMES: Tuple[Tuple["re.Pattern[str]", str], ...] = tuple((re.compile(p, re.I), name) for p, name in (
    (r"^anydesk.*\.(exe|msi|dmg|pkg|appimage)$", "AnyDesk"),
    (r"^teamviewer.*\.(exe|msi|dmg|pkg)$", "TeamViewer"),
    (r"^(screenconnect|connectwisecontrol).*\.(exe|msi)$", "ScreenConnect"),
    (r"^rustdesk.*\.(exe|msi|dmg|appimage|deb)$", "RustDesk"),
    (r"^splashtop.*\.(exe|msi|dmg)$", "Splashtop"),
    (r"^ultraviewer.*\.exe$", "UltraViewer"),
    (r"^(ammyy.*|aa_v3.*)\.exe$", "Ammyy Admin"),
    (r"^supremo.*\.exe$", "Supremo"),
    (r"^todesk.*\.(exe|dmg)$", "ToDesk"),
    (r"^hoptodesk.*\.(exe|dmg|appimage)$", "HopToDesk"),
    (r"^logmein.*\.(exe|msi)$", "LogMeIn"),
    (r"^meshagent.*\.(exe|msi)$", "MeshAgent"),
    (r"^client32\.exe$", "NetSupport"),
))

SERVICE_HINTS = ("screenconnect client", "mesh agent", "meshagent", "ateraagent", "anydesk", "teamviewer", "rustdesk",
                 "splashtop")
SERVICES_KEY = r"SYSTEM\CurrentControlSet\Services"
PROFILE_LIST_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
TEAMVIEWER_KEYS = (r"SOFTWARE\TeamViewer", r"SOFTWARE\WOW6432Node\TeamViewer")
ATERA_KEYS = (r"SOFTWARE\ATERA Networks\AlphaAgent", r"SOFTWARE\WOW6432Node\ATERA Networks\AlphaAgent")
SPLASHTOP_KEYS = (r"SOFTWARE\WOW6432Node\Splashtop Inc.\Splashtop Remote Server",
                  r"SOFTWARE\Splashtop Inc.\Splashtop Remote Server")
NON_PROFILES = frozenset({"public", "default", "default user", "all users"})

# =========================================================================== helpers (pure)


def _plural(n: int, one: str, many: str) -> str:
    return one if n == 1 else many


_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_SECRET_NAME = re.compile(r"pass|pwd|gsk|secret|token|salt|key_pair|securitykey|(?:mesh|server)id|(?:^|[_.\-])key$", re.I)


def clean(value: Any, limit: int = MAX_NAME) -> str:
    """Text from a log or a configuration as it goes into a report: control characters dropped, direction controls spelled out
    and the length capped."""
    return visible(_CONTROL.sub("", str(value))).strip()[:limit]


def is_secret_name(name: str) -> bool:
    """Whether a setting holds a password, hash, salt, token or key: its value is never kept, only whether one is set."""
    return bool(_SECRET_NAME.search(name))


def mask(value: Any) -> str:
    return "set" if str(value).strip() else ""


def _empty(value: Any) -> bool:
    """Whether a registry or settings value holds nothing: missing, zero length, blank or only NUL bytes."""
    if value is None:
        return True
    if isinstance(value, (bytes, bytearray)):
        return not bytes(value).strip(b"\0 ")
    if isinstance(value, str):
        return not value.strip("\0 ")
    return False


def _iso(when: Optional[dt.datetime]) -> str:
    return when.isoformat(sep=" ", timespec="seconds") if when else ""


_ISO_TIME = re.compile(r"(\d{4})-(\d{1,2})-(\d{1,2})[T ,]+(\d{1,2}):(\d{2})(?::(\d{2}))?")
_DMY_TIME = re.compile(r"(\d{1,2})[-./](\d{1,2})[-./](\d{4})[T ,]+(\d{1,2}):(\d{2})(?::(\d{2}))?")


def parse_time(text: str) -> Optional[dt.datetime]:
    """A time as a log writes it, in the PC's local time: ``2024-05-14, 10:02``, ``2024-05-14 10:02:11.123`` or the day-first
    ``14-05-2024 10:02:11`` / ``14.05.2024 10:02:11`` of TeamViewer (month-first when the second number cannot be a month)."""
    m = _ISO_TIME.search(text)
    if m:
        year, month, day, hour, minute, second = m.groups()
    else:
        m = _DMY_TIME.search(text)
        if not m:
            return None
        first, second_number, year, hour, minute, second = m.groups()
        day, month = (first, second_number) if int(second_number) <= 12 else (second_number, first)
    try:
        when = dt.datetime(int(year), int(month), int(day), int(hour), int(minute), int(second or 0))
    except ValueError:
        return None
    return when if 2000 <= when.year < 2100 else None


def split_address(text: str) -> Optional[Tuple[str, Optional[int]]]:
    """``(IP address, port)`` of ``1.2.3.4:5678``, ``[2001:db8::1]:5678`` or a bare address; None when it is not an address."""
    text = text.strip().rstrip(".,;")
    port: Optional[int] = None
    bracket = re.fullmatch(r"\[([0-9A-Fa-f:.]+)\](?::(\d{1,5}))?", text)
    if bracket:
        text, port = bracket.group(1), int(bracket.group(2)) if bracket.group(2) else None
    else:
        plain = re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})", text)
        if plain:
            text, port = plain.group(1), int(plain.group(2))
    try:
        return str(ipaddress.ip_address(text)), port
    except ValueError:
        return None


def host_of(value: str) -> Tuple[str, Optional[int]]:
    """Host and port of ``host``, ``host:port``, ``https://host:port/path`` or ``wss://[::1]:443/agent.ashx`` (no credentials,
    path or query); ``("", None)`` for nothing usable."""
    value = value.strip().strip("'\"")
    if not value:
        return "", None
    try:
        parts = urllib.parse.urlsplit(value if "://" in value else "//" + value)
        host = (parts.hostname or "").rstrip(".")
    except ValueError:
        return "", None
    try:
        port = parts.port
    except ValueError:
        port = None
    return host, port


def on_domain(host: str, domains: Sequence[str]) -> bool:
    host = host.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in domains)


def classify_host(host: str, is_bad: Optional[Callable[[str], bool]] = None) -> Tuple[Severity, List[str]]:
    """How much a server a tool is told to connect through should worry the owner of the PC, with the reasons. HIGH: a bare
    public IP address, a dynamic-DNS name, a host on the threat feed. MEDIUM: any other server somebody runs, including one on
    a private network."""
    host = host.lower().rstrip(".")
    reasons: List[str] = []
    high = False
    try:
        ip: Any = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        if ip.is_global:
            reasons.append("a bare IP address, not a registered name")
            high = True
        else:
            reasons.append("a private network address, so the server is inside your own network or VPN")
    elif on_domain(host, DYNAMIC_DNS):
        reasons.append("a dynamic-DNS name, which anyone can point at their own PC or a rented server in minutes")
        high = True
    if is_bad is not None and is_bad(host):
        reasons.append("listed as malicious on the threat feed")
        high = True
    if not reasons:
        reasons.append("a server run by whoever owns that name, not by the program's vendor")
    return (Severity.HIGH if high else Severity.MEDIUM), reasons


# --------------------------------------------------------------------------- text files


def sniff_encoding(head: bytes) -> str:
    """The encoding of a text file from its first bytes: a byte order mark, or the zero bytes of ASCII text in UTF-16."""
    if head.startswith(codecs.BOM_UTF16_LE):
        return "utf-16-le"
    if head.startswith(codecs.BOM_UTF16_BE):
        return "utf-16-be"
    sample = head[:64]
    half = len(sample) // 2
    if half >= 2:
        if sample[1::2].count(0) >= half * 0.75 and sample[0::2].count(0) <= half * 0.25:
            return "utf-16-le"
        if sample[0::2].count(0) >= half * 0.75 and sample[1::2].count(0) <= half * 0.25:
            return "utf-16-be"
    return "utf-8"


def decode_text(data: bytes, encoding: Optional[str] = None) -> str:
    """Text of a log or configuration: UTF-8 with or without a byte order mark, UTF-16 either way round, and Windows-1252 for
    the byte sequences that are not UTF-8 (a name with an accent in an older log)."""
    encoding = encoding or sniff_encoding(data)
    if encoding == "utf-8":
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("cp1252", errors="replace")
    else:
        text = data.decode(encoding, errors="replace")
    return text.lstrip("\ufeff")


def read_text(path: Path, limit: int = MAX_LOG_BYTES, tail: bool = True) -> Optional[str]:
    """A text file decoded; of a large one the last ``limit`` bytes (``tail``, cut at a line) or the first ``limit`` bytes. None
    when it cannot be read (missing, no permission): a file Aegis may not read is skipped, never an error."""
    try:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode):  # a pipe or a device would block the scan
            return None
        size = info.st_size
        with path.open("rb") as fh:
            encoding = sniff_encoding(fh.read(64))
            wide = encoding != "utf-8"
            count = limit - limit % 2 if wide else limit  # UTF-16 code units stay whole
            skip = max(0, size - count) if tail else 0
            skip += skip % 2 if wide else 0
            fh.seek(skip)
            data = fh.read(count)
    except OSError:
        return None
    if skip and encoding == "utf-8":  # a line cut in half (and maybe a character) at the start
        data = data.split(b"\n", 1)[1] if b"\n" in data else b""
    text = decode_text(data, encoding)
    if skip and encoding != "utf-8":
        text = text.split("\n", 1)[1] if "\n" in text else ""
    return text


def _is_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except OSError:
        return False


def _is_file(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError:
        return False


def file_named(folder: Path, name: str) -> Optional[Path]:
    """The file ``name`` in ``folder``, found without regard to case (Linux and macOS logs differ in case between versions)."""
    exact = folder / name
    if _is_file(exact):
        return exact
    try:
        for entry in folder.iterdir():
            if entry.name.lower() == name.lower() and _is_file(entry):
                return entry
    except OSError:
        pass
    return None


def newest(folder: Path, pattern: str, count: int) -> List[Path]:
    """The ``count`` most recently modified files in ``folder`` matching a glob pattern."""
    try:
        found = [p for p in folder.glob(pattern) if _is_file(p)]
    except OSError:
        return []

    def stamp(path: Path) -> float:
        try:
            return path.stat().st_mtime
        except OSError:
            return 0.0

    return sorted(found, key=stamp, reverse=True)[:count]


def _key(path: Any) -> str:
    return os.path.normcase(os.path.abspath(str(path)))


def parse_keyvalue(text: str) -> Dict[str, str]:
    """``key=value`` lines (AnyDesk ``*.conf``, MeshAgent ``*.msh``). A secret setting keeps only whether it is set."""
    out: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#;":
            continue
        name, eq, value = line.partition("=")
        name = name.strip()
        if eq and name:
            out[name] = mask(value) if is_secret_name(name) else value.strip()
    return out


def parse_ini(text: str) -> Dict[str, Dict[str, str]]:
    """``{section: {key: value}}`` of an INI file, section and key names in lower case (NetSupport ``client32.ini``). A secret
    setting keeps only whether it is set."""
    out: Dict[str, Dict[str, str]] = {"": {}}
    section = ""
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#;":
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            out.setdefault(section, {})
            continue
        name, eq, value = line.partition("=")
        name = name.strip().lower()
        if eq and name:
            out[section][name] = mask(value) if is_secret_name(name) else value.strip()
    return out


def _bracket_depth(text: str) -> int:
    depth = 0
    quote = ""
    for ch in text:
        if quote:
            quote = "" if ch == quote else quote
        elif ch in "'\"":
            quote = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
    return depth


_TOML_KEY = re.compile(r"""^\s*("[^"]+"|'[^']+'|[A-Za-z0-9_.\-]+)\s*=\s*(.*)$""")


def _toml_value(raw: str) -> str:
    raw = raw.strip()
    if raw[:1] in ("'", '"'):
        end = raw.find(raw[0], 1)
        return raw[1:end] if end > 0 else raw[1:]
    if raw.startswith("["):
        return "[array]"
    if raw.startswith("{"):
        return "{table}"
    return re.split(r"\s+#", raw, maxsplit=1)[0].strip()


def parse_toml(text: str) -> Dict[str, Dict[str, str]]:
    """``{table: {key: value}}`` of the small TOML files RustDesk writes (the top level is the table ``""``), without a TOML
    library (the supported Pythons start at 3.9). Arrays and inline tables (the key pair, the confirmed keys) are not read
    at all, and a secret setting keeps only whether it is set."""
    out: Dict[str, Dict[str, str]] = {"": {}}
    table = ""
    lines = iter(text.splitlines())
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        key = _TOML_KEY.match(line)
        if key is None:
            header = re.fullmatch(r"\[\[?([^\]]+)\]\]?", stripped)
            if header:
                table = header.group(1).strip().lower()
                out.setdefault(table, {})
            continue
        name = key.group(1).strip("'\"")
        raw = key.group(2)
        if raw.lstrip()[:1] in ("[", "{"):  # a multi-line array: skip to its end without keeping a character of it
            depth = _bracket_depth(raw)
            while depth > 0:
                nxt = next(lines, None)
                if nxt is None:
                    break
                depth += _bracket_depth(nxt)
        value = _toml_value(raw)
        out[table][name] = mask(value) if is_secret_name(name) else value
    return out


# =========================================================================== data


@dataclass
class Session:
    """One incoming connection (or, for an address seen in a trace, one sighting)."""

    when: Optional[dt.datetime]
    remote_id: str = ""
    name: str = ""
    ip: str = ""
    port: Optional[int] = None
    via: str = ""  # how it was accepted
    kind: str = ""  # what it was used for (TeamViewer: RemoteControl, FileTransfer ...)
    ended: Optional[dt.datetime] = None
    unattended: bool = False  # accepted with a stored password or token, nobody at the PC clicked Accept
    rejected: bool = False
    source: str = ""  # the log file


@dataclass
class Server:
    """A server a tool connects through."""

    role: str
    host: str
    port: Optional[int] = None
    vendor: bool = False  # the program vendor's own cloud
    always_high: bool = False  # reported HIGH whatever the host looks like (a NetSupport gateway)


@dataclass
class ToolReport:
    tool: str
    name: str
    location: str  # the folder, file or registry key that identifies this installation (the finding's location)
    found_at: List[str] = field(default_factory=list)
    logs: List[str] = field(default_factory=list)
    sessions: List[Session] = field(default_factory=list)
    addresses: List[Session] = field(default_factory=list)  # addresses seen in a trace
    rejected: int = 0
    unattended: List[str] = field(default_factory=list)  # why the PC can be reached without a click
    servers: List[Server] = field(default_factory=list)
    server_source: str = ""  # the configuration that names the servers
    facts: Dict[str, Any] = field(default_factory=dict)  # redacted settings that go into the evidence
    running: Optional[bool] = None


@dataclass
class Portable:
    path: Path
    tool: str
    modified: float
    size: int
    server: Optional[Server] = None  # a server named in the file name (RustDesk)
    running: Optional[bool] = None


@dataclass
class Profile:
    name: str
    home: Path
    appdata: Path  # Windows: AppData\Roaming
    local: Path  # Windows: AppData\Local


def _no_processes() -> Optional[List[Tuple[str, str]]]:
    return None


@dataclass
class Env:
    """Where the collectors look. ``system_env`` describes this machine; the tests build one over a temporary tree."""

    os_name: str = OS_NAME
    profiles: List[Profile] = field(default_factory=list)
    program_dirs: List[Path] = field(default_factory=list)
    program_data: Optional[Path] = None
    public: Optional[Path] = None
    service_profiles: List[Path] = field(default_factory=list)  # Windows: the Roaming folders of the service accounts
    temp_dirs: List[Path] = field(default_factory=list)
    extra_roots: List[Path] = field(default_factory=list)  # moved Downloads / Desktop folders
    root: Path = Path("/")  # Linux and macOS: where /etc, /opt and /usr live
    services: Dict[str, str] = field(default_factory=dict)  # remote-access services: name -> command line
    read_value: Callable[..., Any] = reg_read
    read_values: Callable[..., Dict[str, Any]] = reg_values
    read_subkeys: Callable[..., List[str]] = reg_subkeys
    processes: Callable[[], Optional[List[Tuple[str, str]]]] = _no_processes
    skipped: List[str] = field(default_factory=list)  # profiles that could not be read
    cache: Dict[str, Any] = field(default_factory=dict)

    @property
    def windows(self) -> bool:
        return self.os_name == "windows"

    @property
    def etc(self) -> Path:
        return self.root / "etc"

    def running(self) -> Optional[List[Tuple[str, str]]]:
        if "processes" not in self.cache:
            try:
                self.cache["processes"] = self.processes()
            except Exception as exc:  # a process list is a nicety, never a reason to fail
                log.debug("could not list the running processes: %s", exc)
                self.cache["processes"] = None
        return self.cache["processes"]


def _running_processes() -> Optional[List[Tuple[str, str]]]:
    """``(name, exe)`` of every running process (lower-case name), or None when they cannot be listed."""
    try:
        import psutil

        out = []
        for p in psutil.process_iter(["name", "exe"]):
            info = p.info
            out.append(((info.get("name") or "").lower(), info.get("exe") or ""))
        return out
    except Exception:  # pragma: no cover - psutil is a hard dependency
        return None


def tool_running(tool: str, procs: Optional[Sequence[Tuple[str, str]]], near: Optional[Path] = None) -> Optional[bool]:
    """Whether a program of this tool is running (None when the process list is not available). NetSupport's ``client32`` is a
    generic name, so it must run from the folder that holds its client32.ini."""
    if procs is None:
        return None
    stems = PROCESS_STEMS.get(tool, ())
    for name, exe in procs:
        stem = name[:-4] if name.endswith(".exe") else name
        if any(stem == s or (len(s) >= 6 and stem.startswith(s)) for s in stems):
            if tool != "netsupport" or (near is not None and exe and _key(Path(exe).parent) == _key(near)):
                return True
    return False


# =========================================================================== environment (this machine)


def _expand(value: str, environ: Dict[str, str]) -> str:
    env = {k.lower(): v for k, v in environ.items()}
    return re.sub(r"%([^%]+)%", lambda m: env.get(m.group(1).lower(), m.group(0)), value)


def _readable(folder: Path) -> bool:
    try:
        with os.scandir(folder):
            return True
    except OSError:
        return False


def windows_profiles(environ: Dict[str, str], read_value: Callable[..., Any], read_subkeys: Callable[..., List[str]],
                     home: Path, drive: str) -> Tuple[List[Profile], List[str]]:
    """Every user profile of a Windows PC: this user's, the folders under ``Users`` on the system drive and the profiles the
    registry lists (a profile on another drive). Profiles whose folder cannot be listed are named in the second list."""
    candidates: List[Path] = [home]
    users = Path(drive) / "Users"
    try:
        candidates += [p for p in users.iterdir() if p.name.lower() not in NON_PROFILES and _is_dir(p)]
    except OSError:
        pass
    for sid in read_subkeys("HKLM", PROFILE_LIST_KEY):
        if sid.startswith(("S-1-5-21-", "S-1-12-1-")):
            value = read_value("HKLM", f"{PROFILE_LIST_KEY}\\{sid}", "ProfileImagePath")
            if isinstance(value, str) and value.strip():
                candidates.append(Path(_expand(value.strip(), environ)))
    out: List[Profile] = []
    skipped: List[str] = []
    seen = set()
    for path in candidates:
        key = _key(path)
        if key in seen or not _is_dir(path):
            continue
        seen.add(key)
        current = key == _key(home)
        appdata = Path(environ["APPDATA"]) if current and environ.get("APPDATA") else path / "AppData" / "Roaming"
        local = Path(environ["LOCALAPPDATA"]) if current and environ.get("LOCALAPPDATA") else path / "AppData" / "Local"
        out.append(Profile(path.name, path, appdata, local))
        if not current and not _readable(path):
            skipped.append(path.name)
    return sorted(out, key=lambda p: str(p.home).lower()), sorted(skipped)


def read_services(read_subkeys: Callable[..., List[str]], read_value: Callable[..., Any]) -> Dict[str, str]:
    """``{service name: command line}`` of the services that belong to a remote-access tool."""
    out: Dict[str, str] = {}
    for name in read_subkeys("HKLM", SERVICES_KEY):
        if any(hint in name.lower() for hint in SERVICE_HINTS):
            image = read_value("HKLM", f"{SERVICES_KEY}\\{name}", "ImagePath")
            out[name] = image.strip() if isinstance(image, str) else ""
    return out


def fill_windows_env(env: Env, environ: Dict[str, str], home: Path, drive: str, windir: Path, temp: Path) -> Env:
    """The Windows places of ``env`` (profiles, Program Files, ProgramData, service accounts, Temp, the services that belong to
    a remote-access tool), from the environment variables and the registry readers ``env`` carries."""
    env.os_name = "windows"
    env.profiles, env.skipped = windows_profiles(environ, env.read_value, env.read_subkeys, home, drive)
    for var, default in (("ProgramFiles", r"C:\Program Files"), ("ProgramFiles(x86)", r"C:\Program Files (x86)"),
                         ("ProgramW6432", "")):
        value = environ.get(var) or default
        if value and _key(value) not in {_key(p) for p in env.program_dirs}:
            env.program_dirs.append(Path(value))
    env.program_data = Path(environ.get("ProgramData") or r"C:\ProgramData")
    env.public = Path(drive) / "Users" / "Public"
    roaming = Path("AppData") / "Roaming"
    env.service_profiles = [windir / "ServiceProfiles" / "LocalService" / roaming,
                            windir / "ServiceProfiles" / "NetworkService" / roaming,
                            windir / "System32" / "config" / "systemprofile" / roaming]
    env.temp_dirs = [temp, windir / "Temp"]
    env.services = read_services(env.read_subkeys, env.read_value)
    return env


def system_env() -> Env:
    """This machine: every user profile, Program Files, ProgramData, the registry and the running processes."""
    env = Env(processes=_running_processes)
    if OS_NAME == "windows":  # pragma: no cover - exercised on Windows CI
        from aegis.scanners.downloads import download_roots

        fill_windows_env(env, dict(os.environ), user_home(), system_drive(), windows_dir(), Path(tempfile.gettempdir()))
        env.extra_roots = download_roots()
    else:
        homes = discover_homes()
        env.profiles = sorted((Profile(h.name, h, h / ".config", h / ".local" / "share") for h in homes),
                              key=lambda p: str(p.home))
        env.skipped = sorted(p.name for p in env.profiles if not _readable(p.home))
        env.temp_dirs = [Path(tempfile.gettempdir()), Path("/var/tmp")]
    return env


# =========================================================================== AnyDesk

ANYDESK_METHODS: Dict[str, Tuple[str, bool]] = {
    "user": ("accepted by a person at the PC", False),
    "passwd": ("accepted with the unattended-access password", True),
    "password": ("accepted with the unattended-access password", True),
    "pwd": ("accepted with the unattended-access password", True),
    "token": ("accepted with a stored session token", True),
}
REJECTED_WORDS = frozenset({"rejected", "declined", "denied", "refused", "blocked"})
REQUESTED = "requested (the trace does not say whether it was accepted)"
_FIELD_SPLIT = re.compile(r"\t+|\s{2,}")


def parse_anydesk_connections(text: str, source: str = "connection_trace.txt") -> List[Session]:
    """Incoming sessions of ``connection_trace.txt``. A line reads ``Incoming  2024-05-14, 10:02  User  123456789  123456789``:
    direction, time, how it was accepted (``User``: somebody at the PC clicked Accept; ``Passwd`` / ``Token``: a stored password
    or token let the session in), the remote AnyDesk ID and its alias. Outgoing sessions and lines that do not parse are
    skipped."""
    out: List[Session] = []
    for line in text.splitlines():
        parts = [p.strip() for p in _FIELD_SPLIT.split(line.strip()) if p.strip()]
        if len(parts) < 2 or not parts[0].lower().startswith("incoming"):
            continue
        when = parse_time(parts[1])
        method = parts[2].lower() if len(parts) > 2 else ""
        ids = parts[3:5]
        if when is None and not ids:  # neither a time nor a remote ID: not a session
            continue
        via, unattended = ANYDESK_METHODS.get(method, (clean(parts[2], 24) if len(parts) > 2 else "", False))
        alias = clean(ids[1], 40) if len(ids) > 1 and ids[1] != ids[0] else ""
        out.append(Session(when=when, remote_id=clean(ids[0], 40) if ids else "", name=alias, via=via,
                           unattended=unattended, rejected=method in REJECTED_WORDS, source=source))
        if len(out) >= MAX_EVENTS:
            break
    return out


_TRACE_TIME = re.compile(r"(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})")
_TRACE_REQUEST = re.compile(r"Incoming session request:\s*(.*)", re.I)
_TRACE_REQUESTER = re.compile(r"^(?P<name>.*?)\s*\((?P<id>[^()]+)\)\s*\.?$")
_TRACE_LOGIN = re.compile(r"Logged in from\s+(\S+)", re.I)


def parse_anydesk_trace(text: str, source: str = "ad.trace") -> Tuple[List[Session], List[Session]]:
    """``(requests, addresses)`` from ``ad.trace`` / ``ad_svc.trace``: the lines ``Incoming session request: Name (ID).`` and
    ``... Logged in from 203.0.113.9:50443 on relay ...``, each with the time of its line. The address is the one the trace
    names: the connecting person's, or the relay AnyDesk used."""
    requests: List[Session] = []
    addresses: List[Session] = []
    for line in text.splitlines():
        if "ncoming session request" not in line and "ogged in from" not in line:
            continue
        stamp = _TRACE_TIME.search(line)
        when = parse_time(f"{stamp.group(1)} {stamp.group(2)}") if stamp else None
        request = _TRACE_REQUEST.search(line)
        if request:
            who = _TRACE_REQUESTER.match(request.group(1).strip())
            if who:
                requests.append(Session(when, remote_id=clean(who.group("id"), 40), name=clean(who.group("name"), 40),
                                        via=REQUESTED, source=source))
            else:
                requests.append(Session(when, name=clean(request.group(1).rstrip(". "), 40), via=REQUESTED, source=source))
            continue
        login = _TRACE_LOGIN.search(line)
        if login:
            address = split_address(login.group(1))
            if address:
                addresses.append(Session(when, ip=address[0], port=address[1], source=source))
        if len(requests) + len(addresses) >= MAX_EVENTS:
            break
    return requests, addresses


def _true(value: Optional[str]) -> bool:
    return (value or "").strip().lower() in ("true", "1", "yes", "on")


def anydesk_settings(conf: Dict[str, str]) -> Dict[str, Any]:
    """What matters in AnyDesk's ``*.conf`` (already free of secrets): whether an unattended-access password is set, this PC's
    AnyDesk ID, and whether access is limited to an allow-list."""
    password = any(
        value and (name == "ad.anynet.pwd_hash" or (name.startswith("ad.security.permission_profiles._unattended_access.")
                                                    and name.endswith((".pwd", ".pwd_hash"))))
        for name, value in conf.items())
    this_id = conf.get("ad.anynet.id", "")
    acl = conf.get("ad.security.acl_enabled")
    return {"password_set": password, "id": this_id if this_id.isdigit() else "",
            "acl_enabled": None if acl is None else _true(acl)}


def anydesk_dirs(env: Env) -> List[Path]:
    if env.windows:
        return ([env.program_data / "AnyDesk"] if env.program_data else []) + [p.appdata / "AnyDesk" for p in env.profiles]
    return [p.home / ".anydesk" for p in env.profiles] + [env.etc / "anydesk"]


def _service_notes(env: Env, *hints: str) -> List[str]:
    return [f"service {name}" for name in env.services if any(h in name.lower() for h in hints)]


def collect_anydesk(env: Env) -> List[ToolReport]:
    dirs = [d for d in anydesk_dirs(env) if _is_dir(d)]
    apps = [pf / "AnyDesk" / "AnyDesk.exe" for pf in env.program_dirs] if env.windows else [
        env.root / "Applications" / "AnyDesk.app", env.root / "usr" / "bin" / "anydesk"]
    found = [str(p) for p in dirs] + [str(p) for p in apps if _is_file(p) or _is_dir(p)] + _service_notes(env, "anydesk")
    var_log = [] if env.windows else [env.root / "var" / "log" / "anydesk.trace"]
    if not found and not any(_is_file(t) for t in var_log):
        return []
    rep = ToolReport("anydesk", "AnyDesk", found[0] if found else str(var_log[0]), found_at=found)
    seen = set()
    requests: List[Session] = []
    settings: Dict[str, Any] = {"password_set": False, "id": "", "acl_enabled": None}
    password_in: List[str] = []

    def trace(path: Path) -> None:
        text = read_text(path, MAX_TRACE_BYTES)
        if text is not None:
            rep.logs.append(str(path))
            asked, addresses = parse_anydesk_trace(text, path.name)
            requests.extend(asked)
            rep.addresses.extend(addresses)

    for folder in dirs:
        log_file = folder / "connection_trace.txt"
        text = read_text(log_file)
        if text is not None:
            rep.logs.append(str(log_file))
            for session in parse_anydesk_connections(text, log_file.name):
                ident = (session.when, session.remote_id, session.name, session.via)
                if ident not in seen:
                    seen.add(ident)
                    rep.sessions.append(session)
        for path in newest(folder, "ad*.trace", TRACE_FILES):
            trace(path)
        for conf_name in ("system.conf", "service.conf", "user.conf"):
            conf = read_text(folder / conf_name, MAX_CONFIG_BYTES, tail=False)
            if conf is None:
                continue
            got = anydesk_settings(parse_keyvalue(conf))
            if got["password_set"]:
                password_in.append(str(folder / conf_name))
            settings["password_set"] = settings["password_set"] or got["password_set"]
            settings["id"] = settings["id"] or got["id"]
            if got["acl_enabled"] is not None:
                settings["acl_enabled"] = bool(settings["acl_enabled"]) or got["acl_enabled"]
    for path in var_log:
        trace(path)
    rep.rejected = sum(1 for session in rep.sessions if session.rejected)
    if rep.rejected == len(rep.sessions):  # no connection_trace.txt to go by: the requests the traces name stand in for it
        rep.sessions += requests
    if settings["password_set"]:
        rep.unattended.append(f"a password for unattended access is set (in {password_in[0]})")
    rep.facts["unattended_password"] = "set" if settings["password_set"] else "not set"
    if settings["id"]:
        rep.facts["this_id"] = settings["id"]
    if settings["acl_enabled"] is not None:
        rep.facts["access_list"] = "enabled: only the listed IDs may connect" if settings["acl_enabled"] else "not enabled"
    return [rep]


# =========================================================================== TeamViewer


def parse_teamviewer_incoming(text: str, source: str = "Connections_incoming.txt") -> List[Session]:
    """Sessions of ``Connections_incoming.txt``: tab-separated remote ID, display name, start, end, local user, type and session
    id (not kept). Lines without a time, such as a header, are skipped."""
    out: List[Session] = []
    for line in text.splitlines():
        parts = [p.strip() for p in (line.split("\t") if "\t" in line else re.split(r"\s{2,}", line))]
        if len(parts) < 3:
            continue
        when = parse_time(parts[2])
        if when is None:
            continue
        out.append(Session(
            when=when, remote_id=clean(parts[0], 40), name=clean(parts[1], 40),
            ended=parse_time(parts[3]) if len(parts) > 3 else None, kind=clean(parts[5], 24) if len(parts) > 5 else "",
            source=source))
        if len(out) >= MAX_EVENTS:
            break
    return out


def teamviewer_settings(values: Dict[str, Any]) -> Dict[str, Any]:
    """What matters in TeamViewer's settings (registry values, or the Linux and macOS files), as ``{name: data}`` with names in
    lower case: a permanent password set (``SecurityPasswordAES``), a settings password (``OptionsPasswordAES``), start with the
    system (``Always_Online``), this PC's ID and the account the device is assigned to. No password data is returned."""
    def number(name: str) -> int:
        try:
            return int(values.get(name))
        except (TypeError, ValueError):
            return 0

    account = values.get("owningmanageraccountname")
    return {
        "password_set": not _empty(values.get("securitypasswordaes")),
        "settings_password": not _empty(values.get("optionspasswordaes")),
        "start_with_system": number("always_online") == 1,
        "id": str(number("clientid")) if number("clientid") else "",
        "account": clean(account, 60) if isinstance(account, str) and account.strip() else "",
    }


_TV_CONF = re.compile(r"^\s*\[(\w+)\]\s*(\w+)\s*=\s*(.*?)\s*$")


def parse_teamviewer_conf(text: str) -> Dict[str, Any]:
    """The Linux ``global.conf`` (``[int32] Always_Online = 1``, ``[bin] SecurityPasswordAES = "..."``) as the lower-case
    ``{name: data}`` that ``teamviewer_settings`` takes. A password keeps only a marker that it is set."""
    out: Dict[str, Any] = {}
    for line in text.splitlines():
        m = _TV_CONF.match(line)
        if not m:
            continue
        name, data = m.group(2).lower(), m.group(3).strip().strip('"')
        out[name] = mask(data) if is_secret_name(name) or name.endswith("aes") else data
    return out


def teamviewer_plist(data: bytes) -> Dict[str, Any]:
    """The macOS preferences file as the lower-case ``{name: data}`` that ``teamviewer_settings`` takes (empty when it cannot
    be read); a password keeps only a marker that it is set."""
    try:
        loaded = plistlib.loads(data)
    except Exception:
        return {}
    out: Dict[str, Any] = {}
    if isinstance(loaded, dict):
        for name, value in loaded.items():
            lowered = str(name).lower()
            out[lowered] = ("set" if value else "") if lowered.endswith("aes") else value
    return out


def teamviewer_registry(env: Env) -> Tuple[Dict[str, Any], List[str]]:
    """The TeamViewer values of the registry (both views, and the ``Version*`` keys older releases use) with names in lower
    case, and the keys that exist."""
    values: Dict[str, Any] = {}
    keys: List[str] = []
    for base in TEAMVIEWER_KEYS:
        for key in [base] + [f"{base}\\{s}" for s in env.read_subkeys("HKLM", base) if s.lower().startswith("version")]:
            found = env.read_values("HKLM", key)
            if found:
                keys.append(f"HKLM\\{key}")
            for name, data in found.items():
                if _empty(values.get(name.lower())):
                    values[name.lower()] = data
    return values, keys


def collect_teamviewer(env: Env) -> List[ToolReport]:
    values, keys = teamviewer_registry(env) if env.windows else ({}, [])
    candidates: List[Path] = []  # where Connections_incoming.txt lives
    installed: List[Path] = []
    config_note = ""
    if env.windows:
        installed = [pf / "TeamViewer" for pf in env.program_dirs]
        candidates = installed + [p.appdata / "TeamViewer" for p in env.profiles]
    elif env.os_name == "darwin":
        installed = [env.root / "Applications" / "TeamViewer.app"]
        candidates = [env.root / "Library" / "Logs" / "TeamViewer"] + [
            p.home / "Library" / "Logs" / "TeamViewer" for p in env.profiles]
        plist = env.root / "Library" / "Preferences" / "com.teamviewer.teamviewer.preferences.plist"
        try:
            values = teamviewer_plist(plist.read_bytes())
            config_note = str(plist) if values else ""
        except OSError:
            pass
    else:
        installed = [env.root / "opt" / "teamviewer"]
        try:
            candidates = sorted((env.root / "var" / "log").glob("teamviewer*"))
        except OSError:
            pass
        conf = read_text(env.root / "opt" / "teamviewer" / "config" / "global.conf", MAX_CONFIG_BYTES, tail=False)
        if conf is not None:
            values = parse_teamviewer_conf(conf)
            config_note = str(env.root / "opt" / "teamviewer" / "config" / "global.conf")
    present = [d for d in installed if _is_dir(d)]
    found = [str(p) for p in present] + keys + _service_notes(env, "teamviewer")
    folders = [d for d in candidates if _is_dir(d)]
    log_files = [f for f in (file_named(d, "Connections_incoming.txt") for d in folders) if f]
    if not found and not log_files and not config_note:
        return []
    location = found[0] if found else str(log_files[0] if log_files else config_note)
    rep = ToolReport("teamviewer", "TeamViewer", location, found_at=found)
    seen = set()
    for path in log_files:
        text = read_text(path)
        if text is None:
            continue
        rep.logs.append(str(path))
        for s in parse_teamviewer_incoming(text, path.name):
            ident = (s.when, s.remote_id, s.kind)
            if ident not in seen:
                seen.add(ident)
                rep.sessions.append(s)
    got = teamviewer_settings(values)
    where = keys[0] if keys else config_note
    if got["password_set"]:
        rep.unattended.append(f"a permanent password is set (Options > Security > Personal password, in {where})")
    if got["account"]:
        rep.unattended.append(f"this PC is assigned to the TeamViewer account {got['account']}; depending on its Easy access "
                              "setting the owner of that account can connect without a password")
    rep.facts["permanent_password"] = "set" if got["password_set"] else "not set"
    if got["settings_password"]:
        rep.facts["settings_password"] = "set"
    rep.facts["start_with_system"] = got["start_with_system"]
    if got["id"]:
        rep.facts["this_id"] = got["id"]
    if got["account"]:
        rep.facts["assigned_to_account"] = got["account"]
    return [rep]


# =========================================================================== ScreenConnect

_SC_QUERY = re.compile(r"""(?:^|[?\s"'>;])((?:[a-z]=[^&"'<>\s]*&)+[a-z]=[^&"'<>\s]*)""")
SC_TYPES = {"access": "Access (unattended)", "support": "Support (attended)", "meeting": "Meeting"}


def parse_screenconnect(text: str) -> Optional[Dict[str, Any]]:
    """The launch parameters of a ScreenConnect client from its service command line or ``system.config``:
    ``?e=Access&y=Guest&h=relay.example.com&p=8041&s=<session>&k=<key>&t=<name>&c=<property>``. Returns the session type, relay
    host and port, session name and properties; the session id (``s``) and the key (``k``) are never read out."""
    params: Dict[str, List[str]] = {}
    for query in _SC_QUERY.findall(text.replace("&amp;", "&")):
        parts = [part.partition("=") for part in query.split("&")]
        if not any(letter == "h" for letter, _, _ in parts):
            continue
        for letter, _, value in parts:
            if letter in ("e", "h", "p", "t", "c"):  # never s (the session) or k (the key)
                params.setdefault(letter, []).append(urllib.parse.unquote_plus(value))
        break
    host = (params.get("h") or [""])[0].strip().lower().rstrip(".")
    if not host or not ("p" in params or "e" in params):
        return None
    try:
        port: Optional[int] = int(params["p"][0])
    except (KeyError, ValueError, IndexError):
        port = None
    kind = (params.get("e") or [""])[0].strip().lower()
    return {"type": kind, "host": host, "port": port, "name": clean((params.get("t") or [""])[0], 60),
            "properties": [clean(c, 60) for c in params.get("c", []) if c.strip()][:8]}


def image_path(command: str) -> str:
    """The program in a service command line (``"C:\\path with spaces\\x.exe" args`` or ``C:\\x.exe args``)."""
    command = command.strip()
    if command.startswith('"'):
        end = command.find('"', 1)
        return command[1:end] if end > 0 else command[1:]
    m = re.match(r"(.+?\.exe)\b", command, re.I)
    return m.group(1) if m else command.split(" ")[0]


_SC_FOLDER = re.compile(r"^screenconnect client \(([^)]+)\)$", re.I)


def collect_screenconnect(env: Env) -> List[ToolReport]:
    if not env.windows:
        return []
    instances: Dict[str, Dict[str, Any]] = {}
    for name, command in env.services.items():
        m = re.match(r"screenconnect client \(([^)]+)\)", name, re.I)
        if m:
            instances.setdefault(m.group(1).lower(), {"id": m.group(1)}).update(service=name, command=command)
    for pf in env.program_dirs:
        try:
            entries = [e for e in pf.iterdir() if _SC_FOLDER.match(e.name) and _is_dir(e)]
        except OSError:
            continue
        for folder in entries:
            iid = _SC_FOLDER.match(folder.name).group(1)  # type: ignore[union-attr]
            instances.setdefault(iid.lower(), {"id": iid}).setdefault("dir", folder)
    out: List[ToolReport] = []
    for key in sorted(instances):
        inst = instances[key]
        folder = inst.get("dir")
        params = parse_screenconnect(inst.get("command", ""))
        config = folder / "system.config" if folder else None
        if params is None and config is not None:
            text = read_text(config, MAX_CONFIG_BYTES, tail=False)
            params = parse_screenconnect(text) if text else None
        service_key = f"HKLM\\{SERVICES_KEY}\\{inst['service']}" if "service" in inst else ""
        found = ([str(folder)] if folder else []) + ([f"service {inst['service']}"] if "service" in inst else [])
        rep = ToolReport("screenconnect", "ScreenConnect (ConnectWise Control)", str(folder) if folder else service_key,
                         found_at=found, server_source=service_key or str(config or ""))
        rep.facts["instance_id"] = inst["id"]
        if params:
            kind = params["type"]
            rep.facts["session_type"] = SC_TYPES.get(kind, clean(kind, 20) or "unknown")
            relay = f"{params['host']}:{params['port']}" if params["port"] else params["host"]
            vendor = on_domain(params["host"], SCREENCONNECT_CLOUD)
            rep.facts["relay"] = relay + (" (the vendor's cloud: an instance run by a specific company)" if vendor else "")
            if params["name"]:
                rep.facts["session_name"] = params["name"]
            if params["properties"]:
                rep.facts["properties"] = params["properties"]
            rep.servers.append(Server("relay", params["host"], params["port"], vendor=vendor))
            if kind == "access":
                rep.unattended.append("this is an Access client: it stays installed and its operator can connect whenever the "
                                      "PC is on, without anyone clicking Accept")
        out.append(rep)
    return out


# =========================================================================== RustDesk


def rustdesk_settings(main: Dict[str, str], options: Dict[str, str]) -> Dict[str, Any]:
    """What matters in RustDesk's ``RustDesk.toml`` (top level) and ``RustDesk2.toml`` (top level and ``[options]``): whether a
    permanent password and a server key are set, this PC's ID, and the servers named. Secrets are already reduced to markers.
    A permanent password does not let anybody in when the verification method is the one-time password only, or when every
    session has to be accepted with a click."""
    method = options.get("verification-method", "")
    mode = options.get("approve-mode", "")
    ignored = ("the verification method allows only the one-time password" if method == "use-temporary-password"
               else "every session has to be accepted with a click (approve mode)" if mode == "click" else "")
    servers = []
    for role, name in (("rendezvous server", "custom-rendezvous-server"), ("relay server", "relay-server"),
                       ("API server", "api-server")):
        host, port = host_of(options.get(name, ""))
        if host:
            servers.append((role, host, port))
    rendezvous, port = host_of(main.get("rendezvous_server", ""))
    if rendezvous and not any(h == rendezvous for _, h, _ in servers):
        servers.append(("rendezvous server", rendezvous, port))
    return {
        "password_set": bool(main.get("password")) and not ignored,
        "password_stored": bool(main.get("password")),
        "password_ignored": ignored,
        "id": main.get("id", "") if main.get("id", "").isdigit() else "",
        "key_set": bool(options.get("key")),
        "verification_method": clean(method, 40),
        "approve_mode": clean(mode, 40),
        "servers": servers,
    }


_RUSTDESK_LOG = re.compile(
    r"\[(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})(?:\.\d+)?(?: ([+-])(\d{2}):?(\d{2}))?\].*?Connection opened from (\S+)")


def parse_rustdesk_log(text: str, source: str = "rustdesk.log") -> List[Session]:
    """Incoming connections of a RustDesk server log: ``[2024-05-14 10:02:11.123456 +00:00] INFO ... Connection opened from
    203.0.113.9:50443.`` The time is converted to this PC's local time when the line carries an offset."""
    out: List[Session] = []
    for line in text.splitlines():
        if "Connection opened from" not in line:
            continue
        m = _RUSTDESK_LOG.search(line)
        if not m:
            continue
        address = split_address(m.group(6))
        when = parse_time(f"{m.group(1)} {m.group(2)}")
        if when and m.group(3):
            offset = dt.timedelta(hours=int(m.group(4)), minutes=int(m.group(5)))
            zone = dt.timezone(-offset if m.group(3) == "-" else offset)
            try:
                when = when.replace(tzinfo=zone).astimezone().replace(tzinfo=None)
            except (OverflowError, OSError, ValueError):
                pass
        if address:
            out.append(Session(when, ip=address[0], port=address[1], source=source))
        if len(out) >= MAX_EVENTS:
            break
    return out


def rustdesk_name_host(name: str) -> Optional[Server]:
    """The server a portable copy is built for: RustDesk reads it from the file name, ``rustdesk-host=<server>,key=<key>.exe``
    (the key is not kept)."""
    m = re.search(r"host=([^,]+)", name, re.I)
    if not m:
        return None
    host, port = host_of(re.sub(r"\.(exe|msi)$", "", m.group(1), flags=re.I))
    return Server("rendezvous server", host, port, vendor=on_domain(host, RUSTDESK_CLOUD)) if host else None


def rustdesk_config_dirs(env: Env) -> List[Path]:
    if env.windows:
        return [p.appdata / "RustDesk" / "config" for p in env.profiles] + [
            s / "RustDesk" / "config" for s in env.service_profiles]
    if env.os_name == "darwin":
        return [p.home / "Library" / "Preferences" / "com.carriez.RustDesk" for p in env.profiles]
    return [p.home / ".config" / "rustdesk" for p in env.profiles]


def rustdesk_log_dirs(env: Env) -> List[Path]:
    if env.windows:
        roots = [p.appdata / "RustDesk" / "log" for p in env.profiles] + [s / "RustDesk" / "log" for s in env.service_profiles]
        return roots + [r / "server" for r in roots]
    if env.os_name == "darwin":
        return [p.home / "Library" / "Logs" / "RustDesk" / "server" for p in env.profiles]
    return [p.home / ".local" / "share" / "logs" / "RustDesk" / "server" for p in env.profiles]


def collect_rustdesk(env: Env) -> List[ToolReport]:
    config_dirs = [d for d in rustdesk_config_dirs(env) if _is_dir(d)]
    apps = [pf / "RustDesk" for pf in env.program_dirs] if env.windows else [
        env.root / "Applications" / "RustDesk.app", env.root / "usr" / "bin" / "rustdesk", env.root / "usr" / "lib" / "rustdesk"]
    found = [str(d) for d in config_dirs] + [str(a) for a in apps if _is_dir(a) or _is_file(a)] + _service_notes(env, "rustdesk")
    if not found:
        return []
    rep = ToolReport("rustdesk", "RustDesk", found[0], found_at=found)
    password_in = ignored = ""
    stored = key_set = False
    this_id = ""
    methods: List[str] = []
    approve: List[str] = []
    servers: List[Tuple[str, str, Optional[int]]] = []
    for folder in config_dirs:
        main = read_text(folder / "RustDesk.toml", MAX_CONFIG_BYTES, tail=False)
        second = read_text(folder / "RustDesk2.toml", MAX_CONFIG_BYTES, tail=False)
        first_tables = parse_toml(main or "")
        second_tables = parse_toml(second or "")
        got = rustdesk_settings({**second_tables[""], **first_tables[""]},
                                {**first_tables.get("options", {}), **second_tables.get("options", {})})
        if got["password_set"] and not password_in:
            password_in = str(folder / "RustDesk.toml")
        stored = stored or got["password_stored"]
        ignored = ignored or got["password_ignored"]
        key_set = key_set or got["key_set"]
        this_id = this_id or got["id"]
        if got["verification_method"]:
            methods.append(got["verification_method"])
        if got["approve_mode"]:
            approve.append(got["approve_mode"])
        for entry in got["servers"]:
            if entry not in servers:
                servers.append(entry)
        if got["servers"] and not rep.server_source:
            rep.server_source = str(folder / "RustDesk2.toml")
    for role, host, port in servers:
        rep.servers.append(Server(role, host, port, vendor=on_domain(host, RUSTDESK_CLOUD)))
    if password_in:
        rep.unattended.append(f"a permanent password is set (in {password_in}); anyone who has it and knows this PC's ID "
                              "can connect without anyone clicking Accept")
    rep.facts["permanent_password"] = "set" if stored else "not set"
    if stored and not password_in:
        rep.facts["permanent_password_note"] = f"set, but {ignored}"
    rep.facts["server_key"] = "set" if key_set else "not set"
    if this_id:
        rep.facts["this_id"] = this_id
    if methods:
        rep.facts["verification_method"] = methods[0]
    if approve:
        rep.facts["approve_mode"] = approve[0]
    seen = set()
    for folder in [d for d in rustdesk_log_dirs(env) if _is_dir(d)]:
        for path in newest(folder, "*.log", RUSTDESK_LOGS):
            text = read_text(path, MAX_TRACE_BYTES)
            if text is None:
                continue
            sessions = parse_rustdesk_log(text, path.name)
            if sessions:
                rep.logs.append(str(path))
            for s in sessions:
                ident = (s.when, s.ip, s.port)
                if ident not in seen:
                    seen.add(ident)
                    rep.sessions.append(s)
    return [rep]


# =========================================================================== Atera, Splashtop


def collect_atera(env: Env) -> List[ToolReport]:
    if not env.windows:
        return []
    values: Dict[str, Any] = {}
    keys: List[str] = []
    for key in ATERA_KEYS:
        found = env.read_values("HKLM", key)
        if found:
            keys.append(f"HKLM\\{key}")
            for name, data in found.items():
                values.setdefault(name.lower(), data)
    folders = [pf / "ATERA Networks" for pf in env.program_dirs if _is_dir(pf / "ATERA Networks")]
    found_at = [str(f) for f in folders] + keys + _service_notes(env, "ateraagent")
    if not found_at:
        return []
    rep = ToolReport("atera", "Atera agent", found_at[0], found_at=found_at)
    login = values.get("integratorlogin")
    if isinstance(login, str) and login.strip():
        rep.facts["managed_by"] = clean(login, 80)
    for name, label in (("accountid", "account_id"), ("companyid", "company_id")):
        if not _empty(values.get(name)):
            rep.facts[label] = clean(values[name], 40)
    who = f" ({rep.facts['managed_by']})" if "managed_by" in rep.facts else ""
    rep.unattended.append(f"the Atera agent is installed: the account that deployed it{who} can reach this PC at any time, "
                          "without anyone clicking Accept")
    return [rep]


def collect_splashtop(env: Env) -> List[ToolReport]:
    if not env.windows:
        return []
    keys = [f"HKLM\\{key}" for key in SPLASHTOP_KEYS if env.read_values("HKLM", key) or env.read_subkeys("HKLM", key)]
    folders = [pf / "Splashtop" for pf in env.program_dirs if _is_dir(pf / "Splashtop")]
    found_at = [str(f) for f in folders] + keys + _service_notes(env, "splashtop")
    if not found_at:
        return []
    rep = ToolReport("splashtop", "Splashtop Streamer", found_at[0], found_at=found_at)
    rep.unattended.append("the Splashtop Streamer is installed: the Splashtop account it was deployed from can reach this PC at "
                          "any time, without anyone clicking Accept")
    return [rep]


# =========================================================================== NetSupport, MeshAgent


def netsupport_settings(ini: Dict[str, Dict[str, str]]) -> Dict[str, Any]:
    """What matters in NetSupport's ``client32.ini`` (secrets already reduced to markers): the gateways the client phones
    home to, and whether it hides from the user (silent, no tray icon, cannot be disconnected)."""
    http = ini.get("http", {})
    client = ini.get("client", {})
    servers = []
    for gateway, port in (("gatewayaddress", "port"), ("secondarygateway", "secondaryport")):
        host, parsed_port = host_of(http.get(gateway, ""))
        if host:
            try:
                number: Optional[int] = parsed_port or int(http.get(port, "")) or None
            except ValueError:
                number = parsed_port
            servers.append((host, number))
    hidden = []
    if client.get("silent") == "1":
        hidden.append("silent mode (no notice when someone connects)")
    if client.get("systray") == "0":
        hidden.append("no icon near the clock")
    if client.get("disabledisconnect") == "1":
        hidden.append("the user cannot disconnect")
    return {"servers": servers, "hidden": hidden, "gateway_key_set": bool(http.get("gsk"))}


def collect_netsupport(env: Env) -> List[ToolReport]:
    out: List[ToolReport] = []
    for folder, names in walk_roots(env):
        ini_name = next((n for n in names if n.lower() == "client32.ini"), None)
        if ini_name is None:
            continue
        text = read_text(folder / ini_name, MAX_CONFIG_BYTES, tail=False)
        if text is None:
            continue
        got = netsupport_settings(parse_ini(text))
        exe = any(n.lower() == "client32.exe" for n in names)
        rep = ToolReport("netsupport", "NetSupport Manager client", str(folder / ini_name), found_at=[str(folder)],
                         server_source=str(folder / ini_name))
        rep.facts["client32_exe_present"] = exe
        rep.facts["gateway_key"] = "set" if got["gateway_key_set"] else "not set"
        if got["hidden"]:
            rep.facts["hides_from_the_user"] = got["hidden"]
        for host, port in got["servers"]:
            rep.servers.append(Server("gateway", host, port, always_high=True))
        why = "the NetSupport client is installed: whoever runs NetSupport Manager with its settings can control this PC"
        rep.unattended.append(why + (f"; it hides from the user ({', '.join(got['hidden'])})" if got["hidden"] else ""))
        out.append(rep)
    return out


def parse_meshagent(text: str) -> Dict[str, Any]:
    """``MeshAgent.msh``: ``MeshName`` (the group), ``MeshType`` and ``MeshServer=wss://host:443/agent.ashx`` (several may be
    listed). The group and server ids are reduced to markers by ``parse_keyvalue`` and not kept."""
    conf = parse_keyvalue(text)
    servers = []
    for item in re.split(r"[,;|]", conf.get("MeshServer", "")):
        host, port = host_of(item)
        if host:
            servers.append((host, port or (443 if item.strip().lower().startswith("wss") else None)))
    return {"name": clean(conf.get("MeshName", ""), 60), "servers": servers, "group_set": bool(conf.get("MeshID"))}


def collect_meshagent(env: Env) -> List[ToolReport]:
    folders: List[Tuple[Path, List[str]]] = list(walk_roots(env))
    for name, command in env.services.items():
        if "mesh agent" in name.lower() or "meshagent" in name.lower():
            program = Path(image_path(command)) if command else None
            if program is not None and _is_dir(program.parent):
                try:
                    folders.append((program.parent, [e.name for e in program.parent.iterdir()]))
                except OSError:
                    pass
    out: List[ToolReport] = []
    seen = set()
    for folder, names in folders:
        msh = [n for n in names if n.lower().endswith(".msh")]
        if not msh or not any(n.lower().startswith("meshagent") for n in names):
            continue
        path = folder / sorted(msh, key=lambda n: n.lower() != "meshagent.msh")[0]
        if _key(path) in seen:
            continue
        seen.add(_key(path))
        text = read_text(path, MAX_CONFIG_BYTES, tail=False)
        if text is None:
            continue
        got = parse_meshagent(text)
        rep = ToolReport("meshagent", "MeshAgent (MeshCentral)", str(path), found_at=[str(folder)] + _service_notes(env, "mesh"),
                         server_source=str(path))
        if got["name"]:
            rep.facts["group"] = got["name"]
        rep.facts["group_id"] = "set" if got["group_set"] else "not set"
        for host, port in got["servers"]:
            rep.servers.append(Server("MeshCentral server", host, port))
        server = f" on {got['servers'][0][0]}" if got["servers"] else ""
        rep.unattended.append(f"MeshAgent is installed: the MeshCentral server{server} can reach this PC at any time, without "
                              "anyone clicking Accept")
        out.append(rep)
    return out


def walk_roots(env: Env) -> List[Tuple[Path, List[str]]]:
    """``(folder, file names)`` for the folders where a NetSupport client or a MeshAgent is installed or planted: Program Files
    and ProgramData down to two sub-levels (``NetSupport\\NetSupport Manager``), the user profiles' AppData, Downloads, Desktop
    and Temp, the Public folder and the temp folders down to one. Breadth first, so the top of every root is seen before the
    entry cap ends the walk; computed once per scan; links are not followed."""
    if "walk" in env.cache:
        return env.cache["walk"]
    roots: List[Tuple[Path, int]] = []  # (folder, levels of folders to list: 1 is the folder itself)
    if env.windows:
        roots += [(p, 3) for p in env.program_dirs] + ([(env.program_data, 3)] if env.program_data else [])
        roots += [(env.public, 2)] if env.public else []
        for p in env.profiles:
            roots += [(p.appdata, 2), (p.local, 2), (p.local / "Temp", 2), (p.home / "Downloads", 2), (p.home / "Desktop", 2)]
    else:
        roots += [(env.root / "opt", 3), (env.root / "usr" / "local" / "mesh_services", 3)]
    roots += [(t, 2) for t in env.temp_dirs] + [(r, 2) for r in env.extra_roots]
    out: List[Tuple[Path, List[str]]] = []
    seen = set()
    budget = MAX_WALK
    queue: List[Tuple[Path, int]] = []
    for root, depth in roots:
        if _key(root) not in seen:
            seen.add(_key(root))
            queue.append((root, depth))
    index = 0
    while index < len(queue) and budget > 0:
        folder, depth = queue[index]
        index += 1
        files: List[str] = []
        try:
            with os.scandir(folder) as entries:
                for entry in entries:
                    budget -= 1
                    if budget <= 0:
                        break
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            key = _key(entry.path)
                            if depth > 1 and key not in seen:
                                seen.add(key)
                                queue.append((Path(entry.path), depth - 1))
                        else:
                            files.append(entry.name)
                    except OSError:
                        continue
        except OSError:
            continue
        out.append((folder, files))
    env.cache["walk"] = out
    return out


# =========================================================================== portable copies


def portable_tool(name: str) -> Optional[str]:
    for pattern, tool in PORTABLE_NAMES:
        if pattern.match(name):
            return tool
    return None


_NAME_KEY = re.compile(r"(key=)[^,]*?(?=\.(?:exe|msi|dmg|appimage|deb)$|,|$)", re.I)


def shown_name(name: str) -> str:
    """A file name as a finding shows it: direction controls spelled out, and the server key that a RustDesk copy carries in its
    name (``rustdesk-host=<server>,key=<key>.exe``) left out, like every key."""
    return visible(_NAME_KEY.sub(r"\1<omitted>", name))


def portable_roots(env: Env) -> List[Path]:
    """Downloads, Desktop and Temp of every profile (and the moved folders and temp folders of this PC), each once."""
    candidates: List[Path] = []
    for p in env.profiles:
        candidates += [p.home / "Downloads", p.home / "Desktop", p.home / "OneDrive" / "Desktop"]
        if env.windows:
            candidates.append(p.local / "Temp")
    candidates += env.temp_dirs + env.extra_roots
    out: List[Path] = []
    seen = set()
    for folder in candidates:
        if _key(folder) not in seen and _is_dir(folder):
            seen.add(_key(folder))
            out.append(folder)
    return out


def find_portable(env: Env) -> List[Portable]:
    """Remote-access programs sitting in the top level of Downloads, Desktop and Temp by their file name."""
    procs = env.running()
    out: List[Portable] = []
    seen = set()
    for folder in portable_roots(env):
        try:
            with os.scandir(folder) as entries:
                for count, entry in enumerate(entries):
                    if count >= MAX_LISTING:
                        break
                    tool = portable_tool(entry.name)
                    if tool is None:
                        continue
                    try:
                        if not entry.is_file(follow_symlinks=False):
                            continue
                        st = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if _key(entry.path) in seen:
                        continue
                    seen.add(_key(entry.path))
                    running = None if procs is None else any(exe and _key(exe) == _key(entry.path) for _, exe in procs)
                    out.append(Portable(Path(entry.path), tool, st.st_mtime, st.st_size,
                                        rustdesk_name_host(entry.name) if tool == "RustDesk" else None, running))
        except OSError:
            continue
    return sorted(out, key=lambda p: str(p.path).lower())


# =========================================================================== collection

COLLECTORS: Tuple[Callable[[Env], List[ToolReport]], ...] = (
    collect_anydesk, collect_teamviewer, collect_screenconnect, collect_rustdesk, collect_splashtop, collect_atera,
    collect_netsupport, collect_meshagent)
COLLECTOR_NAMES = ("AnyDesk", "TeamViewer", "ScreenConnect", "RustDesk", "Splashtop", "Atera", "NetSupport", "MeshAgent")


def collect(env: Env, cancelled: Callable[[], bool] = lambda: False) -> Tuple[List[ToolReport], List[str]]:
    """Every installation of a remote-access tool on this PC, and the names of the tools that could not be reviewed (a collector
    that fails is skipped, the others still run)."""
    reports: List[ToolReport] = []
    failed: List[str] = []
    procs = env.running()
    for name, collector in zip(COLLECTOR_NAMES, COLLECTORS):
        if cancelled():
            break
        try:
            found = collector(env)
        except Exception as exc:
            log.warning("review of %s failed: %s", name, exc, exc_info=True)
            failed.append(f"{name} ({type(exc).__name__})")
            continue
        for rep in found:
            near = Path(rep.location).parent if rep.tool == "netsupport" else None
            rep.running = tool_running(rep.tool, procs, near)
        reports += found
    return reports, failed


# =========================================================================== findings

MITRE = "T1219.002"  # Remote Access Tools: Remote Desktop Software (the parent technique has sub-techniques since ATT&CK v17)


def _row(s: Session) -> Dict[str, Any]:
    address = s.ip + (f":{s.port}" if s.port else "")
    row = {"time": _iso(s.when), "remote_id": s.remote_id, "name": s.name, "address": address, "how": s.via,
           "type": s.kind, "ended": _iso(s.ended), "log": s.source}
    return {k: v for k, v in row.items() if v}


def _newest_first(items: Sequence[Session]) -> List[Session]:
    return sorted(items, key=lambda s: s.when or dt.datetime.min, reverse=True)


def _distinct(values: Sequence[str]) -> List[str]:
    out: List[str] = []
    for v in values:
        if v and v not in out:
            out.append(v)
    return out


def _evidence(rep: ToolReport) -> Dict[str, Any]:
    ev: Dict[str, Any] = {"tool": rep.name, "found_at": rep.found_at[:MAX_PATHS]}
    if rep.running is not None:
        ev["running"] = rep.running
    return ev


def incoming_finding(rep: ToolReport, now: dt.datetime, days: int = RECENT_DAYS) -> Optional[Finding]:
    """The incoming connections a tool's own log lists: MEDIUM, or LOW when every one is older than ``days`` days."""
    sessions = _newest_first([s for s in rep.sessions if not s.rejected])
    if not sessions:
        return None
    cutoff = now - dt.timedelta(days=days)
    old = all(s.when is not None and s.when < cutoff for s in sessions)
    timed = [s.when for s in sessions if s.when]
    first, last = (min(timed), max(timed)) if timed else (None, None)
    addresses = _newest_first(rep.addresses)
    ids = _distinct([s.remote_id for s in sessions])
    ips = _distinct([s.ip for s in addresses] + [s.ip for s in sessions])
    stored = sum(1 for s in sessions if s.unattended)
    n = len(sessions)
    in_window = sum(1 for s in sessions if s.when is None or s.when >= cutoff)
    when = (f"between {_iso(first)[:16]} and {_iso(last)[:16]}" if first and last and first != last
            else f"on {_iso(first)[:16]}" if first else "at times the log does not give")
    noun = ("incoming session request", "incoming session requests") if all(
        s.via == REQUESTED for s in sessions) else ("incoming connection", "incoming connections")
    parts = [f"{rep.name} keeps a log of who connected to this PC. It lists {n} {_plural(n, *noun)} {when}"
             + (f", from {len(ids)} remote {_plural(len(ids), 'ID', 'IDs')}" if ids else "") + "."]
    if stored:
        parts.append(f"{stored} of them {_plural(stored, 'was', 'were')} accepted with a stored password or token, so nobody "
                     "at the PC had to click Accept.")
    if ips:
        parts.append(f"The logs name {len(ips)} remote {_plural(len(ips), 'address', 'addresses')} (the connecting person's, "
                     "or the relay the program used).")
    if rep.rejected:
        parts.append(f"{rep.rejected} further {_plural(rep.rejected, 'attempt was', 'attempts were')} rejected.")
    if old:
        parts.append(f"All of them are older than {days} days.")
    parts.append("A log entry shows that somebody connected, not that anything bad happened: you, an IT provider or a relative "
                 "who helps you appear here too. But if you did not expect these, someone controlled this PC at those times: "
                 "think about what was open on the screen then (online banking, e-mail, documents) and treat the passwords "
                 "used on this PC as exposed.")
    end = HOW[rep.tool][0]
    recommendation = (f"Compare the times above with when you used {rep.name} or were helped by someone you know. To end a "
                      f"session now, {end}. If you did not expect these connections, or a caller asked you to install "
                      f"{rep.name}, it is a scam or a break-in: disconnect this PC from the internet, uninstall {rep.name}, "
                      f"change your passwords (e-mail first, then banking) from another device and contact your bank. "
                      f"{KEEP_FILES}")
    ev = _evidence(rep)
    ev.update({"logs": rep.logs[:MAX_PATHS], "sessions": n, "first": _iso(first), "last": _iso(last),
               "sessions_in_window": in_window, "window_days": days, "remote_ids": ids[:MAX_IDS],
               "remote_addresses": ips[:MAX_IDS], "accepted_with_stored_password": stored, "rejected": rep.rejected,
               "recent_sessions": [_row(s) for s in sessions[:MAX_RECENT]],
               "recent_addresses": [_row(s) for s in addresses[:MAX_RECENT]]})
    if len(ids) > MAX_IDS:
        ev["remote_ids_total"] = len(ids)
    if len(ips) > MAX_IDS:
        ev["remote_addresses_total"] = len(ips)
    if "this_id" in rep.facts:
        ev["this_id"] = rep.facts["this_id"]
    ev = {k: v for k, v in ev.items() if v != "" and v != [] and v is not None}
    title = f"{rep.name}: {n} {_plural(n, *noun)} in its own log" + (
        f", the latest on {_iso(last)[:10]}" if last else "")
    return Finding(
        rule_id="AEG-RA-INCOMING", title=title, severity=Severity.LOW if old else Severity.MEDIUM,
        category=Category.SUSPICIOUS, description=" ".join(parts), location=rep.logs[0] if rep.logs else rep.location,
        evidence=ev, recommendation=recommendation, scanner="remoteaccess", mitre=[MITRE] + (["T1078"] if stored else []))


def unattended_finding(rep: ToolReport) -> Optional[Finding]:
    """Unattended access: someone can connect without anybody at the PC clicking Accept (MEDIUM)."""
    if not rep.unattended:
        return None
    _, remove, uninstall = HOW[rep.tool]
    ident = f" This PC's ID is {rep.facts['this_id']}." if "this_id" in rep.facts else ""
    note = " An access list limits who may connect to the IDs on it." if str(rep.facts.get("access_list", "")).startswith(
        "enabled") else ""
    description = (f"{rep.name} on this PC can be reached without anyone clicking Accept: {'; '.join(rep.unattended)}.{ident} "
                   "Whoever has the credential, or runs the server or account behind it, can connect at any time while the PC "
                   "is on and online, also when you are away from it. IT providers use this on purpose; tech-support scammers "
                   f"set it up so that they can return later.{note} Aegis shows only whether a password is set, never the "
                   "password.")
    recommendation = (f"Keep it only if you set it up yourself or an IT provider you know manages this PC (ask them to confirm). "
                      f"Otherwise remove it: {remove}; or {uninstall}. {SCAM}")
    ev = _evidence(rep)
    ev["reasons"] = rep.unattended
    ev.update(rep.facts)
    if rep.servers:
        ev["servers"] = [_server_row(s) for s in rep.servers]
    return Finding(
        rule_id="AEG-RA-UNATTENDED", title=f"{rep.name} is set up for unattended access", severity=Severity.MEDIUM,
        category=Category.SUSPICIOUS, description=description, location=rep.location, evidence=ev,
        recommendation=recommendation, scanner="remoteaccess", mitre=[MITRE, "T1133"])


def _server_row(s: Server) -> Dict[str, Any]:
    row: Dict[str, Any] = {"role": s.role, "host": s.host}
    if s.port:
        row["port"] = s.port
    if s.vendor:
        row["operator"] = "the program vendor's cloud"
    return row


def relay_finding(rep: ToolReport, is_bad: Optional[Callable[[str], bool]] = None) -> Optional[Finding]:
    """A server somebody runs sits between this PC and whoever connects: HIGH for a bare public IP address, a dynamic-DNS
    name, a host on the threat feed or a NetSupport gateway; MEDIUM for any other self-hosted server. A vendor's own cloud is
    not reported."""
    rows: List[Dict[str, Any]] = []
    severity = Severity.MEDIUM
    bad = False
    for s in rep.servers:
        if s.vendor:
            continue
        level, reasons = classify_host(s.host, is_bad)
        if s.always_high:
            level = Severity.HIGH
            reasons = ["a NetSupport gateway, the way NetSupport RAT campaigns reach infected PCs through firewalls"] + [
                r for r in reasons if not r.startswith("a server run by")]
        severity = max(severity, level)
        bad = bad or "listed as malicious on the threat feed" in reasons
        rows.append({**_server_row(s), "severity": level.name.lower(), "reasons": reasons})
    if not rows:
        return None
    rows.sort(key=lambda row: row["severity"] != "high")  # the worst server first (the sort keeps the order otherwise)
    first = rows[0]
    address = first["host"] + (f":{first['port']}" if first.get("port") else "")
    others = len(_distinct([row["host"] for row in rows])) - 1
    more = f" (+{others} more)" if others > 0 else ""
    gateway = rep.tool == "netsupport"
    if gateway:
        title = f"{rep.name} phones home to a gateway: {address}{more}"
        what = (f"The NetSupport client on this PC is set to connect out to the gateway {address}{more} and wait there for its "
                "operator, through any firewall. A gateway is rarely needed on a home or office network, and NetSupport RAT "
                "campaigns configure exactly this.")
    else:
        title = f"{rep.name} is set to connect through a server you may not control: {address}{more}"
        what = (f"{rep.name} on this PC is set to use the {first['role']} {address}{more}, not the vendor's own servers. "
                "Whoever runs that server brokers every connection to this PC and can see when it is online.")
    description = (f"{what} Why this stands out: {'; '.join(first['reasons'])}. "
                   + ("If this PC belongs to a company, a school or an IT provider that runs that server, this is expected; "
                      "otherwise a person you may not know can reach it." if severity < Severity.HIGH else
                      "Unless you can name who runs that server, assume a stranger can reach this PC."))
    uninstall = HOW[rep.tool][2]
    if severity >= Severity.HIGH:
        recommendation = (f"Treat this PC as compromised unless you can name who runs {first['host']}: disconnect it from the "
                          f"internet, {uninstall}, run a full Aegis scan and change your passwords (e-mail first, then banking) "
                          f"from another device. If a caller asked you to install it, it is a scam: contact your bank too. "
                          f"{KEEP_FILES}")
    else:
        recommendation = (f"Ask whoever manages this PC whether {first['host']} is their server. If nobody can say, {uninstall}. "
                          f"{SCAM}")
    ev = _evidence(rep)
    ev["servers"] = rows
    ev["configuration"] = rep.server_source
    ev["threat_feed"] = bad
    ev.update({k: v for k, v in rep.facts.items() if k in ("this_id", "group", "session_type", "instance_id")})
    return Finding(
        rule_id="AEG-RA-RELAY", title=title, severity=severity, category=Category.SUSPICIOUS, description=description,
        location=rep.server_source or rep.location, evidence=ev, recommendation=recommendation, scanner="remoteaccess",
        mitre=[MITRE, "T1133"])


def portable_findings(items: Sequence[Portable], now: dt.datetime, days: int = RECENT_DAYS,
                      is_bad: Optional[Callable[[str], bool]] = None) -> List[Finding]:
    """A remote-access program that is not installed sits in Downloads, Desktop or Temp: how scam sessions start. MEDIUM; LOW
    when the file is older than ``days`` days and not running. A RustDesk copy that names its server also gets the relay
    finding."""
    out: List[Finding] = []
    cutoff = (now - dt.timedelta(days=days)).timestamp()
    for item in items:
        recent = item.modified >= cutoff or bool(item.running)
        folder = str(item.path.parent)
        name = shown_name(item.path.name)
        modified = dt.datetime.fromtimestamp(item.modified) if item.modified > 0 else None
        facts = (f", last changed {_iso(modified)[:10]}" if modified else "") + (" and is running now" if item.running else "")
        description = (f"{name} is a {item.tool} program in {folder}{facts}. A program run straight from "
                       "Downloads or Desktop is not installed, so it does not show up in the list of apps, yet while it runs "
                       "the person who has its ID or address can see and control this PC. This is how tech-support scam "
                       "sessions start: the caller asks the victim to download and run it. A copy can also be left behind by "
                       "a session you started yourself.")
        recommendation = ("If you started the session yourself and it is over, delete the file (Aegis does not delete it for "
                          f"you). {SCAM} If the tool is installed, the incoming-connection findings of this scan show who "
                          "connected.")
        ev: Dict[str, Any] = {"tool": item.tool, "file": clean(name, 120), "path": str(item.path), "folder": folder,
                              "size": item.size, "modified": _iso(modified)}
        if item.running is not None:
            ev["running"] = item.running
        if item.server is not None:
            ev["server_in_file_name"] = item.server.host + (f":{item.server.port}" if item.server.port else "")
        out.append(Finding(
            rule_id="AEG-RA-PORTABLE", title=f"Portable remote-access program: {name}",
            severity=Severity.MEDIUM if recent else Severity.LOW, category=Category.SUSPICIOUS, description=description,
            location=str(item.path), evidence=ev, recommendation=recommendation, scanner="remoteaccess", mitre=[MITRE]))
        if item.server is not None and not item.server.vendor:
            rep = ToolReport("rustdesk", f"{item.tool} (portable copy {clean(name, 60)})", str(item.path),
                             found_at=[str(item.path)], servers=[item.server], server_source=str(item.path), running=item.running)
            relay = relay_finding(rep, is_bad)
            if relay is not None:
                out.append(relay)
    return out


def tools_check(reports: Sequence[ToolReport], portable: Sequence[Portable], findings: Sequence[Finding], failed: Sequence[str],
                env: Env, days: int, feed_missing: bool) -> CheckResult:
    """AEG-RA-CHK: PASS when tools are found but none allows unattended access, uses a server somebody runs or logged a recent
    session; FAIL with the reasons; SKIP when there is nothing to review (naming where Aegis looked)."""
    names = _distinct([r.name for r in reports])
    n = len(names)
    serious = [f for f in findings if f.severity >= Severity.MEDIUM]
    problems: List[str] = []
    for name in names:
        mine = [f for f in serious if f.evidence.get("tool") == name]
        bits = []
        if any(f.rule_id == "AEG-RA-UNATTENDED" for f in mine):
            bits.append("unattended access is set up")
        relays = [f for f in mine if f.rule_id == "AEG-RA-RELAY"]
        if relays:
            hosts = ", ".join(_distinct([s["host"] for f in relays for s in f.evidence["servers"]])[:3])
            bits.append(f"connects through {hosts}")
        for f in mine:
            if f.rule_id == "AEG-RA-INCOMING":
                k = f.evidence["sessions_in_window"]
                bits.append(f"{k} incoming {_plural(k, 'session', 'sessions')} in the last {days} days")
        if bits:
            problems.append(f"{name}: {', '.join(bits)}")
    copies = [f for f in serious if f.rule_id == "AEG-RA-PORTABLE"]
    if copies:
        problems.append(f"{len(copies)} portable remote-access {_plural(len(copies), 'program', 'programs')} in Downloads, "
                        "Desktop or Temp")
    named = [f for f in serious if f.rule_id == "AEG-RA-RELAY" and f.evidence.get("tool") not in names]  # portable copies
    if named:
        hosts = ", ".join(_distinct([s["host"] for f in named for s in f.evidence["servers"]])[:3])
        problems.append(f"{_plural(len(named), 'a portable copy is', 'portable copies are')} set to connect through {hosts}")
    notes = ""
    if env.skipped:
        admin = "an administrator" if env.windows else "root (sudo)"
        notes += (f" Not examined (no permission): {', '.join(env.skipped[:5])}"
                  + (", ..." if len(env.skipped) > 5 else "") + f"; run Aegis as {admin} to include "
                  f"{_plural(len(env.skipped), 'that profile', 'those profiles')}.")
    if failed:
        notes += f" Could not be reviewed: {', '.join(failed)}."
    if feed_missing:
        notes += " " + UPDATE_HINT
    low = [f for f in findings if f.severity < Severity.MEDIUM]
    if not reports and not portable:
        where = checked_locations(env)
        detail = (f"No remote-access tool was found ({', '.join(COLLECTOR_NAMES[:-1])} and {COLLECTOR_NAMES[-1]}). Looked in: "
                  f"{where}.{notes}")
        return CheckResult(CHECK_ID, CHECK_TITLE, CheckStatus.WARN if failed else CheckStatus.SKIP, detail, Category.SUSPICIOUS,
                           "remoteaccess")
    found = (f"{n} remote-access {_plural(n, 'tool', 'tools')} found ({', '.join(names)})" if names
             else "No remote-access tool is installed")
    if problems:
        detail = f"{found}. " + "; ".join(problems) + "." + notes
        return CheckResult(CHECK_ID, CHECK_TITLE, CheckStatus.FAIL, detail, Category.SUSPICIOUS, "remoteaccess")
    detail = (f"{found}, none configured for unattended access, no incoming sessions in the last {days} days." if names
              else f"{found}.")
    if low:
        detail += f" {len(low)} older {_plural(len(low), 'item is', 'items are')} listed as low-priority findings."
    status = CheckStatus.WARN if failed else CheckStatus.PASS
    return CheckResult(CHECK_ID, CHECK_TITLE, status, detail + notes, Category.SUSPICIOUS, "remoteaccess")


def checked_locations(env: Env) -> str:
    """Where the scan looked, for the SKIP message."""
    if env.windows:
        places = ([str(env.program_data / "AnyDesk")] if env.program_data else []) + [
            str(pf) for pf in env.program_dirs] + ([str(env.program_data)] if env.program_data else []) + [
            f"AppData of {len(env.profiles)} user {_plural(len(env.profiles), 'profile', 'profiles')}",
            "the HKLM registry (TeamViewer, Atera, Splashtop) and the Windows services"]
    else:
        users = len(env.profiles)
        places = [f"the home folders of {users} {_plural(users, 'user', 'users')}", str(env.etc / "anydesk"),
                  str(env.root / "opt")]
    places.append("Downloads, Desktop and Temp for portable copies")
    return "; ".join(places)


# =========================================================================== scanner


def review(ctx: ScanContext, env: Optional[Env] = None) -> Iterator[Emitted]:
    env = env or system_env()
    days = int(ctx.options.get("remoteaccess_days", RECENT_DAYS) or RECENT_DAYS)
    now = dt.datetime.now()
    ctx.report("remoteaccess", "reading the remote-access tools' settings and logs")
    reports, failed = collect(env, lambda: ctx.cancelled)
    if ctx.cancelled:
        return
    ctx.report("remoteaccess", "looking for portable remote-access programs")
    try:
        portable = find_portable(env)
    except Exception as exc:  # a failing folder walk must not hide what the collectors found
        log.warning("portable program search failed: %s", exc, exc_info=True)
        portable, failed = [], failed + ["portable programs (" + type(exc).__name__ + ")"]
    is_bad = feed_checker(ctx.signatures)
    findings: List[Finding] = []
    for rep in reports:
        for finding in (incoming_finding(rep, now, days), unattended_finding(rep), relay_finding(rep, is_bad)):
            if finding is not None:
                findings.append(finding)
    findings += portable_findings(portable, now, days, is_bad)
    ctx.bump("remoteaccess_tools", len(reports))
    ctx.bump("remoteaccess_sessions", sum(len(r.sessions) for r in reports))
    yield from findings
    hosts = any(not s.vendor for r in reports for s in r.servers)
    yield tools_check(reports, portable, findings, failed, env, days, is_bad is None and hosts)


@register
class RemoteAccessScanner(Scanner):
    name = "remoteaccess"
    title = "Remote-access tool review"
    description = ("Reviews the remote-access tools installed on this PC (AnyDesk, TeamViewer, ScreenConnect, RustDesk, "
                   "Splashtop, Atera, NetSupport, MeshAgent): their own connection logs (who connected and when), unattended "
                   "access passwords, self-hosted or suspicious relay servers, and portable copies in Downloads and Desktop - "
                   "the traces of a tech-support scam. Passwords are never read out.")
    platforms = ("windows", "linux", "darwin")

    def run(self, ctx: ScanContext) -> Iterator[Emitted]:
        ctx.report(self.name, "reviewing remote-access tools")
        try:
            yield from review(ctx)
        except Exception as exc:  # never raise out of run()
            log.warning("remote-access review failed: %s", exc, exc_info=True)
            yield CheckResult(CHECK_ID, CHECK_TITLE, CheckStatus.ERROR, f"{type(exc).__name__}: {exc}", Category.SUSPICIOUS,
                              self.name)
