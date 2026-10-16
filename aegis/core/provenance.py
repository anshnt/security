"""Download provenance: where a downloaded file came from, and what that says about it.

Browsers and download tools record the origin of what they save, and the operating system keeps it with the file:

* **Windows** - the ``Zone.Identifier`` alternate data stream (the Mark-of-the-Web). It holds ``ZoneId=3`` (internet) and,
  for Chrome, Edge, Brave and Firefox, the ``HostUrl`` the file was fetched from and the ``ReferrerUrl`` of the page that
  offered it.
* **macOS** - ``com.apple.quarantine`` names the app that downloaded the file (``0083;65a1b2c3;Safari;UUID``) and
  ``com.apple.metadata:kMDItemWhereFroms`` is a binary plist with the download address and the referring page.
* **Linux** - Chrome / Chromium, ``wget --xattr`` and ``curl --xattr`` write ``user.xdg.origin.url`` and
  ``user.xdg.referrer.url``.

The origin is a signal, never a verdict: legitimate software is sometimes shared through file-hosting sites, and a tool that
strips the record leaves nothing to read. ``classify_download`` turns the origin and the file name into a list of reasons to
doubt a download, each with a severity, a rule id and the ATT&CK ids; it is a pure function with no I/O, so every branch is
unit-tested on any OS. Reading the record (``read_origin``) never raises: it gives None for a file that has none, for a file
system that keeps none (FAT, many network shares) and for any error.

Addresses shown in findings go through ``safe_url``: query strings and fragments are removed (signed download links carry
tokens) and the payload of a ``data:`` address, which is the file itself, is never kept.
"""

from __future__ import annotations

import functools
import ipaddress
import os
import plistlib
import re
import urllib.parse
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from aegis.core.models import Severity
from aegis.core.platform import IS_MAC, IS_WINDOWS

ZONE_STREAM = ":Zone.Identifier"
XDG_ORIGIN = "user.xdg.origin.url"
XDG_REFERRER = "user.xdg.referrer.url"
MAC_QUARANTINE = "com.apple.quarantine"
MAC_WHERE_FROMS = "com.apple.metadata:kMDItemWhereFroms"
MAX_ATTR_BYTES = 256 * 1024  # a longer record is not a download origin; it is dropped unread
MAX_URL_CHARS = 2048

SOURCE_ZONE = "zone.identifier"
SOURCE_QUARANTINE = "quarantine"
SOURCE_XATTR = "xattr"

BADSOURCE = "AEG-DL-BADSOURCE"
SMUGGLED = "AEG-DL-SMUGGLED"
RAWIP = "AEG-DL-RAWIP"
FILEHOST = "AEG-DL-FILEHOST"
INSECURE = "AEG-DL-INSECURE"
WEBDAV = "AEG-DL-WEBDAV"
DECEPTIVE = "AEG-DL-DECEPTIVE"

# =========================================================================== file types

PROGRAM_EXTS = frozenset({"exe", "msi", "msix", "msixbundle", "appx", "appxbundle", "appinstaller", "scr", "com", "pif", "cpl",
                          "application", "jar", "dmg", "pkg", "mpkg", "deb", "rpm", "appimage", "run"})
SCRIPT_EXTS = frozenset({"bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "reg", "sh"})
EXECUTABLE_EXTS = PROGRAM_EXTS | SCRIPT_EXTS  # runs code when it is opened
SHORTCUT_EXTS = frozenset({"lnk", "url", "library-ms", "search-ms"})
CONTAINER_EXTS = frozenset({"iso", "img", "vhd", "vhdx", "zip", "rar", "7z"})  # what HTML smuggling usually builds
SMUGGLED_EXTS = EXECUTABLE_EXTS | SHORTCUT_EXTS | CONTAINER_EXTS
SHARE_EXTS = EXECUTABLE_EXTS | SHORTCUT_EXTS  # what a WebDAV share is used to deliver
# the real extensions of a disguised download, and the document / picture / media types it pretends to be
DISGUISED_EXTS = frozenset({"exe", "scr", "com", "pif", "cpl", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "wsh",
                            "hta", "lnk", "url", "msi", "jar"})
DECOY_EXTS = frozenset({"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "txt", "csv", "odt", "ods", "odp", "jpg",
                        "jpeg", "png", "gif", "bmp", "tif", "tiff", "webp", "heic", "mp3", "mp4", "wav", "avi", "mov", "mkv"})

# Paste, anonymous file-sharing and short-link hosts that malware campaigns lean on. Matched on the registrable-domain suffix
# (``host == entry`` or ``host`` ends with ``.entry``), never as a substring. Legitimate files are shared through them too.
FILE_HOSTS: Tuple[str, ...] = (
    "pastebin.com", "paste.ee", "rentry.co", "hastebin.com", "justpaste.it", "transfer.sh", "temp.sh", "file.io", "0x0.st",
    "bashupload.com", "tmpfiles.org", "gofile.io", "pixeldrain.com", "workupload.com", "catbox.moe", "anonfiles.com",
    "bayfiles.com", "mediafire.com", "mega.nz", "mega.io", "cdn.discordapp.com", "media.discordapp.net", "bit.ly",
    "tinyurl.com", "is.gd", "t.ly", "cutt.ly", "rb.gy", "shorturl.at",
)

# the characters that reorder how a name is shown (U+202A-202E embeddings and overrides, U+2066-2069 isolates); the plain
# direction marks U+200E / U+200F / U+061C that appear in genuine Arabic and Hebrew names do not
BIDI_CONTROLS = "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
_BLANKS = r"\s\u200b-\u200d\u2060\u3164\u2800\ufeff"  # white space and the invisible characters used to pad a name
_TRAILING_BLANKS = re.compile(f"[{_BLANKS}]+$")
_PADDING = re.compile(f"[{_BLANKS}]{{5,}}$")
_BIDI = re.compile(f"[{BIDI_CONTROLS}]")

# =========================================================================== data


@dataclass
class Origin:
    """What the system recorded about where a file was downloaded from."""

    zone: Optional[int] = None  # 3 = internet, 4 = untrusted (Windows); None where no zone is kept
    host_url: str = ""  # the address the file was fetched from
    referrer_url: str = ""  # the page that offered it
    agent: str = ""  # macOS: the app that downloaded it
    source: str = ""  # zone.identifier | quarantine | xattr


@dataclass(frozen=True)
class Reason:
    """One reason to doubt a download."""

    severity: Severity
    rule_id: str
    text: str  # a clause that reads on from "it was flagged because": "it was downloaded from ..."
    mitre: Tuple[str, ...] = ()


# =========================================================================== parsers (pure)


def _to_int(value: Any) -> Optional[int]:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def parse_zone_identifier(text: str) -> Optional[Origin]:
    """Origin from the text of a ``Zone.Identifier`` stream, or None when it records no zone and no address. Tolerant of a
    byte-order mark, CRLF or LF line ends, any letter case, a missing ``[ZoneTransfer]`` header and unknown keys."""
    values: Dict[str, str] = {}
    section = ""  # stays empty when the header is missing
    for line in str(text or "").replace("\x00", "").replace("\ufeff", "").splitlines():
        line = line.strip()
        if not line or line.startswith((";", "#")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue
        if section not in ("", "zonetransfer"):
            continue
        key, equals, value = line.partition("=")
        if equals:
            values.setdefault(key.strip().lower(), value.strip())
    zone = _to_int(values.get("zoneid"))
    host, referrer = values.get("hosturl", "")[:MAX_URL_CHARS], values.get("referrerurl", "")[:MAX_URL_CHARS]
    if zone is None and not host and not referrer:
        return None
    return Origin(zone, host, referrer, "", SOURCE_ZONE)


def parse_quarantine(value: str) -> str:
    """Name of the app that downloaded a file, from a ``com.apple.quarantine`` value (``0083;65a1b2c3;Safari;UUID``); an empty
    string when the value has no app name."""
    parts = str(value or "").strip().split(";")
    if len(parts) < 3:
        return ""
    return re.sub(r"[\x00-\x1f\x7f]", "", parts[2]).strip()[:80]


def parse_where_froms(data: bytes) -> List[str]:
    """Addresses from the binary plist of ``kMDItemWhereFroms`` (the download address first, the referring page second); an
    empty list for anything that is not such a plist."""
    try:
        items = plistlib.loads(data)
    except Exception:  # not a plist, truncated or hostile: there is nothing to read
        return []
    if not isinstance(items, list):
        return []
    urls = [item.strip()[:MAX_URL_CHARS] if isinstance(item, str) else "" for item in items][:4]
    return urls if any(urls) else []


# =========================================================================== reading the record


def _decode(data: bytes) -> str:
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", errors="replace")
    return data.decode("utf-8-sig", errors="replace")


def _read_stream(path: Union[str, "os.PathLike[str]"]) -> Optional[bytes]:
    """The ``Zone.Identifier`` stream of a file (Windows), or None when the file has none."""
    try:
        with open(str(path) + ZONE_STREAM, "rb") as fh:
            return fh.read(MAX_ATTR_BYTES)
    except OSError:
        return None


@functools.lru_cache(maxsize=1)
def _libc_getxattr() -> Callable[..., int]:
    """``getxattr`` of the macOS C library (it takes a position and an options argument that Linux's does not)."""
    import ctypes
    import ctypes.util

    libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.dylib", use_errno=True)
    fn = libc.getxattr
    fn.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
    fn.restype = ctypes.c_ssize_t
    return fn


def _mac_getxattr(path: Union[str, "os.PathLike[str]"], name: str) -> Optional[bytes]:
    import ctypes

    fn = _libc_getxattr()
    raw_path, raw_name = os.fsencode(path), name.encode()
    size = fn(raw_path, raw_name, None, 0, 0, 0)
    if size <= 0 or size > MAX_ATTR_BYTES:
        return None
    buf = ctypes.create_string_buffer(size)
    got = fn(raw_path, raw_name, buf, size, 0, 0)
    return buf.raw[:got] if got > 0 else None


def _getxattr(path: Union[str, "os.PathLike[str]"], name: str) -> Optional[bytes]:
    """One extended attribute of a file, or None when it is missing or the file system keeps no attributes."""
    try:
        if IS_MAC:
            return _mac_getxattr(path, name)
        getter = getattr(os, "getxattr", None)  # not on Windows or macOS
        return getter(path, name)[:MAX_ATTR_BYTES] if getter else None
    except (OSError, ValueError):
        return None


def _attr_text(path: Union[str, "os.PathLike[str]"], name: str) -> str:
    data = _getxattr(path, name)
    return _decode(data).replace("\x00", "").strip()[:MAX_URL_CHARS] if data else ""


def _read_windows(path: Union[str, "os.PathLike[str]"]) -> Optional[Origin]:
    data = _read_stream(path)
    return parse_zone_identifier(_decode(data)) if data else None


def _read_mac(path: Union[str, "os.PathLike[str]"]) -> Optional[Origin]:
    quarantine = _attr_text(path, MAC_QUARANTINE)
    raw = _getxattr(path, MAC_WHERE_FROMS)
    urls = parse_where_froms(raw) if raw else []
    if not quarantine and not urls:
        return None
    return Origin(None, urls[0] if urls else "", urls[1] if len(urls) > 1 else "", parse_quarantine(quarantine),
                  SOURCE_QUARANTINE if quarantine else SOURCE_XATTR)


def _read_linux(path: Union[str, "os.PathLike[str]"]) -> Optional[Origin]:
    url, referrer = _attr_text(path, XDG_ORIGIN), _attr_text(path, XDG_REFERRER)
    return Origin(None, url, referrer, "", SOURCE_XATTR) if url or referrer else None


def read_origin(path: Union[str, "os.PathLike[str]"]) -> Optional[Origin]:
    """The recorded origin of a downloaded file, or None. Never raises."""
    try:
        if IS_WINDOWS:
            return _read_windows(path)
        return _read_mac(path) if IS_MAC else _read_linux(path)
    except Exception:  # an odd file system or a hostile attribute must not stop a scan
        return None


# =========================================================================== addresses (pure)


def url_scheme(url: str) -> str:
    """Lower-case scheme of an address (``unc`` for ``\\\\host\\share``); empty when it has none."""
    text = str(url or "").strip()
    if text.startswith("\\\\"):
        return "unc"
    scheme = text.partition(":")[0].lower()
    return scheme if len(scheme) > 1 and re.fullmatch(r"[a-z][a-z0-9+.-]*", scheme) else ""  # one letter is a drive


def url_host(url: str) -> str:
    """Lower-case host of an address (a ``blob:`` address is unwrapped, a WebDAV ``host@SSL`` name gives ``host``); empty when
    the address has none."""
    text = str(url or "").strip()
    if text[:5].lower() == "blob:":
        text = text[5:]
    if text.startswith("\\\\"):
        return re.split(r"[\\/@]", text[2:], maxsplit=1)[0].lower().strip(".")
    try:
        parts = urllib.parse.urlsplit(text)
        if parts.scheme.lower() == "file" and re.search(r"@(?:ssl|\d+)$", parts.netloc, re.I):
            return parts.netloc.partition("@")[0].lower().strip(".")
        return (parts.hostname or "").lower().strip(".")
    except ValueError:
        return ""


def _ip_address(host: str) -> Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def is_remote_share(url: str) -> bool:
    """True for a WebDAV or network-share address: ``\\\\host@SSL\\DavWWWRoot\\...``, anything with ``DavWWWRoot`` in it, or a
    ``file://host/...`` address with a host that is not this machine."""
    text = str(url or "").strip()
    if "davwwwroot" in text.lower():
        return True
    return url_scheme(text) in ("unc", "file") and url_host(text) not in ("", "localhost", "127.0.0.1", "::1")


def safe_url(url: str, max_path: int = 120) -> str:
    """An address as it may appear in a finding: no credentials, query string or fragment (a signed download link carries a
    token). ``data:`` addresses lose their payload, which is the file itself; anything unreadable gives an empty string."""
    text = str(url or "").strip()
    scheme = url_scheme(text)
    if scheme == "data":
        return "data:"
    if scheme == "blob":
        inner = safe_url(text[5:], max_path)
        return f"blob:{inner}" if inner else "blob:"
    if scheme in ("file", "unc"):
        text = re.sub(r"(?i)^(file://)[^/@\s:]+:[^/@\s]*@", r"\1", re.split(r"[?#]", text, maxsplit=1)[0])
        return text if len(text) <= max_path + 40 else text[:max_path + 37] + "..."
    from aegis.scanners.traces import strip_url  # the one place that cleans addresses for evidence

    return strip_url(text, max_path)


def origin_evidence(origin: Origin) -> Dict[str, Any]:
    """The origin as evidence for a finding: zone, agent and addresses without query strings."""
    return {"origin_source": origin.source, "zone": origin.zone, "host_url": safe_url(origin.host_url),
            "referrer_url": safe_url(origin.referrer_url), "agent": origin.agent}


def visible(text: str) -> str:
    """``text`` with direction-control characters spelled out (``<U+202E>``), so a report cannot be made to show a file name
    back to front."""
    return "".join(f"<U+{ord(c):04X}>" if c in BIDI_CONTROLS else c for c in text)


# =========================================================================== classification (pure)


def _plain(name: str) -> str:
    """A file name as its extensions read: without direction controls and without trailing blanks or invisible padding."""
    return _TRAILING_BLANKS.sub("", _BIDI.sub("", name))


def file_ext(name: str) -> str:
    """Lower-case extension of a file name without the dot, ignoring direction controls and trailing blanks."""
    stem, dot, ext = _plain(name).rpartition(".")
    return ext.lower() if dot else ""


def deceptive_name(name: str) -> List[Reason]:
    """Reasons a file name is built to mislead, whatever the origin: direction-control characters (the right-to-left override
    that turns ``invoice_fdp.exe`` into ``invoice_exe.pdf`` on screen), and a program or script dressed as a document, picture or
    media file with a double extension (``invoice.pdf.exe``), also when blanks push the real extension out of view
    (``report.docx      .exe``). ``setup.1.2.3.exe`` and ``archive.tar.gz`` are ordinary names."""
    out: List[Reason] = []
    bidi = sorted({c for c in name if c in BIDI_CONTROLS})
    if bidi:
        codes = ", ".join(f"U+{ord(c):04X}" for c in bidi)
        out.append(Reason(Severity.HIGH, DECEPTIVE,
                          f"its name contains the direction-control character {codes}, which makes Windows and many file "
                          "managers show part of the name (often the real extension) back to front", ("T1036.002",)))
    stem, dot, ext = _plain(name).rpartition(".")
    if not dot or ext.lower() not in DISGUISED_EXTS:
        return out
    padded = bool(_PADDING.search(stem))
    _, fake_dot, fake = _TRAILING_BLANKS.sub("", stem).rpartition(".")
    if fake_dot and fake.lower() in DECOY_EXTS:
        out.append(Reason(Severity.HIGH, DECEPTIVE,
                          f"its name has a double extension (.{fake.lower()} then .{ext.lower()}"
                          f"{', with blanks between them' if padded else ''}): the real type is .{ext.lower()}, a program or "
                          f"script, but the name makes it look like a .{fake.lower()} file", ("T1036.007",)))
    elif padded:
        out.append(Reason(Severity.HIGH, DECEPTIVE,
                          f"its name is padded with blanks before .{ext.lower()} so that the real extension is pushed out of "
                          "view in narrow file lists", ("T1036",)))
    return out


def _is_local_host(host: str) -> bool:
    address = _ip_address(host)
    if address is not None:
        return address.is_loopback or address.is_private or address.is_link_local
    return host == "localhost"


def classify_origin(name: str, origin: Optional[Origin],
                    is_bad_domain: Optional[Callable[[str], bool]] = None) -> List[Reason]:
    """Reasons to doubt a download from where it came from, strongest first; an empty list when the origin is unknown or
    unremarkable. ``is_bad_domain`` answers whether a host is on a malicious-domain / IP feed (None: no feed is loaded)."""
    out: List[Reason] = []
    if origin is None:
        return out
    ext = file_ext(name)
    host_url, referrer_url = origin.host_url.strip(), origin.referrer_url.strip()
    host, referrer_host = url_host(host_url), url_host(referrer_url)
    scheme = url_scheme(host_url)

    if is_bad_domain is not None:
        listed: List[str] = []
        for role, candidate in (("address the file was fetched from", host), ("page that offered it", referrer_host)):
            if candidate and candidate not in listed and is_bad_domain(candidate):
                listed.append(candidate)
                out.append(Reason(Severity.HIGH, BADSOURCE,
                                  f"the {role} ({candidate}) is on a malicious-domain or malicious-IP feed",
                                  ("T1204.002", "T1105")))
    if scheme in ("blob", "data") and ext in SMUGGLED_EXTS:
        out.append(Reason(Severity.MEDIUM, SMUGGLED,
                          f"the download address is a {scheme}: address, which means the web page built the file itself in "
                          "JavaScript instead of fetching it from a server (HTML smuggling, a way to slip containers and "
                          "programs past download filters)", ("T1027.006", "T1204.002")))
    shares = [u for u in (host_url, referrer_url) if is_remote_share(u)]
    if shares and ext in SHARE_EXTS:
        out.append(Reason(Severity.MEDIUM, WEBDAV,
                          f"it came from a WebDAV or network share ({url_host(shares[0]) or 'remote host'}), a way to deliver "
                          "files that makes a remote server look like a local folder and is used by search-ms and ClickFix "
                          "style campaigns", ("T1105",)))
    source_host = host or referrer_host  # the origin host: the download address, else the page that offered it
    address = _ip_address(source_host)
    if address is not None and address.is_global and ext in EXECUTABLE_EXTS:
        out.append(Reason(Severity.MEDIUM, RAWIP,
                          f"it was downloaded from a bare IP address ({source_host}) instead of a named website, which "
                          "software vendors rarely do", ("T1105",)))
    entry = next((e for e in FILE_HOSTS if source_host == e or source_host.endswith("." + e)), "")
    if entry and ext in EXECUTABLE_EXTS:
        out.append(Reason(Severity.LOW, FILEHOST,
                          f"it was downloaded from {source_host}, a paste, anonymous file-sharing or short-link service that "
                          "malware campaigns often use (legitimate files are shared this way too)", ("T1105",)))
    if host_url.lower().startswith("http://") and ext in EXECUTABLE_EXTS and not _is_local_host(host):
        out.append(Reason(Severity.LOW, INSECURE,
                          "it was downloaded over plain http://, so anyone on the network path could have replaced it",
                          ("T1105",)))
    return sorted(out, key=lambda r: -int(r.severity))


def classify_download(name: str, origin: Optional[Origin],
                      is_bad_domain: Optional[Callable[[str], bool]] = None) -> List[Reason]:
    """Every reason to doubt a download, from its origin and from its name, strongest first (origin before name when equal)."""
    return sorted(classify_origin(name, origin, is_bad_domain) + deceptive_name(name), key=lambda r: -int(r.severity))
