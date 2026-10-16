"""Web and network protection: hosts-file domain blocking and outbound IP blocking.

Both protections are explicit, need administrator/root rights and are fully reversible; no function
here raises - each returns ``{"ok", "changed", "message", "details"}``.

Domain blocking (``enable_web_protection`` / ``disable_web_protection`` / ``refresh_web_protection`` /
``web_protection_status``)
    Writes ``0.0.0.0 <domain>`` lines for the URLhaus domains in ``signatures.bad_domains`` (plus an optional
    user list) inside ONE clearly delimited managed block of the hosts file::

        # >>> Aegis web protection >>>
        ...
        # <<< Aegis web protection <<<

    Nothing outside the block is ever modified: user lines keep their exact bytes, line endings (CRLF/LF/mixed)
    and BOM. The file is replaced atomically after the previous content was saved to the backups directory
    (``webhosts-<timestamp>.json``, restorable with ``aegis.protect.undo``). The block is capped
    (``MAX_HOSTS_ENTRIES``) and critical vendor/update domains are never blocked even if a feed lists them.
    User files: ``<data>/web_blocklist.txt`` (extra domains) and ``<data>/web_allowlist.txt`` (never block).

IP blocking (``enable_ip_blocking`` / ``disable_ip_blocking`` / ``ip_blocking_status``)
    Windows: outbound block rules in the single Windows Firewall rule group "Aegis Threat Intel"
    (``Aegis-Block-<n>``, 200 addresses per rule) for ``signatures.bad_ips`` / ``bad_networks``; a refresh removes
    the group first, so it is idempotent. Linux: nftables table ``aegis`` (or the iptables chain ``AEGIS``).
    macOS: not supported (no safe built-in mechanism) - the functions say so.
    Only public, non-resolver addresses are blocked and networks wider than /16 (IPv4) or /48 (IPv6) are
    ignored, so a bad feed entry can never cut off the local network or public DNS.
"""

from __future__ import annotations

import base64
import datetime as dt
import ipaddress
import json
import logging
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlparse

from aegis.core.config import Config
from aegis.core.platform import IS_MAC, IS_WINDOWS, is_admin, powershell, run, windows_dir
from aegis.protect.util import atomic_write_bytes, new_backup_path, result, sha256_hex, write_json_atomic

try:  # reuse the network scanner's lists of vendor/update/major-service domains and trusted resolvers
    from aegis.scanners.network import AV_DOMAINS, IMPORTANT_DOMAINS, TRUSTED_DNS, UPDATE_DOMAINS
except Exception:  # pragma: no cover - defensive; the scanner is part of the package
    AV_DOMAINS = IMPORTANT_DOMAINS = UPDATE_DOMAINS = ()  # type: ignore[assignment]
    TRUSTED_DNS: Set[str] = set()  # type: ignore[no-redef]

log = logging.getLogger("aegis.webguard")

# --------------------------------------------------------------------------- constants
BLOCK_BEGIN = "# >>> Aegis web protection >>>"
BLOCK_END = "# <<< Aegis web protection <<<"
MAX_HOSTS_ENTRIES = 50_000
WINDOWS_PERF_WARN_LINES = 15_000  # hosts files beyond this slow down the Windows DNS Client service
KEEP_HOSTS_BACKUPS = 10

FW_GROUP = "Aegis Threat Intel"
FW_RULE_PREFIX = "Aegis-Block-"
FW_CHUNK = 200
MAX_IP_ENTRIES = 5000
NFT_TABLE = "aegis"
IPT_CHAIN = "AEGIS"
IP_STATE_FILE = "ip_blocking_state.json"

# Domains (and all their subdomains) that are never blocked, even if a feed lists them.
NEVER_BLOCK_SUFFIXES = (
    "localhost", "localdomain", "msftconnecttest.com", "msftncsi.com", "digicert.com", "letsencrypt.org",
    "githubusercontent.com", "googleusercontent.com", "googleapis.com", "gstatic.com", "cloudflare.com",
)

_HOSTNAME = re.compile(r"^(?=.{4,253}$)([a-z0-9_-]{1,63}\.)+[a-z0-9-]{2,63}$")

ADMIN_MSG_HOSTS = ("Administrator rights are required to edit the hosts file. Re-run Aegis from an elevated "
                   "terminal (Windows: 'Run as administrator'; Linux/macOS: sudo).")
ADMIN_MSG_FIREWALL_WIN = ("Administrator rights are required to change Windows Firewall rules. Re-run Aegis from an "
                          "elevated terminal ('Run as administrator').")
ADMIN_MSG_FIREWALL_POSIX = "Root privileges are required to change firewall rules. Re-run Aegis with sudo."


def _os() -> str:
    return "windows" if IS_WINDOWS else "darwin" if IS_MAC else "linux"


def _which(name: str) -> Optional[str]:
    return shutil.which(name)


def hosts_path() -> Path:
    return (windows_dir() / "System32" / "drivers" / "etc" / "hosts") if IS_WINDOWS else Path("/etc/hosts")


def user_blocklist_path(config: Config) -> Path:
    return config.home / "web_blocklist.txt"


def user_allowlist_path(config: Config) -> Path:
    return config.home / "web_allowlist.txt"


# =========================================================================== domain handling
def normalize_domain(value: Any) -> Optional[str]:
    """Lower-cased hostname, or None when ``value`` is not a plausible blockable domain (IPs, junk,
    single labels, wildcards and 'localhost' all return None)."""
    d = str(value or "").strip().lower()
    if not d:
        return None
    if "://" in d:
        d = urlparse(d).hostname or ""
    d = d.strip().strip(".")
    if not d or "*" in d or "/" in d or " " in d or not _HOSTNAME.match(d):
        return None
    try:
        ipaddress.ip_address(d)
        return None
    except ValueError:
        pass
    if d.rsplit(".", 1)[-1].isdigit():
        return None
    return d


def parse_domain_list(text: str) -> List[str]:
    """Tolerant parser for a user list: bare domains, hosts-file lines (``0.0.0.0 a.example b.example``) and
    URLs; ``#`` starts a comment. Returns normalised, de-duplicated domains in file order."""
    out: List[str] = []
    seen: Set[str] = set()
    for raw in text.splitlines():
        tokens = raw.split("#", 1)[0].split()
        if not tokens:
            continue
        try:
            ipaddress.ip_address(tokens[0])
            tokens = tokens[1:]  # hosts-file syntax: the first column is the address
        except ValueError:
            tokens = tokens[:1]
        for tok in tokens:
            d = normalize_domain(tok)
            if d and d not in seen:
                seen.add(d)
                out.append(d)
    return out


def _read_list(path: Path) -> List[str]:
    try:
        return parse_domain_list(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return []


def _suffix_match(domain: str, suffixes: Iterable[str]) -> bool:
    return any(domain == s or domain.endswith("." + s) for s in suffixes)


def is_protected_domain(domain: str) -> bool:
    """True for domains Aegis refuses to blackhole from a feed: AV vendors, OS/browser updates, major services,
    captive-portal probes, CDNs everyone depends on. Exact-or-subdomain matches only: look-alikes such as
    ``paypal-login.example`` or ``microsoft.com.evil.example`` are NOT protected (they are what the feed is for)."""
    return _suffix_match(domain, tuple(AV_DOMAINS) + tuple(UPDATE_DOMAINS) + tuple(IMPORTANT_DOMAINS) + NEVER_BLOCK_SUFFIXES)


def collect_block_domains(signatures: Any, user_domains: Optional[Sequence[str]] = None,
                          allow: Optional[Iterable[str]] = None,
                          max_entries: int = MAX_HOSTS_ENTRIES) -> Tuple[List[str], Dict[str, int]]:
    """Domains to write into the managed block (user entries first, then feed entries sorted) and counters
    {candidates, invalid, protected, allowlisted, truncated}."""
    stats = {"candidates": 0, "invalid": 0, "protected": 0, "allowlisted": 0, "truncated": 0}
    allow_set = {a for a in (normalize_domain(x) for x in (allow or [])) if a}
    chosen: List[str] = []
    seen: Set[str] = set()
    for raw in user_domains or []:
        d = normalize_domain(raw)
        stats["candidates"] += 1
        if not d:
            stats["invalid"] += 1
        elif _suffix_match(d, allow_set):
            stats["allowlisted"] += 1
        elif d not in seen:
            seen.add(d)
            chosen.append(d)
    feed: List[str] = []
    for raw in getattr(signatures, "bad_domains", None) or []:
        stats["candidates"] += 1
        d = normalize_domain(raw)
        if not d:
            stats["invalid"] += 1
        elif d in seen:
            continue
        elif _suffix_match(d, allow_set):
            stats["allowlisted"] += 1
        elif is_protected_domain(d):
            stats["protected"] += 1
        else:
            seen.add(d)
            feed.append(d)
    feed.sort()
    room = max(0, max_entries - len(chosen))
    if len(feed) > room:
        stats["truncated"] = len(feed) - room
        feed = feed[:room]
    chosen = chosen[:max_entries]
    return chosen + feed, stats


# =========================================================================== hosts file text handling
class HostsFormatError(Exception):
    """The hosts file cannot be edited safely (UTF-16, or a damaged managed block)."""


_LINE_RE = re.compile(r"[^\r\n]*(?:\r\n|\r|\n)|[^\r\n]+")
_UTF8_BOM = b"\xef\xbb\xbf"


@dataclass
class HostsParts:
    bom: bytes
    eol: str
    lines: List[str]  # every line including its own terminator
    blocks: List[Tuple[int, int]]  # inclusive (begin, end) line indexes of each managed block


def _dominant_eol(text: str) -> str:
    crlf = text.count("\r\n")
    lf = text.count("\n") - crlf
    if crlf and crlf >= lf:
        return "\r\n"
    if lf:
        return "\n"
    return "\r\n" if IS_WINDOWS else "\n"


def parse_hosts_bytes(data: bytes) -> HostsParts:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")) or b"\x00" in data[:4096]:
        raise HostsFormatError("the hosts file is UTF-16 encoded; Windows ignores such files - convert it to "
                               "ANSI/UTF-8 first, Aegis will not touch it")
    bom = _UTF8_BOM if data.startswith(_UTF8_BOM) else b""
    text = data[len(bom):].decode("utf-8", "surrogateescape")
    lines = _LINE_RE.findall(text)
    blocks: List[Tuple[int, int]] = []
    start: Optional[int] = None
    for i, line in enumerate(lines):
        s = line.strip()
        if s == BLOCK_BEGIN:
            if start is not None:
                raise HostsFormatError("the Aegis block in the hosts file is damaged (two begin markers); "
                                       "fix or delete the lines between the markers by hand")
            start = i
        elif s == BLOCK_END and start is not None:
            blocks.append((start, i))
            start = None
    if start is not None:
        raise HostsFormatError("the Aegis block in the hosts file has no end marker; Aegis will not guess where "
                               "your own entries resume - remove the begin marker line or add the end marker")
    return HostsParts(bom, _dominant_eol(text), lines, blocks)


def block_lines(domains: Sequence[str], eol: str, updated: Optional[dt.datetime] = None) -> List[str]:
    ts = (updated or dt.datetime.now()).isoformat(timespec="seconds")
    head = [
        BLOCK_BEGIN,
        "# Managed by Aegis Security Suite - lines between the markers are replaced on every update.",
        f"# Updated {ts} - {len(domains)} domains (threat-intelligence feeds + your list)",
        "# Remove with: aegis protect web off",
    ]
    return [ln + eol for ln in head + [f"0.0.0.0 {d}" for d in domains] + [BLOCK_END]]


def _join(parts: HostsParts, lines: List[str]) -> bytes:
    return parts.bom + "".join(lines).encode("utf-8", "surrogateescape")


def read_block_domains(data: bytes) -> Optional[List[str]]:
    """Domains inside the managed block, or None when there is no block."""
    parts = parse_hosts_bytes(data)
    if not parts.blocks:
        return None
    begin, end = parts.blocks[0]
    out: List[str] = []
    for line in parts.lines[begin + 1:end]:
        s = line.strip()
        if s and not s.startswith("#"):
            tok = s.split()
            if len(tok) >= 2:
                out.append(tok[1].lower())
    return out


def read_block_updated(data: bytes) -> Optional[str]:
    parts = parse_hosts_bytes(data)
    if not parts.blocks:
        return None
    begin, end = parts.blocks[0]
    for line in parts.lines[begin + 1:end]:
        m = re.match(r"#\s*Updated\s+(\S+)", line)
        if m:
            return m.group(1)
    return None


def insert_or_update_block(data: bytes, domains: Sequence[str], updated: Optional[dt.datetime] = None) -> bytes:
    """Return ``data`` with the managed block inserted (appended) or replaced in place. Bytes outside the
    block - including the BOM and each line's own terminator - are untouched."""
    parts = parse_hosts_bytes(data)
    new = block_lines(domains, parts.eol, updated)
    lines = list(parts.lines)
    if parts.blocks:
        for begin, end in reversed(parts.blocks[1:]):  # drop duplicate blocks
            del lines[begin:end + 1]
        begin, end = parts.blocks[0]
        lines[begin:end + 1] = new
    else:
        if lines and not lines[-1].endswith(("\n", "\r")):
            lines[-1] += parts.eol
        lines.extend(new)
    return _join(parts, lines)


def remove_block(data: bytes) -> Tuple[bytes, bool]:
    parts = parse_hosts_bytes(data)
    if not parts.blocks:
        return data, False
    lines = list(parts.lines)
    for begin, end in reversed(parts.blocks):
        del lines[begin:end + 1]
    return _join(parts, lines), True


# =========================================================================== hosts file IO
def _read_hosts(path: Path) -> Optional[bytes]:
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return None


def _write_hosts(path: Path, data: bytes) -> None:
    """Atomic replace; falls back to an in-place overwrite when the replace is refused (file locked, odd ACLs).
    Verifies by reading the file back. A symlinked hosts file is written through the link."""
    path = Path(os.path.realpath(path))
    try:
        atomic_write_bytes(path, data, mode_from=path)
    except OSError as exc:
        log.info("atomic hosts replace failed (%s); writing in place", exc)
        with open(path, "wb") as fh:
            fh.write(data)
    if path.read_bytes() != data:
        raise OSError("hosts file content did not match after writing")


def _list_hosts_backups(config: Config) -> List[Path]:
    return sorted(config.backups_dir.glob("webhosts-*.json"), reverse=True)


def _backup_hosts(config: Config, path: Path, original: bytes, reason: str) -> Optional[Path]:
    """Save the pre-change hosts file (raw bytes, so BOM/CRLF survive). Skipped when the newest backup already
    holds identical content; older backups beyond ``KEEP_HOSTS_BACKUPS`` are pruned."""
    digest = sha256_hex(original)
    existing = _list_hosts_backups(config)
    if existing:
        try:
            if json.loads(existing[0].read_text(encoding="utf-8")).get("sha256") == digest:
                return existing[0]
        except (OSError, ValueError):
            pass
    dest = new_backup_path(config.backups_dir, "webhosts")
    write_json_atomic(dest, {
        "kind": "webhosts", "path": str(path), "created": dt.datetime.now().isoformat(timespec="seconds"),
        "reason": reason, "sha256": digest, "size": len(original),
        "had_aegis_block": BLOCK_BEGIN.encode() in original,
        "content_b64": base64.b64encode(original).decode("ascii"),
    })
    for old in _list_hosts_backups(config)[KEEP_HOSTS_BACKUPS:]:
        try:
            old.unlink()
        except OSError:
            pass
    return dest


def flush_dns() -> Tuple[bool, str]:
    """Best-effort DNS cache flush so the hosts change takes effect immediately."""
    if IS_WINDOWS:
        rc, _, err = run(["ipconfig", "/flushdns"], timeout=20)
        return rc == 0, "DNS cache flushed" if rc == 0 else f"ipconfig /flushdns failed: {err.strip()[:120]}"
    if IS_MAC:
        rc1, _, _ = run(["dscacheutil", "-flushcache"], timeout=20)
        run(["killall", "-HUP", "mDNSResponder"], timeout=20)
        return rc1 == 0, "DNS cache flushed" if rc1 == 0 else "dscacheutil -flushcache failed"
    for cmd in (["resolvectl", "flush-caches"], ["systemd-resolve", "--flush-caches"]):
        if _which(cmd[0]):
            rc, _, _ = run(cmd, timeout=20)
            if rc == 0:
                return True, "DNS cache flushed"
    return False, "no DNS cache to flush (or no supported resolver found); the change applies to new lookups"


# =========================================================================== domain blocking API
def _denied_message() -> str:
    return ("Access to the hosts file was denied. " + ADMIN_MSG_HOSTS + " If you are already elevated, security "
            "software (or a read-only attribute) may be protecting the hosts file.")


def _hosts_target(hosts_file: Optional[Path]) -> Path:
    return Path(hosts_file) if hosts_file else hosts_path()


def _user_domains(config: Config, extra: Optional[Sequence[str]]) -> List[str]:
    return _read_list(user_blocklist_path(config)) + list(extra or [])


def enable_web_protection(config: Config, signatures: Any, *, user_domains: Optional[Sequence[str]] = None,
                          hosts_file: Optional[Path] = None, dry_run: bool = False,
                          max_entries: int = MAX_HOSTS_ENTRIES) -> Dict[str, Any]:
    """Insert (or update) the Aegis block in the hosts file. Requires administrator/root. Never raises."""
    try:
        return _enable_web(config, signatures, user_domains, hosts_file, dry_run, max_entries, "enable")
    except PermissionError:
        return result(False, False, _denied_message(), needs_admin=True)
    except Exception as exc:  # noqa: BLE001 - contract: never raise
        log.warning("enable_web_protection failed: %s", exc, exc_info=True)
        return result(False, False, f"web protection failed: {type(exc).__name__}: {exc}")


def refresh_web_protection(config: Config, signatures: Any, *, user_domains: Optional[Sequence[str]] = None,
                           hosts_file: Optional[Path] = None, dry_run: bool = False,
                           max_entries: int = MAX_HOSTS_ENTRIES) -> Dict[str, Any]:
    """Re-generate the block from the current feeds when web protection is on (call after ``aegis update``).
    When it is off nothing happens - updating feeds never switches a protection on by itself."""
    try:
        path = _hosts_target(hosts_file)
        data = _read_hosts(path)
        if data is None or read_block_domains(data) is None:
            return result(True, False, "Web protection is off; nothing to refresh.", hosts_path=str(path), enabled=False)
        return _enable_web(config, signatures, user_domains, hosts_file, dry_run, max_entries, "refresh")
    except HostsFormatError as exc:
        return result(False, False, f"web protection not refreshed: {exc}")
    except PermissionError:
        return result(False, False, _denied_message(), needs_admin=True)
    except Exception as exc:  # noqa: BLE001
        log.warning("refresh_web_protection failed: %s", exc, exc_info=True)
        return result(False, False, f"web protection refresh failed: {type(exc).__name__}: {exc}")


def _enable_web(config: Config, signatures: Any, user_domains: Optional[Sequence[str]], hosts_file: Optional[Path],
                dry_run: bool, max_entries: int, reason: str) -> Dict[str, Any]:
    path = _hosts_target(hosts_file)
    if not dry_run and not is_admin():
        return result(False, False, ADMIN_MSG_HOSTS, needs_admin=True, hosts_path=str(path))
    domains, stats = collect_block_domains(signatures, _user_domains(config, user_domains),
                                           _read_list(user_allowlist_path(config)), max_entries)
    if not domains:
        return result(False, False, "No malicious domains are loaded - run `aegis update` to download the threat "
                      "feeds first.", hosts_path=str(path), **stats)
    data = _read_hosts(path) or b""
    try:
        current = read_block_domains(data) if data else None
        new_data = insert_or_update_block(data, domains)
    except HostsFormatError as exc:
        return result(False, False, f"hosts file left untouched: {exc}", hosts_path=str(path))
    warnings: List[str] = []
    if stats["truncated"]:
        warnings.append(f"limit of {max_entries} entries reached: {stats['truncated']} lower-priority domains were "
                        "not added")
    total_lines = new_data.count(b"\n") + 1
    if IS_WINDOWS and total_lines > WINDOWS_PERF_WARN_LINES:
        warnings.append(f"the hosts file now has about {total_lines} lines; very large hosts files can slow down the "
                        "Windows DNS Client service and name resolution - run `aegis protect web off` if you notice it")
    warnings.append("hosts blocking matches exact host names only (no wildcards): sub-domains not listed stay reachable")
    details = dict(hosts_path=str(path), entries=len(domains), warnings=warnings, **stats)
    if current is not None and current == domains:
        return result(True, False, f"Web protection is already up to date ({len(domains)} domains blocked).", **details)
    if dry_run:
        details["dry_run"] = True
        return result(True, False, f"[dry run] would block {len(domains)} domains in {path}.", **details)
    backup = _backup_hosts(config, path, data, reason)
    _write_hosts(path, new_data)
    ok, flush_msg = flush_dns()
    details.update(backup=str(backup) if backup else None, dns_flush=flush_msg)
    verb = "updated" if current is not None else "enabled"
    return result(True, True, f"Web protection {verb}: {len(domains)} malicious domains blocked via the hosts file. "
                  f"Undo with `aegis protect web off`. {flush_msg}.", **details)


def disable_web_protection(config: Config, *, hosts_file: Optional[Path] = None, dry_run: bool = False) -> Dict[str, Any]:
    """Remove the Aegis block, leaving every other hosts line untouched. Requires administrator/root."""
    path = _hosts_target(hosts_file)
    try:
        if not dry_run and not is_admin():
            return result(False, False, ADMIN_MSG_HOSTS, needs_admin=True, hosts_path=str(path))
        data = _read_hosts(path)
        if data is None:
            return result(True, False, "No hosts file found; nothing to remove.", hosts_path=str(path))
        new_data, removed = remove_block(data)
        if not removed:
            return result(True, False, "Web protection is not enabled (no Aegis block in the hosts file).",
                          hosts_path=str(path))
        if dry_run:
            return result(True, False, f"[dry run] would remove the Aegis block from {path}.", hosts_path=str(path),
                          dry_run=True)
        backup = _backup_hosts(config, path, data, "disable")
        _write_hosts(path, new_data)
        ok, flush_msg = flush_dns()
        return result(True, True, f"Web protection disabled: the Aegis block was removed from {path}. {flush_msg}.",
                      hosts_path=str(path), backup=str(backup) if backup else None, dns_flush=flush_msg)
    except HostsFormatError as exc:
        return result(False, False, f"hosts file left untouched: {exc}", hosts_path=str(path))
    except PermissionError:
        return result(False, False, _denied_message(), needs_admin=True, hosts_path=str(path))
    except Exception as exc:  # noqa: BLE001
        log.warning("disable_web_protection failed: %s", exc, exc_info=True)
        return result(False, False, f"could not disable web protection: {type(exc).__name__}: {exc}", hosts_path=str(path))


def web_protection_status(config: Config, *, hosts_file: Optional[Path] = None) -> Dict[str, Any]:
    """Read-only status (no administrator rights needed)."""
    path = _hosts_target(hosts_file)
    try:
        data = _read_hosts(path)
        details: Dict[str, Any] = {
            "hosts_path": str(path), "admin": is_admin(),
            "user_blocklist": str(user_blocklist_path(config)), "user_blocklist_entries": len(_read_list(user_blocklist_path(config))),
            "user_allowlist_entries": len(_read_list(user_allowlist_path(config))),
            "backups": len(_list_hosts_backups(config)),
        }
        if data is None:
            return result(True, False, "Web protection is OFF (no hosts file found).", enabled=False, entries=0, **details)
        domains = read_block_domains(data)
        if domains is None:
            return result(True, False, "Web protection is OFF. Enable with `aegis protect web on` (administrator).",
                          enabled=False, entries=0, **details)
        updated = read_block_updated(data)
        return result(True, False, f"Web protection is ON: {len(domains)} domains blocked"
                      + (f" (updated {updated})" if updated else "") + ".", enabled=True, entries=len(domains),
                      updated=updated, **details)
    except HostsFormatError as exc:
        return result(False, False, f"hosts file problem: {exc}", enabled=False, hosts_path=str(path))
    except Exception as exc:  # noqa: BLE001
        return result(False, False, f"could not read the hosts file: {type(exc).__name__}: {exc}", enabled=False,
                      hosts_path=str(path))


# =========================================================================== IP blocking: address selection
def _safe_network(net: ipaddress._BaseNetwork) -> bool:
    if net.version == 4 and net.prefixlen < 16:
        return False
    if net.version == 6 and net.prefixlen < 48:
        return False
    if not net.is_global:
        return False
    for resolver in TRUSTED_DNS:
        try:
            if ipaddress.ip_address(resolver) in net:
                return False
        except ValueError:
            continue
    return True


def collect_block_addresses(signatures: Any, max_entries: int = MAX_IP_ENTRIES) -> Tuple[List[str], Dict[str, int]]:
    """Public IPs/CIDRs to block (collapsed, IPv4 then IPv6) and counters {candidates, skipped_unsafe, truncated}."""
    stats = {"candidates": 0, "skipped_unsafe": 0, "truncated": 0}
    nets: List[ipaddress._BaseNetwork] = []
    for raw in list(getattr(signatures, "bad_ips", None) or []):
        stats["candidates"] += 1
        try:
            addr = ipaddress.ip_address(str(raw).strip())
            net = ipaddress.ip_network(addr)
        except ValueError:
            stats["skipped_unsafe"] += 1
            continue
        if addr.is_multicast or str(addr) in TRUSTED_DNS or not _safe_host(addr):
            stats["skipped_unsafe"] += 1
            continue
        nets.append(net)
    for raw in list(getattr(signatures, "bad_networks", None) or []):
        stats["candidates"] += 1
        try:
            net = raw if isinstance(raw, (ipaddress.IPv4Network, ipaddress.IPv6Network)) else ipaddress.ip_network(str(raw), strict=False)
        except ValueError:
            stats["skipped_unsafe"] += 1
            continue
        if _safe_network(net):
            nets.append(net)
        else:
            stats["skipped_unsafe"] += 1
    v4 = sorted(ipaddress.collapse_addresses([n for n in nets if n.version == 4]))
    v6 = sorted(ipaddress.collapse_addresses([n for n in nets if n.version == 6]))
    out = [_fmt(n) for n in v4 + v6]
    if len(out) > max_entries:
        stats["truncated"] = len(out) - max_entries
        out = out[:max_entries]
    return out, stats


def _safe_host(addr: Any) -> bool:
    return bool(addr.is_global) and not addr.is_multicast


def _fmt(net: ipaddress._BaseNetwork) -> str:
    return str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net)


def chunk_addresses(addresses: Sequence[str], size: int = FW_CHUNK) -> List[List[str]]:
    return [list(addresses[i:i + size]) for i in range(0, len(addresses), size)]


# =========================================================================== IP blocking: command generation
_ADDR_RE = re.compile(r"^[0-9a-fA-F:.]+(/\d{1,3})?$")


def _checked(addresses: Iterable[str]) -> List[str]:
    items = list(addresses)
    if not all(_ADDR_RE.match(a) for a in items):
        raise ValueError("refusing to embed a malformed address in a firewall command")
    return items


def powershell_remove_script() -> str:
    return (f"$ErrorActionPreference='SilentlyContinue';Get-NetFirewallRule -Group '{FW_GROUP}' | "
            "Remove-NetFirewallRule")


def powershell_count_script() -> str:
    return f"(Get-NetFirewallRule -Group '{FW_GROUP}' -ErrorAction SilentlyContinue | Measure-Object).Count"


def _ps_rule(n: int, chunk: Sequence[str]) -> str:
    addrs = ",".join(f"'{a}'" for a in _checked(chunk))
    return (f"New-NetFirewallRule -DisplayName '{FW_RULE_PREFIX}{n}' -Group $g -Direction Outbound "
            f"-Action Block -Profile Any -Enabled True -RemoteAddress {addrs} "
            "-Description 'Aegis Security Suite: threat-intelligence IP block' | Out-Null;")


_PS_HEAD = f"$ErrorActionPreference='Stop';$g='{FW_GROUP}';"
_PS_REMOVE = "Get-NetFirewallRule -Group $g -ErrorAction SilentlyContinue | Remove-NetFirewallRule;"
PS_MAX_SCRIPT_CHARS = 20_000  # Windows limits a command line to 32,767 characters


def powershell_add_scripts(chunks: Sequence[Sequence[str]], max_chars: int = PS_MAX_SCRIPT_CHARS) -> List[str]:
    """PowerShell scripts that remove the group (first script only) and create one outbound block rule per
    chunk. Rules are spread over several scripts so none exceeds the command-line length limit."""
    scripts: List[str] = []
    current = _PS_HEAD + _PS_REMOVE
    has_rule = False
    for n, chunk in enumerate(chunks, 1):
        stmt = _ps_rule(n, chunk)
        if has_rule and len(current) + len(stmt) > max_chars:
            scripts.append(current)
            current, has_rule = _PS_HEAD, False
        current += stmt
        has_rule = True
    if has_rule or not scripts:
        scripts.append(current)
    return scripts


def powershell_add_script(chunks: Sequence[Sequence[str]]) -> str:
    """Single-script form (removes the group, then adds every rule)."""
    return powershell_add_scripts(chunks, max_chars=10 ** 9)[0]


def netsh_add_commands(chunks: Sequence[Sequence[str]]) -> List[List[str]]:
    """netsh fallback (netsh cannot assign a rule group): one argv per chunk, rules named Aegis-Block-<n>."""
    return [["netsh", "advfirewall", "firewall", "add", "rule", f"name={FW_RULE_PREFIX}{n}", "dir=out",
             "action=block", f"remoteip={','.join(_checked(chunk))}", "enable=yes", "profile=any",
             "description=Aegis-threat-intel-IP-block"] for n, chunk in enumerate(chunks, 1)]


def netsh_delete_command(n: int) -> List[str]:
    return ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={FW_RULE_PREFIX}{n}"]


def nft_script(addresses: Sequence[str]) -> str:
    """Atomic nftables ruleset: drops the table if it exists and recreates it with interval sets."""
    v4 = [a for a in _checked(addresses) if ":" not in a]
    v6 = [a for a in _checked(addresses) if ":" in a]
    lines = [f"add table inet {NFT_TABLE}", f"delete table inet {NFT_TABLE}", f"table inet {NFT_TABLE} {{"]
    rules = []
    for name, typ, els, family in (("badv4", "ipv4_addr", v4, "ip"), ("badv6", "ipv6_addr", v6, "ip6")):
        if not els:
            continue
        lines.append(f"  set {name} {{ type {typ}; flags interval; elements = {{ {', '.join(els)} }} }}")
        rules.append(f"{family} daddr @{name} counter drop")
    lines.append("  chain output { type filter hook output priority 0; policy accept; " + "; ".join(rules) + ("; " if rules else "") + "}")
    lines.append("}")
    return "\n".join(lines) + "\n"


def iptables_restore_script(addresses: Sequence[str], v6: bool) -> str:
    sel = [a for a in _checked(addresses) if (":" in a) == v6]
    lines = ["*filter", f":{IPT_CHAIN} - [0:0]", f"-F {IPT_CHAIN}"]
    lines += [f"-A {IPT_CHAIN} -d {a} -j DROP" for a in sel]
    lines.append("COMMIT")
    return "\n".join(lines) + "\n"


# =========================================================================== IP blocking: state
def _state_path(config: Config) -> Path:
    return config.home / IP_STATE_FILE


def _read_state(config: Config) -> Dict[str, Any]:
    try:
        return json.loads(_state_path(config).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _write_state(config: Config, state: Dict[str, Any]) -> None:
    try:
        write_json_atomic(_state_path(config), state)
    except OSError as exc:
        log.warning("could not write %s: %s", _state_path(config), exc)


def _clear_state(config: Config) -> None:
    try:
        _state_path(config).unlink()
    except OSError:
        pass


def _admin_message() -> str:
    return ADMIN_MSG_FIREWALL_WIN if IS_WINDOWS else ADMIN_MSG_FIREWALL_POSIX


def _mac_unsupported(action: str) -> Dict[str, Any]:
    return result(False, False, f"IP blocking is not supported on macOS ({action} skipped): there is no safe built-in "
                  "mechanism Aegis can undo. Use DNS-level filtering or your router instead.", supported=False)


# =========================================================================== IP blocking: Windows backend
def _win_rule_count() -> Optional[int]:
    rc, out, _ = powershell(powershell_count_script(), timeout=60)
    if rc != 0:
        return None
    m = re.search(r"\d+", out or "")
    return int(m.group(0)) if m else None


def _win_remove_all(state: Dict[str, Any]) -> None:
    powershell(powershell_remove_script(), timeout=120)
    n = int(state.get("rules") or 0) if state.get("backend") == "netsh" else 0
    for i in range(1, n + 1):
        run(netsh_delete_command(i), timeout=30)


def _win_enable(config: Config, addresses: List[str], digest: str) -> Dict[str, Any]:
    chunks = chunk_addresses(addresses)
    old = _read_state(config)
    backend = "powershell"
    failure = ""
    for script in powershell_add_scripts(chunks):
        rc, out, err = powershell(script, timeout=60 + 15 * script.count("New-NetFirewallRule"))
        if rc != 0:
            failure = (err or out).strip()[:200]
            break
    if failure:
        log.info("PowerShell firewall script failed (%s); falling back to netsh", failure)
        _win_remove_all({"backend": "netsh", "rules": max(len(chunks), int(old.get("rules") or 0))})
        backend = "netsh"
        for argv in netsh_add_commands(chunks):
            rc2, out2, err2 = run(argv, timeout=60)
            if rc2 != 0:
                _win_remove_all({"backend": "netsh", "rules": len(chunks)})
                return result(False, False, "Could not create Windows Firewall rules: "
                              + ((err2 or out2 or failure).strip()[:200] or "unknown error"), backend=backend)
    state = {"backend": backend, "rules": len(chunks), "entries": len(addresses), "digest": digest,
             "group": FW_GROUP, "updated": dt.datetime.now().isoformat(timespec="seconds")}
    _write_state(config, state)
    return result(True, True, f"IP blocking enabled: {len(addresses)} threat-intel addresses blocked outbound in "
                  f"{len(chunks)} Windows Firewall rule(s) (group '{FW_GROUP}'). Undo with `aegis protect ips off`.",
                  backend=backend, rules=len(chunks), entries=len(addresses), group=FW_GROUP)


# =========================================================================== IP blocking: Linux backend
def _linux_backend() -> Optional[str]:
    if _which("nft"):
        return "nftables"
    if _which("iptables"):
        return "iptables"
    return None


def _linux_enable(config: Config, addresses: List[str], digest: str) -> Dict[str, Any]:
    backend = _linux_backend()
    if backend is None:
        return result(False, False, "Neither nft nor iptables was found; install nftables to use IP blocking.")
    if backend == "nftables":
        rc, out, err = run(["nft", "-f", "-"], timeout=120, input_text=nft_script(addresses))
        if rc != 0:
            return result(False, False, f"nft rejected the ruleset: {(err or out).strip()[:200]}", backend=backend)
    else:
        for tool, v6 in (("iptables", False), ("ip6tables", True)):
            if not _which(tool):
                continue
            run([tool, "-N", IPT_CHAIN], timeout=30)  # ok if it already exists
            rc, out, err = run([f"{tool}-restore", "--noflush"], timeout=120,
                               input_text=iptables_restore_script(addresses, v6))
            if rc != 0:
                return result(False, False, f"{tool}-restore failed: {(err or out).strip()[:200]}", backend=backend)
            if run([tool, "-C", "OUTPUT", "-j", IPT_CHAIN], timeout=30)[0] != 0:
                run([tool, "-I", "OUTPUT", "1", "-j", IPT_CHAIN], timeout=30)
    _write_state(config, {"backend": backend, "rules": 1, "entries": len(addresses), "digest": digest,
                          "updated": dt.datetime.now().isoformat(timespec="seconds")})
    return result(True, True, f"IP blocking enabled: {len(addresses)} threat-intel addresses dropped outbound via "
                  f"{backend}. The rules are not persistent across reboots - run `aegis protect ips on` at startup. "
                  "Undo with `aegis protect ips off`.", backend=backend, entries=len(addresses))


def _linux_disable() -> bool:
    removed = False
    if _which("nft"):
        rc, _, _ = run(["nft", "delete", "table", "inet", NFT_TABLE], timeout=30)
        removed = removed or rc == 0
    for tool in ("iptables", "ip6tables"):
        if not _which(tool):
            continue
        for _ in range(5):
            if run([tool, "-D", "OUTPUT", "-j", IPT_CHAIN], timeout=30)[0] != 0:
                break
            removed = True
        run([tool, "-F", IPT_CHAIN], timeout=30)
        rc, _, _ = run([tool, "-X", IPT_CHAIN], timeout=30)
        removed = removed or rc == 0
    return removed


# =========================================================================== IP blocking API
def enable_ip_blocking(config: Config, signatures: Any, *, dry_run: bool = False,
                       max_entries: int = MAX_IP_ENTRIES) -> Dict[str, Any]:
    """Create (or refresh - removes the old rules first) outbound blocks for the threat-intel IPs.
    Requires administrator/root. Never raises."""
    try:
        if _os() == "darwin":
            return _mac_unsupported("enable")
        if not dry_run and not is_admin():
            return result(False, False, _admin_message(), needs_admin=True)
        addresses, stats = collect_block_addresses(signatures, max_entries)
        if not addresses:
            return result(False, False, "No usable malicious IP addresses are loaded - run `aegis update` first.", **stats)
        digest = sha256_hex("\n".join(addresses).encode())
        chunks = chunk_addresses(addresses)
        if dry_run:
            return result(True, False, f"[dry run] would block {len(addresses)} addresses in {len(chunks)} rule(s).",
                          entries=len(addresses), rules=len(chunks), dry_run=True, **stats)
        state = _read_state(config)
        if state.get("digest") == digest and _verify_present(state):
            return result(True, False, f"IP blocking is already up to date ({len(addresses)} addresses).",
                          entries=len(addresses), rules=state.get("rules"), backend=state.get("backend"), **stats)
        res = _win_enable(config, addresses, digest) if _os() == "windows" else _linux_enable(config, addresses, digest)
        res["details"].update(stats)
        if stats["truncated"]:
            res["details"]["warnings"] = [f"limit of {max_entries} addresses reached: {stats['truncated']} not added"]
        return res
    except Exception as exc:  # noqa: BLE001
        log.warning("enable_ip_blocking failed: %s", exc, exc_info=True)
        return result(False, False, f"IP blocking failed: {type(exc).__name__}: {exc}")


def refresh_ip_blocking(config: Config, signatures: Any, *, dry_run: bool = False,
                        max_entries: int = MAX_IP_ENTRIES) -> Dict[str, Any]:
    """Re-apply the feed when IP blocking is on; a no-op when it is off."""
    st = ip_blocking_status(config)
    if not st["details"].get("enabled"):
        return result(True, False, "IP blocking is off; nothing to refresh.", enabled=False)
    return enable_ip_blocking(config, signatures, dry_run=dry_run, max_entries=max_entries)


def _verify_present(state: Dict[str, Any]) -> bool:
    """Do the rules recorded in the state file still exist? (True when it cannot be determined cheaply.)"""
    try:
        if _os() == "windows":
            n = _win_rule_count()
            return n is None or n >= int(state.get("rules") or 1)
        if state.get("backend") == "nftables":
            return run(["nft", "list", "table", "inet", NFT_TABLE], timeout=30)[0] == 0
        if state.get("backend") == "iptables":
            return run(["iptables", "-S", IPT_CHAIN], timeout=30)[0] == 0
    except Exception:  # noqa: BLE001
        pass
    return True


def disable_ip_blocking(config: Config, *, dry_run: bool = False) -> Dict[str, Any]:
    """Remove every Aegis IP-block rule (the whole 'Aegis Threat Intel' group / nft table / iptables chain)."""
    try:
        if _os() == "darwin":
            return _mac_unsupported("disable")
        if not dry_run and not is_admin():
            return result(False, False, _admin_message(), needs_admin=True)
        state = _read_state(config)
        if dry_run:
            return result(True, False, "[dry run] would remove all Aegis IP-block rules.", dry_run=True)
        if _os() == "windows":
            before = _win_rule_count()
            _win_remove_all(state)
            changed = bool(before) or bool(state)
        else:
            changed = _linux_disable() or bool(state)
        _clear_state(config)
        return result(True, changed, "IP blocking disabled: all Aegis block rules were removed." if changed
                      else "IP blocking was not enabled; nothing to remove.")
    except Exception as exc:  # noqa: BLE001
        log.warning("disable_ip_blocking failed: %s", exc, exc_info=True)
        return result(False, False, f"could not disable IP blocking: {type(exc).__name__}: {exc}")


def ip_blocking_status(config: Config) -> Dict[str, Any]:
    """Read-only status; reports whether the rules actually exist, not just what the state file says."""
    try:
        if _os() == "darwin":
            return _mac_unsupported("status")
        state = _read_state(config)
        if _os() == "windows":
            n = _win_rule_count()
            enabled = bool(n) if n is not None else bool(state)
            rules = n if n is not None else state.get("rules")
        else:
            backend = state.get("backend") or _linux_backend()
            enabled = False
            verified = is_admin()
            if not verified:
                enabled = bool(state)  # cannot query nft/iptables without root: trust the state file
            elif backend == "nftables" and _which("nft"):
                enabled = run(["nft", "list", "table", "inet", NFT_TABLE], timeout=30)[0] == 0
            elif backend == "iptables" and _which("iptables"):
                enabled = run(["iptables", "-S", IPT_CHAIN], timeout=30)[0] == 0
            rules = state.get("rules")
        msg = (f"IP blocking is ON: {state.get('entries', '?')} addresses in {rules} rule(s)"
               + (f" (updated {state['updated']})" if state.get("updated") else "") + "."
               if enabled else "IP blocking is OFF. Enable with `aegis protect ips on` (administrator).")
        return result(True, False, msg, enabled=enabled, rules=rules, entries=state.get("entries"),
                      backend=state.get("backend"), updated=state.get("updated"), group=FW_GROUP, admin=is_admin())
    except Exception as exc:  # noqa: BLE001
        return result(False, False, f"could not read IP blocking status: {type(exc).__name__}: {exc}", enabled=False)


def refresh_protections(config: Config, signatures: Any) -> Dict[str, Dict[str, Any]]:
    """Refresh whichever of web/IP protection is currently on (hook for ``aegis update``)."""
    return {"web": refresh_web_protection(config, signatures), "ips": refresh_ip_blocking(config, signatures)}
