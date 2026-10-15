"""Network scanner: live connections, listening services, hosts file, proxy/PAC
hijack, DNS servers, root certificates, Wi-Fi security and SMB shares.

Collection (psutil / registry / PowerShell JSON) is kept apart from the pure
decision functions (``bad_ip_findings``, ``hosts_findings``, ``proxy_findings``,
``dns_findings``, ``rootca_findings``, ``smb_findings`` ...) so they can be unit
tested on any OS with synthetic data.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from aegis.core.models import Category, CheckResult, CheckStatus, Finding, Remediation, Severity
from aegis.core.platform import IS_WINDOWS, as_list, powershell_json, reg_subkeys, reg_values, run, windows_dir
from aegis.scanners.base import ScanContext, Scanner, register

log = logging.getLogger("aegis.network")


def _check(check_id: str, title: str, status: str, detail: str = "") -> CheckResult:
    return CheckResult(check_id, title, status, detail, Category.NETWORK, "network")


def _f(rule: str, title: str, sev: Severity, description: str, location: str, evidence: Dict[str, Any],
       recommendation: str, remediation: Optional[Remediation] = None, mitre: Optional[List[str]] = None,
       category: str = Category.NETWORK) -> Finding:
    return Finding(rule, title, sev, category, description, location, evidence, recommendation, remediation,
                   scanner="network", mitre=mitre or [])


# --------------------------------------------------------------------------- IP helpers

def _ip(value: str) -> Optional[ipaddress._BaseAddress]:
    try:
        return ipaddress.ip_address(value.split("%")[0].strip("[]"))
    except ValueError:
        return None


def is_private_ip(value: str) -> bool:
    """Loopback / private / link-local / unspecified / multicast."""
    a = _ip(value)
    if a is None:
        return False
    return a.is_private or a.is_loopback or a.is_link_local or a.is_unspecified or a.is_multicast or a.is_reserved


def is_loopback_or_null(value: str) -> bool:
    a = _ip(value)
    return bool(a) and (a.is_loopback or a.is_unspecified)


def host_is_internal(host: str) -> bool:
    h = host.strip().strip("[]").lower()
    if not h:
        return True
    if _ip(h):
        return is_private_ip(h)
    return "." not in h or h.endswith((".local", ".lan", ".corp", ".internal", ".intranet", ".home", ".localdomain", ".home.arpa"))


# --------------------------------------------------------------------------- connections

@dataclass
class ConnInfo:
    pid: int
    name: str
    exe: str
    laddr: str
    lport: int
    raddr: str
    rport: int
    status: str

    @property
    def label(self) -> str:
        who = f"{self.name or 'unknown'} (pid {self.pid})" if self.pid else "unknown process"
        return f"{who} -> {self.raddr}:{self.rport}" if self.raddr else f"{who} listening on {self.laddr}:{self.lport}"


def collect_connections() -> Tuple[List[ConnInfo], Optional[str]]:
    """All inet connections with owning process; returns (connections, warning)."""
    import psutil

    warning: Optional[str] = None
    raw: List[Any] = []
    try:
        raw = list(psutil.net_connections(kind="inet"))
    except (psutil.AccessDenied, PermissionError):
        warning = "limited visibility (run as Administrator/root to see all processes' connections)"
        for p in psutil.process_iter(["pid"]):
            try:
                fn = getattr(p, "net_connections", None) or p.connections
                for c in fn(kind="inet"):
                    raw.append(c._replace(pid=p.pid) if hasattr(c, "_replace") else c)
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
    names: Dict[int, Tuple[str, str]] = {}
    out: List[ConnInfo] = []
    me = os.getpid()
    for c in raw:
        pid = c.pid or 0
        if pid == me:
            continue
        if pid and pid not in names:
            try:
                p = psutil.Process(pid)
                names[pid] = (p.name(), p.exe() if _safe_exe(p) else "")
            except Exception:
                names[pid] = ("", "")
        name, exe = names.get(pid, ("", ""))
        laddr = c.laddr.ip if c.laddr else ""
        lport = c.laddr.port if c.laddr else 0
        raddr = c.raddr.ip if c.raddr else ""
        rport = c.raddr.port if c.raddr else 0
        out.append(ConnInfo(pid, name, exe, laddr, lport, raddr, rport, str(c.status)))
    if not any(c.pid for c in out) and out:
        warning = warning or "process attribution unavailable (run as Administrator/root)"
    return out, warning


def _safe_exe(p: Any) -> bool:
    try:
        p.exe()
        return True
    except Exception:
        return False


def _kill(c: ConnInfo) -> Optional[Remediation]:
    if not c.pid:
        return None
    from aegis.scanners.processes import safe_to_quarantine

    q = safe_to_quarantine(c.exe)
    return Remediation("kill_process", {"pid": c.pid, "path": c.exe, "quarantine": q},
                       "Terminate the process" + (" and quarantine its executable" if q else ""))


def _active(c: ConnInfo) -> bool:
    return bool(c.raddr) and c.status.upper() in ("ESTABLISHED", "SYN_SENT", "SYN_RECV", "CLOSE_WAIT", "FIN_WAIT1", "FIN_WAIT2", "TIME_WAIT", "NONE", "")


def bad_ip_findings(conns: Sequence[ConnInfo], is_bad_ip) -> List[Finding]:
    out: List[Finding] = []
    seen: Set[Tuple[int, str]] = set()
    for c in conns:
        if not c.raddr or is_private_ip(c.raddr) or (c.pid, c.raddr) in seen:
            continue
        try:
            bad = is_bad_ip(c.raddr)
        except Exception:
            bad = False
        if not bad:
            continue
        seen.add((c.pid, c.raddr))
        out.append(_f(
            "AEG-NET-BADIP", f"Connection to known malicious IP {c.raddr}", Severity.CRITICAL,
            f"{c.name or 'A process'} has a {c.status.lower() or 'live'} connection to {c.raddr}:{c.rport}, which is listed in "
            "the threat-intelligence blocklist (botnet C2 / malware infrastructure).",
            c.label, {"pid": c.pid, "process": c.name, "exe": c.exe, "remote_ip": c.raddr, "remote_port": c.rport, "status": c.status},
            "Terminate the process, quarantine its executable, then run a full scan and change your passwords.",
            _kill(c), ["T1071", "T1095"], Category.MALWARE))
    return out


BROWSERS = {"chrome", "chromium", "firefox", "msedge", "brave", "opera", "vivaldi", "safari", "iexplore", "arc",
            "chrome_proxy", "msedgewebview2", "librewolf", "waterfox", "yandex", "duckduckgo"}
IRC_CLIENTS = {"hexchat", "irssi", "weechat", "pidgin", "mirc", "xchat", "konversation", "limechat", "thunderbird", "textual"}
# port -> (rule id, title, why, mitre)
C2_PORTS: Dict[int, Tuple[str, str, str]] = {
    4444: ("AEG-NET-C2PORT", "Metasploit/RAT default port", "port 4444 is the default for Metasploit handlers and many RATs"),
    1337: ("AEG-NET-C2PORT", "Backdoor port 1337", "port 1337 is common for backdoors and reverse shells"),
    31337: ("AEG-NET-C2PORT", "Backdoor port 31337", "port 31337 ('elite') is the classic Back Orifice/backdoor port"),
}
for _p in range(6666, 6670):
    C2_PORTS[_p] = ("AEG-NET-IRC", "IRC port (botnet C2)", "IRC ports 6666-6669 are widely used for botnet command-and-control")
for _p in (3333, 5555, 7777, 14444, 45700):
    C2_PORTS[_p] = ("AEG-NET-MINERPORT", "Cryptocurrency mining pool port",
                    "this port is typically used by Stratum mining pools")
MAX_PORT_FINDINGS = 25


def _proc_stem(name: str) -> str:
    n = (name or "").lower()
    return n[:-4] if n.endswith(".exe") else n


def suspicious_port_findings(conns: Sequence[ConnInfo]) -> List[Finding]:
    out: List[Finding] = []
    seen: Set[Tuple[int, int, str]] = set()
    for c in conns:
        if len(out) >= MAX_PORT_FINDINGS:
            break
        if c.rport not in C2_PORTS or not _active(c) or is_private_ip(c.raddr):
            continue
        stem = _proc_stem(c.name)
        if stem in BROWSERS or (c.rport in range(6666, 6670) and stem in IRC_CLIENTS) or not stem:
            continue
        key = (c.pid, c.rport, c.raddr)
        if key in seen:
            continue
        seen.add(key)
        rule, title, why = C2_PORTS[c.rport]
        out.append(_f(
            rule, f"{c.name} connects to {title.lower()} ({c.rport})", Severity.MEDIUM,
            f"{c.name} (pid {c.pid}) is connected to {c.raddr}:{c.rport}; {why}. Legitimate software rarely uses this port.",
            c.label, {"pid": c.pid, "process": c.name, "exe": c.exe, "remote_ip": c.raddr, "remote_port": c.rport,
                      "status": c.status},
            "Check what this program is and why it talks to that server. If unknown, terminate it and scan it.",
            _kill(c), ["T1571", "T1095"] if rule != "AEG-NET-MINERPORT" else ["T1496"]))
    return out


TOR_PORTS = {9050, 9150}
TOR_NAMES = {"tor", "torbrowser", "tor-browser", "obfs4proxy", "lyrebird", "snowflake-client", "i2pd", "privoxy", "vidalia",
             "orbot", "brave"}


def tor_findings(conns: Sequence[ConnInfo]) -> List[Finding]:
    out: List[Finding] = []
    seen: Set[Tuple[int, str]] = set()
    for c in conns:
        listening = c.status.upper() == "LISTEN" and c.lport in TOR_PORTS
        client = bool(c.raddr) and c.rport in TOR_PORTS and is_loopback_or_null(c.raddr)
        if not (listening or client) or not c.name:
            continue
        stem = _proc_stem(c.name)
        is_tor_browser = "tor browser" in c.exe.lower() or "torbrowser" in c.exe.lower()
        if stem in TOR_NAMES or is_tor_browser:
            continue
        key = (c.pid, "L" if listening else "C")
        if key in seen:
            continue
        seen.add(key)
        what = f"listens on Tor SOCKS port {c.lport}" if listening else f"uses the local Tor SOCKS proxy ({c.rport})"
        out.append(_f(
            "AEG-NET-TOR", f"Unexpected Tor usage by {c.name}", Severity.MEDIUM,
            f"{c.name} (pid {c.pid}) {what}. Malware (ransomware, RATs, miners) often hides its traffic through Tor.",
            c.label, {"pid": c.pid, "process": c.name, "exe": c.exe, "port": c.lport if listening else c.rport},
            "If you did not install Tor or Tor Browser, terminate the process and scan it.", _kill(c), ["T1090.003"]))
    return out


# service ports exposed on all interfaces: port -> (service, severity)
EXPOSED_SERVICES: Dict[int, Tuple[str, Severity]] = {
    3389: ("Remote Desktop (RDP)", Severity.MEDIUM), 445: ("SMB file sharing", Severity.LOW),
    5900: ("VNC", Severity.MEDIUM), 5901: ("VNC", Severity.MEDIUM), 5902: ("VNC", Severity.MEDIUM),
    23: ("Telnet", Severity.MEDIUM), 5985: ("WinRM (HTTP)", Severity.LOW), 5986: ("WinRM (HTTPS)", Severity.LOW),
    21: ("FTP", Severity.MEDIUM),
}


def _bound_to_all(laddr: str) -> bool:
    if laddr in ("", "0.0.0.0", "::", "::0"):
        return True
    a = _ip(laddr)
    return bool(a and a.is_unspecified)


def listening_findings(conns: Sequence[ConnInfo]) -> List[Finding]:
    by_port: Dict[int, Set[str]] = {}
    pids: Dict[int, Set[int]] = {}
    for c in conns:
        if c.status.upper() != "LISTEN" or c.lport not in EXPOSED_SERVICES:
            continue
        if not _bound_to_all(c.laddr):
            continue  # bound to loopback or one specific interface
        by_port.setdefault(c.lport, set()).add(c.name or "unknown process")
        pids.setdefault(c.lport, set()).add(c.pid)
    out: List[Finding] = []
    for port, procs in sorted(by_port.items()):
        svc, sev = EXPOSED_SERVICES[port]
        out.append(_f(
            "AEG-NET-LISTEN", f"{svc} is listening on all network interfaces (port {port})", sev,
            f"{', '.join(sorted(procs))} accepts {svc} connections from the network. Exposed management/file-sharing services "
            "are a top target for brute-force and worm attacks.",
            f"0.0.0.0:{port}", {"port": port, "service": svc, "processes": sorted(procs), "pids": sorted(pids[port])},
            "Disable the service if you do not need it, or restrict it with the firewall to trusted addresses/VPN.",
            None, ["T1021"], Category.NETWORK))
    return out


# --------------------------------------------------------------------------- hosts file

AV_DOMAINS = (
    "kaspersky.com", "kaspersky-labs.com", "eset.com", "avast.com", "avg.com", "avira.com", "bitdefender.com",
    "malwarebytes.com", "norton.com", "symantec.com", "mcafee.com", "trendmicro.com", "sophos.com", "f-secure.com",
    "comodo.com", "drweb.com", "pandasecurity.com", "webroot.com", "virustotal.com", "clamav.net", "crowdstrike.com",
    "sentinelone.com", "windowsdefender.com", "emsisoft.com", "gdata.de", "gdatasoftware.com", "zonealarm.com",
    "checkpoint.com", "cylance.com", "carbonblack.com", "defender.microsoft.com", "wdcp.microsoft.com",
    "definitionupdates.microsoft.com",
)
UPDATE_DOMAINS = (
    "windowsupdate.com", "update.microsoft.com", "windowsupdate.microsoft.com", "ntservicepack.microsoft.com",
    "download.windowsupdate.com", "delivery.mp.microsoft.com", "swscan.apple.com", "mesu.apple.com", "gdmf.apple.com",
    "swdist.apple.com", "update.googleapis.com", "dl.google.com", "edgedl.me.gvt1.com", "sls.update.microsoft.com",
)
IMPORTANT_DOMAINS = (
    "microsoft.com", "live.com", "office.com", "office365.com", "outlook.com", "microsoftonline.com", "windows.com",
    "google.com", "gmail.com", "youtube.com", "apple.com", "icloud.com", "paypal.com", "amazon.com", "ebay.com",
    "facebook.com", "instagram.com", "twitter.com", "x.com", "linkedin.com", "dropbox.com", "github.com", "binance.com",
    "coinbase.com", "blockchain.com", "chase.com", "wellsfargo.com", "bankofamerica.com", "citibank.com", "hsbc.com",
    "barclays.co.uk", "lloydsbank.com", "santander.com", "americanexpress.com", "capitalone.com", "venmo.com",
)
BANK_WORDS = ("bank", "paypal", "banco", "banque", "sparkasse")
# telemetry/ads hosts people legitimately null-route; never counted as "update" domains
_PRIVACY_BLOCK_OK = re.compile(r"telemetry|vortex|watson|settings-win|(?<![a-z])ads?\.|adservice|analytics|doubleclick|adsystem|tracking|"
                               r"diagnostics|compat|msftncsi|activity\.windows", re.I)


@dataclass
class HostsEntry:
    ip: str
    hosts: List[str]
    line: str  # stripped original line (used for remediation matching)


def parse_hosts(text: str) -> List[HostsEntry]:
    out: List[HostsEntry] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        body = line.split("#", 1)[0].split()
        if len(body) < 2 or _ip(body[0]) is None:
            continue
        out.append(HostsEntry(body[0], [h.lower().rstrip(".") for h in body[1:]], line))
    return out


def domain_matches(host: str, suffix: str) -> bool:
    return host == suffix or host.endswith("." + suffix)


def classify_host(host: str) -> Optional[str]:
    """'av' | 'update' | 'important' for hostnames worth protecting, else None."""
    if any(domain_matches(host, d) for d in AV_DOMAINS):
        return "av"
    if any(domain_matches(host, d) for d in UPDATE_DOMAINS):
        return "update"
    if any(domain_matches(host, d) for d in IMPORTANT_DOMAINS):
        return "important"
    label = host.split(".")[-2] if host.count(".") >= 1 else ""
    if any(w in label for w in BANK_WORDS):
        return "important"
    return None


def hosts_path() -> Path:
    return (windows_dir() / "System32" / "drivers" / "etc" / "hosts") if IS_WINDOWS else Path("/etc/hosts")


STANDARD_HOSTS = {"localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback",
                  "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters", "ip6-allhosts"}
MANY_CUSTOM = 25


def hosts_findings(text: str, path: str) -> List[Finding]:
    entries = parse_hosts(text)
    redirects: List[Tuple[HostsEntry, str, str, bool]] = []  # entry, host, class, public
    blocks: List[Tuple[HostsEntry, str, str]] = []
    custom = 0
    for e in entries:
        flagged = False
        for h in e.hosts:
            cls = classify_host(h)
            if not cls:
                continue
            if is_loopback_or_null(e.ip):
                if cls in ("av", "update") and not _PRIVACY_BLOCK_OK.search(h):
                    blocks.append((e, h, cls))
                    flagged = True
            else:
                redirects.append((e, h, cls, not is_private_ip(e.ip)))
                flagged = True
        if not flagged and not all(h in STANDARD_HOSTS or h == "host.docker.internal" or h.endswith(".docker.internal")
                                   for h in e.hosts):
            custom += 1
    out: List[Finding] = []
    if redirects:
        lines = list(dict.fromkeys(e.line for e, *_ in redirects))
        public = any(p for *_, p in redirects)
        sample = [f"{e.ip} {h}" for e, h, _c, _p2 in redirects][:20]
        out.append(_f(
            "AEG-NET-HOSTS-REDIRECT", "Hosts file redirects important domains to another IP address",
            Severity.HIGH if public else Severity.MEDIUM,
            "The hosts file overrides DNS for well-known sites/updaters/security vendors. Malware uses this for phishing "
            "(fake bank/Microsoft/Google pages) and to divert software updates.",
            path, {"entries": sample, "count": len(redirects)},
            "Remove the entries unless you added them yourself.",
            Remediation("restore_hosts", {"path": path, "remove_lines": lines}, "Comment out the redirecting hosts entries"),
            ["T1565.001", "T1584.002"], Category.SUSPICIOUS))
    if blocks:
        lines = list(dict.fromkeys(e.line for e, *_ in blocks))
        sample = [f"{e.ip} {h}" for e, h, _c in blocks][:20]
        out.append(_f(
            "AEG-NET-HOSTS-BLOCK", "Hosts file blocks antivirus or update servers", Severity.HIGH,
            "Entries point antivirus-vendor or OS-update domains to 0.0.0.0/127.0.0.1 so the security software and Windows "
            "cannot download updates - a standard malware self-protection trick.",
            path, {"entries": sample, "count": len(blocks)}, "Remove the entries and update your security software.",
            Remediation("restore_hosts", {"path": path, "remove_lines": lines}, "Comment out the blocking hosts entries"),
            ["T1685", "T1565.001"], Category.SUSPICIOUS))
    if custom > MANY_CUSTOM:
        out.append(_f(
            "AEG-NET-HOSTS-CUSTOM", f"Hosts file contains {custom} custom entries", Severity.INFO,
            "Large hosts files are normal for ad-blocking lists but can hide redirects; review if you did not create it.",
            path, {"custom_entries": custom}, "No action needed if this is an ad-blocking list you installed."))
    return out


# --------------------------------------------------------------------------- proxy / PAC

INET_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"


def _proxy_host(server: str) -> str:
    """Host of the first proxy in 'host:port' or 'http=h:p;https=h:p'."""
    first = re.split(r"[;\s]", server.strip())[0]
    first = first.split("=", 1)[-1]
    first = re.sub(r"^[a-z]+://", "", first, flags=re.I)
    if first.startswith("["):
        return first[1:].split("]")[0]
    return first.rsplit(":", 1)[0] if first.count(":") == 1 else first


def proxy_findings(values: Dict[str, Any]) -> List[Finding]:
    out: List[Finding] = []
    loc = "HKCU\\" + INET_KEY
    enabled = values.get("ProxyEnable")
    server = values.get("ProxyServer")
    if enabled == 1 and isinstance(server, str) and server.strip():
        host = _proxy_host(server)
        internal = host_is_internal(host)
        out.append(_f(
            "AEG-NET-PROXY", f"System proxy is enabled ({server.strip()})", Severity.LOW if internal else Severity.MEDIUM,
            "All browser/system traffic is routed through this proxy. Malware sets a proxy to intercept credentials and "
            "inject ads; it is also normal in corporate networks and with debugging/VPN tools."
            + (" The proxy address is local/private, so this may be a legitimate tool." if internal else ""),
            loc, {"ProxyEnable": 1, "ProxyServer": server.strip(), "internal": internal},
            "If you do not use a proxy, disable it (Settings > Network > Proxy) and scan for adware/malware.",
            Remediation("set_registry_value", {"hive": "HKCU", "key": INET_KEY, "value": "ProxyEnable", "data": 0},
                        "Turn the system proxy off"), ["T1090", "T1557"], Category.SUSPICIOUS))
    pac = values.get("AutoConfigURL")
    if isinstance(pac, str) and pac.strip():
        m = re.match(r"^[a-z]+://([^/:]+)", pac.strip(), re.I)
        host = m.group(1) if m else ""
        internal = bool(host) and host_is_internal(host) and not pac.lower().startswith("file:")
        out.append(_f(
            "AEG-NET-PAC", "Automatic proxy configuration script (PAC) is set", Severity.LOW if internal else Severity.MEDIUM,
            f"Windows downloads a proxy script from {pac.strip()} and lets it decide how every connection is routed - a known "
            "malware technique for traffic hijacking.",
            loc, {"AutoConfigURL": pac.strip(), "internal": internal},
            "Remove the script unless your organisation configured it.",
            Remediation("delete_registry_value", {"hive": "HKCU", "key": INET_KEY, "value": "AutoConfigURL"},
                        "Remove the PAC script URL"), ["T1090", "T1557"], Category.SUSPICIOUS))
    return out


def parse_environment_proxy(text: str) -> List[Tuple[str, str]]:
    return [(m.group(1), m.group(2).strip().strip("\"'")) for m in
            re.finditer(r"^\s*(?:export\s+)?((?:http|https|ftp|all)_proxy)\s*=\s*(.+)$", text, re.I | re.M)]


def env_proxy_findings(text: str, path: str) -> List[Finding]:
    found = [(k, v) for k, v in parse_environment_proxy(text) if v]
    if not found:
        return []
    return [_f("AEG-NET-ENVPROXY", "System-wide proxy variables are set", Severity.INFO,
               "Proxy variables in the global environment route command-line traffic through a proxy.",
               path, {"variables": [f"{k}={v}" for k, v in found]}, "Confirm the proxy is intended.")]


# --------------------------------------------------------------------------- DNS

TRUSTED_DNS = {
    "8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844",
    "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3", "2606:4700:4700::1111", "2606:4700:4700::1001",
    "2606:4700:4700::1112", "2606:4700:4700::1002",
    "9.9.9.9", "149.112.112.112", "9.9.9.10", "149.112.112.10", "9.9.9.11", "149.112.112.11", "2620:fe::fe", "2620:fe::9",
    "208.67.222.222", "208.67.220.220", "208.67.222.123", "208.67.220.123", "2620:119:35::35", "2620:119:53::53",
    "94.140.14.14", "94.140.15.15", "94.140.14.140", "94.140.14.141", "176.103.130.130", "176.103.130.131",
    "185.228.168.9", "185.228.169.9", "185.228.168.10", "185.228.169.11", "45.90.28.0", "45.90.30.0",
    "4.2.2.1", "4.2.2.2", "4.2.2.3", "4.2.2.4", "4.2.2.5", "4.2.2.6", "64.6.64.6", "64.6.65.6", "8.26.56.26", "8.20.247.20",
    "77.88.8.8", "77.88.8.1", "84.200.69.80", "84.200.70.40", "194.242.2.2", "76.76.2.0", "76.76.10.0", "76.76.19.19",
    "76.223.122.150", "13.107.42.14",
}
_TRUSTED_PREFIXES = ("45.90.28.", "45.90.30.", "2a07:a8c0::", "2a07:a8c1::")


def is_trusted_dns(ip: str) -> bool:
    return ip in TRUSTED_DNS or ip.startswith(_TRUSTED_PREFIXES)


def parse_resolv_conf(text: str) -> List[Tuple[str, str]]:
    return [("resolv.conf", m.group(1).split("%")[0]) for m in re.finditer(r"^\s*nameserver\s+(\S+)", text, re.M)]


def dns_findings(servers: Sequence[Tuple[str, str]], is_bad_ip) -> List[Finding]:
    """servers: (interface, ip). Flags blocklisted resolvers (HIGH) and unknown public resolvers (LOW)."""
    out: List[Finding] = []
    bad = [(i, s) for i, s in servers if not is_private_ip(s) and is_bad_ip(s)]
    unknown = [(i, s) for i, s in servers if _ip(s) and not is_private_ip(s) and not is_trusted_dns(s) and (i, s) not in bad]
    if bad:
        out.append(_f("AEG-NET-DNS-BAD", "DNS server is a known malicious IP", Severity.HIGH,
                      "A configured DNS server is on the threat blocklist - DNS hijacking (DNSChanger-style) redirects every "
                      "website lookup to attacker-controlled answers.", "DNS configuration",
                      {"servers": [f"{i}: {s}" for i, s in bad]}, "Reset DNS to automatic/your router and check your router for tampering.",
                      None, ["T1584.002", "T1557"], Category.SUSPICIOUS))
    if unknown:
        out.append(_f("AEG-NET-DNS", "Verify your DNS servers", Severity.LOW,
                      "These public DNS servers are not well-known resolvers. They may be your ISP's, but rogue DNS settings are "
                      "how DNSChanger-type malware and hijacked routers redirect browsing.", "DNS configuration",
                      {"servers": [f"{i}: {s}" for i, s in unknown]},
                      "Confirm the addresses belong to your ISP/organisation; otherwise set DNS to automatic or a trusted resolver."))
    return out


def collect_dns() -> List[Tuple[str, str]]:
    if IS_WINDOWS:
        data = powershell_json("Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses } | "
                               "Select-Object InterfaceAlias,ServerAddresses | ConvertTo-Json -Depth 3 -Compress")
        out = []
        for row in as_list(data):
            if isinstance(row, dict):
                for s in as_list(row.get("ServerAddresses")):
                    out.append((str(row.get("InterfaceAlias") or ""), str(s)))
        return out
    out = []
    for p in ("/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"):
        try:
            out += parse_resolv_conf(Path(p).read_text(errors="replace"))
        except OSError:
            pass
    return list(dict.fromkeys(out))


# --------------------------------------------------------------------------- root certificates

ROOT_SCRIPT = (
    "Get-ChildItem Cert:\\CurrentUser\\Root,Cert:\\LocalMachine\\Root -ErrorAction SilentlyContinue | "
    "ForEach-Object { [pscustomobject]@{Store=$(if($_.PSPath -like '*CurrentUser*'){'CurrentUser'}else{'LocalMachine'});"
    "Subject=$_.Subject;Issuer=$_.Issuer;Thumbprint=$_.Thumbprint;NotBefore=$_.NotBefore.ToString('o')} } | "
    "ConvertTo-Json -Compress")

BAD_ROOTS = re.compile(r"superfish|edellroot|dsdtestprovider|privdog|komodia|sendori|do_not_trust|cloudguard", re.I)
DEBUG_ROOTS = re.compile(r"fiddler|mitmproxy|portswigger|burp\s*suite|burp\s*ca|charles\s*proxy|do_not_trust_fiddler|"
                         r"proxyman|httptoolkit|owasp\s*zap|zaproxy", re.I)
_HEX40 = re.compile(r"^[0-9A-Fa-f]{40}$")


USER_ROOT_KEY = r"Software\Microsoft\SystemCertificates\Root\Certificates"


def classify_root_stores(certs: Sequence[Dict[str, Any]], user_thumbprints: Set[str]) -> List[Dict[str, Any]]:
    """Cert:\\CurrentUser\\Root is a *logical* view that also shows every machine-wide
    root, so a root Microsoft ships via Windows Update would look "user-installed".
    Roots physically in the user's store are exactly the thumbprints under
    HKCU\\...\\SystemCertificates\\Root\\Certificates. Re-label by that and dedupe."""
    users = {t.upper() for t in user_thumbprints}
    out: Dict[str, Dict[str, Any]] = {}
    for c in certs:
        thumb = str(c.get("Thumbprint") or "").upper()
        if not thumb:
            continue
        d = dict(c)
        d["Store"] = "CurrentUser" if thumb in users else "LocalMachine"
        out[thumb] = d
    return list(out.values())


_ISO_RE = re.compile(r"^(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(?:\.(\d+))?\s*(Z|[+-]\d\d:?\d\d)?$")


def parse_iso_date(value: Any) -> Optional[dt.datetime]:
    """Naive-UTC datetime from PowerShell dates: .NET round-trip ('o', 7 fractional digits) or /Date(ms)/."""
    if not isinstance(value, str):
        return None
    m = re.match(r"/Date\((-?\d+)\)/", value)
    try:
        if m:
            return dt.datetime.fromtimestamp(int(m.group(1)) / 1000.0, dt.timezone.utc).replace(tzinfo=None)
        m = _ISO_RE.match(value.strip())
        if not m:
            return None
        y, mo, d, h, mi, s = (int(x) for x in m.groups()[:6])
        base = dt.datetime(y, mo, d, h, mi, s)
        tz = m.group(8)
        if tz and tz != "Z":
            sign = 1 if tz[0] == "+" else -1
            digits = tz[1:].replace(":", "")
            base -= sign * dt.timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
        return base
    except (ValueError, OverflowError, OSError):
        return None


def _cert_remediation(store: str, thumb: str) -> Optional[Remediation]:
    if not _HEX40.match(thumb):
        return None
    return Remediation("run_command", {"command": f"Remove-Item -LiteralPath 'Cert:\\{store}\\Root\\{thumb}' -Force", "powershell": True},
                       "Remove the root certificate from the trust store")


def rootca_findings(certs: Sequence[Dict[str, Any]], now: Optional[dt.datetime] = None) -> List[Finding]:
    now = now or dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)  # naive UTC, like parse_iso_date()
    out: List[Finding] = []
    for c in certs:
        subject, issuer = str(c.get("Subject") or ""), str(c.get("Issuer") or "")
        store, thumb = str(c.get("Store") or ""), str(c.get("Thumbprint") or "")
        text = subject + " " + issuer
        ev = {"store": store, "subject": subject, "issuer": issuer, "thumbprint": thumb, "not_before": c.get("NotBefore")}
        loc = f"Cert:\\{store}\\Root\\{thumb}"
        if DEBUG_ROOTS.search(text):
            out.append(_f("AEG-NET-DEBUGCA", "Debugging-proxy root certificate installed", Severity.MEDIUM,
                          f"'{subject}' lets a local proxy (Fiddler/Burp/mitmproxy/Charles/ZAP) decrypt all HTTPS traffic. It is "
                          "fine on a developer's machine but dangerous if left installed or if its private key is shared.",
                          loc, ev, "Remove the certificate if you no longer use that tool.", _cert_remediation(store, thumb),
                          ["T1553.004", "T1557"], Category.SUSPICIOUS))
        elif BAD_ROOTS.search(text):
            out.append(_f("AEG-NET-ROOTCA", "Malicious or insecure root certificate installed", Severity.HIGH,
                          f"'{subject}' is a known adware/MITM root (Superfish, eDellRoot, PrivDog, Komodia ...). It allows attackers "
                          "to intercept and forge HTTPS connections to any site.",
                          loc, ev, "Remove the certificate immediately and uninstall the software that installed it.",
                          _cert_remediation(store, thumb), ["T1553.004", "T1557"], Category.MALWARE))
        elif store == "CurrentUser":
            nb = parse_iso_date(c.get("NotBefore"))
            if nb and 0 <= (now - nb).days <= 30:
                out.append(_f("AEG-NET-ROOTCA-NEW", "Recently issued root certificate in your user trust store", Severity.LOW,
                              f"'{subject}' was issued within the last 30 days (best-effort proxy for 'recently added') and is "
                              "trusted for your account. Rogue roots enable HTTPS interception.",
                              loc, ev, "Verify you or your organisation installed it.", _cert_remediation(store, thumb),
                              ["T1553.004"]))
    return out


# --------------------------------------------------------------------------- Wi-Fi / SMB

_OPEN_AUTH = {"open", "offen", "abierta", "abierto", "ouvert", "ouverte", "aperta", "aperto", "geopend", "otevrena", "açık", "acik"}


def wifi_findings(netsh_output: str) -> List[Finding]:
    """Best-effort parse of ``netsh wlan show interfaces`` (English + common locales)."""
    out: List[Finding] = []
    for block in re.split(r"\n\s*\n", netsh_output.replace("\r", "")):
        ssid = None
        auth = None
        for line in block.splitlines():
            if ":" not in line:
                continue
            key, _, val = line.partition(":")
            key, val = key.strip().lower(), val.strip()
            if key == "ssid":
                ssid = val
            elif key.startswith(("auth", "autent")) and auth is None:
                auth = val.lower()
        if not ssid or not auth:
            continue
        if auth in _OPEN_AUTH or auth == "wep" or auth.startswith("wep"):
            kind = "WEP" if auth.startswith("wep") else "open (no encryption)"
            out.append(_f("AEG-NET-WIFI", f"Connected to an insecure Wi-Fi network ({ssid})", Severity.MEDIUM,
                          f"The current Wi-Fi network uses {kind} security. Anyone nearby can read or tamper with unencrypted "
                          "traffic (best-effort detection from netsh output).",
                          f"Wi-Fi: {ssid}", {"ssid": ssid, "authentication": auth},
                          "Use a WPA2/WPA3 network or a VPN; avoid sensitive logins on this network.", None, ["T1040"]))
    return out


DEFAULT_SHARES = {"admin$", "c$", "d$", "e$", "ipc$", "print$", "fax$"}
SMB_SCRIPT = (
    "$s=@(Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { -not $_.Special } | ForEach-Object { "
    "$a=@(Get-SmbShareAccess -Name $_.Name -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{"
    "Account=[string]$_.AccountName;Type=[string]$_.AccessControlType;Right=[string]$_.AccessRight} }); "
    "[pscustomobject]@{Name=$_.Name;Path=$_.Path;Description=$_.Description;Access=$a} }); "
    "ConvertTo-Json -InputObject $s -Depth 4 -Compress")


def smb_findings(shares: Sequence[Dict[str, Any]]) -> List[Finding]:
    out: List[Finding] = []
    for s in shares:
        name = str(s.get("Name") or "")
        if not name or name.lower() in DEFAULT_SHARES:
            continue
        access = [a for a in as_list(s.get("Access")) if isinstance(a, dict)]
        everyone = [a for a in access if re.search(r"(^|\\)(everyone|anonymous logon|anonymous)$", str(a.get("Account", "")), re.I)
                    and str(a.get("Type", "")).lower() == "allow"]
        writable = any(str(a.get("Right", "")).lower() in ("full", "change") for a in everyone)
        if everyone:
            sev = Severity.MEDIUM
            desc = (f"The share '{name}' ({s.get('Path') or ''}) grants {'write/full' if writable else 'read'} access to Everyone, "
                    "so any user on the network (and malware/ransomware spreading over SMB) can reach it.")
        else:
            sev = Severity.LOW
            desc = f"A non-default network share '{name}' ({s.get('Path') or ''}) is published. Confirm it is still needed."
        out.append(_f("AEG-NET-SMB", f"Network share '{name}' is exposed" + (" to Everyone" if everyone else ""), sev, desc,
                      f"\\\\{os.environ.get('COMPUTERNAME', 'localhost')}\\{name}",
                      {"name": name, "path": s.get("Path"), "access": access},
                      "Remove the share (Remove-SmbShare) or restrict it to specific users.", None, ["T1021.002", "T1135"]))
    return out


# --------------------------------------------------------------------------- scanner

@register
class NetworkScanner(Scanner):
    name = "network"
    title = "Network exposure"
    description = "Connections, listening services, hosts file, proxy/DNS hijack, root certificates, Wi-Fi, SMB shares"
    platforms = ("windows", "linux", "darwin")

    def run(self, ctx: ScanContext):
        sigs = ctx.signatures
        # ---- connections
        try:
            conns, warn = collect_connections()
            bad = bad_ip_findings(conns, sigs.is_bad_ip)
            ports = suspicious_port_findings(conns)
            tor = tor_findings(conns)
            yield from bad
            yield from ports
            yield from tor
            ctx.bump("connections_examined", len(conns))
            status = CheckStatus.FAIL if (bad or ports or tor) else (CheckStatus.WARN if warn else CheckStatus.PASS)
            yield _check("AEG-NET-CHK-CONN", "No connections to malicious hosts or C2 ports", status,
                         f"{len(conns)} connections checked" + (f"; {warn}" if warn else ""))
            listen = listening_findings(conns)
            yield from listen
            yield _check("AEG-NET-CHK-LISTEN", "No risky services exposed on all interfaces",
                         CheckStatus.WARN if listen else CheckStatus.PASS,
                         ", ".join(f"{f.evidence['service']} ({f.evidence['port']})" for f in listen) or "none found")
        except Exception as exc:
            log.debug("connection analysis failed", exc_info=True)
            yield _check("AEG-NET-CHK-CONN", "No connections to malicious hosts or C2 ports", CheckStatus.ERROR, f"{type(exc).__name__}: {exc}")

        # ---- hosts file
        try:
            hp = hosts_path()
            text = hp.read_text(encoding="utf-8", errors="replace") if hp.exists() else None
            if text is None:
                yield _check("AEG-NET-CHK-HOSTS", "Hosts file is clean", CheckStatus.SKIP, f"{hp} not found")
            else:
                hf = hosts_findings(text, str(hp))
                yield from hf
                bad_hosts = [f for f in hf if f.severity >= Severity.MEDIUM]
                yield _check("AEG-NET-CHK-HOSTS", "Hosts file is clean", CheckStatus.FAIL if bad_hosts else CheckStatus.PASS,
                             f"{len(parse_hosts(text))} entries")
        except Exception as exc:
            yield _check("AEG-NET-CHK-HOSTS", "Hosts file is clean", CheckStatus.ERROR, f"{type(exc).__name__}: {exc}")

        # ---- proxy
        try:
            if IS_WINDOWS:
                pf = proxy_findings(reg_values("HKCU", INET_KEY))
                yield from pf
                yield _check("AEG-NET-CHK-PROXY", "No proxy hijack", CheckStatus.FAIL if any(f.severity >= Severity.MEDIUM for f in pf)
                             else (CheckStatus.WARN if pf else CheckStatus.PASS), "; ".join(f.title for f in pf))
            else:
                envf = []
                try:
                    envf = env_proxy_findings(Path("/etc/environment").read_text(errors="replace"), "/etc/environment")
                except OSError:
                    pass
                yield from envf
                yield _check("AEG-NET-CHK-PROXY", "No proxy hijack", CheckStatus.PASS,
                             "system-wide proxy variables set" if envf else "no system proxy configured")
        except Exception as exc:
            yield _check("AEG-NET-CHK-PROXY", "No proxy hijack", CheckStatus.ERROR, f"{type(exc).__name__}: {exc}")

        # ---- DNS
        try:
            servers = collect_dns()
            df = dns_findings(servers, sigs.is_bad_ip)
            yield from df
            yield _check("AEG-NET-CHK-DNS", "DNS servers look legitimate",
                         CheckStatus.FAIL if any(f.severity >= Severity.MEDIUM for f in df) else (CheckStatus.WARN if df else CheckStatus.PASS),
                         ", ".join(sorted({s for _, s in servers})) or "no DNS servers found")
        except Exception as exc:
            yield _check("AEG-NET-CHK-DNS", "DNS servers look legitimate", CheckStatus.ERROR, f"{type(exc).__name__}: {exc}")

        # ---- Windows-only: root CAs, Wi-Fi, SMB
        if IS_WINDOWS:
            try:
                certs = [c for c in as_list(powershell_json(ROOT_SCRIPT, timeout=90)) if isinstance(c, dict)]
                certs = classify_root_stores(certs, set(reg_subkeys("HKCU", USER_ROOT_KEY)))
                if not certs:
                    yield _check("AEG-NET-CHK-ROOTCA", "No rogue root CAs", CheckStatus.ERROR, "could not enumerate certificate stores")
                else:
                    cf = rootca_findings(certs)
                    yield from cf
                    yield _check("AEG-NET-CHK-ROOTCA", "No rogue root CAs",
                                 CheckStatus.FAIL if any(f.severity >= Severity.MEDIUM for f in cf) else CheckStatus.PASS,
                                 f"{len(certs)} root certificates reviewed")
            except Exception as exc:
                yield _check("AEG-NET-CHK-ROOTCA", "No rogue root CAs", CheckStatus.ERROR, f"{type(exc).__name__}: {exc}")
            try:
                rc, out, _ = run(["netsh", "wlan", "show", "interfaces"], timeout=20)
                wf = wifi_findings(out) if rc == 0 else []
                yield from wf
                yield _check("AEG-NET-CHK-WIFI", "Wi-Fi connection is encrypted", CheckStatus.WARN if wf else
                             (CheckStatus.PASS if rc == 0 else CheckStatus.SKIP), "best-effort (parses netsh output)")
            except Exception as exc:
                yield _check("AEG-NET-CHK-WIFI", "Wi-Fi connection is encrypted", CheckStatus.ERROR, f"{type(exc).__name__}: {exc}")
            try:
                shares = [s for s in as_list(powershell_json(SMB_SCRIPT, timeout=60)) if isinstance(s, dict)]
                sf = smb_findings(shares)
                yield from sf
                yield _check("AEG-NET-CHK-SMB", "No unexpected SMB shares",
                             CheckStatus.WARN if sf else CheckStatus.PASS, f"{len(shares)} non-default shares")
            except Exception as exc:
                yield _check("AEG-NET-CHK-SMB", "No unexpected SMB shares", CheckStatus.ERROR, f"{type(exc).__name__}: {exc}")
        else:
            yield _check("AEG-NET-CHK-ROOTCA", "No rogue root CAs", CheckStatus.SKIP, "Windows only")
