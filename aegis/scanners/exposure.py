"""Exposure: what the network can reach on this computer.

Two read-only reviews, both about inbound access rather than malware (inbound Windows Firewall rules are reviewed by the
network scanner):

* **Router port forwards (UPnP IGD)** - asks the router (SSDP M-SEARCH, then the WANIPConnection / WANPPPConnection SOAP
  service) which ports it forwards from the internet, and to which LAN address. Games and torrent clients open these
  automatically; so do botnets that turn a PC into a proxy. A forward of RDP, SMB, VNC, SSH, a database or the Docker API
  to this computer is HIGH. A forward to a program running from a Temp / Downloads folder is HIGH. When the router's own
  WAN address is private (carrier-grade NAT, double NAT) the forwards are not reachable from the internet and are capped
  at LOW. The router is only asked questions; nothing is added or deleted.
* **Docker Engine API without TLS** - ``daemon.json`` ``hosts`` / systemd ``-H tcp://`` without ``--tlsverify`` and Docker
  Desktop's "Expose daemon on tcp://localhost:2375 without TLS". Anyone who can reach that port is root on the host;
  cryptojacking campaigns scan the internet for it.

Every collector takes injectable readers so the parsing and the decisions are unit-tested on any OS.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple

from aegis.core.models import Category, CheckResult, CheckStatus, Finding, Severity
from aegis.core.platform import IS_LINUX, IS_WINDOWS, user_home
from aegis.scanners.base import Emitted, ScanContext, Scanner, register
from aegis.scanners.network import EXPOSED_SERVICES
from aegis.scanners.privacy import staging_location

log = logging.getLogger("aegis.exposure")

# port -> service name for anything that should never be reachable from the internet
RISKY_PORTS: Dict[int, str] = {port: svc for port, (svc, _sev) in EXPOSED_SERVICES.items()}
RISKY_PORTS.update({22: "SSH", 135: "Windows RPC", 139: "NetBIOS file sharing", 2375: "Docker Engine API (no TLS)",
                    5800: "VNC (web)"})

MITRE_EXPOSE = ["T1133"]  # External Remote Services

# =========================================================================== router port forwards (UPnP IGD)
SSDP_ADDR = ("239.255.255.250", 1900)
IGD_TARGETS = ("urn:schemas-upnp-org:device:InternetGatewayDevice:1", "urn:schemas-upnp-org:device:InternetGatewayDevice:2")
WAN_SERVICES = ("urn:schemas-upnp-org:service:WANIPConnection:2", "urn:schemas-upnp-org:service:WANIPConnection:1",
                "urn:schemas-upnp-org:service:WANPPPConnection:1")
SSDP_WAIT_S = 2.0
HTTP_TIMEOUT_S = 3.0
MAX_BODY = 256 * 1024
MAX_MAPPINGS = 128
UPNP_BUDGET_S = 20.0

Fetch = Callable[[str, Optional[bytes], Dict[str, str]], Tuple[int, bytes]]


@dataclass
class PortMapping:
    external_port: int
    protocol: str
    internal_client: str
    internal_port: int
    description: str = ""
    enabled: bool = True
    remote_host: str = ""
    lease_s: int = 0

    @property
    def label(self) -> str:
        return f"{self.protocol} {self.external_port} -> {self.internal_client}:{self.internal_port}"


@dataclass
class Gateway:
    ip: str
    location: str
    control_url: str
    service: str
    name: str = ""
    external_ip: str = ""
    mappings: List[PortMapping] = field(default_factory=list)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:  # a LAN device must not send us elsewhere
        return None


_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)  # the router is never behind a proxy


def http_fetch(url: str, data: Optional[bytes] = None, headers: Optional[Dict[str, str]] = None) -> Tuple[int, bytes]:
    """GET / POST on the LAN with a short timeout and a size cap. HTTP errors return their status and body."""
    req = urllib.request.Request(url, data=data, headers=headers or {}, method="POST" if data is not None else "GET")
    try:
        with _OPENER.open(req, timeout=HTTP_TIMEOUT_S) as resp:
            return resp.status, resp.read(MAX_BODY)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(MAX_BODY) if exc.fp else b""


def ssdp_search(wait: float = SSDP_WAIT_S) -> List[Tuple[str, str]]:
    """M-SEARCH for internet gateways; returns ``(responder_ip, LOCATION)`` pairs."""
    out: List[Tuple[str, str]] = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(0.25)
        for st in IGD_TARGETS:
            msg = (f'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 2\r\n'
                   f"ST: {st}\r\n\r\n")
            sock.sendto(msg.encode("ascii"), SSDP_ADDR)
        deadline = time.monotonic() + wait
        while time.monotonic() < deadline:
            try:
                data, (ip, _port) = sock.recvfrom(4096)
            except socket.timeout:
                continue
            loc = parse_ssdp_location(data)
            if loc and (ip, loc) not in out:
                out.append((ip, loc))
    finally:
        sock.close()
    return out


def parse_ssdp_location(data: bytes) -> str:
    for line in data.decode("latin-1", "replace").splitlines():
        name, _, value = line.partition(":")
        if name.strip().lower() == "location":
            return value.strip()
    return ""


def _private_ip(text: str) -> bool:
    try:
        return ipaddress.ip_address(text).is_private
    except ValueError:
        return False


def same_host_url(url: str, ip: str) -> bool:
    """Only plain-HTTP URLs on the device that answered, which must be on the LAN: a responder cannot point Aegis at
    another host or the internet."""
    try:
        u = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    return u.scheme == "http" and u.hostname == ip and _private_ip(ip)


def _xml(body: bytes) -> Optional[ET.Element]:
    if b"<!DOCTYPE" in body[:4096].upper() or b"<!ENTITY" in body.upper():
        return None  # descriptions never need a DTD; refusing one rules out entity expansion
    try:
        return ET.fromstring(body)
    except ET.ParseError:
        return None


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_description(body: bytes, location: str) -> Optional[Tuple[str, str, str]]:
    """``(service_type, absolute control URL, friendly name)`` of the first WAN connection service, or None."""
    root = _xml(body)
    if root is None:
        return None
    base = location
    name = ""
    for el in root.iter():
        tag = _local(el.tag)
        if tag == "URLBase" and (el.text or "").strip():
            base = el.text.strip()
        elif tag == "friendlyName" and not name:
            name = (el.text or "").strip()
    services = {}
    for el in root.iter():
        if _local(el.tag) != "service":
            continue
        kids = {_local(c.tag): (c.text or "").strip() for c in el}
        if kids.get("serviceType") in WAN_SERVICES and kids.get("controlURL"):
            services[kids["serviceType"]] = urllib.parse.urljoin(base, kids["controlURL"])
    for st in WAN_SERVICES:
        if st in services:
            return st, services[st], name
    return None


def _soap_body(service: str, action: str, args: Mapping[str, Any]) -> bytes:
    inner = "".join(f"<{k}>{v}</{k}>" for k, v in args.items())
    return ('<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
            f'<u:{action} xmlns:u="{service}">{inner}</u:{action}></s:Body></s:Envelope>').encode("utf-8")


def soap_call(fetch: Fetch, gw: Gateway, action: str, args: Optional[Mapping[str, Any]] = None) -> Optional[Dict[str, str]]:
    """Leaf elements of the response by local name, or None on a SOAP fault / error."""
    headers = {"Content-Type": 'text/xml; charset="utf-8"', "SOAPAction": f'"{gw.service}#{action}"'}
    status, body = fetch(gw.control_url, _soap_body(gw.service, action, args or {}), headers)
    if status != 200:
        return None
    root = _xml(body)
    if root is None:
        return None
    return {_local(el.tag): (el.text or "").strip() for el in root.iter() if len(el) == 0}


def _int(text: Any, default: int = 0) -> int:
    try:
        return int(str(text).strip())
    except (TypeError, ValueError):
        return default


def mapping_from(fields: Mapping[str, str]) -> Optional[PortMapping]:
    ext, internal = _int(fields.get("NewExternalPort")), _int(fields.get("NewInternalPort"))
    client = fields.get("NewInternalClient", "")
    if not ext or not client:
        return None
    return PortMapping(ext, (fields.get("NewProtocol") or "").upper(), client, internal or ext,
                       fields.get("NewPortMappingDescription", ""), fields.get("NewEnabled", "1").strip() not in ("0", "false"),
                       fields.get("NewRemoteHost", ""), _int(fields.get("NewLeaseDuration")))


def discover_gateway(search: Callable[[], List[Tuple[str, str]]] = ssdp_search, fetch: Fetch = http_fetch,
                     budget_s: float = UPNP_BUDGET_S) -> Optional[Gateway]:
    """The first UPnP internet gateway that answers, with its external address and port mappings."""
    deadline = time.monotonic() + budget_s
    for ip, location in search():
        if not same_host_url(location, ip):
            log.debug("ignoring SSDP answer from %s with location %s", ip, location)
            continue
        try:
            status, body = fetch(location, None, {})
        except OSError as exc:
            log.debug("UPnP description %s failed: %s", location, exc)
            continue
        desc = parse_description(body, location) if status == 200 else None
        if not desc or not same_host_url(desc[1], ip):
            continue
        gw = Gateway(ip, location, desc[1], desc[0], desc[2])
        try:
            gw.external_ip = (soap_call(fetch, gw, "GetExternalIPAddress") or {}).get("NewExternalIPAddress", "")
            for i in range(MAX_MAPPINGS):
                if time.monotonic() > deadline:
                    break
                fields = soap_call(fetch, gw, "GetGenericPortMappingEntry", {"NewPortMappingIndex": i})
                if fields is None:  # SpecifiedArrayIndexInvalid (713) ends the list
                    break
                m = mapping_from(fields)
                if m:
                    gw.mappings.append(m)
        except OSError as exc:
            log.debug("UPnP SOAP on %s failed: %s", gw.control_url, exc)
        return gw
    return None


def internet_reachable(external_ip: str) -> bool:
    """False when the router's WAN address is private / carrier-grade NAT, so its forwards cannot be reached from the
    internet. Unknown addresses count as reachable."""
    try:
        return ipaddress.ip_address(external_ip).is_global
    except ValueError:
        return True


def _forward_finding(rule: str, title: str, sev: Severity, desc: str, m: PortMapping, gw: Gateway,
                     extra: Optional[Dict[str, Any]] = None) -> Finding:
    ev = {"router": gw.name or gw.ip, "router_ip": gw.ip, "external_ip": gw.external_ip, "external_port": m.external_port,
          "protocol": m.protocol, "internal_client": m.internal_client, "internal_port": m.internal_port,
          "description": m.description[:120], "lease_s": m.lease_s, **(extra or {})}
    rec = ("Remove the forward in your router's admin page (Port forwarding / UPnP), and turn UPnP off there if nothing "
           "you use needs it. If you did not set this up, find and remove the program that asked for it.")
    return Finding(rule, title, sev, Category.NETWORK, desc, f"router {gw.ip}: {m.label}", ev, rec, None, "", MITRE_EXPOSE)


def assess_gateway(gw: Gateway, local_ips: Sequence[str], listeners: Mapping[int, Tuple[str, str]]) -> List[Emitted]:
    """Findings for the router's forwards. ``listeners``: local port -> (process name, exe) of what listens on it."""
    out: List[Emitted] = []
    reachable = internet_reachable(gw.external_ip)
    mine = {ip for ip in local_ips}
    risky = 0
    for m in gw.mappings:
        if not m.enabled:
            continue
        to_me = m.internal_client in mine
        svc = RISKY_PORTS.get(m.internal_port)
        name, exe = listeners.get(m.internal_port, ("", "")) if to_me else ("", "")
        staged = staging_location(exe) if exe else ""
        where = "this computer" if to_me else m.internal_client
        if svc:
            sev = Severity.HIGH if to_me else Severity.MEDIUM
            f = _forward_finding(
                "AEG-EXP-UPNP-RISKY", f"Router forwards {svc} from the internet to {where}", sev,
                f"Your router forwards {m.protocol} port {m.external_port} from the internet to {svc} on {where} "
                f"({m.internal_client}:{m.internal_port}). Internet-wide scanners find and attack these services within "
                f"hours.{' Requested by: ' + m.description[:80] + '.' if m.description else ''}", m, gw)
        elif to_me and staged:
            sev = Severity.HIGH
            f = _forward_finding(
                "AEG-EXP-UPNP-STAGED", f"A program in {staged} opened a router port to this computer", sev,
                f"{name or 'A program'} ({exe}) listens on port {m.internal_port}, and your router forwards "
                f"{m.protocol} {m.external_port} from the internet to it. Proxy and botnet malware run from such folders "
                "and open router ports this way.", m, gw, {"process": name, "exe": exe})
        elif to_me:
            sev = Severity.LOW
            what = f"{name} ({exe})" if name else "nothing is listening on it right now, so the forward is stale"
            f = _forward_finding(
                "AEG-EXP-UPNP-FORWARD", f"Router port {m.external_port}/{m.protocol} is forwarded to this computer", sev,
                f"Your router forwards {m.protocol} port {m.external_port} from the internet to this computer, port "
                f"{m.internal_port}: {what}. Games, torrent and media servers do this through UPnP; make sure you "
                f"recognise it.{' Requested by: ' + m.description[:80] + '.' if m.description else ''}", m, gw,
                {"process": name, "exe": exe})
        else:
            continue
        if not reachable and f.severity > Severity.LOW:
            f.severity = Severity.LOW
            f.description += (f" Your router's internet address ({gw.external_ip}) is private (carrier-grade or double "
                              "NAT), so this forward is probably not reachable from the internet today.")
        risky += f.severity >= Severity.MEDIUM
        out.append(f)
    if gw.mappings:
        lines = [m.label + (f" ({m.description[:40]})" if m.description else "") + ("" if m.enabled else " [disabled]")
                 for m in gw.mappings]
        out.append(Finding(
            "AEG-EXP-UPNP-LIST", f"Router port forwards: {len(gw.mappings)} (UPnP)", Severity.INFO, Category.NETWORK,
            f"{gw.name or 'Your router'} ({gw.ip}, internet address {gw.external_ip or 'unknown'}) forwards these ports "
            "from the internet: " + "; ".join(lines[:20]) + ("; ..." if len(lines) > 20 else ""),
            f"router {gw.ip}", {"router": gw.name, "external_ip": gw.external_ip, "mappings": lines[:100]},
            "Programs on any device in your network can open these through UPnP. Turn UPnP off in the router if you "
            "do not need it.", None, "", MITRE_EXPOSE))
    title = "The router forwards no risky ports from the internet (UPnP)"
    detail = (f"{gw.name or gw.ip}: {len(gw.mappings)} forward(s), {risky} risky" if gw.mappings
              else f"{gw.name or gw.ip} answers UPnP but forwards no ports")
    out.append(CheckResult("EXP-UPNP", title, CheckStatus.FAIL if risky else CheckStatus.PASS, detail, Category.NETWORK))
    return out


def local_ipv4s() -> List[str]:
    try:
        import psutil

        return sorted({a.address for addrs in psutil.net_if_addrs().values() for a in addrs
                       if a.family == socket.AF_INET and not a.address.startswith("127.")})
    except Exception:
        return []


def listening_ports() -> Dict[int, Tuple[str, str]]:
    out: Dict[int, Tuple[str, str]] = {}
    try:
        import psutil

        for c in psutil.net_connections(kind="inet"):
            if c.status != psutil.CONN_LISTEN and c.type != socket.SOCK_DGRAM:
                continue
            if not c.laddr or c.laddr.port in out:
                continue
            name = exe = ""
            if c.pid:
                try:
                    p = psutil.Process(c.pid)
                    name, exe = p.name(), p.exe()
                except Exception:
                    pass
            out[c.laddr.port] = (name, exe)
    except Exception as exc:
        log.debug("listening ports unavailable: %s", exc)
    return out


# =========================================================================== Docker Engine API
DOCKER_DESKTOP_KEY = "exposeDockerAPIOnTCP2375"
_TCP_HOST = re.compile(r"(?:-H|--host)[= ]+[\"']?(tcp://[^\s\"']+)", re.I)


def _docker_sev(host: str) -> Severity:
    h = (urllib.parse.urlsplit(host).hostname or "").lower()
    return Severity.MEDIUM if h in ("localhost", "127.0.0.1", "::1") else Severity.HIGH


def docker_daemon_hosts(text: str) -> Tuple[List[str], bool]:
    """(tcp:// hosts, TLS verification on) from daemon.json text."""
    try:
        doc = json.loads(text)
    except ValueError:
        return [], False
    if not isinstance(doc, dict):
        return [], False
    hosts = [h for h in doc.get("hosts") or [] if isinstance(h, str) and h.lower().startswith("tcp://")]
    return hosts, bool(doc.get("tlsverify"))


def docker_unit_hosts(text: str) -> Tuple[List[str], bool]:
    """(tcp:// hosts, TLS verification on) from a systemd unit / drop-in's ExecStart lines."""
    lines = [ln for ln in text.splitlines() if ln.strip().startswith("ExecStart=")]
    joined = " ".join(lines)
    return _TCP_HOST.findall(joined), "--tlsverify" in joined


def docker_config_files(env: Mapping[str, str], home: Path) -> List[Tuple[str, Path]]:
    if IS_WINDOWS:
        pd = Path(env.get("ProgramData") or env.get("PROGRAMDATA") or r"C:\ProgramData")
        appdata = Path(env.get("APPDATA") or home / "AppData" / "Roaming")
        return [("daemon", pd / "docker" / "config" / "daemon.json"), ("desktop", appdata / "Docker" / "settings-store.json"),
                ("desktop", appdata / "Docker" / "settings.json")]
    files: List[Tuple[str, Path]] = [("daemon", Path("/etc/docker/daemon.json")), ("daemon", home / ".config" / "docker" / "daemon.json")]
    if IS_LINUX:
        files += [("unit", Path("/lib/systemd/system/docker.service")), ("unit", Path("/etc/systemd/system/docker.service"))]
        dropins = Path("/etc/systemd/system/docker.service.d")
        try:
            files += [("unit", p) for p in sorted(dropins.glob("*.conf"))]
        except OSError:
            pass
    return files


def assess_docker(files: Sequence[Tuple[str, Path]], read: Callable[[Path], str]) -> List[Finding]:
    out: List[Finding] = []
    seen = set()
    for kind, path in files:
        try:
            text = read(path)
        except (OSError, UnicodeDecodeError):
            continue
        if kind == "desktop":
            try:
                doc = json.loads(text)
            except ValueError:
                continue
            hosts, tls = (["tcp://localhost:2375"] if isinstance(doc, dict) and doc.get(DOCKER_DESKTOP_KEY) is True else []), False
        elif kind == "unit":
            hosts, tls = docker_unit_hosts(text)
        else:
            hosts, tls = docker_daemon_hosts(text)
        if tls:
            continue
        for host in hosts:
            if host in seen:
                continue
            seen.add(host)
            sev = _docker_sev(host)
            how = ("Docker Desktop's setting 'Expose daemon on tcp://localhost:2375 without TLS' is on"
                   if kind == "desktop" else f"{path} makes the Docker daemon listen on {host} without TLS")
            out.append(Finding(
                "AEG-EXP-DOCKER", f"Docker Engine API is exposed without TLS ({host})", sev, Category.NETWORK,
                f"{how}. Anything that can reach it can start a privileged container, which means full control of this "
                "computer" + (": even a local program without admin rights, or a web page through DNS rebinding."
                              if sev == Severity.MEDIUM else ". Cryptojacking campaigns scan the internet for this port."),
                str(path), {"host": host, "config": str(path), "kind": kind},
                ("Turn the setting off in Docker Desktop > Settings > General." if kind == "desktop" else
                 "Remove the tcp:// host or protect it with TLS (tlsverify, port 2376), then restart Docker."),
                None, "", ["T1610", "T1133"]))
    return out


def _read_text(path: Path) -> str:
    if path.stat().st_size > 1024 * 1024:
        raise OSError("too large")
    return path.read_text(encoding="utf-8", errors="replace")


# =========================================================================== scanner
@register
class ExposureScanner(Scanner):
    name = "exposure"
    title = "Network exposure"
    description = "Router port forwards (UPnP) and the Docker API without TLS"

    def run(self, ctx: ScanContext) -> Iterator[Emitted]:
        env = dict(os.environ)
        ctx.report(self.name, "reviewing Docker configuration")
        yield from assess_docker(docker_config_files(env, user_home()), _read_text)
        if ctx.cancelled:
            return
        ctx.report(self.name, "asking the router for its port forwards (UPnP)")
        try:
            gw = discover_gateway()
        except OSError as exc:
            log.debug("UPnP discovery failed: %s", exc)
            gw = None
        if gw is None:
            yield CheckResult("EXP-UPNP", "The router forwards no risky ports from the internet (UPnP)", CheckStatus.SKIP,
                              "No UPnP router answered on this network (UPnP is off, or the router does not support it).",
                              Category.NETWORK)
            return
        ctx.bump("upnp_mappings", len(gw.mappings))
        yield from assess_gateway(gw, local_ipv4s(), listening_ports())
