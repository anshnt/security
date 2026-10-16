"""Unit tests for aegis.scanners.exposure: router port forwards over a real local UPnP HTTP/SOAP server, Docker API
exposure in daemon.json / Docker Desktop / systemd units, and the new database ports in the network listener check.
Everything runs on any OS."""

import http.server
import json
import re
import threading

import pytest

from aegis.core.models import CheckResult, CheckStatus, Finding, Severity
from aegis.scanners import exposure as X
from aegis.scanners import network as nw

def split(out):
    out = list(out)
    return [x for x in out if isinstance(x, Finding)], [x for x in out if isinstance(x, CheckResult)]


# =========================================================================== UPnP
DESC = """<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><device><friendlyName>Home Router</friendlyName>
<deviceList><device><deviceList><device><serviceList><service>
<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
<controlURL>/ctl/IPConn</controlURL></service></serviceList></device></deviceList></device></deviceList>
</device></root>"""

FAULT = ('<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault>'
         "<detail><UPnPError><errorCode>713</errorCode></UPnPError></detail></s:Fault></s:Body></s:Envelope>")


def soap_ok(action, **fields):
    inner = "".join(f"<{k}>{v}</{k}>" for k, v in fields.items())
    return ('<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>'
            f'<u:{action}Response xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">{inner}'
            f"</u:{action}Response></s:Body></s:Envelope>")


class Router(http.server.BaseHTTPRequestHandler):
    mappings = []
    external = "81.2.69.160"
    seen_actions = []

    def log_message(self, *a):
        pass

    def _send(self, code, body):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/xml")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._send(200, DESC) if self.path == "/desc.xml" else self._send(404, "")

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"])).decode()
        action = self.headers["SOAPAction"].strip('"').split("#")[1]
        Router.seen_actions.append(action)
        if action == "GetExternalIPAddress":
            return self._send(200, soap_ok(action, NewExternalIPAddress=self.external))
        idx = int(re.search(r"<NewPortMappingIndex>(\d+)<", body).group(1))
        if idx >= len(self.mappings):
            return self._send(500, FAULT)
        ext, proto, client, internal, desc = self.mappings[idx]
        self._send(200, soap_ok(action, NewRemoteHost="", NewExternalPort=ext, NewProtocol=proto, NewInternalPort=internal,
                                NewInternalClient=client, NewEnabled=1, NewPortMappingDescription=desc,
                                NewLeaseDuration=0))


@pytest.fixture
def router():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Router)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    Router.mappings, Router.external, Router.seen_actions = [], "81.2.69.160", []
    yield srv
    srv.shutdown()
    srv.server_close()


def test_discover_gateway_over_real_http_and_soap(router):
    port = router.server_address[1]
    Router.mappings = [(3389, "TCP", "192.168.1.10", 3389, "rdp"), (51413, "UDP", "192.168.1.10", 51413, "qBittorrent")]
    gw = X.discover_gateway(lambda: [("127.0.0.1", f"http://127.0.0.1:{port}/desc.xml")])
    assert gw.name == "Home Router" and gw.external_ip == "81.2.69.160"
    assert gw.control_url == f"http://127.0.0.1:{port}/ctl/IPConn" and gw.service.endswith("WANIPConnection:1")
    assert [m.label for m in gw.mappings] == ["TCP 3389 -> 192.168.1.10:3389", "UDP 51413 -> 192.168.1.10:51413"]
    assert Router.seen_actions == ["GetExternalIPAddress"] + ["GetGenericPortMappingEntry"] * 3


def test_discovery_ignores_locations_on_another_host(router):
    port = router.server_address[1]
    assert X.discover_gateway(lambda: [("192.168.1.1", f"http://127.0.0.1:{port}/desc.xml")]) is None
    assert Router.seen_actions == []


@pytest.mark.parametrize("url,ip,ok", [
    ("http://192.168.1.1:5000/rootDesc.xml", "192.168.1.1", True),
    ("http://192.168.1.1:5000/x", "192.168.1.2", False),
    ("https://192.168.1.1/x", "192.168.1.1", False),
    ("http://8.8.8.8/x", "8.8.8.8", False),
    ("http://router.local/x", "192.168.1.1", False),
    ("not a url", "192.168.1.1", False),
])
def test_same_host_url(url, ip, ok):
    assert X.same_host_url(url, ip) is ok


def test_description_with_a_dtd_is_refused():
    evil = b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaa">]><root>&a;</root>'
    assert X.parse_description(evil, "http://192.168.1.1/") is None
    assert X.parse_description(b"<garbage", "http://192.168.1.1/") is None
    assert X.parse_ssdp_location(b"HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1:1900/igd.xml\r\n\r\n") == \
        "http://192.168.1.1:1900/igd.xml"


def gw_with(*mappings, external="81.2.69.160"):
    return X.Gateway("192.168.1.1", "http://192.168.1.1/d.xml", "http://192.168.1.1/c", X.WAN_SERVICES[1], "Home Router",
                     external, [X.PortMapping(*m) for m in mappings])


def test_assess_gateway_severities():
    gw = gw_with((3389, "TCP", "192.168.1.10", 3389, "rdp"), (8080, "TCP", "192.168.1.10", 8080, "proxy"),
                 (51413, "UDP", "192.168.1.10", 51413, "qBittorrent"), (22, "TCP", "192.168.1.50", 22, "nas"),
                 (9999, "TCP", "192.168.1.10", 9999, "old game"), (80, "TCP", "192.168.1.60", 80, "camera"))
    listeners = {8080: ("svc.exe", r"C:\Users\bob\AppData\Local\Temp\svc.exe"),
                 51413: ("qbittorrent.exe", r"C:\Program Files\qBittorrent\qbittorrent.exe")}
    findings, checks = split(X.assess_gateway(gw, ["192.168.1.10"], listeners))
    by = {(f.rule_id, f.evidence.get("external_port")): f for f in findings}
    assert by[("AEG-EXP-UPNP-RISKY", 3389)].severity == Severity.HIGH and "this computer" in by[("AEG-EXP-UPNP-RISKY", 3389)].title
    assert by[("AEG-EXP-UPNP-STAGED", 8080)].severity == Severity.HIGH
    assert by[("AEG-EXP-UPNP-FORWARD", 51413)].severity == Severity.LOW and "qbittorrent.exe" in by[("AEG-EXP-UPNP-FORWARD", 51413)].description
    assert by[("AEG-EXP-UPNP-RISKY", 22)].severity == Severity.MEDIUM and "192.168.1.50" in by[("AEG-EXP-UPNP-RISKY", 22)].title
    assert "stale" in by[("AEG-EXP-UPNP-FORWARD", 9999)].description
    assert ("AEG-EXP-UPNP-RISKY", 80) not in by and ("AEG-EXP-UPNP-FORWARD", 80) not in by  # another device, harmless port
    listing = [f for f in findings if f.rule_id == "AEG-EXP-UPNP-LIST"][0]
    assert listing.severity == Severity.INFO and len(listing.evidence["mappings"]) == 6
    assert checks[0].status == CheckStatus.FAIL and "6 forward(s), 3 risky" in checks[0].detail


def test_carrier_grade_nat_caps_severity():
    findings, checks = split(X.assess_gateway(gw_with((3389, "TCP", "192.168.1.10", 3389, ""), external="100.64.3.9"),
                                              ["192.168.1.10"], {}))
    rdp = [f for f in findings if f.rule_id == "AEG-EXP-UPNP-RISKY"][0]
    assert rdp.severity == Severity.LOW and "carrier-grade" in rdp.description and checks[0].status == CheckStatus.PASS


def test_router_without_forwards_passes():
    findings, checks = split(X.assess_gateway(gw_with(), ["192.168.1.10"], {}))
    assert findings == [] and checks[0].status == CheckStatus.PASS and "forwards no ports" in checks[0].detail


# =========================================================================== Docker
def docker(tmp_path, kind, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return X.assess_docker([(kind, p)], X._read_text)


def test_docker_daemon_json_tcp_without_tls(tmp_path):
    f = docker(tmp_path, "daemon", "daemon.json", json.dumps({"hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2375"]}))
    assert len(f) == 1 and f[0].severity == Severity.HIGH and f[0].evidence["host"] == "tcp://0.0.0.0:2375"
    assert docker(tmp_path, "daemon", "tls.json", json.dumps({"hosts": ["tcp://0.0.0.0:2376"], "tlsverify": True})) == []
    assert docker(tmp_path, "daemon", "bad.json", "{not json") == []


def test_docker_desktop_expose_setting(tmp_path):
    f = docker(tmp_path, "desktop", "settings-store.json", json.dumps({X.DOCKER_DESKTOP_KEY: True}))
    assert f[0].severity == Severity.MEDIUM and "Docker Desktop" in f[0].recommendation
    assert docker(tmp_path, "desktop", "off.json", json.dumps({X.DOCKER_DESKTOP_KEY: False})) == []


def test_docker_systemd_unit(tmp_path):
    unit = "[Service]\nExecStart=\nExecStart=/usr/bin/dockerd -H fd:// -H tcp://0.0.0.0:2375\n"
    assert docker(tmp_path, "unit", "override.conf", unit)[0].evidence["host"] == "tcp://0.0.0.0:2375"
    assert docker(tmp_path, "unit", "tls.conf", unit.replace("2375", "2376 --tlsverify")) == []
    assert docker(tmp_path, "unit", "plain.conf", "[Service]\nExecStart=/usr/bin/dockerd -H fd://\n") == []


def test_docker_missing_files_are_skipped(tmp_path):
    assert X.assess_docker([("daemon", tmp_path / "nope.json")], X._read_text) == []


# =========================================================================== network listener ports, registration
def test_database_listening_on_all_interfaces_is_reported():
    conns = [nw.ConnInfo(pid=10, name="redis-server.exe", exe="", laddr="0.0.0.0", lport=6379, raddr="", rport=0,
                         status="LISTEN"),
             nw.ConnInfo(pid=11, name="postgres.exe", exe="", laddr="127.0.0.1", lport=5432, raddr="", rport=0,
                         status="LISTEN")]
    out = nw.listening_findings(conns)
    assert [(f.evidence["port"], f.severity) for f in out] == [(6379, Severity.MEDIUM)]


def test_scanner_is_registered_and_in_the_audit_and_full_profiles():
    from aegis.core.engine import PROFILES
    from aegis.scanners.base import REGISTRY, load_all

    load_all()
    assert "exposure" in REGISTRY and "exposure" in PROFILES["audit"] and "exposure" in PROFILES["full"]


def test_scanner_run_without_a_router(monkeypatch, ctx):
    monkeypatch.setattr(X, "discover_gateway", lambda: None)
    monkeypatch.setattr(X, "docker_config_files", lambda env, home: [])
    findings, checks = split(X.ExposureScanner().run(ctx))
    upnp = [c for c in checks if c.check_id == "EXP-UPNP"]
    assert findings == [] and upnp[0].status == CheckStatus.SKIP
