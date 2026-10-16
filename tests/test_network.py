"""Tests for aegis.scanners.network: pure decision logic plus a live Linux run."""

import datetime as dt
import os
import re

import pytest

from aegis.core.config import Config
from aegis.core.models import CheckResult, CheckStatus, Finding, Severity
from aegis.core.signatures import SignatureDB
from aegis.scanners import network as nw
from aegis.scanners.base import ScanContext
from aegis.scanners.network import ConnInfo

S = Severity


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path / "home"))
    cfg = Config()
    return ScanContext(cfg, SignatureDB(cfg))


def C(pid=100, name="app.exe", raddr="", rport=0, laddr="10.0.0.5", lport=50000, status="ESTABLISHED", exe=""):
    return ConnInfo(pid, name, exe, laddr, lport, raddr, rport, status)


def rules(fs):
    return [f.rule_id for f in fs]


# --------------------------------------------------------------------------- ip helpers

def test_ip_helpers():
    assert nw.is_private_ip("10.1.2.3") and nw.is_private_ip("192.168.0.1") and nw.is_private_ip("127.0.0.1")
    assert nw.is_private_ip("::1") and nw.is_private_ip("fe80::1%eth0") and nw.is_private_ip("0.0.0.0")
    assert not nw.is_private_ip("8.8.8.8") and not nw.is_private_ip("not-an-ip")
    assert nw.is_loopback_or_null("127.0.0.1") and nw.is_loopback_or_null("0.0.0.0") and not nw.is_loopback_or_null("10.0.0.1")
    assert nw.host_is_internal("wpad") and nw.host_is_internal("proxy.corp") and nw.host_is_internal("192.168.1.1")
    assert not nw.host_is_internal("evil-proxy.example.com") and not nw.host_is_internal("8.8.8.8")


# --------------------------------------------------------------------------- connections

def test_bad_ip_is_critical_with_kill_remediation():
    bad = {"185.220.101.9"}
    conns = [C(7, "evil.exe", "185.220.101.9", 443, exe=r"C:\Users\bob\AppData\Local\Temp\evil.exe"),
             C(8, "chrome.exe", "93.184.216.34", 443), C(9, "x", "10.0.0.9", 443)]
    f = nw.bad_ip_findings(conns, lambda ip: ip in bad)
    assert rules(f) == ["AEG-NET-BADIP"] and f[0].severity == S.CRITICAL
    assert f[0].remediation.action == "kill_process"
    assert f[0].remediation.params == {"pid": 7, "path": r"C:\Users\bob\AppData\Local\Temp\evil.exe", "quarantine": True}
    assert f[0].evidence["remote_ip"] == "185.220.101.9"
    # private addresses are never matched, duplicates collapse
    assert nw.bad_ip_findings([C(1, "a", "10.0.0.1", 1)], lambda ip: True) == []
    assert len(nw.bad_ip_findings([C(7, "e", "185.220.101.9", 1), C(7, "e", "185.220.101.9", 2)], lambda ip: True)) == 1


def test_bad_ip_does_not_quarantine_system_binaries():
    f = nw.bad_ip_findings([C(7, "svchost.exe", "185.220.101.9", 443, exe=r"C:\Windows\System32\svchost.exe")], lambda ip: True)
    assert f[0].remediation.params["quarantine"] is False


@pytest.mark.parametrize("port,rule", [(4444, "AEG-NET-C2PORT"), (1337, "AEG-NET-C2PORT"), (31337, "AEG-NET-C2PORT"),
                                       (6667, "AEG-NET-IRC"), (6669, "AEG-NET-IRC"), (3333, "AEG-NET-MINERPORT"),
                                       (14444, "AEG-NET-MINERPORT"), (45700, "AEG-NET-MINERPORT"), (5555, "AEG-NET-MINERPORT"),
                                       (7777, "AEG-NET-MINERPORT")])
def test_suspicious_ports(port, rule):
    f = nw.suspicious_port_findings([C(5, "svc.exe", "45.9.148.7", port)])
    assert rules(f) == [rule] and f[0].severity == S.MEDIUM and f[0].remediation.action == "kill_process"


def test_suspicious_ports_exemptions():
    assert nw.suspicious_port_findings([C(1, "chrome.exe", "45.9.148.7", 4444)]) == []  # browsers
    assert nw.suspicious_port_findings([C(1, "hexchat", "45.9.148.7", 6667)]) == []  # IRC client on IRC port
    assert nw.suspicious_port_findings([C(1, "adb", "192.168.1.20", 5555)]) == []  # private remote (LAN devices, dev servers)
    assert nw.suspicious_port_findings([C(1, "x", "45.9.148.7", 443)]) == []
    assert nw.suspicious_port_findings([C(0, "", "45.9.148.7", 4444)]) == []  # unknown process
    assert nw.suspicious_port_findings([C(1, "x", "", 0, status="LISTEN")]) == []
    assert rules(nw.suspicious_port_findings([C(1, "hexchat", "45.9.148.7", 4444)])) == ["AEG-NET-C2PORT"]


def test_listening_services_summarised_by_port():
    conns = [C(1, "svchost.exe", "", 0, "0.0.0.0", 3389, "LISTEN"), C(1, "svchost.exe", "", 0, "::", 3389, "LISTEN"),
             C(4, "System", "", 0, "0.0.0.0", 445, "LISTEN"), C(5, "telnetd", "", 0, "0.0.0.0", 23, "LISTEN"),
             C(6, "vnc", "", 0, "127.0.0.1", 5900, "LISTEN"),  # loopback only -> fine
             C(7, "x", "", 0, "192.168.1.5", 21, "LISTEN"),  # bound to one interface -> not "all interfaces"
             C(8, "sshd", "", 0, "0.0.0.0", 22, "LISTEN")]
    f = nw.listening_findings(conns)
    by = {x.evidence["port"]: x for x in f}
    assert set(by) == {3389, 445, 23}
    assert by[3389].severity == S.MEDIUM and by[445].severity == S.LOW and by[23].severity == S.MEDIUM
    assert by[3389].evidence["processes"] == ["svchost.exe"] and len(f) == 3


def test_tor_detection():
    conns = [C(1, "evil.exe", "127.0.0.1", 9050), C(2, "tor.exe", "127.0.0.1", 9050), C(3, "x", "", 0, "127.0.0.1", 9150, "LISTEN"),
             C(4, "firefox.exe", "127.0.0.1", 9150, exe=r"C:\Users\bob\Desktop\Tor Browser\Browser\firefox.exe"),
             C(5, "curl", "8.8.8.8", 9050)]
    f = nw.tor_findings(conns)
    assert sorted(x.evidence["pid"] for x in f) == [1, 3]
    assert all(x.rule_id == "AEG-NET-TOR" and x.severity == S.MEDIUM for x in f)


def test_collect_connections_live():
    conns, warning = nw.collect_connections()
    assert isinstance(conns, list)
    assert all(isinstance(c, ConnInfo) for c in conns)


# --------------------------------------------------------------------------- hosts file

HOSTS_CLEAN = """# Copyright (c) Microsoft
127.0.0.1       localhost
::1             localhost
127.0.1.1       myhost
10.0.0.5        nas.lan nas
0.0.0.0 ads.example.net   # ad blocking
0.0.0.0 vortex.data.microsoft.com
0.0.0.0 telemetry.microsoft.com
127.0.0.1 watson.telemetry.microsoft.com
172.17.0.1 host.docker.internal
"""


def test_parse_hosts():
    es = nw.parse_hosts("# c\n\n127.0.0.1 localhost LocalHost.\nbad line\n1.2.3.4 a.example.com # x\n::1 ip6-localhost\n")
    assert [(e.ip, e.hosts) for e in es] == [("127.0.0.1", ["localhost", "localhost"]), ("1.2.3.4", ["a.example.com"]),
                                             ("::1", ["ip6-localhost"])]
    assert es[1].line == "1.2.3.4 a.example.com # x"


def test_clean_hosts_and_privacy_blocking_is_not_flagged():
    assert nw.hosts_findings(HOSTS_CLEAN, "/etc/hosts") == []


def test_hosts_redirect_important_domains_high():
    text = HOSTS_CLEAN + "185.220.101.50 www.paypal.com\n185.220.101.50 login.microsoftonline.com\n192.168.1.7 www.google.com\n"
    f = nw.hosts_findings(text, r"C:\Windows\System32\drivers\etc\hosts")
    assert rules(f) == ["AEG-NET-HOSTS-REDIRECT"]
    assert f[0].severity == S.HIGH and f[0].remediation.action == "restore_hosts"
    assert f[0].remediation.params["path"].endswith("hosts")
    assert "185.220.101.50 www.paypal.com" in f[0].remediation.params["remove_lines"]
    assert f[0].evidence["count"] == 3


def test_hosts_private_redirect_is_medium():
    f = nw.hosts_findings("192.168.1.7 www.google.com\n", "/etc/hosts")
    assert f[0].severity == S.MEDIUM


def test_hosts_blocking_av_and_update_domains_high():
    text = ("127.0.0.1 update.kaspersky.com\n0.0.0.0 download.eset.com\n0.0.0.0 www.malwarebytes.com\n"
            "0.0.0.0 windowsupdate.microsoft.com\n127.0.0.1 download.windowsupdate.com\n0.0.0.0 virustotal.com\n")
    f = nw.hosts_findings(text, "/etc/hosts")
    assert rules(f) == ["AEG-NET-HOSTS-BLOCK"] and f[0].severity == S.HIGH
    assert f[0].evidence["count"] == 6 and len(f[0].remediation.params["remove_lines"]) == 6


def test_hosts_both_categories_and_bank_keyword_and_many_custom():
    text = "10.9.9.9 www.mybank.com\n0.0.0.0 avast.com\n" + "".join(f"10.0.0.{i % 250} host{i}.lan\n" for i in range(40))
    f = nw.hosts_findings(text, "/etc/hosts")
    assert set(rules(f)) == {"AEG-NET-HOSTS-REDIRECT", "AEG-NET-HOSTS-BLOCK", "AEG-NET-HOSTS-CUSTOM"}
    assert next(x for x in f if x.rule_id == "AEG-NET-HOSTS-CUSTOM").severity == S.INFO


def test_classify_host():
    assert nw.classify_host("update.kaspersky.com") == "av"
    assert nw.classify_host("download.windowsupdate.com") == "update"
    assert nw.classify_host("mail.google.com") == "important"
    assert nw.classify_host("example.org") is None and nw.classify_host("localhost") is None
    assert nw.classify_host("notgoogle.com") is None  # suffix match respects label boundaries


# --------------------------------------------------------------------------- proxy

def test_proxy_findings():
    vals = {"ProxyEnable": 1, "ProxyServer": "45.9.148.9:8080", "AutoConfigURL": "http://evil.example.com/proxy.pac"}
    f = nw.proxy_findings(vals)
    assert rules(f) == ["AEG-NET-PROXY", "AEG-NET-PAC"] and all(x.severity == S.MEDIUM for x in f)
    assert f[0].remediation.action == "set_registry_value"
    assert f[0].remediation.params == {"hive": "HKCU", "key": nw.INET_KEY, "value": "ProxyEnable", "data": 0}
    assert f[1].remediation.action == "delete_registry_value" and f[1].remediation.params["value"] == "AutoConfigURL"


def test_proxy_benign_cases():
    assert nw.proxy_findings({}) == []
    assert nw.proxy_findings({"ProxyEnable": 0, "ProxyServer": "45.9.148.9:8080"}) == []
    local = nw.proxy_findings({"ProxyEnable": 1, "ProxyServer": "127.0.0.1:8888"})
    assert local[0].severity == S.LOW  # Fiddler/Zscaler style local proxy
    corp = nw.proxy_findings({"AutoConfigURL": "http://wpad.corp/wpad.dat"})
    assert corp[0].severity == S.LOW
    multi = nw.proxy_findings({"ProxyEnable": 1, "ProxyServer": "http=45.9.148.9:80;https=45.9.148.9:80"})
    assert multi[0].severity == S.MEDIUM
    assert nw.proxy_findings({"AutoConfigURL": "file:///C:/x/proxy.pac"})[0].severity == S.MEDIUM


def test_env_proxy_info():
    assert nw.env_proxy_findings("PATH=/bin\n", "/etc/environment") == []
    f = nw.env_proxy_findings('PATH=/bin\nhttp_proxy="http://10.0.0.1:3128"\nHTTPS_PROXY=http://10.0.0.1:3128\n', "/etc/environment")
    assert rules(f) == ["AEG-NET-ENVPROXY"] and f[0].severity == S.INFO and len(f[0].evidence["variables"]) == 2


# --------------------------------------------------------------------------- DNS

def test_dns_findings():
    nobad = lambda ip: False
    assert nw.dns_findings([("Wi-Fi", "192.168.1.1"), ("Wi-Fi", "8.8.8.8"), ("Eth", "1.1.1.1"), ("Eth", "2001:4860:4860::8888"),
                            ("lo", "127.0.0.53"), ("Eth", "9.9.9.9"), ("Eth", "208.67.222.222")], nobad) == []
    f = nw.dns_findings([("Wi-Fi", "192.168.1.1"), ("Wi-Fi", "185.220.101.77")], nobad)
    assert rules(f) == ["AEG-NET-DNS"] and f[0].severity == S.LOW and "185.220.101.77" in f[0].evidence["servers"][0]
    f = nw.dns_findings([("Wi-Fi", "185.220.101.77"), ("Wi-Fi", "45.9.148.1")], lambda ip: ip == "185.220.101.77")
    assert rules(f) == ["AEG-NET-DNS-BAD", "AEG-NET-DNS"] and f[0].severity == S.HIGH


def test_parse_resolv_conf():
    t = "# comment\nnameserver 8.8.8.8\nnameserver fe80::1%eth0\nsearch example.com\nnameserver 1.1.1.1\n"
    assert [s for _, s in nw.parse_resolv_conf(t)] == ["8.8.8.8", "fe80::1", "1.1.1.1"]


# --------------------------------------------------------------------------- root certificates

NOW = dt.datetime(2025, 6, 1, 12, 0, 0)


def cert(subject, store="LocalMachine", thumb="A" * 40, nb="2010-01-01T00:00:00.0000000Z", issuer=None):
    return {"Store": store, "Subject": subject, "Issuer": issuer or subject, "Thumbprint": thumb, "NotBefore": nb}


def test_rootca_malicious_roots_high():
    certs = [cert("CN=Superfish, Inc., O=Superfish, Inc."), cert("CN=eDellRoot"), cert("CN=PrivDog Root"),
             cert("CN=Komodia Ltd"), cert("CN=DO_NOT_TRUST"), cert("CN=DigiCert Global Root G2, O=DigiCert Inc")]
    f = nw.rootca_findings(certs, NOW)
    assert len(f) == 5 and all(x.rule_id == "AEG-NET-ROOTCA" and x.severity == S.HIGH for x in f)
    assert f[0].remediation.action == "run_command" and f[0].remediation.params["powershell"] is True
    assert "A" * 40 in f[0].remediation.params["command"]


def test_rootca_debugging_proxies_medium():
    certs = [cert("CN=DO_NOT_TRUST_FiddlerRoot, O=DO_NOT_TRUST, OU=Created by http://www.fiddler2.com"),
             cert("CN=mitmproxy, O=mitmproxy"), cert("CN=PortSwigger CA, O=PortSwigger, OU=PortSwigger CA"),
             cert("CN=Charles Proxy CA (12 Jun 2024, laptop), OU=https://charlesproxy.com/ssl")]
    f = nw.rootca_findings(certs, NOW)
    assert len(f) == 4 and all(x.rule_id == "AEG-NET-DEBUGCA" and x.severity == S.MEDIUM for x in f)


def test_rootca_recent_user_store_low_and_bad_thumbprint_has_no_fix():
    recent = (NOW - dt.timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%S.0000000Z")
    old = "2015-01-01T00:00:00.0000000Z"
    f = nw.rootca_findings([cert("CN=Corp Root", "CurrentUser", "B" * 40, recent), cert("CN=Old Root", "CurrentUser", "C" * 40, old),
                            cert("CN=New Machine Root", "LocalMachine", "D" * 40, recent)], NOW)
    assert rules(f) == ["AEG-NET-ROOTCA-NEW"] and f[0].severity == S.LOW
    bad = nw.rootca_findings([cert("CN=Superfish", thumb="not-a-thumbprint'; evil")], NOW)
    assert bad[0].remediation is None  # never interpolate unvalidated text into a PowerShell command


def test_parse_iso_date():
    assert nw.parse_iso_date("2025-05-30T10:00:00.0000000Z") == dt.datetime(2025, 5, 30, 10, 0, 0)
    assert nw.parse_iso_date("/Date(1748599200000)/") == dt.datetime(2025, 5, 30, 10, 0, 0)
    assert nw.parse_iso_date("garbage") is None and nw.parse_iso_date(None) is None


# --------------------------------------------------------------------------- Wi-Fi / SMB

WIFI_OPEN = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    State                  : connected
    SSID                   : CoffeeShop
    BSSID                  : aa:bb:cc:dd:ee:ff
    Radio type             : 802.11n
    Authentication         : Open
    Cipher                 : None
"""


def test_wifi_findings():
    f = nw.wifi_findings(WIFI_OPEN)
    assert rules(f) == ["AEG-NET-WIFI"] and f[0].severity == S.MEDIUM and f[0].evidence["ssid"] == "CoffeeShop"
    assert nw.wifi_findings(WIFI_OPEN.replace("Open", "WEP"))[0].evidence["authentication"] == "wep"
    assert nw.wifi_findings(WIFI_OPEN.replace("Open", "WPA2-Personal")) == []
    assert nw.wifi_findings(WIFI_OPEN.replace("Authentication", "Authentifizierung").replace("Open", "Offen"))
    assert nw.wifi_findings(WIFI_OPEN.replace("    SSID                   : CoffeeShop\n", "")) == []  # not connected
    assert nw.wifi_findings("") == []


def test_smb_findings():
    shares = [
        {"Name": "ADMIN$", "Path": "C:\\Windows", "Access": []},
        {"Name": "print$", "Path": "C:\\Windows\\system32\\spool\\drivers"},
        {"Name": "Docs", "Path": "C:\\Docs", "Access": [{"Account": "BUILTIN\\Administrators", "Type": "Allow", "Right": "Full"}]},
        {"Name": "Public", "Path": "C:\\Public", "Access": [{"Account": "Everyone", "Type": "Allow", "Right": "Full"}]},
        {"Name": "Ro", "Path": "C:\\Ro", "Access": {"Account": "Everyone", "Type": "Allow", "Right": "Read"}},
        {"Name": "Denied", "Path": "C:\\D", "Access": [{"Account": "Everyone", "Type": "Deny", "Right": "Full"}]},
    ]
    f = {x.evidence["name"]: x for x in nw.smb_findings(shares)}
    assert set(f) == {"Docs", "Public", "Ro", "Denied"}
    assert f["Docs"].severity == S.LOW and f["Denied"].severity == S.LOW
    assert f["Public"].severity == S.MEDIUM and "write/full" in f["Public"].description
    assert f["Ro"].severity == S.MEDIUM and "read" in f["Ro"].description


# --------------------------------------------------------------------------- scanner

def test_scanner_runs_on_linux_and_emits_checks(ctx, monkeypatch):
    monkeypatch.setattr(nw, "IS_WINDOWS", False)  # exercise the non-Windows path on every CI OS
    out = list(nw.NetworkScanner().run(ctx))
    assert all(isinstance(o, (Finding, CheckResult)) for o in out)
    ids = {o.check_id: o for o in out if isinstance(o, CheckResult)}
    for needed in ("AEG-NET-CHK-CONN", "AEG-NET-CHK-HOSTS", "AEG-NET-CHK-PROXY", "AEG-NET-CHK-ROOTCA", "AEG-NET-CHK-FIREWALL"):
        assert needed in ids
    assert ids["AEG-NET-CHK-ROOTCA"].status == "skip"
    assert ids["AEG-NET-CHK-FIREWALL"].status in ("skip", "pass", "warn", "fail")  # ufw may be present (and readable) here
    assert ids["AEG-NET-CHK-CONN"].status in ("pass", "warn", "fail")


def test_scanner_flags_dirty_hosts_and_bad_ip(ctx, tmp_path, monkeypatch):
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n0.0.0.0 update.eset.com\n185.220.101.50 www.paypal.com\n")
    monkeypatch.setattr(nw, "hosts_path", lambda: hosts)
    monkeypatch.setattr(nw, "collect_connections",
                        lambda: ([C(9, "evil", "185.220.101.9", 443, exe="/tmp/evil"), C(10, "svc", "45.9.148.1", 4444)], None))
    monkeypatch.setattr(nw, "collect_dns", lambda: [("lo", "127.0.0.53")])
    ctx.signatures.bad_ips.add("185.220.101.9")
    out = list(nw.NetworkScanner().run(ctx))
    rule_ids = {o.rule_id for o in out if isinstance(o, Finding)}
    assert {"AEG-NET-BADIP", "AEG-NET-C2PORT", "AEG-NET-HOSTS-REDIRECT", "AEG-NET-HOSTS-BLOCK"} <= rule_ids
    checks = {o.check_id: o.status for o in out if isinstance(o, CheckResult)}
    assert checks["AEG-NET-CHK-HOSTS"] == "fail" and checks["AEG-NET-CHK-CONN"] == "fail"
    crit = [o for o in out if isinstance(o, Finding) and o.rule_id == "AEG-NET-BADIP"][0]
    assert crit.severity == S.CRITICAL and crit.scanner == "network"


def test_scanner_clean_machine_passes(ctx, tmp_path, monkeypatch):
    monkeypatch.setattr(nw, "IS_WINDOWS", False)  # don't read the CI host's real certs/proxy/shares
    hosts = tmp_path / "hosts"
    hosts.write_text(HOSTS_CLEAN)
    monkeypatch.setattr(nw, "hosts_path", lambda: hosts)
    monkeypatch.setattr(nw, "collect_connections", lambda: ([C(1, "chrome", "93.184.216.34", 443)], None))
    monkeypatch.setattr(nw, "collect_dns", lambda: [("eth0", "192.168.1.1"), ("eth0", "1.1.1.1")])
    monkeypatch.setattr(nw, "collect_ufw_rules", lambda: (None, "not reviewed in this test"))  # not the CI host's firewall
    out = list(nw.NetworkScanner().run(ctx))
    assert not [o for o in out if isinstance(o, Finding)]
    checks = {o.check_id: o.status for o in out if isinstance(o, CheckResult)}
    assert checks["AEG-NET-CHK-HOSTS"] == "pass" and checks["AEG-NET-CHK-CONN"] == "pass" and checks["AEG-NET-CHK-DNS"] == "pass"


def test_scanner_survives_collector_errors(ctx, monkeypatch):
    def boom():
        raise RuntimeError("boom")
    monkeypatch.setattr(nw, "collect_connections", boom)
    monkeypatch.setattr(nw, "collect_dns", boom)
    out = list(nw.NetworkScanner().run(ctx))
    checks = {o.check_id: o.status for o in out if isinstance(o, CheckResult)}
    assert checks["AEG-NET-CHK-CONN"] == "error" and checks["AEG-NET-CHK-DNS"] == "error"


def test_scanner_metadata():
    from aegis.scanners.base import REGISTRY
    assert REGISTRY["network"] is nw.NetworkScanner and nw.NetworkScanner.name == "network"


def test_root_store_classification_uses_physical_user_store():
    """A new Microsoft root seen through the merged Cert:\\CurrentUser view must not be
    treated as user-installed; only thumbprints in the HKCU registry store are."""
    import datetime as _dt

    recent = (_dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None) - _dt.timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%S")
    ms = {"Store": "CurrentUser", "Subject": "CN=Microsoft Root Certificate Authority 2026", "Issuer": "same",
          "Thumbprint": "A" * 40, "NotBefore": recent}
    mine = {"Store": "CurrentUser", "Subject": "CN=Some Local Dev CA", "Issuer": "same",
            "Thumbprint": "b" * 40, "NotBefore": recent}
    certs = nw.classify_root_stores([ms, dict(ms, Store="LocalMachine"), mine], {"B" * 40})
    assert {c["Thumbprint"].upper(): c["Store"] for c in certs} == {"A" * 40: "LocalMachine", "b".upper() * 40: "CurrentUser"}
    ids = [f.rule_id for f in nw.rootca_findings(certs)]
    assert ids.count("AEG-NET-ROOTCA-NEW") == 1


def test_aegis_web_protection_block_is_not_reported_but_cannot_hide_hijacks():
    block = "\n".join(f"0.0.0.0 malware{i}.example" for i in range(60))
    text = ("127.0.0.1 localhost\n" + nw.AEGIS_BLOCK_BEGIN + "\n" + block + "\n"
            + "185.220.101.50 www.paypal.com\n0.0.0.0 update.eset.com\n" + nw.AEGIS_BLOCK_END + "\n")
    entries = nw.parse_hosts(text)
    hosts = {h for e in entries for h in e.hosts}
    assert not any(h.startswith("malware") for h in hosts)  # our sinkhole entries are ignored
    assert {"www.paypal.com", "update.eset.com"} <= hosts      # hijacks inside our markers are still seen
    ids = {f.rule_id for f in nw.hosts_findings(text, "hosts")}
    assert "AEG-NET-HOSTS-CUSTOM" not in ids
    assert {"AEG-NET-HOSTS-REDIRECT", "AEG-NET-HOSTS-BLOCK"} <= ids


# ---------------------------------------------------------------- saved Wi-Fi profiles
def _wlan_xml(name, auth, enc, mode="auto", hidden=False, conn="ESS"):
    return f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
\t<name>{name}</name>
\t<SSIDConfig>
\t\t<SSID>
\t\t\t<hex>4E6574</hex>
\t\t\t<name>{name}</name>
\t\t</SSID>
\t\t<nonBroadcast>{'true' if hidden else 'false'}</nonBroadcast>
\t</SSIDConfig>
\t<connectionType>{conn}</connectionType>
\t<connectionMode>{mode}</connectionMode>
\t<MSM>
\t\t<security>
\t\t\t<authEncryption>
\t\t\t\t<authentication>{auth}</authentication>
\t\t\t\t<encryption>{enc}</encryption>
\t\t\t\t<useOneX>false</useOneX>
\t\t\t</authEncryption>
\t\t</security>
\t</MSM>
\t<MacRandomization xmlns="http://www.microsoft.com/networking/WLAN/profile/v3">
\t\t<enableRandomization>false</enableRandomization>
\t</MacRandomization>
</WLANProfile>
"""


def test_parse_wlan_profile_xml():
    from aegis.scanners import network as net

    p = net.parse_wlan_profile_xml("﻿" + _wlan_xml("Airport Free WiFi", "open", "none"))
    assert (p.name, p.ssid, p.auth, p.encryption, p.auto, p.hidden) == ("Airport Free WiFi", "Airport Free WiFi", "open",
                                                                         "none", True, False)
    assert p.is_open and not p.is_wep
    home = net.parse_wlan_profile_xml(_wlan_xml("Home", "WPA2PSK", "AES", mode="manual", hidden=True))
    assert (home.auth, home.encryption, home.auto, home.hidden) == ("wpa2psk", "aes", False, True) and not home.is_open
    assert net.parse_wlan_profile_xml(_wlan_xml("adhoc", "open", "none", conn="IBSS")) is None
    assert net.parse_wlan_profile_xml("<notwlan/>") is None and net.parse_wlan_profile_xml("garbage <") is None


def test_wifi_profile_findings_rate_each_kind():
    from aegis.scanners import network as net

    P = net.WifiProfile
    profiles = [P("Cafe", "Cafe", "open", "none", True), P("Library", "Library", "open", "none", False),
                P("OldRouter", "OldRouter", "open", "wep", True), P("Shared", "Shared", "shared", "wep", False),
                P("Legacy", "Legacy", "wpapsk", "tkip", True), P("Hidden", "Hidden", "wpa2psk", "aes", True, hidden=True),
                P("Home", "Home", "wpa2psk", "aes", True), P("Enhanced", "Enhanced", "owe", "aes", True)]
    by = {f.evidence["ssid"]: f for f in net.wifi_profile_findings(profiles)}
    assert set(by) == {"Cafe", "OldRouter", "Shared", "Legacy", "Hidden"}  # manual open, WPA2 and OWE are fine
    assert by["Cafe"].rule_id == "AEG-NET-WIFI-OPEN-AUTO" and by["Cafe"].severity == Severity.LOW
    assert by["Cafe"].remediation.params["command"] == ["netsh", "wlan", "set", "profileparameter", "name=Cafe",
                                                        "connectionmode=manual"]
    assert by["OldRouter"].rule_id == "AEG-NET-WIFI-WEP" and by["OldRouter"].severity == Severity.MEDIUM
    assert by["Shared"].remediation is None  # WEP but not auto-joined: nothing to switch to manual
    assert by["Legacy"].rule_id == "AEG-NET-WIFI-TKIP" and by["Hidden"].rule_id == "AEG-NET-WIFI-HIDDEN-AUTO"
    assert by["Cafe"].location == "Saved Wi-Fi network: Cafe"  # stable fingerprint across scans
    many = [P(f"Hotspot {i}", f"Hotspot {i}", "open", "none", True) for i in range(40)]
    assert len(net.wifi_profile_findings(many)) == net.MAX_WIFI_FINDINGS
    nm = net.wifi_profile_findings([P("Cafe", "Cafe", "none", "none", True, source="networkmanager")])
    assert nm[0].remediation.params["command"] == ["nmcli", "connection", "modify", "Cafe", "connection.autoconnect", "no"]


def test_collect_windows_wifi_profiles_exports_without_keys_and_cleans_up(tmp_path):
    from pathlib import Path

    from aegis.scanners import network as net

    seen = {}

    def runner(cmd, timeout=60):
        seen["cmd"] = cmd
        folder = Path(next(a for a in cmd if a.startswith("folder="))[7:])
        seen["folder"] = folder
        (folder / "Wi-Fi-Cafe.xml").write_text(_wlan_xml("Cafe", "open", "none"), encoding="utf-8")
        (folder / "Wi-Fi-Home.xml").write_text(_wlan_xml("Home", "WPA3SAE", "AES"), encoding="utf-8")
        return 0, "Interface profile \"Cafe\" is saved in file ...", ""

    profiles, why = net.collect_windows_wifi_profiles(runner)
    assert why == "" and sorted(p.ssid for p in profiles) == ["Cafe", "Home"]
    assert "key=absent" in seen["cmd"] and not seen["folder"].exists()  # never exports keys; temp folder removed
    profiles, why = net.collect_windows_wifi_profiles(
        lambda cmd, timeout=60: (1, "The Wireless AutoConfig Service (wlansvc) is not running.", ""))
    assert profiles is None and "wlansvc" in why


def test_collect_nm_wifi_profiles_parses_terse_output():
    from aegis.scanners import network as net

    detail = {
        "Cafe": "802-11-wireless.ssid:Cafe\n802-11-wireless.hidden:no\n802-11-wireless-security.key-mgmt:\n"
                "802-11-wireless-security.wep-key-type:\n",
        "Home\\:5G": "802-11-wireless.ssid:Home:5G\n802-11-wireless.hidden:yes\n802-11-wireless-security.key-mgmt:sae\n"
                     "802-11-wireless-security.wep-key-type:\n",
        "Old": "802-11-wireless.ssid:Old\n802-11-wireless.hidden:no\n802-11-wireless-security.key-mgmt:none\n"
               "802-11-wireless-security.wep-key-type:key\n",
    }

    def runner(cmd, timeout=60):
        if cmd[:4] == ["nmcli", "-t", "-f", "NAME,TYPE,AUTOCONNECT"]:
            return 0, "Wired connection 1:802-3-ethernet:yes\nCafe:802-11-wireless:yes\nHome\\:5G:802-11-wireless:yes\n" \
                      "Old:802-11-wireless:no\n", ""
        name = cmd[-1]
        key = name.replace(":", "\\:")
        return (0, detail[key], "") if key in detail else (10, "", "Error: unknown connection")

    profiles, why = net.collect_nm_wifi_profiles(runner)
    by = {p.name: p for p in profiles}
    assert set(by) == {"Cafe", "Home:5G", "Old"} and why == ""
    assert by["Cafe"].is_open and by["Cafe"].auto and by["Cafe"].source == "networkmanager"
    assert by["Home:5G"].ssid == "Home:5G" and by["Home:5G"].hidden and not by["Home:5G"].is_open
    assert by["Old"].is_wep and not by["Old"].auto
    assert net.collect_nm_wifi_profiles(lambda cmd, timeout=60: (-1, "", "not found: nmcli"))[0] is None


def test_saved_wifi_check_statuses():
    from aegis.scanners import network as net

    P = net.WifiProfile
    out = list(net.NetworkScanner._saved_wifi(lambda: ([P("Cafe", "Cafe", "open", "none", True)], "")))
    assert [type(x).__name__ for x in out] == ["Finding", "CheckResult"] and out[-1].status == CheckStatus.WARN
    out = list(net.NetworkScanner._saved_wifi(lambda: ([P("Old", "Old", "open", "wep", True)], "")))
    assert out[-1].status == CheckStatus.FAIL
    out = list(net.NetworkScanner._saved_wifi(lambda: (None, "no adapter")))
    assert len(out) == 1 and out[0].status == CheckStatus.SKIP and "no adapter" in out[0].detail
    out = list(net.NetworkScanner._saved_wifi(lambda: ([P("Home", "Home", "wpa2psk", "aes", True)], "")))
    assert out[-1].status == CheckStatus.PASS and "1 saved network(s), 1 joined automatically" in out[-1].detail


# --------------------------------------------------------------------------- firewall rules

def FW(name="{R1}", display="Custom rule", program="Any", ports=("Any",), remote=("Any",), profile="Any", group="",
       display_group="", protocol="TCP", package="Any", service="Any", owner=""):
    """A custom enabled inbound allow rule; the defaults describe the 'allow everything' shape."""
    return nw.FirewallRule(name, display, group, display_group, profile, owner, program, package, service, protocol,
                           None if ports is None else list(ports), None if remote is None else list(remote))


def fw_findings(*rules, exists=lambda p: True):
    return nw.firewall_rule_findings(rules, exists)


def fw_by_rule(*rules, exists=lambda p: True):
    return {f.evidence["rule"]: f for f in nw.firewall_rule_findings(rules, exists) if "rule" in f.evidence}


BUILTIN = {"group": "@FirewallAPI.dll,-28752", "display_group": "Remote Desktop", "display": "Remote Desktop - User Mode (TCP-In)"}


def test_parse_firewall_rules_handles_single_objects_lists_and_missing_filters():
    one = {"Name": "{A}", "DisplayName": "Remote Desktop - User Mode (TCP-In)", "Group": "@FirewallAPI.dll,-28752",
           "DisplayGroup": "Remote Desktop", "Profile": "Any", "Owner": "", "Program": "System", "Package": "Any",
           "Service": "Any", "Protocol": "TCP", "LocalPort": "3389", "RemoteAddress": "Any"}
    (r,) = nw.parse_firewall_rules(one)  # PowerShell prints a lone object, not a list
    assert r.name == "{A}" and r.group == "@FirewallAPI.dll,-28752" and r.windows_owned and r.has_group
    assert r.local_ports == ["3389"] and r.remote_addresses == ["Any"] and r.program == "System" and r.label == one["DisplayName"]
    rules = nw.parse_firewall_rules([one, "junk", 5, {"DisplayName": "no name"}, {"Name": "{B}", "DisplayName": "Mine"},
                                     {"Name": "{C}", "Program": None, "LocalPort": [], "RemoteAddress": ["10.0.0.0/8", "LocalSubnet"]}])
    assert [x.name for x in rules] == ["{A}", "{B}", "{C}"]
    b, c = rules[1], rules[2]
    assert b.program is None and b.local_ports is None and b.remote_addresses is None  # filters missing: unknown, not "Any"
    assert b.group == "" and not b.has_group and not b.windows_owned and b.label == "Mine"
    assert c.program is None and c.local_ports == [] and c.remote_addresses == ["10.0.0.0/8", "LocalSubnet"]
    assert nw.parse_firewall_rules(None) == [] and nw.parse_firewall_rules([]) == []
    nameless = nw.parse_firewall_rules({"Name": "{D}"})[0]
    assert nameless.label == "{D}"
    store = nw.parse_firewall_rules({"Name": "{E}", "DisplayName": "@{Microsoft.XboxApp_1?ms-resource://x}"})[0]
    assert store.windows_owned


@pytest.mark.parametrize("program", [
    r"C:\Users\bob\AppData\Local\Temp\evil.exe", r"C:\Users\bob\Downloads\tool.exe", r"C:\Users\Public\x.exe",
    r"C:\Users\bob\AppData\Roaming\svc.exe", r"C:\Users\bob\AppData\Local\svc.exe", r"C:\ProgramData\svc.exe",
    r"C:\$Recycle.Bin\S-1-5-21-1\x.exe", r"C:\Windows\Temp\a.exe", r"c:\users\BOB\appdata\local\temp\Evil.EXE",
    r"C:\Users\bob\Desktop\setup.exe"])
def test_user_writable_programs_are_flagged(program):
    assert nw.firewall_program_in_user_path(program)
    (f,) = fw_findings(FW(program=program, ports=("8080",), remote=("LocalSubnet",), profile="Private"))
    expected = S.MEDIUM if ("\\Downloads\\" in program or "\\Desktop\\" in program) else S.HIGH  # firewall-prompt rules
    assert f.rule_id == "AEG-NET-FW-USERPATH" and f.severity == expected and f.category == "suspicious"
    assert f.mitre == ["T1686.003"] and f.scanner == "network" and program in f.description and f.evidence["program"] == program


@pytest.mark.parametrize("program", [
    r"C:\Program Files\Mozilla Firefox\firefox.exe", r"C:\Program Files (x86)\Steam\steam.exe",
    r"C:\Windows\System32\svchost.exe", r"%SystemRoot%\system32\svchost.exe", r"C:\Users\bob\AppData\Local\Programs\Python\python.exe",
    r"C:\Users\bob\AppData\Roaming\Spotify\Spotify.exe", r"C:\Users\bob\AppData\Local\Discord\app-1.0\Discord.exe",
    r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe", r"C:\Tools\nmap\nmap.exe",
    "Any", "System", "", None])
def test_normal_programs_are_not_flagged_as_user_writable(program):
    assert not nw.firewall_program_in_user_path(program)
    assert not [f for f in fw_findings(FW(program=program, ports=("8080",), remote=("LocalSubnet",), profile="Private"))
                if f.rule_id == "AEG-NET-FW-USERPATH"]


def test_user_path_check_does_not_trust_builtin_groups_or_owners():
    r = FW(program=r"C:\Users\bob\Downloads\x.exe", ports=("3389",), remote=("Any",), owner="S-1-5-21-1-2-3",
           group=BUILTIN["group"], display_group=BUILTIN["display_group"], display=BUILTIN["display"])
    (f,) = fw_findings(r)  # a rule can claim any name or group, so only the program matters
    assert f.rule_id == "AEG-NET-FW-USERPATH"


def test_allow_all_rule_is_medium_outside_builtin_groups():
    (f,) = fw_findings(FW(display="Allow everything"))
    assert f.rule_id == "AEG-NET-FW-ALLOWALL" and f.severity == S.MEDIUM and f.category == "network" and f.mitre == ["T1686.003"]
    assert f.evidence["rule"] == "{R1}" and f.evidence["profile"] == "Any" and f.location == "Windows Firewall rule: Allow everything [{R1}]"
    assert f.remediation.action == "run_command" and f.remediation.params["command"][-3:] == ["dir=in", "new", "enable=no"]
    for kw in (dict(profile="Domain, Public"), dict(profile="Public"), dict(remote=("0.0.0.0/0",)), dict(remote=("Internet",)),
               dict(remote=("10.0.0.1", "*")), dict(ports=("1-65535",)), dict(ports=("0-65535",)), dict(ports=("80", "Any")),
               dict(protocol="Any"), dict(protocol="UDP"), dict(protocol="6"), dict(remote=("0.0.0.0-255.255.255.255",))):
        assert [x.rule_id for x in fw_findings(FW(**kw))] == ["AEG-NET-FW-ALLOWALL"], kw


@pytest.mark.parametrize("kw", [
    dict(group="@FirewallAPI.dll,-28502"),  # Windows' own group
    dict(group="Custom Tools"), dict(display_group="Custom Tools"),  # any group: outside the 'created ad hoc' class
    dict(display="@{Microsoft.WindowsStore_1?ms-resource://x}"),
    dict(owner="S-1-5-21-1-2-3"),
    dict(program=r"C:\Program Files\App\app.exe"), dict(package="S-1-15-2-1"), dict(service="dnscache"),
    dict(ports=("80",)), dict(ports=("1000-2000",)), dict(ports=("RPC",)), dict(ports=()),
    dict(protocol="ICMPv4"), dict(protocol="47"), dict(protocol=""),
    dict(profile="Domain, Private"), dict(profile="Private"), dict(profile=""),
    dict(remote=("LocalSubnet",)), dict(remote=("192.168.0.0/16",)), dict(remote=()),
    dict(program=None), dict(ports=None), dict(remote=None), dict(package=None), dict(service=None)])
def test_rules_that_are_not_allow_all_are_not_reported(kw):
    assert not nw.firewall_allows_everything(FW(**kw))
    assert [f for f in fw_findings(FW(**kw)) if f.rule_id == "AEG-NET-FW-ALLOWALL"] == []


@pytest.mark.parametrize("ports,services", [
    (("3389",), ["Remote Desktop (RDP)"]), (("5900-5903",), ["VNC"]), (("5985", "5986"), ["WinRM (HTTP)", "WinRM (HTTPS)"]),
    (("22",), ["SSH"]), (("445",), ["SMB file sharing"]), (("80,443,3389",), ["Remote Desktop (RDP)"]),
    (("3000-4000",), ["Remote Desktop (RDP)"]), (("21", "445-445", "22"), ["SSH", "SMB file sharing"])])
def test_admin_ports_open_to_the_public_are_medium(ports, services):
    r = FW(display="Remote access", ports=ports)
    assert sorted(set(nw.firewall_public_admin_ports(r).values())) == sorted(services)
    (f,) = [x for x in fw_findings(FW(display="Remote access", ports=ports, program="C:\\Tools\\srv.exe"))]
    assert f.rule_id == "AEG-NET-FW-PUBLICADMIN" and f.severity == S.MEDIUM and f.mitre == ["T1021", "T1686.003"]
    assert sorted(f.evidence["services"]) == sorted(services) and f.remediation is None  # restricting it is the user's call
    assert "Set-NetFirewallRule" in f.recommendation and all(s in f.title for s in services[:1])


@pytest.mark.parametrize("kw", [
    dict(group="@FirewallAPI.dll,-28752"), dict(display="@FirewallAPI.dll,-28753"),  # the built-in feature rule groups
    dict(profile="Domain, Private"), dict(profile="Private"), dict(remote=("LocalSubnet",)), dict(remote=("Intranet",)),
    dict(ports=("8080",)), dict(ports=("23",)), dict(ports=("RPC",)), dict(ports=None), dict(remote=None),
    dict(protocol="ICMPv4"), dict(protocol="47")])
def test_admin_port_rules_that_are_not_exposed_are_not_reported(kw):
    base = dict(ports=("3389",))
    base.update(kw)
    r = FW(program="C:\\Tools\\srv.exe", **base)
    assert nw.firewall_public_admin_ports(r) == {}
    assert fw_findings(r) == []


def test_admin_port_exposure_by_third_party_group_is_still_reported_and_allow_all_ports_is_not_admin_specific():
    third = FW(display="OpenSSH SSH Server (sshd)", ports=("22",), display_group="OpenSSH Server", group="OpenSSH Server")
    assert [f.rule_id for f in fw_findings(third)] == ["AEG-NET-FW-PUBLICADMIN"]
    everything = FW(program="C:\\Tools\\srv.exe", ports=("Any",))  # program-specific, every port: not an admin-port rule
    assert fw_findings(everything) == []
    allow_all = fw_findings(FW(ports=("1-65535",)))
    assert [f.rule_id for f in allow_all] == ["AEG-NET-FW-ALLOWALL"]  # reported once, as allow-all


def test_one_finding_per_rule_most_serious_class_wins_and_findings_are_capped():
    both = FW("{X}", "dropper", program=r"C:\Users\bob\AppData\Local\Temp\a.exe", ports=("3389",))
    allow = FW("{Y}", "open", ports=("Any",))
    fs = fw_findings(both, allow)
    assert [f.rule_id for f in fs] == ["AEG-NET-FW-USERPATH", "AEG-NET-FW-ALLOWALL"]
    many = [FW(f"{{{i}}}", f"Dropper {i}", program=rf"C:\Users\bob\Downloads\d{i}.exe") for i in range(60)]
    capped = fw_findings(*many)
    assert len(capped) == nw.MAX_FW_FINDINGS and len({f.fingerprint for f in capped}) == nw.MAX_FW_FINDINGS


def test_rules_sharing_a_display_name_get_distinct_findings_and_id_based_fixes():
    tcp = FW("{T}", "Zoom", program=r"C:\Users\bob\Downloads\zoom.exe", protocol="TCP", ports=("8080",))
    udp = FW("{U}", "Zoom", program=r"C:\Users\bob\Downloads\zoom.exe", protocol="UDP", ports=("8080",))
    fs = fw_findings(tcp, udp)
    assert len(fs) == 2 and len({f.fingerprint for f in fs}) == 2  # ScanResult would otherwise keep only the first
    assert [f.remediation.params["command"] for f in fs] == ["Disable-NetFirewallRule -Name '{T}'",
                                                             "Disable-NetFirewallRule -Name '{U}'"]
    assert all(f.remediation.params["powershell"] is True for f in fs)
    single = fw_findings(tcp)[0].remediation.params["command"]
    assert single[:5] == ["netsh", "advfirewall", "firewall", "set", "rule"] and "name=Zoom" in single


def test_stale_rules_for_missing_programs_are_one_low_summary():
    gone = [FW(f"{{{i}}}", f"Old app {i}", program=rf"C:\Program Files\Old{i}\old.exe", ports=("8080",), remote=("LocalSubnet",))
            for i in range(30)]
    present = FW("{P}", "Installed", program=r"C:\Program Files\App\app.exe", ports=("8080",))
    calls = []

    def exists(p):
        calls.append(p)
        return "Old" not in p

    fs = fw_findings(present, *gone, FW("{Q}", "Dup", program=r"C:\Program Files\Old3\old.exe", ports=("1",)), exists=exists)
    assert [f.rule_id for f in fs] == ["AEG-NET-FW-STALE"]
    f = fs[0]
    assert f.severity == S.LOW and f.evidence["count"] == 31 and len(f.evidence["rules"]) == 25 and "31" in f.title
    assert f.remediation is None and f.mitre == ["T1686.003"]
    assert sorted(calls) == sorted(set(calls))  # each program is looked up once


def test_stale_check_skips_builtin_unknown_and_already_flagged_rules():
    never = lambda p: False  # noqa: E731
    rules = [FW("{1}", "builtin", program=r"C:\Windows\System32\gone.exe", group="@FirewallAPI.dll,-1", ports=("8080",)),
             FW("{2}", "any", program="Any", ports=("8080",)), FW("{3}", "svc", program="System", ports=("8080",)),
             FW("{4}", "unknown", program=None, ports=None, remote=None),
             FW("{5}", "dropper", program=r"C:\Users\bob\Downloads\x.exe", ports=("8080",)),
             FW("{6}", "open", ports=("Any",))]
    assert [f.rule_id for f in fw_findings(*rules, exists=never)] == ["AEG-NET-FW-USERPATH", "AEG-NET-FW-ALLOWALL"]

    def boom(p):
        raise RuntimeError("probe failed")

    assert fw_findings(FW("{7}", "x", program=r"C:\Gone\x.exe", ports=("1",)), exists=boom) == []  # cannot tell: not stale


def test_program_exists_is_conservative(tmp_path):
    real = tmp_path / "real.exe"
    real.write_text("x")
    assert nw.program_exists(str(real)) and not nw.program_exists(str(tmp_path / "missing.exe"))
    assert nw.program_exists(r"\\server\share\x.exe")  # network path: not probed
    assert nw.program_exists(r"%NO_SUCH_VARIABLE_XYZ%\x.exe")  # unexpanded variable: cannot tell
    assert nw.program_exists("")
    if not os.path.exists("Q:\\"):
        assert nw.program_exists(r"Q:\drive\that\is\not\mounted.exe")  # unmounted drive: cannot tell


@pytest.mark.parametrize("profile,public", [
    ("Any", True), ("any", True), ("Public", True), ("Domain, Public", True), ("Domain, Private, Public", True),
    ("Domain", False), ("Private", False), ("Domain, Private", False), ("", False), ("NotApplicable", False),
    ("0", True), ("4", True), ("7", True), ("3", False), ("1", False)])
def test_profile_includes_public(profile, public):
    assert nw._fw_public(profile) is public


def test_ps_quote_and_netsh_fix_handle_quotes_spaces_and_hostile_names():
    assert nw._ps_quote("Bob's rule") == "Bob''s rule"
    assert nw._ps_quote("a\u2019b\u2018c\u201ad\u201be") == "a\u2019\u2019b\u2018\u2018c\u201a\u201ad\u201b\u201be"
    assert nw._ps_quote("plain {GUID}") == "plain {GUID}"

    fix = nw.firewall_disable_fix(FW("{G1}", "Spotify Music", program=r"C:\Users\bob\Downloads\a b\a.exe"), ambiguous=False)
    assert fix.action == "run_command" and fix.params["powershell"] is False and "Spotify Music" in fix.description
    assert fix.params["command"] == ["netsh", "advfirewall", "firewall", "set", "rule", "name=Spotify Music", "dir=in",
                                     r"program=C:\Users\bob\Downloads\a b\a.exe", "new", "enable=no"]
    assert all(isinstance(a, str) for a in fix.params["command"])  # an argument list: no shell is involved

    # the program filter is only added for a plain, specific path
    for program in ("Any", "System", None, "", r"%ProgramFiles%\x\a.exe", 'C:\\a"b.exe'):
        cmd = nw.firewall_disable_fix(FW(display="Rule", program=program), ambiguous=False).params["command"]
        assert cmd == ["netsh", "advfirewall", "firewall", "set", "rule", "name=Rule", "dir=in", "new", "enable=no"], program

    # shell metacharacters stay inside one argument
    nasty = "a & b | c ; $(calc) %PATH% ^x"
    assert nw.firewall_disable_fix(FW("{G}", nasty), False).params["command"][5] == f"name={nasty}"

    # ambiguous names, "all", resource strings: address the rule by its unique id instead
    for display, ambiguous in (("Shared name", True), ("all", False), ("ALL", False), ("@{Pkg?x}", False), ("", False)):
        ps_fix = nw.firewall_disable_fix(FW("{ID-1}", display), ambiguous)
        assert ps_fix.params == {"command": "Disable-NetFirewallRule -Name '{ID-1}'", "powershell": True}, display

    # a name with quotes: not for netsh, but fine for PowerShell once the quote is doubled (and it round-trips)
    quoted = FW("Bob's \"rule\"", 'My "rule"')
    assert nw.firewall_disable_fix(quoted, False) is None  # double quotes in the id: no automatic fix
    tricky = FW("x'; calc; '", 'q"x')
    fix = nw.firewall_disable_fix(tricky, False)
    m = re.fullmatch(r"Disable-NetFirewallRule -Name '((?:[^']|'')*)'", fix.params["command"])
    assert m and m.group(1).replace("''", "'") == "x'; calc; '"  # everything stays inside the string literal
    smart = nw.firewall_disable_fix(FW("it\u2019s", 'q"x'), False).params["command"]
    assert smart == "Disable-NetFirewallRule -Name 'it\u2019\u2019s'"

    # wildcards, control characters and over-long names are never passed on
    assert nw.firewall_disable_fix(FW("rule*", "ok name"), False).params["command"][5] == "name=ok name"
    for bad in ("rule*", "ru?le", "ru[le]", "line\nbreak", "tab\there", "x" * 201, "nul\x00"):
        assert nw.firewall_disable_fix(FW(bad, bad), False) is None, repr(bad)
    assert nw.firewall_disable_fix(FW("rule*", "ru?le"), False) is None
    assert nw.firewall_disable_fix(FW("{ID}", "x" * 200), False).params["command"][5] == "name=" + "x" * 200


def test_firewall_findings_carry_the_fix_and_explain_how_to_undo_it():
    f = fw_findings(FW("{ID-7}", "Updater", program=r"C:\Users\bob\AppData\Local\Temp\u.exe", ports=("9999",)))[0]
    assert f.remediation.description.startswith("Disable the firewall rule 'Updater'")
    assert "Enable-NetFirewallRule -Name '{ID-7}'" in f.recommendation  # disabled, never deleted: reversible
    quoted = fw_findings(FW("it's", "x'y", program=r"C:\Users\bob\Downloads\u.exe", ports=("1",)))[0]
    assert "Enable-NetFirewallRule -Name 'it''s'" in quoted.recommendation
    admin = fw_findings(FW("{ID-8}", "Custom RDP", ports=("3389",)))[0]
    assert "Set-NetFirewallRule -Name '{ID-8}' -Profile Domain,Private -RemoteAddress LocalSubnet" in admin.recommendation


@pytest.mark.parametrize("name", ["*", "rule*", "ru?le", "ru[le]", 'a"b', "line\nbreak"])
def test_recommendations_never_contain_a_command_with_a_wildcard_or_unquotable_rule_id(name):
    """Pasting `-Name '*'` would touch every rule, so such ids only get the plain-language advice."""
    dropper = fw_findings(FW(name, "x" + name, program=r"C:\Users\bob\Downloads\u.exe", ports=("1",)))[0]
    admin = fw_findings(FW(name, "x" + name, ports=("3389",)))[0]
    for f in (dropper, admin):
        assert "NetFirewallRule" not in f.recommendation
    assert dropper.remediation is None and "Disabling keeps the rule." in dropper.recommendation


def test_collect_windows_firewall_rules_uses_one_batched_call_and_reports_gaps():
    calls = []

    def reader(script, timeout=0):
        calls.append((script, timeout))
        return {"Name": "{A}", "DisplayName": "x", "Program": "Any", "LocalPort": ["Any"], "RemoteAddress": ["Any"]}

    rules, note = nw.collect_windows_firewall_rules(reader)
    assert len(calls) == 1 and calls[0][0] == nw.FIREWALL_SCRIPT and calls[0][1] >= 60  # one call, with a timeout
    assert [r.name for r in rules] == ["{A}"] and note == ""
    assert nw.collect_windows_firewall_rules(lambda s, timeout=0: [])[0] == []  # no rules is an answer, not a failure
    rules, why = nw.collect_windows_firewall_rules(lambda s, timeout=0: None)
    assert rules is None and "could not list" in why
    big = [{"Name": f"r{i}"} for i in range(nw.MAX_FW_RULES)]
    rules, note = nw.collect_windows_firewall_rules(lambda s, timeout=0: big)
    assert len(rules) == nw.MAX_FW_RULES and f"first {nw.MAX_FW_RULES}" in note and f"{nw.MAX_FW_RULES} rule(s)" in note


def test_firewall_script_is_one_well_formed_batched_query():
    from tests.test_persistence import _balanced

    s = nw.FIREWALL_SCRIPT
    assert _balanced(s) and '"' not in s  # survives Windows command-line quoting unchanged
    assert "@MAX@" not in s and f"-First {nw.MAX_FW_RULES}" in s
    for needle in ("Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow", "Get-NetFirewallApplicationFilter -All",
                   "Get-NetFirewallPortFilter -All", "Get-NetFirewallAddressFilter -All", "Get-NetFirewallServiceFilter -All",
                   "ConvertTo-Json -InputObject $o"):
        assert needle in s
    assert s.count("Get-NetFirewallRule") == 1  # filters are fetched in bulk, never per rule


# ---- Linux: ufw

UFW = """Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 3389                       ALLOW IN    Anywhere
[ 3] 5900:5903/tcp              ALLOW IN    192.168.1.0/24
[ 4] 80,443/tcp                 ALLOW IN    Anywhere
[ 5] Nginx Full                 ALLOW IN    Anywhere
[ 6] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
[ 7] 445/tcp                    LIMIT IN    Anywhere
[ 8] Anywhere                   ALLOW OUT   10.0.0.0/8
[ 9] 5985/tcp                   DENY IN     Anywhere
[10] OpenSSH                    ALLOW IN    Anywhere
[11] 5986                       ALLOW       Anywhere                   # winrm
"""


def test_parse_ufw_status():
    active, rules = nw.parse_ufw_status(UFW)
    assert active and len(rules) == 11
    assert (rules[0].to, rules[0].action, rules[0].direction, rules[0].source) == ("22/tcp", "allow", "in", "Anywhere")
    assert (rules[6].action, rules[7].direction, rules[8].action) == ("limit", "out", "deny")
    assert rules[10].to == "5986" and rules[10].direction == "in" and rules[10].source == "Anywhere"  # comment dropped
    assert rules[4].to == "Nginx Full"
    assert nw.parse_ufw_status("Status: inactive\n") == (False, [])
    assert nw.parse_ufw_status("") == (False, [])
    assert nw.parse_ufw_status("Status: active\n[ 1] garbage line\n[ 2] 22/tcp ALLOW IN Anywhere\n")[1] == []  # single spaces: not columns


@pytest.mark.parametrize("to,ports", [
    ("22/tcp", [22]), ("22/tcp (v6)", [22]), ("3389", [3389]), ("5900:5903/tcp", [5900, 5901, 5902, 5903]),
    ("80,443/tcp", []), ("80,3389/udp", [3389]), ("OpenSSH", [22]), ("OpenSSH (v6)", [22]), ("Samba", [445]),
    ("Nginx Full", []), ("Anywhere", []), ("10.0.0.5 22/tcp", [22]), ("22/tcp on eth0", [22]), ("192.168.1.5", []),
    ("1000:2000/tcp", []), ("", [])])
def test_ufw_admin_ports(to, ports):
    assert sorted(nw.ufw_admin_ports(to)) == ports


def test_ufw_findings_report_admin_ports_open_to_anywhere():
    _active, rules = nw.parse_ufw_status(UFW)
    by = {f.evidence["service"]: f for f in nw.ufw_findings(rules)}
    assert set(by) == {"SSH", "Remote Desktop (RDP)", "SMB file sharing", "WinRM (HTTPS)"}  # VNC is limited to a subnet
    assert by["SSH"].severity == S.LOW and by["SSH"].evidence["ports"] == [22] and len(by["SSH"].evidence["rules"]) == 3
    for svc in ("Remote Desktop (RDP)", "SMB file sharing", "WinRM (HTTPS)"):
        assert by[svc].severity == S.MEDIUM and by[svc].rule_id == "AEG-NET-FW-PUBLICADMIN"
    assert by["Remote Desktop (RDP)"].mitre == ["T1021", "T1686"] and by["SSH"].remediation is None
    assert by["SSH"].location == "ufw: SSH allowed from anywhere" and "ufw limit" in by["SSH"].description
    limit_ssh = nw.parse_ufw_status("Status: active\n[ 1] 22/tcp                     LIMIT IN    Anywhere\n")[1]
    assert nw.ufw_findings(limit_ssh) == []  # rate-limited SSH is the recommended setup
    restricted = nw.parse_ufw_status("Status: active\n[ 1] 3389                       ALLOW IN    192.168.1.0/24\n")[1]
    assert nw.ufw_findings(restricted) == []
    anywhere4 = nw.parse_ufw_status("Status: active\n[ 1] 5900                       ALLOW IN    0.0.0.0/0\n")[1]
    assert [f.evidence["service"] for f in nw.ufw_findings(anywhere4)] == ["VNC"]


def test_collect_ufw_rules_statuses():
    ok = lambda cmd, timeout=60: (0, UFW, "")  # noqa: E731
    rules, why = nw.collect_ufw_rules(ok)
    assert len(rules) == 11 and why == ""
    seen = []
    nw.collect_ufw_rules(lambda cmd, timeout=60: seen.append(cmd) or (0, UFW, ""))
    assert seen == [["ufw", "status", "numbered"]]
    rules, why = nw.collect_ufw_rules(lambda cmd, timeout=60: (1, "", "ERROR: You need to be root to run this script\n"))
    assert rules is None and "root" in why
    rules, why = nw.collect_ufw_rules(lambda cmd, timeout=60: (-1, "", "not found: ufw"))
    assert rules is None and "not found" in why
    rules, why = nw.collect_ufw_rules(lambda cmd, timeout=60: (0, "Status: inactive\n", ""))
    assert rules is None and "not active" in why
    assert nw.collect_ufw_rules(lambda cmd, timeout=60: (3, "", ""))[1] == "ufw exited with 3"


# ---- check result and scanner

def test_firewall_check_statuses():
    def run_check(collect, review, what="rule(s)"):
        return list(nw.NetworkScanner._firewall_rules(collect, review, what))

    out = run_check(lambda: (None, "needs root"), lambda r: [])
    assert len(out) == 1 and out[0].status == CheckStatus.SKIP and "needs root" in out[0].detail
    assert out[0].check_id == "AEG-NET-CHK-FIREWALL" and out[0].title == "Firewall rules only allow expected programs"
    assert out[0].category == "network" and out[0].scanner == "network"

    out = run_check(lambda: ([FW(), FW("{2}")], ""), lambda r: [], "enabled inbound allow rule(s)")
    assert [type(o).__name__ for o in out] == ["CheckResult"] and out[0].status == CheckStatus.PASS
    assert out[0].detail == "2 enabled inbound allow rule(s) reviewed; 0 need attention."

    medium = _f_for_test(S.MEDIUM)
    low = _f_for_test(S.LOW)
    out = run_check(lambda: ([FW()], ""), lambda r: [medium, low])
    assert [type(o).__name__ for o in out] == ["Finding", "Finding", "CheckResult"] and out[-1].status == CheckStatus.FAIL
    assert "2 need attention" in out[-1].detail
    out = run_check(lambda: ([FW()], ""), lambda r: [low])
    assert out[-1].status == CheckStatus.WARN
    out = run_check(lambda: ([FW()], "only the first 5000 rules were reviewed"), lambda r: [])
    assert out[-1].status == CheckStatus.WARN and "only the first 5000 rules were reviewed" in out[-1].detail

    def boom():
        raise RuntimeError("boom")

    out = run_check(boom, lambda r: [])
    assert out[0].status == CheckStatus.ERROR and "boom" in out[0].detail
    out = run_check(lambda: ([FW()], ""), lambda r: 1 / 0)
    assert out[-1].status == CheckStatus.ERROR and "ZeroDivisionError" in out[-1].detail


def _f_for_test(sev):
    return Finding("AEG-NET-FW-TEST", "t", sev, "network", scanner="network")


def _isolate_network_run(monkeypatch, tmp_path):
    """Nothing but the code under test touches the host: no psutil, registry, PowerShell, netsh or hosts file."""
    monkeypatch.setattr(nw, "collect_connections", lambda: ([], None))
    monkeypatch.setattr(nw, "collect_dns", lambda: [])
    monkeypatch.setattr(nw, "hosts_path", lambda: tmp_path / "no-hosts")
    monkeypatch.setattr(nw, "powershell_json", lambda *a, **k: None)
    monkeypatch.setattr(nw, "run", lambda *a, **k: (-1, "", "not found"))
    monkeypatch.setattr(nw, "reg_values", lambda *a, **k: {})
    monkeypatch.setattr(nw, "reg_subkeys", lambda *a, **k: [])
    monkeypatch.setattr(nw, "collect_windows_wifi_profiles", lambda *a, **k: (None, "test"))
    monkeypatch.setattr(nw, "collect_nm_wifi_profiles", lambda *a, **k: (None, "test"))


def test_scanner_reviews_firewall_rules_on_windows(ctx, tmp_path, monkeypatch):
    _isolate_network_run(monkeypatch, tmp_path)
    monkeypatch.setattr(nw, "IS_WINDOWS", True)
    rules = [FW("{1}", "Dropper", program=r"C:\Users\bob\AppData\Local\Temp\evil.exe", ports=("4444",)),
             FW("{2}", "Remote Desktop - User Mode (TCP-In)", group="@FirewallAPI.dll,-28752", display_group="Remote Desktop",
                ports=("3389",), program="System"),
             FW("{3}", "Firefox", program=r"C:\Program Files\Mozilla Firefox\firefox.exe", ports=("8080",), profile="Private")]
    monkeypatch.setattr(nw, "collect_windows_firewall_rules", lambda: (rules, ""))
    out = list(nw.NetworkScanner().run(ctx))
    fw = [o for o in out if isinstance(o, Finding) and o.rule_id.startswith("AEG-NET-FW")]
    assert [f.rule_id for f in fw] == ["AEG-NET-FW-USERPATH"] and fw[0].evidence["rule"] == "{1}"
    check = {o.check_id: o for o in out if isinstance(o, CheckResult)}["AEG-NET-CHK-FIREWALL"]
    assert check.status == CheckStatus.FAIL and "3 enabled inbound allow rule(s) reviewed; 1 need attention" in check.detail


def test_scanner_skips_firewall_review_when_windows_cannot_list_rules(ctx, tmp_path, monkeypatch):
    _isolate_network_run(monkeypatch, tmp_path)
    monkeypatch.setattr(nw, "IS_WINDOWS", True)
    monkeypatch.setattr(nw, "collect_windows_firewall_rules", lambda: (None, "service stopped"))
    out = list(nw.NetworkScanner().run(ctx))
    check = {o.check_id: o for o in out if isinstance(o, CheckResult)}["AEG-NET-CHK-FIREWALL"]
    assert check.status == CheckStatus.SKIP and "service stopped" in check.detail


def test_scanner_reviews_ufw_on_linux_and_skips_elsewhere(ctx, tmp_path, monkeypatch):
    _isolate_network_run(monkeypatch, tmp_path)
    monkeypatch.setattr(nw, "IS_WINDOWS", False)
    monkeypatch.setattr(nw, "IS_LINUX", True)
    monkeypatch.setattr(nw, "collect_ufw_rules", lambda: (nw.parse_ufw_status(UFW)[1], ""))
    out = list(nw.NetworkScanner().run(ctx))
    fw = [o for o in out if isinstance(o, Finding) and o.rule_id == "AEG-NET-FW-PUBLICADMIN"]
    assert {f.evidence["service"] for f in fw} == {"SSH", "Remote Desktop (RDP)", "SMB file sharing", "WinRM (HTTPS)"}
    check = {o.check_id: o for o in out if isinstance(o, CheckResult)}["AEG-NET-CHK-FIREWALL"]
    assert check.status == CheckStatus.FAIL and "11 ufw rule(s) reviewed" in check.detail

    monkeypatch.setattr(nw, "collect_ufw_rules", lambda: (None, "ufw is not active"))
    check = {o.check_id: o for o in nw.NetworkScanner().run(ctx) if isinstance(o, CheckResult)}["AEG-NET-CHK-FIREWALL"]
    assert check.status == CheckStatus.SKIP and "ufw is not active" in check.detail

    def linux_only():
        raise AssertionError("ufw is Linux only")

    monkeypatch.setattr(nw, "IS_LINUX", False)  # macOS and others
    monkeypatch.setattr(nw, "collect_ufw_rules", linux_only)
    check = {o.check_id: o for o in nw.NetworkScanner().run(ctx) if isinstance(o, CheckResult)}["AEG-NET-CHK-FIREWALL"]
    assert check.status == CheckStatus.SKIP
