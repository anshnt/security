"""Tests for aegis.scanners.network: pure decision logic plus a live Linux run."""

import datetime as dt

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
    for needed in ("AEG-NET-CHK-CONN", "AEG-NET-CHK-HOSTS", "AEG-NET-CHK-PROXY", "AEG-NET-CHK-ROOTCA"):
        assert needed in ids
    assert ids["AEG-NET-CHK-ROOTCA"].status == "skip"
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
