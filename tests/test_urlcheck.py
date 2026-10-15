"""URL heuristics tests (offline)."""

import json
from types import SimpleNamespace

import pytest

from aegis.tools import urlcheck
from aegis.tools.urlcheck import check_url, levenshtein, registered_domain, split_host


class Sigs:
    def __init__(self, bad=()):
        self.bad = set(bad)

    def is_bad_domain(self, d):
        return d in self.bad or any(d.endswith("." + b) for b in self.bad)

    def is_bad_ip(self, ip):
        return ip in self.bad


def verdict(url, **kw):
    return check_url(url, **kw)["verdict"]


def test_result_shape():
    r = check_url("https://example.com/")
    assert set(r) >= {"url", "host", "verdict", "score", "reasons"}
    assert r["host"] == "example.com" and r["verdict"] == "safe" and 0 <= r["score"] <= 100
    assert isinstance(r["reasons"], list) and r["reasons"]


@pytest.mark.parametrize("host,expected", [
    ("www.example.com", "example.com"),
    ("a.b.example.co.uk", "example.co.uk"),
    ("shop.example.com.au", "example.com.au"),
    ("example.co.in", "example.co.in"),
    ("login.example.com.br", "example.com.br"),
    ("x.example.co.jp", "example.co.jp"),
    ("localhost", "localhost"),
    ("user.github.io", "user.github.io"),
])
def test_registered_domain(host, expected):
    assert registered_domain(host) == expected


def test_split_host():
    assert split_host("a.b.paypal.com") == ("a.b", "paypal", "com")
    assert split_host("www.bbc.co.uk") == ("www", "bbc", "co.uk")


def test_levenshtein():
    assert levenshtein("paypal", "paypa1") == 1
    assert levenshtein("microsoft", "rnicrosoft") == 2
    assert levenshtein("abc", "abc") == 0
    assert levenshtein("abcdefgh", "zzzzzzzz", 2) > 2


@pytest.mark.parametrize("url", [
    "https://www.google.com/search?q=microsoft+login",
    "https://github.com/microsoft/vscode",
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    "https://www.amazon.co.uk/dp/B000",
    "https://www.amazon.de/",
    "https://pineapple.com/",
    "https://en.wikipedia.org/wiki/PayPal",
    "https://stackoverflow.com/questions/1/paypal-ipn",
    "https://docs.python.org/3/library/urllib.html",
    "https://www.bbc.co.uk/news",
    "https://mail.google.com/mail/u/0/#inbox",
    "https://ample.com/",
    "https://www.paypal.com/signin",
])
def test_legit_urls_are_safe(url):
    r = check_url(url)
    assert r["verdict"] == "safe", (url, r["reasons"])


@pytest.mark.parametrize("url,needle", [
    ("http://185.23.4.5/login.php", "IP"),
    ("http://2130706433/", "obfuscated"),
    ("https://paypa1.com/signin", "typosquat"),
    ("https://rnicrosoft.com/", "typosquat"),
    ("https://paypal.com.secure-login.example.xyz/verify", "paypal"),
    ("https://paypal-secure-login.com/", "paypal"),
    ("https://microsoft.com.evil.cn/office365/login", "microsoft"),
    ("https://google.com@evil.example.tk/login", "'@'"),
    ("https://example.com/files/invoice.pdf.exe", "double extension"),
])
def test_phishing_patterns_flagged(url, needle):
    r = check_url(url)
    assert r["verdict"] in ("suspicious", "malicious"), (url, r)
    assert any(needle.lower() in reason.lower() for reason in r["reasons"]), (needle, r["reasons"])


def test_punycode_and_homoglyph():
    r = check_url("https://xn--pypal-4ve.com/")
    assert r["verdict"] == "malicious"
    assert any("punycode" in x for x in r["reasons"])
    r2 = check_url("https://pаypal.com/")  # Cyrillic 'a'
    assert r2["verdict"] == "malicious"
    assert any("homoglyph" in x or "imitate" in x for x in r2["reasons"])


def test_shorteners_are_suspicious():
    for u in ("https://bit.ly/3abc", "https://tinyurl.com/x", "https://t.co/abc", "https://is.gd/x", "https://cutt.ly/y",
              "https://rb.gy/z", "https://shorturl.at/q"):
        r = check_url(u)
        assert r["verdict"] == "suspicious", u
        assert any("expand" in x for x in r["reasons"])


def test_risky_tld_alone_is_not_enough_but_with_login_is_suspicious():
    assert verdict("https://example.xyz/") == "safe"
    assert verdict("https://secure-account-verify.xyz/login") in ("suspicious", "malicious")


def test_dangerous_schemes():
    assert verdict("javascript:alert(1)") == "malicious"
    assert verdict("data:text/html;base64,PGh0bWw+") == "malicious"
    assert verdict("data:image/png;base64,AAAA") == "suspicious"


def test_http_login_page_gets_points_but_not_alone_suspicious():
    r = check_url("http://example.com/account/login")
    assert r["score"] >= 20 and any("unencrypted" in x for x in r["reasons"])


def test_known_bad_domain_from_signatures():
    sigs = Sigs(bad={"malware.example.net"})
    r = check_url("https://sub.malware.example.net/a", signatures=sigs)
    assert r["verdict"] == "malicious" and r["score"] >= 90
    assert check_url("https://good.example.net/", signatures=sigs)["verdict"] == "safe"
    r_ip = check_url("http://203.0.113.7/x", signatures=Sigs(bad={"203.0.113.7"}))
    assert r_ip["verdict"] == "malicious"


def test_excessive_subdomains_and_length():
    r = check_url("https://a.b.c.d.e.f.example.com/" + "x" * 220)
    assert any("subdomains" in x for x in r["reasons"]) and any("long URL" in x for x in r["reasons"])


def test_garbage_never_raises():
    for u in ("", "   ", "http://", "://", "http://[::1", "http://exa mple.com", "\x00", "a" * 5000, "http://a:b:c@d/"):
        r = check_url(u)
        assert r["verdict"] in ("safe", "suspicious", "malicious")


def test_scheme_less_input():
    assert check_url("paypa1.com/login")["verdict"] == "suspicious"
    assert check_url("example.com")["host"] == "example.com"


def test_google_safe_browsing_used_only_with_key(monkeypatch):
    calls = []

    def fake_request(url, method="GET", headers=None, data=None, timeout=15):
        calls.append((url, json.loads(data)))
        return 200, json.dumps({"matches": [{"threatType": "SOCIAL_ENGINEERING"}]}).encode()

    monkeypatch.setattr("aegis.tools.reputation.http_request", fake_request)
    assert check_url("https://example.com/", config=SimpleNamespace(google_safebrowsing_api_key="", abusech_auth_key=""))["verdict"] == "safe"
    assert not calls
    r = check_url("https://example.com/", config=SimpleNamespace(google_safebrowsing_api_key="KEY", abusech_auth_key=""))
    assert r["verdict"] == "malicious" and any("Safe Browsing" in x for x in r["reasons"])
    assert "key=KEY" in calls[0][0] and calls[0][1]["threatInfo"]["threatEntries"] == [{"url": "https://example.com/"}]


def test_urlhaus_used_only_with_auth_key(monkeypatch):
    monkeypatch.setattr("aegis.tools.reputation.http_request", lambda *a, **k: (200, json.dumps(
        {"query_status": "ok", "url_status": "online", "threat": "malware_download", "tags": [], "host": "x"}).encode()))
    cfg = SimpleNamespace(google_safebrowsing_api_key="", abusech_auth_key="AUTH")
    assert check_url("https://example.com/a.exe", config=cfg)["verdict"] == "malicious"


def test_online_failure_is_ignored(monkeypatch):
    monkeypatch.setattr("aegis.tools.reputation.http_request", lambda *a, **k: None)
    cfg = SimpleNamespace(google_safebrowsing_api_key="K", abusech_auth_key="A")
    assert check_url("https://example.com/", config=cfg)["verdict"] == "safe"
