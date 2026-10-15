"""Password checker tests: k-anonymity request shape, parsing, strength model."""

import hashlib
import io
import urllib.error

import pytest

from aegis.tools import password as pw


class FakeResp(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def sha1_parts(p):
    h = hashlib.sha1(p.encode()).hexdigest().upper()
    return h[:5], h[5:]


def install_fake(monkeypatch, body_for_suffix=None, error=None):
    seen = []

    def fake_urlopen(req, timeout=None):
        seen.append({"url": req.full_url, "headers": {k.lower(): v for k, v in req.header_items()}, "data": req.data,
                     "method": req.get_method()})
        if error:
            raise error
        return FakeResp(body_for_suffix.encode())

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    return seen


def test_k_anonymity_only_sends_five_chars(monkeypatch):
    prefix, suffix = sha1_parts("hunter2-example")
    body = f"0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n{suffix}:4242\r\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\r\n"
    seen = install_fake(monkeypatch, body)
    r = pw.check_password("hunter2-example")
    assert r["pwned_count"] == 4242
    assert len(seen) == 1 and seen[0]["method"] == "GET" and seen[0]["data"] is None
    assert seen[0]["url"] == "https://api.pwnedpasswords.com/range/" + prefix and len(prefix) == 5
    assert seen[0]["headers"]["add-padding"] == "true"
    sent = seen[0]["url"] + str(seen[0]["headers"])
    full = hashlib.sha1(b"hunter2-example").hexdigest()
    assert suffix.lower() not in sent.lower() and full not in sent.lower() and "hunter2" not in sent
    assert r["strength"] == 0 and "4,242" in r["feedback"][0]


def test_not_found_and_padding_rows_count_as_zero(monkeypatch):
    prefix, suffix = sha1_parts("zq9!Lm2#vRw8$Kx")
    install_fake(monkeypatch, f"{suffix}:0\r\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:5\r\n")
    r = pw.check_password("zq9!Lm2#vRw8$Kx")
    assert r["pwned_count"] == 0 and r["online_error"] == ""
    assert r["strength"] >= 3


def test_network_failure_sets_online_error(monkeypatch):
    install_fake(monkeypatch, error=urllib.error.URLError("no network"))
    r = pw.check_password("correct horse battery staple")
    assert r["pwned_count"] is None and "no network" in r["online_error"]
    assert r["strength"] >= 3  # offline strength still computed


def test_http_error_is_handled(monkeypatch):
    install_fake(monkeypatch, error=urllib.error.HTTPError("u", 503, "x", {}, None))
    assert pw.check_password("abc")["pwned_count"] is None


def test_offline_makes_no_request(monkeypatch):
    seen = install_fake(monkeypatch, "")
    r = pw.check_password("whatever123", online=False)
    assert seen == [] and r["pwned_count"] is None and r["online_error"] == ""


def test_empty_password():
    r = pw.check_password("", online=False)
    assert r["strength"] == 0 and r["feedback"]


@pytest.mark.parametrize("p", ["password", "123456", "qwerty", "P@ssw0rd", "iloveyou", "Password1", "letmein"])
def test_common_passwords_score_zero(p):
    r = pw.check_password(p, online=False)
    assert r["strength"] == 0, p
    assert r["entropy_bits"] < 28


@pytest.mark.parametrize("p", ["aaaaaaaaaaaa", "abcdefgh", "12345678", "qwertyuiop", "asdfghjkl", "abababababab"])
def test_patterns_are_weak(p):
    assert pw.check_password(p, online=False)["strength"] <= 1


def test_year_and_date_penalised():
    r = pw.check_password("Rex19851021", online=False)
    assert r["strength"] <= 2
    assert any("date" in f.lower() or "year" in f.lower() for f in r["feedback"])


def test_strong_passwords():
    for p in ("x9$Kq!z2Lm@8vR#w", "correct horse battery staple"):
        r = pw.check_password(p, online=False)
        assert r["strength"] == 4, (p, r)
    assert pw.check_password("x9$Kq!z2Lm@8vR#w", online=False)["entropy_bits"] > 80


def test_strength_monotonic_with_length():
    a = pw.check_password("Xk2!pQ", online=False)
    b = pw.check_password("Xk2!pQ7#mZ", online=False)
    c = pw.check_password("Xk2!pQ7#mZ4@wLs9", online=False)
    assert a["entropy_bits"] < b["entropy_bits"] < c["entropy_bits"]
    assert a["strength"] <= b["strength"] <= c["strength"]


def test_short_password_capped():
    r = pw.check_password("Xk2!pQ", online=False)
    assert r["strength"] <= 1 and any("short" in f.lower() for f in r["feedback"])


def test_unicode_password_ok(monkeypatch):
    seen = install_fake(monkeypatch, "")
    r = pw.check_password("pässwörd-日本語-ключ-9!", online=True)
    assert r["pwned_count"] == 0 and len(seen[0]["url"].rsplit("/", 1)[1]) == 5


def test_common_list_bundled():
    words = pw._common()
    assert len(words) >= 200 and "password" in words and words["password"] < 10
