"""Outbound alerting: payload formats per channel, https enforcement, batching, rate limiting, retries,
secret hygiene and the guarantee that nothing raises. urllib and smtplib are mocked - no network is touched."""

from __future__ import annotations

import json
import smtplib
import ssl
import threading
import time
import urllib.error
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

from aegis.core import alerts as A
from aegis.core.config import Config
from aegis.core.models import Category, Finding, Severity

# Secret-shaped test values are assembled at runtime so the repository holds no literal that
# secret scanners (e.g. GitHub push protection) would treat as a real credential.
SLACK = "https://hooks.slack.com/services/" + "T01234567" + "/" + "B01234567" + "/" + "xYzSlackSecretToken123"
FAKE_GH_TOKEN = "gh" + "p_" + "abcdefghijklmnopqrstuvwxyz0123456789"
TEAMS = "https://prod-12.westeurope.logic.azure.com:443/workflows/0a1b2c3d4e5f6a7b8c9d0e1f/triggers/manual/paths/invoke?sig=TeamsSigSecret987654"
DISCORD = "https://discord.com/api/webhooks/1122334455667788/DiscordSecretTokenAbCdEf-123"
GENERIC = "https://siem.example.org/hooks/aegis/GenericSecretPathToken42"
SMTP_PASSWORD = "S3cr3t-smtp-passw0rd"
ALL_SECRETS = ["xYzSlackSecretToken123", "TeamsSigSecret987654", "DiscordSecretTokenAbCdEf-123", "GenericSecretPathToken42",
               SMTP_PASSWORD]


def f(i: int = 1, sev: Severity = Severity.HIGH, title: str = "", loc: str = "") -> Finding:
    return Finding(f"AEG-T-{i}", title or f"Suspicious thing {i}", sev, Category.MALWARE,
                   location=loc or f"C:\\Users\\bob\\Downloads\\thing{i}.exe", scanner="files",
                   description="LONG DESCRIPTION that must not be sent", evidence={"snippet": "EVIDENCE-MUST-NOT-LEAK"})


def make_config(**kw: Any) -> Config:
    c = Config()
    for k, v in kw.items():
        setattr(c, k, v)
    return c


def full_config(**kw: Any) -> Config:
    base = dict(alert_slack_webhook=SLACK, alert_teams_webhook=TEAMS, alert_discord_webhook=DISCORD,
                alert_webhook_url=GENERIC, alert_email_smtp_host="smtp.example.org", alert_email_smtp_port=587,
                alert_email_smtp_user="aegis", alert_email_smtp_password=SMTP_PASSWORD, alert_email_to="ops@example.org",
                alert_email_from="aegis@example.org")
    base.update(kw)
    return make_config(**base)


# --------------------------------------------------------------------------- fakes

class FakeResp:
    def __init__(self, status: int = 200):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, n: int = -1) -> bytes:
        return b"ok"

    def getcode(self) -> int:
        return self.status


class Net:
    """Replacement for urllib.request.urlopen. ``plan`` maps a URL substring to a list of outcomes
    (an int status, or an exception to raise); the last outcome repeats."""

    def __init__(self) -> None:
        self.requests: List[Dict[str, Any]] = []
        self.plan: Dict[str, List[Any]] = {}
        self.delays: List[float] = []
        self.lock = threading.Lock()

    def __call__(self, req, timeout=None, **_kw):
        body = json.loads(req.data.decode("utf-8")) if req.data else None
        with self.lock:
            self.requests.append({"url": req.full_url, "method": req.get_method(), "json": body, "timeout": timeout,
                                  "headers": {k.lower(): v for k, v in req.header_items()}})
            outcome: Any = 200
            for key, outcomes in self.plan.items():
                if key in req.full_url:
                    outcome = outcomes.pop(0) if len(outcomes) > 1 else outcomes[0]
        if isinstance(outcome, BaseException):
            raise outcome
        return FakeResp(outcome)

    def to(self, needle: str) -> List[Dict[str, Any]]:
        return [r for r in self.requests if needle in r["url"]]


@pytest.fixture(autouse=True)
def net(monkeypatch):
    n = Net()
    monkeypatch.setattr(A.urllib.request, "urlopen", n)
    monkeypatch.setattr(A, "_sleep", n.delays.append)
    monkeypatch.delenv("AEGIS_SMTP_PASSWORD", raising=False)
    A.reset_rate_limits()
    return n


class FakeSMTP:
    instances: List["FakeSMTP"] = []
    failures: List[BaseException] = []  # raised from send_message, one per attempt (consumed in order)
    kind = "plain"

    def __init__(self, host, port, timeout=None, context=None):
        self.host, self.port, self.timeout, self.context = host, port, timeout, context
        self.calls: List[Any] = []
        self.sent: List[Any] = []
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.calls.append("quit")
        return False

    def ehlo(self):
        self.calls.append("ehlo")

    def starttls(self, context=None):
        self.calls.append("starttls")

    def login(self, user, password):
        self.calls.append(("login", user, password))

    def send_message(self, msg, from_addr=None, to_addrs=None):
        self.calls.append("send")
        if FakeSMTP.failures:
            raise FakeSMTP.failures.pop(0)
        self.sent.append((msg, from_addr, to_addrs))


class FakeSMTPSSL(FakeSMTP):
    kind = "ssl"


@pytest.fixture
def smtp(monkeypatch):
    FakeSMTP.instances, FakeSMTP.failures = [], []
    monkeypatch.setattr(A.smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(A.smtplib, "SMTP_SSL", FakeSMTPSSL)
    return FakeSMTP


# --------------------------------------------------------------------------- configuration & validation

def test_nothing_configured_nothing_sent(net):
    cfg = Config()
    assert A.configured_channels(cfg) == []
    assert A.send_alerts([f()], cfg, {"kind": "scan"}) == {}
    assert A.test_alert(cfg) == {}
    assert net.requests == []


def test_configured_channels_and_email_needs_host_and_recipient():
    assert A.configured_channels(full_config()) == ["webhook", "slack", "teams", "discord", "email"]
    assert A.configured_channels(make_config(alert_email_smtp_host="smtp.x.org")) == []
    assert A.configured_channels(make_config(alert_email_to="a@b.org")) == []
    assert A.configured_channels(make_config(alert_email_smtp_host="s", alert_email_to="not-an-address")) == []
    cfg = make_config(alert_email_smtp_host="s", alert_email_to="a@b.org; c@d.org , junk, e@f.org")
    assert A.email_recipients(cfg) == ["a@b.org", "c@d.org", "e@f.org"]


@pytest.mark.parametrize("url, ok", [
    (SLACK, True), (TEAMS, True), ("https://hooks.example.test:8443/x?y=1", True),
    ("http://hooks.slack.com/services/T/B/x", False), ("HTTP://example.org/x", False), ("ftp://example.org/x", False),
    ("//example.org/x", False), ("example.org/x", False), ("", False), ("   ", False), ("https://", False),
    ("https://user:pass@example.org/x", False), ("https://example.org/a b", False), ("https://example.org/\nHost: evil", False),
    ("https://example.org:notaport/x", False), ("javascript:alert(1)", False)])
def test_validate_webhook_url_enforces_https(url, ok):
    assert (A.validate_webhook_url(url) == "") is ok


def test_validate_config_reports_problems_without_echoing_secrets():
    cfg = make_config(alert_slack_webhook="http://hooks.slack.com/services/T/B/PLAINTEXTSECRET", alert_email_smtp_host="smtp",
                      alert_email_to="nobody", alert_email_smtp_port=70000, alert_min_severity="loud", alert_on="sometimes",
                      alert_email_smtp_password="hunter2hunter2")
    problems = A.validate_config(cfg)
    text = " ".join(problems)
    assert "Slack webhook" in text and "https://" in text and "recipient" in text and "port" in text
    assert "severity" in text and "'new' or 'all'" in text
    assert "PLAINTEXTSECRET" not in text and "hunter2" not in text
    assert A.validate_config(full_config()) == []
    assert A.validate_config(Config()) == []


def test_min_severity_and_mode_parsing():
    assert A.min_severity(make_config(alert_min_severity="Critical")) == Severity.CRITICAL
    assert A.min_severity(make_config(alert_min_severity="nonsense")) == Severity.HIGH
    assert A.alert_mode(make_config(alert_on="ALL")) == "all" and A.alert_mode(make_config(alert_on="x")) == "new"


def test_smtp_password_env_overrides_config(monkeypatch):
    cfg = make_config(alert_email_smtp_password="from-config")
    assert A.smtp_password(cfg) == "from-config"
    monkeypatch.setenv("AEGIS_SMTP_PASSWORD", "from-env")
    assert A.smtp_password(cfg) == "from-env"


# --------------------------------------------------------------------------- payload formats

def build(findings, cfg=None, **ctx):
    return A.build_alert(findings, cfg or make_config(), {"kind": "scan", "host": "WS-042", **ctx})


def test_alert_contains_host_counts_and_top_findings_only():
    fs = [f(1, Severity.CRITICAL), f(2, Severity.HIGH), f(3, Severity.HIGH), f(4, Severity.MEDIUM)]
    a = build(fs, profile="quick", score=61, grade="D", score_change=-14, resolved=2)
    assert a.host == "WS-042" and a.total == 4 and a.severity == "critical"
    assert a.counts == {"critical": 1, "high": 2, "medium": 1, "low": 0, "info": 0}
    assert a.summary == "4 new findings on WS-042"
    assert [x.severity for x in a.findings] == ["critical", "high", "high", "medium"]
    facts = dict(a.facts)
    assert facts["Host"] == "WS-042" and facts["Source"] == "Scan (quick)"
    assert facts["Security score"] == "61/100 (D), -14 since the previous scan"
    assert facts["Severity"] == "1 critical, 2 high, 1 medium" and facts["Resolved since last scan"] == "2"
    blob = json.dumps(a.__dict__, default=lambda o: o.__dict__)
    assert "EVIDENCE-MUST-NOT-LEAK" not in blob and "LONG DESCRIPTION" not in blob


def test_alert_wording_for_baseline_all_realtime_and_test():
    assert build([f(1)]).summary == "1 new finding on WS-042"
    assert build([f(1)], baseline=True).summary == "1 finding on WS-042 (first scan, no baseline)"
    assert build([f(1), f(2)], mode="all").summary == "2 findings on WS-042"
    assert A.build_alert([f(1)], make_config(), {"kind": "realtime", "host": "H"}).summary == "1 real-time detection on H"
    assert A.build_alert([], make_config(), {"kind": "test", "host": "H"}).summary == "Aegis test alert from H"


def test_alert_truncates_and_sanitises_long_fields():
    long_loc = "C:\\" + "very\\long\\" * 80 + "evil.exe"
    fs = [f(1, Severity.CRITICAL, title="T" * 500, loc=long_loc + "\nsecond line\x07")] + [f(i) for i in range(2, 30)]
    a = A.build_alert(fs, make_config(), {"kind": "scan", "host": "H"}, max_findings=10)
    assert len(a.findings) == 10 and a.omitted == 19 and a.total == 29
    top = a.findings[0]
    assert len(top.title) <= 140 and len(top.location) <= 180 and "\n" not in top.location and "\x07" not in top.location
    assert top.location.startswith("C:\\") and "..." in top.location  # head and tail kept, middle elided


def test_slack_payload_blocks_and_escaping():
    a = build([f(1, Severity.CRITICAL, title="Evil <!channel> & <@U123> thing", loc="C:\\a\\`b`.exe")] + [f(i) for i in range(2, 15)],
              profile="full", score=40, grade="F")
    p = A.build_slack_payload(a)
    types = [b["type"] for b in p["blocks"]]
    assert types[:2] == ["header", "section"] and types[-1] == "context" and "divider" in types
    assert p["blocks"][0]["text"] == {"type": "plain_text", "text": "14 new findings on WS-042"}
    assert p["text"] == "14 new findings on WS-042"
    fields = p["blocks"][1]["fields"]
    assert any("*Host*\nWS-042" == x["text"] for x in fields) and all(x["type"] == "mrkdwn" for x in fields)
    body = [b for b in p["blocks"] if b["type"] == "section" and "text" in b][0]["text"]["text"]
    assert "*CRITICAL*" in body and "&lt;!channel&gt;" in body and "&lt;@U123&gt;" in body and "&amp;" in body
    assert "<!channel>" not in body and "<@U123>" not in body  # no Slack mentions from attacker-controlled names
    assert "`C:\\a\\'b'.exe`" in body  # backticks neutralised so they cannot break out of the code span
    assert "_...and 4 more_" in body and len(body) <= 2900
    assert len(p["blocks"][0]["text"]["text"]) <= 150


def test_teams_payload_is_a_workflows_adaptive_card():
    a = build([f(1, Severity.CRITICAL, title="Evil *bold* [link](http://x) thing"), f(2, Severity.MEDIUM)], score=70, grade="C")
    p = A.build_teams_payload(a)
    assert p["type"] == "message" and len(p["attachments"]) == 1
    att = p["attachments"][0]
    assert att["contentType"] == "application/vnd.microsoft.card.adaptive" and att["contentUrl"] is None
    card = att["content"]
    assert card["type"] == "AdaptiveCard" and card["version"] == "1.4" and "adaptivecards.io" in card["$schema"]
    body = card["body"]
    assert body[0]["type"] == "TextBlock" and body[0]["color"] == "Attention" and body[0]["wrap"] is True
    assert body[1]["type"] == "FactSet" and {"title": "Host", "value": "WS-042"} in body[1]["facts"]
    containers = [b for b in body if b["type"] == "Container"]
    assert len(containers) == 2
    first = containers[0]["items"][0]["text"]
    assert first.startswith("**CRITICAL**") and "\\*bold\\*" in first and "\\[link\\]" in first  # markdown neutralised
    json.dumps(p)


def test_discord_payload_embeds_limits_and_no_mentions():
    fs = [f(i, Severity.HIGH, title="Evil @everyone " + "x" * 400, loc="L" * 3000) for i in range(1, 30)]
    p = A.build_discord_payload(A.build_alert(fs, make_config(), {"kind": "scan", "host": "WS-042"}, max_findings=8))
    assert p["allowed_mentions"] == {"parse": []} and p["username"] == "Aegis"
    e = p["embeds"][0]
    assert e["title"] == "29 new findings on WS-042" and e["color"] == int("e8590c", 16)
    assert 1 <= len(e["fields"]) <= 9 and e["timestamp"].endswith("Z") and "Aegis" in e["footer"]["text"]
    assert all(len(x["name"]) <= 256 and len(x["value"]) <= 1024 for x in e["fields"])
    total = len(e["title"]) + len(e["description"]) + sum(len(x["name"]) + len(x["value"]) for x in e["fields"])
    assert total < 6000  # Discord rejects embeds above 6000 characters
    assert "Host:** WS-042" in e["description"]


def test_generic_payload_has_findings_without_evidence():
    p = A.build_generic_payload(build([f(1, Severity.CRITICAL), f(2)], profile="quick"))
    assert p["source"] == "aegis" and p["kind"] == "scan" and p["host"] == "WS-042" and p["total"] == 2
    assert p["severity"] == "critical" and p["counts"]["high"] == 1
    assert set(p["findings"][0]) == {"severity", "rule_id", "title", "location", "category", "fingerprint"}
    assert "EVIDENCE" not in json.dumps(p) and p["timestamp"].endswith("Z")


def test_email_has_plain_and_escaped_html_parts():
    cfg = make_config(alert_email_smtp_host="smtp", alert_email_to="a@example.org, b@example.org", alert_email_from="Aegis <aegis@example.org>")
    a = A.build_alert([f(1, Severity.CRITICAL, title="<script>alert(1)</script>", loc="C:\\x\\<img src=x onerror=1>.exe"), f(2)],
                      cfg, {"kind": "scan", "host": "WS\r\nBcc: evil@example.org", "profile": "quick"})
    msg = A.build_email(a, cfg)
    assert msg["Subject"].startswith("[Aegis] CRITICAL: 2 new findings on WS") and "\n" not in msg["Subject"]
    assert "evil@example.org" not in str(msg["To"]) and msg["Bcc"] is None
    assert msg["To"] == "a@example.org, b@example.org" and msg["From"] == "Aegis <aegis@example.org>"
    plain = msg.get_body(("plain",)).get_content()
    html_part = msg.get_body(("html",)).get_content()
    assert "Top findings:" in plain and "[CRITICAL]" in plain and "rule AEG-T-1" in plain
    assert "<script>" not in html_part and "&lt;script&gt;" in html_part and "<img" not in html_part
    assert "EVIDENCE-MUST-NOT-LEAK" not in plain + html_part


# --------------------------------------------------------------------------- delivery

def test_send_alerts_posts_json_to_every_channel(net, smtp):
    results = A.send_alerts([f(1, Severity.CRITICAL), f(2)], full_config(), {"kind": "scan", "profile": "quick", "host": "WS-042"})
    assert set(results) == {"webhook", "slack", "teams", "discord", "email"}
    assert all(r["ok"] and r["attempts"] == 1 and r["error"] == "" for r in results.values()), results
    assert results["slack"]["status"] == 200
    assert len(net.requests) == 4
    for req in net.requests:
        assert req["method"] == "POST" and req["headers"]["content-type"].startswith("application/json")
        assert req["headers"]["user-agent"].startswith("Aegis-Security-Suite/") and req["timeout"] and req["timeout"] <= 15
    assert "blocks" in net.to("hooks.slack.com")[0]["json"]
    assert net.to("logic.azure.com")[0]["json"]["type"] == "message"
    assert "embeds" in net.to("discord.com")[0]["json"]
    assert net.to("siem.example.org")[0]["json"]["source"] == "aegis"
    assert len(smtp.instances) == 1 and len(smtp.instances[0].sent) == 1


def test_http_webhooks_are_refused_and_never_requested(net):
    cfg = make_config(alert_slack_webhook="http://hooks.slack.com/services/T/B/PLAINSECRET", alert_discord_webhook=DISCORD)
    res = A.send_alerts([f(1)], cfg, {"kind": "scan"})
    assert res["slack"]["ok"] is False and "https://" in res["slack"]["error"] and res["slack"]["attempts"] == 1
    assert res["discord"]["ok"] is True
    assert net.to("slack.com") == []  # nothing was ever sent to the plain-http URL
    assert "PLAINSECRET" not in json.dumps(res)
    assert net.delays == []  # a permanent configuration error is not retried


def test_retries_with_exponential_backoff_then_succeeds(net):
    net.plan[SLACK] = [urllib.error.HTTPError(SLACK, 500, "Server Error", {}, None),
                       urllib.error.URLError("connection reset"), 200]
    res = A.send_alerts([f(1)], make_config(alert_slack_webhook=SLACK), {"kind": "scan"})
    assert res["slack"]["ok"] and res["slack"]["attempts"] == 3
    assert net.delays == [1.0, 2.0] and len(net.requests) == 3


def test_gives_up_after_max_attempts_and_reports_failure(net):
    net.plan[SLACK] = [urllib.error.URLError("no route to host")]
    res = A.send_alerts([f(1)], make_config(alert_slack_webhook=SLACK), {"kind": "scan"})
    assert res["slack"]["ok"] is False and res["slack"]["attempts"] == A.MAX_ATTEMPTS
    assert "connection failed" in res["slack"]["error"] and len(net.requests) == A.MAX_ATTEMPTS
    assert net.delays == [1.0, 2.0]


def test_client_errors_are_not_retried_but_429_is_and_honours_retry_after(net):
    net.plan[SLACK] = [urllib.error.HTTPError(SLACK, 404, "Not Found", {}, None)]
    res = A.send_alerts([f(1)], make_config(alert_slack_webhook=SLACK), {"kind": "scan"})
    assert res["slack"] == {"ok": False, "status": 404, "attempts": 1, "error": "HTTP 404 Not Found", "skipped": ""}
    assert net.delays == []

    net.requests.clear()
    net.plan[DISCORD] = [urllib.error.HTTPError(DISCORD, 429, "Too Many Requests", {"Retry-After": "7"}, None), 204]
    res = A.send_alerts([f(1)], make_config(alert_discord_webhook=DISCORD), {"kind": "scan"})
    assert res["discord"]["ok"] and res["discord"]["attempts"] == 2 and net.delays == [7.0]


def test_certificate_errors_are_not_retried(net):
    net.plan[SLACK] = [urllib.error.URLError(ssl.SSLCertVerificationError("certificate verify failed"))]
    res = A.send_alerts([f(1)], make_config(alert_slack_webhook=SLACK), {"kind": "scan"})
    assert res["slack"]["ok"] is False and res["slack"]["attempts"] == 1 and net.delays == []


def test_retry_budget_is_bounded(net, monkeypatch):
    clock = SimpleNamespace(t=0.0)
    monkeypatch.setattr(A, "_clock", lambda: clock.t)
    monkeypatch.setattr(A, "_sleep", lambda d: setattr(clock, "t", clock.t + d))
    monkeypatch.setattr(A, "CHANNEL_DEADLINE_S", 1.5)
    net.plan[SLACK] = [urllib.error.URLError("down")]
    res = A.send_alerts([f(1)], make_config(alert_slack_webhook=SLACK), {"kind": "scan"})
    assert res["slack"]["ok"] is False and res["slack"]["attempts"] == 2  # the 2 s second backoff would exceed 1.5 s


def test_send_alerts_never_raises(net, monkeypatch):
    cfg = full_config()
    net.plan[SLACK] = [RuntimeError("kaboom")]
    net.plan[TEAMS] = [MemoryError("out of memory")]
    net.plan[DISCORD] = [ValueError("bad value")]
    res = A.send_alerts([f(1)], cfg, {"kind": "scan"})
    assert res["slack"]["ok"] is False and "RuntimeError" in res["slack"]["error"]
    assert res["teams"]["ok"] is False and res["discord"]["ok"] is False

    monkeypatch.setattr(A, "build_alert", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("builder bug")))
    res = A.send_alerts([f(1)], cfg, {"kind": "scan"})
    assert set(res) == {"webhook", "slack", "teams", "discord", "email"}
    assert all(not r["ok"] and "internal error" in r["error"] for r in res.values())

    assert A.send_alerts(None, cfg, None) == {}  # type: ignore[arg-type]
    assert A.send_alerts(["not a finding", 3], cfg, {"kind": "scan"}) == {}  # type: ignore[list-item]
    assert A.alert_after_scan(SimpleNamespace(), cfg, None) == {}  # malformed result object


def test_each_channel_lists_a_sensible_number_of_findings(net, smtp):
    fs = [f(i, Severity.HIGH, title=f"Thing {i:02d}") for i in range(1, 31)]
    A.send_alerts(fs, full_config(), {"kind": "scan", "host": "H"})
    slack = json.dumps(net.to("slack.com")[0]["json"])
    assert slack.count("*HIGH*") == 10 and "_...and 20 more_" in slack and "30 new findings on H" in slack
    discord = net.to("discord.com")[0]["json"]["embeds"][0]
    assert len([x for x in discord["fields"] if x["name"].startswith("HIGH")]) == 8 and discord["fields"][-1]["value"] == "...and 22 more"
    generic = net.to("siem.example.org")[0]["json"]
    assert len(generic["findings"]) == 25 and generic["omitted"] == 5 and generic["total"] == 30
    plain = smtp.instances[0].sent[0][0].get_body(("plain",)).get_content()
    assert plain.count("[HIGH]") == 25 and "...and 5 more" in plain


def test_mask_secret_for_display():
    assert A.mask_secret("") == "" and A.mask_secret(None) == ""  # type: ignore[arg-type]
    assert A.mask_secret(SLACK) == "https://hooks.slack.com/****"
    assert "TeamsSigSecret" not in A.mask_secret(TEAMS) and A.mask_secret(TEAMS).startswith("https://prod-12.westeurope.logic.azure.com/")
    assert A.mask_secret(SMTP_PASSWORD) == "S3cr****" and A.mask_secret("abc") == "****"
    assert set(A.SECRET_FIELDS) <= set(Config.__dataclass_fields__)


# --------------------------------------------------------------------------- secrets never leak

def test_secrets_never_appear_in_payloads_results_or_logs(net, smtp, caplog):
    cfg = full_config(virustotal_api_key="VT-API-KEY-0123456789abcdef")
    leaky = [
        f(1, Severity.CRITICAL, title=f"Config exposes {SLACK}", loc=f"C:\\cfg\\{SMTP_PASSWORD}.txt password=hunter2hunter2"),
        f(2, Severity.HIGH, title=FAKE_GH_TOKEN + " found", loc="AKIAIOSFODNN7EXAMPLE in /home/x/.aws"),
    ]
    net.plan[SLACK] = [urllib.error.URLError(f"cannot reach {SLACK} (token xYzSlackSecretToken123)")]
    net.plan[DISCORD] = [urllib.error.HTTPError(DISCORD, 401, "Unauthorized DiscordSecretTokenAbCdEf-123", {}, None)]
    with caplog.at_level("DEBUG"):
        res = A.send_alerts(leaky, cfg, {"kind": "scan", "host": "WS-042"})
    sent = json.dumps([r["json"] for r in net.requests]) + "".join(
        str(m.get_body(("plain",)).get_content()) + str(m.get_body(("html",)).get_content()) for i in smtp.instances for m, _a, _t in i.sent)
    reported = json.dumps(res) + caplog.text
    for secret in ALL_SECRETS + ["VT-API-KEY-0123456789abcdef", "hunter2hunter2", FAKE_GH_TOKEN,
                                 "AKIAIOSFODNN7EXAMPLE", "EVIDENCE-MUST-NOT-LEAK"]:
        assert secret not in sent, f"{secret} leaked into a message"
        assert secret not in reported, f"{secret} leaked into results/logs"
    assert "***" in res["slack"]["error"] or "connection failed" in res["slack"]["error"]
    assert smtp.instances[0].calls.count(("login", "aegis", SMTP_PASSWORD)) == 1  # the password is only used to log in


def test_redact_masks_credentials_but_keeps_ordinary_text():
    secrets = A._secret_values(full_config())
    assert A.redact("see https://u:pw@host/x", secrets) == "see https://***@host/x"
    assert A.redact("Bearer abcdefghijklmnopqrstuvwxyz1234", ()) == "Bearer ****"
    assert A.redact("token=abc123def api_key=zzzzzz", ()) == "token=**** api_key=****"
    assert A.redact("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP", ()) == "eyJ****"
    ordinary = r"C:\Users\bob\Downloads\Weak password policy: guest account.exe"
    assert A.redact(ordinary, ()) == ordinary


# --------------------------------------------------------------------------- email / SMTP

def test_email_uses_starttls_login_and_sends_to_all_recipients(smtp):
    cfg = full_config(alert_email_to="a@example.org, b@example.org")
    res = A.send_alerts([f(1)], cfg, {"kind": "scan"})
    assert res["email"]["ok"] and res["email"]["status"] == 250
    s = smtp.instances[0]
    assert (s.host, s.port) == ("smtp.example.org", 587) and s.kind == "plain" and s.timeout
    assert s.calls == ["ehlo", "starttls", "ehlo", ("login", "aegis", SMTP_PASSWORD), "send", "quit"]
    msg, from_addr, to_addrs = s.sent[0]
    assert from_addr == "aegis@example.org" and to_addrs == ["a@example.org", "b@example.org"]


def test_email_port_465_uses_implicit_tls(smtp):
    cfg = make_config(alert_email_smtp_host="smtp.example.org", alert_email_smtp_port=465, alert_email_to="a@example.org",
                      alert_email_starttls=False, alert_email_smtp_user="u", alert_email_smtp_password="p")
    assert A.send_alerts([f(1)], cfg, {"kind": "scan"})["email"]["ok"]
    s = smtp.instances[0]
    assert s.kind == "ssl" and "starttls" not in s.calls and ("login", "u", "p") in s.calls


def test_email_refuses_credentials_over_cleartext(smtp):
    cfg = make_config(alert_email_smtp_host="mail.example.org", alert_email_to="a@example.org", alert_email_starttls=False,
                      alert_email_smtp_user="u", alert_email_smtp_password="p")
    res = A.send_alerts([f(1)], cfg, {"kind": "scan"})
    assert res["email"]["ok"] is False and "unencrypted" in res["email"]["error"] and res["email"]["attempts"] == 1
    assert smtp.instances == []  # never even connected
    cfg.alert_email_smtp_host = "127.0.0.1"  # a local relay is fine
    assert A.send_alerts([f(1)], cfg, {"kind": "scan"})["email"]["ok"]
    cfg.alert_email_smtp_user = ""  # no credentials -> nothing to protect
    cfg.alert_email_smtp_host = "mail.example.org"
    assert A.send_alerts([f(1)], cfg, {"kind": "scan"})["email"]["ok"]


def test_email_password_from_environment(smtp, monkeypatch):
    monkeypatch.setenv("AEGIS_SMTP_PASSWORD", "env-password-value")
    cfg = make_config(alert_email_smtp_host="smtp.example.org", alert_email_to="a@example.org", alert_email_smtp_user="u",
                      alert_email_smtp_password="disk-password-value")
    res = A.send_alerts([f(1)], cfg, {"kind": "scan"})
    assert ("login", "u", "env-password-value") in smtp.instances[0].calls
    assert "env-password-value" not in json.dumps(res)


def test_smtp_transient_errors_retry_permanent_ones_do_not(smtp):
    cfg = make_config(alert_email_smtp_host="smtp.example.org", alert_email_to="a@example.org")
    smtp.failures = [smtplib.SMTPServerDisconnected("gone"), smtplib.SMTPResponseException(451, b"try later")]
    res = A.send_alerts([f(1)], cfg, {"kind": "scan"})
    assert res["email"]["ok"] and res["email"]["attempts"] == 3 and len(smtp.instances) == 3

    smtp.instances.clear()
    smtp.failures = [smtplib.SMTPRecipientsRefused({"a@example.org": (550, b"no such user")})]
    res = A.send_alerts([f(1)], cfg, {"kind": "scan"})
    assert res["email"]["ok"] is False and res["email"]["attempts"] == 1

    smtp.failures = [smtplib.SMTPAuthenticationError(535, b"bad credentials")]
    cfg.alert_email_smtp_user, cfg.alert_email_smtp_password = "u", "p"
    res = A.send_alerts([f(1)], cfg, {"kind": "scan"})
    assert res["email"]["ok"] is False and res["email"]["attempts"] == 1 and "535" in res["email"]["error"]


# --------------------------------------------------------------------------- rate limiting

def test_rate_limiter_sliding_window():
    t = SimpleNamespace(now=0.0)
    rl = A.RateLimiter(max_events=3, window_s=100, clock=lambda: t.now)
    assert [rl.allow("slack") for _ in range(4)] == [True, True, True, False]
    assert rl.allow("teams") is True  # per channel
    t.now = 99.0
    assert rl.allow("slack") is False
    t.now = 100.5
    assert rl.allow("slack") is True
    rl.reset()
    assert rl.allow("slack") and rl.allow("slack") and rl.allow("slack") and not rl.allow("slack")


def test_send_alerts_is_rate_limited_per_channel_but_tests_bypass(net, monkeypatch):
    monkeypatch.setattr(A, "_limiter", A.RateLimiter(max_events=2, window_s=3600))
    cfg = make_config(alert_slack_webhook=SLACK, alert_discord_webhook=DISCORD)
    for _ in range(2):
        assert all(r["ok"] for r in A.send_alerts([f(1)], cfg, {"kind": "scan"}).values())
    third = A.send_alerts([f(1)], cfg, {"kind": "scan"})
    assert all(not r["ok"] and r["skipped"] == "rate-limited" and r["attempts"] == 0 for r in third.values())
    assert len(net.requests) == 4
    assert all(r["ok"] for r in A.test_alert(cfg).values())  # a test message always goes out
    assert len(net.requests) == 6


# --------------------------------------------------------------------------- test_alert

def test_test_alert_sends_one_message_per_channel(net, smtp):
    res = A.test_alert(full_config())
    assert set(res) == {"webhook", "slack", "teams", "discord", "email"} and all(r["ok"] for r in res.values())
    assert len(net.requests) == 4 and len(smtp.instances[0].sent) == 1
    slack_text = json.dumps(net.to("slack.com")[0]["json"])
    assert "Aegis test alert" in slack_text and "no action needed" in slack_text
    assert net.to("siem.example.org")[0]["json"]["kind"] == "test"
    assert "INFO" in slack_text.upper()  # an INFO sample is delivered despite alert_min_severity=high


def test_test_alert_reports_bad_urls_and_failures(net):
    cfg = make_config(alert_slack_webhook="http://insecure.example/x", alert_discord_webhook=DISCORD)
    net.plan[DISCORD] = [urllib.error.HTTPError(DISCORD, 403, "Forbidden", {}, None)]
    res = A.test_alert(cfg)
    assert res["slack"]["ok"] is False and res["discord"]["ok"] is False and res["discord"]["status"] == 403
    assert not hasattr(A.test_alert, "__test__") or A.test_alert.__test__ is False  # never collected by pytest


# --------------------------------------------------------------------------- after a scan

def scan_result(findings, profile="quick"):
    from aegis.core.models import ScanResult

    r = ScanResult(profile=profile, host={"hostname": "WS-042"})
    for x in findings:
        r.add(x)
    return r


def test_alert_after_scan_only_new_findings_at_or_above_threshold(net):
    from aegis.core import history

    cfg = make_config(alert_slack_webhook=SLACK, alert_min_severity="high")
    old = scan_result([f(1, Severity.CRITICAL), f(2, Severity.MEDIUM)])
    new = scan_result([f(1, Severity.CRITICAL), f(2, Severity.MEDIUM), f(3, Severity.HIGH), f(4, Severity.LOW), f(5, Severity.MEDIUM)])
    d = history.diff(old, new)
    res = A.alert_after_scan(new, cfg, d)
    assert res["slack"]["ok"] and len(net.requests) == 1  # ONE message per scan
    text = json.dumps(net.requests[0]["json"])
    assert "Suspicious thing 3" in text and "Suspicious thing 1" not in text  # persisting criticals are not re-announced
    assert "Suspicious thing 4" not in text and "Suspicious thing 5" not in text  # below the threshold
    assert new.stats["alerts"] == {"sent": ["slack"], "failed": {}}


def test_alert_after_scan_nothing_new_sends_nothing(net):
    from aegis.core import history

    cfg = make_config(alert_slack_webhook=SLACK)
    r = scan_result([f(1, Severity.CRITICAL)])
    assert A.alert_after_scan(r, cfg, history.diff(r, scan_result([f(1, Severity.CRITICAL)]))) == {}
    assert A.alert_after_scan(scan_result([f(9, Severity.LOW)]), cfg, None) == {}  # below threshold on a baseline scan
    assert net.requests == []


def test_alert_after_scan_escalated_and_all_modes(net):
    from aegis.core import history

    cfg = make_config(alert_slack_webhook=SLACK)
    old = scan_result([f(1, Severity.MEDIUM), f(2, Severity.CRITICAL)])
    new = scan_result([f(1, Severity.HIGH), f(2, Severity.CRITICAL)])
    d = history.diff(old, new)
    assert A.alert_after_scan(new, cfg, d)["slack"]["ok"]  # medium -> high crosses the threshold
    assert "Suspicious thing 1" in json.dumps(net.requests[0]["json"]) and "Suspicious thing 2" not in json.dumps(net.requests[0]["json"])

    net.requests.clear()
    A.reset_rate_limits()
    cfg.alert_on = "all"
    A.alert_after_scan(new, cfg, d)
    text = json.dumps(net.requests[0]["json"])
    assert "Suspicious thing 1" in text and "Suspicious thing 2" in text and "2 findings on" in text


def test_alert_after_scan_without_baseline_is_labelled(net):
    cfg = make_config(alert_slack_webhook=SLACK)
    A.alert_after_scan(scan_result([f(1, Severity.CRITICAL)]), cfg, None)
    assert "first scan, no baseline" in json.dumps(net.requests[0]["json"])


def test_alert_after_scan_skips_cancelled_scans(net):
    cfg = make_config(alert_slack_webhook=SLACK)
    r = scan_result([f(1, Severity.CRITICAL)])
    r.errors.append("scan cancelled by user")
    assert A.alert_after_scan(r, cfg, None) == {} and net.requests == []


def test_alert_failure_is_recorded_but_scan_result_stays_usable(net):
    net.plan[SLACK] = [urllib.error.HTTPError(SLACK, 500, "boom", {}, None)]
    cfg = make_config(alert_slack_webhook=SLACK)
    r = scan_result([f(1, Severity.CRITICAL)])
    res = A.alert_after_scan(r, cfg, None)
    assert res["slack"]["ok"] is False
    assert r.stats["alerts"]["failed"] == {"slack": "HTTP 500 boom"} and r.stats["alerts"]["sent"] == []


def test_scan_engine_alerts_only_on_new_findings(net, tmp_path, eicar_bytes):
    from aegis.core.engine import ScanEngine

    root = tmp_path / "scanme"
    root.mkdir()
    (root / "a.com").write_bytes(eicar_bytes)
    eng = ScanEngine()
    eng.config.use_windows_defender_engine = False
    eng.config.alert_slack_webhook = SLACK

    eng.scan("custom", ["files"], paths=[root])  # first scan: baseline, reported once
    assert len(net.requests) == 1 and "first scan, no baseline" in json.dumps(net.requests[0]["json"])
    eng.scan("custom", ["files"], paths=[root])  # identical: silence
    assert len(net.requests) == 1
    (root / "b.com").write_bytes(eicar_bytes + b" ")
    eng.scan("custom", ["files"], paths=[root])  # one new critical
    assert len(net.requests) == 2
    text = json.dumps(net.requests[1]["json"])
    assert "b.com" in text and "a.com" not in text and "1 new finding on" in text


def test_scan_engine_works_with_unreachable_alerts(net, tmp_path, eicar_bytes):
    from aegis.core.engine import ScanEngine

    (tmp_path / "a.com").write_bytes(eicar_bytes)
    net.plan[SLACK] = [urllib.error.URLError("offline")]
    eng = ScanEngine()
    eng.config.use_windows_defender_engine = False
    eng.config.alert_slack_webhook = SLACK
    res = eng.scan("custom", ["files"], paths=[tmp_path])
    assert res.findings and res.stats["alerts"]["failed"]["slack"].startswith("connection failed")
    assert (eng.config.home / "last_scan.json").exists()


# --------------------------------------------------------------------------- real-time batching

class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


class Sender:
    def __init__(self) -> None:
        self.calls: List[Any] = []

    def __call__(self, findings, config, context):
        self.calls.append((list(findings), dict(context)))
        return {"slack": {"ok": True, "status": 200, "attempts": 1, "error": "", "skipped": ""}}


def batcher(cfg=None, **kw):
    clock, sender = Clock(), Sender()
    b = A.AlertBatcher(cfg or make_config(alert_slack_webhook=SLACK), sender=sender, clock=clock, window_s=60.0,
                       urgent_window_s=5.0, **kw)
    return b, clock, sender


def test_batcher_collects_events_into_one_message_per_window():
    b, clock, sender = batcher()
    assert b.add(f(1)) and b.add(f(2, Severity.CRITICAL)) and not b.add(f(2, Severity.CRITICAL))  # repeat suppressed
    assert b.pending() == 2 and not b.due()  # CRITICAL queued -> urgent window (5 s) applies
    clock.t += 4.9
    assert not b.due()
    clock.t += 0.2
    assert b.due()
    res = b.flush()
    assert res["slack"]["ok"] and len(sender.calls) == 1
    findings, ctx = sender.calls[0]
    assert sorted(x.rule_id for x in findings) == ["AEG-T-1", "AEG-T-2"]
    assert ctx["kind"] == "realtime" and ctx["events"] == 2
    assert b.pending() == 0 and b.flush() == {} and len(sender.calls) == 1


def test_batcher_normal_window_is_60_seconds():
    b, clock, sender = batcher()
    b.add(f(1, Severity.HIGH))
    clock.t += 59
    assert not b.due()
    clock.t += 2
    assert b.due()


def test_batcher_filters_by_severity_and_requires_a_channel():
    b, _c, _s = batcher(make_config(alert_slack_webhook=SLACK, alert_min_severity="critical"))
    assert not b.add(f(1, Severity.HIGH)) and b.add(f(2, Severity.CRITICAL)) and b.pending() == 1
    b2, _c2, _s2 = batcher(Config())  # no channel configured
    assert not b2.add(f(1, Severity.CRITICAL)) and b2.pending() == 0


def test_batcher_suppresses_repeats_in_new_mode_not_in_all_mode():
    b, clock, _s = batcher()
    assert b.add(f(1)) and not b.add(f(1))  # same fingerprint inside the suppression window
    b.flush()
    assert not b.add(f(1))  # still suppressed after the flush
    clock.t += A.REPEAT_SUPPRESS_S + 1
    assert b.add(f(1))
    b_all, _c, _s2 = batcher(make_config(alert_slack_webhook=SLACK, alert_on="all"))
    assert b_all.add(f(1)) and b_all.add(f(1))


def test_batcher_thread_flushes_by_itself_and_on_stop():
    sender = Sender()
    b = A.AlertBatcher(make_config(alert_slack_webhook=SLACK), window_s=0.05, tick_s=0.01, sender=sender)
    b.start()
    b.start()  # idempotent
    b.add(f(1))
    deadline = time.time() + 5
    while not sender.calls and time.time() < deadline:
        time.sleep(0.01)
    assert len(sender.calls) == 1
    b.add(f(2, Severity.HIGH))
    b.window_s = 3600  # would not be due for an hour ...
    b.stop(timeout=5)  # ... but stopping flushes what is queued
    assert len(sender.calls) == 2 and sender.calls[1][0][0].rule_id == "AEG-T-2"
    assert not any(t.name == "aegis-alert-batcher" and t.is_alive() for t in threading.enumerate())


def test_batcher_survives_a_failing_sender():
    def boom(*a, **k):
        raise RuntimeError("network stack exploded")

    b = A.AlertBatcher(make_config(alert_slack_webhook=SLACK), sender=boom, clock=Clock())
    b.add(f(1))
    assert b.flush() == {}  # swallowed
    assert b.pending() == 0


def test_monitor_emit_feeds_the_batcher_and_writes_a_heartbeat(monkeypatch, tmp_path):
    from aegis.core import doctor
    from aegis.realtime import monitor as M

    sent: List[Any] = []
    monkeypatch.setattr(A, "send_alerts", lambda findings, config, context=None: sent.append((list(findings), context)) or {})
    cfg = make_config(alert_slack_webhook=SLACK, alert_min_severity="medium", notifications=False)
    mon = M.RealtimeMonitor(cfg, SimpleNamespace(), components=(), watch_specs=[])
    mon.start()
    try:
        assert mon._alerts is not None
        for _ in range(250):  # the heartbeat thread writes the file as soon as it starts
            if doctor.read_heartbeat(cfg):
                break
            time.sleep(0.02)
        hb = doctor.read_heartbeat(cfg)
        assert hb is not None and hb["pid"] == __import__("os").getpid() and hb["version"]
        assert mon.emit(f(1, Severity.HIGH), "test") and mon.emit(f(2, Severity.LOW), "test")
        assert mon._alerts.pending() == 1  # the LOW event is below alert_min_severity
        mon._alerts.flush()
        assert len(sent) == 1 and sent[0][0][0].rule_id == "AEG-T-1" and sent[0][1]["kind"] == "realtime"
        mon.emit(f(3, Severity.CRITICAL), "test")  # queued but not yet flushed ...
    finally:
        mon.stop()
    assert len(sent) == 2 and sent[1][0][0].rule_id == "AEG-T-3"  # ... stop() flushed it
    assert mon._alerts is None and doctor.read_heartbeat(cfg) is None  # batcher gone, heartbeat removed
