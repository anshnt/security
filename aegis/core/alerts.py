"""Outbound alerting: tell a human (or a SIEM / chat room) when Aegis finds something.

Everything here is opt-in and config-driven: no channel configured means nothing is ever sent.

Channels (``configured_channels``)
  webhook  generic JSON POST (``alert_webhook_url``)
  slack    Slack incoming webhook, Block Kit (``alert_slack_webhook``)
  teams    Microsoft Teams Workflows / Power Automate webhook, adaptive card (``alert_teams_webhook``)
  discord  Discord webhook, embeds (``alert_discord_webhook``)
  email    SMTP, plain text + HTML (``alert_email_*``; password may come from env ``AEGIS_SMTP_PASSWORD``)

Behaviour
* One message per scan; real-time detections are collected by :class:`AlertBatcher` and sent as one message per
  window (60 s, 5 s once a critical event is queued).
* After a scan (:func:`alert_after_scan`) only findings that are NEW since the previous comparable scan
  (``aegis.core.history.diff``) and at/above ``alert_min_severity`` are sent; ``alert_on = "all"`` sends everything
  at/above the threshold. The very first scan of a profile has no baseline and is reported as such.
* Messages carry host name, severity counts, score and the top findings (severity, title, shortened location, rule id)
  only - never evidence, descriptions, webhook URLs, passwords or API keys, and token-looking strings are masked.
* Webhook URLs must be ``https://`` without embedded credentials; SMTP credentials are refused on unencrypted links.
* Delivery retries with exponential backoff on transient failures (network errors, HTTP 408/429/5xx, SMTP 4xx), never
  on permanent ones; a per-channel sliding-window rate limit protects against loops; channels are sent in parallel.
* Nothing in this module raises: every function returns per-channel result dicts
  ``{"ok": bool, "status": int | None, "attempts": int, "error": str, "skipped": str}``.
"""

from __future__ import annotations

import html
import ipaddress
import json
import logging
import os
import re
import smtplib
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Any, Callable, Deque, Dict, Iterable, List, Optional, Sequence, Tuple

from aegis import __app_name__, __version__
from aegis.core.models import Finding, Severity

log = logging.getLogger("aegis.alerts")

CHANNELS = ("webhook", "slack", "teams", "discord", "email")
URL_FIELDS = {"webhook": "alert_webhook_url", "slack": "alert_slack_webhook", "teams": "alert_teams_webhook",
              "discord": "alert_discord_webhook"}
# Config fields that hold credentials (mask them in UIs / `config show`; never print or send them).
SECRET_FIELDS = ("alert_webhook_url", "alert_slack_webhook", "alert_teams_webhook", "alert_discord_webhook",
                 "alert_email_smtp_password")
_API_KEY_FIELDS = ("virustotal_api_key", "abusech_auth_key", "google_safebrowsing_api_key")

USER_AGENT = "Aegis-Security-Suite/" + __version__
HTTP_TIMEOUT = 10.0
SMTP_TIMEOUT = 15.0
MAX_ATTEMPTS = 3
BACKOFF_BASE_S = 1.0  # 1 s, 2 s, ...
BACKOFF_MAX_S = 15.0
CHANNEL_DEADLINE_S = 45.0  # budget for all attempts on one channel
RATE_LIMIT_MAX = 20  # messages per channel ...
RATE_LIMIT_WINDOW_S = 3600.0  # ... per hour
BATCH_WINDOW_S = 60.0
URGENT_WINDOW_S = 5.0  # a queued CRITICAL event shortens the batch window to this
REPEAT_SUPPRESS_S = 900.0  # real-time: do not re-alert the same finding within 15 minutes (alert_on = "new")
MAX_FINDINGS = {"webhook": 25, "slack": 10, "teams": 10, "discord": 8, "email": 25}

SEV_COLOR = {"critical": "#b3261e", "high": "#e8590c", "medium": "#f2c94c", "low": "#4dabf7", "info": "#9aa5b1"}
_SEV_NAMES = ("critical", "high", "medium", "low", "info")

_sleep: Callable[[float], None] = time.sleep  # tests replace these two
_clock: Callable[[], float] = time.monotonic


# --------------------------------------------------------------------------- configuration helpers

def min_severity(config: Any) -> Severity:
    try:
        return Severity.parse(getattr(config, "alert_min_severity", "high") or "high")
    except (KeyError, ValueError):
        return Severity.HIGH


def alert_mode(config: Any) -> str:
    """"all" or "new" (anything unrecognised means "new")."""
    return "all" if str(getattr(config, "alert_on", "new") or "new").strip().lower() == "all" else "new"


def smtp_password(config: Any) -> str:
    return os.environ.get("AEGIS_SMTP_PASSWORD") or getattr(config, "alert_email_smtp_password", "") or ""


_ADDR = re.compile(r"^[^@\s<>,;\"']+@[^@\s<>,;\"']+\.[^@\s<>,;\"']+$|^[^@\s<>,;\"']+@localhost$")


def email_recipients(config: Any) -> List[str]:
    raw = str(getattr(config, "alert_email_to", "") or "")
    return [a for a in (x.strip() for x in re.split(r"[,;\s]+", raw)) if _ADDR.match(a)]


def _url(config: Any, channel: str) -> str:
    return str(getattr(config, URL_FIELDS[channel], "") or "").strip()


def configured_channels(config: Any) -> List[str]:
    """Channels that have enough configuration to be attempted (a bad URL still counts: it is reported, not hidden)."""
    out = [ch for ch in ("webhook", "slack", "teams", "discord") if _url(config, ch)]
    if str(getattr(config, "alert_email_smtp_host", "") or "").strip() and email_recipients(config):
        out.append("email")
    return out


def validate_webhook_url(url: str) -> str:
    """Empty string when ``url`` is acceptable, otherwise the reason it is not. Only https is accepted."""
    url = (url or "").strip()
    if not url:
        return "the URL is empty"
    if any(ord(c) < 33 for c in url):
        return "the URL contains spaces or control characters"
    try:
        parts = urllib.parse.urlsplit(url)
        parts.port  # noqa: B018 - raises ValueError for an invalid port
    except ValueError:
        return "the URL is malformed"
    if parts.scheme.lower() != "https":
        return "webhook URLs must start with https:// (Aegis will not send alerts over plain http)"
    if not parts.hostname:
        return "the URL has no host name"
    if parts.username or parts.password:
        return "the URL must not contain embedded credentials"
    return ""


def validate_config(config: Any) -> List[str]:
    """Human-readable problems with the alert settings (empty list = fine). Never includes secret values."""
    problems: List[str] = []
    labels = {"webhook": "Generic webhook", "slack": "Slack webhook", "teams": "Teams webhook", "discord": "Discord webhook"}
    for ch, label in labels.items():
        value = _url(config, ch)
        if value:
            why = validate_webhook_url(value)
            if why:
                problems.append(f"{label}: {why}.")
    host = str(getattr(config, "alert_email_smtp_host", "") or "").strip()
    to_raw = str(getattr(config, "alert_email_to", "") or "").strip()
    if host or to_raw:
        if not host:
            problems.append("Email: SMTP host is missing.")
        if not email_recipients(config):
            problems.append("Email: no valid recipient address in 'to'.")
        try:
            port = int(getattr(config, "alert_email_smtp_port", 587))
            if not 0 < port < 65536:
                raise ValueError
        except (TypeError, ValueError):
            problems.append("Email: SMTP port must be a number between 1 and 65535.")
        sender = str(getattr(config, "alert_email_from", "") or "").strip()
        if sender and not _ADDR.match(_bare_address(sender)):
            problems.append("Email: the 'from' address is not valid.")
    try:
        Severity.parse(getattr(config, "alert_min_severity", "high") or "high")
    except (KeyError, ValueError):
        problems.append("Minimum severity must be one of: info, low, medium, high, critical.")
    if str(getattr(config, "alert_on", "new")).strip().lower() not in ("new", "all"):
        problems.append("'Alert on' must be 'new' or 'all'.")
    return problems


def _bare_address(value: str) -> str:
    m = re.search(r"<([^<>]+)>\s*$", value)
    return (m.group(1) if m else value).strip()


def _is_loopback(host: str) -> bool:
    h = host.strip().strip("[]").lower()
    if h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


# --------------------------------------------------------------------------- redaction

_REDACTIONS: List[Tuple["re.Pattern[str]", str]] = [
    (re.compile(r"https://hooks\.slack\.com/\S+", re.I), "https://hooks.slack.com/***"),
    (re.compile(r"https://(?:\w+\.)?discord(?:app)?\.com/api/webhooks/\S+", re.I), "https://discord.com/api/webhooks/***"),
    (re.compile(r"(?<=://)[^/\s:@]+:[^/\s@]+@"), "***@"),  # user:pass@host
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AKIA****"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "gh*_****"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), "xox*-****"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}"), "sk-****"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "AIza****"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}"), "eyJ****"),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}"), "Bearer ****"),
    (re.compile(r"(?i)\b(pass(?:word|wd)?|pwd|secret|token|api[_-]?key)(\s*=\s*)[^\s&,;\"']{3,}"), r"\1\2****"),
]


def _secret_values(config: Any) -> List[str]:
    """Strings that must never appear in outgoing text or in error messages we report."""
    vals: List[str] = []
    for name in list(URL_FIELDS.values()) + ["alert_email_smtp_password", *_API_KEY_FIELDS]:
        v = str(getattr(config, name, "") or "").strip()
        if v:
            vals.append(v)
            if v.lower().startswith("http"):
                try:
                    parts = urllib.parse.urlsplit(v)
                    vals += [seg for seg in parts.path.split("/") if len(seg) >= 12]
                    vals += [x for pair in urllib.parse.parse_qsl(parts.query) for x in pair if len(x) >= 8]
                except ValueError:
                    pass
    env_pw = os.environ.get("AEGIS_SMTP_PASSWORD")
    if env_pw:
        vals.append(env_pw)
    return sorted({v for v in vals if len(v) >= 4}, key=len, reverse=True)


def redact(text: str, secrets: Sequence[str] = ()) -> str:
    """Mask configured secrets and anything that looks like a credential."""
    text = str(text)
    for s in secrets:
        if s:
            text = text.replace(s, "***")
    for pat, repl in _REDACTIONS:
        text = pat.sub(repl, text)
    return text


def mask_secret(value: str) -> str:
    """Display form of a credential for `config show` / logs: a webhook URL keeps only its scheme and host,
    anything else its first 4 characters (empty stays empty)."""
    value = str(value or "")
    if not value:
        return ""
    if value.lower().startswith(("http://", "https://")):
        try:
            parts = urllib.parse.urlsplit(value)
            return f"{parts.scheme}://{parts.hostname or '?'}/****"
        except ValueError:
            pass
    return value[:4] + "****" if len(value) > 4 else "****"


def _shorten(text: str, limit: int) -> str:
    text = " ".join(re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", str(text)).split())  # one line, no control characters
    if len(text) <= limit:
        return text
    head = max(10, limit // 3)
    return text[:head] + "..." + text[-(limit - head - 3):]


# --------------------------------------------------------------------------- alert model

@dataclass
class AlertFinding:
    severity: str
    title: str
    location: str
    rule_id: str
    category: str
    fingerprint: str


@dataclass
class Alert:
    kind: str  # scan | realtime | test
    host: str
    summary: str  # one-line headline
    severity: str  # highest severity in the alert
    counts: Dict[str, int]
    findings: List[AlertFinding]  # top findings, already redacted and shortened
    omitted: int  # findings not listed
    total: int
    facts: List[Tuple[str, str]]
    timestamp: str  # local time, ISO
    utc: str  # ISO 8601 UTC (Discord)

    @property
    def counts_text(self) -> str:
        return ", ".join(f"{self.counts[s]} {s}" for s in _SEV_NAMES if self.counts.get(s)) or "none"


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def build_alert(findings: Iterable[Finding], config: Any, context: Optional[Dict[str, Any]] = None,
                max_findings: int = 10) -> Alert:
    """Turn findings into a channel-neutral, secret-free :class:`Alert`.

    ``context`` keys (all optional): ``kind`` (scan|realtime|test), ``host``, ``profile``, ``score``, ``grade``,
    ``score_change``, ``resolved``, ``mode`` ("new"|"all"), ``baseline`` (no earlier scan to compare with),
    ``events``, ``window_s``."""
    ctx = dict(context or {})
    secrets = _secret_values(config)
    kind = str(ctx.get("kind") or "scan")
    host = _shorten(redact(str(ctx.get("host") or socket.gethostname()), secrets), 64)
    flist = sorted((f for f in findings if isinstance(f, Finding)),
                   key=lambda f: (-int(f.severity), f.title, f.location))
    counts = {s: 0 for s in _SEV_NAMES}
    for f in flist:
        counts[f.severity.name.lower()] += 1
    top = flist[0].severity.name.lower() if flist else "info"
    shown = [AlertFinding(f.severity.name.lower(), _shorten(redact(f.title, secrets), 140),
                          _shorten(redact(f.location, secrets), 180), _shorten(redact(f.rule_id, secrets), 40),
                          _shorten(f.category, 30), f.fingerprint) for f in flist[:max(1, max_findings)]]
    n = len(flist)
    if kind == "test":
        summary = f"Aegis test alert from {host}"
    elif kind == "realtime":
        summary = f"{_plural(n, 'real-time detection')} on {host}"
    else:
        label = "finding" if ctx.get("mode") == "all" or ctx.get("baseline") else "new finding"
        summary = f"{_plural(n, label)} on {host}"
        if ctx.get("baseline"):
            summary += " (first scan, no baseline)"
    now = time.time()
    facts: List[Tuple[str, str]] = [("Host", host)]
    source = {"scan": "Scan" + (f" ({ctx['profile']})" if ctx.get("profile") else ""),
              "realtime": "Real-time protection", "test": "Test message"}.get(kind, kind)
    facts.append(("Source", _shorten(str(source), 40)))
    if isinstance(ctx.get("score"), int):
        score = f"{ctx['score']}/100" + (f" ({ctx['grade']})" if ctx.get("grade") else "")
        if isinstance(ctx.get("score_change"), int) and ctx["score_change"]:
            score += f", {ctx['score_change']:+d} since the previous scan"
        facts.append(("Security score", score))
    if kind != "test":
        facts.append(("Severity", ", ".join(f"{counts[s]} {s}" for s in _SEV_NAMES if counts[s]) or "none"))
    if isinstance(ctx.get("resolved"), int) and ctx["resolved"]:
        facts.append(("Resolved since last scan", str(ctx["resolved"])))
    local = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
    utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
    return Alert(kind=kind, host=host, summary=summary, severity=top, counts=counts, findings=shown,
                 omitted=max(0, n - len(shown)), total=n, facts=facts, timestamp=local, utc=utc)


# --------------------------------------------------------------------------- payload builders (pure)

def _slack_escape(text: str) -> str:
    # Slack control sequences (<!channel>, <@U123>, <http://x|y>) all start with "<"
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_slack_payload(alert: Alert) -> Dict[str, Any]:
    lines = []
    for f in alert.findings:
        loc = _slack_escape(f.location).replace("`", "'")
        lines.append(f"*{f.severity.upper()}*  {_slack_escape(f.title)}" + (f"\n`{loc}`" if loc else ""))
    if alert.omitted:
        lines.append(f"_...and {alert.omitted} more_")
    blocks: List[Dict[str, Any]] = [
        {"type": "header", "text": {"type": "plain_text", "text": alert.summary[:150]}},
        {"type": "section", "fields": [{"type": "mrkdwn", "text": f"*{_slack_escape(k)}*\n{_slack_escape(v)}"[:1900]}
                                       for k, v in alert.facts[:10]]},
    ]
    if lines:
        blocks.append({"type": "divider"})
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)[:2900]}})
    blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": f"{__app_name__} {__version__} | {alert.timestamp}"}]})
    return {"text": _slack_escape(alert.summary), "blocks": blocks}


def _teams_escape(text: str) -> str:
    return re.sub(r"([\\`*_\[\]<~])", r"\\\1", text)


def build_teams_payload(alert: Alert) -> Dict[str, Any]:
    color = {"critical": "Attention", "high": "Attention", "medium": "Warning"}.get(alert.severity, "Default")
    body: List[Dict[str, Any]] = [
        {"type": "TextBlock", "text": _teams_escape(alert.summary), "weight": "Bolder", "size": "Medium", "wrap": True,
         "color": color},
        {"type": "FactSet", "facts": [{"title": k, "value": _teams_escape(v)} for k, v in alert.facts]},
    ]
    if alert.findings:
        body.append({"type": "TextBlock", "text": "Top findings", "weight": "Bolder", "spacing": "Medium"})
    for f in alert.findings:
        items: List[Dict[str, Any]] = [{"type": "TextBlock", "text": f"**{f.severity.upper()}**  {_teams_escape(f.title)}",
                                        "wrap": True}]
        if f.location:
            items.append({"type": "TextBlock", "text": _teams_escape(f.location), "isSubtle": True, "wrap": True,
                          "size": "Small", "spacing": "None"})
        body.append({"type": "Container", "separator": True, "items": items})
    if alert.omitted:
        body.append({"type": "TextBlock", "text": f"...and {alert.omitted} more", "isSubtle": True})
    body.append({"type": "TextBlock", "text": f"{__app_name__} {__version__} | {alert.timestamp}", "isSubtle": True,
                 "size": "Small", "spacing": "Medium"})
    card = {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4",
            "msteams": {"width": "Full"}, "body": body}
    return {"type": "message",
            "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None, "content": card}]}


def build_discord_payload(alert: Alert) -> Dict[str, Any]:
    fields: List[Dict[str, Any]] = []
    for f in alert.findings:
        fields.append({"name": f"{f.severity.upper()} - {f.title}"[:256],
                       "value": (f"`{f.location.replace('`', chr(39))}`" if f.location else "-")[:1024], "inline": False})
    if alert.omitted:
        fields.append({"name": "More", "value": f"...and {alert.omitted} more", "inline": False})
    embed: Dict[str, Any] = {
        "title": alert.summary[:256],
        "description": "\n".join(f"**{k}:** {v}" for k, v in alert.facts)[:2000],
        "color": int(SEV_COLOR.get(alert.severity, SEV_COLOR["info"]).lstrip("#"), 16),
        "fields": fields,
        "footer": {"text": f"{__app_name__} {__version__}"},
        "timestamp": alert.utc,
    }
    fixed = len(embed["title"]) + len(embed["description"]) + len(embed["footer"]["text"])
    while len(fields) > 1 and fixed + sum(len(x["name"]) + len(x["value"]) for x in fields) > 5500:
        fields.pop(-2 if alert.omitted else -1)  # Discord rejects embeds over 6000 characters
    # allowed_mentions: attacker-controlled file names must not be able to ping @everyone
    return {"username": "Aegis", "allowed_mentions": {"parse": []}, "embeds": [embed]}


def build_generic_payload(alert: Alert) -> Dict[str, Any]:
    return {
        "source": "aegis", "version": __version__, "kind": alert.kind, "host": alert.host,
        "summary": alert.summary, "severity": alert.severity, "counts": dict(alert.counts), "total": alert.total,
        "facts": {k: v for k, v in alert.facts}, "timestamp": alert.utc,
        "findings": [{"severity": f.severity, "rule_id": f.rule_id, "title": f.title, "location": f.location,
                      "category": f.category, "fingerprint": f.fingerprint} for f in alert.findings],
        "omitted": alert.omitted,
    }


def build_email(alert: Alert, config: Any) -> EmailMessage:
    sender = str(getattr(config, "alert_email_from", "") or "").strip() or f"aegis@{alert.host or 'localhost'}"
    msg = EmailMessage()
    msg["Subject"] = re.sub(r"[\r\n]+", " ", f"[Aegis] {alert.severity.upper()}: {alert.summary}")[:200]
    msg["From"] = re.sub(r"[\r\n]+", " ", sender)
    msg["To"] = ", ".join(email_recipients(config))
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain="aegis.invalid")
    text = [alert.summary, ""]
    text += [f"{k}: {v}" for k, v in alert.facts]
    if alert.findings:
        text += ["", "Top findings:"]
        for f in alert.findings:
            text.append(f"  [{f.severity.upper()}] {f.title}")
            if f.location:
                text.append(f"      {f.location}")
            text.append(f"      rule {f.rule_id}, id {f.fingerprint}")
    if alert.omitted:
        text.append(f"  ...and {alert.omitted} more")
    text += ["", f"-- {__app_name__} {__version__}", "Details stay on the machine: run `aegis history --diff` or open the latest report."]
    msg.set_content("\n".join(text))
    e = html.escape
    rows = "".join(
        f'<tr><td style="padding:4px 8px"><span style="background:{SEV_COLOR.get(f.severity, "#9aa5b1")};color:#fff;'
        f'padding:1px 6px;border-radius:3px;font-size:12px">{e(f.severity.upper())}</span></td>'
        f'<td style="padding:4px 8px"><b>{e(f.title)}</b><br><code style="font-size:12px">{e(f.location)}</code></td>'
        f'<td style="padding:4px 8px;color:#666;font-size:12px">{e(f.rule_id)}</td></tr>' for f in alert.findings)
    facts = "".join(f"<tr><td style='padding:2px 8px;color:#666'>{e(k)}</td><td style='padding:2px 8px'>{e(v)}</td></tr>"
                    for k, v in alert.facts)
    more = f"<p>...and {alert.omitted} more</p>" if alert.omitted else ""
    msg.add_alternative(
        f'<html><body style="font-family:Segoe UI,Arial,sans-serif;font-size:14px"><h2 style="margin:0 0 8px">{e(alert.summary)}</h2>'
        f"<table>{facts}</table>"
        + (f'<h3>Top findings</h3><table style="border-collapse:collapse">{rows}</table>{more}' if alert.findings else "")
        + f'<p style="color:#888;font-size:12px">{e(__app_name__)} {e(__version__)}</p></body></html>', subtype="html")
    return msg


# --------------------------------------------------------------------------- delivery

class _Permanent(Exception):
    """A failure that retrying cannot fix."""


def _http_post(url: str, payload: Dict[str, Any]) -> int:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "Content-Type": "application/json; charset=utf-8", "User-Agent": USER_AGENT})
    # urllib turns a redirected POST into a body-less GET (301/302/303) or refuses it (307/308), so the alert
    # text is never re-sent to a redirect target.
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        status = getattr(resp, "status", None)
        if not isinstance(status, int):
            getcode = getattr(resp, "getcode", None)
            status = getcode() if callable(getcode) else 200
        if not isinstance(status, int):
            status = 200
        try:
            resp.read(1024)
        except Exception:  # the status line is all we need
            log.debug("could not read alert response body", exc_info=True)
    return status


def _send_email(alert: Alert, config: Any) -> int:
    host = str(config.alert_email_smtp_host).strip()
    try:
        port = int(getattr(config, "alert_email_smtp_port", 587))
    except (TypeError, ValueError):
        raise _Permanent("SMTP port is not a number") from None
    user = str(getattr(config, "alert_email_smtp_user", "") or "")
    password = smtp_password(config)
    starttls = bool(getattr(config, "alert_email_starttls", True))
    implicit_tls = port == 465
    if user and password and not (starttls or implicit_tls) and not _is_loopback(host):
        raise _Permanent("refusing to send SMTP credentials over an unencrypted connection (enable STARTTLS)")
    msg = build_email(alert, config)
    recipients = email_recipients(config)
    sender_hdr = str(msg["From"])
    context = ssl.create_default_context()
    smtp: Any = (smtplib.SMTP_SSL(host, port, timeout=SMTP_TIMEOUT, context=context) if implicit_tls
                 else smtplib.SMTP(host, port, timeout=SMTP_TIMEOUT))
    with smtp as s:
        s.ehlo()
        if starttls and not implicit_tls:
            s.starttls(context=context)  # no silent downgrade: a server without STARTTLS is an error
            s.ehlo()
        if user and password:
            s.login(user, password)
        s.send_message(msg, from_addr=_bare_address(sender_hdr), to_addrs=recipients)
    return 250


def _retry_delay(exc: BaseException, attempt: int) -> Optional[float]:
    """Seconds to wait before retrying after ``exc``, or None when a retry is pointless."""
    if isinstance(exc, _Permanent):
        return None
    backoff = min(BACKOFF_MAX_S, BACKOFF_BASE_S * (2 ** (attempt - 1)))
    if isinstance(exc, urllib.error.HTTPError):
        if exc.code in (408, 425, 429) or exc.code >= 500:
            try:
                after = float(exc.headers.get("Retry-After", "")) if exc.headers else 0.0
            except (TypeError, ValueError):
                after = 0.0
            return max(backoff, min(after, 30.0))
        return None
    if isinstance(exc, smtplib.SMTPResponseException):
        return backoff if 400 <= exc.smtp_code < 500 else None
    if isinstance(exc, (smtplib.SMTPAuthenticationError, smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused,
                        smtplib.SMTPNotSupportedError, ssl.SSLError)):
        return None
    if isinstance(exc, urllib.error.URLError) and isinstance(exc.reason, ssl.SSLError):
        return None  # certificate / protocol problems do not heal by themselves
    if isinstance(exc, (urllib.error.URLError, smtplib.SMTPException, OSError, TimeoutError)):
        return backoff
    return None


def _describe(exc: BaseException, secrets: Sequence[str]) -> str:
    if isinstance(exc, _Permanent):
        msg = str(exc)
    elif isinstance(exc, urllib.error.HTTPError):
        msg = f"HTTP {exc.code} {exc.reason}"
    elif isinstance(exc, urllib.error.URLError):
        msg = f"connection failed: {exc.reason}"
    elif isinstance(exc, smtplib.SMTPResponseException):
        raw = exc.smtp_error
        msg = f"SMTP {exc.smtp_code} {raw.decode('utf-8', 'replace') if isinstance(raw, bytes) else raw}"
    else:
        msg = f"{type(exc).__name__}: {exc}"
    return _shorten(redact(msg, secrets), 300)


def _deliver(job: Callable[[], int], secrets: Sequence[str]) -> Dict[str, Any]:
    """Run one delivery with retries + exponential backoff. Never raises."""
    start = _clock()
    attempts = 0
    while True:
        attempts += 1
        try:
            status = job()
            return {"ok": True, "status": status, "attempts": attempts, "error": "", "skipped": ""}
        except BaseException as exc:  # noqa: BLE001 - nothing may escape an alert
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            error = _describe(exc, secrets)
            delay = _retry_delay(exc, attempts)
            status = exc.code if isinstance(exc, urllib.error.HTTPError) else None
            if delay is None or attempts >= MAX_ATTEMPTS or (_clock() - start) + delay > CHANNEL_DEADLINE_S:
                log.warning("alert delivery failed after %d attempt(s): %s", attempts, error)
                return {"ok": False, "status": status, "attempts": attempts, "error": error, "skipped": ""}
            log.debug("alert delivery attempt %d failed (%s); retrying in %.1fs", attempts, error, delay)
            _sleep(delay)


class RateLimiter:
    """Sliding-window limiter: at most ``max_events`` per ``window_s`` per key."""

    def __init__(self, max_events: int = RATE_LIMIT_MAX, window_s: float = RATE_LIMIT_WINDOW_S,
                 clock: Optional[Callable[[], float]] = None):
        self.max_events, self.window_s, self._clock = max_events, window_s, clock
        self._events: Dict[str, Deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = (self._clock or _clock)()
        with self._lock:
            q = self._events.setdefault(key, deque())
            while q and now - q[0] >= self.window_s:
                q.popleft()
            if len(q) >= self.max_events:
                return False
            q.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._events.clear()


_limiter = RateLimiter()


def reset_rate_limits() -> None:
    _limiter.reset()


def _make_job(channel: str, alert: Alert, config: Any) -> Callable[[], int]:
    if channel == "email":
        return lambda: _send_email(alert, config)
    url = _url(config, channel)
    why = validate_webhook_url(url)
    if why:
        def invalid() -> int:
            raise _Permanent(why)
        return invalid
    builders = {"webhook": build_generic_payload, "slack": build_slack_payload, "teams": build_teams_payload,
                "discord": build_discord_payload}
    payload = builders[channel](alert)
    return lambda: _http_post(url, payload)


def send_alerts(findings: Iterable[Finding], config: Any, context: Optional[Dict[str, Any]] = None) -> Dict[str, Dict[str, Any]]:
    """Send ONE message about ``findings`` to every configured channel.

    The caller decides which findings are alert-worthy (see :func:`select_findings`). Returns
    ``{channel: {"ok", "status", "attempts", "error", "skipped"}}`` (``{}`` when nothing is configured or there is
    nothing to say). Test messages bypass the rate limit. Never raises."""
    results: Dict[str, Dict[str, Any]] = {}
    channels: List[str] = []
    try:
        ctx = dict(context or {})
        channels = configured_channels(config)
        flist = [f for f in (findings or []) if isinstance(f, Finding)]
        if not channels or (not flist and ctx.get("kind") != "test"):
            return {}
        secrets = _secret_values(config)
        jobs: Dict[str, Callable[[], int]] = {}
        base = build_alert(flist, config, ctx, max_findings=max(MAX_FINDINGS.values()))
        for ch in channels:
            if ctx.get("kind") != "test" and not _limiter.allow(ch):
                results[ch] = {"ok": False, "status": None, "attempts": 0, "error": "", "skipped": "rate-limited"}
                continue
            alert = base
            if len(base.findings) > MAX_FINDINGS[ch]:  # same counts/summary, fewer listed rows
                alert = Alert(**{**base.__dict__, "findings": base.findings[:MAX_FINDINGS[ch]],
                                 "omitted": base.omitted + len(base.findings) - MAX_FINDINGS[ch]})
            jobs[ch] = _make_job(ch, alert, config)
        results.update(_run_jobs(jobs, secrets))
    except Exception as exc:
        log.warning("alerting failed: %s", exc)
        for ch in channels:
            results.setdefault(ch, {"ok": False, "status": None, "attempts": 0, "skipped": "",
                                    "error": _shorten(redact(f"internal error: {exc}", _safe_secrets(config)), 200)})
    return results


def _safe_secrets(config: Any) -> List[str]:
    try:
        return _secret_values(config)
    except Exception:
        return []


def _run_jobs(jobs: Dict[str, Callable[[], int]], secrets: Sequence[str]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    if len(jobs) <= 1:
        for ch, job in jobs.items():
            out[ch] = _deliver(job, secrets)
        return out
    threads = []
    for ch, job in jobs.items():
        t = threading.Thread(target=lambda c=ch, j=job: out.__setitem__(c, _deliver(j, secrets)),
                             name=f"aegis-alert-{ch}", daemon=True)
        t.start()
        threads.append(t)
    deadline = time.monotonic() + CHANNEL_DEADLINE_S + 10
    for t in threads:
        t.join(max(0.1, deadline - time.monotonic()))
    for ch in jobs:
        out.setdefault(ch, {"ok": False, "status": None, "attempts": 0, "skipped": "", "error": "timed out"})
    return out


# --------------------------------------------------------------------------- selection + hooks

def select_findings(findings: Iterable[Finding], config: Any) -> List[Finding]:
    """Findings at or above ``alert_min_severity``."""
    thr = min_severity(config)
    return [f for f in findings if f.severity >= thr]


def summarize(results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Compact form of per-channel results for ``ScanResult.stats`` (no secrets: errors are already redacted)."""
    return {"sent": sorted(ch for ch, r in results.items() if r.get("ok")),
            "failed": {ch: r.get("error") or r.get("skipped") or "failed" for ch, r in results.items() if not r.get("ok")}}


def alert_after_scan(result: Any, config: Any, diff: Optional[Dict[str, Any]] = None) -> Dict[str, Dict[str, Any]]:
    """Alert on a finished scan. ``diff`` is the ``history.diff`` result against the previous comparable scan
    (None: no baseline, so every finding counts as new). Never raises; records the outcome in ``result.stats``."""
    try:
        if not configured_channels(config):
            return {}
        if "scan cancelled by user" in (getattr(result, "errors", None) or []):
            return {}
        mode = alert_mode(config)
        if mode == "all" or diff is None:
            candidates = list(result.findings)
        else:
            seen, candidates = set(), []
            for f in list(diff.get("new", [])) + list(diff.get("escalated", [])):
                if f.fingerprint not in seen:
                    seen.add(f.fingerprint)
                    candidates.append(f)
        chosen = select_findings(candidates, config)
        if not chosen:
            return {}
        from aegis.core.scoring import security_score

        score, grade = security_score(result)
        ctx: Dict[str, Any] = {
            "kind": "scan", "profile": result.profile, "score": score, "grade": grade, "mode": mode,
            "baseline": diff is None, "host": (result.host or {}).get("hostname") or "",
            "score_change": diff.get("score_change") if diff else None,
            "resolved": len(diff.get("resolved", [])) if diff else None}
        results = send_alerts(chosen, config, ctx)
        if results:
            result.stats["alerts"] = summarize(results)
        return results
    except Exception as exc:
        log.warning("post-scan alerting failed: %s", exc)
        return {}


def test_alert(config: Any) -> Dict[str, Dict[str, Any]]:
    """Send a harmless test message to every configured channel (``{}`` if none is configured)."""
    host = socket.gethostname()
    sample = Finding(rule_id="AEG-TEST-ALERT", title="Aegis test alert - no action needed", severity=Severity.INFO,
                     category="system", location=f"test message from {host}")
    return send_alerts([sample], config, {"kind": "test", "host": host})


test_alert.__test__ = False  # type: ignore[attr-defined]  # not a pytest test when imported into a test module


# --------------------------------------------------------------------------- real-time batching

class AlertBatcher:
    """Collects real-time events and sends them as one message per window on a background thread.

    ``add()`` is called from the monitor's ``emit()``; it is cheap and thread-safe. The thread starts/stops with
    the monitor. Configuration is read live, so channels configured while protection is on take effect."""

    def __init__(self, config: Any, window_s: float = BATCH_WINDOW_S, tick_s: float = 1.0,
                 sender: Optional[Callable[..., Dict[str, Dict[str, Any]]]] = None,
                 clock: Optional[Callable[[], float]] = None, suppress_s: float = REPEAT_SUPPRESS_S,
                 urgent_window_s: float = URGENT_WINDOW_S):
        self.config = config
        self.window_s, self.tick_s, self.suppress_s, self.urgent_window_s = window_s, tick_s, suppress_s, urgent_window_s
        self._sender = sender or send_alerts
        self._clock = clock or time.monotonic
        self._lock = threading.Lock()
        self._pending: Dict[str, Finding] = {}
        self._first: Optional[float] = None
        self._events = 0
        self._seen: Dict[str, float] = {}
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.last_results: Dict[str, Dict[str, Any]] = {}

    # ---- producer side
    def add(self, finding: Finding) -> bool:
        """Queue ``finding`` if it is alert-worthy. Returns True when it was queued."""
        try:
            if finding.severity < min_severity(self.config) or not configured_channels(self.config):
                return False
            now = self._clock()
            with self._lock:
                fp = finding.fingerprint
                if alert_mode(self.config) == "new":
                    last = self._seen.get(fp)
                    if last is not None and now - last < self.suppress_s:
                        return False
                    self._seen[fp] = now
                    if len(self._seen) > 2000:
                        for k, _ in sorted(self._seen.items(), key=lambda kv: kv[1])[:1000]:
                            self._seen.pop(k, None)
                old = self._pending.get(fp)
                if old is None or finding.severity > old.severity:
                    self._pending[fp] = finding
                self._events += 1
                if self._first is None:
                    self._first = now
            return True
        except Exception:
            log.debug("could not queue alert", exc_info=True)
            return False

    # ---- consumer side
    def pending(self) -> int:
        with self._lock:
            return len(self._pending)

    def due(self, now: Optional[float] = None) -> bool:
        now = self._clock() if now is None else now
        with self._lock:
            if not self._pending or self._first is None:
                return False
            urgent = any(f.severity >= Severity.CRITICAL for f in self._pending.values())
            return now - self._first >= (self.urgent_window_s if urgent else self.window_s)

    def flush(self) -> Dict[str, Dict[str, Any]]:
        """Send everything queued as one message right now ({} if nothing is queued). Never raises."""
        with self._lock:
            batch, events = list(self._pending.values()), self._events
            self._pending, self._first, self._events = {}, None, 0
        if not batch:
            return {}
        try:
            self.last_results = self._sender(batch, self.config, {
                "kind": "realtime", "events": events, "window_s": self.window_s,
                "mode": alert_mode(self.config)})
        except Exception as exc:
            log.warning("real-time alert delivery failed: %s", exc)
            self.last_results = {}
        return self.last_results

    def _loop(self) -> None:
        while not self._stop.wait(self.tick_s):
            try:
                if self.due():
                    self.flush()
            except Exception:
                log.debug("alert batcher tick failed", exc_info=True)
        try:  # the monitor is stopping: do not lose what is queued
            self.flush()
        except Exception:
            log.debug("final alert flush failed", exc_info=True)

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="aegis-alert-batcher", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        t = self._thread
        if t is not None and t is not threading.current_thread():
            t.join(timeout)  # a slow final flush is left to finish on its daemon thread
        self._thread = None
