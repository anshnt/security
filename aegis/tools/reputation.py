"""Optional online reputation look-ups (VirusTotal, MalwareBazaar, URLhaus).

Only hashes / URLs are ever sent - never file contents. Every function swallows
network problems and returns ``None`` (logging the reason) so callers can treat
"cloud unavailable" like "no verdict"."""

from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Mapping, Optional, Tuple

log = logging.getLogger("aegis.reputation")

USER_AGENT = "Aegis-Security-Suite/1.0"
TIMEOUT = 15
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_HASH_RE = re.compile(r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")


def http_request(url: str, method: str = "GET", headers: Optional[Mapping[str, str]] = None,
                 data: Optional[bytes] = None, timeout: float = TIMEOUT) -> Optional[Tuple[int, bytes]]:
    """Perform a request, returning ``(status, body)``; HTTP error statuses are
    returned (not raised). Returns None on connection-level failures."""
    hdrs = {"User-Agent": USER_AGENT}
    hdrs.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return getattr(resp, "status", 200) or 200, resp.read()
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read()
        except Exception:
            body = b""
        return exc.code, body
    except Exception as exc:  # URLError, timeouts, TLS, proxy problems ...
        log.info("request to %s failed: %s", urllib.parse.urlsplit(url).netloc, exc)
        return None


def _json(body: bytes) -> Optional[Any]:
    try:
        return json.loads(body.decode("utf-8", "replace"))
    except ValueError:
        return None


# --------------------------------------------------------------------------- VirusTotal

def virustotal_lookup(sha256: str, api_key: str) -> Optional[Dict[str, Any]]:
    """Look up a file hash on VirusTotal (API v3).

    Returns {"malicious","suspicious","harmless","undetected","total","link","names"}
    (plus "unknown": True when VT has never seen the file) or None on failure."""
    if not api_key or not _HASH_RE.match(sha256 or ""):
        return None
    sha256 = sha256.lower()
    link = f"https://www.virustotal.com/gui/file/{sha256}"
    res = http_request(f"https://www.virustotal.com/api/v3/files/{sha256}", headers={"x-apikey": api_key})
    if res is None:
        return None
    status, body = res
    if status == 404:
        return {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "total": 0,
                "link": link, "names": [], "unknown": True}
    if status != 200:
        log.info("VirusTotal returned HTTP %s", status)
        return None
    doc = _json(body)
    try:
        attrs = doc["data"]["attributes"]
    except (TypeError, KeyError):
        return None
    stats = attrs.get("last_analysis_stats") or {}
    counts = {k: int(stats.get(k, 0) or 0) for k in ("malicious", "suspicious", "harmless", "undetected")}
    names = []
    for n in [attrs.get("meaningful_name")] + list(attrs.get("names") or []):
        if n and n not in names:
            names.append(n)
    out: Dict[str, Any] = dict(counts)
    out["total"] = sum(counts.values()) + int(stats.get("timeout", 0) or 0) + int(stats.get("type-unsupported", 0) or 0) \
        + int(stats.get("failure", 0) or 0) + int(stats.get("confirmed-timeout", 0) or 0)
    out["link"] = link
    out["names"] = names[:5]
    out["threat_label"] = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label", "")
    return out


# --------------------------------------------------------------------------- MalwareBazaar

def malwarebazaar_lookup(sha256: str, auth_key: str) -> Optional[Dict[str, Any]]:
    """Ask MalwareBazaar (abuse.ch) about a hash. {"found": False} when unknown."""
    if not _HASH_RE.match(sha256 or ""):
        return None
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if auth_key:
        headers["Auth-Key"] = auth_key
    body = urllib.parse.urlencode({"query": "get_info", "hash": sha256.lower()}).encode()
    res = http_request("https://mb-api.abuse.ch/api/v1/", "POST", headers, body)
    if res is None:
        return None
    status, raw = res
    doc = _json(raw)
    if not isinstance(doc, dict):
        log.info("MalwareBazaar returned HTTP %s", status)
        return None
    qs = doc.get("query_status")
    if qs in ("hash_not_found", "no_results"):
        return {"found": False}
    if qs != "ok" or not doc.get("data"):
        log.info("MalwareBazaar query_status=%s", qs)
        return None
    d = doc["data"][0]
    return {
        "found": True,
        "signature": d.get("signature") or "",
        "file_name": d.get("file_name") or "",
        "file_type": d.get("file_type") or "",
        "tags": d.get("tags") or [],
        "first_seen": d.get("first_seen") or "",
        "delivery_method": d.get("delivery_method") or "",
        "reporter": d.get("reporter") or "",
        "link": f"https://bazaar.abuse.ch/sample/{sha256.lower()}/",
    }


# --------------------------------------------------------------------------- URLhaus

def urlhaus_lookup(url: str, auth_key: str = "") -> Optional[Dict[str, Any]]:
    """Check a URL against URLhaus. {"found": False} when not listed."""
    if not url:
        return None
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if auth_key:
        headers["Auth-Key"] = auth_key
    res = http_request("https://urlhaus-api.abuse.ch/v1/url/", "POST", headers,
                       urllib.parse.urlencode({"url": url}).encode())
    if res is None:
        return None
    doc = _json(res[1])
    if not isinstance(doc, dict):
        return None
    qs = doc.get("query_status")
    if qs == "no_results":
        return {"found": False}
    if qs != "ok":
        log.info("URLhaus query_status=%s", qs)
        return None
    return {
        "found": True,
        "url_status": doc.get("url_status") or "",  # online | offline | unknown
        "threat": doc.get("threat") or "",
        "tags": doc.get("tags") or [],
        "host": doc.get("host") or "",
        "link": doc.get("urlhaus_reference") or "",
    }
