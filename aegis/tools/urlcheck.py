"""Offline URL reputation heuristics (phishing / malware-delivery indicators) with
optional online confirmation via Google Safe Browsing v4 and URLhaus.

``check_url`` never raises. Verdict thresholds: score >= 60 malicious,
score >= 30 suspicious, otherwise safe. A hit in a known-bad feed is always
malicious."""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import unicodedata
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Tuple

log = logging.getLogger("aegis.urlcheck")

MALICIOUS_AT = 60
SUSPICIOUS_AT = 30

# --------------------------------------------------------------------------- eTLD helper
# Not the full Public Suffix List - the multi-part suffixes seen in real traffic.
_MULTI_SUFFIXES: Set[str] = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "org.nz", "net.nz", "govt.nz", "ac.nz",
    "co.in", "net.in", "org.in", "firm.in", "gen.in", "ind.in", "ac.in", "edu.in", "gov.in", "res.in",
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "ad.jp",
    "co.kr", "or.kr", "ne.kr", "go.kr", "ac.kr",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "com.hk", "org.hk", "edu.hk", "com.tw", "org.tw", "net.tw", "com.sg", "edu.sg", "com.my", "com.ph", "com.vn",
    "co.id", "or.id", "co.th", "in.th", "co.il", "org.il", "ac.il",
    "com.mx", "com.ar", "com.co", "com.pe", "com.ve", "com.ec", "com.uy", "com.py", "com.bo", "com.cl",
    "co.za", "org.za", "net.za", "gov.za", "ac.za", "co.ke", "co.ug", "co.tz", "com.ng", "com.gh", "com.eg",
    "com.tr", "org.tr", "net.tr", "gen.tr", "com.ua", "com.pl", "com.ru", "com.pt", "com.es", "com.gr", "com.ro",
    "com.sa", "com.pk", "com.bd", "com.lk", "com.np", "com.qa", "com.kw", "com.lb", "com.jo",
    "co.at", "or.at", "co.hu", "co.cr", "co.ve", "com.de", "co.com", "uk.com", "us.com", "eu.com", "gb.com",
    "blogspot.com", "github.io", "herokuapp.com", "pages.dev", "workers.dev", "netlify.app", "vercel.app",
    "web.app", "firebaseapp.com", "azurewebsites.net", "cloudfront.net", "appspot.com", "weebly.com",
    "wixsite.com", "000webhostapp.com", "glitch.me", "repl.co", "ngrok.io", "ngrok-free.app", "trycloudflare.com",
    "r2.dev", "s3.amazonaws.com", "storage.googleapis.com", "web.core.windows.net", "blob.core.windows.net",
    "sharepoint.com", "myshopify.com", "square.site", "webflow.io", "framer.app", "carrd.co",
}


def split_host(host: str) -> Tuple[str, str, str]:
    """Split a hostname into (subdomain, registrable label, public suffix)."""
    host = host.lower().strip(".")
    labels = host.split(".")
    if len(labels) < 2:
        return "", host, ""
    suffix_len = 1
    for n in (3, 2):
        if len(labels) > n and ".".join(labels[-n:]) in _MULTI_SUFFIXES:
            suffix_len = n
            break
    else:
        if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_SUFFIXES:
            suffix_len = 2
    sld = labels[-suffix_len - 1]
    return ".".join(labels[:-suffix_len - 1]), sld, ".".join(labels[-suffix_len:])


def registered_domain(host: str) -> str:
    _, sld, suffix = split_host(host)
    return f"{sld}.{suffix}" if suffix else sld


# --------------------------------------------------------------------------- reference data

# brand keyword -> legitimate registrable domains
BRANDS: Dict[str, Set[str]] = {
    "paypal": {"paypal.com", "paypal.me", "paypalobjects.com", "paypal-community.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com", "office365.com",
                  "windows.com", "azure.com", "bing.com", "msn.com", "sharepoint.com", "onedrive.com", "xbox.com",
                  "skype.com", "microsoft365.com", "windowsupdate.com", "msft.net", "azureedge.net", "hotmail.com",
                  "office.net", "msecnd.net", "visualstudio.com", "linkedin.com", "github.com"},
    "office365": {"office365.com", "office.com", "microsoft.com", "microsoftonline.com", "microsoft365.com"},
    "outlook": {"outlook.com", "office.com", "microsoft.com", "live.com", "office365.com", "outlook.office365.com"},
    "apple": {"apple.com", "icloud.com", "me.com", "mzstatic.com", "cdn-apple.com", "apple.news"},
    "amazon": {"amazon.com", "amazonaws.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.it", "amazon.es",
               "amazon.ca", "amazon.com.au", "amazon.co.jp", "amazon.in", "amazon.com.br", "amazon.com.mx",
               "amazon.nl", "amazon.se", "amazon.pl", "amazon.sg", "amazon.ae", "amazon.sa", "amazon.com.tr",
               "amzn.to", "amzn.com", "a.co", "primevideo.com", "audible.com", "twitch.tv", "ssl-images-amazon.com",
               "media-amazon.com", "cloudfront.net"},
    "netflix": {"netflix.com", "nflxso.net", "nflximg.net", "nflxext.com", "nflxvideo.net"},
    "wellsfargo": {"wellsfargo.com", "wf.com"},
    "chase": {"chase.com", "jpmorgan.com", "jpmorganchase.com"},
    "bankofamerica": {"bankofamerica.com", "bofa.com", "merrilledge.com"},
    "coinbase": {"coinbase.com", "cb-pay.com"},
    "binance": {"binance.com", "binance.us", "binance.org", "bnbchain.org"},
    "metamask": {"metamask.io", "consensys.io", "consensys.net"},
    "steam": {"steampowered.com", "steamcommunity.com", "steamstatic.com", "steamgames.com", "valvesoftware.com"},
    "roblox": {"roblox.com", "rbxcdn.com", "robloxlabs.com"},
    "instagram": {"instagram.com", "cdninstagram.com", "instagr.am"},
    "facebook": {"facebook.com", "fb.com", "fb.me", "fbcdn.net", "facebook.net", "messenger.com", "meta.com",
                 "fbsbx.com", "fb.watch"},
    "whatsapp": {"whatsapp.com", "whatsapp.net", "wa.me"},
    "dhl": {"dhl.com", "dhl.de", "dhl.co.uk", "dhl.fr", "dhl.es", "dhl.it", "dhl.nl", "dhl.com.au", "dhl.co.in"},
    "fedex": {"fedex.com", "fedex.com.cn"},
    "usps": {"usps.com", "uspis.gov", "usps.gov"},
    "irs": {"irs.gov", "irs.treasury.gov"},
    "google": {"google.com", "gmail.com", "googleapis.com", "gstatic.com", "youtube.com", "goo.gl", "g.co",
               "googleusercontent.com", "googlevideo.com", "ytimg.com", "google.co.uk", "google.de", "google.fr",
               "google.es", "google.it", "google.ca", "google.com.au", "google.co.jp", "google.co.in",
               "google.com.br", "withgoogle.com", "appspot.com", "web.app", "firebaseapp.com", "blogspot.com",
               "googledrive.com", "googlesyndication.com", "doubleclick.net", "android.com", "chrome.com",
               "chromium.org", "ggpht.com"},
    "linkedin": {"linkedin.com", "licdn.com", "lnkd.in"},
    "dropbox": {"dropbox.com", "dropboxusercontent.com", "db.tt", "dropboxapi.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "adobe": {"adobe.com", "adobe.io", "adobelogin.com", "typekit.net", "acrobat.com", "adobeccstatic.com"},
    "zoom": {"zoom.us", "zoom.com", "zoomgov.com"},
    "ebay": {"ebay.com", "ebay.co.uk", "ebay.de", "ebay.fr", "ebay.it", "ebay.es", "ebay.com.au", "ebay.ca",
             "ebayimg.com", "ebaycdn.net", "ebay.ie", "ebay.in", "ebay.at", "ebay.ch", "ebay.nl"},
    "twitter": {"twitter.com", "x.com", "t.co", "twimg.com"},
    "telegram": {"telegram.org", "t.me", "telegram.me", "telegra.ph"},
    "discord": {"discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media"},
    "spotify": {"spotify.com", "scdn.co", "spotifycdn.com"},
    "icloud": {"icloud.com", "apple.com", "me.com"},
}

# Keywords matched as sub-strings of a host label (long, distinctive brands) ...
_SUBSTRING_BRANDS = {"paypal", "microsoft", "netflix", "office365", "wellsfargo", "bankofamerica", "coinbase", "binance",
                     "metamask", "instagram", "facebook", "whatsapp", "outlook", "docusign", "icloud"}
# ... others only as whole hyphen/dot separated tokens (apple != pineapple).
_TOKEN_ONLY_BRANDS = set(BRANDS) - _SUBSTRING_BRANDS

# Top brand domains for lookalike (edit-distance) comparison.
LOOKALIKE_DOMAINS: List[str] = sorted({
    "paypal.com", "microsoft.com", "apple.com", "amazon.com", "google.com", "facebook.com", "netflix.com",
    "instagram.com", "whatsapp.com", "linkedin.com", "twitter.com", "youtube.com", "outlook.com", "office.com",
    "office365.com", "live.com", "icloud.com", "dropbox.com", "adobe.com", "docusign.com", "coinbase.com",
    "binance.com", "metamask.io", "blockchain.com", "kraken.com", "wellsfargo.com", "chase.com",
    "bankofamerica.com", "citibank.com", "capitalone.com", "americanexpress.com", "hsbc.com", "barclays.co.uk",
    "santander.com", "usps.com", "fedex.com", "dhl.com", "ups.com", "irs.gov", "steampowered.com",
    "steamcommunity.com", "roblox.com", "discord.com", "telegram.org", "spotify.com", "ebay.com", "alibaba.com",
    "github.com", "gitlab.com", "zoom.us", "yahoo.com", "reddit.com", "tiktok.com", "snapchat.com", "twitch.tv",
    "epicgames.com", "playstation.com", "xbox.com", "outlook.office365.com", "onedrive.com", "sharepoint.com",
    "godaddy.com", "namecheap.com", "cloudflare.com", "stripe.com", "shopify.com", "walmart.com", "target.com",
    "bestbuy.com", "booking.com", "airbnb.com", "uber.com", "wetransfer.com", "mailchimp.com",
})

RISKY_TLDS = {"zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "icu", "cyou", "sbs", "click", "link", "rest",
              "quest", "buzz", "cam", "lol"}

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "goo.gl", "ow.ly",
              "buff.ly", "tiny.cc", "v.gd", "t.ly", "rebrand.ly", "bl.ink", "shorte.st", "adf.ly", "lnkd.in",
              "s.id", "qr.ae", "trib.al", "soo.gd", "clck.ru", "vk.cc", "u.to", "x.co", "short.io", "tr.ee",
              "l.ead.me", "bit.do", "mcaf.ee", "po.st", "snip.ly", "urlz.fr", "qrco.de", "shorturl.com"}

# Reputable, user-generated-content sites where a brand word in the *path* is normal.
TRUSTED_SITES = {
    "github.com", "gitlab.com", "stackoverflow.com", "stackexchange.com", "wikipedia.org", "reddit.com", "youtube.com",
    "medium.com", "google.com", "microsoft.com", "apple.com", "amazon.com", "bing.com", "duckduckgo.com",
    "twitter.com", "x.com", "facebook.com", "linkedin.com", "quora.com", "mozilla.org", "python.org", "npmjs.com",
    "pypi.org", "archive.org", "wikimedia.org", "bbc.co.uk", "nytimes.com", "cnn.com", "forbes.com", "theverge.com",
    "techcrunch.com", "arstechnica.com", "wired.com", "microsoftonline.com", "office.com", "live.com",
    "sourceforge.net", "superuser.com", "askubuntu.com", "serverfault.com", "docs.google.com", "trustpilot.com",
}

LOGIN_WORDS = ("login", "log-in", "signin", "sign-in", "logon", "verify", "verification", "account", "secure",
               "update", "password", "passwd", "auth", "wallet", "banking", "confirm", "recover", "unlock", "billing",
               "validate", "security", "suspend", "restore", "webscr", "cmd=_login")
EXEC_EXTS = (".exe", ".scr", ".msi", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta", ".lnk", ".jar", ".apk",
             ".ps1", ".iso", ".img", ".dll", ".cpl", ".msix", ".appx")

# Common Cyrillic / Greek look-alikes -> Latin (for skeleton comparison).
_CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d",
    "һ": "h", "ԛ": "q", "ԝ": "w", "ӏ": "l", "ɡ": "g", "ᴏ": "o", "ο": "o", "ν": "v", "α": "a", "ι": "i", "ρ": "p",
    "τ": "t", "υ": "u", "κ": "k", "ɑ": "a", "ı": "i", "ⅼ": "l", "ǀ": "l", "ӓ": "a", "ё": "e", "ᛁ": "i",
    "0": "o", "1": "l",
}
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "$": "s", "@": "a"})


# --------------------------------------------------------------------------- helpers

def levenshtein(a: str, b: str, limit: int = 99) -> int:
    """Edit distance with early exit once it must exceed ``limit``."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > limit:
            return limit + 1
        prev = cur
    return prev[-1]


def _script_of(ch: str) -> str:
    try:
        return unicodedata.name(ch).split()[0]
    except ValueError:
        return "UNKNOWN"


def _decode_host(host: str) -> str:
    """Decode punycode labels to Unicode (best effort)."""
    out = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except Exception:
                try:
                    label = label[4:].encode("ascii").decode("punycode")
                except Exception:
                    pass
        out.append(label)
    return ".".join(out)


def _mixed_script(label: str) -> bool:
    scripts = {_script_of(c) for c in label if c.isalpha()}
    return len(scripts) > 1 and "LATIN" in scripts and bool(scripts & {"CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE"})


def _skeleton(label: str) -> str:
    s = "".join(_CONFUSABLES.get(c, c) for c in label.lower())
    s = unicodedata.normalize("NFKD", s)
    s = "".join(c for c in s if not unicodedata.combining(c))
    return s.replace("rn", "m").replace("vv", "w")


def _parse_ip(host: str) -> Optional[ipaddress._BaseAddress]:
    """Parse IP literals, including the obfuscated forms browsers accept
    (decimal 2130706433, hex 0x7f000001, octal/short dotted)."""
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass
    h = host.strip(".")
    if re.fullmatch(r"(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}", h, re.I):
        try:
            parts = [int(p, 16) if p.lower().startswith("0x") else (int(p, 8) if len(p) > 1 and p.startswith("0") else int(p))
                     for p in h.split(".")]
            val = 0
            for p in parts[:-1]:
                if p > 255:
                    return None
                val = (val << 8) | p
            last_bytes = 4 - (len(parts) - 1)
            if parts[-1] >= 256 ** last_bytes:
                return None
            val = (val << (8 * last_bytes)) | parts[-1]
            return ipaddress.IPv4Address(val)
        except (ValueError, OverflowError):
            return None
    return None


class _Verdict:
    def __init__(self) -> None:
        self.score = 0
        self.reasons: List[str] = []
        self.forced_malicious = False

    def add(self, pts: int, reason: str) -> None:
        self.score += pts
        self.reasons.append(reason)


def _tokens(text: str) -> List[str]:
    return [t for t in re.split(r"[^a-z0-9]+", text.lower()) if t]


def _brand_hits_in_host(labels: List[str]) -> Set[str]:
    hits: Set[str] = set()
    for label in labels:
        toks = _tokens(label)
        for brand in BRANDS:
            if brand in _SUBSTRING_BRANDS:
                if brand in label:
                    hits.add(brand)
            elif brand in toks:
                hits.add(brand)
    return hits


def _legit_brand_domain(reg: str, brand: str) -> bool:
    return reg in BRANDS[brand]


# --------------------------------------------------------------------------- main

def check_url(url: str, signatures: Any = None, config: Any = None) -> Dict[str, Any]:
    """Assess a URL. Returns {"url","host","verdict","score","reasons", ...}."""
    result: Dict[str, Any] = {"url": url, "host": "", "verdict": "safe", "score": 0, "reasons": [],
                              "registered_domain": ""}
    try:
        v = _Verdict()
        host = _analyse(url, signatures, config, v, result)
        result["host"] = host
        score = min(100, v.score)
        if v.forced_malicious:
            score = max(score, 90)
        result["score"] = score
        result["verdict"] = "malicious" if (v.forced_malicious or score >= MALICIOUS_AT) else \
            "suspicious" if score >= SUSPICIOUS_AT else "safe"
        result["reasons"] = v.reasons or ["no suspicious indicators found (offline heuristics)"] \
            if result["verdict"] == "safe" else v.reasons
    except Exception as exc:  # defensive: callers rely on a dict
        log.debug("check_url failed for %r: %s", url, exc)
        result["verdict"] = "suspicious"
        result["score"] = SUSPICIOUS_AT
        result["reasons"] = [f"could not parse URL ({type(exc).__name__})"]
    return result


def _analyse(raw: str, signatures: Any, config: Any, v: _Verdict, result: Dict[str, Any]) -> str:
    url = (raw or "").strip().strip("<>\"'")
    if not url:
        v.add(SUSPICIOUS_AT, "empty URL")
        return ""
    lowered = url.lower()

    # --- dangerous non-network schemes
    if lowered.startswith(("javascript:", "vbscript:")):
        v.add(80, f"{lowered.split(':', 1)[0]}: URL executes script in the page context")
        return ""
    if lowered.startswith("data:"):
        if lowered.startswith(("data:image/", "data:font/")):
            v.add(SUSPICIOUS_AT, "inline data: URL (check where it came from)")
        else:
            v.add(75, "data: URL carrying an inline document/script (common phishing / smuggling technique)")
        return ""

    explicit_scheme = bool(re.match(r"^[a-z][a-z0-9+.\-]*://", lowered))
    work = url if explicit_scheme else "http://" + url.lstrip("/")
    parts = urllib.parse.urlsplit(work)
    scheme = parts.scheme.lower() if explicit_scheme else ""
    if scheme in ("file",):
        v.add(SUSPICIOUS_AT, "file:// URL points at the local machine")
    elif scheme and scheme not in ("http", "https", "ftp", "ftps"):
        v.add(SUSPICIOUS_AT, f"unusual URL scheme '{scheme}:'")

    netloc = parts.netloc
    userinfo, _, hostport = netloc.rpartition("@")
    try:
        host = (parts.hostname or "").lower().rstrip(".")
        port = parts.port
    except ValueError:
        host, port = hostport.split(":")[0].lower(), None
        v.add(15, "malformed port in URL")
    if not host:
        v.add(SUSPICIOUS_AT, "URL has no host")
        return ""
    path_q = (parts.path or "") + ("?" + parts.query if parts.query else "")
    path_l = urllib.parse.unquote(path_q).lower()

    # --- '@' trick:  https://paypal.com@evil.example/
    if "@" in netloc:
        pts = 40
        why = "'@' in the URL authority - everything before it is ignored by the browser"
        if "." in userinfo:
            pts += 20
            why += f" (the text '{userinfo.split(':')[0]}' is a decoy)"
        v.add(pts, why)

    # --- known bad (feeds)
    if signatures is not None:
        try:
            if signatures.is_bad_domain(host) or (_parse_ip(host) and signatures.is_bad_ip(host)):
                v.forced_malicious = True
                v.add(100, f"{host} is listed in the malicious domain/IP blocklists")
        except Exception as exc:
            log.debug("signature lookup failed: %s", exc)

    ip = _parse_ip(host)
    reg = host
    login_like = any(w in path_l or w in host for w in LOGIN_WORDS)

    if ip is not None:
        canonical = str(ip)
        if canonical != host.strip("[]"):
            v.add(50, f"host is an obfuscated IP address ({host} = {canonical})")
        elif ip.is_private or ip.is_loopback or ip.is_link_local:
            v.add(10, "URL points at a private/loopback address")
        else:
            v.add(35, "host is a raw IP address instead of a domain name")
        if login_like and not ip.is_private:
            v.add(15, "login/verification wording served from a bare IP address")
        if port and port not in (80, 443, 8080, 8443):
            v.add(5, f"non-standard port {port}")
    else:
        sub, sld, suffix = split_host(host)
        reg = registered_domain(host)
        result["registered_domain"] = reg
        tld = host.rsplit(".", 1)[-1]
        decoded = _decode_host(host)

        # --- punycode / homoglyphs
        if "xn--" in host:
            v.add(25, f"internationalised (punycode) domain; displays as '{decoded}'")
        for label in decoded.split("."):
            if _mixed_script(label):
                v.add(45, f"label '{label}' mixes Latin with another script (homoglyph attack)")
                break
        if decoded != host or any(ord(c) > 127 for c in host):
            dsub, dsld, dsuffix = split_host(decoded)
            skel = _skeleton(dsld)
            for brand_dom in LOOKALIKE_DOMAINS:
                b_sld = brand_dom.split(".")[0]
                if skel == b_sld and dsld != b_sld:
                    v.add(60, f"characters in '{dsld}' imitate the brand domain {brand_dom}")
                    break

        # --- risky TLD
        if tld in RISKY_TLDS:
            v.add(15, f"'.{tld}' is a TLD heavily abused for phishing and malware")
            if login_like:
                v.add(10, "credential/verification wording on a high-abuse TLD")

        # --- shorteners
        if reg in SHORTENERS or host in SHORTENERS:
            v.add(SUSPICIOUS_AT, f"URL shortener ({reg}) hides the real destination - expand before trusting")

        # --- brand impersonation
        labels_for_brand = ([x for x in sub.split(".") if x] if sub else []) + [sld]
        trusted_reg = reg in TRUSTED_SITES or any(reg in doms for doms in BRANDS.values())
        brands = _brand_hits_in_host(labels_for_brand)
        flagged_brand = False
        for brand in sorted(brands):
            if any(reg in BRANDS[b] for b in brands):  # one of the matched brands owns this domain
                continue
            if _legit_brand_domain(reg, brand):
                continue
            where = "subdomain" if brand in " ".join(sub.split(".")) else "domain name"
            v.add(45, f"'{brand}' appears in the {where} but {reg} is not an official {brand} domain")
            flagged_brand = True
            if login_like:
                v.add(15, "credential/verification wording alongside the brand name")
            break
        if not flagged_brand and not trusted_reg:
            path_toks = set(_tokens(path_l))
            pbrands = sorted(b for b in BRANDS if (b in path_toks or (b in _SUBSTRING_BRANDS and b in path_l)))
            pbrands = [b for b in pbrands if not _legit_brand_domain(reg, b)]
            if pbrands:
                pts = 15 + (20 if login_like else 0)
                v.add(pts, f"brand name '{pbrands[0]}' used in the URL path on unrelated domain {reg}")

        # --- exact brand label on a non-official / high-abuse suffix
        if sld in BRANDS and not _legit_brand_domain(reg, sld) and not flagged_brand:
            if tld in RISKY_TLDS or suffix.count(".") == 0 and len(tld) > 2 and tld not in ("com", "net", "org", "io", "co"):
                v.add(40, f"'{sld}' is a brand name but {reg} is not an official domain")

        # --- lookalike registered domain (typosquat)
        if not flagged_brand and reg not in LOOKALIKE_DOMAINS and not any(reg in d for d in BRANDS.values()):
            skel_sld = _skeleton(sld.translate(_LEET))
            for brand_dom in LOOKALIKE_DOMAINS:
                b_sld = brand_dom.split(".")[0]
                limit = 1 if len(b_sld) < 8 else 2
                same_skel = skel_sld == b_sld and sld != b_sld
                # edit distance only for names long enough to be unambiguous (ample.com != apple.com)
                dist = levenshtein(f"{sld}.{suffix}", brand_dom, limit) if len(b_sld) >= 6 else limit + 1
                if (dist <= limit and sld != b_sld) or (same_skel and len(b_sld) >= 4):
                    v.add(55, f"{reg} looks like {brand_dom} (typosquatting)")
                    break

        # --- structure heuristics
        dots = len([x for x in sub.split(".") if x]) if sub else 0
        if dots >= 4:
            v.add(10, f"{dots} nested subdomains")
        if sum(1 for w in LOGIN_WORDS if w in sld) >= 2:
            v.add(15, "several credential/verification keywords stuffed into the domain name")
        if host.count("-") >= 3:
            v.add(10, "many hyphens in host name")
        if len(host) > 60:
            v.add(8, "very long host name")
        if re.search(r"\d{5,}", sld):
            v.add(5, "long digit run in domain name")

    # --- length / encoding / redirect heuristics
    if len(url) > 200:
        v.add(10, f"very long URL ({len(url)} characters)")
    elif len(url) > 100:
        v.add(4, "long URL")
    if re.search(r"%(25)?(2e|2f|3a)", url, re.I) and parts.path.count("%") > 6:
        v.add(8, "heavily percent-encoded path")
    if parts.query:
        for _k, val in urllib.parse.parse_qsl(parts.query):
            m = re.match(r"https?://([^/\s:]+)", val, re.I)
            if m and registered_domain(m.group(1).lower()) != reg:
                v.add(10, f"redirect parameter points to another site ({m.group(1)})")
                break

    # --- cleartext credential pages
    if scheme == "http" and any(w in path_l for w in LOGIN_WORDS[:8]):
        v.add(20, "login/verification page served over unencrypted HTTP")

    # --- direct executable / archive lures
    base = urllib.parse.unquote(parts.path).lower().rsplit("/", 1)[-1]
    if base.endswith(EXEC_EXTS):
        risky_ctx = (ip is not None) or (host.rsplit(".", 1)[-1] in RISKY_TLDS) or v.score >= 15
        v.add(20 if risky_ctx else 5, f"URL downloads a '{base.rsplit('.', 1)[-1]}' executable/script file")
    if re.search(r"\.(pdf|docx?|xlsx?|jpe?g|png|txt)\.(exe|scr|js|vbs|bat|cmd|lnk|hta)$", base):
        v.add(50, "double extension disguises an executable as a document")

    # --- optional online confirmation
    _online_checks(url, config, v)
    return host


def _online_checks(url: str, config: Any, v: _Verdict) -> None:
    """Google Safe Browsing v4 and URLhaus - only with keys the user configured."""
    if config is None:
        return
    gsb = getattr(config, "google_safebrowsing_api_key", "") or ""
    if gsb:
        try:
            hit = google_safebrowsing(url, gsb)
            if hit:
                v.forced_malicious = True
                v.add(100, f"Google Safe Browsing flags this URL ({', '.join(hit)})")
        except Exception as exc:
            log.debug("safe browsing lookup failed: %s", exc)
    ab = getattr(config, "abusech_auth_key", "") or ""
    if ab:
        try:
            from aegis.tools.reputation import urlhaus_lookup

            res = urlhaus_lookup(url, ab)
            if res and res.get("found") and res.get("url_status") != "offline":
                v.forced_malicious = True
                v.add(100, f"URLhaus lists this URL as {res.get('threat') or 'malware distribution'}")
            elif res and res.get("found"):
                v.add(40, "URLhaus lists this URL (currently offline)")
        except Exception as exc:
            log.debug("urlhaus lookup failed: %s", exc)


def google_safebrowsing(url: str, api_key: str) -> List[str]:
    """Return threat types Google Safe Browsing v4 reports for ``url`` ([] = clean/unknown)."""
    from aegis.tools.reputation import http_request

    body = {
        "client": {"clientId": "aegis-security-suite", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    res = http_request(
        "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + urllib.parse.quote(api_key),
        "POST", {"Content-Type": "application/json"}, json.dumps(body).encode())
    if not res or res[0] != 200:
        return []
    try:
        doc = json.loads(res[1].decode("utf-8", "replace"))
    except ValueError:
        return []
    return sorted({m.get("threatType", "UNKNOWN") for m in doc.get("matches", [])})
