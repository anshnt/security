"""Locally stored e-mail review: malicious attachments, spoofed senders and deceptive links.

Sources (all read-only, nothing is sent anywhere):

* ``.eml`` files under the scanned paths and Downloads / Documents / Desktop,
* Outlook's attachment cache - ``%LOCALAPPDATA%\\Microsoft\\Windows\\INetCache\\Content.Outlook`` and the "Secure Temp
  Folder" from ``HKCU\\Software\\Microsoft\\Office\\*\\Outlook\\Security\\OutlookSecureTempFolder`` (files that *were
  opened* from a message),
* Thunderbird profiles (``Mail`` / ``ImapMail`` mbox files, newest part of each file).

Attachments are decoded in memory and run through ``aegis.scanners.files.analyse_bytes`` (hash database, YARA, PE /
script / Office heuristics, archive members). Findings carry locations such as ``message.eml!invoice.docm``. On top of
that this module flags dangerous attachment *types* (.iso .img .lnk .hta .js .vbs .wsf .scr .cpl .jar .one .chm,
HTML smuggling, password-protected archives), sender spoofing (From / Return-Path / Reply-To mismatch, failed
SPF/DKIM/DMARC, brand display-name impersonation, look-alike sender domains) and links whose visible text points
somewhere else than the real destination.

``analyse_eml(path_or_bytes, ctx)`` analyses one message and is meant for ``aegis check-file``.
"""

from __future__ import annotations

import io
import logging
import os
import re
import struct
import time
import zipfile
from dataclasses import dataclass, field
from email import policy
from email.header import decode_header, make_header
from email.message import Message
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple, Union

from aegis.core import fileanalysis as fa
from aegis.core.models import Category, CheckResult, CheckStatus, Finding, Remediation, Severity
from aegis.core.platform import IS_WINDOWS, env_path, reg_read, reg_subkeys, user_home
from aegis.scanners.base import Emitted, ScanContext, Scanner, register
from aegis.scanners.files import analyse_bytes, scan_file

log = logging.getLogger("aegis.email")

MAX_EML_BYTES = 64 * 1024 * 1024
MAX_ATTACHMENT_BYTES = 48 * 1024 * 1024
MAX_MBOX_BYTES = 200 * 1024 * 1024  # only the newest part of a bigger mailbox file is read
MAX_MBOX_MESSAGES = 2000
MAX_MESSAGE_BYTES = 40 * 1024 * 1024
MAX_EML_FILES = 500
MAX_LINKS = 25
MAX_NESTING = 3
WALK_DEPTH = 6
MAX_WALK_ENTRIES = 60000
MAX_FINDINGS_PER_MESSAGE = 40

# =========================================================================== reference data

# extension -> (severity, plain-English description)
DANGEROUS_TYPES: Dict[str, Tuple[Severity, str]] = {
    **{e: (Severity.HIGH, d) for e, d in {
        "exe": "a Windows program", "scr": "a screensaver file, which is really a program", "com": "a DOS/Windows program",
        "pif": "a program information file, which is really a program", "cpl": "a Control Panel applet, which is really a program (DLL)",
        "msi": "an installer package", "msix": "an app installer package", "appx": "an app installer package",
        "jar": "a Java program", "hta": "an HTML Application, which runs with full user rights",
        "js": "a JavaScript file that Windows runs directly (not in a browser)", "jse": "an encoded JavaScript file that Windows runs directly",
        "vbs": "a VBScript that Windows runs directly", "vbe": "an encoded VBScript that Windows runs directly",
        "wsf": "a Windows Script File", "wsh": "a Windows Script Host settings file", "ps1": "a PowerShell script",
        "bat": "a batch file", "cmd": "a batch file", "dll": "a program library", "sct": "a script component",
        "xll": "an Excel add-in, which is a DLL that runs code when opened", "wll": "a Word add-in, which is a DLL that runs code",
        "reg": "a registry file that changes Windows settings", "gadget": "a desktop gadget program",
    }.items()},
    **{e: (Severity.MEDIUM, d) for e, d in {
        "iso": "a disk image (opening it bypasses the 'downloaded from the Internet' warning)",
        "img": "a disk image (opening it bypasses the 'downloaded from the Internet' warning)",
        "vhd": "a virtual disk (opening it bypasses the 'downloaded from the Internet' warning)",
        "vhdx": "a virtual disk (opening it bypasses the 'downloaded from the Internet' warning)",
        "lnk": "a shortcut file that can start any command", "one": "an OneNote file that can hide embedded scripts and programs",
        "chm": "a compiled help file that can run code", "url": "an Internet shortcut", "iqy": "an Excel web query that can fetch remote content",
        "slk": "a SYLK spreadsheet (used to smuggle formulas)", "settingcontent-ms": "a settings shortcut that can start a program",
        "inf": "a setup information file that can install and run things", "application": "a ClickOnce application",
        "ace": "an ACE archive (a format with known exploits)",
    }.items()},
    **{e: (Severity.LOW, d) for e, d in {
        "html": "an HTML file (used for 'HTML smuggling' and fake login pages)", "htm": "an HTML file (used for 'HTML smuggling' and fake login pages)",
        "shtml": "an HTML file", "xhtml": "an HTML file", "svg": "an image file that can contain scripts",
        "docm": "a Word document that can contain macros", "xlsm": "an Excel workbook that can contain macros",
        "pptm": "a PowerPoint file that can contain macros", "dotm": "a Word template that can contain macros",
        "xlam": "an Excel add-in that can contain macros", "ppam": "a PowerPoint add-in that can contain macros",
        "xlsb": "a binary Excel workbook (can contain macros)",
    }.items()},
}

FREEMAIL = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com", "ymail.com",
            "aol.com", "icloud.com", "me.com", "proton.me", "protonmail.com", "gmx.com", "gmx.net", "mail.com", "yandex.com",
            "yandex.ru", "mail.ru", "qq.com", "163.com", "126.com", "zoho.com", "rocketmail.com", "hotmail.co.uk", "yahoo.co.uk"}

# bounce / tracking / delivery infrastructure: a Return-Path or link host here does not mean spoofing
ESP_DOMAINS = {
    "amazonses.com", "sendgrid.net", "sendgrid.com", "mailchimp.com", "mcsv.net", "mcdlv.net", "rsgsv.net", "mandrillapp.com",
    "mailgun.org", "mailgun.net", "sparkpostmail.com", "sparkpostmail1.com", "postmarkapp.com", "pm-bounces.com",
    "constantcontact.com", "cmail19.com", "cmail20.com", "createsend.com", "salesforce.com", "exacttarget.com", "marketo.com",
    "mktomail.com", "mktdns.com", "hubspotemail.net", "hs-sites.com", "sendinblue.com", "sendibm1.com", "sendibm2.com",
    "sendibm3.com", "brevo.com", "mailjet.com", "mailjet-mail.com", "mimecast.com", "pphosted.com", "protection.outlook.com",
    "zendesk.com", "intercom-mail.com", "intercom.io", "eventbrite.com", "facebookmail.com", "linkedin.com", "list-manage.com",
    "campaign-archive.com", "campaignmonitor.com", "customeriomail.com", "customer.io", "klaviyomail.com", "klaviyo.com",
    "mailerlite.com", "mlsend.com", "emltrk.com", "ccsend.com", "rs6.net", "ytmail.com", "bnc.salesforce.com", "e2ma.net",
    "responsys.net", "eloqua.com", "elqtrk.com", "wetransfer.com", "substack.com", "convertkit.com", "kit.com", "beehiiv.com",
    "googlegroups.com", "mailchi.mp", "t.co", "mail.beehiiv.com", "email.mg.substack.com", "sailthru.com", "braze.com",
    "iterable.com", "iterable.net", "mailtrack.io",
    # link-rewriting security gateways
    "safelinks.protection.outlook.com", "urldefense.com", "urldefense.proofpoint.com", "mimecast.com", "linkprotect.cudasvc.com",
    "barracudanetworks.com", "l.facebook.com", "lnkd.in",
}


def is_esp(host: str) -> bool:
    """True if the host (or its registered domain) is mail-delivery / click-tracking / link-protection infrastructure."""
    h = (host or "").lower().strip(".")
    return bool(h) and any(h == d or h.endswith("." + d) for d in ESP_DOMAINS)

SUPPORT_WORDS = {"support", "team", "security", "service", "services", "account", "billing", "notification", "notifications",
                 "alert", "alerts", "helpdesk", "help", "admin", "administrator", "noreply", "reply", "verification", "verify",
                 "update", "updates", "order", "orders", "delivery", "payment", "payments", "invoice", "invoices", "customer",
                 "care", "online", "login", "signin", "wallet", "refund", "tracking", "shipping", "department", "center",
                 "centre", "mail", "official", "inc", "corp", "com", "ltd", "llc", "co"}

_MINI_BRANDS: Dict[str, Set[str]] = {
    "paypal": {"paypal.com"}, "microsoft": {"microsoft.com", "outlook.com", "live.com", "office.com"},
    "apple": {"apple.com", "icloud.com"}, "amazon": {"amazon.com"}, "google": {"google.com", "gmail.com"},
    "netflix": {"netflix.com"}, "dhl": {"dhl.com"}, "fedex": {"fedex.com"}, "docusign": {"docusign.com", "docusign.net"},
}
_COMMON_TLDS = {"com", "net", "org", "edu", "gov", "mil", "int", "io", "co", "us", "uk", "de", "fr", "ru", "cn", "info", "biz",
                "me", "tv", "ly", "app", "dev", "xyz", "top", "online", "site", "shop", "ca", "au", "in", "jp", "br", "es", "it",
                "nl", "se", "ch", "pl", "at", "be", "dk", "no", "fi", "ie", "nz", "za", "mx", "ar", "cl", "kr", "tw", "hk", "sg",
                "cc", "pw", "ws", "to", "tk", "ml", "ga", "cf", "gq", "link", "click", "club", "live", "store", "tech", "cloud",
                "email", "ai", "eu", "gl", "page", "website", "space", "icu", "vip", "bank"}

_PWD_HINT = re.compile(r"(?i)\b(?:pass(?:word|code|wd)?|pw|kennwort|contrase[ñn]a|mot de passe)\b\s*(?:is|are|for\s+\w+\s+is|:|=|-)?\s*[:=\"'“]?\s*[A-Za-z0-9!@#$%^&*._-]{3,24}")

# =========================================================================== helpers (domains, headers)


def _urlcheck():
    try:
        from aegis.tools import urlcheck  # imported lazily: optional sibling module

        return urlcheck
    except Exception:  # pragma: no cover - module missing
        return None


def registered_domain(host: str) -> str:
    """eTLD+1 of a host name (uses aegis.tools.urlcheck when available, otherwise a small fallback)."""
    host = (host or "").lower().strip().strip(".")
    uc = _urlcheck()
    if uc and hasattr(uc, "registered_domain"):
        try:
            return uc.registered_domain(host)
        except Exception:
            pass
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in {"co.uk", "org.uk", "ac.uk", "com.au", "co.nz", "co.jp", "com.br", "co.in"}:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def _brands() -> Dict[str, Set[str]]:
    uc = _urlcheck()
    b = getattr(uc, "BRANDS", None) if uc else None
    return b if isinstance(b, dict) and b else _MINI_BRANDS


def _decode(value: str) -> str:
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def header_value(msg: Message, name: str) -> str:
    try:
        v = msg.get(name)
    except Exception:
        v = None
    return "" if v is None else _decode(str(v)).replace("\r", " ").replace("\n", " ").strip()


def split_address(value: str) -> Tuple[str, str, str]:
    """(display name, address, domain) of an address header value."""
    name, addr = parseaddr(value or "")
    name = _decode(name).strip().strip('"')
    addr = addr.strip().strip("<>").lower()
    domain = addr.rsplit("@", 1)[-1] if "@" in addr else ""
    return name, addr, domain


_AUTH_RX = re.compile(r"\b(spf|dkim|dmarc|compauth)\s*=\s*([a-z]+)", re.I)


def parse_authentication(msg: Message) -> Dict[str, str]:
    """Results of the *first* (= receiving server's) Authentication-Results header, plus Received-SPF."""
    res: Dict[str, str] = {}
    try:
        vals = msg.get_all("Authentication-Results") or []
    except Exception:
        vals = []
    if vals:
        for m in _AUTH_RX.finditer(str(vals[0])):
            res.setdefault(m.group(1).lower(), m.group(2).lower())
    if "spf" not in res:
        rspf = header_value(msg, "Received-SPF")
        m = re.match(r"(?i)\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b", rspf)
        if m:
            res["spf"] = m.group(1).lower()
    return res


@dataclass
class Issue:
    rule: str
    title: str
    severity: Severity
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    mitre: List[str] = field(default_factory=list)
    recommendation: str = ""


def analyse_headers(msg: Message, signatures: Any = None) -> List[Issue]:
    """Sender-spoofing indicators of one message (pure; the only I/O is the optional URL reputation heuristics)."""
    issues: List[Issue] = []
    from_name, from_addr, from_dom = split_address(header_value(msg, "From"))
    _rn, rp_addr, rp_dom = split_address(header_value(msg, "Return-Path"))
    _rtn, rt_addr, rt_dom = split_address(header_value(msg, "Reply-To"))
    from_reg = registered_domain(from_dom) if from_dom else ""
    auth = parse_authentication(msg)

    # ---- failed e-mail authentication
    bad = {k: v for k, v in auth.items() if (k == "spf" and v in ("fail", "softfail", "permerror")) or
           (k in ("dkim", "dmarc") and v in ("fail", "permerror")) or (k == "compauth" and v == "fail")}
    if bad:
        hard = auth.get("dmarc") == "fail" or (auth.get("spf") == "fail" and auth.get("dkim") in ("fail", "permerror", "none", None)) \
            or auth.get("compauth") == "fail"
        sev = Severity.MEDIUM if hard else Severity.LOW
        what = ", ".join(f"{k.upper()} {v}" for k, v in sorted(bad.items()))
        issues.append(Issue(
            "AEG-EMAIL-AUTH", "Sender authentication failed (SPF/DKIM/DMARC)", sev,
            f"The receiving mail server recorded: {what}. SPF, DKIM and DMARC are the checks that prove a message really came "
            f"from the domain it claims ({from_dom or 'unknown'}); a failure means the 'From' address may be forged.",
            {"results": auth, "from_domain": from_dom}, ["T1566", "T1684.001"],
            "Do not click links or open attachments unless you can confirm with the sender through another channel."))

    # ---- header mismatches
    mism: List[str] = []
    ev: Dict[str, Any] = {"from": from_addr, "return_path": rp_addr, "reply_to": rt_addr}
    if from_reg and rp_dom:
        rp_reg = registered_domain(rp_dom)
        if rp_reg != from_reg and rp_reg and not is_esp(rp_dom) and not is_esp(from_dom):
            mism.append(f"the bounce address (Return-Path) belongs to {rp_reg}, not {from_reg}")
    freemail_reply = False
    if from_reg and rt_dom:
        rt_reg = registered_domain(rt_dom)
        if rt_reg != from_reg and not (is_esp(rt_dom) and rt_reg not in FREEMAIL):
            freemail_reply = rt_reg in FREEMAIL and from_reg not in FREEMAIL
            mism.append(f"replies would go to {rt_reg}, not {from_reg}" + (" (a free webmail account)" if freemail_reply else ""))
    if mism:
        sev = Severity.MEDIUM if (len(mism) >= 2 or freemail_reply) else Severity.LOW
        issues.append(Issue(
            "AEG-EMAIL-MISMATCH", "Sender addresses do not match", sev,
            "The message header is inconsistent: " + "; ".join(mism) + ". Phishing often forges the visible 'From' address "
            "while the real sender or reply address is different.", ev, ["T1566", "T1684.001"],
            "Check the sender's real address and be careful with anything that asks for passwords, payments or downloads."))

    # ---- display-name impersonation
    brands = _brands()
    if from_name:
        imp = _impersonated_brand(from_name, from_reg, brands)
        shown = re.search(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)", from_name)
        if imp:
            issues.append(Issue(
                "AEG-EMAIL-IMPERSONATE", f"Sender name imitates {imp.title()} but the address is {from_dom or 'unknown'}", Severity.MEDIUM,
                f"The sender calls itself '{from_name}' but the message was sent from {from_dom or 'an unknown domain'}, which is "
                f"not a {imp.title()} domain. Brand impersonation is the most common phishing technique.",
                {"display_name": from_name, "from": from_addr, "brand": imp}, ["T1566", "T1684.001"],
                f"Do not follow links in this message; go to {imp.title()}'s website by typing the address yourself."))
        elif shown and registered_domain(shown.group(1)) != from_reg:
            issues.append(Issue(
                "AEG-EMAIL-IMPERSONATE", "Sender name shows a different e-mail address than the real one", Severity.MEDIUM,
                f"The display name contains the address {shown.group(0)!r}, but the message really comes from {from_addr}. "
                "Mail programs often show only the name, so this makes a forged sender look genuine.",
                {"display_name": from_name, "from": from_addr}, ["T1566", "T1684.001"],
                "Check the real sender address before trusting the message."))

    # ---- look-alike / known-bad sender domain
    if from_dom:
        bad_dom = False
        try:
            bad_dom = bool(signatures and signatures.is_bad_domain(from_dom))
        except Exception:
            bad_dom = False
        if bad_dom:
            issues.append(Issue("AEG-EMAIL-IMPERSONATE", f"Sender domain {from_dom} is on a malicious-domain list", Severity.HIGH,
                                f"{from_dom} appears in the threat database of known malicious domains.", {"from_domain": from_dom},
                                ["T1566"], "Delete the message; do not open attachments or links."))
        else:
            uc = _urlcheck()
            if uc:
                try:
                    r = uc.check_url(f"https://{from_dom}/", signatures)
                except Exception:
                    r = None
                if r and r.get("verdict") in ("suspicious", "malicious") and any(
                        k in " ".join(r.get("reasons", [])).lower() for k in ("looks like", "typosquat", "homoglyph", "punycode",
                                                                              "not an official", "imitate", "malicious")):
                    issues.append(Issue(
                        "AEG-EMAIL-IMPERSONATE", f"Sender domain {from_dom} looks like a fake of a well-known site",
                        Severity.HIGH if r["verdict"] == "malicious" else Severity.MEDIUM,
                        f"The sender's domain {from_dom} raised URL-reputation warnings: " + "; ".join(r["reasons"][:3]) + ".",
                        {"from_domain": from_dom, "score": r.get("score"), "reasons": r.get("reasons", [])[:5]}, ["T1566", "T1583.001"],
                        "Delete the message; do not open attachments or links."))
    return issues


def _impersonated_brand(display_name: str, from_reg: str, brands: Dict[str, Set[str]]) -> Optional[str]:
    low = display_name.lower()
    toks = [t for t in re.split(r"[^a-z0-9]+", low) if t]
    squashed = re.sub(r"[^a-z0-9]", "", low)
    for brand, legit in brands.items():
        hit = brand in toks or (len(brand) >= 6 and brand in squashed)
        if not hit:
            continue
        others = [t for t in toks if t != brand]
        # "Apple Pie Recipes" is not impersonation, "Apple Support", "PayPal" and "Microsoft Account Team" are
        if others and not any(t in SUPPORT_WORDS for t in others):
            continue
        if from_reg and from_reg in legit:
            return None
        if from_reg and any(from_reg == registered_domain(d) for d in legit):
            return None
        return brand
    return None


# =========================================================================== links


class _PageParser(HTMLParser):
    """Collects anchors (href + visible text), forms and password inputs from an HTML body."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.anchors: List[Tuple[str, str]] = []
        self.forms: List[str] = []
        self.password_input = False
        self._href: Optional[str] = None
        self._text: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        a = dict(attrs)
        if tag == "a":
            self._flush()
            self._href, self._text = (a.get("href") or "").strip(), []
        elif tag == "form":
            self.forms.append((a.get("action") or "").strip())
        elif tag == "input" and (a.get("type") or "").lower() == "password":
            self.password_input = True

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a":
            self._flush()

    def _flush(self) -> None:
        if self._href is not None:
            self.anchors.append((self._href, " ".join("".join(self._text).split())))
        self._href, self._text = None, []

    def close(self) -> None:
        super().close()
        self._flush()


def parse_html(html: str) -> _PageParser:
    p = _PageParser()
    try:
        p.feed(html[:2_000_000])
        p.close()
    except Exception:  # malformed HTML is normal in spam
        pass
    return p


_TEXT_DOMAIN = re.compile(r"(?i)^\s*(?:https?://)?(?:www\.)?([a-z0-9][a-z0-9\-]*(?:\.[a-z0-9\-]+)*\.([a-z]{2,10}))(?:[/:?#]\S*)?\s*$")
_URL_RX = re.compile(r"(?i)\bhttps?://[^\s<>\"'\)\]]{4,300}")


def host_of(url: str) -> str:
    m = re.match(r"(?i)^\s*(?:https?://)?(?:[^/@\s]*@)?([^/:?#\s]+)", url or "")
    return m.group(1).lower().strip(".") if m else ""


def link_text_domain(text: str) -> str:
    """Domain shown by an anchor's visible text, or '' if the text does not look like an address."""
    m = _TEXT_DOMAIN.match(text or "")
    if not m or m.group(2).lower() not in _COMMON_TLDS:
        return ""
    return m.group(1).lower()


def analyse_links(anchors: Sequence[Tuple[str, str]], text_urls: Sequence[str] = (), signatures: Any = None) -> List[Issue]:
    """Deceptive / malicious links (anchors are (href, visible text))."""
    issues: List[Issue] = []
    brands = _brands()
    brand_domains: Dict[str, str] = {}
    for brand, doms in brands.items():
        for d in doms:
            brand_domains.setdefault(registered_domain(d), brand)
    uc = _urlcheck()
    checked: Dict[str, Dict[str, Any]] = {}

    def verdict(url: str) -> Dict[str, Any]:
        if url not in checked:
            try:
                checked[url] = uc.check_url(url, signatures) if uc else {}
            except Exception:
                checked[url] = {}
        return checked[url]

    mism: List[Dict[str, str]] = []
    brand_hits: List[Dict[str, str]] = []
    for href, text in list(anchors)[:MAX_LINKS * 4]:
        if not re.match(r"(?i)^\s*https?://", href or ""):
            continue
        shown = link_text_domain(text)
        if not shown:
            continue
        real_host = host_of(href)
        real_reg, shown_reg = registered_domain(real_host), registered_domain(shown)
        if not real_reg or real_reg == shown_reg or is_esp(real_host):
            continue
        item = {"text": text[:120], "href": href[:300], "shown_domain": shown_reg, "real_domain": real_reg}
        if shown_reg in brand_domains and real_reg not in brands.get(brand_domains[shown_reg], set()):
            item["brand"] = brand_domains[shown_reg]
            brand_hits.append(item)
        else:
            mism.append(item)
    if brand_hits:
        b = brand_hits[0]
        issues.append(Issue(
            "AEG-EMAIL-LINK-MISMATCH", f"A link says {b['shown_domain']} but really goes to {b['real_domain']}", Severity.HIGH,
            f"{len(brand_hits)} link(s) show the address of a well-known site as their text but lead to a different website "
            f"(for example the text '{b['text']}' opens {b['href'][:100]}). This is the standard way phishing pages are disguised.",
            {"links": brand_hits[:5]}, ["T1566.002"], "Do not click it. Open the real website by typing its address yourself."))
    if mism:
        sus = [m for m in mism if verdict(m["href"]).get("verdict") in ("suspicious", "malicious")]
        sev = Severity.MEDIUM if sus else Severity.LOW
        issues.append(Issue(
            "AEG-EMAIL-LINK-MISMATCH", "Link text shows a different website than the link target", sev,
            f"{len(mism)} link(s) display one website address but open another"
            + (" - and the real destination also looks suspicious" if sus else " (often just click-tracking, but also how phishing hides its destination)") + ".",
            {"links": mism[:5]}, ["T1566.002"], "Hover over links to see the real address before clicking."))

    # reputation of every distinct URL (anchors + plain text)
    urls: List[str] = []
    for href, _t in anchors:
        if re.match(r"(?i)^\s*https?://", href or ""):
            urls.append(href.strip())
    urls += list(text_urls)
    seen: Set[str] = set()
    malicious: List[Dict[str, Any]] = []
    suspicious: List[Dict[str, Any]] = []
    for u in urls:
        if u in seen:
            continue
        seen.add(u)
        if len(seen) > MAX_LINKS:
            break
        r = verdict(u)
        if r.get("verdict") == "malicious":
            malicious.append({"url": u[:300], "score": r.get("score"), "reasons": r.get("reasons", [])[:3]})
        elif r.get("verdict") == "suspicious":
            suspicious.append({"url": u[:300], "score": r.get("score"), "reasons": r.get("reasons", [])[:3]})
    for m in malicious[:5]:
        issues.append(Issue(
            "AEG-EMAIL-LINK-BAD", "Message contains a link that looks malicious", Severity.HIGH,
            f"The link {m['url'][:120]} scored as malicious: " + "; ".join(m["reasons"]) + ".", m, ["T1566.002"],
            "Do not click it. Delete the message and, if you already clicked, run a full scan and change passwords."))
    if suspicious and not malicious:
        issues.append(Issue(
            "AEG-EMAIL-LINK-SUSPECT", f"{len(suspicious)} suspicious link(s) in the message", Severity.LOW,
            "Some links have traits common in phishing (URL shorteners, look-alike or risky domains): "
            + "; ".join(f"{s['url'][:60]} ({s['reasons'][0] if s['reasons'] else 'suspicious'})" for s in suspicious[:3]) + ".",
            {"links": suspicious[:5]}, ["T1566.002"], "Check where a link really goes before opening it."))
    return issues


# =========================================================================== attachment content checks (pure)

def encrypted_archive_info(data: bytes, ext: str) -> Optional[str]:
    """Description if the data is a password-protected zip / 7z / rar archive, else None."""
    head = data[:8]
    try:
        if head[:4] == b"PK\x03\x04" and ext not in fa.OFFICE_EXTS and ext not in ("jar", "apk", "xpi", "crx"):
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                enc = [i.filename for i in zf.infolist() if i.flag_bits & 0x1]
                if enc:
                    return f"password-protected ZIP ({len(enc)} encrypted file(s): {', '.join(enc[:3])})"
        elif head[:6] == b"7z\xbc\xaf\x27\x1c":
            if b"\x06\xf1\x07\x01" in data[-8192:]:
                return "password-protected 7-Zip archive"
        elif head[:7] == b"Rar!\x1a\x07\x00":  # RAR 4: archive header flag MHD_PASSWORD (0x80) = encrypted headers
            if len(data) > 12 and data[9] == 0x73 and (struct.unpack_from("<H", data, 10)[0] & 0x0080):
                return "password-protected RAR archive (encrypted file list)"
        elif head[:8] == b"Rar!\x1a\x07\x01\x00":  # RAR 5: header type 4 = archive encryption header
            pos = 8 + 4
            size, shift = 0, 0
            while pos < len(data) and shift < 35:  # skip the header-size vint
                b = data[pos]
                pos += 1
                size |= (b & 0x7F) << shift
                shift += 7
                if not b & 0x80:
                    break
            if pos < len(data) and data[pos] == 4:
                return "password-protected RAR archive (encrypted file list)"
    except (zipfile.BadZipFile, struct.error, IndexError, RuntimeError, OSError):
        return None
    return None


_ISO_NAMES = re.compile(rb"(?i)([A-Za-z0-9_\-~$ ]{1,40}\.(?:exe|dll|lnk|bat|cmd|vbs|js|hta|scr|ps1|wsf|cpl|msi))(?:;1)?")


def disk_image_listing(data: bytes) -> List[str]:
    """Names of programs/shortcuts visible in an ISO/IMG (ISO9660/Joliet directory records are ASCII or UTF-16BE)."""
    sample = data[:48 * 1024 * 1024]
    names: List[str] = []
    for blob in (sample, sample.replace(b"\x00", b"")):
        for m in _ISO_NAMES.finditer(blob):
            n = m.group(1).decode("latin-1").strip()
            if n.lower() not in (x.lower() for x in names):
                names.append(n)
            if len(names) >= 12:
                return names
    return names


_ONE_SCRIPT = re.compile(rb"(?i)(wscript\.shell|mshta|powershell(?:\.exe)?\s+-|cmd(?:\.exe)?\s+/c|createobject\s*\(|\.hta\b|\.vbs\b|\.wsf\b|\.cmd\b|\.bat\b|regsvr32|rundll32|urldownloadtofile)")


def onenote_indicators(data: bytes) -> List[str]:
    out: List[str] = []
    if b"This program cannot be run in DOS mode" in data:
        out.append("an embedded Windows program")
    flat = data.replace(b"\x00", b"")
    m = _ONE_SCRIPT.search(data) or _ONE_SCRIPT.search(flat)
    if m:
        out.append("embedded script / command text (" + m.group(0).decode("latin-1")[:40] + ")")
    return out


def html_indicators(text: str) -> List[Tuple[str, str, Severity, str, List[str]]]:
    """(rule, title, severity, explanation, mitre) for an HTML attachment/body."""
    out: List[Tuple[str, str, Severity, str, List[str]]] = []
    if re.search(r"atob\s*\(", text) and re.search(r"new\s+Blob|msSaveOrOpenBlob|createObjectURL|\bBlob\s*\(", text):
        out.append(("AEG-EMAIL-HTMLSMUGGLE", "HTML smuggling: the page builds and saves a file by itself", Severity.HIGH,
                    "The page decodes a hidden payload with JavaScript and saves it as a file on your computer, so no malicious file "
                    "ever crosses the mail filter. This is a technique used to deliver malware loaders.", ["T1027.006", "T1204.002"]))
    page = parse_html(text)
    if page.password_input:
        out.append(("AEG-EMAIL-PHISHFORM", "HTML page asks for a password", Severity.MEDIUM,
                    "The page contains a password field. Attachments that are web pages with a login form are a common way to "
                    "steal passwords because the fake page is stored locally and not on a website that can be blocked.",
                    ["T1566.001", "T1056.003"]))
    return out


# =========================================================================== message analysis


@dataclass
class MsgInfo:
    subject: str = ""
    sender: str = ""
    date: str = ""


@dataclass
class Scope:
    """Shared by one analysed message tree."""

    ctx: ScanContext
    location: str  # display location of the top-level message
    container: str  # file whose quarantine would remove the threat ("" = do not offer quarantine)
    findings: List[Finding] = field(default_factory=list)
    attachments: int = 0
    messages: int = 0


def _meta(msg: Message) -> MsgInfo:
    return MsgInfo(subject=header_value(msg, "Subject")[:150], sender=header_value(msg, "From")[:150], date=header_value(msg, "Date")[:60])


def clean_filename(name: str) -> str:
    name = re.split(r"[\\/]", name or "")[-1]
    return "".join(ch for ch in name if ch >= " " and ch != "\x7f")[:200]


def _part_text(part: Message) -> str:
    try:
        payload = part.get_payload(decode=True)
    except Exception:
        payload = None
    if payload is None:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, "replace")
    except LookupError:
        return payload.decode("utf-8", "replace")


def _walk_message(msg: Message) -> Iterator[Tuple[str, Message]]:
    """Yield ('body'|'attachment'|'message', part). Nested message/rfc822 parts are yielded as 'message' and not flattened."""
    stack = [msg]
    while stack:
        part = stack.pop(0)
        ctype = part.get_content_type()
        if ctype == "message/rfc822" and part is not msg:
            yield "message", part
            continue
        if part.is_multipart():
            subs = part.get_payload()
            if isinstance(subs, list):
                stack = [s for s in subs if isinstance(s, Message)] + stack
            continue
        fname = ""
        try:
            fname = part.get_filename() or ""
        except Exception:
            fname = ""
        disp = (part.get_content_disposition() or "") if hasattr(part, "get_content_disposition") else ""
        if fname or disp == "attachment" or (ctype not in ("text/plain", "text/html") and not ctype.startswith("multipart/")):
            yield "attachment", part
        else:
            yield "body", part


def _mk(rule: str, title: str, sev: Severity, cat: str, desc: str, location: str, meta: MsgInfo, evidence: Dict[str, Any],
        rec: str, mitre: List[str], remediation: Optional[Remediation] = None) -> Finding:
    ev = {"email_subject": meta.subject, "email_from": meta.sender}
    ev.update(evidence)
    return Finding(rule, title, sev, cat, desc, location, ev, rec, remediation, mitre=mitre)


def _remedy(scope: Scope, desc: str) -> Optional[Remediation]:
    if scope.container:
        return Remediation("quarantine_file", {"path": scope.container}, desc)
    return None


def analyse_attachment(scope: Scope, name: str, ctype: str, data: bytes, meta: MsgInfo, location: str, body_text: str) -> List[Finding]:
    ctx = scope.ctx
    out: List[Finding] = []
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    sha = ""
    # ---- content analysis (hashes, YARA, PE/script/Office heuristics, zip members)
    try:
        sub = analyse_bytes(ctx, Path(scope.container or name), data, ext, location, depth=1)
    except Exception as exc:  # pragma: no cover - defensive
        log.debug("analyse_bytes failed for %s: %s", location, exc)
        sub = []
    for f in sub:
        f.evidence.setdefault("email_subject", meta.subject)
        f.evidence.setdefault("email_from", meta.sender)
        sha = sha or str(f.evidence.get("sha256", ""))
        f.remediation = _remedy(scope, "Move the message file containing the attachment to quarantine")
        out.append(f)
    good_flag = any(f.severity >= Severity.HIGH for f in sub)

    # ---- dangerous type
    if ext in DANGEROUS_TYPES:
        sev, why = DANGEROUS_TYPES[ext]
        extra: Dict[str, Any] = {}
        reasons: List[str] = []
        if ext in ("iso", "img", "vhd", "vhdx"):
            listing = disk_image_listing(data)
            if listing:
                extra["contains"] = listing
                lows = " ".join(listing).lower()
                if ".lnk" in lows or ".exe" in lows or ".dll" in lows or ".bat" in lows or ".cmd" in lows or ".hta" in lows:
                    sev = Severity.HIGH
                    reasons.append("it contains programs/shortcuts: " + ", ".join(listing[:4]))
        elif ext == "one":
            ind = onenote_indicators(data)
            if ind:
                sev = Severity.HIGH
                extra["indicators"] = ind
                reasons.append("it contains " + " and ".join(ind))
        elif ext in ("lnk",):
            lnk = fa.lnk_indicators(data) + [i for i in fa.content_indicators(data, "lnk") if i.score > 0]
            if any(i.severity >= Severity.MEDIUM for i in lnk):
                sev = Severity.HIGH
                reasons.append("the shortcut launches a command interpreter / LOLBin")
        elif ext in ("html", "htm", "shtml", "xhtml", "svg"):
            text = data.decode("utf-8", "replace")
            for rule, title, hsev, expl, hm in html_indicators(text):
                out.append(_mk(rule, title, hsev, Category.SUSPICIOUS, f"{name}: {expl}", location, meta, {"attachment": name},
                               "Do not open the attachment; delete the message.", hm, _remedy(scope, "Quarantine the message file")))
            sev = Severity.LOW
        elif ext in ("chm",):
            if any(i.severity >= Severity.MEDIUM for i in fa.content_indicators(data, "text")):
                sev = Severity.HIGH
                reasons.append("its content contains script-launching code")
        if not (good_flag and sev < Severity.HIGH):  # content analysis already raised the alarm; keep the type note concise
            out.append(_mk(
                "AEG-EMAIL-DANGEROUS", f"Risky attachment type (.{ext}): {name}", sev, Category.SUSPICIOUS,
                f"The message carries '{name}', {why}. Attackers send this type of file because it can run code or avoid "
                "security warnings." + (" Flagged more strongly because " + "; ".join(reasons) + "." if reasons else ""),
                location, meta, {"attachment": name, "extension": ext, "content_type": ctype, "size": len(data), "sha256": sha, **extra},
                "Do not open it. Confirm with the sender (by phone or a new message) that they sent it; delete the message otherwise.",
                ["T1566.001", "T1204.002"], _remedy(scope, "Move the message file containing the attachment to quarantine") if sev >= Severity.MEDIUM else None))

    # ---- password-protected archives
    enc = encrypted_archive_info(data, ext)
    if enc:
        hinted = bool(_PWD_HINT.search(body_text or ""))
        out.append(_mk(
            "AEG-EMAIL-ENCRYPTED", f"Password-protected archive attached: {name}", Severity.HIGH if hinted else Severity.MEDIUM,
            Category.SUSPICIOUS,
            f"'{name}' is a {enc}. Malware is routinely sent in password-protected archives because mail scanners and antivirus "
            "cannot look inside." + (" The message body also gives the password, a typical malspam pattern." if hinted else ""),
            location, meta, {"attachment": name, "archive": enc, "password_in_body": hinted, "size": len(data)},
            "Do not open it unless you expected exactly this file from this sender. Aegis cannot inspect the contents.",
            ["T1027.013", "T1566.001"], _remedy(scope, "Move the message file containing the attachment to quarantine")))
    return out


def analyse_message(msg: Message, scope: Scope, location: str, depth: int = 0) -> None:
    """Analyse one message (headers, links, attachments, nested messages) and append findings to ``scope.findings``."""
    ctx = scope.ctx
    scope.messages += 1
    meta = _meta(msg)
    # ---- collect bodies and attachments
    body_texts: List[str] = []
    html_bodies: List[str] = []
    attachments: List[Tuple[str, str, bytes]] = []
    nested: List[Message] = []
    for kind, part in _walk_message(msg):
        if kind == "body":
            text = _part_text(part)
            (html_bodies if part.get_content_type() == "text/html" else body_texts).append(text)
        elif kind == "message":
            inner = part.get_payload()
            if isinstance(inner, list) and inner and isinstance(inner[0], Message):
                nested.append(inner[0])
        else:
            try:
                data = part.get_payload(decode=True) or b""
            except Exception:
                data = b""
            try:
                raw_name = part.get_filename() or ""
            except Exception:
                raw_name = ""
            name = clean_filename(_decode(raw_name)) or ("attachment" + (("." + part.get_content_subtype()) if part.get_content_subtype() else ""))
            if len(data) > MAX_ATTACHMENT_BYTES:
                continue
            attachments.append((name, part.get_content_type(), data))
    body_all = "\n".join(body_texts + [re.sub(r"<[^>]+>", " ", h) for h in html_bodies])[:200000]

    # ---- headers (sender spoofing)
    issues: List[Issue] = []
    try:
        issues += analyse_headers(msg, ctx.signatures)
    except Exception as exc:  # pragma: no cover - defensive
        log.debug("header analysis failed: %s", exc)
    # ---- links
    anchors: List[Tuple[str, str]] = []
    for h in html_bodies:
        page = parse_html(h)
        anchors += page.anchors
        if page.password_input:
            for rule, title, sev, expl, hm in html_indicators(h):
                if rule == "AEG-EMAIL-PHISHFORM":
                    issues.append(Issue(rule, "Message body contains a password form", sev, expl, {}, hm,
                                        "Never type a password into a form inside an e-mail."))
    plain_urls = _URL_RX.findall("\n".join(body_texts))[:MAX_LINKS]
    try:
        issues += analyse_links(anchors, plain_urls, ctx.signatures)
    except Exception as exc:  # pragma: no cover - defensive
        log.debug("link analysis failed: %s", exc)
    risky_attachment = False
    for name, ctype, data in attachments:
        scope.attachments += 1
        ctx.bump("email_attachments")
        loc = f"{location}!{name}"
        fs = analyse_attachment(scope, name, ctype, data, meta, loc, body_all)
        risky_attachment = risky_attachment or any(f.severity >= Severity.MEDIUM for f in fs)
        scope.findings.extend(fs)
    for it in issues:
        sev = it.severity
        if risky_attachment and it.rule in ("AEG-EMAIL-AUTH", "AEG-EMAIL-MISMATCH", "AEG-EMAIL-IMPERSONATE") and sev < Severity.HIGH:
            sev = Severity(min(int(sev) + 1, int(Severity.HIGH)))  # a spoofed sender with a risky attachment is worse
        scope.findings.append(_mk(
            it.rule, it.title, sev, Category.SUSPICIOUS if it.rule != "AEG-EMAIL-LINK-BAD" else Category.MALWARE, it.description,
            location, meta, it.evidence, it.recommendation or "Be careful with this message.", it.mitre,
            _remedy(scope, "Move the message file to quarantine") if sev >= Severity.HIGH and it.rule == "AEG-EMAIL-LINK-BAD" else None))
    if depth < MAX_NESTING:
        for i, inner in enumerate(nested):
            analyse_message(inner, scope, f"{location}!{(_meta(inner).subject or 'forwarded message')[:50]}.eml", depth + 1)


def _parse(data: bytes) -> Optional[Message]:
    try:
        return BytesParser(policy=policy.default).parsebytes(data)
    except Exception as exc:
        log.debug("could not parse message: %s", exc)
        return None


def analyse_eml(path_or_bytes: Union[str, "os.PathLike[str]", bytes], ctx: ScanContext) -> List[Finding]:
    """Analyse one RFC 5322 message (a file path or the raw bytes). Never raises. Attachment findings have locations like
    ``message.eml!attachment.docm``; for a path, the quarantine remediation targets the .eml file."""
    try:
        if isinstance(path_or_bytes, (bytes, bytearray)):
            data, location, container = bytes(path_or_bytes), "<message>", ""
        else:
            p = Path(path_or_bytes)
            if p.stat().st_size > MAX_EML_BYTES:
                return []
            data, location, container = p.read_bytes(), str(p), str(p)
        msg = _parse(data)
        if msg is None:
            return []
        scope = Scope(ctx, location, container)
        analyse_message(msg, scope, location)
        # one finding per (rule, location); highest severity first
        seen: Dict[Tuple[str, str], Finding] = {}
        for f in scope.findings:
            k = (f.rule_id, f.location)
            if k not in seen or f.severity > seen[k].severity:
                seen[k] = f
        out = sorted(seen.values(), key=lambda f: -int(f.severity))
        ctx.bump("email_messages")
        return out[:MAX_FINDINGS_PER_MESSAGE]
    except Exception as exc:
        log.debug("analyse_eml failed: %s", exc)
        return []


# =========================================================================== mbox (Thunderbird)

def iter_mbox_messages(path: str, max_bytes: int = MAX_MBOX_BYTES, max_messages: int = MAX_MBOX_MESSAGES,
                       max_msg_bytes: int = MAX_MESSAGE_BYTES) -> Iterator[bytes]:
    """Stream the messages of an mbox file (newest ``max_bytes`` only). The 'From ' separator line is dropped."""
    count = 0
    with open(path, "rb") as fh:
        size = os.fstat(fh.fileno()).st_size
        prev_blank = True
        if size > max_bytes:
            fh.seek(size - max_bytes)
            fh.readline()
            prev_blank = False
        cur: List[bytes] = []
        cur_len = 0
        started = False
        oversize = False
        for line in fh:
            if line.startswith(b"From ") and (prev_blank or not started):
                if started and cur and not oversize:
                    yield b"".join(cur)
                    count += 1
                    if count >= max_messages:
                        return
                cur, cur_len, oversize, started = [], 0, False, True
                prev_blank = False
                continue
            if started and not oversize:
                cur.append(line)
                cur_len += len(line)
                if cur_len > max_msg_bytes:
                    oversize, cur = True, []
            prev_blank = line in (b"\n", b"\r\n")
        if started and cur and not oversize and count < max_messages:
            yield b"".join(cur)


def looks_like_mbox(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(5) == b"From "
    except OSError:
        return False


# =========================================================================== discovery

def thunderbird_profile_dirs() -> List[Path]:
    home = user_home()
    cands: List[Path] = []
    if IS_WINDOWS:
        a = env_path("APPDATA")
        if a:
            cands.append(a / "Thunderbird" / "Profiles")
    cands += [home / ".thunderbird", home / "Library" / "Thunderbird" / "Profiles",
              home / ".var" / "app" / "org.mozilla.Thunderbird" / ".thunderbird", home / "snap" / "thunderbird" / "common" / ".thunderbird"]
    out: List[Path] = []
    for c in cands:
        try:
            if c.is_dir():
                out += [p for p in sorted(c.iterdir()) if p.is_dir()]
        except OSError:
            continue
    return out


def discover_thunderbird_mbox(profiles: Optional[Sequence[Path]] = None, limit: int = 200) -> List[str]:
    files: List[str] = []
    for prof in (profiles if profiles is not None else thunderbird_profile_dirs()):
        for sub in ("Mail", "ImapMail"):
            base = Path(prof) / sub
            if not base.is_dir():
                continue
            for dirpath, _dirs, names in os.walk(base):
                for n in names:
                    if "." in n and n.rsplit(".", 1)[-1].lower() in ("msf", "dat", "json", "sqlite", "txt", "html", "ini", "log"):
                        continue
                    full = os.path.join(dirpath, n)
                    if looks_like_mbox(full):
                        files.append(full)
                        if len(files) >= limit:
                            return files
    return files


def outlook_cache_dirs() -> List[Path]:
    dirs: List[Path] = []
    la = env_path("LOCALAPPDATA")
    if la:
        dirs.append(la / "Microsoft" / "Windows" / "INetCache" / "Content.Outlook")
    try:
        for ver in reg_subkeys("HKCU", r"Software\Microsoft\Office"):
            if re.match(r"^\d+\.\d+$", ver):
                v = reg_read("HKCU", rf"Software\Microsoft\Office\{ver}\Outlook\Security", "OutlookSecureTempFolder")
                if v:
                    dirs.append(Path(os.path.expandvars(str(v))))
    except Exception:  # pragma: no cover - defensive
        pass
    seen: Set[str] = set()
    out: List[Path] = []
    for d in dirs:
        try:
            key = str(d).lower().rstrip("\\/")
            if key not in seen and d.is_dir():
                seen.add(key)
                out.append(d)
        except OSError:
            continue
    return out


def _is_narrow(p: Path) -> bool:
    try:
        parts = p.resolve().parts
    except OSError:
        return False
    return len(parts) > (2 if IS_WINDOWS else 1) and str(p.resolve()) != os.path.abspath(os.sep)


def eml_roots(ctx: ScanContext) -> List[Path]:
    home = user_home()
    roots = [home / "Downloads", home / "Documents", home / "Desktop"]
    roots += [p for p in ctx.paths if _is_narrow(p)]
    out: List[Path] = []
    seen: Set[str] = set()
    for r in roots:
        try:
            if r.is_dir() and str(r.resolve()).lower() not in seen:
                seen.add(str(r.resolve()).lower())
                out.append(r)
        except OSError:
            continue
    return out


def find_eml_files(roots: Iterable[Path], deadline: float, limit: int = MAX_EML_FILES, depth: int = WALK_DEPTH,
                   cancelled=lambda: False) -> List[str]:
    found: List[str] = []
    entries = 0
    seen: Set[str] = set()
    for root in roots:
        base = str(root).rstrip("\\/").count(os.sep)
        for dirpath, dirnames, names in os.walk(root, onerror=lambda e: None):
            entries += len(names) + 1
            if cancelled() or time.monotonic() > deadline or entries > MAX_WALK_ENTRIES or len(found) >= limit:
                return found
            if dirpath.rstrip("\\/").count(os.sep) - base >= depth:
                dirnames[:] = []
            dirnames[:] = [d for d in dirnames if d.lower() not in ("node_modules", ".git", "$recycle.bin", "windows", "appdata")]
            for n in names:
                if n.lower().endswith(".eml"):
                    full = os.path.join(dirpath, n)
                    if full not in seen:
                        seen.add(full)
                        found.append(full)
                        if len(found) >= limit:
                            return found
    return found


# =========================================================================== scanner


@register
class EmailScanner(Scanner):
    name = "email"
    title = "E-mail attachment & phishing review"
    description = ("Scans saved .eml messages, Outlook's attachment cache and Thunderbird mailboxes for malicious attachments, "
                   "spoofed senders and deceptive links.")
    platforms = ("windows", "linux", "darwin")

    def run(self, ctx: ScanContext) -> Iterator[Emitted]:
        budget = float(ctx.options.get("email_budget_s", 90) or 90)
        deadline = time.monotonic() + budget
        emls = ctx.options.get("email_eml_files")
        if emls is None:
            roots = [Path(p) for p in ctx.options["email_roots"]] if ctx.options.get("email_roots") else eml_roots(ctx)
            ctx.report(self.name, "looking for saved e-mail messages")
            emls = find_eml_files(roots, deadline, cancelled=lambda: ctx.cancelled)
        mboxes = ctx.options.get("email_mbox_files")
        if mboxes is None:
            try:
                mboxes = discover_thunderbird_mbox()
            except Exception as exc:  # pragma: no cover - defensive
                log.debug("thunderbird discovery failed: %s", exc)
                mboxes = []
        outlook = ctx.options.get("email_outlook_dirs")
        if outlook is None:
            try:
                outlook = [str(d) for d in outlook_cache_dirs()] if IS_WINDOWS else []
            except Exception as exc:  # pragma: no cover - defensive
                log.debug("outlook discovery failed: %s", exc)
                outlook = []
        if not (emls or mboxes or outlook):
            yield CheckResult("AEG-EMAIL-SCAN", "Saved e-mail review", CheckStatus.SKIP,
                              "No saved .eml messages, Thunderbird mailboxes or Outlook attachment cache were found.", Category.SUSPICIOUS)
            return
        msgs = atts = 0
        bad = 0
        emitted = 0

        def emit(fs: Iterable[Finding]) -> Iterator[Finding]:
            nonlocal bad, emitted
            for f in fs:
                emitted += 1
                if f.severity >= Severity.MEDIUM:
                    bad += 1
                yield f

        # ---- .eml files
        for path in emls:
            if ctx.cancelled or time.monotonic() > deadline:
                break
            ctx.report(self.name, f"reading {os.path.basename(path)}")
            before = ctx.stats.get("email_attachments", 0)
            fs = analyse_eml(path, ctx)
            msgs += 1
            atts += ctx.stats.get("email_attachments", 0) - before
            yield from emit(fs)

        # ---- Thunderbird mailboxes (attachments are not extracted to disk, so findings point at the mailbox file)
        for mb in mboxes:
            if ctx.cancelled or time.monotonic() > deadline:
                break
            ctx.report(self.name, f"reading mailbox {os.path.basename(mb)}")
            try:
                for i, raw in enumerate(iter_mbox_messages(mb)):
                    if ctx.cancelled or time.monotonic() > deadline:
                        break
                    msg = _parse(raw)
                    if msg is None:
                        continue
                    scope = Scope(ctx, f"{mb}#{i + 1}", "")  # never offer to quarantine a whole mailbox
                    before = ctx.stats.get("email_attachments", 0)
                    analyse_message(msg, scope, f"{mb}#{i + 1}")
                    atts += ctx.stats.get("email_attachments", 0) - before
                    msgs += 1
                    yield from emit(scope.findings[:MAX_FINDINGS_PER_MESSAGE])
            except OSError as exc:
                log.debug("cannot read mailbox %s: %s", mb, exc)

        # ---- Outlook attachment cache: files that were opened from messages
        opened = 0
        for d in outlook:
            if ctx.cancelled or time.monotonic() > deadline:
                break
            for dirpath, dirnames, names in os.walk(d):
                if dirpath[len(str(d)):].count(os.sep) >= 3:
                    dirnames[:] = []
                for n in names:
                    if ctx.cancelled or opened >= 300 or time.monotonic() > deadline:
                        break
                    opened += 1
                    full = Path(dirpath) / n
                    ext = n.rsplit(".", 1)[-1].lower() if "." in n else ""
                    try:
                        fs = scan_file(ctx, full)
                    except Exception as exc:  # pragma: no cover - defensive
                        log.debug("scan_file failed for %s: %s", full, exc)
                        fs = []
                    for f in fs:
                        f.evidence.setdefault("source", "Outlook attachment cache")
                    yield from emit(fs)
                    if ext in DANGEROUS_TYPES and DANGEROUS_TYPES[ext][0] >= Severity.HIGH:
                        why = DANGEROUS_TYPES[ext][1]
                        yield from emit([Finding(
                            "AEG-EMAIL-OPENED", f"A risky file was opened from an e-mail: {n}", Severity.HIGH, Category.SUSPICIOUS,
                            f"Outlook's attachment cache holds '{n}' ({why}). Files appear here when an attachment is opened, so "
                            "this program or script may already have run on your PC. Outlook normally blocks these types, so it "
                            "may also have come inside an archive.",
                            str(full), {"extension": ext, "source": "Outlook attachment cache"},
                            "If you did not intend to open it, run a full scan, check startup items, and change your passwords.",
                            Remediation("quarantine_file", {"path": str(full)}, "Move the file to quarantine"),
                            mitre=["T1204.002", "T1566.001"])])
                    atts += 1
        ctx.bump("email_messages_reviewed", msgs)
        yield CheckResult(
            "AEG-EMAIL-SCAN", "No malicious attachments, spoofed senders or deceptive links in saved e-mail",
            CheckStatus.FAIL if bad else CheckStatus.PASS,
            f"{msgs} message(s) and {atts} attachment(s) reviewed ({len(emls)} .eml file(s), {len(mboxes)} mailbox file(s), "
            f"{opened} Outlook-cache file(s)); {bad} finding(s) of medium severity or higher.", Category.SUSPICIOUS)
