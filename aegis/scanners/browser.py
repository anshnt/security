"""Browser hygiene scanner: malicious / risky extensions, search-engine and
homepage hijacks, forced-install policies (the ChromeLoader / adware trick),
disabled Safe Browsing, notification spam, rogue proxies and stored passwords.

Chromium family (Chrome, Edge, Brave, Vivaldi, Opera, Opera GX, Chromium,
Yandex, Arc) and Firefox family (Firefox, LibreWolf, Waterfox) are covered on
Windows, Linux and macOS. Profile discovery takes a base directory so it can be
tested against fake trees. Saved passwords are only ever *counted*."""

from __future__ import annotations

import configparser
import datetime as dt
import json
import logging
import os
import plistlib
import re
import shutil
import sqlite3
import struct
import tempfile
import urllib.parse
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

from aegis.core.models import Category, CheckResult, CheckStatus, Finding, Remediation, Severity
from aegis.core.platform import IS_LINUX, IS_MAC, IS_WINDOWS, OS_NAME, reg_read, reg_subkeys, reg_values
from aegis.scanners.base import ScanContext, Scanner, register
from aegis.tools.urlcheck import RISKY_TLDS, split_host

log = logging.getLogger("aegis.browser")

SCANNER = "browser"
MAX_JSON_BYTES = 64 * 1024 * 1024
EXT_ID_RE = re.compile(r"^[a-p]{32}$")
Emitted = Any  # Finding | CheckResult


# =========================================================================== knowledge base

# Popular, legitimate extensions (Chrome Web Store IDs) that legitimately hold broad permissions.
ALLOWED_EXTENSION_IDS: Dict[str, str] = {
    "cjpalhdlnbpafiamejdnhcphjbkeiagm": "uBlock Origin",
    "ddkjiahejlhfcafbddmgiahcphecmpfh": "uBlock Origin Lite",
    "nngceckbapebfimnlniiiahkandclblb": "Bitwarden",
    "aeblfdkhhhdcdjpifhhbdiojplfjncoa": "1Password",
    "hdokiejnpimakedhajhdlcegeplioahd": "LastPass",
    "fdjamakpfbbddfjaooikfcpapjohcfmg": "Dashlane",
    "kbfnbcaeplbcioakkpcpgfkobkghlhen": "Grammarly",
    "ghbmnnjooekpmoecnnnilnnbdlolhkhi": "Google Docs Offline",
    "hokifickgkhplphjiodbggjmoafhignh": "Microsoft Editor",
    "efaidnbmnnnibpcajpcglclefindmkaj": "Adobe Acrobat",
    "eimadpbcbfnmbkopoojfekhnkhdbieeh": "Dark Reader",
    "fmkadmapgofadopljbjfkapdkoienihi": "React Developer Tools",
    "lmhkpmbekcpmknklioeibfkpmmfibljd": "Redux DevTools",
    "nkbihfbeogaeaoehlefnkodbefgpgknn": "MetaMask",
    "aapbdbdomjkkjkaonfhkkikfgjllcleb": "Google Translate",
    "cfhdojbkjhnklbpkdaibdccddilifddb": "Adblock Plus",
    "gighmmpiobklfepjocnamgkkbiglidom": "AdBlock",
    "pkehgijcmpdhfbdbbnkijodmdjhbjlgp": "Privacy Badger",
    "lpcaedmchfhocbbapmcbpinfpgnhiddi": "Google Keep",
    "gmbmikajjgmnabiglmofipeabaddhgne": "Save to Google Drive",
    "inomeogfingihgjfjlpeplalcfajhgai": "Chrome Remote Desktop",
    "jldhpllghnbhlbpcmnajkpdmadaolakh": "Todoist",
    "pioclpoplcdbaefihamjohnefbikjilc": "Evernote Web Clipper",
    "gppongmhjkpfnbhagpmjfkannfbllamg": "Wappalyzer",
    "blipmdconlkpinefehnmjammfjpmpbjk": "Lighthouse",
    "liecbddmkiiihnedobmlmillhodjkdmb": "Loom",
}

# Name prefixes of well-known extensions; only honoured when the extension comes from an official store.
ALLOWED_NAME_PREFIXES: Tuple[str, ...] = (
    "ublock origin", "bitwarden", "1password", "lastpass", "dashlane", "grammarly", "google docs offline",
    "microsoft editor", "adobe acrobat", "dark reader", "react developer tools", "redux devtools", "metamask",
    "adblock plus", "privacy badger", "google translate", "keeper", "nordpass", "proton pass", "protonvpn",
    "proton vpn", "nordvpn", "expressvpn", "okta browser plugin", "microsoft defender browser protection",
    "malwarebytes browser guard", "avast online security", "norton safe web", "norton password manager",
    "kaspersky protection", "bitdefender trafficlight", "mcafee webadvisor", "eset", "web of trust",
    "google translate", "save to google drive", "chrome remote desktop", "ghostery", "duckduckgo privacy essentials",
    "vue.js devtools", "angular devtools", "wappalyzer", "lighthouse", "json viewer", "microsoft 365", "onenote web clipper",
)

STORE_UPDATE_HOSTS = {
    "clients2.google.com", "clients.google.com", "edge.microsoft.com", "microsoftedge.microsoft.com",
    "extensionws.microsoft.com", "addons.opera.com", "extensions.opera.com", "addons-nd.opera.com",
    "update.googleapis.com", "clients2.googleusercontent.com",
}
# Browsers whose own store is not Google's / Microsoft's; any https update_url counts as "store" for them.
OWN_STORE_BROWSERS = {"opera", "operagx", "yandex", "vivaldi", "arc"}

KNOWN_ENGINE_DOMAINS = {
    "bing.com", "duckduckgo.com", "ecosia.org", "brave.com", "startpage.com", "baidu.com", "naver.com", "qwant.com",
    "you.com", "perplexity.ai", "kagi.com", "seznam.cz", "sogou.com", "so.com", "daum.net", "swisscows.com",
    "mojeek.com", "wikipedia.org", "aol.com", "ya.ru", "rambler.ru", "metager.org", "lilo.org", "presearch.com",
    "givero.com", "yahoo.com", "google.com", "yandex.com", "yandex.ru", "yandex.by", "yandex.kz", "yandex.com.tr",
    "microsoft.com", "live.com", "msn.com", "github.com", "amazon.com", "youtube.com",
}
# Engines that appear under many country domains (google.de, yahoo.co.jp, yandex.ru ...).
MULTI_TLD_ENGINES = {"google", "yahoo", "yandex", "bing"}

KNOWN_HIJACKER_DOMAINS = {
    "searchbaron.com", "safefinder.com", "mysearchdial.com", "mywebsearch.com", "myway.com", "mystart.com",
    "ask.com", "conduit.com", "search-results.com", "trovi.com", "delta-search.com", "istartsurf.com",
    "webssearches.com", "hao123.com", "searchmarquis.com", "searchlock.com", "searchbaron.net", "mindspark.com",
    "searchnu.com", "snap.do", "sweet-page.com", "babylon.com", "bing-search.net", "yessearches.com",
    "search-hub.net", "tabsearch.net", "findrsearch.com", "qvo6.com", "nationzoom.com", "startsearch.net",
    "getsearchlist.com", "searchassistant.net", "searchprotect.com", "ichiban-search.com", "wow-search.com",
    "lookforsearch.com", "searchgol.com", "searchqu.com", "izito.com", "dsnrch.com", "everyonesearch.com",
}
HIJACK_NAME_WORDS = ("searchbaron", "safefinder", "searchprotect", "search-protect", "mysearch", "mywebsearch",
                     "findrsearch", "searchmarquis", "searchlock", "delta-search", "istartsurf", "trovi")

# Extension names typical of adware / fake-update lures.
SUSPICIOUS_EXT_NAME_RE = re.compile(
    r"flash\s*player|adobe\s*flash|java\s*update|(chrome|browser|google|edge|firefox)\s*(update|security|protection\s*update)|"
    r"security\s*update|search\s*(baron|protect)|safe\s*finder|my\s*search|new\s*tab\s*search|system\s*update|"
    r"video\s*player\s*update|codec\s*pack|pdf\s*(converter|viewer)\s*(pro|plus)?$", re.I)

NOTIFICATION_OK_DOMAINS = (
    "google.com", "microsoft.com", "live.com", "office.com", "slack.com", "whatsapp.com", "discord.com", "telegram.org",
    "facebook.com", "messenger.com", "twitter.com", "x.com", "linkedin.com", "github.com", "youtube.com", "reddit.com",
    "zoom.us", "instagram.com", "outlook.com", "proton.me", "protonmail.com", "yahoo.com", "icloud.com", "apple.com",
    "amazon.com", "ebay.com", "paypal.com", "twitch.tv", "notion.so", "asana.com", "trello.com", "atlassian.net",
    "atlassian.com", "spotify.com", "netflix.com", "pinterest.com", "tiktok.com", "bing.com", "microsoftonline.com",
)

# Permission weights for risk scoring.
PERM_WEIGHTS: Dict[str, Tuple[int, str]] = {
    "webRequestBlocking": (3, "can block and modify every network request"),
    "webRequest": (2, "can observe network requests"),
    "declarativeNetRequestWithHostAccess": (2, "can redirect or modify requests on the sites it can access"),
    "declarativeNetRequest": (1, "can block or redirect requests"),
    "proxy": (3, "can route your traffic through a proxy"),
    "debugger": (4, "can attach a debugger to any tab (full page access)"),
    "nativeMessaging": (3, "can talk to programs installed on your computer"),
    "cookies": (2, "can read and change cookies (session tokens)"),
    "history": (2, "can read your browsing history"),
    "management": (2, "can disable or manage other extensions"),
    "clipboardRead": (2, "can read your clipboard"),
    "desktopCapture": (3, "can capture your screen"),
    "tabCapture": (2, "can capture tab audio/video"),
    "privacy": (2, "can change browser privacy settings"),
    "downloads": (1, "can start and manage downloads"),
    "browsingData": (1, "can clear browsing data"),
    "contentSettings": (1, "can change site permissions"),
    "pageCapture": (1, "can save pages as MHTML"),
    "topSites": (1, "can read your most visited sites"),
    "tabs": (1, "can see the URL and title of every tab"),
    "webNavigation": (1, "can observe navigation"),
    "geolocation": (1, "can read your location"),
}
# Findings flagged "very broad" for store extensions: any one of these permissions ...
VERY_DANGEROUS_APIS = {"debugger", "proxy", "nativeMessaging"}


# =========================================================================== small helpers

def _read_json(path: Path) -> Any:
    """Read a JSON file leniently; {} on any problem."""
    try:
        if path.stat().st_size > MAX_JSON_BYTES:
            return {}
        return json.loads(path.read_text(encoding="utf-8-sig", errors="replace"))
    except (OSError, ValueError):
        return {}


def _get(d: Any, dotted: str, default: Any = None) -> Any:
    cur = d
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def _pget(prefs: Dict[str, Any], secure: Dict[str, Any], dotted: str, default: Any = None) -> Any:
    v = _get(secure, dotted)
    if v is None:
        v = _get(prefs, dotted)
    return default if v is None else v


def _host_of(url: str) -> str:
    try:
        u = url.strip()
        if "://" not in u:
            u = "http://" + u
        return (urllib.parse.urlsplit(u).hostname or "").lower()
    except ValueError:
        return ""


def _chrome_time(value: Any) -> str:
    """Chromium timestamps: microseconds since 1601-01-01."""
    try:
        us = int(value)
        return (dt.datetime(1601, 1, 1) + dt.timedelta(microseconds=us)).isoformat(timespec="seconds")
    except (TypeError, ValueError, OverflowError):
        return ""


def _version_key(name: str) -> Tuple[int, ...]:
    nums = re.findall(r"\d+", name)
    return tuple(int(n) for n in nums[:6]) or (0,)


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "default"


def _finding(rule: str, title: str, sev: Severity, desc: str, location: str, evidence: Dict[str, Any],
             rec: str, remediation: Optional[Remediation] = None, mitre: Optional[List[str]] = None,
             category: str = Category.BROWSER) -> Finding:
    return Finding(rule, title, sev, category, desc, location, evidence, rec, remediation,
                   scanner=SCANNER, mitre=mitre or [])


def _check(check_id: str, title: str, status: str, detail: str = "") -> CheckResult:
    return CheckResult(check_id, title, status, detail, Category.BROWSER, SCANNER)


def _status_for(findings: Iterable[Finding]) -> str:
    worst = max((f.severity for f in findings), default=Severity.INFO)
    return CheckStatus.FAIL if worst >= Severity.HIGH else CheckStatus.WARN if worst >= Severity.LOW else CheckStatus.PASS


def _lower_one(sev: Severity) -> Severity:
    return Severity(max(int(sev) - 1, int(Severity.INFO)))


# =========================================================================== managed-PC detection

@lru_cache(maxsize=1)
def is_managed_pc() -> bool:
    """True when the machine is domain-joined / MDM-enrolled, i.e. when browser
    policies are expected. Policies on an unmanaged home PC are a red flag."""
    try:
        if IS_WINDOWS:
            if os.environ.get("USERDNSDOMAIN"):
                return True
            dom = reg_read("HKLM", r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "Domain")
            if isinstance(dom, str) and dom.strip():
                return True
            for sub in reg_subkeys("HKLM", r"SOFTWARE\Microsoft\Enrollments"):
                prov = reg_read("HKLM", rf"SOFTWARE\Microsoft\Enrollments\{sub}", "ProviderID")
                if isinstance(prov, str) and prov.strip():
                    return True
            return False
        if IS_LINUX:
            return any(Path(p).exists() for p in ("/etc/krb5.keytab", "/etc/sssd/sssd.conf", "/etc/realmd.conf"))
        if IS_MAC:
            mp = Path("/Library/Managed Preferences")
            return mp.is_dir() and any(mp.glob("*.plist"))
    except Exception as exc:  # never let detection break the scan
        log.debug("managed-PC detection failed: %s", exc)
    return False


# =========================================================================== profile discovery

@dataclass
class BrowserRoot:
    key: str
    name: str
    base: Path
    family: str  # chromium | firefox


def _env(env: Optional[Dict[str, str]], name: str, default: str = "") -> str:
    return (env if env is not None else os.environ).get(name, default)


def chromium_browser_roots(os_name: str = OS_NAME, home: Optional[Path] = None,
                           env: Optional[Dict[str, str]] = None) -> List[BrowserRoot]:
    """Candidate user-data directories of Chromium-based browsers (existing or not)."""
    home = home or Path.home()
    out: List[BrowserRoot] = []

    def add(key: str, name: str, p: Path) -> None:
        out.append(BrowserRoot(key, name, p, "chromium"))

    if os_name == "windows":
        local = Path(_env(env, "LOCALAPPDATA") or home / "AppData" / "Local")
        roam = Path(_env(env, "APPDATA") or home / "AppData" / "Roaming")
        add("chrome", "Google Chrome", local / "Google" / "Chrome" / "User Data")
        add("chrome", "Google Chrome Beta", local / "Google" / "Chrome Beta" / "User Data")
        add("edge", "Microsoft Edge", local / "Microsoft" / "Edge" / "User Data")
        add("brave", "Brave", local / "BraveSoftware" / "Brave-Browser" / "User Data")
        add("vivaldi", "Vivaldi", local / "Vivaldi" / "User Data")
        add("opera", "Opera", roam / "Opera Software" / "Opera Stable")
        add("operagx", "Opera GX", roam / "Opera Software" / "Opera GX Stable")
        add("chromium", "Chromium", local / "Chromium" / "User Data")
        add("yandex", "Yandex Browser", local / "Yandex" / "YandexBrowser" / "User Data")
        pk = local / "Packages"
        try:
            for p in sorted(pk.glob("TheBrowserCompany.Arc_*")):
                add("arc", "Arc", p / "LocalCache" / "Local" / "Arc" / "User Data")
        except OSError:
            pass
    elif os_name == "darwin":
        sup = home / "Library" / "Application Support"
        add("chrome", "Google Chrome", sup / "Google" / "Chrome")
        add("edge", "Microsoft Edge", sup / "Microsoft Edge")
        add("brave", "Brave", sup / "BraveSoftware" / "Brave-Browser")
        add("vivaldi", "Vivaldi", sup / "Vivaldi")
        add("opera", "Opera", sup / "com.operasoftware.Opera")
        add("operagx", "Opera GX", sup / "com.operasoftware.OperaGX")
        add("chromium", "Chromium", sup / "Chromium")
        add("yandex", "Yandex Browser", sup / "Yandex" / "YandexBrowser")
        add("arc", "Arc", sup / "Arc" / "User Data")
    else:
        cfg = Path(_env(env, "XDG_CONFIG_HOME") or home / ".config")
        add("chrome", "Google Chrome", cfg / "google-chrome")
        add("chrome", "Google Chrome Beta", cfg / "google-chrome-beta")
        add("edge", "Microsoft Edge", cfg / "microsoft-edge")
        add("brave", "Brave", cfg / "BraveSoftware" / "Brave-Browser")
        add("vivaldi", "Vivaldi", cfg / "vivaldi")
        add("opera", "Opera", cfg / "opera")
        add("chromium", "Chromium", cfg / "chromium")
        add("yandex", "Yandex Browser", cfg / "yandex-browser")
        # snap / flatpak sandboxes
        add("chromium", "Chromium (snap)", home / "snap" / "chromium" / "common" / "chromium")
        add("chrome", "Google Chrome (flatpak)", home / ".var" / "app" / "com.google.Chrome" / "config" / "google-chrome")
        add("brave", "Brave (flatpak)", home / ".var" / "app" / "com.brave.Browser" / "config" / "BraveSoftware" / "Brave-Browser")
    return out


def firefox_browser_roots(os_name: str = OS_NAME, home: Optional[Path] = None,
                          env: Optional[Dict[str, str]] = None) -> List[BrowserRoot]:
    """Directories containing profiles.ini for Firefox-family browsers."""
    home = home or Path.home()
    out: List[BrowserRoot] = []

    def add(key: str, name: str, p: Path) -> None:
        out.append(BrowserRoot(key, name, p, "firefox"))

    if os_name == "windows":
        roam = Path(_env(env, "APPDATA") or home / "AppData" / "Roaming")
        add("firefox", "Mozilla Firefox", roam / "Mozilla" / "Firefox")
        add("librewolf", "LibreWolf", roam / "librewolf")
        add("waterfox", "Waterfox", roam / "Waterfox")
    elif os_name == "darwin":
        sup = home / "Library" / "Application Support"
        add("firefox", "Mozilla Firefox", sup / "Firefox")
        add("librewolf", "LibreWolf", sup / "librewolf")
        add("waterfox", "Waterfox", sup / "Waterfox")
    else:
        add("firefox", "Mozilla Firefox", home / ".mozilla" / "firefox")
        add("firefox", "Mozilla Firefox (snap)", home / "snap" / "firefox" / "common" / ".mozilla" / "firefox")
        add("firefox", "Mozilla Firefox (flatpak)", home / ".var" / "app" / "org.mozilla.firefox" / ".mozilla" / "firefox")
        add("librewolf", "LibreWolf", home / ".librewolf")
        add("librewolf", "LibreWolf (flatpak)", home / ".var" / "app" / "io.gitlab.librewolf-community" / ".librewolf")
        add("waterfox", "Waterfox", home / ".waterfox")
    return out


_PROFILE_DIR_RE = re.compile(r"^(Default|Profile \d+)$")


def chromium_profiles(base: Path) -> List[Path]:
    """Profile directories under a Chromium user-data dir. Guest / System
    profiles are excluded. Opera keeps its single profile directly in ``base``."""
    base = Path(base)
    try:
        if not base.is_dir():
            return []
        profiles = [p for p in sorted(base.iterdir())
                    if p.is_dir() and _PROFILE_DIR_RE.match(p.name)
                    and ((p / "Preferences").exists() or (p / "Secure Preferences").exists() or (p / "Extensions").is_dir())]
        if not profiles and ((base / "Preferences").exists() or (base / "Secure Preferences").exists()):
            profiles = [base]
        return profiles
    except OSError:
        return []


def chromium_profile_label(base: Path, profile: Path) -> str:
    """'Default' or 'Profile 1 (Work)' using Local State's profile names."""
    if profile == base:
        return "Default"
    name = _get(_read_json(base / "Local State"), f"profile.info_cache.{profile.name}.name", "")
    return f"{profile.name} ({name})" if isinstance(name, str) and name and name != profile.name else profile.name


def firefox_profiles(base: Path) -> List[Tuple[str, Path]]:
    """(name, path) of Firefox-family profiles listed in <base>/profiles.ini
    (falls back to <base>/Profiles/* when the ini is missing)."""
    base = Path(base)
    found: List[Tuple[str, Path]] = []
    ini = base / "profiles.ini"
    try:
        if ini.is_file():
            cp = configparser.RawConfigParser(strict=False)
            cp.read_string(ini.read_text(encoding="utf-8-sig", errors="replace"))
            for section in cp.sections():
                if not section.lower().startswith("profile"):
                    continue
                path = cp.get(section, "Path", fallback="").strip()
                if not path:
                    continue
                rel = cp.get(section, "IsRelative", fallback="1").strip() != "0"
                p = (base / path) if rel else Path(path)
                if p.is_dir() and all(p != q for _n, q in found):
                    found.append((cp.get(section, "Name", fallback=p.name), p))
        if not found and (base / "Profiles").is_dir():
            for p in sorted((base / "Profiles").iterdir()):
                if p.is_dir():
                    found.append((p.name, p))
    except (OSError, configparser.Error) as exc:
        log.debug("cannot read %s: %s", ini, exc)
    return found


# =========================================================================== extension model

@dataclass
class ExtInfo:
    id: str
    browser: str  # browser key
    browser_name: str
    profile: str
    name: str = ""
    version: str = ""
    location: Optional[int] = None  # Chromium ManifestLocation
    enabled: bool = True
    disable_reasons: Any = 0
    path: Optional[Path] = None  # version dir (or unpacked dir)
    ext_dir: Optional[Path] = None  # Extensions/<id> (only when inside the profile)
    manifest: Dict[str, Any] = field(default_factory=dict)
    update_url: str = ""
    from_webstore: Optional[bool] = None
    by_default: bool = False
    install_time: str = ""
    perms: Set[str] = field(default_factory=set)
    hosts: Set[str] = field(default_factory=set)
    content_hosts: Set[str] = field(default_factory=set)
    connectable: Set[str] = field(default_factory=set)
    csp: str = ""
    orphan: bool = False  # files on disk but not registered in Preferences
    firefox: bool = False
    unsigned: bool = False
    ff_location: str = ""
    source_uri: str = ""


def resolve_ext_name(manifest: Dict[str, Any], version_dir: Optional[Path]) -> str:
    """Resolve '__MSG_name__' placeholders via _locales/<default_locale>/messages.json."""
    raw = manifest.get("name")
    name = raw if isinstance(raw, str) else ""
    m = re.fullmatch(r"__MSG_(.+?)__", name.strip())
    if not m or not version_dir:
        return name
    key = m.group(1).lower()
    locales = version_dir / "_locales"
    default = manifest.get("default_locale")
    order = [x for x in (default, "en", "en_US", "en_GB") if isinstance(x, str)]
    try:
        if locales.is_dir():
            order += [p.name for p in sorted(locales.iterdir()) if p.is_dir()]
    except OSError:
        pass
    seen: Set[str] = set()
    for loc in order:
        if loc in seen:
            continue
        seen.add(loc)
        msgs = _read_json(locales / loc / "messages.json")
        if isinstance(msgs, dict):
            for k, v in msgs.items():
                if k.lower() == key and isinstance(v, dict) and isinstance(v.get("message"), str):
                    return v["message"]
    return name


def is_broad_host(pattern: str) -> bool:
    """<all_urls>, *://*/*, http(s)://*/* and friends - every website."""
    p = pattern.strip()
    if p == "<all_urls>":
        return True
    m = re.match(r"^(\*|https?|wss?|ftp)://(\*|\*\.\*)(:\*|:\d+)?(/.*)?$", p)
    return bool(m)


def _manifest_access(manifest: Dict[str, Any], pref_entry: Dict[str, Any]) -> Tuple[Set[str], Set[str], Set[str], Set[str]]:
    perms: Set[str] = set()
    hosts: Set[str] = set()
    for p in manifest.get("permissions") or []:
        if isinstance(p, str):
            (hosts if ("://" in p or p == "<all_urls>") else perms).add(p)
    for p in manifest.get("host_permissions") or []:
        if isinstance(p, str):
            hosts.add(p)
    ap = pref_entry.get("active_permissions") or pref_entry.get("granted_permissions") or {}
    if isinstance(ap, dict):
        perms.update(x for x in ap.get("api", []) if isinstance(x, str))
        hosts.update(x for x in ap.get("explicit_host", []) if isinstance(x, str))
    content: Set[str] = set()
    for cs in manifest.get("content_scripts") or []:
        if isinstance(cs, dict):
            content.update(m for m in cs.get("matches", []) if isinstance(m, str))
    if isinstance(ap, dict):
        content.update(x for x in ap.get("scriptable_host", []) if isinstance(x, str))
    conn: Set[str] = set()
    ec = manifest.get("externally_connectable")
    if isinstance(ec, dict):
        conn.update(m for m in ec.get("matches", []) if isinstance(m, str))
    return perms, hosts, content, conn


def _manifest_csp(manifest: Dict[str, Any]) -> str:
    csp = manifest.get("content_security_policy")
    if isinstance(csp, dict):
        return " ".join(str(v) for v in csp.values())
    return csp if isinstance(csp, str) else ""


def _latest_version_dir(ext_dir: Path) -> Optional[Path]:
    try:
        dirs = [p for p in ext_dir.iterdir() if p.is_dir()]
    except OSError:
        return None
    dirs = [d for d in dirs if (d / "manifest.json").exists()] or dirs
    return max(dirs, key=lambda p: (_version_key(p.name), p.stat().st_mtime), default=None) if dirs else None


def _is_abs(p: str) -> bool:
    return bool(re.match(r"^[A-Za-z]:[\\/]", p)) or p.startswith(("/", "\\\\"))


def collect_chromium_extensions(profile: Path, browser_key: str, browser_name: str,
                                profile_label: str = "") -> List[ExtInfo]:
    """Extensions of one Chromium profile from Preferences / Secure Preferences
    plus the Extensions/<id>/<version> folders."""
    profile = Path(profile)
    prefs = _read_json(profile / "Preferences")
    secure = _read_json(profile / "Secure Preferences")
    settings: Dict[str, Dict[str, Any]] = {}
    for src in (prefs, secure):
        s = _get(src, "extensions.settings")
        if isinstance(s, dict):
            for ext_id, entry in s.items():
                if isinstance(entry, dict):
                    settings.setdefault(ext_id, {}).update(entry)
    ext_root = profile / "Extensions"
    out: List[ExtInfo] = []
    seen: Set[str] = set()
    label = profile_label or profile.name

    for ext_id, entry in settings.items():
        if not EXT_ID_RE.match(ext_id):
            continue
        loc = entry.get("location")
        loc = loc if isinstance(loc, int) else None
        if loc in (5, 10):  # component extensions are part of the browser
            continue
        rel = entry.get("path")
        vdir: Optional[Path] = None
        if isinstance(rel, str) and rel:
            vdir = Path(rel) if _is_abs(rel) else ext_root / rel.replace("\\", "/")
        if (vdir is None or not vdir.is_dir()) and (ext_root / ext_id).is_dir():
            vdir = _latest_version_dir(ext_root / ext_id)
        manifest = _read_json(vdir / "manifest.json") if vdir else {}
        if not manifest and isinstance(entry.get("manifest"), dict):
            manifest = entry["manifest"]
        info = _build_chromium_info(ext_id, entry, manifest, vdir, ext_root, browser_key, browser_name, label)
        out.append(info)
        seen.add(ext_id)

    # on-disk extensions not (or not yet) registered in prefs
    try:
        disk = [p for p in sorted(ext_root.iterdir()) if p.is_dir() and EXT_ID_RE.match(p.name)] if ext_root.is_dir() else []
    except OSError:
        disk = []
    for d in disk:
        if d.name in seen:
            continue
        vdir = _latest_version_dir(d)
        manifest = _read_json(vdir / "manifest.json") if vdir else {}
        info = _build_chromium_info(d.name, {}, manifest, vdir, ext_root, browser_key, browser_name, label)
        info.orphan = bool(settings)  # registered profiles: unregistered folders are leftovers
        out.append(info)
    return out


def _build_chromium_info(ext_id: str, entry: Dict[str, Any], manifest: Dict[str, Any], vdir: Optional[Path],
                         ext_root: Path, browser_key: str, browser_name: str, label: str) -> ExtInfo:
    perms, hosts, content, conn = _manifest_access(manifest, entry)
    state = entry.get("state")
    dr = entry.get("disable_reasons", 0)
    info = ExtInfo(
        id=ext_id, browser=browser_key, browser_name=browser_name, profile=label,
        name=resolve_ext_name(manifest, vdir) or str(_get(entry, "manifest.name", "") or ""),
        version=str(manifest.get("version") or _get(entry, "manifest.version", "") or ""),
        location=entry.get("location") if isinstance(entry.get("location"), int) else None,
        enabled=(state in (1, None)) and not dr, disable_reasons=dr, path=vdir, manifest=manifest,
        update_url=str(manifest.get("update_url") or _get(entry, "manifest.update_url", "") or ""),
        from_webstore=entry.get("from_webstore") if isinstance(entry.get("from_webstore"), bool) else None,
        by_default=bool(entry.get("was_installed_by_default") or entry.get("was_installed_by_oem")),
        install_time=_chrome_time(entry.get("install_time")),
        perms=perms, hosts=hosts, content_hosts=content, connectable=conn, csp=_manifest_csp(manifest),
    )
    try:
        if (ext_root / ext_id).is_dir():
            info.ext_dir = ext_root / ext_id
    except OSError:
        pass
    return info


# =========================================================================== extension risk

@dataclass
class Risk:
    score: int = 0
    flags: List[str] = field(default_factory=list)
    broad: bool = False
    apis: Set[str] = field(default_factory=set)


def assess_risk(info: ExtInfo) -> Risk:
    r = Risk()
    all_hosts = info.hosts | info.content_hosts
    broad_hosts = {h for h in all_hosts if is_broad_host(h)}
    r.broad = bool(broad_hosts)
    if r.broad:
        r.score += 3
        where = "injects scripts into" if any(is_broad_host(h) for h in info.content_hosts) else "can access"
        r.flags.append(f"{where} every website you visit (<all_urls>-style access)")
    for perm, (w, why) in PERM_WEIGHTS.items():
        if perm in info.perms:
            if perm in ("webRequest", "declarativeNetRequest") and perm + "Blocking" in info.perms:
                continue
            r.score += w
            r.apis.add(perm)
            r.flags.append(f"{perm}: {why}")
    if "scripting" in info.perms and r.broad:
        r.score += 3
        r.apis.add("scripting")
        r.flags.append("scripting: can inject code into any page")
    if any(is_broad_host(c) for c in info.connectable):
        r.score += 2
        r.flags.append("externally_connectable: any website can message this extension")
    csp = info.csp.lower()
    if re.search(r"script-src[^;]*https?://", csp):
        r.score += 3
        r.flags.append("content-security-policy allows loading remote scripts")
    if "unsafe-eval" in csp:
        r.score += 1
        r.flags.append("content-security-policy allows eval()")
    return r


def is_store_extension(info: ExtInfo) -> bool:
    """Installed from an official extension store (not sideloaded)."""
    if info.from_webstore:
        return True
    host = _host_of(info.update_url) if info.update_url else ""
    if host in STORE_UPDATE_HOSTS:
        return True
    if info.browser in OWN_STORE_BROWSERS and info.location in (1, None) and info.update_url.startswith("https://"):
        return True
    return False


def sideload_reason(info: ExtInfo, managed: bool) -> Optional[str]:
    """Why the extension did not arrive through the normal store flow (None = normal)."""
    loc = info.location
    if loc == 4:
        return "loaded unpacked (developer mode)"
    if loc == 8:
        return "loaded with the --load-extension command-line switch"
    if loc == 3:
        return "silently installed by another program through the Windows registry"
    if loc in (2, 6):
        if info.by_default:
            return None
        return "silently installed by another program via an external-extensions file"
    if loc in (7, 9):
        return None if managed else "force-installed by a browser policy on a PC that is not managed by an organisation"
    if not is_store_extension(info):
        return "not installed from an official extension store"
    return None


def _name_allowed(name: str) -> bool:
    n = name.strip().lower()
    return any(n.startswith(p) for p in ALLOWED_NAME_PREFIXES)


def _ext_evidence(info: ExtInfo, risk: Risk, reason: str = "") -> Dict[str, Any]:
    ev: Dict[str, Any] = {
        "id": info.id, "name": info.name, "version": info.version, "browser": info.browser_name,
        "profile": info.profile, "enabled": info.enabled, "location_code": info.location,
        "update_url": info.update_url, "risk_score": risk.score, "risk_flags": risk.flags[:12],
        "permissions": sorted(info.perms)[:40], "host_access": sorted(info.hosts | info.content_hosts)[:20],
    }
    if info.install_time:
        ev["installed"] = info.install_time
    if reason:
        ev["reason"] = reason
    if info.path:
        ev["path"] = str(info.path)
    return ev


def _ext_remediation(info: ExtInfo) -> Optional[Remediation]:
    """Only offer removal of folders inside the profile's own Extensions dir -
    never an unpacked developer folder somewhere else."""
    if info.ext_dir is not None and info.ext_dir.is_dir():
        return Remediation("remove_path", {"path": str(info.ext_dir)},
                           f"Archive and remove the extension folder {info.ext_dir.name} (close {info.browser_name} first)")
    return None


def classify_extension(info: ExtInfo, sigs: Any, managed: bool = False) -> List[Finding]:
    """Turn one extension into zero or more findings (see module docstring for the policy)."""
    out: List[Finding] = []
    label = f"{info.browser_name} / {info.profile}"
    display = info.name or info.id
    location = str(info.ext_dir) if info.ext_dir else f"{label}::{info.id}"
    bad_ids = {x.lower() for x in getattr(sigs, "bad_extensions", set()) or set()}

    # 1. confirmed-malicious extension IDs
    if info.id.lower() in bad_ids:
        risk = assess_risk(info)
        state = "" if info.enabled else " (currently disabled, but it can be re-enabled)"
        if info.orphan:
            state = " (leftover files; the extension is no longer registered in the profile)"
        out.append(_finding(
            "AEG-BRW-EXT-BAD", f"Malicious browser extension: {display}", Severity.CRITICAL,
            f"Extension ID {info.id} is on the list of known malicious extensions{state}. Such extensions spy on browsing, "
            "hijack searches, inject ads or steal credentials.",
            location, _ext_evidence(info, risk, "listed in malicious-extensions feed"),
            f"Remove it from {info.browser_name} now (the extensions page, then 'Remove'), change passwords of sensitive "
            "accounts you used since it was installed, and run a full malware scan.",
            _ext_remediation(info), ["T1176"]))
        return out

    # 2. update URL on a known-bad domain
    uhost = _host_of(info.update_url) if info.update_url else ""
    if uhost and sigs is not None and getattr(sigs, "is_bad_domain", None) and sigs.is_bad_domain(uhost):
        out.append(_finding(
            "AEG-BRW-EXT-BADHOST", f"Extension updates from a malicious host: {display}", Severity.CRITICAL,
            f"The extension fetches updates from {uhost}, which is listed as malicious.", location,
            _ext_evidence(info, assess_risk(info), "update_url on blocklisted domain"),
            f"Remove the extension from {info.browser_name} and run a full malware scan.", _ext_remediation(info), ["T1176"]))
        return out

    if info.orphan:
        return out  # unregistered leftovers are inert
    if info.id in ALLOWED_EXTENSION_IDS:
        return out

    risk = assess_risk(info)
    store = is_store_extension(info)
    reason = sideload_reason(info, managed)
    sev: Optional[Severity] = None
    rule = "AEG-BRW-EXT-SIDELOAD"

    if reason and not (info.location in (7, 9) and managed):
        severe = (risk.broad and risk.score >= 5) or risk.score >= 6
        sev = Severity.HIGH if severe else Severity.MEDIUM
        if not info.enabled:
            sev = _lower_one(sev)
        title = f"Sideloaded browser extension: {display}"
        desc = (f"'{display}' was {reason}. Extensions that bypass the store review have no malware screening"
                + (f" and request powerful access: {'; '.join(risk.flags[:4])}." if risk.flags else "."))
        rec = (f"If you did not install this on purpose, remove it from {info.browser_name} (Extensions page) and "
               "check for the program that installed it. Keep it only if you know and trust the source.")
        if info.location == 3:
            rec += " Also remove the matching key under the browser's 'Extensions' registry location so it is not reinstalled."
        out.append(_finding(rule, title, sev, desc, location, _ext_evidence(info, risk, reason), rec,
                            _ext_remediation(info) if info.location != 4 else None, ["T1176"]))
    elif store and not _name_allowed(info.name):
        very_broad = bool(risk.apis & VERY_DANGEROUS_APIS) or (
            risk.broad and "webRequest" in risk.apis and "cookies" in risk.apis) or (
            risk.broad and "webRequestBlocking" in risk.apis and "cookies" in risk.apis) or (
            risk.broad and "management" in risk.apis) or (risk.broad and risk.score >= 9)
        if very_broad and info.enabled:
            out.append(_finding(
                "AEG-BRW-EXT-REVIEW", f"Extension with very broad access: {display}", Severity.LOW,
                f"'{display}' comes from the extension store but holds powerful permissions: "
                f"{'; '.join(risk.flags[:5])}. Store extensions are occasionally sold to new owners who add spyware.",
                location, _ext_evidence(info, risk), "Review whether you still use this extension and trust its publisher; "
                "remove it if not.", None, ["T1176"]))

    # 3. adware-style names / PUP list
    name_l = info.name.lower()
    pup = next((p for p in (getattr(sigs, "pup_names", []) or []) if len(p) >= 6 and p in name_l), None)
    if (pup or SUSPICIOUS_EXT_NAME_RE.search(info.name or "")) and not _name_allowed(info.name) and not out:
        out.append(_finding(
            "AEG-BRW-EXT-PUP", f"Possible adware extension: {display}", Severity.MEDIUM,
            f"The extension name matches a known adware / fake-update pattern ({pup or 'name heuristic'}).",
            location, _ext_evidence(info, risk, "name pattern"), f"Remove it from {info.browser_name} unless you installed it deliberately.",
            _ext_remediation(info) if info.location != 4 else None, ["T1176"]))
    return out


# =========================================================================== search / homepage hijack

def search_engine_verdict(url: str) -> Tuple[str, str]:
    """Classify a search/homepage URL. Returns (state, reason) with state one of
    'known' (recognised mainstream engine), 'hijacker' (known hijacker pattern) or 'unknown'."""
    host = _host_of(url) if url else ""
    if not host:
        return "known", ""
    _sub, sld, suffix = split_host(host)
    reg = f"{sld}.{suffix}" if suffix else sld
    path_q = urllib.parse.urlsplit(url if "://" in url else "http://" + url)
    q = path_q.query.lower()
    if reg in KNOWN_HIJACKER_DOMAINS or any(host == d or host.endswith("." + d) for d in KNOWN_HIJACKER_DOMAINS):
        return "hijacker", f"{reg} is a known browser-hijacker / search-redirect domain"
    if any(w in host for w in HIJACK_NAME_WORDS):
        return "hijacker", f"{host} matches a known hijacker naming pattern"
    if sld == "yahoo" and suffix.split(".")[-1] not in RISKY_TLDS:
        if path_q.path.lower().startswith("/yhs") or "hspart=" in q or "hsimp=" in q or re.search(r"(^|&)type=", q):
            return "hijacker", "Yahoo hosted-search affiliate URL (hspart/hsimp/type parameters) used by search hijackers"
        return "known", ""
    tld = suffix.split(".")[-1]
    if sld in MULTI_TLD_ENGINES and tld not in RISKY_TLDS:
        return "known", ""
    if reg in KNOWN_ENGINE_DOMAINS:
        return "known", ""
    if host.startswith("search.") and host.count(".") == 2 and tld in ("com", "net", "info", "xyz", "top", "online", "site",
                                                                      "club", "live", "co"):
        return "hijacker", f"{host} looks like a search redirector"
    return "unknown", f"{host} is not a mainstream search engine"


def _search_url_from_chromium(prefs: Dict[str, Any], secure: Dict[str, Any]) -> str:
    data = _pget(prefs, secure, "default_search_provider_data.template_url_data")
    if isinstance(data, dict):
        url = data.get("url")
        if isinstance(url, str):
            return url
    return ""


def analyse_hijack_urls(entries: Sequence[Tuple[str, str]], sigs: Any) -> List[Tuple[str, str, str]]:
    """For (kind, url) pairs return (kind, url, reason) for those that look hijacked."""
    hits = []
    for kind, url in entries:
        if not url or url.startswith(("about:", "chrome:", "chrome-search:", "edge:", "brave:", "vivaldi:", "opera:", "file:")):
            continue
        host = _host_of(url)
        state, reason = search_engine_verdict(url)
        bad = bool(host and sigs is not None and getattr(sigs, "is_bad_domain", None) and sigs.is_bad_domain(host))
        if bad:
            hits.append((kind, url, f"{host} is on the malicious-domain blocklist"))
        elif state == "hijacker":
            hits.append((kind, url, reason))
    return hits


# =========================================================================== Chromium profile analysis

def _sqlite_count(db: Path, sql: str) -> Optional[int]:
    """Run a single COUNT(*) on a *copy* of the database (browsers lock the original)."""
    if not db.is_file():
        return None
    tmpdir = tempfile.mkdtemp(prefix="aegis_br_")
    try:
        tmp = Path(tmpdir) / "copy.db"
        shutil.copyfile(db, tmp)
        conn = sqlite3.connect(str(tmp), timeout=3)
        try:
            row = conn.execute(sql).fetchone()
            return int(row[0]) if row else 0
        finally:
            conn.close()
    except (OSError, sqlite3.Error) as exc:
        log.debug("cannot count rows in %s: %s", db.name, exc)
        return None
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def count_saved_logins(profile: Path) -> int:
    """Number of saved-password rows (count only - no credential is ever read)."""
    total = 0
    for name in ("Login Data", "Login Data For Account"):
        n = _sqlite_count(profile / name, "SELECT COUNT(*) FROM logins")
        total += n or 0
    return total


def _pw_finding(browser_name: str, profile_label: str, count: int, location: str) -> Finding:
    return _finding(
        "AEG-BRW-PWSTORE", f"{count} passwords stored in {browser_name} ({profile_label})", Severity.LOW,
        f"{count} saved logins are kept in the browser's password store. Infostealer malware (RedLine, Lumma, Raccoon, ...) "
        "targets these files first.",
        location, {"browser": browser_name, "profile": profile_label, "saved_logins": count},
        "Prefer a password manager with a master password (Bitwarden, 1Password, KeePassXC) and delete the browser-saved "
        "passwords afterwards.", None, ["T1555.003"])


def _notification_hosts(prefs: Dict[str, Any]) -> List[str]:
    exc = _get(prefs, "profile.content_settings.exceptions.notifications")
    hosts: List[str] = []
    if isinstance(exc, dict):
        for pattern, val in exc.items():
            if not isinstance(val, dict) or val.get("setting") != 1:
                continue
            origin = pattern.split(",")[0].replace("[*.]", "")
            host = _host_of(origin)
            if host and host not in hosts:
                hosts.append(host)
    return hosts


def analyse_chromium_prefs(prefs: Dict[str, Any], secure: Dict[str, Any], browser_name: str, label: str,
                           location: str, sigs: Any, managed: bool) -> Tuple[List[Finding], Dict[str, str]]:
    """Preference-level checks. Returns (findings, {'safebrowsing': detail, 'search': detail})."""
    findings: List[Finding] = []
    info: Dict[str, str] = {}
    ctx_ev = {"browser": browser_name, "profile": label}

    # ---- default search engine
    search_url = _search_url_from_chromium(prefs, secure)
    verdict = "known"
    if search_url:
        verdict, reason = search_engine_verdict(search_url)
        host = _host_of(search_url)
        bad = bool(host and sigs is not None and getattr(sigs, "is_bad_domain", None) and sigs.is_bad_domain(host))
        if verdict != "known" or bad:
            sev = Severity.HIGH if (verdict == "hijacker" or bad) else Severity.MEDIUM
            if bad:
                reason = f"{host} is on the malicious-domain blocklist"
            findings.append(_finding(
                "AEG-BRW-HIJACK-SEARCH", f"Default search engine changed ({host})", sev,
                f"The default search provider points to {host}: {reason}. Search hijackers monetise or spy on every query.",
                location, dict(ctx_ev, search_url=search_url[:300], reason=reason),
                "Open Settings > Search engine and choose a trusted engine. Remove recently installed extensions and "
                "programs that may have changed it.", None, ["T1176"]))
            info["search"] = f"default search is {host}"
    # ---- homepage & startup pages
    entries: List[Tuple[str, str]] = []
    hp = _pget(prefs, secure, "homepage")
    if isinstance(hp, str) and hp and not _pget(prefs, secure, "homepage_is_newtabpage", False):
        entries.append(("homepage", hp))
    if _pget(prefs, secure, "session.restore_on_startup") == 4:
        urls = _pget(prefs, secure, "session.startup_urls", [])
        entries += [("startup", u) for u in urls if isinstance(u, str)]
    hits = analyse_hijack_urls(entries, sigs)
    for kind, rule, what in (("homepage", "AEG-BRW-HIJACK-HOME", "Homepage"), ("startup", "AEG-BRW-HIJACK-STARTUP", "Startup page")):
        sel = [h for h in hits if h[0] == kind]
        if sel:
            findings.append(_finding(
                rule, f"{what} hijacked ({_host_of(sel[0][1])})", Severity.MEDIUM,
                f"{what} points to a known hijacker/redirector: " + "; ".join(f"{u[:120]} ({r})" for _k, u, r in sel[:3]),
                location, dict(ctx_ev, urls=[u for _k, u, _r in sel][:10], reasons=[r for _k, _u, r in sel][:10]),
                "Change it in Settings > On startup / Appearance, and look for an extension or program that keeps resetting it.",
                None, ["T1176"]))
            info["search"] = info.get("search", "") or f"{what.lower()} hijacked"

    # ---- Safe Browsing
    sb = _pget(prefs, secure, "safebrowsing.enabled")
    if sb is False:
        findings.append(_finding(
            "AEG-BRW-SAFEBROWSING", f"Safe Browsing is turned off in {browser_name} ({label})", Severity.MEDIUM,
            "Safe Browsing / SmartScreen warnings for phishing and malware downloads are disabled in this profile. "
            "Malware and adware commonly switch this off.", location, dict(ctx_ev, safebrowsing_enabled=False),
            "Open Settings > Privacy and security > Security and select Standard or Enhanced protection.", None, ["T1562.001"]))
        info["safebrowsing"] = "disabled"
    elif _pget(prefs, secure, "safebrowsing.enhanced") is True:
        info["safebrowsing"] = "enhanced protection on"
    else:
        info["safebrowsing"] = "standard protection on"

    # ---- proxy
    proxy = _pget(prefs, secure, "proxy")
    if isinstance(proxy, dict) and proxy.get("mode") in ("fixed_servers", "pac_script"):
        target = proxy.get("server") or proxy.get("pac_url") or ""
        findings.append(_finding(
            "AEG-BRW-PROXY", f"Browser proxy configured ({proxy['mode']})", Severity.MEDIUM,
            f"{browser_name} ({label}) routes traffic through {proxy['mode']} {target}. Banking trojans and adware use a "
            "forced proxy / PAC file to intercept or redirect web traffic.",
            location, dict(ctx_ev, mode=proxy["mode"], target=str(target)[:200]),
            "If you do not use a corporate proxy or VPN tool, remove the proxy in Settings > System and look for the "
            "extension or program that set it.", None, ["T1090", "T1557"]))

    # ---- notification permission spam
    hosts = _notification_hosts(prefs)
    if hosts:
        bad_hosts = [h for h in hosts if sigs is not None and getattr(sigs, "is_bad_domain", None) and sigs.is_bad_domain(h)]
        unknown = [h for h in hosts if not any(h == d or h.endswith("." + d) for d in NOTIFICATION_OK_DOMAINS)]
        if bad_hosts:
            findings.append(_finding(
                "AEG-BRW-NOTIF-BAD", f"Malicious site allowed to send notifications ({bad_hosts[0]})", Severity.HIGH,
                "Sites on the malware blocklist can push notifications to this profile - a common vector for fake alerts "
                "and malware downloads.", location, dict(ctx_ev, sites=bad_hosts[:25]),
                "Open Settings > Privacy and security > Site settings > Notifications and remove these sites.", None, ["T1566"]))
        rest = [h for h in unknown if h not in bad_hosts]
        if rest:
            findings.append(_finding(
                "AEG-BRW-NOTIF", f"{len(rest)} sites allowed to send notifications", Severity.LOW,
                "Notification permission is the main channel of push-notification spam and fake virus alerts. Sites allowed: "
                + ", ".join(rest[:25]) + (f" (+{len(rest) - 25} more)" if len(rest) > 25 else ""),
                location, dict(ctx_ev, sites=rest[:25], total=len(rest)),
                "Review Settings > Privacy and security > Site settings > Notifications and remove sites you do not recognise.",
                None, []))
    return findings, info


def scan_chromium_profile(base: Path, profile: Path, browser_key: str, browser_name: str, sigs: Any,
                          managed: bool) -> Iterator[Emitted]:
    label = chromium_profile_label(base, profile)
    slug = f"{browser_key}.{_slug(label)}"
    prefs = _read_json(profile / "Preferences")
    secure = _read_json(profile / "Secure Preferences")
    pref_path = profile / ("Preferences" if (profile / "Preferences").exists() else "Secure Preferences")

    ext_findings: List[Finding] = []
    exts = collect_chromium_extensions(profile, browser_key, browser_name, label)
    for ext in exts:
        try:
            ext_findings += classify_extension(ext, sigs, managed)
        except Exception as exc:
            log.debug("extension analysis failed for %s: %s", ext.id, exc)
    pf, info = analyse_chromium_prefs(prefs if isinstance(prefs, dict) else {}, secure if isinstance(secure, dict) else {},
                                      browser_name, label, str(pref_path), sigs, managed)
    all_findings = ext_findings + pf
    yield from all_findings

    # password store (count only)
    n = count_saved_logins(profile)
    if n > 0:
        yield _pw_finding(browser_name, label, n, str(profile / "Login Data"))

    active = [e for e in exts if not e.orphan]
    yield _check(f"browser.{slug}.extensions", f"{browser_name} [{label}]: extensions reviewed",
                 _status_for(ext_findings),
                 f"{len(active)} extension(s) reviewed; {len(ext_findings)} issue(s)" if active else "no extensions installed")
    sb = info.get("safebrowsing", "")
    yield _check(f"browser.{slug}.safebrowsing", f"{browser_name} [{label}]: Safe Browsing enabled",
                 CheckStatus.FAIL if sb == "disabled" else CheckStatus.PASS, sb)
    search_issue = [f for f in pf if f.rule_id.startswith("AEG-BRW-HIJACK")]
    yield _check(f"browser.{slug}.search", f"{browser_name} [{label}]: default search engine & homepage OK",
                 CheckStatus.FAIL if search_issue else CheckStatus.PASS,
                 info.get("search", "default search engine and startup pages look normal"))


# =========================================================================== policies

CHROMIUM_POLICY_KIND = {
    "ExtensionInstallForcelist": "ext",
    "DefaultSearchProviderSearchURL": "search",
    "HomepageLocation": "home",
    "NewTabPageLocation": "home",
    "RestoreOnStartupURLs": "startup",
    "ProxySettings": "proxy",
    "ProxyServer": "proxy",
    "ProxyPacUrl": "proxy",
    "ProxyMode": "proxy",
    "SafeBrowsingEnabled": "safebrowsing",
    "SafeBrowsingProtectionLevel": "safebrowsing",
    "SmartScreenEnabled": "safebrowsing",
}
CHROMIUM_POLICY_VENDORS: Dict[str, Dict[str, Any]] = {
    "chrome": {"reg": r"Google\Chrome", "linux": ["/etc/opt/chrome/policies/managed"], "mac": "com.google.Chrome"},
    "edge": {"reg": r"Microsoft\Edge", "linux": ["/etc/opt/edge/policies/managed"], "mac": "com.microsoft.Edge"},
    "brave": {"reg": r"BraveSoftware\Brave", "linux": ["/etc/brave/policies/managed"], "mac": "com.brave.Browser"},
    "chromium": {"reg": "Chromium", "linux": ["/etc/chromium/policies/managed", "/etc/chromium-browser/policies/managed"],
                 "mac": "org.chromium.Chromium"},
    "vivaldi": {"reg": "Vivaldi", "linux": ["/etc/vivaldi/policies/managed"], "mac": "com.vivaldi.Vivaldi"},
}
# Browser display names for policy messages
POLICY_BROWSER_NAMES = {"chrome": "Google Chrome", "edge": "Microsoft Edge", "brave": "Brave", "chromium": "Chromium",
                        "vivaldi": "Vivaldi", "firefox": "Mozilla Firefox"}


@dataclass
class PolicyEntry:
    browser: str
    kind: str  # ext | search | home | startup | proxy | safebrowsing
    name: str  # policy name
    value: Any
    source: str  # registry key or file path
    reg: Optional[Tuple[str, str, str]] = None  # (hive, key, value-name) for remediation
    ext_id: str = ""


def _policy_entries_from_mapping(browser: str, mapping: Dict[str, Any], source: str,
                                 reg_base: Optional[Tuple[str, str]] = None) -> List[PolicyEntry]:
    """Common conversion of a {policy name: value} mapping (JSON file or plist)."""
    out: List[PolicyEntry] = []
    for name, val in mapping.items():
        kind = CHROMIUM_POLICY_KIND.get(name)
        if name == "ExtensionSettings" and isinstance(val, (dict, str)):
            if isinstance(val, str):
                try:
                    val = json.loads(val)
                except ValueError:
                    continue
            for ext_id, cfg in (val or {}).items():
                if ext_id != "*" and isinstance(cfg, dict) and cfg.get("installation_mode") in ("force_installed", "normal_installed"):
                    out.append(PolicyEntry(browser, "ext", name, f"{ext_id};{cfg.get('update_url', '')}", source,
                                           (reg_base[0], reg_base[1], "ExtensionSettings") if reg_base else None, ext_id))
            continue
        if not kind:
            continue
        if name == "ProxySettings" and isinstance(val, str):
            try:
                val = json.loads(val)
            except ValueError:
                pass
        items = val if isinstance(val, list) else [val]
        for i, item in enumerate(items):
            reg = (reg_base[0], reg_base[1], name) if reg_base and not isinstance(val, list) else None
            ext_id = str(item).split(";")[0].strip() if kind == "ext" else ""
            out.append(PolicyEntry(browser, kind, name, item, source if not isinstance(val, list) else f"{source}[{i}]", reg, ext_id))
    return out


def read_windows_chromium_policies(browser: str, reg_path: str) -> List[PolicyEntry]:
    out: List[PolicyEntry] = []
    for hive in ("HKLM", "HKCU"):
        key = rf"SOFTWARE\Policies\{reg_path}"
        values = reg_values(hive, key)
        src = f"{hive}\\{key}"
        simple = {k: v for k, v in values.items() if k in CHROMIUM_POLICY_KIND or k == "ExtensionSettings"}
        out += _policy_entries_from_mapping(browser, simple, src, (hive, key))
        for sub in reg_subkeys(hive, key):
            if sub in ("ExtensionInstallForcelist", "RestoreOnStartupURLs"):
                subkey = f"{key}\\{sub}"
                for vname, data in sorted(reg_values(hive, subkey).items()):
                    if not isinstance(data, str) or not data.strip():
                        continue
                    kind = CHROMIUM_POLICY_KIND[sub]
                    out.append(PolicyEntry(browser, kind, sub, data, f"{hive}\\{subkey}\\{vname}", (hive, subkey, vname),
                                           data.split(";")[0].strip() if kind == "ext" else ""))
    return out


def read_file_chromium_policies(browser: str, directories: Sequence[str]) -> List[PolicyEntry]:
    out: List[PolicyEntry] = []
    for d in directories:
        p = Path(d)
        try:
            files = sorted(p.glob("*.json")) if p.is_dir() else []
        except OSError:
            files = []
        for f in files:
            data = _read_json(f)
            if isinstance(data, dict):
                out += _policy_entries_from_mapping(browser, data, str(f))
    return out


def read_mac_chromium_policies(browser: str, domain: str) -> List[PolicyEntry]:
    out: List[PolicyEntry] = []
    roots = [Path("/Library/Managed Preferences")]
    try:
        roots += [d for d in Path("/Library/Managed Preferences").iterdir() if d.is_dir()]
    except OSError:
        pass
    for r in roots:
        f = r / f"{domain}.plist"
        try:
            if f.is_file():
                out += _policy_entries_from_mapping(browser, plistlib.loads(f.read_bytes()), str(f))
        except (OSError, plistlib.InvalidFileException, ValueError):
            continue
    return out


def read_firefox_policies_json(paths: Sequence[Path]) -> List[PolicyEntry]:
    out: List[PolicyEntry] = []
    for p in paths:
        data = _read_json(Path(p))
        pol = data.get("policies") if isinstance(data, dict) else None
        if not isinstance(pol, dict):
            continue
        src = str(p)
        for item in _get(pol, "Extensions.Install", []) or []:
            out.append(PolicyEntry("firefox", "ext", "Extensions.Install", item, src, None, str(item)))
        es = pol.get("ExtensionSettings")
        if isinstance(es, dict):
            for ext_id, cfg in es.items():
                if ext_id != "*" and isinstance(cfg, dict) and cfg.get("installation_mode") in ("force_installed", "normal_installed"):
                    out.append(PolicyEntry("firefox", "ext", "ExtensionSettings", cfg.get("install_url", ""), src, None, ext_id))
        hp = pol.get("Homepage")
        if isinstance(hp, dict):
            if hp.get("URL"):
                out.append(PolicyEntry("firefox", "home", "Homepage.URL", hp["URL"], src))
            for u in hp.get("Additional", []) or []:
                out.append(PolicyEntry("firefox", "startup", "Homepage.Additional", u, src))
        if pol.get("OverrideFirstRunPage"):
            out.append(PolicyEntry("firefox", "home", "OverrideFirstRunPage", pol["OverrideFirstRunPage"], src))
        se = pol.get("SearchEngines")
        if isinstance(se, dict):
            for add in se.get("Add", []) or []:
                if isinstance(add, dict) and add.get("URLTemplate"):
                    out.append(PolicyEntry("firefox", "search", "SearchEngines.Add", add["URLTemplate"], src))
            if se.get("Default"):
                out.append(PolicyEntry("firefox", "search", "SearchEngines.Default", str(se["Default"]), src))
        px = pol.get("Proxy")
        if isinstance(px, dict) and str(px.get("Mode", "")).lower() in ("manual", "autoconfig"):
            out.append(PolicyEntry("firefox", "proxy", "Proxy", px.get("HTTPProxy") or px.get("AutoConfigURL") or px.get("Mode"), src))
        if pol.get("DisableSafeBrowsing") is True:
            out.append(PolicyEntry("firefox", "safebrowsing", "DisableSafeBrowsing", True, src))
    return out


def read_windows_firefox_policies() -> List[PolicyEntry]:
    out: List[PolicyEntry] = []
    for hive in ("HKLM", "HKCU"):
        root = r"SOFTWARE\Policies\Mozilla\Firefox"
        src = f"{hive}\\{root}"
        for vname, data in sorted(reg_values(hive, root + r"\Extensions\Install").items()):
            if isinstance(data, str) and data:
                out.append(PolicyEntry("firefox", "ext", "Extensions.Install", data, f"{src}\\Extensions\\Install\\{vname}",
                                       (hive, root + r"\Extensions\Install", vname), data))
        hp = reg_values(hive, root + r"\Homepage")
        if isinstance(hp.get("URL"), str) and hp["URL"]:
            out.append(PolicyEntry("firefox", "home", "Homepage.URL", hp["URL"], f"{src}\\Homepage\\URL",
                                   (hive, root + r"\Homepage", "URL")))
        for vname, data in sorted(reg_values(hive, root + r"\Homepage\Additional").items()):
            if isinstance(data, str) and data:
                out.append(PolicyEntry("firefox", "startup", "Homepage.Additional", data,
                                       f"{src}\\Homepage\\Additional\\{vname}", (hive, root + r"\Homepage\Additional", vname)))
        se = reg_values(hive, root + r"\SearchEngines")
        if isinstance(se.get("Default"), str) and se["Default"]:
            out.append(PolicyEntry("firefox", "search", "SearchEngines.Default", se["Default"],
                                   f"{src}\\SearchEngines\\Default", (hive, root + r"\SearchEngines", "Default")))
        px = reg_values(hive, root + r"\Proxy")
        if str(px.get("Mode", "")).lower() in ("manual", "autoconfig"):
            out.append(PolicyEntry("firefox", "proxy", "Proxy", px.get("HTTPProxy") or px.get("AutoConfigURL") or px.get("Mode"),
                                   f"{src}\\Proxy", (hive, root + r"\Proxy", "Mode")))
    return out


def firefox_policy_files() -> List[Path]:
    paths: List[Path] = []
    if IS_WINDOWS:
        for var in ("ProgramFiles", "ProgramFiles(x86)"):
            pf = os.environ.get(var)
            if pf:
                paths += [Path(pf) / "Mozilla Firefox" / "distribution" / "policies.json",
                          Path(pf) / "LibreWolf" / "distribution" / "policies.json",
                          Path(pf) / "Waterfox" / "distribution" / "policies.json"]
    elif IS_MAC:
        paths.append(Path("/Applications/Firefox.app/Contents/Resources/distribution/policies.json"))
    else:
        paths += [Path(p) for p in ("/usr/lib/firefox/distribution/policies.json", "/usr/lib64/firefox/distribution/policies.json",
                                    "/opt/firefox/distribution/policies.json", "/etc/firefox/policies/policies.json",
                                    "/usr/lib/firefox-esr/distribution/policies.json")]
    return [p for p in paths if p.is_file()]


def analyse_policies(entries: Sequence[PolicyEntry], sigs: Any, managed: bool) -> List[Finding]:
    """Convert policy entries to findings. On managed PCs they are INFO only."""
    out: List[Finding] = []
    bad_ids = {x.lower() for x in getattr(sigs, "bad_extensions", set()) or set()}
    for e in entries:
        bname = POLICY_BROWSER_NAMES.get(e.browser, e.browser)
        rem = None
        if e.reg and IS_WINDOWS:
            hive, key, vname = e.reg
            rem = Remediation("delete_registry_value", {"hive": hive, "key": key, "value": vname, "view64": True},
                              f"Delete the {bname} policy value {vname} from {hive}\\{key}")
        location = e.source
        value = e.value if isinstance(e.value, (str, int, float, bool)) else json.dumps(e.value, default=str)[:300]
        ev = {"browser": bname, "policy": e.name, "value": value, "managed_pc": managed}

        if e.kind == "ext":
            ext_id = e.ext_id or str(e.value)
            if ext_id.lower() in bad_ids:
                out.append(_finding(
                    "AEG-BRW-POLICY-EXT", f"Known-malicious extension force-installed by policy ({ext_id})", Severity.CRITICAL,
                    f"A {bname} policy force-installs extension {ext_id}, which is on the malicious-extension list. Policy "
                    "installs cannot be removed from the browser UI.", location, dict(ev, extension_id=ext_id),
                    "Delete the policy value, restart the browser, then remove the extension and run a full malware scan.",
                    rem if not managed else None, ["T1176", "T1112"]))
                continue
            sev = Severity.INFO if managed else Severity.HIGH
            out.append(_finding(
                "AEG-BRW-POLICY-EXT", f"Extension force-installed by {bname} policy ({ext_id})", sev,
                (f"A {bname} policy force-installs extension {ext_id}. " +
                 ("This PC is managed by an organisation, so this is probably expected." if managed else
                  "This PC does not appear to be managed by an organisation: forced extensions that the user cannot remove "
                  "are the signature of adware such as ChromeLoader.")),
                location, dict(ev, extension_id=ext_id),
                "Verify with your IT department." if managed else
                "Delete the policy value (Aegis can do this), restart the browser, then remove the extension.",
                None if managed else rem, ["T1176", "T1112"]))
            continue

        reason = ""
        sev = Severity.MEDIUM
        value_s = str(value)
        if e.kind in ("search", "home", "startup"):
            url = value_s
            if e.name.endswith("Default") and "://" not in url:
                url = ""  # Firefox default engine is a name, not a URL
            if url:
                state, reason = search_engine_verdict(url)
                host = _host_of(url)
                if host and sigs is not None and getattr(sigs, "is_bad_domain", None) and sigs.is_bad_domain(host):
                    state, reason = "hijacker", f"{host} is on the malicious-domain blocklist"
                if state == "hijacker":
                    sev = Severity.HIGH
                elif state == "known":
                    sev = Severity.LOW
        elif e.kind == "safebrowsing":
            off = (e.name == "SafeBrowsingProtectionLevel" and str(e.value) == "0") or \
                  (e.name in ("SafeBrowsingEnabled", "SmartScreenEnabled") and str(e.value) in ("0", "False", "false")) or \
                  e.name == "DisableSafeBrowsing"
            if not off:
                continue
            reason = "policy disables Safe Browsing / SmartScreen"
        elif e.kind == "proxy":
            if e.name == "ProxyMode" and str(e.value) not in ("fixed_servers", "pac_script"):
                continue
            if e.name == "ProxySettings" and isinstance(e.value, dict) and e.value.get("ProxyMode") in ("direct", "system", "auto_detect"):
                continue
        what = {"search": "default search engine", "home": "homepage", "startup": "startup pages", "proxy": "proxy",
                "safebrowsing": "Safe Browsing"}[e.kind]
        if managed:
            sev = Severity.INFO
        out.append(_finding(
            "AEG-BRW-POLICY-HIJACK", f"{bname} {what} is set by policy", sev,
            f"The {bname} policy {e.name} = {value_s[:200]!r} controls the {what} and cannot be changed in the browser UI. "
            + ("This PC is managed by an organisation, so this is probably expected." if managed else
               "On a PC that is not managed by an organisation this is a classic adware / hijacker trick (e.g. ChromeLoader)")
            + (f". {reason}" if reason else "."),
            location, dict(ev, reason=reason),
            "Verify with your IT department." if managed else
            "Remove the policy value (Aegis can do this), restart the browser and scan for the program that created it.",
            None if managed else rem, ["T1112", "T1176"]))
    return out


def scan_policies(browser_key: str, managed: bool, sigs: Any) -> List[Finding]:
    entries: List[PolicyEntry] = []
    if browser_key == "firefox":
        if IS_WINDOWS:
            entries += read_windows_firefox_policies()
        entries += read_firefox_policies_json(firefox_policy_files())
    else:
        vendor = CHROMIUM_POLICY_VENDORS.get(browser_key)
        if not vendor:
            return []
        if IS_WINDOWS:
            entries += read_windows_chromium_policies(browser_key, vendor["reg"])
        elif IS_MAC:
            entries += read_mac_chromium_policies(browser_key, vendor["mac"])
        else:
            entries += read_file_chromium_policies(browser_key, vendor["linux"])
    return analyse_policies(entries, sigs, managed)


# =========================================================================== registry-installed extensions (Windows)

EXT_REGISTRY_KEYS = {
    "chrome": r"SOFTWARE\Google\Chrome\Extensions",
    "edge": r"SOFTWARE\Microsoft\Edge\Extensions",
    "brave": r"SOFTWARE\BraveSoftware\Brave-Browser\Extensions",
}


def scan_registry_extensions(sigs: Any, managed: bool) -> List[Finding]:
    """Extensions side-loaded through HKLM/HKCU ...\\Extensions\\<id> (needs update_url or path/version)."""
    out: List[Finding] = []
    if not IS_WINDOWS:
        return out
    bad_ids = {x.lower() for x in getattr(sigs, "bad_extensions", set()) or set()}
    for bkey, root in EXT_REGISTRY_KEYS.items():
        bname = POLICY_BROWSER_NAMES.get(bkey, bkey)
        for hive in ("HKLM", "HKCU"):
            for view64 in (True, False):
                for ext_id in reg_subkeys(hive, root, view64):
                    if not EXT_ID_RE.match(ext_id.lower()):
                        continue
                    key = f"{root}\\{ext_id}"
                    vals = reg_values(hive, key, view64)
                    target = vals.get("update_url") or vals.get("path")
                    if not target:
                        continue
                    if ext_id in ALLOWED_EXTENSION_IDS:
                        continue
                    value_name = "update_url" if "update_url" in vals else "path"
                    is_bad = ext_id.lower() in bad_ids
                    sev = Severity.CRITICAL if is_bad else Severity.INFO if managed else Severity.MEDIUM
                    out.append(_finding(
                        "AEG-BRW-EXT-REGISTRY", f"Extension installed through the registry ({ext_id})", sev,
                        f"A program registered {bname} extension {ext_id} under {hive}\\{key} ({value_name} = {target}). "
                        "Registry-installed extensions load without the user's consent and are a common adware vector."
                        + (" The ID is on the malicious-extension list." if is_bad else ""),
                        f"{hive}\\{key}" + ("" if view64 else " (32-bit view)"),
                        {"browser": bname, "extension_id": ext_id, "value": str(target)[:300], "managed_pc": managed},
                        "Delete the registry entry (Aegis can do this), restart the browser and remove the extension from its Extensions page.",
                        Remediation("delete_registry_value", {"hive": hive, "key": key, "value": value_name, "view64": view64},
                                    f"Delete {hive}\\{key}\\{value_name} so the browser no longer installs the extension"),
                        ["T1176", "T1112"]))
    return out


# =========================================================================== Firefox

def lz4_block_decompress(src: bytes, max_size: int = 64 * 1024 * 1024) -> bytes:
    """Minimal LZ4 block decoder (Firefox's *.mozlz4 files)."""
    out = bytearray()
    i, n = 0, len(src)
    while i < n:
        token = src[i]
        i += 1
        lit = token >> 4
        if lit == 15:
            while True:
                b = src[i]
                i += 1
                lit += b
                if b != 255:
                    break
        out += src[i:i + lit]
        i += lit
        if i >= n:
            break
        offset = src[i] | (src[i + 1] << 8)
        i += 2
        if offset == 0:
            raise ValueError("invalid LZ4 offset")
        mlen = token & 15
        if mlen == 15:
            while True:
                b = src[i]
                i += 1
                mlen += b
                if b != 255:
                    break
        mlen += 4
        start = len(out) - offset
        if start < 0:
            raise ValueError("invalid LZ4 back-reference")
        for k in range(mlen):
            out.append(out[start + k])
        if len(out) > max_size:
            raise ValueError("LZ4 output too large")
    return bytes(out)


def read_mozlz4(path: Path) -> Any:
    try:
        raw = path.read_bytes()
        if raw[:8] != b"mozLz40\0":
            return {}
        size = struct.unpack("<I", raw[8:12])[0]
        data = lz4_block_decompress(raw[12:], max_size=min(max(size, 1) * 2 + 1024, 64 * 1024 * 1024))
        return json.loads(data.decode("utf-8", "replace"))
    except (OSError, ValueError, IndexError, struct.error):
        return {}


def firefox_default_search_url(profile: Path) -> Tuple[str, str, bool]:
    """(engine name, URL template, is_app_provided) of the profile's default search engine."""
    data = read_mozlz4(profile / "search.json.mozlz4")
    if not isinstance(data, dict):
        return "", "", True
    meta = data.get("metaData", {}) if isinstance(data.get("metaData"), dict) else {}
    want_id = meta.get("defaultEngineId") or ""
    want_name = meta.get("current") or ""
    for eng in data.get("engines", []) or []:
        if not isinstance(eng, dict):
            continue
        if (want_id and eng.get("id") == want_id) or (want_name and eng.get("_name") == want_name):
            urls = eng.get("_urls") or []
            tmpl = ""
            for u in urls:
                if isinstance(u, dict) and u.get("template") and (u.get("rels") in (None, [], ["searchform"]) or not tmpl):
                    tmpl = u["template"]
                    if not u.get("rels"):
                        break
            return str(eng.get("_name", "")), tmpl, bool(eng.get("_isAppProvided"))
    return "", "", True


_PREF_RE = re.compile(r'^\s*user_pref\(\s*"([^"]+)"\s*,\s*(.+?)\s*\)\s*;\s*$')


def parse_user_prefs(path: Path) -> Dict[str, Any]:
    """Parse prefs.js / user.js ``user_pref("k", v);`` lines."""
    out: Dict[str, Any] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for line in text.splitlines():
        m = _PREF_RE.match(line)
        if not m:
            continue
        k, raw = m.group(1), m.group(2)
        if raw in ("true", "false"):
            out[k] = raw == "true"
        elif re.fullmatch(r"-?\d+", raw):
            out[k] = int(raw)
        elif len(raw) >= 2 and raw[0] == raw[-1] == '"':
            try:
                out[k] = json.loads(raw)
            except ValueError:
                out[k] = raw[1:-1]
        else:
            out[k] = raw
    return out


def collect_firefox_extensions(profile: Path, browser_key: str, browser_name: str, label: str) -> List[ExtInfo]:
    data = _read_json(profile / "extensions.json")
    out: List[ExtInfo] = []
    addons = data.get("addons") if isinstance(data, dict) else None
    for a in addons or []:
        if not isinstance(a, dict) or a.get("type") != "extension":
            continue
        loc = str(a.get("location") or "")
        if a.get("hidden") or loc.startswith("app-builtin") or loc in ("app-system-defaults", "app-system-addons"):
            continue  # shipped with the browser
        up = a.get("userPermissions") or {}
        perms = {p for p in (up.get("permissions") or []) if isinstance(p, str)}
        origins = {p for p in (up.get("origins") or []) if isinstance(p, str)}
        name = _get(a, "defaultLocale.name", "") or a.get("id", "")
        src = str(a.get("sourceURI") or "")
        signed = a.get("signedState")
        info = ExtInfo(
            id=str(a.get("id", "")), browser=browser_key, browser_name=browser_name, profile=label, name=str(name),
            version=str(a.get("version", "")), location=None, enabled=bool(a.get("active")) and not a.get("userDisabled"),
            path=Path(a["path"]) if isinstance(a.get("path"), str) else None, perms=perms, hosts=origins,
            update_url=str(a.get("updateURL") or ""), firefox=True,
            unsigned=isinstance(signed, int) and signed < 2 and loc != "app-temporary",
            ff_location=loc, source_uri=src,
            install_time=dt.datetime.fromtimestamp(a["installDate"] / 1000).isoformat(timespec="seconds")
            if isinstance(a.get("installDate"), (int, float)) and a["installDate"] > 0 else "",
        )
        out.append(info)
    return out


def classify_firefox_extension(info: ExtInfo, sigs: Any, managed: bool) -> List[Finding]:
    out: List[Finding] = []
    label = f"{info.browser_name} / {info.profile}"
    display = info.name or info.id
    location = f"{info.path}" if info.path else f"{label}::{info.id}"
    bad_ids = {x.lower() for x in getattr(sigs, "bad_extensions", set()) or set()}
    risk = assess_risk(info)
    if info.id.lower() in bad_ids:
        out.append(_finding("AEG-BRW-EXT-BAD", f"Malicious browser extension: {display}", Severity.CRITICAL,
                            f"Add-on {info.id} is on the list of known malicious extensions.", location,
                            _ext_evidence(info, risk, "listed in malicious-extensions feed"),
                            f"Remove it from {info.browser_name} (about:addons) and run a full malware scan.", None, ["T1176"]))
        return out
    amo = info.source_uri.startswith("https://addons.mozilla.org/") or "addons.mozilla.org" in info.update_url
    reg_installed = info.ff_location.startswith("winreg")
    reason = None
    if info.unsigned and info.ff_location != "app-temporary":
        reason = "unsigned (Mozilla did not sign it)"
    elif info.ff_location == "app-temporary":
        reason = "loaded temporarily (developer mode)"
    elif reg_installed:
        reason = "installed by another program through the Windows registry"
    elif not amo and info.ff_location == "app-profile" and info.source_uri.startswith(("file:", "http:")):
        reason = "installed from a file or non-store URL"
    if reason:
        severe = (risk.broad and risk.score >= 5) or risk.score >= 6
        sev = Severity.HIGH if (severe or (info.unsigned and info.ff_location != "app-temporary" and risk.score >= 3)) else Severity.MEDIUM
        if not info.enabled:
            sev = _lower_one(sev)
        out.append(_finding(
            "AEG-BRW-EXT-SIDELOAD", f"Sideloaded browser extension: {display}", sev,
            f"Firefox add-on '{display}' is {reason}" + (f" and requests: {'; '.join(risk.flags[:4])}." if risk.flags else "."),
            location, _ext_evidence(info, risk, reason),
            f"If you did not install it deliberately, remove it in {info.browser_name} (about:addons).", None, ["T1176"]))
    elif not _name_allowed(info.name) and info.id not in ALLOWED_EXTENSION_IDS:
        very_broad = bool(risk.apis & VERY_DANGEROUS_APIS) or (risk.broad and "webRequest" in risk.apis and "cookies" in risk.apis)
        if very_broad and info.enabled:
            out.append(_finding(
                "AEG-BRW-EXT-REVIEW", f"Extension with very broad access: {display}", Severity.LOW,
                f"'{display}' holds powerful permissions: {'; '.join(risk.flags[:5])}.", location, _ext_evidence(info, risk),
                "Review whether you still use this add-on and trust its publisher.", None, ["T1176"]))
    return out


def analyse_firefox_prefs(prefs: Dict[str, Any], user_prefs: Dict[str, Any], browser_name: str, label: str,
                          location: str, user_js: Optional[Path], sigs: Any) -> Tuple[List[Finding], Dict[str, str]]:
    findings: List[Finding] = []
    info: Dict[str, str] = {}
    ev = {"browser": browser_name, "profile": label}
    merged = dict(prefs)
    merged.update(user_prefs)

    def src(key: str) -> str:
        return "user.js (re-applied on every start)" if key in user_prefs else "prefs.js"

    # homepage / keyword.URL
    entries: List[Tuple[str, str]] = []
    hp = merged.get("browser.startup.homepage")
    if isinstance(hp, str) and hp:
        entries += [("homepage", u) for u in hp.split("|") if u]
    kw = merged.get("keyword.URL")
    if isinstance(kw, str) and kw:
        entries.append(("search", kw))
    hits = analyse_hijack_urls(entries, sigs)
    for kind, url, reason in hits:
        key = "keyword.URL" if kind == "search" else "browser.startup.homepage"
        rule = "AEG-BRW-HIJACK-SEARCH" if kind == "search" else "AEG-BRW-HIJACK-HOME"
        findings.append(_finding(
            rule, f"Firefox {'search' if kind == 'search' else 'homepage'} hijacked ({_host_of(url)})",
            Severity.MEDIUM, f"{key} points to {url[:150]} ({reason}); set in {src(key)}.", location,
            dict(ev, pref=key, url=url[:300], reason=reason, source=src(key)),
            "Reset the setting in about:preferences and remove the extension/program that changed it; delete user.js if "
            "you did not create it.", None, ["T1176"]))
        info["search"] = "homepage/search hijacked"
    # default search engine from search.json.mozlz4 is handled by caller (needs profile path)

    # proxy
    ptype = merged.get("network.proxy.type")
    if ptype in (1, 2):
        target = merged.get("network.proxy.autoconfig_url") if ptype == 2 else merged.get("network.proxy.http")
        findings.append(_finding(
            "AEG-BRW-PROXY", f"Firefox proxy configured ({'PAC file' if ptype == 2 else 'manual'})", Severity.MEDIUM,
            f"network.proxy.type={ptype} ({target or 'no target'}) routes Firefox traffic through a proxy; set in "
            f"{src('network.proxy.type')}. Adware and banking trojans use this to intercept traffic.", location,
            dict(ev, proxy_type=ptype, target=str(target or "")[:200], source=src("network.proxy.type")),
            "If you do not use a proxy, set Network Settings to 'Use system proxy settings' / 'No proxy'.", None, ["T1090", "T1557"]))

    # safe browsing
    off = [k for k in ("browser.safebrowsing.malware.enabled", "browser.safebrowsing.phishing.enabled") if merged.get(k) is False]
    if off:
        findings.append(_finding(
            "AEG-BRW-SAFEBROWSING", f"Safe Browsing is turned off in {browser_name} ({label})", Severity.MEDIUM,
            f"{', '.join(off)} set to false: Firefox no longer warns about phishing/malware sites.", location,
            dict(ev, prefs=off, pref_source=[src(k) for k in off]), "Enable 'Block dangerous and deceptive content' in about:preferences#privacy.", None, ["T1562.001"]))
        info["safebrowsing"] = "disabled"
    else:
        info["safebrowsing"] = "enabled"

    # signature enforcement
    if merged.get("xpinstall.signatures.required") is False:
        findings.append(_finding(
            "AEG-BRW-FF-SIGREQ", "Firefox extension signature enforcement is disabled", Severity.HIGH,
            f"xpinstall.signatures.required=false ({src('xpinstall.signatures.required')}) lets unsigned, unreviewed add-ons "
            "run. This is only normal on Developer Edition / Nightly.", location, dict(ev, source=src("xpinstall.signatures.required")),
            "Remove the setting (set it to true) and review installed add-ons.", None, ["T1176", "T1562.001"]))

    # user.js that reapplies hijack-type settings
    if user_js is not None and user_js.is_file() and any(f.evidence.get("source", "").startswith("user.js") for f in findings):
        findings.append(_finding(
            "AEG-BRW-FF-USERJS", "user.js re-applies browser hijack settings on every start", Severity.MEDIUM,
            f"{user_js} overrides homepage/proxy/search settings each time Firefox starts, so changing them in the UI does not stick.",
            str(user_js), dict(ev, file=str(user_js)),
            "Review user.js; delete it (or the offending lines) if you did not create it.", None, ["T1176", "T1112"]))
    return findings, info


def scan_firefox_profile(name: str, profile: Path, browser_key: str, browser_name: str, sigs: Any,
                         managed: bool) -> Iterator[Emitted]:
    label = name
    slug = f"{browser_key}.{_slug(label)}"
    prefs = parse_user_prefs(profile / "prefs.js")
    user_js = profile / "user.js"
    user_prefs = parse_user_prefs(user_js) if user_js.exists() else {}

    exts = collect_firefox_extensions(profile, browser_key, browser_name, label)
    ext_findings: List[Finding] = []
    for e in exts:
        try:
            ext_findings += classify_firefox_extension(e, sigs, managed)
        except Exception as exc:
            log.debug("firefox extension analysis failed for %s: %s", e.id, exc)
    pf, info = analyse_firefox_prefs(prefs, user_prefs, browser_name, label, str(profile / "prefs.js"), user_js, sigs)

    # default search engine
    eng_name, tmpl, app_provided = firefox_default_search_url(profile)
    if tmpl and not app_provided:
        state, reason = search_engine_verdict(tmpl)
        host = _host_of(tmpl)
        bad = bool(host and sigs is not None and getattr(sigs, "is_bad_domain", None) and sigs.is_bad_domain(host))
        if state != "known" or bad:
            pf.append(_finding(
                "AEG-BRW-HIJACK-SEARCH", f"Default search engine changed ({host})",
                Severity.HIGH if (state == "hijacker" or bad) else Severity.MEDIUM,
                f"Firefox's default search engine '{eng_name}' is not a built-in engine and points to {host}: {reason}.",
                str(profile / "search.json.mozlz4"),
                {"browser": browser_name, "profile": label, "engine": eng_name, "url": tmpl[:300], "reason": reason},
                "Open about:preferences#search and choose a trusted default engine; remove unknown engines.", None, ["T1176"]))
            info["search"] = f"default search is {host}"

    yield from ext_findings
    yield from pf

    try:
        data = _read_json(profile / "logins.json")
        n = len(data.get("logins", [])) if isinstance(data, dict) else 0
    except Exception:
        n = 0
    if n > 0:
        yield _pw_finding(browser_name, label, n, str(profile / "logins.json"))

    active = [e for e in exts if e.enabled]
    yield _check(f"browser.{slug}.extensions", f"{browser_name} [{label}]: extensions reviewed", _status_for(ext_findings),
                 f"{len(exts)} add-on(s) reviewed; {len(ext_findings)} issue(s)" if exts else "no add-ons installed")
    yield _check(f"browser.{slug}.safebrowsing", f"{browser_name} [{label}]: Safe Browsing enabled",
                 CheckStatus.FAIL if info.get("safebrowsing") == "disabled" else CheckStatus.PASS, info.get("safebrowsing", ""))
    hijack = [f for f in pf if f.rule_id.startswith("AEG-BRW-HIJACK") or f.rule_id in ("AEG-BRW-FF-USERJS",)]
    yield _check(f"browser.{slug}.search", f"{browser_name} [{label}]: default search engine & homepage OK",
                 CheckStatus.FAIL if hijack else CheckStatus.PASS, info.get("search", "default search engine and homepage look normal"))


# =========================================================================== the scanner

@register
class BrowserScanner(Scanner):
    name = "browser"
    title = "Browser hygiene"
    description = ("Malicious/sideloaded extensions, search & homepage hijacks, forced-install policies, "
                   "Safe Browsing, notification spam, proxies and stored passwords (Chromium family + Firefox family)")
    platforms = ("windows", "linux", "darwin")

    # overridable for tests
    def chromium_roots(self) -> List[BrowserRoot]:
        return chromium_browser_roots()

    def firefox_roots(self) -> List[BrowserRoot]:
        return firefox_browser_roots()

    def run(self, ctx: ScanContext) -> Iterator[Emitted]:
        sigs = ctx.signatures
        try:
            managed = is_managed_pc()
        except Exception:
            managed = False
        installed: Set[str] = set()

        for root in self.chromium_roots():
            if ctx.cancelled:
                return
            try:
                profiles = chromium_profiles(root.base)
            except Exception as exc:
                log.debug("profile discovery failed for %s: %s", root.base, exc)
                continue
            if not profiles:
                continue
            installed.add(root.key)
            ctx.report(SCANNER, f"Scanning {root.name}")
            for prof in profiles:
                ctx.bump("browser_profiles")
                try:
                    yield from scan_chromium_profile(root.base, prof, root.key, root.name, sigs, managed)
                except Exception as exc:
                    log.debug("scan of %s failed", prof, exc_info=True)
                    yield _check(f"browser.{root.key}.{_slug(prof.name)}.scan", f"{root.name} [{prof.name}]: profile scan",
                                 CheckStatus.ERROR, f"{type(exc).__name__}: {exc}")

        for root in self.firefox_roots():
            if ctx.cancelled:
                return
            try:
                profiles_ff = firefox_profiles(root.base)
            except Exception as exc:
                log.debug("firefox profile discovery failed for %s: %s", root.base, exc)
                continue
            if not profiles_ff:
                continue
            installed.add(root.key)
            ctx.report(SCANNER, f"Scanning {root.name}")
            for pname, ppath in profiles_ff:
                ctx.bump("browser_profiles")
                try:
                    yield from scan_firefox_profile(pname, ppath, root.key, root.name, sigs, managed)
                except Exception as exc:
                    log.debug("scan of %s failed", ppath, exc_info=True)
                    yield _check(f"browser.{root.key}.{_slug(pname)}.scan", f"{root.name} [{pname}]: profile scan",
                                 CheckStatus.ERROR, f"{type(exc).__name__}: {exc}")

        # policies are per browser (not per profile) - checked even if the browser seems absent: malware plants them
        for key in list(CHROMIUM_POLICY_VENDORS) + ["firefox"]:
            if ctx.cancelled:
                return
            try:
                pol = scan_policies(key, managed, sigs)
            except Exception as exc:
                log.debug("policy scan failed for %s", key, exc_info=True)
                yield _check(f"browser.{key}.policy", f"{POLICY_BROWSER_NAMES.get(key, key)}: policy review",
                             CheckStatus.ERROR, f"{type(exc).__name__}: {exc}")
                continue
            yield from pol
            if key in installed or pol:
                bad = [f for f in pol if f.severity >= Severity.MEDIUM]
                yield _check(f"browser.{key}.policy", f"{POLICY_BROWSER_NAMES.get(key, key)}: no policy-based hijack",
                             CheckStatus.FAIL if any(f.severity >= Severity.HIGH for f in bad) else
                             CheckStatus.WARN if bad else CheckStatus.PASS,
                             f"{len(pol)} policy item(s) found" if pol else "no browser policies set")

        if IS_WINDOWS:
            try:
                yield from scan_registry_extensions(sigs, managed)
            except Exception as exc:
                log.debug("registry extension scan failed: %s", exc)
