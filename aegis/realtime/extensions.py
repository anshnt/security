"""Extension guard: alerts when a browser extension is installed while real-time protection runs.

Malicious extensions arrive by sideloading (an installer drops one through the registry, an external-extensions file, a
policy or ``--load-extension``) and by store extensions that ask for every site and the user's cookies. The browser
scanner reviews what is installed during a scan; this guard watches for new ones in between:

* on start it records the extensions of every Chromium-family profile (Chrome, Edge, Brave, Vivaldi, Opera ...) and
  every Firefox-family profile of the current user (of every user when it runs with administrator rights);
* every ``interval`` seconds it looks again, re-reading a profile only when its Preferences, Secure Preferences,
  ``Extensions`` folder or ``extensions.json`` changed, and reports each extension it has not seen before.

A new extension is judged with the browser scanner's own rules (known-malicious IDs, malicious update hosts, sideloading,
adware names, very broad permissions, its allow-list of well-known extensions): when they produce a finding, that finding
is raised with "New extension - " in front of its title, so a sideloaded or malicious one pops up a desktop notification.
Otherwise the event is AEG-RT-EXTENSION at LOW: recorded in the event log and the GUI, without a notification. Nothing is
removed automatically.
"""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Dict, Iterable, List, Optional, Tuple

from aegis.core.models import Category, Finding, Severity
from aegis.core.platform import IS_MAC, IS_WINDOWS, is_admin

if TYPE_CHECKING:  # pragma: no cover
    from aegis.realtime.monitor import RealtimeMonitor
    from aegis.scanners.browser import BrowserRoot, ExtInfo

log = logging.getLogger("aegis.realtime.extensions")

POLL_INTERVAL_S = 60.0
PROFILE_FILES = ("Preferences", "Secure Preferences", "Extensions", "extensions.json")

Key = Tuple[str, str, str]  # (browser key, profile folder, extension id)
Stamp = Tuple[Tuple[str, int, int], ...]


def profile_stamp(profile: Path) -> Stamp:
    """What changes when an extension is added to a profile: size and modification time of its extension files."""
    out = []
    for name in PROFILE_FILES:
        try:
            st = (profile / name).stat()
        except OSError:
            continue
        out.append((name, st.st_size, st.st_mtime_ns))
    return tuple(out)


def user_homes(admin: Optional[bool] = None) -> List[Path]:
    """The current user's home folder, plus every other user's when the guard runs with administrator rights (the
    background service runs as SYSTEM or root, whose own profile has no browsers)."""
    homes = [Path.home()]
    if admin if admin is not None else is_admin():
        bases = [Path(os.environ.get("SystemDrive", "C:") + "\\Users")] if IS_WINDOWS else [Path("/Users" if IS_MAC else "/home")]
        for base in bases:
            try:
                homes += sorted(p for p in base.iterdir() if p.is_dir() and p.name.lower() not in ("public", "default",
                                                                                                    "default user", "all users"))
            except OSError:
                continue
    seen, out = set(), []
    for h in homes:
        key = os.path.normcase(str(h))
        if key not in seen:
            seen.add(key)
            out.append(h)
    return out


def browser_roots(homes: Iterable[Path]) -> List["BrowserRoot"]:
    from aegis.scanners import browser as B

    roots: List[Any] = []
    me = Path.home()
    for home in homes:
        env = None if home == me else {}  # another user's folders follow from the home, not from this process's env
        roots += B.chromium_browser_roots(home=home, env=env) + B.firefox_browser_roots(home=home, env=env)
    return roots


def profile_extensions(root: "BrowserRoot") -> List[Tuple[Path, str, Callable[[], List["ExtInfo"]]]]:
    """(profile folder, label, reader of its extensions) for every profile of one browser."""
    from aegis.scanners import browser as B

    out: List[Tuple[Path, str, Callable[[], List[Any]]]] = []
    if root.family == "firefox":
        for name, path in B.firefox_profiles(root.base):
            out.append((path, name, lambda p=path, n=name: B.collect_firefox_extensions(p, root.key, root.name, n)))
    else:
        for path in B.chromium_profiles(root.base):
            label = B.chromium_profile_label(root.base, path)
            out.append((path, label, lambda p=path, lb=label: B.collect_chromium_extensions(p, root.key, root.name, lb)))
    return out


def new_extension_finding(info: "ExtInfo", sigs: Any, managed: bool) -> Optional[Finding]:
    """The alert for an extension that just appeared: the browser scanner's own verdict when it has one, otherwise a LOW
    AEG-RT-EXTENSION event. None for leftover files of an extension that is no longer registered."""
    from aegis.scanners import browser as B

    if info.orphan:
        return None
    classify = B.classify_firefox_extension if info.firefox else B.classify_extension  # Firefox add-ons have their own rules
    verdicts = classify(info, sigs, managed)
    if verdicts:
        f = max(verdicts, key=lambda x: int(x.severity))
        f.title = f"New extension - {f.title}"
        f.scanner = "realtime"
        f.evidence = dict(f.evidence, source="extension-guard")
        return f
    risk = B.assess_risk(info)
    display = info.name or info.id
    label = f"{info.browser_name} / {info.profile}"
    access = f" Its access: {'; '.join(risk.flags[:3])}." if risk.flags else ""
    return Finding(
        "AEG-RT-EXTENSION", f"New browser extension: {display} ({info.browser_name})", Severity.LOW, Category.BROWSER,
        f"'{display}' {info.version} was added to {label} while real-time protection was running.{access}",
        str(info.ext_dir) if info.ext_dir else f"{label}::{info.id}",
        dict(B._ext_evidence(info, risk), source="extension-guard"),
        f"If you did not add it yourself just now, remove it from {info.browser_name} (Extensions page) and look for the "
        "program that installed it.", None, "realtime", ["T1176"])


class ExtensionGuard:
    def __init__(self, monitor: "RealtimeMonitor", interval: float = POLL_INTERVAL_S,
                 roots: Optional[Callable[[], List[Any]]] = None):
        self.monitor = monitor
        self.interval = interval
        self.roots = roots or (lambda: browser_roots(user_homes()))
        self._stamps: Dict[str, Stamp] = {}
        self._known: Dict[str, Dict[Key, "ExtInfo"]] = {}  # profile folder -> its extensions
        self._baseline = False
        self._managed: Optional[bool] = None

    def enabled(self) -> bool:
        return bool(getattr(self.monitor.config, "realtime_extension_guard", True))

    def start(self, stop: threading.Event) -> List[threading.Thread]:
        return [self.monitor.spawn("extension-guard", lambda: self._loop(stop))]

    def _loop(self, stop: threading.Event) -> None:
        self.tick()  # baseline: what is installed already was not installed just now
        while not stop.wait(self.interval):
            try:
                self.tick()
            except Exception:
                log.exception("extension guard tick failed")

    def managed(self) -> bool:
        if self._managed is None:
            try:
                from aegis.scanners.browser import is_managed_pc

                self._managed = bool(is_managed_pc())
            except Exception:
                self._managed = False
        return self._managed

    def tick(self) -> List[Finding]:
        """Look for new extensions. The setting is read every time, so the GUI can switch the guard on and off while it
        runs; switching it back on takes a fresh baseline instead of reporting what was installed while it was off."""
        if not self.enabled():
            self._stamps, self._known, self._baseline = {}, {}, False
            return []
        new: List["ExtInfo"] = []
        for root in self.roots():
            try:
                profiles = profile_extensions(root)
            except Exception:
                log.debug("profile discovery failed for %s", getattr(root, "base", root), exc_info=True)
                continue
            for path, _label, read in profiles:
                folder = os.path.normcase(str(path))
                stamp = profile_stamp(path)
                if self._stamps.get(folder) == stamp and folder in self._known:
                    continue
                try:
                    exts = {(e.browser, folder, e.id.lower()): e for e in read() if e.id}
                except Exception:
                    log.debug("could not read the extensions of %s", path, exc_info=True)
                    continue
                before = self._known.get(folder)
                if self._baseline and before is not None:
                    new += [e for k, e in exts.items() if k not in before]
                elif self._baseline:  # a profile created since the baseline: everything in it is new
                    new += list(exts.values())
                self._stamps[folder], self._known[folder] = stamp, exts
        self._baseline = True
        out: List[Finding] = []
        for info in new:
            try:
                f = new_extension_finding(info, self.monitor.signatures, self.managed())
            except Exception:
                log.debug("could not judge extension %s", info.id, exc_info=True)
                continue
            if f is not None:
                out.append(f)
                self.monitor.emit(f, "extension-guard")
        return out
