"""Desktop notifications for real-time events.

Windows: a native toast through PowerShell (WinRT ToastNotificationManager);
falls back to a MessageBox / msg.exe for high-severity alerts.
Linux: notify-send.  macOS: osascript.  Every call is also written to the log.
Notifications are rate-limited to one per title every few seconds so a burst of
detections cannot flood the desktop.
"""

from __future__ import annotations

import base64
import logging
import shutil
import threading
import time
from typing import Callable, Dict, Optional
from xml.sax.saxutils import escape

from aegis.core.platform import IS_LINUX, IS_MAC, IS_WINDOWS, run

log = logging.getLogger("aegis.notify")

# Windows needs a registered AppUserModelID for toasts to show; PowerShell's own is always registered.
TOAST_APP_ID = r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"
RATE_LIMIT_S = 5.0

ASYNC = True  # deliver on a worker thread (tests switch this off)
_clock: Callable[[], float] = time.monotonic
_lock = threading.Lock()
_last_sent: Dict[str, float] = {}

_SEVERITY_NAMES = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}


def _sev_name(severity) -> str:
    if isinstance(severity, str):
        return severity.strip().lower() or "info"
    try:
        return _SEVERITY_NAMES.get(int(severity), "info")
    except (TypeError, ValueError):
        return "info"


def reset_rate_limit() -> None:
    with _lock:
        _last_sent.clear()


def notify(title: str, message: str, severity="info") -> bool:
    """Show a desktop notification. Returns False when it was rate-limited.

    `severity` may be a string ("critical") or an int / aegis Severity."""
    sev = _sev_name(severity)
    level = logging.WARNING if sev in ("medium", "high", "critical") else logging.INFO
    log.log(level, "[%s] %s - %s", sev, title, message)
    now = _clock()
    with _lock:
        prev = _last_sent.get(title)
        if prev is not None and now - prev < RATE_LIMIT_S:
            return False
        _last_sent[title] = now
        if len(_last_sent) > 256:  # bound memory
            for k in sorted(_last_sent, key=_last_sent.get)[:128]:
                _last_sent.pop(k, None)
    if ASYNC:
        threading.Thread(target=_safe_deliver, args=(title, message, sev), daemon=True, name="aegis-notify").start()
    else:
        _safe_deliver(title, message, sev)
    return True


def _safe_deliver(title: str, message: str, sev: str) -> None:
    try:
        _deliver(title, message, sev)
    except Exception as exc:  # a notification must never take the monitor down
        log.debug("notification failed: %s", exc)


def _deliver(title: str, message: str, sev: str) -> bool:
    title, message = title[:120], message[:400]
    if IS_WINDOWS:
        if _windows_toast(title, message, sev):
            return True
        if sev in ("high", "critical"):
            return _windows_messagebox(title, message, sev)
        return False
    if IS_MAC:
        return _mac_notify(title, message)
    if IS_LINUX:
        return _linux_notify(title, message, sev)
    return False


# --------------------------------------------------------------------------- Windows

def build_toast_xml(title: str, message: str, sev: str) -> str:
    """Toast XML; high / critical alerts use the 'reminder' scenario so they stay on screen."""
    q = {'"': "&quot;", "'": "&apos;"}
    urgent = sev in ("high", "critical")
    head = "<toast scenario='reminder'>" if urgent else "<toast>"
    sound = "<audio src='ms-winsoundevent:Notification.Looping.Alarm2' loop='false'/>" if sev == "critical" else \
        "<audio src='ms-winsoundevent:Notification.Default'/>" if urgent else "<audio silent='true'/>"
    actions = "<actions><action content='Dismiss' arguments='dismiss' activationType='system'/></actions>" if urgent else ""
    return (
        f"{head}<visual><binding template='ToastGeneric'>"
        f"<text>{escape(title, q)}</text><text>{escape(message, q)}</text>"
        f"</binding></visual>{actions}{sound}</toast>"
    )


def build_toast_script(title: str, message: str, sev: str) -> str:
    xml = build_toast_xml(title, message, sev).replace("'", "''")  # PowerShell single-quote escaping
    return (
        "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null;"
        "[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null;"
        "$x = New-Object Windows.Data.Xml.Dom.XmlDocument;"
        f"$x.LoadXml('{xml}');"
        "$t = [Windows.UI.Notifications.ToastNotification]::new($x);"
        f"[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{TOAST_APP_ID}').Show($t)"
    )


def _windows_toast(title: str, message: str, sev: str) -> bool:
    script = build_toast_script(title, message, sev)
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    exe = shutil.which("powershell") or "powershell"
    rc, _out, err = run([exe, "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
                         "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded], timeout=20)
    if rc != 0:
        log.debug("toast failed rc=%s %s", rc, err.strip()[:200])
    return rc == 0


def _windows_messagebox(title: str, message: str, sev: str) -> bool:
    try:
        import ctypes

        flags = 0x10 if sev == "critical" else 0x30  # MB_ICONERROR / MB_ICONWARNING
        flags |= 0x40000 | 0x1000  # MB_TOPMOST | MB_SYSTEMMODAL
        # MessageBoxW blocks until dismissed - we are already on a worker thread.
        ctypes.windll.user32.MessageBoxW(0, message, title, flags)  # type: ignore[attr-defined]
        return True
    except Exception:
        rc, _o, _e = run(["msg", "*", "/TIME:60", f"{title}\n{message}"], timeout=10)
        return rc == 0


# --------------------------------------------------------------------------- Linux / macOS

def _linux_notify(title: str, message: str, sev: str) -> bool:
    exe = shutil.which("notify-send")
    if not exe:
        return False
    urgency = "critical" if sev in ("high", "critical") else "low" if sev in ("info", "low") else "normal"
    rc, _o, _e = run([exe, "-a", "Aegis", "-u", urgency, "--", title, message], timeout=10)
    return rc == 0


def _applescript_quote(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _mac_notify(title: str, message: str) -> bool:
    script = f"display notification {_applescript_quote(message)} with title {_applescript_quote(title)}"
    rc, _o, _e = run(["osascript", "-e", script], timeout=10)
    return rc == 0
