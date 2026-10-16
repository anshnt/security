"""Clipboard guard: warns when a web page puts a ClickFix / fake-CAPTCHA command on the clipboard.

ClickFix pages ("I am not a robot - press Win+R, Ctrl+V, Enter", or "open Terminal and paste this" on a Mac) copy a
PowerShell / mshta / curl command to the clipboard and talk the visitor into running it. The guard looks at clipboard
text when it changes and classifies it with the same rules the ``traces`` scanner uses for the Run dialog and shell
history:

* HIGH or CRITICAL verdicts raise a real-time alert (desktop notification) before the command is pasted;
* a CRITICAL verdict - a download-and-run command carrying the fake-CAPTCHA lure text - also empties the clipboard when
  ``realtime_clear_malicious_clipboard`` is on (the default), so the paste does nothing.

It also catches crypto "clipper" malware (:mod:`aegis.realtime.clipper`): a copied wallet address replaced moments later
by a different address of the same coin, written by another program. The original address is put back (Windows) and the
program is named. Clippers react within milliseconds, so on Windows the guard listens for clipboard-change messages
(``AddClipboardFormatListener``) instead of only polling.

Privacy: clipboard text is only examined in memory. Nothing is logged or stored except, for an alert, a masked and
shortened copy of the malicious command. On Windows the guard reads the clipboard only when its sequence number
changes; it needs the user's desktop session, so it does not run inside the background service (session 0).
"""

from __future__ import annotations

import hashlib
import logging
import re
import shutil
import threading
import time
from typing import TYPE_CHECKING, Any, Callable, List, Optional, Tuple

from aegis.core.models import Category, Finding, Severity
from aegis.core.platform import IS_MAC, IS_WINDOWS, run
from aegis.realtime.clipper import RESTORE_COOLDOWN_S, ClipperDetector, Owner, classify_address, swap_finding

if TYPE_CHECKING:  # pragma: no cover
    from aegis.realtime.monitor import RealtimeMonitor

log = logging.getLogger("aegis.realtime.clipboard")

MAX_CLIPBOARD_CHARS = 16384  # longer text is a document, not a command to paste
POLL_INTERVAL_S = 1.0 if IS_WINDOWS else 2.0

Reader = Callable[[], Optional[str]]
_POWERSHELL = re.compile(r"(?i)\b(?:powershell|pwsh)(?:\.exe)?\b")


# =========================================================================== platform access

def _windows_api() -> Any:
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    user32.OpenClipboard.argtypes = [wintypes.HWND]
    user32.OpenClipboard.restype = wintypes.BOOL
    user32.CloseClipboard.restype = wintypes.BOOL
    user32.EmptyClipboard.restype = wintypes.BOOL
    user32.GetClipboardData.argtypes = [wintypes.UINT]
    user32.GetClipboardData.restype = wintypes.HANDLE
    user32.IsClipboardFormatAvailable.argtypes = [wintypes.UINT]
    user32.IsClipboardFormatAvailable.restype = wintypes.BOOL
    user32.GetClipboardSequenceNumber.restype = wintypes.DWORD
    kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalLock.restype = wintypes.LPVOID
    kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    kernel32.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    user32.SetClipboardData.restype = wintypes.HANDLE
    user32.GetClipboardOwner.restype = wintypes.HWND
    user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user32.GetWindowThreadProcessId.restype = wintypes.DWORD
    user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    user32.DefWindowProcW.restype = ctypes.c_ssize_t
    user32.CreateWindowExW.argtypes = [wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_int,
                                       ctypes.c_int, ctypes.c_int, ctypes.c_int, wintypes.HWND, wintypes.HMENU,
                                       wintypes.HINSTANCE, wintypes.LPVOID]
    user32.CreateWindowExW.restype = wintypes.HWND
    user32.AddClipboardFormatListener.argtypes = [wintypes.HWND]
    user32.RemoveClipboardFormatListener.argtypes = [wintypes.HWND]
    user32.SetTimer.argtypes = [wintypes.HWND, ctypes.c_size_t, wintypes.UINT, wintypes.LPVOID]
    user32.KillTimer.argtypes = [wintypes.HWND, ctypes.c_size_t]
    user32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
    user32.GetMessageW.restype = wintypes.BOOL
    user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
    user32.DestroyWindow.argtypes = [wintypes.HWND]
    user32.UnregisterClassW.argtypes = [wintypes.LPCWSTR, wintypes.HINSTANCE]
    kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
    kernel32.GlobalFree.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalFree.restype = wintypes.HGLOBAL
    kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    kernel32.GetModuleHandleW.restype = wintypes.HMODULE
    return ctypes, user32, kernel32


CF_UNICODETEXT = 13
GMEM_MOVEABLE = 0x0002
WM_TIMER = 0x0113
WM_CLIPBOARDUPDATE = 0x031D
HWND_MESSAGE = -3


def windows_session_id() -> Optional[int]:
    """Session of this process (0 = services session, which has no user clipboard)."""
    try:
        ctypes, _user32, kernel32 = _windows_api()
        from ctypes import wintypes

        sid = wintypes.DWORD()
        if kernel32.ProcessIdToSessionId(kernel32.GetCurrentProcessId(), ctypes.byref(sid)):
            return int(sid.value)
    except Exception:
        log.debug("session id lookup failed", exc_info=True)
    return None


class WindowsClipboard:
    """Reads clipboard text only when GetClipboardSequenceNumber says it changed."""

    def __init__(self) -> None:
        self._ctypes, self._user32, self._kernel32 = _windows_api()
        self._seq: Optional[int] = None

    def changed(self) -> bool:
        seq = int(self._user32.GetClipboardSequenceNumber())
        if seq == self._seq:
            return False
        self._seq = seq
        return True

    def read(self) -> Optional[str]:
        u, k = self._user32, self._kernel32
        if not u.IsClipboardFormatAvailable(CF_UNICODETEXT) or not u.OpenClipboard(None):
            return None
        try:
            handle = u.GetClipboardData(CF_UNICODETEXT)
            if not handle:
                return None
            ptr = k.GlobalLock(handle)
            if not ptr:
                return None
            try:
                return self._ctypes.wstring_at(ptr)
            finally:
                k.GlobalUnlock(handle)
        finally:
            u.CloseClipboard()

    def clear(self) -> bool:
        u = self._user32
        if not u.OpenClipboard(None):
            return False
        try:
            return bool(u.EmptyClipboard())
        finally:
            u.CloseClipboard()

    def owner(self) -> Owner:
        """The program whose window owns the clipboard (pid 0 when a program wrote it without a window)."""
        hwnd = self._user32.GetClipboardOwner()
        if not hwnd:
            return Owner()
        from ctypes import wintypes

        pid = wintypes.DWORD(0)
        self._user32.GetWindowThreadProcessId(hwnd, self._ctypes.byref(pid))
        o = Owner(int(pid.value))
        if o.pid:
            try:
                import psutil

                proc = psutil.Process(o.pid)
                o.name, o.exe = proc.name(), proc.exe()
            except Exception:
                pass
        return o

    def write(self, text: str) -> bool:
        u, k, ct = self._user32, self._kernel32, self._ctypes
        data = (text + "\0").encode("utf-16-le")
        for _ in range(5):  # another program may hold the clipboard for a moment
            if u.OpenClipboard(None):
                break
            time.sleep(0.02)
        else:
            return False
        try:
            if not u.EmptyClipboard():
                return False
            h = k.GlobalAlloc(GMEM_MOVEABLE, len(data))
            ptr = k.GlobalLock(h) if h else None
            if not ptr:
                if h:
                    k.GlobalFree(h)
                return False
            ct.memmove(ptr, data, len(data))
            k.GlobalUnlock(h)
            if not u.SetClipboardData(CF_UNICODETEXT, h):
                k.GlobalFree(h)  # the system owns the memory only once SetClipboardData succeeds
                return False
            return True
        finally:
            u.CloseClipboard()

    def listen(self, on_change: Callable[[], None], stop: threading.Event, interval: float) -> None:
        """Call ``on_change`` on every WM_CLIPBOARDUPDATE, and every ``interval`` seconds as a fallback, until ``stop``
        is set. Runs a message loop on a hidden message-only window owned by the calling thread."""
        ct, u, k = self._ctypes, self._user32, self._kernel32
        from ctypes import wintypes

        wndproc_t = ct.WINFUNCTYPE(ct.c_ssize_t, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)

        class WNDCLASSW(ct.Structure):
            _fields_ = [("style", wintypes.UINT), ("lpfnWndProc", wndproc_t), ("cbClsExtra", ct.c_int),
                        ("cbWndExtra", ct.c_int), ("hInstance", wintypes.HINSTANCE), ("hIcon", wintypes.HICON),
                        ("hCursor", wintypes.HANDLE), ("hbrBackground", wintypes.HBRUSH),
                        ("lpszMenuName", wintypes.LPCWSTR), ("lpszClassName", wintypes.LPCWSTR)]

        def proc(hwnd: Any, msg: int, wparam: Any, lparam: Any) -> int:
            if msg in (WM_CLIPBOARDUPDATE, WM_TIMER):
                try:
                    on_change()
                except Exception:
                    log.debug("clipboard change handler failed", exc_info=True)
                return 0
            return u.DefWindowProcW(hwnd, msg, wparam, lparam)

        callback = wndproc_t(proc)  # must stay referenced while the window exists
        hinst = k.GetModuleHandleW(None)
        name = f"AegisClipboardListener{threading.get_ident()}"
        u.RegisterClassW.argtypes = [ct.POINTER(WNDCLASSW)]
        if not u.RegisterClassW(ct.byref(WNDCLASSW(0, callback, 0, 0, hinst, None, None, None, None, name))):
            raise OSError(ct.get_last_error(), "RegisterClassW failed")
        hwnd = u.CreateWindowExW(0, name, name, 0, 0, 0, 0, 0, wintypes.HWND(HWND_MESSAGE), None, hinst, None)
        try:
            if not hwnd or not u.AddClipboardFormatListener(hwnd):
                raise OSError(ct.get_last_error(), "clipboard listener could not be registered")
            u.SetTimer(hwnd, 1, max(100, int(interval * 1000)), None)
            msg = wintypes.MSG()
            while not stop.is_set() and u.GetMessageW(ct.byref(msg), hwnd, 0, 0) > 0:
                u.DispatchMessageW(ct.byref(msg))
        finally:
            if hwnd:
                u.KillTimer(hwnd, 1)
                u.RemoveClipboardFormatListener(hwnd)
                u.DestroyWindow(hwnd)
            u.UnregisterClassW(name, hinst)


def unix_clipboard_commands(which: Callable[[str], Optional[str]] = shutil.which) -> Optional[Tuple[List[str], List[str]]]:
    """(read command, clear command) for this desktop, or None when no clipboard tool is installed."""
    if IS_MAC:
        return (["pbpaste"], ["pbcopy"]) if which("pbpaste") else None
    if which("wl-paste") and which("wl-copy"):
        return ["wl-paste", "--no-newline", "--type", "text"], ["wl-copy", "--clear"]
    if which("xclip"):
        return ["xclip", "-selection", "clipboard", "-o"], ["xclip", "-selection", "clipboard", "-i"]
    if which("xsel"):
        return ["xsel", "--clipboard", "--output"], ["xsel", "--clipboard", "--clear"]
    return None


class CommandClipboard:
    """Clipboard through command-line tools (macOS pbpaste/pbcopy, Wayland wl-paste, X11 xclip/xsel)."""

    def __init__(self, read_cmd: List[str], clear_cmd: List[str], runner: Callable[..., Tuple[int, str, str]] = run):
        self.read_cmd, self.clear_cmd, self.runner = read_cmd, clear_cmd, runner

    def changed(self) -> bool:
        return True  # no cheap change counter: the guard compares a hash of the text instead

    def read(self) -> Optional[str]:
        rc, out, _err = self.runner(self.read_cmd, timeout=5)
        return out if rc == 0 else None

    def clear(self) -> bool:
        rc, _out, _err = self.runner(self.clear_cmd, timeout=5, input_text="")
        return rc == 0


# =========================================================================== classification

def classify_clipboard(text: str, is_bad_domain: Optional[Callable[[str], bool]] = None,
                       windows: bool = IS_WINDOWS) -> Optional[Any]:
    """The traces verdict for clipboard text that would be pasted into Win+R / a terminal, or None. Windows text is
    judged like a Run-dialog command; elsewhere like a shell command (plus the Run-dialog rules when it runs pwsh)."""
    from aegis.scanners import traces

    if not text or not text.strip() or len(text) > MAX_CLIPBOARD_CHARS:
        return None
    if windows:
        verdicts = [traces.classify_run_command(text)]
    else:  # shell rules; the Run-dialog rules only for PowerShell (pwsh) commands, or every curl | sh installer would trip them
        verdicts = [traces.classify_unix_command(text, is_bad_domain=is_bad_domain)]
        if _POWERSHELL.search(text):
            verdicts.append(traces.classify_run_command(text))
    verdicts = [v for v in verdicts if v is not None]
    return max(verdicts, key=lambda v: int(v.severity)) if verdicts else None


def clipboard_finding(text: str, verdict: Any, cleared: Optional[bool]) -> Finding:
    from aegis.scanners import traces

    command = traces.mask_command(text)
    reasons = list(verdict.reasons)[:5]
    where = "Win+R or a terminal" if IS_WINDOWS else "a terminal"
    if cleared:
        title = "Blocked: a fake CAPTCHA page put a malicious command on your clipboard (clipboard cleared)"
    else:
        title = "A malicious command was copied to your clipboard - do not paste it"
    return Finding(
        "AEG-RT-CLIPBOARD", title, verdict.severity, Category.MALWARE,
        f"Something - almost always a web page - placed a command on your clipboard that downloads and runs code: "
        f"{command}. This is how ClickFix / fake CAPTCHA attacks work: the page asks you to press keys that paste it "
        f"into {where}. Why it is dangerous: {'; '.join(reasons) or 'it matches a known attack pattern'}."
        + (" Aegis emptied the clipboard, so pasting does nothing." if cleared else ""),
        "clipboard", {"command": command, "reasons": reasons, "cleared": bool(cleared)},
        "Do not paste or run it. Close the page that asked you to, and do not follow 'verification' steps that ask you to "
        "press Win+R, Ctrl+V or open a terminal - real CAPTCHAs never do that. If you already ran it, disconnect from the "
        "network, run a full Aegis scan and change your passwords from another device.",
        None, "realtime", list(verdict.mitre) or ["T1204.004"])


# =========================================================================== guard

class ClipboardGuard:
    def __init__(self, monitor: "RealtimeMonitor", interval: float = POLL_INTERVAL_S, clipboard: Any = None,
                 clock: Callable[[], float] = time.monotonic):
        self.monitor = monitor
        self.interval = interval
        self.clipboard = clipboard
        self._last_hash: Optional[str] = None
        self.available = True
        self.clock = clock
        self.clipper = ClipperDetector()
        self._last_restore = -RESTORE_COOLDOWN_S

    def _default_clipboard(self) -> Any:
        if IS_WINDOWS:
            if windows_session_id() == 0:
                log.info("clipboard guard not started: the services session has no user clipboard")
                return None
            return WindowsClipboard()
        cmds = unix_clipboard_commands()
        if cmds is None:
            log.info("clipboard guard not started: no clipboard tool (pbpaste, wl-paste, xclip or xsel) found")
            return None
        return CommandClipboard(*cmds)

    def start(self, stop: threading.Event) -> List[threading.Thread]:
        if not getattr(self.monitor.config, "realtime_clipboard_guard", True):
            return []
        if self.clipboard is None:
            try:
                self.clipboard = self._default_clipboard()
            except Exception:
                log.exception("clipboard guard could not open the clipboard")
                self.clipboard = None
        if self.clipboard is None:
            self.available = False
            return []
        self.tick(baseline=True)  # what is on the clipboard already was not put there just now
        return [self.monitor.spawn("clipboard-guard", lambda: self._loop(stop))]

    def _loop(self, stop: threading.Event) -> None:
        listen = getattr(self.clipboard, "listen", None)
        if listen is not None:  # Windows: react to every change at once, so a clipper's swap is seen as it happens
            try:
                listen(self._safe_tick, stop, self.interval)
                return
            except Exception:
                log.warning("clipboard change messages unavailable, polling instead", exc_info=True)
        while not stop.wait(self.interval):
            self._safe_tick()

    def _safe_tick(self) -> None:
        try:
            self.tick()
        except Exception:
            log.debug("clipboard guard tick failed", exc_info=True)

    def tick(self, baseline: bool = False) -> Optional[Finding]:
        cb = self.clipboard
        if cb is None or not getattr(self.monitor.config, "realtime_clipboard_guard", True) or not cb.changed():
            return None  # the setting is re-read every tick, so switching it off in the app applies at once
        text = cb.read()
        if text is None:
            return None
        digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
        if digest == self._last_hash:
            return None
        self._last_hash = digest
        swap = self._check_clipper(text, baseline)
        if swap is not None:
            return swap
        if baseline:
            return None
        sigs = getattr(self.monitor, "signatures", None)
        verdict = classify_clipboard(text, getattr(sigs, "is_bad_domain", None))
        if verdict is None or verdict.severity < Severity.HIGH:
            return None
        self.monitor.stats["clipboard_alerts"] += 1
        cleared: Optional[bool] = None
        if verdict.severity >= Severity.CRITICAL and getattr(self.monitor.config, "realtime_clear_malicious_clipboard", True):
            try:
                cleared = bool(cb.clear())
            except Exception:
                cleared = False
            if cleared:
                self._last_hash = hashlib.sha256(b"").hexdigest()
                self.monitor.stats["clipboard_cleared"] += 1
        finding = clipboard_finding(text, verdict, cleared)
        self.monitor.emit(finding, "clipboard-guard")
        return finding

    def _check_clipper(self, text: str, baseline: bool) -> Optional[Finding]:
        """Feed the clipper detector; on a swap put the original address back (once per cooldown) and report it."""
        cb = self.clipboard
        owner = Owner()
        if classify_address(text) and hasattr(cb, "owner"):
            try:
                owner = cb.owner()
            except Exception:
                log.debug("clipboard owner lookup failed", exc_info=True)
        swap = self.clipper.observe(text, self.clock(), owner)
        if swap is None or baseline:
            return None
        restored = False
        now = self.clock()
        write = getattr(cb, "write", None)
        if write is not None and now - self._last_restore >= RESTORE_COOLDOWN_S:
            try:
                restored = bool(write(swap.original))
            except Exception:
                log.debug("restoring the clipboard failed", exc_info=True)
            if restored:
                self._last_restore = now
                self._last_hash = hashlib.sha256(swap.original.encode("utf-8", "replace")).hexdigest()
                self.clipper.observe(swap.original, now, Owner())  # a clipper that swaps again is caught again
        self.monitor.stats["clipboard_swaps"] += 1
        finding = swap_finding(swap, restored)
        remediate = getattr(self.monitor, "auto_remediate", None)
        if remediate is not None:
            remediate(finding)  # terminates and quarantines the clipper when auto-quarantine is on
        self.monitor.emit(finding, "clipboard-guard")
        return finding
