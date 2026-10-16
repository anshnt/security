"""Crypto clipper detection: address classification, the swap detector's timing / writer rules, and the clipboard guard
restoring the original address against a fake clipboard (restore, own-write skip, cooldown, auto-remediation). Runs on
any OS; the real Windows clipboard and its change messages are exercised in CI only."""

import collections
import os
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from aegis.core.config import Config
from aegis.core.models import Severity
from aegis.realtime import clipboard as cb
from aegis.realtime import clipper as C

BTC = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
BTC_LOOKALIKE = BTC[:7] + "xy2kgdygjrsqtzq2n0yrf2493p83kkfj" + BTC[-3:]
BTC_LEGACY = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
ETH = "0x52908400098527886E0F7030069857D2E4169EE7"
ETH_LOOKALIKE = "0x529" + "a" * 33 + "9ee7"
ETH_OTHER = "0xde709f2102306220921060314715629080e2fb77"


@pytest.mark.parametrize("text,family", [
    (BTC, "Bitcoin"), (BTC_LEGACY, "Bitcoin"), ("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", "Bitcoin"),
    (ETH, "Ethereum / EVM"), (f"  {ETH}\r\n", "Ethereum / EVM"),
    ("ltc1qg82tfn0ywhw7h3t6dgtv2kk3qk5cvh7k3f9ckd", "Litecoin"), ("LVg2kJoFNg45Nbpy53h7Fe1wKyeXVRhMH9", "Litecoin"),
    ("TNPeeaaFB7K9cmo4uQpcU32zGK8G1NYqeL", "Tron"), ("DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L", "Dogecoin"),
    ("rEb8TK3gBgk5auZkwc6sHnwrGVJH8DuaLh", "XRP"), ("bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a", "Bitcoin Cash"),
    ("EQDtFpEwcFAEcRe5mLVh2N6C0x-_hJEM7W61_JLnSF74p4q2", "TON"),
    ("7EcDhSYGxXyscszYEp35KHN8vvw3svAuLKTzXwCFLtV", "Solana"),
    ("44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A", "Monero"),
])
def test_classify_known_address_formats(text, family):
    assert C.classify_address(text) == family


@pytest.mark.parametrize("text", ["", "hello world", "password123", "https://example.com/very/long/path/1234567890",
                                  ETH + " please send", "0x123", "x" * 200, "C:\\Users\\bob\\Documents\\wallet.txt"])
def test_classify_rejects_other_text(text):
    assert C.classify_address(text) is None


def test_look_alike():
    assert C.look_alike(ETH, ETH_LOOKALIKE) and C.look_alike(BTC, BTC_LOOKALIKE)
    assert not C.look_alike(ETH, ETH_OTHER) and not C.look_alike(ETH, ETH)


BROWSER = C.Owner(100, "chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe")
CLIPPER = C.Owner(666, "svchost32.exe", r"C:\Users\bob\AppData\Roaming\svchost32.exe")


def test_swap_by_another_program_is_detected():
    d = C.ClipperDetector()
    assert d.observe(ETH, 10.0, BROWSER) is None
    s = d.observe(ETH_LOOKALIKE, 10.05, CLIPPER)
    assert s and s.family == "Ethereum / EVM" and s.original == ETH and s.replacement == ETH_LOOKALIKE
    assert s.writer == CLIPPER and s.copied_from == BROWSER and s.lookalike and s.delay_s == 0.05


@pytest.mark.parametrize("second,owner,delay", [
    (ETH_OTHER, BROWSER, 0.3),  # the same program wrote both: a person copying from one page
    (ETH_OTHER, CLIPPER, 2.5),  # too slow for a clipper
    (BTC, CLIPPER, 0.1),  # a different coin: not a swap
    (ETH, CLIPPER, 0.1),  # the same address written again
    ("some text", CLIPPER, 0.1),
])
def test_not_a_swap(second, owner, delay):
    d = C.ClipperDetector()
    d.observe(ETH, 10.0, BROWSER)
    assert d.observe(second, 10.0 + delay, owner) is None


def test_unknown_writers_need_an_almost_instant_swap():
    d = C.ClipperDetector()
    d.observe(ETH, 1.0, C.Owner())
    assert d.observe(ETH_OTHER, 1.5, C.Owner()) is not None
    d = C.ClipperDetector()
    d.observe(ETH, 1.0, BROWSER)
    assert d.observe(ETH_OTHER, 2.0, C.Owner()) is None  # writer hidden (no owner window) and over 0.8 s


def test_unrelated_copy_in_between_resets():
    d = C.ClipperDetector()
    d.observe(ETH, 1.0, BROWSER)
    d.observe("notes", 1.1, BROWSER)
    assert d.observe(ETH_OTHER, 1.2, CLIPPER) is None


def test_finding_content_and_kill_fix():
    s = C.Swap("Bitcoin", BTC, BTC_LOOKALIKE, 0.02, CLIPPER, BROWSER, lookalike=True)
    f = C.swap_finding(s, restored=True)
    assert f.rule_id == "AEG-RT-CLIPPER" and f.severity == Severity.CRITICAL and "svchost32.exe" in f.title
    assert "put your original address back" in f.description and f.evidence["replacement"] == BTC_LOOKALIKE
    assert f.remediation.action == "kill_process" and f.remediation.params["pid"] == 666
    plain = C.swap_finding(C.Swap("Bitcoin", BTC, BTC_LEGACY, 0.5, C.Owner(), BROWSER), restored=False)
    assert plain.severity == Severity.HIGH and plain.remediation is None and "unknown program" in plain.title


# --------------------------------------------------------------------------- the clipboard guard
class FakeClipboard:
    def __init__(self):
        self.seq, self.text, self.who, self.writes = 1, "", C.Owner(), []
        self._seen = None

    def put(self, text, who):
        self.seq += 1
        self.text, self.who = text, who

    def changed(self):
        if self.seq == self._seen:
            return False
        self._seen = self.seq
        return True

    def read(self):
        return self.text

    def owner(self):
        return self.who

    def write(self, text):
        self.writes.append(text)
        self.put(text, C.Owner())
        return True

    def clear(self):
        self.put("", C.Owner())
        return True


class FakeMonitor:
    def __init__(self):
        self.config = Config()
        self.signatures = SimpleNamespace(is_bad_domain=lambda d: False)
        self.stats = collections.Counter()
        self.events, self.remediated = [], []

    def emit(self, finding, source=""):
        self.events.append((finding, source))
        return True

    def auto_remediate(self, finding):
        self.remediated.append(finding)

    def spawn(self, name, target):
        return SimpleNamespace(name=name)


def make_guard():
    clock = {"t": 0.0}
    clip, mon = FakeClipboard(), FakeMonitor()
    g = cb.ClipboardGuard(mon, clipboard=clip, clock=lambda: clock["t"])
    g.start(threading.Event())  # baseline of what was already on the clipboard
    return g, clip, mon, clock


def test_guard_restores_the_original_and_reports():
    g, clip, mon, clock = make_guard()
    clip.put(ETH, BROWSER)
    clock["t"] = 5.0
    assert g.tick() is None
    clip.put(ETH_LOOKALIKE, CLIPPER)
    clock["t"] = 5.03
    f = g.tick()
    assert f and f.rule_id == "AEG-RT-CLIPPER" and f.evidence["restored"] and clip.writes == [ETH] and clip.text == ETH
    assert mon.events[0][1] == "clipboard-guard" and mon.remediated == [f] and mon.stats["clipboard_swaps"] == 1
    assert g.tick() is None and len(mon.events) == 1  # our own restore is not a clipboard change to analyse


def test_guard_cooldown_stops_a_restore_war():
    g, clip, mon, clock = make_guard()
    clip.put(ETH, BROWSER)
    clock["t"] = 1.0
    g.tick()
    clip.put(ETH_OTHER, CLIPPER)
    clock["t"] = 1.01
    assert g.tick().evidence["restored"]
    g.tick()  # sees its own restore
    clip.put(ETH_OTHER, CLIPPER)  # the clipper fights back at once
    clock["t"] = 1.02
    again = g.tick()
    assert again and again.evidence["restored"] is False and clip.writes == [ETH]
    assert "character by character" in again.description


def test_guard_without_write_support_still_reports():
    g, clip, mon, clock = make_guard()
    clip.write = None  # e.g. a command-line clipboard: report only
    clip.put(BTC, BROWSER)
    g.tick()
    clip.put(BTC_LOOKALIKE, CLIPPER)
    clock["t"] = 0.1
    f = g.tick()
    assert f.evidence["restored"] is False and f.severity == Severity.CRITICAL


def test_address_already_on_the_clipboard_at_start_is_only_a_baseline():
    clock = {"t": 0.0}
    clip, mon = FakeClipboard(), FakeMonitor()
    clip.put(ETH, BROWSER)
    g = cb.ClipboardGuard(mon, clipboard=clip, clock=lambda: clock["t"])
    g.start(threading.Event())
    clip.put("hello", BROWSER)
    assert g.tick() is None and mon.events == []


def test_loop_falls_back_to_polling_when_listening_fails():
    calls = []
    g, clip, mon, clock = make_guard()

    def broken_listen(on_change, stop, interval):
        raise OSError("no message window")

    clip.listen = broken_listen
    stop = threading.Event()
    g.interval = 0.01
    g.tick = lambda baseline=False: (calls.append(1), stop.set())
    g._loop(stop)
    assert calls


@pytest.mark.skipif(sys.platform != "win32", reason="Windows message-only window")
def test_windows_listener_runs_and_stops_without_touching_the_clipboard():
    clip = cb.WindowsClipboard()
    ticks, stop = [], threading.Event()

    def on_change():
        ticks.append(1)
        if len(ticks) >= 2:
            stop.set()

    t = threading.Thread(target=clip.listen, args=(on_change, stop, 0.1), daemon=True)
    t.start()
    t.join(5)
    assert not t.is_alive() and len(ticks) >= 2  # timer fallback ticks arrive through the message loop


@pytest.mark.skipif(sys.platform != "win32" or not os.environ.get("CI"),
                    reason="drives the real Windows clipboard; CI only, so a developer's clipboard is never overwritten")
def test_real_windows_clipboard_swap_is_undone_by_the_listener():
    clip = cb.WindowsClipboard()
    if not clip.write(ETH):
        pytest.skip("no clipboard access in this session")
    assert clip.read() == ETH and isinstance(clip.owner(), C.Owner)
    mon = FakeMonitor()
    g = cb.ClipboardGuard(mon, clipboard=clip, interval=0.2)
    stop = threading.Event()
    assert g.start(stop) and clip.write("warm-up text")
    t = threading.Thread(target=g._loop, args=(stop,), daemon=True)
    t.start()
    try:
        time.sleep(0.5)
        assert clip.write(ETH)  # "the user copies an address"
        deadline = time.monotonic() + 3
        while (g.clipper._last or ("",))[0] != ETH and time.monotonic() < deadline:
            time.sleep(0.02)
        assert clip.write(ETH_LOOKALIKE)  # "the clipper swaps it"
        deadline = time.monotonic() + 3
        while not mon.events and time.monotonic() < deadline:
            time.sleep(0.02)
        assert mon.events and mon.events[0][0].rule_id == "AEG-RT-CLIPPER"
        assert mon.events[0][0].evidence["restored"] and clip.read() == ETH
    finally:
        stop.set()
        t.join(3)
