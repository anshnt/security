"""Crypto "clipper" detection for the clipboard guard.

Clippers watch the clipboard and, the moment a cryptocurrency address is copied, replace it with the attacker's address
of the same coin, often a look-alike that shares the first and last characters so a glance at the pasted text does not
reveal the swap. :class:`ClipperDetector` gets every clipboard change and reports when an address is replaced by a
*different address of the same coin* within a couple of seconds by a different program. The clipboard guard
(:mod:`aegis.realtime.clipboard`) then puts the original address back and names the program when Windows can tell.

Only text shaped like a wallet address is examined here; nothing is logged.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from aegis.core.models import Category, Finding, Remediation, Severity

SWAP_WINDOW_S = 2.0  # clippers swap within milliseconds; a person needs longer to select and copy another address
UNKNOWN_WRITER_WINDOW_S = 0.8  # when Windows cannot tell the two writers apart, only an almost instant swap counts
RESTORE_COOLDOWN_S = 10.0  # a clipper that fights back is reported again, but not restored in a loop
MAX_ADDRESS = 128

_B58 = "1-9A-HJ-NP-Za-km-z"
_BECH = "ac-hj-np-z02-9"
# most specific first: the generic base58 Solana pattern overlaps several others and goes last
ADDRESS_PATTERNS: List[Tuple[str, "re.Pattern[str]"]] = [
    ("Ethereum / EVM", re.compile(r"^0x[0-9a-fA-F]{40}$")),
    ("Bitcoin", re.compile(rf"^(?:bc1[{_BECH}]{{11,71}}|[13][{_B58}]{{25,34}})$")),
    ("Litecoin", re.compile(rf"^(?:ltc1[{_BECH}]{{11,71}}|[LM][{_B58}]{{26,33}})$")),
    ("Bitcoin Cash", re.compile(r"^(?:bitcoincash:)?[qp][02-9ac-hj-np-z]{41}$")),
    ("Monero", re.compile(rf"^[48][0-9AB][{_B58}]{{93}}$")),
    ("Tron", re.compile(rf"^T[{_B58}]{{33}}$")),
    ("Dogecoin", re.compile(rf"^D[5-9A-HJ-NP-U][{_B58}]{{32}}$")),
    ("XRP", re.compile(rf"^r[{_B58}]{{24,34}}$")),
    ("TON", re.compile(r"^(?:EQ|UQ)[A-Za-z0-9_-]{46}$")),
    ("Cardano", re.compile(r"^addr1[02-9ac-hj-np-z]{50,110}$")),
    ("Solana", re.compile(rf"^[{_B58}]{{32,44}}$")),
]


def classify_address(text: str) -> Optional[str]:
    """Coin family of a wallet address, or None."""
    t = (text or "").strip()
    if not 25 <= len(t) <= MAX_ADDRESS or any(c.isspace() for c in t):
        return None
    for family, rx in ADDRESS_PATTERNS:
        if rx.match(t):
            return family
    return None


def look_alike(a: str, b: str) -> bool:
    """Same first and last characters (after any 0x), different address: the 'address poisoning' trick."""
    a, b = a.lower(), b.lower()
    if a.startswith("0x") and b.startswith("0x"):
        a, b = a[2:], b[2:]
    return a != b and len(a) == len(b) and a[:3] == b[:3] and a[-3:] == b[-3:]


@dataclass
class Owner:
    """The program that wrote the clipboard (pid 0 = Windows could not tell)."""

    pid: int = 0
    name: str = ""
    exe: str = ""


@dataclass
class Swap:
    family: str
    original: str
    replacement: str
    delay_s: float
    writer: Owner
    copied_from: Owner
    lookalike: bool = False


@dataclass
class ClipperDetector:
    """Pure decision logic: feed every clipboard change, get a Swap when an address was replaced."""

    window_s: float = SWAP_WINDOW_S
    unknown_window_s: float = UNKNOWN_WRITER_WINDOW_S
    _last: Optional[Tuple[str, str, float, Owner]] = field(default=None, repr=False)

    def observe(self, text: str, now: float, owner: Optional[Owner] = None) -> Optional[Swap]:
        owner = owner or Owner()
        family = classify_address(text)
        if family is None:
            self._last = None
            return None
        addr = text.strip()
        last, self._last = self._last, (addr, family, now, owner)
        if not last or last[1] != family or last[0] == addr:
            return None
        delay = now - last[2]
        known = bool(owner.pid and last[3].pid)
        if known and owner.pid == last[3].pid:
            return None  # the same program wrote both: a person copying two addresses from one app
        if delay > (self.window_s if known else self.unknown_window_s):
            return None
        self._last = last  # the genuine address stays the reference
        return Swap(family, last[0], addr, round(delay, 3), owner, last[3], look_alike(last[0], addr))


def swap_finding(swap: Swap, restored: bool) -> Finding:
    who = swap.writer.name or "an unknown program"
    sev = Severity.CRITICAL if swap.lookalike else Severity.HIGH
    desc = (f"A copied {swap.family} address was replaced {swap.delay_s:.2f}s later by a different {swap.family} address "
            f"written by {who}{f' ({swap.writer.exe})' if swap.writer.exe else ''}. This is how clipboard-hijacking "
            "(clipper) malware steals crypto payments.")
    if swap.lookalike:
        desc += " The new address starts and ends with the same characters as yours, so it was chosen to pass a quick look."
    desc += (" Aegis put your original address back on the clipboard." if restored else
             " Check the address you paste character by character.")
    rem = (Remediation("kill_process", {"pid": swap.writer.pid, "path": swap.writer.exe, "quarantine": True},
                       f"Terminate {who} and quarantine it") if swap.writer.pid and swap.writer.exe else None)
    return Finding(
        "AEG-RT-CLIPPER", f"Clipboard hijack: {swap.family} address swapped by {who}", sev, Category.MALWARE, desc,
        swap.writer.exe or "clipboard",
        {"family": swap.family, "original": swap.original, "replacement": swap.replacement, "delay_s": swap.delay_s,
         "writer_pid": swap.writer.pid, "writer": swap.writer.name, "writer_exe": swap.writer.exe,
         "copied_from": swap.copied_from.name, "lookalike": swap.lookalike, "restored": restored},
        "Do not send anything to the replaced address. Run a full scan, remove the program named here, and only then "
        "copy wallet addresses again.", rem, "realtime", ["T1115", "T1565.002"])
