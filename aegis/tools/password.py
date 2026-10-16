"""Password checker: offline strength estimation plus an optional Have I Been
Pwned breach look-up using the k-anonymity range API.

Privacy: only the first 5 hex characters of the SHA-1 are ever sent. The
password and the full hash never leave the machine."""

from __future__ import annotations

import hashlib
import logging
import math
import re
import urllib.error
import urllib.request
from functools import lru_cache
from typing import Dict, List, Tuple

from aegis import __version__
from aegis.core.config import PACKAGE_DATA

log = logging.getLogger("aegis.password")

HIBP_URL = "https://api.pwnedpasswords.com/range/"
USER_AGENT = "Aegis-Security-Suite/" + __version__

_KEYBOARD_ROWS = ["1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm", "qazwsxedcrfvtgbyhnujmikolp",
                  "1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik9ol0p"]
_LEET_MAP = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g", "@": "a", "$": "s",
             "!": "i", "+": "t", "|": "l", "(": "c", "€": "e", "£": "l"}


@lru_cache(maxsize=1)
def _common() -> Dict[str, int]:
    """word -> rank (0 = most common)."""
    out: Dict[str, int] = {}
    try:
        for line in (PACKAGE_DATA / "common_passwords.txt").read_text(encoding="utf-8").splitlines():
            line = line.strip().lower()
            if line and not line.startswith("#") and line not in out:
                out[line] = len(out)
    except OSError as exc:
        log.debug("common password list unavailable: %s", exc)
    return out


# --------------------------------------------------------------------------- pwned passwords

def pwned_count(password: str, timeout: float = 10.0) -> int:
    """Number of times ``password`` appears in HIBP breach corpora.
    Raises OSError/URLError on network problems (callers catch)."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()  # noqa: S324 - HIBP protocol requires SHA-1
    prefix, suffix = sha1[:5], sha1[5:]
    req = urllib.request.Request(HIBP_URL + prefix, headers={"Add-Padding": "true", "User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", "replace")
    for line in body.splitlines():
        h, _, count = line.strip().partition(":")
        if h.upper() == suffix:
            try:
                return int(count.strip() or 0)  # padded decoy rows carry a count of 0
            except ValueError:
                return 0
    return 0


# --------------------------------------------------------------------------- strength model

def _pool_size(pw: str) -> int:
    pool = 0
    if re.search(r"[a-z]", pw):
        pool += 26
    if re.search(r"[A-Z]", pw):
        pool += 26
    if re.search(r"\d", pw):
        pool += 10
    if re.search(r"[^\w\s]|_", pw):
        pool += 33
    if re.search(r"\s", pw):
        pool += 1
    if re.search(r"[^\x00-\x7f]", pw):
        pool += 100
    return max(pool, 1)


def _unleet(s: str) -> str:
    return "".join(_LEET_MAP.get(c, c) for c in s)


def _matches(pw: str, brute_bits: float) -> List[Tuple[int, int, float, str]]:
    """Cheap-pattern spans as (start, end_exclusive, bits, kind)."""
    spans: List[Tuple[int, int, float, str]] = []
    low = pw.lower()
    n = len(pw)
    common = _common()

    # dictionary words (also with l33t substitutions), >= 3 chars
    for i in range(n):
        for j in range(i + 3, n + 1):
            frag = low[i:j]
            if frag in common:
                spans.append((i, j, math.log2(common[frag] + 2) + (1 if pw[i:j] != frag else 0), "dictionary"))
            else:
                ul = _unleet(frag)
                if ul != frag and ul in common:
                    spans.append((i, j, math.log2(common[ul] + 2) + 2, "leet"))

    # repeated block: aaaa, abababab, 123123123
    for size in range(1, n // 2 + 1):
        i = 0
        while i + 2 * size <= n:
            block = pw[i:i + size]
            reps = 1
            while pw[i + reps * size:i + (reps + 1) * size] == block:
                reps += 1
            if reps >= 2 and (size * reps >= 4 or size == 1 and reps >= 3):
                spans.append((i, i + size * reps, brute_bits * size + math.log2(reps) + 1, "repeat"))
                i += size * reps
            else:
                i += 1

    # sequences: abcd, 4321, 13579
    i = 0
    while i < n - 2:
        d = ord(pw[i + 1]) - ord(pw[i])
        if d != 0 and abs(d) <= 2:
            j = i + 1
            while j + 1 < n and ord(pw[j + 1]) - ord(pw[j]) == d:
                j += 1
            if j - i + 1 >= 3:
                spans.append((i, j + 1, math.log2(26) + math.log2(j - i + 1) + 1.5, "sequence"))
                i = j
        i += 1

    # keyboard walks (forwards or backwards along a row)
    for row in _KEYBOARD_ROWS:
        for rev in (row, row[::-1]):
            i = 0
            while i < n - 3:
                k = rev.find(low[i])
                if k >= 0:
                    j = i
                    while j + 1 < n and k + (j - i) + 1 < len(rev) and low[j + 1] == rev[k + (j - i) + 1]:
                        j += 1
                    if j - i + 1 >= 4:
                        spans.append((i, j + 1, math.log2(40) + math.log2(j - i + 1) + 1, "keyboard"))
                        i = j
                i += 1

    # years and dates
    for m in re.finditer(r"(?<!\d)(19\d\d|20[0-3]\d)(?!\d)", pw):
        spans.append((m.start(), m.end(), 7.0, "year"))
    for m in re.finditer(r"(?<!\d)(0?[1-9]|[12]\d|3[01])[-/. ]?(0?[1-9]|1[0-2])[-/. ]?(19\d\d|20[0-3]\d|\d\d)(?!\d)", pw):
        spans.append((m.start(), m.end(), 13.0, "date"))
    for m in re.finditer(r"(?<!\d)(19\d\d|20[0-3]\d)[-/. ]?(0?[1-9]|1[0-2])[-/. ]?(0?[1-9]|[12]\d|3[01])(?!\d)", pw):
        spans.append((m.start(), m.end(), 13.0, "date"))
    return spans


def _estimate(pw: str) -> Tuple[float, List[str]]:
    """Minimum-cost decomposition of the password into brute-force characters
    and cheap patterns (a tiny zxcvbn). Returns (bits, pattern kinds used)."""
    n = len(pw)
    pool = _pool_size(pw)
    per_char = math.log2(pool)
    spans = _matches(pw, per_char)
    best = [0.0] * (n + 1)
    kinds: List[List[str]] = [[] for _ in range(n + 1)]
    by_end: Dict[int, List[Tuple[int, float, str]]] = {}
    for s, e, bits, kind in spans:
        by_end.setdefault(e, []).append((s, bits, kind))
    for i in range(1, n + 1):
        best[i] = best[i - 1] + per_char
        kinds[i] = kinds[i - 1]
        for s, bits, kind in by_end.get(i, ()):
            cost = best[s] + bits
            if cost < best[i]:
                best[i] = cost
                kinds[i] = kinds[s] + [kind]
    return best[n], kinds[n]


def _strength(bits: float) -> int:
    return 0 if bits < 28 else 1 if bits < 36 else 2 if bits < 60 else 3 if bits < 80 else 4


def check_password(password: str, online: bool = True) -> Dict[str, object]:
    """Evaluate a password.

    Returns {"pwned_count": int|None, "strength": 0-4, "entropy_bits": float,
    "feedback": [str], "online_error": str}. ``pwned_count`` is None when the
    HIBP check was skipped (online=False) or failed (``online_error`` says why)."""
    feedback: List[str] = []
    result: Dict[str, object] = {"pwned_count": None, "strength": 0, "entropy_bits": 0.0, "feedback": feedback,
                                 "online_error": ""}
    if not password:
        feedback.append("Password is empty.")
        return result

    bits, kinds = _estimate(password)
    strength = _strength(bits)
    low = password.lower()
    common = _common()
    base = re.sub(r"[\d\W_]+$", "", low)
    exact_common = low in common or _unleet(low) in common
    common_base = not exact_common and len(low) < 14 and base in common

    if exact_common or common_base:
        strength = 0
        rank = common.get(low, common.get(_unleet(low), common.get(base, 50)))
        bits = min(bits, math.log2(rank + 2) + (3 if exact_common else 10))
        feedback.append("This is one of the most commonly used passwords - attackers try it first." if exact_common else
                        "This is a common password with a predictable suffix (digits/symbols) - crackers try these variants first.")
    n = len(password)
    if n < 8:
        strength = min(strength, 1)
        feedback.append("Too short: use at least 12 characters (a passphrase of 4+ random words works well).")
    elif n < 12:
        strength = min(strength, 3)
        feedback.append("Longer is stronger: aim for 12+ characters.")
    if "dictionary" in kinds and not (exact_common or common_base):
        feedback.append("Contains common words or passwords - avoid dictionary words, names and predictable endings.")
    if "leet" in kinds:
        feedback.append("Substituting characters like @ for a or 0 for o barely helps; crackers try those first.")
    if "keyboard" in kinds:
        feedback.append("Keyboard patterns such as 'qwerty' or 'asdf' are easy to guess.")
    if "sequence" in kinds:
        feedback.append("Avoid sequences like 'abcd' or '1234'.")
    if "repeat" in kinds:
        feedback.append("Avoid repeated characters or blocks like 'aaa' or 'abcabc'.")
    if "year" in kinds or "date" in kinds:
        feedback.append("Avoid dates and years - they are among the first things guessed.")
    if len(set(password)) <= max(2, n // 4):
        feedback.append("Very few distinct characters.")
    if password.isalpha() or password.isdigit():
        feedback.append("Mix in additional character types or, better, add length.")

    if online:
        try:
            count = pwned_count(password)
            result["pwned_count"] = count
            if count > 0:
                strength = 0
                feedback.insert(0, f"This password appeared in {count:,} known data breaches - never use it.")
        except Exception as exc:  # network down, proxy, HTTP error ...
            result["online_error"] = f"{type(exc).__name__}: {exc}"
            log.info("HIBP lookup failed: %s", exc)

    if strength >= 3 and not feedback:
        feedback.append("Looks strong. Store it in a password manager and use it for one account only.")
    elif not feedback:
        feedback.append("Reasonable, but longer and more random is better.")

    result["strength"] = strength
    result["entropy_bits"] = round(bits, 1)
    return result
