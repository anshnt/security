"""Literal "atom" prefiltering for regex-based detection.

Running dozens of regexes over every file dominated scan time. Most detection
regexes cannot match unless some fixed string occurs in the data
(``downloadstring``, ``vssadmin``...). At compile time we derive, from the
regex's own parse tree, a set of literals of which at least one *must* appear
in any match; at scan time a cheap substring search on a lower-cased copy of
the data decides whether the full regex needs to run at all (the same idea as
YARA atoms / Aho-Corasick prefilters).

Soundness: atoms are only taken from parts of the pattern every match must
pass through (top-level sequence items and groups, every branch of an
alternation, repeats with min >= 1). Anything else contributes nothing, and a
pattern without a usable requirement simply has no prefilter. Atoms and data
are both lower-cased, which is valid for case-sensitive and case-insensitive
patterns alike.
"""

from __future__ import annotations

import re
from typing import FrozenSet, List, Optional, Sequence, Set

try:  # Python 3.11+
    import re._parser as _sre_parse  # type: ignore[import-not-found]
    import re._constants as _sre_c  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - Python 3.9 / 3.10
    import sre_constants as _sre_c  # type: ignore[no-redef]
    import sre_parse as _sre_parse  # type: ignore[no-redef]

MIN_ATOM = 3  # shorter literals are too common to filter anything
MAX_ALTERNATIVES = 64

Requirement = FrozenSet[bytes]  # at least one of these (lower-cased) literals must occur


def _lower(b: bytes) -> bytes:
    return b.lower()


def _requirements(items: Sequence, depth: int = 0) -> List[Requirement]:
    """Requirements implied by a parsed sequence (every element must match, in order)."""
    if depth > 20:
        return []
    reqs: List[Requirement] = []
    run = bytearray()

    def flush() -> None:
        if len(run) >= MIN_ATOM:
            reqs.append(frozenset({_lower(bytes(run))}))
        run.clear()

    for op, av in items:
        if op is _sre_c.LITERAL:
            if av > 0xFF:  # non-byte literal (str patterns are not used here)
                flush()
                continue
            run.append(av)
            continue
        flush()
        if op is _sre_c.SUBPATTERN:
            sub = av[-1]  # (group, add_flags, del_flags, pattern)
            reqs.extend(_requirements(list(sub), depth + 1))
        elif op is _sre_c.BRANCH:
            alts = av[1]
            best_per_branch: List[Requirement] = []
            for alt in alts:
                r = _best(_requirements(list(alt), depth + 1))
                if r is None:
                    best_per_branch = []
                    break
                best_per_branch.append(r)
            if best_per_branch:
                union = frozenset().union(*best_per_branch)
                if len(union) <= MAX_ALTERNATIVES:
                    reqs.append(union)
        elif op in (_sre_c.MAX_REPEAT, _sre_c.MIN_REPEAT) or op is getattr(_sre_c, "POSSESSIVE_REPEAT", None):
            lo, _hi, sub = av
            if lo >= 1:  # at least one occurrence is mandatory
                reqs.extend(_requirements(list(sub), depth + 1))
        elif op is getattr(_sre_c, "ATOMIC_GROUP", None):
            reqs.extend(_requirements(list(av), depth + 1))
        # IN, ANY, NOT_LITERAL, AT, ASSERT, GROUPREF, CATEGORY ...: no literal requirement
    flush()
    return reqs


def _best(reqs: List[Requirement]) -> Optional[Requirement]:
    """Most selective requirement: the one whose *shortest* alternative is longest."""
    usable = [r for r in reqs if r and min(len(a) for a in r) >= MIN_ATOM]
    if not usable:
        return None
    return max(usable, key=lambda r: (min(len(a) for a in r), -len(r)))


def required_atoms(pattern: "re.Pattern[bytes]") -> Optional[FrozenSet[bytes]]:
    """Lower-cased literals of which at least one occurs in every match of
    ``pattern``, or None when no useful prefilter can be derived."""
    if not isinstance(pattern.pattern, bytes):
        return None
    try:
        parsed = _sre_parse.parse(pattern.pattern, pattern.flags & ~re.DEBUG)
    except Exception:
        return None
    return _best(_requirements(list(parsed)))


class Prefiltered:
    """A compiled bytes regex plus its atoms. ``search(data, lowered)`` skips the
    regex when no atom occurs in ``lowered`` (= ``data.lower()``, computed once
    per file by the caller and shared across patterns)."""

    __slots__ = ("regex", "atoms", "pattern")

    def __init__(self, regex: "re.Pattern[bytes]"):
        self.regex = regex
        self.pattern = regex.pattern
        self.atoms = required_atoms(regex)

    def may_match(self, lowered: bytes) -> bool:
        return self.atoms is None or any(a in lowered for a in self.atoms)

    def search(self, data: bytes, lowered: Optional[bytes] = None):
        if self.atoms is not None:
            if lowered is None:
                lowered = data.lower()
            if not any(a in lowered for a in self.atoms):
                return None
        return self.regex.search(data)


def atoms_summary(patterns: Sequence["re.Pattern[bytes]"]) -> Set[int]:
    """Indexes of patterns that got a prefilter (diagnostics/tests)."""
    return {i for i, p in enumerate(patterns) if required_atoms(p) is not None}
