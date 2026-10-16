"""The literal-atom prefilter must never hide a real regex match.

For every detection regex shipped with Aegis (Aegis-Lite rule strings and the
script heuristics) we generate random strings that the regex matches - random
branch choices, repeat counts and letter case - and assert the prefiltered
search finds them too."""

import random
import re
import string

import pytest

from aegis.core import fileanalysis as fa
from aegis.core.atoms import Prefiltered, _sre_c, _sre_parse, required_atoms

_WORD = string.ascii_letters + string.digits + "_"


def _gen(items, rnd, flags, depth=0):
    out = bytearray()
    for op, av in items:
        if op is _sre_c.LITERAL:
            c = av
            if flags & re.IGNORECASE and chr(c).isalpha() and rnd.random() < 0.5:
                c = ord(chr(c).swapcase())
            out.append(c)
        elif op is _sre_c.NOT_LITERAL:
            out.append(ord("Q") if av != ord("Q") else ord("Z"))
        elif op is _sre_c.ANY:
            out.append(ord(rnd.choice("aZ9 -")))
        elif op is _sre_c.IN:
            out += _gen_in(av, rnd)
        elif op is _sre_c.BRANCH:
            out += _gen(list(rnd.choice(av[1])), rnd, flags, depth + 1)
        elif op is _sre_c.SUBPATTERN:
            out += _gen(list(av[-1]), rnd, flags | (av[1] or 0), depth + 1)
        elif op in (_sre_c.MAX_REPEAT, _sre_c.MIN_REPEAT) or op is getattr(_sre_c, "POSSESSIVE_REPEAT", None):
            lo, hi, sub = av
            hi = min(hi, lo + 3)
            for _ in range(rnd.randint(lo, max(lo, hi))):
                out += _gen(list(sub), rnd, flags, depth + 1)
        elif op is getattr(_sre_c, "ATOMIC_GROUP", None):
            out += _gen(list(av), rnd, flags, depth + 1)
        elif op is _sre_c.CATEGORY:
            out += _gen_category(av)
        # AT, ASSERT, ASSERT_NOT, GROUPREF...: emit nothing (the regex check below filters bad samples)
    return bytes(out)


def _gen_category(cat):
    name = str(cat).upper()
    if "NOT" in name:
        return b"-" if "WORD" in name or "DIGIT" in name else b"x"
    if "DIGIT" in name:
        return b"7"
    if "SPACE" in name:
        return b" "
    if "WORD" in name:
        return b"w"
    return b"x"


def _gen_in(items, rnd):
    negate = any(op is _sre_c.NEGATE for op, _ in items)
    if negate:
        banned = set()
        for op, av in items:
            if op is _sre_c.LITERAL:
                banned.add(av)
            elif op is _sre_c.RANGE:
                banned.update(range(av[0], av[1] + 1))
        for c in b"QZqz-#":
            if c not in banned:
                return bytes([c])
        return b"\x01"
    op, av = rnd.choice([x for x in items if x[0] is not _sre_c.NEGATE])
    if op is _sre_c.LITERAL:
        return bytes([av])
    if op is _sre_c.RANGE:
        return bytes([rnd.randint(av[0], av[1])])
    if op is _sre_c.CATEGORY:
        return _gen_category(av)
    return b"x"


def _all_patterns():
    from aegis.core.config import Config
    from aegis.core.signatures import SignatureDB

    pats = {}
    for rule in SignatureDB(Config.load()).rules:
        for sid, p in rule.strings.items():
            pats[f"{rule.id}:{sid}"] = p.regex
    for rid, _t, rx, _s, _m in fa._COMPILED_SCRIPT:
        pats[rid] = rx.regex
    return pats


def test_prefilter_never_hides_a_match():
    rnd = random.Random(1337)
    pats = _all_patterns()
    assert len(pats) > 150
    checked = with_atoms = 0
    for name, rx in pats.items():
        pf = Prefiltered(rx)
        with_atoms += pf.atoms is not None
        parsed = list(_sre_parse.parse(rx.pattern, rx.flags))
        for _ in range(25):
            core = _gen(parsed, rnd, rx.flags)
            data = bytes(rnd.choice(b"abc XYZ\n") for _ in range(rnd.randint(0, 20))) + core + b" tail"
            if not rx.search(data):
                continue  # generator produced a non-match (assertions, anchors...) - nothing to check
            checked += 1
            assert pf.search(data, data.lower()) is not None, (name, rx.pattern[:80], data[:120])
    assert checked > 1000, checked
    assert with_atoms / len(pats) > 0.6, "most detection regexes should get a prefilter"


@pytest.mark.parametrize("pattern,expected", [
    (rb"(?i)vssadmin(\.exe)?\s+delete\s+shadows", {b"vssadmin"}),
    (rb"(downloadstring|downloaddata)", {b"download"}),
    (rb"foo(bar)?baz", {b"foo"}),
    (rb"(hello)+world", {b"hello"}),
    (rb"(alpha|beta)", {b"alpha", b"beta"}),
])
def test_atoms_extracted(pattern, expected):
    assert required_atoms(re.compile(pattern, re.S)) == expected


@pytest.mark.parametrize("pattern", [rb"abc|de", rb"[a-z]+", rb"x{3}", rb"MZ.{2}PE", rb"(foo)?bar?"])
def test_no_unsafe_or_useless_atoms(pattern):
    atoms = required_atoms(re.compile(pattern, re.S))
    # Either no prefilter, or every atom is genuinely required (checked by matching samples)
    if atoms:
        for sample in (b"abc", b"de", b"bar", b"ba", b"xxx", b"MZ..PE"):
            if re.search(pattern, sample):
                assert any(a in sample.lower() for a in atoms)


def test_case_insensitive_and_binary_prefilter():
    pf = Prefiltered(re.compile(rb"(?i)DownloadString"))
    assert pf.search(b"x.DOWNLOADSTRING(y)") is not None
    assert pf.search(b"nothing here") is None
    hexpat = Prefiltered(re.compile(rb"\xfc\xe8\x82\x00\x00\x00\x60"))
    assert hexpat.search(b"\x00\xfc\xe8\x82\x00\x00\x00\x60\x89") is not None
