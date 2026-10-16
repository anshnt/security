"""Sigma rule engine: run the community detection-rule format (SigmaHQ) on endpoint events.

Sigma (https://sigmahq.io) is the industry-standard, vendor-neutral format for behaviour
detections. This module is a small pure-Python implementation of the parts of the
specification that matter for Windows endpoint rules, usable both for event-log hunting
(``aegis.scanners.eventlog``) and for real-time process monitoring
(``aegis.realtime.monitor.ProcessGuard``).

Rule sources (``load_rules``): the curated rules bundled in ``aegis/data/sigma``, the
SigmaHQ rules downloaded by ``aegis.tools.sigma_update`` into ``<signatures_dir>/sigma``,
and your own rules in ``<signatures_dir>/sigma_custom``. PyYAML is an optional
dependency (``pip install pyyaml``, extra ``sigma``); without it the engine reports itself
unavailable and every caller skips Sigma gracefully.

Supported
    * selection maps, lists of maps (OR) and keyword lists (searched across every field)
    * field modifiers: contains, startswith, endswith, all, re (+ i/m/s), cidr, windash,
      exists, base64, base64offset (+ utf16le/utf16be/utf16/wide), fieldref, cased,
      lt/lte/gt/gte
    * plain values are case-insensitive with ``*`` / ``?`` wildcards and the Sigma ``\\``
      escape; ``null`` matches a missing or empty field
    * conditions with and / or / not, parentheses, ``1 of x*``, ``all of x*``, ``N of
      them``; several conditions in a list are OR-ed
Not supported (counted in ``SigmaRuleSet.skipped``, never raised): correlation rules,
aggregations (``| count() > n``), ``near``, rule filters, multi-document collections
(``action: global``), unknown modifiers and the ``expand`` modifier.

Events are plain dicts using Sigma field names. Keys starting with ``_`` are routing /
bookkeeping metadata and are invisible to rules: ``_product`` (default ``windows``),
``_category`` (``process_creation``, ``ps_script``, ``registry_set``, ``file_event``,
``network_connection``, ``image_load`` ...), ``_service`` (``security``, ``system``,
``sysmon`` ...), ``_log``, ``_event_id``, ``_ts``. ``events_from_eventlog`` and
``event_from_process`` build such events from the event-log scanner records and from the
real-time process guard's process info.

Detection content downloaded from SigmaHQ is licensed under the Detection Rule License
(DRL) 1.1; the rules bundled with Aegis are original and MIT licensed.
"""

from __future__ import annotations

import base64
import datetime as dt
import fnmatch
import hashlib
import ipaddress
import itertools
import json
import logging
import operator
import re
import subprocess
import time
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from aegis.core.models import Category, Finding, Severity

log = logging.getLogger("aegis.sigma")

BUNDLED_DIR = Path(__file__).resolve().parent.parent / "data" / "sigma"
RULE_SUFFIXES = (".yml", ".yaml")
MAX_RULE_FILE_BYTES = 1 << 20  # a rule file larger than this is not a rule
MAX_FIELD_CHARS = 100_000  # event values are truncated to this before matching (bounds regex cost)
MAX_DOC_RULES = 64  # YAML documents read from one file

DEFAULT_MIN_SEVERITY = Severity.LOW
MAX_FINDINGS_PER_RULE = 10
MAX_LOW_FINDINGS_PER_RULE = 3  # "low" / "informational" rules are generic: never flood a report
MAX_FINDINGS_TOTAL = 300

# =========================================================================== optional PyYAML

_YAML_STATE: Dict[str, Any] = {"tried": False, "module": None}


def _yaml() -> Any:
    """PyYAML, imported on first use; None when it is not installed."""
    if not _YAML_STATE["tried"]:
        _YAML_STATE["tried"] = True
        try:
            import yaml  # type: ignore

            _YAML_STATE["module"] = yaml
        except Exception:  # ImportError, or a broken installation
            _YAML_STATE["module"] = None
    return _YAML_STATE["module"]


def available() -> bool:
    """True when the engine can load rules (PyYAML is importable)."""
    return _yaml() is not None


def _yaml_load_all(text: str) -> List[Any]:
    yaml = _yaml()
    if yaml is None:
        raise RuntimeError("PyYAML is not installed")
    loader = getattr(yaml, "CSafeLoader", None) or yaml.SafeLoader  # safe loaders only: rules are untrusted input
    return list(yaml.load_all(text, Loader=loader))


# =========================================================================== errors


class SigmaError(Exception):
    """A rule cannot be used. ``kind`` is 'invalid' (malformed) or 'unsupported' (valid Sigma we do not implement)."""

    kind = "invalid"


class InvalidRule(SigmaError):
    kind = "invalid"


class UnsupportedRule(SigmaError):
    kind = "unsupported"


# =========================================================================== value patterns


class _Wild:
    __slots__ = ("sym",)

    def __init__(self, sym: str) -> None:
        self.sym = sym

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return self.sym


_STAR = _Wild("*")
_QMARK = _Wild("?")
_ESCAPABLE = "\\*?"


def parse_pattern(text: str) -> List[Any]:
    """Split a Sigma plain value into literal strings and wildcard markers.

    ``*`` / ``?`` are wildcards; a backslash escapes a following ``*``, ``?`` or ``\\``
    (so ``\\\\*`` is a backslash followed by a wildcard and ``\\\\\\\\server`` is ``\\\\server``);
    any other backslash is literal, which keeps Windows paths such as ``\\cmd.exe`` intact."""
    out: List[Any] = []
    buf: List[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "\\" and i + 1 < n and text[i + 1] in _ESCAPABLE:
            buf.append(text[i + 1])
            i += 2
            continue
        if c in "*?":
            if buf:
                out.append("".join(buf))
                buf = []
            if c == "*":
                if not out or out[-1] is not _STAR:
                    out.append(_STAR)
            else:
                out.append(_QMARK)
            i += 1
            continue
        buf.append(c)
        i += 1
    if buf:
        out.append("".join(buf))
    return out


def _compile_atom(tokens: Sequence[Any], mode: str, cased: bool) -> Tuple[str, Any]:
    """One value -> ``(kind, arg)``; kind is eq / prefix / suffix / sub / any / regex.
    Literals are lower-cased unless ``cased`` (events are lower-cased once, not per rule)."""
    toks: List[Any] = []
    if mode in ("contains", "endswith"):
        toks.append(_STAR)
    toks.extend(tokens)
    if mode in ("contains", "startswith"):
        toks.append(_STAR)
    norm: List[Any] = []
    for t in toks:
        if t is _STAR and norm and norm[-1] is _STAR:
            continue
        norm.append(t)

    def fold(s: str) -> str:
        return s if cased else s.lower()

    n = len(norm)
    if n == 0:
        return "eq", ""
    if n == 1 and norm[0] is _STAR:
        return "any", None
    if n == 1 and isinstance(norm[0], str):
        return "eq", fold(norm[0])
    if n == 2 and isinstance(norm[0], str) and norm[1] is _STAR:
        return "prefix", fold(norm[0])
    if n == 2 and norm[0] is _STAR and isinstance(norm[1], str):
        return "suffix", fold(norm[1])
    if n == 3 and norm[0] is _STAR and isinstance(norm[1], str) and norm[2] is _STAR:
        return "sub", fold(norm[1])
    start_anchor, end_anchor = norm[0] is not _STAR, norm[-1] is not _STAR
    core = list(norm)
    if core and core[0] is _STAR:
        core = core[1:]
    if core and core[-1] is _STAR:
        core = core[:-1]
    body = "".join(".*" if t is _STAR else "." if t is _QMARK else re.escape(fold(t)) for t in core)
    return "regex", re.compile(("\\A" if start_anchor else "") + body + ("\\Z" if end_anchor else ""), re.S)


def _atom_fn(atom: Tuple[str, Any]) -> Callable[[str], bool]:
    kind, a = atom
    if kind == "eq":
        return lambda s: s == a
    if kind == "prefix":
        return lambda s: s.startswith(a)
    if kind == "suffix":
        return lambda s: s.endswith(a)
    if kind == "sub":
        return lambda s: a in s
    if kind == "any":
        return lambda s: True
    if kind == "regex":
        search = a.search
        return lambda s: search(s) is not None
    if kind == "fn":
        return a
    raise InvalidRule(f"internal: unknown atom kind {kind}")  # pragma: no cover


def _build_test(atoms: Sequence[Tuple[str, Any]], link_all: bool) -> Optional[Callable[[str], bool]]:
    """Combine the atoms of one field into a single ``str -> bool`` test (OR, or AND for ``|all``)."""
    if not atoms:
        return None
    kinds = {k for k, _ in atoms}
    if link_all and len(atoms) > 1:
        if kinds == {"sub"}:
            subs = tuple(a for _, a in atoms)

            def all_subs(s: str) -> bool:
                for x in subs:
                    if x not in s:
                        return False
                return True

            return all_subs
        fns = [_atom_fn(a) for a in atoms]

        def all_fns(s: str) -> bool:
            for f in fns:
                if not f(s):
                    return False
            return True

        return all_fns
    if "any" in kinds:
        return lambda s: True
    if kinds == {"suffix"}:
        sfx = tuple(a for _, a in atoms)
        return lambda s: s.endswith(sfx)
    if kinds == {"prefix"}:
        pfx = tuple(a for _, a in atoms)
        return lambda s: s.startswith(pfx)
    if kinds == {"eq"}:
        eqs = frozenset(a for _, a in atoms)
        if len(eqs) == 1:
            only = next(iter(eqs))
            return lambda s: s == only
        return lambda s: s in eqs
    if kinds == {"sub"}:
        subs = tuple(a for _, a in atoms)
        if len(subs) == 1:
            only = subs[0]
            return lambda s: only in s

        def any_sub(s: str) -> bool:
            for x in subs:
                if x in s:
                    return True
            return False

        return any_sub
    eqs = frozenset(a for k, a in atoms if k == "eq")
    pfx = tuple(a for k, a in atoms if k == "prefix")
    sfx = tuple(a for k, a in atoms if k == "suffix")
    subs = tuple(a for k, a in atoms if k == "sub")
    others = [_atom_fn(at) for at in atoms if at[0] in ("regex", "fn")]

    def mixed(s: str) -> bool:
        if s in eqs:
            return True
        if pfx and s.startswith(pfx):
            return True
        if sfx and s.endswith(sfx):
            return True
        for x in subs:
            if x in s:
                return True
        for f in others:
            if f(s):
                return True
        return False

    return mixed


# =========================================================================== value transformations

_DASHES = ("-", "/", "\u2013", "\u2014", "\u2015")  # hyphen, slash, en dash, em dash, horizontal bar
_SWITCH_RX = re.compile(r"(?<!\w)[-/](?=\w)")  # a dash or slash that starts a switch: not glued to the previous word
MAX_WINDASH_EXPANSIONS = 3  # like pySigma: more expanded dashes in one value would mean 5**n variants


def windash_variants(value: str) -> List[str]:
    """Sigma ``windash``: Windows tools accept ``-`` ``/`` and the typographic dashes interchangeably for
    command-line switches, so every switch-leading ``-`` or ``/`` (not one inside a word such as
    ``Invoke-Expression``) is replaced by each of them (the first three such positions, as pySigma does)."""
    spots = [m.start() for m in _SWITCH_RX.finditer(value)][:MAX_WINDASH_EXPANSIONS]
    if not spots:
        return [value]
    pieces: List[str] = []
    last = 0
    for pos in spots:
        pieces.append(value[last:pos])
        last = pos + 1
    pieces.append(value[last:])
    out = []
    for combo in itertools.product(_DASHES, repeat=len(spots)):
        text = pieces[0]
        for dash, rest in zip(combo, pieces[1:]):
            text += dash + rest
        out.append(text)
    return list(dict.fromkeys(out))


def base64_offset_variants(data: bytes) -> List[str]:
    """The three base64 renderings of ``data`` that can appear inside a larger base64 string
    (depending on its alignment), with the unstable leading/trailing characters trimmed."""
    start = (0, 2, 3)
    end = (None, -3, -2)
    out = []
    for i in range(3):
        enc = base64.b64encode(i * b" " + data)[start[i]: end[(len(data) + i) % 3]]
        out.append(enc.decode("ascii"))
    return out


_ENCODINGS = {"utf16le": "utf-16-le", "wide": "utf-16-le", "utf16be": "utf-16-be", "utf16": "utf-16"}
_MATCH_MODS = {"contains", "startswith", "endswith", "re", "cidr", "exists", "fieldref", "lt", "lte", "gt", "gte"}
_TRANSFORM_MODS = {"windash", "base64", "base64offset"} | set(_ENCODINGS)
_COMPARE = {"lt": operator.lt, "lte": operator.le, "gt": operator.gt, "gte": operator.ge}


@dataclass
class _Mods:
    match: str = ""
    link_all: bool = False
    cased: bool = False
    re_flags: int = 0
    transforms: List[str] = field(default_factory=list)


def _parse_modifiers(mods: Sequence[str]) -> _Mods:
    m = _Mods()
    for raw in mods:
        name = raw.strip().lower()
        if name == "all":
            m.link_all = True
        elif name == "cased":
            m.cased = True
        elif name in ("i", "m", "s"):
            if m.match != "re":
                raise UnsupportedRule(f"modifier '{raw}' is only valid after 're'")
            m.re_flags |= {"i": re.I, "m": re.M, "s": re.S}[name]
        elif name in _MATCH_MODS:
            if m.match:
                raise UnsupportedRule(f"conflicting modifiers '{m.match}' and '{raw}'")
            m.match = name
        elif name in _TRANSFORM_MODS:
            m.transforms.append(name)
        elif name == "expand":
            raise UnsupportedRule("modifier 'expand' (placeholders) is not supported")
        else:
            raise UnsupportedRule(f"unknown modifier '{raw}'")
    return m


def _as_text(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return v if isinstance(v, str) else str(v)


def _transform_values(values: List[str], mods: _Mods) -> Tuple[List[str], bool, str]:
    """Apply windash / encoding / base64 modifiers. Returns (values, literal_only, match_mode)."""
    literal = False
    cur: List[Any] = list(values)
    mode = mods.match or "equals"
    for t in mods.transforms:
        if t == "windash":
            nxt: List[Any] = []
            for v in cur:
                if not isinstance(v, str):
                    raise UnsupportedRule("windash after an encoding modifier")
                nxt.extend(windash_variants(v))
            cur = nxt
        elif t in _ENCODINGS:
            enc = _ENCODINGS[t]
            if not all(isinstance(v, str) for v in cur):
                raise UnsupportedRule("repeated encoding modifiers")
            cur = [v.encode(enc) for v in cur]
        elif t in ("base64", "base64offset"):
            nxt = []
            for v in cur:
                if isinstance(v, str):
                    if "*" in v or "?" in v:
                        raise UnsupportedRule("wildcards inside a base64 value are not supported")
                    v = v.encode("utf-8")
                if t == "base64":
                    nxt.append(base64.b64encode(v).decode("ascii"))
                else:
                    nxt.extend(base64_offset_variants(v))
            cur = nxt
            literal = True
            if t == "base64offset" and not mods.match:
                mode = "contains"
    if any(not isinstance(v, str) for v in cur):
        raise UnsupportedRule("encoding modifier without base64")
    return cur, literal, mode


@lru_cache(maxsize=8192)
def _parse_ip(text: str) -> Any:
    s = text.strip().strip("[]").split("%")[0]
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return None
    mapped = getattr(ip, "ipv4_mapped", None)
    return mapped or ip


def _cidr_test(values: Sequence[Any]) -> Callable[[str], bool]:
    nets = []
    for v in values:
        try:
            nets.append(ipaddress.ip_network(_as_text(v).strip(), strict=False))
        except ValueError:
            raise InvalidRule(f"invalid CIDR network '{v}'")

    def test(s: str) -> bool:
        ip = _parse_ip(s)
        if ip is None:
            return False
        for n in nets:
            if ip.version == n.version and ip in n:
                return True
        return False

    return test


def _number_test(op: Callable[[float, float], bool], values: Sequence[Any]) -> Callable[[str], bool]:
    refs = []
    for v in values:
        try:
            refs.append(float(v))
        except (TypeError, ValueError):
            raise InvalidRule(f"comparison value '{v}' is not a number")

    def test(s: str) -> bool:
        try:
            x = float(s)
        except ValueError:
            try:
                x = float(int(s, 0))
            except ValueError:
                return False
        for r in refs:
            if op(x, r):
                return True
        return False

    return test


# =========================================================================== event preparation


class _Prepared:
    """An event ready for matching: lower-cased and original values by lower-cased field name."""

    __slots__ = ("raw", "low", "route", "event", "_text", "_rawtext")

    def __init__(self, event: Mapping[str, Any], route: Tuple[str, str, str]) -> None:
        raw: Dict[str, Any] = {}
        low: Dict[str, Any] = {}
        for k, v in event.items():
            if v is None or not isinstance(k, str) or k[:1] == "_":
                continue
            kl = k.lower()
            if isinstance(v, (list, tuple, set, frozenset)):
                items = [_as_text(x)[:MAX_FIELD_CHARS] for x in v if x is not None]
                if not items:
                    continue
                raw[kl] = items
                low[kl] = [x.lower() for x in items]
            else:
                s = _as_text(v)
                if len(s) > MAX_FIELD_CHARS:
                    s = s[:MAX_FIELD_CHARS]
                raw[kl] = s
                low[kl] = s.lower()
        self.raw, self.low, self.route, self.event = raw, low, route, event
        self._text: Optional[str] = None
        self._rawtext: Optional[str] = None

    @staticmethod
    def _join(d: Mapping[str, Any]) -> str:
        parts: List[str] = []
        for v in d.values():
            if v.__class__ is str:
                parts.append(v)
            else:
                parts.extend(v)
        return "\x00".join(parts)

    def text(self) -> str:
        """All field values, lower-cased, for keyword searches."""
        if self._text is None:
            self._text = self._join(self.low)
        return self._text

    def raw_text(self) -> str:
        if self._rawtext is None:
            self._rawtext = self._join(self.raw)
        return self._rawtext


def _route_of(event: Mapping[str, Any]) -> Tuple[str, str, str]:
    return (str(event.get("_product") or "windows").lower(), str(event.get("_category") or "").lower(),
            str(event.get("_service") or "").lower())


# =========================================================================== field matchers

Check = Callable[[_Prepared], bool]


def _field_check(fname: str, mods: _Mods, values: List[Any]) -> Check:
    """Compile ``field|modifiers: values`` into a predicate over a prepared event."""
    fl = fname.lower()
    if mods.match == "exists":
        if len(values) != 1:
            raise InvalidRule("'exists' takes a single true/false value")
        want = values[0] if isinstance(values[0], bool) else _as_text(values[0]).strip().lower() == "true"
        if not fl:
            raise UnsupportedRule("'exists' needs a field name")
        return lambda ev: (fl in ev.low) == want
    if mods.match == "fieldref":
        if not fl:
            raise UnsupportedRule("'fieldref' needs a field name")
        refs = [_as_text(v).lower() for v in values]

        def fieldref(ev: _Prepared) -> bool:
            a = ev.low.get(fl)
            if a is None:
                return False
            hits = [(a == ev.low.get(r)) if a.__class__ is str else (ev.low.get(r) in a) for r in refs
                    if ev.low.get(r) is not None]
            if mods.link_all:
                return len(hits) == len(refs) and all(hits)
            return any(hits)

        return fieldref

    allow_null = any(v is None for v in values)
    values = [v for v in values if v is not None]
    atoms: List[Tuple[str, Any]] = []
    use_raw = mods.cased
    if values:
        if mods.match == "re":
            if mods.transforms:
                raise UnsupportedRule("modifiers before 're' are not supported")
            for v in values:
                try:
                    rx = re.compile(_as_text(v), mods.re_flags)
                except re.error as exc:
                    raise UnsupportedRule(f"invalid regular expression {v!r}: {exc}")
                atoms.append(("regex", rx))
            use_raw = True
        elif mods.match == "cidr":
            if mods.transforms:
                raise UnsupportedRule("modifiers before 'cidr' are not supported")
            atoms.append(("fn", _cidr_test(values)))
        elif mods.match in _COMPARE:
            atoms.append(("fn", _number_test(_COMPARE[mods.match], values)))
        else:
            texts = [_as_text(v) for v in values]
            texts, literal, mode = _transform_values(texts, mods)
            if literal:
                use_raw = True  # base64 is case sensitive
            for t in texts:
                atoms.append(_compile_atom([t] if literal else parse_pattern(t), mode, use_raw))
    test = _build_test(atoms, mods.link_all)

    if not fl:  # keyword-style: search every field value
        if allow_null or test is None:
            raise UnsupportedRule("null or empty value without a field name")
        kw = test
        return (lambda ev: kw(ev.raw_text())) if use_raw else (lambda ev: kw(ev.text()))

    if test is None:  # only null: the field must be missing or empty
        return lambda ev: not ev.low.get(fl)
    t = test

    def check(ev: _Prepared) -> bool:
        v = (ev.raw if use_raw else ev.low).get(fl)
        if v is None:
            return allow_null
        if v.__class__ is str:
            if allow_null and not v:
                return True
            return t(v)
        for x in v:
            if t(x):
                return True
        return False

    return check


def _all_checks(checks: Sequence[Check]) -> Check:
    if len(checks) == 1:
        return checks[0]
    if len(checks) == 2:
        a, b = checks
        return lambda ev: a(ev) and b(ev)
    seq = tuple(checks)

    def run(ev: _Prepared) -> bool:
        for c in seq:
            if not c(ev):
                return False
        return True

    return run


def _any_checks(checks: Sequence[Check]) -> Check:
    if len(checks) == 1:
        return checks[0]
    if len(checks) == 2:
        a, b = checks
        return lambda ev: a(ev) or b(ev)
    seq = tuple(checks)

    def run(ev: _Prepared) -> bool:
        for c in seq:
            if c(ev):
                return True
        return False

    return run


# =========================================================================== selections


class _Selection:
    """One named search identifier. ``maps`` are the OR-ed field maps (each: check + the fields it constrains);
    ``keywords`` the OR-ed keyword values."""

    __slots__ = ("test", "maps", "keywords")

    def __init__(self, test: Check, maps: List[Tuple[Check, List[Tuple[str, str]]]],
                 keywords: List[Tuple[str, Callable[[str], bool]]]) -> None:
        self.test, self.maps, self.keywords = test, maps, keywords

    def collect(self, ev: _Prepared, out: Dict[str, Any]) -> None:
        """Add the event values that made this (already matching) selection true."""
        for check, fields in self.maps:
            if check(ev):
                for display, fl in fields:
                    v = ev.raw.get(fl)
                    if v is not None:
                        out[display] = v
                return
        if self.keywords:
            text = ev.text()
            hit = [kw for kw, fn in self.keywords if fn(text)]
            if hit:
                out.setdefault("keywords", []).extend(hit)


def _compile_map(name: str, spec: Mapping[str, Any]) -> Tuple[Check, List[Tuple[str, str]]]:
    if not spec:
        raise InvalidRule(f"selection '{name}' is empty")
    checks: List[Check] = []
    fields: List[Tuple[str, str]] = []
    for key, val in spec.items():
        parts = str(key).split("|")
        fname, mods = parts[0].strip(), _parse_modifiers(parts[1:])
        if isinstance(val, (list, tuple)):
            values = list(val)
        else:
            values = [val]
        if not values or any(isinstance(v, (Mapping, list, tuple)) for v in values):
            raise InvalidRule(f"selection '{name}': invalid value for '{key}'")
        if not fname and not mods.match:
            mods.match = "contains"  # '|all': [...] style keyword maps search the whole event
        checks.append(_field_check(fname, mods, values))
        if fname and mods.match != "exists":
            fields.append((fname, fname.lower()))
    return _all_checks(checks), fields


def _compile_selection(name: str, spec: Any) -> _Selection:
    if isinstance(spec, Mapping):
        maps_spec: List[Any] = [spec]
    elif isinstance(spec, (list, tuple)):
        if not spec:
            raise InvalidRule(f"selection '{name}' is empty")
        if all(isinstance(x, Mapping) for x in spec):
            maps_spec = list(spec)
        elif all(not isinstance(x, (Mapping, list, tuple)) and x is not None for x in spec):
            return _keyword_selection(name, list(spec))
        else:
            raise UnsupportedRule(f"selection '{name}' mixes keywords and field maps")
    elif spec is None:
        raise InvalidRule(f"selection '{name}' is empty")
    else:
        return _keyword_selection(name, [spec])
    maps = [_compile_map(name, m) for m in maps_spec]
    return _Selection(_any_checks([c for c, _ in maps]), maps, [])


def _keyword_selection(name: str, words: List[Any]) -> _Selection:
    atoms = [_compile_atom(parse_pattern(_as_text(w)), "contains", False) for w in words]
    test = _build_test(atoms, False)
    if test is None:
        raise InvalidRule(f"selection '{name}' has no keywords")
    kws = [(_as_text(w), _atom_fn(a)) for w, a in zip(words, atoms)]
    return _Selection(lambda ev: test(ev.text()), [], kws)


# =========================================================================== conditions

_COND_TOKEN = re.compile(r"\(|\)|[^\s()]+")


def _parse_condition(text: str, names: Sequence[str]) -> Any:
    """Condition string -> AST: ('sel', name) | ('not', x) | ('and'|'or', [x..]) | ('quant', count|'all', [names])."""
    if "|" in text:
        raise UnsupportedRule("aggregation conditions (count/min/max/sum/avg/near) are not supported")
    toks = _COND_TOKEN.findall(text)
    if not toks:
        raise InvalidRule("empty condition")
    if any(t.lower() == "near" for t in toks):
        raise UnsupportedRule("'near' conditions are not supported")
    pos = [0]
    nameset = set(names)

    def peek() -> Optional[str]:
        return toks[pos[0]] if pos[0] < len(toks) else None

    def take() -> str:
        t = toks[pos[0]]
        pos[0] += 1
        return t

    def resolve(pattern: str) -> List[str]:
        if pattern.lower() == "them":
            got = [n for n in names if not n.startswith("_")]
        elif any(c in pattern for c in "*?["):
            got = [n for n in names if fnmatch.fnmatchcase(n, pattern)]
        else:
            got = [pattern] if pattern in nameset else []
        if not got:
            raise InvalidRule(f"condition refers to unknown selection '{pattern}'")
        return got

    def parse_or() -> Any:
        items = [parse_and()]
        while (peek() or "").lower() == "or":
            take()
            items.append(parse_and())
        return items[0] if len(items) == 1 else ("or", items)

    def parse_and() -> Any:
        items = [parse_not()]
        while (peek() or "").lower() == "and":
            take()
            items.append(parse_not())
        return items[0] if len(items) == 1 else ("and", items)

    def parse_not() -> Any:
        if (peek() or "").lower() == "not":
            take()
            return ("not", parse_not())
        return parse_atom()

    def parse_atom() -> Any:
        t = peek()
        if t is None:
            raise InvalidRule("condition ends unexpectedly")
        if t == "(":
            take()
            node = parse_or()
            if peek() != ")":
                raise InvalidRule("unbalanced parentheses in condition")
            take()
            return node
        if t == ")":
            raise InvalidRule("unbalanced parentheses in condition")
        take()
        if pos[0] < len(toks) and toks[pos[0]].lower() == "of" and (t.isdigit() or t.lower() in ("all", "any")):
            take()
            if peek() is None:
                raise InvalidRule("'of' needs a selection pattern")
            names_matched = resolve(take())
            count: Any = "all" if t.lower() == "all" else (1 if t.lower() == "any" else int(t))
            return ("quant", count, names_matched)
        if t.lower() in ("and", "or", "of"):
            raise InvalidRule(f"unexpected '{t}' in condition")
        if t not in nameset:
            raise InvalidRule(f"condition refers to unknown selection '{t}'")
        return ("sel", t)

    node = parse_or()
    if peek() is not None:
        raise InvalidRule(f"unexpected '{peek()}' in condition")
    return node


def _positive_names(node: Any, negated: bool = False) -> List[str]:
    """Selections whose truth contributes to a match (not under an odd number of 'not')."""
    kind = node[0]
    if kind == "sel":
        return [] if negated else [node[1]]
    if kind == "not":
        return _positive_names(node[1], not negated)
    if kind == "quant":
        return [] if negated else list(node[2])
    out: List[str] = []
    for child in node[1]:
        out += _positive_names(child, negated)
    return out


def _compile_condition(node: Any, fns: Mapping[str, Check]) -> Check:
    kind = node[0]
    if kind == "sel":
        return fns[node[1]]
    if kind == "not":
        inner = _compile_condition(node[1], fns)
        return lambda ev: not inner(ev)
    if kind == "and":
        return _all_checks([_compile_condition(c, fns) for c in node[1]])
    if kind == "or":
        return _any_checks([_compile_condition(c, fns) for c in node[1]])
    count, members = node[1], tuple(fns[n] for n in node[2])
    if count == "all":
        return _all_checks(list(members))
    if count == 1:
        return _any_checks(list(members))

    def at_least(ev: _Prepared) -> bool:
        hits = 0
        for f in members:
            if f(ev):
                hits += 1
                if hits >= count:
                    return True
        return False

    return at_least


# =========================================================================== MITRE / severity helpers

_ATTACK_TAG = re.compile(r"^attack\.(t\d{4})(?:\.(\d{3}))?$", re.I)
_RETIRED_STATE: Dict[str, Any] = {"map": None}


def _retired_map() -> Dict[str, str]:
    """ATT&CK ids retired in v20 -> replacement, from ``aegis/data/sigma/attack_v20_remap.tsv``
    (community rules still carry the old ids in their tags)."""
    if _RETIRED_STATE["map"] is None:
        out: Dict[str, str] = {}
        try:
            for line in (BUNDLED_DIR / "attack_v20_remap.tsv").read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    old, _, new = line.partition("\t")
                    if old and new:
                        out[old.strip().upper()] = new.strip().upper()
        except OSError:
            pass
        _RETIRED_STATE["map"] = out
    return _RETIRED_STATE["map"]


def attack_ids_from_tags(tags: Iterable[Any]) -> List[str]:
    """``attack.t1059.001`` -> ``T1059.001``; tactic / group / software tags are ignored; retired ids are
    replaced by their ATT&CK v20 successors."""
    remap = _retired_map()
    out: List[str] = []
    for tag in tags or []:
        m = _ATTACK_TAG.match(str(tag).strip())
        if not m:
            continue
        tid = m.group(1).upper() + (("." + m.group(2)) if m.group(2) else "")
        tid = remap.get(tid, tid)
        if tid not in out:
            out.append(tid)
    return out


_LEVELS = {"informational": 0, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def level_to_severity(level: Any, status: Any = "") -> Severity:
    """Sigma level -> Severity. Experimental / test rules have not been validated at scale, so they are
    downgraded one step; an unknown level is treated as low."""
    base = _LEVELS.get(str(level or "").strip().lower(), 1)
    if str(status or "").strip().lower() in ("experimental", "test"):
        base = max(0, base - 1)
    return Severity(base)


# =========================================================================== rules


def _str_list(v: Any) -> List[str]:
    if v is None:
        return []
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v if x is not None]
    return [str(v)]


@dataclass(eq=False)
class SigmaRule:
    id: str
    title: str
    status: str = ""
    level: str = ""
    description: str = ""
    author: str = ""
    date: str = ""
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    falsepositives: List[str] = field(default_factory=list)
    product: str = ""
    category: str = ""
    service: str = ""
    source: str = ""
    origin: str = ""
    mitre: List[str] = field(default_factory=list)
    positive: Tuple[str, ...] = ()
    selections: Dict[str, _Selection] = field(default_factory=dict, repr=False)
    _check: Optional[Check] = field(default=None, repr=False)

    @property
    def rule_id(self) -> str:
        """Finding rule id: ``SIGMA-`` + the first 8 characters of the Sigma rule id."""
        return "SIGMA-" + (self.id.replace("-", "")[:8] if self.id else "00000000")

    @property
    def severity(self) -> Severity:
        return level_to_severity(self.level, self.status)

    @property
    def logsource(self) -> Dict[str, str]:
        return {k: v for k, v in (("product", self.product), ("category", self.category), ("service", self.service)) if v}

    def matches(self, ev: _Prepared) -> bool:
        return bool(self._check(ev)) if self._check else False

    def explain(self, ev: _Prepared) -> Dict[str, Any]:
        """The event field values that satisfied this rule's selections."""
        out: Dict[str, Any] = {}
        for name in self.positive:
            sel = self.selections.get(name)
            if sel is not None and sel.test(ev):
                sel.collect(ev, out)
        return out


_KNOWN_KEYS_IGNORED = {"timeframe"}


def rule_from_dict(doc: Mapping[str, Any], source: str = "", origin: str = "") -> SigmaRule:
    """Compile one parsed Sigma rule. Raises ``UnsupportedRule`` / ``InvalidRule``."""
    if not isinstance(doc, Mapping):
        raise InvalidRule("a Sigma rule must be a mapping")
    if "correlation" in doc:
        raise UnsupportedRule("correlation rules are not supported")
    if doc.get("action") in ("global", "reset", "repeat"):
        raise UnsupportedRule("multi-document rule collections (action: global/reset/repeat) are not supported")
    if "filter" in doc and "detection" not in doc:
        raise UnsupportedRule("rule filters are not supported")
    title = str(doc.get("title") or "").strip()
    if not title:
        raise InvalidRule("missing title")
    det = doc.get("detection")
    if not isinstance(det, Mapping):
        raise InvalidRule("missing detection")
    ls = doc.get("logsource")
    if not isinstance(ls, Mapping):
        raise InvalidRule("missing logsource")
    cond = det.get("condition")
    if cond is None:
        raise InvalidRule("missing condition")
    conds = [str(c) for c in cond] if isinstance(cond, (list, tuple)) else [str(cond)]

    sel_specs = {str(k): v for k, v in det.items() if k != "condition" and k not in _KNOWN_KEYS_IGNORED}
    if not sel_specs:
        raise InvalidRule("no search identifiers in detection")
    selections: Dict[str, _Selection] = {}
    for name, spec in sel_specs.items():
        try:
            selections[name] = _compile_selection(name, spec)
        except SigmaError:
            raise
        except Exception as exc:  # a bug must never take the rule loader down
            raise InvalidRule(f"selection '{name}': {type(exc).__name__}: {exc}")
    names = list(selections)
    asts = [_parse_condition(c, names) for c in conds]
    check = _any_checks([_compile_condition(a, {n: s.test for n, s in selections.items()}) for a in asts])
    positive: List[str] = []
    for a in asts:
        for n in _positive_names(a):
            if n not in positive:
                positive.append(n)

    rid = str(doc.get("id") or "").strip()
    if not rid:
        rid = hashlib.sha1(f"{title}|{source}".encode("utf-8", "replace")).hexdigest()
    desc = " ".join(str(doc.get("description") or "").split())
    tags = _str_list(doc.get("tags"))
    return SigmaRule(
        id=rid, title=title, status=str(doc.get("status") or "").strip().lower(),
        level=str(doc.get("level") or "").strip().lower(), description=desc, author=str(doc.get("author") or ""),
        date=str(doc.get("date") or ""), references=_str_list(doc.get("references")), tags=tags,
        falsepositives=_str_list(doc.get("falsepositives")),
        product=str(ls.get("product") or "").strip().lower(), category=str(ls.get("category") or "").strip().lower(),
        service=str(ls.get("service") or "").strip().lower(), source=source, origin=origin,
        mitre=attack_ids_from_tags(tags), positive=tuple(positive), selections=selections, _check=check)


@dataclass
class Skipped:
    """A rule that was read but cannot be used."""

    source: str
    title: str
    reason: str
    kind: str  # unsupported | invalid | status | error


def parse_rules_text(text: str, source: str = "", origin: str = "",
                     categories: Optional[Sequence[str]] = None) -> Tuple[List[SigmaRule], List[Skipped]]:
    """Parse the Sigma rule(s) in a YAML text. Never raises: problems become ``Skipped`` entries.
    ``categories`` keeps only rules of those logsource categories (others are dropped silently)."""
    rules: List[SigmaRule] = []
    skipped: List[Skipped] = []
    if categories:  # cheap text pre-filter: do not YAML-parse files that cannot contain a wanted category
        wanted_rx = re.compile(r"category['\"]?\s*:\s*['\"]?(?:%s)\b" % "|".join(re.escape(c) for c in categories), re.I)
        if not wanted_rx.search(text):
            return rules, skipped
    try:
        docs = _yaml_load_all(text)
    except Exception as exc:
        first_line = (str(exc).splitlines() or [type(exc).__name__])[0][:160]
        return rules, [Skipped(source, "", f"YAML error: {first_line}", "invalid")]
    wanted = {c.lower() for c in categories} if categories else None
    for doc in docs[:MAX_DOC_RULES]:
        if doc is None:
            continue
        title = str(doc.get("title", "")) if isinstance(doc, Mapping) else ""
        try:
            if wanted is not None and isinstance(doc, Mapping):
                ls = doc.get("logsource")
                if not isinstance(ls, Mapping) or str(ls.get("category") or "").lower() not in wanted:
                    continue
            rule = rule_from_dict(doc, source, origin)
            if rule.status in ("deprecated", "unsupported"):
                skipped.append(Skipped(source, rule.title, f"rule status is '{rule.status}'", "status"))
                continue
            rules.append(rule)
        except SigmaError as exc:
            skipped.append(Skipped(source, title, str(exc), exc.kind))
        except Exception as exc:
            log.debug("sigma: unexpected error in %s", source, exc_info=True)
            skipped.append(Skipped(source, title, f"{type(exc).__name__}: {exc}", "error"))
    return rules, skipped


def load_rule_file(path: Any, origin: str = "", categories: Optional[Sequence[str]] = None
                   ) -> Tuple[List[SigmaRule], List[Skipped]]:
    p = Path(path)
    try:
        if p.stat().st_size > MAX_RULE_FILE_BYTES:
            return [], [Skipped(str(p), "", "file too large", "invalid")]
        text = p.read_bytes().decode("utf-8-sig", "replace")
    except OSError as exc:
        return [], [Skipped(str(p), "", f"cannot read: {exc}", "invalid")]
    return parse_rules_text(text, str(p), origin, categories)


def iter_rule_files(directory: Any) -> List[Path]:
    d = Path(directory)
    if not d.is_dir():
        return []
    return sorted(p for p in d.rglob("*") if p.suffix.lower() in RULE_SUFFIXES and p.is_file())


# =========================================================================== rule set

CATEGORY_ALIASES: Dict[str, Tuple[str, ...]] = {
    "registry_set": ("registry_set", "registry_event"),
    "registry_add": ("registry_add", "registry_event"),
    "registry_delete": ("registry_delete", "registry_event"),
    "registry_rename": ("registry_rename", "registry_event"),
}


class SigmaRuleSet:
    """Loaded rules, indexed by logsource so an event only runs against relevant rules."""

    def __init__(self, rules: Iterable[SigmaRule] = (), skipped: Iterable[Skipped] = (), is_available: bool = True,
                 reason: str = "", signature: str = "") -> None:
        self.skipped: List[Skipped] = list(skipped)
        self.available = bool(is_available)
        self.reason = reason
        self.signature = signature
        self._by_id: Dict[str, SigmaRule] = {}
        self._index: Dict[Tuple[str, str, str], List[SigmaRule]] = {}
        self._cache: Dict[Tuple[str, str, str], Tuple[SigmaRule, ...]] = {}
        for r in rules:
            self.add(r)

    # ---- content
    def add(self, rule: SigmaRule) -> None:
        """Add a rule; a later rule with the same Sigma id replaces the earlier one (downloaded over bundled)."""
        old = self._by_id.get(rule.id)
        if old is not None:
            key = (old.product, old.category, old.service)
            bucket = self._index.get(key, [])
            if old in bucket:
                bucket.remove(old)
        self._by_id[rule.id] = rule
        self._index.setdefault((rule.product, rule.category, rule.service), []).append(rule)
        self._cache.clear()

    @property
    def rules(self) -> List[SigmaRule]:
        return list(self._by_id.values())

    def __len__(self) -> int:
        return len(self._by_id)

    def __bool__(self) -> bool:
        return bool(self._by_id)

    def get(self, rule_id: str) -> Optional[SigmaRule]:
        return self._by_id.get(rule_id)

    def summary(self) -> Dict[str, Any]:
        by_kind: Dict[str, int] = {}
        for s in self.skipped:
            by_kind[s.kind] = by_kind.get(s.kind, 0) + 1
        by_origin: Dict[str, int] = {}
        by_category: Dict[str, int] = {}
        for r in self._by_id.values():
            by_origin[r.origin or "?"] = by_origin.get(r.origin or "?", 0) + 1
            k = r.category or (f"service:{r.service}" if r.service else "other")
            by_category[k] = by_category.get(k, 0) + 1
        return {"available": self.available, "reason": self.reason, "rules": len(self._by_id),
                "skipped": dict(by_kind), "unsupported": by_kind.get("unsupported", 0), "by_origin": by_origin,
                "by_category": by_category}

    # ---- matching
    def _candidates(self, route: Tuple[str, str, str]) -> Tuple[SigmaRule, ...]:
        got = self._cache.get(route)
        if got is None:
            product, category, service = route
            cats = CATEGORY_ALIASES.get(category, (category,)) if category else ()
            out: List[SigmaRule] = []
            for p in dict.fromkeys((product, "")):
                keys = [(p, "", "")]
                for c in cats:
                    keys.append((p, c, ""))
                    if service:
                        keys.append((p, c, service))
                if service:
                    keys.append((p, "", service))
                for k in keys:
                    out.extend(self._index.get(k, ()))
            got = self._cache[route] = tuple(out)
        return got

    def candidates(self, event: Mapping[str, Any]) -> Tuple[SigmaRule, ...]:
        """Rules whose logsource fits this event."""
        return self._candidates(_route_of(event))

    def _match(self, event: Mapping[str, Any], ignore_logsource: bool = False
               ) -> Optional[List[Tuple[SigmaRule, Dict[str, Any]]]]:
        """Matches, or None when no rule's logsource fits the event (so it was not evaluated)."""
        if not self._by_id:
            return None
        route = event.route if isinstance(event, _Prepared) else _route_of(event)
        cands = tuple(self._by_id.values()) if ignore_logsource else self._candidates(route)
        if not cands:
            return None
        ev = event if isinstance(event, _Prepared) else _Prepared(event, route)
        out: List[Tuple[SigmaRule, Dict[str, Any]]] = []
        for rule in cands:
            try:
                if rule._check(ev):  # type: ignore[misc]
                    out.append((rule, rule.explain(ev)))
            except Exception:
                log.debug("sigma rule %s failed on an event", rule.id, exc_info=True)
        return out

    def match(self, event: Mapping[str, Any], ignore_logsource: bool = False) -> List[Tuple[SigmaRule, Dict[str, Any]]]:
        """Every rule that matches ``event`` as ``(rule, matched_fields)``. ``ignore_logsource`` evaluates all
        rules regardless of the event's ``_category`` / ``_service`` (for events without routing metadata)."""
        return self._match(event, ignore_logsource) or []


# =========================================================================== loading


def rule_directories(config: Any = None) -> List[Tuple[Path, str]]:
    """(directory, origin) pairs in load order; later directories override earlier rules with the same id."""
    dirs: List[Tuple[Path, str]] = [(BUNDLED_DIR, "bundled")]
    if config is None:
        return dirs  # no configuration: the bundled rules only (never reads machine-wide state)
    try:
        from aegis.core.config import shared_signatures_dir

        shared = shared_signatures_dir()
    except Exception:
        shared = None
    own: Optional[Path] = None
    try:
        own = Path(config.signatures_dir)
    except Exception:
        own = None
    if shared is not None and (own is None or shared.resolve() != own.resolve()):
        dirs.append((shared / "sigma", "downloaded"))
    if own is not None:
        dirs.append((own / "sigma", "downloaded"))
        dirs.append((own / "sigma_custom", "custom"))
    return dirs


def rules_signature(config: Any = None) -> str:
    """Cheap fingerprint of the rule files on disk (count + newest mtime): changes when rules are updated."""
    count, newest = 0, 0
    for d, _ in rule_directories(config):
        for p in iter_rule_files(d):
            try:
                newest = max(newest, p.stat().st_mtime_ns)
                count += 1
            except OSError:
                continue
    return f"{count}:{newest}"


def load_rules(config: Any = None, categories: Optional[Sequence[str]] = None, include_bundled: bool = True,
               extra_dirs: Sequence[Any] = ()) -> SigmaRuleSet:
    """Load the bundled, downloaded and custom Sigma rules.

    Returns an empty rule set with ``available == False`` when PyYAML is missing. ``categories`` limits the load to
    those logsource categories (the real-time guard only needs ``process_creation``)."""
    if not available():
        return SigmaRuleSet(is_available=False, reason="PyYAML is not installed (pip install pyyaml)")
    rules: List[SigmaRule] = []
    skipped: List[Skipped] = []
    dirs = [(d, o) for d, o in rule_directories(config) if include_bundled or o != "bundled"]
    dirs += [(Path(d), "custom") for d in extra_dirs]
    for d, origin in dirs:
        for p in iter_rule_files(d):
            r, s = load_rule_file(p, origin, categories)
            rules += r
            skipped += s
    try:
        sig = rules_signature(config)
    except Exception:
        sig = ""
    rs = SigmaRuleSet(rules, skipped, True, "", sig)
    if skipped:
        log.debug("sigma: %d rules loaded, %d skipped", len(rs), len(skipped))
    return rs


# =========================================================================== event conversion

SYSMON_CATEGORIES: Dict[int, str] = {
    1: "process_creation", 2: "file_change", 3: "network_connection", 5: "process_termination", 6: "driver_load",
    7: "image_load", 8: "create_remote_thread", 9: "raw_access_thread", 10: "process_access", 11: "file_event",
    12: "registry_add", 13: "registry_set", 14: "registry_rename", 15: "create_stream_hash", 17: "pipe_created",
    18: "pipe_created", 19: "wmi_event", 20: "wmi_event", 21: "wmi_event", 22: "dns_query", 23: "file_delete",
    24: "clipboard_change", 25: "process_tampering", 26: "file_delete", 27: "file_block_executable",
    28: "file_block_shredding", 29: "file_executable_detected",
}

# eventlog.py log key -> (channel, sigma service, default provider name)
_LOG_INFO: Dict[str, Tuple[str, str, str]] = {
    "Security": ("Security", "security", "Microsoft-Windows-Security-Auditing"),
    "System": ("System", "system", "Service Control Manager"),
    "PowerShell": ("Microsoft-Windows-PowerShell/Operational", "powershell", "Microsoft-Windows-PowerShell"),
    "Defender": ("Microsoft-Windows-Windows Defender/Operational", "windefend", "Microsoft-Windows-Windows Defender"),
    "WMI": ("Microsoft-Windows-WMI-Activity/Operational", "wmi", "Microsoft-Windows-WMI-Activity"),
    "Sysmon": ("Microsoft-Windows-Sysmon/Operational", "sysmon", "Microsoft-Windows-Sysmon"),
}
_EVENTLOG_PROVIDER_BY_ID = {1102: "Microsoft-Windows-Eventlog", 104: "Microsoft-Windows-Eventlog"}
_INTEGRITY_BY_RID = {"4096": "Low", "8192": "Medium", "8448": "Medium", "12288": "High", "16384": "System"}


def _fmt_time(ts: Any) -> str:
    try:
        return dt.datetime.fromtimestamp(float(ts), dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (TypeError, ValueError, OverflowError, OSError):
        return "unknown time"


def _integrity_from_label(label: str) -> str:
    m = re.search(r"S-1-16-(\d+)", label or "")
    return _INTEGRITY_BY_RID.get(m.group(1), "") if m else ""


def _security_user(data: Mapping[str, Any]) -> str:
    user, dom = str(data.get("SubjectUserName") or ""), str(data.get("SubjectDomainName") or "")
    if user and dom and dom != "-":
        return f"{dom}\\{user}"
    return user


def _one_eventlog_event(ev: Mapping[str, Any], data_override: Optional[Mapping[str, Any]] = None
                        ) -> Optional[Dict[str, Any]]:
    log_key = str(ev.get("log") or "")
    try:
        eid = int(ev.get("id") or 0)
    except (TypeError, ValueError):
        return None
    channel, service, default_provider = _LOG_INFO.get(log_key, (log_key, log_key.lower(), ""))
    data = dict(data_override if data_override is not None else (ev.get("data") or {}))
    out: Dict[str, Any] = {k: v for k, v in data.items() if v not in (None, "")}

    def put(key: str, value: Any) -> None:
        if value not in (None, "") and key not in out:
            out[key] = value

    out["EventID"] = str(eid)
    out["Channel"] = channel
    out["Provider_Name"] = str(ev.get("provider") or "") or _EVENTLOG_PROVIDER_BY_ID.get(eid) or default_provider
    put("Computer", ev.get("computer"))
    out["_product"] = "windows"
    out["_service"] = service
    out["_log"] = log_key
    out["_event_id"] = eid
    out["_ts"] = ev.get("ts")
    category = ""
    if log_key == "Sysmon":
        category = SYSMON_CATEGORIES.get(eid, "")
        if eid == 12:
            category = "registry_delete" if "delete" in str(data.get("EventType", "")).lower() else "registry_add"
    elif log_key == "Security" and eid == 4688:
        category = "process_creation"
        put("Image", data.get("NewProcessName"))
        put("ParentImage", data.get("ParentProcessName"))
        put("User", _security_user(data))
        # in 4688 the native "ProcessId" is the *creator's* id; Sigma's ProcessId is the new process (as in pySigma)
        if data.get("NewProcessId"):
            out["ProcessId"] = data["NewProcessId"]
        if data.get("ProcessId"):
            out["ParentProcessId"] = data["ProcessId"]
        put("IntegrityLevel", _integrity_from_label(str(data.get("MandatoryLabel", ""))))
    elif log_key == "PowerShell" and eid == 4104:
        category = "ps_script"
    if category:
        out["_category"] = category
    return out


def events_from_eventlog(events: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """Convert the normalised records of ``aegis.scanners.eventlog`` (``{id, log, ts, provider, data, ...}``)
    into Sigma events. Sysmon events keep their native field names; Security 4688 gets the Sigma process fields
    (Image, ParentImage, User, IntegrityLevel) next to the native ones; PowerShell 4104 parts are re-assembled
    into one ``ScriptBlockText`` event per script block."""
    records = [e for e in events if isinstance(e, Mapping)]
    out: List[Dict[str, Any]] = []
    for e in records:
        if e.get("log") == "PowerShell" and e.get("id") == 4104:
            continue
        conv = _one_eventlog_event(e)
        if conv is not None:
            out.append(conv)
    blocks: Dict[str, Dict[str, Any]] = {}
    ps = sorted((e for e in records if e.get("log") == "PowerShell" and e.get("id") == 4104),
                key=lambda e: e.get("ts") or 0)
    for e in ps:
        d = e.get("data") or {}
        bid = str(d.get("ScriptBlockId") or "") or f"anon-{id(e)}"
        slot = blocks.setdefault(bid, {"parts": {}, "ev": e})
        try:
            num = int(d.get("MessageNumber") or 1)
        except (TypeError, ValueError):
            num = 1
        slot["parts"][num] = str(d.get("ScriptBlockText") or "")
    for slot in blocks.values():
        data = dict(slot["ev"].get("data") or {})
        data["ScriptBlockText"] = "".join(slot["parts"][n] for n in sorted(slot["parts"]))
        conv = _one_eventlog_event(slot["ev"], data)
        if conv is not None:
            out.append(conv)
    return out


def _cmdline_text(cmdline: Any) -> str:
    if isinstance(cmdline, (list, tuple)):
        return subprocess.list2cmdline([str(a) for a in cmdline])
    return str(cmdline or "")


def event_from_process(info: Mapping[str, Any], product: str = "windows") -> Dict[str, Any]:
    """Sigma ``process_creation`` event from the real-time process guard's process info
    (``pid, name, exe, cmdline (list), ppid, parent_name, parent_exe, parent_cmdline, username``)."""
    exe = str(info.get("exe") or "")
    name = str(info.get("name") or "")
    parent_exe = str(info.get("parent_exe") or "")
    parent_name = str(info.get("parent_name") or "")
    ev: Dict[str, Any] = {
        "Image": exe or name,
        "CommandLine": _cmdline_text(info.get("cmdline")),
        "ParentImage": parent_exe or parent_name,
        "ParentCommandLine": _cmdline_text(info.get("parent_cmdline")),
        "User": str(info.get("username") or ""),
        "ProcessId": str(info.get("pid", "")),
        "ParentProcessId": str(info.get("ppid", "")),
        "_product": product, "_category": "process_creation", "_log": "ProcessGuard", "_ts": info.get("create_time"),
        "_pid": info.get("pid"),
    }
    return {k: v for k, v in ev.items() if v not in ("", None)}


# =========================================================================== findings

_IGNORED_FP = {"unknown", "unlikely", "none", "n/a", "na", "-", "not available"}
_EVENT_FIELDS = ("Image", "CommandLine", "ParentImage", "ParentCommandLine", "User", "IntegrityLevel", "TargetObject",
                 "Details", "TargetFilename", "DestinationIp", "DestinationPort", "DestinationHostname", "ImageLoaded",
                 "ScriptBlockText", "ServiceName", "ImagePath", "ServiceFileName", "TaskName", "EventID", "Provider_Name")


def _clip(value: Any, n: int = 600) -> Any:
    if isinstance(value, (list, tuple)):
        return [_clip(v, n) for v in value[:10]]
    s = value if isinstance(value, str) else str(value)
    return s if len(s) <= n else s[:n] + "..."


def _base_name(path: str) -> str:
    return re.split(r"[\\/]", (path or "").strip().strip('"'))[-1]


def _summary(ev: Mapping[str, Any]) -> str:
    """Short, human readable description of an event (also the identity used to collapse repeats)."""
    image = _base_name(str(ev.get("Image") or ev.get("NewProcessName") or ""))
    for key, label in (("CommandLine", ""), ("ScriptBlockText", "script: "), ("TargetObject", "registry: "),
                       ("TargetFilename", "file: "), ("ImagePath", "service: "), ("ServiceFileName", "service: "),
                       ("TaskName", "task: ")):
        val = ev.get(key)
        if val:
            text = " ".join(str(val).split())
            if key == "TargetObject" and ev.get("Details"):
                text += " = " + " ".join(str(ev["Details"]).split())[:120]
            if len(text) > 160:
                text = text[:160] + "..."
            return label + text
    if ev.get("DestinationIp"):
        return f"{image or 'connection'} -> {ev.get('DestinationIp')}:{ev.get('DestinationPort', '')}"
    if ev.get("ImageLoaded"):
        return f"{image or 'process'} loaded {ev['ImageLoaded']}"
    return image or f"event {ev.get('EventID', '?')}"


def _category_for(rule: SigmaRule) -> str:
    tags = {t.lower() for t in rule.tags}
    if "attack.persistence" in tags:
        return Category.PERSISTENCE
    if any(re.fullmatch(r"attack\.s\d{4}", t) for t in tags) or "detection.emerging_threats" in tags:
        return Category.MALWARE
    return Category.SUSPICIOUS


def finding_for_match(rule: SigmaRule, matched: Mapping[str, Any], event: Mapping[str, Any],
                      occurrences: int = 1) -> Finding:
    """Build the Aegis Finding for one rule match."""
    sev = rule.severity
    summary = _summary(event)
    ts = event.get("_ts")
    log_key, event_id = event.get("_log"), event.get("_event_id")
    if log_key == "ProcessGuard" or (log_key is None and event.get("_pid") is not None):
        where = f"process {event.get('_pid', '')}".strip()
    elif log_key:
        where = f"{log_key} log, event {event_id if event_id is not None else '?'} at {_fmt_time(ts)}"
    else:
        where = _fmt_time(ts) if ts else ""
    location = f"{summary} [{where}]" if where else summary
    evidence: Dict[str, Any] = {
        "source": "sigma", "sigma_rule_id": rule.id, "sigma_title": rule.title, "sigma_level": rule.level or "unknown",
        "sigma_status": rule.status or "unspecified", "logsource": rule.logsource,
        "matched": {k: _clip(v) for k, v in matched.items()},
        "event": {k: _clip(event[k], 800 if k == "ScriptBlockText" else 500) for k in _EVENT_FIELDS
                  if event.get(k) not in (None, "")},
        "references": rule.references[:8], "tags": rule.tags[:12], "occurrences": occurrences,
    }
    if rule.author:
        evidence["author"] = rule.author
    if log_key:
        evidence["log"] = log_key
        evidence["event_id"] = event_id
    if ts:
        evidence["time"] = _fmt_time(ts)
    if event.get("_pid") is not None:
        evidence["pid"] = event["_pid"]
    desc = rule.description or f"The Sigma detection rule '{rule.title}' matched."
    mf = "; ".join(f"{k}={str(_clip(v, 120))}" for k, v in list(matched.items())[:4])
    desc += f" (Sigma rule, level {rule.level or 'unspecified'}, status {rule.status or 'unspecified'}"
    desc += f"; matched {mf})" if mf else ")"
    rec = ("If you or an administrator did not run this, treat it as a possible compromise: check the processes and "
           "persistence scans, change passwords from another device and run a full scan.")
    fps = [f for f in rule.falsepositives if f.strip().lower().rstrip(".") not in _IGNORED_FP]
    if fps:
        rec += " Known false positives: " + "; ".join(f.strip().rstrip(".") for f in fps[:4]) + "."
    return Finding(rule.rule_id, f"Sigma: {rule.title}", sev, _category_for(rule), desc, location, evidence, rec,
                   None, "", list(rule.mitre))


def same_technique(a: Iterable[str], b: Iterable[str]) -> bool:
    """True when two ATT&CK id lists share a technique (a sub-technique counts as its parent)."""
    for x in a:
        for y in b:
            if x == y or x.startswith(y + ".") or y.startswith(x + "."):
                return True
    return False


def fold_finding(base: Finding, sigma_finding: Finding) -> Finding:
    """Merge a Sigma finding into another finding that describes the same activity (the other detector's finding is
    kept as the richer one: plain-language text, remediation): its severity is raised if the Sigma rule rates the
    activity higher, the rule is listed under ``evidence['sigma_rules']`` and its ATT&CK ids are added."""
    ev = sigma_finding.evidence
    title = ev.get("sigma_title") or sigma_finding.title
    refs = base.evidence.setdefault("sigma_rules", [])
    if isinstance(refs, list) and not any(r.get("rule_id") == ev.get("sigma_rule_id") for r in refs):
        refs.append({"rule_id": ev.get("sigma_rule_id"), "title": title, "level": ev.get("sigma_level"),
                     "severity": sigma_finding.severity.name.lower()})
        base.description = (base.description + f" The Sigma rule '{title}' also matches this activity.").strip()
    if sigma_finding.severity > base.severity:
        base.severity = sigma_finding.severity
    for m in sigma_finding.mitre:
        if m not in base.mitre:
            base.mitre.append(m)
    return base


@dataclass
class SigmaMatch:
    rule: SigmaRule
    matched: Dict[str, Any]
    event: Mapping[str, Any]


@dataclass
class SigmaRun:
    matches: List[SigmaMatch] = field(default_factory=list)
    events: int = 0  # events offered
    evaluated: int = 0  # events that had at least one candidate rule
    truncated: bool = False  # the deadline was reached before every event was evaluated
    seconds: float = 0.0


def evaluate(events: Iterable[Mapping[str, Any]], ruleset: SigmaRuleSet, deadline: Optional[float] = None,
             ignore_logsource: bool = False) -> SigmaRun:
    """Match every event against the rule set. ``deadline`` is a ``time.monotonic()`` value; evaluation stops
    (``truncated``) when it passes."""
    run = SigmaRun()
    started = time.monotonic()
    if not ruleset or not ruleset.available:
        return run
    for i, event in enumerate(events):
        run.events += 1
        if deadline is not None and i % 32 == 0 and time.monotonic() > deadline:
            run.truncated = True
            break
        try:
            hits = ruleset._match(event, ignore_logsource)
        except Exception:
            log.debug("sigma: event evaluation failed", exc_info=True)
            continue
        if hits is None:
            continue
        run.evaluated += 1
        for rule, matched in hits:
            run.matches.append(SigmaMatch(rule, matched, event))
    run.seconds = time.monotonic() - started
    return run


def findings_from_matches(matches: Sequence[SigmaMatch], min_severity: Severity = DEFAULT_MIN_SEVERITY,
                          max_per_rule: int = MAX_FINDINGS_PER_RULE, max_low_per_rule: int = MAX_LOW_FINDINGS_PER_RULE,
                          max_total: int = MAX_FINDINGS_TOTAL) -> List[Finding]:
    """Turn matches into findings: repeats of the same rule on the same activity are collapsed into one finding
    (``evidence.occurrences``), low-level rules are capped per rule, and the total is bounded."""
    groups: Dict[Tuple[str, str], List[SigmaMatch]] = {}
    for m in matches:
        if m.rule.severity < min_severity:
            continue
        groups.setdefault((m.rule.id, _summary(m.event)), []).append(m)
    per_rule: Dict[str, int] = {}
    out: List[Finding] = []
    for (rid, _), ms in groups.items():
        first = min(ms, key=lambda x: x.event.get("_ts") or 0)
        rule = first.rule
        cap = max_low_per_rule if rule.severity <= Severity.LOW else max_per_rule
        if per_rule.get(rid, 0) >= cap:
            continue
        per_rule[rid] = per_rule.get(rid, 0) + 1
        f = finding_for_match(rule, first.matched, first.event, len(ms))
        if len(ms) > 1:
            last = max(ms, key=lambda x: x.event.get("_ts") or 0).event.get("_ts")
            if last:
                f.evidence["last_seen"] = _fmt_time(last)
        out.append(f)
    out.sort(key=lambda f: -int(f.severity))
    return out[:max_total]


def sigma_findings(events: Iterable[Mapping[str, Any]], ruleset: SigmaRuleSet, min_severity: Severity = DEFAULT_MIN_SEVERITY,
                   deadline: Optional[float] = None, **caps: int) -> List[Finding]:
    """Evaluate Sigma events and return findings (see ``findings_from_matches`` for the de-duplication and caps)."""
    return findings_from_matches(evaluate(events, ruleset, deadline).matches, min_severity, **caps)


# =========================================================================== rule testing (for `aegis sigma test`)


def _looks_like_eventlog_record(e: Any) -> bool:
    return isinstance(e, Mapping) and "id" in e and "log" in e and isinstance(e.get("data"), Mapping)


def test_rule_on_events(rule_path: Any, events_json_path: Any, ignore_logsource: Optional[bool] = None) -> Dict[str, Any]:
    """Run one rule file (or every rule in a directory) against a JSON file of events and report what matched.

    The JSON is a list of Sigma events (dicts with Sigma field names, optionally ``_category`` / ``_service``), or of
    ``aegis.scanners.eventlog`` records (converted automatically). Events without routing metadata are evaluated
    regardless of the rule's logsource (``ignore_logsource=None`` decides per file). Never raises: problems are in
    ``error``. Result::

        {"ok", "error", "rules": [{id, title, level, severity, supported, reason}], "events": N,
         "matches": [{"rule_id", "title", "severity", "event_index", "matched", "event"}], "skipped": [...]}"""
    result: Dict[str, Any] = {"ok": False, "error": "", "rules": [], "events": 0, "matches": [], "skipped": []}
    if not available():
        result["error"] = "PyYAML is not installed (pip install pyyaml)"
        return result
    try:
        raw = json.loads(Path(events_json_path).read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        result["error"] = f"cannot read events: {exc}"
        return result
    if isinstance(raw, Mapping):
        raw = raw.get("events", [raw])
    if not isinstance(raw, list):
        result["error"] = "events JSON must be a list"
        return result
    events: List[Mapping[str, Any]] = [e for e in raw if isinstance(e, Mapping)]
    if events and all(_looks_like_eventlog_record(e) for e in events):
        events = events_from_eventlog(events)
    result["events"] = len(events)
    p = Path(rule_path)
    files = iter_rule_files(p) if p.is_dir() else [p]
    rules: List[SigmaRule] = []
    skipped: List[Skipped] = []
    for f in files:
        r, s = load_rule_file(f, "custom")
        rules += r
        skipped += s
    result["skipped"] = [{"source": s.source, "title": s.title, "reason": s.reason, "kind": s.kind} for s in skipped]
    result["rules"] = [{"id": r.id, "title": r.title, "level": r.level, "severity": r.severity.name.lower(),
                        "supported": True, "reason": ""} for r in rules] + \
                      [{"id": "", "title": s.title, "level": "", "severity": "", "supported": False, "reason": s.reason}
                       for s in skipped]
    if not rules:
        result["error"] = skipped[0].reason if skipped else "no rules found"
        return result
    rs = SigmaRuleSet(rules, skipped)
    no_meta = not any(e.get("_category") or e.get("_service") for e in events)
    ignore = no_meta if ignore_logsource is None else ignore_logsource
    for i, ev in enumerate(events):
        for rule, matched in rs.match(ev, ignore_logsource=ignore):
            result["matches"].append({
                "rule_id": rule.id, "title": rule.title, "severity": rule.severity.name.lower(), "event_index": i,
                "matched": {k: _clip(v) for k, v in matched.items()},
                "event": {k: _clip(v, 300) for k, v in ev.items() if not str(k).startswith("_")}})
    result["ok"] = True
    return result


test_rule_on_events.__test__ = False  # type: ignore[attr-defined]  # not a pytest test, despite the name

__all__ = [
    "SigmaRule", "SigmaRuleSet", "SigmaMatch", "SigmaRun", "Skipped", "SigmaError", "UnsupportedRule", "InvalidRule",
    "available", "load_rules", "load_rule_file", "parse_rules_text", "rule_from_dict", "rule_directories",
    "rules_signature", "evaluate", "sigma_findings", "findings_from_matches", "finding_for_match",
    "events_from_eventlog", "event_from_process", "test_rule_on_events", "same_technique", "fold_finding", "attack_ids_from_tags", "level_to_severity",
    "parse_pattern", "windash_variants", "base64_offset_variants",
]
