"""Aegis-Lite: a small, dependency-free, YARA-inspired content rule engine.

Rules live in JSON files (aegis/data/rules/*.json and <data>/signatures/rules/).
They let Aegis detect malicious content even where the native `yara-python`
module is not installed; when it is, genuine YARA rules are evaluated as well.

Rule schema::

    {
      "id": "AEG-PS-001",
      "name": "PowerShell download cradle",
      "severity": "high",                 # info|low|medium|high|critical
      "category": "malware",
      "description": "...",
      "mitre": ["T1059.001"],
      "file_types": ["script", "text"],   # pe|script|office|archive|text|lnk|any or extensions like "ps1"
      "strings": {
        "a": {"text": "DownloadString", "nocase": true},
        "b": {"regex": "IEX\\s*\\("},
        "c": {"hex": "4D 5A ?? 00"},
        "d": {"text": "evil", "wide": true}
      },
      "condition": "a and (b or c)"       # and/or/not, parens, any, all,
    }                                     # "N of them", "N of (a,b)", "any of (a,c)"
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Set

from aegis.core.models import Severity

log = logging.getLogger("aegis.rules")


class RuleError(ValueError):
    pass


def _hex_to_regex(hexstr: str) -> bytes:
    parts = hexstr.replace(",", " ").split()
    out = b""
    for p in parts:
        if p in ("??", "?"):
            out += b"."
        elif len(p) == 2:
            out += re.escape(bytes([int(p, 16)]))
        else:
            raise RuleError(f"bad hex token {p!r}")
    return out


def _compile_string(spec: dict) -> "re.Pattern[bytes]":
    flags = re.DOTALL
    if spec.get("nocase"):
        flags |= re.IGNORECASE
    if "regex" in spec:
        return re.compile(spec["regex"].encode("utf-8"), flags)
    if "hex" in spec:
        return re.compile(_hex_to_regex(spec["hex"]), flags)
    if "text" in spec:
        text: str = spec["text"]
        variants = []
        if spec.get("ascii", True):
            variants.append(re.escape(text.encode("utf-8")))
        if spec.get("wide"):
            variants.append(re.escape(text.encode("utf-16-le")))
        return re.compile(b"|".join(variants), flags)
    raise RuleError("string needs text, regex or hex")


# ------------------------------------------------------------------ condition parser

_TOKEN = re.compile(r"\s*(\(|\)|,|[A-Za-z_][A-Za-z0-9_]*|\d+)")


def _tokenize(cond: str) -> List[str]:
    pos, toks = 0, []
    cond = cond.strip()
    while pos < len(cond):
        m = _TOKEN.match(cond, pos)
        if not m:
            raise RuleError(f"cannot parse condition near {cond[pos:]!r}")
        toks.append(m.group(1))
        pos = m.end()
        while pos < len(cond) and cond[pos].isspace():
            pos += 1
    return toks


Pred = Callable[[Set[str]], bool]


class _Parser:
    def __init__(self, tokens: List[str], ids: List[str]):
        self.t = tokens
        self.i = 0
        self.ids = ids

    def peek(self) -> Optional[str]:
        return self.t[self.i] if self.i < len(self.t) else None

    def take(self, expected: Optional[str] = None) -> str:
        tok = self.peek()
        if tok is None or (expected is not None and tok.lower() != expected):
            raise RuleError(f"expected {expected!r}, got {tok!r}")
        self.i += 1
        return tok

    def parse(self) -> Pred:
        p = self.or_expr()
        if self.peek() is not None:
            raise RuleError(f"unexpected token {self.peek()!r}")
        return p

    def or_expr(self) -> Pred:
        parts = [self.and_expr()]
        while (self.peek() or "").lower() == "or":
            self.take()
            parts.append(self.and_expr())
        return parts[0] if len(parts) == 1 else (lambda m, ps=parts: any(p(m) for p in ps))

    def and_expr(self) -> Pred:
        parts = [self.not_expr()]
        while (self.peek() or "").lower() == "and":
            self.take()
            parts.append(self.not_expr())
        return parts[0] if len(parts) == 1 else (lambda m, ps=parts: all(p(m) for p in ps))

    def not_expr(self) -> Pred:
        if (self.peek() or "").lower() == "not":
            self.take()
            inner = self.not_expr()
            return lambda m: not inner(m)
        return self.atom()

    def _set(self) -> List[str]:
        if (self.peek() or "").lower() == "them":
            self.take()
            return list(self.ids)
        self.take("(")
        names = [self.take()]
        while self.peek() == ",":
            self.take(",")
            names.append(self.take())
        self.take(")")
        for n in names:
            if n not in self.ids:
                raise RuleError(f"unknown string id {n!r}")
        return names

    def atom(self) -> Pred:
        tok = self.peek()
        if tok is None:
            raise RuleError("unexpected end of condition")
        low = tok.lower()
        if tok == "(":
            self.take("(")
            p = self.or_expr()
            self.take(")")
            return p
        if tok.isdigit() or low in ("any", "all"):
            self.take()
            if (self.peek() or "").lower() == "of":
                self.take("of")
                names = self._set()
                need = len(names) if low == "all" else 1 if low == "any" else int(tok)
            else:  # bare any / all
                if tok.isdigit():
                    raise RuleError("number must be followed by 'of'")
                names = list(self.ids)
                need = len(names) if low == "all" else 1
            return lambda m, ns=names, k=need: _at_least(ns, m, k)
        if tok in self.ids:
            self.take()
            return lambda m, n=tok: n in m
        raise RuleError(f"unknown identifier {tok!r}")


def _at_least(names: List[str], hits, k: int) -> bool:
    """`k of (names)` with early exit once satisfied (or once it can no longer be)."""
    found = 0
    for i, n in enumerate(names):
        if n in hits:
            found += 1
            if found >= k:
                return True
        elif found + (len(names) - i - 1) < k:
            return False
    return found >= k


# ------------------------------------------------------------------ rules

@dataclass
class Rule:
    id: str
    name: str
    severity: Severity
    category: str
    description: str
    file_types: List[str]
    strings: Dict[str, "re.Pattern[bytes]"]
    predicate: Pred
    mitre: List[str] = field(default_factory=list)
    source: str = ""

    def applies_to(self, kind: str, ext: str) -> bool:
        if not self.file_types or "any" in self.file_types:
            return True
        return kind in self.file_types or ext.lstrip(".").lower() in self.file_types

    def match(self, data: bytes) -> Optional[Dict[str, str]]:
        """Evaluate the condition, searching each string only when the condition
        needs it (and at most once): `a and b` never searches b when a is absent.
        Returns the strings that were found (the evidence) on a match."""
        lazy = _LazyHits(self.strings, data)
        if self.predicate(lazy):  # type: ignore[arg-type]
            return lazy.hits
        return None


class _LazyHits:
    """Set-like view the compiled condition queries with `sid in hits`."""

    __slots__ = ("_strings", "_data", "_checked", "hits")

    def __init__(self, strings: Dict[str, "re.Pattern[bytes]"], data: bytes):
        self._strings = strings
        self._data = data
        self._checked: Set[str] = set()
        self.hits: Dict[str, str] = {}

    def __contains__(self, sid: object) -> bool:
        if sid not in self._checked:
            self._checked.add(sid)  # type: ignore[arg-type]
            m = self._strings[sid].search(self._data)  # type: ignore[index]
            if m:
                self.hits[sid] = m.group(0)[:80].decode("utf-8", "replace")  # type: ignore[index]
        return sid in self.hits


def compile_rule(d: dict, source: str = "") -> Rule:
    for key in ("id", "name", "strings", "condition"):
        if key not in d:
            raise RuleError(f"rule missing {key!r}")
    strings = {sid: _compile_string(spec) for sid, spec in d["strings"].items()}
    pred = _Parser(_tokenize(d["condition"]), list(strings)).parse()
    return Rule(
        id=d["id"],
        name=d["name"],
        severity=Severity.parse(d.get("severity", "medium")),
        category=d.get("category", "malware"),
        description=d.get("description", ""),
        file_types=[t.lower() for t in d.get("file_types", ["any"])],
        strings=strings,
        predicate=pred,
        mitre=d.get("mitre", []),
        source=source,
    )


def load_rule_files(paths: Iterable[Path]) -> List[Rule]:
    rules: List[Rule] = []
    seen: Set[str] = set()
    for path in paths:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            log.warning("cannot read rule file %s: %s", path, exc)
            continue
        for d in data if isinstance(data, list) else data.get("rules", []):
            try:
                r = compile_rule(d, source=path.name)
            except Exception as exc:
                log.warning("bad rule %s in %s: %s", d.get("id"), path.name, exc)
                continue
            if r.id in seen:  # later files (updates) override bundled rules
                rules = [x for x in rules if x.id != r.id]
            seen.add(r.id)
            rules.append(r)
    return rules
