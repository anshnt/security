"""Core data models shared by every scanner, the engine, reports and the UI."""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: "str | int | Severity") -> "Severity":
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[str(value).strip().upper()]

    @property
    def label(self) -> str:
        return self.name.capitalize()


class Category:
    """Well-known finding categories (plain strings so plugins can add more)."""

    MALWARE = "malware"
    PUP = "pup"  # potentially unwanted program / adware
    SUSPICIOUS = "suspicious"
    PROCESS = "process"
    PERSISTENCE = "persistence"
    BROWSER = "browser"
    NETWORK = "network"
    SYSTEM = "system"  # hardening / configuration
    VULNERABILITY = "vulnerability"
    PRIVACY = "privacy"  # exposed secrets / credentials
    RANSOMWARE = "ransomware"
    INTEGRITY = "integrity"


class CheckStatus:
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    SKIP = "skip"
    ERROR = "error"


@dataclass
class Remediation:
    """A machine-actionable fix that `aegis.core.remediation` knows how to apply."""

    action: str  # quarantine_file | kill_process | delete_registry_value | disable_task | ...
    params: Dict[str, Any] = field(default_factory=dict)
    description: str = ""


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    category: str
    description: str = ""
    location: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""
    remediation: Optional[Remediation] = None
    scanner: str = ""
    mitre: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: _dt.datetime.now().isoformat(timespec="seconds"))

    @property
    def fingerprint(self) -> str:
        """Stable id used for de-duplication, allow-listing and `aegis fix --id`."""
        raw = f"{self.rule_id}|{self.location}".lower()
        return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:12]

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.name.lower()
        d["fingerprint"] = self.fingerprint
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Finding":
        d = dict(d)
        d.pop("fingerprint", None)
        d["severity"] = Severity.parse(d.get("severity", "info"))
        rem = d.get("remediation")
        if rem:
            d["remediation"] = Remediation(**rem)
        return cls(**d)


@dataclass
class CheckResult:
    """Outcome of a single hardening / configuration check (pass or fail)."""

    check_id: str
    title: str
    status: str
    detail: str = ""
    category: str = Category.SYSTEM
    scanner: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    profile: str = "custom"
    started: str = field(default_factory=lambda: _dt.datetime.now().isoformat(timespec="seconds"))
    finished: str = ""
    host: Dict[str, Any] = field(default_factory=dict)
    scanners: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    checks: List[CheckResult] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        fp = finding.fingerprint
        for existing in self.findings:
            if existing.fingerprint == fp:
                if finding.severity > existing.severity:
                    existing.severity = finding.severity
                return
        self.findings.append(finding)

    def counts(self) -> Dict[str, int]:
        out = {s.name.lower(): 0 for s in Severity}
        for f in self.findings:
            out[f.severity.name.lower()] += 1
        return out

    def sorted_findings(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: (-int(f.severity), f.category, f.title))

    def to_dict(self) -> Dict[str, Any]:
        from aegis.core.scoring import security_score

        score, grade = security_score(self)
        return {
            "profile": self.profile,
            "started": self.started,
            "finished": self.finished,
            "host": self.host,
            "scanners": self.scanners,
            "score": score,
            "grade": grade,
            "counts": self.counts(),
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "checks": [c.to_dict() for c in self.checks],
            "stats": self.stats,
            "errors": self.errors,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ScanResult":
        r = cls(
            profile=d.get("profile", "custom"),
            started=d.get("started", ""),
            finished=d.get("finished", ""),
            host=d.get("host", {}),
            scanners=d.get("scanners", []),
            stats=d.get("stats", {}),
            errors=d.get("errors", []),
        )
        r.findings = [Finding.from_dict(f) for f in d.get("findings", [])]
        r.checks = [CheckResult(**c) for c in d.get("checks", [])]
        return r
