"""Scanner plugin interface and registry."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Dict, Iterable, List, Optional, Type, Union

from aegis.core.models import CheckResult, Finding
from aegis.core.platform import OS_NAME, is_admin

if TYPE_CHECKING:  # pragma: no cover
    from aegis.core.config import Config
    from aegis.core.signatures import SignatureDB

ProgressFn = Callable[[str, str], None]  # (scanner_name, message)


@dataclass
class ScanContext:
    config: "Config"
    signatures: "SignatureDB"
    paths: List[Path] = field(default_factory=list)  # for file-oriented scanners
    deep: bool = False  # full scan: content-scan every file, not just risky types
    is_admin: bool = field(default_factory=is_admin)
    cancel: threading.Event = field(default_factory=threading.Event)
    progress: Optional[ProgressFn] = None
    stats: Dict[str, int] = field(default_factory=dict)
    options: Dict[str, object] = field(default_factory=dict)

    def report(self, scanner: str, message: str) -> None:
        if self.progress:
            try:
                self.progress(scanner, message)
            except Exception:
                pass

    def bump(self, key: str, n: int = 1) -> None:
        self.stats[key] = self.stats.get(key, 0) + n

    @property
    def cancelled(self) -> bool:
        return self.cancel.is_set()


Emitted = Union[Finding, CheckResult]


class Scanner:
    """Subclass, set `name`/`description`, implement `run` yielding Findings
    (threats / misconfigurations) and CheckResults (pass/fail hardening checks)."""

    name: str = ""
    title: str = ""
    description: str = ""
    platforms: tuple = ("windows", "linux", "darwin")
    needs_admin_for_full_results: bool = False

    def supported(self) -> bool:
        return OS_NAME in self.platforms

    def run(self, ctx: ScanContext) -> Iterable[Emitted]:  # pragma: no cover - interface
        raise NotImplementedError


REGISTRY: Dict[str, Type[Scanner]] = {}


def register(cls: Type[Scanner]) -> Type[Scanner]:
    REGISTRY[cls.name] = cls
    return cls


def load_all() -> Dict[str, Type[Scanner]]:
    """Import every built-in scanner module so they self-register."""
    import importlib

    for mod in (
        "files",
        "processes",
        "persistence",
        "browser",
        "network",
        "system_audit",
        "software",
        "secrets",
        "eventlog",
        "drivers",
        "sideload",
        "usb",
        "email",
        "memory",
        "supplychain",
        "ide",
        "privacy",
        "apptamper",
        "recovery",
    ):
        try:
            importlib.import_module(f"aegis.scanners.{mod}")
        except Exception as exc:  # a broken optional module must not kill the suite
            import logging

            logging.getLogger("aegis.scanners").warning("scanner module %s failed to load: %s", mod, exc)
    return REGISTRY
