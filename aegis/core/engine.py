"""Scan orchestration: profiles, running scanners, collecting results."""

from __future__ import annotations

import datetime as dt
import logging
import threading
import time
import traceback
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence

from aegis.core.config import Config
from aegis.core.models import CheckResult, Finding, ScanResult, Severity
from aegis.core.platform import full_scan_roots, host_info, quick_scan_dirs
from aegis.core.signatures import SignatureDB
from aegis.scanners.base import REGISTRY, ScanContext, load_all

log = logging.getLogger("aegis.engine")

# Which scanners each profile runs. "files" receives paths from the profile.
PROFILES: Dict[str, List[str]] = {
    "quick": ["processes", "persistence", "files", "browser", "network"],
    "full": ["processes", "persistence", "files", "browser", "network", "system_audit", "software", "secrets"],
    "audit": ["system_audit", "software", "network", "browser"],
    "custom": [],
}


class ScanEngine:
    def __init__(self, config: Optional[Config] = None, signatures: Optional[SignatureDB] = None):
        self.config = config or Config.load()
        self.signatures = signatures or SignatureDB(self.config)
        load_all()

    def available_scanners(self) -> Dict[str, str]:
        return {name: cls.description for name, cls in sorted(REGISTRY.items())}

    def scan(
        self,
        profile: str = "quick",
        scanners: Optional[Sequence[str]] = None,
        paths: Optional[Sequence[Path]] = None,
        progress: Optional[Callable[[str, str], None]] = None,
        cancel: Optional[threading.Event] = None,
        on_finding: Optional[Callable[[Finding], None]] = None,
        deep: Optional[bool] = None,
    ) -> ScanResult:
        from_profile = not scanners
        names = list(scanners) if scanners else list(PROFILES.get(profile, []))
        if not names:
            raise ValueError("no scanners selected")
        unknown = [n for n in names if n not in REGISTRY]
        if unknown:
            if from_profile:
                # A built-in profile references a scanner whose module failed to
                # load (e.g. an optional dependency). Skip it rather than abort.
                for n in unknown:
                    log.warning("profile %r scanner %r is unavailable - skipping", profile, n)
                names = [n for n in names if n in REGISTRY]
                if not names:
                    raise ValueError("no scanners available")
            else:
                raise ValueError(f"unknown scanner(s): {', '.join(unknown)}; available: {', '.join(sorted(REGISTRY))}")

        if paths:
            scan_paths = [Path(p) for p in paths]
        elif profile == "full":
            scan_paths = full_scan_roots()
        else:
            scan_paths = quick_scan_dirs()

        ctx = ScanContext(
            config=self.config,
            signatures=self.signatures,
            paths=scan_paths,
            deep=profile == "full" if deep is None else deep,
            progress=progress,
            cancel=cancel or threading.Event(),
        )
        result = ScanResult(profile=profile, host=host_info())
        suppressed = {x.lower() for x in self.config.allowlist_fingerprints}
        t0 = time.time()

        for name in names:
            if ctx.cancelled:
                result.errors.append("scan cancelled by user")
                break
            scanner = REGISTRY[name]()
            if not scanner.supported():
                ctx.report(name, "not supported on this OS - skipped")
                continue
            result.scanners.append(name)
            ctx.report(name, f"starting: {scanner.title or name}")
            st = time.time()
            try:
                for item in scanner.run(ctx) or ():
                    if isinstance(item, CheckResult):
                        item.scanner = item.scanner or name
                        result.checks.append(item)
                    elif isinstance(item, Finding):
                        item.scanner = item.scanner or name
                        if item.fingerprint in suppressed:
                            ctx.bump("suppressed_findings")
                            continue
                        before = len(result.findings)
                        result.add(item)
                        if len(result.findings) > before and on_finding:
                            on_finding(item)
                    if ctx.cancelled:
                        break
            except Exception as exc:
                msg = f"{name}: {exc}"
                log.error("scanner failed: %s\n%s", msg, traceback.format_exc())
                result.errors.append(msg)
            ctx.stats[f"time_{name}_s"] = round(time.time() - st, 2)
            ctx.report(name, "done")

        result.finished = dt.datetime.now().isoformat(timespec="seconds")
        ctx.stats["duration_s"] = round(time.time() - t0, 2)
        ctx.stats["admin"] = int(ctx.is_admin)
        result.stats = dict(ctx.stats)
        result.stats["signatures"] = self.signatures.summary()

        if self.config.auto_quarantine:
            self._auto_quarantine(result)
        self._save_last(result)
        return result

    def _auto_quarantine(self, result: ScanResult) -> None:
        from aegis.core.remediation import apply_remediation

        threshold = Severity.parse(self.config.auto_quarantine_min_severity)
        for f in result.findings:
            if f.severity >= threshold and f.remediation and f.remediation.action in ("quarantine_file", "kill_process"):
                ok, msg = apply_remediation(f, self.config)
                f.evidence["auto_remediation"] = msg
                log.warning("auto-remediation %s: %s", "ok" if ok else "failed", msg)

    def _save_last(self, result: ScanResult) -> None:
        try:
            stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
            out = self.config.reports_dir / f"scan-{result.profile}-{stamp}.json"
            out.write_text(result.to_json(), encoding="utf-8")
            (self.config.home / "last_scan.json").write_text(result.to_json(), encoding="utf-8")
            result.stats["saved_to"] = str(out)
        except Exception as exc:  # pragma: no cover
            log.debug("could not save scan result: %s", exc)


def last_scan(config: Config) -> Optional[ScanResult]:
    import json

    p = config.home / "last_scan.json"
    if not p.exists():
        return None
    try:
        return ScanResult.from_dict(json.loads(p.read_text(encoding="utf-8")))
    except Exception:
        return None


def iter_findings(results: Iterable[ScanResult]) -> Iterable[Finding]:
    for r in results:
        yield from r.findings
