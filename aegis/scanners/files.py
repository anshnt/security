"""File scanner: hash signatures, content rules (Aegis-Lite + YARA), static
heuristics, archive inspection, optional Microsoft Defender second opinion and
optional VirusTotal hash reputation. `scan_file` is reused by the process,
persistence and real-time scanners."""

from __future__ import annotations

import fnmatch
import hashlib
import io
import json
import logging
import os
import sqlite3
import threading
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Tuple

from aegis.core import fileanalysis as fa
from aegis.core.models import Category, Finding, Remediation, Severity
from aegis.core.platform import IS_WINDOWS, in_suspicious_location, run
from aegis.scanners.base import ScanContext, Scanner, register

log = logging.getLogger("aegis.files")

READ_LIMIT = 32 * 1024 * 1024  # bytes of content inspected by rules/heuristics
SKIP_DIRS_WIN = {"\\windows\\winsxs", "\\windows\\installer", "\\windows\\servicing", "\\system volume information",
                 "\\windows\\softwaredistribution", "\\$windows.~bt", "\\windows\\assembly", "\\windows\\microsoft.net\\assembly"}
SKIP_DIRS_NIX = {"/proc", "/sys", "/dev", "/run", "/snap", "/var/lib/docker", "/var/lib/containerd", "/System/Volumes"}


# --------------------------------------------------------------------------- cache

class ScanCache:
    """Remembers clean files by (path, size, mtime, signature version) so repeat
    scans skip unchanged files - the same trick commercial AVs use."""

    def __init__(self, path: Path, sig_version: str):
        self.sig_version = sig_version
        self._lock = threading.Lock()
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS clean (path TEXT PRIMARY KEY, size INT, mtime REAL, sig TEXT, sha256 TEXT)")

    def is_clean(self, path: str, st: os.stat_result) -> bool:
        with self._lock:
            row = self.db.execute("SELECT size, mtime, sig FROM clean WHERE path=?", (path,)).fetchone()
        return bool(row) and row[0] == st.st_size and abs(row[1] - st.st_mtime) < 1e-3 and row[2] == self.sig_version

    def mark_clean(self, path: str, st: os.stat_result, sha256: str) -> None:
        with self._lock:
            self.db.execute("INSERT OR REPLACE INTO clean VALUES (?,?,?,?,?)", (path, st.st_size, st.st_mtime, self.sig_version, sha256))

    def commit(self) -> None:
        with self._lock:
            self.db.commit()


# --------------------------------------------------------------------------- core analysis

def hash_file(path: Path) -> Tuple[str, str, str]:
    sha256, sha1, md5 = hashlib.sha256(), hashlib.sha1(), hashlib.md5()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)
    return sha256.hexdigest(), sha1.hexdigest(), md5.hexdigest()


def _yara_matches(ctx: ScanContext, data: bytes) -> List[Tuple[str, dict]]:
    rules = ctx.signatures.yara_rules
    if rules is None:
        return []
    try:
        return [(m.rule, dict(m.meta)) for m in rules.match(data=data, timeout=30)]
    except Exception as exc:
        log.debug("yara error: %s", exc)
        return []


def analyse_bytes(ctx: ScanContext, path: Path, data: bytes, ext: str, location: str, depth: int = 0) -> List[Finding]:
    """Analyse in-memory content. `location` is the display path (may be
    `archive.zip!inner/file.exe`)."""
    findings: List[Finding] = []
    sigs = ctx.signatures
    sha256 = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()
    if sha256 in {h.lower() for h in ctx.config.allowlist_hashes}:
        return []
    remediation = Remediation("quarantine_file", {"path": str(path)}, "Move the file to quarantine") if depth == 0 else \
        Remediation("quarantine_file", {"path": str(path)}, "Quarantine the containing archive")

    threat = sigs.lookup_hash(sha256, md5)
    if threat:
        findings.append(Finding(
            "AEG-SIG-HASH", f"Known malware: {threat}", Severity.CRITICAL, Category.MALWARE,
            "File hash matches a known malware sample in the threat database.", location,
            {"sha256": sha256, "md5": md5, "threat": threat}, "Quarantine and delete the file, then run a full scan.",
            remediation, mitre=["T1204"]))
        return findings  # definitive

    kind = fa.classify(data[:4096], ext)
    for rule in sigs.rules:
        if not rule.applies_to(kind, ext):
            continue
        hits = rule.match(data)
        if hits is not None:
            findings.append(Finding(
                rule.id, rule.name, rule.severity, rule.category, rule.description, location,
                {"sha256": sha256, "matched": hits, "rule_source": rule.source},
                "Quarantine the file unless you are certain it is legitimate.", remediation, mitre=rule.mitre))

    for name, meta in _yara_matches(ctx, data):
        sev = Severity.parse(meta.get("severity", "high")) if str(meta.get("severity", "")).lower() in \
            ("info", "low", "medium", "high", "critical") else Severity.HIGH
        findings.append(Finding(
            f"YARA-{name}", f"YARA: {meta.get('description') or name}", sev, Category.MALWARE,
            str(meta.get("description", "")), location, {"sha256": sha256, "rule": name, "author": meta.get("author", "")},
            "Quarantine the file unless you are certain it is legitimate.", remediation))

    # ---- heuristics
    inds: List[fa.Indicator] = fa.name_indicators(path if depth == 0 else Path(location.split("!")[-1]), kind)
    if kind == "pe":
        info = fa.parse_pe(data)
        inds += fa.pe_indicators(info, len(data))
        if depth == 0 and in_suspicious_location(str(path)) and not info.has_signature:
            inds.append(fa.Indicator("AEG-H-LOC-EXEC", "Unsigned executable in a user-writable drop location",
                                     Severity.LOW, 15, str(path.parent), ["T1204.002"]))
    elif kind in ("script", "text"):
        inds += fa.content_indicators(data, kind)
        inds += fa.ransom_note_indicators(path, data)
    elif kind == "lnk":
        inds += fa.lnk_indicators(data) + fa.content_indicators(data, kind)
    elif kind == "office":
        inds += fa.office_indicators(path if depth == 0 else _BytesPath(data), data)
    elif kind == "pdf":
        inds += fa.pdf_indicators(data)
    elif kind == "elf":
        inds += fa.content_indicators(data, kind)

    strong = [i for i in inds if i.severity >= Severity.HIGH]
    score = sum(i.score for i in inds)
    sev = fa.score_to_severity(score)
    if strong:
        sev = max(sev or Severity.HIGH, max(i.severity for i in strong))
    # Already detected by a signature/rule: heuristics only enrich evidence.
    if findings:
        findings[0].evidence["heuristics"] = [f"{i.rule_id}: {i.title}" for i in inds if i.score > 0]
    elif sev is not None:
        top = max(inds, key=lambda i: i.score)
        findings.append(Finding(
            "AEG-HEUR", f"Suspicious {kind}: {top.title}", sev, Category.SUSPICIOUS,
            "Static heuristics found characteristics common in malware. This is not a definitive detection.",
            location, {"sha256": sha256, "score": score, "indicators": [
                {"id": i.rule_id, "title": i.title, "detail": i.detail, "score": i.score} for i in inds if i.score > 0]},
            "Verify the file's origin. If you did not intentionally download/install it, quarantine it and "
            "submit the hash to VirusTotal.", remediation, mitre=sorted({m for i in inds for m in i.mitre})))

    # ---- archives: inspect members (zip-family only; no external tools)
    if kind == "archive" and data[:4] == b"PK\x03\x04" and depth < ctx.config.archive_max_depth:
        findings += _scan_zip(ctx, path, data, location, depth)
    return findings


class _BytesPath(io.BytesIO):
    """Lets zipfile open nested office documents from memory."""

    def __init__(self, data: bytes):
        super().__init__(data)
        self.name = "<memory>"


def _scan_zip(ctx: ScanContext, path: Path, data: bytes, location: str, depth: int) -> List[Finding]:
    out: List[Finding] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return out
    with zf:
        infos = zf.infolist()[: ctx.config.archive_max_members]
        encrypted_exec = [i.filename for i in infos if i.flag_bits & 0x1 and
                          i.filename.lower().rsplit(".", 1)[-1] in fa.EXEC_EXTS | fa.SCRIPT_EXTS | {"lnk"}]
        if encrypted_exec:
            out.append(Finding(
                "AEG-H-ZIP-ENCEXEC", "Password-protected archive containing executables", Severity.MEDIUM, Category.SUSPICIOUS,
                "Malware is commonly delivered in password-protected archives so that email gateways and AV cannot inspect it.",
                location, {"members": encrypted_exec[:20]},
                "Do not open unless you trust the sender; scan the extracted files.",
                Remediation("quarantine_file", {"path": str(path)}), mitre=["T1027.013"]))
        for info in infos:
            if info.is_dir() or info.flag_bits & 0x1 or info.file_size > ctx.config.max_file_size_mb * 1024 * 1024:
                continue
            if info.compress_size and info.file_size / max(info.compress_size, 1) > 1000:
                out.append(Finding("AEG-H-ZIPBOMB", "Decompression bomb", Severity.MEDIUM, Category.SUSPICIOUS,
                                   "Archive member has an extreme compression ratio.", f"{location}!{info.filename}"))
                continue
            ext = info.filename.lower().rsplit(".", 1)[-1] if "." in info.filename else ""
            if not ctx.deep and ext not in fa.RISKY_EXTS:
                continue
            try:
                member = zf.read(info)[:READ_LIMIT]
            except Exception:
                continue
            ctx.bump("archive_members_scanned")
            out += analyse_bytes(ctx, path, member, ext, f"{location}!{info.filename}", depth + 1)
    return out


def defender_scan(path: Path) -> Optional[str]:
    """Ask Microsoft Defender (MpCmdRun) about a single file. Returns the threat
    name if Defender flags it, else None."""
    if not IS_WINDOWS:
        return None
    candidates = [Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Windows Defender" / "MpCmdRun.exe"]
    platform_dir = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Microsoft" / "Windows Defender" / "Platform"
    if platform_dir.is_dir():
        candidates = sorted(platform_dir.glob("*/MpCmdRun.exe"), reverse=True) + candidates
    exe = next((c for c in candidates if c.exists()), None)
    if not exe:
        return None
    rc, out, _ = run([str(exe), "-Scan", "-ScanType", "3", "-File", str(path), "-DisableRemediation"], timeout=120)
    if rc == 2:
        for line in out.splitlines():
            if line.strip().lower().startswith("threat"):
                return line.split(":", 1)[-1].strip() or "Defender detection"
        return "Defender detection"
    return None


def scan_file(ctx: ScanContext, path: Path, cache: Optional[ScanCache] = None) -> List[Finding]:
    """Scan one file on disk. Never raises for I/O problems."""
    try:
        st = path.stat()
    except OSError:
        return []
    if not path.is_file() or st.st_size == 0:
        return []
    spath = str(path)
    if cache and cache.is_clean(spath, st):
        ctx.bump("files_cached")
        return []
    ext = path.suffix.lower().lstrip(".")
    try:
        with path.open("rb") as fh:
            head = fh.read(4096)
            kind = fa.classify(head, ext)
            risky = ext in fa.RISKY_EXTS or kind in ("pe", "elf", "macho", "script", "lnk", "office", "pdf", "archive") \
                or (kind == "text" and st.st_size < 1024 * 1024)  # ransom notes, configs, droppers
            too_big = st.st_size > ctx.config.max_file_size_mb * 1024 * 1024
            if not ctx.deep and not risky:
                ctx.bump("files_skipped_type")
                return []
            if too_big:
                fh.close()
                sha256, _, md5 = hash_file(path)
                threat = ctx.signatures.lookup_hash(sha256, md5)
                ctx.bump("files_scanned")
                if threat:
                    return [Finding("AEG-SIG-HASH", f"Known malware: {threat}", Severity.CRITICAL, Category.MALWARE,
                                    "File hash matches a known malware sample.", spath, {"sha256": sha256},
                                    "Quarantine the file.", Remediation("quarantine_file", {"path": spath}))]
                return []
            data = head + fh.read(READ_LIMIT - len(head))
    except (OSError, PermissionError) as exc:
        ctx.bump("files_unreadable")
        log.debug("cannot read %s: %s", path, exc)
        return []
    ctx.bump("files_scanned")
    ctx.bump("bytes_scanned", len(data))
    findings = analyse_bytes(ctx, path, data, ext, spath)

    # Second opinions for suspicious-but-unconfirmed files.
    if findings and all(f.category == Category.SUSPICIOUS for f in findings):
        sha256 = findings[0].evidence.get("sha256", "")
        if ctx.config.use_windows_defender_engine:
            threat = defender_scan(path)
            if threat:
                findings.insert(0, Finding("AEG-DEFENDER", f"Microsoft Defender: {threat}", Severity.HIGH, Category.MALWARE,
                                           "Microsoft Defender's engine also flags this file.", spath, {"sha256": sha256},
                                           "Quarantine the file.", Remediation("quarantine_file", {"path": spath})))
        if ctx.config.cloud_lookup and ctx.config.virustotal_api_key and sha256:
            try:
                from aegis.tools.reputation import virustotal_lookup

                vt = virustotal_lookup(sha256, ctx.config.virustotal_api_key)
                if vt and vt.get("malicious", 0) >= 3:
                    findings.insert(0, Finding("AEG-VT", f"VirusTotal: {vt['malicious']}/{vt['total']} engines detect this file",
                                               Severity.HIGH if vt["malicious"] < 10 else Severity.CRITICAL, Category.MALWARE,
                                               "Multiple antivirus engines on VirusTotal classify this file as malicious.",
                                               spath, vt, "Quarantine the file.", Remediation("quarantine_file", {"path": spath})))
                elif vt:
                    for f in findings:
                        f.evidence["virustotal"] = vt
            except Exception as exc:  # network errors must not break scanning
                log.debug("VT lookup failed: %s", exc)

    if not findings and cache:
        cache.mark_clean(spath, st, "")
    return findings


# --------------------------------------------------------------------------- walking

def _excluded(path: str, patterns: List[str]) -> bool:
    low = path.lower()
    for pat in patterns:
        p = pat.lower()
        if any(ch in p for ch in "*?["):
            if fnmatch.fnmatch(low, p):
                return True
        elif low.startswith(p.rstrip("\\/")):
            return True
    return False


def iter_files(roots: Iterable[Path], ctx: ScanContext) -> Iterator[Path]:
    excl = ctx.config.exclusions + [str(ctx.config.home)]  # never scan our own quarantine
    skip = SKIP_DIRS_WIN if IS_WINDOWS else SKIP_DIRS_NIX
    for root in roots:
        if ctx.cancelled:
            return
        if root.is_file():
            yield root
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=ctx.config.follow_symlinks, onerror=lambda e: None):
            if ctx.cancelled:
                return
            low = dirpath.lower()
            if IS_WINDOWS:
                low = low[2:] if len(low) > 1 and low[1] == ":" else low
                if any(low.startswith(s) for s in skip):
                    dirnames[:] = []
                    continue
            elif any(dirpath == s or dirpath.startswith(s + "/") for s in skip):
                dirnames[:] = []
                continue
            if _excluded(dirpath, excl):
                dirnames[:] = []
                continue
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                if not _excluded(full, excl):
                    yield Path(full)


@register
class FileScanner(Scanner):
    name = "files"
    title = "Malware file scan"
    description = "Signatures, YARA/Aegis-Lite rules, PE/script/document heuristics, archive inspection"

    def run(self, ctx: ScanContext):
        cache = None
        if ctx.config.use_cache:
            try:
                sig = ctx.signatures.summary()
                version = json.dumps(sig, sort_keys=True)
                cache = ScanCache(ctx.config.home / "scan_cache.sqlite", hashlib.sha1(version.encode()).hexdigest()[:12])
            except Exception as exc:
                log.debug("cache disabled: %s", exc)
        results: List[Finding] = []
        lock = threading.Lock()
        count = 0

        def work(p: Path) -> None:
            nonlocal count
            fs = scan_file(ctx, p, cache)
            with lock:
                results.extend(fs)
                count += 1
                if count % 500 == 0:
                    ctx.report(self.name, f"{count} files examined... ({p.parent})")

        roots = ctx.paths
        ctx.report(self.name, "scanning " + ", ".join(str(r) for r in roots))
        with ThreadPoolExecutor(max_workers=ctx.config.scan_threads) as pool:
            batch = []
            for p in iter_files(roots, ctx):
                batch.append(pool.submit(work, p))
                if len(batch) >= 256:
                    for f in batch:
                        f.result()
                    batch = []
                    with lock:
                        pending, results[:] = list(results), []
                    yield from pending
            for f in batch:
                f.result()
        if cache:
            cache.commit()
        yield from results
