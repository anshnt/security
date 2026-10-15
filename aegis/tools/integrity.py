"""File-integrity monitoring (FIM) for the files attackers love to tamper with:
hosts file, startup folders, scheduled-task definitions, shell profiles, SSH
keys, sudoers, cron, LaunchAgents ...

``create_baseline`` hashes the watched paths into ``<data>/integrity_baseline.json``;
``compare_baseline`` reports modified / new / deleted files as Findings."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import logging
import os
import platform
import socket
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from aegis.core.models import Category, Finding, Severity
from aegis.core.platform import IS_MAC, IS_WINDOWS, windows_dir

log = logging.getLogger("aegis.integrity")

BASELINE_NAME = "integrity_baseline.json"
MAX_FILES_PER_ROOT = 5000
MAX_HASH_BYTES = 128 * 1024 * 1024
MAX_DEPTH = 6

# (filename or path fragment, mitre) - files whose tampering is high severity
_HIGH_NAMES = ("hosts", "sudoers", "ld.so.preload", "authorized_keys")
_MITRE_HINTS: List[Tuple[str, List[str]]] = [
    ("hosts", ["T1565.001"]),
    ("authorized_keys", ["T1098.004"]),
    ("ld.so.preload", ["T1574.006"]),
    ("sudoers", ["T1548.003"]),
    ("sshd_config", ["T1021.004"]),
    ("crontab", ["T1053.003"]),
    ("cron", ["T1053.003"]),
    ("startup", ["T1547.001"]),
    ("launchagents", ["T1543.001"]),
    ("launchdaemons", ["T1543.004"]),
    ("system32/tasks", ["T1053.005"]),
    ("system32\\tasks", ["T1053.005"]),
    ("profile.ps1", ["T1546.013"]),
    (".bashrc", ["T1546.004"]),
    (".bash_profile", ["T1546.004"]),
    (".zshrc", ["T1546.004"]),
    (".profile", ["T1546.004"]),
    ("passwd", ["T1136.001"]),
    ("shadow", ["T1098"]),
    ("autostart", ["T1547.013"]),
]


# --------------------------------------------------------------------------- defaults

def default_paths() -> List[Path]:
    """Critical files/directories for this OS (only existing entries are baselined)."""
    home = Path.home()
    paths: List[Path] = []
    if IS_WINDOWS:
        win = windows_dir()
        appdata = os.environ.get("APPDATA")
        pd = os.environ.get("ProgramData", r"C:\ProgramData")
        docs = home / "Documents"
        paths += [
            win / "System32" / "drivers" / "etc",
            win / "System32" / "Tasks",
            Path(pd) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "StartUp",
            win / "System32" / "WindowsPowerShell" / "v1.0" / "profile.ps1",
            win / "System32" / "WindowsPowerShell" / "v1.0" / "Microsoft.PowerShell_profile.ps1",
            Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "PowerShell" / "7" / "profile.ps1",
            docs / "WindowsPowerShell" / "profile.ps1",
            docs / "WindowsPowerShell" / "Microsoft.PowerShell_profile.ps1",
            docs / "PowerShell" / "profile.ps1",
            docs / "PowerShell" / "Microsoft.PowerShell_profile.ps1",
        ]
        if appdata:
            paths.append(Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
    elif IS_MAC:
        paths += [home / "Library" / "LaunchAgents", Path("/Library/LaunchAgents"), Path("/Library/LaunchDaemons"),
                  Path("/etc/hosts"), Path("/etc/sudoers"), Path("/etc/ssh/sshd_config"), Path("/etc/crontab"),
                  home / ".zshrc", home / ".zprofile", home / ".bash_profile", home / ".bashrc",
                  home / ".ssh" / "authorized_keys"]
    else:
        paths += [Path("/etc/passwd"), Path("/etc/shadow"), Path("/etc/sudoers"), Path("/etc/sudoers.d"),
                  Path("/etc/ssh/sshd_config"), Path("/etc/hosts"), Path("/etc/crontab"), Path("/etc/cron.d"),
                  Path("/etc/ld.so.preload"), Path("/etc/profile"), home / ".bashrc", home / ".profile",
                  home / ".bash_profile", home / ".zshrc", home / ".ssh" / "authorized_keys",
                  home / ".config" / "autostart"]
    return paths


# --------------------------------------------------------------------------- hashing / walking

def _hash(path: Path) -> Dict[str, Any]:
    """Describe one file: sha256 + size + mtime + mode, or an error marker."""
    try:
        st = path.stat()
        entry: Dict[str, Any] = {"size": st.st_size, "mtime": int(st.st_mtime), "mode": oct(st.st_mode & 0o7777)}
        if st.st_size > MAX_HASH_BYTES:
            entry["sha256"] = "skipped:too-large"
            return entry
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        entry["sha256"] = h.hexdigest()
        return entry
    except (OSError, PermissionError) as exc:
        return {"sha256": "", "error": type(exc).__name__}


def _walk(root: Path) -> Iterator[Path]:
    """Yield files under root (or root itself if it is a file); bounded and symlink-safe."""
    try:
        if root.is_file():
            yield root
            return
        if not root.is_dir():
            return
    except OSError:
        return
    count = 0
    base_depth = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=lambda e: None):
        if len(Path(dirpath).parts) - base_depth >= MAX_DEPTH:
            dirnames[:] = []
        dirnames.sort()
        for name in sorted(filenames):
            p = Path(dirpath) / name
            try:
                if p.is_symlink():
                    continue
            except OSError:
                continue
            yield p
            count += 1
            if count >= MAX_FILES_PER_ROOT:
                log.warning("integrity: %s has more than %d files; remaining files are not monitored", root, count)
                return


def _key(p: Path) -> str:
    s = str(p)
    return s.lower() if IS_WINDOWS else s


def snapshot(roots: Iterable[Path]) -> Dict[str, Dict[str, Any]]:
    files: Dict[str, Dict[str, Any]] = {}
    for root in roots:
        for p in _walk(Path(root)):
            files[_key(p)] = _hash(p)
    return files


# --------------------------------------------------------------------------- public API

def baseline_path(config: Any) -> Path:
    return Path(config.home) / BASELINE_NAME


def create_baseline(config: Any, paths: Optional[Sequence[Any]] = None) -> Dict[str, Any]:
    """Hash the watched files (defaults when ``paths`` is None) and save the
    baseline. Returns the baseline dict."""
    roots = [Path(p) for p in paths] if paths else default_paths()
    roots = [r for r in roots if r.exists()]
    files = snapshot(roots)
    baseline = {
        "version": 1,
        "created": dt.datetime.now().isoformat(timespec="seconds"),
        "host": socket.gethostname(),
        "os": platform.platform(),
        "roots": [str(r) for r in roots],
        "files": files,
    }
    out = baseline_path(config)
    tmp = out.with_suffix(".tmp")
    tmp.write_text(json.dumps(baseline, indent=1), encoding="utf-8")
    os.replace(tmp, out)
    baseline["path"] = str(out)
    baseline["count"] = len(files)
    return baseline


def load_baseline(config: Any) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(baseline_path(config).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _is_high(path: str) -> bool:
    name = Path(path.replace("\\", "/")).name.lower()
    return name in _HIGH_NAMES


def _mitre(path: str) -> List[str]:
    p = path.lower()
    for frag, ids in _MITRE_HINTS:
        if frag in p:
            return list(ids)
    return ["T1565.001"]


def compare_baseline(config: Any) -> List[Finding]:
    """Compare the current state against the saved baseline."""
    base = load_baseline(config)
    if not base:
        return [Finding("AEG-INTEG-NOBASE", "No integrity baseline exists", Severity.INFO, Category.INTEGRITY,
                        "File-integrity monitoring needs a baseline of known-good critical files.",
                        str(baseline_path(config)), {}, "Run `aegis integrity --baseline` on a clean system.",
                        scanner="integrity")]
    old: Dict[str, Dict[str, Any]] = base.get("files", {})
    roots = [Path(r) for r in base.get("roots", [])]
    new = snapshot(roots)
    findings: List[Finding] = []

    def mk(rule: str, title: str, path: str, sev: Severity, desc: str, evidence: Dict[str, Any]) -> Finding:
        return Finding(
            rule, title, Severity.HIGH if sev == Severity.HIGH or (_is_high(path) and rule != "AEG-INTEG-DEL") else sev,
            Category.INTEGRITY, desc, path, evidence,
            "Verify the change was intentional. If not, restore the file from a trusted backup and run a full scan; "
            "after legitimate changes re-create the baseline with `aegis integrity --baseline`.",
            scanner="integrity", mitre=_mitre(path))

    for path, meta in sorted(new.items()):
        before = old.get(path)
        if before is None:
            findings.append(mk("AEG-INTEG-NEW", f"New file in a monitored location: {Path(path).name}", path, Severity.MEDIUM,
                               "A file appeared in a location that is watched for persistence and tampering.",
                               {"sha256": meta.get("sha256", ""), "size": meta.get("size"), "baseline_created": base.get("created")}))
            continue
        if meta.get("error") or before.get("error"):
            continue  # unreadable now or then (e.g. permissions) - cannot compare
        if meta.get("sha256") != before.get("sha256"):
            findings.append(mk("AEG-INTEG-MOD", f"Monitored file modified: {Path(path).name}", path, Severity.MEDIUM,
                               "The content of a monitored file differs from the baseline.",
                               {"old_sha256": before.get("sha256"), "new_sha256": meta.get("sha256"),
                                "old_size": before.get("size"), "new_size": meta.get("size"),
                                "baseline_created": base.get("created")}))
    for path, before in sorted(old.items()):
        if path not in new and not before.get("error"):
            findings.append(mk("AEG-INTEG-DEL", f"Monitored file deleted: {Path(path).name}", path, Severity.MEDIUM,
                               "A file present in the baseline no longer exists.",
                               {"old_sha256": before.get("sha256"), "baseline_created": base.get("created")}))
    return findings
