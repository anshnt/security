"""Small shared helpers for the protect package: result dicts, atomic writes, backup files."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional


def result(ok: bool, changed: bool, message: str, **details: Any) -> Dict[str, Any]:
    """The uniform return shape of every protection function: never raises, always these keys."""
    return {"ok": bool(ok), "changed": bool(changed), "message": message, "details": details}


def stamp() -> str:
    """Timestamp used in backup file names (same shape as core/remediation.py)."""
    return dt.datetime.now().strftime("%Y%m%d-%H%M%S-%f")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def atomic_write_bytes(path: Path, data: bytes, mode_from: Optional[Path] = None) -> None:
    """Write ``data`` next to ``path`` then ``os.replace`` it over the target.

    On POSIX the permission bits (and the owner, when running as root) of ``mode_from`` are
    carried over to the new file. Raises OSError on failure; the temp file is always cleaned up."""
    path = Path(path)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".aegis-tmp", dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass
        if mode_from is not None and mode_from.exists():
            try:
                st = mode_from.stat()
                os.chmod(tmp, st.st_mode & 0o7777)
                if hasattr(os, "chown") and os.geteuid() == 0:  # type: ignore[attr-defined]
                    os.chown(tmp, st.st_uid, st.st_gid)  # type: ignore[attr-defined]
            except OSError:
                pass
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def write_json_atomic(path: Path, payload: Any) -> None:
    atomic_write_bytes(Path(path), json.dumps(payload, indent=2, default=str).encode("utf-8"))


def new_backup_path(backups_dir: Path, kind: str, suffix: str = ".json") -> Path:
    """Unique ``<kind>-<timestamp>[-N]<suffix>`` path inside the backups directory. The file is
    reserved (created empty, exclusively) so two backups in the same clock tick - common on
    Windows - or in parallel processes can never be handed the same name."""
    ts = stamp()
    for n in range(1, 10000):
        p = backups_dir / (f"{kind}-{ts}{suffix}" if n == 1 else f"{kind}-{ts}-{n}{suffix}")
        try:
            with open(p, "x"):
                pass
            return p
        except FileExistsError:
            continue
    raise OSError(f"could not allocate a backup file name for {kind}")
