"""Quarantine vault.

Files are moved into <data>/quarantine as `<id>.bin`, XOR-obfuscated with a
random per-item key so they can no longer execute or be re-detected by other
AV products, with a `<id>.json` metadata sidecar. Items can be listed,
restored to their original location, or permanently deleted."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import secrets
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List, Optional

from aegis.core.config import Config

_CHUNK = 1024 * 1024


@dataclass
class QuarantineItem:
    id: str
    original_path: str
    sha256: str
    size: int
    threat: str
    quarantined_at: str
    key_hex: str

    @property
    def key(self) -> bytes:
        return bytes.fromhex(self.key_hex)


def _xor_stream(src: Path, dst: Path, key: bytes) -> str:
    """Copy src->dst XOR-ing with key; returns sha256 of the *plain* bytes."""
    h = hashlib.sha256()
    klen = len(key)
    offset = 0
    with src.open("rb") as fi, dst.open("wb") as fo:
        while True:
            chunk = fi.read(_CHUNK)
            if not chunk:
                break
            h.update(chunk)
            o = offset % klen
            n = len(chunk)
            ks = ((key[o:] + key[:o]) * (n // klen + 1))[:n]
            fo.write((int.from_bytes(chunk, "little") ^ int.from_bytes(ks, "little")).to_bytes(n, "little"))
            offset += n
    return h.hexdigest()


class Quarantine:
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config.load()
        self.dir = self.config.quarantine_dir

    def add(self, path: "str | Path", threat: str = "unknown") -> QuarantineItem:
        src = Path(path)
        if not src.is_file():
            raise FileNotFoundError(str(src))
        qid = uuid.uuid4().hex[:16]
        key = secrets.token_bytes(32)
        dst = self.dir / f"{qid}.bin"
        digest = _xor_stream(src, dst, key)
        item = QuarantineItem(
            id=qid,
            original_path=str(src.resolve()),
            sha256=digest,
            size=src.stat().st_size,
            threat=threat,
            quarantined_at=dt.datetime.now().isoformat(timespec="seconds"),
            key_hex=key.hex(),
        )
        (self.dir / f"{qid}.json").write_text(json.dumps(asdict(item), indent=2), encoding="utf-8")
        try:
            _force_remove(src)
        except Exception:
            # Could not delete (locked / in use). Roll back so we don't claim success.
            dst.unlink(missing_ok=True)
            (self.dir / f"{qid}.json").unlink(missing_ok=True)
            raise
        return item

    def list(self) -> List[QuarantineItem]:
        items = []
        for meta in sorted(self.dir.glob("*.json")):
            try:
                items.append(QuarantineItem(**json.loads(meta.read_text(encoding="utf-8"))))
            except Exception:
                continue
        return sorted(items, key=lambda i: i.quarantined_at, reverse=True)

    def get(self, qid: str) -> QuarantineItem:
        for item in self.list():
            if item.id == qid or item.id.startswith(qid):
                return item
        raise KeyError(f"no quarantine item {qid}")

    def restore(self, qid: str, to: Optional["str | Path"] = None, overwrite: bool = False) -> Path:
        item = self.get(qid)
        target = Path(to) if to else Path(item.original_path)
        if target.exists() and not overwrite:
            raise FileExistsError(str(target))
        target.parent.mkdir(parents=True, exist_ok=True)
        digest = _xor_stream(self.dir / f"{item.id}.bin", target, item.key)
        # _xor_stream hashes its input (the obfuscated blob); verify the output instead.
        restored = hashlib.sha256(target.read_bytes()).hexdigest()
        if restored != item.sha256:
            target.unlink(missing_ok=True)
            raise IOError(f"integrity check failed restoring {item.id} ({digest[:8]})")
        self.delete(item.id)
        return target

    def delete(self, qid: str) -> None:
        item = self.get(qid)
        (self.dir / f"{item.id}.bin").unlink(missing_ok=True)
        (self.dir / f"{item.id}.json").unlink(missing_ok=True)


def _force_remove(p: Path) -> None:
    try:
        p.unlink()
    except PermissionError:
        os.chmod(p, 0o666)  # clear read-only attribute on Windows
        p.unlink()
