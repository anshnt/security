"""List and undo every kind of backup Aegis writes into ``config.backups_dir``.

Kinds (file name prefix -> what it holds -> how it is undone)

==========  ====================================================  ==========================================
registry    ``{hive,key,value,data[,view64]}`` from                value restored; deleted again when it did
            ``set_registry_value`` / ``delete_registry_value``     not exist before (set) - a delete-backup
                                                                   of a value that never existed is a no-op
task        ``{name,xml}`` from ``disable_task``                   ``schtasks /Create /XML <file> /F``
service     ``{name,query}`` from ``disable_service``              start type parsed from ``sc qc`` and
                                                                   restored with ``sc config``
hosts       ``{path,content}`` from ``restore_hosts``              hosts file content restored
webhosts    raw hosts file before a web-protection change          hosts file restored byte for byte
harden      one journal per ``aegis.protect.harden.apply`` run     every change reverted, newest first
removed     ``removed-<name>-<stamp>.zip`` from ``remove_path``    extracted to ``restore_to`` (the original
                                                                   location is not recorded in the archive)
==========  ====================================================  ==========================================

Limits worth knowing: registry values are stored through JSON, so REG_BINARY data and the exact REG_EXPAND_SZ type
cannot be restored faithfully; ``kill_process``, ``quarantine_file`` (use the quarantine vault's restore) and
``remove_wmi_subscription`` write no backup. Restoring a hosts/webhosts backup refuses any file other than this
system's hosts file. ``undo`` never raises: it returns ``{"ok","changed","message","details","results"}``.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import logging
import os
import re
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from aegis.core.config import Config
from aegis.core.platform import IS_WINDOWS, is_admin, run
from aegis.protect import harden, webguard
from aegis.protect.util import result, write_json_atomic

log = logging.getLogger("aegis.undo")

_JSON_RE = re.compile(r"^(?P<kind>[a-z][a-z0-9_]*)-(?P<stamp>\d{8}-\d{6}(?:-\d{6})?)(?:-\d+)?\.json$")
_ZIP_RE = re.compile(r"^removed-(?P<name>.+)-(?P<stamp>\d{8}-\d{6})\.zip$")
UNDO_LOG = "undo-log.json"  # not matched by the patterns above, so it never shows up as a backup

KINDS = ("registry", "task", "service", "hosts", "webhosts", "harden", "removed")
WINDOWS_ONLY_KINDS = ("registry", "task", "service")

ADMIN_MSG = ("Administrator rights are required to undo this change because it restores system settings. "
             "Re-run Aegis from an elevated terminal (Windows: 'Run as administrator'; Linux/macOS: sudo).")


# =========================================================================== listing
def _parse_stamp(stamp: str) -> Optional[dt.datetime]:
    for fmt in ("%Y%m%d-%H%M%S-%f", "%Y%m%d-%H%M%S"):
        try:
            return dt.datetime.strptime(stamp, fmt)
        except ValueError:
            continue
    return None


def _short(value: Any, limit: int = 70) -> str:
    text = repr(value) if not isinstance(value, str) else value
    return text if len(text) <= limit else text[:limit - 3] + "..."


def _load_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
        return doc if isinstance(doc, dict) else None
    except (OSError, ValueError):
        return None


def _undo_log(config: Config) -> List[Dict[str, Any]]:
    doc = _load_json(config.backups_dir / UNDO_LOG)
    return list(doc.get("entries", [])) if doc else []


def _mark_undone(config: Config, backup_id: str, kind: str) -> None:
    entries = _undo_log(config)
    entries.append({"id": backup_id, "kind": kind, "at": dt.datetime.now().isoformat(timespec="seconds")})
    try:
        write_json_atomic(config.backups_dir / UNDO_LOG, {"entries": entries})
    except OSError as exc:
        log.warning("could not record the undo in %s: %s", UNDO_LOG, exc)


def _undone_map(config: Config) -> Dict[str, str]:
    return {e.get("id", ""): e.get("at", "") for e in _undo_log(config)}


def _registry_is_delete_backup(doc: Dict[str, Any]) -> bool:
    return "view64" in doc  # only delete_registry_value records it


def _summarise(kind: str, doc: Optional[Dict[str, Any]], path: Path) -> str:
    if kind == "removed":
        try:
            with zipfile.ZipFile(path) as z:
                n = sum(1 for name in z.namelist() if not name.endswith("/"))
        except (OSError, zipfile.BadZipFile):
            n = 0
        m = _ZIP_RE.match(path.name)
        return f"removed folder '{m.group('name') if m else path.stem}' archived ({n} file(s))"
    if not doc:
        return "unreadable backup file"
    if kind == "registry":
        loc = f"{doc.get('hive')}\\{doc.get('key')}\\{doc.get('value')}"
        old = "absent" if doc.get("data") is None else _short(doc.get("data"))
        return f"{'deleted' if _registry_is_delete_backup(doc) else 'changed'} {loc} (previous value: {old})"
    if kind == "task":
        return f"disabled scheduled task {doc.get('name')}"
    if kind == "service":
        st = _parse_service_start(str(doc.get("query", "")))
        return f"disabled service {doc.get('name')} (start type was {st[0] if st else 'unknown'})"
    if kind == "hosts":
        return f"hosts entries neutralised in {doc.get('path')}"
    if kind == "webhosts":
        return (f"hosts file before web protection '{doc.get('reason', 'change')}' ({doc.get('size', '?')} bytes, "
                f"{'with' if doc.get('had_aegis_block') else 'without'} Aegis block)")
    if kind == "harden":
        entries = doc.get("entries") or []
        applied = [e.get("action") for e in entries if e.get("status") == "applied"]
        shown = ", ".join(str(a) for a in applied[:4]) + (", ..." if len(applied) > 4 else "")
        return f"{doc.get('profile', 'custom')} hardening: {len(applied)} applied" + (f" ({shown})" if applied else "")
    return "unknown backup"


def _undoable(kind: str, doc: Optional[Dict[str, Any]]) -> bool:
    if kind not in KINDS:
        return False
    if kind in WINDOWS_ONLY_KINDS and not IS_WINDOWS:
        return False
    if kind == "harden":
        return bool(doc) and doc.get("platform") == harden.current_platform()
    return kind == "removed" or bool(doc)


def list_backups(config: Config, kinds: Optional[Sequence[str]] = None) -> List[Dict[str, Any]]:
    """Every backup in the backups directory, newest first:
    ``{id, kind, timestamp, path, size, summary, undoable, undone}``."""
    out: List[Dict[str, Any]] = []
    undone = _undone_map(config)
    try:
        files = list(config.backups_dir.iterdir())
    except OSError:
        return out
    for path in files:
        if not path.is_file():
            continue
        m = _JSON_RE.match(path.name)
        z = _ZIP_RE.match(path.name)
        if not (m or z):
            continue
        kind = "removed" if z else m.group("kind")  # type: ignore[union-attr]
        stamp = (z or m).group("stamp")  # type: ignore[union-attr]
        if kinds and kind not in kinds:
            continue
        ts = _parse_stamp(stamp)
        if ts is None:
            try:
                ts = dt.datetime.fromtimestamp(path.stat().st_mtime)
            except OSError:
                ts = dt.datetime.min
        doc = None if z else _load_json(path)
        out.append({
            "id": path.stem, "kind": kind if kind in KINDS else "other", "timestamp": ts.isoformat(timespec="seconds"),
            "path": str(path), "size": path.stat().st_size, "summary": _summarise(kind, doc, path),
            "undoable": _undoable(kind, doc), "undone": undone.get(path.stem),
        })
    out.sort(key=lambda e: (e["timestamp"], e["id"]), reverse=True)
    return out


def _resolve(config: Config, backup_id: str) -> Tuple[Optional[Dict[str, Any]], str]:
    """(entry, error). Accepts an exact id, a file name, ``latest`` or a unique prefix."""
    entries = list_backups(config)
    bid = str(backup_id or "").strip()
    if not bid:
        return None, "no backup id given - run `aegis undo list` to see the available backups"
    if bid.lower() == "latest":
        # web-protection hosts snapshots (written by every web change and by hosts undos) are excluded: using
        # "latest" on them would flip the hosts file back and forth - use `aegis protect web off` or an explicit id
        pending = [e for e in entries if e["undoable"] and not e["undone"] and e["kind"] != "webhosts"]
        return (pending[0], "") if pending else (None, "there is nothing left to undo")
    stem = re.sub(r"\.(json|zip)$", "", os.path.basename(bid))
    exact = [e for e in entries if e["id"] == stem]
    if exact:
        return exact[0], ""
    prefix = [e for e in entries if e["id"].startswith(stem)]
    if len(prefix) == 1:
        return prefix[0], ""
    if len(prefix) > 1:
        return None, f"'{bid}' matches {len(prefix)} backups - give more of the id"
    return None, f"no backup named '{bid}' - run `aegis undo list`"


# =========================================================================== per-kind restore
_START_TYPES = {0: "boot", 1: "system", 2: "auto", 3: "demand", 4: "disabled"}


def _parse_service_start(query: str) -> Optional[Tuple[str, str]]:
    """(``sc config`` start= value, label) from ``sc qc`` output. The number is locale independent; the
    English START_TYPE label is preferred and the second 'N WORD' line (TYPE comes first) is the fallback."""
    line = None
    m = re.search(r"^.*START_TYPE.*$", query, re.M)
    if m:
        line = m.group(0)
    else:
        rows = re.findall(r"^\s*\S+\s*:\s*\d+\s+[A-Z_]+.*$", query, re.M)
        if len(rows) >= 2:
            line = rows[1]
    if not line:
        return None
    nm = re.search(r":\s*(\d+)", line)
    if not nm or int(nm.group(1)) not in _START_TYPES:
        return None
    value = int(nm.group(1))
    if value == 2 and "DELAYED" in line.upper():
        return "delayed-auto", "auto (delayed)"
    return _START_TYPES[value], _START_TYPES[value]


def _need_windows(kind: str) -> Optional[Dict[str, Any]]:
    if kind in WINDOWS_ONLY_KINDS and not IS_WINDOWS:
        return result(False, False, f"{kind} backups can only be restored on Windows.", kind=kind)
    return None


def _undo_registry(doc: Dict[str, Any], dry_run: bool) -> Dict[str, Any]:
    hive, key, value = str(doc.get("hive", "")), str(doc.get("key", "")), str(doc.get("value", ""))
    if not (hive and key and value):
        return result(False, False, "the registry backup is incomplete", kind="registry")
    data = doc.get("data")
    delete_backup = _registry_is_delete_backup(doc)
    if delete_backup and data is None:
        return result(True, False, f"{hive}\\{key}\\{value} did not exist before it was 'deleted'; nothing to restore.",
                      kind="registry")
    if isinstance(data, str) and re.match(r"^b['\"]", data):
        return result(False, False, "this value was binary (REG_BINARY); the backup cannot restore it faithfully.",
                      kind="registry")
    if hive.upper() != "HKCU" and not dry_run and not is_admin():
        return result(False, False, ADMIN_MSG, kind="registry", needs_admin=True)
    ok, msg = harden.restore_registry_value(hive, key, value, data, existed=data is not None,
                                            view64=bool(doc.get("view64", True)), dry_run=dry_run)
    return result(ok, ok and not dry_run, msg, kind="registry", results=[{"item": f"{hive}\\{key}\\{value}", "ok": ok, "message": msg}])


_TASK_NAME = re.compile(r"^[^\x00-\x1f\"<>|*?]{1,256}$")


def _undo_task(doc: Dict[str, Any], dry_run: bool) -> Dict[str, Any]:
    name, xml = str(doc.get("name", "")), doc.get("xml")
    if not _TASK_NAME.match(name) or not isinstance(xml, str) or "<Task" not in xml:
        return result(False, False, "the task backup is incomplete or its name is not valid", kind="task")
    if dry_run:
        return result(True, False, f"[dry run] would re-create scheduled task {name} from the saved XML.", kind="task", dry_run=True)
    if not is_admin():
        return result(False, False, ADMIN_MSG, kind="task", needs_admin=True)
    with tempfile.TemporaryDirectory(prefix="aegis-task-") as tmp:
        f = Path(tmp) / "task.xml"
        f.write_text(xml, encoding="utf-16")  # schtasks expects the UTF-16 the export declared
        rc, out, err = run(["schtasks", "/Create", "/TN", name, "/XML", str(f), "/F"], timeout=60)
    msg = (out or err).strip()[:300] or (f"re-created scheduled task {name}" if rc == 0 else "schtasks failed")
    return result(rc == 0, rc == 0, msg, kind="task", results=[{"item": name, "ok": rc == 0, "message": msg}])


_SERVICE_NAME = re.compile(r"^[A-Za-z0-9_.$@ -]{1,256}$")


def _undo_service(doc: Dict[str, Any], dry_run: bool) -> Dict[str, Any]:
    name = str(doc.get("name", ""))
    if not _SERVICE_NAME.match(name):
        return result(False, False, "the service backup has no valid service name", kind="service")
    start = _parse_service_start(str(doc.get("query", "")))
    if start is None:
        return result(False, False, "could not read the original start type from the saved `sc qc` output "
                      "(restore it manually with `sc config <name> start= auto|demand`)", kind="service")
    value, label = start
    if value == "disabled":
        return result(True, False, f"service {name} was already disabled when the backup was taken; nothing to restore.",
                      kind="service")
    if dry_run:
        return result(True, False, f"[dry run] would set service {name} start type to {label}.", kind="service", dry_run=True)
    if not is_admin():
        return result(False, False, ADMIN_MSG, kind="service", needs_admin=True)
    rc, out, err = run(["sc", "config", name, "start=", value], timeout=60)
    msg = ((out or err).strip()[:200] if rc != 0 else
           f"service {name} start type restored to {label}; it is not started automatically - start it with "
           f"`sc start {name}` or restart the PC")
    return result(rc == 0, rc == 0, msg, kind="service", results=[{"item": name, "ok": rc == 0, "message": msg}])


def _same_file(a: Path, b: Path) -> bool:
    return os.path.normcase(os.path.realpath(a)) == os.path.normcase(os.path.realpath(b))


def _restore_hosts_bytes(config: Config, doc_path: str, data: bytes, dry_run: bool, kind: str) -> Dict[str, Any]:
    target = webguard.hosts_path()
    if not _same_file(Path(doc_path), target):
        return result(False, False, f"the backup was taken for {doc_path}, which is not this system's hosts file "
                      f"({target}); refusing to overwrite it.", kind=kind)
    if dry_run:
        return result(True, False, f"[dry run] would restore {target} ({len(data)} bytes).", kind=kind, dry_run=True)
    if not is_admin():
        return result(False, False, ADMIN_MSG, kind=kind, needs_admin=True)
    current = webguard._read_hosts(target) or b""
    if current == data:
        return result(True, False, f"{target} already matches the backup.", kind=kind)
    webguard._backup_hosts(config, target, current, "undo")  # keep the undo itself undoable
    webguard._write_hosts(target, data)
    ok, flush = webguard.flush_dns()
    return result(True, True, f"restored {target} from the backup. {flush}.", kind=kind,
                  results=[{"item": str(target), "ok": True, "message": "restored"}])


def _undo_hosts(config: Config, doc: Dict[str, Any], dry_run: bool) -> Dict[str, Any]:
    content = doc.get("content")
    if not isinstance(content, str) or not doc.get("path"):
        return result(False, False, "the hosts backup is incomplete", kind="hosts")
    try:
        current = webguard._read_hosts(webguard.hosts_path()) or b""
        eol = webguard.parse_hosts_bytes(current).eol if current else ("\r\n" if IS_WINDOWS else "\n")
    except webguard.HostsFormatError:
        eol = "\r\n" if IS_WINDOWS else "\n"
    text = content.replace("\r\n", "\n").replace("\n", eol)  # remediation read the file with universal newlines
    return _restore_hosts_bytes(config, str(doc["path"]), text.encode("utf-8", "surrogateescape"), dry_run, "hosts")


def _undo_webhosts(config: Config, doc: Dict[str, Any], dry_run: bool) -> Dict[str, Any]:
    try:
        data = base64.b64decode(str(doc.get("content_b64", "")), validate=True)
    except ValueError:
        return result(False, False, "the web-protection backup is damaged (content cannot be decoded)", kind="webhosts")
    if not doc.get("path"):
        return result(False, False, "the web-protection backup has no path", kind="webhosts")
    return _restore_hosts_bytes(config, str(doc["path"]), data, dry_run, "webhosts")


def _undo_harden(doc: Dict[str, Any], dry_run: bool) -> Dict[str, Any]:
    if doc.get("platform") != harden.current_platform():
        return result(False, False, f"this journal was written on {doc.get('platform')}; it cannot be reverted on "
                      f"{harden.current_platform()}.", kind="harden")
    if harden.journal_needs_admin(doc) and not dry_run and not is_admin():
        return result(False, False, ADMIN_MSG, kind="harden", needs_admin=True)
    rows = harden.revert_journal(doc, dry_run)
    reverted = [r for r in rows if not r["skipped"]]
    ok = all(r["ok"] for r in rows)
    reboot = any(e.get("needs_reboot") and e.get("status") == "applied" for e in doc.get("entries") or [])
    verb = "would revert" if dry_run else "reverted"
    msg = f"{verb} {len(reverted)} hardening change(s)" + ("" if ok else "; some could not be reverted (see results)")
    if reboot and not dry_run:
        msg += ". A restart is required for some restored settings to take effect."
    results = [{"item": r["action"], "ok": r["ok"], "message": "; ".join(r["messages"])} for r in rows]
    return result(ok, bool(reverted) and not dry_run, ("[dry run] " if dry_run else "") + msg, kind="harden",
                  results=results, reboot_required=reboot and not dry_run)


def _undo_removed(path: Path, restore_to: Optional[str], dry_run: bool) -> Dict[str, Any]:
    if not restore_to:
        return result(False, False, f"The archive does not record where the folder came from. Re-run with a "
                      f"destination (restore_to=<folder>) or extract {path} manually.", kind="removed", needs_destination=True)
    dest = Path(restore_to)
    if dest.exists() and (not dest.is_dir() or any(dest.iterdir())):
        return result(False, False, f"{dest} already exists and is not empty; choose a new folder.", kind="removed")
    try:
        with zipfile.ZipFile(path) as z:
            root = os.path.realpath(dest)
            for member in z.namelist():
                target = os.path.realpath(os.path.join(root, member))
                if target != root and not target.startswith(root + os.sep):
                    return result(False, False, "the archive contains paths outside the destination; refusing to extract.",
                                  kind="removed")
            if dry_run:
                n_files = sum(1 for name in z.namelist() if not name.endswith("/"))
                return result(True, False, f"[dry run] would extract {n_files} file(s) to {dest}.", kind="removed", dry_run=True)
            dest.mkdir(parents=True, exist_ok=True)
            z.extractall(dest)
            count = sum(1 for name in z.namelist() if not name.endswith("/"))
    except (OSError, zipfile.BadZipFile) as exc:
        return result(False, False, f"could not extract {path.name}: {exc}", kind="removed")
    return result(True, True, f"restored {count} file(s) to {dest}.", kind="removed",
                  results=[{"item": str(dest), "ok": True, "message": f"{count} file(s)"}])


# =========================================================================== public API
def undo(config: Config, backup_id: str, dry_run: bool = False, force: bool = False,
         restore_to: Optional[str] = None) -> Dict[str, Any]:
    """Revert one backup (``backup_id`` = id from :func:`list_backups`, ``latest`` = the newest one not yet undone,
    or a unique prefix).

    ``dry_run`` reports what would be restored without touching anything. A backup that was already undone is
    refused unless ``force`` is set. ``restore_to`` is only used for ``removed`` archives. Never raises."""
    try:
        entry, err = _resolve(config, backup_id)
        if entry is None:
            return result(False, False, err)
        kind, path = entry["kind"], Path(entry["path"])
        if kind not in KINDS:
            return result(False, False, f"{entry['id']} is not a backup kind this version of Aegis can undo.", kind=kind)
        if not entry["undoable"]:
            why = (f"{kind} backups can only be restored on Windows" if kind in WINDOWS_ONLY_KINDS and not IS_WINDOWS
                   else "the backup file is unreadable or belongs to another platform")
            return result(False, False, f"{entry['id']} cannot be undone here: {why}.", kind=kind)
        if entry["undone"] and not force and not dry_run:
            return result(False, False, f"{entry['id']} was already undone on {entry['undone']}. Use force to repeat it.",
                          kind=kind, already_undone=True)
        win = _need_windows(kind)
        if win:
            return win
        doc = None if kind == "removed" else _load_json(path)
        if kind != "removed" and doc is None:
            return result(False, False, f"{path.name} could not be read.", kind=kind)
        if kind == "registry":
            res = _undo_registry(doc or {}, dry_run)
        elif kind == "task":
            res = _undo_task(doc or {}, dry_run)
        elif kind == "service":
            res = _undo_service(doc or {}, dry_run)
        elif kind == "hosts":
            res = _undo_hosts(config, doc or {}, dry_run)
        elif kind == "webhosts":
            res = _undo_webhosts(config, doc or {}, dry_run)
        elif kind == "harden":
            res = _undo_harden(doc or {}, dry_run)
        else:
            res = _undo_removed(path, restore_to, dry_run)
        res["details"]["backup_id"] = entry["id"]
        res["details"].setdefault("kind", kind)
        res.setdefault("results", res["details"].pop("results", []))
        res.setdefault("reboot_required", bool(res["details"].get("reboot_required", False)))
        if res["ok"] and not dry_run and (res["changed"] or kind in ("registry", "harden")):
            _mark_undone(config, entry["id"], kind)
        return res
    except Exception as exc:  # noqa: BLE001 - contract: never raise
        log.warning("undo failed: %s", exc, exc_info=True)
        return result(False, False, f"undo failed: {type(exc).__name__}: {exc}")
