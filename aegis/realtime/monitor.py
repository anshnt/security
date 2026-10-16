"""Real-time protection engine.

Four independent guards, each on its own daemon thread(s), share one
`RealtimeMonitor`:

* FileGuard         - watches user-writable folders (ReadDirectoryChangesW on
                      Windows, scandir polling elsewhere / as a fallback),
                      waits for new files to settle, then scans them.
* ProcessGuard      - notices newly started processes, evaluates the command
                      line and image, optionally terminates malicious ones.
* RansomwareGuard   - hidden canary (honeypot) documents, a sliding-window
                      mass-modification detector and an I/O tracker that finds
                      and *suspends* the likely culprit processes.
* PersistenceGuard  - diffs autorun entries and the hosts file.

Honesty note: this is user-mode protection. It reacts within about a second of
an event, it cannot veto an operation before it happens like a kernel
minifilter driver can, and a determined attacker with admin rights can stop it.
"""

from __future__ import annotations

import collections
import hashlib
import inspect
import io
import json
import logging
import math
import os
import random
import re
import secrets
import stat as stat_mod
import string
import struct
import threading
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Deque, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from aegis.core import provenance
from aegis.core.config import Config
from aegis.core.models import Category, Finding, Remediation, Severity
from aegis.core.platform import IS_LINUX, IS_WINDOWS, env_path, is_under, normalize_path, system_binary_dirs, user_home, windows_dir

log = logging.getLogger("aegis.realtime")

EventCallback = Callable[[Finding], None]
WatchSpec = Tuple[Path, bool]  # (directory, recursive)

NOTIFY_MIN_SEVERITY = Severity.MEDIUM
DEDUP_WINDOW_S = 30.0
EVENT_LOG_NAME = "realtime_events.jsonl"
HEARTBEAT_INTERVAL_S = 30.0  # monitor.heartbeat is rewritten this often; `aegis doctor` reads it

SKIP_DIR_NAMES = {".git", "node_modules", "__pycache__", ".venv", "venv", "site-packages", ".cache", "$recycle.bin",
                  "system volume information", ".tox", ".mypy_cache", ".pytest_cache"}
PARTIAL_EXTS = {".crdownload", ".part", ".partial", ".download", ".opdownload"}


def _norm(p: "str | Path") -> str:
    return os.path.normcase(os.path.abspath(str(p)))


# =========================================================================== event log

class EventLog:
    """Append-only JSON-lines log with simple size-based rotation."""

    def __init__(self, path: Path, max_bytes: int = 10 * 1024 * 1024):
        self.path = Path(path)
        self.max_bytes = max_bytes
        self._lock = threading.Lock()

    def write(self, record: Dict[str, Any]) -> None:
        line = json.dumps(record, default=str, ensure_ascii=False)
        with self._lock:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                if self.path.exists() and self.path.stat().st_size > self.max_bytes:
                    os.replace(self.path, self.path.with_suffix(".jsonl.1"))
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            except OSError as exc:
                log.debug("cannot write event log: %s", exc)


# =========================================================================== default watch locations

def default_watch_specs() -> List[WatchSpec]:
    """Where malware lands: downloads, desktop, documents, temp, Startup folders,
    %APPDATA% root (non-recursive) and %PUBLIC%."""
    home = user_home()
    specs: List[WatchSpec] = []
    if IS_WINDOWS:
        specs += [(home / "Downloads", True), (home / "Desktop", True), (home / "Documents", True)]
        for var in ("TEMP", "TMP"):
            p = env_path(var)
            if p:
                specs.append((p, True))
        appdata = env_path("APPDATA")
        if appdata:
            specs.append((appdata / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup", True))
            specs.append((appdata, False))
        pd = env_path("ProgramData")
        if pd:
            specs.append((pd / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "StartUp", True))
        public = env_path("PUBLIC")
        if public:
            specs.append((public, True))
    else:
        specs += [(Path("/tmp"), True), (home / "Downloads", True)]
    seen: Set[str] = set()
    out: List[WatchSpec] = []
    for p, rec in specs:
        key = _norm(p)
        if key not in seen and p.is_dir():
            seen.add(key)
            out.append((p, rec))
    return out


# =========================================================================== file-system watchers

def parse_notify_buffer(buf: bytes, n: int) -> List[Tuple[int, str]]:
    """Decode a FILE_NOTIFY_INFORMATION chain returned by ReadDirectoryChangesW."""
    out: List[Tuple[int, str]] = []
    off = 0
    n = min(n, len(buf))
    while off + 12 <= n:
        nxt, action, namelen = struct.unpack_from("<III", buf, off)
        raw = buf[off + 12: off + 12 + namelen]
        out.append((action, raw.decode("utf-16-le", "replace")))
        if nxt == 0:
            break
        off += nxt
    return out


FsCallback = Callable[[str, str, Optional[str]], None]  # (kind, path, old_path)


class PollingWatcher:
    """Portable watcher: periodic os.scandir snapshot diff. Cheap enough for the
    handful of hot folders we watch (depth and entry caps bound the cost)."""

    def __init__(self, specs: Sequence[WatchSpec], callback: FsCallback, interval: float = 2.0,
                 max_depth: int = 4, max_entries: int = 60000):
        self.specs = list(specs)
        self.callback = callback
        self.interval = interval
        self.max_depth = max_depth
        self.max_entries = max_entries
        self._snap: Optional[Dict[str, Tuple[int, int]]] = None

    def snapshot(self) -> Dict[str, Tuple[int, int]]:
        snap: Dict[str, Tuple[int, int]] = {}
        for root, recursive in self.specs:
            stack: List[Tuple[str, int]] = [(str(root), 0)]
            while stack and len(snap) < self.max_entries:
                d, depth = stack.pop()
                try:
                    with os.scandir(d) as it:
                        for e in it:
                            try:
                                if e.is_dir(follow_symlinks=False):
                                    if recursive and depth < self.max_depth and e.name.lower() not in SKIP_DIR_NAMES:
                                        stack.append((e.path, depth + 1))
                                elif e.is_file(follow_symlinks=False):
                                    st = e.stat(follow_symlinks=False)
                                    snap[e.path] = (st.st_size, st.st_mtime_ns)
                            except OSError:
                                continue
                except OSError:
                    continue
        return snap

    def poll_once(self) -> int:
        """Diff against the previous snapshot; the first call only seeds the baseline."""
        new = self.snapshot()
        old, self._snap = self._snap, new
        if old is None:
            return 0
        created = [p for p in new if p not in old]
        deleted = [p for p in old if p not in new]
        modified = [p for p in new if p in old and new[p] != old[p]]
        # Pair delete+create with identical size/mtime as a rename (typical of ransomware renames).
        by_sig = {old[p]: p for p in deleted if old[p][0] > 0}
        count = 0
        for p in created:
            src = by_sig.pop(new[p], None)
            if src is not None:
                deleted.remove(src)
                self._emit("renamed", p, src)
            else:
                self._emit("created", p)
            count += 1
        for p in modified:
            self._emit("modified", p)
            count += 1
        for p in deleted:
            self._emit("deleted", p)
            count += 1
        return count

    def _emit(self, kind: str, path: str, old: Optional[str] = None) -> None:
        try:
            self.callback(kind, path, old)
        except Exception:
            log.exception("watcher callback failed")

    def run(self, stop: threading.Event) -> None:
        try:
            self.poll_once()  # baseline
        except Exception:
            log.exception("baseline snapshot failed")
        while not stop.wait(self.interval):
            try:
                self.poll_once()
            except Exception:
                log.exception("poll failed")


class WindowsDirWatcher:
    """ReadDirectoryChangesW via ctypes: one blocking call per directory on its own
    thread. Stopped by CancelIoEx. Falls back to polling for that directory if the
    native API cannot be used."""

    FILE_LIST_DIRECTORY = 0x0001
    SHARE_ALL = 0x7
    OPEN_EXISTING = 3
    FLAG_BACKUP_SEMANTICS = 0x02000000
    NOTIFY_FILTER = 0x1 | 0x8 | 0x10  # FILE_NAME | SIZE | LAST_WRITE
    ACTIONS = {1: "created", 2: "deleted", 3: "modified", 4: "rename_old", 5: "rename_new"}

    def __init__(self, spec: WatchSpec, callback: FsCallback, poll_interval: float = 2.0):
        self.root, self.recursive = spec
        self.callback = callback
        self.poll_interval = poll_interval
        self._handle: Any = None
        self._k32: Any = None
        self._stop_evt: Optional[threading.Event] = None
        self.native = False

    def _setup(self) -> bool:
        import ctypes
        from ctypes import wintypes

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
        k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                                    wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        k32.CreateFileW.restype = wintypes.HANDLE
        k32.ReadDirectoryChangesW.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD, wintypes.BOOL,
                                              wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID,
                                              wintypes.LPVOID]
        k32.ReadDirectoryChangesW.restype = wintypes.BOOL
        k32.CancelIoEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
        k32.CancelIoEx.restype = wintypes.BOOL
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        k32.CloseHandle.restype = wintypes.BOOL
        invalid = (1 << (ctypes.sizeof(ctypes.c_void_p) * 8)) - 1
        h = k32.CreateFileW(str(self.root), self.FILE_LIST_DIRECTORY, self.SHARE_ALL, None, self.OPEN_EXISTING,
                            self.FLAG_BACKUP_SEMANTICS, None)
        if h is None or h == invalid:
            return False
        self._k32, self._handle = k32, h
        return True

    def cancel(self) -> None:
        if self._k32 is not None and self._handle:
            try:
                self._k32.CancelIoEx(self._handle, None)
            except Exception:
                pass

    def run(self, stop: threading.Event) -> None:
        self._stop_evt = stop
        try:
            self.native = self._setup()
        except Exception as exc:
            log.debug("native watcher unavailable for %s: %s", self.root, exc)
            self.native = False
        if not self.native:
            PollingWatcher([(self.root, self.recursive)], self.callback, self.poll_interval).run(stop)
            return
        import ctypes
        from ctypes import wintypes

        buf = ctypes.create_string_buffer(64 * 1024)
        returned = wintypes.DWORD(0)
        old_name: Optional[str] = None
        resync: Optional[PollingWatcher] = None
        try:
            while not stop.is_set():
                ok = self._k32.ReadDirectoryChangesW(self._handle, buf, len(buf), self.recursive, self.NOTIFY_FILTER,
                                                     ctypes.byref(returned), None, None)
                if stop.is_set():
                    break
                if not ok:
                    log.debug("ReadDirectoryChangesW failed on %s (err %s)", self.root, ctypes.get_last_error())
                    stop.wait(1.0)
                    continue
                if returned.value == 0:  # buffer overflow: too many changes, resync by snapshot diff
                    if resync is None:
                        resync = PollingWatcher([(self.root, self.recursive)], self.callback, self.poll_interval)
                    resync.poll_once()
                    continue
                for action, name in parse_notify_buffer(buf.raw, returned.value):
                    full = os.path.join(str(self.root), name)
                    kind = self.ACTIONS.get(action)
                    if kind == "rename_old":
                        old_name = full
                    elif kind == "rename_new":
                        self._dispatch("renamed", full, old_name)
                        old_name = None
                    elif kind:
                        self._dispatch(kind, full, None)
        finally:
            try:
                self._k32.CloseHandle(self._handle)
            except Exception:
                pass
            self._handle = None

    def _dispatch(self, kind: str, path: str, old: Optional[str]) -> None:
        try:
            self.callback(kind, path, old)
        except Exception:
            log.exception("watcher callback failed")


# =========================================================================== file guard

@dataclass
class _Pending:
    first_seen: float
    changed_at: float
    sig: Optional[Tuple[int, int]] = None


class FileGuard:
    """Debounced scan-on-write for new / changed files in the watched folders."""

    def __init__(self, monitor: "RealtimeMonitor", specs: Optional[Sequence[WatchSpec]] = None, backend: str = "auto",
                 poll_interval: float = 2.0, stable_secs: float = 1.0, tick: float = 0.25):
        self.monitor = monitor
        self.specs = list(specs) if specs is not None else self._configured_specs(monitor.config)
        self.backend = backend  # auto | native | poll
        self.poll_interval = poll_interval
        self.stable_secs = stable_secs
        self.tick = tick
        self._pending: Dict[str, _Pending] = {}
        self._plock = threading.Lock()
        self._recent: "collections.OrderedDict[str, Tuple[int, int]]" = collections.OrderedDict()
        self._win_watchers: List[WindowsDirWatcher] = []
        self._home = _norm(monitor.config.home)

    @staticmethod
    def _configured_specs(config: Config) -> List[WatchSpec]:
        if config.realtime_watch_dirs:
            return [(Path(os.path.expandvars(d)), True) for d in config.realtime_watch_dirs if Path(os.path.expandvars(d)).is_dir()]
        return default_watch_specs()

    # ---- thread management
    def start(self, stop: threading.Event) -> List[threading.Thread]:
        threads: List[threading.Thread] = []
        use_native = IS_WINDOWS and self.backend in ("auto", "native")
        if use_native:
            for spec in self.specs:
                w = WindowsDirWatcher(spec, self.on_event, self.poll_interval)
                self._win_watchers.append(w)
                threads.append(self.monitor.spawn(f"fs-watch-{spec[0].name or 'root'}", lambda w=w: w.run(stop)))
        elif self.specs:
            pw = PollingWatcher(self.specs, self.on_event, self.poll_interval)
            threads.append(self.monitor.spawn("fs-poll", lambda: pw.run(stop)))
        threads.append(self.monitor.spawn("file-scan", lambda: self._worker(stop)))
        return threads

    def stop(self) -> None:
        for w in self._win_watchers:
            w.cancel()

    def _worker(self, stop: threading.Event) -> None:
        while not stop.wait(self.tick):
            try:
                self.process_pending()
            except Exception:
                log.exception("file guard worker error")

    # ---- event intake (called from watcher threads)
    def _ignored(self, path: str) -> bool:
        n = _norm(path)
        if n.startswith(self._home):
            return True
        base = os.path.basename(n)
        if any(base.endswith(x) for x in PARTIAL_EXTS):
            return True
        try:
            from aegis.scanners.files import _excluded

            if self.monitor.config.exclusions and _excluded(path, self.monitor.config.exclusions):
                return True
        except Exception:
            pass
        return False

    def on_event(self, kind: str, path: str, old_path: Optional[str] = None) -> None:
        if self._ignored(path):
            return
        self.monitor.stats["fs_events"] += 1
        try:
            self.monitor.ransomware.on_fs_event(kind, path, old_path)
        except Exception:
            log.exception("ransomware guard failed on fs event")
        if kind in ("created", "modified", "renamed"):
            self.queue(path)

    def queue(self, path: str) -> None:
        now = time.monotonic()
        with self._plock:
            e = self._pending.get(path)
            if e is None:
                if len(self._pending) >= 10000:
                    return
                self._pending[path] = _Pending(now, now)
            else:
                e.changed_at = now

    # ---- debounce + scan
    def process_pending(self, now: Optional[float] = None) -> int:
        """Scan every pending file whose size/mtime has been stable for `stable_secs`."""
        now = time.monotonic() if now is None else now
        with self._plock:
            items = list(self._pending.items())
        scanned = 0
        for path, e in items:
            try:
                st = os.stat(path)
            except OSError:
                if now - e.first_seen > 5:
                    self._drop(path)
                continue
            if not stat_mod.S_ISREG(st.st_mode):
                self._drop(path)
                continue
            sig = (st.st_size, st.st_mtime_ns)
            if sig != e.sig:
                e.sig, e.changed_at = sig, now
                continue
            if now - e.changed_at < self.stable_secs:
                continue
            if self._recent.get(path) == sig:
                self._drop(path)
                continue
            if not _can_open(path):  # still held by the writer
                if now - e.first_seen > 120:
                    self._drop(path)
                continue
            self._drop(path)
            self._recent[path] = sig
            while len(self._recent) > 4096:
                self._recent.popitem(last=False)
            self.scan_path(path)
            scanned += 1
        return scanned

    def _drop(self, path: str) -> None:
        with self._plock:
            self._pending.pop(path, None)

    def scan_path(self, path: str) -> List[Finding]:
        from aegis.scanners.files import scan_file

        mon = self.monitor
        if mon.ransomware.is_canary(path):
            return []
        try:
            findings = scan_file(mon.context(), Path(path))
        except Exception:
            log.exception("scan_file crashed on %s", path)
            return []
        mon.stats["files_scanned"] += 1
        handled: Set[str] = set()
        out: List[Finding] = []
        origin: Optional[Dict[str, Any]] = None  # read once, and only for a file that has a finding
        for f in sorted(findings, key=lambda x: -int(x.severity)):
            if f.severity < Severity.LOW:
                continue
            f.scanner = f.scanner or "realtime"
            f.evidence.setdefault("source", "file-guard")
            if origin is None:
                origin = download_origin(path)
            for key, value in origin.items():
                f.evidence.setdefault(key, value)
            rem = f.remediation
            target = rem.params.get("path") if rem and rem.action == "quarantine_file" else None
            if target and _norm(target) in handled:
                f.evidence["auto_remediation"] = "file already quarantined"
            else:
                msg = mon.auto_remediate(f)
                if msg and target and f.evidence.get("auto_remediation_ok"):
                    handled.add(_norm(target))
            mon.emit(f, "file-guard")
            out.append(f)
        return out


def _can_open(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            fh.read(1)
        return True
    except OSError:
        return False


def download_origin(path: str) -> Dict[str, Any]:
    """Where a file was downloaded from (zone, query-free addresses, downloading app) as finding evidence; empty when the system
    records no origin. Best effort: it never raises, so it cannot break the file guard."""
    try:
        origin = provenance.read_origin(path)
        return provenance.origin_evidence(origin) if origin else {}
    except Exception:
        log.debug("could not read the origin of %s", path, exc_info=True)
        return {}


# =========================================================================== ransomware guard

KNOWN_EXTS = {
    "txt", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "rtf", "odt", "ods", "odp", "csv", "md", "json", "xml",
    "html", "htm", "css", "js", "ts", "py", "c", "cpp", "h", "hpp", "cs", "java", "go", "rs", "rb", "php", "sql", "ini",
    "cfg", "conf", "log", "yml", "yaml", "toml", "jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "svg", "webp", "heic",
    "mp3", "wav", "flac", "aac", "ogg", "m4a", "mp4", "mkv", "avi", "mov", "wmv", "webm", "zip", "rar", "7z", "gz", "tar",
    "bz2", "xz", "iso", "exe", "dll", "msi", "bat", "cmd", "ps1", "sh", "lnk", "tmp", "bak", "db", "sqlite", "pst", "ost",
    "psd", "ai", "eps", "dwg", "dxf", "obj", "stl", "ttf", "otf", "woff", "woff2", "pyc", "o", "a", "so", "class", "jar",
    "vmdk", "vhd", "vhdx", "ics", "eml", "msg", "key", "pem", "crt", "epub", "mobi", "torrent", "download", "crdownload",
    "part", "lock", "map", "ipynb", "bin", "dat", "cache", "url", "tsv", "sln", "csproj", "vcxproj", "gradle", "kt",
    "swift", "lua", "pl", "r", "scss", "less", "vue", "jsx", "tsx", "numbers", "pages", "keynote", "indd", "raw", "cr2",
    "nef", "arw", "dng", "mpg", "mpeg", "3gp", "flv", "m4v", "wma", "aiff", "mid", "midi", "pptm", "docm", "xlsm",
}
RANSOM_EXTS = {
    "locked", "encrypted", "encrypt", "crypt", "crypted", "crypto", "enc", "locky", "cerber", "zepto", "odin",
    "wncry", "wcry", "wnry", "lockbit", "akira", "blackcat", "alphv", "royal", "hive", "conti", "ryuk", "maze",
    "revil", "sodinokibi", "djvu", "phobos", "dharma", "wallet", "arena", "cezar", "petya", "mamba", "basta",
    "babuk", "hermes", "gandcrab", "cryptolocker", "cryptowall", "xtbl", "ecc", "ezz", "exx", "kraken", "mallox",
    "rhysida", "medusa", "blacksuit", "8base", "nokoyawa",
}
RANSOM_NOTE_RE = re.compile(
    r"(^|[^a-z])(readme|read[_ -]?me|how[_ -]?to|decrypt|restore|recover|instruction|help[_ -]?decrypt|ransom|"
    r"your[_ -]?files|files[_ -]?encrypted|unlock)", re.I)
NOTE_EXTS = {"txt", "html", "htm", "hta", "url", "rtf", "bmp", "png", "jpg"}
CHECKABLE_ENTROPY_EXTS = {"txt", "csv", "log", "md", "rtf", "xml", "json", "html", "htm", "ini", "cfg", "py", "js", "c",
                          "cpp", "h", "java", "cs", "sql", "bmp", "wav", "tif", "tiff", "yml", "yaml"}
MAGIC_BY_EXT: Dict[str, Tuple[bytes, ...]] = {
    "docx": (b"PK\x03\x04",), "xlsx": (b"PK\x03\x04",), "pptx": (b"PK\x03\x04",), "zip": (b"PK\x03\x04",),
    "pdf": (b"%PDF",), "png": (b"\x89PNG",), "jpg": (b"\xff\xd8\xff",), "jpeg": (b"\xff\xd8\xff",),
    "gif": (b"GIF8",), "doc": (b"\xd0\xcf\x11\xe0",), "xls": (b"\xd0\xcf\x11\xe0",), "ppt": (b"\xd0\xcf\x11\xe0",),
    "7z": (b"7z\xbc\xaf",), "mp3": (b"ID3", b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"), "bmp": (b"BM",),
}


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = collections.Counter(data)
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _ext(name: str) -> str:
    return os.path.splitext(name)[1].lower().lstrip(".")


def looks_random_ext(ext: str) -> bool:
    """e.g. 'k3x9a2' - 4-12 chars mixing letters and digits, not a known extension."""
    if not ext or ext in KNOWN_EXTS or not 4 <= len(ext) <= 12 or not ext.isalnum():
        return False
    return any(c.isdigit() for c in ext) and any(c.isalpha() for c in ext)


def is_ransom_note_name(name: str) -> bool:
    return _ext(name) in NOTE_EXTS and bool(RANSOM_NOTE_RE.search(os.path.splitext(name)[0]))


def classify_event(path: str, kind: str, old_path: Optional[str] = None) -> Tuple[str, ...]:
    """Name/extension based ransomware indicators for one file event."""
    name = os.path.basename(path)
    ext = _ext(name)
    reasons: List[str] = []
    if kind in ("created", "renamed"):
        if ext in RANSOM_EXTS:
            reasons.append("ransom-ext")
        elif looks_random_ext(ext):
            reasons.append("random-ext")
    if kind == "renamed" and old_path:
        old_name = os.path.basename(old_path)
        old_ext = _ext(old_name)
        if ext != old_ext and ext not in KNOWN_EXTS and old_ext in KNOWN_EXTS:
            reasons.append("ext-changed")
        if name.lower().startswith(old_name.lower() + ".") and ext not in KNOWN_EXTS:
            reasons.append("ext-appended")
    if kind in ("created", "renamed") and is_ransom_note_name(name):
        reasons.append("ransom-note")
    return tuple(dict.fromkeys(reasons))


def sample_flags(path: str, max_bytes: int = 8192) -> Tuple[str, ...]:
    """Content indicators from the first bytes of a file: header no longer matches
    the extension, or plain-text-like types that now look like random data."""
    ext = _ext(path)
    magics = MAGIC_BY_EXT.get(ext)
    if magics is None and ext not in CHECKABLE_ENTROPY_EXTS:
        return ()
    try:
        with open(path, "rb") as fh:
            head = fh.read(max_bytes)
    except OSError:
        return ()
    if len(head) < 16:
        return ()
    flags: List[str] = []
    if magics and not any(head.startswith(m) for m in magics):
        flags.append("bad-magic")
    if ext in CHECKABLE_ENTROPY_EXTS and _entropy(head) > 7.5:
        flags.append("high-entropy")
    return tuple(flags)


@dataclass
class BurstInfo:
    total: int
    suspicious: int
    notes: int
    window_s: float
    reasons: Dict[str, int]
    sample_paths: List[str]


class BurstDetector:
    """Sliding-window detector for mass file modification / renaming.

    Plain volume is not enough (a git checkout or unzip also touches hundreds of
    files), so a burst only triggers when at least `threshold` distinct files
    changed inside `window` seconds AND a meaningful share of them carry
    ransomware indicators (random/appended extensions, bad magic, high entropy,
    ransom-note names) - or a ransom note appeared alongside a large burst."""

    def __init__(self, window: float = 10.0, threshold: int = 30, min_suspicious: int = 3, suspicious_ratio: float = 0.25):
        self.window = window
        self.threshold = threshold
        self.min_suspicious = min_suspicious
        self.suspicious_ratio = suspicious_ratio
        self._events: Deque[Tuple[float, str, Tuple[str, ...]]] = collections.deque()
        self._lock = threading.Lock()

    def add(self, path: str, reasons: Iterable[str] = (), now: Optional[float] = None) -> None:
        now = time.monotonic() if now is None else now
        with self._lock:
            self._events.append((now, path, tuple(reasons)))
            self._prune(now)

    def _prune(self, now: float) -> None:
        cutoff = now - self.window
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()

    def check(self, now: Optional[float] = None) -> Optional[BurstInfo]:
        now = time.monotonic() if now is None else now
        with self._lock:
            self._prune(now)
            per_path: Dict[str, Set[str]] = {}
            for _ts, path, reasons in self._events:
                per_path.setdefault(path, set()).update(reasons)
        total = len(per_path)
        suspicious_paths = [p for p, r in per_path.items() if r]
        notes = sum(1 for r in per_path.values() if "ransom-note" in r)
        if total < max(5, self.threshold // 2):
            return None
        sus = len(suspicious_paths)
        by_reason = collections.Counter(x for r in per_path.values() for x in r)
        volume_hit = total >= self.threshold and sus >= max(self.min_suspicious, self.suspicious_ratio * total)
        note_hit = notes >= 1 and total >= max(10, self.threshold // 2) and sus >= self.min_suspicious
        if not (volume_hit or note_hit):
            return None
        return BurstInfo(total, sus, notes, self.window, dict(by_reason), (suspicious_paths or list(per_path))[:8])

    def reset(self) -> None:
        with self._lock:
            self._events.clear()


# ---------------------------------------------------------------- canaries

def _zip_bytes(parts: Dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, content in parts.items():
            z.writestr(name, content)
    return buf.getvalue()


_FILLER = ("Quarterly summary and internal planning notes. Budget forecast, vendor invoices, account reconciliation, "
           "payroll review, project milestones and meeting minutes. ")


def build_canary_bytes(ext: str, token: str) -> bytes:
    """Plausible, valid-looking decoy document of the requested type."""
    rng = random.Random(token)  # pseudo-prose that does not deflate to nothing, unique per canary
    words = " ".join("".join(rng.choices(string.ascii_lowercase, k=rng.randint(3, 9))) for _ in range(450))
    body = f"Confidential - {token}. {_FILLER}{words}"
    if ext == "docx":
        return _zip_bytes({
            "[Content_Types].xml": '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
            "_rels/.rels": '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>',
            "word/document.xml": f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>{body}</w:t></w:r></w:p></w:body></w:document>',
        })
    if ext == "xlsx":
        return _zip_bytes({
            "[Content_Types].xml": '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>',
            "_rels/.rels": '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>',
            "xl/workbook.xml": '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>',
            "xl/_rels/workbook.xml.rels": '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>',
            "xl/worksheets/sheet1.xml": f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>{body}</t></is></c></row></sheetData></worksheet>',
        })
    # minimal but structurally valid PDF
    stream = f"BT /F1 12 Tf 72 720 Td ({token} confidential) Tj ET\n% {words}"
    objs = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        f"<< /Length {len(stream)} >>\nstream\n{stream}\nendstream",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, o in enumerate(objs, 1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n{o}\nendobj\n".encode("latin-1")
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


@dataclass
class Canary:
    path: str
    sha256: str
    size: int
    mtime_ns: int
    tripped: bool = False


@dataclass
class CanaryHit:
    path: str
    kind: str  # modified | deleted | renamed
    detail: str = ""


def _hide_file(path: str) -> None:
    if IS_WINDOWS:
        try:
            import ctypes

            ctypes.windll.kernel32.SetFileAttributesW(str(path), 0x2)  # type: ignore[attr-defined]  # FILE_ATTRIBUTE_HIDDEN
        except Exception:
            pass


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class CanaryManager:
    """Hidden decoy documents; any write, rename or delete is a near-certain sign of ransomware
    (or a wiper) walking the user's folders."""

    TYPES = ("docx", "xlsx", "pdf")

    def __init__(self, config: Config, dirs: Optional[Sequence[Path]] = None, state_path: Optional[Path] = None):
        self.config = config
        self.dirs = [Path(d) for d in dirs] if dirs is not None else self.default_dirs()
        self.state_path = state_path or (config.home / "canaries.json")
        self._lock = threading.RLock()
        self.canaries: Dict[str, Canary] = {}  # normalised path -> canary
        self.startup_hits: List[CanaryHit] = []
        self._load()

    @staticmethod
    def default_dirs() -> List[Path]:
        home = user_home()
        out = []
        for n in ("Documents", "Desktop", "Pictures"):
            for base in (home, home / "OneDrive"):
                p = base / n
                if p.is_dir() and p not in out:
                    out.append(p)
        return out

    # ---- state
    def _load(self) -> None:
        try:
            raw = json.loads(self.state_path.read_text(encoding="utf-8"))
            for d in raw:
                c = Canary(**d)
                self.canaries[_norm(c.path)] = c
        except (OSError, ValueError, TypeError):
            pass

    def _save(self) -> None:
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            self.state_path.write_text(json.dumps([c.__dict__ for c in self.canaries.values()], indent=1), encoding="utf-8")
        except OSError as exc:
            log.debug("cannot save canary state: %s", exc)

    # ---- lifecycle
    def deploy(self) -> List[str]:
        """Create missing canaries (one of each type per folder). Returns the created paths."""
        created: List[str] = []
        with self._lock:
            dirs_norm = {_norm(d) for d in self.dirs}
            for key, c in list(self.canaries.items()):
                if _norm(os.path.dirname(c.path)) not in dirs_norm:
                    continue  # canary from a folder we no longer manage; leave it to remove_canaries()
                try:
                    st = os.stat(c.path)
                except OSError:
                    del self.canaries[key]  # missing at startup (user cleanup): recreate silently
                    continue
                if (st.st_size, st.st_mtime_ns) != (c.size, c.mtime_ns) and _sha256_file(c.path) != c.sha256:
                    self.startup_hits.append(CanaryHit(c.path, "modified", "changed while real-time protection was off"))
                    c.tripped = True
                    continue
            present = {(_norm(os.path.dirname(c.path)), _ext(c.path)) for c in self.canaries.values()}
            for d in self.dirs:
                for ext in self.TYPES:
                    if (_norm(d), ext) in present:
                        continue
                    path = self._create(d, ext)
                    if path:
                        created.append(path)
            self._save()
        return created

    def _create(self, directory: Path, ext: str) -> Optional[str]:
        token = secrets.token_hex(3)
        path = str(directory / f"~$aegis-canary-{token}.{ext}")
        try:
            data = build_canary_bytes(ext, token)
            with open(path, "wb") as fh:
                fh.write(data)
            _hide_file(path)
            st = os.stat(path)
        except OSError as exc:
            log.debug("cannot create canary in %s: %s", directory, exc)
            return None
        self.canaries[_norm(path)] = Canary(path, hashlib.sha256(data).hexdigest(), st.st_size, st.st_mtime_ns)
        return path

    def remove_canaries(self) -> int:
        n = 0
        with self._lock:
            for c in list(self.canaries.values()):
                try:
                    if IS_WINDOWS:
                        try:
                            import ctypes

                            ctypes.windll.kernel32.SetFileAttributesW(c.path, 0x80)  # type: ignore[attr-defined]
                        except Exception:
                            pass
                    os.remove(c.path)
                    n += 1
                except FileNotFoundError:
                    pass
                except OSError as exc:
                    log.debug("cannot remove canary %s: %s", c.path, exc)
            self.canaries.clear()
            self._save()
        return n

    def rearm(self) -> List[str]:
        """Forget tripped canaries (after the user has dealt with an incident) and recreate them."""
        with self._lock:
            for key, c in list(self.canaries.items()):
                if c.tripped:
                    try:
                        os.remove(c.path)
                    except OSError:
                        pass
                    del self.canaries[key]
        return self.deploy()

    # ---- detection
    def is_canary(self, path: str) -> bool:
        return _norm(path) in self.canaries

    def paths(self) -> List[str]:
        return [c.path for c in self.canaries.values()]

    def _verify(self, c: Canary) -> Optional[CanaryHit]:
        if c.tripped:
            return None
        try:
            st = os.stat(c.path)
        except FileNotFoundError:
            c.tripped = True
            return CanaryHit(c.path, "deleted", "canary file was deleted or renamed")
        except OSError:
            return None
        if (st.st_size, st.st_mtime_ns) == (c.size, c.mtime_ns):
            return None
        try:
            digest = _sha256_file(c.path)
        except OSError:
            return None
        if digest == c.sha256:
            c.size, c.mtime_ns = st.st_size, st.st_mtime_ns  # merely touched
            return None
        c.tripped = True
        return CanaryHit(c.path, "modified", "canary file contents were changed")

    def check_event(self, kind: str, path: str, old_path: Optional[str] = None) -> Optional[CanaryHit]:
        """Decide whether a file-system event touches a canary."""
        with self._lock:
            if kind == "renamed" and old_path:
                c = self.canaries.get(_norm(old_path))
                if c and not c.tripped:
                    c.tripped = True
                    return CanaryHit(c.path, "renamed", f"renamed to {os.path.basename(path)}")
            c = self.canaries.get(_norm(path))
            if c is None or kind == "created":
                return None
            if kind == "deleted":
                if c.tripped:
                    return None
                c.tripped = True
                return CanaryHit(c.path, "deleted", "canary file was deleted")
            if kind in ("modified", "renamed"):
                return self._verify(c)
        return None

    def poll(self) -> List[CanaryHit]:
        """Cheap periodic stat of every canary - independent of the file watchers."""
        hits = []
        with self._lock:
            for c in list(self.canaries.values()):
                h = self._verify(c)
                if h:
                    hits.append(h)
        return hits


# ---------------------------------------------------------------- process I/O tracking

PROTECTED_NAMES = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe",
    "svchost.exe", "dwm.exe", "explorer.exe", "fontdrvhost.exe", "spoolsv.exe", "wmiprvse.exe", "msmpeng.exe",
    "nissrv.exe", "searchindexer.exe", "system idle process", "memory compression", "sihost.exe", "taskhostw.exe",
    "runtimebroker.exe", "ctfmon.exe", "audiodg.exe", "lsm.exe", "init", "systemd", "kthreadd",
}
BENIGN_HEAVY_WRITERS = {
    "onedrive.exe", "dropbox.exe", "googledrivefs.exe", "backupandsync.exe", "icloudservices.exe", "idrive.exe",
    "msiexec.exe", "trustedinstaller.exe", "tiworker.exe", "wuauclt.exe", "usoclient.exe", "robocopy.exe",
}


def _own_ancestors() -> Set[int]:
    """pids of this process and its parent chain (shell, terminal, IDE...)."""
    out: Set[int] = {os.getpid()}
    try:
        import psutil

        out.update(p.pid for p in psutil.Process().parents())
    except Exception:
        out.add(os.getppid())
    return out


def is_protected_process(pid: int, name: str, exe: str) -> bool:
    """True for processes Aegis must never suspend or kill automatically."""
    if pid in (0, 1, 4) or pid in _own_ancestors():
        return True
    low = (name or "").lower()
    if low in PROTECTED_NAMES:
        return True
    if not exe:
        return True  # cannot identify (kernel thread / access denied) - do not touch
    if is_under(exe, [Path(p) for p in system_binary_dirs()]):
        return True
    return False


@dataclass
class Culprit:
    pid: int
    name: str
    exe: str
    write_bytes: int


class IOTracker:
    """Per-process write-byte deltas over a short history; used to find which process
    is hammering the disk when a ransomware alert fires."""

    def __init__(self, history_s: float = 20.0):
        self.history_s = history_s
        self._last: Dict[int, int] = {}
        self._hist: Deque[Tuple[float, Dict[int, int]]] = collections.deque()
        self._lock = threading.Lock()

    def feed(self, counters: Dict[int, int], now: Optional[float] = None) -> None:
        """Record cumulative write_bytes per pid (separated from psutil for testing)."""
        now = time.monotonic() if now is None else now
        deltas: Dict[int, int] = {}
        with self._lock:
            for pid, wb in counters.items():
                prev = self._last.get(pid)
                if prev is not None and wb > prev:
                    deltas[pid] = wb - prev
            self._last = dict(counters)
            self._hist.append((now, deltas))
            while self._hist and self._hist[0][0] < now - self.history_s:
                self._hist.popleft()

    def poll(self, now: Optional[float] = None) -> None:
        try:
            import psutil
        except ImportError:  # pragma: no cover
            return
        counters: Dict[int, int] = {}
        for p in psutil.process_iter():
            try:
                counters[p.pid] = p.io_counters().write_bytes
            except (psutil.Error, AttributeError, OSError):
                continue
        self.feed(counters, now)

    def totals(self, window_s: float = 10.0, now: Optional[float] = None) -> Dict[int, int]:
        now = time.monotonic() if now is None else now
        out: Dict[int, int] = collections.defaultdict(int)
        with self._lock:
            for ts, deltas in self._hist:
                if ts >= now - window_s:
                    for pid, d in deltas.items():
                        out[pid] += d
        return dict(out)

    def top_writers(self, window_s: float = 10.0, n: int = 3, min_bytes: int = 1 << 20,
                    now: Optional[float] = None) -> List[Culprit]:
        try:
            import psutil
        except ImportError:  # pragma: no cover
            return []
        out: List[Culprit] = []
        for pid, wb in sorted(self.totals(window_s, now).items(), key=lambda kv: -kv[1]):
            if wb < min_bytes:
                break
            try:
                p = psutil.Process(pid)
                name, exe = p.name(), p.exe()
            except (psutil.Error, OSError):
                continue
            if is_protected_process(pid, name, exe) or name.lower() in BENIGN_HEAVY_WRITERS:
                continue
            out.append(Culprit(pid, name, exe, wb))
            if len(out) >= n:
                break
        return out


class RansomwareGuard:
    def __init__(self, monitor: "RealtimeMonitor", canary_dirs: Optional[Sequence[Path]] = None, interval: float = 1.0,
                 burst: Optional[BurstDetector] = None, suspend: bool = True, cooldown: float = 60.0,
                 state_path: Optional[Path] = None):
        self.monitor = monitor
        self.interval = interval
        self.suspend_enabled = suspend
        self.cooldown = cooldown
        self.burst = burst or BurstDetector()
        self.io = IOTracker()
        self.canaries = CanaryManager(monitor.config, canary_dirs, state_path) if monitor.config.ransomware_canaries else None
        self.suspended: Dict[int, Culprit] = {}
        self._last_burst = float("-inf")  # monotonic() counts from boot: 0.0 would mute bursts right after startup
        self._sample_tokens = 40.0
        self._sample_ts = time.monotonic()

    def start(self, stop: threading.Event) -> List[threading.Thread]:
        if self.canaries is not None:
            try:
                self.canaries.deploy()
                for hit in self.canaries.startup_hits:
                    self._on_canary(hit, startup=True)
                self.canaries.startup_hits.clear()
            except Exception:
                log.exception("canary deployment failed")
        return [self.monitor.spawn("ransomware", lambda: self._loop(stop))]

    def _loop(self, stop: threading.Event) -> None:
        while not stop.wait(self.interval):
            try:
                self.tick()
            except Exception:
                log.exception("ransomware guard tick failed")

    def tick(self) -> None:
        self.io.poll()
        if self.canaries is not None:
            for hit in self.canaries.poll():
                self._on_canary(hit)
        info = self.burst.check()
        if info:
            self._on_burst(info)

    def remove_canaries(self) -> int:
        return self.canaries.remove_canaries() if self.canaries else 0

    def is_canary(self, path: str) -> bool:
        return bool(self.canaries and self.canaries.is_canary(path))

    # ---- intake
    def _take_sample_token(self) -> bool:
        now = time.monotonic()
        self._sample_tokens = min(40.0, self._sample_tokens + (now - self._sample_ts) * 20.0)
        self._sample_ts = now
        if self._sample_tokens >= 1.0:
            self._sample_tokens -= 1.0
            return True
        return False

    def on_fs_event(self, kind: str, path: str, old_path: Optional[str] = None) -> None:
        if self.canaries is not None:
            if self.canaries.is_canary(path) or (old_path and self.canaries.is_canary(old_path)):
                hit = self.canaries.check_event(kind, path, old_path)
                if hit:
                    self._on_canary(hit)
                return
        if kind == "deleted":
            return
        reasons = list(classify_event(path, kind, old_path))
        if kind in ("modified", "renamed", "created") and self._take_sample_token():
            reasons += list(sample_flags(path))
        self.burst.add(path, reasons)

    # ---- response
    def _suspend_culprits(self) -> List[Culprit]:
        culprits = self.io.top_writers()
        done: List[Culprit] = []
        if not self.suspend_enabled:
            return culprits
        import psutil

        for c in culprits:
            if c.pid in self.suspended:
                done.append(c)
                continue
            try:
                psutil.Process(c.pid).suspend()
                self.suspended[c.pid] = c
                done.append(c)
                log.critical("ransomware guard suspended pid %s (%s)", c.pid, c.exe)
            except (psutil.Error, OSError) as exc:
                log.warning("could not suspend pid %s: %s", c.pid, exc)
        return done

    def resume(self, pid: int) -> bool:
        """Resume a process this guard suspended (user decided it was a false alarm)."""
        import psutil

        try:
            psutil.Process(pid).resume()
            self.suspended.pop(pid, None)
            return True
        except (psutil.Error, OSError):
            return False

    def _culprit_evidence(self, culprits: List[Culprit]) -> Dict[str, Any]:
        return {
            "suspect_processes": [{"pid": c.pid, "name": c.name, "exe": c.exe, "bytes_written_10s": c.write_bytes}
                                  for c in culprits],
            "suspended_pids": sorted(self.suspended),
        }

    def _on_canary(self, hit: CanaryHit, startup: bool = False) -> None:
        culprits = [] if startup else self._suspend_culprits()
        ev = {"canary": hit.path, "action": hit.kind, "detail": hit.detail, **self._culprit_evidence(culprits)}
        rem = Remediation("kill_process", {"pid": culprits[0].pid, "path": culprits[0].exe, "quarantine": False},
                          f"Terminate {culprits[0].name} (pid {culprits[0].pid})") if culprits else None
        sev = Severity.HIGH if startup else Severity.CRITICAL
        named = ", ".join(f"{c.name} (pid {c.pid})" for c in culprits if c.pid in self.suspended)
        f = Finding(
            "AEG-RANSOM-CANARY", "Ransomware canary file tampered" if not startup else "Canary file changed while protection was off",
            sev, Category.RANSOMWARE,
            f"A hidden decoy document was {hit.kind} ({hit.detail}). Normal software never touches these files; "
            "ransomware that encrypts or wipes documents does." + (f" Suspected process(es), now suspended: {named}." if named else ""),
            hit.path, ev,
            "Disconnect the PC from the network, do NOT reboot, review the suspended processes and terminate them. "
            "Restore any damaged files from backup.", rem, "realtime", ["T1486", "T1485"])
        self.monitor.emit(f, "ransomware-guard", force=True)

    def _on_burst(self, info: BurstInfo) -> None:
        now = time.monotonic()
        if now - self._last_burst < self.cooldown:
            return
        self._last_burst = now
        culprits = self._suspend_culprits()
        ev = {"files_changed": info.total, "suspicious_files": info.suspicious, "ransom_notes": info.notes,
              "window_s": info.window_s, "indicators": info.reasons, "sample_paths": info.sample_paths,
              **self._culprit_evidence(culprits)}
        rem = Remediation("kill_process", {"pid": culprits[0].pid, "path": culprits[0].exe, "quarantine": False},
                          f"Terminate {culprits[0].name} (pid {culprits[0].pid})") if culprits else None
        named = ", ".join(f"{c.name} (pid {c.pid})" for c in culprits if c.pid in self.suspended)
        f = Finding(
            "AEG-RANSOM-BURST", "Possible ransomware: mass file modification", Severity.CRITICAL, Category.RANSOMWARE,
            f"{info.total} files changed within {info.window_s:.0f}s and {info.suspicious} carry ransomware indicators "
            f"({', '.join(sorted(info.reasons))})." + (f" Highest disk writers, now suspended: {named}." if named else
                                                       " No suspendable culprit process could be identified."),
            "user folders", ev,
            "If you did not start a bulk operation, disconnect from the network, keep the PC on, and terminate the "
            "suspended process. Restore damaged files from backup.", rem, "realtime", ["T1486"])
        self.monitor.emit(f, "ransomware-guard", force=True)
        self.burst.reset()


# =========================================================================== process guard

HIGH_CONFIDENCE_PREFIXES = ("AEG-SIG", "AEG-RULE", "AEG-YARA", "AEG-DEFENDER", "AEG-VT")
SIGMA_RELOAD_S = 600.0  # how often the process guard checks whether the Sigma rule files changed


class ProcessGuard:
    """Evaluates newly started processes. Detection happens right after start (poll
    interval), not before execution - a kernel driver would be needed for that."""

    def __init__(self, monitor: "RealtimeMonitor", interval: float = 1.5,
                 analyse_fn: Optional[Callable[[str], list]] = None,
                 scan_fn: Optional[Callable[[Any, Path], List[Finding]]] = None,
                 sigma_rules: Optional[Any] = None):
        self.monitor = monitor
        self.interval = interval
        self.analyse_fn = analyse_fn
        self.scan_fn = scan_fn
        self._sigma_fixed = sigma_rules  # explicit SigmaRuleSet (tests); otherwise loaded lazily from disk
        self._sigma: Any = None  # lazily loaded process_creation rules; False = engine unavailable
        self._sigma_checked = float("-inf")
        self._seen: Dict[int, float] = {}
        self._retries: Dict[int, int] = {}  # pids re-read because their cmdline was empty
        self._scanned_exes: "collections.OrderedDict[Tuple[str, int, int], List[Finding]]" = collections.OrderedDict()

    def start(self, stop: threading.Event) -> List[threading.Thread]:
        self.seed()
        return [self.monitor.spawn("process-guard", lambda: self._loop(stop))]

    def _loop(self, stop: threading.Event) -> None:
        while not stop.wait(self.interval):
            try:
                self.poll_once()
            except Exception:
                log.exception("process guard poll failed")

    def seed(self) -> None:
        import psutil

        for pid in psutil.pids():
            try:
                self._seen[pid] = psutil.Process(pid).create_time()
            except (psutil.Error, OSError):
                self._seen[pid] = 0.0

    def _info(self, pid: int) -> Optional[Dict[str, Any]]:
        import psutil

        try:
            p = psutil.Process(pid)
            with p.oneshot():
                info = {"pid": pid, "create_time": p.create_time(), "name": p.name(), "ppid": p.ppid()}
                for key, fn in (("exe", p.exe), ("cmdline", p.cmdline), ("username", p.username)):
                    try:
                        info[key] = fn()
                    except (psutil.Error, OSError):
                        info[key] = "" if key != "cmdline" else []
            info["parent_name"] = info["parent_exe"] = info["parent_cmdline"] = ""
            try:
                parent = psutil.Process(info["ppid"])
                # PID-reuse guard: a real parent started before its child
                if parent.create_time() <= info["create_time"] + 1.0:
                    info["parent_name"] = parent.name()
                    for key, fn in (("parent_exe", parent.exe), ("parent_cmdline", lambda: " ".join(parent.cmdline()))):
                        try:
                            info[key] = fn()
                        except (psutil.Error, OSError):
                            pass
            except (psutil.Error, OSError):
                pass
            return info
        except (psutil.Error, OSError):
            return None

    def poll_once(self) -> List[Dict[str, Any]]:
        import psutil

        current = set(psutil.pids())
        new_infos: List[Dict[str, Any]] = []
        for pid in current:
            if pid in self._seen:
                continue
            info = self._info(pid)
            if info is None:
                continue
            if not info.get("cmdline") and self._retries.get(pid, 0) < 2:
                # Caught mid-exec (or not readable yet): an empty command line would
                # skip command-line analysis entirely, so look again next poll.
                self._retries[pid] = self._retries.get(pid, 0) + 1
                continue
            self._retries.pop(pid, None)
            self._seen[pid] = info["create_time"]
            if info["ppid"] == os.getpid() or pid == os.getpid():
                continue  # our own helpers (toast PowerShell etc.)
            new_infos.append(info)
        for pid in [p for p in self._seen if p not in current]:
            del self._seen[pid]  # also lets reused pids be seen again
        for pid in [p for p in self._retries if p not in current]:
            del self._retries[pid]
        for info in new_infos:
            self.monitor.stats["processes_seen"] += 1
            try:
                self.handle(info)
            except Exception:
                log.exception("process evaluation failed for pid %s", info.get("pid"))
        return new_infos

    # ---- evaluation
    def _analyse(self, cmd: str) -> list:
        fn = self.analyse_fn
        if fn is None:
            try:
                from aegis.core.cmdline import analyse_command_line as fn  # type: ignore[assignment]
            except Exception:
                return []
        try:
            return list(fn(cmd))  # type: ignore[misc]
        except Exception:
            return []

    def _scan_exe(self, exe: str) -> List[Finding]:
        if not exe or is_under(exe, [Path(p) for p in system_binary_dirs()]):
            return []
        try:
            st = os.stat(exe)
        except OSError:
            return []
        key = (_norm(exe), st.st_size, st.st_mtime_ns)
        if key in self._scanned_exes:
            return []  # already evaluated this exact binary (findings were reported then)
        self._scanned_exes[key] = []
        while len(self._scanned_exes) > 2048:
            self._scanned_exes.popitem(last=False)
        fn = self.scan_fn
        if fn is None:
            from aegis.scanners.files import scan_file as fn  # type: ignore[assignment]
        return list(fn(self.monitor.context(), Path(exe)))  # type: ignore[misc]

    def _scanner_findings(self, info: Dict[str, Any]) -> Optional[List[Finding]]:
        """Reuse the processes scanner's per-process logic (masquerading, suspicious parent/child
        chains, command-line rules, deleted images). Returns None if that module is unavailable."""
        try:
            from aegis.scanners import processes as P
        except Exception:
            return None
        try:
            ev = getattr(P, "evaluate_process", None)
            if callable(ev):  # explicit single-process entry point, if the scanner offers one
                import psutil

                params = inspect.signature(ev).parameters
                cmd = " ".join(info["cmdline"])
                avail = {"ctx": self.monitor.context(), "context": self.monitor.context(), "info": info, "pid": info["pid"],
                         "proc": psutil.Process(info["pid"]), "process": psutil.Process(info["pid"]), "name": info["name"],
                         "exe": info["exe"], "cmdline": cmd, "cmd": cmd, "ppid": info["ppid"]}
                if all(k in avail for k, p in params.items() if p.default is inspect.Parameter.empty):
                    res = ev(**{k: avail[k] for k in params if k in avail})
                    return [f for f in (res or []) if isinstance(f, Finding)]
            proc_cls = getattr(P, "ProcInfo", None)
            if proc_cls is None:
                return None
            join = getattr(P, "_join_cmdline", None)
            cmd = join(info["cmdline"]) if callable(join) else " ".join(info["cmdline"])
            proc = proc_cls(pid=info["pid"], name=info["name"], ppid=info["ppid"], exe=info.get("exe", ""), cmdline=cmd,
                            username=info.get("username", "") or "", create_time=info.get("create_time", 0.0),
                            parent_name=info.get("parent_name", ""), parent_cmdline=info.get("parent_cmdline", ""),
                            parent_exe=info.get("parent_exe", ""))
            out: List[Finding] = []
            for fname in ("masquerade_findings", "chain_findings", "cmdline_findings", "deleted_exe_findings"):
                fn = getattr(P, fname, None)
                if not callable(fn):
                    continue
                try:
                    out += [f for f in fn([proc], skip={os.getpid()}) if f.severity >= Severity.MEDIUM]
                except Exception as exc:
                    log.debug("%s failed: %s", fname, exc)
            return out
        except Exception as exc:
            log.debug("processes scanner unavailable: %s", exc)
            return None

    def _sigma_ruleset(self) -> Any:
        """The Sigma process_creation rules, loaded on first use and reloaded when the rule files change.
        None when PyYAML is missing or no rules are installed."""
        if self._sigma_fixed is not None:
            return self._sigma_fixed
        now = time.monotonic()
        if self._sigma is not None and now - self._sigma_checked < SIGMA_RELOAD_S:
            return self._sigma or None
        self._sigma_checked = now
        try:
            from aegis.core import sigma

            cfg = self.monitor.config
            if self._sigma and sigma.rules_signature(cfg) == self._sigma.signature:
                return self._sigma
            rules = sigma.load_rules(cfg, categories=("process_creation",))
            self._sigma = rules if rules.available and len(rules) else False
        except Exception:
            log.debug("sigma rules unavailable", exc_info=True)
            self._sigma = self._sigma or False
        return self._sigma or None

    def _with_sigma(self, info: Dict[str, Any], findings: List[Finding]) -> List[Finding]:
        """Add the Sigma process_creation matches for this process. A match that describes the same technique as a
        finding we already have is folded into it (one alert per behaviour); Sigma alone never auto-terminates.
        Optional and guarded: without PyYAML, rules or the Sigma module the findings are returned unchanged."""
        if self._sigma_fixed is None and (self.analyse_fn is not None or self.scan_fn is not None):
            return findings  # analysis functions were injected (tests): evaluate exactly what was asked for
        try:
            rules = self._sigma_ruleset()
            if not rules:
                return findings
            from aegis.core import sigma

            ev = sigma.event_from_process(info, "windows" if IS_WINDOWS else "linux")
            exe = info.get("exe") or ""
            for rule, matched in rules.match(ev):
                sf = sigma.finding_for_match(rule, matched, ev)
                if sf.severity < Severity.MEDIUM:
                    continue
                sf.severity = min(sf.severity, Severity.HIGH)  # a behaviour rule alone is not grounds to kill a process
                base = next((f for f in findings if sigma.same_technique(f.mitre, sf.mitre)), None)
                if base is not None:
                    sigma.fold_finding(base, sf)
                    continue
                sf.remediation = Remediation("kill_process", {"pid": info["pid"], "path": exe, "quarantine": False},
                                             f"Terminate {info.get('name')} (pid {info['pid']})")
                findings.append(sf)
        except Exception:
            log.debug("sigma evaluation failed for pid %s", info.get("pid"), exc_info=True)
        return findings

    def _with_browser_risk(self, info: Dict[str, Any], findings: List[Finding]) -> List[Finding]:
        """Add a finding when a browser starts with cookie-theft switches (hidden remote debugging, an extension loaded
        from a drop folder): the same classifier the apptamper scanner uses. It alerts only; the rule is not one the
        guard auto-terminates for."""
        if self.analyse_fn is not None or self.scan_fn is not None:
            return findings
        try:
            from aegis.scanners import apptamper

            argv = [str(a) for a in (info.get("cmdline") or [])]
            risk = apptamper.browser_cmdline_risk(info.get("name") or "", argv, info.get("exe") or "")
            if risk:
                proc = apptamper.BrowserProc(info["pid"], info.get("name") or "", info.get("exe") or "", argv,
                                             str(info.get("username") or ""), float(info.get("create_time") or 0.0))
                findings.append(apptamper.browser_process_finding(proc, risk))
        except Exception:
            log.debug("browser launch check failed for pid %s", info.get("pid"), exc_info=True)
        return findings

    def evaluate(self, info: Dict[str, Any]) -> List[Finding]:
        exe = info.get("exe") or ""
        cmd = " ".join(info.get("cmdline") or [])
        injected = self.analyse_fn is not None or self.scan_fn is not None
        findings = None if injected else self._scanner_findings(info)
        if findings is None:  # fall back to the shared command-line rules
            findings = []
            for hit in self._analyse(cmd):
                rule_id, title, sev, mitre, matched = hit[:5]
                if Severity.parse(sev) < Severity.MEDIUM:
                    continue
                findings.append(Finding(
                    rule_id, title, Severity.parse(sev), Category.PROCESS,
                    f"A newly started process has a suspicious command line (matched: {matched}).",
                    exe or info.get("name", ""), {"pid": info["pid"], "cmdline": cmd[:1000], "matched": str(matched)[:200]},
                    "Review the process; terminate it if you did not expect it.",
                    Remediation("kill_process", {"pid": info["pid"], "path": exe, "quarantine": False},
                                f"Terminate {info.get('name')} (pid {info['pid']})"),
                    "realtime", list(mitre or [])))
        findings = self._with_sigma(info, self._with_browser_risk(info, list(findings))) + self._scan_exe(exe)
        for f in findings:
            f.scanner = f.scanner or "realtime"
            f.evidence.setdefault("pid", info["pid"])
            f.evidence.setdefault("parent", info.get("parent_name", ""))
            f.evidence.setdefault("source", "process-guard")
        return findings

    def should_kill(self, info: Dict[str, Any], findings: List[Finding]) -> bool:
        if not self.monitor.config.realtime_kill_malicious_processes or not findings:
            return False
        if is_protected_process(info["pid"], info.get("name", ""), info.get("exe", "")):
            return False
        for f in findings:
            if f.severity >= Severity.CRITICAL:
                return True
            if f.severity >= Severity.HIGH and f.rule_id.startswith(HIGH_CONFIDENCE_PREFIXES):
                return True
        return False

    def handle(self, info: Dict[str, Any]) -> List[Finding]:
        findings = self.evaluate(info)
        if not findings:
            return []
        exe = info.get("exe") or ""
        if self.should_kill(info, findings):
            quarantine = any(f.remediation and f.remediation.action == "quarantine_file" and
                             _norm(f.remediation.params.get("path", "")) == _norm(exe) for f in findings if exe)
            top = max(findings, key=lambda f: int(f.severity))
            kill = Finding(top.rule_id, top.title, top.severity, Category.PROCESS, top.description, top.location,
                           dict(top.evidence), remediation=Remediation(
                               "kill_process", {"pid": info["pid"], "path": exe, "quarantine": quarantine}))
            from aegis.core.remediation import apply_remediation

            ok, msg = apply_remediation(kill, self.monitor.config)
            top.evidence["auto_remediation"] = msg
            top.evidence["auto_remediation_ok"] = ok
            top.title = ("Blocked: " if ok else "Could not block: ") + top.title
            self.monitor.stats["processes_killed"] += int(ok)
        for f in findings:
            self.monitor.emit(f, "process-guard")
        return findings


# =========================================================================== persistence guard

_NAME_KEYS = ("name", "entry", "value_name", "title", "label")
_LOC_KEYS = ("location", "key", "reg_key", "source", "where", "path")
_CMD_KEYS = ("command", "cmd", "image_path", "imagepath", "target", "commandline", "command_line", "exe", "value", "data")
_KIND_KEYS = ("kind", "type", "category", "mechanism", "technique")


def _pick(entry: Any, keys: Sequence[str]) -> str:
    for k in keys:
        v = entry.get(k) if isinstance(entry, dict) else getattr(entry, k, None)
        if v not in (None, "") and not callable(v):
            return str(v)
    return ""


def normalise_entry(entry: Any) -> Dict[str, Any]:
    """Adapt whatever `collect_entries()` returns (the persistence scanner's dicts, or any
    object with similar attributes) to a flat dict."""
    d: Dict[str, Any] = {"kind": _pick(entry, _KIND_KEYS), "name": _pick(entry, _NAME_KEYS),
                         "location": _pick(entry, _LOC_KEYS), "command": _pick(entry, _CMD_KEYS), "raw": entry}
    d["key"] = "|".join(d[k] for k in ("kind", "location", "name", "command")).lower()
    rem = entry.get("remediation") if isinstance(entry, dict) else getattr(entry, "remediation", None)
    if not isinstance(rem, Remediation):
        meta = entry.get("meta") if isinstance(entry, dict) else getattr(entry, "meta", None)
        rd = meta.get("remediation") if isinstance(meta, dict) else None  # persistence scanner's format
        rem = Remediation(rd["action"], dict(rd.get("params", {})), rd.get("description", "")) \
            if isinstance(rd, dict) and rd.get("action") else None
    d["remediation"] = rem
    d["enabled"] = entry.get("enabled", True) if isinstance(entry, dict) else getattr(entry, "enabled", True)
    return d


def default_hosts_path() -> Path:
    return windows_dir() / "System32" / "drivers" / "etc" / "hosts" if IS_WINDOWS else Path("/etc/hosts")


class PersistenceGuard:
    def __init__(self, monitor: "RealtimeMonitor", interval: float = 30.0,
                 collect_fn: Optional[Callable[[], Iterable[Any]]] = None, hosts_path: Optional[Path] = None):
        self.monitor = monitor
        self.interval = interval
        self.collect_fn = collect_fn
        self.hosts_path = Path(hosts_path) if hosts_path else default_hosts_path()
        self._entries: Optional[Dict[str, Dict[str, Any]]] = None
        self._hosts: Optional[Tuple[str, str]] = None  # (sha256, text)

    def start(self, stop: threading.Event) -> List[threading.Thread]:
        return [self.monitor.spawn("persistence-guard", lambda: self._loop(stop))]

    def _loop(self, stop: threading.Event) -> None:
        self.tick()  # baseline
        while not stop.wait(self.interval):
            try:
                self.tick()
            except Exception:
                log.exception("persistence guard tick failed")

    def _collect(self) -> Optional[List[Any]]:
        fn = self.collect_fn
        if fn is None:
            try:
                from aegis.scanners.persistence import collect_entries as fn  # type: ignore[assignment]
            except Exception:
                return None
        try:
            try:
                return list(fn())  # type: ignore[misc]
            except TypeError:  # variant that wants a ScanContext
                return list(fn(self.monitor.context()))  # type: ignore[misc]
        except Exception as exc:
            log.debug("collect_entries failed: %s", exc)
            return None

    def snapshot(self) -> Optional[Dict[str, Dict[str, Any]]]:
        raw = self._collect()
        if raw is None:
            return None
        snap: Dict[str, Dict[str, Any]] = {}
        for e in raw:
            try:
                d = normalise_entry(e)
            except Exception:
                continue
            if d["key"].strip("|"):
                snap[d["key"]] = d
        return snap

    def tick(self) -> List[Finding]:
        out: List[Finding] = []
        snap = self.snapshot()
        if snap is not None:
            if self._entries is not None:
                for key, d in snap.items():
                    if key not in self._entries:
                        out.append(self._new_entry_finding(d))
            self._entries = snap
        out += self._check_hosts()
        for f in out:
            self.monitor.emit(f, "persistence-guard")
        return out

    def _new_entry_finding(self, d: Dict[str, Any]) -> Finding:
        cmd = d["command"]
        sev = Severity.MEDIUM if d.get("enabled", True) else Severity.LOW
        hits: List[str] = []
        mitre = ["T1547"]
        try:
            from aegis.core.cmdline import analyse_command_line

            for h in analyse_command_line(cmd):
                if Severity.parse(h[2]) >= Severity.MEDIUM:
                    sev = max(sev, Severity.HIGH)
                    hits.append(str(h[1]))
                    mitre += list(h[3] or [])
        except Exception:
            pass
        exe_findings: List[Finding] = []
        raw = d.get("raw")
        try:
            from aegis.core.cmdline import extract_executable

            exe = (raw.get("path") if isinstance(raw, dict) else None) or (extract_executable(cmd) if cmd else None)
            if exe and os.path.isfile(exe) and not is_under(exe, [Path(p) for p in system_binary_dirs()]):
                from aegis.scanners.files import scan_file

                exe_findings = scan_file(self.monitor.context(), Path(exe))
        except Exception:
            pass
        if exe_findings:
            sev = max([sev] + [f.severity for f in exe_findings])
            hits += [f.title for f in exe_findings]
        try:  # the persistence scanner's own verdict on this entry (missing target, odd location, ...)
            from aegis.scanners import persistence as P

            if isinstance(raw, dict) and "type" in raw:
                reasons = P.assess_entry(raw, scan_findings=exe_findings)
                pf = P.finding_for_entry(raw, reasons)
                if pf:
                    sev = max(sev, pf.severity)
                    hits += [r.text.split(":")[0][:80] for r in reasons if r.severity > Severity.INFO]
                    mitre += list(pf.mitre)
        except Exception as exc:
            log.debug("assess_entry failed: %s", exc)
        hits = list(dict.fromkeys(hits))
        return Finding(
            "AEG-RT-AUTORUN", f"New autorun entry: {d['name'] or d['command'][:60]}", sev, Category.PERSISTENCE,
            "A new startup / persistence entry appeared while real-time protection was running." +
            (f" Suspicious: {'; '.join(hits[:3])}." if hits else ""),
            d["location"] or d["command"],
            {"kind": d["kind"], "name": d["name"], "location": d["location"], "command": cmd[:1000], "indicators": hits[:5]},
            "If you did not just install software, remove this entry (Aegis can disable it from the scan results).",
            d.get("remediation"), "realtime", sorted(set(mitre)))

    def _check_hosts(self) -> List[Finding]:
        try:
            raw = self.hosts_path.read_bytes()
        except OSError:
            return []
        digest = hashlib.sha256(raw).hexdigest()
        text = raw.decode("utf-8", "replace")
        prev, self._hosts = self._hosts, (digest, text)
        if prev is None or prev[0] == digest:
            return []
        old_lines = {ln.strip() for ln in prev[1].splitlines()}
        added = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")
                 and ln.strip() not in old_lines]
        rem = Remediation("restore_hosts", {"path": str(self.hosts_path), "remove_lines": added},
                          "Disable the added hosts entries") if added else None
        return [Finding(
            "AEG-RT-HOSTS", "Hosts file was modified", Severity.HIGH if IS_WINDOWS else Severity.MEDIUM, Category.NETWORK,
            "The system hosts file changed. Malware edits it to redirect banking / update / security sites." +
            (f" Added entries: {'; '.join(added[:5])}" if added else ""),
            str(self.hosts_path), {"added_lines": added[:50], "sha256": digest},
            "Review the added entries and remove any you did not create.", rem, "realtime", ["T1565.001"])]


# =========================================================================== the monitor

ALL_COMPONENTS = ("files", "processes", "ransomware", "persistence", "clipboard", "extensions")


class RealtimeMonitor:
    """Starts / stops all guards. Safe to call start()/stop() repeatedly."""

    def __init__(self, config: Config, signatures: Any, on_event: Optional[EventCallback] = None,
                 components: Sequence[str] = ALL_COMPONENTS, watch_specs: Optional[Sequence[WatchSpec]] = None,
                 backend: str = "auto", poll_interval: float = 2.0, stable_secs: float = 1.0,
                 canary_dirs: Optional[Sequence[Path]] = None):
        self.config = config
        self.signatures = signatures
        self.on_event = on_event
        self.components = tuple(components)
        self.events: Deque[Finding] = collections.deque(maxlen=1000)
        self.stats: "collections.Counter[str]" = collections.Counter()
        self.event_log = EventLog(config.logs_dir / EVENT_LOG_NAME)
        self.started_at: Optional[float] = None
        self._stop = threading.Event()
        self._threads: List[threading.Thread] = []
        self._running = False
        self._lock = threading.RLock()
        self._ctx: Any = None
        self._recent: Dict[str, float] = {}
        self._alerts: Any = None  # aegis.core.alerts.AlertBatcher while running
        self.files = FileGuard(self, watch_specs, backend, poll_interval, stable_secs)
        self.processes = ProcessGuard(self)
        self.ransomware = RansomwareGuard(self, canary_dirs)
        self.persistence = PersistenceGuard(self)
        from aegis.realtime.clipboard import ClipboardGuard
        from aegis.realtime.extensions import ExtensionGuard

        self.clipboard = ClipboardGuard(self)
        self.extensions = ExtensionGuard(self)

    # ---- plumbing used by the guards
    @property
    def running(self) -> bool:
        return self._running and not self._stop.is_set()

    def context(self) -> Any:
        """Shared ScanContext for scan_file (quick mode, never deep)."""
        if self._ctx is None:
            from aegis.scanners.base import ScanContext

            self._ctx = ScanContext(config=self.config, signatures=self.signatures, paths=[], deep=False,
                                    cancel=threading.Event())
        return self._ctx

    def spawn(self, name: str, target: Callable[[], None]) -> threading.Thread:
        def runner() -> None:
            try:
                target()
            except Exception:
                log.exception("real-time component %s crashed", name)

        t = threading.Thread(target=runner, name=f"aegis-rt-{name}", daemon=True)
        t.start()
        self._threads.append(t)
        return t

    def auto_remediate(self, finding: Finding) -> Optional[str]:
        cfg = self.config
        if not cfg.auto_quarantine or not finding.remediation:
            return None
        try:
            threshold = Severity.parse(cfg.auto_quarantine_min_severity)
        except (KeyError, ValueError):
            threshold = Severity.HIGH
        if finding.severity < threshold or finding.remediation.action not in ("quarantine_file", "kill_process"):
            return None
        from aegis.core.remediation import apply_remediation

        ok, msg = apply_remediation(finding, cfg)
        finding.evidence["auto_remediation"] = msg
        finding.evidence["auto_remediation_ok"] = ok
        self.stats["auto_remediated"] += int(ok)
        if ok:
            finding.title = f"Blocked: {finding.title}"
        return msg

    def emit(self, finding: Finding, source: str = "", force: bool = False) -> bool:
        """Record, notify and forward a finding. De-duplicated for DEDUP_WINDOW_S
        unless `force`. Returns False if suppressed."""
        try:
            if not force and finding.fingerprint in {x.lower() for x in self.config.allowlist_fingerprints}:
                return False
            now = time.monotonic()
            with self._lock:
                last = self._recent.get(finding.fingerprint)
                if not force and last is not None and now - last < DEDUP_WINDOW_S:
                    return False
                self._recent[finding.fingerprint] = now
                if len(self._recent) > 2000:
                    for k, _ in sorted(self._recent.items(), key=lambda kv: kv[1])[:1000]:
                        self._recent.pop(k, None)
                self.events.append(finding)
            self.stats["events"] += 1
            record = {"time": finding.timestamp, "source": source, **finding.to_dict()}
            self.event_log.write(record)
            log.warning("realtime event [%s] %s - %s", finding.severity.name, finding.title, finding.location)
            if self.config.notifications and finding.severity >= NOTIFY_MIN_SEVERITY:
                try:
                    from aegis.realtime import notify as notify_mod

                    notify_mod.notify(f"Aegis: {finding.title}"[:100], self._notification_text(finding), finding.severity)
                except Exception:
                    log.debug("notify failed", exc_info=True)
            if self.on_event:
                try:
                    self.on_event(finding)
                except Exception:
                    log.exception("on_event callback raised")
            alerts = self._alerts
            if alerts is not None:  # outbound alerts (Slack/Teams/...): queued and batched on their own thread
                try:
                    alerts.add(finding)
                except Exception:
                    log.debug("alert queue failed", exc_info=True)
            return True
        except Exception:
            log.exception("emit failed")
            return False

    @staticmethod
    def _notification_text(f: Finding) -> str:
        loc = f.location if len(f.location) < 120 else "..." + f.location[-117:]
        action = f.evidence.get("auto_remediation")
        return f"{loc}\n{action}" if action else loc

    # ---- lifecycle
    def start(self) -> None:
        with self._lock:
            if self._running and not self._stop.is_set():
                return
            self._stop = threading.Event()
            self._threads = []
            self._running = True
            self.started_at = time.time()
            guards = {"files": self.files, "processes": self.processes, "ransomware": self.ransomware,
                      "persistence": self.persistence, "clipboard": self.clipboard, "extensions": self.extensions}
            for name in self.components:
                guard = guards.get(name)
                if guard is None:
                    continue
                try:
                    guard.start(self._stop)
                except Exception:
                    log.exception("failed to start %s guard", name)
            self._start_services()
            log.info("real-time protection started (%s)", ", ".join(self.components))

    def _start_services(self) -> None:
        """Heartbeat file (read by `aegis doctor`) and the outbound-alert batcher thread."""
        self.spawn("heartbeat", lambda stop=self._stop: self._heartbeat_loop(stop))
        try:
            from aegis.core.alerts import AlertBatcher

            self._alerts = AlertBatcher(self.config)
            self._alerts.start()
        except Exception:
            log.exception("alert batcher failed to start")
            self._alerts = None

    def _heartbeat_loop(self, stop: threading.Event) -> None:
        from aegis.core.doctor import write_heartbeat

        while True:
            write_heartbeat(self.config, self.started_at, self.components)
            if stop.wait(HEARTBEAT_INTERVAL_S):
                return

    def _stop_services(self) -> None:
        alerts, self._alerts = self._alerts, None
        if alerts is not None:
            alerts.stop(timeout=2.0)  # flushes what is queued; a slow network never blocks shutdown for long
        try:
            from aegis.core.doctor import clear_heartbeat

            clear_heartbeat(self.config)
        except Exception:
            log.debug("could not remove heartbeat", exc_info=True)

    def stop(self, timeout: float = 3.0) -> None:
        with self._lock:
            if not self._running:
                return
            self._stop.set()
            threads = list(self._threads)
        deadline = time.monotonic() + timeout
        for t in threads:  # joined outside the lock: workers may be blocked in emit()
            while t.is_alive() and time.monotonic() < deadline:
                self.files.stop()  # repeated: CancelIoEx is a no-op if it races ahead of the blocking read
                t.join(0.2)
        with self._lock:
            self._threads = [t for t in self._threads if t.is_alive()]
            self._running = False
        self._stop_services()
        log.info("real-time protection stopped")

    def run_forever(self) -> None:
        self.start()
        try:
            while self.running:
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def remove_canaries(self) -> int:
        return self.ransomware.remove_canaries()

    def status(self) -> Dict[str, Any]:
        return {
            "running": self.running,
            "components": list(self.components),
            "uptime_s": int(time.time() - self.started_at) if self.started_at and self.running else 0,
            "watched": [str(p) for p, _ in self.files.specs],
            "canaries": len(self.ransomware.canaries.canaries) if self.ransomware.canaries else 0,
            "suspended_pids": sorted(self.ransomware.suspended),
            "stats": dict(self.stats),
        }
