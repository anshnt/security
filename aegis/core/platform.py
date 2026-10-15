"""Operating-system helpers: detection, privilege checks, safe subprocess and
registry access. Every scanner goes through these so it degrades gracefully on
non-Windows hosts and in unprivileged sessions."""

from __future__ import annotations

import ctypes
import json
import logging
import os
import platform
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

log = logging.getLogger("aegis.platform")

IS_WINDOWS = sys.platform.startswith("win")
IS_LINUX = sys.platform.startswith("linux")
IS_MAC = sys.platform == "darwin"
OS_NAME = "windows" if IS_WINDOWS else "darwin" if IS_MAC else "linux"

if IS_WINDOWS:  # pragma: no cover - exercised on Windows CI
    import winreg  # type: ignore
else:
    winreg = None  # type: ignore

# Hide console windows spawned by the GUI / background monitor on Windows.
_CREATE_NO_WINDOW = 0x08000000


def is_admin() -> bool:
    try:
        if IS_WINDOWS:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        return os.geteuid() == 0
    except Exception:
        return False


def host_info() -> Dict[str, Any]:
    info = {
        "hostname": socket.gethostname(),
        "os": OS_NAME,
        "platform": platform.platform(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "admin": is_admin(),
        "user": os.environ.get("USERNAME") or os.environ.get("USER", ""),
    }
    if IS_WINDOWS:
        try:
            info["build"] = sys.getwindowsversion().build  # type: ignore[attr-defined]
        except Exception:
            pass
    return info


def run(cmd: Sequence[str], timeout: int = 60, input_text: Optional[str] = None) -> Tuple[int, str, str]:
    """Run a command without a shell. Returns (returncode, stdout, stderr);
    never raises - a missing binary or timeout yields returncode -1."""
    kwargs: Dict[str, Any] = {}
    if IS_WINDOWS:
        kwargs["creationflags"] = _CREATE_NO_WINDOW
    try:
        p = subprocess.run(
            list(cmd),
            capture_output=True,
            timeout=timeout,
            input=input_text,
            text=True,
            encoding="utf-8",
            errors="replace",
            **kwargs,
        )
        return p.returncode, p.stdout or "", p.stderr or ""
    except FileNotFoundError:
        return -1, "", f"not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return -1, "", f"timeout after {timeout}s: {cmd[0]}"
    except Exception as exc:  # pragma: no cover
        return -1, "", str(exc)


def powershell(script: str, timeout: int = 90) -> Tuple[int, str, str]:
    """Run a PowerShell snippet (Windows only). Output is forced to UTF-8."""
    exe = shutil.which("powershell") or shutil.which("pwsh") or "powershell"
    prefix = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;$ProgressPreference='SilentlyContinue';"
    return run([exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", prefix + script], timeout=timeout)


def powershell_json(script: str, timeout: int = 90) -> Any:
    """Run PowerShell and parse `... | ConvertTo-Json` output. Returns None on
    failure; single objects are returned as dicts, collections as lists."""
    if not IS_WINDOWS:
        return None
    rc, out, err = powershell(script, timeout=timeout)
    out = out.strip()
    if not out:
        if err.strip():
            log.debug("powershell error: %s", err.strip()[:500])
        return None
    try:
        return json.loads(out)
    except ValueError:
        log.debug("powershell returned non-JSON: %s", out[:300])
        return None


def as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


# --------------------------------------------------------------------------- registry

HIVES = {
    "HKLM": "HKEY_LOCAL_MACHINE",
    "HKCU": "HKEY_CURRENT_USER",
    "HKU": "HKEY_USERS",
    "HKCR": "HKEY_CLASSES_ROOT",
}


def _hive(name: str):
    return getattr(winreg, HIVES.get(name, name))


def reg_read(hive: str, key: str, value: str, view64: bool = True) -> Any:
    """Read a single registry value; None if missing or not on Windows."""
    if not IS_WINDOWS:
        return None
    access = winreg.KEY_READ | (winreg.KEY_WOW64_64KEY if view64 else winreg.KEY_WOW64_32KEY)
    try:
        with winreg.OpenKey(_hive(hive), key, 0, access) as k:
            return winreg.QueryValueEx(k, value)[0]
    except OSError:
        return None


def reg_values(hive: str, key: str, view64: bool = True) -> Dict[str, Any]:
    """All values of a key as {name: data}."""
    out: Dict[str, Any] = {}
    if not IS_WINDOWS:
        return out
    access = winreg.KEY_READ | (winreg.KEY_WOW64_64KEY if view64 else winreg.KEY_WOW64_32KEY)
    try:
        with winreg.OpenKey(_hive(hive), key, 0, access) as k:
            i = 0
            while True:
                try:
                    name, data, _ = winreg.EnumValue(k, i)
                except OSError:
                    break
                out[name] = data
                i += 1
    except OSError:
        pass
    return out


def reg_subkeys(hive: str, key: str, view64: bool = True) -> List[str]:
    out: List[str] = []
    if not IS_WINDOWS:
        return out
    access = winreg.KEY_READ | (winreg.KEY_WOW64_64KEY if view64 else winreg.KEY_WOW64_32KEY)
    try:
        with winreg.OpenKey(_hive(hive), key, 0, access) as k:
            i = 0
            while True:
                try:
                    out.append(winreg.EnumKey(k, i))
                except OSError:
                    break
                i += 1
    except OSError:
        pass
    return out


def reg_walk_values(hive: str, key: str, view64: bool = True) -> Iterator[Tuple[str, Dict[str, Any]]]:
    """Yield (subkey_path, values) for each immediate subkey."""
    for sub in reg_subkeys(hive, key, view64):
        path = f"{key}\\{sub}"
        yield path, reg_values(hive, path, view64)


def reg_delete_value(hive: str, key: str, value: str, view64: bool = True) -> None:
    if not IS_WINDOWS:
        raise OSError("registry not available on this platform")
    access = winreg.KEY_SET_VALUE | (winreg.KEY_WOW64_64KEY if view64 else winreg.KEY_WOW64_32KEY)
    with winreg.OpenKey(_hive(hive), key, 0, access) as k:
        winreg.DeleteValue(k, value)


def reg_set_value(hive: str, key: str, value: str, data: Any, kind: Optional[int] = None, view64: bool = True) -> None:
    if not IS_WINDOWS:
        raise OSError("registry not available on this platform")
    if kind is None:
        kind = winreg.REG_DWORD if isinstance(data, int) else winreg.REG_SZ
    access = winreg.KEY_SET_VALUE | (winreg.KEY_WOW64_64KEY if view64 else winreg.KEY_WOW64_32KEY)
    with winreg.CreateKeyEx(_hive(hive), key, 0, access) as k:
        winreg.SetValueEx(k, value, 0, kind, data)


# --------------------------------------------------------------------------- paths

def env_path(var: str, default: str = "") -> Optional[Path]:
    v = os.environ.get(var) or default
    return Path(v) if v else None


def user_home() -> Path:
    return Path.home()


def windows_dir() -> Path:
    return Path(os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows")


def system_drive() -> str:
    return os.environ.get("SystemDrive", "C:") + "\\"


def suspicious_dirs() -> List[Path]:
    """User-writable locations malware loves to drop and run from."""
    dirs: List[Path] = []
    home = user_home()
    if IS_WINDOWS:
        for var in ("TEMP", "TMP"):
            p = env_path(var)
            if p:
                dirs.append(p)
        for v in ("APPDATA", "LOCALAPPDATA", "PUBLIC", "ProgramData"):
            p = env_path(v)
            if p:
                dirs.append(p)
        dirs += [home / "Downloads", windows_dir() / "Temp", Path(system_drive()) / "$Recycle.Bin",
                 Path(system_drive()) / "Users" / "Public"]
    else:
        dirs += [Path("/tmp"), Path("/var/tmp"), Path("/dev/shm"), home / "Downloads"]
    seen, out = set(), []
    for d in dirs:
        key = str(d).lower()
        if key not in seen:
            seen.add(key)
            out.append(d)
    return out


def quick_scan_dirs() -> List[Path]:
    """Hot spots for a quick scan: downloads, desktop, temp, startup, appdata roots."""
    home = user_home()
    dirs = [home / "Downloads", home / "Desktop"]
    if IS_WINDOWS:
        for v in ("TEMP",):
            p = env_path(v)
            if p:
                dirs.append(p)
        appdata = env_path("APPDATA")
        if appdata:
            dirs.append(appdata / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
        pd = env_path("ProgramData", r"C:\ProgramData")
        if pd:
            dirs.append(pd / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "StartUp")
        dirs.append(Path(system_drive()) / "Users" / "Public")
    else:
        dirs += [Path("/tmp"), Path("/var/tmp"), Path("/dev/shm")]
    return [d for d in dirs if d.exists()]


def full_scan_roots() -> List[Path]:
    if IS_WINDOWS:
        roots = []
        try:
            import psutil

            for part in psutil.disk_partitions(all=False):
                if "cdrom" in part.opts or not part.fstype:
                    continue
                roots.append(Path(part.mountpoint))
        except Exception:
            roots = [Path(system_drive())]
        return roots
    return [Path("/")]


def normalize_path(p: str) -> str:
    """Lower-cased, environment-expanded, quote-stripped path for comparisons."""
    p = os.path.expandvars(p.strip().strip('"'))
    if IS_WINDOWS:
        p = p.replace("/", "\\")
        if p.lower().startswith("\\??\\"):
            p = p[4:]
        if p.lower().startswith("\\systemroot\\"):
            p = str(windows_dir()) + p[11:]
        elif p.lower().startswith("system32\\"):
            p = str(windows_dir() / p)
    return p.lower() if IS_WINDOWS else p


def is_under(path: str, parents: Sequence[Path]) -> bool:
    np = normalize_path(path)
    for parent in parents:
        pp = normalize_path(str(parent)).rstrip("\\/")
        if pp and (np == pp or np.startswith(pp + ("\\" if IS_WINDOWS else "/"))):
            return True
    return False


def in_suspicious_location(path: str) -> bool:
    """True if the path lives in a user-writable drop location (but not inside a
    well-known installed-program tree like AppData\\Local\\Programs)."""
    np = normalize_path(path)
    if IS_WINDOWS:
        benign = ("\\appdata\\local\\programs\\", "\\appdata\\local\\microsoft\\", "\\appdata\\roaming\\microsoft\\",
                  "\\programdata\\microsoft\\", "\\appdata\\local\\google\\", "\\appdata\\local\\mozilla\\",
                  "\\appdata\\local\\discord\\", "\\appdata\\local\\slack\\", "\\appdata\\local\\zoom\\",
                  "\\appdata\\roaming\\zoom\\", "\\appdata\\local\\packages\\", "\\programdata\\package cache\\",
                  "\\appdata\\local\\github", "\\appdata\\local\\jetbrains\\", "\\appdata\\local\\spotify",
                  "\\appdata\\roaming\\spotify", "\\appdata\\local\\whatsapp", "\\appdata\\local\\1password",
                  "\\appdata\\local\\bravesoftware\\", "\\appdata\\local\\vivaldi\\", "\\appdata\\local\\teams",
                  "\\appdata\\local\\temp\\_mei")  # PyInstaller one-file unpack dir (incl. Aegis itself)
        if any(b in np for b in benign):
            return False
    return is_under(path, suspicious_dirs())


def system_binary_dirs() -> List[str]:
    if IS_WINDOWS:
        w = windows_dir()
        return [normalize_path(str(p)) for p in (w / "System32", w / "SysWOW64", w, w / "WinSxS", w / "explorer.exe")]
    return ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/libexec", "/lib", "/usr/local/bin", "/System"]


def enable_ansi() -> bool:
    """Enable VT escape processing on Windows 10+ consoles."""
    if not sys.stdout.isatty():
        return False
    if IS_WINDOWS:
        try:
            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            h = kernel32.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            kernel32.GetConsoleMode(h, ctypes.byref(mode))
            kernel32.SetConsoleMode(h, mode.value | 0x0004)
            return True
        except Exception:
            return False
    return True
