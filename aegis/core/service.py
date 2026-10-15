"""Background-service installation (`aegis install-service` / `uninstall-service`).

Windows: three Task Scheduler tasks registered from generated task XML with
`schtasks /Create /XML` (locale independent - no parsing of localized output):
  * Aegis Realtime Protection  - at logon, highest privileges, `monitor`
  * Aegis Daily Quick Scan     - daily 12:30, `scan quick --report html`
  * Aegis Signature Update     - every 6 hours, `update`
Linux: systemd *user* units (monitor service + daily scan and 6-hourly update timers).
"""

from __future__ import annotations

import logging
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple
from xml.sax.saxutils import escape

from aegis.core.platform import IS_LINUX, IS_WINDOWS, is_admin, run

log = logging.getLogger("aegis.service")

TASK_REALTIME = "Aegis Realtime Protection"
TASK_SCAN = "Aegis Daily Quick Scan"
TASK_UPDATE = "Aegis Signature Update"
ALL_TASKS = (TASK_REALTIME, TASK_SCAN, TASK_UPDATE)

# (task name, aegis CLI args, trigger kind, description)
TASK_DEFS: List[Tuple[str, List[str], str, str]] = [
    (TASK_REALTIME, ["monitor"], "logon", "Aegis real-time protection (file, process, ransomware and persistence guards)."),
    (TASK_SCAN, ["scan", "quick", "--report", "html"], "daily", "Daily Aegis quick scan with an HTML report."),
    (TASK_UPDATE, ["update"], "interval", "Download fresh Aegis threat-intelligence signatures every 6 hours."),
]

SYSTEMD_UNIT_NAMES = ("aegis-monitor.service", "aegis-scan.service", "aegis-scan.timer",
                      "aegis-update.service", "aegis-update.timer")


# --------------------------------------------------------------------------- launch command

def launch_command(windowless: bool = False) -> Tuple[str, List[str]]:
    """(executable, base_args) that start Aegis: the frozen exe itself, or
    `python -m aegis` (using pythonw.exe on Windows for background tasks)."""
    if getattr(sys, "frozen", False):
        return sys.executable, []
    exe = sys.executable
    if IS_WINDOWS and windowless:
        pyw = Path(exe).with_name("pythonw.exe")
        if pyw.exists():
            exe = str(pyw)
    return exe, ["-m", "aegis"]


def _win_quote(arg: str) -> str:
    return f'"{arg}"' if (" " in arg or not arg) else arg


# --------------------------------------------------------------------------- Windows Task Scheduler XML

def build_task_xml(name: str, command: str, arguments: Sequence[str], trigger: str, description: str = "",
                   highest: bool = True, start: str = "2025-01-01") -> str:
    """Task Scheduler 1.2 XML. `trigger` is logon | daily | interval (every 6h)."""
    if trigger == "logon":
        trig = "<LogonTrigger><Enabled>true</Enabled></LogonTrigger>"
    elif trigger == "daily":
        trig = (f"<CalendarTrigger><StartBoundary>{start}T12:30:00</StartBoundary><Enabled>true</Enabled>"
                "<ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger>")
    elif trigger == "interval":
        trig = ("<CalendarTrigger><Repetition><Interval>PT6H</Interval><Duration>P1D</Duration>"
                f"<StopAtDurationEnd>false</StopAtDurationEnd></Repetition><StartBoundary>{start}T00:05:00</StartBoundary>"
                "<Enabled>true</Enabled><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger>")
    else:
        raise ValueError(f"unknown trigger {trigger!r}")
    run_level = "HighestAvailable" if highest else "LeastPrivilege"
    args = " ".join(_win_quote(a) for a in arguments)
    return (
        '<?xml version="1.0" encoding="UTF-16"?>\n'
        '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
        f"<RegistrationInfo><Author>Aegis Security Suite</Author><Description>{escape(description)}</Description>"
        f"<URI>\\{escape(name)}</URI></RegistrationInfo>"
        f"<Triggers>{trig}</Triggers>"
        f'<Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType><RunLevel>{run_level}</RunLevel></Principal></Principals>'
        "<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"
        "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"
        "<AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable>"
        "<RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>"
        "<IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>"
        "<AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden>"
        "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>7</Priority></Settings>"
        f'<Actions Context="Author"><Exec><Command>{escape(command)}</Command><Arguments>{escape(args)}</Arguments></Exec></Actions>'
        "</Task>\n"
    )


def windows_task_xmls(highest: Optional[bool] = None) -> Dict[str, str]:
    """name -> XML for the three Aegis tasks."""
    highest = is_admin() if highest is None else highest
    out: Dict[str, str] = {}
    for name, cli_args, trigger, desc in TASK_DEFS:
        exe, base = launch_command(windowless=(trigger == "logon"))
        out[name] = build_task_xml(name, exe, base + cli_args, trigger, desc, highest)
    return out


def _schtasks_create(name: str, xml: str, workdir: Path) -> Tuple[bool, str]:
    path = workdir / (name.replace(" ", "_") + ".xml")
    path.write_bytes(xml.encode("utf-16"))  # schtasks wants UTF-16 with BOM
    rc, out, err = run(["schtasks", "/Create", "/TN", name, "/XML", str(path), "/F"], timeout=60)
    return rc == 0, (out or err).strip()


# --------------------------------------------------------------------------- Linux systemd (--user)

def _systemd_quote(arg: str) -> str:
    if arg and not any(c in arg for c in ' \t"\'\\$%'):
        return arg
    return '"' + arg.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$") + '"'


def systemd_units(executable: Optional[str] = None, base_args: Optional[Sequence[str]] = None) -> Dict[str, str]:
    """unit file name -> content for systemd --user."""
    if executable is None:
        executable, base = launch_command()
        base_args = base
    cmd = " ".join(_systemd_quote(a) for a in [executable, *(base_args or [])])
    return {
        "aegis-monitor.service": (
            "[Unit]\nDescription=Aegis real-time protection\nAfter=default.target\n\n"
            f"[Service]\nType=simple\nExecStart={cmd} monitor\nRestart=on-failure\nRestartSec=10\n"
            "Nice=10\nIOSchedulingClass=idle\n\n[Install]\nWantedBy=default.target\n"),
        "aegis-scan.service": (
            "[Unit]\nDescription=Aegis quick scan\n\n"
            f"[Service]\nType=oneshot\nExecStart={cmd} scan quick --report html\nNice=15\nIOSchedulingClass=idle\n"
            "SuccessExitStatus=0 1\n"),
        "aegis-scan.timer": (
            "[Unit]\nDescription=Aegis daily quick scan\n\n"
            "[Timer]\nOnCalendar=*-*-* 12:30:00\nPersistent=true\nRandomizedDelaySec=300\n\n[Install]\nWantedBy=timers.target\n"),
        "aegis-update.service": (
            "[Unit]\nDescription=Aegis signature update\nWants=network-online.target\nAfter=network-online.target\n\n"
            f"[Service]\nType=oneshot\nExecStart={cmd} update\n"),
        "aegis-update.timer": (
            "[Unit]\nDescription=Aegis signature update every 6 hours\n\n"
            "[Timer]\nOnCalendar=*-*-* 00,06,12,18:05:00\nPersistent=true\nRandomizedDelaySec=300\n\n[Install]\nWantedBy=timers.target\n"),
    }


def systemd_user_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "systemd" / "user"


# --------------------------------------------------------------------------- public API

def install_service(config=None) -> List[str]:
    """Install background protection. Returns a human-readable list of actions done."""
    actions: List[str] = []
    if IS_WINDOWS:
        admin = is_admin()
        if not admin:
            actions.append("Not running as Administrator: tasks are registered with standard privileges "
                           "(re-run elevated for highest privileges / full protection).")
        xmls = windows_task_xmls(highest=admin)
        with tempfile.TemporaryDirectory(prefix="aegis-task-") as tmp:
            for name, xml in xmls.items():
                ok, msg = _schtasks_create(name, xml, Path(tmp))
                actions.append(f"{'Created' if ok else 'FAILED to create'} scheduled task '{name}'" + (f": {msg}" if not ok else ""))
        return actions
    if IS_LINUX:
        d = systemd_user_dir()
        d.mkdir(parents=True, exist_ok=True)
        for fname, content in systemd_units().items():
            (d / fname).write_text(content, encoding="utf-8")
            actions.append(f"Wrote {d / fname}")
        if shutil.which("systemctl"):
            run(["systemctl", "--user", "daemon-reload"])
            for unit in ("aegis-monitor.service", "aegis-scan.timer", "aegis-update.timer"):
                rc, out, err = run(["systemctl", "--user", "enable", "--now", unit])
                actions.append(f"{'Enabled' if rc == 0 else 'FAILED to enable'} {unit}" + (f": {(err or out).strip()}" if rc else ""))
            actions.append("Tip: run `loginctl enable-linger $USER` to keep protection running when logged out.")
        else:
            actions.append("systemctl not found: units were written but not enabled.")
        return actions
    actions.append("Background service installation is not supported on this OS yet (Windows and Linux only).")
    return actions


def uninstall_service() -> List[str]:
    actions: List[str] = []
    if IS_WINDOWS:
        for name in ALL_TASKS:
            rc, out, err = run(["schtasks", "/Delete", "/TN", name, "/F"])
            actions.append(f"{'Removed' if rc == 0 else 'Not removed (missing or access denied)'} scheduled task '{name}'")
        return actions
    if IS_LINUX:
        d = systemd_user_dir()
        if shutil.which("systemctl"):
            for unit in ("aegis-monitor.service", "aegis-scan.timer", "aegis-update.timer"):
                run(["systemctl", "--user", "disable", "--now", unit])
        for fname in SYSTEMD_UNIT_NAMES:
            p = d / fname
            if p.exists():
                p.unlink()
                actions.append(f"Removed {p}")
        if shutil.which("systemctl"):
            run(["systemctl", "--user", "daemon-reload"])
        if not actions:
            actions.append("No Aegis systemd units were installed.")
        return actions
    actions.append("Nothing to remove on this OS.")
    return actions
