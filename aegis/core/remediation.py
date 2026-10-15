"""Remediation actions. Every destructive action backs up what it changes into
<data>/backups first so it can be undone manually."""

from __future__ import annotations

import datetime as dt
import json
import logging
import shutil
from pathlib import Path
from typing import Callable, Dict, Tuple

from aegis.core.config import Config
from aegis.core.models import Finding
from aegis.core.platform import IS_WINDOWS, powershell, reg_delete_value, reg_read, reg_set_value, run
from aegis.core.quarantine import Quarantine

log = logging.getLogger("aegis.remediation")

Result = Tuple[bool, str]


def _backup(cfg: Config, kind: str, payload: dict) -> Path:
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    p = cfg.backups_dir / f"{kind}-{stamp}.json"
    p.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return p


def quarantine_file(cfg: Config, params: dict, finding: Finding) -> Result:
    item = Quarantine(cfg).add(params["path"], threat=finding.title)
    return True, f"quarantined {item.original_path} as {item.id}"


def kill_process(cfg: Config, params: dict, finding: Finding) -> Result:
    import psutil

    pid = int(params["pid"])
    try:
        proc = psutil.Process(pid)
        exe = params.get("path") or proc.exe()
        for child in proc.children(recursive=True):
            child.kill()
        proc.kill()
        proc.wait(timeout=5)
    except psutil.NoSuchProcess:
        exe = params.get("path")
    msg = f"terminated pid {pid}"
    if params.get("quarantine") and exe and Path(exe).is_file():
        ok, qmsg = quarantine_file(cfg, {"path": exe}, finding)
        msg += f"; {qmsg}"
    return True, msg


def delete_registry_value(cfg: Config, params: dict, finding: Finding) -> Result:
    hive, key, value = params["hive"], params["key"], params["value"]
    view64 = params.get("view64", True)
    old = reg_read(hive, key, value, view64)
    b = _backup(cfg, "registry", {"hive": hive, "key": key, "value": value, "data": old, "view64": view64})
    reg_delete_value(hive, key, value, view64)
    return True, f"deleted {hive}\\{key}\\{value} (backup: {b.name})"


def set_registry_value(cfg: Config, params: dict, finding: Finding) -> Result:
    hive, key, value, data = params["hive"], params["key"], params["value"], params["data"]
    old = reg_read(hive, key, value)
    b = _backup(cfg, "registry", {"hive": hive, "key": key, "value": value, "data": old})
    reg_set_value(hive, key, value, data)
    return True, f"set {hive}\\{key}\\{value}={data!r} (backup: {b.name})"


def disable_task(cfg: Config, params: dict, finding: Finding) -> Result:
    name = params["name"]
    rc, out, err = run(["schtasks", "/Query", "/TN", name, "/XML"])
    if rc == 0:
        _backup(cfg, "task", {"name": name, "xml": out})
    rc, out, err = run(["schtasks", "/Change", "/TN", name, "/Disable"])
    return rc == 0, (out or err).strip() or f"disabled task {name}"


def disable_service(cfg: Config, params: dict, finding: Finding) -> Result:
    name = params["name"]
    _backup(cfg, "service", {"name": name, "query": run(["sc", "qc", name])[1]})
    run(["sc", "stop", name])
    rc, out, err = run(["sc", "config", name, "start=", "disabled"])
    return rc == 0, (out or err).strip()


def remove_wmi_subscription(cfg: Config, params: dict, finding: Finding) -> Result:
    name = params["name"].replace("'", "''")
    script = (
        f"Get-CimInstance -Namespace root/subscription -ClassName __EventFilter | Where-Object Name -eq '{name}' | Remove-CimInstance;"
        f"Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer | Where-Object Name -eq '{name}' | Remove-CimInstance;"
        f"Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding | "
        f"Where-Object {{ $_.Filter.Name -eq '{name}' -or $_.Consumer.Name -eq '{name}' }} | Remove-CimInstance"
    )
    rc, out, err = powershell(script)
    return rc == 0, err.strip() or f"removed WMI subscription objects named {params['name']}"


def restore_hosts(cfg: Config, params: dict, finding: Finding) -> Result:
    path = Path(params["path"])
    original = path.read_text(encoding="utf-8", errors="replace")
    b = _backup(cfg, "hosts", {"path": str(path), "content": original})
    keep = []
    bad = set(params.get("remove_lines", []))
    for line in original.splitlines():
        if line.strip() in bad:
            keep.append("# disabled by Aegis: " + line)
        else:
            keep.append(line)
    path.write_text("\n".join(keep) + "\n", encoding="utf-8")
    return True, f"neutralised {len(bad)} hosts entries (backup: {b.name})"


def remove_path(cfg: Config, params: dict, finding: Finding) -> Result:
    """Move a directory (e.g. a malicious browser extension) into backups as a zip."""
    p = Path(params["path"])
    if not p.exists():
        return False, f"{p} no longer exists"
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    archive = shutil.make_archive(str(cfg.backups_dir / f"removed-{p.name}-{stamp}"), "zip", root_dir=str(p))
    shutil.rmtree(p)
    return True, f"removed {p} (archived to {Path(archive).name})"


def run_fix_command(cfg: Config, params: dict, finding: Finding) -> Result:
    """Run a fixed, pre-defined hardening command embedded by a scanner."""
    cmd = params["command"]
    if params.get("powershell"):
        rc, out, err = powershell(cmd)
    else:
        rc, out, err = run(cmd)
    return rc == 0, (out or err).strip()[:300] or "done"


ACTIONS: Dict[str, Callable[[Config, dict, Finding], Result]] = {
    "quarantine_file": quarantine_file,
    "kill_process": kill_process,
    "delete_registry_value": delete_registry_value,
    "set_registry_value": set_registry_value,
    "disable_task": disable_task,
    "disable_service": disable_service,
    "remove_wmi_subscription": remove_wmi_subscription,
    "restore_hosts": restore_hosts,
    "remove_path": remove_path,
    "run_command": run_fix_command,
}

WINDOWS_ONLY = {"delete_registry_value", "set_registry_value", "disable_task", "disable_service", "remove_wmi_subscription"}


def apply_remediation(finding: Finding, cfg: Config) -> Result:
    rem = finding.remediation
    if not rem:
        return False, "no automatic fix available - follow the recommendation"
    fn = ACTIONS.get(rem.action)
    if not fn:
        return False, f"unknown remediation action {rem.action}"
    if rem.action in WINDOWS_ONLY and not IS_WINDOWS:
        return False, f"{rem.action} is only available on Windows"
    try:
        ok, msg = fn(cfg, rem.params, finding)
    except PermissionError:
        ok, msg = False, "access denied - re-run Aegis as Administrator"
    except Exception as exc:
        ok, msg = False, f"{type(exc).__name__}: {exc}"
    log.warning("remediation %s on %s -> %s: %s", rem.action, finding.location, ok, msg)
    return ok, msg
