"""One-command hardening with full undo.

A declarative catalogue (``CATALOGUE``) lists every hardening action: id, title, why, risk/side-effects,
platform, profile membership, a ``check`` function (current state) and an ``apply`` function. Typical use::

    items = plan("recommended")                  # what would change, per action (read-only)
    out = apply(items, config)                   # does it, writes ONE journal in config.backups_dir
    # later: aegis.protect.undo.undo(config, "<journal id>")

Profiles
    recommended  safe for home PCs: Defender protections, firewall, legacy-protocol and credential hardening,
                 logging that feeds the event-log/Sigma hunting, ASR rules in *audit* mode
    strict       recommended + ASR rules in block mode, Controlled Folder Access, LSA protection (PPL)
    custom       an explicit list of action ids (``plan("custom", only=[...])`` or ``only=`` with any profile)

Design rules
* ``plan`` never changes anything. ``apply`` re-reads each setting right before changing it, so the journal
  holds the real previous value ("absent" for registry values that did not exist).
* The journal (``harden-<timestamp>.json``) is written before the first change and updated after every action, so
  even a crash mid-run leaves everything needed to revert. Each action's previous state is stored as typed
  *revert operations* (registry / Set-MpPreference / auditpol / firewall / ...), never as commands: reverting
  rebuilds the command from validated data, and registry targets are checked against the catalogue.
* Settings are never downgraded (an ASR rule already in block mode stays in block mode).
* An action that fails part-way is rolled back immediately. Needs-admin actions are skipped, not half-applied.
* Nothing here raises for normal failures; results are dicts with an ``ok`` flag.
"""

from __future__ import annotations

import csv
import datetime as dt
import glob
import io
import logging
import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from aegis.core.config import Config
from aegis.core.platform import (
    IS_MAC,
    IS_WINDOWS,
    is_admin,
    powershell,
    powershell_json,
    reg_delete_value,
    reg_read,
    reg_set_value,
    reg_subkeys,
    run,
)
from aegis.protect import asr
from aegis.protect.util import atomic_write_bytes, new_backup_path, result, write_json_atomic

log = logging.getLogger("aegis.harden")

COMPLIANT = "compliant"
WILL_CHANGE = "will_change"
NOT_APPLICABLE = "not_applicable"
NEEDS_ADMIN = "needs_admin"

PROFILES = ("recommended", "strict", "custom")
JOURNAL_VERSION = 1

ASR_DEFAULT_MODE = {"recommended": "AuditMode", "strict": "Enabled", "custom": "AuditMode"}


def current_platform() -> str:
    return "windows" if IS_WINDOWS else "darwin" if IS_MAC else "linux"


# =========================================================================== model
@dataclass
class Check:
    """Result of inspecting one action's current state."""

    state: str
    detail: str = ""
    current: Dict[str, Any] = field(default_factory=dict)
    ops: List[Dict[str, Any]] = field(default_factory=list)  # revert operations (previous values)
    data: Dict[str, Any] = field(default_factory=dict)  # values apply() needs
    needs_admin: bool = True


@dataclass
class HardenAction:
    id: str
    title: str
    why: str
    risk: str  # side effects worth reading before approving
    platform: str  # windows | linux | darwin
    group: str
    profiles: Tuple[str, ...]  # ("recommended", "strict") | ("strict",) | () = only via explicit ids
    check: Callable[["HardenEnv", Dict[str, Any]], Check]
    apply: Callable[["HardenEnv", Check, Dict[str, Any]], Tuple[bool, str]]
    needs_admin: bool = True
    needs_reboot: bool = False
    registry: Tuple["RegSetting", ...] = ()  # registry values this action may write (revert allow-list)


@dataclass
class PlanItem:
    id: str
    title: str
    why: str
    risk: str
    platform: str
    group: str
    state: str
    detail: str = ""
    needs_admin: bool = True
    needs_reboot: bool = False
    params: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.__dict__)


# =========================================================================== environment (lazy facts)
_DEFENDER_SCRIPT = (
    "$ErrorActionPreference='SilentlyContinue';$r=[ordered]@{};"
    "try{$p=Get-MpPreference;if($p){$r['pref']=[pscustomobject]@{DisableRealtimeMonitoring=[bool]$p.DisableRealtimeMonitoring;"
    "PUAProtection=[int]$p.PUAProtection;MAPSReporting=[int]$p.MAPSReporting;"
    "EnableNetworkProtection=[int]$p.EnableNetworkProtection;EnableControlledFolderAccess=[int]$p.EnableControlledFolderAccess;"
    "AttackSurfaceReductionRules_Ids=@($p.AttackSurfaceReductionRules_Ids|Where-Object{$_}|ForEach-Object{[string]$_});"
    "AttackSurfaceReductionRules_Actions=@($p.AttackSurfaceReductionRules_Actions|ForEach-Object{[int]$_})}}}catch{};"
    "try{$m=Get-MpComputerStatus;if($m){$r['mp']=[pscustomobject]@{AntivirusEnabled=[bool]$m.AntivirusEnabled;"
    "AMRunningMode=[string]$m.AMRunningMode}}}catch{};"
    "try{$r['av']=@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct|ForEach-Object"
    "{[pscustomobject]@{name=[string]$_.displayName;state=[int64]$_.productState}})}catch{};"
    "$r|ConvertTo-Json -Depth 5 -Compress"
)

_FIREWALL_PRODUCT_SCRIPT = (
    "$ErrorActionPreference='SilentlyContinue';ConvertTo-Json -InputObject @(Get-CimInstance -Namespace root/SecurityCenter2 "
    "-ClassName FirewallProduct|ForEach-Object{[pscustomobject]@{name=[string]$_.displayName;state=[int64]$_.productState}}) -Compress"
)


def _as_list(v: Any) -> List[Any]:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _to_int(v: Any) -> Optional[int]:
    if v is None or isinstance(v, bool):
        return None if v is None else int(v)
    try:
        return int(v)
    except (TypeError, ValueError):
        try:
            return int(str(v).strip(), 0)
        except (TypeError, ValueError):
            return None


def _product_enabled(state: Any) -> bool:
    s = _to_int(state)
    return bool(s is not None and (s & 0x1000) and not (s & 0x2000))


@dataclass
class DefenderInfo:
    pref: Optional[Dict[str, Any]]
    third_party: List[str]
    passive: bool = False

    @property
    def usable(self) -> bool:
        return self.pref is not None and not self.third_party and not self.passive

    @property
    def reason(self) -> str:
        if self.pref is None:
            return "Microsoft Defender settings are not available on this system"
        if self.third_party:
            return f"another antivirus is active ({', '.join(self.third_party)}); Defender is not the primary protection"
        if self.passive:
            return "Microsoft Defender is running in passive mode"
        return ""


class HardenEnv:
    """Per-run context: platform, privileges and lazily collected facts (one PowerShell call for Defender)."""

    def __init__(self, admin: Optional[bool] = None, platform: Optional[str] = None):
        self.platform = platform or current_platform()
        self.admin = is_admin() if admin is None else bool(admin)
        self._defender: Optional[DefenderInfo] = None
        self._cache: Dict[str, Any] = {}

    def memo(self, key: str, fn: Callable[[], Any]) -> Any:
        if key not in self._cache:
            self._cache[key] = fn()
        return self._cache[key]

    def defender(self, refresh: bool = False) -> DefenderInfo:
        if self._defender is None or refresh:
            data = powershell_json(_DEFENDER_SCRIPT, timeout=120) if self.platform == "windows" else None
            data = data if isinstance(data, dict) else {}
            pref = data.get("pref") if isinstance(data.get("pref"), dict) else None
            third = [str(p.get("name")) for p in _as_list(data.get("av")) if isinstance(p, dict)
                     and _product_enabled(p.get("state")) and not re.search(r"windows defender|microsoft defender",
                                                                         str(p.get("name", "")), re.I)]
            mp = data.get("mp") if isinstance(data.get("mp"), dict) else {}
            self._defender = DefenderInfo(pref, third, "passive" in str(mp.get("AMRunningMode", "")).lower())
        return self._defender

    def windows_build(self) -> Optional[int]:
        return self.memo("build", lambda: _to_int(reg_read("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuild"))
                         or _to_int(reg_read("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuildNumber")))


def _finish(env: HardenEnv, chk: Check) -> str:
    """Final plan state: a needed change that the current privileges cannot make becomes NEEDS_ADMIN."""
    if chk.state == WILL_CHANGE and chk.needs_admin and not env.admin:
        return NEEDS_ADMIN
    return chk.state


# =========================================================================== registry actions
@dataclass(frozen=True)
class RegSetting:
    hive: str
    key: str
    value: str
    data: Any
    ok: Optional[Callable[[Any], bool]] = None  # custom "already compliant" predicate on the current value
    also: Tuple[Tuple[str, str, str], ...] = ()  # other locations that also count as compliant when == data
    view64: bool = True


def _eq(cur: Any, want: Any) -> bool:
    if cur is None:
        return False
    if isinstance(want, int):
        return _to_int(cur) == want
    return str(cur).strip().lower() == str(want).strip().lower()


def _setting_ok(s: RegSetting) -> Tuple[bool, Any]:
    cur = reg_read(s.hive, s.key, s.value, s.view64)
    if s.ok is not None:
        good = bool(s.ok(_to_int(cur) if isinstance(s.data, int) else cur))
    else:
        good = _eq(cur, s.data)
    if not good:
        for hive, key, value in s.also:
            if _eq(reg_read(hive, key, value, s.view64), s.data):
                good = True
                break
    return good, cur


def _reg_op(s: RegSetting, cur: Any) -> Dict[str, Any]:
    return {"type": "registry", "hive": s.hive, "key": s.key, "value": s.value, "existed": cur is not None,
            "data": cur, "view64": s.view64}


def _registry_action(id: str, title: str, why: str, risk: str, group: str, profiles: Tuple[str, ...],
                     settings: Sequence[RegSetting], needs_reboot: bool = False,
                     applicable: Optional[Callable[[HardenEnv], Optional[str]]] = None) -> HardenAction:
    admin_needed = any(s.hive.upper() != "HKCU" for s in settings)

    def check(env: HardenEnv, params: Dict[str, Any]) -> Check:
        reason = applicable(env) if applicable else None
        if reason:
            return Check(NOT_APPLICABLE, reason)
        ops: List[Dict[str, Any]] = []
        current: Dict[str, Any] = {}
        for s in settings:
            good, cur = _setting_ok(s)
            current[f"{s.hive}\\{s.key}\\{s.value}"] = "absent" if cur is None else cur
            if not good:
                ops.append(_reg_op(s, cur))
        if not ops:
            return Check(COMPLIANT, "already configured", current)
        return Check(WILL_CHANGE, f"{len(ops)} registry value(s) will be set", current, ops, {}, admin_needed)

    def apply_(env: HardenEnv, chk: Check, params: Dict[str, Any]) -> Tuple[bool, str]:
        by_loc = {(s.hive, s.key, s.value): s for s in settings}
        for op in chk.ops:
            s = by_loc[(op["hive"], op["key"], op["value"])]
            try:
                reg_set_value(s.hive, s.key, s.value, s.data, view64=s.view64)
            except PermissionError:
                return False, "access denied - run Aegis as Administrator"
            except OSError as exc:
                return False, f"could not write {s.hive}\\{s.key}\\{s.value}: {exc}"
            if not _eq(reg_read(s.hive, s.key, s.value, s.view64), s.data):
                return False, f"{s.hive}\\{s.key}\\{s.value} did not keep the new value (a policy may override it)"
        return True, f"set {len(chk.ops)} registry value(s)"

    return HardenAction(id, title, why, risk, "windows", group, profiles, check, apply_, admin_needed, needs_reboot,
                        registry=tuple(settings))


# =========================================================================== Microsoft Defender actions
_MP_ENUM: Dict[str, Dict[int, str]] = {
    "PUAProtection": {0: "Disabled", 1: "Enabled", 2: "AuditMode"},
    "MAPSReporting": {0: "Disabled", 1: "Basic", 2: "Advanced"},
    "EnableNetworkProtection": {0: "Disabled", 1: "Enabled", 2: "AuditMode"},
    "EnableControlledFolderAccess": {0: "Disabled", 1: "Enabled", 2: "AuditMode", 3: "BlockDiskModificationOnly",
                                     4: "AuditDiskModificationOnly"},
}
_MP_BOOL = {"DisableRealtimeMonitoring"}


def _mp_statement(name: str, value: Any) -> Optional[str]:
    """``Set-MpPreference`` statement for an allow-listed setting/value, else None."""
    if name in _MP_BOOL:
        return f"Set-MpPreference -{name} ${'true' if value else 'false'}"
    label = _MP_ENUM.get(name, {}).get(value) if isinstance(value, int) and not isinstance(value, bool) else None
    return f"Set-MpPreference -{name} {label}" if label else None


def _run_ps(statements: Sequence[str], timeout: int = 120) -> Tuple[bool, str]:
    rc, out, err = powershell("$ErrorActionPreference='Stop';" + ";".join(statements), timeout=timeout)
    return rc == 0, (err or out).strip()[:300]


def _defender_pref_action(id: str, title: str, why: str, risk: str, profiles: Tuple[str, ...], name: str,
                          want: Callable[[Dict[str, Any]], Any], ok: Callable[[Any, Any], bool],
                          needs_reboot: bool = False) -> HardenAction:
    def check(env: HardenEnv, params: Dict[str, Any]) -> Check:
        d = env.defender()
        if not d.usable:
            return Check(NOT_APPLICABLE, d.reason)
        cur = d.pref.get(name) if d.pref else None
        if cur is None:
            return Check(NOT_APPLICABLE, f"Defender did not report {name}")
        target = want(params)
        if ok(cur, target):
            return Check(COMPLIANT, f"{name} is already {cur}", {name: cur})
        return Check(WILL_CHANGE, f"{name}: {cur} -> {target}", {name: cur}, [{"type": "mp_pref", "name": name, "previous": cur}],
                     {"target": target})

    def apply_(env: HardenEnv, chk: Check, params: Dict[str, Any]) -> Tuple[bool, str]:
        target = chk.data["target"]
        stmt = _mp_statement(name, target)
        if not stmt:
            return False, f"unsupported value {target!r} for {name}"
        ok_ps, msg = _run_ps([stmt])
        if not ok_ps:
            return False, msg or "Set-MpPreference failed (tamper protection or policy may block it)"
        now = env.defender(refresh=True).pref or {}
        if not ok(now.get(name), target):
            return False, f"{name} did not change (Tamper Protection or a policy may be managing it)"
        return True, f"{name} set to {target}"

    return HardenAction(id, title, why, risk, "windows", "defender", profiles, check, apply_, True, needs_reboot)


def _cfa_mode(params: Dict[str, Any]) -> int:
    return 2 if str(params.get("mode", "Enabled")).lower() in ("2", "auditmode", "audit") else 1


def _asr_check(env: HardenEnv, params: Dict[str, Any]) -> Check:
    d = env.defender()
    if not d.usable:
        return Check(NOT_APPLICABLE, d.reason)
    pref = d.pref or {}
    if "AttackSurfaceReductionRules_Ids" not in pref:
        return Check(NOT_APPLICABLE, "this Windows/Defender version does not report ASR rules")
    modes: Dict[str, int] = {asr.norm_guid(g): int(m) for g, m in (params.get("modes") or {}).items()}
    if not modes:
        return Check(NOT_APPLICABLE, "no ASR rules selected")
    state = asr.parse_asr_state(pref.get("AttackSurfaceReductionRules_Ids"), pref.get("AttackSurfaceReductionRules_Actions"))
    # Never downgrade, and leave rules that were explicitly Disabled alone (an admin turned them off on purpose).
    kept_off = [g for g in modes if state.get(g) == asr.MODE_DISABLED]
    todo = {g: m for g, m in modes.items() if g not in kept_off and asr.mode_strength(state.get(g)) < asr.mode_strength(m)}
    summary = asr.summarize_asr(state, list(modes))
    current = {"enabled": summary["enabled"], "audit": len(summary["audit"]), "not_configured": len(summary["not_configured"]),
               "explicitly_disabled": len(kept_off), "selected": len(modes)}
    note = f" ({len(kept_off)} explicitly disabled rule(s) left alone)" if kept_off else ""
    if not todo:
        return Check(COMPLIANT, f"all {len(modes)} selected rules are already at or above the requested mode{note}", current)
    label = ", ".join(sorted({asr.MODE_NAMES[m] for m in todo.values()}))
    ops = [{"type": "mp_asr", "rules": {g: state.get(g) for g in todo}}]
    return Check(WILL_CHANGE, f"{len(todo)} of {len(modes)} ASR rules will be set to {label}{note}", current, ops, {"todo": todo})


def _asr_apply(env: HardenEnv, chk: Check, params: Dict[str, Any]) -> Tuple[bool, str]:
    todo: Dict[str, int] = chk.data["todo"]
    ok_ps, msg = _run_ps(_asr_add_statements(todo))
    if not ok_ps:
        return False, msg or "Add-MpPreference failed (Tamper Protection or a policy may block it)"

    def landed() -> bool:
        pref = env.defender(refresh=True).pref or {}
        state = asr.parse_asr_state(pref.get("AttackSurfaceReductionRules_Ids"), pref.get("AttackSurfaceReductionRules_Actions"))
        return all(state.get(g) == m for g, m in todo.items())

    if not landed():  # some builds keep the old action on Add-: fall back to Set- with the merged list
        pref = env.defender().pref or {}
        merged = asr.parse_asr_state(pref.get("AttackSurfaceReductionRules_Ids"), pref.get("AttackSurfaceReductionRules_Actions"))
        merged.update(todo)
        ok_ps, msg = _run_ps([_asr_cmd("Set-MpPreference", merged)])
        if not ok_ps or not landed():
            return False, msg or "the ASR rule modes did not change (a policy may be managing them)"
    return True, f"{len(todo)} ASR rules configured"


def _asr_cmd(cmdlet: str, rules: Dict[str, int], with_actions: Optional[bool] = None) -> str:
    """One Add-/Set-/Remove-MpPreference statement (ids and actions pair by index). Remove- names only the ids
    unless ``with_actions`` is set (a fallback for builds that insist on both parameters)."""
    ids = list(rules)
    for g in ids:
        if g not in asr.RULES_BY_GUID:
            raise ValueError(f"not a known ASR rule GUID: {g}")
    stmt = f"{cmdlet} -AttackSurfaceReductionRules_Ids {','.join(ids)}"
    if with_actions is None:
        with_actions = cmdlet != "Remove-MpPreference"
    if with_actions:
        stmt += " -AttackSurfaceReductionRules_Actions " + ",".join(asr.MODE_NAMES[rules[g]] for g in ids)
    return stmt


def _asr_add_statements(rules: Dict[str, int]) -> List[str]:
    return [_asr_cmd("Add-MpPreference", rules)] if rules else []


# =========================================================================== firewall
_FW_PROFILES = (("domain", "DomainProfile"), ("private", "StandardProfile"), ("public", "PublicProfile"))
_FW_LOCAL = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
_FW_POLICY = r"SOFTWARE\Policies\Microsoft\WindowsFirewall"


def _fw_state() -> Tuple[Dict[str, bool], List[str]]:
    """({profile: enabled}, [profiles forced by policy])"""
    states: Dict[str, bool] = {}
    forced: List[str] = []
    for name, sub in _FW_PROFILES:
        pol = _to_int(reg_read("HKLM", f"{_FW_POLICY}\\{sub}", "EnableFirewall"))
        loc = _to_int(reg_read("HKLM", f"{_FW_LOCAL}\\{sub}", "EnableFirewall"))
        eff = pol if pol is not None else loc
        states[name] = True if eff is None else eff != 0
        if pol == 0:
            forced.append(name)
    return states, forced


def _third_party_firewall(env: HardenEnv) -> List[str]:
    def load() -> List[str]:
        rows = powershell_json(_FIREWALL_PRODUCT_SCRIPT, timeout=60)
        return [str(r.get("name")) for r in _as_list(rows) if isinstance(r, dict)
                and "windows" not in str(r.get("name", "")).lower() and _product_enabled(r.get("state"))]
    return env.memo("fw_products", load)


def _firewall_check(env: HardenEnv, params: Dict[str, Any]) -> Check:
    states, forced = _fw_state()
    off = [p for p, on in states.items() if not on]
    if not off:
        return Check(COMPLIANT, "Windows Firewall is on for all profiles", {"profiles": states})
    if set(off) <= set(forced):
        return Check(NOT_APPLICABLE, "the firewall is turned off by Group Policy for " + ", ".join(off))
    third = _third_party_firewall(env)
    if third:
        return Check(NOT_APPLICABLE, f"a third-party firewall is active ({', '.join(third)})")
    todo = [p for p in off if p not in forced]
    return Check(WILL_CHANGE, "firewall is off for: " + ", ".join(todo), {"profiles": states},
                 [{"type": "firewall", "profiles": {p: False for p in todo}}], {"todo": todo})


def _firewall_apply(env: HardenEnv, chk: Check, params: Dict[str, Any]) -> Tuple[bool, str]:
    for p in chk.data["todo"]:
        rc, out, err = run(["netsh", "advfirewall", "set", f"{p}profile", "state", "on"], timeout=60)
        if rc != 0:
            return False, f"netsh failed for the {p} profile: {(err or out).strip()[:150]}"
    states, _ = _fw_state()
    still = [p for p in chk.data["todo"] if not states.get(p)]
    if still:
        return False, "the firewall is still off for " + ", ".join(still)
    return True, "Windows Firewall turned on for " + ", ".join(chk.data["todo"])


# =========================================================================== process-creation auditing
PROC_CREATION_GUID = "{0CCE922B-69AE-11D9-BED3-505054503030}"  # Detailed Tracking > Process Creation
_AUDIT_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
_CMDLINE_VALUE = "ProcessCreationIncludeCmdLine_Enabled"


def _auditpol_get(guid: str) -> Optional[int]:
    """Setting value of one audit subcategory: 0 none, 1 success, 2 failure, 3 both. Parsed from the numeric
    last column of ``auditpol /backup`` (the text columns are localised)."""
    with tempfile.TemporaryDirectory(prefix="aegis-audit-") as tmp:
        target = os.path.join(tmp, "audit.csv")
        rc, _, _ = run(["auditpol", "/backup", f"/file:{target}"], timeout=60)
        if rc != 0 or not os.path.exists(target):
            return None
        try:
            text = Path(target).read_text(encoding="utf-8-sig", errors="replace")
        except OSError:
            return None
    want = guid.strip("{}").lower()
    for row in csv.reader(io.StringIO(text)):
        if any(c.strip().strip("{}").lower() == want for c in row):
            val = _to_int(row[-1]) if row else None
            return val if val in (0, 1, 2, 3) else None
    return None


def _auditpol_set(guid: str, value: int) -> Tuple[bool, str]:
    rc, out, err = run(["auditpol", "/set", f"/subcategory:{guid}",
                        "/success:" + ("enable" if value & 1 else "disable"),
                        "/failure:" + ("enable" if value & 2 else "disable")], timeout=60)
    return rc == 0, (err or out).strip()[:200]


def _process_audit_check(env: HardenEnv, params: Dict[str, Any]) -> Check:
    raw = reg_read("HKLM", _AUDIT_KEY, _CMDLINE_VALUE)
    cmd = _to_int(raw)
    current: Dict[str, Any] = {_CMDLINE_VALUE: cmd}
    if not env.admin:  # auditpol cannot be read (or changed) without elevation
        return Check(WILL_CHANGE, "needs administrator rights to read and change the audit policy", current)
    pol = _auditpol_get(PROC_CREATION_GUID)
    if pol is None:
        return Check(NOT_APPLICABLE, "could not read the Process Creation audit policy (auditpol unavailable)")
    current["process_creation_audit"] = pol
    ops: List[Dict[str, Any]] = []
    data: Dict[str, Any] = {}
    if cmd != 1:
        ops.append({"type": "registry", "hive": "HKLM", "key": _AUDIT_KEY, "value": _CMDLINE_VALUE,
                    "existed": raw is not None, "data": raw, "view64": True})
        data["registry"] = True
    if not pol & 1:
        ops.append({"type": "auditpol", "guid": PROC_CREATION_GUID, "previous": pol})
        data["auditpol"] = pol
    if not ops:
        return Check(COMPLIANT, "process creation (Event 4688) with command lines is already audited", current)
    return Check(WILL_CHANGE, "enable Event 4688 process-creation auditing with command lines", current, ops, data)


def _process_audit_apply(env: HardenEnv, chk: Check, params: Dict[str, Any]) -> Tuple[bool, str]:
    if chk.data.get("registry"):
        try:
            reg_set_value("HKLM", _AUDIT_KEY, _CMDLINE_VALUE, 1)
        except OSError as exc:
            return False, f"could not set {_CMDLINE_VALUE}: {exc}"
        if _to_int(reg_read("HKLM", _AUDIT_KEY, _CMDLINE_VALUE)) != 1:
            return False, f"{_CMDLINE_VALUE} did not keep its value"
    if "auditpol" in chk.data:
        prev = chk.data["auditpol"]
        ok, msg = _auditpol_set(PROC_CREATION_GUID, prev | 1)
        if not ok:
            return False, f"auditpol failed: {msg}"
        if (_auditpol_get(PROC_CREATION_GUID) or 0) & 1 == 0:
            return False, "the audit policy did not change (a Group Policy may manage it)"
    return True, "process-creation auditing with command lines enabled"


# =========================================================================== Windows applicability helpers
def _office_present() -> bool:
    try:
        for hive, base in (("HKLM", r"SOFTWARE\Microsoft\Office"), ("HKCU", r"Software\Microsoft\Office")):
            if {s.lower() for s in reg_subkeys(hive, base)} & {"16.0", "15.0", "14.0", "clicktorun"}:
                return True
    except Exception:  # noqa: BLE001
        pass
    return False


def _need_office(env: HardenEnv) -> Optional[str]:
    return None if env.memo("office", _office_present) else "Microsoft Office does not appear to be installed"


def _lsa_applicable(env: HardenEnv) -> Optional[str]:
    build = env.windows_build()
    if build is None:
        return "could not read the Windows build number"
    if build < 22621:
        return ("reversible LSA protection needs Windows 11 22H2 or later; older builds can only enable it with a UEFI "
                "lock that Aegis could not undo")
    return None


def _smb1_client_applicable(env: HardenEnv) -> Optional[str]:
    deps = reg_read("HKLM", r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation", "DependOnService")
    if any(str(d).lower() == "mrxsmb10" for d in _as_list(deps)):
        return ("the Workstation service still depends on the SMBv1 driver; remove the 'SMB 1.0/CIFS Client' Windows "
                "feature instead of disabling the driver")
    return None


_LSA = r"SYSTEM\CurrentControlSet\Control\Lsa"
_EXPLORER_POL = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
_OFFICE_APPS = ("word", "excel", "powerpoint")


# =========================================================================== Linux / macOS helpers
def _read_text(path: str, limit: int = 2_000_000) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(limit)
    except OSError:
        return None


def _write_file(path: str, text: str, mode: int = 0o644) -> None:
    target = Path(path)
    existed = target.exists()
    atomic_write_bytes(target, text.encode("utf-8"), mode_from=target if existed else None)
    if not existed:
        try:
            os.chmod(target, mode)
        except OSError:
            pass


def _delete_file(path: str) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def _which(name: str) -> Optional[str]:
    return shutil.which(name)


SSHD_CONFIG = "/etc/ssh/sshd_config"
SYSCTL_CONF = "/etc/sysctl.d/60-aegis-hardening.conf"
UFW_CONF = "/etc/ufw/ufw.conf"


def _sshd_ports(text: Optional[str]) -> List[int]:
    ports = [int(m.group(1)) for m in re.finditer(r"^\s*Port\s+(\d{1,5})\b", text or "", re.I | re.M)]
    return ports or [22]


def _ufw_active() -> Optional[bool]:
    conf = _read_text(UFW_CONF)
    if conf is not None:
        m = re.search(r"^\s*ENABLED\s*=\s*(\w+)", conf, re.I | re.M)
        if m:
            return m.group(1).lower() == "yes"
    rc, out, _ = run(["ufw", "status"], timeout=20)
    if rc == 0:
        return "status: active" in out.lower()
    return None


def _ufw_has_rule(port: int) -> bool:
    rc, out, _ = run(["ufw", "show", "added"], timeout=20)
    if rc != 0:
        return False
    for ln in (x.strip().lower() for x in out.splitlines()):
        if re.fullmatch(rf"ufw allow (from any to any port )?{port}(/tcp)?( .*)?", ln):
            return True
        if port == 22 and ln in ("ufw allow ssh", "ufw allow openssh"):
            return True
    return False


def _ufw_check(env: HardenEnv, params: Dict[str, Any]) -> Check:
    if not _which("ufw"):
        return Check(NOT_APPLICABLE, "ufw is not installed (install it with your package manager to use this action)")
    if _ufw_active():
        return Check(COMPLIANT, "ufw firewall is active")
    cfg = _read_text(SSHD_CONFIG)
    ports = _sshd_ports(cfg) if cfg is not None else []
    add = [f"{p}/tcp" for p in ports if not _ufw_has_rule(p)]  # rules Aegis adds (and removes again on undo)
    return Check(WILL_CHANGE, "enable ufw (default: deny incoming)"
                 + (f", keeping SSH port(s) {', '.join(map(str, ports))} open" if ports else ""),
                 {"active": False}, [{"type": "ufw", "was_active": False, "added_rules": add}], {"add": add})


def _ufw_apply(env: HardenEnv, chk: Check, params: Dict[str, Any]) -> Tuple[bool, str]:
    for rule in chk.data.get("add", []):
        rc, out, err = run(["ufw", "allow", rule], timeout=30)
        if rc != 0:
            return False, f"ufw allow {rule} failed: {(err or out).strip()[:150]}"
    rc, out, err = run(["ufw", "--force", "enable"], timeout=60)
    if rc != 0:
        return False, f"ufw enable failed: {(err or out).strip()[:150]}"
    return (True, "ufw enabled") if _ufw_active() else (False, "ufw did not report itself active")


def _aslr_check(env: HardenEnv, params: Dict[str, Any]) -> Check:
    raw = _read_text("/proc/sys/kernel/randomize_va_space")
    if raw is None:
        rc, out, _ = run(["sysctl", "-n", "kernel.randomize_va_space"], timeout=20)
        raw = out if rc == 0 else None
    cur = _to_int((raw or "").strip()) if raw is not None else None
    if cur is None:
        return Check(NOT_APPLICABLE, "kernel.randomize_va_space is not available")
    if cur == 2:
        return Check(COMPLIANT, "full address-space randomisation (ASLR) is on", {"randomize_va_space": cur})
    prev_conf = _read_text(SYSCTL_CONF)
    ops = [{"type": "sysctl", "key": "kernel.randomize_va_space", "previous": str(cur)},
           {"type": "file", "path": SYSCTL_CONF, "existed": prev_conf is not None, "content": prev_conf}]
    return Check(WILL_CHANGE, f"kernel.randomize_va_space {cur} -> 2", {"randomize_va_space": cur}, ops)


def _aslr_apply(env: HardenEnv, chk: Check, params: Dict[str, Any]) -> Tuple[bool, str]:
    rc, out, err = run(["sysctl", "-w", "kernel.randomize_va_space=2"], timeout=30)
    if rc != 0:
        return False, f"sysctl failed: {(err or out).strip()[:150]}"
    try:
        _write_file(SYSCTL_CONF, "# written by Aegis hardening\nkernel.randomize_va_space = 2\n")
    except OSError as exc:
        return True, f"ASLR enabled for this boot only (could not write {SYSCTL_CONF}: {exc})"
    return True, "ASLR set to 2 now and at every boot"


def _sshd_effective(text: str) -> Dict[str, str]:
    """First-occurrence-wins sshd settings, with Include expanded and Match blocks ignored."""
    def reader(pattern: str) -> List[str]:
        if not os.path.isabs(pattern):
            pattern = os.path.join("/etc/ssh", pattern)
        return [t for t in (_read_text(p) for p in sorted(glob.glob(pattern))) if t is not None]

    cfg: Dict[str, str] = {}

    def walk(body: str, depth: int = 0) -> bool:
        for raw in body.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = re.split(r"\s+|\s*=\s*", line, maxsplit=1)
            if len(parts) < 2:
                continue
            key, val = parts[0].lower(), parts[1].strip().strip('"')
            if key == "match":
                return False
            if key == "include" and depth < 3:
                for sub in reader(val):
                    if not walk(sub, depth + 1):
                        return False
                continue
            cfg.setdefault(key, val.lower())
        return True

    walk(text)
    return cfg


def _admin_users_exist() -> bool:
    """A non-root, login-capable account in a sudo-style group (so disabling root SSH cannot lock the owner out)."""
    passwd = _read_text("/etc/passwd") or ""
    group = _read_text("/etc/group") or ""
    admins: set = set()
    gids: set = set()
    for line in group.splitlines():
        f = line.split(":")
        if len(f) >= 4 and f[0] in ("sudo", "wheel", "admin"):
            admins.update(u for u in f[3].split(",") if u)
            gids.add(f[2])
    for line in passwd.splitlines():
        f = line.split(":")
        if len(f) < 7:
            continue
        uid = _to_int(f[2])
        if uid is None or uid < 1000 or uid >= 60000 or f[6].strip().endswith(("nologin", "false")):
            continue
        if f[0] in admins or f[3] in gids:
            return True
    return False


_ROOT_LOGIN_RE = re.compile(r"^(\s*)PermitRootLogin\s+yes\s*(#.*)?$", re.I)


def _ssh_root_check(env: HardenEnv, params: Dict[str, Any]) -> Check:
    text = _read_text(SSHD_CONFIG)
    if text is None:
        return Check(NOT_APPLICABLE, "sshd is not installed (no /etc/ssh/sshd_config)")
    if _sshd_effective(text).get("permitrootlogin") != "yes":
        return Check(COMPLIANT, "SSH root login is not enabled")
    if not _admin_users_exist():
        return Check(NOT_APPLICABLE, "no non-root login account with sudo rights was found; disabling root SSH login "
                                     "could lock you out")
    lines = text.splitlines(keepends=True)
    edits: List[Dict[str, str]] = []
    for ln in lines:
        if re.match(r"\s*match\b", ln, re.I):
            break
        if _ROOT_LOGIN_RE.match(ln.rstrip("\r\n")):
            edits.append({"old": ln.rstrip("\r\n"), "new": "PermitRootLogin no"})
    if not edits:
        return Check(NOT_APPLICABLE, "PermitRootLogin yes comes from an included file; Aegis only edits the main sshd_config")
    return Check(WILL_CHANGE, "set 'PermitRootLogin no' in sshd_config", {"permitrootlogin": "yes"},
                 [{"type": "file_lines", "path": SSHD_CONFIG, "edits": edits}], {"edits": edits})


def _reload_sshd() -> None:
    for cmd in (["systemctl", "reload", "ssh"], ["systemctl", "reload", "sshd"]):
        if run(cmd, timeout=30)[0] == 0:
            return


def _ssh_root_apply(env: HardenEnv, chk: Check, params: Dict[str, Any]) -> Tuple[bool, str]:
    original = _read_text(SSHD_CONFIG)
    if original is None:
        return False, "cannot read sshd_config"
    out: List[str] = []
    edits = list(chk.data["edits"])
    for ln in original.splitlines(keepends=True):
        body = ln.rstrip("\r\n")
        if edits and _ROOT_LOGIN_RE.match(body) and body == edits[0]["old"]:
            out.append("PermitRootLogin no" + ln[len(body):])
            edits.pop(0)
        else:
            out.append(ln)
    new_text = "".join(out)
    _write_file(SSHD_CONFIG, new_text)
    sshd = _which("sshd") or ("/usr/sbin/sshd" if os.path.exists("/usr/sbin/sshd") else None)
    bad = sshd and run([sshd, "-t"], timeout=30)[0] != 0
    if bad or _sshd_effective(new_text).get("permitrootlogin") == "yes":
        _write_file(SSHD_CONFIG, original)
        return False, "sshd rejected the change or another setting still allows root login; sshd_config was restored"
    _reload_sshd()
    return True, "root SSH login disabled (sshd reloaded)"


def _mac_cmd(argv: Sequence[str]) -> Optional[str]:
    rc, out, err = run(list(argv), timeout=20)
    return (out + err) if rc >= 0 else None


_SOCKETFILTER = "/usr/libexec/ApplicationFirewall/socketfilterfw"


def _mac_firewall_on() -> Optional[bool]:
    txt = _mac_cmd([_SOCKETFILTER, "--getglobalstate"])
    if txt is None:
        return None
    m = re.search(r"State\s*=\s*(\d)", txt)
    if m:
        return m.group(1) in ("1", "2")
    low = txt.lower()
    return "enabled" in low and "disabled" not in low


def _mac_firewall_check(env: HardenEnv, params: Dict[str, Any]) -> Check:
    on = _mac_firewall_on()
    if on is None:
        return Check(NOT_APPLICABLE, "socketfilterfw is not available")
    if on:
        return Check(COMPLIANT, "the application firewall is on")
    return Check(WILL_CHANGE, "turn the application firewall on", {"firewall": "off"}, [{"type": "mac_firewall", "previous": False}])


def _mac_firewall_apply(env: HardenEnv, chk: Check, params: Dict[str, Any]) -> Tuple[bool, str]:
    rc, out, err = run([_SOCKETFILTER, "--setglobalstate", "on"], timeout=30)
    if rc != 0:
        return False, (err or out).strip()[:150] or "socketfilterfw failed"
    return (True, "application firewall turned on") if _mac_firewall_on() else (False, "the firewall is still off")


def _mac_gatekeeper_on() -> Optional[bool]:
    txt = _mac_cmd(["spctl", "--status"])
    if txt is None:
        return None
    return "assessments enabled" in txt.lower()


def _mac_gatekeeper_check(env: HardenEnv, params: Dict[str, Any]) -> Check:
    on = _mac_gatekeeper_on()
    if on is None:
        return Check(NOT_APPLICABLE, "spctl is not available")
    if on:
        return Check(COMPLIANT, "Gatekeeper is on")
    return Check(WILL_CHANGE, "turn Gatekeeper on", {"gatekeeper": "off"}, [{"type": "mac_gatekeeper", "previous": False}])


def _mac_gatekeeper_apply(env: HardenEnv, chk: Check, params: Dict[str, Any]) -> Tuple[bool, str]:
    rc, out, err = run(["spctl", "--master-enable"], timeout=30)
    if rc != 0:
        return False, (err or out).strip()[:150] or "spctl failed"
    return (True, "Gatekeeper turned on") if _mac_gatekeeper_on() else (False, "Gatekeeper is still off")


# =========================================================================== catalogue
BOTH = ("recommended", "strict")
STRICT = ("strict",)


def _build_catalogue() -> List[HardenAction]:
    A: List[HardenAction] = []

    # ---- Microsoft Defender
    A.append(_defender_pref_action(
        "defender.realtime", "Microsoft Defender real-time protection on",
        "Real-time protection scans files and processes as they are used; without it malware runs unchecked.",
        "None for normal use. If you turned it off to install something, turn it back off in Windows Security.",
        BOTH, "DisableRealtimeMonitoring", lambda p: False, lambda cur, t: cur is False))
    A.append(_defender_pref_action(
        "defender.pua", "Block potentially unwanted apps (PUA)",
        "Blocks adware, bundled toolbars and fake optimisers that Defender otherwise ignores.",
        "Rarely blocks a legitimate but pushy installer or crack-style tool; Windows Security shows what was blocked.",
        BOTH, "PUAProtection", lambda p: 1, lambda cur, t: cur == 1))
    A.append(_defender_pref_action(
        "defender.cloud", "Cloud-delivered protection on",
        "Gives Defender near-instant verdicts on brand-new malware (and is required by network protection and some ASR rules).",
        "Sends file metadata and suspicious samples' hashes to Microsoft (privacy trade-off).",
        BOTH, "MAPSReporting", lambda p: 2, lambda cur, t: cur in (1, 2)))
    A.append(_defender_pref_action(
        "defender.network_protection", "Network protection on",
        "Blocks connections to known malicious and low-reputation sites for every program, not just the browser.",
        "May block some sites or downloaders that Microsoft rates as low-reputation; it needs real-time and cloud protection.",
        BOTH, "EnableNetworkProtection", lambda p: 1, lambda cur, t: cur == 1))
    A.append(HardenAction(
        "defender.asr", "Attack Surface Reduction (ASR) rules",
        "ASR rules block the behaviours malware relies on: Office macros launching programs, scripts downloading "
        "executables, credential theft from LSASS, WMI persistence, ransomware heuristics and more.",
        "Block mode can stop legitimate macros, scripts or brand-new unknown programs; start with audit mode "
        "(the default for the recommended profile), review Defender events, then switch. Managed (Intune/GPO) "
        "devices may override local values.",
        "windows", "defender", BOTH, _asr_check, _asr_apply))
    A.append(_defender_pref_action(
        "defender.cfa", "Controlled Folder Access (ransomware shield)",
        "Stops untrusted programs from changing files in Documents, Pictures, Desktop and other protected folders.",
        "Noisy: legitimate programs that save into protected folders are blocked until you allow them "
        "(Windows Security > Ransomware protection). Use audit mode first (cfa_mode=AuditMode).",
        STRICT, "EnableControlledFolderAccess", lambda p: _cfa_mode(p),
        lambda cur, t: (cur in (1, 3)) if t == 1 else cur in (1, 2, 3, 4)))

    # ---- firewall / network protocols
    A.append(HardenAction(
        "windows.firewall", "Windows Firewall on for every profile",
        "Anything on the network can connect to services on this PC when the firewall is off.",
        "Programs that relied on the firewall being off (some games, file sharing) may need a firewall rule.",
        "windows", "network", BOTH, _firewall_check, _firewall_apply))
    A.append(_registry_action(
        "windows.smb1_server", "Turn off the SMBv1 server",
        "SMBv1 is the obsolete protocol exploited by WannaCry/NotPetya.",
        "Very old devices (Windows XP, old NAS/printers/scanners) can no longer reach shares on this PC. Takes effect after a restart.",
        "network", BOTH,
        [RegSetting("HKLM", r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1", 0)], needs_reboot=True))
    A.append(_registry_action(
        "windows.smb1_client", "Turn off the SMBv1 client driver",
        "Stops this PC from talking to servers that only speak the broken SMBv1 protocol.",
        "Old NAS boxes/printers that only support SMBv1 become unreachable. Applies only where the driver is present. "
        "Takes effect after a restart.",
        "network", BOTH,
        [RegSetting("HKLM", r"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start", 4,
                    ok=lambda c: c is None or c == 4)], needs_reboot=True, applicable=_smb1_client_applicable))
    A.append(_registry_action(
        "windows.llmnr", "Turn off LLMNR name resolution",
        "LLMNR lets any device on the network answer name lookups, which attackers abuse to capture password hashes.",
        "Names that only resolve through LLMNR (rare, mostly tiny home networks without DNS names) stop resolving.",
        "network", BOTH,
        [RegSetting("HKLM", r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast", 0)]))

    # ---- credentials
    A.append(_registry_action(
        "windows.wdigest", "Stop WDigest caching clear-text passwords",
        "UseLogonCredential=1 keeps plaintext passwords in LSASS memory for credential stealers; only changed when it is on.",
        "None on modern Windows (WDigest is off by default since Windows 8.1).",
        "credentials", BOTH,
        [RegSetting("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential", 0,
                    ok=lambda c: c in (None, 0))]))
    A.append(_registry_action(
        "windows.lsa_ppl", "LSA protection (RunAsPPL)",
        "Runs the Local Security Authority as a protected process so credential-dumping tools cannot read it.",
        "Needs a restart. Unsigned or old security/smart-card/password-filter plug-ins that load into LSASS will "
        "be blocked (check Event Viewer after the restart). Set without a UEFI lock so it stays reversible; "
        "Windows 11 22H2+ only.",
        "credentials", STRICT, [RegSetting("HKLM", _LSA, "RunAsPPL", 2, ok=lambda c: c in (1, 2))],
        needs_reboot=True, applicable=_lsa_applicable))

    # ---- everyday exposure
    A.append(_registry_action(
        "windows.file_extensions", "Show file extensions in Explorer",
        "Hidden extensions let 'invoice.pdf.exe' look like a PDF - the most common way to disguise malware.",
        "File names in Explorer get longer. Applies to the account running Aegis; sign out/in or restart Explorer to see it.",
        "ux", BOTH,
        [RegSetting("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "HideFileExt", 0)]))
    A.append(_registry_action(
        "windows.autorun", "Turn off AutoRun on every drive type",
        "Stops USB sticks and discs from launching programs automatically (a classic worm route).",
        "Discs/USB installers no longer start by themselves; open them from File Explorer instead.",
        "ux", BOTH,
        [RegSetting("HKLM", _EXPLORER_POL, "NoDriveTypeAutoRun", 255,
                    also=(("HKCU", _EXPLORER_POL, "NoDriveTypeAutoRun"),))]))

    # ---- logging (feeds the event-log / Sigma hunting)
    A.append(_registry_action(
        "windows.ps_scriptblock", "PowerShell script-block logging",
        "Records the content of every PowerShell script (Event 4104) so malicious scripts leave evidence.",
        "Adds events to the PowerShell log; script text, including anything secret typed or pasted into a script, "
        "is logged in clear text and readable by administrators.",
        "logging", BOTH,
        [RegSetting("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging", 1,
                    also=(("HKCU", r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
                           "EnableScriptBlockLogging"),))]))
    A.append(HardenAction(
        "windows.process_audit", "Process-creation auditing with command lines",
        "Logs every started program and its command line (Security Event 4688) - the data the event-log and Sigma "
        "hunting rules need to spot attacks.",
        "Increases the Security log volume (it may wrap sooner) and command lines can contain secrets such as "
        "passwords typed into commands; only administrators can read the Security log.",
        "windows", "logging", BOTH, _process_audit_check, _process_audit_apply))

    # ---- Office
    A.append(_registry_action(
        "office.macro_internet", "Block macros in Office files from the internet",
        "Stops Word/Excel/PowerPoint from running macros in files downloaded from the internet or opened from email.",
        "Macros in files you downloaded stop working until you unblock the file (File properties > Unblock). "
        "Applies to the account running Aegis.",
        "office", BOTH,
        [RegSetting("HKCU", f"Software\\Policies\\Microsoft\\Office\\16.0\\{app}\\security",
                    "blockcontentexecutionfrominternet", 1) for app in _OFFICE_APPS], applicable=_need_office))

    # ---- Linux
    A.append(HardenAction(
        "linux.ufw", "Enable the ufw firewall",
        "Without a host firewall every listening service is reachable from the network.",
        "Incoming connections are denied except SSH (kept open when sshd is installed). Services you host "
        "(web server, file sharing) need `ufw allow` rules.",
        "linux", "network", BOTH, _ufw_check, _ufw_apply))
    A.append(HardenAction(
        "linux.aslr", "Full address-space layout randomisation (ASLR)",
        "ASLR makes memory-corruption exploits much less reliable.",
        "None in practice (it is the distribution default); applied now and at every boot.",
        "linux", "kernel", BOTH, _aslr_check, _aslr_apply))
    A.append(HardenAction(
        "linux.ssh_root_login", "Disable direct root login over SSH",
        "PermitRootLogin yes lets attackers brute-force the root account over the network.",
        "Only changed when root login is explicitly enabled AND a non-root user with sudo rights exists. You must "
        "log in as that user and use sudo afterwards.",
        "linux", "ssh", BOTH, _ssh_root_check, _ssh_root_apply))

    # ---- macOS
    A.append(HardenAction(
        "macos.firewall", "Turn the macOS application firewall on",
        "Incoming connections to apps are not filtered while the firewall is off.",
        "Apps that accept incoming connections prompt for permission the first time.",
        "darwin", "network", BOTH, _mac_firewall_check, _mac_firewall_apply))
    A.append(HardenAction(
        "macos.gatekeeper", "Turn Gatekeeper on",
        "Gatekeeper blocks unsigned/un-notarised apps from running.",
        "Unsigned apps need a right-click > Open (or an explicit allow in System Settings) the first time.",
        "darwin", "malware", BOTH, _mac_gatekeeper_check, _mac_gatekeeper_apply))
    return A


CATALOGUE: List[HardenAction] = _build_catalogue()
ACTIONS_BY_ID: Dict[str, HardenAction] = {a.id: a for a in CATALOGUE}

def _collect_registry_targets() -> set:
    targets = {("HKLM", _AUDIT_KEY.lower(), _CMDLINE_VALUE.lower())}  # process_audit writes this one itself
    for a in CATALOGUE:
        for st in a.registry:
            targets.add((st.hive.upper(), st.key.lower(), st.value.lower()))
    return targets


# Registry values the catalogue may touch: journals are plain data a local attacker could edit, so reverts refuse
# anything outside this set.
REGISTRY_TARGETS = _collect_registry_targets()


def describe_catalogue(platform: Optional[str] = None) -> List[Dict[str, Any]]:
    """Static description of every action (for ``aegis harden --list``)."""
    plat = platform or current_platform()
    return [{"id": a.id, "title": a.title, "why": a.why, "risk": a.risk, "platform": a.platform, "group": a.group,
             "profiles": [p for p in BOTH if p in a.profiles], "needs_admin": a.needs_admin,
             "needs_reboot": a.needs_reboot, "applies_here": a.platform == plat} for a in CATALOGUE
            if platform is None or a.platform == plat]


# =========================================================================== plan
def _params_for(action: HardenAction, profile: str, options: Dict[str, Any]) -> Dict[str, Any]:
    if action.id == "defender.asr":
        mode = asr.parse_mode(options.get("asr_mode") or ASR_DEFAULT_MODE.get(profile, "AuditMode"))
        if mode not in (asr.MODE_ENABLED, asr.MODE_AUDIT, asr.MODE_WARN):
            mode = asr.MODE_AUDIT
        modes = {}
        for guid in asr.resolve_rules(options.get("asr_set") or options.get("asr_rules")):
            rule = asr.RULES_BY_GUID[guid]
            if rule.tier == "server":
                continue
            m = asr.MODE_ENABLED if (mode == asr.MODE_WARN and not rule.warn_supported) else mode
            modes[guid] = m
        return {"modes": modes}
    if action.id == "defender.cfa":
        return {"mode": options.get("cfa_mode") or "Enabled"}
    return {}


def plan(profile: str = "recommended", only: Optional[Sequence[str]] = None, options: Optional[Dict[str, Any]] = None,
         env: Optional[HardenEnv] = None) -> List[PlanItem]:
    """Current state of each action in the profile (or of the ids in ``only``). Read-only.

    ``options``: ``asr_mode`` (AuditMode | Enabled | Warn), ``asr_set`` ("consumer" | "standard" | "all" | list of
    GUIDs/keys), ``cfa_mode`` (Enabled | AuditMode). Unknown profiles raise ValueError."""
    if profile not in PROFILES:
        raise ValueError(f"unknown profile {profile!r} (choose from {', '.join(PROFILES)})")
    env = env or HardenEnv()
    opts = dict(options or {})
    if only:
        ids = list(dict.fromkeys(str(i).strip() for i in only if str(i).strip()))
    else:
        ids = [a.id for a in CATALOGUE if profile in a.profiles and a.platform == env.platform]
    items: List[PlanItem] = []
    for id_ in ids:
        action = ACTIONS_BY_ID.get(id_)
        if action is None:
            items.append(PlanItem(id_, id_, "", "", "", "", NOT_APPLICABLE, "unknown action id"))
            continue
        base = dict(id=action.id, title=action.title, why=action.why, risk=action.risk, platform=action.platform,
                    group=action.group, needs_reboot=action.needs_reboot)
        if action.platform != env.platform:
            items.append(PlanItem(state=NOT_APPLICABLE, detail=f"{action.platform}-only action", needs_admin=action.needs_admin, **base))
            continue
        params = _params_for(action, profile, opts)
        try:
            chk = action.check(env, params)
        except Exception as exc:  # noqa: BLE001 - one broken check must not break the plan
            log.warning("check %s failed: %s", action.id, exc, exc_info=True)
            items.append(PlanItem(state=NOT_APPLICABLE, detail=f"could not check: {type(exc).__name__}: {exc}",
                                  needs_admin=action.needs_admin, params=params, **base))
            continue
        items.append(PlanItem(state=_finish(env, chk), detail=chk.detail, needs_admin=chk.needs_admin if chk.state == WILL_CHANGE else action.needs_admin,
                              params=params, **base))
    return items


# =========================================================================== journal
class Journal:
    """The undo journal of ONE apply() run, rewritten atomically after every step."""

    def __init__(self, config: Config, profile: str, platform: str, options: Dict[str, Any]):
        self.path = new_backup_path(config.backups_dir, "harden")
        self.doc: Dict[str, Any] = {
            "kind": "harden", "version": JOURNAL_VERSION, "id": self.path.stem,
            "created": dt.datetime.now().isoformat(timespec="seconds"), "profile": profile, "platform": platform,
            "options": options, "entries": [],
        }

    def begin(self, item: PlanItem, ops: List[Dict[str, Any]]) -> Dict[str, Any]:
        entry = {"action": item.id, "title": item.title, "status": "pending", "message": "", "ops": ops,
                 "needs_reboot": item.needs_reboot}
        self.doc["entries"].append(entry)
        self.save()
        return entry

    def finish(self, entry: Dict[str, Any], status: str, message: str) -> None:
        entry["status"], entry["message"] = status, message
        try:
            self.save()
        except OSError as exc:  # the change is done; the earlier "pending" snapshot still lets undo revert it
            log.warning("could not update the undo journal %s: %s", self.path, exc)

    def save(self) -> None:
        write_json_atomic(self.path, self.doc)


def _normalise_plan(plan_items: Any) -> List[Tuple[str, Dict[str, Any]]]:
    out: List[Tuple[str, Dict[str, Any]]] = []
    for it in plan_items or []:
        if isinstance(it, PlanItem):
            out.append((it.id, dict(it.params)))
        elif isinstance(it, dict):
            out.append((str(it.get("id")), dict(it.get("params") or {})))
        else:
            out.append((str(it), {}))
    return out


def apply(plan_items: Any, config: Config, dry_run: bool = False, options: Optional[Dict[str, Any]] = None,
          env: Optional[HardenEnv] = None, profile: str = "custom") -> Dict[str, Any]:
    """Apply a plan. Returns ``{"ok", "changed", "message", "details", "results", "journal", "reboot_required"}``.

    ``plan_items`` may be PlanItem objects, their dicts, or plain action ids. Every action is re-checked first, so
    stale plans are safe. One journal per run is written in ``config.backups_dir`` (not for ``dry_run``)."""
    env = env or HardenEnv()
    opts = dict(options or {})
    entries = _normalise_plan(plan_items)
    journal: Optional[Journal] = None
    results: List[Dict[str, Any]] = []
    reboot = False

    for id_, params in entries:
        action = ACTIONS_BY_ID.get(id_)
        res: Dict[str, Any] = {"id": id_, "title": action.title if action else id_, "status": "", "message": "",
                               "needs_reboot": bool(action and action.needs_reboot)}
        results.append(res)
        if action is None:
            res.update(status="not_applicable", message="unknown action id")
            continue
        if action.platform != env.platform:
            res.update(status="not_applicable", message=f"{action.platform}-only action")
            continue
        params = params or _params_for(action, profile, opts)
        try:
            chk = action.check(env, params)
        except Exception as exc:  # noqa: BLE001
            res.update(status="failed", message=f"could not check: {type(exc).__name__}: {exc}")
            continue
        state = _finish(env, chk)
        if state == COMPLIANT:
            res.update(status="already_compliant", message=chk.detail)
            continue
        if state == NOT_APPLICABLE:
            res.update(status="not_applicable", message=chk.detail)
            continue
        if state == NEEDS_ADMIN:
            res.update(status="needs_admin", message="administrator rights are required for this change - "
                                                    "re-run Aegis from an elevated terminal")
            continue
        if dry_run:
            res.update(status="dry_run", message="would change: " + chk.detail)
            continue
        try:  # never change anything without a journal that can undo it
            if journal is None:
                journal = Journal(config, profile, env.platform, opts)
            entry = journal.begin(PlanItem(id=action.id, title=action.title, why=action.why, risk=action.risk,
                                           platform=action.platform, group=action.group, state=state,
                                           needs_reboot=action.needs_reboot), chk.ops)
        except OSError as exc:
            res.update(status="failed", message=f"could not write the undo journal ({exc}); nothing was changed")
            continue
        try:
            ok, msg = action.apply(env, chk, params)
        except PermissionError:
            ok, msg = False, "access denied - run Aegis as Administrator"
        except Exception as exc:  # noqa: BLE001
            log.warning("apply %s failed: %s", action.id, exc, exc_info=True)
            ok, msg = False, f"{type(exc).__name__}: {exc}"
        if ok:
            journal.finish(entry, "applied", msg)
            res.update(status="applied", message=msg)
            reboot = reboot or action.needs_reboot
        else:
            rolled = _rollback(entry["ops"])
            journal.finish(entry, "failed", msg + ("; changes rolled back" if rolled else ""))
            res.update(status="failed", message=msg + ("; changes rolled back" if rolled else ""))

    counts: Dict[str, int] = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    applied, failed, needs_admin = counts.get("applied", 0), counts.get("failed", 0), counts.get("needs_admin", 0)
    if dry_run:
        msg = f"[dry run] {counts.get('dry_run', 0)} change(s) would be made; nothing was modified."
    elif applied or failed:
        msg = f"{applied} hardening change(s) applied" + (f", {failed} failed" if failed else "")
        if journal:
            msg += f". Undo with `aegis undo {journal.path.stem}`."
        if reboot:
            msg += " A restart is required for some changes to take effect."
    else:
        msg = "nothing to change"
    if needs_admin and not dry_run:
        msg += (f" {needs_admin} action(s) were skipped because they need administrator rights - re-run Aegis from "
                "an elevated terminal.")
    ok = failed == 0 and not (needs_admin and not applied and not dry_run)
    out = result(ok, bool(applied), msg.strip(), counts=counts, reboot_required=reboot)
    out.update(results=results, journal=str(journal.path) if journal else None, reboot_required=reboot)
    return out


def _rollback(ops: List[Dict[str, Any]]) -> bool:
    """Undo a half-applied action immediately (ops are safe to run even for unchanged values)."""
    done = False
    for op in reversed(ops):
        try:
            ok, _ = revert_op(op)
            done = done or ok
        except Exception:  # noqa: BLE001
            continue
    return done


# =========================================================================== revert (also used by aegis.protect.undo)
def _reg_kind(data: Any) -> Optional[int]:
    from aegis.core import platform as _p

    if _p.winreg is not None and isinstance(data, list):
        return _p.winreg.REG_MULTI_SZ
    return None


def restore_registry_value(hive: str, key: str, value: str, data: Any, existed: bool, view64: bool = True,
                           dry_run: bool = False, restrict: bool = False) -> Tuple[bool, str]:
    """Put a registry value back (``existed=False`` deletes it). ``restrict`` limits the target to values the
    hardening catalogue itself changes - used for journals, which are data a local attacker could edit."""
    hive_u = str(hive).upper()
    loc = f"{hive_u}\\{key}\\{value}"
    if hive_u not in ("HKLM", "HKCU", "HKU", "HKCR"):
        return False, f"refusing unknown registry hive {hive!r}"
    if restrict and (hive_u, str(key).lower(), str(value).lower()) not in REGISTRY_TARGETS:
        return False, f"refusing to touch {loc}: not a setting Aegis hardening changes"
    try:
        if existed:
            if dry_run:
                return True, f"would restore {loc} = {data!r}"
            reg_set_value(hive_u, key, value, data, kind=_reg_kind(data), view64=view64)
            return True, f"restored {loc} = {data!r}"
        if dry_run:
            return True, f"would delete {loc} (it did not exist before)"
        if reg_read(hive_u, key, value, view64) is None:
            return True, f"{loc} is already absent"
        reg_delete_value(hive_u, key, value, view64)
        return True, f"deleted {loc} (it did not exist before)"
    except PermissionError:
        return False, f"access denied restoring {loc} - run as Administrator"
    except OSError as exc:
        return False, f"could not restore {loc}: {exc}"


def op_needs_admin(op: Dict[str, Any]) -> bool:
    return not (op.get("type") == "registry" and str(op.get("hive", "")).upper() == "HKCU")


def _revert_registry(op: Dict[str, Any], dry_run: bool) -> Tuple[bool, str]:
    return restore_registry_value(op.get("hive", ""), op.get("key", ""), op.get("value", ""), op.get("data"),
                                  bool(op.get("existed")), bool(op.get("view64", True)), dry_run, restrict=True)


def _revert_mp_pref(op: Dict[str, Any], dry_run: bool) -> Tuple[bool, str]:
    name, prev = op.get("name"), op.get("previous")
    stmt = _mp_statement(str(name), prev)
    if not stmt:
        return False, f"cannot restore {name}: unknown setting or value {prev!r}"
    if dry_run:
        return True, f"would run: {stmt}"
    ok, msg = _run_ps([stmt])
    return ok, f"restored {name} to {prev}" if ok else f"could not restore {name}: {msg}"


def _revert_mp_asr(op: Dict[str, Any], dry_run: bool) -> Tuple[bool, str]:
    rules = {asr.norm_guid(g): m for g, m in (op.get("rules") or {}).items()}
    if not rules or not all(g in asr.RULES_BY_GUID for g in rules):
        return False, "journal lists no known ASR rule ids"
    remove = [g for g, m in rules.items() if m is None]
    restore: Dict[str, int] = {}
    for g, m in rules.items():
        if m is not None:
            if m not in asr.MODE_NAMES:
                return False, f"unknown previous ASR action {m!r} for {g}"
            restore[g] = int(m)
    stmts: List[str] = []
    if remove:
        stmts.append(_asr_cmd("Remove-MpPreference", {g: 0 for g in remove}))
    if restore:
        stmts.append(_asr_cmd("Add-MpPreference", restore))
    if dry_run:
        return True, "would run: " + "; ".join(stmts)
    ok, msg = _run_ps(stmts)
    if not ok and remove:  # some builds want -Actions next to -Ids even for Remove-
        stmts[0] = _asr_cmd("Remove-MpPreference", {g: 0 for g in remove}, with_actions=True)
        ok, msg = _run_ps(stmts)
    return ok, (f"restored {len(rules)} ASR rule setting(s)" if ok else f"could not restore ASR rules: {msg}")


def _revert_auditpol(op: Dict[str, Any], dry_run: bool) -> Tuple[bool, str]:
    guid, prev = str(op.get("guid", "")).upper(), op.get("previous")
    if guid != PROC_CREATION_GUID or prev not in (0, 1, 2, 3):
        return False, "refusing to restore an audit subcategory Aegis does not manage"
    if dry_run:
        return True, f"would set Process Creation auditing back to {prev}"
    ok, msg = _auditpol_set(guid, int(prev))
    return ok, "restored the Process Creation audit policy" if ok else f"auditpol failed: {msg}"


def _revert_firewall(op: Dict[str, Any], dry_run: bool) -> Tuple[bool, str]:
    msgs: List[str] = []
    for p, was_on in (op.get("profiles") or {}).items():
        if p not in ("domain", "private", "public") or was_on:
            continue
        if dry_run:
            msgs.append(f"would turn the {p} firewall profile off again")
            continue
        rc, out, err = run(["netsh", "advfirewall", "set", f"{p}profile", "state", "off"], timeout=60)
        if rc != 0:
            return False, f"netsh failed for {p}: {(err or out).strip()[:120]}"
        msgs.append(f"{p} profile restored to off")
    return True, "; ".join(msgs) or "nothing to restore"


def _revert_ufw(op: Dict[str, Any], dry_run: bool) -> Tuple[bool, str]:
    rules = [r for r in op.get("added_rules") or [] if re.fullmatch(r"\d{1,5}/(tcp|udp)", str(r))]
    if dry_run:
        return True, "would " + ("disable ufw and " if not op.get("was_active") else "") + f"delete {len(rules)} added rule(s)"
    if not op.get("was_active"):
        rc, out, err = run(["ufw", "disable"], timeout=60)
        if rc != 0:
            return False, f"ufw disable failed: {(err or out).strip()[:120]}"
    for r in rules:
        run(["ufw", "delete", "allow", r], timeout=30)
    return True, "ufw restored to its previous state"


_SYSCTL_ALLOWED = {"kernel.randomize_va_space"}
_FILE_ALLOWED = {SYSCTL_CONF}
_FILE_LINES_ALLOWED = {SSHD_CONFIG}


def _revert_sysctl(op: Dict[str, Any], dry_run: bool) -> Tuple[bool, str]:
    key, prev = str(op.get("key")), str(op.get("previous"))
    if key not in _SYSCTL_ALLOWED or not re.fullmatch(r"[0-2]", prev):
        return False, "refusing to restore an unmanaged sysctl"
    if dry_run:
        return True, f"would run sysctl -w {key}={prev}"
    rc, out, err = run(["sysctl", "-w", f"{key}={prev}"], timeout=30)
    return rc == 0, f"restored {key}={prev}" if rc == 0 else f"sysctl failed: {(err or out).strip()[:120]}"


def _revert_file(op: Dict[str, Any], dry_run: bool) -> Tuple[bool, str]:
    path = str(op.get("path"))
    if path not in _FILE_ALLOWED:
        return False, "refusing to restore a file Aegis does not manage"
    if dry_run:
        return True, f"would {'restore' if op.get('existed') else 'delete'} {path}"
    try:
        if op.get("existed") and op.get("content") is not None:
            _write_file(path, str(op["content"]))
        else:
            _delete_file(path)
    except OSError as exc:
        return False, f"could not restore {path}: {exc}"
    return True, f"restored {path}"


def _revert_file_lines(op: Dict[str, Any], dry_run: bool) -> Tuple[bool, str]:
    path = str(op.get("path"))
    if path not in _FILE_LINES_ALLOWED:
        return False, "refusing to edit a file Aegis does not manage"
    text = _read_text(path)
    if text is None:
        return False, f"cannot read {path}"
    lines = text.splitlines(keepends=True)
    changed = 0
    for edit in op.get("edits") or []:
        old, new = str(edit.get("old", "")), str(edit.get("new", ""))
        for i, ln in enumerate(lines):
            if ln.rstrip("\r\n") == new and old:
                lines[i] = old + ln[len(ln.rstrip("\r\n")):]
                changed += 1
                break
    if dry_run:
        return True, f"would restore {changed} line(s) in {path}"
    if not changed:
        return True, f"{path}: the edited line is no longer present; left as is"
    try:
        _write_file(path, "".join(lines))
    except OSError as exc:
        return False, f"could not write {path}: {exc}"
    if path == SSHD_CONFIG:
        _reload_sshd()
    return True, f"restored {changed} line(s) in {path}"


def _revert_mac_firewall(op: Dict[str, Any], dry_run: bool) -> Tuple[bool, str]:
    state = "on" if op.get("previous") else "off"
    if dry_run:
        return True, f"would turn the application firewall {state}"
    rc, out, err = run([_SOCKETFILTER, "--setglobalstate", state], timeout=30)
    return rc == 0, f"application firewall set to {state}" if rc == 0 else (err or out).strip()[:120]


def _revert_mac_gatekeeper(op: Dict[str, Any], dry_run: bool) -> Tuple[bool, str]:
    flag = "--master-enable" if op.get("previous") else "--master-disable"
    if dry_run:
        return True, f"would run spctl {flag}"
    rc, out, err = run(["spctl", flag], timeout=30)
    return rc == 0, "Gatekeeper restored" if rc == 0 else (err or out).strip()[:120]


REVERTERS: Dict[str, Callable[[Dict[str, Any], bool], Tuple[bool, str]]] = {
    "registry": _revert_registry, "mp_pref": _revert_mp_pref, "mp_asr": _revert_mp_asr, "auditpol": _revert_auditpol,
    "firewall": _revert_firewall, "ufw": _revert_ufw, "sysctl": _revert_sysctl, "file": _revert_file,
    "file_lines": _revert_file_lines, "mac_firewall": _revert_mac_firewall, "mac_gatekeeper": _revert_mac_gatekeeper,
}


def revert_op(op: Dict[str, Any], dry_run: bool = False) -> Tuple[bool, str]:
    """Revert one journal operation. Never raises."""
    fn = REVERTERS.get(str(op.get("type")))
    if fn is None:
        return False, f"unknown journal operation {op.get('type')!r}"
    try:
        return fn(op, dry_run)
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"


def revert_journal(doc: Dict[str, Any], dry_run: bool = False) -> List[Dict[str, Any]]:
    """Revert a harden journal: entries newest-first, each entry's operations in reverse order."""
    out: List[Dict[str, Any]] = []
    for entry in reversed(doc.get("entries") or []):
        ops = list(entry.get("ops") or [])
        status = entry.get("status")
        row = {"action": entry.get("action"), "title": entry.get("title"), "ok": True, "messages": [], "skipped": False}
        if not ops or status == "skipped":
            row.update(skipped=True, messages=["nothing to revert"])
            out.append(row)
            continue
        for op in reversed(ops):
            ok, msg = revert_op(op, dry_run)
            row["messages"].append(msg)
            row["ok"] = row["ok"] and ok
        out.append(row)
    return out


def journal_needs_admin(doc: Dict[str, Any]) -> bool:
    return any(op_needs_admin(op) for e in doc.get("entries") or [] for op in e.get("ops") or [])
