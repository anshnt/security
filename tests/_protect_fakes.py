"""Fakes shared by tests/test_harden.py and tests/test_undo.py: a dict-backed registry, Microsoft Defender
cmdlets (Set-/Add-/Remove-MpPreference), netsh firewall profiles and auditpol. Nothing here touches the real
system, so the Windows code paths run on Linux CI too."""

from __future__ import annotations

import csv
import io
import re
from typing import Any, Dict, List, Optional, Tuple

from aegis.protect import asr, harden

NT_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
FW_LOCAL = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
_PROFILE_SUB = {"domain": "DomainProfile", "private": "StandardProfile", "public": "PublicProfile"}


class FakeReg:
    """Registry as a dict: (HIVE, key.lower(), value.lower()) -> data. Absent values read as None."""

    def __init__(self) -> None:
        self.values: Dict[Tuple[str, str, str], Any] = {}
        self.subkey_map: Dict[Tuple[str, str], List[str]] = {}
        self.writes: List[Tuple[str, str, str, Any]] = []
        self.fail_on: Optional[Tuple[str, str]] = None  # (key substring, value lower) -> OSError on set

    @staticmethod
    def _k(hive: str, key: str, value: str) -> Tuple[str, str, str]:
        return (hive.upper(), key.lower(), value.lower())

    def put(self, hive: str, key: str, value: str, data: Any) -> None:
        self.values[self._k(hive, key, value)] = data

    def get(self, hive: str, key: str, value: str) -> Any:
        return self.values.get(self._k(hive, key, value))

    def read(self, hive, key, value, view64=True):  # noqa: ANN001
        return self.get(hive, key, value)

    def set_value(self, hive, key, value, data, kind=None, view64=True):  # noqa: ANN001
        if self.fail_on and self.fail_on[0] in key.lower() and self.fail_on[1] == value.lower():
            raise OSError("simulated registry failure")
        self.writes.append((hive, key, value, data))
        self.put(hive, key, value, data)

    def delete_value(self, hive, key, value, view64=True):  # noqa: ANN001
        k = self._k(hive, key, value)
        if k not in self.values:
            raise FileNotFoundError(2, "value not found")
        del self.values[k]

    def subkeys(self, hive, key, view64=True):  # noqa: ANN001
        return list(self.subkey_map.get((hive.upper(), key.lower()), []))

    def snapshot(self) -> Dict[Tuple[str, str, str], Any]:
        return dict(self.values)


_SET_NAMES = {name: {label: num for num, label in mapping.items()} for name, mapping in harden._MP_ENUM.items()}
_ASR_NAMES = {label.lower(): num for num, label in asr.MODE_NAMES.items()}


class FakeDefender:
    """Get-/Set-/Add-/Remove-MpPreference. ``tamper=True`` makes every change silently not stick."""

    def __init__(self, third_party: Optional[str] = None, tamper: bool = False, present: bool = True,
                 add_updates_existing: bool = True) -> None:
        self.present = present
        self.tamper = tamper
        self.add_updates_existing = add_updates_existing
        self.pref: Dict[str, Any] = {
            "DisableRealtimeMonitoring": True, "PUAProtection": 0, "MAPSReporting": 0, "EnableNetworkProtection": 0,
            "EnableControlledFolderAccess": 0,
        }
        self.asr_state: Dict[str, int] = {}
        self.av = [{"name": third_party, "state": 0x061100}] if third_party else [{"name": "Windows Defender", "state": 0x061100}]
        self.statements: List[str] = []

    def facts(self) -> Optional[Dict[str, Any]]:
        if not self.present:
            return None
        pref = dict(self.pref)
        pref["AttackSurfaceReductionRules_Ids"] = list(self.asr_state)
        pref["AttackSurfaceReductionRules_Actions"] = list(self.asr_state.values())
        return {"pref": pref, "mp": {"AntivirusEnabled": True, "AMRunningMode": "Normal"}, "av": self.av}

    # ---- powershell(script) fake
    def run_script(self, script: str, timeout: int = 90) -> Tuple[int, str, str]:
        for stmt in script.replace("$ErrorActionPreference='Stop';", "").split(";"):
            stmt = stmt.strip()
            if not stmt:
                continue
            self.statements.append(stmt)
            m = re.match(r"^(Add|Set|Remove)-MpPreference -AttackSurfaceReductionRules_Ids (\S+)(?: -AttackSurfaceReductionRules_Actions (\S+))?$", stmt)
            if m:
                self._asr(m.group(1), m.group(2).split(","), m.group(3).split(",") if m.group(3) else [])
                continue
            m = re.match(r"^Set-MpPreference -(\w+) (\S+)$", stmt)
            if m:
                self._pref(m.group(1), m.group(2))
                continue
            return 1, "", f"unrecognised statement: {stmt}"
        return 0, "", ""

    def _pref(self, name: str, raw: str) -> None:
        if self.tamper:
            return
        if raw in ("$true", "$false"):
            self.pref[name] = raw == "$true"
        else:
            self.pref[name] = _SET_NAMES[name][raw]

    def _asr(self, verb: str, ids: List[str], actions: List[str]) -> None:
        if self.tamper:
            return
        if verb == "Remove":
            for g in ids:
                self.asr_state.pop(g, None)
        elif verb == "Set":
            self.asr_state = {g: _ASR_NAMES[a.lower()] for g, a in zip(ids, actions)}
        else:
            for g, a in zip(ids, actions):
                if g in self.asr_state and not self.add_updates_existing:
                    continue
                self.asr_state[g] = _ASR_NAMES[a.lower()]


class FakeWindows:
    """Registry + Defender + netsh + auditpol wired into aegis.protect.harden (and undo) via monkeypatch."""

    def __init__(self, build: int = 22631, admin: bool = True, defender: Optional[FakeDefender] = None) -> None:
        self.reg = FakeReg()
        self.reg.put("HKLM", NT_KEY, "CurrentBuild", str(build))
        self.defender = defender or FakeDefender()
        self.admin = admin
        self.audit = {harden.PROC_CREATION_GUID: 0}
        self.fw_products: List[Dict[str, Any]] = []
        self.calls: List[List[str]] = []

    # ---- subprocess fake
    def run(self, argv, timeout=60, input_text=None):  # noqa: ANN001
        argv = list(argv)
        self.calls.append(argv)
        if argv[:3] == ["netsh", "advfirewall", "set"] and len(argv) == 6:
            prof = argv[3].replace("profile", "")
            self.reg.put("HKLM", f"{FW_LOCAL}\\{_PROFILE_SUB[prof]}", "EnableFirewall", 1 if argv[5] == "on" else 0)
            return 0, "Ok.", ""
        if argv[0] == "auditpol":
            return self._auditpol(argv)
        return 0, "", ""

    def _auditpol(self, argv: List[str]) -> Tuple[int, str, str]:
        if argv[1] == "/backup":
            path = argv[2].split(":", 1)[1]
            buf = io.StringIO()
            w = csv.writer(buf, lineterminator="\n")
            w.writerow(["Machine Name", "Policy Target", "Subcategory", "Subcategory GUID", "Inclusion Setting",
                        "Exclusion Setting", "Setting Value"])
            w.writerow(["PC", "System", "Security State Change", "{0CCE9210-69AE-11D9-BED3-505054503030}", "Success", "", "1"])
            for guid, val in self.audit.items():
                w.writerow(["PC", "System", "Process Creation", guid, "x", "", str(val)])
            with open(path, "w", encoding="utf-8-sig") as fh:
                fh.write(buf.getvalue())
            return 0, "", ""
        if argv[1] == "/set":
            guid = argv[2].split(":", 1)[1]
            val = (1 if argv[3] == "/success:enable" else 0) | (2 if argv[4] == "/failure:enable" else 0)
            self.audit[guid] = val
            return 0, "", ""
        return 1, "", "bad auditpol call"

    # ---- hooks
    def powershell_json(self, script, timeout=90):  # noqa: ANN001
        if script == harden._DEFENDER_SCRIPT:
            return self.defender.facts()
        if script == harden._FIREWALL_PRODUCT_SCRIPT:
            return self.fw_products
        return None

    def install(self, monkeypatch, *, undo_module=None) -> "FakeWindows":  # noqa: ANN001
        monkeypatch.setattr(harden, "IS_WINDOWS", True)
        monkeypatch.setattr(harden, "IS_MAC", False)
        monkeypatch.setattr(harden, "reg_read", self.reg.read)
        monkeypatch.setattr(harden, "reg_set_value", self.reg.set_value)
        monkeypatch.setattr(harden, "reg_delete_value", self.reg.delete_value)
        monkeypatch.setattr(harden, "reg_subkeys", self.reg.subkeys)
        monkeypatch.setattr(harden, "run", self.run)
        monkeypatch.setattr(harden, "powershell", self.defender.run_script)
        monkeypatch.setattr(harden, "powershell_json", self.powershell_json)
        monkeypatch.setattr(harden, "is_admin", lambda: self.admin)
        if undo_module is not None:
            monkeypatch.setattr(undo_module, "IS_WINDOWS", True)
            monkeypatch.setattr(undo_module, "is_admin", lambda: self.admin)
            monkeypatch.setattr(undo_module, "run", self.run)
        return self

    def env(self) -> harden.HardenEnv:
        return harden.HardenEnv(admin=self.admin)
