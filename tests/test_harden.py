"""Tests for aegis.protect.harden / aegis.protect.asr and the ASR audit + `harden` remediation action.

Windows paths run against tests/_protect_fakes.py (dict registry, fake Defender cmdlets, netsh, auditpol), Linux and
macOS paths against a tiny fake file system, so everything passes on Linux and Windows CI."""

import datetime as dt
import json
import re
from pathlib import Path

import pytest

from aegis.core.config import Config
from aegis.core.models import Finding, Remediation, Severity
from aegis.protect import asr, harden, undo
from aegis.scanners import system_audit as sa
from tests._protect_fakes import FakeDefender, FakeWindows

GUID_PROC = harden.PROC_CREATION_GUID
EXPLORER_ADV = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
SMB_KEY = r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
LLMNR_KEY = r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
LSA_KEY = r"SYSTEM\CurrentControlSet\Control\Lsa"
SBL_KEY = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"

# The 19 rules exactly as Microsoft documents them (GUID + Microsoft Intune name) on
# https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference (checked 2026-10-16).
MICROSOFT_ASR = {
    "56a863a9-875e-4185-98a7-b882c64b5ce5": "Block abuse of exploited vulnerable signed drivers (Device)",
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2": "Block credential stealing from the Windows local security authority subsystem",
    "e6db77e5-3df2-4cf1-b95a-636979351e5b": "Block persistence through WMI event subscription",
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c": "Block Adobe Reader from creating child processes",
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a": "Block all Office applications from creating child processes",
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550": "Block executable content from email client and webmail",
    "01443614-cd74-433a-b99e-2ecdc07bfc25": "Block executable files from running unless they meet a prevalence, age, or trusted list criterion",
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc": "Block execution of potentially obfuscated scripts",
    "d3e037e1-3eb8-44c8-a917-57927947596d": "Block JavaScript or VBScript from launching downloaded executable content",
    "3b576869-a4ec-4529-8536-b80a7769e899": "Block Office applications from creating executable content",
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84": "Block Office applications from injecting code into other processes",
    "26190899-1602-49e8-8b27-eb1d0a1ce869": "Block Office communication application from creating child processes",
    "d1e49aac-8f56-4280-b9ba-993a6d77406c": "Block process creations originating from PSExec and WMI commands",
    "33ddedf1-c6e0-47cb-833e-de6133960387": "Block rebooting machine in Safe Mode",
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4": "Block untrusted and unsigned processes that run from USB",
    "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb": "Block use of copied or impersonated system tools",
    "a8f5898e-1dc8-49a9-9878-85004b8a61e6": "Block Webshell creation for Servers",
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b": "Block Win32 API calls from Office macros",
    "c1db55ab-c21a-4637-bb3f-a12568109d35": "Use advanced protection against ransomware",
}


@pytest.fixture
def cfg():
    return Config.load()


@pytest.fixture
def win(monkeypatch):
    return FakeWindows().install(monkeypatch, undo_module=undo)


def by_id(items):
    return {i.id: i for i in items}


# =========================================================================== ASR table
def test_asr_table_matches_microsoft_reference_exactly():
    assert {r.guid: r.name for r in asr.ASR_RULES} == MICROSOFT_ASR


def test_asr_table_is_well_formed():
    guids = [r.guid for r in asr.ASR_RULES]
    assert len(guids) == len(set(guids)) == 19
    assert all(asr.GUID_RE.match(g) for g in guids)  # lower-case canonical GUIDs
    assert all(r.name.strip() and r.effect.strip() for r in asr.ASR_RULES)
    assert len({r.name for r in asr.ASR_RULES}) == 19 and len({r.key for r in asr.ASR_RULES}) == 19
    assert {r.tier for r in asr.ASR_RULES} == {"standard", "consumer", "advanced", "server"}


def test_asr_tiers_and_sets():
    assert len(asr.STANDARD_GUIDS) == 3  # Microsoft's "Standard protection rules"
    assert set(asr.STANDARD_GUIDS) <= set(asr.CONSUMER_GUIDS)
    assert len(asr.CONSUMER_GUIDS) == 13
    assert "a8f5898e-1dc8-49a9-9878-85004b8a61e6" not in asr.CLIENT_GUIDS  # Exchange-only rule is never applied to PCs
    advanced = {r.guid for r in asr.ASR_RULES if r.tier == "advanced"}
    assert advanced and not advanced & set(asr.CONSUMER_GUIDS)  # false-positive-prone rules are opt-in
    assert asr.ASR_SOURCE_URL.startswith("https://learn.microsoft.com/")


def test_asr_helpers():
    assert asr.parse_mode("Enabled") == 1 and asr.parse_mode("block") == 1 and asr.parse_mode("audit") == 2
    assert asr.parse_mode("AuditMode") == 2 and asr.parse_mode("warn") == 6 and asr.parse_mode(5) == 5
    assert asr.parse_mode("nonsense") is None and asr.parse_mode(7) is None and asr.parse_mode(True) is None
    assert asr.mode_strength(1) > asr.mode_strength(6) > asr.mode_strength(2) > asr.mode_strength(0) == asr.mode_strength(None)
    st = asr.parse_asr_state(["{56A863A9-875E-4185-98A7-B882C64B5CE5}", "junk", "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"], [1, 2, "x"])
    assert st == {"56a863a9-875e-4185-98a7-b882c64b5ce5": 1}  # junk id skipped, bad action skipped
    assert asr.parse_asr_state("56a863a9-875e-4185-98a7-b882c64b5ce5", 2) == {"56a863a9-875e-4185-98a7-b882c64b5ce5": 2}
    assert asr.parse_asr_state(None, None) == {}
    assert asr.resolve_rules("standard") == asr.STANDARD_GUIDS
    assert asr.resolve_rules(["lsass", "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C", "nope"]) == [
        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"]
    summ = asr.summarize_asr({"56a863a9-875e-4185-98a7-b882c64b5ce5": 1, "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2": 2})
    assert summ["enabled"] == 1 and len(summ["audit"]) == 1 and summ["total"] == 18


# =========================================================================== catalogue
def test_catalogue_is_well_formed():
    ids = [a.id for a in harden.CATALOGUE]
    assert len(ids) == len(set(ids))
    for a in harden.CATALOGUE:
        assert a.title and a.why and a.risk, a.id
        assert a.platform in ("windows", "linux", "darwin")
        assert set(a.profiles) <= {"recommended", "strict"}
        assert callable(a.check) and callable(a.apply)
        for s in a.registry:  # every registry write is on the revert allow-list
            assert (s.hive.upper(), s.key.lower(), s.value.lower()) in harden.REGISTRY_TARGETS
    strict = {a.id for a in harden.CATALOGUE if "strict" in a.profiles}
    rec = {a.id for a in harden.CATALOGUE if "recommended" in a.profiles}
    assert rec <= strict
    assert strict - rec == {"defender.cfa", "windows.lsa_ppl"}  # strict adds CFA and LSA PPL (ASR goes to block mode)


def test_catalogue_covers_the_requested_actions():
    wanted = {"defender.realtime", "defender.pua", "defender.cloud", "defender.network_protection", "defender.asr",
              "defender.cfa", "windows.firewall", "windows.smb1_server", "windows.llmnr", "windows.wdigest",
              "windows.lsa_ppl", "windows.file_extensions", "windows.autorun", "windows.ps_scriptblock",
              "windows.process_audit", "windows.file_audit", "office.macro_internet", "linux.ufw", "linux.aslr", "linux.ssh_root_login",
              "macos.firewall", "macos.gatekeeper"}
    assert wanted <= {a.id for a in harden.CATALOGUE}
    desc = harden.describe_catalogue()
    assert all({"id", "title", "why", "risk", "needs_reboot"} <= set(d) for d in desc)
    assert next(d for d in desc if d["id"] == "windows.lsa_ppl")["needs_reboot"] is True


# =========================================================================== plan (Windows)
def test_plan_on_a_fresh_windows_pc(win):
    items = by_id(harden.plan("recommended", env=win.env()))
    st = {k: v.state for k, v in items.items()}
    assert st["defender.realtime"] == st["defender.pua"] == st["defender.cloud"] == "will_change"
    assert st["defender.network_protection"] == st["defender.asr"] == "will_change"
    assert st["windows.smb1_server"] == st["windows.llmnr"] == st["windows.autorun"] == "will_change"
    assert st["windows.ps_scriptblock"] == st["windows.process_audit"] == st["windows.file_extensions"] == "will_change"
    assert st["windows.file_audit"] == "will_change"
    assert st["windows.firewall"] == "compliant"  # absent value = firewall on
    assert st["windows.wdigest"] == "compliant" and st["windows.smb1_client"] == "compliant"
    assert st["office.macro_internet"] == "not_applicable" and "Office" in items["office.macro_internet"].detail
    assert "defender.cfa" not in st and "windows.lsa_ppl" not in st and not any(k.startswith("linux.") for k in st)
    # ASR default for the recommended profile is audit mode over the 13 consumer-safe rules
    assert set(items["defender.asr"].params["modes"].values()) == {asr.MODE_AUDIT}
    assert len(items["defender.asr"].params["modes"]) == 13
    assert all(i.why and i.risk for i in items.values())


def test_plan_strict_adds_block_mode_cfa_and_lsa(win):
    items = by_id(harden.plan("strict", env=win.env()))
    assert set(items["defender.asr"].params["modes"].values()) == {asr.MODE_ENABLED}
    assert items["defender.cfa"].state == "will_change" and items["defender.cfa"].params == {"mode": "Enabled"}
    assert items["windows.lsa_ppl"].state == "will_change" and items["windows.lsa_ppl"].needs_reboot


def test_lsa_ppl_needs_windows_11_22h2(monkeypatch):
    old = FakeWindows(build=19045).install(monkeypatch, undo_module=undo)
    item = by_id(harden.plan("custom", only=["windows.lsa_ppl"], env=old.env()))["windows.lsa_ppl"]
    assert item.state == "not_applicable" and "22H2" in item.detail and "UEFI" in item.detail


def test_lsa_ppl_value_is_the_reversible_non_uefi_one(win, cfg):
    harden.apply(harden.plan("custom", only=["windows.lsa_ppl"], env=win.env()), cfg, env=win.env())
    assert win.reg.get("HKLM", LSA_KEY, "RunAsPPL") == 2  # 2 = no UEFI lock (1 would need Microsoft's opt-out tool)


def test_office_macro_action_follows_office_presence(win, cfg):
    win.reg.subkey_map[("HKLM", r"software\microsoft\office")] = ["ClickToRun"]
    item = by_id(harden.plan("recommended", env=win.env()))["office.macro_internet"]
    assert item.state == "will_change" and item.needs_admin is False  # HKCU only
    harden.apply(["office.macro_internet"], cfg, env=win.env())
    for app in ("word", "excel", "powerpoint"):
        assert win.reg.get("HKCU", rf"Software\Policies\Microsoft\Office\16.0\{app}\security", "blockcontentexecutionfrominternet") == 1


def test_firewall_states(win):
    sub = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
    win.reg.put("HKLM", sub + r"\PublicProfile", "EnableFirewall", 0)
    item = by_id(harden.plan("recommended", env=win.env()))["windows.firewall"]
    assert item.state == "will_change" and "public" in item.detail
    win.fw_products = [{"name": "Contoso Firewall", "state": 0x061100}]
    item = by_id(harden.plan("recommended", env=harden.HardenEnv(admin=True)))["windows.firewall"]
    assert item.state == "not_applicable" and "Contoso" in item.detail
    win.fw_products = []
    win.reg.put("HKLM", r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile", "EnableFirewall", 0)
    item = by_id(harden.plan("recommended", env=harden.HardenEnv(admin=True)))["windows.firewall"]
    assert item.state == "not_applicable" and "Group Policy" in item.detail


def test_defender_actions_not_applicable_with_third_party_av_or_no_defender(monkeypatch):
    fw = FakeWindows(defender=FakeDefender(third_party="Contoso Antivirus")).install(monkeypatch, undo_module=undo)
    items = by_id(harden.plan("recommended", env=fw.env()))
    for k in ("defender.realtime", "defender.pua", "defender.cloud", "defender.network_protection", "defender.asr"):
        assert items[k].state == "not_applicable" and "Contoso Antivirus" in items[k].detail
    none = FakeWindows(defender=FakeDefender(present=False)).install(monkeypatch, undo_module=undo)
    items = by_id(harden.plan("recommended", env=none.env()))
    assert items["defender.pua"].state == "not_applicable" and "not available" in items["defender.pua"].detail
    assert items["windows.llmnr"].state == "will_change"  # registry actions are unaffected


def test_plan_without_admin_marks_machine_wide_changes_needs_admin(monkeypatch):
    fw = FakeWindows(admin=False).install(monkeypatch, undo_module=undo)
    fw.reg.subkey_map[("HKLM", r"software\microsoft\office")] = ["16.0"]
    items = by_id(harden.plan("recommended", env=fw.env()))
    assert items["windows.llmnr"].state == "needs_admin" and items["defender.pua"].state == "needs_admin"
    assert items["windows.process_audit"].state == items["windows.file_audit"].state == "needs_admin"
    assert items["windows.file_extensions"].state == "will_change"  # HKCU only: no elevation needed
    assert items["office.macro_internet"].state == "will_change"
    assert items["windows.wdigest"].state == "compliant"


def test_plan_unknown_profile_and_ids(win):
    with pytest.raises(ValueError):
        harden.plan("paranoid")
    items = harden.plan("custom", only=["nope", "linux.aslr", "windows.llmnr", "windows.llmnr"], env=win.env())
    assert [i.id for i in items] == ["nope", "linux.aslr", "windows.llmnr"]  # de-duplicated, order kept
    assert items[0].state == "not_applicable" and "unknown" in items[0].detail
    assert items[1].state == "not_applicable" and "linux-only" in items[1].detail


def test_plan_survives_a_broken_check(win, monkeypatch):
    def boom(env, params):
        raise RuntimeError("kaput")

    monkeypatch.setattr(harden.ACTIONS_BY_ID["windows.llmnr"], "check", boom)
    item = by_id(harden.plan("custom", only=["windows.llmnr"], env=win.env()))["windows.llmnr"]
    assert item.state == "not_applicable" and "kaput" in item.detail


def test_plan_items_are_json_serialisable(win):
    json.dumps([i.to_dict() for i in harden.plan("strict", env=win.env())])


# =========================================================================== apply -> journal -> undo
def snapshot(win):
    return (win.reg.snapshot(), dict(win.defender.pref), dict(win.defender.asr_state), dict(win.audit))


def test_apply_journal_undo_round_trip_restores_everything(win, cfg):
    win.reg.put("HKLM", SMB_KEY, "SMB1", 1)  # previously ON -> must come back as 1, not be deleted
    win.reg.put("HKCU", EXPLORER_ADV, "HideFileExt", 1)
    win.audit[GUID_PROC] = 2  # failure-only auditing must survive (becomes 3, reverts to 2)
    win.defender.pref["PUAProtection"] = 2
    win.defender.asr_state["c1db55ab-c21a-4637-bb3f-a12568109d35"] = asr.MODE_ENABLED  # already blocking: stays
    before = snapshot(win)

    items = harden.plan("recommended", env=win.env())
    out = harden.apply(items, cfg, env=win.env(), profile="recommended")
    assert out["ok"] and out["changed"] and out["journal"] and "aegis undo" in out["message"]
    assert out["reboot_required"] is True  # SMBv1 changes need a restart
    st = {r["id"]: r["status"] for r in out["results"]}
    assert st["defender.asr"] == "applied" and st["windows.wdigest"] == "already_compliant"
    assert st["office.macro_internet"] == "not_applicable"

    # ---- everything actually changed
    assert win.reg.get("HKLM", SMB_KEY, "SMB1") == 0 and win.reg.get("HKCU", EXPLORER_ADV, "HideFileExt") == 0
    assert win.reg.get("HKLM", LLMNR_KEY, "EnableMulticast") == 0 and win.reg.get("HKLM", SBL_KEY, "EnableScriptBlockLogging") == 1
    assert win.reg.get("HKLM", harden._AUDIT_KEY, harden._CMDLINE_VALUE) == 1 and win.audit[GUID_PROC] == 3
    assert win.audit[harden.FILE_SYSTEM_GUID] == 1
    p = win.defender.pref
    assert p["DisableRealtimeMonitoring"] is False and p["PUAProtection"] == 1 and p["MAPSReporting"] == 2
    assert p["EnableNetworkProtection"] == 1
    assert len(win.defender.asr_state) == 13 and win.defender.asr_state["c1db55ab-c21a-4637-bb3f-a12568109d35"] == asr.MODE_ENABLED
    assert sum(1 for m in win.defender.asr_state.values() if m == asr.MODE_AUDIT) == 12

    # ---- exactly one journal, holding the previous values (including "absent")
    journals = sorted(cfg.backups_dir.glob("harden-*.json"))
    assert len(journals) == 1 and out["journal"] == str(journals[0])
    doc = json.loads(journals[0].read_text())
    assert doc["kind"] == "harden" and doc["profile"] == "recommended" and doc["platform"] == "windows"
    ops = {e["action"]: e["ops"] for e in doc["entries"]}
    assert ops["windows.smb1_server"][0]["existed"] is True and ops["windows.smb1_server"][0]["data"] == 1
    assert ops["windows.llmnr"][0]["existed"] is False and ops["windows.llmnr"][0]["data"] is None
    assert {"type": "auditpol", "guid": GUID_PROC, "previous": 2} in ops["windows.process_audit"]
    assert ops["windows.file_audit"] == [{"type": "auditpol", "guid": harden.FILE_SYSTEM_GUID, "previous": 0}]
    assert {"type": "mp_pref", "name": "PUAProtection", "previous": 2} in ops["defender.pua"]
    asr_op = ops["defender.asr"][0]
    assert asr_op["type"] == "mp_asr" and "c1db55ab-c21a-4637-bb3f-a12568109d35" not in asr_op["rules"]
    assert set(asr_op["rules"].values()) == {None}  # none of the others were configured before
    assert all(e["status"] == "applied" for e in doc["entries"])

    # ---- list shows it, undo restores the exact previous state
    entry = next(e for e in undo.list_backups(cfg) if e["kind"] == "harden")
    assert entry["id"] == journals[0].stem and entry["undoable"] and "applied" in entry["summary"]
    res = undo.undo(cfg, entry["id"])
    assert res["ok"] and res["changed"], res
    assert snapshot(win) == before
    assert res["reboot_required"] is True
    assert undo.undo(cfg, entry["id"])["ok"] is False  # already undone
    assert next(e for e in undo.list_backups(cfg) if e["kind"] == "harden")["undone"]
    assert undo.undo(cfg, entry["id"], force=True)["ok"]


def test_second_apply_is_a_no_op_without_a_journal(win, cfg):
    harden.apply(harden.plan("recommended", env=win.env()), cfg, env=win.env())
    n = len(list(cfg.backups_dir.glob("harden-*.json")))
    out = harden.apply(harden.plan("recommended", env=win.env()), cfg, env=win.env())
    assert out["ok"] and not out["changed"] and out["journal"] is None and "nothing to change" in out["message"]
    assert len(list(cfg.backups_dir.glob("harden-*.json"))) == n
    assert {r["status"] for r in out["results"]} <= {"already_compliant", "not_applicable"}


def test_dry_run_changes_nothing_and_writes_no_journal(win, cfg):
    before = snapshot(win)
    out = harden.apply(harden.plan("strict", env=win.env()), cfg, dry_run=True, env=win.env())
    assert out["ok"] and not out["changed"] and out["journal"] is None and "dry run" in out["message"]
    assert snapshot(win) == before and not list(cfg.backups_dir.glob("harden-*.json"))
    assert any(r["status"] == "dry_run" for r in out["results"])


def test_apply_accepts_plain_ids_and_dicts(win, cfg):
    out = harden.apply(["windows.llmnr", {"id": "windows.autorun"}], cfg, env=win.env())
    assert out["ok"] and win.reg.get("HKLM", LLMNR_KEY, "EnableMulticast") == 0
    assert win.reg.get("HKLM", harden._EXPLORER_POL, "NoDriveTypeAutoRun") == 255


def test_apply_without_admin_skips_with_a_clear_message(monkeypatch, cfg):
    fw = FakeWindows(admin=False).install(monkeypatch, undo_module=undo)
    before = snapshot(fw)
    out = harden.apply(harden.plan("recommended", env=fw.env()), cfg, env=fw.env())
    assert "administrator" in out["message"].lower() and "elevated" in out["message"]
    st = {r["id"]: r["status"] for r in out["results"]}
    assert st["windows.llmnr"] == st["defender.pua"] == st["windows.process_audit"] == "needs_admin"
    # only the HKCU-only action needs no elevation: it is applied (and journalled), nothing else changes
    assert st["windows.file_extensions"] == "applied" and out["ok"] and out["changed"]
    assert fw.reg.get("HKCU", EXPLORER_ADV, "HideFileExt") == 0
    assert fw.reg.get("HKLM", LLMNR_KEY, "EnableMulticast") is None
    assert snapshot(fw)[1:] == before[1:]
    # when EVERYTHING needs elevation the run is reported as failed, never as a quiet success
    only_admin = harden.apply(["windows.llmnr", "defender.pua"], cfg, env=fw.env())
    assert only_admin["ok"] is False and not only_admin["changed"] and only_admin["journal"] is None


def test_never_downgrades_and_respects_explicit_disables(win, cfg):
    block, audit, off = ("9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c",
                         "d4f940ab-401b-4efc-aadc-ad5f3c50688a")
    win.defender.asr_state.update({block: asr.MODE_ENABLED, audit: asr.MODE_AUDIT, off: asr.MODE_DISABLED})
    win.defender.pref["MAPSReporting"] = 1  # Basic cloud protection is left alone
    harden.apply(harden.plan("recommended", env=win.env()), cfg, env=win.env())
    assert win.defender.asr_state[block] == asr.MODE_ENABLED  # audit target does not downgrade block
    assert win.defender.asr_state[audit] == asr.MODE_AUDIT
    assert win.defender.asr_state[off] == asr.MODE_DISABLED  # an admin turned it off on purpose
    assert win.defender.pref["MAPSReporting"] == 1
    detail = by_id(harden.plan("recommended", env=win.env()))["defender.asr"].detail
    assert "explicitly disabled rule(s) left alone" in detail or "already at or above" in detail


def test_asr_option_modes(win, cfg):
    items = by_id(harden.plan("recommended", options={"asr_mode": "Enabled", "asr_set": "all"}, env=win.env()))
    modes = items["defender.asr"].params["modes"]
    assert set(modes.values()) == {1} and set(modes) == set(asr.CLIENT_GUIDS) and len(modes) == 18
    warn = by_id(harden.plan("recommended", options={"asr_mode": "Warn"}, env=win.env()))["defender.asr"].params["modes"]
    assert warn["9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"] == asr.MODE_ENABLED  # LSASS rule has no warn mode
    assert warn["7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"] == asr.MODE_WARN
    junk = by_id(harden.plan("recommended", options={"asr_mode": "banana"}, env=win.env()))["defender.asr"].params["modes"]
    assert set(junk.values()) == {asr.MODE_AUDIT}


def test_asr_upgrade_works_when_add_does_not_update_existing_rules(monkeypatch, cfg):
    fw = FakeWindows(defender=FakeDefender(add_updates_existing=False)).install(monkeypatch, undo_module=undo)
    g = "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"
    fw.defender.asr_state[g] = asr.MODE_AUDIT
    out = harden.apply(harden.plan("strict", env=fw.env()), cfg, env=fw.env())
    assert fw.defender.asr_state[g] == asr.MODE_ENABLED, out
    assert any(s.startswith("Set-MpPreference -AttackSurfaceReductionRules_Ids") for s in fw.defender.statements)
    assert len(fw.defender.asr_state) == 13


def test_tamper_protection_is_reported_not_hidden(monkeypatch, cfg):
    fw = FakeWindows(defender=FakeDefender(tamper=True)).install(monkeypatch, undo_module=undo)
    out = harden.apply(harden.plan("custom", only=["defender.pua", "defender.asr"], env=fw.env()), cfg, env=fw.env())
    assert out["ok"] is False
    st = {r["id"]: r for r in out["results"]}
    assert st["defender.pua"]["status"] == "failed" and "did not change" in st["defender.pua"]["message"]
    assert st["defender.asr"]["status"] == "failed"
    doc = json.loads(Path(out["journal"]).read_text())
    assert [e["status"] for e in doc["entries"]] == ["failed", "failed"]


def test_failed_action_is_rolled_back_immediately(win, cfg):
    win.reg.put("HKLM", SMB_KEY, "SMB1", 1)
    win.reg.fail_on = ("windows nt\\dnsclient", "enablemulticast")
    out = harden.apply(["windows.smb1_server", "windows.llmnr"], cfg, env=win.env())
    st = {r["id"]: r for r in out["results"]}
    assert st["windows.smb1_server"]["status"] == "applied" and st["windows.llmnr"]["status"] == "failed"
    assert out["ok"] is False and win.reg.get("HKLM", LLMNR_KEY, "EnableMulticast") is None
    # the multi-value action rolls back what it already wrote
    win.reg.fail_on = ("scriptblocklogging", "enablescriptblocklogging")
    win.reg.put("HKLM", harden._EXPLORER_POL, "NoDriveTypeAutoRun", 7)
    out = harden.apply(["windows.autorun", "windows.ps_scriptblock"], cfg, env=win.env())
    assert win.reg.get("HKLM", harden._EXPLORER_POL, "NoDriveTypeAutoRun") == 255  # separate action: kept
    assert win.reg.get("HKLM", SBL_KEY, "EnableScriptBlockLogging") is None


def test_nothing_is_changed_when_the_undo_journal_cannot_be_written(win, cfg, monkeypatch):
    def full_disk(*a, **k):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(harden, "write_json_atomic", full_disk)
    before = snapshot(win)
    out = harden.apply(["windows.llmnr", "defender.pua"], cfg, env=win.env())
    assert out["ok"] is False and not out["changed"]
    assert all(r["status"] == "failed" and "nothing was changed" in r["message"] for r in out["results"])
    assert snapshot(win) == before


def test_a_journal_update_failure_after_the_change_does_not_abort_the_run(win, cfg, monkeypatch):
    real = harden.write_json_atomic
    calls = {"n": 0}

    def flaky(path, payload):
        calls["n"] += 1
        if calls["n"] == 2:  # the "pending" snapshot was written; the post-change update fails
            raise OSError(28, "No space left on device")
        return real(path, payload)

    monkeypatch.setattr(harden, "write_json_atomic", flaky)
    out = harden.apply(["windows.llmnr", "windows.autorun"], cfg, env=win.env())
    assert [r["status"] for r in out["results"]] == ["applied", "applied"]
    assert win.reg.get("HKLM", LLMNR_KEY, "EnableMulticast") == 0
    monkeypatch.setattr(harden, "write_json_atomic", real)
    assert undo.undo(cfg, "latest")["ok"] and win.reg.get("HKLM", LLMNR_KEY, "EnableMulticast") is None


def test_multi_value_action_rolls_back_the_values_it_already_wrote(win, cfg):
    win.reg.subkey_map[("HKLM", r"software\microsoft\office")] = ["16.0"]
    win.reg.fail_on = (r"office\16.0\excel", "blockcontentexecutionfrominternet")  # word succeeds, excel fails
    out = harden.apply(["office.macro_internet"], cfg, env=win.env())
    assert out["ok"] is False and out["results"][0]["status"] == "failed"
    assert "rolled back" in out["results"][0]["message"]
    for app in ("word", "excel", "powerpoint"):
        assert win.reg.get("HKCU", rf"Software\Policies\Microsoft\Office\16.0\{app}\security", "blockcontentexecutionfrominternet") is None


def test_journal_exists_before_the_first_change_even_if_the_process_dies(win, cfg, monkeypatch):
    def die(*a, **k):
        raise KeyboardInterrupt  # not an Exception: simulates the process being killed mid-change

    monkeypatch.setattr(harden, "reg_set_value", die)
    with pytest.raises(KeyboardInterrupt):
        harden.apply(["windows.llmnr"], cfg, env=win.env())
    (journal,) = cfg.backups_dir.glob("harden-*.json")
    doc = json.loads(journal.read_text())
    assert doc["entries"][0]["status"] == "pending" and doc["entries"][0]["ops"][0]["existed"] is False
    win.reg.put("HKLM", LLMNR_KEY, "EnableMulticast", 0)  # pretend the write happened before the crash
    res = undo.undo(cfg, journal.stem)
    assert res["ok"] and win.reg.get("HKLM", LLMNR_KEY, "EnableMulticast") is None


def test_revert_refuses_tampered_journal_entries(win):
    win.reg.put("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Evil", "calc.exe")
    ok, msg = harden.revert_op({"type": "registry", "hive": "HKLM", "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                                "value": "Evil", "existed": True, "data": "calc.exe"})
    assert not ok and "not a setting Aegis hardening changes" in msg
    assert harden.revert_op({"type": "registry", "hive": "HKXX", "key": "k", "value": "v"})[0] is False
    assert harden.revert_op({"type": "mp_pref", "name": "DisableAntiSpyware", "previous": 1})[0] is False
    assert harden.revert_op({"type": "mp_pref", "name": "PUAProtection", "previous": 99})[0] is False
    assert harden.revert_op({"type": "mp_asr", "rules": {"00000000-0000-0000-0000-000000000000": None}})[0] is False
    assert harden.revert_op({"type": "auditpol", "guid": "{0CCE9215-69AE-11D9-BED3-505054503030}", "previous": 0})[0] is False
    assert harden.revert_op({"type": "file", "path": "/etc/passwd", "existed": False})[0] is False
    assert harden.revert_op({"type": "file_lines", "path": "/etc/shadow", "edits": []})[0] is False
    assert harden.revert_op({"type": "sysctl", "key": "kernel.core_pattern", "previous": "1"})[0] is False
    assert harden.revert_op({"type": "run", "argv": ["calc.exe"]})[0] is False  # journals never carry commands
    assert win.reg.get("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Evil") == "calc.exe"


def test_asr_revert_retries_remove_with_actions_when_the_build_demands_it(win, cfg, monkeypatch):
    real = win.defender.run_script

    def picky(script, timeout=90):
        if "Remove-MpPreference" in script and "_Actions" not in script:
            return 1, "", "Parameter set cannot be resolved using the specified named parameters"
        return real(script, timeout)

    monkeypatch.setattr(harden, "powershell", picky)
    harden.apply(["defender.asr"], cfg, env=win.env())
    assert len(win.defender.asr_state) == 13
    assert undo.undo(cfg, "latest")["ok"] and win.defender.asr_state == {}
    assert any(st.startswith("Remove-MpPreference") and "_Actions" in st for st in win.defender.statements)


def test_asr_commands_only_accept_known_guids():
    with pytest.raises(ValueError):
        harden._asr_cmd("Add-MpPreference", {"1; calc": 1})
    cmd = harden._asr_cmd("Add-MpPreference", {"7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c": 2, "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2": 1})
    assert cmd == ("Add-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c,"
                   "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions AuditMode,Enabled")
    assert "Actions" not in harden._asr_cmd("Remove-MpPreference", {"7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c": 0})
    assert harden._asr_cmd("Remove-MpPreference", {"7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c": 0}, with_actions=True).endswith(
        "-AttackSurfaceReductionRules_Actions Disabled")


def test_mp_statements():
    assert harden._mp_statement("DisableRealtimeMonitoring", False) == "Set-MpPreference -DisableRealtimeMonitoring $false"
    assert harden._mp_statement("EnableNetworkProtection", 1) == "Set-MpPreference -EnableNetworkProtection Enabled"
    assert harden._mp_statement("EnableControlledFolderAccess", 2) == "Set-MpPreference -EnableControlledFolderAccess AuditMode"
    assert harden._mp_statement("MAPSReporting", 2) == "Set-MpPreference -MAPSReporting Advanced"
    assert harden._mp_statement("PUAProtection", 7) is None and harden._mp_statement("Bogus", 1) is None


def test_firewall_apply_and_undo(win, cfg):
    sub = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
    for p in ("DomainProfile", "PublicProfile"):
        win.reg.put("HKLM", f"{sub}\\{p}", "EnableFirewall", 0)
    win.reg.put("HKLM", sub + r"\StandardProfile", "EnableFirewall", 1)
    out = harden.apply(["windows.firewall"], cfg, env=win.env())
    assert out["ok"] and ["netsh", "advfirewall", "set", "domainprofile", "state", "on"] in win.calls
    assert all(win.reg.get("HKLM", f"{sub}\\{p}", "EnableFirewall") == 1 for p in ("DomainProfile", "StandardProfile", "PublicProfile"))
    assert undo.undo(cfg, Path(out["journal"]).stem)["ok"]
    assert win.reg.get("HKLM", f"{sub}\\DomainProfile", "EnableFirewall") == 0
    assert win.reg.get("HKLM", f"{sub}\\StandardProfile", "EnableFirewall") == 1  # was on: untouched
    assert win.reg.get("HKLM", f"{sub}\\PublicProfile", "EnableFirewall") == 0


def test_process_audit_reads_auditpol_numerically(win, cfg):
    item = by_id(harden.plan("custom", only=["windows.process_audit"], env=win.env()))["windows.process_audit"]
    assert item.state == "will_change"
    win.audit[GUID_PROC] = 1
    win.reg.put("HKLM", harden._AUDIT_KEY, harden._CMDLINE_VALUE, 1)
    item = by_id(harden.plan("custom", only=["windows.process_audit"], env=win.env()))["windows.process_audit"]
    assert item.state == "compliant"
    # auditpol unreadable -> never guess
    win.audit.clear()
    item = by_id(harden.plan("custom", only=["windows.process_audit"], env=win.env()))["windows.process_audit"]
    assert item.state == "not_applicable" and "audit policy" in item.detail


def test_file_audit_adds_success_auditing_and_undo_restores_the_policy(win, cfg):
    fs = harden.FILE_SYSTEM_GUID
    win.audit[fs] = 2  # failure-only auditing set by someone else: kept, and restored exactly
    items = harden.plan("custom", only=["windows.file_audit"], env=win.env())
    assert by_id(items)["windows.file_audit"].state == "will_change"
    out = harden.apply(items, cfg, env=win.env(), profile="custom")
    assert out["ok"] and win.audit[fs] == 3
    assert undo.undo(cfg, Path(out["journal"]).stem)["ok"] and win.audit[fs] == 2
    win.audit[fs] = 1
    assert by_id(harden.plan("custom", only=["windows.file_audit"], env=win.env()))["windows.file_audit"].state == "compliant"
    del win.audit[fs]  # auditpol unreadable -> never guess
    item = by_id(harden.plan("custom", only=["windows.file_audit"], env=win.env()))["windows.file_audit"]
    assert item.state == "not_applicable" and "audit policy" in item.detail
    ok, msg = harden.revert_op({"type": "auditpol", "guid": fs, "previous": 0}, dry_run=True)
    assert ok and "File System" in msg


def test_smb1_client_is_left_alone_when_workstation_depends_on_it(win):
    win.reg.put("HKLM", r"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start", 3)
    assert by_id(harden.plan("recommended", env=win.env()))["windows.smb1_client"].state == "will_change"
    win.reg.put("HKLM", r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation", "DependOnService", ["Bowser", "MRxSmb10", "NSI"])
    item = by_id(harden.plan("recommended", env=win.env()))["windows.smb1_client"]
    assert item.state == "not_applicable" and "depends on the SMBv1 driver" in item.detail


# =========================================================================== Linux
class FakeLinux:
    def __init__(self, monkeypatch, files=None, tools=("ufw", "sysctl", "sshd", "systemctl"), admin=True):
        self.fs = dict(files or {})
        self.tools = set(tools)
        self.calls = []
        self.sshd_ok = True
        self.ufw_rules = []
        monkeypatch.setattr(harden, "IS_WINDOWS", False)
        monkeypatch.setattr(harden, "IS_MAC", False)
        monkeypatch.setattr(harden, "is_admin", lambda: admin)
        monkeypatch.setattr(harden, "_read_text", lambda p, limit=0: self.fs.get(p))
        monkeypatch.setattr(harden, "_write_file", lambda p, t, mode=0o644: self.fs.__setitem__(p, t))
        monkeypatch.setattr(harden, "_delete_file", lambda p: self.fs.pop(p, None))
        monkeypatch.setattr(harden, "_which", lambda n: f"/usr/sbin/{n}" if n in self.tools else None)
        monkeypatch.setattr(harden, "run", self.run)
        monkeypatch.setattr(harden.glob, "glob", lambda pat: [])
        monkeypatch.setattr(undo, "is_admin", lambda: admin)

    def run(self, argv, timeout=60, input_text=None):
        argv = list(argv)
        self.calls.append(argv)
        if argv[:3] == ["ufw", "show", "added"]:
            return 0, "Added user rules (see 'ufw status' for running firewall):\n" + "".join(f"ufw allow {r}\n" for r in self.ufw_rules), ""
        if argv[:2] == ["ufw", "allow"]:
            self.ufw_rules.append(argv[2])
        elif argv[:3] == ["ufw", "delete", "allow"]:
            self.ufw_rules.remove(argv[3])
        elif argv[:3] == ["ufw", "--force", "enable"]:
            self.fs["/etc/ufw/ufw.conf"] = "ENABLED=yes\n"
        elif argv[:2] == ["ufw", "disable"]:
            self.fs["/etc/ufw/ufw.conf"] = "ENABLED=no\n"
        elif argv[:2] == ["sysctl", "-w"]:
            self.fs["/proc/sys/kernel/randomize_va_space"] = argv[2].split("=")[1] + "\n"
        elif argv[-1] == "-t" and argv[0].endswith("sshd"):
            return (0 if self.sshd_ok else 1), "", "bad config" if not self.sshd_ok else ""
        return 0, "", ""


SSHD = "Include /etc/ssh/sshd_config.d/*.conf\r\n# comment\nPort 2222\nPermitRootLogin yes\nPasswordAuthentication yes\n"
PASSWD = "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\nsvc:x:998:998::/:/usr/sbin/nologin\n"
GROUP = "sudo:x:27:alice\nusers:x:100:\n"


def test_linux_aslr_round_trip(monkeypatch, cfg):
    lx = FakeLinux(monkeypatch, {"/proc/sys/kernel/randomize_va_space": "0\n"})
    item = by_id(harden.plan("recommended", env=harden.HardenEnv()))["linux.aslr"]
    assert item.state == "will_change"
    out = harden.apply(harden.plan("recommended", env=harden.HardenEnv()), cfg, env=harden.HardenEnv())
    assert out["ok"] and lx.fs["/proc/sys/kernel/randomize_va_space"] == "2\n"
    assert "randomize_va_space = 2" in lx.fs[harden.SYSCTL_CONF]
    res = undo.undo(cfg, "latest")
    assert res["ok"], res
    assert lx.fs["/proc/sys/kernel/randomize_va_space"] == "0\n" and harden.SYSCTL_CONF not in lx.fs
    assert harden.plan("custom", only=["linux.aslr"], env=harden.HardenEnv())[0].state == "will_change"


def test_linux_aslr_already_on(monkeypatch):
    FakeLinux(monkeypatch, {"/proc/sys/kernel/randomize_va_space": "2\n"})
    assert by_id(harden.plan("recommended", env=harden.HardenEnv()))["linux.aslr"].state == "compliant"


def test_linux_ssh_root_login_round_trip(monkeypatch, cfg):
    lx = FakeLinux(monkeypatch, {"/etc/ssh/sshd_config": SSHD, "/etc/passwd": PASSWD, "/etc/group": GROUP})
    item = by_id(harden.plan("recommended", env=harden.HardenEnv()))["linux.ssh_root_login"]
    assert item.state == "will_change"
    out = harden.apply(["linux.ssh_root_login"], cfg, env=harden.HardenEnv())
    assert out["ok"], out
    new = lx.fs["/etc/ssh/sshd_config"]
    assert "PermitRootLogin no\n" in new and "PermitRootLogin yes" not in new
    assert new.replace("PermitRootLogin no", "PermitRootLogin yes") == SSHD  # nothing else touched (CRLF line kept)
    assert ["systemctl", "reload", "ssh"] in lx.calls
    assert by_id(harden.plan("recommended", env=harden.HardenEnv()))["linux.ssh_root_login"].state == "compliant"
    assert undo.undo(cfg, "latest")["ok"]
    assert lx.fs["/etc/ssh/sshd_config"] == SSHD


def test_linux_ssh_root_login_guards(monkeypatch, cfg):
    # no sudo-capable non-root user -> never risk a lock-out
    FakeLinux(monkeypatch, {"/etc/ssh/sshd_config": SSHD, "/etc/passwd": PASSWD, "/etc/group": "sudo:x:27:\n"})
    item = by_id(harden.plan("recommended", env=harden.HardenEnv()))["linux.ssh_root_login"]
    assert item.state == "not_applicable" and "lock you out" in item.detail
    # no sshd at all
    FakeLinux(monkeypatch, {})
    assert by_id(harden.plan("recommended", env=harden.HardenEnv()))["linux.ssh_root_login"].state == "not_applicable"
    # already safe
    FakeLinux(monkeypatch, {"/etc/ssh/sshd_config": "PermitRootLogin prohibit-password\n", "/etc/passwd": PASSWD, "/etc/group": GROUP})
    assert by_id(harden.plan("recommended", env=harden.HardenEnv()))["linux.ssh_root_login"].state == "compliant"
    # root login enabled in an included file: Aegis edits only the main config -> not applicable
    lx = FakeLinux(monkeypatch, {"/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\n", "/etc/passwd": PASSWD,
                                 "/etc/group": GROUP, "/etc/ssh/sshd_config.d/50.conf": "PermitRootLogin yes\n"})
    monkeypatch.setattr(harden.glob, "glob", lambda pat: ["/etc/ssh/sshd_config.d/50.conf"])
    item = by_id(harden.plan("recommended", env=harden.HardenEnv()))["linux.ssh_root_login"]
    assert item.state == "not_applicable" and "included file" in item.detail
    assert lx.fs["/etc/ssh/sshd_config"] == "Include /etc/ssh/sshd_config.d/*.conf\n"


def test_linux_ssh_change_is_restored_when_sshd_rejects_it(monkeypatch, cfg):
    lx = FakeLinux(monkeypatch, {"/etc/ssh/sshd_config": SSHD, "/etc/passwd": PASSWD, "/etc/group": GROUP})
    lx.sshd_ok = False
    out = harden.apply(["linux.ssh_root_login"], cfg, env=harden.HardenEnv())
    assert out["ok"] is False and "restored" in out["results"][0]["message"]
    assert lx.fs["/etc/ssh/sshd_config"] == SSHD


def test_linux_ufw_keeps_ssh_open_and_undoes_cleanly(monkeypatch, cfg):
    lx = FakeLinux(monkeypatch, {"/etc/ufw/ufw.conf": "ENABLED=no\n", "/etc/ssh/sshd_config": "Port 2222\n"})
    item = by_id(harden.plan("recommended", env=harden.HardenEnv()))["linux.ufw"]
    assert item.state == "will_change" and "2222" in item.detail
    out = harden.apply(["linux.ufw"], cfg, env=harden.HardenEnv())
    assert out["ok"] and lx.ufw_rules == ["2222/tcp"] and lx.fs["/etc/ufw/ufw.conf"] == "ENABLED=yes\n"
    assert lx.calls.index(["ufw", "allow", "2222/tcp"]) < lx.calls.index(["ufw", "--force", "enable"])  # SSH first
    assert by_id(harden.plan("recommended", env=harden.HardenEnv()))["linux.ufw"].state == "compliant"
    assert undo.undo(cfg, "latest")["ok"]
    assert lx.ufw_rules == [] and lx.fs["/etc/ufw/ufw.conf"] == "ENABLED=no\n"


def test_linux_ufw_does_not_delete_a_rule_the_user_already_had(monkeypatch, cfg):
    lx = FakeLinux(monkeypatch, {"/etc/ufw/ufw.conf": "ENABLED=no\n", "/etc/ssh/sshd_config": "# defaults\n"})
    lx.ufw_rules = ["22/tcp"]
    harden.apply(["linux.ufw"], cfg, env=harden.HardenEnv())
    assert ["ufw", "allow", "22/tcp"] not in lx.calls
    undo.undo(cfg, "latest")
    assert lx.ufw_rules == ["22/tcp"]  # the user's own rule survives the undo


def test_linux_ufw_missing_is_not_applicable(monkeypatch):
    FakeLinux(monkeypatch, {}, tools=())
    item = by_id(harden.plan("recommended", env=harden.HardenEnv()))["linux.ufw"]
    assert item.state == "not_applicable" and "not installed" in item.detail


def test_linux_actions_need_root(monkeypatch, cfg):
    FakeLinux(monkeypatch, {"/proc/sys/kernel/randomize_va_space": "0\n"}, admin=False)
    item = by_id(harden.plan("recommended", env=harden.HardenEnv()))["linux.aslr"]
    assert item.state == "needs_admin"
    out = harden.apply(["linux.aslr"], cfg, env=harden.HardenEnv())
    assert out["ok"] is False and "administrator" in out["message"].lower()


# =========================================================================== macOS
def test_macos_actions_round_trip(monkeypatch, cfg):
    state = {"fw": 0, "gk": False}

    def run(argv, timeout=60, input_text=None):
        argv = list(argv)
        if argv[0].endswith("socketfilterfw"):
            if argv[1] == "--setglobalstate":
                state["fw"] = 1 if argv[2] == "on" else 0
                return 0, "", ""
            return 0, f"Firewall is {'enabled' if state['fw'] else 'disabled'}. (State = {state['fw']})\n", ""
        if argv[0] == "spctl":
            if argv[1] == "--status":
                return 0, "assessments " + ("enabled" if state["gk"] else "disabled") + "\n", ""
            state["gk"] = argv[1] == "--master-enable"
            return 0, "", ""
        return 0, "", ""

    monkeypatch.setattr(harden, "IS_WINDOWS", False)
    monkeypatch.setattr(harden, "IS_MAC", True)
    monkeypatch.setattr(harden, "is_admin", lambda: True)
    monkeypatch.setattr(undo, "is_admin", lambda: True)
    monkeypatch.setattr(harden, "run", run)
    items = by_id(harden.plan("recommended", env=harden.HardenEnv()))
    assert set(items) == {"macos.firewall", "macos.gatekeeper"} and all(i.state == "will_change" for i in items.values())
    out = harden.apply(list(items.values()), cfg, env=harden.HardenEnv())
    assert out["ok"] and state == {"fw": 1, "gk": True}
    assert undo.undo(cfg, "latest")["ok"]
    assert state == {"fw": 0, "gk": False}


# =========================================================================== ASR audit (system_audit) + remediation
TODAY = dt.date(2026, 10, 16)


def audit_env(asr_state=None, third_party=False, with_keys=True):
    pref = {"ExclusionPath": [], "PUAProtection": 1, "EnableControlledFolderAccess": 0, "MAPSReporting": 2}
    if with_keys:
        pref["AttackSurfaceReductionRules_Ids"] = list(asr_state or {})
        pref["AttackSurfaceReductionRules_Actions"] = list((asr_state or {}).values())
    av = [{"name": "Windows Defender", "state": 0x061100}]
    if third_party:
        av = [{"name": "Contoso AV", "state": 0x061100}]
    mp = {"AMServiceEnabled": True, "AntivirusEnabled": True, "RealTimeProtectionEnabled": True, "AMRunningMode": "Normal"}
    return sa.AuditEnv(today=TODAY, facts={"av": av, "mp": mp, "pref": pref})


def test_asr_audit_none_configured_is_one_low_finding_with_a_harden_remediation():
    checks = sa.check_asr(audit_env({}))
    assert [c.key for c in checks] == ["ASR-RULES"]
    c = checks[0]
    assert c.ok is False and c.severity == Severity.LOW and c.status == "warn"
    f = c.to_finding()
    assert f.rule_id == "AEG-AUDIT-ASR-RULES" and f.recommendation and f.location and f.category == "system"
    assert f.remediation.action == "harden" and f.remediation.params == {"ids": ["defender.asr"], "asr_mode": "AuditMode"}
    assert "aegis harden" in f.recommendation
    assert not any(t.startswith("T1562") for t in f.mitre)
    json.dumps(f.to_dict())


def test_asr_audit_counts_block_warn_and_audit_separately():
    state = {g: asr.MODE_AUDIT for g in asr.CONSUMER_GUIDS}
    state["56a863a9-875e-4185-98a7-b882c64b5ce5"] = asr.MODE_ENABLED
    state["d1e49aac-8f56-4280-b9ba-993a6d77406c"] = asr.MODE_DISABLED
    checks = {c.key: c for c in sa.check_asr(audit_env(state))}
    assert checks["ASR-VULNERABLE-DRIVERS"].ok is True and checks["ASR-VULNERABLE-DRIVERS"].to_finding() is None
    assert checks["ASR-PSEXEC-WMI"].ok is False and checks["ASR-PSEXEC-WMI"].to_finding() is None  # rows never create findings
    assert "ASR-ADOBE-CHILD" not in checks  # audit-mode and unconfigured rules are only counted in the aggregate
    agg = checks["ASR-RULES"]
    f = agg.to_finding()
    assert f.evidence["enabled"] == 1 and len(f.evidence["audit"]) == 12
    assert f.remediation.params["asr_mode"] == "Enabled"  # audit data exists: next step is to block


def test_asr_audit_passes_with_enough_rules_blocking():
    state = {g: asr.MODE_ENABLED for g in asr.CONSUMER_GUIDS[:sa.ASR_MIN_ENABLED]}
    checks = sa.check_asr(audit_env(state))
    agg = next(c for c in checks if c.key == "ASR-RULES")
    assert agg.ok is True and agg.status == "pass" and agg.to_finding() is None
    assert len([c for c in checks if c.key != "ASR-RULES"]) == sa.ASR_MIN_ENABLED


def test_asr_audit_skips_when_defender_is_not_primary_or_keys_missing():
    third = sa.check_asr(audit_env({}, third_party=True))
    assert third[0].ok is None and "not the active antivirus" in third[0].detail
    old = sa.check_asr(audit_env(with_keys=False))
    assert old[0].ok is None and "not reported" in old[0].detail
    assert sa.check_asr(sa.AuditEnv(today=TODAY, facts={}))[0].ok is None


def test_asr_audit_is_part_of_the_windows_run_and_batched_call():
    assert sa.check_asr in sa.WINDOWS_CHECKS
    assert "AttackSurfaceReductionRules_Ids" in sa._PS_FACTS and "AttackSurfaceReductionRules_Actions" in sa._PS_FACTS
    assert "EnableNetworkProtection" in sa._PS_FACTS
    items = list(sa.run_checks(audit_env({}), [sa.check_asr]))
    assert {type(i).__name__ for i in items} == {"CheckResult", "Finding"}


def test_remediation_harden_action_applies_and_is_undoable(win, cfg):
    from aegis.core.remediation import ACTIONS, WINDOWS_ONLY, apply_remediation

    assert "harden" in ACTIONS and "harden" not in WINDOWS_ONLY
    f = Finding("AEG-AUDIT-ASR-RULES", "t", Severity.LOW, "system",
                remediation=Remediation("harden", {"ids": ["defender.asr", "windows.llmnr"], "asr_mode": "AuditMode"}))
    ok, msg = apply_remediation(f, cfg)
    assert ok, msg
    assert len(win.defender.asr_state) == 13 and set(win.defender.asr_state.values()) == {asr.MODE_AUDIT}
    assert win.reg.get("HKLM", LLMNR_KEY, "EnableMulticast") == 0
    assert "aegis undo" in msg
    assert undo.undo(cfg, "latest")["ok"] and win.defender.asr_state == {}
    # no ids / unknown ids / not admin are explicit failures, never silent successes
    assert apply_remediation(Finding("X", "t", Severity.LOW, "x", remediation=Remediation("harden", {})), cfg)[0] is False
    win.admin = False
    ok, msg = apply_remediation(f, cfg)
    assert ok is False and "administrator" in msg.lower()


def test_ids_in_remediation_cover_real_catalogue_entries():
    f = sa.check_asr(audit_env({}))[0].to_finding()
    assert all(i in harden.ACTIONS_BY_ID for i in f.remediation.params["ids"])
    assert re.fullmatch(r"AEG-AUDIT-[A-Z0-9-]+", f.rule_id)
