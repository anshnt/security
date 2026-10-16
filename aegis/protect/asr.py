"""Microsoft Defender Attack Surface Reduction (ASR) rule table.

Every GUID and name below was checked against Microsoft's reference page
(https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference,
page "Last updated on 2026-09-09", fetched 2026-10-16) by extracting each rule's "GUID" field and its
"Microsoft Intune name" from the page source. Names are the Intune names (the current official ones);
where the Configuration Manager name differs it is not used. Rules are only listed when Microsoft
documents a GUID for them - nothing here comes from memory or third-party lists.

Mode values accepted by ``Add-/Set-/Remove-MpPreference -AttackSurfaceReductionRules_Actions``
(page "Enable attack surface reduction rules"): 0/Disabled, 1/Enabled (Block), 2/AuditMode,
5/NotConfigured, 6/Warn.

Tiers (Aegis' own judgement about false-positive risk on a home PC, not Microsoft terminology
except "standard", which mirrors Microsoft's "Standard protection rules" group):
  standard  - Microsoft's "Standard protection rules"; low impact, recommended everywhere
  consumer  - rules that rarely affect home software; part of the default Aegis set
  advanced  - noticeable false-positive risk (blocks unknown/unsigned software, admin tools); opt-in
  server    - Exchange-server-only rule; never applied to PCs
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence

ASR_SOURCE_URL = "https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference"
ASR_VERIFIED_ON = "2026-10-16"

GUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

# Action values as documented for AttackSurfaceReductionRules_Actions.
MODE_DISABLED, MODE_ENABLED, MODE_AUDIT, MODE_NOT_CONFIGURED, MODE_WARN = 0, 1, 2, 5, 6
MODE_NAMES: Dict[int, str] = {0: "Disabled", 1: "Enabled", 2: "AuditMode", 5: "NotConfigured", 6: "Warn"}
MODE_VALUES: Dict[str, int] = {v.lower(): k for k, v in MODE_NAMES.items()}
MODE_VALUES.update({"block": 1, "audit": 2})  # friendly aliases used by the CLI

# How strongly a mode protects; used so Aegis never *downgrades* an existing stronger setting.
_STRENGTH = {None: 0, 0: 0, 5: 0, 2: 1, 6: 2, 1: 3}


def mode_strength(mode: Optional[int]) -> int:
    return _STRENGTH.get(mode, 0)


def parse_mode(value: Any) -> Optional[int]:
    """'Enabled' / 'block' / 1 / '2' -> documented int, or None if not a valid ASR action."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value in MODE_NAMES else None
    text = str(value).strip().lower()
    if text.isdigit():
        n = int(text)
        return n if n in MODE_NAMES else None
    return MODE_VALUES.get(text)


@dataclass(frozen=True)
class AsrRule:
    guid: str  # lower-case
    name: str  # Microsoft Intune name
    key: str  # short id for options / docs
    tier: str  # standard | consumer | advanced | server
    warn_supported: bool = True
    effect: str = ""  # what it blocks / side effect worth telling the user


ASR_RULES: List[AsrRule] = [
    AsrRule("56a863a9-875e-4185-98a7-b882c64b5ce5", "Block abuse of exploited vulnerable signed drivers (Device)",
            "vulnerable_drivers", "standard",
            effect="stops apps saving known-vulnerable signed drivers (BYOVD); an old vendor driver installer can fail"),
    AsrRule("9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
            "Block credential stealing from the Windows local security authority subsystem",
            "lsass", "standard", warn_supported=False,
            effect="blocks other processes from reading LSASS memory; produces many harmless audit events"),
    AsrRule("e6db77e5-3df2-4cf1-b95a-636979351e5b", "Block persistence through WMI event subscription",
            "wmi_persistence", "standard",
            effect="blocks WMI event-subscription persistence; avoid on PCs managed by Configuration Manager"),
    AsrRule("7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", "Block Adobe Reader from creating child processes",
            "adobe_child", "consumer", effect="Adobe Reader can no longer launch other programs"),
    AsrRule("d4f940ab-401b-4efc-aadc-ad5f3c50688a", "Block all Office applications from creating child processes",
            "office_child", "consumer",
            effect="Word/Excel/PowerPoint/OneNote/Access cannot launch other programs (breaks macros that run cmd/PowerShell)"),
    AsrRule("be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", "Block executable content from email client and webmail",
            "email_executables", "consumer", effect="executables/scripts/archives opened from mail are blocked"),
    AsrRule("5beb7efe-fd9a-4556-801d-275e5ffc04cc", "Block execution of potentially obfuscated scripts",
            "obfuscated_scripts", "consumer", effect="heavily obfuscated scripts are blocked (rarely, minified legitimate ones)"),
    AsrRule("d3e037e1-3eb8-44c8-a917-57927947596d",
            "Block JavaScript or VBScript from launching downloaded executable content",
            "script_downloaders", "consumer", effect="JS/VBS can no longer download and run programs"),
    AsrRule("3b576869-a4ec-4529-8536-b80a7769e899", "Block Office applications from creating executable content",
            "office_executables", "consumer", effect="Office can no longer write executable files to disk"),
    AsrRule("75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", "Block Office applications from injecting code into other processes",
            "office_injection", "consumer", warn_supported=False,
            effect="Office cannot inject code into other processes; restart Office apps after enabling"),
    AsrRule("26190899-1602-49e8-8b27-eb1d0a1ce869", "Block Office communication application from creating child processes",
            "outlook_child", "consumer", effect="Outlook cannot launch other programs (blocks rules/forms exploits)"),
    AsrRule("92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b", "Block Win32 API calls from Office macros",
            "macro_win32", "consumer", effect="VBA macros cannot call Win32 APIs (breaks some advanced add-ins)"),
    AsrRule("c1db55ab-c21a-4637-bb3f-a12568109d35", "Use advanced protection against ransomware",
            "ransomware", "consumer",
            effect="blocks files without a good cloud reputation that look like ransomware; brand-new unknown "
                   "programs may be blocked once (needs cloud-delivered protection)"),
    # ---- advanced (opt-in)
    AsrRule("01443614-cd74-433a-b99e-2ecdc07bfc25",
            "Block executable files from running unless they meet a prevalence, age, or trusted list criterion",
            "prevalence", "advanced",
            effect="blocks unknown or recent executables - many false positives for games and niche tools "
                   "(needs cloud-delivered protection)"),
    AsrRule("d1e49aac-8f56-4280-b9ba-993a6d77406c", "Block process creations originating from PSExec and WMI commands",
            "psexec_wmi", "advanced", effect="breaks remote administration tools and Configuration Manager"),
    AsrRule("33ddedf1-c6e0-47cb-833e-de6133960387", "Block rebooting machine in Safe Mode",
            "safe_mode", "advanced", effect="bcdedit/bootcfg can no longer reboot into Safe Mode"),
    AsrRule("b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", "Block untrusted and unsigned processes that run from USB",
            "usb_untrusted", "advanced", effect="unsigned portable apps cannot run from USB sticks/SD cards"),
    AsrRule("c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb", "Block use of copied or impersonated system tools",
            "impersonated_tools", "advanced",
            effect="can block legitimate third-party tools that run from unusual locations (heuristic)"),
    # ---- server only
    AsrRule("a8f5898e-1dc8-49a9-9878-85004b8a61e6", "Block Webshell creation for Servers",
            "webshell", "server", effect="Exchange servers only"),
]

RULES_BY_GUID: Dict[str, AsrRule] = {r.guid: r for r in ASR_RULES}
RULES_BY_KEY: Dict[str, AsrRule] = {r.key: r for r in ASR_RULES}

STANDARD_GUIDS: List[str] = [r.guid for r in ASR_RULES if r.tier == "standard"]
CONSUMER_GUIDS: List[str] = [r.guid for r in ASR_RULES if r.tier in ("standard", "consumer")]
CLIENT_GUIDS: List[str] = [r.guid for r in ASR_RULES if r.tier != "server"]


def norm_guid(value: Any) -> str:
    return str(value or "").strip().strip("{}").lower()


def resolve_rules(spec: Any) -> List[str]:
    """Turn 'consumer' | 'all' | 'standard' | a list of GUIDs/short keys into a list of known GUIDs."""
    if spec in (None, "", "consumer"):
        return list(CONSUMER_GUIDS)
    if spec == "standard":
        return list(STANDARD_GUIDS)
    if spec in ("all", "all-client"):
        return list(CLIENT_GUIDS)
    items: Iterable[Any] = [spec] if isinstance(spec, str) else spec
    out: List[str] = []
    for item in items:
        g = norm_guid(item)
        rule = RULES_BY_GUID.get(g) or RULES_BY_KEY.get(str(item).strip().lower())
        if rule and rule.guid not in out:
            out.append(rule.guid)
    return out


def parse_asr_state(ids: Any, actions: Any) -> Dict[str, int]:
    """Pair ``AttackSurfaceReductionRules_Ids`` with ``_Actions`` (same index) -> {guid: action}.
    Tolerates a single value instead of a list, mismatched lengths and junk."""
    def as_list(v: Any) -> List[Any]:
        if v is None:
            return []
        return list(v) if isinstance(v, (list, tuple)) else [v]

    out: Dict[str, int] = {}
    for guid, action in zip(as_list(ids), as_list(actions)):
        g = norm_guid(guid)
        if not GUID_RE.match(g):
            continue
        try:
            out[g] = int(action)
        except (TypeError, ValueError):
            continue
    return out


def summarize_asr(state: Dict[str, int], guids: Optional[Sequence[str]] = None) -> Dict[str, Any]:
    """Counts and names for reporting. ``guids`` limits the view (default: every client rule)."""
    scope = list(guids) if guids is not None else list(CLIENT_GUIDS)
    blocking, warn, audit, disabled, unset = [], [], [], [], []
    for g in scope:
        mode = state.get(g)
        name = RULES_BY_GUID[g].name if g in RULES_BY_GUID else g
        if mode == MODE_ENABLED:
            blocking.append(name)
        elif mode == MODE_WARN:
            warn.append(name)
        elif mode == MODE_AUDIT:
            audit.append(name)
        elif mode == MODE_DISABLED:
            disabled.append(name)
        else:
            unset.append(name)
    return {"enabled": len(blocking) + len(warn), "block": blocking, "warn": warn, "audit": audit,
            "disabled": disabled, "not_configured": unset, "total": len(scope)}
