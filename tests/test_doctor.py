"""Self-check ("doctor"): ACL parsing and exposure rules (hand-written icacls / Get-Acl samples), the safe-ACL fix,
signature freshness, heartbeat, services, antivirus, disk, history and alert checks. Windows-only behaviour is driven
through mocks (monkeypatching the module's IS_WINDOWS / run / powershell_json), so everything runs on Linux and Windows."""

from __future__ import annotations

import datetime as dt
import json
import os
import stat
import sys
import time
from collections import namedtuple
from pathlib import Path
from types import SimpleNamespace
from typing import List, Tuple

import pytest

from aegis.core import doctor as D
from aegis.core.config import Config
from aegis.core.models import CheckStatus, Finding, ScanResult, Severity

posix_only = pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX permission bits")


@pytest.fixture
def cfg():
    return Config()


@pytest.fixture(autouse=True)
def no_shared_signatures(monkeypatch):
    monkeypatch.setattr("aegis.core.config.shared_signatures_dir", lambda: None)


def status_of(check) -> str:
    return check.status


# --------------------------------------------------------------------------- icacls samples (written by hand)

# A config.json inside %ProgramData%\Aegis with Windows' default inheritance: Users may only read.
ICACLS_CONFIG_OK = r"""C:\ProgramData\Aegis\config.json NT AUTHORITY\SYSTEM:(I)(F)
                                 BUILTIN\Administrators:(I)(F)
                                 BUILTIN\Users:(I)(RX)

Successfully processed 1 files; Failed processing 0 files
"""

# The signatures folder as created under %ProgramData%: the parent's "(CI)(WD,AD,WEA,WA)" lets Users create files.
ICACLS_SIGNATURES_DEFAULT = r"""C:\ProgramData\Aegis\signatures NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
                                BUILTIN\Administrators:(I)(OI)(CI)(F)
                                BUILTIN\Users:(I)(OI)(CI)(RX)
                                BUILTIN\Users:(I)(CI)(WD,AD,WEA,WA)
                                CREATOR OWNER:(I)(OI)(CI)(IO)(F)

Successfully processed 1 files; Failed processing 0 files
"""

# A data folder created directly under C:\ : Authenticated Users get Modify. Anyone can edit the allow-list.
ICACLS_CDRIVE_FOLDER = r"""C:\Aegis BUILTIN\Administrators:(I)(OI)(CI)(F)
         NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
         BUILTIN\Users:(I)(OI)(CI)(RX)
         NT AUTHORITY\Authenticated Users:(I)(OI)(CI)(M)

Successfully processed 1 files; Failed processing 0 files
"""

ICACLS_EVERYONE_FULL = r"""D:\Tools\Aegis\config.json Everyone:(F)
                           BUILTIN\Administrators:(F)

Successfully processed 1 files; Failed processing 0 files
"""

# DENY for Users does not help against a separate "Authenticated Users" grant.
ICACLS_DENY_ONE_GROUP_ONLY = r"""C:\ProgramData\Aegis\config.json BUILTIN\Users:(DENY)(W)
                                 NT AUTHORITY\Authenticated Users:(I)(M)
                                 NT AUTHORITY\SYSTEM:(I)(F)

Successfully processed 1 files; Failed processing 0 files
"""

# DENY of the very principal that is granted write cancels it.
ICACLS_DENY_CANCELS = r"""C:\ProgramData\Aegis\config.json Everyone:(DENY)(W)
                                 Everyone:(I)(M)
                                 NT AUTHORITY\SYSTEM:(I)(F)

Successfully processed 1 files; Failed processing 0 files
"""

ICACLS_SPACES_IN_PATH = r"""C:\Program Files\Aegis\config.json NT AUTHORITY\SYSTEM:(I)(F)
                                   BUILTIN\Administrators:(I)(F)
                                   BUILTIN\Users:(I)(M)
                                   CONTOSO\Domain Users:(I)(WD,AD)

Successfully processed 1 files; Failed processing 0 files
"""

# German Windows: principal names are localised, so they cannot be mapped to SIDs (best effort: not flagged).
ICACLS_GERMAN = r"""C:\ProgramData\Aegis\config.json NT-AUTORITÄT\SYSTEM:(I)(F)
                                 VORDEFINIERT\Administratoren:(I)(F)
                                 VORDEFINIERT\Benutzer:(I)(M)

Successfully processed 1 files; Failed processing 0 files
"""


def test_parse_icacls_locked_down_file():
    entries = D.parse_icacls(ICACLS_CONFIG_OK, r"C:\ProgramData\Aegis\config.json")
    assert [e.who for e in entries] == ["NT AUTHORITY\\SYSTEM", "BUILTIN\\Administrators", "BUILTIN\\Users"]
    assert [e.write for e in entries] == [True, True, False]
    assert entries[2].sid == "S-1-5-32-545" and entries[2].standard_user and entries[0].sid == "S-1-5-18"
    assert D.write_exposure(entries) == []


def test_parse_icacls_default_programdata_inheritance_allows_creating_files_in_subfolders():
    entries = D.parse_icacls(ICACLS_SIGNATURES_DEFAULT, r"C:\ProgramData\Aegis\signatures")
    assert len(entries) == 5
    create = [e for e in entries if e.who == "BUILTIN\\Users" and e.write]
    assert len(create) == 1 and not create[0].strong  # create/append only
    owner = [e for e in entries if e.who == "CREATOR OWNER"][0]
    assert owner.inherit_only and owner.strong
    assert D.write_exposure(entries) == ["BUILTIN\\Users"]  # a user can plant files in signatures\
    assert D.write_exposure(entries, strong_only=True) == []  # ... but cannot replace or delete existing ones


def test_parse_icacls_authenticated_users_modify_is_flagged():
    entries = D.parse_icacls(ICACLS_CDRIVE_FOLDER, r"C:\Aegis")
    assert D.write_exposure(entries) == ["NT AUTHORITY\\Authenticated Users"]
    assert D.write_exposure(entries, strong_only=True) == ["NT AUTHORITY\\Authenticated Users"]


def test_parse_icacls_everyone_full_and_unknown_path_prefix():
    entries = D.parse_icacls(ICACLS_EVERYONE_FULL)  # path not passed: the first line is split heuristically
    assert [e.who for e in entries] == ["Everyone", "BUILTIN\\Administrators"]
    assert D.write_exposure(entries) == ["Everyone"]


def test_parse_icacls_deny_entries():
    only_users_denied = D.parse_icacls(ICACLS_DENY_ONE_GROUP_ONLY, r"C:\ProgramData\Aegis\config.json")
    assert [e.allow for e in only_users_denied] == [False, True, True]
    assert D.write_exposure(only_users_denied) == ["NT AUTHORITY\\Authenticated Users"]
    assert D.write_exposure(D.parse_icacls(ICACLS_DENY_CANCELS, r"C:\ProgramData\Aegis\config.json")) == []


def test_parse_icacls_path_with_spaces_and_domain_groups():
    for path in (r"C:\Program Files\Aegis\config.json", ""):
        entries = D.parse_icacls(ICACLS_SPACES_IN_PATH, path)
        assert [e.who for e in entries] == ["NT AUTHORITY\\SYSTEM", "BUILTIN\\Administrators", "BUILTIN\\Users",
                                            "CONTOSO\\Domain Users"], path
        assert D.write_exposure(entries) == ["BUILTIN\\Users", "CONTOSO\\Domain Users"]


def test_parse_icacls_localised_names_are_ignored_not_guessed():
    entries = D.parse_icacls(ICACLS_GERMAN, r"C:\ProgramData\Aegis\config.json")
    assert len(entries) == 3 and entries[2].who == "VORDEFINIERT\\Benutzer" and entries[2].write
    assert D.write_exposure(entries) == []  # unknown principal: no false alarm (the PowerShell/SID path covers this)


def test_parse_icacls_ignores_noise():
    assert D.parse_icacls("") == []
    assert D.parse_icacls("Access is denied.\n") == []
    assert D.parse_icacls("Successfully processed 0 files; Failed processing 1 files\n") == []


# --------------------------------------------------------------------------- Get-Acl JSON (locale independent)

FULL, MODIFY, READ_EXEC, CREATE_ONLY, GENERIC_ALL = 2032127, 1245631, 1179817, 0x2 | 0x4 | 0x10 | 0x100, 0x10000000


def acl_json(*aces) -> List[dict]:
    return [{"sid": sid, "name": name, "type": typ, "rights": rights, "inherit_only": io} for sid, name, typ, rights, io in aces]


def test_parse_acl_json_with_sids():
    entries = D.parse_acl_json(acl_json(
        ("S-1-5-18", "NT AUTHORITY\\SYSTEM", "Allow", FULL, False),
        ("S-1-5-32-544", "BUILTIN\\Administrators", "Allow", FULL, False),
        ("S-1-5-32-545", "VORDEFINIERT\\Benutzer", "Allow", READ_EXEC, False)))  # localised name, SID still works
    assert D.write_exposure(entries) == []
    users_modify = D.parse_acl_json(acl_json(("S-1-5-32-545", "VORDEFINIERT\\Benutzer", "Allow", MODIFY, False)))
    assert D.write_exposure(users_modify) == ["VORDEFINIERT\\Benutzer"]  # found despite the German name


@pytest.mark.parametrize("rights, write, strong", [
    (READ_EXEC, False, False), (CREATE_ONLY, True, False), (MODIFY, True, True), (FULL, True, True),
    (GENERIC_ALL, True, True), (0x10000, True, True), (0x40000, True, True), (0x80000, True, True), (0x1, False, False)])
def test_parse_acl_json_rights_masks(rights, write, strong):
    e = D.parse_acl_json(acl_json(("S-1-1-0", "Everyone", "Allow", rights, False)))[0]
    assert (e.write, e.strong) == (write, strong)


def test_acl_json_domain_users_deny_and_inherit_only():
    dom = "S-1-5-21-1004336348-1177238915-682003330"
    flagged = D.parse_acl_json(acl_json((f"{dom}-513", "CONTOSO\\Domain Users", "Allow", MODIFY, False)))
    assert D.write_exposure(flagged) == ["CONTOSO\\Domain Users"]
    not_users = D.parse_acl_json(acl_json((f"{dom}-512", "CONTOSO\\Domain Admins", "Allow", FULL, False),
                                          (f"{dom}-1105", "CONTOSO\\alice", "Allow", FULL, False)))
    assert D.write_exposure(not_users) == []
    child_only = D.parse_acl_json(acl_json(("S-1-5-32-545", "BUILTIN\\Users", "Allow", FULL, True)))
    assert D.write_exposure(child_only) == []  # inherit-only entries do not apply to the object itself
    denied = D.parse_acl_json(acl_json(("S-1-5-11", "NT AUTHORITY\\Authenticated Users", "Deny", MODIFY, False),
                                       ("S-1-5-11", "NT AUTHORITY\\Authenticated Users", "Allow", MODIFY, False)))
    assert D.write_exposure(denied) == []
    assert D.parse_acl_json("garbage") == [] and D.parse_acl_json(None) == []
    assert D.parse_acl_json([{"sid": "S-1-1-0", "rights": "not a number"}])[0].write is False


# --------------------------------------------------------------------------- check_acl (Windows paths, mocked)

def windows_env(monkeypatch, acls):
    """Pretend to be Windows; `acls` maps a path suffix ('config.json', 'signatures', ...) to entries."""
    monkeypatch.setattr(D, "IS_WINDOWS", True)

    def fake(paths):
        out = {}
        for p in paths:
            key = "home" if p.name.startswith("aegis_home") else p.name
            out[str(p)] = acls.get(key, acls.get("*"))
        return out

    monkeypatch.setattr(D, "_windows_acls", fake)


def prepare_dirs(cfg):
    cfg.save()
    (cfg.signatures_dir / "rules").mkdir(exist_ok=True)
    cfg.quarantine_dir  # noqa: B018 - creates the folder


def test_check_acl_flags_users_who_can_write_the_allowlist(cfg, monkeypatch):
    prepare_dirs(cfg)
    windows_env(monkeypatch, {
        "config.json": D.parse_icacls(ICACLS_CDRIVE_FOLDER.replace(r"C:\Aegis", r"C:\Aegis\config.json")),
        "*": D.parse_icacls(ICACLS_CONFIG_OK, "C:\\x")})
    c = D.check_acl(cfg)
    assert c.status == CheckStatus.FAIL and c.severity == "medium" and c.fix_id == "acl" and c.check_id == "DOC-ACL"
    assert "config.json" in c.detail and "Authenticated Users" in c.detail and "allow-list" in c.detail
    assert "aegis doctor --fix" in c.fix and "Administrators" in c.fix


def test_check_acl_programdata_default_users_create_in_signatures_is_flagged_but_data_root_is_not(cfg, monkeypatch):
    prepare_dirs(cfg)
    sig_acl = D.parse_icacls(ICACLS_SIGNATURES_DEFAULT, "C:\\x")
    windows_env(monkeypatch, {"signatures": sig_acl, "rules": sig_acl, "home": sig_acl, "*": D.parse_icacls(ICACLS_CONFIG_OK, "C:\\x")})
    c = D.check_acl(cfg)
    assert c.status == CheckStatus.FAIL
    assert "signatures" in c.detail and "signatures/rules" in c.detail and "data folder" not in c.detail  # root: create-only is tolerated


def test_check_acl_passes_when_only_admins_can_write(cfg, monkeypatch):
    prepare_dirs(cfg)
    windows_env(monkeypatch, {"*": D.parse_icacls(ICACLS_CONFIG_OK, "C:\\x")})
    c = D.check_acl(cfg)
    assert c.status == CheckStatus.PASS and c.fix_id == "" and "No standard-user write access" in c.detail


def test_check_acl_skips_when_acls_cannot_be_read(cfg, monkeypatch):
    prepare_dirs(cfg)
    monkeypatch.setattr(D, "IS_WINDOWS", True)
    monkeypatch.setattr(D, "_windows_acls", lambda paths: {str(p): None for p in paths})
    assert D.check_acl(cfg).status == CheckStatus.SKIP


def test_windows_acls_prefers_powershell_json_and_falls_back_to_icacls(tmp_path, monkeypatch):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    monkeypatch.setattr(D, "IS_WINDOWS", True)
    ps = [{"path": str(a), "ok": True, "acl": acl_json(("S-1-5-32-545", "BUILTIN\\Users", "Allow", MODIFY, False))},
          {"path": str(b), "ok": False}]
    monkeypatch.setattr(D, "powershell_json", lambda script, timeout=90: ps)
    seen: List[List[str]] = []

    def fake_run(cmd, timeout=60, input_text=None):
        seen.append(list(cmd))
        return 0, ICACLS_CONFIG_OK.replace(r"C:\ProgramData\Aegis\config.json", str(b)), ""

    monkeypatch.setattr(D, "run", fake_run)
    res = D._windows_acls([a, b])
    assert D.write_exposure(res[str(a)]) == ["BUILTIN\\Users"]  # from Get-Acl
    assert D.write_exposure(res[str(b)]) == [] and len(res[str(b)]) == 3  # from icacls
    assert len(seen) == 1 and seen[0][-1] == str(b)  # icacls ran only for the path PowerShell could not read
    monkeypatch.setattr(D, "powershell_json", lambda script, timeout=90: None)
    monkeypatch.setattr(D, "run", lambda *a, **k: (-1, "", "not found"))
    assert D._windows_acls([a]) == {str(a): None}


def test_acl_script_quotes_paths():
    script = D._acl_script([Path("C:/Users/O'Brien/AppData/Aegis")])
    assert "O''Brien" in script and "Get-Acl -LiteralPath" in script and "ConvertTo-Json" in script


# --------------------------------------------------------------------------- applying the safe ACL

class Runner:
    def __init__(self, fail_on: Tuple[str, ...] = ()):
        self.cmds: List[List[str]] = []
        self.fail_on = fail_on

    def __call__(self, cmd, timeout=60, input_text=None):
        self.cmds.append(list(cmd))
        if any(tag in cmd for tag in self.fail_on):
            return 5, "", "Access is denied."
        return 0, "Successfully processed 1 files; Failed processing 0 files", ""


@pytest.fixture
def as_admin_windows(monkeypatch):
    monkeypatch.setattr(D, "IS_WINDOWS", True)
    monkeypatch.setattr(D, "is_admin", lambda: True)


def test_apply_safe_acl_command_sequence(tmp_path, as_admin_windows):
    target = tmp_path / "Aegis"
    target.mkdir()
    r = Runner()
    ok, msg = D.apply_safe_acl(target, runner=r)
    assert ok and str(target) in msg
    assert len(r.cmds) == 4
    grant, remove, inherit, reset = r.cmds
    assert grant[1:3] == [str(target), "/grant:r"]
    assert grant[3:] == ["*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX"]  # SIDs: any language
    assert remove[2] == "/remove:g" and "*S-1-5-11" in remove and "*S-1-1-0" in remove
    assert inherit[1:] == [str(target), "/inheritance:r"]
    assert reset[1] == str(target) + "\\*" and reset[2:] == ["/reset", "/T", "/C", "/Q"]
    # the folder is never left without a usable ACL: grants come before inheritance is removed
    assert r.cmds.index(grant) < r.cmds.index(inherit)


def test_apply_safe_acl_stops_when_a_required_step_fails(tmp_path, as_admin_windows):
    target = tmp_path / "Aegis"
    target.mkdir()
    r = Runner(fail_on=("/grant:r",))
    ok, msg = D.apply_safe_acl(target, runner=r)
    assert not ok and "Access is denied" in msg and len(r.cmds) == 1  # never removed inheritance after a failed grant
    r2 = Runner(fail_on=("/remove:g", "/reset"))
    ok, msg = D.apply_safe_acl(target, runner=r2)
    assert ok and "skipped" in msg and len(r2.cmds) == 4  # optional steps may fail without undoing the rest


def test_apply_safe_acl_refuses_dangerous_targets(tmp_path, monkeypatch, as_admin_windows):
    programdata = tmp_path / "ProgramData"
    (programdata / "Aegis").mkdir(parents=True)
    other = tmp_path / "Documents"
    other.mkdir()
    monkeypatch.setenv("ProgramData", str(programdata))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "profile"))
    r = Runner()
    for bad in (Path(tmp_path.anchor or "/"), programdata, tmp_path, other, tmp_path / "profile"):
        ok, msg = D.apply_safe_acl(bad, runner=r)
        assert not ok and msg, bad
    assert r.cmds == []  # nothing was ever executed
    assert D.apply_safe_acl(programdata / "Aegis", runner=r)[0] is True  # the genuine data folder is accepted


def test_apply_safe_acl_requires_admin_and_windows(tmp_path, monkeypatch):
    target = tmp_path / "Aegis"
    target.mkdir()
    r = Runner()
    monkeypatch.setattr(D, "IS_WINDOWS", False)
    assert D.apply_safe_acl(target, runner=r)[0] is False
    monkeypatch.setattr(D, "IS_WINDOWS", True)
    monkeypatch.setattr(D, "is_admin", lambda: False)
    ok, msg = D.apply_safe_acl(target, runner=r)
    assert not ok and "Administrator" in msg and r.cmds == []


ICACLS_CONFIG_ADMINS_ONLY = r"""C:\ProgramData\Aegis\config.json NT AUTHORITY\SYSTEM:(F)
                                 BUILTIN\Administrators:(F)

Successfully processed 1 files; Failed processing 0 files
"""


def test_read_flags_in_parsed_acls():
    entries = D.parse_icacls(ICACLS_CONFIG_OK, r"C:\ProgramData\Aegis\config.json")
    assert [e.read for e in entries] == [True, True, True]
    assert D.read_exposure(entries) == ["BUILTIN\\Users"] and D.write_exposure(entries) == []
    create_only = D.parse_icacls(ICACLS_SIGNATURES_DEFAULT, r"C:\ProgramData\Aegis\signatures")
    assert [e.read for e in create_only if e.who == "BUILTIN\\Users"] == [True, False]  # (RX) vs (WD,AD,WEA,WA)
    assert D.read_exposure(D.parse_acl_json(acl_json(("S-1-5-32-545", "BUILTIN\\Users", "Allow", READ_EXEC, False)))) == ["BUILTIN\\Users"]
    assert D.read_exposure(D.parse_acl_json(acl_json(("S-1-5-32-545", "BUILTIN\\Users", "Allow", CREATE_ONLY, False)))) == []


def test_check_acl_warns_when_credentials_are_readable_by_every_user(cfg, monkeypatch):
    cfg.alert_slack_webhook = "https://hooks.slack.com/services/T/B/tokentokentoken"
    cfg.alert_email_smtp_password = "hunter2hunter2"
    prepare_dirs(cfg)
    windows_env(monkeypatch, {"*": D.parse_icacls(ICACLS_CONFIG_OK, "C:\\x")})  # Users: read & execute
    c = D.check_acl(cfg)
    assert c.status == CheckStatus.WARN and c.severity == "low" and c.fix_id == "acl"
    assert "alert_slack_webhook" in c.detail and "alert_email_smtp_password" in c.detail and "BUILTIN\\Users" in c.detail
    assert "tokentokentoken" not in c.detail + c.fix and "hunter2" not in c.detail + c.fix
    windows_env(monkeypatch, {"*": D.parse_icacls(ICACLS_CONFIG_ADMINS_ONLY, "C:\\x")})  # locked down: fine
    assert D.check_acl(cfg).status == CheckStatus.PASS
    cfg.alert_slack_webhook = cfg.alert_email_smtp_password = ""
    windows_env(monkeypatch, {"*": D.parse_icacls(ICACLS_CONFIG_OK, "C:\\x")})  # nothing secret: readable is fine
    assert D.check_acl(cfg).status == CheckStatus.PASS


def test_apply_safe_acl_can_lock_config_json_to_admins(tmp_path, as_admin_windows):
    target = tmp_path / "Aegis"
    target.mkdir()
    (target / "config.json").write_text("{}")
    r = Runner()
    assert D.apply_safe_acl(target, runner=r, lock_config=True)[0]
    assert len(r.cmds) == 6
    cfg_file = str(target / "config.json")
    assert r.cmds[4][1:] == [cfg_file, "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F"]  # no Users entry
    assert r.cmds[5][1:] == [cfg_file, "/inheritance:r"]
    assert r.cmds.index(r.cmds[3]) < 4 and r.cmds[3][2] == "/reset"  # after the reset, which would re-inherit Users: read
    r2 = Runner()
    D.apply_safe_acl(target, runner=r2)
    assert len(r2.cmds) == 4  # default: Users keep read & execute on everything


# --------------------------------------------------------------------------- POSIX permissions

@posix_only
def test_posix_permissions_check_and_fix(cfg):
    cfg.save()
    os.chmod(cfg.home, 0o777)
    os.chmod(cfg.path, 0o666)
    c = D.check_acl(cfg)
    assert c.status == CheckStatus.FAIL and c.fix_id == "perms" and "config.json" in c.detail
    ok, msg = D.apply_posix_perms(cfg)
    assert ok and "config.json" in msg
    assert stat.S_IMODE(os.stat(cfg.path).st_mode) & 0o022 == 0 and stat.S_IMODE(os.stat(cfg.home).st_mode) & 0o022 == 0
    assert D.check_acl(cfg).status == CheckStatus.PASS
    assert D.apply_posix_perms(cfg) == (True, "nothing to change")


@posix_only
def test_posix_config_with_credentials_must_not_be_world_readable(cfg):
    cfg.alert_slack_webhook = "https://hooks.slack.com/services/T/B/secret-token-value"
    cfg.save()
    os.chmod(cfg.home, 0o755)
    os.chmod(cfg.path, 0o644)
    c = D.check_acl(cfg)
    assert c.status == CheckStatus.WARN and "alert_slack_webhook" in c.detail and c.fix_id == "perms"
    assert "secret-token-value" not in c.detail and "secret-token-value" not in c.fix
    D.apply_posix_perms(cfg)
    assert stat.S_IMODE(os.stat(cfg.path).st_mode) == 0o600
    assert D.check_acl(cfg).status == CheckStatus.PASS
    cfg.alert_slack_webhook = ""
    cfg.save()
    os.chmod(cfg.path, 0o644)
    assert D.check_acl(cfg).status == CheckStatus.PASS  # nothing secret in it: 0644 is fine


# --------------------------------------------------------------------------- signature freshness

def write_state(cfg, feeds, **extra):
    state = {"feeds": {name: {"ok": True, "updated": ts, "count": 10} for name, ts in feeds.items()}, **extra}
    (cfg.signatures_dir / "update_state.json").write_text(json.dumps(state), encoding="utf-8")


def iso(now: float, days_ago: float) -> str:
    return dt.datetime.fromtimestamp(now - days_ago * 86400, dt.timezone.utc).isoformat(timespec="seconds")


@pytest.mark.parametrize("days, status", [(0.5, CheckStatus.PASS), (2.9, CheckStatus.PASS), (3.5, CheckStatus.WARN),
                                          (13.9, CheckStatus.WARN), (14.5, CheckStatus.FAIL), (400, CheckStatus.FAIL)])
def test_signature_freshness_thresholds(cfg, days, status):
    now = time.time()
    write_state(cfg, {"malwarebazaar": iso(now, days), "urlhaus": iso(now, days + 5)})
    c = D.check_signatures(cfg, now)
    assert c.status == status and c.check_id == "DOC-SIGS"
    assert f"{days:.1f} day" in c.detail
    if status != CheckStatus.PASS:
        assert c.fix_id == "update" and "aegis update" in c.fix


def test_signature_freshness_uses_newest_feed_and_reports_failures(cfg):
    now = time.time()
    write_state(cfg, {"malwarebazaar": iso(now, 20), "urlhaus": iso(now, 1)})
    state = json.loads((cfg.signatures_dir / "update_state.json").read_text())
    state["feeds"]["feodo"] = {"ok": False, "error": "HTTP 401 (an abuse.ch Auth-Key is required)"}
    state["feeds"]["yara_forge"] = {"ok": False, "error": "yara-python not installed; skipped"}
    (cfg.signatures_dir / "update_state.json").write_text(json.dumps(state))
    c = D.check_signatures(cfg, now)
    assert c.status == CheckStatus.PASS and "feodo" in c.detail and "yara_forge" not in c.detail  # skipped feeds are not failures


def test_signature_freshness_never_updated_or_corrupt_state(cfg):
    c = D.check_signatures(cfg, time.time())
    assert c.status == CheckStatus.WARN and "never downloaded" in c.detail and c.fix_id == "update"
    (cfg.signatures_dir / "update_state.json").write_text("{not json")
    assert D.check_signatures(cfg, time.time()).status == CheckStatus.WARN
    (cfg.signatures_dir / "update_state.json").write_text(json.dumps({"feeds": {"a": {"ok": False, "error": "HTTP 500"}}}))
    c = D.check_signatures(cfg, time.time())
    assert c.status == CheckStatus.WARN and "never been downloaded successfully" in c.detail and "a" in c.detail


# --------------------------------------------------------------------------- real-time monitor heartbeat

def test_heartbeat_roundtrip_and_states(cfg, monkeypatch):
    assert D.check_monitor(cfg).status == CheckStatus.WARN  # no heartbeat: not running
    assert D.write_heartbeat(cfg, started=time.time(), components=("files", "processes"))
    hb = D.read_heartbeat(cfg)
    assert hb["pid"] == os.getpid() and hb["components"] == ["files", "processes"] and isinstance(hb["time"], float)
    now = time.time()
    c = D.check_monitor(cfg, now=now + 10)
    assert c.status == CheckStatus.PASS and "pid" in c.detail and "files, processes" in c.detail
    stale = D.check_monitor(cfg, now=now + D.HEARTBEAT_STALE_S + 5)
    assert stale.status == CheckStatus.FAIL and "stopped unexpectedly" in stale.detail and stale.severity == "high"
    assert D.check_monitor(cfg, now=now + D.HEARTBEAT_STALE_S - 5).status == CheckStatus.PASS


def test_credential_canary_state_comes_from_the_heartbeat(cfg):
    now = time.time()
    assert D.check_credential_canary(cfg).status == CheckStatus.SKIP  # protection not running
    D.write_heartbeat(cfg, components=("files",))
    assert "does not report" in D.check_credential_canary(cfg, now).detail
    cases = [("watching 4 decoy files", CheckStatus.PASS, ""),
             ("off", CheckStatus.SKIP, ""),
             ("not running: this system tells user-mode programs nothing about file reads (macOS needs an Endpoint "
              "Security extension)", CheckStatus.SKIP, ""),
             ("not running: needs administrator rights (to put audit entries on the decoys and read the Security log)",
              CheckStatus.WARN, "install-service"),
             ("watching 4 decoy files, but Windows does not log file reads; turn it on with `aegis harden --only "
              "windows.file_audit --apply`", CheckStatus.WARN, "windows.file_audit"),
             ("not running: inotify is unavailable (no inotify)", CheckStatus.WARN, "aegis.log")]
    for state, status, fix in cases:
        D.write_heartbeat(cfg, components=("credential_canary",), guards={"credential_canary": state})
        c = D.check_credential_canary(cfg, now)
        assert c.status == status and fix in c.fix, (state, c)
    assert D.check_credential_canary(cfg, now + D.HEARTBEAT_STALE_S + 5).status == CheckStatus.SKIP  # stale heartbeat


def test_heartbeat_with_dead_process_or_garbage(cfg, monkeypatch):
    D.write_heartbeat(cfg)
    import psutil

    with monkeypatch.context() as m:
        m.setattr(psutil, "pid_exists", lambda pid: False)
        c = D.check_monitor(cfg, now=time.time())
    assert c.status == CheckStatus.FAIL and "process is gone" in c.detail
    D.heartbeat_path(cfg).write_text("garbage, not json")  # unreadable content: the file's mtime is used instead
    assert D.read_heartbeat(cfg)["time"] > 0
    D.heartbeat_path(cfg).unlink()
    assert D.read_heartbeat(cfg) is None


def test_clear_heartbeat_only_removes_our_own(cfg):
    D.write_heartbeat(cfg)
    D.clear_heartbeat(cfg)
    assert not D.heartbeat_path(cfg).exists()
    D.heartbeat_path(cfg).write_text(json.dumps({"pid": os.getpid() + 12345, "time": time.time()}))
    D.clear_heartbeat(cfg)  # another monitor's heartbeat stays
    assert D.heartbeat_path(cfg).exists()
    D.clear_heartbeat(SimpleNamespace(home=cfg.home / "missing"))  # missing folder: no error


# --------------------------------------------------------------------------- scheduled tasks / systemd units

def fake_run(table, calls=None):
    def run(cmd, timeout=60, input_text=None):
        if calls is not None:
            calls.append(list(cmd))
        for key, result in table.items():
            if key in " ".join(cmd):
                return result
        return (1, "", "not found")

    return run


TASK_XML_ENABLED = '<Task><Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><Enabled>true</Enabled></Settings></Task>'
TASK_XML_DISABLED = '<Task><Settings><Enabled>false</Enabled></Settings></Task>'


def test_service_check_windows_tasks(monkeypatch, cfg):
    from aegis.core import service

    monkeypatch.setattr(D, "IS_WINDOWS", True)
    monkeypatch.setattr(D, "IS_LINUX", False)
    calls: List[List[str]] = []
    monkeypatch.setattr(D, "run", fake_run({n: (0, TASK_XML_ENABLED, "") for n in service.ALL_TASKS}, calls))
    c = D.check_service(cfg)
    assert c.status == CheckStatus.PASS and all(n in c.detail for n in service.ALL_TASKS)
    assert all(cmd[:2] == ["schtasks", "/Query"] and "/XML" in cmd for cmd in calls)  # exit codes + XML, no localised text

    table = {service.TASK_REALTIME: (0, TASK_XML_ENABLED, ""), service.TASK_SCAN: (0, TASK_XML_DISABLED, "")}
    monkeypatch.setattr(D, "run", fake_run(table))
    c = D.check_service(cfg)
    assert c.status == CheckStatus.WARN and service.TASK_SCAN in c.detail and service.TASK_UPDATE in c.detail
    assert service.TASK_REALTIME not in c.detail.split("Missing or disabled:")[1] and "install-service" in c.fix

    monkeypatch.setattr(D, "run", fake_run({}))
    c = D.check_service(cfg)
    assert c.status == CheckStatus.WARN and "No scheduled protection" in c.detail


def test_service_check_linux_systemd(monkeypatch, cfg):
    monkeypatch.setattr(D, "IS_WINDOWS", False)
    monkeypatch.setattr(D, "IS_LINUX", True)
    monkeypatch.setattr(D.shutil, "which", lambda name: "/usr/bin/systemctl")
    monkeypatch.setattr(D, "run", fake_run({"is-enabled": (0, "enabled", "")}))
    assert D.check_service(cfg).status == CheckStatus.PASS
    monkeypatch.setattr(D, "run", fake_run({"aegis-monitor.service": (0, "enabled", "")}))
    c = D.check_service(cfg)
    assert c.status == CheckStatus.WARN and "aegis-scan.timer" in c.detail and "aegis-monitor.service" not in c.detail.split(":", 1)[1]
    monkeypatch.setattr(D, "run", fake_run({"is-enabled": (1, "disabled", "")}))
    assert "No scheduled protection" in D.check_service(cfg).detail


def test_service_check_linux_without_user_bus_falls_back_to_unit_files(monkeypatch, cfg, tmp_path):
    from aegis.core import service

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    udir = service.systemd_user_dir()
    udir.mkdir(parents=True)
    monkeypatch.setattr(D, "IS_WINDOWS", False)
    monkeypatch.setattr(D, "IS_LINUX", True)
    monkeypatch.setattr(D.shutil, "which", lambda name: "/usr/bin/systemctl")
    monkeypatch.setattr(D, "run", fake_run({"is-enabled": (1, "", "Failed to connect to bus: No medium found")}))
    assert D.check_service(cfg).status == CheckStatus.WARN  # no unit files yet
    for name in service.systemd_units("/usr/bin/aegis", []):
        (udir / name).write_text("[Unit]\n")
    c = D.check_service(cfg)
    assert c.status == CheckStatus.PASS and "could not be queried" in c.detail
    monkeypatch.setattr(D.shutil, "which", lambda name: None)  # no systemctl at all
    assert D.check_service(cfg).status == CheckStatus.PASS


def test_service_check_unsupported_os(monkeypatch, cfg):
    monkeypatch.setattr(D, "IS_WINDOWS", False)
    monkeypatch.setattr(D, "IS_LINUX", False)
    assert D.check_service(cfg).status == CheckStatus.SKIP


# --------------------------------------------------------------------------- antivirus (Windows)

DEFENDER_ON = 0x061100  # on, definitions current
DEFENDER_OFF = 0x060100
THIRD_PARTY_ON = 0x041000
THIRD_PARTY_STALE = 0x041010


def av_facts(products, mp=None):
    facts = {"av": [{"name": n, "state": s, "exe": ""} for n, s in products]}
    if mp is not None:
        facts["mp"] = mp
    return facts


MP_OK = {"AMServiceEnabled": True, "AntivirusEnabled": True, "RealTimeProtectionEnabled": True, "AntivirusSignatureAge": 0,
         "AMRunningMode": "Normal", "IsTamperProtected": True, "BehaviorMonitorEnabled": True, "QuickScanAge": 1}


def test_antivirus_check_variants(monkeypatch, cfg):
    monkeypatch.setattr(D, "IS_WINDOWS", True)

    def with_facts(facts):
        monkeypatch.setattr(D, "powershell_json", lambda script, timeout=90: facts)
        return D.check_antivirus(cfg)

    c = with_facts(av_facts([("Windows Defender", DEFENDER_ON)], MP_OK))
    assert c.status == CheckStatus.PASS and "Microsoft Defender" in c.detail

    c = with_facts(av_facts([("Windows Defender", DEFENDER_OFF)], dict(MP_OK, AntivirusEnabled=True, RealTimeProtectionEnabled=False)))
    assert c.status == CheckStatus.FAIL and c.severity == "high" and "Windows Security" in c.fix

    c = with_facts(av_facts([("Contoso Shield", THIRD_PARTY_ON), ("Windows Defender", DEFENDER_OFF)],
                            dict(MP_OK, RealTimeProtectionEnabled=False, AMRunningMode="Passive Mode")))
    assert c.status == CheckStatus.PASS and "Contoso Shield" in c.detail

    c = with_facts(av_facts([("Contoso Shield", THIRD_PARTY_STALE)]))
    assert c.status == CheckStatus.WARN and "out-of-date" in c.detail

    c = with_facts(av_facts([("Windows Defender", DEFENDER_ON)], dict(MP_OK, AntivirusSignatureAge=12)))
    assert c.status == CheckStatus.WARN and "12 days" in c.detail

    assert with_facts(None).status == CheckStatus.SKIP and with_facts({}).status == CheckStatus.SKIP


def test_antivirus_check_skipped_off_windows(monkeypatch, cfg):
    monkeypatch.setattr(D, "IS_WINDOWS", False)
    assert D.check_antivirus(cfg).status == CheckStatus.SKIP


# --------------------------------------------------------------------------- disk, yara, pyyaml, history, alerts, misc

Usage = namedtuple("Usage", "total used free")
GB = 1024 ** 3


@pytest.mark.parametrize("free, total, status", [(50 * 1024 ** 2, 100 * GB, CheckStatus.FAIL), (500 * 1024 ** 2, 100 * GB, CheckStatus.WARN),
                                                 (5 * GB, 100 * GB, CheckStatus.PASS), (100 * GB, 1000 * GB, CheckStatus.PASS)])
def test_disk_space_thresholds(cfg, monkeypatch, free, total, status):
    (cfg.quarantine_dir / "item.bin").write_bytes(b"x" * 2048)
    monkeypatch.setattr(D.shutil, "disk_usage", lambda p: Usage(total, total - free, free))
    c = D.check_disk(cfg)
    assert c.status == status and "2.0 KB" in c.detail  # shows what the quarantine holds
    if status != CheckStatus.PASS:
        assert c.fix


def test_disk_space_warns_on_low_percentage(cfg, monkeypatch):
    monkeypatch.setattr(D.shutil, "disk_usage", lambda p: Usage(2000 * GB, 1950 * GB, 50 * GB))  # 2.5 % free, but 50 GB
    assert D.check_disk(cfg).status == CheckStatus.WARN


def test_yara_engine_and_pyyaml_checks(cfg, monkeypatch):
    monkeypatch.setattr(D, "_yara_info", lambda: (True, "4.5.1"))
    assert D.check_yara_engine(cfg).status == CheckStatus.PASS and "4.5.1" in D.check_yara_engine(cfg).detail
    monkeypatch.setattr(D, "_yara_info", lambda: (False, ""))
    c = D.check_yara_engine(cfg)
    assert c.status == CheckStatus.WARN and "pip install yara-python" in c.fix
    monkeypatch.setattr(D, "_have_module", lambda name: name == "yaml")
    assert D.check_pyyaml(cfg).status == CheckStatus.PASS
    monkeypatch.setattr(D, "_have_module", lambda name: False)
    c = D.check_pyyaml(cfg)
    assert c.status == CheckStatus.WARN and "pip install pyyaml" in c.fix and "Sigma" in c.detail


def test_yara_rules_count(cfg, monkeypatch):
    db = SimpleNamespace(yara_count=3, yara_rules=[object()] * 120, rules=[object()] * 78)
    monkeypatch.setattr(D, "_yara_info", lambda: (True, "4.5"))
    c = D.check_yara_rules(cfg, db)
    assert c.status == CheckStatus.PASS and "3 YARA rule file" in c.detail and "120 rule" in c.detail and "78 built-in" in c.detail
    c = D.check_yara_rules(cfg, SimpleNamespace(yara_count=0, yara_rules=None, rules=[object()]))
    assert c.status == CheckStatus.FAIL and "aegis update" in c.fix
    monkeypatch.setattr(D, "_yara_info", lambda: (False, ""))
    c = D.check_yara_rules(cfg, SimpleNamespace(yara_count=0, yara_rules=None, rules=[object()] * 5))
    assert c.status == CheckStatus.PASS and "5 built-in" in c.detail
    assert D.check_yara_rules(cfg, SimpleNamespace(yara_count=0, yara_rules=None, rules=[])).status == CheckStatus.WARN


def test_history_and_last_scan_checks(cfg):
    from aegis.core import history

    c = D.check_history(cfg)
    assert c.status == CheckStatus.PASS and "0 scan(s) recorded" in c.detail and "schema v1" in c.detail
    c = D.check_last_scan(cfg)
    assert c.status == CheckStatus.WARN and "No scan" in c.detail and "aegis scan quick" in c.fix
    now = dt.datetime(2026, 10, 16, 12, 0, 0)
    r = ScanResult(profile="quick", started=(now - dt.timedelta(days=2, minutes=5)).isoformat(timespec="seconds"),
                   finished=(now - dt.timedelta(days=2)).isoformat(timespec="seconds"))
    history.record(r, cfg)
    assert D.check_history(cfg).detail.startswith("1 scan(s) recorded")
    c = D.check_last_scan(cfg, now=now.timestamp())
    assert c.status == CheckStatus.PASS and "2.0 day" in c.detail
    c = D.check_last_scan(cfg, now=(now + dt.timedelta(days=10)).timestamp())
    assert c.status == CheckStatus.WARN and "12 day" in c.detail


def test_alerts_check(cfg):
    c = D.check_alerts(cfg)
    assert c.status == CheckStatus.SKIP and "optional" in c.detail
    cfg.alert_slack_webhook = "https://hooks.slack.com/services/T/B/tokentokentoken"
    cfg.alert_email_smtp_host, cfg.alert_email_to = "smtp.example.org", "ops@example.org"
    c = D.check_alerts(cfg)
    assert c.status == CheckStatus.PASS and "slack, email" in c.detail and "high" in c.detail and "tokentokentoken" not in c.detail
    cfg.alert_discord_webhook = "http://discord.com/api/webhooks/1/secrettokensecret"
    c = D.check_alerts(cfg)
    assert c.status == CheckStatus.FAIL and "https://" in c.detail and "secrettokensecret" not in c.detail


def test_admin_runtime_and_datadir_checks(cfg, monkeypatch):
    monkeypatch.setattr(D, "is_admin", lambda: True)
    assert D.check_admin(cfg).status == CheckStatus.PASS
    monkeypatch.setattr(D, "is_admin", lambda: False)
    c = D.check_admin(cfg)
    assert c.status == CheckStatus.WARN and c.fix
    c = D.check_runtime(cfg)
    assert c.status == CheckStatus.PASS and ("from source" in c.detail or "packaged" in c.detail)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    assert "packaged executable" in D.check_runtime(cfg).detail
    assert D.check_datadir(cfg).status == CheckStatus.PASS
    bad = SimpleNamespace(home=cfg.home / "does" / "not" / "exist")
    c = D.check_datadir(bad)
    assert c.status == CheckStatus.FAIL and "cannot write" in c.detail


# --------------------------------------------------------------------------- orchestration

ALL_IDS = ["DOC-ADMIN", "DOC-RUNTIME", "DOC-DATADIR", "DOC-ACL", "DOC-SIGS", "DOC-YARA", "DOC-YARA-RULES", "DOC-PYYAML",
           "DOC-SERVICE", "DOC-MONITOR", "DOC-CREDCANARY", "DOC-AV", "DOC-DISK", "DOC-HISTORY", "DOC-SCANAGE", "DOC-ALERTS"]


@pytest.fixture
def quiet_system(monkeypatch):
    """No real PowerShell / schtasks / systemctl during orchestration tests."""
    monkeypatch.setattr(D, "run", lambda *a, **k: (-1, "", "not found"))
    monkeypatch.setattr(D, "powershell_json", lambda *a, **k: None)


def test_doctor_runs_every_check_and_never_raises(cfg, quiet_system):
    results = D.doctor(cfg)
    assert [r.check_id for r in results] == ALL_IDS
    assert all(isinstance(r, D.DoctorCheck) and r.scanner == "doctor" and r.title and r.detail for r in results)
    assert not [r for r in results if r.status == CheckStatus.ERROR], [r.detail for r in results if r.status == CheckStatus.ERROR]
    assert all(r.fix for r in results if r.status in (CheckStatus.WARN, CheckStatus.FAIL)), "every problem comes with a fix"
    assert all(set(r.to_dict()) >= {"check_id", "title", "status", "detail", "severity", "fix", "fix_id"} for r in results)
    json.dumps([r.to_dict() for r in results])


def test_a_crashing_check_becomes_an_error_result(cfg, quiet_system, monkeypatch):
    monkeypatch.setattr(D, "check_disk", lambda config: (_ for _ in ()).throw(OSError("disk exploded")))
    results = D.doctor(cfg)
    disk = [r for r in results if r.check_id == "DOC-DISK"][0]
    assert disk.status == CheckStatus.ERROR and "disk exploded" in disk.detail
    assert len(results) == len(ALL_IDS) and results[-1].check_id == "DOC-ALERTS"


def test_doctor_with_default_config_load(quiet_system):
    assert len(D.doctor()) == len(ALL_IDS)


def test_summarize_has_failures_and_render(cfg, quiet_system):
    results = [D._chk("A", "Fine", CheckStatus.PASS, "ok"),
               D._chk("B", "Stale", CheckStatus.WARN, "old", "medium", "Run update", "update"),
               D._chk("C", "Broken", CheckStatus.FAIL, "bad", "high", "Do the thing"),
               D._chk("D", "Skipped", CheckStatus.SKIP, "n/a")]
    counts = D.summarize(results)
    assert counts == {"pass": 1, "warn": 1, "fail": 1, "skip": 1, "error": 0}
    assert D.has_failures(results) and not D.has_failures(results[:2])
    text = D.render_doctor(results)
    assert "[PASS] Fine" in text and "[WARN] Stale (medium)" in text and "[FAIL] Broken (high)" in text
    assert "Fix: Run update   [automatic: aegis doctor --fix]" in text and "Fix: Do the thing" in text
    assert "1 passed, 1 warning(s), 1 failed, 1 skipped" in text
    assert "\033[" in D.render_doctor(results, color=True) and "\033[" not in text


def test_apply_fixes_dispatches_by_fix_id_once(cfg, monkeypatch):
    done: List[str] = []
    monkeypatch.setattr(D, "apply_safe_acl", lambda path, runner=None, lock_config=False: done.append(f"acl:{path.name}:{lock_config}") or (True, "acl done"))
    monkeypatch.setattr(D, "apply_posix_perms", lambda c: done.append("perms") or (True, "perms done"))
    monkeypatch.setattr(D, "_run_update", lambda c: done.append("update") or (False, "no network"))
    results = [D._chk("1", "a", CheckStatus.FAIL, fix_id="acl"), D._chk("2", "b", CheckStatus.WARN, fix_id="update"),
               D._chk("3", "c", CheckStatus.WARN, fix_id="update"), D._chk("4", "d", CheckStatus.PASS, fix_id="perms"),
               D._chk("5", "e", CheckStatus.FAIL), D._chk("6", "f", CheckStatus.FAIL, fix_id="perms")]
    out = D.apply_fixes(cfg, results)
    assert [o[0] for o in out] == ["acl", "update", "perms"] and done == [f"acl:{cfg.home.name}:False", "update", "perms"]
    cfg.alert_slack_webhook = "https://hooks.slack.com/services/T/B/tokentokentoken"
    done.clear()
    D.apply_fixes(cfg, results[:1])
    assert done == [f"acl:{cfg.home.name}:True"]  # credentials in config.json -> it is locked down as well
    cfg.alert_slack_webhook = ""
    assert out[1] == ("update", False, "no network")  # a failed fix is reported, not raised
    done.clear()
    assert [o[0] for o in D.apply_fixes(cfg, results, only=["perms"])] == ["perms"] and done == ["perms"]
    monkeypatch.setattr(D, "apply_posix_perms", lambda c: (_ for _ in ()).throw(RuntimeError("boom")))
    assert D.apply_fixes(cfg, [D._chk("6", "f", CheckStatus.FAIL, fix_id="perms")]) == [("perms", False, "RuntimeError: boom")]


def test_run_update_fix_reports_feed_results(cfg, monkeypatch):
    import aegis.tools.updater as updater

    monkeypatch.setattr(updater, "update_signatures", lambda config, progress=None: {
        "urlhaus": {"ok": True, "count": 3, "error": ""}, "feodo": {"ok": False, "count": 0, "error": "HTTP 401"},
        "yara_forge": {"ok": False, "count": 0, "error": "skipped", "skipped": True}})
    ok, msg = D._run_update(cfg)
    assert ok and "1 feed(s) updated" in msg and "feodo" in msg and "yara_forge" not in msg


def test_doctor_end_to_end_after_a_scan_and_monitor_start(cfg, quiet_system, monkeypatch):
    """History, heartbeat and the other checks agree with reality once something has actually run."""
    from aegis.core import history

    r = ScanResult(profile="quick", finished=dt.datetime.now().isoformat(timespec="seconds"))
    r.add(Finding("AEG-T-1", "t", Severity.LOW, "malware", location="x"))
    history.record(r, cfg)
    D.write_heartbeat(cfg, components=("files",))
    by_id = {c.check_id: c for c in D.doctor(cfg)}
    assert by_id["DOC-HISTORY"].detail.startswith("1 scan(s)")
    assert by_id["DOC-SCANAGE"].status == CheckStatus.PASS
    assert by_id["DOC-MONITOR"].status == CheckStatus.PASS
