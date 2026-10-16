"""Linux kernel hardening and integrity audit (aegis.scanners.system_audit.check_linux_kernel) on fake /proc + /sys trees."""

import datetime as dt
import json
import os
import stat
import subprocess
import sys

import pytest

from aegis.core.models import CheckResult, CheckStatus, Finding, Severity
from aegis.scanners import system_audit as sa

TODAY = dt.date(2026, 10, 15)
linux_only = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="needs a Linux /proc and /sys")

HEALTHY_SYSCTL = {
    "kernel/randomize_va_space": "2", "kernel/kptr_restrict": "1", "kernel/dmesg_restrict": "1",
    "kernel/yama/ptrace_scope": "1", "kernel/unprivileged_bpf_disabled": "2", "fs/protected_symlinks": "1",
    "fs/protected_hardlinks": "1", "fs/protected_fifos": "1", "fs/protected_regular": "2", "fs/suid_dumpable": "0",
    "kernel/sysrq": "176",
}
UBUNTU_LSM = "lockdown,capability,landlock,yama,apparmor,ima,evm"


def write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def proc_line(name, flags="", state="Live"):
    return f"{name} 16384 0 - {state} 0x0000000000000000" + (f" ({flags})" if flags else "") + "\n"


def make_tree(root, sysctl=None, modules=None, hide=(), ghost=(), builtin=("printk", "acpi", "tcp_cubic"), tainted="0",
              lsm=UBUNTU_LSM, apparmor="Y", enforce=None, lockdown="[none] integrity confidentiality", proc_modules=True,
              markers=()):
    """A healthy kernel unless overridden. ``sysctl`` maps /proc/sys paths to text (None removes the file); ``modules``
    maps loadable module -> /proc/modules flags (listed in /proc/modules and in /sys/module); ``hide`` names are in
    /sys/module only, ``ghost`` names in /proc/modules only; ``markers`` are extra paths below the root."""
    values = dict(HEALTHY_SYSCTL, **(sysctl or {}))
    for rel, text in values.items():
        if text is not None:
            write(root, f"proc/sys/{rel}", text + "\n")
    write(root, "proc/sys/kernel/tainted", tainted + "\n")
    modules = {"ext4": "", "snd": ""} if modules is None else modules
    if proc_modules:
        write(root, "proc/modules", "".join(proc_line(n, f) for n, f in modules.items()) + "".join(proc_line(n) for n in ghost))
    for name in builtin:  # built-in code that only has parameters: no initstate, no refcnt
        write(root, f"sys/module/{name}/parameters/.keep", "")
    for name in list(modules) + list(hide):
        write(root, f"sys/module/{name}/initstate", "live\n")
        write(root, f"sys/module/{name}/refcnt", "0\n")
    if lsm is not None:
        write(root, "sys/kernel/security/lsm", lsm + "\n")
    if lockdown is not None:
        write(root, "sys/kernel/security/lockdown", lockdown + "\n")
    if apparmor is not None:
        write(root, "sys/module/apparmor/parameters/enabled", apparmor + "\n")
    if enforce is not None:
        write(root, "sys/fs/selinux/enforce", enforce)
    for rel in markers:
        write(root, rel, "")
    return root


def run_kernel(root, facts=None):
    env = sa.AuditEnv(today=TODAY, facts=facts if facts is not None else {})
    return sa.check_linux_kernel(env, root), env


def keys(checks):
    return {c.key: c for c in checks}


def findings_of(root, **kw):
    """The failed rows below the summary, by key: one per finding."""
    checks, _ = run_kernel(make_tree(root, **kw))
    return keys([c for c in checks if c.ok is False and c.key != "KERNEL"])


# ---------------------------------------------------------------- healthy kernel
def test_healthy_kernel_passes_with_one_summary_row(tmp_path):
    checks, env = run_kernel(make_tree(tmp_path))
    assert [c.key for c in checks] == ["KERNEL"]
    (c,) = checks
    assert c.ok is True and c.status == CheckStatus.PASS and c.title == "Kernel hardening and integrity"
    assert c.check_id == "AEG-AUDIT-KERNEL" and c.to_finding() is None
    assert "11 kernel setting(s) checked, none weak" in c.detail and "apparmor" in c.detail and "lockdown: none" in c.detail
    facts = env.facts["linux_kernel"]
    assert facts["sysctl"]["kernel.randomize_va_space"] == 2 and facts["sysctl"]["kernel.sysrq"] == 176
    assert facts["lockdown"] == "none" and facts["mac"] == ["apparmor"] and facts["tainted"] == 0
    assert facts["hidden_modules"] == [] and facts["modules_listed"] == 2 and facts["sys_modules"] == 6
    assert c.evidence is facts


def test_settings_missing_on_this_kernel_are_fine(tmp_path):
    missing = {"kernel/yama/ptrace_scope": None, "kernel/unprivileged_bpf_disabled": None, "fs/protected_fifos": None,
               "fs/protected_regular": None}
    checks, env = run_kernel(make_tree(tmp_path, sysctl=missing))
    assert [c.key for c in checks] == ["KERNEL"] and checks[0].ok is True
    assert "kernel.yama.ptrace_scope" not in env.facts["linux_kernel"]["sysctl"]


# ---------------------------------------------------------------- sysctl branches
@pytest.mark.parametrize("path,value,key,severity,fixed", [
    ("kernel/randomize_va_space", "0", "KERNEL-ASLR", Severity.HIGH, {"kernel.randomize_va_space": "2"}),
    ("kernel/randomize_va_space", "1", "KERNEL-ASLR", Severity.LOW, {"kernel.randomize_va_space": "2"}),
    ("kernel/kptr_restrict", "0", "KERNEL-KPTR", Severity.LOW, {"kernel.kptr_restrict": "1"}),
    ("kernel/dmesg_restrict", "0", "KERNEL-DMESG", Severity.LOW, {"kernel.dmesg_restrict": "1"}),
    ("kernel/yama/ptrace_scope", "0", "KERNEL-PTRACE", Severity.LOW, {"kernel.yama.ptrace_scope": "1"}),
    ("kernel/unprivileged_bpf_disabled", "0", "KERNEL-BPF", Severity.MEDIUM, {"kernel.unprivileged_bpf_disabled": "1"}),
    ("fs/protected_symlinks", "0", "KERNEL-LINKS", Severity.MEDIUM, {"fs.protected_symlinks": "1"}),
    ("fs/protected_hardlinks", "0", "KERNEL-LINKS", Severity.MEDIUM, {"fs.protected_hardlinks": "1"}),
    ("fs/protected_fifos", "0", "KERNEL-FIFOS", Severity.LOW, {"fs.protected_fifos": "1"}),
    ("fs/protected_regular", "0", "KERNEL-FIFOS", Severity.LOW, {"fs.protected_regular": "1"}),
    ("fs/suid_dumpable", "1", "KERNEL-DUMP", Severity.LOW, {"fs.suid_dumpable": "0"}),
    ("kernel/sysrq", "1", "KERNEL-SYSRQ", Severity.LOW, {"kernel.sysrq": "176"}),
    ("kernel/sysrq", "511", "KERNEL-SYSRQ", Severity.LOW, {"kernel.sysrq": "176"}),
])
def test_weak_sysctl_is_reported_with_the_right_severity(tmp_path, path, value, key, severity, fixed):
    weak = findings_of(tmp_path, sysctl={path: value})
    assert set(weak) == {key}
    c = weak[key]
    assert c.severity == severity and c.check_id == "AEG-AUDIT-" + key
    f = c.to_finding()
    assert f.rule_id == "AEG-AUDIT-" + key and f.category == "system" and f.recommendation and f.description
    assert f.location == "/proc/sys/" + path and f.evidence["recommended"] == fixed
    assert f.evidence["current"] == {n: int(value) for n in fixed}
    for name, val in fixed.items():  # the manual steps name the exact command and the drop-in line
        assert f"sysctl -w {name}={val}" in f.recommendation and f"{name} = {val}" in f.recommendation
    assert sa.KERNEL_DROPIN in f.recommendation
    assert c.status == (CheckStatus.FAIL if severity >= Severity.MEDIUM else CheckStatus.WARN)


@pytest.mark.parametrize("path,value", [
    ("kernel/randomize_va_space", "2"), ("kernel/kptr_restrict", "2"), ("kernel/dmesg_restrict", "1"),
    ("kernel/yama/ptrace_scope", "2"), ("kernel/yama/ptrace_scope", None), ("kernel/unprivileged_bpf_disabled", "1"),
    ("kernel/unprivileged_bpf_disabled", "2"), ("kernel/unprivileged_bpf_disabled", None), ("fs/protected_fifos", None),
    ("fs/protected_fifos", "2"), ("fs/protected_regular", None), ("fs/suid_dumpable", "0"), ("fs/suid_dumpable", "2"),
    ("kernel/sysrq", "0"), ("kernel/sysrq", "176"), ("kernel/sysrq", "438"), ("kernel/randomize_va_space", "junk"),
])
def test_acceptable_sysctl_values_add_no_finding(tmp_path, path, value):
    assert findings_of(tmp_path, sysctl={path: value}) == {}


def test_aslr_off_is_high_and_uses_the_journalled_harden_fix(tmp_path):
    f = findings_of(tmp_path, sysctl={"kernel/randomize_va_space": "0"})["KERNEL-ASLR"].to_finding()
    assert f.severity == Severity.HIGH and f.title == "Address space layout randomisation (ASLR) is disabled"
    assert f.remediation.action == "harden" and f.remediation.params == {"ids": ["linux.aslr"]}
    assert f.mitre == ["T1068"]
    low = findings_of(tmp_path / "b", sysctl={"kernel/randomize_va_space": "1"})["KERNEL-ASLR"].to_finding()
    assert low.severity == Severity.LOW and "heap" in low.title


def test_links_and_fifos_are_one_finding_per_group_listing_each_weak_setting(tmp_path):
    weak = findings_of(tmp_path, sysctl={"fs/protected_symlinks": "0", "fs/protected_hardlinks": "0",
                                         "fs/protected_fifos": "0", "fs/protected_regular": "0"})
    assert set(weak) == {"KERNEL-LINKS", "KERNEL-FIFOS"}
    links = weak["KERNEL-LINKS"].to_finding()
    assert links.evidence["recommended"] == {"fs.protected_symlinks": "1", "fs.protected_hardlinks": "1"}
    assert "fs.protected_symlinks=0" in links.title and "fs.protected_hardlinks=0" in links.title
    script = links.remediation.params["command"][2]
    assert "sysctl -w fs.protected_symlinks=1" in script and "sysctl -w fs.protected_hardlinks=1" in script
    fifos = weak["KERNEL-FIFOS"].to_finding()
    assert set(fifos.evidence["recommended"]) == {"fs.protected_fifos", "fs.protected_regular"}


def test_ptrace_finding_maps_to_current_attack_ids_and_warns_about_debuggers(tmp_path):
    f = findings_of(tmp_path, sysctl={"kernel/yama/ptrace_scope": "0"})["KERNEL-PTRACE"].to_finding()
    assert f.mitre == ["T1055.008", "T1003.007"] and "gdb -p" in f.recommendation


def test_sysctl_fix_is_a_fixed_shell_command_with_the_persistent_dropin(tmp_path):
    f = findings_of(tmp_path, sysctl={"kernel/kptr_restrict": "0"})["KERNEL-KPTR"].to_finding()
    assert f.remediation.action == "run_command" and f.remediation.params["powershell"] is False
    cmd = f.remediation.params["command"]
    assert cmd[:2] == ["sh", "-c"] and len(cmd) == 3
    assert "sysctl -w kernel.kptr_restrict=1" in cmd[2] and sa.KERNEL_DROPIN in cmd[2]
    assert cmd[2].index("sysctl -w") < cmd[2].index("sed -i")  # nothing is persisted when the live change fails
    assert "kernel.kptr_restrict" in f.remediation.description and f.remediation.description.endswith("every reboot")


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the fix only runs on Linux, whose sed -i is GNU sed")
def test_sysctl_fix_script_persists_replaces_and_repeats(tmp_path, monkeypatch):
    dropin = tmp_path / "sysctl.d" / "61-test.conf"
    dropin.parent.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "sysctl.log"
    fake = bin_dir / "sysctl"
    fake.write_text(f"#!/bin/sh\necho \"$@\" >> {log}\n[ \"$FAKE_SYSCTL_FAIL\" = 1 ] && exit 1\nexit 0\n")
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setattr(sa, "KERNEL_DROPIN", str(dropin))
    env = dict(os.environ, PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}")

    def apply(settings, **extra):
        cmd = sa.sysctl_fix(settings, "x").params["command"]
        return subprocess.run(cmd, env=dict(env, **extra), capture_output=True, text=True)

    assert apply({"kernel.kptr_restrict": "1"}).returncode == 0
    dropin.write_text(dropin.read_text() + "vm.swappiness = 10\n")  # somebody else's line must survive
    assert apply({"kernel.kptr_restrict": "2", "fs.suid_dumpable": "0"}).returncode == 0
    assert apply({"kernel.kptr_restrict": "2", "fs.suid_dumpable": "0"}).returncode == 0
    lines = dropin.read_text().splitlines()
    assert lines[0].startswith("#") and lines.count("kernel.kptr_restrict = 2") == 1
    assert "kernel.kptr_restrict = 1" not in lines and lines.count("fs.suid_dumpable = 0") == 1
    assert "vm.swappiness = 10" in lines
    assert "-w kernel.kptr_restrict=1" in log.read_text()
    before = dropin.read_text()
    assert apply({"kernel.dmesg_restrict": "1"}, FAKE_SYSCTL_FAIL="1").returncode != 0  # sysctl -w failed: file untouched
    assert dropin.read_text() == before


# ---------------------------------------------------------------- known rootkit modules
def test_rootkit_module_in_proc_modules(tmp_path):
    weak = findings_of(tmp_path, modules={"ext4": "", "diamorphine": "OE"})
    assert set(weak) >= {"KERNEL-ROOTKIT"}
    c = weak["KERNEL-ROOTKIT"]
    f = c.to_finding()
    assert c.severity == Severity.HIGH and f.rule_id == "AEG-AUDIT-KERNEL-ROOTKIT" and "diamorphine" in f.title
    assert f.mitre == ["T1014", "T1547.006"] and f.category == "malware" and f.remediation is None
    assert f.evidence["modules"] == {"diamorphine": ["/proc/modules", "/sys/module"]}
    assert "compromised" in f.recommendation and f.location == "kernel module diamorphine"


def test_rootkit_module_only_in_sys_module_is_still_found(tmp_path):
    weak = findings_of(tmp_path, hide=("adore-ng",))
    f = weak["KERNEL-ROOTKIT"].to_finding()
    assert f.evidence["modules"] == {"adore_ng": ["/sys/module"]}  # '-' and '_' are the same module name
    assert "KERNEL-HIDDENMOD" in weak  # and it is missing from the module list


@pytest.mark.parametrize("name", sorted(sa.ROOTKIT_MODULES))
def test_every_listed_rootkit_name_matches(tmp_path, name):
    assert "KERNEL-ROOTKIT" in findings_of(tmp_path, modules={name.upper(): ""})


@pytest.mark.parametrize("name", ["nvidia", "vboxdrv", "zfs", "netfilter", "kinsing", "bdvl", "reptile_helper", "diamorphine2",
                                  "my_reptile", "singularity_net", "khook", "adore_fs"])
def test_similar_or_unrelated_module_names_are_not_rootkits(tmp_path, name):
    assert "KERNEL-ROOTKIT" not in findings_of(tmp_path, modules={name: ""})


# ---------------------------------------------------------------- hidden modules
def test_hidden_module_is_in_sys_module_but_not_in_proc_modules(tmp_path):
    weak = findings_of(tmp_path, hide=("sneaky",))
    assert set(weak) == {"KERNEL-HIDDENMOD"}
    c = weak["KERNEL-HIDDENMOD"]
    f = c.to_finding()
    assert c.severity == Severity.HIGH and "sneaky" in f.title and f.evidence["modules"] == ["sneaky"]
    assert f.mitre == ["T1014", "T1547.006"] and f.category == "suspicious" and "list" in f.description


def test_builtin_modules_without_initstate_are_not_hidden_modules(tmp_path):
    builtin = ("printk", "acpi", "tcp_cubic", "kernel", "vt", "workqueue", "ipv6", "xz_dec")
    assert findings_of(tmp_path, builtin=builtin) == {}
    for name in builtin:  # sysfs shows built-ins that carry a MODULE_VERSION with a version file only
        write(tmp_path, f"sys/module/{name}/version", "1.0\n")
    assert findings_of(tmp_path, builtin=builtin) == {}


def test_sys_module_directory_with_only_refcnt_counts_as_loadable(tmp_path):
    root = make_tree(tmp_path)
    write(root, "sys/module/oddball/refcnt", "1\n")
    checks, _ = run_kernel(root)
    assert "KERNEL-HIDDENMOD" in keys([c for c in checks if c.ok is False])


def test_module_in_transition_is_not_reported(tmp_path):
    root = make_tree(tmp_path)
    write(root, "sys/module/loading/initstate", "coming\n")
    write(root, "sys/module/leaving/initstate", "going\n")
    checks, _ = run_kernel(root)
    assert [c.key for c in checks] == ["KERNEL"]


def test_module_that_finishes_loading_during_the_scan_is_not_reported(tmp_path, monkeypatch):
    root = make_tree(tmp_path, hide=("racing",))
    real = sa._read_proc_modules
    calls = []

    def fake(r):
        calls.append(1)
        data = real(r)
        if len(calls) > 1 and data is not None:  # the second look sees the module in the list
            data["racing"] = ""
        return data

    monkeypatch.setattr(sa, "_read_proc_modules", fake)
    checks, _ = run_kernel(root)
    assert len(calls) >= 2 and [c.key for c in checks] == ["KERNEL"]


def test_module_that_unloads_during_the_scan_is_not_reported(tmp_path, monkeypatch):
    root = make_tree(tmp_path, hide=("racing",))
    real = sa.scan_sys_modules
    calls = []

    def fake(r):
        calls.append(1)
        data = real(r)
        if len(calls) > 1 and data is not None:
            data.pop("racing", None)  # gone from sysfs on the second look
        return data

    monkeypatch.setattr(sa, "scan_sys_modules", fake)
    checks, _ = run_kernel(root)
    assert len(calls) >= 2 and [c.key for c in checks] == ["KERNEL"]


def test_module_listed_but_not_yet_in_sysfs_is_normal(tmp_path):
    # the kernel lists a module (state Loading) a moment before it creates its sysfs directory
    checks, _ = run_kernel(make_tree(tmp_path, ghost=("loading_soon",)))
    assert [c.key for c in checks] == ["KERNEL"]


def test_unreadable_module_list_means_no_hidden_module_verdict(tmp_path):
    root = make_tree(tmp_path, hide=("sneaky",), proc_modules=False)
    checks, env = run_kernel(root)
    assert [c.key for c in checks] == ["KERNEL"] and env.facts["linux_kernel"]["modules_listed"] is None


def test_parse_proc_modules_flags():
    text = ("nvidia 56000000 98 nvidia_modeset, Live 0x0000000000000000 (POE)\n"
            "vboxdrv 700416 3 vboxnetflt,vboxnetadp, Live 0x0000000000000000 (OE)\n"
            "loading_mod 1024 0 - Live 0x0 (OE+)\next4 1000000 2 - Live 0x0000000000000000\n\n"
            "Mixed-Case 4096 0 - Live 0x0\n")
    assert sa.parse_proc_modules(text) == {"nvidia": "POE", "vboxdrv": "OE", "loading_mod": "OE", "ext4": "",
                                           "mixed_case": ""}


# ---------------------------------------------------------------- taint
def test_taint_without_a_listed_culprit_is_medium(tmp_path):
    weak = findings_of(tmp_path, tainted="12288")
    assert set(weak) == {"KERNEL-TAINT"}
    c = weak["KERNEL-TAINT"]
    f = c.to_finding()
    assert c.severity == Severity.LOW and c.status == CheckStatus.WARN and f.rule_id == "AEG-AUDIT-KERNEL-TAINT"
    assert f.evidence["letters"] == ["E", "O"] and f.mitre == ["T1014"] and f.remediation is None
    assert "unsigned module" in f.description and "out-of-tree module" in f.description and "restart" in f.recommendation
    assert "no longer listed" in f.title


@pytest.mark.parametrize("tainted,letters", [("4096", ["O"]), ("8192", ["E"]), ("8193", ["E"]), ("12289", ["E", "O"])])
def test_taint_bits_o_and_e_are_checked_separately(tmp_path, tainted, letters):
    assert findings_of(tmp_path, tainted=tainted)["KERNEL-TAINT"].to_finding().evidence["letters"] == letters


def test_taint_explained_by_listed_modules_is_no_finding_and_is_recorded(tmp_path):
    root = make_tree(tmp_path, tainted="12289", modules={"ext4": "", "nvidia": "POE", "vboxdrv": "OE"})
    checks, env = run_kernel(root)
    assert [c.key for c in checks] == ["KERNEL"] and checks[0].ok is True
    facts = env.facts["linux_kernel"]
    assert facts["unsigned_or_out_of_tree"] == ["nvidia", "vboxdrv"]
    assert facts["flagged_modules"] == {"nvidia": "POE", "vboxdrv": "OE"}
    assert "nvidia, vboxdrv" in checks[0].detail


def test_taint_only_partly_explained_still_reports_the_other_flag(tmp_path):
    weak = findings_of(tmp_path, tainted="12288", modules={"zfs": "O"})
    assert weak["KERNEL-TAINT"].to_finding().evidence["letters"] == ["E"]
    both = findings_of(tmp_path / "b", tainted="12288", modules={"a": "E", "b": "O"})
    assert both == {}


@pytest.mark.parametrize("tainted", ["0", "1", "512", "64", "16384"])
def test_other_taint_bits_are_not_reported(tmp_path, tainted):
    assert findings_of(tmp_path, tainted=tainted) == {}


def test_taint_is_not_judged_without_a_readable_module_list(tmp_path):
    assert findings_of(tmp_path, tainted="12288", proc_modules=False) == {}


# ---------------------------------------------------------------- mandatory access control, lockdown
def test_no_mandatory_access_control_is_low(tmp_path):
    weak = findings_of(tmp_path, lsm="capability,landlock,lockdown,yama,bpf", apparmor=None)
    assert set(weak) == {"KERNEL-MAC"}
    c = weak["KERNEL-MAC"]
    f = c.to_finding()
    assert c.severity == Severity.LOW and f.title == "No mandatory access control (AppArmor/SELinux) is active"
    assert f.evidence == {"lsm": ["capability", "landlock", "lockdown", "yama", "bpf"]} and f.remediation is None
    assert "SELINUX=enforcing" in f.recommendation and "apparmor" in f.recommendation.lower()


@pytest.mark.parametrize("lsm,mac", [(UBUNTU_LSM, ["apparmor"]), ("lockdown,capability,yama,selinux,bpf", ["selinux"]),
                                     ("capability,smack", ["smack"]), ("capability,tomoyo,yama", ["tomoyo"]),
                                     ("apparmor,selinux", ["apparmor", "selinux"])])
def test_active_mac_modules_are_accepted(tmp_path, lsm, mac):
    checks, env = run_kernel(make_tree(tmp_path, lsm=lsm, apparmor=None, enforce="1"))
    assert [c.key for c in checks] == ["KERNEL"] and env.facts["linux_kernel"]["mac"] == mac


def test_selinux_permissive_is_low_and_enforcing_is_fine(tmp_path):
    weak = findings_of(tmp_path, lsm="lockdown,capability,yama,selinux,bpf", apparmor=None, enforce="0")
    assert set(weak) == {"KERNEL-SELINUX"}
    f = weak["KERNEL-SELINUX"].to_finding()
    assert f.severity == Severity.LOW and f.mitre == ["T1685"] and f.location == "/sys/fs/selinux/enforce"
    assert f.remediation is None and "setenforce 1" in f.recommendation
    assert findings_of(tmp_path / "b", lsm="lockdown,capability,yama,selinux,bpf", apparmor=None, enforce="1") == {}
    checks, env = run_kernel(make_tree(tmp_path / "c", lsm="selinux", apparmor=None, enforce="0"))
    assert env.facts["linux_kernel"]["selinux"] == "permissive"


def test_mac_state_falls_back_to_apparmor_and_selinux_files_without_securityfs(tmp_path):
    checks, env = run_kernel(make_tree(tmp_path, lsm=None, lockdown=None, apparmor="Y"))
    assert [c.key for c in checks] == ["KERNEL"] and env.facts["linux_kernel"]["mac"] == ["apparmor"]
    checks, env = run_kernel(make_tree(tmp_path / "b", lsm=None, lockdown=None, apparmor=None, enforce="1"))
    assert [c.key for c in checks] == ["KERNEL"] and env.facts["linux_kernel"]["mac"] == ["selinux"]
    assert env.facts["linux_kernel"]["selinux"] == "enforcing" and env.facts["linux_kernel"]["lockdown"] is None


def test_unknown_mac_state_is_a_skipped_row_not_a_finding(tmp_path):
    checks, _ = run_kernel(make_tree(tmp_path, lsm=None, lockdown=None, apparmor=None))
    rows = keys(checks)
    assert rows["KERNEL"].ok is True and rows["KERNEL-MAC"].ok is None and rows["KERNEL-MAC"].status == CheckStatus.SKIP
    assert rows["KERNEL-MAC"].to_finding() is None and "securityfs" in rows["KERNEL-MAC"].detail


@pytest.mark.parametrize("text,mode", [("[none] integrity confidentiality", "none"), ("none [integrity] confidentiality", "integrity"),
                                       ("none integrity [confidentiality]", "confidentiality")])
def test_lockdown_mode_is_recorded_only(tmp_path, text, mode):
    checks, env = run_kernel(make_tree(tmp_path, lockdown=text))
    assert env.facts["linux_kernel"]["lockdown"] == mode and [c.key for c in checks] == ["KERNEL"]


# ---------------------------------------------------------------- containers and unreadable kernels
@pytest.mark.parametrize("marker,name", [(".dockerenv", "docker"), ("run/.containerenv", "podman")])
def test_container_marker_files_skip_the_whole_check(tmp_path, marker, name):
    root = make_tree(tmp_path, sysctl={"kernel/randomize_va_space": "0"}, hide=("diamorphine",), markers=(marker,))
    checks, env = run_kernel(root)
    assert len(checks) == 1 and checks[0].ok is None and checks[0].status == CheckStatus.SKIP
    assert name in checks[0].detail and "host" in checks[0].detail and checks[0].check_id == "AEG-AUDIT-KERNEL"
    assert "linux_kernel" not in env.facts


@pytest.mark.parametrize("path,text,name", [
    ("run/systemd/container", "docker\n", "docker"), ("run/systemd/container", "lxc", "lxc"),
    ("run/systemd/container", "systemd-nspawn", "systemd-nspawn"), ("proc/1/cgroup", "12:cpu:/docker/abc123\n", "docker"),
    ("proc/1/cgroup", "0::/kubepods/burstable/pod1/abc\n", "kubernetes"), ("proc/1/cgroup", "1:name=x:/lxc/web\n", "lxc"),
    ("proc/1/cgroup", "0::/system.slice/libpod-abc.scope\n", "podman"),
])
def test_detect_container(tmp_path, path, text, name):
    write(tmp_path, path, text)
    assert sa.detect_container(tmp_path) == name


@pytest.mark.parametrize("path,text", [("run/systemd/container", "wsl\n"), ("run/systemd/container", "\n"),
                                       ("proc/1/cgroup", "0::/init.scope\n"), ("proc/1/cgroup", "0::/\n")])
def test_hosts_and_wsl_are_not_containers(tmp_path, path, text):
    write(tmp_path, path, text)
    assert sa.detect_container(tmp_path) == ""
    assert sa.detect_container(tmp_path / "nothing-here") == ""


def test_wsl_kernel_is_audited_like_a_host(tmp_path):
    root = make_tree(tmp_path, sysctl={"kernel/kptr_restrict": "0"})
    write(root, "run/systemd/container", "wsl\n")
    checks, _ = run_kernel(root)
    assert "KERNEL-KPTR" in keys([c for c in checks if c.ok is False])


def test_unreadable_proc_is_a_skip(tmp_path):
    checks, env = run_kernel(tmp_path)  # empty tree: no /proc, no /sys
    assert len(checks) == 1 and checks[0].status == CheckStatus.SKIP and "not readable" in checks[0].detail
    assert "linux_kernel" not in env.facts


# ---------------------------------------------------------------- emission contract and registration
ALLOWED_MITRE = {"T1068", "T1014", "T1547.006", "T1055.008", "T1003.007", "T1685"}


def test_rows_become_results_and_findings_through_run_checks(tmp_path):
    root = make_tree(tmp_path, sysctl={"kernel/randomize_va_space": "0", "kernel/yama/ptrace_scope": "0", "fs/suid_dumpable": "1",
                                       "kernel/sysrq": "1", "kernel/unprivileged_bpf_disabled": "0", "kernel/kptr_restrict": "0",
                                       "kernel/dmesg_restrict": "0", "fs/protected_symlinks": "0", "fs/protected_fifos": "0"},
                     modules={"diamorphine": "OE"}, hide=("sneaky",), tainted="12288",
                     lsm="capability,landlock", apparmor=None)
    items = list(sa.run_checks(sa.AuditEnv(today=TODAY), [lambda e: sa.check_linux_kernel(e, root)]))
    results = [i for i in items if isinstance(i, CheckResult)]
    found = [i for i in items if isinstance(i, Finding)]
    ids = {r.check_id for r in results}
    assert {"AEG-AUDIT-KERNEL", "AEG-AUDIT-KERNEL-ASLR", "AEG-AUDIT-KERNEL-KPTR", "AEG-AUDIT-KERNEL-DMESG",
            "AEG-AUDIT-KERNEL-PTRACE", "AEG-AUDIT-KERNEL-BPF", "AEG-AUDIT-KERNEL-LINKS", "AEG-AUDIT-KERNEL-FIFOS",
            "AEG-AUDIT-KERNEL-DUMP", "AEG-AUDIT-KERNEL-SYSRQ", "AEG-AUDIT-KERNEL-ROOTKIT", "AEG-AUDIT-KERNEL-HIDDENMOD",
            "AEG-AUDIT-KERNEL-MAC"} <= ids
    assert "AEG-AUDIT-KERNEL" not in {f.rule_id for f in found}  # the summary never becomes a finding of its own
    summary = next(r for r in results if r.check_id == "AEG-AUDIT-KERNEL")
    assert summary.status == CheckStatus.FAIL and "problem(s) found" in summary.detail
    assert len(found) == len(results) - 1
    for f in found:
        assert f.rule_id in ids and f.title and f.description and f.recommendation and f.location and f.evidence
        assert set(f.mitre) <= ALLOWED_MITRE
        json.dumps(f.to_dict())


def test_summary_status_follows_the_worst_severity(tmp_path):
    (low, _), (high, _) = (run_kernel(make_tree(tmp_path, sysctl={"kernel/kptr_restrict": "0"})),
                           run_kernel(make_tree(tmp_path / "b", sysctl={"kernel/randomize_va_space": "0"})))
    assert low[0].status == CheckStatus.WARN and low[0].severity == Severity.LOW and "1 problem(s)" in low[0].detail
    assert high[0].status == CheckStatus.FAIL and high[0].severity == Severity.HIGH


def test_kernel_check_is_registered_for_linux_only():
    assert sa.check_linux_kernel in sa.LINUX_CHECKS
    assert sa.check_linux_kernel not in sa.WINDOWS_CHECKS and sa.check_linux_kernel not in sa.MAC_CHECKS


# ---------------------------------------------------------------- this machine
@linux_only
def test_check_runs_against_the_real_proc_and_sys():
    env = sa.AuditEnv(today=TODAY)
    checks = sa.check_linux_kernel(env)
    assert checks and checks[0].key == "KERNEL" and checks[0].title == "Kernel hardening and integrity"
    for c in checks:
        assert isinstance(c, sa.Check) and c.status in (CheckStatus.PASS, CheckStatus.WARN, CheckStatus.FAIL, CheckStatus.SKIP)
        assert c.to_result().check_id.startswith("AEG-AUDIT-KERNEL")
        f = c.to_finding()
        if f:
            json.dumps(f.to_dict())
            assert f.recommendation and f.location


@linux_only
def test_check_reads_the_real_kernel_when_container_detection_is_bypassed(monkeypatch):
    monkeypatch.setattr(sa, "detect_container", lambda root=None: "")
    env = sa.AuditEnv(today=TODAY)
    checks = sa.check_linux_kernel(env)
    assert checks[0].key == "KERNEL"
    if checks[0].status != CheckStatus.SKIP:
        facts = env.facts["linux_kernel"]
        assert facts["sysctl"] and all(isinstance(v, int) for v in facts["sysctl"].values())
        assert isinstance(facts["hidden_modules"], list) and checks[0].evidence is facts
    items = list(sa.run_checks(env, [sa.check_linux_kernel]))
    assert not any(isinstance(i, CheckResult) and i.status == CheckStatus.ERROR for i in items)
