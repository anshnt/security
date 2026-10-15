"""File-integrity monitoring tests."""

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from aegis.core.models import Category, Severity
from aegis.tools import integrity as fim


@pytest.fixture
def cfg(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    return SimpleNamespace(home=home)


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "watched"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "hosts").write_text("127.0.0.1 localhost\n")
    (root / "etc" / "motd").write_text("hello\n")
    (root / "sudoers").write_text("root ALL=(ALL) ALL\n")
    (root / "startup").mkdir()
    (root / "startup" / "ok.lnk").write_text("a")
    return root


def by_title(findings):
    return {f.title.split(": ", 1)[-1]: f for f in findings}


def test_baseline_created_with_hashes(cfg, tree):
    b = fim.create_baseline(cfg, [tree])
    saved = json.loads((cfg.home / "integrity_baseline.json").read_text())
    assert saved["roots"] == [str(tree)] and b["count"] == 4
    entry = saved["files"][fim._key(tree / "etc" / "hosts")]
    assert len(entry["sha256"]) == 64 and entry["size"] == len("127.0.0.1 localhost\n")
    assert fim.compare_baseline(cfg) == []


def test_modified_new_deleted(cfg, tree):
    fim.create_baseline(cfg, [tree])
    (tree / "etc" / "motd").write_text("changed\n")
    (tree / "etc" / "hosts").write_text("127.0.0.1 localhost\n6.6.6.6 bank.example\n")
    (tree / "startup" / "evil.lnk").write_text("x")
    (tree / "startup" / "ok.lnk").unlink()
    (tree / "sudoers").unlink()
    f = by_title(fim.compare_baseline(cfg))
    assert f["motd"].rule_id == "AEG-INTEG-MOD" and f["motd"].severity == Severity.MEDIUM
    assert f["hosts"].severity == Severity.HIGH and f["hosts"].rule_id == "AEG-INTEG-MOD"
    assert f["hosts"].evidence["old_sha256"] != f["hosts"].evidence["new_sha256"]
    assert f["evil.lnk"].rule_id == "AEG-INTEG-NEW" and f["evil.lnk"].severity == Severity.MEDIUM
    assert f["ok.lnk"].rule_id == "AEG-INTEG-DEL" and f["ok.lnk"].severity == Severity.MEDIUM
    assert f["sudoers"].rule_id == "AEG-INTEG-DEL"
    for x in f.values():
        assert x.category == Category.INTEGRITY and x.location and x.mitre and x.recommendation
        json.dumps(x.to_dict())


def test_critical_new_files_are_high(cfg, tmp_path):
    root = tmp_path / "ssh"
    root.mkdir()
    (root / "id_rsa.pub").write_text("k")
    fim.create_baseline(cfg, [root])
    (root / "authorized_keys").write_text("ssh-rsa AAAA attacker\n")
    f = fim.compare_baseline(cfg)
    assert len(f) == 1 and f[0].severity == Severity.HIGH and "T1098.004" in f[0].mitre


def test_ld_so_preload_and_sudoers_high(cfg, tmp_path):
    (tmp_path / "ld.so.preload").write_text("/lib/a.so\n")
    (tmp_path / "sudoers").write_text("x\n")
    fim.create_baseline(cfg, [tmp_path / "ld.so.preload", tmp_path / "sudoers"])
    (tmp_path / "ld.so.preload").write_text("/lib/evil.so\n")
    (tmp_path / "sudoers").write_text("x\nuser ALL=(ALL) NOPASSWD: ALL\n")
    assert {f.severity for f in fim.compare_baseline(cfg)} == {Severity.HIGH}


def test_no_baseline_gives_info(cfg):
    f = fim.compare_baseline(cfg)
    assert len(f) == 1 and f[0].severity == Severity.INFO and f[0].rule_id == "AEG-INTEG-NOBASE"


def test_unchanged_after_touch(cfg, tree):
    fim.create_baseline(cfg, [tree])
    os.utime(tree / "etc" / "motd", (1, 1))  # mtime change alone is not a modification
    assert fim.compare_baseline(cfg) == []


def test_baseline_is_replaced_atomically(cfg, tree):
    fim.create_baseline(cfg, [tree])
    (tree / "etc" / "motd").write_text("v2\n")
    fim.create_baseline(cfg, [tree])
    assert fim.compare_baseline(cfg) == []
    assert not list(cfg.home.glob("*.tmp"))


def test_missing_paths_ignored_and_default_paths_work(cfg, tmp_path):
    b = fim.create_baseline(cfg, [tmp_path / "does-not-exist"])
    assert b["count"] == 0
    defaults = fim.default_paths()
    assert defaults and all(isinstance(p, Path) for p in defaults)
    b2 = fim.create_baseline(cfg)  # real system files, must not raise even when unreadable (e.g. /etc/shadow)
    assert b2["count"] >= 0
    assert fim.compare_baseline(cfg) == [] or all(f.category == "integrity" for f in fim.compare_baseline(cfg))


def test_unreadable_files_are_skipped_not_reported(cfg, tmp_path, monkeypatch):
    root = tmp_path / "w"
    root.mkdir()
    f = root / "secret"
    f.write_text("x")
    real_hash = fim._hash
    monkeypatch.setattr(fim, "_hash", lambda p: {"sha256": "", "error": "PermissionError"})
    fim.create_baseline(cfg, [root])
    monkeypatch.setattr(fim, "_hash", real_hash)
    assert fim.compare_baseline(cfg) == []


def test_symlinks_not_followed(cfg, tmp_path):
    root = tmp_path / "w"
    root.mkdir()
    target = tmp_path / "outside"
    target.write_text("x")
    try:
        (root / "link").symlink_to(target)
    except OSError:
        pytest.skip("symlinks unavailable")
    assert fim.create_baseline(cfg, [root])["count"] == 0
