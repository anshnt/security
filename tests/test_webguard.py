"""Tests for aegis.protect.webguard: hosts-file managed block (LF / CRLF / BOM / mixed files), caps and safety
filters, DNS flush, Windows Firewall / nftables / iptables command generation and chunking (mocked run/powershell),
admin refusals. Platform-specific paths are selected by monkeypatching the module's IS_WINDOWS / IS_MAC, so the
file passes on Linux and Windows CI."""

import base64
import ipaddress
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from aegis.core.config import Config
from aegis.protect import webguard as wg

BEGIN, END = wg.BLOCK_BEGIN.encode(), wg.BLOCK_END.encode()

ORIGINALS = {
    "lf": b"127.0.0.1 localhost\n::1 localhost\n# my entry\n10.0.0.5 nas.home\n",
    "crlf": b"127.0.0.1 localhost\r\n# my entry\r\n10.0.0.5 nas.home\r\n",
    "bom_crlf": b"\xef\xbb\xbf127.0.0.1 localhost\r\n10.0.0.5 nas.home\r\n",
    "bom_lf": b"\xef\xbb\xbf# hosts\n127.0.0.1 localhost\n",
    "mixed": b"127.0.0.1 localhost\r\n10.0.0.5 nas.home\n# x\r\n",
    "odd_spacing": b"127.0.0.1\tlocalhost   \n  \n\t# indented comment\n   10.1.1.1   a.home   b.home\n",
    "latin1": "# caf\xe9 - not UTF-8\n127.0.0.1 localhost\n".encode("latin-1"),
}
DOMAINS = ["evil.example", "malware.test.example", "phish.example.org"]


@pytest.fixture
def cfg():
    return Config.load()


@pytest.fixture
def sigs():
    return SimpleNamespace(bad_domains=set(DOMAINS), bad_ips=set(), bad_networks=[])


@pytest.fixture
def calls(monkeypatch):
    """Admin + recording fake `run` (DNS flush etc.) on a Linux-flavoured module."""
    log = []
    monkeypatch.setattr(wg, "is_admin", lambda: True)
    monkeypatch.setattr(wg, "IS_WINDOWS", False)
    monkeypatch.setattr(wg, "IS_MAC", False)
    monkeypatch.setattr(wg, "_which", lambda n: None)
    monkeypatch.setattr(wg, "run", lambda argv, timeout=60, input_text=None: (log.append(list(argv)) or (0, "", "")))
    return log


def hosts(tmp_path, content: bytes) -> Path:
    p = tmp_path / "hosts"
    p.write_bytes(content)
    return p


def block_of(data: bytes) -> bytes:
    b, e = data.index(BEGIN), data.index(END) + len(END)
    return data[b:e]


# =========================================================================== managed block
@pytest.mark.parametrize("name", sorted(ORIGINALS))
def test_enable_appends_block_and_keeps_every_user_byte(name, tmp_path, cfg, sigs, calls):
    original = ORIGINALS[name]
    p = hosts(tmp_path, original)
    r = wg.enable_web_protection(cfg, sigs, hosts_file=p)
    assert r["ok"] and r["changed"], r
    new = p.read_bytes()
    assert new.startswith(original)  # user lines (bytes, BOM, line endings, odd spacing) untouched
    assert new.count(BEGIN) == 1 and new.count(END) == 1
    if original.startswith(b"\xef\xbb\xbf"):
        assert new.count(b"\xef\xbb\xbf") == 1
    for d in DOMAINS:
        assert f"0.0.0.0 {d}".encode() in new
    # the block uses the file's own dominant line ending
    block = new[len(original):]
    if b"\r\n" in original and original.count(b"\r\n") >= original.count(b"\n") - original.count(b"\r\n"):
        assert block.count(b"\n") == block.count(b"\r\n")
    else:
        assert b"\r" not in block
    assert wg.read_block_domains(new) == sorted(DOMAINS)


@pytest.mark.parametrize("name", sorted(ORIGINALS))
def test_disable_restores_the_original_file_exactly(name, tmp_path, cfg, sigs, calls):
    original = ORIGINALS[name]
    p = hosts(tmp_path, original)
    wg.enable_web_protection(cfg, sigs, hosts_file=p)
    r = wg.disable_web_protection(cfg, hosts_file=p)
    assert r["ok"] and r["changed"], r
    assert p.read_bytes() == original  # byte for byte, including CRLF and BOM


def test_no_trailing_newline_gets_one_before_the_block(tmp_path, cfg, sigs, calls):
    p = hosts(tmp_path, b"127.0.0.1 localhost\n10.0.0.5 nas.home")
    wg.enable_web_protection(cfg, sigs, hosts_file=p)
    assert p.read_bytes().startswith(b"127.0.0.1 localhost\n10.0.0.5 nas.home\n# >>>")
    wg.disable_web_protection(cfg, hosts_file=p)
    assert p.read_bytes() == b"127.0.0.1 localhost\n10.0.0.5 nas.home\n"  # only the missing final newline remains


def test_empty_and_missing_hosts_file(tmp_path, cfg, sigs, calls):
    p = hosts(tmp_path, b"")
    assert wg.enable_web_protection(cfg, sigs, hosts_file=p)["ok"]
    assert p.read_bytes().startswith(BEGIN)
    missing = tmp_path / "other" / "hosts"
    missing.parent.mkdir()
    assert wg.enable_web_protection(cfg, sigs, hosts_file=missing)["ok"] and missing.exists()


def test_update_replaces_the_block_in_place_and_keeps_text_around_it(tmp_path, cfg, sigs, calls):
    p = hosts(tmp_path, ORIGINALS["crlf"])
    wg.enable_web_protection(cfg, sigs, hosts_file=p)
    first = p.read_bytes()
    with_tail = first + b"192.168.1.9 added-later.home\r\n# my own footer\r\n"
    p.write_bytes(with_tail)
    sigs.bad_domains = {"new1.example", "new2.example"}
    r = wg.enable_web_protection(cfg, sigs, hosts_file=p)
    assert r["ok"] and r["changed"] and "updated" in r["message"]
    new = p.read_bytes()
    head = first[:first.index(BEGIN)]
    assert new.startswith(head) and new.endswith(b"192.168.1.9 added-later.home\r\n# my own footer\r\n")
    assert wg.read_block_domains(new) == ["new1.example", "new2.example"]
    assert new.count(BEGIN) == 1
    assert wg.web_protection_status(cfg, hosts_file=p)["details"]["entries"] == 2


def test_enable_twice_is_idempotent_and_makes_no_extra_backup(tmp_path, cfg, sigs, calls):
    p = hosts(tmp_path, ORIGINALS["lf"])
    wg.enable_web_protection(cfg, sigs, hosts_file=p)
    after = p.read_bytes()
    n = len(list(cfg.backups_dir.glob("webhosts-*.json")))
    r = wg.enable_web_protection(cfg, sigs, hosts_file=p)
    assert r["ok"] and not r["changed"] and "up to date" in r["message"]
    assert p.read_bytes() == after and len(list(cfg.backups_dir.glob("webhosts-*.json"))) == n


def test_duplicate_blocks_collapse_to_one(tmp_path, cfg, sigs, calls):
    one = wg.insert_or_update_block(ORIGINALS["lf"], ["a.example"])
    with_user_line = one + b"10.9.9.9 mid.home\n"
    both = with_user_line + b"".join(x.encode() for x in wg.block_lines(["z.example"], "\n"))  # a second block
    assert both.count(BEGIN) == 2
    fixed = wg.insert_or_update_block(both, ["only.example"])
    assert fixed.count(BEGIN) == 1 and wg.read_block_domains(fixed) == ["only.example"]
    assert b"10.9.9.9 mid.home" in fixed and fixed.startswith(ORIGINALS["lf"])
    stripped, removed = wg.remove_block(both)
    assert removed and BEGIN not in stripped and stripped == ORIGINALS["lf"] + b"10.9.9.9 mid.home\n"


def test_damaged_block_is_never_guessed_at(tmp_path, cfg, sigs, calls):
    broken = ORIGINALS["lf"] + BEGIN + b"\n0.0.0.0 x.example\n10.0.0.9 my-own-line.home\n"  # no end marker
    p = hosts(tmp_path, broken)
    for fn in (lambda: wg.enable_web_protection(cfg, sigs, hosts_file=p), lambda: wg.disable_web_protection(cfg, hosts_file=p)):
        r = fn()
        assert r["ok"] is False and "end marker" in r["message"] and p.read_bytes() == broken
    assert wg.web_protection_status(cfg, hosts_file=p)["ok"] is False
    p.write_bytes(ORIGINALS["lf"] + BEGIN + b"\n" + BEGIN + b"\n" + END + b"\n")  # nested begin
    assert "damaged" in wg.enable_web_protection(cfg, sigs, hosts_file=p)["message"]


def test_utf16_hosts_file_is_left_alone(tmp_path, cfg, sigs, calls):
    raw = "127.0.0.1 localhost\n".encode("utf-16")
    p = hosts(tmp_path, raw)
    r = wg.enable_web_protection(cfg, sigs, hosts_file=p)
    assert r["ok"] is False and "UTF-16" in r["message"] and p.read_bytes() == raw


def test_disable_when_not_enabled_is_a_clean_no_op(tmp_path, cfg, calls):
    p = hosts(tmp_path, ORIGINALS["lf"])
    r = wg.disable_web_protection(cfg, hosts_file=p)
    assert r["ok"] and not r["changed"] and "not enabled" in r["message"] and p.read_bytes() == ORIGINALS["lf"]
    assert wg.disable_web_protection(cfg, hosts_file=tmp_path / "nope")["ok"]


def test_marker_text_inside_a_user_comment_is_not_a_block(tmp_path, cfg, sigs, calls):
    original = b"# note: never type # >>> Aegis web protection >>> by hand\n127.0.0.1 localhost\n"
    p = hosts(tmp_path, original)
    wg.enable_web_protection(cfg, sigs, hosts_file=p)
    assert p.read_bytes().startswith(original) and wg.disable_web_protection(cfg, hosts_file=p)["changed"]
    assert p.read_bytes() == original


# =========================================================================== domain selection
def test_collect_block_domains_filters_and_caps():
    sigs = SimpleNamespace(bad_domains={"Evil.Example", "evil.example.", "microsoft.com", "login.microsoftonline.com",
                                        "download.windowsupdate.com", "kaspersky.com", "1.2.3.4", "*.wild.example",
                                        "single", "raw.githubusercontent.com", "ok.example", "sub.ok.example", "keep.example"})
    out, stats = wg.collect_block_domains(sigs, ["Mine.Example", "bad..domain", "keep.example"], allow=["ok.example"])
    assert out == ["mine.example", "keep.example", "evil.example"]  # user entries first, then the sorted feed
    assert stats["protected"] == 5 and stats["allowlisted"] == 2 and stats["invalid"] >= 4 and stats["truncated"] == 0
    many = SimpleNamespace(bad_domains={f"bad{i:02d}.example" for i in range(20)})
    out, stats = wg.collect_block_domains(many, ["u1.example", "u2.example"], max_entries=5)
    assert out == ["u1.example", "u2.example", "bad00.example", "bad01.example", "bad02.example"]
    assert stats["truncated"] == 17
    out, _ = wg.collect_block_domains(many, [f"user{i}.example" for i in range(9)], max_entries=5)
    assert len(out) == 5 and all(d.startswith("user") for d in out)  # the user's own list wins over the feed


def test_look_alike_domains_are_not_mistaken_for_protected_ones():
    # the feed exists to block these; only the real vendor domains (and their sub-domains) are protected
    for lookalike in ("paypal-secure-login.example", "microsoft.com.evil.example", "my-bank-login.example",
                      "windowsupdate.com.evil.example", "evilx.com", "notmicrosoft.com"):
        assert wg.is_protected_domain(lookalike) is False, lookalike
    for real in ("paypal.com", "www.paypal.com", "update.microsoft.com", "kaspersky.com", "dl.google.com",
                 "raw.githubusercontent.com", "x.com"):
        assert wg.is_protected_domain(real) is True, real
    out, stats = wg.collect_block_domains(SimpleNamespace(bad_domains={"paypal-secure-login.example", "paypal.com"}))
    assert out == ["paypal-secure-login.example"] and stats["protected"] == 1


def test_normalize_and_parse_domain_list():
    assert wg.normalize_domain("HTTP://Evil.Example/path?x=1") == "evil.example"
    assert wg.normalize_domain("1.2.3.4") is None and wg.normalize_domain("::1") is None
    assert wg.normalize_domain("localhost") is None and wg.normalize_domain("a b.example") is None
    assert wg.normalize_domain("x_y.example") == "x_y.example" and wg.normalize_domain("") is None
    text = "# c\n0.0.0.0 one.example two.example  # trailing\nthree.example\n127.0.0.1 localhost\nhttp://four.example/x\nbad\n\n"
    assert wg.parse_domain_list(text) == ["one.example", "two.example", "three.example", "four.example"]


def test_user_blocklist_and_allowlist_files(tmp_path, cfg, sigs, calls):
    wg.user_blocklist_path(cfg).write_text("# mine\nmy-tracker.example\n0.0.0.0 other.example\n", encoding="utf-8")
    wg.user_allowlist_path(cfg).write_text("phish.example.org\n", encoding="utf-8")
    p = hosts(tmp_path, ORIGINALS["lf"])
    r = wg.enable_web_protection(cfg, sigs, hosts_file=p, user_domains=["extra.example"])
    domains = wg.read_block_domains(p.read_bytes())
    assert domains[:3] == ["my-tracker.example", "other.example", "extra.example"]
    assert "phish.example.org" not in domains and "evil.example" in domains
    st = wg.web_protection_status(cfg, hosts_file=p)["details"]
    assert st["user_blocklist_entries"] == 2 and st["user_allowlist_entries"] == 1 and r["details"]["allowlisted"] == 1


def test_cap_is_enforced_with_a_warning(tmp_path, cfg, calls):
    sigs = SimpleNamespace(bad_domains={f"bad{i:03d}.example" for i in range(60)})
    p = hosts(tmp_path, ORIGINALS["lf"])
    r = wg.enable_web_protection(cfg, sigs, hosts_file=p, max_entries=25)
    assert r["ok"] and r["details"]["entries"] == 25 and r["details"]["truncated"] == 35
    assert any("limit of 25" in w for w in r["details"]["warnings"])
    assert len(wg.read_block_domains(p.read_bytes())) == 25
    assert wg.MAX_HOSTS_ENTRIES == 50_000


def test_windows_dns_client_performance_warning(tmp_path, cfg, sigs, calls, monkeypatch):
    monkeypatch.setattr(wg, "IS_WINDOWS", True)
    monkeypatch.setattr(wg, "WINDOWS_PERF_WARN_LINES", 5)
    p = hosts(tmp_path, ORIGINALS["crlf"])
    r = wg.enable_web_protection(cfg, sigs, hosts_file=p)
    assert any("DNS Client" in w for w in r["details"]["warnings"])
    assert ["ipconfig", "/flushdns"] in calls
    monkeypatch.setattr(wg, "IS_WINDOWS", False)
    monkeypatch.setattr(wg, "WINDOWS_PERF_WARN_LINES", 5)
    r = wg.enable_web_protection(cfg, SimpleNamespace(bad_domains={"zzz.example"}), hosts_file=p)
    assert not any("DNS Client" in w for w in r["details"]["warnings"])


def test_no_domains_loaded_is_reported_not_written(tmp_path, cfg, calls):
    p = hosts(tmp_path, ORIGINALS["lf"])
    r = wg.enable_web_protection(cfg, SimpleNamespace(bad_domains=set()), hosts_file=p)
    assert r["ok"] is False and "aegis update" in r["message"] and p.read_bytes() == ORIGINALS["lf"]


# =========================================================================== write path, backups, privileges
def test_backup_holds_the_raw_original_and_restores_byte_for_byte(tmp_path, cfg, sigs, calls):
    p = hosts(tmp_path, ORIGINALS["bom_crlf"])
    r = wg.enable_web_protection(cfg, sigs, hosts_file=p)
    (b,) = cfg.backups_dir.glob("webhosts-*.json")
    doc = json.loads(b.read_text())
    assert r["details"]["backup"] == str(b) and doc["kind"] == "webhosts" and doc["path"] == str(p)
    assert base64.b64decode(doc["content_b64"]) == ORIGINALS["bom_crlf"] and doc["had_aegis_block"] is False
    assert not list(tmp_path.glob("*.aegis-tmp"))  # no stray temp files next to the hosts file


def test_backups_are_pruned(tmp_path, cfg, sigs, calls, monkeypatch):
    monkeypatch.setattr(wg, "KEEP_HOSTS_BACKUPS", 2)
    p = hosts(tmp_path, ORIGINALS["lf"])
    for i in range(5):  # a user edit between changes makes each backup distinct
        p.write_bytes(ORIGINALS["lf"] + f"10.0.0.{i} edit{i}.home\n".encode())
        wg.enable_web_protection(cfg, SimpleNamespace(bad_domains={f"d{i}.example"}), hosts_file=p)
    assert len(list(cfg.backups_dir.glob("webhosts-*.json"))) == 2


def test_atomic_replace_falls_back_to_in_place_write(tmp_path, cfg, sigs, calls, monkeypatch):
    def refuse(*a, **k):
        raise OSError("replace refused (file locked / bind mount)")

    monkeypatch.setattr(wg, "atomic_write_bytes", refuse)
    p = hosts(tmp_path, ORIGINALS["lf"])
    r = wg.enable_web_protection(cfg, sigs, hosts_file=p)
    assert r["ok"] and wg.read_block_domains(p.read_bytes()) == sorted(DOMAINS)


def test_symlinked_hosts_file_is_written_through_the_link(tmp_path, cfg, sigs, calls):
    real = tmp_path / "real_hosts"
    real.write_bytes(ORIGINALS["lf"])
    link = tmp_path / "hosts"
    try:
        link.symlink_to(real)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    wg.enable_web_protection(cfg, sigs, hosts_file=link)
    assert link.is_symlink() and BEGIN in real.read_bytes()


def test_non_admin_is_refused_with_a_clear_message(tmp_path, cfg, sigs, monkeypatch):
    p = hosts(tmp_path, ORIGINALS["lf"])
    monkeypatch.setattr(wg, "is_admin", lambda: False)
    for r in (wg.enable_web_protection(cfg, sigs, hosts_file=p), wg.disable_web_protection(cfg, hosts_file=p)):
        assert r["ok"] is False and not r["changed"]
        assert "Administrator rights are required" in r["message"] and r["details"]["needs_admin"] is True
    assert p.read_bytes() == ORIGINALS["lf"]
    # with the protection already on, a non-elevated refresh/disable is refused too and changes nothing
    monkeypatch.setattr(wg, "is_admin", lambda: True)
    wg.enable_web_protection(cfg, sigs, hosts_file=p)
    on = p.read_bytes()
    monkeypatch.setattr(wg, "is_admin", lambda: False)
    sigs.bad_domains = {"fresh.example"}
    for r in (wg.refresh_web_protection(cfg, sigs, hosts_file=p), wg.disable_web_protection(cfg, hosts_file=p)):
        assert r["ok"] is False and "Administrator rights are required" in r["message"]
    assert p.read_bytes() == on
    # dry runs and status never need elevation
    assert wg.enable_web_protection(cfg, sigs, hosts_file=p, dry_run=True)["ok"]
    assert wg.web_protection_status(cfg, hosts_file=p)["details"]["enabled"] is True
    assert p.read_bytes() == on


def test_dry_run_writes_nothing(tmp_path, cfg, sigs, calls):
    p = hosts(tmp_path, ORIGINALS["lf"])
    r = wg.enable_web_protection(cfg, sigs, hosts_file=p, dry_run=True)
    assert r["ok"] and not r["changed"] and r["details"]["dry_run"] and "dry run" in r["message"]
    assert p.read_bytes() == ORIGINALS["lf"] and not list(cfg.backups_dir.glob("webhosts-*"))
    wg.enable_web_protection(cfg, sigs, hosts_file=p)
    on = p.read_bytes()
    assert wg.disable_web_protection(cfg, hosts_file=p, dry_run=True)["details"]["dry_run"] and p.read_bytes() == on


def test_functions_never_raise(tmp_path, cfg, sigs, calls, monkeypatch):
    r = wg.enable_web_protection(cfg, sigs, hosts_file=tmp_path / "no_such_dir" / "hosts")
    assert set(r) == {"ok", "changed", "message", "details"} and r["ok"] is False and not r["changed"]
    p = hosts(tmp_path, ORIGINALS["lf"])

    def denied(*a, **k):
        raise PermissionError("denied")

    monkeypatch.setattr(wg, "_write_hosts", denied)
    r = wg.enable_web_protection(cfg, sigs, hosts_file=p)
    assert r["ok"] is False and "denied" in r["message"] and r["details"]["needs_admin"] is True
    assert wg.disable_web_protection(cfg, hosts_file=p)["ok"]  # nothing to remove: still a clean result
    monkeypatch.setattr(wg, "collect_block_domains", lambda *a, **k: 1 / 0)
    assert wg.enable_web_protection(cfg, sigs, hosts_file=p)["ok"] is False


def test_status_and_refresh(tmp_path, cfg, sigs, calls):
    p = hosts(tmp_path, ORIGINALS["lf"])
    st = wg.web_protection_status(cfg, hosts_file=p)
    assert st["ok"] and st["details"]["enabled"] is False and "OFF" in st["message"]
    off = wg.refresh_web_protection(cfg, sigs, hosts_file=p)
    assert off["ok"] and not off["changed"] and "off" in off["message"] and BEGIN not in p.read_bytes()  # never turns itself on
    wg.enable_web_protection(cfg, sigs, hosts_file=p)
    st = wg.web_protection_status(cfg, hosts_file=p)
    assert st["details"]["enabled"] is True and st["details"]["entries"] == 3 and st["details"]["updated"] and "ON" in st["message"]
    same = wg.refresh_web_protection(cfg, sigs, hosts_file=p)
    assert same["ok"] and not same["changed"]
    sigs.bad_domains = {"fresh.example"}
    fresh = wg.refresh_web_protection(cfg, sigs, hosts_file=p)
    assert fresh["changed"] and wg.read_block_domains(p.read_bytes()) == ["fresh.example"]
    assert wg.web_protection_status(cfg, hosts_file=tmp_path / "gone")["details"]["enabled"] is False


def test_flush_dns_commands_per_platform(monkeypatch):
    log = []
    monkeypatch.setattr(wg, "run", lambda argv, timeout=60, input_text=None: (log.append(list(argv)) or (0, "", "")))
    monkeypatch.setattr(wg, "IS_WINDOWS", True)
    assert wg.flush_dns()[0] and log == [["ipconfig", "/flushdns"]]
    log.clear()
    monkeypatch.setattr(wg, "IS_WINDOWS", False)
    monkeypatch.setattr(wg, "IS_MAC", True)
    assert wg.flush_dns()[0] and log[0] == ["dscacheutil", "-flushcache"] and ["killall", "-HUP", "mDNSResponder"] in log
    log.clear()
    monkeypatch.setattr(wg, "IS_MAC", False)
    monkeypatch.setattr(wg, "_which", lambda n: "/usr/bin/" + n if n == "resolvectl" else None)
    assert wg.flush_dns()[0] and log == [["resolvectl", "flush-caches"]]
    monkeypatch.setattr(wg, "_which", lambda n: None)
    ok, msg = wg.flush_dns()
    assert ok is False and "no DNS cache" in msg  # best effort: never an exception
    monkeypatch.setattr(wg, "IS_WINDOWS", True)
    monkeypatch.setattr(wg, "run", lambda *a, **k: (1, "", "boom"))
    assert wg.flush_dns()[0] is False


def test_default_hosts_path_per_platform(monkeypatch):
    monkeypatch.setattr(wg, "IS_WINDOWS", False)
    assert wg.hosts_path() == Path("/etc/hosts")
    monkeypatch.setattr(wg, "IS_WINDOWS", True)
    monkeypatch.setattr(wg, "windows_dir", lambda: Path("C:/Windows"))
    assert wg.hosts_path().parts[-4:] == ("System32", "drivers", "etc", "hosts")


# =========================================================================== IP blocking: selection / generation
def ip_sigs(ips=(), nets=()):
    return SimpleNamespace(bad_ips=set(ips), bad_networks=[ipaddress.ip_network(n) for n in nets], bad_domains=set())


def test_collect_block_addresses_keeps_only_safe_public_targets():
    s = ip_sigs(
        ips=["10.0.0.1", "127.0.0.1", "169.254.1.1", "8.8.8.8", "1.1.1.1", "224.0.0.1", "45.9.9.9", "45.9.9.10",
             "2001:db8::1", "2a02:6b8::1", "junk", "0.0.0.0"],
        nets=["45.9.9.0/24", "0.0.0.0/0", "8.8.0.0/16", "100.64.0.0/10", "10.0.0.0/8", "198.51.100.0/24",
              "2a02:6b8::/32", "2a02:6b8:1::/48", "45.8.0.0/15", "93.184.216.0/24"])
    out, stats = wg.collect_block_addresses(s)
    assert out == ["45.9.9.0/24", "93.184.216.0/24", "2a02:6b8::1", "2a02:6b8:1::/48"]  # IPv4 first; sorted; collapsed
    assert stats["candidates"] == 22 and stats["skipped_unsafe"] >= 13
    for bad in ("8.8.8.8", "1.1.1.1", "10.0.0.1", "127.0.0.1"):
        assert bad not in out  # resolvers, private and loopback space can never be blocked
    big = ip_sigs(ips=[f"45.{i // 250}.{i % 250}.7" for i in range(30)])
    out, stats = wg.collect_block_addresses(big, max_entries=10)
    assert len(out) == 10 and stats["truncated"] == 20


def test_chunking():
    addrs = [f"45.{i // 250}.{i % 250}.7" for i in range(450)]
    chunks = wg.chunk_addresses(addrs)
    assert [len(c) for c in chunks] == [200, 200, 50] and sum(chunks, []) == addrs
    assert wg.chunk_addresses([]) == [] and wg.FW_CHUNK == 200


def test_powershell_script_generation():
    addrs = [f"45.{i // 250}.{i % 250}.7" for i in range(450)]
    chunks = wg.chunk_addresses(addrs)
    one = wg.powershell_add_script(chunks)
    assert one.startswith("$ErrorActionPreference='Stop';$g='Aegis Threat Intel';")
    assert "Remove-NetFirewallRule" in one and one.index("Remove-NetFirewallRule") < one.index("New-NetFirewallRule")
    for n in (1, 2, 3):
        assert f"-DisplayName 'Aegis-Block-{n}'" in one
    assert one.count("New-NetFirewallRule") == 3 and one.count("-Direction Outbound -Action Block") == 3
    assert "-Group $g" in one and "-Profile Any" in one
    for a in addrs:
        assert f"'{a}'" in one
    # long lists are spread over several scripts (Windows caps a command line at 32,767 characters)
    scripts = wg.powershell_add_scripts(chunks, max_chars=5000)
    assert len(scripts) >= 2 and all(len(s) < 9000 for s in scripts)
    assert "Remove-NetFirewallRule" in scripts[0] and all("Remove-NetFirewallRule" not in s for s in scripts[1:])
    assert sum(s.count("New-NetFirewallRule") for s in scripts) == 3
    names = [n for s in scripts for n in (f"Aegis-Block-{i}" for i in (1, 2, 3)) if f"'{n}'" in s]
    assert names == ["Aegis-Block-1", "Aegis-Block-2", "Aegis-Block-3"]
    assert wg.powershell_add_scripts([])[0].count("New-NetFirewallRule") == 0
    assert "Aegis Threat Intel" in wg.powershell_remove_script() and "Aegis Threat Intel" in wg.powershell_count_script()
    big = wg.chunk_addresses([f"45.{i // 250}.{i % 250}.7" for i in range(wg.MAX_IP_ENTRIES)])
    assert all(len(s) < wg.PS_MAX_SCRIPT_CHARS + 6000 for s in wg.powershell_add_scripts(big))


def test_netsh_command_generation():
    chunks = wg.chunk_addresses([f"45.{i // 250}.{i % 250}.7" for i in range(450)])
    cmds = wg.netsh_add_commands(chunks)
    assert len(cmds) == 3
    first = cmds[0]
    assert first[:5] == ["netsh", "advfirewall", "firewall", "add", "rule"] and "name=Aegis-Block-1" in first
    assert "dir=out" in first and "action=block" in first and "enable=yes" in first and "profile=any" in first
    remote = next(a for a in first if a.startswith("remoteip="))
    assert len(remote[len("remoteip="):].split(",")) == 200
    assert all(" " not in a for a in first)  # no quoting surprises for netsh
    assert wg.netsh_delete_command(2) == ["netsh", "advfirewall", "firewall", "delete", "rule", "name=Aegis-Block-2"]


def test_malformed_addresses_never_reach_a_command():
    for bad in ("1.2.3.4'; calc; '", "1.2.3.4 -j ACCEPT", "$(x)", "evil.example"):
        with pytest.raises(ValueError):
            wg.powershell_add_script([[bad]])
        with pytest.raises(ValueError):
            wg.netsh_add_commands([[bad]])
        with pytest.raises(ValueError):
            wg.nft_script([bad])
        with pytest.raises(ValueError):
            wg.iptables_restore_script([bad], False)


def test_nft_script():
    s = wg.nft_script(["45.9.9.0/24", "93.184.216.1", "2a02:6b8::1"])
    assert s.splitlines()[:3] == ["add table inet aegis", "delete table inet aegis", "table inet aegis {"]
    assert "set badv4 { type ipv4_addr; flags interval; elements = { 45.9.9.0/24, 93.184.216.1 } }" in s
    assert "set badv6 { type ipv6_addr; flags interval; elements = { 2a02:6b8::1 } }" in s
    assert "ip daddr @badv4 counter drop" in s and "ip6 daddr @badv6 counter drop" in s
    assert "hook output" in s and "policy accept" in s  # outbound only, never changes the default policy
    only4 = wg.nft_script(["45.9.9.0/24"])
    assert "badv6" not in only4 and only4.rstrip().endswith("}")


def test_iptables_script():
    s = wg.iptables_restore_script(["45.9.9.0/24", "2a02:6b8::1"], False)
    assert s.splitlines() == ["*filter", ":AEGIS - [0:0]", "-F AEGIS", "-A AEGIS -d 45.9.9.0/24 -j DROP", "COMMIT"]
    assert "-A AEGIS -d 2a02:6b8::1 -j DROP" in wg.iptables_restore_script(["45.9.9.0/24", "2a02:6b8::1"], True)


# =========================================================================== IP blocking: Windows
class FakeFirewall:
    def __init__(self):
        self.rules = 0
        self.scripts = []
        self.netsh = []
        self.fail_ps = False

    def powershell(self, script, timeout=90):
        self.scripts.append(script)
        if script == wg.powershell_count_script():
            return 0, f"{self.rules}\r\n", ""
        if script == wg.powershell_remove_script():
            self.rules = 0
            return 0, "", ""
        if "New-NetFirewallRule" in script:
            if self.fail_ps:
                return 1, "", "The term 'New-NetFirewallRule' is not recognized"
            if "Remove-NetFirewallRule" in script:
                self.rules = 0
            self.rules += script.count("New-NetFirewallRule")
            return 0, "", ""
        return 0, "", ""

    def run(self, argv, timeout=60, input_text=None):
        argv = list(argv)
        self.netsh.append(argv)
        if argv[:5] == ["netsh", "advfirewall", "firewall", "add", "rule"]:
            self.rules += 1
        elif argv[:5] == ["netsh", "advfirewall", "firewall", "delete", "rule"]:
            if not self.rules:
                return 1, "", "No rules match the specified criteria."
            self.rules -= 1
        return 0, "Ok.", ""


@pytest.fixture
def winfw(monkeypatch):
    fw = FakeFirewall()
    monkeypatch.setattr(wg, "IS_WINDOWS", True)
    monkeypatch.setattr(wg, "IS_MAC", False)
    monkeypatch.setattr(wg, "is_admin", lambda: True)
    monkeypatch.setattr(wg, "powershell", fw.powershell)
    monkeypatch.setattr(wg, "run", fw.run)
    return fw


def bad_ips(n=450):
    return ip_sigs(ips=[f"45.{i // 250}.{i % 250}.7" for i in range(n)])


def test_windows_enable_creates_chunked_rules_in_one_group(winfw, cfg):
    r = wg.enable_ip_blocking(cfg, bad_ips())
    assert r["ok"] and r["changed"] and r["details"]["rules"] == 3 and r["details"]["entries"] == 450
    assert r["details"]["group"] == "Aegis Threat Intel" and r["details"]["backend"] == "powershell"
    assert winfw.rules == 3 and not winfw.netsh
    st = wg.ip_blocking_status(cfg)
    assert st["ok"] and st["details"]["enabled"] and st["details"]["rules"] == 3 and "ON" in st["message"]
    state = json.loads((cfg.home / wg.IP_STATE_FILE).read_text())
    assert state["entries"] == 450 and state["backend"] == "powershell"


def test_windows_refresh_is_idempotent_and_replaces_the_group(winfw, cfg):
    wg.enable_ip_blocking(cfg, bad_ips())
    adds = sum("New-NetFirewallRule" in s for s in winfw.scripts)
    again = wg.enable_ip_blocking(cfg, bad_ips())
    assert again["ok"] and not again["changed"] and "up to date" in again["message"]
    assert sum("New-NetFirewallRule" in s for s in winfw.scripts) == adds  # nothing re-created
    changed = wg.enable_ip_blocking(cfg, bad_ips(210))  # feed changed: group removed, then re-added
    assert changed["changed"] and winfw.rules == 2 and "Remove-NetFirewallRule" in winfw.scripts[-1]
    winfw.rules = 0  # someone deleted the rules by hand: the state file alone must not fool us
    healed = wg.enable_ip_blocking(cfg, bad_ips(210))
    assert healed["changed"] and winfw.rules == 2


def test_windows_disable_removes_everything(winfw, cfg):
    wg.enable_ip_blocking(cfg, bad_ips())
    r = wg.disable_ip_blocking(cfg)
    assert r["ok"] and r["changed"] and winfw.rules == 0 and not (cfg.home / wg.IP_STATE_FILE).exists()
    assert wg.ip_blocking_status(cfg)["details"]["enabled"] is False
    again = wg.disable_ip_blocking(cfg)
    assert again["ok"] and not again["changed"] and "not enabled" in again["message"]


def test_windows_falls_back_to_netsh_when_powershell_cannot_create_rules(winfw, cfg):
    winfw.fail_ps = True
    r = wg.enable_ip_blocking(cfg, bad_ips())
    assert r["ok"] and r["details"]["backend"] == "netsh" and winfw.rules == 3
    adds = [a for a in winfw.netsh if a[3] == "add"]
    assert [a[5] for a in adds] == ["name=Aegis-Block-1", "name=Aegis-Block-2", "name=Aegis-Block-3"]
    winfw.fail_ps = False
    winfw.netsh.clear()
    d = wg.disable_ip_blocking(cfg)
    assert d["ok"] and winfw.rules == 0
    assert [a[5] for a in winfw.netsh if a[3] == "delete"] == ["name=Aegis-Block-1", "name=Aegis-Block-2", "name=Aegis-Block-3"]


def test_windows_failure_cleans_up_and_reports(winfw, cfg, monkeypatch):
    winfw.fail_ps = True
    monkeypatch.setattr(winfw, "run", lambda argv, timeout=60, input_text=None: (1, "", "Access is denied"))
    monkeypatch.setattr(wg, "run", winfw.run)
    r = wg.enable_ip_blocking(cfg, bad_ips(10))
    assert r["ok"] is False and "Access is denied" in r["message"] and not (cfg.home / wg.IP_STATE_FILE).exists()


def test_ip_blocking_dry_run_and_empty_feed(winfw, cfg):
    d = wg.enable_ip_blocking(cfg, bad_ips(), dry_run=True)
    assert d["ok"] and not d["changed"] and d["details"]["rules"] == 3 and not winfw.scripts
    e = wg.enable_ip_blocking(cfg, ip_sigs(ips=["10.0.0.1", "8.8.8.8"]))
    assert e["ok"] is False and "aegis update" in e["message"] and winfw.rules == 0


def test_ip_blocking_requires_admin_and_says_so(winfw, cfg, monkeypatch):
    monkeypatch.setattr(wg, "is_admin", lambda: False)
    for r in (wg.enable_ip_blocking(cfg, bad_ips()), wg.disable_ip_blocking(cfg)):
        assert r["ok"] is False and not r["changed"] and r["details"]["needs_admin"] is True
        assert "Administrator rights are required" in r["message"] and "Windows Firewall" in r["message"]
    assert winfw.rules == 0 and not winfw.scripts
    monkeypatch.setattr(wg, "IS_WINDOWS", False)
    monkeypatch.setattr(wg, "_which", lambda n: "/usr/sbin/nft")
    r = wg.enable_ip_blocking(cfg, bad_ips())
    assert r["ok"] is False and "Root privileges are required" in r["message"]


def test_refresh_ip_blocking_only_when_on(winfw, cfg):
    off = wg.refresh_ip_blocking(cfg, bad_ips())
    assert off["ok"] and not off["changed"] and winfw.rules == 0
    wg.enable_ip_blocking(cfg, bad_ips(50))
    on = wg.refresh_ip_blocking(cfg, bad_ips(300))
    assert on["ok"] and on["changed"] and winfw.rules == 2


def test_refresh_protections_handles_both(winfw, cfg, tmp_path, monkeypatch):
    monkeypatch.setattr(wg, "hosts_path", lambda: hosts(tmp_path, ORIGINALS["lf"]))
    out = wg.refresh_protections(cfg, SimpleNamespace(bad_domains={"a.example"}, bad_ips=set(), bad_networks=[]))
    assert set(out) == {"web", "ips"} and all(v["ok"] and not v["changed"] for v in out.values())


# =========================================================================== IP blocking: Linux / macOS
class FakeLinuxFw:
    def __init__(self, monkeypatch, tools):
        self.calls = []
        self.inputs = {}
        self.table = False
        monkeypatch.setattr(wg, "IS_WINDOWS", False)
        monkeypatch.setattr(wg, "IS_MAC", False)
        monkeypatch.setattr(wg, "is_admin", lambda: True)
        monkeypatch.setattr(wg, "_which", lambda n: "/usr/sbin/" + n if n in tools else None)
        monkeypatch.setattr(wg, "run", self.run)

    def run(self, argv, timeout=60, input_text=None):
        argv = list(argv)
        self.calls.append(argv)
        if input_text is not None:
            self.inputs[argv[0]] = input_text
        if argv[:2] == ["nft", "-f"]:
            self.table = True
        if argv[:4] == ["nft", "delete", "table", "inet"]:
            ok, self.table = self.table, False
            return (0 if ok else 1), "", ""
        if argv[:3] == ["nft", "list", "table"]:
            return (0 if self.table else 1), "", ""
        if argv[1:3] == ["-C", "OUTPUT"]:
            return 1, "", ""
        return 0, "", ""


def test_linux_nftables_enable_status_disable(monkeypatch, cfg):
    fw = FakeLinuxFw(monkeypatch, {"nft"})
    r = wg.enable_ip_blocking(cfg, ip_sigs(ips=["45.9.9.9", "2a02:6b8::1"], nets=["93.184.216.0/24"]))
    assert r["ok"] and r["changed"] and r["details"]["backend"] == "nftables" and "not persistent" in r["message"]
    script = fw.inputs["nft"]
    assert "add table inet aegis" in script and "93.184.216.0/24" in script and "45.9.9.9" in script
    assert ["nft", "-f", "-"] in fw.calls
    assert wg.ip_blocking_status(cfg)["details"]["enabled"] is True
    again = wg.enable_ip_blocking(cfg, ip_sigs(ips=["45.9.9.9", "2a02:6b8::1"], nets=["93.184.216.0/24"]))
    assert not again["changed"]
    d = wg.disable_ip_blocking(cfg)
    assert d["ok"] and d["changed"] and ["nft", "delete", "table", "inet", "aegis"] in fw.calls
    assert wg.ip_blocking_status(cfg)["details"]["enabled"] is False


def test_linux_iptables_fallback(monkeypatch, cfg):
    fw = FakeLinuxFw(monkeypatch, {"iptables", "ip6tables", "iptables-restore", "ip6tables-restore"})
    r = wg.enable_ip_blocking(cfg, ip_sigs(ips=["45.9.9.9", "2a02:6b8::1"]))
    assert r["ok"] and r["details"]["backend"] == "iptables"
    assert ["iptables-restore", "--noflush"] in fw.calls and ["ip6tables-restore", "--noflush"] in fw.calls
    assert "-A AEGIS -d 45.9.9.9 -j DROP" in fw.inputs["iptables-restore"] and "2a02:6b8::1" not in fw.inputs["iptables-restore"]
    assert "-A AEGIS -d 2a02:6b8::1 -j DROP" in fw.inputs["ip6tables-restore"]
    assert ["iptables", "-I", "OUTPUT", "1", "-j", "AEGIS"] in fw.calls  # jump rule inserted once
    d = wg.disable_ip_blocking(cfg)
    assert d["ok"] and ["iptables", "-F", "AEGIS"] in fw.calls and ["iptables", "-X", "AEGIS"] in fw.calls


def test_linux_without_any_firewall_tool(monkeypatch, cfg):
    FakeLinuxFw(monkeypatch, set())
    r = wg.enable_ip_blocking(cfg, ip_sigs(ips=["45.9.9.9"]))
    assert r["ok"] is False and "nftables" in r["message"]


def test_macos_is_skipped_with_a_clear_message(monkeypatch, cfg):
    monkeypatch.setattr(wg, "IS_WINDOWS", False)
    monkeypatch.setattr(wg, "IS_MAC", True)
    for r in (wg.enable_ip_blocking(cfg, ip_sigs(ips=["45.9.9.9"])), wg.disable_ip_blocking(cfg), wg.ip_blocking_status(cfg)):
        assert r["ok"] is False and not r["changed"] and "macOS" in r["message"] and "not supported" in r["message"]
        assert r["details"]["supported"] is False


def test_ip_functions_never_raise(winfw, cfg, monkeypatch):
    monkeypatch.setattr(wg, "collect_block_addresses", lambda *a, **k: 1 / 0)
    r = wg.enable_ip_blocking(cfg, bad_ips())
    assert set(r) == {"ok", "changed", "message", "details"} and r["ok"] is False
    monkeypatch.setattr(wg, "_win_rule_count", lambda: 1 / 0)
    assert wg.ip_blocking_status(cfg)["ok"] is False
    assert wg.disable_ip_blocking(cfg)["ok"] is False


# =========================================================================== real SignatureDB + feed files
def test_works_with_the_real_signature_database_and_feed_formats(tmp_path, cfg, calls):
    from aegis.core.signatures import SignatureDB

    (cfg.signatures_dir / "urlhaus_hosts.txt").write_text(
        "################\n# abuse.ch URLhaus hostfile\n################\n127.0.0.1\tlocalhost\n"
        "127.0.0.1\tmalware-drop.example\n127.0.0.1\tdl.windowsupdate.com\n127.0.0.1\t185.10.10.10\n127.0.0.1\tphish-paypal.example\n",
        encoding="utf-8")
    (cfg.signatures_dir / "feodo_ipblocklist.txt").write_text(
        "# Feodo Tracker\n45.9.9.9\n93.184.216.0/24\n10.0.0.1\n8.8.8.8\n,junk,line\n", encoding="utf-8")
    sigs = SignatureDB(cfg)
    p = hosts(tmp_path, ORIGINALS["crlf"])
    r = wg.enable_web_protection(cfg, sigs, hosts_file=p)
    assert r["ok"] and r["changed"], r
    # real feed noise handled: localhost / IP-as-domain / protected update domain are dropped, look-alike is kept
    assert wg.read_block_domains(p.read_bytes()) == ["malware-drop.example", "phish-paypal.example"]
    addrs, stats = wg.collect_block_addresses(sigs)
    assert addrs == ["45.9.9.9", "93.184.216.0/24"] and stats["skipped_unsafe"] == 2
    assert wg.disable_web_protection(cfg, hosts_file=p)["changed"] and p.read_bytes() == ORIGINALS["crlf"]


def test_the_managed_block_does_not_trip_the_network_scanners_hosts_checks(tmp_path, cfg, calls):
    """Feed domains map to 0.0.0.0 and never include AV/update domains, so the hosts-file findings of
    aegis.scanners.network stay quiet (a long list only yields the INFO 'many custom entries' note)."""
    from aegis.core.models import Severity
    from aegis.scanners.network import hosts_findings

    sigs = SimpleNamespace(bad_domains={f"malware{i}.example" for i in range(60)} | {"dl.windowsupdate.com", "kaspersky.com"})
    p = hosts(tmp_path, ORIGINALS["crlf"])
    wg.enable_web_protection(cfg, sigs, hosts_file=p)
    findings = hosts_findings(p.read_text(encoding="utf-8"), str(p))
    assert all(f.severity == Severity.INFO for f in findings)
    assert {f.rule_id for f in findings} <= {"AEG-NET-HOSTS-CUSTOM"}
