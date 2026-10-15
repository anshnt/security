"""Updater tests: mocked downloads, validation, atomic replace, state file."""

import io
import json
import urllib.error
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from aegis.tools import updater

SHA = "".join(f"{i:064x}\n" for i in range(1, 151))
IPS = "# Feodo\n203.0.113.5\n198.51.100.7\n"
HOSTS = "# URLhaus\n" + "".join(f"127.0.0.1\thost{i}.example.net\n" for i in range(30))
EXT = "# list\n" + "".join(("%032x" % i).translate(str.maketrans("0123456789", "abcdefghij")) + "\n" for i in range(1, 60))


class Resp(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def make_config(tmp_path, key=""):
    d = tmp_path / "sigs"
    d.mkdir()
    return SimpleNamespace(signatures_dir=d, abusech_auth_key=key)


def route(monkeypatch, table, seen=None):
    """table: url-substring -> bytes | Exception"""

    def fake(req, timeout=None):
        url = req.full_url
        if seen is not None:
            seen.append((url, {k.lower(): v for k, v in req.header_items()}))
        for needle, payload in table.items():
            if needle in url:
                if isinstance(payload, Exception):
                    raise payload
                return Resp(payload if isinstance(payload, bytes) else payload.encode())
        raise urllib.error.URLError("unrouted " + url)

    monkeypatch.setattr("urllib.request.urlopen", fake)


LOLDRIVERS = json.dumps(
    [{"Category": "vulnerable driver", "CVE": ["CVE-2019-16098"], "Tags": ["RTCore64.sys"],
      "KnownVulnerableSamples": [{"SHA256": f"{i:064x}", "OriginalFilename": "RTCore64.sys"} for i in range(1, 501)]},
     {"Category": "malicious", "Tags": ["evil.sys"],
      "KnownVulnerableSamples": [{"SHA256": f"{i:064x}", "Filename": "evil.sys"} for i in range(1000, 1100)]
      + [{"SHA256": "not-a-hash"}]}])
GOOD = {"bazaar.abuse.ch": SHA, "feodotracker": IPS, "urlhaus.abuse.ch": HOSTS, "malicious-extensions-list": EXT,
        "loldrivers.io": LOLDRIVERS}


@pytest.fixture(autouse=True)
def no_yara(monkeypatch):
    monkeypatch.setattr(updater, "_have_yara", lambda: False)


def test_all_feeds_update_and_state_written(tmp_path, monkeypatch):
    cfg = make_config(tmp_path)
    seen = []
    route(monkeypatch, GOOD, seen)
    res = updater.update_signatures(cfg)
    assert {k: v["ok"] for k, v in res.items() if k != "yara_forge"} == {
        "malwarebazaar": True, "feodo": True, "urlhaus": True, "malicious_extensions": True, "loldrivers": True}
    assert res["loldrivers"]["count"] == 600
    assert res["malwarebazaar"]["count"] == 150 and res["feodo"]["count"] == 2 and res["urlhaus"]["count"] == 30
    assert res["malicious_extensions"]["count"] == 59
    assert (cfg.signatures_dir / "malwarebazaar_recent.txt").read_text() == SHA
    for name in ("feodo_ipblocklist.txt", "urlhaus_hosts.txt", "malicious_extensions.txt"):
        assert (cfg.signatures_dir / name).exists()
    state = json.loads((cfg.signatures_dir / "update_state.json").read_text())
    assert state["feeds"]["malwarebazaar"]["count"] == 150 and state["feeds"]["malwarebazaar"]["updated"]
    assert "last_run" in state
    assert all(h["user-agent"] == "Aegis-Security-Suite/1.0" for _u, h in seen)
    assert not any(k == "auth-key" for _u, h in seen for k in h)
    assert not list(cfg.signatures_dir.glob("*.tmp"))


def test_auth_key_sent_to_abusech_only(tmp_path, monkeypatch):
    cfg = make_config(tmp_path, key="SECRETKEY")
    seen = []
    route(monkeypatch, GOOD, seen)
    updater.update_signatures(cfg)
    for url, headers in seen:
        if "abuse.ch" in url:
            assert headers.get("auth-key") == "SECRETKEY"
        else:
            assert "auth-key" not in headers


def test_invalid_content_keeps_previous_file(tmp_path, monkeypatch):
    cfg = make_config(tmp_path)
    target = cfg.signatures_dir / "malwarebazaar_recent.txt"
    target.write_text("previous\n")
    route(monkeypatch, dict(GOOD, **{"bazaar.abuse.ch": "<html>Rate limited</html>"}))
    res = updater.update_signatures(cfg)
    assert res["malwarebazaar"]["ok"] is False and "invalid" in res["malwarebazaar"]["error"]
    assert target.read_text() == "previous\n"
    assert res["feodo"]["ok"] is True  # others unaffected
    state = json.loads((cfg.signatures_dir / "update_state.json").read_text())
    assert state["feeds"]["malwarebazaar"]["ok"] is False


def test_truncated_download_rejected(tmp_path, monkeypatch):
    cfg = make_config(tmp_path)
    route(monkeypatch, dict(GOOD, **{"bazaar.abuse.ch": SHA[:64 * 20]}))  # only 10 hashes < min 100
    assert updater.update_signatures(cfg)["malwarebazaar"]["ok"] is False
    assert not (cfg.signatures_dir / "malwarebazaar_recent.txt").exists()


def test_network_and_http_errors_do_not_raise(tmp_path, monkeypatch):
    cfg = make_config(tmp_path)
    route(monkeypatch, {"bazaar.abuse.ch": urllib.error.HTTPError("u", 401, "Unauthorized", {}, None),
                        "feodotracker": urllib.error.URLError("down"), "urlhaus.abuse.ch": HOSTS,
                        "malicious-extensions-list": TimeoutError("slow")})
    res = updater.update_signatures(cfg)
    assert res["malwarebazaar"]["ok"] is False and "Auth-Key" in res["malwarebazaar"]["error"]
    assert res["feodo"]["ok"] is False and res["malicious_extensions"]["ok"] is False
    assert res["urlhaus"]["ok"] is True


def test_extension_list_shrink_guard(tmp_path, monkeypatch):
    cfg = make_config(tmp_path)
    (cfg.signatures_dir / "malicious_extensions.txt").write_text(EXT * 3 if False else EXT + "".join(
        ("%032x" % i).translate(str.maketrans("0123456789", "abcdefghij")) + "\n" for i in range(100, 400)))
    small = "# tiny\n" + "".join(("%032x" % i).translate(str.maketrans("0123456789", "abcdefghij")) + "\n" for i in range(1, 30))
    route(monkeypatch, dict(GOOD, **{"malicious-extensions-list": small}))
    res = updater.update_signatures(cfg)
    assert res["malicious_extensions"]["ok"] is False and "shrank" in res["malicious_extensions"]["error"]


def test_atomic_write_replaces_and_cleans_up(tmp_path):
    tmp_path = tmp_path / "d"
    tmp_path.mkdir()
    p = tmp_path / "f.txt"
    p.write_text("old")
    updater.atomic_write(p, b"new")
    assert p.read_text() == "new" and [x.name for x in tmp_path.iterdir()] == ["f.txt"]


def test_atomic_write_failure_keeps_old(tmp_path, monkeypatch):
    tmp_path = tmp_path / "d"
    tmp_path.mkdir()
    p = tmp_path / "f.txt"
    p.write_text("old")
    monkeypatch.setattr(updater.os, "replace", lambda *a: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError):
        updater.atomic_write(p, b"new")
    assert p.read_text() == "old" and [x.name for x in tmp_path.iterdir()] == ["f.txt"]


def test_progress_callback_variants(tmp_path, monkeypatch):
    route(monkeypatch, GOOD)
    msgs = []
    updater.update_signatures(make_config(tmp_path), progress=lambda name, msg: msgs.append((name, msg)))
    assert ("malwarebazaar", "updated (150 entries)") in msgs
    tmp2 = tmp_path / "two"
    tmp2.mkdir()
    one = []
    updater.update_signatures(make_config(tmp2), progress=lambda m: one.append(m))
    assert any(m.startswith("urlhaus: updated") for m in one)


def test_loaded_by_signature_db(tmp_path, monkeypatch):
    """The downloaded files are in the formats SignatureDB reads."""
    from aegis.core.config import Config
    from aegis.core.signatures import SignatureDB

    monkeypatch.setenv("AEGIS_HOME", str(tmp_path / "home"))
    cfg = Config()
    route(monkeypatch, GOOD)
    updater.update_signatures(cfg)
    db = SignatureDB(cfg)
    assert db.is_bad_ip("203.0.113.5") and db.is_bad_domain("host3.example.net")
    assert len(db.bad_extensions) >= 59 and (("%032x" % 1).translate(str.maketrans("0123456789", "abcdefghij"))) in db.bad_extensions
    assert any(len(h) == 64 for h in db.hashes)


# --------------------------------------------------------------------------- YARA Forge

yara = pytest.importorskip("yara")

RULE = 'rule T1 { strings: $a = "needle-one" condition: $a }\nrule T2 { strings: $a = "needle-two" condition: $a }\n'


def make_zip(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


def test_yara_forge_install(tmp_path, monkeypatch):
    monkeypatch.setattr(updater, "_have_yara", lambda: True)
    cfg = make_config(tmp_path)
    api = json.dumps({"assets": [{"name": "yara-forge-rules-extended.zip", "browser_download_url": "https://dl/ext.zip"},
                                 {"name": "yara-forge-rules-core.zip", "browser_download_url": "https://dl/core.zip"}]})
    seen = []
    route(monkeypatch, dict(GOOD, **{"api.github.com": api, "dl/core.zip": make_zip({
        "packages/core/yara-rules-core.yar": RULE, "../../evil.yar": RULE, "readme.txt": "x"})}), seen)
    res = updater.update_signatures(cfg)
    assert res["yara_forge"]["ok"] is True and res["yara_forge"]["count"] == 4  # 2 files x 2 rules
    installed = sorted(p.name for p in (cfg.signatures_dir / "yara").iterdir())
    assert installed == ["yara-forge-evil.yar", "yara-forge-yara-rules-core.yar"]  # basenames only: no path traversal
    assert not (tmp_path / "evil.yar").exists()
    assert any("dl/core.zip" in u for u, _h in seen) and not any("ext.zip" in u for u, _h in seen)


def test_yara_forge_falls_back_when_api_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(updater, "_have_yara", lambda: True)
    cfg = make_config(tmp_path)
    route(monkeypatch, dict(GOOD, **{"api.github.com": urllib.error.HTTPError("u", 403, "x", {}, None),
                                     "releases/latest/download/yara-forge-rules-core.zip": make_zip({"core.yar": RULE})}))
    assert updater.update_signatures(cfg)["yara_forge"]["ok"] is True


def test_yara_forge_broken_rules_not_installed(tmp_path, monkeypatch):
    monkeypatch.setattr(updater, "_have_yara", lambda: True)
    cfg = make_config(tmp_path)
    old = cfg.signatures_dir / "yara"
    old.mkdir()
    (old / "yara-forge-core.yar").write_text(RULE)
    route(monkeypatch, dict(GOOD, **{"api.github.com": urllib.error.URLError("x"),
                                     "yara-forge-rules-core.zip": make_zip({"core.yar": "rule broken { condition: nope"})}))
    res = updater.update_signatures(cfg)
    assert res["yara_forge"]["ok"] is False
    assert (old / "yara-forge-core.yar").read_text() == RULE


def test_yara_skipped_without_yara_python(tmp_path, monkeypatch):
    monkeypatch.setattr(updater, "_have_yara", lambda: False)
    route(monkeypatch, GOOD)
    res = updater.update_signatures(make_config(tmp_path))
    assert res["yara_forge"]["ok"] is False and res["yara_forge"].get("skipped") is True


def test_loldrivers_converted_to_driver_scanner_format(tmp_path, monkeypatch):
    from aegis.scanners.drivers import load_vulnerable_driver_hashes

    cfg = make_config(tmp_path)
    route(monkeypatch, GOOD)
    updater.update_signatures(cfg)
    lines = (cfg.signatures_dir / "vulnerable_drivers.txt").read_text().splitlines()
    assert len(lines) == 600 and all(len(ln.split("\t")[0]) == 64 for ln in lines)
    assert f"{1:064x}\tLOLDrivers.VulnDriver: RTCore64.sys [CVE-2019-16098]" in lines
    assert f"{1000:064x}\tLOLDrivers.MalDriver: evil.sys" in lines
    hashes = load_vulnerable_driver_hashes([cfg.signatures_dir], base=tmp_path / "missing.txt")
    assert len(hashes) == 600


def test_empty_upstream_feed_keeps_previous_copy(tmp_path, monkeypatch):
    """Feodo Tracker has been publishing empty lists; that must not wipe the old copy or count as failure."""
    cfg = make_config(tmp_path)
    (cfg.signatures_dir / "feodo_ipblocklist.txt").write_text(IPS)
    route(monkeypatch, dict(GOOD, feodotracker="# Feodo Tracker: datasets currently empty\n"))
    res = updater.update_signatures(cfg)
    assert res["feodo"]["ok"] and res["feodo"]["count"] == 0
    assert (cfg.signatures_dir / "feodo_ipblocklist.txt").read_text() == IPS
