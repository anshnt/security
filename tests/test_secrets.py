"""Unit tests for aegis.scanners.secrets: detection, masking and Linux-safe scanner run."""

import base64
import json
import os
import struct
import zipfile
from pathlib import Path

import pytest

from aegis.core.config import Config
from aegis.core.models import CheckResult, CheckStatus, Finding, Severity
from aegis.core.signatures import SignatureDB
from aegis.scanners import secrets as sec
from aegis.scanners.base import ScanContext

VALID_12 = "legal winner thank year wave sausage worth useful legal winner thank yellow"
VALID_12B = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
VALID_24 = ("void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol "
            "group space point ten exist slush involve unfold")
BAD_CHECKSUM_12 = "legal winner thank year wave sausage worth useful legal winner thank zoo"


@pytest.fixture(scope="module")
def wordlist():
    w = sec.load_bip39()
    assert len(w) == 2048
    return w


def write(tmp_path, name, text):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def rules_of(hits):
    return {h.rule for h in hits}


def blob(findings):
    return json.dumps([f.to_dict() for f in findings])


# ---------------------------------------------------------------- masking
def test_mask():
    assert sec.mask(_tok("gh", "p_", "abcdefghijklmnop")) == "ghp_****"
    assert sec.mask("abc") == "****"
    assert sec.mask(_tok("AK", "IA", "IOSFODNN7ABCDEFG")) == "AKIA****"


# ---------------------------------------------------------------- seed phrases
def test_bip39_checksum(wordlist):
    assert sec.bip39_checksum_ok(VALID_12.split(), wordlist)
    assert sec.bip39_checksum_ok(VALID_12B.split(), wordlist)
    assert sec.bip39_checksum_ok(VALID_24.split(), wordlist)
    assert not sec.bip39_checksum_ok(BAD_CHECKSUM_12.split(), wordlist)
    assert not sec.bip39_checksum_ok(["notaword"] * 12, wordlist)


@pytest.mark.parametrize("text", [
    VALID_12, "my wallet seed: " + VALID_12 + " keep it safe!", VALID_12.replace(" ", "\n"),
    ", ".join(VALID_12.split()), " ".join(f"{i}. {w}" for i, w in enumerate(VALID_12.split(), 1)), VALID_24,
])
def test_seed_phrase_detected(wordlist, text):
    found = sec.find_seed_phrases(text, wordlist)
    assert found and found[0]["checksum_valid"] is True
    h = sec.seed_hit(found)
    assert h.severity == Severity.HIGH and h.rule == "SEED"
    flat = json.dumps(h.evidence)
    assert "winner" not in flat and "sausage" not in flat  # only a masked first word


def test_seed_phrase_invalid_checksum_is_possible_medium(wordlist):
    found = sec.find_seed_phrases(BAD_CHECKSUM_12, wordlist)
    assert found and found[0]["checksum_valid"] is False
    assert sec.seed_hit(found).severity == Severity.MEDIUM


def test_seed_phrase_false_positives(wordlist):
    prose = ("The quick brown fox jumps over the lazy dog and then the dog wakes up and chases the fox across the "
             "field until they both fall asleep under a large tree near the river.")
    assert sec.find_seed_phrases(prose, wordlist) == []
    assert sec.find_seed_phrases("abandon ability able about above absent", wordlist) == []  # too short
    assert sec.find_seed_phrases(VALID_12.upper(), wordlist) == []  # must be lowercase
    all_words = "\n".join(sorted(wordlist, key=wordlist.get))
    assert sec.find_seed_phrases(all_words, wordlist) == []  # the BIP-39 list itself is not a seed
    assert sec.find_seed_phrases(VALID_12, {}) == []  # no wordlist -> disabled
    # the famous public test vector (2 distinct words) is not a real wallet
    assert sec.find_seed_phrases(VALID_12B, wordlist) == []


# ---------------------------------------------------------------- tokens
# Fake tokens are assembled at runtime from split prefixes and generated bodies so the
# repository never contains a secret-shaped literal (keeps GitHub push protection and
# other secret scanners quiet). They are syntactically valid but not real credentials.
def _body(n: int, alphabet: str = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789") -> str:
    return (alphabet * (n // len(alphabet) + 1))[:n]


def _tok(*parts: str) -> str:
    return "".join(parts)


GH = _tok("gh", "p_", _body(36))
SLACK = _tok("xo", "xb-", "1234567890", "12-", "1234567890", "123-", _body(24))
STRIPE = _tok("sk", "_live_", _body(24))
GOOGLE = _tok("AI", "za", "SyA-", _body(31, "1234567890abcdefghijklmnopqrstu"))
ANTHROPIC = _tok("sk-", "ant-api03-", _body(36), "-_", _body(8))
OPENAI = _tok("sk-", "proj-", _body(40))
AWS_ID = _tok("AK", "IA", _body(16, "ZXY1234ABCD5678"))
AWS_SECRET = _tok("wJal", _body(36, "rXUtnFEMIK7MDENGbPxRfiCYzZ0123abcd/"))


@pytest.mark.parametrize("secret,rule,sev", [
    (GH, "GITHUB", Severity.HIGH), (SLACK, "SLACK", Severity.HIGH), (STRIPE, "STRIPE", Severity.HIGH),
    (GOOGLE, "GOOGLE", Severity.MEDIUM), (ANTHROPIC, "ANTHROPIC", Severity.HIGH), (OPENAI, "OPENAI", Severity.HIGH),
    (_tok("github", "_pat_", _body(22), "_", _body(59)), "GITHUB", Severity.HIGH),
])
def test_token_detection_and_masking(secret, rule, sev):
    hits = sec.scan_tokens(f"config:\n  api_key = {secret}\n")
    assert len(hits) == 1 and hits[0].rule == rule and hits[0].severity == sev
    flat = json.dumps(hits[0].evidence) + hits[0].description + hits[0].title
    assert secret not in flat
    assert hits[0].evidence["matches"][0]["masked"] == secret[:4] + "****"
    assert hits[0].evidence["matches"][0]["line"] == 2


def test_anthropic_not_reported_as_openai():
    assert rules_of(sec.scan_tokens(ANTHROPIC)) == {"ANTHROPIC"}


def test_aws_key_with_and_without_secret():
    only = sec.scan_tokens(f"id = {AWS_ID}")
    assert only[0].rule == "AWS" and only[0].severity == Severity.MEDIUM
    both = sec.scan_tokens(f"aws_access_key_id = {AWS_ID}\naws_secret_access_key = {AWS_SECRET}\n")
    assert both[0].severity == Severity.HIGH
    assert AWS_ID not in json.dumps(both[0].evidence) and AWS_SECRET not in json.dumps(both[0].evidence)
    assert sec.scan_tokens("AKIAIOSFODNN7EXAMPLE") == []  # documented placeholder


def test_token_placeholders_ignored():
    assert sec.scan_tokens("token: xoxb-your-token-here\nsk-ant-xxxxxxxx\nghp_xxx\nsk-1234") == []


# ---------------------------------------------------------------- private keys
def _openssh_key(cipher: bytes) -> str:
    body = (b"openssh-key-v1\x00" + struct.pack(">I", len(cipher)) + cipher + struct.pack(">I", 4) + b"none"
            + struct.pack(">I", 0) + struct.pack(">I", 1) + struct.pack(">I", 51) + b"\x00" * 51 + struct.pack(">I", 200) + os.urandom(200))
    b64 = base64.b64encode(body).decode()
    lines = "\n".join(b64[i:i + 70] for i in range(0, len(b64), 70))
    return f"-----BEGIN OPENSSH PRIVATE KEY-----\n{lines}\n-----END OPENSSH PRIVATE KEY-----\n"


PEM_BODY = "\n".join(["MIIEowIBAAKCAQEA" + "a1B2c3D4e5F6g7H8" * 4] * 6)


def test_openssh_key_encryption_detection():
    plain = sec.scan_private_keys(_openssh_key(b"none"))
    enc = sec.scan_private_keys(_openssh_key(b"aes256-ctr"))
    assert plain[0]["encrypted"] is False and enc[0]["encrypted"] is True


def test_pem_private_keys():
    pem = f"-----BEGIN RSA PRIVATE KEY-----\n{PEM_BODY}\n-----END RSA PRIVATE KEY-----\n"
    enc = f"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,ABCDEF\n\n{PEM_BODY}\n-----END RSA PRIVATE KEY-----\n"
    p8 = f"-----BEGIN PRIVATE KEY-----\n{PEM_BODY}\n-----END PRIVATE KEY-----\n"
    e8 = f"-----BEGIN ENCRYPTED PRIVATE KEY-----\n{PEM_BODY}\n-----END ENCRYPTED PRIVATE KEY-----\n"
    assert sec.scan_private_keys(pem)[0]["encrypted"] is False
    assert sec.scan_private_keys(enc)[0]["encrypted"] is True
    assert sec.scan_private_keys(p8)[0]["encrypted"] is False
    assert sec.scan_private_keys(e8)[0]["encrypted"] is True
    assert sec.scan_private_keys("-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----") == []  # doc snippet


def test_private_key_hit_severity_by_location(tmp_path):
    pem = f"-----BEGIN RSA PRIVATE KEY-----\n{PEM_BODY}\n-----END RSA PRIVATE KEY-----\n"
    keys = sec.scan_private_keys(pem)
    assert sec.private_key_hit(keys, in_ssh_dir=False).severity == Severity.HIGH
    assert sec.private_key_hit(keys, in_ssh_dir=True).severity == Severity.MEDIUM
    assert sec.private_key_hit(sec.scan_private_keys(_openssh_key(b"aes256-ctr")), False) is None
    h = sec.analyse_file(write(tmp_path, "Downloads/server.pem", pem))
    assert "PRIVKEY" in rules_of(h)
    assert PEM_BODY[:40] not in json.dumps([x.evidence for x in h])


# ---------------------------------------------------------------- file names
@pytest.mark.parametrize("name,rule,sev", [
    ("passwords.txt", "PWFILE", Severity.MEDIUM), ("My Passwords.xlsx", "PWFILE", Severity.MEDIUM),
    ("credentials.docx", "PWFILE", Severity.MEDIUM), ("password-policy.pdf", "PWFILE", Severity.LOW),
    ("wallet.dat", "WALLET", Severity.MEDIUM), ("backup.wallet", "WALLET", Severity.MEDIUM),
    ("UTC--2020-01-01T00-00-00.000Z--abcdef", "WALLET", Severity.LOW),
    ("notes.txt", None, None), ("vault.kdbx", None, None), ("photo.jpg", None, None),
])
def test_name_heuristics(name, rule, sev):
    h = sec.name_hit(Path(name))
    if rule is None:
        assert h is None
    else:
        assert h.rule == rule and h.severity == sev


def test_weak_name_upgraded_by_content(tmp_path):
    p = write(tmp_path, "Documents/password-notes.txt", "")
    p.write_text("gmail password: hunter2\nbank pass = abc123\nnetflix pwd: qwerty\n")
    hits = sec.analyse_file(p)
    pw = [h for h in hits if h.rule == "PWFILE"][0]
    assert pw.severity == Severity.MEDIUM and pw.evidence["credential_like_lines"] == 3
    assert "hunter2" not in json.dumps(pw.evidence)


# ---------------------------------------------------------------- specific formats
def test_env_file(tmp_path):
    p = write(tmp_path, "Documents/proj/.env", "DEBUG=true\nDB_PASSWORD=Sup3rS3cretValue\nAPI_KEY=your_api_key\n"
                                              "SECRET_KEY='abcdef123456'\nDATABASE_URL=postgres://u:pw1234@db/x\nPORT=8000\n")
    hits = sec.analyse_file(p)
    env = [h for h in hits if h.rule == "ENV"][0]
    keys = {e["key"] for e in env.evidence["entries"]}
    assert keys == {"DB_PASSWORD", "SECRET_KEY", "DATABASE_URL"}
    assert "Sup3rS3cretValue" not in json.dumps(env.evidence) and env.severity == Severity.MEDIUM
    ex = write(tmp_path, "proj/.env.example", "DB_PASSWORD=changeme\n")
    assert not sec.analyse_file(ex)


def test_git_credentials(tmp_path):
    p = write(tmp_path, ".git-credentials", f"https://bob:{GH}@github.com\nhttps://alice:pa55w0rd@git.example.com\n")
    h = [x for x in sec.analyse_file(p) if x.rule == "GITCRED"][0]
    assert h.severity == Severity.HIGH and h.evidence["count"] == 2
    assert GH not in json.dumps(h.evidence) and "pa55w0rd" not in json.dumps(h.evidence)
    p2 = write(tmp_path, "h2/.git-credentials", "https://alice:pa55w0rd@git.example.com\n")
    assert [x for x in sec.analyse_file(p2) if x.rule == "GITCRED"][0].severity == Severity.MEDIUM


def test_npmrc_pypirc_netrc(tmp_path):
    n = write(tmp_path, ".npmrc", "//registry.npmjs.org/:_authToken=" + _tok("np", "m_", _body(36)) + "\nregistry=x\n")
    assert "NPMRC" in rules_of(sec.analyse_file(n))
    ok = write(tmp_path, "b/.npmrc", "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n")
    assert "NPMRC" not in rules_of(sec.analyse_file(ok))
    p = write(tmp_path, ".pypirc", "[pypi]\nusername = __token__\npassword = pypi-AgEIcHlwaS5vcmcCJGFiY2RlZg\n")
    assert "PYPIRC" in rules_of(sec.analyse_file(p))
    nr = write(tmp_path, ".netrc", "machine example.com login bob password s3cret\n")
    assert "NETRC" in rules_of(sec.analyse_file(nr))


def test_docker_and_aws_files_need_right_directory(tmp_path):
    cfg = json.dumps({"auths": {"https://index.docker.io/v1/": {"auth": base64.b64encode(b"bob:pw").decode()}}})
    d = write(tmp_path, ".docker/config.json", cfg)
    h = [x for x in sec.analyse_file(d) if x.rule == "DOCKER"][0]
    assert h.evidence["registries"] == ["https://index.docker.io/v1/"]
    assert "DOCKER" not in rules_of(sec.analyse_file(write(tmp_path, "other/config.json", cfg)))
    a = write(tmp_path, ".aws/credentials", f"[default]\naws_access_key_id = {AWS_ID}\naws_secret_access_key = {AWS_SECRET}\n")
    h = sec.analyse_file(a)
    assert rules_of(h) == {"AWSFILE"}  # dedicated parser, no duplicate generic finding
    assert AWS_SECRET not in json.dumps([x.evidence for x in h])


def test_rdp_filezilla_unattend(tmp_path):
    rdp = write(tmp_path, "Desktop/server.rdp", "full address:s:10.0.0.5\nusername:s:bob\npassword 51:b:01000000d08c9ddf0115d1118c7a00c04fc297eb\n")
    h = [x for x in sec.analyse_file(rdp) if x.rule == "RDP"][0]
    assert h.evidence["host"] == "10.0.0.5" and "01000000" not in json.dumps(h.evidence)
    assert "RDP" not in rules_of(sec.analyse_file(write(tmp_path, "Desktop/clean.rdp", "full address:s:x\n")))
    fz = write(tmp_path, "FileZilla/sitemanager.xml", '<FileZilla3><Servers><Server><Host>ftp.example.com</Host>'
                                                      '<Pass encoding="base64">aHVudGVyMg==</Pass></Server></Servers></FileZilla3>')
    h = [x for x in sec.analyse_file(fz) if x.rule == "FILEZILLA"][0]
    assert h.evidence["servers"] == ["ftp.example.com"] and "aHVudGVyMg" not in json.dumps(h.evidence)
    un = write(tmp_path, "Panther/unattend.xml", "<unattend><AdministratorPassword><Value>Pa55w0rd!</Value>"
                                                 "<PlainText>true</PlainText></AdministratorPassword></unattend>")
    h = [x for x in sec.analyse_file(un) if x.rule == "UNATTEND"][0]
    assert h.severity == Severity.HIGH and "Pa55w0rd" not in json.dumps(h.evidence)
    redacted = write(tmp_path, "P2/unattend.xml", "<AdministratorPassword><Value>*SENSITIVE*DATA*DELETED*</Value>"
                                                  "<PlainText>false</PlainText></AdministratorPassword>")
    assert "UNATTEND" not in rules_of(sec.analyse_file(redacted))
    b64 = write(tmp_path, "P3/unattend.xml", "<Password><Value>UGE1NXcwcmQh</Value><PlainText>false</PlainText></Password>")
    assert [x for x in sec.analyse_file(b64) if x.rule == "UNATTEND"][0].severity == Severity.MEDIUM


# ---------------------------------------------------------------- end-to-end file scanning
def test_scan_file_text_and_docx(tmp_path, wordlist):
    t = write(tmp_path, "Desktop/notes.txt", f"remember my token {GH}\nand seed:\n{VALID_12}\n")
    fs = sec.scan_file(t, wordlist)
    assert {f.rule_id for f in fs} == {"AEG-SEC-GITHUB", "AEG-SEC-SEED"}
    for f in fs:
        assert f.category == "privacy" and f.location == str(t) and f.recommendation and f.mitre
    assert GH not in blob(fs) and "winner" not in blob(fs) and "sausage" not in blob(fs)

    docx = tmp_path / "Documents" / "recovery.docx"
    docx.parent.mkdir(parents=True)
    runs = "".join(f"<w:r><w:t>{w} </w:t></w:r>" for w in VALID_12.split())
    with zipfile.ZipFile(docx, "w") as z:
        z.writestr("word/document.xml", f"<w:document><w:body><w:p>{runs}</w:p></w:body></w:document>")
    assert "AEG-SEC-SEED" in {f.rule_id for f in sec.scan_file(docx, wordlist)}


def test_binary_and_large_files_skipped(tmp_path):
    b = tmp_path / "x.dat"
    b.write_bytes(b"\x00\x01" + GH.encode())
    assert sec.scan_file(b) == []
    big = tmp_path / "big.txt"
    big.write_text(GH + "\n" + "x" * (sec.MAX_FILE_BYTES + 10))
    assert sec.scan_file(big) == []


# ---------------------------------------------------------------- SSH permissions (POSIX)
@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_ssh_permissions(tmp_path):
    ssh = tmp_path / ".ssh"
    ssh.mkdir()
    key = ssh / "id_rsa"
    key.write_text(f"-----BEGIN RSA PRIVATE KEY-----\n{PEM_BODY}\n-----END RSA PRIVATE KEY-----\n")
    (ssh / "id_rsa.pub").write_text("ssh-rsa AAAA user@host\n")
    (ssh / "config").write_text("Host *\n")
    os.chmod(ssh, 0o700)
    os.chmod(key, 0o644)
    fs = sec.check_ssh_permissions(ssh)
    assert len(fs) == 1 and fs[0].rule_id == "AEG-SEC-SSHPERM" and fs[0].severity == Severity.HIGH
    assert fs[0].remediation.params["command"] == ["chmod", "600", str(key)]
    os.chmod(key, 0o640)
    assert sec.check_ssh_permissions(ssh)[0].severity == Severity.MEDIUM
    os.chmod(key, 0o600)
    assert sec.check_ssh_permissions(ssh) == []
    os.chmod(ssh, 0o777)
    d = sec.check_ssh_permissions(ssh)
    assert d and d[0].rule_id == "AEG-SEC-SSHDIR" and d[0].remediation.params["command"][1] == "700"
    os.chmod(ssh, 0o700)


# ---------------------------------------------------------------- scanner run on this platform
def test_scanner_end_to_end(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / "Desktop").mkdir(parents=True)
    (home / "Documents" / "node_modules" / "pkg").mkdir(parents=True)
    (home / "Downloads").mkdir()
    (home / "Desktop" / "keys.txt").write_text(f"stripe={STRIPE}\n{VALID_12}\n")
    (home / "Documents" / "node_modules" / "pkg" / "leak.txt").write_text(f"{GH}\n")  # must be skipped
    (home / "Downloads" / "passwords.xlsx").write_bytes(b"PK\x03\x04")
    (home / "readme.txt").write_text("hello\n")
    (home / ".git-credentials").write_text("https://bob:pa55word123@example.com\n")
    monkeypatch.setattr(sec, "user_home", lambda: home)
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path / "aegis"))
    cfg = Config()
    ctx = ScanContext(config=cfg, signatures=SignatureDB(cfg))
    items = list(sec.SecretsScanner().run(ctx))
    findings = [i for i in items if isinstance(i, Finding)]
    rules = {f.rule_id for f in findings}
    assert {"AEG-SEC-STRIPE", "AEG-SEC-SEED", "AEG-SEC-PWFILE", "AEG-SEC-GITCRED"} <= rules
    assert not any("node_modules" in f.location for f in findings)
    assert STRIPE not in blob(findings) and "pa55word123" not in blob(findings)
    checks = [i for i in items if isinstance(i, CheckResult)]
    assert any(c.check_id == "AEG-SEC-EXPOSED" and c.status == CheckStatus.FAIL for c in checks)
    assert ctx.stats["secrets_files_scanned"] >= 4


def test_scanner_clean_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / "Documents").mkdir(parents=True)
    (home / "Documents" / "recipe.txt").write_text("flour, eggs and milk\n")
    monkeypatch.setattr(sec, "user_home", lambda: home)
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path / "aegis"))
    cfg = Config()
    ctx = ScanContext(config=cfg, signatures=SignatureDB(cfg))
    items = list(sec.SecretsScanner().run(ctx))
    assert not [i for i in items if isinstance(i, Finding)]
    assert any(isinstance(i, CheckResult) and i.status == CheckStatus.PASS and i.check_id == "AEG-SEC-EXPOSED" for i in items)


def test_scanner_real_home_does_not_raise(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path))
    cfg = Config()
    ctx = ScanContext(config=cfg, signatures=SignatureDB(cfg))
    items = list(sec.SecretsScanner().run(ctx))
    assert all(isinstance(i, (Finding, CheckResult)) for i in items)
    assert sec.SecretsScanner.name == "secrets"
