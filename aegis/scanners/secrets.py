"""Credential-exposure scanner: finds the secrets infostealers harvest.

Looks in the user's Desktop, Documents, Downloads (and OneDrive equivalents),
files directly in the home folder, and well-known credential stores for:

* crypto recovery (seed) phrases (BIP-39 checksum-validated) and wallet files
* API keys / tokens (AWS, GitHub, GitLab, Slack, Stripe, Google, OpenAI, Anthropic, ...)
* unencrypted private keys (PEM, OpenSSH new format, PuTTY .ppk)
* .env files with secrets, plaintext password lists, saved RDP / FileZilla passwords,
  unattend.xml passwords, .git-credentials, .npmrc, .pypirc, docker auth, .netrc, AWS credentials
* PuTTY / WinSCP saved passwords in the registry (Windows)
* world/group-readable SSH private keys (Linux/macOS)

Secrets are NEVER copied into findings: evidence holds only masked values
(first 4 characters + ****), counts, key names and file paths.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import stat as statmod
import struct
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from aegis.core.config import PACKAGE_DATA
from aegis.core.models import Category, CheckResult, CheckStatus, Finding, Remediation, Severity
from aegis.core.platform import IS_WINDOWS, env_path, reg_walk_values, user_home
from aegis.scanners.base import Emitted, ScanContext, Scanner, register

log = logging.getLogger("aegis.secrets")

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_UNZIPPED_BYTES = 4 * 1024 * 1024
BIP39_FILE = PACKAGE_DATA / "bip39_english.txt"

SKIP_DIRS = {"node_modules", ".git", ".svn", ".hg", "venv", ".venv", "env", "site-packages", "__pycache__", ".cache",
             ".npm", ".cargo", ".gradle", ".m2", "appdata", "library", "$recycle.bin", ".trash", "program files",
             "program files (x86)", "windows", "dist-packages", ".tox", ".idea", ".vscode"}

TEXT_EXTS = {".txt", ".md", ".csv", ".json", ".yml", ".yaml", ".xml", ".ini", ".cfg", ".conf", ".config", ".env",
             ".properties", ".toml", ".log", ".py", ".js", ".ts", ".sh", ".bash", ".ps1", ".bat", ".cmd", ".rb", ".php",
             ".java", ".cs", ".go", ".tf", ".tfvars", ".pem", ".key", ".ppk", ".sql", ".note", ".notes", ".rtf",
             ".html", ".htm", ".rdp", ".ovpn", ".gitconfig", ".org", ".tsv", ".pass", ".secret"}
ZIP_DOC_EXTS = {".docx", ".xlsx"}
DOC_EXTS = {".txt", ".csv", ".xlsx", ".xls", ".docx", ".doc", ".rtf", ".odt", ".ods", ".md", ".json", ".xml", ".ini",
            ".html", ".htm", ".pdf", ".note", ".notes", ".rec"}


# =========================================================================== helpers
def mask(secret: str, keep: int = 4) -> str:
    """first 4 chars + ****; never reveals more."""
    secret = str(secret)
    if len(secret) <= keep:
        return "****"
    return secret[:keep] + "****"


@dataclass
class Hit:
    """A detection inside one file (turned into a Finding by `to_finding`)."""

    rule: str  # suffix of AEG-SEC-<rule>
    title: str
    severity: Severity
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""
    mitre: List[str] = field(default_factory=lambda: ["T1552.001"])
    remediation: Optional[Remediation] = None

    def to_finding(self, path: str) -> Finding:
        ev = dict(self.evidence)
        ev.setdefault("file", path)
        return Finding(
            rule_id=f"AEG-SEC-{self.rule}", title=self.title, severity=self.severity, category=Category.PRIVACY,
            description=self.description, location=path, evidence=ev, recommendation=self.recommendation,
            remediation=self.remediation, mitre=list(self.mitre),
        )


ROTATE = ("Treat the secret as exposed: revoke or rotate it in the provider's console now (changing it is the only "
          "way to be safe), then delete this file or move the credential into a password manager, OS keychain or "
          "environment variable. Never keep secrets in plain-text files on Desktop/Documents/Downloads.")


def _lineno(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _is_placeholder(value: str) -> bool:
    v = value.strip().strip("'\"").lower()
    if not v or len(v) < 4:
        return True
    if re.fullmatch(r"[x*#.\-_<>]+", v):
        return True
    if v.startswith(("${", "$(", "{{", "<", "%", "your", "my_", "my-", "changeme", "change_me", "example", "replace",
                     "xxx", "todo", "none", "null", "secret", "password", "placeholder", "dummy", "test")):
        return True
    return v in ("password", "pass", "secret", "token", "false", "true", "undefined", "empty")


# =========================================================================== token patterns
def _mixed(s: str) -> bool:
    return any(c.isdigit() for c in s) and any(c.isupper() for c in s) and any(c.islower() for c in s)


# id, label, regex, severity, validator
TOKEN_PATTERNS: List[Tuple[str, str, "re.Pattern[str]", Severity, Optional[Callable[[str], bool]]]] = [
    ("GITHUB", "GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b"),
     Severity.HIGH, None),
    ("GITLAB", "GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20}\b"), Severity.HIGH, None),
    ("SLACK", "Slack token", re.compile(r"\bxox[baprs]-\d{6,}-[A-Za-z0-9\-]{10,}\b"), Severity.HIGH, None),
    ("STRIPE", "Stripe live secret key", re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{24,}\b"), Severity.HIGH, None),
    ("ANTHROPIC", "Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{30,}"), Severity.HIGH, None),
    ("OPENAI", "OpenAI API key", re.compile(r"\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{40,}"),
     Severity.HIGH, _mixed),
    ("SENDGRID", "SendGrid API key", re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"), Severity.HIGH, None),
    ("GOOGLE", "Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), Severity.MEDIUM, None),
    ("HUGGINGFACE", "Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{34,}\b"), Severity.MEDIUM, _mixed),
    ("NPM", "npm access token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), Severity.MEDIUM, None),
    ("TELEGRAM", "Telegram bot token", re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_\-]{33}\b"), Severity.MEDIUM, None),
]
AWS_KEY_RX = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
AWS_SECRET_NEAR_RX = re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])")


def scan_tokens(text: str) -> List[Hit]:
    """API-key style secrets in free text. One Hit per token type; evidence is masked."""
    hits: List[Hit] = []
    for rid, label, rx, sev, validator in TOKEN_PATTERNS:
        found = []
        for m in rx.finditer(text):
            val = m.group(0)
            if validator and not validator(val):
                continue
            if "example" in val.lower() or "xxxx" in val.lower():
                continue
            found.append({"masked": mask(val), "line": _lineno(text, m.start())})
        if found:
            hits.append(Hit(rid, f"{label} stored in a file", sev,
                            f"{len(found)} {label}(s) found in plain text. Anyone (or any infostealer) that can read this "
                            "file can use the token.", {"type": label, "count": len(found), "matches": found[:5]},
                            ROTATE, ["T1552.001"]))
    aws: List[Dict[str, Any]] = []
    with_secret = False
    for m in AWS_KEY_RX.finditer(text):
        if "EXAMPLE" in m.group(0):
            continue
        window = text[max(0, m.start() - 250): m.end() + 250]
        has_secret = any(s.group(0) != m.group(0) and not s.group(0).startswith("AKIA")
                         and re.search(r"[A-Z]", s.group(0)) and re.search(r"[a-z]", s.group(0))
                         and re.search(r"\d", s.group(0)) for s in AWS_SECRET_NEAR_RX.finditer(window))
        with_secret = with_secret or has_secret
        aws.append({"masked": mask(m.group(0)), "line": _lineno(text, m.start()), "secret_nearby": has_secret})
    if aws:
        hits.append(Hit("AWS", "AWS access key stored in a file", Severity.HIGH if with_secret else Severity.MEDIUM,
                        "An AWS access key ID" + (" together with what looks like its secret key" if with_secret else "")
                        + " is stored in plain text. Leaked AWS keys are abused within minutes for crypto-mining and data theft.",
                        {"type": "AWS access key", "count": len(aws), "matches": aws[:5]}, ROTATE, ["T1552.001"]))
    return hits


# =========================================================================== private keys
_PEM_RX = re.compile(r"-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----(.*?)-----END \1-----", re.S)


def openssh_key_encrypted(pem_body: str) -> Optional[bool]:
    """Decode an OpenSSH new-format key body: True if a passphrase protects it, False if cipher is
    'none', None if it cannot be parsed."""
    try:
        data = base64.b64decode(re.sub(r"\s+", "", pem_body))
        magic = b"openssh-key-v1\x00"
        if not data.startswith(magic):
            return None
        off = len(magic)
        (n,) = struct.unpack(">I", data[off:off + 4])
        cipher = data[off + 4: off + 4 + n]
        return cipher != b"none"
    except Exception:
        return None


def scan_private_keys(text: str) -> List[Dict[str, Any]]:
    """Return one dict per private key block: {kind, encrypted(bool|None), line}."""
    out = []
    for m in _PEM_RX.finditer(text):
        kind, body = m.group(1), m.group(2)
        compact = re.sub(r"\s+", "", re.sub(r"^[A-Za-z\-]+:.*$", "", body, flags=re.M))
        if len(compact) < 100:
            continue  # a documentation snippet / truncated placeholder, not a real key
        if kind == "ENCRYPTED PRIVATE KEY":
            enc: Optional[bool] = True
        elif kind == "OPENSSH PRIVATE KEY":
            enc = openssh_key_encrypted(body)
        else:
            enc = bool(re.search(r"Proc-Type:\s*4,\s*ENCRYPTED", body))
        out.append({"kind": kind, "encrypted": enc, "line": _lineno(text, m.start())})
    if re.search(r"PuTTY-User-Key-File-\d+:", text):
        m = re.search(r"^Encryption:\s*(\S+)", text, re.M)
        out.append({"kind": "PuTTY PPK", "encrypted": (m.group(1).lower() != "none") if m else None,
                    "line": 1})
    return out


def private_key_hit(keys: List[Dict[str, Any]], in_ssh_dir: bool) -> Optional[Hit]:
    plain = [k for k in keys if k["encrypted"] is False]
    if not plain:
        return None
    sev = Severity.MEDIUM if in_ssh_dir else Severity.HIGH
    where = "in your .ssh folder" if in_ssh_dir else "outside .ssh (in a folder that is often synced, e-mailed or shared)"
    return Hit(
        "PRIVKEY", "Unencrypted private key file", sev,
        f"A private key without a passphrase ({plain[0]['kind']}) is stored {where}. Anyone who copies the file can "
        "log in to the servers/services it protects.",
        {"keys": [{"kind": k["kind"], "line": k["line"]} for k in plain[:5]], "count": len(plain)},
        "Protect the key with a passphrase (ssh-keygen -p -f <keyfile>) and keep it only in ~/.ssh with owner-only "
        "permissions; or better, use a hardware key / ssh-agent. If the key was ever copied elsewhere, generate a new key pair "
        "and remove the old public key from every server.", ["T1552.004"])


# =========================================================================== seed phrases
_WORDLIST_CACHE: Dict[str, Dict[str, int]] = {}


def load_bip39(path: Path = BIP39_FILE) -> Dict[str, int]:
    key = str(path)
    if key not in _WORDLIST_CACHE:
        words: Dict[str, int] = {}
        try:
            for i, line in enumerate(w.strip() for w in path.read_text(encoding="utf-8").splitlines() if w.strip()):
                words[line] = i
        except OSError:
            log.warning("BIP-39 wordlist missing at %s; seed phrase detection disabled", path)
        _WORDLIST_CACHE[key] = words if len(words) == 2048 else {}
    return _WORDLIST_CACHE[key]


def bip39_checksum_ok(words: Sequence[str], index: Dict[str, int]) -> bool:
    n = len(words)
    if n not in (12, 15, 18, 21, 24) or any(w not in index for w in words):
        return False
    bits = "".join(f"{index[w]:011b}" for w in words)
    cs_len = n // 3
    ent_len = len(bits) - cs_len
    ent = int(bits[:ent_len], 2).to_bytes(ent_len // 8, "big")
    digest = hashlib.sha256(ent).digest()
    return bits[ent_len:] == f"{digest[0]:08b}"[:cs_len]


def find_seed_phrases(text: str, index: Dict[str, int]) -> List[Dict[str, Any]]:
    """Runs of >=12 consecutive lowercase BIP-39 words. A window of 12/15/18/21/24 words with a valid BIP-39
    checksum is a real recovery phrase (valid=True); an exact-length run with a bad checksum is reported as 'possible'."""
    if not index:
        return []
    results: List[Dict[str, Any]] = []
    cur: List[str] = []

    def flush() -> None:
        nonlocal cur
        run = cur
        cur = []
        if not (12 <= len(run) <= 60):  # >60 is a dictionary/word list, not a seed
            return
        valid_window = None
        for L in (24, 21, 18, 15, 12):
            for start in range(0, len(run) - L + 1):
                w = run[start:start + L]
                if len(set(w)) >= L // 2 and bip39_checksum_ok(w, index):
                    valid_window = w
                    break
            if valid_window:
                break
        if valid_window:
            results.append({"words": len(valid_window), "checksum_valid": True, "first": mask(valid_window[0])})
        elif len(run) in (12, 15, 18, 21, 24) and len(set(run)) >= len(run) // 2:
            results.append({"words": len(run), "checksum_valid": False, "first": mask(run[0])})

    for tok in re.findall(r"[A-Za-z]+|\d+", text):
        if tok.isdigit():
            if len(tok) <= 2 and cur:
                continue  # list numbering "1. word 2. word"
            flush()
        elif tok in index:  # lowercase exact match only
            cur.append(tok)
        else:
            flush()
    flush()
    return results


def seed_hit(found: List[Dict[str, Any]]) -> Optional[Hit]:
    if not found:
        return None
    valid = any(f["checksum_valid"] for f in found)
    top = max(found, key=lambda f: (f["checksum_valid"], f["words"]))
    return Hit(
        "SEED", "Crypto wallet recovery (seed) phrase stored in a file" if valid else
        "Possible crypto wallet recovery phrase stored in a file",
        Severity.HIGH if valid else Severity.MEDIUM,
        (f"A {top['words']}-word BIP-39 recovery phrase with a valid checksum" if valid else
         f"A run of {top['words']} words from the BIP-39 recovery-word list")
        + " is saved in plain text. Anyone who reads it can empty the wallet - this is the first thing crypto-stealing "
        "malware searches for.",
        {"phrases": [{"words": f["words"], "checksum_valid": f["checksum_valid"], "first_word": f["first"]}
                     for f in found[:3]]},
        "Move the funds to a new wallet created with a NEW seed phrase right away if this phrase is real. Then delete "
        "this file (and empty the Recycle Bin / any cloud-sync copies) and keep the new phrase only on paper or a "
        "metal backup stored offline - never on a computer, phone or cloud drive.", ["T1552.001", "T1005"])


# =========================================================================== specific file formats
_SECRET_KEY_NAME = re.compile(r"(secret|passw(or)?d|passwd|pwd|token|api[_-]?key|private[_-]?key|access[_-]?key|"
                              r"client[_-]?secret|auth|credential|database_url|connection[_-]?string)", re.I)


def scan_env_file(text: str) -> Optional[Hit]:
    keys = []
    for ln, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.replace("export ", "").strip()
        v = v.strip().strip("'\"")
        if _SECRET_KEY_NAME.search(k) and not _is_placeholder(v):
            if k.upper().endswith("URL") and "@" not in v:
                continue  # URL without embedded credentials
            keys.append({"key": k, "value": mask(v), "line": ln})
    if not keys:
        return None
    return Hit("ENV", ".env file containing secrets", Severity.MEDIUM,
               f"{len(keys)} secret-looking setting(s) are stored in plain text in an environment file.",
               {"entries": keys[:15], "count": len(keys)}, ROTATE, ["T1552.001"])


def scan_password_lines(text: str) -> int:
    return sum(1 for l in text.splitlines() if re.search(r"(?i)\b(pass(word)?|pwd|passwd|pw)\b\s*[:=\-]\s*\S+", l))


def scan_git_credentials(text: str) -> Optional[Hit]:
    entries, token_like = [], False
    for line in text.splitlines():
        m = re.match(r"^\s*(\w+)://([^:/\s@]+):([^@\s]+)@([^/\s]+)", line)
        if m:
            pw = m.group(3)
            tl = len(pw) >= 20 or bool(re.match(r"(gh[pousr]_|github_pat_|glpat-|ATBB)", pw))
            token_like = token_like or tl
            entries.append({"host": m.group(4), "user": mask(m.group(2)), "password": mask(pw)})
    if not entries:
        return None
    return Hit("GITCRED", "Git credentials stored in plain text", Severity.HIGH if token_like else Severity.MEDIUM,
               f"{len(entries)} saved Git login(s) are stored unencrypted in .git-credentials.",
               {"entries": entries[:10], "count": len(entries)},
               "Revoke the stored token/password at the Git host, switch to a credential helper that uses the OS keychain "
               "(git config --global credential.helper manager on Windows, osxkeychain on macOS, libsecret on Linux), "
               "and delete ~/.git-credentials.", ["T1552.001"])


def scan_npmrc(text: str) -> Optional[Hit]:
    entries = []
    for ln, line in enumerate(text.splitlines(), 1):
        m = re.match(r"^\s*(?P<k>(?://[^\s=]+:)?_(?:authToken|auth|password))\s*=\s*(?P<v>\S+)", line)
        if m and not _is_placeholder(m.group("v")):
            entries.append({"key": m.group("k")[-12:], "value": mask(m.group("v")), "line": ln})
    if not entries:
        return None
    return Hit("NPMRC", "npm credentials stored in .npmrc", Severity.MEDIUM,
               f"{len(entries)} npm auth token/password setting(s) are saved in plain text.",
               {"entries": entries[:10]}, "Revoke the token on npmjs.com (Access Tokens), create a new granular token, and "
               "pass it through an environment variable (_authToken=${NPM_TOKEN}) instead of the file.", ["T1552.001"])


def scan_pypirc(text: str) -> Optional[Hit]:
    entries = []
    for ln, line in enumerate(text.splitlines(), 1):
        m = re.match(r"^\s*password\s*[:=]\s*(\S+)", line, re.I)
        if m and not _is_placeholder(m.group(1)):
            entries.append({"value": mask(m.group(1)), "line": ln})
    if not entries:
        return None
    return Hit("PYPIRC", "PyPI credentials stored in .pypirc", Severity.MEDIUM,
               f"{len(entries)} PyPI/TestPyPI password or token(s) are saved in plain text.",
               {"entries": entries[:10]}, "Revoke the token at pypi.org > Account settings > API tokens and use "
               "keyring or Trusted Publishing instead of a stored password.", ["T1552.001"])


def scan_docker_config(text: str) -> Optional[Hit]:
    regs: List[str] = []
    try:
        data = json.loads(text)
        for reg, v in (data.get("auths") or {}).items():
            if isinstance(v, dict) and v.get("auth"):
                regs.append(reg)
    except Exception:
        regs = [m.group(1) for m in re.finditer(r'"([^"]+)"\s*:\s*\{\s*"auth"\s*:\s*"[^"]{8,}"', text)]
    if not regs:
        return None
    return Hit("DOCKER", "Docker registry login stored in plain text", Severity.MEDIUM,
               f"Docker config holds a base64 (not encrypted) login for {len(regs)} registr{'y' if len(regs) == 1 else 'ies'}.",
               {"registries": regs[:10]}, "Run `docker logout <registry>`, rotate the registry password/token and configure a "
               "credential helper (credsStore) so Docker uses the OS keychain.", ["T1552.001"])


def scan_netrc(text: str) -> Optional[Hit]:
    machines = re.findall(r"(?:machine|default)\s+(\S+)", text)
    if re.search(r"\bpassword\s+\S+", text):
        return Hit("NETRC", "Passwords stored in .netrc", Severity.MEDIUM,
                   "The .netrc file stores login passwords in plain text for command-line tools (curl, git, ftp).",
                   {"machines": machines[:10]}, ROTATE, ["T1552.001"])
    return None


def scan_aws_credentials(text: str) -> Optional[Hit]:
    profiles = re.findall(r"^\s*\[([^\]]+)\]", text, re.M)
    secrets = [m.group(1) for m in re.finditer(r"aws_secret_access_key\s*=\s*(\S+)", text, re.I) if not _is_placeholder(m.group(1))]
    ids = [m.group(1) for m in re.finditer(r"aws_access_key_id\s*=\s*(\S+)", text, re.I)]
    if not secrets:
        return None
    return Hit("AWSFILE", "AWS credentials file contains long-term secret keys", Severity.MEDIUM,
               f"~/.aws/credentials stores {len(secrets)} secret access key(s) in plain text.",
               {"profiles": profiles[:10], "access_key_ids": [mask(i) for i in ids[:10]]},
               "Prefer short-lived credentials (AWS IAM Identity Center / `aws sso login`) and delete unused keys in the IAM "
               "console. Rotate any key that has been copied off this machine.", ["T1552.001"])


def scan_rdp(text: str) -> Optional[Hit]:
    m = re.search(r"(?im)^password 51:b:([0-9a-f]+)\s*$", text)
    if not m:
        return None
    host = re.search(r"(?im)^full address:s:(.+)$", text)
    return Hit("RDP", "Saved Remote Desktop password in .rdp file", Severity.MEDIUM,
               "This .rdp file contains an encrypted-but-recoverable saved password; infostealers can decrypt it on the "
               "same PC and anyone with your Windows profile can reuse it.",
               {"host": host.group(1).strip() if host else "", "password": "(hidden)"},
               "Delete the 'password 51:b:' line (re-open the connection and untick 'Allow me to save credentials'), and "
               "change the password for that remote account. Share .rdp files only without credentials.", ["T1552.001", "T1021.001"])


def scan_filezilla(text: str) -> Optional[Hit]:
    passes = re.findall(r"<Pass([^>]*)>([^<]+)</Pass>", text)
    if not passes:
        return None
    hosts = list(dict.fromkeys(re.findall(r"<Host>([^<]+)</Host>", text)))
    return Hit("FILEZILLA", "FileZilla saved FTP/SFTP passwords", Severity.MEDIUM,
               f"{len(passes)} FTP/SFTP password(s) are stored in plain text or base64 (trivially reversible).",
               {"servers": hosts[:10], "entries": len(passes)},
               "Change those server passwords, then in FileZilla choose 'Ask for password' (Site Manager > Logon Type) or use "
               "SSH keys. Delete sitemanager.xml / recentservers.xml entries you do not need.", ["T1552.001"])


def scan_unattend(text: str) -> Optional[Hit]:
    count, plain = 0, False
    for m in re.finditer(r"<(AdministratorPassword|Password)>(.*?)</\1>", text, re.S):
        body = m.group(2)
        v = re.search(r"<Value>(.*?)</Value>", body, re.S)
        if not v or not v.group(1).strip() or "SENSITIVE*DATA*DELETED" in v.group(1):
            continue
        count += 1
        pt = re.search(r"<PlainText>\s*(true|false)\s*</PlainText>", body, re.I)
        plain = plain or bool(pt and pt.group(1).lower() == "true")
    if not count:
        return None
    return Hit("UNATTEND", "Windows unattend/sysprep file contains a password", Severity.HIGH if plain else Severity.MEDIUM,
               f"{count} account password(s) are stored in this deployment answer file "
               + ("in clear text." if plain else "as reversible base64."),
               {"entries": count, "plain_text": plain},
               "Delete the file (C:\\Windows\\Panther\\unattend.xml etc.) and change the passwords of the accounts it created; "
               "they commonly reuse the local administrator password across many PCs.", ["T1552.001"])


KNOWN_FILE_SCANNERS: Dict[str, Callable[[str], Optional[Hit]]] = {
    ".git-credentials": scan_git_credentials,
    ".npmrc": scan_npmrc,
    ".pypirc": scan_pypirc,
    ".netrc": scan_netrc,
    "_netrc": scan_netrc,
    "credentials": scan_aws_credentials,  # only honoured inside a .aws directory
    "config.json": scan_docker_config,  # only honoured inside a .docker directory
    "sitemanager.xml": scan_filezilla,
    "recentservers.xml": scan_filezilla,
    "unattend.xml": scan_unattend,
    "sysprep.xml": scan_unattend,
    "autounattend.xml": scan_unattend,
}


# =========================================================================== filename heuristics
_STRONG_STEM = re.compile(
    r"^(my[ _\-]?|all[ _\-]?|old[ _\-]?|saved[ _\-]?|new[ _\-]?)?"
    r"(passwords?|passwd|pwds?|logins?|credentials?|accounts?[ _\-]?(and|&|n)?[ _\-]?passwords?)"
    r"(?:[ _\-.()]*(?:\d+|list|backup|old|new|copy|final|file|export|data|sheet|doc|v\d+|2fa|accounts?|sites?|"
    r"websites?|wifi|bank|email|crypto))*[ _\-.()]*$", re.I)
_WEAK_WORDS = ("password", "passwd", "credential", "secret", "recovery phrase", "recovery_phrase", "seed phrase",
               "seed_phrase", "backup codes", "backup_codes", "mnemonic", "private key", "private_key", "2fa", "api_key",
               "apikey")
WALLET_NAMES = {"wallet.dat", "exodus.wallet", "default_wallet", "keystore.json"}


def name_hit(path: Path) -> Optional[Hit]:
    """Suspicious file name (passwords.txt, wallet.dat, ...)."""
    name = path.name
    low = name.lower()
    stem, ext = os.path.splitext(low)
    if ext == ".kdbx" or ext == ".lnk":
        return None
    if low in WALLET_NAMES or ext == ".wallet" or low.startswith("utc--"):
        sev = Severity.LOW if low.startswith("utc--") else Severity.MEDIUM
        return Hit("WALLET", "Cryptocurrency wallet file", sev,
                   f"'{name}' is a crypto wallet file. Infostealers copy these files; if the wallet has no strong passphrase "
                   "the funds can be stolen.",
                   {"file_name": name}, "Make sure the wallet is protected by a long passphrase, keep the only backup offline "
                   "(not in Downloads/Desktop/cloud sync), and consider moving funds to a hardware wallet.",
                   ["T1005", "T1552.001"])
    if ext in DOC_EXTS or ext == "":
        if ext and _STRONG_STEM.match(stem):
            return Hit("PWFILE", "Password list stored in a file", Severity.MEDIUM,
                       f"The file '{name}' looks like a list of passwords or logins kept in a document or spreadsheet. "
                       "Infostealers specifically search for files with names like this.", {"file_name": name},
                       "Move the passwords into a password manager (Bitwarden, KeePassXC, 1Password...), delete the file and "
                       "change any password that was in it that matters (bank, e-mail, crypto).", ["T1552.001"])
        if ext and any(w in low for w in _WEAK_WORDS):
            return Hit("PWFILE", "File name suggests stored credentials", Severity.LOW,
                       f"The file name '{name}' suggests it may contain passwords, keys or recovery codes.",
                       {"file_name": name, "heuristic": "name only"},
                       "Check the file; if it contains real credentials move them to a password manager and delete it.",
                       ["T1552.001"])
    return None


# =========================================================================== file analysis
def _looks_binary(sample: bytes) -> bool:
    return b"\x00" in sample


def read_text_for_scan(path: Path) -> Optional[str]:
    """Return scannable text or None (too big, binary, unreadable). Handles .docx/.xlsx text."""
    ext = path.suffix.lower()
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size == 0:
        return None
    try:
        if ext in ZIP_DOC_EXTS:
            if size > MAX_FILE_BYTES:
                return None
            with zipfile.ZipFile(path) as z:
                member = "word/document.xml" if ext == ".docx" else "xl/sharedStrings.xml"
                info = z.getinfo(member)
                if info.file_size > MAX_UNZIPPED_BYTES:
                    return None
                xml = z.read(member).decode("utf-8", "replace")
            xml = re.sub(r"</(?:w:p|si|w:tab|w:br)[^>]*>", " ", xml)
            return re.sub(r"<[^>]+>", "", xml)
        name = path.name.lower()
        texty = ext in TEXT_EXTS or name in KNOWN_FILE_SCANNERS or name.startswith(("id_", ".env")) or name.endswith(".env")
        if not texty and ext == "" and size <= 200_000:
            texty = True
        if not texty or size > MAX_FILE_BYTES:
            return None
        with path.open("rb") as fh:
            head = fh.read(4096)
            if _looks_binary(head):
                return None
            rest = fh.read(MAX_FILE_BYTES)
        return (head + rest).decode("utf-8", "replace")
    except (OSError, zipfile.BadZipFile, KeyError, RuntimeError):
        return None


def _parent_names(path: Path) -> List[str]:
    return [p.name.lower() for p in path.parents][:4]


def analyse_file(path: Path, wordlist: Optional[Dict[str, int]] = None, in_ssh_dir: bool = False,
                 text: Optional[str] = None) -> List[Hit]:
    """All detections for one file."""
    hits: List[Hit] = []
    nh = name_hit(path)
    if nh:
        hits.append(nh)
    if text is None:
        text = read_text_for_scan(path)
    if text is None:
        return hits
    name = path.name.lower()
    handled = False

    # dedicated parsers for well-known credential stores (they replace the generic token scan)
    scanner = KNOWN_FILE_SCANNERS.get(name)
    parents = _parent_names(path)
    if scanner and not (name == "credentials" and ".aws" not in parents) \
            and not (name == "config.json" and ".docker" not in parents):
        handled = True
        h = scanner(text)
        if h:
            hits.append(h)
    if path.suffix.lower() == ".rdp":
        h = scan_rdp(text)
        if h:
            hits.append(h)
    if name == ".env" or name.startswith(".env.") or name.endswith(".env"):
        if not name.endswith((".example", ".sample", ".template", ".dist")):
            h = scan_env_file(text)
            if h:
                hits.append(h)
                handled = True  # avoid double-reporting the same tokens

    if not handled:
        hits.extend(scan_tokens(text))
    kh = private_key_hit(scan_private_keys(text), in_ssh_dir)
    if kh:
        hits.append(kh)
    if wordlist:
        sh = seed_hit(find_seed_phrases(text, wordlist))
        if sh:
            hits.append(sh)
    # password-list content check upgrades a weak name hit only when lines look like real credentials
    if nh and nh.rule == "PWFILE" and nh.severity == Severity.LOW:
        n = scan_password_lines(text)
        if n >= 3:
            nh.severity = Severity.MEDIUM
            nh.title = "Password list stored in a file"
            nh.evidence["credential_like_lines"] = n
            nh.description = (f"'{path.name}' contains {n} lines that look like 'password: ...' entries. "
                              "Infostealers search for files like this.")
        else:
            nh.evidence["credential_like_lines"] = n
    return hits


def scan_file(path: Path, wordlist: Optional[Dict[str, int]] = None, in_ssh_dir: bool = False) -> List[Finding]:
    return [h.to_finding(str(path)) for h in analyse_file(path, wordlist, in_ssh_dir)]


# =========================================================================== discovery
def scan_roots(home: Path) -> List[Tuple[Path, int]]:
    """(directory, max_depth). depth 0 = files directly inside only."""
    roots: List[Tuple[Path, int]] = [(home / "Desktop", 4), (home / "Documents", 4), (home / "Downloads", 3), (home, 0)]
    try:
        for od in sorted(home.glob("OneDrive*")):
            roots += [(od / "Desktop", 4), (od / "Documents", 4), (od, 0)]
    except OSError:
        pass
    seen, out = set(), []
    for p, d in roots:
        try:
            key = str(p.resolve())
        except OSError:
            key = str(p)
        if key not in seen and p.is_dir():
            seen.add(key)
            out.append((p, d))
    return out


def iter_candidate_files(root: Path, max_depth: int, limit: int = 20000) -> Iterator[Path]:
    base_depth = len(root.parts)
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        depth = len(Path(dirpath).parts) - base_depth
        dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIRS and not (d.startswith(".") and d.lower() != ".aws")
                       ] if depth < max_depth else []
        for fn in filenames:
            count += 1
            if count > limit:
                return
            yield Path(dirpath) / fn


def known_credential_files(home: Path) -> List[Path]:
    cands = [home / ".git-credentials", home / ".npmrc", home / ".pypirc", home / ".netrc", home / "_netrc",
             home / ".docker" / "config.json", home / ".aws" / "credentials", home / ".config" / "gh" / "hosts.yml",
             home / ".env"]
    appdata = env_path("APPDATA") if IS_WINDOWS else None
    roots = [home / ".config" / "filezilla"]
    if appdata:
        roots.append(appdata / "FileZilla")
        cands += [appdata / "npm" / ".npmrc", appdata / "pip" / "pip.ini"]
    for r in roots:
        cands += [r / "sitemanager.xml", r / "recentservers.xml"]
    if IS_WINDOWS:
        win = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        drive = Path(os.environ.get("SystemDrive", "C:") + "\\")
        cands += [win / "Panther" / "unattend.xml", win / "Panther" / "Unattend" / "Unattend.xml",
                  win / "Panther" / "Unattend" / "Autounattend.xml", win / "System32" / "Sysprep" / "unattend.xml",
                  win / "System32" / "Sysprep" / "sysprep.xml", drive / "unattend.xml", drive / "sysprep.xml"]
    return [p for p in cands if p.is_file()]


def known_wallet_locations(home: Path) -> List[Path]:
    out: List[Path] = []
    bases: List[Path] = []
    if IS_WINDOWS:
        for v in ("APPDATA", "LOCALAPPDATA"):
            p = env_path(v)
            if p:
                bases.append(p)
    else:
        bases += [home / ".bitcoin", home / ".electrum", home / ".ethereum", home / ".config", home / "Library" / "Application Support"]
    for b in bases:
        for rel in ("Bitcoin/wallet.dat", "Bitcoin/wallets/wallet.dat", "Electrum/wallets/default_wallet",
                    "Exodus/exodus.wallet", ".bitcoin/wallet.dat", "wallet.dat", "wallets/default_wallet"):
            p = b / rel
            if p.exists():
                out.append(p)
        eth = b / "Ethereum" / "keystore"
        if eth.is_dir():
            out += sorted(eth.glob("UTC--*"))[:5]
    return out


def ssh_private_key_files(ssh_dir: Path) -> List[Path]:
    out = []
    if not ssh_dir.is_dir():
        return out
    for p in sorted(ssh_dir.iterdir()):
        n = p.name.lower()
        if not p.is_file() or n.endswith(".pub") or n in ("known_hosts", "known_hosts.old", "config", "authorized_keys",
                                                          "authorized_keys2"):
            continue
        out.append(p)
    return out


def check_ssh_permissions(ssh_dir: Path) -> List[Finding]:
    """POSIX only: private keys that other users can read, loose ~/.ssh permissions."""
    findings: List[Finding] = []
    if not ssh_dir.is_dir():
        return findings
    try:
        dmode = statmod.S_IMODE(ssh_dir.stat().st_mode)
    except OSError:
        return findings
    if dmode & 0o022:
        findings.append(Finding(
            rule_id="AEG-SEC-SSHDIR", title="~/.ssh folder is writable by other users", severity=Severity.MEDIUM,
            category=Category.PRIVACY, location=str(ssh_dir),
            description=f"{ssh_dir} has mode {dmode:04o}; other users could replace authorized_keys or your keys.",
            evidence={"mode": f"{dmode:04o}"}, recommendation=f"Run: chmod 700 {ssh_dir}",
            remediation=Remediation("run_command", {"command": ["chmod", "700", str(ssh_dir)], "powershell": False},
                                    "Restrict ~/.ssh to the owner"), mitre=["T1098.004"]))
    for p in ssh_private_key_files(ssh_dir):
        try:
            st = p.stat()
            if st.st_size > 100_000:
                continue
            head = p.read_text(encoding="utf-8", errors="replace")[:4000]
        except OSError:
            continue
        if not re.search(r"-----BEGIN [A-Z ]*PRIVATE KEY-----|PuTTY-User-Key-File", head):
            continue
        mode = statmod.S_IMODE(st.st_mode)
        if mode & 0o044:
            other = bool(mode & 0o004)
            findings.append(Finding(
                rule_id="AEG-SEC-SSHPERM",
                title="SSH private key readable by other users" if other else "SSH private key readable by group members",
                severity=Severity.HIGH if other else Severity.MEDIUM, category=Category.PRIVACY, location=str(p),
                description=f"{p.name} has mode {mode:04o}. " + ("Every local user" if other else "Members of its group")
                + " can read the private key and impersonate you on every server that trusts it.",
                evidence={"mode": f"{mode:04o}", "file": str(p)},
                recommendation=f"Run: chmod 600 {p}  (OpenSSH also refuses to use keys with loose permissions). "
                               "If other users could read it for a long time, replace the key pair.",
                remediation=Remediation("run_command", {"command": ["chmod", "600", str(p)], "powershell": False},
                                        "Make the private key owner-readable only"), mitre=["T1552.004"]))
    return findings


def registry_secret_hits() -> List[Tuple[str, Hit]]:
    """PuTTY proxy passwords and WinSCP saved passwords (Windows registry; empty elsewhere)."""
    out: List[Tuple[str, Hit]] = []
    for path, vals in reg_walk_values("HKCU", r"Software\SimonTatham\PuTTY\Sessions"):
        pw = vals.get("ProxyPassword")
        if pw:
            sess = path.rsplit("\\", 1)[-1]
            out.append((f"HKCU\\{path}", Hit("PUTTY", "PuTTY session stores a proxy password", Severity.MEDIUM,
                                              f"PuTTY saved session '{sess}' keeps its proxy password in plain text in the registry.",
                                              {"session": sess, "ProxyPassword": mask(str(pw))},
                                              "Remove the password from the session (PuTTY > Connection > Proxy) and change it.",
                                              ["T1552.002"])))
    for path, vals in reg_walk_values("HKCU", r"Software\Martin Prikryl\WinSCP 2\Sessions"):
        if vals.get("Password"):
            sess = path.rsplit("\\", 1)[-1]
            out.append((f"HKCU\\{path}", Hit("WINSCP", "WinSCP session stores a password", Severity.MEDIUM,
                                              f"WinSCP saved session '{sess}' stores its password in the registry using weak, "
                                              "reversible obfuscation.", {"session": sess, "password": "(hidden)"},
                                              "Delete the saved password (WinSCP > Edit session), use SSH keys or a master "
                                              "password (Preferences > Security) and change the server password.",
                                              ["T1552.002"])))
    return out


# =========================================================================== scanner
@register
class SecretsScanner(Scanner):
    name = "secrets"
    title = "Credential exposure scan"
    description = ("Finds passwords, API keys, private keys, recovery phrases and wallet files left in plain text "
                   "- the things infostealers harvest.")
    platforms = ("windows", "linux", "darwin")

    def run(self, ctx: ScanContext) -> Iterator[Emitted]:
        home = user_home()
        wordlist = load_bip39()
        max_files = 12000 if ctx.deep else 4000
        budget = 180.0 if ctx.deep else 60.0
        deadline = time.monotonic() + budget
        seen: set = set()
        scanned = 0
        flagged = 0

        def emit(hits: List[Hit], path: Path) -> Iterator[Finding]:
            nonlocal flagged
            for h in hits:
                flagged += 1
                yield h.to_finding(str(path))

        ctx.report(self.name, "checking known credential stores")
        # 1. well-known credential files and wallets
        for p in known_credential_files(home):
            key = str(p).lower()
            if key in seen:
                continue
            seen.add(key)
            scanned += 1
            try:
                yield from emit(analyse_file(p, wordlist), p)
            except Exception as exc:
                log.debug("secrets: %s: %s", p, exc)
        for p in known_wallet_locations(home):
            nh = name_hit(p)
            if nh and str(p).lower() not in seen:
                seen.add(str(p).lower())
                nh.severity = Severity.INFO
                nh.title = "Cryptocurrency wallet installed"
                nh.description = (f"A crypto wallet file ({p.name}) exists in its application folder. Infostealers copy these; "
                                  "its safety depends on the wallet passphrase.")
                yield from emit([nh], p)

        # 2. ~/.ssh
        ssh_dir = home / ".ssh"
        ssh_findings: List[Finding] = []
        if ssh_dir.is_dir():
            for p in ssh_private_key_files(ssh_dir):
                seen.add(str(p).lower())
                scanned += 1
                try:
                    text = p.read_text(encoding="utf-8", errors="replace")[:200_000] if p.stat().st_size < 200_000 else None
                except OSError:
                    text = None
                if text and re.search(r"-----BEGIN|PuTTY-User-Key-File", text):
                    kh = private_key_hit(scan_private_keys(text), True)
                    if kh:
                        yield from emit([kh], p)
            if not IS_WINDOWS:
                ssh_findings = check_ssh_permissions(ssh_dir)
                for f in ssh_findings:
                    flagged += 1
                    yield f
        if not IS_WINDOWS:
            yield CheckResult("AEG-SEC-SSHPERM", "SSH keys have safe permissions",
                              CheckStatus.FAIL if ssh_findings else (CheckStatus.PASS if ssh_dir.is_dir() else CheckStatus.SKIP),
                              f"{len(ssh_findings)} permission problem(s) in {ssh_dir}." if ssh_findings else
                              ("Permissions look correct." if ssh_dir.is_dir() else "No ~/.ssh folder."), Category.PRIVACY)

        # 3. user folders
        for root, depth in scan_roots(home):
            ctx.report(self.name, f"scanning {root}")
            for path in iter_candidate_files(root, depth):
                if ctx.cancelled or scanned >= max_files or time.monotonic() > deadline:
                    break
                key = str(path).lower()
                if key in seen:
                    continue
                seen.add(key)
                scanned += 1
                try:
                    hits = analyse_file(path, wordlist)
                except Exception as exc:  # never let one odd file stop the scan
                    log.debug("secrets: %s: %s", path, exc)
                    continue
                yield from emit(hits, path)
            if ctx.cancelled:
                break

        # 4. registry-stored passwords (Windows)
        if IS_WINDOWS:
            try:
                for loc, hit in registry_secret_hits():
                    flagged += 1
                    yield hit.to_finding(loc)
            except Exception as exc:
                log.debug("secrets registry scan failed: %s", exc)

        ctx.bump("secrets_files_scanned", scanned)
        yield CheckResult(
            "AEG-SEC-EXPOSED", "No credentials, keys or recovery phrases left in plain text",
            CheckStatus.PASS if flagged == 0 else CheckStatus.FAIL,
            f"Scanned {scanned} file(s); {flagged} exposure(s) found." if flagged else f"Scanned {scanned} file(s); nothing exposed.",
            Category.PRIVACY)
