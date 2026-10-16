"""Tests for aegis.scanners.remoteaccess: the log and configuration parsers (realistic samples in UTF-8, UTF-8 with a byte order
mark, UTF-16 and Windows-1252), the host classifier, the collectors over a fake Windows PC and Linux / macOS trees with several
user profiles and a fake registry, every finding branch, the check result, the redaction of passwords, hashes, keys and session
ids, the scanner flow, and a run on this machine. Nothing here reads a real remote-access tool's files except the one test that
says so."""

import codecs
import datetime as dt
import json
import os
import plistlib
import re
import time
from pathlib import Path

import pytest

from aegis.core.models import Category, CheckResult, CheckStatus, Finding, Severity
from aegis.scanners import remoteaccess as ra
from aegis.scanners.base import REGISTRY, load_all

NOW = dt.datetime(2026, 10, 16, 12, 0)
IP = "45.9.148.10"  # a public address (the documentation ranges count as private)
BAD_IP = "185.220.101.7"
RLO = "\u202e"

# secrets planted in every sample: none of them may reach a finding, a check result, a report or a log
ANYDESK_HASH = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
ANYDESK_SALT = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
ANYDESK_TOKEN_SALT = "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b"
TEAMVIEWER_AES = "SECRETAESBLOB0123456789ABCDEF"
TEAMVIEWER_OPTIONS_AES = "OPTIONSAESBLOB9876543210FEDCBA"
SC_KEY = "BgIAAACkAABSU0ExAAgAAAEAAQDKq3Xy7pW9hQ"
SC_SESSION = "0f9d6a64-3c1e-4b52-8a37-6c5d2b8e1f90"
RUSTDESK_PASSWORD = "00gH3k9dQwErTy5uIoPlKjHgSECRET=="
RUSTDESK_SALT = "r4nd0ms4ltv4lueSECRET"
RUSTDESK_KEY_PAIR = "219, 44, 173, 90, 12, 7, 255, 131"
RUSTDESK_SERVER_KEY = "Qk3vJ8w1u5X0pZ2mN7aB9cD4eF6gH8iJ0kL2mN4oPSECRETKEY="
NETSUPPORT_GSK = "FA=B3G9Q<O8M@E8:HHC<I8:3N0SECRETGSK"
NETSUPPORT_KEY = "NS-SECURITY-KEY-1234567890"
MESH_ID = "0xA3F10B77C4E2D9" + "5B" * 24
MESH_SERVER_ID = "7B6E1D3F9A02C85E" + "AC" * 24
SECRETS = (ANYDESK_HASH, ANYDESK_SALT, ANYDESK_TOKEN_SALT, TEAMVIEWER_AES, TEAMVIEWER_OPTIONS_AES, SC_KEY, SC_SESSION,
           RUSTDESK_PASSWORD, RUSTDESK_SALT, RUSTDESK_KEY_PAIR, RUSTDESK_SERVER_KEY, NETSUPPORT_GSK, NETSUPPORT_KEY, MESH_ID,
           MESH_SERVER_ID)


def split(out):
    out = list(out)
    return [x for x in out if isinstance(x, Finding)], [x for x in out if isinstance(x, CheckResult)]


def rules(findings):
    return [f.rule_id for f in findings]


def by_rule(findings):
    return {f.rule_id: f for f in findings}


def put(path, content, encoding="utf-8"):
    """Write text (or bytes) to a file, creating the folders."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content if isinstance(content, bytes) else content.encode(encoding))
    return path


def utf16(text, bom=True, order="le"):
    mark = (codecs.BOM_UTF16_LE if order == "le" else codecs.BOM_UTF16_BE) if bom else b""
    return mark + text.encode(f"utf-16-{order}")


def age(path, days):
    stamp = time.time() - days * 86400
    os.utime(path, (stamp, stamp))
    return path


# =========================================================================== samples (the formats as the tools write them)
ANYDESK_CONNECTIONS = (
    "Incoming    2026-10-12, 09:41    User    123456789    123456789\n"
    "Incoming    2026-10-13, 22:15    Passwd    987654321    987654321\n"
    "Incoming    2026-10-14, 03:07    Token    987654321    helpdesk@ad\n"
    "Outgoing    2026-10-14, 10:00    User    555000111    555000111\n"
    "Incoming    2026-10-15, 18:30    Rejected    111222333    111222333\n"
)
ANYDESK_TRACE = (
    "   info 2026-10-13 22:14:58.512       svc   2216   3584   -   app.service - Starting AnyDesk service.\n"
    f"   info 2026-10-13 22:15:01.220       svc   2216   3584   -   anynet.any_socket - Logged in from {BAD_IP}:50443 on relay "
    "3a9f1c2e.\n"
    "   info 2026-10-13 22:15:01.980       svc   2216   3584   -   app.session - Incoming session request: Mallory (987654321).\n"
    "   info 2026-10-13 22:15:02.100       svc   2216   3584   -   app.session - Remote OS: Windows 10.\n"
    "   info 2026-10-14 03:06:49.001       svc   2216   3584   -   anynet.any_socket - Logged in from "
    "[2001:db8:85a3::8a2e:370:7334]:51234 on relay 77ab01ff.\n"
    "   info 2026-10-14 03:06:50.300       svc   2216   3584   -   app.session - Incoming session request: helpdesk@ad "
    "(987654321).\n"
    "   warning 2026-10-14 03:07:00.000    svc   2216   3584   -   anynet.any_socket - Logged in from nowhere on relay 0.\n"
)
ANYDESK_SYSTEM_CONF = (
    "ad.anynet.id=123456780\n"
    f"ad.anynet.pwd_hash={ANYDESK_HASH}\n"
    f"ad.anynet.pwd_salt={ANYDESK_SALT}\n"
    f"ad.anynet.token_salt={ANYDESK_TOKEN_SALT}\n"
    "ad.security.acl_enabled=false\n"
    "ad.security.interactive_access=2\n"
)
TEAMVIEWER_INCOMING = (
    "1357924680\tCarol-Laptop\t12-10-2026 09:41:07\t12-10-2026 10:12:44\talice\tRemoteControl\t"
    "{4f1c5b6e-0000-4a7e-9c77-1f2e3d4c5b6a}\n"
    "1357924680\tCarol-Laptop\t15-10-2026 21:05:00\t15-10-2026 21:30:10\talice\tFileTransfer\t"
    "{0a1b2c3d-1111-4222-8333-444455556666}\n"
    "2468013579\tSupport Desk (M\u00fcller)\t16-10-2026 08:00:12\t16-10-2026 08:03:55\talice\tRemoteControl\t"
    "{99887766-5544-4332-8211-00ffeeddccbb}\n"
)
SC_ACCESS_IMAGE = (
    '"C:\\Program Files (x86)\\ScreenConnect Client (a1b2c3d4e5f6a7b8)\\ScreenConnect.ClientService.exe" '
    f'"?e=Access&y=Guest&h=instance-ab12cd-relay.screenconnect.com&p=443&s={SC_SESSION}&k={SC_KEY}&t=Reception+PC'
    '&c=ACME+Ltd&c=&c=&c=Laptop"')
SC_SUPPORT_IMAGE = (
    '"C:\\Program Files (x86)\\ScreenConnect Client (0123456789abcdef)\\ScreenConnect.ClientService.exe" '
    f'"?e=Support&y=Guest&h=helpdesk.fixmypc.duckdns.org&p=8041&s={SC_SESSION}&k={SC_KEY}&t=&c=&c=&c=&c="')
RUSTDESK_MAIN = (
    "id = '742913850'\n"
    f"password = '{RUSTDESK_PASSWORD}'\n"
    f"salt = '{RUSTDESK_SALT}'\n"
    f"key_pair = [[{RUSTDESK_KEY_PAIR}],\n"
    "  [17, 3, 99, 250, 1, 2, 3]]\n"
    "key_confirmed = true\n"
    "\n"
    "[keys_confirmed]\n"
    "'rd.example.net' = true\n"
)
RUSTDESK_SECOND = (
    "rendezvous_server = 'rd.example.net:21116'\n"
    "nat_type = 1\n"
    "serial = 0\n"
    "\n"
    "[options]\n"
    "custom-rendezvous-server = 'rd.example.net'\n"
    "relay-server = 'rd.example.net'\n"
    "api-server = 'https://rd.example.net'\n"
    f"key = '{RUSTDESK_SERVER_KEY}'\n"
    "verification-method = 'use-both-passwords'\n"
    "approve-mode = 'password'\n"
)
RUSTDESK_LOG = (
    "[2026-10-14 03:06:49.512345 +00:00] INFO [src/server.rs:112] Server started\n"
    f"[2026-10-14 03:06:49.600000 +00:00] INFO [src/server/connection.rs:176] Connection opened from {BAD_IP}:50443.\n"
    "[2026-10-14 03:06:50.000000 +00:00] INFO [src/server/connection.rs:300] Login request received\n"
)
NETSUPPORT_INI = (
    "[_Info]\n"
    "Filename=C:\\Users\\bob\\AppData\\Roaming\\WinUpd\\client32.ini\n"
    "\n"
    "[Client]\n"
    "_present=1\n"
    "DisableChat=1\n"
    "silent=1\n"
    "SysTray=0\n"
    "DisableDisconnect=1\n"
    f"SecurityKey={NETSUPPORT_KEY}\n"
    "\n"
    "[HTTP]\n"
    "CMPI=60\n"
    f"GatewayAddress={IP}:443\n"
    "Port=443\n"
    "SecondaryGateway=updatecheck.duckdns.org\n"
    "SecondaryPort=8443\n"
    f"GSK={NETSUPPORT_GSK}\n"
)
NETSUPPORT_LEGIT_INI = "[Client]\n_present=1\nDisableChat=0\n\n[HTTP]\nPort=5405\n"
MESH_MSH = (
    "MeshName=Reception PCs\n"
    "MeshType=2\n"
    f"MeshID={MESH_ID}\n"
    f"ServerID={MESH_SERVER_ID}\n"
    "MeshServer=wss://mesh.acme-it.example:443/agent.ashx\n"
)


# =========================================================================== fake machines
class FakeRegistry:
    """HKLM as {key path: {value: data}}; names are matched without regard to case, as the registry does."""

    def __init__(self):
        self.keys = {}
        self.originals = []

    def add(self, key, values=None):
        self.keys[key.lower()] = dict(values or {})
        self.originals.append(key)

    def values(self, hive, key, view64=True):
        return dict(self.keys.get(key.lower(), {}))

    def read(self, hive, key, value, view64=True):
        for name, data in self.keys.get(key.lower(), {}).items():
            if name.lower() == value.lower():
                return data
        return None

    def subkeys(self, hive, key, view64=True):
        prefix = key.lower() + "\\"
        out = []
        for original in self.originals:
            if original.lower().startswith(prefix):
                name = original[len(prefix):].split("\\")[0]
                if name not in out:
                    out.append(name)
        return out


class Pc:
    """A fake Windows PC under a temporary folder: users alice and bob, Program Files, ProgramData and a registry."""

    def __init__(self, tmp_path, users=("alice", "bob")):
        self.root = tmp_path / "c"
        self.reg = FakeRegistry()
        profiles = []
        for name in users:
            home = self.root / "Users" / name
            for sub in ("AppData/Roaming", "AppData/Local/Temp", "Downloads", "Desktop"):
                (home / sub).mkdir(parents=True)
            profiles.append(ra.Profile(name, home, home / "AppData" / "Roaming", home / "AppData" / "Local"))
        self.pf, self.pf86, self.pd = (self.root / "Program Files", self.root / "Program Files (x86)", self.root / "ProgramData")
        for folder in (self.pf, self.pf86, self.pd):
            folder.mkdir(parents=True)
        self.service_home = self.root / "Windows" / "ServiceProfiles" / "LocalService" / "AppData" / "Roaming"
        self.service_home.mkdir(parents=True)
        self.env = ra.Env(
            os_name="windows", profiles=profiles, program_dirs=[self.pf, self.pf86], program_data=self.pd,
            public=self.root / "Users" / "Public", service_profiles=[self.service_home],
            temp_dirs=[self.root / "Windows" / "Temp"], read_value=self.reg.read, read_values=self.reg.values,
            read_subkeys=self.reg.subkeys)
        (self.root / "Windows" / "Temp").mkdir(parents=True)

    def user(self, name):
        return next(p for p in self.env.profiles if p.name == name)

    def service(self, name, image):
        self.reg.add(f"{ra.SERVICES_KEY}\\{name}", {"ImagePath": image})
        self.env.services = ra.read_services(self.reg.subkeys, self.reg.read)


class Unix:
    """A fake Linux or macOS machine under a temporary folder: users alice and a root account, and a fake root folder."""

    def __init__(self, tmp_path, os_name="linux"):
        self.root = tmp_path / "unix"
        profiles = []
        for name, home in (("alice", self.root / "home" / "alice"), ("root", self.root / "root")):
            home.mkdir(parents=True)
            profiles.append(ra.Profile(name, home, home / ".config", home / ".local" / "share"))
        self.tmp = self.root / "tmp"
        self.tmp.mkdir()
        self.env = ra.Env(os_name=os_name, profiles=profiles, root=self.root, temp_dirs=[self.tmp])

    def user(self, name):
        return next(p for p in self.env.profiles if p.name == name)


@pytest.fixture
def pc(tmp_path):
    return Pc(tmp_path)


@pytest.fixture
def unix(tmp_path):
    return Unix(tmp_path)


def session(when="2026-10-14 03:07", remote_id="987654321", **kw):
    return ra.Session(dt.datetime.fromisoformat(when) if isinstance(when, str) else when, remote_id=remote_id, **kw)


def report(tool="anydesk", name="AnyDesk", **kw):
    kw.setdefault("location", r"C:\ProgramData\AnyDesk")
    return ra.ToolReport(tool, name, **kw)


# =========================================================================== pure helpers
@pytest.mark.parametrize("text,expected", [
    ("2026-10-12, 09:41", dt.datetime(2026, 10, 12, 9, 41)),
    ("2026-10-12 09:41:07.123", dt.datetime(2026, 10, 12, 9, 41, 7)),
    ("2026-10-12T09:41:07", dt.datetime(2026, 10, 12, 9, 41, 7)),
    ("12-10-2026 09:41:07", dt.datetime(2026, 10, 12, 9, 41, 7)),  # day first, as TeamViewer writes it
    ("12.10.2026 09:41:07", dt.datetime(2026, 10, 12, 9, 41, 7)),
    ("10/14/2026 09:41:07", dt.datetime(2026, 10, 14, 9, 41, 7)),  # cannot be day first
    ("15-10-2026 23:59", dt.datetime(2026, 10, 15, 23, 59)),
])
def test_parse_time(text, expected):
    assert ra.parse_time(text) == expected


@pytest.mark.parametrize("text", ["", "garbage", "2026-10-12", "2026-13-40, 10:00", "1999-01-01 10:00", "32-01-2026 10:00",
                                  "2101-01-01 10:00", "Incoming"])
def test_parse_time_rejects_what_is_not_a_time(text):
    assert ra.parse_time(text) is None


@pytest.mark.parametrize("text,expected", [
    ("203.0.113.9:50443", ("203.0.113.9", 50443)),
    ("203.0.113.9:50443.", ("203.0.113.9", 50443)),
    ("[2001:db8:85a3::8a2e:370:7334]:51234", ("2001:db8:85a3::8a2e:370:7334", 51234)),
    ("2001:db8::1", ("2001:db8::1", None)),
    ("203.0.113.9", ("203.0.113.9", None)),
    ("relay-3a9f", None), ("999.1.1.1:80", None), ("", None), ("nowhere", None),
])
def test_split_address(text, expected):
    assert ra.split_address(text) == expected


@pytest.mark.parametrize("text,expected", [
    ("rd.example.net", ("rd.example.net", None)),
    ("rd.example.net:21116", ("rd.example.net", 21116)),
    ("https://rd.example.net/api?x=1", ("rd.example.net", None)),
    ("wss://Mesh.Example.com:443/agent.ashx", ("mesh.example.com", 443)),
    ("[2001:db8::1]:21116", ("2001:db8::1", 21116)),
    ("  'quoted.example.net'  ", ("quoted.example.net", None)),
    ("user:pass@creds.example.net:80", ("creds.example.net", 80)),
    ("host:99999", ("host", None)),
    ("", ("", None)), ("   ", ("", None)),
])
def test_host_of(text, expected):
    assert ra.host_of(text) == expected


def test_clean_drops_control_characters_and_spells_out_direction_controls():
    assert ra.clean(f"Mal\x00lory\n{RLO}fdp.exe\t") == "Mallory<U+202E>fdp.exe"
    assert ra.clean("x" * 500, 20) == "x" * 20
    assert ra.clean(None) == "None"


@pytest.mark.parametrize("name,secret", [
    ("password", True), ("Password2", True), ("salt", True), ("key_pair", True), ("key", True), ("GSK", True),
    ("SecondaryGSK", True), ("SecurityKey", True), ("ad.anynet.pwd_hash", True), ("ad.anynet.token_salt", True),
    ("MeshID", True), ("ServerID", True),
    ("ad.security.permission_profiles._unattended_access.pwd", True), ("api-key", True),
    ("id", False), ("GatewayAddress", False), ("rendezvous_server", False), ("MeshServer", False), ("MeshName", False),
    ("ad.anynet.id", False), ("relay-server", False), ("keys_confirmed", False), ("Port", False),
])
def test_secret_names(name, secret):
    assert ra.is_secret_name(name) is secret


def test_mask_keeps_only_whether_a_value_is_set():
    assert ra.mask("hunter2") == "set" and ra.mask("  ") == "" and ra.mask("") == ""


@pytest.mark.parametrize("value,empty", [(None, True), ("", True), ("  \x00", True), (b"", True), (b"\x00\x00", True),
                                         (bytearray(b" "), True), (b"\x01", False), ("x", False), (0, False), (7, False)])
def test_empty_values(value, empty):
    assert ra._empty(value) is empty


# --------------------------------------------------------------------------- host classification
def test_a_public_ip_address_is_high():
    sev, reasons = ra.classify_host(IP)
    assert sev == Severity.HIGH and "bare IP address" in reasons[0]


@pytest.mark.parametrize("host", ["192.168.1.20", "10.0.0.5", "127.0.0.1", "172.16.4.4", "100.100.1.1", "fd00::1"])
def test_a_private_address_is_medium(host):
    sev, reasons = ra.classify_host(host)
    assert sev == Severity.MEDIUM and "private network" in reasons[0]


@pytest.mark.parametrize("host", ["me.duckdns.org", "x.ddns.net", "a.b.no-ip.org", "host.no-ip.biz", "srv.hopto.org",
                                  "srv.zapto.org", "files.servehttp.com", "x.myftp.org", "DUCKDNS.ORG", "me.duckdns.org."])
def test_dynamic_dns_names_are_high(host):
    sev, reasons = ra.classify_host(host)
    assert sev == Severity.HIGH and "dynamic-DNS" in reasons[0]


@pytest.mark.parametrize("host", ["rd.example.net", "support.acme-it.example", "notduckdns.org", "ddns.net.example.com",
                                  "mesh.co"])
def test_any_other_server_is_medium(host):
    sev, reasons = ra.classify_host(host)
    assert sev == Severity.MEDIUM and "run by whoever owns that name" in reasons[0]


def test_the_threat_feed_makes_a_host_high():
    sev, reasons = ra.classify_host("rd.example.net", lambda h: h == "rd.example.net")
    assert sev == Severity.HIGH and reasons == ["listed as malicious on the threat feed"]
    sev, reasons = ra.classify_host(BAD_IP, lambda h: h == BAD_IP)
    assert sev == Severity.HIGH and len(reasons) == 2
    assert ra.classify_host("rd.example.net", lambda h: False)[0] == Severity.MEDIUM


# --------------------------------------------------------------------------- encodings and reading
@pytest.mark.parametrize("raw,encoding", [
    (b"plain ascii text\r\n", "utf-8"),
    (codecs.BOM_UTF8 + b"with a byte order mark", "utf-8"),
    (codecs.BOM_UTF16_LE + "text".encode("utf-16-le"), "utf-16-le"),
    (codecs.BOM_UTF16_BE + "text".encode("utf-16-be"), "utf-16-be"),
    ("Incoming 2026-10-12".encode("utf-16-le"), "utf-16-le"),  # no byte order mark: the zero bytes give it away
    ("Incoming 2026-10-12".encode("utf-16-be"), "utf-16-be"),
    (b"", "utf-8"), (b"ab", "utf-8"),
])
def test_sniff_encoding(raw, encoding):
    assert ra.sniff_encoding(raw) == encoding


def test_decode_text_handles_every_encoding_the_logs_use():
    line = "Incoming 2026-10-12 M\u00fcller"
    for raw in (line.encode("utf-8"), codecs.BOM_UTF8 + line.encode("utf-8"), utf16(line), utf16(line, bom=False),
                utf16(line, order="be"), utf16(line, bom=False, order="be"), line.encode("cp1252")):
        assert ra.decode_text(raw) == line, raw[:10]
    assert ra.decode_text(b"") == ""
    assert ra.decode_text(b"\xff\xfe\xfa") != ""  # a broken file is decoded with replacement characters, never an error


def test_read_text_tail_keeps_whole_lines(tmp_path):
    lines = [f"line {i:05d} {'x' * 40}\n" for i in range(2000)]
    for name, raw in (("u8.txt", "".join(lines).encode()), ("u16.txt", utf16("".join(lines))),
                      ("u16nobom.txt", utf16("".join(lines), bom=False)), ("u16be.txt", utf16("".join(lines), order="be"))):
        path = put(tmp_path / name, raw)
        text = ra.read_text(path, limit=4001)
        got = text.splitlines()
        assert got and got[-1] == lines[-1].strip(), name
        assert all(re.fullmatch(r"line \d{5} x{40}", g) for g in got), (name, got[0])  # no half line at the start
        assert len(got) < 100
        head = ra.read_text(path, limit=4000, tail=False)
        assert head.startswith("line 00000"), name


def test_read_text_of_a_small_file_is_the_whole_file(tmp_path):
    path = put(tmp_path / "a.txt", utf16("abc\ndef\n"))
    assert ra.read_text(path) == "abc\ndef\n"


def test_read_text_never_raises(tmp_path):
    assert ra.read_text(tmp_path / "missing.txt") is None
    assert ra.read_text(tmp_path) is None  # a folder
    assert ra.read_text(put(tmp_path / "empty.txt", b"")) == ""


def test_read_text_skips_pipes_that_would_block_the_scan(tmp_path):
    if not hasattr(os, "mkfifo"):
        pytest.skip("no named pipes on this platform")
    pipe = tmp_path / "connection_trace.txt"
    os.mkfifo(pipe)
    assert ra.read_text(pipe) is None


def test_file_named_ignores_case(tmp_path):
    put(tmp_path / "connections_incoming.TXT", "x")
    assert ra.file_named(tmp_path, "Connections_incoming.txt").name.lower() == "connections_incoming.txt"
    assert ra.file_named(tmp_path, "other.txt") is None
    assert ra.file_named(tmp_path / "nowhere", "a.txt") is None


def test_newest_orders_by_modification_time(tmp_path):
    for name, days in (("ad.trace", 3), ("ad_svc.trace", 1), ("ad.1.trace", 9), ("other.txt", 0)):
        age(put(tmp_path / name, "x"), days)
    assert [p.name for p in ra.newest(tmp_path, "ad*.trace", 2)] == ["ad_svc.trace", "ad.trace"]
    assert ra.newest(tmp_path / "nowhere", "*.trace", 3) == []


# --------------------------------------------------------------------------- key=value, INI and TOML
def test_keyvalue_masks_secrets():
    text = "# comment\n; other\nad.anynet.id=123\nad.anynet.pwd_hash=abc123\nad.anynet.pwd_salt=\nnoequals\n=x\n"
    got = ra.parse_keyvalue(text)
    assert got == {"ad.anynet.id": "123", "ad.anynet.pwd_hash": "set", "ad.anynet.pwd_salt": ""}


def test_ini_lowercases_names_and_masks_secrets():
    got = ra.parse_ini(NETSUPPORT_INI)
    assert got["http"]["gatewayaddress"] == f"{IP}:443" and got["http"]["gsk"] == "set" and got["client"]["securitykey"] == "set"
    assert got["client"]["silent"] == "1" and got["_info"]["filename"].endswith("client32.ini")
    assert NETSUPPORT_GSK not in repr(got) and NETSUPPORT_KEY not in repr(got)


def test_toml_reads_tables_skips_arrays_and_masks_secrets():
    got = ra.parse_toml(RUSTDESK_MAIN)
    assert got[""] == {"id": "742913850", "password": "set", "salt": "set", "key_pair": "set", "key_confirmed": "true"}
    assert got["keys_confirmed"] == {"rd.example.net": "true"}
    second = ra.parse_toml(RUSTDESK_SECOND)
    assert second[""]["rendezvous_server"] == "rd.example.net:21116" and second[""]["nat_type"] == "1"
    assert second["options"]["relay-server"] == "rd.example.net" and second["options"]["key"] == "set"
    assert second["options"]["verification-method"] == "use-both-passwords"
    for secret in (RUSTDESK_PASSWORD, RUSTDESK_SALT, RUSTDESK_KEY_PAIR, RUSTDESK_SERVER_KEY):
        assert secret not in repr(got) + repr(second)


def test_toml_edge_cases():
    got = ra.parse_toml("""# a comment
"quoted-name" = "double \\"quoted\\" value"
bare = 42   # trailing comment
inline = { 'a' = 1, 'b' = [2, 3] }
list = [
  'one',   # a comment
  'two',
]
empty = ''
unterminated = [1, 2
""")
    assert got[""]["quoted-name"].startswith("double ") and got[""]["bare"] == "42" and got[""]["inline"] == "{table}"
    assert got[""]["list"] == "[array]" and got[""]["empty"] == ""
    assert ra.parse_toml("") == {"": {}} and ra.parse_toml("[a]\n[b]\nx=1") == {"": {}, "a": {}, "b": {"x": "1"}}


# =========================================================================== AnyDesk parsers
def test_anydesk_connections():
    got = ra.parse_anydesk_connections(ANYDESK_CONNECTIONS)
    assert [(s.when, s.remote_id, s.name, s.unattended, s.rejected) for s in got] == [
        (dt.datetime(2026, 10, 12, 9, 41), "123456789", "", False, False),
        (dt.datetime(2026, 10, 13, 22, 15), "987654321", "", True, False),
        (dt.datetime(2026, 10, 14, 3, 7), "987654321", "helpdesk@ad", True, False),
        (dt.datetime(2026, 10, 15, 18, 30), "111222333", "", False, True)]  # the outgoing session is not listed
    assert got[0].via == "accepted by a person at the PC" and got[1].via == "accepted with the unattended-access password"
    assert got[2].via == "accepted with a stored session token" and got[0].source == "connection_trace.txt"


def test_anydesk_connections_parse_robustly():
    text = ("\n   \nIncoming\tt\t\n"
            "Incoming\t2026-10-12, 09:41:33\tUser\t123456789\n"  # seconds, no alias
            "incoming    2026-10-12, 10:00    Something Else    5555    me\n"  # a way of accepting nobody documented
            "Incoming    not a time    User    1    1\n"  # no time: still a session, at an unknown time
            "Incoming    2026-10-12, 11:00\n"  # nothing but the time
            "Closed    2026-10-12, 12:00    User    9    9\n"
            "garbage that is not a log line at all\n")
    got = ra.parse_anydesk_connections(text)
    assert [(s.when, s.remote_id, s.name, s.via) for s in got] == [
        (dt.datetime(2026, 10, 12, 9, 41, 33), "123456789", "", "accepted by a person at the PC"),
        (dt.datetime(2026, 10, 12, 10, 0), "5555", "me", "Something Else"),
        (None, "1", "", "accepted by a person at the PC"),
        (dt.datetime(2026, 10, 12, 11, 0), "", "", "")]
    assert ra.parse_anydesk_connections("") == []
    assert ra.parse_anydesk_connections("Outgoing  2026-10-12, 09:41  User  1  1") == []


def test_anydesk_connections_are_capped():
    text = "".join(f"Incoming    2026-10-12, 09:41    User    {i}    {i}\n" for i in range(ra.MAX_EVENTS + 50))
    assert len(ra.parse_anydesk_connections(text)) == ra.MAX_EVENTS


def test_anydesk_trace_requests_and_addresses():
    requests, addresses = ra.parse_anydesk_trace(ANYDESK_TRACE, "ad_svc.trace")
    assert [(r.when, r.remote_id, r.name, r.source) for r in requests] == [
        (dt.datetime(2026, 10, 13, 22, 15, 1), "987654321", "Mallory", "ad_svc.trace"),
        (dt.datetime(2026, 10, 14, 3, 6, 50), "987654321", "helpdesk@ad", "ad_svc.trace")]
    assert [(a.when, a.ip, a.port) for a in addresses] == [
        (dt.datetime(2026, 10, 13, 22, 15, 1), BAD_IP, 50443),
        (dt.datetime(2026, 10, 14, 3, 6, 49), "2001:db8:85a3::8a2e:370:7334", 51234)]  # "from nowhere" is not an address


def test_anydesk_trace_odd_lines():
    text = ("info 2026-10-13 22:15:01 x Incoming session request: Just A Name.\n"
            "info nothing Incoming session request: \n"
            f"info 2026-10-13 22:15:02 x Logged in from {IP}\n"  # an address without a port
            "no timestamp Logged in from 203.0.113.9:1234 on relay 1\n")
    requests, addresses = ra.parse_anydesk_trace(text)
    assert [(r.name, r.remote_id) for r in requests] == [("Just A Name", ""), ("", "")]
    assert [(a.ip, a.port, a.when is None) for a in addresses] == [(IP, None, False), ("203.0.113.9", 1234, True)]
    assert ra.parse_anydesk_trace("") == ([], [])


def test_anydesk_settings_say_whether_a_password_is_set_and_never_its_value():
    conf = ra.parse_keyvalue(ANYDESK_SYSTEM_CONF)
    got = ra.anydesk_settings(conf)
    assert got == {"password_set": True, "id": "123456780", "acl_enabled": False}
    assert ANYDESK_HASH not in repr(conf) and ANYDESK_SALT not in repr(conf) and ANYDESK_TOKEN_SALT not in repr(conf)
    profile = ra.parse_keyvalue("ad.security.permission_profiles._unattended_access.pwd=abcdef\nad.security.acl_enabled=true\n")
    assert ra.anydesk_settings(profile) == {"password_set": True, "id": "", "acl_enabled": True}
    for text in ("", "ad.anynet.pwd_hash=\nad.anynet.pwd_salt=abc\n",
                 "ad.anynet.id=abc\nad.security.permission_profiles._default.pwd_x=1"):
        assert ra.anydesk_settings(ra.parse_keyvalue(text))["password_set"] is False
    assert ra.anydesk_settings({})["acl_enabled"] is None


# =========================================================================== TeamViewer parsers
def test_teamviewer_incoming():
    got = ra.parse_teamviewer_incoming(TEAMVIEWER_INCOMING)
    assert [(s.remote_id, s.name, s.when, s.ended, s.kind) for s in got] == [
        ("1357924680", "Carol-Laptop", dt.datetime(2026, 10, 12, 9, 41, 7), dt.datetime(2026, 10, 12, 10, 12, 44),
         "RemoteControl"),
        ("1357924680", "Carol-Laptop", dt.datetime(2026, 10, 15, 21, 5), dt.datetime(2026, 10, 15, 21, 30, 10),
         "FileTransfer"),
        ("2468013579", "Support Desk (M\u00fcller)", dt.datetime(2026, 10, 16, 8, 0, 12), dt.datetime(2026, 10, 16, 8, 3, 55),
         "RemoteControl")]
    assert "{" not in repr(got)  # the session id is not kept


def test_teamviewer_incoming_odd_lines_and_formats():
    text = ("TeamViewer ID\tName\tStart\tEnd\tUser\tType\tId\n"  # a header
            "\n"
            "11111\tdotted\t12.10.2026 09:41:07\t\talice\n"  # dotted dates, no end, no type
            "22222\tiso\t2026-10-12 09:41:07\t2026-10-12 09:50:00\talice\tRemoteControl\n"
            "33333    spaced    12-10-2026 09:41:07    12-10-2026 09:42:07    alice    VPN\n"  # no tabs at all
            "only\ttwo\n")
    got = ra.parse_teamviewer_incoming(text)
    assert [(s.remote_id, s.name, s.ended, s.kind) for s in got] == [
        ("11111", "dotted", None, ""), ("22222", "iso", dt.datetime(2026, 10, 12, 9, 50), "RemoteControl"),
        ("33333", "spaced", dt.datetime(2026, 10, 12, 9, 42, 7), "VPN")]
    assert ra.parse_teamviewer_incoming("") == []


def test_teamviewer_settings():
    values = {"securitypasswordaes": b"\x01\x02\x03", "optionspasswordaes": b"\x04", "always_online": 1, "clientid": 1357924680,
              "owningmanageraccountname": "support@acme-it.example"}
    assert ra.teamviewer_settings(values) == {
        "password_set": True, "settings_password": True, "start_with_system": True, "id": "1357924680",
        "account": "support@acme-it.example"}
    blank = {"securitypasswordaes": b"", "always_online": "0", "clientid": "x", "owningmanageraccountname": " "}
    assert ra.teamviewer_settings(blank) == {
        "password_set": False, "settings_password": False, "start_with_system": False, "id": "", "account": ""}
    assert ra.teamviewer_settings({})["password_set"] is False


def test_teamviewer_linux_conf_and_macos_plist_are_read_without_the_password():
    conf = ra.parse_teamviewer_conf(
        "[int32] Always_Online = 1\n[int32] ClientID = 1357924680\n"
        f"[bin] SecurityPasswordAES = \"{TEAMVIEWER_AES}\"\n[strng] OptionsPasswordAES = \"\"\n"
        "[strng] Other = \"x\"\n# comment\n")
    assert conf == {"always_online": "1", "clientid": "1357924680", "securitypasswordaes": "set", "optionspasswordaes": "",
                    "other": "x"}
    got = ra.teamviewer_settings(conf)
    assert got["password_set"] is True and got["start_with_system"] is True and got["id"] == "1357924680"
    plist = ra.teamviewer_plist(plistlib.dumps({"ClientID": 1357924680, "Always_Online": 1,
                                               "SecurityPasswordAES": TEAMVIEWER_AES.encode()}))
    assert plist == {"clientid": 1357924680, "always_online": 1, "securitypasswordaes": "set"}
    assert ra.teamviewer_settings(plist)["password_set"] is True
    assert ra.teamviewer_plist(b"not a plist") == {} and ra.teamviewer_plist(plistlib.dumps([1, 2])) == {}
    assert TEAMVIEWER_AES not in repr(conf) + repr(plist)


# =========================================================================== ScreenConnect parser
def test_screenconnect_access_client_on_the_vendor_cloud():
    got = ra.parse_screenconnect(SC_ACCESS_IMAGE)
    assert got == {"type": "access", "host": "instance-ab12cd-relay.screenconnect.com", "port": 443, "name": "Reception PC",
                   "properties": ["ACME Ltd", "Laptop"]}
    assert SC_KEY not in repr(got) and SC_SESSION not in repr(got)


def test_screenconnect_support_client_with_a_dynamic_dns_relay():
    got = ra.parse_screenconnect(SC_SUPPORT_IMAGE)
    assert got["type"] == "support" and got["host"] == "helpdesk.fixmypc.duckdns.org" and got["port"] == 8041
    assert got["name"] == "" and got["properties"] == []


def test_screenconnect_parameters_in_a_config_file_and_with_noise_in_the_key():
    xml = ('<?xml version="1.0"?><configuration><setting name="Launch"><value>'
           f"?e=Access&amp;y=Guest&amp;h=relay.acme.example&amp;p=8041&amp;s={SC_SESSION}&amp;k=AAA+e=BBB%3D%3D&amp;t=PC1"
           "</value></setting></configuration>")
    got = ra.parse_screenconnect(xml)
    assert (got["type"], got["host"], got["port"], got["name"]) == ("access", "relay.acme.example", 8041, "PC1")
    no_question_mark = ra.parse_screenconnect("e=Access&y=Guest&h=relay.acme.example&p=8041")
    assert no_question_mark["host"] == "relay.acme.example"


@pytest.mark.parametrize("text", ["", "no parameters here", "?e=Access&y=Guest&p=443", "?h=&p=443&e=Access", "?a=1&b=2&c=3",
                                  "?h=relay.example.com", "?p=443&x=1"])
def test_screenconnect_without_a_relay_is_not_a_client(text):
    assert ra.parse_screenconnect(text) is None


def test_screenconnect_needs_only_a_relay_and_a_type_or_port():
    assert ra.parse_screenconnect("?e=A&h=x")["host"] == "x" and ra.parse_screenconnect("?h=x&p=1")["port"] == 1


def test_screenconnect_port_may_be_missing():
    assert ra.parse_screenconnect("?e=Support&y=Guest&h=relay.example.com&t=x")["port"] is None
    assert ra.parse_screenconnect("?e=Support&y=Guest&h=relay.example.com&p=abc")["port"] is None


@pytest.mark.parametrize("command,program", [
    ('"C:\\Program Files (x86)\\ScreenConnect Client (abc)\\ScreenConnect.ClientService.exe" "?e=Access"',
     "C:\\Program Files (x86)\\ScreenConnect Client (abc)\\ScreenConnect.ClientService.exe"),
    ("C:\\Program Files\\Mesh Agent\\MeshAgent.exe run", "C:\\Program Files\\Mesh Agent\\MeshAgent.exe"),
    ("C:\\tools\\svc.exe --flag", "C:\\tools\\svc.exe"), ("/usr/bin/svc --x", "/usr/bin/svc"), ('"C:\\broken', "C:\\broken"),
    ("", ""),
])
def test_image_path(command, program):
    assert ra.image_path(command) == program


# =========================================================================== RustDesk, NetSupport, MeshAgent parsers
def test_rustdesk_settings():
    first, second = ra.parse_toml(RUSTDESK_MAIN), ra.parse_toml(RUSTDESK_SECOND)
    got = ra.rustdesk_settings({**second[""], **first[""]}, second["options"])
    assert got["password_set"] is True and got["password_stored"] is True and got["id"] == "742913850" and got["key_set"] is True
    assert got["verification_method"] == "use-both-passwords" and got["approve_mode"] == "password"
    assert got["servers"] == [("rendezvous server", "rd.example.net", None), ("relay server", "rd.example.net", None),
                              ("API server", "rd.example.net", None)]  # the top-level server is the same host: listed once


def test_rustdesk_one_time_password_only_is_not_unattended():
    got = ra.rustdesk_settings({"password": "set"}, {"verification-method": "use-temporary-password"})
    assert got["password_set"] is False and got["password_stored"] is True


def test_rustdesk_password_is_no_way_in_when_every_session_needs_a_click():
    got = ra.rustdesk_settings({"password": "set"}, {"approve-mode": "click"})
    assert got["password_set"] is False and got["password_stored"] is True
    assert got["password_ignored"] == "every session has to be accepted with a click (approve mode)"
    for mode in ("password", "password-click", ""):
        assert ra.rustdesk_settings({"password": "set"}, {"approve-mode": mode})["password_set"] is True


def test_rustdesk_default_servers_and_a_bare_install():
    got = ra.rustdesk_settings({"rendezvous_server": "rs-ny.rustdesk.com:21116"}, {})
    assert got["servers"] == [("rendezvous server", "rs-ny.rustdesk.com", 21116)] and got["password_set"] is False
    assert got["id"] == "" and got["key_set"] is False


def test_rustdesk_log_times_follow_the_offset():
    got = ra.parse_rustdesk_log(RUSTDESK_LOG, "rustdesk_rCURRENT.log")
    assert len(got) == 1 and (got[0].ip, got[0].port, got[0].source) == (BAD_IP, 50443, "rustdesk_rCURRENT.log")
    utc = dt.datetime(2026, 10, 14, 3, 6, 49, tzinfo=dt.timezone.utc)
    assert got[0].when == utc.astimezone().replace(tzinfo=None)
    plus = ra.parse_rustdesk_log("[2026-10-14 03:06:49.5 +08:30] INFO x Connection opened from 203.0.113.9:1.\n")
    assert plus[0].when == dt.datetime(2026, 10, 13, 18, 36, 49, tzinfo=dt.timezone.utc).astimezone().replace(tzinfo=None)
    local = ra.parse_rustdesk_log("[2026-10-14 03:06:49] INFO x Connection opened from 203.0.113.9:1.\n")
    assert local[0].when == dt.datetime(2026, 10, 14, 3, 6, 49)  # no offset: the time is taken as it is
    assert ra.parse_rustdesk_log("Connection opened from nowhere\n[2026-10-14 03:06:49] Connection opened from junk.\n") == []


@pytest.mark.parametrize("name,host,port,vendor", [
    ("rustdesk-host=rd.example.net,key=Abc123=.exe", "rd.example.net", None, False),
    ("rustdesk-host=45.9.148.10:21116,key=Abc.exe", "45.9.148.10", 21116, False),
    ("RustDesk-Host=rs-ny.rustdesk.com.exe", "rs-ny.rustdesk.com", None, True),
    ("rustdesk-host=me.duckdns.org.msi", "me.duckdns.org", None, False),
])
def test_rustdesk_server_named_in_the_file_name(name, host, port, vendor):
    got = ra.rustdesk_name_host(name)
    assert (got.host, got.port, got.vendor) == (host, port, vendor)
    assert "key" not in repr(got).lower().replace("rendezvous", "")


@pytest.mark.parametrize("name", ["rustdesk-1.2.3-x86_64.exe", "rustdesk.exe", "rustdesk-host=,key=a.exe"])
def test_rustdesk_file_names_without_a_server(name):
    assert ra.rustdesk_name_host(name) is None


def test_netsupport_settings_for_a_planted_client():
    got = ra.netsupport_settings(ra.parse_ini(NETSUPPORT_INI))
    assert got["servers"] == [(IP, 443), ("updatecheck.duckdns.org", 8443)] and got["gateway_key_set"] is True
    assert got["hidden"] == ["silent mode (no notice when someone connects)", "no icon near the clock",
                             "the user cannot disconnect"]


def test_netsupport_settings_for_a_plain_client():
    got = ra.netsupport_settings(ra.parse_ini(NETSUPPORT_LEGIT_INI))
    assert got == {"servers": [], "hidden": [], "gateway_key_set": False}
    assert ra.netsupport_settings({})["servers"] == []
    odd = ra.netsupport_settings(ra.parse_ini("[HTTP]\nGatewayAddress=gw.example.com\nPort=abc\n"))
    assert odd["servers"] == [("gw.example.com", None)]


def test_meshagent_settings():
    got = ra.parse_meshagent(MESH_MSH)
    assert got == {"name": "Reception PCs", "servers": [("mesh.acme-it.example", 443)], "group_set": True}
    assert MESH_ID not in repr(got) and MESH_SERVER_ID not in repr(got)
    several = ra.parse_meshagent(
        f"MeshServer=wss://a.example:8443/agent.ashx, wss://{IP}/agent.ashx; ws://b.example/agent.ashx\n")
    assert several["servers"] == [("a.example", 8443), (IP, 443), ("b.example", None)] and several["group_set"] is False
    assert ra.parse_meshagent("") == {"name": "", "servers": [], "group_set": False}


# =========================================================================== collectors: AnyDesk
def plant_anydesk(pc):
    """AnyDesk as a Windows PC has it: the service folder, alice's profile (UTF-16 log) and a copy of one session."""
    folder = pc.pd / "AnyDesk"
    put(folder / "connection_trace.txt", ANYDESK_CONNECTIONS)
    put(folder / "ad_svc.trace", ANYDESK_TRACE)
    put(folder / "system.conf", ANYDESK_SYSTEM_CONF)
    mine = pc.user("alice").appdata / "AnyDesk"
    put(mine / "connection_trace.txt",
        utf16("Incoming    2026-10-12, 09:41    User    123456789    123456789\n"  # the same session
              "Incoming    2026-10-16, 11:20    User    424242424    424242424\n"))
    put(mine / "ad.trace", codecs.BOM_UTF8 + "info 2026-10-16 11:19:50 x Incoming session request: Eve (424242424).\n".encode())
    put(mine / "user.conf", "ad.roster.items=1\n")
    (pc.pf / "AnyDesk").mkdir()
    return folder, mine


def test_anydesk_is_merged_across_the_service_folder_and_every_profile(pc):
    folder, mine = plant_anydesk(pc)
    [rep] = ra.collect_anydesk(pc.env)
    assert rep.tool == "anydesk" and rep.name == "AnyDesk" and rep.location == str(folder)
    assert str(folder) in rep.found_at and str(mine) in rep.found_at
    assert str(pc.pf / "AnyDesk") not in rep.found_at  # the folder is there, the program is not
    got = sorted((s.when, s.remote_id, s.rejected) for s in rep.sessions)
    assert got == [(dt.datetime(2026, 10, 12, 9, 41), "123456789", False),
                   (dt.datetime(2026, 10, 13, 22, 15), "987654321", False),
                   (dt.datetime(2026, 10, 14, 3, 7), "987654321", False),
                   (dt.datetime(2026, 10, 15, 18, 30), "111222333", True),
                   (dt.datetime(2026, 10, 16, 11, 20), "424242424", False)]  # the session in both folders counts once
    assert rep.rejected == 1
    assert [Path(p).name for p in rep.logs] == ["connection_trace.txt", "ad_svc.trace", "connection_trace.txt", "ad.trace"]
    assert [a.ip for a in rep.addresses] == [BAD_IP, "2001:db8:85a3::8a2e:370:7334"]
    assert rep.unattended == [f"a password for unattended access is set (in {folder / 'system.conf'})"]
    assert rep.facts == {"unattended_password": "set", "this_id": "123456780", "access_list": "not enabled"}


def test_anydesk_requests_stand_in_when_there_is_no_connection_log(pc):
    folder = pc.pd / "AnyDesk"
    put(folder / "ad_svc.trace", ANYDESK_TRACE)
    [rep] = ra.collect_anydesk(pc.env)
    assert [(s.remote_id, s.name) for s in rep.sessions] == [("987654321", "Mallory"), ("987654321", "helpdesk@ad")]
    assert rep.unattended == [] and rep.facts["unattended_password"] == "not set" and "this_id" not in rep.facts


def test_anydesk_with_only_rejected_sessions_falls_back_to_the_traces(pc):
    folder = pc.pd / "AnyDesk"
    put(folder / "connection_trace.txt", "Incoming    2026-10-15, 18:30    Rejected    111222333    111222333\n")
    put(folder / "ad_svc.trace", ANYDESK_TRACE)
    [rep] = ra.collect_anydesk(pc.env)
    assert rep.rejected == 1 and sum(1 for s in rep.sessions if not s.rejected) == 2


def test_anydesk_acl_and_unreadable_files(pc, monkeypatch):
    folder = pc.pd / "AnyDesk"
    put(folder / "service.conf", "ad.security.acl_enabled=true\n")
    put(folder / "system.conf", "ad.anynet.id=123456780\n")
    real = ra.read_text

    def refuse(path, *args, **kw):
        return None if Path(path).name == "connection_trace.txt" else real(path, *args, **kw)

    monkeypatch.setattr(ra, "read_text", refuse)
    put(folder / "connection_trace.txt", ANYDESK_CONNECTIONS)
    [rep] = ra.collect_anydesk(pc.env)
    assert rep.sessions == [] and rep.logs == [] and rep.facts["access_list"].startswith("enabled")
    assert rep.facts["unattended_password"] == "not set"


def test_anydesk_is_absent_without_any_trace_of_it(pc, unix):
    assert ra.collect_anydesk(pc.env) == [] and ra.collect_anydesk(unix.env) == []


def test_anydesk_installed_but_never_used(pc):
    exe = put(pc.pf86 / "AnyDesk" / "AnyDesk.exe", b"MZ")
    [rep] = ra.collect_anydesk(pc.env)
    assert rep.found_at == [str(exe)] and rep.sessions == [] and rep.unattended == []
    pc.service("AnyDesk", '"C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe" --service')
    [rep] = ra.collect_anydesk(pc.env)
    assert "service AnyDesk" in rep.found_at


def test_anydesk_on_linux_and_macos(unix, tmp_path):
    home = unix.user("alice").home
    put(home / ".anydesk" / "connection_trace.txt", ANYDESK_CONNECTIONS)
    put(home / ".anydesk" / "ad.trace", ANYDESK_TRACE)
    put(unix.root / "etc" / "anydesk" / "system.conf", ANYDESK_SYSTEM_CONF)
    put(unix.root / "var" / "log" / "anydesk.trace", "info 2026-10-16 11:19:50 x Logged in from 203.0.113.9:1 on relay 5.\n")
    [rep] = ra.collect_anydesk(unix.env)
    assert len(rep.sessions) == 4 and rep.rejected == 1 and rep.unattended and rep.location == str(home / ".anydesk")
    assert "203.0.113.9" in [a.ip for a in rep.addresses] and str(unix.root / "var" / "log" / "anydesk.trace") in rep.logs
    mac = Unix(tmp_path / "mac", "darwin")
    put(mac.user("alice").home / ".anydesk" / "connection_trace.txt", ANYDESK_CONNECTIONS)
    (mac.root / "Applications" / "AnyDesk.app").mkdir(parents=True)
    [rep] = ra.collect_anydesk(mac.env)
    assert len(rep.sessions) == 4 and str(mac.root / "Applications" / "AnyDesk.app") in rep.found_at


# =========================================================================== collectors: TeamViewer
def plant_teamviewer(pc):
    put(pc.pf86 / "TeamViewer" / "Connections_incoming.txt", codecs.BOM_UTF8 + TEAMVIEWER_INCOMING.encode("utf-8"))
    pc.reg.add(r"SOFTWARE\WOW6432Node\TeamViewer", {"ClientID": 1357924680, "Always_Online": 1})
    pc.reg.add(r"SOFTWARE\WOW6432Node\TeamViewer\Version15", {"SecurityPasswordAES": TEAMVIEWER_AES.encode(),
                                                            "OptionsPasswordAES": TEAMVIEWER_OPTIONS_AES.encode(),
                                                            "OwningManagerAccountName": "support@acme-it.example"})
    pc.reg.add(r"SOFTWARE\TeamViewer", {})


def test_teamviewer_reads_the_log_and_the_registry(pc):
    plant_teamviewer(pc)
    put(pc.user("bob").appdata / "TeamViewer" / "Connections_incoming.txt", utf16(
        "5550001\tQuickSupport caller\t14-10-2026 10:00:00\t14-10-2026 10:30:00\tbob\tRemoteControl\t{x}\n"))  # a QS copy
    [rep] = ra.collect_teamviewer(pc.env)
    assert rep.tool == "teamviewer" and rep.name == "TeamViewer" and rep.location == str(pc.pf86 / "TeamViewer")
    assert len(rep.sessions) == 4 and {s.remote_id for s in rep.sessions} == {"1357924680", "2468013579", "5550001"}
    assert [Path(p).name for p in rep.logs] == ["Connections_incoming.txt"] * 2
    assert rep.unattended == [
        r"a permanent password is set (Options > Security > Personal password, in HKLM\SOFTWARE\WOW6432Node\TeamViewer)",
        "this PC is assigned to the TeamViewer account support@acme-it.example; depending on its Easy access setting the "
        "owner of that account can connect without a password"]
    assert rep.facts == {"permanent_password": "set", "settings_password": "set", "start_with_system": True,
                         "this_id": "1357924680", "assigned_to_account": "support@acme-it.example"}
    assert TEAMVIEWER_AES not in repr(rep) and "AESBLOB" not in repr(rep).replace(TEAMVIEWER_AES, "")


def test_teamviewer_without_a_password(pc):
    pc.reg.add(r"SOFTWARE\TeamViewer", {"ClientID": 1357924680, "Always_Online": 0})
    [rep] = ra.collect_teamviewer(pc.env)
    assert rep.unattended == []
    assert rep.facts == {"permanent_password": "not set", "start_with_system": False, "this_id": "1357924680"}


def test_teamviewer_is_absent_without_any_trace_of_it(pc, unix):
    assert ra.collect_teamviewer(pc.env) == [] and ra.collect_teamviewer(unix.env) == []


def test_teamviewer_on_linux(unix):
    put(unix.root / "opt" / "teamviewer" / "config" / "global.conf",
        f"[int32] Always_Online = 1\n[bin] SecurityPasswordAES = \"{TEAMVIEWER_AES}\"\n[int32] ClientID = 1357924680\n")
    put(unix.root / "var" / "log" / "teamviewer15" / "connections_incoming.txt", TEAMVIEWER_INCOMING)  # a lower-case file name
    [rep] = ra.collect_teamviewer(unix.env)
    assert len(rep.sessions) == 3 and rep.unattended and rep.facts["this_id"] == "1357924680"
    assert str(unix.root / "opt" / "teamviewer" / "config" / "global.conf") in rep.unattended[0]


def test_teamviewer_on_macos(tmp_path):
    mac = Unix(tmp_path, "darwin")
    plist = mac.root / "Library" / "Preferences" / "com.teamviewer.teamviewer.preferences.plist"
    put(plist, plistlib.dumps({"ClientID": 1357924680, "SecurityPasswordAES": TEAMVIEWER_AES.encode()}))
    put(mac.root / "Library" / "Logs" / "TeamViewer" / "Connections_incoming.txt", TEAMVIEWER_INCOMING)
    [rep] = ra.collect_teamviewer(mac.env)
    assert len(rep.sessions) == 3 and rep.unattended and str(plist) in rep.unattended[0]


# =========================================================================== collectors: ScreenConnect
def plant_screenconnect(pc):
    pc.service("ScreenConnect Client (a1b2c3d4e5f6a7b8)", SC_ACCESS_IMAGE)
    pc.service("ScreenConnect Client (0123456789abcdef)", SC_SUPPORT_IMAGE)
    (pc.pf86 / "ScreenConnect Client (a1b2c3d4e5f6a7b8)").mkdir()
    (pc.pf86 / "ScreenConnect Client (0123456789abcdef)").mkdir()


def test_screenconnect_instances_are_reported_one_by_one(pc):
    plant_screenconnect(pc)
    support, access = ra.collect_screenconnect(pc.env)  # sorted by instance id
    assert access.location == str(pc.pf86 / "ScreenConnect Client (a1b2c3d4e5f6a7b8)")
    assert access.facts["session_type"] == "Access (unattended)" and access.facts["instance_id"] == "a1b2c3d4e5f6a7b8"
    assert access.facts["relay"].startswith("instance-ab12cd-relay.screenconnect.com:443 (the vendor's cloud")
    assert access.facts["session_name"] == "Reception PC" and access.facts["properties"] == ["ACME Ltd", "Laptop"]
    assert len(access.unattended) == 1 and access.servers[0].vendor is True and access.servers[0].port == 443
    assert access.server_source == r"HKLM\SYSTEM\CurrentControlSet\Services\ScreenConnect Client (a1b2c3d4e5f6a7b8)"
    assert support.facts["session_type"] == "Support (attended)" and support.unattended == []
    assert support.servers[0].host == "helpdesk.fixmypc.duckdns.org" and support.servers[0].vendor is False
    assert SC_KEY not in repr([access, support]) and SC_SESSION not in repr([access, support])


def test_screenconnect_falls_back_to_the_config_file_and_to_the_service_key(pc):
    folder = pc.pf / "ScreenConnect Client (feedfacefeedface)"
    put(folder / "system.config",
        f"<value>?e=Access&amp;y=Guest&amp;h=relay.acme.example&amp;p=8041&amp;s={SC_SESSION}&amp;k={SC_KEY}</value>")
    pc.service("ScreenConnect Client (cafebabecafebabe)", '"C:\\Gone\\ScreenConnect.ClientService.exe"')  # no folder, no query
    [stray, via_config] = ra.collect_screenconnect(pc.env)
    assert via_config.location == str(folder) and via_config.servers[0].host == "relay.acme.example" and via_config.unattended
    assert via_config.server_source == str(folder / "system.config")
    assert stray.location.endswith("ScreenConnect Client (cafebabecafebabe)") and stray.servers == [] and stray.unattended == []
    assert SC_KEY not in repr([stray, via_config])


def test_screenconnect_only_exists_on_windows(unix):
    assert ra.collect_screenconnect(unix.env) == []


# =========================================================================== collectors: RustDesk
def plant_rustdesk(pc):
    config = pc.user("alice").appdata / "RustDesk" / "config"
    put(config / "RustDesk.toml", RUSTDESK_MAIN)
    put(config / "RustDesk2.toml", RUSTDESK_SECOND)
    put(pc.user("alice").appdata / "RustDesk" / "log" / "server" / "rustdesk_rCURRENT.log", RUSTDESK_LOG)
    return config


def test_rustdesk_reads_both_files_and_the_server_log(pc):
    config = plant_rustdesk(pc)
    [rep] = ra.collect_rustdesk(pc.env)
    assert rep.location == str(config) and rep.server_source == str(config / "RustDesk2.toml")
    assert [(s.role, s.host, s.vendor) for s in rep.servers] == [
        ("rendezvous server", "rd.example.net", False), ("relay server", "rd.example.net", False),
        ("API server", "rd.example.net", False)]
    assert rep.unattended and str(config / "RustDesk.toml") in rep.unattended[0]
    assert rep.facts == {"permanent_password": "set", "server_key": "set", "this_id": "742913850",
                         "verification_method": "use-both-passwords", "approve_mode": "password"}
    assert [s.ip for s in rep.sessions] == [BAD_IP] and len(rep.logs) == 1
    for secret in (RUSTDESK_PASSWORD, RUSTDESK_SALT, RUSTDESK_KEY_PAIR, RUSTDESK_SERVER_KEY):
        assert secret not in repr(rep)


def test_rustdesk_service_account_profile_is_read_too(pc):
    config = pc.service_home / "RustDesk" / "config"
    put(config / "RustDesk.toml", "password = 'abc'\nid = '1'\n")
    [rep] = ra.collect_rustdesk(pc.env)
    assert rep.location == str(config) and rep.unattended and rep.servers == []


def test_rustdesk_with_the_one_time_password_only(pc):
    config = pc.user("alice").appdata / "RustDesk" / "config"
    put(config / "RustDesk.toml", "password = 'abc'\n")
    put(config / "RustDesk2.toml", "[options]\nverification-method = 'use-temporary-password'\n")
    [rep] = ra.collect_rustdesk(pc.env)
    assert rep.unattended == [] and rep.facts["permanent_password"] == "set"
    assert rep.facts["permanent_password_note"] == "set, but the verification method allows only the one-time password"
    put(config / "RustDesk2.toml", "[options]\napprove-mode = 'click'\n")
    [rep] = ra.collect_rustdesk(pc.env)
    assert rep.unattended == [] and rep.facts["permanent_password_note"].endswith("(approve mode)")


def test_rustdesk_with_the_vendor_servers_has_no_self_hosted_server(pc):
    put(pc.user("bob").appdata / "RustDesk" / "config" / "RustDesk2.toml", "rendezvous_server = 'rs-ny.rustdesk.com:21116'\n")
    [rep] = ra.collect_rustdesk(pc.env)
    assert [(s.host, s.vendor) for s in rep.servers] == [("rs-ny.rustdesk.com", True)]
    assert rep.facts["permanent_password"] == "not set" and rep.facts["server_key"] == "not set"


def test_rustdesk_on_linux_macos_and_windows_without_a_trace(unix, tmp_path, pc):
    config = unix.user("alice").home / ".config" / "rustdesk"
    put(config / "RustDesk.toml", "password = 'abc'\n")
    put(unix.user("alice").home / ".local" / "share" / "logs" / "RustDesk" / "server" / "x.log",
        "[2026-10-14 03:06:49 +00:00] INFO x Connection opened from 203.0.113.9:1.\n")
    [rep] = ra.collect_rustdesk(unix.env)
    assert rep.location == str(config) and rep.unattended and len(rep.sessions) == 1
    mac = Unix(tmp_path / "mac", "darwin")
    put(mac.user("alice").home / "Library" / "Preferences" / "com.carriez.RustDesk" / "RustDesk2.toml",
        "[options]\nrelay-server = 'rd.example.net'\n")
    [rep] = ra.collect_rustdesk(mac.env)
    assert [s.host for s in rep.servers] == ["rd.example.net"]
    assert ra.collect_rustdesk(pc.env) == []


# =========================================================================== collectors: Atera, Splashtop
def test_atera_names_the_account_that_manages_the_pc(pc):
    pc.reg.add(r"SOFTWARE\ATERA Networks\AlphaAgent", {"IntegratorLogin": "tech@acme-it.example", "AccountId": "0013z00002AbCdE",
                                                      "CompanyId": 17})
    [rep] = ra.collect_atera(pc.env)
    assert rep.facts == {"managed_by": "tech@acme-it.example", "account_id": "0013z00002AbCdE", "company_id": "17"}
    assert "(tech@acme-it.example)" in rep.unattended[0] and rep.location == r"HKLM\SOFTWARE\ATERA Networks\AlphaAgent"


def test_atera_by_folder_or_service_without_registry_values(pc):
    (pc.pf / "ATERA Networks" / "AteraAgent").mkdir(parents=True)
    pc.service("AteraAgent", '"C:\\Program Files\\ATERA Networks\\AteraAgent\\AteraAgent.exe"')
    [rep] = ra.collect_atera(pc.env)
    assert rep.facts == {} and "service AteraAgent" in rep.found_at and rep.found_at[0] == str(pc.pf / "ATERA Networks")
    assert rep.unattended == ["the Atera agent is installed: the account that deployed it can reach this PC at any time, "
                              "without anyone clicking Accept"]


def test_splashtop_streamer(pc):
    pc.reg.add(r"SOFTWARE\WOW6432Node\Splashtop Inc.\Splashtop Remote Server", {"Version": "3.6.2.0"})
    [rep] = ra.collect_splashtop(pc.env)
    assert rep.name == "Splashtop Streamer" and rep.unattended and rep.location.endswith("Splashtop Remote Server")
    only_subkeys = Pc(pc.root.parent / "other")
    only_subkeys.reg.add(r"SOFTWARE\Splashtop Inc.\Splashtop Remote Server\Child")
    assert ra.collect_splashtop(only_subkeys.env)[0].found_at == [r"HKLM\SOFTWARE\Splashtop Inc.\Splashtop Remote Server"]


def test_atera_and_splashtop_are_absent_on_other_systems_and_when_missing(pc, unix):
    for env in (pc.env, unix.env):
        assert ra.collect_atera(env) == [] and ra.collect_splashtop(env) == []


# =========================================================================== collectors: NetSupport, MeshAgent
def test_netsupport_is_found_planted_and_installed(pc):
    planted = pc.user("bob").appdata / "WinUpd"
    put(planted / "client32.ini", utf16(NETSUPPORT_INI))
    put(planted / "client32.exe", b"MZ")
    put(pc.pf86 / "NetSupport" / "NetSupport Manager" / "client32.ini", NETSUPPORT_LEGIT_INI)
    put(pc.pd / "Cache" / "client32.INI", "[Client]\n")  # a name in other case
    reports = {Path(r.location).parent.name: r for r in ra.collect_netsupport(pc.env)}
    assert sorted(reports) == ["Cache", "NetSupport Manager", "WinUpd"]
    bad = reports["WinUpd"]
    assert bad.location == str(planted / "client32.ini") and bad.facts["client32_exe_present"] is True
    assert [(s.role, s.host, s.port, s.always_high) for s in bad.servers] == [
        ("gateway", IP, 443, True), ("gateway", "updatecheck.duckdns.org", 8443, True)]
    assert bad.facts["gateway_key"] == "set" and len(bad.facts["hides_from_the_user"]) == 3
    assert "hides from the user" in bad.unattended[0]
    plain = reports["NetSupport Manager"]
    assert plain.servers == [] and plain.facts["client32_exe_present"] is False and plain.facts["gateway_key"] == "not set"
    assert "hides" not in plain.unattended[0]
    assert NETSUPPORT_GSK not in repr(list(reports.values())) and NETSUPPORT_KEY not in repr(list(reports.values()))


def test_netsupport_in_temp_and_moved_download_folders(pc, tmp_path):
    put(pc.env.temp_dirs[0] / "x" / "client32.ini", NETSUPPORT_LEGIT_INI)
    moved = tmp_path / "moved Downloads"
    put(moved / "pkg" / "client32.ini", NETSUPPORT_LEGIT_INI)
    pc.env.extra_roots = [moved]
    assert sorted(Path(r.location).parent.name for r in ra.collect_netsupport(pc.env)) == ["pkg", "x"]


def test_netsupport_is_not_searched_deeper_than_the_walk_allows(pc):
    put(pc.user("alice").appdata / "a" / "b" / "client32.ini", NETSUPPORT_LEGIT_INI)  # three levels down in AppData
    put(pc.pf / "a" / "b" / "client32.ini", NETSUPPORT_LEGIT_INI)  # two levels down in Program Files
    assert [Path(r.location).parent.parent.name for r in ra.collect_netsupport(pc.env)] == ["a"]
    assert ra.collect_netsupport(pc.env)[0].location.startswith(str(pc.pf))


def test_the_walk_is_cached_capped_and_never_follows_links(pc, monkeypatch):
    put(pc.pf / "tool" / "one.txt", "x")
    first = ra.walk_roots(pc.env)
    assert ra.walk_roots(pc.env) is first
    assert any(folder == pc.pf / "tool" and names == ["one.txt"] for folder, names in first)
    fresh = Pc(pc.root.parent / "second")
    for i in range(30):
        put(fresh.pf / f"d{i}" / "f.txt", "x")
    monkeypatch.setattr(ra, "MAX_WALK", 12)
    assert len(ra.walk_roots(fresh.env)) < 8
    link_target = pc.root.parent / "elsewhere"
    put(link_target / "client32.ini", NETSUPPORT_LEGIT_INI)
    third = Pc(pc.root.parent / "third")
    try:
        os.symlink(link_target, third.user("alice").appdata / "linked", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("this account cannot create symbolic links")
    assert ra.collect_netsupport(third.env) == []


def test_meshagent_is_found_by_folder_and_by_service(pc):
    folder = pc.pf / "Mesh Agent"
    put(folder / "MeshAgent.exe", b"MZ")
    put(folder / "MeshAgent.msh", utf16(MESH_MSH))
    other = pc.root / "Tools" / "agent"  # outside every searched root: only the service points at it
    put(other / "MeshAgent.exe", b"MZ")
    put(other / "custom.msh", "MeshServer=wss://45.9.148.10:443/agent.ashx\nMeshName=x\n")
    pc.service("Mesh Agent", f'"{other / "MeshAgent.exe"}" run')
    reports = {Path(r.location).parent.name: r for r in ra.collect_meshagent(pc.env)}
    assert sorted(reports) == ["Mesh Agent", "agent"]
    main = reports["Mesh Agent"]
    assert main.facts == {"group": "Reception PCs", "group_id": "set"} and main.location == str(folder / "MeshAgent.msh")
    assert [(s.role, s.host, s.port) for s in main.servers] == [("MeshCentral server", "mesh.acme-it.example", 443)]
    assert "mesh.acme-it.example" in main.unattended[0]
    assert reports["agent"].location == str(other / "custom.msh") and reports["agent"].servers[0].host == IP
    assert MESH_ID not in repr(list(reports.values())) and MESH_SERVER_ID not in repr(list(reports.values()))


def test_meshagent_needs_the_agent_next_to_the_msh_file_and_ignores_unreadable_ones(pc, monkeypatch):
    put(pc.pd / "Random" / "settings.msh", "MeshServer=wss://x.example/agent.ashx\n")  # no MeshAgent beside it
    assert ra.collect_meshagent(pc.env) == []
    put(pc.pd / "Random" / "MeshAgent.exe", b"MZ")
    monkeypatch.setattr(ra, "read_text", lambda *a, **k: None)
    assert ra.collect_meshagent(pc.env) == []


def test_meshagent_on_linux(unix):
    folder = unix.root / "usr" / "local" / "mesh_services" / "meshagent"
    put(folder / "meshagent", b"\x7fELF")
    put(folder / "meshagent.msh", MESH_MSH)
    [rep] = ra.collect_meshagent(unix.env)
    assert rep.location == str(folder / "meshagent.msh") and rep.servers[0].host == "mesh.acme-it.example"


# =========================================================================== portable copies
@pytest.mark.parametrize("name,tool", [
    ("AnyDesk.exe", "AnyDesk"), ("anydesk (1).exe", "AnyDesk"), ("AnyDesk.dmg", "AnyDesk"), ("TeamViewerQS.exe", "TeamViewer"),
    ("TeamViewerQS_en-idc3qdkyfx.exe", "TeamViewer"), ("TeamViewer_Setup.exe", "TeamViewer"), ("rustdesk-1.2.3.exe", "RustDesk"),
    ("rustdesk-host=rd.example.net,key=abc.exe", "RustDesk"), ("ScreenConnect.ClientSetup.exe", "ScreenConnect"),
    ("ConnectWiseControl.ClientSetup.msi", "ScreenConnect"), ("SplashtopSOS.exe", "Splashtop"),
    ("UltraViewer_setup.exe", "UltraViewer"), ("AA_v3.exe", "Ammyy Admin"), ("Ammyy_Admin.exe", "Ammyy Admin"),
    ("SupremoSetup.exe", "Supremo"), ("ToDesk_Setup.exe", "ToDesk"), ("HopToDesk.exe", "HopToDesk"), ("LogMeIn.msi", "LogMeIn"),
    ("MeshAgent-Windows.exe", "MeshAgent"), ("client32.exe", "NetSupport"),
])
def test_portable_program_names(name, tool):
    assert ra.portable_tool(name) == tool


@pytest.mark.parametrize("name", ["notes.txt", "anydesk.txt", "teamviewer.pdf", "my-anydesk.exe", "client32.dll", "setup.exe",
                                  "rustdesk", "chrome.exe", "supreme.exe", "ScreenConnect.zip"])
def test_other_file_names_are_not_portable_programs(name):
    assert ra.portable_tool(name) is None


def test_portable_copies_are_found_in_downloads_desktop_and_temp_of_every_profile(pc):
    plant = [pc.user("alice").home / "Downloads" / "AnyDesk.exe", pc.user("bob").home / "Desktop" / "TeamViewerQS.exe",
             pc.user("bob").local / "Temp" / "ScreenConnect.ClientSetup.exe", pc.env.temp_dirs[0] / "rustdesk.exe",
             pc.user("alice").home / "OneDrive" / "Desktop" / "SplashtopSOS.exe"]
    for path in plant:
        put(path, b"MZ" + b"\0" * 10)
    put(pc.user("alice").home / "Downloads" / "sub" / "AnyDesk.exe", b"MZ")  # only the top level is looked at
    put(pc.user("alice").home / "Downloads" / "readme.txt", "x")
    (pc.user("alice").home / "Downloads" / "TeamViewer.exe").mkdir()  # a folder with such a name
    got = ra.find_portable(pc.env)
    assert sorted(p.path for p in got) == sorted(plant)
    assert {p.path.name: p.tool for p in got}["ScreenConnect.ClientSetup.exe"] == "ScreenConnect"
    assert all(p.running is None and p.server is None for p in got)


def test_portable_copy_in_a_moved_folder_is_found_once(pc, tmp_path):
    moved = tmp_path / "D" / "Downloads"
    put(moved / "AnyDesk.exe", b"MZ")
    pc.env.extra_roots = [moved, moved, pc.user("alice").home / "Downloads"]
    assert [p.path for p in ra.find_portable(pc.env)] == [moved / "AnyDesk.exe"]


def test_portable_rustdesk_names_its_server_and_running_copies_are_marked(pc):
    path = put(pc.user("alice").home / "Downloads" / "rustdesk-host=rd.example.net,key=SECRETKEY123.exe", b"MZ")
    other = put(pc.user("alice").home / "Downloads" / "AnyDesk.exe", b"MZ")
    pc.env.processes = lambda: [("anydesk.exe", str(other)), ("explorer.exe", r"C:\Windows\explorer.exe"), ("idle", "")]
    got = {p.path.name: p for p in ra.find_portable(pc.env)}
    assert got[path.name].server.host == "rd.example.net" and got[path.name].running is False
    assert got["AnyDesk.exe"].running is True and got["AnyDesk.exe"].server is None


def test_portable_search_on_a_machine_with_unreadable_folders(pc, monkeypatch):
    put(pc.user("alice").home / "Downloads" / "AnyDesk.exe", b"MZ")
    real = os.scandir

    def deny(path):
        if "bob" in str(path):
            raise PermissionError(13, "denied")
        return real(path)

    monkeypatch.setattr(os, "scandir", deny)
    assert [p.path.name for p in ra.find_portable(pc.env)] == ["AnyDesk.exe"]


# =========================================================================== running programs
@pytest.mark.parametrize("tool,procs,near,expected", [
    ("anydesk", [("anydesk.exe", "")], None, True), ("anydesk", [("firefox.exe", "")], None, False),
    ("anydesk", None, None, None),
    ("teamviewer", [("teamviewer_service.exe", "")], None, True), ("teamviewer", [("teamviewerd", "")], None, True),
    ("meshagent", [("meshagent.exe", "")], None, True), ("rustdesk", [("rustdesk", "")], None, True),
    ("atera", [("ateraagent.exe", "")], None, True), ("splashtop", [("srservice.exe", "")], None, True),
    ("screenconnect", [("screenconnect.clientservice.exe", "")], None, True),
    ("netsupport", [("client32.exe", "")], None, False),  # a generic name needs the folder
])
def test_tool_running(tool, procs, near, expected):
    assert ra.tool_running(tool, procs, near) is expected


def test_netsupport_running_needs_the_folder_of_its_ini(tmp_path):
    here, elsewhere = tmp_path / "here", tmp_path / "elsewhere"
    assert ra.tool_running("netsupport", [("client32.exe", str(here / "client32.exe"))], here) is True
    assert ra.tool_running("netsupport", [("client32.exe", str(elsewhere / "client32.exe"))], here) is False


def test_the_process_list_is_read_once_and_a_failing_list_is_not_an_error(pc):
    calls = []

    def procs():
        calls.append(1)
        return [("anydesk.exe", "")]

    pc.env.processes = procs
    assert pc.env.running() == pc.env.running() == [("anydesk.exe", "")] and len(calls) == 1
    other = Pc(pc.root.parent / "other")
    other.env.processes = lambda: (_ for _ in ()).throw(RuntimeError("no access"))
    assert other.env.running() is None


def test_running_processes_of_this_machine_have_lower_case_names():
    procs = ra._running_processes()
    assert procs is None or (procs and all(name == name.lower() for name, _ in procs))


def test_collect_marks_running_tools(pc):
    plant_anydesk(pc)
    pc.env.processes = lambda: [("anydesk.exe", "")]
    reports, failed = ra.collect(pc.env)
    assert failed == [] and [(r.tool, r.running) for r in reports] == [("anydesk", True)]
    pc.env.cache.clear()
    pc.env.processes = lambda: [("firefox.exe", "")]
    assert ra.collect(pc.env)[0][0].running is False
    pc.env.cache.clear()
    pc.env.processes = ra._no_processes
    assert ra.collect(pc.env)[0][0].running is None


# =========================================================================== environment of a Windows PC
def test_windows_profiles_come_from_users_and_the_registry(tmp_path):
    drive = tmp_path / "C"
    for name in ("alice", "bob", "Public", "Default", "All Users"):
        (drive / "Users" / name).mkdir(parents=True)
    (drive / "Users" / "desktop.ini").write_text("x")
    elsewhere = tmp_path / "D" / "Profiles" / "carol"
    elsewhere.mkdir(parents=True)
    reg = FakeRegistry()
    reg.add(ra.PROFILE_LIST_KEY + r"\S-1-5-21-1-2-3-1001", {"ProfileImagePath": str(elsewhere)})
    reg.add(ra.PROFILE_LIST_KEY + r"\S-1-5-18", {"ProfileImagePath": r"%systemroot%\system32\config\systemprofile"})
    reg.add(ra.PROFILE_LIST_KEY + r"\S-1-5-21-1-2-3-1002", {"ProfileImagePath": str(tmp_path / "gone")})
    reg.add(ra.PROFILE_LIST_KEY + r"\S-1-5-21-1-2-3-1003", {"ProfileImagePath": "%TESTROOT%\\C\\Users\\bob"})
    environ = {"APPDATA": str(drive / "Users" / "alice" / "AppData" / "Roaming"), "TESTROOT": str(tmp_path)}
    profiles, skipped = ra.windows_profiles(environ, reg.read, reg.subkeys, drive / "Users" / "alice", str(drive))
    assert [p.name for p in profiles] == ["alice", "bob", "carol"] and skipped == []
    alice = profiles[0]
    assert alice.appdata == drive / "Users" / "alice" / "AppData" / "Roaming" and alice.local == alice.home / "AppData" / "Local"
    assert profiles[1].appdata == drive / "Users" / "bob" / "AppData" / "Roaming"


def test_unreadable_profiles_are_named(tmp_path, monkeypatch):
    drive = tmp_path / "C"
    for name in ("alice", "bob"):
        (drive / "Users" / name).mkdir(parents=True)
    real = ra._readable
    monkeypatch.setattr(ra, "_readable", lambda folder: False if folder.name == "bob" else real(folder))
    reg = FakeRegistry()
    profiles, skipped = ra.windows_profiles({}, reg.read, reg.subkeys, drive / "Users" / "alice", str(drive))
    assert [p.name for p in profiles] == ["alice", "bob"] and skipped == ["bob"]  # this user's own profile is never "unreadable"


def test_fill_windows_env(tmp_path):
    drive = tmp_path / "C"
    (drive / "Users" / "alice").mkdir(parents=True)
    reg = FakeRegistry()
    reg.add(ra.SERVICES_KEY + r"\AnyDesk", {"ImagePath": '"C:\\AnyDesk.exe" --service'})
    reg.add(ra.SERVICES_KEY + r"\Spooler", {"ImagePath": "spoolsv.exe"})
    reg.add(ra.SERVICES_KEY + r"\ScreenConnect Client (abc)", {})
    env = ra.Env(read_value=reg.read, read_values=reg.values, read_subkeys=reg.subkeys)
    environ = {"ProgramFiles": str(tmp_path / "PF"), "ProgramFiles(x86)": str(tmp_path / "PF86"),
               "ProgramW6432": str(tmp_path / "PF"), "ProgramData": str(tmp_path / "PD")}
    ra.fill_windows_env(env, environ, drive / "Users" / "alice", str(drive), tmp_path / "Win", tmp_path / "Temp")
    assert env.windows and [p.name for p in env.profiles] == ["alice"]
    assert env.program_dirs == [tmp_path / "PF", tmp_path / "PF86"] and env.program_data == tmp_path / "PD"
    assert env.public == drive / "Users" / "Public" and env.temp_dirs == [tmp_path / "Temp", tmp_path / "Win" / "Temp"]
    assert [p.parts[-4:] for p in env.service_profiles][0] == ("ServiceProfiles", "LocalService", "AppData", "Roaming")
    # only the services of remote-access tools are kept
    assert env.services == {"AnyDesk": '"C:\\AnyDesk.exe" --service', "ScreenConnect Client (abc)": ""}


def test_system_env_describes_this_machine():
    env = ra.system_env()
    assert env.os_name == ra.OS_NAME and env.profiles and env.temp_dirs
    assert env.windows == (os.name == "nt") and env.processes is ra._running_processes
    if env.windows:
        assert env.program_dirs and env.program_data is not None


# =========================================================================== findings: incoming connections
def many_sessions(n, days_ago, **kw):
    return [session(NOW - dt.timedelta(days=days_ago, minutes=i), remote_id=f"{100000000 + i}", **kw) for i in range(n)]


def test_recent_incoming_connections_are_medium():
    by_password = session("2026-10-14 03:07", "987654321", unattended=True, via="accepted with the unattended-access password")
    rep = report(sessions=[session("2026-10-12 09:41", "123456789"), by_password],
                 logs=[r"C:\ProgramData\AnyDesk\connection_trace.txt"], found_at=[r"C:\ProgramData\AnyDesk"], rejected=1)
    f = ra.incoming_finding(rep, NOW)
    assert (f.rule_id, f.severity, f.category, f.scanner) == ("AEG-RA-INCOMING", Severity.MEDIUM, Category.SUSPICIOUS,
                                                              "remoteaccess")
    assert f.title == "AnyDesk: 2 incoming connections in its own log, the latest on 2026-10-14"
    assert f.location == r"C:\ProgramData\AnyDesk\connection_trace.txt" and f.remediation is None
    assert f.mitre == ["T1219.002", "T1078"]
    assert "between 2026-10-12 09:41 and 2026-10-14 03:07" in f.description and "from 2 remote IDs" in f.description
    assert "1 of them was accepted with a stored password or token, so nobody at the PC had to click Accept" in f.description
    assert "1 further attempt was rejected" in f.description and "someone controlled this PC at those times" in f.description
    assert "older than" not in f.description
    ev = f.evidence
    assert (ev["sessions"], ev["first"], ev["last"], ev["sessions_in_window"], ev["window_days"]) == (
        2, "2026-10-12 09:41:00", "2026-10-14 03:07:00", 2, 90)
    assert ev["remote_ids"] == ["987654321", "123456789"] and ev["accepted_with_stored_password"] == 1 and ev["rejected"] == 1
    assert ev["recent_sessions"][0] == {"time": "2026-10-14 03:07:00", "remote_id": "987654321",
                                        "how": "accepted with the unattended-access password"}
    assert ev["tool"] == "AnyDesk" and ev["logs"] == [r"C:\ProgramData\AnyDesk\connection_trace.txt"] and "running" not in ev
    assert "To end a session now, use the Disconnect button in the AnyDesk window" in f.recommendation
    assert "it is a scam or a break-in" in f.recommendation and "Aegis never deletes them" in f.recommendation
    json.dumps(f.to_dict())


def test_incoming_connections_older_than_90_days_are_low():
    rep = report(sessions=many_sessions(3, 120), logs=["a.txt"])
    f = ra.incoming_finding(rep, NOW)
    assert f.severity == Severity.LOW and "All of them are older than 90 days" in f.description and f.mitre == ["T1219.002"]
    assert f.evidence["sessions_in_window"] == 0 and "accepted_with_stored_password" in f.evidence


def test_the_age_window_is_the_option_and_the_border_is_exact():
    rep = report(sessions=[session(NOW - dt.timedelta(days=90, seconds=1))], logs=["a.txt"])
    assert ra.incoming_finding(rep, NOW).severity == Severity.LOW
    rep = report(sessions=[session(NOW - dt.timedelta(days=89, hours=23))], logs=["a.txt"])
    assert ra.incoming_finding(rep, NOW).severity == Severity.MEDIUM
    rep = report(sessions=many_sessions(1, 20), logs=["a.txt"])
    assert ra.incoming_finding(rep, NOW, 7).severity == Severity.LOW
    assert ra.incoming_finding(rep, NOW, 30).severity == Severity.MEDIUM


def test_one_recent_session_among_old_ones_makes_it_medium():
    f = ra.incoming_finding(report(sessions=many_sessions(5, 400) + many_sessions(1, 3), logs=["a.txt"]), NOW)
    assert f.severity == Severity.MEDIUM and f.evidence["sessions_in_window"] == 1


def test_a_session_at_an_unknown_time_cannot_be_called_old():
    rep = report(sessions=[ra.Session(None, remote_id="1"), session(NOW - dt.timedelta(days=500))], logs=["a.txt"])
    f = ra.incoming_finding(rep, NOW)
    assert f.severity == Severity.MEDIUM and f.evidence["sessions_in_window"] == 1
    only = ra.incoming_finding(report(sessions=[ra.Session(None, remote_id="1")], logs=["a.txt"]), NOW)
    assert "at times the log does not give" in only.description and only.title == "AnyDesk: 1 incoming connection in its own log"
    assert "first" not in only.evidence and "last" not in only.evidence and only.severity == Severity.MEDIUM


def test_requests_from_a_trace_are_not_called_connections():
    requests, _ = ra.parse_anydesk_trace(ANYDESK_TRACE, "ad_svc.trace")
    f = ra.incoming_finding(report(sessions=requests, logs=["ad_svc.trace"]), NOW)
    assert f.title == "AnyDesk: 2 incoming session requests in its own log, the latest on 2026-10-14"
    assert "It lists 2 incoming session requests between" in f.description and "accepted with a stored" not in f.description
    assert f.evidence["recent_sessions"][0]["how"] == "requested (the trace does not say whether it was accepted)"
    mixed = ra.incoming_finding(report(sessions=requests + [session("2026-10-15 10:00")], logs=["a"]), NOW)
    assert mixed.title.startswith("AnyDesk: 3 incoming connections in its own log")


def test_a_single_session_reads_on_a_date():
    f = ra.incoming_finding(report(sessions=[session("2026-10-14 03:07")], logs=["a.txt"]), NOW)
    assert "It lists 1 incoming connection on 2026-10-14 03:07, from 1 remote ID." in f.description


def test_rejected_attempts_alone_are_not_connections():
    assert ra.incoming_finding(report(sessions=[session(rejected=True)], rejected=1), NOW) is None
    assert ra.incoming_finding(report(), NOW) is None


def test_incoming_evidence_is_capped_and_newest_first():
    sessions = many_sessions(25, 2)
    addresses = [ra.Session(NOW - dt.timedelta(hours=i), ip=f"203.0.113.{i}", source="ad.trace") for i in range(1, 26)]
    f = ra.incoming_finding(report(sessions=sessions, addresses=addresses, logs=["a.txt"]), NOW)
    ev = f.evidence
    assert ev["sessions"] == 25 and len(ev["remote_ids"]) == 20 and ev["remote_ids_total"] == 25
    assert len(ev["remote_addresses"]) == 20 and ev["remote_addresses_total"] == 25 and ev["remote_addresses"][0] == "203.0.113.1"
    assert len(ev["recent_sessions"]) == 10 and len(ev["recent_addresses"]) == 10
    times = [r["time"] for r in ev["recent_sessions"]]
    assert times == sorted(times, reverse=True) and ev["remote_ids"][0] == "100000000"
    assert ev["recent_addresses"][0] == {"time": _iso(NOW - dt.timedelta(hours=1)), "address": "203.0.113.1", "log": "ad.trace"}
    json.dumps(f.to_dict())


def _iso(when):
    return when.isoformat(sep=" ", timespec="seconds")


def test_incoming_names_are_cleaned_and_addresses_listed_with_ports():
    s = session(NOW, "1", name=ra.clean(f"Eve{RLO}fdp\x00"), ip="203.0.113.9", port=50443, kind="FileTransfer",
                ended=NOW + dt.timedelta(minutes=5))
    row = ra.incoming_finding(report(sessions=[s], logs=["a"]), NOW).evidence["recent_sessions"][0]
    assert row["name"] == "Eve<U+202E>fdp" and row["address"] == "203.0.113.9:50443" and row["type"] == "FileTransfer"
    assert row["ended"] == _iso(NOW + dt.timedelta(minutes=5))


def test_incoming_finding_reports_if_the_tool_is_running_and_this_pc_s_id():
    rep = report(sessions=[session("2026-10-14 03:07")], logs=["a.txt"], running=True, facts={"this_id": "123456780"})
    ev = ra.incoming_finding(rep, NOW).evidence
    assert ev["running"] is True and ev["this_id"] == "123456780"
    stopped = report(sessions=[session("2026-10-14 03:07")], logs=["a.txt"], running=False)
    assert ra.incoming_finding(stopped, NOW).evidence["running"] is False


def test_the_location_of_an_incoming_finding_is_the_first_log_or_the_installation():
    rep = report(sessions=[session("2026-10-14 03:07")], logs=[r"C:\one\log.txt", r"C:\two\log.txt"], location="loc")
    assert ra.incoming_finding(rep, NOW).location == r"C:\one\log.txt"
    assert ra.incoming_finding(report(sessions=[session("2026-10-14 03:07")], location="loc"), NOW).location == "loc"


# =========================================================================== findings: unattended access
def test_every_tool_has_instructions_and_a_collector_name():
    tools = set(ra.HOW)
    assert tools == {"anydesk", "teamviewer", "screenconnect", "rustdesk", "atera", "splashtop", "netsupport", "meshagent"}
    assert tools == set(ra.PROCESS_STEMS) and len(ra.COLLECTORS) == len(ra.COLLECTOR_NAMES) == len(tools)
    for tool, steps in ra.HOW.items():
        assert len(steps) == 3 and all(steps), tool


def test_unattended_access_is_medium_and_explains_itself():
    rep = report(unattended=["a password for unattended access is set (in system.conf)"], facts={"this_id": "123456780",
                 "unattended_password": "set", "access_list": "enabled: only the listed IDs may connect"},
                 found_at=["a"], running=False)
    f = ra.unattended_finding(rep)
    assert (f.rule_id, f.severity, f.category, f.title) == ("AEG-RA-UNATTENDED", Severity.MEDIUM, Category.SUSPICIOUS,
                                                            "AnyDesk is set up for unattended access")
    assert f.mitre == ["T1219.002", "T1133"] and f.remediation is None and f.location == r"C:\ProgramData\AnyDesk"
    assert "can be reached without anyone clicking Accept" in f.description and "This PC's ID is 123456780." in f.description
    assert "An access list limits who may connect" in f.description and "never the password" in f.description
    assert f.evidence["reasons"] == rep.unattended and f.evidence["unattended_password"] == "set"
    assert f.evidence["running"] is False
    assert "Settings > Security" in f.recommendation and "it is a scam" in f.recommendation
    assert "uninstall AnyDesk" in f.recommendation
    json.dumps(f.to_dict())


def test_no_unattended_finding_without_a_reason():
    assert ra.unattended_finding(report()) is None


def test_unattended_finding_lists_the_servers():
    rep = report(tool="screenconnect", name="ScreenConnect (ConnectWise Control)", unattended=["an Access client"],
                 servers=[ra.Server("relay", "instance-1.screenconnect.com", 443, vendor=True), ra.Server("relay", "x.example")])
    assert ra.unattended_finding(rep).evidence["servers"] == [
        {"role": "relay", "host": "instance-1.screenconnect.com", "port": 443, "operator": "the program vendor's cloud"},
        {"role": "relay", "host": "x.example"}]


# =========================================================================== findings: relay servers
def relay_report(host, tool="rustdesk", name="RustDesk", port=None, **kw):
    return report(tool=tool, name=name, servers=[ra.Server("relay server", host, port, **kw)],
                  server_source=r"C:\cfg\RustDesk2.toml")


def test_a_self_hosted_server_is_medium():
    f = ra.relay_finding(relay_report("rd.example.net"))
    assert (f.rule_id, f.severity, f.category) == ("AEG-RA-RELAY", Severity.MEDIUM, Category.SUSPICIOUS)
    assert f.title == "RustDesk is set to connect through a server you may not control: rd.example.net"
    assert f.location == r"C:\cfg\RustDesk2.toml" and f.mitre == ["T1219.002", "T1133"] and f.remediation is None
    assert "relay server rd.example.net" in f.description and "run by whoever owns that name" in f.description
    assert "company, a school or an IT provider" in f.description and "Ask whoever manages this PC" in f.recommendation
    assert f.evidence["servers"] == [{"role": "relay server", "host": "rd.example.net", "severity": "medium",
                                      "reasons": ["a server run by whoever owns that name, not by the program's vendor"]}]
    assert f.evidence["threat_feed"] is False and f.evidence["configuration"] == r"C:\cfg\RustDesk2.toml"


@pytest.mark.parametrize("host,why", [(IP, "bare IP address"), ("me.duckdns.org", "dynamic-DNS"),
                                      ("files.hopto.org", "dynamic-DNS")])
def test_a_raw_ip_or_dynamic_dns_relay_is_high(host, why):
    f = ra.relay_finding(relay_report(host, port=21117))
    assert f.severity == Severity.HIGH and why in f.description and f"{host}:21117" in f.title
    assert "Treat this PC as compromised unless you can name who runs" in f.recommendation
    assert "Aegis never deletes" in f.recommendation
    assert "stranger" in f.description and f.evidence["servers"][0]["port"] == 21117


def test_a_relay_on_the_threat_feed_is_high():
    feed = lambda host: host == "rd.example.net"  # noqa: E731
    f = ra.relay_finding(relay_report("rd.example.net"), feed)
    assert f.severity == Severity.HIGH and f.evidence["threat_feed"] is True
    assert "listed as malicious on the threat feed" in f.description
    assert ra.relay_finding(relay_report("rd.example.net"), lambda host: False).severity == Severity.MEDIUM


def test_a_private_network_relay_is_medium():
    f = ra.relay_finding(relay_report("192.168.1.20"))
    assert f.severity == Severity.MEDIUM and "private network address" in f.description


def test_the_vendors_own_cloud_is_not_a_relay_finding():
    assert ra.relay_finding(relay_report("instance-1.screenconnect.com", vendor=True)) is None
    assert ra.relay_finding(report()) is None


def test_a_netsupport_gateway_is_always_high_and_says_so():
    gateways = [ra.Server("gateway", "gw.example.com", 443, always_high=True),
                ra.Server("gateway", "backup.example.com", None, always_high=True)]
    rep = report(tool="netsupport", name="NetSupport Manager client", servers=gateways, server_source=r"C:\x\client32.ini")
    f = ra.relay_finding(rep)
    assert f.severity == Severity.HIGH
    assert f.title == "NetSupport Manager client phones home to a gateway: gw.example.com:443 (+1 more)"
    assert "NetSupport RAT campaigns configure exactly this" in f.description and "NetSupport gateway" in f.description
    assert [s["host"] for s in f.evidence["servers"]] == ["gw.example.com", "backup.example.com"]
    assert not any(r.startswith("a server run by") for s in f.evidence["servers"] for r in s["reasons"])
    assert "remove the folder that holds client32.ini" in f.recommendation


def test_the_worst_server_sets_the_severity_and_the_vendor_is_skipped():
    rep = report(tool="rustdesk", name="RustDesk", servers=[ra.Server("rendezvous server", "rs-ny.rustdesk.com", vendor=True),
                                                            ra.Server("relay server", "rd.example.net"),
                                                            ra.Server("API server", IP)])
    f = ra.relay_finding(rep)
    assert f.severity == Severity.HIGH and f.title.endswith(f"{IP} (+1 more)")  # the worst server is the one named
    assert [(s["host"], s["severity"]) for s in f.evidence["servers"]] == [(IP, "high"), ("rd.example.net", "medium")]
    assert "bare IP address" in f.description


def test_one_host_in_several_roles_is_one_server_in_the_title():
    rep = report(tool="rustdesk", name="RustDesk", servers=[ra.Server("rendezvous server", "rd.example.net"),
                                                            ra.Server("relay server", "rd.example.net"),
                                                            ra.Server("API server", "rd.example.net")])
    f = ra.relay_finding(rep)
    assert f.title.endswith("rd.example.net") and len(f.evidence["servers"]) == 3


# =========================================================================== findings: portable copies
DOWNLOADS = Path("Users") / "alice" / "Downloads"


def portable(name, tool="AnyDesk", days=5, **kw):
    return ra.Portable(DOWNLOADS / name, tool, (NOW - dt.timedelta(days=days)).timestamp(), 1234, **kw)


def test_a_recent_portable_copy_is_medium():
    [f] = ra.portable_findings([portable("AnyDesk.exe")], NOW)
    assert (f.rule_id, f.severity, f.category, f.scanner) == ("AEG-RA-PORTABLE", Severity.MEDIUM, Category.SUSPICIOUS,
                                                              "remoteaccess")
    assert f.title == "Portable remote-access program: AnyDesk.exe" and f.location == str(DOWNLOADS / "AnyDesk.exe")
    assert f.mitre == ["T1219.002"] and f.remediation is None
    assert f"is a AnyDesk program in {DOWNLOADS}, last changed 2026-10-11" in f.description
    assert "tech-support scam sessions start" in f.description
    assert "delete the file (Aegis does not delete it for you)" in f.recommendation and "it is a scam" in f.recommendation
    assert (f.evidence["size"], f.evidence["tool"], f.evidence["file"], f.evidence["folder"]) == (
        1234, "AnyDesk", "AnyDesk.exe", str(DOWNLOADS))
    assert f.evidence["modified"].startswith("2026-10-11") and "running" not in f.evidence
    assert "server_in_file_name" not in f.evidence


def test_an_old_portable_copy_is_low_unless_it_is_running():
    [old] = ra.portable_findings([portable("AnyDesk.exe", days=200)], NOW)
    assert old.severity == Severity.LOW and "running now" not in old.description
    [running] = ra.portable_findings([portable("AnyDesk.exe", days=200, running=True)], NOW)
    assert running.severity == Severity.MEDIUM and "and is running now" in running.description
    assert running.evidence["running"] is True
    [edge] = ra.portable_findings([portable("AnyDesk.exe", days=91)], NOW)
    assert edge.severity == Severity.LOW
    [window] = ra.portable_findings([portable("AnyDesk.exe", days=91)], NOW, days=120)
    assert window.severity == Severity.MEDIUM


def test_a_portable_rustdesk_that_names_a_server_gets_the_relay_finding_too():
    name = f"rustdesk-host=rd.example.net,key={RUSTDESK_SERVER_KEY}.exe"
    item = portable(name, "RustDesk", server=ra.Server("rendezvous server", "rd.example.net"))
    found = by_rule(ra.portable_findings([item], NOW))
    assert set(found) == {"AEG-RA-PORTABLE", "AEG-RA-RELAY"}
    copy, relay = found["AEG-RA-PORTABLE"], found["AEG-RA-RELAY"]
    assert copy.evidence["server_in_file_name"] == "rd.example.net" and copy.location == str(item.path)
    assert relay.severity == Severity.MEDIUM and relay.location == str(item.path) and relay.fingerprint != copy.fingerprint
    assert relay.evidence["tool"] == "RustDesk (portable copy rustdesk-host=rd.example.net,key=<omitted>.exe)"
    assert [s["host"] for s in relay.evidence["servers"]] == ["rd.example.net"]
    for shown in (copy.title, copy.description, copy.evidence["file"], relay.title, relay.description, relay.evidence["tool"]):
        assert RUSTDESK_SERVER_KEY not in shown  # the server key in the file name is left out (the path itself is a path)
    dns = portable("rustdesk-host=me.duckdns.org.exe", "RustDesk", server=ra.Server("rendezvous server", "me.duckdns.org", 21116))
    assert by_rule(ra.portable_findings([dns], NOW))["AEG-RA-RELAY"].severity == Severity.HIGH


def test_a_portable_rustdesk_for_the_vendor_servers_has_no_relay_finding():
    server = ra.Server("rendezvous server", "rs-ny.rustdesk.com", vendor=True)
    assert rules(ra.portable_findings([portable("rustdesk-host=rs-ny.rustdesk.com.exe", "RustDesk", server=server)], NOW)) == [
        "AEG-RA-PORTABLE"]


def test_a_deceptive_file_name_is_spelled_out():
    [f] = ra.portable_findings([portable(f"AnyDesk{RLO}fdp.exe")], NOW)
    assert RLO not in f.title and "<U+202E>" in f.title and "<U+202E>" in f.description


@pytest.mark.parametrize("name,shown", [
    ("rustdesk-host=rd.example.net,key=Abc123=.exe", "rustdesk-host=rd.example.net,key=<omitted>.exe"),
    ("rustdesk-host=rd.example.net,key=Abc.msi", "rustdesk-host=rd.example.net,key=<omitted>.msi"),
    ("RustDesk-Host=x.example,KEY=abc,other=1.exe", "RustDesk-Host=x.example,KEY=<omitted>,other=1.exe"),
    ("AnyDesk.exe", "AnyDesk.exe"), (f"a{RLO}b.exe", "a<U+202E>b.exe"),
])
def test_shown_name_leaves_out_the_server_key(name, shown):
    assert ra.shown_name(name) == shown


# =========================================================================== the check result
def test_the_check_skips_when_nothing_is_installed_and_names_where_it_looked(pc):
    c = ra.tools_check([], [], [], [], pc.env, 90, False)
    assert (c.check_id, c.title, c.status, c.category, c.scanner) == (
        "AEG-RA-CHK", "Remote access tools reviewed", CheckStatus.SKIP, Category.SUSPICIOUS, "remoteaccess")
    assert ("No remote-access tool was found (AnyDesk, TeamViewer, ScreenConnect, RustDesk, Splashtop, Atera, NetSupport and "
            "MeshAgent)") in c.detail
    assert str(pc.pd / "AnyDesk") in c.detail and str(pc.pf) in c.detail and "AppData of 2 user profiles" in c.detail
    assert "registry" in c.detail and "Downloads, Desktop and Temp" in c.detail


def test_the_skip_detail_for_linux_and_macos(unix):
    c = ra.tools_check([], [], [], [], unix.env, 90, False)
    assert c.status == CheckStatus.SKIP and "the home folders of 2 users" in c.detail
    assert str(unix.root / "etc" / "anydesk") in c.detail


def test_the_check_passes_when_tools_are_found_and_nothing_is_wrong(pc):
    reps = [report(), report(tool="teamviewer", name="TeamViewer")]
    c = ra.tools_check(reps, [], [], [], pc.env, 90, False)
    assert c.status == CheckStatus.PASS
    assert c.detail == ("2 remote-access tools found (AnyDesk, TeamViewer), none configured for unattended access, no "
                        "incoming sessions in the last 90 days.")
    one = ra.tools_check(reps[:1], [], [], [], pc.env, 30, False)
    assert one.detail.startswith("1 remote-access tool found (AnyDesk), none") and "last 30 days" in one.detail


def test_the_check_mentions_old_items_but_still_passes(pc):
    old = ra.incoming_finding(report(sessions=many_sessions(2, 300), logs=["a"]), NOW)
    c = ra.tools_check([report()], [], [old], [], pc.env, 90, False)
    assert c.status == CheckStatus.PASS and "1 older item is listed as low-priority findings." in c.detail


def test_the_check_fails_with_a_summary_per_tool(pc):
    anydesk = report(unattended=["x"], sessions=many_sessions(3, 2), logs=["a"])
    rustdesk = report(tool="rustdesk", name="RustDesk",
                      servers=[ra.Server("relay server", IP), ra.Server("relay server", "rd.example.net")])
    reps = [anydesk, rustdesk]
    findings = [f for rep in reps
                for f in (ra.incoming_finding(rep, NOW), ra.unattended_finding(rep), ra.relay_finding(rep)) if f]
    c = ra.tools_check(reps, [], findings, [], pc.env, 90, False)
    assert c.status == CheckStatus.FAIL
    assert c.detail == ("2 remote-access tools found (AnyDesk, RustDesk). AnyDesk: unattended access is set up, 3 incoming "
                        f"sessions in the last 90 days; RustDesk: connects through {IP}, rd.example.net.")


def test_the_check_counts_portable_copies_and_their_servers(pc):
    item = portable("rustdesk-host=me.duckdns.org.exe", "RustDesk", server=ra.Server("rendezvous server", "me.duckdns.org"))
    findings = ra.portable_findings([item, portable("AnyDesk.exe")], NOW)
    c = ra.tools_check([], [item], findings, [], pc.env, 90, False)
    assert c.status == CheckStatus.FAIL
    assert c.detail == ("No remote-access tool is installed. 2 portable remote-access programs in Downloads, Desktop or Temp; "
                        "a portable copy is set to connect through me.duckdns.org.")


def test_an_old_portable_copy_alone_does_not_fail_the_check(pc):
    item = portable("AnyDesk.exe", days=300)
    c = ra.tools_check([], [item], ra.portable_findings([item], NOW), [], pc.env, 90, False)
    assert c.status == CheckStatus.PASS
    assert c.detail == "No remote-access tool is installed. 1 older item is listed as low-priority findings."


def test_the_check_names_profiles_that_could_not_be_read_and_tools_that_failed(pc):
    pc.env.skipped = ["bob", "carol"]
    c = ra.tools_check([report()], [], [], ["TeamViewer (ValueError)"], pc.env, 90, False)
    assert c.status == CheckStatus.WARN
    assert "Not examined (no permission): bob, carol; run Aegis as an administrator to include those profiles." in c.detail
    assert "Could not be reviewed: TeamViewer (ValueError)." in c.detail
    pc.env.skipped = ["bob"]
    assert "include that profile." in ra.tools_check([report()], [], [], [], pc.env, 90, False).detail
    pc.env.skipped = [f"user{i}" for i in range(8)]
    assert "user4, ..." in ra.tools_check([report()], [], [], [], pc.env, 90, False).detail
    nothing = ra.tools_check([], [], [], ["AnyDesk (OSError)"], pc.env, 90, False)
    assert nothing.status == CheckStatus.WARN and "No remote-access tool was found" in nothing.detail


def test_the_check_asks_for_root_on_linux_and_macos(unix):
    unix.env.skipped = ["root"]
    c = ra.tools_check([report()], [], [], [], unix.env, 90, False)
    assert "Not examined (no permission): root; run Aegis as root (sudo) to include that profile." in c.detail


def test_the_check_says_when_the_threat_feed_is_missing(pc):
    c = ra.tools_check([report()], [], [], [], pc.env, 90, True)
    assert "no threat feed is loaded" in c.detail and c.status == CheckStatus.PASS


# =========================================================================== the scanner
@pytest.fixture
def machine(monkeypatch):
    """Make the scanner review a fake machine instead of this one."""
    def use(env):
        monkeypatch.setattr(ra, "system_env", lambda: env)
        return env

    return use


def plant_everything(pc):
    plant_anydesk(pc)
    plant_teamviewer(pc)
    plant_screenconnect(pc)
    plant_rustdesk(pc)
    pc.reg.add(r"SOFTWARE\ATERA Networks\AlphaAgent", {"IntegratorLogin": "tech@acme-it.example", "AccountId": "0013z00002AbCdE"})
    pc.reg.add(r"SOFTWARE\WOW6432Node\Splashtop Inc.\Splashtop Remote Server", {"Version": "3.6.2.0"})
    put(pc.user("bob").appdata / "WinUpd" / "client32.ini", NETSUPPORT_INI)
    put(pc.pf / "Mesh Agent" / "MeshAgent.msh", MESH_MSH)
    put(pc.user("bob").home / "Downloads" / "AnyDesk.exe", b"MZ")
    put(pc.user("alice").home / "Desktop" / "rustdesk-host=me.duckdns.org.exe", b"MZ")
    pc.env.services = ra.read_services(pc.reg.subkeys, pc.reg.read)


def test_the_scanner_skips_when_nothing_is_installed(ctx, pc, machine):
    machine(pc.env)
    findings, checks = split(ra.RemoteAccessScanner().run(ctx))
    assert findings == []
    assert [(c.check_id, c.status, c.scanner) for c in checks] == [("AEG-RA-CHK", CheckStatus.SKIP, "remoteaccess")]
    assert ctx.stats.get("remoteaccess_tools", 0) == 0


def test_the_scanner_reports_every_tool_with_its_findings(ctx, pc, machine):
    plant_everything(pc)
    machine(pc.env)
    findings, checks = split(ra.RemoteAccessScanner().run(ctx))
    got = sorted((f.rule_id, f.evidence["tool"], f.severity.name) for f in findings)
    sc, mesh = "ScreenConnect (ConnectWise Control)", "MeshAgent (MeshCentral)"
    assert got == sorted([
        ("AEG-RA-INCOMING", "AnyDesk", "MEDIUM"), ("AEG-RA-UNATTENDED", "AnyDesk", "MEDIUM"),
        ("AEG-RA-INCOMING", "TeamViewer", "MEDIUM"), ("AEG-RA-UNATTENDED", "TeamViewer", "MEDIUM"),
        ("AEG-RA-UNATTENDED", sc, "MEDIUM"), ("AEG-RA-RELAY", sc, "HIGH"),
        ("AEG-RA-INCOMING", "RustDesk", "MEDIUM"), ("AEG-RA-UNATTENDED", "RustDesk", "MEDIUM"),
        ("AEG-RA-RELAY", "RustDesk", "MEDIUM"),
        ("AEG-RA-UNATTENDED", "Atera agent", "MEDIUM"), ("AEG-RA-UNATTENDED", "Splashtop Streamer", "MEDIUM"),
        ("AEG-RA-UNATTENDED", "NetSupport Manager client", "MEDIUM"), ("AEG-RA-RELAY", "NetSupport Manager client", "HIGH"),
        ("AEG-RA-UNATTENDED", mesh, "MEDIUM"), ("AEG-RA-RELAY", mesh, "MEDIUM"),
        ("AEG-RA-PORTABLE", "AnyDesk", "MEDIUM"), ("AEG-RA-PORTABLE", "RustDesk", "MEDIUM"),
        ("AEG-RA-RELAY", "RustDesk (portable copy rustdesk-host=me.duckdns.org.exe)", "HIGH")])
    [check] = checks
    assert check.check_id == "AEG-RA-CHK" and check.status == CheckStatus.FAIL
    assert check.detail.startswith("8 remote-access tools found (AnyDesk, TeamViewer, ScreenConnect (ConnectWise Control), "
                                   "RustDesk, Splashtop Streamer, Atera agent, NetSupport Manager client, MeshAgent "
                                   "(MeshCentral)). AnyDesk: ")
    assert "no threat feed is loaded" in check.detail  # the test signatures hold no feed
    assert ctx.stats["remoteaccess_tools"] == 9 and ctx.stats["remoteaccess_sessions"] > 0
    assert all(f.scanner == "remoteaccess" and f.category == Category.SUSPICIOUS for f in findings)
    assert all(f.recommendation and f.mitre for f in findings)
    assert len({f.fingerprint for f in findings}) == len(findings)  # every finding has its own identity


def test_findings_are_stable_between_scans(ctx, pc, machine):
    plant_everything(pc)
    machine(pc.env)
    first = [f.fingerprint for f in split(ra.RemoteAccessScanner().run(ctx))[0]]
    pc.env.cache.clear()
    second = [f.fingerprint for f in split(ra.RemoteAccessScanner().run(ctx))[0]]
    assert first == second


def test_the_threat_feed_raises_a_relay_to_high(ctx, pc, machine):
    put(pc.user("alice").appdata / "RustDesk" / "config" / "RustDesk2.toml", "[options]\nrelay-server = 'rd.example.net'\n")
    machine(pc.env)
    [relay] = [f for f in split(ra.RemoteAccessScanner().run(ctx))[0] if f.rule_id == "AEG-RA-RELAY"]
    assert relay.severity == Severity.MEDIUM
    ctx.signatures.bad_domains.add("rd.example.net")
    pc.env.cache.clear()
    findings, checks = split(ra.RemoteAccessScanner().run(ctx))
    [relay] = [f for f in findings if f.rule_id == "AEG-RA-RELAY"]
    assert relay.severity == Severity.HIGH and relay.evidence["threat_feed"] is True and "no threat feed" not in checks[0].detail


def test_the_days_option_sets_the_window(ctx, pc, machine):
    put(pc.pd / "AnyDesk" / "connection_trace.txt",
        f"Incoming    {(dt.datetime.now() - dt.timedelta(days=30)):%Y-%m-%d, %H:%M}    User    1    1\n")
    machine(pc.env)
    [f] = split(ra.RemoteAccessScanner().run(ctx))[0]
    assert f.severity == Severity.MEDIUM
    ctx.options["remoteaccess_days"] = 7
    pc.env.cache.clear()
    [f] = split(ra.RemoteAccessScanner().run(ctx))[0]
    assert f.severity == Severity.LOW


def test_a_collector_that_crashes_is_reported_and_the_others_still_run(ctx, pc, machine, monkeypatch):
    plant_anydesk(pc)
    machine(pc.env)

    def broken(env):
        raise ValueError("bad data")

    monkeypatch.setattr(ra, "COLLECTORS", (ra.collect_anydesk, broken))
    monkeypatch.setattr(ra, "COLLECTOR_NAMES", ("AnyDesk", "TeamViewer"))
    findings, checks = split(ra.RemoteAccessScanner().run(ctx))
    assert "AEG-RA-INCOMING" in rules(findings)
    assert checks[0].status == CheckStatus.FAIL and "Could not be reviewed: TeamViewer (ValueError)." in checks[0].detail


def test_a_failing_portable_search_does_not_hide_the_tools(ctx, pc, machine, monkeypatch):
    plant_anydesk(pc)
    machine(pc.env)
    monkeypatch.setattr(ra, "find_portable", lambda env: (_ for _ in ()).throw(OSError("denied")))
    findings, checks = split(ra.RemoteAccessScanner().run(ctx))
    assert "AEG-RA-INCOMING" in rules(findings) and "portable programs (OSError)" in checks[0].detail


def test_a_crash_in_the_review_becomes_an_error_check(ctx, monkeypatch):
    monkeypatch.setattr(ra, "system_env", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    findings, checks = split(ra.RemoteAccessScanner().run(ctx))
    assert findings == [] and len(checks) == 1
    assert (checks[0].check_id, checks[0].status, checks[0].scanner) == ("AEG-RA-CHK", CheckStatus.ERROR, "remoteaccess")
    assert checks[0].detail == "RuntimeError: boom" and checks[0].category == Category.SUSPICIOUS


def test_the_scanner_stops_when_cancelled(ctx, pc, machine, monkeypatch):
    plant_everything(pc)
    machine(pc.env)
    ctx.cancel.set()
    assert list(ra.RemoteAccessScanner().run(ctx)) == []
    ctx.cancel.clear()
    seen = []
    real = ra.collect_anydesk

    def stop_after_anydesk(env):
        seen.append(1)
        ctx.cancel.set()
        return real(env)

    monkeypatch.setattr(ra, "COLLECTORS", (stop_after_anydesk,) + ra.COLLECTORS[1:])
    assert list(ra.RemoteAccessScanner().run(ctx)) == [] and seen == [1]


def test_the_scanner_reports_progress(ctx, pc, machine):
    machine(pc.env)
    messages = []
    ctx.progress = lambda scanner, message: messages.append((scanner, message))
    list(ra.RemoteAccessScanner().run(ctx))
    assert ("remoteaccess", "reviewing remote-access tools") in messages
    assert ("remoteaccess", "looking for portable remote-access programs") in messages


def test_running_tools_are_marked_in_the_evidence(ctx, pc, machine):
    plant_anydesk(pc)
    pc.env.processes = lambda: [("anydesk.exe", "")]
    machine(pc.env)
    findings, _ = split(ra.RemoteAccessScanner().run(ctx))
    assert findings and all(f.evidence["running"] is True for f in findings)


def test_the_scanner_never_modifies_the_files_it_reads(ctx, pc, machine):
    plant_everything(pc)
    machine(pc.env)

    def snapshot():
        return {str(p): (p.stat().st_size, p.stat().st_mtime_ns) for p in pc.root.rglob("*") if p.is_file()}

    before = snapshot()
    list(ra.RemoteAccessScanner().run(ctx))
    assert snapshot() == before


# =========================================================================== no secret reaches a report
def test_no_password_hash_salt_key_or_session_id_reaches_a_finding_or_a_check(ctx, pc, machine):
    plant_everything(pc)
    machine(pc.env)
    findings, checks = split(ra.RemoteAccessScanner().run(ctx))
    text = json.dumps([f.to_dict() for f in findings] + [c.to_dict() for c in checks])
    for secret in SECRETS:
        assert secret not in text, secret
    # what is shown instead: set / not set
    assert '"unattended_password": "set"' in text and '"permanent_password": "set"' in text and '"gateway_key": "set"' in text
    assert '"group_id": "set"' in text and '"server_key": "set"' in text


def test_no_secret_reaches_the_scan_report_or_the_log(ctx, pc, machine, caplog):
    plant_everything(pc)
    machine(pc.env)
    from aegis.core.engine import ScanEngine

    with caplog.at_level("DEBUG"):
        res = ScanEngine().scan("custom", ["remoteaccess"], paths=[pc.root])
    blob = res.to_json() + caplog.text
    for secret in SECRETS:
        assert secret not in blob, secret
    assert res.errors == [] and res.findings


def test_no_secret_survives_in_the_collected_reports(pc):
    plant_everything(pc)
    reports, failed = ra.collect(pc.env)
    assert failed == [] and len(reports) == 9
    blob = repr(reports) + repr(ra.find_portable(pc.env))
    for secret in SECRETS:
        assert secret not in blob, secret


def test_secrets_in_linux_and_macos_files_stay_out_of_the_reports(unix, tmp_path):
    put(unix.root / "opt" / "teamviewer" / "config" / "global.conf", f'[bin] SecurityPasswordAES = "{TEAMVIEWER_AES}"\n')
    put(unix.user("alice").home / ".anydesk" / "system.conf", ANYDESK_SYSTEM_CONF)
    put(unix.user("alice").home / ".config" / "rustdesk" / "RustDesk.toml", RUSTDESK_MAIN)
    put(unix.root / "usr" / "local" / "mesh_services" / "meshagent" / "meshagent.msh", MESH_MSH)
    reports, failed = ra.collect(unix.env)
    assert failed == [] and sorted(r.tool for r in reports) == ["anydesk", "meshagent", "rustdesk", "teamviewer"]
    findings = [f for r in reports for f in (ra.unattended_finding(r), ra.relay_finding(r), ra.incoming_finding(r, NOW)) if f]
    blob = repr(reports) + json.dumps([f.to_dict() for f in findings])
    for secret in SECRETS:
        assert secret not in blob, secret
    assert sum(1 for f in findings if f.rule_id == "AEG-RA-UNATTENDED") == 4


# =========================================================================== registration and wiring
def test_scanner_registered_in_the_full_profile_only():
    from aegis.core.engine import PROFILES

    load_all()
    cls = REGISTRY["remoteaccess"]
    assert cls.name == "remoteaccess" and cls.title == "Remote-access tool review" and cls.description
    assert set(cls.platforms) == {"windows", "linux", "darwin"} and cls().supported()
    assert PROFILES["full"].count("remoteaccess") == 1
    assert PROFILES["full"].index("remoteaccess") > PROFILES["full"].index("downloads")
    assert "remoteaccess" not in PROFILES["quick"] and "remoteaccess" not in PROFILES["audit"] and PROFILES["custom"] == []


def test_cli_help_names_the_scanner():
    from aegis.cli import build_parser

    scan_parser = build_parser()._subparsers._group_actions[0].choices["scan"]
    scan = next(a for a in scan_parser._actions if "--scanners" in a.option_strings)
    assert "remoteaccess" in scan.help


def test_engine_runs_the_scanner(pc, machine):
    from aegis.core.engine import ScanEngine

    plant_anydesk(pc)
    machine(pc.env)
    res = ScanEngine().scan("custom", ["remoteaccess"], paths=[pc.root])
    assert res.scanners == ["remoteaccess"] and res.errors == []
    assert sorted(f.rule_id for f in res.findings) == ["AEG-RA-INCOMING", "AEG-RA-UNATTENDED"]
    assert {c.check_id: c.status for c in res.checks if c.scanner == "remoteaccess"} == {"AEG-RA-CHK": CheckStatus.FAIL}
    json.loads(res.to_json())


def test_engine_skips_cleanly_when_nothing_is_installed(pc, machine):
    from aegis.core.engine import ScanEngine

    machine(pc.env)
    res = ScanEngine().scan("custom", ["remoteaccess"], paths=[pc.root])
    assert res.errors == [] and res.findings == []
    assert [(c.check_id, c.status) for c in res.checks] == [("AEG-RA-CHK", CheckStatus.SKIP)]


def test_attack_ids_used_are_current_and_well_formed():
    """The ATT&CK ids this module emits (checked against the v20 enterprise matrix: T1219 was split in v17 and T1219.002 is Remote
    Desktop Software; T1133 External Remote Services and T1078 Valid Accounts are current); retired ids are caught globally by
    tests/test_core.py::test_no_retired_attack_technique_ids."""
    used = set(re.findall(r"(?<![\w.])T1\d{3}(?:\.\d{3})?(?![.\d])", Path(ra.__file__).read_text(encoding="utf-8")))
    assert used == {"T1219.002", "T1133", "T1078"}, used


def test_the_source_is_plain_ascii():
    text = Path(ra.__file__).read_text(encoding="utf-8")
    assert text.isascii(), [(n, line) for n, line in enumerate(text.splitlines(), 1) if not line.isascii()]


# =========================================================================== real operating system
def test_scanner_runs_for_real_on_this_machine(ctx):
    """No monkeypatching: whatever this machine has installed, the review finishes without an ERROR and its output serialises."""
    out = list(ra.RemoteAccessScanner().run(ctx))
    findings, checks = split(out)
    assert [c.check_id for c in checks] == ["AEG-RA-CHK"] and checks[0].status != CheckStatus.ERROR, checks[0].detail
    assert all(f.rule_id.startswith("AEG-RA-") and f.recommendation for f in findings)
    json.dumps([x.to_dict() for x in out])
