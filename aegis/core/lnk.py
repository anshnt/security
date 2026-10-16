"""Pure-Python reader for Windows shortcut files (``.lnk``, the MS-SHLLINK format).

Extracts what a security scanner needs from a shortcut without any Windows API, so shortcuts can be analysed on any
OS: target path, command-line arguments, working directory, relative path, icon location, description and the
environment-variable target.

* The header (size 0x4C and the ``00021401-0000-0000-C000-000000000046`` LinkCLSID) decides whether the data is a shell
  link at all; anything else yields ``None``.
* ``LinkTargetIDList`` is skipped, ``LinkInfo`` supplies the target (``LocalBasePath`` + ``CommonPathSuffix``, the
  Unicode variants when present, or the network share name), the string data supplies description / relative path /
  working directory / arguments / icon, and the ``EnvironmentVariableDataBlock`` supplies the unexpanded
  ``%VAR%`` target some shortcuts use.
* Parsing is defensive: every offset is bounds-checked, and truncated or hostile input produces partial information
  (``LnkInfo.truncated`` is set) or ``None``, never an exception.

Not parsed: the item IDs inside the ``LinkTargetIDList`` (shortcuts to shell folders or AppX apps carry no
``LinkInfo``; their ``target_path`` stays empty).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional, Tuple

HEADER_SIZE = 0x4C
LINK_CLSID = bytes.fromhex("01140200" "0000" "0000" "c000000000000046")  # 00021401-0000-0000-C000-000000000046
MAX_LNK_BYTES = 256 * 1024  # real shortcuts are a few KB; nothing past this is read from disk

_HAS_ID_LIST = 0x01
_HAS_LINK_INFO = 0x02
_HAS_NAME = 0x04
_HAS_RELATIVE_PATH = 0x08
_HAS_WORKING_DIR = 0x10
_HAS_ARGUMENTS = 0x20
_HAS_ICON_LOCATION = 0x40
_IS_UNICODE = 0x80

_LI_LOCAL = 0x01  # VolumeIDAndLocalBasePath
_LI_NETWORK = 0x02  # CommonNetworkRelativeLinkAndPathSuffix

_ENV_BLOCK_SIGNATURE = 0xA0000001
_ENV_BLOCK_SIZE = 0x314

_STRING_FIELDS: Tuple[Tuple[int, str], ...] = (
    (_HAS_NAME, "name"),
    (_HAS_RELATIVE_PATH, "relative_path"),
    (_HAS_WORKING_DIR, "working_dir"),
    (_HAS_ARGUMENTS, "arguments"),
    (_HAS_ICON_LOCATION, "icon_location"),
)


@dataclass
class LnkInfo:
    target_path: str = ""  # LinkInfo path, or the %VAR% target of the environment block when that holds a variable
    arguments: str = ""
    working_dir: str = ""
    relative_path: str = ""
    icon_location: str = ""
    name: str = ""  # NAME_STRING: the description / comment of the shortcut
    env_target: str = ""  # EnvironmentVariableDataBlock target (Unicode preferred), unexpanded
    link_flags: int = 0
    show_command: int = 0
    truncated: bool = False  # parsing stopped early; the fields above hold what was readable

    @property
    def description(self) -> str:
        return self.name

    @property
    def command_line(self) -> str:
        return (self.target_path + (" " + self.arguments if self.arguments else "")).strip()


class _Truncated(Exception):
    """Raised internally when a structure runs past the end of the data."""


def _u16(data: bytes, pos: int) -> int:
    if pos < 0 or pos + 2 > len(data):
        raise _Truncated
    return struct.unpack_from("<H", data, pos)[0]


def _u32(data: bytes, pos: int) -> int:
    if pos < 0 or pos + 4 > len(data):
        raise _Truncated
    return struct.unpack_from("<I", data, pos)[0]


def _decode_ansi(raw: bytes) -> str:
    try:
        return raw.decode("cp1252")
    except UnicodeDecodeError:  # the five bytes cp1252 leaves undefined
        return raw.decode("latin-1")


def _clean(text: str) -> str:
    return text.replace("\x00", "")


def _ansi_at(block: bytes, off: int) -> str:
    """NUL-terminated ANSI string at ``off`` (empty when the offset is 0 or outside the block)."""
    if off <= 0 or off >= len(block):
        return ""
    end = block.find(b"\x00", off)
    return _decode_ansi(block[off:len(block) if end < 0 else end])


def _utf16_cstr(raw: bytes) -> str:
    """UTF-16LE text up to the first (2-byte aligned) NUL character, or to the end of ``raw``."""
    end = raw.find(b"\x00\x00")
    while end != -1 and end % 2:
        end = raw.find(b"\x00\x00", end + 1)
    return raw[:len(raw) & ~1 if end == -1 else end].decode("utf-16-le", "replace")


def _utf16_at(block: bytes, off: int) -> str:
    """NUL-terminated UTF-16LE string at ``off`` (empty when the offset is 0 or outside the block)."""
    if off <= 0 or off + 2 > len(block):
        return ""
    return _utf16_cstr(block[off:])


def _join_path(base: str, suffix: str, sep: str = "\\") -> str:
    if not suffix:
        return base
    if not base:
        return suffix
    if base.endswith(("\\", "/")) or suffix.startswith(("\\", "/")):
        return base + suffix
    return base + sep + suffix


def _network_name(block: bytes, off: int) -> str:
    """Share name of a CommonNetworkRelativeLink structure that starts at ``off`` inside the LinkInfo block."""
    try:
        name_off = _u32(block, off + 8)
        unicode_off = _u32(block, off + 20) if name_off > 0x14 else 0
    except _Truncated:
        return ""
    text = _utf16_at(block, off + unicode_off) if unicode_off else ""
    return text or _ansi_at(block, off + name_off)


def _link_info_target(block: bytes) -> str:
    """Target path held by a LinkInfo structure (``block`` starts at LinkInfoSize)."""
    if len(block) < 0x1C:
        return ""
    header_size = _u32(block, 4)
    flags = _u32(block, 8)
    if header_size < 0x1C:
        return ""
    local_off, net_off, suffix_off = _u32(block, 16), _u32(block, 20), _u32(block, 24)
    local_uni = suffix_uni = 0
    if header_size >= 0x24 and len(block) >= 0x24:
        local_uni, suffix_uni = _u32(block, 28), _u32(block, 32)
    suffix = (_utf16_at(block, suffix_uni) if suffix_uni else "") or _ansi_at(block, suffix_off)
    if flags & _LI_LOCAL:
        base = (_utf16_at(block, local_uni) if local_uni else "") or _ansi_at(block, local_off)
        return _clean(_join_path(base, suffix))
    if flags & _LI_NETWORK and net_off:
        return _clean(_join_path(_network_name(block, net_off), suffix))
    return ""


def _env_target(block: bytes) -> str:
    """Target of an EnvironmentVariableDataBlock body (260 ANSI bytes followed by 520 Unicode bytes)."""
    ansi = block[:260]
    text = _utf16_cstr(block[260:780])
    if not text:
        cut = ansi.find(b"\x00")
        text = _decode_ansi(ansi if cut < 0 else ansi[:cut])
    return _clean(text)


def _read_extra_blocks(info: LnkInfo, data: bytes, pos: int) -> None:
    while pos + 4 <= len(data):
        size = _u32(data, pos)
        if size < 4:  # TerminalBlock
            return
        if size < 8 or pos + size > len(data):
            info.truncated = True
            return
        if _u32(data, pos + 4) == _ENV_BLOCK_SIGNATURE and size == _ENV_BLOCK_SIZE and not info.env_target:
            info.env_target = _env_target(data[pos + 8:pos + size])
        pos += size


def _parse(data: bytes, info: LnkInfo) -> None:
    flags = info.link_flags
    pos = HEADER_SIZE
    if flags & _HAS_ID_LIST:
        pos += 2 + _u16(data, pos)
        if pos > len(data):
            raise _Truncated
    if flags & _HAS_LINK_INFO:
        size = _u32(data, pos)
        block = data[pos:pos + size]
        if size >= 0x1C:
            info.target_path = _link_info_target(block)
        if size < 0x1C or pos + size > len(data):
            raise _Truncated
        pos += size
    unicode_strings = bool(flags & _IS_UNICODE)
    for flag, attr in _STRING_FIELDS:
        if not flags & flag:
            continue
        count = _u16(data, pos)
        pos += 2
        nbytes = count * 2 if unicode_strings else count
        raw = data[pos:pos + nbytes]
        if unicode_strings:
            text = raw[:len(raw) & ~1].decode("utf-16-le", "replace")
        else:
            text = _decode_ansi(raw)
        setattr(info, attr, _clean(text))
        pos += nbytes
        if pos > len(data):
            raise _Truncated
    _read_extra_blocks(info, data, pos)


def parse_lnk(data: bytes) -> Optional[LnkInfo]:
    """Parse the bytes of a ``.lnk`` file. ``None`` when they are not a valid shell link (wrong header size or
    LinkCLSID, or fewer than 0x4C bytes); otherwise an :class:`LnkInfo`, possibly partial for damaged files. Never
    raises."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return None
    data = bytes(data)
    if len(data) < HEADER_SIZE or _u32(data, 0) != HEADER_SIZE or data[4:20] != LINK_CLSID:
        return None
    info = LnkInfo(link_flags=_u32(data, 20), show_command=_u32(data, 60))
    try:
        _parse(data, info)
    except (_Truncated, struct.error, ValueError, IndexError, OverflowError, MemoryError):
        info.truncated = True
    # a %VAR% target is only kept unexpanded in the environment block; LinkInfo then holds a resolved copy (or nothing)
    if info.env_target and ("%" in info.env_target or not info.target_path):
        info.target_path = info.env_target
    return info


def read_lnk(path: str, max_bytes: int = MAX_LNK_BYTES) -> Optional[LnkInfo]:
    """Parse the shortcut file at ``path`` (``None`` when unreadable or not a shortcut)."""
    try:
        with open(path, "rb") as fh:
            return parse_lnk(fh.read(max_bytes))
    except OSError:
        return None
