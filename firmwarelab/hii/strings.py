"""HII string packages (EFI_HII_STRING_PACKAGE_HDR + SIBT blocks)."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.binary import u16, u24, u32, ucs2_string

PACKAGE_TYPE_STRINGS = 0x04

SIBT_END = 0x00
SIBT_STRING_SCSU = 0x10
SIBT_STRING_SCSU_FONT = 0x11
SIBT_STRINGS_SCSU = 0x12
SIBT_STRINGS_SCSU_FONT = 0x13
SIBT_STRING_UCS2 = 0x14
SIBT_STRING_UCS2_FONT = 0x15
SIBT_STRINGS_UCS2 = 0x16
SIBT_STRINGS_UCS2_FONT = 0x17
SIBT_DUPLICATE = 0x20
SIBT_SKIP2 = 0x21
SIBT_SKIP1 = 0x22
SIBT_EXT1 = 0x30
SIBT_EXT2 = 0x31
SIBT_EXT4 = 0x32
SIBT_FONT = 0x40


@dataclass
class StringPackage:
    offset: int  # offset of the package in the scanned blob
    length: int
    language: str
    strings: dict[int, str] = field(default_factory=dict)

    def get(self, sid: int) -> str:
        return self.strings.get(sid, "")

    @property
    def max_id(self) -> int:
        return max(self.strings) if self.strings else 0


def _scsu(data, p):
    end = bytes(data[p:p + 4096]).find(b"\0")
    if end < 0:
        raise ValueError("unterminated SCSU string")
    return bytes(data[p:p + end]).decode("latin-1"), end + 1


def _ucs2(data, p):
    s, used = ucs2_string(data, p)
    if used == 0 or p + used > len(data) or data[p + used - 1] != 0 or data[p + used - 2] != 0:
        raise ValueError("unterminated UCS2 string")
    return s, used


def parse_string_package(data, off: int) -> StringPackage | None:
    """Parse and validate a string package at ``off``. Returns None if invalid."""
    n = len(data)
    if off + 0x2F > n or data[off + 3] != PACKAGE_TYPE_STRINGS:
        return None
    length = u24(data, off)
    hdr_size = u32(data, off + 4)
    info_off = u32(data, off + 8)
    if hdr_size != info_off or not (0x2F <= hdr_size <= 0x80) or length < hdr_size or off + length > n:
        return None
    lang_raw = bytes(data[off + 46:off + hdr_size])
    z = lang_raw.find(b"\0")
    if z <= 0 or z != len(lang_raw) - 1:
        return None
    try:
        lang = lang_raw[:z].decode("ascii")
    except UnicodeDecodeError:
        return None
    if not all(c.isalnum() or c in "-_;" for c in lang):
        return None
    pkg = StringPackage(off, length, lang)
    p = off + info_off
    end = off + length
    sid = 1
    try:
        while p < end:
            bt = data[p]
            p += 1
            if bt == SIBT_END:
                return pkg
            if bt == SIBT_STRING_SCSU:
                s, used = _scsu(data, p)
                pkg.strings[sid] = s
                sid += 1
                p += used
            elif bt == SIBT_STRING_SCSU_FONT:
                s, used = _scsu(data, p + 1)
                pkg.strings[sid] = s
                sid += 1
                p += 1 + used
            elif bt in (SIBT_STRINGS_SCSU, SIBT_STRINGS_SCSU_FONT):
                if bt == SIBT_STRINGS_SCSU_FONT:
                    p += 1
                count = u16(data, p)
                p += 2
                for _ in range(count):
                    s, used = _scsu(data, p)
                    pkg.strings[sid] = s
                    sid += 1
                    p += used
            elif bt == SIBT_STRING_UCS2:
                s, used = _ucs2(data, p)
                pkg.strings[sid] = s
                sid += 1
                p += used
            elif bt == SIBT_STRING_UCS2_FONT:
                s, used = _ucs2(data, p + 1)
                pkg.strings[sid] = s
                sid += 1
                p += 1 + used
            elif bt in (SIBT_STRINGS_UCS2, SIBT_STRINGS_UCS2_FONT):
                if bt == SIBT_STRINGS_UCS2_FONT:
                    p += 1
                count = u16(data, p)
                p += 2
                for _ in range(count):
                    s, used = _ucs2(data, p)
                    pkg.strings[sid] = s
                    sid += 1
                    p += used
            elif bt == SIBT_DUPLICATE:
                dup = u16(data, p)
                pkg.strings[sid] = pkg.strings.get(dup, "")
                sid += 1
                p += 2
            elif bt == SIBT_SKIP2:
                sid += u16(data, p)
                p += 2
            elif bt == SIBT_SKIP1:
                sid += data[p]
                p += 1
            elif bt == SIBT_EXT1:
                ln = data[p + 1]
                p += max(ln, 3) - 1
            elif bt == SIBT_EXT2:
                ln = u16(data, p + 1)
                p += max(ln, 4) - 1
            elif bt == SIBT_EXT4:
                ln = u32(data, p + 1)
                p += max(ln, 6) - 1
            elif bt == SIBT_FONT:
                ln = u16(data, p + 1)
                p += max(ln, 4) - 1
            else:
                return None
    except (IndexError, ValueError):
        return None
    return None


def find_string_packages(data) -> list[StringPackage]:
    raw = bytes(data)
    out = []
    # The language field of every string package starts 46 bytes into it; search on the
    # distinctive HdrSize == StringInfoOffset pair instead of every 0x04 byte.
    pos = 0
    n = len(raw)
    while True:
        i = raw.find(b"\x04", pos + 3)
        if i < 0 or i + 0x2C > n:
            break
        off = i - 3
        pos = i - 2
        if off < 0:
            continue
        hs = raw[off + 4:off + 8]
        if hs != raw[off + 8:off + 12] or hs[1:] != b"\0\0\0":
            continue
        pkg = parse_string_package(raw, off)
        if pkg is not None and pkg.strings:
            out.append(pkg)
            pos = off + pkg.length - 3
    return out
