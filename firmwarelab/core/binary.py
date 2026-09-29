"""Low level binary helpers: integer access, checksums, alignment, hex formatting."""

from __future__ import annotations

import struct
import zlib

_U8 = struct.Struct("<B")
_U16 = struct.Struct("<H")
_U32 = struct.Struct("<I")
_U64 = struct.Struct("<Q")


def u8(data, off: int = 0) -> int:
    return data[off]


def u16(data, off: int = 0) -> int:
    return _U16.unpack_from(data, off)[0]


def u24(data, off: int = 0) -> int:
    return data[off] | (data[off + 1] << 8) | (data[off + 2] << 16)


def u32(data, off: int = 0) -> int:
    return _U32.unpack_from(data, off)[0]


def u64(data, off: int = 0) -> int:
    return _U64.unpack_from(data, off)[0]


def p16(v: int) -> bytes:
    return _U16.pack(v & 0xFFFF)


def p24(v: int) -> bytes:
    return bytes((v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF))


def p32(v: int) -> bytes:
    return _U32.pack(v & 0xFFFFFFFF)


def p64(v: int) -> bytes:
    return _U64.pack(v & 0xFFFFFFFFFFFFFFFF)


def put16(buf: bytearray, off: int, v: int) -> None:
    _U16.pack_into(buf, off, v & 0xFFFF)


def put24(buf: bytearray, off: int, v: int) -> None:
    buf[off:off + 3] = p24(v)


def put32(buf: bytearray, off: int, v: int) -> None:
    _U32.pack_into(buf, off, v & 0xFFFFFFFF)


def put64(buf: bytearray, off: int, v: int) -> None:
    _U64.pack_into(buf, off, v & 0xFFFFFFFFFFFFFFFF)


def sum8(data) -> int:
    """Plain 8-bit sum of all bytes."""
    return sum(data) & 0xFF


def checksum8(data) -> int:
    """Value that makes the 8-bit sum of data plus the value equal to zero."""
    return (0x100 - (sum(data) & 0xFF)) & 0xFF


def sum16(data) -> int:
    """16-bit sum of little-endian words (length must be even)."""
    n = len(data) // 2
    if n == 0:
        return 0
    return sum(struct.unpack_from("<%dH" % n, data, 0)) & 0xFFFF


def checksum16(data) -> int:
    return (0x10000 - sum16(data)) & 0xFFFF


def sum32(data) -> int:
    n = len(data) // 4
    if n == 0:
        return 0
    return sum(struct.unpack_from("<%dI" % n, data, 0)) & 0xFFFFFFFF


def checksum32(data) -> int:
    return (0x100000000 - sum32(data)) & 0xFFFFFFFF


def crc32(data, value: int = 0) -> int:
    return zlib.crc32(data, value) & 0xFFFFFFFF


def align_up(value: int, alignment: int) -> int:
    if alignment <= 1:
        return value
    return (value + alignment - 1) // alignment * alignment


def align_down(value: int, alignment: int) -> int:
    if alignment <= 1:
        return value
    return value // alignment * alignment


def is_uniform(data, byte: int | None = None) -> bool:
    """True if every byte of data equals `byte` (or equals the first byte when byte is None)."""
    if not data:
        return True
    if byte is None:
        byte = data[0]
    return data.count(byte) == len(data) if isinstance(data, (bytes, bytearray)) else bytes(data).count(byte) == len(data)


def uniform_byte(data) -> int | None:
    """Return the fill byte if the buffer consists of a single repeated byte, else None."""
    if not data:
        return None
    b = data[0]
    return b if is_uniform(data, b) else None


def hexs(v: int, width: int = 0) -> str:
    """Format an integer in UEFITool-like style: 1A2Bh."""
    if width:
        return "%0*Xh" % (width, v)
    return "%Xh" % v


def size_str(v: int) -> str:
    """Hex and decimal size string, e.g. '1000h (4096)'."""
    return "%Xh (%d)" % (v, v)


def human_size(v: int) -> str:
    if v < 1024:
        return "%d B" % v
    f = float(v)
    for unit in ("KiB", "MiB", "GiB"):
        f /= 1024.0
        if f < 1024 or unit == "GiB":
            return ("%.2f" % f).rstrip("0").rstrip(".") + " " + unit
    return str(v)


def hexdump(data, base: int = 0, width: int = 16, limit: int | None = None) -> str:
    """Classic hex dump used by CLI output and reports."""
    lines = []
    data = bytes(data if limit is None else data[:limit])
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hx = " ".join("%02X" % b for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append("%08X  %-*s  %s" % (base + i, width * 3 - 1, hx, asc))
    return "\n".join(lines)


def printable_ascii(data, min_len: int = 1) -> str | None:
    """Decode a NUL-terminated ASCII string if it is printable."""
    end = bytes(data).find(b"\x00")
    raw = bytes(data if end < 0 else data[:end])
    if len(raw) < min_len:
        return None
    if all(32 <= b < 127 for b in raw):
        return raw.decode("ascii")
    return None


def ucs2_string(data, off: int = 0, max_chars: int | None = None) -> tuple[str, int]:
    """Read a NUL-terminated UCS-2 string. Returns (string, bytes consumed incl. terminator)."""
    chars = []
    pos = off
    end = len(data) - 1
    while pos < end:
        c = data[pos] | (data[pos + 1] << 8)
        pos += 2
        if c == 0:
            return "".join(chars), pos - off
        chars.append(chr(c) if c < 0xD800 or c > 0xDFFF else "�")
        if max_chars is not None and len(chars) >= max_chars:
            break
    return "".join(chars), pos - off


def encode_ucs2(s: str, terminate: bool = True) -> bytes:
    out = s.encode("utf-16-le")
    return out + b"\x00\x00" if terminate else out


def find_all(data, pattern: bytes, start: int = 0, end: int | None = None, step_align: int = 1):
    """Yield all offsets of pattern in data (optionally only aligned offsets)."""
    if end is None:
        end = len(data)
    pos = data.find(pattern, start, end)
    while pos >= 0:
        if step_align <= 1 or pos % step_align == 0:
            yield pos
        pos = data.find(pattern, pos + 1, end)
