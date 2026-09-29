"""Intel GbE (integrated LAN) region: MAC address and NVM checksum handling."""

from __future__ import annotations

import re
import struct

from ..core.node import Node

GBE_BANK_SIZE = 0x1000
CHECKSUM_WORD = 0x3F
CHECKSUM_TARGET = 0xBABA


def mac_of(data, bank: int = 0) -> str:
    b = bytes(data[bank * GBE_BANK_SIZE:bank * GBE_BANK_SIZE + 6])
    return ":".join("%02X" % x for x in b)


def bank_checksum_ok(data, bank: int = 0) -> bool:
    base = bank * GBE_BANK_SIZE
    if base + 0x80 > len(data):
        return False
    words = struct.unpack_from("<64H", data, base)
    return sum(words) & 0xFFFF == CHECKSUM_TARGET


def banks(data) -> int:
    return max(1, len(data) // GBE_BANK_SIZE) if len(data) >= GBE_BANK_SIZE else 1


def parse_mac(text: str) -> bytes:
    t = re.sub(r"[^0-9A-Fa-f]", "", text)
    if len(t) != 12:
        raise ValueError("MAC address must contain 12 hex digits")
    return bytes.fromhex(t)


def set_mac(data, mac: bytes | str) -> bytes:
    """Write MAC into every valid NVM bank and fix the checksums."""
    if isinstance(mac, str):
        mac = parse_mac(mac)
    buf = bytearray(data)
    for bank in range(banks(buf)):
        base = bank * GBE_BANK_SIZE
        if base + 0x80 > len(buf):
            break
        if bank > 0 and not bank_checksum_ok(buf, bank) and buf[base:base + 6] == b"\xff" * 6:
            continue
        buf[base:base + 6] = mac
        words = list(struct.unpack_from("<64H", buf, base))
        words[CHECKSUM_WORD] = 0
        struct.pack_into("<H", buf, base + CHECKSUM_WORD * 2, (CHECKSUM_TARGET - sum(words)) & 0xFFFF)
    return bytes(buf)


def parse_gbe_region(ctx, region: Node) -> None:
    data = region.body_view
    if len(data) < 0x80:
        region.msg("GbE region too small")
        return
    region.meta["mac"] = mac_of(data)
    region.text = region.meta["mac"]
    region.add_info("MAC address", region.meta["mac"])
    ver = data[10], data[11]
    region.add_info("Version", "%d.%d" % (ver[1], ver[0] >> 4))
    for bank in range(banks(data)):
        if (bank + 1) * GBE_BANK_SIZE > len(data) and bank:
            break
        ok = bank_checksum_ok(data, bank)
        region.add_info("NVM bank %d checksum" % bank, "valid" if ok else "invalid")
        if bank == 0 and not ok:
            region.msg("GbE NVM bank 0 checksum is invalid")
