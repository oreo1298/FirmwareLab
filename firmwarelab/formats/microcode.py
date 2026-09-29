"""Intel CPU microcode updates."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from ..core.binary import is_uniform, size_str, sum32
from ..core.node import Node, NodeType

# CPUID signature -> codename (family 6 / others). Stepping-specific where it matters.
CPU_CODENAMES = {
    0x10676: "Penryn/Wolfdale (C0)", 0x1067A: "Penryn/Wolfdale/Yorkfield (E0)",
    0x106A4: "Nehalem-EP/Bloomfield (C0)", 0x106A5: "Nehalem-EP/Bloomfield (D0)",
    0x106E5: "Lynnfield/Clarksfield", 0x20652: "Arrandale/Clarkdale (C2)", 0x20655: "Arrandale/Clarkdale (K0)",
    0x206C2: "Westmere-EP/Gulftown", 0x206A7: "Sandy Bridge (D2/J1/Q0)", 0x206D6: "Sandy Bridge-E (C1)",
    0x206D7: "Sandy Bridge-E (C2/M1)", 0x306A9: "Ivy Bridge (E1/L1/N0/P0)", 0x306E4: "Ivy Bridge-E",
    0x306C3: "Haswell (C0)", 0x40651: "Haswell-ULT", 0x40661: "Haswell Crystal Well",
    0x306F2: "Haswell-E/EP", 0x306D4: "Broadwell-U/Y", 0x40671: "Broadwell-H/C",
    0x406F1: "Broadwell-E/EP", 0x506E3: "Skylake-S/H", 0x406E3: "Skylake-U/Y",
    0x50654: "Skylake-SP/X", 0x50657: "Cascade Lake", 0x5065B: "Cooper Lake",
    0x806E9: "Kaby Lake-U/Y / Amber Lake", 0x806EA: "Kaby Lake-R / Coffee Lake-U",
    0x806EB: "Whiskey Lake-U", 0x806EC: "Whiskey/Comet Lake-U", 0x906E9: "Kaby Lake-S/H/X",
    0x906EA: "Coffee Lake-S/H (U0/B0)", 0x906EB: "Coffee Lake-S (B0)", 0x906EC: "Coffee Lake-S (P0)",
    0x906ED: "Coffee Lake Refresh (R0)", 0xA0652: "Comet Lake-H/S (Q0)", 0xA0653: "Comet Lake-S (G1)",
    0xA0655: "Comet Lake-S (G0)", 0xA0660: "Comet Lake-U (A0)", 0xA0661: "Comet Lake-U (K1)",
    0xA0671: "Rocket Lake-S", 0x706E5: "Ice Lake-U/Y", 0x606A6: "Ice Lake-SP",
    0x806C1: "Tiger Lake-U", 0x806C2: "Tiger Lake-U (C0)", 0x806D1: "Tiger Lake-H",
    0x90672: "Alder Lake-S", 0x90675: "Alder Lake-S", 0x906A3: "Alder Lake-P", 0x906A4: "Alder Lake-P",
    0xB0671: "Raptor Lake-S", 0xB06A2: "Raptor Lake-P", 0xB06A3: "Raptor Lake-P",
    0xB06F2: "Raptor Lake-S (ADL die)", 0xB06F5: "Raptor Lake-S (ADL die)", 0xA06A4: "Meteor Lake",
    0x806F8: "Sapphire Rapids", 0x30673: "Bay Trail (B2/B3)", 0x30678: "Bay Trail (C0)",
    0x30679: "Bay Trail (D0)", 0x406C3: "Cherry/Braswell (C0)", 0x406C4: "Cherry/Braswell (D0)",
    0x506C9: "Apollo Lake", 0x506CA: "Apollo Lake (E0)", 0x706A1: "Gemini Lake", 0x706A8: "Gemini Lake Refresh",
    0x906C0: "Jasper Lake", 0xB06E0: "Alder Lake-N", 0x50662: "Broadwell-DE", 0x50663: "Broadwell-DE",
    0x50664: "Broadwell-DE", 0x406D8: "Avoton/Rangeley", 0x506F1: "Denverton",
}


@dataclass
class MicrocodeInfo:
    revision: int
    date: str
    signature: int
    checksum: int
    flags: int
    data_size: int
    total_size: int
    checksum_valid: bool
    ext_signatures: list[tuple[int, int, int]] = field(default_factory=list)

    @property
    def cpu_name(self) -> str:
        return cpu_name(self.signature)

    @property
    def platforms(self) -> list[int]:
        return [i for i in range(8) if self.flags & (1 << i)]


def cpu_name(sig: int) -> str:
    if sig in CPU_CODENAMES:
        return CPU_CODENAMES[sig]
    stepping = sig & 0xF
    model = ((sig >> 4) & 0xF) | ((sig >> 12) & 0xF0)
    family = ((sig >> 8) & 0xF) + ((sig >> 20) & 0xFF)
    return "Family %Xh Model %Xh Stepping %Xh" % (family, model, stepping)


def _bcd_ok(v: int, lo: int, hi: int) -> bool:
    s = "%X" % v
    return s.isdigit() and lo <= int(s) <= hi


def is_intel_microcode(data, pos: int = 0) -> bool:
    if pos + 48 > len(data):
        return False
    hv, rev, date, sig, ck, lr, flags, dsize, tsize = struct.unpack_from("<9I", data, pos)
    if hv != 1 or lr != 1 or sig == 0 or sig == 0xFFFFFFFF:
        return False
    if dsize == 0:
        dsize = 2000
    if tsize == 0:
        tsize = 2048
    month = (date >> 24) & 0xFF
    day = (date >> 16) & 0xFF
    year = date & 0xFFFF
    if not (_bcd_ok(month, 1, 12) and _bcd_ok(day, 1, 31) and _bcd_ok(year, 1995, 2099)):
        return False
    if dsize % 4 or tsize % 1024 or dsize + 48 > tsize:
        return False
    if pos + tsize > len(data):
        return False
    return True


def parse_info(data, pos: int = 0) -> MicrocodeInfo:
    hv, rev, date, sig, ck, lr, flags, dsize, tsize = struct.unpack_from("<9I", data, pos)
    if dsize == 0:
        dsize = 2000
    if tsize == 0:
        tsize = 2048
    date_str = "%04X-%02X-%02X" % (date & 0xFFFF, (date >> 24) & 0xFF, (date >> 16) & 0xFF)
    blob = data[pos:pos + tsize]
    info = MicrocodeInfo(rev, date_str, sig, ck, flags, dsize, tsize, sum32(blob) == 0)
    if tsize > dsize + 48 + 20:
        e = pos + 48 + dsize
        count = struct.unpack_from("<I", data, e)[0]
        if count <= 64 and e + 20 + count * 12 <= pos + tsize:
            for i in range(count):
                info.ext_signatures.append(struct.unpack_from("<III", data, e + 20 + i * 12))
    return info


def parse_microcode(ctx, data, offset: int, in_decoded: bool = False) -> Node | None:
    if not is_intel_microcode(data, 0):
        return None
    info = parse_info(data, 0)
    raw = data[:info.total_size]
    node = Node(NodeType.MICROCODE, "Intel", "Intel microcode",
                "CPUID %Xh, rev %Xh" % (info.signature, info.revision), raw,
                hdr_size=48, offset=offset, in_decoded=in_decoded)
    node.meta["ucode"] = info
    node.add_info("CPU signature", "%08Xh (%s)" % (info.signature, info.cpu_name))
    node.add_info("Revision", "%Xh" % info.revision)
    node.add_info("Date", info.date)
    node.add_info("Platform IDs", "%02Xh [%s]" % (info.flags, ", ".join(str(p) for p in info.platforms)))
    node.add_info("Data size", size_str(info.data_size))
    node.add_info("Total size", size_str(info.total_size))
    node.add_info("Checksum", "%08Xh, %s" % (info.checksum, "valid" if info.checksum_valid else "invalid"))
    for s, f, c in info.ext_signatures:
        node.add_info("Extended signature", "%08Xh (%s), platforms %02Xh" % (s, cpu_name(s), f))
    if not info.checksum_valid:
        node.msg("Microcode checksum is invalid")
    if ctx is not None:
        ctx.remember("microcode", node)
    return node


def parse_microcode_area(ctx, parent: Node, data, base: int) -> None:
    from .area import make_padding
    pos = 0
    n = len(data)
    while pos < n:
        node = parse_microcode(ctx, data[pos:], base + pos)
        if node is not None:
            parent.add(node)
            pos += node.size
            continue
        # find next microcode on 16-byte boundary
        nxt = -1
        p = (pos + 15) & ~15
        raw = data
        while p + 48 <= n:
            if raw[p] == 1 and is_intel_microcode(raw, p):
                nxt = p
                break
            p += 16
        end = nxt if nxt >= 0 else n
        if end <= pos:
            end = n
        parent.add(make_padding(data[pos:end], base + pos))
        pos = end


def fix_checksum(blob: bytes) -> bytes:
    """Recompute the main (and extended table) checksum of a microcode update."""
    buf = bytearray(blob)
    struct.pack_into("<I", buf, 16, 0)
    struct.pack_into("<I", buf, 16, (0x100000000 - sum32(buf)) & 0xFFFFFFFF)
    return bytes(buf)


def is_empty(data) -> bool:
    return is_uniform(data, 0xFF) or is_uniform(data, 0x00)
