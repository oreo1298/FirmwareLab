"""Intel Flash Descriptor (IFD): regions, masters, straps, VSCC table and modifications."""

from __future__ import annotations

import csv
import os
import struct
from dataclasses import dataclass, field

from ..core.binary import u32

SIGNATURE = b"\x5a\xa5\xf0\x0f"
DESCRIPTOR_SIZE = 0x1000
MAX_BASE = 0xE0

REGION_NAMES = [
    "Descriptor", "BIOS", "ME", "GbE", "PDR", "DevExp1", "BIOS2", "Microcode", "EC", "DevExp2",
    "IE", "10GbE1", "10GbE2", "Reserved1", "Reserved2", "PTT",
]
MASTER_NAMES = ["BIOS", "ME", "GbE", "Reserved", "EC"]

_JEDEC: dict[int, str] | None = None


def jedec_name(jid: int) -> str:
    global _JEDEC
    if _JEDEC is None:
        _JEDEC = {}
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "jedec.csv")
        if os.path.isfile(path):
            with open(path, encoding="utf-8") as fh:
                for row in csv.reader(fh):
                    if len(row) >= 2 and not row[0].startswith("#"):
                        try:
                            _JEDEC[int(row[0], 16)] = row[1]
                        except ValueError:
                            pass
    return _JEDEC.get(jid, "Unknown")


def jedec_capacity(jid: int) -> int | None:
    """Estimate chip capacity in bytes from the JEDEC capacity byte."""
    c = jid & 0xFF
    if 0x10 <= c <= 0x19:
        return 1 << c
    if 0x20 <= c <= 0x22:
        return 1 << (c - 0x20 + 26)
    return None


@dataclass
class Region:
    index: int
    name: str
    base: int  # raw 15/16-bit base value
    limit: int
    offset: int
    size: int

    @property
    def end(self) -> int:
        return self.offset + self.size

    @property
    def used(self) -> bool:
        return self.size > 0


@dataclass
class Master:
    name: str
    read: int
    write: int
    requester_id: int = 0
    raw: int = 0
    offset: int = 0  # offset of the FLMSTR register in the descriptor


@dataclass
class Descriptor:
    offset: int  # descriptor start inside the image (0 normally)
    version: int  # 1 (ICH8 .. 100-series style) or 2 (Skylake+)
    fcba: int
    frba: int
    fmba: int
    fpsba: int
    nc: int
    nr: int
    nm: int
    isl: int
    psl: int
    flcomp: int
    regions: list[Region] = field(default_factory=list)
    masters: list[Master] = field(default_factory=list)
    pch_straps: list[int] = field(default_factory=list)
    proc_straps: list[int] = field(default_factory=list)
    vscc: list[tuple[int, int]] = field(default_factory=list)  # (jedec id, vscc value)
    descriptor_version: tuple[int, int] | None = None
    messages: list[str] = field(default_factory=list)

    def region(self, name: str) -> Region | None:
        for r in self.regions:
            if r.name == name and r.used:
                return r
        return None

    @property
    def component_sizes(self) -> list[int]:
        if self.version == 1:
            dens = [self.flcomp & 0x07, (self.flcomp >> 3) & 0x07]
            unused = 0x7
        else:
            dens = [self.flcomp & 0x0F, (self.flcomp >> 4) & 0x0F]
            unused = 0xF
        out = []
        for i in range(min(self.nc + 1, 2)):
            d = dens[i]
            if d == unused or d > 0xA:
                continue
            out.append((512 * 1024) << d)
        return out


def find_descriptor(data) -> int:
    """Offset of a flash descriptor (0 for images with a descriptor), or -1."""
    if len(data) >= DESCRIPTOR_SIZE and bytes(data[16:20]) == SIGNATURE:
        return 0
    return -1


def parse(data, offset: int = 0) -> Descriptor:
    d = data[offset:offset + DESCRIPTOR_SIZE]
    if len(d) < DESCRIPTOR_SIZE or bytes(d[16:20]) != SIGNATURE:
        raise ValueError("Flash descriptor signature not found")
    flmap0, flmap1, flmap2 = struct.unpack_from("<III", d, 20)
    fcba = (flmap0 & 0xFF) << 4
    nc = (flmap0 >> 8) & 0x3
    frba = ((flmap0 >> 16) & 0xFF) << 4
    nr = (flmap0 >> 24) & 0x7
    fmba = (flmap1 & 0xFF) << 4
    nm = (flmap1 >> 8) & 0x3
    fpsba = ((flmap1 >> 16) & 0xFF) << 4
    isl = (flmap1 >> 24) & 0xFF
    psl = (flmap2 >> 8) & 0xFF
    for name, base in (("component", fcba), ("region", frba), ("master", fmba)):
        if base > MAX_BASE << 4 or base == 0:
            raise ValueError("Invalid descriptor %s base %Xh" % (name, base))
    if fmba == frba or fmba == fcba or frba == fcba:
        raise ValueError("Overlapping descriptor sections")
    flcomp = u32(d, fcba)
    # v1 descriptors hardcode ReadClockFrequency (bits 17..19) to 0 (20 MHz). Some tool-generated
    # v2 descriptors also leave it zero, so fall back to the strap count (v2 PCHs have 60+ straps).
    version = 1 if ((flcomp >> 17) & 0x7) == 0 else 2
    if version == 1 and isl > 32:
        version = 2
    desc = Descriptor(offset, version, fcba, frba, fmba, fpsba, nc, nr, nm, isl, psl, flcomp)
    dv = u32(d, 0x20)
    if version == 2 and dv not in (0xFFFFFFFF, 0):
        desc.descriptor_version = ((dv >> 21) & 0x7FF, (dv >> 14) & 0x7F)
    # Regions
    count = 16 if version == 2 else 7
    mask = 0x7FFF
    for i in range(count):
        p = frba + i * 4
        if p + 4 > DESCRIPTOR_SIZE:
            break
        v = u32(d, p)
        base = v & mask
        limit = (v >> 16) & mask
        if i == 0:
            off, size = 0, DESCRIPTOR_SIZE
        elif limit == 0 or (base == mask and limit in (0, mask)) or base > limit:
            off, size = base << 12, 0
        else:
            off = base << 12
            size = (limit + 1 - base) << 12
        desc.regions.append(Region(i, REGION_NAMES[i], base, limit, off, size))
    # Masters
    for i in range(min(nm + 1, 5) if version == 1 else 5):
        p = fmba + i * 4
        if p + 4 > DESCRIPTOR_SIZE:
            break
        v = u32(d, p)
        if version == 1:
            m = Master(MASTER_NAMES[i], (v >> 16) & 0xFF, (v >> 24) & 0xFF, v & 0xFFFF, v, p)
        else:
            m = Master(MASTER_NAMES[i], (v >> 8) & 0xFFF, (v >> 20) & 0xFFF, 0, v, p)
        desc.masters.append(m)
    # Straps
    for i in range(isl):
        p = fpsba + i * 4
        if p + 4 <= DESCRIPTOR_SIZE:
            desc.pch_straps.append(u32(d, p))
    # VSCC table
    upper = 0xEFC
    vtba = d[upper] << 4
    vtl = d[upper + 1]
    for i in range(vtl // 2):
        p = vtba + i * 8
        if p + 8 > DESCRIPTOR_SIZE:
            break
        jid = (d[p] << 16) | (d[p + 1] << 8) | d[p + 2]
        desc.vscc.append((jid, u32(d, p + 4)))
    return desc


def region_access_table(desc: Descriptor) -> list[tuple[str, list[str], list[str]]]:
    """Per master: list of region names readable and writable."""
    out = []
    for m in desc.masters:
        readable = [REGION_NAMES[i] for i in range(12 if desc.version == 2 else 8) if m.read & (1 << i)]
        writable = [REGION_NAMES[i] for i in range(12 if desc.version == 2 else 8) if m.write & (1 << i)]
        out.append((m.name, readable, writable))
    return out


def describe(desc: Descriptor) -> list[tuple[str, str]]:
    rows = [("Descriptor version", "v%d" % desc.version)]
    if desc.descriptor_version:
        rows.append(("Flash descriptor revision", "%d.%d" % desc.descriptor_version))
    rows.append(("Flash chips", str(desc.nc + 1)))
    sizes = desc.component_sizes
    if sizes and all(sizes):
        rows.append(("Component density", ", ".join("%d MiB" % (s >> 20) for s in sizes)))
    rows.append(("Regions (NR)", str(desc.nr + 1)))
    rows.append(("Masters (NM)", str(desc.nm + 1)))
    rows.append(("PCH straps", str(desc.isl)))
    for r in desc.regions:
        if r.used:
            rows.append(("%s region" % r.name, "%08Xh - %08Xh (%Xh bytes)" % (r.offset, r.end - 1, r.size)))
    for name, rd, wr in region_access_table(desc):
        if name == "Reserved":
            continue
        rows.append(("%s master read" % name, ", ".join(rd) or "none"))
        rows.append(("%s master write" % name, ", ".join(wr) or "none"))
    for jid, v in desc.vscc:
        rows.append(("VSCC flash chip", "%06Xh (%s)" % (jid, jedec_name(jid))))
    if is_locked(desc):
        rows.append(("Lock status", "Locked: BIOS master cannot write all regions (ME/descriptor protected)"))
    else:
        rows.append(("Lock status", "Unlocked"))
    return rows


def is_locked(desc: Descriptor) -> bool:
    bios = next((m for m in desc.masters if m.name == "BIOS"), None)
    if bios is None:
        return False
    needed = 0x0F if desc.version == 1 else 0x0F  # Descriptor, BIOS, ME, GbE
    return (bios.write & needed) != needed


def unlock(image: bytes | bytearray, desc: Descriptor | None = None) -> bytes:
    """Grant full read/write access to all regions for the BIOS (host CPU) and ME masters.

    Same effect as ``ifdtool --unlock`` for the host: flashrom/FPT can then write every
    region from the OS. The GbE master keeps its own settings; straps and region layout
    are untouched.
    """
    buf = bytearray(image)
    desc = desc or parse(buf)
    base = desc.offset
    for m in desc.masters:
        if m.name not in ("BIOS", "ME"):
            continue
        p = base + m.offset
        v = u32(buf, p)
        if desc.version == 1:
            v = (v & 0x0000FFFF) | 0xFFFF0000
        else:
            v = (v & 0x000000FF) | 0xFFFFFF00
        struct.pack_into("<I", buf, p, v)
    return bytes(buf)


def set_me_disable_bit(image: bytes | bytearray, me_major: int, enable: bool = True,
                       desc: Descriptor | None = None) -> bytes:
    """Set (or clear) the ME soft-disable strap.

    ME 11 and newer: HAP bit (PCHSTRP0 bit 16). Older ME: AltMeDisable (PCHSTRP10 bit 7).
    This mirrors me_cleaner's -S behaviour. Only use on platforms where it is known to work.
    """
    buf = bytearray(image)
    desc = desc or parse(buf)
    if me_major >= 11:
        idx, bit = 0, 16
    else:
        idx, bit = 10, 7
    if idx >= desc.isl:
        raise ValueError("Descriptor has only %d PCH straps" % desc.isl)
    p = desc.offset + desc.fpsba + idx * 4
    v = u32(buf, p)
    v = v | (1 << bit) if enable else v & ~(1 << bit)
    struct.pack_into("<I", buf, p, v)
    return bytes(buf)


def me_disable_bit_state(desc: Descriptor, me_major: int) -> bool | None:
    idx, bit = (0, 16) if me_major >= 11 else (10, 7)
    if idx >= len(desc.pch_straps):
        return None
    return bool(desc.pch_straps[idx] & (1 << bit))
