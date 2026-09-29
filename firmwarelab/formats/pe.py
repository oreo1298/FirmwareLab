"""PE32/PE32+ and TE image parsing and rebasing (for XIP modules that move)."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from ..core.binary import u16, u32, u64

MACHINES = {
    0x014C: "x86", 0x8664: "x86-64", 0x0200: "Itanium", 0x01C2: "ARM Thumb",
    0x01C0: "ARM", 0x01C4: "ARMv7 Thumb-2", 0xAA64: "AArch64", 0x0EBC: "EFI Byte Code",
    0x5032: "RISC-V32", 0x5064: "RISC-V64", 0x5128: "RISC-V128", 0x6232: "LoongArch32",
    0x6264: "LoongArch64",
}

SUBSYSTEMS = {
    10: "EFI application", 11: "EFI boot service driver", 12: "EFI runtime driver",
    13: "EFI ROM", 1: "Native", 2: "Windows GUI", 3: "Windows CUI",
}

TE_HEADER_SIZE = 40


class PeError(ValueError):
    pass


@dataclass
class PeSection:
    name: str
    vaddr: int
    vsize: int
    raw_off: int
    raw_size: int
    characteristics: int


@dataclass
class PeInfo:
    kind: str  # "PE32", "PE32+", "TE"
    machine: int
    subsystem: int
    image_base: int
    entry_point: int
    size_of_image: int = 0
    base_of_code: int = 0
    stripped_size: int = 0
    header_size: int = 0
    image_base_offset: int = 0  # file offset of the ImageBase field
    image_base_width: int = 8
    reloc_dir: tuple[int, int] = (0, 0)
    debug_dir: tuple[int, int] = (0, 0)
    sections: list[PeSection] = field(default_factory=list)
    pdb_path: str | None = None
    characteristics: int = 0
    dll_characteristics: int = 0
    timestamp: int = 0
    checksum: int = 0
    checksum_offset: int = 0

    @property
    def machine_name(self) -> str:
        return MACHINES.get(self.machine, "Unknown (%04Xh)" % self.machine)

    @property
    def subsystem_name(self) -> str:
        return SUBSYSTEMS.get(self.subsystem, "Unknown (%d)" % self.subsystem)

    @property
    def has_relocations(self) -> bool:
        return self.reloc_dir[1] > 0

    def rva_to_offset(self, rva: int) -> int | None:
        if self.kind == "TE":
            return rva - self.stripped_size + TE_HEADER_SIZE
        if rva < self.header_size:
            return rva
        for s in self.sections:
            span = max(s.vsize, s.raw_size)
            if s.vaddr <= rva < s.vaddr + span:
                if rva - s.vaddr >= s.raw_size:
                    return None
                return s.raw_off + (rva - s.vaddr)
        return None

    @property
    def module_name(self) -> str | None:
        if not self.pdb_path:
            return None
        name = self.pdb_path.replace("\\", "/").rsplit("/", 1)[-1]
        for ext in (".pdb", ".dll", ".efi", ".debug"):
            if name.lower().endswith(ext):
                name = name[: -len(ext)]
        return name or None


def is_pe(data) -> bool:
    if len(data) < 0x40 or data[0:2] != b"MZ":
        return False
    lfanew = u32(data, 0x3C)
    return lfanew + 24 <= len(data) and data[lfanew:lfanew + 4] == b"PE\0\0"


def is_te(data) -> bool:
    return len(data) >= TE_HEADER_SIZE and data[0:2] == b"VZ"


def _read_sections(data, off, count) -> list[PeSection]:
    out = []
    for i in range(count):
        p = off + i * 40
        if p + 40 > len(data):
            break
        name = bytes(data[p:p + 8]).split(b"\0", 1)[0].decode("latin-1")
        vsize, vaddr, rsize, roff = struct.unpack_from("<IIII", data, p + 8)
        ch = u32(data, p + 36)
        out.append(PeSection(name, vaddr, vsize, roff, rsize, ch))
    return out


def parse(data) -> PeInfo:
    data = memoryview(data) if not isinstance(data, (bytes, bytearray, memoryview)) else data
    if is_te(data):
        machine = u16(data, 2)
        nsec = data[4]
        subsystem = data[5]
        stripped = u16(data, 6)
        entry = u32(data, 8)
        boc = u32(data, 12)
        base = u64(data, 16)
        reloc = (u32(data, 24), u32(data, 28))
        debug = (u32(data, 32), u32(data, 36))
        info = PeInfo("TE", machine, subsystem, base, entry, base_of_code=boc,
                      stripped_size=stripped, header_size=TE_HEADER_SIZE, image_base_offset=16,
                      image_base_width=8, reloc_dir=reloc, debug_dir=debug)
        info.sections = _read_sections(data, TE_HEADER_SIZE, nsec)
        _read_debug(data, info)
        return info
    if not is_pe(data):
        raise PeError("not a PE or TE image")
    lfanew = u32(data, 0x3C)
    coff = lfanew + 4
    machine, nsec, ts, _, _, opt_size, chars = struct.unpack_from("<HHIIIHH", data, coff)
    opt = coff + 20
    if opt + 2 > len(data):
        raise PeError("truncated optional header")
    magic = u16(data, opt)
    if magic == 0x10B:
        kind = "PE32"
        base = u32(data, opt + 28)
        base_off, width = opt + 28, 4
        dd_count_off, dd_off = opt + 92, opt + 96
    elif magic == 0x20B:
        kind = "PE32+"
        base = u64(data, opt + 24)
        base_off, width = opt + 24, 8
        dd_count_off, dd_off = opt + 108, opt + 112
    else:
        raise PeError("unknown optional header magic %04Xh" % magic)
    entry = u32(data, opt + 16)
    boc = u32(data, opt + 20)
    size_of_image = u32(data, opt + 56)
    size_of_headers = u32(data, opt + 60)
    checksum = u32(data, opt + 64)
    subsystem = u16(data, opt + 68)
    dllch = u16(data, opt + 70)
    ndd = u32(data, dd_count_off) if dd_count_off + 4 <= len(data) else 0

    def ddir(i):
        if i >= ndd or dd_off + i * 8 + 8 > len(data):
            return (0, 0)
        return struct.unpack_from("<II", data, dd_off + i * 8)

    info = PeInfo(kind, machine, subsystem, base, entry, size_of_image=size_of_image,
                  base_of_code=boc, header_size=size_of_headers, image_base_offset=base_off,
                  image_base_width=width, reloc_dir=ddir(5), debug_dir=ddir(6),
                  characteristics=chars, dll_characteristics=dllch, timestamp=ts,
                  checksum=checksum, checksum_offset=opt + 64)
    info.sections = _read_sections(data, opt + opt_size, nsec)
    _read_debug(data, info)
    return info


def _read_debug(data, info: PeInfo) -> None:
    rva, size = info.debug_dir
    if not rva or not size:
        return
    off = info.rva_to_offset(rva)
    if off is None or off < 0:
        return
    for i in range(min(size // 28, 16)):
        e = off + i * 28
        if e + 28 > len(data):
            return
        typ = u32(data, e + 12)
        dsize = u32(data, e + 16)
        draw_rva = u32(data, e + 20)
        draw_off = u32(data, e + 24)
        if typ != 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
            continue
        p = info.rva_to_offset(draw_rva) if draw_rva else None
        if p is None or p < 0 or p + 4 > len(data):
            p = draw_off if info.kind != "TE" else None
        if p is None or p < 0 or p + 4 > len(data):
            continue
        sig = bytes(data[p:p + 4])
        if sig == b"RSDS":
            s = p + 24
        elif sig == b"NB10":
            s = p + 16
        elif sig == b"MTOC":
            s = p + 20
        else:
            continue
        end = min(len(data), p + max(dsize, 4) + 260)
        raw = bytes(data[s:end]).split(b"\0", 1)[0]
        try:
            info.pdb_path = raw.decode("utf-8")
        except UnicodeDecodeError:
            info.pdb_path = raw.decode("latin-1")
        return


def relocations(data, info: PeInfo) -> list[tuple[int, int]]:
    """Return list of (type, rva) fixups."""
    rva, size = info.reloc_dir
    out = []
    if not rva or not size:
        return out
    off = info.rva_to_offset(rva)
    if off is None or off < 0:
        raise PeError("relocation directory outside of image data")
    end = min(len(data), off + size)
    p = off
    while p + 8 <= end:
        page, bsize = struct.unpack_from("<II", data, p)
        if bsize < 8 or p + bsize > end + 8:
            break
        n = (bsize - 8) // 2
        for i in range(n):
            e = u16(data, p + 8 + i * 2)
            t = e >> 12
            if t == 0:
                continue
            out.append((t, page + (e & 0xFFF)))
        p += bsize
    return out


def rebase(data, delta: int) -> bytes:
    """Apply a base address change of ``delta`` to a PE/TE image. Returns new bytes."""
    if delta == 0:
        return bytes(data)
    buf = bytearray(data)
    info = parse(buf)
    fixups = relocations(buf, info)
    if not fixups and info.reloc_dir[1] == 0:
        raise PeError("image has no relocation information, cannot rebase")
    i = 0
    while i < len(fixups):
        t, rva = fixups[i]
        off = info.rva_to_offset(rva)
        if off is None or off < 0 or off >= len(buf):
            i += 1
            continue
        if t == 3:  # HIGHLOW
            v = struct.unpack_from("<I", buf, off)[0]
            struct.pack_into("<I", buf, off, (v + delta) & 0xFFFFFFFF)
        elif t == 10:  # DIR64
            v = struct.unpack_from("<Q", buf, off)[0]
            struct.pack_into("<Q", buf, off, (v + delta) & 0xFFFFFFFFFFFFFFFF)
        elif t == 1:  # HIGH
            v = struct.unpack_from("<H", buf, off)[0]
            v = ((v << 16) + delta) >> 16
            struct.pack_into("<H", buf, off, v & 0xFFFF)
        elif t == 2:  # LOW
            v = struct.unpack_from("<H", buf, off)[0]
            struct.pack_into("<H", buf, off, (v + delta) & 0xFFFF)
        elif t == 4:  # HIGHADJ, uses next entry as low part
            v = struct.unpack_from("<H", buf, off)[0]
            low = fixups[i + 1][1] & 0xFFFF if i + 1 < len(fixups) else 0
            if low & 0x8000:
                low -= 0x10000
            full = (v << 16) + low + delta + 0x8000
            struct.pack_into("<H", buf, off, (full >> 16) & 0xFFFF)
            i += 1
        else:
            raise PeError("unsupported relocation type %d" % t)
        i += 1
    base = info.image_base + delta
    if info.image_base_width == 8:
        struct.pack_into("<Q", buf, info.image_base_offset, base & 0xFFFFFFFFFFFFFFFF)
    else:
        struct.pack_into("<I", buf, info.image_base_offset, base & 0xFFFFFFFF)
    return bytes(buf)


def expected_xip_base(info: PeInfo, image_address: int) -> int:
    """Image base an XIP image located at ``image_address`` must have."""
    if info.kind == "TE":
        return image_address + TE_HEADER_SIZE - info.stripped_size
    return image_address


def describe(info: PeInfo) -> list[tuple[str, str]]:
    rows = [
        ("Image format", info.kind),
        ("Machine", info.machine_name),
        ("Subsystem", info.subsystem_name),
        ("Image base", "%Xh" % info.image_base),
        ("Entry point RVA", "%Xh" % info.entry_point),
    ]
    if info.kind == "TE":
        rows.append(("Stripped size", "%Xh" % info.stripped_size))
    else:
        rows.append(("Size of image", "%Xh" % info.size_of_image))
    rows.append(("Relocations", "present (%Xh bytes)" % info.reloc_dir[1] if info.has_relocations else "none"))
    if info.sections:
        rows.append(("Sections", ", ".join(s.name or "?" for s in info.sections)))
    if info.pdb_path:
        rows.append(("Debug path", info.pdb_path))
    return rows
