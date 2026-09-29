"""Intel Firmware Interface Table (FIT), Boot Guard key/boot policy manifests and ACMs."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from ..core.binary import u16, u32, u64

FIT_POINTER_ADDRESS = 0xFFFFFFC0
FIT_SIGNATURE = b"_FIT_   "

FIT_TYPES = {
    0x00: "FIT header", 0x01: "Microcode", 0x02: "Startup ACM", 0x03: "Diagnostic ACM",
    0x04: "Platform boot policy", 0x07: "BIOS startup module", 0x08: "TPM policy",
    0x09: "BIOS policy", 0x0A: "TXT policy", 0x0B: "Key manifest", 0x0C: "Boot policy manifest",
    0x10: "CSE secure boot", 0x1A: "Feature policy", 0x2C: "JMP $ debug policy",
    0x2D: "FIT PMC", 0x2E: "FIT PMC ACM", 0x2F: "SPI config", 0x7F: "Unused",
}


@dataclass
class FitEntry:
    index: int
    address: int
    size: int  # raw size field (units of 16 bytes for most types)
    version: int
    type: int
    cv: bool
    checksum: int
    entry_offset: int  # file offset of this FIT entry
    target_offset: int | None = None  # file offset the address points to

    @property
    def type_name(self) -> str:
        return FIT_TYPES.get(self.type, "Type %02Xh" % self.type)


@dataclass
class IbbSegment:
    base: int
    size: int
    flags: int

    @property
    def is_ibb(self) -> bool:
        return not (self.flags & 1)


@dataclass
class BootGuardInfo:
    km_present: bool = False
    km_version: int = 0
    km_id: int = 0
    km_svn: int = 0
    bpm_present: bool = False
    bpm_version: int = 0
    bpm_svn: int = 0
    acm_present: bool = False
    acm_date: str = ""
    acm_debug: bool = False
    acm_chipset: int = 0
    ibb_entry: int = 0
    ibb_segments: list[IbbSegment] = field(default_factory=list)
    vendor_ranges: list[tuple[int, int]] = field(default_factory=list)
    messages: list[str] = field(default_factory=list)


@dataclass
class FitTable:
    pointer_offset: int
    table_offset: int
    entries: list[FitEntry]
    checksum_valid: bool | None
    bootguard: BootGuardInfo
    messages: list[str] = field(default_factory=list)

    def microcode_entries(self) -> list[FitEntry]:
        return [e for e in self.entries if e.type == 1]


def parse(ctx, data) -> FitTable | None:
    """Locate and parse the FIT using the context's memory map. ``data`` is the whole file."""
    ptr_off = ctx.offset_of_address(FIT_POINTER_ADDRESS)
    if ptr_off is None or ptr_off + 8 > len(data):
        return None
    ptr = u64(data, ptr_off) & 0xFFFFFFFF
    if ptr in (0, 0xFFFFFFFF):
        return None
    table_off = ctx.offset_of_address(ptr)
    if table_off is None or table_off + 16 > len(data):
        return None
    if bytes(data[table_off:table_off + 8]) != FIT_SIGNATURE:
        return None
    count = u32(data, table_off + 8) & 0xFFFFFF
    if count == 0 or count > 512 or table_off + count * 16 > len(data):
        return None
    entries = []
    for i in range(count):
        p = table_off + i * 16
        addr = u64(data, p)
        size = u32(data, p + 8) & 0xFFFFFF
        ver = u16(data, p + 12)
        tb = data[p + 14]
        ck = data[p + 15]
        e = FitEntry(i, addr, size, ver, tb & 0x7F, bool(tb & 0x80), ck, p)
        if i > 0 and e.type not in (0x7F,) and addr:
            e.target_offset = ctx.offset_of_address(addr & 0xFFFFFFFF)
        entries.append(e)
    hdr = entries[0]
    ck_valid = None
    if hdr.cv:
        ck_valid = sum(data[table_off:table_off + count * 16]) & 0xFF == 0
    fit = FitTable(ptr_off, table_off, entries, ck_valid, BootGuardInfo())
    if ck_valid is False:
        fit.messages.append("FIT checksum is invalid")
    _parse_bootguard(ctx, data, fit)
    _check_microcode(data, fit)
    return fit


def _check_microcode(data, fit: FitTable) -> None:
    from . import microcode
    for e in fit.microcode_entries():
        if e.target_offset is None:
            fit.messages.append("FIT microcode entry %d points outside the image (%Xh)" % (e.index, e.address))
        elif not microcode.is_intel_microcode(data, e.target_offset) and \
                not microcode.is_empty(data[e.target_offset:e.target_offset + 48]):
            fit.messages.append("FIT microcode entry %d does not point to a valid microcode (%Xh)" % (e.index, e.address))


def _parse_bootguard(ctx, data, fit: FitTable) -> None:
    bg = fit.bootguard
    for e in fit.entries:
        off = e.target_offset
        if off is None:
            continue
        if e.type == 0x02 and off + 0x40 <= len(data):
            bg.acm_present = True
            bg.acm_chipset = u16(data, off + 12)
            flags = u16(data, off + 14)
            bg.acm_debug = bool(flags & 0x8000)
            bg.acm_date = "%04X-%02X-%02X" % (u16(data, off + 22), data[off + 21], data[off + 20])
        elif e.type == 0x0B and bytes(data[off:off + 8]) == b"__KEYM__":
            bg.km_present = True
            bg.km_version = data[off + 8]
            if bg.km_version < 0x20:
                bg.km_svn = data[off + 10]
                bg.km_id = data[off + 11]
            else:
                bg.km_svn = data[off + 18]
                bg.km_id = data[off + 19]
        elif e.type == 0x0C and bytes(data[off:off + 8]) == b"__ACBP__":
            bg.bpm_present = True
            bg.bpm_version = data[off + 8]
            try:
                if bg.bpm_version < 0x20:
                    _parse_bpm_v1(data, off, bg)
                else:
                    _parse_bpm_v2(data, off, bg)
            except (struct.error, IndexError) as ex:
                bg.messages.append("Boot policy manifest parsing failed: %s" % ex)


def _hash_len_v1(data, p) -> int:
    return 4 + 32


def _parse_ibbs_segments(data, p, bg):
    n = data[p]
    p += 1
    for _ in range(min(n, 64)):
        flags = u16(data, p + 2)
        base = u32(data, p + 4)
        size = u32(data, p + 8)
        bg.ibb_segments.append(IbbSegment(base, size, flags))
        p += 12
    return p


def _parse_bpm_v1(data, off, bg):
    bg.bpm_svn = data[off + 11]
    p = off + 16
    for _ in range(8):
        sid = bytes(data[p:p + 8])
        if sid == b"__IBBS__":
            q = p + 9 + 3 + 4 + 8 + 8 + 4 + 4 + 8 + 8
            q += 36  # post IBB hash
            bg.ibb_entry = u32(data, q)
            q += 4 + 36
            _parse_ibbs_segments(data, q, bg)
            return
        if sid == b"__PMDA__":
            total = u16(data, p + 9)
            _parse_pmda(data, p + 11, total, bg, v2=False)
            p += 9 + 2 + total
            continue
        return


def _read_hash(data, p) -> int:
    ln = u16(data, p + 2)
    return p + 4 + ln


def _parse_bpm_v2(data, off, bg):
    bg.bpm_svn = data[off + 17]
    p = off + 20
    for _ in range(16):
        sid = bytes(data[p:p + 8])
        total = u16(data, p + 10)
        if total < 12:
            return
        if sid == b"__IBBS__":
            q = p + 12 + 4 + 4 + 8 + 8 + 4 + 4 + 8 + 8
            q = _read_hash(data, q)
            bg.ibb_entry = u32(data, q)
            q += 4
            q += 2  # digests size
            nd = u16(data, q)
            q += 2
            for _ in range(min(nd, 8)):
                q = _read_hash(data, q)
            q = _read_hash(data, q)  # OBB digest
            q += 3
            _parse_ibbs_segments(data, q, bg)
        elif sid == b"__PMDA__":
            _parse_pmda(data, p + 12, total - 12, bg, v2=True)
        elif sid == b"__PMSG__":
            return
        p += total


def _parse_pmda(data, p, total, bg, v2: bool):
    try:
        if v2:
            p += 2  # reserved
            p += 2  # total size
            ver = u32(data, p)
            n = u32(data, p + 4)
            p += 8
            for _ in range(min(n, 64)):
                if ver == 3:
                    base, size = u32(data, p + 4), u32(data, p + 8)
                    esz = u16(data, p + 12)
                    bg.vendor_ranges.append((base, size))
                    p += esz if esz else 16 + 36
                else:
                    break
        else:
            ver = u32(data, p)
            n = u32(data, p + 4)
            p += 8
            for _ in range(min(n, 64)):
                base, size = u32(data, p), u32(data, p + 4)
                bg.vendor_ranges.append((base, size))
                p += 8 + (32 if ver == 1 else 36)
    except (struct.error, IndexError):
        pass


def describe(fit: FitTable) -> list[tuple[str, str]]:
    rows = [("FIT address", "%Xh" % (fit.entries[0].address if fit.entries else 0)),
            ("FIT table offset", "%Xh" % fit.table_offset), ("Entries", str(len(fit.entries)))]
    bg = fit.bootguard
    if bg.km_present or bg.bpm_present:
        rows.append(("Boot Guard", "Key manifest %s, boot policy %s" % (
            "present" if bg.km_present else "absent", "present" if bg.bpm_present else "absent")))
        if bg.ibb_segments:
            segs = ", ".join("%08Xh+%Xh" % (s.base, s.size) for s in bg.ibb_segments if s.is_ibb)
            rows.append(("IBB segments", segs))
    if bg.acm_present:
        rows.append(("Startup ACM", "date %s, %s" % (bg.acm_date, "debug" if bg.acm_debug else "production")))
    return rows
