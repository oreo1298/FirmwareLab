"""AMD Embedded Firmware Structure (EFS) and PSP/BIOS directories (read-only analysis)."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.binary import u32, u64

EFS_SIGNATURE = 0x55AA55AA
EFS_OFFSETS = (0xFA0000, 0xF20000, 0xE20000, 0xC20000, 0x820000, 0x020000)

PSP_TYPES = {
    0x00: "AMD public key", 0x01: "PSP boot loader", 0x02: "PSP secure OS", 0x03: "PSP recovery",
    0x04: "PSP NVRAM", 0x05: "RTM public key", 0x06: "BIOS RTM", 0x08: "SMU firmware",
    0x09: "Secured debug", 0x0A: "ABL public key", 0x0B: "PSP soft fuse chain", 0x0C: "Trustlets",
    0x0D: "Trustlet key", 0x10: "AGESA resume", 0x12: "SMU firmware 2", 0x13: "Debug unlock",
    0x1A: "SEV driver", 0x1B: "Boot driver", 0x1C: "SoC driver", 0x1D: "Debug driver",
    0x1F: "Interface driver", 0x20: "HW IP config", 0x21: "Wrapped iKEK", 0x22: "Token unlock",
    0x24: "Security gasket", 0x25: "MP2 firmware", 0x28: "Driver entries", 0x29: "KVM image",
    0x2A: "MP5 firmware", 0x2D: "S0i3 driver", 0x30: "ABL0", 0x31: "ABL1", 0x32: "ABL2", 0x33: "ABL3",
    0x34: "ABL4", 0x35: "ABL5", 0x36: "ABL6", 0x37: "ABL7", 0x38: "SEV data", 0x39: "SEV code",
    0x3A: "PSP whitelist", 0x3C: "VBIOS boot loader", 0x40: "PSP L2 directory", 0x42: "DXIO firmware",
    0x44: "USB PHY firmware", 0x45: "TOS security policy", 0x46: "EFS backup", 0x47: "DRTM TA",
    0x48: "Recovery A/B A", 0x49: "BIOS directory table", 0x4A: "Recovery A/B B", 0x50: "Key DB BL",
    0x51: "Key DB TOS", 0x52: "PSP verstage", 0x53: "Verstage signature", 0x54: "RPMC NVRAM",
    0x55: "SPL table", 0x58: "DMCU ERAM", 0x59: "DMCU ISR", 0x5A: "MSMU", 0x5C: "SPI ROM config",
    0x5D: "MPIO", 0x5F: "TPM lite", 0x71: "DMCUB", 0x73: "PSP boot loader A/B", 0x76: "RIB",
}
BIOS_TYPES = {
    0x05: "BIOS public key", 0x07: "BIOS signature", 0x60: "APCB", 0x61: "APOB", 0x62: "BIOS binary",
    0x63: "APOB NV", 0x64: "PMU instructions", 0x65: "PMU data", 0x66: "Microcode", 0x67: "FHP driver",
    0x68: "APCB backup", 0x69: "Early VGA", 0x6A: "MP2 config", 0x6B: "PSP shared memory",
    0x70: "BIOS L2 directory",
}


@dataclass
class DirEntry:
    type: int
    subprogram: int
    size: int
    location: int
    offset: int | None
    destination: int | None = None
    name: str = ""


@dataclass
class Directory:
    kind: str  # $PSP, $PL2, $BHD, $BL2, 2PSP, 2BHD
    offset: int
    entries: list[DirEntry] = field(default_factory=list)


@dataclass
class AmdInfo:
    efs_offset: int
    directories: list[Directory] = field(default_factory=list)
    messages: list[str] = field(default_factory=list)

    def microcodes(self) -> list[DirEntry]:
        return [e for d in self.directories for e in d.entries if d.kind in ("$BHD", "$BL2") and e.type == 0x66]


def _to_offset(value: int, size: int) -> int | None:
    if value == 0 or value == 0xFFFFFFFF:
        return None
    v = value & 0xFFFFFFFF
    if v >= 0xFF000000 or (v & 0xFF000000 and size <= 0x1000000):
        v &= 0x00FFFFFF
        if size > 0x1000000:
            v += size - 0x1000000
    elif size and size & (size - 1) == 0:
        v &= size - 1
    return v if v < size else None


def find_efs(data) -> int:
    n = len(data)
    for off in EFS_OFFSETS:
        for base in (off, off - 0x1000000 + n if n > 0x1000000 else None):
            if base is None or base < 0 or base + 0x50 > n:
                continue
            if u32(data, base) == EFS_SIGNATURE:
                return base
    return -1


def parse(data) -> AmdInfo | None:
    efs = find_efs(data)
    if efs < 0:
        return None
    info = AmdInfo(efs)
    n = len(data)
    candidates = [u32(data, efs + 0x10), u32(data, efs + 0x14), u32(data, efs + 0x18),
                  u32(data, efs + 0x1C), u32(data, efs + 0x20), u32(data, efs + 0x28)]
    seen = set()
    queue = [_to_offset(c, n) for c in candidates]
    while queue:
        off = queue.pop(0)
        if off is None or off in seen or off + 16 > n:
            continue
        seen.add(off)
        sig = bytes(data[off:off + 4])
        if sig in (b"$PSP", b"$PL2", b"$BHD", b"$BL2"):
            d = _parse_dir(data, off, sig.decode(), n)
            info.directories.append(d)
            for e in d.entries:
                if (sig in (b"$PSP", b"$PL2") and e.type in (0x40, 0x49)) or (sig in (b"$BHD", b"$BL2") and e.type == 0x70):
                    queue.append(e.offset)
        elif sig in (b"2PSP", b"2BHD"):
            count = u32(data, off + 8)
            d = Directory(sig.decode(), off)
            for i in range(min(count, 32)):
                p = off + 32 + i * 16
                loc = u64(data, p + 8)
                o = _to_offset(loc, n)
                d.entries.append(DirEntry(u32(data, p), 0, 0, loc, o, name="Combo entry %d" % i))
                queue.append(o)
            info.directories.append(d)
    return info


def _parse_dir(data, off, kind, n) -> Directory:
    d = Directory(kind, off)
    count = u32(data, off + 8)
    bios = kind in ("$BHD", "$BL2")
    esize = 24 if bios else 16
    for i in range(min(count, 256)):
        p = off + 16 + i * esize
        if p + esize > n:
            break
        t = data[p]
        sub = data[p + 1] if bios else data[p + 1]
        size = u32(data, p + 4)
        loc = u64(data, p + 8)
        dest = u64(data, p + 16) if bios else None
        o = _to_offset(loc & 0x3FFFFFFFFFFFFFFF, n)
        name = (BIOS_TYPES if bios else PSP_TYPES).get(t, "Type %02Xh" % t)
        d.entries.append(DirEntry(t, sub, size, loc, o, dest, name))
    return d


def describe(info: AmdInfo) -> list[tuple[str, str]]:
    rows = [("EFS offset", "%Xh" % info.efs_offset)]
    for d in info.directories:
        rows.append(("%s directory" % d.kind, "offset %Xh, %d entries" % (d.offset, len(d.entries))))
    return rows
