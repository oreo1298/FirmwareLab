"""PCI option ROMs (legacy VBIOS/RAID/PXE and EFI drivers such as GOP)."""

from __future__ import annotations

from dataclasses import dataclass

from ..core.binary import u16, u32

CODE_TYPES = {0: "x86 legacy", 1: "Open Firmware", 2: "HP PA-RISC", 3: "EFI"}
EFI_MACHINES = {0x014C: "IA32", 0x8664: "x64", 0x0EBC: "EBC", 0xAA64: "AArch64", 0x0200: "IA64"}
CLASS_NAMES = {0x03: "Display", 0x01: "Mass storage", 0x02: "Network", 0x0C: "Serial bus"}


@dataclass
class RomImage:
    offset: int
    size: int
    vendor: int
    device: int
    class_code: int
    code_type: int
    revision: int
    last: bool
    efi_subsystem: int = 0
    efi_machine: int = 0
    efi_compressed: bool = False

    def describe(self) -> str:
        s = "%04X:%04X %s" % (self.vendor, self.device, CODE_TYPES.get(self.code_type, "type %d" % self.code_type))
        if self.code_type == 3:
            s += " (%s%s)" % (EFI_MACHINES.get(self.efi_machine, "%04Xh" % self.efi_machine),
                              ", compressed" if self.efi_compressed else "")
        return s + ", %d KiB" % (self.size // 1024)


def parse(data) -> list[RomImage]:
    out = []
    pos = 0
    n = len(data)
    for _ in range(16):
        if pos + 0x1A > n or data[pos] != 0x55 or data[pos + 1] != 0xAA:
            break
        pcir = pos + u16(data, pos + 0x18)
        if pcir + 0x18 > n or bytes(data[pcir:pcir + 4]) != b"PCIR":
            break
        vendor = u16(data, pcir + 4)
        device = u16(data, pcir + 6)
        cc = data[pcir + 0x0D] | (data[pcir + 0x0E] << 8) | (data[pcir + 0x0F] << 16)
        length = u16(data, pcir + 0x10) * 512
        rev = u16(data, pcir + 0x12)
        ctype = data[pcir + 0x14]
        last = bool(data[pcir + 0x15] & 0x80)
        img = RomImage(pos, length, vendor, device, cc, ctype, rev, last)
        if ctype == 3 and u32(data, pos + 4) == 0x0EF1:
            img.efi_subsystem = u16(data, pos + 8)
            img.efi_machine = u16(data, pos + 10)
            img.efi_compressed = u16(data, pos + 12) == 1
        out.append(img)
        if last or length == 0:
            break
        pos += length
    return out


def describe(data) -> str | None:
    try:
        imgs = parse(data)
    except Exception:
        return None
    if not imgs:
        return None
    cls = CLASS_NAMES.get(imgs[0].class_code >> 16, "")
    return "PCI option ROM%s: %s" % (" (%s)" % cls if cls else "", "; ".join(i.describe() for i in imgs))
