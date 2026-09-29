"""Firmware update capsules: UEFI, FMP, AMI Aptio, Toshiba."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from ..core import guids as G
from ..core.binary import size_str, u16, u32, u64
from ..core.guids import guid_db, guid_to_str

EFI_LIKE = {
    G.EFI_CAPSULE_GUID: "UEFI capsule",
    G.INTEL_CAPSULE_GUID: "Intel capsule",
    G.LENOVO_CAPSULE_GUID: "Lenovo capsule",
    G.LENOVO2_CAPSULE_GUID: "Lenovo capsule",
}


@dataclass
class CapsuleInfo:
    kind: str
    guid: bytes
    header_size: int
    image_size: int
    flags: int
    rows: list

    @property
    def body_range(self) -> tuple[int, int]:
        return self.header_size, self.image_size


def detect(data) -> CapsuleInfo | None:
    """Recognize a capsule header at the start of data."""
    if len(data) < 28:
        return None
    g = bytes(data[:16])
    if g in (G.APTIO_SIGNED_CAPSULE_GUID, G.APTIO_UNSIGNED_CAPSULE_GUID):
        hs, flags, total = struct.unpack_from("<III", data, 16)
        rom_off = u16(data, 28)
        if not (0 < rom_off <= len(data)) or hs == 0 or hs > total:
            return None
        signed = g == G.APTIO_SIGNED_CAPSULE_GUID
        total = min(total, len(data)) if total >= rom_off else len(data)
        rows = [("Capsule GUID", guid_to_str(g)), ("Type", "AMI Aptio %s capsule" % ("signed" if signed else "unsigned")),
                ("Header size", size_str(hs)), ("Flags", "%08Xh" % flags), ("Image size", size_str(total)),
                ("ROM image offset", "%Xh" % rom_off), ("ROM layout offset", "%Xh" % u16(data, 30))]
        return CapsuleInfo("AMI Aptio %s capsule" % ("signed" if signed else "unsigned"), g, rom_off,
                           len(data), flags, rows)
    if g == G.TOSHIBA_CAPSULE_GUID:
        hs, full, flags = struct.unpack_from("<III", data, 16)
        if hs == 0 or hs > len(data) or full > len(data) or hs > full:
            return None
        rows = [("Capsule GUID", guid_to_str(g)), ("Type", "Toshiba capsule"), ("Header size", size_str(hs)),
                ("Full size", size_str(full)), ("Flags", "%08Xh" % flags)]
        return CapsuleInfo("Toshiba capsule", g, hs, full, flags, rows)
    if g in EFI_LIKE or g == G.EFI_FMP_CAPSULE_GUID:
        hs, flags, total = struct.unpack_from("<III", data, 16)
        if hs < 28 or hs > len(data) or total < hs or total > len(data) + 0x1000:
            return None
        total = min(total, len(data))
        kind = "FMP capsule" if g == G.EFI_FMP_CAPSULE_GUID else EFI_LIKE[g]
        rows = [("Capsule GUID", guid_to_str(g)), ("Type", kind), ("Header size", size_str(hs)),
                ("Flags", "%08Xh" % flags), ("Image size", size_str(total))]
        return CapsuleInfo(kind, g, hs, total, flags, rows)
    return None


@dataclass
class FmpPayload:
    index: int
    offset: int
    size: int
    image_type_id: bytes
    image_index: int
    image_size: int
    vendor_code_size: int
    hardware_instance: int
    auth_size: int

    @property
    def image_offset(self) -> int:
        return self.offset + self.header_size + self.auth_size

    header_size: int = 0


def parse_fmp(data, header_size: int) -> list[FmpPayload]:
    """Parse EFI_FIRMWARE_MANAGEMENT_CAPSULE_HEADER and its payload items."""
    base = header_size
    if base + 8 > len(data):
        return []
    version, drivers, payloads = struct.unpack_from("<IHH", data, base)
    if version != 1 or drivers + payloads > 64:
        return []
    offs = [u64(data, base + 8 + i * 8) for i in range(drivers + payloads)]
    out = []
    for i, off in enumerate(offs[drivers:]):
        p = base + off
        if p + 32 > len(data):
            continue
        ver = u32(data, p)
        tid = bytes(data[p + 4:p + 20])
        idx = data[p + 20]
        isize, vsize = struct.unpack_from("<II", data, p + 24)
        hw = u64(data, p + 32) if ver >= 2 and p + 40 <= len(data) else 0
        hsize = 40 if ver == 2 else (48 if ver >= 3 else 32)
        auth = 0
        img = p + hsize
        # EFI_FIRMWARE_IMAGE_AUTHENTICATION: MonotonicCount(8) + WIN_CERTIFICATE_UEFI_GUID
        if img + 24 <= len(data):
            cert_len = u32(data, img + 8)
            cert_type = u16(data, img + 14)
            if cert_type == 0x0EF1 and 24 <= cert_len < isize:
                auth = 8 + cert_len
        out.append(FmpPayload(i, p, isize, tid, idx, isize, vsize, hw, auth, hsize))
    return out


def describe_fmp(payloads: list[FmpPayload]) -> list[tuple[str, str]]:
    db = guid_db()
    rows = []
    for p in payloads:
        rows.append(("Payload %d" % p.index, "%s, image %Xh bytes%s" % (
            db.display(p.image_type_id), p.image_size, ", authenticated" if p.auth_size else "")))
    return rows
