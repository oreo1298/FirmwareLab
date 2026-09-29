"""Parsing of unstructured areas (BIOS region, padding, raw files) and blob identification."""

from __future__ import annotations

import struct

from ..core import guids as G
from ..core.binary import is_uniform, u32
from ..core.node import Node, NodeType
from . import ffs

VSS2_SIGNATURES = (G.EFI_VARIABLE_GUID, G.EFI_VARIABLE_GUID_2, G.EFI_AUTHENTICATED_VARIABLE_GUID)
FTW_SIGNATURES = (G.EDKII_WORKING_BLOCK_SIGNATURE_GUID, G.VSS2_WORKING_BLOCK_SIGNATURE_GUID)


def padding_subtype(data) -> str:
    if is_uniform(data, 0xFF):
        return "Empty (FFh)"
    if is_uniform(data, 0x00):
        return "Empty (00h)"
    return "Non-empty"


def make_padding(data, offset: int, in_decoded: bool = False) -> Node:
    st = padding_subtype(data)
    node = Node(NodeType.PADDING, st, "Padding", "", data, offset=offset, in_decoded=in_decoded)
    node.add_info("Size", "%Xh (%d)" % (len(data), len(data)))
    return node


def _find_candidates(data):
    """Yield (offset, kind) of recognizable structures in data, sorted by offset."""
    raw = bytes(data)
    out = []
    pos = raw.find(ffs.FV_SIGNATURE, 40)
    while pos >= 0:
        v = pos - 40
        if ffs.check_volume(raw, v):
            out.append((v, "volume"))
        pos = raw.find(ffs.FV_SIGNATURE, pos + 1)
    for sig in (b"$VSS", b"$SVS", b"$NSS"):
        pos = raw.find(sig)
        while pos >= 0:
            if pos + 16 <= len(raw) and raw[pos + 8] == 0x5A:
                out.append((pos, "nvram"))
            pos = raw.find(sig, pos + 1)
    for g in VSS2_SIGNATURES + FTW_SIGNATURES:
        pos = raw.find(g)
        while pos >= 0:
            out.append((pos, "nvram"))
            pos = raw.find(g, pos + 1)
    pos = raw.find(b"_FDC")
    while pos >= 0:
        out.append((pos, "nvram"))
        pos = raw.find(b"_FDC", pos + 1)
    pos = raw.find(b"EVSA")
    while pos >= 0:
        if pos >= 4 and raw[pos - 4] == 0xEC:
            out.append((pos - 4, "nvram"))
        pos = raw.find(b"EVSA", pos + 1)
    # Intel microcode updates: header version 1 + loader revision 1
    pos = raw.find(b"\x01\x00\x00\x00")
    from . import microcode
    while pos >= 0:
        if pos % 16 == 0 and microcode.is_intel_microcode(raw, pos):
            out.append((pos, "microcode"))
        pos = raw.find(b"\x01\x00\x00\x00", pos + 1)
    out.sort()
    return out


def parse_raw_area(ctx, parent: Node, data, base: int, probe: bool = False,
                   in_decoded: bool = False) -> bool:
    """Parse an area into volumes, NVRAM stores, microcode and padding.

    Children are placed at ``base + local offset`` relative to parent. Returns True if
    any structure was recognized.
    """
    from . import microcode, nvram
    n = len(data)
    cands = _find_candidates(data)
    volume_starts = [off for off, kind in cands if kind == "volume"]
    items: list[Node] = []
    pos = 0
    found = False
    for off, kind in cands:
        if off < pos:
            continue
        if kind != "volume" and any(v == off for v in volume_starts):
            continue
        node = None
        if kind == "volume":
            node = ffs.parse_volume(ctx, data[off:], base + off, in_decoded)
        elif kind == "microcode":
            node = microcode.parse_microcode(ctx, data[off:], base + off, in_decoded)
        elif kind == "nvram" and ctx.options.parse_nvram:
            node = nvram.parse_store_at(ctx, data[off:], base + off, 0xFF, in_decoded)
        if node is None or node.size == 0:
            continue
        if kind != "volume" and any(off < v < off + node.size for v in volume_starts):
            continue  # a spurious match must never swallow a real volume
        if off > pos:
            items.append(make_padding(data[pos:off], base + pos, in_decoded))
        items.append(node)
        pos = off + node.size
        found = True
    if probe and not found:
        return False
    if pos < n:
        items.append(make_padding(data[pos:], base + pos, in_decoded))
    for it in items:
        parent.add(it)
    return found


def identify_blob(data) -> str | None:
    """Recognize common payloads stored in raw sections/files."""
    b = bytes(data[:64])
    n = len(data)
    if b[:2] == b"BM" and n >= 26:
        w = struct.unpack_from("<i", b, 18)[0] if n >= 26 else 0
        h = struct.unpack_from("<i", b, 22)[0] if n >= 26 else 0
        return "BMP image %dx%d" % (w, abs(h))
    if b[:8] == b"\x89PNG\r\n\x1a\n" and n >= 24:
        w, h = struct.unpack_from(">II", b, 16)
        return "PNG image %dx%d" % (w, h)
    if b[:3] == b"\xff\xd8\xff":
        return "JPEG image"
    if b[:6] in (b"GIF87a", b"GIF89a") and n >= 10:
        w, h = struct.unpack_from("<HH", b, 6)
        return "GIF image %dx%d" % (w, h)
    if b[:2] == b"\x55\xaa" and n >= 0x1C:
        from . import oprom
        desc = oprom.describe(data)
        if desc:
            return desc
    if b[:4] == b"$VBT":
        return "Intel Video BIOS Table (VBT)"
    if n >= 36 and b[:4] in (b"DSDT", b"SSDT", b"FACP", b"APIC", b"MCFG", b"HPET", b"SLIC", b"MSDM",
                             b"DMAR", b"BGRT", b"FPDT", b"TPM2", b"UEFI", b"WSMT", b"NHLT", b"LPIT"):
        length = u32(b, 4)
        if 36 <= length <= n:
            return "ACPI %s table (OEM '%s')" % (b[:4].decode(), b[10:16].decode("latin-1").strip())
    if b[:4] == b"_SM_" or b[:5] == b"_SM3_":
        return "SMBIOS entry point"
    if b[:4] == b"MZ\x90\x00" or b[:2] == b"MZ":
        return "PE executable"
    if b[:2] == b"VZ":
        return "TE executable"
    if b[:4] == b"NVAR":
        return "AMI NVAR store"
    if b[:4] == b"$VSS":
        return "VSS NVRAM store"
    if n > 0x800 and bytes(data[0x10:0x14]) == b"\x5a\xa5\xf0\x0f":
        return "Intel flash descriptor"
    return None
