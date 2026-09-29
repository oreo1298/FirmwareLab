"""UEFI firmware volumes, FFS files and file sections: parsing and reconstruction."""

from __future__ import annotations

import struct
import zlib

from .. import codecs
from ..codecs import tiano
from ..core import guids as G
from ..core.binary import (align_up, checksum8, crc32, is_uniform, p24, p32, size_str, sum16, u16, u24,
                           u32, u64, ucs2_string)
from ..core.guids import guid_db, guid_to_str
from ..core.node import Node, NodeType
from . import pe as pemod

FV_SIGNATURE = b"_FVH"
FV_MIN_HEADER = 0x38

FILE_TYPES = {
    0x00: "All", 0x01: "Raw", 0x02: "Freeform", 0x03: "SEC core", 0x04: "PEI core", 0x05: "DXE core",
    0x06: "PEI module", 0x07: "DXE driver", 0x08: "Combined PEI/DXE", 0x09: "Application",
    0x0A: "MM module", 0x0B: "Volume image", 0x0C: "Combined MM/DXE", 0x0D: "MM core",
    0x0E: "MM standalone", 0x0F: "MM standalone core", 0xF0: "Pad",
}
XIP_FILE_TYPES = {0x03, 0x04, 0x06, 0x08}

SECTION_TYPES = {
    0x01: "Compressed", 0x02: "GUID defined", 0x03: "Disposable", 0x10: "PE32 image", 0x11: "PIC image",
    0x12: "TE image", 0x13: "DXE dependency", 0x14: "Version", 0x15: "UI", 0x16: "Compatibility16",
    0x17: "Volume image", 0x18: "Freeform subtype GUID", 0x19: "Raw", 0x1B: "PEI dependency",
    0x1C: "MM dependency", 0x20: "Insyde postcode", 0xF0: "Phoenix postcode",
}
ENCAPSULATION_SECTIONS = {0x01, 0x02, 0x03, 0x17}

FFS_ALIGN = (1, 16, 128, 512, 1024, 4096, 32768, 65536)
FFS_ALIGN2 = (131072, 262144, 524288, 1048576, 2097152, 4194304, 8388608, 16777216)

FILE_STATE_BITS = (
    (0x20, "Header invalid"), (0x10, "Deleted"), (0x08, "Marked for update"),
    (0x04, "Data valid"), (0x02, "Header valid"), (0x01, "Header construction"),
)

DEPEX_OPCODES = {0x00: "BEFORE", 0x01: "AFTER", 0x02: "PUSH", 0x03: "AND", 0x04: "OR", 0x05: "NOT",
                 0x06: "TRUE", 0x07: "FALSE", 0x08: "END", 0x09: "SOR"}

AMI_ROM_HOLES = {G.str_to_guid("%08X-0FC1-11DC-9011-00173153EBA8" % (0x05CA01FC + i)) for i in range(16)}
NVAR_FILE_GUIDS = {
    G.NVRAM_NVAR_STORE_FILE_GUID, G.NVRAM_NVAR_EXTERNAL_DEFAULTS_FILE_GUID,
    G.NVRAM_NVAR_PEI_EXTERNAL_DEFAULTS_FILE_GUID, G.NVRAM_NVAR_BB_DEFAULTS_FILE_GUID,
}
MICROCODE_FILE_GUIDS = {G.MICROCODE_FILE_GUID, G.MICROCODE_FILE_GUID_2}


def file_type_name(t: int) -> str:
    if t in FILE_TYPES:
        return FILE_TYPES[t]
    if 0xC0 <= t <= 0xDF:
        return "OEM %02Xh" % t
    if 0xE0 <= t <= 0xEF:
        return "Debug %02Xh" % t
    if 0xF0 <= t:
        return "FFS %02Xh" % t
    return "Unknown %02Xh" % t


def section_type_name(t: int) -> str:
    return SECTION_TYPES.get(t, "Unknown %02Xh" % t)


def file_alignment(attrs: int, revision: int = 2) -> int:
    idx = (attrs & 0x38) >> 3
    if revision >= 2 and attrs & 0x02:
        return FFS_ALIGN2[idx]
    return FFS_ALIGN[idx]


def alignment_to_attrs(alignment: int) -> int:
    """Return attribute bits encoding a data alignment (smallest encodable >= alignment)."""
    for i, a in enumerate(FFS_ALIGN):
        if a >= alignment:
            return i << 3
    for i, a in enumerate(FFS_ALIGN2):
        if a >= alignment:
            return (i << 3) | 0x02
    raise ValueError("alignment too large")


def file_state_text(state: int, empty: int) -> str:
    s = state ^ 0xFF if empty == 0xFF else state
    for bit, name in FILE_STATE_BITS:
        if s & bit:
            return name
    return "None"


def depex_text(data) -> str:
    out = []
    i = 0
    db = guid_db()
    while i < len(data):
        op = data[i]
        name = DEPEX_OPCODES.get(op, "UNKNOWN(%02Xh)" % op)
        if op in (0x00, 0x01, 0x02):
            if i + 17 > len(data):
                out.append(name + " <truncated>")
                break
            g = data[i + 1:i + 17]
            out.append("%s %s" % (name, db.display(g)))
            i += 17
        else:
            out.append(name)
            i += 1
            if op == 0x08:
                break
    return "\n".join(out)


# =============================================================================
# Volumes
# =============================================================================

def check_volume(data, pos: int = 0) -> dict | None:
    """Validate an FV header at ``pos``; return its fields or None."""
    if pos + FV_MIN_HEADER + 16 > len(data):
        return None
    if bytes(data[pos + 40:pos + 44]) != FV_SIGNATURE:
        return None
    fv_length = u64(data, pos + 32)
    attrs = u32(data, pos + 44)
    hdr_len = u16(data, pos + 48)
    if hdr_len < FV_MIN_HEADER or hdr_len & 1 or fv_length < hdr_len or hdr_len > 0x10000:
        return None
    return {
        "fs_guid": bytes(data[pos + 16:pos + 32]),
        "fv_length": fv_length,
        "attrs": attrs,
        "hdr_len": hdr_len,
        "checksum": u16(data, pos + 50),
        "ext_off": u16(data, pos + 52),
        "revision": data[pos + 55],
    }


def find_volume(data, start: int = 0) -> int:
    """Offset of the next plausible FV header at or after ``start``, or -1."""
    pos = start
    while True:
        i = bytes(data).find(FV_SIGNATURE, pos + 40) if not isinstance(data, bytes) else data.find(FV_SIGNATURE, pos + 40)
        if i < 0:
            return -1
        vpos = i - 40
        if vpos >= start and check_volume(data, vpos):
            return vpos
        pos = vpos + 1


def parse_volume(ctx, data, offset: int, in_decoded: bool = False) -> Node | None:
    h = check_volume(data, 0)
    if h is None:
        return None
    size = h["fv_length"]
    truncated = False
    if size > len(data):
        truncated = True
        size = len(data)
    raw = data[:size]
    hdr_len = h["hdr_len"]
    attrs = h["attrs"]
    rev = h["revision"]
    fs_guid = h["fs_guid"]
    blocks = []
    p = FV_MIN_HEADER
    while p + 8 <= min(hdr_len, size):
        nb, ln = struct.unpack_from("<II", raw, p)
        p += 8
        if nb == 0 and ln == 0:
            break
        blocks.append((nb, ln))
    checksum_ok = sum16(raw[:hdr_len]) == 0
    empty = 0xFF if attrs & 0x800 else 0x00
    fv_name = None
    ext_size = 0
    files_start = align_up(hdr_len, 8)
    ext_off = h["ext_off"]
    if rev >= 2 and ext_off and ext_off + 20 <= size and ext_off >= hdr_len:
        fv_name = bytes(raw[ext_off:ext_off + 16])
        ext_size = u32(raw, ext_off + 16)
        if ext_off + ext_size <= size and ext_size >= 20:
            files_start = align_up(ext_off + ext_size, 8)
        else:
            fv_name = None
    if files_start > size:
        files_start = min(hdr_len, size)

    if fs_guid in G.FFS3_VOLUMES:
        ffs = 3
    elif fs_guid in G.FFS2_VOLUMES:
        ffs = 2
    else:
        ffs = 0
    db = guid_db()
    if fs_guid in (G.NVRAM_MAIN_STORE_VOLUME_GUID, G.NVRAM_ADDITIONAL_STORE_VOLUME_GUID):
        subtype = "NVRAM"
    elif ffs:
        subtype = "FFSv%d" % ffs
    else:
        subtype = "Unknown"
    node = Node(NodeType.VOLUME, subtype, db.display(fs_guid), db.display(fv_name) if fv_name else "",
                raw, hdr_size=files_start, offset=offset, in_decoded=in_decoded)
    if fv_name:
        node.text = db.display(fv_name)
    alignment = 1 << ((attrs & 0x001F0000) >> 16) if rev >= 2 else 1
    node.meta.update(fs_guid=fs_guid, attrs=attrs, revision=rev, hdr_len=hdr_len, empty=empty,
                     ffs_version=ffs, fv_name=fv_name, ext_off=ext_off if fv_name else 0,
                     ext_size=ext_size, alignment=alignment, blocks=blocks, fv_length=h["fv_length"],
                     truncated=truncated)
    node.add_info("File system GUID", guid_to_str(fs_guid))
    if fv_name:
        node.add_info("Volume name GUID", guid_to_str(fv_name))
    node.add_info("Full size", size_str(h["fv_length"]))
    node.add_info("Header size", size_str(hdr_len))
    node.add_info("Body size", size_str(size - files_start))
    node.add_info("Revision", rev)
    node.add_info("Attributes", "%08Xh" % attrs)
    node.add_info("Erase polarity", "1" if empty == 0xFF else "0")
    node.add_info("Checksum", "%04Xh, %s" % (h["checksum"], "valid" if checksum_ok else "invalid"))
    if rev >= 2:
        node.add_info("Alignment", "%Xh%s" % (alignment, " (weak)" if attrs & 0x80000000 else ""))
    if blocks:
        node.add_info("Block map", ", ".join("%d x %Xh" % b for b in blocks))
    if fv_name:
        node.add_info("Extended header", "offset %Xh, size %Xh" % (ext_off, ext_size))
    if not checksum_ok:
        node.msg("Volume header checksum is invalid")
    if truncated:
        node.msg("Volume size %Xh exceeds available data, volume is truncated" % h["fv_length"])
    total_blocks = sum(nb * ln for nb, ln in blocks)
    if blocks and total_blocks != h["fv_length"]:
        node.msg("Block map size %Xh differs from volume size %Xh" % (total_blocks, h["fv_length"]))

    ctx.depth += 1
    try:
        if ctx.depth > ctx.options.max_depth:
            node.msg("Maximum nesting depth reached")
        elif ffs:
            parse_files(ctx, node)
        elif subtype == "NVRAM" and ctx.options.parse_nvram:
            from . import nvram
            nvram.parse_nvram_area(ctx, node, node.body_view, node.hdr_size, empty)
        elif fs_guid == G.APPLE_MICROCODE_VOLUME_GUID:
            from . import microcode
            microcode.parse_microcode_area(ctx, node, node.body_view, node.hdr_size)
        else:
            node.msg("Unknown file system %s" % guid_to_str(fs_guid))
            body = node.body_view
            if len(body) >= 24 and _plausible_file(body, empty):
                parse_files(ctx, node)
            elif ctx.options.parse_nvram:
                from . import nvram
                nvram.parse_nvram_area(ctx, node, body, node.hdr_size, empty, probe=True)
    finally:
        ctx.depth -= 1
    used = sum(c.size for c in node.children if c.type == NodeType.FILE)
    free = sum(c.size for c in node.children if c.type == NodeType.FREE_SPACE)
    if ffs:
        node.add_info("Used space", size_str(used))
        node.add_info("Free space", size_str(free))
    return node


def _plausible_file(data, empty) -> bool:
    size = u24(data, 20)
    return 24 <= size <= len(data) and data[18] in FILE_TYPES


def volume_address(ctx, node: Node) -> int | None:
    return ctx.address_of(node.abs_offset)


# =============================================================================
# Files
# =============================================================================

def parse_files(ctx, vol: Node) -> None:
    body = vol.body_view
    base = vol.hdr_size
    empty = vol.meta["empty"]
    ffs3 = vol.meta["ffs_version"] == 3
    rev1 = vol.meta["revision"] == 1
    n = len(body)
    pos = 0
    while pos < n:
        rem = body[pos:]
        if is_uniform(rem, empty):
            vol.add(Node(NodeType.FREE_SPACE, "", "Volume free space", "", rem, offset=base + pos))
            break
        if len(rem) < 24:
            _add_nonuefi(vol, rem, base + pos, "Non-UEFI data found in volume's free space")
            break
        hdr = rem[:24]
        if is_uniform(hdr, empty):
            k = 0
            ln = len(rem)
            while k < ln and rem[k] == empty:
                k += 1
            k = k & ~7
            if k:
                vol.add(Node(NodeType.FREE_SPACE, "", "Volume free space", "", rem[:k], offset=base + pos))
            _add_nonuefi(vol, rem[k:], base + pos + k, "Non-UEFI data found in volume's free space")
            break
        size = u24(hdr, 20)
        attrs = hdr[19]
        hsize = 24
        if not rev1 and attrs & 0x01 and (ffs3 or size == 0) and (size in (0, 0xFFFFFF)):
            if len(rem) < 32:
                _add_nonuefi(vol, rem, base + pos, "Truncated large file header")
                break
            size = u64(rem, 24)
            hsize = 32
        if size < hsize or size > len(rem):
            _add_nonuefi(vol, rem, base + pos, "Invalid file size %Xh at volume offset %Xh" % (size, base + pos))
            break
        f = parse_file(ctx, vol, rem[:size], base + pos, hsize)
        vol.add(f)
        pos = align_up(pos + size, 8)
    _check_duplicates(vol)


def _add_nonuefi(parent: Node, data, offset: int, message: str) -> Node:
    node = Node(NodeType.DATA, "Non-UEFI", "Non-UEFI data", "", data, offset=offset)
    node.msg(message)
    parent.add(node)
    return node


def _check_duplicates(vol: Node) -> None:
    seen = {}
    for c in vol.children:
        if c.type != NodeType.FILE or c.meta.get("type") == 0xF0:
            continue
        g = c.meta["guid"]
        if g in seen:
            c.msg("File with duplicate GUID %s" % guid_to_str(g))
        seen[g] = c


def parse_file(ctx, vol: Node | None, raw, offset: int, hsize: int = 24, in_decoded: bool = False) -> Node:
    empty = vol.meta["empty"] if vol is not None else 0xFF
    rev = vol.meta["revision"] if vol is not None else 2
    guid = bytes(raw[0:16])
    hck, fck, ftype, attrs = raw[16], raw[17], raw[18], raw[19]
    state = raw[23]
    tail = 2 if (rev == 1 and attrs & 0x01) else 0
    db = guid_db()
    node = Node(NodeType.FILE, file_type_name(ftype), db.display(guid), "", raw,
                hdr_size=hsize, tail_size=tail, offset=offset, in_decoded=in_decoded)
    alignment = file_alignment(attrs, rev)
    node.meta.update(guid=guid, type=ftype, attrs=attrs, state=state, empty=empty, revision=rev,
                     large=(hsize == 32), alignment=alignment, fixed_checksum=fck)
    body = node.body_view
    calc_h = (0x100 - ((sum(raw[:hsize]) - hck - fck - state) & 0xFF)) & 0xFF
    if attrs & 0x40:
        calc_d = checksum8(body)
    else:
        calc_d = 0x5A if rev == 1 else 0xAA
    node.add_info("File GUID", guid_to_str(guid))
    node.add_info("Type", "%02Xh (%s)" % (ftype, file_type_name(ftype)))
    node.add_info("Attributes", "%02Xh" % attrs)
    node.add_info("Full size", size_str(len(raw)))
    node.add_info("Header size", size_str(hsize))
    node.add_info("Body size", size_str(len(raw) - hsize - tail))
    node.add_info("State", "%02Xh (%s)" % (state, file_state_text(state, empty)))
    node.add_info("Header checksum", "%02Xh, %s" % (hck, "valid" if calc_h == hck else "invalid, should be %02Xh" % calc_h))
    node.add_info("Data checksum", "%02Xh, %s" % (fck, "valid" if calc_d == fck else "invalid, should be %02Xh" % calc_d))
    if alignment > 1:
        node.add_info("Data alignment", "%Xh" % alignment)
        if not in_decoded and (offset + hsize) % alignment:
            node.msg("File data is not aligned to %Xh" % alignment)
    if calc_h != hck:
        node.msg("Invalid file header checksum")
    if calc_d != fck:
        node.msg("Invalid file data checksum")
    if tail:
        t = u16(raw, len(raw) - 2)
        if t != (~u16(raw, 16)) & 0xFFFF:
            node.msg("Invalid file tail")
    if attrs & 0x04 or guid == G.VOLUME_TOP_FILE_GUID:
        node.fixed = True
    if guid == G.VOLUME_TOP_FILE_GUID:
        node.flags.add("vtf")
        node.text = "Volume Top File"
    if guid in (G.PEI_APRIORI_FILE_GUID, G.DXE_APRIORI_FILE_GUID):
        node.text = "PEI apriori file" if guid == G.PEI_APRIORI_FILE_GUID else "DXE apriori file"
    state_bits = state ^ 0xFF if empty == 0xFF else state
    if state_bits & 0x10:
        node.flags.add("deleted")

    ctx.depth += 1
    try:
        _parse_file_body(ctx, node, ftype, guid, body, hsize)
    finally:
        ctx.depth -= 1
    if not node.text:
        _derive_file_text(node)
    return node


def _parse_file_body(ctx, node: Node, ftype: int, guid: bytes, body, hsize: int) -> None:
    empty = node.meta["empty"]
    if ftype == 0xF0:
        if is_uniform(body, empty):
            node.name = "Pad-file"
            node.flags.add("pad")
        else:
            node.name = "Non-empty pad-file"
            node.msg("Non-empty pad file contains data")
            from . import area
            area.parse_raw_area(ctx, node, body, hsize, probe=True)
        return
    if ftype == 0x01 or ftype == 0x00:
        if guid in NVAR_FILE_GUIDS and ctx.options.parse_nvram:
            from . import nvram
            nvram.parse_nvar_store(ctx, node, body, hsize, empty)
            return
        if guid in MICROCODE_FILE_GUIDS:
            from . import microcode
            microcode.parse_microcode_area(ctx, node, body, hsize)
            return
        if guid in AMI_ROM_HOLES:
            node.text = "AMI ROM hole"
            return
        if guid in (G.BOOT_GUARD_AMI_HASH_FILE_GUID, G.BOOT_GUARD_PHOENIX_HASH_FILE_GUID):
            node.text = "Boot Guard vendor hash file"
            ctx.remember("bg_vendor_hash", node)
            return
        # Like UEFITool: try to parse the raw body as sections first, fall back to a raw area.
        if probe_sections(body):
            if parse_sections(ctx, node, body, hsize):
                node.meta["raw_as_sections"] = True
                return
            node.children.clear()
        from . import area
        area.parse_raw_area(ctx, node, body, hsize, probe=True)
        return
    if ftype <= 0x0F or 0xC0 <= ftype <= 0xEF:
        ok = parse_sections(ctx, node, body, hsize)
        if not ok and ftype >= 0xC0:
            node.children.clear()
        return


def _own_sections(node: Node):
    """Sections of a file, descending through encapsulations but not into nested volumes."""
    stack = list(reversed(node.children))
    while stack:
        n = stack.pop()
        if n.type != NodeType.SECTION:
            continue
        yield n
        stack.extend(reversed(n.children))


def _derive_file_text(node: Node) -> None:
    for s in _own_sections(node):
        if s.meta.get("type") == 0x15 and s.meta.get("ui"):
            node.text = s.meta["ui"]
            return
    for s in _own_sections(node):
        pi = s.meta.get("pe")
        if pi is not None and pi.module_name:
            node.text = pi.module_name
            node.meta["text_from_pdb"] = True
            return


# =============================================================================
# Sections
# =============================================================================

def probe_sections(data) -> bool:
    """Quick structural check that data is a valid sequence of sections."""
    pos = 0
    n = len(data)
    count = 0
    while pos < n:
        if n - pos < 4:
            return count > 0 and is_uniform(data[pos:], data[pos])
        size = u24(data, pos)
        stype = data[pos + 3]
        hs = 4
        if size == 0xFFFFFF:
            if n - pos < 8:
                return False
            size = u32(data, pos + 4)
            hs = 8
        if size < hs or pos + size > n:
            rest = data[pos:]
            return count > 0 and (is_uniform(rest, 0) or is_uniform(rest, 0xFF))
        if stype not in SECTION_TYPES:
            return False
        count += 1
        pos = align_up(pos + size, 4)
    return count > 0


def parse_sections(ctx, parent: Node, data, base: int, in_decoded: bool = False) -> bool:
    pos = 0
    n = len(data)
    ok = True
    while pos < n:
        rem = n - pos
        if rem < 4:
            parent.meta["trailing"] = bytes(data[pos:])
            break
        size = u24(data, pos)
        hsize = 4
        if size == 0xFFFFFF and rem >= 8:
            size = u32(data, pos + 4)
            hsize = 8
        if size < hsize or size > rem:
            rest = data[pos:]
            if is_uniform(rest, 0xFF) or is_uniform(rest, 0x00):
                parent.meta["trailing"] = bytes(rest)
            else:
                d = Node(NodeType.DATA, "Invalid", "Invalid section data", "", rest,
                         offset=base + pos, in_decoded=in_decoded)
                d.msg("Section size %Xh at offset %Xh is invalid" % (size, pos))
                parent.add(d)
                ok = False
            break
        sec = parse_section(ctx, data[pos:pos + size], base + pos, hsize, in_decoded)
        parent.add(sec)
        pos = align_up(pos + size, 4)
    return ok


def _undecided_pick(tiano_data, efi_data):
    if probe_sections(tiano_data):
        return tiano_data, codecs.TIANO
    if probe_sections(efi_data):
        return efi_data, codecs.EFI11
    return tiano_data, codecs.TIANO


def parse_section(ctx, raw, offset: int, hsize: int, in_decoded: bool = False) -> Node:
    stype = raw[3]
    name = section_type_name(stype)
    node = Node(NodeType.SECTION, name, name + " section", "", raw, hdr_size=hsize,
                offset=offset, in_decoded=in_decoded)
    node.meta.update(type=stype, ext=(hsize == 8))
    node.add_info("Type", "%02Xh (%s)" % (stype, name))
    node.add_info("Full size", size_str(len(raw)))
    ctx.depth += 1
    try:
        if ctx.depth > ctx.options.max_depth:
            node.msg("Maximum nesting depth reached")
            return node
        _parse_section_body(ctx, node, stype, raw, hsize)
    finally:
        ctx.depth -= 1
    return node


def _decode_into(ctx, node: Node, algorithm: str, decoded: bytes, params: dict | None = None) -> None:
    node.decoded = decoded
    node.meta["algorithm"] = algorithm
    node.meta["params"] = params or {}
    node.add_info("Compression algorithm", algorithm)
    node.add_info("Decompressed size", size_str(len(decoded)))
    parse_sections(ctx, node, memoryview(decoded), 0, in_decoded=True)


def _parse_section_body(ctx, node: Node, stype: int, raw, hsize: int) -> None:
    size = len(raw)
    if stype == 0x01:  # compression
        if size < hsize + 5:
            node.msg("Compressed section header is truncated")
            return
        ulen = u32(raw, hsize)
        ctype = raw[hsize + 4]
        node.hdr_size = hsize + 5
        node.meta.update(uncompressed_length=ulen, compression_type=ctype)
        node.add_info("Compression type", "%02Xh" % ctype)
        node.add_info("Uncompressed length", size_str(ulen))
        body = node.body_view
        if ctype == 0:
            node.meta["algorithm"] = codecs.NONE
            parse_sections(ctx, node, body, node.hdr_size)
            return
        if not ctx.options.decompress:
            return
        try:
            if ctype == 1:
                data, ver, alt = tiano.decompress_auto(body)
                if alt is not None:
                    data, algo = _undecided_pick(data, alt)
                else:
                    algo = codecs.TIANO if ver == tiano.TIANO else codecs.EFI11
                params = {}
            elif ctype == 2:
                try:
                    data = codecs.decompress(codecs.LZMA, body)
                    algo = codecs.LZMA
                    params = codecs.lzma_params(body)
                except codecs.CodecError:
                    data = codecs.decompress(codecs.LZMA_INTEL_LEGACY, body)
                    algo = codecs.LZMA_INTEL_LEGACY
                    params = dict(codecs.lzma_params(bytes(body[4:])), prefix=bytes(body[:4]))
            else:
                node.msg("Unknown compression type %02Xh" % ctype)
                return
        except (codecs.CodecError, tiano.TianoError, ValueError) as e:
            node.msg("Decompression failed: %s" % e)
            return
        if len(data) != ulen:
            node.msg("Decompressed size %Xh differs from header value %Xh" % (len(data), ulen))
        _decode_into(ctx, node, algo, data, params)
        return

    if stype == 0x02:  # GUID defined
        if size < hsize + 20:
            node.msg("GUID defined section header is truncated")
            return
        guid = bytes(raw[hsize:hsize + 16])
        data_off = u16(raw, hsize + 16)
        gattrs = u16(raw, hsize + 18)
        if hsize + 20 <= data_off <= size:
            node.hdr_size = data_off
        else:
            node.hdr_size = hsize + 20
            node.msg("Invalid data offset %Xh in GUID defined section" % data_off)
        db = guid_db()
        node.name = db.display(guid)
        node.meta.update(guid=guid, data_offset=data_off, guid_attrs=gattrs)
        node.add_info("Section GUID", guid_to_str(guid))
        node.add_info("Data offset", "%Xh" % data_off)
        node.add_info("Attributes", "%04Xh" % gattrs)
        body = node.body_view
        try:
            if guid in G.LZMA_SECTION_GUIDS:
                if not ctx.options.decompress:
                    return
                try:
                    data = codecs.decompress(codecs.LZMA, body)
                    _decode_into(ctx, node, codecs.LZMA, data, codecs.lzma_params(body))
                except codecs.CodecError:
                    data = codecs.decompress(codecs.LZMA_INTEL_LEGACY, body)
                    _decode_into(ctx, node, codecs.LZMA_INTEL_LEGACY, data,
                                 dict(codecs.lzma_params(bytes(body[4:])), prefix=bytes(body[:4])))
                return
            if guid == G.SECTION_LZMAF86_GUID:
                if ctx.options.decompress:
                    _decode_into(ctx, node, codecs.LZMAF86, codecs.decompress(codecs.LZMAF86, body),
                                 codecs.lzma_params(body))
                return
            if guid == G.SECTION_TIANO_GUID:
                if ctx.options.decompress:
                    data, ver, alt = tiano.decompress_auto(body)
                    if alt is not None:
                        data, algo = _undecided_pick(data, alt)
                    else:
                        algo = codecs.TIANO if ver == tiano.TIANO else codecs.EFI11
                    _decode_into(ctx, node, algo, data)
                return
            if guid == G.SECTION_BROTLI_GUID:
                if ctx.options.decompress:
                    data = codecs.decompress(codecs.BROTLI, body)
                    scratch = u64(body, 8) if len(body) >= 16 else 0
                    _decode_into(ctx, node, codecs.BROTLI, data, {"scratch_size": scratch})
                return
            if guid == G.SECTION_GZIP_GUID:
                if ctx.options.decompress:
                    _decode_into(ctx, node, codecs.GZIP, codecs.decompress(codecs.GZIP, body))
                return
            if guid in (G.SECTION_ZLIB_AMD_GUID, G.SECTION_ZLIB_AMD2_GUID):
                if ctx.options.decompress:
                    if len(body) > 0x100 and 0x100 + u32(body, 0x14) <= len(body):
                        csize = u32(body, 0x14)
                        data = zlib.decompress(bytes(body[0x100:0x100 + csize]))
                        params = {"amd_header": bytes(body[:0x100])}
                    else:
                        data = zlib.decompress(bytes(body))
                        params = {}
                    node.meta["zlib_amd"] = True
                    _decode_into(ctx, node, codecs.ZLIB, data, params)
                return
            if guid == G.SECTION_CRC32_GUID:
                if node.hdr_size >= hsize + 24:
                    stored = u32(raw, hsize + 20)
                    calc = crc32(body)
                    node.add_info("CRC32", "%08Xh, %s" % (stored, "valid" if stored == calc else "invalid, should be %08Xh" % calc))
                    if stored != calc:
                        node.msg("Invalid CRC32 in GUID defined section")
                node.meta["crc32"] = True
                parse_sections(ctx, node, body, node.hdr_size)
                return
            if guid in (G.FIRMWARE_CONTENTS_SIGNED_GUID, G.CERT_TYPE_RSA2048_SHA256_GUID):
                node.flags.add("signed")
                node.add_info("Signature", "present, modifications will invalidate it")
                parse_sections(ctx, node, body, node.hdr_size)
                return
        except (codecs.CodecError, tiano.TianoError, zlib.error, ValueError) as e:
            node.msg("Decompression failed: %s" % e)
            return
        if gattrs & 0x01:
            node.msg("GUID defined section with unknown processing (%s)" % guid_to_str(guid))
            if probe_sections(body):
                parse_sections(ctx, node, body, node.hdr_size)
            return
        parse_sections(ctx, node, body, node.hdr_size)
        return

    if stype == 0x03:
        parse_sections(ctx, node, node.body_view, node.hdr_size)
        return

    if stype in (0x10, 0x11, 0x12):
        body = node.body_view
        try:
            info = pemod.parse(body)
            node.meta["pe"] = info
            for k, v in pemod.describe(info):
                node.add_info(k, v)
        except (pemod.PeError, struct.error, IndexError) as e:
            if stype != 0x11:
                node.msg("Invalid %s image: %s" % ("TE" if stype == 0x12 else "PE32", e))
        return

    if stype in (0x13, 0x1B, 0x1C):
        txt = depex_text(node.body_view)
        node.meta["depex"] = txt
        node.add_info("Parsed expression", txt.replace("\n", "; "))
        return

    if stype == 0x14:
        if size >= hsize + 2:
            node.hdr_size = hsize + 2
            build = u16(raw, hsize)
            s, _ = ucs2_string(node.body_view)
            node.meta.update(build=build, version=s)
            node.add_info("Build number", build)
            node.add_info("Version string", s)
            node.text = s
        return

    if stype == 0x15:
        s, _ = ucs2_string(node.body_view)
        node.meta["ui"] = s
        node.text = s
        node.add_info("Text", s)
        return

    if stype == 0x17:
        from . import area
        area.parse_raw_area(ctx, node, node.body_view, node.hdr_size)
        return

    if stype == 0x18:
        if size >= hsize + 16:
            node.hdr_size = hsize + 16
            sg = bytes(raw[hsize:hsize + 16])
            node.meta["subtype_guid"] = sg
            node.add_info("Subtype GUID", guid_to_str(sg))
            node.name = guid_db().display(sg)
        return

    if stype == 0x19:
        _parse_raw_section(ctx, node)
        return

    if stype in (0x20, 0xF0):
        if size >= hsize + 4:
            node.hdr_size = hsize + 4
            node.add_info("Postcode", "%Xh" % u32(raw, hsize))
        return


def _parse_raw_section(ctx, node: Node) -> None:
    body = node.body_view
    from . import area
    detected = area.identify_blob(body)
    if detected:
        node.add_info("Contents", detected)
        node.text = detected
    if len(body) >= 0x48 and check_volume(body, 0):
        area.parse_raw_area(ctx, node, body, node.hdr_size)
        return
    if len(body) >= 10 and bytes(body[:4]) == b"NVAR" and ctx.options.parse_nvram:
        from . import nvram
        nvram.parse_nvar_store(ctx, node, body, node.hdr_size, 0xFF)
        return
    parent = node.parent
    if ctx.options.parse_nvram and len(body) > 0x10 and parent is not None and \
            parent.meta.get("guid") == G.PHOENIX_EVSA_RAW_SECTION_GUID:
        from . import nvram
        nvram.parse_nvram_area(ctx, node, body, node.hdr_size, 0xFF, probe=True)


# =============================================================================
# Construction helpers (used by insert operations and the builder)
# =============================================================================

def section_header(stype: int, total_size: int) -> bytes:
    """Common section header; switches to the extended form when needed."""
    if total_size + 4 < 0xFFFFFF:
        return p24(total_size + 4) + bytes([stype])
    return p24(0xFFFFFF) + bytes([stype]) + p32(total_size + 8)


def make_section(stype: int, body: bytes, extra_header: bytes = b"") -> bytes:
    payload_len = len(extra_header) + len(body)
    if payload_len + 4 < 0xFFFFFF:
        hdr = p24(payload_len + 4) + bytes([stype])
    else:
        hdr = p24(0xFFFFFF) + bytes([stype]) + p32(payload_len + 8)
    return hdr + extra_header + body


def make_ui_section(name: str) -> bytes:
    return make_section(0x15, name.encode("utf-16-le") + b"\0\0")


def make_compressed_section(inner: bytes, algorithm: str = codecs.EFI11) -> bytes:
    if algorithm == codecs.NONE:
        ctype, data = 0, inner
    elif algorithm in (codecs.EFI11, codecs.TIANO):
        ctype, data = 1, codecs.compress(algorithm, inner)
    elif algorithm == codecs.LZMA:
        ctype, data = 2, codecs.compress(codecs.LZMA, inner)
    else:
        raise ValueError("Compression section does not support %s" % algorithm)
    return make_section(0x01, data, p32(len(inner)) + bytes([ctype]))


def make_guided_section(guid: bytes, body: bytes, attrs: int = 0x01, extra: bytes = b"") -> bytes:
    hsize_common = 4
    data_offset = hsize_common + 20 + len(extra)
    total = data_offset + len(body)
    if total < 0xFFFFFF:
        hdr = p24(total) + b"\x02"
    else:
        data_offset += 4
        total += 4
        hdr = p24(0xFFFFFF) + b"\x02" + p32(total)
    return hdr + guid + struct.pack("<HH", data_offset, attrs) + extra + body


def join_sections(sections: list[bytes]) -> bytes:
    out = bytearray()
    for s in sections:
        out += bytes(align_up(len(out), 4) - len(out))
        out += s
    return bytes(out)


def make_file(guid: bytes, ftype: int, body: bytes, attrs: int = 0, empty: int = 0xFF,
              revision: int = 2, large_ok: bool = False) -> bytes:
    """Create a complete FFS file with valid checksums and state for the given erase polarity."""
    size = 24 + len(body)
    if size > 0xFFFFFF:
        if not large_ok:
            raise ValueError("File too large for FFSv2 volume (%Xh bytes)" % size)
        size += 8
        hdr = bytearray(guid + b"\0\0" + bytes([ftype, attrs | 0x01]) + p24(0xFFFFFF) + b"\0" + struct.pack("<Q", size))
    else:
        hdr = bytearray(guid + b"\0\0" + bytes([ftype, attrs]) + p24(size) + b"\0")
    finalize_file_header(hdr, body, empty, revision)
    return bytes(hdr) + body


def finalize_file_header(hdr: bytearray, body, empty: int, revision: int = 2, state: int | None = None,
                         fixed_checksum: int | None = None) -> None:
    """Fill IntegrityCheck and State fields of an FFS file header in place."""
    attrs = hdr[19]
    if state is None:
        state = 0x07  # HEADER_CONSTRUCTION | HEADER_VALID | DATA_VALID
        if empty == 0xFF:
            state = (~state) & 0xFF
    hdr[16] = 0
    hdr[17] = 0
    hdr[23] = 0
    hdr[16] = checksum8(hdr)
    if attrs & 0x40:
        hdr[17] = checksum8(body)
    else:
        hdr[17] = fixed_checksum if fixed_checksum in (0xAA, 0x5A) else (0x5A if revision == 1 else 0xAA)
    hdr[23] = state


def make_pad_file(size: int, empty: int = 0xFF, revision: int = 2, guid: bytes | None = None) -> bytes:
    if size < 24:
        raise ValueError("Pad file must be at least 24 bytes")
    body = bytes([empty]) * (size - 24)
    name = guid if guid is not None and len(guid) == 16 else bytes([empty]) * 16
    hdr = bytearray(name + b"\0\0" + b"\xf0\x00" + p24(size) + b"\0")
    finalize_file_header(hdr, body, empty, revision)
    return bytes(hdr) + body
