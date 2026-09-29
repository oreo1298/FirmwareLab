"""Top level image parsing: capsules, Intel images with descriptor, UEFI/AMD images."""

from __future__ import annotations

import os

from ..core.binary import human_size, size_str
from ..core.node import Node, NodeType
from . import amd, area, capsule, descriptor, ffs, fit, gbe, me
from . import pe as pemod
from .context import ParseContext, ParseOptions, ProtectedRange


def parse_image(data, name: str = "", options: ParseOptions | None = None) -> tuple[Node, ParseContext]:
    """Parse a firmware file. Returns (root node, parse context with analysis results)."""
    data = bytes(data)
    ctx = ParseContext(options)
    ctx.image_size = len(data)
    mv = memoryview(data)
    cap = capsule.detect(mv)
    if cap is not None and cap.header_size < len(data):
        root = Node(NodeType.CAPSULE, cap.kind, name or cap.kind, "", mv, hdr_size=cap.header_size)
        for k, v in cap.rows:
            root.add_info(k, v)
        root.meta["capsule"] = cap
        body = root.body_view
        if cap.guid == capsule.G.EFI_FMP_CAPSULE_GUID:
            payloads = capsule.parse_fmp(mv, cap.header_size)
            root.meta["fmp"] = payloads
            for k, v in capsule.describe_fmp(payloads):
                root.add_info(k, v)
            area.parse_raw_area(ctx, root, body, cap.header_size)
        else:
            img = _parse_image_body(ctx, body, cap.header_size, "Image")
            root.add(img)
    else:
        root = _parse_image_body(ctx, mv, 0, name or "Image")
        if name:
            root.name = name
    root.meta["file_name"] = name
    _post_process(ctx, root, data)
    return root, ctx


def parse_file(path: str, options: ParseOptions | None = None) -> tuple[Node, ParseContext]:
    with open(path, "rb") as fh:
        data = fh.read()
    return parse_image(data, os.path.basename(path), options)


def _parse_image_body(ctx, data, offset: int, name: str) -> Node:
    if descriptor.find_descriptor(data) == 0:
        try:
            return _parse_intel_image(ctx, data, offset, name)
        except ValueError as e:
            node = _parse_uefi_image(ctx, data, offset, name)
            node.msg("Flash descriptor found but could not be parsed: %s" % e)
            return node
    return _parse_uefi_image(ctx, data, offset, name)


def _parse_uefi_image(ctx, data, offset: int, name: str) -> Node:
    node = Node(NodeType.IMAGE, "UEFI", name, "UEFI image", data, offset=offset)
    ctx.map_start = offset
    ctx.map_end = offset + len(data)
    amd_info = amd.parse(data)
    if amd_info is not None:
        node.subtype = "AMD"
        node.text = "AMD image"
        node.meta["amd"] = amd_info
        ctx.vendor_hints.add("AMD")
        for k, v in amd.describe(amd_info):
            node.add_info(k, v)
    node.add_info("Full size", size_str(len(data)))
    area.parse_raw_area(ctx, node, data, 0)
    return node


def _parse_intel_image(ctx, data, offset: int, name: str) -> Node:
    desc = descriptor.parse(data, 0)
    node = Node(NodeType.IMAGE, "Intel", name, "Intel image", data, offset=offset)
    node.meta["descriptor"] = desc
    size = len(data)
    regions = [r for r in desc.regions if r.used]
    bios = [r for r in regions if r.name == "BIOS"]
    me_r = next((r for r in regions if r.name == "ME"), None)
    # Gigabyte style descriptors describe BIOS as covering the whole image
    if bios and bios[0].size == size and me_r is not None:
        b = bios[0]
        b.offset = me_r.end
        b.size = size - b.offset
        node.msg("Gigabyte-style descriptor: BIOS region start derived from ME region end")
    placed = []
    for r in sorted(regions, key=lambda r: r.offset):
        if r.offset >= size:
            node.msg("%s region at %Xh is outside of the image (dual-chip storage or truncated dump?)" % (r.name, r.offset))
            continue
        if r.end > size:
            node.msg("%s region is truncated: ends at %Xh, image size %Xh" % (r.name, r.end, size))
        if placed and r.offset < placed[-1].end:
            node.msg("%s region overlaps %s region" % (r.name, placed[-1].name))
            continue
        placed.append(r)
    pos = 0
    for r in placed:
        if r.offset > pos:
            node.add(area.make_padding(data[pos:r.offset], pos))
        end = min(r.end, size)
        reg = Node(NodeType.REGION, r.name, "%s region" % r.name, "", data[r.offset:end], offset=r.offset)
        reg.meta["region"] = r
        reg.add_info("Offset", "%Xh" % r.offset)
        reg.add_info("Size", "%s, %s" % (size_str(end - r.offset), human_size(end - r.offset)))
        node.add(reg)
        _parse_region(ctx, reg, desc)
        pos = end
    if pos < size:
        node.add(area.make_padding(data[pos:], pos))
    for k, v in descriptor.describe(desc):
        node.add_info(k, v)
    return node


def _parse_region(ctx, reg: Node, desc) -> None:
    name = reg.subtype
    if name == "Descriptor":
        reg.fixed = True
        for k, v in descriptor.describe(desc):
            reg.add_info(k, v)
        return
    if name in ("BIOS", "BIOS2"):
        if name == "BIOS" or ctx.map_end is None:
            ctx.map_start = reg.abs_offset if reg.abs_offset is not None else reg.offset
            ctx.map_start = reg.offset + (reg.parent.offset if reg.parent else 0)
            ctx.map_end = ctx.map_start + reg.size
        area.parse_raw_area(ctx, reg, reg.body_view, 0)
        return
    if name == "ME":
        me.parse_me_region(ctx, reg)
        return
    if name == "GbE":
        gbe.parse_gbe_region(ctx, reg)
        return
    body = reg.body_view
    if len(body) and not area.is_uniform(body):
        area.parse_raw_area(ctx, reg, body, 0, probe=True)
    else:
        reg.add_info("State", "empty")


# =============================================================================
# Post-processing: XIP detection, FIT, Boot Guard, summaries
# =============================================================================

def _post_process(ctx: ParseContext, root: Node, data: bytes) -> None:
    _detect_xip(ctx, root)
    try:
        table = fit.parse(ctx, data)
    except Exception as e:  # never let analysis break parsing
        table = None
        root.msg("FIT parsing failed: %s" % e)
    if table is not None:
        ctx.fit = table
        root.meta["fit"] = table
        for m in table.messages + table.bootguard.messages:
            root.msg(m)
        bg = table.bootguard
        for s in bg.ibb_segments:
            if s.is_ibb:
                off = ctx.offset_of_address(s.base)
                if off is not None:
                    ctx.protected.append(ProtectedRange(off, off + s.size, "Boot Guard IBB"))
        for base, size in bg.vendor_ranges:
            off = ctx.offset_of_address(base)
            if off is not None:
                ctx.protected.append(ProtectedRange(off, off + size, "Boot Guard vendor hash"))
        if ctx.protected:
            _mark_protected(ctx, root)
    _vendor_hints(ctx, root, data)
    root.meta["context"] = ctx


def _detect_xip(ctx: ParseContext, root: Node) -> None:
    for n in root.walk():
        if n.type != NodeType.SECTION or "pe" not in n.meta:
            continue
        f = n.find_ancestor(NodeType.FILE)
        if f is None or f.meta.get("type") not in ffs.XIP_FILE_TYPES:
            continue
        body_abs = n.abs_offset
        if body_abs is None:
            continue
        addr = ctx.address_of(body_abs + n.hdr_size)
        if addr is None:
            continue
        info: pemod.PeInfo = n.meta["pe"]
        expected = pemod.expected_xip_base(info, addr)
        n.meta["address"] = addr
        n.add_info("Memory address", "%08Xh" % addr)
        if info.image_base == expected:
            n.flags.add("xip")
            n.add_info("Execute in place", "yes (image base matches flash address)")
            for a in n.ancestors():
                a.flags.add("has_xip")
            if f.meta.get("type") == 0x04:
                ctx.remember("pei_core_section", n)
        else:
            n.add_info("Execute in place", "no (image base %Xh, flash address based %Xh)" % (info.image_base, expected))
    for n in root.walk():
        if n.type in (NodeType.VOLUME, NodeType.FILE) and not n.in_decoded:
            addr = ctx.address_of(n.abs_offset)
            if addr is not None:
                n.meta["address"] = addr


def _mark_protected(ctx: ParseContext, root: Node) -> None:
    ranges = ctx.protected
    for n in root.walk():
        if n.type in (NodeType.IMAGE, NodeType.CAPSULE) or n.in_decoded:
            continue
        a = n.abs_offset
        if a is None:
            continue
        e = a + n.size
        for r in ranges:
            if a < r.end and r.start < e:
                if n.type not in (NodeType.REGION,) or (a >= r.start and e <= r.end):
                    n.flags.add("protected")
                    n.meta.setdefault("protected_by", set()).add(r.label)


def _vendor_hints(ctx: ParseContext, root: Node, data: bytes) -> None:
    raw = data
    if b"$FID" in raw or b"AMITSE" in raw or ctx.findings.get("nvar_store"):
        ctx.vendor_hints.add("AMI")
    if b"$BVDT$" in raw or b"InsydeH2O" in raw or b"_FDC" in raw:
        ctx.vendor_hints.add("Insyde")
    if b"$FLASH_MAP" in raw or b"Phoenix" in raw:
        ctx.vendor_hints.add("Phoenix")
    if b"OVMF" in raw or b"EDK II" in raw:
        ctx.vendor_hints.add("EDK II")
    if ctx.vendor_hints:
        root.add_info("Vendor hints", ", ".join(sorted(ctx.vendor_hints)))
