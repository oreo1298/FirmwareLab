"""Human-readable and machine-readable reports of a parsed image."""

from __future__ import annotations

import json

from ..core.binary import crc32, human_size
from ..core.node import Node, NodeType

TYPE_ABBR = {
    NodeType.IMAGE: "Image", NodeType.CAPSULE: "Capsule", NodeType.REGION: "Region",
    NodeType.PADDING: "Padding", NodeType.VOLUME: "Volume", NodeType.FILE: "File",
    NodeType.SECTION: "Section", NodeType.FREE_SPACE: "Free space", NodeType.NVRAM_STORE: "NVRAM store",
    NodeType.NVRAM_VARIABLE: "NVRAM var", NodeType.MICROCODE: "Microcode", NodeType.ME: "ME",
    NodeType.FIT: "FIT", NodeType.AMD: "AMD", NodeType.OPTION_ROM: "OptROM", NodeType.DATA: "Data",
    NodeType.BOOT_GUARD: "BootGuard",
}


def report_text(root: Node, verbose: bool = False) -> str:
    lines = ["%-20s | %-22s | %-8s | %-8s | %-8s | Name" %
             ("Type", "Subtype", "Base", "Size", "CRC32"),
             "-" * 100]

    def walk(n: Node, depth: int):
        off = n.abs_offset
        base = "%08X" % off if off is not None else "  N/A   "
        data = n.content if n.decoded is not None else n.data
        lines.append("%-20s | %-22s | %s | %08X | %08X | %s%s" % (
            TYPE_ABBR.get(n.type, n.type.value), n.subtype[:22], base, n.size, crc32(data),
            "-" * depth + (" " if depth else ""), n.display_name))
        for c in n.children:
            walk(c, depth + 1)

    walk(root, 0)
    return "\n".join(lines)


def _node_dict(n: Node, include_info: bool) -> dict:
    off = n.abs_offset
    d = {
        "type": n.type.value,
        "subtype": n.subtype,
        "name": n.name,
        "text": n.text,
        "offset": off,
        "address": n.meta.get("address"),
        "size": n.size,
        "header_size": n.hdr_size,
        "body_size": n.body_size,
        "flags": sorted(n.flags),
    }
    if n.meta.get("guid"):
        from ..core.guids import guid_to_str
        d["guid"] = guid_to_str(n.meta["guid"])
    if n.meta.get("algorithm"):
        d["compression"] = n.meta["algorithm"]
    if n.messages:
        d["messages"] = list(n.messages)
    if include_info and n.info:
        d["info"] = {k: v for k, v in n.info}
    if n.children:
        d["children"] = [_node_dict(c, include_info) for c in n.children]
    return d


def report_json(root: Node, include_info: bool = True) -> str:
    return json.dumps(_node_dict(root, include_info), indent=2)


def summary(root: Node, ctx=None) -> str:
    counts: dict = {}
    for n in root.walk():
        counts[n.type] = counts.get(n.type, 0) + 1
    lines = ["FirmwareLab image summary", "=" * 40,
             "Total size: %s (%s)" % ("%Xh" % root.size, human_size(root.size)),
             "Total items: %d" % root.count(), ""]
    for t, c in sorted(counts.items(), key=lambda kv: kv[1], reverse=True):
        lines.append("  %-16s %d" % (TYPE_ABBR.get(t, t.value), c))
    files = [n for n in root.walk() if n.type == NodeType.FILE and "pad" not in n.flags]
    named = [f for f in files if f.text]
    lines += ["", "Named modules: %d / %d files" % (len(named), len(files))]
    ucodes = [n for n in root.walk() if n.type == NodeType.MICROCODE]
    if ucodes:
        lines.append("")
        lines.append("Microcode updates:")
        for u in ucodes:
            i = u.meta.get("ucode")
            if i:
                lines.append("  CPUID %08Xh rev %Xh (%s) %s" % (i.signature, i.revision, i.cpu_name, i.date))
    if ctx is not None:
        if ctx.fit is not None:
            lines += ["", "FIT: %d entries" % len(ctx.fit.entries)]
            bg = ctx.fit.bootguard
            if bg.km_present or bg.bpm_present:
                lines.append("Boot Guard: KM=%s BPM=%s, %d IBB segment(s)" % (
                    bg.km_present, bg.bpm_present, sum(1 for s in bg.ibb_segments if s.is_ibb)))
        if ctx.vendor_hints:
            lines.append("Vendor hints: %s" % ", ".join(sorted(ctx.vendor_hints)))
    msgs = [(n, m) for n in root.walk() for m in n.messages]
    if msgs:
        lines += ["", "Warnings: %d" % len(msgs)]
        for n, m in msgs[:30]:
            lines.append("  %s: %s" % (n.display_name, m))
    return "\n".join(lines)
