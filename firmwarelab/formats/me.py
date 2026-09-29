"""Intel ME / CSME region: flash partition table ($FPT) and version detection."""

from __future__ import annotations

import struct

from ..core.binary import is_uniform, size_str, u16, u32
from ..core.node import Node, NodeType

PARTITION_TYPES = {0: "Code", 1: "Data", 2: "NVRAM", 3: "Generic", 4: "EFFS", 5: "ROM"}

KNOWN_PARTITIONS = {
    "FTPR": "Fault tolerant partition (main firmware)", "NFTP": "Non fault tolerant partition",
    "MDMV": "Media DRM", "DLMP": "IDLM", "FTUP": "Firmware update", "MFS": "ME file system",
    "EFFS": "Embedded flash file system", "ROMB": "ROM bypass", "WCOD": "WLAN microcode",
    "LOCL": "Localization", "PSVN": "Secure version numbers", "UTOK": "Unlock token",
    "ISHC": "Integrated sensor hub", "IUNP": "IUnit", "FLOG": "Flash log", "UEPB": "UEP",
    "GLUT": "GLUT", "BIAL": "BIAL", "OPR": "Operational", "SCA": "SCA", "FITC": "FIT config",
    "RCVY": "Recovery", "BTGP": "Boot Guard", "CSE": "CSE", "IVBP": "IVB", "PMCP": "PMC firmware",
    "PCHC": "PCH config", "IOMP": "IOM firmware", "TBTP": "Thunderbolt firmware", "PHYP": "PHY firmware",
    "PSEP": "PSE firmware", "NPHY": "NPHY firmware", "SAMF": "SAM firmware", "GTGP": "GTGP", "DPHY": "DPHY",
}


def find_fpt(data) -> int:
    for off in (0x10, 0x0):
        if len(data) >= off + 0x20 and bytes(data[off:off + 4]) == b"$FPT":
            return off
    return -1


def me_version(data) -> tuple[int, int, int, int] | None:
    raw = bytes(data)
    for sig in (b"$MN2", b"$MAN"):
        p = raw.find(sig)
        while p >= 0:
            if p + 16 <= len(raw):
                major, minor, hotfix, build = struct.unpack_from("<HHHH", raw, p + 8)
                if 0 < major < 100 and minor < 100 and build < 0x8000:
                    return major, minor, hotfix, build
            p = raw.find(sig, p + 1)
    return None


BPDT_TYPES = [
    "SMIP", "RBEP", "FTPR", "UCOD", "IBBP", "S-BPDT", "OBBP", "NFTP", "ISHC", "DLMP", "UEBP", "UTOK",
    "UFS PHY", "UFS GPP", "PMCP", "IUNP", "NVMC", "UEP", "WCOD", "LOCL", "OEMP", "FITC", "PAVP", "IOMP",
    "XPHY", "TBTP", "PLTS", "RES27", "RES28", "RES29", "RES30", "DPHY", "PCHC", "ISIF", "ISIC", "HBMI",
    "OMSM", "GTGP", "MDFI", "PUNP", "PHYP", "SAMF", "PPHY", "GBST", "TCCP", "PSEP", "EFWP",
]


def _ifwi_layout(data) -> list[tuple[str, int, int]] | None:
    """Detect an IFWI 1.6/1.7 layout header after the ROM bypass vector."""
    if len(data) < 0x60:
        return None
    parts = []
    if u16(data, 0x10) == 0x40:  # IFWI 1.7
        entries = [("Data partition", 0x18)] + [("Boot partition %d" % (i + 1), 0x20 + i * 8) for i in range(5)]
    else:  # IFWI 1.6
        entries = [("Data partition", 0x10)] + [("Boot partition %d" % (i + 1), 0x18 + i * 8) for i in range(5)]
    for name, p in entries:
        off, size = u32(data, p), u32(data, p + 4)
        if size == 0 or off == 0:
            continue
        if off + size > len(data) or off < 0x40:
            return None
        parts.append((name, off, size))
    if not parts or not any(n.startswith("Boot") for n, _, _ in parts):
        return None
    return sorted(parts, key=lambda x: x[1])


def _describe_bpdt(node: Node, data) -> None:
    sig = u32(data, 0)
    if sig not in (0x55AA, 0xAA55AA):
        return
    count = u16(data, 4)
    node.add_info("BPDT", "%s, %d entries" % ("green" if sig == 0x55AA else "yellow", count))
    fitc = struct.unpack_from("<HHHH", data, 16)
    if any(fitc):
        node.add_info("FITC version", "%d.%d.%d.%d" % fitc)
    for i in range(min(count, 64)):
        p = 24 + i * 12
        if p + 12 > len(data):
            break
        t = u16(data, p)
        off, size = u32(data, p + 4), u32(data, p + 8)
        name = BPDT_TYPES[t] if t < len(BPDT_TYPES) else "Type %d" % t
        if size:
            node.add_info("  %s" % name, "offset %Xh, size %Xh" % (off, size))


def _parse_ifwi(ctx, region: Node, data, base: int, layout) -> None:
    items = []
    pos = 0
    if len(data) >= 0x10:
        items.append(_data_node(data[:0x10], base, "ROM bypass vector", "ROM bypass"))
        items.append(_data_node(data[0x10:0x60], base + 0x10, "IFWI layout header", "IFWI header"))
        pos = 0x60
    for name, off, size in layout:
        if off < pos:
            continue
        if off > pos:
            items.append(_pad(data[pos:off], base + pos))
        pn = Node(NodeType.ME, "IFWI partition", name, "", data[off:off + size], offset=base + off)
        pn.add_info("Offset", "%Xh" % off)
        pn.add_info("Size", size_str(size))
        _describe_bpdt(pn, pn.raw)
        if name == "Data partition":
            fpt = find_fpt(pn.raw) if bytes(pn.raw[:4]) != b"$FPT" else 0
            if fpt >= 0:
                pn.add_info("Contents", "flash partition table ($FPT)")
        items.append(pn)
        pos = off + size
    if pos < len(data):
        items.append(_pad(data[pos:], base + pos))
    for it in items:
        region.add(it)
    region.add_info("Layout", "IFWI (CSME 12+)" if u16(data, 0x10) == 0x40 else "IFWI 1.6")


def parse_me_region(ctx, region: Node) -> None:
    data = region.body_view
    base = region.hdr_size
    if is_uniform(data):
        region.add_info("State", "empty (%02Xh)" % data[0] if len(data) else "empty")
        region.msg("ME region is empty")
        return
    fpt = find_fpt(data)
    if fpt < 0:
        layout = _ifwi_layout(data)
        if layout:
            _parse_ifwi(ctx, region, data, base, layout)
        else:
            region.msg("ME partition table ($FPT) not found")
        v = me_version(data)
        if v:
            region.add_info("ME version", "%d.%d.%d.%d" % v)
            region.meta["me_version"] = v
            region.text = "v%d.%d.%d.%d" % v
        return
    count = u32(data, fpt + 4)
    hver = data[fpt + 8]
    hlen = 0x20  # entries always follow the 32-byte header (HeaderLength counts the ROM bypass)
    if count > 128:
        region.msg("Implausible FPT entry count %d" % count)
        return
    entries_off = fpt + hlen
    table_end = entries_off + count * 32
    if table_end > len(data):
        region.msg("FPT entries exceed region size")
        return
    parts = []
    for i in range(count):
        e = entries_off + i * 32
        rawname = bytes(data[e:e + 4]).rstrip(b"\0\xff")
        name = rawname.decode("ascii") if rawname and all(32 < c < 127 for c in rawname) else "?%s" % rawname.hex().upper()
        owner = bytes(data[e + 4:e + 8])
        off = u32(data, e + 8)
        size = u32(data, e + 12)
        attrs = u32(data, e + 28)
        ptype = attrs & 0x7F
        valid = (attrs >> 24) & 0xFF
        parts.append((name, owner, off, size, ptype, valid))
    region.meta["fpt"] = {"offset": fpt, "version": hver, "entries": parts}
    region.add_info("FPT version", "%02Xh" % hver)
    region.add_info("FPT partitions", str(count))
    if hlen >= 0x20:
        fitc = struct.unpack_from("<HHHH", data, fpt + 24)
        if any(fitc):
            region.add_info("FITC version", "%d.%d.%d.%d" % fitc)
    # Build tiled children: [bypass] FPT table, partitions, padding
    items = []
    cursor = 0
    if fpt > 0:
        items.append(_data_node(data[:fpt], base, "ROM bypass vector", "ROM bypass"))
    table_node = Node(NodeType.ME, "FPT", "Flash partition table", "%d entries" % count,
                      data[fpt:table_end], hdr_size=hlen, offset=base + fpt)
    items.append(table_node)
    cursor = table_end
    usable = sorted(
        [p for p in parts if p[3] and p[2] not in (0, 0xFFFFFFFF) and p[2] + p[3] <= len(data) and p[5] != 0xFF],
        key=lambda p: p[2])
    for name, owner, off, size, ptype, valid in usable:
        if off < cursor:
            continue
        if off > cursor:
            items.append(_pad(data[cursor:off], base + cursor))
        pn = Node(NodeType.ME, "Partition", name, KNOWN_PARTITIONS.get(name, ""), data[off:off + size],
                  offset=base + off)
        pn.add_info("Partition name", name)
        pn.add_info("Type", PARTITION_TYPES.get(ptype, "%Xh" % ptype))
        pn.add_info("Offset", "%Xh" % off)
        pn.add_info("Size", size_str(size))
        if name in ("FTPR", "NFTP", "RCVY", "OPR1", "OPR2"):
            v = me_version(pn.raw)
            if v:
                pn.add_info("Version", "%d.%d.%d.%d" % v)
        if bytes(pn.raw[:4]) == b"$CPD":
            pn.add_info("Format", "CSE code partition directory ($CPD)")
        items.append(pn)
        cursor = off + size
    if cursor < len(data):
        items.append(_pad(data[cursor:], base + cursor))
    for it in items:
        region.add(it)
    ftpr = next((p for p in usable if p[0] == "FTPR"), None)
    v = me_version(data[ftpr[2]:ftpr[2] + ftpr[3]]) if ftpr else me_version(data)
    if v:
        region.meta["me_version"] = v
        region.add_info("ME version", "%d.%d.%d.%d" % v)
        region.text = "v%d.%d.%d.%d" % v


def _data_node(data, offset, name, subtype):
    return Node(NodeType.ME, subtype, name, "", data, offset=offset)


def _pad(data, offset):
    from .area import make_padding
    return make_padding(data, offset)
