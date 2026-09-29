"""NVRAM variable stores: EDK2 VSS/VSS2, FTW, Insyde FDC, Phoenix EVSA and AMI NVAR.

Variable nodes use header = variable header + name, body = variable data,
tail = trailing extension (NVAR extended header), so replacing a variable's
body edits its value.
"""

from __future__ import annotations

import struct

from ..core import guids as G
from ..core.binary import align_up, crc32, is_uniform, size_str, u16, u24, u32, u64, ucs2_string
from ..core.guids import guid_db, guid_to_str
from ..core.node import Node, NodeType

VSS_SIGNATURES = {b"$VSS": "VSS store", b"$SVS": "Apple SVS store", b"$NSS": "Apple NSS store"}
VSS2_GUIDS = {
    G.EFI_VARIABLE_GUID: "VSS2 store",
    G.EFI_VARIABLE_GUID_2: "VSS2 store",
    G.EFI_AUTHENTICATED_VARIABLE_GUID: "VSS2 authenticated store",
}
FTW_GUIDS = (G.EDKII_WORKING_BLOCK_SIGNATURE_GUID, G.VSS2_WORKING_BLOCK_SIGNATURE_GUID)

# VSS attributes
VAR_ATTRS = [
    (0x01, "NV"), (0x02, "BS"), (0x04, "RT"), (0x08, "HW"), (0x10, "AW"), (0x20, "TA"), (0x40, "AP"),
    (0x80000000, "CRC"),
]
# NVAR attributes
NVAR_RUNTIME, NVAR_ASCII_NAME, NVAR_GUID, NVAR_DATA_ONLY = 0x01, 0x02, 0x04, 0x08
NVAR_EXT_HEADER, NVAR_HW_ERROR, NVAR_AUTH_WRITE, NVAR_VALID = 0x10, 0x20, 0x40, 0x80
NVAR_ATTRS = [(0x01, "Runtime"), (0x02, "AsciiName"), (0x04, "Guid"), (0x08, "DataOnly"),
              (0x10, "ExtHeader"), (0x20, "HwErrorRecord"), (0x40, "AuthWrite"), (0x80, "Valid")]


def attr_text(value: int, table) -> str:
    parts = [name for bit, name in table if value & bit]
    return ", ".join(parts) if parts else "none"


def vss_state_text(state: int) -> tuple[str, bool]:
    """Return (description, is_current)."""
    if state & 0x80:
        return "Invalid", False
    if state & 0x40:
        return "Header valid only", False
    if not state & 0x02:
        return "Deleted", False
    if not state & 0x01:
        return "In deleted transition", True
    return "Added", True


# =============================================================================
# Store detection
# =============================================================================

def parse_store_at(ctx, data, offset: int, empty: int = 0xFF, in_decoded: bool = False) -> Node | None:
    """Try to parse any known NVRAM store at the beginning of data."""
    if len(data) < 16:
        return None
    sig4 = bytes(data[:4])
    if sig4 in VSS_SIGNATURES:
        return parse_vss_store(ctx, data, offset, empty, in_decoded)
    g = bytes(data[:16])
    if g in VSS2_GUIDS:
        return parse_vss2_store(ctx, data, offset, empty, in_decoded)
    if g in FTW_GUIDS:
        return parse_ftw_store(ctx, data, offset, in_decoded)
    if sig4 == b"_FDC":
        return parse_fdc_store(ctx, data, offset, empty, in_decoded)
    if data[0] == 0xEC and bytes(data[4:8]) == b"EVSA":
        return parse_evsa_store(ctx, data, offset, in_decoded)
    return None


def parse_nvram_area(ctx, parent: Node, data, base: int, empty: int = 0xFF, probe: bool = False) -> bool:
    """Parse a sequence of NVRAM stores separated by padding (NVRAM volume body)."""
    raw = bytes(data)
    n = len(raw)
    cands = []
    for sig in VSS_SIGNATURES:
        p = raw.find(sig)
        while p >= 0:
            cands.append(p)
            p = raw.find(sig, p + 1)
    for g in list(VSS2_GUIDS) + list(FTW_GUIDS):
        p = raw.find(g)
        while p >= 0:
            cands.append(p)
            p = raw.find(g, p + 1)
    for sig in (b"_FDC",):
        p = raw.find(sig)
        while p >= 0:
            cands.append(p)
            p = raw.find(sig, p + 1)
    p = raw.find(b"EVSA")
    while p >= 0:
        if p >= 4:
            cands.append(p - 4)
        p = raw.find(b"EVSA", p + 1)
    cands.sort()
    items = []
    pos = 0
    for c in cands:
        if c < pos:
            continue
        node = parse_store_at(ctx, data[c:], base + c, empty)
        if node is None:
            continue
        if c > pos:
            items.append(_gap(data[pos:c], base + pos, empty))
        items.append(node)
        pos = c + node.size
    if probe and not items:
        return False
    if pos < n:
        items.append(_gap(data[pos:], base + pos, empty))
    for it in items:
        parent.add(it)
    return True


def _gap(data, offset, empty):
    from .area import make_padding
    if is_uniform(data, empty):
        return Node(NodeType.FREE_SPACE, "", "Free space", "", data, offset=offset)
    return make_padding(data, offset)


# =============================================================================
# VSS / VSS2
# =============================================================================

def parse_vss_store(ctx, data, offset, empty=0xFF, in_decoded=False) -> Node | None:
    sig = bytes(data[:4])
    size = u32(data, 4)
    fmt, state = data[8], data[9]
    if fmt != 0x5A or size <= 16 or size == 0xFFFFFFFF:
        return None
    if size > len(data):
        size = len(data)
    raw = data[:size]
    node = Node(NodeType.NVRAM_STORE, "VSS", VSS_SIGNATURES[sig], "", raw, hdr_size=16,
                offset=offset, in_decoded=in_decoded)
    node.meta.update(kind="vss", signature=sig, format=fmt, state=state, auth_store=None, align=1)
    node.add_info("Signature", sig.decode())
    node.add_info("Store size", size_str(size))
    node.add_info("Format", "%02Xh" % fmt)
    node.add_info("State", "%02Xh" % state)
    _parse_vss_variables(ctx, node, node.body_view, 16, align=1, auth_store=None,
                         apple=(sig != b"$VSS"))
    if ctx is not None:
        ctx.remember("nvram_store", node)
    return node


def parse_vss2_store(ctx, data, offset, empty=0xFF, in_decoded=False) -> Node | None:
    if len(data) < 28:
        return None
    g = bytes(data[:16])
    size = u32(data, 16)
    fmt, state = data[20], data[21]
    if size <= 28 or size == 0xFFFFFFFF or fmt != 0x5A:
        return None
    if size > len(data):
        size = len(data)
    raw = data[:size]
    auth = True if g == G.EFI_AUTHENTICATED_VARIABLE_GUID else (False if g == G.EFI_VARIABLE_GUID else None)
    node = Node(NodeType.NVRAM_STORE, "VSS2", VSS2_GUIDS[g], "", raw, hdr_size=28,
                offset=offset, in_decoded=in_decoded)
    node.meta.update(kind="vss2", signature=g, format=fmt, state=state, auth_store=auth, align=4)
    node.add_info("Signature", guid_to_str(g))
    node.add_info("Store size", size_str(size))
    node.add_info("Format", "%02Xh" % fmt)
    node.add_info("State", "%02Xh" % state)
    _parse_vss_variables(ctx, node, node.body_view, 28, align=4, auth_store=auth, apple=False)
    if ctx is not None:
        ctx.remember("nvram_store", node)
    return node


def _vss_is_auth(data, pos, auth_store) -> bool:
    if auth_store is not None:
        return auth_store
    attrs = u32(data, pos + 4)
    if attrs & 0x70:
        return True
    name_size = u32(data, pos + 8)
    data_size = u32(data, pos + 12)
    return name_size == 0 or data_size == 0


def _parse_vss_variables(ctx, store: Node, body, base: int, align: int, auth_store, apple: bool) -> None:
    n = len(body)
    pos = 0
    db = guid_db()
    while pos < n:
        if pos + 2 <= n and body[pos] != 0xAA and align == 1:
            ap = align_up(pos, 4)
            if ap + 2 <= n and body[ap] == 0xAA and body[ap + 1] == 0x55:
                pos = ap
        if pos + 2 > n or body[pos] != 0xAA or body[pos + 1] != 0x55:
            break
        state = body[pos + 2]
        attrs = u32(body, pos + 4)
        kind = "VSS"
        if state in (0xFC, 0xF8) and store.meta["kind"] == "vss":
            # Intel legacy variable: total size, no name/data size fields
            if pos + 28 > n:
                break
            total = u32(body, pos + 8)
            if total < 32 or pos + total > n:
                break
            guid = bytes(body[pos + 12:pos + 28])
            name, nlen = ucs2_string(body, pos + 28)
            hsize = 28 + nlen
            dsize = total - hsize
            kind = "Intel legacy"
        else:
            is_auth = _vss_is_auth(body, pos, auth_store)
            if is_auth:
                if pos + 60 > n:
                    break
                name_size = u32(body, pos + 36)
                dsize = u32(body, pos + 40)
                guid = bytes(body[pos + 44:pos + 60])
                fixed = 60
                kind = "Auth VSS"
            else:
                if pos + 32 > n:
                    break
                name_size = u32(body, pos + 8)
                dsize = u32(body, pos + 12)
                guid = bytes(body[pos + 16:pos + 32])
                fixed = 32
                if apple and attrs & 0x80000000:
                    fixed = 36
                    kind = "Apple VSS"
            if name_size > n or dsize > n or pos + fixed + name_size + dsize > n:
                break
            name, _ = ucs2_string(body, pos + fixed, name_size // 2)
            hsize = fixed + name_size
            total = hsize + dsize
        raw = body[pos:pos + total]
        state_txt, current = vss_state_text(state)
        var = Node(NodeType.NVRAM_VARIABLE, kind, name, db.display(guid), raw, hdr_size=hsize,
                   offset=base + pos)
        var.meta.update(kind="vss", var_kind=kind, guid=guid, var_name=name, attrs=attrs,
                        state=state, current=current, data_size=dsize)
        var.add_info("Variable GUID", guid_to_str(guid))
        var.add_info("Name", name)
        var.add_info("Attributes", "%08Xh (%s)" % (attrs, attr_text(attrs, VAR_ATTRS)))
        var.add_info("State", "%02Xh (%s)" % (state, state_txt))
        var.add_info("Data size", size_str(dsize))
        if kind == "Auth VSS":
            mc = u64(raw, 8)
            pk = u32(raw, 32)
            var.add_info("Monotonic counter", "%Xh" % mc)
            var.add_info("Timestamp", _efi_time(raw[16:32]))
            var.add_info("PubKey index", pk)
        if kind == "Apple VSS":
            stored = u32(raw, 32)
            calc = crc32(var.body_view)
            var.add_info("Data CRC32", "%08Xh, %s" % (stored, "valid" if stored == calc else "invalid"))
        if not current:
            var.flags.add("inactive")
        store.add(var)
        pos += total
        if align > 1:
            pos = align_up(pos, align)
    if pos < n:
        rest = body[pos:]
        if is_uniform(rest, 0xFF):
            store.add(Node(NodeType.FREE_SPACE, "", "Free space", "", rest, offset=base + pos))
        else:
            from .area import make_padding
            pad = make_padding(rest, base + pos)
            pad.msg("Unparsed data in variable store")
            store.add(pad)


def _efi_time(b) -> str:
    if len(b) < 16:
        return "?"
    year, month, day, hour, minute, second = struct.unpack_from("<HBBBBB", b, 0)
    if year == 0 and month == 0:
        return "not set"
    return "%04d-%02d-%02d %02d:%02d:%02d" % (year, month, day, hour, minute, second)


# =============================================================================
# FTW / FDC / EVSA
# =============================================================================

def parse_ftw_store(ctx, data, offset, in_decoded=False) -> Node | None:
    if len(data) < 32:
        return None
    crc = u32(data, 16)
    state = data[20]
    q32 = u32(data, 24)
    if q32 % 0x10 == 0x04:
        hsize, qsize = 28, q32
    elif q32 % 0x10 == 0:
        hsize, qsize = 32, q32 | (u32(data, 28) << 32)
    else:
        return None
    total = hsize + qsize
    if total > len(data) or total <= hsize:
        return None
    raw = data[:total]
    hdr = bytearray(raw[:hsize])
    hdr[16:20] = b"\xff\xff\xff\xff"
    hdr[20] = 0xFF
    calc = crc32(bytes(hdr))
    node = Node(NodeType.NVRAM_STORE, "FTW", "FTW store", "", raw, hdr_size=hsize, offset=offset,
                in_decoded=in_decoded)
    node.meta.update(kind="ftw")
    node.add_info("Signature", guid_to_str(bytes(data[:16])))
    node.add_info("State", "%02Xh" % state)
    node.add_info("Write queue size", size_str(qsize))
    node.add_info("Header CRC32", "%08Xh, %s" % (crc, "valid" if crc == calc else "invalid, should be %08Xh" % calc))
    return node


def parse_fdc_store(ctx, data, offset, empty=0xFF, in_decoded=False) -> Node | None:
    size = u32(data, 4)
    if size < 0x60 or size > len(data):
        return None
    raw = data[:size]
    node = Node(NodeType.NVRAM_STORE, "FDC", "Insyde FDC store", "", raw, hdr_size=8, offset=offset,
                in_decoded=in_decoded)
    node.meta.update(kind="fdc")
    node.add_info("Size", size_str(size))
    from . import area
    area.parse_raw_area(ctx, node, node.body_view, 8, probe=True)
    return node


def parse_evsa_store(ctx, data, offset, in_decoded=False) -> Node | None:
    hlen = u16(data, 2)
    size = u32(data, 12)
    if hlen != 20 or size <= 20 or size > len(data):
        return None
    raw = data[:size]
    node = Node(NodeType.NVRAM_STORE, "EVSA", "EVSA store", "", raw, hdr_size=20, offset=offset,
                in_decoded=in_decoded)
    node.meta.update(kind="evsa")
    node.add_info("Store size", size_str(size))
    node.add_info("Attributes", "%08Xh" % u32(data, 8))
    body = node.body_view
    n = len(body)
    pos = 0
    guids: dict[int, bytes] = {}
    names: dict[int, str] = {}
    entries = []
    while pos + 4 <= n:
        t = body[pos]
        if t not in (0xED, 0xE1, 0xEE, 0xE2, 0xEF, 0xE3, 0x83):
            break
        length = u16(body, pos + 2)
        if length < 4 or pos + length > n:
            break
        e = body[pos:pos + length]
        if t in (0xED, 0xE1) and length >= 22:
            guids[u16(e, 4)] = bytes(e[6:22])
        elif t in (0xEE, 0xE2) and length >= 6:
            names[u16(e, 4)] = ucs2_string(e, 6)[0]
        entries.append((pos, t, e))
        pos += length
    db = guid_db()
    for epos, t, e in entries:
        if t in (0xED, 0xE1):
            label, kind, hs = "GUID %d" % u16(e, 4), "EVSA GUID", len(e)
            text = db.display(bytes(e[6:22])) if len(e) >= 22 else ""
        elif t in (0xEE, 0xE2):
            label, kind, hs = names.get(u16(e, 4), "?"), "EVSA name", len(e)
            text = ""
        else:
            gid, vid, attrs = u16(e, 4), u16(e, 6), u32(e, 8)
            hs = 12
            if attrs & 0x10000000 and len(e) >= 16:
                hs = 16
            label = names.get(vid, "Var %d" % vid)
            text = db.display(guids[gid]) if gid in guids else ""
            kind = "EVSA data" if t != 0x83 else "EVSA invalid data"
        var = Node(NodeType.NVRAM_VARIABLE, kind, label, text, e, hdr_size=hs, offset=20 + epos)
        var.meta.update(kind="evsa", entry_type=t, checksum=e[1])
        if t in (0xEF, 0xE3, 0x83):
            gid, vid = u16(e, 4), u16(e, 6)
            var.meta.update(var_name=names.get(vid), guid=guids.get(gid), current=(t != 0x83),
                            attrs=u32(e, 8))
        var.add_info("Entry type", "%02Xh" % t)
        var.add_info("Checksum", "%02Xh, %s" % (e[1], "valid" if _evsa_checksum(e) == e[1] else "invalid"))
        node.add(var)
    if pos < n:
        rest = body[pos:]
        node.add(Node(NodeType.FREE_SPACE, "", "Free space", "", rest, offset=20 + pos)
                 if is_uniform(rest, 0xFF) else Node(NodeType.PADDING, "Non-empty", "Padding", "", rest,
                                                     offset=20 + pos))
    return node


def _evsa_checksum(entry) -> int:
    s = (sum(entry) - entry[1]) & 0xFF
    return (0x100 - s) & 0xFF


# =============================================================================
# AMI NVAR
# =============================================================================

def parse_nvar_store(ctx, parent: Node, data, base: int, empty: int = 0xFF) -> bool:
    """Parse NVAR entries in data and add them to parent. Returns True if entries were found."""
    n = len(data)
    pos = 0
    entries: list[tuple[int, Node]] = []
    guid_count = 0
    db = guid_db()
    by_offset: dict[int, Node] = {}
    while pos + 10 <= n and bytes(data[pos:pos + 4]) == b"NVAR":
        size = u16(data, pos + 4)
        nxt = u24(data, pos + 6)
        attrs = data[pos + 9]
        if size <= 10 or pos + size > n:
            break
        raw = data[pos:pos + size]
        e = _parse_nvar_entry(raw, attrs, nxt)
        if e["guid_index"] is not None:
            guid_count = max(guid_count, e["guid_index"] + 1)
        node = Node(NodeType.NVRAM_VARIABLE, e["subtype"], e["name"] or "", "", raw,
                    hdr_size=e["hsize"], tail_size=e["tail"], offset=base + pos)
        node.meta.update(kind="nvar", attrs=attrs, next=nxt, guid=e["guid"], guid_index=e["guid_index"],
                         var_name=e["name"], ext_attrs=e["ext_attrs"], checksum=e["checksum"],
                         checksum_ok=e["checksum_ok"], valid=e["valid"], current=False, prev=None)
        by_offset[pos] = node
        entries.append((pos, node))
        pos += size
    if not entries:
        return False
    # Resolve GUIDs from the GUID store at the end of the area
    for _, node in entries:
        gi = node.meta["guid_index"]
        if gi is not None and node.meta["guid"] is None and (gi + 1) * 16 <= n:
            s = n - (gi + 1) * 16
            node.meta["guid"] = bytes(data[s:s + 16])
    # Resolve link chains: data-only entries inherit name and GUID
    for off, node in entries:
        nxt = node.meta["next"]
        if nxt != 0xFFFFFF and node.meta["valid"]:
            target = by_offset.get(off + nxt)
            if target is not None:
                node.meta["link"] = target
                target.meta["prev"] = node
    for off, node in entries:
        m = node.meta
        if m["attrs"] & NVAR_DATA_ONLY and m["valid"]:
            prev = m.get("prev")
            root = prev
            while root is not None and root.meta.get("prev") is not None and root.meta["attrs"] & NVAR_DATA_ONLY:
                root = root.meta["prev"]
            if root is not None:
                m["var_name"] = root.meta["var_name"]
                m["guid"] = root.meta["guid"]
                node.name = root.name
                node.subtype = "NVAR data" if m["next"] == 0xFFFFFF else "NVAR link"
            else:
                node.subtype = "NVAR invalid link"
                node.name = "InvalidLink"
                m["valid"] = False
    for off, node in entries:
        m = node.meta
        g = m["guid"]
        node.text = db.display(g) if g else ""
        # an entry holds the current value if it is valid and the end of its chain
        m["current"] = bool(m["valid"]) and m["next"] == 0xFFFFFF
        _nvar_info(node, base)
        if not m["current"]:
            node.flags.add("inactive")
        parent.add(node)
        body = node.body_view
        if m["valid"] and len(body) >= 10 and bytes(body[:4]) == b"NVAR":
            node.meta["nested"] = True
            parse_nvar_store(ctx, node, body, node.hdr_size, empty)
    guid_area = guid_count * 16
    free_end = n - guid_area
    if pos < free_end:
        rest = data[pos:free_end]
        if is_uniform(rest, empty):
            parent.add(Node(NodeType.FREE_SPACE, "", "Free space", "", rest, offset=base + pos))
        else:
            from .area import make_padding
            parent.add(make_padding(rest, base + pos))
    elif free_end < pos:
        guid_area = max(0, n - pos)
        free_end = pos
    if guid_area:
        gs = Node(NodeType.DATA, "GUID store", "GUID store", "%d GUIDs" % guid_count,
                  data[free_end:], offset=base + free_end)
        gs.meta["kind"] = "nvar_guid_store"
        parent.add(gs)
    parent.meta["nvar_store"] = True
    if ctx is not None:
        ctx.remember("nvar_store", parent)
    return True


def _parse_nvar_entry(raw, attrs: int, nxt: int) -> dict:
    size = len(raw)
    e = {"guid": None, "guid_index": None, "name": None, "hsize": 10, "tail": 0,
         "ext_attrs": None, "checksum": None, "checksum_ok": None, "valid": bool(attrs & NVAR_VALID),
         "subtype": "NVAR entry"}
    if not attrs & NVAR_VALID:
        e["subtype"] = "NVAR invalid"
        e["name"] = "Invalid"
        return e
    p = 10
    if not attrs & NVAR_DATA_ONLY:
        if attrs & NVAR_GUID:
            e["guid"] = bytes(raw[p:p + 16])
            p += 16
        else:
            e["guid_index"] = raw[p]
            p += 1
        if attrs & NVAR_ASCII_NAME:
            end = bytes(raw).find(b"\0", p)
            if end < 0:
                end = size - 1
            e["name"] = bytes(raw[p:end]).decode("latin-1")
            p = end + 1
        else:
            s, used = ucs2_string(raw, p)
            e["name"] = s
            p += used
    if nxt != 0xFFFFFF:
        e["subtype"] = "NVAR link"
    e["hsize"] = min(p, size)
    if attrs & NVAR_EXT_HEADER and size > 12:
        ext = u16(raw, size - 2)
        if 3 <= ext <= size - e["hsize"]:
            e["tail"] = ext
            ea = raw[size - ext]
            e["ext_attrs"] = ea
            if ea & 0x01 and ext >= 4:
                e["checksum"] = raw[size - 3]
                e["checksum_ok"] = nvar_checksum_sum(raw) == 0
    return e


def nvar_checksum_sum(raw) -> int:
    """UEFITool-compatible NVAR checksum verification sum (0 means valid)."""
    s = sum(raw[10:]) + raw[4] + raw[5] + raw[9]
    return s & 0xFF


def _nvar_info(node: Node, base: int) -> None:
    m = node.meta
    if m["guid"]:
        node.add_info("Variable GUID", guid_to_str(m["guid"]))
    if m["guid_index"] is not None:
        node.add_info("GUID index", m["guid_index"])
    if m["var_name"]:
        node.add_info("Name", m["var_name"])
    node.add_info("Attributes", "%02Xh (%s)" % (m["attrs"], attr_text(m["attrs"], NVAR_ATTRS)))
    node.add_info("Data size", size_str(node.body_size))
    if m["next"] != 0xFFFFFF:
        node.add_info("Next entry", "+%Xh" % m["next"])
    if m["ext_attrs"] is not None:
        node.add_info("Extended attributes", "%02Xh" % m["ext_attrs"])
    if m["checksum"] is not None:
        node.add_info("Checksum", "%02Xh, %s" % (m["checksum"], "valid" if m["checksum_ok"] else "invalid"))
        if not m["checksum_ok"]:
            node.msg("Invalid NVAR entry checksum")
    node.add_info("Current value", "yes" if m.get("current") else "no (superseded, invalid or link)")


# =============================================================================
# Reconstruction
# =============================================================================

def build_vss_variable(node: Node, body: bytes) -> bytes:
    hdr = bytearray(node.header)
    kind = node.meta.get("var_kind")
    if kind == "Auth VSS":
        struct.pack_into("<I", hdr, 40, len(body))
    elif kind == "Intel legacy":
        struct.pack_into("<I", hdr, 8, len(hdr) + len(body))
    else:
        struct.pack_into("<I", hdr, 12, len(body))
        if kind == "Apple VSS":
            struct.pack_into("<I", hdr, 32, crc32(body))
    return bytes(hdr) + body


def build_nvar_entry(node: Node, body: bytes) -> bytes:
    hdr = bytearray(node.header)
    tail = bytearray(node.tail)
    total = len(hdr) + len(body) + len(tail)
    if total > 0xFFFF:
        raise ValueError("NVAR entry too large (%Xh bytes)" % total)
    struct.pack_into("<H", hdr, 4, total)
    raw = bytearray(hdr + body + tail)
    if node.meta.get("checksum") is not None and len(tail) >= 4:
        idx = len(raw) - 3
        raw[idx] = 0
        raw[idx] = (0x100 - nvar_checksum_sum(raw)) & 0xFF
    return bytes(raw)


def build_evsa_entry(node: Node, body: bytes) -> bytes:
    raw = bytearray(node.header + body)
    struct.pack_into("<H", raw, 2, len(raw))
    if node.hdr_size == 16:
        struct.pack_into("<I", raw, 12, len(body))
    raw[1] = 0
    raw[1] = _evsa_checksum(raw)
    return bytes(raw)


def layout_store(store: Node, parts: list[tuple[Node, bytes]], body_size: int, align: int = 1,
                 fill: int = 0xFF) -> bytes:
    """Lay out variables sequentially, followed by free space up to body_size.

    NVAR link offsets are recomputed so chains stay intact when entry sizes change.
    Trailing fixed items (GUID store) stay at the end of the area.
    """
    tail_items = [(n, b) for n, b in parts if n.meta.get("kind") == "nvar_guid_store"]
    parts = [(n, b) for n, b in parts if n.meta.get("kind") != "nvar_guid_store"
             and n.type != NodeType.FREE_SPACE]
    # Nodes are keyed by their original offset (stable across copy-on-write clones).
    new_off: dict[int, int] = {}
    placed = []
    pos = 0
    for n, b in parts:
        pos = align_up(pos, align)
        placed.append((n, b, pos))
        new_off[n.offset] = pos
        pos += len(b)
    tail_len = sum(len(b) for _, b in tail_items)
    if pos + tail_len > body_size:
        raise ValueError("Variable store '%s' overflows by %Xh bytes" % (store.name, pos + tail_len - body_size))
    out = bytearray([fill]) * body_size
    for n, b, o in placed:
        b = bytearray(b)
        nxt = n.meta.get("next", 0xFFFFFF)
        if n.meta.get("kind") == "nvar" and nxt != 0xFFFFFF and n.meta.get("valid"):
            target = n.offset + nxt
            if target in new_off:
                rel = new_off[target] - o
                if rel != nxt:
                    b[6:9] = rel.to_bytes(3, "little")
                    if n.meta.get("checksum") is not None and n.tail_size >= 4:
                        b[len(b) - 3] = 0
                        b[len(b) - 3] = (0x100 - nvar_checksum_sum(b)) & 0xFF
        out[o:o + len(b)] = b
    p = body_size - tail_len
    for _, b in tail_items:
        out[p:p + len(b)] = b
        p += len(b)
    return bytes(out)


# =============================================================================
# Queries used by editors
# =============================================================================

def iter_variables(root: Node):
    for n in root.walk():
        if n.type == NodeType.NVRAM_VARIABLE and n.meta.get("var_name") is not None:
            yield n


def store_role(var: Node) -> str:
    """'defaults' if the variable lives in an AMI defaults store, else 'current'."""
    for a in var.ancestors():
        if a.type == NodeType.FILE and a.meta.get("guid") in (
                G.NVRAM_NVAR_EXTERNAL_DEFAULTS_FILE_GUID, G.NVRAM_NVAR_PEI_EXTERNAL_DEFAULTS_FILE_GUID,
                G.NVRAM_NVAR_BB_DEFAULTS_FILE_GUID):
            return "defaults"
        if a.type == NodeType.NVRAM_VARIABLE and a.meta.get("var_name") in ("StdDefaults", "MfgDefaults"):
            return "defaults"
    return "current"


def find_variables(root: Node, name: str, guid: bytes | None = None, current_only: bool = True) -> list[Node]:
    out = []
    for v in iter_variables(root):
        if v.meta.get("var_name") != name:
            continue
        if guid is not None and v.meta.get("guid") not in (None, guid):
            continue
        if current_only and not v.meta.get("current", True):
            continue
        out.append(v)
    return out
