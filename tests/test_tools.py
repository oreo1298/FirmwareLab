import struct

import pytest

from firmwarelab.core import guids as G
from firmwarelab.core.node import NodeType
from firmwarelab.formats import descriptor, gbe, microcode
from firmwarelab.tools import assemble, diff, flash, patch, search
from firmwarelab.tools.project import Document


def test_guid_db_loaded():
    db = G.guid_db()
    assert len(db) > 1000
    assert db.name(G.str_to_guid("EE4E5898-3914-4259-9D6E-DC7BD79403CF")) == "LzmaCustomDecompressGuid"


def test_guid_roundtrip():
    g = "12345678-9ABC-DEF0-1122-334455667788"
    assert G.guid_to_str(G.str_to_guid(g)) == g


def test_search(simple_volume):
    doc = Document(simple_volume, "t.bin")
    assert len(search.search_guid(doc.root, "11111111-1111-1111-1111-111111111111")) == 1
    assert len(search.search_text(doc.root, "DriverBeta")) >= 1
    assert len(search.search_name(doc.root, "Gamma")) >= 1
    assert len(search.search_hex(doc.root, "4D5A")) >= 1  # MZ


def test_patch_pattern(simple_volume):
    doc = Document(simple_volume, "t.bin")
    guid = "11111111-1111-1111-1111-111111111111"
    script = "%s 10 P:%s:%s" % (guid, b"MZ".hex() + "90" * 4, b"XY".hex() + "aa" * 4)
    res = patch.apply_script(doc, script)
    assert len(res) == 1
    data = doc.build()
    d2 = Document(data, "t2.bin")
    sec = d2.root.find(lambda n: n.type == NodeType.SECTION and n.meta.get("type") == 0x10
                       and n.find_ancestor(NodeType.FILE).meta["guid"] == G.str_to_guid(guid))
    assert sec.body[:6] == b"XY\xaa\xaa\xaa\xaa"


def test_patch_offset(simple_volume):
    doc = Document(simple_volume, "t.bin")
    guid = "22222222-2222-2222-2222-222222222222"
    script = "%s 10 O:0:%s" % (guid, "deadbeef")
    res = patch.apply_script(doc, script)
    assert len(res) == 1


def test_diff(simple_volume):
    doc = Document(simple_volume, "t.bin")
    orig_root = Document(simple_volume, "o.bin").root
    f = doc.root.find(lambda n: n.type == NodeType.FILE and n.text == "DriverBeta")
    doc.remove(f)
    entries = diff.diff_trees(orig_root, doc.root)
    s = diff.summarize(entries)
    assert s["removed"] >= 1


def test_flash_analyze(simple_volume):
    doc = Document(simple_volume, "t.bin")
    r = flash.analyze(doc)
    assert r.size == 0x20000
    assert r.nearest_chip == 0x80000


def test_flash_pad():
    padded = flash.pad_to(b"\x01\x02", 16, fill=0xFF, at_end=True)
    assert padded == b"\x01\x02" + b"\xff" * 14


# --- Intel-specific: build a descriptor synthetically ----------------------

def _make_descriptor(regions, version=2, nstraps=60):
    """Minimal v2 descriptor with given regions {name: (base_kb, limit_kb)} in 4KiB units."""
    d = bytearray(b"\xff" * 0x1000)
    d[16:20] = descriptor.SIGNATURE
    fcba, frba, fmba, fpsba = 0x40, 0x80, 0x100, 0x200
    struct.pack_into("<I", d, 0x14, (fcba >> 4) | (0 << 8) | ((frba >> 4) << 16) | (7 << 24))
    struct.pack_into("<I", d, 0x18, (fmba >> 4) | (2 << 8) | ((fpsba >> 4) << 16) | (nstraps << 24))
    struct.pack_into("<I", d, 0x1C, (0 << 8))
    # flcomp: nonzero read clock freq => v2
    struct.pack_into("<I", d, fcba, (2 << 17) if version == 2 else 0)
    names = descriptor.REGION_NAMES
    for i, name in enumerate(names):
        base = limit = 0x7FFF
        if name in regions:
            b, l = regions[name]
            base, limit = b, l
        elif name != "Descriptor":
            base, limit = 0x7FFF, 0
        if name == "Descriptor":
            base, limit = 0, 0
        struct.pack_into("<I", d, frba + i * 4, (base & 0x7FFF) | ((limit & 0x7FFF) << 16))
    for i in range(5):
        # v2 master: full access
        struct.pack_into("<I", d, fmba + i * 4, 0xFFFFFF00)
    return bytes(d)


def test_descriptor_parse_and_unlock():
    desc_bytes = _make_descriptor({"BIOS": (0x10, 0x1F), "ME": (0x1, 0xF)})
    desc = descriptor.parse(desc_bytes)
    assert desc.version == 2
    assert desc.region("BIOS").offset == 0x10000
    # lock BIOS master then unlock
    buf = bytearray(desc_bytes)
    bios = next(m for m in desc.masters if m.name == "BIOS")
    struct.pack_into("<I", buf, bios.offset, 0x00000000)
    locked = descriptor.parse(bytes(buf))
    assert descriptor.is_locked(locked)
    unlocked = descriptor.unlock(bytes(buf))
    assert not descriptor.is_locked(descriptor.parse(unlocked))


def test_assemble_split():
    desc_bytes = _make_descriptor({"BIOS": (0x10, 0x1F), "ME": (0x1, 0xF)})
    bios = b"B" * 0x10000
    me = b"M" * 0xF000
    img = assemble.assemble(desc_bytes, {"BIOS": bios, "ME": me}, size=0x20000)
    assert len(img) == 0x20000
    parts = assemble.split(img)
    assert "BIOS" in parts and "ME" in parts
    # BIOS is end-aligned
    assert parts["BIOS"].endswith(b"B")


def test_gbe_mac():
    data = bytearray(b"\xff" * 0x2000)
    # bank 0 must have a valid-ish checksum region; set_mac fixes it
    out = gbe.set_mac(bytes(data), "00:11:22:33:44:55")
    assert gbe.mac_of(out) == "00:11:22:33:44:55"
    assert gbe.bank_checksum_ok(out, 0)


def test_microcode_checksum():
    # craft a tiny fake microcode header and check checksum fixing
    blob = bytearray(0x800)
    struct.pack_into("<9I", blob, 0, 1, 0x10, 0x05072021, 0x306C3, 0, 1, 0, 0x7C8, 0x800)
    fixed = microcode.fix_checksum(bytes(blob))
    from firmwarelab.core.binary import sum32
    assert sum32(fixed) == 0
