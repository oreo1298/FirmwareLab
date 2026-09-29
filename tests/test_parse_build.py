import pytest

from firmwarelab.core.node import NodeType
from firmwarelab.formats.image import parse_image
from firmwarelab.tools.builder import build
from firmwarelab.tools.project import Document


def _roundtrip(data):
    root, _ = parse_image(data)
    out, warnings = build(root)
    return root, out, warnings


def test_volume_roundtrip(simple_volume):
    root, out, warnings = _roundtrip(simple_volume)
    assert out == simple_volume
    files = [n for n in root.walk() if n.type == NodeType.FILE and "pad" not in n.flags]
    assert len(files) == 3
    assert {f.text for f in files} == {"DriverAlpha", "DriverBeta", "DriverGamma"}


def test_all_dirty_roundtrip(simple_volume):
    root, _ = parse_image(simple_volume)
    for n in root.walk():
        n.dirty = True
    out, _ = build(root)
    assert out == simple_volume


def test_compressed_roundtrip(compressed_volume):
    root, out, _ = _roundtrip(compressed_volume)
    assert out == compressed_volume
    inner = [n for n in root.walk() if n.type == NodeType.FILE and n.text and n.text.startswith("Inner")]
    assert len(inner) == 4
    lz = root.find(lambda n: n.meta.get("algorithm") == "LZMA")
    assert lz is not None and lz.decoded


def test_edit_section_body(compressed_volume):
    doc = Document(compressed_volume, "t.bin")
    sec = doc.root.find(lambda n: n.type == NodeType.SECTION and b"payload 0" in bytes(n.body)
                        and not n.children)
    assert sec is not None
    doc.replace(sec, b"REPLACED payload zero!!" + bytes(len(sec.body) - 23), mode="body")
    data = doc.build()
    doc2 = Document(data, "t2.bin")
    sec2 = doc2.root.find(lambda n: n.type == NodeType.SECTION and b"REPLACED" in bytes(n.body)
                          and not n.children)
    assert sec2 is not None


def test_insert_remove(simple_volume):
    from firmwarelab.formats import ffs
    from firmwarelab.core import guids as G
    doc = Document(simple_volume, "t.bin")
    vol = doc.root.find(lambda n: n.type == NodeType.VOLUME)
    newf = ffs.make_file(G.str_to_guid("99999999-9999-9999-9999-999999999999"), 0x07,
                         ffs.join_sections([ffs.make_section(0x19, b"x" * 100), ffs.make_ui_section("Injected")]))
    doc.insert(vol, newf, "into")
    data = doc.build()
    d2 = Document(data, "t2.bin")
    assert d2.root.find(lambda n: n.type == NodeType.FILE and n.text == "Injected") is not None
    victim = d2.root.find(lambda n: n.type == NodeType.FILE and n.text == "DriverBeta")
    d2.remove(victim)
    d3 = Document(d2.build(), "t3.bin")
    assert d3.root.find(lambda n: n.type == NodeType.FILE and n.text == "DriverBeta") is None
    assert d3.root.find(lambda n: n.type == NodeType.FILE and n.text == "Injected") is not None


def test_undo_redo(simple_volume):
    doc = Document(simple_volume, "t.bin")
    original = doc.build()
    f = doc.root.find(lambda n: n.type == NodeType.FILE and n.text == "DriverAlpha")
    doc.remove(f)
    assert doc.build() != original
    assert doc.undo() is not None
    assert doc.build() == original
    assert doc.redo() is not None
    assert doc.build() != original


def test_verify_reports_changes(simple_volume):
    doc = Document(simple_volume, "t.bin")
    f = doc.root.find(lambda n: n.type == NodeType.FILE and n.text == "DriverGamma")
    doc.remove(f)
    data = doc.build()
    rep = doc.verify(data)
    assert rep.ok
    assert any("DriverGamma" in c for c in rep.changed_files)


# --- OVMF-based tests (skipped if OVMF not installed) -----------------------

def test_ovmf_roundtrip(ovmf_path):
    with open(ovmf_path, "rb") as fh:
        data = fh.read()
    root, out, warnings = _roundtrip(data)
    assert out == data
    assert root.count() > 100


def test_ovmf_named_modules(ovmf_path):
    doc = Document.open(ovmf_path)
    files = [n for n in doc.root.walk() if n.type == NodeType.FILE and "pad" not in n.flags]
    named = [f for f in files if f.text]
    assert len(named) > 50


def test_ovmf_edit_recompress(ovmf_path):
    doc = Document.open(ovmf_path)
    sec = doc.root.find(lambda n: n.type == NodeType.SECTION and n.meta.get("type") == 0x15
                        and n.meta.get("ui") == "PlatformDxe")
    if sec is None:
        pytest.skip("PlatformDxe not present")
    doc.replace(sec, "PatchedName!".encode("utf-16-le") + b"\0\0", mode="body")
    data = doc.build()
    rep = doc.verify(data)
    assert rep.ok
    d2 = Document(data, "x.fd")
    assert d2.root.find(lambda n: n.meta.get("ui") == "PatchedName!") is not None
