import struct

from firmwarelab.hii import ifr, strings


def _string_package(lang, texts):
    """Build a minimal EFI_HII_STRING_PACKAGE with UCS2 string blocks."""
    lang_bytes = lang.encode() + b"\0"
    hdr_size = 46 + len(lang_bytes)
    body = bytearray()
    for t in texts:
        body += bytes([strings.SIBT_STRING_UCS2]) + t.encode("utf-16-le") + b"\0\0"
    body += bytes([strings.SIBT_END])
    length = hdr_size + len(body)
    pkg = bytearray()
    pkg += struct.pack("<I", length)[:3] + bytes([strings.PACKAGE_TYPE_STRINGS])
    pkg += struct.pack("<I", hdr_size)  # HdrSize
    pkg += struct.pack("<I", hdr_size)  # StringInfoOffset
    pkg += bytes(46 - 12)  # language window + fontstyle etc.
    pkg += lang_bytes
    pkg += body
    return bytes(pkg)


def test_string_package_parse():
    pkg = _string_package("en-US", ["Hello", "World", "Setting"])
    p = strings.parse_string_package(pkg, 0)
    assert p is not None
    assert p.language == "en-US"
    assert p.get(1) == "Hello"
    assert p.get(3) == "Setting"


def test_find_string_packages():
    blob = b"\x00" * 8 + _string_package("en-US", ["Alpha", "Beta"]) + b"\xff" * 8
    pkgs = strings.find_string_packages(blob)
    assert len(pkgs) == 1
    assert pkgs[0].get(2) == "Beta"


def _form_package():
    """Hand-build a tiny form package: FormSet > Form > OneOf with two options + default."""
    ops = bytearray()

    def op(code, payload, scope=False):
        ln = 2 + len(payload)
        return bytes([code, (ln & 0x7F) | (0x80 if scope else 0)]) + payload

    # OneOfOption value 0 and 1, default = option 1
    oneof = op(0x05, struct.pack("<HHHHHB", 2, 3, 0x10, 1, 0, 0) + bytes([0x10, 1]), scope=True)
    opt0 = op(0x09, struct.pack("<HBB", 4, 0x00, 0) + bytes([0]))
    opt1 = op(0x09, struct.pack("<HBB", 5, 0x10, 0) + bytes([1]))  # default flag
    end = op(0x29, b"")
    form = op(0x01, struct.pack("<HH", 1, 6), scope=True)
    varstore = op(0x24, bytes(16) + struct.pack("<HH", 1, 0x10) + b"Setup\0")
    formset_payload = bytes(16) + struct.pack("<HH", 7, 8) + bytes([0])
    formset = op(0x0E, formset_payload, scope=True)
    body = formset + varstore + form + oneof + opt0 + opt1 + end + end + end
    length = 4 + len(body)
    pkg = struct.pack("<I", length)[:3] + bytes([ifr.PACKAGE_TYPE_FORMS]) + body
    return pkg


def test_form_package_parse():
    pkg_bytes = _form_package()
    pkg = ifr.parse_form_package(pkg_bytes, 0)
    assert pkg is not None
    fs = ifr.build_formsets(pkg, None)
    assert len(fs) == 1
    assert len(fs[0].questions) == 1
    q = fs[0].questions[0]
    assert q.kind == "OneOf"
    assert q.qid == 0x10
    assert len(q.options) == 2
    assert q.defaults.get(0) == 1


def test_expression_text():
    # EqIdVal Q5 == 2 ; simple
    op = ifr.IfrOp(0, 0x12, 6, False, bytes([0x12, 6]) + struct.pack("<HH", 5, 2), 0)
    op.fields = ifr._decode_fields(op)
    txt = ifr.expression_text([op])
    assert "== 2h" in txt
