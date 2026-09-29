"""Board / BIOS-revision identification."""

import struct

from conftest import make_volume

from firmwarelab.core import guids as G
from firmwarelab.formats import ffs
from firmwarelab.formats.image import parse_image
from firmwarelab.tools import identify


# --------------------------------------------------------------------------- helpers
def _fixed_ucs2(s: str, nbytes: int) -> bytes:
    b = s.encode("utf-16-le")
    assert len(b) <= nbytes, (s, nbytes)
    return b + b"\x00" * (nbytes - len(b))


def make_ibiosi(board="Z390MG", ext="86A", major="0028", build="P", minor="01",
                y="21", mo="09", d="15", h="10", mi="30") -> bytes:
    dot = b".\x00"
    return (b"$IBIOSI$"
            + _fixed_ucs2(board, 16) + dot
            + _fixed_ucs2(ext, 6) + dot
            + _fixed_ucs2(major, 8) + dot
            + _fixed_ucs2(build, 2) + _fixed_ucs2(minor, 4) + dot
            + _fixed_ucs2(y, 4) + _fixed_ucs2(mo, 4) + _fixed_ucs2(d, 4)
            + _fixed_ucs2(h, 4) + _fixed_ucs2(mi, 4)
            + b"\x00\x00")


def smbios_struct(t: int, formatted_after_header: bytes, strings: list[str], handle=0x11) -> bytes:
    length = 4 + len(formatted_after_header)
    body = bytearray(struct.pack("<BBH", t, length, handle))
    body += formatted_after_header
    if strings:
        for s in strings:
            body += s.encode("ascii") + b"\x00"
        body += b"\x00"
    else:
        body += b"\x00\x00"
    return bytes(body)


def make_smbios_table(bios_vendor="American Megatrends Inc.", bios_version="F5",
                      bios_date="09/15/2021", sys_vendor="Gigabyte Technology Co., Ltd.",
                      sys_product="Z390 M GAMING", board_vendor="Gigabyte Technology Co., Ltd.",
                      board_product="Z390 M GAMING-CF") -> bytes:
    # Type 0: vendor@4=1, version@5=2, date@8=3  (length 0x18)
    t0f = bytearray(0x14)
    t0f[0] = 1
    t0f[1] = 2
    t0f[4] = 3
    type0 = smbios_struct(0x00, bytes(t0f), [bios_vendor, bios_version, bios_date])
    # Type 1: manufacturer@4=1, product@5=2, version@6=3  (length 0x1B)
    t1f = bytearray(0x17)
    t1f[0] = 1
    t1f[1] = 2
    t1f[2] = 3
    type1 = smbios_struct(0x01, bytes(t1f), [sys_vendor, sys_product, "Default string"])
    # Type 2: manufacturer@4=1, product@5=2, version@6=3  (length 0x0F)
    t2f = bytearray(0x0B)
    t2f[0] = 1
    t2f[1] = 2
    t2f[2] = 3
    type2 = smbios_struct(0x02, bytes(t2f), [board_vendor, board_product, "1.0"])
    end = smbios_struct(0x7F, b"", [])
    return type0 + type1 + type2 + end


def _driver_with(payload: bytes, guid: str) -> bytes:
    body = ffs.join_sections([ffs.make_section(0x19, payload), ffs.make_ui_section("BoardInfo")])
    return ffs.make_file(G.str_to_guid(guid), 0x07, body, empty=0xFF)


def _image_with(payload: bytes):
    vol = make_volume([_driver_with(payload, "AAAAAAAA-0000-0000-0000-000000000001")], size=0x20000)
    return parse_image(vol, "test.bin")


# --------------------------------------------------------------------------- tests
def test_ibiosi_board_and_version():
    root, ctx = _image_with(b"pad" + make_ibiosi() + b"tail")
    info = identify.identify(root, ctx)
    assert info.board_id == "Z390MG"
    assert info.board_model == "Z390MG"
    assert info.bios_version == "Z390MG.86A.0028.P01"
    assert info.bios_date == "2021-09-15 10:30"
    assert info.summary_line().startswith("Z390MG")


def test_smbios_make_model():
    root, ctx = _image_with(make_smbios_table())
    info = identify.identify(root, ctx)
    assert info.board_vendor == "Gigabyte Technology Co., Ltd."
    assert info.board_model == "Z390 M GAMING-CF"
    assert info.bios_vendor == "American Megatrends Inc."
    assert info.bios_version == "F5"
    assert info.bios_date == "09/15/2021"
    assert info.manufacturer().startswith("Gigabyte")
    assert info.model() == "Z390 M GAMING-CF"


def test_smbios_placeholder_demoted():
    table = make_smbios_table(board_product="To be filled by O.E.M.",
                              sys_product="Real Model X99")
    root, ctx = _image_with(table)
    info = identify.identify(root, ctx)
    # A real value from Type 1 must win over the Type 2 placeholder.
    assert info.model() == "Real Model X99"


def test_ibiosi_overrides_smbios_version():
    root, ctx = _image_with(make_smbios_table() + b"\xff\xff" + make_ibiosi())
    info = identify.identify(root, ctx)
    # $IBIOSI$ is high-confidence and should own the BIOS version string.
    assert info.bios_version == "Z390MG.86A.0028.P01"
    # …while the make/model still comes from SMBIOS.
    assert info.board_model == "Z390 M GAMING-CF"


def test_reaches_inside_compressed_volume():
    inner_files = [_driver_with(make_ibiosi(board="X570AOR"), "BBBBBBBB-0000-0000-0000-000000000002")]
    inner_vol = make_volume(inner_files, size=0x8000)
    fv_sec = ffs.make_section(0x17, inner_vol)
    outer = ffs.make_compressed_section(fv_sec, "LZMA")
    container = ffs.make_file(G.str_to_guid("CCCCCCCC-0000-0000-0000-000000000003"), 0x0B,
                              ffs.join_sections([outer]), empty=0xFF)
    vol = make_volume([container], size=0x20000)
    root, ctx = parse_image(vol, "compressed.bin")
    info = identify.identify(root, ctx)
    assert info.board_id == "X570AOR"


def test_insyde_vendor_and_empty():
    root, ctx = _image_with(b"$BVDT" + b"\x00\x00" + b"BIOS Ver 1.07.00" + b"\x00")
    info = identify.identify(root, ctx)
    assert info.bios_vendor == "Insyde"


def test_no_identity_is_empty():
    root, ctx = _image_with(b"nothing identifying here" * 4)
    info = identify.identify(root, ctx)
    assert info.is_empty
    assert info.summary_line().startswith("unknown board")
