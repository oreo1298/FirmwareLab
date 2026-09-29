"""Shared fixtures. Synthetic firmware images are generated so tests need no external blobs."""

import os
import struct

import pytest

from firmwarelab.core import guids as G
from firmwarelab.formats import ffs


def make_volume(files: list[bytes], size: int = 0x10000, empty: int = 0xFF,
                fs_guid: bytes = G.FFS2_GUID) -> bytes:
    """Build a minimal but valid FFSv2 firmware volume containing the given files."""
    hdr_len = 0x48
    header = bytearray(16)  # zero vector
    header += fs_guid
    header += struct.pack("<Q", size)  # FvLength
    header += b"_FVH"
    header += struct.pack("<I", 0x000CFEFF)  # attributes, erase polarity 1
    header += struct.pack("<H", hdr_len)
    header += struct.pack("<H", 0)  # checksum placeholder
    header += struct.pack("<H", 0)  # ext header offset
    header += bytes([0, 2])  # reserved, revision 2
    header += struct.pack("<II", size // 0x1000, 0x1000)  # block map
    header += struct.pack("<II", 0, 0)  # terminator
    assert len(header) == hdr_len, len(header)
    from firmwarelab.core.binary import checksum16
    struct.pack_into("<H", header, 50, checksum16(header))
    body = bytearray()
    for f in files:
        body += f
        body += bytes([empty]) * ((-len(body)) % 8)
    if len(body) > size - hdr_len:
        raise ValueError("files do not fit")
    body += bytes([empty]) * (size - hdr_len - len(body))
    return bytes(header) + bytes(body)


def make_driver(name: str, guid: str, payload: bytes = b"", compress=None) -> bytes:
    secs = []
    if compress:
        from firmwarelab.formats import ffs as _f
        inner = _f.join_sections([ffs.make_section(0x19, payload or b"code"), ffs.make_ui_section(name)])
        secs = [ffs.make_compressed_section(inner, compress)]
    else:
        secs = [ffs.make_section(0x10, payload or (b"MZ" + bytes(0x80))), ffs.make_ui_section(name),
                ffs.make_section(0x14, struct.pack("<H", 1) + "1.0".encode("utf-16-le") + b"\0\0")]
    body = ffs.join_sections(secs)
    return ffs.make_file(G.str_to_guid(guid), 0x07, body, empty=0xFF)


@pytest.fixture
def simple_volume():
    files = [
        make_driver("DriverAlpha", "11111111-1111-1111-1111-111111111111", b"MZ" + b"\x90" * 200),
        make_driver("DriverBeta", "22222222-2222-2222-2222-222222222222", b"MZ" + b"\xcc" * 400),
        make_driver("DriverGamma", "33333333-3333-3333-3333-333333333333"),
    ]
    return make_volume(files, size=0x20000)


@pytest.fixture
def compressed_volume():
    inner_files = [make_driver("Inner%d" % i, "4444444%d-4444-4444-4444-444444444444" % i,
                               b"payload %d " % i * 40) for i in range(4)]
    inner_vol = make_volume(inner_files, size=0x8000)
    fv_image_section = ffs.make_section(0x17, inner_vol)
    outer = ffs.make_compressed_section(fv_image_section, "LZMA")
    container = ffs.make_file(G.str_to_guid("55555555-5555-5555-5555-555555555555"), 0x0B,
                              ffs.join_sections([outer]), empty=0xFF)
    return make_volume([container], size=0x20000)


OVMF_PATHS = [
    "/usr/share/OVMF/OVMF.fd",
    "/usr/share/ovmf/OVMF.fd",
]


@pytest.fixture
def ovmf_path():
    for p in OVMF_PATHS + [os.environ.get("FWLAB_TEST_OVMF", "")]:
        if p and os.path.isfile(p):
            return p
    pytest.skip("OVMF firmware not available")
