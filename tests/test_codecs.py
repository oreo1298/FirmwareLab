import os
import random

import pytest

from firmwarelab import codecs
from firmwarelab.codecs import lzma_efi, tiano


SAMPLES = [
    b"",
    b"A",
    b"hello world" * 100,
    bytes(4096),
    b"\xff" * 20000,
    os.urandom(3000),
    bytes(random.Random(7).choice(b"ABCDEFG") for _ in range(9000)),
]


@pytest.mark.parametrize("data", SAMPLES)
@pytest.mark.parametrize("version", [tiano.EFI11, tiano.TIANO])
def test_tiano_roundtrip(data, version):
    comp = tiano.compress(data, version)
    assert tiano.decompress(comp, version) == data


@pytest.mark.parametrize("data", SAMPLES)
def test_tiano_auto(data):
    if not data:
        return
    comp = tiano.compress(data, tiano.TIANO)
    out, ver, alt = tiano.decompress_auto(comp)
    assert out == data


@pytest.mark.parametrize("data", SAMPLES)
def test_lzma_roundtrip(data):
    comp = lzma_efi.compress(data)
    assert lzma_efi.decompress(comp) == data
    assert lzma_efi.looks_like_lzma(comp)


@pytest.mark.parametrize("data", SAMPLES)
def test_lzmaf86_roundtrip(data):
    comp = lzma_efi.compress(data, x86=True)
    assert lzma_efi.decompress_f86(comp) == data


def test_x86_bcj_roundtrip():
    data = os.urandom(50000)
    assert lzma_efi.x86_decode(lzma_efi.x86_encode(data)) == data


@pytest.mark.parametrize("algo", [codecs.EFI11, codecs.TIANO, codecs.LZMA, codecs.LZMAF86, codecs.GZIP, codecs.ZLIB])
def test_registry_roundtrip(algo):
    data = b"FirmwareLab codec registry test payload " * 50
    comp = codecs.compress(algo, data)
    assert codecs.decompress(algo, comp) == data


def test_brotli_roundtrip():
    if not codecs.brotli_available():
        pytest.skip("brotli not installed")
    data = b"brotli test " * 500
    comp = codecs.compress(codecs.BROTLI, data)
    assert codecs.decompress(codecs.BROTLI, comp) == data


def test_bad_lzma_header():
    with pytest.raises(lzma_efi.LzmaError):
        lzma_efi.parse_header(b"\xff\xff\xff")
