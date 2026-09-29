"""Compression algorithms used in UEFI firmware images, behind one registry."""

from __future__ import annotations

import gzip
import struct
import zlib

from . import lzma_efi, tiano

NONE = "None"
EFI11 = "EFI 1.1"
TIANO = "Tiano"
LZMA = "LZMA"
LZMA_INTEL_LEGACY = "Intel legacy LZMA"
LZMAF86 = "LZMAF86"
BROTLI = "Brotli"
GZIP = "GZip"
ZLIB = "Zlib"

ALL = (NONE, EFI11, TIANO, LZMA, LZMA_INTEL_LEGACY, LZMAF86, BROTLI, GZIP, ZLIB)


class CodecError(ValueError):
    pass


try:  # optional dependency
    import brotli as _brotli  # type: ignore
except ImportError:  # pragma: no cover - depends on environment
    _brotli = None


def brotli_available() -> bool:
    return _brotli is not None


def decompress(algorithm: str, data) -> bytes:
    data = bytes(data)
    try:
        if algorithm == NONE:
            return data
        if algorithm == EFI11:
            return tiano.decompress(data, tiano.EFI11)
        if algorithm == TIANO:
            return tiano.decompress(data, tiano.TIANO)
        if algorithm == LZMA:
            return lzma_efi.decompress(data)
        if algorithm == LZMA_INTEL_LEGACY:
            return lzma_efi.decompress(data[4:])
        if algorithm == LZMAF86:
            return lzma_efi.decompress_f86(data)
        if algorithm == BROTLI:
            if _brotli is None:
                raise CodecError("Brotli support requires the 'brotli' Python module")
            size = struct.unpack_from("<Q", data, 0)[0]
            out = _brotli.decompress(data[16:])
            if len(out) != size:
                raise CodecError("Brotli size mismatch")
            return out
        if algorithm == GZIP:
            return gzip.decompress(data)
        if algorithm == ZLIB:
            return zlib.decompress(data)
    except (tiano.TianoError, lzma_efi.LzmaError, zlib.error, OSError, EOFError, struct.error) as e:
        raise CodecError("%s decompression failed: %s" % (algorithm, e)) from e
    except Exception as e:  # brotli raises its own error type
        if _brotli is not None and isinstance(e, getattr(_brotli, "error", ())):
            raise CodecError("Brotli decompression failed: %s" % e) from e
        raise
    raise CodecError("Unknown compression algorithm %r" % algorithm)


def compress(algorithm: str, data, params: dict | None = None) -> bytes:
    """Compress data. ``params`` carries settings taken from the original stream
    (LZMA dictionary size/lc/lp/pb, Brotli scratch size, Intel legacy prefix)."""
    params = params or {}
    data = bytes(data)
    if algorithm == NONE:
        return data
    if algorithm == EFI11:
        return tiano.compress(data, tiano.EFI11)
    if algorithm == TIANO:
        return tiano.compress(data, tiano.TIANO)
    if algorithm in (LZMA, LZMAF86, LZMA_INTEL_LEGACY):
        out = lzma_efi.compress(
            data,
            dict_size=params.get("dict_size", lzma_efi.DEFAULT_DICT_SIZE),
            lc=params.get("lc", 3), lp=params.get("lp", 0), pb=params.get("pb", 2),
            x86=(algorithm == LZMAF86))
        if algorithm == LZMA_INTEL_LEGACY:
            prefix = params.get("prefix", struct.pack("<I", len(out)))
            out = prefix[:4] + out
        return out
    if algorithm == BROTLI:
        if _brotli is None:
            raise CodecError("Brotli support requires the 'brotli' Python module")
        stream = _brotli.compress(data, quality=params.get("quality", 9), lgwin=params.get("lgwin", 22))
        scratch = params.get("scratch_size", 0)
        return struct.pack("<QQ", len(data), scratch) + stream
    if algorithm == GZIP:
        return gzip.compress(data, 9, mtime=0)
    if algorithm == ZLIB:
        return zlib.compress(data, 9)
    raise CodecError("Unknown compression algorithm %r" % algorithm)


def lzma_params(data) -> dict:
    """Extract encoder parameters from an existing EFI LZMA stream."""
    try:
        lc, lp, pb, dsize, _ = lzma_efi.parse_header(data)
        return {"lc": lc, "lp": lp, "pb": pb, "dict_size": dsize}
    except lzma_efi.LzmaError:
        return {}
