"""LZMA as used by UEFI firmware (EDK2 LzmaCustomDecompress / LzmaF86).

Stream layout: 1 byte properties, 4 bytes dictionary size, 8 bytes uncompressed
size, followed by the raw LZMA stream.  Firmware tools write the real
uncompressed size and no end-of-payload marker; this module does the same when
the system liblzma supports LZMA1EXT (xz >= 5.4), falling back to Python's lzma
module (which appends an end marker that firmware decoders also accept).
"""

from __future__ import annotations

import ctypes
import ctypes.util
import lzma
import re
import struct

HEADER_SIZE = 13
DEFAULT_DICT_SIZE = 1 << 23


class LzmaError(ValueError):
    pass


def parse_header(data) -> tuple[int, int, int, int, int]:
    """Return (lc, lp, pb, dict_size, uncompressed_size)."""
    if len(data) < HEADER_SIZE:
        raise LzmaError("data too small for LZMA header")
    props = data[0]
    if props >= 9 * 5 * 5:
        raise LzmaError("invalid LZMA properties byte %02Xh" % props)
    lc = props % 9
    rest = props // 9
    lp = rest % 5
    pb = rest // 5
    dict_size, size = struct.unpack_from("<IQ", data, 1)
    return lc, lp, pb, dict_size, size


def looks_like_lzma(data) -> bool:
    try:
        lc, lp, pb, dsize, size = parse_header(data)
    except LzmaError:
        return False
    return dsize >= 4096 and (size == 0xFFFFFFFFFFFFFFFF or size < 0x40000000)


def decompress(data) -> bytes:
    lc, lp, pb, dsize, size = parse_header(data)
    if size != 0xFFFFFFFFFFFFFFFF and size > 0x40000000:
        raise LzmaError("suspicious uncompressed size %Xh" % size)
    dec = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
    try:
        out = dec.decompress(bytes(data))
    except lzma.LZMAError as e:
        out = _decompress_ext(data, lc, lp, pb, dsize, size)
        if out is None:
            raise LzmaError(str(e)) from e
    if size != 0xFFFFFFFFFFFFFFFF and len(out) != size:
        raise LzmaError("decompressed size %Xh does not match header %Xh" % (len(out), size))
    return out


# --------------------------------------------------------------------------
# liblzma access through ctypes for LZMA1EXT (no end marker, known size)
# --------------------------------------------------------------------------

class _LzmaOptions(ctypes.Structure):
    _fields_ = [
        ("dict_size", ctypes.c_uint32),
        ("preset_dict", ctypes.c_void_p),
        ("preset_dict_size", ctypes.c_uint32),
        ("lc", ctypes.c_uint32),
        ("lp", ctypes.c_uint32),
        ("pb", ctypes.c_uint32),
        ("mode", ctypes.c_int),
        ("nice_len", ctypes.c_uint32),
        ("mf", ctypes.c_int),
        ("depth", ctypes.c_uint32),
        ("ext_flags", ctypes.c_uint32),
        ("ext_size_low", ctypes.c_uint32),
        ("ext_size_high", ctypes.c_uint32),
        ("reserved_int4", ctypes.c_uint32),
        ("reserved_enum1", ctypes.c_int),
        ("reserved_enum2", ctypes.c_int),
        ("reserved_enum3", ctypes.c_int),
        ("reserved_enum4", ctypes.c_int),
        ("reserved_ptr1", ctypes.c_void_p),
        ("reserved_ptr2", ctypes.c_void_p),
    ]


class _LzmaFilter(ctypes.Structure):
    _fields_ = [("id", ctypes.c_uint64), ("options", ctypes.c_void_p)]


_FILTER_LZMA1EXT = 0x4000000000000002
_FILTER_X86 = 0x04
_VLI_UNKNOWN = 0xFFFFFFFFFFFFFFFF
_PRESET_EXTREME = 0x80000000

_lib = None
_lib_checked = False


def _liblzma():
    global _lib, _lib_checked
    if _lib_checked:
        return _lib
    _lib_checked = True
    name = ctypes.util.find_library("lzma") or "liblzma.so.5"
    try:
        lib = ctypes.CDLL(name)
        lib.lzma_version_number.restype = ctypes.c_uint32
        if lib.lzma_version_number() < 50040002:
            return None
        lib.lzma_lzma_preset.argtypes = [ctypes.POINTER(_LzmaOptions), ctypes.c_uint32]
        lib.lzma_lzma_preset.restype = ctypes.c_ubyte
        lib.lzma_raw_buffer_encode.argtypes = [
            ctypes.POINTER(_LzmaFilter), ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_size_t]
        lib.lzma_raw_buffer_encode.restype = ctypes.c_int
        lib.lzma_raw_buffer_decode.argtypes = [
            ctypes.POINTER(_LzmaFilter), ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t),
            ctypes.c_size_t, ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_size_t]
        lib.lzma_raw_buffer_decode.restype = ctypes.c_int
        _lib = lib
    except (OSError, AttributeError):
        _lib = None
    return _lib


def has_native_encoder() -> bool:
    return _liblzma() is not None


def _options(lc, lp, pb, dict_size, preset, size=None, allow_eopm=False):
    lib = _liblzma()
    opt = _LzmaOptions()
    if lib.lzma_lzma_preset(ctypes.byref(opt), preset):
        raise LzmaError("lzma_lzma_preset failed")
    opt.dict_size = dict_size
    opt.lc, opt.lp, opt.pb = lc, lp, pb
    opt.ext_flags = 1 if allow_eopm else 0
    if size is None:
        size = _VLI_UNKNOWN
    opt.ext_size_low = size & 0xFFFFFFFF
    opt.ext_size_high = (size >> 32) & 0xFFFFFFFF
    return opt


def _decompress_ext(data, lc, lp, pb, dsize, size):
    """Decode with LZMA1EXT (known size, optional end marker)."""
    lib = _liblzma()
    if lib is None or size == 0xFFFFFFFFFFFFFFFF:
        return None
    opt = _options(lc, lp, pb, max(dsize, 4096), 6, size, allow_eopm=True)
    filters = (_LzmaFilter * 2)()
    filters[0].id = _FILTER_LZMA1EXT
    filters[0].options = ctypes.cast(ctypes.byref(opt), ctypes.c_void_p)
    filters[1].id = _VLI_UNKNOWN
    src = bytes(data[HEADER_SIZE:])
    in_pos = ctypes.c_size_t(0)
    out = ctypes.create_string_buffer(max(size, 1))
    out_pos = ctypes.c_size_t(0)
    ret = lib.lzma_raw_buffer_decode(filters, None, src, ctypes.byref(in_pos), len(src),
                                     out, ctypes.byref(out_pos), size)
    if ret not in (0, 1) or out_pos.value != size:
        return None
    return out.raw[:size]


def compress(data, dict_size: int = DEFAULT_DICT_SIZE, lc: int = 3, lp: int = 0, pb: int = 2,
             x86: bool = False) -> bytes:
    """Compress to EFI LZMA format (optionally with x86 BCJ pre-filter for LZMAF86)."""
    data = bytes(data)
    payload = x86_encode(data) if x86 else data
    header = bytes([(pb * 5 + lp) * 9 + lc]) + struct.pack("<IQ", dict_size, len(data))
    lib = _liblzma()
    if lib is not None:
        opt = _options(lc, lp, pb, dict_size, 9 | _PRESET_EXTREME)
        filters = (_LzmaFilter * 2)()
        filters[0].id = _FILTER_LZMA1EXT
        filters[0].options = ctypes.cast(ctypes.byref(opt), ctypes.c_void_p)
        filters[1].id = _VLI_UNKNOWN
        cap = len(payload) + len(payload) // 2 + 65536
        out = ctypes.create_string_buffer(cap)
        out_pos = ctypes.c_size_t(0)
        ret = lib.lzma_raw_buffer_encode(filters, None, payload, len(payload), out,
                                         ctypes.byref(out_pos), cap)
        if ret == 0:
            return header + out.raw[:out_pos.value]
    raw = lzma.compress(payload, format=lzma.FORMAT_ALONE, filters=[{
        "id": lzma.FILTER_LZMA1, "preset": 9 | lzma.PRESET_EXTREME,
        "dict_size": dict_size, "lc": lc, "lp": lp, "pb": pb}])
    return header + raw[HEADER_SIZE:]


# --------------------------------------------------------------------------
# x86 BCJ filter (used by LZMAF86 sections)
# --------------------------------------------------------------------------

_E8_RE = re.compile(b"[\xe8\xe9]")
_ALLOWED = (True, True, True, False, True, False, False, False)
_BITNUM = (0, 1, 2, 2, 3, 3, 3, 3)


def _x86_convert(buf: bytearray, encoding: bool, ip: int = 0) -> None:
    size = len(buf)
    if size < 5:
        return
    prev_mask = 0
    prev_pos = (ip - 5) & 0xFFFFFFFF
    limit = size - 5
    pos = 0
    search = _E8_RE.search
    while pos <= limit:
        m = search(buf, pos, limit + 1)
        if m is None:
            break
        pos = m.start()
        now = (ip + pos) & 0xFFFFFFFF
        offset = (now - prev_pos) & 0xFFFFFFFF
        prev_pos = now
        if offset > 5:
            prev_mask = 0
        else:
            for _ in range(offset):
                prev_mask = ((prev_mask & 0x77) << 1) & 0xFF
        b = buf[pos + 4]
        if (b == 0 or b == 0xFF) and _ALLOWED[(prev_mask >> 1) & 7] and (prev_mask >> 1) < 0x10:
            src = (b << 24) | (buf[pos + 3] << 16) | (buf[pos + 2] << 8) | buf[pos + 1]
            base = (ip + pos + 5) & 0xFFFFFFFF
            while True:
                if encoding:
                    dest = (src + base) & 0xFFFFFFFF
                else:
                    dest = (src - base) & 0xFFFFFFFF
                if prev_mask == 0:
                    break
                i = _BITNUM[(prev_mask >> 1) & 7]
                b = (dest >> (24 - i * 8)) & 0xFF
                if not (b == 0 or b == 0xFF):
                    break
                src = dest ^ ((1 << (32 - i * 8)) - 1)
            buf[pos + 4] = (~(((dest >> 24) & 1) - 1)) & 0xFF
            buf[pos + 3] = (dest >> 16) & 0xFF
            buf[pos + 2] = (dest >> 8) & 0xFF
            buf[pos + 1] = dest & 0xFF
            pos += 5
            prev_mask = 0
        else:
            pos += 1
            prev_mask |= 1
            if b == 0 or b == 0xFF:
                prev_mask |= 0x10


def x86_encode(data) -> bytes:
    buf = bytearray(data)
    _x86_convert(buf, True)
    return bytes(buf)


def x86_decode(data) -> bytes:
    buf = bytearray(data)
    _x86_convert(buf, False)
    return bytes(buf)


def decompress_f86(data) -> bytes:
    return x86_decode(decompress(data))
