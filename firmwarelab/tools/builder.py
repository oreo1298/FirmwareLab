"""Reconstruction of modified firmware trees into bytes.

Unmodified subtrees are emitted verbatim. Modified containers are rebuilt from their
children with sizes, checksums, compression and alignment regenerated.

Volume layout is *stable*: every file is kept at its original offset whenever that
is possible (gaps are filled with pad files), so an edit only moves the files that
really have to move. Execute-in-place PEI images that move are rebased, and the
PEI core entry point stored in the volume top file is patched accordingly.
"""

from __future__ import annotations

import struct
import zlib

from .. import codecs
from ..core import guids as G
from ..core.binary import align_up, checksum16, crc32, p24, p32
from ..core.node import Node, NodeType
from ..formats import ffs, nvram
from ..formats import pe as pemod


class BuildError(Exception):
    def __init__(self, message: str, node: Node | None = None):
        super().__init__(message)
        self.node = node


FIXED_SIZE_TYPES = {NodeType.IMAGE, NodeType.REGION, NodeType.ME, NodeType.PADDING, NodeType.FREE_SPACE}


class Builder:
    def __init__(self):
        self.warnings: list[tuple[Node | None, str]] = []
        self.moved: list[tuple[Node, int]] = []

    def warn(self, node, text):
        self.warnings.append((node, text))

    # ------------------------------------------------------------------
    def build(self, node: Node, shift: int | None = 0) -> bytes:
        if not node.dirty and not (shift and ("has_xip" in node.flags or "xip" in node.flags)):
            return bytes(node.raw)
        t = node.type
        if t == NodeType.VOLUME:
            return self._volume(node, shift)
        if t == NodeType.FILE:
            return self._file(node, shift)
        if t == NodeType.SECTION:
            return self._section(node, shift)
        if t == NodeType.NVRAM_STORE:
            return self._nvram_store(node, shift)
        if t == NodeType.NVRAM_VARIABLE:
            return self._nvram_variable(node, shift)
        if t == NodeType.CAPSULE:
            return self._capsule(node, shift)
        return self._generic(node, shift)

    # ------------------------------------------------------------------
    def _concat(self, parent: Node, shift: int | None, start: int, align: int = 1,
                decoded: bool = False) -> bytes:
        """Concatenate rebuilt children; ``start`` is where the first child lands in parent."""
        out = bytearray()
        for c in parent.children:
            if align > 1:
                out += bytes(align_up(len(out), align) - len(out))
            new_pos = start + len(out)
            if decoded or shift is None:
                cs = None
            else:
                cs = shift + (new_pos - c.offset)
            out += self.build(c, cs)
        return bytes(out)

    def _generic(self, node: Node, shift):
        if not node.children:
            return bytes(node.raw)
        decoded = node.decoded is not None
        body = self._concat(node, shift, node.hdr_size, decoded=decoded)
        if node.meta.get("nvar_store"):
            body = self._nvar_area(node, node.body_size, node.hdr_size)
        if not decoded and node.type in FIXED_SIZE_TYPES and len(body) != node.body_size:
            raise BuildError("%s size changed from %Xh to %Xh bytes; the layout of this area is fixed" % (
                node.name, node.body_size, len(body)), node)
        return node.header + body + node.tail

    def _capsule(self, node: Node, shift):
        body = self._concat(node, shift, node.hdr_size)
        hdr = bytearray(node.header)
        total = len(hdr) + len(body)
        cap = node.meta.get("capsule")
        if cap is not None and cap.guid == G.TOSHIBA_CAPSULE_GUID:
            struct.pack_into("<I", hdr, 20, total)
        elif len(hdr) >= 28:
            struct.pack_into("<I", hdr, 24, total)
        return bytes(hdr) + body

    # ------------------------------------------------------------------ volumes
    def _volume(self, node: Node, shift):
        hdr = bytearray(node.header)
        body_size = node.size - node.hdr_size
        empty = node.meta["empty"]
        if node.meta.get("ffs_version"):
            body = self._layout_files(node, shift, body_size)
        else:
            body = self._concat(node, shift, node.hdr_size)
            if len(body) > body_size:
                raise BuildError("Volume %s overflows by %Xh bytes" % (node.name, len(body) - body_size), node)
            body += bytes([empty]) * (body_size - len(body))
        if node.meta.get("header_dirty"):
            hl = node.meta["hdr_len"]
            struct.pack_into("<H", hdr, 50, 0)
            struct.pack_into("<H", hdr, 50, checksum16(hdr[:hl]))
        return bytes(hdr) + body

    @staticmethod
    def _place(cur: int, hsize: int, align: int, preferred: int | None) -> int:
        def ok(p):
            return p % 8 == 0 and (p + hsize) % align == 0 and (p == cur or p - cur >= 24)
        if preferred is not None and preferred >= cur and ok(preferred):
            return preferred
        if ok(cur):
            return cur
        p = align_up(cur + 24, 8)
        if align > 8:
            p += (-(p + hsize)) % align
        return p

    def _layout_files(self, vol: Node, shift, body_size: int) -> bytes:
        empty = vol.meta["empty"]
        rev = vol.meta["revision"]
        ffs3 = vol.meta["ffs_version"] == 3
        hs = vol.hdr_size
        files = [c for c in vol.children if c.type == NodeType.FILE and "pad" not in c.flags]
        data_nodes = [c for c in vol.children if c.type == NodeType.DATA]
        pad_guid = next((bytes(c.raw[:16]) for c in vol.children if "pad" in c.flags), bytes([empty]) * 16)
        vtf = None
        if files and "vtf" in files[-1].flags:
            vtf = files.pop()
        end_limit = hs + body_size
        if data_nodes:
            end_limit = min(end_limit, min(d.offset for d in data_nodes))
        out = bytearray()
        pei_moves = []
        for f in files:
            cur = hs + len(out)
            align = max(f.meta.get("alignment", 1), 1)
            hsize = f.hdr_size
            preferred = None if f.meta.get("inserted") else f.offset
            pos = self._place(cur, hsize, align, preferred)
            if pos > cur:
                out += ffs.make_pad_file(pos - cur, empty, rev, pad_guid)
            fshift = None if shift is None else shift + (pos - f.offset)
            fb = self._file(f, fshift, target_empty=empty, target_rev=rev, large_ok=ffs3) \
                if (f.dirty or fshift or f.meta.get("empty") != empty) else bytes(f.raw)
            if fshift and not f.meta.get("inserted"):
                self.moved.append((f, fshift))
                if f.meta.get("type") == 0x04:
                    pei_moves.append((f, fshift))
            out += fb
            out += bytes([empty]) * (align_up(len(out), 8) - len(out))
        if vtf is not None:
            vb = bytearray(self.build(vtf, None if shift is None else shift) if vtf.dirty else bytes(vtf.raw))
            if pei_moves:
                vb = bytearray(self._patch_vtf(vtf, vb, pei_moves, empty, rev))
            vtf_pos = hs + body_size - len(vb)
            gap = vtf_pos - (hs + len(out))
            if gap < 0:
                raise BuildError("Volume %s is too small: files overlap the volume top file by %Xh bytes" % (
                    vol.name, -gap), vol)
            if 0 < gap < 24:
                raise BuildError("Volume %s: %Xh bytes left before the volume top file, a pad file needs 24" % (
                    vol.name, gap), vol)
            if gap:
                out += ffs.make_pad_file(gap, empty, rev, pad_guid)
            out += vb
        else:
            if pei_moves:
                self.warn(vol, "PEI core moved but no volume top file found in the same volume")
            limit = end_limit - hs
            if len(out) > limit:
                raise BuildError("Volume %s overflows by %Xh bytes" % (vol.name, len(out) - limit), vol)
            for d in data_nodes:
                rel = d.offset - hs
                out += bytes([empty]) * (rel - len(out))
                out += bytes(d.raw)
            if len(out) > body_size:
                raise BuildError("Volume %s overflows by %Xh bytes" % (vol.name, len(out) - body_size), vol)
            out += bytes([empty]) * (body_size - len(out))
        return bytes(out)

    def _patch_vtf(self, vtf: Node, vb: bytearray, moves, empty, rev) -> bytes:
        for f, delta in moves:
            sec = next((s for s in f.walk() if "xip" in s.flags and "pe" in s.meta), None)
            if sec is None:
                continue
            info: pemod.PeInfo = sec.meta["pe"]
            old_entry = (info.image_base + info.entry_point) & 0xFFFFFFFF
            new_entry = (old_entry + delta) & 0xFFFFFFFF
            needle = p32(old_entry)
            body_start = vtf.hdr_size
            idx = bytes(vb).find(needle, body_start)
            if idx < 0:
                self.warn(vtf, "PEI core entry point %08Xh not found in the volume top file" % old_entry)
                continue
            while idx >= 0:
                vb[idx:idx + 4] = p32(new_entry)
                idx = bytes(vb).find(needle, idx + 4)
            self.warn(vtf, "PEI core entry point in volume top file updated %08Xh -> %08Xh" % (old_entry, new_entry))
        hdr = bytearray(vb[:vtf.hdr_size])
        body = bytes(vb[vtf.hdr_size:len(vb) - vtf.tail_size])
        ffs.finalize_file_header(hdr, body, empty, rev, state=hdr[23], fixed_checksum=vtf.meta.get("fixed_checksum"))
        return bytes(hdr) + body + bytes(vb[len(vb) - vtf.tail_size:])

    # ------------------------------------------------------------------ files
    def _file(self, node: Node, shift, target_empty: int | None = None, target_rev: int | None = None,
              large_ok: bool = False) -> bytes:
        empty = node.meta.get("empty", 0xFF) if target_empty is None else target_empty
        rev = node.meta.get("revision", 2) if target_rev is None else target_rev
        hsize = node.hdr_size
        if node.meta.get("nvar_store"):
            body = self._nvar_area(node, node.body_size, hsize)
        elif node.children:
            if node.children[0].type == NodeType.SECTION or any(c.type == NodeType.SECTION for c in node.children):
                body = self._concat(node, shift, hsize, align=4)
            else:
                body = self._concat(node, shift, hsize)
                if len(body) != node.body_size and node.meta.get("type") in (0x01, 0x00):
                    pass  # raw files may change size
        else:
            body = node.body
        hdr = bytearray(node.header)
        state = hdr[23]
        if node.meta.get("empty", empty) != empty:
            state ^= 0xFF
        tail = node.tail_size
        size = hsize + len(body) + tail
        if hsize == 24 and size > 0xFFFFFF:
            if not large_ok:
                raise BuildError("File %s is too large for an FFSv2 volume (%Xh bytes)" % (node.display_name, size), node)
            hdr = hdr[:20] + p24(0xFFFFFF) + bytes([state]) + struct.pack("<Q", size + 8)
            hdr[19] |= 0x01
            size += 8
        elif hsize == 32:
            hdr[20:23] = p24(0xFFFFFF)
            struct.pack_into("<Q", hdr, 24, size)
        else:
            hdr[20:23] = p24(size)
        ffs.finalize_file_header(hdr, body, empty, rev, state=state,
                                 fixed_checksum=node.meta.get("fixed_checksum"))
        out = bytes(hdr) + body
        if tail:
            out += struct.pack("<H", (~struct.unpack_from("<H", hdr, 16)[0]) & 0xFFFF)
        return out

    # ------------------------------------------------------------------ sections
    def _section(self, node: Node, shift) -> bytes:
        stype = node.meta.get("type")
        hdr = bytearray(node.header)
        hs_common = 8 if node.meta.get("ext") else 4
        body: bytes
        if node.meta.get("nvar_store"):
            body = self._nvar_area(node, node.body_size, node.hdr_size)
        elif node.decoded is not None:
            inner = self._concat(node, None, 0, align=4, decoded=True)
            if inner == node.decoded and not node.meta.get("force_recompress"):
                body = node.body
            else:
                body = self._encode(node, inner)
                if stype == 0x01 and len(hdr) >= hs_common + 5:
                    struct.pack_into("<I", hdr, hs_common, len(inner))
        elif node.children:
            if stype == 0x17:
                body = self._concat(node, shift, node.hdr_size)
            else:
                body = self._concat(node, shift, node.hdr_size, align=4)
            if stype == 0x01 and len(hdr) >= hs_common + 5:
                struct.pack_into("<I", hdr, hs_common, len(body))
        elif shift and "xip" in node.flags:
            try:
                body = pemod.rebase(node.body, shift)
            except pemod.PeError as e:
                raise BuildError("Cannot rebase %s by %Xh: %s" % (node.path_names(), shift, e), node)
        else:
            body = node.body
        if stype == 0x02 and node.meta.get("crc32") and len(hdr) >= hs_common + 24:
            struct.pack_into("<I", hdr, hs_common + 20, crc32(body))
        if stype == 0x02 and "signed" in node.flags and body != node.body:
            self.warn(node, "Signed GUID defined section content changed; its signature is no longer valid")
        return self._section_with_size(node, hdr, body)

    @staticmethod
    def _section_with_size(node: Node, hdr: bytearray, body: bytes) -> bytes:
        ext = node.meta.get("ext")
        total = len(hdr) + len(body)
        if ext:
            hdr[0:3] = p24(0xFFFFFF)
            struct.pack_into("<I", hdr, 4, total)
        elif total >= 0xFFFFFF:
            # switch to the extended header, shifting type specific fields
            hdr = bytearray(p24(0xFFFFFF) + hdr[3:4] + p32(total + 4) + hdr[4:])
            if node.meta.get("type") == 0x02:
                struct.pack_into("<H", hdr, 8 + 16, struct.unpack_from("<H", hdr, 8 + 16)[0] + 4)
            total += 4
        else:
            hdr[0:3] = p24(total)
        return bytes(hdr) + body

    def _encode(self, node: Node, inner: bytes) -> bytes:
        algo = node.meta.get("algorithm")
        params = dict(node.meta.get("params") or {})
        try:
            if node.meta.get("zlib_amd"):
                comp = zlib.compress(inner, 9)
                hdr = bytearray(params.get("amd_header") or bytes(0x100))
                if len(hdr) >= 0x18:
                    struct.pack_into("<I", hdr, 0x14, len(comp))
                    return bytes(hdr) + comp
                return comp
            if algo == codecs.BROTLI and params.get("scratch_size", 0) < len(inner):
                self.warn(node, "Brotli scratch buffer size kept from original; verify the image boots")
            return codecs.compress(algo, inner, params)
        except codecs.CodecError as e:
            raise BuildError("Cannot recompress %s: %s" % (node.path_names(), e), node)

    # ------------------------------------------------------------------ NVRAM
    def _nvar_area(self, node: Node, body_size: int, start: int) -> bytes:
        parts = [(c, self.build(c, None)) for c in node.children]
        try:
            return nvram.layout_store(node, parts, body_size)
        except ValueError as e:
            raise BuildError(str(e), node)

    def _nvram_store(self, node: Node, shift) -> bytes:
        kind = node.meta.get("kind")
        body_size = node.body_size
        if kind in ("vss", "vss2"):
            parts = [(c, self.build(c, None)) for c in node.children]
            try:
                body = nvram.layout_store(node, parts, body_size, align=node.meta.get("align", 1))
            except ValueError as e:
                raise BuildError(str(e), node)
            return node.header + body
        if kind == "evsa":
            parts = [(c, self.build(c, None)) for c in node.children]
            body = nvram.layout_store(node, parts, body_size)
            return node.header + body
        return self._generic(node, shift)

    def _nvram_variable(self, node: Node, shift) -> bytes:
        kind = node.meta.get("kind")
        if node.children and node.meta.get("nvar_store"):
            body = self._nvar_area(node, node.body_size, node.hdr_size)
        else:
            body = node.body
        try:
            if kind == "vss":
                return nvram.build_vss_variable(node, body)
            if kind == "nvar":
                return nvram.build_nvar_entry(node, body)
            if kind == "evsa":
                return nvram.build_evsa_entry(node, body)
        except ValueError as e:
            raise BuildError(str(e), node)
        return node.header + body + node.tail


def build(root: Node) -> tuple[bytes, list]:
    b = Builder()
    data = b.build(root, 0)
    return data, b.warnings
