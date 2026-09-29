"""Document model with copy-on-write editing, undo/redo and verified saving."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field

from ..core.binary import u24, u32
from ..core.node import Node, NodeType
from ..formats import area, ffs, image, microcode, nvram
from ..formats.context import ParseContext, ParseOptions
from .builder import Builder


class EditError(Exception):
    pass


@dataclass
class HistoryEntry:
    root: Node
    description: str


@dataclass
class VerifyReport:
    ok: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    changed_files: list[str] = field(default_factory=list)
    moved: list[str] = field(default_factory=list)


class Document:
    """An opened firmware file and its (editable) tree."""

    def __init__(self, data: bytes, path: str | None = None, options: ParseOptions | None = None):
        self.path = path
        self.options = options or ParseOptions()
        self.original = bytes(data)
        self.name = os.path.basename(path) if path else "untitled.bin"
        self.root, self.ctx = image.parse_image(self.original, self.name, self.options)
        self.undo_stack: list[HistoryEntry] = []
        self.redo_stack: list[HistoryEntry] = []
        self.listeners = []
        self.last_build_warnings: list = []

    @classmethod
    def open(cls, path: str, options: ParseOptions | None = None) -> "Document":
        with open(path, "rb") as fh:
            data = fh.read()
        return cls(data, path, options)

    # ------------------------------------------------------------------ state
    @property
    def modified(self) -> bool:
        return bool(self.undo_stack)

    def _notify(self, what: str) -> None:
        for cb in list(self.listeners):
            cb(what)

    def _commit(self, new_root: Node, description: str) -> None:
        self.undo_stack.append(HistoryEntry(self.root, description))
        self.redo_stack.clear()
        self.root = new_root
        self.root.relink()
        self._notify("edit")

    def undo(self) -> str | None:
        if not self.undo_stack:
            return None
        e = self.undo_stack.pop()
        self.redo_stack.append(HistoryEntry(self.root, e.description))
        self.root = e.root
        self.root.relink()
        self._notify("undo")
        return e.description

    def redo(self) -> str | None:
        if not self.redo_stack:
            return None
        e = self.redo_stack.pop()
        self.undo_stack.append(HistoryEntry(self.root, e.description))
        self.root = e.root
        self.root.relink()
        self._notify("redo")
        return e.description

    def history(self) -> list[str]:
        return [e.description for e in self.undo_stack]

    # ------------------------------------------------------------------ COW
    def _cow_path(self, node: Node) -> tuple[Node, Node]:
        """Clone the path root..node's parent. Returns (new_root, clone of node's parent)."""
        path = node.path()
        if node.root() is not self.root:
            raise EditError("Node does not belong to the current tree (stale reference)")
        new_root = self.root.clone()
        new_root.dirty = True
        cur = new_root
        for idx in path[:-1]:
            child = cur.children[idx].clone()
            child.dirty = True
            cur.children[idx] = child
            cur = child
        return new_root, cur

    def _swap(self, node: Node, replacement: Node | None, description: str) -> Node | None:
        if node.parent is None:
            if replacement is None:
                raise EditError("Cannot remove the root item")
            replacement.dirty = True
            self._commit(replacement, description)
            return replacement
        new_root, parent = self._cow_path(node)
        idx = node.path()[-1]
        if replacement is None:
            del parent.children[idx]
        else:
            replacement.dirty = True
            parent.children[idx] = replacement
        self._commit(new_root, description)
        return replacement

    def _insert_child(self, parent: Node, index: int, child: Node, description: str) -> Node:
        if parent.parent is None:
            new_root = self.root.clone()
            new_root.dirty = True
            holder = new_root
        else:
            new_root, pp = self._cow_path(parent)
            holder = parent.clone()
            holder.dirty = True
            pp.children[parent.path()[-1]] = holder
        child.dirty = True
        child.meta["inserted"] = True
        holder.children.insert(index, child)
        self._commit(new_root, description)
        return child

    def resolve(self, path: list[int]) -> Node | None:
        return Node.by_path(self.root, path)

    # ------------------------------------------------------------------ extraction
    @staticmethod
    def extract(node: Node, mode: str = "full") -> bytes:
        """mode: full (header+body+tail), body, uncompressed (decoded body), header."""
        if mode == "full":
            return node.data
        if mode == "body":
            return node.body
        if mode == "header":
            return node.header
        if mode == "uncompressed":
            return node.decoded if node.decoded is not None else node.body
        raise ValueError(mode)

    def extract_to(self, node: Node, path: str, mode: str = "full") -> None:
        with open(path, "wb") as fh:
            fh.write(self.extract(node, mode))

    # ------------------------------------------------------------------ parsing helpers
    def _scratch_ctx(self) -> ParseContext:
        ctx = ParseContext(self.options)
        ctx.map_start, ctx.map_end = self.ctx.map_start, self.ctx.map_end
        return ctx

    def parse_like(self, template: Node, data: bytes) -> Node:
        """Parse ``data`` as the same kind of structure as ``template``."""
        ctx = self._scratch_ctx()
        mv = memoryview(bytes(data))
        t = template.type
        node = None
        if t == NodeType.VOLUME:
            node = ffs.parse_volume(ctx, mv, template.offset, template.in_decoded)
            if node is None:
                raise EditError("Data is not a valid firmware volume")
        elif t == NodeType.FILE:
            vol = template.find_ancestor(NodeType.VOLUME)
            node = self._parse_file_bytes(ctx, vol, mv, template.offset, template.in_decoded)
        elif t == NodeType.SECTION:
            node = self._parse_section_bytes(ctx, mv, template.offset, template.in_decoded)
        elif t == NodeType.MICROCODE:
            node = microcode.parse_microcode(ctx, mv, template.offset, template.in_decoded)
            if node is None:
                raise EditError("Data is not a valid Intel microcode update")
        else:
            node = Node(template.type, template.subtype, template.name, template.text, mv,
                        hdr_size=min(template.hdr_size, len(mv)), tail_size=0,
                        offset=template.offset, in_decoded=template.in_decoded)
            node.meta = dict(template.meta)
            node.info = list(template.info)
            if t in (NodeType.REGION,) and template.subtype in ("BIOS", "BIOS2"):
                area.parse_raw_area(ctx, node, node.body_view, 0)
            elif t == NodeType.PADDING:
                node.subtype = area.padding_subtype(mv)
        node.offset = template.offset
        node.in_decoded = template.in_decoded
        node.fixed = node.fixed or template.fixed
        return node

    @staticmethod
    def _parse_file_bytes(ctx, vol: Node | None, mv, offset: int, in_decoded: bool) -> Node:
        if len(mv) < 24:
            raise EditError("Data is too small to be an FFS file")
        size = u24(mv, 20)
        attrs = mv[19]
        hsize = 24
        if attrs & 0x01 and size in (0, 0xFFFFFF) and len(mv) >= 32:
            size = int.from_bytes(bytes(mv[24:32]), "little")
            hsize = 32
        if size != len(mv):
            raise EditError("FFS file size field (%Xh) does not match data size (%Xh)" % (size, len(mv)))
        return ffs.parse_file(ctx, vol, mv, offset, hsize, in_decoded)

    @staticmethod
    def _parse_section_bytes(ctx, mv, offset: int, in_decoded: bool) -> Node:
        if len(mv) < 4:
            raise EditError("Data is too small to be a section")
        size = u24(mv, 0)
        hsize = 4
        if size == 0xFFFFFF:
            size = u32(mv, 4)
            hsize = 8
        if size != len(mv):
            raise EditError("Section size field (%Xh) does not match data size (%Xh)" % (size, len(mv)))
        return ffs.parse_section(ctx, mv, offset, hsize, in_decoded)

    def _rebuilt_bytes(self, node: Node) -> bytes:
        b = Builder()
        return b.build(node, None)

    # ------------------------------------------------------------------ edit operations
    def replace(self, node: Node, data: bytes, mode: str = "full", allow_guid_change: bool = False) -> Node:
        """Replace a node. mode 'full' takes a complete structure, 'body' only its body.

        For compressed/encoded sections the body is the *uncompressed* content; it is
        re-encoded with the section's original algorithm and parameters.
        """
        data = bytes(data)
        if node.parent is None and mode == "full":
            self.apply_raw_image(data, "Replace whole image")
            return self.root
        if mode == "body":
            data = self._full_from_body(node, data)
        if node.type == NodeType.NVRAM_VARIABLE:
            new = node.clone()
            new.children = []
            new.set_raw(data)
            new.meta["data_size"] = new.body_size
            self._reparse_variable_children(new)
        else:
            new = self.parse_like(node, data)
        if node.type == NodeType.FILE and not allow_guid_change and \
                new.meta.get("guid") != node.meta.get("guid") and "pad" not in node.flags:
            raise EditError("New file GUID %s differs from the original %s" % (new.name, node.name))
        if node.type in (NodeType.REGION, NodeType.PADDING, NodeType.VOLUME, NodeType.ME, NodeType.FREE_SPACE) \
                and len(new.raw) != node.size:
            raise EditError("Replacement must be exactly %Xh bytes (got %Xh)" % (node.size, len(new.raw)))
        new.meta["replaced"] = True
        return self._swap(node, new, "Replace %s" % node.display_name)

    def _full_from_body(self, node: Node, body: bytes) -> bytes:
        import struct
        b = Builder()
        t = node.type
        if t == NodeType.SECTION:
            hdr = bytearray(node.header)
            stype = node.meta.get("type")
            hs = 8 if node.meta.get("ext") else 4
            if node.decoded is not None:
                payload = b._encode(node, body)
            else:
                payload = body
            if stype == 0x01 and len(hdr) >= hs + 5:
                struct.pack_into("<I", hdr, hs, len(body))
            if stype == 0x02 and node.meta.get("crc32") and len(hdr) >= hs + 24:
                from ..core.binary import crc32
                struct.pack_into("<I", hdr, hs + 20, crc32(payload))
            return b._section_with_size(node, hdr, payload)
        if t in (NodeType.FILE, NodeType.NVRAM_VARIABLE):
            tmp = node.clone()
            tmp.children = []
            tmp.decoded = None
            tmp.meta.pop("nvar_store", None)
            tmp.set_raw(node.header + body + node.tail)
            tmp.dirty = True
            if t == NodeType.FILE:
                return b._file(tmp, None, large_ok=True)
            return b._nvram_variable(tmp, None)
        if len(body) != node.body_size and t != NodeType.DATA:
            raise EditError("Body must keep its size (%Xh bytes)" % node.body_size)
        return node.header + body + node.tail

    def _reparse_variable_children(self, var: Node) -> None:
        body = var.body_view
        if var.meta.get("kind") == "nvar" and len(body) >= 10 and bytes(body[:4]) == b"NVAR":
            nvram.parse_nvar_store(None, var, body, var.hdr_size)

    def set_variable_data(self, var: Node, data: bytes) -> Node:
        if var.type != NodeType.NVRAM_VARIABLE:
            raise EditError("Not an NVRAM variable")
        return self.replace(var, data, mode="body")

    def patch(self, node: Node, offset: int, new_bytes: bytes, description: str | None = None) -> Node:
        """Overwrite bytes inside a node (same size), e.g. from the hex editor."""
        raw = bytearray(node.data)
        if offset < 0 or offset + len(new_bytes) > len(raw):
            raise EditError("Patch outside of the item")
        raw[offset:offset + len(new_bytes)] = new_bytes
        if node.type == NodeType.NVRAM_VARIABLE:
            new = node.clone()
            new.children = []
            new.set_raw(bytes(raw))
            self._reparse_variable_children(new)
        else:
            new = self.parse_like(node, bytes(raw))
        new.meta["replaced"] = True
        return self._swap(node, new, description or "Patch %s" % node.display_name)

    def remove(self, node: Node) -> None:
        if node.parent is None:
            raise EditError("Cannot remove the root item")
        if node.type in (NodeType.REGION, NodeType.IMAGE):
            raise EditError("Regions can not be removed; replace their contents instead")
        parent = node.parent
        if node.type == NodeType.VOLUME and parent.type in (NodeType.REGION, NodeType.IMAGE, NodeType.SECTION, NodeType.FILE) \
                and not node.in_decoded and parent.type != NodeType.SECTION:
            # volumes in fixed layouts are replaced by empty padding
            pad = area.make_padding(memoryview(b"\xff" * node.size), node.offset, node.in_decoded)
            self._swap(node, pad, "Remove %s" % node.display_name)
            return
        if node.fixed and node.type == NodeType.FILE:
            raise EditError("%s is a fixed file (e.g. volume top file) and can not be removed" % node.display_name)
        if node.type == NodeType.NVRAM_VARIABLE and node.meta.get("kind") == "nvar":
            raise EditError("Removing NVAR entries is not supported; clear their valid flag or edit data instead")
        self._swap(node, None, "Remove %s" % node.display_name)

    def insert(self, target: Node, data: bytes, where: str = "into") -> Node:
        """Insert an FFS file or section. where: into (append to container), before, after."""
        if where == "into":
            parent = target
            if parent.type == NodeType.VOLUME:
                index = len(parent.children)
                # before free space / VTF / trailing data
                while index > 0 and (parent.children[index - 1].type in (NodeType.FREE_SPACE, NodeType.DATA)
                                     or "vtf" in parent.children[index - 1].flags):
                    index -= 1
            else:
                index = len(parent.children)
        else:
            parent = target.parent
            if parent is None:
                raise EditError("Cannot insert next to the root item")
            index = target.index + (1 if where == "after" else 0)
        ctx = self._scratch_ctx()
        mv = memoryview(bytes(data))
        if parent.type == NodeType.VOLUME:
            if not parent.meta.get("ffs_version"):
                raise EditError("Files can only be inserted into FFS volumes")
            child = self._parse_file_bytes(ctx, parent, mv, 0, parent.in_decoded or parent.is_compressed_context)
            guid = child.meta["guid"]
            if any(c.type == NodeType.FILE and c.meta.get("guid") == guid and "pad" not in c.flags for c in parent.children):
                child.msg("A file with this GUID already exists in the volume")
        elif parent.type in (NodeType.FILE, NodeType.SECTION):
            if parent.type == NodeType.FILE and parent.children and parent.children[0].type != NodeType.SECTION:
                raise EditError("This file does not contain sections")
            child = self._parse_section_bytes(ctx, mv, 0, parent.decoded is not None)
            child.in_decoded = parent.decoded is not None
        else:
            raise EditError("Can not insert into %s" % parent.type.value)
        child.offset = 0
        return self._insert_child(parent, index, child, "Insert %s" % child.display_name)

    def rebuild(self, node: Node) -> None:
        """Force reconstruction of a node (recompute checksums/sizes)."""
        new = node.clone()
        new.meta["force_recompress"] = True
        self._swap(node, new, "Rebuild %s" % node.display_name)

    def apply_raw_image(self, data: bytes, description: str) -> None:
        """Replace the whole image with new bytes (used by patchers and descriptor tools)."""
        root, ctx = image.parse_image(data, self.name, self.options)
        root.dirty = False
        self.undo_stack.append(HistoryEntry(self.root, description))
        self.redo_stack.clear()
        self.root = root
        self.root.meta["raw_replaced"] = True
        self.ctx = ctx
        self._notify("edit")

    # ------------------------------------------------------------------ build & save
    def build(self) -> bytes:
        b = Builder()
        b.ctx = self.ctx
        data = b.build(self.root, 0)
        self.last_build_warnings = b.warnings
        self._last_moved = b.moved
        return data

    def verify(self, data: bytes) -> VerifyReport:
        """Re-parse built data and compare with the edited tree."""
        rep = VerifyReport(True)
        for node, text in self.last_build_warnings:
            rep.warnings.append(("%s: %s" % (node.path_names(), text)) if node is not None else text)
        for f, delta in getattr(self, "_last_moved", []):
            rep.moved.append("%s moved by %+Xh bytes%s" % (f.display_name, delta, " (rebased)" if "has_xip" in f.flags else ""))
        try:
            new_root, new_ctx = image.parse_image(data, self.name, self.options)
        except Exception as e:  # pragma: no cover - defensive
            rep.ok = False
            rep.errors.append("Rebuilt image can not be parsed: %s" % e)
            return rep
        if len(data) != len(self.original) and self.root.type != NodeType.CAPSULE:
            rep.warnings.append("Image size changed from %Xh to %Xh bytes" % (len(self.original), len(data)))
        old_msgs = _message_set(self.root)
        new_msgs = _message_set(new_root)
        for m in sorted(new_msgs - old_msgs):
            if "checksum" in m.lower() or "invalid" in m.lower() or "overflow" in m.lower():
                rep.errors.append(m)
                rep.ok = False
            else:
                rep.warnings.append(m)
        old_files = _file_map(image.parse_image(self.original, self.name, self.options)[0])
        new_files = _file_map(new_root)
        for key, crc in new_files.items():
            if key not in old_files:
                rep.changed_files.append("added: %s" % key[1])
            elif old_files[key] != crc:
                rep.changed_files.append("modified: %s" % key[1])
        for key in old_files:
            if key not in new_files:
                rep.changed_files.append("removed: %s" % key[1])
        protected = [n for n in self.root.walk() if n.dirty and "protected" in n.flags and n.type == NodeType.FILE]
        for n in protected:
            rep.warnings.append("%s lies in a Boot Guard protected range; the platform may refuse to boot" % n.display_name)
        return rep

    def save(self, path: str | None = None, backup: bool = True, verify: bool = True,
             reload: bool = True) -> VerifyReport:
        path = path or self.path
        if not path:
            raise EditError("No file name given")
        data = self.build()
        rep = self.verify(data) if verify else VerifyReport(True)
        if not rep.ok:
            return rep
        if backup and os.path.exists(path) and path == self.path:
            shutil.copy2(path, path + ".bak")
        with open(path, "wb") as fh:
            fh.write(data)
        if reload:
            self.path = path
            self.name = os.path.basename(path)
            self.original = data
            self.root, self.ctx = image.parse_image(data, self.name, self.options)
            self.undo_stack.clear()
            self.redo_stack.clear()
            self._notify("reload")
        return rep


def _message_set(root: Node) -> set[str]:
    out = set()
    for n in root.walk():
        for m in n.messages:
            out.add("%s: %s" % (n.path_names(), m))
    return out


def _file_map(root: Node) -> dict:
    import zlib
    out = {}
    counts: dict = {}
    for n in root.walk():
        if n.type == NodeType.FILE and "pad" not in n.flags:
            name = n.path_names()
            k = (n.meta.get("guid"), name)
            counts[k] = counts.get(k, 0) + 1
            out[(k[0], "%s#%d" % (name, counts[k]) if counts[k] > 1 else name)] = zlib.crc32(n.content if n.decoded else n.body)
    return out
