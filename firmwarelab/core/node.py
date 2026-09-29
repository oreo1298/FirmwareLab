"""The firmware tree model.

Every parsed structure (image, region, volume, file, section, NVRAM variable, ...)
is a :class:`Node`.  A node owns a read-only view of its raw bytes, split into
header / body / tail parts, a list of children and type specific metadata.

Edits are performed copy-on-write (see :mod:`firmwarelab.tools.project`): the
path from the root to the edited node is cloned, so previous tree versions can be
kept for undo while unmodified subtrees are shared between versions.
"""

from __future__ import annotations

import enum
from typing import Any, Callable, Iterator


class NodeType(str, enum.Enum):
    IMAGE = "Image"
    CAPSULE = "Capsule"
    REGION = "Region"
    PADDING = "Padding"
    VOLUME = "Volume"
    FILE = "File"
    SECTION = "Section"
    FREE_SPACE = "Free space"
    NVRAM_STORE = "NVRAM store"
    NVRAM_VARIABLE = "NVRAM variable"
    MICROCODE = "Microcode"
    FIT = "FIT"
    ME = "ME structure"
    AMD = "AMD structure"
    OPTION_ROM = "Option ROM"
    BOOT_GUARD = "Boot Guard"
    DATA = "Data"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


class Node:
    __slots__ = (
        "type", "subtype", "name", "text", "info", "raw", "hdr_size", "tail_size",
        "offset", "in_decoded", "decoded", "meta", "messages", "children", "parent",
        "dirty", "fixed", "flags", "uid",
    )

    _uid_counter = 0

    def __init__(self, type: NodeType, subtype: str = "", name: str = "", text: str = "",
                 raw=b"", hdr_size: int = 0, tail_size: int = 0, offset: int = 0,
                 in_decoded: bool = False, fixed: bool = False):
        self.type = type
        self.subtype = subtype
        self.name = name
        self.text = text
        self.info: list[tuple[str, str]] = []
        self.raw = raw if isinstance(raw, memoryview) else memoryview(bytes(raw))
        self.hdr_size = hdr_size
        self.tail_size = tail_size
        self.offset = offset
        self.in_decoded = in_decoded
        self.decoded: bytes | None = None
        self.meta: dict[str, Any] = {}
        self.messages: list[str] = []
        self.children: list[Node] = []
        self.parent: Node | None = None
        self.dirty = False
        self.fixed = fixed
        self.flags: set[str] = set()
        Node._uid_counter += 1
        self.uid = Node._uid_counter

    # ------------------------------------------------------------------ data
    @property
    def size(self) -> int:
        return len(self.raw)

    @property
    def header(self) -> bytes:
        return bytes(self.raw[:self.hdr_size])

    @property
    def body(self) -> bytes:
        end = len(self.raw) - self.tail_size
        return bytes(self.raw[self.hdr_size:end])

    @property
    def body_view(self) -> memoryview:
        return self.raw[self.hdr_size:len(self.raw) - self.tail_size]

    @property
    def tail(self) -> bytes:
        if not self.tail_size:
            return b""
        return bytes(self.raw[len(self.raw) - self.tail_size:])

    @property
    def data(self) -> bytes:
        return bytes(self.raw)

    @property
    def body_size(self) -> int:
        return len(self.raw) - self.hdr_size - self.tail_size

    @property
    def content(self) -> bytes:
        """Decoded body for encapsulation nodes, raw body otherwise."""
        return self.decoded if self.decoded is not None else self.body

    def set_raw(self, raw, hdr_size: int | None = None, tail_size: int | None = None) -> None:
        self.raw = raw if isinstance(raw, memoryview) else memoryview(bytes(raw))
        if hdr_size is not None:
            self.hdr_size = hdr_size
        if tail_size is not None:
            self.tail_size = tail_size

    # ------------------------------------------------------------- location
    @property
    def abs_offset(self) -> int | None:
        """Offset within the opened file, or None if inside decompressed data."""
        off = 0
        n: Node | None = self
        while n is not None:
            if n.in_decoded:
                return None
            off += n.offset
            n = n.parent
        return off

    @property
    def is_compressed_context(self) -> bool:
        n: Node | None = self
        while n is not None:
            if n.in_decoded:
                return True
            n = n.parent
        return False

    def decoded_base(self) -> tuple["Node | None", int]:
        """Return (encapsulating ancestor or None for the file, offset in its data space)."""
        off = 0
        n: Node | None = self
        while n is not None:
            off += n.offset
            if n.in_decoded:
                return n.parent, off
            n = n.parent
        return None, off

    # --------------------------------------------------------------- tree
    def add(self, child: "Node") -> "Node":
        child.parent = self
        self.children.append(child)
        return child

    def insert(self, index: int, child: "Node") -> "Node":
        child.parent = self
        self.children.insert(index, child)
        return child

    @property
    def index(self) -> int:
        if self.parent is None:
            return 0
        for i, c in enumerate(self.parent.children):
            if c is self:
                return i
        return -1

    @property
    def depth(self) -> int:
        d = 0
        n = self.parent
        while n is not None:
            d += 1
            n = n.parent
        return d

    def root(self) -> "Node":
        n = self
        while n.parent is not None:
            n = n.parent
        return n

    def ancestors(self) -> Iterator["Node"]:
        n = self.parent
        while n is not None:
            yield n
            n = n.parent

    def find_ancestor(self, type: NodeType) -> "Node | None":
        for a in self.ancestors():
            if a.type == type:
                return a
        return None

    def walk(self) -> Iterator["Node"]:
        """Depth first pre-order traversal including self."""
        stack = [self]
        while stack:
            n = stack.pop()
            yield n
            stack.extend(reversed(n.children))

    def find(self, pred: Callable[["Node"], bool]) -> "Node | None":
        for n in self.walk():
            if pred(n):
                return n
        return None

    def find_all(self, pred: Callable[["Node"], bool]) -> list["Node"]:
        return [n for n in self.walk() if pred(n)]

    def path(self) -> list[int]:
        """Index path from the root to this node."""
        out = []
        n = self
        while n.parent is not None:
            out.append(n.index)
            n = n.parent
        return list(reversed(out))

    def path_names(self) -> str:
        parts = []
        n: Node | None = self
        while n is not None:
            parts.append(n.display_name)
            n = n.parent
        return " / ".join(reversed(parts))

    @staticmethod
    def by_path(root: "Node", path: list[int]) -> "Node | None":
        n = root
        for i in path:
            if i < 0 or i >= len(n.children):
                return None
            n = n.children[i]
        return n

    # --------------------------------------------------------------- misc
    @property
    def display_name(self) -> str:
        return self.text if (self.text and self.type in (NodeType.FILE,)) else self.name

    def add_info(self, key: str, value) -> None:
        self.info.append((key, str(value)))

    def get_info(self, key: str) -> str | None:
        for k, v in self.info:
            if k == key:
                return v
        return None

    def msg(self, text: str) -> None:
        self.messages.append(text)

    def clone(self) -> "Node":
        """Shallow copy: shares raw bytes and child nodes, copies containers."""
        n = Node.__new__(Node)
        for slot in Node.__slots__:
            setattr(n, slot, getattr(self, slot))
        n.info = list(self.info)
        n.meta = dict(self.meta)
        n.messages = list(self.messages)
        n.children = list(self.children)
        n.flags = set(self.flags)
        Node._uid_counter += 1
        n.uid = Node._uid_counter
        return n

    def relink(self) -> None:
        """Fix parent pointers of the whole subtree (after undo/redo or copy-on-write)."""
        stack = [self]
        while stack:
            n = stack.pop()
            for c in n.children:
                c.parent = n
                stack.append(c)

    def count(self) -> int:
        return sum(1 for _ in self.walk())

    def __repr__(self) -> str:
        off = self.abs_offset
        return "<Node %s/%s %r size=%X off=%s>" % (
            self.type.value, self.subtype, self.display_name, self.size,
            "%X" % off if off is not None else "-")


def mark_dirty(node: Node) -> None:
    n: Node | None = node
    while n is not None:
        n.dirty = True
        n = n.parent
