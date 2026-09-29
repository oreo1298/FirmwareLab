"""Parsing context shared by all format parsers."""

from __future__ import annotations

from dataclasses import dataclass

from ..core.node import Node


@dataclass
class ProtectedRange:
    start: int
    end: int  # exclusive, absolute file offsets
    label: str


@dataclass
class ParseOptions:
    decompress: bool = True
    parse_nvram: bool = True
    parse_ifr_hints: bool = True
    max_depth: int = 48


class ParseContext:
    """Carries options, address mapping and cross-structure findings during a parse."""

    def __init__(self, options: ParseOptions | None = None):
        self.options = options or ParseOptions()
        # Memory map: flash offsets [map_start, map_end) are mapped so that map_end == 4 GiB.
        self.map_start: int | None = None
        self.map_end: int | None = None
        self.protected: list[ProtectedRange] = []
        self.vendor_hints: set[str] = set()
        self.fit = None
        self.bootguard = {}
        self.depth = 0
        self.image_size = 0
        self.findings: dict[str, list[Node]] = {}

    def remember(self, kind: str, node: Node) -> None:
        self.findings.setdefault(kind, []).append(node)

    def address_of(self, abs_offset: int | None) -> int | None:
        if abs_offset is None or self.map_end is None or self.map_start is None:
            return None
        if not (self.map_start <= abs_offset < self.map_end):
            return None
        return 0x100000000 - (self.map_end - abs_offset)

    def offset_of_address(self, address: int) -> int | None:
        if self.map_end is None or self.map_start is None:
            return None
        off = self.map_end - (0x100000000 - address)
        if self.map_start <= off < self.map_end:
            return off
        return None
