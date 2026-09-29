"""Searching a parsed tree by GUID, text, hex pattern or wildcard byte pattern."""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..core import guids as G
from ..core.node import Node, NodeType


@dataclass
class Match:
    node: Node
    where: str  # 'header', 'body', 'name', 'info'
    offset: int  # byte offset within the matched region, -1 for metadata matches
    context: str


def _pattern_to_regex(pattern: str) -> re.Pattern:
    """Compile a hex pattern with '..' or 'xx' wildcards (nibble-level not supported)."""
    pattern = pattern.replace(" ", "").replace("-", "")
    if len(pattern) % 2:
        raise ValueError("Hex pattern must have an even number of nibbles")
    parts = []
    for i in range(0, len(pattern), 2):
        byte = pattern[i:i + 2]
        if byte in ("..", "xx", "??", "**"):
            parts.append(b".")
        else:
            try:
                parts.append(re.escape(bytes([int(byte, 16)])))
            except ValueError:
                raise ValueError("Invalid hex byte %r in pattern" % byte)
    return re.compile(b"".join(parts), re.DOTALL)


def search_guid(root: Node, guid) -> list[Match]:
    if isinstance(guid, str):
        guid = G.str_to_guid(guid)
    out = []
    for n in root.walk():
        if n.meta.get("guid") == guid:
            out.append(Match(n, "name", 0, "GUID match"))
        elif n.type == NodeType.SECTION and n.meta.get("subtype_guid") == guid:
            out.append(Match(n, "name", 0, "subtype GUID match"))
        elif n.type == NodeType.VOLUME and guid in (n.meta.get("fs_guid"), n.meta.get("fv_name")):
            out.append(Match(n, "name", 0, "volume GUID match"))
    return out


def search_text(root: Node, text: str, case_sensitive: bool = False,
                unicode: bool = True, ascii_: bool = True) -> list[Match]:
    needles = []
    if ascii_:
        needles.append(text.encode("ascii", "ignore"))
    if unicode:
        needles.append(text.encode("utf-16-le"))
    out = []
    for n in root.walk():
        if n.children and n.type not in (NodeType.SECTION,):
            continue
        data = n.content if n.decoded is not None else n.body
        hay = data if case_sensitive else bytes(data).lower()
        for raw in needles:
            needle = raw if case_sensitive else raw.lower()
            if not needle:
                continue
            pos = hay.find(needle)
            if pos >= 0:
                out.append(Match(n, "body", pos, _snippet(data, pos, len(needle))))
                break
    return out


def search_hex(root: Node, pattern: str, search_headers: bool = True) -> list[Match]:
    rx = _pattern_to_regex(pattern)
    out = []
    for n in root.walk():
        data = n.content if n.decoded is not None else (n.body if n.children else n.data)
        m = rx.search(bytes(data))
        if m:
            out.append(Match(n, "body", m.start(), _hex_snippet(data, m.start(), m.end() - m.start())))
    return out


def search_name(root: Node, text: str) -> list[Match]:
    t = text.lower()
    out = []
    for n in root.walk():
        if t in n.name.lower() or t in n.text.lower():
            out.append(Match(n, "name", -1, n.display_name))
    return out


def _snippet(data, pos, length, radius=16):
    start = max(0, pos - radius)
    chunk = bytes(data[start:pos + length + radius])
    return "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)


def _hex_snippet(data, pos, length, radius=8):
    start = max(0, pos - radius)
    chunk = bytes(data[start:pos + length + radius])
    return " ".join("%02X" % b for b in chunk)
