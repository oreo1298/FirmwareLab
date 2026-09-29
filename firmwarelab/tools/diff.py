"""Structural and binary diff between two firmware images."""

from __future__ import annotations

from dataclasses import dataclass

from ..core.node import Node, NodeType


@dataclass
class DiffEntry:
    status: str  # 'added', 'removed', 'modified', 'moved'
    path: str
    kind: str
    detail: str = ""
    a: Node | None = None
    b: Node | None = None


def _key(n: Node) -> tuple:
    """A stable identity for a node within its parent, independent of offset."""
    if n.type == NodeType.FILE:
        return ("F", n.meta.get("guid"), n.meta.get("type"))
    if n.type == NodeType.SECTION:
        return ("S", n.meta.get("type"), n.meta.get("guid"), n.meta.get("subtype_guid"), n.display_name)
    if n.type == NodeType.VOLUME:
        return ("V", n.meta.get("fs_guid"), n.meta.get("fv_name"))
    if n.type == NodeType.NVRAM_VARIABLE:
        return ("N", n.meta.get("var_name"), n.meta.get("guid"), n.meta.get("current"))
    if n.type == NodeType.REGION:
        return ("R", n.subtype)
    return (n.type.value, n.subtype, n.display_name, n.size)


def _content(n: Node) -> bytes:
    return n.content if n.decoded is not None else (n.body if n.children else n.data)


def _label(n: Node) -> str:
    base = "%s %s" % (n.type.value, n.subtype)
    if n.display_name:
        base += " '%s'" % n.display_name
    return base


def diff_trees(a: Node, b: Node, path: str = "") -> list[DiffEntry]:
    out: list[DiffEntry] = []
    _diff_children(a, b, path or a.display_name, out)
    return out


def _diff_children(a: Node, b: Node, path: str, out: list[DiffEntry]) -> None:
    a_children = a.children
    b_children = b.children
    # match children by identity key, allowing duplicates by order
    used_b = [False] * len(b_children)
    b_index: dict = {}
    for i, c in enumerate(b_children):
        b_index.setdefault(_key(c), []).append(i)
    consumed = {}
    a_matched = [False] * len(a_children)
    matches = []
    for ai, ca in enumerate(a_children):
        k = _key(ca)
        lst = b_index.get(k, [])
        idx = None
        start = consumed.get(k, 0)
        for j in range(start, len(lst)):
            if not used_b[lst[j]]:
                idx = lst[j]
                consumed[k] = j + 1
                break
        if idx is not None:
            used_b[idx] = True
            a_matched[ai] = True
            matches.append((ca, b_children[idx], ai, idx))
    for ca, cb, ai, bi in matches:
        cp = path + " / " + (cb.display_name or cb.subtype or cb.type.value)
        if ca.children or cb.children:
            _diff_children(ca, cb, cp, out)
            if _content(ca)[:0] != b"":
                pass
        else:
            da, dbb = _content(ca), _content(cb)
            if da != dbb:
                out.append(DiffEntry("modified", cp, _label(cb),
                                     "size %Xh -> %Xh" % (len(da), len(dbb)) if len(da) != len(dbb)
                                     else "%d bytes differ" % sum(1 for x, y in zip(da, dbb) if x != y),
                                     ca, cb))
        if ca.abs_offset is not None and cb.abs_offset is not None and ca.offset != cb.offset:
            out.append(DiffEntry("moved", cp, _label(cb), "offset %Xh -> %Xh" % (ca.offset, cb.offset), ca, cb))
    for ai, ca in enumerate(a_children):
        if not a_matched[ai]:
            out.append(DiffEntry("removed", path + " / " + (ca.display_name or ca.subtype), _label(ca), "", ca, None))
    for bi, cb in enumerate(b_children):
        if not used_b[bi]:
            out.append(DiffEntry("added", path + " / " + (cb.display_name or cb.subtype), _label(cb), "", None, cb))


def summarize(entries: list[DiffEntry]) -> dict[str, int]:
    out = {"added": 0, "removed": 0, "modified": 0, "moved": 0}
    for e in entries:
        out[e.status] = out.get(e.status, 0) + 1
    return out


def format_text(entries: list[DiffEntry]) -> str:
    sym = {"added": "+", "removed": "-", "modified": "~", "moved": "»"}
    lines = []
    for e in entries:
        lines.append("%s %s [%s]%s" % (sym.get(e.status, "?"), e.path, e.kind,
                                       "  (%s)" % e.detail if e.detail else ""))
    s = summarize(entries)
    lines.append("")
    lines.append("%d added, %d removed, %d modified, %d moved" %
                 (s["added"], s["removed"], s["modified"], s["moved"]))
    return "\n".join(lines)
