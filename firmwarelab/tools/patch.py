"""Pattern-based binary patching, in the spirit of (and compatible with) UEFIPatch.

A patch script is a list of rules applied to the decoded contents of matching nodes.
Rules are expressed as JSON or a compact text format::

    # comment
    <GUID> <section-type|*> P:<find-hex>:<replace-hex>   # pattern replace (wildcards with '..')
    <GUID> <section-type|*> O:<hex-offset>:<replace-hex> # absolute offset in the node body

The engine works on the parsed tree, so patches reach code inside compressed volumes;
edited nodes are re-encoded on save by the builder.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from ..core import guids as G
from ..core.node import Node, NodeType
from .search import _pattern_to_regex


class PatchError(ValueError):
    pass


@dataclass
class Rule:
    guid: bytes | None
    section_type: int | None
    kind: str  # 'pattern' or 'offset'
    find: str
    replace: str
    count: int = 0  # 0 = all occurrences
    label: str = ""


@dataclass
class PatchResult:
    rule: Rule
    node: Node
    offset: int
    old: bytes
    new: bytes


_SEC_ALIASES = {"*": None, "any": None, "pe32": 0x10, "te": 0x12, "pei_depex": 0x1B, "dxe_depex": 0x13,
                "raw": 0x19, "ui": 0x15, "pe": 0x10}


def _replace_bytes(pattern: str) -> tuple[bytes, list[int]]:
    """Return (template bytes, positions of wildcard bytes to keep from original)."""
    pattern = pattern.replace(" ", "")
    if len(pattern) % 2:
        raise PatchError("Replacement hex must have an even number of nibbles")
    out = bytearray()
    keep = []
    for i in range(0, len(pattern), 2):
        b = pattern[i:i + 2]
        if b in ("..", "xx", "??"):
            out.append(0)
            keep.append(i // 2)
        else:
            out.append(int(b, 16))
    return bytes(out), keep


def parse_script(text: str) -> list[Rule]:
    text = text.strip()
    if text.startswith("["):
        return [_rule_from_dict(d) for d in json.loads(text)]
    rules = []
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 3:
            raise PatchError("Line %d: expected 'GUID SECTION ACTION'" % lineno)
        guid = None if parts[0] in ("*", "any") else G.str_to_guid(parts[0])
        st = parts[1].lower()
        sec = _SEC_ALIASES.get(st, None)
        if sec is None and st not in ("*", "any"):
            try:
                sec = int(st, 16)
            except ValueError:
                raise PatchError("Line %d: unknown section type %r" % (lineno, st))
        action = " ".join(parts[2:])
        m = re.match(r"([POA]):([0-9A-Fa-fxX.?]+):([0-9A-Fa-f. ]+)$", action)
        if not m:
            raise PatchError("Line %d: bad action %r" % (lineno, action))
        code, find, repl = m.groups()
        kind = "offset" if code in ("O", "A") else "pattern"
        rules.append(Rule(guid, sec, kind, find, repl.replace(" ", ""), label=line))
    return rules


def _rule_from_dict(d: dict) -> Rule:
    guid = d.get("guid")
    return Rule(G.str_to_guid(guid) if guid else None, d.get("section_type"),
                d.get("kind", "pattern"), d["find"], d["replace"], d.get("count", 0), d.get("label", ""))


def _target_nodes(root: Node, rule: Rule):
    for n in root.walk():
        if rule.guid is not None:
            f = n if n.type == NodeType.FILE else n.find_ancestor(NodeType.FILE)
            if f is None or f.meta.get("guid") != rule.guid:
                continue
        if rule.section_type is not None:
            if n.type != NodeType.SECTION or n.meta.get("type") != rule.section_type:
                continue
        elif rule.guid is not None and n.type != NodeType.SECTION:
            continue
        yield n


def _node_data(n: Node) -> bytes:
    return n.content if n.decoded is not None else n.body


def apply_rule(doc, rule: Rule, dry_run: bool = False) -> list[PatchResult]:
    results = []
    for n in list(_target_nodes(doc.root, rule)):
        n = doc.resolve(n.path()) or n
        data = bytearray(_node_data(n))
        changed = False
        if rule.kind == "pattern":
            rx = _pattern_to_regex(rule.find)
            repl, keep = _replace_bytes(rule.replace)
            if len(rx.pattern) and rx.pattern.count(b".") >= 0:
                pass
            pos = 0
            hits = 0
            while True:
                m = rx.search(bytes(data), pos)
                if not m:
                    break
                span = m.end() - m.start()
                if span != len(repl):
                    raise PatchError("Rule %r: find (%d bytes) and replace (%d bytes) length mismatch" % (
                        rule.label or rule.find, span, len(repl)))
                new = bytearray(repl)
                for k in keep:
                    new[k] = data[m.start() + k]
                old = bytes(data[m.start():m.end()])
                results.append(PatchResult(rule, n, m.start(), old, bytes(new)))
                if not dry_run:
                    data[m.start():m.end()] = new
                changed = True
                hits += 1
                pos = m.start() + span
                if rule.count and hits >= rule.count:
                    break
        else:
            off = int(rule.find, 16)
            repl, keep = _replace_bytes(rule.replace)
            if off + len(repl) > len(data):
                continue
            new = bytearray(repl)
            for k in keep:
                new[k] = data[off + k]
            results.append(PatchResult(rule, n, off, bytes(data[off:off + len(repl)]), bytes(new)))
            if not dry_run:
                data[off:off + len(repl)] = new
            changed = True
        if changed and not dry_run:
            doc.replace(n, bytes(data), mode="body")
    return results


def apply_script(doc, script: str, dry_run: bool = False) -> list[PatchResult]:
    rules = parse_script(script)
    out = []
    for rule in rules:
        out.extend(apply_rule(doc, rule, dry_run))
    return out
