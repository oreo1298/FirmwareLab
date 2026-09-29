"""Locate HII string and form packages inside firmware modules."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.node import Node, NodeType
from .ifr import FormPackage, FormSet, build_formsets, find_form_packages
from .strings import StringPackage, find_string_packages

SCANNED_SECTION_TYPES = {0x10, 0x11, 0x12, 0x18, 0x19}


@dataclass
class HiiModule:
    file: Node
    section: Node
    string_packages: list[StringPackage]
    form_packages: list[FormPackage]
    formsets: list[FormSet] = field(default_factory=list)
    pairing: dict[int, StringPackage | None] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.file.display_name

    @property
    def languages(self) -> list[str]:
        seen = []
        for p in self.string_packages:
            if p.language not in seen:
                seen.append(p.language)
        return seen

    @property
    def section_path(self) -> list[int]:
        return self.section.path()


def _referenced_ids(pkg: FormPackage) -> set[int]:
    ids = set()
    for op in pkg.ops:
        for k in ("prompt", "help", "title", "option", "text2", "error", "warning"):
            v = op.fields.get(k)
            if isinstance(v, int) and v:
                ids.add(v)
    return ids


def pick_strings(pkg: FormPackage, candidates: list[StringPackage], language: str = "en-US") -> StringPackage | None:
    if not candidates:
        return None
    langs = [c for c in candidates if c.language == language]
    if not langs:
        langs = [c for c in candidates if c.language.split("-")[0] == language.split("-")[0]]
    if not langs:
        langs = [c for c in candidates if not c.language.startswith("x-")] or candidates
    if len(langs) == 1:
        return langs[0]
    refs = _referenced_ids(pkg)

    def score(c: StringPackage):
        cov = sum(1 for r in refs if r in c.strings)
        return (cov, -abs(c.offset - pkg.offset))

    return max(langs, key=score)


def scan_blob(blob) -> tuple[list[StringPackage], list[FormPackage]]:
    forms = find_form_packages(blob)
    if not forms:
        return [], []
    return find_string_packages(blob), forms


def scan(root: Node, language: str = "en-US") -> list[HiiModule]:
    modules = []
    for n in root.walk():
        if n.type != NodeType.SECTION or n.meta.get("type") not in SCANNED_SECTION_TYPES or n.children:
            continue
        body = n.body
        if len(body) < 64 or b"\x02\x0e" not in body:
            continue
        strings, forms = scan_blob(body)
        if not forms:
            continue
        f = n.find_ancestor(NodeType.FILE)
        mod = HiiModule(f if f is not None else n, n, strings, forms)
        for pkg in forms:
            sp = pick_strings(pkg, strings, language)
            mod.pairing[pkg.offset] = sp
            mod.formsets.extend(build_formsets(pkg, sp))
        modules.append(mod)
    return modules
