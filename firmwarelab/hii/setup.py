"""Read-only BIOS Setup browser: map IFR questions to their current NVRAM values.

This module intentionally does not rewrite IFR or hide/unhide questions. It reads the
Setup form structure and pairs each question with the value stored in the backing
NVRAM variable, so users can inspect (and, where a plain variable store backs the
question, edit through the normal NVRAM editor) BIOS settings.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core.node import Node
from ..formats import nvram
from .ifr import FormSet, Question
from .scan import HiiModule, scan


@dataclass
class QuestionRef:
    module: HiiModule
    formset: FormSet
    question: Question

    @property
    def prompt(self) -> str:
        return self.question.prompt


class SetupBrowser:
    def __init__(self, doc, language: str = "en-US"):
        self.doc = doc
        self.language = language
        self.refresh()

    def refresh(self) -> None:
        self.modules: list[HiiModule] = scan(self.doc.root, self.language)

    def formsets(self):
        for m in self.modules:
            for fs in m.formsets:
                yield m, fs

    def questions(self):
        for m, fs in self.formsets():
            for q in fs.questions:
                yield QuestionRef(m, fs, q)

    def search(self, text: str) -> list[QuestionRef]:
        t = text.lower()
        return [r for r in self.questions()
                if t in r.question.prompt.lower() or t in r.question.help.lower()]

    def varstore_of(self, ref: QuestionRef):
        return ref.formset.varstores.get(ref.question.varstore_id)

    def variables_for(self, ref: QuestionRef) -> dict[str, list[Node]]:
        vs = self.varstore_of(ref)
        out: dict[str, list[Node]] = {"current": [], "defaults": []}
        if vs is None or not vs.name:
            return out
        for v in nvram.find_variables(self.doc.root, vs.name, vs.guid):
            out[nvram.store_role(v)].append(v)
        return out

    @staticmethod
    def _read(data: bytes, q: Question):
        size = q.size or 1
        if q.var_offset + size > len(data):
            return None
        chunk = data[q.var_offset:q.var_offset + size]
        if q.kind in ("OneOf", "Numeric", "CheckBox"):
            return int.from_bytes(chunk, "little")
        return bytes(chunk)

    def current_value(self, ref: QuestionRef, store: str = "current"):
        vs = self.variables_for(ref).get(store) or []
        return self._read(vs[0].body, ref.question) if vs else None

    def describe_value(self, ref: QuestionRef, value) -> str:
        q = ref.question
        if value is None:
            return "n/a"
        if isinstance(value, bytes):
            return value.hex(" ").upper()
        if q.kind == "CheckBox":
            return "Enabled" if value else "Disabled"
        t = q.option_text(value)
        return "%s (%Xh)" % (t, value) if t is not None else "%Xh" % value

    def dump(self, hidden: bool = True) -> str:
        lines = []
        for m, fs in self.formsets():
            lines.append("### %s  (module %s)" % (fs.title or "FormSet", m.name))
            for vs in fs.varstores.values():
                lines.append("    varstore %Xh %s '%s' size %Xh" % (vs.varstore_id, vs.kind, vs.name or "", vs.size))
            for form in fs.forms:
                shown = [i for i in form.items]
                if not shown:
                    continue
                lines.append("  Form '%s' (id %Xh)" % (form.title, form.form_id))
                for item in form.items:
                    if isinstance(item, Question):
                        ref = QuestionRef(m, fs, item)
                        cur = self.describe_value(ref, self.current_value(ref))
                        dv = item.defaults.get(0)
                        tags = []
                        if item.hidden:
                            if not hidden:
                                continue
                            tags.append("hidden")
                        if item.grayed:
                            tags.append("grayed")
                        lines.append("    [%s] %-40s = %s%s%s" % (
                            item.kind, item.prompt[:40], cur,
                            "  (default %s)" % self.describe_value(ref, dv) if dv is not None else "",
                            "  <%s>" % ",".join(tags) if tags else ""))
                    else:
                        lines.append("    -- %s: %s" % (item.kind, item.text))
        return "\n".join(lines)
