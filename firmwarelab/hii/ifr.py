"""IFR (Internal Forms Representation) parsing, text export and form model."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from ..core.binary import u16, u24, u32, u64
from ..core.guids import guid_db, guid_to_str
from .strings import StringPackage

PACKAGE_TYPE_FORMS = 0x02

OPCODES = {
    0x01: "Form", 0x02: "Subtitle", 0x03: "Text", 0x04: "Image", 0x05: "OneOf", 0x06: "CheckBox",
    0x07: "Numeric", 0x08: "Password", 0x09: "OneOfOption", 0x0A: "SuppressIf", 0x0B: "Locked",
    0x0C: "Action", 0x0D: "ResetButton", 0x0E: "FormSet", 0x0F: "Ref", 0x10: "NoSubmitIf",
    0x11: "InconsistentIf", 0x12: "EqIdVal", 0x13: "EqIdId", 0x14: "EqIdValList", 0x15: "And",
    0x16: "Or", 0x17: "Not", 0x18: "Rule", 0x19: "GrayOutIf", 0x1A: "Date", 0x1B: "Time",
    0x1C: "String", 0x1D: "Refresh", 0x1E: "DisableIf", 0x1F: "Animation", 0x20: "ToLower",
    0x21: "ToUpper", 0x22: "Map", 0x23: "OrderedList", 0x24: "VarStore", 0x25: "VarStoreNameValue",
    0x26: "VarStoreEfi", 0x27: "VarStoreDevice", 0x28: "Version", 0x29: "End", 0x2A: "Match",
    0x2B: "Get", 0x2C: "Set", 0x2D: "Read", 0x2E: "Write", 0x2F: "Equal", 0x30: "NotEqual",
    0x31: "GreaterThan", 0x32: "GreaterEqual", 0x33: "LessThan", 0x34: "LessEqual",
    0x35: "BitwiseAnd", 0x36: "BitwiseOr", 0x37: "BitwiseNot", 0x38: "ShiftLeft",
    0x39: "ShiftRight", 0x3A: "Add", 0x3B: "Subtract", 0x3C: "Multiply", 0x3D: "Divide",
    0x3E: "Modulo", 0x3F: "RuleRef", 0x40: "QuestionRef1", 0x41: "QuestionRef2", 0x42: "Uint8",
    0x43: "Uint16", 0x44: "Uint32", 0x45: "Uint64", 0x46: "True", 0x47: "False", 0x48: "ToUint",
    0x49: "ToString", 0x4A: "ToBoolean", 0x4B: "Mid", 0x4C: "Find", 0x4D: "Token",
    0x4E: "StringRef1", 0x4F: "StringRef2", 0x50: "Conditional", 0x51: "QuestionRef3", 0x52: "Zero",
    0x53: "One", 0x54: "Ones", 0x55: "Undefined", 0x56: "Length", 0x57: "Dup", 0x58: "This",
    0x59: "Span", 0x5A: "Value", 0x5B: "Default", 0x5C: "DefaultStore", 0x5D: "FormMap",
    0x5E: "Catenate", 0x5F: "GuidOp", 0x60: "Security", 0x61: "ModalTag", 0x62: "RefreshId",
    0x63: "WarningIf", 0x64: "Match2",
}

EXPRESSION_OPS = {
    0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x20, 0x21, 0x22, 0x28, 0x2A, 0x2B, 0x2C, 0x2F, 0x30, 0x31,
    0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41,
    0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51,
    0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5E, 0x60, 0x64,
}
QUESTION_OPS = {0x05: "OneOf", 0x06: "CheckBox", 0x07: "Numeric", 0x08: "Password", 0x0C: "Action",
                0x0F: "Ref", 0x1A: "Date", 0x1B: "Time", 0x1C: "String", 0x23: "OrderedList",
                0x0D: "ResetButton"}
CONDITION_OPS = {0x0A: "SuppressIf", 0x19: "GrayOutIf", 0x1E: "DisableIf"}

TYPE_SIZES = {0: 1, 1: 2, 2: 4, 3: 8, 4: 1, 5: 3, 6: 4, 7: 2, 10: 2}
TYPE_NAMES = {0: "UINT8", 1: "UINT16", 2: "UINT32", 3: "UINT64", 4: "BOOLEAN", 5: "TIME", 6: "DATE",
              7: "STRING", 8: "OTHER", 9: "UNDEFINED", 10: "ACTION", 11: "BUFFER", 12: "REF"}


class IfrError(ValueError):
    pass


@dataclass
class IfrOp:
    offset: int  # absolute offset in the scanned blob
    opcode: int
    length: int
    scope: bool
    raw: bytes
    depth: int
    fields: dict = field(default_factory=dict)
    children: list = field(default_factory=list)
    parent: "IfrOp | None" = None

    @property
    def name(self) -> str:
        return OPCODES.get(self.opcode, "Unknown%02X" % self.opcode)


@dataclass
class FormPackage:
    offset: int
    length: int
    ops: list[IfrOp]  # flat, in order
    roots: list[IfrOp]  # top level ops (usually one FormSet)
    max_string_id: int = 0


def _value(data, p, typ):
    if typ == 0 or typ == 4:
        return data[p]
    if typ == 1 or typ == 7 or typ == 10:
        return u16(data, p)
    if typ == 2:
        return u32(data, p)
    if typ == 3:
        return u64(data, p)
    if typ == 5:
        return "%02d:%02d:%02d" % (data[p], data[p + 1], data[p + 2])
    if typ == 6:
        return "%04d-%02d-%02d" % (u16(data, p), data[p + 2], data[p + 3])
    return None


def _decode_fields(op: IfrOp) -> dict:
    d = op.raw
    o = op.opcode
    f: dict = {}
    L = op.length

    def qh():
        f.update(prompt=u16(d, 2), help=u16(d, 4), qid=u16(d, 6), varstore=u16(d, 8),
                 varinfo=u16(d, 10), qflags=d[12])

    if o == 0x0E and L >= 22:
        f.update(guid=bytes(d[2:18]), title=u16(d, 18), help=u16(d, 20))
        if L >= 23:
            f["flags"] = d[22]
            f["class_guids"] = [bytes(d[23 + i * 16:39 + i * 16]) for i in range(d[22] & 3) if 39 + i * 16 <= L]
    elif o == 0x01 and L >= 6:
        f.update(form_id=u16(d, 2), title=u16(d, 4))
    elif o == 0x02 and L >= 6:
        f.update(prompt=u16(d, 2), help=u16(d, 4), flags=d[6] if L > 6 else 0)
    elif o == 0x03 and L >= 8:
        f.update(prompt=u16(d, 2), help=u16(d, 4), text2=u16(d, 6))
    elif o in (0x05, 0x07) and L >= 14:
        qh()
        flags = d[13]
        f["flags"] = flags
        size = 1 << (flags & 0x0F & 3)
        f["size"] = size
        p = 14
        if p + 3 * size <= L:
            fmt = {1: "B", 2: "H", 4: "I", 8: "Q"}[size]
            f["min"], f["max"], f["step"] = struct.unpack_from("<3" + fmt, d, p)
    elif o == 0x06 and L >= 14:
        qh()
        f["flags"] = d[13]
        f["size"] = 1
    elif o == 0x08 and L >= 17:
        qh()
        f.update(min_size=u16(d, 13), max_size=u16(d, 15))
    elif o == 0x09 and L >= 6:
        f.update(option=u16(d, 2), flags=d[4], type=d[5])
        f["value"] = _value(d, 6, d[5]) if 6 + TYPE_SIZES.get(d[5], 0) <= L else None
    elif o == 0x0C and L >= 13:
        qh()
        if L >= 15:
            f["config"] = u16(d, 13)
    elif o == 0x0D and L >= 8:
        f.update(prompt=u16(d, 2), help=u16(d, 4), default_id=u16(d, 6))
    elif o == 0x0F and L >= 15:
        qh()
        f["form_id"] = u16(d, 13)
        if L >= 17:
            f["ref_qid"] = u16(d, 15)
        if L >= 33:
            f["formset"] = bytes(d[17:33])
    elif o in (0x10, 0x11) and L >= 4:
        f["error"] = u16(d, 2)
    elif o == 0x63 and L >= 5:
        f.update(warning=u16(d, 2), timeout=d[4])
    elif o == 0x12 and L >= 6:
        f.update(qid=u16(d, 2), value=u16(d, 4))
    elif o == 0x13 and L >= 6:
        f.update(qid1=u16(d, 2), qid2=u16(d, 4))
    elif o == 0x14 and L >= 6:
        n = u16(d, 4)
        f.update(qid=u16(d, 2), values=[u16(d, 6 + i * 2) for i in range(n) if 8 + i * 2 <= L])
    elif o in (0x18, 0x3F) and L >= 3:
        f["rule_id"] = d[2]
    elif o in (0x1A, 0x1B) and L >= 14:
        qh()
        f["flags"] = d[13]
    elif o == 0x1C and L >= 16:
        qh()
        f.update(min_size=d[13], max_size=d[14], flags=d[15])
    elif o == 0x1D and L >= 3:
        f["interval"] = d[2]
    elif o == 0x23 and L >= 15:
        qh()
        f.update(max_containers=d[13], flags=d[14])
    elif o == 0x24 and L >= 22:
        name_raw = bytes(d[22:L]).split(b"\0", 1)[0]
        f.update(guid=bytes(d[2:18]), varstore_id=u16(d, 18), size=u16(d, 20),
                 var_name=name_raw.decode("latin-1"))
    elif o == 0x25 and L >= 20:
        f.update(varstore_id=u16(d, 2), guid=bytes(d[4:20]))
    elif o == 0x26 and L >= 24:
        f.update(varstore_id=u16(d, 2), guid=bytes(d[4:20]), attributes=u32(d, 20))
        if L >= 26:
            f["size"] = u16(d, 24)
            f["var_name"] = bytes(d[26:L]).split(b"\0", 1)[0].decode("latin-1")
    elif o == 0x27 and L >= 4:
        f["device_path"] = u16(d, 2)
    elif o in (0x2B, 0x2C) and L >= 7:
        f.update(varstore=u16(d, 2), varinfo=u16(d, 4), vartype=d[6])
    elif o == 0x40 and L >= 4:
        f["qid"] = u16(d, 2)
    elif o == 0x42 and L >= 3:
        f["value"] = d[2]
    elif o == 0x43 and L >= 4:
        f["value"] = u16(d, 2)
    elif o == 0x44 and L >= 6:
        f["value"] = u32(d, 2)
    elif o == 0x45 and L >= 10:
        f["value"] = u64(d, 2)
    elif o == 0x4E and L >= 4:
        f["string"] = u16(d, 2)
    elif o == 0x59 and L >= 3:
        f["flags"] = d[2]
    elif o == 0x5B and L >= 5:
        f.update(default_id=u16(d, 2), type=d[4])
        f["value"] = _value(d, 5, d[4]) if 5 + TYPE_SIZES.get(d[4], 0) <= L else None
    elif o == 0x5C and L >= 6:
        f.update(name=u16(d, 2), default_id=u16(d, 4))
    elif o == 0x5F and L >= 18:
        f.update(guid=bytes(d[2:18]), data=bytes(d[18:L]))
    elif o in (0x60, 0x62) and L >= 18:
        f["guid"] = bytes(d[2:18])
    return f


def parse_form_package(data, off: int, validate: bool = True) -> FormPackage | None:
    """Parse a form package (type 2) at ``off``; returns None if not valid IFR."""
    n = len(data)
    if off + 6 > n or data[off + 3] != PACKAGE_TYPE_FORMS:
        return None
    length = u24(data, off)
    if length < 6 or off + length > n:
        return None
    p = off + 4
    end = off + length
    if data[p] != 0x0E:
        return None
    ops: list[IfrOp] = []
    roots: list[IfrOp] = []
    stack: list[IfrOp] = []
    max_sid = 0
    while p < end:
        if p + 2 > end:
            return None
        opc = data[p]
        ln = data[p + 1] & 0x7F
        scope = bool(data[p + 1] & 0x80)
        if ln < 2 or p + ln > end or (validate and opc not in OPCODES):
            return None
        op = IfrOp(p, opc, ln, scope, bytes(data[p:p + ln]), len(stack))
        try:
            op.fields = _decode_fields(op)
        except (struct.error, IndexError):
            op.fields = {}
        for k in ("prompt", "help", "title", "option", "text2", "error", "warning", "string"):
            v = op.fields.get(k)
            if isinstance(v, int) and v > max_sid:
                max_sid = v
        ops.append(op)
        if opc == 0x29:
            if stack:
                stack.pop()
            elif validate:
                return None
            p += ln
            continue
        if stack:
            op.parent = stack[-1]
            stack[-1].children.append(op)
        else:
            roots.append(op)
        if scope:
            stack.append(op)
        p += ln
    if validate and stack:
        return None
    return FormPackage(off, length, ops, roots, max_sid)


def find_form_packages(data) -> list[FormPackage]:
    raw = bytes(data)
    out = []
    pos = 0
    while True:
        i = raw.find(b"\x0e", pos)
        if i < 0:
            break
        pos = i + 1
        if i < 4 or raw[i - 1] != PACKAGE_TYPE_FORMS or i + 1 >= len(raw):
            continue
        ln = raw[i + 1] & 0x7F
        if not (raw[i + 1] & 0x80) or ln < 22 or ln > 0x40:
            continue
        pkg = parse_form_package(raw, i - 4)
        if pkg is not None:
            out.append(pkg)
            pos = pkg.offset + pkg.length
    return out


# =============================================================================
# Expressions
# =============================================================================

_BINARY = {0x15: "and", 0x16: "or", 0x2F: "==", 0x30: "!=", 0x31: ">", 0x32: ">=", 0x33: "<",
           0x34: "<=", 0x35: "&", 0x36: "|", 0x38: "<<", 0x39: ">>", 0x3A: "+", 0x3B: "-",
           0x3C: "*", 0x3D: "/", 0x3E: "%", 0x5E: "cat", 0x2A: "match", 0x64: "match2"}
_UNARY = {0x17: "not", 0x37: "~", 0x48: "uint", 0x49: "str", 0x4A: "bool", 0x20: "lower", 0x21: "upper",
          0x56: "len", 0x41: "questionref", 0x4F: "stringref"}


def expression_text(ops: list[IfrOp], strings: StringPackage | None = None, qnames: dict | None = None) -> str:
    """Render an RPN expression as readable infix text."""
    st: list[str] = []
    qnames = qnames or {}

    def q(qid):
        name = qnames.get(qid)
        return "%s(Q%Xh)" % (name, qid) if name else "Q%Xh" % qid

    for op in ops:
        o = op.opcode
        f = op.fields
        if o == 0x46:
            st.append("TRUE")
        elif o == 0x47:
            st.append("FALSE")
        elif o in (0x42, 0x43, 0x44, 0x45):
            st.append("%Xh" % f.get("value", 0))
        elif o == 0x52:
            st.append("0")
        elif o == 0x53:
            st.append("1")
        elif o == 0x54:
            st.append("ONES")
        elif o == 0x55:
            st.append("UNDEFINED")
        elif o == 0x58:
            st.append("THIS")
        elif o == 0x12:
            st.append("%s == %Xh" % (q(f.get("qid", 0)), f.get("value", 0)))
        elif o == 0x13:
            st.append("%s == %s" % (q(f.get("qid1", 0)), q(f.get("qid2", 0))))
        elif o == 0x14:
            st.append("%s in [%s]" % (q(f.get("qid", 0)), ", ".join("%Xh" % v for v in f.get("values", []))))
        elif o == 0x40:
            st.append(q(f.get("qid", 0)))
        elif o == 0x3F:
            st.append("rule%d" % f.get("rule_id", 0))
        elif o == 0x4E:
            s = strings.get(f.get("string", 0)) if strings else ""
            st.append('"%s"' % s)
        elif o == 0x2B:
            st.append("get(vs%X+%Xh)" % (f.get("varstore", 0), f.get("varinfo", 0)))
        elif o == 0x28:
            st.append("VERSION")
        elif o == 0x51:
            st.append("questionref3")
        elif o in _UNARY:
            a = st.pop() if st else "?"
            st.append("%s(%s)" % (_UNARY[o], a) if o != 0x17 else "not (%s)" % a)
        elif o in _BINARY:
            b = st.pop() if st else "?"
            a = st.pop() if st else "?"
            st.append("(%s %s %s)" % (a, _BINARY[o], b))
        elif o == 0x50:
            c = st.pop() if st else "?"
            b = st.pop() if st else "?"
            a = st.pop() if st else "?"
            st.append("(%s ? %s : %s)" % (a, b, c))
        else:
            st.append(op.name)
    return " ; ".join(st) if len(st) != 1 else st[0]


def evaluate_constant(ops: list[IfrOp]) -> bool | None:
    """Evaluate a condition made only of constants (e.g. SuppressIf TRUE)."""
    st = []
    for op in ops:
        o = op.opcode
        if o == 0x46:
            st.append(True)
        elif o == 0x47:
            st.append(False)
        elif o in (0x42, 0x43, 0x44, 0x45):
            st.append(op.fields.get("value", 0))
        elif o == 0x52:
            st.append(0)
        elif o == 0x53:
            st.append(1)
        elif o == 0x17 and st:
            st.append(not st.pop())
        elif o in (0x15, 0x16) and len(st) >= 2:
            b, a = st.pop(), st.pop()
            st.append((a and b) if o == 0x15 else (a or b))
        else:
            return None
    return bool(st[-1]) if st else None


def condition_ops(cond: IfrOp) -> list[IfrOp]:
    """Expression opcodes immediately following a SuppressIf/GrayOutIf/DisableIf."""
    out = []
    for c in cond.children:
        if c.opcode in EXPRESSION_OPS:
            out.append(c)
        else:
            break
    return out


# =============================================================================
# Form model
# =============================================================================

@dataclass
class VarStoreDef:
    varstore_id: int
    kind: str
    guid: bytes
    name: str | None
    size: int
    attributes: int = 0


@dataclass
class Condition:
    kind: str
    op: IfrOp
    expression: list[IfrOp]
    text: str
    constant: bool | None


@dataclass
class Question:
    kind: str
    op: IfrOp
    prompt: str
    help: str
    qid: int
    varstore_id: int
    var_offset: int
    qflags: int
    size: int
    flags: int = 0
    minimum: int | None = None
    maximum: int | None = None
    step: int | None = None
    options: list[tuple[int, str, int]] = field(default_factory=list)  # (value, text, flags)
    defaults: dict = field(default_factory=dict)  # default_id -> value
    conditions: list[Condition] = field(default_factory=list)
    form: "Form | None" = None
    option_ops: list[IfrOp] = field(default_factory=list)
    default_ops: list[IfrOp] = field(default_factory=list)
    target_form: int | None = None

    @property
    def hidden(self) -> bool:
        return any(c.kind == "SuppressIf" for c in self.conditions)

    @property
    def always_hidden(self) -> bool:
        return any(c.kind == "SuppressIf" and c.constant is True for c in self.conditions)

    @property
    def grayed(self) -> bool:
        return any(c.kind in ("GrayOutIf", "DisableIf") for c in self.conditions)

    def option_text(self, value) -> str | None:
        for v, t, _ in self.options:
            if v == value:
                return t
        return None

    @property
    def default_value(self):
        return self.defaults.get(0)


@dataclass
class Statement:
    kind: str  # Subtitle, Text, Ref
    op: IfrOp
    text: str
    extra: str = ""
    conditions: list[Condition] = field(default_factory=list)
    target_form: int | None = None


@dataclass
class Form:
    form_id: int
    title: str
    op: IfrOp
    items: list = field(default_factory=list)  # Question | Statement


@dataclass
class FormSet:
    guid: bytes
    title: str
    help: str
    op: IfrOp
    package: FormPackage
    strings: StringPackage | None
    forms: list[Form] = field(default_factory=list)
    varstores: dict[int, VarStoreDef] = field(default_factory=dict)
    questions: list[Question] = field(default_factory=list)
    default_stores: dict[int, str] = field(default_factory=dict)

    def form_by_id(self, fid: int) -> Form | None:
        for f in self.forms:
            if f.form_id == fid:
                return f
        return None


def build_formsets(pkg: FormPackage, strings: StringPackage | None) -> list[FormSet]:
    s = strings.get if strings else (lambda sid: "")
    out = []
    qnames: dict[int, str] = {}
    for op in pkg.ops:
        if op.opcode in QUESTION_OPS and "qid" in op.fields and "prompt" in op.fields:
            qnames[op.fields["qid"]] = s(op.fields["prompt"])

    for root in pkg.roots:
        if root.opcode != 0x0E:
            continue
        fs = FormSet(root.fields.get("guid", bytes(16)), s(root.fields.get("title", 0)),
                     s(root.fields.get("help", 0)), root, pkg, strings)
        _walk(root, fs, None, [], s, qnames)
        out.append(fs)
    return out


def _walk(op: IfrOp, fs: FormSet, form: Form | None, conds: list[Condition], s, qnames):
    for c in op.children:
        o = c.opcode
        f = c.fields
        if o == 0x24 or o == 0x26:
            vs = VarStoreDef(f.get("varstore_id", 0), "Buffer" if o == 0x24 else "EFI", f.get("guid", bytes(16)),
                             f.get("var_name"), f.get("size", 0), f.get("attributes", 0))
            fs.varstores[vs.varstore_id] = vs
        elif o == 0x25:
            fs.varstores[f.get("varstore_id", 0)] = VarStoreDef(f.get("varstore_id", 0), "NameValue",
                                                               f.get("guid", bytes(16)), None, 0)
        elif o == 0x5C:
            fs.default_stores[f.get("default_id", 0)] = s(f.get("name", 0))
        if o == 0x01 or o == 0x5D:
            nf = Form(f.get("form_id", 0), s(f.get("title", 0)), c)
            fs.forms.append(nf)
            _walk(c, fs, nf, [], s, qnames)
            continue
        if o in CONDITION_OPS:
            expr = condition_ops(c)
            cond = Condition(CONDITION_OPS[o], c, expr, expression_text(expr, fs.strings, qnames),
                             evaluate_constant(expr))
            _walk(c, fs, form, conds + [cond], s, qnames)
            continue
        if o in QUESTION_OPS and "qid" in f:
            q = Question(QUESTION_OPS[o], c, s(f.get("prompt", 0)), s(f.get("help", 0)), f["qid"],
                         f.get("varstore", 0), f.get("varinfo", 0), f.get("qflags", 0), f.get("size", 0),
                         f.get("flags", 0), f.get("min"), f.get("max"), f.get("step"),
                         conditions=list(conds), form=form)
            if o == 0x06:
                q.defaults[0] = 1 if f.get("flags", 0) & 0x01 else 0
                if f.get("flags", 0) & 0x02:
                    q.defaults[1] = 1
            if o == 0x0F:
                q.target_form = f.get("form_id")
            if o == 0x23:
                q.size = f.get("max_containers", 0)
            for ch in c.children:
                if ch.opcode == 0x09:
                    val = ch.fields.get("value")
                    fl = ch.fields.get("flags", 0)
                    q.options.append((val, s(ch.fields.get("option", 0)), fl))
                    q.option_ops.append(ch)
                    if fl & 0x10:
                        q.defaults.setdefault(0, val)
                    if fl & 0x20:
                        q.defaults.setdefault(1, val)
                elif ch.opcode == 0x5B:
                    q.defaults[ch.fields.get("default_id", 0)] = ch.fields.get("value")
                    q.default_ops.append(ch)
                elif ch.opcode in CONDITION_OPS:
                    pass
            if o == 0x23 and q.options:
                width = TYPE_SIZES.get(c.children[0].fields.get("type", 0), 1) if c.children else 1
                q.size = f.get("max_containers", 0) * width
            if o in (0x05, 0x07) and not q.size:
                q.size = 1
            if o == 0x1A:
                q.size = 4
            if o == 0x1B:
                q.size = 3
            if o == 0x1C:
                q.size = f.get("max_size", 0) * 2
            fs.questions.append(q)
            if form is not None:
                form.items.append(q)
            continue
        if o in (0x02, 0x03) and form is not None:
            txt = s(f.get("prompt", 0))
            extra = s(f.get("text2", 0)) if o == 0x03 else ""
            form.items.append(Statement("Subtitle" if o == 0x02 else "Text", c, txt, extra, list(conds)))
        if c.children and o not in QUESTION_OPS:
            _walk(c, fs, form, conds, s, qnames)


# =============================================================================
# Text export (IFRExtractor-like verbose format)
# =============================================================================

def op_text(op: IfrOp, strings: StringPackage | None) -> str:
    s = strings.get if strings else (lambda sid: "")
    f = op.fields
    db = guid_db()
    n = op.name
    o = op.opcode
    if o == 0x0E:
        return 'FormSet Guid: %s, Title: "%s", Help: "%s"' % (guid_to_str(f.get("guid", bytes(16))),
                                                            s(f.get("title", 0)), s(f.get("help", 0)))
    if o == 0x01:
        return 'Form FormId: %Xh, Title: "%s"' % (f.get("form_id", 0), s(f.get("title", 0)))
    if o in (0x02,):
        return 'Subtitle Prompt: "%s", Help: "%s"' % (s(f.get("prompt", 0)), s(f.get("help", 0)))
    if o == 0x03:
        return 'Text Prompt: "%s", Help: "%s", Text: "%s"' % (s(f.get("prompt", 0)), s(f.get("help", 0)),
                                                             s(f.get("text2", 0)))
    if o in QUESTION_OPS and "qid" in f:
        base = '%s Prompt: "%s", Help: "%s", QuestionFlags: %Xh, QuestionId: %Xh, VarStoreId: %Xh, VarOffset: %Xh' % (
            n, s(f.get("prompt", 0)), s(f.get("help", 0)), f.get("qflags", 0), f["qid"], f.get("varstore", 0),
            f.get("varinfo", 0))
        if o in (0x05, 0x07):
            base += ", Flags: %Xh, Size: %d" % (f.get("flags", 0), f.get("size", 1) * 8)
            if "min" in f:
                base += ", Min: %Xh, Max: %Xh, Step: %Xh" % (f["min"], f["max"], f["step"])
        elif o == 0x06:
            base += ", Flags: %Xh, Default: %s, MfgDefault: %s" % (
                f.get("flags", 0), "Enabled" if f.get("flags", 0) & 1 else "Disabled",
                "Enabled" if f.get("flags", 0) & 2 else "Disabled")
        elif o == 0x0F:
            base += ", FormId: %Xh" % f.get("form_id", 0)
        elif o == 0x1C:
            base += ", MinSize: %d, MaxSize: %d" % (f.get("min_size", 0), f.get("max_size", 0))
        elif o == 0x23:
            base += ", MaxContainers: %d" % f.get("max_containers", 0)
        return base
    if o == 0x09:
        fl = f.get("flags", 0)
        tags = []
        if fl & 0x10:
            tags.append("Default")
        if fl & 0x20:
            tags.append("MfgDefault")
        return 'OneOfOption Option: "%s" Value: %s%s' % (s(f.get("option", 0)), _fmt(f.get("value")),
                                                          (", " + ", ".join(tags)) if tags else "")
    if o == 0x24:
        return 'VarStore Guid: %s, VarStoreId: %Xh, Size: %Xh, Name: "%s"' % (
            guid_to_str(f.get("guid", bytes(16))), f.get("varstore_id", 0), f.get("size", 0), f.get("var_name", ""))
    if o == 0x26:
        return 'VarStoreEfi Guid: %s, VarStoreId: %Xh, Attributes: %Xh, Size: %Xh, Name: "%s"' % (
            guid_to_str(f.get("guid", bytes(16))), f.get("varstore_id", 0), f.get("attributes", 0),
            f.get("size", 0), f.get("var_name", ""))
    if o == 0x25:
        return "VarStoreNameValue Guid: %s, VarStoreId: %Xh" % (guid_to_str(f.get("guid", bytes(16))),
                                                                 f.get("varstore_id", 0))
    if o == 0x5B:
        return "Default DefaultId: %Xh Value: %s" % (f.get("default_id", 0), _fmt(f.get("value")))
    if o == 0x5C:
        return 'DefaultStore DefaultId: %Xh, Name: "%s"' % (f.get("default_id", 0), s(f.get("name", 0)))
    if o == 0x12:
        return "EqIdVal QuestionId: %Xh, Value: %Xh" % (f.get("qid", 0), f.get("value", 0))
    if o == 0x13:
        return "EqIdId QuestionId1: %Xh, QuestionId2: %Xh" % (f.get("qid1", 0), f.get("qid2", 0))
    if o == 0x14:
        return "EqIdValList QuestionId: %Xh, Values: %s" % (f.get("qid", 0), " ".join("%Xh" % v for v in f.get("values", [])))
    if o in (0x42, 0x43, 0x44, 0x45):
        return "%s Value: %Xh" % (n, f.get("value", 0))
    if o == 0x5F:
        return "GuidOp Guid: %s" % db.display(f.get("guid", bytes(16)))
    if o in (0x10, 0x11):
        return '%s Error: "%s"' % (n, s(f.get("error", 0)))
    if o == 0x63:
        return 'WarningIf Warning: "%s"' % s(f.get("warning", 0))
    if o == 0x40:
        return "QuestionRef1 QuestionId: %Xh" % f.get("qid", 0)
    return n


def _fmt(v) -> str:
    if isinstance(v, int):
        return "%Xh" % v
    return str(v)


def package_text(pkg: FormPackage, strings: StringPackage | None, with_bytes: bool = True) -> str:
    lines = []
    depth = 0
    for op in pkg.ops:
        if op.opcode == 0x29:
            depth = max(0, depth - 1)
        line = "\t" * depth + op_text(op, strings)
        if with_bytes:
            line += " {%s}" % " ".join("%02X" % b for b in op.raw)
        lines.append(line)
        if op.scope and op.opcode != 0x29:
            depth += 1
    return "\n".join(lines)
