"""Identify the target motherboard and BIOS revision of a firmware image.

Firmware rarely carries a single authoritative "make/model" field, so this module
gathers evidence from several independent sources and merges them, keeping the
highest-confidence value found for each field:

* **AMI/Intel ``$IBIOSI$`` BIOS ID** — the canonical Intel-format BIOS version
  string (board tag, version and build date), UCS-2 encoded.  High confidence.
* **SMBIOS templates** (Type 0 BIOS, Type 1 System, Type 2 Baseboard) embedded in
  the SMBIOS driver — BIOS vendor/version/date and system/baseboard
  manufacturer + product.  Placeholder strings ("To be filled by O.E.M." etc.)
  are recognised and demoted.
* **Insyde ``$BVDT``** version data table — marks Insyde firmware and often
  carries a printable version string.
* **Vendor hints** already collected during the parse (AMI/Insyde/Phoenix/AMD/EDK
  II) — used only as a low-confidence fallback for the BIOS vendor.

The scan reaches inside compressed volumes by also examining every decompressed
blob discovered during parsing, not just the raw image.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..core.node import Node

# Confidence levels (higher wins when several sources set the same field).
LOW, MEDIUM, HIGH = 1, 2, 3
_CONF_NAME = {LOW: "low", MEDIUM: "medium", HIGH: "high"}

# SMBIOS template placeholder strings that mean "not actually filled in".
_PLACEHOLDERS = {
    "to be filled by o.e.m.", "to be filled by o.e.m", "default string",
    "system manufacturer", "system product name", "system version",
    "system serial number", "base board manufacturer", "base board product name",
    "base board version", "baseboard manufacturer", "baseboard product name",
    "manufacturer", "product name", "not specified", "not applicable", "none",
    "oem", "o.e.m.", "$manfid$", "chassis manufacturer", "type2 - board vendor name",
    "type2 - board product name", "type1 - system version",
}


@dataclass
class Finding:
    """A single piece of evidence for one identity field."""

    field: str
    value: str
    source: str
    confidence: int
    placeholder: bool = False


@dataclass
class BoardInfo:
    """Merged identification result."""

    board_vendor: str | None = None
    board_model: str | None = None
    board_version: str | None = None
    system_vendor: str | None = None
    system_product: str | None = None
    bios_vendor: str | None = None
    bios_version: str | None = None
    bios_date: str | None = None
    board_id: str | None = None  # raw Intel/AMI board tag
    findings: list[Finding] = field(default_factory=list)
    _conf: dict = field(default_factory=dict)
    _is_ph: dict = field(default_factory=dict)

    # -- merge -------------------------------------------------------------
    def consider(self, fld: str, value: str, source: str, confidence: int,
                 placeholder: bool = False) -> None:
        value = (value or "").strip()
        if not value:
            return
        self.findings.append(Finding(fld, value, source, confidence, placeholder))
        # A real value always beats a placeholder; otherwise higher confidence wins.
        prev = self._conf.get(fld)
        rank = confidence - (2 if placeholder else 0)
        if prev is None or rank > prev:
            self._conf[fld] = rank
            self._is_ph[fld] = placeholder
            setattr(self, fld, value)

    def _pick(self, *fields: str) -> str | None:
        """First non-placeholder value across the given fields, else the first set."""
        vals = [(getattr(self, f), self._is_ph.get(f, False)) for f in fields]
        vals = [(v, ph) for v, ph in vals if v]
        for v, ph in vals:
            if not ph:
                return v
        return vals[0][0] if vals else None

    # -- presentation ------------------------------------------------------
    @property
    def is_empty(self) -> bool:
        return not any((self.board_vendor, self.board_model, self.system_vendor,
                        self.system_product, self.bios_version, self.bios_date,
                        self.board_id))

    def manufacturer(self) -> str | None:
        return self._pick("board_vendor", "system_vendor")

    def model(self) -> str | None:
        return self._pick("board_model", "system_product", "board_id")

    def describe(self) -> list[tuple[str, str]]:
        rows: list[tuple[str, str]] = []

        def add(label, value):
            if value:
                rows.append((label, value))

        add("Board manufacturer", self.manufacturer())
        add("Board model", self.model())
        add("Board version", self.board_version)
        if self.system_vendor and self.system_vendor != self.board_vendor:
            add("System manufacturer", self.system_vendor)
        if self.system_product and self.system_product != self.board_model:
            add("System product", self.system_product)
        add("BIOS vendor", self.bios_vendor)
        add("BIOS version", self.bios_version)
        add("BIOS date", self.bios_date)
        if self.board_id and self.board_id != self.board_model:
            add("Intel board tag", self.board_id)
        return rows

    def summary_line(self) -> str:
        mk, md = self.manufacturer(), self.model()
        if mk and md:
            board = "%s %s" % (mk, md)
        else:
            board = md or mk or "unknown board"
        ver = self.bios_version or "unknown version"
        if self.bios_date:
            ver += " (%s)" % self.bios_date
        return "%s — BIOS %s" % (board, ver)


# =============================================================================
# Evidence gathering
# =============================================================================

def _gather_blobs(root: Node, raw: bytes | None) -> list[bytes]:
    """The raw image plus every decompressed blob, so scans reach into volumes."""
    blobs: list[bytes] = []
    if raw is not None:
        blobs.append(bytes(raw))
    else:
        blobs.append(root.data)
    for n in root.walk():
        if n.decoded is not None:
            blobs.append(bytes(n.decoded))
    return blobs


def _printable(s: bytes, max_len: int = 64) -> str | None:
    if not s or len(s) > max_len:
        return None
    if not all(0x20 <= b < 0x7F for b in s):
        return None
    text = s.decode("ascii").strip()
    return text or None


# ---------------------------------------------------------------- $IBIOSI$

# BoardID(8) . BoardExt(3) . VersionMajor(4) . BuildType(1)+VersionMinor(2) .
# Year(2) Month(2) Day(2) Hour(2) Minute(2)  — all UCS-2, dots are 2E 00.
_IBIOSI = re.compile(
    br"\$IBIOSI\$"
    br"(.{16})\x2e\x00"
    br"(.{6})\x2e\x00"
    br"(.{8})\x2e\x00"
    br"(.{2})(.{4})\x2e\x00"
    br"(.{4})(.{4})(.{4})(.{4})(.{4})"
    br"\x00\x00",
    re.DOTALL,
)


def _ucs2(b: bytes) -> str:
    return b.decode("utf-16-le", "ignore").replace("\x00", "").strip()


def _scan_ibiosi(info: BoardInfo, blobs: list[bytes]) -> None:
    for blob in blobs:
        m = _IBIOSI.search(blob)
        if not m:
            continue
        board_id = _ucs2(m.group(1))
        board_ext = _ucs2(m.group(2))
        major = _ucs2(m.group(3))
        build_type = _ucs2(m.group(4))
        minor = _ucs2(m.group(5))
        year, month, day, hour, minute = (_ucs2(m.group(i)) for i in range(6, 11))
        src = "AMI/Intel $IBIOSI$ BIOS ID"
        if board_id:
            info.board_id = info.board_id or board_id
            # A terse board tag; a human SMBIOS baseboard product name should win.
            info.consider("board_model", board_id, src, MEDIUM)
        version = ".".join(p for p in (board_id, board_ext, major, build_type + minor) if p)
        if version:
            info.consider("bios_version", version, src, HIGH)
        if year.isdigit() and month.isdigit() and day.isdigit():
            try:
                date = "20%02d-%02d-%02d" % (int(year), int(month), int(day))
                if hour.isdigit() and minute.isdigit():
                    date += " %02d:%02d" % (int(hour), int(minute))
                info.consider("bios_date", date, src, HIGH)
            except ValueError:
                pass
        return  # one authoritative record is enough


# ---------------------------------------------------------------- SMBIOS

# String-reference field offsets within each structure's formatted area.
_SMBIOS_FIELDS = {
    0x00: {4: "bios_vendor", 5: "bios_version", 8: "bios_date"},
    0x01: {4: "system_vendor", 5: "system_product", 6: "system_version"},
    0x02: {4: "board_vendor", 5: "board_model", 6: "board_version"},
}
_KNOWN_BIOS_VENDORS = (
    "american megatrends", "insyde", "phoenix", "dell", "hewlett", "lenovo",
    "intel corp", "byosoft", "sea bios", "seabios", "coreboot", "edk",
)
# Per-field confidence for SMBIOS-sourced values.  A baseboard product name is the
# most trustworthy "board model"; a BIOS-version string is better taken from
# $IBIOSI$ when present, so Type 0 fields stay at medium.
_SMBIOS_CONF = {
    "bios_vendor": MEDIUM, "bios_version": MEDIUM, "bios_date": MEDIUM,
    "system_vendor": HIGH, "system_product": HIGH, "system_version": MEDIUM,
    "board_vendor": HIGH, "board_model": HIGH, "board_version": MEDIUM,
}


def _parse_struct(data: bytes, p: int, n: int):
    """Parse one SMBIOS structure at p. Returns (type, length, strings, end) or None."""
    if p + 4 > n:
        return None
    t = data[p]
    length = data[p + 1]
    if length < 4 or p + length > n:
        return None
    sp = p + length
    strings: list[bytes] = []
    if sp + 1 < n and data[sp] == 0 and data[sp + 1] == 0:
        return t, length, strings, sp + 2
    while sp < n:
        e = data.find(b"\x00", sp)
        if e < 0:
            return None
        if e == sp:  # empty string terminates the set
            return t, length, strings, sp + 1
        strings.append(data[sp:e])
        if len(strings) > 32:
            return None
        sp = e + 1
    return None


def _walk_smbios(data: bytes, start: int, n: int):
    structs = []
    p = start
    while p < n and len(structs) <= 64:
        r = _parse_struct(data, p, n)
        if r is None:
            break
        t, length, strings, end = r
        structs.append((t, length, strings))
        if t == 0x7F or end <= p:  # end-of-table marker
            break
        p = end
    return structs


def _string_at(strings: list[bytes], idx: int) -> str | None:
    if 1 <= idx <= len(strings):
        return _printable(strings[idx - 1])
    return None


def _collect_chain(data: bytes, structs, start: int):
    """Pull identity fields out of a validated chain, with a plausibility score."""
    fields: list[tuple[str, str, bool]] = []
    have = set()
    reached_end = False
    bios_vendor_ok = False
    p = start
    for t, length, strings in structs:
        spec = _SMBIOS_FIELDS.get(t)
        if spec is not None:
            for off, name in spec.items():
                if off >= length:
                    continue
                val = _string_at(strings, data[p + off])
                if val is None:
                    continue
                ph = val.strip().lower() in _PLACEHOLDERS
                fields.append((name, val, ph))
                have.add(t)
                if name == "bios_vendor" and any(k in val.lower() for k in _KNOWN_BIOS_VENDORS):
                    bios_vendor_ok = True
        if t == 0x7F:
            reached_end = True
            break
        r = _parse_struct(data, p, len(data))
        if r is None:
            break
        p = r[3]
    score = len(have) + (2 if reached_end else 0) + (2 if bios_vendor_ok else 0)
    score += sum(1 for _, _, ph in fields if not ph)
    return score, fields, have


def _looks_real(val: str) -> bool:
    """A convincing identifier: several characters, at least one letter."""
    v = val.strip()
    return len(v) >= 3 and any(c.isalpha() for c in v)


def _scan_smbios(info: BoardInfo, blobs: list[bytes]) -> None:
    best_score = 0
    best_fields: list[tuple[str, str, bool]] = []
    anchor = re.compile(br"[\x00\x01\x02][\x08-\x30]")
    for blob in blobs:
        n = len(blob)
        seen_starts = 0
        for m in anchor.finditer(blob):
            p = m.start()
            seen_starts += 1
            if seen_starts > 40000:
                break
            structs = _walk_smbios(blob, p, n)
            if len(structs) < 2:
                continue
            types = {t for t, _, _ in structs}
            reached_end = 0x7F in types
            useful = types & {0x00, 0x01, 0x02}
            if not useful or (len(structs) < 3 and not reached_end):
                continue
            score, fields, have = _collect_chain(blob, structs, p)
            # Guard against random byte coincidences forming a "valid" chain: demand
            # either a recognised BIOS vendor or two convincing identity strings.
            real = [v for name, v, ph in fields if not ph and _looks_real(v)]
            recognized = any(name == "bios_vendor" and any(k in v.lower() for k in _KNOWN_BIOS_VENDORS)
                             for name, v, ph in fields)
            if not (recognized or len(real) >= 2):
                continue
            if score < 4:
                continue
            if score > best_score:
                best_score = score
                best_fields = fields
    for name, val, ph in best_fields:
        conf = _SMBIOS_CONF.get(name, MEDIUM)
        info.consider(name, val, "SMBIOS template", conf, placeholder=ph)


# ---------------------------------------------------------------- Insyde $BVDT

def _scan_insyde(info: BoardInfo, blobs: list[bytes]) -> None:
    for blob in blobs:
        i = blob.find(b"$BVDT")
        if i < 0:
            continue
        info.consider("bios_vendor", "Insyde", "Insyde $BVDT table", LOW)
        window = blob[i + 5:i + 512]
        # Grab the first version-looking ASCII string after the signature.
        for m in re.finditer(rb"[ -~]{4,48}", window):
            text = m.group().decode("ascii").strip()
            low = text.lower()
            if any(ch.isdigit() for ch in text) and ("." in text or low.startswith("v")):
                info.consider("bios_version", text, "Insyde $BVDT table", MEDIUM)
                break
        return


# ---------------------------------------------------------------- vendor hints

def _from_context(info: BoardInfo, ctx) -> None:
    if ctx is None:
        return
    hints = getattr(ctx, "vendor_hints", None) or set()
    vendor_map = {
        "AMI": "American Megatrends",
        "Insyde": "Insyde",
        "Phoenix": "Phoenix Technologies",
        "EDK II": "EDK II / TianoCore",
    }
    for hint in hints:
        name = vendor_map.get(hint)
        if name:
            info.consider("bios_vendor", name, "vendor hint (%s)" % hint, LOW)


# =============================================================================
# Public API
# =============================================================================

def identify(root: Node, ctx=None, raw: bytes | None = None) -> BoardInfo:
    """Identify the target board and BIOS revision from a parsed image."""
    info = BoardInfo()
    if ctx is None:
        ctx = root.meta.get("context")
    blobs = _gather_blobs(root, raw)
    try:
        _scan_ibiosi(info, blobs)
    except Exception:
        pass
    try:
        _scan_smbios(info, blobs)
    except Exception:
        pass
    try:
        _scan_insyde(info, blobs)
    except Exception:
        pass
    _from_context(info, ctx)
    return info
