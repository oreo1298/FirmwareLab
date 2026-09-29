"""A lightweight, fast hex viewer/editor widget."""

from __future__ import annotations

from PySide6.QtCore import QRect, QSize, Qt, Signal
from PySide6.QtGui import QColor, QFont, QFontMetrics, QPainter
from PySide6.QtWidgets import QAbstractScrollArea


class HexView(QAbstractScrollArea):
    """Displays bytes in a classic hex+ASCII grid. Editable when setEditable(True)."""

    byteEdited = Signal(int, int)  # offset, new value
    selectionChanged = Signal(int, int)  # start, length

    def __init__(self, parent=None):
        super().__init__(parent)
        self._data = bytearray()
        self._editable = False
        self._bpl = 16
        self._cursor = 0
        self._sel_anchor = None
        self._nibble = False  # editing low/high nibble
        self._highlights: list[tuple[int, int, QColor]] = []
        self._base = 0
        font = QFont("monospace")
        font.setStyleHint(QFont.Monospace)
        font.setPointSize(10)
        self.setFont(font)
        self._recalc()
        self.setFocusPolicy(Qt.StrongFocus)
        self.viewport().setCursor(Qt.IBeamCursor)

    # ------------------------------------------------------------------ data
    def set_data(self, data, base: int = 0):
        self._data = bytearray(data)
        self._base = base
        self._cursor = 0
        self._sel_anchor = None
        self._recalc()
        self.verticalScrollBar().setValue(0)
        self.viewport().update()

    def data(self) -> bytes:
        return bytes(self._data)

    def setEditable(self, editable: bool):
        self._editable = editable

    def set_highlights(self, spans):
        self._highlights = list(spans)
        self.viewport().update()

    # ------------------------------------------------------------------ metrics
    def _recalc(self):
        fm = QFontMetrics(self.font())
        self._ch = fm.horizontalAdvance("0")
        self._rh = fm.height() + 2
        self._addr_w = (len("%08X" % (self._base + len(self._data))) + 2) * self._ch
        self._hex_x = self._addr_w
        self._hex_w = self._bpl * 3 * self._ch
        self._asc_x = self._hex_x + self._hex_w + self._ch
        self._rows = max(1, (len(self._data) + self._bpl - 1) // self._bpl)
        self.verticalScrollBar().setRange(0, max(0, self._rows - self._visible_rows()))
        self.verticalScrollBar().setPageStep(self._visible_rows())
        total_w = self._asc_x + self._bpl * self._ch + self._ch
        self.horizontalScrollBar().setRange(0, max(0, total_w - self.viewport().width()))

    def _visible_rows(self):
        return max(1, self.viewport().height() // self._rh)

    def resizeEvent(self, e):
        self._recalc()
        super().resizeEvent(e)

    def sizeHint(self):
        return QSize(self._asc_x + self._bpl * self._ch + 40, 400)

    # ------------------------------------------------------------------ paint
    def paintEvent(self, e):
        p = QPainter(self.viewport())
        p.setFont(self.font())
        top = self.verticalScrollBar().value()
        xoff = -self.horizontalScrollBar().value()
        pal = self.palette()
        addr_col = QColor("#7f9cc0")
        p.fillRect(self.viewport().rect(), pal.base().color())
        for vis in range(self._visible_rows() + 1):
            row = top + vis
            if row >= self._rows:
                break
            y = vis * self._rh
            off = row * self._bpl
            p.setPen(addr_col)
            p.drawText(xoff + 4, y + self._rh - 4, "%08X" % (self._base + off))
            for i in range(self._bpl):
                idx = off + i
                if idx >= len(self._data):
                    break
                b = self._data[idx]
                hx = self._hex_x + xoff + i * 3 * self._ch + 4
                ax = self._asc_x + xoff + i * self._ch
                bg = self._bg_for(idx)
                if bg is not None:
                    p.fillRect(QRect(hx - 2, y, self._ch * 2 + 2, self._rh), bg)
                    p.fillRect(QRect(ax, y, self._ch, self._rh), bg)
                p.setPen(pal.text().color() if b else QColor("#666"))
                p.drawText(hx, y + self._rh - 4, "%02X" % b)
                p.setPen(pal.text().color() if 32 <= b < 127 else QColor("#556"))
                p.drawText(ax, y + self._rh - 4, chr(b) if 32 <= b < 127 else ".")
        p.end()

    def _bg_for(self, idx):
        s, l = self._selection()
        if l and s <= idx < s + l:
            return self.palette().highlight().color()
        for start, length, col in self._highlights:
            if start <= idx < start + length:
                return col
        if idx == self._cursor and self._editable:
            return QColor("#40507080")
        return None

    def _selection(self):
        if self._sel_anchor is None:
            return self._cursor, 0
        a, b = sorted((self._sel_anchor, self._cursor))
        return a, b - a + 1

    # ------------------------------------------------------------------ input
    def _pos_at(self, x, y):
        row = self.verticalScrollBar().value() + y // self._rh
        xoff = self.horizontalScrollBar().value()
        x += xoff
        col = None
        if self._hex_x <= x < self._asc_x:
            col = (x - self._hex_x - 4) // (3 * self._ch)
        elif x >= self._asc_x:
            col = (x - self._asc_x) // self._ch
        if col is None or col < 0 or col >= self._bpl:
            return None
        idx = row * self._bpl + col
        return idx if idx < len(self._data) else None

    def mousePressEvent(self, e):
        idx = self._pos_at(e.position().x(), e.position().y())
        if idx is not None:
            self._cursor = idx
            self._sel_anchor = idx if not (e.modifiers() & Qt.ShiftModifier) else self._sel_anchor
            if not (e.modifiers() & Qt.ShiftModifier):
                self._sel_anchor = idx
            self._nibble = False
            s, l = self._selection()
            self.selectionChanged.emit(s, l)
            self.viewport().update()

    def mouseMoveEvent(self, e):
        if e.buttons() & Qt.LeftButton:
            idx = self._pos_at(e.position().x(), e.position().y())
            if idx is not None:
                self._cursor = idx
                s, l = self._selection()
                self.selectionChanged.emit(s, l)
                self.viewport().update()

    def keyPressEvent(self, e):
        k = e.key()
        moved = True
        if k == Qt.Key_Right:
            self._cursor = min(len(self._data) - 1, self._cursor + 1)
        elif k == Qt.Key_Left:
            self._cursor = max(0, self._cursor - 1)
        elif k == Qt.Key_Down:
            self._cursor = min(len(self._data) - 1, self._cursor + self._bpl)
        elif k == Qt.Key_Up:
            self._cursor = max(0, self._cursor - self._bpl)
        elif k == Qt.Key_Home:
            self._cursor -= self._cursor % self._bpl
        elif k == Qt.Key_End:
            self._cursor += self._bpl - 1 - (self._cursor % self._bpl)
            self._cursor = min(self._cursor, len(self._data) - 1)
        else:
            moved = False
        if moved:
            self._sel_anchor = self._cursor if not (e.modifiers() & Qt.ShiftModifier) else self._sel_anchor
            self._ensure_visible()
            s, l = self._selection()
            self.selectionChanged.emit(s, l)
            self.viewport().update()
            return
        if self._editable and e.text() and e.text()[0] in "0123456789abcdefABCDEF":
            v = int(e.text(), 16)
            cur = self._data[self._cursor]
            if not self._nibble:
                self._data[self._cursor] = (v << 4) | (cur & 0x0F)
                self._nibble = True
            else:
                self._data[self._cursor] = (cur & 0xF0) | v
                self.byteEdited.emit(self._cursor, self._data[self._cursor])
                self._nibble = False
                self._cursor = min(len(self._data) - 1, self._cursor + 1)
            self.viewport().update()
            return
        super().keyPressEvent(e)

    def _ensure_visible(self):
        row = self._cursor // self._bpl
        top = self.verticalScrollBar().value()
        if row < top:
            self.verticalScrollBar().setValue(row)
        elif row >= top + self._visible_rows():
            self.verticalScrollBar().setValue(row - self._visible_rows() + 1)

    def selection(self):
        return self._selection()
