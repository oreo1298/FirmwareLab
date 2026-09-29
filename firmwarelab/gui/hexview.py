"""A fast hex viewer: only the visible rows are painted; suite-matched styling.

Read-only by design — editing firmware happens through the structured operations
(replace / patch / insert). Shows the selected item's bytes at their real flash
offset, with the same offset/decoded layout, striping, selection band and cursor
box as the EZP2019Linux hex view.
"""

from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QColor, QFontMetricsF, QGuiApplication, QKeySequence, QPainter, QPen
from PySide6.QtWidgets import QAbstractScrollArea, QMenu

from .theme import mono_font, theme

ROW = 16
_HEX_DIGITS = "0123456789abcdefABCDEF"


class HexView(QAbstractScrollArea):
    cursorMoved = Signal(int)
    selectionChanged = Signal(int, int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._data = b""
        self._base = 0
        self.cursor = 0
        self.pane = "hex"
        self.anchor: int | None = None
        self.sel_start = 0
        self.sel_end = 0
        self._highlights: list[tuple[int, int]] = []
        self._empty_text = "No item selected — pick something in the structure tree."
        self.setFrameShape(QAbstractScrollArea.NoFrame)
        self.setFocusPolicy(Qt.StrongFocus)
        self.viewport().setCursor(Qt.IBeamCursor)
        self.setFont(mono_font(10.5))
        self._metrics()
        theme.changed.connect(lambda _p: self.viewport().update())
        self.verticalScrollBar().valueChanged.connect(lambda _v: self.viewport().update())
        self.horizontalScrollBar().valueChanged.connect(lambda _v: self.viewport().update())

    # -- data -------------------------------------------------------------------------
    def set_data(self, data, base: int = 0, empty_text: str | None = None) -> None:
        self._data = bytes(data)
        self._base = base
        self.cursor = 0
        self.anchor = None
        self.sel_start = self.sel_end = 0
        if empty_text is not None:
            self._empty_text = empty_text
        self._highlights = []
        self._layout_changed()
        self.verticalScrollBar().setValue(0)
        self.viewport().update()

    def set_highlights(self, spans) -> None:
        self._highlights = list(spans)
        self.viewport().update()

    def data(self) -> bytes:
        return self._data

    # -- geometry ---------------------------------------------------------------------
    def _metrics(self) -> None:
        fm = QFontMetricsF(self.font())
        self.cw = fm.horizontalAdvance("0")
        self.ascent = fm.ascent()
        self.lh = round(fm.height() + 5)
        self.header_h = self.lh + 8
        self.margin = round(self.cw * 1.5)
        self.x_hex = self.margin + 10 * self.cw
        self.hex_w = ROW * 3 * self.cw + self.cw
        self.x_ascii = self.x_hex + self.hex_w + 1.5 * self.cw
        self.content_w = self.x_ascii + ROW * self.cw + self.margin

    def _hex_x(self, col: int) -> float:
        return self.x_hex + col * 3 * self.cw + (self.cw if col >= 8 else 0)

    def _ascii_x(self, col: int) -> float:
        return self.x_ascii + col * self.cw

    def rows(self) -> int:
        return -(-len(self._data) // ROW)

    def visible_rows(self) -> int:
        return max(1, int((self.viewport().height() - self.header_h) // self.lh))

    def _layout_changed(self) -> None:
        vbar = self.verticalScrollBar()
        vbar.setRange(0, max(0, self.rows() - self.visible_rows()))
        vbar.setPageStep(self.visible_rows())
        vbar.setSingleStep(1)
        hbar = self.horizontalScrollBar()
        hbar.setRange(0, max(0, int(self.content_w - self.viewport().width())))
        hbar.setPageStep(self.viewport().width())
        self.cursor = min(self.cursor, max(0, len(self._data) - 1))
        self.viewport().update()

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self._layout_changed()

    # -- navigation -------------------------------------------------------------------
    def goto(self, offset: int, length: int = 0) -> None:
        if not len(self._data):
            return
        offset = max(0, min(offset, len(self._data) - 1))
        self._move(offset, extend=False)
        if length:
            self.anchor = offset
            self._set_selection(offset, offset + length)
        self.ensure_visible(offset, center=True)

    def ensure_visible(self, offset: int, center: bool = False) -> None:
        row = offset // ROW
        vbar = self.verticalScrollBar()
        top, vis = vbar.value(), self.visible_rows()
        if center and not (top <= row < top + vis):
            vbar.setValue(max(0, row - vis // 2))
        elif row < top:
            vbar.setValue(row)
        elif row >= top + vis:
            vbar.setValue(row - vis + 1)

    def selection(self) -> tuple[int, int]:
        return (self.sel_start, self.sel_end)

    def _set_selection(self, start: int, end: int) -> None:
        n = len(self._data)
        start, end = max(0, min(start, n)), max(0, min(end, n))
        if (start, end) != (self.sel_start, self.sel_end):
            self.sel_start, self.sel_end = start, end
            self.selectionChanged.emit(start, end)
        self.viewport().update()

    # -- painting ---------------------------------------------------------------------
    def paintEvent(self, event) -> None:  # noqa: N802
        pal = theme.palette
        p = QPainter(self.viewport())
        p.setFont(self.font())
        vp = self.viewport().rect()
        p.fillRect(vp, QColor(pal.hex_bg))
        dx = -self.horizontalScrollBar().value()
        cw, lh, asc = self.cw, self.lh, self.ascent
        data = self._data
        size = len(data)
        top = self.verticalScrollBar().value()
        vis = self.visible_rows() + 1
        focused = self.hasFocus()

        c_text = QColor(pal.hex_text)
        c_zero = QColor(pal.hex_zero)
        c_ff = QColor(pal.hex_ff)
        c_ascii = QColor(pal.hex_ascii)
        c_off = QColor(pal.hex_offset)
        c_sel = QColor(pal.hex_selection)
        c_stripe = QColor(pal.hex_stripe)
        c_cursor = QColor(pal.hex_cursor)
        c_hl = QColor(pal.warning)
        c_hl.setAlpha(70)
        sel_a, sel_b = self.sel_start, self.sel_end
        ty = (lh - (asc + QFontMetricsF(self.font()).descent())) / 2 + asc

        for r in range(vis):
            row = top + r
            base = row * ROW
            if base >= size:
                break
            y = self.header_h + r * lh
            if row % 2:
                p.fillRect(QRectF(0, y, vp.width(), lh), c_stripe)
            chunk = data[base:base + ROW]
            n = len(chunk)

            for hs, hl in self._highlights:
                if hs < base + n and hs + hl > base:
                    s = max(hs, base) - base
                    e = min(hs + hl, base + n) - base
                    p.fillRect(QRectF(self._hex_x(s) + dx - cw * 0.5, y + 1,
                                      self._hex_x(e - 1) + dx + cw * 2.5 - (self._hex_x(s) + dx - cw * 0.5),
                                      lh - 2), c_hl)

            if sel_b > sel_a and sel_a < base + n and sel_b > base:
                s = max(sel_a, base) - base
                e = min(sel_b, base + n) - base
                x1 = self._hex_x(s) + dx - cw * 0.5
                x2 = self._hex_x(e - 1) + dx + cw * 2.5
                p.fillRect(QRectF(x1, y + 1, x2 - x1, lh - 2), c_sel)
                p.fillRect(QRectF(self._ascii_x(s) + dx, y + 1, (e - s) * cw, lh - 2), c_sel)

            p.setPen(c_off)
            p.drawText(QPointF(self.margin + dx, y + ty), f"{self._base + base:08X}")

            for i in range(n):
                b = chunk[i]
                hx = self._hex_x(i) + dx
                ax = self._ascii_x(i) + dx
                printable = 0x20 <= b < 0x7F
                color = c_ff if b == 0xFF else c_zero if b == 0x00 else c_text
                text_color = c_ascii if printable else c_zero
                p.setPen(color)
                p.drawText(QPointF(hx, y + ty), f"{b:02X}")
                p.setPen(text_color)
                p.drawText(QPointF(ax, y + ty), chr(b) if printable else "·")

            if base <= self.cursor < base + n:
                i = self.cursor - base
                hx = self._hex_x(i) + dx
                ax = self._ascii_x(i) + dx
                p.setRenderHint(QPainter.Antialiasing, True)
                p.setBrush(Qt.NoBrush)
                p.setPen(QPen(c_cursor, 1.6))
                box_h = QRectF(hx - cw * 0.35, y + 1.5, cw * 2.7, lh - 3)
                box_a = QRectF(ax - 1, y + 1.5, cw + 2, lh - 3)
                active_hex = self.pane == "hex"
                if focused:
                    p.drawRoundedRect(box_h if active_hex else box_a, 3, 3)
                    other = box_a if active_hex else box_h
                    p.drawLine(QPointF(other.left(), other.bottom()), QPointF(other.right(), other.bottom()))
                else:
                    for box in (box_h, box_a):
                        p.drawLine(QPointF(box.left(), box.bottom()), QPointF(box.right(), box.bottom()))
                p.setRenderHint(QPainter.Antialiasing, False)

        # header on top
        p.fillRect(QRectF(0, 0, vp.width(), self.header_h), QColor(pal.hex_bg))
        hy = (self.header_h - lh) / 2 + ty
        cur_col = self.cursor % ROW if size else -1
        p.setPen(QColor(pal.hex_header))
        p.drawText(QPointF(self.margin + dx, hy), "Offset")
        for i in range(ROW):
            p.setPen(c_cursor if i == cur_col else QColor(pal.hex_header))
            p.drawText(QPointF(self._hex_x(i) + dx, hy), f"{i:02X}")
        p.setPen(QColor(pal.hex_header))
        p.drawText(QPointF(self._ascii_x(0) + dx, hy), "Decoded text")
        p.setPen(QPen(QColor(pal.border), 1))
        p.drawLine(0, self.header_h - 1, vp.width(), self.header_h - 1)
        if not size:
            p.setPen(QColor(pal.text_faint))
            p.drawText(QRectF(vp).adjusted(0, self.header_h, 0, 0), Qt.AlignCenter, self._empty_text)
        p.end()

    # -- hit testing ------------------------------------------------------------------
    def _hit(self, pos: QPointF) -> tuple[int, str]:
        x = pos.x() + self.horizontalScrollBar().value()
        y = pos.y()
        row = self.verticalScrollBar().value() + int((y - self.header_h) // self.lh)
        row = max(0, min(row, self.rows() - 1))
        cw = self.cw
        if x >= self.x_ascii - cw * 0.5:
            col = int((x - self.x_ascii) // cw)
            pane = "ascii"
        else:
            rel = x - self.x_hex
            if rel < 8 * 3 * cw:
                col = int(rel // (3 * cw))
            else:
                rel -= 8 * 3 * cw + cw
                col = 8 + int(rel // (3 * cw))
            pane = "hex"
        col = max(0, min(col, ROW - 1))
        offset = min(row * ROW + col, max(0, len(self._data) - 1))
        return offset, pane

    def mousePressEvent(self, event) -> None:  # noqa: N802
        if not len(self._data) or event.button() == Qt.RightButton:
            return super().mousePressEvent(event)
        offset, pane = self._hit(event.position())
        self.pane = pane
        self._move(offset, extend=bool(event.modifiers() & Qt.ShiftModifier))
        self._dragging = True

    def mouseMoveEvent(self, event) -> None:  # noqa: N802
        if getattr(self, "_dragging", False):
            offset, _ = self._hit(event.position())
            self._move(offset, extend=True)

    def mouseReleaseEvent(self, event) -> None:  # noqa: N802
        self._dragging = False

    def contextMenuEvent(self, event) -> None:  # noqa: N802
        if not len(self._data):
            return
        menu = QMenu(self)
        a_hex = menu.addAction("Copy as hex")
        a_txt = menu.addAction("Copy as text")
        menu.addSeparator()
        a_all = menu.addAction("Select all")
        chosen = menu.exec(event.globalPos())
        if chosen == a_hex:
            self.copy(as_text=False)
        elif chosen == a_txt:
            self.copy(as_text=True)
        elif chosen == a_all:
            self.select_all()

    def keyPressEvent(self, event) -> None:  # noqa: N802
        n = len(self._data)
        if not n:
            return super().keyPressEvent(event)
        key = event.key()
        shift = bool(event.modifiers() & Qt.ShiftModifier)
        ctrl = bool(event.modifiers() & Qt.ControlModifier)
        vis = self.visible_rows()
        moves = {Qt.Key_Left: -1, Qt.Key_Right: 1, Qt.Key_Up: -ROW, Qt.Key_Down: ROW,
                 Qt.Key_PageUp: -ROW * vis, Qt.Key_PageDown: ROW * vis}
        if event.matches(QKeySequence.SelectAll):
            self.select_all()
        elif event.matches(QKeySequence.Copy):
            self.copy(as_text=self.pane == "ascii")
        elif key in moves:
            self._move(self.cursor + moves[key], extend=shift)
        elif key == Qt.Key_Home:
            self._move(0 if ctrl else self.cursor - self.cursor % ROW, extend=shift)
        elif key == Qt.Key_End:
            self._move(n - 1 if ctrl else min(n - 1, self.cursor - self.cursor % ROW + ROW - 1), extend=shift)
        elif key in (Qt.Key_Tab, Qt.Key_Backtab):
            self.pane = "ascii" if self.pane == "hex" else "hex"
            self.viewport().update()
        else:
            super().keyPressEvent(event)

    def focusNextPrevChild(self, _next: bool) -> bool:  # noqa: N802
        return False

    def _move(self, offset: int, extend: bool) -> None:
        n = len(self._data)
        offset = max(0, min(offset, n - 1))
        if extend:
            if self.anchor is None:
                self.anchor = self.cursor
            a, b = sorted((self.anchor, offset))
            self._set_selection(a, b + 1)
        else:
            self.anchor = offset
            self._set_selection(offset, offset)
        if offset != self.cursor:
            self.cursor = offset
            self.cursorMoved.emit(offset)
        self.ensure_visible(offset)
        self.viewport().update()

    def select_all(self) -> None:
        self.anchor = 0
        self._set_selection(0, len(self._data))

    def copy(self, as_text: bool = False) -> None:
        a, b = self.selection()
        if b <= a:
            a, b = self.cursor, self.cursor + 1
        chunk = self._data[a:min(b, a + (16 << 20))]
        text = ("".join(chr(c) if 0x20 <= c < 0x7F else "." for c in chunk) if as_text
                else chunk.hex(" ").upper())
        QGuiApplication.clipboard().setText(text)
