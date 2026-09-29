"""Auxiliary dialogs: search, NVRAM editor, Setup browser, IFR viewer, flash wizard."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)


class SearchDialog(QDialog):
    activated = Signal(object)  # node

    def __init__(self, doc, parent=None):
        super().__init__(parent)
        self.doc = doc
        self.setWindowTitle("Search")
        self.resize(720, 460)
        lay = QVBoxLayout(self)
        row = QHBoxLayout()
        self.kind = QComboBox()
        self.kind.addItems(["Text", "GUID", "Hex pattern", "Name"])
        self.query = QLineEdit()
        self.query.returnPressed.connect(self.run)
        btn = QPushButton("Search")
        btn.clicked.connect(self.run)
        row.addWidget(self.kind)
        row.addWidget(self.query, 1)
        row.addWidget(btn)
        lay.addLayout(row)
        self.results = QTableWidget(0, 4)
        self.results.setHorizontalHeaderLabels(["Type", "Name", "Location", "Context"])
        self.results.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.results.setEditTriggers(QTableWidget.NoEditTriggers)
        self.results.cellDoubleClicked.connect(self._activate)
        lay.addWidget(self.results, 1)
        self._matches = []

    def run(self):
        from ..tools import search
        q = self.query.text().strip()
        if not q:
            return
        kind = self.kind.currentText()
        try:
            if kind == "GUID":
                m = search.search_guid(self.doc.root, q)
            elif kind == "Hex pattern":
                m = search.search_hex(self.doc.root, q)
            elif kind == "Name":
                m = search.search_name(self.doc.root, q)
            else:
                m = search.search_text(self.doc.root, q)
        except ValueError as e:
            QMessageBox.warning(self, "Search", str(e))
            return
        self._matches = m
        self.results.setRowCount(len(m))
        for i, mt in enumerate(m):
            off = mt.node.abs_offset
            loc = "%08X" % off if off is not None else "decompressed"
            for c, val in enumerate([mt.node.type.value, mt.node.display_name, loc, mt.context]):
                self.results.setItem(i, c, QTableWidgetItem(str(val)))
        self.setWindowTitle("Search — %d match(es)" % len(m))

    def _activate(self, row, _col):
        if 0 <= row < len(self._matches):
            self.activated.emit(self._matches[row].node)


class NvramDialog(QDialog):
    changed = Signal()

    def __init__(self, doc, parent=None):
        super().__init__(parent)
        self.doc = doc
        self.setWindowTitle("NVRAM variables")
        self.resize(900, 560)
        lay = QVBoxLayout(self)
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Filter by name…")
        self.filter.textChanged.connect(self._reload)
        lay.addWidget(self.filter)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Name", "GUID", "Store", "Size", "Value (hex)"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.cellDoubleClicked.connect(self._edit)
        lay.addWidget(self.table, 1)
        self._vars = []
        self._reload()

    def _reload(self):
        from ..core.guids import guid_db
        from ..formats import nvram
        flt = self.filter.text().lower()
        self._vars = [v for v in nvram.iter_variables(self.doc.root)
                      if flt in (v.meta.get("var_name") or "").lower()]
        self.table.setRowCount(len(self._vars))
        for i, v in enumerate(self._vars):
            role = nvram.store_role(v)
            state = role + ("" if v.meta.get("current", True) else " (inactive)")
            vals = [v.meta.get("var_name"), guid_db().display(v.meta.get("guid") or b""), state,
                    "%Xh" % v.body_size, v.body[:48].hex()]
            for c, val in enumerate(vals):
                it = QTableWidgetItem(str(val))
                if not v.meta.get("current", True):
                    it.setForeground(Qt.gray)
                self.table.setItem(i, c, it)

    def _edit(self, row, _col):
        if not (0 <= row < len(self._vars)):
            return
        v = self._vars[row]
        dlg = ValueEditor(v.meta.get("var_name"), v.body, self)
        if dlg.exec() == QDialog.Accepted:
            try:
                self.doc.set_variable_data(self.doc.resolve(v.path()), dlg.value())
            except Exception as e:
                QMessageBox.warning(self, "Edit variable", str(e))
                return
            self.changed.emit()
            self._reload()


class ValueEditor(QDialog):
    def __init__(self, name, data, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Edit %s" % name)
        self.resize(560, 320)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("Hex bytes (whitespace ignored):"))
        self.edit = QPlainTextEdit()
        f = QFont("monospace")
        f.setStyleHint(QFont.Monospace)
        self.edit.setFont(f)
        self.edit.setPlainText(bytes(data).hex(" "))
        lay.addWidget(self.edit, 1)
        self.ascii = QLineEdit()
        self.ascii.setPlaceholderText("…or type ASCII text and press Set ASCII")
        row = QHBoxLayout()
        row.addWidget(self.ascii, 1)
        b = QPushButton("Set ASCII")
        b.clicked.connect(self._set_ascii)
        row.addWidget(b)
        lay.addLayout(row)
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)

    def _set_ascii(self):
        self.edit.setPlainText(self.ascii.text().encode().hex(" "))

    def value(self) -> bytes:
        txt = "".join(self.edit.toPlainText().split())
        return bytes.fromhex(txt)


class SetupDialog(QDialog):
    def __init__(self, doc, parent=None):
        super().__init__(parent)
        self.doc = doc
        self.setWindowTitle("BIOS Setup browser (read-only)")
        self.resize(1000, 620)
        lay = QVBoxLayout(self)
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Filter questions…")
        self.filter.textChanged.connect(self._reload)
        lay.addWidget(self.filter)
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Question", "Value", "Default", "Type", "Module", "Flags"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        lay.addWidget(self.table, 1)
        from ..hii.setup import SetupBrowser
        try:
            self.browser = SetupBrowser(doc)
        except Exception as e:
            self.browser = None
            lay.addWidget(QLabel("Setup scan failed: %s" % e))
        self._reload()

    def _reload(self):
        if self.browser is None:
            return
        flt = self.filter.text().lower()
        refs = [r for r in self.browser.questions()
                if not flt or flt in r.prompt.lower() or flt in (r.question.help or "").lower()]
        rows = [r for r in refs if r.question.kind not in ("Action",)]
        self.table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            q = r.question
            cur = self.browser.describe_value(r, self.browser.current_value(r))
            dv = self.browser.describe_value(r, q.defaults.get(0)) if q.defaults.get(0) is not None else ""
            flags = []
            if q.hidden:
                flags.append("hidden")
            if q.grayed:
                flags.append("grayed")
            for c, val in enumerate([q.prompt, cur, dv, q.kind, r.module.name, ",".join(flags)]):
                it = QTableWidgetItem(str(val))
                if flags:
                    it.setForeground(Qt.gray)
                self.table.setItem(i, c, it)


class IfrDialog(QDialog):
    def __init__(self, doc, parent=None):
        super().__init__(parent)
        self.setWindowTitle("IFR / HII forms")
        self.resize(1000, 680)
        lay = QHBoxLayout(self)
        self.list = QListWidget()
        self.list.setMaximumWidth(260)
        lay.addWidget(self.list)
        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        f = QFont("monospace")
        f.setStyleHint(QFont.Monospace)
        self.text.setFont(f)
        lay.addWidget(self.text, 1)
        from ..hii import scan
        self.mods = scan.scan(doc.root)
        for m in self.mods:
            self.list.addItem(QListWidgetItem("%s (%d forms)" % (m.name, len(m.form_packages))))
        self.list.currentRowChanged.connect(self._show)
        if self.mods:
            self.list.setCurrentRow(0)
        else:
            self.text.setPlainText("No HII form packages found in this image.")

    def _show(self, row):
        from ..hii.ifr import package_text
        if not (0 <= row < len(self.mods)):
            return
        m = self.mods[row]
        out = []
        for pkg in m.form_packages:
            out.append(package_text(pkg, m.pairing.get(pkg.offset)))
        self.text.setPlainText("\n\n".join(out))


class FlashDialog(QDialog):
    def __init__(self, doc, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Flash readiness")
        self.resize(680, 420)
        lay = QVBoxLayout(self)
        from ..tools import flash
        r = flash.analyze(doc)
        from ..core.binary import human_size
        info = ["Image size: %s (%s)" % ("%Xh" % r.size, human_size(r.size)),
                "Nearest standard chip: %s" % (human_size(r.nearest_chip) if r.nearest_chip else "n/a"),
                "Flash-ready: %s" % ("yes" if r.ok else "NO"), ""]
        for i in r.issues:
            info.append("✗ " + i)
        for n in r.notes:
            info.append("• " + n)
        t = QPlainTextEdit("\n".join(info))
        t.setReadOnly(True)
        lay.addWidget(t, 1)
        bb = QDialogButtonBox(QDialogButtonBox.Close)
        bb.rejected.connect(self.reject)
        bb.accepted.connect(self.accept)
        lay.addWidget(bb)


class DiffDialog(QDialog):
    def __init__(self, entries, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Image comparison")
        self.resize(1000, 620)
        lay = QVBoxLayout(self)
        from ..tools import diff
        s = diff.summarize(entries)
        lay.addWidget(QLabel("%d added, %d removed, %d modified, %d moved" %
                             (s["added"], s["removed"], s["modified"], s["moved"])))
        self.table = QTableWidget(len(entries), 4)
        self.table.setHorizontalHeaderLabels(["Status", "Item", "Path", "Detail"])
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        colors = {"added": "#3ba55d", "removed": "#e05555", "modified": "#d0a020", "moved": "#5599dd"}
        for i, e in enumerate(entries):
            for c, val in enumerate([e.status, e.kind, e.path, e.detail]):
                it = QTableWidgetItem(str(val))
                it.setForeground(Qt.GlobalColor.white if False else it.foreground())
                if c == 0:
                    from PySide6.QtGui import QBrush, QColor
                    it.setForeground(QBrush(QColor(colors.get(e.status, "#aaa"))))
                self.table.setItem(i, c, it)
        lay.addWidget(self.table, 1)
