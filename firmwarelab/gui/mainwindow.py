"""FirmwareLab main window."""

from __future__ import annotations

import os

from PySide6.QtCore import Qt, QSettings
from PySide6.QtGui import QAction, QKeySequence, QFont
from PySide6.QtWidgets import (QApplication, QFileDialog, QInputDialog, QMainWindow,
                              QMessageBox, QPlainTextEdit, QSplitter, QTabWidget, QTableWidget,
                              QTableWidgetItem, QHeaderView, QTreeView, QMenu)

from .. import __app_name__, __version__
from ..core.binary import human_size
from ..core.node import Node, NodeType
from . import theme
from .hexview import HexView
from .treemodel import FirmwareTreeModel


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.doc = None
        self.model = None
        self.dark = True
        self.settings = QSettings("FirmwareLab", "FirmwareLab")
        self.dark = self.settings.value("dark", True, type=bool)
        self.setWindowTitle(__app_name__)
        self.resize(1360, 860)
        self._build_ui()
        self._build_menu()
        self.apply_theme()
        self._update_actions()

    # ------------------------------------------------------------------ UI
    def _build_ui(self):
        splitter = QSplitter(Qt.Horizontal)
        self.tree = QTreeView()
        self.tree.setUniformRowHeights(True)
        self.tree.setAlternatingRowColors(False)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._tree_menu)
        splitter.addWidget(self.tree)

        right = QSplitter(Qt.Vertical)
        self.tabs = QTabWidget()
        self.info = QTableWidget(0, 2)
        self.info.setHorizontalHeaderLabels(["Property", "Value"])
        self.info.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.info.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.info.setEditTriggers(QTableWidget.NoEditTriggers)
        self.info.verticalHeader().setVisible(False)
        self.tabs.addTab(self.info, "Information")

        self.hex = HexView()
        self.tabs.addTab(self.hex, "Hex")

        self.textview = QPlainTextEdit()
        self.textview.setReadOnly(True)
        mono = QFont("monospace")
        mono.setStyleHint(QFont.Monospace)
        self.textview.setFont(mono)
        self.tabs.addTab(self.textview, "Text / Body")

        right.addWidget(self.tabs)
        self.messages = QPlainTextEdit()
        self.messages.setReadOnly(True)
        self.messages.setMaximumHeight(160)
        right.addWidget(self.messages)
        right.setStretchFactor(0, 4)
        right.setStretchFactor(1, 1)
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 4)
        self.setCentralWidget(splitter)
        self.status = self.statusBar()
        self.status.showMessage("Open a firmware image to begin")

    def _act(self, text, slot, shortcut=None, tip=None):
        a = QAction(text, self)
        a.triggered.connect(slot)
        if shortcut:
            a.setShortcut(QKeySequence(shortcut))
        if tip:
            a.setStatusTip(tip)
        return a

    def _build_menu(self):
        mb = self.menuBar()
        m = mb.addMenu("&File")
        self.act_open = self._act("&Open…", self.open_file, "Ctrl+O")
        self.act_save = self._act("&Save", self.save_file, "Ctrl+S")
        self.act_saveas = self._act("Save &As…", self.save_file_as, "Ctrl+Shift+S")
        self.act_reload = self._act("&Reload", self.reload_file, "Ctrl+R")
        m.addAction(self.act_open)
        m.addAction(self.act_save)
        m.addAction(self.act_saveas)
        m.addAction(self.act_reload)
        m.addSeparator()
        m.addAction(self._act("E&xit", self.close, "Ctrl+Q"))

        e = mb.addMenu("&Edit")
        self.act_undo = self._act("&Undo", self.undo, "Ctrl+Z")
        self.act_redo = self._act("&Redo", self.redo, "Ctrl+Y")
        e.addAction(self.act_undo)
        e.addAction(self.act_redo)
        e.addSeparator()
        self.act_extract = self._act("&Extract…", self.extract_item, "Ctrl+E")
        self.act_extract_body = self._act("Extract &body / uncompressed…", lambda: self.extract_item("uncompressed"))
        self.act_replace = self._act("&Replace body…", self.replace_item)
        self.act_replace_full = self._act("Replace &file…", lambda: self.replace_item("full"))
        self.act_insert = self._act("&Insert file/section…", self.insert_item)
        self.act_remove = self._act("Re&move", self.remove_item, "Del")
        self.act_rebuild = self._act("Re&build", self.rebuild_item)
        for a in (self.act_extract, self.act_extract_body, self.act_replace, self.act_replace_full,
                  self.act_insert, self.act_remove, self.act_rebuild):
            e.addAction(a)

        t = mb.addMenu("&Tools")
        t.addAction(self._act("&Search…", self.open_search, "Ctrl+F"))
        t.addAction(self._act("&NVRAM variables…", self.open_nvram))
        t.addAction(self._act("BIOS &Setup browser…", self.open_setup))
        t.addAction(self._act("&IFR / HII forms…", self.open_ifr))
        t.addSeparator()
        t.addAction(self._act("&Compare with…", self.open_diff))
        t.addAction(self._act("&Apply patch script…", self.apply_patch))
        t.addAction(self._act("&Flash readiness…", self.open_flash))
        t.addSeparator()
        t.addAction(self._act("&Descriptor: unlock", self.descriptor_unlock))
        t.addAction(self._act("&Report to file…", self.export_report))

        v = mb.addMenu("&View")
        self.act_theme = self._act("Toggle &dark theme", self.toggle_theme, "Ctrl+D")
        v.addAction(self.act_theme)
        v.addAction(self._act("E&xpand all", lambda: self.tree.expandToDepth(4)))
        v.addAction(self._act("&Collapse all", self.tree.collapseAll))

        h = mb.addMenu("&Help")
        h.addAction(self._act("&About", self.about))

        tb = self.addToolBar("Main")
        tb.setMovable(False)
        for a in (self.act_open, self.act_save, self.act_undo, self.act_redo):
            tb.addAction(a)
        tb.addSeparator()
        tb.addAction(self.act_extract)
        tb.addAction(self.act_replace)

    # ------------------------------------------------------------------ theme
    def apply_theme(self):
        app = QApplication.instance()
        if self.dark:
            app.setStyleSheet(theme.DARK_QSS)
        else:
            app.setStyleSheet(theme.LIGHT_QSS)
        if self.model:
            self.model.dark = self.dark
            self.model.layoutChanged.emit()

    def toggle_theme(self):
        self.dark = not self.dark
        self.settings.setValue("dark", self.dark)
        self.apply_theme()

    # ------------------------------------------------------------------ file ops
    def open_file(self, path=None):
        if not path:
            path, _ = QFileDialog.getOpenFileName(self, "Open firmware image", "",
                                                  "Firmware (*.bin *.rom *.fd *.cap *.fv *.efi *.wph);;All files (*)")
        if not path:
            return
        self.load(path)

    def load(self, path):
        from ..tools.project import Document
        try:
            self.doc = Document.open(path)
        except Exception as e:
            QMessageBox.critical(self, "Open", "Failed to parse %s:\n%s" % (path, e))
            return
        self.doc.listeners.append(self._on_doc_change)
        self.model = FirmwareTreeModel(self.doc.root, self.dark)
        self.tree.setModel(self.model)
        self.tree.selectionModel().currentChanged.connect(self._on_select)
        self.tree.expandToDepth(2)
        hdr = self.tree.header()
        from PySide6.QtWidgets import QHeaderView
        hdr.setSectionResizeMode(0, QHeaderView.Interactive)
        self.tree.setColumnWidth(0, 340)
        self.tree.setColumnWidth(1, 90)
        self.tree.setColumnWidth(2, 130)
        self.tree.setColumnWidth(3, 80)
        self.tree.setColumnWidth(4, 80)
        self._refresh_messages()
        self._update_title()
        self._update_actions()
        n = self.doc.root.count()
        self.status.showMessage("Loaded %s — %d items, %s" % (os.path.basename(path), n, human_size(self.doc.root.size)))

    def _rebind_model(self):
        self.model.set_root(self.doc.root)
        self.tree.expandToDepth(2)
        self._refresh_messages()
        self._update_title()
        self._update_actions()

    def _on_doc_change(self, what):
        self._rebind_model()

    def save_file(self):
        if not self.doc:
            return
        if not self.doc.path:
            return self.save_file_as()
        self._do_save(self.doc.path)

    def save_file_as(self):
        if not self.doc:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save firmware image", self.doc.path or "", "All files (*)")
        if path:
            self._do_save(path)

    def _do_save(self, path):
        try:
            rep = self.doc.save(path, backup=True, verify=True, reload=True)
        except Exception as e:
            QMessageBox.critical(self, "Save", "Build failed:\n%s" % e)
            return
        if not rep.ok:
            QMessageBox.critical(self, "Save", "Verification failed, file not written:\n\n" + "\n".join(rep.errors))
            return
        self._rebind_model()
        msg = "Saved %s" % os.path.basename(path)
        if rep.warnings:
            msg += " (%d warning(s))" % len(rep.warnings)
        self.status.showMessage(msg)
        if rep.warnings or rep.moved:
            self.messages.appendPlainText("--- save report ---")
            for m in rep.moved:
                self.messages.appendPlainText("moved: " + m)
            for w in rep.warnings:
                self.messages.appendPlainText("warning: " + w)

    def reload_file(self):
        if self.doc and self.doc.path:
            if self.doc.modified:
                if QMessageBox.question(self, "Reload", "Discard unsaved changes?") != QMessageBox.Yes:
                    return
            self.load(self.doc.path)

    # ------------------------------------------------------------------ selection
    def current_node(self) -> Node | None:
        if not self.model:
            return None
        idx = self.tree.currentIndex()
        return self.model.node_at(idx)

    def _on_select(self, cur, _prev):
        node = self.model.node_at(cur)
        if node is None:
            return
        self._show_info(node)
        data = node.content if node.decoded is not None else node.data
        base = node.abs_offset or 0
        self.hex.set_data(data[:1 << 20], base)
        self.hex.setEditable(False)
        self._show_text(node)
        self._update_actions()

    def _show_info(self, node: Node):
        rows = [("Type", node.type.value), ("Subtype", node.subtype), ("Name", node.name)]
        if node.text:
            rows.append(("Text", node.text))
        off = node.abs_offset
        rows.append(("Offset", "%08Xh" % off if off is not None else "in decompressed data"))
        if node.meta.get("address"):
            rows.append(("Memory address", "%08Xh" % node.meta["address"]))
        rows.append(("Full size", "%Xh (%s)" % (node.size, human_size(node.size))))
        rows.append(("Header size", "%Xh" % node.hdr_size))
        rows.append(("Body size", "%Xh" % node.body_size))
        if node.flags:
            rows.append(("Flags", ", ".join(sorted(node.flags))))
        rows.extend(node.info)
        self.info.setRowCount(len(rows))
        for i, (k, v) in enumerate(rows):
            self.info.setItem(i, 0, QTableWidgetItem(str(k)))
            self.info.setItem(i, 1, QTableWidgetItem(str(v)))
        if node.messages:
            r = self.info.rowCount()
            self.info.setRowCount(r + len(node.messages))
            for j, m in enumerate(node.messages):
                self.info.setItem(r + j, 0, QTableWidgetItem("⚠ message"))
                self.info.setItem(r + j, 1, QTableWidgetItem(m))

    def _show_text(self, node: Node):
        t = node.meta.get("depex") or node.meta.get("version")
        if node.meta.get("type") == 0x15:
            t = node.meta.get("ui")
        if t:
            self.textview.setPlainText(str(t))
            return
        data = node.content if node.decoded is not None else node.body
        printable = bytes(b if 32 <= b < 127 or b in (9, 10, 13) else 0x2E for b in data[:65536])
        self.textview.setPlainText(printable.decode("latin-1"))

    def _refresh_messages(self):
        self.messages.clear()
        msgs = [(n, m) for n in self.doc.root.walk() for m in n.messages]
        for n, m in msgs:
            self.messages.appendPlainText("%s: %s" % (n.display_name, m))
        if not msgs:
            self.messages.appendPlainText("No parser warnings.")

    # ------------------------------------------------------------------ edit ops
    def _need_node(self):
        n = self.current_node()
        if n is None:
            QMessageBox.information(self, __app_name__, "Select an item first.")
        return n

    def extract_item(self, mode="full"):
        n = self._need_node()
        if not n:
            return
        default = (n.text or n.name or n.type.value).replace("/", "_")
        ext = ".ffs" if n.type == NodeType.FILE else (".sct" if n.type == NodeType.SECTION else ".bin")
        path, _ = QFileDialog.getSaveFileName(self, "Extract", default + ext)
        if not path:
            return
        try:
            self.doc.extract_to(n, path, mode if mode != "uncompressed" or n.decoded is not None else "body")
        except Exception as e:
            QMessageBox.warning(self, "Extract", str(e))
            return
        self.status.showMessage("Extracted to " + path)

    def replace_item(self, mode="body"):
        n = self._need_node()
        if not n:
            return
        path, _ = QFileDialog.getOpenFileName(self, "Replace with file")
        if not path:
            return
        with open(path, "rb") as fh:
            data = fh.read()
        from ..tools.project import EditError
        try:
            self.doc.replace(n, data, mode=mode)
        except EditError as e:
            QMessageBox.warning(self, "Replace", str(e))
            return
        self.status.showMessage("Replaced %s" % n.display_name)

    def insert_item(self):
        n = self._need_node()
        if not n:
            return
        where, ok = QInputDialog.getItem(self, "Insert", "Position:", ["into", "before", "after"], 0, False)
        if not ok:
            return
        path, _ = QFileDialog.getOpenFileName(self, "Insert file/section")
        if not path:
            return
        with open(path, "rb") as fh:
            data = fh.read()
        from ..tools.project import EditError
        try:
            self.doc.insert(n, data, where=where)
        except EditError as e:
            QMessageBox.warning(self, "Insert", str(e))
            return
        self.status.showMessage("Inserted into %s" % n.display_name)

    def remove_item(self):
        n = self._need_node()
        if not n:
            return
        if QMessageBox.question(self, "Remove", "Remove %s?" % n.display_name) != QMessageBox.Yes:
            return
        from ..tools.project import EditError
        try:
            self.doc.remove(n)
        except EditError as e:
            QMessageBox.warning(self, "Remove", str(e))

    def rebuild_item(self):
        n = self._need_node()
        if not n:
            return
        self.doc.rebuild(n)

    def undo(self):
        if self.doc:
            d = self.doc.undo()
            if d:
                self.status.showMessage("Undo: " + d)

    def redo(self):
        if self.doc:
            d = self.doc.redo()
            if d:
                self.status.showMessage("Redo: " + d)

    # ------------------------------------------------------------------ dialogs
    def open_search(self):
        if not self.doc:
            return
        from .dialogs import SearchDialog
        dlg = SearchDialog(self.doc, self)
        dlg.activated.connect(self._reveal)
        dlg.show()

    def _reveal(self, node):
        idx = self.model.index_for_node(node)
        if idx.isValid():
            self.tree.setCurrentIndex(idx)
            self.tree.scrollTo(idx)

    def open_nvram(self):
        if not self.doc:
            return
        from .dialogs import NvramDialog
        dlg = NvramDialog(self.doc, self)
        dlg.changed.connect(lambda: self.status.showMessage("NVRAM variable modified"))
        dlg.exec()

    def open_setup(self):
        if self.doc:
            from .dialogs import SetupDialog
            SetupDialog(self.doc, self).exec()

    def open_ifr(self):
        if self.doc:
            from .dialogs import IfrDialog
            IfrDialog(self.doc, self).exec()

    def open_flash(self):
        if self.doc:
            from .dialogs import FlashDialog
            FlashDialog(self.doc, self).exec()

    def open_diff(self):
        if not self.doc:
            return
        path, _ = QFileDialog.getOpenFileName(self, "Compare with image")
        if not path:
            return
        from ..tools.project import Document
        from ..tools import diff
        from .dialogs import DiffDialog
        try:
            other = Document.open(path)
        except Exception as e:
            QMessageBox.critical(self, "Compare", str(e))
            return
        entries = diff.diff_trees(self.doc.root, other.root)
        DiffDialog(entries, self).exec()

    def apply_patch(self):
        if not self.doc:
            return
        path, _ = QFileDialog.getOpenFileName(self, "Apply patch script", "", "Patch scripts (*.txt *.json);;All (*)")
        if not path:
            return
        from ..tools import patch
        with open(path) as fh:
            script = fh.read()
        try:
            res = patch.apply_script(self.doc, script)
        except patch.PatchError as e:
            QMessageBox.warning(self, "Patch", str(e))
            return
        QMessageBox.information(self, "Patch", "Applied %d change(s)." % len(res))

    def descriptor_unlock(self):
        if not self.doc or self.doc.root.meta.get("descriptor") is None:
            QMessageBox.information(self, "Descriptor", "This image has no Intel flash descriptor.")
            return
        from ..formats import descriptor
        data = self.doc.build()
        newdata = descriptor.unlock(data, descriptor.parse(data))
        self.doc.apply_raw_image(newdata, "Unlock flash descriptor")
        self.status.showMessage("Flash descriptor unlocked (BIOS/ME masters granted full access)")

    def export_report(self):
        if not self.doc:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save report", "report.txt",
                                              "Text (*.txt);;JSON (*.json)")
        if not path:
            return
        from ..tools import report
        with open(path, "w") as fh:
            fh.write(report.report_json(self.doc.root) if path.endswith(".json")
                     else report.report_text(self.doc.root))
        self.status.showMessage("Report written to " + path)

    def _tree_menu(self, pos):
        n = self.current_node()
        if n is None:
            return
        m = QMenu(self)
        m.addAction(self.act_extract)
        m.addAction(self.act_extract_body)
        m.addSeparator()
        m.addAction(self.act_replace)
        m.addAction(self.act_replace_full)
        m.addAction(self.act_insert)
        m.addAction(self.act_remove)
        m.addAction(self.act_rebuild)
        m.exec(self.tree.viewport().mapToGlobal(pos))

    # ------------------------------------------------------------------ state
    def _update_title(self):
        if self.doc:
            star = "*" if self.doc.modified else ""
            self.setWindowTitle("%s — %s%s" % (__app_name__, self.doc.name, star))
        else:
            self.setWindowTitle(__app_name__)

    def _update_actions(self):
        has = self.doc is not None
        for a in (self.act_save, self.act_saveas, self.act_reload, self.act_extract, self.act_extract_body,
                  self.act_replace, self.act_replace_full, self.act_insert, self.act_remove, self.act_rebuild):
            a.setEnabled(has)
        if has:
            self.act_undo.setEnabled(bool(self.doc.undo_stack))
            self.act_redo.setEnabled(bool(self.doc.redo_stack))
        self._update_title()

    def about(self):
        QMessageBox.about(self, "About " + __app_name__,
                          "<h3>%s %s</h3>"
                          "<p>A modern UEFI/BIOS firmware explorer, editor and modding toolkit.</p>"
                          "<p>Parses and rebuilds UEFI volumes, FFS files, sections, NVRAM stores, "
                          "Intel flash descriptor / ME, microcode, FIT and Boot Guard, capsules and more.</p>"
                          "<p>GUID database and format details derived from UEFITool "
                          "(© Nikolaj Schlej, BSD-2-Clause).</p>" % (__app_name__, __version__))
