"""FirmwareLab main window — styled as part of the EZP2019Linux suite."""

from __future__ import annotations

import os
import time

from PySide6.QtCore import QSettings, QSize, Qt
from PySide6.QtGui import QAction, QCursor, QGuiApplication, QKeySequence
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QStackedWidget,
    QTabWidget,
    QToolBar,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from .. import __app_name__, __version__
from ..core.binary import human_size
from ..core.node import Node, NodeType
from . import icons
from .hexview import HexView
from .theme import mono_font, theme
from .treemodel import FirmwareTreeModel
from .widgets import Card, KeyValueGrid, StatTile, StatusDot, Toast, scaled_font
from .worker import OpenWorker, SaveWorker, run_async

MAX_RECENT = 10
SUBTITLE = "Firmware Editor for Linux"


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.doc = None
        self.model = None
        self._busy = False
        self._icon_actions: list[tuple[QAction, str]] = []
        self.settings = QSettings("firmwarelab", "firmwarelab")
        self.recent = list(self.settings.value("recent", [], type=list) or [])
        self.setWindowTitle(__app_name__)
        self.resize(1380, 880)
        self.setMinimumSize(1000, 660)
        self.setAcceptDrops(True)

        self._build_menu()
        self._build_toolbar()
        self._build_body()
        self._build_statusbar()
        self.toast = Toast(self.centralWidget())

        theme.changed.connect(self._retheme)
        self._retheme(theme.palette)
        self._update_actions()
        self._update_recent_menu()

    # ================================================================== construction
    def _act(self, text, slot, shortcut=None, tip=None, icon=None):
        a = QAction(text, self)
        a.triggered.connect(slot)
        if shortcut:
            a.setShortcut(QKeySequence(shortcut))
        if tip:
            a.setStatusTip(tip)
        if icon:
            self._icon_actions.append((a, icon))
        return a

    def _build_menu(self):
        mb = self.menuBar()
        m = mb.addMenu("&File")
        self.act_open = self._act("&Open…", self.open_file, "Ctrl+O", icon="open")
        self.act_save = self._act("&Save", self.save_file, "Ctrl+S", icon="save")
        self.act_saveas = self._act("Save &As…", self.save_file_as, "Ctrl+Shift+S")
        self.act_reload = self._act("&Reload", self.reload_file, "Ctrl+R")
        m.addAction(self.act_open)
        self.recent_menu = m.addMenu("Open &Recent")
        m.addAction(self.act_save)
        m.addAction(self.act_saveas)
        m.addAction(self.act_reload)
        m.addSeparator()
        m.addAction(self._act("E&xit", self.close, "Ctrl+Q"))

        e = mb.addMenu("&Edit")
        self.act_undo = self._act("&Undo", self.undo, "Ctrl+Z", icon="undo")
        self.act_redo = self._act("&Redo", self.redo, "Ctrl+Y", icon="redo")
        e.addAction(self.act_undo)
        e.addAction(self.act_redo)
        e.addSeparator()
        self.act_extract = self._act("&Extract…", self.extract_item, "Ctrl+E", icon="extract")
        self.act_extract_body = self._act("Extract &body / uncompressed…", lambda: self.extract_item("uncompressed"))
        self.act_replace = self._act("&Replace body…", self.replace_item, icon="patch")
        self.act_replace_full = self._act("Replace &file…", lambda: self.replace_item("full"))
        self.act_insert = self._act("&Insert file/section…", self.insert_item, icon="insert")
        self.act_remove = self._act("Re&move", self.remove_item, "Del", icon="remove")
        self.act_rebuild = self._act("Re&build", self.rebuild_item, icon="rebuild")
        for a in (self.act_extract, self.act_extract_body, self.act_replace, self.act_replace_full,
                  self.act_insert, self.act_remove, self.act_rebuild):
            e.addAction(a)

        t = mb.addMenu("&Tools")
        self.act_search = self._act("&Search…", self.open_search, "Ctrl+F", icon="search")
        t.addAction(self.act_search)
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
        v.addAction(self._act("Toggle &theme", self.toggle_theme, "Ctrl+D"))
        v.addAction(self._act("E&xpand all", lambda: self.tree.expandToDepth(6)))
        v.addAction(self._act("&Collapse all", lambda: self.tree.collapseAll()))

        h = mb.addMenu("&Help")
        h.addAction(self._act("&About", self.about))

    def _tool(self, action: QAction, primary: bool = False) -> QToolButton:
        btn = QToolButton()
        btn.setDefaultAction(action)
        btn.setToolButtonStyle(Qt.ToolButtonTextUnderIcon)
        btn.setIconSize(QSize(22, 22))
        btn.setCursor(Qt.PointingHandCursor)
        if primary:
            btn.setProperty("accent", True)
        return btn

    def _build_toolbar(self):
        tb = QToolBar()
        tb.setMovable(False)
        tb.setFloatable(False)
        tb.setIconSize(QSize(22, 22))
        self.addToolBar(Qt.TopToolBarArea, tb)

        # app identity
        ident = QWidget()
        il = QHBoxLayout(ident)
        il.setContentsMargins(4, 0, 8, 0)
        il.setSpacing(10)
        self.app_icon = QLabel()
        il.addWidget(self.app_icon)
        text = QVBoxLayout()
        text.setSpacing(0)
        name = QLabel(__app_name__)
        name.setObjectName("AppName")
        name.setFont(scaled_font(name, 1.35, bold=True))
        self.subtitle = QLabel(SUBTITLE)
        self.subtitle.setObjectName("Faint")
        self.subtitle.setFont(scaled_font(self.subtitle, 0.85))
        text.addWidget(name)
        text.addWidget(self.subtitle)
        il.addLayout(text)
        tb.addWidget(ident)
        tb.addSeparator()

        tb.addWidget(self._tool(self.act_open))
        tb.addWidget(self._tool(self.act_save, primary=True))
        tb.addSeparator()
        tb.addWidget(self._tool(self.act_extract))
        tb.addWidget(self._tool(self.act_replace))
        tb.addWidget(self._tool(self.act_insert))
        tb.addWidget(self._tool(self.act_remove))
        tb.addSeparator()
        tb.addWidget(self._tool(self.act_undo))
        tb.addWidget(self._tool(self.act_redo))
        tb.addSeparator()
        tb.addWidget(self._tool(self.act_search))

        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        tb.addWidget(spacer)

        # status pill
        pill = QWidget()
        pl = QHBoxLayout(pill)
        pl.setContentsMargins(0, 0, 0, 0)
        pl.setSpacing(8)
        self.pill = QLabel("No image loaded")
        self.pill.setObjectName("Pill")
        self.pill_dot = StatusDot(9)
        holder = QWidget()
        hl = QHBoxLayout(holder)
        hl.setContentsMargins(12, 4, 6, 4)
        hl.setSpacing(8)
        hl.addWidget(self.pill_dot)
        self.pill_label = QLabel("No image loaded")
        hl.addWidget(self.pill_label)
        holder.setObjectName("Pill")
        pl.addWidget(holder)
        tb.addWidget(pill)

        self.btn_theme = QToolButton()
        self.btn_theme.setObjectName("Flat")
        self.btn_theme.setCursor(Qt.PointingHandCursor)
        self.btn_theme.setToolTip("Toggle light / dark theme")
        self.btn_theme.clicked.connect(self.toggle_theme)
        tb.addWidget(self.btn_theme)

        self.btn_about = QToolButton()
        self.btn_about.setObjectName("Flat")
        self.btn_about.setCursor(Qt.PointingHandCursor)
        self.btn_about.setToolTip("About FirmwareLab")
        self.btn_about.clicked.connect(self.about)
        tb.addWidget(self.btn_about)

    def _build_body(self):
        page = QWidget()
        page.setObjectName("Page")
        outer = QHBoxLayout(page)
        outer.setContentsMargins(12, 12, 12, 10)
        outer.setSpacing(10)

        split = QSplitter(Qt.Horizontal)
        split.setChildrenCollapsible(False)
        split.setHandleWidth(8)

        # --- structure card
        self.tree_card = Card("Structure", icon="structure")
        self.tree = self._make_tree()
        self.left_stack = QStackedWidget()
        self.welcome = self._make_welcome()
        self.left_stack.addWidget(self.welcome)  # 0
        self.left_stack.addWidget(self.tree)     # 1
        self.tree_card.add(self.left_stack, 1)
        split.addWidget(self.tree_card)

        # --- right column
        right = QSplitter(Qt.Vertical)
        right.setChildrenCollapsible(False)
        right.setHandleWidth(8)

        self.detail_card = Card("Details", icon="info")
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.addTab(self._make_info_tab(), "Information")
        self.tabs.addTab(self._make_hex_tab(), "Hex")
        self.tabs.addTab(self._make_text_tab(), "Text")
        self.detail_card.add(self.tabs, 1)
        right.addWidget(self.detail_card)

        self.log_card = Card("Activity", icon="log")
        self.clear_log_btn = QToolButton()
        self.clear_log_btn.setText("Clear")
        self.clear_log_btn.setAutoRaise(True)
        self.clear_log_btn.setCursor(Qt.PointingHandCursor)
        self.clear_log_btn.clicked.connect(lambda: self.messages.clear())
        self.log_card.add_header_widget(self.clear_log_btn)
        self.messages = QPlainTextEdit()
        self.messages.setObjectName("Log")
        self.messages.setReadOnly(True)
        self.messages.setFont(mono_font(9.5))
        self.log_card.add(self.messages, 1)
        right.addWidget(self.log_card)
        right.setStretchFactor(0, 5)
        right.setStretchFactor(1, 2)

        split.addWidget(right)
        split.setStretchFactor(0, 5)
        split.setStretchFactor(1, 6)
        outer.addWidget(split)
        self.setCentralWidget(page)

    def _make_tree(self):
        from PySide6.QtWidgets import QTreeView
        tree = QTreeView()
        tree.setUniformRowHeights(True)
        tree.setAllColumnsShowFocus(True)
        tree.setContextMenuPolicy(Qt.CustomContextMenu)
        tree.customContextMenuRequested.connect(self._tree_menu)
        tree.setIndentation(16)
        return tree

    def _make_welcome(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setAlignment(Qt.AlignCenter)
        lay.setSpacing(8)
        self.welcome_icon = QLabel()
        self.welcome_icon.setAlignment(Qt.AlignCenter)
        lay.addWidget(self.welcome_icon)
        title = QLabel("Open a firmware image")
        title.setObjectName("Heading")
        title.setFont(scaled_font(title, 1.2, bold=True))
        title.setAlignment(Qt.AlignCenter)
        lay.addWidget(title)
        hint = QLabel("File → Open · Ctrl+O · or drag a .bin / .rom / .fd / .cap here")
        hint.setObjectName("Faint")
        hint.setAlignment(Qt.AlignCenter)
        lay.addWidget(hint)
        return w

    def _make_info_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(2, 6, 2, 2)
        lay.setSpacing(10)
        tiles = QHBoxLayout()
        tiles.setSpacing(8)
        self.tile_size = StatTile("Size")
        self.tile_items = StatTile("Items")
        self.tile_vendor = StatTile("Detected")
        for t in (self.tile_size, self.tile_items, self.tile_vendor):
            tiles.addWidget(t, 1)
        lay.addLayout(tiles)
        divider = QFrame()
        divider.setObjectName("Divider")
        lay.addWidget(divider)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        holder = QWidget()
        hl = QVBoxLayout(holder)
        hl.setContentsMargins(0, 0, 0, 0)
        hl.setSpacing(8)
        self.info_grid = KeyValueGrid()
        hl.addWidget(self.info_grid)
        self.info_msgs = QLabel()
        self.info_msgs.setWordWrap(True)
        self.info_msgs.setObjectName("Muted")
        self.info_msgs.hide()
        hl.addWidget(self.info_msgs)
        hl.addStretch(1)
        scroll.setWidget(holder)
        lay.addWidget(scroll, 1)
        return w

    def _make_hex_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(2, 6, 2, 2)
        lay.setSpacing(8)
        bar = QHBoxLayout()
        bar.setSpacing(8)
        self.goto_edit = QLineEdit()
        self.goto_edit.setPlaceholderText("Go to 0x…")
        self.goto_edit.setMaximumWidth(160)
        self.goto_edit.returnPressed.connect(self._hex_goto)
        self.find_edit = QLineEdit()
        self.find_edit.setPlaceholderText("Find hex or text…")
        self.find_edit.returnPressed.connect(self._hex_find)
        bar.addWidget(self.goto_edit)
        bar.addWidget(self.find_edit, 1)
        lay.addLayout(bar)
        self.hex = HexView()
        self.hex.cursorMoved.connect(lambda _o: self._update_hex_status())
        self.hex.selectionChanged.connect(lambda _a, _b: self._update_hex_status())
        lay.addWidget(self.hex, 1)
        self.hex_status = QLabel("")
        self.hex_status.setObjectName("Muted")
        self.hex_status.setFont(mono_font(9))
        lay.addWidget(self.hex_status)
        return w

    def _make_text_tab(self):
        self.textview = QPlainTextEdit()
        self.textview.setReadOnly(True)
        self.textview.setFont(mono_font(10))
        return self.textview

    def _build_statusbar(self):
        sb = self.statusBar()
        self.status_dot = StatusDot(9)
        self.status_label = QLabel("Ready")
        sb.addWidget(self.status_dot)
        sb.addWidget(self.status_label)
        self.status_right = QLabel("")
        self.status_right.setObjectName("Muted")
        sb.addPermanentWidget(self.status_right)

    # ================================================================== theming
    def _retheme(self, palette):
        self.app_icon.setPixmap(icons.pixmap("chip", palette.accent, 30))
        self.welcome_icon.setPixmap(icons.pixmap("binary", palette.text_faint, 52))
        for action, name in self._icon_actions:
            action.setIcon(icons.icon(name, palette.text, palette.text_faint))
        self.btn_theme.setIcon(icons.icon("sun" if palette.dark else "moon", palette.text_muted))
        self.btn_about.setIcon(icons.icon("info", palette.text_muted))
        self.clear_log_btn.setIcon(icons.icon("close", palette.text_muted, size=16))
        self.status_dot.set_color(palette.success if self.doc else palette.text_faint,
                                  halo=self.doc is not None)
        if self.model:
            self.model.refresh_theme()
        self._update_pill()

    def toggle_theme(self):
        mode = theme.toggle(QApplication.instance())
        self.settings.setValue("theme", mode)

    # ================================================================== drag & drop
    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls() and any(u.isLocalFile() for u in e.mimeData().urls()):
            e.acceptProposedAction()

    def dropEvent(self, e):
        for u in e.mimeData().urls():
            if u.isLocalFile():
                self.open_file(u.toLocalFile())
                break

    # ================================================================== file ops
    def open_file(self, path=None):
        if self._busy:
            return
        if not path:
            path, _ = QFileDialog.getOpenFileName(
                self, "Open firmware image", "",
                "Firmware (*.bin *.rom *.fd *.cap *.fv *.efi *.wph *.scap);;All files (*)")
        if path:
            self.load(path)

    def _set_busy(self, busy, message=""):
        self._busy = busy
        if busy:
            QGuiApplication.setOverrideCursor(QCursor(Qt.WaitCursor))
        else:
            QGuiApplication.restoreOverrideCursor()
        if message:
            self.status_label.setText(message)
        self.status_dot.set_color(theme.palette.warning if busy else
                                  (theme.palette.success if self.doc else theme.palette.text_faint),
                                  halo=busy or self.doc is not None)
        self.act_open.setEnabled(not busy)
        self._update_actions()

    def load(self, path):
        if self._busy:
            return
        if not os.path.isfile(path):
            QMessageBox.warning(self, "Open", "File not found:\n%s" % path)
            self._remove_recent(path)
            return
        self._set_busy(True, "Parsing %s…" % os.path.basename(path))
        run_async(self, OpenWorker(path), on_done=self._on_loaded, on_failed=self._on_load_failed)

    def _on_load_failed(self, msg, path):
        self._set_busy(False, "Failed to open %s" % os.path.basename(path))
        self.toast.show_message("Could not parse %s: %s" % (os.path.basename(path), msg), "error")
        QMessageBox.critical(self, "Open", "Failed to parse %s:\n\n%s" % (path, msg))

    def _on_loaded(self, doc, path):
        self.doc = doc
        self.doc.listeners.append(self._on_doc_change)
        self.model = FirmwareTreeModel(self.doc.root)
        self.tree.setModel(self.model)
        self.tree.selectionModel().currentChanged.connect(self._on_select)
        self.tree.expandToDepth(2)
        hdr = self.tree.header()
        hdr.setSectionResizeMode(0, QHeaderView.Interactive)
        self.tree.setColumnWidth(0, 320)
        for c, wdt in ((1, 90), (2, 130), (3, 84), (4, 84)):
            self.tree.setColumnWidth(c, wdt)
        self.left_stack.setCurrentIndex(1)
        self._refresh_messages()
        self._refresh_summary()
        self._add_recent(path)
        self._set_busy(False, "Loaded %s" % os.path.basename(path))
        self.toast.show_message("Loaded %s — %d items, %s" %
                                (os.path.basename(path), self.doc.root.count(), human_size(self.doc.root.size)),
                                "success")
        self._update_title()

    # ================================================================== recent files
    def _add_recent(self, path):
        path = os.path.abspath(path)
        if path in self.recent:
            self.recent.remove(path)
        self.recent.insert(0, path)
        self.recent = self.recent[:MAX_RECENT]
        self.settings.setValue("recent", self.recent)
        self._update_recent_menu()

    def _remove_recent(self, path):
        path = os.path.abspath(path)
        if path in self.recent:
            self.recent.remove(path)
            self.settings.setValue("recent", self.recent)
            self._update_recent_menu()

    def _update_recent_menu(self):
        self.recent_menu.clear()
        if not self.recent:
            a = self.recent_menu.addAction("(none)")
            a.setEnabled(False)
            return
        for p in self.recent:
            act = self.recent_menu.addAction(p)
            act.triggered.connect(lambda _=False, path=p: self.open_file(path))
        self.recent_menu.addSeparator()
        self.recent_menu.addAction(self._act("Clear list", self._clear_recent))

    def _clear_recent(self):
        self.recent = []
        self.settings.setValue("recent", self.recent)
        self._update_recent_menu()

    def _on_doc_change(self, what):
        self.model.set_root(self.doc.root)
        self.tree.expandToDepth(2)
        self._refresh_messages()
        self._refresh_summary()
        self._update_actions()

    # ================================================================== save
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
        if self._busy:
            return
        self.doc.listeners = []
        self._set_busy(True, "Building and verifying %s…" % os.path.basename(path))
        run_async(self, SaveWorker(self.doc, path, backup=True, verify=True),
                  on_done=self._on_saved, on_failed=self._on_save_failed)

    def _on_save_failed(self, msg, path):
        self.doc.listeners = [self._on_doc_change]
        self._set_busy(False, "Save failed")
        self.toast.show_message("Build failed: %s" % msg, "error")
        QMessageBox.critical(self, "Save", "Build failed:\n\n%s" % msg)

    def _on_saved(self, rep, path):
        self.doc.listeners = [self._on_doc_change]
        self._set_busy(False)
        if not rep.ok:
            self.status_label.setText("Save aborted: verification failed")
            self.toast.show_message("Verification failed — file not written", "error")
            QMessageBox.critical(self, "Save", "Verification failed, file not written:\n\n" + "\n".join(rep.errors))
            return
        self.model.set_root(self.doc.root)
        self.tree.expandToDepth(2)
        self._refresh_summary()
        self._add_recent(path)
        self.status_label.setText("Saved %s" % os.path.basename(path))
        kind = "warning" if rep.warnings else "success"
        extra = " (%d warning(s))" % len(rep.warnings) if rep.warnings else ""
        self.toast.show_message("Saved %s%s" % (os.path.basename(path), extra), kind)
        if rep.warnings or rep.moved:
            self.log("save report:", "info")
            for m in rep.moved:
                self.log("  moved: " + m, "info")
            for wmsg in rep.warnings:
                self.log("  warning: " + wmsg, "warning")
        self._update_title()

    def reload_file(self):
        if self.doc and self.doc.path:
            if self.doc.modified and QMessageBox.question(
                    self, "Reload", "Discard unsaved changes?") != QMessageBox.Yes:
                return
            self.load(self.doc.path)

    # ================================================================== selection
    def current_node(self) -> Node | None:
        if not self.model:
            return None
        return self.model.node_at(self.tree.currentIndex())

    def _on_select(self, cur, _prev):
        node = self.model.node_at(cur)
        if node is None:
            return
        self.detail_card.title_label.setText((node.display_name or node.type.value).upper())
        self._show_info(node)
        data = node.content if node.decoded is not None else node.data
        self.hex.set_data(data[:1 << 20], node.abs_offset or 0)
        self._update_hex_status()
        self._show_text(node)
        self._update_actions()

    def _show_info(self, node: Node):
        self.info_grid.clear()
        seen: set[str] = set()

        def row(key, value):
            if key in seen:
                return
            seen.add(key)
            self.info_grid.add_row(key, value)

        info_keys = {k for k, _ in node.info}
        row("Type", node.type.value)
        if node.subtype:
            row("Subtype", node.subtype)
        if node.text and node.text != node.name:
            row("Text", node.text)
        if "Offset" not in info_keys:
            off = node.abs_offset
            row("Offset", "%08Xh" % off if off is not None else "in decompressed data")
        if node.meta.get("address") and "Memory address" not in info_keys:
            row("Memory address", "%08Xh" % node.meta["address"])
        if "Full size" not in info_keys:
            row("Full size", "%Xh (%s)" % (node.size, human_size(node.size)))
        row("Header / body", "%Xh / %Xh" % (node.hdr_size, node.body_size))
        if node.flags:
            row("Flags", ", ".join(sorted(node.flags)))
        for k, v in node.info:
            # node.info may legitimately repeat a key (e.g. multiple VSCC chips); keep those.
            if k in ("Full size", "Type", "Offset", "Memory address") and k in seen:
                continue
            self.info_grid.add_row(k, v)
        if node.messages:
            self.info_msgs.setText("⚠ " + "\n⚠ ".join(node.messages))
            self.info_msgs.show()
        else:
            self.info_msgs.hide()

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

    def _update_hex_status(self):
        n = self.hex.data()
        if not n:
            self.hex_status.setText("")
            return
        cur = self.hex.cursor
        a, b = self.hex.selection()
        val = n[cur] if cur < len(n) else 0
        parts = ["Offset 0x%08X (%d)" % (cur, cur), "Value 0x%02X (%d)" % (val, val)]
        if b > a:
            parts.append("Selected %d bytes (0x%X–0x%X)" % (b - a, a, b - 1))
        self.hex_status.setText("    ".join(parts))

    def _hex_goto(self):
        text = self.goto_edit.text().strip().replace("0x", "").replace("h", "")
        if not text:
            return
        try:
            off = int(text, 16)
        except ValueError:
            return
        base = 0
        node = self.current_node()
        if node is not None and node.abs_offset:
            base = node.abs_offset
        self.tabs.setCurrentIndex(1)
        self.hex.goto(max(0, off - base))
        self.hex.setFocus()

    def _hex_find(self):
        q = self.find_edit.text().strip()
        if not q or not self.hex.data():
            return
        data = self.hex.data()
        needle = None
        cleaned = q.replace(" ", "")
        if len(cleaned) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in cleaned):
            needle = bytes.fromhex(cleaned)
        pos = data.find(needle) if needle else -1
        if pos < 0:
            pos = data.find(q.encode("latin-1", "ignore"))
        if pos < 0:
            pos = data.lower().find(q.encode("utf-16-le").lower())
        if pos >= 0:
            self.tabs.setCurrentIndex(1)
            self.hex.goto(pos, max(1, len(needle) if needle else len(q)))
            self.hex.setFocus()
        else:
            self.toast.show_message("Not found in this item's bytes", "warning")

    # ================================================================== summary + log
    def _refresh_summary(self):
        if not self.doc:
            return
        root = self.doc.root
        self.tile_size.set(human_size(root.size), "%Xh bytes" % root.size)
        self.tile_items.set(str(root.count()))
        ctx = getattr(self.doc, "ctx", None)
        vendor = ", ".join(sorted(ctx.vendor_hints)) if ctx and ctx.vendor_hints else root.subtype
        self.tile_vendor.set(vendor or "—")

    def _refresh_messages(self):
        self.messages.clear()
        msgs = [(n, m) for n in self.doc.root.walk() for m in n.messages]
        if not msgs:
            self.log("%s %s — no parser warnings." % (__app_name__, __version__), "info")
            return
        self.log("%d parser warning(s):" % len(msgs), "warning")
        for n, m in msgs:
            self.log("  %s: %s" % (n.display_name, m), "warning")

    def log(self, text: str, kind: str = "info"):
        pal = theme.palette
        color = {"warning": pal.warning, "error": pal.danger, "success": pal.success}.get(kind, pal.text_muted)
        stamp = time.strftime("%H:%M:%S")
        self.messages.appendHtml(
            '<span style="color:%s">%s</span>&nbsp;&nbsp;<span style="color:%s">%s</span>'
            % (pal.text_faint, stamp, color, _escape(text)))
        self.messages.verticalScrollBar().setValue(self.messages.verticalScrollBar().maximum())

    # ================================================================== edit ops
    def _need_node(self):
        n = self.current_node()
        if n is None:
            self.toast.show_message("Select an item in the structure tree first.", "info")
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
        self.toast.show_message("Extracted to " + os.path.basename(path), "success")

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
        self.toast.show_message("Replaced %s" % n.display_name, "success")

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
        self.toast.show_message("Inserted into %s" % n.display_name, "success")

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
            return
        self.toast.show_message("Removed", "success")

    def rebuild_item(self):
        n = self._need_node()
        if n:
            self.doc.rebuild(n)

    def undo(self):
        if self.doc:
            d = self.doc.undo()
            if d:
                self.status_label.setText("Undo: " + d)

    def redo(self):
        if self.doc:
            d = self.doc.redo()
            if d:
                self.status_label.setText("Redo: " + d)

    # ================================================================== dialogs
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
        if self.doc:
            from .dialogs import NvramDialog
            NvramDialog(self.doc, self).exec()

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
        from ..tools import diff
        from ..tools.project import Document
        from .dialogs import DiffDialog
        try:
            other = Document.open(path)
        except Exception as e:
            QMessageBox.critical(self, "Compare", str(e))
            return
        DiffDialog(diff.diff_trees(self.doc.root, other.root), self).exec()

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
        self.toast.show_message("Applied %d change(s)." % len(res), "success" if res else "info")

    def descriptor_unlock(self):
        if not self.doc or self.doc.root.meta.get("descriptor") is None:
            self.toast.show_message("This image has no Intel flash descriptor.", "info")
            return
        from ..formats import descriptor
        data = self.doc.build()
        newdata = descriptor.unlock(data, descriptor.parse(data))
        self.doc.apply_raw_image(newdata, "Unlock flash descriptor")
        self.toast.show_message("Flash descriptor unlocked (BIOS/ME masters granted full access)", "success")

    def export_report(self):
        if not self.doc:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save report", "report.txt", "Text (*.txt);;JSON (*.json)")
        if not path:
            return
        from ..tools import report
        with open(path, "w") as fh:
            fh.write(report.report_json(self.doc.root) if path.endswith(".json")
                     else report.report_text(self.doc.root))
        self.toast.show_message("Report written to " + os.path.basename(path), "success")

    def _tree_menu(self, pos):
        if self.current_node() is None:
            return
        m = QMenu(self)
        for a in (self.act_extract, self.act_extract_body, None, self.act_replace, self.act_replace_full,
                  self.act_insert, self.act_remove, self.act_rebuild):
            m.addSeparator() if a is None else m.addAction(a)
        m.exec(self.tree.viewport().mapToGlobal(pos))

    # ================================================================== state
    def _update_title(self):
        if self.doc:
            self.setWindowTitle("%s — %s%s" % (__app_name__, self.doc.name, "*" if self.doc.modified else ""))
        else:
            self.setWindowTitle(__app_name__)
        self._update_pill()

    def _update_pill(self):
        if not hasattr(self, "pill_label"):
            return
        pal = theme.palette
        if self.doc:
            star = " • modified" if self.doc.modified else ""
            self.pill_label.setText("%s · %s%s" % (self.doc.name, human_size(self.doc.root.size), star))
            self.pill_dot.set_color(pal.warning if self.doc.modified else pal.success)
        else:
            self.pill_label.setText("No image loaded")
            self.pill_dot.set_color(pal.text_faint, halo=False)

    def _update_actions(self):
        has = self.doc is not None and not self._busy
        for a in (self.act_save, self.act_saveas, self.act_reload, self.act_extract, self.act_extract_body,
                  self.act_replace, self.act_replace_full, self.act_insert, self.act_remove, self.act_rebuild,
                  self.act_search):
            a.setEnabled(has)
        self.act_undo.setEnabled(has and bool(self.doc.undo_stack))
        self.act_redo.setEnabled(has and bool(self.doc.redo_stack))
        self._update_title()
        if self.doc:
            self.status_right.setText("%d items · %s" % (self.doc.root.count(), human_size(self.doc.root.size)))

    def about(self):
        QMessageBox.about(
            self, "About " + __app_name__,
            "<h3>%s %s</h3>"
            "<p>%s — part of the EZP2019Linux suite.</p>"
            "<p>Parses and rebuilds UEFI volumes, FFS files, sections, NVRAM stores, "
            "the Intel flash descriptor / ME, microcode, FIT and Boot Guard, capsules and more.</p>"
            "<p>GUID database and format details derived from UEFITool "
            "(© Nikolaj Schlej, BSD-2-Clause).</p>" % (__app_name__, __version__, SUBTITLE))

    def resizeEvent(self, e):
        super().resizeEvent(e)
        if hasattr(self, "toast") and self.toast.isVisible():
            self.toast._place()


def _escape(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace(" ", "&nbsp;"))
