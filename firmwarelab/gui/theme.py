"""Color palettes and per-node-type styling for the GUI."""

from __future__ import annotations

from ..core.node import NodeType

# Type -> (light bg, dark bg) row tint
TYPE_COLORS = {
    NodeType.IMAGE: ("#e8eef7", "#243044"),
    NodeType.CAPSULE: ("#efe6f7", "#332a44"),
    NodeType.REGION: ("#e6f2ec", "#22362c"),
    NodeType.VOLUME: ("#fff4e0", "#403420"),
    NodeType.FILE: ("#ffffff", "#1c1f26"),
    NodeType.SECTION: ("#f5f7fa", "#20242c"),
    NodeType.PADDING: ("#f0f0f0", "#2a2a2a"),
    NodeType.FREE_SPACE: ("#f7f7f7", "#242424"),
    NodeType.NVRAM_STORE: ("#e6f0f7", "#1f3040"),
    NodeType.NVRAM_VARIABLE: ("#f2f8fc", "#1b2733"),
    NodeType.MICROCODE: ("#fdeef0", "#3a2529"),
    NodeType.ME: ("#eef0f2", "#2b2f34"),
    NodeType.AMD: ("#fdeeea", "#3a2822"),
    NodeType.OPTION_ROM: ("#eef7ee", "#243626"),
    NodeType.DATA: ("#f4f4f4", "#26262a"),
    NodeType.FIT: ("#f0eefb", "#282540"),
    NodeType.BOOT_GUARD: ("#fbeeee", "#3a2424"),
}

DARK_QSS = """
QWidget { background:#15171c; color:#d7dae0; selection-background-color:#3b6ea5; selection-color:#fff; }
QMainWindow, QDialog { background:#15171c; }
QTreeView, QTableView, QPlainTextEdit, QTextEdit, QListWidget, QLineEdit, QComboBox, QSpinBox {
    background:#1b1e24; color:#d7dae0; border:1px solid #2b2f38; selection-background-color:#3b6ea5; }
QTreeView::item:selected, QTableView::item:selected { background:#3b6ea5; color:#fff; }
QHeaderView::section { background:#232730; color:#c2c7d0; padding:4px; border:0; border-right:1px solid #2b2f38; }
QMenuBar, QMenu { background:#1b1e24; color:#d7dae0; }
QMenuBar::item:selected, QMenu::item:selected { background:#3b6ea5; }
QToolBar { background:#1b1e24; border-bottom:1px solid #2b2f38; spacing:3px; }
QPushButton, QToolButton { background:#252a33; border:1px solid #333a45; border-radius:4px; padding:4px 10px; }
QPushButton:hover, QToolButton:hover { background:#2f3641; }
QPushButton:disabled { color:#666; }
QTabBar::tab { background:#1b1e24; padding:6px 12px; border:1px solid #2b2f38; }
QTabBar::tab:selected { background:#2b3340; }
QStatusBar { background:#1b1e24; color:#9aa0aa; }
QSplitter::handle { background:#2b2f38; }
QScrollBar:vertical { background:#1b1e24; width:12px; } QScrollBar::handle:vertical { background:#333a45; border-radius:5px; }
"""

LIGHT_QSS = """
QHeaderView::section { background:#eceff3; padding:4px; border:0; border-right:1px solid #d4d8de; }
QToolBar { border-bottom:1px solid #d4d8de; spacing:3px; }
QPushButton, QToolButton { border:1px solid #c4c8ce; border-radius:4px; padding:4px 10px; background:#f4f6f8; }
QPushButton:hover { background:#e8ebef; }
"""


def type_color(node_type: NodeType, dark: bool) -> str:
    pair = TYPE_COLORS.get(node_type)
    if not pair:
        return "#1c1f26" if dark else "#ffffff"
    return pair[1] if dark else pair[0]
