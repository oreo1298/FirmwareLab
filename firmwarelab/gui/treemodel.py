"""Qt item model wrapping the FirmwareLab Node tree."""

from __future__ import annotations

from PySide6.QtCore import QAbstractItemModel, QModelIndex, Qt
from PySide6.QtGui import QBrush, QColor, QFont

from ..core.binary import human_size
from ..core.node import Node, NodeType
from . import theme

COLUMNS = ["Name", "Type", "Subtype", "Offset", "Size", "Compression"]


class FirmwareTreeModel(QAbstractItemModel):
    def __init__(self, root: Node, dark: bool = True, parent=None):
        super().__init__(parent)
        self._root = root
        self.dark = dark

    def set_root(self, root: Node):
        self.beginResetModel()
        self._root = root
        self.endResetModel()

    # ------------------------------------------------------------------ Qt API
    def index(self, row, column, parent=QModelIndex()):
        if not self.hasIndex(row, column, parent):
            return QModelIndex()
        pnode = parent.internalPointer() if parent.isValid() else self._root_holder()
        children = self._children(pnode)
        if row < len(children):
            return self.createIndex(row, column, children[row])
        return QModelIndex()

    def _root_holder(self):
        return None

    def _children(self, node):
        if node is None:
            return [self._root]
        return node.children

    def parent(self, index):
        if not index.isValid():
            return QModelIndex()
        node: Node = index.internalPointer()
        if node is self._root or node.parent is None:
            return QModelIndex()
        parent = node.parent
        gp = parent.parent
        siblings = gp.children if gp is not None else [self._root]
        try:
            row = siblings.index(parent)
        except ValueError:
            row = 0
        return self.createIndex(row, 0, parent)

    def rowCount(self, parent=QModelIndex()):
        if parent.column() > 0:
            return 0
        node = parent.internalPointer() if parent.isValid() else None
        return len(self._children(node))

    def columnCount(self, parent=QModelIndex()):
        return len(COLUMNS)

    def node_at(self, index) -> Node | None:
        return index.internalPointer() if index.isValid() else None

    def index_for_node(self, node: Node) -> QModelIndex:
        if node is self._root:
            return self.createIndex(0, 0, node)
        parent = node.parent
        if parent is None:
            return QModelIndex()
        try:
            row = parent.children.index(node)
        except ValueError:
            return QModelIndex()
        return self.createIndex(row, 0, node)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        node: Node = index.internalPointer()
        col = index.column()
        if role == Qt.DisplayRole:
            if col == 0:
                return node.text or node.name or node.type.value
            if col == 1:
                return node.type.value
            if col == 2:
                return node.subtype
            if col == 3:
                off = node.abs_offset
                return "%08X" % off if off is not None else "—"
            if col == 4:
                return "%Xh" % node.size
            if col == 5:
                return node.meta.get("algorithm", "")
        elif role == Qt.ToolTipRole:
            off = node.abs_offset
            parts = [node.path_names(), "Size: %s (%s)" % ("%Xh" % node.size, human_size(node.size))]
            if off is not None:
                parts.append("Offset: %08Xh" % off)
            if node.meta.get("address"):
                parts.append("Address: %08Xh" % node.meta["address"])
            if node.messages:
                parts.append("\n".join("⚠ " + m for m in node.messages))
            return "\n".join(parts)
        elif role == Qt.BackgroundRole:
            return QBrush(QColor(theme.type_color(node.type, self.dark)))
        elif role == Qt.ForegroundRole:
            if node.messages:
                return QBrush(QColor("#e05555"))
            if "inactive" in node.flags or "deleted" in node.flags:
                return QBrush(QColor("#8a8f98"))
            if "protected" in node.flags:
                return QBrush(QColor("#d08020"))
        elif role == Qt.FontRole and col == 0:
            if node.type in (NodeType.VOLUME, NodeType.REGION, NodeType.IMAGE, NodeType.CAPSULE):
                f = QFont()
                f.setBold(True)
                return f
            if "xip" in node.flags:
                f = QFont()
                f.setItalic(True)
                return f
        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return COLUMNS[section]
        return None

    def flags(self, index):
        if not index.isValid():
            return Qt.NoItemFlags
        return Qt.ItemIsEnabled | Qt.ItemIsSelectable
