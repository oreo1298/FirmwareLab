"""GUI application entry point."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from PySide6.QtCore import QSettings, Qt, QTimer
from PySide6.QtGui import QGuiApplication, QIcon

from .. import __app_name__, __version__

ICON_PATH = Path(__file__).resolve().parent.parent / "data" / "firmwarelab.svg"


def _app_icon() -> QIcon:
    themed = QIcon.fromTheme("firmwarelab")
    if not themed.isNull():
        return themed
    if ICON_PATH.exists():
        return QIcon(str(ICON_PATH))
    return QIcon()


def run(files=None) -> int:
    from PySide6.QtWidgets import QApplication

    from .mainwindow import MainWindow
    from .theme import theme

    QGuiApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    QApplication.setApplicationName("firmwarelab")
    QApplication.setApplicationDisplayName(__app_name__)
    QApplication.setApplicationVersion(__version__)
    QApplication.setOrganizationName("firmwarelab")
    QGuiApplication.setDesktopFileName("firmwarelab")

    app = QApplication.instance() or QApplication(sys.argv)
    app.setWindowIcon(_app_icon())

    settings = QSettings("firmwarelab", "firmwarelab")
    mode = os.environ.get("FIRMWARELAB_THEME") or str(settings.value("theme", "system"))
    theme.apply(app, mode)
    hints = QGuiApplication.styleHints()
    if hasattr(hints, "colorSchemeChanged"):
        hints.colorSchemeChanged.connect(
            lambda _s: theme.apply(app) if theme.mode == "system" else None)

    win = MainWindow()
    win.show()
    if files:
        for f in files:
            if f:
                QTimer.singleShot(0, lambda path=f: win.open_file(path))
                break
    return app.exec()


def main() -> int:
    return run(sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
