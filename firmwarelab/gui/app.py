"""GUI application entry point."""

from __future__ import annotations

import sys


def run(files=None) -> int:
    from PySide6.QtWidgets import QApplication
    from .mainwindow import MainWindow

    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("FirmwareLab")
    app.setOrganizationName("FirmwareLab")
    win = MainWindow()
    win.show()
    if files:
        for f in files:
            if f:
                win.load(f)
                break
    return app.exec()


def main() -> int:
    return run(sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
