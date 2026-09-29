"""Stroke icons drawn for this app (24×24, rendered in the theme's colours).

Shared design language with the EZP2019Linux suite: 24×24 line icons with round
caps/joins, tinted at render time to the active palette.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from PySide6.QtCore import QByteArray, QRectF, Qt
from PySide6.QtGui import QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer

_PATHS: dict[str, str] = {
    # shared with the suite
    "open": '<path d="M3 7.5A1.5 1.5 0 0 1 4.5 6H9l2 2h8.5A1.5 1.5 0 0 1 21 9.5v9A1.5 1.5 0 0 1 19.5 20h-15A1.5 1.5 0 0 1 3 18.5z"/><path d="M3 11h18"/>',
    "save": '<path d="M5 4h11l4 4v11a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1z"/><path d="M8 4v4.5h7V4"/><rect x="7" y="13" width="10" height="7" rx="1"/>',
    "search": '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m20 20-4.8-4.8"/>',
    "database": '<ellipse cx="12" cy="5.5" rx="7.5" ry="2.8"/><path d="M4.5 5.5v13c0 1.5 3.4 2.8 7.5 2.8s7.5-1.3 7.5-2.8v-13"/><path d="M4.5 12c0 1.5 3.4 2.8 7.5 2.8s7.5-1.3 7.5-2.8"/>',
    "info": '<circle cx="12" cy="12" r="9"/><path d="M12 11v5.5"/><path d="M12 7.6v.1"/>',
    "cancel": '<circle cx="12" cy="12" r="9"/><path d="m15 9-6 6M9 9l6 6"/>',
    "chip": '<rect x="6" y="6" width="12" height="12" rx="1.5"/><rect x="9.5" y="9.5" width="5" height="5" rx=".6"/><path d="M9.5 2.5V6M14.5 2.5V6M9.5 18v3.5M14.5 18v3.5M2.5 9.5H6M2.5 14.5H6M18 9.5h3.5M18 14.5h3.5"/>',
    "sun": '<circle cx="12" cy="12" r="4"/><path d="M12 2.5v2M12 19.5v2M5.3 5.3l1.4 1.4M17.3 17.3l1.4 1.4M2.5 12h2M19.5 12h2M5.3 18.7l1.4-1.4M17.3 6.7l1.4-1.4"/>',
    "moon": '<path d="M20 14.6A8.2 8.2 0 0 1 9.4 4a8.2 8.2 0 1 0 10.6 10.6z"/>',
    "log": '<path d="m5 16.5 5-4.5-5-4.5"/><path d="M12.5 18H19"/>',
    "plus": '<path d="M12 5v14M5 12h14"/>',
    "trash": '<path d="M4.5 7h15"/><path d="M10 11v5.5M14 11v5.5"/><path d="m6.5 7 .9 11.6a1.6 1.6 0 0 0 1.6 1.4h6a1.6 1.6 0 0 0 1.6-1.4L17.5 7"/><path d="M9.5 7V4.5h5V7"/>',
    "edit": '<path d="M4 20h4L19 9a2.1 2.1 0 0 0-3-3L5 17z"/><path d="m14.5 7.5 2 2"/>',
    "copy": '<rect x="8.5" y="8.5" width="11.5" height="11.5" rx="1.8"/><path d="M15.5 8.5V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v7.5a2 2 0 0 0 2 2h2.5"/>',
    "check": '<path d="m5 12.5 4.5 4.5L19.5 7"/>',
    "warning": '<path d="M10.3 4.4 2.9 17.5A2 2 0 0 0 4.6 20.5h14.8a2 2 0 0 0 1.7-3L13.7 4.4a2 2 0 0 0-3.4 0z"/><path d="M12 9.5v4.5"/><path d="M12 17.2v.1"/>',
    "error": '<circle cx="12" cy="12" r="9"/><path d="M12 7.5v5.5"/><path d="M12 16.3v.1"/>',
    "refresh": '<path d="M20 11.5A8 8 0 0 0 5.6 7.2L4 9"/><path d="M4 4.5V9h4.5"/><path d="M4 12.5a8 8 0 0 0 14.4 4.3L20 15"/><path d="M20 19.5V15h-4.5"/>',
    "import": '<path d="M12 4v10"/><path d="m8 10 4 4 4-4"/><path d="M5 16v2.5A1.5 1.5 0 0 0 6.5 20h11a1.5 1.5 0 0 0 1.5-1.5V16"/>',
    "export": '<path d="M12 14V4"/><path d="m8 8 4-4 4 4"/><path d="M5 16v2.5A1.5 1.5 0 0 0 6.5 20h11a1.5 1.5 0 0 0 1.5-1.5V16"/>',
    "binary": '<path d="M6 3.5h8.5L19 8v11a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 5 19V5a1.5 1.5 0 0 1 1-1.4"/><path d="M14 3.5V8h5"/><rect x="8" y="11.5" width="3" height="5" rx="1.2"/><path d="M14.5 11.5v5"/>',
    "chevron_down": '<path d="m6.5 9.5 5.5 5.5 5.5-5.5"/>',
    "chevron_up": '<path d="m6.5 14.5 5.5-5.5 5.5 5.5"/>',
    "shield": '<path d="M12 3.2 19 6v5.6c0 4.3-2.9 7.6-7 9.2-4.1-1.6-7-4.9-7-9.2V6z"/><path d="M12 8.5v4"/><path d="M12 15.6v.1"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3.5 2"/>',
    "menu": '<path d="M4 7h16M4 12h16M4 17h16"/>',
    "close": '<path d="M6 6l12 12M18 6 6 18"/>',
    "goto": '<path d="M5 4v6.5A3.5 3.5 0 0 0 8.5 14H19"/><path d="m15 10 4 4-4 4"/>',
    "auto": '<path d="M13.5 2.5 5 13.5h6.5l-1 8 8.5-11h-6.5z"/>',
    # firmware-specific
    "file": '<path d="M6 3h8l4 4v13a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z"/><path d="M14 3v4h4"/>',
    "section": '<rect x="4" y="5" width="16" height="5" rx="1.2"/><rect x="4" y="14" width="16" height="5" rx="1.2"/>',
    "volume": '<path d="m12 3 8 4.5-8 4.5-8-4.5z"/><path d="m4 12 8 4.5 8-4.5"/><path d="m4 16.5 8 4.5 8-4.5"/>',
    "cpu": '<rect x="7.5" y="7.5" width="9" height="9" rx="1.3"/><rect x="10.3" y="10.3" width="3.4" height="3.4" rx=".5"/><path d="M10 4v3.5M14 4v3.5M10 16.5V20M14 16.5V20M4 10h3.5M4 14h3.5M16.5 10H20M16.5 14H20"/>',
    "sliders": '<path d="M4 8h8M16 8h4M4 16h4M12 16h8"/><circle cx="14" cy="8" r="2.2"/><circle cx="8" cy="16" r="2.2"/>',
    "unlock": '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8.5 11V7a3.5 3.5 0 0 1 6.9-.9"/><path d="M12 15v2"/>',
    "diff": '<circle cx="6.5" cy="6" r="2.5"/><circle cx="17.5" cy="18" r="2.5"/><path d="M6.5 8.5v6A2.5 2.5 0 0 0 9 17h6M17.5 15.5v-6A2.5 2.5 0 0 0 15 7H9"/>',
    "package": '<path d="m12 3 8 4.5v9L12 21l-8-4.5v-9z"/><path d="m4 7.5 8 4.5 8-4.5M12 12v9"/>',
    "map": '<path d="m9 4-5.5 2.5v13L9 17l6 2.5 5.5-2.5v-13L15 6.5 9 4z"/><path d="M9 4v13M15 6.5v13"/>',
    "region": '<rect x="3.5" y="4.5" width="17" height="15" rx="1.5"/><path d="M3.5 10h17M9 4.5v15"/>',
    "structure": '<rect x="4" y="4" width="6" height="4" rx="1"/><rect x="14" y="10" width="6" height="4" rx="1"/><rect x="14" y="16" width="6" height="4" rx="1"/><path d="M7 8v6.5A1.5 1.5 0 0 0 8.5 16H14M7 12h7"/>',
    "eraser": '<path d="m15.6 3.9 4.5 4.5a1.5 1.5 0 0 1 0 2.1L11.6 19H7.4l-3.5-3.5a1.5 1.5 0 0 1 0-2.1l9.6-9.5a1.5 1.5 0 0 1 2.1 0z"/><path d="m8.8 9.2 6 6"/><path d="M11.6 19H20"/>',
    "network": '<circle cx="12" cy="5" r="2.2"/><circle cx="5.5" cy="18.5" r="2.2"/><circle cx="18.5" cy="18.5" r="2.2"/><path d="M12 7.2v4.3M12 11.5 6.4 16.6M12 11.5l5.6 5.1"/>',
    "undo": '<path d="M9 7 4.5 11.5 9 16"/><path d="M4.5 11.5H14a5.5 5.5 0 0 1 0 11h-2.5"/>',
    "redo": '<path d="m15 7 4.5 4.5L15 16"/><path d="M19.5 11.5H10a5.5 5.5 0 0 0 0 11h2.5"/>',
}
_PATHS["flash"] = _PATHS["auto"]
_PATHS["nvram"] = _PATHS["database"]
_PATHS["microcode"] = _PATHS["cpu"]
_PATHS["patch"] = _PATHS["edit"]
_PATHS["extract"] = _PATHS["export"]
_PATHS["insert"] = _PATHS["plus"]
_PATHS["remove"] = _PATHS["trash"]
_PATHS["rebuild"] = _PATHS["refresh"]
_PATHS["setup"] = _PATHS["sliders"]
_PATHS["descriptor"] = _PATHS["map"]
_PATHS["capsule"] = _PATHS["package"]


def svg(name: str, color: str, stroke: float = 1.9) -> str:
    body = _PATHS[name]
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" '
            f'stroke="{color}" stroke-width="{stroke}" stroke-linecap="round" '
            f'stroke-linejoin="round">{body}</svg>')


def _render(svg_text: str, size: int, ratio: float = 2.0) -> QPixmap:
    renderer = QSvgRenderer(QByteArray(svg_text.encode()))
    px = QPixmap(int(size * ratio), int(size * ratio))
    px.fill(Qt.transparent)
    painter = QPainter(px)
    painter.setRenderHint(QPainter.Antialiasing)
    renderer.render(painter, QRectF(0, 0, px.width(), px.height()))
    painter.end()
    px.setDevicePixelRatio(ratio)
    return px


@lru_cache(maxsize=512)
def icon(name: str, color: str, disabled_color: str | None = None, size: int = 24) -> QIcon:
    ic = QIcon()
    ic.addPixmap(_render(svg(name, color), size), QIcon.Normal)
    if disabled_color:
        ic.addPixmap(_render(svg(name, disabled_color), size), QIcon.Disabled)
    return ic


def pixmap(name: str, color: str, size: int = 20) -> QPixmap:
    return _render(svg(name, color), size)


def write_svg_file(directory: Path, name: str, color: str, stroke: float = 2.4) -> Path:
    """Write an icon to disk so style sheets can reference it with url()."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name}-{color.lstrip('#')}.svg"
    if not path.exists():
        tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        tmp.write_text(svg(name, color, stroke), encoding="utf-8")
        os.replace(tmp, path)
    return path
