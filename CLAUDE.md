# FirmwareLab — repository notes for Claude

FirmwareLab is a from-scratch Python UEFI/BIOS firmware toolkit (parser, editor,
rebuilder, CLI + PySide6 GUI). Primary target: Arch Linux; runs on Python ≥ 3.10.

## Layout
- `firmwarelab/core/` — Node tree model, binary helpers, GUID/JEDEC databases.
- `firmwarelab/codecs/` — Tiano/EFI 1.1, LZMA (+x86 BCJ), Brotli/GZip/Zlib registry.
- `firmwarelab/formats/` — parsers: image, ffs, area, nvram, microcode, descriptor,
  me, gbe, capsule, fit, amd, oprom, pe. `context.py` carries the memory map.
- `firmwarelab/hii/` — HII strings, IFR opcodes, form model, read-only Setup browser.
- `firmwarelab/tools/` — project (edit/undo/save+verify), builder, patch, diff,
  search, flash, assemble, report, identify (board make/model + BIOS revision).
- `firmwarelab/cli/main.py` — the `fwlab` command.
- `firmwarelab/gui/` — PySide6 app.
- `tests/` — pytest; synthetic images in `conftest.py`, OVMF tests auto-skip.

## Invariants (do not regress)
- **Byte-exact round-trip:** parsing then rebuilding an unmodified image must return
  identical bytes. `tests/test_parse_build.py` guards this on synthetic + OVMF images.
- **Verified saves:** `Document.save` re-parses the built image and refuses to write
  on new checksum/parse/overflow errors. Keep that pass intact.
- **XIP correctness:** moving an execute-in-place PEI/SEC module rebases its PE image
  and patches the reset-vector entry point in the volume top file.
- Never disable/skip an integrity check to make output "work".

## Running
The system Python is usually externally-managed (PEP 668) — use a venv, not bare pip.
```sh
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q                                           # or: make test
FWLAB_TEST_OVMF=/usr/share/OVMF/OVMF.fd pytest -q   # + integration
QT_QPA_PLATFORM=offscreen python -c "from firmwarelab.gui.app import run; run([])"  # headless GUI check
python -m firmwarelab.gui.app                        # launch the GUI (needs PySide6)
```

## GUI notes
- The GUI shares its design system with the **EZP2019Linux** suite: `gui/theme.py`
  (identical Palette/QSS + Fusion + ThemeManager), `gui/icons.py` (24×24 stroke
  icons tinted at render time), `gui/widgets.py` (Card, KeyValueGrid, StatTile,
  StatusDot, Toast, SegmentedControl), and a matching hex view. Keep the two apps
  visually consistent when editing these. The window is: identity + icon-over-text
  toolbar (accent primary Save) + status pill/theme toggle, a Structure card, a
  Details card (Information/Hex/Text), and an Activity log card.
- The GUI is the primary interface. Parsing and saving run on a background QThread
  (`firmwarelab/gui/worker.py`) so the window never freezes; completion slots must be
  bound methods of a GUI-thread QObject, and `run_async` keeps a reference to the
  worker so it is not GC'd mid-run. During a threaded save the document's listeners
  are detached so its reload does not touch Qt from the worker thread.

## Attribution
GUID/JEDEC data and format layouts derive from UEFITool (BSD-2-Clause); see `NOTICE`.
Keep that credit when touching `data/` or format structures.
