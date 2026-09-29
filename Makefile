# FirmwareLab — convenience targets.
# For a system package on Arch, use packaging/PKGBUILD (makepkg -si) instead.

PREFIX ?= $(HOME)/.local

.PHONY: help run install uninstall test lint gui-check dist clean

help:
	@echo "FirmwareLab make targets:"
	@echo "  make run          Launch the GUI from source (needs PySide6)"
	@echo "  make install      Install into a venv under PREFIX ($(PREFIX)) with launchers"
	@echo "  make uninstall    Remove an install.sh installation"
	@echo "  make test         Run the test suite"
	@echo "  make lint         Run ruff (if installed)"
	@echo "  make gui-check    Headless GUI smoke test"
	@echo "  make dist         Build wheel + sdist"

run:
	python3 -m firmwarelab.gui.app

install:
	PREFIX="$(PREFIX)" ./packaging/install.sh

uninstall:
	rm -rf "$(PREFIX)/lib/firmwarelab"
	rm -f "$(PREFIX)/bin/fwlab" "$(PREFIX)/bin/firmwarelab"
	rm -f "$(PREFIX)/share/applications/firmwarelab.desktop"
	rm -f "$(PREFIX)/share/icons/hicolor/scalable/apps/firmwarelab.svg"
	@echo "Uninstalled FirmwareLab from $(PREFIX)."

test:
	python3 -m pytest -q

lint:
	ruff check firmwarelab

gui-check:
	QT_QPA_PLATFORM=offscreen python3 -c "from firmwarelab.gui.app import run; run([])" && echo "GUI import OK"

dist:
	python3 -m build

clean:
	rm -rf build dist ./*.egg-info firmwarelab/__pycache__ .pytest_cache .ruff_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
