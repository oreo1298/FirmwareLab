#!/usr/bin/env bash
# Run the FirmwareLab GUI straight from a source checkout, no installation.
#
# Requires only Python 3.10+ and PySide6. On Arch:
#     sudo pacman -S --needed python pyside6 python-brotli
# then:
#     ./firmwarelab.sh [image.bin]
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 -c "import sys; sys.path.insert(0, '$here'); from firmwarelab.gui.app import main; sys.exit(main())" "$@"
