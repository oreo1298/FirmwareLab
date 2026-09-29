#!/usr/bin/env bash
# Self-contained installer for FirmwareLab (any distro, no root required).
#
# It creates a virtualenv under $PREFIX and installs FirmwareLab into it, then
# drops launchers on your PATH and a .desktop entry + icon so the GUI shows up in
# your application menu.
#
# The venv is created with --system-site-packages, so if PySide6 / brotli are
# already installed from your distro's packages (e.g. `pacman -S pyside6
# python-brotli` on Arch) they are reused instead of pip downloading ~250 MB.
#
#   PREFIX=~/.local ./packaging/install.sh        # default
#   NO_GUI=1        ./packaging/install.sh        # CLI only, skip PySide6
set -euo pipefail

PREFIX="${PREFIX:-$HOME/.local}"
VENV="$PREFIX/lib/firmwarelab/venv"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo ">> Creating virtualenv at $VENV"
mkdir -p "$PREFIX/lib/firmwarelab"
python3 -m venv --system-site-packages "$VENV"
"$VENV/bin/python" -m pip install --quiet --upgrade pip

extras="brotli"
if [ "${NO_GUI:-0}" != "1" ]; then
  if "$VENV/bin/python" -c "import PySide6" 2>/dev/null; then
    echo ">> Using PySide6 already available on the system"
  else
    echo ">> PySide6 not found; it will be installed into the venv (large download)."
    echo "   Tip: install it from your distro first for a smaller footprint, e.g."
    echo "        Arch:   sudo pacman -S --needed pyside6 python-brotli"
    echo "        Debian: sudo apt install python3-pyside6.qtwidgets"
    extras="full"
  fi
fi

echo ">> Installing FirmwareLab"
"$VENV/bin/python" -m pip install --quiet "$HERE[$extras]"

echo ">> Installing launchers into $PREFIX/bin"
mkdir -p "$PREFIX/bin"
for tool in fwlab firmwarelab; do
  ln -sf "$VENV/bin/$tool" "$PREFIX/bin/$tool"
done

echo ">> Installing desktop entry and icon"
mkdir -p "$PREFIX/share/applications" \
         "$PREFIX/share/icons/hicolor/scalable/apps"
install -m644 "$HERE/assets/firmwarelab.svg" \
  "$PREFIX/share/icons/hicolor/scalable/apps/firmwarelab.svg"
sed "s#^Exec=firmwarelab#Exec=$PREFIX/bin/firmwarelab#" \
  "$HERE/packaging/firmwarelab.desktop" \
  > "$PREFIX/share/applications/firmwarelab.desktop"

echo
echo "Done. FirmwareLab is installed."
case ":$PATH:" in
  *":$PREFIX/bin:"*) : ;;
  *) echo "NOTE: add $PREFIX/bin to your PATH:  export PATH=\"$PREFIX/bin:\$PATH\"" ;;
esac
echo "Launch the GUI:   firmwarelab   (or from your application menu)"
echo "Command line:     fwlab --help"
