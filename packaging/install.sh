#!/usr/bin/env bash
# Simple local installer for non-Arch distros (installs into a virtualenv under ~/.local).
set -euo pipefail

PREFIX="${PREFIX:-$HOME/.local}"
VENV="$PREFIX/lib/firmwarelab-venv"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "Installing FirmwareLab into $VENV"
python3 -m venv "$VENV"
"$VENV/bin/pip" install --upgrade pip >/dev/null
"$VENV/bin/pip" install "$HERE[full]"

mkdir -p "$PREFIX/bin"
for tool in fwlab firmwarelab; do
  ln -sf "$VENV/bin/$tool" "$PREFIX/bin/$tool"
done

install -Dm644 "$HERE/assets/firmwarelab.svg" \
  "$PREFIX/share/icons/hicolor/scalable/apps/firmwarelab.svg"
sed "s#Exec=firmwarelab#Exec=$PREFIX/bin/firmwarelab#" "$HERE/packaging/firmwarelab.desktop" \
  > "$PREFIX/share/applications/firmwarelab.desktop" 2>/dev/null || \
  install -Dm644 "$HERE/packaging/firmwarelab.desktop" "$PREFIX/share/applications/firmwarelab.desktop"

echo "Done. Ensure $PREFIX/bin is on your PATH."
echo "Run 'fwlab --help' or launch 'firmwarelab' from your application menu."
