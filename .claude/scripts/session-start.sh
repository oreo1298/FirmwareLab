#!/usr/bin/env bash
# Prepare a Claude Code web session to build, test and run FirmwareLab.
set -u
echo "[FirmwareLab] preparing session…"

python3 -m pip install --quiet --upgrade pip >/dev/null 2>&1 || true
# Core has no third-party deps; install test/GUI/brotli extras best-effort.
python3 -m pip install --quiet pytest brotli >/dev/null 2>&1 || true
python3 -m pip install --quiet PySide6 >/dev/null 2>&1 || true

# Fetch an OVMF image for the integration tests if none is present.
OVMF=""
for p in /usr/share/OVMF/OVMF.fd /usr/share/ovmf/OVMF.fd /usr/share/OVMF/OVMF_CODE*.fd; do
  [ -f "$p" ] && OVMF="$p" && break
done
if [ -z "$OVMF" ] && command -v apt-get >/dev/null 2>&1; then
  sudo apt-get install -y -q ovmf >/dev/null 2>&1 || true
  for p in /usr/share/OVMF/OVMF.fd /usr/share/ovmf/OVMF.fd; do
    [ -f "$p" ] && OVMF="$p" && break
  done
fi
[ -n "$OVMF" ] && echo "[FirmwareLab] OVMF test image: $OVMF (export FWLAB_TEST_OVMF to use)"
echo "[FirmwareLab] ready — run: python3 -m pytest -q"
