"""Flashing helpers: chip-size validation, padding, capsule stripping and flashrom command building."""

from __future__ import annotations

import shutil
from dataclasses import dataclass

from ..core.node import NodeType
from ..formats import capsule, descriptor

FLASH_SIZES = [1 << i for i in range(19, 27)]  # 512 KiB .. 64 MiB


@dataclass
class FlashReadiness:
    ok: bool
    size: int
    nearest_chip: int | None
    issues: list[str]
    notes: list[str]


def analyze(doc) -> FlashReadiness:
    data = doc.build()
    size = len(data)
    issues, notes = [], []
    nearest = next((s for s in FLASH_SIZES if s >= size), None)
    if size not in FLASH_SIZES:
        if nearest:
            notes.append("Image is %Xh bytes; standard SPI chips are %s. Pad to %Xh before flashing a bare chip." % (
                size, "/".join("%dMiB" % (s >> 20) if s >= 1 << 20 else "%dKiB" % (s >> 10) for s in FLASH_SIZES), nearest))
        else:
            issues.append("Image (%Xh bytes) is larger than the largest common SPI chip (64 MiB)" % size)
    root = doc.root
    if root.type == NodeType.CAPSULE:
        issues.append("Image is a capsule; extract the payload before flashing to a chip (see 'strip-capsule')")
    desc = root.meta.get("descriptor")
    if desc is not None:
        if descriptor.is_locked(desc):
            notes.append("Flash descriptor is locked: an external programmer is required to write ME/descriptor "
                         "regions, or unlock the descriptor first (see 'descriptor unlock').")
        for r in desc.regions:
            if r.used and r.end > size:
                issues.append("%s region extends beyond the image; this looks like a partial dump" % r.name)
    for n in root.walk():
        if "protected" in n.flags and n.dirty:
            notes.append("%s is Boot Guard protected and was modified; the platform may refuse to boot" % n.display_name)
    return FlashReadiness(not issues, size, nearest, issues, notes)


def pad_to(data: bytes, size: int, fill: int = 0xFF, at_end: bool = False) -> bytes:
    if len(data) > size:
        raise ValueError("Image (%Xh) is larger than target size (%Xh)" % (len(data), size))
    pad = bytes([fill]) * (size - len(data))
    return data + pad if at_end else pad + data


def strip_capsule(data: bytes) -> bytes:
    """Return the firmware image inside a capsule (or the input unchanged)."""
    cap = capsule.detect(data)
    if cap is None:
        return bytes(data)
    start, end = cap.body_range
    return bytes(data[start:end])


def flashrom_command(path: str, programmer: str = "internal", region: str | None = None,
                     read_back: bool = True) -> list[str]:
    cmd = ["flashrom", "-p", programmer]
    if region:
        cmd += ["--ifd", "-i", "%s:%s" % (region, path)] if region != "full" else ["-w", path]
    else:
        cmd += ["-w", path]
    if read_back:
        cmd += ["--verify"]
    return cmd


def flashrom_available() -> bool:
    return shutil.which("flashrom") is not None
