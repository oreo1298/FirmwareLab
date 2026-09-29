"""Assemble or split full SPI flash images using the Intel flash descriptor layout."""

from __future__ import annotations

from ..formats import descriptor


class AssembleError(ValueError):
    pass


def region_layout(desc_bytes) -> tuple[descriptor.Descriptor, int]:
    desc = descriptor.parse(desc_bytes)
    total = sum(desc.component_sizes) or max((r.end for r in desc.regions if r.used), default=0)
    total = max(total, max((r.end for r in desc.regions if r.used), default=0))
    return desc, total


def assemble(desc_bytes: bytes, regions: dict[str, bytes], size: int | None = None,
             fill: int = 0xFF, bios_align_end: bool = True) -> bytes:
    """Build a full flash image.

    ``regions`` maps region names (BIOS, ME, GbE, PDR, EC, ...) to their contents.
    Contents smaller than the region are padded with ``fill``; the BIOS region is
    top-aligned by default because the reset vector must stay at its end.
    """
    desc, total = region_layout(desc_bytes)
    size = size or total
    if size <= 0:
        raise AssembleError("Cannot determine flash size from descriptor")
    out = bytearray([fill]) * size
    out[0:len(desc_bytes)] = desc_bytes[:descriptor.DESCRIPTOR_SIZE]
    for name, data in regions.items():
        r = desc.region(name)
        if r is None:
            raise AssembleError("Descriptor has no %s region" % name)
        if r.end > size:
            raise AssembleError("%s region ends beyond image size" % name)
        if len(data) > r.size:
            raise AssembleError("%s data (%Xh bytes) is larger than the region (%Xh bytes)" % (name, len(data), r.size))
        if name in ("BIOS", "BIOS2") and bios_align_end:
            start = r.end - len(data)
        else:
            start = r.offset
        out[start:start + len(data)] = data
    return bytes(out)


def split(image: bytes) -> dict[str, bytes]:
    """Split a full image into its regions according to its descriptor."""
    desc = descriptor.parse(image)
    out = {}
    for r in desc.regions:
        if r.used and r.offset < len(image):
            out[r.name] = image[r.offset:min(r.end, len(image))]
    return out
