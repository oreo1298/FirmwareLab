"""`fwlab` command line tool."""

from __future__ import annotations

import argparse
import os
import sys

from .. import __version__
from ..core import guids as G
from ..core.binary import hexdump, human_size
from ..core.node import NodeType
from ..formats.context import ParseOptions


def _eprint(*a):
    print(*a, file=sys.stderr)


def _load(path: str, no_decompress: bool = False):
    from ..tools.project import Document
    opts = ParseOptions(decompress=not no_decompress)
    try:
        return Document.open(path, opts)
    except FileNotFoundError:
        _eprint("error: file not found:", path)
        sys.exit(2)


def _resolve(doc, selector: str):
    """Resolve a node selector: path like 0/1/3, or a GUID, or a name substring."""
    from ..tools import search
    if selector is None:
        return doc.root
    if "/" in selector and all(p.isdigit() for p in selector.split("/") if p):
        path = [int(p) for p in selector.split("/") if p != ""]
        n = doc.resolve(path)
        if n is None:
            _eprint("error: no item at path", selector)
            sys.exit(2)
        return n
    if G.is_guid_text(selector):
        hits = search.search_guid(doc.root, selector)
        if not hits:
            _eprint("error: no item with GUID", selector)
            sys.exit(2)
        return hits[0].node
    hits = search.search_name(doc.root, selector)
    if not hits:
        _eprint("error: no item matching", repr(selector))
        sys.exit(2)
    return hits[0].node


# --------------------------------------------------------------------------- info
def cmd_info(args):
    doc = _load(args.file, args.no_decompress)
    from ..tools import report
    if args.json:
        print(report.report_json(doc.root, include_info=not args.no_info))
    elif args.summary:
        print(report.summary(doc.root, doc.ctx))
    else:
        print(report.report_text(doc.root, verbose=args.verbose))
    return 0


def cmd_tree(args):
    doc = _load(args.file, args.no_decompress)
    maxd = args.depth if args.depth is not None else 99

    def walk(n, d):
        if d > maxd:
            return
        off = n.abs_offset
        addr = n.meta.get("address")
        loc = ("@%08X" % off) if off is not None else "@decompressed"
        extra = " ->%08X" % addr if addr else ""
        flags = (" [%s]" % ",".join(sorted(n.flags))) if n.flags else ""
        name = n.text or n.name
        print("%s%s %s (%s, %s)%s%s" % (
            "  " * d, n.subtype or n.type.value, name, "%Xh" % n.size, loc + extra, flags,
            "  ! " + "; ".join(n.messages) if n.messages else ""))
        for c in n.children:
            walk(c, d + 1)

    walk(doc.root, 0)
    return 0


# --------------------------------------------------------------------------- extract
def cmd_extract(args):
    doc = _load(args.file, args.no_decompress)
    node = _resolve(doc, args.item)
    if args.all:
        return _extract_all(doc, node, args.output or (args.file + ".dump"))
    data = doc.extract(node, args.mode)
    out = args.output or "%s_%s.bin" % (os.path.splitext(os.path.basename(args.file))[0], node.type.value.lower())
    with open(out, "wb") as fh:
        fh.write(data)
    print("wrote %s (%s)" % (out, human_size(len(data))))
    return 0


def _extract_all(doc, root, outdir):
    os.makedirs(outdir, exist_ok=True)
    n = 0
    for node in root.walk():
        if node.type == NodeType.FILE and "pad" not in node.flags:
            name = "%s_%s.ffs" % (node.text or "file", G.guid_to_str(node.meta["guid"])[:8]) \
                if node.meta.get("guid") else "file_%d.bin" % node.uid
            name = name.replace("/", "_")
            with open(os.path.join(outdir, name), "wb") as fh:
                fh.write(node.data)
            n += 1
    print("extracted %d files to %s" % (n, outdir))
    return 0


# --------------------------------------------------------------------------- replace/insert/remove
def _save(doc, args, default_suffix="_mod"):
    out = args.output
    inplace = getattr(args, "inplace", False)
    if not out and not inplace:
        base, ext = os.path.splitext(args.file)
        out = base + default_suffix + ext
    rep = doc.save(out, backup=not getattr(args, "no_backup", False),
                   verify=not getattr(args, "no_verify", False), reload=False)
    _print_report(rep)
    if not rep.ok:
        _eprint("error: verification failed, file not written")
        return 3
    print("wrote", out or args.file)
    return 0


def _print_report(rep):
    for m in rep.moved:
        print("  moved:", m)
    for f in rep.changed_files[:40]:
        print("  ", f)
    for w in rep.warnings:
        _eprint("  warning:", w)
    for e in rep.errors:
        _eprint("  error:", e)


def cmd_replace(args):
    doc = _load(args.file)
    node = _resolve(doc, args.item)
    with open(args.data, "rb") as fh:
        data = fh.read()
    from ..tools.project import EditError
    try:
        doc.replace(node, data, mode=args.mode, allow_guid_change=args.allow_guid_change)
    except EditError as e:
        _eprint("error:", e)
        return 2
    return _save(doc, args)


def cmd_insert(args):
    doc = _load(args.file)
    node = _resolve(doc, args.item)
    with open(args.data, "rb") as fh:
        data = fh.read()
    from ..tools.project import EditError
    try:
        doc.insert(node, data, where=args.where)
    except EditError as e:
        _eprint("error:", e)
        return 2
    return _save(doc, args)


def cmd_remove(args):
    doc = _load(args.file)
    node = _resolve(doc, args.item)
    from ..tools.project import EditError
    try:
        doc.remove(node)
    except EditError as e:
        _eprint("error:", e)
        return 2
    return _save(doc, args)


# --------------------------------------------------------------------------- search
def cmd_search(args):
    doc = _load(args.file, args.no_decompress)
    from ..tools import search
    if args.guid:
        matches = search.search_guid(doc.root, args.guid)
    elif args.hex:
        matches = search.search_hex(doc.root, args.hex)
    elif args.name:
        matches = search.search_name(doc.root, args.name)
    else:
        matches = search.search_text(doc.root, args.text)
    for m in matches:
        off = m.node.abs_offset
        print("%s  %s  %s%s :: %s" % (
            m.node.type.value, m.node.display_name,
            "@%08X" % off if off is not None else "@decompressed",
            "+%X" % m.offset if m.offset >= 0 else "", m.context))
    print("%d match(es)" % len(matches))
    return 0


# --------------------------------------------------------------------------- patch
def cmd_patch(args):
    doc = _load(args.file)
    from ..tools import patch
    with open(args.script) as fh:
        script = fh.read()
    try:
        results = patch.apply_script(doc, script, dry_run=args.dry_run)
    except patch.PatchError as e:
        _eprint("error:", e)
        return 2
    for r in results:
        print("%s %s +%Xh: %s -> %s" % (
            "would patch" if args.dry_run else "patched", r.node.display_name, r.offset,
            r.old.hex(), r.new.hex()))
    print("%d change(s)" % len(results))
    if args.dry_run or not results:
        return 0
    return _save(doc, args)


# --------------------------------------------------------------------------- diff
def cmd_diff(args):
    from ..tools import diff
    a = _load(args.file, args.no_decompress)
    b = _load(args.other, args.no_decompress)
    entries = diff.diff_trees(a.root, b.root)
    if args.json:
        import json
        print(json.dumps([{"status": e.status, "path": e.path, "kind": e.kind, "detail": e.detail}
                          for e in entries], indent=2))
    else:
        print(diff.format_text(entries))
    return 0


# --------------------------------------------------------------------------- nvram
def cmd_nvram(args):
    doc = _load(args.file)
    from ..formats import nvram
    if args.set is not None:
        name, value = args.set
        vars_ = nvram.find_variables(doc.root, name)
        if not vars_:
            _eprint("error: variable not found:", name)
            return 2
        data = bytes.fromhex(value) if all(c in "0123456789abcdefABCDEF" for c in value) and len(value) % 2 == 0 \
            else value.encode()
        for v in vars_:
            doc.set_variable_data(doc.resolve(v.path()), data)
        return _save(doc, args)
    for v in nvram.iter_variables(doc.root):
        if args.name and args.name.lower() not in (v.meta.get("var_name") or "").lower():
            continue
        cur = "" if v.meta.get("current", True) else " (inactive)"
        print("%-40s %-38s %s%s" % (v.meta.get("var_name"), G.guid_db().display(v.meta.get("guid") or b""),
                                    v.body[:32].hex(), cur))
    return 0


# --------------------------------------------------------------------------- setup
def cmd_setup(args):
    doc = _load(args.file)
    from ..hii.setup import SetupBrowser
    b = SetupBrowser(doc, args.language)
    if args.search:
        for r in b.search(args.search):
            print("%-45s = %-20s  [%s / %s]" % (
                r.prompt[:45], b.describe_value(r, b.current_value(r)), r.module.name, r.formset.title))
        return 0
    print(b.dump(hidden=not args.no_hidden))
    return 0


# --------------------------------------------------------------------------- ifr
def cmd_ifr(args):
    doc = _load(args.file)
    from ..hii import scan
    mods = scan.scan(doc.root, args.language)
    if not mods:
        print("no HII form packages found")
        return 0
    from ..hii.ifr import package_text
    for m in mods:
        if args.module and args.module.lower() not in m.name.lower():
            continue
        for pkg in m.form_packages:
            print("===== %s (form package @%Xh) =====" % (m.name, pkg.offset))
            print(package_text(pkg, m.pairing.get(pkg.offset), with_bytes=args.bytes))
    return 0


# --------------------------------------------------------------------------- microcode
def cmd_microcode(args):
    doc = _load(args.file)
    ucodes = [n for n in doc.root.walk() if n.type == NodeType.MICROCODE]
    if not ucodes:
        print("no microcode found")
        return 0
    for u in ucodes:
        i = u.meta.get("ucode")
        off = u.abs_offset
        print("@%s CPUID %08Xh rev %Xh %s %s size %Xh %s" % (
            "%08X" % off if off is not None else "decompressed", i.signature, i.revision, i.cpu_name,
            i.date, i.total_size, "OK" if i.checksum_valid else "BAD-CHECKSUM"))
        for s, f, c in i.ext_signatures:
            print("    ext CPUID %08Xh (%s) platforms %02Xh" % (s, __import__("firmwarelab.formats.microcode",
                  fromlist=["cpu_name"]).cpu_name(s), f))
    return 0


# --------------------------------------------------------------------------- descriptor
def cmd_descriptor(args):
    from ..formats import descriptor
    doc = _load(args.file)
    desc = doc.root.meta.get("descriptor")
    if desc is None:
        # maybe raw descriptor file
        with open(args.file, "rb") as fh:
            data = fh.read()
        if descriptor.find_descriptor(data) != 0:
            _eprint("error: no Intel flash descriptor in this image")
            return 2
        desc = descriptor.parse(data)
    if args.unlock:
        data = doc.build()
        newdata = descriptor.unlock(data, descriptor.parse(data))
        doc.apply_raw_image(newdata, "Unlock flash descriptor")
        return _save(doc, args, "_unlocked")
    for k, v in descriptor.describe(desc):
        print("%-28s %s" % (k, v))
    return 0


# --------------------------------------------------------------------------- gbe
def cmd_gbe(args):
    from ..formats import gbe
    doc = _load(args.file)
    reg = doc.root.find(lambda n: n.type == NodeType.REGION and n.subtype == "GbE")
    if reg is None:
        _eprint("error: no GbE region")
        return 2
    if args.set_mac:
        newbody = gbe.set_mac(reg.body, args.set_mac)
        doc.replace(doc.resolve(reg.path()), newbody, mode="body")
        return _save(doc, args, "_gbe")
    print("MAC:", gbe.mac_of(reg.body))
    return 0


# --------------------------------------------------------------------------- flash
def cmd_flash(args):
    from ..tools import flash
    doc = _load(args.file)
    if args.strip_capsule:
        data = flash.strip_capsule(doc.build())
        out = args.output or (os.path.splitext(args.file)[0] + "_payload.bin")
        with open(out, "wb") as fh:
            fh.write(data)
        print("wrote payload", out, human_size(len(data)))
        return 0
    if args.pad_to:
        size = _parse_size(args.pad_to)
        data = flash.pad_to(doc.build(), size, at_end=args.pad_end)
        out = args.output or (os.path.splitext(args.file)[0] + "_padded.bin")
        with open(out, "wb") as fh:
            fh.write(data)
        print("padded to", human_size(size), "->", out)
        return 0
    r = flash.analyze(doc)
    print("Image size: %s (%s)" % ("%Xh" % r.size, human_size(r.size)))
    if r.nearest_chip:
        print("Nearest standard chip: %s" % human_size(r.nearest_chip))
    print("Flash-ready:", "yes" if r.ok else "NO")
    for i in r.issues:
        print("  issue:", i)
    for n in r.notes:
        print("  note:", n)
    return 0


def _parse_size(s: str) -> int:
    s = s.strip().lower()
    mult = 1
    for suf, m in (("k", 1024), ("m", 1024 ** 2), ("kib", 1024), ("mib", 1024 ** 2)):
        if s.endswith(suf):
            mult = m
            s = s[: -len(suf)]
            break
    return int(s, 0) * mult


# --------------------------------------------------------------------------- assemble/split
def cmd_assemble(args):
    from ..tools import assemble
    with open(args.descriptor, "rb") as fh:
        desc = fh.read()
    regions = {}
    for spec in args.region or []:
        name, _, path = spec.partition("=")
        with open(path, "rb") as fh:
            regions[name] = fh.read()
    try:
        data = assemble.assemble(desc, regions, size=_parse_size(args.size) if args.size else None)
    except assemble.AssembleError as e:
        _eprint("error:", e)
        return 2
    with open(args.output, "wb") as fh:
        fh.write(data)
    print("assembled %s (%s)" % (args.output, human_size(len(data))))
    return 0


def cmd_split(args):
    from ..tools import assemble
    with open(args.file, "rb") as fh:
        data = fh.read()
    try:
        regions = assemble.split(data)
    except ValueError as e:
        _eprint("error:", e)
        return 2
    outdir = args.output or (os.path.splitext(args.file)[0] + "_regions")
    os.makedirs(outdir, exist_ok=True)
    for name, blob in regions.items():
        p = os.path.join(outdir, name.lower() + ".bin")
        with open(p, "wb") as fh:
            fh.write(blob)
        print("  %s -> %s (%s)" % (name, p, human_size(len(blob))))
    return 0


def cmd_hexdump(args):
    doc = _load(args.file, args.no_decompress)
    node = _resolve(doc, args.item)
    data = doc.extract(node, args.mode)
    print(hexdump(data, limit=args.limit))
    return 0


# --------------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="fwlab", description="FirmwareLab - UEFI/BIOS firmware toolkit")
    p.add_argument("--version", action="version", version="FirmwareLab " + __version__)
    sub = p.add_subparsers(dest="command", required=True)

    def add_common(sp, decompress=True):
        if decompress:
            sp.add_argument("--no-decompress", action="store_true", help="do not decompress sections")

    def add_save(sp):
        sp.add_argument("-o", "--output", help="output file (default: <name>_mod.<ext>)")
        sp.add_argument("--inplace", action="store_true", help="overwrite the input file")
        sp.add_argument("--no-backup", action="store_true", help="do not write a .bak backup")
        sp.add_argument("--no-verify", action="store_true", help="skip rebuild verification")

    s = sub.add_parser("info", help="print the item table"); add_common(s)
    s.add_argument("file"); s.add_argument("--json", action="store_true"); s.add_argument("--summary", action="store_true")
    s.add_argument("--no-info", action="store_true"); s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(func=cmd_info)

    s = sub.add_parser("tree", help="print the structure tree"); add_common(s)
    s.add_argument("file"); s.add_argument("--depth", type=int); s.set_defaults(func=cmd_tree)

    s = sub.add_parser("extract", help="extract an item"); add_common(s)
    s.add_argument("file"); s.add_argument("item", nargs="?")
    s.add_argument("-o", "--output"); s.add_argument("--mode", choices=["full", "body", "header", "uncompressed"], default="full")
    s.add_argument("--all", action="store_true", help="extract all FFS files to a directory")
    s.set_defaults(func=cmd_extract)

    s = sub.add_parser("replace", help="replace an item's contents"); add_save(s)
    s.add_argument("file"); s.add_argument("item"); s.add_argument("data")
    s.add_argument("--mode", choices=["full", "body", "uncompressed"], default="body")
    s.add_argument("--allow-guid-change", action="store_true")
    s.set_defaults(func=cmd_replace)

    s = sub.add_parser("insert", help="insert an FFS file or section"); add_save(s)
    s.add_argument("file"); s.add_argument("item"); s.add_argument("data")
    s.add_argument("--where", choices=["into", "before", "after"], default="into")
    s.set_defaults(func=cmd_insert)

    s = sub.add_parser("remove", help="remove an item"); add_save(s)
    s.add_argument("file"); s.add_argument("item"); s.set_defaults(func=cmd_remove)

    s = sub.add_parser("search", help="search the image"); add_common(s)
    s.add_argument("file")
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--text"); g.add_argument("--guid"); g.add_argument("--hex"); g.add_argument("--name")
    s.set_defaults(func=cmd_search)

    s = sub.add_parser("patch", help="apply a patch script"); add_save(s)
    s.add_argument("file"); s.add_argument("script"); s.add_argument("--dry-run", action="store_true")
    s.set_defaults(func=cmd_patch)

    s = sub.add_parser("diff", help="compare two images"); add_common(s)
    s.add_argument("file"); s.add_argument("other"); s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_diff)

    s = sub.add_parser("nvram", help="list or set NVRAM variables"); add_save(s)
    s.add_argument("file"); s.add_argument("--name")
    s.add_argument("--set", nargs=2, metavar=("NAME", "HEXVALUE"))
    s.set_defaults(func=cmd_nvram)

    s = sub.add_parser("setup", help="browse BIOS Setup questions and current values")
    s.add_argument("file"); s.add_argument("--search"); s.add_argument("--language", default="en-US")
    s.add_argument("--no-hidden", action="store_true"); s.set_defaults(func=cmd_setup)

    s = sub.add_parser("ifr", help="dump IFR forms as text")
    s.add_argument("file"); s.add_argument("--module"); s.add_argument("--language", default="en-US")
    s.add_argument("--bytes", action="store_true", help="append raw opcode bytes")
    s.set_defaults(func=cmd_ifr)

    s = sub.add_parser("microcode", help="list CPU microcode updates")
    s.add_argument("file"); s.set_defaults(func=cmd_microcode)

    s = sub.add_parser("descriptor", help="show or unlock the Intel flash descriptor"); add_save(s)
    s.add_argument("file"); s.add_argument("--unlock", action="store_true")
    s.set_defaults(func=cmd_descriptor)

    s = sub.add_parser("gbe", help="show or set the GbE MAC address"); add_save(s)
    s.add_argument("file"); s.add_argument("--set-mac", metavar="MAC")
    s.set_defaults(func=cmd_gbe)

    s = sub.add_parser("flash", help="check flash readiness, pad or strip capsule")
    s.add_argument("file"); s.add_argument("-o", "--output")
    s.add_argument("--pad-to", metavar="SIZE"); s.add_argument("--pad-end", action="store_true")
    s.add_argument("--strip-capsule", action="store_true"); s.set_defaults(func=cmd_flash)

    s = sub.add_parser("assemble", help="assemble a full image from regions + descriptor")
    s.add_argument("--descriptor", required=True); s.add_argument("--region", action="append", metavar="NAME=FILE")
    s.add_argument("--size"); s.add_argument("-o", "--output", required=True); s.set_defaults(func=cmd_assemble)

    s = sub.add_parser("split", help="split a full image into region files")
    s.add_argument("file"); s.add_argument("-o", "--output"); s.set_defaults(func=cmd_split)

    s = sub.add_parser("hexdump", help="hex dump an item"); add_common(s)
    s.add_argument("file"); s.add_argument("item", nargs="?")
    s.add_argument("--mode", choices=["full", "body", "uncompressed"], default="full")
    s.add_argument("--limit", type=int, default=1024); s.set_defaults(func=cmd_hexdump)

    s = sub.add_parser("gui", help="launch the graphical interface")
    s.add_argument("file", nargs="?"); s.set_defaults(func=cmd_gui)
    return p


def cmd_gui(args):
    try:
        from ..gui.app import run
    except ImportError as e:
        _eprint("error: GUI requires PySide6 (pip install firmwarelab[gui]):", e)
        return 2
    return run([args.file] if args.file else [])


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
