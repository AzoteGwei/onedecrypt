#!/usr/bin/env python3
"""Minimal Go 1.26+ pclntab parser for stripped Go ELF binaries.

Go 1.26 removed the textStart field from pcHeader (see runtime/symtab.go);
the text base is taken from the ELF .text section. Function name offsets are
relative to funcnametab; _func structs live at pclnOffset + funcoff.
"""
import json
import struct
import sys

from elftools.elf.elffile import ELFFile


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def i32(b, o):
    return struct.unpack_from("<i", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def cstr(b, o):
    e = b.index(b"\x00", o)
    return b[o:e].decode("utf-8", "replace")


def main():
    path = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else None
    raw = open(path, "rb").read()
    elf = ELFFile(open(path, "rb"))
    text_sec = next(s for s in elf.iter_sections() if s.name == ".text")
    text_base = text_sec["sh_addr"]
    pcln_sec = next(s for s in elf.iter_sections() if s.name == ".gopclntab")
    base = pcln_sec["sh_offset"]
    nfunc = u64(raw, base + 8)
    nfiles = u64(raw, base + 16)
    funcname_off = u64(raw, base + 32)
    pcln_off = u64(raw, base + 64)
    print(
        "text=0x%x pclntab=0x%x nfunc=%d nfiles=%d funcname=0x%x pcln=0x%x"
        % (text_base, base, nfunc, nfiles, funcname_off, pcln_off),
        file=sys.stderr,
    )
    funcnametab = base + funcname_off
    ftab = base + pcln_off
    funcs = []
    for i in range(nfunc):
        ent = ftab + i * 8
        entryoff = u32(raw, ent)
        funcoff = u32(raw, ent + 4)
        fptr = ftab + funcoff
        nameoff = i32(raw, fptr + 4)
        if nameoff < 0:
            continue
        name = cstr(raw, funcnametab + nameoff)
        if not name:
            continue
        funcs.append({"addr": text_base + entryoff, "name": name})
    print("parsed %d functions" % len(funcs), file=sys.stderr)
    if out:
        with open(out, "w") as f:
            json.dump(funcs, f, indent=0)
    for f in funcs:
        print("0x%x %s" % (f["addr"], f["name"]))


if __name__ == "__main__":
    main()
