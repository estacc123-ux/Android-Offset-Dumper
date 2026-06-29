#!/usr/bin/env python3
"""
Banner printing for libroblox.so analysis.
"""
import os, struct
from config import KEYWORDS
from arm64 import adrp_target
from elf_helpers import comma, sec_flags, arch_name, etype_name, export_import_counts


def print_banner(path, binary, raw):
    mb = os.path.getsize(path) / 1_048_576

    # null-terminated printable strings >= 4 chars
    sc = run = 0
    for b in raw:
        if 0x20 <= b < 0x7F:
            run += 1
        else:
            if run >= 4 and b == 0:
                sc += 1
            run = 0

    # keyword scan
    kw = sum(raw.count(k) for k in KEYWORDS)

    # BSS refs: ADRP targets landing in .bss
    bss = next((s for s in binary.sections if s.name == ".bss"), None)
    text = next((s for s in binary.sections if s.name == ".text"), None)
    bss_refs = 0
    if bss and text:
        bs = bss.virtual_address
        be = bs + bss.size
        tva = text.virtual_address
        td = bytes(text.content)
        n = len(td) // 4
        wds = struct.unpack(f"<{n}I", td[: n * 4])
        for i, w in enumerate(wds):
            t = adrp_target(tva + i * 4, w)
            if t is not None and bs <= t < be:
                bss_refs += 1

    ex, im = export_import_counts(binary)

    print(f"Loaded: {path} ({mb:.1f} MB)")
    print(f"  -Arch:       {arch_name(binary)}")
    print(f"  -Type:       {etype_name(binary)}")
    print(f"  -Entry:      {hex(binary.header.entrypoint)}")
    print(f"  -Sections:   {len(binary.sections)}")
    print(f"  -Segments:   {len(binary.segments)}")
    print(f"  -Exports:    {ex}")
    print(f"  -Imports:    {im}")
    print(f"  -Strings:    {comma(sc)}")
    print(f"  -BSS refs:   {comma(bss_refs)}")
    print(f"  -Notable:    {comma(kw)} keyword matches")
    print()
    print("  --- SECTIONS ---")
    for sec in binary.sections:
        name = sec.name or ""
        print(
            f"  {sec.virtual_address:#018x}  {name:<40} {comma(sec.size):>12}  {sec_flags(sec)}"
        )
    print()
