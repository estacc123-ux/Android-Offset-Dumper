#!/usr/bin/env python3
"""
Usage:
    python main.py
    python main.py <path>
    python main.py <path> --base 0x7f12340000
"""

import sys, os, argparse

#  deps
try:
    import lief

    try:
        lief.logging.disable()
    except Exception:
        pass
except ImportError:
    sys.exit("[!] pip install lief")

from config import (
    DEFAULT_BINARY,
    ANCHOR1,
    ANCHOR2,
    ANCHOR3,
    ANCHOR4,
    ANCHOR5,
    ANCHOR6,
    ANCHOR7,
    OFFSET_TABLE,
)
from elf_helpers import str_va, writable_ranges, arch_name
from arm64 import find_xrefs, func_start, find_elm, first_bl, find_script_context_on_sp
from banner import print_banner
from header_gen import write_header


def scan_anchor(raw, binary, td, tva, anchor, result_key, R):
    """Generic anchor scanner: find string, xref, walk to func start."""
    print(f'[*] Anchor: "{anchor[:52]}..."')
    va = str_va(raw, binary, anchor)
    if va is None:
        print("    [!] NOT FOUND")
        return
    print(f"    String VA  : {va:#010x}")
    refs = find_xrefs(td, tva, va)
    print(f"    XREFs      : {len(refs)}")
    for ref in refs:
        fv = func_start(td, tva, ref)
        if fv:
            print(f"    XREF       @ {ref:#010x}  ->  func @ {fv:#010x}")
            R[result_key] = fv
            return
    print("    [!] Could not walk back to function prologue")


def main():
    ap = argparse.ArgumentParser(
        prog="dump_offsets.py",
        description="libroblox.so offset dumper",
    )
    ap.add_argument(
        "binary",
        nargs="?",
        default=DEFAULT_BINARY,
        help=f"path to libroblox.so (default: {DEFAULT_BINARY})",
    )
    ap.add_argument(
        "--base",
        type=lambda x: int(x, 0),
        default=0,
        metavar="ADDR",
        help="runtime load base for Frida offsets (e.g. 0x7f12340000)",
    )
    ap.add_argument(
        "-o",
        "--output",
        default="offsets.h",
        metavar="FILE",
        help="output header file (default: offsets.h)",
    )
    args = ap.parse_args()

    if not os.path.isfile(args.binary):
        sys.exit(f"[!] {args.binary}: not found")

    print(f"[*] Parsing {args.binary} ...")
    binary = lief.parse(args.binary)
    if not binary:
        sys.exit("[!] lief.parse failed")

    with open(args.binary, "rb") as f:
        raw = f.read()

    print_banner(args.binary, binary, raw)

    text = next((s for s in binary.sections if s.name == ".text"), None)
    if not text:
        sys.exit("[!] .text not found")

    td = bytes(text.content)
    tva = text.virtual_address
    wr = writable_ranges(binary)
    R = {}  # results

    # anchor 1 -> rbx_loadmodule + EnableLoadModule + err_reporter
    print(f'[*] Anchor 1: "{ANCHOR1}"')
    va1 = str_va(raw, binary, ANCHOR1)
    if va1 is None:
        print("    [!] NOT FOUND - strings may be stripped or encrypted")
    else:
        print(f"    String VA  : {va1:#010x}")
        refs1 = find_xrefs(td, tva, va1)
        print(f"    XREFs      : {len(refs1)}")
        for ref in refs1:
            fv = func_start(td, tva, ref)
            if fv:
                print(f"    XREF       @ {ref:#010x}  ->  func @ {fv:#010x}")
                R["rbx_loadmodule"] = fv
                R["EnableLoadModule"] = find_elm(td, tva, fv, wr)
                R["err_reporter"] = first_bl(td, tva, ref)
                break
        if "rbx_loadmodule" not in R:
            print("    [!] Could not walk back to function prologue")

    # anchor 2 -> verify rbx_loadmodule
    print()
    print(f'[*] Anchor 2 (verify): "{ANCHOR2[:52]}..."')
    va2 = str_va(raw, binary, ANCHOR2)
    confirmed = False
    if va2:
        print(f"    String VA  : {va2:#010x}")
        refs2 = find_xrefs(td, tva, va2)
        for ref in refs2:
            fv2 = func_start(td, tva, ref)
            if fv2 == R.get("rbx_loadmodule"):
                confirmed = True
                print(f"    Same func   (XREF @ {ref:#010x})")
                break
        if not confirmed:
            if refs2:
                print("    [!] XREF found but resolves to different function")
            else:
                print("    [!] No XREFs to anchor 2")
    else:
        print("    [!] Anchor 2 not found")

    # anchor 3 -> OnGameLeave
    print()
    scan_anchor(raw, binary, td, tva, ANCHOR3, "OnGameLeave", R)

    # anchor 4 -> OnGameBegin
    print()
    scan_anchor(raw, binary, td, tva, ANCHOR4, "OnGameBegin", R)

    # anchor 5 -> ScriptContextResume
    print()
    scan_anchor(raw, binary, td, tva, ANCHOR5, "ScriptContextResume", R)

    # anchor 6 -> JobStart
    print()
    scan_anchor(raw, binary, td, tva, ANCHOR6, "JobStart", R)

    # anchor 7 -> JobStop
    print()
    scan_anchor(raw, binary, td, tva, ANCHOR7, "JobStop", R)

    # ScriptContext_OnServiceProvider (vtable scan)
    print()
    print("[*] Scanning for ScriptContext_OnServiceProvider ...")
    scsp = find_script_context_on_sp(binary, raw, td, tva, wr)
    if scsp:
        print(f"    Found       @ {scsp:#010x}   off={scsp - tva:#010x}")
        R["ScriptContext_OnServiceProvider"] = scsp
    else:
        print("    [!] NOT FOUND")

    # results
    base = args.base
    print()
    print("  --- OFFSET TABLE ---")

    for entry in OFFSET_TABLE:
        label = entry["label"]
        key = entry["key"]
        va = R.get(key)
        if va is None:
            print(f"  {label:<26}  NOT FOUND")
            continue
        off = va - tva
        note = f"<- sub_{va:X} equiv"
        if base:
            print(f"  {label:<26}  VA={va:#010x}   rt={base + va:#x}")
        else:
            print(f"  {label:<26}  VA={va:#010x}   off={off:#010x}")
        print(f"  {'':26}  {note}")

    conf = (
        "HIGH  (dual-anchor verified)" if confirmed else "MEDIUM  (single-anchor only)"
    )
    print(f"\n  Confidence : {conf}")

    label_map = {e["key"]: e["label"] for e in OFFSET_TABLE}
    labeled_results = {label_map.get(k, k): v for k, v in R.items()}
    header_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), args.output)
    write_header(header_path, labeled_results, tva, args.binary, arch_name(binary))
    print(f"\n[*] Header written: {header_path}")


if __name__ == "__main__":
    main()
