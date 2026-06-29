#!/usr/bin/env python3
"""
ELF helper: address translation, string lookup, section helpers.
"""

import os, struct
from config import SHF_FLAGS


def comma(n):
    return f"{n:,}"


def sec_flags(sec):
    try:
        v = int(sec.flags)
    except Exception:
        return "[]"
    return "[" + "".join(k for k, m in SHF_FLAGS.items() if v & m) + "]"


def arch_name(binary):
    s = str(binary.header.machine_type)
    if "AARCH64" in s or "ARM64" in s:
        return "ARM64"
    if "ARM" in s:
        return "ARM"
    if "X86_64" in s or "AMD64" in s:
        return "x86_64"
    return s.split(".")[-1]


def etype_name(binary):
    s = str(binary.header.file_type)
    if "DYNAMIC" in s:
        return "DYN (shared lib)"
    if "EXEC" in s:
        return "EXEC"
    return s.split(".")[-1]


def export_import_counts(binary):
    try:
        ex = len(list(binary.exported_functions))
    except Exception:
        ex = sum(1 for s in binary.dynamic_symbols if s.exported)
    try:
        im = len(list(binary.imported_functions))
    except Exception:
        im = sum(1 for s in binary.dynamic_symbols if s.imported)
    return ex, im


def fileoff_to_va(binary, off):
    """Convert a file offset to a virtual address."""
    for sec in binary.sections:
        so = sec.offset
        if so and sec.size and so <= off < so + sec.size:
            return sec.virtual_address + (off - so)
    for seg in binary.segments:
        fo = seg.file_offset
        ps = seg.physical_size
        if fo and ps and fo <= off < fo + ps:
            return seg.virtual_address + (off - fo)
    return None


def str_va(raw, binary, s):
    """Find the VA of a null-terminated string in the binary."""
    off = raw.find(s.encode() + b"\x00")
    return fileoff_to_va(binary, off) if off != -1 else None


def writable_ranges(binary):
    """Return list of (start, end) VA ranges for writable sections."""
    return [
        (s.virtual_address, s.virtual_address + s.size)
        for s in binary.sections
        if int(s.flags) & SHF_FLAGS["W"] and s.size
    ]
