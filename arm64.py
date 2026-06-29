#!/usr/bin/env python3
"""
instruction decoding and pattern scanning.
"""
import struct
try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    from capstone.arm64 import (
        ARM64_OP_REG,
        ARM64_OP_MEM,
        ARM64_REG_X29,
        ARM64_REG_X30,
        ARM64_REG_SP,
    )

    HAS_CS = True
except ImportError:
    HAS_CS = False
    print("[~] capstone not found - using raw STP mask (less reliable)")
    print("    pip install capstone  (recommended)\n")


def adrp_target(pc, w):
    """Decode ADRP -> target page VA, or None if not ADRP."""
    if (w & 0x9F000000) != 0x90000000:
        return None
    imm = (((w >> 5) & 0x7FFFF) << 2) | ((w >> 29) & 3)
    if imm & (1 << 20):
        imm -= 1 << 21
    return (pc & ~0xFFF) + (imm << 12)


def find_xrefs(td, tva, target):
    """ADRP+ADD/LDRB/LDR pairs in .text referencing target VA."""
    page = target & ~0xFFF
    off12 = target & 0xFFF
    out = []
    n = len(td) // 4
    words = struct.unpack(f"<{n}I", td[: n * 4])
    for i, w in enumerate(words[:-1]):
        if (w & 0x9F000000) != 0x90000000:
            continue
        rd = w & 0x1F
        pc = tva + i * 4
        if adrp_target(pc, w) != page:
            continue
        nw = words[i + 1]
        rn = (nw >> 5) & 0x1F
        if rn != rd:
            continue
        imm = (nw >> 10) & 0xFFF
        # ADD Xd, Xn, #imm12
        if (nw & 0xFFC00000) == 0x91000000 and imm == off12:
            out.append(pc)
        # LDRB Wd, [Xn, #imm12]  (unshifted)
        elif (nw & 0xFFC00000) == 0x39400000 and imm == off12:
            out.append(pc)
        # LDR Wd, [Xn, #imm12]   (<<2)
        elif (nw & 0xFFC00000) == 0xB9400000 and (imm << 2) == off12:
            out.append(pc)
        # LDR Xd, [Xn, #imm12]   (<<3)
        elif (nw & 0xFFC00000) == 0xF9400000 and (imm << 3) == off12:
            out.append(pc)
    return out


def func_start(td, tva, ref_va, window=0x600):
    """Walk back from ref_va to find STP x29, x30, [sp, ...] prologue."""
    roff = ref_va - tva
    soff = max(0, roff - window)

    if HAS_CS:
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        md.detail = True
        chunk = td[soff : roff + 4]
        insns = list(md.disasm(chunk, tva + soff))
        for ins in reversed(insns):
            if ins.mnemonic != "stp":
                continue
            ops = ins.operands
            if (
                len(ops) >= 3
                and ops[0].type == ARM64_OP_REG
                and ops[0].reg == ARM64_REG_X29
                and ops[1].type == ARM64_OP_REG
                and ops[1].reg == ARM64_REG_X30
                and ops[2].type == ARM64_OP_MEM
                and ops[2].mem.base == ARM64_REG_SP
            ):
                return ins.address
    else:
        # raw mask: STP X29, X30, [SP, #any]!
        # bits 31-24 = 0xA9, bits 15-0 = 0x7BFD, bits 23-16 vary (frame size)
        for i in range(roff, soff - 1, -4):
            if (struct.unpack_from("<I", td, i)[0] & 0xFF00FFFF) == 0xA9007BFD:
                return tva + i
    return None


def find_elm(td, tva, func_va, wranges):
    """
    First ADRP+LDRB within 0x100 bytes of func start that targets
    a writable section -> EnableLoadModule byte flag.
    """
    fo = func_va - tva
    limit = min(fo + 0x100, len(td) - 7)
    for i in range(fo, limit, 4):
        w = struct.unpack_from("<I", td, i)[0]
        if (w & 0x9F000000) != 0x90000000:
            continue
        rd = w & 0x1F
        ap = adrp_target(tva + i, w)
        if ap is None:
            continue
        nw = struct.unpack_from("<I", td, i + 4)[0]
        # must be LDRB (byte load) - the flag is a single byte
        if (nw & 0xFFC00000) != 0x39400000:
            continue
        if (nw >> 5) & 0x1F != rd:
            continue
        target = ap + ((nw >> 10) & 0xFFF)
        if any(lo <= target < hi for lo, hi in wranges):
            return target
    return None


def first_bl(td, tva, ref_va, ahead=0x50):
    """First BL instruction after ref_va -> err_reporter (sub_220B7A0)."""
    roff = ref_va - tva
    limit = min(roff + ahead, len(td) - 3)
    for i in range(roff, limit, 4):
        w = struct.unpack_from("<I", td, i)[0]
        if (w & 0xFC000000) == 0x94000000:
            imm26 = w & 0x3FFFFFF
            if imm26 & (1 << 25):
                imm26 -= 1 << 26
            return (tva + i) + (imm26 << 2)
    return None


def find_script_context_on_sp(binary, raw, td, tva, wranges):
    """
    1. String anchor "MemoryCategoryDataMutex" -> xref -> func
    2. Fallback: vtable scan in .data.rel.ro
    """
    # try 1: string anchor
    anchor = "MemoryCategoryDataMutex"
    va = None
    off = raw.find(anchor.encode() + b"\x00")
    if off != -1:
        for sec in binary.sections:
            so = sec.offset
            if so and sec.size and so <= off < so + sec.size:
                va = sec.virtual_address + (off - so)
                break

    if va is not None:
        refs = find_xrefs(td, tva, va)
        for ref in refs:
            fv = func_start(td, tva, ref, window=0x1000)
            if fv:
                fo = fv - tva
                if fo + 0x100 <= len(td):
                    return fv

    # try 2: vtable scan in .data.rel.ro
    ro_data = next((s for s in binary.sections if s.name == ".data.rel.ro"), None)
    if ro_data is None:
        return None

    ro_start = ro_data.virtual_address
    ro_size = ro_data.size
    ro_off = ro_data.offset
    if not ro_size:
        return None

    ro_raw = raw[ro_off : ro_off + ro_size]
    text_end = tva + len(td)
    bin_min = tva
    bin_max = text_end

    # scan for arrays of valid pointers
    for i in range(0, len(ro_raw) - 400, 8):
        ptr = struct.unpack_from("<Q", ro_raw, i)[0]
        if ptr < bin_min or ptr > bin_max or (ptr & 3) != 0:
            continue
        # check 10 consecutive pointers are valid
        valid = 0
        for j in range(10):
            if i + j * 8 + 8 > len(ro_raw):
                break
            p = struct.unpack_from("<Q", ro_raw, i + j * 8)[0]
            if bin_min < p < bin_max and (p & 3) == 0:
                valid += 1
        if valid < 8:
            continue

        # check vtable entries for mutex references
        for idx in range(64):
            if i + idx * 8 + 8 > len(ro_raw):
                break
            entry = struct.unpack_from("<Q", ro_raw, i + idx * 8)[0]
            if entry < tva or entry >= text_end:
                continue
            # check function size >= 0x200
            entry_roff = entry - tva
            if entry_roff + 0x200 > len(td):
                continue
            # scan first 0x400 bytes of function for data references
            has_mutex = False
            scan_limit = min(entry_roff + 0x400, len(td) - 4)
            for si in range(entry_roff, scan_limit, 4):
                w = struct.unpack_from("<I", td, si)[0]
                if (w & 0x9F000000) != 0x90000000:
                    continue
                ap = adrp_target(tva + si, w)
                if ap is None:
                    continue
                nw = struct.unpack_from("<I", td, si + 4)[0]
                rn = (nw >> 5) & 0x1F
                if rn != (w & 0x1F):
                    continue
                imm = (nw >> 10) & 0xFFF
                if (nw & 0xFFC00000) == 0x91000000:
                    target = ap + imm
                elif (nw & 0xFFC00000) == 0xF9400000:
                    target = ap + (imm << 3)
                elif (nw & 0xFFC00000) == 0xB9400000:
                    target = ap + (imm << 2)
                else:
                    continue
                if any(lo <= target < hi for lo, hi in wranges):
                    has_mutex = True
                    break
            if has_mutex:
                return entry

    return None
