#!/usr/bin/env python3
"""
C++ header file generator for dumped offsets.
"""

import datetime


def generate_header(results, tva, binary_path, arch="ARM64"):
    lines = []

    # header comment
    lines.append("// Dump")
    # lines.append(f"// Source: {binary_path}")
    lines.append(f"// Source: libroblox.so")
    lines.append(f"// Arch: {arch}")
    lines.append(f"// Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append("#pragma once")
    lines.append("")
    lines.append("namespace Offsets {")
    lines.append("")

    for key, va in results.items():
        off = va - tva
        lines.append(f"    inline uintptr_t {key} = {off:#x};")
        lines.append("")

    lines.append("} // namespace Offsets")
    lines.append("")

    return "\n".join(lines)


def write_header(path, results, tva, binary_path, arch="ARM64"):
    content = generate_header(results, tva, binary_path, arch)
    with open(path, "w") as f:
        f.write(content)
    return path
