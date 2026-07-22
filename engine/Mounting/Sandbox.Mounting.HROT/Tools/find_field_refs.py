#!/usr/bin/env python3
"""Find x86 memory operands using selected structure-field displacements."""

from __future__ import annotations

import sys
import struct

import capstone
import pefile


def main() -> None:
    pe = pefile.PE(sys.argv[1])
    fields = {int(value, 0) for value in sys.argv[2:]}
    image = pe.OPTIONAL_HEADER.ImageBase
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    md.skipdata = True

    for section in pe.sections:
        if not section.Characteristics & 0x20000000:
            continue
        start = image + section.VirtualAddress
        instructions = list(md.disasm(section.get_data(), start))
        for index, instruction in enumerate(instructions):
            if instruction.id == 0:
                continue
            matched = False
            for operand in instruction.operands:
                if operand.type != capstone.x86.X86_OP_MEM:
                    continue
                if operand.mem.disp in fields:
                    matched = True
                    break
            if not matched:
                continue
            print(f"--- {instruction.address:08X} ---")
            for item in instructions[max(0, index - 5):index + 6]:
                marker = ">" if item.address == instruction.address else " "
                print(f"{marker} {item.address:08X}  {item.mnemonic:8} {item.op_str}")

    # Linear disassembly loses synchronization in Delphi sections containing
    # embedded tables. Also report every literal disp32 occurrence and decode
    # a small window around it; this catches indexed structure accesses that
    # Capstone's section-wide pass can otherwise skip.
    print("\n=== raw disp32 occurrences ===")
    for section in pe.sections:
        if not section.Characteristics & 0x20000000:
            continue
        data = section.get_data()
        section_start = image + section.VirtualAddress
        for field in sorted(fields):
            needle = struct.pack("<I", field & 0xFFFFFFFF)
            offset = 0
            while True:
                hit = data.find(needle, offset)
                if hit < 0:
                    break
                window_start = max(0, hit - 12)
                window = data[window_start:min(len(data), hit + 16)]
                print(f"--- literal {field:#x} at {section_start + hit:08X} ---")
                for item in md.disasm(window, section_start + window_start):
                    print(f"  {item.address:08X}  {item.mnemonic:8} {item.op_str}")
                offset = hit + 1


if __name__ == "__main__":
    main()
