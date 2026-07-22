#!/usr/bin/env python3
"""Search for the routine that initializes field 0x14 in the HROT grid."""

import struct
import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs

GRID_SIZE = 101
CELL_SIZE = 0x1E0
FIELD = 0x14

def main():
    exe_path = r"D:\SteamLibrary\steamapps\common\HROT\HROT.exe"
    pe = pefile.PE(exe_path)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    data = pe.__data__
    md = Cs(CS_ARCH_X86, CS_MODE_32)

    # Strategy: search for code that accesses [reg+0x14] in a loop
    # where the register is incremented by CELL_SIZE (0x1E0)
    #
    # Common Delphi patterns for grid init:
    #   mov eax, [grid_base]
    #   mov ecx, 10201  (grid cell count)
    # loop:
    #   mov dword [eax+0x14], <value>
    #   add eax, 0x1E0
    #   dec ecx
    #   jnz loop

    print("Searching for grid initialization loops that write to +0x14...")
    print()

    for section in pe.sections:
        if not section.Characteristics & 0x20000000:
            continue
        section_data = section.get_data()
        section_va = image_base + section.VirtualAddress

        instructions = list(md.disasm(section_data, section_va))
        for idx, ins in enumerate(instructions):
            # Look for: mov [reg+0x14], imm32 or mov [reg+0x14], reg
            if ins.mnemonic != "mov":
                continue
            if "+0x14]" not in ins.op_str:
                continue
            parts = ins.op_str.split(", ")
            if len(parts) != 2:
                continue
            dst, src = parts
            if "+0x14]" not in dst:
                continue

            # Check for nearby add reg, 0x1E0 (cell stride)
            for ctx in instructions[max(0,idx-8):min(len(instructions),idx+8)]:
                if ctx.mnemonic == "add" and "0x1e0" in ctx.op_str.lower():
                    print(f"=== Found at 0x{ins.address:08X}: {ins.mnemonic} {ins.op_str} ===")
                    for show in instructions[max(0,idx-6):min(len(instructions),idx+8)]:
                        marker = " >>" if show.address == ins.address else "   "
                        print(f"  {marker} {show.address:08X}  {show.mnemonic:8} {show.op_str}")
                    print()
                    break

    # Also search for: mov dword [eax+disp], imm where disp % 0x1E0 == 0x14
    # with a loop counter (ecx/edx) being decremented
    print("Searching for loop patterns with cell-stride writes to +0x14...")
    print()

    for section in pe.sections:
        if not section.Characteristics & 0x20000000:
            continue
        section_data = section.get_data()
        section_va = image_base + section.VirtualAddress

        instructions = list(md.disasm(section_data, section_va))
        for idx, ins in enumerate(instructions):
            # Look for dec ecx / dec edx followed by jnz
            if ins.mnemonic in ("dec", "sub") and "ecx" in ins.op_str:
                # Check if next instruction is jnz
                if idx + 1 < len(instructions) and instructions[idx + 1].mnemonic in ("jnz", "jne"):
                    # Check if there's a write to [reg+0x14] within 6 instructions before
                    for back in range(max(0, idx - 6), idx):
                        b_ins = instructions[back]
                        if b_ins.mnemonic == "mov" and "+0x14]" in b_ins.op_str:
                            print(f"=== Loop at 0x{ins.address:08X} (dec+jnz) with +0x14 write at 0x{b_ins.address:08X} ===")
                            for show in instructions[max(0,idx-8):min(len(instructions),idx+3)]:
                                marker = " >>" if show.address in (ins.address, b_ins.address) else "   "
                                print(f"  {marker} {show.address:08X}  {show.mnemonic:8} {show.op_str}")
                            print()
                            break

if __name__ == "__main__":
    main()
