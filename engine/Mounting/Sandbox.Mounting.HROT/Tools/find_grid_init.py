#!/usr/bin/env python3
"""Search for the grid initialization routine that sets field 0x14."""

import struct
import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs

GRID_SIZE = 101
CELL_SIZE = 0x1E0

def main():
    exe_path = r"D:\SteamLibrary\steamapps\common\HROT\HROT.exe"
    pe = pefile.PE(exe_path)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    data = pe.__data__

    # The grid is 101*101*0x1E0 = 3,091,620 bytes
    # Field 0x14 is at cell offset 0x14
    # We need to find code that writes to [reg+disp] where disp % 0x1E0 == 0x14
    # This is likely a loop that initializes the grid

    # Strategy: look for the grid base address reference
    # In the world constructor, the grid is accessed via [eax+disp32]
    # The grid base is loaded into eax before the constructor body.
    # Let's find what value eax holds.

    # From the world constructor, look at the very beginning to see how eax is loaded
    start_va = 0x0054595C  # map 1 world constructor

    for s in pe.sections:
        s_len = max(s.Misc_VirtualSize, s.SizeOfRawData)
        s_rva = s.VirtualAddress
        if s_rva <= (start_va - image_base) < s_rva + s_len:
            code_off = s.PointerToRawData + (start_va - image_base) - s_rva
            code = data[code_off:code_off + 64]
            break

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    print("Map 1 world constructor prologue:")
    for ins in md.disasm(code, start_va):
        print(f"  {ins.address:08X}  {ins.mnemonic:8} {ins.op_str}")
        if ins.address > start_va + 40:
            break

    # Now search for code that initializes the grid with a loop
    # Looking for: loop that writes to [eax+0x14] or [reg+0x14] with a floor height
    # The initialization likely happens in a routine called before the per-map constructors

    # Search for the address referenced in the constructor prologue
    # The grid base is typically loaded from a global. Let's find globals referenced
    # near the start of the constructor.

    # Also search for any code that writes 0x14 with a computed value
    # (not just constant writes, but loop-based initialization)

    # Let's look for the pattern: the grid base address is a global pointer
    # We can find it by looking for instructions that load from a fixed address
    # into eax before the constructor body

    # Check if there's a common initialization function
    # Search for code that references field 0x14 in a loop context
    print("\nSearching for loop-based grid initialization...")

    # The grid is likely zero-filled by the CRT, then the constructor adds specific values
    # But field 0x14 has real values, so something writes to it

    # Let's look for any code that references 0x14 as a displacement
    # in a context that suggests grid access (loop with cell-sized stride)

    # Search all executable sections for patterns like:
    #   add eax, 0x1E0  (cell stride)
    #   cmp/cmp with grid bounds
    #   writes to [reg+0x14]

    for section in pe.sections:
        if not section.Characteristics & 0x20000000:  # not executable
            continue
        section_data = section.get_data()
        section_va = image_base + section.VirtualAddress

        for i in range(len(section_data) - 20):
            # Look for: mov [reg+0x14], reg  or  mov [reg+0x14], imm
            # in a context where reg is being incremented by 0x1E0

            # Check for add reg, 0x1E0 (cell stride)
            if section_data[i:i+3] == b"\x81\xC0":
                add_val = struct.unpack_from('<i', section_data, i + 3)[0]
                if add_val == CELL_SIZE:
                    # Found a cell-stride add. Check nearby for writes to +0x14
                    window = section_data[max(0,i-32):min(len(section_data),i+32)]
                    for j in range(len(window) - 4):
                        # mov [reg+disp32], reg
                        if window[j] == 0x89 and window[j+1] in (0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87):
                            disp = struct.unpack_from('<i', window, j + 2)[0]
                            if disp % CELL_SIZE == 0x14:
                                va = section_va + i
                                print(f"  Found at 0x{va:08X}: add eax, 0x1E0 with nearby write to +0x{disp:X}")

    # Alternative: search for the grid base global pointer
    # The world constructor loads the grid base from somewhere
    # Let's look for: mov eax, [address] at the start of constructors
    print("\nLooking for grid base load in constructors...")

    # From the map probe, we know the grid base is at 0xDE8248 (from the pattern
    # "mov eax, dword ptr [0xde8248]" in the reconstruction code)
    grid_base_ref = 0xDE8248
    print(f"Grid base reference from map probe: 0x{grid_base_ref:08X}")

    # Search for code that writes to [eax+0x14] where eax = grid base
    # This would be the initialization loop
    print(f"\nSearching for writes to [eax+0x14] (grid+0x14) in all code sections...")

    for section in pe.sections:
        if not section.Characteristics & 0x20000000:
            continue
        section_data = section.get_data()
        section_va = image_base + section.VirtualAddress

        instructions = list(md.disasm(section_data, section_va))
        for idx, ins in enumerate(instructions):
            if ins.mnemonic != "mov":
                continue
            # Check for any [reg+0x14] write
            if "+0x14]" not in ins.op_str:
                continue

            # Check if this is a write (destination is memory)
            parts = ins.op_str.split(", ")
            if len(parts) != 2:
                continue
            dst, src = parts
            if "+0x14]" not in dst:
                continue

            # Print context
            print(f"\n  Found at 0x{ins.address:08X}: {ins.mnemonic} {ins.op_str}")
            for ctx in instructions[max(0,idx-5):min(len(instructions),idx+6)]:
                marker = " >>" if ctx.address == ins.address else "   "
                print(f"  {marker} {ctx.address:08X}  {ctx.mnemonic:8} {ctx.op_str}")

if __name__ == "__main__":
    main()
