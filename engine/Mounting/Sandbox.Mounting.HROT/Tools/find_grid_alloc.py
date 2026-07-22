#!/usr/bin/env python3
"""Find the grid allocation and initialization code by tracing the grid base pointer."""

import struct
import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs

def main():
    exe_path = r"D:\SteamLibrary\steamapps\common\HROT\HROT.exe"
    pe = pefile.PE(exe_path)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    data = pe.__data__
    md = Cs(CS_ARCH_X86, CS_MODE_32)

    # Grid base pointer: 0xDE8248 (in .DATA section)
    # Grid base RVA = 0xDE8248 - image_base
    grid_ptr_va = 0xDE8248
    grid_ptr_rva = grid_ptr_va - image_base

    print(f"Grid base pointer: VA=0x{grid_ptr_va:08X} RVA=0x{grid_ptr_rva:08X}")

    # Find which section has this pointer
    for s in pe.sections:
        s_len = max(s.Misc_VirtualSize, s.SizeOfRawData)
        if s.VirtualAddress <= grid_ptr_rva < s.VirtualAddress + s_len:
            off = s.PointerToRawData + grid_ptr_rva - s.VirtualAddress
            grid_ptr_bytes = data[off:off+4]
            grid_ptr_val = struct.unpack_from('<I', grid_ptr_bytes)[0]
            print(f"  Grid base value: 0x{grid_ptr_val:08X}")
            break

    # Now search for code that:
    # 1. Allocates the grid (calls VirtualAlloc, HeapAlloc, or New)
    # 2. Stores the result at 0xDE8248
    # 3. Initializes the grid with default values

    print("\nSearching for code that writes to grid pointer 0xDE8248...")
    print("(This is where the grid is allocated/initialized)")
    print()

    for section in pe.sections:
        if not (section.Characteristics & 0x20000000):
            continue
        section_data = section.get_data()
        section_va = image_base + section.VirtualAddress

        instructions = list(md.disasm(section_data, section_va))
        for idx, ins in enumerate(instructions):
            # Look for: mov [0xDE8248], eax  (store allocated grid pointer)
            if ins.mnemonic == "mov" and "0xde8248" in ins.op_str.lower():
                parts = ins.op_str.split(", ")
                if len(parts) == 2 and "0xde8248" in parts[0].lower():
                    print(f"=== Grid pointer store at 0x{ins.address:08X} ===")
                    for show in instructions[max(0,idx-15):min(len(instructions),idx+20)]:
                        marker = " >>" if show.address == ins.address else "   "
                        print(f"  {marker} {show.address:08X}  {show.mnemonic:8} {show.op_str}")
                    print()

    # Also look for: mov dword ptr [eax+0x14], ... in the initialization context
    # The grid might be initialized with a loop that writes to ALL fields
    print("Searching for initialization that writes floor_height_init (0x14)...")
    print()

    # Search for: fld tbyte ptr [constant] / fstp dword ptr [reg+0x14]
    # This is how Delphi would initialize a float field
    for section in pe.sections:
        if not (section.Characteristics & 0x20000000):
            continue
        section_data = section.get_data()
        section_va = image_base + section.VirtualAddress

        instructions = list(md.disasm(section_data, section_va))
        for idx, ins in enumerate(instructions):
            # fstp dword ptr [reg+0x14] - store float to field 0x14
            if ins.mnemonic == "fstp" and "+0x14]" in ins.op_str:
                print(f"=== fstp to +0x14 at 0x{ins.address:08X} ===")
                for show in instructions[max(0,idx-5):min(len(instructions),idx+5)]:
                    marker = " >>" if show.address == ins.address else "   "
                    print(f"  {marker} {show.address:08X}  {show.mnemonic:8} {show.op_str}")
                print()

            # Also look for any write to +0x14 in a loop context
            if ins.mnemonic in ("mov", "fstp") and "+0x14]" in ins.op_str:
                parts = ins.op_str.split(", ")
                if len(parts) == 2 and "+0x14]" in parts[0]:
                    # Check for nearby loop instructions
                    for ctx in instructions[max(0,idx-10):min(len(instructions),idx+5)]:
                        if ctx.mnemonic in ("loop", "jnz", "jne", "dec"):
                            print(f"=== Loop write to +0x14 at 0x{ins.address:08X} ===")
                            for show in instructions[max(0,idx-8):min(len(instructions),idx+5)]:
                                marker = " >>" if show.address == ins.address else "   "
                                print(f"  {marker} {show.address:08X}  {show.mnemonic:8} {show.op_str}")
                            print()
                            break

if __name__ == "__main__":
    main()
