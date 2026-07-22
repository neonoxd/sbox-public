#!/usr/bin/env python3
"""Find ALL code that writes to grid field 0x14 (displacement % 0x1E0 == 0x14)."""

import struct
import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs

CELL_SIZE = 0x1E0
TARGET_FIELD = 0x14

def main():
    exe_path = r"D:\SteamLibrary\steamapps\common\HROT\HROT.exe"
    pe = pefile.PE(exe_path)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    data = pe.__data__
    md = Cs(CS_ARCH_X86, CS_MODE_32)

    total = 101 * 101 * CELL_SIZE  # 3,091,620

    print("Scanning ALL code sections for writes to grid field 0x14...")
    print(f"Looking for displacements where disp % 0x1E0 == 0x{TARGET_FIELD:03X}")
    print()

    found = 0
    for section in pe.sections:
        if not (section.Characteristics & 0x20000000):  # EXECUTE
            continue
        section_data = section.get_data()
        section_va = image_base + section.VirtualAddress
        name = section.Name.decode(errors='replace').rstrip('\0')

        instructions = list(md.disasm(section_data, section_va))
        for idx, ins in enumerate(instructions):
            # mov byte/dword ptr [reg+disp32], imm/reg
            if ins.mnemonic != "mov":
                continue

            op_str = ins.op_str
            # Check for memory destination with a displacement
            if "+0x" not in op_str:
                continue

            parts = op_str.split(", ")
            if len(parts) != 2:
                continue
            dst = parts[0]

            # Extract displacement
            try:
                # Handle formats like "dword ptr [eax + 0x12345]"
                bracket_content = dst.split("[")[1].split("]")[0]
                if "+" in bracket_content:
                    disp_str = bracket_content.split("+")[-1].strip()
                    disp = int(disp_str, 16)
                else:
                    continue
            except (IndexError, ValueError):
                continue

            if disp < 0 or disp >= total:
                continue

            if disp % CELL_SIZE != TARGET_FIELD:
                continue

            # This writes to grid field 0x14! Print context
            cell_idx = disp // CELL_SIZE
            x = cell_idx % 101
            y = cell_idx // 101

            # Check what value is being written
            src = parts[1]
            value_str = ""
            if "0x" in src:
                try:
                    v = int(src, 16)
                    if v < 1000:
                        value_str = f"  (imm={v})"
                    else:
                        fv = struct.unpack("<f", struct.pack("<I", v))[0]
                        value_str = f"  (imm={v:#010x} = {fv:.6f})"
                except ValueError:
                    pass

            print(f"  [{name}] 0x{ins.address:08X}: {ins.mnemonic} {op_str}  cell=({x},{y}){value_str}")

            # Print 3 instructions before for context
            for back in range(max(0, idx-3), idx):
                b = instructions[back]
                print(f"    {b.address:08X}  {b.mnemonic:8} {b.op_str}")
            print()
            found += 1

    print(f"Total writes to field 0x{TARGET_FIELD:03X}: {found}")

if __name__ == "__main__":
    main()
