#!/usr/bin/env python3
"""Check if the grid is pre-initialized in the PE data section."""

import struct
import pefile

GRID_SIZE = 101
CELL_SIZE = 0x1E0
GRID_SIZE_BYTES = GRID_SIZE * GRID_SIZE * CELL_SIZE

def main():
    exe_path = r"D:\SteamLibrary\steamapps\common\HROT\HROT.exe"
    pe = pefile.PE(exe_path)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    data = pe.__data__

    # The grid base pointer is at 0xDE8248 (VA)
    # This is a pointer TO the grid, stored in the .data section
    # Let's find what it points to

    grid_ptr_va = 0xDE8248
    grid_ptr_rva = grid_ptr_va - image_base

    print(f"Grid pointer VA: 0x{grid_ptr_va:08X}")
    print(f"Grid pointer RVA: 0x{grid_ptr_rva:08X}")

    # Find which section contains this RVA
    for s in pe.sections:
        s_len = max(s.Misc_VirtualSize, s.SizeOfRawData)
        if s.VirtualAddress <= grid_ptr_rva < s.VirtualAddress + s_len:
            off = s.PointerToRawData + grid_ptr_rva - s.VirtualAddress
            ptr_bytes = data[off:off+4]
            ptr_val = struct.unpack_from('<I', ptr_bytes)[0]
            print(f"  In section: {s.Name.decode(errors='replace').rstrip(chr(0))}")
            print(f"  Pointer value: 0x{ptr_val:08X}")

            # The pointer points to the grid. Convert to file offset
            grid_rva = ptr_val - image_base
            for s2 in pe.sections:
                s2_len = max(s2.Misc_VirtualSize, s2.SizeOfRawData)
                if s2.VirtualAddress <= grid_rva < s2.VirtualAddress + s2_len:
                    grid_off = s2.PointerToRawData + grid_rva - s2.VirtualAddress
                    print(f"  Grid in section: {s2.Name.decode(errors='replace').rstrip(chr(0))}")
                    print(f"  Grid file offset: 0x{grid_off:X}")

                    # Read first cell from the PE file
                    cell_data = data[grid_off:grid_off + CELL_SIZE]
                    print(f"\n  First cell in PE (offset 0x00-0x{CELL_SIZE:X}):")
                    print(f"    +0x06 = {cell_data[0x06]}")
                    print(f"    +0x14 = {struct.unpack_from('<f', cell_data, 0x14)[0]:.6f} ({struct.unpack_from('<I', cell_data, 0x14)[0]:#010x})")
                    print(f"    +0x28 = {struct.unpack_from('<f', cell_data, 0x28)[0]:.6f}")
                    print(f"    +0x38 = {struct.unpack_from('<f', cell_data, 0x38)[0]:.6f}")

                    # Check if the grid data looks initialized (not all zeros)
                    non_zero = sum(1 for b in cell_data if b != 0)
                    print(f"    Non-zero bytes in cell: {non_zero}/{CELL_SIZE}")

                    # Check several cells
                    print(f"\n  Sampling cells from PE:")
                    for cell_idx in [0, 1, 100, 500, 1000, 5000, 10000]:
                        c_off = grid_off + cell_idx * CELL_SIZE
                        if c_off + CELL_SIZE > len(data):
                            break
                        c = data[c_off:c_off + CELL_SIZE]
                        v14 = struct.unpack_from('<f', c, 0x14)[0]
                        v28 = struct.unpack_from('<f', c, 0x28)[0]
                        v38 = struct.unpack_from('<f', c, 0x38)[0]
                        x = cell_idx % GRID_SIZE
                        y = cell_idx // GRID_SIZE
                        print(f"    cell({x:3d},{y:3d}): +0x14={v14:10.4f} +0x28={v28:10.4f} +0x38={v38:10.4f}")

                    break
            break

    # Also check: what is the grid pointer's section characteristics?
    print("\n--- Checking section flags ---")
    for s in pe.sections:
        name = s.Name.decode(errors='replace').rstrip(chr(0))
        chars = s.Characteristics
        flags = []
        if chars & 0x00000020: flags.append("CODE")
        if chars & 0x00000040: flags.append("INITIALIZED_DATA")
        if chars & 0x00000080: flags.append("UNINITIALIZED_DATA")
        if chars & 0x20000000: flags.append("EXECUTE")
        if chars & 0x40000000: flags.append("READ")
        if chars & 0x80000000: flags.append("WRITE")
        print(f"  {name:8s} VA=0x{s.VirtualAddress:08X} Size=0x{s.Misc_VirtualSize:08X} Raw=0x{s.SizeOfRawData:08X} [{', '.join(flags)}]")

if __name__ == "__main__":
    main()
