#!/usr/bin/env python3
"""Find writes to byte_06 (offset 0x06) that set it to 0."""

import struct
import pefile

GRID_SIZE = 101
CELL_SIZE = 0x1E0
TOTAL = GRID_SIZE * GRID_SIZE * CELL_SIZE

# Cells where byte_06 differs
DIFF_CELLS = set()
for y in range(GRID_SIZE):
    for x in range(GRID_SIZE):
        # From the diff output: (88,28), (90,28), (91,28), (88,29), (90,29), (91,29),
        # (85,30), (86,30), (87,30), (88,30), ...
        # These are around x=85-91, y=28-30
        if 84 <= x <= 92 and 27 <= y <= 31:
            DIFF_CELLS.add((x, y))

def main():
    exe_path = r"D:\SteamLibrary\steamapps\common\HROT\HROT.exe"
    pe = pefile.PE(exe_path)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    data = pe.__data__

    # Map 1 world constructor
    start_va, end_va = 0x0054595C, 0x00596EF0

    start_off = None
    end_off = None
    for s in pe.sections:
        s_len = max(s.Misc_VirtualSize, s.SizeOfRawData)
        s_rva = s.VirtualAddress
        if s_rva <= (start_va - image_base) < s_rva + s_len:
            start_off = s.PointerToRawData + (start_va - image_base) - s_rva
        if s_rva <= (end_va - image_base) < s_rva + s_len:
            end_off = s.PointerToRawData + (end_va - image_base) - s_rva

    print(f"Constructor: 0x{start_va:08X}-0x{end_va:08X}")
    print(f"File offset: 0x{start_off:X}-0x{end_off:X}")
    print(f"Difference cells: {sorted(DIFF_CELLS)}")
    print()

    # Search for all writes to byte_06 (disp % CELL_SIZE == 0x06) that write 0
    found = 0
    for i in range(start_off, end_off):
        # mov byte ptr [eax+disp32], imm8
        if i + 7 <= end_off and data[i] == 0xC6 and data[i + 1] == 0x80:
            disp = struct.unpack_from('<i', data, i + 2)[0]
            if 0 <= disp and disp + 1 <= TOTAL and disp % CELL_SIZE == 0x06:
                imm = data[i + 6]
                cell_idx = disp // CELL_SIZE
                x = cell_idx % GRID_SIZE
                y = cell_idx // GRID_SIZE
                marker = " <-- DIFF CELL" if (x, y) in DIFF_CELLS else ""
                print(f"  mov byte [eax+0x{disp:X}], 0x{imm:02X}  cell=({x},{y}){marker}")
                found += 1

        # mov [eax+disp32], edx (treated as 0)
        if i + 6 <= end_off and data[i] == 0x89 and data[i + 1] == 0x90:
            disp = struct.unpack_from('<i', data, i + 2)[0]
            if 0 <= disp and disp + 1 <= TOTAL and disp % CELL_SIZE == 0x06:
                cell_idx = disp // CELL_SIZE
                x = cell_idx % GRID_SIZE
                y = cell_idx // GRID_SIZE
                marker = " <-- DIFF CELL" if (x, y) in DIFF_CELLS else ""
                print(f"  mov [eax+0x{disp:X}], edx (=0)  cell=({x},{y}){marker}")
                found += 1

    print(f"\nTotal writes to byte_06: {found}")

    # Check if the diff cells are covered by any write
    covered = set()
    for i in range(start_off, end_off):
        if i + 7 <= end_off and data[i] == 0xC6 and data[i + 1] == 0x80:
            disp = struct.unpack_from('<i', data, i + 2)[0]
            if 0 <= disp and disp + 1 <= TOTAL and disp % CELL_SIZE == 0x06:
                cell_idx = disp // CELL_SIZE
                x = cell_idx % GRID_SIZE
                y = cell_idx // GRID_SIZE
                covered.add((x, y))

    uncovered = DIFF_CELLS - covered
    if uncovered:
        print(f"\nDiff cells NOT covered by any write to byte_06:")
        for x, y in sorted(uncovered):
            print(f"  ({x},{y})")
    else:
        print(f"\nAll diff cells have writes to byte_06")

if __name__ == "__main__":
    main()
