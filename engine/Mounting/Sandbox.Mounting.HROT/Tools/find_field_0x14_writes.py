#!/usr/bin/env python3
"""Find all writes to a specific field offset in HROT map constructors."""

import struct
import sys
import pefile

from hrot_world_ranges import WORLD_RANGES

GRID_SIZE = 101
CELL_SIZE = 0x1E0
FIELD = 0x14  # offset to search for

def main():
    exe_path = r"D:\SteamLibrary\steamapps\common\HROT\HROT.exe"
    map_id = 1

    start_va, end_va = WORLD_RANGES[map_id]

    pe = pefile.PE(exe_path)
    image_base = pe.OPTIONAL_HEADER.ImageBase

    start_off = None
    end_off = None
    for s in pe.sections:
        s_len = max(s.Misc_VirtualSize, s.SizeOfRawData)
        s_rva = s.VirtualAddress
        if s_rva <= (start_va - image_base) < s_rva + s_len:
            start_off = s.PointerToRawData + (start_va - image_base) - s_rva
        if s_rva <= (end_va - image_base) < s_rva + s_len:
            end_off = s.PointerToRawData + (end_va - image_base) - s_rva

    if start_off is None or end_off is None:
        print("Cannot find constructor range")
        return

    data = pe.__data__
    total = GRID_SIZE * GRID_SIZE * CELL_SIZE

    print(f"Searching constructor 0x{start_va:08X}-0x{end_va:08X} for writes to field 0x{FIELD:03X}")
    print()

    found = 0
    for i in range(start_off, end_off):
        # mov byte ptr [eax+disp32], imm8
        if i + 7 <= end_off and data[i] == 0xC6 and data[i + 1] == 0x80:
            disp = struct.unpack_from('<i', data, i + 2)[0]
            if 0 <= disp and disp + 1 <= total and disp % CELL_SIZE == FIELD:
                imm = data[i + 6]
                cell_idx = disp // CELL_SIZE
                x = cell_idx % GRID_SIZE
                y = cell_idx // GRID_SIZE
                print(f"  mov byte [eax+0x{disp:X}], 0x{imm:02X}  at 0x{image_base + i:08X}  cell=({x},{y})")
                found += 1
            continue

        # mov dword ptr [eax+disp32], imm32
        if i + 10 <= end_off and data[i] == 0xC7 and data[i + 1] == 0x80:
            disp = struct.unpack_from('<i', data, i + 2)[0]
            if 0 <= disp and disp + 4 <= total and disp % CELL_SIZE == FIELD:
                imm = struct.unpack_from('<i', data, i + 6)[0]
                fv = struct.unpack_from('<f', data, i + 6)[0]
                cell_idx = disp // CELL_SIZE
                x = cell_idx % GRID_SIZE
                y = cell_idx // GRID_SIZE
                print(f"  mov dword [eax+0x{disp:X}], 0x{imm:08X} ({fv:.6f})  at 0x{image_base + i:08X}  cell=({x},{y})")
                found += 1
            continue

        # mov [eax+disp32], edx
        if i + 6 <= end_off and data[i] == 0x89 and data[i + 1] == 0x90:
            disp = struct.unpack_from('<i', data, i + 2)[0]
            if 0 <= disp and disp + 4 <= total and disp % CELL_SIZE == FIELD:
                cell_idx = disp // CELL_SIZE
                x = cell_idx % GRID_SIZE
                y = cell_idx // GRID_SIZE
                print(f"  mov [eax+0x{disp:X}], edx (=0)  at 0x{image_base + i:08X}  cell=({x},{y})")
                found += 1

    print(f"\nTotal writes to field 0x{FIELD:03X}: {found}")
    print(f"Expected (live diffs): 1376")

    # Also check what the live grid actually has at this field
    print("\n--- Checking live grid ---")
    live_path = r"C:\dev\pub\sbox-public\engine\Mounting\Sandbox.Mounting.HROT\Tools\hrot_dump\grid_live_map01.bin"
    with open(live_path, "rb") as f:
        f.read(22)  # skip header
        live_grid = f.read()

    # Count unique values at field 0x14
    from collections import Counter
    vals = Counter()
    for cell in range(GRID_SIZE * GRID_SIZE):
        off = cell * CELL_SIZE + FIELD
        v = struct.unpack_from('<f', live_grid, off)[0]
        vals[round(v, 4)] += 1

    print("Unique values at field 0x14 in live grid:")
    for v, count in vals.most_common(20):
        print(f"  {v:12.4f}  ({count} cells)")

    # Check: are the non-sentinel values at 0x14 the same as at 0x38?
    print("\n--- Cross-checking 0x14 vs 0x38 ---")
    match = 0
    mismatch = 0
    for cell in range(GRID_SIZE * GRID_SIZE):
        off = cell * CELL_SIZE
        v14 = struct.unpack_from('<f', live_grid, off + 0x14)[0]
        v38 = struct.unpack_from('<f', live_grid, off + 0x38)[0]
        if abs(v14 - v38) < 0.001:
            match += 1
        elif v14 != -2000.0 or v38 != 0.0:
            mismatch += 1
            if mismatch <= 5:
                x = cell % GRID_SIZE
                y = cell // GRID_SIZE
                print(f"  MISMATCH cell=({x},{y}): 0x14={v14:.4f} 0x38={v38:.4f}")

    print(f"\n0x14 == 0x38: {match} cells")
    print(f"0x14 != 0x38 (excluding sentinels): {mismatch} cells")

if __name__ == "__main__":
    main()
