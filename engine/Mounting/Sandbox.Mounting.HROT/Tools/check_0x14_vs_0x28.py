#!/usr/bin/env python3
"""Check if field 0x14 matches ceiling height (0x28) and if it's written via fstp."""

import struct

CELL_SIZE = 0x1E0
GRID_SIZE = 101

def main():
    live_path = r"C:\dev\pub\sbox-public\engine\Mounting\Sandbox.Mounting.HROT\Tools\hrot_dump\grid_live_map01.bin"

    HEADER_SIZE = 22
    with open(live_path, "rb") as f:
        f.read(HEADER_SIZE)
        live = f.read()

    # Check: is 0x14 == 0x28 (ceiling height)?
    print("Checking if field 0x14 equals ceiling height (0x28):")
    match = 0
    mismatch = 0
    for y in range(GRID_SIZE):
        for x in range(GRID_SIZE):
            off = (y * GRID_SIZE + x) * CELL_SIZE
            v14 = struct.unpack_from('<f', live, off + 0x14)[0]
            v28 = struct.unpack_from('<f', live, off + 0x28)[0]
            if abs(v14 - (-2000.0)) < 0.001 and abs(v28 - 1.5625) < 0.001:
                continue  # both default
            if abs(v14 - v28) < 0.001:
                match += 1
            else:
                mismatch += 1
                if mismatch <= 10:
                    print(f"  DIFF ({x},{y}): 0x14={v14:.4f} 0x28={v28:.4f}")

    print(f"  0x14 == 0x28: {match}")
    print(f"  0x14 != 0x28: {mismatch}")

    # Now check if any cell has 0x14 == 0x28 AND 0x14 != -2000.0
    print("\nCells where 0x14 matches ceiling height and is not sentinel:")
    count = 0
    for y in range(GRID_SIZE):
        for x in range(GRID_SIZE):
            off = (y * GRID_SIZE + x) * CELL_SIZE
            v14 = struct.unpack_from('<f', live, off + 0x14)[0]
            v28 = struct.unpack_from('<f', live, off + 0x28)[0]
            if abs(v14 - (-2000.0)) < 0.001:
                continue
            if abs(v14 - v28) < 0.001:
                count += 1
                if count <= 5:
                    v38 = struct.unpack_from('<f', live, off + 0x38)[0]
                    print(f"  ({x:3d},{y:3d}) 0x14={v14:10.4f} == 0x28={v28:10.4f}  0x38={v38:10.4f}")
    print(f"  Total: {count}")

    # Also check: are there cells where 0x14 != 0x28 and 0x14 != -2000.0?
    print("\nCells where 0x14 does NOT match ceiling height:")
    count = 0
    for y in range(GRID_SIZE):
        for x in range(GRID_SIZE):
            off = (y * GRID_SIZE + x) * CELL_SIZE
            v14 = struct.unpack_from('<f', live, off + 0x14)[0]
            v28 = struct.unpack_from('<f', live, off + 0x28)[0]
            if abs(v14 - (-2000.0)) < 0.001:
                continue
            if abs(v14 - v28) > 0.001:
                count += 1
                if count <= 10:
                    v38 = struct.unpack_from('<f', live, off + 0x38)[0]
                    print(f"  ({x:3d},{y:3d}) 0x14={v14:10.4f} 0x28={v28:10.4f} 0x38={v38:10.4f}")
    print(f"  Total: {count}")

if __name__ == "__main__":
    main()
