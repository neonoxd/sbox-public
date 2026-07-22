#!/usr/bin/env python3
"""Check if field 0x14 is a Delphi runtime artifact by examining cell structure."""

import struct
import pefile

CELL_SIZE = 0x1E0
GRID_SIZE = 101

def main():
    live_path = r"C:\dev\pub\sbox-public\engine\Mounting\Sandbox.Mounting.HROT\Tools\hrot_dump\grid_live_map01.bin"
    recon_path = r"C:\dev\pub\sbox-public\engine\Mounting\Sandbox.Mounting.HROT\Tools\hrot_dump\grid_reconstructed_map01.bin"

    HEADER_SIZE = 22
    with open(live_path, "rb") as f:
        f.read(HEADER_SIZE)
        live = f.read()
    with open(recon_path, "rb") as f:
        f.read(HEADER_SIZE)
        recon = f.read()

    # For each cell with non-sentinel 0x14, check what other fields look like
    print("Cells with non-sentinel field 0x14 (showing first 20):")
    print(f"{'cell':>10s}  {'0x14':>10s}  {'0x28 ceil':>10s}  {'0x38 floor':>10s}  {'0x34 f_on':>5s}  {'0x24 c_on':>5s}  {'0x06':>5s}  {'0x1D5 base':>10s}")
    count = 0
    for y in range(GRID_SIZE):
        for x in range(GRID_SIZE):
            off = (y * GRID_SIZE + x) * CELL_SIZE
            v14 = struct.unpack_from('<f', live, off + 0x14)[0]
            if abs(v14 - (-2000.0)) < 0.001:
                continue
            v28 = struct.unpack_from('<f', live, off + 0x28)[0]
            v38 = struct.unpack_from('<f', live, off + 0x38)[0]
            b34 = live[off + 0x34]
            b24 = live[off + 0x24]
            b06 = live[off + 0x06]
            b1d5 = struct.unpack('b', bytes([live[off + 0x1D5]]))[0]
            print(f"  ({x:3d},{y:3d})  {v14:10.4f}  {v28:10.4f}  {v38:10.4f}  {b34:5d}  {b24:5d}  {b06:5d}  {b1d5*1.5625:10.4f}")
            count += 1
            if count >= 20:
                break
        if count >= 20:
            break

    # Check: is 0x14 always a multiple of 1.5625?
    print("\nChecking if field 0x14 values are multiples of 1.5625:")
    multiples = 0
    non_multiples = 0
    for y in range(GRID_SIZE):
        for x in range(GRID_SIZE):
            off = (y * GRID_SIZE + x) * CELL_SIZE
            v14 = struct.unpack_from('<f', live, off + 0x14)[0]
            if abs(v14 - (-2000.0)) < 0.001:
                continue
            ratio = v14 / 1.5625
            if abs(ratio - round(ratio)) < 0.01:
                multiples += 1
            else:
                non_multiples += 1
                if non_multiples <= 5:
                    print(f"  NOT multiple: ({x},{y}) v14={v14:.6f} ratio={ratio:.4f}")
    print(f"  Multiples of 1.5625: {multiples}")
    print(f"  Non-multiples: {non_multiples}")

    # Check: does 0x14 correlate with 0x38 (floor height)?
    print("\nCorrelation between 0x14 and 0x38:")
    same = 0
    diff = 0
    for y in range(GRID_SIZE):
        for x in range(GRID_SIZE):
            off = (y * GRID_SIZE + x) * CELL_SIZE
            v14 = struct.unpack_from('<f', live, off + 0x14)[0]
            v38 = struct.unpack_from('<f', live, off + 0x38)[0]
            if abs(v14 - (-2000.0)) < 0.001 and abs(v38) < 0.001:
                continue  # both default
            if abs(v14 - v38) < 0.001:
                same += 1
            else:
                diff += 1
                if diff <= 10:
                    print(f"  DIFF ({x},{y}): 0x14={v14:.4f} 0x38={v38:.4f}")
    print(f"  Same: {same}, Different: {diff}")

    # Check: is 0x14 the same in live and recon for cells where recon wrote to 0x38?
    print("\nReconstruction 0x38 vs live 0x14 (checking if recon writes floor to wrong field):")
    match = 0
    mismatch = 0
    for y in range(GRID_SIZE):
        for x in range(GRID_SIZE):
            off = (y * GRID_SIZE + x) * CELL_SIZE
            r38 = struct.unpack_from('<f', recon, off + 0x38)[0]
            l14 = struct.unpack_from('<f', live, off + 0x14)[0]
            if abs(r38) < 0.001 and abs(l14 - (-2000.0)) < 0.001:
                continue  # both default
            if abs(r38 - l14) < 0.001:
                match += 1
            else:
                mismatch += 1
                if mismatch <= 5:
                    print(f"  MISMATCH ({x},{y}): recon_0x38={r38:.4f} live_0x14={l14:.4f}")
    print(f"  recon_0x38 == live_0x14: {match}")
    print(f"  recon_0x38 != live_0x14: {mismatch}")

if __name__ == "__main__":
    main()
