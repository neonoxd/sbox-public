#!/usr/bin/env python3
"""Dump raw argument values for specific doors."""

import struct
import sys
import pefile

DOOR_HELPER = 0x00D77C20


def pushed_values(data, call, count):
    for candidate in range(call, max(-1, call - 25), -1):
        cursor = candidate
        result = [0] * count
        for argument in range(count - 1, -1, -1):
            if cursor >= 5 and data[cursor - 5] == 0x68:
                result[argument] = struct.unpack_from("<I", data, cursor - 4)[0]
                cursor -= 5
            elif cursor >= 2 and data[cursor - 2] == 0x6A:
                result[argument] = struct.unpack_from("<b", data, cursor - 1)[0] & 0xFFFFFFFF
                cursor -= 2
            else:
                break
        else:
            return result
    return None


def main():
    pe = pefile.PE(sys.argv[1])
    image = pe.OPTIONAL_HEADER.ImageBase

    # Search in a wide range to find all door calls
    start_va = int(sys.argv[2], 0)
    end_va = int(sys.argv[3], 0)
    start = pe.get_offset_from_rva(start_va - image)
    end = pe.get_offset_from_rva(end_va - image)
    data = pe.__data__

    for i in range(start, end - 4):
        if data[i] != 0xE8:
            continue
        call_va = image + pe.get_rva_from_offset(i)
        target = call_va + 5 + struct.unpack_from("<i", data, i + 1)[0]
        if target != DOOR_HELPER:
            continue

        args = pushed_values(data, i, 17)
        if args is None:
            continue

        floats = [struct.unpack("<f", struct.pack("<I", v & 0xFFFFFFFF))[0]
                  for v in args]

        x, vertical, z = floats[2], floats[1], floats[0]
        travelX, travelVertical, travelZ = floats[5], floats[4], floats[3]

        print(f"\n=== VA=0x{call_va:08X} ===")
        print(f"  pos=({x:.4g}, {vertical:.4g}, {z:.4g})")
        print(f"  travel=({travelX:.4g}, {travelVertical:.4g}, {travelZ:.4g})")
        for idx in range(17):
            fval = floats[idx]
            ival = args[idx]
            print(f"  args[{idx:2d}] = 0x{ival:08X} ({ival:6d}) float={fval:.6g}")


if __name__ == "__main__":
    main()
