#!/usr/bin/env python3
"""Trace raw argument values for specific door calls."""

import struct
import sys
import pefile

DOOR_HELPER = 0x00D77C20


def main():
    pe = pefile.PE(sys.argv[1])
    start_va = int(sys.argv[2], 0)
    end_va = int(sys.argv[3], 0)
    image = pe.OPTIONAL_HEADER.ImageBase
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

        args = None
        for candidate in range(i, max(-1, i - 25), -1):
            cursor = candidate
            result = [0] * 17
            valid = True
            for argument in range(16, -1, -1):
                if cursor >= 5 and data[cursor - 5] == 0x68:
                    result[argument] = struct.unpack_from(
                        "<I", data, cursor - 4
                    )[0]
                    cursor -= 5
                elif cursor >= 2 and data[cursor - 2] == 0x6A:
                    result[argument] = (
                        struct.unpack_from("<b", data, cursor - 1)[0]
                        & 0xFFFFFFFF
                    )
                    cursor -= 2
                else:
                    valid = False
                    break
            if valid:
                args = result
                break

        if args is None:
            continue

        floats = [
            struct.unpack("<f", struct.pack("<I", v & 0xFFFFFFFF))[0]
            for v in args
        ]

        x, vertical, z = floats[2], floats[1], floats[0]
        travelX, travelVertical, travelZ = floats[5], floats[4], floats[3]

        # Print ALL raw argument values for this door
        print(f"\n=== VA=0x{call_va:08X} ===")
        print(f"  pos=({x}, {vertical}, {z})")
        print(f"  travel=({travelX}, {travelVertical}, {travelZ})")
        for idx in range(17):
            fval = floats[idx]
            ival = args[idx]
            print(
                f"  arguments[{idx:2d}] = 0x{ival:08X} ({ival:5d}) float={fval:.6g}"
            )


if __name__ == "__main__":
    main()
