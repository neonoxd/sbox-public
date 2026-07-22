#!/usr/bin/env python3
"""Dump constant HROT door constructor calls from one map constructor."""

from __future__ import annotations

import struct
import sys

import pefile


DOOR_HELPER = 0x00D77C20


def pushed_values(data: bytes, call: int, count: int) -> list[int] | None:
    for candidate in range(call, max(-1, call - 25), -1):
        cursor = candidate
        result = [0] * count
        for argument in range(count - 1, -1, -1):
            if cursor >= 5 and data[cursor - 5] == 0x68:
                result[argument] = struct.unpack_from("<I", data, cursor - 4)[0]
                cursor -= 5
            elif cursor >= 2 and data[cursor - 2] == 0x6A:
                result[argument] = struct.unpack_from("<b", data, cursor - 1)[0]
                cursor -= 2
            else:
                break
        else:
            return result
    return None


def main() -> None:
    pe = pefile.PE(sys.argv[1])
    start_va = int(sys.argv[2], 0)
    end_va = int(sys.argv[3], 0)
    image = pe.OPTIONAL_HEADER.ImageBase
    start = pe.get_offset_from_rva(start_va - image)
    end = pe.get_offset_from_rva(end_va - image)
    data = pe.__data__

    count = 0
    for call in range(start, end - 4):
        if data[call] != 0xE8:
            continue
        call_va = image + pe.get_rva_from_offset(call)
        target = call_va + 5 + struct.unpack_from("<i", data, call + 1)[0]
        if target != DOOR_HELPER:
            continue
        args = pushed_values(data, call, 17)
        if args is None:
            continue
        floats = [struct.unpack("<f", struct.pack("<I", value & 0xFFFFFFFF))[0]
                  for value in args]
        position = floats[2], floats[1], floats[0]
        travel = floats[5], floats[4], floats[3]
        print(f"{call_va:08X} pos={position} travel={travel} "
              f"material={args[16]} atlas={list(reversed(args[7:11]))}")
        count += 1
    print(f"doors={count}")


if __name__ == "__main__":
    main()
