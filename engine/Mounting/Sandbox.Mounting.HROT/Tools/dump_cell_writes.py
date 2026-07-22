#!/usr/bin/env python3
"""List every constant executable write targeting selected HROT map cells."""

from __future__ import annotations

import struct
import sys

import pefile

from dump_map_cells import CELL_SIZE, GRID_SIZE, WORLD_RANGES


def main() -> None:
    pe = pefile.PE(sys.argv[1])
    map_id = int(sys.argv[2])
    selected = {
        (int(value.split(",")[0]), int(value.split(",")[1]))
        for value in sys.argv[3:]
    }
    image = pe.OPTIONAL_HEADER.ImageBase
    start, end = WORLD_RANGES[map_id]
    code = pe.get_data(start - image, end - start)

    for index in range(len(code)):
        width = 0
        value = b""
        if code[index:index + 2] == b"\xc6\x80" and index + 7 <= len(code):
            displacement = struct.unpack_from("<i", code, index + 2)[0]
            width = 1
            value = code[index + 6:index + 7]
        elif code[index:index + 2] == b"\xc7\x80" and index + 10 <= len(code):
            displacement = struct.unpack_from("<i", code, index + 2)[0]
            width = 4
            value = code[index + 6:index + 10]
        elif code[index:index + 2] == b"\x89\x90" and index + 6 <= len(code):
            displacement = struct.unpack_from("<i", code, index + 2)[0]
            width = 4
            value = b"\0\0\0\0"
        else:
            continue

        if displacement < 0 or displacement >= GRID_SIZE * GRID_SIZE * CELL_SIZE:
            continue
        cell_index, field = divmod(displacement, CELL_SIZE)
        x = cell_index % GRID_SIZE
        y = cell_index // GRID_SIZE
        if (x, y) not in selected:
            continue
        numeric = (
            str(value[0])
            if width == 1
            else f"i={struct.unpack('<i', value)[0]} "
                 f"f={struct.unpack('<f', value)[0]:.7g}"
        )
        print(
            f"cell=({x},{y}) field=0x{field:03X} width={width} "
            f"value={numeric} at={start + index:08X}"
        )


if __name__ == "__main__":
    main()
