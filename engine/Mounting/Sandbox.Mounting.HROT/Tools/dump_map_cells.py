#!/usr/bin/env python3
"""Reconstruct and print selected HROT executable map cells."""

from __future__ import annotations

import struct
import sys

import pefile

from hrot_world_ranges import WORLD_RANGES

GRID_SIZE = 101
CELL_SIZE = 0x1E0


def is_world_field(displacement: int, width: int, length: int) -> bool:
    if displacement < 0 or displacement + width > length:
        return False
    field = displacement % CELL_SIZE
    if field in {
        0x06,
        0x1C, 0x20, 0x24, 0x28, 0x2C, 0x30, 0x34, 0x38,
        0x3C, 0x40, 0x44, 0x48, 0x4C, 0x50, 0x54, 0x58,
        0x5C, 0x60, 0x64, 0x68, 0x6C, 0x70, 0x74, 0x78,
        0x1D5, 0x1D6,
    }:
        return True
    return any(start <= field < start + 0x54 for start in (0x7C, 0xD0, 0x124, 0x178))


def main() -> None:
    pe = pefile.PE(sys.argv[1])
    map_id, center_x, center_y = map(int, sys.argv[2:5])
    radius = int(sys.argv[5]) if len(sys.argv) > 5 else 2
    image = pe.OPTIONAL_HEADER.ImageBase
    start, end = WORLD_RANGES[map_id]
    executable = pe.get_data(start - image, end - start)
    grid = bytearray(GRID_SIZE * GRID_SIZE * CELL_SIZE)
    for cell in range(GRID_SIZE * GRID_SIZE):
        offset = cell * CELL_SIZE
        grid[offset + 6] = 1
        struct.pack_into("<f", grid, offset + 0x28, 1.5625)
        struct.pack_into("<f", grid, offset + 0x14, -2000.0)

    for index in range(len(executable)):
        if executable[index:index + 2] == b"\xc6\x80" and index + 7 <= len(executable):
            displacement = struct.unpack_from("<i", executable, index + 2)[0]
            if is_world_field(displacement, 1, len(grid)):
                grid[displacement] = executable[index + 6]
        elif executable[index:index + 2] == b"\xc7\x80" and index + 10 <= len(executable):
            displacement = struct.unpack_from("<i", executable, index + 2)[0]
            if is_world_field(displacement, 4, len(grid)):
                grid[displacement:displacement + 4] = executable[index + 6:index + 10]
        elif executable[index:index + 2] == b"\x89\x90" and index + 6 <= len(executable):
            displacement = struct.unpack_from("<i", executable, index + 2)[0]
            if is_world_field(displacement, 4, len(grid)):
                grid[displacement:displacement + 4] = b"\0\0\0\0"

    for y in range(center_y - radius, center_y + radius + 1):
        for x in range(center_x - radius, center_x + radius + 1):
            offset = (y * GRID_SIZE + x) * CELL_SIZE
            byte = lambda field: grid[offset + field]
            integer = lambda field: struct.unpack_from("<i", grid, offset + field)[0]
            single = lambda field: struct.unpack_from("<f", grid, offset + field)[0]
            print(
                f"({x:02},{y:02}) floor={byte(0x34)} "
                f"h={single(0x38):7.3f} mat={integer(0x2C)},{integer(0x30)} "
                f"base={struct.unpack('<b', bytes([byte(0x1D5)]))[0] * 1.5625:7.3f} "
                f"ceil={byte(0x24)} ch={single(0x28):7.3f} "
                f"walls=E{byte(0x44)}[{integer(0x3C)},{integer(0x40)};{byte(0x7C)}] "
                f"W{byte(0x54)}[{integer(0x4C)},{integer(0x50)};{byte(0xD0)}] "
                f"S{byte(0x64)}[{integer(0x5C)},{integer(0x60)};{byte(0x124)}] "
                f"N{byte(0x74)}[{integer(0x6C)},{integer(0x70)};{byte(0x178)}] "
                f"stair={byte(0x1D6)}"
            )


if __name__ == "__main__":
    main()
