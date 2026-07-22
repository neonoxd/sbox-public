#!/usr/bin/env python3
"""Inventory low explicit walls with an unfilled span to an explicit ceiling."""

from __future__ import annotations

import collections
import struct
import sys

import pefile

from dump_map_cells import CELL_SIZE, GRID_SIZE, is_world_field
from hrot_world_ranges import WORLD_RANGES



FACES = (
    ("E", 0x3C, 0x44, 0x7C),
    ("W", 0x4C, 0x54, 0xD0),
    ("S", 0x5C, 0x64, 0x124),
    ("N", 0x6C, 0x74, 0x178),
)


def reconstruct(pe: pefile.PE, map_id: int) -> bytearray:
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
    return grid


def main() -> None:
    pe = pefile.PE(sys.argv[1])
    for map_id in WORLD_RANGES:
        grid = reconstruct(pe, map_id)
        hits = []
        materials = collections.Counter()
        stair_hits = []
        covered_stair_side_hits = []
        for y in range(GRID_SIZE):
            for x in range(GRID_SIZE):
                offset = (y * GRID_SIZE + x) * CELL_SIZE
                if not grid[offset + 0x34] or not grid[offset + 0x24]:
                    continue
                ceiling = struct.unpack_from("<f", grid, offset + 0x28)[0]
                wall_base = struct.unpack("<b", bytes([grid[offset + 0x1D5]]))[0] * 1.5625
                for name, material, active, auxiliary in FACES:
                    if not grid[offset + active] or grid[offset + auxiliary]:
                        continue
                    if ceiling <= wall_base + 1.5625 + 0.01:
                        continue
                    atlas = struct.unpack_from("<ii", grid, offset + material)
                    hits.append((x, y, name, ceiling - wall_base - 1.5625, atlas))
                    materials[atlas] += 1
                    if grid[offset + 0x1D6] in range(1, 5):
                        stair_hits.append(hits[-1])
                        direction = grid[offset + 0x1D6]
                        is_side = (
                            direction in (1, 2) and name in ("S", "N")
                        ) or (
                            direction in (3, 4) and name in ("E", "W")
                        )
                        gap = ceiling - wall_base - 1.5625
                        is_partial_band = abs(gap / 1.5625 - round(gap / 1.5625)) > 0.03
                        if is_side and is_partial_band:
                            covered_stair_side_hits.append(hits[-1])
        if hits:
            print(
                f"map {map_id:02}: {len(hits)} gaps, "
                f"{len(stair_hits)} on stair cells, "
                f"{len(covered_stair_side_hits)} partial side panels, "
                f"materials={materials.most_common(8)}"
            )
            if map_id == 1:
                for hit in covered_stair_side_hits:
                    print(" ", hit)


if __name__ == "__main__":
    main()
