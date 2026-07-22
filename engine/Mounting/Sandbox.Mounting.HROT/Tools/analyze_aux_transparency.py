#!/usr/bin/env python3
"""Inventory inactive auxiliary walls whose final band changes material."""

from __future__ import annotations

import struct
import sys

import pefile

from analyze_upper_wall_gaps import FACES, WORLD_RANGES, reconstruct
from dump_map_cells import CELL_SIZE, GRID_SIZE


def main() -> None:
    pe = pefile.PE(sys.argv[1])
    for map_id in WORLD_RANGES:
        grid = reconstruct(pe, map_id)
        hits = []
        for y in range(GRID_SIZE):
            for x in range(GRID_SIZE):
                offset = (y * GRID_SIZE + x) * CELL_SIZE
                for name, _, active, auxiliary in FACES:
                    count = grid[offset + auxiliary]
                    if grid[offset + active] or count < 2 or count > 10:
                        continue
                    previous = struct.unpack_from(
                        "<ii", grid, offset + auxiliary + 4 + (count - 2) * 8
                    )
                    final = struct.unpack_from(
                        "<ii", grid, offset + auxiliary + 4 + (count - 1) * 8
                    )
                    if previous != final:
                        hits.append((x, y, name, count, previous, final))
        if hits:
            print(f"map {map_id:02}: {len(hits)} candidates")
            for hit in hits[:30]:
                print(" ", hit)


if __name__ == "__main__":
    main()
