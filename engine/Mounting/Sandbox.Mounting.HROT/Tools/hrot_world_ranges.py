#!/usr/bin/env python3
"""The world-constructor address ranges, read from the mount's own table.

Six scripts in this directory need these ranges. They used to each carry a
literal copy, and four of those copies had gone stale at 8 maps while the mount
grew to 32 - so any verification run silently covered a quarter of the game.

Rather than widen four tables, this parses ``HrotExecutableMapData.cs`` and
makes the C# the single source of truth. Adding a map there is now enough.

Usage:
    from hrot_world_ranges import WORLD_RANGES
    start_va, end_va = WORLD_RANGES[map_id]

Run directly to print the table.
"""

from __future__ import annotations

import re
from pathlib import Path

MAP_DATA_SOURCE = Path(__file__).resolve().parent.parent / "HrotExecutableMapData.cs"

# [12] = new( 0x00877AE0, 0x008A55EC ),
_ENTRY = re.compile(
    r"\[\s*(\d+)\s*\]\s*=\s*new\(\s*0x([0-9A-Fa-f]+)\s*,\s*0x([0-9A-Fa-f]+)\s*\)"
)


def load_world_ranges(source: Path = MAP_DATA_SOURCE) -> dict[int, tuple[int, int]]:
    """Parse the WorldConstructors dictionary out of the C# source."""
    text = source.read_text(encoding="utf-8")

    start = text.find("WorldConstructors")
    if start < 0:
        raise RuntimeError(f"No WorldConstructors table in {source}")
    end = text.find("};", start)
    if end < 0:
        raise RuntimeError(f"Unterminated WorldConstructors table in {source}")

    ranges = {
        int(m.group(1)): (int(m.group(2), 16), int(m.group(3), 16))
        for m in _ENTRY.finditer(text[start:end])
    }
    if not ranges:
        raise RuntimeError(f"WorldConstructors table in {source} parsed empty")
    return ranges


WORLD_RANGES: dict[int, tuple[int, int]] = load_world_ranges()


def shared_range_ids() -> dict[tuple[int, int], list[int]]:
    """Map ids that share a constructor range with another map.

    Maps 12, 13 and 16 all point at the same range in the shipped table. That
    is not obviously correct - it means three levels replay identical geometry
    - so anything iterating every map should expect to see it.
    """
    by_range: dict[tuple[int, int], list[int]] = {}
    for map_id, span in sorted(WORLD_RANGES.items()):
        by_range.setdefault(span, []).append(map_id)
    return {span: ids for span, ids in by_range.items() if len(ids) > 1}


if __name__ == "__main__":
    print(f"{len(WORLD_RANGES)} maps from {MAP_DATA_SOURCE}")
    for map_id, (start_va, end_va) in sorted(WORLD_RANGES.items()):
        print(f"  {map_id:>3}  0x{start_va:08X} .. 0x{end_va:08X}  ({end_va - start_va:>8} bytes)")
    for span, ids in shared_range_ids().items():
        print(f"\nshared range 0x{span[0]:08X}: maps {ids}")
