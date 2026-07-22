#!/usr/bin/env python3
"""Reconnaissance on a map constructor: what it calls, and what we cannot name.

This is how the wall-sign decal helper and the player-start helper were both
found. A level constructor is a flat list of calls to placement helpers, so
finding a new feature means finding which unnamed target is responsible:

- **by frequency** - a helper called 11 times in map 1 is placing something
  there are 11 of;
- **by once-per-map** - a helper called exactly once in most maps is a
  level-wide property, which is what the player start turned out to be;
- **by coordinate** - if you can see the thing in game, find the call whose
  arguments are near it. `--near X Z` does this, and it is usually the fastest
  route.

Arguments are float bit patterns pushed before the call, so integers in the
output are already reinterpreted. Register arguments (EAX/EDX/ECX) are shown
too - helpers routinely take an id or an index that way, and reading the wrong
register is an easy way to get a plausible wrong answer.

Usage:
    find_helpers.py --map 1                 every target, known ones named
    find_helpers.py --map 1 --unknown       only targets with no name
    find_helpers.py --once                  once-per-map candidates, all maps
    find_helpers.py --map 1 --near 78 60    calls placing something at a cell
    find_helpers.py --map 1 --target 0xD4D500   every call to one helper
"""

from __future__ import annotations

import argparse
import collections
import struct
import sys

import hrot_re
import dump_signs

# Everything HrotExecutableProps and the mount already understand. Anything not
# in here is a candidate for whatever you are currently looking for.
KNOWN = {
    0x00DBDF04: "PlaceAtHeight",
    0x00DBDDE0: "PlaceOnFloor",
    0x00DBDE24: "PlaceAboveFloor",
    0x00DBE468: "PlaceAtCell",
    0x00D5CDF4: "PlaceFloorLamp",
    0x00D5CE0C: "PlaceLampPost",
    0x00D5CF20: "PlaceRaisedLamp",
    0x00D5CD48: "PlaceCeilingFluorescent",
    0x00D5CFE8: "PlaceCeilingBakelite",
    0x00D5D08C: "PlaceCeilingChandelier",
    0x00D5D120: "PlaceCeilingChandelier2",
    0x00DBDD64: "ScaleLastPlaced",
    0x00D4D690: "PlaceGlassPanel",
    0x00D77C20: "PlaceDoor",
    0x00DBE688: "TriggerAttach",
    0x00DBE7E0: "ModelRegister",
    0x00D4D500: "MakeDecal (wall sign)",
    0x00D98380: "MakeSignBox (subtitle volume)",
    0x00DBE4AC: "PlacePlayerStart",
    0x004A326C: "SetPlayerAngle",
    0x004049A0: "LStrAsg",
    0x004613F4: "Vector3Ctor",
}


def as_float(immediate: int) -> float | None:
    value = struct.unpack("<f", struct.pack("<I", immediate & 0xFFFFFFFF))[0]
    return None if value != value or abs(value) > 1e6 else value


def describe(target: int) -> str:
    return KNOWN.get(target, "")


def show_call(address: int, target: int, registers: dict, pushes: list) -> str:
    floats = [as_float(value) for value in pushes]
    shown = ", ".join(f"{f:g}" if f is not None else "?" for f in floats)
    name = describe(target) or f"0x{target:08X}"
    return f"  0x{address:08X} {name:30s} regs={registers} [{shown}]"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exe", nargs="?", default=hrot_re.DEFAULT_EXE)
    parser.add_argument("--map", type=int)
    parser.add_argument("--unknown", action="store_true")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--near", nargs=2, type=float, metavar=("X", "Z"))
    parser.add_argument("--tolerance", type=float, default=1.5)
    parser.add_argument("--target", help="only calls to this address")
    arguments = parser.parse_args()

    image = hrot_re.Image(arguments.exe)
    calls = dump_signs.scan_all(image)

    target_filter = int(arguments.target, 0) if arguments.target else None
    map_ids = ([arguments.map] if arguments.map is not None
               else sorted(dump_signs.CONSTRUCTORS))

    if arguments.once:
        appears_in = collections.Counter()
        exactly_once = collections.Counter()
        for map_id in sorted(dump_signs.CONSTRUCTORS):
            counts = collections.Counter(t for _, t, _, _ in calls[map_id])
            for target, n in counts.items():
                appears_in[target] += 1
                if n == 1:
                    exactly_once[target] += 1

        print("helpers called exactly once in the most maps - level-wide "
              "properties look like this:\n")
        for target, once in exactly_once.most_common(25):
            name = describe(target)
            if arguments.unknown and name:
                continue
            flag = "" if name else "   <- unknown"
            print(f"  0x{target:08X} once in {once:2d} of {appears_in[target]:2d} "
                  f"maps  {name}{flag}")
        return 0

    for map_id in map_ids:
        if map_id not in dump_signs.CONSTRUCTORS:
            print(f"map {map_id} has no constructor range", file=sys.stderr)
            continue

        entries = calls[map_id]
        if not entries:
            continue

        if arguments.near or target_filter is not None:
            print(f"\n=== map {map_id}")
            for address, target, registers, pushes in entries:
                if target_filter is not None and target != target_filter:
                    continue
                if arguments.near:
                    floats = [f for f in (as_float(v) for v in pushes)
                              if f is not None]
                    x, z = arguments.near
                    if not (any(abs(f - x) <= arguments.tolerance for f in floats)
                            and any(abs(f - z) <= arguments.tolerance for f in floats)):
                        continue
                print(show_call(address, target, registers, pushes))
            continue

        counts = collections.Counter(t for _, t, _, _ in entries)
        print(f"\n=== map {map_id}: {len(entries)} calls, "
              f"{len(counts)} distinct targets")
        for target, n in counts.most_common():
            name = describe(target)
            if arguments.unknown and name:
                continue
            flag = "" if name else "   <- unknown"
            print(f"  0x{target:08X} x{n:<4d} {name}{flag}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
