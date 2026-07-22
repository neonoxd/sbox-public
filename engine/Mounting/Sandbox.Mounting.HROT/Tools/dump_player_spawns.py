#!/usr/bin/env python3
"""Dump every map's player start. No game needed.

Mirrors `HrotExecutableProps.ReadPlayerSpawn` closely enough to be a check on
it: the C# walks raw bytes, this walks the same bytes, and if they disagree the
mount is wrong regardless of what it renders. Two real bugs were caught exactly
this way - see below.

The player object is behind the pointer at 0xDE7C74; position is fields +4, +8
and +0xC. Constructors set it two ways and **both are needed** - only maps 0, 1,
2 and 101 use the call:

    inline (most maps):
        mov eax,[0xDE7C74] ; mov [eax+4],  x
        mov eax,[0xDE7C74] ; mov [eax+8],  vertical
        mov eax,[0xDE7C74] ; mov [eax+0xC], z
        push yaw ; call 0x004A326C

    call form:
        push x, vertical, z ; mov eax, facing ; call 0x00DBE4AC

Three traps, each of which produced a plausible wrong answer rather than an
error:

- a **zero vertical** is emitted as `xor edx,edx ; mov [eax+8],edx`, two bytes
  shorter than the immediate form. A fixed stride skips those maps and it reads
  as "these levels have no spawn" - it was ten of the thirty-two;
- the facing of the call form is in **EAX**, not EDX. Reading EDX returns 0,
  which is the correct index for map 1 and wrong for the other three;
- find the **angle call first, then its push**. Scanning forward for the first
  push found an unrelated `push 1.25` on map 4 and reported it as a facing.
  Every real value is one of -89.99, 90.01, 0.01, 179.99.

s&box needs a further 90 degrees on the yaw; that lives in
`HrotMap.PlayerStartYawOffset`, not here, so this prints HROT's own angle.

Usage:
    dump_player_spawns.py            every map
    dump_player_spawns.py --map 1
"""

from __future__ import annotations

import argparse
import struct
import sys

import hrot_re
import dump_signs

PLAYER_POINTER = 0x00DE7C74
PLACE_PLAYER_START = 0x00DBE4AC
SET_PLAYER_ANGLE = 0x004A326C
CENTRE = 0.5
YAWS = [-89.99, 90.01, 0.01, 179.99]
UNIT_SCALE = 64.0


def field_write(data, offset, field):
    """(value, next offset) for one `mov eax,[player]` plus its field write."""
    if offset + 5 > len(data) or data[offset] != 0xA1:
        return None
    if struct.unpack_from("<I", data, offset + 1)[0] != PLAYER_POINTER:
        return None

    write = offset + 5

    # mov dword ptr [eax+field], imm32
    if (write + 7 <= len(data) and data[write] == 0xC7
            and data[write + 1] == 0x40 and data[write + 2] == field):
        return struct.unpack_from("<f", data, write + 3)[0], write + 7

    # xor edx, edx ; mov dword ptr [eax+field], edx  - how a zero is written
    if (write + 5 <= len(data) and data[write] in (0x31, 0x33)
            and data[write + 1] == 0xD2 and data[write + 2] == 0x89
            and data[write + 3] == 0x50 and data[write + 4] == field):
        return 0.0, write + 5

    return None


def read_yaw(image, data, offset, end):
    """The push feeding the angle setter, found from the call backwards."""
    limit = min(end, offset + 192)

    for i in range(offset, limit - 4):
        if data[i] != 0xE8:
            continue
        following = image.off2va(i + 5)
        if following is None:
            continue
        target = (following + struct.unpack_from("<i", data, i + 1)[0]) & 0xFFFFFFFF
        if target != SET_PLAYER_ANGLE:
            continue

        for candidate in range(i, max(offset, i - 24) - 1, -1):
            if candidate - 5 < offset or data[candidate - 5] != 0x68:
                continue
            value = struct.unpack_from("<f", data, candidate - 4)[0]
            if any(abs(value - yaw) < 0.001 for yaw in YAWS):
                return value
        return None

    return None


def read_facing_index(data, start, call_offset):
    """EAX, not EDX - the trap this file's docstring warns about."""
    for probe in range(call_offset - 1, max(start, call_offset - 24) - 1, -1):
        if data[probe] == 0xB8 and probe + 5 <= call_offset:
            return struct.unpack_from("<i", data, probe + 1)[0]
        if data[probe] == 0xB0 and probe + 2 <= call_offset:
            return data[probe + 1]
        if (data[probe] in (0x31, 0x33) and probe + 2 <= call_offset
                and data[probe + 1] == 0xC0):
            return 0
    return 0


def spawn_for_map(image, map_id):
    data = image.data
    lo, hi = dump_signs.CONSTRUCTORS[map_id]
    start, end = image.va2off(lo), image.va2off(hi)

    # inline
    i = start
    while i + 15 <= end:
        first = field_write(data, i, 0x04)
        if first:
            second = field_write(data, first[1], 0x08)
            if second:
                third = field_write(data, second[1], 0x0C)
                if third:
                    return ("inline", first[0], second[0], third[0],
                            read_yaw(image, data, third[1], end))
        i += 1

    # call form
    i = start
    while i + 5 <= end:
        if data[i] == 0xE8:
            following = image.off2va(i + 5)
            if following is not None:
                target = (following
                          + struct.unpack_from("<i", data, i + 1)[0]) & 0xFFFFFFFF
                if target == PLACE_PLAYER_START:
                    for candidate in range(i, max(start, i - 24) - 1, -1):
                        pushes, cursor = [], candidate
                        while (len(pushes) < 3 and cursor - 5 >= start
                               and data[cursor - 5] == 0x68):
                            pushes.insert(
                                0, struct.unpack_from("<f", data, cursor - 4)[0])
                            cursor -= 5
                        if len(pushes) == 3 and all(abs(v) < 4096 for v in pushes):
                            index = read_facing_index(data, start, i)
                            yaw = YAWS[index] if 0 <= index < len(YAWS) else None
                            return ("call", pushes[0] + CENTRE, pushes[1],
                                    pushes[2] + CENTRE, yaw)
        i += 1

    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exe", nargs="?", default=hrot_re.DEFAULT_EXE)
    parser.add_argument("--map", type=int)
    arguments = parser.parse_args()

    image = hrot_re.Image(arguments.exe)
    map_ids = ([arguments.map] if arguments.map is not None
               else sorted(dump_signs.CONSTRUCTORS))

    missing = []
    for map_id in map_ids:
        found = spawn_for_map(image, map_id)
        if found is None:
            missing.append(map_id)
            print(f"  map {map_id:3d}  no player start decoded")
            continue

        kind, x, y, z, yaw = found
        sbox = (x * UNIT_SCALE, -z * UNIT_SCALE, y * UNIT_SCALE)
        yaw_text = f"{yaw:7.2f}" if yaw is not None else "      ?"
        print(f"  map {map_id:3d} {kind:6s} "
              f"hrot=({x:7.2f},{y:8.3f},{z:7.2f}) "
              f"sbox=({sbox[0]:8.0f},{sbox[1]:8.0f},{sbox[2]:8.0f}) "
              f"yaw={yaw_text}")

    print(f"\n{len(map_ids) - len(missing)}/{len(map_ids)} maps decoded",
          file=sys.stderr)
    if missing:
        print(f"missing: {missing}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
