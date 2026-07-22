#!/usr/bin/env python3
"""Dump HROT's wall signs from the map constructors. No game needed.

A sign is two unrelated records, authored side by side. See
REVERSE_ENGINEERING.md 12, "Wall signs".

The visible sign is a decal quad - the text is painted into a 512x512 sheet,
not drawn from glyphs:

    0x00D4D500( dl = facing, push x0, y0, x1, y1, cellX, cellZ, y, scale )
        -> 0x28-byte record at 0x17D65E4
           { flag @ +0, facing @ +1, cellZ @ +4, cellX @ +8, y @ +0xC,
             half width @ +0x10, half height @ +0x14 (negative),
             uv rect @ +0x18 }

    half_width  = (x1 - x0) *  0.003774 * scale
    half_height = (y1 - y0) * -0.004100 * scale

    These are HALF extents: the emitter at 0xD89B5C draws centre +/- each.
    uv     = pixel / 512, V flipped, half-texel inset of 0.5/512
    facing: 0,1 = the two Z-facing walls; 2,3 = the two X-facing. Which of
            each pair is positive is not established.

The English subtitle is a separate proximity box:

    0x00D98380( dx = stringId, push x, y, z, halfX, halfY, halfZ, arg7 )
        -> 0x20-byte record at 0x17D3CFC, signed byte count at 0x17D3F9C

Moving a box in live memory moves where the subtitle triggers and leaves the
sign itself alone, which is how the two systems were told apart. The id is the
English string; there is no reliable offset to the Czech text, which is pixels
in the sheet anyway.

Usage:
    dump_signs.py                every map, decals and subtitle boxes
    dump_signs.py --map 1        one map
    dump_signs.py --decals       decals only
    dump_signs.py --boxes        subtitle boxes only
"""

from __future__ import annotations

import argparse
import pathlib
import re
import struct
import sys

import hrot_re

MAKE_DECAL = 0x00D4D500
MAKE_SIGN = 0x00D98380

WIDTH_K = 0.003774
HEIGHT_K = 0.004100
SHEET = 512

# 0/1 and 2/3 are opposite pairs - poking the byte live turned a sign 90
# degrees one way for 2 and the other for 3 - and the axis agrees with the
# thin axis of the paired subtitle box on all 11 of map 1. Which member of
# each pair faces which way is NOT established.
FACING = {0: "Z", 1: "Z opposite", 2: "X", 3: "X opposite"}

# Entity constructor ranges, parsed out of the C# rather than copied here.
# A transcribed copy of this table silently went stale once already: it listed
# seven maps while the mount had thirty-two, so every total this tool printed
# was a slice of the game presented as all of it.
def load_constructors(source: pathlib.Path | None = None) -> dict[int, tuple[int, int]]:
    source = source or (pathlib.Path(__file__).resolve().parent.parent
                        / "HrotExecutableProps.cs")
    text = source.read_text(encoding="utf-8-sig")

    anchor = text.find("Constructors = new()")
    if anchor < 0:
        raise RuntimeError(f"No Constructors table in {source}")
    close = text.find("};", anchor)
    if close < 0:
        raise RuntimeError(f"Unterminated Constructors table in {source}")

    ranges = {}
    for map_id, start, end in re.findall(
            r"\[(\d+)\]\s*=\s*new\(\s*(0x[0-9A-Fa-f]+)\s*,\s*(0x[0-9A-Fa-f]+)\s*\)",
            text[anchor:close]):
        ranges[int(map_id)] = (int(start, 16), int(end, 16))

    if not ranges:
        raise RuntimeError(f"Constructors table in {source} parsed empty")
    return ranges


CONSTRUCTORS = load_constructors()


def as_float(immediate: int) -> float | None:
    value = struct.unpack("<f", struct.pack("<I", immediate & 0xFFFFFFFF))[0]
    return None if value != value or abs(value) > 1e6 else value


def scan_all(image: hrot_re.Image):
    """Bucket every call in the constructor ranges by map, in one pass.

    ``Image.sweep`` disassembles from the start of each executable section and
    only filters by ``lo``, so a narrow range costs a whole-section pass - and
    ``anchors`` multiplies that by four. Scanning per map per record type meant
    fourteen of them; the ranges are disjoint, so one sweep across the span and
    a bucket per map does the same work once.

    Addresses repeat between anchors, so they are de-duplicated here. Not doing
    that once turned 83 signs into a confident 332.
    """
    lo = min(start for start, _ in CONSTRUCTORS.values())
    hi = max(end for _, end in CONSTRUCTORS.values())
    owner = {}

    seen: set[int] = set()
    pushes: list[int] = []
    registers: dict[str, int] = {}
    calls: dict[int, list] = {map_id: [] for map_id in CONSTRUCTORS}

    for instruction in image.sweep(lo, hi):
        if instruction.address in seen:
            continue
        seen.add(instruction.address)

        if instruction.mnemonic == "mov" and instruction.operands                 and instruction.operands[-1].type == 2:
            destination = instruction.op_str.split(",")[0].strip()
            if destination in ("ax", "al", "dx", "dl", "cx", "cl"):
                registers[destination] = instruction.operands[-1].imm
        elif instruction.mnemonic == "xor":
            destination = instruction.op_str.split(",")[0].strip()
            if destination in ("edx", "eax", "ecx"):
                registers[destination[1:]] = 0

        if instruction.mnemonic == "push" and instruction.operands                 and instruction.operands[0].type == 2:
            pushes.append(instruction.operands[0].imm)
            continue

        if instruction.mnemonic == "call" and instruction.operands                 and instruction.operands[0].type == 2:
            address = instruction.address
            map_id = owner.get(address)
            if map_id is None:
                map_id = next((m for m, (s_, e_) in CONSTRUCTORS.items()
                               if s_ <= address < e_), -1)
                owner[address] = map_id
            if map_id >= 0:
                calls[map_id].append(
                    (address, instruction.operands[0].imm,
                     dict(registers), list(pushes)))
            pushes, registers = [], {}

    return calls


def decals(calls, map_id: int) -> list[dict]:
    found = []

    for address, target, registers, pushes in calls[map_id]:
        if target != MAKE_DECAL:
            continue

        if len(pushes) < 8:
            print(f"  !! map {map_id} 0x{address:08X}: {len(pushes)} pushes, "
                  "record skipped", file=sys.stderr)
            continue

        args = [as_float(value) for value in pushes[-8:]]
        cell_x, cell_z, y, x0, y0, x1, y1, scale = args
        facing = registers.get("dl", registers.get("dx", 0))

        found.append({
            "address": address,
            "facing": facing,
            "cell": (cell_x, cell_z),
            "y": y,
            "rect": (int(x0), int(y0), int(x1), int(y1)),
            "scale": scale,
            "half_width": (x1 - x0) * WIDTH_K * scale,
            "half_height": (y1 - y0) * HEIGHT_K * scale,
        })

    return found


def boxes(image: hrot_re.Image, calls, map_id: int) -> list[dict]:
    found = []

    for address, target, registers, pushes in calls[map_id]:
        if target != MAKE_SIGN:
            continue

        if len(pushes) < 7:
            print(f"  !! map {map_id} 0x{address:08X}: {len(pushes)} pushes, "
                  "record skipped", file=sys.stderr)
            continue

        args = [as_float(value) for value in pushes[-7:]]
        string_id = registers.get("dx", registers.get("dl", 0))

        found.append({
            "address": address,
            "position": tuple(args[0:3]),
            "half": tuple(args[3:6]),
            "arg7": args[6],
            "id": string_id,
            "text": image.string_by_id(string_id) if string_id else None,
        })

    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exe", nargs="?", default=hrot_re.DEFAULT_EXE)
    parser.add_argument("--map", type=int)
    parser.add_argument("--decals", action="store_true")
    parser.add_argument("--boxes", action="store_true")
    arguments = parser.parse_args()

    image = hrot_re.Image(arguments.exe)
    calls = scan_all(image)
    map_ids = [arguments.map] if arguments.map is not None else sorted(CONSTRUCTORS)

    want_decals = arguments.decals or not arguments.boxes
    want_boxes = arguments.boxes or not arguments.decals

    totals = [0, 0]
    for map_id in map_ids:
        if map_id not in CONSTRUCTORS:
            print(f"map {map_id} has no constructor range here")
            continue

        print(f"\n=== map {map_id}")

        if want_decals:
            found = decals(calls, map_id)
            totals[0] += len(found)
            print(f"  {len(found)} decal(s)")
            for decal in found:
                x0, y0, x1, y1 = decal["rect"]
                print(f"    0x{decal['address']:08X} facing={decal['facing']}"
                      f" ({FACING.get(decal['facing'], '?')})"
                      f" cell=({decal['cell'][0]:g},{decal['cell'][1]:g})"
                      f" y={decal['y']:g}"
                      f" rect=({x0},{y0})-({x1},{y1})"
                      f" half=({decal['half_width']:.3f},"
                      f"{decal['half_height']:.3f})")

        if want_boxes:
            found = boxes(image, calls, map_id)
            totals[1] += len(found)
            print(f"  {len(found)} subtitle box(es)")
            for box in found:
                position = ",".join(f"{v:.3f}" for v in box["position"])
                half = ",".join(f"{v:.3f}" for v in box["half"])
                print(f"    0x{box['address']:08X} id={box['id']:<5}"
                      f" pos=({position}) half=({half}) arg7={box['arg7']:g}")
                print(f"        {box['text']}")

    print(f"\n{totals[0]} decals, {totals[1]} subtitle boxes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
