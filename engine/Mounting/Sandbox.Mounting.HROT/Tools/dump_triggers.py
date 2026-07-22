#!/usr/bin/env python3
"""Dump HROT's trigger records from the map constructors. No game needed.

Triggers are static map data, contrary to what was assumed while chasing cell
field 0x19. Each is attached to the prop that was just placed:

    0x00DBE688( al = type, edx = param, ecx = param2 )
        -> 0x00DBE60C writes the 12-byte record  { byte type @ +0,
                                                   dword param @ +4,
                                                   dword param2 @ +8 }
        -> stored at 0x18CD8D0 + counter*0x78, counter at [0xDE7EC8]

The executor at 0x00D7A31C dispatches on the type byte through a 90-entry jump
table at 0x00D7A392. See REVERSE_ENGINEERING.md section 12 (Triggers and moving
volumes).

Volume types all bounds-check `param` to 1..6, the moving-floor volumes that
drive both elevators and water:

    type 5  toggle      type 8  (second volume op)      type 9  raise

Usage:
    dump_triggers.py [exe]              every trigger, grouped by map
    dump_triggers.py [exe] --volumes    only the volume types
    dump_triggers.py [exe] --map 5      one map
"""

from __future__ import annotations

import collections
import sys

import capstone
import pefile

from inventory_entity_helpers import RANGES

DEFAULT_EXE = r"D:\SteamLibrary\steamapps\common\HROT\HROT.exe"

ATTACH_TRIGGER = 0x00DBE688
VOLUME_TYPES = {5, 8, 9, 32, 89}

TRIGGER_TYPES = {
    1: "door",
    5: "volume toggle",
    8: "volume (second op)",
    9: "volume raise",
    32: "volume via 0xDA9470 (edx=-1)",
    89: "volume via 0xDA9470 (dl=1)",
}


def literal(text: str) -> int | None:
    try:
        return int(text, 0)
    except ValueError:
        return None


def read_triggers(exe: str) -> list[tuple[int, int, int | None, int | None, int | None]]:
    pe = pefile.PE(exe)
    image = pe.OPTIONAL_HEADER.ImageBase
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True

    rows = []
    for map_id, (start, end) in sorted(RANGES.items()):
        instructions = list(md.disasm(pe.get_data(start - image, end - start), start))
        for index, insn in enumerate(instructions):
            if insn.mnemonic != "call" or not insn.operands:
                continue
            if insn.operands[0].type != capstone.x86.X86_OP_IMM:
                continue
            if insn.operands[0].imm != ATTACH_TRIGGER:
                continue

            # The three arguments are set immediately before the call, in any
            # order, and a zeroed one is written as `xor reg, reg`.
            registers: dict[str, int] = {}
            for back in range(index - 1, max(0, index - 8), -1):
                previous = instructions[back]
                if previous.mnemonic == "call":
                    break
                if "," not in previous.op_str:
                    continue
                destination, source = previous.op_str.split(", ", 1)
                if previous.mnemonic == "xor" and destination == source:
                    registers.setdefault(destination, 0)
                elif previous.mnemonic == "mov":
                    value = literal(source)
                    if value is not None:
                        registers.setdefault(destination, value)

            def pick(*names):
                for name in names:
                    if name in registers:
                        return registers[name]
                return None

            rows.append((map_id, insn.address,
                         pick("al", "eax"), pick("edx", "dl"), pick("ecx", "cl")))
    return rows


def main() -> None:
    argv = sys.argv[1:]
    only_volumes = "--volumes" in argv
    only_map = None
    if "--map" in argv:
        position = argv.index("--map")
        only_map = int(argv[position + 1])
        del argv[position:position + 2]
    positional = [a for a in argv if not a.startswith("--")]
    exe = positional[0] if positional else DEFAULT_EXE

    rows = read_triggers(exe)
    print(f"{len(rows)} trigger attachments across "
          f"{len({r[0] for r in rows})} maps\n")

    histogram = collections.Counter(r[2] for r in rows)
    print("types in use: " + ", ".join(
        f"{t}x{n}" + (f" ({TRIGGER_TYPES[t]})" if t in TRIGGER_TYPES else "")
        for t, n in sorted(histogram.items(), key=lambda kv: -kv[1])))
    print()

    current = None
    for map_id, address, ttype, param, param2 in rows:
        if only_map is not None and map_id != only_map:
            continue
        if only_volumes and ttype not in VOLUME_TYPES:
            continue
        if map_id != current:
            print(f"--- map {map_id}")
            current = map_id
        name = TRIGGER_TYPES.get(ttype, "")
        print(f"    0x{address:08X}  type {ttype if ttype is not None else '?':>3}  "
              f"param {param}  param2 {param2}"
              f"{'   ' + name if name else ''}")


if __name__ == "__main__":
    main()
