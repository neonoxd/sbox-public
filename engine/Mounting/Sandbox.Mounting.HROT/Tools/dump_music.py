#!/usr/bin/env python3
"""Which music each map plays. No game needed.

HROT's music is **three simultaneous looping layers**, not one track per map.
Each map's prop constructor points four globals at a sound id:

    mov eax, dword ptr [0x00DE7C38]     ; layer pointer
    mov dword ptr [eax], 0x150          ; 336 = mus_21

and the mixer at 0x00DCB721 plays each layer that has a non-zero gain:

    fld   dword ptr [ebx + 0x430]       ; layer gain
    fcomp dword ptr [0x00DCB92C]        ; 0.0
    jbe   skip
    push  dword ptr [ebx + 0x430]
    push  0x3F800000
    mov   eax, dword ptr [0x00DE7C38]
    mov   eax, dword ptr [eax]          ; the sound id
    mov   dl, 1                         ; looping
    call  0x00DCF710

Three of those blocks sit in a row with gains at +0x430, +0x438 and +0x440, so
`mus_9` and `mus_9_a` are **layers of one cue**, not alternates - which is why
several maps name the same `_a` track twice.

Why the earlier searches missed it: this is a dword store *through a pointer*,
not `mov ax, <id>`. Searching for a register holding a music id found only prop
placers, where `ax` is the model id - see the trap in `dump_sounds.py`.

Usage:
    dump_music.py               every map, with level names
    dump_music.py --check       the control scan: what else writes these globals
    dump_music.py --map 5
"""

from __future__ import annotations

import argparse
import struct
import sys

import hrot_re
import dump_sounds
import dump_level_names
from dump_signs import load_constructors

# Layer pointers, in the order the mixer plays them, then the intermission
# slot. Named for their role rather than their content: the mount only drives
# layer 1, because nothing here has the combat state the others fade in on.
GLOBALS = {
    0x00DE7C38: "layer1",
    0x00DE7C90: "layer2",
    0x00DE7EA4: "layer3",
    0x00DE7FC8: "intermission",
}

MIXER = 0x00DCB721


def read_map_music(image: hrot_re.Image, start: int, end: int) -> dict[str, int]:
    """The sound id each layer global is pointed at, within one constructor."""
    offset = image.va2off(start)
    if offset is None:
        return {}

    blob = image.data[offset:offset + (end - start)]
    found: dict[str, int] = {}

    # A1 <ptr32>  C7 00 <imm32>
    for i in range(len(blob) - 10):
        if blob[i] != 0xA1 or blob[i + 5] != 0xC7 or blob[i + 6] != 0x00:
            continue
        pointer = struct.unpack_from("<I", blob, i + 1)[0]
        role = GLOBALS.get(pointer)
        if role is None:
            continue
        found[role] = struct.unpack_from("<I", blob, i + 7)[0]

    return found


def control_scan(image: hrot_re.Image, sounds: dict[int, str]) -> list[tuple]:
    """Every write to a layer global anywhere, music id or not.

    The per-map scan filters to known music ids, which cannot fail to look
    convincing. This one does not filter, so it can report a global being used
    for something that is not music - the check that says the four addresses
    really are the music slots rather than four addresses that happened to
    match.
    """
    rows = []
    for virtual_address, blob in image.executable_sections():
        for i in range(len(blob) - 10):
            if blob[i] != 0xA1 or blob[i + 5] != 0xC7 or blob[i + 6] != 0x00:
                continue
            pointer = struct.unpack_from("<I", blob, i + 1)[0]
            if pointer not in GLOBALS:
                continue
            value = struct.unpack_from("<I", blob, i + 7)[0]
            rows.append((virtual_address + i, GLOBALS[pointer], value,
                         sounds.get(value)))
    return rows


def read_map_music_disasm(image: hrot_re.Image, start: int, end: int) -> dict[str, int]:
    """The same decode, but through Capstone instead of a raw byte walk.

    `read_map_music` matches the bytes `A1 <ptr> C7 00 <imm>` wherever they
    occur, which is the shape that silently broke the decal decoder: `0xA1` can
    appear inside another instruction's operand and the walk then reads a
    perfectly plausible pointer out of the middle of something else. This one
    only ever looks at instruction boundaries, so a disagreement between the two
    is a real bug in one of them.
    """
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_EAX

    found: dict[str, int] = {}
    previous = None

    for instruction in image.disasm(start, end - start):
        # hrot_re disassembles with skipdata on - undecodable bytes come back as
        # pseudo-instructions whose operands raise rather than being empty.
        if instruction.id == 0:
            previous = None
            continue

        operands = instruction.operands
        if instruction.mnemonic != "mov" or len(operands) != 2:
            previous = None
            continue

        destination, source = operands

        # mov eax, dword ptr [<absolute>]  - load the layer pointer
        if (destination.type == X86_OP_REG and destination.reg == X86_REG_EAX
                and source.type == X86_OP_MEM
                and source.mem.base == 0 and source.mem.index == 0):
            previous = source.mem.disp & 0xFFFFFFFF
            continue

        # mov dword ptr [eax], <imm>       - store the sound id through it
        if (previous is not None
                and destination.type == X86_OP_MEM
                and destination.mem.base == X86_REG_EAX
                and destination.mem.index == 0 and destination.mem.disp == 0
                and source.type == X86_OP_IMM):
            role = GLOBALS.get(previous)
            if role is not None:
                found[role] = source.imm & 0xFFFFFFFF

        previous = None

    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exe", nargs="?", default=hrot_re.DEFAULT_EXE)
    parser.add_argument("--map", type=int)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--verify", action="store_true",
                        help="diff the byte walk against a Capstone decode")
    arguments = parser.parse_args()

    image = hrot_re.Image(arguments.exe)
    sounds = dump_sounds.read_table(image)
    # dump_level_names carries its own Image class rather than hrot_re's, and
    # the two do not share a method set.
    names = dump_level_names.level_names(
        dump_level_names.Image(arguments.exe))
    constructors = load_constructors()

    if arguments.verify:
        disagreements = 0
        for map_id in sorted(constructors):
            start, end = constructors[map_id]
            walked = read_map_music(image, start, end)
            decoded = read_map_music_disasm(image, start, end)
            if walked != decoded:
                disagreements += 1
                print(f"  !! map {map_id}: bytes {walked} vs disasm {decoded}")
        print(f"{len(constructors)} maps, {disagreements} disagreement(s) "
              f"between the byte walk and Capstone.")
        return 1 if disagreements else 0

    if arguments.check:
        rows = control_scan(image, sounds)
        strays = [r for r in rows
                  if not (r[3] or "").startswith("mus_")]
        print(f"{len(rows)} writes to the four layer globals")
        for address, role, value, name in rows:
            if (name or "").startswith("mus_"):
                continue
            print(f"  !! {address:08X} {role:12s} {value:5d}  "
                  f"{name or '<unregistered>'}")
        print(f"\n{len(strays)} write a value that is not a mus_* track.")
        print("`disko2.wav` is the expected one: a diegetic disco, and so a"
              " real music cue.")
        return 0

    print(f"{'map':>4}  {'level':28s} {'layer1':14s} {'layer2':14s} "
          f"{'layer3':14s} intermission")

    silent = []
    for map_id in sorted(constructors):
        if arguments.map is not None and map_id != arguments.map:
            continue

        start, end = constructors[map_id]
        found = read_map_music(image, start, end)

        def show(role: str) -> str:
            value = found.get(role)
            if value is None:
                return "-"
            name = sounds.get(value)
            if not name:
                return f"?({value})"
            # Trim the mus_ prefix for width, but never assume it: map 15's
            # second layer is disko2.wav, a diegetic cue.
            stem = name[:-4] if name.endswith(".wav") else name
            return f"{stem[4:] if stem.startswith('mus_') else stem}({value})"

        if "layer1" not in found:
            silent.append(map_id)

        _, level = names.get(map_id, (0, "?"))
        print(f"{map_id:>4}  {level[:28]:28s} {show('layer1'):14s} "
              f"{show('layer2'):14s} {show('layer3'):14s} "
              f"{show('intermission')}")

    if silent:
        print(f"\nno layer 1: maps {silent}", file=sys.stderr)
        print("Map 100 is the hub and sets only the intermission slot, which"
              " is consistent.", file=sys.stderr)

    print(f"\nmixer at {MIXER:08X}; layer gains at ebx+0x430/+0x438/+0x440",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
