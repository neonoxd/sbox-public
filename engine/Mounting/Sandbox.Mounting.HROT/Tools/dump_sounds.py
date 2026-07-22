#!/usr/bin/env python3
"""Dump HROT's sound id -> filename table. No game needed.

Every WAV is registered once, in a flat run of:

    mov edx, <"name.wav">
    mov eax, <id>
    call 0x00DCAF38          ; RegisterSound

419 registrations, ids 1..427, against 423 WAVs in the PAK - so a handful ship
unregistered.

**A sound id is not usable as a search key.** Ids run 1..427, which is inside
the static-model range (1..840) and inside the range of nearly every flag,
count and index a map constructor passes. Searching for "a register holding a
valid sound id" matches almost everything: it produced three separate confident
false leads, and each one dissolved on inspection -

- `0xD47AB0` turned out to be string formatting (`mov ax, 0x15`);
- `0xD4DB7C` takes `(x, z, height, int, int, int)` and is not audio;
- the prop placers matched because `ax` there is the **model** id: 203 is
  `hasicak`, a fire extinguisher, not `atmo_fx2`.

If you are looking for what *plays* these, work from the audio library rather
than from the ids - `RegisterSound` hands each WAV to a wrapper at `0x4E284C` /
`0x4D252C`, and a positional play call goes through the same library. Or read
the running game, which is cheaper: stand where a sound is audible and look at
what HROT holds, rather than guessing which of eight hundred helpers emitted it.

Usage:
    dump_sounds.py                  the whole table
    dump_sounds.py --find ambient   ids whose filename contains a string
    dump_sounds.py --id 187
"""

from __future__ import annotations

import argparse
import re
import struct
import sys

import hrot_re

REGISTER_SOUND = 0x00DCAF38

# mov edx, imm32 ; mov eax, imm32 ; call rel32
PATTERN = re.compile(rb"\xBA(....)\xB8(....)\xE8(....)", re.S)


def read_table(image: hrot_re.Image) -> dict[int, str]:
    sounds: dict[int, str] = {}

    for virtual_address, blob in image.executable_sections():
        for match in PATTERN.finditer(blob):
            address = virtual_address + match.start()
            relative = struct.unpack("<i", match.group(3))[0]

            # The call must land on RegisterSound; the same three-instruction
            # shape is used all over the executable for unrelated things.
            if address + 15 + relative != REGISTER_SOUND:
                continue

            name = image.delphi_string(struct.unpack("<I", match.group(1))[0])
            if not name:
                continue

            sound_id = struct.unpack("<i", match.group(2))[0]
            if sound_id in sounds and sounds[sound_id] != name:
                print(f"  !! id {sound_id} registered twice: "
                      f"{sounds[sound_id]} then {name}", file=sys.stderr)
            sounds[sound_id] = name

    return sounds


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exe", nargs="?", default=hrot_re.DEFAULT_EXE)
    parser.add_argument("--find")
    parser.add_argument("--id", type=int)
    arguments = parser.parse_args()

    image = hrot_re.Image(arguments.exe)
    sounds = read_table(image)

    if not sounds:
        print("no registrations found: RegisterSound has moved in this build",
              file=sys.stderr)
        return 1

    for sound_id in sorted(sounds):
        name = sounds[sound_id]
        if arguments.id is not None and sound_id != arguments.id:
            continue
        if arguments.find and arguments.find.lower() not in name.lower():
            continue
        print(f"{sound_id:5d}  {name}")

    print(f"\n{len(sounds)} registrations, ids {min(sounds)}..{max(sounds)}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
