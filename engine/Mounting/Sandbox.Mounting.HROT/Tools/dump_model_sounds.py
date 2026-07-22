#!/usr/bin/env python3
"""Which prop models emit a looping sound, and how far it carries. No game needed.

Mirrors `HrotExecutableSounds.ReadModelSounds` closely enough to check it - the
C# walks raw bytes, this walks the same bytes, and a disagreement means the
mount is wrong whatever it sounds like.

HROT has no emitter entities. A prop's update case calls an attenuated play
function every frame:

    0xDCF7A4( eax = soundId, push gain, near, far, distance )
        distance >= far  -> silent
        distance <  near -> full volume
        else                (far - distance) / (far - near)

and which prop plays what comes from the update switch, keyed on the model id
in Delphi's two-level form:

    movzx eax, word [ebx-0x70]        ; model id
    mov   al,  byte [eax + 0xD6E7D3]  ; model -> case index
    jmp   dword [eax*4 + 0xD6EB2C]    ; case -> code

87 models reach a case that plays something; 78 pass their radii as constants
and are the ones the mount can place. The rest - fire (`ohen`) and machinery
(`motor`) - compute the distance at runtime and are left alone rather than
given an invented radius.

**Do not search for sound ids.** They run 1..427, inside the static-model range
and inside nearly every flag a constructor passes, so "this register holds a
valid sound id" matches almost anything. That produced four false leads, one of
which shipped: `RegisterModel`'s fourth argument was read as a sound and is the
damaged-model id. Work from the code that plays, or from the running game.

Usage:
    dump_model_sounds.py                every emitting model
    dump_model_sounds.py --sound vn     models playing a matching sound
    dump_model_sounds.py --model 181
"""

from __future__ import annotations

import argparse
import struct
import subprocess
import sys
import pathlib

import hrot_re
import dump_sounds

CASE_TABLE = 0x00D6E7D3
JUMP_TABLE = 0x00D6EB2C
PLAY_ATTENUATED = 0x00DCF7A4
MAX_MODEL = 0x358
CASE_COUNT = 224
CASE_SPAN = 0x400


def model_names(exe: str) -> dict[int, str]:
    """Reuses list_static_models.py rather than re-parsing the registrations."""
    tool = pathlib.Path(__file__).with_name("list_static_models.py")
    output = subprocess.run([sys.executable, str(tool), exe],
                            capture_output=True, text=True).stdout
    names = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].isdigit():
            names[int(parts[0])] = parts[1].replace("model=", "")
    return names


def read(image, sounds):
    data = image.data
    case_offset = image.va2off(CASE_TABLE)
    jump_offset = image.va2off(JUMP_TABLE)
    if case_offset is None or jump_offset is None:
        return {}, 0

    targets = [struct.unpack_from("<I", data, jump_offset + i * 4)[0]
               for i in range(CASE_COUNT)]
    starts = sorted(set(targets))

    def case_sound(entry):
        """(soundId, far, near, gain) for the first usable play call."""
        end = min([s for s in starts if s > entry] + [entry + CASE_SPAN])
        begin, finish = image.va2off(entry), image.va2off(end)
        if begin is None or finish is None:
            return None

        for off in range(begin, finish - 4):
            if data[off] != 0xE8:
                continue
            following = image.off2va(off + 5)
            if following is None:
                continue
            target = (following
                      + struct.unpack_from("<i", data, off + 1)[0]) & 0xFFFFFFFF
            if target != PLAY_ATTENUATED:
                continue

            sound, probe = None, off
            for back in range(off - 1, off - 12, -1):
                if data[back] == 0xB8 and back + 5 <= off:
                    sound, probe = struct.unpack_from("<i", data, back + 1)[0], back
                    break
                if data[back] == 0x66 and data[back + 1] == 0xB8 and back + 4 <= off:
                    sound, probe = struct.unpack_from("<H", data, back + 2)[0], back
                    break

            if sound is None or sound not in sounds:
                continue

            values, cursor, count = [0.0, 0.0, 0.0], probe, 0
            for argument in (2, 1, 0):
                if cursor - 5 < begin or data[cursor - 5] != 0x68:
                    break
                raw = struct.unpack_from("<I", data, cursor - 4)[0]
                values[argument] = struct.unpack("<f", struct.pack("<I", raw))[0]
                cursor -= 5
                count += 1

            # Keep looking within the case: the first call may take a computed
            # distance while a later one does not.
            if count < 3 or values[0] <= 0.0:
                continue

            return sound, values[0], values[1], values[2]

        return None

    emitters, reached = {}, 0
    by_case = {}
    for model in range(MAX_MODEL + 1):
        index = data[case_offset + model]
        if index >= CASE_COUNT:
            continue
        if index not in by_case:
            by_case[index] = case_sound(targets[index])
        found = by_case[index]
        if found:
            emitters[model] = found
        elif targets[index] != targets[0]:
            reached += 1

    return emitters, reached


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exe", nargs="?", default=hrot_re.DEFAULT_EXE)
    parser.add_argument("--sound")
    parser.add_argument("--model", type=int)
    arguments = parser.parse_args()

    image = hrot_re.Image(arguments.exe)
    sounds = dump_sounds.read_table(image)
    emitters, _ = read(image, sounds)
    names = model_names(arguments.exe)

    if not emitters:
        print("no emitting models found: the switch tables have moved",
              file=sys.stderr)
        return 1

    shown = 0
    for model in sorted(emitters):
        sound, far, near, gain = emitters[model]
        name = sounds.get(sound, "?")
        if arguments.model is not None and model != arguments.model:
            continue
        if arguments.sound and arguments.sound.lower() not in name.lower():
            continue
        shown += 1
        print(f"  model {model:4d} {names.get(model, '?'):24s} -> {sound:4d} "
              f"{name:24s} far={far:g} near={near:g} gain={gain:g}")

    print(f"\n{len(emitters)} emitting model(s), {shown} shown", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
