#!/usr/bin/env python3
"""Show what HROT is playing right now. Requires the game running.

The audio init at 0xDCAE68 clears 13 entries of 12 bytes at 0x18D5820, so that
is the channel table. The first dword of a slot is a sound id, -1 when idle.

This is the fastest way to answer "what is that noise" - which is exactly how
the prop emitter decode got unstuck, after four static searches had each found
a confident wrong answer. Stand next to something audible and read the table:
a slot that holds the same id across samples is a loop, one that comes and goes
is a one-shot.

Reaching it from scratch, in case the addresses move: HROT loads OpenAL
dynamically, so nothing is in the import table. Find the "alSourcePlay" and
"alSource3f" strings, follow each to the `mov [global], eax` that stores its
GetProcAddress result, find the one function that reads those globals, and take
its only caller - that is the audio init, and the table is the block it clears.

Usage:
    dump_live_channels.py               sample a few times and summarise
    dump_live_channels.py --watch       keep sampling until interrupted
    dump_live_channels.py --samples 20
"""

from __future__ import annotations

import argparse
import collections
import struct
import sys
import time

import hrot_re
import dump_sounds

CHANNELS = 0x018D5820
SLOT = 12
COUNT = 13


def read_channels(live, sounds):
    blob = live.read(CHANNELS, SLOT * COUNT)
    if blob is None:
        return None

    active = []
    for index in range(COUNT):
        values = struct.unpack_from("<3i", blob, index * SLOT)
        if values[0] < 0:
            continue
        active.append((index, values, sounds.get(values[0])))

    return active


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=6)
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--interval", type=float, default=0.4)
    arguments = parser.parse_args()

    live = hrot_re.Live()
    sounds = dump_sounds.read_table(hrot_re.Image())

    print(f"pid {live.pid}, map {live.map_id()}, "
          f"{len(sounds)} sounds in the table")

    seen = collections.Counter()
    sample = 0

    while arguments.watch or sample < arguments.samples:
        active = read_channels(live, sounds)
        if active is None:
            print("could not read the channel table", file=sys.stderr)
            return 1

        print(f"\n--- sample {sample}: {len(active)} slot(s) playing")
        for index, values, name in active:
            seen[(values[0], name)] += 1
            print(f"    slot {index:2d}  id {values[0]:4d}  "
                  f"{name or '<unregistered>':24s} {values[1]:6d} {values[2]:6d}")

        sample += 1
        time.sleep(arguments.interval)

    if not arguments.watch:
        print("\nacross samples - a stable id is a loop, a fleeting one is not:")
        for (sound_id, name), n in seen.most_common():
            kind = "loop" if n == sample else f"{n}/{sample} samples"
            print(f"   {sound_id:4d}  {name or '<unregistered>':24s} {kind}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
