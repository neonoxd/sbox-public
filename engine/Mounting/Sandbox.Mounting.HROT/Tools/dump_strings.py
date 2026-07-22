#!/usr/bin/env python3
"""Dump HROT's localisation table. No game needed.

Every string the game shows lives in one 1250-case function at 0xDA9FD8,
reached through the jump table at 0xDAA004:

    GetString( id ) -> mov eax,[ebp+8] ; mov eax,[eax-8]
                       mov edx, <delphi string> ; call LStrAsg

Both languages are in it. English runs from roughly id 0, Czech from about
1083, and there is **no fixed offset between a string and its translation** -
458 pairs with 1083 but the difference does not hold generally, which cost an
afternoon when it was assumed rather than checked.

This is the table wall-sign subtitles come from (`dump_signs.py --boxes` prints
ids), along with level names, pickup messages and menu text.

Usage:
    dump_strings.py                     every id that resolves
    dump_strings.py --find socialist    ids whose text contains a string
    dump_strings.py --id 458            one id
    dump_strings.py --range 1083 1200   a span
"""

from __future__ import annotations

import argparse
import sys

import hrot_re

# The switch has 644 arms but ids run past them into the Czech block, so the
# scan goes well beyond and simply reports what resolves.
MAX_ID = 1400


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exe", nargs="?", default=hrot_re.DEFAULT_EXE)
    parser.add_argument("--find", help="only ids whose text contains this")
    parser.add_argument("--id", type=int, help="one id")
    parser.add_argument("--range", nargs=2, type=int, metavar=("LO", "HI"))
    arguments = parser.parse_args()

    image = hrot_re.Image(arguments.exe)

    if arguments.id is not None:
        ids = [arguments.id]
    elif arguments.range:
        ids = range(arguments.range[0], arguments.range[1] + 1)
    else:
        ids = range(MAX_ID)

    resolved = 0
    shown = 0

    for string_id in ids:
        try:
            text = image.string_by_id(string_id)
        except Exception as error:
            print(f"{string_id:5d}  <error {error}>", file=sys.stderr)
            continue

        if not text:
            continue

        resolved += 1
        if arguments.find and arguments.find.lower() not in text.lower():
            continue

        shown += 1
        print(f"{string_id:5d}  {text}")

    # An id that resolves to nothing is normal - the table is sparse - but a
    # run that resolves nothing at all means the addresses have moved.
    print(f"\n{resolved} id(s) resolved, {shown} shown", file=sys.stderr)
    if resolved == 0:
        print("nothing resolved: the string table addresses no longer match "
              "this build", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
