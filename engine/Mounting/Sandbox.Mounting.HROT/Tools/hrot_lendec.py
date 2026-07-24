#!/usr/bin/env python3
"""A 32-bit x86 instruction-length decoder, and the proof it is good enough.

The mount needs to walk the prop constructors *forward* to recover the arguments
category A of the decoder-gap census hides (a float parked with `mov [esp],imm`
and re-read by later placements through `push [esp+4]`). Walking forward needs
instruction lengths, and `HrotExecutableProps` is a backward byte-pattern matcher
with none.

This is the reference implementation of that decoder, mirrored by `HrotX86.cs` in
the mount. It returns **0 for anything it does not recognise** rather than
guessing a length, because a mis-measured instruction desyncs the walk and every
length after it; the forward pass treats 0 as "stop and mark unknown".

`--check` is the thing that makes it trustworthy: it decodes every instruction in
all 32 prop constructors and compares each boundary against capstone. Agreement
on every instruction is what says the subset is complete for this binary - and it
is a claim that has to be re-run after any game update, because it is a statement
about HROT's compiled code, not about x86.

Usage:
    hrot_lendec.py --check          verify every boundary against capstone
    hrot_lendec.py --unknown        show the forms it cannot decode, with counts
"""
from __future__ import annotations

import argparse
import collections
import sys

PREFIXES = {0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3}

# opcodes taking a modrm byte and no immediate
MODRM_ONLY = set()
MODRM_ONLY |= {0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0A, 0x0B,
               0x10, 0x11, 0x12, 0x13, 0x18, 0x19, 0x1A, 0x1B,
               0x20, 0x21, 0x22, 0x23, 0x28, 0x29, 0x2A, 0x2B,
               0x30, 0x31, 0x32, 0x33, 0x38, 0x39, 0x3A, 0x3B}
MODRM_ONLY |= {0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8D, 0x8F}
MODRM_ONLY |= {0xD0, 0xD1, 0xD2, 0xD3}
MODRM_ONLY |= {0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF}   # x87
MODRM_ONLY |= {0xFE, 0xFF}

MODRM_IMM8 = {0x6B, 0x80, 0x83, 0xC0, 0xC1, 0xC6}
MODRM_IMM32 = {0x69, 0x81, 0xC7}                                  # imm16 under 0x66

# no modrm; fixed extra bytes
FIXED = {
    0x06: 0, 0x07: 0, 0x0E: 0, 0x16: 0, 0x17: 0, 0x1E: 0, 0x1F: 0,
    0x27: 0, 0x2F: 0, 0x37: 0, 0x3F: 0,
    0x60: 0, 0x61: 0, 0x90: 0, 0x98: 0, 0x99: 0, 0x9B: 0,
    0x9C: 0, 0x9D: 0, 0x9E: 0, 0x9F: 0,
    0xA4: 0, 0xA5: 0, 0xA6: 0, 0xA7: 0, 0xAA: 0, 0xAB: 0,
    0xAC: 0, 0xAD: 0, 0xAE: 0, 0xAF: 0,
    0xC3: 0, 0xC9: 0, 0xCB: 0, 0xCC: 0, 0xCE: 0, 0xCF: 0,
    0xF4: 0, 0xF5: 0, 0xF8: 0, 0xF9: 0, 0xFA: 0, 0xFB: 0, 0xFC: 0, 0xFD: 0,
    0x6A: 1, 0xCD: 1, 0xD4: 1, 0xD5: 1, 0xD7: 0, 0xE0: 1, 0xE1: 1, 0xE2: 1,
    0xE3: 1, 0xEB: 1, 0x3C: 1, 0xA8: 1,
    0x68: 4, 0xE8: 4, 0xE9: 4, 0xA9: 4,
    0xC2: 2, 0xCA: 2,
    0xA0: 4, 0xA1: 4, 0xA2: 4, 0xA3: 4,
}
for op in range(0x40, 0x60):      # inc/dec/push/pop r32
    FIXED[op] = 0
for op in range(0x70, 0x80):      # jcc rel8
    FIXED[op] = 1
for op in range(0xB0, 0xB8):      # mov r8, imm8
    FIXED[op] = 1
# 0xB8-0xBF (mov r32, imm32) handled specially - operand size depends on 0x66
# 0x04/0x0C/... al,imm8 and 0x05/0x0D/... eax,imm32 handled by the arith pattern


def _modrm_len(code: int, i: int, addr32: bool) -> int:
    """Bytes consumed by modrm (+sib +disp), or -1 if truncated."""
    if i >= len(code):
        return -1
    modrm = code[i]
    mod, rm = modrm >> 6, modrm & 7
    size = 1
    if mod != 3 and rm == 4:                       # SIB
        if i + 1 >= len(code):
            return -1
        sib = code[i + 1]
        size += 1
        if mod == 0 and (sib & 7) == 5:
            size += 4
    if mod == 1:
        size += 1
    elif mod == 2:
        size += 4
    elif mod == 0 and rm == 5:
        size += 4
    return size


def length(code: bytes, i: int) -> int:
    """Length of the instruction at `i`, or 0 if this decoder does not know it."""
    start = i
    opsize16 = False
    while i < len(code) and code[i] in PREFIXES:
        if code[i] == 0x66:
            opsize16 = True
        i += 1
    if i >= len(code):
        return 0
    op = code[i]
    i += 1

    if op == 0x0F:
        if i >= len(code):
            return 0
        op2 = code[i]
        i += 1
        if 0x80 <= op2 <= 0x8F:                    # jcc rel32
            return (i + 4) - start
        if op2 in (0xB6, 0xB7, 0xBE, 0xBF, 0xAF) or 0x90 <= op2 <= 0x9F:
            n = _modrm_len(code, i, True)
            return 0 if n < 0 else (i + n) - start
        return 0

    if 0xB8 <= op <= 0xBF:                          # mov r32/r16, imm
        return (i + (2 if opsize16 else 4)) - start

    # arithmetic block 0x00-0x3F: xx0-xx3 modrm, xx4 al,imm8, xx5 eax,imm32
    if op < 0x40 and (op & 7) in (4, 5) and (op >> 3) < 8:
        return (i + (1 if (op & 7) == 4 else (2 if opsize16 else 4))) - start

    if op in MODRM_ONLY:
        n = _modrm_len(code, i, True)
        return 0 if n < 0 else (i + n) - start

    if op in MODRM_IMM8:
        n = _modrm_len(code, i, True)
        return 0 if n < 0 else (i + n + 1) - start

    if op in MODRM_IMM32:
        n = _modrm_len(code, i, True)
        return 0 if n < 0 else (i + n + (2 if opsize16 else 4)) - start

    if op in (0xF6, 0xF7):                          # grp3: /0 and /1 carry an imm
        n = _modrm_len(code, i, True)
        if n < 0:
            return 0
        extra = 0
        if (code[i] >> 3) & 7 in (0, 1):
            extra = 1 if op == 0xF6 else (2 if opsize16 else 4)
        return (i + n + extra) - start

    if op in FIXED:
        return (i + FIXED[op]) - start

    return 0


def _check(unknown_only: bool) -> int:
    import hrot_re
    from dump_signs import load_constructors

    img = hrot_re.Image()
    ranges = load_constructors()
    agree = mismatch = unknown = total = 0
    forms: collections.Counter = collections.Counter()

    for map_id, (start, end) in sorted(ranges.items()):
        off = img.va2off(start)
        code = img.data[off:off + (end - start)]
        # capstone's own boundaries are the reference
        expected = {}
        for insn in img._md.disasm(code, start):
            if insn.mnemonic != ".byte":
                expected[insn.address - start] = insn.size

        for pos, size in expected.items():
            total += 1
            got = length(code, pos)
            if got == 0:
                unknown += 1
                forms[" ".join(f"{b:02X}" for b in code[pos:pos + 3])] += 1
            elif got == size:
                agree += 1
            else:
                mismatch += 1
                if mismatch <= 10:
                    print(f"  MISMATCH map {map_id} +{pos:#x}: got {got}, capstone {size}"
                          f"  bytes {' '.join(f'{b:02X}' for b in code[pos:pos+8])}",
                          file=sys.stderr)

    if unknown_only:
        print("forms this decoder does not know (leading bytes, by count):")
        for form, count in forms.most_common(40):
            print(f"  {form}  x{count}")
        return 0

    print(f"{total} instructions compared against capstone")
    print(f"  agree     {agree}")
    print(f"  MISMATCH  {mismatch}")
    print(f"  unknown   {unknown}   (decoder returns 0; forward pass stops)")
    return 1 if mismatch else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--unknown", action="store_true")
    args = parser.parse_args()
    if args.check or args.unknown:
        return _check(args.unknown)
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
