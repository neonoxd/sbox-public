#!/usr/bin/env python3
"""Rank direct-call targets used by HROT level prop/gameplay constructors."""

from __future__ import annotations

import collections
import sys

import capstone
import pefile


RANGES = {
    0: (0x00542CAC, 0x0054595C),
    1: (0x00596EF0, 0x00599FD0),
    2: (0x005EC248, 0x005EF5B4),
    4: (0x0064E0A8, 0x00651AF8),
    5: (0x006AA680, 0x006AD7A4),
    6: (0x00700404, 0x00704C30),
    7: (0x0074E914, 0x007519A4),
    8: (0x0079C6DC, 0x0079FA18),
    9: (0x007D9F0C, 0x007DCF50),
    10: (0x0082CFA0, 0x0083026C),
    11: (0x00874CDC, 0x00877AE0),
    12: (0x008A55EC, 0x008A819C),
    14: (0x008F3690, 0x008F6A04),
    15: (0x0092A7C8, 0x0092BC60),
    17: (0x009C058C, 0x009C20B8),
    20: (0x00A09C48, 0x00A0CD8C),
    21: (0x00A1F05C, 0x00A1F8A4),
    22: (0x00A882F0, 0x00A8AE44),
    23: (0x00ACC354, 0x00ACFC6C),
    24: (0x00AE20F4, 0x00AE2DC0),
    25: (0x00B9BA18, 0x00B9F338),
    26: (0x00BCDA08, 0x00BD0900),
    27: (0x00C03774, 0x00C061BC),
    28: (0x00C3727C, 0x00C39DB0),
    29: (0x00C7D558, 0x00C80770),
    100: (0x00C83FD8, 0x00C841E8),
    101: (0x00C97A28, 0x00C982F8),
    102: (0x00CAA088, 0x00CAAC50),
    103: (0x00CBD2C4, 0x00CBE070),
    104: (0x00D40814, 0x00D5D388),
}

KNOWN = {
    0x00DBDDE0: "PlaceOnFloor",
    0x00DBDE24: "PlaceAboveFloor",
    0x00DBDF04: "PlaceAtHeight",
    0x00DBE468: "PlaceAtCell",
    0x00DBDD64: "ScaleLastPlaced",
    0x00D5CD48: "CeilingFluorescent",
    0x00D5CFE8: "CeilingBakelite",
}


def main() -> None:
    path = sys.argv[1]
    wanted = {int(value, 16) for value in sys.argv[2:]}
    pe = pefile.PE(path)
    image = pe.OPTIONAL_HEADER.ImageBase
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    uses: dict[int, list[tuple[int, int, list[str]]]] = collections.defaultdict(list)

    for map_id, (start, end) in RANGES.items():
        code = pe.get_data(start - image, end - start)
        instructions = list(md.disasm(code, start))
        for index, insn in enumerate(instructions):
            if insn.mnemonic != "call" or not insn.operands:
                continue
            operand = insn.operands[0]
            if operand.type != capstone.x86.X86_OP_IMM:
                continue
            target = operand.imm
            before = [
                f"{item.mnemonic} {item.op_str}".strip()
                for item in instructions[max(0, index - 8):index]
            ]
            uses[target].append((map_id, insn.address, before))

    ranked = sorted(
        uses.items(),
        key=lambda item: (
            -len({use[0] for use in item[1]}),
            -len(item[1]),
            item[0],
        ),
    )
    for target, calls in ranked:
        if wanted and target not in wanted:
            continue
        maps = sorted({call[0] for call in calls})
        known = KNOWN.get(target, "")
        print(
            f"{target:08X} calls={len(calls):4} maps={len(maps):2} "
            f"{maps} {known}"
        )
        if (not known or wanted) and len(calls) >= 1:
            for map_id, address, before in calls[:12 if wanted else 2]:
                print(f"  map={map_id} at={address:08X}")
                for line in before:
                    print(f"    {line}")


if __name__ == "__main__":
    main()
