#!/usr/bin/env python3
"""Show executable map-constructor call sites for a static model ID."""

from __future__ import annotations

import sys

import capstone
import pefile

from inventory_entity_helpers import RANGES


def main() -> None:
    pe = pefile.PE(sys.argv[1])
    model_id = int(sys.argv[2], 0)
    image = pe.OPTIONAL_HEADER.ImageBase
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

    for map_id, (start, end) in RANGES.items():
        code = pe.get_data(start - image, end - start)
        instructions = list(md.disasm(code, start))
        for index, instruction in enumerate(instructions):
            if instruction.mnemonic != "mov" or instruction.op_str != f"ax, {model_id:#x}":
                continue
            print(f"===== map {map_id} at {instruction.address:08X} =====")
            for item in instructions[max(0, index - 8):min(len(instructions), index + 8)]:
                marker = ">" if item.address == instruction.address else " "
                print(
                    f"{marker} {item.address:08X}  "
                    f"{item.mnemonic:<8} {item.op_str}"
                )


if __name__ == "__main__":
    main()
