#!/usr/bin/env python3
"""Find executable instructions accessing selected HROT cell-field offsets."""

from __future__ import annotations

import sys

import capstone
import pefile


def main() -> None:
    pe = pefile.PE(sys.argv[1])
    wanted = {int(value, 0) for value in sys.argv[2:]}
    image = pe.OPTIONAL_HEADER.ImageBase
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    md.skipdata = True

    for section in pe.sections:
        if not section.Name.rstrip(b"\0").startswith(b"CODE"):
            continue
        instructions = list(md.disasm(
            section.get_data(), image + section.VirtualAddress
        ))
        for index, instruction in enumerate(instructions):
            if instruction.id == 0:
                continue
            found = False
            for operand in instruction.operands:
                if (
                    operand.type == capstone.x86.X86_OP_MEM
                    and operand.mem.disp in wanted
                ):
                    found = True
                    break
            if not found:
                continue
            print(
                f"{instruction.address:08X} "
                f"{instruction.mnemonic:<8} {instruction.op_str}"
            )


if __name__ == "__main__":
    main()
