#!/usr/bin/env python3
"""Find code instructions referencing addresses inside a global-data range."""

from __future__ import annotations

import sys

import capstone
import pefile


def main() -> None:
    pe = pefile.PE(sys.argv[1])
    lower = int(sys.argv[2], 0)
    upper = int(sys.argv[3], 0)
    image = pe.OPTIONAL_HEADER.ImageBase
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True

    for section in pe.sections:
        if not section.IMAGE_SCN_MEM_EXECUTE:
            continue
        code = section.get_data()
        address = image + section.VirtualAddress
        instructions = list(md.disasm(code, address))
        for index, instruction in enumerate(instructions):
            references = []
            for operand in instruction.operands:
                if operand.type == capstone.x86.X86_OP_IMM:
                    references.append(operand.imm & 0xFFFFFFFF)
                elif operand.type == capstone.x86.X86_OP_MEM:
                    references.append(operand.mem.disp & 0xFFFFFFFF)
            for offset in range(max(0, len(instruction.bytes) - 3)):
                references.append(int.from_bytes(
                    instruction.bytes[offset:offset + 4], "little"
                ))
            if not any(lower <= value < upper for value in references):
                continue
            print(f"===== reference {instruction.address:08X} =====")
            for item in instructions[max(0, index - 6):index + 7]:
                marker = ">" if item.address == instruction.address else " "
                print(
                    f"{marker} {item.address:08X} "
                    f"{item.mnemonic:<8} {item.op_str}"
                )


if __name__ == "__main__":
    main()
