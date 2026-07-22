#!/usr/bin/env python3
"""Find immediate code references to an ASCII string in HROT.exe."""

from __future__ import annotations

import struct
import sys

import capstone
import pefile


def main() -> None:
    pe = pefile.PE(sys.argv[1])
    needle = sys.argv[2].encode("ascii").lower()
    data = bytes(pe.__data__)
    image = pe.OPTIONAL_HEADER.ImageBase
    addresses: list[int] = []
    lower = data.lower()
    start = 0
    while True:
        offset = lower.find(needle, start)
        if offset < 0:
            break
        try:
            addresses.append(image + pe.get_rva_from_offset(offset))
        except pefile.PEFormatError:
            pass
        start = offset + 1

    print("string addresses:", [f"{address:08X}" for address in addresses])
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    for section in pe.sections:
        if not section.IMAGE_SCN_MEM_EXECUTE:
            continue
        section_data = section.get_data()
        section_address = image + section.VirtualAddress
        instructions = list(md.disasm(section_data, section_address))
        for index, instruction in enumerate(instructions):
            raw = instruction.bytes
            if not any(
                struct.pack("<I", address) in raw for address in addresses
            ):
                continue
            print(f"===== xref {instruction.address:08X} =====")
            for item in instructions[max(0, index - 8):index + 9]:
                marker = ">" if item.address == instruction.address else " "
                print(
                    f"{marker} {item.address:08X} "
                    f"{item.mnemonic:<8} {item.op_str}"
                )


if __name__ == "__main__":
    main()
