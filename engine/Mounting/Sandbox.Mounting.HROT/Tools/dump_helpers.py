#!/usr/bin/env python3
"""Disassemble selected HROT.exe helper functions for reverse engineering."""

from __future__ import annotations

import sys

import capstone
import pefile


def main() -> None:
    path = sys.argv[1]
    addresses = [int(value, 16) for value in sys.argv[2:]]
    pe = pefile.PE(path)
    image = pe.OPTIONAL_HEADER.ImageBase
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

    for address in addresses:
        print(f"===== {address:08X} =====")
        code = pe.get_data(address - image, 0x300)
        return_count = 0
        for instruction in md.disasm(code, address):
            print(
                f"{instruction.address:08X}  "
                f"{instruction.mnemonic:<8} {instruction.op_str}"
            )
            if instruction.mnemonic.startswith("ret"):
                return_count += 1
                if return_count >= 1:
                    break


if __name__ == "__main__":
    main()
