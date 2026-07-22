#!/usr/bin/env python3
"""Disassemble a virtual-address range from a 32-bit PE file."""

from __future__ import annotations

import sys

import capstone
import pefile


def main() -> None:
    pe = pefile.PE(sys.argv[1])
    start = int(sys.argv[2], 0)
    end = int(sys.argv[3], 0)
    image = pe.OPTIONAL_HEADER.ImageBase
    code = pe.get_data(start - image, end - start)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    for instruction in md.disasm(code, start):
        print(
            f"{instruction.address:08X}  "
            f"{instruction.bytes.hex():<20} "
            f"{instruction.mnemonic:<8} {instruction.op_str}"
        )


if __name__ == "__main__":
    main()
