#!/usr/bin/env python3
"""Disassemble D77C20 door helper to understand door struct layout."""

import sys
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

def main():
    pe = pefile.PE(sys.argv[1])
    image = pe.OPTIONAL_HEADER.ImageBase
    helper_va = 0x00D77C20
    rva = helper_va - image
    offset = pe.get_offset_from_rva(rva)
    data = pe.__data__

    # Disassemble ~1KB to cover the full function including jump table
    code = data[offset:offset+0x400]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    for insn in md.disasm(code, helper_va):
        print(f"  0x{insn.address:08X}: {insn.mnemonic:8s} {insn.op_str}")

if __name__ == "__main__":
    main()
