#!/usr/bin/env python3
"""Disassemble the tail of D77C20 to find atlas storage."""

import struct
import sys
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

def main():
    pe = pefile.PE(sys.argv[1])
    image = pe.OPTIONAL_HEADER.ImageBase
    data = pe.__data__

    # Continue disassembly from 0xD77E4F (after refPoint store)
    start_va = 0xD77E4F
    rva = start_va - image
    offset = pe.get_offset_from_rva(rva)
    code = data[offset:offset+0x200]

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for insn in md.disasm(code, start_va):
        print(f"  0x{insn.address:08X}: {insn.mnemonic:8s} {insn.op_str}")
        if insn.mnemonic == 'ret' or insn.address > start_va + 0x1E0:
            break

if __name__ == "__main__":
    main()
