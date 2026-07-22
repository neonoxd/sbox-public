#!/usr/bin/env python3
"""Disassemble D77C20 to understand door struct layout."""

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

    # Disassemble roughly 400 bytes of D77C20
    code = data[offset:offset+0x200]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    for insn in md.disasm(code, helper_va):
        # Highlight interesting instructions
        note = ""
        if "ebp" in insn.op_str:
            note = "  ; stack arg"
        if "0x4613f4" in insn.op_str or "0x4613F4" in insn.op_str:
            note = "  ; Vector3 store?"
        if "eax" in insn.op_str and "ecx" in insn.op_str:
            note = "  ; refPoint setup?"
        print(f"  0x{insn.address:08X}: {insn.mnemonic:8s} {insn.op_str}{note}")

if __name__ == "__main__":
    main()
