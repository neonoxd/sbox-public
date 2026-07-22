#!/usr/bin/env python3
"""Disassemble D77C20 including jump table branches."""

import struct
import sys
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

def main():
    pe = pefile.PE(sys.argv[1])
    image = pe.OPTIONAL_HEADER.ImageBase
    data = pe.__data__

    helper_va = 0x00D77C20
    rva = helper_va - image
    offset = pe.get_offset_from_rva(rva)

    # Read jump table at 0xD77D42 (28 bytes = 7 entries for behaviors 0-6, + ja to 0xd77dfe)
    jump_table_va = 0xD77D42
    jump_table_off = pe.get_offset_from_rva(jump_table_va - image)
    jump_targets = []
    for j in range(8):
        target_va = struct.unpack_from('<I', data, jump_table_off + j * 4)[0]
        jump_targets.append(target_va)
        print(f"Jump table[{j}] = 0x{target_va:08X}")

    # Disassemble from each branch
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    # Also disassemble from 0xD77D05 (the default path, behavior != 0-7)
    # Actually, the 'ja' at 0xd77d35 goes to 0xd77dfe for behavior > 7
    # Let's disassemble 0xD77D3B-0xD77E10 (the jump targets + common epilogue)

    for branch_idx, target in enumerate(jump_targets):
        rva2 = target - image
        off2 = pe.get_offset_from_rva(rva2)
        code = data[off2:off2+0x80]
        print(f"\n--- Branch {branch_idx} (behavior={branch_idx}) at 0x{target:08X} ---")
        for insn in md.disasm(code, target):
            print(f"  0x{insn.address:08X}: {insn.mnemonic:8s} {insn.op_str}")
            if insn.mnemonic == 'ret':
                break
            # Stop after a reasonable distance
            if insn.address > target + 0x60:
                break

if __name__ == "__main__":
    main()
