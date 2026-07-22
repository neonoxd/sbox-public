#!/usr/bin/env python3
"""Find how HROT renderer reads door atlas values from the door struct."""

import struct
import sys
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

def main():
    pe = pefile.PE(sys.argv[1])
    image = pe.OPTIONAL_HEADER.ImageBase
    data = pe.__data__

    # The door array base is at 0x17D40C8. The door struct is 124 bytes.
    # Atlas values are at door+0x64, 0x68, 0x6C, 0x70.
    # We need to find code that reads from these offsets.

    # Search for references to the door struct + atlas offsets.
    # The renderer likely loads the array base, computes index*124, and accesses +0x64..0x70.
    # Pattern: [reg + reg*N + 0x64] where N is related to 124 (0x7C)

    md = Cs(CS_ARCH_X86, CS_MODE_32)

    # Scan the .text section for instructions referencing door+0x64..0x70
    # Look for displacements 0x64, 0x68, 0x6C, 0x70 with base 0x17D40C8
    # Also search for indirect references through the array

    # Search for mov reg, [base + offset] where base is the door array
    # and offset includes 0x64/0x68/0x6C/0x70
    
    # Actually, let's search for all instructions that reference the door array base
    # 0x17D40C8 = 0x017D40C8
    
    door_base = 0x17D40C8
    
    # Search for push/mov instructions referencing this address
    for i in range(len(data) - 4):
        # Look for push imm32 with door base
        if data[i] == 0x68:
            val = struct.unpack_from('<I', data, i + 1)[0]
            if val == door_base:
                rva = pe.get_rva_from_offset(i)
                va = image + rva
                print(f"0x{va:08X}: push 0x{door_base:08X} (door array base)")
        
        # Look for mov reg, imm32 with door base
        if data[i] in (0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF):
            val = struct.unpack_from('<I', data, i + 1)[0]
            if val == door_base:
                rva = pe.get_rva_from_offset(i)
                va = image + rva
                reg = ['eax','ecx','edx','ebx','esp','ebp','esi','edi'][data[i] - 0xB8]
                print(f"0x{va:08X}: mov {reg}, 0x{door_base:08X}")

    # Also look for references to door+0x64..0x70 after array indexing
    # The pattern would be something like: mov eax, [edi + esi*4 + 0x64]
    # where edi = base, esi = index * 31
    
    # Search for instructions with displacement 0x64..0x70
    print("\n--- Searching for door struct offset references ---")
    for target_offset in [0x64, 0x68, 0x6C, 0x70]:
        # Search for instructions with this displacement
        code = data
        count = 0
        for insn in md.disasm(code, image):
            if count > 500000:
                break
            count += 1
            if f"+ 0x{target_offset:x}" in insn.op_str or f"+ 0x{target_offset:02x}" in insn.op_str:
                # Check if this references the door array (edi/esi pattern)
                if 'edi' in insn.op_str or 'esi' in insn.op_str:
                    print(f"  0x{insn.address:08X}: {insn.mnemonic:8s} {insn.op_str}")
    
if __name__ == "__main__":
    main()
