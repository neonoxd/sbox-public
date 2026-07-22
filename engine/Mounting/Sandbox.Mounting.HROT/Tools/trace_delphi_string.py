#!/usr/bin/env python3
"""Trace Delphi short/ANSI string data references and nearby code."""

from __future__ import annotations

import struct
import sys

import capstone
import pefile


def main() -> None:
    pe = pefile.PE(sys.argv[1])
    needle = sys.argv[2].encode("ascii").lower()
    data = bytes(pe.__data__)
    lower = data.lower()
    image = pe.OPTIONAL_HEADER.ImageBase
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

    string_offsets = []
    cursor = 0
    while True:
        cursor = lower.find(needle, cursor)
        if cursor < 0:
            break
        string_offsets.append(cursor)
        cursor += 1

    for string_offset in string_offsets:
        address = image + pe.get_rva_from_offset(string_offset)
        print(f"===== string {address:08X} file={string_offset:08X} =====")
        print(data[max(0, string_offset - 24):string_offset + 96])
        for candidate in range(address - 16, address + 17):
            packed = struct.pack("<I", candidate)
            reference = 0
            while True:
                reference = data.find(packed, reference)
                if reference < 0:
                    break
                try:
                    ref_address = image + pe.get_rva_from_offset(reference)
                except pefile.PEFormatError:
                    reference += 1
                    continue
                print(
                    f"pointer {candidate:08X} stored at "
                    f"{ref_address:08X} file={reference:08X}"
                )
                start = max(0, reference - 64)
                try:
                    start_address = image + pe.get_rva_from_offset(start)
                except pefile.PEFormatError:
                    reference += 1
                    continue
                for instruction in md.disasm(data[start:reference + 80], start_address):
                    marker = ">" if instruction.address <= ref_address < (
                        instruction.address + instruction.size
                    ) else " "
                    print(
                        f"{marker} {instruction.address:08X} "
                        f"{instruction.mnemonic:<8} {instruction.op_str}"
                    )
                reference += 1


if __name__ == "__main__":
    main()
