#!/usr/bin/env python3
"""Dump HROT's map-id -> level-name mapping by reading its own GetLevelName.

This is a port, not an inference. Three structures chain together:

    GetLevelName        0x00DA4939  bounds the map id to 0..0x68, indexes the
                                    byte table at 0x00DA4960, jumps through the
                                    jump table at 0x00DA49C9
    each arm                        mov edx, esi / mov ax, <stringId> / call
                                    LoadString at 0x00DB9AA0
    localisation switch 0x00DA9FD8  jump table at 0x00DAA004, 644 entries; each
                                    arm assigns one Delphi literal

The mount does this itself at load time, in HrotExecutableMapData.ReadMapNames -
no name is stored in the C#. This script is for inspecting the table offline and
for diffing the decode against what a given build reports.

An earlier version of HrotMapNames stored the literals aligned to map ids
positionally. The literals are in source order and the map ids are not, so that
was right only on maps 1 and 2 - the only two anyone had checked.

Usage:
    dump_level_names.py [path-to-HROT.exe]      prints "mapId  strId  name"
    dump_level_names.py --csharp                prints a C# dictionary body, for diffing
"""

from __future__ import annotations

import struct
import sys

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs

DEFAULT_EXE = r"D:\SteamLibrary\steamapps\common\HROT\HROT.exe"

LEVEL_NAME_BYTE_TABLE = 0x00DA4960
LEVEL_NAME_JUMP_TABLE = 0x00DA49C9
STRING_JUMP_TABLE = 0x00DAA004
MAX_MAP_ID = 0x68

# The names carry Czech diacritics; the mount stores them transliterated so the
# scene metadata stays ASCII.
TRANSLITERATE = str.maketrans({
    "ů": "u", "š": "s", "č": "c", "í": "i", "é": "e",
    "á": "a", "ž": "z", "ř": "r", "ě": "e", "ý": "y",
    "ď": "d", "ť": "t", "ň": "n", "ú": "u", "Ů": "U",
    "Š": "S", "Č": "C", "Ž": "Z", "Ř": "R",
})


class Image:
    def __init__(self, path: str):
        self.pe = pefile.PE(path)
        self.data = open(path, "rb").read()
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.md = Cs(CS_ARCH_X86, CS_MODE_32)

    def offset(self, va: int) -> int:
        rva = va - self.base
        for s in self.pe.sections:
            size = max(s.SizeOfRawData, s.Misc_VirtualSize)
            if s.VirtualAddress <= rva < s.VirtualAddress + size:
                return s.PointerToRawData + (rva - s.VirtualAddress)
        raise ValueError(f"VA 0x{va:08X} is not in any section")

    def dword(self, va: int) -> int:
        return struct.unpack_from("<I", self.data, self.offset(va))[0]

    def byte(self, va: int) -> int:
        return self.data[self.offset(va)]

    def delphi_string(self, va: int) -> str:
        o = self.offset(va)
        length = struct.unpack_from("<I", self.data, o - 4)[0]
        if length == 0 or length > 300:
            raise ValueError(f"implausible Delphi length {length} at 0x{va:08X}")
        return self.data[o:o + length].decode("cp1250")

    def first_imm(self, va: int, prefixes: tuple[str, ...]) -> int | None:
        """First immediate moved into one of `prefixes` within one arm."""
        o = self.offset(va)
        for insn in self.md.disasm(self.data[o:o + 24], va):
            if insn.mnemonic == "mov" and insn.op_str.startswith(prefixes):
                return int(insn.op_str.split("0x")[1], 16)
            if insn.mnemonic == "ret":
                break
        return None


def string_for_id(img: Image, string_id: int) -> str | None:
    arm = img.dword(STRING_JUMP_TABLE + string_id * 4)
    literal = img.first_imm(arm, ("edx, 0x",))
    return img.delphi_string(literal) if literal else None


def level_names(img: Image) -> dict[int, tuple[int, str]]:
    out: dict[int, tuple[int, str]] = {}
    for map_id in range(MAX_MAP_ID + 1):
        case = img.byte(LEVEL_NAME_BYTE_TABLE + map_id)
        arm = img.dword(LEVEL_NAME_JUMP_TABLE + case * 4)
        string_id = img.first_imm(arm, ("eax, 0x", "ax, 0x"))
        if string_id is None:
            continue
        name = string_for_id(img, string_id)
        if name:
            out[map_id] = (string_id, name)
    return out


def main() -> None:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    as_csharp = "--csharp" in sys.argv
    img = Image(args[0] if args else DEFAULT_EXE)

    names = level_names(img)
    # Map 1 is Kosmonautu Station independently: it is the map carrying the
    # metro sign prop, the metro stairs and the "kosmonauti" ladder. If this
    # anchor ever fails, the table addresses above are for a different build.
    anchor = names.get(1, (0, ""))[1]
    if not anchor.startswith("Kosmonaut"):
        print(f"WARNING: map 1 resolved to {anchor!r}, expected Kosmonautu Station",
              file=sys.stderr)

    if as_csharp:
        for map_id, (_, name) in sorted(names.items()):
            ascii_name = name.translate(TRANSLITERATE).replace('"', '\\"')
            print(f'\t\t[{map_id}] = "{ascii_name}",')
        return

    print("mapId  strId  name")
    for map_id, (string_id, name) in sorted(names.items()):
        print(f"{map_id:5}  {string_id:5}  {name.translate(TRANSLITERATE)}")


if __name__ == "__main__":
    main()
