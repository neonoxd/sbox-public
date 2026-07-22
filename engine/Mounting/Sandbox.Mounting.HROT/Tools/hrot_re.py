#!/usr/bin/env python3
"""Shared helpers for reverse-engineering HROT.exe.

Every investigation in this directory needs the same handful of things: map a
virtual address to a file offset, read a Delphi string, disassemble a region
that does not start on an instruction boundary, find who references an address,
dump a jump table, replay a map constructor. Before this existed those were
rewritten per script - 60 copies of `va2off` in one session - which cost far
more in repeated *bugs* than in typing.

Three of those bugs are now impossible to hit through this module, and all three
produced confident, wrong, empty results:

  * capstone's ``X86_OP_IMM`` is **2**, not 1. Comparing against 1 silently
    matches nothing, so a scan reports "no call sites" for code that is full of
    them.
  * ``Cs.disasm`` stops dead at the first byte it cannot decode. Without
    ``skipdata`` a sweep quietly covers a fraction of what you asked for and
    returns clean, empty, false negatives.
  * A region rarely starts on an instruction boundary. Disassembling from a
    guessed address yields plausible-looking nonsense; :meth:`Image.disasm_at`
    searches for the alignment that actually decodes the instruction you want.

Usage::

    from hrot_re import Image, Grid, Live

    img = Image()
    print(img.delphi_string(0x00DAFCF8))
    for insn in img.disasm(0x00D8B3A2, 0x80):
        print(insn)
    print(img.callers(0x00D5D388))

    grid = Grid(2)
    print(grid.cell(38, 54).floor_height)

    live = Live()
    print(live.map_id())
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from typing import Iterable, Iterator

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG  # noqa: F401 - re-exported

DEFAULT_EXE = r"D:\SteamLibrary\steamapps\common\HROT\HROT.exe"

# Grid geometry. See REVERSE_ENGINEERING.md section 9.
GRID_BASE = 0x00E626A0
GRID_SIZE = 101
CELL_SIZE = 0x1E0
ROW_STRIDE = GRID_SIZE * CELL_SIZE          # 0xBD60

# Frequently used addresses, so they are written down once.
MAP_ID_ADDR = 0x017B9460                    # signed byte, current map id
LOAD_LEVEL = 0x00D5D388                     # LoadLevel( edx = map id )
TRIGGER_EXECUTOR = 0x00D7A31C               # RunTrigger( eax = ctx, edx = record )
TRIGGER_JUMP_TABLE = 0x00D7A392             # 90 entries
STRING_JUMP_TABLE = 0x00DAA004              # 644 entries
LEVEL_NAME_BYTE_TABLE = 0x00DA4960
LEVEL_NAME_JUMP_TABLE = 0x00DA49C9
MODEL_REGISTER = 0x00DBE7E0
TRIGGER_ATTACH = 0x00DBE688

CP1250 = "cp1250"


class Image:
    """The executable: address mapping, reads, strings and disassembly."""

    def __init__(self, path: str = DEFAULT_EXE):
        self.path = path
        self.pe = pefile.PE(path)
        self.data = open(path, "rb").read()
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        # skipdata is not optional; see the module docstring.
        self._md = Cs(CS_ARCH_X86, CS_MODE_32)
        self._md.detail = True
        self._md.skipdata = True

    # -- address mapping ---------------------------------------------------

    def va2off(self, va: int) -> int | None:
        rva = va - self.base
        for section in self.pe.sections:
            size = max(section.Misc_VirtualSize, section.SizeOfRawData)
            if section.VirtualAddress <= rva < section.VirtualAddress + size:
                offset = section.PointerToRawData + (rva - section.VirtualAddress)
                return offset if 0 <= offset < len(self.data) else None
        return None

    def off2va(self, offset: int) -> int | None:
        for section in self.pe.sections:
            size = max(section.SizeOfRawData, section.Misc_VirtualSize)
            if section.PointerToRawData <= offset < section.PointerToRawData + size:
                return self.base + section.VirtualAddress + (offset - section.PointerToRawData)
        return None

    def executable_sections(self) -> Iterator[tuple[int, bytes]]:
        """(virtual address, raw bytes) for each executable section."""
        for section in self.pe.sections:
            if not section.Characteristics & 0x20000000:
                continue
            start = section.PointerToRawData
            yield (self.base + section.VirtualAddress,
                   self.data[start:start + section.SizeOfRawData])

    # -- scalar reads ------------------------------------------------------

    def _at(self, va: int, size: int) -> bytes | None:
        offset = self.va2off(va)
        if offset is None or offset + size > len(self.data):
            return None
        return self.data[offset:offset + size]

    def u8(self, va: int) -> int | None:
        raw = self._at(va, 1)
        return raw[0] if raw else None

    def u16(self, va: int) -> int | None:
        raw = self._at(va, 2)
        return struct.unpack("<H", raw)[0] if raw else None

    def u32(self, va: int) -> int | None:
        raw = self._at(va, 4)
        return struct.unpack("<I", raw)[0] if raw else None

    def i32(self, va: int) -> int | None:
        raw = self._at(va, 4)
        return struct.unpack("<i", raw)[0] if raw else None

    def f32(self, va: int) -> float | None:
        raw = self._at(va, 4)
        return struct.unpack("<f", raw)[0] if raw else None

    # -- strings -----------------------------------------------------------

    def delphi_string(self, va: int, max_length: int = 300) -> str | None:
        """A Delphi long string: length dword at ``va - 4``, bytes at ``va``."""
        length = self.u32(va - 4)
        if length is None or length == 0 or length > max_length:
            return None
        raw = self._at(va, length)
        return raw.decode(CP1250, errors="replace") if raw else None

    def cstring(self, va: int, max_length: int = 128) -> str | None:
        offset = self.va2off(va)
        if offset is None:
            return None
        end = offset
        limit = min(len(self.data), offset + max_length)
        while end < limit and self.data[end] != 0:
            end += 1
        return self.data[offset:end].decode("latin-1") if end > offset else None

    # -- disassembly -------------------------------------------------------

    def disasm(self, va: int, length: int):
        """Decode ``length`` bytes from ``va``, assuming it is aligned."""
        offset = self.va2off(va)
        if offset is None:
            return []
        return list(self._md.disasm(self.data[offset:offset + length], va))

    def disasm_at(self, target_va: int, before: int = 0x40, after: int = 0x40):
        """Decode a window around ``target_va``, finding the alignment first.

        Regions rarely begin on an instruction boundary. This tries each start
        offset and keeps the one whose decode actually lands on ``target_va``,
        which is what stops a plausible-looking but wrong disassembly.
        Returns ``[]`` when no alignment hits it - treat that as "look again",
        not as "nothing there".
        """
        for shift in range(16):
            start = target_va - before + shift
            decoded = self.disasm(start, before + after)
            if any(insn.address == target_va for insn in decoded):
                return decoded
        return []

    def function_start(self, inside_va: int, search: int = 0x600) -> int | None:
        """Scan back for a ``push ebp; mov ebp, esp`` prologue."""
        offset = self.va2off(inside_va)
        if offset is None:
            return None
        for delta in range(4, search):
            if self.data[offset - delta:offset - delta + 3] == b"\x55\x8b\xec":
                return inside_va - delta
        return None

    def sweep(self, lo: int | None = None, hi: int | None = None, anchors: int = 4):
        """Yield instructions across the executable sections.

        Several alignments are tried so a desynchronised stretch does not hide
        code. Addresses can repeat between anchors; de-duplicate by
        ``insn.address`` if that matters.
        """
        for start, raw in self.executable_sections():
            for shift in range(anchors):
                for insn in self._md.disasm(raw[shift:], start + shift):
                    if lo is not None and insn.address < lo:
                        continue
                    if hi is not None and insn.address >= hi:
                        break
                    yield insn

    # -- searching ---------------------------------------------------------

    def find_bytes(self, pattern: bytes) -> list[int]:
        """Virtual addresses where a literal byte pattern occurs."""
        out = []
        for match in re.finditer(re.escape(pattern), self.data):
            va = self.off2va(match.start())
            if va is not None:
                out.append(va)
        return out

    def xrefs(self, va: int) -> list[int]:
        """Everywhere the 32-bit value ``va`` appears - data or immediates."""
        return self.find_bytes(struct.pack("<I", va))

    def callers(self, target_va: int) -> list[int]:
        """Addresses of ``E8 rel32`` calls that land on ``target_va``."""
        out = []
        for match in re.finditer(b"\xe8", self.data):
            offset = match.start()
            va = self.off2va(offset)
            if va is None or offset + 5 > len(self.data):
                continue
            rel = struct.unpack_from("<i", self.data, offset + 1)[0]
            if (va + 5 + rel) & 0xFFFFFFFF == target_va:
                out.append(va)
        return out

    # -- tables ------------------------------------------------------------

    def jump_table(self, base_va: int, count: int) -> list[int]:
        return [self.u32(base_va + i * 4) for i in range(count)]

    def byte_table(self, base_va: int, count: int) -> list[int]:
        return [self.u8(base_va + i) for i in range(count)]

    def switch_targets(self, base_va: int, byte_table_va: int, count: int) -> dict[int, int]:
        """Resolve a Delphi ``byte table -> jump table`` switch.

        Both HROT dispatches found so far use this shape: bound the index, read
        a case number from a byte table, then jump through a dword table.
        """
        cases = self.byte_table(byte_table_va, count)
        return {index: self.u32(base_va + case * 4)
                for index, case in enumerate(cases) if case is not None}

    def string_by_id(self, string_id: int) -> str | None:
        """A localisation string, through the 644-entry switch at 0xDAA004."""
        arm = self.u32(STRING_JUMP_TABLE + string_id * 4)
        if arm is None:
            return None
        for insn in self.disasm(arm, 32):
            if insn.mnemonic == "mov" and insn.op_str.startswith("edx, 0x"):
                return self.delphi_string(int(insn.op_str.split("0x")[1], 16))
        return None


# ---------------------------------------------------------------------------
# Static map reconstruction
# ---------------------------------------------------------------------------

def world_ranges() -> dict[int, tuple[int, int]]:
    from hrot_world_ranges import WORLD_RANGES
    return WORLD_RANGES


def is_world_field(displacement: int, width: int, length: int) -> bool:
    """The mount's replay filter, kept in step with HrotExecutableMapData.

    **Prefer ``Grid(map_id, filtered=False)`` when exploring.** This filter is
    what hid cell fields 0x09 and 0x0C - the water flag and its surface height -
    for the entire time the liquid pass was believed to be blocked on something
    else. A filter that drops a field you have not thought of yet is invisible.
    """
    if displacement < 0 or displacement + width > length:
        return False
    field = displacement % CELL_SIZE
    if field in {
        0x06,
        0x09, 0x0C,          # water type and surface height
        0x10,                # overlay quad gate
        0x1C, 0x20, 0x24, 0x28, 0x2C, 0x30, 0x34, 0x38,
        0x3C, 0x40, 0x44, 0x48, 0x4C, 0x50, 0x54, 0x58,
        0x5C, 0x60, 0x64, 0x68, 0x6C, 0x70, 0x74, 0x78,
        0x1D5, 0x1D6,
    }:
        return True
    return any(start <= field < start + 0x54 for start in (0x7C, 0xD0, 0x124, 0x178))


@dataclass
class Cell:
    data: bytes
    offset: int

    def u8(self, field: int) -> int:
        return self.data[self.offset + field]

    def i8(self, field: int) -> int:
        return struct.unpack_from("<b", self.data, self.offset + field)[0]

    def f32(self, field: int) -> float:
        return struct.unpack_from("<f", self.data, self.offset + field)[0]

    def ivec2(self, field: int) -> tuple[int, int]:
        return struct.unpack_from("<ii", self.data, self.offset + field)

    # Named accessors for the fields used most often.
    @property
    def has_floor(self) -> bool: return self.u8(0x34) != 0
    @property
    def has_ceiling(self) -> bool: return self.u8(0x24) != 0
    @property
    def floor_height(self) -> float: return self.f32(0x38)
    @property
    def ceiling_height(self) -> float: return self.f32(0x28)
    @property
    def wall_base(self) -> float: return self.i8(0x1D5) * 1.5625
    @property
    def stair_direction(self) -> int: return self.u8(0x1D6)
    @property
    def water_type(self) -> int: return self.u8(0x09)
    @property
    def water_height(self) -> float: return self.f32(0x0C)
    @property
    def volume_index(self) -> int: return self.u8(0x19)
    @property
    def floor_material(self) -> tuple[int, int]: return self.ivec2(0x2C)


class Grid:
    """A map's 101x101 cell grid, replayed from its world constructor."""

    def __init__(self, map_id: int, image: Image | None = None, filtered: bool = True):
        self.map_id = map_id
        self.image = image or Image()
        self.filtered = filtered
        self.data = self._replay()

    def _replay(self) -> bytearray:
        start, end = world_ranges()[self.map_id]
        image = self.image
        code_start = image.va2off(start)
        code = image.data[code_start:code_start + (end - start)]

        grid = bytearray(GRID_SIZE * GRID_SIZE * CELL_SIZE)
        for index in range(GRID_SIZE * GRID_SIZE):
            offset = index * CELL_SIZE
            grid[offset + 0x06] = 1
            struct.pack_into("<f", grid, offset + 0x28, 1.5625)
            struct.pack_into("<f", grid, offset + 0x14, -2000.0)

        def accept(displacement: int, width: int) -> bool:
            if self.filtered:
                return is_world_field(displacement, width, len(grid))
            return 0 <= displacement and displacement + width <= len(grid)

        # mov byte [eax+disp32], imm8
        for match in re.finditer(re.escape(b"\xc6\x80"), code):
            o = match.start()
            d = struct.unpack_from("<i", code, o + 2)[0]
            if accept(d, 1):
                grid[d] = code[o + 6]
        # mov dword [eax+disp32], imm32
        for match in re.finditer(re.escape(b"\xc7\x80"), code):
            o = match.start()
            d = struct.unpack_from("<i", code, o + 2)[0]
            if accept(d, 4):
                grid[d:d + 4] = code[o + 6:o + 10]
        # mov [eax+disp32], edx - always a cleared edx in these constructors
        for match in re.finditer(re.escape(b"\x89\x90"), code):
            o = match.start()
            d = struct.unpack_from("<i", code, o + 2)[0]
            if accept(d, 4):
                grid[d:d + 4] = b"\0\0\0\0"
        return grid

    def cell(self, row: int, column: int) -> Cell:
        """Row-major, matching the disassembly's ``row * 0xBD60 + column * 0x1E0``.

        Note the C# ``HrotMapGrid.Cell( x, y )`` indexes ``y * GridSize + x``,
        i.e. **column first**. Passing them the same way round is a transpose
        that still finds the right *number* of cells and puts every one of them
        in the wrong place.
        """
        return Cell(self.data, (row * GRID_SIZE + column) * CELL_SIZE)

    def cells(self) -> Iterator[tuple[int, int, Cell]]:
        for row in range(GRID_SIZE):
            for column in range(GRID_SIZE):
                yield row, column, self.cell(row, column)

    def where(self, predicate) -> list[tuple[int, int, Cell]]:
        return [(r, c, cell) for r, c, cell in self.cells() if predicate(cell)]


# ---------------------------------------------------------------------------
# Live process
# ---------------------------------------------------------------------------

class Live:
    """Reads the running game's memory. HROT must be running with a map loaded.

    A debugger cannot be attached - HROT crashes shortly after - so this is the
    only practical way to see the fields no static replay can reach.
    """

    VALIDATION_ADDR = 0x00D77F78
    VALIDATION_VALUE = 0.5

    def __init__(self, process: str = "HROT.exe"):
        import ctypes
        import ctypes.wintypes as wt

        class ProcessEntry32(ctypes.Structure):
            _fields_ = [
                ("dwSize", wt.DWORD), ("cntUsage", wt.DWORD),
                ("th32ProcessID", wt.DWORD),
                ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                ("th32ModuleID", wt.DWORD), ("cntThreads", wt.DWORD),
                ("th32ParentProcessID", wt.DWORD), ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wt.DWORD), ("szExeFile", ctypes.c_char * 260),
            ]

        self._ctypes = ctypes
        kernel32 = ctypes.windll.kernel32
        snapshot = kernel32.CreateToolhelp32Snapshot(0x0002, 0)
        entry = ProcessEntry32()
        entry.dwSize = ctypes.sizeof(ProcessEntry32)
        pid = 0
        if kernel32.Process32First(snapshot, ctypes.byref(entry)):
            while True:
                if entry.szExeFile.decode("latin-1").lower() == process.lower():
                    pid = entry.th32ProcessID
                    break
                if not kernel32.Process32Next(snapshot, ctypes.byref(entry)):
                    break
        kernel32.CloseHandle(snapshot)
        if not pid:
            raise RuntimeError(f"{process} is not running.")

        self.pid = pid
        self._handle = kernel32.OpenProcess(0x0010 | 0x0400, False, pid)
        if not self._handle:
            raise RuntimeError("OpenProcess failed - try an administrator shell.")

        check = self.read(self.VALIDATION_ADDR, 4)
        if check is None or abs(struct.unpack("<f", check)[0] - self.VALIDATION_VALUE) > 1e-6:
            raise RuntimeError("Address validation failed; not the retail build.")

    def read(self, address: int, size: int) -> bytes | None:
        ctypes = self._ctypes
        buffer = ctypes.create_string_buffer(size)
        done = ctypes.c_size_t(0)
        ok = ctypes.windll.kernel32.ReadProcessMemory(
            self._handle, ctypes.c_void_p(address), buffer, size, ctypes.byref(done))
        return buffer.raw if ok and done.value == size else None

    def map_id(self) -> int:
        raw = self.read(MAP_ID_ADDR, 1)
        return struct.unpack("<b", raw)[0] if raw else -1

    def grid(self) -> bytes | None:
        return self.read(GRID_BASE, GRID_SIZE * GRID_SIZE * CELL_SIZE)

    def cell(self, row: int, column: int, grid: bytes | None = None) -> Cell | None:
        grid = grid or self.grid()
        if grid is None:
            return None
        return Cell(grid, (row * GRID_SIZE + column) * CELL_SIZE)


def selftest() -> int:
    """Check the helpers against findings recorded in the porting documents.

    Run this after touching anything here, and after a game update: every value
    below is build-specific, so a failure means either this module broke or the
    executable is not the retail build these addresses came from.
    """
    img = Image()
    passed = failed = 0

    def check(name, got, want):
        nonlocal passed, failed
        if got == want:
            passed += 1
            print(f"  PASS {name}")
        else:
            failed += 1
            print(f"  FAIL {name}: got {got!r}, want {want!r}")

    names = img.switch_targets(LEVEL_NAME_JUMP_TABLE, LEVEL_NAME_BYTE_TABLE, 0x69)

    def level_name(map_id):
        arm = names.get(map_id)
        for insn in img.disasm(arm, 24) if arm else []:
            if insn.mnemonic == "mov" and insn.op_str.startswith(("ax, ", "eax, ")):
                return img.string_by_id(int(insn.op_str.split(", ")[1], 0))
        return None

    # 6.20 - map id is not play order, and map 0 is not the intro.
    check("level name, map 0", level_name(0), "Vyšehrad Castle")
    check("level name, map 1", level_name(1), "Kosmonautů Station")
    check("level name, map 24", level_name(24), "The Degustation")

    # 6.23 - the 90-entry trigger dispatch.
    arms = img.jump_table(TRIGGER_JUMP_TABLE, 0x5A)
    check("trigger 4 (level exit)", arms[4], 0x00D7B64E)
    check("trigger 5 (volume toggle)", arms[5], 0x00D7B8A4)
    check("trigger 9 (volume raise)", arms[9], 0x00D7B7C3)

    # 6.25 - water is cell fields 0x09 and 0x0C.
    check("water cells, map 2", len(Grid(2).where(lambda c: c.water_type)), 173)
    check("water cells, map 22", len(Grid(22).where(lambda c: c.water_type)), 1508)
    check("water cells, map 5 (volumes, no static water)",
          len(Grid(5).where(lambda c: c.water_type)), 0)

    # The Luna pipe that started the water investigation.
    pipe = Grid(2).cell(56, 35)
    check("pipe floor height", round(pipe.floor_height, 4), -6.25)
    check("pipe water height", round(pipe.water_height, 3), -5.95)

    # The replay filter must not drop water; that omission hid it for a long time.
    check("filter admits 0x09/0x0C",
          is_world_field(0x09, 1, GRID_SIZE * GRID_SIZE * CELL_SIZE) and
          is_world_field(0x0C, 4, GRID_SIZE * GRID_SIZE * CELL_SIZE), True)

    check("disasm_at finds an unaligned target",
          any(i.address == 0x00D8B45D
              for i in img.disasm_at(0x00D8B45D, before=0x30, after=0x10)), True)
    check("callers of LoadLevel", len(img.callers(LOAD_LEVEL)), 4)
    check("callers of LoadString", len(img.callers(0x00DB9AA0)), 319)

    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    import sys
    sys.exit(selftest())
