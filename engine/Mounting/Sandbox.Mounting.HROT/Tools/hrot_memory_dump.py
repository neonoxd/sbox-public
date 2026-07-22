#!/usr/bin/env python3
"""Attach to a running HROT process and dump live game state.

Compares the live grid against the statically reconstructed grid to find
discrepancies. Produces binary dumps and a human-readable diff report.

Requirements: pip install pymem pefile

Usage:
    python hrot_memory_dump.py <HROT.exe_path> [--map MAP_ID] [--output DIR]
    python hrot_memory_dump.py --diff <reconstructed.bin> <live.bin>
"""

from __future__ import annotations

import argparse
import math
import os
import struct
import sys
import time
from pathlib import Path

import pefile

from hrot_world_ranges import WORLD_RANGES

try:
    import pymem
    import pymem.process
except ImportError:
    pymem = None

GRID_SIZE = 101
CELL_SIZE = 0x1E0
GRID_BYTE_SIZE = GRID_SIZE * GRID_SIZE * CELL_SIZE  # 3,091,620

# IEEE 754 encoding of key initialization values.
FLOOR_HEIGHT_INIT = struct.pack("<f", -2000.0)     # 0x0000FA7C44
CEILING_HEIGHT_INIT = struct.pack("<f", 1.5625)     # 0x0000C83F
FLOOR_HEIGHT_INIT_REVERSED = FLOOR_HEIGHT_INIT[::-1]
CEILING_HEIGHT_INIT_REVERSED = CEILING_HEIGHT_INIT[::-1]

PROCESS_NAME = "HROT.exe"

# --------------------------------------------------------------------------- #
#  Binary structures for dump files
# --------------------------------------------------------------------------- #

DUMP_MAGIC = b"HROTDUMP"
DUMP_VERSION = 1

HEADER_FORMAT = "<8sIBBQ"  # magic, version, map_id, padding, grid_size
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

GLASS_HEADER_FORMAT = "<IB"  # count, padding
GLASS_HEADER_SIZE = struct.calcsize(GLASS_HEADER_FORMAT)
GLASS_RECORD_FORMAT = "<8fI"  # x,z,bottom,height,atlasX,atlasY,orientation,_,active
GLASS_RECORD_SIZE = struct.calcsize(GLASS_RECORD_FORMAT)

STATIC_HEADER_FORMAT = "<IB"  # count, padding
STATIC_HEADER_SIZE = struct.calcsize(STATIC_HEADER_FORMAT)
STATIC_RECORD_FORMAT = "<H32s32s"  # id, model, texture


def read_u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def read_u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def read_i32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<i", data, offset)[0]


def read_u8(data: bytes, offset: int) -> int:
    return data[offset]


def read_f32(data: bytes, offset: int) -> float:
    return struct.unpack_from("<f", data, offset)[0]


def read_cstring(data: bytes, offset: int, max_len: int = 128) -> str | None:
    end = data.find(b"\0", offset, offset + max_len)
    if end < 0:
        return None
    try:
        return data[offset:end].decode("ascii")
    except UnicodeDecodeError:
        return None


def read_extended80(data: bytes, offset: int) -> float:
    """Decode an x87 80-bit extended-precision constant."""
    significand = int.from_bytes(data[offset:offset + 8], "little")
    sign_exponent = int.from_bytes(data[offset + 8:offset + 10], "little")
    sign = -1.0 if sign_exponent & 0x8000 else 1.0
    exponent = sign_exponent & 0x7FFF
    if exponent == 0 and significand == 0:
        return 0.0
    if exponent == 0x7FFF:
        return float("inf") if sign > 0 else float("-inf")
    return sign * (significand / 9223372036854775808.0) * (2.0 ** (exponent - 16383))


# --------------------------------------------------------------------------- #
#  PE parsing
# --------------------------------------------------------------------------- #

class Section:
    __slots__ = ("virtual_address", "virtual_size", "raw_address", "raw_size")

    def __init__(self, va: int, vs: int, ra: int, rs: int):
        self.virtual_address = va
        self.virtual_size = vs
        self.raw_address = ra
        self.raw_size = rs


def parse_pe(path: str) -> tuple[int, list[Section]]:
    pe = pefile.PE(path)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    sections = []
    for s in pe.sections:
        sections.append(Section(
            s.VirtualAddress,
            s.Misc_VirtualSize,
            s.PointerToRawData,
            s.SizeOfRawData,
        ))
    return image_base, sections


def va_to_offset(va: int, image_base: int, sections: list[Section]) -> int | None:
    rva = va - image_base
    for s in sections:
        length = max(s.virtual_size, s.raw_size)
        if s.virtual_address <= rva < s.virtual_address + length:
            return s.raw_address + rva - s.virtual_address
    return None


def offset_to_va(offset: int, image_base: int, sections: list[Section]) -> int | None:
    for s in sections:
        if s.raw_address <= offset < s.raw_address + s.raw_size:
            return image_base + s.virtual_address + (offset - s.raw_address)
    return None


# --------------------------------------------------------------------------- #
#  Process memory scanning
# --------------------------------------------------------------------------- #

def find_process() -> pymem.Pymem | None:
    try:
        return pymem.Pymem(PROCESS_NAME)
    except pymem.exception.ProcessNotFound:
        return None
    except pymem.exception.ProcessAccessDenied:
        print(f"Error: Access denied to {PROCESS_NAME}. Run as administrator.", file=sys.stderr)
        return None


def read_process_memory(pm: pymem.Pymem, address: int, size: int) -> bytes | None:
    try:
        return pm.read_bytes(address, size)
    except Exception:
        return None


def scan_for_grid_in_process(pm: pymem.Pymem) -> list[int]:
    """Scan the HROT.exe module for likely grid base addresses.

    Looks for the characteristic initialization pattern:
        byte +0x06 = 1
        float +0x14 = -2000.0
        float +0x28 = 1.5625

    Spaced CELL_SIZE bytes apart across at least 3 cells.
    """
    module = pymem.process.module_from_name(pm.process_handle, PROCESS_NAME)
    base = module.lpBaseOfDll
    size = module.SizeOfImage

    print(f"Scanning {PROCESS_NAME} module: 0x{base:08X} - 0x{base + size:08X} ({size:,} bytes)")

    chunk_size = 1024 * 1024  # 1 MB chunks
    candidates = []

    for start in range(base, base + size, chunk_size - CELL_SIZE):
        end = min(start + chunk_size, base + size)
        data = read_process_memory(pm, start, end - start)
        if data is None:
            continue

        # Search for the floor height initialization value (-2000.0)
        search_offset = 0
        while search_offset < len(data):
            hit = data.find(FLOOR_HEIGHT_INIT, search_offset)
            if hit < 0:
                break

            candidate = start + hit - 0x14  # Floor height is at cell+0x14
            if candidate >= base:
                if _validate_grid_candidate(pm, candidate):
                    candidates.append(candidate)

            search_offset = hit + 4

    return candidates


def _validate_grid_candidate(pm: pymem.Pymem, base: int) -> bool:
    """Validate that a candidate grid base has the expected initialization pattern."""
    # Check 3 cells spaced CELL_SIZE apart
    checks = [
        (0x06, 1, "B"),        # byte 6 = 1
        (0x14, -2000.0, "f"),   # floor height
        (0x28, 1.5625, "f"),    # ceiling height
    ]

    for i in range(3):
        cell_base = base + i * CELL_SIZE
        data = read_process_memory(pm, cell_base, CELL_SIZE)
        if data is None:
            return False

        for field_offset, expected, fmt in checks:
            actual = struct.unpack_from(f"<{fmt}", data, field_offset)[0]
            if abs(actual - expected) > 0.001:
                return False

    return True


# --------------------------------------------------------------------------- #
#  Grid cell access (shared by dump and reconstruction)
# --------------------------------------------------------------------------- #

class GridCell:
    """Read-only accessor for a cell within a flat grid byte array."""

    __slots__ = ("_data", "_offset")

    def __init__(self, data: bytes, offset: int):
        self._data = data
        self._offset = offset

    def _byte(self, field: int) -> int:
        return self._data[self._offset + field]

    def _i32(self, field: int) -> int:
        return struct.unpack_from("<i", self._data, self._offset + field)[0]

    def _f32(self, field: int) -> float:
        return struct.unpack_from("<f", self._data, self._offset + field)[0]

    @property
    def has_floor(self) -> bool:
        return self._byte(0x34) != 0

    @property
    def has_ceiling(self) -> bool:
        return self._byte(0x24) != 0

    @property
    def floor_height(self) -> float:
        return self._f32(0x38)

    @property
    def ceiling_height(self) -> float:
        return self._f32(0x28)

    @property
    def wall_base(self) -> float:
        return struct.unpack("<b", bytes([self._byte(0x1D5)]))[0] * 1.5625

    @property
    def stair_direction(self) -> int:
        v = self._byte(0x1D6)
        return v if 1 <= v <= 4 else 0

    def face_material(self, base: int) -> tuple[int, int]:
        return (self._i32(base), self._i32(base + 4))

    def face_active(self, base: int) -> bool:
        return self._byte(base + 0xC) != 0  # offset from material start

    def __repr__(self) -> str:
        return (
            f"Cell(floor={self.has_floor} fh={self.floor_height:.3f} "
            f"ceil={self.has_ceiling} ch={self.ceiling_height:.3f} "
            f"wall_base={self.wall_base:.3f} stair={self.stair_direction})"
        )


def get_cell(grid: bytes, x: int, y: int) -> GridCell:
    if not (0 <= x < GRID_SIZE and 0 <= y < GRID_SIZE):
        raise IndexError(f"Cell ({x},{y}) out of range")
    return GridCell(grid, (y * GRID_SIZE + x) * CELL_SIZE)


# --------------------------------------------------------------------------- #
#  Grid reconstruction from executable (matches HrotExecutableMapData.cs)
# --------------------------------------------------------------------------- #


# Offsets within a cell that the world constructor writes to.
WORLD_FIELDS: set[int] = set()

def _init_world_fields() -> set[int]:
    fields = set()
    for f in (
        0x06,
        0x1C, 0x20, 0x24, 0x28, 0x2C, 0x30, 0x34, 0x38,
        0x3C, 0x40, 0x44, 0x48, 0x4C, 0x50, 0x54, 0x58,
        0x5C, 0x60, 0x64, 0x68, 0x6C, 0x70, 0x74, 0x78,
        0x1D5, 0x1D6,
    ):
        fields.add(f)
    # Four directional auxiliary wall records (84 bytes each).
    for base in (0x7C, 0xD0, 0x124, 0x178):
        for i in range(0x54):
            fields.add(base + i)
    return fields

WORLD_FIELDS = _init_world_fields()


def _is_world_field(displacement: int) -> bool:
    if displacement < 0 or displacement >= GRID_BYTE_SIZE:
        return False
    return (displacement % CELL_SIZE) in WORLD_FIELDS


def _create_initialized_grid() -> bytearray:
    grid = bytearray(GRID_BYTE_SIZE)
    for cell in range(GRID_SIZE * GRID_SIZE):
        offset = cell * CELL_SIZE
        grid[offset + 0x06] = 1
        struct.pack_into("<f", grid, offset + 0x28, 1.5625)
        struct.pack_into("<f", grid, offset + 0x14, -2000.0)
    return grid


def reconstruct_grid(exe_path: str, map_id: int) -> bytearray | None:
    """Reconstruct the grid from the executable's constant writes.

    This is the Python equivalent of HrotExecutableMapData.Read().
    """
    if map_id not in WORLD_RANGES:
        print(f"Map {map_id} has no known world constructor", file=sys.stderr)
        return None

    start_va, end_va = WORLD_RANGES[map_id]
    if start_va == end_va:
        print(f"Map {map_id} has no world constructor (shared range)", file=sys.stderr)
        return None

    try:
        data = Path(exe_path).read_bytes()
    except OSError as e:
        print(f"Cannot read executable: {e}", file=sys.stderr)
        return None

    pe = pefile.PE(exe_path)
    image_base = pe.OPTIONAL_HEADER.ImageBase

    start_off = None
    end_off = None
    for s in pe.sections:
        s_len = max(s.Misc_VirtualSize, s.SizeOfRawData)
        s_rva = s.VirtualAddress
        if s_rva <= (start_va - image_base) < s_rva + s_len:
            start_off = s.PointerToRawData + (start_va - image_base) - s_rva
        if s_rva <= (end_va - image_base) < s_rva + s_len:
            end_off = s.PointerToRawData + (end_va - image_base) - s_rva

    if start_off is None or end_off is None or end_off <= start_off:
        print(f"Cannot locate constructor range for map {map_id}", file=sys.stderr)
        return None

    code = data[start_off:end_off]
    grid = _create_initialized_grid()
    writes = 0

    for i in range(len(code)):
        # mov byte ptr [eax+disp32], imm8
        if i + 7 <= len(code) and code[i] == 0xC6 and code[i + 1] == 0x80:
            disp = read_i32(code, i + 2)
            if _is_world_field(disp):
                grid[disp] = code[i + 6]
                writes += 1
            continue

        # mov dword ptr [eax+disp32], imm32
        if i + 10 <= len(code) and code[i] == 0xC7 and code[i + 1] == 0x80:
            disp = read_i32(code, i + 2)
            if _is_world_field(disp):
                grid[disp:disp + 4] = code[i + 6:i + 10]
                writes += 1
            continue

        # mov [eax+disp32], edx (preceded by xor edx,edx => zero)
        if i + 6 <= len(code) and code[i] == 0x89 and code[i + 1] == 0x90:
            disp = read_i32(code, i + 2)
            if _is_world_field(disp):
                grid[disp:disp + 4] = b"\0\0\0\0"
                writes += 1

    print(f"Reconstructed grid for map {map_id}: {writes} writes")
    return grid


# --------------------------------------------------------------------------- #
#  Static model registration scan (matches HrotExecutableStaticModels.cs)
# --------------------------------------------------------------------------- #

def scan_static_models(exe_path: str) -> dict[int, tuple[str, str]]:
    """Scan the executable for static model registrations.

    Pattern: mov ecx,texture; mov edx,model; mov ax,id; call RegisterModel
    Returns: {id: (model_basename, texture_basename)}
    """
    data = Path(exe_path).read_bytes()
    pe = pefile.PE(exe_path)
    image_base = pe.OPTIONAL_HEADER.ImageBase

    sections: list[Section] = []
    for s in pe.sections:
        sections.append(Section(s.VirtualAddress, s.Misc_VirtualSize,
                                s.PointerToRawData, s.SizeOfRawData))

    def resolve(va: int) -> str | None:
        off = va_to_offset(va, image_base, sections)
        if off is None:
            return None
        end = data.find(b"\0", off, off + 128)
        if end < 0:
            return None
        try:
            s = data[off:end].decode("ascii")
        except UnicodeDecodeError:
            return None
        valid = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-./\\")
        return s if s and all(c in valid for c in s) else None

    result: dict[int, tuple[str, str]] = {}
    for i in range(len(data) - 19):
        if (data[i] == 0xB9 and data[i + 5] == 0xBA
                and data[i + 10:i + 12] == b"\x66\xb8"
                and data[i + 14] == 0xE8):
            tex_va = read_u32(data, i + 1)
            mod_va = read_u32(data, i + 6)
            model_id = read_u16(data, i + 12)
            tex = resolve(tex_va)
            mod = resolve(mod_va)
            if tex and mod:
                result[model_id] = (mod, tex)

    print(f"Found {len(result)} static model registrations")
    return result


# --------------------------------------------------------------------------- #
#  Glass panel scan (matches HrotExecutableProps.ReadGlassPanels)
# --------------------------------------------------------------------------- #

def scan_glass_panels(exe_path: str, map_id: int) -> list[dict]:
    """Scan for glass panel constructor calls in the prop constructor range."""
    if map_id not in WORLD_RANGES:
        return []

    PROP_RANGES: dict[int, tuple[int, int]] = {
        0:   (0x00542CAC, 0x0054595C),
        1:   (0x00596EF0, 0x00599FD0),
        2:   (0x005EC248, 0x005EF5B4),
        4:   (0x0064E0A8, 0x00651AF8),
        5:   (0x006AA680, 0x006AD7A4),
        6:   (0x00700404, 0x00704C30),
        7:   (0x0074E914, 0x007519A4),
        8:   (0x0079C6DC, 0x0079FA18),
        9:   (0x007D9F0C, 0x007DCF50),
        10:  (0x0082CFA0, 0x0083026C),
        11:  (0x00874CDC, 0x00877AE0),
        12:  (0x008A55EC, 0x008A819C),
        13:  (0x008A55EC, 0x008A819C),
        14:  (0x008F3690, 0x008F6A04),
        15:  (0x0092A7C8, 0x0092BC60),
        16:  (0x008A55EC, 0x008A819C),
        17:  (0x009C058C, 0x009C20B8),
        20:  (0x00A09C48, 0x00A0CD8C),
        21:  (0x00A1F05C, 0x00A1F8A4),
        22:  (0x00A882F0, 0x00A8AE44),
        23:  (0x00ACC354, 0x00ACFC6C),
        24:  (0x00AE20F4, 0x00AE2DC0),
        25:  (0x00B9BA18, 0x00B9F338),
        26:  (0x00BCDA08, 0x00BD0900),
        27:  (0x00C03774, 0x00C061BC),
        28:  (0x00C3727C, 0x00C39DB0),
        29:  (0x00C7D558, 0x00C80770),
        100: (0x00C83FD8, 0x00C841E8),
        101: (0x00C97A28, 0x00C982F8),
        102: (0x00CAA088, 0x00CAAC50),
        103: (0x00CBD2C4, 0x00CBE070),
        104: (0x00D40814, 0x00D5D388),
    }

    PLACE_GLASS = 0x00D4D690
    start_va, end_va = PROP_RANGES.get(map_id, (0, 0))
    if not start_va:
        return []

    data = Path(exe_path).read_bytes()
    pe = pefile.PE(exe_path)
    image_base = pe.OPTIONAL_HEADER.ImageBase

    start_off = va_to_offset(start_va, image_base,
        [Section(s.VirtualAddress, s.Misc_VirtualSize, s.PointerToRawData, s.SizeOfRawData)
         for s in pe.sections])
    end_off = va_to_offset(end_va, image_base,
        [Section(s.VirtualAddress, s.Misc_VirtualSize, s.PointerToRawData, s.SizeOfRawData)
         for s in pe.sections])

    if start_off is None or end_off is None:
        return []

    sections = [Section(s.VirtualAddress, s.Misc_VirtualSize,
                         s.PointerToRawData, s.SizeOfRawData) for s in pe.sections]
    panels: list[dict] = []

    for i in range(start_off, min(end_off, len(data) - 5)):
        if data[i] != 0xE8:
            continue
        next_va = offset_to_va(i + 5, image_base, sections)
        if next_va is None:
            continue
        target = (next_va + read_i32(data, i + 1)) & 0xFFFFFFFF
        if target != PLACE_GLASS:
            continue

        args = _read_immediate_pushes(data, start_off, i, 9)
        if args is None:
            continue

        x = struct.unpack("<f", struct.pack("<I", args[0] & 0xFFFFFFFF))[0]
        z = struct.unpack("<f", struct.pack("<I", args[1] & 0xFFFFFFFF))[0]
        bottom = struct.unpack("<f", struct.pack("<I", args[2] & 0xFFFFFFFF))[0]
        height = struct.unpack("<f", struct.pack("<I", args[3] & 0xFFFFFFFF))[0]
        atlas_y = read_i32_from_u32(args[4])

        atlas_x = _read_register_before_call(data, start_off, i, 0xB9, 0xB9)
        orientation = _read_register_before_call(data, start_off, i, 0xBA, 0xBA)

        if not all(math.isfinite(v) for v in (x, z, bottom, height)):
            continue
        if not (-4096 <= x <= 4096 and -4096 <= z <= 4096):
            continue
        if not (0 <= atlas_x <= 7 and 0 <= atlas_y <= 7):
            continue
        if not (0 <= orientation <= 3):
            continue

        panels.append({
            "x": x, "z": z, "bottom": bottom, "height": height,
            "atlas_x": atlas_x, "atlas_y": atlas_y,
            "orientation": orientation, "active": True,
        })

    print(f"Found {len(panels)} glass panels for map {map_id}")
    return panels


def _read_immediate_pushes(data: bytes, start: int, end: int, count: int) -> list[int] | None:
    """Read `count` push imm32/imm8 instructions walking backward from end."""
    for candidate in range(end, max(-1, end - 24), -1):
        cursor = candidate
        decoded = [0] * count
        valid = True
        for arg in range(count - 1, -1, -1):
            if cursor - 5 >= start and data[cursor - 5] == 0x68:
                decoded[arg] = read_u32(data, cursor - 4)
                cursor -= 5
            elif cursor - 2 >= start and data[cursor - 2] == 0x6A:
                decoded[arg] = struct.unpack("<b", bytes([data[cursor - 1]]))[0]
                cursor -= 2
            else:
                valid = False
                break
        if valid:
            return decoded
    return None


def _read_register_before_call(data: bytes, start: int, call_end: int,
                                reg_byte: int, reg_dword: int) -> int:
    value = 0
    minimum = max(start, call_end - 24)
    for i in range(minimum, call_end):
        if i + 1 < call_end and data[i] == 0x31 and data[i + 1] == (reg_byte & 0xF8 | 0xD0):
            value = 0
            i += 1
        elif i + 1 < call_end and data[i] == (reg_byte - 0x30):
            value = data[i + 1]
            i += 1
        elif i + 4 < call_end and data[i] == reg_dword:
            value = read_i32(data, i + 1)
            i += 4
    return value


def read_i32_from_u32(v: int) -> int:
    return struct.unpack("<i", struct.pack("<I", v & 0xFFFFFFFF))[0]


# --------------------------------------------------------------------------- #
#  Prop placement scan (matches HrotExecutableProps.Read)
# --------------------------------------------------------------------------- #

PLACE_ON_FLOOR = 0x00DBDDE0
PLACE_ABOVE_FLOOR = 0x00DBDE24
PLACE_AT_HEIGHT = 0x00DBDF04
PLACE_AT_CELL = 0x00DBE468
SCALE_LAST = 0x00DBDD64
PLACE_FLOOR_LAMP = 0x00D5CDF4
PLACE_LAMP_POST = 0x00D5CE0C
PLACE_RAISED_LAMP = 0x00D5CF20
PLACE_CEILING_FLUORESCENT = 0x00D5CD48
PLACE_CEILING_BAKELITE = 0x00D5CFE8
PLACE_CEILING_CHANDELIER = 0x00D5D08C
PLACE_CEILING_CHANDELIER2 = 0x00D5D120
PLACE_DOOR = 0x00D77C20


def scan_props(exe_path: str, map_id: int) -> tuple[list[dict], list[dict]]:
    """Scan for prop placements and door placements.

    Returns: (prop_list, door_list)
    """
    PROP_RANGES: dict[int, tuple[int, int]] = {
        0:   (0x00542CAC, 0x0054595C),
        1:   (0x00596EF0, 0x00599FD0),
        2:   (0x005EC248, 0x005EF5B4),
        4:   (0x0064E0A8, 0x00651AF8),
        5:   (0x006AA680, 0x006AD7A4),
        6:   (0x00700404, 0x00704C30),
        7:   (0x0074E914, 0x007519A4),
        8:   (0x0079C6DC, 0x0079FA18),
        9:   (0x007D9F0C, 0x007DCF50),
        10:  (0x0082CFA0, 0x0083026C),
        11:  (0x00874CDC, 0x00877AE0),
        12:  (0x008A55EC, 0x008A819C),
        13:  (0x008A55EC, 0x008A819C),
        14:  (0x008F3690, 0x008F6A04),
        15:  (0x0092A7C8, 0x0092BC60),
        16:  (0x008A55EC, 0x008A819C),
        17:  (0x009C058C, 0x009C20B8),
        20:  (0x00A09C48, 0x00A0CD8C),
        21:  (0x00A1F05C, 0x00A1F8A4),
        22:  (0x00A882F0, 0x00A8AE44),
        23:  (0x00ACC354, 0x00ACFC6C),
        24:  (0x00AE20F4, 0x00AE2DC0),
        25:  (0x00B9BA18, 0x00B9F338),
        26:  (0x00BCDA08, 0x00BD0900),
        27:  (0x00C03774, 0x00C061BC),
        28:  (0x00C3727C, 0x00C39DB0),
        29:  (0x00C7D558, 0x00C80770),
        100: (0x00C83FD8, 0x00C841E8),
        101: (0x00C97A28, 0x00C982F8),
        102: (0x00CAA088, 0x00CAAC50),
        103: (0x00CBD2C4, 0x00CBE070),
        104: (0x00D40814, 0x00D5D388),
    }

    start_va, end_va = PROP_RANGES.get(map_id, (0, 0))
    if not start_va:
        return [], []

    data = Path(exe_path).read_bytes()
    pe = pefile.PE(exe_path)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    sections = [Section(s.VirtualAddress, s.Misc_VirtualSize,
                         s.PointerToRawData, s.SizeOfRawData) for s in pe.sections]

    start_off = va_to_offset(start_va, image_base, sections)
    end_off = va_to_offset(end_va, image_base, sections)
    if start_off is None or end_off is None:
        return [], []

    props: list[dict] = []
    doors: list[dict] = []

    for i in range(start_off, min(end_off, len(data) - 14)):
        if data[i] != 0xE8:
            continue

        next_va = offset_to_va(i + 5, image_base, sections)
        if next_va is None:
            continue
        target = (next_va + read_i32(data, i + 1)) & 0xFFFFFFFF

        if target == PLACE_DOOR:
            args = _read_immediate_pushes(data, start_off, i, 17)
            if args is None:
                continue
            doors.append({
                "target": "door",
                "args": [f"0x{a:08X}" for a in args],
            })
            continue

        if target in (PLACE_CEILING_FLUORESCENT, PLACE_CEILING_BAKELITE):
            pushes = _find_two_pushes_before_call(data, start_off, i)
            if pushes:
                props.append({
                    "model_id": 13 if target == PLACE_CEILING_FLUORESCENT else 130,
                    "target": "ceiling_light",
                    "x": pushes[0], "z": pushes[1],
                })
            continue

        if target in (PLACE_FLOOR_LAMP, PLACE_LAMP_POST, PLACE_RAISED_LAMP,
                       PLACE_CEILING_CHANDELIER, PLACE_CEILING_CHANDELIER2):
            pushes = _find_float_pushes_before_call(data, start_off, i, 2)
            if pushes:
                props.append({
                    "model_id": {PLACE_FLOOR_LAMP: 1, PLACE_LAMP_POST: 234,
                                 PLACE_RAISED_LAMP: 8, PLACE_CEILING_CHANDELIER: 12,
                                 PLACE_CEILING_CHANDELIER2: 331}[target],
                    "target": "specialized_light",
                    "x": pushes[0], "z": pushes[1],
                })
            continue

        # Generic placement: mov ax,id16; call helper
        if (i + 9 <= end_off
                and data[i] == 0x66 and data[i + 1] == 0xB8
                and data[i + 4] == 0xE8):
            model_id = read_u16(data, i + 2)
            call_va = offset_to_va(i + 9, image_base, sections)
            if call_va is None:
                continue
            call_target = (call_va + read_i32(data, i + 5)) & 0xFFFFFFFF

            # Check for post-placement scale
            scale = 1.0
            if (i + 9 < end_off and data[i + 9] == 0x68
                    and i + 14 < end_off and data[i + 14] == 0xE8):
                scale_candidate_va = offset_to_va(i + 14, image_base, sections)
                if scale_candidate_va is not None:
                    scale_target = (scale_candidate_va + read_i32(data, i + 10)) & 0xFFFFFFFF
                    if scale_target == SCALE_LAST:
                        scale = struct.unpack("<f", data[i + 10:i + 14])[0]

            arg_count = {
                PLACE_AT_HEIGHT: 4, PLACE_ABOVE_FLOOR: 4,
                PLACE_ON_FLOOR: 3, PLACE_AT_CELL: 0,
            }.get(call_target, 0)

            args = None
            if arg_count > 0:
                args = _read_push_floats_before_call(data, start_off, i, arg_count)

            if call_target == PLACE_AT_CELL:
                # mov ecx,z; mov edx,x before the call
                if i >= 10 and data[i - 10] == 0xB9 and data[i - 5] == 0xBA:
                    cell_z = read_i32(data, i - 9)
                    cell_x = read_i32(data, i - 4)
                    props.append({
                        "model_id": model_id,
                        "target": "at_cell",
                        "cell_x": cell_x, "cell_z": cell_z,
                        "scale": scale,
                    })
            elif args and len(args) >= arg_count:
                props.append({
                    "model_id": model_id,
                    "target": call_target_name(call_target),
                    "args": args[:arg_count],
                    "scale": scale,
                })

    print(f"Found {len(props)} prop placements and {len(doors)} doors for map {map_id}")
    return props, doors


def call_target_name(target: int) -> str:
    names = {
        PLACE_ON_FLOOR: "on_floor",
        PLACE_ABOVE_FLOOR: "above_floor",
        PLACE_AT_HEIGHT: "at_height",
        PLACE_AT_CELL: "at_cell",
    }
    return names.get(target, f"0x{target:08X}")


def _find_two_pushes_before_call(data: bytes, start: int, call_end: int) -> list[float] | None:
    result = []
    cursor = call_end
    for _ in range(2):
        found = False
        for candidate in range(cursor - 5, max(start - 1, cursor - 32), -1):
            if data[candidate] == 0x68:
                val = struct.unpack("<f", data[candidate + 1:candidate + 5])[0]
                if math.isfinite(val) and -4096 <= val <= 4096:
                    result.append(val)
                    cursor = candidate
                    found = True
                    break
        if not found:
            return None
    return result[::-1]


def _find_float_pushes_before_call(data: bytes, start: int, call_end: int,
                                    count: int) -> list[float] | None:
    result: list[float] = []
    cursor = call_end
    for _ in range(count):
        found = False
        for candidate in range(cursor - 5, max(start - 1, cursor - 32), -1):
            if data[candidate] == 0x68:
                val = struct.unpack("<f", data[candidate + 1:candidate + 5])[0]
                if math.isfinite(val) and -4096 <= val <= 4096:
                    result.append(val)
                    cursor = candidate
                    found = True
                    break
        if not found:
            return None
    return result[::-1]


def _read_push_floats_before_call(data: bytes, start: int, call_end: int,
                                   count: int) -> list[float] | None:
    """Read float pushes walking backward from the call, skipping register setup."""
    result: list[float] = []
    cursor = call_end
    for _ in range(count):
        if cursor - 5 < start:
            return None
        if data[cursor - 5] == 0x68:
            val = struct.unpack("<f", data[cursor - 4:cursor])[0]
            result.append(val)
            cursor -= 5
        elif cursor - 2 >= start and data[cursor - 2] == 0x6A:
            val = float(struct.unpack("<b", bytes([data[cursor - 1]]))[0])
            result.append(val)
            cursor -= 2
        else:
            return None
    return result[::-1]


# --------------------------------------------------------------------------- #
#  Dump file I/O
# --------------------------------------------------------------------------- #

def write_grid_dump(path: Path, map_id: int, grid: bytearray) -> None:
    with open(path, "wb") as f:
        f.write(struct.pack(HEADER_FORMAT,
                            DUMP_MAGIC, DUMP_VERSION, map_id, 0, GRID_BYTE_SIZE))
        f.write(grid)
    print(f"Wrote grid dump: {path} ({GRID_BYTE_SIZE + HEADER_SIZE:,} bytes)")


def read_grid_dump(path: Path) -> tuple[int, bytes]:
    with open(path, "rb") as f:
        header = f.read(HEADER_SIZE)
        magic, version, map_id, _, grid_size = struct.unpack(HEADER_FORMAT, header)
        if magic != DUMP_MAGIC:
            raise ValueError(f"Not an HROT dump file: bad magic {magic!r}")
        if version != DUMP_VERSION:
            raise ValueError(f"Unsupported dump version {version}")
        grid = f.read(grid_size)
        if len(grid) != grid_size:
            raise ValueError(f"Incomplete grid dump: {len(grid)} / {grid_size} bytes")
    return map_id, grid


def write_glass_dump(path: Path, map_id: int, panels: list[dict]) -> None:
    with open(path, "wb") as f:
        f.write(struct.pack(GLASS_HEADER_FORMAT, len(panels), 0))
        for p in panels:
            f.write(struct.pack(GLASS_RECORD_FORMAT,
                                p["x"], p["z"], p["bottom"], p["height"],
                                float(p["atlas_x"]), float(p["atlas_y"]),
                                float(p["orientation"]), 0.0,
                                1))
    print(f"Wrote glass dump: {path} ({len(panels)} panels)")


def write_props_dump(path: Path, map_id: int, props: list[dict]) -> None:
    with open(path, "wb") as f:
        # Header: magic, version, count
        f.write(b"HROTPROP")
        f.write(struct.pack("<I", len(props)))
        for p in props:
            mid = p.get("model_id", 0)
            f.write(struct.pack("<Ii", mid, 0))  # model_id, padding
            # Write args as raw bytes
            args = p.get("args", [])
            f.write(struct.pack("<I", len(args)))
            for a in args:
                if isinstance(a, float):
                    f.write(struct.pack("<f", a))
                elif isinstance(a, int):
                    f.write(struct.pack("<i", a))
                else:
                    f.write(struct.pack("<I", 0))
    print(f"Wrote props dump: {path} ({len(props)} props)")


def write_models_dump(path: Path, models: dict[int, tuple[str, str]]) -> None:
    with open(path, "wb") as f:
        f.write(struct.pack(STATIC_HEADER_FORMAT, len(models), 0))
        for model_id in sorted(models):
            model, texture = models[model_id]
            m_bytes = model.encode("ascii").ljust(32, b"\0")[:32]
            t_bytes = texture.encode("ascii").ljust(32, b"\0")[:32]
            f.write(struct.pack(STATIC_RECORD_FORMAT, model_id, m_bytes, t_bytes))
    print(f"Wrote models dump: {path} ({len(models)} registrations)")


# --------------------------------------------------------------------------- #
#  Grid comparison
# --------------------------------------------------------------------------- #

def compare_grids(reconstructed: bytes, live: bytes, map_id: int) -> list[dict]:
    """Compare two grids cell-by-cell and report all field differences."""
    diffs: list[dict] = []

    for y in range(GRID_SIZE):
        for x in range(GRID_SIZE):
            off = (y * GRID_SIZE + x) * CELL_SIZE
            cell_recon = reconstructed[off:off + CELL_SIZE]
            cell_live = live[off:off + CELL_SIZE]

            if cell_recon == cell_live:
                continue

            cell_diffs = _diff_cell(cell_recon, cell_live, x, y)
            diffs.extend(cell_diffs)

    return diffs


def _diff_cell(a: bytes, b: bytes, x: int, y: int) -> list[dict]:
    """Compare two cell byte arrays and report meaningful field differences."""
    diffs = []

    # Key fields to compare
    fields = [
        ("byte", 0x06, 1, "byte_06"),
        ("float", 0x14, 4, "floor_height_init"),
        ("float", 0x1C, 4, "ceiling_atlas_x"),
        ("int32", 0x20, 4, "ceiling_atlas_y"),
        ("byte", 0x24, 1, "ceiling_active"),
        ("float", 0x28, 4, "ceiling_height"),
        ("int32", 0x2C, 4, "floor_atlas_x"),
        ("int32", 0x30, 4, "floor_atlas_y"),
        ("byte", 0x34, 1, "floor_active"),
        ("float", 0x38, 4, "floor_height"),
        ("int32", 0x3C, 4, "east_atlas_x"),
        ("int32", 0x40, 4, "east_atlas_y"),
        ("byte", 0x44, 1, "east_active"),
        ("int32", 0x4C, 4, "west_atlas_x"),
        ("int32", 0x50, 4, "west_atlas_y"),
        ("byte", 0x54, 1, "west_active"),
        ("int32", 0x5C, 4, "south_atlas_x"),
        ("int32", 0x60, 4, "south_atlas_y"),
        ("byte", 0x64, 1, "south_active"),
        ("int32", 0x6C, 4, "north_atlas_x"),
        ("int32", 0x70, 4, "north_atlas_y"),
        ("byte", 0x74, 1, "north_active"),
        ("int32", 0x78, 4, "north_height"),
        ("int8", 0x1D5, 1, "wall_base"),
        ("byte", 0x1D6, 1, "stair_direction"),
    ]

    for type_name, offset, size, name in fields:
        if a[offset:offset + size] != b[offset:offset + size]:
            if type_name == "float":
                rv = struct.unpack_from("<f", a, offset)[0]
                lv = struct.unpack_from("<f", b, offset)[0]
                diffs.append({"cell": (x, y), "field": name, "offset": offset,
                               "reconstructed": rv, "live": lv})
            elif type_name in ("int32", "int8"):
                rv = struct.unpack_from("<i" if type_name == "int32" else "<b",
                                         a, offset)[0]
                lv = struct.unpack_from("<i" if type_name == "int32" else "<b",
                                         b, offset)[0]
                diffs.append({"cell": (x, y), "field": name, "offset": offset,
                               "reconstructed": rv, "live": lv})
            else:
                rv = a[offset]
                lv = b[offset]
                diffs.append({"cell": (x, y), "field": name, "offset": offset,
                               "reconstructed": rv, "live": lv})

    # Compare auxiliary wall records
    for wall_name, base in [("east", 0x7C), ("west", 0xD0),
                             ("south", 0x124), ("north", 0x178)]:
        if a[base:base + 0x54] != b[base:base + 0x54]:
            # Report the first differing byte in the auxiliary record
            for i in range(0x54):
                if a[base + i] != b[base + i]:
                    diffs.append({
                        "cell": (x, y),
                        "field": f"{wall_name}_aux[{i}]",
                        "offset": base + i,
                        "reconstructed": a[base + i],
                        "live": b[base + i],
                    })
                    break

    return diffs


def write_diff_report(path: Path, diffs: list[dict], map_id: int) -> None:
    with open(path, "w") as f:
        f.write(f"HROT Grid Diff Report - Map {map_id}\n")
        f.write(f"{'=' * 60}\n\n")

        if not diffs:
            f.write("No differences found. Reconstructed grid matches live.\n")
            return

        f.write(f"Total field differences: {len(diffs)}\n\n")

        # Group by cell
        cells: dict[tuple[int, int], list[dict]] = {}
        for d in diffs:
            key = d["cell"]
            cells.setdefault(key, []).append(d)

        for (x, y) in sorted(cells):
            f.write(f"--- Cell ({x},{y}) ---\n")
            for d in cells[(x, y)]:
                f.write(f"  {d['field']:<24s} @ 0x{d['offset']:03X}:  "
                         f"reconstructed={d['reconstructed']!r}  "
                         f"live={d['live']!r}\n")
            f.write("\n")

        # Summary by field
        field_counts: dict[str, int] = {}
        for d in diffs:
            field_counts[d["field"]] = field_counts.get(d["field"], 0) + 1

        f.write(f"\n{'=' * 60}\n")
        f.write("Summary by field:\n")
        for field, count in sorted(field_counts.items(), key=lambda x: -x[1]):
            f.write(f"  {field:<32s} {count:4d} cells differ\n")

    print(f"Wrote diff report: {path} ({len(diffs)} differences)")


# --------------------------------------------------------------------------- #
#  Visualization (enhanced hrot_map_probe for dumps)
# --------------------------------------------------------------------------- #

def render_grid_png(grid: bytes, output: Path, fields: list[tuple[str, int, str]] | None = None) -> None:
    """Render grid fields as a tiled heatmap PNG."""
    try:
        from PIL import Image, ImageDraw
    except ImportError:
        print("Pillow not installed, skipping PNG visualization", file=sys.stderr)
        return

    if fields is None:
        fields = [
            ("floor_h", 0x38, "f32"),
            ("ceil_h", 0x28, "f32"),
            ("floor_on", 0x34, "u8"),
            ("ceil_on", 0x24, "u8"),
            ("wall_base", 0x1D5, "i8"),
            ("stair", 0x1D6, "u8"),
            ("east_on", 0x44, "u8"),
            ("west_on", 0x54, "u8"),
            ("south_on", 0x64, "u8"),
            ("north_on", 0x74, "u8"),
        ]

    tile_size = 200
    cols = min(5, len(fields))
    rows_count = math.ceil(len(fields) / cols)
    label_h = 24
    atlas = Image.new("RGB",
                       (cols * tile_size, rows_count * (tile_size + label_h)),
                       (24, 24, 24))
    draw = ImageDraw.Draw(atlas)

    for idx, (name, offset, kind) in enumerate(fields):
        col = idx % cols
        row = idx // cols
        x0 = col * tile_size
        y0 = row * (tile_size + label_h)

        values = []
        for cy in range(GRID_SIZE):
            for cx in range(GRID_SIZE):
                cell_off = (cy * GRID_SIZE + cx) * CELL_SIZE
                if kind == "f32":
                    values.append(struct.unpack_from("<f", grid, cell_off + offset)[0])
                elif kind == "i8":
                    values.append(float(struct.unpack_from("<b", grid, cell_off + offset)[0]))
                else:
                    values.append(float(grid[cell_off + offset]))

        finite = [v for v in values if math.isfinite(v)]
        if kind == "f32":
            non_sentinel = [v for v in finite if abs(v) < 1000.0]
            lo = min(non_sentinel, default=0.0)
            hi = max(non_sentinel, default=1.0)
        else:
            lo = min(finite, default=0.0)
            hi = max(finite, default=1.0)

        span = max(hi - lo, 1e-6)
        tile = Image.new("RGB", (GRID_SIZE, GRID_SIZE))
        pixels = tile.load()

        for ty in range(GRID_SIZE):
            for tx in range(GRID_SIZE):
                v = values[ty * GRID_SIZE + tx]
                if not math.isfinite(v):
                    color = (255, 0, 255)
                elif kind == "u8" and v == 0:
                    color = (0, 0, 0)
                else:
                    t = max(0.0, min(1.0, (v - lo) / span))
                    color = (int(255 * t), int(255 * (1 - abs(t * 2 - 1))), int(255 * (1 - t)))
                pixels[tx, ty] = color

        tile = tile.resize((tile_size, tile_size), Image.Resampling.NEAREST)
        atlas.paste(tile, (x0, y0))
        draw.text((x0 + 4, y0 + tile_size + 4), f"{name} @ 0x{offset:X}",
                   fill=(240, 240, 240))

    output.parent.mkdir(parents=True, exist_ok=True)
    atlas.save(str(output))
    print(f"Wrote visualization: {output}")


# --------------------------------------------------------------------------- #
#  Main
# --------------------------------------------------------------------------- #

def cmd_dump(args: argparse.Namespace) -> None:
    exe_path = args.exe
    map_id = args.map
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Executable: {exe_path}")
    print(f"Map ID: {map_id}")
    print(f"Output: {output_dir}")
    print()

    # 1. Reconstruct grid from executable
    print("--- Reconstructing grid from executable ---")
    recon_grid = reconstruct_grid(exe_path, map_id)
    if recon_grid is None:
        print("Failed to reconstruct grid", file=sys.stderr)
        sys.exit(1)

    recon_path = output_dir / f"grid_reconstructed_map{map_id:02d}.bin"
    write_grid_dump(recon_path, map_id, recon_grid)

    # 2. Scan static models
    print("\n--- Scanning static model registrations ---")
    static_models = scan_static_models(exe_path)
    models_path = output_dir / "static_models.bin"
    write_models_dump(models_path, static_models)

    # 3. Scan glass panels
    print("\n--- Scanning glass panels ---")
    glass_panels = scan_glass_panels(exe_path, map_id)
    glass_path = output_dir / f"glass_panels_map{map_id:02d}.bin"
    write_glass_dump(glass_path, map_id, glass_panels)

    # 4. Scan props and doors
    print("\n--- Scanning prop placements ---")
    props, doors = scan_props(exe_path, map_id)
    props_path = output_dir / f"props_map{map_id:02d}.bin"
    write_props_dump(props_path, map_id, props)

    # 5. Render visualization
    print("\n--- Rendering visualization ---")
    viz_path = output_dir / f"grid_map{map_id:02d}.png"
    render_grid_png(recon_grid, viz_path)

    # 6. Try to attach to live process
    print("\n--- Attempting live process attachment ---")
    if pymem is None:
        print("pymem not installed. Install with: pip install pymem")
        print("Skipping live dump.")
        _write_summary(output_dir, map_id, recon_grid, static_models,
                        glass_panels, props, doors, None)
        return

    pm = find_process()
    if pm is None:
        print(f"{PROCESS_NAME} not running. Skipping live dump.")
        print("Start HROT, load a level, then re-run this tool.")
        _write_summary(output_dir, map_id, recon_grid, static_models,
                        glass_panels, props, doors, None)
        return

    try:
        print(f"Attached to {PROCESS_NAME} (PID {pm.process_id})")

        # Scan for grid in process memory
        print("Scanning for grid in process memory...")
        grid_addrs = scan_for_grid_in_process(pm)

        if not grid_addrs:
            print("Could not locate grid in process memory.")
            print("The grid may not be initialized yet. Load a level first.")
            _write_summary(output_dir, map_id, recon_grid, static_models,
                            glass_panels, props, doors, None)
            return

        print(f"Found {len(grid_addrs)} candidate grid address(es):")
        for addr in grid_addrs:
            print(f"  0x{addr:08X}")

        # Use the first candidate
        live_base = grid_addrs[0]
        live_data = read_process_memory(pm, live_base, GRID_BYTE_SIZE)
        if live_data is None or len(live_data) != GRID_BYTE_SIZE:
            print("Failed to read full grid from process memory")
            _write_summary(output_dir, map_id, recon_grid, static_models,
                            glass_panels, props, doors, None)
            return

        live_path = output_dir / f"grid_live_map{map_id:02d}.bin"
        write_grid_dump(live_path, map_id, bytearray(live_data))

        # Compare grids
        print("\n--- Comparing grids ---")
        diffs = compare_grids(recon_grid, live_data, map_id)
        diff_path = output_dir / f"diff_map{map_id:02d}.txt"
        write_diff_report(diff_path, diffs, map_id)

        # Render live visualization
        print("\n--- Rendering live visualization ---")
        live_viz_path = output_dir / f"grid_live_map{map_id:02d}.png"
        render_grid_png(bytearray(live_data), live_viz_path)

        _write_summary(output_dir, map_id, recon_grid, static_models,
                        glass_panels, props, doors, diffs)

    finally:
        pm.close_process()


def _write_summary(output_dir: Path, map_id: int, recon_grid: bytes,
                    static_models: dict, glass_panels: list, props: list,
                    doors: list, diffs: list | None) -> None:
    summary_path = output_dir / "summary.txt"
    with open(summary_path, "w") as f:
        f.write(f"HROT Memory Dump Summary\n")
        f.write(f"{'=' * 50}\n\n")
        f.write(f"Map: {map_id}\n")
        f.write(f"Grid size: {GRID_SIZE}x{GRID_SIZE} cells, {CELL_SIZE} bytes each\n")
        f.write(f"Total grid: {GRID_BYTE_SIZE:,} bytes\n\n")

        # Cell stats
        active_floors = 0
        active_ceilings = 0
        stair_cells = 0
        for y in range(GRID_SIZE):
            for x in range(GRID_SIZE):
                off = (y * GRID_SIZE + x) * CELL_SIZE
                if recon_grid[off + 0x34]:
                    active_floors += 1
                if recon_grid[off + 0x24]:
                    active_ceilings += 1
                if 1 <= recon_grid[off + 0x1D6] <= 4:
                    stair_cells += 1

        f.write(f"Active floors: {active_floors}\n")
        f.write(f"Active ceilings: {active_ceilings}\n")
        f.write(f"Stair cells: {stair_cells}\n\n")

        f.write(f"Static model registrations: {len(static_models)}\n")
        f.write(f"Glass panels: {len(glass_panels)}\n")
        f.write(f"Prop placements: {len(props)}\n")
        f.write(f"Door placements: {len(doors)}\n\n")

        if diffs is not None:
            f.write(f"Grid differences: {len(diffs)}\n")
            if diffs:
                cells_affected = len({d["cell"] for d in diffs})
                f.write(f"Cells with differences: {cells_affected}\n")
        else:
            f.write("Grid differences: N/A (live dump not performed)\n")

    print(f"\nWrote summary: {summary_path}")


def cmd_diff(args: argparse.Namespace) -> None:
    """Compare two grid dump files."""
    recon_path = Path(args.reconstructed)
    live_path = Path(args.live)

    recon_id, recon_grid = read_grid_dump(recon_path)
    live_id, live_grid = read_grid_dump(live_path)

    if recon_id != live_id:
        print(f"Warning: map IDs differ (reconstructed={recon_id}, live={live_id})")

    diffs = compare_grids(recon_grid, live_grid, recon_id)

    if args.output:
        diff_path = Path(args.output)
    else:
        diff_path = recon_path.parent / f"diff_map{recon_id:02d}.txt"

    write_diff_report(diff_path, diffs, recon_id)

    # Also render a side-by-side diff visualization
    if diffs:
        _render_diff_visualization(recon_grid, live_grid, recon_id,
                                    diff_path.with_suffix(".png"))


def _render_diff_visualization(recon: bytes, live: bytes, map_id: int,
                                output: Path) -> None:
    """Render a visualization highlighting cells where grids differ."""
    try:
        from PIL import Image, ImageDraw
    except ImportError:
        return

    diff_mask = Image.new("L", (GRID_SIZE, GRID_SIZE), 0)
    pixels = diff_mask.load()

    for y in range(GRID_SIZE):
        for x in range(GRID_SIZE):
            off = (y * GRID_SIZE + x) * CELL_SIZE
            if recon[off:off + CELL_SIZE] != live[off:off + CELL_SIZE]:
                pixels[x, y] = 255

    diff_mask = diff_mask.resize((GRID_SIZE * 4, GRID_SIZE * 4), Image.Resampling.NEAREST)
    output.parent.mkdir(parents=True, exist_ok=True)
    diff_mask.save(str(output))
    print(f"Wrote diff visualization: {output}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="HROT memory dumper and grid comparison tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Dump command
    dump_parser = subparsers.add_parser("dump",
        help="Dump live HROT process state and compare with reconstruction")
    dump_parser.add_argument("exe", type=Path,
        help="Path to HROT.exe")
    dump_parser.add_argument("--map", type=int, default=1,
        help="Map ID to dump (default: 1)")
    dump_parser.add_argument("--output", type=Path, default=Path("hrot_dump"),
        help="Output directory (default: hrot_dump)")

    # Diff command
    diff_parser = subparsers.add_parser("diff",
        help="Compare two grid dump files")
    diff_parser.add_argument("reconstructed", type=Path,
        help="Path to reconstructed grid dump")
    diff_parser.add_argument("live", type=Path,
        help="Path to live grid dump")
    diff_parser.add_argument("--output", type=Path, default=None,
        help="Output diff report path")

    args = parser.parse_args()

    if args.command == "dump":
        cmd_dump(args)
    elif args.command == "diff":
        cmd_diff(args)


if __name__ == "__main__":
    main()
