#!/usr/bin/env python3
"""Reconstruct and visualize HROT's statically generated map cell data.

This is a reverse-engineering aid, not part of the mount assembly. It expects
the retail 32-bit HROT executable and uses Capstone, pefile, and Pillow.
"""

from __future__ import annotations

import argparse
import math
import re
import struct
from pathlib import Path

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from PIL import Image, ImageDraw

from hrot_world_ranges import WORLD_RANGES


GRID_SIZE = 101
CELL_SIZE = 0x1E0


def initialized_grid() -> bytearray:
    data = bytearray(GRID_SIZE * GRID_SIZE * CELL_SIZE)
    for cell in range(GRID_SIZE * GRID_SIZE):
        base = cell * CELL_SIZE
        data[base + 6] = 1
        struct.pack_into("<f", data, base + 0x28, 1.5625)
        struct.pack_into("<f", data, base + 0x14, -2000.0)
    return data


def parse_immediate(value: str) -> int | None:
    value = value.strip()
    try:
        return int(value, 0)
    except ValueError:
        return None


def reconstruct_grid(exe_path: Path, map_id: int) -> bytearray:
    if map_id not in WORLD_RANGES:
        raise ValueError(f"Map id {map_id} does not have a known world constructor")

    start_va, end_va = WORLD_RANGES[map_id]
    if start_va == end_va:
        raise ValueError(f"Map id {map_id} has no normal world constructor")

    raw = exe_path.read_bytes()
    pe = pefile.PE(str(exe_path))
    image_base = pe.OPTIONAL_HEADER.ImageBase
    start = pe.get_offset_from_rva(start_va - image_base)
    end = pe.get_offset_from_rva(end_va - image_base)

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    grid = initialized_grid()
    registers: dict[str, int | str | None] = {}
    writes = 0

    memory_write = re.compile(
        r"(byte|word|dword) ptr \[(e[abcd]x|e[sd]i|e[bs]p)"
        r"(?: \+ (0x[0-9a-f]+))?\], (.+)"
    )

    for ins in md.disasm(raw[start:end], start_va):
        operands = ins.op_str

        if ins.mnemonic == "mov":
            parts = operands.split(", ", 1)
            if len(parts) == 2 and parts[0] in {
                "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
            }:
                destination, source = parts
                if source == "dword ptr [0xde8248]":
                    registers[destination] = "grid"
                elif source in registers:
                    registers[destination] = registers[source]
                else:
                    registers[destination] = parse_immediate(source)

            match = memory_write.fullmatch(operands)
            if match:
                width_name, base_register, displacement_text, source = match.groups()
                if registers.get(base_register) != "grid":
                    continue

                displacement = int(displacement_text or "0", 0)
                width = {"byte": 1, "word": 2, "dword": 4}[width_name]
                value = parse_immediate(source)
                if value is None and source in registers:
                    register_value = registers[source]
                    value = register_value if isinstance(register_value, int) else None

                if value is None or displacement + width > len(grid):
                    continue

                grid[displacement : displacement + width] = int(value).to_bytes(
                    width, "little", signed=False
                )
                writes += 1

        elif ins.mnemonic == "xor":
            parts = operands.split(", ")
            if len(parts) == 2 and parts[0] == parts[1]:
                registers[parts[0]] = 0
        elif ins.mnemonic == "lea":
            parts = operands.split(", ", 1)
            if parts:
                registers[parts[0]] = None
        elif ins.mnemonic == "call":
            # Delphi register calling convention treats eax/ecx/edx as volatile.
            registers["eax"] = None
            registers["ecx"] = None
            registers["edx"] = None

    print(f"Applied {writes} constant grid writes for map {map_id}")
    return grid


def field_values(grid: bytearray, offset: int, kind: str) -> list[float]:
    values: list[float] = []
    fmt = {"u8": "<B", "i32": "<i", "f32": "<f"}[kind]
    for cell in range(GRID_SIZE * GRID_SIZE):
        value = struct.unpack_from(fmt, grid, cell * CELL_SIZE + offset)[0]
        values.append(float(value))
    return values


def colorize(values: list[float], kind: str) -> Image.Image:
    image = Image.new("RGB", (GRID_SIZE, GRID_SIZE))
    pixels = image.load()

    finite = [v for v in values if math.isfinite(v)]
    if kind == "f32":
        non_default = [v for v in finite if abs(v) < 1000.0]
        lo = min(non_default, default=0.0)
        hi = max(non_default, default=1.0)
    else:
        lo = min(finite, default=0.0)
        hi = max(finite, default=1.0)

    span = max(hi - lo, 1e-6)
    for y in range(GRID_SIZE):
        for x in range(GRID_SIZE):
            value = values[y * GRID_SIZE + x]
            if not math.isfinite(value):
                color = (255, 0, 255)
            elif kind == "u8" and value == 0:
                color = (0, 0, 0)
            elif kind == "i32":
                n = int(value) & 0xFFFFFFFF
                color = ((n * 97) & 255, (n * 57) & 255, (n * 23) & 255)
            else:
                t = max(0.0, min(1.0, (value - lo) / span))
                color = (
                    int(255 * t),
                    int(255 * (1.0 - abs(t * 2.0 - 1.0))),
                    int(255 * (1.0 - t)),
                )
            pixels[x, y] = color
    return image


def render_atlas(grid: bytearray, output: Path) -> None:
    fields = [
        ("flags_00", 0x00, "u8"),
        ("flags_01", 0x01, "u8"),
        ("flags_02", 0x02, "u8"),
        ("flags_03", 0x03, "u8"),
        ("flags_04", 0x04, "u8"),
        ("flags_05", 0x05, "u8"),
        ("flags_06", 0x06, "u8"),
        ("surface_24", 0x24, "u8"),
        ("height_28", 0x28, "f32"),
        ("surface_34", 0x34, "u8"),
        ("height_38", 0x38, "f32"),
        ("surface_44", 0x44, "u8"),
        ("height_48", 0x48, "f32"),
        ("surface_54", 0x54, "u8"),
        ("height_58", 0x58, "f32"),
        ("surface_64", 0x64, "u8"),
        ("height_68", 0x68, "f32"),
        ("surface_74", 0x74, "u8"),
        ("height_78", 0x78, "f32"),
        ("tex_1c", 0x1C, "i32"),
        ("tex_20", 0x20, "i32"),
        ("tex_2c", 0x2C, "i32"),
        ("tex_30", 0x30, "i32"),
        ("tex_3c", 0x3C, "i32"),
        ("tex_40", 0x40, "i32"),
        ("tex_4c", 0x4C, "i32"),
        ("tex_50", 0x50, "i32"),
        ("tex_5c", 0x5C, "i32"),
        ("tex_60", 0x60, "i32"),
        ("tex_6c", 0x6C, "i32"),
        ("tex_70", 0x70, "i32"),
        ("light_1d5", 0x1D5, "u8"),
        ("light_1d6", 0x1D6, "u8"),
    ]

    tile_size = 202
    columns = 6
    rows = math.ceil(len(fields) / columns)
    atlas = Image.new("RGB", (columns * tile_size, rows * (tile_size + 24)), (24, 24, 24))
    draw = ImageDraw.Draw(atlas)

    for index, (name, offset, kind) in enumerate(fields):
        x = (index % columns) * tile_size
        y = (index // columns) * (tile_size + 24)
        tile = colorize(field_values(grid, offset, kind), kind)
        tile = tile.resize((tile_size, tile_size), Image.Resampling.NEAREST)
        atlas.paste(tile, (x, y))
        draw.text((x + 4, y + tile_size + 4), f"{name} @ 0x{offset:X}", fill=(240, 240, 240))

    output.parent.mkdir(parents=True, exist_ok=True)
    atlas.save(output)
    print(f"Wrote {output}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("exe", type=Path)
    parser.add_argument("map_id", type=int)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    render_atlas(reconstruct_grid(args.exe, args.map_id), args.output)


if __name__ == "__main__":
    main()
