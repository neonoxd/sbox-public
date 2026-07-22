#!/usr/bin/env python3
"""Dump the running game's volume assignment (cell field 0x19) and volume table.

Cell field 0x19 assigns each cell to one of six engine-wide volumes. Nothing
static has located what writes it - see REVERSE_ENGINEERING.md 11.9 - so this
reads the answer out of the running game instead.

It dumps two things and writes them to JSON for offline analysis:

  * every cell with 0x19 set, grouped into volumes, with each volume's bounding
    rectangle and whether it is exactly filled (a solid rect) or ragged;
  * the seven volume records at 0x17D6148, stride 0x48, decoded.

The rectangles are the point. If volumes are defined by a constructor call
taking a cell rect, the bounds printed here should appear as integer arguments
in that map's entity constructor - a search that has not been run, because the
earlier one looked for *float* arguments.

It also compares each volume cell's **live** floor height (0x38) against the
**static** one the mount replays from the constructor. That comparison is the
test for 6.22/6.24: if they agree, the water surface sits where the mount
already draws the floor, and any visual difference is material rather than
geometry. If the live height is higher, the volume raises the surface above the
map-data floor and the mount is drawing it too low.

Usage:
    load a map that has volumes (Palace of Culture / map 5 is the richest),
    then run with no arguments.

    dump_live_volumes.py --cell 38,54 --cell 56,35
        also dump those specific cells in full, live vs static. Takes
        row,column in HROT's frame - a prop at world (x, z) is row x, column z.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import json
import os
import struct
import sys

GRID_BASE = 0x00E626A0
GRID_SIZE = 101
CELL_SIZE = 0x1E0
VOLUME_FIELD = 0x19

MAP_ID_ADDR = 0x017B9460          # signed byte, the current map id
VOLUME_TABLE = 0x017D6148         # record base; stride 0x48, 7 records
VOLUME_STRIDE = 0x48
VOLUME_COUNT = 7
CENTROID_ARRAY = 0x017D61D4

VALIDATION_ADDR = 0x00D77F78
VALIDATION_VALUE = 0.5

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
TH32CS_SNAPPROCESS = 0x0002


class ProcessEntry32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD), ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wt.DWORD), ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD), ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wt.DWORD), ("szExeFile", ctypes.c_char * 260),
    ]


def find_process(name: str) -> int:
    kernel32 = ctypes.windll.kernel32
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    entry = ProcessEntry32()
    entry.dwSize = ctypes.sizeof(ProcessEntry32)
    found = 0
    if kernel32.Process32First(snapshot, ctypes.byref(entry)):
        while True:
            if entry.szExeFile.decode("latin-1").lower() == name.lower():
                found = entry.th32ProcessID
                break
            if not kernel32.Process32Next(snapshot, ctypes.byref(entry)):
                break
    kernel32.CloseHandle(snapshot)
    return found


def open_reader():
    pid = find_process("HROT.exe")
    if not pid:
        print("HROT.exe is not running.")
        sys.exit(1)

    kernel32 = ctypes.windll.kernel32
    handle = kernel32.OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        print("OpenProcess failed - try an administrator shell.")
        sys.exit(1)

    def read(address: int, size: int) -> bytes | None:
        buffer = ctypes.create_string_buffer(size)
        done = ctypes.c_size_t(0)
        ok = kernel32.ReadProcessMemory(
            handle, ctypes.c_void_p(address), buffer, size, ctypes.byref(done))
        return buffer.raw if ok and done.value == size else None

    check = read(VALIDATION_ADDR, 4)
    if check is None or abs(struct.unpack("<f", check)[0] - VALIDATION_VALUE) > 1e-6:
        print("Address validation failed; the image is rebased or not retail.")
        sys.exit(1)

    return pid, read


def decode_volume(record: bytes) -> dict:
    f = lambda o: struct.unpack_from("<f", record, o)[0]
    d = lambda o: struct.unpack_from("<I", record, o)[0]
    return {
        "threshold_0x00": f(0x00),
        "active_0x09": record[0x09],
        "state_0x0A": struct.unpack_from("<b", record, 0x0A)[0],
        "level_0x0C": f(0x0C),
        "param_0x10": f(0x10),
        "param_0x14": f(0x14),
        "base_0x18": f(0x18),
        "enable_solid_0x1D": record[0x1D],
        "handle_0x24": d(0x24),
        "handle_0x28": d(0x28),
    }


def static_grid(map_id: int):
    """The mount's own reconstruction, for comparing live against static."""
    import re
    import pefile
    from hrot_world_ranges import WORLD_RANGES
    from dump_map_cells import is_world_field

    if map_id not in WORLD_RANGES:
        return None
    path = r"D:\SteamLibrary\steamapps\common\HROT\HROT.exe"
    pe = pefile.PE(path)
    image = pe.OPTIONAL_HEADER.ImageBase
    start, end = WORLD_RANGES[map_id]
    code = pe.get_data(start - image, end - start)

    grid = bytearray(GRID_SIZE * GRID_SIZE * CELL_SIZE)
    for c in range(GRID_SIZE * GRID_SIZE):
        o = c * CELL_SIZE
        grid[o + 6] = 1
        struct.pack_into("<f", grid, o + 0x28, 1.5625)
        struct.pack_into("<f", grid, o + 0x14, -2000.0)
    for m in re.finditer(b"\xc6\x80", code):
        o = m.start(); d = struct.unpack_from("<i", code, o + 2)[0]
        if is_world_field(d, 1, len(grid)): grid[d] = code[o + 6]
    for m in re.finditer(b"\xc7\x80", code):
        o = m.start(); d = struct.unpack_from("<i", code, o + 2)[0]
        if is_world_field(d, 4, len(grid)): grid[d:d + 4] = code[o + 6:o + 10]
    return grid


def describe(grid, row, column):
    o = (row * GRID_SIZE + column) * CELL_SIZE
    f = lambda off: struct.unpack_from("<f", grid, o + off)[0]
    return {
        "0x00": grid[o + 0x00], "0x01": grid[o + 0x01], "0x03": grid[o + 0x03],
        "0x10": grid[o + 0x10], "0x19": grid[o + 0x19],
        "0x24 hasCeiling": grid[o + 0x24], "0x34 hasFloor": grid[o + 0x34],
        "0x38 floorH": round(f(0x38), 4), "0x28 ceilH": round(f(0x28), 4),
        "0x1D4": grid[o + 0x1D4], "0x1D7": grid[o + 0x1D7],
        "floorMat": struct.unpack_from("<ii", grid, o + 0x2C),
    }


def main() -> None:
    wanted_cells = []
    argv = sys.argv[1:]
    while "--cell" in argv:
        i = argv.index("--cell")
        r, c = argv[i + 1].split(",")
        wanted_cells.append((int(r), int(c)))
        del argv[i:i + 2]

    pid, read = open_reader()

    raw_map_id = read(MAP_ID_ADDR, 1)
    map_id = struct.unpack("<b", raw_map_id)[0] if raw_map_id else -1

    grid = read(GRID_BASE, GRID_SIZE * GRID_SIZE * CELL_SIZE)
    if grid is None:
        print("Could not read the grid - is a map actually loaded?")
        sys.exit(1)

    print(f"HROT.exe pid {pid}, map id {map_id}\n")

    volumes: dict[int, list[tuple[int, int]]] = {}
    for row in range(GRID_SIZE):
        for column in range(GRID_SIZE):
            index = grid[(row * GRID_SIZE + column) * CELL_SIZE + VOLUME_FIELD]
            if index:
                volumes.setdefault(index, []).append((row, column))

    if not volumes:
        print("No cell has 0x19 set - this map has no volumes.")
        print("Palace of Culture (map 5) is the richest; Luna (map 2) also has some.")
        sys.exit(1)

    report: dict = {"map_id": map_id, "volumes": {}, "records": {}, "centroids": {}}

    print(f"{sum(len(c) for c in volumes.values())} cells across "
          f"{len(volumes)} volumes\n")
    for index in sorted(volumes):
        cells = volumes[index]
        rows = [r for r, _ in cells]
        cols = [c for _, c in cells]
        r0, r1, c0, c1 = min(rows), max(rows), min(cols), max(cols)
        area = (r1 - r0 + 1) * (c1 - c0 + 1)
        solid = area == len(cells)
        print(f"  volume {index}: {len(cells):4} cells   "
              f"rows {r0:3}-{r1:3}  cols {c0:3}-{c1:3}   "
              f"{'solid rect' if solid else f'ragged ({area - len(cells)} holes)'}")
        report["volumes"][index] = {
            "cells": cells, "row_min": r0, "row_max": r1,
            "col_min": c0, "col_max": c1, "solid_rect": solid,
        }

    print("\nvolume records at 0x%08X:" % VOLUME_TABLE)
    for index in range(VOLUME_COUNT):
        record = read(VOLUME_TABLE + index * VOLUME_STRIDE, VOLUME_STRIDE)
        if record is None:
            continue
        decoded = decode_volume(record)
        report["records"][index] = decoded
        report["records"][index]["raw"] = record.hex()
        print(f"  [{index}] level={decoded['level_0x0C']:9.4f} "
              f"base={decoded['base_0x18']:9.4f} "
              f"threshold={decoded['threshold_0x00']:9.4f} "
              f"active={decoded['active_0x09']} "
              f"state={decoded['state_0x0A']:>3} "
              f"solid={decoded['enable_solid_0x1D']}")

    centroids = read(CENTROID_ARRAY, VOLUME_COUNT * VOLUME_STRIDE)
    if centroids:
        report["centroids"]["raw"] = centroids.hex()

    static = static_grid(map_id)

    if static is not None:
        print("\nlive vs static floor height on volume cells:")
        mismatches = []
        for index in sorted(volumes):
            for row, column in volumes[index]:
                o = (row * GRID_SIZE + column) * CELL_SIZE
                live_h = struct.unpack_from("<f", grid, o + 0x38)[0]
                static_h = struct.unpack_from("<f", static, o + 0x38)[0]
                if abs(live_h - static_h) > 1e-4:
                    mismatches.append((index, row, column, live_h, static_h))
        if mismatches:
            print(f"  {len(mismatches)} volume cells differ - the volume is NOT at rest,")
            print("  so the surface is not where the map data puts it:")
            for index, row, column, lh, sh in mismatches[:12]:
                print(f"    vol {index} ({row:3},{column:3})  live {lh:8.4f}  static {sh:8.4f}"
                      f"  delta {lh - sh:+.4f}")
        else:
            print("  all volume cells match - the surface sits at the map-data floor height")
        report["floor_mismatches"] = [
            {"volume": i, "row": r, "col": c, "live": lh, "static": sh}
            for i, r, c, lh, sh in mismatches
        ]

    for row, column in wanted_cells:
        print(f"\ncell ({row},{column}):")
        live = describe(grid, row, column)
        stat = describe(static, row, column) if static is not None else {}
        for key in live:
            s = stat.get(key)
            flag = "" if s is None or s == live[key] else f"   (static {s})"
            print(f"    {key:16} {live[key]}{flag}")
        report.setdefault("cells", {})[f"{row},{column}"] = {"live": live, "static": stat}

    out = os.path.join(os.environ.get("TEMP", "."), f"hrot_volumes_map{map_id:02}.json")
    with open(out, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=1)
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
