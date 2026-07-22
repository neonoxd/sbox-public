#!/usr/bin/env python3
"""Compare HROT's live world grid against the mount's static reconstruction.

Several cell fields are computed at load time and never appear in the map
constructors, so a static replay cannot see them: 0x01 and 0x03 (cell gates),
0x07 and 0x08 (the riser flags), 0x1D7 (ceiling band count), 0x1D4 and 0x19
(liquid). The renderer port either substitutes for these or skips them.

This reads them out of the running game and checks the port's rules against
the real values, the same way the door dump validated the door decode.

Usage:
    dump_live_grid.py <mapId>      e.g. dump_live_grid.py 1

Load the matching map first, then run it.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import struct
import sys

from hrot_world_ranges import WORLD_RANGES

GRID_BASE = 0x00E626A0
GRID_SIZE = 101
CELL_SIZE = 0x1E0

VALIDATION_ADDR = 0x00D77F78
VALIDATION_VALUE = 0.5

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
TH32CS_SNAPPROCESS = 0x0002

# The constructor ranges the mount replays, for the static comparison, come
# from hrot_world_ranges - which parses the mount's own table, so this covers
# every map the mount builds rather than the first eight.
REPLAYED_FIELDS = {
    0x06, 0x10, 0x1C, 0x20, 0x24, 0x28, 0x2C, 0x30, 0x34, 0x38,
    0x3C, 0x40, 0x44, 0x48, 0x4C, 0x50, 0x54, 0x58,
    0x5C, 0x60, 0x64, 0x68, 0x6C, 0x70, 0x74, 0x78, 0x1D5, 0x1D6,
}
AUX_RECORDS = (0x7C, 0xD0, 0x124, 0x178)

WALL_BAND = 1.5625
CEILING_EPSILON = 0.02
CEILING_SPAN = 1.40625


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


def read_live_grid() -> bytes:
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

    total = GRID_SIZE * GRID_SIZE * CELL_SIZE
    grid = read(GRID_BASE, total)
    if grid is None:
        print("Could not read the grid - is a map actually loaded?")
        sys.exit(1)

    print(f"HROT.exe pid {pid}, read {total} bytes of grid\n")
    return grid


def replay_static(map_id: int) -> bytearray:
    """The mount's own reconstruction, so the two can be compared."""
    import pefile

    path = "D:/SteamLibrary/steamapps/common/HROT/HROT.exe"
    pe = pefile.PE(path)
    image = pe.OPTIONAL_HEADER.ImageBase
    start, end = WORLD_RANGES[map_id]
    executable = pe.get_data(start - image, end - start)

    grid = bytearray(GRID_SIZE * GRID_SIZE * CELL_SIZE)
    for cell in range(GRID_SIZE * GRID_SIZE):
        offset = cell * CELL_SIZE
        grid[offset + 6] = 1
        struct.pack_into("<f", grid, offset + 0x28, WALL_BAND)
        struct.pack_into("<f", grid, offset + 0x14, -2000.0)

    def is_field(displacement: int, width: int) -> bool:
        if displacement < 0 or displacement + width > len(grid):
            return False
        field = displacement % CELL_SIZE
        return field in REPLAYED_FIELDS or any(
            base <= field < base + 0x54 for base in AUX_RECORDS)

    for i in range(len(executable) - 10):
        pair = executable[i:i + 2]
        if pair == b"\xc6\x80":
            d = struct.unpack_from("<i", executable, i + 2)[0]
            if is_field(d, 1):
                grid[d] = executable[i + 6]
        elif pair == b"\xc7\x80":
            d = struct.unpack_from("<i", executable, i + 2)[0]
            if is_field(d, 4):
                grid[d:d + 4] = executable[i + 6:i + 10]
        elif pair == b"\x89\x90":
            d = struct.unpack_from("<i", executable, i + 2)[0]
            if is_field(d, 4):
                grid[d:d + 4] = b"\0\0\0\0"

    return grid


def main() -> None:
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)

    map_id = int(sys.argv[1], 0)
    if map_id not in WORLD_RANGES:
        print(f"No world range for map {map_id}.")
        sys.exit(1)

    live = read_live_grid()
    static = replay_static(map_id)

    def at(buffer, row, column):
        return (row * GRID_SIZE + column) * CELL_SIZE

    def byte(buffer, row, column, field):
        return buffer[at(buffer, row, column) + field]

    def single(buffer, row, column, field):
        return struct.unpack_from("<f", buffer, at(buffer, row, column) + field)[0]

    def baseline(buffer, row, column):
        raw = buffer[at(buffer, row, column) + 0x1D5]
        return struct.unpack("<b", bytes([raw]))[0] * WALL_BAND

    # Sanity: the fields the replay does cover must agree, or the live map is
    # not the one named on the command line and nothing below means anything.
    agree = total = 0
    for row in range(GRID_SIZE):
        for column in range(GRID_SIZE):
            total += 1
            if (byte(live, row, column, 0x34) == byte(static, row, column, 0x34)
                    and byte(live, row, column, 0x24) == byte(static, row, column, 0x24)
                    and byte(live, row, column, 0x1D6) == byte(static, row, column, 0x1D6)):
                agree += 1
    print(f"replayed fields agree on {agree}/{total} cells")
    if agree < total * 0.99:
        print("  -> the loaded map does not match; stopping.")
        sys.exit(1)

    def real(buffer, row, column):
        """The predicate the port substitutes for cell 0x01."""
        if not 0 <= row < GRID_SIZE or not 0 <= column < GRID_SIZE:
            return False
        if (byte(buffer, row, column, 0x34) or byte(buffer, row, column, 0x24)
                or byte(buffer, row, column, 0x10)
                or byte(buffer, row, column, 0x44) or byte(buffer, row, column, 0x54)
                or byte(buffer, row, column, 0x64) or byte(buffer, row, column, 0x74)):
            return True
        # Cells can carry stacked auxiliary bands with no active base wall.
        base = at(buffer, row, column)
        return any(struct.unpack_from("<b", buffer, base + record)[0] > 0
                   for record in AUX_RECORDS)

    print("\n--- cell 0x01 vs the port's IsRealCell substitution ---")
    both = only_live = only_ours = neither = 0
    missing = []
    for row in range(GRID_SIZE):
        for column in range(GRID_SIZE):
            live_flag = byte(live, row, column, 0x01) != 0
            ours = bool(real(static, row, column))
            if live_flag and ours:
                both += 1
            elif live_flag:
                only_live += 1
                missing.append((row, column))
            elif ours:
                only_ours += 1
            else:
                neither += 1
    print(f"  agree set   {both}\n  agree clear {neither}")
    print(f"  live only   {only_live}   (cells the port wrongly excludes)")
    print(f"  port only   {only_ours}   (cells the port wrongly includes)")

    if missing:
        print("  cells the port misses, with whatever the replay does hold:")
        for row, column in missing[:20]:
            base = at(static, row, column)
            fields = " ".join(f"{name}={static[base + field]}" for name, field in (
                ("floor", 0x34), ("ceil", 0x24), ("E", 0x44), ("W", 0x54),
                ("S", 0x64), ("N", 0x74), ("0x00", 0x00), ("0x06", 0x06),
                ("0x10", 0x10)))
            aux = [struct.unpack_from("<b", static, base + r)[0] for r in AUX_RECORDS]
            print(f"    ({row:3},{column:3})  {fields} aux={aux} "
                  f"stair={static[base + 0x1D6]}")

    def classify_bands(row, column):
        if not byte(static, row, column, 0x24):
            return 0
        top = baseline(static, row, column) + WALL_BAND
        ceiling = single(static, row, column, 0x28)
        if top - CEILING_EPSILON > ceiling:
            return 1
        if top + CEILING_SPAN > ceiling and top + CEILING_EPSILON < ceiling:
            return 2
        return 0

    print("\n--- riser flags 0x07 / 0x08 and band count 0x1D7 ---")
    stats = {"0x07": [0, 0], "0x08": [0, 0], "0x1D7": [0, 0]}
    mismatched = {"0x07": [], "0x08": [], "0x1D7": []}
    for row in range(GRID_SIZE):
        for column in range(GRID_SIZE):
            floor_riser = ceiling_riser = False
            for dr, dc in ((-1, 0), (1, 0), (0, 1), (0, -1)):
                nr, nc = row + dr, column + dc
                if not real(static, nr, nc):
                    continue
                if single(static, nr, nc, 0x38) < single(static, row, column, 0x38):
                    floor_riser = True
                if (not byte(static, nr, nc, 0x24)
                        or single(static, nr, nc, 0x28) > single(static, row, column, 0x28)):
                    ceiling_riser = True

            for name, ours, live_value in (
                    ("0x07", floor_riser, byte(live, row, column, 0x07) != 0),
                    ("0x08", ceiling_riser, byte(live, row, column, 0x08) != 0),
                    ("0x1D7", classify_bands(row, column), byte(live, row, column, 0x1D7))):
                if ours == live_value:
                    stats[name][0] += 1
                else:
                    stats[name][1] += 1
                    mismatched[name].append((row, column))

    for name, (match, differ) in stats.items():
        print(f"  {name}: {match} match, {differ} differ")

    def near_liquid(row, column):
        for dr, dc in ((0, 0), (-1, 0), (1, 0), (0, 1), (0, -1)):
            nr, nc = row + dr, column + dc
            if 0 <= nr < GRID_SIZE and 0 <= nc < GRID_SIZE                     and byte(live, nr, nc, 0x19):
                return True
        return False

    print("  of the differing cells, how many touch a liquid cell (0x19):")
    for name, cells in mismatched.items():
        touching = sum(1 for rc in cells if near_liquid(*rc))
        print(f"    {name}: {touching}/{len(cells)} adjacent to liquid")
        for rc in [c for c in cells if not near_liquid(*c)][:6]:
            print(f"       unexplained at {rc}")

    print("\n--- liquid fields, for the unported pass ---")
    for field, label in ((0x1D4, "0x1D4 flat-floor suppressor"),
                         (0x19, "0x19 liquid table index")):
        counts = {}
        for row in range(GRID_SIZE):
            for column in range(GRID_SIZE):
                value = byte(live, row, column, field)
                counts[value] = counts.get(value, 0) + 1
        nonzero = {k: v for k, v in counts.items() if k != 0}
        print(f"  {label}: {sum(nonzero.values())} cells set, values {nonzero}")

    # The rule that assigns 0x19 has not been found in the code, so dump the
    # cells themselves with whatever the static replay holds for them. If the
    # assignment keys off something in the map data - floor material is the
    # obvious candidate - it should be visible here.
    print("")
    print("--- liquid cells, with their static floor/ceiling data ---")
    print(f"  {'cell':>10} {'0x19':>5} {'floorAtlas':>12} {'ceilAtlas':>11} "
          f"{'floorH':>8} {'ceilH':>8}")
    for row in range(GRID_SIZE):
        for column in range(GRID_SIZE):
            value = byte(live, row, column, 0x19)
            if not value:
                continue
            base = at(static, row, column)
            fx, fy = struct.unpack_from("<2i", static, base + 0x2C)
            cx, cy = struct.unpack_from("<2i", static, base + 0x1C)
            print(f"  ({row:3},{column:3}) {value:>5} {f'({fx},{fy})':>12} "
                  f"{f'({cx},{cy})':>11} "
                  f"{single(static, row, column, 0x38):>8.2f} "
                  f"{single(static, row, column, 0x28):>8.2f}")


if __name__ == "__main__":
    main()
