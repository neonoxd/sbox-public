#!/usr/bin/env python3
"""Print addresses of cells whose 0x19 (liquid index) is set, for breakpoints.

Nothing static has located what writes cell field 0x19, so the remaining route
is a hardware write breakpoint. This finds a cell that actually carries the
field in the running game, so the breakpoint lands somewhere the writer will
touch rather than on an always-zero cell.

Usage: load a map with liquid, then run with no arguments.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import struct
import sys

GRID_BASE = 0x00E626A0
GRID_SIZE = 101
CELL_SIZE = 0x1E0
LIQUID_FIELD = 0x19

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


def main() -> None:
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
        print("Address validation failed.")
        sys.exit(1)

    grid = read(GRID_BASE, GRID_SIZE * GRID_SIZE * CELL_SIZE)
    if grid is None:
        print("Could not read the grid - is a map loaded?")
        sys.exit(1)

    found = []
    for row in range(GRID_SIZE):
        for column in range(GRID_SIZE):
            offset = (row * GRID_SIZE + column) * CELL_SIZE
            value = grid[offset + LIQUID_FIELD]
            if value:
                found.append((row, column, value, GRID_BASE + offset + LIQUID_FIELD))

    if not found:
        print("No cell has 0x19 set - this map has no liquid. Try Luna (2) "
              "or Palace of Culture (5).")
        sys.exit(1)

    print(f"{len(found)} liquid cells. Watch any of these addresses:\n")
    for row, column, value, address in found[:10]:
        print(f"  cell ({row:3},{column:3})  0x19 = {value}   ->  "
              f"bph {address:#010x}, w, 1")

    row, column, value, address = found[0]
    print(f"\nSuggested, in the x32dbg command bar:\n\n    bph {address:#010x}, w, 1\n")
    print("Then reload the level. Expect two hits: the cell initializer at\n"
          "0x00D42174 clearing it, then the writer setting it non-zero.")


if __name__ == "__main__":
    main()
