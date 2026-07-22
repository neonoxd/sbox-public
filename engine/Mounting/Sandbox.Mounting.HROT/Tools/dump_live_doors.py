#!/usr/bin/env python3
"""Dump HROT's live door records and the entity array they link into.

Static analysis cannot see fields written after construction (see
REVERSE_ENGINEERING.md section 12, Doors). This reads them out of the running
process instead.

Usage: load a map with a visible door, then run this. No arguments.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import struct
import sys

# Absolute VAs. HROT is a 32-bit Delphi binary with a fixed image base, so
# these are valid as-is; VALIDATION_ADDR below proves it before anything else
# is trusted.
DOOR_ARRAY = 0x017D40C8
DOOR_STRIDE = 0x7C
DOOR_COUNT = 0x017D51CC
DOOR_SLOTS = 0x21           # 33, the fixed array size from the reset loop

ENTITY_POINTER = 0x00DE7C94  # holds the entity array base
ENTITY_STRIDE = 0x78

VALIDATION_ADDR = 0x00D77F78  # the 0.5 constant D77C20 adds to door x/z
VALIDATION_VALUE = 0.5

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
TH32CS_SNAPPROCESS = 0x0002


class ProcessEntry32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wt.DWORD),
        ("szExeFile", ctypes.c_char * 260),
    ]


def find_process(name: str) -> int:
    kernel32 = ctypes.windll.kernel32
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == -1:
        raise OSError("CreateToolhelp32Snapshot failed")

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


class Reader:
    def __init__(self, pid: int) -> None:
        self.kernel32 = ctypes.windll.kernel32
        self.handle = self.kernel32.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
        if not self.handle:
            raise OSError(
                "OpenProcess failed - try running this from an "
                "administrator shell")

    def read(self, address: int, size: int) -> bytes | None:
        buffer = ctypes.create_string_buffer(size)
        read = ctypes.c_size_t(0)
        ok = self.kernel32.ReadProcessMemory(
            self.handle, ctypes.c_void_p(address), buffer, size,
            ctypes.byref(read))
        if not ok or read.value != size:
            return None
        return buffer.raw

    def u32(self, address: int) -> int | None:
        raw = self.read(address, 4)
        return struct.unpack("<I", raw)[0] if raw else None

    def f32(self, address: int) -> float | None:
        raw = self.read(address, 4)
        return struct.unpack("<f", raw)[0] if raw else None


def looks_like_pointer(value: int) -> bool:
    return 0x00400000 <= value < 0x7FFF0000


def main() -> None:
    pid = find_process("HROT.exe")
    if not pid:
        print("HROT.exe is not running.")
        sys.exit(1)
    print(f"HROT.exe pid {pid}")

    reader = Reader(pid)

    check = reader.f32(VALIDATION_ADDR)
    if check is None or abs(check - VALIDATION_VALUE) > 1e-6:
        print(f"Address validation failed (read {check}, expected "
              f"{VALIDATION_VALUE}). The image is rebased or the process is "
              f"not the retail build; every address below would be wrong.")
        sys.exit(1)
    print(f"Address validation OK ({VALIDATION_ADDR:#010x} = {check})\n")

    count = reader.u32(DOOR_COUNT)
    print(f"door count @{DOOR_COUNT:#010x} = {count}\n")

    live = []
    for index in range(DOOR_SLOTS):
        base = DOOR_ARRAY + index * DOOR_STRIDE
        raw = reader.read(base, DOOR_STRIDE)
        if raw is None:
            continue

        x, y, z = struct.unpack_from("<3f", raw, 0x00)
        if x == 0.0 and y == 0.0 and z == 0.0:
            continue

        live.append((index, base, raw, x, y, z))

    print(f"{len(live)} occupied door slots\n")

    for index, base, raw, x, y, z in live:
        atlas = struct.unpack_from("<4i", raw, 0x64)
        ident = struct.unpack_from("<H", raw, 0x78)[0]
        print(f"door[{index:2}] @{base:#010x} pos=({x:7.2f},{y:6.2f},{z:7.2f}) "
              f"axis+0x5C={raw[0x5C]} cl+0x5D={raw[0x5D]} "
              f"atlas={atlas} id+0x78={ident}")

        # Any field that looks like a heap pointer is a candidate for the
        # renderable the draw path uses - that is the whole reason for this.
        for offset in range(0, DOOR_STRIDE - 3, 4):
            value = struct.unpack_from("<I", raw, offset)[0]
            if looks_like_pointer(value):
                print(f"           +{offset:#04x} -> {value:#010x}  "
                      f"(pointer candidate)")

        print("           " + " ".join(
            f"{raw[i]:02x}" for i in range(0, DOOR_STRIDE)))
        print()

    entity_base = reader.u32(ENTITY_POINTER)
    print(f"entity array pointer @{ENTITY_POINTER:#010x} = "
          f"{entity_base:#010x}" if entity_base else "entity pointer unreadable")

    if not entity_base or not looks_like_pointer(entity_base):
        return

    # AI code at 0xDA8857 matches a door's +0x78 against entity +0x4C.
    wanted = {struct.unpack_from("<H", raw, 0x78)[0] for _, _, raw, *_ in live}
    print(f"\nscanning entities for +0x4C matching door ids {sorted(wanted)}")
    for index in range(256):
        raw = reader.read(entity_base + index * ENTITY_STRIDE, ENTITY_STRIDE)
        if raw is None:
            break

        link = struct.unpack_from("<I", raw, 0x4C)[0]
        if link not in wanted:
            continue

        print(f"  entity[{index:3}] +0x4C={link}")
        print("      " + " ".join(f"{raw[i]:02x}" for i in range(ENTITY_STRIDE)))
        for offset in range(0, ENTITY_STRIDE - 3, 4):
            value = struct.unpack_from("<I", raw, offset)[0]
            if looks_like_pointer(value):
                print(f"      +{offset:#04x} -> {value:#010x} (pointer)")


if __name__ == "__main__":
    main()
