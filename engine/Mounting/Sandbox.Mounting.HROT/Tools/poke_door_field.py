#!/usr/bin/env python3
"""Write a byte into a live HROT door record, to test what a field controls.

Static tracing has not found the code that reads door record +0x5C, but live
memory shows it holds 2 on exactly the two map-1 leaves that render as solid
slabs and 0 or 1 everywhere else. Changing it in the running game settles
whether that correlation is causal without needing to find the reader.

Usage:
    poke_door_field.py                 list doors with +0x5C and +0x5D
    poke_door_field.py 6 0x5C 0        set door[6] +0x5C to 0
    poke_door_field.py 6 0x5C 2        put it back

Nothing here is persistent - it edits process memory only, so restarting the
map or the game restores the original values.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import struct
import sys

DOOR_ARRAY = 0x017D40C8
DOOR_STRIDE = 0x7C
DOOR_SLOTS = 0x21

VALIDATION_ADDR = 0x00D77F78
VALIDATION_VALUE = 0.5

PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
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
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION
        | PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        print("OpenProcess failed - try an administrator shell.")
        sys.exit(1)

    def read(address: int, size: int) -> bytes | None:
        buffer = ctypes.create_string_buffer(size)
        done = ctypes.c_size_t(0)
        ok = kernel32.ReadProcessMemory(
            handle, ctypes.c_void_p(address), buffer, size, ctypes.byref(done))
        return buffer.raw if ok and done.value == size else None

    def write(address: int, payload: bytes) -> bool:
        done = ctypes.c_size_t(0)
        return bool(kernel32.WriteProcessMemory(
            handle, ctypes.c_void_p(address), payload, len(payload),
            ctypes.byref(done))) and done.value == len(payload)

    check = read(VALIDATION_ADDR, 4)
    if check is None or abs(struct.unpack("<f", check)[0] - VALIDATION_VALUE) > 1e-6:
        print("Address validation failed; refusing to write anything.")
        sys.exit(1)

    if len(sys.argv) == 1:
        print(f"{'#':>3} {'pos':>26} {'+0x5C':>6} {'+0x5D':>6}")
        for index in range(DOOR_SLOTS):
            raw = read(DOOR_ARRAY + index * DOOR_STRIDE, DOOR_STRIDE)
            if raw is None:
                continue
            x, y, z = struct.unpack_from("<3f", raw, 0)
            if x == 0.0 and y == 0.0 and z == 0.0:
                continue
            print(f"{index:>3} ({x:7.2f},{y:6.2f},{z:7.2f}) "
                  f"{raw[0x5C]:>6} {raw[0x5D]:>6}")
        return

    if len(sys.argv) != 4:
        print(__doc__)
        sys.exit(1)

    index = int(sys.argv[1], 0)
    offset = int(sys.argv[2], 0)
    value = int(sys.argv[3], 0)
    if not 0 <= index < DOOR_SLOTS or not 0 <= offset < DOOR_STRIDE \
            or not 0 <= value <= 255:
        print("Out of range.")
        sys.exit(1)

    address = DOOR_ARRAY + index * DOOR_STRIDE + offset
    before = read(address, 1)
    if before is None:
        print("Read failed.")
        sys.exit(1)

    if not write(address, bytes([value])):
        print("Write failed.")
        sys.exit(1)

    after = read(address, 1)
    print(f"door[{index}] +{offset:#04x}: {before[0]} -> "
          f"{after[0] if after else '?'}")


if __name__ == "__main__":
    main()
