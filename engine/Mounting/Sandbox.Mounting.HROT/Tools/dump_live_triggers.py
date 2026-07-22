#!/usr/bin/env python3
"""Dump the running game's per-prop trigger records.

Each prop gets one 12-byte trigger record when it is placed. 0x00DBE688 takes
the three values in registers, 0x00DBE60C writes them, and the result lands in
an array indexed by the prop's own index:

    0x00DBE6A9  mov eax, [0xDE7EC8] ; -> object
    0x00DBE6AE  mov eax, [eax]      ; -> prop count so far
    0x00DBE6B2  shl eax, 4          ; count * 16
    0x00DBE6B5  sub eax, edx        ;   ... - count = count * 15
    0x00DBE6BA  mov [eax*8 + 0x18CD8D0], edx    ; *8 -> stride 0x78

    record +0x00  byte   type   (bounds-checked 0..0x59 by the executor)
    record +0x04  dword  param
    record +0x08  dword  param2

An earlier version of this script read 0x17D7B14 as if it were this array. That
is a real but *different* table - 11 entries of 0x58, each holding seven 0xC
records, fired together by 0x00D7B780 - and reading it per-prop produced one
plausible row followed by float and filler noise. Both are dumped here, the
per-prop array first, because that is where a switch's trigger actually lives.

Triggers are static map data, so `dump_triggers.py` gets the same records out of
the executable with no game running. Use this one to see live state, or to check
the static reader against what the game actually built.

See REVERSE_ENGINEERING.md section 12 (Triggers and moving volumes).

Usage:
    load the map, then run with no arguments.
    dump_live_triggers.py --all       include records whose type is 0
    dump_live_triggers.py --limit N   read N prop slots (default: the live count)
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import json
import os
import struct
import sys

MAP_ID_ADDR = 0x017B9460

# Per-prop trigger records - what 0x00DBE688 writes.
PROP_TRIGGERS = 0x018CD8D0
PROP_STRIDE = 0x78
PROP_COUNT_POINTER = 0x00DE7EC8
PROP_SLOTS_FALLBACK = 1024

# The separate 11-entry table fired by 0x00D7B780.
ENTITY_TABLE = 0x017D7B14
ENTITY_STRIDE = 0x58
ENTITY_COUNT = 11            # 0x00DBE620 bounds-checks the index with `sub al, 0xB`
TRIGGERS_PER_ENTITY = 7
TRIGGER_SIZE = 0x0C

MAX_TYPE = 0x59

VALIDATION_ADDR = 0x00D77F78
VALIDATION_VALUE = 0.5

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
TH32CS_SNAPPROCESS = 0x0002

TRIGGER_TYPES = {
    1: "door",
    4: "level exit",
    5: "volume toggle",
    8: "volume (second op)",
    9: "volume raise",
    32: "volume via 0xDA9470 (edx=-1)",
    89: "volume via 0xDA9470 (dl=1)",
}


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


def live_prop_count(read) -> int | None:
    """Follow [0xDE7EC8] -> object -> first dword, the prop count."""
    pointer = read(PROP_COUNT_POINTER, 4)
    if not pointer:
        return None
    address = struct.unpack("<I", pointer)[0]
    if not 0x00400000 <= address <= 0x7FFFFFFF:
        return None
    value = read(address, 4)
    if not value:
        return None
    count = struct.unpack("<I", value)[0]
    return count if 0 < count <= 100000 else None


def describe(ttype: int) -> str:
    name = TRIGGER_TYPES.get(ttype)
    return f"   {name}" if name else ""


def main() -> None:
    show_all = "--all" in sys.argv
    limit = None
    if "--limit" in sys.argv:
        limit = int(sys.argv[sys.argv.index("--limit") + 1])

    pid, read = open_reader()

    raw = read(MAP_ID_ADDR, 1)
    map_id = struct.unpack("<b", raw)[0] if raw else -1

    counted = live_prop_count(read)
    slots = limit or counted or PROP_SLOTS_FALLBACK
    source = ("--limit" if limit else
              f"live count {counted}" if counted else
              f"fallback {PROP_SLOTS_FALLBACK}, live count unreadable")

    print(f"HROT.exe pid {pid}, map id {map_id}")
    print(f"reading {slots} prop slots ({source})\n")

    report: dict = {"map_id": map_id, "prop_triggers": {}, "entity_table": {}}

    block = read(PROP_TRIGGERS, slots * PROP_STRIDE)
    if block is None:
        print("Could not read the per-prop trigger array - is a map loaded?")
        sys.exit(1)

    shown = 0
    by_type: dict[int, int] = {}
    for index in range(slots):
        offset = index * PROP_STRIDE
        ttype = block[offset]
        param, param2 = struct.unpack_from("<II", block, offset + 4)
        if ttype == 0 and not show_all:
            continue
        if ttype > MAX_TYPE:
            # Past the end of the real array, or a slot holding something else.
            continue
        shown += 1
        by_type[ttype] = by_type.get(ttype, 0) + 1
        report["prop_triggers"][index] = {
            "type": ttype, "param": param, "param2": param2}
        print(f"  prop {index:4} @ 0x{PROP_TRIGGERS + offset:08X}  "
              f"type {ttype:3}  param {param:6}  param2 {param2:6}{describe(ttype)}")

    print(f"\n{shown} prop trigger records")
    if by_type:
        print("types: " + ", ".join(
            f"{t}x{n}" + (f" ({TRIGGER_TYPES[t]})" if t in TRIGGER_TYPES else "")
            for t, n in sorted(by_type.items())))

    # The other table, for completeness. Small and separate; 0x00D7B780 fires
    # all seven of an entry's records in sequence.
    entities = read(ENTITY_TABLE, ENTITY_COUNT * ENTITY_STRIDE)
    if entities:
        print(f"\nentity table at 0x{ENTITY_TABLE:08X} ({ENTITY_COUNT} entries):")
        any_entity = False
        for index in range(ENTITY_COUNT):
            records = []
            for slot in range(TRIGGERS_PER_ENTITY):
                o = index * ENTITY_STRIDE + slot * TRIGGER_SIZE
                ttype = entities[o]
                param, param2 = struct.unpack_from("<II", entities, o + 4)
                if ttype and ttype <= MAX_TYPE:
                    records.append({"slot": slot, "type": ttype,
                                    "param": param, "param2": param2})
            if not records:
                continue
            any_entity = True
            report["entity_table"][index] = records
            print(f"  entity {index}")
            for r in records:
                print(f"    slot {r['slot']}  type {r['type']:3}  "
                      f"param {r['param']:6}  param2 {r['param2']:6}"
                      f"{describe(r['type'])}")
        if not any_entity:
            print("  (empty)")

    out = os.path.join(os.environ.get("TEMP", "."), f"hrot_triggers_map{map_id:02}.json")
    with open(out, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=1)
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
