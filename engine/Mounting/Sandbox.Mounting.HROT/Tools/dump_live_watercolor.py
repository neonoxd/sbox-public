#!/usr/bin/env python3
"""Read the vertex colour HROT gives water geometry, from the running game.

HROT's water vertex shader scrolls by `v_coords.y += transp.z * u_time`, where
`transp = gl_Color.rgb`. So a water surface's flow rate is its **vertex colour
blue channel**, and red/green are the alpha clamp. One shader draws pools and
waterfalls alike - the split is a colour, not a second program.

The pools set that colour with literals, so they can be read statically:
`0x00D8F485` uses `glColor3f(0.8, 0.91, 0)` for water type 1 and `0x00D8F49E`
`(0.55, 0.9, 0)` for type 2 - blue 0, which is why pools wobble without flowing.

The waterfall *models* (257 `vzduchnavod`, 591 `mlynvod`, both textured `voda1`)
take theirs from their GLScene material instead - applied at `0x004E1583`,
`glColor4f([edi+0x20], [edi+0x24], [edi+0x28], ...)`. That is a heap object built
at load time, not a literal, so disassembly does not reach the value. Read live
it is **(1, 1, 0.09)**: opaque, flowing at 0.09 * u_time.

Method: find the Delphi string `voda1` in committed memory, find dwords pointing
at it (the material's name field), then read colour vectors around each holder.
A GLScene material lays out ambient and diffuse exactly 0x38 apart, which
identifies the pair; the generic material shows GLScene's untouched default
`(0.8, 0.8, 0.8)` at that spacing, the water one `(1, 1, 0.09)`.

Needs a map loaded (HROT must have built its materials). Read-only: this only
ever calls ReadProcessMemory.

Usage:
    dump_live_watercolor.py                 materials named voda1
    dump_live_watercolor.py --name sklo     any other material
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import struct
import sys

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01

# A GLScene material's ambient and diffuse colour vectors sit this far apart.
COLOUR_STRIDE = 0x38

# GLScene's untouched defaults. A material still showing these was never given a
# colour by HROT, so its blue is not a scroll rate.
GLSCENE_DEFAULT_AMBIENT = (0.2, 0.2, 0.2, 1.0)
GLSCENE_DEFAULT_DIFFUSE = (0.8, 0.8, 0.8, 1.0)

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


class MemoryBasicInformation(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wt.DWORD), ("RegionSize", ctypes.c_size_t),
                ("State", wt.DWORD), ("Protect", wt.DWORD), ("Type", wt.DWORD)]


class ProcessEntry32(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD),
                ("th32ProcessID", wt.DWORD),
                ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                ("th32ModuleID", wt.DWORD), ("cntThreads", wt.DWORD),
                ("th32ParentProcessID", wt.DWORD), ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wt.DWORD), ("szExeFile", ctypes.c_char * 260)]


def find_process(name: str) -> int:
    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
    entry = ProcessEntry32()
    entry.dwSize = ctypes.sizeof(ProcessEntry32)
    pid = 0
    if kernel32.Process32First(snapshot, ctypes.byref(entry)):
        while True:
            if entry.szExeFile.decode(errors="ignore").lower() == name.lower():
                pid = entry.th32ProcessID
                break
            if not kernel32.Process32Next(snapshot, ctypes.byref(entry)):
                break
    kernel32.CloseHandle(snapshot)
    return pid


class Live:
    def __init__(self, pid: int):
        self.handle = kernel32.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
        if not self.handle:
            raise OSError("OpenProcess failed - try running as administrator")

    def read(self, address: int, size: int) -> bytes | None:
        buf = ctypes.create_string_buffer(size)
        got = ctypes.c_size_t(0)
        ok = kernel32.ReadProcessMemory(
            self.handle, ctypes.c_void_p(address), buf, size, ctypes.byref(got))
        return buf.raw[:got.value] if ok else None

    def regions(self):
        out, address = [], 0
        info = MemoryBasicInformation()
        while address < 0x7FFF0000:
            if not kernel32.VirtualQueryEx(self.handle, ctypes.c_void_p(address),
                                           ctypes.byref(info), ctypes.sizeof(info)):
                break
            size = info.RegionSize or 0x1000
            if (info.State == MEM_COMMIT and not (info.Protect & PAGE_GUARD)
                    and info.Protect != PAGE_NOACCESS and size < 0x4000000):
                out.append((info.BaseAddress or address, size))
            address += size
        return out


def is_default(values, default, tolerance: float = 1e-6) -> bool:
    """A float32 0.8 reads back as 0.800000011920929, so compare loosely."""
    return all(abs(a - b) < tolerance for a, b in zip(values, default))


def colours_at(live: Live, holder: int, lo: int, hi: int):
    """Every 4-float vector in [0,1] with alpha 1, by offset from the holder."""
    found = []
    for delta in range(lo, hi, 4):
        blob = live.read(holder + delta, 16)
        if not blob or len(blob) < 16:
            continue
        values = struct.unpack("<4f", blob)
        if (all(0.0 <= v <= 1.0 for v in values) and values[3] == 1.0
                and any(v > 0.0 for v in values[:3])):
            found.append((delta, values))
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--name", default="voda1", help="material name to look for")
    parser.add_argument("--all", action="store_true",
                        help="print every colour vector, not just the ambient/diffuse pair")
    args = parser.parse_args()

    pid = find_process("HROT.exe")
    if not pid:
        print("HROT.exe is not running", file=sys.stderr)
        return 1
    live = Live(pid)
    print(f"HROT.exe pid {pid}")

    needle = args.name.encode() + b"\x00"
    strings, blobs = [], {}
    for base, size in live.regions():
        data = live.read(base, size)
        if not data:
            continue
        blobs[base] = data
        start = 0
        while True:
            i = data.find(needle, start)
            if i < 0:
                break
            strings.append(base + i)
            start = i + 1
    if not strings:
        print(f"no '{args.name}' string found - is a map loaded?", file=sys.stderr)
        return 1

    targets = set(strings)
    holders = [base + off
               for base, data in blobs.items()
               for off in range(0, len(data) - 4, 4)
               if struct.unpack_from("<I", data, off)[0] in targets]
    print(f"'{args.name}': {len(strings)} strings, {len(holders)} referencing objects\n")

    for holder in holders:
        found = colours_at(live, holder, 0x40, 0x160)
        if not found:
            continue
        print(f"object {holder:#010x}")
        pair = None
        for delta, values in found:
            match = next((v for d, v in found if d == delta + COLOUR_STRIDE), None)
            if match is not None and pair is None:
                pair = (delta, values, match)
        for delta, values in found:
            keep = args.all or (pair and delta in (pair[0], pair[0] + COLOUR_STRIDE))
            if not keep:
                continue
            role = ""
            if pair and delta == pair[0]:
                role = "  ambient"
            elif pair and delta == pair[0] + COLOUR_STRIDE:
                # float32 round-trips to 0.800000011920929, so compare loosely
                if is_default( values, GLSCENE_DEFAULT_DIFFUSE ):
                    role = "  diffuse - GLScene DEFAULT, never set by HROT: NOT a scroll rate"
                else:
                    role = f"  DIFFUSE -> scroll rate = blue = {values[2]:g}"
            print(f"    +{delta:#05x}  ({values[0]:.4g}, {values[1]:.4g}, "
                  f"{values[2]:.4g}, {values[3]:g}){role}")
        print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
