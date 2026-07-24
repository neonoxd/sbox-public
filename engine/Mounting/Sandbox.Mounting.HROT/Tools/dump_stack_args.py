#!/usr/bin/env python3
"""Recover placement arguments the backward reader cannot, by forward simulation.

`HrotExecutableProps` walks *backward* from a placement call collecting literal
pushes. That cannot see category A of the decoder-gap census (section 12): HROT
parks a float in the stack slot with `mov [esp],imm` and every sibling placement
re-reads it through `push [esp+4]`. The write can precede the *previous* call -
the callees pop their own arguments, so the slot survives - and no bounded
backward search reaches it.

This is the reference the mount's own forward pass has to agree with. It models
the two things the backward reader lacks:

  * `esp`, so a stack displacement means something;
  * stack memory, so a slot written once and read many calls later resolves.

Deliberately conservative: anything that could move `esp` or clobber a slot in a
way this does not model (a call that is not a known helper, an unrecognised
write through esp) drops the affected slots to unknown rather than guessing. An
argument this tool reports is one it actually traced; a `None` is an honest gap,
which is the whole point - a plausible wrong number here would be worse than a
missing one.

Usage:
    dump_stack_args.py                  every recovered site, all 32 maps
    dump_stack_args.py --map 2          one map
    dump_stack_args.py --model 257      one model
"""
from __future__ import annotations

import argparse
import struct
import sys

import hrot_re
# The prop-constructor ranges are parsed out of HrotExecutableProps.cs by
# dump_signs, so this tool cannot drift from the mount's own table.
from dump_signs import load_constructors

# Placement helpers and how many floats each takes on the stack. The model id
# arrives in AX, so it is not a stack argument. Push order is argument order.
HELPERS = {
    0x00DBDDE0: ("PlaceOnFloor", 3),      # x, z, yaw
    0x00DBDE24: ("PlaceAboveFloor", 4),   # x, vertical offset, z, yaw
    0x00DBDF04: ("PlaceAtHeight", 4),     # x, y, z, yaw
    0x00DBE468: ("PlaceAtCell", 3),
    0x00DBDD64: ("ScaleUniform", 1),      # applies to the previous placement
}

# SetCoordComponent(coords, index, value) writes [coords + 0x20 + index*4] - the
# same vector layout the orientation struct uses. HROT reaches it through the
# just-placed object's Scale coordinates at +0x5C:
#
#   push <value>
#   mov eax,[0xDE7EC8]; mov eax,[eax]     ; index of the object just placed
#   mov edx,eax; shl eax,4; sub eax,edx   ; *15
#   mov edx,[0xDE7C94]; mov eax,[edx+eax*8]
#   mov eax,[eax+0x5C]                    ; its Scale coordinates
#   mov edx,<component>
#   call 0x492D18
#
# This is per-axis scale - a second scaling mechanism alongside the uniform
# helper. Components HROT never writes stay 1.
SET_COORD_COMPONENT = 0x00492D18


class Stack:
    """esp-relative memory. esp counts down from 0 as things are pushed."""

    def __init__(self):
        self.esp = 0
        self.mem: dict[int, float | None] = {}

    def push(self, value):
        self.esp -= 4
        self.mem[self.esp] = value

    def write(self, disp, value):
        self.mem[self.esp + disp] = value

    def read(self, disp):
        return self.mem.get(self.esp + disp)

    def pop(self, count):
        for _ in range(count):
            self.mem.pop(self.esp, None)
            self.esp += 4

    def clobber_all(self):
        self.mem.clear()


def bits_to_float(value: int) -> float:
    return struct.unpack("<f", struct.pack("<I", value & 0xFFFFFFFF))[0]


def simulate(img, start, end, scales=None):
    """Walk one constructor forward, yielding (va, model, helper, args).

    When `scales` is a dict it collects per-axis scale as
    {placement va: [c0, c1, c2]}, components HROT never sets left at 1.
    """
    begin = img.va2off(start)
    code = img.data[begin:begin + (end - start)]
    stack = Stack()
    model = None
    edx = None          # the scale setter takes its component in EDX
    placement = None    # the object a following scale component attaches to

    for insn in img._md.disasm(code, start):
        m, op = insn.mnemonic, insn.op_str

        # model id for the next placement
        if m == "mov" and op.startswith("ax, "):
            try:
                model = int(op.split(", ")[1], 0)
            except ValueError:
                model = None
            continue

        if m == "mov" and op.startswith("edx, "):
            rhs = op.split(", ")[1]
            edx = int(rhs, 0) if rhs.startswith("0x") or rhs.isdigit() else None
            continue

        if m == "xor" and op == "edx, edx":
            edx = 0
            continue

        if m == "push":
            if op.startswith("0x") or op.isdigit():
                try:
                    stack.push(bits_to_float(int(op, 0)))
                except ValueError:
                    stack.push(None)
            elif "esp" in op and "ptr" in op:
                disp = 0
                if "+" in op:
                    disp = int(op.split("+")[1].split("]")[0].strip(), 0)
                stack.push(stack.read(disp))
            else:
                stack.push(None)          # a register or something unmodelled
            continue

        # mov dword ptr [esp (+ disp)], imm   - the category A write
        if m == "mov" and op.startswith("dword ptr [esp"):
            try:
                lhs, rhs = op.split("],")
                disp = 0
                if "+" in lhs:
                    disp = int(lhs.split("+")[1].strip(), 0)
                rhs = rhs.strip()
                stack.write(disp, bits_to_float(int(rhs, 0))
                            if rhs.startswith("0x") or rhs.isdigit() else None)
            except (ValueError, IndexError):
                stack.clobber_all()
            continue

        if m in ("add", "sub") and op.startswith("esp, "):
            try:
                delta = int(op.split(", ")[1], 0)
                if delta > 0x7FFFFFFF:
                    delta -= 0x100000000
                # `add esp, -4` is the x87 spill idiom: it makes room, value next.
                if m == "add":
                    if delta < 0:
                        stack.esp += delta
                    else:
                        stack.pop(delta // 4)
                else:
                    stack.esp -= delta
            except ValueError:
                stack.clobber_all()
            continue

        if m == "call":
            try:
                target = int(op, 16)
            except ValueError:
                stack.clobber_all()
                continue
            if target == SET_COORD_COMPONENT:
                value = stack.read(0)
                if scales is not None and placement is not None \
                        and value is not None and edx in (0, 1, 2):
                    scales.setdefault(placement, [1.0, 1.0, 1.0])[edx] = value
                stack.pop(1)
                continue
            if target in HELPERS:
                name, count = HELPERS[target]
                args = [stack.read((count - 1 - i) * 4) for i in range(count)]
                yield (insn.address, model, name, args)
                stack.pop(count)          # stdcall: the callee pops its arguments
                # Scale components that follow attach to this object even when an
                # argument did not resolve - the backward reader may have it.
                if name != "ScaleUniform":
                    placement = insn.address
                    model = None
            else:
                # An unknown callee may do anything to the slots we care about,
                # and may itself be the object a following scale component
                # belongs to. Map 104's 183 scale writes follow Delphi/GLScene
                # constructors rather than placements; dropping the placement
                # stops them attaching to whichever prop was placed last.
                stack.clobber_all()
                placement = None
                edx = None
            continue

        # x87 stores into the spill slot make it a computed value we did not trace
        if m in ("fstp", "fst") and "[esp" in op:
            disp = 0
            if "+" in op:
                disp = int(op.split("+")[1].split("]")[0].strip(), 0)
            stack.write(disp, None)
            continue


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("exe", nargs="?", default=hrot_re.DEFAULT_EXE)
    parser.add_argument("--map", type=int)
    parser.add_argument("--model", type=int)
    parser.add_argument("--only-recovered", action="store_true",
                        help="only sites with a non-literal argument this pass resolved")
    parser.add_argument("--scales", action="store_true",
                        help="only placements carrying a per-axis scale")
    args = parser.parse_args()

    img = hrot_re.Image(args.exe)
    ranges = load_constructors()

    total = resolved = scaled = 0
    for map_id in sorted(ranges):
        if args.map is not None and map_id != args.map:
            continue
        start, end = ranges[map_id]
        scales: dict[int, list[float]] = {}
        sites = list(simulate(img, start, end, scales))
        for va, model, helper, values in sites:
            if args.model is not None and model != args.model:
                continue
            axis = scales.get(va)
            if args.scales and axis is None:
                continue
            total += 1
            if any(v is None for v in values):
                continue
            resolved += 1
            shown = ", ".join(f"{v:g}" for v in values)
            suffix = ""
            if axis is not None:
                scaled += 1
                suffix = "  scale (" + ", ".join(f"{c:g}" for c in axis) + ")"
            print(f"  map {map_id:>3}  {va:08X}  model {model if model is not None else '?':>4}"
                  f"  {helper:16s} ({shown}){suffix}")

    print(f"\n{resolved}/{total} placement sites fully resolved by forward simulation",
          file=sys.stderr)
    print(f"{scaled} of them carry a per-axis scale", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
