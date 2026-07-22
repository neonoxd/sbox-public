#!/usr/bin/env python3
"""Which prop models spin, on which axis, and how fast. No game needed.

Mirrors `HrotExecutableAnimation.ReadModelSpins` closely enough to check it - the
C# walks raw bytes, this disassembles the same bytes, and a disagreement means
the mount is wrong.

HROT animates a spinning prop from its update case, the same per-model switch the
ambient sounds come out of:

    movzx eax, word [ebx-0x70]        ; model id
    mov   al,  byte [eax + 0xD6E7D3]  ; model -> case index
    jmp   dword [eax*4 + 0xD6EB2C]    ; case -> code

Inside a spinning case the idiom is a read-add-write on one Euler angle of the
object's orientation struct at [obj+0x200]:

    mov eax, [ebx-0x74]        ; the object
    call <angle getter>        ; st0 = orientation[OFF]
    fadd dword [const]         ; += degrees THIS TICK (no dt: fixed 100 Hz tick)
    add esp,-4 / fstp [esp] / wait
    mov eax, [ebx-0x74]
    call <angle setter>        ; orientation[OFF] = st0

The angle at OFF 0x24 is yaw - its setter 0x4A326C is the same one the player
start facing uses. OFF 0x20 is a second axis (pitch/roll); its s&box mapping is
resolved by eye in the editor, not here.

**The rate is degrees per fixed sim tick, and HROT ticks at 100 Hz**, so the
angular velocity is `degrees * 100` per second. The increment has no dt scaling
but the spin is not framerate-dependent: HROT drives a GLScene TGLCadencer whose
FixedDeltaTime is 0 (variable) and runs its own fixed-step accumulator. The
per-tick object walker at 0x00D4F7FC is followed by `inc [0x17D76A8]`, a sim-tick
counter that reads a rock-steady 100 Hz live (the fixed step 0.01 is bracketed by
the 0.009/0.011 clamp constants in that code). The intact fan (565) at 4.0 against
the damaged one (566) at 1.5 is HROT's own relative pair.

Usage:
    dump_model_spins.py
    dump_model_spins.py --model 123
"""
from __future__ import annotations
import argparse, struct, subprocess, sys, pathlib
import hrot_re

CASE_TABLE = 0x00D6E7D3
JUMP_TABLE = 0x00D6EB2C
MAX_MODEL  = 0x358
CASE_COUNT = 224
CASE_SPAN  = 0x400

# The angle getter/setter methods touch one Euler offset in the orientation
# struct at [obj+0x200]. A setter is `...; mov eax,[eax+0x200]; fcomp [eax+OFF]`.
AXIS_NAME = {0x20: "axis0x20", 0x24: "yaw"}


def accessor_offset(img, va):
    """(kind, offset) if va is an angle getter/setter for a known Euler slot."""
    ins = [(i.mnemonic, i.op_str) for i in img.disasm(va, 0x30)]
    for a, b in zip(ins, ins[1:]):
        if a == ("mov", "eax, dword ptr [eax + 0x200]"):
            if b[0] == "mov" and b[1].startswith("eax, dword ptr [eax + 0x"):
                off = int(b[1].split("+ ")[1].rstrip("]"), 16)
                if off in AXIS_NAME: return ("get", off)
            if b[0] == "fcomp" and b[1].startswith("dword ptr [eax + 0x"):
                off = int(b[1].split("+ ")[1].rstrip("]"), 16)
                if off in AXIS_NAME: return ("set", off)
    return None


def read_spins(img):
    targets = [img.u32(JUMP_TABLE + i * 4) for i in range(CASE_COUNT)]
    starts = sorted(set(t for t in targets if t))
    setter_axis = {}  # va -> offset, memoised

    def case_spins(entry):
        end = min([s for s in starts if s > entry] + [entry + CASE_SPAN])
        begin, finish = img.va2off(entry), img.va2off(end)
        if begin is None or finish is None:
            return []
        ins = list(img._md.disasm(img.data[begin:finish], entry))
        out = []
        for k, insn in enumerate(ins):
            # fadd dword [const]  (D8 05 <addr32>)
            if insn.mnemonic != "fadd" or "dword ptr [0x" not in insn.op_str:
                continue
            const_va = int(insn.op_str.split("[")[1].rstrip("]"), 16)
            deg = img.f32(const_va)
            # A per-tick spin rate is a small positive angle; anything else is a
            # fadd that isn't a rotation (or an unmapped operand).
            if deg is None or not (0.0 < deg <= 90.0):
                continue
            # the write-back setter call within a few instructions after
            for j in range(k + 1, min(k + 8, len(ins))):
                if ins[j].mnemonic != "call":
                    continue
                try: tgt = int(ins[j].op_str, 16)
                except ValueError: continue
                if tgt not in setter_axis:
                    kind = accessor_offset(img, tgt)
                    setter_axis[tgt] = kind[1] if kind and kind[0] == "set" else None
                off = setter_axis[tgt]
                if off is not None:
                    out.append((off, deg))
                break
        return out

    per_case, spins = {}, {}
    for model in range(MAX_MODEL + 1):
        idx = img.u8(CASE_TABLE + model)
        if idx >= CASE_COUNT:
            continue
        if idx not in per_case:
            per_case[idx] = case_spins(targets[idx])
        if per_case[idx]:
            spins[model] = per_case[idx]
    return spins


def model_names(exe):
    tool = pathlib.Path(__file__).with_name("list_static_models.py")
    out = subprocess.run([sys.executable, str(tool), exe],
                         capture_output=True, text=True).stdout
    names = {}
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 2 and p[0].isdigit():
            names[int(p[0])] = p[1].replace("model=", "")
    return names


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("exe", nargs="?", default=hrot_re.DEFAULT_EXE)
    ap.add_argument("--model", type=int)
    args = ap.parse_args()

    img = hrot_re.Image(args.exe)
    spins = read_spins(img)
    names = model_names(args.exe)

    for model in sorted(spins):
        if args.model is not None and model != args.model:
            continue
        parts = ", ".join(f"{AXIS_NAME[o]} += {d:g}/tick" for o, d in spins[model])
        print(f"  model {model:4d} {names.get(model,'?'):24s} -> {parts}")
    print(f"\n{len(spins)} spinning model(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
