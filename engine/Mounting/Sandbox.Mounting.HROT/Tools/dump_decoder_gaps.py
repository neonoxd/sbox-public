#!/usr/bin/env python3
"""Census of the placement call sites HrotExecutableProps silently skips.

The prop/lamp/glass-panel readers in the mount accept a call site only when its
arguments are pushed as literals, built by the one x87 form the prop reader
knows, or emitted from the counted-loop shape the panel reader knows. Every
other call site is dropped with no error and no geometry - the failure mode this
whole codebase is mostly about.

This is the second independent reading the AGENTS.md asks for: it ports the C#
accept/reject predicate byte-for-byte (the mount walks raw bytes; nothing here
disassembles to make the decision, so a site this flags as a GAP is one the
mount skips), then disassembles each skipped site with capstone to bucket it by
why. Helper addresses and constructor ranges are parsed out of
HrotExecutableProps.cs, never transcribed - a copied table is how dump_signs
once reported seven maps as the whole game.

Categories (see REVERSE_ENGINEERING.md section 12, "Decoder gap census"):
  A  stack-slot reload      mov [esp],imm; push imm; push [esp+4]   (static)
  B  image-const arithmetic fld[k]; fsub/fadd [esp]                 (mostly static)
  C  loop counter (non-LEA) counted row, counter maths not LEA form (static)
  E  adjacency / reg-move   panel loop maths splits the pushes; or  (static)
                            PlaceAtCell via mov ecx,reg not mov ecx,imm
  F  computed float         pushed float is a CALL result / cross-call x87 (mixed)
  D  dynamic                arg read from another entity's fields   (NOT static)

Usage:
    dump_decoder_gaps.py                 the census
    dump_decoder_gaps.py --sites         every gap site, with category
    dump_decoder_gaps.py --check         self-consistency check
"""
from __future__ import annotations

import argparse
import collections
import pathlib
import re
import struct
import sys

import capstone
import pefile

import hrot_re
import dump_signs

CS = r"HrotExecutableProps.cs"


def helper_addresses() -> dict[str, int]:
    """Parse `const uint PlaceX = 0x...;` out of the decoder source."""
    source = pathlib.Path(__file__).resolve().parent.parent / CS
    text = source.read_text(encoding="utf-8-sig")
    found = dict(re.findall(r"const uint (\w+)\s*=\s*(0x[0-9A-Fa-f]+);", text))
    return {name: int(value, 16) for name, value in found.items()}


H = helper_addresses()
GENERIC = {H["PlaceOnFloor"]: 3, H["PlaceAboveFloor"]: 4, H["PlaceAtHeight"]: 4}
LAMP_ARGS = {
    H["PlaceFloorLamp"]: 2, H["PlaceLampPost"]: 2, H["PlaceRaisedLamp"]: 3,
    H["PlaceCeilingChandelier"]: 3, H["PlaceCeilingChandelier2"]: 2,
}
NAME = {v: k for k, v in H.items()}


class Img:
    def __init__(self, path):
        self.pe = pefile.PE(path)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.data = self.pe.__data__
        self.secs = [(s.VirtualAddress, s.Misc_VirtualSize,
                      s.PointerToRawData, s.SizeOfRawData) for s in self.pe.sections]

    def va_to_off(self, va):
        rva = va - self.base
        for (v, vs, raw, rs) in self.secs:
            if v <= rva < v + max(vs, rs):
                off = raw + rva - v
                if off < len(self.data):
                    return off
        return None

    def off_to_va(self, off):
        for (v, vs, raw, rs) in self.secs:
            if raw <= off < raw + rs:
                return self.base + v + off - raw
        return 0


def i32(d, o):
    return struct.unpack_from("<i", d, o)[0]


def u32(d, o):
    return struct.unpack_from("<I", d, o)[0]


def bits_to_f(b):
    return struct.unpack("<f", struct.pack("<I", b & 0xFFFFFFFF))[0]


# ---- faithful port of HrotExecutableProps' accept/reject predicate ----

def _imm_push_back(d, start, cur):
    if cur - 5 >= start and d[cur - 5] == 0x68:
        return cur - 5
    if cur - 2 >= start and d[cur - 2] == 0x6A:
        return cur - 2
    return None


def _computed_float_back(img, d, start, cur):
    end = cur
    if end - 1 >= start and d[end - 1] == 0x9B:
        end -= 1
    if end - 3 < start or d[end - 3] != 0xD9 or d[end - 2] != 0x1C or d[end - 1] != 0x24:
        return None
    end -= 3
    if end - 3 < start or d[end - 3] != 0x83 or d[end - 2] != 0xC4 or d[end - 1] != 0xFC:
        return None
    end -= 3
    if end - 2 < start or d[end - 2] != 0xDE or d[end - 1] != 0xC1:
        return None
    end -= 2
    if end - 6 < start or d[end - 6] != 0xDB or d[end - 5] != 0x2D:
        return None
    if img.va_to_off(u32(d, end - 4)) is None:
        return None
    end -= 6
    if end - 3 >= start and d[end - 3] == 0xDB and d[end - 2] == 0x04 and d[end - 1] == 0x24:
        reg_op, expr = 0xBE, end - 3
        if expr - 3 < start or d[expr - 3] != 0x89 or d[expr - 2] != 0x34 or d[expr - 1] != 0x24:
            return None
        expr -= 3
    elif end - 4 >= start and d[end - 4] == 0xDB and d[end - 3] == 0x44 and d[end - 2] == 0x24:
        stk, reg_op, expr = d[end - 1], 0xBF, end - 4
        if (expr - 4 < start or d[expr - 4] != 0x89 or d[expr - 3] != 0x7C
                or d[expr - 2] != 0x24 or d[expr - 1] != stk):
            return None
        expr -= 4
    else:
        return None
    for i in range(expr - 5, max(start, expr - 2048) - 1, -1):
        if d[i] == reg_op:
            return expr
    return None


def pushes_backwards(img, d, start, end, count):
    cur = end
    for _ in range(count):
        r = _imm_push_back(d, start, cur)
        if r is None:
            r = _computed_float_back(img, d, start, cur)
        if r is None:
            return False
        cur = r
    return True


def special_float_pushes(img, d, start, call, count):
    return any(pushes_backwards(img, d, start, c, count)
               for c in range(call, max(start, call - 24) - 1, -1))


def special_placement_pushes(d, start, call):
    found = 0
    for i in range(call - 5, max(start, call - 32) - 1, -1):
        if d[i] == 0x68 and i + 5 <= call:
            v = bits_to_f(u32(d, i + 1))
            if v == v and -4096.0 <= v <= 4096.0:
                found += 1
                if found == 2:
                    return True
    return False


def cell_placement(d, start, end):
    if end - 10 < start or d[end - 10] != 0xB9 or d[end - 5] != 0xBA:
        return False
    cur = end - 10
    return (cur - 2 >= start and d[cur - 2] == 0x6A) or (cur - 5 >= start and d[cur - 5] == 0x68)


def imm_push_bits(d, start, call, count):
    for cand in range(call, max(start, call - 24) - 1, -1):
        cur, ok = cand, True
        for _ in range(count):
            if cur - 5 >= start and d[cur - 5] == 0x68:
                cur -= 5
            elif cur - 2 >= start and d[cur - 2] == 0x6A:
                cur -= 2
            else:
                ok = False
                break
        if ok:
            return True
    return False


def reg_value(d, start, call, register):
    for p in range(call - 1, max(start, call - 160) - 1, -1):
        if d[p] == 0xB8 + register and p + 5 <= call:
            return i32(d, p + 1)
        if d[p] in (0x33, 0x31) and p + 2 <= call and d[p + 1] == 0xC0 + register * 9:
            return 0
    return None


def _ext_const(d, off):
    if off is None or off + 10 > len(d):
        return None
    mant = struct.unpack_from("<Q", d, off)[0]
    exp = struct.unpack_from("<H", d, off + 8)[0]
    sign = -1.0 if (exp & 0x8000) else 1.0
    exp &= 0x7FFF
    if exp in (0, 0x7FFF):
        return None
    return sign * mant * (2.0 ** (exp - 16383 - 63))


def _computed_arg(img, d, start, cur):
    off, scale = 0.0, 1.0
    if (cur - 8 < start or d[cur - 1] != 0x9B or d[cur - 4] != 0xD9 or d[cur - 3] != 0x1C
            or d[cur - 2] != 0x24 or d[cur - 7] != 0x83 or d[cur - 6] != 0xC4 or d[cur - 5] != 0xFC):
        return None
    p = cur - 7
    if p - 8 >= start and d[p - 8] == 0xDB and d[p - 7] == 0x2D and d[p - 2] == 0xDE:
        if _ext_const(img.data, img.va_to_off(u32(d, p - 6))) is None:
            return None
        if d[p - 1] not in (0xC1, 0xE9, 0xE1, 0xC9):
            return None
        p -= 8
    if p - 6 >= start and d[p - 6] == 0xD8 and d[p - 5] in (0x05, 0x25, 0x2D, 0x0D):
        if img.va_to_off(u32(d, p - 4)) is None:
            return None
        p -= 6
    if p - 3 >= start and d[p - 3] == 0xDB and d[p - 2] == 0x04 and d[p - 1] == 0x24:
        p -= 3
    elif p - 4 >= start and d[p - 4] == 0xDB and d[p - 3] == 0x44 and d[p - 2] == 0x24:
        p -= 4
    else:
        return None
    if p - 3 >= start and d[p - 3] == 0x89 and (d[p - 2] & 0xC7) == 0x04 and d[p - 1] == 0x24:
        spill, p = (d[p - 2] >> 3) & 7, p - 3
    elif p - 4 >= start and d[p - 4] == 0x89 and (d[p - 3] & 0xC7) == 0x44 and d[p - 2] == 0x24:
        spill, p = (d[p - 3] >> 3) & 7, p - 4
    else:
        return None
    reg = spill
    if p - 3 >= start and d[p - 3] == 0x8D and ((d[p - 2] >> 3) & 7) == spill and (d[p - 2] & 0xC0) == 0x40:
        reg, p = d[p - 2] & 7, p - 3
    return (reg, p)


def _call_arguments(img, d, start, call, count):
    for cand in range(call, max(start, call - 24) - 1, -1):
        cur, decoded, computed, ok = cand, [], 0, True
        for _ in range(count):
            if cur - 5 >= start and d[cur - 5] == 0x68:
                decoded.append(("lit", -1)); cur -= 5
            elif cur - 2 >= start and d[cur - 2] == 0x6A:
                decoded.append(("lit", -1)); cur -= 2
            else:
                r = _computed_arg(img, d, start, cur)
                if r is not None:
                    decoded.append(("computed", r[0])); cur = r[1]; computed += 1
                else:
                    ok = False; break
        if ok and computed:
            return decoded
    return None


def _loop_trailer(d, start, end, call):
    for p in range(call + 5, min(end, call + 128) - 5):
        if (0x40 <= d[p] <= 0x47 and d[p + 1] == 0x83 and 0xF8 <= d[p + 2] <= 0xFF
                and d[p + 4] == 0x75 and (d[p] & 7) == (d[p + 2] & 7)):
            tgt = p + 6 + struct.unpack_from("<b", d, p + 5)[0]
            if start <= tgt <= call:
                return (d[p] & 7, d[p + 3], tgt)
    return None


def panel_decoded(img, d, start, end, call):
    if imm_push_bits(d, start, call, 9):
        return True
    parsed = _call_arguments(img, d, start, call, 9)
    if parsed is None:
        return False
    counter = -1
    tr = _loop_trailer(d, start, end, call)
    if tr is not None:
        lc, bound, top = tr
        if any(reg == lc for _, reg in parsed):
            init = reg_value(d, start, top, lc)
            if init is not None and bound > init and bound - init <= 64:
                counter = lc
    seen = set()
    for kind, reg in parsed:
        if kind != "computed" or reg == counter or reg in seen:
            continue
        if reg_value(d, start, call, reg) is None:
            return False
        seen.add(reg)
    return True


def find_gaps(img):
    d = img.data
    ranges = dump_signs.CONSTRUCTORS
    gaps, totals = [], collections.Counter()
    for m in sorted(ranges):
        s_va, e_va = ranges[m]
        start, end = img.va_to_off(s_va), img.va_to_off(e_va)
        i = start
        while i + 9 <= end:
            if d[i] == 0xE8:
                nxt = img.off_to_va(i + 5)
                if nxt:
                    tgt = (nxt + i32(d, i + 1)) & 0xFFFFFFFF
                    if tgt in (H["PlaceCeilingFluorescent"], H["PlaceCeilingBakelite"]):
                        totals[NAME[tgt]] += 1
                        if not special_placement_pushes(d, start, i):
                            gaps.append((m, img.off_to_va(i), NAME[tgt]))
                        i += 1; continue
                    if tgt in LAMP_ARGS:
                        totals[NAME[tgt]] += 1
                        if not special_float_pushes(img, d, start, i, LAMP_ARGS[tgt]):
                            gaps.append((m, img.off_to_va(i), NAME[tgt]))
                        i += 1; continue
                    if tgt == H["PlaceGlassPanel"]:
                        totals["PlaceGlassPanel"] += 1
                        if not panel_decoded(img, d, start, end, i):
                            gaps.append((m, img.off_to_va(i), "PlaceGlassPanel"))
                        i += 1; continue
            if d[i] != 0x66 or d[i + 1] != 0xB8 or d[i + 4] != 0xE8:
                i += 1; continue
            nxt = img.off_to_va(i + 9)
            if not nxt:
                i += 1; continue
            tgt = (nxt + i32(d, i + 5)) & 0xFFFFFFFF
            if tgt == H["PlaceAtCell"]:
                totals["PlaceAtCell"] += 1
                if not cell_placement(d, start, i):
                    gaps.append((m, img.off_to_va(i), "PlaceAtCell"))
                i += 1; continue
            if tgt in GENERIC:
                totals[NAME[tgt]] += 1
                if not pushes_backwards(img, d, start, i, GENERIC[tgt]):
                    gaps.append((m, img.off_to_va(i), NAME[tgt]))
                i += 1; continue
            i += 1
    return gaps, totals


# ---- classification (capstone reading of the setup block) ----

def classify(md, pe, base, ranges, va):
    owner = next((m for m, (s, e) in ranges.items() if s <= va < e), None)
    s, e = ranges[owner]
    insns = list(md.disasm(pe.get_data(s - base, e - s), s))
    idx = next((k for k, x in enumerate(insns) if x.address == va), None)
    if idx is None:
        # The byte-scan matched 66 B8/E8 mid-instruction: not a real call. Map
        # 104's declared range overlaps the lamp helper code, so a couple of
        # these fall inside it. The mount's identical scan skips them too; they
        # are not missing geometry.
        return "P"
    j = idx - 1
    while j > 0 and insns[j].mnemonic != "call":
        j -= 1
    block = insns[j + 1: idx + 1]
    mem_push = [x for x in block if x.mnemonic == "push" and "ptr" in x.op_str]
    dyn = any("[esp" not in x.op_str for x in mem_push)
    stackslot = any("[esp" in x.op_str for x in mem_push)
    has_fild = any(x.mnemonic == "fild" for x in block)
    has_fld = any(x.mnemonic == "fld" for x in block)
    loop_ctr = has_fild and any(x.mnemonic in ("sub", "lea") and re.search(r"e(si|bx|di)", x.op_str) for x in block)
    reg_cell = any(x.mnemonic == "mov" and x.op_str.startswith("ecx,")
                   and not x.op_str.split(",")[1].strip().startswith("0x") for x in block)
    if dyn:
        return "D"
    if reg_cell:
        return "E"
    if has_fld and not has_fild:
        return "B"
    if loop_ctr:
        return "C"
    if stackslot:
        return "A"
    if any(x.mnemonic == "fstp" for x in block):
        return "F"
    return "?"


CAT_TEXT = {
    "A": "stack-slot reload (static)",
    "B": "image-const arithmetic (mostly static)",
    "C": "loop counter, non-LEA (static)",
    "E": "adjacency / reg-move cell (static)",
    "F": "computed float / call-result (mixed)",
    "D": "dynamic - reads another entity (NOT static)",
    "P": "phantom byte match in map-104 helper overlap (not geometry)",
    "?": "unclassified",
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("exe", nargs="?", default=hrot_re.DEFAULT_EXE)
    ap.add_argument("--sites", action="store_true")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    img = Img(args.exe)
    gaps, totals = find_gaps(img)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    ranges = dump_signs.CONSTRUCTORS
    cats = {(m, va): classify(md, img.pe, img.base, ranges, va) for (m, va, _) in gaps}

    prop = sum(1 for (m, va, n) in gaps if n != "PlaceGlassPanel")
    panel = sum(1 for (m, va, n) in gaps if n == "PlaceGlassPanel")

    if args.check:
        # Fingerprint of the retail build these addresses are for. A different
        # exe (game update) will legitimately differ - rerun without --check,
        # confirm the categories still make sense, and update these numbers.
        bad = [k for k, v in cats.items() if v == "?"]
        phantom = sum(1 for v in cats.values() if v == "P")
        print(f"gaps: {len(gaps)}  prop/lamp={prop}  panel={panel}  phantom={phantom}")
        print(f"unclassified: {len(bad)} {bad}")
        ok = prop == 66 and panel == 10 and phantom == 2 and not bad
        print("OK" if ok else "MISMATCH (expected prop=66 panel=10 phantom=2, 0 unclassified)")
        return 0 if ok else 1

    print(f"placement call sites the mount silently skips: {len(gaps)} "
          f"({prop} prop/lamp, {panel} glass-panel)\n")
    by_cat = collections.Counter(cats.values())
    print("by category:")
    for c in ["A", "B", "C", "E", "F", "D", "?"]:
        if by_cat.get(c):
            print(f"  {c}  {by_cat[c]:3}  {CAT_TEXT[c]}")
    print("\nby helper (total / skipped):")
    skipped = collections.Counter(n for (_, _, n) in gaps)
    for name in sorted(totals):
        g = skipped.get(name, 0)
        flag = f"   <- {g} skipped" if g else ""
        print(f"  {name:26s} {totals[name]:4}{flag}")

    if args.sites:
        print("\nsites (addresses are build-specific):")
        for (m, va, n) in gaps:
            print(f"  map {m:>3}  {va:08X}  {n:24s} {cats[(m, va)]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
