#!/usr/bin/env python3
"""Extract HROT's embedded GLSL shaders from HROT.exe. No game needed.

HROT does its material effects in GLSL, not on the CPU - which is why the water
"animation" is invisible to every CPU-side scan (update case, material setup,
RegisterModel and the world renderer are all static). The shaders are GLScene
`TGLSLShader` sources compiled into the executable as Delphi string blocks:

    0x06 <len:1>  <len bytes of one source line>   (repeated per line)

Thirteen full shaders parse out. The water pair is the interesting one:

  * fragment (uniforms BaseMap, LightMap, BaterkaMap, **DistMap**, u_time):
    a time-driven sine UV wobble, plus a normal-map warp sampled from `DistMap`
    (= `vodanorm.jpg`), sampling `BaseMap` (= `voda1.jpg`) at the warped coords,
    with alpha driven by the normal map's red ("vlnky" = Czech *ripples*);
  * vertex (uniform u_time): `v_coords.y += u_time` - the scroll/flow itself.

`u_time` is the only per-frame input; everything else is constants in the source,
so the exact scroll/wobble/warp are readable here rather than measured. Other
shaders are lighting/spec/decal passes; one scrolls clouds (`MrakCoord`,
*mrak* = cloud).

Usage:
    dump_shaders.py                 list shaders with their uniforms/samplers
    dump_shaders.py --print N       print full source of shader N
    dump_shaders.py --out DIR       write every shader to DIR/NN_kind[_tag].glsl
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys

import hrot_re


def parse_lines(data: bytes, start: int) -> str:
    """Reassemble one shader from its `0x06 <len> <text>` line records."""
    out, p = [], start
    while p + 2 < len(data) and data[p] == 0x06:
        length = data[p + 1]
        text = data[p + 2:p + 2 + length]
        if not all((32 <= b < 127) or b in (9, 10, 13) for b in text):
            break
        out.append(text.decode("latin-1"))
        p += 2 + length
        if length == 0:
            break
    return "".join(out)


def extract(image) -> list[tuple[int, str]]:
    """Every embedded shader, as (virtual address, source), by its #version line."""
    data = image.data
    shaders, seen = [], set()
    for match in re.finditer(rb"#version", data):
        start = match.start() - 2          # back over the <len> and 0x06 markers
        if start < 0 or data[start] != 0x06 or start in seen:
            continue
        source = parse_lines(data, start)
        if "void main" in source:
            seen.add(start)
            shaders.append((image.off2va(start), source))
    return shaders


def classify(source: str) -> tuple[str, str]:
    """(kind, tag) - fragment/vertex, and a short role guess from its uniforms."""
    kind = "frag" if "gl_FragColor" in source else "vert"
    if "DistMap" in source or re.search(r"v_coords\.y\s*\+=\s*u_time", source):
        tag = "water"
    elif "MrakCoord" in source:
        tag = "clouds"
    elif "SpecMap" in source:
        tag = "spec"
    else:
        tag = ""
    return kind, tag


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("exe", nargs="?", default=hrot_re.DEFAULT_EXE)
    parser.add_argument("--print", dest="index", type=int)
    parser.add_argument("--out")
    args = parser.parse_args()

    image = hrot_re.Image(args.exe)
    shaders = extract(image)

    if args.index is not None:
        print(shaders[args.index][1])
        return 0

    if args.out:
        out = pathlib.Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        for i, (_, source) in enumerate(shaders):
            kind, tag = classify(source)
            name = f"{i:02d}_{kind}" + (f"_{tag}" if tag else "") + ".glsl"
            (out / name).write_text(source, encoding="utf-8")
        print(f"wrote {len(shaders)} shaders to {out}/", file=sys.stderr)
        return 0

    for i, (va, source) in enumerate(shaders):
        kind, tag = classify(source)
        uniforms = re.findall(r"uniform\s+\w+\s+(\w+)", source)
        samplers = re.findall(r"uniform\s+sampler2D\s+(\w+)", source)
        print(f"[{i:2d}] {va:#010x} {kind:4s} {tag or '':7s} "
              f"samplers={samplers} uniforms={uniforms}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
