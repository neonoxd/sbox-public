#!/usr/bin/env python3
"""Crop one HROT atlas tile and enlarge it without filtering."""

from __future__ import annotations

import sys

from PIL import Image


def main() -> None:
    image = Image.open(sys.argv[1]).convert("RGBA")
    x, y = map(int, sys.argv[2:4])
    columns = int(sys.argv[4])
    rows = int(sys.argv[5])
    output = sys.argv[6]
    left = x * image.width // columns
    top = (y - 1) * image.height // rows
    right = (x + 1) * image.width // columns
    bottom = y * image.height // rows
    tile = image.crop((left, top, right, bottom))
    tile.resize((512, 512), Image.Resampling.NEAREST).save(output)
    print(f"crop=({left},{top})..({right},{bottom}) size={tile.size}")


if __name__ == "__main__":
    main()
