#!/usr/bin/env python3
"""Match a screenshot crop against axis-aligned regions of a source texture."""

from __future__ import annotations

import sys

from PIL import Image, ImageChops, ImageFilter, ImageOps, ImageStat


def score(left: Image.Image, right: Image.Image) -> float:
    left_edges = ImageOps.autocontrast(
        left.convert("L").filter(ImageFilter.FIND_EDGES)
    )
    right_edges = ImageOps.autocontrast(
        right.convert("L").filter(ImageFilter.FIND_EDGES)
    )
    difference = ImageChops.difference(left_edges, right_edges)
    return sum(value * value for value in ImageStat.Stat(difference).rms)


def projection_score(left: Image.Image, right: Image.Image) -> float:
    left = left.convert("L")
    right = right.convert("L")

    def correlation(first: list[int], second: list[int]) -> float:
        first_mean = sum(first) / len(first)
        second_mean = sum(second) / len(second)
        first_centered = [value - first_mean for value in first]
        second_centered = [value - second_mean for value in second]
        numerator = sum(a * b for a, b in zip(first_centered, second_centered))
        first_length = sum(value * value for value in first_centered) ** 0.5
        second_length = sum(value * value for value in second_centered) ** 0.5
        return numerator / max(first_length * second_length, 0.001)

    left_x = list(left.resize((right.width, 1), Image.Resampling.BOX).getdata())
    right_x = list(right.resize((right.width, 1), Image.Resampling.BOX).getdata())
    left_y = list(left.resize((1, right.height), Image.Resampling.BOX).getdata())
    right_y = list(right.resize((1, right.height), Image.Resampling.BOX).getdata())
    return -(correlation(left_x, right_x) + correlation(left_y, right_y))


def main() -> None:
    source = Image.open(sys.argv[1]).convert("RGBA")
    sample = Image.open(sys.argv[2]).convert("RGB")
    background = Image.new("RGBA", source.size, (0, 0, 0, 255))
    composited = Image.alpha_composite(background, source).convert("RGB")
    print(f"source={source.size} sample={sample.size}")

    candidates = []
    for columns in (2, 4, 8):
        for rows in (1, 2, 4, 8):
            width = source.width // columns
            height = source.height // rows
            for y in range(rows):
                for x in range(columns):
                    region = composited.crop((
                        x * width, y * height,
                        (x + 1) * width, (y + 1) * height,
                    ))
                    resized = region.resize(sample.size, Image.Resampling.BILINEAR)
                    candidates.append((
                        projection_score(resized, sample),
                        x / columns, (x + 1) / columns,
                        y / rows, (y + 1) / rows,
                    ))

    # Also search arbitrary rectangles aligned to sklo's 32-pixel authoring
    # grid. The game frequently uses only a sub-rectangle and stretches it.
    for left in range(0, source.width, 32):
        for right in range(left + 64, source.width + 1, 32):
            for top in range(0, source.height, 32):
                for bottom in range(top + 64, source.height + 1, 32):
                    region = composited.crop((left, top, right, bottom))
                    resized = region.resize(sample.size, Image.Resampling.BILINEAR)
                    candidates.append((
                        projection_score(resized, sample),
                        left / source.width, right / source.width,
                        top / source.height, bottom / source.height,
                    ))

    for result in sorted(candidates)[:12]:
        print(
            f"score={result[0]:.3f} "
            f"u={result[1]:.3f}..{result[2]:.3f} "
            f"v={result[3]:.3f}..{result[4]:.3f}"
        )

    if len(sys.argv) > 3:
        composited.save(sys.argv[3])


if __name__ == "__main__":
    main()
