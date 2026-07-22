#!/usr/bin/env python3
"""Print object bounds, texture names and mesh counts from a legacy 3DS."""

from __future__ import annotations

import struct
import sys


def read_cstring(data: bytes, offset: int, end: int) -> tuple[str, int]:
    finish = data.find(b"\0", offset, end)
    if finish < 0:
        return "", end
    return data[offset:finish].decode("ascii", "replace"), finish + 1


def main() -> None:
    data = open(sys.argv[1], "rb").read()
    objects: list[dict] = []
    textures: list[str] = []

    def chunks(start: int, end: int, current: dict | None = None) -> None:
        cursor = start
        while cursor + 6 <= end:
            chunk_id, length = struct.unpack_from("<HI", data, cursor)
            if length < 6 or cursor + length > end:
                break
            content, chunk_end = cursor + 6, cursor + length
            if chunk_id in (0x4D4D, 0x3D3D, 0x4100, 0xAFFF, 0xA200):
                chunks(content, chunk_end, current)
            elif chunk_id == 0x4000:
                name, nested = read_cstring(data, content, chunk_end)
                current = {"name": name, "vertices": [], "faces": 0, "uvs": 0}
                objects.append(current)
                chunks(nested, chunk_end, current)
            elif chunk_id == 0x4110 and current is not None:
                count = struct.unpack_from("<H", data, content)[0]
                current["vertices"].extend(
                    struct.unpack_from("<3f", data, content + 2 + index * 12)
                    for index in range(count)
                )
            elif chunk_id == 0x4120 and current is not None:
                current["faces"] += struct.unpack_from("<H", data, content)[0]
            elif chunk_id == 0x4140 and current is not None:
                current["uvs"] += struct.unpack_from("<H", data, content)[0]
            elif chunk_id == 0xA300:
                texture, _ = read_cstring(data, content, chunk_end)
                textures.append(texture)
            cursor = chunk_end

    chunks(0, len(data))
    print("textures:", textures)
    for obj in objects:
        vertices = obj["vertices"]
        if vertices:
            minimum = tuple(min(vertex[axis] for vertex in vertices) for axis in range(3))
            maximum = tuple(max(vertex[axis] for vertex in vertices) for axis in range(3))
        else:
            minimum = maximum = ()
        print(
            f"{obj['name']}: vertices={len(vertices)} faces={obj['faces']} "
            f"uvs={obj['uvs']} min={minimum} max={maximum}"
        )


if __name__ == "__main__":
    main()
