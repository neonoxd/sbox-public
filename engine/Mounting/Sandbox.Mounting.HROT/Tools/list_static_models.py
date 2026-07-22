#!/usr/bin/env python3
"""List HROT.exe static-model registrations, optionally filtered by ID."""

from __future__ import annotations

import struct
import sys

import pefile


def main() -> None:
    pe = pefile.PE(sys.argv[1])
    wanted = {int(value, 0) for value in sys.argv[2:]}
    data = pe.__data__

    def read_string(virtual_address: int) -> str | None:
        try:
            offset = pe.get_offset_from_rva(
                virtual_address - pe.OPTIONAL_HEADER.ImageBase
            )
        except pefile.PEFormatError:
            return None
        end = data.find(b"\0", offset, offset + 128)
        if end < 0:
            return None
        try:
            value = data[offset:end].decode("ascii")
        except UnicodeDecodeError:
            return None
        valid = set(
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "0123456789_-.\\/"
        )
        return value if value and all(character in valid for character in value) else None

    for offset in range(len(data) - 19):
        if (
            data[offset] != 0xB9
            or data[offset + 5] != 0xBA
            or data[offset + 10 : offset + 12] != b"\x66\xb8"
            or data[offset + 14] != 0xE8
        ):
            continue
        texture_address = struct.unpack_from("<I", data, offset + 1)[0]
        model_address = struct.unpack_from("<I", data, offset + 6)[0]
        model_id = struct.unpack_from("<H", data, offset + 12)[0]
        if wanted and model_id not in wanted:
            continue
        texture = read_string(texture_address)
        model = read_string(model_address)
        if texture and model:
            print(f"{model_id:4} model={model:<32} texture={texture}")


if __name__ == "__main__":
    main()
