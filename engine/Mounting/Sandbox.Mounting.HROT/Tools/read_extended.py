#!/usr/bin/env python3
"""Read Delphi/x87 80-bit extended constants from HROT.exe."""

from __future__ import annotations

import math
import sys

import pefile


def decode_extended(value: bytes) -> float:
    significand = int.from_bytes(value[:8], "little")
    sign_exponent = int.from_bytes(value[8:10], "little")
    sign = -1.0 if sign_exponent & 0x8000 else 1.0
    exponent = sign_exponent & 0x7FFF
    if exponent == 0 and significand == 0:
        return math.copysign(0.0, sign)
    if exponent == 0x7FFF:
        return math.copysign(math.inf, sign)
    return sign * math.ldexp(significand / (1 << 63), exponent - 16383)


def main() -> None:
    pe = pefile.PE(sys.argv[1])
    image = pe.OPTIONAL_HEADER.ImageBase
    for text in sys.argv[2:]:
        address = int(text, 16)
        raw = pe.get_data(address - image, 10)
        print(f"{address:08X} {raw.hex()} {decode_extended(raw):.9g}")


if __name__ == "__main__":
    main()
