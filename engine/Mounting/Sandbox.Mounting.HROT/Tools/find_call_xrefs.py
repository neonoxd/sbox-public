#!/usr/bin/env python3
"""Find raw x86 near CALL references to one virtual address."""

from __future__ import annotations

import struct
import sys

import pefile


def main() -> None:
	pe = pefile.PE(sys.argv[1])
	target = int(sys.argv[2], 0)
	image = pe.OPTIONAL_HEADER.ImageBase
	for section in pe.sections:
		data = section.get_data()
		base = image + section.VirtualAddress
		for offset in range(len(data) - 4):
			if data[offset] != 0xE8:
				continue
			destination = base + offset + 5 + struct.unpack_from("<i", data, offset + 1)[0]
			if destination == target:
				print(f"{base + offset:08X}")


if __name__ == "__main__":
	main()
