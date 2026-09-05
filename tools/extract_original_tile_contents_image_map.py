#!/usr/bin/env python3
"""Extract imageIndexForTileContents() from The Blockheads 1.7.6 ARMv7 ELF.

The function returns atlas image indices for Tile contents.  It first handles
Tile byte 11 when tileIsAirWaterOrSnow() is true, then falls back to a Tile byte
3 switch.  Unsupported values return -1.  Only case targets with the exact
`movw r0; str r0,[fp,#-4]; b return` shape are accepted as direct evidence.
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

FUNCTION_VA = 0x00A13E6C
FUNCTION_SIZE = 640
RETURN_TARGET = 0x00A140E0
CONTENTS_TABLE_VA = 0x00A13F10
CONTENTS_FIRST = 66
CONTENTS_LAST = 81
FALLBACK_TABLE_VA = 0x00A14090
FALLBACK_FIRST = 96
FALLBACK_LAST = 104
INVALID_TARGET = 0x00A140D4
EXPLICIT_CONTENTS = {
    96: (112, 0x00A14054),
    124: (446, 0x00A1403C),
    125: (601, 0x00A14024),
    147: (760, 0x00A13FDC),
    148: (762, 0x00A13FE8),
}


class Elf32Arm:
    def __init__(self, path: Path) -> None:
        self.data = path.read_bytes()
        if self.data[:4] != b"\x7fELF" or self.data[4] != 1 or self.data[5] != 1:
            raise ValueError("expected a little-endian ELF32 file")
        if struct.unpack_from("<H", self.data, 18)[0] != 40:
            raise ValueError("expected EM_ARM")
        phoff = struct.unpack_from("<I", self.data, 28)[0]
        phentsize, phnum = struct.unpack_from("<HH", self.data, 42)
        self.loads: list[tuple[int, int, int]] = []
        for index in range(phnum):
            offset = phoff + index * phentsize
            p_type, p_offset, p_vaddr, _, p_filesz = struct.unpack_from(
                "<IIIII", self.data, offset
            )
            if p_type == 1:
                self.loads.append((p_vaddr, p_vaddr + p_filesz, p_offset))

    def read_va(self, va: int, size: int) -> bytes:
        for start, end, file_offset in self.loads:
            if start <= va and va + size <= end:
                begin = file_offset + va - start
                return self.data[begin : begin + size]
        raise ValueError(f"virtual address is not file-backed: 0x{va:08x}")

    def word(self, va: int) -> int:
        return struct.unpack("<I", self.read_va(va, 4))[0]


def movw_r0_immediate(word: int) -> int | None:
    if (word & 0x0FF00000) != 0x03000000 or ((word >> 12) & 0xF) != 0:
        return None
    return ((word >> 4) & 0xF000) | (word & 0x0FFF)


def branch_target(address: int, word: int) -> int | None:
    if (word & 0xFF000000) != 0xEA000000:
        return None
    immediate = word & 0x00FFFFFF
    if immediate & 0x00800000:
        immediate -= 0x01000000
    return address + 8 + immediate * 4


def direct_image(elf: Elf32Arm, target: int) -> int | None:
    image = movw_r0_immediate(elf.word(target))
    if image is None or elf.word(target + 4) != 0xE50B0004:
        return None
    if branch_target(target + 8, elf.word(target + 8)) != RETURN_TARGET:
        return None
    return image


def table_rows(
    elf: Elf32Arm, field_offset: int, base: int, first: int, last: int
) -> list[tuple[int, int, int, int, int]]:
    rows = []
    table = elf.read_va(base, (last - first + 1) * 4)
    for value in range(first, last + 1):
        relative = struct.unpack_from("<i", table, (value - first) * 4)[0]
        target = base + relative
        image = direct_image(elf, target)
        rows.append((field_offset, value, -1 if image is None else image,
                     -1 if image is None else image % 32,
                     -1 if image is None else image // 32, target))
    return rows


def extract(elf: Elf32Arm) -> str:
    rows = table_rows(elf, 11, CONTENTS_TABLE_VA, CONTENTS_FIRST, CONTENTS_LAST)
    for value, (expected_image, target) in EXPLICIT_CONTENTS.items():
        actual = direct_image(elf, target)
        if actual != expected_image:
            raise ValueError(
                f"explicit contents case {value} changed: expected {expected_image}, got {actual}"
            )
        rows.append((11, value, actual, actual % 32, actual // 32, target))
    rows.extend(table_rows(elf, 3, FALLBACK_TABLE_VA, FALLBACK_FIRST, FALLBACK_LAST))
    lines = ["tile_offset\ttile_value\timage_index\tcol\trow\tcase_target"]
    for offset, value, image, col, row, target in sorted(rows):
        lines.append(
            f"{offset}\t{value}\t{image}\t{col}\t{row}\t0x{target:08x}"
        )
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("libapplication", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    text = extract(Elf32Arm(args.libapplication))
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
