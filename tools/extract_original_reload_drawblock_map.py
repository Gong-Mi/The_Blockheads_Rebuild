#!/usr/bin/env python3
"""Extract direct TileType image assignments from WorldHelper reloadDrawBlock.

The original 1.7.6 method switches on Tile byte 0 (values 1..77) at
0x00a20ef0.  Each case initializes image slots later selected by the three block
passes.  This extractor records only constants assigned before a case's first
conditional branch; field-sensitive cases stay `conditional`.
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

METHOD_VA = 0x00A1D730
TABLE_VA = 0x00A20EF0
FIRST_TILE_TYPE = 1
LAST_TILE_TYPE = 77
PRIMARY_SLOT = 1336
PRIMARY_PAIR_SLOT = 1340
SECONDARY_SLOT = 1352
SECONDARY_PAIR_SLOT = 1356
SLOTS = (PRIMARY_SLOT, PRIMARY_PAIR_SLOT, SECONDARY_SLOT, SECONDARY_PAIR_SLOT)


class Elf32Arm:
    def __init__(self, path: Path) -> None:
        self.data = path.read_bytes()
        if self.data[:4] != b"\x7fELF" or self.data[4] != 1 or self.data[5] != 1:
            raise ValueError("expected little-endian ELF32")
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
        raise ValueError(f"unmapped VA 0x{va:08x}")

    def word(self, va: int) -> int:
        return struct.unpack("<I", self.read_va(va, 4))[0]


def movw(word: int) -> tuple[int, int] | None:
    if (word & 0x0FF00000) != 0x03000000:
        return None
    register = (word >> 12) & 0xF
    immediate = ((word >> 4) & 0xF000) | (word & 0x0FFF)
    return register, immediate


def branch(word: int) -> bool:
    return (word & 0x0E000000) == 0x0A000000


def constant_slot_prefix(elf: Elf32Arm, target: int) -> tuple[dict[int, int], bool]:
    constants: dict[int, int] = {}
    slots: dict[int, int] = {}
    conditional_before_assignment = False
    for index in range(96):
        word = elf.word(target + index * 4)
        decoded = movw(word)
        if decoded:
            constants[decoded[0]] = decoded[1]
        if (word & 0xFFFF0000) == 0xE50B0000:
            register = (word >> 12) & 0xF
            offset = word & 0xFFF
            if offset in SLOTS and register in constants:
                slots[offset] = constants[register]
        if branch(word):
            condition = word >> 28
            if condition != 0xE and not slots:
                conditional_before_assignment = True
            if condition == 0xE:
                break
    return slots, conditional_before_assignment


def cell(image: int | None) -> tuple[str, str]:
    if image is None:
        return "", ""
    return str(image % 32), str(image // 32)


def extract(elf: Elf32Arm) -> str:
    table = elf.read_va(TABLE_VA, (LAST_TILE_TYPE - FIRST_TILE_TYPE + 1) * 4)
    header = (
        "tile_type\tresolution\tprimary_image\tprimary_col\tprimary_row\t"
        "secondary_image\tsecondary_col\tsecondary_row\tcase_target"
    )
    lines = [header]
    for tile_type in range(FIRST_TILE_TYPE, LAST_TILE_TYPE + 1):
        relative = struct.unpack_from(
            "<i", table, (tile_type - FIRST_TILE_TYPE) * 4
        )[0]
        target = TABLE_VA + relative
        slots, conditional = constant_slot_prefix(elf, target)
        primary = slots.get(PRIMARY_SLOT)
        secondary = slots.get(SECONDARY_SLOT)
        resolution = "conditional" if conditional else ("direct" if slots else "default")
        pcol, prow = cell(primary)
        scol, srow = cell(secondary)
        lines.append(
            "\t".join(
                (
                    str(tile_type), resolution,
                    "" if primary is None else str(primary), pcol, prow,
                    "" if secondary is None else str(secondary), scol, srow,
                    f"0x{target:08x}",
                )
            )
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
