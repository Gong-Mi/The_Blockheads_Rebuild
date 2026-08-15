#!/usr/bin/env python3
"""Extract the original 1.7.6 TileType -> ItemType jump table.

The input is the ARMv7 libApplication.so from the owned APK.  This extracts the
`isForeground == 0` switch in itemTypeFromTileIsForegorund().  Cases whose
entry immediately assigns an ItemType are marked `direct`; cases that inspect
other Tile fields or call World helpers are deliberately marked `conditional`
rather than guessed.
"""

from __future__ import annotations

import argparse
import csv
import struct
from pathlib import Path

FUNCTION_VA = 0x00A18044
FUNCTION_SIZE = 3496
TABLE_BASE_VA = 0x00A1868C
FIRST_TILE_TYPE = 1
LAST_TILE_TYPE = 77
RETURN_TARGET = 0x00A18DB8


class Elf32Arm:
    def __init__(self, path: Path) -> None:
        self.data = path.read_bytes()
        if self.data[:4] != b"\x7fELF" or self.data[4] != 1 or self.data[5] != 1:
            raise ValueError("expected a little-endian ELF32 file")
        machine = struct.unpack_from("<H", self.data, 18)[0]
        if machine != 40:
            raise ValueError(f"expected EM_ARM (40), got {machine}")
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
    """Decode an ARM A1 `movw r0, #imm16`."""
    if (word & 0x0FF00000) != 0x03000000 or ((word >> 12) & 0xF) != 0:
        return None
    return ((word >> 4) & 0xF000) | (word & 0x0FFF)


def branch_target(address: int, word: int) -> int | None:
    """Decode an unconditional ARM `b` target."""
    if (word & 0xFF000000) != 0xEA000000:
        return None
    immediate = word & 0x00FFFFFF
    if immediate & 0x00800000:
        immediate -= 0x01000000
    return address + 8 + immediate * 4


def direct_item_type(elf: Elf32Arm, target: int) -> int | None:
    """Accept only the auditable `movw r0; str; b return` case shape."""
    item_type = movw_r0_immediate(elf.word(target))
    if item_type is None:
        return None
    store = elf.word(target + 4)
    if store != 0xE50B0004:  # str r0, [fp, #-4]
        return None
    if branch_target(target + 8, elf.word(target + 8)) != RETURN_TARGET:
        return None
    return item_type


def load_item_images(path: Path | None) -> dict[int, tuple[int, int, int]]:
    if path is None:
        return {}
    rows: dict[int, tuple[int, int, int]] = {}
    with path.open(newline="", encoding="utf-8") as stream:
        for row in csv.DictReader(stream, delimiter="\t"):
            rows[int(row["item_type"])] = (
                int(row["image_dataA0"]),
                int(row["col_dataA0"]),
                int(row["row_dataA0"]),
            )
    return rows


def extract(elf: Elf32Arm, item_images: dict[int, tuple[int, int, int]]) -> str:
    lines = [
        "foreground_arg\ttile_type\tresolution\titem_type\timage_dataA0\t"
        "col_dataA0\trow_dataA0\tcase_target"
    ]
    table = elf.read_va(
        TABLE_BASE_VA, (LAST_TILE_TYPE - FIRST_TILE_TYPE + 1) * 4
    )
    for tile_type in range(FIRST_TILE_TYPE, LAST_TILE_TYPE + 1):
        relative = struct.unpack_from(
            "<i", table, (tile_type - FIRST_TILE_TYPE) * 4
        )[0]
        target = TABLE_BASE_VA + relative
        item_type = direct_item_type(elf, target)
        if item_type is None:
            values = ("0", str(tile_type), "conditional", "", "", "", "", f"0x{target:08x}")
        else:
            image = item_images.get(item_type)
            image_columns = ("", "", "") if image is None else tuple(map(str, image))
            values = (
                "0",
                str(tile_type),
                "direct",
                str(item_type),
                *image_columns,
                f"0x{target:08x}",
            )
        lines.append("\t".join(values))
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("libapplication", type=Path)
    parser.add_argument("--item-image-map", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    elf = Elf32Arm(args.libapplication)
    text = extract(elf, load_item_images(args.item_image_map))
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
