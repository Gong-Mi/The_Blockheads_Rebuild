#!/usr/bin/env python3
"""Extract imageTypeForItemType()'s original 1.7.6 switch table.

The input is the ARMv7 libApplication.so from the owned APK.  The output is
text evidence only; the binary is never copied into the repository.
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

FUNCTION_VA = 0x004D71DC
JUMP_BASE_VA = 0x004D726C
JUMP_FIRST_ITEM = 1024
JUMP_LAST_ITEM = 1105
DEFAULT_TARGET = 0x004D769C
DEFAULT_IMAGE = 32
LOW_CASES = {
    58: (109, 109, 0x004D760C),
    168: (304, 305, 0x004D7594),
    174: (118, 118, 0x004D7600),
}


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
        for i in range(phnum):
            off = phoff + i * phentsize
            p_type, p_offset, p_vaddr, _, p_filesz = struct.unpack_from(
                "<IIIII", self.data, off
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
    # ARM A1 MOVW: cond | 0011 0000 | imm4 | Rd | imm12.
    if (word & 0x0FF00000) != 0x03000000 or ((word >> 12) & 0xF) != 0:
        return None
    return ((word >> 4) & 0xF000) | (word & 0x0FFF)


def decode_target(elf: Elf32Arm, target: int) -> tuple[int, int]:
    if target == DEFAULT_TARGET:
        return DEFAULT_IMAGE, DEFAULT_IMAGE
    first = movw_r0_immediate(elf.word(target))
    if first is not None:
        return first, first

    # The five subtype-dependent cases begin with ldrsb/cmp/beq, then assign
    # the dataA!=0 image and the dataA==0 image with MOVW r0 instructions.
    values: list[int] = []
    for offset in range(0, 40, 4):
        value = movw_r0_immediate(elf.word(target + offset))
        if value is not None and value not in values:
            values.append(value)
        if len(values) == 2:
            break
    if len(values) != 2:
        raise ValueError(f"cannot decode case target 0x{target:08x}: {values}")
    image_when_nonzero, image_when_zero = values
    return image_when_zero, image_when_nonzero


def atlas_cell(image: int) -> tuple[int, int]:
    return image % 32, image // 32


def extract(path: Path) -> list[tuple[int, int, int, int]]:
    elf = Elf32Arm(path)
    rows: list[tuple[int, int, int, int]] = []
    for item, (zero, nonzero, target) in LOW_CASES.items():
        rows.append((item, zero, nonzero, target))
    table = elf.read_va(
        JUMP_BASE_VA, (JUMP_LAST_ITEM - JUMP_FIRST_ITEM + 1) * 4
    )
    for item in range(JUMP_FIRST_ITEM, JUMP_LAST_ITEM + 1):
        relative = struct.unpack_from(
            "<i", table, (item - JUMP_FIRST_ITEM) * 4
        )[0]
        target = JUMP_BASE_VA + relative
        zero, nonzero = decode_target(elf, target)
        rows.append((item, zero, nonzero, target))
    return sorted(rows)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("libapplication", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    lines = [
        "item_type\timage_dataA0\tcol_dataA0\trow_dataA0\t"
        "image_dataA1\tcol_dataA1\trow_dataA1\tcase_target"
    ]
    for item, zero, nonzero, target in extract(args.libapplication):
        c0, r0 = atlas_cell(zero)
        c1, r1 = atlas_cell(nonzero)
        lines.append(
            f"{item}\t{zero}\t{c0}\t{r0}\t{nonzero}\t{c1}\t{r1}\t0x{target:08x}"
        )
    text = "\n".join(lines) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
