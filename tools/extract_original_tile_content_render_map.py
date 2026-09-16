#!/usr/bin/env python3
"""Extract reloadDrawBlock Tile[3] content image assignments.

The original ARMv7 method dispatches on Tile byte 3 values 3..123 at
0x00a221f4.  The resulting constants initialize the content draw-image pair
used by the middle rendering pass. Numeric mappings are ELF evidence; optional
names are C+ correlations from medioqrity/TheBlockheadsTools commit
c9bc7eea11ecdefa7de47000bfe70b14be374f3c, not original enum symbols.
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

TABLE_VA = 0x00A221F4
FIRST_CONTENT = 3
LAST_CONTENT = 123
DRAW_SLOT = 1344
PAIR_SLOT = 1348

CANDIDATE_NAMES = {
    3: "AppleTreeLeaf", 4: "AppleTreeTrunk", 5: "AppleTreeTrunkLeaf",
    6: "PineTreeLeaf", 7: "PineTreeTrunk", 8: "PineTreeTrunkLeaf",
    9: "MapleTreeLeaf", 10: "MapleTreeTrunk", 11: "MapleTreeTrunkLeaf",
    12: "MangoTreeLeaf", 13: "MangoTreeTrunk", 14: "MangoTreeTrunkLeaf",
    15: "CoconutTreeLeaf", 16: "CoconutTreeTrunk",
    18: "OrangeTreeLeaf", 19: "OrangeTreeTrunk", 20: "OrangeTreeTrunkLeaf",
    21: "CherryTreeLeaf", 22: "CherryTreeTrunk", 23: "CherryTreeTrunkLeaf",
    24: "CoffeeTreeLeaf", 25: "CoffeeTreeTrunk", 26: "CoffeeTreeTrunkLeaf",
    29: "DeadPineTreeTrunk", 34: "DeadPineTreeLeaf",
    37: "DeadOrangeTreeLeaf", 38: "DeadOrangeTreeTrunk",
    39: "DeadCherryTreeLeaf", 40: "DeadCherryTreeTrunk",
    43: "Cactus", 44: "DeadCactus", 89: "LimeTreeLeaf",
    90: "LimeTreeTrunk", 91: "LimeTreeTrunkLeaf",
    92: "DeadLimeTreeLeaf", 93: "DeadLimeTreeTrunk",
    109: "AmethystTreeTrunk", 110: "AmethystTreeLeaf",
    111: "AmethystTreeTrunkLeaf", 112: "SapphireTreeTrunk",
    113: "SapphireTreeLeaf", 114: "SapphireTreeTrunkLeaf",
    115: "EmeraldTreeTrunk", 116: "EmeraldTreeLeaf",
    117: "EmeraldTreeTrunkLeaf", 118: "RubyTreeTrunk",
    119: "RubyTreeLeaf", 120: "RubyTreeTrunkLeaf",
    121: "DiamondTreeTrunk", 122: "DiamondTreeLeaf",
    123: "DiamondTreeTrunkLeaf",
}


class Elf32Arm:
    def __init__(self, path: Path) -> None:
        self.data = path.read_bytes()
        if self.data[:6] != b"\x7fELF\x01\x01":
            raise ValueError("expected little-endian ELF32")
        if struct.unpack_from("<H", self.data, 18)[0] != 40:
            raise ValueError("expected EM_ARM")
        phoff = struct.unpack_from("<I", self.data, 28)[0]
        phentsize, phnum = struct.unpack_from("<HH", self.data, 42)
        self.loads: list[tuple[int, int, int]] = []
        for index in range(phnum):
            p_type, p_offset, p_vaddr, _, p_filesz = struct.unpack_from(
                "<IIIII", self.data, phoff + index * phentsize
            )
            if p_type == 1:
                self.loads.append((p_vaddr, p_vaddr + p_filesz, p_offset))

    def word(self, va: int) -> int:
        for start, end, file_offset in self.loads:
            if start <= va and va + 4 <= end:
                offset = file_offset + va - start
                return struct.unpack_from("<I", self.data, offset)[0]
        raise ValueError(f"unmapped VA 0x{va:08x}")


def movw(word: int) -> tuple[int, int] | None:
    if (word & 0x0FF00000) != 0x03000000:
        return None
    return (word >> 12) & 0xF, ((word >> 4) & 0xF000) | (word & 0x0FFF)


def extract_case(elf: Elf32Arm, target: int) -> tuple[int | None, int | None, bool]:
    constants: dict[int, int] = {}
    slots: dict[int, int] = {}
    conditional = False
    for index in range(96):
        word = elf.word(target + index * 4)
        decoded = movw(word)
        if decoded:
            constants[decoded[0]] = decoded[1]
        if (word & 0xFFFF0000) == 0xE50B0000:
            register = (word >> 12) & 0xF
            offset = word & 0xFFF
            if offset in (DRAW_SLOT, PAIR_SLOT) and register in constants:
                slots.setdefault(offset, constants[register])
        if (word & 0x0E000000) == 0x0A000000:
            if (word >> 28) != 0xE:
                conditional = True
            else:
                break
    return slots.get(DRAW_SLOT), slots.get(PAIR_SLOT), conditional


def render(elf: Elf32Arm) -> str:
    rows = [
        "content_value\tcandidate_name\tdraw_image\tdraw_col\tdraw_row\tpaired_image\tpaired_col\tpaired_row\tresolution\tcase_target"
    ]
    for value in range(FIRST_CONTENT, LAST_CONTENT + 1):
        target = TABLE_VA + elf.word(TABLE_VA + 4 * (value - FIRST_CONTENT))
        draw, pair, conditional = extract_case(elf, target)
        if draw is None and pair is None:
            continue
        def cell(image: int | None) -> tuple[str, str, str]:
            return ("", "", "") if image is None else (str(image), str(image % 32), str(image // 32))
        di, dc, dr = cell(draw)
        pi, pc, pr = cell(pair)
        rows.append(
            f"{value}\t{CANDIDATE_NAMES.get(value, '')}\t{di}\t{dc}\t{dr}\t{pi}\t{pc}\t{pr}\t"
            f"{'conditional' if conditional else 'direct'}\t0x{target:08x}"
        )
    return "\n".join(rows) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("elf", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    text = render(Elf32Arm(args.elf))
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
