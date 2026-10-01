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
# 59 of the 121 content values share this case body. It is NOT an "empty"
# default: it dispatches on a second field ([fp-0x540] against 0x100/0xe0/0x200/
# 0x1e0/0x109...) before assigning, so its draw image depends on that input and
# is not resolved by this table. Recorded as shared-body, never guessed.
SHARED_BODY_VA = 0x00A22D70
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


def cell(image: int | None) -> tuple[str, str, str]:
    return ("", "", "") if image is None else (str(image), str(image % 32), str(image // 32))


def extract_rows(elf: Elf32Arm) -> list[dict]:
    """Every content value in [3, 123], each with its resolution.

    Values whose case body assigns draw/pair slots are `direct`; values sharing
    the second-field dispatch body are `shared-body`; anything else stays
    `unresolved` and is counted, so the domain is closed explicitly instead of
    being silently missing rows.
    """
    rows = []
    for value in range(FIRST_CONTENT, LAST_CONTENT + 1):
        target = TABLE_VA + elf.word(TABLE_VA + 4 * (value - FIRST_CONTENT))
        draw, pair, conditional = extract_case(elf, target)
        di, dc, dr = cell(draw)
        pi, pc, pr = cell(pair)
        if draw is not None or pair is not None:
            resolution = "conditional" if conditional else "direct"
        elif target == SHARED_BODY_VA:
            resolution = "shared-body"
        else:
            resolution = "unresolved"
        rows.append({
            "content_value": value,
            "candidate_name": CANDIDATE_NAMES.get(value, ""),
            "draw_image": di, "draw_col": dc, "draw_row": dr,
            "paired_image": pi, "paired_col": pc, "paired_row": pr,
            "resolution": resolution,
            "case_target": f"0x{target:08x}",
        })
    return rows


def render(elf: Elf32Arm) -> str:
    rows = ["content_value\tcandidate_name\tdraw_image\tdraw_col\tdraw_row\t"
            "paired_image\tpaired_col\tpaired_row\tresolution\tcase_target"]
    for row in extract_rows(elf):
        rows.append("\t".join(str(row[h]) for h in (
            "content_value", "candidate_name", "draw_image", "draw_col", "draw_row",
            "paired_image", "paired_col", "paired_row", "resolution", "case_target")))
    return "\n".join(rows) + "\n"


def build_record(elf: Elf32Arm, sha: str) -> dict:
    rows = extract_rows(elf)
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["resolution"]] = counts.get(row["resolution"], 0) + 1
    return {
        "schema": 1,
        "elf_sha256": sha,
        "table_address": f"0x{TABLE_VA:08x}",
        "content_domain": [FIRST_CONTENT, LAST_CONTENT],
        "shared_body_address": f"0x{SHARED_BODY_VA:08x}",
        "counts": counts,
        "claim": (
            "reloadDrawBlock Tile[3] content -> content draw-image pair for the "
            "middle pass; values sharing the second-field dispatch body are "
            "labelled shared-body, not guessed"
        ),
        "rows": rows,
    }


def main() -> int:
    import hashlib
    import json
    import sys

    parser = argparse.ArgumentParser()
    parser.add_argument("elf", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    elf = Elf32Arm(args.elf)
    sha = hashlib.sha256(args.elf.read_bytes()).hexdigest()
    text = render(elf)
    record = build_record(elf, sha)
    payload = json.dumps(record, indent=2, ensure_ascii=False) + "\n"

    if args.check:
        bad = 0
        for path, expected in ((args.output, text), (args.json, payload)):
            if path is None:
                continue
            if not path.exists() or path.read_text(encoding="utf-8") != expected:
                print(f"CHECK FAILED: {path} is stale", file=sys.stderr)
                bad = 1
        if not bad:
            print(f"check ok: {len(record['rows'])} content values {record['counts']}")
        return bad

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(payload, encoding="utf-8")
    if not args.output and not args.json:
        print(text, end="")
    if args.output or args.json:
        print(f"wrote {len(record['rows'])} content values {record['counts']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
