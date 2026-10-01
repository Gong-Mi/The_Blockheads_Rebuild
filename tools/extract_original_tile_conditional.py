#!/usr/bin/env python3
"""Extract the conditional TileType -> ItemType chains of the original 1.7.6 map.

`tools/extract_original_tile_item_map.py` only accepts the exact
`movw r0, #imm; str r0, [fp, #-4]; b return` case shape and marks every other
entry of `itemTypeFromTileIsForegorund()` as `conditional`.  Nine entries take
that shape: their value depends on another Tile field.

This tool resolves those chains mechanically instead of guessing.  Every
conditional case is a chain of

    ldr  r0, [fp, #-0x14]     ; the Tile* argument
    ldrb r0, [r0, #3]         ; OriginalTile.contentsType()
    cmp  r0, #<item type>
    bne  next                 ; or `beq <value block>`
    movw r0, #<item type>
    str  r0, [fp, #-4]
    b    <return target>

ending in a fallback value block (or the shared default path, which stores 0).
A step whose value block is only reached after a `bl` helper call is recorded as
helper-gated and NOT resolved: the helper's semantics are not part of this map.

Output is deterministic: TSV for the join with the item image map, JSON for the
evidence record (toolchain identity plus one row per step).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from extract_original_tile_item_map import (  # noqa: E402
    Elf32Arm,
    FUNCTION_VA,
    FUNCTION_SIZE,
    RETURN_TARGET,
    TABLE_BASE_VA,
    FIRST_TILE_TYPE,
    LAST_TILE_TYPE,
)

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM  # noqa: E402

# The shared default path: `b 0xa18db0; movw r0, #0; str r0, [fp, #-4]`.
DEFAULT_PATH = 0x00A18DAC
EPILOGUE = RETURN_TARGET

# OriginalTile.contentsType() is raw[3] (original_save_format.h).
CONTENTS_OFFSET = 3


class ChainError(RuntimeError):
    """Raised when a case does not match the recovered chain shape."""


class Disassembler:
    def __init__(self, elf: Elf32Arm) -> None:
        self.elf = elf
        self.md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        self.md.detail = True
        text = elf.read_va(FUNCTION_VA, FUNCTION_SIZE)
        self.insns = {i.address: i for i in self.md.disasm(text, FUNCTION_VA)}
        self.addresses = sorted(self.insns)

    def at(self, address: int):
        insn = self.insns.get(address)
        if insn is None:
            raise ChainError(f"0x{address:08x} is not an instruction boundary")
        return insn

    def next(self, address: int) -> int:
        for candidate in self.addresses:
            if candidate > address:
                return candidate
        raise ChainError(f"no instruction after 0x{address:08x}")

    def seq(self, address: int, count: int):
        out = []
        cursor = address
        for _ in range(count):
            insn = self.at(cursor)
            out.append(insn)
            cursor = insn.address + insn.size
        return out


def lower(insn) -> tuple[str, str]:
    return insn.mnemonic, insn.op_str.replace(" ", "")


def branch_target(insn) -> int | None:
    if not insn.mnemonic.startswith("b"):
        return None
    if not insn.operands:
        return None
    operand = insn.operands[0]
    if operand.type != 2:  # ARM_OP_IMM
        return None
    return operand.imm


def is_contents_load(seq) -> bool:
    """`ldr r0, [fp, #-0x14]` / `ldrb r0, [r0, #3]`."""
    if len(seq) < 2:
        return False
    first, second = lower(seq[0]), lower(seq[1])
    return (
        first[0] == "ldr"
        and first[1].startswith("r0,[fp,#-0x14]")
        and second[0] == "ldrb"
        and second[1] == f"r0,[r0,#{CONTENTS_OFFSET}]"
    )


def value_block(dis: Disassembler, address: int) -> tuple[int, int] | None:
    """Return (item_type, consumed) for a value block, else None.

    Value block shape: `movw r0, #imm; str r0, [fp, #-4]; b <epilogue>`.
    A trampoline of unconditional `b` instructions is followed first.
    """
    cursor = address
    seen = 0
    while seen < 16:
        seen += 1
        insn = dis.at(cursor)
        if insn.mnemonic == "b":
            target = branch_target(insn)
            if target is None:
                return None
            if target == EPILOGUE:
                return None
            cursor = target
            continue
        break
    seq = dis.seq(cursor, 3)
    mnemonics = [lower(i) for i in seq]
    if mnemonics[0][0] != "movw" or not mnemonics[0][1].startswith("r0,#"):
        return None
    item_type = int(mnemonics[0][1].split("#", 1)[1], 0)
    if mnemonics[1] != ("str", "r0,[fp,#-4]"):
        return None
    if mnemonics[2][0] != "b" or branch_target(seq[2]) != EPILOGUE:
        return None
    return item_type, seen - 1


def walk_chain(dis: Disassembler, start: int, limit: int = 64):
    """Walk one conditional case into steps + fallback.

    Each step is a dict with the compared contentsType value, the item type it
    selects, the field offset and the address it was read from.  `fallback` is
    the item type reached when no comparison matches; `helper_gated` lists the
    helper calls that sit on the way to a value block, which stop the walk.
    """
    steps = []
    helper_gated = []
    address = start
    visited = set()
    for _ in range(limit):
        if address in visited:
            raise ChainError(f"cycle at 0x{address:08x}")
        visited.add(address)
        if address == DEFAULT_PATH:
            return steps, 0, helper_gated, "default-path"
        block = dis.seq(address, 8)
        cursor = address
        helpers = []
        if is_contents_load(block):
            cursor = block[1].address + block[1].size
            compare = dis.at(cursor)
            mnemonic, operands = lower(compare)
            if mnemonic != "cmp":
                raise ChainError(f"expected cmp at 0x{cursor:08x}, got {mnemonic}")
            compared = int(operands.split(",")[1].split("#", 1)[1], 0)
            branch = dis.at(dis.next(compare.address))
            bmnemonic, boperands = lower(branch)
            if bmnemonic not in ("bne", "beq"):
                raise ChainError(
                    f"expected bne/beq at 0x{branch.address:08x}, got {bmnemonic}"
                )
            target = branch_target(branch)
            if target is None:
                raise ChainError(f"branch at 0x{branch.address:08x} has no target")
            if bmnemonic == "bne":
                # fallthrough is the value block for `compared`
                value = value_block(dis, branch.address + branch.size)
                if value is None:
                    tail = dis.at(branch.address + branch.size)
                    tail_operands = tail.op_str.replace(" ", "")
                    if tail.mnemonic == "movw" and tail_operands.startswith("r0,#"):
                        # `movw r0, #V` followed by more setup (a further call
                        # argument) is an assignment this map cannot finish:
                        # record the value and stop instead of guessing.
                        steps.append(
                            {
                                "contents_type": compared,
                                "item_type": int(tail_operands.split("#", 1)[1], 0),
                                "read_at": f"0x{compare.address:08x}",
                                "tail": "unresolved-after-assignment",
                            }
                        )
                        return steps, None, helper_gated, "tail-unresolved"
                    raise ChainError(
                        f"no value block after 0x{branch.address:08x}"
                    )
                item_type, _ = value
                steps.append(
                    {
                        "contents_type": compared,
                        "item_type": item_type,
                        "read_at": f"0x{compare.address:08x}",
                    }
                )
                address = target
                continue
            # beq: the equal branch is the value block, fallthrough continues
            value = value_block(dis, target)
            if value is None:
                raise ChainError(f"no value block at 0x{target:08x}")
            item_type, _ = value
            steps.append(
                {
                    "contents_type": compared,
                    "item_type": item_type,
                    "read_at": f"0x{compare.address:08x}",
                }
            )
            address = branch.address + branch.size
            continue
        # Not a compare chain.  A helper call (`bl`) anywhere before the value
        # block means the chain depends on code outside this map.  When the
        # helper is immediately gated as `bl H; sxtb r0, r0; cmp r0, #0;
        # beq ZERO_PATH; movw r0, #V`, the helper-nonzero result is recorded as
        # an explicit helper step and the walk continues down ZERO_PATH, whose
        # remaining comparisons are still pure contentsType reads.
        insn = dis.at(address)
        if insn.mnemonic == "bl":
            helper_gated.append(f"0x{branch_target(insn) or 0:08x}")
            return steps, None, helper_gated, "helper-gated"
        probe = dis.seq(address, 8)
        helper_index = None
        for index, candidate in enumerate(probe):
            if candidate.mnemonic == "bl":
                helper_index = index
                break
        if helper_index is not None:
            helper_address = branch_target(probe[helper_index]) or 0
            gate = probe[helper_index + 1 : helper_index + 5]
            if len(gate) == 4 and gate[1].mnemonic == "cmp" and gate[2].mnemonic == "beq":
                value = value_block(dis, gate[3].address)
                zero_path = branch_target(gate[2])
                if value is not None and zero_path is not None:
                    steps.append(
                        {
                            "contents_type": None,
                            "item_type": value[0],
                            "helper": f"0x{helper_address:08x}",
                            "helper_nonzero_item_type": value[0],
                            "read_at": f"0x{probe[helper_index].address:08x}",
                        }
                    )
                    helper_gated.append(f"0x{helper_address:08x}")
                    address = zero_path
                    continue
            helper_gated.append(f"0x{helper_address:08x}")
            return steps, None, helper_gated, "helper-gated"
        value = value_block(dis, address)
        if value is not None:
            return steps, value[0], helper_gated, "fallback-value"
        raise ChainError(f"unrecognised block at 0x{address:08x}")
    raise ChainError(f"chain from 0x{start:08x} exceeds {limit} links")


def conditional_targets(elf: Elf32Arm) -> dict[int, list[int]]:
    import struct

    table = elf.read_va(TABLE_BASE_VA, (LAST_TILE_TYPE - FIRST_TILE_TYPE + 1) * 4)
    groups: dict[int, list[int]] = {}
    for tile in range(FIRST_TILE_TYPE, LAST_TILE_TYPE + 1):
        relative = struct.unpack_from("<i", table, (tile - FIRST_TILE_TYPE) * 4)[0]
        groups.setdefault(TABLE_BASE_VA + relative, []).append(tile)
    return groups


def is_direct(elf: Elf32Arm, target: int) -> bool:
    word = elf.word(target)
    if (word & 0x0FF00000) != 0x03000000 or ((word >> 12) & 0xF) != 0:
        return False
    return elf.word(target + 4) == 0xE50B0004


def extract(elf: Elf32Arm, sha256: str):
    dis = Disassembler(elf)
    groups = conditional_targets(elf)
    rows = []
    json_cases = []
    for target in sorted(groups):
        if is_direct(elf, target):
            continue
        tiles = groups[target]
        steps, fallback, helpers, termination = walk_chain(dis, target)
        for step_index, step in enumerate(steps):
            for tile in tiles:
                rows.append(
                    (
                        tile,
                        "contents" if step.get("helper") is None else "helper",
                        step["contents_type"] if step["contents_type"] is not None else "",
                        step["item_type"],
                        step.get("helper") or "",
                        f"0x{target:08x}",
                        step_index,
                        "resolved" if step.get("tail") is None else step["tail"],
                    )
                )
        for tile in tiles:
            rows.append(
                (
                    tile,
                    "contents",
                    "",
                    "" if fallback is None else fallback,
                    "",
                    f"0x{target:08x}",
                    len(steps),
                    termination,
                )
            )
        json_cases.append(
            {
                "case_target": f"0x{target:08x}",
                "tile_types": tiles,
                "termination": termination,
                "fallback_item_type": fallback,
                "helper_gated": helpers,
                "steps": steps,
            }
        )
    return rows, json_cases, sha256


def render_tsv(rows) -> str:
    # The row tuples carry eight values: tile, resolution, contents_type,
    # item_type, helper, case_target, step_index, status. An earlier header
    # declared nine names and included a `depends_on` column that was never
    # emitted, which shifted every field after `resolution` one name to the left
    # while the contract test - comparing header text plus row multisets against
    # the same tuples - stayed green. Keep the names exactly aligned to the data.
    header = (
        "tile_type\tresolution\tcontents_type\titem_type\thelper\t"
        "case_target\tstep_index\tstatus"
    )
    lines = [header]
    for row in rows:
        lines.append("\t".join(str(value) for value in row))
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("libapplication", type=Path)
    # Canonical outputs by default: with `--tsv`/`--json` optional and None,
    # `--check` skipped both comparisons and printed "check ok" without reading
    # anything, so a stale artifact could look verified. Default to the
    # committed paths and let an explicit path override them.
    parser.add_argument("--tsv", type=Path,
                        default=Path("reconstruction/reverse-v3/native/"
                                     "original_tile_conditional.tsv"))
    parser.add_argument("--json", type=Path,
                        default=Path("reconstruction/reverse-v3/native/"
                                     "original_tile_conditional.json"))
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail when the outputs on disk differ from the freshly extracted ones",
    )
    args = parser.parse_args()

    data = args.libapplication.read_bytes()
    sha256 = hashlib.sha256(data).hexdigest()
    elf = Elf32Arm(args.libapplication)
    rows, cases, sha256 = extract(elf, sha256)
    tsv = render_tsv(rows)
    record = {
        "schema": 1,
        "tool": "extract_original_tile_conditional.py",
        "elf_sha256": sha256,
        "function": "itemTypeFromTileIsForegorund",
        "function_address": f"0x{FUNCTION_VA:08x}",
        "table_address": f"0x{TABLE_BASE_VA:08x}",
        "return_target": f"0x{RETURN_TARGET:08x}",
        "default_path": f"0x{DEFAULT_PATH:08x}",
        "dependency": "OriginalTile.contentsType() (original_save_format.h raw[3])",
        "claim": (
            "Conditional TileType cases of the foreground_arg == 0 switch, "
            "resolved as contentsType() compare chains. Helper-gated steps are "
            "recorded as unresolved, never guessed."
        ),
        "cases": cases,
    }
    payload = json.dumps(record, indent=2, ensure_ascii=False) + "\n"

    status = 0
    if args.check:
        for path, expected in ((args.tsv, tsv), (args.json, payload)):
            if not path.exists():
                print(f"CHECK FAILED: {path} is missing", file=sys.stderr)
                status = 1
                continue
            if path.read_text(encoding="utf-8") != expected:
                print(f"CHECK FAILED: {path} is stale", file=sys.stderr)
                status = 1
        if status == 0:
            print(f"check ok: {len(rows)} rows / {len(cases)} conditional cases")
        return status

    if args.tsv:
        args.tsv.parent.mkdir(parents=True, exist_ok=True)
        args.tsv.write_text(tsv, encoding="utf-8")
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(payload, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
