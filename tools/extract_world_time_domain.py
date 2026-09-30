#!/usr/bin/env python3
"""Extract the worldTime-domain constants from the pinned original ARM ELF.

`-[World getDayNightFractionForX:atWorldTime:]` @ 0x00582ad8 normalises its
double worldTime argument by dividing by a literal-pool constant before taking
the fractional part and converting to radians. Those pool words define the
clock's domain: an in-game day is that many SECONDS, and the phase multiplier
is 2*pi. The JSON record + WORLD_TIME_DOMAIN.md carry the conclusion; this tool
regenerates it from the ELF and fails on drift (--check).

Usage:
  python3 tools/extract_world_time_domain.py <libApplication.so> [--json OUT] [--check]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from extract_original_tile_item_map import Elf32Arm  # noqa: E402

FUNCTION = "0x00582ad8"
# (instruction address, pc-relative imm, pool address, role) — read from the
# disassembly of the function prologue.
POOL = [
    (0x00582B10, 0x2C8, "seconds_per_day_divisor"),
    (0x00582B3C, 0x2A4, "two_pi_phase_multiplier"),
    (0x00582B54, 0x294, "day_length_scale"),
]


def f64_at(elf: Elf32Arm, addr: int) -> float:
    lo = struct.unpack("<I", elf.read_va(addr, 4))[0]
    hi = struct.unpack("<I", elf.read_va(addr + 4, 4))[0]
    return struct.unpack("<d", struct.pack("<II", lo, hi))[0]


def extract(elf: Elf32Arm, sha: str) -> dict:
    records = []
    for insn_addr, imm, role in POOL:
        pool = insn_addr + 8 + imm
        value = f64_at(elf, pool)
        records.append(
            {
                "role": role,
                "read_from_instruction": hex(insn_addr),
                "literal_pool": hex(pool),
                "f64": value,
            }
        )
    seconds_per_day = records[0]["f64"]
    return {
        "schema": 1,
        "elf_sha256": sha,
        "function": "getDayNightFractionForX:atWorldTime:",
        "function_address": FUNCTION,
        "constants": records,
        "claim": (
            "worldTime is a seconds clock; an in-game day is "
            f"{seconds_per_day:g} seconds; the day phase is derived by "
            "fmod(worldTime / seconds_per_day) then (0.5 - fraction) * 2*pi"
        ),
        "season_gate": {
            "evidence": "reconstruction/reverse-v3/native/PLANT_LOADSAVE_ARM.md",
            "threshold_seconds": 1800.0,
            "domain": "same seconds clock; 1800.0 == 2 in-game days at this save",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("libapplication", type=Path)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    sha = hashlib.sha256(args.libapplication.read_bytes()).hexdigest()
    record = extract(Elf32Arm(args.libapplication), sha)
    payload = json.dumps(record, indent=2, ensure_ascii=False) + "\n"

    if args.check:
        if args.json is None or not args.json.exists():
            print("CHECK FAILED: --json output missing", file=sys.stderr)
            return 1
        if args.json.read_text(encoding="utf-8") != payload:
            print(f"CHECK FAILED: {args.json} is stale", file=sys.stderr)
            return 1
        print(f"check ok: day={record['constants'][0]['f64']:g}s "
              f"phase=2pi@{record['constants'][1]['f64']!r}")
        return 0

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
