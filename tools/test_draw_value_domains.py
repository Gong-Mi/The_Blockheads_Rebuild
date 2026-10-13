#!/usr/bin/env python3
"""Contract test for the draw-value domain cross-check (no ELF needed in CI).

Pins the three findings: the shared body's draws are image ids (37/49 shared with the
sprite set), the direct tile cases are a separate sub-domain (0 overlap), and all six
constants compared against [fp,-0x540] come from that direct-case set.
"""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "reconstruction/reverse-v3/native"
TSV = NATIVE / "draw_value_domains.tsv"
JSON_PATH = NATIVE / "draw_value_domains.json"
EXPECTED_SETS = {
    "direct_tile_cases": (44, 192, 606),
    "tile_map_inline": (33, 32, 746),
    "item_sprite_images": (47, 32, 746),
    "shared_body_draw_values": (49, 32, 746),
}
EXPECTED_OVERLAPS = {
    "shared_body_vs_sprites": (37, 12, 10),
    "shared_body_vs_direct_cases": (0, 49, 44),
    "direct_cases_vs_sprites": (0, 44, 47),
    "constants_vs_direct_cases": (6, 0, 38),
    "constants_vs_shared_body": (0, 6, 49),
}


def main() -> int:
    record = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    for name, (count, low, high) in EXPECTED_SETS.items():
        entry = record["sets"][name]
        assert (entry["count"], entry["min"], entry["max"]) == (count, low, high), entry
    for name, (shared, only_a, only_b) in EXPECTED_OVERLAPS.items():
        entry = record["overlaps"][name]
        assert (entry["shared"], entry["only_a"], entry["only_b"]) == (shared, only_a, only_b), entry

    constants = record["values"]["shared_body_constants"]
    assert constants == [224, 256, 265, 274, 480, 512], constants
    direct = set(record["values"]["direct_tile_cases"])
    assert set(constants) <= direct, "constants are no longer inside the direct-case set"
    assert not (set(record["values"]["shared_body_draw_values"]) & direct), \
        "shared body draws now overlap the direct cases - the sub-domain split changed"

    tsv_rows = list(csv.reader(io.StringIO(TSV.read_text(encoding="utf-8")), delimiter="\t"))
    assert tsv_rows[0] == ["scope", "metric", "value"], tsv_rows[0]
    assert any(row[0] == "overlap" and row[1] == "shared_body_vs_sprites" for row in tsv_rows[1:])

    print(f"draw-value-domains: PASS ({len(EXPECTED_SETS)} sets, "
          f"{len(EXPECTED_OVERLAPS)} overlaps)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
