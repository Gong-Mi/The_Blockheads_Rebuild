#!/usr/bin/env python3
"""Contract test for the conditional TileType evidence chain (CI, no ELF needed).

The extraction itself needs the pinned original ARM ELF, which is not in the
repository.  What CI can enforce is that the three committed artifacts stay in
lockstep and keep the properties the extractor claims:

    original_tile_conditional.json   evidence record (per case, chain order)
    original_tile_conditional.tsv    flattened rows
    generated/original_tile_conditional_table.inc   APK decode product

Every check is deterministic and mutation sensitive: editing one artifact
without regenerating the others fails here.
"""

from __future__ import annotations

import csv
import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import gen_tile_conditional_table as gen  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "reconstruction/reverse-v3/native"
JSON_PATH = NATIVE / "original_tile_conditional.json"
TSV_PATH = NATIVE / "original_tile_conditional.tsv"
INC_PATH = ROOT / "app/src/main/cpp/original_tile_conditional_table.inc"

# The nine conditional entries of the foreground_arg == 0 switch.
EXPECTED_TILES = {1, 2, 3, 5, 6, 12, 13, 27, 28}
EXPECTED_CASES = {"0x00a187c0", "0x00a18a98", "0x00a18b04", "0x00a18c10"}
PINNED_ELF = "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"
PINNED_FUNCTION = "0x00a18044"


def rows_from_json(record: dict):
    rows = []
    for case in record["cases"]:
        target = case["case_target"]
        tiles = case["tile_types"]
        for step_index, step in enumerate(case["steps"]):
            if step.get("helper") is not None:
                kind, contents, helper = "helper", "", step["helper"]
            elif step.get("tail") is not None:
                kind, contents, helper = "contents", step["contents_type"], ""
            else:
                kind, contents, helper = "contents", step["contents_type"], ""
            status = step.get("tail") or "resolved"
            for tile in tiles:
                rows.append(
                    (str(tile), kind, str(contents), str(step["item_type"]), helper,
                     target, str(step_index), status)
                )
        for tile in tiles:
            rows.append(
                (
                    str(tile),
                    "contents",
                    "",
                    "" if case["fallback_item_type"] is None else str(case["fallback_item_type"]),
                    "",
                    target,
                    str(len(case["steps"])),
                    case["termination"],
                )
            )
    return rows


def main() -> int:
    record = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    assert record["elf_sha256"] == PINNED_ELF, "evidence is not from the pinned ELF"
    assert record["function_address"] == PINNED_FUNCTION, "function VA drifted"
    assert "contentsType" in record["dependency"], "dependency field lost"

    tiles = {int(case["tile_types"][i]) for case in record["cases"] for i in range(len(case["tile_types"]))}
    assert tiles == EXPECTED_TILES, f"conditional tile set changed: {sorted(tiles)}"
    assert {case["case_target"] for case in record["cases"]} == EXPECTED_CASES

    # chain order: addresses must be strictly increasing inside a case, so a
    # later comparison can never be reordered in front of an earlier helper gate
    for case in record["cases"]:
        addresses = [int(step["read_at"], 16) for step in case["steps"]]
        assert addresses == sorted(addresses), f"{case['case_target']}: chain reordered"

    # the tiles 2/3/5 chain must keep its helper gates BEFORE its later compares
    first_target = next(c for c in record["cases"] if c["case_target"] == "0x00a187c0")
    kinds = ["helper" if s.get("helper") else "contents" for s in first_target["steps"]]
    helper_positions = [i for i, k in enumerate(kinds) if k == "helper"]
    assert helper_positions, "the tiles 2/3/5 chain lost its helper gate"
    assert min(helper_positions) < len(kinds) - 1, "helper gate moved to the end"

    # TSV <-> JSON lockstep
    tsv_rows = [
        tuple(row)
        for row in csv.reader(
            io.StringIO(TSV_PATH.read_text(encoding="utf-8")), delimiter="\t"
        )
    ]
    header, body = tsv_rows[0], tsv_rows[1:]
    assert header == (
        "tile_type", "resolution", "depends_on", "contents_type", "item_type",
        "helper", "case_target", "step_index", "status",
    ), f"TSV header changed: {header}"
    expected = rows_from_json(record)
    assert sorted(body) == sorted(expected), (
        f"TSV is stale relative to the JSON: {len(body)} rows vs {len(expected)}"
    )

    # .inc <-> JSON lockstep (the APK decode product)
    assert INC_PATH.exists(), f"{INC_PATH} is missing"
    assert INC_PATH.read_text(encoding="utf-8") == gen.render(record), (
        f"{INC_PATH} is stale; run tools/gen_tile_conditional_table.py"
    )
    inc_text = INC_PATH.read_text(encoding="utf-8")
    for tile in EXPECTED_TILES:
        assert f"    {{{tile}, " in inc_text, f"tile {tile} missing from the .inc"
    assert '// 0x00a11390' in inc_text, "helper marker lost from the .inc"

    print(
        f"tile-conditional: PASS ({len(EXPECTED_TILES)} tiles / "
        f"{len(record['cases'])} cases / {len(body)} rows / inc in lockstep)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
