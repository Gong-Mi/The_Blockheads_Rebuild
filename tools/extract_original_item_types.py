#!/usr/bin/env python3
"""Assemble the original ItemType table from in-repo evidence.

Joins three independent in-repo sources:

* ``original_item_image_map.tsv`` - the switch-table extraction of
  ``imageTypeForItemType`` (A-grade ELF evidence, see
  ``tools/extract_original_item_image_map.py``).
* ``original_tile_item_map.tsv`` - the direct ``itemTypeFromTileIsForegorund``
  tile -> item assignments (A-grade ELF evidence, see
  ``tools/extract_original_tile_item_map.py``).
* ``assets/defaultPrices`` - the original binary-plist price table keyed by
  ItemType string (original APK asset).

Names come from the pinned ``reference_itemtype_enum.txt`` /
``reference_voxeltype_enum.txt`` snapshots (C+ correlation names; the numeric
values they carry are corroborated by the A-grade extractions above).

The output is text evidence only; the binary is never copied into the
repository.  The tool asserts cross-source agreement and refuses to write on
contradiction.
"""

from __future__ import annotations

import plistlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "reconstruction/reverse-v3/native"

IMAGE_MAP = NATIVE / "original_item_image_map.tsv"
TILE_ITEM_MAP = NATIVE / "original_tile_item_map.tsv"
ITEMTYPE_ENUM = NATIVE / "reference_itemtype_enum.txt"
VOXELTYPE_ENUM = NATIVE / "reference_voxeltype_enum.txt"
DEFAULT_PRICES = ROOT / "assets/defaultPrices"
OUTPUT = NATIVE / "original_item_types.tsv"

# imageTypeForItemType's documented fallback (tools/extract_original_item_image_map.py):
# every unmapped ItemType resolves to the generic item image 0x20 = 32,
# atlas (0, 1).  The function's explicit low-range cases are 58, 168, 174;
# the high block [0x400, 0x451] is fully listed by the extraction.
DEFAULT_IMAGE = 32
DEFAULT_COL = 0
DEFAULT_ROW = 1
LOW_CASES = {58: (109, 109), 168: (304, 305), 174: (118, 118)}
HIGH_FIRST, HIGH_LAST = 0x400, 0x451


def load_enum(path: Path) -> dict[int, str]:
    values: dict[int, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, _, value = line.partition("=")
        values[int(value.strip())] = name.strip()
    return values


def load_image_map() -> dict[int, tuple[int, int, int, int, int, int, str]]:
    rows: dict[int, tuple[int, int, int, int, int, int, str]] = {}
    lines = IMAGE_MAP.read_text().splitlines()
    header = lines[0].split("\t")
    assert header[:7] == ["item_type", "image_dataA0", "col_dataA0",
                          "row_dataA0", "image_dataA1", "col_dataA1",
                          "row_dataA1"], header
    for line in lines[1:]:
        if not line.strip():
            continue
        parts = line.split("\t")
        item_type = int(parts[0])
        rows[item_type] = (int(parts[1]), int(parts[2]), int(parts[3]),
                           int(parts[4]), int(parts[5]), int(parts[6]),
                           parts[7])
    return rows


def load_tile_map() -> list[tuple[int, int]]:
    """Direct-only tile -> item assignments (conditional rows carry no item)."""
    pairs: list[tuple[int, int]] = []
    lines = TILE_ITEM_MAP.read_text().splitlines()
    for line in lines[1:]:
        if not line.strip():
            continue
        parts = line.split("\t")
        tile_type, resolution, item_type = parts[1], parts[2], parts[3]
        if resolution == "direct" and item_type:
            pairs.append((int(tile_type), int(item_type)))
    return pairs


def load_prices() -> dict[int, tuple[str, str]]:
    with DEFAULT_PRICES.open("rb") as handle:
        raw = plistlib.load(handle)
    prices: dict[int, tuple[str, str]] = {}
    for key, entry in raw.items():
        item_type = int(entry["id"])
        assert int(key) == item_type, (key, entry)
        prices[item_type] = (entry["price"], entry["old_price"])
    return prices


def main() -> int:
    names = load_enum(ITEMTYPE_ENUM)
    voxels = load_enum(VOXELTYPE_ENUM)
    images = load_image_map()
    tiles = load_tile_map()
    prices = load_prices()

    errors: list[str] = []

    # --- Cross-source assertions -------------------------------------------
    covered = sorted(images)
    expected_high = list(range(HIGH_FIRST, HIGH_LAST + 1))
    if [t for t in covered if t >= HIGH_FIRST] != expected_high:
        errors.append("image map must cover the full 0x400..0x451 block")
    low_covered = [t for t in covered if t < HIGH_FIRST]
    if low_covered != sorted(LOW_CASES):
        errors.append(f"unexpected low cases in image map: {low_covered}")
    for item_type, (a0, a1) in LOW_CASES.items():
        got = images.get(item_type)
        if got is None or (got[0], got[3]) != (a0, a1):
            errors.append(
                f"image map disagrees with LOW_CASES for {item_type}: {got}")

    for tile_type, item_type in tiles:
        if item_type not in names and item_type != 0:
            errors.append(f"tile map target {item_type} missing from enum")

    if len(prices) != 266:
        errors.append(f"expected 266 priced items, got {len(prices)}")
    for item_type in prices:
        if item_type not in names:
            errors.append(f"priced id {item_type} missing from enum")

    if 168 not in names or names[168] != "Shop":
        errors.append("reference enum lost the Shop = 168 anchor")
    if 58 not in names or names[58] != "Window":
        errors.append("reference enum lost the Window = 58 anchor")
    if names.get(1024) != "Stone" or names.get(1105) != "LuminousPlaster":
        errors.append("reference enum lost high-block anchors")

    if errors:
        for error in errors:
            print(f"item-types: FAIL {error}")
        return 1

    # --- Assemble ----------------------------------------------------------
    sources_by_type: dict[int, list[str]] = {t: ["enum"] for t in names}
    if 0 in sources_by_type:
        sources_by_type[0].append("placeholder")
    for tile_type, item_type in tiles:
        if item_type in sources_by_type:
            sources_by_type[item_type].append(
                f"tile{tile_type}({voxels.get(tile_type, '?')})")
    for item_type in prices:
        sources_by_type[item_type].append("price")

    lines = ["item_type\titem_type_hex\tname\timage_a0\tcol_a0\trow_a0\t"
             "image_a1\tcol_a1\trow_a1\tprice\told_price\tsources"]
    for item_type in sorted(names):
        name = names[item_type]
        if item_type in images:
            image_a0, col_a0, row_a0, image_a1, col_a1, row_a1, target = \
                images[item_type]
            kind = "imagetype" if image_a0 != DEFAULT_IMAGE else \
                "imagetype(default)"
            sources_by_type[item_type].append(f"{kind}@{target}")
        else:
            image_a0 = image_a1 = DEFAULT_IMAGE
            col_a0 = col_a1 = DEFAULT_COL
            row_a0 = row_a1 = DEFAULT_ROW
        price, old_price = prices.get(item_type, ("", ""))
        lines.append("\t".join([
            str(item_type), f"0x{item_type:03X}", name,
            str(image_a0), str(col_a0), str(row_a0),
            str(image_a1), str(col_a1), str(row_a1),
            price, old_price, ";".join(sources_by_type[item_type]),
        ]))

    OUTPUT.write_text("\n".join(lines) + "\n")
    print(f"item-types: wrote {OUTPUT.relative_to(ROOT)} "
          f"({len(names)} types, {len(prices)} priced, "
          f"{len(tiles)} tile assignments, {len(images)} imagetype rows)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
