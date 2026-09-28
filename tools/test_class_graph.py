#!/usr/bin/env python3
"""CI guard for the class metadata + object graph tooling.

Regenerates both artifacts and
  * pins the measured floors (classes / super / owns / typed / mentions /
    curated construction edges) so evidence can only grow;
  * CROSS-CHECKS the superref cells the ARM harnesses pin by hand against the
    cells the ELF metadata says exist for those classes — the automation that
    replaces hand-mining must agree with what was hand-mined.
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "reconstruction/reverse-v3/native"

FLOORS = {
    "classes": 530,
    "super_edges": 270,
    "owns_edges": 2400,
    "typed_edges": 64,
    "construction_edges": 13,
}

# what the harnesses pin by hand (class -> superref cell)
PINNED_SUPERREFS = {
    "ArtificialLight": "0x00e8be48",
    "TrainCar": "0x00e8be24",
    "OwnershipSign": "0x00e8be20",
    "Painting": "0x00e8be64",
    "DropBear": "0x00e8bd3c",
    "CaveTroll": "0x00e8bf2c",
    "SteamTrain": "0x00e8bf10",
    "SurfaceBlock": "0x00e8bd70",
    "Window": "0x00e8bed4",
    "Egg": "0x00e8bf24",
}


def main() -> int:
    for tool in ("tools/elf_class_metadata.py", "tools/class_graph.py"):
        proc = subprocess.run([sys.executable, str(ROOT / tool)],
                              capture_output=True, text=True)
        if proc.returncode != 0:
            print(proc.stdout)
            print(proc.stderr)
            return 1
    graph = json.loads((NATIVE / "object_graph.json").read_text())
    got = {
        "classes": graph["classes"],
        "super_edges": len(graph["super_edges"]),
        "owns_edges": len(graph["owns_edges"]),
        "typed_edges": len(graph["typed_edges"]),
        "construction_edges": len(graph["construction_edges"]),
    }
    for key, floor in FLOORS.items():
        if got[key] < floor:
            print(f"graph REGRESSED: {key}={got[key]} < {floor}")
            return 1
    # cross-check: every hand-pinned superref must be a metadata candidate
    meta = json.loads((NATIVE / "class_metadata.json").read_text())
    for cls, cell in PINNED_SUPERREFS.items():
        entry = meta["classes"].get(cls)
        if entry is None:
            print(f"metadata misses class {cls}")
            return 1
        if cell not in entry["superref_candidates"]:
            print(f"superref MISMATCH {cls}: pinned {cell} not in "
                  f"{entry['superref_candidates']}")
            return 1
    print(f"class-graph: PASS ({got}, {len(PINNED_SUPERREFS)} superref pins "
          f"cross-checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
