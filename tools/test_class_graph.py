#!/usr/bin/env python3
"""CI-safe guard for the class metadata + object graph tooling.

CI mode (no pinned ELF): verifies the COMMITTED artifacts — the metadata's
classes and the ten hand-pinned superref cells, the graph's floors, and the
curated construction edges (names verified against the metadata).
Host mode (ELF present, or --elf given): regenerates both artifacts first,
then verifies. The ELF itself never belongs in CI — that is the whole point
of the other *_evidence.py guards, and this one follows the same convention.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "reconstruction/reverse-v3/native"
DEFAULT_ELF = Path.home() / "blockheads-work/extracted/lib/armeabi-v7a/libApplication.so"

FLOORS = {"classes": 530, "super_edges": 270, "owns_edges": 2400,
          "typed_edges": 64, "construction_edges": 13}

PINNED_SUPERREFS = {
    "ArtificialLight": "0x00e8be48", "TrainCar": "0x00e8be24",
    "OwnershipSign": "0x00e8be20", "Painting": "0x00e8be64",
    "DropBear": "0x00e8bd3c", "CaveTroll": "0x00e8bf2c",
    "SteamTrain": "0x00e8bf10", "SurfaceBlock": "0x00e8bd70",
    "Window": "0x00e8bed4", "Egg": "0x00e8bf24",
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--elf", type=Path, default=None,
                    help="pinned ELF; regenerate artifacts when it exists")
    a = ap.parse_args()
    elf = a.elf if a.elf is not None else DEFAULT_ELF
    if elf.exists():
        for tool in ("tools/elf_class_metadata.py", "tools/class_graph.py"):
            proc = subprocess.run([sys.executable, str(ROOT / tool)],
                                  capture_output=True, text=True)
            if proc.returncode != 0:
                print(proc.stdout)
                print(proc.stderr)
                return 1
        mode = "host (regenerated)"
    else:
        mode = "ci (committed artifacts)"

    meta = json.loads((NATIVE / "class_metadata.json").read_text())
    graph = json.loads((NATIVE / "object_graph.json").read_text())
    curated = json.loads((NATIVE / "construction_edges.json").read_text())

    got = {"classes": meta["class_count"],
           "super_edges": len(graph["super_edges"]),
           "owns_edges": len(graph["owns_edges"]),
           "typed_edges": len(graph["typed_edges"]),
           "construction_edges": len(graph["construction_edges"])}
    for key, floor in FLOORS.items():
        if got[key] < floor:
            print(f"graph REGRESSED: {key}={got[key]} < {floor}")
            return 1
    for cls, cell in PINNED_SUPERREFS.items():
        entry = meta["classes"].get(cls)
        if entry is None:
            print(f"metadata misses class {cls}")
            return 1
        if cell not in entry["superref_candidates"]:
            print(f"superref MISMATCH {cls}: pinned {cell} not in "
                  f"{entry['superref_candidates']}")
            return 1
    for e in curated["edges"]:
        for role in ("from", "to"):
            if e[role] not in meta["classes"]:
                print(f"construction edge names a missing class: {e}")
                return 1
    print(f"class-graph: PASS [{mode}] ({got}, "
          f"{len(PINNED_SUPERREFS)} superref pins, "
          f"{len(curated['edges'])} construction edges checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
