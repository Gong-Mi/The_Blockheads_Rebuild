#!/usr/bin/env python3
"""Collect the ARM differential traces into one golden snapshot.

Runs the three host harnesses (forwarder5b / midtier / specials), reads their
result JSONs, and merges every per-class case into a single committed golden
(native/arm_goldens.json): class -> case -> {labels, image_sha256, ret}.

Purpose: the differentials compare ARM against the MODELS; the golden adds a
drift detector for the REFERENCE side — if a harness/stub change ever alters
what the original bodies do under the synthetic graph, the host guard flags
it instead of silently re-baselining.

Host only (needs the pinned ELF + Unicorn). CI verifies the committed golden
without rerunning (tools/test_arm_goldens.py).
"""
import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "reconstruction/reverse-v3/native"
ELF_SHA = "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"

HARNESSES = [
    ("forwarder5b", "tools/test_forwarder5b_arm.py", "forwarder5b-arm-result.json"),
    ("midtier", "tools/test_midtier_arm.py", "midtier-arm-result.json"),
    ("specials", "tools/test_specials_arm.py", "specials-arm-result.json"),
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--elf", type=Path, required=True)
    ap.add_argument("--out", type=Path, default=NATIVE / "arm_goldens.json")
    a = ap.parse_args()
    if hashlib.sha256(a.elf.read_bytes()).hexdigest() != ELF_SHA:
        raise SystemExit("ELF SHA mismatch")

    golden = {"elf_sha256": ELF_SHA, "sets": {}}
    with tempfile.TemporaryDirectory() as tmp:
        for name, script, outfile in HARNESSES:
            if name == "specials":
                # the specials harness needs the PLT/memcpy stubs only; its
                # default (model) mode writes specials-arm-result.json
                out = Path(tmp) / name
                out.mkdir()
                proc = subprocess.run(
                    [sys.executable, str(ROOT / script), str(a.elf),
                     "--output-dir", str(out)], capture_output=True, text=True)
            else:
                out = Path(tmp) / name
                out.mkdir()
                proc = subprocess.run(
                    [sys.executable, str(ROOT / script), str(a.elf),
                     "--output-dir", str(out)], capture_output=True, text=True)
            if proc.returncode != 0:
                print(f"{name} harness failed:")
                print(proc.stdout)
                print(proc.stderr)
                return 1
            result = json.loads((out / outfile).read_text())
            rows = result.get("rows", [])
            entries = {}
            for r in rows:
                cls = r.get("class")
                case = r.get("case", r.get("super_returns_nil"))
                key = str(case)
                entries.setdefault(cls, {})[key] = {
                    "labels": r.get("labels", r.get("arm_trace")),
                    "image_sha256": r.get("image_sha256"),
                    "ret": r.get("arm_return"),
                }
            golden["sets"][name] = {
                "classes": sorted(entries),
                "cases": result.get("cases"),
                "match": result.get("match"),
                "entries": entries,
            }
    a.out.write_text(json.dumps(golden, indent=2) + "\n")
    total = sum(len(s["entries"]) for s in golden["sets"].values())
    print(f"wrote {a.out}")
    for name, s in golden["sets"].items():
        print(f"  {name}: {len(s['classes'])} classes, cases={s['cases']}, "
              f"match={s['match']}")
    print(f"total class entries: {total}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
