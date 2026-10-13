#!/usr/bin/env python3
"""CI-safe guard for the ARM golden traces.

CI mode (no ELF): verifies the committed golden's structure — every set
present, class floors met, every entry carrying labels + an image hash, and
the ELF pin intact.
Host mode (--elf): re-runs tools/collect_arm_goldens.py into a temp file and
DIFFS it against the committed golden — the drift detector. Any change in a
class's call labels, image hash or return value under the synthetic graph
means a harness/stub change altered the reference behaviour (or the golden
was hand-edited) and must be reviewed, not silently re-baselined.
"""
import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "reconstruction/reverse-v3/native"
ELF_SHA = "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"

FLOORS = {"forwarder5b": 5, "midtier": 11, "specials": 7}


def load(path: Path) -> dict:
    return json.loads(path.read_text())


def check_structure(golden: dict) -> str:
    if golden.get("elf_sha256") != ELF_SHA:
        return "golden ELF pin mismatch"
    for name, floor in FLOORS.items():
        s = golden["sets"].get(name)
        if s is None:
            return f"golden misses set {name}"
        if len(s["classes"]) < floor:
            return f"set {name}: {len(s['classes'])} classes < {floor}"
        if not s.get("match"):
            return f"set {name}: match flag false"
        for cls, cases in s["entries"].items():
            for case, e in cases.items():
                if e.get("labels") is None and e.get("ret") is None:
                    return f"{name}/{cls}/{case}: entry has no trace"
                if name != "forwarder5b" and e.get("image_sha256") is None:
                    return f"{name}/{cls}/{case}: entry has no image hash"
    return ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--elf", type=Path)
    a = ap.parse_args()
    committed = NATIVE / "arm_goldens.json"
    if not committed.exists():
        print("arm-goldens: MISSING (run tools/collect_arm_goldens.py --elf ...)")
        return 1
    golden = load(committed)
    err = check_structure(golden)
    if err:
        print(f"arm-goldens: FAIL ({err})")
        return 1

    if a.elf is None or not a.elf.exists():
        total = sum(len(s["classes"]) for s in golden["sets"].values())
        print(f"arm-goldens: PASS (ci; {total} class entries, floors met)")
        return 0

    with tempfile.TemporaryDirectory() as tmp:
        fresh = Path(tmp) / "arm_goldens.json"
        proc = subprocess.run(
            [sys.executable, str(ROOT / "tools/collect_arm_goldens.py"),
             "--elf", str(a.elf), "--out", str(fresh)],
            capture_output=True, text=True)
        if proc.returncode != 0:
            print(proc.stdout)
            print(proc.stderr)
            return 1
        new = load(fresh)
    diffs = []
    additions = []
    for name in FLOORS:
        old_set = golden["sets"].get(name, {}).get("entries", {})
        new_set = new["sets"].get(name, {}).get("entries", {})
        for cls in sorted(old_set):            # only the GOLDEN's entries pin
            for case in sorted(old_set[cls]):
                o = old_set[cls][case]
                n = new_set.get(cls, {}).get(case)
                if n is None:
                    diffs.append(f"{name}/{cls}/{case}: LOST in the rerun")
                elif o != n:
                    diffs.append(f"{name}/{cls}/{case}:\n  old {o}\n  new {n}")
        for cls in sorted(set(new_set) - set(old_set)):
            additions.append(f"{name}/{cls} (regenerate the golden to pin it)")
        for cls in sorted(set(old_set) & set(new_set)):
            for case in sorted(set(new_set[cls]) - set(old_set[cls])):
                additions.append(f"{name}/{cls}/{case} (regenerate to pin)")
    if diffs:
        print("arm-goldens DRIFT (harness/reference behaviour changed):")
        for d in diffs[:6]:
            print(d)
        return 1
    total = sum(len(s["classes"]) for s in new["sets"].values())
    if additions:
        print("arm-goldens: PASS with additions (not yet pinned — regenerate "
              "the golden):")
        for ad in additions[:8]:
            print(f"  + {ad}")
        return 0
    print(f"arm-goldens: PASS (host; rerun matches the committed golden, "
          f"{total} class entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
