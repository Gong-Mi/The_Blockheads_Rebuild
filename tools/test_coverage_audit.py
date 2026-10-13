#!/usr/bin/env python3
"""CI guard for the coverage audit (tools/coverage_report.py).

Regenerates the audit and pins the headline numbers: the covered slice and
the executed set may only GROW (new evidence); a drop means evidence files
were lost or the generator broke.
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MINIMUMS = {           # pin the measured floors (grow-only)
    "covered_methods": 177,
    "covered_words": 56861,
    "arm_methods": 99,
    "arm_words": 24738,
    "listings_methods": 145,
}


def main() -> int:
    proc = subprocess.run([sys.executable, str(ROOT / "tools/coverage_report.py")],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr)
        return 1
    d = json.loads((ROOT / "reconstruction/reverse-v3/native/"
                    "coverage_audit.json").read_text())
    covered_methods = sum(s["methods"] for s in d["subsystems"].values())
    covered_words = sum(s["words"] for s in d["subsystems"].values())
    got = {
        "covered_methods": covered_methods,
        "covered_words": covered_words,
        "arm_methods": d["arm"]["methods"],
        "arm_words": d["arm"]["words"],
        "listings_methods": d["listing"]["methods"],
    }
    for key, floor in MINIMUMS.items():
        if got[key] < floor:
            print(f"coverage REGRESSED: {key}={got[key]} < {floor}")
            return 1
    print(f"coverage-audit: PASS ({got})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
