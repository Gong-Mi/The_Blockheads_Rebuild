#!/usr/bin/env python3
"""Contract test for the evidence-scan linter (runs in CI, needs no binary).

The linter exists because two shipped audits produced fiction from a raw-byte
regex (a phantom `_KelpPlant.wav`) and from basename pairing (22 phantom
dimension mismatches). This test keeps it honest in both directions: the real
tools/ tree must be clean, and a synthetic offender must still be caught.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LINTER = ROOT / "tools/lint_evidence_scan.py"

BAD_SAMPLE = '''import re
from pathlib import Path


def bogus(elf: Path):
    blob = elf.read_bytes()
    return set(re.findall(r"[A-Za-z0-9_]+\\.wav", blob))
'''

# Two more shapes that shipped in this repository and looked verified: a check
# that skips its own comparison, and an output path with no canonical default.
VACUOUS_CHECK_SAMPLE = '''import argparse
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tsv", type=Path)
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    if args.check:
        for path, expected in ((args.tsv, "x"),):
            if path is None:
                continue
            if path.read_text() != expected:
                return 1
    return 0
'''


def main() -> int:
    ok = subprocess.run([sys.executable, str(LINTER)], capture_output=True, text=True)
    assert ok.returncode == 0, f"tools/ is not clean:\n{ok.stdout}\n{ok.stderr}"
    assert "0 violations" in ok.stdout, ok.stdout

    sys.path.insert(0, str(ROOT / "tools"))
    import lint_evidence_scan as lint  # noqa: E402

    with tempfile.TemporaryDirectory() as tmp:
        sample = Path(tmp) / "bogus_tool.py"
        sample.write_text(BAD_SAMPLE, encoding="utf-8")
        found = lint.scan(sample)
    assert found, "the synthetic raw-byte regex offender was not flagged"
    assert any("NUL-string" in item or "raw bytes" in item for item in found), found

    with tempfile.TemporaryDirectory() as tmp:
        sample = Path(tmp) / "vacuous_check_tool.py"
        sample.write_text(VACUOUS_CHECK_SAMPLE, encoding="utf-8")
        vacuous = lint.scan(sample)
    assert any("skips a missing/None output path" in item for item in vacuous), vacuous
    assert any("output argument without a default" in item for item in vacuous), vacuous

    print(f"evidence-scan lint: PASS (clean tree + synthetic offender flagged)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
