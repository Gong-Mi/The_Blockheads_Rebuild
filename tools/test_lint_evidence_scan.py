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

    print(f"evidence-scan lint: PASS (clean tree + synthetic offender flagged)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
