#!/usr/bin/env python3
"""Contract test for the stale-consumer check (no ELF needed in CI).

The check exists because renaming a column broke CI three times in one cycle: each
tool that reads another tool's artifact by column name had to be found by hand. The
test keeps it honest in both directions - the real tree must be clean, and a
synthetic tool that reads a column no artifact has must still be flagged.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / "tools/check_artifact_consumers.py"

STALE_SAMPLE = '''import csv
from pathlib import Path

NATIVE = Path("reconstruction/reverse-v3/native")


def read(path: Path):
    with path.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh, delimiter="\\t"):
            print(row["col_dataA0"], row["item_type"])
'''


def main() -> int:
    ok = subprocess.run([sys.executable, str(CHECKER)], capture_output=True, text=True)
    assert ok.returncode == 0, f"tools/ is not clean:\n{ok.stdout}\n{ok.stderr}"
    assert "0 stale references" in ok.stdout, ok.stdout

    sys.path.insert(0, str(ROOT / "tools"))
    import check_artifact_consumers as checker  # noqa: E402

    known = set()
    for names in checker.artifact_columns().values():
        known |= names
    with tempfile.TemporaryDirectory() as tmp:
        sample = Path(tmp) / "stale_consumer.py"
        sample.write_text(STALE_SAMPLE, encoding="utf-8")
        findings = checker.scan(sample, known)
    # `col_dataA0` still exists in the tile artifact header, so it is not stale by
    # itself; the synthetic case uses a name that exists in no artifact at all.
    with tempfile.TemporaryDirectory() as tmp:
        sample = Path(tmp) / "stale_consumer2.py"
        sample.write_text(STALE_SAMPLE.replace("col_dataA0", "col_from_image_zz"),
                          encoding="utf-8")
        findings2 = checker.scan(sample, known)
    assert findings2, "a reference to a column in no artifact was not flagged"
    assert any("col_from_image_zz" in item for item in findings2), findings2

    print("artifact-consumer check: PASS (clean tree + synthetic stale consumer flagged)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
