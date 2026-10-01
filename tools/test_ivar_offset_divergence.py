#!/usr/bin/env python3
"""Contract test for the ivar-offset divergence measurement (no device needed).

Pins what is deterministic about the artifact (the cell count follows from the pinned ELF)
and what was observed at capture time, and requires the open question to stay documented.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "reconstruction/reverse-v3/native"
JSON_PATH = NATIVE / "live_ivar_offset_divergence.json"
DOC_PATH = NATIVE / "IVAR_OFFSET_READING.md"

# 3793 is the number of OBJC_IVAR_$_ symbols with a nonzero st_value in the pinned ELF's
# .dynsym, so this count is reproducible from the ELF alone.
CELLS_COMPARED = 3793
# observed at capture time; the live split is not deterministic across sessions
OBSERVED_IDENTICAL = 58
OBSERVED_REWRITTEN = 3735


def main() -> int:
    assert JSON_PATH.exists(), f"missing {JSON_PATH}"
    d = json.loads(JSON_PATH.read_text(encoding="utf-8"))

    assert d["cells_compared"] == CELLS_COMPARED, d["cells_compared"]
    assert d["cells_identical"] == OBSERVED_IDENTICAL, d["cells_identical"]
    assert d["cells_rewritten"] == OBSERVED_REWRITTEN, d["cells_rewritten"]
    assert d["cells_identical"] + d["cells_rewritten"] == d["cells_compared"]
    # the finding is "almost all differ"; a change to "almost all match" must fail loudly
    assert d["cells_rewritten"] > 0.9 * d["cells_compared"], d

    offs = d["live_offsets"]
    for key in ("Blockhead.state", "Blockhead.bodyCube", "DynamicObject.floatPos",
                "World.saveID"):
        assert key in offs, f"missing live offset {key}"

    claim = d["claim"]
    assert "not a verified runtime offset" in claim, claim
    assert "CANDIDATE" in claim, claim

    assert DOC_PATH.exists(), f"missing {DOC_PATH}"
    doc = DOC_PATH.read_text(encoding="utf-8")
    # the open question must stay stated, and the failed approaches recorded.
    # needles avoid markdown emphasis: a phrase wrapped in ** ** still contains the plain
    # text, but a phrase that *spans* the emphasis markers does not.
    assert "open" in doc.lower(), "the open question is no longer stated"
    assert "instance discovery" in doc, "the instance-discovery flaw is no longer stated"
    assert "The actual blocker" in doc, "the blocker section is gone"
    assert "Next method" in doc, "the next-method section is gone"
    assert "candidate, not verified" in doc, "the non-verified status is no longer stated"

    tool = ROOT / "tools/probe_live_ivar_offsets.py"
    assert tool.exists(), f"missing {tool}"

    print(f"ivar-offset-divergence: PASS ({d['cells_rewritten']}/{d['cells_compared']} cells "
          f"differ; open question documented)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
