#!/usr/bin/env python3
"""Contract test for tools/emulate_worldtime_getter.py.

The harness IS the experiment, so this test pins what makes it evidence rather than a demo:

  * it must refuse to pass without BOTH a positive control (two doubles returned bit-exact) and a
    negative control (rewriting the cell must move the returned value to the other offset) - the
    first version of that control wiped its own marker and could have passed while proving nothing;
  * the committed artifact must match a fresh run, because it is the record of an execution.

Self-skips (exit 0 with a "skip:" line) when the pinned ELF is absent, so CI without the copyrighted
binary stays green for the right reason.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ART = ROOT / "reconstruction/reverse-v3/native/worldtime_getter_emulation.json"


def main() -> int:
    src = (ROOT / "tools/emulate_worldtime_getter.py").read_text()
    for needle in ("negative control", "decoy", "bit_exact", "UC_ERR_INSN_INVALID"):
        assert needle in src, f"the harness lost its {needle!r} reasoning"
    assert "planted_at=alt, decoy=decoy" in src, "the negative control must place a decoy value"

    pinned = Path(os.environ.get("BH_ELF",
                  ROOT.parent.parent / "extracted/lib/armeabi-v7a/libApplication.so"))
    if not pinned.is_file():
        print("skip: pinned ELF not present")
        return 0

    # never /tmp: this device's /tmp is not writable (the harness reproduces that lesson)
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "check.json"
        run = subprocess.run([sys.executable, str(ROOT / "tools/emulate_worldtime_getter.py"),
                              str(pinned), "--json", str(out)], capture_output=True, text=True)
        assert run.returncode == 0, run.stdout[-800:] + run.stderr[-800:]
        fresh = json.loads(out.read_text())
    assert fresh["passed"] is True
    assert all(p["bit_exact"] for p in fresh["positive"]), fresh["positive"]
    assert fresh["negative_control"]["equals_value_at_self_plus_cell"] is True
    assert ART.is_file(), "the committed artifact is missing"
    committed = json.loads(ART.read_text())
    assert fresh["fastForward"]["negative_control"]["equals_value_at_self_plus_cell"] is True
    assert [p["returned"] for p in fresh["fastForward"]["positive"]] == [0, 1, 127, -128, -1], \
        "ldrsb sign-extension must hold for 0x80 and 0xFF"
    assert set(fresh["sbyte_fields"]) == {"fastForward", "doubleTimeUnlocked", "isSimulating"}, \
        "both char fields must be executed"
    for name, rep in fresh["sbyte_fields"].items():
        assert [p["returned"] for p in rep["positive"]] == [0, 1, 127, -128, -1], name
        assert rep["negative_control"]["equals_value_at_self_plus_cell"] is True, name
    src_tool = (ROOT / "tools/emulate_worldtime_getter.py").read_text()
    assert "slot derived from the getter's own literal pool" in src_tool, \
        "the doubleTimeUnlocked slot must stay derived, not guessed"
    for key in ("getter_imp", "cell", "got_slot", "passed", "negative_control", "fastForward"):
        assert committed[key] == fresh[key], f"committed artifact drifted at {key}"
    print("worldtime getter emulation: controls hold and the committed artifact matches a fresh run")
    return 0


if __name__ == "__main__":
    sys.exit(main())
