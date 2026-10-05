#!/usr/bin/env python3
"""Contract test for tools/emulate_float_getters.py (the third abstraction).

Pins what the batch would silently lose:
  * the four float getters that executed must still execute, with the address-provenance check AND the
    cross-control recorded true - not merely a matching number;
  * `simulationProgress` must stay reported as not-executed, so a future change cannot quietly claim
    it works;
  * the Unicorn register-id pitfall must stay fixed: the tool may not build a register table from
    range(), because UC_ARM_REG_R0 is 66 and id 0 reads back garbage.

Self-skips when the pinned ELF is absent.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ART = ROOT / "reconstruction/reverse-v3/native/float_getter_emulation.json"


def main() -> int:
    src = (ROOT / "tools/emulate_float_getters.py").read_text()
    assert "UC_ARM_REG_R0 == 66" in src, "the register-id pitfall must stay documented in the tool"
    assert "for i in range(13)" not in src, "register table must come from arm_const, not range()"
    pinned = Path(os.environ.get("BH_ELF",
                  ROOT.parent.parent / "extracted/lib/armeabi-v7a/libApplication.so"))
    if not pinned.is_file():
        print("skip: pinned ELF not present")
        return 0
    run = subprocess.run([sys.executable, str(ROOT / "tools/emulate_float_getters.py"), str(pinned),
                          "--methods",
                          str(ROOT / "reconstruction/reverse-v3/native/libApplication_objc_methods.tsv")],
                         capture_output=True, text=True)
    out = run.stdout + run.stderr
    assert "Invalid instruction" not in out or "simulationProgress" in out, out[-400:]
    rep = json.loads(ART.read_text())
    executed = {r["field"]: r for r in rep["results"] if r.get("status") == "executed"}
    for name in ("timeOfDayFraction", "weatherFraction", "rainFraction",
                 "rainFractionNotIncludingSnow"):
        assert name in executed, name
        row = executed[name]
        assert all(p["ok"] for p in row["positive"]), row
        assert row["provenance"]["matches_derived_offset"] is True, row
        assert row["cross_control"]["follows_cell"] is True, row
    skipped = [r for r in rep["results"] if r.get("status") != "executed"]
    assert [r["field"] for r in skipped] == ["simulationProgress"], skipped
    print(f"float getters: {len(executed)} executed with provenance + cross-control, "
          f"{len(skipped)} still unexplained ({skipped[0]['field']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
