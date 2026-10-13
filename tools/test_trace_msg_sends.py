#!/usr/bin/env python3
"""Contract test for tools/trace_msg_sends.py (the msgSend trace).

Pins the two things that make the trace worth anything, and the one that made it worthless:
  * the selectors must RESOLVE - a non-zero unresolved count means the image bias was dropped from the
    SEL resolution again, and the symptom (an empty-looking trace) does not point at the cause;
  * the first cycle must be the four known sends from their four sites, so a change in the method or
    the tool shows up as a diff rather than as a slightly different table;
  * the abstractions the run needs (VFP skipped, zero pages invented, call-outs) must be recorded in the
    artifact, because they bound what the trace means.

Self-skips when the pinned ELF is absent.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ART = ROOT / "reconstruction/reverse-v3/native/dynworld_update_send_trace.json"


def main() -> int:
    tool = (ROOT / "tools/trace_msg_sends.py").read_text()
    assert "file VA" in tool, "the SEL-is-a-file-VA finding must stay documented in the tool"
    pinned = Path(os.environ.get("BH_ELF",
                  ROOT.parent.parent / "extracted/lib/armeabi-v7a/libApplication.so"))
    if not pinned.is_file():
        print("skip: pinned ELF not present")
        return 0
    rep = json.loads(ART.read_text())
    assert rep["counts"]["sends"] > 0, rep["counts"]
    assert rep["counts"]["unresolved_selectors"] == 0, "selector resolution regressed"
    first, seen = [], set()
    for s in rep["trace"]:
        key = (s["site"], s["selector"])
        if key in seen:
            break
        seen.add(key)
        first.append(key)
    assert first == [("0x8ce148", "update:accurateDT:isSimulation:"),
                     ("0x8ce164", "needsRemoved"),
                     ("0x8ce694", "sendNetDataIfNeededForObject:isCreation:"),
                     ("0x8ce6b0", "needsRemoved")], first
    assert rep["counts"]["vfp_skipped"] > 0 and rep["counts"]["zero_pages_invented"] > 0
    print(f"send trace: {len(first)} sends in the first cycle, all selectors resolved, "
          f"{rep['counts']['vfp_skipped']} VFP instructions skipped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
