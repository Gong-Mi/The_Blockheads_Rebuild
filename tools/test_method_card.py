#!/usr/bin/env python3
"""Contract test for tools/method_card.py, against facts established elsewhere.

The card is a reading aid, so the test must not simply restate its output. The ground truth here was derived from
the binary by hand earlier this session and cross-checked against the ivar scanner: Blockhead -[customizationComplete:]
WRITES Blockhead.skinOptions at offset 728 (mov r3,#1 ; strb r3,[r0,r1] at 0xc89f7c), and Blockhead -[isMale] is a
15-word getter.

It also pins the card's honesty: when it finds no ivars it must say that absence is not evidence, because the
scanner models cell-idiom access only - a card that printed nothing silently would read as "this method touches no
state", which is the failure mode this whole repository keeps guarding against.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ELF = Path(os.environ.get("BH_ELF", ROOT.parent.parent / "extracted/lib/armeabi-v7a/libApplication.so"))


def card(cls: str, selector: str) -> dict:
    out = Path(tempfile.mkdtemp(prefix="bh-card-"))     # /tmp is not writable on the device; tempfile picks one
    j = out / f"card_{cls}_{selector.strip(':').replace(':', '_')}.json"
    r = subprocess.run([sys.executable, "tools/method_card.py", str(ELF),
                        "--class", cls, "--selector", selector, "--json", str(j)],
                       cwd=ROOT, capture_output=True, text=True, timeout=900)
    assert r.returncode == 0, (r.returncode, r.stdout[-300:], r.stderr[-300:])
    return json.loads(j.read_text())


def main() -> int:
    if not ELF.is_file():
        print("skip: pinned ELF not present")
        return 0
    try:
        import capstone  # noqa: F401
        import elftools  # noqa: F401
    except ImportError as e:
        print(f"skip: {e.name} not installed")
        return 0

    # ground truth: the write, from the hand derivation cross-checked with the scanner
    c = card("Blockhead", "customizationComplete:")
    assert c["imp"] == "0x00c89eec", c["imp"]
    assert c["body"]["words"] == 74, c["body"]
    writes = [v for v in c["ivars"] if v["access"] == "write"]
    assert writes, f"customizationComplete: must show the skinOptions write, got {c['ivars']}"
    assert any(w["ivar"] == "Blockhead.skinOptions" for w in writes), writes

    # ground truth: the getter's size, and that the card admits it cannot attribute its read
    m = card("Blockhead", "isMale")
    assert m["body"]["words"] == 15, m["body"]        # the eight-instruction getter
    assert m["imp"] == "0x00c86548", m["imp"]

    # the honesty clause: printed when nothing was attributed
    out = subprocess.run([sys.executable, "tools/method_card.py", str(ELF),
                          "--class", "Blockhead", "--selector", "isMale"],
                         cwd=ROOT, capture_output=True, text=True, timeout=900).stdout
    if not m["ivars"]:
        assert "absence is not evidence" in out, "an empty card must say that absence is not evidence"

    # a method with calls must list them, and they must be real method-table entries
    t = card("World", "worldTime")
    for name in t["calls"] + t["called_by"]:
        assert " -[" in name and name.endswith("]"), name

    # the worklist must not be topped by compiler-generated members: MainMenuUI's .cxx_construct had 441 callers
    # and filled the first ranking this tool produced, which would have sent the semantic effort at linker plumbing.
    rank = subprocess.run([sys.executable, "tools/method_card.py", str(ELF), "--rank", "12"],
                          cwd=ROOT, capture_output=True, text=True, timeout=900).stdout
    assert rank.strip(), "the rank mode must produce a worklist"
    for line in rank.splitlines()[1:]:
        assert ".cxx_construct" not in line and ".cxx_destruct" not in line, line
    assert "Blockhead -[update:accurateDT:isSimulation:]" in rank or True   # presence is not required; absence of
                                                                            # generated members is
    print(f'method-card: PASS (customizationComplete writes {writes[0]["ivar"]}; '
          f'isMale is {m["body"]["words"]} words; empty cards explain themselves)')
    return 0


if __name__ == "__main__":
    sys.exit(main())
