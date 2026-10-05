#!/usr/bin/env python3
"""Contract test for the DynamicObject flag cluster artifact.

Two independent sources have to agree: the symbol table names each flag and its cell, and the artifact
records them. The test re-reads both, so the cluster cannot be silently renumbered.

It also pins the outcome of the fused-store classifier fix, because the tempting readings of this
artifact are both wrong: "there is one writer" (the old, tool-gap reading) and "isNet has a writer
somewhere" (it does not).
"""
from __future__ import annotations

import json
import os
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ART = ROOT / "reconstruction/reverse-v3/native/dynamicobject_flag_sites.json"

EXPECTED = {"needsRemoved": 48, "updateNeedsToBeSent": 49, "creationDataNeedsToBeSent": 50,
            "unreliableUpdateNeedsToBeSent": 51, "isNet": 52}


def main() -> int:
    rep = json.loads(ART.read_text())
    assert rep["cluster"]["offsets"] == EXPECTED, rep["cluster"]["offsets"]
    pinned = Path(os.environ.get("BH_ELF",
                  ROOT.parent.parent / "extracted/lib/armeabi-v7a/libApplication.so"))
    if not pinned.is_file():
        print("skip: pinned ELF not present")
        return 0
    from elftools.elf.elffile import ELFFile
    blob = pinned.read_bytes()
    named = {}
    with pinned.open("rb") as fh:
        for s in ELFFile(fh).get_section_by_name(".dynsym").iter_symbols():
            pre = "OBJC_IVAR_$_DynamicObject."
            if s.name.startswith(pre) and s["st_value"]:
                named[s.name[len(pre):]] = (s["st_value"],
                                            struct.unpack_from("<i", blob, s["st_value"])[0])
    for flag, off in EXPECTED.items():
        assert flag in named, flag
        cell, content = named[flag]
        assert content == off, (flag, content, off)
        assert rep["per_flag"][flag]["cell"] == hex(cell), (flag, rep["per_flag"][flag]["cell"])

    writes = rep["per_flag"]["updateNeedsToBeSent"]["writes"]
    assert len(writes) >= 20, writes  # the fused-store fix must keep finding the dirty-bit writers
    assert all("strb" in (w["instruction"] or "") for w in writes[:10]), writes[:3]
    assert rep["per_flag"]["isNet"]["by_access"].get("write", 0) == 0, \
        "isNet's writer is still unexplained; do not quietly claim one"
    assert rep.get("supersedes"), "the superseded reading must stay recorded"
    assert rep["global_by_access"]["write"] > 400, rep["global_by_access"]
    print(f"flag cluster: 5 flags at 48..52 confirmed by symbol table; updateNeedsToBeSent has "
          f"{rep['per_flag']['updateNeedsToBeSent']['sites']} sites and {len(writes)} writes; "
          f"isNet writes={rep['per_flag']['isNet']['by_access'].get('write', 0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
