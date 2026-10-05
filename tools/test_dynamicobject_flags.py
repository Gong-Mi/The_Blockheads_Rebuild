#!/usr/bin/env python3
"""Contract test for the DynamicObject flag cluster artifact.

Two independent sources have to agree here: the symbol table names each flag and its cell, and the
artifact records them. The test re-reads the symbol table and the cells' contents, so the cluster cannot
be silently renumbered - and it pins the one classified write plus the classifier-gap boundary, because
the tempting misreading of this artifact is "there is one writer".
"""
from __future__ import annotations

import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ART = ROOT / "reconstruction/reverse-v3/native/dynamicobject_flags.json"

EXPECTED = {"needsRemoved": 48, "updateNeedsToBeSent": 49, "creationDataNeedsToBeSent": 50,
            "unreliableUpdateNeedsToBeSent": 51, "isNet": 52}


def main() -> int:
    rep = json.loads(ART.read_text())
    assert rep["cluster"]["offsets"] == EXPECTED, rep["cluster"]["offsets"]
    import os
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
                named[s.name[len(pre):]] = (s["st_value"], struct.unpack_from("<i", blob, s["st_value"])[0])
    for flag, off in EXPECTED.items():
        assert flag in named, flag
        cell, content = named[flag]
        assert content == off, (flag, content, off)
        assert rep["per_flag"][flag]["cell"] == hex(cell), (flag, rep["per_flag"][flag]["cell"], hex(cell))
    w = rep["per_flag"]["updateNeedsToBeSent"]["classified_writes"]
    assert len(w) == 1 and w[0]["add_site"] == "0x5f63a4", w
    assert "strb" in (w[0]["instruction"] or ""), w
    assert rep["per_flag"]["updateNeedsToBeSent"]["by_access"]["pointer-or-unknown"] > 10, \
        "the classifier gap must stay visible in the artifact"
    assert any("classifier" in b for b in rep["boundary"]), rep["boundary"]
    print(f"flag cluster: 5 flags at 48..52 confirmed by symbol table; "
          f"updateNeedsToBeSent has {rep['per_flag']['updateNeedsToBeSent']['sites']} sites, "
          f"1 classified write, {rep['per_flag']['updateNeedsToBeSent']['by_access']['pointer-or-unknown']} unclassified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
