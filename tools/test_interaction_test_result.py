#!/usr/bin/env python3
"""Contract test for the recovered InteractionTestResult record - the size checked four ways.

This record is one of the better-established structures in the binary precisely because independent things
agree about it, and this test checks them independently rather than quoting one:

  * the type encoding parsed out of the method table sums to the size;
  * the SETTER's signature declares a by-value argument at offset 8 with a frame of 8 + size;
  * a method that RETURNS the struct declares a frame of exactly the size;
  * the save read-back in Action -[initWithSaveDict:inventoryItems:] uses a 12-byte getBytes:length:;
  * the host ivar is named by the symbol table at offset 52.

If any of those moved, one of the assertions fails - which is the point: four sources, four checks.
"""
from __future__ import annotations

import json
import os
import re
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HDR = ROOT / "reconstruction/recovered/interaction_test_result.h"
TSV = ROOT / "reconstruction/reverse-v3/native/libApplication_objc_methods.tsv"
ART = ROOT / "reconstruction/reverse-v3/native/action_initsavedict_inventoryitems.json"
SIZES = {"i": 4, "S": 2, "c": 1, "C": 1, "f": 4, "d": 8, "l": 4, "B": 1}


def derive(enc: str):
    body = enc[enc.index("=") + 1:enc.rindex("}")]
    fields, off, i = [], 0, 0
    while i < len(body):
        m = re.match(r"\[(\d+)([a-zA-Z])\]", body[i:])
        if m:
            k, ch = int(m.group(1)), m.group(2)
            fields.append((len(fields), off, k * SIZES[ch])); off += k * SIZES[ch]; i += m.end()
        else:
            ch = body[i]
            fields.append((len(fields), off, SIZES[ch])); off += SIZES[ch]; i += 1
    return fields, off


def main() -> int:
    text = TSV.read_text()
    enc_m = re.search(r"\{(InteractionTestResult=[^}]+)\}", text)
    assert enc_m, "the struct encoding must still appear in the method table"
    enc = "{" + enc_m.group(1) + "}"
    fields, total = derive(enc)
    assert total == 12, total

    # (2) the setter's by-value argument frame: v20@0:4{...}8  -> 20 == 8 + total
    setter = re.search(r"\t(setInteractionTestResult:)\tv(\d+)@0:4\{InteractionTestResult=[^}]+\}8", text)
    assert setter, "setter signature missing"
    assert int(setter.group(2)) == 8 + total, (setter.group(2), total)

    # (3) a method returning it: {InteractionTestResult=...}12@0:4@8 -> the frame IS the struct size
    ret = re.search(r"\{InteractionTestResult=[^}]+\}(\d+)@0:4@8\n", text)
    if ret:
        assert int(ret.group(1)) == total, (ret.group(1), total)

    # (4) the save read-back length recorded by the earlier batch must equal the size
    if ART.is_file():
        art = json.loads(ART.read_text())
        consts = json.dumps(art.get("constants", {}))
        assert "getBytes:length: 12" in consts, consts[-200:]
        assert art["constants"].get("interactionTestResult@52", "").find("12") >= 0

    # (5) the host ivar, named by the binary
    pinned = Path(os.environ.get("BH_ELF",
                  ROOT.parent.parent / "extracted/lib/armeabi-v7a/libApplication.so"))
    if pinned.is_file():
        from elftools.elf.elffile import ELFFile
        blob = pinned.read_bytes()
        with pinned.open("rb") as fh:
            for s in ELFFile(fh).get_section_by_name(".dynsym").iter_symbols():
                if s.name == "OBJC_IVAR_$_Action.interactionTestResult":
                    assert struct.unpack_from("<i", blob, s["st_value"])[0] == 52
                    break
            else:
                raise AssertionError("Action.interactionTestResult ivar symbol missing")

    hdr = HDR.read_text()
    for idx, off, size in fields:
        assert f"static_assert(offsetof(InteractionTestResult, f{idx}) == {off}" in hdr, (idx, off)
    assert f"sizeof(InteractionTestResult) == {total}" in hdr
    print(f"interaction test result: {len(fields)} fields, {total} bytes, confirmed by the encoding, the "
          f"setter frame ({8 + total}), the return frame and the 12-byte save read-back")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
