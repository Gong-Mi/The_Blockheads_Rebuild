#!/usr/bin/env python3
"""Contract test for the recovered CraftableItem record: the layout must come from the encoding.

The record's shape is not a guess - the original's method table carries the type encoding
`{CraftableItem=ii[8i][8i]iiiSSi[8i]}`. This test parses that encoding straight out of the method table,
computes the field offsets and the total size, and requires the C++ header to agree, so the header cannot
diverge from the binary by a hand edit. It also checks the size a second, independent way: the argument
offsets in the same signature step from 8 to 132, which is 124.

The field SEMANTICS remain unknown and are not asserted anywhere - f0..f10 are positional names.
"""
from __future__ import annotations

import json
import os
import re
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HDR = ROOT / "reconstruction/recovered/craftable_item_record.h"
TSV = ROOT / "reconstruction/reverse-v3/native/libApplication_objc_methods.tsv"
ART = ROOT / "reconstruction/reverse-v3/native/craftable_item_struct.json"
SIZES = {"i": 4, "S": 2, "c": 1, "C": 1, "f": 4, "d": 8, "l": 4, "B": 1}


def derive(enc: str):
    body = enc[enc.index("=") + 1:enc.rindex("}")]
    fields, off, i = [], 0, 0
    while i < len(body):
        m = re.match(r"\[(\d+)([a-zA-Z])\]", body[i:])
        if m:
            n, k = int(m.group(1)), m.group(2)
            fields.append((len(fields), off, n * SIZES[k]))
            off += n * SIZES[k]
            i += m.end()
        else:
            k = body[i]
            fields.append((len(fields), off, SIZES[k]))
            off += SIZES[k]
            i += 1
    return fields, off


def main() -> int:
    text = TSV.read_text()
    m = re.search(r"\{CraftableItem=([^}]+)\}[^\t@]*8@(\d+)@(\d+)", text)
    assert m, "the CraftableItem encoding must still appear in the method table"
    enc = "{CraftableItem=" + m.group(1) + "}"
    span = int(m.group(2)) - 8
    fields, total = derive(enc)
    assert total == span, (total, span)

    hdr = HDR.read_text()
    for idx, off, size in fields:
        assert re.search(rf"\bf{idx}\b", hdr), f"field f{idx} missing from the header"
        assert f"static_assert(offsetof(CraftableItemRecord, f{idx}) == {off}" in hdr, (idx, off)
    assert f"sizeof(CraftableItemRecord) == {total}" in hdr
    assert f"__TOTAL__" not in hdr

    # the pre-existing artifact recorded the same eleven offsets; if it still has them, require agreement
    if ART.is_file():
        art = json.loads(ART.read_text())
        rec = art.get("fields") or art.get("offsets") or []
        offs = [f["offset"] if isinstance(f, dict) else f for f in rec] if rec else []
        if offs:
            assert offs == [o for _, o, _ in fields], (offs, [o for _, o, _ in fields])

    # cross-artifact: the host facts must agree with the deserialiser evidence, not just with the encoding
    des = ROOT / "reconstruction/reverse-v3/native/craftableitem_initsavedict.json"
    if des.is_file():
        d = json.loads(des.read_text())
        ci = [c for c in d["classes"] if c["class"] == "CraftableItemObject"][0]
        assert ci["blob"]["length"] == total, (ci["blob"]["length"], total)
        assert ci["blob"]["key"] == "craftableItem"
        host_off = None
        for k in ci["keys"]:
            if k.get("ivar", "").endswith(".craftableItem"):
                host_off = k["ivar_offset"]
        assert host_off == 4, host_off
        assert f"kCraftableItemObjectRecordOffset = {host_off};" in hdr
        assert "kCraftableItemObjectInstanceSize = 128" in hdr
        assert f"kCraftableItemBlobLength = {total};" in hdr


    # the "exactly two references" claim is re-scanned here, not quoted: a third use of the key would mean
    # another writer or reader exists and this model's story about the pair would be incomplete
    pinned2 = Path(os.environ.get("BH_ELF", ROOT.parent.parent /
                                  "extracted/lib/armeabi-v7a/libApplication.so"))
    if pinned2.is_file():
        blob2 = pinned2.read_bytes()
        cf, pic = 0x00f9b7b8, 0x105faf4
        want = {(cf - pic) & 0xffffffff, cf}
        pool = [a for a in range(0x001C4500, 0x00DB8AA8, 4) if struct.unpack_from("<I", blob2, a)[0] in want]
        refs = []
        for a in pool:
            for back in range(4, 0x600, 4):
                addr = a - back
                if addr < 0 or addr + 4 > len(blob2):
                    continue
                w = struct.unpack_from("<I", blob2, addr)[0]
                if (w >> 28) == 0xE and ((w >> 24) & 0xF) in (0x5,):   # ldr rX,[pc,#imm]
                    imm = w & 0xFFF
                    if addr + 8 + imm == a:
                        refs.append(addr)
                        break
        assert sorted(refs) == [0x00ac79a8, 0x00ac7a68], [hex(r) for r in refs]
        assert "kCraftableItemKeyReferencesInBinary = 2" in hdr

    # the dispatch boundary must stay recorded: it is the reason the fillers are still unfound
    pair = ROOT / "reconstruction/reverse-v3/native/craftable_item_serialisation_pair.json"
    if pair.is_file():
        pd = json.loads(pair.read_text())
        assert "dispatch_boundary" in pd, "the selector-dispatch boundary must stay documented"
        assert pd["dispatch_boundary"]["selector"].startswith("initWithCraftableItem:")
        assert "selref_slots: EMPTY" in " ".join(pd["dispatch_boundary"]["facts"]), \
            "the measured selref fact must stay recorded"
        assert "correction" in pd["dispatch_boundary"], "the tool-attribution correction must stay"
        assert "kCraftableItemInitializerDispatchUnknown" in hdr

    print(f"craftable item record: {len(fields)} fields, {total} bytes, derived from the encoding "
          f"and confirmed by the signature's argument span ({span})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
