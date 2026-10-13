#!/usr/bin/env python3
"""Extract the FULL Objective-C class metadata from the pinned ELF.

Automates what used to be hand-mined from listings: class hierarchy, instance
sizes, ivar layouts (name/offset/type) and the __objc_superrefs cells.

Layouts decoded against sha256 733d8210…c94c7 (ARM32, Apportable):
  __objc_classlist : array of class_t*            (538 entries, [0]=sentinel)
  class_t          : {isa, superclass, cache, vtable, data(=class_ro_t*)}
  class_ro_t       : {flags, instanceStart, instanceSize, ivarLayout,
                      name*(abs), baseMethods, baseProtocols, ivars*,
                      weakIvarLayout, baseProperties}
  ivar_list_t      : {entsize(4), count(4)} then entries
  ivar_t           : {offset*(4 -> the offset value), name*(4), type*(4),
                      alignment(4), size(4)}
  __objc_superrefs : cells holding a class pointer (the super2 operand)

Outputs native/class_metadata.json + a readable native/CLASS_TABLE.md.
"""
import json
import struct
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "reconstruction/reverse-v3/native"
ELF = Path.home() / "blockheads-work/extracted/lib/armeabi-v7a/libApplication.so"
ELF_SHA = "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"

CLASSLIST = 0xE8BF58
CLASSLIST_SIZE = 2152
SUPERREFS = 0xE8B850
SUPERREFS_SIZE = 1800


def main() -> int:
    import hashlib
    if hashlib.sha256(ELF.read_bytes()).hexdigest() != ELF_SHA:
        raise SystemExit("ELF SHA mismatch")
    elf = ELFFile(ELF.open("rb"))
    loads = []
    for s in elf.iter_segments():
        if s["p_type"] == "PT_LOAD":
            loads.append((s["p_vaddr"], s["p_memsz"], len(s.data()), s.data()))

    def rd(addr, n):
        if addr is None or addr < 0:
            return None
        for base, memsz, dlen, data in loads:
            if base <= addr and addr + n <= base + memsz and addr + n - base <= dlen:
                return data[addr - base:addr - base + n]
        return None

    def u32(a):
        b = rd(a, 4)
        return struct.unpack("<I", b)[0] if b else None

    def cstr(a, cap=128):
        b = rd(a, cap) or b""
        return b.split(b"\0")[0].decode("latin1")

    classes = {}
    for i in range(CLASSLIST_SIZE // 4):
        cls = u32(CLASSLIST + i * 4)
        if not cls or cls == 0xFFFFFFFF:
            continue
        isa, sup, cache, vt, data = (u32(cls), u32(cls + 4), u32(cls + 8),
                                     u32(cls + 12), u32(cls + 16))
        if not data:
            continue
        instance_size = u32(data + 8)
        ivars_ptr = u32(data + 28)
        ivars = []
        if ivars_ptr:
            entsize = u32(ivars_ptr)
            count = u32(ivars_ptr + 4)
            if entsize and count and count < 400:
                for k in range(count):
                    ent = ivars_ptr + 8 + k * entsize
                    off_ptr = u32(ent)
                    name_ptr = u32(ent + 4)
                    type_ptr = u32(ent + 8)
                    ivars.append({
                        "name": cstr(name_ptr),
                        "offset": u32(off_ptr) if off_ptr else None,
                        "type": cstr(type_ptr, 64),
                    })
        classes[cls] = {
            "name": cstr(u32(data + 16) or 0),
            "class_addr": cls,
            "super_addr": sup,
            "instance_size": instance_size,
            "ivars": ivars,
        }

    # names for superclasses (may live outside the classlist)
    for c in classes.values():
        sup = c["super_addr"]
        c["super"] = classes[sup]["name"] if sup in classes else (
            None if not sup else f"<{sup:#x}>")

    # superref cells: cell -> class pointer it holds; reverse map class -> cells
    superref_cells = {}
    for i in range(SUPERREFS_SIZE // 4):
        cell = SUPERREFS + i * 4
        val = u32(cell)
        if val:
            superref_cells[cell] = val
    by_class = {}
    for cell, val in superref_cells.items():
        by_class.setdefault(val, []).append(cell)

    # merge: which class does each superref cell's target name
    for c in classes.values():
        c["superref_candidates"] = by_class.get(c["class_addr"], [])
        # the cell the class's own code uses holds the class's own address
        # (super2 struct {self, own-class}); emit as hex strings for readability
        c["superref_candidates"] = [f"0x{x:08x}" for x in c["superref_candidates"]]

    out = {
        "elf_sha256": ELF_SHA,
        "class_count": len(classes),
        "classes": {c["name"]: {
            "class_addr": f"0x{c['class_addr']:08x}",
            "super": c["super"],
            "super_addr": f"0x{c['super_addr']:08x}" if c["super_addr"] else None,
            "instance_size": c["instance_size"],
            "ivars": c["ivars"],
            "superref_candidates": c["superref_candidates"],
        } for c in sorted(classes.values(), key=lambda x: x["name"])},
    }
    (NATIVE / "class_metadata.json").write_text(json.dumps(out, indent=2) + "\n")

    # readable table: only classes with ivars (the interesting ones)
    lines = ["# Class metadata (machine-extracted from the pinned ELF)",
             "",
             f"Source: `tools/elf_class_metadata.py` over sha256 `{ELF_SHA}`.",
             f"Classes: {len(classes)}. Ivar layouts below are authoritative "
             "(they are what the harnesses have been pinning by hand).", ""]
    interesting = [c for c in classes.values() if c["ivars"]]
    lines.append(f"## Classes with ivars ({len(interesting)} of {len(classes)})")
    lines.append("")
    lines.append("| class | super | size | ivars (name@offset) |")
    lines.append("|---|---|---:|---|")
    for c in sorted(interesting, key=lambda x: x["name"]):
        iv = ", ".join(f"{i['name']}@{i['offset']}" for i in c["ivars"][:12])
        if len(c["ivars"]) > 12:
            iv += f", … (+{len(c['ivars']) - 12})"
        lines.append(f"| {c['name']} | {c['super'] or '-'} | "
                     f"{c['instance_size']} | {iv} |")
    (NATIVE / "CLASS_TABLE.md").write_text("\n".join(lines) + "\n")
    print(f"classes={len(classes)} with_ivars={len(interesting)} "
          f"superref_cells={len(superref_cells)}")
    # spot-check the classes this session pinned by hand
    for cls_name, want in (("ArtificialLight", 0xE8BE48), ("TrainCar", 0xE8BE24),
                           ("OwnershipSign", 0xE8BE20), ("Painting", 0xE8BE64),
                           ("DropBear", 0xE8BD3C), ("CaveTroll", 0xE8BF2C),
                           ("SteamTrain", 0xE8BF10)):
        c = out["classes"].get(cls_name)
        got = c["superref_candidates"] if c else None
        ok = got and f"0x{want:08x}" in got
        print(f"  {cls_name:16s} pinned=0x{want:08x} candidates={got} "
              f"{'OK' if ok else 'MISS'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
