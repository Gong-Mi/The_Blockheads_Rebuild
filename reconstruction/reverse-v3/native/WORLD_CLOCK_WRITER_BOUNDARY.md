# The world-clock writer boundary

Evidence grade: **A** for each exclusion (each is a mechanical sweep or a membership check over the
pinned ELF, reproducible with the commands below), **negative** in conclusion - this document says
what does *not* write the field, and that is a real result rather than a shrug.

Companion: `world_clock_writer_boundary.json`. Context: `LIVE_WORLD_CLOCK.md` (the measured 20
units/real second while `fastForward == 1`), `IVAR_CELL_REFERENCES.md` (the cell reference map).

## The problem this closes out

The running original advances `World.worldTime` (double at +648) at 20 units per real second while
`World.fastForward` (char at +934) reads 1. The library appears to contain no code that writes either
field. Before drawing that conclusion the live premise was re-checked, because this project has seen
79 `__objc_ivar` cells rewritten at runtime and a rewritten cell would invalidate every offset-based
reading: as of the last check all four clock cells still read file == live (648 / 934 / 3112 / 880)
and the values are live (worldTime 361752.29, fastForward 1). The premise holds.

## Eight mechanisms excluded

| mechanism | how it was tested | result |
|---|---|---|
| cell-based ivar store | `extract_ivar_cell_references.py --self-check`, 27155 add-sites / 20593 resolved | worldTime: 3 references, **all reads**; fastForward: 1 reference, the `ldrsb` in its own getter. **0 writes.** |
| literal-immediate store | store-shaped sweep for `#0x288` / `#0x3a6` | 440 hits, all stack slots (`[sp, #0x648]`) or draw-buffer offsets; none is a World field |
| offset materialised into a register | 330874 `movw/mov` immediate candidates + add/store lookahead | 1 hit, verified **false positive** (base was already object+offset, so it addressed `DynamicWorld.dynamicObjects` element + 0x288, and it stores a pointer while worldTime is a double) |
| another library in the APK | all 25 `.so` grepped | only libApplication names either field |
| a setter / property write | method table + property table | no `-setWorldTime:`, no `-setFastForward:`; `fastForward` is a declared **readonly property** (`Tc,R,VfastForward`) |
| a KVC / runtime name literal | the property-name cstring `0xf4fff7` | referenced exactly once - by its own `property_t`; never used as a key literal |
| a bulk copy into the object | trampolines first identified (`0x1c2888`/`0x1c2924`/`0x1c2948` are 3-instruction PLT entries all funnelling to `0x1c27c0`, a dst/src/len routine), then 4043 call sites classified | immediate lengths 8 (916), 16 (642), **64 (417)**, 24, **124 (51)**...; length >= 0x100 into a non-stack destination: 21 sites, **zero in World-family methods** |
| the Java / DEX side | all four DEX files grepped | 3 `fastForward` strings in classes2.dex, **all three Android media API text** (`Dead object in fastForward.`, `TRANSACTION_fastForward`, an AIDL transaction name). Announced as a hit, then corrected - a name match is not an attribution |

## Incidental cross-check

The same copy-size sweep produced 64 bytes at 417 call sites and 124 bytes at 51 - independently
corroborating two facts pinned by entirely different means elsewhere (the 64-byte tile record, and
the 124-byte `CraftableItem` from the `getBytes:length:124` savedict evidence). That is the kind of
agreement that raises confidence in both lines.

## What is left open, stated precisely

1. **a runtime-resolved offset** - `setValue:forKey:` with a key read from data, or `object_setIvar`
   with the ivar fetched by name at run time. Invisible to every static sweep *by construction*.
2. **a mechanism outside libApplication that never names the field**, so it cannot appear in the
   string greps.
3. The cell scan resolves 20593 of 27155 add-sites, and resolves nothing reached through the
   trampoline table; that residue is **not claimed covered**.

## Consequence for the replacement

`game_engine.cpp` maps its sleep state onto `fastForward`. The STATE and the 20.0 factor are measured;
the trigger is not. The mapping stays labelled an inference, and `LIVE_WORLD_CLOCK.md` already says so.

## Regeneration

```text
tools/extract_ivar_cell_references.py <libApplication.so> \
  --methods reconstruction/reverse-v3/native/libApplication_objc_methods.tsv --self-check --json OUT
# literal sweep, register-materialisation sweep, trampoline identification and DEX greps are
# described above; each is a few lines over the same pinned ELF and the decoded instructions.
```
