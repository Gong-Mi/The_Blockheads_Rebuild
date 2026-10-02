# getSaveDict key pairings — batch 2e (Tutorial, BlockheadCraftableItemObject, Ladder, TradePortal)

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`
Recovery: `tools/recover_subclass_savedict_keys_b2e.py` →
`subclass_savedict_keys_b2e.json`. Listings:
`disasm_tutorial_getsavedict.txt` (146w),
`disasm_bcico_getsavedict.txt` (150w),
`disasm_ladder_getsavedict.txt` (155w),
`disasm_tradeportal_getsavedict.txt` (157w).

```text
Tutorial  [NSMutableDictionary dictionary] fresh, NO super:
    numberWithInt: state @12 (0x71e30c/0x71e330)
    numberWithInt: impromptuNightState @16 (0x71e36c/0x71e390)
    numberWithBool: wrongToolHasBeenDisplayed @20 (0x71e3cc/0x71e3f0)
    (pool lists wrongTool cells first; execution state first — order again
    proven by the forward simulator, not by pool position)

BlockheadCraftableItemObject  [super] +
    direct-object name @128 (0x811cc0)
    dataWithBytes:length: of the 20-byte POD at skinOptions @132
      (movw r8,#0x14 @0x811bfc; conv blx r4 0x811cfc; set 0x811d20)
    numberWithInt: of the CONSTANT 1 under craftableObjectType
      (movw lr,#1 @0x811bdc; conv 0x811d48; set 0x811d6c)

Ladder  [super] +
    numberWithInt: itemType @56 (0xaae3d0/0xaae3f4)
    numberWithUnsignedInt: paintColor @60 (0xaae430/0xaae454)
    direct-object INHERITED DynamicObject.ownerID @36 (set 0xaae4cc)

TradePortal  [super] +
    direct-object localPriceOffsets @128 (set 0x00d39540)
    numberWithInt: level @132 (0x00d395ec/0x00d39610)
    nested [TradePortal.light @100 getSaveDict] (0x00d39634) -> lightDict (0x00d3968c)
```

Notable facts:

- **Tutorial builds its own fresh dictionary** (second fresh-dict class after
  CraftableItemObject) — tutorial progress is fully self-contained state
  (3 ints/bools), never a DynamicObject payload merge.
- **craftableObjectType is a compile-time constant 1** for
  BlockheadCraftableItemObject (movw lr,#1 feeding numberWithInt:), not an
  ivar read — a discriminator tag baked per class.
- **skinOptions POD length 20** (`movw r8,#0x14`) versus CICO's 124: each
  craftable class serialises its own fixed struct.
- **numberWithUnsignedInt:** (paintColor) — a fourth boxing selector in the
  save path besides int/float/bool.
- Ladder repeats the Window pattern: an INHERITED `DynamicObject.ownerID`
  key stored directly as an object.

Process: extraction-first held (all words/cells pulled from the annotated
listings programmatically before writing tables) — first run passed every
gate again.

Static level-A only; 29 overrides remain, read-back sides and
save/roundtrip behavior unresolved.
