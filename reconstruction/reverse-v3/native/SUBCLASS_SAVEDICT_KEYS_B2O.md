# getSaveDict key pairings — batch 2o (Action, Tree)

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`
Recovery: `tools/recover_subclass_savedict_keys_b2o.py` →
`subclass_savedict_keys_b2o.json`. Listings:
`disasm_action_getsavedict.txt` (510w),
`disasm_tree_getsavedict.txt` (818w).

```text
Action 0x00735e54  NO super — builds its own [NSMutableDictionary
                    dictionary] and saves 14 keys:
                    inProgress@4/isAI@6 bool (ldrsb/ldrb+sxtb),
                    goalTilePos.x/.y@8 int word pair,
                    interactionItemIndex@20/SubIndex@22 int,
                    interactionItemType = msgSend(interactionItem,
                      itemType) computed selector,
                    goalInteraction@24/pathType@28 int,
                    interactionObjectID@32 numberWithUnsignedLong,
                    inventoryChange@64 nil-guarded DIRECT dict,
                    craftableItemObject@40 = NESTED [getSaveDict],
                    craftCountOrExtraData@44 = ldrsh SIGNED halfword
                      boxed numberWithUnsignedInt,
                    interactionTestResult@52 = dataWithBytes:0xc
                      12-byte RAW BUFFER, UNGUARDED
Tree 0x004c3cac    [super] + height@60 int, saveTime (worldTime
                    double), treeSeasonOffset@84, age@96 float,
                    dead@104 bool, timeDied@112 = FIRST OWN-IVAR
                    DOUBLE (vldr d0), removeCheckCount@120 float,
                    treeFruit = per-fruit dictionaries (pos.x word,
                    pos.y word+4, hasCreatedFreeBlockThisSeason byte+8)
                    built from treeFruits@124 C-array loop over
                    fruitCount@128, then isStaticTree gate: seven
                    growth keys (maxHeightGene@54/growthRateGene@56
                    ldrh halfwords, maxHeightReached@64,
                    growthCounter@68/growthRate@72/maxAge@92 float,
                    maxHeight@88 int) saved ONLY for non-static trees
```

Facts:

- **Action is the first own-dictionary override**: no
  `objc_msgSendSuper2` anywhere in the body; the method creates
  `[NSMutableDictionary dictionary]` (classref 0x7365b8, selref
  0x7365c0, call `bl #0x1c281c` word `4d32eaeb` @0x735ee0). Action
  entities do NOT inherit DynamicObject's base save keys.
- **Action.craftCountOrExtraData is a signed-halfword-as-unsigned box**:
  `ldrsh` @0x7364cc (word `f000d0e1`) loads a signed 16-bit value,
  then `numberWithUnsignedInt:` boxes it — a negative halfword becomes
  a large unsigned int on the wire. A replacement encoder must
  reproduce sign-extension-then-unsigned, not the raw bits.
- **Action.interactionTestResult is the second raw-buffer key**
  (12 bytes, `movw #0xc` word `0ce000e3` @0x73644c; after
  CaveTroll.state's 36) and is saved UNGUARDED — an all-zero result
  still produces an NSData entry (CaveTroll's is guarded by the
  shape of its own code path).
- **Action.craftableItemObject is the first nested entity save**:
  `[ivar getSaveDict]` @0x7363d0 (word `33ff2fe1`), nil-guarded
  (beq word `1000000a` @0x7363e4) — the save graph embeds another
  dynamic object's full save dict.
- **Tree.timeDied is the first own-ivar double**: `vldr d0` @0x4c40d0
  reads the stored 64-bit field — every prior double (saveTime in
  Plant/InteractionObject/Tree) was world-fed via
  `[world worldTime]`.
- **Tree's fruit sub-dicts reuse parent-family key names**: each fruit
  dictionary carries `pos.x`/`pos.y`/`hasCreatedFreeBlockThisSeason`,
  colliding with other classes' top-level key names; they live only
  inside the `treeFruit` array entries.
- **The isStaticTree gate (msg `blx r2` @0x4c44b8 + sxtb + bne word
  `f300001a` @0x4c44c4) makes the key set CONDITIONAL**: static trees
  save 8 keys, non-static trees save 15. A replacement encoder must
  branch on the same selector, not emit a fixed set.
- Tree's genes are halfwords (`ldrh` @0x4c45f0 word `b000d0e1`,
  @0x4c4674 word `b030d3e1`) — zero-extended like Torch's dataA/dataB.

Static level-A only; 1 override remains (Workbench 1232w),
read-back/roundtrip unresolved.
