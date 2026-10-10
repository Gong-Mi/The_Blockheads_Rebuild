# getSaveDict key pairings — batch 2p (Workbench) — FINAL override

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`
Recovery: `tools/recover_subclass_savedict_keys_b2p.py` →
`subclass_savedict_keys_b2p.json`. Listing:
`disasm_workbench_getsavedict.txt` (1232w).

```text
Workbench 0x00ae81d0  [super] + 20 static keys + format family +
                      nested saves:
                      workbenchType ← RE-KEYED ivar type@120 (int)
                      selectedIndex@136 int, xScroll@172 float,
                      level@176 int, craftProgressCount@188 float,
                      hurryTimer@192 / hurrySeconds@196 float,
                      hurrying@200 bool, hurryCost@204 int,
                      availableElectricity@222 unsigned int,
                      fireSpreadTimer@208 / fuelFraction@212 float,
                      hasFuel@220 bool,
                      lastWorldTime@256 = OWN-IVAR DOUBLE (2nd after
                        Tree.timeDied)
                      currentBlockheadIndexFuel = loop index of
                        currentFuelBlockhead@108 in
                        [dynamicWorld blockheads]
                      craftingItemDatav2 = NESTED
                        [craftingItemObject@180 getSaveDict]
                      count@228 / countLeft@232 / countCreated@236 int
                      sourceItems_%d = per-index [saveData] arrays
                        (2nd format-string family)
                      lightDict = NESTED [light@100 getSaveDict]
```

Facts:

- **With b2p the static subclass getSaveDict key matrix is COMPLETE**:
  every one of the 66 `getSaveDict` methods in the pinned ObjC method
  map is now inventoried and paired (15 super-forwarders + Blockhead/
  Chest tail dispatchers + FreeBlock/NPC/Tree-base batches + b2b..b2p
  key pairings).
- **Workbench is the largest override** (1232 words) and re-keys its
  type ivar: wire key `workbenchType` reads `OBJC_IVAR_$_Workbench.type`
  (same re-key family as Painting.outputImageData/imageData).
- **lastWorldTime@256 is the second own-ivar double** (after
  Tree.timeDied): a stored 64-bit field boxed `numberWithDouble:` —
  distinct from every world-fed saveTime.
- **sourceItems_%d is the second format-string key family** (after
  TrainCar): `[NSString stringWithFormat:'sourceItems_%d', i]`
  @0xae9370 keys a per-index NSMutableArray of per-item `[saveData]`
  dicts — save cost is O(indices × items).
- **Two nested entity saves**: craftingItemDatav2 (nil-guarded
  `[craftingItemObject@180 getSaveDict]`) and lightDict
  (`[light@100 getSaveDict]`) embed other objects' full save dicts.
- **PENDING (recorded, not asserted)**: the `craftableItem` selector
  (selref cell 0xae94c0) and the second craftingItemObject@180 load
  enter the spill cascade feeding the count trio, but the exact
  consumer semantics (guard vs value source) were not traced to a
  branch gate in this batch — listed in `pending_gates` of the JSON.

Static level-A only. The static key matrix is complete, but
read-back/roundtrip, entity construction and runtime behavior remain
unresolved.
