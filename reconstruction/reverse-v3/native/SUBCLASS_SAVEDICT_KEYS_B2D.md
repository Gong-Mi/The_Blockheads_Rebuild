# getSaveDict key pairings — batch 2d (PaintingCraftableItemObject, NormalPlant, GlowBlock, GatherBlock)

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`
Recovery: `tools/recover_subclass_savedict_keys_b2d.py` →
`subclass_savedict_keys_b2d.json`. Listings:
`disasm_paintingcico_getsavedict.txt` (129w),
`disasm_normalplant_getsavedict.txt` (136w),
`disasm_glowblock_getsavedict.txt` (123w),
`disasm_gatherblock_getsavedict.txt` (122w).

```text
PaintingCraftableItemObject [super] + direct-object imageData @128 (0x742074)
    + direct-object outputImageData @132 (0x7420ec)
    + numberWithInt: craftableObjectType (conv 0x742150, set 0x742174)
      (value cell pending — deliberately unclaimed)

NormalPlant [super] + numberWithFloat: availableFood @120
    + [self emitsLight] guard (blx 0xa66f3c, cmp r0,#0 beq 0xa66ff4) around
      nested [self.light @124 getSaveDict] (0xa66f94) -> lightDict (0xa66fec)

GlowBlock [super] + numberWithInt: tileType @60 (0xca8d84/0xca8da8)
    + nested [self.light @56 getSaveDict] (0xca8dcc), nil-check
      cmp/beq->0xca8e28 -> lightDict (0xca8e24)

GatherBlock [super] + numberWithFloat: timer @56 (0x8698c0/0x8698e4) FIRST
    + numberWithInt: lastKnownGatherValue @60 (0x869920/0x869944)
```

New shapes this batch:

- **Nested child dictionaries**: NormalPlant and GlowBlock call
  `[<child> getSaveDict]` on their `light` ivar and insert the returned
  dictionary under `lightDict`. The save tree is recursive through
  DynamicObject composition, not flat — the replacement loader must build
  child dicts and attach, not flatten.
- **Behavioural guard on key presence**: NormalPlant only writes lightDict
  when `[self emitsLight]` is non-nil/true (beq to the return block at
  0xa66ff4); GlowBlock just skips nil receivers via cmp/beq.
- Pool order != execution order again (GatherBlock: pool lists
  lastKnownGatherValue cells first, timer is boxed and set first).

Process note: after three batches where the raw-word gate rejected
hand-transcribed dispatch words (2b: one; 2c: three; and the claim-text
typo), this batch extracted every word and cell mechanically from the
annotated listings before writing the table — the gates then passed on the
first run. The extraction-first workflow is now the standard.

Static level-A only; 33 overrides remain unpaired, read-back sides and
save/roundtrip behavior unresolved.
