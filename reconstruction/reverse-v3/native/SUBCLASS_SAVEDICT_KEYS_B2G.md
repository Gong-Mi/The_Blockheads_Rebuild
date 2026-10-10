# getSaveDict key pairings — batch 2g (Rail, KelpPlant, VinePlant, Egg)

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`
Recovery: `tools/recover_subclass_savedict_keys_b2g.py` →
`subclass_savedict_keys_b2g.json`. Listings:
`disasm_rail_getsavedict.txt` (159w), `disasm_kelpplant_getsavedict.txt`
(160w), `disasm_vineplant_getsavedict.txt` (160w),
`disasm_egg_getsavedict.txt` (171w).

```text
Rail      [super] + numberWithInt: itemType @56 (0x77b180/0x77b1a4)
                + configuration<-currentConfiguration @60 int (0x77b1e0/0x77b204)
                + numberWithBool: ownedByStation @65 (0x77b240/0x77b264)
KelpPlant [super] + numberWithInt: numberOfOccupiedTilesAbove @200 (0x816830/0x816854)
                + numberWithFloat: growthTimer @176 (0x816890/0x8168b4)
                + numberWithFloat: availableFood @180 (0x8168f0/0x816914)
VinePlant [super] + numberWithInt: numberOfOccupiedTilesBelow @180 (0x4f7614/0x4f7638)
                + numberWithFloat: growthTimer @176 (0x4f7674/0x4f7698)
                + numberWithFloat: availableFood @100 (0x4f76d4/0x4f76f8)
Egg       [super] + numberWithFloat: hatchTimer @64 (0xd4ea18/0xd4ea3c)
                + saveTime from [self.world @4 worldTime] (msg 0xd4ea78,
                  numberWithFloat 0xd4ea9c, set 0xd4eac0) — same formula as NPC
                + direct-object genesDict @56 (set 0xd4eb38, no dictionaryWithDictionary
                  copy observed in this body)
```

Facts:

- **Rail has no ownerID key** despite the 2f template family having it;
  the 7-dispatch-site count (super + 3×(conv,set)) closes that: this body
  is exactly its three keys.
- **KelpPlant/VinePlant share the growth template but diverge structurally**:
  Above@200 vs Below@180 for the tile-count key, availableFood @180 vs
  @100. Same names, different layouts — the replacement cannot reuse one
  offset table across plant classes.
- **Egg re-derives `saveTime`** with the identical NPC formula
  (`[world worldTime]` → numberWithFloat: → setObject:forKey:), confirming
  the saveTime pattern is world-clock stamping, class-independent, and
  matching the earlier finding that saveTime has no read-back key.
- genesDict is inserted WITHOUT a dictionaryWithDictionary: copy (unlike
  NPC.tameCountsByClientID): Egg owns its dict directly.

Process: the world-ivar cell gate initially failed because the cell re-bases
to the GOT **slot** whose stored word is the symbol address — fixed by
comparing `rw(rebase(cell)) == ivar_st_value` (one more hand-transcription
caught, not by hand this time: by the gate's own evidence path).

Static level-A only; 21 overrides remain (Egg@171w … Workbench@1232w),
read-back/roundtrip unresolved.
