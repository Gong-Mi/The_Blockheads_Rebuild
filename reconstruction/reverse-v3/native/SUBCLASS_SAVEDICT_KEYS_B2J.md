# getSaveDict key pairings — batch 2j (Torch, TradingPost, FireObject)

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`
Recovery: `tools/recover_subclass_savedict_keys_b2j.py` →
`subclass_savedict_keys_b2j.json`. Listings:
`disasm_torch_getsavedict.txt` (266w),
`disasm_tradingpost_getsavedict.txt` (327w),
`disasm_fireobject_getsavedict.txt` (244w).

```text
Torch 0x004b65b8        [super] + itemType@64 / dataA@80 / dataB@82
                        / connectionType@60 numberWithInt:
                        + nil-guarded lightDict DIRECT (Torch.light@56,
                          via second objc_msgSend(self, getSaveDict))
                        + nil-guarded ownerID DIRECT (DynamicObject.ownerID@36)
TradingPost 0x005e6b08   [super] + nil-guarded sellerClientName@112 DIRECT
                        + fast-enumerate sellSlot@100 building a LOCAL
                          NSMutableArray of per-item [saveData] dicts,
                          EXCLUDING itemType == 11 (0xb)
                        + coinCount@104 numberWithInt:
                        + priceTier@108 numberWithInt:
                        + sellSlot@100 DIRECT (live array object)
FireObject 0x0067501c    [super] + burnTimer@56 numberWithFloat: (vldr s0)
                        + spreadTimer_0..3 numberWithFloat: — the four
                          float32 lanes of ONE ivar FireObject.spreadTimers@60
                          (vldr s0 [r3, #0/4/8/0xc])
                        + nil-guarded lightDict DIRECT (FireObject.light@76)
```

Facts:

- **FireObject is the first `numberWithFloat:` batch**: burnTimer and the
  four spread timers are float32 values read by VFP `vldr s0` and boxed
  via `numberWithFloat:`. spreadTimer_0..3 map to ONE array ivar
  (`FireObject.spreadTimers@60`) at word offsets +0/+4/+8/+0xc — same
  "one ivar, many keys" shape as ElevatorShaft's dotted pos keys, but with
  underscore-suffixed keys instead of dotted ones.
- **Torch.dataA@80 / dataB@82 are halfword loads** (`ldrh` at
  0x4b6784/0x4b67e4): zero-extended 16-bit values into `numberWithInt:`;
  a replacement encoder must not sign-extend them.
- **TradingPost.saveData is a selector on each iterated item, not an
  ivar**: `objc_msgSend(item, saveData)` at 0x5e6db4 collects each
  item's own save dict into a local NSMutableArray, and entries whose
  `itemType == 11` are EXCLUDED (cmp #0xb + beq at 0x5e6d68/0x5e6d6c).
  The filtered array is local-only — no setObject stores it.
- **TradingPost.sellSlot is saved DIRECT** (the live array object,
  `blx r8` word `38ff2fe1` at 0x5e6efc), while `sellerClientName@112`
  is the nil-guarded raw-object pattern (cmp/beq 0x5e6b8c/0x5e6b90).
- **Torch ownerID reuses DynamicObject.ownerID@36** with a nil-guard,
  same shared-ivar pattern as Sign/ElevatorMotor/ElevatorShaft/Painting.
- Torch and FireObject both issue a **second `objc_msgSend(self,
  getSaveDict)`** (Torch @0x4b660c, FireObject @0x675070) whose result is
  the light object stored under `lightDict` — the light is itself a
  DynamicObject that saves through its own getSaveDict; the stored
  value is nil-guarded (Torch cmp/beq 0x4b68b8/0x4b68bc; FireObject
  0x675350/0x675354).
- The spill-cascade register scheduling in TradingPost pairs
  coinCount (conv 0x5e6f38 → set 0x5e6f5c) BEFORE priceTier (conv
  0x5e6f98 → set 0x5e6fbc); both were confirmed by the freeblock
  simulator's r3-at-set tracing, not by textual order of the CFString
  loads.

Process note: addresses came from `tools/gen_b2j_table.py` (annotated
listings + freeblock simulator, same pipeline as b2f/b2h/b2i); the
simulator emits conv→set pairing order and the CFString/ivar cells; every
cell was then re-gated against the pinned ELF in the recovery script, plus
24 extra instruction-word gates (guards, ldrh, vldr, enumeration,
itemType==0xb exclusion, saveData dispatch).

Static level-A only; 10 overrides remain (Plant, Tree, Action,
ArtificialLight, Boat, CaveTroll, CraftableItemObject, DropBear, NPC,
InteractionObject, TrainCar, TrainStation, Workbench minus already-done
inventoried Blockhead/Chest), read-back/roundtrip unresolved.
