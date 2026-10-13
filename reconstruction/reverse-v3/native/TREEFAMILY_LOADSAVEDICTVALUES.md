# Tree family `-[loadSaveDictValues:]` read-back evidence — batch b3b

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`
Recovery: `tools/recover_treefamily_loadsavedictvalues.py` →
`treefamily_loadsavedictvalues.json`. Listings:
`disasm_plant_loadsavedictvalues.txt` (332w) /
`disasm_gemtree_loadsavedictvalues.txt` (99w) /
`disasm_cactustree_loadsavedictvalues.txt` (157w) /
`disasm_coconuttree_loadsavedictvalues.txt` (29w).

This closes the read-back side of the family b3a opened with Tree: every
remaining `loadSaveDictValues:` in the Plant/Tree inheritance family is now
decoded with word-gated sites, an exact CFString-pool set equality per
method, and 11 mutation negative controls.

```text
Plant -[loadSaveDictValues:] 0x009554a0 (332w) — own keys only, NO super call
  seasonOffset@68         objectForKey → intValue    → str  r0,[r1]
  age@72                  objectForKey → floatValue  → vstr s0,[r0]
  gatherProgress@80       objectForKey → intValue    → str
  hasFloweredThisSeason@84 objectForKey → boolValue  → strb
  flowering@85            objectForKey → boolValue   → strb
  frozen@76               objectForKey → boolValue   → strb
  maxAgeGene@54           objectForKey → intValue    → strh → clamp [1,255]
  growthRateGene@56       objectForKey → intValue    → strh → clamp [1,255]
  saveTime                objectForKey → doubleValue → NO ivar store:
                          if ([self.world worldTime] - saveTime > 1800.0)
                              hasFloweredThisSeason@84 = 0

GemTree -[loadSaveDictValues:] 0x005293ec (99w)
  gemTreeType@136 (int → str), fruitYear@140 (int → str)
  THEN [super loadSaveDictValues:] via objc_msgSendSuper2 → Tree

CactusTree -[loadSaveDictValues:] 0x00b534b4 (157w)
  [super loadSaveDictValues:] FIRST (objc_msgSendSuper2 → Tree), then
  splitHeightA@136 (int → str), splitHeightB@140 (int → str),
  splitDirection@144 (bool → strb), availableFood@148 (float → vstr s0)

CoconutTree -[loadSaveDictValues:] 0x00a99a40 (29w)
  pure super forwarder — zero CFString cells, zero own-ivar stores
```

Facts:

- **Family read/write asymmetry table** (computed from the closed b2*
  batches plus b3a; not asserted from memory):

  | class | save keys | read back | write-only |
  |---|---|---|---|
  | Plant | 11 | 9 | `maxAge`, `growthRate` |
  | Tree | 15 | 14 | `saveTime` |
  | GemTree | 2 | 2 | — |
  | CactusTree | 4 | 4 | — |
  | CoconutTree | 0 (forwarder) | 0 (forwarder) | — |

  Plant's write-only pair are the *derived* caches (`maxAge`@88,
  `growthRate`@92 float): the loader ignores them and re-derives from the
  genes it does read (`maxAgeGene`@54, `growthRateGene`@56) — while Tree's
  write-only `saveTime` is the world-clock stamp proven in b3a.
- **Plant's genes are sanitized on load**: both gene halfwords are re-read
  after the store and passed through local helper `0x004c0b70`
  (`out=v; if v>b out=b; if v<a out=a; bx lr`) with bounds staged as
  `movw ip,#1` / `movw lr,#0xff` at 0x009554b4/0x009554b8 — i.e.
  `strh clamp(gene,1,255)` back into the same ivar.
- **Plant's saveTime read is conditional state, not a restore**: the
  double is compared against `[self.world worldTime]` (ivar
  `DynamicObject.world`@4, selector `worldTime`) with `vsub.f64` /
  `vcmpe.f64` / `ble` and the 1800.0 second constant at 0x00955964/0x00955960;
  taking the branch writes 0 into `hasFloweredThisSeason@84`. No ivar
  receives the timestamp.
- **Super-forward ordering differs per subclass**: GemTree stores its own
  keys first and calls super last; CactusTree calls super first and stores
  its own keys after; CoconutTree only forwards. The class field of each
  `objc_sendSuper2` struct is the `__objc_superrefs` slot for the *own*
  class (`OBJC_CLASS_$_GemTree` / `$_CactusTree` / `$_CoconutTree`, each
  with an R_ARM_RELATIVE fixup), so the runtime resolves the target through
  `current->superclass` — declared hierarchy obtained from the class
  structs: Plant → DynamicObject, Tree → DynamicObject, and
  GemTree/CactusTree/CoconutTree → Tree.
- **Shared CFString objects across sides**: every key read back by these
  loaders is the *same* CFString cell the matching getSaveDict wrote
  (`cfstring_object` equality asserted per key), and the save/load ivar
  offsets agree — the pairing is cross-side consistent, not per-method
  coincidence.
- **Negative controls**: 11 mutations (store opcode flip, clamp bound
  immediate, the 1800.0 constant, ivar-offset slot and its pointer cell,
  receiver-add site, superref target, key cell payload, conversion
  register, super selector cell) must each fail the run
  (`--self-test`), so no gate is vacuous.
- Static level-A only; runtime roundtrip (assemble a save dictionary, load
  it back, compare ivars) is still unresolved. Next natural boundary:
  `initWithSaveDict:` (CraftableItemObject 788w + two ~100w variants),
  `initWithSaveDict:inventoryItems:` (Action 815w), `loadFromSave`
  (CrystalManager 506w), and the 43 subclasses that load their own keys
  inside `initWithWorld:dynamicWorld:saveDict:cache:` overrides.
