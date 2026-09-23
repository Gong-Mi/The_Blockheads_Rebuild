# Craftable-item family `-[initWithSaveDict:]` read-back evidence — batch b3c

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`
Recovery: `tools/recover_craftableitem_initsavedict.py` →
`craftableitem_initsavedict.json`. Listings:
`disasm_craftableitemobject_initsavedict.txt` (85w) /
`disasm_paintingcraftableitemobject_initsavedict.txt` (103w) /
`disasm_blockheadcraftableitemobject_initsavedict.txt` (788w, incl. the
local pack helper 0x008112d8).

```text
CraftableItemObject 0x00ac7900 ( 85w) — ROOT class (class struct super = NIL)
  self = [super init]            (objc_msgSendSuper2, own superref slot)
  if (!self) return nil
  [[saveDict objectForKey:@"craftableItem"] getBytes:&self->craftableItem
   length:124]                   → 124-byte POD blob at craftableItem@4

PaintingCraftableItemObject 0x00741e18 (103w)
  self = [super initWithSaveDict:saveDict]; if (!self) return nil
  self->imageData@128       = [[saveDict objectForKey:@"imageData"] retain]
  self->outputImageData@132 = [[saveDict objectForKey:@"outputImageData"]
                               retain]

BlockheadCraftableItemObject 0x00810f10 (788w)
  self = [super initWithSaveDict:saveDict]; if (!self) return nil
  self->name@128 = [[saveDict objectForKey:@"name"] retain]
  skinOptions@132 is a 20-byte record with TWO sources:
    blob present → [data getBytes:&self->skinOptions length:20]
    blob absent (beq 0x8110ec) → scalar keys isMale(boolValue→sxtb),
      headIndex / skinIndex / hairStyleIndex (intValue) are passed to local
      helper 0x8112d8(&local, isMale, headIndex, skinIndex, stack=
      hairStyleIndex); its 20-byte result is memcpy'd (0x1c2894) into
      self+132. Helper internals are listed but NOT decoded in this batch.
```

Facts:

- **CraftableItemObject is a root class**: its class struct (`0x00e91cc8`)
  carries `super = NIL` with the RO_ROOT flag, `instance_start = 4`,
  `instance_size = 128` — and the 124-byte blob written at `craftableItem@4`
  fills exactly `4 + 124 = 128`. Painting/Blockhead subclasses start at 128
  with sizes 136 / 152, matching `imageData@128 + outputImageData@132` and
  `name@128 + skinOptions@132 (20 bytes)`. The layout cross-check is asserted
  in the tool (a drifted instance size fails the run).
- **`[super init]` resolution is an evidence boundary, not a claim**: the
  call site is word-gated `objc_msgSendSuper2` with the struct's class field
  pointing at the own-class `__objc_superrefs` slot; for the root class the
  superclass word is NIL, so what the runtime dispatches to is left to a
  runtime experiment.
- **save/load asymmetry for this family** (write sets from the closed b2*
  batches + `item_savedict_keys.json`):

  | class | written | read back | write-only | read-only |
  |---|---|---|---|---|
  | CraftableItemObject | `craftableItem` | `craftableItem` | — | — |
  | PaintingCraftableItemObject | `craftableObjectType`, `imageData`, `outputImageData` | `imageData`, `outputImageData` | `craftableObjectType` | — |
  | BlockheadCraftableItemObject | `craftableObjectType`, `name`, `skinOptions` | `name`, `skinOptions` | `craftableObjectType` | `hairStyleIndex`, `headIndex`, `isMale`, `skinIndex` |

  The Blockhead row is the first **read-only key set** of the line: the
  loader accepts the four legacy scalar keys, while the current
  `getSaveDict` only ever writes the 20-byte `skinOptions` blob — the blob
  path is what this binary produces, the scalar path is a compatibility
  reader for dictionaries that lack it. `craftableObjectType` is
  write-only on both subclasses (the concrete class is chosen by type
  dispatch, not by a dictionary value).
- **Every restore is nil-guarded**: `movw r0,#0` / `cmp r1,r0` /
  `bne` with the zero-return block between the guard and the continue
  target, word-gated per class.
- **The blob lengths are literal immediates**: `movw r3,#0x7c` (124) for
  craftableItem, `movw r3,#0x14` (20) and `movw r2,#0x14` (20, memcpy) for
  skinOptions — all three gated, and each fails a mutation test.
- **Negative controls**: 11 mutations (blob length immediate, getBytes site
  register, nil-branch displacement, superref target, two ivar offsets,
  retain site, dual-source branch word, sxtb register, memcpy call, key
  cell payload) must each fail the run (`--self-test`).
- Static level-A evidence only; the packed helper 0x008112d8 body and the
  runtime roundtrip (assemble a save dict → init → compare ivars) remain
  unresolved. Next natural boundary: Action
  `initWithSaveDict:inventoryItems:` 0x00735198 (815w), CrystalManager
  `loadFromSave` 0x009f3d44 (506w), and the 43 subclasses that read their
  own keys inside `initWithWorld:dynamicWorld:saveDict:cache:` overrides.
