# Minimal reassembling overrides — batch 2b (Bed, TrainStation, CraftableItemObject)

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`
Recovery: `tools/recover_item_savedict_keys.py` → `item_savedict_keys.json`.
Annotated listings: `disasm_bed_getsavedict.txt` (112w),
`disasm_trainstation_getsavedict.txt` (68w),
`disasm_craftableitemobject_getsavedict.txt` (78w).

```text
Bed           [super getSaveDict] + numberWithInt: itemType @100 (0x00d411c8 -> 0x00d411ec)
                                        numberWithInt: beddingColor @104 (0x00d41228 -> 0x00d4124c)
TrainStation  [super getSaveDict] + direct NSString object  text @128 (set 0x00b39560)
CraftableItemObject  NO super:  [NSMutableDictionary dictionary] (0x00ac7af4)
                   + [NSData dataWithBytes:self+4 length:0x7c] (0x00ac7b34) -> craftableItem (0x00ac7b58)
```

Notable facts:

- Bed key ORDER comes from the forward simulator, not the literal-pool
  order in the listing: itemType is boxed and set FIRST (0x00d411c8/1ec),
  beddingColor second (0x00d41228/24c), while the pool cells appear in the
  opposite order. Pool position is not execution order.
- TrainStation writes its `text` NSString without NSNumber boxing
  (`direct_object`), like NPC's name/tamedClientID keys.
- CraftableItemObject does NOT inherit the parent dictionary at all: it
  makes a fresh one and serialises the object's own 124-byte POD
  (`movw r5,#0x7c` @0x00ac7a84, raw-word gated) starting at
  `CraftableItemObject.craftableItem` @4 as an NSData blob under
  `craftableItem`. This is save-format evidence: craftable item state is a
  fixed-size inline struct, not a field-by-field dictionary.
- super identity (Bed/TrainStation): the classref slot materialises the
  class's OWN struct (name walk `word(class+0x10)` ro, `word(ro+0x10)`
  cstr == class), which is exactly ARM32 objc_msgSendSuper2 semantics.

Static level-A only; read-back for these keys, remaining 40 overrides, and
save/roundtrip behavior unresolved.
