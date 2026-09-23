# Tree -[loadSaveDictValues:] read-back evidence — batch b3a

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`
Recovery: `tools/recover_tree_loadsavedictvalues.py` →
`tree_loadsavedictvalues.json`. Listing:
`disasm_tree_loadsavedictvalues.txt` (748w).

```text
Tree -[loadSaveDictValues:] 0x004c2df0
  treeSeasonOffset@84   objectForKey → intValue → WORD store
  dead@104              objectForKey → boolValue → BYTE store
  timeDied@112          objectForKey → doubleValue → vstr d0 (64-bit)
  removeCheckCount@120  objectForKey → floatValue → vstr s2
  treeFruit             objectForKey → fruitCount@128 reset to 0 →
                        enumerate array → per-fruit dictionaries
                        (pos.x / pos.y / hasCreatedFreeBlockThisSeason)
                        reconstructed into treeFruits@124 C-array with
                        12-BYTE record stride
  isStaticTree gate     sxtb/cmp/bne → skip gene/growth block for
                        static trees (mirrors save-side b2o gate)
```

Facts:

- **saveTime is NOT read back** — the first proven save/load key
  asymmetry: Tree's getSaveDict writes the world-clock double
  `saveTime`, but `loadSaveDictValues:` contains no `saveTime` key
  anywhere in its literal pool (verified by a negative scan over all
  PC-relative CFString cells in the method body). It is a write-only
  stamp.
- **The isStaticTree gate is symmetric**: the load side re-derives the
  conditional key set with the same selector — static trees load only
  the always-on keys, exactly matching the save-side conditional from
  b2o.
- **The fruit records are 12-byte structs** (`movw #0xc` stride +
  `mul`), reconstructed from the same three per-fruit keys the save
  side wrote (pos.x word, pos.y word, hasCreatedFreeBlockThisSeason
  byte) — a full structural roundtrip of the treeFruit array.
- fruitCount@128 is RESET TO 0 before reconstruction (store
  @0x4c3074) — the load is destructive-resetting, not appending.
- Conversion fidelity: timeDied restores through `doubleValue` into a
  64-bit `vstr d0` (matching the save-side `vldr d0` +
  numberWithDouble), dead through `boolValue` into a byte store
  (matching ldrb+sxtb on save).

Static level-A only; runtime roundtrip (assemble a save dict, load it
back, compare ivars) unresolved.
