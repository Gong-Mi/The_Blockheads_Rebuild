# Tree loader — executed (level-B) ARM verification, stage 1 — batch b4d

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`

Fourth executed slice and the first staged one: `-[Tree loadSaveDictValues:]`
(0x004c2df0, **748 words**) under Unicorn, stage 1 = empty `treeFruit` array.

- `reconstruction/recovered/tree_load_save_dict.{h,cpp}` — recovered contract
  (`tree_load_save_dict_stage1`), CMake target
  `blockheads_recovered_tree_stage1`.
- `tools/test_tree_load_save_dict.cpp` — CTest contract
  (`recovered_tree_load_save_dict_stage1`), CI-visible without the ELF.
- `tools/tree_load_save_dict_arm_bridge.cpp` — -O0/-O2 bridge.
- `tools/test_tree_loadsave_arm.py` — executes the original 748-word body.
- `tools/test_tree_loadsave_arm_evidence.py` — CI-safe guard.

Result (Termux, Unicorn 2.1.4): **5 cases matched** against both C++ builds.

Executed from the original binary: the four scalar chains
(`treeSeasonOffset@84` word, `dead@104` byte, `timeDied@112` 64-bit,
`removeCheckCount@120` float), `height@60` (int→word) and `age@96`
(float→vstr), the `treeFruit` fetch with the `fruitCount@128` reset, the real
`bl 0x1c2924` **memset veneer** (patched to a stub that records its arguments)
and `countByEnumeratingWithState:objects:count:` (returns 0 for the empty
array, so the record loop is skipped), then the `isStaticTree` gate at the
`bne` 0x4c3570 branch.

**Finding only execution could produce — the always-on set is larger than the
static decode assumed.** The observed message order for a static tree is:

```text
objectForKey:/intValue     treeSeasonOffset      → @84 word
objectForKey:/boolValue    dead                  → @104 byte
objectForKey:/doubleValue  timeDied              → @112 64-bit
objectForKey:/floatValue   removeCheckCount      → @120 float
objectForKey:              treeFruit             (fruitCount@128 reset, memset)
countByEnumeratingWithState:objects:count:       (empty array → 0)
objectForKey:/intValue     height                → @60 word   ← ALWAYS-ON
objectForKey:/floatValue   age                   → @96 float  ← ALWAYS-ON
isStaticTree                                     ← gate comes LAST
```

`height` and `age` are therefore always-on keys read *before* the gate; only
the remaining family (`maxHeightReached`, `growthRateGene`, `maxHeightGene`,
`maxHeight`, `growthRate`, `growthCounter`, `maxAge`) is conditional on the
gate. The harness asserts the requested key set exactly, so a mis-gated run
cannot pass; the C++ contract and the b3a-derived documentation were updated
accordingly. `saveTime` remains write-only (never read here), consistent with
b3a.

Stage 2 (next batch) adds the per-fruit records; the decode already pins the
record layout from the instruction stream: 12-byte stride, `pos.x` word at +0,
`pos.y` word at +4, `hasCreatedFreeBlockThisSeason` byte at +8, the counter
being `fruitCount@128` itself, and a preceding identity requirement (the local
helper `0x00a12f24` result compared against `self`'s 64-bit `uniqueID@40`, plus
`[self tileIsKindOfSelf:…]`).

Boundaries (unchanged): emulated original ARM with a synthetic message graph —
not Foundation, not the original-app runtime, not device gameplay; the
dictionary, boxes, array and the memset/enumeration stubs are synthetic, and
results stay outside the repository
(`~/blockheads-work/methods-save/scratch/tree-arm-differential/`). CI runs the
C++ contract test and the evidence guard only.
