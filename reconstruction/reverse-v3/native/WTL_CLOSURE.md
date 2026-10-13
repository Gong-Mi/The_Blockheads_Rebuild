# WorldTileLoader closure set — dealloc, .cxx_construct and the accessor surface (E18)

Batch E18 closes the WorldTileLoader line: after the write/send (E14), migrate (E15),
load (E16) and construct (E17) batches, this set covers the class's teardown and its
accessor surface. **16 bodies, 736 verified words**, from the pinned original
`libApplication.so` (1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_wtl_closure.py` (hash-gated; every instruction word
re-verified from the pinned ELF; `--check` reproduces the artifact byte for byte).
Artifact: `reconstruction/reverse-v3/native/wtl_closure.json`.

## Bodies

| body | imp | words | content |
|---|---|---:|---|
| dealloc | 0x00854770 | 298 | 15 objc_msgSend(release) dispatches, six `__wrap_free` C-buffer frees, `objc_msgSendSuper2(super, dealloc)` |
| .cxx_construct | 0x00868fd8 | 6 | no-op stub (returns self; no C++ subobjects) |
| distanceOrderedFoodTypes | 0x00865074 | 15 | atomic getter (`dmb ish`) |
| randomSeed | 0x00868c40 | 15 | atomic getter |
| bestStartPosition | 0x00868c7c | 24 | `objc_copyStruct` struct getter ({int,int}, size 8, atomic 1) |
| treeDensityNoiseFunction | 0x00868cdc | 85 | atomic getter (exidx range shared down to 0x00868e30; body itself is the first 14 words) |
| seasonOffsetNoiseFunction | 0x00868d20 | 68 | atomic getter (shared exidx suffix) |
| treePositions | 0x00868d64 | 51 | atomic getter, raw pointer (shared exidx suffix) |
| npcPositions | 0x00868da8 | 34 | atomic getter, raw pointer (shared exidx suffix) |
| plantPositions | 0x00868dec | 17 | atomic getter, raw pointer |
| highestPoint | 0x00868e30 | 24 | `objc_copyStruct` struct getter ({int,int}, size 8, atomic 1) |
| needsToExit | 0x00868e90 | 15 | plain `ldrsb` getter (char) |
| setNeedsToExit: | 0x00868ecc | 17 | char setter with `dmb ish` before and after the store |
| xFrequencyMultiplier | 0x00868f10 | 15 | atomic getter (float via vmov r0, s0) |
| yHeightDivider | 0x00868f4c | 35 | atomic getter (float via vmov r0, s0; shared exidx suffix) |
| lightBlockDatabase | 0x00868f94 | 17 | atomic getter |

(Word counts are the artifact's `verified_words`; the first five accessors share one
exidx end 0x00868e30, so their spec ranges nest - each range is re-verified against the
pinned ELF in full, and the shared tail rows are the following accessors' prologues.)

## Load-bearing findings

- **dealloc** resolves all 21 ivar cells: 13 release dispatches through the release
  selector cell 0x00854bbc (blockDirectory first, then the twelve noise functions:
  heightNoiseFunctionA/B, fault, treeDensity, rockType, flintDensity, tinDensity, sand,
  seasonOffset, caveNoiseFunctionA/B, gemNoiseFunction), the two
  lightBlockDatabase/lightBlockDatabaseEnvironment releases in the tail, and **six
  `__wrap_free` calls** on treePositions, npcPositions, plantPositions, dirtHeights,
  rockHeights and lakeHeights — the three height arrays and the three position arrays
  are raw C buffers, not Objective-C collections.
- The super-call is `objc_msgSendSuper2({self, class}, @selector(dealloc))` with the
  classref cell 0x00854bb4 (OBJC_CLASS_$_WorldTileLoader) — the import cell 0x00854bac
  and selector cell 0x00854bb0 are both pinned.
- **.cxx_construct** is a no-op stub: the class constructs no C++ subobjects.
- The accessor surface is uniform: **atomic getters** with a `dmb ish` before the load
  (eight of them object/pointer-typed), two **objc_copyStruct struct getters**
  (bestStartPosition, highestPoint — both {int,int}, atomic=1, hasStrong=0), one plain
  `ldrsb` getter (needsToExit, no barrier) and one barrier-bracketed char setter
  (setNeedsToExit:). The float getters (xFrequencyMultiplier, yHeightDivider) return
  through vmov r0, s0.
- Accessor offsets come from the ivar cells and match the E17 constructor's writer
  side (randomSeed, bestStartPosition, positions, height scale pair, lightBlockDatabase).

## Boundaries (honest)

- Struct field meanings for bestStartPosition/highestPoint are named in the E16/E17
  batches (writer side), not here.
- The reference-counting semantics behind the objc_msgSend(release) dispatches are the
  runtime's; this batch pins the call graph, not ARC bookkeeping.
- Readers/writers of the six freed buffers outside this class are covered by their own
  batches; the frees here only pin the buffer identity.
