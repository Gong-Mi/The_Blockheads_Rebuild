# DynamicWorld final smalls — E42

The final smalls: the crystal sound, the free-block lookup, the light-change
overload, the active-blockhead resolver/getter and the selection setter.
**6 bodies, 380 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_finalsm.py` (hash-gated; `--check` reproduces the
artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/final_smalls.json`.

| body | imp | words | content |
|---|---|---:|---|
| playTimeCrystalReceivedSoundAtPos: | 0x008de650 | 140 | crystal sound |
| freeblockWithUniqueID: | 0x008df2a8 | 71 | free-block lookup |
| activeBlockhead | 0x008e2bac | 68 | active-blockhead resolver |
| selectedBlockheadChanged: | 0x008e2cf8 | 52 | selection setter |
| lightChangedAtMacroPos:sendReliably: (2-arg) | 0x008e1b68 | 34 | light-change overload |
| activeBlockheadIndex | 0x008e2cbc | 15 | index getter |

## Load-bearing findings

- **Slot confirmations**: **ffffe55c = the active blockhead index** (the getter
  reads it directly; the setter range-checks against the ffffe4f8 count via
  ffe23204 then stores the index or 0); **ffffe5a4** is the crystal-sound
  accumulator (the same slot E24's free-block sound bumps).
- **freeblockWithUniqueID:** — the **ffffe54c/ffffe550 +0xa8 free-block slice**
  two-registry lookup — the same +0xa8 slice E41's drawFreeBlocks walks (pair
  confirmed across batches).
- **lightChangedAtMacroPos:sendReliably:** (2-arg) — the **ffe23580** forwarder
  with the sxtb'd reliability byte + the constant 1 in the frame — the overload
  E23's 3-argument version forwards into.
- **playTimeCrystalReceivedSoundAtPos:** — the **ffffe5a4 >= 1.0 gate**
  (`vcmpe.f32`) + class ffe2af10 + the **0xfff34074 sound string** + the
  vcvt int->float position maths.
- **activeBlockhead** resolves through the ffffe4f8 collection with the
  ffffe55c index bounds-check (ffe231cc fetch; nil when out of range).

## Boundaries (honest)

- Cells pinned by cell address; the 1.0 compare and the frame constants read
  from the listing; the +0xa8 slice identity is offset-pinned; all 7 uncl
  cells resolve as PIC base anchors (clean); the fetch tails continue in the
  listings.
