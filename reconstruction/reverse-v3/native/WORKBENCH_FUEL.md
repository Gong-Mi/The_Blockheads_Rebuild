# Workbench fuel/craft-status cluster — E76 (electricity line)

The Workbench's fuel and crafting-status machinery: the furnace's 100-unit
fuel cap, the fuel manager handover, the hurry-up chain, the 124-byte
crafting record and the status predicates.
**16 bodies, 1684 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_wbfuel.py` (hash-gated; `--check` reproduces
the artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/workbench_fuel.json`.

| body | imp | words | content |
|---|---|---:|---|
| wf_updatehasfuel | 0x00aedb58 | 428 | fuel-state refresh + cancel chain |
| wf_hurry | 0x00aed558 | 384 | hurryCompletion: |
| wf_addfuel | 0x00afdf94 | 226 | addToFuel: (cap 100) |
| wf_startfuel | 0x00afc87c | 160 | fuel manager handover |
| wf_totalleft | 0x00aed318 | 144 | items left |
| wf_crafttype | 0x00aed44c | 67 | crafting item type (0x7c record) |
| wf_hasreqfuel | 0x00afe31c | 60 | required-fuel predicate |
| wf_fuelcount | 0x00afdec4 | 52 | count clamped [0,10] |
| wf_addfuelitem | 0x00b019c0 | 49 | per-item fuel add |
| wf_fuelitems | 0x00b01894 | 25 | items table |
| wf_fuelitemcount | 0x00b0179c | 25 | count |
| wf_doubleheight | 0x00afe40c | 19 | double-height delegate |
| wf_frac | 0x00afe63c | 16 | u16 craft progress |
| wf_reqhuman | 0x00afcafc | 15 | needs operator flag |
| wf_candismiss | 0x00b02134 | 7 | = 1 |
| wf_iobjtype | 0x00ae9b5c | 7 | = 1 |

## Load-bearing findings

- **The furnace fuel cap**: `addToFuel:` type **0xf (15)** reads the **u16
  counter (`ldrh` fffff150)** and gates at **`0x64` (100)** (`cmp r0, 0x64;
  bge`), then **`add`/`strh`** writes the units back. The cell is the SAME
  u16 store as the electricity charge (E75) - per-type semantics: furnace
  fuel cap 100 vs battery charge 8192 vs TrainTrain fuel.
- **The fraction**: `addToFuel:` runs `fuel += amount x multiplier`
  (`vcvt.f32.s32; vmul.f32; vadd.f32`); `fuelCount` mirrors the SteamTrain's
  accumulator clamped to **[0, 10]** (the `movw r3, 0xa` + the 0x7d70a4
  pool); `fractionComplete` reads the **u16 fffff1a0** craft progress.
- **The fuel manager**: `startManagingFuelWithBlockhead:` gates on the
  **fffff160 flag** + the **fffff190 owner compare** (same blockhead exits)
  then sets the manager (ffe26644 notify).
- **The cancel chain**: `updateHasFuel` gates on fffff144 + the **fffff14c
  float threshold** (`vcmpe; bpl`) and on empty runs the ffffcacc-gated
  ffe26428/2c/34 trio with the `cmp r0, 3` arm - the crafting cancel.
- **The hurry**: `hurryCompletion:` gates on **fffff168**, sets the busy
  flag + the fffff170/16c/164 state, and runs the time interpolation
  (`vcvt/vdiv/vsub/vmul` over the fff3c1a4 record) with Vector position math
  - the time-crystal spend.
- **The crafting record**: `currentlyCraftingItemType` nil-fills a **0x7c
  (124)-byte record** (`movw r2, 0x7c`); `totalItemsLeftToCraft` uses the
  same stret machinery.
- **The predicates**: `hasRequiredFuel` = fffff144 OR (u16 units > 0) OR the
  **negated** fffff12c flag (`eor r0, r0, 1`); `canDismissFuelUI` = **1**
  (contrast the SteamTrain's 0); `interactionObjectType` = **1**;
  `requiresHumanInteraction` = the fffff160 flag; `isDoubleHeight` = the
  type-class helper 0xafe458.

## Boundaries (honest)

- uncl 22/22 resolve as PIC base anchors (clean).
- The ffe26xxx/ffe265xx call-chain identities stay opaque; the workbench
  type names (0xf etc.) stay codes; the hurry interpolation's exact
  constants read from the listing registers.
