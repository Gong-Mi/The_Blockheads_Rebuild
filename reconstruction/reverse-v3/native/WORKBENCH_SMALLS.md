# Workbench mid/smalls closure — E79 (electricity line)

The Workbench's remaining mid and small bodies: the level-scaled malloc
array, the typed titles, the compound witness predicate, the freeblock
family and the type pin.
**10 bodies, 786 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_wbsmalls.py` (hash-gated; `--check` reproduces
the artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/workbench_smalls.json`.

## Load-bearing findings

- **The level array**: `initLevelStuff` calls `__wrap_malloc((level+1) << 2)`
  (`movw r0, 2; lsl r1, r1, 2` @0xae1ba8) and stores the pointer through the
  **fffff11c cell** — the SAME pointer that dealloc's `__wrap_free` (E77)
  releases: the workbench owns one level-scaled 4-byte-entry array.
- **The type pin**: `objectType` = **0x2d (45)** — the Workbench's
  dynamic-object type code (new pin: SteamTrain 42 / Workbench 45 / torch
  17 among the family).
- **The freeblock family**: `freeblockCreationItemType` (type-keyed →
  helper 0xafd54c), `freeBlockCreationSaveDict` (ffe264e4 forwarder),
  `freeBlockCreationDataA/B` = **0** - the workbench places with zero data.
- **The titles**: `title` (fffff130/f120 typed + helper 0xafa8b0);
  `actionTitle` and `titleForCraftProgressUI` both forward via
  ffffbcac + **ffe26678** (the shared action-title target; the latter also
  uses ffe26698).
- **The witness predicate**: `requiresPhysicalBlock` = the **ffffcacc**
  gate → fffff160 byte booleanized (`movne 1; and; strb`) else the super
  (fffbca8 + ffe26658).

## Boundaries (honest)

- uncl 10/10 resolve as PIC base anchors (clean).
- The ffe26xxx/ffe264xx chain identities stay opaque; the titlecraft
  listing region fuses its neighbor body (flagged); the level array entry
  semantics beyond the 4-byte stride stay unasserted.
