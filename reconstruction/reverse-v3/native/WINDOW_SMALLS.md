# Window class + SteamTrain small accessors — E71 (electricity line)

The Window class (the glass-window dynamic object) plus the SteamTrain's
small accessors: the window lifecycle (ctors, record, draw marshalling,
removal), its constants, the train's fuel/choice accessors (including the
`dmb`-fenced flag) and the `fuelUIPos` vector math.
**22 bodies, 1185 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_winsmalls.py` (hash-gated; `--check` reproduces
the artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/window_smalls.json`.

## Load-bearing findings

- **Window constants**: `freeblockCreationItemType` reads an ivar via the
  fffff900 + class-cell pattern; the roster neighbor at 0x00c984e0 returns
  **31 = the window's item type** (the pinned window=0x1f type code);
  `initSubDerivedItems` is **empty**; `occupiesBackgroundContents` returns
  **1**.
- **Window lifecycle**: the placed ctor writes through the
  ffffc8ac/bcac/f900 cells (cache-insert callback via blx); the netData
  ctor length-checks a **0x20 (32)-byte record** (`cmp r0, 0x20; bls`);
  `creationNetDataForClient:` zero-fills/memcpys a **0x18 (24)-byte stret**
  and stores the halfword field; `setNeedsRemoved:` gates on the sxtb'd flag
  then calls **tileAtWorldPositionLoaded** + the ffe27eb8 caller - the window
  notifies its tile on removal (same family as the glow-block's light-glow
  reload).
- **Window draw**: the roster region is **pure argument-frame marshalling**
  with **16-byte frame alignment** (`bic sp, sp, 0xf`) for two by-value
  `_GLKMatrix4` structs (the types line pins the signature); no in-region
  call - the continuation sits at the roster seam (boundary flagged, not
  invented).
- **SteamTrain accessors**: `fuelItemCount` = **4**; `fuelItems` = a global
  table pointer (PIC target below the scanned window); `fuelUIPos` =
  `Vector2::Vector2(0, 4.0f)` + `operator+` over the macro position (the fuel
  UI floats 4 units above the train); `fuelCount` = the float accumulator
  (`vmul/vadd/vcvt.s32`) clamped to [0, 10]; `canDismissFuelUI` = **0**;
  `requiresFuel` = **1**; `isEngine` = **1**; `maxNumberOfRiders` = **1**;
  `setTargetVelocity:` = **empty**.
- **The dmb flag**: `setNeedsToUpdateChoiceUI:` stores under **`dmb ish`**
  barriers (the game's atomic-flag idiom), paired with `needsToUpdateChoiceUI`
  (ldrsb of the fffffcf8 cell byte).
- **setWorkbenchChoiceUIOption:** runs the four-cell chain
  (fffffce4/fcd0/fccc/fcc8) with the **inverted booleanization**
  (`cmp/movne/eor/and`) then the choice-UI refresh gate.

## Boundaries (honest)

- uncl 18/20 resolve as PIC base anchors; 2 cells (st3_fuelitemcount /
  st3_fuelitems sharing 0x00d2fdec) resolve below the scanned window
  (0xb46f80) = a shared data-section thunk target.
- The window draw continuation and the ffe2xxxx call-chain identities stay
  opaque; the roster neighbor body (0x1f returner) is annotated but not a
  separate roster target.
