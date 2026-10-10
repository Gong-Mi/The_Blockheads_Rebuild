# Snow surface + ice melt (E118)

The snow-surface + ice-melt line opens: SnowSurfaceBlock (19 bodies), the Column/Stairs melt pair and the two DynamicWorld snow hooks. 25 bodies, 44419 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| hd_00 | Blockhead -[asleep] | 0x00c7af40 | 34 | 0 | 0 | 1 | 0 | 0 | 1 |
| hd_01 | Blockhead -[canEat] | 0x00bb564c | 61 | 0 | 0 | 1 | 0 | 0 | 3 |
| hd_02 | Blockhead -[canMeditate] | 0x00bb51c0 | 291 | 1 | 1 | 10 | 0 | 5 | 19 |
| hd_03 | Blockhead -[canSleepOnSpot] | 0x00bb4cfc | 305 | 1 | 1 | 10 | 0 | 5 | 20 |
| hd_04 | Blockhead -[death] | 0x00b8c850 | 16 | 0 | 0 | 1 | 0 | 0 | 0 |
| hd_05 | Blockhead -[die] | 0x00bb5740 | 798 | 18 | 3 | 15 | 1 | 38 | 46 |
| hd_06 | Blockhead -[dieForGood] | 0x00c82a88 | 258 | 8 | 2 | 5 | 1 | 12 | 3 |
| hd_07 | Blockhead -[drownFraction] | 0x00b8caf8 | 16 | 0 | 0 | 1 | 0 | 0 | 0 |
| hd_08 | Blockhead -[energy] | 0x00b8c910 | 42 | 0 | 0 | 1 | 0 | 0 | 2 |
| hd_09 | Blockhead -[fullness] | 0x00b8c8d0 | 16 | 0 | 0 | 1 | 0 | 0 | 0 |
| hd_10 | Blockhead -[happiness] | 0x00b8c890 | 16 | 0 | 0 | 1 | 0 | 0 | 0 |
| hd_11 | Blockhead -[health] | 0x00b8c810 | 16 | 0 | 0 | 1 | 0 | 0 | 0 |
| hd_12 | Blockhead -[hasCoffeeEnergy] | 0x00b8cb38 | 22 | 0 | 0 | 1 | 0 | 0 | 0 |
| hd_13 | Blockhead -[hungerPaused] | 0x00c82104 | 38 | 0 | 0 | 2 | 0 | 0 | 1 |
| hd_14 | Blockhead -[meditating] | 0x00c7afc8 | 20 | 0 | 0 | 1 | 0 | 0 | 0 |
| hd_15 | Blockhead -[meditationProgress] | 0x00b8c9b8 | 16 | 0 | 0 | 1 | 0 | 0 | 0 |
| hd_16 | Blockhead -[meditateIfPossible] | 0x00bb6e68 | 123 | 7 | 1 | 4 | 0 | 7 | 3 |
| hd_17 | Blockhead -[sleepOnSpotIfPossible] | 0x00bb6b48 | 200 | 10 | 3 | 6 | 1 | 13 | 5 |
| hd_18 | Blockhead -[sleepOnSpotIfPossibleOtherwiseCancelActions] | 0x00bb7054 | 48 | 3 | 1 | 0 | 0 | 3 | 2 |
| hd_19 | Blockhead -[sleepRushed] | 0x00c7b15c | 95 | 2 | 1 | 2 | 0 | 3 | 6 |
| hd_20 | Blockhead -[wakeUp] | 0x00c7b054 | 19 | 1 | 1 | 0 | 0 | 1 | 0 |
| hd_21 | Blockhead -[sufferDamage:isSimulation:recoil:] | 0x00bec89c | 1092 | 12 | 5 | 15 | 1 | 36 | 100 |
| hd_22 | Blockhead -[willDieIfHitByForce:] | 0x00c82a2c | 8 | 0 | 0 | 0 | 0 | 0 | 0 |
| hd_23 | Blockhead -[needsHarmFlash] | 0x00c8a3c0 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| hd_24 | Blockhead -[setNeedsHarmFlash:] | 0x00c8a3fc | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| hd_25 | Blockhead -[regenerateRushed] | 0x00c7b2d8 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| hd_26 | Blockhead -[regenerating] | 0x00c7b018 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| hd_27 | Blockhead -[regenerationProgress] | 0x00b8cb90 | 16 | 0 | 0 | 1 | 0 | 0 | 0 |
| hd_28 | Blockhead -[doubleTimeUnlocked] | 0x00c81cd8 | 51 | 1 | 1 | 3 | 0 | 1 | 2 |
| hd_29 | Blockhead -[canFly] | 0x00c82f18 | 43 | 1 | 1 | 1 | 0 | 1 | 1 |
| hd_30 | Blockhead -[canCrawl] | 0x00c820e8 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| hd_31 | Blockhead -[canCollapse] | 0x00bb47d0 | 331 | 0 | 0 | 7 | 0 | 3 | 25 |
| hd_32 | Blockhead -[collapseIfPossible] | 0x00bb63b8 | 484 | 16 | 5 | 10 | 1 | 20 | 20 |
| hd_33 | Blockhead -[cancelSimulateDueToCollapse] | 0x00c8a588 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| hd_34 | Blockhead -[shouldContinueSimulating] | 0x00bb8fe0 | 114 | 4 | 1 | 2 | 0 | 4 | 8 |
| hd_35 | Blockhead -[crouching] | 0x00c79510 | 34 | 0 | 0 | 1 | 0 | 0 | 1 |
| hd_36 | Blockhead -[falling] | 0x00c7b0a0 | 47 | 1 | 1 | 2 | 0 | 1 | 1 |
| hd_37 | Blockhead -[isDoubleHeight] | 0x00c87bc8 | 8 | 0 | 0 | 0 | 0 | 0 | 0 |
| hd_38 | Blockhead -[isIdle] | 0x00bb8e54 | 84 | 4 | 1 | 1 | 0 | 4 | 6 |
| hd_39 | Blockhead -[idle] | 0x00c7adbc | 97 | 3 | 1 | 3 | 0 | 3 | 4 |
| hd_40 | Blockhead -[moving] | 0x00c86934 | 108 | 3 | 1 | 2 | 0 | 3 | 4 |
| hd_41 | Blockhead -[currentAnimationType] | 0x00b8cbd0 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| hd_42 | Blockhead -[isVisible] | 0x00c828c4 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| hd_43 | Blockhead -[isMale] | 0x00c86548 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| hd_44 | Blockhead -[isRunByAI] | 0x00c80de0 | 21 | 0 | 0 | 1 | 0 | 0 | 0 |
| hd_45 | Blockhead -[isAddingFuelToAnyWorkbench] | 0x00bac054 | 20 | 0 | 0 | 1 | 0 | 0 | 0 |
| hd_46 | Blockhead -[isCraftingAtAnyWorkbench] | 0x00bac004 | 20 | 0 | 0 | 1 | 0 | 0 | 0 |
| hd_47 | Blockhead -[isInteractingWithAnyInteractionObject] | 0x00bac624 | 20 | 0 | 0 | 1 | 0 | 0 | 0 |
| hd_48 | Blockhead -[isClientBlockheadBeingControlledByServer] | 0x00c8a4c0 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| hd_49 | Blockhead -[setIsClientBlockheadBeingControlledByServer:] | 0x00c8a4fc | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| hd_50 | Blockhead -[mostCommonFoodTypeIndex] | 0x00c69920 | 468 | 6 | 1 | 1 | 0 | 26 | 24 |
| hd_51 | Blockhead -[canUseDynamicObject:] | 0x00c7c4a8 | 82 | 3 | 1 | 1 | 1 | 3 | 4 |
| hd_52 | Blockhead -[currentTipText] | 0x00c805c0 | 224 | 5 | 5 | 3 | 2 | 8 | 16 |
| hd_53 | Blockhead -[tipType] | 0x00c8a5c4 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| hd_54 | Blockhead -[setTipType:] | 0x00c8a600 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| hd_55 | Blockhead -[updateNameTextView] | 0x00c82e90 | 34 | 1 | 1 | 1 | 0 | 1 | 0 |
| hd_56 | Blockhead -[name] | 0x00c8a090 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| hd_57 | Blockhead -[changeName:] | 0x00c86584 | 149 | 6 | 1 | 4 | 0 | 8 | 2 |
| hd_58 | Blockhead -[titleForCraftProgressUI] | 0x00c87b8c | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| hd_59 | Blockhead -[unableToWorkReason] | 0x00c87a60 | 75 | 3 | 1 | 0 | 0 | 3 | 6 |
| hd_60 | Blockhead -[update:accurateDT:isSimulation:] | 0x00bb9238 | 37886 | 329 | 106 | 313 | 29 | 1056 | 1771 |
| hd_61 | Blockhead -[.cxx_construct] | 0x00c8a768 | 194 | 0 | 0 | 16 | 0 | 15 | 0 |
| hd_62 | Blockhead -[.cxx_destruct] | 0x00c8a6e8 | 32 | 0 | 0 | 1 | 0 | 2 | 0 |

## Findings (E124)

- **Blockhead's first slice lands**: 63 bodies / 44,419 words of the central class
  (261 methods total; 246 were untouched before this batch). Life, state, gates,
  the tips/name surface - and the master tick.
- **The master tick**: `update:accurateDT:isSimulation:` = **37,886 words /
  1,810 branches / 1,010 call sites / 71 callees** (85% of the batch) - the
  per-frame spine: 285 message dispatches + 183 fn-ptr calls, 51 memsets,
  32 idivs, 27 sinf; it drives the just-audited movement chain (checkCanEnterTile,
  dpadFindPath, clearLineOfSightBetweenTiles 1x each; tileAtWorldPositionLoaded
  14x) with its Vector2 math (24 conversions) in a ~13KB stack frame.
  Census-grade.
- **The ivar map** (decoded through the offset cells): life floats [0x20 health,
  0x24 happiness, 0x28 fullness, 0x2c energy, 0x30 meditationProgress, 0x34
  drownFraction, 0x54 coffeeEnergy, 0x58 hungerPause, 0x5c death, 0x64
  regenerationProgress]; the action enum [0x50] (5 = sleeping, 7 = meditating);
  the animation type [0x4c] (0x17 = crouching); the interaction enum [0x4]
  (4 = crafting, 5 = using, 13 = adding fuel); the state bytes [0x60 ...].
- **The gates**: canEat (hunger threshold), canFly == 0x116 (the flight item),
  the collapse / sleep / meditate tile-probe trio (tileAtWorldPositionLoaded x2 +
  tileIsSolid + the dispatched queries), canCollapse, the damage/death pipeline
  (sufferDamage early-out for force < 0, die writes [0x5c] = 1.0f, dieForGood),
  mostCommonFoodTypeIndex (the 32-slot intpair scan) and the tip/name surface.

## Boundaries

- update tick / die / dieForGood / sufferDamage / collapseIfPossible /
  mostCommonFoodTypeIndex / currentTipText / updateNameTextView / changeName /
  unableToWorkReason are census(-lite); the full branch trees are in the listings.
- willDieIfHitByForce: / canCrawl / isDoubleHeight are trivial constant gates
  (8-7 words).
