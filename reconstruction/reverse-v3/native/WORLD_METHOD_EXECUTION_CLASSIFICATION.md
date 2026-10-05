# Which `World` methods can be executed under Unicorn, and which need a live runtime

Evidence grade: **A for the classification** (pure instruction inspection with an explicit rule, a
per-row call-target category, and three controls fixed by earlier execution), **B for the judgement
behind the rule** - "calls objc_msgSend" is a proxy for "the receiver's class must exist", which is
true of this family but is a proxy.

Tool: `tools/classify_world_methods.py` (+ the generated `world_method_classification.{json,tsv}`).

## Why this exists

The three getters already executed - `worldTime`, `fastForward`, `doubleTimeUnlocked` - were picked by
a rule that lived in a chat message. The rule is now a tool, so the rest of the world/main-domain
bucket stops depending on whoever is at the keyboard.

## The rule

| condition in the body | verdict |
|---|---|
| calls `objc_msgSend` (`0x1c281c`) or an unidentified target | **needs-runtime** - the receiver's class must exist to drive it live |
| calls only the copy family (0x1c2888, 0x1c2924, 0x1c2948) or uses any VFP instruction | **unicorn-with-abstraction** - something must be supplied or skipped, stated per row |
| no call outside the method table, no VFP | **unicorn-clean** - runs as-is with a fabricated receiver |

## Result over every `World` instance method

| verdict | methods |
|---|---:|
| **unicorn-clean** | **81** |
| unicorn-with-abstraction | 13 |
| needs-runtime | 259 |
| total | 353 |

So the execution route covers **94 of 353** world methods (26.6%), and the other 259 are declared live-only rather than left ambiguous.

Controls: the tool refuses to report unless the three already-executed methods land on their known
verdicts (`worldTime` = unicorn-with-abstraction, `fastForward` and `doubleTimeUnlocked` =
unicorn-clean). A rule change that moves them fails the run.

## Sample of the clean set (the next work list)

- `startPinchOrPan` (152 B, 35 insns)
- `translation` (72 B, 17 insns)
- `isSimulating` (60 B, 14 insns)
- `distanceOrderedFoodTypes` (60 B, 14 insns)
- `stopFollowingOrTranslatingToGoal` (96 B, 22 insns)
- `highestPoint` (72 B, 17 insns)
- `tutorialActive` (84 B, 20 insns)
- `pvpEnabled` (60 B, 13 insns)
- `welcomeMessage` (60 B, 14 insns)
- `serverPassword` (60 B, 14 insns)
- `clientPassword` (60 B, 14 insns)
- `serverPrivacySetting` (60 B, 14 insns)

Rows carrying an abstraction, i.e. the ones that need one stated decision each:

- `simulationProgress` (64 B, VFP=True, categories=[])
- `resetPauseIdleTimer` (80 B, VFP=True, categories=[])
- `worldTime` (100 B, VFP=True, categories=['copy-stub'])
- `sunDirection` (96 B, VFP=False, categories=['copy-stub'])
- `timeOfDayFraction` (72 B, VFP=True, categories=[])
- `weatherFraction` (72 B, VFP=True, categories=[])
- `rainFraction` (72 B, VFP=True, categories=[])
- `rainFractionNotIncludingSnow` (72 B, VFP=True, categories=[])
- `dayColor` (96 B, VFP=False, categories=['copy-stub'])
- `startPortalPos` (96 B, VFP=False, categories=['copy-stub'])

## Boundary

- "unicorn-clean" means the body needs no runtime object, not that the method is interesting: most of
  the 81 are trivial accessors.
- The rule uses `objc_msgSend` as a proxy for "needs a live object graph"; a method that calls a
  *local* method which itself calls msgSend is still classified clean. The classification is therefore
  an upper bound on what runs standalone, and each executed method is verified on its own anyway.
- Nothing here is executed in this batch: the verdicts are computed, and the three executed methods
  were executed by `emulate_worldtime_getter.py` with their own controls.
