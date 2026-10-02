# Mid-size initWithWorld loaders with own save keys (batch b3j)

Scope: five `initWithWorld:…` implementations in the 102–134 word range of
`libApplication.so` (sha256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

    AppleTree    0x009bd3b0 (102w, long variant)   super = Tree
    TrainStation 0x00b38f88 (105w, exact variant)  super = InteractionObject
    Plant        0x009559d0 (114w, long variant)    super = DynamicObject
    GatherBlock  0x008695a0 (128w, exact variant)  super = DynamicObject
    Yak          0x0095dae4 (134w, exact variant)   super = DonkeyLike

583 words total. Evidence level: **static (level-A)**, word-gated.

## Finding: forward-then-READ shape (not pure forwarders)

All five forward to super first (`objc_msgSendSuper2`, own-class superref,
nil guard → nil), then **read their own save keys directly** (4 of 5) — this
batch closes the first own-key read sites of the selector front:

```text
AppleTree    availableFood  → floatValue     → AppleTree.availableFood
TrainStation text           → (retain)       → TrainStation.text
             then [self initSubDerivedItems] (side effect, result discarded)
GatherBlock  lastKnownGatherValue → floatValue → float→uint→float round
             trip (vcvt.u32.f32 + vcvt.f32.u32 = (float)(uint)v) →
             GatherBlock.lastKnownGatherValue
             timer → intValue → GatherBlock.timer
Yak          hair → floatValue → Yak.hair
             milk → floatValue → Yak.milk
             then [self updateTextures] (side effect)
Plant        NO key — stores the two noise-function ARGS into
             Plant.seasonOffsetNoiseFunction / Plant.treeDensityNoiseFunction,
             reads DynamicObject.pos/dynamicWorld through slots, then calls
             [self loadSaveDictValues:] — save-dict reading is DELEGATED to
             the b3a-covered method — plus
             [dynamicWorld dynamicWorldChangedAtPos:objectType:]
```

Key/ivar pairing is proven by literal-pool decode: each key CFString, its
conversion selector, and its target OBJC_IVAR slot all appear as gated
literal cells in the same body, and the CFString-pool sets are exact-gated
(positive set + corrupted-key negative control).

## Structural discoveries

1. **Plant is a 6-arg long-variant method that forwards only the 4-arg
   exact selector to super** — it swallows the two noise-function args into
   its own ivars instead of passing them on. The forwarded selector may
   differ from the method's own selector; a loader-front gate must not
   assume they match.
2. Runtime superclasses: TrainStation hangs off **InteractionObject**,
   Yak off **DonkeyLike** (a b3h forwarder class — its loader chain is
   DonkeyLike → DynamicObject), Plant/AppleTree confirm the Tree and
   DynamicObject fronts.
3. Two new post-init hook names appear on this front: `initSubDerivedItems`
   (TrainStation, known from b3h) and **`updateTextures`** (Yak — new).
4. GatherBlock's value pipeline contains an explicit float→uint→float
   round trip — quantization of the loaded gather value, decoded from the
   `vcvt` pair.

## Census after b3j

```text
selector front covered: 25 methods (b3f 5 + b3g NPC + b3h 5 + b3i 9 + b3j 5)
remaining: 18 methods / 9,051 words
largest: Workbench 1,390w, FreeBlock 1,347w, Chest 760w
```

## Negative controls

6/6 mutations detected at the correct site: per-class word gates
(AppleTree w45 super call, TrainStation w44 nil guard, Plant w56 ivar
store, GatherBlock w87 vcvt, Yak w95 vstr) + the key-set control
(corrupting the availableFood CFString's data pointer → key-set drift).

## Artifacts

- `tools/recover_midsize5_initwithworld.py` — recovery tool
  (`--check` / `--self-test`).
- `reconstruction/reverse-v3/native/midsize5_initwithworld.json` — gated
  evidence with per-class own_keys / own_key_ivar_pairs.
- `tools/test_midsize5_initwithworld_evidence.py` — dual-mode guard.
- This document.
