# WorldTileLoader world constructor — initWithWorld:randomSeed:isNewWorld:saveID:loadedVersion:blockDatabase: (E17)

Batch E17 of the WorldTileLoader storage/generation recovery. The largest single
body in the binary: **10857 instruction words** at `0x00849728`–`0x008540cc`
(ARM.exidx end; next ObjC IMP `0x0085475c` `-[WorldTileLoader compressBlocks]`),
from the pinned original `libApplication.so` (1.7.6, armeabi-v7a,
SHA-256 `733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_wtl_initwithworld.py` (hash-gated; every instruction
word re-verified from the pinned ELF; `--check` reproduces the artifact byte for
byte). Machine spec tables + hand-written semantics; the JSON artifact is
`reconstruction/reverse-v3/native/wtl_initwithworld.json`.

## What it is

This is the world constructor: it stores its six arguments (world, randomSeed,
isNewWorld, saveID, loadedVersion, blockDatabase), resolves the block-storage
location from the Documents search paths, normalises the world size to **0x200**,
allocates the per-column arrays, builds the whole noise-function set from the
save seed, runs the per-column tree/plant candidate pass that stamps the type
array and accumulates spawn-distance bids, and closes in a **seed-retry loop**
with the bestStartPosition search, a statistics NSLog and the final
world-registration dispatch. It returns self (or 0 when the opening dispatch
fails), with a stack-protector check at the epilogue.

## Control skeleton (address-ordered)

| region | addresses | content |
|---|---|---|
| opening + arg spills | 0x00849728–0x008498a8 | frame ~0x1e50; first GOT-stub dispatch with an out struct; `== 0` → return 0; arg stores through ivar slots |
| size normalisation | 0x008498ac–0x008499a0 | sample float; `> 0x200` → ÷2 loop (counter++, field ×2.0); `< 0x200` → ×2 loop (counter−−); normalised to 0x200 |
| arrays + paths | 0x008499a4–0x00849b90 | three `__wrap_calloc(n<<5, 4)` arrays = rockHeights/dirtHeights/lakeHeights; NSSearchPathForDirectoriesInDomains(0xe,1,1) → block-storage location (blockDirectory/blockDatabase ivars follow) |
| saved-state pass | 0x00849fc8–0x0084a518 | per item: `== 32` check, {int,int} fetch vs literal **0x7fffffff** sentinel, NSLog, multi-arg dispatch; do/while re-entry with arg 0x10 |
| loop head | 0x0084a540 | `[fp,-0xab5] == 1` → FINAL path (0x00853f98); else phases below |
| option probes | 0x0084a560–0x0084a6a4 | customRules byte **+0xc == 2** → [fp,-0xb5c]=2; worldWidthMacro vs 0x200 (small worlds → 0x0084d9f0) |
| noise construction groups | 0x0084a6ac–0x0084a814; 0x0084b000–0x0084b368; 0x0084d420–0x0084d818 | seed + sub-seed offsets (+9/+8/+0x49/+6/+3/+0xc/+7/+4/+0xa/+5) → slot dispatches → ivar slots; ivar cells resolve to the full noise family: heightNoiseFunctionA/B, caveNoiseFunctionA/B, fault/rockType/sand/gem/flintDensity/tinDensity/treeDensity/seasonOffsetNoiseFunction |
| height arrays + scale | 0x0084b36c–0x0084b5cc | two more `calloc(n<<5,4)` floats; memset `(n<<5)<<1`; min/max scan → **xFrequencyMultiplier/yHeightDivider** fields (+0x324/+0x328 of the parameter block); customRules byte +2 == 4 / byte +0xb == 0 force 1.0 |
| param floats | 0x0084e264–0x0084e508 | +0x204/+0x200 defaults + customRules byte +0xa ∈ {1,3,5} overrides (season-related; seasonOffsetNoiseFunction established here) |
| spawn streak search | 0x0084bcdc–0x0084cf00 | two-array column scan; lrand48/2³¹ vs customRules byte +0xd threshold (== 2 → 5.0); streak machine updates best at 0x0084c604 |
| sentinel + retry | 0x0084d000–0x0084d3d0 | stored value **== −1** → NSLog + increment + `bl 0x008540dc` (reseeder) + flag=1; flag==0 → six position/food collections (treePositions/plantPositions/npcPositions families) read-dispatch-store; customRules byte +0x10 probes |
| column candidate loop | 0x0084e510–0x008532a8 | idx 2 … (n<<5)−1; **quarter-column** indices (n<<5)/4 and ×3 → 0x0085328c; height-array pre-gates; per-column max → makeIntpair |
| tree candidacy ×9 | 0x0084ed20 (t1), 0x0084eff8 (t3), 0x0084f29c (t2), 0x0084f56c (t7), 0x0084f864 (t8), 0x0084fb58 (t9), 0x008500b8 (t6), 0x0085015c (t4), 0x0085202c (t1) | p = noise/(n<<5)+d1+params[0x204]; ×(growthVigorForTreeTypeAtPos − C); lrand48 < p² → type array write + distance bid (0x008540fc; <0x3e8 → accumulate 0x3e8−dist) |
| plant candidacy ×10 | 0x00850890 (p1), 0x00850b20 (p2), 0x00850e08 (p9), 0x00851098 (var), 0x0085139c (p4), 0x008516dc (p3), 0x008519a0 (p8), 0x00851c40 (p5), 0x00852724 (p4), 0x00852ac8 (p9) | same shape; plant vigor; ×8/×4/×2 scales; index transforms ++0x3e8/0x7d0/0x98d/0x164/0xbb8/0x4ba/0x1d4c/0xc23; second family adds neighbor flatness gates ([idx±1] diffs < 2) |
| best position | 0x008532b0–0x008534c8 | max-pair callback acceptance → **bestStartPosition** record (`[+4]=level`, `[*]=idx`) |
| new-world tail | 0x008534d8–0x00853f10 | 32 bid counters → positive count + sum; NSLog; customRules cascade (bytes +2/+0xa) — any hit ends the pass at 0x00853f14; `count ≥ 6 && sum ≥ 0x2710` also ends; NSLog; world-registration dispatch (0x00853c2c, ~18 args); 12-slot sweep; counter++ + `bl 0x008540dc` reseed; → loop head |
| sorted table | 0x00853f14–0x00853f90 | `quickSort(float*, 0x1f, uint*)` then reverse-order write into **distanceOrderedFoodTypes** |
| final path | 0x00853f98–0x00854028 | slot dispatch (classref included) → move self to return slot → stack-guard check → epilogue `pop {r4-r8,sl,fp,pc}` |

## Load-bearing findings

- The three W1 calloc arrays are **rockHeights / dirtHeights / lakeHeights**
  (ivar cells); the two later float arrays carry the vertical scale into
  **xFrequencyMultiplier / yHeightDivider**.
- The noise set is built in three visible groups from the save seed with fixed
  sub-seed offsets; 25 `bl 0x008540cc` (lrand48 wrapper) and 2 `bl 0x008540dc`
  (reseeder) calls are counted in the body.
- The −1 sentinel path (0x0084d000) is the retry trigger: NSLog, increment,
  reseed, flag=1 → the loop head takes the FINAL path on the next entry.
- The candidate pass stamps raw type ids (tree 1,2,3,4,6,7,8,9; plant
  1,2,3,4,5,8,9) into the type array and bids distances into the 32-entry
  scratch that is later sorted (descending) into distanceOrderedFoodTypes.
- The 0x7fffffff literal (cell 0x0084acf0) is the saved-state sentinel; the
  `== 32` per-item gate opens the migration/log path.

## Boundaries (honest)

- The parameter block at [sp,0xea8] (base fp-0x5ec) is read as a world-parameter
  scratch object; its concrete type is not proven from this body alone.
- Noise construction groups are leaf slot dispatches; argument shapes
  (octaves-like ints, keyword doubles, flags) are observed, not mapped to a
  named API.
- The −1 sentinel slot and the incremented seed slot are tracked by slot
  address; which named ivar carries them is not proven here.
- 0x008540dc (reseeder) and 0x008540fc (distance/bid helper) are project labels
  from call usage, not symbols.
- The finishing dispatch at 0x00853c2c and the 12-slot sweep are read as
  world-registration/finalisation from argument shape; their concrete selectors
  are slot values not statically resolved.
- Tree/plant type ids are raw integers in this pass; the game enum mapping
  belongs to the growthVigor* callees' batches.
