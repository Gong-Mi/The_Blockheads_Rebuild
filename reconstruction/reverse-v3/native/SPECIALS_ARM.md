# special loaders — EXECUTED differential (Unicorn, per-class models)

The five bespoke loader bodies whose shapes are not flat key tables:
SteamTrain 42, OwnershipSign 60, Painting 52, DropBear 25, CaveTroll 39.

Harness: `tools/test_specials_arm.py` (pinned ELF sha256 `733d8210…c94c7`).
It has three modes:
- `--dump` — a LENIENT recorder: every selector the body throws is accepted,
  benign values returned, and the full call order printed with receiver kinds.
  This is the raw material the per-class model is written from.
- `--dump-images CLASS` — per-case labels + nonzero image bytes.
- default — the pinned comparison: each MODELLED class runs four cases
  (0 all keys, 1 even-index, 2 nil super, 3 odd-index) and must equal the
  model in `tools/specials_arm_bridge.cpp` at -O0/-O2 on call sequence,
  512-byte image and return register.

CI guard: `tools/test_specials_arm_evidence.py` (CTest `specials_arm_evidence`;
constants in CI, full differential with `--elf` on the host).

## Modelled so far

### SteamTrain 42 (0x00D18834, super = TrainCar)

Own body: `fuelFraction` floatValue -> word @260, `hasFuel` boolValue ->
STRB @268, `goingRight` boolValue -> STRB @252, `stopped` boolValue ->
STRB @325 — in exactly that order, and **no post-init hook of its own**
(the `loadDerivedStuff` hook belongs to the TrainCar super chain, which the
stubbed super2 stands for; the module's reason was corrected accordingly).

### OwnershipSign 60 (0x00A34B18, super = Sign)

The per-case dump pinned three facts the first listing pass missed:

1. **Default radii = 15** (`movw lr, #0xf` then two stores) — not 30 and not
   0. An absent radius key keeps 15.
2. **A present radius clamps into [1, 30]** through the body's own helper at
   0x4BE068 — disassembled with capstone: `clampf(x, lo, hi)` over the
   float-converted int (`vmov.f32 s0,#1.0; s2,#30.0` around the call). The
   helper runs natively inside the harness (in-ELF address), so the harness
   needs no stub for it.
3. **The `landOwnerID` read is a PROBE that gates the whole object block**:
   with a nil ID the body never touches `landOwnerName` nor the two
   stale-value autoreleases; when non-nil it runs
   autorelease ×2 (stale ivars, nil on a fresh object), `ofk:landOwnerID` +
   retain -> @124, `ofk:landOwnerName` + retain -> @128. Each radius then
   probes its own key and re-reads + intValue + clamps only when non-nil,
   and the body ends with `[self updateText]`.

All three landed in the module (`kOwnershipDefaultRadius = 15`,
`ownershipClampRadius`, the ID gate) with contract tests for the clamp, the
default and the gate.

### Painting 52 (0x00AA81E8, super = DynamicObject)

Own body, ARM-attested: five reads in order — `itemType` intValue -> word
@56, `outputImageData` retain -> @60, `hasVerifiedImageData` boolValue ->
STRB @79, `ownerID` retain -> @36, `ownerName` retain -> @64 — then the two
`[self->dynamicWorld isServer]` gates (the cell map in the annotated listing
resolves both receivers to DynamicObject.dynamicWorld@8):

- gate 1, when isServer AND `ownerID != nil` AND `ownerName == nil`:
  `[dynamicWorld getOwnerNameForObjectOwnerID:self->ownerID]` -> retain ->
  stored BACK into `ownerName` @64;
- gate 2, when isServer: `[dynamicWorld playerIsBannedWithID:self->ownerID]`
  -> STRB `hiddenDueToServerBan` @77;
- `[self initSubDerivedItems]` tail hook.

The harness runs phase 2 with isServer=1 and a fixed resolved token, so case
3 (ownerID present, ownerName absent) exercises the resolve path and case 0
the plain one. Both gates' conditions and store targets are now in the
module's comment/reason (the world side itself stays not-run offline).

### DropBear 25 (0x0079D538, super = NPC)

Own body, ARM-attested: nine reads in order — provokeMeter float @300,
courageMeter float @304, dropping STRB @308, dropSpeed float @312, onGround
STRB @344, dropPos.x int @348, dropPos.y int @352, goalTreeDirection int
@356, saveTime float — then the AGE STEP:
`age@88 += ([world worldTime] − saveTime)`, where worldTime is read as a
**double** (`vmov d1, r0, r1`). Then `[self maxAge]` is compared against the
age: `age > maxAge` -> `[self removeFromMacroBlock]` + `[self release]` +
**return NIL** (dies of old age); else `[self loadDerivedStuff]` + return
self. The death branch is exercised as case 4 (maxAge stub set to 0) and is
now documented in the npc_full module's reason.

### CaveTroll 39 (0x00D538CC, super = NPC)

Own body, ARM-attested: super, then the coordinate-wrap helper — an in-ELF
function at 0xA12F64 that calls `[world worldWidthMacro]`/`macroTiles` and
wraps a coordinate into `worldWidthMacro*32` — runs before the reads:
`defendSquare.x` intValue -> word @356, `defendSquare.y` intValue -> word
@360, `state` probe -> when present `[bytes]`/`[length]` -> **memcpy** (the
PLT veneer 0x1C2894, GOT slot 0x105FB40) into the @208 blob, `dead`
boolValue -> STRB @56. When the state blob was present the wrap helper runs
AGAIN (the movement-state re-init block), then `[self
initSubDerivedStuffStuff]`. `travelSpeed@312`/`travelFraction@400` are
world-derived (4.0f / 1.0f under the harness's worldWidthMacro=4 stub).

Harness facts this class forced (all now generic in the runner): the binary
has a SECOND set of msgSend pointers — the PLT's own GOT slots (rel.plt,
objc_msgSend at 0x105FB18); bodies that call the PLT stub (CaveTroll does)
need EVERY slot patched by symbol. The memcpy veneer is stubbed with real
copy semantics, `worldWidthMacro`/`worldHeightMacro` answer 4 (returning 0
spins the wrap helper forever), and `--trace` records the last PCs / call
list / registers so a runaway execution is diagnosed instead of guessed.

## Coverage

Modelled and pinned (25/25 cases across the four-case scheme plus DropBear's
death case 4): SteamTrain 42, OwnershipSign 60, Painting 52, DropBear 25,
CaveTroll 39.

### ArtificialLight 21 (0x00A93C64, super = DynamicObject) — MODELLED

The tail turned out to be reachable once the .plt hook covered every entry
(the body's first tail call sits at PLT entry 172, past the original hook
range — the low-address walk was the unresolved lazy resolver). With the
generic .plt handler in place the full body runs:

- `[self isClient]` FIRST (before super): true -> `[self release]` + nil;
- super; then EIGHT int reads stored in order — maxRed@64, maxGreen@68,
  maxBlue@72, maxHeat@76, radius@80, contributionGridOrigin.x@84, .y@88,
  lightDirection@96;
- the `downlight` boolValue read stores NO own field: a true value OVERWRITES
  lightDirection@96 with a word store of 1 (the cell map pins 0xffffef30 =
  lightDirection@96; the earlier reading treated downlight as a plain field);
- `diameter@92 = radius << 1` (the write trace showed 0x0002468A for the stub
  radius 0x12345);
- two `__wrap_calloc` calls fill contributionGrid@56 / addedGrid@60;
  parentObject@100 is the 5th ARGUMENT (zero under the harness);
- `[self addToTiles]` tail (world state, not run offline).

The module now carries the gate (`downlight_forces_direction`), the derived
diameter and the corrected reason; the contract test gained a downlight-false
control.

### Historical note: reads attested before the tail was cracked

The 5-arg body's `--dump` is clean and pins the reads: `[self isClient]`
first (true -> `[self release]` + return nil), the super 4-arg init, then
**nine reads in this order** — maxRed, maxGreen, maxBlue, maxHeat, radius,
contributionGridOrigin.x, contributionGridOrigin.y, lightDirection,
downlight (intValue x7 + boolValue; the reverse of the first listing pass's
order, now corrected in the module's header). The tail builds real C++
objects (diameter/contributionGrid) and calls `[self addToTiles]` — beyond
the synthetic graph — so ArtificialLight stays dump-attested for the reads
and is NOT in the pinned model set.

Boundary: Unicorn with a synthetic ObjC graph — not Foundation, not the
original-app runtime, not device gameplay. The device pass (0.2-b5f
all-types snapshot) proves the recovered C++ loaders end to end; this proves
the original bodies' behaviour the loaders claim.
