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

## Still to model

Painting 52 (isServer-gated owner-name resolution + ban flag), DropBear 25
(the maxAge/worldTime age step + eight own keys), CaveTroll 39 (the
fromSquare travel-state block, the `dead` byte, `defendSquare.x/.y` and the
`state` data blob copied through the in-ELF memcpy veneer 0x1C2894).
Their `--dump` output is one command away; the pinned models land here as
they are written.

Boundary: Unicorn with a synthetic ObjC graph — not Foundation, not the
original-app runtime, not device gameplay. The device pass (0.2-b5f
all-types snapshot) proves the recovered C++ loaders end to end; this proves
the original bodies' behaviour the loaders claim.
