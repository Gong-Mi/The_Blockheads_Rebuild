# mid-tier key-table family — EXECUTED differential (Unicorn, ten bodies)

Batch: the ten flat key-table loaders of the mid-tier family, executed under
Unicorn against the module's OWN spec table
(`reconstruction/recovered/midtier_full.{h,cpp}` via
`tools/midtier_arm_bridge.cpp`, -O0 and -O2).

Covered (11 classes, 44 cases): Window 31, Rail 40, Ladder 19, Egg 30,
Column 53, Stairs 54, Door 20, Wire 38, ElevatorShaft 56, ElevatorMotor 55,
and Boat 32 (the probe shape: objectForKey probe → nil → the -1 default
survives; non-nil → a SECOND objectForKey + intValue overwrites @120).

Harness: `tools/test_midtier_arm.py` (pinned ELF sha256 `733d8210…c94c7`);
CI guard `tools/test_midtier_arm_evidence.py` (CTest `midtier_arm_evidence`:
constants in CI, full differential with `--elf` on the host).

## What the differential caught (four real decode errors, all fixed)

1. **Read order** — seven of the ten bodies read their keys in a different
   order than the first listing pass suggested. ARM truth (now the spec
   order): Rail itemType→ownedByStation→configuration; Ladder
   itemType→paintColor→ownerID; Column itemType→configuration→paintColor→
   ownerID; Stairs itemType→configuration→ownerID→paintColor; Door
   itemType→blocked→ironPlaceClientID→ownerID; ElevatorShaft
   itemType→pos.x→pos.y→ownerID→paintColor; ElevatorMotor
   itemType→availableElectricity→minY→maxY→ownerID. (Window and Wire already
   matched.)
2. **Egg reads breed INSIDE its genesDict child** — the body stores the
   retained `genesDict` at @56 and then does
   `[[self->genesDict] objectForKey:@"breed"]`; a top-level `breed` is never
   read. The module now models nested reads (`MidtierKeySpec::nested_in`);
   the fixture and the contract test carry the nested shape plus a
   top-level-breed control.
3. **ElevatorMotor conversions** — `availableElectricity` and `minY` use
   `unsignedIntValue`, not `intValue`.
4. **ElevatorMotor widths** — `availableElectricity` is the STRH store
   (@60); `minY`/`maxY` are plain words (@64/@68). The first pass had the
   halfword on `maxY`.

5. **Wire's solidConfiguration has a zero->1 store-back** (round two, case
   3): after `str intValue(...)`, the body reloads the ivar, compares with 0
   and rewrites **1** when zero (`cmp r0, #0; bne; movw r0, #1; str` at
   0x00950218..0x0095024c). An absent/zero key therefore lands as 1; the
   module models it as `zero_to_one` on that key.

## Harness-side ABI fact

The bodies do `vmov s0, r0` after a `floatValued` call: the float comes back
through **r0** (objc_msgSend's integer return path), so the stub sets both r0
and s0 — a stub that only set s0 fed token bits into `hatchTimer`.

## Per-case assertions

- the exact call-label sequence (super → per key: objectForKey:/conversion →
  hook) must equal the bridge's spec-table expectation — this pins the READ
  ORDER above;
- traced nested reads must receive the parent's token as receiver;
- the 256-byte instance image must equal the spec-table expectation for
  case 0 (all keys), case 1 (alternating presence; nested keys effective only
  when their parent is present) and case 2 (nil super → nil return, no reads);
- the return register must be self / nil accordingly.

Result: 44/44 cases match (`midtier-arm-result.json` in the run's output
directory). Case 3 (odd-index keys present) is what surfaced both the Boat
probe-absent path and the Wire normalization.

Boundary: Unicorn with a synthetic ObjC graph — not Foundation, not the
original-app runtime, not device gameplay. The device pass (0.2-b5e
all-types snapshot) proves the recovered C++ loaders end to end; this proves
the original bodies' behaviour the loaders claim.
