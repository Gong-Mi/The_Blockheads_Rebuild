# getSaveDict key pairings — batch 2k (Boat, ArtificialLight, DropBear)

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`
Recovery: `tools/recover_subclass_savedict_keys_b2k.py` →
`subclass_savedict_keys_b2k.json`. Listings:
`disasm_boat_getsavedict.txt` (271w),
`disasm_artificiallight_getsavedict.txt` (310w),
`disasm_dropbear_getsavedict.txt` (318w).

```text
Boat 0x0096c238          [super] + nil-guard on rider@116; if the rider
                          exists: fast-enumerate [dynamicWorld blockheads],
                          find the blockhead == rider (skip [needsRemoved]),
                          save its INDEX as currentBlockheadIndex
                          numberWithInt:; + nil-guarded ownerID DIRECT
ArtificialLight 0x00a942d4 [super] + maxRed@64 / maxGreen@68 / maxBlue@72
                          / maxHeat@76 / radius@80 / contributionGridOrigin.x@84
                          / contributionGridOrigin.y@84+4 / lightDirection@96
                          all numberWithInt: plain word loads
DropBear 0x0079ddc0      [super] + provokeMeter@300 / courageMeter@304
                          / dropSpeed@312 numberWithFloat: (vldr s0),
                          dropping@308 / onGround@344 numberWithBool:
                          (ldrb+sxtb), dropPos.x@348 / dropPos.y@348+4 /
                          goalTreeDirection@356 numberWithBool: of WORD
                          loads narrowed by sxtb to the low byte
```

Facts:

- **Boat.currentBlockheadIndex is the first loop-index value**: the saved
  value is the position of `Boat.rider@116` inside
  `[self.dynamicWorld blockheads]`, not an ivar. `rider` itself,
  `needsRemoved` (selector on each enumerated blockhead), and the
  `blockheads` array are NOT saved under any key; the enumeration is a
  search (rider nil-guard cmp/beq 0x96c2bc/0x96c2c0; equality cmp/bne
  0x96c438/0x96c440; needsRemoved msgSend @0x96c46c + sxtb + bne
  0x96c478; found flag ldrsb @0x96c510 gates the set at 0x96c5a0).
- **ArtificialLight.contributionGridOrigin.x/.y are the second DOTTED
  struct pair** after ElevatorShaft.lastKnownMotorPos: one ivar
  `ArtificialLight.contributionGridOrigin@84`, word+0 (`ldr` @0xa94640)
  and word+4 (`ldr #4` @0xa946a0), both plain `numberWithInt:`.
- **DropBear.dropPos is a struct of two SIGNED BYTES in word slots**:
  the full word is loaded (`ldr` @0x79e148 for .x, `ldr #4` @0x79e1a8
  for .y) then `sxtb` (@0x79e15c/@0x79e1bc) narrows to the low byte
  before `numberWithBool:`. A replacement encoder must reproduce the
  byte narrowing — copying the raw word would be wrong.
  `goalTreeDirection@356` is the same word-load-then-sxtb shape.
- **dropping@308 / onGround@344 are true ldrb+sxtb signed bytes**
  (ldrb @0x79e028/@0x79e0e8).
- DropBear's conv/set cadence alternates `blx r3` (bools via [sp 0x48] =
  msgSend, sel `numberWithBool:` @cell 0x79e270) and `blx lr` (floats
  via [sp 0x60] = msgSend, sel `numberWithFloat:` @cell 0x79e294);
  provokeMeter set 0x79dfa8, courageMeter 0x79e008, dropping 0x79e068,
  dropSpeed 0x79e0c8, onGround 0x79e128, dropPos.x 0x79e188,
  dropPos.y 0x79e1e8, goalTreeDirection 0x79e248.
- The spill-cascade set sites were taken from the simulator's
  r3-at-set tracing and re-verified against the instruction stream
  (r3 spilled key cells: [fp -0x64] provokeMeter, [fp -0x5c] courageMeter,
  [fp -0x54] dropping, [fp -0x48] dropSpeed, [fp -0x40] onGround,
  [fp -0x3c]/[fp -0x58] dropPos.x/.y? — see listing; goalTreeDirection
  from [fp -0x3c] region), all gated by instruction word in the
  recovery script (26 extra gates).

Static level-A only; 7 overrides remain (Action 510w, Plant 456w,
Tree 818w, CaveTroll 322w, InteractionObject 514w, TrainCar 557w,
Workbench 1232w), read-back/roundtrip unresolved.
