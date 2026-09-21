# getSaveDict key pairings — batch 2i (Sign, ElevatorMotor, ElevatorShaft, Painting)

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`
Recovery: `tools/recover_subclass_savedict_keys_b2i.py` →
`subclass_savedict_keys_b2i.json`. Listings:
`disasm_sign_getsavedict.txt` (216w),
`disasm_elevatormotor_getsavedict.txt` (223w),
`disasm_elevatorshaft_getsavedict.txt` (223w),
`disasm_painting_getsavedict.txt` (242w).

```text
Sign 0x005faeb4   [super] + nil-guarded DIRECT text@100 / ownerID@36
                    / ownerName via InteractionObject@84,
                    + connectionType@112 / offsetType@116 numberWithInt:
ElevatorMotor 0x00700b5c [super] + itemType@56 numberWithInt:
                    + availableElectricity@60 / minY@64 / maxY@68
                      numberWithUnsignedInt:
                    + ownerID@36 direct
ElevatorShaft 0x00cad998 [super] + itemType@56 numberWithInt:
                    + lastKnownMotorPos.x@60 / lastKnownMotorPos.y@+4
                      numberWithInt: (DOTTED keys, one struct ivar)
                    + paintColor@84 numberWithUnsignedInt:
                    + ownerID@36 direct
Painting 0x00aa8fc8  [super] + itemType@56 numberWithInt:
                    + outputImageData@60 DIRECT (gated [imageData length]>0),
                    + ownerID@36 / ownerName@64 direct,
                    + hasVerifiedImageData@79 numberWithBool: (ldrb+sxtb)
```

Facts:

- **`numberWithUnsignedInt:` makes its first appearance** in this batch
  (ElevatorMotor availableElectricity/minY/maxY, ElevatorShaft paintColor).
  The wire type is NSNumber from an unsigned word; a replacement encoder
  must not sign-extend these values.
- **`lastKnownMotorPos.x` / `.y` are the first DOTTED wire keys**, both
  boxed from ONE ivar `ElevatorShaft.lastKnownMotorPos@60` (struct at +0
  and word+4 via `ldr r3, [r3, #4]` at 0xcadb44/0xcadba4). Key strings
  must survive verbatim including the dot.
- **Sign stores text/ownerID/ownerName as guarded RAW objects** (three
  separate nil-or-zero `cmp`/`beq` guards at 0x5faf38, 0x5fafb8, 0x5fb038;
  no boxing call) — same pattern as OwnershipSign (b2h) but on the
  InteractionObject-inherited ownerName@84.
- **Painting.outputImageData re-keys Painting.imageData@60**: the dict key
  is `outputImageData` while the source ivar is `imageData`, and the write
  is gated by a `[imageData length]` call (0xaa9130) with `cmp r0, #0;
  bls` (0xaa9134/0xaa9138) — empty image data is NOT saved.
- **hasVerifiedImageData@79 is a signed byte** (ldrb @0xaa92e0 + sxtb
  @0xaa92f0 into numberWithBool:) — negative bytes exist in the struct.
- ElevatorMotor/ElevatorShaft share the four-key shape but the dotted
  pair is unique to the shaft; the motor's ints are the unsigned trio.

Process note: addresses came from `tools/gen_b2i_table.py` (annotated
listings + freeblock simulator, same pipeline as b2f/b2h); the simulator
emits conv→set pairing order and the CFString/ivar cells; every cell was
then re-gated against the pinned ELF in the recovery script.

Static level-A only; 13 overrides remain (Torch 266w … Workbench 1232w
plus the Blockhead/Chest tail dispatchers), read-back/roundtrip unresolved.
