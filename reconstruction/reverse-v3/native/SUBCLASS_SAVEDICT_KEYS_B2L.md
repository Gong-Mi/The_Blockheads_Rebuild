# getSaveDict key pairings — batch 2l (CaveTroll, Plant)

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`
Recovery: `tools/recover_subclass_savedict_keys_b2l.py` →
`subclass_savedict_keys_b2l.json`. Listings:
`disasm_cavetroll_getsavedict.txt` (322w),
`disasm_plant_getsavedict.txt` (456w).

```text
CaveTroll 0x00d54924   [super] + state@208 = [NSData dataWithBytes:
                        length:0x24] — 36 RAW BYTES of the struct ivar
                        (first raw-buffer key in the save path)
                        + dead = numberWithBool of INHERITED NPC.dead@56
                          (ldrb+sxtb)
                        + defendSquare.x/.y@356 numberWithInt: (word+0/+4)
                        + attackingNPC = numberWithBool of
                          CaveTroll.chasingNPC@388 signed byte
                        + lastKnownNPCPosition.x/.y@392 numberWithInt:
                          (word+0/+4)
Plant 0x00955d7c        [super] + saveTime = numberWithDouble(
                          [self.world worldTime]) — 64-bit double from
                          the WORLD CLOCK selector, not an ivar
                        + seasonOffset@68 / gatherProgress@80 /
                          maxAgeGene@54 / growthRateGene@56 numberWithInt:
                        + age@72 / maxAge@88 / growthRate@92
                          numberWithFloat: (vldr s2)
                        + hasFloweredThisSeason@84 / flowering@85 /
                          frozen@76 numberWithBool: (ldrb+sxtb; @85 is
                          the byte ADJACENT to @84)
```

Facts:

- **CaveTroll.state is the first `dataWithBytes:length:` serialization**:
  36 raw bytes (`movw #0x24` @0xd54a0c) read from the struct ivar
  `CaveTroll.state@208` and boxed as NSData (selref cell 0xd54e0c,
  NSData classref cell 0xd54e14, msgSend call @0xd54aa8, set @0xd54ad4).
  Not a direct object, not an NSNumber.
- **CaveTroll.dead reads the INHERITED `NPC.dead@56`** — the first
  subclass save proven to reach a non-DynamicObject parent-family ivar
  (ldrb @0xd54af4 + sxtb @0xd54b08, conv 0xd54b10, set 0xd54b34).
- **attackingNPC re-keys chasingNPC**: the wire key is `attackingNPC`
  while the source ivar is `CaveTroll.chasingNPC@388`, a signed byte
  (ldrb @0xd54c94 + sxtb @0xd54cac, conv `blx sl` @0xd54cdc word
  `3aff2fe1`, set 0xd54d00) — same re-key pattern as Painting's
  outputImageData/imageData.
- **defendSquare.x/.y and lastKnownNPCPosition.x/.y** are the third and
  fourth DOTTED word pairs (356@+0/+4 loads 0xd54b54/0xd54bb4; 392
  loads 0xd54d20/0xd54d80), all plain `numberWithInt:`.
- **Plant.saveTime is the first `numberWithDouble:` key** and it is
  world-fed: `objc_msgSend(self.world, worldTime)` @0x956000 (blx r2)
  returns a 64-bit double in r0/r1, `vmov d0, r0, r1` @0x956004
  (word `100b41ec`), then `numberWithDouble:` conv @0x956020, set
  0x956044. `worldTime` is a selector on DynamicObject.world@4 — the
  same world-clock contract the Egg batch stamped as worldTime.
- **Plant.flowering@85 is a byte offset adjacent to
  hasFloweredThisSeason@84** (85 = 84+1): two consecutive bool bytes,
  each ldrb+sxtb (loads 0x956184/0x9561e4, frozen 0x956244).
- Plant float values are read via `vldr s2` (single-precision into the
  s2 register before vmov to the argument) — conv sites for
  age/maxAge/growthRate use `blx lr` word `3eff2fe1`.
- The `attackingNPC` conv site's register form differs from every prior
  batch (`blx sl`, word `3aff2fe1`) because the simulator spilled the
  msgSend pointer into sl — gated verbatim.

Process note: pairing came from `tools/gen_b2l_table.py` (annotated
listings + freeblock simulator, same pipeline as b2j/b2k). The
simulator's pending heuristic mislabeled CaveTroll.state as
`direct_object` (no numberWith selector) — the instruction stream
showed the dataWithBytes:length: path and the manual correction is
recorded here and gated by five extra word gates (movw #0x24, NSData
classref, selref, call site, plus the byte loads).

Static level-A only; 5 overrides remain (Action 510w, Tree 818w,
InteractionObject 514w, TrainCar 557w, Workbench 1232w),
read-back/roundtrip unresolved.
