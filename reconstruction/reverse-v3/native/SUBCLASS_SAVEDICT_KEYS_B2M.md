# getSaveDict key pairings — batch 2m (InteractionObject)

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`
Recovery: `tools/recover_subclass_savedict_keys_b2m.py` →
`subclass_savedict_keys_b2m.json`. Listing:
`disasm_interactionobject_getsavedict.txt` (514w).

```text
InteractionObject 0x005f50b8  [super] + saveTime = numberWithDouble(
                              [self.world worldTime]) — world-clock
                              double, same contract as Plant (b2l)
                              + isInUse@68 / flipped@69 numberWithBool:
                              (ldrb+sxtb; ADJACENT BYTES 68/69)
                              + interactionObjectType = numberWithInt of
                              msgSend(self, 'interactionObjectType') —
                              computed selector, not an ivar
                              + paintColor@88 numberWithUnsignedInt:
                              + currentBlockheadIndex = loop index of
                              currentBlockhead@56 inside
                              [dynamicWorld blockheads] (identity only)
                              + ownerID@36 / ownerName@84 nil-guarded
                              DIRECT
```

Facts:

- **InteractionObject is the ownerName@84 parent**: the base class
  itself saves `ownerName` (nil-guarded DIRECT, cmp/beq
  0x5f57d8/0x5f57dc, set 0x5f5834). Sign (b2i) and Painting (b2i) save
  their own `ownerName` keys — those subclass writes override/coexist
  with this parent write in the assembled dictionary.
- **saveTime (worldTime double) is a cross-subtree contract**: both
  Plant (b2l) and InteractionObject save
  `numberWithDouble([self.world worldTime])` — msgSend worldTime
  @0x5f5298 (`blx ip`), `vmov d0, r0, r1` @0x5f529c (word `100b41ec`),
  conv @0x5f52b8, set @0x5f52dc. Egg (b2g) previously noted the
  worldTime stamp.
- **interactionObjectType is the second computed-selector value** (after
  TradingPost's per-item saveData): the wire key equals the selector
  name; selref cell 0x5f5874, conv 0x5f53e4, set 0x5f5408.
- **currentBlockheadIndex mirrors Boat's rider search but identity
  only**: currentBlockhead@56 nil-guard (cmp `r0,r2` word `020050e1` /
  beq 0x5f5484/0x5f5488), enumeration @0x5f5508, equality
  cmp `r3,r0` word `000053e1` / bne 0x5f5600/0x5f5608, found ldrsb
  @0x5f56a0 — NO needsRemoved skip (Boat checks `[b needsRemoved]`,
  InteractionObject does not).
- **isInUse@68 / flipped@69 are adjacent bytes** (69 = 68+1), both
  ldrb+sxtb bools (loads 0x5f52fc/0x5f535c) — the third adjacent-byte
  pair after Plant's 84/85.
- paintColor@88 uses `numberWithUnsignedInt:` — unsigned word, no
  sign-extension (ElevatorMotor/ElevatorShaft/Painting family pattern).

Static level-A only; 4 overrides remain (Action 510w, Tree 818w,
TrainCar 557w, Workbench 1232w), read-back/roundtrip unresolved.
