# getSaveDict key pairings — batch 2n (TrainCar)

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`
Recovery: `tools/recover_subclass_savedict_keys_b2n.py` →
`subclass_savedict_keys_b2n.json`. Listing:
`disasm_traincar_getsavedict.txt` (557w).

```text
TrainCar 0x00a394b0  [super] + per occupied rider slot i:
                      key = [NSString stringWithFormat:
                             'currentBlockheadIndex_%d', i]
                      value = that rider's index in
                             [dynamicWorld blockheads]
                      (needsRemoved entries skipped)
                    + rightCarID  = [rightCar@168 uniqueID]
                      leftCarID   = [leftCar@172 uniqueID]
                      engineCarID = [engineCar@176 uniqueID]
                      (each nil-guarded, numberWithInt box)
                    + ownerID@36 nil-guarded DIRECT
                    + engineIsRight@180 signed-byte bool,
                      saved UNCONDITIONALLY
```

Facts:

- **'currentBlockheadIndex_%d' is the first DYNAMIC format-string wire
  key**: the CFString payload itself contains the `%d` (cell 0xa39d54,
  obj 0xf972a8), the key is built at save time via
  `[NSString stringWithFormat:]` (call `blx lr` word `3eff2fe1` @
  0xa398a0), and ONE ENTRY IS EMITTED PER OCCUPIED RIDER SLOT — a
  replacement encoder must synthesize currentBlockheadIndex_0, _1, …
  keys, not a fixed key set.
- **TrainCar.riders@76 is a raw C array**: slot access is `ldr [base +
  i*4]` (`add r2, r3, r2, lsl #4` + `ldr` @0xa3958c, word `002092e5`),
  NOT an NSArray subscript — the only raw C-array traversal in the
  save path so far. Nil slots skip (beq word `cb00000a` @0xa39598).
- **rightCarID/leftCarID/engineCarID are cross-entity references**:
  they serialize the NEIGHBOR car's `uniqueID` (import-thunk `bl
  #0x1c281c` @0xa39980/0xa39a70/0xa39b60 — words `a523deeb`,
  `6923deeb`, `2d23deeb`), each behind a nil-guard (beq word
  `3100000a` @0xa39904/0xa399f4/0xa39ae4). A missing neighbor saves
  NOTHING (no key), unlike guard-suppressed direct objects.
- The rider search is the Boat-family double loop (slot × blockheads,
  O(riders × blockheads)) WITH the `[needsRemoved]` skip (msgSend
  @0xa39748) that InteractionObject's version lacks.
- **engineIsRight@180 is saved unconditionally**: no nil/zero guard
  before `numberWithBool` (ldrb word `0040d4e5` @0xa39c7c + sxtb
  word `74e0afe6` @0xa39c8c, conv `blx lr` @0xa39ca8, set @0xa39ccc)
  — every other bool key so far was either guarded or part of a
  fixed-shape cascade; this is the first unconditional bool store.
- The dynamic conv registers spill differently from prior batches
  (`blx r6` word `36ff2fe1` for the numberWithInt) — gated verbatim.

Static level-A only; 3 overrides remain (Action 510w, Tree 818w,
Workbench 1232w), read-back/roundtrip unresolved.
