# NPC `-[initWithWorld:dynamicWorld:saveDict:cache:]` read-back evidence — batch b3g

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`
Recovery: `tools/recover_npc_initwithworld.py` → `npc_initwithworld.json`.
Listing: `disasm_npc_initwithworld.txt` (95w).

This is the initialiser that b3f's five creatures (ClownFish, Shark,
Scorpion, Dodo, DonkeyLike) forward into.

```text
NPC -[initWithWorld:dynamicWorld:saveDict:cache:] 0x00644b24 (95w)
  [super initWithWorld:dynamicWorld:saveDict:cache:]
      objc_msgSendSuper2, struct {self, OBJC_CLASS_$_NPC} at sp+0x28,
      own superref 0x00e8bc84 → 0x00e90828; call at word 38
  if (super result == nil) return nil          words 44/45 + 46-48
  [self loadValuesFromSaveDict:saveDict]       word 61 (saveDict = 5th arg)
  r0 = lrand48()                               word 62 → wrapper 0x006445d8
  randomHarmFromHungerTimer@144 = 1.0f + 20.0f * (float(r0) / 2^31f)
      movw #1 / vmov s0=1.0f / movw #0x14 / vmov s2=20.0f /
      vldr s4 = 0x4f000000 (2^31f) / vmov s6,r0 / vcvt.f32.s32 /
      vdiv / vmul / vadd / vstr           words 66-79
```

Facts:

- **The class chain is now two levels deep in evidence**: b3f resolved the
  five creatures' superrefs to `NPC`; this batch resolves NPC's own superref
  to `DynamicObject` (in-file class struct), i.e.
  `DynamicObject → NPC → {ClownFish, Shark, Scorpion, Dodo, DonkeyLike}`.
- **The hunger timer is seeded from `lrand48()`, so this loader is NOT
  deterministic**: the call chain is
  `bl 0x006445d8` → local 4-word wrapper (`push {fp,lr} / mov fp,sp /
  bl 0x001c2804 / pop {fp,pc}`) → ABI veneer `0x001c2804`
  (`add ip,pc,#imm / add ip,ip,#imm / ldr pc,[ip,#imm]!`) → slot
  `0x0105fb10` = imported **lrand48**. The value is converted
  (`vcvt.f32.s32`), divided by the pinned float literal `0x4f000000` (2^31)
  and scaled by 20 with a +1 offset, giving a uniform draw in **[1.0, 21.0)**
  stored through `vstr` into `randomHarmFromHungerTimer@144`.
  Any differential or roundtrip harness for NPC must control `lrand48`'s
  sequence, otherwise the timer (and everything downstream that reads it)
  diverges by construction.
- **No CFString keys and one ivar**: the loader reads no dictionary keys
  itself (`loadValuesFromSaveDict:` owns the key side, paired in the earlier
  save-line batches) and touches exactly one ivar slot
  (`NPC.randomHarmFromHungerTimer` = 144); the selector cells resolve to
  `initWithWorld:dynamicWorld:saveDict:cache:` and `loadValuesFromSaveDict:`.
- **Negative controls 11/11**: super call word, `loadValuesFromSaveDict:`
  call word, the wrapper call word, the timer formula's `vmul`/`vstr` words,
  the 2^31 float literal, the timer ivar offset, NPC's superref slot, the
  wrapper's `bl` word, the veneer's final slot word and a selector cell —
  each must fail the run.
- Static level-A evidence only; `loadValuesFromSaveDict:`'s own body is a
  separate batch, and the runtime roundtrip stays unresolved. Remaining on
  this selector after b3f+b3g: **37 methods / 10,511 words**.
