# Five 74-word `-[initWithWorld:dynamicWorld:saveDict:cache:]` forwarders — batch b3f

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`
Recovery: `tools/recover_forwarder5_initwithworld.py` →
`forwarder5_initwithworld.json`. Listings:
`disasm_clownfish_initwithworld.txt`,
`disasm_shark_initwithworld.txt`,
`disasm_scorpion_initwithworld.txt`,
`disasm_dodo_initwithworld.txt`,
`disasm_donkeylike_initwithworld.txt` (74 words each).

Census: **43** methods carry `initWithWorld:dynamicWorld:saveDict:cache:`
(10,976 words total). This batch takes the five smallest — exactly 74 words
each — and freezes them as one shared skeleton.

```text
ClownFish 0x0078e420 / Shark 0x007c8918 / Scorpion 0x00893d58 /
Dodo 0x00a6b7dc / DonkeyLike 0x00ab0c3c   (74 words each)

  [super initWithWorld:dynamicWorld:saveDict:cache:]
      objc_msgSendSuper2, struct {self, OBJC_CLASS_$_<own class>}
      via the own __objc_superrefs slot; blx at word 41
  if (super result == nil) return nil
      movw #0 / cmp / bne at words 43 / 47 / 48, return-zero block 49-51
  [self loadDerivedStuff]
      objc_msgSend via the GOT + the loadDerivedStuff selector cell,
      blx at word 62
  return self
```

Facts:

- **The five bodies are word-for-word identical**: the 69-word code body is
  pinned by sha256
  `bbd0bc16ac1ca4e3776bafe9153a60672ca15a66b68d4efffad33581d804f1c8`,
  verified equal for all five in the same run. Only the referenced literal
  cells differ per class (super2 GOT slot, msgSend GOT slot, the
  `initWithWorld:…` selector cell, the `loadDerivedStuff` selector cell and
  the own-class superref slot; the sixth literal is an unmapped PIC-base
  offset). A single flipped instruction in any body changes the hash — an
  obvious thing to try that the mutation controls confirm.
- **All five resolve to the same superclass: `NPC`.** The superref slot of
  each class is dereferenced to its class object and the class struct's
  superclass word is resolved in-file — ClownFish, Shark, Scorpion, Dodo and
  DonkeyLike are all NPC subclasses, so the forwarded initialiser is
  `-[NPC initWithWorld:dynamicWorld:saveDict:cache:]` (0x00644b24, 95 words —
  the next natural read).
- **No keys and no ivars**: none of the five touches a CFString key or an
  ivar-offset slot; their entire persisted state is restored by the
  superclass initialiser, and their only own contribution is the
  `loadDerivedStuff` post-init hook. This is the first "zero-own-state"
  reader of the line and it bounds what an offline save assembler must
  provide for these five classes: nothing beyond the inherited keys.
- **Negative controls 8/8**: a flipped super-call word (idx 41), a flipped
  `loadDerivedStuff` call word (idx 62, Shark), a flipped nil-branch (idx 48,
  Scorpion), a body word outside the gate list (idx 20, Dodo → hash drift),
  the DonkeyLike epilogue word (idx 67), the ClownFish superref slot target,
  and two selector cells (ClownFish/Shark) — each must fail the run.
- Static level-A evidence only; the `loadDerivedStuff` body and the runtime
  roundtrip are unresolved. Remaining on this selector: **38 methods,
  10,606 words** (largest: Workbench 1,390w, FreeBlock 1,347w, Chest 760w).

Two-sided confirmation: the save side of the same five classes is also
keyless — `subclass_savedict_inventory.json` records `getSaveDict` for
ClownFish, Shark, Scorpion, Dodo and DonkeyLike as `super_forward` with zero
own keys — so their entire persistence is inherited in both directions and an
offline save assembler needs no per-class entries for them.
