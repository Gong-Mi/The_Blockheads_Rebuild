# Five more `-[initWithWorld:dynamicWorld:saveDict:cache:]` forwarders — batch b3h

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`
Recovery: `tools/recover_forwarder5b_initwithworld.py` →
`forwarder5b_initwithworld.json`. Listings:
`disasm_surfaceblock_initwithworld.txt` (57w),
`disasm_passengercar_initwithworld.txt` (60w),
`disasm_handcar_initwithworld.txt` (60w),
`disasm_mirror_initwithworld.txt` (71w),
`disasm_snowsurfaceblock_initwithworld.txt` (71w).

```text
super-only shape (no post-init hook):
  SurfaceBlock     0x00812e64 (57w)  super → DynamicObject
  PassengerCar     0x0081bcc8 (60w)  super → TrainCar
  HandCar          0x00a4f564 (60w)  super → TrainCar

super + initSubDerivedItems hook:
  Mirror           0x00a9f434 (71w)  super → InteractionObject
  SnowSurfaceBlock 0x00d8d89c (71w)  super → DynamicObject

  each: [super initWithWorld:dynamicWorld:saveDict:cache:] through
        objc_msgSendSuper2 with the own-class superref →
        nil guard (return nil) → [optional hook] → return self
```

Facts:

- **This selector is a forwarding *convention*, not one shared body**: unlike
  b3f's five (which were byte-identical), these five have per-class bodies and
  forward into **three different parents** — `TrainCar` for both rail vehicles,
  `InteractionObject` for Mirror, `DynamicObject` for SurfaceBlock and
  SnowSurfaceBlock (all resolved from the class structs in-file). Each method
  is therefore gated at its own word indices rather than against a shared
  skeleton hash.
- **A second post-init hook name appears**: Mirror and SnowSurfaceBlock call
  `[self initSubDerivedItems]` after the super init, alongside b3f's
  `loadDerivedStuff`. Both hooks are zero-argument, self-only calls through the
  shared `objc_msgSend` GOT — so the convention is
  `[super …] → nil guard → [self <hook>] → self`, with the hook name varying
  per family.
- **Again zero keys, zero ivars**: four of the five touch exactly one
  unmapped PIC-base cell besides their GOT/selector/superref cells; none reads
  a CFString key or writes an ivar, which keeps them on the "nothing to add to
  an offline save" side of the ledger (same as b3f).
- **Selector census after b3h: 11 methods / 784 words covered, 32 methods /
  10,192 words remaining** (recounted in the tool and frozen into the JSON).
- **Negative controls 8/8**: the SurfaceBlock super-call word, the
  PassengerCar nil-compare and nil-branch words, the HandCar return branch,
  Mirror's hook call word, SnowSurfaceBlock's hook-needle store word, the
  SnowSurfaceBlock superref slot and Mirror's hook selector cell — each must
  fail the run.
- Static level-A evidence only; the hook bodies (`initSubDerivedItems`,
  `loadDerivedStuff`) and the runtime roundtrip remain unresolved.
