# InteractionObject -[initWithWorld:dynamicWorld:saveDict:cache:] — executed differential

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`

Boundary from the pinned ObjC method map:

```text
IMP:      0x005F4634
boundary: 0x005F4BB4 (next method IMP)
words:    352 (exact coverage asserted by emit_annotated_method.py)
types:    @24@0:4@8@12@16@20 (exact-initWithWorld variant)
```

The annotated listing (`disasm_interactionobject_initwithworld.txt`) was
generated deterministically over the pinned ELF (coverage gate OK). The
contract `reconstruction/recovered/interaction_object_init.{h,cpp}` is now
**executed**: `tools/test_interaction_object_arm.py` runs the original
352-word body under Unicorn with a synthetic ObjC message graph and
compares the resulting 96-byte instance image and the full call trace
against the C++ contract at -O0 and -O2, across **8 cases, all matched**.

## The differential caught two static-decode errors

1. **The third tail gate.** The static reading had two gates
   (isServer, ownerID != nil). Execution showed a third:
   `ownerName@84 == nil` (cmp/bne at 0x5f4a94/0x5f4a98) — a record that
   CARRIES ownerName skips the world resolution entirely. Case 7 pins it.
2. **The unconditional -1 default store.** `savedBlockheadIndex@80 = -1`
   is stored BEFORE the currentBlockheadIndex probe
   (0x5f4948-0x5f495c, the same -1-default pattern as the NPC
   savedBlockheadIndexFuel); the probe's second read overwrites it only
   when non-nil. Cases 2/3 pin the default.

## Executed facts (frozen by the run)

```text
super (4-arg, objc_msgSendSuper2, own-class superref) -> nil returns nil
isInUse    objectForKey -> boolValue          -> strb  @68
flipped    objectForKey -> boolValue          -> strb  @69
ownerID    objectForKey -> retain             -> str    @36
ownerName  objectForKey -> retain             -> str    @84
paintColor objectForKey -> unsignedIntValue   -> STRH   @88  (halfword!)
savedBlockheadIndex@80 = -1                   -> str    @80 (unconditional)
currentBlockheadIndex probe; second read + intValue only when non-nil
                                              -> str    @80 (overwrite)
tail: if (isServer) if (ownerID@36 != nil) if (ownerName@84 == nil)
      ownerName@84 = retain([dynamicWorld getOwnerNameForObjectOwnerID:])
```

Image 96 bytes: the deepest write is paintColor@88 (+2) — stated rationale
like the NPC 160-byte image. The stubbed super's stores (world@4 /
dynamicWorld@8) are excluded from the image comparison (outside this
contract's slice).

## Boundaries (unchanged discipline)

Unicorn execution of the original ARM with a synthetic message graph (the
dispatch stub serves objectForKey: through the REAL ELF CFString objects,
the conversions, retain, isServer and getOwnerNameForObjectOwnerID:); not
Foundation, not the original-app runtime, not device gameplay. The world
side and the boxed values are synthetic; the superclass initialiser is
stubbed.

Reproduce: `tools/test_interaction_object_arm.py <pinned ELF> --output-dir
<dir>` (needs Unicorn 2.1.4 + the ELF); the CI-safe guard is
`tools/test_interaction_object_arm_evidence.py`.
