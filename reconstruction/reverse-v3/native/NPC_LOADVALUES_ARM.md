# NPC -[loadValuesFromSaveDict:] — executed differential (batch b4f)

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`

Boundary from the pinned ObjC method map:

```text
IMP:      0x00643b20
boundary: 0x0064448c (next method IMP)
words:    603 (exact coverage asserted by the b3n listing)
```

The b3n decode of this method (15 key chains + 4 guard probes +
`dictionaryWithDictionary:` copy site, static level-A) is now **executed**:
`tools/test_npc_loadvalues_arm.py` runs the original ARM body under Unicorn
with a synthetic save dictionary and compares the resulting 160-byte
instance image and the full message trace against the recovered C++
contract `reconstruction/recovered/npc_load_values_from_save_dict.{h,cpp}`
at -O0 and -O2. `tools/test_npc_loadvalues_arm_evidence.py` guards it in
both host and CI modes; CTest `recovered_npc_load_values` exercises the
contract without the ELF.

## Harness topology (stated limits)

* One `objc_msgSend` GOT slot (0x0105b7a0) patched to a dispatch stub; the
  body loads every selector from its own selref cells, so the stub reads
  the real selector strings.
* Keys resolve through the CFString OBJECT's +8 data pointer — the body
  passes the real ELF CFString objects (0x00f80568–0x00f80648), not bare
  C strings.
* Per-key boxed values return raw payloads; single-precision bits travel
  `vmov s0, r0` → `vstr` unchanged (NaN/−inf/subnormal verified bit-exact
  in the `float_edges` case).
* The `NSMutableDictionary` classref cell (0x00e8a238) has a zero file word
  and is patched to a synthetic class object; `dictionaryWithDictionary:`
  returns the fixed token `0x00D1C700` that the recovered C++ stores, so
  both images agree byte-for-byte.
* The two-level ivar-offset resolution executes for real (intermediate
  cell → `OBJC_IVAR_$_…` symbol → offset value, all file-backed).

## What execution confirmed (or corrected)

Confirmed the b3n static decode end to end, including the parts static
analysis could not settle:

* **Group gates are probe-key gates.** `fullness` nil skips the whole
  {fullness, layTimer, damage, age} group — a present layTimer/damage/age
  is NOT read back (executed negative control: the probe fires once and
  the group body never runs). Same for the `layCooldownTimer` gate over
  its six-key group. `breed` and `currentBlockheadIndex` gate only
  themselves.
* **The taming block is UNGATED.** `tamedClientID`, `name` and the
  `tameCountsByClientID` nil-out/copy run even when the keys are absent —
  nil is stored, the old name and old dictionary are still autoreleased
  (their initial values observed as receivers), and only the
  `dictionaryWithDictionary:` copy is nil-gated. This matches the b3n
  guard-probe census (the block contributes no guard probe).
* **Truncations happen at the store width, after conversion.** damage
  (intValue) 70000 → `strh` → 4464; mateBreed −1 → 65535; breed
  (unsignedIntegerValue) 0x12345678 → 0x5678. `savedBlockheadIndex` gets a
  full-word −1 default BEFORE the currentBlockheadIndex probe and keeps it
  when the key is absent.
* **Trace shape, all keys present: 37 calls** — probe+read pairs for the
  four gated keys (fullness, layCooldownTimer, breed,
  currentBlockheadIndex looked up twice), single lookups for the rest,
  two retains + one autorelease around the name swap, one autorelease +
  dictionary copy + retain for the tameCounts swap.
* No `objc_msgSendSuper2` in this body (no DynamicObject forward), as b3n
  asserted.

## Case table (10 cases, all matched bit-exactly)

`all_present_old_nil`, `all_present_old_set` (old name/tameCounts tokens
observed as autorelease receivers), `missing_fullness` (group-1 skip),
`missing_laycooldown` (group-2 skip), `missing_breed`, `missing_
currentblockhead` (−1 default survives), `missing_tamecounts` (no copy,
ivar nil), `missing_tamedclientid_name` (nil stores, autoreleases still
traced, copy still happens), `truncations`, `float_edges` (subnormal /
FLT_MAX / −inf / NaN / negative-zero-family bit patterns).

## Boundary

Executed evidence only where stated: synthetic dictionary/boxes/copy, not
Foundation, not the original-app runtime, not device gameplay. Retain/
release balance, the real `NSMutableDictionary` semantics and any
acceptance on a device remain outside this batch. The loader that calls
this method (`-[NPC initWithWorld:…]`, b4a) and this state load are now
both behavior-verified; the natural next slices are the `Tree
growInTimeSinceSaved:` state machine (b3n) and the Chest per-slot loop,
or the b3e write-side counterpart.
