# KelpPlant BIG loader — executed differential (batch b4n)

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`

```text
IMP:      0x00815BE8
boundary: 0x00816560 (next method IMP)
words:    606 (exact coverage asserted by this listing)
selector: initWithWorld:dynamicWorld:saveDict:cache:
          treeDensityNoiseFunction:seasonOffsetNoiseFunction:
super:    Plant          instance_size: 0xCC = 204 (class_ro_t+8)
```

The b3m-1 static decode (mirror-twin plant loaders) is executed for KelpPlant:
`tools/test_kelp_plant_init_arm.py` runs the original ARM body under Unicorn and
compares the 204-byte instance image, the return value, the tile-consume count
AND the full (code, arg) trace with
`reconstruction/recovered/kelp_plant_init.{h,cpp}` at -O0 and -O2 across
**13 cases, bit-exact**. CTest `recovered_kelp_plant_init` + guard
`tools/test_kelp_plant_init_arm_evidence.py` cover CI.

## Execution corrected two static readings

1. **The food refill is a normalised random dose, not an identity.**
   The refill path (availableFood < 0.1f) computes
   `(float)((double)((float)lrand48() / 2^31 * 900.0f) * 1.5)`, i.e. a fraction
   in [0,1) scaled to up to 1350. The two adjacent pool words at 0x815CCC and
   0x815CD0 are `900.0f` and `2147483648.0f` (2^31); a reading that took the
   second literal for a duplicate of the first turns the division and the
   multiply into a cancellation and produces "r * 1.5". The ARM stored bytes
   (`0x3A1450C0` for r = 900) match the corrected formula exactly.
2. **The `worldContentsChangedAtPos:` position is built AFTER the increment.**
   The tile query uses `y = pos.y + occupied + 1` with the pre-increment count,
   but the notification reloads the already-incremented field, so its y is the
   query y + 1.

## Harness facts

* ONE selector-string dispatcher serves `objc_msgSendSuper2` (GOT 0x0105B79C)
  and `objc_msgSend` (GOT 0x0105B7A0 + veneer slot 0x0105FB18); the super
  handler asserts the objc_super struct (receiver + the OWN class word
  0x00E91278) and all SIX forwarded arguments.
* `lrand48` (veneer 0x001C2804 -> slot 0x0105FB10) is stubbed, and the body
  reaches it through the real `0x814F44` wrapper.
* The world accessor `0x00A12F24` is hooked (it asks the world for macro tiles);
  the tile-kind helper `0x00A11690` and the `0x004B49FC` position builder run
  **natively** against fixture tile bytes, so the tile gate and the notification
  struct are the real instructions.
* Branch edges are kept as the ARM compares them: `blt` (N!=V, unordered taken),
  `bpl` (N==0), `ble`/`MOVGT` on the f32 compares — a NaN takes the same edge in
  the contract as in the original.
* Shared-harness fix: `MsgDispatcher` read only 64 bytes of the selector string.
  The long-variant selector is ~99 chars, so the stub saw a truncated name and
  raised "unimplemented message". It now reads 256 bytes (this was the first
  long-variant method executed at Level-B).

## Case table (13 cases, all matched bit-exactly)

```text
super_nil                     trace 1   (nil super -> nil)
no_growth_timer_low           trace 13  (timer <= threshold; full tail ran)
food_refill                   trace 14  (0.05 -> lrand48 dose)
food_refill_negative_rand     trace 14  (negative lrand48 value)
frozen_gate                   trace 9   (returns right after the food stage)
die_of_old_age                trace 13  (age overflow, no compost)
compost_adjust                trace 14  (elapsed rewritten; age 999.9)
growth_single_tile            trace 16  (2 queries: grow, then blocked)
growth_blocked_tile_marker    trace 14  (tile byte 11 != 0 -> timer = 0)
growth_blocked_wrong_kind     trace 14  (tile byte 0 != 3 -> timer = 0)
growth_multi_tile             trace 22  (5 queries, occupied 2 -> 6)
occupied_limit                trace 13  (15 tiles -> no growth)
no_tile_answer                trace 14  (no world answer -> timer = 0)
```

## Boundary

Executed differential evidence for this method only: synthetic fixtures, not
Foundation, not the original-app runtime, no APK/device acceptance. The
remaining decode-only front members are VinePlant (681w, the mirror twin),
FreeBlock (1,347w) and Workbench (1,390w).
