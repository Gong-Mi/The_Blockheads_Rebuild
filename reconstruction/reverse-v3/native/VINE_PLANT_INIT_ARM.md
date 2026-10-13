# VinePlant BIG loader — executed differential (batch b4o)

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`

```text
IMP:      0x004F68A0
boundary: 0x004F7344 (next method IMP from the pinned ObjC method map)
words:    681 (exact coverage asserted by this listing)
selector: initWithWorld:dynamicWorld:saveDict:cache:
          treeDensityNoiseFunction:seasonOffsetNoiseFunction:
super:    Plant          instance_size: 0xB8 = 184 (class_ro_t+8)
```

The b3m-1 static decode's mirror twin is executed for VinePlant:
`tools/test_vine_plant_init_arm.py` runs the original ARM body under Unicorn and
compares the 184-byte instance image, the return value, the tile-consume count
AND the full (code, arg) trace with
`reconstruction/recovered/vine_plant_init.{h,cpp}` at -O0 and -O2 across
**15 cases, bit-exact**. CTest `recovered_vine_plant_init` + guard
`tools/test_vine_plant_init_arm_evidence.py` cover CI.

## Decoded differences from the KelpPlant twin (b4n)

1. **No Plant.frozen gate.** KelpPlant returns early when `frozen != 0`;
   VinePlant has no such read — the `occupied_limit` case (15 tiles, huge
   timer) runs the full tail with no growth.
2. **Mirrored growth axis.** The growth cell is
   `y = pos.y - numberOfOccupiedTilesBelow - 1` (KelpPlant: `y + above + 1`),
   and the marker is written into the tile BELOW the plant.
3. **EXTRA tile-suitability scan (~75 words).** Two `__aeabi_idiv` calls and
   a light/sun key: `key = tile.byte[7] * 0.4 / 255 + lightSum` where
   `lightSum = (half[7]/4 + half[8]/4 + half[9]/2) / 1024`; growth requires
   `key > 0.2f` (case `growth_light_boundary` proves the exact edge).
4. **Inverted tile-kind gate.** The `0x00A11690` helper must return **0**
   (KelpPlant: must return non-zero), i.e. `tile[0] == 3` is REJECTED, and
   `tile[0] == 31` is rejected too; the marker byte is `0x7C` (KelpPlant:
   `0x51`).
5. **Energy constant 900.0f** (KelpPlant: 225.0f), in both the refill dose
   (`lrand48()/2^31 * 900 * 1.5`) and the growth threshold (`900/factor`).
6. **The `worldContentsChangedAtPos:` y equals the query y** (KelpPlant:
   query + 1): VinePlant's notification is built from the same y the tile
   query used, before the increment is reloaded.

## Harness facts

* Same shared dispatcher as b4n: `objc_msgSendSuper2` (GOT 0x0105B79C) and
  `objc_msgSend` (GOT 0x0105B7A0 + veneer slot 0x0105FB18); the super handler
  asserts the objc_super struct (receiver + the OWN class word 0x00E90558,
  superref slot 0x00E8BC40) and all SIX forwarded arguments.
* `lrand48` (veneer 0x001C2804 -> slot 0x0105FB10) is stubbed, reached through
  the real `0x004F688C` wrapper.
* The world accessor `0x00A12F24` is hooked; the tile-kind helper `0x00A11690`
  and the `0x004B49FC` position builder run **natively** against fixture tile
  bytes, so the inverted kind gate and the notification struct are the real
  instructions. `__aeabi_idiv` is stubbed with real signed 32-bit division.
* Branch edges kept as the ARM compares them: `blt` (N!=V, unordered taken),
  `bpl` (N==0), `ble` on the f32 compare — a NaN takes the same edge in the
  contract as in the original.

## Case table (15 cases, all matched bit-exactly)

```text
super_nil                     trace 1   (nil super -> nil)
no_growth_timer_low           trace 13  (timer <= threshold; full tail ran)
food_refill                   trace 14  (0.05 -> lrand48 dose)
food_refill_negative_rand     trace 14  (negative lrand48 value)
die_of_old_age                trace 13  (age overflow, no compost)
compost_adjust                trace 14  (elapsed rewritten; age 999.9)
growth_single_tile            trace 16  (2 queries: grow, then blocked)
growth_blocked_kind3          trace 14  (kind helper != 0 -> timer = 0)
growth_blocked_byte0_31       trace 14  (tile[0] == 31 -> timer = 0)
growth_blocked_marker         trace 14  (tile byte 11 != 0 -> timer = 0)
growth_blocked_too_dark       trace 14  (light key <= 0.2 -> timer = 0)
growth_light_boundary         trace 16  (key just above the gate: grows)
growth_multi_tile             trace 22  (5 queries, occupied 2 -> 6)
occupied_limit                trace 13  (15 tiles -> no growth)
no_tile_answer                trace 14  (no world answer -> timer = 0)
```

## Boundary

Executed differential evidence for this method only: synthetic fixtures, not
Foundation, not the original-app runtime, no APK/device acceptance. The
remaining decode-only front members are FreeBlock (1,347w) and
Workbench (1,390w).
