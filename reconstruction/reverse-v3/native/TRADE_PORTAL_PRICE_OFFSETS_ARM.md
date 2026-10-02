# TradePortal -[loadPriceOffsets:] — executed differential (batch b4i)

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`

Boundary from the pinned ObjC method map:

```text
IMP:      0x00d37a78
boundary: 0x00d37d8c (next method IMP)
words:    197 (exact coverage asserted by the b3n listing)
types:    v8@0:4 (void return, one dictionary argument: localPriceOffsets source)
```

The b3n decode of this method (the price offset normalization pass over
`TradePortal.localPriceOffsets`, static level-A) is now **executed**:
`tools/test_trade_portal_price_offsets_arm.py` runs the original ARM body under Unicorn
with synthetic dictionary fixtures and compares the resulting 160-byte
instance image and the full message trace against the recovered C++
contract `reconstruction/recovered/trade_portal_price_offsets.{h,cpp}` at -O0 and -O2.
`tools/test_trade_portal_price_offsets_arm_evidence.py` guards it in both host and CI modes;
CTest `recovered_trade_portal_price_offsets` exercises the contract without the ELF.

## Harness topology (stated limits)

* `objc_msgSend` (GOT slot 0x0105B7A0) is stubbed:
  - `countByEnumeratingWithState:objects:count:` on sourceDict
  - `objectForKey:` on sourceDict -> returns boxed double
  - `doubleValue` on boxed double -> returns f64 softfp pair r0:r1
  - `[NSNumber numberWithDouble:clamped_d0]` (receiver is `OBJC_CLASS_$_NSNumber` 0x00E8B754)
  - `[self->localPriceOffsets setObject:num forKey:key]`
* `memset` (0x001C2924 via slot 0x0105FB70) executes natively.
* `objc_enumerationMutation` (0x001C2E28 via slot 0x0105FD1C) is stubbed as a no-op.
* The two-level ivar-offset resolution executes for real:
  - `OBJC_IVAR_$_TradePortal.localPriceOffsets` = 128 (self + 128)

## What execution confirmed

* **The clamp rule is [0.5, 2.0] exact**:
  - `vcmpe.f64 d0, d1` (compare with 0.5) followed by `bpl #0xd37c24`: if d0 < 0.5,
    value is clamped to 0.5.
  - `vcmpe.f64 d1, d0` (compare with 2.0) followed by `ble #0xd37c50`: if d1 > 2.0,
    value is clamped to 2.0.
  - Within [0.5, 2.0], raw value is preserved unmodified.
* **Fast-enumeration loop shape**: 16-element stack buffer chunking; terminal
  enumeration call returns 0.
* **Dictionary rebuilding**: for each key, the clamped double is boxed into an
  `NSNumber` and stored into `self->localPriceOffsets` at offset 128.

## Case table (6 cases, all matched bit-exactly)

* `empty_dict`: empty source dictionary; loop skipped; exits cleanly.
* `clamp_low_edge`: values 0.1, 0.499999 (clamped to 0.5) and 0.5 (preserved).
* `clamp_high_edge`: values 2.0 (preserved), 2.00001, 100.0 (clamped to 2.0).
* `within_range`: values 0.75, 1.0, 1.5 within [0.5, 2.0] untouched.
* `negative_values`: negative values (-10.0, -0.0001) clamped to 0.5.
* `nan_float`: NaN float passes through VFP comparison without clamping.

## Ledger state

- Persistence core: 149/149 closed at static level-A.
- Executed Level-B differentials: b4a (NPC loader) + b4b (Plant) + b4c (Forwarders) + b4d (Tree stage 1) + b4e (Tree fruit records) + b4f (NPC loadValues) + b4g (Tree growth stage 1) + b4h (FreightCar 4th variant) + **b4i (TradePortal price offsets)**.
