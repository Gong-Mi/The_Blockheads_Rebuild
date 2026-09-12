# ITEM_MONEY currency-split region: recovered local method

Original input: Android 1.7.6 ARM32 `libApplication.so`, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`.
Region `0xc628f8..0xc62fec` of
`Blockhead -pickupFreeblockIfPossible:inTile:intentional:`.

Recovered as `inventory_pickup_currency.cpp` under
`recovered::pickup_currency::splitMoney`, a sibling module of the parent
pickup contract; the parent still refuses the whole pending region through
`pendingPathUnresolved()` (integration behind the parent's resolved-freeblock
argument is future work, this module is NOT wired into the parent).

## Corrected static structure (CFG-based manifest)

`tools/recover_pickup_currency.py` regenerates
`inventory_pickup_currency.json` + `disasm_inventory_pickup_currency.txt`.
It supersedes the coarse POOLS list of `recover_inventory_pickup.py` for
this span: that list mislabelled code words as pool data (for example
`0xc62bd8` onward is live code; the "pool at 0xc62bb8" claim in the earlier
contract actually spans `0xc62bb8..0xc62bd8`, seven PIC slots + PIC base).
The new split is driven by a worklist CFG plus a hard rule: any word
referenced by a pc-relative load is data (capstone decodes pool words such
as the PIC base as `ldrsbteq`). Exact pools: `0xc62bb8..0xc62bd8`,
`0xc62dac..0xc62db8`, `0xc62f8c..0xc62f9c`, `0xc63300..0xc63340`,
`0xc63804..0xc638a0`.

Earlier guesses were also wrong in two places and are now corrected with
evidence:
- The "three循环 keyed by 0x104/0xa7/0xa6" framing is right, but the helper
  at `0xc62c00`/`0xc62de0` labelled "analyzed separately" is `__aeabi_idiv`
  and `__modsi3` (PLT stub GOT slots `0x106001c`/`0x105fdc4`): the original
  computes `dataB/100` and `dataB%100` directly.
- The old note "0xc62fb8 smmul-by-constant scaling" is exact: magic
  `0x68db8bad`, `asr #12`, `add r0, r2, r0, lsr #31` == signed `/10000`,
  and `mls r0, r1, #0x2710` == `%10000` of the residual. `makeIntpair`
  (`_Z11makeIntpairii` at `0x4b49fc`) packs those two into the tail.

## Executed behavior contract (message order is mandatory)

1. `itemType@freeblock` (`0xc628f8`). If `0xb`: `setNeedsRemoved:@f=1`
   (`0xc6292c..0xc62968`, signed 1 through `sxtb`), then FALLS THROUGH
   (no early return — proven by the executed ARM trace continuing).
2. `itemType@freeblock` again (`0xc6296c`). `!= 0x12a` leaves the region at
   `0xc63340` (achievement tail, out of scope here).
3. `dataA@f` then `dataB@f` (`0xc629b0..0xc62a14`), each result through
   `uxth` (low 16 bits, zero-extended).
4. Three bounded insertion loops, denoms platinum `0x104`, gold `0xa7`,
   copper `0xa6` (server `ItemType`: 260/167/166):
   - loop while `inserted < limit`; per-iteration gate
     `[self canPickUpItemOfType:denom subItems:nil dataA:0 dataB:0]`
     must return exactly 1 (`cmp #1`, not <1, not !=0);
   - on pass: `[InventoryItem alloc]` ->
     `[item initWithType:denom dataA:0 dataB:0 subItems:nil
     dynamicObjectSaveDict:nil]` -> `autorelease` ->
     `[self addItemToInventory:item flash:1]` (return value NOT read);
   - on fail: this level ends immediately, no more inserts at it.
5. Cascade limits (frame slots re-read from the ORIGINAL fields each time):
   - `limit1 = uxth(dataA)`
   - `limit2 = (dataA - platinum) * 100 + dataB / 100`  (`__aeabi_idiv`)
   - `limit3 = (limit2 - gold) * 100 + dataB % 100`     (`__modsi3`)
6. `residual = limit3 - copper` (`0xc62f9c..0xc62fa8`).
   `> 0` enters the makeIntpair/achievement tail; `<= 0` exits at
   `0xc630a8`. Both tails read lazily initialized `.bss` ivar-offset slots
   `0x145c418/0x145c508/0x145c5e4` — above `_end` (`0xfcbf97` in-file),
   statically unresolvable, therefore NOT recovered. The C++ models
   thousands/remainder for the oracle but callers must not side-effect past
   the stop edges.

Denomination model implied by the constants: 1 platinum = 100 gold =
10000 copper (the /100, %100, *100, 10000-magic chain is a unit cascade;
dataA counts platinum-scale units, dataB sub-platinum copper cents). This
semantic naming is inference from executed arithmetic, labelled C-level for
the *names*, A-level for the arithmetic itself.

## Verification

- Contract fixtures `tools/test_inventory_pickup_currency.cpp`
  (`recovered_inventory_pickup_currency` in CTest; O0 and O2 builds,
  27/27 total).
- Executed original-ARM differential `tools/test_pickup_currency_arm.py`:
  runs the pinned bytes `0xc628f8..` and hooks ONLY `objc_msgSend` (both
  the PIC import slot and the PLT-stub GOT), `__aeabi_idiv` and
  `__modsi3`; the loops, counters, *100 cascade and /10000 magic execute as
  original instructions. Frame counters are poisoned (`0xdead`) before each
  case. 288 cases (3 types x 4 dataA x 4 dataB x 6 gate streams incl.
  `uxth` wrap inputs) match the C++ probe on EVERY case at O0 and O2: full
  selector+receiver+denom trace, chosen stop edge, P/G/C counts and K/R.
  Four negative controls are detected: limit3 base change (54), dropped
  0xb `setNeedsRemoved:` (96), dropped `uxth` on dataA (24), non-strict
  gate comparison (28).

Reproduce (pyelftools, Unicorn, clang++ required; original ELF not bundled):

```sh
LIBUNICORN_PATH="$PREFIX/lib" python3 tools/test_pickup_currency_arm.py \
  "$HOME/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so" \
  --output-dir "$HOME/blockheads-work/currency-verify"
```

## Boundaries

Synthetic receivers only: no Foundation, no real InventoryItem, no original
app execution, no Android device. `behavior-verified` for the parent method
stays 0 in the ledger; this region is implemented-with-recorded-boundaries.
Integration order that remains: resolved-freeblock plumbing from the parent
(lookup region still pending), then the three lazily resolved tail slots.
