# Original inventory direct helper recovery

`inventory_rules.cpp` restores eight complete Android 1.7.6 C++ helper bodies,
including their direct dependencies, from the hash-pinned ARM ELF. These are C++
exports, counted separately from the Objective-C IMP ledger. No semantic enum
names are guessed from the replacement project's item database.

| Function | Original address | Complete bytes |
|---|---|---|
| itemTypeIsValidFillItem | 0x00580cdc | 384 |
| itemTypeIsValidInventoryItem | 0x00c5e9ac | 116 |
| itemTypeIsLiquid | 0x00c5ea20 | 24 |
| itemTypeCarriesLiquids | 0x00c5ea90 | 24 |
| itemTypeSubItemsCanBeModifiedWhileCarried | 0x004eb960 | 68 |
| itemTypeCanBeColored | 0x004d6128 | 248 |
| itemTypeIsStackable | 0x004ea3cc | 244 |
| usageIncrementPerUse | 0x005e9c30 | 884 |

Important recovered conditions:
- Valid-fill uses signed bounds; some negative integers pass. Do not silently
  replace this original predicate with a generic positive-ID validator.
- Liquid/carries-liquid always return zero. Their names do not imply reachable
  liquid inventory behavior in this build.
- Mutable carried subitems are types1/12, and make items unstackable even when
  the two compared values are equal. Otherwise equality comes before special
  type0x67/0x5b exclusion and color zero/nonzero equivalence.
- Usage preserves mode==0, unknown-type -1, integer rounding, flag3 precedence,
  subsequent mode doubling/halving and a final positive-path lower bound of1.

## Real instruction differential

`tools/recover_inventory_rules.py` executes these original ARM bodies and their
internal dependencies under Unicorn. Only the imported __aeabi_idiv is an
explicit signed-integer shim; all eight helper bodies use original instructions.
The recovered C++ is compiled as both O0 and O2, then compared per input.

The executed run matched 42,788 inputs. Per-helper counts, symbol/size identity,
complete fixed instruction words and region hashes are in `inventory_rules.json`.
Every input and its actual ARM/O0/O2 result was saved locally in
`~/blockheads-work/gameplay-audit/inventory-rules/differential/cases.jsonl`.
This is a bounded original-instruction oracle, NOT original app/Android runtime
execution, proof for all integer inputs, or GPU/gameplay acceptance.

    LIBUNICORN_PATH="$PREFIX/lib" python3 tools/recover_inventory_rules.py \
      /absolute/original.so --output-dir /absolute/helper-differential

Mandatory C++ boundary tests are independent of copyrighted ELF availability.
The original input SHA is
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`.
Wrong SHA is rejected before fixed-address execution. Original binaries and full
per-input logs are not committed. Native Unicorn 2.1.4 was used on Termux; the
installed Python wheel's bundled shared library could not be loaded here.
