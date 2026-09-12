# Ownership removal helpers: complete local recovery

Pinned original Android 1.7.6 ARM ELF SHA256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`.

These seven pure functions are implemented in `inventory_ownership.cpp`, under
`blockheads::recovered::ownership`. Item IDs remain original int32 values;
there is no replacement Player ID conversion or uint16 truncation.

| Function | Original range (end exclusive) |
|---|---|
| workbenchKindForItemType (descriptive local name; original symbol unresolved) | 0x5deeb8..0x5df240 |
| itemTypeIsWorkbench | 0x5b2aa0..0x5b2ad4 |
| itemTypeIsTorch | 0x5df794..0x5df88c |
| itemTypeIsStairs | 0x5b2b0c..0x5b2ca0 |
| itemTypeIsColumn | 0x5b291c..0x5b2aa0 |
| itemTypeIsPainting | 0x5b902c..0x5b90c0 |
| itemTypeRequiresOwnershipToRemove | 0x627c40..0x627f74 |

## Source recovery

The ownership function tests five explicit IDs, then workbench classification,
then another explicit-ID list, then torch/stairs/column/painting in that order,
and finally equality to 0xb2. Returns are signed char 0/1. Its dependency on
workbench classification is closed by restoring the complete direct callee's
int32 output, not a guessed bool table. PC-relative tables at 0x5defb0 and
0x5df004 use table-base + stored relative word; all return arms and the default
are preserved. Workbench kind names are not inferred from integer values.

Notable original distinctions: 0x429 true vs 0x428 false; 0xa5 true vs 0xa6
false; 0x14c column vs 0x14d stairs. Painting is exactly 0xd4..0xdc; 0xdd is a
workbench input, not a painting. Negative/large int32 inputs do not wrap to a
uint16 item. Original switches have been expressed as readable C++ switches;
this is source recovery/preservation, not a claim of historical test-first TDD.

## Executed verification

`tools/test_inventory_ownership_arm.py` maps the hash-pinned ELF and runs the
seven complete original bodies under Unicorn, including their original direct
calls and jump tables. NO helper, import or message hooks. For each function,
66,567 inputs (all 0..65535, signed boundaries and seeded int32 samples) match
both C++ O0 and O2. Total 465,969 function/input pairs; 931,938 C++ comparisons.
This is not exhaustive over all int32 bit patterns. Full raw nonzero input/output
sets, function byte hashes and zero mismatch lists are persisted in
`inventory_ownership_evidence.json` (an execution report, not a table used by
production code). The source is hand-recovered from the instruction bodies;
Unicorn is the independent executable oracle.

```sh
LIBUNICORN_PATH="$PREFIX/lib" python3 tools/test_inventory_ownership_arm.py \
  "$HOME/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so" \
  --output-dir "$HOME/blockheads-work/ownership-verify"
```

CTest `recovered_inventory_ownership` executes explicit boundary and dependency
checks without the original ELF. It is part of the existing recovered inventory
library test suite; CI uploads its test executable with the library. The ARM
oracle is local-only because the original ELF is not distributed by this repo.

## Integration boundary

The pickup call at 0xc6225c calls this classification helper. Recovering the
helper does not recover the surrounding expectedCraftItems search, isAdmin,
ownership access check or special removal effects. The new helper library is
NOT yet called by the incomplete pickup adapter or APK. No World modification,
Foundation or Android gameplay acceptance is claimed. Seven C++ helpers are
tracked here separately: do not add them to the 36-entry Objective-C method
ledger or increase its full-method behavior-verified count.
