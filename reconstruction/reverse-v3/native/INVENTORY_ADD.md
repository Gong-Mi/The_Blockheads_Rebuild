# Inventory add: recovered object-runtime slice

## Scope and evidence

- Repository base inspected: `473899a`.
- Original ARM32 ELF: `~/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so`.
- SHA-256: `733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`.
- Implemented all four overloads in `reconstruction/recovered/inventory_add.cpp`:
  - `0xc5f904..0xc5f960`: `addItemToInventory:`
  - `0xc5f960..0xc5f9d8`: `addItemToInventory:flash:`
  - `0xc5f9d8..0xc5fa6c`: `addItemToInventory:flash:disableWarpCheck:`
  - `0xc5fa6c..0xc61c00`: `addItemToInventory:flash:disableWarpCheck:forceSlotIndex:`
- Existing `inventory_add.json` and `disasm_inventory_add.txt` regenerated in memory and checked against the pinned ELF by `recover_inventory_add.py --check`: PASS. Extractor reports 2,188 instructions, 130 calls, four methods. Word/call coverage is an audit index, **not** a native behavioral differential result.

## Implemented contract

The first three methods dispatch the next distinct selector dynamically, supplying respectively `flash=0`, `disableWarpCheck=0`, and `forceSlotIndex=-1`. They do not bypass Runtime overrides by directly calling the full implementation.

The full method preserves the following priority:

| Pass | ARM region | Selection |
|---|---|---|
| 1 | `c5fc64..c601e0` | Matching occupied outer stack |
| 2 | `c601e0..c60a10` | Matching occupied substack in a carried modifiable container |
| 3 | `c60a10..c60cb8` | Empty outer stack |
| 4 | `c60cb8..c61698` | Incoming modifiable container absorbs a whole occupied outer stack |
| 5 | `c61698..c61ba4` | Empty substack in a carried modifiable container |

- Outer indices are **1 through 7**, not the prototype's 30-slot domain. No prototype numeric IDs are connected.
- Force-slot filtering exists only in passes 1–3. Passes 4–5 deliberately ignore it.
- Passes 1–2 first require `itemTypeIsStackable(initialType,0,0)`. Their per-candidate callback order differs and remains separate in the source.
- Matching stacks require fresh counts below 99. Positive `usageIncrementPerUse(initialType,2,0,0)` inserts before the first strictly larger `dataA`, otherwise appends; counts and item fields are dynamically re-read.
- Pass 4 prefers the first empty incoming substack. If none is selected, it sends `subItems` again and enumerates compatible occupied substacks; combined unsigned 32-bit count must be at most 99, and source type `0x67` additionally requires equal `dataB`. The empty-substack path has no 99 cap. Transfer order is `addObjectsFromArray`, `removeAllObjects`, `addObject`—not sorted per-item insertion.
- Passes 2 and 5 write sub-change bytes only when the signed sub-index is `<4`, while the flash still receives the full sub-index. Other successful passes write the outer-change byte and flash sub-index `-1`.
- Fast enumeration uses batches of 16, one mutation baseline across batches, mutation checks before each element, and re-reads the state's item pointer after a returning mutation handler.
- Success returns the **outer index**, exhaustion/invalid item returns **-1**; never an accepted-item count. The warp callback's return value is discarded.
- Achievements (`0x117`: `grp.titanium`; `0x105`: `grp.mj.platinum`) and non-network found-list effects happen before selection, even if inventory is exhausted. World is re-read per use. Flash precedes the optional warp callback; warp gets initial type and freshly read item `dataB`.
- Linked actual recovered rules in `blockheads::recovered` and `inventory_capacity::subItemCapacityAtC5EAA8`; no helper stubs. The pinned original liquid and carries-liquid helpers return zero, but their calls/gates remain expressed.

## Verification

Executed successfully at both **O0 and O2**, with `-Wall -Wextra -Werror`, linking the actual recovered rules and capacity source:

```sh
cd ~/The_Blockheads_Rebuild
python tools/recover_inventory_add.py \
  --elf ~/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so --check
for opt in 0 2; do
  clang++ -std=c++17 -O$opt -Wall -Wextra -Werror \
    tools/test_inventory_add.cpp \
    reconstruction/recovered/inventory_add.cpp \
    reconstruction/recovered/inventory_rules.cpp \
    reconstruction/recovered/inventory_capacity.cpp \
    -o /data/data/com.termux/files/usr/tmp/test_inventory_add_O$opt && \
  /data/data/com.termux/files/usr/tmp/test_inventory_add_O$opt || exit
done
```

Both test executables printed:

```text
inventory_add: wrapper dispatch, five passes, re-reads, mutation and effects passed
```

Tests exercise wrapper override dispatch, invalid and nil items, five-pass priority, force-slot exceptions, full stacks, incoming container absorption, special dataB mismatch, ordered insertion, found/achievement/flash/warp order, dynamic world/type/dataB/count changes, sub-index 3/4 boundary and multi-batch index 17, throwing and returning mutation handlers.

Two pre-existing fixture assumptions were corrected rather than weakening the linked rules/implementation:

1. ItemType `2` is invalid in the real recovered rules. Default fixture item and matching items now use original type `4`, with a positive validity assertion and explicit type-2 rejection test. Object identity `2` remains unchanged.
2. The count-mutation scenario sees four reads of outer slot 1: two in pass 1, one in pass 2, one in pass 3—not three.

## Remaining boundaries

- These are executable **fixture-runtime tests**, not whole-method original ARM/Unicorn differential tests. The parent's independent helper differential results must not be attributed to these four add methods.
- Runtime is a mandatory abstract interface. The production ObjC/Foundation bridge, ownership/retain/release, nil messaging, exceptions, object identity, mutation pointer lifetime, UI, achievements, found-list persistence and warp effects are not supplied by this slice. None silently return canned values in production source.
- Enumeration contract requires valid `items` and `mutations` pointers whenever a positive batch count is returned. Invalid/dangling pointers, arbitrary native stack aliasing and asynchronous races are not portable compatibility guarantees. Returning mutation handlers and synchronous object callbacks are covered by fixtures.
- 32-bit counters/sums preserve wrapping in source. Billions-of-elements counter wrap, malicious enumerators and pathological callback-induced nontermination have not been executed in tests.
- No CMake/app integration, no foreground device actions, no APK/device gameplay acceptance, no commit or push in this task.
