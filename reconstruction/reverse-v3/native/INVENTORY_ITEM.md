# InventoryItem logical method recovery

Input: original Android 1.7.6 ARM32 `libApplication.so`, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`.

## Scope

`inventory_item.h/.cpp` implement the local logical bodies of fourteen instance
methods: initWithType, initWithSaveData, saveData, two subslot methods and nine
scalar/reference getters/setters. They also restore the complete numeric
subItemSlotCount helper at 0xac5b4c. `dealloc` and Foundation/NSObject allocation,
reference counting, arbitrary subclasses and runtime dispatch are not ported.

This is a typed logical model for newly allocated ordinary items and stable
ordinary arrays, not a complete Objective-C ABI/runtime replacement. The
required `InventoryRuntime` supplies NSObject initialization success, explicit
stack bytes, gzip and property-list operations. There is no production fake
codec. Typed C++ recursive calls/arrays do not emulate arbitrary subclass
selectors, re-entrant array mutation, replacing-self initializers or Foundation
exception identity. C++ fences mirror observed barrier positions, not a proof of
thread-safe mutation or identical refcount lifetimes.

## Recovered contracts

- `initWithType:dataA:dataB:subItems:dynamicObjectSaveDict:` @0xac5644:
  int32 type, uint16 A/B, retained opaque dynamic-object identity. Container slot
  counts are selected by numeric native helper, not inferred from item names.
  Creates fresh slot arrays, shallow-copies child identities, pads missing input
  slots and ignores extra input slots. Types with no subslots ignore that input.
- `initWithSaveData:` @0xac5dd8:
  copies min(length,8) bytes into an original uninitialized stack header. Loads
  unsigned16 type, uint16 A/B and uint8 selected index. Length>8 inflates the tail,
  decodes a property list with options0, reads keys `d` and `s`, and recursively
  initializes children. Missing `s` is nil/empty; present but short arrays reach
  the original objectAtIndex failure rather than silently padding.
- `saveData` @0xac64d4:
  writes low16 type, A16, B16 and selected8 into an eight-byte header. Byte7 is
  not written in the original; it is NOT a version field. The logical API
  requires an explicit stack image, so it never reads actual uninitialized C++
  memory. This means exact raw bytes require the supplied stack-byte choice;
  semantic equality is not a deterministic original serialization assertion.
  Nonempty child slots become all ordered `s` slot arrays; an all-empty bag omits
  `s`. Nonnil dynamic identity produces `d`. A nonempty tail dictionary is encoded
  as XML property-list format100/options0 and gzip-compressed before appending.
- `updateSubItemSlot:atIndex:` @0xac6ddc and
  `subItemSlotDataAtIndex:` @0xac7130:
  unsigned strict-less bounds are preserved. Negative indexes become large and
  are rejected; index==count continues to array access and can throw. Update
  clears the existing mutable slot before recursive child creation; it does not
  replace the slot identity. Nil slot zero still performs the observed messages.
- Getters/setters @0xac745c..0xac76a8 preserve raw field widths, selected index
  without clamping, and explicit barrier placements.

## Evidence and tests

`recover_inventory_item.py` verifies fixed ELF identity, parses nineteen bounded
regions with code/literal distinction, PIC references/ivar symbols/relocations,
CFString keys and helper code. Its manifest records 2025 instructions, 139 pool
words, 99 calls and fourteen logical methods. This coverage count is not itself
semantic or runtime equivalence. Exact source routes and boundary notes are also
recorded in `inventory_item.json` and inline implementation anchors.

    python3 tools/recover_inventory_item.py --elf /absolute/original.so
    python3 tools/recover_inventory_item.py --elf /absolute/original.so --check

The interrupted children preserved source and passing test output before timeout;
the parent reruns the final files and evidence commands before publication.
C++ tests use an explicitly labelled codec spy, not made-up gzip/plist samples.
They exercise header widths, identity/shallow-copy behavior, nil initialization,
recursive tail calls/order, missing-vs-short `s`, partial header inputs and
subslot mutation/bounds. The composition test uses actual InventoryItem getters,
capacity and add methods on a shared fixture graph, then real plain-header save
and load; it is not original Android/World integration.

## Android adapter blocker

Current `Player` is a thirty-slot type/count prototype in a different numeric
item domain. It cannot represent these nested arrays and opaque dictionary
identities. Replacing its calls directly would lose data and change save/UI
contracts. No synthetic conversion into that flattened inventory is shipped.
Real Foundation codec, original World effects and a lossless original inventory
loader/UI boundary remain prerequisites for Android gameplay integration.
