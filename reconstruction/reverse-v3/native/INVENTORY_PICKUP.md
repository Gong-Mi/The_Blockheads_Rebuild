# Original pickup method: ordinary freeblock insertion path

Original input: Android 1.7.6 ARM32 `libApplication.so`, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`.

## Recovered local method

`Blockhead::pickupFreeblockIfPossible:inTile:intentional:` implements the
ordinary freeblock pickup decision in `inventory_pickup.cpp`, with explicit
dynamic receivers, field re-reads and message order. The original return is
signed char: 1 success, 0 rejection; neither bool nor accepted count.

Executed order (original instruction anchors):
- entry gate: world = [[self + DynamicObject.world]] (ivar +4) then
  worldUIDragging(world), nonzero rejects (0xc61c48..0xc61c6c);
- state is INLINE storage: self + Blockhead.state offset (+0x38), NOT
  a pointer loaded from that location. Signed bytes at storage+0x60/+0x68
  nonzero reject (0xc61c7c..0xc61cbc). The old double-dereference description
  in 14f3574 was incorrect; `stateStorageAddress` makes the boundary explicit.
- priorityBlockhead send on the freeblock (0xc61cd0..0xc61cfc);
- intentional gate (0xc61d00..0xc61d84): with intentional==0, a set
  ignoringFreeblocksDueToDrop byte (ivar +0x2b4) or nonzero meditating requires
  priority==self to continue; intentional nonzero skips this region;
- non-nil foreign priority rejects (0xc61d88..0xc61db4);
- ordinary fields of the resolved freeblock: itemType/subItems/dataA/dataB
  (distinct reads);
- canPickUpItemOfType:subItems:dataA:dataB: result must equal exactly 1
  (original `cmp r0,#1`); other values reject;
- needsRemoved nonzero rejects (duplicate-pickup guard);
- InventoryItem construction preserving type/A/B/subItems/dynamicObjectSaveDict
  (explicit read before the dynamic constructor message);
- addItemToInventory:flash:1; the return slot is NOT used to branch, only as
  recording payload;
- freeblock setNeedsRemoved:1;
- indexed-record comparator: equal branch executes one recording callback, both
  branches reach success;
- failure block: only when priorityBlockhead == self, the freeblock receives
  priorityBlockheadCannotPickup; otherwise silent 0.

## Not recovered (explicit boundaries, no guessing)

- Freeblock/tile lookup and container-enumeration region 0xc61dd0..0xc626d8:
  the local method reads resolved freeblocks through the lookup chain. The
  recovered function requires a resolved freeblock as its argument; the lookup,
  fast enumeration and Tile-pack copies in this region are not ported.
- Ownership special-item branches (0xc6225c itemTypeRequiresOwnershipToRemove
  and the 0x428/0x429/0xcf/0xa8/0xa4..0xa6 sub-branches) are not implemented.
- Currency-split loop 0xc62900..0xc63440 is NOW RECOVERED as the sibling
  module `recovered::pickup_currency::splitMoney`
  (`inventory_pickup_currency.cpp`, contract `INVENTORY_PICKUP_CURRENCY.md`):
  three strict-gate insertion loops keyed by 0x104/0xa7/0xa6, uxth field
  truncation, cascade limits via __aeabi_idiv/__modsi3 (`0xc62c00`/`0xc62de0`
  are PLT stubs, not opaque helpers), residual/10000 via the smmul magic +
  makeIntpair. The parent still refuses the region through
  `pendingPathUnresolved()` until the lookup region supplies the resolved
  freeblock. The earlier "residual-tail slots 0x145c418/0x145c508/0x145c5e4
  above `_end` are statically unresolvable" claim was wrong: they are
  GOT-anchor recomputes (`add rN, pc, rN` after the literal load), and with
  that rule every literal in the method resolves (see
  `INVENTORY_PICKUP_CURRENCY.md` correction note). The C++ models the
  residual K/R arithmetic for the differential but production callers must
  not execute tail side effects: the tails are manifest evidence only.
  dataA/dataB denomination names
  remain inference-labelled (C evidence); arithmetic itself is A evidence.

Integration with a game Runtime therefore requires implementing the dynamic
selector bridge and deciding the pending paths. Until then this module is not an
Android gameplay adapter and it does not make the APK playable.

## Manifest

`recover_inventory_pickup.py` pins the ELF hash, checks the PIC base and
objc_msgSend import, resolves 29 selector slots and 9 ivar slots
(state / ignoringFreeblocksDueToDrop / isClientBlockheadBeingControlledByServer /
unconfirmedPickups / thisFramePickupRequests / DynamicObject world/dynamicWorld/pos),
enumerates 80 calls and decisive byte anchors. Outputs:
`inventory_pickup.json` and `disasm_inventory_pickup.txt`.

## Verification

Behavioral fixture `tools/test_inventory_pickup.cpp` runs against the local
implementation O0 and O2: gate rejection with exact message order, foreign and
self priority gates, ordinary success order and preserved freeblock fields,
capacity==1 strictness (0/2 reject), needsRemoved duplication guard, comparator
record branch, pending-path refusal, nil freeblock/item construction failure and
silent vs tip rejection. These are synthetic-runtime contracts, not Foundation,
original-app or device execution.

### Executed original-ARM entry differential

`tools/test_pickup_entry_arm.py` executes the pinned original bytes from
0xc61c00 until entry rejection/return or BEFORE 0xc61db4. It hooks only
objc_msgSend with explicit synthetic receivers; signed field loads, conditional
branches and the stack argument load run unchanged. The fifth argument is at
entry SP, not entry SP+8. The inline state's first word is poisoned with an
unmapped address, so a mistakenly added pointer dereference cannot pass.

O0 and O2 each match all 2,187 input combinations (zero/positive/negative signed
bytes across dragging/state/intentional/ignoring/meditating and nil/self/foreign
priority). Compared outputs are entry continuation/rejection AND selector/field
read order. Three compiled C++ negative controls are detected: skipped
intentional gate (27 mismatches), negative dragging incorrectly accepted (729),
and omitted second state gate (243). Counts are per optimization, not distinct
input universes. Existing fixture tests now pass explicit run(0) and use nil
priority so foreign-priority rejection cannot mask an untested forced gate.

Reproduce (pyelftools, Unicorn and clang++ required; original ELF not bundled):

```sh
LIBUNICORN_PATH="$PREFIX/lib" python3 tools/test_pickup_entry_arm.py \
  "$HOME/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so" \
  --output-dir "$HOME/blockheads-work/pickup-entry-verify"
```

Full pickup remains UNVERIFIED, not proven impossible to emulate. An invalid
instruction in the abandoned harness never established the claimed recording
region root cause: its diagnostic returned a nonzero first gate and exited
early, and the later exception trace patch did not land. Spilled indirect call
targets require relocation/dataflow analysis; their existence alone is not a
hard limit on Unicorn. This entry test makes NO lookup/ownership/currency,
ordinary insertion, recording, Foundation or APK equivalence claim. No change
to full-method behavior-verified count is justified by this bounded test.
