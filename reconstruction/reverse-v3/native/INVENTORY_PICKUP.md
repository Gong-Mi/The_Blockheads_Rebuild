# Original pickup method: ordinary freeblock insertion path

Original input: Android 1.7.6 ARM32 `libApplication.so`, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`.

## Recovered local method

`Blockhead::pickupFreeblockIfPossible:inTile:intentional:` implements the
ordinary freeblock pickup decision in `inventory_pickup.cpp`, with explicit
dynamic receivers, field re-reads and message order. The original return is
signed char: 1 success, 0 rejection; neither bool nor accepted count.

Executed order (original instruction anchors):
- entry gates: Blockhead state bytes (ivar `state` at 0x38, bytes +0x28/+0x30
  give offsets 0x60/0x68); a nonzero byte rejects immediately;
- priorityBlockhead: nonzero and not self rejects; the intentional flag does not
  bypass this check (original 0xc61d78);
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
- Currency-split loop 0xc62900..0xc63440 (0x12a denominations, __aeabi_idiv,
  __modsi3, makeIntpair, 0x104/0xb special cases) is not implemented.
  `pendingPathUnresolved` lets the production runtime refuse these paths without
  any side effect, rather than guessing partial semantics.

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