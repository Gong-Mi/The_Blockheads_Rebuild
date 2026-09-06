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
- state bytes: [[self + Blockhead.state]] (ivar +0x38); state+0x60 and state+0x68
  nonzero reject (0xc61c7c..0xc61cbc);
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
- Currency-split loop 0xc62900..0xc63440 is recorded as static evidence, not
  ported: type==0x12a branch enters three bounded loops keyed by denominations
  0x104/0xa7/0xa6; each iteration sends a capacity query (parameters (0,0)) that
  must return 1, then an insert/effect message chain before the loop counter
  advances; after the first loop the remaining high-denomination count converts
  through 100-base arithmetic with __aeabi_idiv/__modsi3 and an smmul-by-
  constant scaling near 0xc62fb8; makeIntpair and a residual-freeblock creation
  call shape the tail. Specific dataA/dataB meanings and the +100 offsets are
  NOT asserted without runtime evidence. `pendingPathUnresolved` lets the
  production runtime refuse these paths without any side effect, rather than
  guessing partial semantics.

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