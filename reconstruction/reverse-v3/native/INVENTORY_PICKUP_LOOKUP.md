# pickupFreeblockIfPossible lookup region

Original ELF: `libApplication.so` ARM32, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`.

Region: `0xc61dd0..0xc626d8` (578 ARM instructions, 17 calls, 42 branch sites).
Manifest generator: `tools/recover_pickup_lookup.py`.
Output: `inventory_pickup_lookup.json`.

## Confirmed static structure

- At `0xc61dd0`, a two-word header is read from the resolved object and compared. Equality branches to `0xc621c8`; inequality enters a bounded preparation path.
- `0xc61e10` is an indirect Objective-C dispatch after a stack-built pair/coordinate object. Receiver, selector and exact dynamic class remain unresolved; it is not labelled as a particular fast-enumeration selector yet.
- `0xc62108` is `__aeabi_memmove`; the preceding block constructs/copies a small coordinate/object representation. This is not enough to name the fields.
- `0xc6214c..0xc621b8` is a loop that compares a two-byte value and advances a cursor by 2 on mismatch. It is structurally an enumeration/packed-record loop, but the record type and source collection are not yet proven.
- `0xc6225c` directly calls `itemTypeRequiresOwnershipToRemove(ItemType)`.
- `0xc623bc..0xc624f8` dispatches on the returned ItemType. Confirmed constants are `0x428`, `0x429`, `0xa4`, `0xa5`, `0xa6`, `0xa7`, `0xa8`, and `0xcf`; the branches lead to different indirect calls.
- `0xc62500..0xc626d8` performs the second predicate/priority gate and writes the local result byte used by the parent method.

## Not yet claimed

The current bytes do not by themselves prove the earlier labels “expectedCraftItems”, “isAdmin”, “fast enumeration”, or a particular `remove*AtPos:` selector. Those require resolving the indirect selector/receiver chains or controlled original-runtime observation. The manifest records the three pending bindings explicitly:

1. dispatch receiver/selector at `0xc61e10`;
2. per-entry indirect removal calls;
3. the Tile/coordinate struct layout used by the stack copies.

This is static evidence only. No parent-method integration has been made, and `inventory_pickup.cpp` continues to refuse the unresolved lookup path conservatively.
