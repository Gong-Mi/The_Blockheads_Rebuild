# Item -> item mappings, decoded from the mapping functions

Some `...ItemType` symbols do not answer a yes/no question: they map one item type to
another (a seed to the tree it grows, a cage to the NPC inside, a dyeable item to its
dyed variant). `tools/extract_item_mapping_functions.py` decodes them into tables.

Two shapes appear and the extractor handles both the same way - what is wanted is the
pair (compared value, constant the reached body returns):

- a **sparse switch** the compiler turned into a comparison tree
  (`cmp rX, #K ; beq body`), and
- a **dense switch** compiled into an inline jump table
  (`add r2, pc, #4 ; ldr r1, [r1, r2] ; add pc, r1, r2`).

Collecting the pairs directly is what catches the special cases *before* a jump table
(`npcTypeFromCageItemType` compares against 303 before it indexes its table); an earlier
cut of this tool only read the table and silently lost that entry.

## Counts (current run)

| element | count |
|---|---:|
| functions decoded | 4 |
| ... with an inline table | 2 |
| compare pairs decoded / with an output | 26 / 26 |
| table entries resolved | 14 |

## The mappings

`treeTypeForSeedItemType` - seed item -> tree type

| seed item | tree type |
|---:|---:|
| 46 | 6 |
| 60 | 7 |
| 77 | 8 |
| 78 | 9 |
| 160 | 10 |

plus a 7-entry table (indices 0-6 -> 1, 2, 3, 5, 0, 0, 4).

`plantTypeForSeedItemType` - seed item -> plant type

| 54 | 61 | 62 | 71 | 112 | 144 | 295 | 310 | 316 |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 2 | 3 | 4 | 5 | 6 | 7 | 9 | 10 |

`npcTypeFromCageItemType` - cage item -> NPC type

| input | output |
|---:|---:|
| 303 | 1 |
| 324-330 (table) | 3, 8, 2, 7, 0, 0, 3 |

`genericDyedItemTypeForItemType` - dyeable item -> its dyed variant (11 pairs)

| 85 | 84 | 117 | 115 | 122 | 130 | 124 | 126 | 127 | 169 | 170 |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 114 | 113 | 118 | 116 | 123 | 131 | 125 | 128 | 129 | 172 | 173 |

This function is why the extractor had to learn a second branch form. Its whole chain is
written as `cmp #IN ; bne SKIP ; movw r0, #OUT`, i.e. the equal path **falls through**
instead of branching - an earlier cut only followed `beq` and decoded this function to
zero pairs, which was reported as "not decoded" rather than as what it was: a form the
tool could not read yet.

`randomBonusItemTypeForTile` remains undecoded: it takes a tile and a world, not an item
type, so it is a different kind of function and is not claimed here.

## Boundaries

- The table indices are indices: the input item type for index i is the table's domain
  base + i, and for `npcTypeFromCageItemType` that base is readable from the bound check
  (`sub r1, r0, #0x144 ; cmp r1, #6`), i.e. items 324-330. For the tree table the base is
  recorded in the JSON rather than asserted here.
- Outputs are the constants the case bodies return; nothing here proves the caller uses
  them as item types (they are, by type, but that is a reading).
- 26 pairs is not completeness: only the four functions named above were decoded, and
  `randomBonusItemTypeForTile` (tile+world in, item out) is a different shape entirely.
