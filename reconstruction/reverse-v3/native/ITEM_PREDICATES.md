# The item attribute matrix, taken from the client's own symbols

`.dynsym` still carries 108 `...ItemType...` symbols with addresses and sizes, so the
item logic is addressable without heuristics: each predicate is a small function that
answers one question about one item type. `tools/extract_item_predicates.py` decodes
each body and separates the literals that fall inside the item domain (0-343,
1024-1105) from control-flow constants.

## Counts (current run)

| element | count |
|---|---:|
| ItemType symbols found | 108 |
| decoded (size <= 4 KB) | 95 |
| ... returning a literal (`always-constant`) | 2 |
| ... comparing against literals (`equals-set`) | 45 |
| ... still unclassified (larger bodies: loops or tables) | 48 |
| predicates that name item types | **51** |
| distinct item types named | **191** (of the 426-item domain) |

## What the predicates say (examples, ids as in `original_item_types.tsv`)

| predicate | item types | reading |
|---|---|---|
| `itemTypeIsLiquid` | - | **always returns 0**: 1.7.6 has no liquid item |
| `itemTypeCarriesLiquids` | - | **always returns 0** |
| `itemTypeIsLuminous` | 1105 | exactly one luminous item |
| `itemTypeIsGemBlock` | 1098-1102 | the five gem blocks |
| `itemTypeCanBeWornOnHead` | 289, 293 | headwear |
| `itemTypeCanBeWornOnLegs` | 287, 291 | legwear |
| `itemTypeCanBeWornOnFeet` | 290, 294 | footwear |
| `itemTypeCanBeWornOnTorso` | 278 | torso wear |
| `textureNameForClothingItemType` | 287, 289-291, 293, 294 | the same clothing set drives texture selection |
| `reflectivityForClothingItem` | 261, 277, 278 | which items have a reflectivity |
| `itemTypeIsMetal` | 285, 286, 322 | metal set |
| `itemTypeIsHangable` / `itemTypeIsSolid` | shared literal set (0x417-0x446 range) | both read the same ids - worth a second look rather than two independent claims |
| `itemTypeIsValidFillItem` | 1039-1053 odd ids | the fill items |
| `treeTypeForSeedItemType` / `plantTypeForSeedItemType` | seeds -> tree/plant types | item-to-item mappings, not booleans |
| `npcTypeFromCageItemType` | 303, 325-330 | cage -> NPC mapping |
| `genericDyedItemTypeForItemType` | dyed variants | item-to-item mapping |
| `xOffsetForItemType` | 74, 156 | the two items drawn at -0.1875 x offset |

## Boundary that matters

Item types 0-3 are also plausible control constants, and several predicates use 0/1 for
"false/true". A literal of 0 or 1 therefore cannot be classified by value alone: the
artifact keeps both `item_types` and `other_literals` and this note, rather than
pretending the small values are resolved. Everything from 4 upwards inside the domain is
a genuine item id.

Also honest: 48 of 95 bodies are still `unclassified` (they loop or index tables), and
their sizes are recorded - those are the next batch, not a claim of completeness.

## Boundaries

- Predicates only: transform functions (`*ForItemType` that return an item type) are
  listed with their literal sets but their mapping semantics are not decoded here.
- A predicate naming an id does not prove the runtime path exercises it.
- No gameplay integration: this is the client's own answer table, nothing more.
