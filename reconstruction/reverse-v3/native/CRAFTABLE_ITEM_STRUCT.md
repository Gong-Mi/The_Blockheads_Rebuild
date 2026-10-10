# The CraftableItem blob: layout from the type encoding

Crafting data reaches the client as a POD blob inside each `CraftableItemObject`: the
savedict read-back evidence records

```
[[saveDict objectForKey:@"craftableItem"] getBytes:&self->craftableItem length:124]
```

so the recipe body is a 124-byte struct copied verbatim out of the save. Its layout is
not a guess - the binary carries the Objective-C type encoding, and
`tools/parse_craftable_item_struct.py` parses it:

```
@132@0:4{CraftableItem=ii[8i][8i]iiiSSi[8i]}8
```

## Fields (current run)

| index | offset | type | count | size |
|---:|---:|---|---:|---:|
| 0 | 0 | `i` | 1 | 4 |
| 1 | 4 | `i` | 1 | 4 |
| 2 | 8 | `i` | 8 | 32 |
| 3 | 40 | `i` | 8 | 32 |
| 4 | 72 | `i` | 1 | 4 |
| 5 | 76 | `i` | 1 | 4 |
| 6 | 80 | `i` | 1 | 4 |
| 7 | 84 | `S` | 1 | 2 |
| 8 | 86 | `S` | 1 | 2 |
| 9 | 88 | `i` | 1 | 4 |
| 10 | 92 | `i` | 8 | 32 |

Totals: 11 fields, packed size **124**, three `int[8]` arrays occupying 96 of the 124
bytes.

## The cross-check

124 is not taken from the encoding and used as the answer - it is measured twice in
unrelated places: the packed size of the encoding's field list, and the `length:124`
the savedict read-back recorded from a real `getBytes:` call. They agree, which is why
the layout can be treated as settled. The ObjC instance is 128 bytes
(`CraftableItemObject` instance_size), i.e. the blob plus the 4-byte isa.

## What is NOT claimed

Field meanings. The encoding gives types and offsets only. Three `int[8]` arrays are a
plausible shape for "ingredient item types / ingredient counts / something else", and
the `S S` pair at 84/86 a plausible small enum pair, but nothing here reads those
fields, so no meaning is asserted. What would settle it: the code that *builds* a
CraftableItem (the server-side population path) or a recipe blob decoded from a save
that has a workbench - the archived world used by the tile-data work has none (its 16
dynamic objects are all trees).

## Boundaries

- Layout from one encoding string; a second `CraftableItem`-shaped type elsewhere would
  need its own parse (the file records the encoding offset it found).
- The blob is copied verbatim from the save, so its producer is the server, not the
  client: this artifact describes the *shape* the client expects.
