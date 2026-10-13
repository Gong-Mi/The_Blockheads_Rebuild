# Item display names: nameForItemType, recovered whole (E142)

The client carries its own ItemType -> display-name table, and this batch
recovers it end to end: **425/425 ids extracted** (343 in the primary table
plus 82 in the high-range table), with 29 ids resolving to the 'UNKNOWN'
placeholder. This supersedes the "item display names are not extractable from
this APK" conclusion recorded in ITEM_DISPLAY_NAME_SOURCES.md - see the
Correction section there, and the one in TEXT_ASSET_INVENTORY.md.

## The dispatcher

`nameForItemType(int)` @ `0x004db268` (bare C function; extent
`0x004db268..0x004dde3c`, pinned by the ARM.exidx table):

- prologue: `ldr r1,[0x004dc270]` (word `0x00b8487c`) + `add r1,pc,r1` ->
  PIC base `0x0105faf4`, spilled to `[sp,#0xc]` and reused by every arm;
- `cmp r0,0x400` splits the two ranges; the low range runs
  `sub r1,r0,#1; movw r2,0x156; bhi -> default; add r2,pc,#4; ldr r1,[r1,r2];
  add pc,r1,r2` - an inline jump table @ `0x004db2bc` of 343 signed 4-byte
  offsets, targets = `0x004db2bc + off`;
- the high range repeats the shape @ `0x004db840`, 82 entries, guarded by
  `sub r1,r0,#0x400; cmp r1,0x51`;
- everything else (0, 344..1023, >= 1106, negative) branches to the default
  stub @ `0x004ddb8c`, which loads the 'UNKNOWN' constant string (CFString
  object @ `0x00f76218`);
- every arm loads its name the Apportable way: `ldr r0,[pc,#imm]` where the
  pool word is `CFString object - PIC base`, then `ldr r1,[sp,#0xc];
  add r0,r0,r1; str r0,[sp,#0x14]; b 0x004ddb9c`;
- the tail @ `0x004ddb9c` is `ldr r0,[sp,#0x14]; add sp,sp,#0x18; bx lr` -
  it returns the stored name; the function is a pure item-id -> NSString\*
  lookup.

Callers (the complete `bl 0x004db268` scan): `0x004ca164` and `0x004dfae4`
(both C/C++ helpers that pick the name for a context; records only, their
owning batches name them).

## The names

The names are ordinary constant CFStrings (16-byte `{isa, flags 0x7c8,
cstr, len}` objects) living in the same packed string region as every other
literal the binary uses. The singular-name block sits at
`0xf4b194..0xf4c4b0` ('ROCK' .. 'RANDOM ORE', 390 packed strings) and is
preceded by a plural-name block; run 1 of the constant-string area carries
the mapping objects twice (two 390-entry sequences, identical contents - more
than one translation unit references the set). Display form is the game's
usual UPPERCASE ('GOLD NUGGET', 'DIAMOND STAIRS'), which is exactly why the
earlier label-token audits missed it.

Coverage: ids `1..343` (table 1) and `1024..1105` (table 2) = 425 rows, no
holes, no undecodable arms. Cross-checks against the reference label set and
the server 1.7.1 DWARF enum all hold at every sampled point - e.g. 1
CLOTHING, 3 FLINT, 4 STICK, 6 FLINT AXE, 9 DOUBLE-TIME, 11 TIME CRYSTAL, 17
BASIC TORCH, 19 BLOCKHEAD, 21 APPLE, 336 EMERALD COLUMN, 343 DIAMOND STAIRS,
1024 STONE, 1105 LUMINOUS PLASTER.

## The UNKNOWN set (29 ids)

`2, 5, 10, 18, 26, 107, 108, 113, 114, 116, 118, 123, 125, 128, 129, 131,
132, 171, 172, 173, 211, 256, 298, 1044, 1046, 1058, 1059, 1073, 1092` -
exactly the client's non-displayable slots: the Deprecated* entries (12),
the Rainbow*/DYED_GENERIC palette placeholders (15), and two internal-only
items (256 PoisonArrow, 298 Coins = ITEM_MONEY). The compiler folded each of
these arms to the default stub, so the client itself has no name for them.

## Artifact

`item_display_names.json` carries every row: item_type, name, table,
table-entry address, stub address, CFString object address, cstr address and
length, plus the mechanism fields (function extent, PIC base, table bases,
default stub, tail, callers). `tools/extract_item_display_names.py`
re-derives it from the pinned ELF and `--check`s byte-identically.

## Boundaries

- Static read of the pinned ELF (sha256 733d8210...94c7) only; nothing was
  executed; no device run was performed.
- These are the strings the CLIENT displays; they are not developer
  identifiers - the reference/server columns differ by design (e.g.
  ITEM_COBBLESTONE vs 'STONE', ITEM_GOLD_ORE vs 'GOLD NUGGET').
- Caller identities (0x4ca164 / 0x4dfae4) are addresses only; naming them
  belongs to the batches that own those functions.
- The plural-name block (ending at 0xf4b194) is noted but not mapped here.
- The jump tables and arms are the 1.7.6 Android client's; the same lookup
  in other versions may differ in extent and ids.
