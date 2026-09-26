# NPC -[loadValuesFromSaveDict:] bounded listing (read-back side)

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`

Boundary from the pinned ObjC method map:

```text
IMP:      0x00643b20
boundary: 0x0064448c (next method IMP)
words:    603 (exact coverage asserted, raw words byte-verified)
PIC base: 0x0105faf4
```

Emitter: `tools/emit_npc_loadvalues_listing.py` (capstone 5, deterministic).
Cells classified via file bytes + relocation tables only (no load-memory
pretence): GOT = named dynamic relocation; ivar-offset storage = resolved
slot equals dynsym `OBJC_IVAR_$_…` address; CFString key = slot carries
`R_ARM_ABS32 → __CFConstantStringClassReference`, data pointer +8 is a file
constant whose `len` field matches strlen; selref via `__objc_selrefs`.

## What the body reads

Selector cells: `objectForKey:` — 9 cell references, 19 distinct call sites (forward-simulator count; 4 keys are probed twice: fullness, layCooldownTimer, breed, currentBlockheadIndex), `floatValue` ×2, `intValue` ×3,
`boolValue`, `unsignedIntegerValue`, `retain` ×2, `autorelease`,
`dictionaryWithDictionary:`. All dispatch through the single
`objc_msgSend` GOT slot; no `objc_msgSendSuper2` cell appears — the NPC
read-back does not forward to DynamicObject.

CFString key cells (with their ivar-offset storage cells seen in the same
prologue register set):

```text
fullness, age, damage, layTimer, breed, mateBreed,
tameCooldownTimer, layCooldownTimer, mateCooldownTimer,
hasBred, hasBeenFedByBlockheadOrChest, name,
tameCountsByClientID, tamedClientID, currentBlockheadIndex
```

Note the asymmetry the cells already expose: the write-side key
`currentBlockheadIndex` reads back into ivar storage
`OBJC_IVAR_$_NPC.savedBlockheadIndex`, and write-side `saveTime` has no
read-back key (it is derived from world time on save).

## Corrections this batch forced

An earlier draft of this document described one-character strings
(`X P 6 T …`) as "the save-dict key CFStrings". Wrong on two counts:
they are the `OBJC_IVAR_$_*` offset-storage words (dynsym-confirmed, and
the selector table is a dense run of NUL-separated names, so single
letters there are selector-name tails, not strings), while the real NPC
keys are the full-word CFStrings listed above, found at
`0x00f80568`–`0x00f80648`. Also fixed in the emitter: `selectors.get(0)`
matched the ELF header magic for load-relocated zero words — zero words
are now explicitly unclassified.

## Status boundary

Refs/cfg evidence (bounded listing + cell classification) plus per-chain
pairings: `tools/recover_npc_loadvalues_keys.py` → `npc_loadvalues_keys.json`
pins all 15 `key → objectForKey: → conversion → self+ivar writeback` chains
with CFString reloc/length, key-load cell, raw-word, dynsym-ivar and
write-side agreement gates, plus the 4 guard probes and the
`dictionaryWithDictionary:` copy site for `tameCountsByClientID`.
Retain/release ordering, object copy semantics and all runtime behavior
remain unresolved; replacement code and device acceptance not claimed.
