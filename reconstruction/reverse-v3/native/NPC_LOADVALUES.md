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

Emitter: `tools/emit_npc_loadvalues_listing.py` (capstone 5, deterministic,
literal-cell annotations only — no semantic claims beyond resolution shape).

## Dispatch inventory observed through cell resolution

- all literal-cell GOT resolutions point at the single `objc_msgSend` slot
  (`0x0105b7a0`), dereferenced then called via rotating registers
  (`blx r4/r2/r3/lr/ip`); no `objc_msgSendSuper2` cell appears in the body;
- selector cells resolve to: `objectForKey:`, `floatValue`, `intValue`,
  `boolValue`, `unsignedIntegerValue`, `retain`, `autorelease`,
  `dictionaryWithDictionary:`;
- 14 further cells resolve to one-character NUL-terminated C strings
  (`X P 6 T H L d e b \` l \\ h` plus the `@\"` pool neighbours). Their role
  (dictionary keys vs selref-section adjacency) is NOT established here:
  they are recorded as pending single-char cells, not as key pairings;
- nil-guard shape at `0x00643b34`–`0x00643b7c`: `movw ip,#0` spilled to
  `[fp,-0x30]`, first `objectForKey:` result `cmp` against that zero,
  `beq 0x643d34` (cleanup epilogue head `movw r0,#0`).

## Status boundary

This batch is refs/cfg-level evidence only (bounded listing + cell
resolution). Per-site key→ivar writeback pairing, the identity of the
single-char cells, retain/release ordering, replacement code, entity
construction and original-runtime behavior are all unclaimed and next-batch
material.
