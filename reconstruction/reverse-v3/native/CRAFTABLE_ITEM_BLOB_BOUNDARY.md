# CraftableItem blob: proved, and sealed

Evidence grade: **A** for the instruction-level chains (read directly from the pinned ELF), **A** for
the layout (two independent sources), and an explicit **seal** on the part that is not done.

Companion: `craftable_item_blob_boundary.json`. Layout source of record: `CRAFTABLE_ITEM_STRUCT.md`.

## The layout gained a second, independent source

`CRAFTABLE_ITEM_STRUCT.md` pinned `{CraftableItem=ii[8i][8i]iiiSSi[8i]}` (fields at 0/4/8/40/72/76/80/84/86/88/92,
4+4+32+32+4+4+4+2+2+4+32 = 124) from a type encoding, and checked it against the 124-byte length a
savedict read-back measured. It now also arrives from a **method signature**:

```text
-[CraftableItemObject setCraftableItem:]   v132@0:4{CraftableItem=ii[8i][8i]iiiSSi[8i]}8
```

Same 11 fields, same 124 bytes, and it proves the struct is **passed by value**.

## The read-back, at instruction level

`CraftableItemObject -[initWithSaveDict:]`:

```text
0xac79e0  blx r4              ; objc_msgSend(saveDict, objectForKey:, @"craftableItem")
0xac79f4  ldr r3, [r2]        ; r3 = the ivar offset from a .got slot
0xac79f8  add r1, r1, r3      ; r1 = self + offset        (CraftableItemObject.craftableItem is +4)
0xac7a10  ldr r3, [sp, #0x10] ; r3 = 124   (movw r3, #0x7c at 0xac7984)
0xac7a18  blx ip              ; objc_msgSend(NSData, getBytes:length:, &self->craftableItem, 124)
```

This is the previously recorded line `[[saveDict objectForKey:@"craftableItem"]
getBytes:&self->craftableItem length:124]`, now confirmed instruction by instruction. It also
corrects a claim **I** made earlier in this session: that the library contains only one
`getBytes:length:` reference (a 10-byte UINib path). That was a tool-coverage artefact - see below.

## The write direction

`CraftableItemObject -[setCraftableItem:]`:

```text
0xac7c28  add r2, fp, #8      ; r2 = &(the by-value struct argument)
0xac7c2c  movw r3, #0x7c      ; 124
0xac7c4c  ldr r1, [ip]        ; r1 = the ivar offset from a .got slot (=4)
0xac7c50  add r0, r0, r1      ; r0 = self+4 = &self->craftableItem
0xac7c68  bl #0x1c2888        ; memcpy(&self->craftableItem, &arg, 124)
```

## The ivar has exactly three reference sites

`CraftableItemObject.craftableItem` (cell `0xf34ea0`, offset 4) is referenced in exactly three
places: the getBytes read-back, the memcpy write, and an initialiser at `0xac7ccc` (super dispatch
then return self; its role is **inferred from shape, not proved by name**). No field read touches the
cell - which is consistent with everything else: consumers hold the struct by value or by pointer.

## Why the field-semantics attempts failed (three of them)

Because the offsets of a 124-byte struct are small numbers (0, 4, 8, 40, ...) that **collide
numerically with stack-frame offsets**, matching on the offset alone is invalid by construction. The
first attempt produced a table of ~1600 "field accesses" that were all `[sp, ...]` frames. The trap
also has a cheap alarm: when a rule has not locked onto an object, the hits cover essentially every
method in the library.

A second, independent lesson: `getBytes:length:` has a **third selector addressing form** -
`ldr ip,[pc,#k] ; add ip, ip, r1 ; ldr ip,[ip] ; blx`, where `r1` is a per-class slot index.
`tools/find_selector_senders.py` models only the pool+PIC form, so it reported slots=1 / sends=0 for
this selector while real call sites exist. **An empty result covers only the channel that was
scanned.** The reliable search is by the length immediate: `movw r3, #0x7c` (124) occurs exactly five
times in the library.

## Sealed, with the condition to reopen

Field semantics for the 11 offsets is **not done**, and is sealed here rather than re-attempted with
another heuristic. The condition to reopen is a base-provenance tracker: instruction-level
register/dataflow from the by-value buffer (the 124-byte copy destination) to each access, so that
`[sp, #k+field]` can be told apart from a genuine stack frame at the same offset. Offset heuristics
cannot do it - three attempts failed, each invalid by construction rather than merely incomplete.

It would also become easy with a **live `CraftableItemObject` instance** to read: the current world
has no workbench, so none exists. That is a user-side state, not a tooling gap.
