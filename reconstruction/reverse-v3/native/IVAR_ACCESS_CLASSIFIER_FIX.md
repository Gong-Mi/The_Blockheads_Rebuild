# The fused-store gap in the cell-reference classifier

A tool fix, recorded because of how it failed rather than what it added.

## The gap

`tools/extract_ivar_cell_references.py` classifies how each resolved ivar cell is consumed: read, write,
or neither. It looked for an explicit address computation before the access:

    add rF, rObj, rO        ; field address
    strb rZ, [rF]           ; write  (what it recognised)

but the compiler very often folds that add into the access itself:

    ldr  r1, [r1, r2]       ; the .got slot
    ldr  r1, [r1]           ; the cell's content - the offset
    mov  r3, #1
    strb r3, [r0, r1]       ; write, register-offset addressing, no add to find

Sites in the second form were filed as `pointer-or-unknown`. That is a **tool gap that reads as an
absence of writes** in the target, and it is the failure mode this project has now hit twice.

## What it changed

| | before | after |
|---|---:|---:|
| sites classified read | 1517 | 4898 |
| sites classified write | 197 | 464 |
| unclassified | 5479 | 1831 |

3648 sites moved out of "unknown" - the fix is checked **before** the add form, because a fused site has
no add for the old rule to find, and the fused rule requires that the register holding the cell's
content is the one used as the access's index, which is what makes it the same cell by construction.

## The two things it did to prior conclusions

It **flipped a flag census**: `DynamicObject.updateNeedsToBeSent` went from 1 classified write to 22,
which turns "one writer, probably a tool gap" into the mechanism (many "something changed" paths set one
dirty bit).

It **left the world-clock conclusion alone**: `World.fastForward` still has exactly one site and it is
still a read, so "no writer for the fastForward flag" survives the better classifier. A fix that
flattered every earlier claim would be a reason to distrust it; this one is selective, which is the
useful kind of result.
