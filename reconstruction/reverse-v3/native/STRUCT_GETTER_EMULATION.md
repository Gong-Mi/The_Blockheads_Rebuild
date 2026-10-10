# Struct-returning World getters: two shapes, and the ABI that made them look broken

Evidence grade: **executed** - all three getters ran in a real ARM emulator and their struct content
came back byte-exact, each with a provenance check and a control.

Tool: `tools/emulate_struct_getters.py` (+ `struct_getter_emulation.json`).

| getter | offset | width | shape | field read anchored by | control |
|---|---:|---:|---|---|---|
| `translation` | 624 | 8 | inline `ldr`/`str` pairs | the access that lands on self+offset | same-width value |
| `highestPoint` | 3164 | 8 | inline `ldr`/`str` pairs | the access that lands on self+offset | same-width value |
| `sunDirection` | 660 | 16 | copy helper | the helper called with src == self+offset and n == width | source-address-follows-cell |

## The ABI fact that cost the most

A struct-returning Objective-C method **does not take self in r0**. It follows the stret convention:

    r0 = hidden return buffer (the caller's memory)
    r1 = self
    r2 = _cmd

Writing self into r0 - which is right for the scalar getters - puts every effective address at a small
unmapped address here, and the symptom is a memory fault that looks like a bad derived offset rather
than a wrong calling convention. Any struct-returning method in this binary needs r1 = self.

## Widths come from the type encoding, and the binary is asked to agree

`{Vector=[4f]}8@0:4` parses to 16 bytes, `{Vector2=[2f]}` to 8, `{?=ii}` to 8 - then the observed
copy length has to match: the helper is called with `n == 0x10` for `sunDirection`, which independently
confirms the 16 the type string claims. Two sources, one number.

## A control with no partner must not be demanded

`sunDirection` is the only 16-byte struct in this family, so the same-width value comparison that
controls the other two rows has no partner to compare against - and requiring one turned a working read
into a MISMATCH. The fallback control does not depend on width: rewrite the cell to any other field and
require the **source address to follow it**. A control that cannot exist is not evidence of a bug.

## Boundary: one field has no symbol to cross-check

`translation` derives cell `0xf328d4`, but `.dynsym` has **no `OBJC_IVAR_$_World.translation`** - only
`World.translationGoal` and many other classes' `translationOffset`. So for that field the symbol
cross-check is *unavailable*, which the artifact records as `null` with a note, not as agreement and not
as disagreement. The read is still anchored by the effective-address provenance, which does not depend
on the symbol.
