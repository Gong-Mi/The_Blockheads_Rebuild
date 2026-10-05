# The third abstraction: the float clock/weather getters

Evidence grade: **executed** - four getters ran in a real ARM emulator with their values read back
bit-exact, each with an address-provenance check and a cross-control that can fail.

Tool: `tools/emulate_float_getters.py` (+ `float_getter_emulation.json`).

## The correction this batch makes

`WORLD_METHOD_EXECUTION_CLASSIFICATION.md` put the clock/weather getters in one bucket and I wrote
that **one abstraction covers eight methods**. That was a cost estimate, and running them showed it
is wrong: the family has **three abstraction classes, and they are not the same abstraction**.

| class | shape in the original | what must be supplied |
|---|---|---|
| `char` (`fastForward`, `doubleTimeUnlocked`) | `ldrsb r0,[r0,r1]` - value in r0 | **nothing** |
| `double` (`worldTime`) | field read through the 8-byte copy helper, then moved by VFP | serve the copy, read the buffer |
| `float` (this batch) | `ldr r0,[r0,r1]` -> `dmb ish` -> `str r0,[sp,#8]` -> `vldr s0,[sp,#8]` -> `vmov r0,s0` | intercept the **word load** that addresses the field |

The float shape is the trap: the only VFP instruction sits on a **stack copy**, so hooking it reads the
stack, not the field (`vldr s0,[sp,#8]`). The real read is the plain `ldr` one instruction after
`dmb ish`. Unicorn's default ARM model rejects the `vldr` outright
(`UC_ERR_INSN_INVALID`), so the getter cannot simply be run to completion - it must be stopped at the
read, which is also the only reading that is faithful.

## Result

| getter | offset | executed | address provenance | cross-control |
|---|---:|---|---|---|
| `timeOfDayFraction` | 880 | yes | EA == self+offset | follows a rewritten cell |
| `weatherFraction` | 916 | yes | EA == self+offset | follows a rewritten cell |
| `rainFraction` | 920 | yes | EA == self+offset | follows a rewritten cell |
| `rainFractionNotIncludingSnow` | 924 | yes | EA == self+offset | follows a rewritten cell |
| `simulationProgress` | 3136 | **no** | - | - |

`simulationProgress` is not a failure of the method but a different shape: its offset is derived
correctly (3136) yet no load in its body hits that address, so it addresses the field some other way
and needs its own reading.

## What the provenance check buys

The offset is derived from the getter's own literal pool (`slot = wA + PIC base`, `cell = *(slot)`,
`offset = *(cell)`) and cross-checked against `OBJC_IVAR_$_World.<name>` before anything runs. Then
pass 1 requires that **the first load whose effective address equals `self + offset`** exists in the
body. A wrong derivation would have no such load and the field fails instead of returning a plausible
number from the wrong place. Pass 2 pins that instruction and reads whatever address **it** computes,
so the cross-control (rewriting the cell to another float field's offset, with a decoy planted at the
original offset) returns that other field's value - proving the value tracks the cell rather than a
cached offset.

## Pitfall found here (cost me several rounds)

Unicorn's register ids are **not** ARM register numbers: `UC_ARM_REG_R0 == 66`, and id 0 is a
deprecated no-op that reads back garbage while only printing a warning. A table built as
`{"r0": 0, "r1": 1, ...}` therefore computes every effective address from a wrong register value and
silently matches nothing. Build such tables from the real `unicorn.arm_const` constants; the
regression is guarded in the contract test.

## Honest process note

The batch tool initially died on its first failing field and took the whole run down with it, which
also made me misread *which* field was failing - the traceback points at one call site inside a loop,
so the failing iteration is not visible in it. Per-field isolation is now in place.
