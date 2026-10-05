# The third abstraction: the float clock/weather getters

Evidence grade: **executed** - all five getters ran in a real ARM emulator with their values read back
bit-exact, each with an address-provenance check and a cross-control that can fail.

Tool: `tools/emulate_float_getters.py` (+ `float_getter_emulation.json`).

## The correction this batch makes

`WORLD_METHOD_EXECUTION_CLASSIFICATION.md` put the clock/weather getters in one bucket and I wrote
that **one abstraction covers eight methods**. That was a cost estimate, and running them showed it is
wrong: the family has **three abstraction classes, and they are not the same abstraction**.

| class | shape in the original | what must be supplied |
|---|---|---|
| `char` (`fastForward`, `doubleTimeUnlocked`) | `ldrsb r0,[r0,r1]` - value in r0 | **nothing** |
| `double` (`worldTime`) | field read through the 8-byte copy helper, then moved by VFP | serve the copy, read the buffer |
| `float` (this batch) | see below - two instruction shapes, one rule | intercept the access that addresses the field |

## Two instruction shapes, one rule

The float getters do not even agree with each other on how to read the field:

    weather family (timeOfDayFraction, weatherFraction, rainFraction, rainFractionNotIncludingSnow)
        ldr r0, [r0, r1]     <- the field, 32-bit word
        dmb ish
        str r0, [sp, #8]
        vldr s0, [sp, #8]    <- VFP on a STACK COPY, not on the field
        vmov r0, s0

    simulationProgress
        add r0, r0, r1
        vldr s0, [r0]        <- VFP DIRECTLY on the field

The weather shape is the trap: the only VFP instruction operates on a stack copy, so hooking it reads
the stack rather than the field, and Unicorn's default ARM model rejects the `vldr` outright
(`UC_ERR_INSN_INVALID`) - the getter cannot be run to completion. The rule that covers both shapes is
**"the memory access whose effective address equals `self + offset`"**, and it must collect VFP loads
as well as integer ones. Collecting only integer loads is exactly why `simulationProgress` first came
back unexplained: a limitation of the tool, not a property of the target.

## Result

| getter | offset | executed | address provenance | cross-control |
|---|---:|---|---|---|
| `timeOfDayFraction` | 880 | yes | EA == self+offset | follows a rewritten cell |
| `weatherFraction` | 916 | yes | EA == self+offset | follows a rewritten cell |
| `rainFraction` | 920 | yes | EA == self+offset | follows a rewritten cell |
| `rainFractionNotIncludingSnow` | 924 | yes | EA == self+offset | follows a rewritten cell |
| `simulationProgress` | 3136 | yes | EA == self+offset (via `vldr`) | follows a rewritten cell |

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
