# World clock / weather / scalar domain: the offset map, derived and cross-checked

Every offset in `clock_domain_layout.json` is **derived**, not transcribed: `slot = wA + PIC base`,
`cell = *(slot)`, `offset = *(cell)`, each cross-checked against `OBJC_IVAR_$_World.<name>`. The
contract test re-derives all of them and fails on any disagreement, so this table cannot drift into a
list of hand-written numbers.

| field | offset | role | executed by |
|---|---:|---|---|
| `worldTime` | 648 | elapsed world time | emulate_worldtime_getter.py |
| `sunDirection` | 660 | sun as a Vector (4 floats) | not yet - 16-byte copy loop |
| `timeOfDayFraction` | 880 | day/night phase | emulate_float_getters.py |
| `weatherFraction` | 916 | weather mix | emulate_float_getters.py |
| `rainFraction` | 920 | rain mix | emulate_float_getters.py |
| `rainFractionNotIncludingSnow` | 924 | rain without snow | emulate_float_getters.py |
| `fastForward` | 934 | run-at-20x flag | emulate_worldtime_getter.py |
| `doubleTimeUnlocked` | 3072 | double-time unlock flag | emulate_worldtime_getter.py |
| `simulationProgress` | 3136 | simulation catch-up progress | emulate_float_getters.py |
| `isSimulating` | 3140 | simulation active flag | emulate_worldtime_getter.py |

## What the layout says

`simulationProgress` (float, 3136) and `isSimulating` (char, 3140) are **adjacent** - a float followed
by a flag, which is a layout hint the two independent derivations agree on rather than something read
off a diagram.

`sunDirection` is a `Vector` (four floats, 16 bytes) at 660, returning through a copy loop; the other
struct-returning getters in this family (`translation`, `highestPoint`) copy 8 bytes inline with a
plain `ldr`/`str` pair instead. Both need their own reading, which is why the executed set stops at
scalars for now.

## A writer, found by looking at the one non-getter in the bucket

`resetPauseIdleTimer` is declared `void` and is not a getter at all: it **stores a constant into the
object**.

    0x5ac360  vldr s0, [pc, #0x28]     ; the literal at 0x5ac390
    0x5ac37c  add  r0, r0, r1          ; r1 = *(cell) = the derived offset 3264
    0x5ac380  vstr s0, [r0]            ; store to self+3264

The literal at 0x5ac390 is `0x00000000`, i.e. **0.0f**. So the method resets the float at offset 3264
to zero - the field's reset value, read out of the binary rather than guessed.

Grade, stated honestly: **static**. The setter's own `vldr` cannot run under Unicorn
(`UC_ERR_INSN_INVALID`), so unlike the getters above this one has no execution evidence. What it has is
the instruction pair plus the derived, symbol-checked target offset.

## Lesson from deriving these: a window tuned to one getter is a guess

The companion pool load sits at a different distance from the `add` in each getter - `sunDirection`'s
is **9 instructions later**. A fixed look-ahead window (+3, then +7) reported "slot not derivable" for
it, which reads like a property of the target but was a property of my search. The lookup now scans the
whole prologue.
