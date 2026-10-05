# Every ivar offset cell and who touches it

Evidence grade: **A for the reference map** (pure arithmetic over the pinned ELF, regenerated
by tooling, with an enforced positive control), **B for the access classification** (heuristic,
hand-verified on four known sites).

Tool: `tools/extract_ivar_cell_references.py` (`--self-check`). Artifact:
`ivar_cell_references.json`.

## The mechanism

`OBJC_IVAR_$_C.i` denotes a 4-byte cell in `__objc_ivar`. No literal of that cell appears in
the code; the compiler reaches it through a two-word position-independent idiom:

```text
ldr  rA, [pc, #kA]      ; wA
ldr  rB, [pc, #kB]      ; wB
add  rB, pc, rB         ; v = (add_addr + 8) + wB   == PIC base 0x105faf4 (all 5730 sites)
ldr  rX, [rA, rB]       ; *.got entry - ITS FILE CONTENTS ARE THE CELL VA
ldr  rX, [rX]           ; the runtime offset
```

So a reference exists exactly when `*(wA + v)` is a known cell VA. The middle address lands in
`.got` (`World.worldTime` -> slot `0x105c754`, `World.fastForward` -> slot `0x105c778`), and
every resolved site reproduced the PIC base, which is the internal consistency check. The bias-load search window is 240 instructions back: a 24-instruction window resolves only 13430/27155 add sites and silently loses ~34% of references, which is how these numbers were first understated. Both fields' site lists were identical under either window. The bias-load search window is 240 instructions: a 24-instruction window resolves only 13430/27155 add sites and silently loses ~34% of references, which is how these numbers were first understated. Both fields' site lists were identical under either window.

## Result

| | |
|---|---|
| ivar symbols | 3793 |
| ivars with cell-based references | 2003 |
| reference sites | 7193 |
| by access | read 1517, write 197, pointer-or-unknown 5479 |
| attribution | unique 6265, ambiguous 803, none 125 |

## The two fields this batch was about

`World.worldTime` (cell `0xf328f4`, offset 648, `d`) - **three references, all reads**:

| site | instruction | method |
|---|---|---|
| `0x582a8c` | `vldr d0, [r1]` | `World -[getWeatherFractionForPos:]` |
| `0x5a1ff0` | `vldr d0, [r3]` | `World -[render:cameraZ:projectionMatrix:pinchScale:]` |
| `0x5d99c4` | offset copied out | `World -[worldTime]` |

`World.fastForward` (cell `0xf32930`, offset 934, `c`) - **exactly one reference**: the byte
read `ldrsb r0, [r0]` in its own getter. Attribution is deliberately `ambiguous`: the site sits
in a run of one-line getters sharing one body (`startPortalPos`, `serverClients`, `server`,
`client`, `fastForward`, `doubleTimeUnlocked`), so naming one of them would be a guess.

## The complement sweep

If the cell path has no writer, a writer could still use a literal offset. It does not: sweeping
stores with `#0x288` / `#0x3a6` over the whole code window gives 440 hits, and every one is
either a stack slot (`str rX, [sp, #0x648]`, `str rX, [sp, #0x3a4]`) or a draw-buffer offset -
dozens of `-draw:` methods write a vertex buffer at 0x648, which is exactly why a naive literal
sweep looks alarming and means nothing.

## What this establishes, and what it does not

Neither `World.worldTime` nor `World.fastForward` is written by any store in this library, cell
based or literal. The live values (the clock advancing 20 units per real second under
`fastForward == 1`, measured in `LIVE_WORLD_CLOCK.md`) therefore come from one of: a bulk copy
into the object, an object built from serialized data, or another library in the APK. Those are
the three remaining doors and none of them is claimed closed here.

The classification is heuristic and the tool says so: it reads the instruction sequence after
the site. Four separate decode bugs were caught by the self-check while building it (a mask that
pinned Rd and therefore only ever scanned `rd=0`; the offset load's direction; the cell VA
landing in the *destination* register; a same-named register swallowing the access instruction),
each of which presented as "no error, absurd result". Do not run the tool without `--self-check`.
