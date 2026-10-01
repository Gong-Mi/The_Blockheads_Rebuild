# Ivar-offset cells: the file and the process disagree (measurement, with an open question)

## What was measured

Every `OBJC_IVAR_$_<Class>.<ivar>` symbol in `.dynsym` points at a 4-byte storage cell in
`.data`. The cell can be read from two places:

| reading | where | produced by |
|---|---|---|
| **file-content** | the ELF file at the symbol's VMA | the compiler/linker layout |
| **process-content** | `/proc/<pid>/mem` at `base_rw + (symbol_vma - 0xe32000)` | whatever the runtime left there |

`tools/probe_live_ivar_offsets.py` reads both, for every ivar symbol, in one pass
(pid 18779, `libApplication.so` `rw-p` base `0x653fc000`):

```
compared 3793 ivar storage cells: 58 identical, 3735 rewritten   (98.5% differ)
```

Sample rows:

| ivar | file-content | process-content |
|---|---:|---:|
| `Blockhead.bodyCube` | 228 | 516 |
| `Blockhead.hatCube` | 252 | 180 |
| `Blockhead.state` | 56 | 728 |
| `DonkeyLike.bodyMatrix` | 336 | 260 |
| `DonkeyLike.walkTimer` | 264 | 8 |
| `DynamicObject.floatPos` | 24 | 36 |
| `World.saveID` | 436 | 3460 |

## Why this matters for the listings

The annotated listings print the **file-content** of the cell:

```
0x00ab9e38  ldr r2, [pc, #0xe04]  ; ... -> ivar-offset storage
            OBJC_IVAR_$_DonkeyLike.bodyMatrix (slot 0x0105d06c) = 336
```

That annotation is a **symbol identification**: it says which ivar the instruction touches.
The trailing number is the cell's file content. Since 98.5% of cells disagree between the
two readings, **the printed number cannot be assumed to be a runtime field offset**; at most
one of the two readings is usable as one, and the listings do not say which.

## What was attempted to decide it, and why each attempt was inconclusive

1. **Value test on `Blockhead.state + 0x4c`.** `-[Blockhead updateAnimation]` writes an
   animation id (0/7/14/23/32) at `[self + ivar + 0x4c]`. Applying both readings to the one
   live `Blockhead` instance found: file-content -> `1699070120`, process-content ->
   `1757354448`. Neither is an animation id. This is *expected* for this object rather than
   decisive: the same listing branches on `isNet` and **skips the entire keyframe mapping**
   for net-controlled blockheads, so the field may never have been written. A state-dependent
   test cannot settle a question about a field the object's state may never set.

2. **`World.saveID` -> must equal the on-disk save directory name.** The ground truth is
   solid (read from `/proc/<pid>/fd`, `a8124d2b4dea3347ddef22a1550a78c6`), but neither
   reading resolved to it on the single candidate. One candidate is not enough to separate
   "wrong offset" from "this particular World has not saved yet".

3. **Type-invariant test** (`DynamicObject.isNet` in {0,1}; `floatPos` finite and small;
   `pos` small), 48 candidate objects, then 33 after excluding the library's own mappings:
   `tools/decide_ivar_reading_by_types.py`. First run: every rate near zero; verdict
   "process-content" on a single lucky hit. Second run (metadata hits excluded, heap only):
   verdict flipped to "file-content", with pass rates 18/33, 21/33, 14/33 — i.e. **near
   chance**. A sample whose pass rate is near chance means the sample is not what it claims
   to be.

## The actual blocker

A 4-byte search for the realized class pointer is **not** instance discovery. It matches
any word equal to the class pointer, which includes class references, method/ivar metadata,
superclass chains and stale copies. Restricting the search to heap mappings removed the
in-library metadata but did not make the remaining hits behave like object headers
(`Donkey` matched 33 times in heap, at chance-level field plausibility, for a world whose
live object count is unknown and almost certainly not 33).

So the question "which reading is the runtime offset" is **open**, and this artifact does not
answer it. What it does establish is that the two readings differ almost everywhere, which is
enough to stop treating either number as verified.

## Next method (defined, not yet run)

Walk a **real object graph from a reachable root** instead of scanning for a pattern:

1. Resolve a class through the runtime rather than by address arithmetic: `libSystem.so`
   exports `objc_getClass` (0x815a8) and the internal `look_up_class` (0x75334) reached via
   `NXMapGet` (0x64e08) against the class map at `libSystem.so:0x1ab178`. Using the runtime's
   own lookup removes the "is this word a class pointer" guesswork.
2. From any confirmed instance, follow a chain whose endpoints are externally checkable
   (`GameView.world` -> `World.dynamicWorld` -> `DynamicWorld.blockheads` -> a `Blockhead`),
   and require **every hop** to land on an address whose header word equals a
   runtime-resolved class pointer. A single bad hop invalidates the chain; a full valid chain
   pins every offset along it.
3. Cross-check the terminal field against an independent file: `World.saveID` against
   `/proc/<pid>/fd`, `World.worldWidthMacro` against the 32x32 `PhysicalBlock` tiling already
   read from the heap.

Until step 2 produces a chain that validates end to end, the correct status for every offset
in this repository's live-memory artifacts is **candidate, not verified**.

## Boundaries

- One build (`elf_sha256` pinned), one process, one session. The 58/3735 split is the split at
  capture time; the deterministic quantity is the 3793 cells, which follows from the ELF alone.
- The divergence is a *measurement of the cells*, not a claim about why the runtime rewrote
  them (class realization, layout flattening and relocation are all consistent with it and
  none of them has been isolated here).
