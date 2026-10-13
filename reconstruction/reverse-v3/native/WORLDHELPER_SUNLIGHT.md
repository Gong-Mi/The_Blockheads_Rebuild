# WorldHelper per-tile sunlight update pair (static maps)

Original ELF `libApplication.so` (armeabi-v7a), SHA-256 `733d8210…b94c7`.
Two class bodies, word-verified against the pinned bytes by
`tools/recover_worldhelper_sunlight.py --check`:

| method | IMP | bounded end | words |
|---|---|---|---|
| `+[updateSunLightForTile:atPos:world:]` | `0x00a1b7d4` | `0x00a1bd10` | 335 |
| `+[updateSunLightRemovedForTile:atPos:world:]` | `0x00a1c680` | `0x00a1ca64` | 249 |

These are the two **leaf entry points** of the sunlight propagation system in
`WorldHelper`: the pair the world calls when a tile's exposure changes. Both
build small Objective-C containers with class references resolved through
`.rel.dyn` (verified by relocation, not by reading runtime state):

```text
NSMutableArray      @ 0x00e8ae78   (classref cells 0x00a1bcf0 / 0x00a1ca3c)
NSMutableIndexSet   @ 0x00e8ae7c   (classref cells 0x00a1bce8 / 0x00a1ca34)
NSNumber            @ 0x00e8ae74   (classref cells 0x00a1bd00 / 0x00a1ca48)
```

The six `bl` sites in both bodies all target `_Z25worldIndexAtWorldPositioniiP5World`
(`0x00a156a8`) — the tile-address helper, called directly (not via msgSend).

## +[updateSunLightForTile:atPos:world:] — sun floods in

```text
array = [NSMutableArray array];  open = [NSMutableIndexSet indexSet];
for (dx, dy) in [(0,0), (0,+1), (0,-1), (+1,0), (-1,0)]:
    index = worldIndexAtWorldPosition(x+dx, y+dy, world);
    if (index >= 0) {
        [array addObject:[NSNumber numberWithInt:index]];
        [open  addIndex:index];
    }
while ([array count] > 0)
    [+WorldHelper recursivelyUpdateSunLightWithList:array
     openIndices:open world:world];
```

- Five worldIndex blocks, in exactly the order self, y+1, y-1, x+1, x-1
  (`add r1, r1, 1` / `sub r1, r1, 1` / `add r0, r0, 1` / `sub r0, r0, 1` are
  anchored instructions; each block's miss branch is `blt` to the next).
- Each hit runs three sends: `[NSNumber numberWithInt:index]`,
  `[array addObject:…]`, `[open addIndex:index]`.
- The drain loop re-invokes the recursive update engine until the work list
  is empty — the engine mutates `array`/`open`; its internals are not mapped
  here.

## +[updateSunLightRemovedForTile:atPos:world:] — sun is taken away

```text
list = [NSMutableArray array];   lightWasRemovedList = [NSMutableArray array];
openIndices = [NSMutableIndexSet indexSet];
removeIndices = [NSMutableIndexSet indexSet];
index0 = worldIndexAtWorldPosition(x, y, world);
if (index0 < 0) return;
[list addObject:[NSNumber numberWithInt:index0]];
while ([list count] > 0)
    [+WorldHelper recursivelyRemoveAllSunLightWithList:list
     openIndices:openIndices lightWasRemovedList:lightWasRemovedList
     removeIndices:removeIndices world:world
     minx:x-32 maxX:x+32];
if (![removeIndices containsIndex:index0]) {
    [lightWasRemovedList addObject:[NSNumber numberWithInt:index0]];
    [removeIndices addIndex:index0];
    while ([lightWasRemovedList count] > 0)
        [+WorldHelper recursivelyUpdateSunLightWithList:lightWasRemovedList
         openIndices:removeIndices world:world];
}
```

- Four containers are allocated up front (two arrays, two index sets) — the
  first collect touches only `list`; `openIndices` is the removal engine's
  accumulator.
- The removal sweep is bounded to the column band
  `minx = x-32 … maxX = x+32` (`sub r0, r0, 0x20` / `add r0, r0, 0x20`
  anchored).
- After the sweep, if `index0` was **not** among the removed indices
  (`containsIndex:` result is `sxtb`-tested and `bne` skips the whole
  re-update block), the original index is queued and the *update* engine is
  drained — i.e. the tile is re-lit after the removal cascade.
- `index0 < 0` (off-world) exits through the shared epilogue.

## Boundaries

- Both bodies have **no ARM.exidx entry of their own**; each is closed by the
  next method IMP (end column above) and the tool rejects any extra or
  missing word.
- The recursive engines (`recursivelyUpdateSunLightWithList:openIndices:world:`
  `0x00a19c0c`, `recursivelyRemoveAllSunLightWithList:…` `0x00a1bd10`) and the
  broader sunlight algorithm are **outside these bodies** — this batch
  anchors only how work is enqueued and handed to them. Argument roles for
  the engine calls are from selector names plus which object is passed, not
  from engine internals; recorded as such.
- No runtime claim; no device run.

## Artifacts

| artifact | role |
|---|---|
| `tools/recover_worldhelper_sunlight.py` | hash-gated extractor; `--check` re-verifies every anchor |
| `disasm_worldhelper_updatesunlight.txt` / `disasm_worldhelper_updatesunlightremoved.txt` | the two bounded listings |
| `worldhelper_sunlight.json` | machine record: selectors/classrefs/calls/branches per method |
| `tools/test_worldhelper_sunlight_evidence.py` | CI contract on the committed JSON (no ELF needed) |
