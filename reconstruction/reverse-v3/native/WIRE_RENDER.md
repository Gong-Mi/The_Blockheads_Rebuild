# Wire render trio — draw:, staticGeometryDrawCubeCount, addDrawCubeData:fromIndex:

How a wire block turns into draw-cube records for the static geometry
buffer, closing the `Wire` class. 3 bodies, **2861 verified words** total,
recovered from the pinned original `libApplication.so` (1.7.6, armeabi-v7a,
SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`); every
instruction word re-verified, tool refuses to emit on drift
(`tools/recover_wire_render.py`; JSON: `wire_render.json`).

## Bodies

1. **`draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:`**
   (`0x009510f8`..`0x00951320`, 138 words). Argument-frame canonicaliser
   only: repacks the full incoming argument layout — self/selector, float
   pinchScale, the camera ints and both `_GLKMatrix4` 16-float blocks —
   into a fixed local frame layout and returns. No call sites, no branches,
   no ivar/selector cells in this bounded body; the GL submission path is
   not inside it.

2. **`staticGeometryDrawCubeCount`** (`0x00951f2c`..`0x00952770`, 529
   words). Counts the static draw cubes this wire needs:
   - +1 for each of 6 orientation groups hit by
     `Wire.currentConfiguration@60` — `{1,2,3,4,5}`, `{1,2,6,7,8}`,
     `{7,10,12}`, `{8,9,11}`, `{4,9,10}`, `{5,11,12}`;
   - +1 for each of 4 solid groups hit by
     `Wire.currentSolidConfiguration@64` — `{2,4,5,6,9,12,14,16}`,
     `{2,4,5,6,10,11,13,17}`, `{2,5,7,8,9,10,11,12}`,
     `{2,6,7,9,10,13,14,15}`;
   - returns the total (0..10) — the exact number of `fillBuffer:` records
     `addDrawCubeData:fromIndex:` appends. 54 branches, zero calls.

3. **`addDrawCubeData:fromIndex:`** (`0x00952770`..`0x009549b8`, 2194
   words). The draw-cube builder:
   - position = `DynamicObject.floatPos@24` (Vector2, read through
     `Vector2::operator float*()`), +5.0 y-lift, z fold = `-1.0f` default
     / `0.0f` when `Wire.currentSolidConfiguration@64 == 0` (held in the
     `[sp+0x400+0x120]` slot);
   - vertex variants scale z by f64 constants **0.05 / 0.45 / 0.525**
     (e.g. `x' = x + z*0.05`); per-variant record float table
     **0.4f / 0.5f / 0.05f / 1.0f / 0.525f / 1.525f**
     (`0x3ecccccd`, `0x3f000000`, `0x3d4ccccd`, `0x3f800000`,
     `0x3f066666`, `0x3fc33333`);
   - texture = **`texCoordsForImageIndex(0x70)`** (image index 0x70 = the
     wire texture); helper `0x009549b8` (IMP gap, out of body) builds the
     Vertex Vector (`bl 0x9549b8` twice, once per z branch);
   - per matched configuration group (the same 6 config + 4 solid groups
     as `staticGeometryDrawCubeCount`) one record is staged with
     `index = fromIndex + running count` and appended via
     **[`macroTileOwner@12` `fillBuffer:fromIndex:matrix:width:height:depth:centerX:centerY:centerZ:topMinS:topMaxS:topMinT:topMaxT:sideMinS:sideMaxS:sideMinT:sideMaxT:macroWorldX:macroWorldY:`]**
     (`0xe83a6c`, ten call sites); `OBJC_CLASS_$_DrawCube` class cells
     (`0x00e8abb4`) guard the records;
   - returns the i16 count of appended cubes
     (`ldr r0, [sp, 0x524]`).

## Anchors

- Selector cell: the 20-argument `fillBuffer:...:macroWorldY:` at three
  cells (`0x00952804`, `0x00954988`, `0x009549a4`; slot `0x00e83a6c`).
- Class cells: `OBJC_CLASS_$_DrawCube` (`0x00e8abb4`) x3.
- Ivars: `Wire.currentConfiguration@60` (`0x0105e2f8`),
  `Wire.currentSolidConfiguration@64` (`0x0105e2fc`),
  `DynamicObject.floatPos@24` (`0x0105c3d0`),
  `DynamicObject.macroTileOwner@12` (`0x0105c3b8`).
- All 14 call sites pinned: 10 `objc_msgSend`, 2
  `Vector2::operator float*()` (`0x004bdaac`),
  `texCoordsForImageIndex` (`0x004d6820`), `bl 0x9549b8`; 115 branches
  (54 + 61) pinned.
- Key constants: 5.0 (`vmov.f32 s0, 5`), -1.0f/0.0f fold, 0.05 f64
  (`0x3fa999999999999a`), 0.45 f64 (`0x3fdccccccccccccc`), 0.525 f64
  (`0x3fe0cccccccccccd`), float tags `0x3ccc/0x3d4c/0x3f06/0x3fc3`,
  image index `0x70`.

## Boundaries

- `draw:` is a frame canonicaliser inside its own bounded body (no calls);
  it does not submit GL.
- `addDrawCubeData:fromIndex:` body ends at `0x009549b8`; the
  vector-builder helper `0x009549b8`..`0x00954a2c` (IMP gap) is excluded
  but pinned as a call target. The `fillBuffer:` implementation
  (DrawCube/static-geometry buffer internals) is out of body scope.
- This closes the `Wire` class: 22/22 instance methods now carry static
  evidence (updateWireConfiguration + 19 closure bodies + this render
  trio).
