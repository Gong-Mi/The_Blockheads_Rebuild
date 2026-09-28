# The world render front — the map (first slices)

The world's draw path lives in `DynamicWorld` (210 methods) and `World`
(353). The method table sizes give the layers (by address order):

| DynamicWorld method | words |
|---|---|
| `preDrawUpdate:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:cameraZ:` | 401 |
| `draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:...` | **7203** (the master draw) |
| `drawOpaqueObjects:projectionMatrix:modelViewMatrix:...` | 1395 |
| `drawInFrontOfBlocksObjects:projectionMatrix:modelViewMatrix:...` | 1642 |
| `drawFreeBlocks:projectionMatrix:modelViewMatrix:...` | 548 |
| `drawBlockheadBoxes:...` | 398 |
| `drawNames:projectionMatrix:modelViewMatrix:pinchScale:...` | 1393 |

World: `preRenderUpdate:fastSlowDT:cameraZ:projectionMatrix:...` 8640w,
`render:cameraZ:projectionMatrix:pinchScale:` (the entry).

## The pre-draw fan-out (decoded: `preDrawUpdate:`, 401w)

`disasm_dw_predrawupdate.txt` — the method is a clean three-collection
fan-out, each member receiving the same camera bounds:

```
for b in netBlockheads@48:              [b …]; [b preDrawUpdate:cameraMinXWorld:…]
for b in netBlockheadsWithDisconnectedClients@52:  … same
for b in blockheads@44:                 … same
```

(The per-member call sites at 0x008D1368 / 0x008D1558 / 0x008D1748, the
fast enumerations guarded by `objc_enumerationMutation`.)

So the pre-draw stage is per-Blockhead visibility/update under the camera
rect; the draw stage then batches whatever the objects marked visible.

## The FreeBlock layer (first draw slice)

`drawFreeBlocks:` (548w) walks `dynamicObjects@60`, reads each object's
`pos` / `itemType` (the same fields the save front decodes for type 14) and
draws — the smallest of the draw methods and the natural bridge between the
save/load front and the render front.

## The object side: the base draw is a no-op (decoded)

`DynamicObject -draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:…`
(0x0083AC50, 138w) turns out to be an **empty method with nine arguments**:
the whole body is the argument-saving prologue and the epilogue — the base
class draws nothing, exactly like the UI family's base. The per-type draw
lives in the overrides: `FreeBlock -draw:` is 4835w, `Blockhead -draw:…` is
the blockhead's own, and `GlowBlock` / `GatherBlock` / `Tree` simply inherit
the no-op (they are drawn through the static-geometry batches below).

## The static-geometry batch API (the map piece)

`DynamicObject`'s render surface (from its method table) is a **batch
builder**: per-geometry-type count accessors paired with the data-add
methods that the world's batching calls:

| count accessor | add method |
|---|---|
| `staticGeometryDrawCubeCount` | `addDrawCubeData:fromIndex:` |
| `staticGeometryDrawCubeCountTrans` | `addDrawCubeDataTrans:fromIndex:` |
| `staticGeometryDrawQuadCountForMacroPos:` | `addDrawQuadData:fromIndex:forMacroPos:` |
| `staticGeometryForegroundDrawQuadCountForMacroPos:` | `addForegroundDrawQuadData:fromIndex:forMacroPos:` |
| `staticGeometryDrawItemQuadCount` | `addDrawItemQuadData:fromIndex:` |
| `staticGeometryCylinderCount` (+ `…Trans`) | `addCylinderData:fromIndex:` (+ `Trans`) |
| `staticGeometryDodoEggCount` | `addDodoEggDrawQuadData:fromIndex:` |
| `lightGlowQuadCount` | `addLightGlowQuadData:fromIndex:` (798w) |

So every world object contributes its geometry into per-type static batches
(cubes, normal/foreground/item quads, cylinders, dodo eggs, light-glow
quads), and the world's `drawOpaqueObjects:` fan-out (decoded above) calls
each object's `draw:` for whatever is *not* static. That is the batching
model the 7203w master draw orchestrates.

## The first real object draw: `FreeBlock -draw:…` (0x0062F868, 4835w)

`disasm_freeblock_draw.txt` — the free block (the save front's type 14) is
also a rich *renderer*, and its structure reads directly off the listing:

- **multi-pass GL**: four `__wrap_glUseProgram`, five `glUniform1i`, nine
  `glUniform4f`, five `glUniformMatrix4fv`, six `glBindTexture`, two
  `glActiveTexture`, plus the attribute enable/disable pair — with the
  uniform pushes going through the cached `uniformLocations` array
  (19 `intValue`/`objectAtIndex:` lookups). No direct `glDrawElements` in
  this body: the geometry goes through the static batches / the shared
  draw-quad path;
- **the instance state it reads**: `bounceTimer@68` (the pick-up bounce),
  `rotation@76`, `blockCube@88` (the cube model), `paintColor@152` (the
  painted tint), `pos@16`/`floatPos@24` (the interpolated position) and
  `needsRemoved@48`;
- **the macro-coordinate transform**: `world@4` (14 refs) and
  `worldWidthMacro` (12) with `macroTiles` — the same coordinate kit the
  save front's tree/dodo math uses;
- **lazy resource build**: two `shaderNamed:attributes:uniforms:` and two
  `cache textureNamed:` calls inside the draw (the shaders/textures are
  built on first draw, then reused).

The same shape holds for the other object draws (Blockhead's family), so the
object layer is a set of per-type renderers over the shared batch API and
the recovered shader set.

## The light layer (decoded accessors + the glow batch builder)

The world's lights are the save front's own light objects (Torch,
GlowBlock, ArtificialLight, FireObject) seen from the render side:

- `DynamicObject -lightPos` (41w) = `(pos.x@16, pos.y@16+4, -1.0)` built
  through the 3-float constructor `0x004B52AC` — the light's screen position
  with z = -1 (in front of the blocks);
- `DynamicObject -getLightRGB` (17w) = the base returns a constant RGB
  (also through 0x004B52AC); the subclasses override it with their light
  colours — the same values the save front decodes from their save dicts;
- `isUplight` / `isDownlight` (7w each) select the glow direction;
- `addLightGlowQuadData:fromIndex:` (0x0083BC18, 798w) is the **batch
  builder**: it reads `lightPos`, `getLightRGB`, the up/down flags and
  `lightGlowQuadCount`, and writes the glow quad's vertices into the batch
  buffer — the body is almost entirely the float/vertex math (hence few
  annotations), the interface is the seven refs above.

So the light pipeline: each light emits its glow quad into the
`lightGlowQuadCount`/`addLightGlowQuadData:` batch, drawn by the master
draw; the UI shader `LightQuads.vsh/fsh` (in the asset set) is its GPU
half.

## Next slices

`drawOpaqueObjects:` (the opaque batch), `drawInFrontOfBlocksObjects:`,
`drawFreeBlocks:`'s object level, then the 7203w master `draw:`; the world
classes' shaders (`Block`, `ShadedWorldObject`, `WorldObjectNewLighting`)
are already in `assets/shaders` and the mapping sweep covers their inits.
