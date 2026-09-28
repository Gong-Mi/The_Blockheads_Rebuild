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

## Next slices

`drawOpaqueObjects:` (the opaque batch), `drawInFrontOfBlocksObjects:`,
`drawFreeBlocks:`'s object level, then the 7203w master `draw:`; the world
classes' shaders (`Block`, `ShadedWorldObject`, `WorldObjectNewLighting`)
are already in `assets/shaders` and the mapping sweep covers their inits.
