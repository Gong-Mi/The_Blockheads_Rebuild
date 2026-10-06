# WorldHelper recalculateLightingForPhysicalBlockIfNeeded: — the per-block lighting orchestrator

Original ELF `libApplication.so` (armeabi-v7a), SHA-256 `733d8210…b94c7`.
One class body, word-verified against the pinned bytes by
`tools/recover_worldhelper_recalculatelighting.py --check`:

| method | IMP | bounded end | words |
|---|---|---|---|
| `+[recalculateLightingForPhysicalBlockIfNeeded:world:clientLightBlockIndex:forBlockhead:]` | `0x00a1ca64` | `0x00a1d730` | 819 |

The per-macro-block lighting pass: server-only, centered on a blockhead's view
(or the world portal), culling far blocks, then walking the full 32×32 tile
grid and writing the radial light field. It is the caller-side partner of the
per-tile pair (`WORLDHELPER_SUNLIGHT.md`) and the two engines
(`WORLDHELPER_RECURSIVE_REMOVE.md`, `WORLDHELPER_RECURSIVE_UPDATE.md`).

## Gates and center

```text
if (clientLightBlockIndex == 0) return;
dw = [world dynamicWorld];  if ([dw isClient]) return;
if ([blockhead isClientBlockheadBeingControlledByServer]) return;   // nonzero → return
bx32 = physicalBlock->blockX << 5;  by32 = physicalBlock->blockY << 5;
extra = (clientLightBlockIndex != -1) ? physicalBlock[0x20 + idx*4] : 0;
    // when extra != 0 it is loaded first via
    // [world loadLightBlockForClientLightBlockIndex:idx intoPhysicalBlock:pb]
center = blockhead ? [blockhead pos] : [world startPortalPos];   // nil world → {0,0}
vr     = blockhead ? [blockhead viewRadius] : 4;
margin = max(22 - vr, 0);
```

`PhysicalBlock` layout used here: `[0]`/`[1]` are the macro block's grid
coordinates (× 32 for world units), `+8` the 1024-tile array (64 bytes each),
`+0x20` the 32 client light-block pointers (`[32*]` in the type encoding).

## Wrap and cull

```text
w = [world worldWidthMacro];
if (center.x - bx32 <  -(w<<4)) center.x += w<<5;   // w*32 = full wrap
if (center.x - bx32 >   (w<<4)) center.x -= w<<5;   // (the ±w*16 band)
same for center.y;
return unless center.x in (bx32-vr, bx32+32+vr) and center.y in (by32-vr, by32+32+vr);
```

## The 32×32 tile walk

```text
for (i = 0..31 rows, j = 0..31 cols):
    tile = physicalBlock->tiles + (i*32+j)*64;
    worldPos = (bx32+j, by32+i);
    srcByte = extra ? extra[i*32+j] : tile[6];
    dx = center.x - (bx32+j); if (dx < 0) dx += 1;   // then wrapped ±w<<4 / w<<5
    dy = center.y - (by32+i); if (dy < 0) dy += 1;   // same
    d2 = dx*dx + dy*dy;  if (d2 >= 0x1e4) continue;  // cut-off radius 22
    t = ((float)sqrtf(d2) + (float)margin) / 2.0f;
    u = 4.0f - t * 4.0f;                              // = 4 - 2*(dist + margin)
    lightI = (int)(255.0f * u);
    newLight = (lightI > srcByte) ? min(lightI, 0xff) : srcByte;   // saturating max
    if (tile[9] == 0) {
        if (newLight > 0) {
            tile[9] = newLight;  flag36 = 1;
            if (backWallIsMutable(tile) && !tileIsSolid(tile)
                && tile[3] == 0 && tile[0] != 3)
                [+WorldHelper updateSunLightForTile:tile atPos:worldPos world:world];
        }
    } else if (newLight > tile[9]) { tile[9] = newLight;  flag36 = 1; }
    if (tile[0] == 3) {                                // temperature / freeze path
        weather   = [world getWeatherFractionForPos:worldPos];
        dayNight  = [world getDayNightFractionForX:(float)worldPos.x
                       atWorldTime:(double)[world worldTime]];
        season    = seasonForWorldX(worldPos.x, (double)[world worldTime], world);
        temp = currentTemperatureForTileAtWorldPos(tile, worldPos,
                       weather, dayNight, season, world);
        if (temp < 0) [world fillTile:tile atPos:worldPos withType:0x422];
    }
    if (newLight != srcByte) {
        if (extra) extra[i*32+j] = newLight; else tile[6] = newLight;
        flag35 = 1;
    }
```

- The falloff is the ARM's exact arithmetic: divide by 2.0, multiply by 4.0,
  subtract from 4.0, scale by 255.0 and convert — i.e.
  `light = (int)(255.0f * (4.0f - 2.0f*((sqrt(d2)+margin)/2.0f)))`, with the
  saturating max against the stored byte and a hard `d2 >= 0x1e4` skip.
- `tile[9]` is the per-tile light value written here; `tile[6]` is the
  fallback storage for the light byte when no client light-block data exists
  (`extra`), which is the same byte the target-derived engine reads.

## Reporting (after the loops)

```text
if (flag36) [dw lightChangedAtMacroPos:makeIntpair(pb.blockX, pb.blockY)
             sendReliably:0 sendAtAll:0];
if (flag35) [dw exploreLightChangedAtMacroPos:makeIntpair(pb.blockX, pb.blockY)
             clientLightBlockIndex:idx];
```

## Anchored facts

- 15 selector cells (isClient, dynamicWorld ×2, isClientBlockheadBeingControlledByServer,
  loadLightBlockForClientLightBlockIndex:intoPhysicalBlock:, startPortalPos, pos,
  viewRadius, worldWidthMacro, updateSunLightForTile:atPos:world:,
  getWeatherFractionForPos:, worldTime, getDayNightFractionForX:atWorldTime:,
  fillTile:atPos:withType:, lightChangedAtMacroPos:sendReliably:sendAtAll:,
  exploreLightChangedAtMacroPos:clientLightBlockIndex:) plus the objc_msgSend
  import cell.
- All 40 call sites with pinned targets: msgSend thunk `0x001c281c` (×22),
  stret `0x001c2918`, memset `0x001c2924`, `__aeabi_idiv` `0x001c3728` (×5),
  `sqrtf` `0x001c2b28`, `backWallIsMutable` `0x00a1234c`, `tileIsSolid`
  `0x00a1179c`, `makeIntpair` `0x004b49fc` (×4), `seasonForWorldX`
  `0x00a14a48`, `currentTemperatureForTileAtWorldPos` `0x00a15404`.
- All 62 branches pinned exactly; the light arithmetic seeds (`vmov.f32
  s2, 4` / `s4, 2`), the `0x1e4` cutoff, the `0x422` fill type, the three
  store sites (tile[9] ×2, tile byte-6/extraData, flag bytes) are anchored
  instructions.

## Boundaries

- No own ARM.exidx entry; closed by the next method IMP (`0x00a1d730`).
- The temperature model behind `currentTemperatureForTileAtWorldPos`, the
  `fillTile:atPos:withType:` effects, `seasonForWorldX` and all dynamic-world
  network plumbing are **outside this body** (call sites pinned, semantics
  not claimed).
- `tile[9]`/`tile[6]` names are not claimed; the byte roles are what the code
  reads and writes.
- No runtime claim; no device run.

## Artifacts

| artifact | role |
|---|---|
| `tools/recover_worldhelper_recalculatelighting.py` | hash-gated extractor; `--check` re-verifies every anchor |
| `disasm_worldhelper_recalculatelighting.txt` | the bounded listing |
| `worldhelper_recalculatelighting.json` | machine record: selectors/calls/branches |
| `tools/test_worldhelper_recalculatelighting_evidence.py` | CI contract on the committed JSON (no ELF needed) |
