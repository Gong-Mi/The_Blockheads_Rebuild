# The server-side Tile field map (DWARF, first-party names)

Source: the Linux server 1.7.1 original binary's DWARF (`server_tile_dwarf.json`,
sha256 `b1534f723ac524e1...`, DIE 0x41129): a 64-byte struct with 26 members. This is
the first-party field table behind every `tile[N]` access in the client audits; the
Android 1.7.6 client matches it field-for-field up to offset 12 and carries ONE extra
byte at +13 (padding on the server; its name is open).

| offset | name | our audits |
|---|---|---|
| +0x00 | `typeIndex` | "byte0" - the front material code (air 2 / water 3 / ice 4 / burnables {9,0x15,0x16,0x17,0x20} ...) |
| +0x01 | `backWallTypeIndex` | "byte1" - the background wall twin |
| +0x02 | `zoneTypeIndex` | 1 underground / 2 surface / 3 generation water; zone-gates the cave flood (E119 aq_24 correction) |
| +0x03 | `contents` | the third byte; not yet audited |
| +0x04 | `partialContentLeft` | the water level / snow amount (0x7f half, 0xff full; E118/E119 writes) |
| +0x05 | `gatherProgress` | | 
| +0x06 | `light` | computed light (ClientTileLoader floors it with exploredFraction) |
| +0x07 | `sunLight` | the TEMPERATURE coupler (cov = sunLight/255*0.8+0.2) and the snow-accumulation gate >239 |
| +0x08 | `seasonOffset` | |
| +0x09 | `exploredFraction` | 0 = never explored; gates the ice melt branch + BlockheadAI testTile (`TILE_BYTE9_EXPLORED.md`) |
| +0x0a | `terrainSlowFactor` | |
| +0x0b | `foregroundContents` | the content codes ('d' 0x64 caps, fires, torch arms, 'B' 0x42) |
| +0x0c | `backgroundContents` | |
| +0x0e | `artificialLightR` | u16, /1024 (the light-channel trio) |
| +0x10 | `artificialLightG` | u16 |
| +0x12 | `artificialLightB` | u16 |
| +0x14 | `artificialHeat` | s16 - the temperature formula's local heat term (E119 temperature read) |
| +0x16 | `onFire` | u16 - the fire flag the FireObject machinery drives |
| +0x18 | `dynamicObjectOwnerOld` | u32 legacy |
| +0x1c..+0x26 | `paintFront/Top/Right/Left/Bot` | u16 per-face paint |
| +0x28 | `dynamicObjectOwner` | u32 |
| +0x30 | `padding` | to 64 |

## Corrections this table forces on the earlier batches

- E118's "coverage byte7" reads are `sunLight`; the snow accumulation gate `>239` is
  "open to the sky". The melt/accumulation chapter's `s16@0x14` is `artificialHeat`
  (matching the E119 temperature formula's local-heat term).
- E118's `byte0 == 4 && byte9 > 0` ice-melt branch is **exploration-gated**: only tiles
  with `exploredFraction > 0` (seen by a player) simulate the melt.
- E119's aq_24 flood gate `byte2 == 1` is `zoneTypeIndex == 1` (underground).
- The client field at +0x13 (absent on the server) stays unnamed.
