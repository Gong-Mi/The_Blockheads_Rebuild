# Original 1.7.6 renderer and asset contract

This document records static evidence from the original APK and
`libApplication.so`. It does not claim pixel parity for the rebuild.

## Evidence levels

- **A**: directly present in the original APK, shader source, ELF metadata,
  selector table, symbol table, or current rebuild source.
- **B**: reproduced by a controlled run of the original application.
- **C**: conclusion combining multiple A-level observations.
- **D**: proposed implementation direction, not recovered original behavior.

This document contains A/C evidence. Device screenshots of the rebuild are
acceptance evidence for the rebuild, not B-level evidence for the original.

## Asset namespace

[A] The original `assets/GameResources/` tree contains **723 files** totaling
71,108,242 bytes:

- 553 direct children;
- 125 files under `HDTex/`;
- remaining files under `Fonts/`, `UI/`, `instructions/`, and `skins/`;
- 458 PNG, 152 WAV, 46 `.vsh`, and 46 `.fsh` files.

[A] Paths are mixed-case and case-sensitive. Examples include `TileMap.png`,
`TileDestruct.png`, `TileReflect.png`, `ItemNormals.png`, `Items.png`,
`SkyBetter.png`, `Sun.png`, `Moon.png`, and `HDTex/TileMap.png`. There are no
case-fold collisions.

[A] There are 126 repeated-basename groups spanning 252 paths, mostly SD files
and their `HDTex/` counterparts. The namespaces must not be flattened by
basename. Representative pairs are:

| Asset | SD | HD |
|---|---:|---:|
| `Items.png` | 512×256 | 2048×1024 |
| `TileMap.png` | 512×512 | 2048×2048 |
| `TileDestruct.png` | 512×512 | 2048×2048 |
| `TileReflect.png` | 512×512 | 2048×2048 |
| `head_ct.png` | 32×16 | 128×64 |
| `body_ct.png` | 32×16 | 128×64 |
| `arms_ct.png` / `legs_ct.png` | 16×16 | 64×64 |

[A] The rebuild contains byte-identical copies of all 723 resources after
removing the original `GameResources/` prefix. Runtime now selects the original
`HDTex/TileMap.png`, `HDTex/TileDestruct.png`, and `HDTex/Items.png` directly;
CI and the packaged-APK contract pin their original SHA-256 values.

## Native renderer topology

[A] Objective-C metadata in `libApplication.so` exposes `World`, `Shader`,
`CPTexture2D`, `DrawCube`, `Weather`, `ParticleEmitter`, `GameView`,
`WorldTileLoader`, `DynamicWorld`, `OwnershipAreaRenderer`, and `Blockhead`.

[A] `World` has distinct state for `blockShader`, `blockTransparentShader`,
`staticDrawCubeShader`, `lightsShader`, `dodoEggShader`, sky/star/black-tile
shaders, tile/destruction/light textures, sky/sun/moon textures, item and item
normal textures, block geometry arrays, camera bounds, and time/weather
matrices.

[A] Recovered selectors include:

- `preRenderUpdate:fastSlowDT:cameraZ:projectionMatrix:`
- `preDrawUpdate:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:`
- `reloadDrawBlock:world:waterAnimationIndex:slowAnimationIndex:mapPixelData:skyPixelData:`
- `drawOpaqueObjects:...`
- `drawFreeBlocks:...`
- `drawInFrontOfBlocksObjects:...`
- `renderCloudWithMatrix:translation:dt:weatherFraction:futureWeatherFraction:timeOfDayFraction:`
- `renderWithMatrix:pinchScale:withDayColor:rainFraction:snowFraction:snowLevel:`
- `renderAndUpdate:...windMovement:`

[C] The original renderer is multi-pass. Opaque blocks, transparent blocks,
free blocks, in-front objects, water, static cubes, dynamic objects, dodo eggs,
light glows, particles, and weather cannot be represented faithfully by one
opaque terrain VBO pass.

## Exact block shader packing

[A] `Block.vsh` consumes four `vec4` attributes: `position`, `texCoord`,
`other`, and `paintColor`.

| Field | Original shader meaning |
|---|---|
| `position.xyz` | world position |
| `position.w` | atlas column |
| `texCoord.xy` | 0–255 coordinate inside one atlas cell |
| `texCoord.z` | artificial-light contribution scalar |
| `texCoord.w / 255` | Y displacement |
| `other.xy / 256` | lightmap UV |
| `other.z` | atlas row |
| `other.w / 255` | gather opacity in `BlockTransparent` |
| `paintColor` | paint RGB and paint alpha |

[A] `Block.fsh` samples a fixed **32×32 atlas** using the half-texel inset:

```text
((((coord / 255) * 0.984375) + 0.0078125) + cell) / 32
```

[A] It samples `texture`, `light_texture`, and `destruct_texture`.
Destruction RG perturbs the normal; destruction alpha controls diffuse and
specular terms. Lightmap RGB supplies artificial light and lightmap alpha
controls observed daylight. Paint alpha changes the final color equation and
must be zero for an unpainted tile.

[A] `BlockTransparent` is a separate shader contract. It forwards
`other.w / 255` as gather opacity, thresholds destruction blue against it, and
produces transparent output. It is not a mode of the opaque fragment shader.

## Other shader families

[A] Original assets and metadata establish these independent contracts:

- `LightQuads`: texture, night fraction, luminosity encoded by paint alpha;
- `StaticDrawCubes`: position, UV, normal, paint, lightmap, diffuse/specular;
- `Item`: normalized UVs over `Items.png` and `ItemNormals.png`;
- Blockhead body, clothing, face, hair, and multi-texture character shaders;
- `SkyBetter`, sun, moon, stars, six-layer HD cloud shaders;
- lightmap-aware rain and point-rendered snow.

The original spelling `artificalLight` is part of the character shader ABI.

## Tile conversion and direct contents-image mapping

[A] `itemTypeFromTileIsForegorund(Tile*, intpair, signed char, World*)` is a
3496-byte ARM function at `0x00a18044`. Call sites include
`DynamicWorld -createFreeBlockAtPosition:forForegroundContents:forTile:...`
and `randomBonusItemTypeForTile`; it converts a Tile into the corresponding
collectible/free-block ItemType. It is not itself the terrain renderer. The
`foreground_arg == 0` path switches on Tile byte 0 for TileTypes 1 through 77
using the jump table at `0x00a1868c`. Most cases assign a distinct ItemType;
nine entries additionally inspect Tile fields or call world/tree helpers.

[A] `tools/extract_original_tile_item_map.py` extracts direct assignments only
when the case has the exact `movw r0; str r0,[fp,#-4]; b return` shape. It marks
all other entries `conditional` rather than guessing. Its output is
`original_tile_item_map.tsv`. Joining it with `original_item_image_map.tsv`
provides a semantic cross-reference for placeable/free-block items, not proof
that the terrain renderer obtains its UVs through this call chain. Examples:

| TileType | ItemType | item image index | atlas `(col,row)` |
|---:|---:|---:|---:|
| 4 | 1060 | 110 | (14,3) |
| 7/8 | 1051 | 65 | (1,2) |
| 9 | 1049 | 196 | (4,6) |
| 10 | 1024 | 33 | (1,1) |
| 11 | 1026 | 34 | (2,1) |
| 53–57 | 1066–1070 | 112–116 | (16–20,3) |

[A] The renderer-side helper
`imageIndexForTileContents(Tile*, World*, intpair)` is a separate 640-byte
function at `0x00a13e6c`. It directly returns atlas image indices from Tile
byte 11 when `tileIsAirWaterOrSnow()` is true and otherwise falls back to Tile
byte 3. `tools/extract_original_tile_contents_image_map.py` recovers its two
jump tables and explicit cases into `original_tile_contents_image_map.tsv`.
Examples include byte 11 values 67–74 mapping to image indices 239–244 and
byte 3 values 103/104 mapping to image index 116.

[A] The main base-tile mapping is embedded in
`WorldHelper +reloadDrawBlock:world:waterAnimationIndex:...` at `0x00a1d730`.
Its Tile byte 0 switch uses the 77-entry table at `0x00a20ef0` and writes image
indices into the three later draw-pass slots. The draw loop at `0x00a27d5c`
selects those slots before applying `% 32` and `/ 32` atlas addressing.
`tools/extract_original_reload_drawblock_map.py` records constants assigned
before field-sensitive branches in `original_reload_drawblock_map.tsv`.
Recovered direct examples include TileType 4→110 `(14,3)`, 7/8→65 `(1,2)`,
9→196 `(4,6)`, 10→33 `(1,1)`, 48→97 `(1,3)`, 49→98 `(2,3)`, and
53–57→112–116 `(16–20,3)`.

[A/C+] A second `reloadDrawBlock` jump table at `0x00a221f4` dispatches on
Tile byte 3 values 3..123 and initializes the middle-pass draw-image pair.
`tools/extract_original_tile_content_render_map.py` extracts its constants to
`original_tile_content_render_map.tsv`. Numeric values, image indices,
addresses and atlas cells are A-grade original ELF evidence. Candidate content
names are separately marked C+ and come from the independent save-analysis
project `medioqrity/TheBlockheadsTools` at commit
`c9bc7eea11ecdefa7de47000bfe70b14be374f3c`, not an original developer header.
Cross-checks include PineTreeTrunk `7 -> image 192 (0,6)` and PineTreeLeaf
`6 -> image 237 (13,7)`.

[A/C+] That independent enum source correlates original TileType values with
Stone=1, Air=2, Water=3, Ice=4, Snow=5, Dirt=6, DesertSand=7,
BeachSand=8, Wood=9, GrassDirt=27 and SnowDirt=28. Names remain C+; switch
values and image assignments are A-grade ELF facts. The rebuild's basic cells
now use the field-sensitive original cases: Stone/content0 image 32,
Dirt/content0 image 64, GrassDirt/content0 image 160, CopperOre content61
image 1, TinOre content62 image 3, IronOre content63 image 2, and GoldNuggets
content77 image 84. These replace visual guesses while retaining the rebuild's
temporary custom item IDs.

[C] The current rebuild's small semantic IDs and hand-authored item definitions
are not the original TileType or ItemType namespace. They remain a replacement
compatibility layer until the direct renderer-side mappings used by
`WorldHelper +reloadDrawBlock:...` are fully recovered and wired into the world
representation.

## Rebuild conformance ledger

Verified in current source and CI:

- terrain atlas indices use item definitions rather than guessed numeric IDs;
- the terrain VBO is unbound before client-side character arrays;
- a new EGL context recreates renderer-owned GL objects and requeues cached
  chunk meshes for VBO upload;
- original HD terrain/destruction/item atlases are loaded directly and pinned by
  source and packaged-APK SHA-256 contracts;
- the original `white.png` is used for untextured solid-color draws while a real
  per-block lightmap remains outstanding;
- gameplay initializes `artificalLight` and `lightPosition`;
- unpainted generated vertices use paint alpha zero;
- shaders pass `glslangValidator` and source contract checks run in CI.

Outstanding evidence-backed gaps:

1. [A] `texCoord.z` and `other.xy` are not populated as a real per-block
   artificial-light/lightmap contract.
2. [A] The original `white.png` currently substitutes for a real physical-block
   lightmap; it is an original asset but not the original lightmap behavior.
3. [A/C] Transparent/background/water/object passes remain collapsed or absent.
4. [A] Character drawing uses only the body program and flat six-vertex faces;
   clothing, face, hair, multi-texture composition, and cuboid geometry remain.
5. [A] Dynamic painting/column/stairs objects and some renderer-side
   `WorldHelper +reloadDrawBlock:...` cases still require runtime/world-state
   resolution; static Tile[0], Tile[3], and Tile[11] tables are now extracted.
6. [A] Shader compile/link/validation diagnostics are incomplete.
7. [A/C] Sky and weather are prototypes rather than recovered original passes.

## Acceptance observations

These are rebuild-device observations, not original-runtime evidence:

- CI run `31873929349` built commit `983078f` successfully.
- APK installation and saved-world loading succeeded on the test device.
- Terrain and UI remain visible after EGL context recreation.
- Setting unpainted paint alpha to zero made brick atlas content materially
  recognizable, but broad terrain remains dark and the character remains only
  partially recognizable.
